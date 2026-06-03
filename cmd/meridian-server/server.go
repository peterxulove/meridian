// Meridian server — high-performance, anti-detection secure proxy.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"context"

	"meridian/pkg/config"
	"meridian/pkg/crypto"
	"meridian/pkg/mfp"
	"meridian/pkg/mtp"
	"meridian/pkg/transport"

	"github.com/quic-go/quic-go"
)

// Server manages Meridian connections.
type Server struct {
	cfg     config.ServerConfig
	udp     *net.UDPConn
	conns   sync.Map
	stopped atomic.Bool
	wg      sync.WaitGroup
	stats   ServerStats
}

// ServerStats tracks connection metrics.
type ServerStats struct {
	Active  atomic.Uint64
	Handled atomic.Uint64
	In      atomic.Uint64
	Out     atomic.Uint64
}

// NewServer creates a new Meridian server.
func NewServer(cfg config.ServerConfig) (*Server, error) {
	return &Server{cfg: cfg}, nil
}

// Start begins listening on the configured address.
func (s *Server) Start() error {
	if s.cfg.Transport == config.TransportWebSocket {
		return s.startWS()
	}
	// Start TCP Tunnel listener concurrently for reliable proxying
	go s.startTCP()
	return s.startQUIC()
}

func (s *Server) startQUIC() error {
	tlsCfg, err := transport.ServerTLSConfig(s.cfg)
	if err != nil {
		return err
	}
	
	listener, err := quic.ListenAddr(s.cfg.ListenAddr, tlsCfg, &quic.Config{
		KeepAlivePeriod:            s.cfg.KeepaliveInterval,
		MaxStreamReceiveWindow:     8 * 1024 * 1024,  // 8MB
		MaxConnectionReceiveWindow: 20 * 1024 * 1024, // 20MB
	})
	if err != nil {
		return err
	}
	fmt.Printf("  [QUIC] Listening on %s (tunnel server)\n", s.cfg.ListenAddr)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			if s.stopped.Load() {
				break
			}
			conn, err := listener.Accept(context.Background())
			if err != nil {
				if s.stopped.Load() {
					break
				}
				continue
			}
			go s.handleQUICConnection(conn)
		}
	}()
	return nil
}

func (s *Server) handleQUICConnection(conn *quic.Conn) {
	if config.DebugMode {
		fmt.Printf("[DEBUG] [QUIC] Accepted connection from %s\n", (*conn).RemoteAddr())
	}
	stream, err := (*conn).AcceptStream(context.Background())
	if err != nil {
		if config.DebugMode {
			fmt.Printf("[DEBUG] [QUIC] AcceptStream failed: %v\n", err)
		}
		return
	}
	wrapper := &quicStreamWrapper{Stream: stream, qconn: conn}
	s.handleTCPTunnel(wrapper)
}

func (s *Server) startWS() error {
	// WebSocket listener is not yet fully implemented.
	// The stub returns an error so the caller knows it's unavailable.
	return fmt.Errorf("server: WebSocket transport not yet implemented")
}

func (s *Server) handlePacket(data []byte, remote *net.UDPAddr) {
	if len(data) < 14 {
		return
	}

	// Fix #24: use crypto.Magic constant instead of a duplicated literal.
	if binary.BigEndian.Uint32(data[0:4]) != crypto.Magic {
		return
	}

	s.stats.Handled.Add(1)
	s.stats.In.Add(uint64(len(data)))

	// Distinguish handshake packets (version byte at offset 4) from data frames.
	if data[4] == crypto.CurrentVersion {
		s.doHandshake(data, remote)
	} else {
		frame, err := mfp.ParseFrame(data)
		if err == nil {
			s.forwardFrame(frame, remote)
		}
	}
}

func (s *Server) doHandshake(data []byte, remote *net.UDPAddr) {
	// Parse client hello using the fixed MTP parser.
	hs, err := mtp.ParseClientHello(data)
	if err != nil {
		fmt.Printf("  [Handshake] Parse error from %s: %v\n", remote, err)
		return
	}

	// Generate server ECDHE key pair.
	// Fix: GenerateKeyPair now returns (*KeyPair, error) after the crypto fix.
	serverEK, err := crypto.GenerateKeyPair()
	if err != nil {
		fmt.Printf("  [Handshake] Key generation failed: %v\n", err)
		return
	}

	// Compute shared secret via X25519.
	shared, err := crypto.SharedKey(
		&crypto.KeyPair{PrivKey: serverEK.PrivKey},
		hs.ClientECDHE,
	)
	if err != nil {
		fmt.Printf("  [Handshake] SharedKey failed: %v\n", err)
		return
	}

	// Generate server random.
	serverRandomBytes, err := crypto.GenerateRandom(32)
	if err != nil {
		fmt.Printf("  [Handshake] GenerateRandom failed: %v\n", err)
		return
	}
	var serverRandom [32]byte
	copy(serverRandom[:], serverRandomBytes)

	// Derive session keys.
	keys, err := crypto.DeriveKeys(shared, hs.ClientRandom, serverRandom)
	if err != nil {
		fmt.Printf("  [Handshake] DeriveKeys failed: %v\n", err)
		return
	}
	_ = keys // keys used by the per-connection encoder/decoder (not yet wired)

	s.stats.Active.Add(1)
	defer s.stats.Active.Add(^uint64(0))

	fmt.Printf("  [Handshake] OK from %s cipher=MERIDIAN-CHACHA\n", remote.String())
	// TODO: send ServerHello with serverRandom, serverEK.PubKey, negotiated cipher, derived keys.
}

func (s *Server) forwardFrame(frame *mfp.DataFrame, remote *net.UDPAddr) {
	// TODO: look up the session by remote address, decrypt, and forward to the
	// configured upstream destination.
	_ = frame
	_ = remote
}

// Stop signals the server to shut down and waits for all goroutines to exit.
func (s *Server) Stop() {
	s.stopped.Store(true)
	if s.udp != nil {
		s.udp.Close()
	}
	s.conns.Range(func(k, v interface{}) bool {
		if c, ok := v.(io.Closer); ok {
			c.Close()
		}
		return true
	})
	s.wg.Wait()
}

// Stats returns the current server statistics.
func (s *Server) Stats() (active, handled, bytesIn, bytesOut uint64) {
	return s.stats.Active.Load(), s.stats.Handled.Load(),
		s.stats.In.Load(), s.stats.Out.Load()
}

func (s *Server) writeCertKey(certFile, keyFile string) error {
	_, err := crypto.LoadCert(certFile, keyFile)
	return err
}

func splitHostPort(addr string) (string, string) {
	h, p, _ := net.SplitHostPort(addr)
	return h, p
}

// Compile-time checks that referenced symbols exist.
var (
	_ = transport.ServerTLSConfig
	_ = mtp.BuildClientHello
	_ = mfp.NewFramePool
)

func (s *Server) startTCP() {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		fmt.Printf("  [TCP] Listen error on %s: %v\n", s.cfg.ListenAddr, err)
		return
	}
	defer ln.Close()
	fmt.Printf("  [TCP] Listening on %s (tunnel server)\n", s.cfg.ListenAddr)

	for {
		if s.stopped.Load() {
			break
		}
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go s.handleTCPTunnel(conn)
	}
}

type activeStream struct {
	conn      net.Conn
	writeChan chan []byte
	closeOnce sync.Once
}

func (s *Server) handleTCPTunnel(conn net.Conn) {
	if config.DebugMode {
		fmt.Printf("[DEBUG] [Tunnel] New tunnel connection from %s\n", conn.RemoteAddr())
	}
	defer conn.Close()

	// ── MTP Handshake (Server Side) ───────────────────────────────────────
	conn.SetReadDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		if config.DebugMode {
			fmt.Printf("[DEBUG] [Tunnel] Handshake read failed: %v\n", err)
		}
		return
	}
	conn.SetReadDeadline(time.Time{})

	if n < 136 {
		if config.DebugMode {
			fmt.Printf("[DEBUG] [Tunnel] Invalid handshake (too short)\n")
		}
		return
	}

	hs, err := mtp.ParseClientHello(buf[:n])
	if err != nil {
		fmt.Printf("  [TCP Handshake] Parse error from %s: %v\n", conn.RemoteAddr(), err)
		return
	}

	serverEK, err := crypto.GenerateKeyPair()
	if err != nil {
		return
	}

	shared, err := crypto.SharedKey(
		&crypto.KeyPair{PrivKey: serverEK.PrivKey},
		hs.ClientECDHE,
	)
	if err != nil {
		return
	}

	serverRandomBytes, err := crypto.GenerateRandom(32)
	if err != nil {
		return
	}
	var serverRandom [32]byte
	copy(serverRandom[:], serverRandomBytes)

	keys, err := crypto.DeriveKeys(shared, hs.ClientRandom, serverRandom)
	if err != nil {
		return
	}

	// Build & Send ServerHello
	sh := buildServerHello(serverEK.PubKey, serverRandomBytes, hs.ClientID)
	if _, err := conn.Write(sh); err != nil {
		return
	}

	fmt.Printf("  [TCP Handshake] OK from %s cipher=MERIDIAN-CHACHA\n", conn.RemoteAddr())

	// Create Encoder and Decoder
	enc := mfp.NewDownlinkEncoder(keys)
	dec := mfp.NewUplinkDecoder(keys)

	// Map of active StreamID -> target connection
	activeStreams := make(map[uint32]*activeStream)
	var mu sync.Mutex // protects activeStreams
	var writeMu sync.Mutex // protects concurrent writing to conn

	defer func() {
		mu.Lock()
		for _, c := range activeStreams {
			c.closeOnce.Do(func() { close(c.writeChan) })
			c.conn.Close()
		}
		mu.Unlock()
	}()

	// Loop to read and dispatch MFP frames from client
	for {
		frameData, err := readTCPFrame(conn)
		if err != nil {
			return // Client disconnected
		}

		frame, err := dec.Decode(frameData)
		if err != nil {
			continue
		}

		sid := frame.Header.StreamID

		if frame.Header.Type == mfp.TypeRESET {
			mu.Lock()
			tc, exists := activeStreams[sid]
			if exists {
				tc.closeOnce.Do(func() { close(tc.writeChan) })
				tc.conn.Close()
				delete(activeStreams, sid)
			}
			mu.Unlock()
			continue
		}

		if frame.Header.Type == mfp.TypeDATA {
			flags := frame.Header.Flags
			if flags == 0x01 {
				// CONNECT stream request
				targetAddr := string(frame.Data)
				go func(streamID uint32, addr string) {
					// Perform dial directly on server (resolving DNS on server side!)
					targetConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
					if err != nil {
						writeMu.Lock()
						respFrame, _ := enc.Encode(streamID, 0x08, []byte(err.Error()))
						conn.Write(respFrame)
						writeMu.Unlock()
						return
					}

					streamInfo := &activeStream{
						conn:      targetConn,
						writeChan: make(chan []byte, 1024),
					}

					mu.Lock()
					activeStreams[streamID] = streamInfo
					mu.Unlock()

					// Send CONNECT SUCCESS frame (Flags = 0x01)
					writeMu.Lock()
					respFrame, _ := enc.Encode(streamID, 0x01, []byte("OK"))
					conn.Write(respFrame)
					writeMu.Unlock()

					// Start writer goroutine
					go func() {
						for data := range streamInfo.writeChan {
							if _, err := targetConn.Write(data); err != nil {
								break
							}
						}
						targetConn.Close()
						mu.Lock()
						delete(activeStreams, streamID)
						mu.Unlock()
						// Send RESET to client
						writeMu.Lock()
						rf, _ := enc.Encode(streamID, mfp.TypeRESET, nil)
						conn.Write(rf)
						writeMu.Unlock()
					}()

					// Start bidirectional relay (reader)
					go func() {
						relayBuf := make([]byte, 32*1024)
						for {
							rn, err := targetConn.Read(relayBuf)
							if rn > 0 {
								writeMu.Lock()
								df, errEnc := enc.Encode(streamID, 0x00, relayBuf[:rn])
								if errEnc == nil {
									conn.Write(df)
								}
								writeMu.Unlock()
							}
							if err != nil {
								break
							}
						}
						streamInfo.closeOnce.Do(func() { close(streamInfo.writeChan) })
					}()
				}(sid, targetAddr)
			} else {
				// Standard DATA frame
				mu.Lock()
				tc, exists := activeStreams[sid]
				mu.Unlock()

				if exists {
					tc.writeChan <- frame.Data
				}
			}
		}
	}
}

func buildServerHello(serverEKPub, serverRandom []byte, clientID [16]byte) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(0xDeadBeEF))
	buf.WriteByte(1) // version
	buf.WriteByte(0) // status = accept
	buf.Write(serverRandom)
	buf.Write(serverEKPub)
	buf.Write(make([]byte, 32)) // server hash placeholder
	binary.Write(buf, binary.BigEndian, uint16(1)) // cipher = CHACHA
	buf.Write(make([]byte, 32)) // cert hash placeholder
	buf.Write(clientID[:])
	binary.Write(buf, binary.BigEndian, uint32(3600)) // session lifetime
	buf.Write([]byte{0, 0, 0, 0}) // hash tag
	return buf.Bytes()
}

// readTCPFrame reads a complete MFP frame (header + encrypted payload + auth tag) from r.
func readTCPFrame(r io.Reader) ([]byte, error) {
	header := make([]byte, 14)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	payloadLen := binary.BigEndian.Uint16(header[1:3])
	// Payload ciphertext is followed by 16-byte Poly1305 Auth Tag
	frameData := make([]byte, 14+int(payloadLen)+16)
	copy(frameData[0:14], header)
	if _, err := io.ReadFull(r, frameData[14:]); err != nil {
		return nil, err
	}
	return frameData, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// QUIC Wrapper
// ─────────────────────────────────────────────────────────────────────────────

type quicStreamWrapper struct {
	*quic.Stream
	qconn *quic.Conn
}

func (q *quicStreamWrapper) LocalAddr() net.Addr {
	return q.qconn.LocalAddr()
}

func (q *quicStreamWrapper) RemoteAddr() net.Addr {
	return q.qconn.RemoteAddr()
}

func (q *quicStreamWrapper) Close() error {
	q.Stream.CancelRead(0)
	q.Stream.Close()
	return q.qconn.CloseWithError(0, "closed")
}
