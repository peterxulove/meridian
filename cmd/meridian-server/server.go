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

	"meridian/pkg/config"
	"meridian/pkg/crypto"
	"meridian/pkg/mfp"
	"meridian/pkg/mtp"
	"meridian/pkg/transport"

	"github.com/apernet/hysteria/core/v2/server"
)

// Server manages Meridian connections.
type Server struct {
	cfg     config.ServerConfig
	udp     *net.UDPConn
	conns    sync.Map
	hyServer server.Server
	stopped  atomic.Bool
	wg       sync.WaitGroup
	stats    ServerStats
	sessionStore *mtp.SessionStore
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
	return &Server{
		cfg:          cfg,
		sessionStore: mtp.NewSessionStore(),
	}, nil
}

// Start begins listening on the configured address.
func (s *Server) Start() error {
	if s.cfg.Transport == config.TransportWebSocket {
		return s.startWS()
	}
	// Start TCP Tunnel listener concurrently for reliable proxying
	go s.startTCP()
	return s.startHysteria()
}

func (s *Server) startHysteria() error {
	tlsCfg, err := transport.ServerTLSConfig(s.cfg)
	if err != nil {
		return err
	}
	
	udpAddr, err := net.ResolveUDPAddr("udp", s.cfg.ListenAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	s.udp = conn

	hyServer, err := server.NewServer(&server.Config{
		Conn: conn,
		TLSConfig: server.TLSConfig{
			Certificates:   tlsCfg.Certificates,
			GetCertificate: tlsCfg.GetCertificate,
			ClientCAs:      tlsCfg.ClientCAs,
		},
		Authenticator: &dummyAuthenticator{password: s.cfg.Password},
		Outbound:      &hysteriaOutbound{s: s},
		BandwidthConfig: server.BandwidthConfig{
			MaxTx: s.cfg.DownMbps * 1024 * 1024 / 8, // DownMbps server tx
			MaxRx: s.cfg.UpMbps * 1024 * 1024 / 8,
		},
		DisableUDP: true,
	})
	if err != nil {
		return err
	}
	s.hyServer = hyServer

	fmt.Printf("  [Hysteria v2] Listening on %s (tunnel server)\n", s.cfg.ListenAddr)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := hyServer.Serve(); err != nil {
			if !s.stopped.Load() {
				fmt.Printf("[Hysteria v2] Serve failed: %v\n", err)
			}
		}
	}()
	return nil
}

func (s *Server) startWS() error {
	listener := transport.NewWSListener(s.cfg)
	
	go func() {
		if err := listener.ListenAndServe(); err != nil {
			if !s.stopped.Load() {
				fmt.Printf("  [WebSocket] Listen error: %v\n", err)
			}
		}
	}()

	fmt.Printf("  [WebSocket] Listening on %s%s (tunnel server)\n", s.cfg.ListenAddr, s.cfg.WSSPath)

	for {
		if s.stopped.Load() {
			break
		}
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go s.handleTCPTunnel(conn)
	}
	return nil
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
	if s.hyServer != nil {
		s.hyServer.Close()
	}
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
	n, err := io.ReadAtLeast(conn, buf, 136)
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

	var keys *crypto.KeyMaterial
	var status byte = 1 // 1 = full handshake, 0 = resume accepted
	var serverEKPub []byte = make([]byte, 32)
	var serverRandomBytes []byte = make([]byte, 32)

	if hs.IsResume {
		if cached, ok := s.sessionStore.Lookup(hs.ClientID); ok {
			keys = cached.Keys
			status = 0
		}
	}

	if status != 0 {
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

		serverRandomBytes, err = crypto.GenerateRandom(32)
		if err != nil {
			return
		}
		var serverRandom [32]byte
		copy(serverRandom[:], serverRandomBytes)

		keys, err = crypto.DeriveKeys(shared, hs.ClientRandom, serverRandom)
		if err != nil {
			return
		}
		serverEKPub = serverEK.PubKey

		s.sessionStore.Store(hs.ClientID, &mtp.SessionEntry{
			Keys:         keys,
			ExpiresAt:    time.Now().Add(1 * time.Hour),
			ClientRandom: hs.ClientRandom,
			ServerRandom: serverRandom,
		})
	}

	// Build & Send ServerHello
	sh := buildServerHello(status, serverEKPub, serverRandomBytes, hs.ClientID)
	if _, err := conn.Write(sh); err != nil {
		return
	}

	if config.DebugMode {
		fmt.Printf("  [TCP Handshake] OK from %s cipher=MERIDIAN-CHACHA (resume=%v)\n", conn.RemoteAddr(), status == 0)
	} else {
		fmt.Printf("  [TCP Handshake] OK from %s cipher=MERIDIAN-CHACHA\n", conn.RemoteAddr())
	}

	// Create Encoder and Decoder
	enc := mfp.NewDownlinkEncoder(keys)
	enc.SetRenewal(s.cfg.RenewalDataLimit, s.cfg.RenewalInterval)
	dec := mfp.NewUplinkDecoder(keys)
	dec.SetRenewal(s.cfg.RenewalDataLimit, s.cfg.RenewalInterval)

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

		if dec.ShouldRotate() {
			if config.DebugMode {
				fmt.Println("[DEBUG] Rotating keys on server decoder")
			}
			if err := dec.RotateKeys(); err != nil && config.DebugMode {
				fmt.Printf("[DEBUG] Failed to rotate server decoder keys: %v\n", err)
			}
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
						if enc.ShouldRotate() {
							enc.RotateKeys()
						}
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
					if enc.ShouldRotate() {
						enc.RotateKeys()
					}
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
						if enc.ShouldRotate() {
							enc.RotateKeys()
						}
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
									if enc.ShouldRotate() {
										if config.DebugMode {
											fmt.Println("[DEBUG] Rotating keys on server encoder")
										}
										enc.RotateKeys()
									}
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

func buildServerHello(status byte, serverEKPub, serverRandom []byte, clientID [16]byte) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(0xDeadBeEF))
	buf.WriteByte(1) // version
	buf.WriteByte(status) // status
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
// Hysteria Outbound & Auth
// ─────────────────────────────────────────────────────────────────────────────

type dummyAuthenticator struct {
	password string
}

func (a *dummyAuthenticator) Authenticate(addr net.Addr, auth string, tx uint64) (ok bool, id string) {
	return auth == a.password, ""
}

type hysteriaOutbound struct {
	s *Server
}

func (h *hysteriaOutbound) TCP(reqAddr string) (net.Conn, error) {
	c1, c2 := net.Pipe()
	go h.s.handleTCPTunnel(c1)
	return c2, nil
}

func (h *hysteriaOutbound) UDP(reqAddr string) (server.UDPConn, error) {
	return nil, fmt.Errorf("udp not supported")
}

func (h *hysteriaOutbound) CheckUDP(reqAddr string) error {
	return fmt.Errorf("udp not supported")
}
