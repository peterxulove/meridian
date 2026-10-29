// Meridian server — high-performance, anti-detection secure proxy.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
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
	cfg          config.ServerConfig
	udp          *net.UDPConn
	conns        sync.Map
	hyServer     server.Server
	stopped      atomic.Bool
	wg           sync.WaitGroup
	stats        ServerStats
	mirror       *transport.MirrorListener
	ws           *transport.WSListener
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
	switch s.cfg.Transport {
	case config.TransportWebSocket:
		return s.startWS()
	case config.TransportHTTPPOST:
		return s.startHTTPPOST()
	case config.TransportHybrid:
		// QUIC is UDP and WebSocket is TCP, so both can share the same port.
		// This lets existing QUIC clients keep working while new clients use
		// the higher-throughput TCP lane pool.
		go func() {
			if err := s.startWS(); err != nil && !s.stopped.Load() {
				fmt.Printf("  [WebSocket] Listen error: %v\n", err)
			}
		}()
		return s.startHysteria()
	default:
		// Legacy raw-TCP fallback for configurations that predate WebSocket.
		go s.startTCP()
		return s.startHysteria()
	}
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

// startHTTPPOST serves the HTTP-POST mirror transport: the client uploads
// each Meridian frame as a multipart form POST and reads downlink bytes from
// the response body. The listener turns those short requests back into
// long-lived sessions, which are driven by the same handleTCPTunnel path.
func (s *Server) startHTTPPOST() error {
	listener := transport.NewMirrorListener(s.cfg)
	s.mirror = listener

	go func() {
		if err := listener.ListenAndServe(); err != nil {
			if !s.stopped.Load() {
				fmt.Printf("  [HTTP-POST] Listen error: %v\n", err)
			}
		}
	}()

	fmt.Printf("  [HTTP-POST] Listening on %s%s (tunnel server)\n", s.cfg.ListenAddr, listener.Path())

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

func (s *Server) startWS() error {
	listener := transport.NewWSListener(s.cfg)
	s.ws = listener

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

// The UDP socket created in startHysteria is owned entirely by the Hysteria
// server, which parses and dispatches every datagram itself. Meridian's own
// MTP/MFP framing runs over the TCP-like stream Hysteria exposes (see
// hysteriaOutbound.TCP → handleTCPTunnel), so there is no separate UDP packet
// path to handle here.
//
// The former handlePacket/doHandshake/forwardFrame trio was dead code: nothing
// called it, and its handshake path was an unfinished TODO. It was removed
// rather than left as a misleading stub.

// Stop signals the server to shut down and waits for all goroutines to exit.
func (s *Server) Stop() {
	s.stopped.Store(true)
	if s.hyServer != nil {
		s.hyServer.Close()
	}
	if s.udp != nil {
		s.udp.Close()
	}
	if s.ws != nil {
		_ = s.ws.Close()
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
	id        uint32
	conn      net.Conn
	writeChan chan []byte
	done      chan struct{}
	closeOnce sync.Once
	flow      *mfp.FlowWindow
	ack       *mfp.AckTracker
	// buffered counts bytes queued for the target but not yet written. It is
	// the stall signal: the client can only have one flow-control window of
	// unacknowledged bytes in flight, so holding more than that means this
	// target has stopped draining and only this stream should be reset.
	buffered  atomic.Int64
	maxBuffer int64
}

// enqueue hands one DATA frame to the target writer. It reports false when the
// stream already holds more unread bytes than the peer could have in flight.
func (as *activeStream) enqueue(data []byte) bool {
	size := int64(len(data))
	if as.maxBuffer > 0 && as.buffered.Load()+size > as.maxBuffer {
		return false
	}
	as.buffered.Add(size)
	select {
	case as.writeChan <- data:
		return true
	case <-as.done:
		as.buffered.Add(-size)
		return true
	}
}

const (
	// DATA frame flags carrying the control-plane result of a CONNECT.
	flagConnect      = 0x01
	flagConnectError = 0x08

	// tunnelWriteTimeout keeps one unresponsive peer from holding writeMu
	// forever. Once a tunnel write times out the frame stream is unsynchronised,
	// so the tunnel is closed and the client reconnects.
	tunnelWriteTimeout = 30 * time.Second
	// maxDecodeFailures bounds how many frames may fail authentication before
	// the tunnel is considered desynchronised and torn down.
	maxDecodeFailures = 16
)

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

	// ── Authenticate the client ────────────────────────────────────────────
	// The TCP listener is reachable by anyone who can route to this port, so
	// the password must be checked here too — the Hysteria authenticator only
	// covers the UDP path. Without this the server is an open proxy.
	if err := authenticateHello(hs, s.cfg.Password); err != nil {
		fmt.Printf("  [TCP Handshake] Auth failed from %s: %v\n", conn.RemoteAddr(), err)
		// Report a generic failure so unauthenticated peers cannot probe which
		// inputs are valid.
		conn.Write([]byte{0x00})
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

	// Per-stream ACK flow control needs both ends to understand ACK frames.
	// The client advertises it with a ClientHello flag; echoing version 2 in
	// ServerHello confirms the server also supports it. Version 1 clients get
	// the old unlimited behaviour.
	flowControl := hs.FlowControl
	negotiatedVer := byte(1)
	if flowControl {
		negotiatedVer = 2
	}

	// Build & Send ServerHello
	sh := buildServerHello(negotiatedVer, status, serverEKPub, serverRandomBytes, hs.ClientID)
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

	// Mirror the client's anti-detection settings. Padding mode must match on
	// both sides or the length prefix cannot be stripped on decode.
	padCfg := mfp.PaddingConfig{
		Mode:     s.cfg.PaddingMode,
		BaseSize: s.cfg.BasePayloadSize,
		MaxSize:  s.cfg.MaxPayloadSize,
		Balanced: s.cfg.DirectionBalance,
	}
	enc.SetPadding(padCfg)
	dec.SetPadding(padCfg)
	if s.cfg.DirectionBalance {
		bal := mfp.NewDirectionBalancer(true)
		enc.SetBalancer(bal)
		dec.SetBalancer(bal)
	}

	// Map of active StreamID -> target connection
	activeStreams := make(map[uint32]*activeStream)
	pendingDials := make(map[uint32]struct{})
	streamLimit := int(s.cfg.MaxConcurrentStream)
	var mu sync.Mutex      // protects activeStreams and pendingDials
	var writeMu sync.Mutex // serialises encoder use and frame writes
	tunnelClosed := new(atomic.Bool)

	// done is closed exactly once when this tunnel goes away. Every goroutine
	// that can outlive the dispatch loop watches it so it cannot leak a target
	// connection or block forever on a dead tunnel.
	done := make(chan struct{})
	var closeTunnelOnce sync.Once
	closeTunnel := func() {
		closeTunnelOnce.Do(func() {
			close(done)
			conn.Close()
		})
	}
	defer closeTunnel()

	// send encodes and writes one frame (plus its rekey marker) atomically.
	// The write deadline guarantees a stalled peer cannot hold writeMu forever.
	send := func(typ byte, sid uint32, flags byte, data []byte) error {
		select {
		case <-done:
			return net.ErrClosed
		default:
		}

		writeMu.Lock()
		defer writeMu.Unlock()

		frame, boundary, err := enc.EncodeTypeAndRenew(typ, sid, flags, data)
		if err != nil {
			return err
		}
		conn.SetWriteDeadline(time.Now().Add(tunnelWriteTimeout))
		defer conn.SetWriteDeadline(time.Time{})
		if _, err := conn.Write(frame); err != nil {
			return err
		}
		if len(boundary) > 0 {
			if _, err := conn.Write(boundary); err != nil {
				return err
			}
		}
		return nil
	}

	// retireStream removes a stream exactly once. The caller sends a RESET only
	// when retireStream reports that it was the one that actually retired it.
	retireStream := func(st *activeStream) bool {
		fired := false
		st.closeOnce.Do(func() {
			fired = true
			close(st.done)
			st.conn.Close()
			st.flow.Close()
			mu.Lock()
			if activeStreams[st.id] == st {
				delete(activeStreams, st.id)
			}
			mu.Unlock()
		})
		return fired
	}

	defer func() {
		closeTunnel()
		mu.Lock()
		tunnelClosed.Store(true)
		streams := make([]*activeStream, 0, len(activeStreams))
		for _, st := range activeStreams {
			streams = append(streams, st)
		}
		activeStreams = make(map[uint32]*activeStream)
		pendingDials = make(map[uint32]struct{})
		mu.Unlock()
		for _, st := range streams {
			retireStream(st)
		}
	}()

	// A tunnel that stops sending anything for three keepalive periods is dead.
	idleTimeout := 3 * s.cfg.KeepaliveInterval
	if idleTimeout < 2*time.Minute {
		idleTimeout = 2 * time.Minute
	}
	decodeFailures := 0

	// Loop to read and dispatch MFP frames from client
	for {
		conn.SetReadDeadline(time.Now().Add(idleTimeout))
		frameData, err := readTCPFrame(conn)
		if err != nil {
			return // Client disconnected
		}

		frame, err := dec.Decode(frameData)
		if err != nil {
			decodeFailures++
			if decodeFailures >= maxDecodeFailures {
				fmt.Printf("  [Tunnel] closing desynchronised tunnel from %s\n", conn.RemoteAddr())
				return
			}
			continue
		}
		decodeFailures = 0

		// The peer announces the last frame under the current key with an
		// encrypted BOUNDARY marker. Both sides therefore rotate on the exact
		// same frame, regardless of their local clocks.
		if frame.Header.Type == mfp.TypeBOUNDARY {
			if err := dec.RotateKeys(); err != nil {
				fmt.Printf("  [Tunnel] key rotation failed: %v\n", err)
				return
			}
			continue
		}

		sid := frame.Header.StreamID

		// Keepalive: answer client PINGs so idle tunnels survive NAT timeouts.
		// Stream 0 is the control stream and never maps to a target connection.
		if frame.Header.Type == mfp.TypePING {
			if err := send(mfp.TypePONG, 0, 0, frame.Data); err != nil {
				return
			}
			continue
		}

		// Dummy frames injected for direction balancing are well-formed AEAD
		// frames, but they carry no stream data — just skip them.
		if frame.Header.Type == mfp.TypeKEEPALIVE {
			continue
		}

		if frame.Header.Type == mfp.TypeRESET {
			mu.Lock()
			delete(pendingDials, sid)
			tc := activeStreams[sid]
			mu.Unlock()
			if tc != nil {
				retireStream(tc)
			}
			continue
		}

		// ACK releases flow-control credit for bytes the client's application
		// has consumed. It is cumulative, so duplicates are harmless.
		if frame.Header.Type == mfp.TypeACK {
			if cum, ok := mfp.DecodeAck(frame.Data); ok {
				mu.Lock()
				tc := activeStreams[sid]
				mu.Unlock()
				if tc != nil {
					tc.flow.Ack(cum)
				}
			}
			continue
		}

		if frame.Header.Type == mfp.TypeDATA {
			flags := frame.Header.Flags
			if flags == 0x01 {
				// CONNECT stream request
				targetAddr := string(frame.Data)
				if targetAddr == "" {
					if err := send(mfp.TypeRESET, sid, 0, nil); err != nil {
						return
					}
					continue
				}

				// max_concurrent_streams caps how many target connections one
				// tunnel may hold. The client turns this into a clean retry on
				// another lane instead of an ever-growing dial storm.
				mu.Lock()
				atCapacity := streamLimit > 0 && len(activeStreams)+len(pendingDials) >= streamLimit
				mu.Unlock()
				if atCapacity {
					if err := send(mfp.TypeDATA, sid, flagConnectError,
						[]byte("server busy: stream limit reached")); err != nil {
						return
					}
					continue
				}

				mu.Lock()
				_, busy := activeStreams[sid]
				_, dialing := pendingDials[sid]
				if !busy && !dialing {
					pendingDials[sid] = struct{}{}
				}
				mu.Unlock()
				if busy || dialing {
					continue
				}

				go func(streamID uint32, addr string) {
					// Perform dial directly on server (resolving DNS on server side!)
					dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
					targetConn, err := dialer.Dial("tcp", addr)
					if err != nil {
						mu.Lock()
						delete(pendingDials, streamID)
						mu.Unlock()
						if sendErr := send(mfp.TypeDATA, streamID, 0x08, []byte(err.Error())); sendErr != nil {
							closeTunnel()
						}
						return
					}

					// A RESET may have arrived while the dial was in flight; the
					// pending entry is removed in that case, so do not resurrect
					// the stream (which would leak the target connection).
					mu.Lock()
					_, stillPending := pendingDials[streamID]
					closedNow := tunnelClosed.Load()
					if stillPending && !closedNow {
						delete(pendingDials, streamID)
					}
					mu.Unlock()
					select {
					case <-done:
						targetConn.Close()
						return
					default:
					}
					if !stillPending || closedNow {
						targetConn.Close()
						return
					}

					streamInfo := &activeStream{
						id:        streamID,
						conn:      targetConn,
						writeChan: make(chan []byte, config.StreamQueueFrames),
						done:      make(chan struct{}),
						maxBuffer: config.StreamBufferLimit(s.cfg.StreamWindow),
					}
					if flowControl {
						streamInfo.flow = mfp.NewFlowWindow(int64(s.cfg.StreamWindow))
						streamInfo.ack = mfp.NewAckTracker(s.cfg.StreamWindow)
					}

					mu.Lock()
					activeStreams[streamID] = streamInfo
					mu.Unlock()

					// Send CONNECT SUCCESS frame (Flags = 0x01)
					if err := send(mfp.TypeDATA, streamID, 0x01, []byte("OK")); err != nil {
						retireStream(streamInfo)
						closeTunnel()
						return
					}

					// Start writer goroutine
					go func() {
						for {
							select {
							case <-streamInfo.done:
								return
							case <-done:
								retireStream(streamInfo)
								return
							case data := <-streamInfo.writeChan:
								if _, err := targetConn.Write(data); err != nil {
									if retireStream(streamInfo) {
										_ = send(mfp.TypeRESET, streamID, 0, nil)
									}
									return
								}
								streamInfo.buffered.Add(-int64(len(data)))
								// Tell the client these bytes reached the target so it
								// can release flow-control credit for them.
								if cum, due := streamInfo.ack.Consume(len(data)); due {
									if sendErr := send(mfp.TypeACK, streamID, 0, mfp.EncodeAck(cum)); sendErr != nil {
										retireStream(streamInfo)
										return
									}
								}
							}
						}
					}()

					// Start bidirectional relay (reader)
					go func() {
						defer func() {
							if retireStream(streamInfo) {
								_ = send(mfp.TypeRESET, streamID, 0, nil)
							}
						}()
						relayBuf := make([]byte, 60*1024)
						for {
							rn, err := targetConn.Read(relayBuf)
							if rn > 0 {
								// Never let one bulk stream put more than the window
								// on the wire: that is what keeps a new stream's
								// first response from queueing behind megabytes.
								if flowErr := streamInfo.flow.Acquire(int64(rn)); flowErr != nil {
									break
								}
								if sendErr := send(mfp.TypeDATA, streamID, 0, relayBuf[:rn]); sendErr != nil {
									streamInfo.flow.Refund(int64(rn))
									closeTunnel()
									return
								}
							}
							if err != nil {
								break
							}
						}
					}()
				}(sid, targetAddr)
			} else {
				// Standard DATA frame
				mu.Lock()
				tc, exists := activeStreams[sid]
				mu.Unlock()

				if !exists {
					continue
				}
				// Never block the tunnel-wide dispatch loop on one slow target.
				// If a stream holds more unread bytes than the peer can have in
				// flight, reset just that stream so the application reconnects;
				// the other streams keep working.
				select {
				case <-done:
					return
				default:
				}
				if !tc.enqueue(frame.Data) {
					fmt.Printf("  [Tunnel] stream %d stalled, resetting\n", sid)
					if retireStream(tc) {
						go send(mfp.TypeRESET, sid, 0, nil)
					}
				}
			}
		}
	}
}

func buildServerHello(version, status byte, serverEKPub, serverRandom []byte, clientID [16]byte) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(0xDeadBeEF))
	buf.WriteByte(version) // negotiated version (mirrors the ClientHello)
	buf.WriteByte(status)  // status
	buf.Write(serverRandom)
	buf.Write(serverEKPub)
	buf.Write(make([]byte, 32))                    // server hash placeholder
	binary.Write(buf, binary.BigEndian, uint16(1)) // cipher = CHACHA
	buf.Write(make([]byte, 32))                    // cert hash placeholder
	buf.Write(clientID[:])
	binary.Write(buf, binary.BigEndian, uint32(3600)) // session lifetime
	buf.Write([]byte{0, 0, 0, 0})                     // hash tag
	return buf.Bytes()
}

// authenticateHello validates the auth extension carried in a ClientHello
// against the configured password. It is a no-op when no password is set,
// which keeps passwordless test environments working.
func authenticateHello(hs *mtp.Handshake, password string) error {
	if password == "" {
		return nil
	}
	ext := mtp.FindExtension(hs.Extensions, mtp.ExtAuth)
	if ext == nil {
		return errors.New("no auth extension")
	}
	return mtp.VerifyAuth(ext.Data, password, &hs.ClientRandom, hs.ClientECDHE, time.Now())
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
