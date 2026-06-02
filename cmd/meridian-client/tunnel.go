package main

import (
	"context"
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

	"github.com/quic-go/quic-go"
)

// TunnelClient manages the secure multiplexed TCP tunnel to the server.
type TunnelClient struct {
	cfg           config.ClientConfig
	tunnelConn    net.Conn
	encoder       *mfp.Encoder
	decoder       *mfp.Decoder
	mu            sync.Mutex
	activeStreams map[uint32]*StreamConn
	streamIDAlloc uint32
	closed        atomic.Bool
	handshakeDone chan struct{}
}

// NewTunnelClient creates a new TunnelClient.
func NewTunnelClient(cfg config.ClientConfig) *TunnelClient {
	return &TunnelClient{
		cfg:           cfg,
		activeStreams: make(map[uint32]*StreamConn),
		handshakeDone: make(chan struct{}),
	}
}

// Connect establishes the TCP or QUIC connection and performs the MTP handshake.
func (tc *TunnelClient) Connect() error {
	var conn net.Conn

	if tc.cfg.Transport == "QUIC" {
		tlsCfg, err := transport.ClientTLSConfig(tc.cfg)
		if err != nil {
			return fmt.Errorf("tunnel: TLS config error: %w", err)
		}
		
		ctx, cancel := context.WithTimeout(context.Background(), tc.cfg.DialTimeout)
		defer cancel()
		
		qconn, err := quic.DialAddr(ctx, tc.cfg.ServerAddr, tlsCfg, &quic.Config{
			KeepAlivePeriod:            15 * time.Second,
			MaxStreamReceiveWindow:     8 * 1024 * 1024,  // 8MB
			MaxConnectionReceiveWindow: 20 * 1024 * 1024, // 20MB
		})
		if err != nil {
			return fmt.Errorf("tunnel: QUIC dial failed: %w", err)
		}
		
		stream, err := qconn.OpenStreamSync(ctx)
		if err != nil {
			qconn.CloseWithError(1, err.Error())
			return fmt.Errorf("tunnel: QUIC open stream failed: %w", err)
		}
		conn = &quicStreamWrapper{Stream: stream, qconn: qconn}
	} else {
		tcpConn, err := net.DialTimeout("tcp", tc.cfg.ServerAddr, tc.cfg.DialTimeout)
		if err != nil {
			return fmt.Errorf("tunnel: TCP dial failed: %w", err)
		}
		conn = tcpConn
	}
	tc.tunnelConn = conn

	// ── MTP Handshake (Client Side) ───────────────────────────────────────
	ek, err := crypto.GenerateKeyPair()
	if err != nil {
		conn.Close()
		return fmt.Errorf("tunnel: key generation failed: %w", err)
	}

	cr, err := crypto.GenerateRandom(32)
	if err != nil {
		conn.Close()
		return fmt.Errorf("tunnel: generate client random failed: %w", err)
	}
	var crArr [32]byte
	copy(crArr[:], cr)

	hello, err := mtp.BuildClientHello(tc.cfg, &crArr, ek.PubKey)
	if err != nil {
		conn.Close()
		return fmt.Errorf("tunnel: BuildClientHello failed: %w", err)
	}

	// Write ClientHello
	if _, err := conn.Write(hello); err != nil {
		conn.Close()
		return fmt.Errorf("tunnel: failed to write ClientHello: %w", err)
	}

	// Read ServerHello
	respBuf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(tc.cfg.HandshakeTimeout))
	_, err = io.ReadAtLeast(conn, respBuf, 136) // Min ServerHello size
	if err != nil {
		conn.Close()
		return fmt.Errorf("tunnel: failed to read ServerHello: %w", err)
	}
	conn.SetReadDeadline(time.Time{})

	// Validate ServerHello Magic
	if binary.BigEndian.Uint32(respBuf[0:4]) != uint32(0xDeadBeEF) {
		conn.Close()
		return fmt.Errorf("tunnel: invalid magic in ServerHello")
	}

	serverRandom := respBuf[6:38]
	serverEKPub := respBuf[38:70]

	// Compute shared secret
	shared, err := crypto.SharedKey(ek, serverEKPub)
	if err != nil {
		conn.Close()
		return fmt.Errorf("tunnel: SharedKey computation failed: %w", err)
	}

	// Derive Keys
	var srArr [32]byte
	copy(srArr[:], serverRandom)
	keys, err := crypto.DeriveKeys(shared, crArr, srArr)
	if err != nil {
		conn.Close()
		return fmt.Errorf("tunnel: DeriveKeys failed: %w", err)
	}

	tc.encoder = mfp.NewEncoder(keys)
	tc.decoder = mfp.NewDownlinkDecoder(keys)

	if config.DebugMode {
		fmt.Printf("[DEBUG] [Tunnel] Handshake successful over %s! Cipher: MERIDIAN-CHACHA\n", tc.cfg.Transport)
	} else {
		fmt.Printf("  [Tunnel] Handshake successful over %s! Cipher: MERIDIAN-CHACHA\n", tc.cfg.Transport)
	}

	// Start read loop
	go tc.readLoop()

	return nil
}

// DialStream allocates a new StreamID and requests a connection to targetAddr.
func (tc *TunnelClient) DialStream(ctx context.Context, targetAddr string) (net.Conn, error) {
	if tc.closed.Load() {
		return nil, errors.New("tunnel: client is closed")
	}

	sid := atomic.AddUint32(&tc.streamIDAlloc, 1)

	sc := &StreamConn{
		sid:         sid,
		client:      tc,
		readChan:    make(chan []byte, 128),
		confirmChan: make(chan bool, 1),
		closed:      make(chan struct{}),
	}

	tc.mu.Lock()
	tc.activeStreams[sid] = sc
	tc.mu.Unlock()

	// Send CONNECT frame
	tc.mu.Lock()
	connFrame, err := tc.encoder.Encode(sid, 0x01, []byte(targetAddr)) // Flags = 0x01: Connect Request
	if err != nil {
		tc.mu.Unlock()
		tc.removeStream(sid)
		return nil, fmt.Errorf("tunnel: failed to encode connect frame: %w", err)
	}
	_, err = tc.tunnelConn.Write(connFrame)
	tc.mu.Unlock()

	if err != nil {
		tc.removeStream(sid)
		return nil, fmt.Errorf("tunnel: failed to send connect frame: %w", err)
	}

	// Wait for confirmation (Flags = 0x01 from server)
	select {
	case success := <-sc.confirmChan:
		if !success {
			tc.removeStream(sid)
			if config.DebugMode {
				fmt.Printf("[DEBUG] [Tunnel] Stream %d connection rejected by server\n", sid)
			}
			return nil, fmt.Errorf("tunnel: connection rejected by server")
		}
		if config.DebugMode {
			fmt.Printf("[DEBUG] [Tunnel] Stream %d connection established to %s\n", sid, targetAddr)
		}
	case <-ctx.Done():
		tc.removeStream(sid)
		return nil, ctx.Err()
	case <-time.After(tc.cfg.DialTimeout):
		tc.removeStream(sid)
		return nil, errors.New("tunnel: dial timeout waiting for server response")
	}

	return sc, nil
}

func (tc *TunnelClient) removeStream(sid uint32) {
	tc.mu.Lock()
	delete(tc.activeStreams, sid)
	tc.mu.Unlock()
}

func (tc *TunnelClient) readLoop() {
	defer tc.Close()
	for {
		frameData, err := readTCPFrame(tc.tunnelConn)
		if err != nil {
			return
		}

		frame, err := tc.decoder.Decode(frameData)
		if err != nil {
			continue
		}

		sid := frame.Header.StreamID
		flags := frame.Header.Flags

		tc.mu.Lock()
		sc, exists := tc.activeStreams[sid]
		tc.mu.Unlock()

		if exists {
			if frame.Header.Type == mfp.TypeRESET {
				sc.CloseFromServer()
			} else if frame.Header.Type == mfp.TypeDATA {
				if flags == 0x01 {
					sc.confirmChan <- true
				} else {
					select {
					case sc.readChan <- frame.Data:
					default:
						// drop data if channel full to avoid blocking readLoop
					}
				}
			}
		}
	}
}

// Close gracefully closes the tunnel client.
func (tc *TunnelClient) Close() {
	if tc.closed.CompareAndSwap(false, true) {
		if tc.tunnelConn != nil {
			tc.tunnelConn.Close()
		}
		tc.mu.Lock()
		for _, sc := range tc.activeStreams {
			sc.CloseFromServer()
		}
		tc.mu.Unlock()
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// StreamConn represents a multiplexed TCP stream over the secure tunnel
// ─────────────────────────────────────────────────────────────────────────────

type StreamConn struct {
	sid         uint32
	client      *TunnelClient
	readChan    chan []byte
	confirmChan chan bool
	closed      chan struct{}
	closeOnce   sync.Once
	leftover    []byte
}

func (sc *StreamConn) Read(b []byte) (int, error) {
	if len(sc.leftover) > 0 {
		n := copy(b, sc.leftover)
		sc.leftover = sc.leftover[n:]
		return n, nil
	}

	select {
	case data, ok := <-sc.readChan:
		if !ok {
			return 0, io.EOF
		}
		n := copy(b, data)
		if n < len(data) {
			sc.leftover = data[n:]
		}
		return n, nil
	case <-sc.closed:
		return 0, io.EOF
	}
}

func (sc *StreamConn) Write(b []byte) (int, error) {
	select {
	case <-sc.closed:
		return 0, io.ErrClosedPipe
	default:
	}

	sc.client.mu.Lock()
	frame, err := sc.client.encoder.Encode(sc.sid, 0x00, b)
	if err != nil {
		sc.client.mu.Unlock()
		return 0, err
	}
	_, err = sc.client.tunnelConn.Write(frame)
	sc.client.mu.Unlock()

	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (sc *StreamConn) Close() error {
	sc.closeOnce.Do(func() {
		close(sc.closed)
		sc.client.removeStream(sc.sid)
		// Send RESET frame to server
		sc.client.mu.Lock()
		frame, err := sc.client.encoder.Encode(sc.sid, mfp.TypeRESET, nil)
		if err == nil {
			sc.client.tunnelConn.Write(frame)
		}
		sc.client.mu.Unlock()
	})
	return nil
}

func (sc *StreamConn) CloseFromServer() {
	sc.closeOnce.Do(func() {
		close(sc.closed)
		close(sc.readChan)
	})
}

func (sc *StreamConn) LocalAddr() net.Addr            { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }
func (sc *StreamConn) RemoteAddr() net.Addr           { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }
func (sc *StreamConn) SetDeadline(t time.Time) error  { return nil }
func (sc *StreamConn) SetReadDeadline(t time.Time) error { return nil }
func (sc *StreamConn) SetWriteDeadline(t time.Time) error { return nil }

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
