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

	"github.com/apernet/hysteria/core/v2/client"
)

// TunnelClient manages the secure multiplexed TCP tunnel to the server.
type TunnelClient struct {
	cfg           config.ClientConfig
	tunnelConn    net.Conn
	encoder       *mfp.Encoder
	decoder       *mfp.Decoder
	mu            sync.Mutex
	writeMu       sync.Mutex
	activeStreams map[uint32]*StreamConn
	streamIDAlloc uint32
	closed        atomic.Bool
	handshakeDone chan struct{}
	sessionStore  *mtp.SessionStore
	padCfg        mfp.PaddingConfig
	balancer      *mfp.DirectionBalancer
	closeCh       chan struct{}
	lastRecv      atomic.Int64
	activeLoad    atomic.Int64
	connectedAt   time.Time
	draining      atomic.Bool
	flowControl   bool
}

// errLaneSaturated is returned when a lane already carries its configured
// number of streams. The caller retries on another lane instead of failing the
// user connection.
var errLaneSaturated = errors.New("tunnel: lane saturated")

const (
	// DATA frame flags carrying the control-plane result of a CONNECT.
	flagConnect      = 0x01
	flagConnectError = 0x08

	// tunnelWriteTimeout bounds a single frame write. A peer that stops reading
	// would otherwise pin writeMu (and every stream) forever.
	tunnelWriteTimeout = 30 * time.Second
	// maxDecodeFailures is the point at which the tunnel is assumed to be
	// desynchronised and is torn down for a clean reconnect.
	maxDecodeFailures = 16
	// maxFrameDataSize leaves room for the 2-byte padding length prefix and
	// the small random tail while keeping the frame below the uint16 payload
	// limit.
	maxFrameDataSize = 60 * 1024
)

// NewTunnelClient creates a new TunnelClient.
func NewTunnelClient(cfg config.ClientConfig, sessionStore *mtp.SessionStore) *TunnelClient {
	return &TunnelClient{
		cfg:           cfg,
		activeStreams: make(map[uint32]*StreamConn),
		handshakeDone: make(chan struct{}),
		sessionStore:  sessionStore,
		closeCh:       make(chan struct{}),
	}
}

// Connect establishes the TCP or QUIC connection and performs the MTP handshake.
func (tc *TunnelClient) Connect() error {
	var conn net.Conn
	if tc.cfg.Transport == config.TransportHybrid {
		return errors.New("tunnel: client transport must be QUIC or WebSocket, not QUIC+WebSocket")
	}

	if tc.cfg.Transport == config.TransportHysteria || tc.cfg.Transport == "QUIC" || tc.cfg.Transport == "Hysteria" {
		tlsCfg, err := transport.ClientTLSConfig(tc.cfg)
		if err != nil {
			return fmt.Errorf("tunnel: TLS config error: %w", err)
		}

		serverAddr, err := net.ResolveUDPAddr("udp", tc.cfg.ServerAddr)
		if err != nil {
			return fmt.Errorf("tunnel: resolve UDP addr failed: %w", err)
		}

		hyClient, _, err := client.NewClient(&client.Config{
			ServerAddr: serverAddr,
			Auth:       tc.cfg.Password,
			TLSConfig: client.TLSConfig{
				ServerName:            tlsCfg.ServerName,
				InsecureSkipVerify:    tlsCfg.InsecureSkipVerify,
				VerifyPeerCertificate: tlsCfg.VerifyPeerCertificate,
				RootCAs:               tlsCfg.RootCAs,
			},
			BandwidthConfig: client.BandwidthConfig{
				MaxTx: tc.cfg.UpMbps * 1024 * 1024 / 8,
				MaxRx: tc.cfg.DownMbps * 1024 * 1024 / 8,
			},
		})
		if err != nil {
			return fmt.Errorf("tunnel: Hysteria client creation failed: %w", err)
		}

		stream, err := hyClient.TCP("dummy:80")
		if err != nil {
			hyClient.Close()
			return fmt.Errorf("tunnel: Hysteria TCP dial failed: %w", err)
		}
		conn = &hysteriaStreamWrapper{Conn: stream, hyClient: hyClient}
	} else if tc.cfg.Transport == config.TransportWebSocket || tc.cfg.Transport == "WebSocket" {
		wsURL := "wss://" + tc.cfg.ServerAddr + tc.cfg.WSSPath
		wsConn, err := transport.WSDial(wsURL, tc.cfg)
		if err != nil {
			return fmt.Errorf("tunnel: WebSocket dial failed: %w", err)
		}
		conn = wsConn
	} else if tc.cfg.Transport == config.TransportHTTPPOST || tc.cfg.Transport == "HTTP-POST" {
		postTransport := transport.NewHTTPPOSTTransport(tc.cfg)
		postConn, err := postTransport.Dial(tc.cfg.ServerAddr)
		if err != nil {
			return fmt.Errorf("tunnel: HTTP-POST dial failed: %w", err)
		}
		conn = postConn
	} else {
		tcpConn, err := net.DialTimeout("tcp", tc.cfg.ServerAddr, tc.cfg.DialTimeout)
		if err != nil {
			return fmt.Errorf("tunnel: TCP dial failed: %w", err)
		}
		conn = tcpConn
	}
	tc.tunnelConn = conn

	// ── MTP Handshake (Client Side) ───────────────────────────────────────
	var keys *crypto.KeyMaterial
	var resumeKeys *crypto.KeyMaterial
	var ek *crypto.KeyPair

	if cached, ok := tc.sessionStore.Lookup(tc.cfg.SessionID); ok {
		resumeKeys = cached.Keys
	}

	var err error
	ek, err = crypto.GenerateKeyPair()
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

	hello, err := mtp.BuildClientHello(tc.cfg, &crArr, ek.PubKey, resumeKeys)
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
	// HTTP-POST returns downlink bytes in discrete response bodies, so a
	// single Read may not fill the whole ServerHello. Accumulate until we
	// have at least the minimum size rather than relying on one read.
	var readTotal int
	for readTotal < 136 {
		n, rerr := conn.Read(respBuf[readTotal:])
		if rerr != nil {
			conn.Close()
			return fmt.Errorf("tunnel: failed to read ServerHello: %w", rerr)
		}
		readTotal += n
	}
	conn.SetReadDeadline(time.Time{})

	// Validate ServerHello Magic
	if binary.BigEndian.Uint32(respBuf[0:4]) != uint32(0xDeadBeEF) {
		conn.Close()
		return fmt.Errorf("tunnel: invalid magic in ServerHello")
	}

	serverRandom := respBuf[6:38]
	serverEKPub := respBuf[38:70]
	status := respBuf[5]
	// The server echoes the negotiated version. Version 2 peers exchange ACK
	// frames and honour the per-stream window; older servers do not, so we
	// keep the historical unlimited behaviour for them.
	tc.flowControl = respBuf[4] >= 2

	if resumeKeys != nil && status == 0 {
		// Server accepted resume
		keys = resumeKeys
		if config.DebugMode {
			fmt.Printf("[DEBUG] [Tunnel] 0-RTT session resumed successfully\n")
		}
	} else {
		// Compute shared secret
		shared, err := crypto.SharedKey(ek, serverEKPub)
		if err != nil {
			conn.Close()
			return fmt.Errorf("tunnel: SharedKey computation failed: %w", err)
		}

		// Derive Keys
		var srArr [32]byte
		copy(srArr[:], serverRandom)
		keys, err = crypto.DeriveKeys(shared, crArr, srArr)
		if err != nil {
			conn.Close()
			return fmt.Errorf("tunnel: DeriveKeys failed: %w", err)
		}

		// Store session for future resume
		tc.sessionStore.Store(tc.cfg.SessionID, &mtp.SessionEntry{
			Keys:         keys,
			ExpiresAt:    time.Now().Add(1 * time.Hour), // use negotiated lifetime later
			ClientRandom: crArr,
			ServerRandom: srArr,
		})
	}

	tc.encoder = mfp.NewEncoder(keys)
	tc.encoder.SetRenewal(tc.cfg.RenewalDataLimit, tc.cfg.RenewalInterval)
	tc.decoder = mfp.NewDownlinkDecoder(keys)
	tc.decoder.SetRenewal(tc.cfg.RenewalDataLimit, tc.cfg.RenewalInterval)

	// Wire the anti-detection settings from config. Both sides must agree on
	// the padding mode, otherwise the receiver cannot strip the length prefix.
	tc.padCfg = mfp.PaddingConfig{
		Mode:     tc.cfg.PaddingMode,
		BaseSize: tc.cfg.BasePayloadSize,
		MaxSize:  tc.cfg.MaxPayloadSize,
		Balanced: tc.cfg.DirectionBalance,
	}
	tc.encoder.SetPadding(tc.padCfg)
	tc.decoder.SetPadding(tc.padCfg)
	tc.encoder.SetJitterMS(tc.cfg.TimingJitterMS)
	if tc.cfg.DirectionBalance {
		tc.balancer = mfp.NewDirectionBalancer(true)
		tc.encoder.SetBalancer(tc.balancer)
		tc.decoder.SetBalancer(tc.balancer)
	}

	if config.DebugMode {
		fmt.Printf("[DEBUG] [Tunnel] Handshake successful over %s! Cipher: MERIDIAN-CHACHA\n", tc.cfg.Transport)
	} else {
		fmt.Printf("  [Tunnel] Handshake successful over %s! Cipher: MERIDIAN-CHACHA\n", tc.cfg.Transport)
	}

	tc.connectedAt = time.Now()

	// Start read loop
	go tc.readLoop()

	// Keepalive keeps the tunnel alive through NAT/firewall idle timeouts and
	// gives the balancer a reason to emit traffic when it is enabled.
	if tc.cfg.KeepaliveInterval > 0 {
		go tc.keepaliveLoop()
	}

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
		readChan:    make(chan []byte, config.StreamQueueDepth(tc.cfg.StreamWindow)),
		confirmChan: make(chan bool, 1),
		closed:      make(chan struct{}),
	}
	if tc.flowControl {
		sc.flow = mfp.NewFlowWindow(int64(tc.cfg.StreamWindow))
		sc.ack = mfp.NewAckTracker(tc.cfg.StreamWindow)
	}

	tc.mu.Lock()
	tc.activeStreams[sid] = sc
	tc.activeLoad.Add(1)
	tc.mu.Unlock()

	// Enforce the per-lane stream cap. The counter is incremented before the
	// check so two racing dials cannot both slip past the limit; the loser is
	// rolled back and the caller moves on to a less loaded lane.
	if limit := int64(tc.cfg.MaxConcurrentStream); limit > 0 && tc.activeLoad.Load() > limit {
		tc.removeStream(sid)
		sc.CloseFromServer()
		return nil, errLaneSaturated
	}

	// Send CONNECT frame (Flags = 0x01: connect request).
	if err := tc.sendFrame(mfp.TypeDATA, sid, flagConnect, []byte(targetAddr), 0); err != nil {
		tc.removeStream(sid)
		sc.CloseFromServer()
		return nil, fmt.Errorf("tunnel: failed to send connect frame: %w", err)
	}

	// Wait for confirmation (Flags = 0x01 from server)
	select {
	case success := <-sc.confirmChan:
		if !success {
			tc.removeStream(sid)
			sc.CloseFromServer()
			if config.DebugMode {
				fmt.Printf("[DEBUG] [Tunnel] Stream %d connection rejected by server\n", sid)
			}
			return nil, fmt.Errorf("tunnel: connection rejected by server")
		}
		if config.DebugMode {
			fmt.Printf("[DEBUG] [Tunnel] Stream %d connection established to %s\n", sid, targetAddr)
		}
	case <-ctx.Done():
		tc.abortStream(sid)
		return nil, ctx.Err()
	case <-tc.closeCh:
		tc.abortStream(sid)
		return nil, errors.New("tunnel: closed while dialing")
	case <-time.After(tc.cfg.DialTimeout):
		tc.abortStream(sid)
		return nil, errors.New("tunnel: dial timeout waiting for server response")
	}

	return sc, nil
}

// abortStream forgets a stream and tells the server to cancel a CONNECT that
// may still be dialing. Without the RESET a late dial completion would leak a
// target connection on the server for the lifetime of the tunnel.
func (tc *TunnelClient) abortStream(sid uint32) {
	tc.removeStream(sid)
	go func() { _ = tc.sendFrame(mfp.TypeRESET, sid, 0, nil, 0) }()
}

func (tc *TunnelClient) removeStream(sid uint32) {
	tc.mu.Lock()
	if _, ok := tc.activeStreams[sid]; ok {
		delete(tc.activeStreams, sid)
		tc.activeLoad.Add(-1)
	}
	tc.mu.Unlock()
}

// ActiveLoad returns the number of user streams currently assigned to this
// outer tunnel. The client uses it to keep lanes evenly loaded.
func (tc *TunnelClient) ActiveLoad() int64 {
	return tc.activeLoad.Load()
}

// Draining reports whether the lane is being retired at the end of its
// configured session lifetime. Draining lanes take no new streams.
func (tc *TunnelClient) Draining() bool {
	return tc.draining.Load()
}

// ConnectedAt is when the handshake for this lane completed.
func (tc *TunnelClient) ConnectedAt() time.Time {
	return tc.connectedAt
}

// keepaliveLoop sends a PING on the control stream every KeepaliveInterval so
// idle tunnels are not dropped by NAT or stateful firewalls, and injects dummy
// frames when direction balancing is enabled.
func (tc *TunnelClient) keepaliveLoop() {
	ticker := time.NewTicker(tc.cfg.KeepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-tc.done():
			return
		case <-ticker.C:
			// If the server stops answering PINGs the tunnel is dead even
			// though the socket may still look open. Close it so the
			// supervisor reconnects instead of leaving every dial timing out.
			timeout := 3 * tc.cfg.KeepaliveInterval
			if timeout < 90*time.Second {
				timeout = 90 * time.Second
			}
			if last := tc.lastRecv.Load(); last > 0 &&
				time.Since(time.Unix(0, last)) > timeout {
				fmt.Println("  [Tunnel] peer silent for too long, reconnecting")
				tc.Close()
				return
			}
			tc.sendKeepalive()
		}
	}
}

func (tc *TunnelClient) sendKeepalive() {
	tc.writeMu.Lock()
	defer tc.writeMu.Unlock()

	if tc.closed.Load() || tc.encoder == nil || tc.tunnelConn == nil {
		return
	}

	// Stream 0 is the control stream; PING carries a timestamp payload.
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, uint64(time.Now().UnixNano()))

	frame, boundary, err := tc.encoder.EncodeTypeAndRenew(mfp.TypePING, 0, 0, payload)
	if err != nil {
		return
	}
	frames := [][]byte{frame, boundary}

	// Direction balancing: pad the send side with a dummy frame when the
	// uplink/downlink ratio looks suspiciously one-sided.
	if tc.encoder.WantsDummy() {
		// Must go through the encoder so the frame carries a valid AEAD tag and
		// an in-order nonce; a raw header-only frame cannot be authenticated by
		// the peer and used to break the whole direction.
		dummy, err := tc.encoder.DummyFrame()
		if err == nil {
			frames = append(frames, dummy)
		}
	}

	if err := tc.writeWire(frames...); err != nil {
		tc.Close()
	}
}

// sendFrame encodes one frame and, when a rekey is due, its BOUNDARY marker,
// then writes both while holding the tunnel write lock. Encoding and writing
// are serialised so frames from different streams can never interleave.
func (tc *TunnelClient) sendFrame(typ byte, sid uint32, flags byte, data []byte, jitterNanos int64) error {
	if jitterNanos > 0 {
		timer := time.NewTimer(time.Duration(jitterNanos))
		select {
		case <-timer.C:
		case <-tc.closeCh:
			timer.Stop()
			return errors.New("tunnel: closed during jitter wait")
		}
	}

	tc.writeMu.Lock()
	defer tc.writeMu.Unlock()

	if tc.closed.Load() {
		return net.ErrClosed
	}
	if tc.encoder == nil || tc.tunnelConn == nil {
		return errors.New("tunnel: not connected")
	}

	frame, boundary, err := tc.encoder.EncodeTypeAndRenew(typ, sid, flags, data)
	if err != nil {
		return err
	}
	if err := tc.writeWire(frame, boundary); err != nil {
		tc.Close()
		return err
	}
	return nil
}

// writeWire writes frames in order under a deadline. Callers must hold
// writeMu. A timeout means the frame stream is no longer trustworthy, so the
// caller closes the tunnel.
func (tc *TunnelClient) writeWire(frames ...[]byte) error {
	tc.tunnelConn.SetWriteDeadline(time.Now().Add(tunnelWriteTimeout))
	defer tc.tunnelConn.SetWriteDeadline(time.Time{})

	for _, frame := range frames {
		if len(frame) == 0 {
			continue
		}
		if _, err := tc.tunnelConn.Write(frame); err != nil {
			return err
		}
	}
	return nil
}

// done returns a channel that is closed when the tunnel shuts down.
func (tc *TunnelClient) done() <-chan struct{} {
	return tc.closeCh
}

func (tc *TunnelClient) readLoop() {
	defer tc.Close()

	tc.lastRecv.Store(time.Now().UnixNano())
	idleTimeout := time.Duration(0)
	if tc.cfg.KeepaliveInterval > 0 {
		idleTimeout = 3 * tc.cfg.KeepaliveInterval
		if idleTimeout < 90*time.Second {
			idleTimeout = 90 * time.Second
		}
	}
	decodeFailures := 0

	for {
		if idleTimeout > 0 {
			tc.tunnelConn.SetReadDeadline(time.Now().Add(idleTimeout))
		}
		frameData, err := readTCPFrame(tc.tunnelConn)
		if err != nil {
			return
		}

		frame, err := tc.decoder.Decode(frameData)
		if err != nil {
			decodeFailures++
			if decodeFailures >= maxDecodeFailures {
				fmt.Println("  [Tunnel] downlink desynchronised, reconnecting")
				return
			}
			continue
		}
		decodeFailures = 0
		tc.lastRecv.Store(time.Now().UnixNano())

		// The server tells us which frame is the last one under the current
		// key. Rotating here (instead of on a local timer) keeps both ends on
		// the same frame even if their clocks or byte counters drift.
		if frame.Header.Type == mfp.TypeBOUNDARY {
			if err := tc.decoder.RotateKeys(); err != nil {
				fmt.Printf("  [Tunnel] key rotation failed: %v\n", err)
				return
			}
			continue
		}

		sid := frame.Header.StreamID
		flags := frame.Header.Flags

		// PONG answers our keepalive; it carries no stream data.
		if frame.Header.Type == mfp.TypePONG {
			continue
		}

		// Dummy frames injected for direction balancing carry no data.
		if frame.Header.Type == mfp.TypeKEEPALIVE {
			continue
		}

		// ACK releases uplink flow-control credit for bytes the server has
		// already written to the target.
		if frame.Header.Type == mfp.TypeACK {
			if cum, ok := mfp.DecodeAck(frame.Data); ok {
				tc.mu.Lock()
				sc := tc.activeStreams[sid]
				tc.mu.Unlock()
				if sc != nil {
					sc.flow.Ack(cum)
				}
			}
			continue
		}

		// Note received bytes so direction balancing can compare directions.
		if tc.balancer != nil {
			tc.encoder.NoteRecv(uint64(len(frame.Data)))
		}

		tc.mu.Lock()
		sc, exists := tc.activeStreams[sid]
		tc.mu.Unlock()

		if !exists {
			continue
		}

		switch frame.Header.Type {
		case mfp.TypeRESET:
			tc.removeStream(sid)
			sc.CloseFromServer()
		case mfp.TypeDATA:
			switch flags {
			case flagConnect:
				select {
				case sc.confirmChan <- true:
				default:
				}
			case flagConnectError:
				select {
				case sc.confirmChan <- false:
				default:
				}
			default:
				// Never let one stalled SOCKS consumer block the shared read
				// loop: if its queue is full, reset just that stream. The
				// application sees EOF and retries on a fresh connection.
				select {
				case sc.readChan <- frame.Data:
				case <-sc.closed:
				case <-tc.closeCh:
					return
				default:
					fmt.Printf("  [Tunnel] stream %d consumer stalled, resetting\n", sid)
					tc.removeStream(sid)
					sc.CloseFromServer()
					go func(id uint32) {
						_ = tc.sendFrame(mfp.TypeRESET, id, 0, nil, 0)
					}(sid)
				}
			}
		}
	}
}

// Close gracefully closes the tunnel client.
func (tc *TunnelClient) Close() {
	if !tc.closed.CompareAndSwap(false, true) {
		return
	}
	close(tc.closeCh)
	if tc.tunnelConn != nil {
		tc.tunnelConn.Close()
	}

	tc.mu.Lock()
	streams := make([]*StreamConn, 0, len(tc.activeStreams))
	for _, sc := range tc.activeStreams {
		streams = append(streams, sc)
	}
	tc.activeStreams = make(map[uint32]*StreamConn)
	tc.activeLoad.Store(0)
	tc.mu.Unlock()

	for _, sc := range streams {
		sc.CloseFromServer()
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
	flow        *mfp.FlowWindow
	ack         *mfp.AckTracker
}

func (sc *StreamConn) Read(b []byte) (int, error) {
	if len(sc.leftover) > 0 {
		n := copy(b, sc.leftover)
		sc.leftover = sc.leftover[n:]
		sc.sendAck(n)
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
		sc.sendAck(n)
		return n, nil
	case <-sc.closed:
		// A RESET arrives right after the final DATA frames. Drain whatever is
		// already queued before reporting EOF, otherwise the tail of the
		// stream is silently dropped.
		select {
		case data, ok := <-sc.readChan:
			if ok {
				n := copy(b, data)
				if n < len(data) {
					sc.leftover = data[n:]
				}
				sc.sendAck(n)
				return n, nil
			}
		default:
		}
		return 0, io.EOF
	}
}

// sendAck tells the server how many downlink bytes the application has
// consumed, which is what releases its flow-control window.
func (sc *StreamConn) sendAck(n int) {
	if sc.ack == nil || n <= 0 {
		return
	}
	if cum, due := sc.ack.Consume(n); due {
		_ = sc.client.sendFrame(mfp.TypeACK, sc.sid, 0, mfp.EncodeAck(cum), 0)
	}
}

func (sc *StreamConn) Write(b []byte) (int, error) {
	select {
	case <-sc.closed:
		return 0, io.ErrClosedPipe
	default:
	}

	written := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > maxFrameDataSize {
			chunk = chunk[:maxFrameDataSize]
		}
		jitter := sc.client.encoder.JitterDelayFor(len(chunk))
		if err := sc.flow.Acquire(int64(len(chunk))); err != nil {
			sc.Close()
			return written, err
		}
		if err := sc.client.sendFrame(mfp.TypeDATA, sc.sid, 0, chunk, jitter); err != nil {
			sc.flow.Refund(int64(len(chunk)))
			return written, err
		}
		written += len(chunk)
		b = b[len(chunk):]
	}
	return written, nil
}

func (sc *StreamConn) Close() error {
	sc.closeOnce.Do(func() {
		close(sc.closed)
		sc.flow.Close()
		sc.client.removeStream(sc.sid)
		// Best-effort RESET so the server can close its target immediately
		// instead of waiting for a read timeout.
		_ = sc.client.sendFrame(mfp.TypeRESET, sc.sid, 0, nil, 0)
	})
	return nil
}

func (sc *StreamConn) CloseFromServer() {
	sc.closeOnce.Do(func() {
		close(sc.closed)
		sc.flow.Close()
	})
}

func (sc *StreamConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }
func (sc *StreamConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }
func (sc *StreamConn) SetDeadline(t time.Time) error      { return nil }
func (sc *StreamConn) SetReadDeadline(t time.Time) error  { return nil }
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
// Hysteria Wrapper
// ─────────────────────────────────────────────────────────────────────────────

type hysteriaStreamWrapper struct {
	net.Conn
	hyClient client.Client
}

func (h *hysteriaStreamWrapper) Close() error {
	h.Conn.Close()
	return h.hyClient.Close()
}
