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
	// earlyData means the server accepts DATA before CONNECT SUCCESS, so a new
	// stream does not have to wait a round trip before the application can
	// speak. It is negotiated as ServerHello version 3.
	earlyData bool

	// idleTimeout reclaims streams that stopped carrying bytes in either
	// direction. An abandoned player connection keeps its slot forever
	// otherwise, and enough of them make the proxy refuse new work while the
	// tunnel still reports itself healthy. Zero disables reclamation.
	idleTimeout time.Duration
	// dialSem bounds how many streams on this lane may be waiting for the
	// server to finish dialling the target, so a connection storm queues
	// instead of timing out en masse. Nil means unlimited.
	dialSem chan struct{}

	// firstByteTimeout bounds how long a new stream may wait for the server's
	// first word. A server that accepted the tunnel but stopped answering
	// leaves every request hanging with its SOCKS handshake complete and no
	// error anywhere; this turns that into a reset the application can retry.
	// Zero disables the watchdog.
	firstByteTimeout time.Duration
	// silentLimit is how many streams in a row may time out unanswered before
	// this lane is declared dead and reconnected. Zero never closes the lane.
	silentLimit int
	// silentStreak counts consecutive unanswered streams. Any response on any
	// stream clears it: it measures the lane, not the target.
	silentStreak atomic.Int32
	// dialSeq numbers the streams this lane opens, and lastSilentSeq remembers
	// the one whose silence was counted last. A stream numbered at or below it
	// was already in flight then, so it belongs to the same incident — a
	// browser opening five sockets to a dead host is one failure, not five —
	// and only a later dial counts as new evidence. A sequence number is used
	// instead of a timestamp because two dials can share a clock tick.
	dialSeq       atomic.Int64
	lastSilentSeq atomic.Int64
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
	tc := &TunnelClient{
		cfg:              cfg,
		activeStreams:    make(map[uint32]*StreamConn),
		handshakeDone:    make(chan struct{}),
		sessionStore:     sessionStore,
		closeCh:          make(chan struct{}),
		idleTimeout:      cfg.StreamIdleTimeout,
		firstByteTimeout: cfg.FirstByteTimeout,
		silentLimit:      cfg.FirstByteFailures,
	}
	if cfg.MaxPendingDials > 0 {
		tc.dialSem = make(chan struct{}, cfg.MaxPendingDials)
	}
	return tc
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
	// Version 3 also allows sending DATA before the server confirms the dial.
	tc.earlyData = respBuf[4] >= 3

	if resumeKeys != nil && status == 0 {
		// Server accepted resume
		keys = resumeKeys
		if config.DebugMode {
			logf("[Tunnel] 0-RTT session resumed successfully")
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

	logf("[Tunnel] handshake successful over %s, cipher MERIDIAN-CHACHA", tc.cfg.Transport)
	if config.DebugMode {
		features := "none"
		switch {
		case tc.earlyData:
			features = fmt.Sprintf("flow-control + early-data (window %d KiB)", tc.cfg.StreamWindow/1024)
		case tc.flowControl:
			features = fmt.Sprintf("flow-control (window %d KiB)", tc.cfg.StreamWindow/1024)
		}
		logf("[Tunnel] server features: %s", features)
	}

	tc.connectedAt = time.Now()

	// Start read loop
	go tc.readLoop()

	// Reclaim half-dead streams: the slot they hold is what turns "a few
	// abandoned connections" into "the proxy refuses everything".
	if tc.idleTimeout > 0 {
		go tc.reapLoop()
	}

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

	// Wait for a dial slot before spending a server-side dial. Waiting (instead
	// of failing) is what keeps a connection storm from turning into a burst of
	// timeouts: the dials that do go through finish quickly and the rest queue
	// behind them under the caller's own deadline. Taking the slot before the
	// stream is published keeps its release path race-free.
	if tc.dialSem != nil {
		select {
		case tc.dialSem <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-tc.closeCh:
			return nil, errors.New("tunnel: closed while waiting for a dial slot")
		}
	}

	sc := &StreamConn{
		sid:         sid,
		client:      tc,
		target:      targetAddr,
		readChan:    make(chan []byte, config.StreamQueueFrames),
		confirmChan: make(chan bool, 1),
		closed:      make(chan struct{}),
		maxBuffer:   config.StreamBufferLimit(tc.cfg.StreamWindow),
		dialSeq:     tc.dialSeq.Add(1),
	}
	if tc.flowControl {
		sc.flow = mfp.NewFlowWindow(int64(tc.cfg.StreamWindow))
		sc.ack = mfp.NewAckTracker(tc.cfg.StreamWindow)
	}
	sc.touch()

	// With early data no confirmation arrives, so the slot would be held until
	// the first byte comes back. Bound it by the dial timeout: the server has
	// that long to produce something, otherwise the slot is released and the
	// stream simply looks slow to the application.
	if tc.dialSem != nil {
		sc.dialTimer = time.AfterFunc(tc.cfg.DialTimeout, sc.endDial)
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

	// Arm the first-byte watchdog before the stream can reach the application.
	// With early data the CONNECT is not awaited here, so without this a server
	// that has stopped answering leaves the request hanging forever; the SOCKS
	// handshake has already succeeded and no counter moves anywhere.
	if tc.firstByteTimeout > 0 {
		sc.firstByteTimer = time.AfterFunc(tc.firstByteTimeout, func() { tc.watchFirstByte(sc) })
	}

	// Wait for confirmation (Flags = 0x01 from server)
	//
	// With early data the wait is skipped: the server queues whatever the
	// application sends until its dial completes, which removes one round trip
	// from every new connection (this is what the first video request of a
	// playback session is most sensitive to). A dial failure then surfaces as
	// a closed stream instead of a dial error, which the application handles
	// the same way it handles any mid-transfer failure.
	if tc.earlyData {
		return sc, nil
	}

	select {
	case success := <-sc.confirmChan:
		sc.endDial()
		if !success {
			tc.removeStream(sid)
			sc.CloseFromServer()
			if config.DebugMode {
				logf("[Tunnel] stream %d rejected by server", sid)
			}
			return nil, fmt.Errorf("tunnel: connection rejected by server")
		}
		if config.DebugMode {
			logf("[Tunnel] stream %d established to %s", sid, targetAddr)
		}
	case <-ctx.Done():
		sc.endDial()
		tc.abortStream(sid)
		return nil, ctx.Err()
	case <-tc.closeCh:
		sc.endDial()
		tc.abortStream(sid)
		return nil, errors.New("tunnel: closed while dialing")
	case <-time.After(tc.cfg.DialTimeout):
		sc.endDial()
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

// watchFirstByte runs when a stream has waited firstByteTimeout without the
// server saying anything at all — no CONNECT SUCCESS, no data, no reset.
//
// This is the failure the tunnel cannot otherwise see: the SOCKS handshake
// succeeded, the request bytes went into a live tunnel, and the server (which
// still answers keepalives) never completes the dial. Early data makes it
// worse, because the client deliberately does not wait for the confirmation.
// On router 110 that state held for eight minutes: every request sat until the
// application gave up, and no counter in the log moved. Resetting the stream
// hands the failure to the application, which retries, and enough of them in a
// row condemn the lane so the supervisor builds a fresh one.
func (tc *TunnelClient) watchFirstByte(sc *StreamConn) {
	if !sc.responded.CompareAndSwap(false, true) {
		return
	}
	select {
	case <-sc.closed:
		return
	default:
	}
	noteEvent("stream_silent", "tunnel: stream %d (%s) got no answer in %v, resetting",
		sc.sid, sc.target, tc.firstByteTimeout)
	tc.abortStream(sc.sid)
	sc.failWith(fmt.Errorf("tunnel: no response from the server in %v", tc.firstByteTimeout))
	tc.noteSilentStream(sc)
}

// noteSilentStream decides whether this silence is new evidence about the lane.
// A stream that was already in flight when the previous silence was counted
// belongs to the same incident, so only a dial made after that one advances the
// streak: three sockets opened together to one dead host must not condemn a
// lane that is serving everything else.
func (tc *TunnelClient) noteSilentStream(sc *StreamConn) {
	prev := tc.lastSilentSeq.Load()
	if sc.dialSeq <= prev {
		return
	}
	// Count everything dialled so far, not just this stream: whatever else is
	// already in flight is part of the same incident.
	if cut := tc.dialSeq.Load(); !tc.lastSilentSeq.CompareAndSwap(prev, cut) {
		// Another stream's silence won the race and already counted.
		return
	}
	n := tc.silentStreak.Add(1)
	if tc.silentLimit > 0 && int(n) >= tc.silentLimit {
		logf("[Tunnel] %d streams in a row went unanswered within %v, server is not serving; reconnecting",
			n, tc.firstByteTimeout)
		tc.Close()
	}
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
				logf("[Tunnel] peer silent for too long, reconnecting")
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
				logf("[Tunnel] downlink desynchronised, reconnecting")
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
				logf("[Tunnel] key rotation failed: %v", err)
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

		// Any frame for this stream means the server is serving the lane: it
		// disarms the first-byte watchdog and clears the silent streak. PING
		// answers deliberately do not count — a server whose dial path is hung
		// still answers keepalives, which is what made that failure invisible.
		sc.noteResponded()

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
				// In early-data mode nobody is waiting for the confirmation,
				// so hand the failure to the application instead of leaving
				// it with a silently closed stream.
				if tc.earlyData {
					reason := "tunnel: server rejected the connection"
					if len(frame.Data) > 0 {
						reason = "tunnel: " + string(frame.Data)
					}
					tc.removeStream(sid)
					sc.failWith(errors.New(reason))
				}
			default:
				// Never let one stalled SOCKS consumer block the shared read
				// loop: if it holds more unread bytes than the flow-control
				// window allows in flight, reset just that stream. The
				// application sees EOF and retries on a fresh connection.
				if !sc.enqueue(frame.Data) {
					noteEvent("stream_stalled", "tunnel: stream %d (%s) consumer stalled, resetting", sid, sc.target)
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

// ActiveWithin counts the streams that moved a byte within the window. The
// drain path uses it to tell "nobody is using this lane any more" from "a
// transfer is still running on it"; the stream count alone cannot, because a
// paused video and a finished one both sit there holding a slot.
func (tc *TunnelClient) ActiveWithin(window time.Duration) int {
	now := time.Now()
	tc.mu.Lock()
	defer tc.mu.Unlock()
	n := 0
	for _, sc := range tc.activeStreams {
		if sc.idleFor(now) <= window {
			n++
		}
	}
	return n
}

// ─────────────────────────────────────────────────────────────────────────────
// Idle stream reclamation
// ─────────────────────────────────────────────────────────────────────────────

// reaperInterval is how often abandoned streams are looked for. It is
// deliberately coarser than the idle timeout: the goal is to free the slot
// within a few tens of seconds, not to police exact timings.
const reaperInterval = 30 * time.Second

func (tc *TunnelClient) reapLoop() {
	ticker := time.NewTicker(reaperInterval)
	defer ticker.Stop()
	for {
		select {
		case <-tc.done():
			return
		case now := <-ticker.C:
			tc.reapIdle(now)
		}
	}
}

// reapPressurePermille is the share of a lane's stream cap at which reclaiming
// idle streams starts. Below it the reaper does nothing at all.
//
// The gate matters more than the threshold. A paused video, a browser's
// keep-alive socket and a connection the application forgot all look the same
// from the byte stream: no traffic in either direction. Only one of the three
// deserves to be closed, and there is no way to tell which from here — so the
// client keeps them all while it has room, and starts evicting only when the
// lane is 80% full and new connections are about to be refused.
const reapPressurePermille = 800

// underStreamPressure reports whether this lane is close enough to its stream
// cap that idle streams are worth evicting.
func (tc *TunnelClient) underStreamPressure() bool {
	limit := int64(tc.cfg.MaxConcurrentStream)
	if limit <= 0 {
		// No cap configured: nothing is being squeezed out, so reclaim on
		// age alone as before.
		return true
	}
	return tc.activeLoad.Load()*1000 >= limit*reapPressurePermille
}

// reapIdle closes streams that have carried no byte in either direction for
// longer than the idle timeout, but only while the lane is under pressure. It
// returns how many it reclaimed.
//
// This is the difference between "a player abandoned some connections" and "the
// proxy stopped accepting connections": abandoned streams keep their slots (and
// their share of the flow-control window) until the application closes a socket
// it has already forgotten about. Each reclaimed stream is reset on the wire so
// the server closes its target instead of holding it open.
//
// Reclaiming on a timer alone is what cut videos: at a 10 minute threshold the
// reaper reset a stream every time a viewer paused for ten minutes, and the
// player reported it as an interruption. The threshold is now a lower bound on
// age, not a schedule.
func (tc *TunnelClient) reapIdle(now time.Time) int {
	if tc.idleTimeout <= 0 {
		return 0
	}
	if !tc.underStreamPressure() {
		return 0
	}
	tc.mu.Lock()
	victims := make([]*StreamConn, 0, 8)
	for _, sc := range tc.activeStreams {
		if sc.idleFor(now) > tc.idleTimeout {
			victims = append(victims, sc)
		}
	}
	tc.mu.Unlock()

	// Capture the load that justified the eviction before anything is removed:
	// the counter falls as the loop runs, and the last line then reads "0/16
	// full", which describes the state after the fact instead of the reason.
	load := tc.activeLoad.Load()
	for _, sc := range victims {
		idle := sc.idleFor(now)
		sid := sc.sid
		tc.removeStream(sid)
		sc.CloseFromServer()
		go func() { _ = tc.sendFrame(mfp.TypeRESET, sid, 0, nil, 0) }()
		noteEvent("stream_idle", "tunnel: stream %d (%s) idle for %v, reclaimed (lane was %d/%d in use)",
			sid, sc.target, idle.Round(time.Second), load, tc.cfg.MaxConcurrentStream)
	}
	return len(victims)
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
	// buffered counts bytes handed to this stream but not yet consumed by the
	// application. maxBuffer is the stall threshold, derived from the
	// flow-control window so a healthy stream is never reset mid-transfer.
	buffered  atomic.Int64
	maxBuffer int64
	// readErr carries a server-side failure (rejected dial) to the application
	// when the stream was opened with early data.
	errMu   sync.Mutex
	readErr error
	// lastActive is the Unix-nano time of the last byte moved in either
	// direction. The reaper uses it to find streams the application abandoned
	// without closing.
	lastActive atomic.Int64
	// target is the address this stream dialled. It exists for the logs: a
	// reclaimed stream used to be reported as a bare number, so "is the client
	// killing my video or a dead socket?" was unanswerable from the file.
	target string
	// dialTimer releases the lane's dial slot if the server never answers;
	// endDialOnce makes the release idempotent across every path.
	dialTimer   *time.Timer
	endDialOnce sync.Once
	// firstByteTimer fires when the server has said nothing at all about this
	// stream; responded is the flag that decides the race between the watchdog
	// and the first frame that arrives, whichever comes first.
	firstByteTimer *time.Timer
	responded      atomic.Bool
	// dialSeq is this stream's number in the lane's dial order. The lane
	// compares it against the last counted silence to tell a new failure from
	// the same burst.
	dialSeq int64
}

// noteResponded records that the server answered this stream. It disarms the
// first-byte watchdog and clears the lane's silent streak: a server that
// answers anything is serving that lane, whatever the next target does.
func (sc *StreamConn) noteResponded() {
	if sc.responded.CompareAndSwap(false, true) && sc.firstByteTimer != nil {
		sc.firstByteTimer.Stop()
	}
	if sc.client != nil {
		sc.client.silentStreak.Store(0)
		sc.client.lastSilentSeq.Store(0)
	}
}

// stopWatchdog disarms the first-byte timer when the stream ends, so a closed
// stream cannot leave a timer that fires into a finished conversation.
func (sc *StreamConn) stopWatchdog() {
	if sc.firstByteTimer != nil {
		sc.firstByteTimer.Stop()
	}
}

// touch records traffic on the stream, deferring idle reclamation.
func (sc *StreamConn) touch() {
	sc.lastActive.Store(time.Now().UnixNano())
}

// idleFor reports how long the stream has been silent.
func (sc *StreamConn) idleFor(now time.Time) time.Duration {
	last := sc.lastActive.Load()
	if last == 0 {
		return 0
	}
	return now.Sub(time.Unix(0, last))
}

// endDial gives the lane's dial slot back. It runs at most once: the first
// downlink byte, the confirmation, an error path or the dial timeout all call
// it, whichever comes first.
func (sc *StreamConn) endDial() {
	sc.endDialOnce.Do(func() {
		if sc.dialTimer != nil {
			sc.dialTimer.Stop()
		}
		if sc.client == nil || sc.client.dialSem == nil {
			return
		}
		select {
		case <-sc.client.dialSem:
		default:
		}
	})
}

// enqueue hands one DATA frame to the application reader. It reports false
// when the stream is holding more unread bytes than the sender could ever have
// in flight, which means this consumer has stopped reading and the stream has
// to be reset so it cannot pin memory or block the shared read loop.
func (sc *StreamConn) enqueue(data []byte) bool {
	size := int64(len(data))
	if sc.maxBuffer > 0 && sc.buffered.Load()+size > sc.maxBuffer {
		return false
	}
	// The server produced bytes for this stream, so its dial is done and the
	// lane can spend the slot on the next connection.
	sc.endDial()
	sc.touch()
	sc.buffered.Add(size)
	select {
	case sc.readChan <- data:
		return true
	case <-sc.closed:
		sc.buffered.Add(-size)
		return true
	case <-sc.client.closeCh:
		sc.buffered.Add(-size)
		return true
	}
}

// consume accounts for bytes the application has taken off the queue.
func (sc *StreamConn) consume(n int) {
	if n > 0 {
		sc.buffered.Add(-int64(n))
	}
}

func (sc *StreamConn) Read(b []byte) (int, error) {
	if len(sc.leftover) > 0 {
		n := copy(b, sc.leftover)
		sc.leftover = sc.leftover[n:]
		sc.consume(n)
		sc.sendAck(n)
		return n, nil
	}

	select {
	case data, ok := <-sc.readChan:
		if !ok {
			return 0, sc.readFailure()
		}
		n := copy(b, data)
		if n < len(data) {
			sc.leftover = data[n:]
		}
		sc.consume(n)
		sc.sendAck(n)
		sc.touch()
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
				sc.consume(n)
				sc.sendAck(n)
				return n, nil
			}
		default:
		}
		return 0, sc.readFailure()
	}
}

// readFailure reports a recorded server-side failure, or plain EOF.
func (sc *StreamConn) readFailure() error {
	sc.errMu.Lock()
	err := sc.readErr
	sc.errMu.Unlock()
	if err != nil {
		return err
	}
	return io.EOF
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

	sc.touch()
	written := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > maxFrameDataSize {
			chunk = chunk[:maxFrameDataSize]
		}
		jitter := sc.client.encoder.JitterDelayFor(len(chunk))
		if err := sc.flow.Acquire(int64(len(chunk))); err != nil {
			noteEvent("uplink_stalled", "tunnel: stream %d (%s) uplink stalled: %v", sc.sid, sc.target, err)
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
		sc.stopWatchdog()
		sc.flow.Close()
		sc.endDial()
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
		sc.stopWatchdog()
		sc.flow.Close()
		sc.endDial()
	})
}

// failWith records why the stream ended so a Read that was pipelined past
// CONNECT SUCCESS can report the real cause instead of a bare EOF.
func (sc *StreamConn) failWith(err error) {
	sc.errMu.Lock()
	if sc.readErr == nil {
		sc.readErr = err
	}
	sc.errMu.Unlock()
	sc.CloseFromServer()
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
