package mfp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"meridian/pkg/config"
	"meridian/pkg/crypto"
	"sync"
	"time"
)

const (
	TypeDATA      = 0x00
	TypeACK       = 0x01
	TypeCONGEST   = 0x02
	TypePING      = 0x03
	TypePONG      = 0x04
	TypeBOUNDARY  = 0x05
	TypeERROR     = 0x06
	TypeFLOW      = 0x07
	TypeRESET     = 0x08
	TypeKEEPALIVE = 0xFF
)

// FrameHeader is the 14-byte MFP frame header.
//
// Wire layout (per spec §4.1):
//
//	Offset  Size  Field
//	0       1     Type
//	1       2     PayloadLen
//	3       4     StreamID
//	7       1     Flags
//	8       4     Sequence
//	12      2     Extended
type FrameHeader struct {
	Type       byte
	PayloadLen uint16
	StreamID   uint32
	Flags      byte
	Sequence   uint32
	Extended   uint16
}

// DataFrame bundles a decoded header with its plaintext payload.
type DataFrame struct {
	Header FrameHeader
	Data   []byte
}

// EncodeHeader serialises a FrameHeader into exactly 14 bytes.
// Fix #1/#2: previous code wrote Flags to buf[7] and then overwrote it with
// Sequence starting at buf[7], clobbering the Flags field.
// Correct layout: Flags @ offset 7, Sequence @ offset 8, Extended @ offset 12.
func EncodeHeader(h *FrameHeader) []byte {
	buf := make([]byte, 14)
	buf[0] = h.Type
	binary.BigEndian.PutUint16(buf[1:3], h.PayloadLen)
	binary.BigEndian.PutUint32(buf[3:7], h.StreamID)
	buf[7] = h.Flags                                   // Flags  @ offset 7 (1 byte)
	binary.BigEndian.PutUint32(buf[8:12], h.Sequence)  // Sequence @ offset 8 (4 bytes)
	binary.BigEndian.PutUint16(buf[12:14], h.Extended) // Extended @ offset 12 (2 bytes)
	return buf
}

// DecodeHeader deserialises a 14-byte FrameHeader.
// Fix #1/#2: mirrors the corrected offsets from EncodeHeader.
func DecodeHeader(data []byte) (*FrameHeader, error) {
	if len(data) < 14 {
		return nil, errors.New("mfp: too short to decode header")
	}
	return &FrameHeader{
		Type:       data[0],
		PayloadLen: binary.BigEndian.Uint16(data[1:3]),
		StreamID:   binary.BigEndian.Uint32(data[3:7]),
		Flags:      data[7],                             // Fix: was data[7] overlapping with Sequence
		Sequence:   binary.BigEndian.Uint32(data[8:12]), // Fix: was data[7:11]
		Extended:   binary.BigEndian.Uint16(data[12:14]),
	}, nil
}

// NewData constructs a DATA DataFrame.
func NewData(sid uint32, seq uint32, data []byte) *DataFrame {
	return &DataFrame{
		Header: FrameHeader{
			Type:       TypeDATA,
			PayloadLen: uint16(len(data)),
			StreamID:   sid,
			Sequence:   seq,
		},
		Data: data,
	}
}

// Encode serialises the DataFrame to wire bytes (header + data).
func (f *DataFrame) Encode() ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, 14+len(f.Data)))
	buf.Write(EncodeHeader(&f.Header))
	buf.Write(f.Data)
	return buf.Bytes(), nil
}

// ParseFrame deserialises a raw wire buffer into a DataFrame.
// Note: data[14:] is treated as the raw (still-encrypted) payload;
// use Decoder.Decode for authenticated decryption.
func ParseFrame(data []byte) (*DataFrame, error) {
	if len(data) < 14 {
		return nil, errors.New("mfp: too short")
	}
	h, err := DecodeHeader(data)
	if err != nil {
		return nil, err
	}
	return &DataFrame{Header: *h, Data: data[14:]}, nil
}

// ---------------------------------------------------------------------------
// Frame pool
// ---------------------------------------------------------------------------

// FramePool is a simple free-list of reusable byte slices.
type FramePool struct{ data [][]byte }

func NewFramePool() *FramePool { return &FramePool{} }

func (p *FramePool) Get() *[]byte {
	if len(p.data) > 0 {
		last := len(p.data) - 1
		b := p.data[last]
		p.data = p.data[:last]
		return &b
	}
	b := make([]byte, 0, 1452)
	return &b
}

func (p *FramePool) Put(buf *[]byte) {
	*buf = (*buf)[:0]
	p.data = append(p.data, *buf)
}

// ---------------------------------------------------------------------------
// Stream
// ---------------------------------------------------------------------------

// Stream tracks per-stream state: sequence number and encryption counter.
type Stream struct {
	ID      uint32
	Seq     uint32
	Counter uint64
	Buffer  *FramePool
}

func NewStream(id uint32, pool *FramePool) *Stream { return &Stream{ID: id, Buffer: pool} }
func (s *Stream) NextSeq() uint32                  { s.Seq++; return s.Seq }
func (s *Stream) NextCounter() uint64              { s.Counter++; return s.Counter }

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

// Encoder encrypts outbound frames using a per-packet nonce derived from
// a direction-specific seed and a monotonically increasing counter.
//
// Fix #6: previous code copied InitKey into the nonce on every packet, giving
// every encrypted frame the same nonce — a fatal ChaCha20-Poly1305 vulnerability
// that allows XOR-based plaintext recovery. Now uses GenerateNonce(seed, counter).
//
// Direction:
// - Client encoding uplink (client→server): use NonceSeedUplink (default)
// - Server encoding downlink (server→client): use NonceSeedDownlk
type Encoder struct {
	Keys  *crypto.KeyMaterial
	Pool  *FramePool
	Count uint64
	seed  *[crypto.NonceSeedLen]byte

	isUplink        bool
	bytesProcessed  uint64
	createdAt       time.Time
	renewalLimit    uint64
	renewalInterval time.Duration
	generation      uint32
	mu              sync.Mutex

	// Anti-detection: traffic padding. PaddingNone (zero value) keeps the
	// wire format byte-identical to pre-padding behaviour, so callers that
	// never call SetPadding are unaffected.
	padCfg PaddingConfig
	// JitterNanos is the maximum artificial send delay applied after
	// encoding. Zero disables jitter.
	jitterNanos int64
	// balancer, when non-nil, tracks direction symmetry for dummy injection.
	balancer *DirectionBalancer
	// SentBytes counts pre-padding bytes handed to Encode.
	sentBytes uint64
}

// NewEncoder creates an uplink encoder (client→server), using NonceSeedUplink.
func NewEncoder(keys *crypto.KeyMaterial) *Encoder {
	return &Encoder{Keys: keys, Pool: NewFramePool(), seed: &keys.NonceSeedUplink, isUplink: true, createdAt: time.Now()}
}

// NewDownlinkEncoder creates a downlink encoder (server→client), using NonceSeedDownlk.
func NewDownlinkEncoder(keys *crypto.KeyMaterial) *Encoder {
	return &Encoder{Keys: keys, Pool: NewFramePool(), seed: &keys.NonceSeedDownlk, isUplink: false, createdAt: time.Now()}
}

// Encode encrypts data for stream sid with the given flags.
// When padding is enabled the header PayloadLen records the *padded* length
// (which is what the receiver's framer needs) and the original length is
// carried in a 2-byte prefix inside the payload, recovered by Decoder.Decode.
// With padding disabled the behaviour is unchanged from earlier versions.
// Encode encrypts a DATA frame for stream sid with the given flags.
func (e *Encoder) Encode(sid uint32, flags byte, data []byte) ([]byte, error) {
	return e.EncodeType(TypeDATA, sid, flags, data)
}

// EncodeType encrypts a frame with an explicit wire type.
//
// Encode always writes TypeDATA into the header, so control frames (PING,
// PONG, RESET) must use this method — otherwise the type constant lands in the
// Flags field and the peer never sees a typed control frame.
func (e *Encoder) EncodeType(typ byte, sid uint32, flags byte, data []byte) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.encodeLocked(typ, sid, flags, data)
}

// EncodeTypeAndRenew encodes a frame and, when the renewal policy fires,
// returns an additional TypeBOUNDARY frame that tells the peer to switch to
// the next key generation. The encoder advances its key only after both frames
// have been produced, so the boundary frame itself still uses the old key.
//
// Rotation must be receiver-driven: the sender decides *which* frame is the
// last one under the current key and announces it in-band. The receiver then
// rotates after decrypting that marker. Clock- or byte-count-based rotation on
// both ends independently is not safe — the two sides disagree by at least one
// frame whenever their timers drift, after which every frame fails
// authentication and the tunnel is permanently dead.
func (e *Encoder) EncodeTypeAndRenew(typ byte, sid uint32, flags byte, data []byte) (frame, boundary []byte, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	frame, err = e.encodeLocked(typ, sid, flags, data)
	if err != nil {
		return nil, nil, err
	}
	if !e.shouldRotateLocked() {
		return frame, nil, nil
	}

	boundary, err = e.encodeLocked(TypeBOUNDARY, 0, 0, nil)
	if err != nil {
		return nil, nil, err
	}
	if err := e.rotateLocked(); err != nil {
		return nil, nil, err
	}
	return frame, boundary, nil
}

// encodeLocked performs the actual encoding. Callers must hold e.mu.
func (e *Encoder) encodeLocked(typ byte, sid uint32, flags byte, data []byte) ([]byte, error) {

	seq := e.Count
	e.Count++

	e.sentBytes += uint64(len(data))
	if e.balancer != nil {
		e.balancer.Sent += uint64(len(data))
	}

	payload := data
	// Enabled() treats the empty mode as "no padding" so a zero-value
	// PaddingConfig cannot accidentally activate padding.
	if e.padCfg.Enabled() {
		padded, err := PadPayload(data, e.padCfg)
		if err != nil {
			return nil, err
		}
		payload = padded
	} else if e.jitterNanos > 0 {
		// Jitter without padding still needs a private copy because the
		// caller may reuse its buffer once Encode returns.
		payload = append([]byte(nil), data...)
	}
	if len(payload) > 65535 {
		return nil, fmt.Errorf("mfp: payload too large for frame header: %d", len(payload))
	}

	header := &FrameHeader{
		Type:       typ,
		PayloadLen: uint16(len(payload)),
		StreamID:   sid,
		Sequence:   uint32(seq),
		Flags:      flags,
	}
	hb := EncodeHeader(header)

	// Fix #6: derive a unique nonce per packet using the direction-specific seed.
	nonce := crypto.GenerateNonce(e.seed, seq)

	ciphertext, err := crypto.AEADEncrypt(&e.Keys.TrafficEncKey, nonce, payload)
	if err != nil {
		return nil, err
	}

	e.bytesProcessed += uint64(len(data))

	buf := e.Pool.Get()
	*buf = append((*buf)[:0], hb...)
	*buf = append(*buf, ciphertext...)
	return *buf, nil
}

func (e *Encoder) SetRenewal(limit uint64, interval time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.renewalLimit = limit
	e.renewalInterval = interval
}

// SetPadding enables traffic padding. Passing PaddingNone keeps the wire
// format unchanged, which is what the test configs rely on.
func (e *Encoder) SetPadding(cfg PaddingConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.padCfg = cfg.Normalize()
}

// SetJitterMS sets the maximum artificial delay (milliseconds) applied before
// a caller should write an encoded frame. Zero disables jitter.
func (e *Encoder) SetJitterMS(ms float64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ms <= 0 {
		e.jitterNanos = 0
		return
	}
	e.jitterNanos = int64(ms * 1e6)
}

// JitterDelay returns a random delay in [0, jitter] nanoseconds for the
// caller to wait on before writing. Returns 0 when jitter is disabled.
// It deliberately does not sleep: the caller owns the write lock and should
// decide how to pace without holding it across a sleep.
func (e *Encoder) JitterDelay() int64 {
	return e.jitterDelayLocked(false)
}

// JitterDelayFor returns a random delay only for small, latency-insensitive
// frames. Bulk data must not sleep once per frame: a 30ms jitter applied to
// every 32KB write serialises the whole tunnel and caps it far below the link
// rate. Large frames already dominate the traffic shape, so skipping jitter
// there preserves the anti-detection benefit without throttling throughput.
func (e *Encoder) JitterDelayFor(payloadLen int) int64 {
	return e.jitterDelayLocked(payloadLen >= 8*1024)
}

func (e *Encoder) jitterDelayLocked(skip bool) int64 {
	e.mu.Lock()
	maxDelay := e.jitterNanos
	e.mu.Unlock()
	if skip || maxDelay <= 0 {
		return 0
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	v := int64(binary.BigEndian.Uint64(b[:]) >> 1) // keep positive
	if v <= 0 {
		return 0
	}
	return v % maxDelay
}

// SetBalancer attaches a DirectionBalancer used to decide when dummy frames
// should be injected to mask asymmetric traffic.
func (e *Encoder) SetBalancer(b *DirectionBalancer) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.balancer = b
}

// NoteRecv records bytes received on the opposite direction so the balancer
// can compare directions.
func (e *Encoder) NoteRecv(n uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.balancer != nil {
		e.balancer.Recv += n
	}
}

// WantsDummy reports whether traffic is asymmetric enough to warrant a dummy
// frame. Callers should send DummyFrame() when it returns true.
func (e *Encoder) WantsDummy() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.balancer != nil && e.balancer.ShouldSendDummy()
}

// DummyFrame builds a properly encrypted KEEPALIVE frame for direction
// balancing.
//
// The previous package-level DummyFrame() returned 14 raw bytes with no
// ciphertext and no AEAD tag. Because Decoder.Decode decrypts every frame it
// reads, such a frame could not be authenticated: the receiving side dropped
// it, and — before the nonce fix — it also burned a nonce, desynchronising the
// direction so all subsequent frames failed too.
//
// Encoding the dummy through the normal path gives it a valid tag and an
// in-order nonce, so the peer decodes it as an ordinary KEEPALIVE and skips it.
func (e *Encoder) DummyFrame() ([]byte, error) {
	return e.EncodeType(TypeKEEPALIVE, 0, 0, nil)
}

func (e *Encoder) ShouldRotate() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.shouldRotateLocked()
}

// shouldRotateLocked reports whether the next frame must trigger a rekey.
// Callers must hold e.mu.
func (e *Encoder) shouldRotateLocked() bool {
	if e.renewalLimit > 0 && e.bytesProcessed >= e.renewalLimit {
		return true
	}
	if e.renewalInterval > 0 && time.Since(e.createdAt) >= e.renewalInterval {
		return true
	}
	return false
}

func (e *Encoder) RotateKeys() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rotateLocked()
}

// rotateLocked derives and installs the next key generation.
// Callers must hold e.mu.
func (e *Encoder) rotateLocked() error {
	e.generation++
	newKeys, err := crypto.RotateKeyMaterial(e.Keys, e.generation)
	if err != nil {
		return err
	}
	e.Keys = newKeys
	if e.isUplink {
		e.seed = &newKeys.NonceSeedUplink
	} else {
		e.seed = &newKeys.NonceSeedDownlk
	}
	e.Count = 0
	e.bytesProcessed = 0
	e.createdAt = time.Now()
	return nil
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

// Decoder decrypts inbound frames using a per-packet nonce derived from
// a direction-specific seed and a monotonically increasing counter.
//
// Fix #6 (direction): Decoder must use the SAME seed the encoder used.
// - Server decoding client uplink → use NonceSeedUplink
// - Client decoding server downlink → use NonceSeedDownlk
// Use NewUplinkDecoder or NewDownlinkDecoder to select the correct seed.
type Decoder struct {
	Keys  *crypto.KeyMaterial
	Pool  *FramePool
	Count uint64
	seed  *[crypto.NonceSeedLen]byte // matches the encoder's seed for this direction

	isUplink        bool
	bytesProcessed  uint64
	createdAt       time.Time
	renewalLimit    uint64
	renewalInterval time.Duration
	generation      uint32
	mu              sync.Mutex

	// padCfg mirrors the peer encoder's padding config. When Mode is not
	// PaddingNone, Decode strips the 2-byte length prefix written by
	// PadPayload so callers see the original plaintext.
	padCfg PaddingConfig
	// recvBytes counts plaintext bytes delivered to the caller.
	recvBytes uint64
	// balancer mirrors the encoder's, used purely for byte accounting.
	balancer *DirectionBalancer
}

// NewUplinkDecoder creates a decoder for server-side decryption of client→server frames.
// It uses NonceSeedUplink, matching the client's Encoder.
func NewUplinkDecoder(keys *crypto.KeyMaterial) *Decoder {
	return &Decoder{Keys: keys, Pool: NewFramePool(), seed: &keys.NonceSeedUplink, isUplink: true, createdAt: time.Now()}
}

// NewDownlinkDecoder creates a decoder for client-side decryption of server→client frames.
// It uses NonceSeedDownlk, matching the server's Encoder (when server sends downlink).
func NewDownlinkDecoder(keys *crypto.KeyMaterial) *Decoder {
	return &Decoder{Keys: keys, Pool: NewFramePool(), seed: &keys.NonceSeedDownlk, isUplink: false, createdAt: time.Now()}
}

// NewDecoder is kept for backward compatibility; defaults to uplink (server-side) decoding.
func NewDecoder(keys *crypto.KeyMaterial) *Decoder {
	return NewUplinkDecoder(keys)
}

// Decode authenticates and decrypts an inbound wire buffer.
func (d *Decoder) Decode(data []byte) (*DataFrame, error) {
	if len(data) < 14 {
		return nil, errors.New("mfp: too short")
	}
	h, err := DecodeHeader(data[:14])
	if err != nil {
		return nil, err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// A frame that fails authentication must not consume a nonce. Advancing the
	// counter on failure desynchronises this direction permanently: the next
	// legitimate frame is tried with the wrong nonce and rejected in turn. This
	// is what happens when an unauthenticated dummy frame (DummyFrame carries no
	// AEAD tag) reaches a decoder.
	nonce := crypto.GenerateNonce(d.seed, d.Count)

	plain, err := crypto.AEADDecrypt(&d.Keys.TrafficEncKey, nonce, data[14:])
	if err != nil {
		return nil, err
	}
	d.Count++

	// Strip padding when enabled. The 2-byte prefix encodes the original
	// length, letting us drop the random tail added by the peer.
	// Mirrors Encoder.Encode: only strip when the peer actually pads.
	if d.padCfg.Enabled() {
		stripped, err := UnpadPayload(plain, d.padCfg)
		if err != nil {
			return nil, err
		}
		plain = stripped
	}

	d.bytesProcessed += uint64(len(plain))
	d.recvBytes += uint64(len(plain))
	if d.balancer != nil {
		d.balancer.Recv += uint64(len(plain))
	}

	return &DataFrame{Header: *h, Data: plain}, nil
}

func (d *Decoder) SetRenewal(limit uint64, interval time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.renewalLimit = limit
	d.renewalInterval = interval
}

// SetPadding mirrors the peer encoder's padding config so Decode can strip
// the length prefix and return the original plaintext.
func (d *Decoder) SetPadding(cfg PaddingConfig) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.padCfg = cfg.Normalize()
}

// SetBalancer attaches a DirectionBalancer for received-byte accounting.
func (d *Decoder) SetBalancer(b *DirectionBalancer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.balancer = b
}

func (d *Decoder) ShouldRotate() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.renewalLimit > 0 && d.bytesProcessed >= d.renewalLimit {
		return true
	}
	if d.renewalInterval > 0 && time.Since(d.createdAt) >= d.renewalInterval {
		return true
	}
	return false
}

func (d *Decoder) RotateKeys() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.generation++
	newKeys, err := crypto.RotateKeyMaterial(d.Keys, d.generation)
	if err != nil {
		return err
	}
	d.Keys = newKeys
	if d.isUplink {
		d.seed = &newKeys.NonceSeedUplink
	} else {
		d.seed = &newKeys.NonceSeedDownlk
	}
	d.Count = 0
	d.bytesProcessed = 0
	d.createdAt = time.Now()
	return nil
}

// ---------------------------------------------------------------------------
// Padding
// ---------------------------------------------------------------------------

// PaddingConfig controls traffic-padding behaviour.
type PaddingConfig struct {
	Mode     config.PaddingMode
	BaseSize uint32
	MaxSize  uint32
	Balanced bool
}

// Normalize returns cfg with empty/zero fields filled in so that a
// zero-value PaddingConfig behaves as "no padding" rather than accidentally
// matching the padding branch ("" != PaddingNone).
//
// Callers should prefer this when building a PaddingConfig from config files,
// where padding_mode may be absent.
func (cfg PaddingConfig) Normalize() PaddingConfig {
	if cfg.Mode == "" {
		cfg.Mode = config.PaddingNone
	}
	if cfg.BaseSize == 0 {
		cfg.BaseSize = 1400
	}
	if cfg.MaxSize == 0 {
		cfg.MaxSize = 1452
	}
	if cfg.MaxSize < cfg.BaseSize {
		cfg.MaxSize = cfg.BaseSize
	}
	return cfg
}

// Enabled reports whether padding is active for this configuration.
func (cfg PaddingConfig) Enabled() bool {
	return cfg.Mode != config.PaddingNone && cfg.Mode != ""
}

// PadPayload pads data according to the padding mode.
//
// In random mode the first 2 bytes of the padded payload encode the original
// data length (big-endian uint16) so UnpadPayload can recover it without extra
// framing.
//
// Fix #19: previous code used math/rand (predictable) instead of crypto/rand.
func PadPayload(data []byte, cfg PaddingConfig) ([]byte, error) {
	switch cfg.Mode {
	case config.PaddingNone:
		return data, nil

	case config.PaddingFixed:
		if uint32(len(data)) >= cfg.BaseSize {
			return data, nil
		}
		p := make([]byte, cfg.BaseSize)
		copy(p, data)
		// Fill remaining bytes with deterministic pseudo-random padding derived
		// from the data itself (avoids crypto/rand overhead for fixed padding).
		for i := len(data); i < int(cfg.BaseSize); i++ {
			p[i] = byte(i ^ len(data))
		}
		return p, nil

	default: // PaddingRandom
		// Layout: [2-byte actual length (BE)] [actual data] [random padding].
		// Small frames are padded up to BaseSize; large frames only receive a
		// small random tail up to MaxSize. The old code added a full BaseSize
		// to every frame, including 32KB bulk frames, wasting bandwidth and
		// generating unnecessary crypto/rand traffic on the hot path.
		actualLen := uint16(len(data))
		minimum := cfg.BaseSize
		if payloadLen := uint32(len(data)) + 2; payloadLen > minimum {
			minimum = payloadLen
		}

		extra := uint32(0)
		if cfg.MaxSize > cfg.BaseSize {
			diff := cfg.MaxSize - cfg.BaseSize + 1
			rnd := make([]byte, 4)
			if _, err := rand.Read(rnd); err != nil { // Fix #19: crypto/rand
				return nil, fmt.Errorf("mfp: rand.Read for padding failed: %w", err)
			}
			extra = binary.BigEndian.Uint32(rnd) % diff
		}
		totalLen := minimum + extra
		p := make([]byte, totalLen)
		binary.BigEndian.PutUint16(p[0:2], actualLen)
		copy(p[2:], data)
		if _, err := rand.Read(p[2+len(data):]); err != nil { // Fix #19
			return nil, fmt.Errorf("mfp: rand.Read for random padding failed: %w", err)
		}
		return p, nil
	}
}

// UnpadPayload strips padding added by PadPayload.
// Fix #20: random mode was not implemented — it just returned data unchanged.
// Now reads the 2-byte length prefix written by PadPayload.
func UnpadPayload(data []byte, cfg PaddingConfig) ([]byte, error) {
	switch cfg.Mode {
	case config.PaddingNone, config.PaddingFixed:
		return data, nil
	default: // PaddingRandom
		if len(data) < 2 {
			return nil, errors.New("mfp: padded payload too short to contain length prefix")
		}
		actualLen := int(binary.BigEndian.Uint16(data[0:2]))
		if 2+actualLen > len(data) {
			return nil, errors.New("mfp: length prefix exceeds payload size")
		}
		return data[2 : 2+actualLen], nil
	}
}

// ---------------------------------------------------------------------------
// Direction balancer & packet timer
// ---------------------------------------------------------------------------

// DirectionBalancer decides whether a dummy frame should be injected to make
// traffic appear symmetric.
type DirectionBalancer struct {
	Sent, Recv uint64
	Balance    bool
}

func NewDirectionBalancer(b bool) *DirectionBalancer { return &DirectionBalancer{Balance: b} }
func (b *DirectionBalancer) ShouldSendDummy() bool   { return b.Balance && b.Sent > b.Recv*2 }

// PacketTimer controls artificial timing jitter (in nanoseconds).
type PacketTimer struct{ JitterMS float64 }

func NewPacketTimer(j float64) *PacketTimer { return &PacketTimer{JitterMS: j} }
func (t *PacketTimer) Delay() int64 {
	if t.JitterMS <= 0 {
		return 0
	}
	rnd := make([]byte, 8)
	rand.Read(rnd)                                //nolint:errcheck // best-effort jitter
	v := int64(binary.BigEndian.Uint64(rnd) >> 1) // ensure positive
	return v % int64(t.JitterMS*1e6)
}

// DummyFrame is kept only for source compatibility and must not be sent on the
// wire: it produces a 14-byte header with no ciphertext and no AEAD tag, which
// the receiving decoder cannot authenticate. Use (*Encoder).DummyFrame.
//
// Deprecated: use (*Encoder).DummyFrame instead.
func DummyFrame() ([]byte, error) {
	b := make([]byte, 14)
	b[0] = TypeKEEPALIVE
	return b, nil
}

// FrameTypeString returns a human-readable name for a frame type byte.
func FrameTypeString(t byte) string {
	switch t {
	case TypeDATA:
		return "DATA"
	case TypeACK:
		return "ACK"
	case TypeCONGEST:
		return "CONGEST"
	case TypePING:
		return "PING"
	case TypePONG:
		return "PONG"
	case TypeBOUNDARY:
		return "BOUNDARY"
	case TypeERROR:
		return "ERROR"
	case TypeFLOW:
		return "FLOW"
	case TypeRESET:
		return "RESET"
	case TypeKEEPALIVE:
		return "KEEPALIVE"
	}
	return "UNKNOWN"
}
