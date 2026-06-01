package mfp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"meridian/pkg/config"
	"meridian/pkg/crypto"
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
//   Offset  Size  Field
//   0       1     Type
//   1       2     PayloadLen
//   3       4     StreamID
//   7       1     Flags
//   8       4     Sequence
//   12      2     Extended
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
	buf[7] = h.Flags                              // Flags  @ offset 7 (1 byte)
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
		Flags:      data[7],                              // Fix: was data[7] overlapping with Sequence
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
}

// NewEncoder creates an uplink encoder (client→server), using NonceSeedUplink.
func NewEncoder(keys *crypto.KeyMaterial) *Encoder {
	return &Encoder{Keys: keys, Pool: NewFramePool(), seed: &keys.NonceSeedUplink}
}

// NewDownlinkEncoder creates a downlink encoder (server→client), using NonceSeedDownlk.
func NewDownlinkEncoder(keys *crypto.KeyMaterial) *Encoder {
	return &Encoder{Keys: keys, Pool: NewFramePool(), seed: &keys.NonceSeedDownlk}
}

// Encode encrypts data for stream sid with the given flags.
// PayloadLen in the header records the actual (pre-padding) data length so
// the receiver can strip padding via Decoder.Decode.
func (e *Encoder) Encode(sid uint32, flags byte, data []byte) ([]byte, error) {
	seq := e.Count
	e.Count++

	header := &FrameHeader{
		Type:       TypeDATA,
		PayloadLen: uint16(len(data)),
		StreamID:   sid,
		Sequence:   uint32(seq),
		Flags:      flags,
	}
	hb := EncodeHeader(header)

	// Fix #6: derive a unique nonce per packet using the direction-specific seed.
	nonce := crypto.GenerateNonce(e.seed, seq)

	ciphertext, err := crypto.AEADEncrypt(&e.Keys.TrafficEncKey, nonce, data)
	if err != nil {
		return nil, err
	}

	buf := e.Pool.Get()
	*buf = append((*buf)[:0], hb...)
	*buf = append(*buf, ciphertext...)
	return *buf, nil
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
}

// NewUplinkDecoder creates a decoder for server-side decryption of client→server frames.
// It uses NonceSeedUplink, matching the client's Encoder.
func NewUplinkDecoder(keys *crypto.KeyMaterial) *Decoder {
	return &Decoder{Keys: keys, Pool: NewFramePool(), seed: &keys.NonceSeedUplink}
}

// NewDownlinkDecoder creates a decoder for client-side decryption of server→client frames.
// It uses NonceSeedDownlk, matching the server's Encoder (when server sends downlink).
func NewDownlinkDecoder(keys *crypto.KeyMaterial) *Decoder {
	return &Decoder{Keys: keys, Pool: NewFramePool(), seed: &keys.NonceSeedDownlk}
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

	nonce := crypto.GenerateNonce(d.seed, d.Count)
	d.Count++

	plain, err := crypto.AEADDecrypt(&d.Keys.TrafficEncKey, nonce, data[14:])
	if err != nil {
		return nil, err
	}
	return &DataFrame{Header: *h, Data: plain}, nil
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
		// Layout: [2-byte actual length (BE)] [actual data] [random padding]
		actualLen := uint16(len(data))
		padded := cfg.BaseSize
		if cfg.MaxSize > cfg.BaseSize {
			// Compute a random amount of additional padding in [0, MaxSize-BaseSize].
			diff := cfg.MaxSize - cfg.BaseSize + 1
			rnd := make([]byte, 4)
			if _, err := rand.Read(rnd); err != nil { // Fix #19: crypto/rand
				return nil, fmt.Errorf("mfp: rand.Read for padding failed: %w", err)
			}
			extra := binary.BigEndian.Uint32(rnd) % diff
			padded += extra
		}
		totalLen := 2 + uint32(len(data)) + padded
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
	rand.Read(rnd) //nolint:errcheck // best-effort jitter
	v := int64(binary.BigEndian.Uint64(rnd) >> 1) // ensure positive
	return v % int64(t.JitterMS*1e6)
}

// DummyFrame builds a 14-byte KEEPALIVE frame for direction balancing.
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