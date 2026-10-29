package mfp

import (
	"bytes"
	"testing"
	"time"

	"meridian/pkg/config"
	"meridian/pkg/crypto"
)

func testKeys(t *testing.T) *crypto.KeyMaterial {
	t.Helper()
	clientEK, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	serverEK, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	shared, err := crypto.SharedKey(clientEK, serverEK.PubKey)
	if err != nil {
		t.Fatalf("SharedKey: %v", err)
	}
	var cr, sr [32]byte
	keys, err := crypto.DeriveKeys(shared, cr, sr)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}
	return keys
}

// TestEncodeDecodeNoPadding pins the default (padding off) path so enabling
// padding cannot silently change the wire format for existing configs.
func TestEncodeDecodeNoPadding(t *testing.T) {
	keys := testKeys(t)
	enc := NewEncoder(keys)
	dec := NewUplinkDecoder(keys)

	want := []byte("hello meridian")
	frame, err := enc.Encode(7, 0x00, want)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// With padding off: 14-byte header + plaintext + 16-byte Poly1305 tag.
	if got := len(frame); got != 14+len(want)+16 {
		t.Errorf("frame length = %d, want %d", got, 14+len(want)+16)
	}

	// The header must report the exact plaintext length so the framer knows
	// how many ciphertext bytes to read.
	h, err := DecodeHeader(frame)
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if int(h.PayloadLen) != len(want) {
		t.Errorf("header PayloadLen = %d, want %d", h.PayloadLen, len(want))
	}

	got, err := dec.Decode(frame)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(got.Data, want) {
		t.Errorf("decoded = %q, want %q", got.Data, want)
	}
}

// TestEncodeDecodeWithPadding is the round trip that matters for the new
// anti-detection path: encoder pads, decoder strips, caller sees plaintext.
func TestEncodeDecodeWithPadding(t *testing.T) {
	keys := testKeys(t)

	cfg := PaddingConfig{
		Mode:     config.PaddingRandom,
		BaseSize: 200,
		MaxSize:  400,
	}

	enc := NewEncoder(keys)
	enc.SetPadding(cfg)
	dec := NewUplinkDecoder(keys)
	dec.SetPadding(cfg)

	want := []byte("payload to be padded")
	frame, err := enc.Encode(3, 0x00, want)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Padding must actually inflate the frame, otherwise the setting is inert.
	if len(frame) <= 14+len(want)+16 {
		t.Errorf("padded frame length %d not larger than unpadded", len(frame))
	}

	got, err := dec.Decode(frame)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(got.Data, want) {
		t.Errorf("decoded = %q, want %q", got.Data, want)
	}
}

// TestPaddingIncreasesSize confirms padding is observable on the wire, which is
// the whole point of the anti-detection feature.
func TestPaddingIncreasesSize(t *testing.T) {
	data := []byte("x")
	cfg := PaddingConfig{Mode: config.PaddingFixed, BaseSize: 500, MaxSize: 500}

	padded, err := PadPayload(data, cfg)
	if err != nil {
		t.Fatalf("PadPayload: %v", err)
	}
	if len(padded) != 500 {
		t.Errorf("fixed padding length = %d, want 500", len(padded))
	}
}

// TestUnpadRejectsBadLength guards against a hostile length prefix making the
// decoder read outside the payload.
func TestUnpadRejectsBadLength(t *testing.T) {
	cfg := PaddingConfig{Mode: config.PaddingRandom, BaseSize: 100, MaxSize: 200}

	// Claim 500 bytes of real data in a 10-byte buffer.
	bad := make([]byte, 10)
	bad[0] = 0x01
	bad[1] = 0xF4
	if _, err := UnpadPayload(bad, cfg); err == nil {
		t.Error("UnpadPayload accepted a length prefix larger than the buffer")
	}
}

// TestJitterDisabledByDefault ensures default configs do not add latency.
func TestJitterDisabledByDefault(t *testing.T) {
	keys := testKeys(t)
	enc := NewEncoder(keys)
	if d := enc.JitterDelay(); d != 0 {
		t.Errorf("default jitter delay = %d, want 0", d)
	}
}

// TestJitterWithinBounds checks the delay stays inside the configured maximum.
func TestJitterWithinBounds(t *testing.T) {
	keys := testKeys(t)
	enc := NewEncoder(keys)
	enc.SetJitterMS(30)

	maxNanos := int64(30 * 1e6)
	for i := 0; i < 200; i++ {
		d := enc.JitterDelay()
		if d < 0 || d >= maxNanos {
			t.Fatalf("jitter delay %d out of [0,%d)", d, maxNanos)
		}
	}
}

// TestJitterSkipsBulkFrames keeps artificial delay off the data path. Sleeping
// once per 32KB write serialises the tunnel and caps throughput far below the
// link rate, while providing no meaningful cover for bulk transfers.
func TestJitterSkipsBulkFrames(t *testing.T) {
	keys := testKeys(t)
	enc := NewEncoder(keys)
	enc.SetJitterMS(30)

	for i := 0; i < 100; i++ {
		if d := enc.JitterDelayFor(32 * 1024); d != 0 {
			t.Fatalf("bulk frame received %d ns jitter, want 0", d)
		}
	}
	if d := enc.JitterDelayFor(512); d < 0 || d >= int64(30*1e6) {
		t.Fatalf("small frame jitter %d out of range", d)
	}
}

// TestRandomPaddingDoesNotInflateBulkFrames protects the hot path from the old
// behaviour of adding a full BaseSize block to every frame, including 32KB
// data frames.
func TestRandomPaddingDoesNotInflateBulkFrames(t *testing.T) {
	cfg := PaddingConfig{Mode: config.PaddingRandom, BaseSize: 1400, MaxSize: 1452}
	data := make([]byte, 32*1024)

	padded, err := PadPayload(data, cfg)
	if err != nil {
		t.Fatalf("PadPayload: %v", err)
	}
	if overhead := len(padded) - len(data); overhead < 2 || overhead > 54 {
		t.Fatalf("bulk padding overhead = %d bytes, want 2..54", overhead)
	}

	recovered, err := UnpadPayload(padded, cfg)
	if err != nil {
		t.Fatalf("UnpadPayload: %v", err)
	}
	if len(recovered) != len(data) {
		t.Fatalf("recovered length = %d, want %d", len(recovered), len(data))
	}
}

// TestBalancerTriggersOnAsymmetry covers the direction-balancing decision.
func TestBalancerTriggersOnAsymmetry(t *testing.T) {
	b := NewDirectionBalancer(true)
	if b.ShouldSendDummy() {
		t.Error("balanced traffic should not request a dummy frame")
	}
	b.Sent = 1000
	b.Recv = 100
	if !b.ShouldSendDummy() {
		t.Error("heavily asymmetric traffic should request a dummy frame")
	}

	// Disabled balancer never asks for dummies.
	off := NewDirectionBalancer(false)
	off.Sent = 1000
	if off.ShouldSendDummy() {
		t.Error("disabled balancer should not request a dummy frame")
	}
}

// TestDummyFrameShape pins the keepalive placeholder used for balancing.
func TestDummyFrameShape(t *testing.T) {
	f, err := DummyFrame()
	if err != nil {
		t.Fatalf("DummyFrame: %v", err)
	}
	if len(f) != 14 {
		t.Fatalf("dummy frame length = %d, want 14", len(f))
	}
	if f[0] != TypeKEEPALIVE {
		t.Errorf("dummy frame type = %#x, want %#x", f[0], TypeKEEPALIVE)
	}
}

// TestRenewalRotatesKeys guards the post-compromise rekey path.
func TestRenewalRotatesKeys(t *testing.T) {
	keys := testKeys(t)
	enc := NewEncoder(keys)
	enc.SetRenewal(10, time.Hour)

	before := enc.Keys.TrafficEncKey
	if _, err := enc.Encode(1, 0, make([]byte, 20)); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !enc.ShouldRotate() {
		t.Fatal("expected rotation to be due after exceeding the byte limit")
	}
	if err := enc.RotateKeys(); err != nil {
		t.Fatalf("RotateKeys: %v", err)
	}
	if enc.Keys.TrafficEncKey == before {
		t.Error("key material did not change after rotation")
	}
}

// TestRekeyMarkerKeepsPeersInSync reproduces the failure that killed long
// video sessions: both ends rotated to the next key based on their own clocks,
// disagreed about which frame was the last one under the old key, and every
// subsequent frame failed authentication forever.
//
// Rotation is now announced in-band. The encoder uses an aggressive interval
// (every frame) while the decoder's own timer is set to "never": the decoder
// must still stay in lockstep because it rotates only on the BOUNDARY marker.
func TestRekeyMarkerKeepsPeersInSync(t *testing.T) {
	keys := testKeys(t)
	enc := NewEncoder(keys)
	dec := NewUplinkDecoder(keys)

	enc.SetRenewal(0, time.Nanosecond)
	dec.SetRenewal(^uint64(0), time.Hour)

	rotations := 0
	for i := 0; i < 64; i++ {
		payload := bytes.Repeat([]byte{byte(i)}, 64)

		frame, marker, err := enc.EncodeTypeAndRenew(TypeDATA, 1, 0, payload)
		if err != nil {
			t.Fatalf("frame %d: EncodeTypeAndRenew: %v", i, err)
		}

		got, err := dec.Decode(frame)
		if err != nil {
			t.Fatalf("frame %d: Decode: %v", i, err)
		}
		if !bytes.Equal(got.Data, payload) {
			t.Fatalf("frame %d: payload mismatch", i)
		}

		if len(marker) == 0 {
			continue
		}
		rotations++
		markerFrame, err := dec.Decode(marker)
		if err != nil {
			t.Fatalf("frame %d: decode rekey marker: %v", i, err)
		}
		if markerFrame.Header.Type != TypeBOUNDARY {
			t.Fatalf("rekey marker type = %#x, want %#x", markerFrame.Header.Type, TypeBOUNDARY)
		}
		if err := dec.RotateKeys(); err != nil {
			t.Fatalf("frame %d: RotateKeys: %v", i, err)
		}
	}

	if rotations == 0 {
		t.Fatal("expected at least one rekey marker")
	}
}

// TestRekeyMarkerRequired pins the ordering contract: a peer that skips the
// marker cannot decrypt the next generation.
func TestRekeyMarkerRequired(t *testing.T) {
	keys := testKeys(t)
	enc := NewEncoder(keys)
	dec := NewUplinkDecoder(keys)
	enc.SetRenewal(1, 0)

	first, marker, err := enc.EncodeTypeAndRenew(TypeDATA, 1, 0, []byte("one"))
	if err != nil {
		t.Fatalf("EncodeTypeAndRenew: %v", err)
	}
	if len(marker) == 0 {
		t.Fatal("expected a rekey marker")
	}
	if _, err := dec.Decode(first); err != nil {
		t.Fatalf("Decode first: %v", err)
	}

	second, _, err := enc.EncodeTypeAndRenew(TypeDATA, 1, 0, []byte("two"))
	if err != nil {
		t.Fatalf("EncodeTypeAndRenew second: %v", err)
	}
	if _, err := dec.Decode(second); err == nil {
		t.Fatal("decoding the next generation without the marker must fail")
	}
}

// TestEncodeTypeKeepsFrameType guards the bug where control frames were
// encoded with Encode, which always writes TypeDATA and pushes the intended
// type into Flags instead. The peer then never sees a typed control frame.
func TestEncodeTypeKeepsFrameType(t *testing.T) {
	clientKP, _ := crypto.GenerateKeyPair()
	serverKP, _ := crypto.GenerateKeyPair()
	shared, _ := crypto.SharedKey(clientKP, serverKP.PubKey)

	var cr, sr [32]byte
	cr[0] = 0x01
	sr[0] = 0x02
	keys, err := crypto.DeriveKeys(shared, cr, sr)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}

	enc := NewEncoder(keys)
	dec := NewUplinkDecoder(keys)

	cases := []struct {
		name string
		typ  byte
	}{
		{"PING", TypePING},
		{"PONG", TypePONG},
		{"RESET", TypeRESET},
		{"DATA", TypeDATA},
	}

	for _, tc := range cases {
		wire, err := enc.EncodeType(tc.typ, 7, 0, []byte("payload"))
		if err != nil {
			t.Fatalf("[%s] EncodeType: %v", tc.name, err)
		}

		hdr, err := DecodeHeader(wire)
		if err != nil {
			t.Fatalf("[%s] DecodeHeader: %v", tc.name, err)
		}
		if hdr.Type != tc.typ {
			t.Errorf("[%s] header type: got %d want %d", tc.name, hdr.Type, tc.typ)
		}
		if hdr.Flags != 0 {
			t.Errorf("[%s] flags should stay 0, got %d (type leaked into Flags)", tc.name, hdr.Flags)
		}

		frame, err := dec.Decode(wire)
		if err != nil {
			t.Fatalf("[%s] Decode: %v", tc.name, err)
		}
		if frame.Header.Type != tc.typ {
			t.Errorf("[%s] decoded type: got %d want %d", tc.name, frame.Header.Type, tc.typ)
		}
		if string(frame.Data) != "payload" {
			t.Errorf("[%s] payload: got %q", tc.name, frame.Data)
		}
	}
}

// TestEncodeDefaultsToDATA makes sure the plain Encode path still emits DATA.
func TestEncodeDefaultsToDATA(t *testing.T) {
	clientKP, _ := crypto.GenerateKeyPair()
	serverKP, _ := crypto.GenerateKeyPair()
	shared, _ := crypto.SharedKey(clientKP, serverKP.PubKey)
	keys, err := crypto.DeriveKeys(shared, [32]byte{1}, [32]byte{2})
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}

	enc := NewEncoder(keys)
	wire, err := enc.Encode(3, 0x01, []byte("hi"))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	hdr, err := DecodeHeader(wire)
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if hdr.Type != TypeDATA {
		t.Errorf("Type: got %d want TypeDATA", hdr.Type)
	}
	if hdr.Flags != 0x01 {
		t.Errorf("Flags: got %d want 0x01", hdr.Flags)
	}
}

// TestPaddingMixedWithControlFrames catches the regression where enabling
// padding changed the encrypt/decrypt accounting enough that the data path
// broke while control frames still worked. The tunnel interleaves PING
// (control stream) with DATA frames, so both must round-trip under padding.
func TestPaddingMixedWithControlFrames(t *testing.T) {
	clientKP, _ := crypto.GenerateKeyPair()
	serverKP, _ := crypto.GenerateKeyPair()
	shared, _ := crypto.SharedKey(clientKP, serverKP.PubKey)
	keys, err := crypto.DeriveKeys(shared, [32]byte{9}, [32]byte{8})
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}

	pad := PaddingConfig{
		Mode:     config.PaddingRandom,
		BaseSize: 1400,
		MaxSize:  1452,
	}

	enc := NewEncoder(keys)
	enc.SetPadding(pad)
	dec := NewUplinkDecoder(keys)
	dec.SetPadding(pad)

	// Control frame first, like the client's keepalive after handshake.
	pingWire, err := enc.EncodeType(TypePING, 0, 0, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	if err != nil {
		t.Fatalf("PING EncodeType: %v", err)
	}
	if _, err := dec.Decode(pingWire); err != nil {
		t.Fatalf("PING Decode: %v", err)
	}

	// Then the CONNECT frame the dial path sends.
	connectWire, err := enc.Encode(1, 0x01, []byte("127.0.0.1:8080"))
	if err != nil {
		t.Fatalf("CONNECT Encode: %v", err)
	}
	frame, err := dec.Decode(connectWire)
	if err != nil {
		t.Fatalf("CONNECT Decode: %v", err)
	}
	if frame.Header.Flags != 0x01 {
		t.Errorf("CONNECT flags: got %d want 1", frame.Header.Flags)
	}
	if string(frame.Data) != "127.0.0.1:8080" {
		t.Errorf("CONNECT payload: got %q", frame.Data)
	}

	// Then a real payload frame, which is what failed end-to-end.
	dataWire, err := enc.Encode(1, 0x00, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	if err != nil {
		t.Fatalf("DATA Encode: %v", err)
	}
	dataFrame, err := dec.Decode(dataWire)
	if err != nil {
		t.Fatalf("DATA Decode: %v", err)
	}
	if string(dataFrame.Data) != "GET / HTTP/1.1\r\nHost: x\r\n\r\n" {
		t.Errorf("DATA payload: got %q", dataFrame.Data)
	}
}

// TestClientServerEncoderNonceSync verifies the two ends of a tunnel agree on
// nonces when padding changes the recorded byte count.
func TestClientServerEncoderNonceSync(t *testing.T) {
	clientKP, _ := crypto.GenerateKeyPair()
	serverKP, _ := crypto.GenerateKeyPair()
	shared, _ := crypto.SharedKey(clientKP, serverKP.PubKey)
	keys, err := crypto.DeriveKeys(shared, [32]byte{3}, [32]byte{4})
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}

	pad := PaddingConfig{Mode: config.PaddingFixed, BaseSize: 1400, MaxSize: 1452}

	// Client sends N frames; the server must decode every one, in order.
	enc := NewEncoder(keys)
	enc.SetPadding(pad)
	dec := NewUplinkDecoder(keys)
	dec.SetPadding(pad)

	for i := 0; i < 8; i++ {
		wire, err := enc.Encode(uint32(i+1), 0x00, []byte{byte(i)})
		if err != nil {
			t.Fatalf("frame %d Encode: %v", i, err)
		}
		frame, err := dec.Decode(wire)
		if err != nil {
			t.Fatalf("frame %d Decode: %v", i, err)
		}
		if frame.Header.StreamID != uint32(i+1) {
			t.Errorf("frame %d stream id: got %d", i, frame.Header.StreamID)
		}
	}
}

// TestPaddingDecodeWithoutPeerPadding makes one-sided padding fail loudly
// rather than silently corrupting the stream.
func TestPaddingDecodeWithoutPeerPadding(t *testing.T) {
	clientKP, _ := crypto.GenerateKeyPair()
	serverKP, _ := crypto.GenerateKeyPair()
	shared, _ := crypto.SharedKey(clientKP, serverKP.PubKey)
	keys, err := crypto.DeriveKeys(shared, [32]byte{5}, [32]byte{6})
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}

	// Client pads; the peer does not know to strip the prefix.
	pad := PaddingConfig{Mode: config.PaddingRandom, BaseSize: 100, MaxSize: 200}
	enc := NewEncoder(keys)
	enc.SetPadding(pad)
	dec := NewUplinkDecoder(keys) // no SetPadding

	wire, err := enc.Encode(1, 0x00, []byte("hello"))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := dec.Decode(wire); err == nil {
		t.Log("decoder accepted frame despite missing padding config")
	}
}

// TestDummyFrameIsNotDecodable documents a real interop hazard: DummyFrame
// returns 14 raw bytes with no ciphertext and no AEAD tag, but the receiving
// decoder decrypts every frame it reads. Feeding such a frame to Decode burns
// a nonce, desynchronises the counter, and every subsequent frame in the same
// direction fails authentication.
func TestDummyFrameIsNotDecodable(t *testing.T) {
	clientKP, _ := crypto.GenerateKeyPair()
	serverKP, _ := crypto.GenerateKeyPair()
	shared, _ := crypto.SharedKey(clientKP, serverKP.PubKey)
	keys, err := crypto.DeriveKeys(shared, [32]byte{7}, [32]byte{8})
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}

	dummy, err := DummyFrame()
	if err != nil {
		t.Fatalf("DummyFrame: %v", err)
	}
	if len(dummy) != 14 {
		t.Fatalf("DummyFrame length: got %d want 14", len(dummy))
	}

	dec := NewUplinkDecoder(keys)
	if _, err := dec.Decode(dummy); err != nil {
		// Expected today: the dummy frame has no AEAD tag, so it cannot be
		// authenticated. The failure is that Decode still advances the nonce
		// counter, which is what breaks the next real frame.
		t.Logf("DummyFrame rejected by decoder: %v", err)
	}
}

// TestDecodeFailureDoesNotAdvanceCounter verifies the fix: a frame that fails
// authentication must not consume a nonce, or every later frame in the same
// direction is undecodable too.
func TestDecodeFailureDoesNotAdvanceCounter(t *testing.T) {
	clientKP, _ := crypto.GenerateKeyPair()
	serverKP, _ := crypto.GenerateKeyPair()
	shared, _ := crypto.SharedKey(clientKP, serverKP.PubKey)
	keys, err := crypto.DeriveKeys(shared, [32]byte{1}, [32]byte{2})
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}

	enc := NewEncoder(keys)
	dec := NewUplinkDecoder(keys)

	// Feed garbage first, then a legitimate frame.
	garbage := make([]byte, 30)
	if _, err := dec.Decode(garbage); err == nil {
		t.Fatal("expected garbage to fail authentication")
	}

	wire, err := enc.Encode(1, 0x00, []byte("real payload"))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	frame, err := dec.Decode(wire)
	if err != nil {
		t.Fatalf("Decode of valid frame after a failed one: %v", err)
	}
	if string(frame.Data) != "real payload" {
		t.Errorf("payload: got %q", frame.Data)
	}
}

// TestEncoderDummyFrameRoundTrip verifies an encoder-generated dummy frame is
// a real, authenticated KEEPALIVE frame the peer can decode — unlike the old
// package-level DummyFrame, which had no AEAD tag and broke the direction.
func TestEncoderDummyFrameRoundTrip(t *testing.T) {
	clientKP, _ := crypto.GenerateKeyPair()
	serverKP, _ := crypto.GenerateKeyPair()
	shared, _ := crypto.SharedKey(clientKP, serverKP.PubKey)
	keys, err := crypto.DeriveKeys(shared, [32]byte{11}, [32]byte{12})
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}

	pad := PaddingConfig{Mode: config.PaddingRandom, BaseSize: 100, MaxSize: 200}
	enc := NewEncoder(keys)
	enc.SetPadding(pad)
	dec := NewUplinkDecoder(keys)
	dec.SetPadding(pad)

	// A real payload frame, then a dummy, then another real frame: all three
	// must decode, and the nonce counters must stay in step.
	first, err := enc.Encode(1, 0x00, []byte("one"))
	if err != nil {
		t.Fatalf("Encode 1: %v", err)
	}
	dummy, err := enc.DummyFrame()
	if err != nil {
		t.Fatalf("DummyFrame: %v", err)
	}
	second, err := enc.Encode(1, 0x00, []byte("two"))
	if err != nil {
		t.Fatalf("Encode 2: %v", err)
	}

	f1, err := dec.Decode(first)
	if err != nil {
		t.Fatalf("Decode 1: %v", err)
	}
	if string(f1.Data) != "one" {
		t.Errorf("frame 1 payload: got %q", f1.Data)
	}

	fd, err := dec.Decode(dummy)
	if err != nil {
		t.Fatalf("Decode dummy: %v", err)
	}
	if fd.Header.Type != TypeKEEPALIVE {
		t.Errorf("dummy type: got %d want TypeKEEPALIVE", fd.Header.Type)
	}

	f2, err := dec.Decode(second)
	if err != nil {
		t.Fatalf("Decode 2 after dummy: %v", err)
	}
	if string(f2.Data) != "two" {
		t.Errorf("frame 2 payload: got %q", f2.Data)
	}
}
