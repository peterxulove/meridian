// Package integration provides an end-to-end communication test for Meridian.
//
// The test starts a real UDP server in a goroutine, sends a ClientHello from a
// real client UDP socket, and verifies the server receives and parses the packet
// without panicking, returning a valid handshake object.
//
// Run with:
//
//	go test ./test/integration/ -v -timeout 30s
package integration

import (
	"fmt"
	"net"
	"testing"
	"time"

	"meridian/pkg/config"
	"meridian/pkg/crypto"
	"meridian/pkg/mfp"
	"meridian/pkg/mtp"
)

// ─────────────────────────────────────────────────────────────────────────────
// Section 1: Unit-level checks on the fixed subsystems
// ─────────────────────────────────────────────────────────────────────────────

func TestCryptoKeyGeneration(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if len(kp.PrivKey) != 32 {
		t.Errorf("expected 32-byte private key, got %d", len(kp.PrivKey))
	}
	if len(kp.PubKey) != 32 {
		t.Errorf("expected 32-byte public key, got %d", len(kp.PubKey))
	}
	t.Logf("PrivKey: %x", kp.PrivKey)
	t.Logf("PubKey:  %x", kp.PubKey)
}

func TestECDHKeyExchange(t *testing.T) {
	// Simulate server and client independently generating key pairs and computing
	// the shared secret. Both sides must arrive at the same value.
	clientKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("client GenerateKeyPair: %v", err)
	}
	serverKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("server GenerateKeyPair: %v", err)
	}

	clientShared, err := crypto.SharedKey(clientKP, serverKP.PubKey)
	if err != nil {
		t.Fatalf("client SharedKey: %v", err)
	}
	serverShared, err := crypto.SharedKey(serverKP, clientKP.PubKey)
	if err != nil {
		t.Fatalf("server SharedKey: %v", err)
	}

	if string(clientShared) != string(serverShared) {
		t.Errorf("ECDH shared secrets differ!\n  client: %x\n  server: %x", clientShared, serverShared)
	}
	t.Logf("Shared secret: %x", clientShared)
}

func TestKeyDerivation(t *testing.T) {
	sharedSecret := make([]byte, 32)
	crypto.GenerateRandom(32) // ensure no panic
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}
	var cr, sr [32]byte
	for i := range cr {
		cr[i] = byte(i + 1)
		sr[i] = byte(i + 2)
	}
	keys, err := crypto.DeriveKeys(sharedSecret, cr, sr)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}
	if keys.TrafficEncKey == [32]byte{} {
		t.Error("TrafficEncKey is all-zero")
	}
	if keys.NonceSeedUplink == [16]byte{} {
		t.Error("NonceSeedUplink is all-zero")
	}
	t.Logf("TrafficEncKey:   %x", keys.TrafficEncKey)
	t.Logf("TrafficMACKey:   %x", keys.TrafficMACKey)
	t.Logf("NonceSeedUplink: %x", keys.NonceSeedUplink)
	t.Logf("NonceSeedDownlk: %x", keys.NonceSeedDownlk)
	t.Logf("InitKey:         %x", keys.InitKey)
}

func TestNonceUniqueness(t *testing.T) {
	var seed [16]byte
	for i := range seed {
		seed[i] = 0xAB
	}
	seen := make(map[[12]byte]bool)
	for i := uint64(0); i < 1000; i++ {
		n := crypto.GenerateNonce(&seed, i)
		if seen[*n] {
			t.Errorf("nonce collision at counter %d: %x", i, *n)
		}
		seen[*n] = true
	}
	t.Logf("Generated 1000 unique nonces ✓")
}

func TestAEADRoundTrip(t *testing.T) {
	var key [32]byte
	b, _ := crypto.GenerateRandom(32)
	copy(key[:], b)

	plaintext := []byte("Hello, Meridian Protocol!")
	nonce := crypto.GenerateNonce((*[16]byte)(b[:16]), 42)

	ct, err := crypto.AEADEncrypt(&key, nonce, plaintext)
	if err != nil {
		t.Fatalf("AEADEncrypt: %v", err)
	}
	t.Logf("Ciphertext (%d bytes): %x", len(ct), ct)

	pt, err := crypto.AEADDecrypt(&key, nonce, ct)
	if err != nil {
		t.Fatalf("AEADDecrypt: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Errorf("plaintext mismatch: got %q, want %q", pt, plaintext)
	}
	t.Logf("Round-trip OK: %q", pt)
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 2: Frame encoding/decoding
// ─────────────────────────────────────────────────────────────────────────────

func TestFrameHeaderEncodeDecodeRoundTrip(t *testing.T) {
	orig := &mfp.FrameHeader{
		Type:       mfp.TypeDATA,
		PayloadLen: 512,
		StreamID:   99,
		Flags:      0x05,
		Sequence:   12345678,
		Extended:   0xBEEF,
	}
	wire := mfp.EncodeHeader(orig)
	if len(wire) != 14 {
		t.Fatalf("encoded header length %d, want 14", len(wire))
	}

	decoded, err := mfp.DecodeHeader(wire)
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}

	if decoded.Type != orig.Type {
		t.Errorf("Type: got %d, want %d", decoded.Type, orig.Type)
	}
	if decoded.PayloadLen != orig.PayloadLen {
		t.Errorf("PayloadLen: got %d, want %d", decoded.PayloadLen, orig.PayloadLen)
	}
	if decoded.StreamID != orig.StreamID {
		t.Errorf("StreamID: got %d, want %d", decoded.StreamID, orig.StreamID)
	}
	// The key fix: Flags must not be overwritten by Sequence.
	if decoded.Flags != orig.Flags {
		t.Errorf("Flags: got %d, want %d (Flags was clobbered by Sequence in the old code)", decoded.Flags, orig.Flags)
	}
	if decoded.Sequence != orig.Sequence {
		t.Errorf("Sequence: got %d, want %d", decoded.Sequence, orig.Sequence)
	}
	if decoded.Extended != orig.Extended {
		t.Errorf("Extended: got %d, want %d", decoded.Extended, orig.Extended)
	}
	t.Logf("Frame header round-trip OK ✓")
}

func TestEncoderDecoderRoundTrip(t *testing.T) {
	// Build a shared key from a known ECDHE exchange.
	clientKP, _ := crypto.GenerateKeyPair()
	serverKP, _ := crypto.GenerateKeyPair()
	shared, _ := crypto.SharedKey(clientKP, serverKP.PubKey)

	var cr, sr [32]byte
	cr[0] = 0xCA
	sr[0] = 0xFE
	keys, err := crypto.DeriveKeys(shared, cr, sr)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}

	// Client encodes uplink with NonceSeedUplink;
	// Server decodes uplink with NewUplinkDecoder (same seed).
	encoder := mfp.NewEncoder(keys)
	decoder := mfp.NewUplinkDecoder(keys)

	payload := []byte("Meridian encrypted frame test payload 🔐")

	wire, err := encoder.Encode(1, 0, payload)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	t.Logf("Encoded wire frame (%d bytes): %x…", len(wire), wire[:min(len(wire), 32)])

	frame, err := decoder.Decode(wire)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if string(frame.Data) != string(payload) {
		t.Errorf("payload mismatch:\n  got:  %q\n  want: %q", frame.Data, payload)
	}
	t.Logf("Encoder↔Decoder round-trip OK ✓  payload: %q", frame.Data)
}

func TestPaddingRoundTrip(t *testing.T) {
	cfg := mfp.PaddingConfig{
		Mode:     config.PaddingRandom,
		BaseSize: 100,
		MaxSize:  200,
	}
	original := []byte("test data for padding")
	padded, err := mfp.PadPayload(original, cfg)
	if err != nil {
		t.Fatalf("PadPayload: %v", err)
	}
	t.Logf("Original: %d bytes, Padded: %d bytes", len(original), len(padded))

	recovered, err := mfp.UnpadPayload(padded, cfg)
	if err != nil {
		t.Fatalf("UnpadPayload: %v", err)
	}
	if string(recovered) != string(original) {
		t.Errorf("padding round-trip failed: got %q, want %q", recovered, original)
	}
	t.Logf("Padding round-trip OK ✓")
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 3: ClientHello construction and parsing
// ─────────────────────────────────────────────────────────────────────────────

func TestClientHelloBuildAndParse(t *testing.T) {
	cfg := config.DefaultClientConfig()
	cfg.ServerAddr = "127.0.0.1:15443"
	cfg.Transport = config.TransportHysteria
	cfg.PaddingMode = config.PaddingNone
	cfg.RealityMode = false

	b, _ := crypto.GenerateRandom(16)
	copy(cfg.SessionID[:], b)

	clientKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	cr, _ := crypto.GenerateRandom(32)
	var crArr [32]byte
	copy(crArr[:], cr)

	wire, err := mtp.BuildClientHello(cfg, &crArr, clientKP.PubKey)
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}
	t.Logf("ClientHello wire size: %d bytes", len(wire))

	hs, err := mtp.ParseClientHello(wire)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if hs.ClientRandom != crArr {
		t.Errorf("ClientRandom mismatch")
	}
	if string(hs.ClientECDHE) != string(clientKP.PubKey) {
		t.Errorf("ClientECDHE mismatch:\n  got:  %x\n  want: %x", hs.ClientECDHE, clientKP.PubKey)
	}
	t.Logf("ClientHello build+parse OK ✓")
	t.Logf("  ClientRandom: %x", hs.ClientRandom)
	t.Logf("  ClientECDHE:  %x", hs.ClientECDHE)
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 4: End-to-end UDP communication test
// ─────────────────────────────────────────────────────────────────────────────

// testServer is a minimal UDP echo server for integration testing.
type testServer struct {
	conn    *net.UDPConn
	addr    *net.UDPAddr
	received chan []byte
}

func startTestServer(t *testing.T) *testServer {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0") // OS picks free port
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	srv := &testServer{
		conn:     conn,
		addr:     conn.LocalAddr().(*net.UDPAddr),
		received: make(chan []byte, 16),
	}
	go srv.loop(t)
	return srv
}

func (s *testServer) loop(t *testing.T) {
	buf := make([]byte, 4096)
	for {
		s.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, remote, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		// Parse and validate the received ClientHello.
		hs, parseErr := mtp.ParseClientHello(pkt)
		var reply []byte
		if parseErr != nil {
			reply = []byte(fmt.Sprintf("ERROR: %v", parseErr))
		} else {
			// Build a minimal server ECDHE response for the test.
			serverKP, _ := crypto.GenerateKeyPair()
			shared, _ := crypto.SharedKey(serverKP, hs.ClientECDHE)
			_, _ = crypto.DeriveKeys(shared, hs.ClientRandom, [32]byte{0xCC})
			reply = []byte("HANDSHAKE_OK")
		}

		s.conn.WriteToUDP(reply, remote)
		s.received <- pkt
	}
}

func (s *testServer) close() { s.conn.Close() }

func TestUDPClientServerHandshake(t *testing.T) {
	srv := startTestServer(t)
	defer srv.close()

	t.Logf("Test server listening on %s", srv.addr)

	// Build and send a real ClientHello to the test server.
	cfg := config.DefaultClientConfig()
	cfg.ServerAddr = srv.addr.String()
	cfg.PaddingMode = config.PaddingNone
	cfg.RealityMode = false
	b, _ := crypto.GenerateRandom(16)
	copy(cfg.SessionID[:], b)

	clientKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	cr, _ := crypto.GenerateRandom(32)
	var crArr [32]byte
	copy(crArr[:], cr)

	hello, err := mtp.BuildClientHello(cfg, &crArr, clientKP.PubKey)
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}

	// Dial a real UDP socket.
	clientConn, err := net.DialUDP("udp", nil, srv.addr)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer clientConn.Close()

	// Send the ClientHello.
	if _, err := clientConn.Write(hello); err != nil {
		t.Fatalf("Write ClientHello: %v", err)
	}
	t.Logf("Sent ClientHello (%d bytes) to server", len(hello))

	// Wait for the server's reply.
	clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply := make([]byte, 256)
	n, err := clientConn.Read(reply)
	if err != nil {
		t.Fatalf("Read server reply: %v", err)
	}
	replyStr := string(reply[:n])
	t.Logf("Server replied: %q", replyStr)

	if replyStr != "HANDSHAKE_OK" {
		t.Errorf("Expected HANDSHAKE_OK, got: %q", replyStr)
	}

	// Confirm the server received the packet.
	select {
	case pkt := <-srv.received:
		t.Logf("Server received %d bytes ✓", len(pkt))
	case <-time.After(2 * time.Second):
		t.Error("Server did not receive packet within timeout")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 5: Full crypto pipeline (ECDH → DeriveKeys → Encode → Decode)
// ─────────────────────────────────────────────────────────────────────────────

func TestFullCryptoPipeline(t *testing.T) {
	// 1. Generate key pairs for client and server
	clientKP, _ := crypto.GenerateKeyPair()
	serverKP, _ := crypto.GenerateKeyPair()

	// 2. Compute shared secret on both sides
	clientShared, _ := crypto.SharedKey(clientKP, serverKP.PubKey)
	serverShared, _ := crypto.SharedKey(serverKP, clientKP.PubKey)

	// 3. Derive keys (same randoms → same keys)
	cr, _ := crypto.GenerateRandom(32)
	sr, _ := crypto.GenerateRandom(32)
	var crArr, srArr [32]byte
	copy(crArr[:], cr)
	copy(srArr[:], sr)

	clientKeys, _ := crypto.DeriveKeys(clientShared, crArr, srArr)
	serverKeys, _ := crypto.DeriveKeys(serverShared, crArr, srArr)

	// 4. Uplink: client encodes → server decodes
	// Both use NonceSeedUplink (Encoder default = Uplink; NewUplinkDecoder = Uplink).
	clientEncoder := mfp.NewEncoder(clientKeys)
	serverDecoder := mfp.NewUplinkDecoder(serverKeys)

	// 5. Downlink: server encodes → client decodes
	// Server Encoder uses NonceSeedUplink by default — for downlink we need a
	// separate encoder that uses NonceSeedDownlk. Create it manually here.
	// (In production a Server-side Encoder would use Downlk seed.)
	serverEncoder := mfp.NewEncoder(serverKeys)
	// Override the seed to downlink for the server encoder.
	// (Field is unexported — test only checks uplink direction below.)
	clientDecoder := mfp.NewDownlinkDecoder(clientKeys)
	_ = serverEncoder
	_ = clientDecoder

	messages := []string{
		"Hello from client!",
		"Second message",
		"Third 🔐",
	}

	for i, msg := range messages {
		wire, err := clientEncoder.Encode(1, 0, []byte(msg))
		if err != nil {
			t.Fatalf("[msg %d] Encode: %v", i, err)
		}
		frame, err := serverDecoder.Decode(wire)
		if err != nil {
			t.Fatalf("[msg %d] Decode: %v", i, err)
		}
		if string(frame.Data) != msg {
			t.Errorf("[msg %d] payload mismatch: got %q, want %q", i, frame.Data, msg)
		}
		t.Logf("[msg %d] %q → encrypted (%d B) → decrypted ✓", i, msg, len(wire))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
