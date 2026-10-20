package mtp

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"meridian/pkg/config"
	"meridian/pkg/crypto"
)

func testClientConfig(password string) config.ClientConfig {
	cfg := config.DefaultClientConfig()
	cfg.Password = password
	cfg.SessionID = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	return cfg
}

// buildHello creates a ClientHello with real-looking ECDHE material.
func buildHello(t *testing.T, password string) ([]byte, *[32]byte, []byte) {
	t.Helper()
	cfg := testClientConfig(password)
	ek, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	rnd, err := crypto.GenerateRandom(32)
	if err != nil {
		t.Fatalf("GenerateRandom: %v", err)
	}
	var cr [32]byte
	copy(cr[:], rnd)

	hello, err := BuildClientHello(cfg, &cr, ek.PubKey, nil)
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}
	return hello, &cr, ek.PubKey
}

func TestClientHelloRoundTrip(t *testing.T) {
	hello, cr, pub := buildHello(t, "secret")

	hs, err := ParseClientHello(hello)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if !bytes.Equal(hs.ClientECDHE, pub) {
		t.Error("parsed ECDHE key differs from what was sent")
	}
	if hs.ClientRandom != *cr {
		t.Error("parsed client random differs from what was sent")
	}
	if hs.ClientID != [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16} {
		t.Errorf("unexpected client ID: %v", hs.ClientID)
	}
}

// TestAuthTagAccepted is the happy path: the server must accept a tag built
// from the same password, random, and key.
func TestAuthTagAccepted(t *testing.T) {
	hello, _, _ := buildHello(t, "correct-horse")
	hs, err := ParseClientHello(hello)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}

	ext := FindExtension(hs.Extensions, ExtAuth)
	if ext == nil {
		t.Fatal("auth extension missing from ClientHello")
	}
	if len(ext.Data) != AuthTagSize {
		t.Fatalf("auth tag length = %d, want %d", len(ext.Data), AuthTagSize)
	}

	if err := VerifyAuth(ext.Data, "correct-horse", &hs.ClientRandom, hs.ClientECDHE, time.Now()); err != nil {
		t.Errorf("valid auth tag rejected: %v", err)
	}
}

// TestAuthRejectsWrongPassword is the security-critical case: without this the
// server is an open proxy reachable by anyone who can route to the port.
func TestAuthRejectsWrongPassword(t *testing.T) {
	hello, _, _ := buildHello(t, "correct-horse")
	hs, err := ParseClientHello(hello)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	ext := FindExtension(hs.Extensions, ExtAuth)
	if ext == nil {
		t.Fatal("auth extension missing")
	}

	if err := VerifyAuth(ext.Data, "wrong-password", &hs.ClientRandom, hs.ClientECDHE, time.Now()); err == nil {
		t.Error("auth tag with wrong password was accepted")
	}
}

// TestAuthRejectsReplayInOtherSession binds the tag to the session material: a
// captured tag must not validate inside a different handshake.
func TestAuthRejectsReplayInOtherSession(t *testing.T) {
	_, cr, pub := buildHello(t, "pw")
	tag := AuthTag("pw", cr, pub, time.Now())

	// Same password, but a different random and key than the tag was bound to.
	otherRandom := [32]byte{9, 9, 9}
	otherKey := make([]byte, 32)
	if err := VerifyAuth(tag, "pw", &otherRandom, otherKey, time.Now()); err == nil {
		t.Error("tag replayed into a different session was accepted")
	}
}

// TestAuthRejectsStaleTimestamp guards the replay window.
func TestAuthRejectsStaleTimestamp(t *testing.T) {
	_, cr, pub := buildHello(t, "pw")
	stale := time.Now().Add(-24 * time.Hour)
	tag := AuthTag("pw", cr, pub, stale)

	if err := VerifyAuth(tag, "pw", cr, pub, time.Now()); err == nil {
		t.Error("stale auth tag was accepted")
	}
}

// TestAuthRejectsMalformed covers short/absent tags against a configured password.
func TestAuthRejectsMalformed(t *testing.T) {
	cr := [32]byte{1}
	pub := make([]byte, 32)

	if err := VerifyAuth(nil, "pw", &cr, pub, time.Now()); err == nil {
		t.Error("nil auth tag was accepted")
	}
	if err := VerifyAuth([]byte{1, 2, 3}, "pw", &cr, pub, time.Now()); err == nil {
		t.Error("short auth tag was accepted")
	}
}

// TestAuthNoPasswordKeepsWorking preserves the passwordless test environments.
func TestAuthNoPasswordKeepsWorking(t *testing.T) {
	if err := VerifyAuth(nil, "", &[32]byte{1}, make([]byte, 32), time.Now()); err != nil {
		t.Errorf("passwordless mode must stay open, got: %v", err)
	}
}

// TestAuthTagTimestampIsBigEndian pins the wire format.
func TestAuthTagTimestampIsBigEndian(t *testing.T) {
	cr := [32]byte{7}
	pub := make([]byte, 32)
	now := time.Unix(1700000000, 0)

	tag := AuthTag("pw", &cr, pub, now)
	if got := binary.BigEndian.Uint32(tag[0:4]); got != 1700000000 {
		t.Errorf("timestamp field = %d, want 1700000000", got)
	}
	if len(tag) != AuthTagSize {
		t.Errorf("tag length = %d, want %d", len(tag), AuthTagSize)
	}
}

func TestParseExtensionsIgnoresTrailingBytes(t *testing.T) {
	// A malformed trailing extension must not panic or break the walk.
	data := make([]byte, OffCiph+10)
	binary.BigEndian.PutUint16(data[OffCiph:OffCiph+2], 0x0001)
	binary.BigEndian.PutUint16(data[OffCiph+2:OffCiph+4], 100) // length beyond buffer
	// 4 bytes of HASH_TAG follow.
	data = append(data, 0, 0, 0, 0)

	exts := ParseExtensions(data, OffCiph)
	if len(exts) != 0 {
		t.Errorf("expected no well-formed extensions, got %d", len(exts))
	}
}
