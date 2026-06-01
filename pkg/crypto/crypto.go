package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	Magic          = uint32(0xDeadBeEF)
	CurrentVersion = 0x01
	HashLen        = 32
	RandomLen      = 32
	SessionLen     = 16
	KeyLen         = 32
	MACLen         = 32
	NonceLen       = 12
	TagLen         = 16
	ECDHKeyLen     = 32
	NonceSeedLen   = 16
)

var (
	ErrHandshakeHashMismatch = errors.New("handshake hash mismatch")
	ErrInvalidCipherSuite    = errors.New("unsupported cipher suite")
)

// KeyPair holds an X25519 key pair.
type KeyPair struct {
	PrivKey []byte
	PubKey  []byte
}

// GenerateKeyPair creates a new X25519 ephemeral key pair.
// Fix #17: was returning a hardcoded placeholder; now uses golang.org/x/crypto/curve25519.
func GenerateKeyPair() (*KeyPair, error) {
	priv := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(priv); err != nil {
		return nil, fmt.Errorf("crypto: failed to generate private key: %w", err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("crypto: X25519 public key derivation failed: %w", err)
	}
	return &KeyPair{PrivKey: priv, PubKey: pub}, nil
}

// SharedKey performs X25519 ECDH to compute the shared secret.
// Fix #17: was returning an unimplemented error; now uses golang.org/x/crypto/curve25519.
func SharedKey(priv *KeyPair, pub []byte) ([]byte, error) {
	if len(pub) != curve25519.PointSize {
		return nil, fmt.Errorf("crypto: invalid peer public key length %d (want %d)", len(pub), curve25519.PointSize)
	}
	shared, err := curve25519.X25519(priv.PrivKey, pub)
	if err != nil {
		return nil, fmt.Errorf("crypto: X25519 shared key computation failed: %w", err)
	}
	return shared, nil
}

// KeyMaterial holds all session keys derived from ECDHE.
type KeyMaterial struct {
	TrafficEncKey   [KeyLen]byte
	TrafficMACKey   [KeyLen]byte
	NonceSeedUplink [NonceSeedLen]byte
	NonceSeedDownlk [NonceSeedLen]byte
	InitKey         [KeyLen]byte
}

// DeriveKeys derives session key material from the shared ECDHE secret and randoms.
// Total bytes required: KeyLen*2 + NonceSeedLen*2 + KeyLen = 128 bytes.
// Fix #16: previous code requested KeyLen*4+NonceSeedLen*2+KeyLen (192 bytes), which is wrong.
func DeriveKeys(sharedSecret []byte, clientRandom, serverRandom [RandomLen]byte) (*KeyMaterial, error) {
	ms := hkdfExpand(sha256.New, sharedSecret, append(clientRandom[:], serverRandom[:]...), []byte("meridian-master"), KeyLen)
	const totalLen = KeyLen*2 + NonceSeedLen*2 + KeyLen // 128 bytes
	kb := hkdfExpand(sha256.New, ms, nil, []byte("meridian-keys"), totalLen)

	keys := &KeyMaterial{}
	offset := 0
	copy(keys.TrafficEncKey[:], kb[offset:offset+KeyLen])
	offset += KeyLen
	copy(keys.TrafficMACKey[:], kb[offset:offset+KeyLen])
	offset += KeyLen
	copy(keys.NonceSeedUplink[:], kb[offset:offset+NonceSeedLen])
	offset += NonceSeedLen
	copy(keys.NonceSeedDownlk[:], kb[offset:offset+NonceSeedLen])
	offset += NonceSeedLen
	copy(keys.InitKey[:], kb[offset:offset+KeyLen])
	return keys, nil
}

// ComputeHandshakeHash computes the handshake transcript hash for MITM prevention.
func ComputeHandshakeHash(cipherListBytes []byte, clientRandom, serverRandom [RandomLen]byte, clientECDHE, serverECDHE []byte) [HashLen]byte {
	h := sha256.New()
	h.Write(cipherListBytes)
	h.Write(clientRandom[:])
	h.Write(clientECDHE)
	h.Write(serverRandom[:])
	h.Write(serverECDHE)
	var result [HashLen]byte
	h.Sum(result[:0])
	return result
}

// ComputeHashTag returns the first 4 bytes of SHA-256(data) for quick integrity check.
func ComputeHashTag(data []byte) [4]byte {
	h := sha256.Sum256(data)
	return [4]byte{h[0], h[1], h[2], h[3]}
}

// AEADEncrypt encrypts plaintext with ChaCha20-Poly1305.
func AEADEncrypt(key *[KeyLen]byte, nonce *[NonceLen]byte, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce[:], plaintext, nil), nil
}

// AEADDecrypt decrypts ciphertext with ChaCha20-Poly1305.
func AEADDecrypt(key *[KeyLen]byte, nonce *[NonceLen]byte, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce[:], ciphertext, nil)
}

// GenerateNonce derives a 12-byte nonce from a 16-byte seed and a 64-bit counter.
// Fix #7: previous code only set cb[0] and cb[7], leaving cb[1]–cb[6] as zero.
// Now uses binary.BigEndian.PutUint64 to correctly encode all 8 counter bytes.
func GenerateNonce(seed *[NonceSeedLen]byte, counter uint64) *[NonceLen]byte {
	h := sha256.New()
	cb := make([]byte, 8)
	binary.BigEndian.PutUint64(cb, counter) // Fix: all 8 bytes
	h.Write(seed[:])
	h.Write(cb)
	sum := h.Sum(nil)
	var nonce [NonceLen]byte
	copy(nonce[:], sum[:NonceLen])
	return &nonce
}

// VerifyHandshakeHash compares two handshake hashes in constant time.
func VerifyHandshakeHash(computed, expected [HashLen]byte) bool {
	return subtle.ConstantTimeCompare(computed[:], expected[:]) == 1
}

// HMAC256 computes HMAC-SHA256.
func HMAC256(key []byte, data []byte) [32]byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	var result [32]byte
	h.Sum(result[:0])
	return result
}

// GenerateRandom returns n cryptographically random bytes.
// Fix #4: previous code called rand.Read(b) and discarded the error, which means
// a failure would silently return all-zero bytes — a critical security vulnerability.
func GenerateRandom(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("crypto: rand.Read failed: %w", err)
	}
	return b, nil
}

func hkdfExpand(h func() hash.Hash, ikm []byte, salt []byte, label []byte, keyLen int) []byte {
	reader := hkdf.New(h, ikm, salt, label)
	key := make([]byte, keyLen)
	if _, err := reader.Read(key); err != nil {
		// hkdf.Read only returns an error when keyLen > 255*hashLen (~8KB), which we never reach.
		panic(fmt.Sprintf("hkdf.Read: unexpected error: %v", err))
	}
	return key
}

// SPKIHash reads a PEM-encoded certificate file and returns SHA-256(SubjectPublicKeyInfo DER).
// Fix #8: previous implementation hashed the raw file bytes (PEM text), not the SPKI structure.
func SPKIHash(certPath string) ([]byte, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("crypto: failed to decode PEM block in cert file")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to parse certificate: %w", err)
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(parsed.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to marshal SPKI: %w", err)
	}
	h := sha256.Sum256(spkiDER)
	return h[:], nil
}

// LoadCert loads a TLS certificate + key pair from PEM files.
func LoadCert(certFile, keyFile string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(certFile, keyFile)
}

// SPKIFromCert loads a cert+key pair and returns SHA-256(SPKI DER) of the leaf certificate.
// Fix #8: previous code called LoadX509KeyPair(certPath, certPath) — using the cert as both
// cert and key, which would always fail or return garbage. Now takes separate cert/key paths.
func SPKIFromCert(certPath, keyPath string) ([]byte, error) {
	cert, err := LoadCert(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	if len(cert.Certificate) == 0 {
		return nil, errors.New("crypto: no certificate in key pair")
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to parse certificate: %w", err)
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(parsed.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to marshal SPKI: %w", err)
	}
	h := sha256.Sum256(spkiDER)
	return h[:], nil
}
