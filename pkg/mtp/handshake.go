package mtp

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"

	"meridian/pkg/config"
	"meridian/pkg/crypto"
)

const (
	MagicValue = uint32(0xDeadBeEF)
	CurrentVer = 0x01
	FlagResume = byte(0x01)
	FlagWS     = byte(0x02)
	FlagPad    = byte(0x04)

	// Wire offsets within ClientHello (per spec §3.2)
	OffMagic  = 0
	OffVer    = 4
	OffFlags  = 5
	OffMTU    = 6
	OffCRand  = 8
	OffECDHE  = 40
	OffHash   = 72
	OffSID    = 104
	OffCiph   = 120
)

// Extension is a variable-length TLS-style extension.
type Extension struct {
	ID   uint16
	Data []byte
}

// Handshake holds the negotiated parameters for a single session.
type Handshake struct {
	ClientRandom     [32]byte
	ServerRandom     [32]byte
	ClientECDHE      []byte
	ServerECDHE      []byte
	ClientID         [16]byte
	ServerID         [16]byte
	NegotiatedCipher config.CipherID
	SessionLT        uint32
	Extensions       []Extension
	Keys             *crypto.KeyMaterial
	IsResume         bool
}

// GenerateKeyPair wraps crypto.GenerateKeyPair for callers that import mtp.
// Signature updated to return error following the crypto package change.
func GenerateKeyPair() (*crypto.KeyPair, error) { return crypto.GenerateKeyPair() }

// GenerateRandomBytes wraps crypto.GenerateRandom.
func GenerateRandomBytes(n int) ([]byte, error) { return crypto.GenerateRandom(n) }

// BuildClientHello constructs a wire-format ClientHello packet.
// Fix #5: writeExt was writing to out-of-bounds memory (buf.Bytes()[st:st+2]
// where st == buf.Len(), so the slice is beyond the current content).
// Now writeExt writes placeholder bytes into the buffer first, then backfills.
//
// Fix: ClientHello hash (offset 72) is SHA256(ciphers || clientRandom || clientECDHE)
// per spec §3.2, not SHA256(buf[120:end]).
func BuildClientHello(cfg config.ClientConfig, cr *[32]byte, pubECDHE []byte, resumeKeys *crypto.KeyMaterial) ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, 256))

	// Magic (4) + Version (1) + Flags (1) + ClientMTU (2) = 8 bytes
	binary.Write(buf, binary.BigEndian, MagicValue)
	buf.WriteByte(CurrentVer)
	flags := byte(0x00)
	if resumeKeys != nil {
		flags |= FlagResume
	}
	if cfg.Transport == config.TransportWebSocket {
		flags |= FlagWS
	}
	if cfg.PaddingMode == config.PaddingFixed {
		flags |= FlagPad
	}
	buf.WriteByte(flags)
	binary.Write(buf, binary.BigEndian, uint16(1452)) // ClientMTU

	// CLIENT_RANDOM (32) @ offset 8
	buf.Write(cr[:])

	// CLIENT_ECDHE (32) @ offset 40
	buf.Write(pubECDHE)

	// CLIENT_HASH (32) @ offset 72 — placeholder; filled in below.
	hashOffset := buf.Len() // = 72
	buf.Write(make([]byte, 32))

	// CLIENT_ID (16) @ offset 104
	buf.Write(cfg.SessionID[:])

	// CIPHERS @ offset 120 — hard-coded preference list (5 suites × 2 bytes ID)
	// Each entry here is just the 2-byte CIPHER_ID as a minimal implementation.
	cipherStart := buf.Len() // = 120
	buf.Write([]byte{
		0x00, 0x01, // MERIDIAN-CHACHA
		0x00, 0x02, // MERIDIAN-AES256
		0x00, 0x03, // MERIDIAN-AES128
		0x00, 0x04, // MERIDIAN-ARIA
		0x00, 0x05, // MERIDIAN-SM4
	})

	// EXTENSIONS
	writeExt(buf, 0x0001, extReal(cfg))
	writeExt(buf, 0x0004, extFP(cfg))
	writeExt(buf, 0x0002, extTr(cfg))
	writeExt(buf, 0x0006, extBW())

	// Back-fill CLIENT_HASH = SHA256(ciphers || clientRandom || clientECDHE)
	// per spec §3.2: "SHA256(CIPHERS || CLIENT_RANDOM || CLIENT_ECDHE)"
	hashInput := make([]byte, 0, len(buf.Bytes())-cipherStart+32+32)
	hashInput = append(hashInput, buf.Bytes()[cipherStart:]...) // ciphers + extensions
	hashInput = append(hashInput, cr[:]...)
	hashInput = append(hashInput, pubECDHE...)
	h := sha256.Sum256(hashInput)
	copy(buf.Bytes()[hashOffset:hashOffset+32], h[:])

	// HASH_TAG (4): SHA256(full message so far)[0:4]
	tag := sha256.Sum256(buf.Bytes())
	buf.Write(tag[:4])

	return buf.Bytes(), nil
}

// ParseClientHello deserialises the first fields of a ClientHello.
// Fix #3: previous code read data[OffECDHE] (a key byte) as the ECDHE length.
// X25519 public keys are always exactly 32 bytes; no dynamic length is needed.
func ParseClientHello(data []byte) (*Handshake, error) {
	const minLen = OffCiph + 4 // header + at least one cipher entry
	if len(data) < minLen {
		return nil, errors.New("mtp: ClientHello too short")
	}
	// Validate magic
	if binary.BigEndian.Uint32(data[OffMagic:OffMagic+4]) != MagicValue {
		return nil, errors.New("mtp: invalid magic")
	}
	// Validate version
	if data[OffVer] != CurrentVer {
		return nil, errors.New("mtp: unsupported version")
	}
	// Ensure the ECDHE field is present (32 bytes starting at offset 40)
	if len(data) < OffECDHE+crypto.ECDHKeyLen {
		return nil, errors.New("mtp: ClientHello too short for ECDHE key")
	}

	hs := &Handshake{}
	hs.IsResume = (data[OffFlags] & FlagResume) != 0
	copy(hs.ClientRandom[:], data[OffCRand:OffCRand+32])
	hs.ClientECDHE = make([]byte, crypto.ECDHKeyLen) // Fix: fixed 32 bytes, not data[40] length
	copy(hs.ClientECDHE, data[OffECDHE:OffECDHE+crypto.ECDHKeyLen])
	copy(hs.ClientID[:], data[OffSID:OffSID+16])
	hs.SessionLT = 3600 // default; server may override
	return hs, nil
}

// writeExt appends an extension (ID + length + data) to buf.
//
// Fix #5: previous implementation read buf.Bytes()[st:st+2] where st==buf.Len(),
// which is out of bounds — buf.Bytes() only covers [0, Len()), so index st is one
// past the end. The fix writes 4 placeholder bytes into the buffer first (making
// positions [st, st+4) valid), then backfills the length field after the data
// callback has appended its content.
func writeExt(buf *bytes.Buffer, extID uint16, fn func(*bytes.Buffer)) {
	// Write extID into the buffer (2 bytes now in bounds).
	var idBytes [2]byte
	binary.BigEndian.PutUint16(idBytes[:], extID)
	buf.Write(idBytes[:])

	// Write placeholder length (2 bytes); record its position for backfill.
	lenPos := buf.Len()
	buf.Write([]byte{0x00, 0x00})

	// Append extension data.
	dataStart := buf.Len()
	fn(buf)
	dataLen := buf.Len() - dataStart

	// Backfill length. buf.Bytes() now has content at lenPos because we wrote
	// placeholder bytes above.
	binary.BigEndian.PutUint16(buf.Bytes()[lenPos:lenPos+2], uint16(dataLen))
}

// extReal builds the REALITY_MODE extension (0x0001).
func extReal(cfg config.ClientConfig) func(*bytes.Buffer) {
	return func(b *bytes.Buffer) {
		sni := []byte(cfg.SNISpoof)
		binary.Write(b, binary.BigEndian, uint16(len(sni)))
		b.Write(sni)
		binary.Write(b, binary.BigEndian, uint16(443))
		b.Write(cfg.RealitySPKIHash)
		binary.Write(b, binary.BigEndian, cfg.RealityMaxTime)
		binary.Write(b, binary.BigEndian, cfg.RealityShortID)
	}
}

// extFP builds the FINGERPRINT extension (0x0004).
func extFP(cfg config.ClientConfig) func(*bytes.Buffer) {
	return func(b *bytes.Buffer) {
		switch cfg.Fingerprint {
		case config.FingerprintChromeWin:
			b.Write([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
		case config.FingerprintFirefoxMac:
			b.Write([]byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0})
		case config.FingerprintCurlLinux:
			b.Write([]byte{5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4})
		}
	}
}

// extTr builds the TRAFFIC_PROFILE extension (0x0002).
func extTr(cfg config.ClientConfig) func(*bytes.Buffer) {
	return func(b *bytes.Buffer) {
		m := byte(2) // random
		if cfg.PaddingMode == config.PaddingNone {
			m = 0
		}
		if cfg.PaddingMode == config.PaddingFixed {
			m = 1
		}
		b.WriteByte(m)
		binary.Write(b, binary.BigEndian, cfg.BasePayloadSize)
		binary.Write(b, binary.BigEndian, uint16(100))
	}
}

// extBW builds the BANDWIDTH_CONFIG extension (0x0006).
func extBW() func(*bytes.Buffer) {
	return func(b *bytes.Buffer) {
		binary.Write(b, binary.BigEndian, uint64(1_000_000_000)) // upload BPS
		binary.Write(b, binary.BigEndian, uint64(1_000_000_000)) // download BPS
		binary.Write(b, binary.BigEndian, uint16(30))            // adjust interval (s)
	}
}

// LoadCert is a convenience wrapper over tls.LoadX509KeyPair.
func LoadCert(cf, kf string) (tls.Certificate, error) { return tls.LoadX509KeyPair(cf, kf) }

// SPKIFromCert delegates to the crypto package.
func SPKIFromCert(certPath, keyPath string) ([]byte, error) {
	return crypto.SPKIFromCert(certPath, keyPath)
}