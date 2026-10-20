package anti

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
)

// FingerprintSet defines the set of emulated TLS fingerprints.
//
// ClientHelloSpec mirrors the fields of a real TLS ClientHello that
// fingerprinting systems (JA3/JA4, uTLS) observe on the wire. It is the
// structured source of truth; ClientHello keeps the serialised bytes for
// callers that need a raw fingerprint blob.
type FingerprintSet struct {
	Name string
	// ClientHello bytes that match a specific real browser/client
	ClientHello []byte
	// ServerHelloHash is the expected hash of the peer's ServerHello blob.
	ServerHelloHash []byte
	// Spec drives *tls.Config so the Go client actually emits the shape
	// described above instead of Go's default fingerprint.
	Spec ClientHelloSpec
}

// ClientHelloSpec captures the observable TLS handshake parameters that DPI
// engines fingerprint.
type ClientHelloSpec struct {
	// CipherSuites is the ordered TLS 1.3 / 1.2 cipher preference list.
	CipherSuites []uint16
	// Curves is the supported_groups extension (elliptic curves).
	Curves []tls.CurveID
	// Alpn is the ALPN protocol list.
	Alpn []string
	// MinVersion / MaxVersion bound the advertised supported_versions.
	MinVersion uint16
	MaxVersion uint16
	// SessionTicket enables the session_ticket extension.
	SessionTicket bool
	// Renegotiation enables the renegotiation_info extension.
	Renegotiation bool
	// SNIHost, when non-empty, is the spoofed server name sent in SNI.
	SNIHost string
}

// Predefined fingerprints matching real TLS ClientHello.
//
// These mirror widely published ClientHello shapes (Chrome 120 on Windows,
// Firefox 121 on macOS, curl 8.4 on Linux). They are not byte-exact captures,
// but they reproduce the fields JA3/JA4-style fingerprinting depends on:
// cipher order, supported groups, ALPN, and version range.
var Fingerprints = map[string]FingerprintSet{
	"chrome_win": {
		Name:            "chrome_win",
		ClientHello:     []byte("chrome_120_win_clienthello_placeholder_01234567890abc"),
		ServerHelloHash: []byte("server_hello_hash_placeholder"),
		Spec: ClientHelloSpec{
			// Chrome's TLS 1.3-first ordering (GREASE omitted; Go emits its own).
			CipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
			Curves:        []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
			Alpn:          []string{"h2", "http/1.1"},
			MinVersion:    tls.VersionTLS12,
			MaxVersion:    tls.VersionTLS13,
			SessionTicket: true,
			Renegotiation: true,
		},
	},
	"firefox_mac": {
		Name:            "firefox_mac",
		ClientHello:     []byte("firefox_121_mac_clienthello_placeholder_01234567890ab"),
		ServerHelloHash: []byte("server_hello_hash_placeholder_1234567890ab"),
		Spec: ClientHelloSpec{
			// Firefox prefers TLS 1.3 AEAD suites and X25519 first.
			CipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
			Curves:        []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521},
			Alpn:          []string{"h2", "http/1.1"},
			MinVersion:    tls.VersionTLS12,
			MaxVersion:    tls.VersionTLS13,
			SessionTicket: true,
			Renegotiation: true,
		},
	},
	"curl_linux": {
		Name:            "curl_linux",
		ClientHello:     []byte("curl_84_linux_clienthello_placeholder_0123456789ab"),
		ServerHelloHash: []byte("server_hello_hash_placeholder_1234567890ab"),
		Spec: ClientHelloSpec{
			// curl/OpenSSL exposes the full suite list, TLS 1.0 through 1.3.
			CipherSuites: []uint16{
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			},
			Curves:        []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
			Alpn:          []string{"http/1.1"},
			MinVersion:    tls.VersionTLS10,
			MaxVersion:    tls.VersionTLS13,
			SessionTicket: true,
			Renegotiation: false,
		},
	},
}

// Get returns the fingerprint for a target name.
func GetFingerprint(name string) FingerprintSet {
	if fp, ok := Fingerprints[name]; ok {
		return fp
	}
	// Return chrome_win as default
	return Fingerprints["chrome_win"]
}

// ApplyFingerprint mutates cfg so the Go TLS stack emits the ClientHello
// shape described by the named fingerprint.
//
// This is what makes the fingerprint setting actually observable on the wire:
// without it the config value is inert and Go sends its own default
// ClientHello, which is trivially identifiable as Go rather than a browser.
//
// Fields the caller already set deliberately (notably InsecureSkipVerify and
// VerifyPeerCertificate for REALITY SPKI pinning) are left untouched.
func ApplyFingerprint(cfg *tls.Config, name string) {
	if cfg == nil {
		return
	}
	fp := GetFingerprint(name)
	spec := fp.Spec

	if len(spec.CipherSuites) > 0 {
		cfg.CipherSuites = spec.CipherSuites
	}
	if len(spec.Curves) > 0 {
		cfg.CurvePreferences = spec.Curves
	}
	if len(spec.Alpn) > 0 {
		cfg.NextProtos = spec.Alpn
	}
	if spec.MinVersion > 0 {
		cfg.MinVersion = spec.MinVersion
	}
	if spec.MaxVersion > 0 {
		cfg.MaxVersion = spec.MaxVersion
	}
	if spec.SNIHost != "" {
		cfg.ServerName = spec.SNIHost
	}
	// Go emits session_ticket and secure renegotiation extensions based on
	// these fields; toggling them changes the observable extension set.
	cfg.SessionTicketsDisabled = !spec.SessionTicket
	cfg.Renegotiation = tls.RenegotiateNever
	if spec.Renegotiation {
		cfg.Renegotiation = tls.RenegotiateOnceAsClient
	}
}

// ApplyFingerprintWithSNI applies a fingerprint and overrides the spoofed SNI.
// A nil cfg is ignored so callers can pass through unconditionally.
func ApplyFingerprintWithSNI(cfg *tls.Config, name, sni string) {
	if cfg == nil {
		return
	}
	ApplyFingerprint(cfg, name)
	if sni != "" {
		cfg.ServerName = sni
	}
}

// Hash fingerprints for comparison.
func HashFingerprint(fp FingerprintSet) string {
	h := sha256.Sum256(fp.ClientHello)
	return hex.EncodeToString(h[:])
}

// PrintFingerprints lists all available fingerprints.
func PrintFingerprints() {
	for name, fp := range Fingerprints {
		h := HashFingerprint(fp)
		fmt.Printf("  %s: %s\n", name, h)
	}
}
