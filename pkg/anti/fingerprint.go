package anti

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// FingerprintSet defines the set of emulated TLS fingerprints.
type FingerprintSet struct {
	Name string
	// ClientHello bytes that match a specific real browser/client
	ClientHello []byte
	// fingerprints
	ServerHelloHash []byte
}

// Predefined fingerprints matching real TLS ClientHello.
var Fingerprints = map[string]FingerprintSet{
	"chrome_win": {
		Name: "chrome_win",
		// Placeholder: In production, this is the exact ClientHello from Chrome 120 on Windows 11
		ClientHello: []byte("chrome_120_win_clienthello_placeholder_01234567890abc"),
		ServerHelloHash: []byte("server_hello_hash_placeholder"),
	},
	"firefox_mac": {
		Name: "firefox_mac",
		ClientHello: []byte("firefox_121_mac_clienthello_placeholder_01234567890ab"),
		ServerHelloHash: []byte("server_hello_hash_placeholder_1234567890ab"),
	},
	"curl_linux": {
		Name: "curl_linux",
		ClientHello: []byte("curl_84_linux_clienthello_placeholder_0123456789ab"),
		ServerHelloHash: []byte("server_hello_hash_placeholder_1234567890ab"),
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
