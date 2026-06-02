package config

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// DebugMode enables verbose debug logging globally
var DebugMode bool = false

// CipherID identifies the encryption suite.
type CipherID uint16

const (
	CipherMeridianChacha CipherID = 0x0001 // ChaCha20-Poly1305 + Argon2id
	CipherMeridianAES256 CipherID = 0x0002 // AES-256-GCM + HKDF-SHA256
	CipherMeridianAES128 CipherID = 0x0003 // AES-128-GCM + HKDF-SHA256
	CipherMeridianARIA   CipherID = 0x0004 // ARIA-256-GCM + Argon2id
	CipherMeridianSM4    CipherID = 0x0005 // SM4-GCM + SM3-KDF
)

func (c CipherID) String() string {
	switch c {
	case CipherMeridianChacha:
		return "MERIDIAN-CHACHA"
	case CipherMeridianAES256:
		return "MERIDIAN-AES256"
	case CipherMeridianAES128:
		return "MERIDIAN-AES128"
	case CipherMeridianARIA:
		return "MERIDIAN-ARIA"
	case CipherMeridianSM4:
		return "MERIDIAN-SM4"
	default:
		return "UNKNOWN"
	}
}

// TransportType defines the transport layer.
type TransportType string

const (
	TransportQUIC     TransportType = "QUIC"
	TransportWebSocket TransportType = "WebSocket"
	TransportHTTPPOST  TransportType = "HTTP-POST"
)

// PaddingMode defines traffic padding strategy.
type PaddingMode string

const (
	PaddingNone  PaddingMode = "none"
	PaddingFixed PaddingMode = "fixed"
	PaddingRandom PaddingMode = "random"
)

// FingerprintTarget is a TLS fingerprint to emulate.
type FingerprintTarget string

const (
	FingerprintChromeWin FingerprintTarget = "chrome_win"
	FingerprintFirefoxMac FingerprintTarget = "firefox_mac"
	FingerprintCurlLinux FingerprintTarget = "curl_linux"
)

// ClientConfig is the client-side configuration.
type ClientConfig struct {
	ServerAddr       string            `yaml:"server_addr" json:"server_addr"`
	Transport        TransportType     `yaml:"transport" json:"transport"`
	CipherSuite      CipherID          `yaml:"cipher_suite" json:"cipher_suite"`
	Password         string            `yaml:"password" json:"-"` // excluded from JSON logging
	SessionID        [16]byte          `yaml:"-" json:"-"`       // auto-generated if empty

	// REALITY / SNI
	SNISpoof        string            `yaml:"sni_spoof" json:"sni_spoof"`
	RealityMode     bool              `yaml:"reality_mode" json:"reality_mode"`
	RealitySPKIHex  string            `yaml:"reality_spki" json:"reality_spki"`
	RealitySPKIHash []byte            `yaml:"-" json:"-"`
	RealityShortID  uint32            `yaml:"reality_short_id" json:"reality_short_id"`
	RealityMaxTime  uint64            `yaml:"reality_max_time" json:"reality_max_time"`
	ServerCertFile  string             `yaml:"server_cert" json:"server_cert"`
	ServerKeyFile   string             `yaml:"server_key" json:"server_key"`

	// Anti-detection
	Fingerprint    FingerprintTarget `yaml:"fingerprint" json:"fingerprint"`
	PaddingMode    PaddingMode       `yaml:"padding_mode" json:"padding_mode"`
	BasePayloadSize uint32           `yaml:"base_payload_size" json:"base_payload_size"`
	MaxPayloadSize  uint32           `yaml:"max_payload_size" json:"max_payload_size"`
	DirectionBalance bool            `yaml:"direction_balance" json:"direction_balance"`
	TimingJitterMS  float64          `yaml:"timing_jitter_ms" json:"timing_jitter_ms"`

	// Connection settings
	KeepaliveInterval time.Duration `yaml:"keepalive_interval" json:"keepalive_interval"`
	HandshakeTimeout  time.Duration `yaml:"handshake_timeout" json:"handshake_timeout"`
	StreamWindow      uint64        `yaml:"stream_window" json:"stream_window"`
	MaxConcurrentStream uint32      `yaml:"max_concurrent_streams" json:"max_concurrent_streams"`
	SessionLifetime   time.Duration `yaml:"session_lifetime" json:"session_lifetime"`
	DialTimeout       time.Duration `yaml:"dial_timeout" json:"dial_timeout"`

	// Local proxy settings (SOCKS/HTTP)
	ListenAddr      string `yaml:"listen_addr" json:"listen_addr"`
	ProxyProtocol   string `yaml:"proxy_protocol" json:"proxy_protocol"` // "socks5" or "http"

	// HTTP-POST mirror mode (when transport=HTTP-POST)
	UploadURL       string `yaml:"upload_url" json:"upload_url"`
	MirrorBoundary  string `yaml:"mirror_boundary" json:"mirror_boundary"`
	MirrorPath      string `yaml:"mirror_path" json:"mirror_path"`

	// WebSocket upgrade settings
	WSSPath string `yaml:"wss_path" json:"wss_path"`
}

// ServerConfig is the server-side configuration.
type ServerConfig struct {
	ListenAddr     string            `yaml:"listen_addr" json:"listen_addr"`
	Transport      TransportType     `yaml:"transport" json:"transport"`
	CipherSuite    CipherID          `yaml:"cipher_suite" json:"cipher_suite"`
	Password       string            `yaml:"password" json:"-"`
	WSSPath        string            `yaml:"wss_path" json:"wss_path"`

	// REALITY mode
	RealityMode     bool   `yaml:"reality_mode" json:"reality_mode"`
	ServerCertFile  string `yaml:"server_cert" json:"server_cert"`
	ServerKeyFile   string `yaml:"server_key" json:"server_key"`
	ServerSPKIHex   string `yaml:"server_spki" json:"server_spki"`
	ServerSPKIHash  []byte `yaml:"-" json:"-"`
	RealityShortID  uint32 `yaml:"reality_short_id" json:"reality_short_id"`
	RealityMaxTime  uint64 `yaml:"reality_max_time" json:"reality_max_time"`
	RealityEnabled  bool   `yaml:"reality_enabled" json:"reality_enabled"`

	// Target destinations (for proxy mode)
	// When traffic arrives, it's forwarded to these upstream destinations
	Destinations []DestinationConfig `yaml:"destinations" json:"destinations"`

	// Anti-detection
	Fingerprint     FingerprintTarget `yaml:"fingerprint" json:"fingerprint"`
	PaddingMode     PaddingMode       `yaml:"padding_mode" json:"padding_mode"`
	BasePayloadSize uint32            `yaml:"base_payload_size" json:"base_payload_size"`
	MaxPayloadSize  uint32            `yaml:"max_payload_size" json:"max_payload_size"`
	TimingJitterMS  float64           `yaml:"timing_jitter_ms" json:"timing_jitter_ms"`

	// Connection limits
	MaxClients       int           `yaml:"max_clients" json:"max_clients"`
	StreamWindow     uint64        `yaml:"stream_window" json:"stream_window"`
	KeepaliveInterval time.Duration `yaml:"keepalive_interval" json:"keepalive_interval"`
	HandshakeTimeout time.Duration `yaml:"handshake_timeout" json:"handshake_timeout"`
}

// DestinationConfig defines an upstream proxy destination.
type DestinationConfig struct {
	Name       string `yaml:"name" json:"name"`
	Addr       string `yaml:"addr" json:"addr"`
	Protocol   string `yaml:"protocol" json:"protocol"` // "direct", "socks5", "http"
	Username   string `yaml:"username" json:"username"`
	Password   string `yaml:"password" json:"-"`
	Rule       string `yaml:"rule" json:"rule"` // "all", "geosite:cn", etc.
	Priority   int    `yaml:"priority" json:"priority"`
}

// DefaultClientConfig returns sensible defaults.
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		Transport:         TransportQUIC,
		CipherSuite:       CipherMeridianChacha,
		SNISpoof:          "www.google.com",
		RealityMode:       true,
		Fingerprint:       FingerprintChromeWin,
		PaddingMode:       PaddingRandom,
		BasePayloadSize:   1400,
		MaxPayloadSize:    1452,
		DirectionBalance:  false,
		TimingJitterMS:    30.0,
		KeepaliveInterval: 30 * time.Second,
		HandshakeTimeout:  10 * time.Second,
		StreamWindow:      1048576, // 1MB
		MaxConcurrentStream: 100,
		SessionLifetime:   time.Hour,
		DialTimeout:       15 * time.Second,
		ListenAddr:       "127.0.0.1:1080",
		ProxyProtocol:    "socks5",
		WSSPath:          "/ws/",
		MirrorPath:       "/upload",
	}
}

// DefaultServerConfig returns sensible defaults.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		ListenAddr:       "0.0.0.0:443",
		Transport:        TransportQUIC,
		CipherSuite:      CipherMeridianChacha,
		RealityMode:      false,
		RealityEnabled:   false,
		Fingerprint:      FingerprintChromeWin,
		PaddingMode:      PaddingRandom,
		BasePayloadSize:  1400,
		MaxPayloadSize:   1452,
		TimingJitterMS:   30.0,
		MaxClients:       1000,
		StreamWindow:     1048576,
		KeepaliveInterval: 30 * time.Second,
		HandshakeTimeout:  10 * time.Second,
		Destinations: []DestinationConfig{
			{
				Name: "default",
				Addr: "127.0.0.1:8080",
				Protocol: "direct",
				Rule:     "all",
				Priority: 0,
			},
		},
	}
}

// LoadClientConfig reads a YAML/JSON config file and returns a ClientConfig.
// Fix #15: previous code silently ignored parse failures and returned defaults;
// now returns an error if both YAML and JSON parsing fail.
func LoadClientConfig(path string) (ClientConfig, error) {
	cfg := DefaultClientConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	// Try YAML first.
	if yamlErr := yaml.Unmarshal(data, &cfg); yamlErr != nil {
		// Fallback to JSON.
		if jsonErr := json.Unmarshal(data, &cfg); jsonErr != nil {
			return DefaultClientConfig(), fmt.Errorf(
				"config: failed to parse %q as YAML (%v) or JSON (%v)",
				path, yamlErr, jsonErr,
			)
		}
	}
	if cfg.RealitySPKIHex != "" {
		hash, err := hex.DecodeString(cfg.RealitySPKIHex)
		if err != nil {
			return cfg, fmt.Errorf("config: invalid reality_spki hex: %v", err)
		}
		cfg.RealitySPKIHash = hash
	}
	return cfg, nil
}

// LoadServerConfig reads a YAML/JSON config file and returns a ServerConfig.
// Fix #15: same as LoadClientConfig — errors are now propagated.
func LoadServerConfig(path string) (ServerConfig, error) {
	cfg := DefaultServerConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if yamlErr := yaml.Unmarshal(data, &cfg); yamlErr != nil {
		if jsonErr := json.Unmarshal(data, &cfg); jsonErr != nil {
			return DefaultServerConfig(), fmt.Errorf(
				"config: failed to parse %q as YAML (%v) or JSON (%v)",
				path, yamlErr, jsonErr,
			)
		}
	}
	if cfg.ServerSPKIHex != "" {
		hash, err := hex.DecodeString(cfg.ServerSPKIHex)
		if err != nil {
			return cfg, fmt.Errorf("config: invalid server_spki hex: %v", err)
		}
		cfg.ServerSPKIHash = hash
	}
	return cfg, nil
}
