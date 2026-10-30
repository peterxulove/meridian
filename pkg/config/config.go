package config

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
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
	TransportHysteria  TransportType = "QUIC"
	TransportWebSocket TransportType = "WebSocket"
	TransportHybrid    TransportType = "QUIC+WebSocket"
	TransportHTTPPOST  TransportType = "HTTP-POST"
)

// PaddingMode defines traffic padding strategy.
type PaddingMode string

const (
	PaddingNone   PaddingMode = "none"
	PaddingFixed  PaddingMode = "fixed"
	PaddingRandom PaddingMode = "random"
)

// FingerprintTarget is a TLS fingerprint to emulate.
type FingerprintTarget string

const (
	FingerprintChromeWin  FingerprintTarget = "chrome_win"
	FingerprintFirefoxMac FingerprintTarget = "firefox_mac"
	FingerprintCurlLinux  FingerprintTarget = "curl_linux"
)

// ClientConfig is the client-side configuration.
type ClientConfig struct {
	ServerAddr  string        `yaml:"server_addr" json:"server_addr"`
	Transport   TransportType `yaml:"transport" json:"transport"`
	CipherSuite CipherID      `yaml:"cipher_suite" json:"cipher_suite"`
	Password    string        `yaml:"password" json:"-"` // excluded from JSON logging
	SessionID   [16]byte      `yaml:"-" json:"-"`        // auto-generated if empty

	// REALITY / SNI
	SNISpoof        string `yaml:"sni_spoof" json:"sni_spoof"`
	RealityMode     bool   `yaml:"reality_mode" json:"reality_mode"`
	RealitySPKIHex  string `yaml:"reality_spki" json:"reality_spki"`
	RealitySPKIHash []byte `yaml:"-" json:"-"`
	RealityShortID  uint32 `yaml:"reality_short_id" json:"reality_short_id"`
	RealityMaxTime  uint64 `yaml:"reality_max_time" json:"reality_max_time"`
	ServerCertFile  string `yaml:"server_cert" json:"server_cert"`
	ServerKeyFile   string `yaml:"server_key" json:"server_key"`

	// Anti-detection
	Fingerprint      FingerprintTarget `yaml:"fingerprint" json:"fingerprint"`
	PaddingMode      PaddingMode       `yaml:"padding_mode" json:"padding_mode"`
	BasePayloadSize  uint32            `yaml:"base_payload_size" json:"base_payload_size"`
	MaxPayloadSize   uint32            `yaml:"max_payload_size" json:"max_payload_size"`
	DirectionBalance bool              `yaml:"direction_balance" json:"direction_balance"`
	TimingJitterMS   float64           `yaml:"timing_jitter_ms" json:"timing_jitter_ms"`

	// Connection settings
	KeepaliveInterval   time.Duration `yaml:"keepalive_interval" json:"keepalive_interval"`
	HandshakeTimeout    time.Duration `yaml:"handshake_timeout" json:"handshake_timeout"`
	StreamWindow        uint64        `yaml:"stream_window" json:"stream_window"`
	MaxConcurrentStream uint32        `yaml:"max_concurrent_streams" json:"max_concurrent_streams"`
	// TunnelConnections is the number of independent outer transports. A
	// single TCP/QUIC stream is BDP-limited, so multiplexing every user stream
	// onto one outer connection caps aggregate throughput. Deploying several
	// lanes and distributing streams across them removes that bottleneck.
	TunnelConnections int           `yaml:"tunnel_connections" json:"tunnel_connections"`
	SessionLifetime   time.Duration `yaml:"session_lifetime" json:"session_lifetime"`
	DialTimeout       time.Duration `yaml:"dial_timeout" json:"dial_timeout"`

	// Hysteria v2
	UpMbps   uint64 `yaml:"up_mbps" json:"up_mbps"`
	DownMbps uint64 `yaml:"down_mbps" json:"down_mbps"`

	// Local proxy settings (SOCKS/HTTP)
	ListenAddr    string `yaml:"listen_addr" json:"listen_addr"`
	ProxyProtocol string `yaml:"proxy_protocol" json:"proxy_protocol"` // "socks5" or "http"

	// HTTP-POST mirror mode (when transport=HTTP-POST)
	UploadURL      string `yaml:"upload_url" json:"upload_url"`
	MirrorBoundary string `yaml:"mirror_boundary" json:"mirror_boundary"`
	MirrorPath     string `yaml:"mirror_path" json:"mirror_path"`

	// WebSocket upgrade settings
	WSSPath string `yaml:"wss_path" json:"wss_path"`

	// TransportSchedule switches the outer transport on a daily local-time
	// schedule. The first entry whose window contains the current time wins;
	// outside every window Transport is used. Windows may wrap around
	// midnight, for example "19:00" to "03:00".
	TransportSchedule []TransportWindow `yaml:"transport_schedule" json:"transport_schedule"`

	// ScheduleTimezone pins the clock the schedule is evaluated against. An
	// empty value uses the system local zone, which is wrong on routers whose
	// /etc/localtime is missing or unreadable (Go then silently falls back to
	// UTC). Accepts an IANA name ("Asia/Shanghai") or a fixed offset
	// ("UTC+8", "+08:00", "GMT-5").
	ScheduleTimezone string `yaml:"schedule_timezone" json:"schedule_timezone"`

	RenewalInterval  time.Duration `yaml:"renewal_interval" json:"renewal_interval"`
	RenewalDataLimit uint64        `yaml:"renewal_data_limit" json:"renewal_data_limit"`

	// StreamIdleTimeout is how long a stream may carry no byte in either
	// direction before it becomes a candidate for reclamation. A player that
	// abandons a connection without closing its socket leaves a half-dead
	// stream holding a slot; enough of them and every new connection is
	// refused while the tunnel still looks healthy.
	//
	// Being a candidate is not enough to be closed: the reaper only acts when
	// the lane is near its stream cap (see reapIdle). A paused video and a
	// forgotten socket are indistinguishable from the byte stream alone, so
	// the client must not throw streams away while it has room to keep them.
	// Zero disables reclamation.
	StreamIdleTimeout time.Duration `yaml:"stream_idle_timeout" json:"stream_idle_timeout"`

	// MaxPendingDials bounds how many streams on one lane may be waiting for
	// the server to finish dialling the target. A connection storm otherwise
	// sends hundreds of dials at once, the server queues them all, and the
	// slowest ones time out — which looks like a dead proxy. Extra dials wait
	// for a slot instead of failing outright. Zero disables the cap.
	MaxPendingDials int `yaml:"max_pending_dials" json:"max_pending_dials"`

	// QUICFallbackFailures is how many QUIC attempts in a row may fail before
	// the lane parks itself on WebSocket for a while. A path that drops every
	// QUIC handshake recovers in seconds on the alternative, but retrying the
	// blocked transport is the one thing that cannot work; the two transports
	// share the port, so the switch costs nothing but a dial. Zero disables
	// the fallback, which is what a deployment that must stay on QUIC wants.
	QUICFallbackFailures int `yaml:"quic_fallback_failures" json:"quic_fallback_failures"`

	// QUICFallbackHold is how long a lane stays on WebSocket before it tries
	// QUIC again. It doubles on each consecutive trip (capped at an hour) so a
	// path that is blocked for the evening is not re-probed every ten minutes,
	// and it is forgotten as soon as a QUIC connection carries traffic again.
	QUICFallbackHold time.Duration `yaml:"quic_fallback_hold" json:"quic_fallback_hold"`

	// QUICFallbackMinUptime is how long a QUIC connection must survive to
	// count as proof the transport works. A handshake that succeeds and dies
	// immediately is a failure like any other — that is exactly what a blocked
	// or throttled UDP path looks like — so it must also drive the fallback
	// instead of resetting the streak.
	QUICFallbackMinUptime time.Duration `yaml:"quic_fallback_min_uptime" json:"quic_fallback_min_uptime"`

	// Local logging. LogFile empty keeps the historical behaviour: everything
	// goes to stdout, which procd/syslog captures. A path tees the same lines
	// into a size-rotated file so a burst of errors cannot evict the evidence
	// (the router's syslog ring is only a few dozen KiB).
	LogFile       string `yaml:"log_file" json:"log_file"`
	LogRotateSize uint64 `yaml:"log_rotate_size" json:"log_rotate_size"`
	LogRotateKeep int    `yaml:"log_rotate_keep" json:"log_rotate_keep"`
	// LogTimezone decides which clock the log timestamps use. Empty falls back
	// to schedule_timezone, then to the system zone. A router whose
	// /etc/localtime is missing logs in UTC while its neighbour logs in
	// UTC+8, which makes correlating two boxes during an incident guesswork.
	LogTimezone string `yaml:"log_timezone" json:"log_timezone"`
	// LogVerbose logs one line per proxied connection. Per-minute counters are
	// always logged, so this is only for packet-level forensics.
	LogVerbose bool `yaml:"log_verbose" json:"log_verbose"`
}

// TransportWindow is one entry of a daily transport schedule.
type TransportWindow struct {
	Transport TransportType `yaml:"transport" json:"transport"`
	From      string        `yaml:"from" json:"from"` // "HH:MM", local time
	To        string        `yaml:"to" json:"to"`     // "HH:MM", local time
}

// CompiledTransportWindow is a TransportWindow with its times parsed once at
// start-up, so the supervisor loop can test it every second cheaply.
type CompiledTransportWindow struct {
	Transport TransportType
	From, To  int // minutes since local midnight
}

// Contains reports whether t falls inside the window. A window whose end is
// not after its start wraps around midnight.
func (w CompiledTransportWindow) Contains(t time.Time) bool {
	m := t.Hour()*60 + t.Minute()
	if w.From < w.To {
		return m >= w.From && m < w.To
	}
	return m >= w.From || m < w.To
}

// CompileTransportSchedule validates and parses the configured windows. An
// invalid entry is a start-up error rather than a silent fallback: a typo in
// the schedule would otherwise keep the client on the wrong transport for a
// whole day.
func CompileTransportSchedule(windows []TransportWindow) ([]CompiledTransportWindow, error) {
	out := make([]CompiledTransportWindow, 0, len(windows))
	for i, w := range windows {
		switch w.Transport {
		case TransportHysteria, TransportWebSocket:
		default:
			return nil, fmt.Errorf("transport_schedule[%d]: unsupported client transport %q (use QUIC or WebSocket)", i, w.Transport)
		}
		from, err := parseClock(w.From)
		if err != nil {
			return nil, fmt.Errorf("transport_schedule[%d].from: %w", i, err)
		}
		to, err := parseClock(w.To)
		if err != nil {
			return nil, fmt.Errorf("transport_schedule[%d].to: %w", i, err)
		}
		if from == to {
			return nil, fmt.Errorf("transport_schedule[%d]: from and to are the same (%s)", i, w.From)
		}
		out = append(out, CompiledTransportWindow{Transport: w.Transport, From: from, To: to})
	}
	return out, nil
}

func parseClock(s string) (int, error) {
	var h, m int
	if _, err := fmt.Sscanf(s, "%d:%d", &h, &m); err != nil {
		return 0, fmt.Errorf("invalid time %q (want HH:MM)", s)
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, fmt.Errorf("invalid time %q", s)
	}
	return h*60 + m, nil
}

// offsetPattern matches fixed UTC offsets: "UTC+8", "UTC+08:00", "+08:00",
// "-0700". The sign is the real direction (UTC+8 is eight hours ahead).
var offsetPattern = regexp.MustCompile(`^(?i:(?:UTC|GMT))?([+-])(\d{1,2})(?::?(\d{2}))?$`)

// LoadScheduleLocation resolves the zone used to evaluate transport_schedule.
// It never silently falls back: a typo would otherwise move the switch by
// hours, which is exactly the class of bug this option exists to avoid.
func LoadScheduleLocation(name string) (*time.Location, error) {
	name = strings.TrimSpace(name)
	if name == "" || strings.EqualFold(name, "Local") {
		return time.Local, nil
	}
	if m := offsetPattern.FindStringSubmatch(name); m != nil {
		hours, err := strconv.Atoi(m[2])
		if err != nil || hours > 14 {
			return nil, fmt.Errorf("invalid schedule_timezone %q", name)
		}
		minutes := 0
		if m[3] != "" {
			minutes, err = strconv.Atoi(m[3])
			if err != nil || minutes > 59 {
				return nil, fmt.Errorf("invalid schedule_timezone %q", name)
			}
		}
		offset := hours*3600 + minutes*60
		if m[1] == "-" {
			offset = -offset
		}
		return time.FixedZone(name, offset), nil
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, fmt.Errorf("schedule_timezone %q: %w (use an IANA name or a fixed offset such as UTC+8)", name, err)
	}
	return loc, nil
}

// ServerConfig is the server-side configuration.
type ServerConfig struct {
	ListenAddr  string        `yaml:"listen_addr" json:"listen_addr"`
	Transport   TransportType `yaml:"transport" json:"transport"`
	CipherSuite CipherID      `yaml:"cipher_suite" json:"cipher_suite"`
	Password    string        `yaml:"password" json:"-"`
	WSSPath     string        `yaml:"wss_path" json:"wss_path"`

	// FallbackURL is where the WebSocket listener sends everything that is not
	// a tunnel upgrade. An endpoint that answers 404 to a plain GET confirms
	// itself to an active prober in one request; proxying to a real site makes
	// the port answer like that site instead. Empty keeps the old 404.
	FallbackURL string `yaml:"fallback_url" json:"fallback_url"`
	// FallbackSNI is the TLS name to verify when FallbackURL points at a
	// loopback address but the cover site's certificate names a domain.
	FallbackSNI string `yaml:"fallback_sni" json:"fallback_sni"`

	// HTTP-POST mirror mode: the path the client uploads frames to.
	MirrorPath string `yaml:"mirror_path" json:"mirror_path"`

	// REALITY mode
	RealityMode    bool   `yaml:"reality_mode" json:"reality_mode"`
	ServerCertFile string `yaml:"server_cert" json:"server_cert"`
	ServerKeyFile  string `yaml:"server_key" json:"server_key"`
	ServerSPKIHex  string `yaml:"server_spki" json:"server_spki"`
	ServerSPKIHash []byte `yaml:"-" json:"-"`
	RealityShortID uint32 `yaml:"reality_short_id" json:"reality_short_id"`
	RealityMaxTime uint64 `yaml:"reality_max_time" json:"reality_max_time"`
	RealityEnabled bool   `yaml:"reality_enabled" json:"reality_enabled"`

	// Target destinations (for proxy mode)
	// When traffic arrives, it's forwarded to these upstream destinations
	Destinations []DestinationConfig `yaml:"destinations" json:"destinations"`

	// Anti-detection
	Fingerprint     FingerprintTarget `yaml:"fingerprint" json:"fingerprint"`
	PaddingMode     PaddingMode       `yaml:"padding_mode" json:"padding_mode"`
	BasePayloadSize uint32            `yaml:"base_payload_size" json:"base_payload_size"`
	MaxPayloadSize  uint32            `yaml:"max_payload_size" json:"max_payload_size"`
	TimingJitterMS  float64           `yaml:"timing_jitter_ms" json:"timing_jitter_ms"`
	// DirectionBalance injects dummy frames when traffic is asymmetric. The
	// client drives this decision; the server mirrors the setting so both
	// sides agree on the wire format.
	DirectionBalance bool `yaml:"direction_balance" json:"direction_balance"`

	// Connection limits
	MaxClients          int           `yaml:"max_clients" json:"max_clients"`
	StreamWindow        uint64        `yaml:"stream_window" json:"stream_window"`
	MaxConcurrentStream uint32        `yaml:"max_concurrent_streams" json:"max_concurrent_streams"`
	KeepaliveInterval   time.Duration `yaml:"keepalive_interval" json:"keepalive_interval"`
	HandshakeTimeout    time.Duration `yaml:"handshake_timeout" json:"handshake_timeout"`

	// Hysteria v2
	UpMbps   uint64 `yaml:"up_mbps" json:"up_mbps"`
	DownMbps uint64 `yaml:"down_mbps" json:"down_mbps"`

	RenewalInterval  time.Duration `yaml:"renewal_interval" json:"renewal_interval"`
	RenewalDataLimit uint64        `yaml:"renewal_data_limit" json:"renewal_data_limit"`
}

// DestinationConfig defines an upstream proxy destination.
type DestinationConfig struct {
	Name     string `yaml:"name" json:"name"`
	Addr     string `yaml:"addr" json:"addr"`
	Protocol string `yaml:"protocol" json:"protocol"` // "direct", "socks5", "http"
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"-"`
	Rule     string `yaml:"rule" json:"rule"` // "all", "geosite:cn", etc.
	Priority int    `yaml:"priority" json:"priority"`
}

// DefaultClientConfig returns sensible defaults.
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		Transport:           TransportHysteria,
		CipherSuite:         CipherMeridianChacha,
		SNISpoof:            "www.google.com",
		RealityMode:         true,
		Fingerprint:         FingerprintChromeWin,
		PaddingMode:         PaddingRandom,
		BasePayloadSize:     1400,
		MaxPayloadSize:      1452,
		DirectionBalance:    false,
		TimingJitterMS:      0.0,
		KeepaliveInterval:   30 * time.Second,
		HandshakeTimeout:    10 * time.Second,
		StreamWindow:        DefaultStreamWindow,
		MaxConcurrentStream: DefaultMaxConcurrentStreams,
		TunnelConnections:   1,
		SessionLifetime:     time.Hour,
		DialTimeout:         15 * time.Second,
		ListenAddr:          "127.0.0.1:1080",
		ProxyProtocol:       "socks5",
		WSSPath:             "/ws/",
		MirrorPath:          "/upload",
		// Zero selects Hysteria's adaptive BBR path. A hardcoded optimistic
		// rate switches it to Brutal, which overshoots unknown links and can be
		// slower than BBR; explicit caps remain available for known links.
		UpMbps:           0,
		DownMbps:         0,
		RenewalInterval:  5 * time.Minute,
		RenewalDataLimit: 67108864, // 64MB
		// Ten minutes is long enough that a browser's idle keep-alive socket
		// survives, and short enough that abandoned streams free their slots
		// within one playback session.
		StreamIdleTimeout:     DefaultStreamIdleTimeout,
		MaxPendingDials:       DefaultMaxPendingDials,
		QUICFallbackFailures:  DefaultQUICFallbackFailures,
		QUICFallbackHold:      DefaultQUICFallbackHold,
		QUICFallbackMinUptime: DefaultQUICFallbackMinUptime,
		LogRotateSize:         DefaultLogRotateSize,
		LogRotateKeep:         DefaultLogRotateKeep,
	}
}

// DefaultServerConfig returns sensible defaults.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		ListenAddr:          "0.0.0.0:443",
		Transport:           TransportHysteria,
		CipherSuite:         CipherMeridianChacha,
		RealityMode:         false,
		RealityEnabled:      false,
		Fingerprint:         FingerprintChromeWin,
		PaddingMode:         PaddingRandom,
		BasePayloadSize:     1400,
		MaxPayloadSize:      1452,
		TimingJitterMS:      0.0,
		MaxClients:          1000,
		StreamWindow:        DefaultStreamWindow,
		MaxConcurrentStream: DefaultMaxConcurrentStreams,
		KeepaliveInterval:   30 * time.Second,
		HandshakeTimeout:    10 * time.Second,
		Destinations: []DestinationConfig{
			{
				Name:     "default",
				Addr:     "127.0.0.1:8080",
				Protocol: "direct",
				Rule:     "all",
				Priority: 0,
			},
		},
		UpMbps:           0,
		DownMbps:         0,
		RenewalInterval:  5 * time.Minute,
		RenewalDataLimit: 67108864, // 64MB
	}
}

// Tuning limits shared by both roles.
const (
	// FrameSizeHint is the largest DATA payload the mux emits (60 KiB). It is
	// the unit used to turn a byte budget into a per-stream queue depth.
	FrameSizeHint = 60 * 1024

	// DefaultStreamWindow is the number of unacknowledged bytes one stream may
	// have in flight. It is the latency/throughput knob: queueing delay is
	// roughly window / link rate, so 1 MiB keeps a saturated 150 Mbps lane
	// under ~55 ms while still allowing ~145 Mbps per stream at 55 ms RTT.
	DefaultStreamWindow = 1 << 20
	minStreamWindow     = 256 << 10
	maxStreamWindow     = 16 << 20

	// DefaultMaxConcurrentStreams is the per-tunnel stream cap. It protects
	// the server from one client exhausting file descriptors without getting
	// in the way of a busy router that multiplexes hundreds of LAN sockets.
	DefaultMaxConcurrentStreams = 512
	minMaxConcurrentStreams     = 16
	maxMaxConcurrentStreams     = 4096
)

// NormalizeStreamWindow clamps a configured stream window to a sane range.
// Zero selects the default so an omitted key never disables buffering.
func NormalizeStreamWindow(v uint64) uint64 {
	if v == 0 {
		return DefaultStreamWindow
	}
	if v < minStreamWindow {
		return minStreamWindow
	}
	if v > maxStreamWindow {
		return maxStreamWindow
	}
	return v
}

// NormalizeMaxConcurrentStreams clamps the per-tunnel stream cap. Zero selects
// the default; values below the floor are raised so a legacy config that was
// written when the key did nothing cannot starve a busy client.
func NormalizeMaxConcurrentStreams(v uint32) uint32 {
	if v == 0 {
		return DefaultMaxConcurrentStreams
	}
	if v < minMaxConcurrentStreams {
		return minMaxConcurrentStreams
	}
	if v > maxMaxConcurrentStreams {
		return maxMaxConcurrentStreams
	}
	return v
}

// StreamQueueFrames is the slot count of the per-stream frame channel. The
// channel is only a hand-off buffer; the real backpressure threshold is
// StreamBufferLimit, so it just needs enough slots for the smallest frames a
// sender can emit.
const StreamQueueFrames = 1024

// StreamBufferLimit is how many unread bytes one stream may hold before it is
// treated as stalled. Flow control caps what a sender can have in flight at
// the window size, so exceeding the window (plus a frame of slack) can only
// mean the local consumer stopped reading. Sizing this in bytes rather than
// frames keeps a burst of small frames from resetting a healthy stream.
func StreamBufferLimit(window uint64) int64 {
	return int64(NormalizeStreamWindow(window)) + 4*FrameSizeHint
}

// NormalizeSessionLifetime clamps how long an outer connection may live before
// the client drains and reconnects it. Zero disables recycling.
func NormalizeSessionLifetime(d time.Duration) time.Duration {
	if d == 0 {
		return 0
	}
	if d < 5*time.Minute {
		return 5 * time.Minute
	}
	if d > 24*time.Hour {
		return 24 * time.Hour
	}
	return d
}

// NormalizeTunnelConnections clamps the lane count to a safe range.
func NormalizeTunnelConnections(n int) int {
	if n <= 0 {
		return 1
	}
	if n > 16 {
		return 16
	}
	return n
}

// Client-side operational defaults.
const (
	// DefaultStreamIdleTimeout is how long a stream may carry no traffic
	// before the client may reclaim it. 30 minutes sits above the pauses a
	// viewer actually takes: a video paused at 10 minutes was being reset
	// mid-session, which the player reports as an interruption. Reclamation is
	// additionally gated on lane pressure, so this is a ceiling on how long a
	// forgotten stream survives a squeeze, not a timer that kills idle ones.
	DefaultStreamIdleTimeout = 30 * time.Minute
	// minStreamIdleTimeout protects against a config that would shred healthy
	// connections. Zero still means "disabled".
	minStreamIdleTimeout = 30 * time.Second

	// DefaultMaxPendingDials is the per-lane cap on connections waiting for
	// the server to finish dialling. Browsers open a handful of connections
	// per page, so this leaves plenty of head-room while still absorbing a
	// restart storm.
	DefaultMaxPendingDials = 64
	maxMaxPendingDials     = 4096

	// DefaultLogRotateSize is the size at which the client log file rolls
	// over. 4 MiB is ~30 hours of steady traffic even with per-minute
	// summaries and tunnel events.
	DefaultLogRotateSize = 4 << 20
	minLogRotateSize     = 64 << 10

	// DefaultLogRotateKeep is how many rolled files are kept (log.1 .. log.N).
	DefaultLogRotateKeep = 3
	maxLogRotateKeep     = 20

	// DefaultQUICFallbackFailures is the streak length that means "this path
	// is not going to carry QUIC right now" rather than "one unlucky dial".
	// Three attempts is about 15s of retrying at the reconnect interval.
	DefaultQUICFallbackFailures = 3
	maxQUICFallbackFailures     = 20

	// DefaultQUICFallbackHold keeps a fallen-back lane on WebSocket for long
	// enough that a blocked path is not re-probed in the middle of a video,
	// and short enough that a restored path is picked up within the hour.
	DefaultQUICFallbackHold = 10 * time.Minute
	minQUICFallbackHold     = 30 * time.Second
	maxQUICFallbackHold     = 6 * time.Hour

	// DefaultQUICFallbackMinUptime is the uptime that makes a QUIC
	// connection count as healthy. It is far above the handshake and far below
	// the time a blocked path takes to drop the association, so a flap is
	// still visible as a failure.
	DefaultQUICFallbackMinUptime = 15 * time.Second
	minQUICFallbackMinUptime     = 5 * time.Second
	maxQUICFallbackMinUptime     = 10 * time.Minute
)

// NormalizeStreamIdleTimeout clamps the idle reclamation threshold. Zero and
// negatives disable reclamation, which stays a valid choice.
func NormalizeStreamIdleTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	if d < minStreamIdleTimeout {
		return minStreamIdleTimeout
	}
	return d
}

// NormalizeMaxPendingDials clamps the per-lane dial cap. Zero disables it.
func NormalizeMaxPendingDials(n int) int {
	if n <= 0 {
		return 0
	}
	if n > maxMaxPendingDials {
		return maxMaxPendingDials
	}
	return n
}

// NormalizeQUICFallback clamps the QUIC fallback policy. Zero failures keeps
// the fallback off; the durations fall back to their defaults so an omitted
// key can never turn the hold into zero (which would flap every reconnect).
func NormalizeQUICFallback(failures int, hold, minUptime time.Duration) (int, time.Duration, time.Duration) {
	if failures < 0 {
		failures = 0
	}
	if failures > maxQUICFallbackFailures {
		failures = maxQUICFallbackFailures
	}
	if hold <= 0 {
		hold = DefaultQUICFallbackHold
	} else if hold < minQUICFallbackHold {
		hold = minQUICFallbackHold
	} else if hold > maxQUICFallbackHold {
		hold = maxQUICFallbackHold
	}
	if minUptime <= 0 {
		minUptime = DefaultQUICFallbackMinUptime
	} else if minUptime < minQUICFallbackMinUptime {
		minUptime = minQUICFallbackMinUptime
	} else if minUptime > maxQUICFallbackMinUptime {
		minUptime = maxQUICFallbackMinUptime
	}
	return failures, hold, minUptime
}

// NormalizeLogRotate clamps the log rotation settings so a typo cannot turn
// rotation into either "never rotates" or "keeps a thousand files".
func NormalizeLogRotate(size uint64, keep int) (uint64, int) {
	if size == 0 {
		size = DefaultLogRotateSize
	} else if size < minLogRotateSize {
		size = minLogRotateSize
	}
	if keep <= 0 {
		keep = DefaultLogRotateKeep
	} else if keep > maxLogRotateKeep {
		keep = maxLogRotateKeep
	}
	return size, keep
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
	cfg.StreamWindow = NormalizeStreamWindow(cfg.StreamWindow)
	cfg.MaxConcurrentStream = NormalizeMaxConcurrentStreams(cfg.MaxConcurrentStream)
	cfg.SessionLifetime = NormalizeSessionLifetime(cfg.SessionLifetime)
	cfg.TunnelConnections = NormalizeTunnelConnections(cfg.TunnelConnections)
	cfg.StreamIdleTimeout = NormalizeStreamIdleTimeout(cfg.StreamIdleTimeout)
	cfg.MaxPendingDials = NormalizeMaxPendingDials(cfg.MaxPendingDials)
	cfg.QUICFallbackFailures, cfg.QUICFallbackHold, cfg.QUICFallbackMinUptime =
		NormalizeQUICFallback(cfg.QUICFallbackFailures, cfg.QUICFallbackHold, cfg.QUICFallbackMinUptime)
	cfg.LogRotateSize, cfg.LogRotateKeep = NormalizeLogRotate(cfg.LogRotateSize, cfg.LogRotateKeep)
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
	cfg.StreamWindow = NormalizeStreamWindow(cfg.StreamWindow)
	cfg.MaxConcurrentStream = NormalizeMaxConcurrentStreams(cfg.MaxConcurrentStream)
	return cfg, nil
}
