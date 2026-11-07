package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeIPVersion(t *testing.T) {
	cases := map[string]string{
		"":      IPVersionAuto,
		"auto":  IPVersionAuto,
		"4":     IPVersion4,
		"ipv4":  IPVersion4,
		"V4":    IPVersion4,
		"6":     IPVersion6,
		"IPv6":  IPVersion6,
		" 6 ":   IPVersion6,
		"bogus": IPVersionAuto,
	}
	for in, want := range cases {
		if got := NormalizeIPVersion(in); got != want {
			t.Errorf("NormalizeIPVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeServerAddr(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"example.com", "example.com:443", false},
		{"example.com:8443", "example.com:8443", false},
		{"1.2.3.4", "1.2.3.4:443", false},
		{"1.2.3.4:443", "1.2.3.4:443", false},
		// A bare IPv6 literal has no unambiguous port, so the default is used.
		{"2404:3881:100:1000::6440:146", "[2404:3881:100:1000::6440:146]:443", false},
		{"[2404:3881:100:1000::6440:146]", "[2404:3881:100:1000::6440:146]:443", false},
		{"[2404:3881:100:1000::6440:146]:8443", "[2404:3881:100:1000::6440:146]:8443", false},
		{"::1", "[::1]:443", false},
		{"", "", true},
		{"[2404:3881::1:443", "", true},
		{"2404:3881::zz", "", true},
	}
	for _, c := range cases {
		got, err := NormalizeServerAddr(c.in, DefaultServerPort)
		if c.wantErr {
			if err == nil {
				t.Errorf("NormalizeServerAddr(%q) = %q, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeServerAddr(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("NormalizeServerAddr(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeServerAddrDefaultPort(t *testing.T) {
	got, err := NormalizeServerAddr("example.com", "8443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "example.com:8443" {
		t.Errorf("got %q, want example.com:8443", got)
	}
}

func TestDualStackListenAddr(t *testing.T) {
	cases := map[string]string{
		"0.0.0.0:443":              "[::]:443",
		":443":                     "[::]:443",
		"[::]:443":                 "[::]:443",
		"443":                      "[::]:443",
		"127.0.0.1:1080":           "127.0.0.1:1080",
		"192.168.1.10:443":         "192.168.1.10:443",
		"[2404:3881::1]:443":       "[2404:3881::1]:443",
		"2404:3881::1":             "[2404:3881::1]:443",
		"0.0.0.0:8443":             "[::]:8443",
		"[fe80::1%en0]:443":        "[fe80::1%en0]:443",
	}
	for in, want := range cases {
		got, err := DualStackListenAddr(in)
		if err != nil {
			t.Errorf("DualStackListenAddr(%q) unexpected error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("DualStackListenAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestListenTargetHonoursIPv6Switch(t *testing.T) {
	on := DefaultServerConfig()
	on.ListenAddr = "0.0.0.0:443"
	if got := on.ListenTarget(); got != "[::]:443" {
		t.Errorf("IPv6 enabled: ListenTarget = %q, want [::]:443", got)
	}

	off := DefaultServerConfig()
	off.ListenAddr = "0.0.0.0:443"
	off.IPv6 = false
	if got := off.ListenTarget(); got != "0.0.0.0:443" {
		t.Errorf("IPv6 disabled: ListenTarget = %q, want 0.0.0.0:443", got)
	}
}

func TestDialNetwork(t *testing.T) {
	c := DefaultClientConfig()
	if got := c.DialNetwork("tcp"); got != "tcp" {
		t.Errorf("auto: got %q, want tcp", got)
	}
	c.IPVersion = IPVersion6
	if got := c.DialNetwork("tcp"); got != "tcp6" {
		t.Errorf("v6: got %q, want tcp6", got)
	}
	if got := c.DialNetwork("udp"); got != "udp6" {
		t.Errorf("v6: got %q, want udp6", got)
	}
	c.IPVersion = IPVersion4
	if got := c.DialNetwork("udp"); got != "udp4" {
		t.Errorf("v4: got %q, want udp4", got)
	}
}

// LoadClientConfig must hand the rest of the program an address that net.Dial
// and net.ResolveUDPAddr can parse, whatever form the operator typed.
func TestLoadClientConfigNormalizesIPv6(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.yaml")
	body := "server_addr: \"2404:3881:100:1000::6440:146\"\nip_version: \"6\"\ntransport: \"QUIC\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadClientConfig(path)
	if err != nil {
		t.Fatalf("LoadClientConfig: %v", err)
	}
	if want := "[2404:3881:100:1000::6440:146]:443"; cfg.ServerAddr != want {
		t.Errorf("ServerAddr = %q, want %q", cfg.ServerAddr, want)
	}
	if cfg.IPVersion != IPVersion6 {
		t.Errorf("IPVersion = %q, want %q", cfg.IPVersion, IPVersion6)
	}
}

func TestLoadServerConfigIPv6Default(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	if err := os.WriteFile(path, []byte("listen_addr: \"0.0.0.0:443\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadServerConfig(path)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	if !cfg.IPv6 {
		t.Error("IPv6 should default to true when the key is absent")
	}
	if got := cfg.ListenTarget(); got != "[::]:443" {
		t.Errorf("ListenTarget = %q, want [::]:443", got)
	}

	// An explicit opt-out must survive loading.
	if err := os.WriteFile(path, []byte("listen_addr: \"0.0.0.0:443\"\nipv6: false\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err = LoadServerConfig(path)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	if cfg.IPv6 {
		t.Error("ipv6: false was ignored")
	}
	if got := cfg.ListenTarget(); got != "0.0.0.0:443" {
		t.Errorf("ListenTarget = %q, want 0.0.0.0:443", got)
	}
}
