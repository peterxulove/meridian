package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNormalizeStreamWindow(t *testing.T) {
	cases := []struct {
		in   uint64
		want uint64
	}{
		{0, DefaultStreamWindow},
		{1, minStreamWindow},
		{4 << 20, 4 << 20},
		{1 << 40, maxStreamWindow},
	}
	for _, c := range cases {
		if got := NormalizeStreamWindow(c.in); got != c.want {
			t.Errorf("NormalizeStreamWindow(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestStreamQueueDepthTracksWindow(t *testing.T) {
	small := StreamQueueDepth(1 << 10)
	if small != minStreamQueueDepth {
		t.Fatalf("tiny window depth = %d, want floor %d", small, minStreamQueueDepth)
	}

	huge := StreamQueueDepth(1 << 40)
	if huge != maxStreamQueueDepth {
		t.Fatalf("huge window depth = %d, want ceiling %d", huge, maxStreamQueueDepth)
	}

	window := uint64(8 << 20)
	want := int(window / FrameSizeHint)
	if got := StreamQueueDepth(window); got != want {
		t.Fatalf("depth = %d, want %d", got, want)
	}
}

func TestNormalizeMaxConcurrentStreams(t *testing.T) {
	if got := NormalizeMaxConcurrentStreams(0); got != DefaultMaxConcurrentStreams {
		t.Fatalf("zero = %d, want %d", got, DefaultMaxConcurrentStreams)
	}
	if got := NormalizeMaxConcurrentStreams(1); got != minMaxConcurrentStreams {
		t.Fatalf("one = %d, want floor %d", got, minMaxConcurrentStreams)
	}
	if got := NormalizeMaxConcurrentStreams(200); got != 200 {
		t.Fatalf("200 = %d, want 200", got)
	}
	if got := NormalizeMaxConcurrentStreams(1 << 20); got != maxMaxConcurrentStreams {
		t.Fatalf("huge = %d, want ceiling %d", got, maxMaxConcurrentStreams)
	}
}

func TestNormalizeSessionLifetime(t *testing.T) {
	if got := NormalizeSessionLifetime(0); got != 0 {
		t.Fatalf("zero should disable recycling, got %v", got)
	}
	if got := NormalizeSessionLifetime(time.Second); got != 5*time.Minute {
		t.Fatalf("short lifetime = %v, want floor 5m", got)
	}
	if got := NormalizeSessionLifetime(48 * time.Hour); got != 24*time.Hour {
		t.Fatalf("long lifetime = %v, want ceiling 24h", got)
	}
	if got := NormalizeSessionLifetime(time.Hour); got != time.Hour {
		t.Fatalf("one hour = %v, want 1h", got)
	}
}

func TestLoadClientConfigAppliesTuning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.yaml")
	body := []byte("server_addr: \"127.0.0.1:443\"\n" +
		"stream_window: 1024\n" +
		"max_concurrent_streams: 1\n" +
		"session_lifetime: \"30s\"\n" +
		"tunnel_connections: 99\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadClientConfig(path)
	if err != nil {
		t.Fatalf("LoadClientConfig: %v", err)
	}
	if cfg.StreamWindow != minStreamWindow {
		t.Errorf("stream window = %d, want %d", cfg.StreamWindow, minStreamWindow)
	}
	if cfg.MaxConcurrentStream != minMaxConcurrentStreams {
		t.Errorf("max streams = %d, want %d", cfg.MaxConcurrentStream, minMaxConcurrentStreams)
	}
	if cfg.SessionLifetime != 5*time.Minute {
		t.Errorf("session lifetime = %v, want 5m", cfg.SessionLifetime)
	}
	if cfg.TunnelConnections != 16 {
		t.Errorf("tunnel connections = %d, want 16", cfg.TunnelConnections)
	}
}

func TestLoadServerConfigAppliesTuning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	body := []byte("listen_addr: \"0.0.0.0:443\"\n" +
		"stream_window: 0\n" +
		"max_concurrent_streams: 0\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadServerConfig(path)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	if cfg.StreamWindow != DefaultStreamWindow {
		t.Errorf("stream window = %d, want %d", cfg.StreamWindow, DefaultStreamWindow)
	}
	if cfg.MaxConcurrentStream != DefaultMaxConcurrentStreams {
		t.Errorf("max streams = %d, want %d", cfg.MaxConcurrentStream, DefaultMaxConcurrentStreams)
	}
}
