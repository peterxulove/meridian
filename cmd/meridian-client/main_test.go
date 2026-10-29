package main

import (
	"testing"
	"time"

	"meridian/pkg/config"
)

func TestNewClientCreatesDistinctLaneSessions(t *testing.T) {
	cfg := config.DefaultClientConfig()
	cfg.TunnelConnections = 4

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if got := len(client.tunnels); got != 4 {
		t.Fatalf("lane count = %d, want 4", got)
	}

	seen := make(map[[16]byte]bool)
	for i, session := range client.laneSessions {
		if session == ([16]byte{}) {
			t.Fatalf("lane %d has an empty session ID", i)
		}
		if seen[session] {
			t.Fatalf("lane %d reuses another lane's session ID", i)
		}
		seen[session] = true
	}
}

func TestPickTunnelUsesLeastLoadedLane(t *testing.T) {
	cfg := config.DefaultClientConfig()
	cfg.TunnelConnections = 3
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	lanes := []*TunnelClient{{}, {}, {}}
	lanes[0].activeLoad.Store(4)
	lanes[1].activeLoad.Store(0)
	lanes[2].activeLoad.Store(2)
	client.tunnels = lanes

	tunnel, lane := client.pickTunnel()
	if tunnel != lanes[1] || lane != 1 {
		t.Fatalf("picked lane %d load %d, want lane 1 load 0", lane, tunnel.ActiveLoad())
	}

	lanes[1].closed.Store(true)
	tunnel, lane = client.pickTunnel()
	if tunnel != lanes[2] || lane != 2 {
		t.Fatalf("picked lane %d after close, want lane 2", lane)
	}
}

func TestPickTunnelSkipsDrainingLane(t *testing.T) {
	cfg := config.DefaultClientConfig()
	cfg.TunnelConnections = 2
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	lanes := []*TunnelClient{{}, {}}
	lanes[0].draining.Store(true)
	client.tunnels = lanes

	tunnel, lane := client.pickTunnel()
	if tunnel != lanes[1] || lane != 1 {
		t.Fatalf("picked lane %d, want the non-draining lane 1", lane)
	}

	lanes[1].draining.Store(true)
	if tunnel, lane := client.pickTunnel(); tunnel != nil || lane != -1 {
		t.Fatalf("picked lane %d while all lanes drain, want none", lane)
	}
}

func TestDrainGraceBounds(t *testing.T) {
	cases := []struct {
		lifetime time.Duration
		want     time.Duration
	}{
		// A short lifetime still gets a usable grace, and a long one is capped
		// so a never-ending stream cannot pin a lane forever.
		{5 * time.Minute, 5 * time.Minute},
		{time.Hour, 30 * time.Minute},
		{24 * time.Hour, 30 * time.Minute},
	}
	for _, c := range cases {
		if got := drainGrace(c.lifetime); got != c.want {
			t.Errorf("drainGrace(%v) = %v, want %v", c.lifetime, got, c.want)
		}
	}
}

func TestStaggerLifetime(t *testing.T) {
	hour := time.Hour
	if got := staggerLifetime(0, 2, 4); got != 0 {
		t.Errorf("disabled lifetime = %v, want 0", got)
	}
	if got := staggerLifetime(hour, 0, 4); got != hour {
		t.Errorf("lane 0 = %v, want %v", got, hour)
	}
	if got := staggerLifetime(hour, 1, 4); got != hour+3*time.Minute {
		t.Errorf("lane 1 = %v, want %v", got, hour+3*time.Minute)
	}
	if got := staggerLifetime(hour, 3, 4); got != hour+9*time.Minute {
		t.Errorf("lane 3 = %v, want %v", got, hour+9*time.Minute)
	}
}
