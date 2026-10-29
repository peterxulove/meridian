package main

import (
	"testing"

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
