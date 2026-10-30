package main

import (
	"testing"
	"time"

	"meridian/pkg/config"
)

// newTestGuard returns a guard with a controllable clock so the hold can expire
// without a test sleeping for it.
func newTestGuard(t *testing.T, failures int, hold time.Duration) (*transportGuard, *time.Time) {
	t.Helper()
	cfg := config.DefaultClientConfig()
	cfg.QUICFallbackFailures, cfg.QUICFallbackHold, cfg.QUICFallbackMinUptime =
		config.NormalizeQUICFallback(failures, hold, 15*time.Second)
	g := newTransportGuard(cfg)
	now := time.Date(2026, 10, 30, 18, 0, 0, 0, time.UTC)
	clock := &now
	g.now = func() time.Time { return *clock }
	return g, clock
}

func TestFallbackTripsOnlyAfterTheConfiguredStreak(t *testing.T) {
	g, _ := newTestGuard(t, 3, 10*time.Minute)
	quic := config.TransportHysteria

	for i := 1; i < 3; i++ {
		if g.failure(quic) {
			t.Fatalf("failure %d tripped the fallback, want it to wait for %d", i, g.after)
		}
		if got := g.effective(quic); got != quic {
			t.Fatalf("after %d failures effective = %v, want %v", i, got, quic)
		}
	}
	if !g.failure(quic) {
		t.Fatalf("the %drd failure did not trip the fallback", g.after)
	}
	if got := g.effective(quic); got != config.TransportWebSocket {
		t.Fatalf("effective after trip = %v, want %v", got, config.TransportWebSocket)
	}
	if !g.holding() {
		t.Fatal("guard reports not holding right after the trip")
	}
}

func TestFallbackReturnsToQUICWhenTheHoldExpires(t *testing.T) {
	g, clock := newTestGuard(t, 1, 10*time.Minute)
	quic := config.TransportHysteria

	g.failure(quic)
	if got := g.effective(quic); got != config.TransportWebSocket {
		t.Fatalf("effective = %v, want WebSocket during the hold", got)
	}

	*clock = clock.Add(9 * time.Minute)
	if got := g.effective(quic); got != config.TransportWebSocket {
		t.Fatalf("effective = %v, still inside the hold", got)
	}

	*clock = clock.Add(2 * time.Minute)
	if got := g.effective(quic); got != quic {
		t.Fatalf("effective = %v, want QUIC once the hold expired", got)
	}
	if g.holding() {
		t.Fatal("guard still reports holding after the deadline")
	}
}

func TestFallbackHoldDoublesAndIsCapped(t *testing.T) {
	g, _ := newTestGuard(t, 1, 10*time.Minute)
	quic := config.TransportHysteria

	want := []time.Duration{10 * time.Minute, 20 * time.Minute, 40 * time.Minute, time.Hour, time.Hour}
	for i, expected := range want {
		g.until = time.Time{} // pretend the previous hold expired
		g.failure(quic)
		if got := g.remaining(); got != expected {
			t.Fatalf("trip %d hold = %v, want %v", i+1, got, expected)
		}
	}
}

func TestHealthyQUICConnectionClearsTheStreak(t *testing.T) {
	g, _ := newTestGuard(t, 3, 10*time.Minute)
	quic := config.TransportHysteria

	g.failure(quic)
	g.failure(quic)
	if g.ended(quic, 20*time.Minute) {
		t.Fatal("a long-lived connection tripped the fallback")
	}
	if g.fails != 0 {
		t.Fatalf("streak = %d after a healthy connection, want 0", g.fails)
	}

	// Two more failures after the reset must not trip it: the streak starts over.
	g.failure(quic)
	if g.failure(quic) {
		t.Fatal("the streak survived a healthy connection")
	}
}

func TestShortLivedQUICConnectionCountsAsFailure(t *testing.T) {
	g, _ := newTestGuard(t, 3, 10*time.Minute)
	quic := config.TransportHysteria

	// A handshake that dies inside the min-uptime window is what a blocked UDP
	// path looks like, so it has to feed the same streak as a refused dial.
	g.ended(quic, 2*time.Second)
	g.ended(quic, 2*time.Second)
	if g.holding() {
		t.Fatal("fell back before the streak was long enough")
	}
	if !g.ended(quic, 2*time.Second) {
		t.Fatalf("the %drd short-lived connection did not trip the fallback", g.after)
	}
	if got := g.effective(quic); got != config.TransportWebSocket {
		t.Fatalf("effective = %v, want WebSocket", got)
	}
}

func TestFallbackIgnoresFailuresOnTheFallbackTransport(t *testing.T) {
	g, _ := newTestGuard(t, 1, 10*time.Minute)
	ws := config.TransportWebSocket

	// The schedule may itself ask for WebSocket; failures there say nothing
	// about QUIC being blocked and must not start a hold.
	for i := 0; i < 5; i++ {
		if g.failure(ws) {
			t.Fatal("a WebSocket failure tripped the QUIC fallback")
		}
		g.ended(ws, time.Second)
	}
	if g.effective(ws) != ws {
		t.Fatal("effective transport changed while the schedule asked for WebSocket")
	}
	if g.holding() {
		t.Fatal("guard is holding after only WebSocket failures")
	}
}

func TestFallbackDisabledByZeroFailures(t *testing.T) {
	g, _ := newTestGuard(t, 0, 10*time.Minute)
	quic := config.TransportHysteria

	for i := 0; i < 10; i++ {
		if g.failure(quic) {
			t.Fatal("disabled fallback tripped")
		}
	}
	if got := g.effective(quic); got != quic {
		t.Fatalf("effective = %v, want %v when the fallback is disabled", got, quic)
	}
}

func TestFallbackKeepsScheduleTransportsItCannotReplace(t *testing.T) {
	g, _ := newTestGuard(t, 1, 10*time.Minute)

	// HTTP-POST has no alternative on the same port, so the guard must leave
	// it alone even after its failures.
	for i := 0; i < 3; i++ {
		g.failure(config.TransportHTTPPOST)
	}
	if got := g.effective(config.TransportHTTPPOST); got != config.TransportHTTPPOST {
		t.Fatalf("effective = %v, want HTTP-POST untouched", got)
	}
}

func TestHoldForIsNeverZero(t *testing.T) {
	g, _ := newTestGuard(t, 1, time.Second) // clamps to minQUICFallbackHold
	if d := g.holdFor(1); d < 30*time.Second {
		t.Fatalf("holdFor(1) = %v, want at least 30s so a lane cannot flap", d)
	}
}
