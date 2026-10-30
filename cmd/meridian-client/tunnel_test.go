package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"meridian/pkg/config"
)

// newIdleTestTunnel builds a TunnelClient with no transport: enough to exercise
// stream bookkeeping without a server.
func newIdleTestTunnel(idle time.Duration, dialCap int) *TunnelClient {
	cfg := config.DefaultClientConfig()
	cfg.StreamIdleTimeout = idle
	cfg.MaxPendingDials = dialCap
	return NewTunnelClient(cfg, nil)
}

func newTestStream(tc *TunnelClient, sid uint32, lastActive time.Time) *StreamConn {
	sc := &StreamConn{
		sid:      sid,
		client:   tc,
		readChan: make(chan []byte, 4),
		closed:   make(chan struct{}),
	}
	sc.lastActive.Store(lastActive.UnixNano())
	return sc
}

func TestReapIdleReclaimsOnlySilentStreams(t *testing.T) {
	tc := newIdleTestTunnel(time.Minute, 0)
	now := time.Now()

	idle := newTestStream(tc, 1, now.Add(-2*time.Minute))
	busy := newTestStream(tc, 2, now.Add(-10*time.Second))
	tc.activeStreams[1] = idle
	tc.activeStreams[2] = busy
	tc.activeLoad.Store(2)

	if n := tc.reapIdle(now); n != 1 {
		t.Fatalf("reclaimed %d streams, want 1", n)
	}
	if _, ok := tc.activeStreams[1]; ok {
		t.Error("idle stream is still registered, its slot would stay pinned")
	}
	if _, ok := tc.activeStreams[2]; !ok {
		t.Error("a stream that carried traffic 10s ago was reclaimed")
	}
	if got := tc.ActiveLoad(); got != 1 {
		t.Errorf("active load = %d, want 1", got)
	}
	select {
	case <-idle.closed:
	default:
		t.Error("reclaimed stream was not closed, the application would hang")
	}
	if busy.closedClosed() {
		t.Error("busy stream was closed")
	}
}

func TestReapIdleDisabledWhenTimeoutZero(t *testing.T) {
	tc := newIdleTestTunnel(0, 0)
	now := time.Now()

	stale := newTestStream(tc, 1, now.Add(-24*time.Hour))
	tc.activeStreams[1] = stale
	tc.activeLoad.Store(1)

	if n := tc.reapIdle(now); n != 0 {
		t.Fatalf("reclaimed %d streams with reclamation disabled", n)
	}
	if _, ok := tc.activeStreams[1]; !ok {
		t.Fatal("stream disappeared while reclamation was disabled")
	}
}

func TestDialSlotQueuesInsteadOfFailing(t *testing.T) {
	tc := newIdleTestTunnel(time.Minute, 1)
	tc.dialSem <- struct{}{} // the lane's only slot is taken

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := tc.DialStream(ctx, "www.example.com:443")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DialStream error = %v, want context deadline exceeded", err)
	}
	// A dial that never got a slot must not leak a stream record.
	tc.mu.Lock()
	streams := len(tc.activeStreams)
	tc.mu.Unlock()
	if streams != 0 {
		t.Fatalf("%d streams registered after a refused dial", streams)
	}
}

func TestEndDialReleasesSlotOnce(t *testing.T) {
	tc := newIdleTestTunnel(time.Minute, 2)
	tc.dialSem <- struct{}{}

	sc := &StreamConn{client: tc}
	sc.endDial()
	if len(tc.dialSem) != 0 {
		t.Fatalf("slot still held after endDial: %d", len(tc.dialSem))
	}

	// A second call must not steal another stream's slot.
	tc.dialSem <- struct{}{}
	sc.endDial()
	if len(tc.dialSem) != 1 {
		t.Fatalf("second endDial released a slot it did not own: %d", len(tc.dialSem))
	}
}

// closedClosed reports whether the stream's closed channel is already closed.
func (sc *StreamConn) closedClosed() bool {
	select {
	case <-sc.closed:
		return true
	default:
		return false
	}
}
