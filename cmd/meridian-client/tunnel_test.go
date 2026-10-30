package main

import (
	"context"
	"errors"
	"strings"
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
	// Reclamation only happens under pressure now, so the default test lane is
	// deliberately tiny: two streams fill it.
	cfg.MaxConcurrentStream = 2
	return NewTunnelClient(cfg, nil)
}

func newTestStream(tc *TunnelClient, sid uint32, lastActive time.Time) *StreamConn {
	stream := &StreamConn{
		sid:      sid,
		client:   tc,
		readChan: make(chan []byte, 4),
		closed:   make(chan struct{}),
	}
	stream.lastActive.Store(lastActive.UnixNano())
	return stream
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

func TestReapIdleLeavesIdleStreamsAloneWithoutPressure(t *testing.T) {
	// The default lane holds hundreds of streams and normal browsing uses a
	// fraction of that. A video paused for 40 minutes used to be reset at the
	// 10 minute mark even here, which the player reports as an interruption.
	tc := newIdleTestTunnel(time.Minute, 0)
	tc.cfg.MaxConcurrentStream = 512
	now := time.Now()

	paused := newTestStream(tc, 7, now.Add(-40*time.Minute))
	paused.target = "rr3---sn-abc.googlevideo.com:443"
	tc.activeStreams[7] = paused
	tc.activeLoad.Store(1)

	if n := tc.reapIdle(now); n != 0 {
		t.Fatalf("reclaimed %d streams while the lane had room for 511 more", n)
	}
	if _, ok := tc.activeStreams[7]; !ok {
		t.Fatal("paused video stream was reclaimed, that is the interruption")
	}
}

func TestReapIdleReclaimsOnlyWhenLaneNearlyFull(t *testing.T) {
	tc := newIdleTestTunnel(10*time.Minute, 0)
	tc.cfg.MaxConcurrentStream = 4 // 80% = 3.2 streams, so 4 is pressure
	now := time.Now()

	old := newTestStream(tc, 1, now.Add(-30*time.Minute))
	old.target = "rr3---sn-abc.googlevideo.com:443"
	fresh := newTestStream(tc, 2, now.Add(-5*time.Second))
	other := newTestStream(tc, 3, now.Add(-20*time.Minute))
	fourth := newTestStream(tc, 4, now.Add(-5*time.Second))
	for _, sc := range []*StreamConn{old, fresh, other, fourth} {
		tc.activeStreams[sc.sid] = sc
	}
	tc.activeLoad.Store(4)

	if n := tc.reapIdle(now); n != 2 {
		t.Fatalf("reclaimed %d streams, want 2 (the two stale ones)", n)
	}
	if _, ok := tc.activeStreams[1]; ok {
		t.Error("stale stream survived a full lane")
	}
	if _, ok := tc.activeStreams[2]; !ok {
		t.Error("stream that moved bytes 5s ago was reclaimed")
	}
	if _, ok := tc.activeStreams[3]; ok {
		t.Error("stream idle for 20m survived a full lane with a 10m threshold")
	}
	if _, ok := tc.activeStreams[4]; !ok {
		t.Error("stream that moved bytes 5s ago was reclaimed")
	}
}

func TestReapIdleLogNamesTheTarget(t *testing.T) {
	tc := newIdleTestTunnel(time.Minute, 0)
	now := time.Now()

	sc := newTestStream(tc, 9, now.Add(-30*time.Minute))
	sc.target = "rr3---sn-abc.googlevideo.com:443"
	tc.activeStreams[9] = sc
	tc.activeLoad.Store(2)

	if n := tc.reapIdle(now); n != 1 {
		t.Fatalf("reclaimed %d streams, want 1", n)
	}
	// A bare stream id made "did the client kill my video?" unanswerable.
	conns, counts, samples := events.snapshot()
	line := formatSummary(conns, counts, samples, time.Minute)
	if !strings.Contains(line, "rr3---sn-abc.googlevideo.com:443") {
		t.Fatalf("summary does not name the reclaimed target: %s", line)
	}
}

func TestActiveWithinIgnoresQuietStreams(t *testing.T) {
	tc := newIdleTestTunnel(time.Minute, 0)
	now := time.Now()

	playing := newTestStream(tc, 1, now.Add(-3*time.Second))
	playing.target = "rr1---sn-abc.googlevideo.com:443"
	paused := newTestStream(tc, 2, now.Add(-20*time.Minute))
	for _, sc := range []*StreamConn{playing, paused} {
		tc.activeStreams[sc.sid] = sc
	}
	tc.activeLoad.Store(2)

	// A playing video keeps its lane alive through a drain; a paused one does
	// not, otherwise the lane would never be released.
	if n := tc.ActiveWithin(drainActiveWindow); n != 1 {
		t.Fatalf("ActiveWithin = %d, want 1", n)
	}
	if n := tc.ActiveWithin(time.Hour); n != 2 {
		t.Fatalf("ActiveWithin(1h) = %d, want 2", n)
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
func (stream *StreamConn) closedClosed() bool {
	select {
	case <-stream.closed:
		return true
	default:
		return false
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// First-byte watchdog
// ─────────────────────────────────────────────────────────────────────────────

func newWatchdogTunnel(timeout time.Duration, failures int) *TunnelClient {
	cfg := config.DefaultClientConfig()
	cfg.FirstByteTimeout = timeout
	cfg.FirstByteFailures = failures
	return NewTunnelClient(cfg, nil)
}

func registerStream(tc *TunnelClient, sid uint32) *StreamConn {
	stream := newTestStream(tc, sid, time.Now())
	stream.dialSeq = tc.dialSeq.Add(1)
	tc.mu.Lock()
	tc.activeStreams[sid] = stream
	tc.activeLoad.Add(1)
	tc.mu.Unlock()
	return stream
}

func TestWatchdogResetsStreamTheServerNeverAnswers(t *testing.T) {
	tc := newWatchdogTunnel(10*time.Second, 3)
	stream := registerStream(tc, 1)

	tc.watchFirstByte(stream)

	if _, ok := tc.activeStreams[1]; ok {
		t.Error("silent stream is still registered, it would hold its slot and hang the caller")
	}
	if !stream.closedClosed() {
		t.Error("silent stream was not closed; the application keeps waiting")
	}
	if _, err := stream.Read(make([]byte, 8)); err == nil {
		t.Error("read returned no error after the watchdog fired")
	}
	if n := tc.silentStreak.Load(); n != 1 {
		t.Errorf("silent streak = %d, want 1", n)
	}
	if tc.closed.Load() {
		t.Error("lane was closed after a single silent stream; one slow target must not kill it")
	}
}

func TestWatchdogDisarmedByServerResponse(t *testing.T) {
	tc := newWatchdogTunnel(10*time.Second, 3)
	stream := registerStream(tc, 1)

	// CONNECT SUCCESS, data and a reset all arrive as frames on the stream.
	stream.noteResponded()
	tc.watchFirstByte(stream)

	if _, ok := tc.activeStreams[1]; !ok {
		t.Error("a stream the server answered was reset")
	}
	if stream.closedClosed() {
		t.Error("a stream the server answered was closed")
	}
	if n := tc.silentStreak.Load(); n != 0 {
		t.Errorf("silent streak = %d after a response, want 0", n)
	}
}

func TestSilentStreakCondemnsTheLane(t *testing.T) {
	tc := newWatchdogTunnel(10*time.Second, 3)

	for sid := uint32(1); sid <= 2; sid++ {
		tc.watchFirstByte(registerStream(tc, sid))
		if tc.closed.Load() {
			t.Fatalf("lane closed after %d silent streams, want 3", sid)
		}
	}
	tc.watchFirstByte(registerStream(tc, 3))

	if !tc.closed.Load() {
		t.Error("three unanswered dials in a row did not condemn the lane")
	}
}

func TestSilentStreakClearedByTrafficOnAnotherStream(t *testing.T) {
	tc := newWatchdogTunnel(10*time.Second, 3)
	tc.watchFirstByte(registerStream(tc, 1))
	tc.watchFirstByte(registerStream(tc, 2))

	// One target answering proves the lane's dial path works, whatever the
	// other two did.
	registerStream(tc, 3).noteResponded()
	if got := tc.silentStreak.Load(); got != 0 {
		t.Fatalf("silent streak = %d after a response, want 0", got)
	}

	tc.watchFirstByte(registerStream(tc, 4))
	if tc.closed.Load() {
		t.Error("lane closed on the first silent stream after a healthy one")
	}
}

func TestBurstOfSilentStreamsCountsOnce(t *testing.T) {
	tc := newWatchdogTunnel(10*time.Second, 2)

	// Both dials were in flight when the first silence was counted, so they are
	// one incident: a browser opening two sockets to a dead host must not
	// condemn a lane that is serving everything else.
	first := registerStream(tc, 1)
	second := registerStream(tc, 2)
	tc.watchFirstByte(first)
	tc.watchFirstByte(second)

	if tc.closed.Load() {
		t.Error("lane closed on a single burst of unanswered dials")
	}
	if n := tc.silentStreak.Load(); n != 1 {
		t.Errorf("silent streak = %d for one burst, want 1", n)
	}
}

func TestWatchdogOffWhenTimeoutIsZero(t *testing.T) {
	cfg := config.DefaultClientConfig()
	cfg.FirstByteTimeout = 0
	tc := NewTunnelClient(cfg, nil)
	if tc.firstByteTimeout != 0 {
		t.Fatalf("timeout = %v, want 0 (disabled)", tc.firstByteTimeout)
	}
	if n := tc.silentStreak.Load(); n != 0 {
		t.Errorf("streak = %d on a fresh lane", n)
	}
}
