package mfp

import (
	"io"
	"testing"
	"time"
)

func TestFlowWindowBlocksUntilAcked(t *testing.T) {
	f := NewFlowWindow(100)
	if err := f.Acquire(100); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if got := f.Inflight(); got != 100 {
		t.Fatalf("inflight = %d, want 100", got)
	}

	blocked := make(chan error, 1)
	go func() { blocked <- f.Acquire(60) }()

	select {
	case err := <-blocked:
		t.Fatalf("acquire should block while the window is full, got %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	// A partial ACK is not enough to fit another 60 bytes.
	f.Ack(20)
	select {
	case err := <-blocked:
		t.Fatalf("acquire should still block with 80/100 used, got %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	// Releasing the full amount lets the waiter through.
	f.Ack(100)
	select {
	case err := <-blocked:
		if err != nil {
			t.Fatalf("acquire after ack: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("acquire did not resume after ack")
	}
}

func TestFlowWindowAckIsCumulativeAndClamped(t *testing.T) {
	f := NewFlowWindow(1000)
	if err := f.Acquire(400); err != nil {
		t.Fatal(err)
	}
	// ACK beyond what was sent must not create negative in-flight.
	f.Ack(10_000)
	if got := f.Inflight(); got != 0 {
		t.Fatalf("inflight after over-ack = %d, want 0", got)
	}
	// Duplicate / stale ACKs are ignored.
	f.Ack(0)
	f.Ack(1)
	if got := f.Inflight(); got != 0 {
		t.Fatalf("inflight after stale ack = %d, want 0", got)
	}
}

func TestFlowWindowRefund(t *testing.T) {
	f := NewFlowWindow(100)
	if err := f.Acquire(80); err != nil {
		t.Fatal(err)
	}
	f.Refund(80)
	if got := f.Inflight(); got != 0 {
		t.Fatalf("inflight after refund = %d, want 0", got)
	}
	if err := f.Acquire(100); err != nil {
		t.Fatalf("acquire after refund: %v", err)
	}
}

func TestFlowWindowCloseUnblocksWaiters(t *testing.T) {
	f := NewFlowWindow(10)
	if err := f.Acquire(10); err != nil {
		t.Fatal(err)
	}
	blocked := make(chan error, 1)
	go func() { blocked <- f.Acquire(10) }()
	time.Sleep(50 * time.Millisecond)
	f.Close()

	select {
	case err := <-blocked:
		if err != io.ErrClosedPipe {
			t.Fatalf("blocked acquire returned %v, want io.ErrClosedPipe", err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not unblock the waiter")
	}
}

func TestAckTrackerThreshold(t *testing.T) {
	a := NewAckTracker(1 << 20)
	if a.threshold != 128*1024 {
		t.Fatalf("threshold = %d, want 128KiB", a.threshold)
	}
	if _, due := a.Consume(64 * 1024); due {
		t.Fatal("ACK fired before the threshold")
	}
	cum, due := a.Consume(64 * 1024)
	if !due {
		t.Fatal("ACK should fire at the threshold")
	}
	if cum != 128*1024 {
		t.Fatalf("cumulative = %d, want 128KiB", cum)
	}
	if _, due := a.Consume(1); due {
		t.Fatal("ACK fired again too early")
	}
}

func TestAckTrackerThresholdBounds(t *testing.T) {
	if got := NewAckTracker(64 * 1024).threshold; got != 16*1024 {
		t.Fatalf("small window threshold = %d, want 16KiB floor", got)
	}
	if got := NewAckTracker(64 << 20).threshold; got != 256*1024 {
		t.Fatalf("large window threshold = %d, want 256KiB ceiling", got)
	}
}

func TestEncodeDecodeAck(t *testing.T) {
	cum, ok := DecodeAck(EncodeAck(123456789))
	if !ok || cum != 123456789 {
		t.Fatalf("round trip = %d/%v", cum, ok)
	}
	if _, ok := DecodeAck([]byte{1, 2, 3}); ok {
		t.Fatal("short payload should be rejected")
	}
}
