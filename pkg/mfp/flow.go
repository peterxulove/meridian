package mfp

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"
)

// ErrFlowStalled is returned when a stream cannot make progress because the
// peer stopped acknowledging data. The caller resets the stream instead of
// blocking a whole lane forever.
var ErrFlowStalled = errors.New("mfp: stream stalled waiting for flow-control credit")

const (
	// flowStallTimeout is how long a writer waits for credit before giving up.
	// A video player routinely stops reading once its buffer is full and may
	// resume minutes later; a short timeout turned those pauses into resets,
	// which the player reports as an interrupted stream. A dead peer is still
	// detected immediately because closing the tunnel or the stream closes the
	// window, so this only has to catch an application that hangs forever.
	flowStallTimeout = 10 * time.Minute
	// defaultFlowWindow is used when a caller passes a non-positive window.
	defaultFlowWindow = 1 << 20
)

// FlowWindow bounds how many unacknowledged bytes one stream may have in
// flight.
//
// Without it a bulk stream fills the shared socket buffer and every later
// frame - including the first response of a newly opened stream - queues
// behind it. That turns a saturated lane into multi-second latency for
// interactive traffic. With a window, the sender stops at N unacknowledged
// bytes, so the worst-case queueing delay is window / link rate.
type FlowWindow struct {
	mu       sync.Mutex
	window   int64
	inflight int64
	acked    uint64
	sent     uint64
	closed   bool
	notify   chan struct{}
}

// NewFlowWindow creates a window of the given size in bytes.
func NewFlowWindow(window int64) *FlowWindow {
	if window <= 0 {
		window = defaultFlowWindow
	}
	return &FlowWindow{window: window, notify: make(chan struct{})}
}

// Acquire reserves n bytes of credit, blocking while the window is full.
func (f *FlowWindow) Acquire(n int64) error {
	if f == nil || n <= 0 {
		return nil
	}
	deadline := time.Now().Add(flowStallTimeout)

	for {
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			return io.ErrClosedPipe
		}
		if f.inflight+n <= f.window {
			f.inflight += n
			f.sent += uint64(n)
			f.mu.Unlock()
			return nil
		}
		wait := f.notify
		f.mu.Unlock()

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return ErrFlowStalled
		}
		timer := time.NewTimer(remaining)
		select {
		case <-wait:
			timer.Stop()
		case <-timer.C:
			return ErrFlowStalled
		}
	}
}

// Refund returns credit for bytes that were reserved but never written.
func (f *FlowWindow) Refund(n int64) {
	if f == nil || n <= 0 {
		return
	}
	f.mu.Lock()
	if n >= f.inflight {
		f.inflight = 0
	} else {
		f.inflight -= n
	}
	if uint64(n) >= f.sent {
		f.sent = 0
	} else {
		f.sent -= uint64(n)
	}
	f.signalLocked()
	f.mu.Unlock()
}

// Ack releases credit for cum bytes consumed by the peer. cum is cumulative,
// so a lost or reordered ACK cannot over-credit the sender.
func (f *FlowWindow) Ack(cum uint64) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	if cum > f.sent {
		cum = f.sent
	}
	if cum <= f.acked {
		return
	}
	delta := int64(cum - f.acked)
	f.acked = cum
	if delta >= f.inflight {
		f.inflight = 0
	} else {
		f.inflight -= delta
	}
	f.signalLocked()
}

// Inflight reports the number of unacknowledged bytes, for tests and stats.
func (f *FlowWindow) Inflight() int64 {
	if f == nil {
		return 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.inflight
}

// Close unblocks every waiter. The stream is gone, so no further data flows.
func (f *FlowWindow) Close() {
	if f == nil {
		return
	}
	f.mu.Lock()
	if !f.closed {
		f.closed = true
		f.signalLocked()
	}
	f.mu.Unlock()
}

func (f *FlowWindow) signalLocked() {
	close(f.notify)
	f.notify = make(chan struct{})
}

// AckTracker turns bytes consumed by the application into throttled ACK
// frames: one ACK per threshold bytes, which keeps the reverse-direction
// overhead negligible while still refilling the sender's window promptly.
type AckTracker struct {
	mu        sync.Mutex
	threshold uint64
	consumed  uint64
	pending   uint64
}

// NewAckTracker sizes the ACK threshold from the stream window.
func NewAckTracker(window uint64) *AckTracker {
	threshold := window / 8
	if threshold < 16*1024 {
		threshold = 16 * 1024
	}
	if threshold > 256*1024 {
		threshold = 256 * 1024
	}
	return &AckTracker{threshold: threshold}
}

// Consume records n consumed bytes and reports whether an ACK is due, along
// with the cumulative byte count to send.
func (a *AckTracker) Consume(n int) (uint64, bool) {
	if a == nil || n <= 0 {
		return 0, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.consumed += uint64(n)
	a.pending += uint64(n)
	if a.pending < a.threshold {
		return a.consumed, false
	}
	a.pending = 0
	return a.consumed, true
}

// Consumed returns the cumulative consumed byte count.
func (a *AckTracker) Consumed() uint64 {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.consumed
}

// EncodeAck builds the 8-byte ACK payload (cumulative consumed bytes).
func EncodeAck(cum uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, cum)
	return buf
}

// DecodeAck parses an ACK payload.
func DecodeAck(payload []byte) (uint64, bool) {
	if len(payload) < 8 {
		return 0, false
	}
	return binary.BigEndian.Uint64(payload[:8]), true
}
