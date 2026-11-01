package main

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// deadlineRecordingConn records every deadline the proxy sets on the SOCKS
// control connection. The UDP association must clear the handshake deadline
// and never install another one: a QUIC connection can be idle for minutes
// while the browser sits on a page, and a timer here kills it silently.
type deadlineRecordingConn struct {
	net.Conn
	mu        sync.Mutex
	deadlines []time.Time
}

func (c *deadlineRecordingConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, t)
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

func (c *deadlineRecordingConn) lastDeadline() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.deadlines) == 0 {
		return time.Time{}, false
	}
	return c.deadlines[len(c.deadlines)-1], true
}

func (c *deadlineRecordingConn) waitForZeroDeadline(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		for _, d := range c.deadlines {
			if d.IsZero() {
				c.mu.Unlock()
				return true
			}
		}
		c.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

func TestUDPAssociateClearsHandshakeDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	s := NewSocks5Server("127.0.0.1:0", "", "", nil, 4)
	recorded := make(chan *deadlineRecordingConn, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		rc := &deadlineRecordingConn{Conn: conn}
		recorded <- rc
		s.handleUDPAssociate(rc, "")
		conn.Close()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read UDP associate reply: %v", err)
	}
	if reply[1] != replySuccess {
		t.Fatalf("UDP associate reply code = %d, want %d", reply[1], replySuccess)
	}

	rc := <-recorded
	if !rc.waitForZeroDeadline(2 * time.Second) {
		t.Fatal("UDP associate never cleared the handshake deadline")
	}

	// A periodic deadline (the old 60s loop) would show up here. The
	// association must stay alive for as long as its TCP control connection.
	time.Sleep(150 * time.Millisecond)
	if d, ok := rc.lastDeadline(); !ok || !d.IsZero() {
		t.Fatalf("UDP associate installed a new deadline %v", d)
	}

	select {
	case <-done:
		t.Fatal("UDP associate closed while its control connection was idle")
	case <-time.After(200 * time.Millisecond):
	}
}
