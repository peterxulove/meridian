package main

import (
	"context"
	"net"
	"testing"
	"time"

	"meridian/pkg/config"
)

func TestDialRaceFallsBackPastBlackhole(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())

	// 10.255.255.1 is a blackhole: the connect never completes, so only the
	// staggered fallback can make this succeed.
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialRace(ctx, []string{"10.255.255.1", "127.0.0.1"}, port)
	if err != nil {
		t.Fatalf("dialRace failed: %v", err)
	}
	conn.Close()

	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("fallback took %v, want well under the dial timeout", elapsed)
	}
}

func TestDialRaceReturnsErrorWhenAllFail(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close() // nothing is listening now

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if conn, err := dialRace(ctx, []string{"127.0.0.1"}, port); err == nil {
		conn.Close()
		t.Fatal("expected an error when the only address refuses")
	}
}

func TestPreferIPv4KeepsAllAddresses(t *testing.T) {
	got := preferIPv4([]string{"2001:db8::1", "192.0.2.9", "2001:db8::2", "192.0.2.1"})
	want := []string{"192.0.2.9", "192.0.2.1", "2001:db8::1", "2001:db8::2"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestDialUDPTarget(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 256)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()

	s, err := NewServer(config.ServerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := s.dialUDPTarget(context.Background(), pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("dialUDPTarget: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("echo = %q, want ping", buf[:n])
	}
}
