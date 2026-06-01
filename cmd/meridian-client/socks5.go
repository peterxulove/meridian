// Package main — SOCKS5 proxy server (RFC 1928 + RFC 1929)
//
// This file implements a complete SOCKS5 proxy that:
//   - Listens on a configurable address (0.0.0.0:1080 by default for LAN access)
//   - Supports CONNECT command (TCP tunnel) for all destination types
//   - Supports DOMAIN NAME, IPv4, and IPv6 target address types
//   - Optionally enforces username/password authentication (RFC 1929)
//   - Forwards traffic through the Meridian encrypted tunnel to the server
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// SOCKS5 protocol constants (RFC 1928).
const (
	socks5Version = 0x05

	// Authentication methods
	authNone     = 0x00
	authPassword = 0x02
	authNoAccept = 0xFF

	// Commands
	cmdConnect = 0x01

	// Address types
	addrIPv4   = 0x01
	addrDomain = 0x03
	addrIPv6   = 0x04

	// Reply codes
	replySuccess         = 0x00
	replyGeneralFailure  = 0x01
	replyNotAllowed      = 0x02
	replyNetUnreachable  = 0x03
	replyHostUnreachable = 0x04
	replyConnRefused     = 0x05
	replyCmdNotSupported = 0x07
	replyAddrNotSupported = 0x08
)

// Socks5Server is a SOCKS5 proxy server that forwards connections through
// the Meridian encrypted tunnel.
type Socks5Server struct {
	listenAddr string
	username   string
	password   string
	dial       func(ctx context.Context, network, addr string) (net.Conn, error)
	listener   net.Listener
	stopOnce   sync.Once
	wg         sync.WaitGroup

	// Stats
	mu       sync.Mutex
	active   int
	total    uint64
	bytesIn  uint64
	bytesOut uint64
}

// NewSocks5Server creates a new SOCKS5 server.
// dialFn is called to establish the upstream (Meridian-tunnelled) connection.
// If username/password are empty, no authentication is required.
func NewSocks5Server(listenAddr, username, password string, dialFn func(ctx context.Context, network, addr string) (net.Conn, error)) *Socks5Server {
	return &Socks5Server{
		listenAddr: listenAddr,
		username:   username,
		password:   password,
		dial:       dialFn,
	}
}

// Start begins listening for SOCKS5 connections.
func (s *Socks5Server) Start() error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("socks5: listen %s: %w", s.listenAddr, err)
	}
	s.listener = ln
	fmt.Printf("  [SOCKS5] Listening on %s (serving LAN)\n", s.listenAddr)
	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

// Stop gracefully shuts down the SOCKS5 server.
func (s *Socks5Server) Stop() {
	s.stopOnce.Do(func() {
		if s.listener != nil {
			s.listener.Close()
		}
	})
	s.wg.Wait()
}

// Stats returns current connection metrics.
func (s *Socks5Server) Stats() (active int, total, bytesIn, bytesOut uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active, s.total, s.bytesIn, s.bytesOut
}

func (s *Socks5Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			// Listener closed — normal shutdown
			return
		}
		s.mu.Lock()
		s.active++
		s.total++
		s.mu.Unlock()

		go func(c net.Conn) {
			defer func() {
				c.Close()
				s.mu.Lock()
				s.active--
				s.mu.Unlock()
			}()
			s.handleConn(c)
		}(conn)
	}
}

// handleConn processes a single SOCKS5 client connection.
func (s *Socks5Server) handleConn(conn net.Conn) {
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// ── Phase 1: negotiate authentication method ──────────────────────────
	if err := s.negotiate(conn); err != nil {
		logf("socks5: [%s] negotiation failed: %v", conn.RemoteAddr(), err)
		return
	}

	// ── Phase 2: authenticate if required ────────────────────────────────
	if s.username != "" {
		if err := s.authenticate(conn); err != nil {
			logf("socks5: [%s] auth failed: %v", conn.RemoteAddr(), err)
			return
		}
	}

	// ── Phase 3: read CONNECT request ────────────────────────────────────
	target, err := s.readRequest(conn)
	if err != nil {
		logf("socks5: [%s] request error: %v", conn.RemoteAddr(), err)
		return
	}

	logf("socks5: [%s] → %s", conn.RemoteAddr(), target)

	// ── Phase 4: dial upstream (Meridian tunnel or direct) ────────────────
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	upstream, err := s.dial(ctx, "tcp", target)
	if err != nil {
		logf("socks5: [%s] dial %s failed: %v", conn.RemoteAddr(), target, err)
		s.writeReply(conn, replyHostUnreachable, nil)
		return
	}
	defer upstream.Close()

	// ── Phase 5: send success reply ────────────────────────────────────────
	localAddr := upstream.LocalAddr().(*net.TCPAddr)
	s.writeReply(conn, replySuccess, localAddr)

	// ── Phase 6: relay traffic bidirectionally ────────────────────────────
	conn.SetDeadline(time.Time{}) // remove deadline for data phase
	upstream.SetDeadline(time.Time{})
	s.relay(conn, upstream)
}

// negotiate sends the supported auth methods and selects one.
func (s *Socks5Server) negotiate(conn net.Conn) error {
	// Read VER + NMETHODS
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != socks5Version {
		return fmt.Errorf("unsupported SOCKS version %d", header[0])
	}
	nmethods := int(header[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// Choose method
	chosen := byte(authNoAccept)
	if s.username == "" {
		// No auth required — accept if client offers method 0
		for _, m := range methods {
			if m == authNone {
				chosen = authNone
				break
			}
		}
	} else {
		// Username/password auth
		for _, m := range methods {
			if m == authPassword {
				chosen = authPassword
				break
			}
		}
	}

	_, err := conn.Write([]byte{socks5Version, chosen})
	if err != nil {
		return err
	}
	if chosen == authNoAccept {
		return fmt.Errorf("no acceptable authentication method")
	}
	return nil
}

// authenticate performs RFC 1929 username/password authentication.
func (s *Socks5Server) authenticate(conn net.Conn) error {
	// Sub-negotiation version
	ver := make([]byte, 1)
	if _, err := io.ReadFull(conn, ver); err != nil {
		return err
	}
	// Read username
	ulenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, ulenBuf); err != nil {
		return err
	}
	uname := make([]byte, ulenBuf[0])
	if _, err := io.ReadFull(conn, uname); err != nil {
		return err
	}
	// Read password
	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenBuf); err != nil {
		return err
	}
	passwd := make([]byte, plenBuf[0])
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return err
	}

	if string(uname) != s.username || string(passwd) != s.password {
		conn.Write([]byte{0x01, 0x01}) // failure
		return fmt.Errorf("invalid credentials from %s", conn.RemoteAddr())
	}
	_, err := conn.Write([]byte{0x01, 0x00}) // success
	return err
}

// readRequest reads the SOCKS5 CONNECT request and returns "host:port".
func (s *Socks5Server) readRequest(conn net.Conn) (string, error) {
	// VER CMD RSV ATYP
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}
	if header[0] != socks5Version {
		return "", fmt.Errorf("unexpected version %d in request", header[0])
	}
	if header[1] != cmdConnect {
		// Send "command not supported" and abort
		s.writeReply(conn, replyCmdNotSupported, nil)
		return "", fmt.Errorf("command %d not supported (only CONNECT)", header[1])
	}

	// Parse destination address
	var host string
	switch header[3] {
	case addrIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()
	case addrIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = "[" + net.IP(addr).String() + "]"
	case addrDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", err
		}
		domainBuf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return "", err
		}
		host = string(domainBuf)
	default:
		s.writeReply(conn, replyAddrNotSupported, nil)
		return "", fmt.Errorf("unsupported address type %d", header[3])
	}

	// Read port (big-endian uint16)
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", err
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])

	return fmt.Sprintf("%s:%d", host, port), nil
}

// writeReply sends the SOCKS5 reply to the client.
func (s *Socks5Server) writeReply(conn net.Conn, code byte, boundAddr *net.TCPAddr) {
	reply := []byte{socks5Version, code, 0x00, addrIPv4, 0, 0, 0, 0, 0, 0}
	if boundAddr != nil {
		ip := boundAddr.IP.To4()
		if ip == nil {
			ip = []byte{0, 0, 0, 0}
		}
		copy(reply[4:8], ip)
		port := boundAddr.Port
		reply[8] = byte(port >> 8)
		reply[9] = byte(port & 0xff)
	}
	conn.Write(reply)
}

// relay copies traffic between client and upstream connections bidirectionally.
// It tracks byte counts for statistics.
func (s *Socks5Server) relay(client, upstream net.Conn) {
	done := make(chan struct{}, 2)

	copy := func(dst, src net.Conn, counter *uint64) {
		defer func() { done <- struct{}{} }()
		n, _ := io.Copy(dst, src)
		s.mu.Lock()
		*counter += uint64(n)
		s.mu.Unlock()
		// Signal the other direction to stop by closing the connection
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}

	go copy(upstream, client, &s.bytesIn)
	go copy(client, upstream, &s.bytesOut)

	// Wait for both directions to finish (or one side closes)
	<-done
	<-done
}

// logf logs a formatted message with timestamp to stdout.
func logf(format string, args ...any) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(os.Stdout, "[%s] "+format+"\n", append([]any{ts}, args...)...)
}
