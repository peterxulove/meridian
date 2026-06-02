// Package main — SOCKS5 proxy server (RFC 1928 + RFC 1929)
//
// This file implements a complete SOCKS5 proxy that:
//   - Listens on a configurable address (0.0.0.0:1080 by default for LAN access)
//   - Supports CONNECT command (TCP tunnel) for all destination types
//   - Supports UDP ASSOCIATE command (UDP tunnel) with dynamic relay listeners
//   - Supports DOMAIN NAME, IPv4, and IPv6 target address types
//   - Optionally enforces username/password authentication (RFC 1929)
//   - Uses robust public DNS (8.8.8.8 + 1.1.1.1 over both UDP and TCP) to avoid local DNS failures
//   - Limits concurrent connections via a semaphore to avoid "too many open files"
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
	cmdConnect      = 0x01
	cmdUDPAssociate = 0x03

	// Address types
	addrIPv4   = 0x01
	addrDomain = 0x03
	addrIPv6   = 0x04

	// Reply codes
	replySuccess          = 0x00
	replyGeneralFailure   = 0x01
	replyNotAllowed       = 0x02
	replyNetUnreachable   = 0x03
	replyHostUnreachable  = 0x04
	replyConnRefused      = 0x05
	replyCmdNotSupported  = 0x07
	replyAddrNotSupported = 0x08

	// maxConcurrent limits how many connections are in flight simultaneously.
	// Prevents "too many open files" on systems with low ulimits.
	maxConcurrent = 512
)

var dnsServers = []string{
	"223.5.5.5:53",       // AliDNS (China)
	"119.29.29.29:53",    // DNSPod (China)
	"114.114.114.114:53", // 114DNS (China)
	"8.8.8.8:53",         // Google DNS
	"1.1.1.1:53",         // Cloudflare DNS
}

// publicResolver is a net.Resolver that uses public DNS servers (AliDNS, Tencent, Google, Cloudflare)
// to avoid local DNS failures. It tries UDP first, then TCP fallback with a fast 1-second timeout per server
// to prevent lookup hangs in case certain servers are blocked.
var publicResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 1 * time.Second}
		// Try UDP first
		for _, server := range dnsServers {
			conn, err := d.DialContext(ctx, "udp", server)
			if err == nil {
				return conn, nil
			}
		}
		// Try TCP fallback
		for _, server := range dnsServers {
			conn, err := d.DialContext(ctx, "tcp", server)
			if err == nil {
				return conn, nil
			}
		}
		return nil, fmt.Errorf("all public DNS resolvers timed out or failed")
	},
}

// publicDialer dials upstream connections using the public DNS resolver.
var publicDialer = &net.Dialer{
	Timeout:   15 * time.Second,
	KeepAlive: 30 * time.Second,
	Resolver:  publicResolver,
}



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
	sem        chan struct{} // concurrency limiter

	// Stats
	mu       sync.Mutex
	active   int
	total    uint64
	bytesIn  uint64
	bytesOut uint64
	failed   uint64
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
		sem:        make(chan struct{}, maxConcurrent),
	}
}

// Start begins listening for SOCKS5 connections.
func (s *Socks5Server) Start() error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("socks5: listen %s: %w", s.listenAddr, err)
	}
	s.listener = ln
	fmt.Printf("  [SOCKS5] Listening on %s (LAN, max %d concurrent)\n", s.listenAddr, maxConcurrent)
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
func (s *Socks5Server) Stats() (active int, total, failed, bytesIn, bytesOut uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active, s.total, s.failed, s.bytesIn, s.bytesOut
}

func (s *Socks5Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return // listener closed — normal shutdown
		}

		// Acquire semaphore slot (non-blocking: drop connection if saturated).
		select {
		case s.sem <- struct{}{}:
		default:
			conn.Close()
			s.mu.Lock()
			s.failed++
			s.mu.Unlock()
			logf("[warn] connection limit reached (%d), dropped %s", maxConcurrent, conn.RemoteAddr())
			continue
		}

		s.mu.Lock()
		s.active++
		s.total++
		s.mu.Unlock()

		go func(c net.Conn) {
			defer func() {
				c.Close()
				<-s.sem // release slot
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

	// ── Phase 3: read CONNECT / UDP ASSOCIATE request ─────────────────────
	cmd, target, err := s.readRequest(conn)
	if err != nil {
		logf("socks5: [%s] request error: %v", conn.RemoteAddr(), err)
		return
	}

	if cmd == cmdUDPAssociate {
		s.handleUDPAssociate(conn, target)
		return
	}

	logf("socks5: [%s] → %s", conn.RemoteAddr(), target)

	// ── Phase 4: dial upstream using public DNS ────────────────────────────
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	upstream, err := s.dial(ctx, "tcp", target)
	if err != nil {
		logf("socks5: [%s] dial %s failed: %v", conn.RemoteAddr(), target, err)
		s.writeReply(conn, replyHostUnreachable, nil)
		s.mu.Lock()
		s.failed++
		s.mu.Unlock()
		return
	}
	defer upstream.Close()

	// ── Phase 5: send success reply ────────────────────────────────────────
	localAddr, _ := upstream.LocalAddr().(*net.TCPAddr)
	s.writeReply(conn, replySuccess, localAddr)

	// ── Phase 6: relay traffic bidirectionally ────────────────────────────
	conn.SetDeadline(time.Time{}) // remove deadline for data phase
	upstream.SetDeadline(time.Time{})
	s.relay(conn, upstream)
}

// handleUDPAssociate implements SOCKS5 UDP Associate (CMD = 0x03) relay.
func (s *Socks5Server) handleUDPAssociate(conn net.Conn, clientUDPAddrStr string) {
	localTCPAddr, ok := conn.LocalAddr().(*net.TCPAddr)
	var listenIP net.IP
	if ok {
		listenIP = localTCPAddr.IP
	} else {
		listenIP = net.IPv4zero
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: listenIP, Port: 0})
	if err != nil {
		logf("socks5: [%s] UDP associate listen failed: %v", conn.RemoteAddr(), err)
		s.writeReply(conn, replyGeneralFailure, nil)
		return
	}
	defer udpConn.Close()

	boundUDPAddr := udpConn.LocalAddr().(*net.UDPAddr)
	logf("socks5: [%s] UDP associate bound to UDP %s", conn.RemoteAddr(), boundUDPAddr)

	// Send success reply with the bound UDP IP and Port
	s.writeReply(conn, replySuccess, &net.TCPAddr{IP: boundUDPAddr.IP, Port: boundUDPAddr.Port})

	// Keep the TCP control connection open to maintain the UDP association.
	tcpClosed := make(chan struct{})
	go func() {
		defer close(tcpClosed)
		buf := make([]byte, 256)
		for {
			conn.SetDeadline(time.Now().Add(60 * time.Second))
			_, err := conn.Read(buf)
			if err != nil {
				return // TCP connection closed or timed out
			}
		}
	}()

	relayDone := make(chan struct{})
	go s.udpRelay(udpConn, tcpClosed, relayDone)

	select {
	case <-tcpClosed:
		logf("socks5: [%s] UDP associate TCP closed, terminating session", conn.RemoteAddr())
	case <-relayDone:
		logf("socks5: [%s] UDP associate relay finished", conn.RemoteAddr())
	}
}

// udpRelay acts as a UDP relay server, multiplexing packets from the SOCKS5 client.
func (s *Socks5Server) udpRelay(udpConn *net.UDPConn, tcpClosed chan struct{}, relayDone chan struct{}) {
	defer close(relayDone)

	// Map to keep track of active outbound UDP sockets (client remote address string -> client UDP conn)
	outConns := make(map[string]*net.UDPConn)
	var mu sync.Mutex

	defer func() {
		mu.Lock()
		for _, c := range outConns {
			c.Close()
		}
		mu.Unlock()
	}()

	// Immediately close the UDP listener if the TCP control connection is terminated
	go func() {
		<-tcpClosed
		udpConn.Close()
	}()

	buf := make([]byte, 65535)
	for {
		n, remoteAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			return // normal termination when udpConn is closed
		}

		if n < 10 {
			continue // SOCKS5 UDP header must be at least 10 bytes
		}

		// Parse SOCKS5 UDP Header (RFC 1928 Section 7):
		// RSV: buf[0:2] (must be 0x00 0x00)
		// FRAG: buf[2] (current fragment, must be 0x00 as we don't support fragmentation)
		// ATYP: buf[3] (0x01 = IPv4, 0x03 = Domain, 0x04 = IPv6)
		if buf[0] != 0x00 || buf[1] != 0x00 || buf[2] != 0x00 {
			continue
		}

		atyp := buf[3]
		var host string
		var port int
		var offset int

		switch atyp {
		case addrIPv4:
			host = net.IP(buf[4:8]).String()
			port = int(buf[8])<<8 | int(buf[9])
			offset = 10
		case addrIPv6:
			if n < 22 {
				continue
			}
			host = "[" + net.IP(buf[4:20]).String() + "]"
			port = int(buf[20])<<8 | int(buf[21])
			offset = 22
		case addrDomain:
			domainLen := int(buf[4])
			if n < 7+domainLen {
				continue
			}
			host = string(buf[5 : 5+domainLen])
			port = int(buf[5+domainLen])<<8 | int(buf[6+domainLen])
			offset = 7 + domainLen
		default:
			continue
		}

		targetAddr := fmt.Sprintf("%s:%d", host, port)
		payload := buf[offset:n]

		clientKey := remoteAddr.String()
		mu.Lock()
		outConn, exists := outConns[clientKey]
		if !exists {
			outConn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
			if err != nil {
				mu.Unlock()
				logf("socks5: outbound UDP listen failed: %v", err)
				continue
			}
			outConns[clientKey] = outConn

			// Relay response packets from the target back to the client
			go func(cAddr *net.UDPAddr, cOut *net.UDPConn) {
				defer func() {
					cOut.Close()
					mu.Lock()
					delete(outConns, cAddr.String())
					mu.Unlock()
				}()

				respBuf := make([]byte, 65535)
				for {
					rn, tAddr, err := cOut.ReadFromUDP(respBuf)
					if err != nil {
						return
					}

					header := make([]byte, 22)
					header[0] = 0x00
					header[1] = 0x00
					header[2] = 0x00 // FRAG = 0

					var hLen int
					tIP := tAddr.IP.To4()
					if tIP != nil {
						header[3] = addrIPv4
						copy(header[4:8], tIP)
						header[8] = byte(tAddr.Port >> 8)
						header[9] = byte(tAddr.Port & 0xff)
						hLen = 10
					} else {
						header[3] = addrIPv6
						copy(header[4:20], tAddr.IP.To16())
						header[20] = byte(tAddr.Port >> 8)
						header[21] = byte(tAddr.Port & 0xff)
						hLen = 22
					}

					packet := make([]byte, hLen+rn)
					copy(packet[0:hLen], header[0:hLen])
					copy(packet[hLen:], respBuf[:rn])

					udpConn.WriteToUDP(packet, cAddr)
				}
			}(remoteAddr, outConn)
		}
		mu.Unlock()

		// Resolve destination target UDP address and forward the packet
		go func(cOut *net.UDPConn, tAddr string, pay []byte) {
			tUDPAddr, err := net.ResolveUDPAddr("udp", tAddr)
			if err != nil {
				// If local resolution fails, fallback to custom public DNS resolver
				thost, tportStr, err2 := net.SplitHostPort(tAddr)
				if err2 == nil {
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					ips, err3 := publicResolver.LookupIPAddr(ctx, thost)
					cancel()
					if err3 == nil && len(ips) > 0 {
						var tport int
						fmt.Sscan(tportStr, &tport)
						tUDPAddr = &net.UDPAddr{IP: ips[0].IP, Port: tport}
					}
				}
			}
			if tUDPAddr != nil {
				cOut.WriteToUDP(pay, tUDPAddr)
			}
		}(outConn, targetAddr, payload)
	}
}

// negotiate sends the supported auth methods and selects one.
func (s *Socks5Server) negotiate(conn net.Conn) error {
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

	chosen := byte(authNoAccept)
	if s.username == "" {
		for _, m := range methods {
			if m == authNone {
				chosen = authNone
				break
			}
		}
	} else {
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
	ver := make([]byte, 1)
	if _, err := io.ReadFull(conn, ver); err != nil {
		return err
	}
	ulenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, ulenBuf); err != nil {
		return err
	}
	uname := make([]byte, ulenBuf[0])
	if _, err := io.ReadFull(conn, uname); err != nil {
		return err
	}
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

// readRequest reads the SOCKS5 CONNECT/UDP ASSOCIATE request and returns "host:port".
func (s *Socks5Server) readRequest(conn net.Conn) (byte, string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, "", err
	}
	if header[0] != socks5Version {
		return 0, "", fmt.Errorf("unexpected version %d in request", header[0])
	}
	cmd := header[1]
	if cmd != cmdConnect && cmd != cmdUDPAssociate {
		s.writeReply(conn, replyCmdNotSupported, nil)
		return 0, "", fmt.Errorf("command %d not supported (only CONNECT and UDP ASSOCIATE)", cmd)
	}

	var host string
	switch header[3] {
	case addrIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return 0, "", err
		}
		host = net.IP(addr).String()
	case addrIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return 0, "", err
		}
		host = "[" + net.IP(addr).String() + "]"
	case addrDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return 0, "", err
		}
		domainBuf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return 0, "", err
		}
		host = string(domainBuf)
	default:
		s.writeReply(conn, replyAddrNotSupported, nil)
		return 0, "", fmt.Errorf("unsupported address type %d", header[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return 0, "", err
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])
	return cmd, fmt.Sprintf("%s:%d", host, port), nil
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
		reply[8] = byte(boundAddr.Port >> 8)
		reply[9] = byte(boundAddr.Port & 0xff)
	}
	conn.Write(reply)
}

// relay copies traffic between client and upstream connections bidirectionally.
func (s *Socks5Server) relay(client, upstream net.Conn) {
	done := make(chan struct{}, 2)

	pipe := func(dst, src net.Conn, counter *uint64) {
		defer func() { done <- struct{}{} }()
		n, _ := io.Copy(dst, src)
		s.mu.Lock()
		*counter += uint64(n)
		s.mu.Unlock()
		// Half-close the write side so the other goroutine's Read returns EOF.
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		} else {
			dst.Close()
		}
	}

	go pipe(upstream, client, &s.bytesIn)
	go pipe(client, upstream, &s.bytesOut)
	<-done
	<-done
}

// logf logs a formatted message with timestamp to stdout.
func logf(format string, args ...any) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(os.Stdout, "[%s] "+format+"\n", append([]any{ts}, args...)...)
}
