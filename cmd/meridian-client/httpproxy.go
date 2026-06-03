package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type HttpProxyServer struct {
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

// NewHttpProxyServer creates a new HTTP proxy server.
func NewHttpProxyServer(listenAddr, username, password string, dialFn func(ctx context.Context, network, addr string) (net.Conn, error)) *HttpProxyServer {
	return &HttpProxyServer{
		listenAddr: listenAddr,
		username:   username,
		password:   password,
		dial:       dialFn,
		sem:        make(chan struct{}, maxConcurrent),
	}
}

func (s *HttpProxyServer) Start() error {
	l, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	s.listener = l
	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

func (s *HttpProxyServer) Stop() {
	s.stopOnce.Do(func() {
		if s.listener != nil {
			s.listener.Close()
		}
		s.wg.Wait()
	})
}

func (s *HttpProxyServer) Stats() (active int, total, failed, bytesIn, bytesOut uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active, s.total, s.failed, s.bytesIn, s.bytesOut
}

func (s *HttpProxyServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return // listener closed — normal shutdown
		}

		select {
		case s.sem <- struct{}{}:
		default:
			conn.Close()
			s.mu.Lock()
			s.failed++
			s.mu.Unlock()
			continue
		}

		s.mu.Lock()
		s.active++
		s.total++
		s.mu.Unlock()

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			defer conn.Close()
			
			s.handleConn(conn)

			s.mu.Lock()
			s.active--
			s.mu.Unlock()
		}()
	}
}

func (s *HttpProxyServer) handleConn(conn net.Conn) {
	// Set initial read deadline
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		s.mu.Lock()
		s.failed++
		s.mu.Unlock()
		return
	}
	
	// Check auth if configured
	if s.username != "" || s.password != "" {
		authHeader := req.Header.Get("Proxy-Authorization")
		if authHeader == "" || !s.checkAuth(authHeader) {
			conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Meridian Proxy\"\r\n\r\n"))
			s.mu.Lock()
			s.failed++
			s.mu.Unlock()
			return
		}
	}
	
	// Clear the read deadline so the tunnel can stay open
	conn.SetReadDeadline(time.Time{})

	if req.Method == http.MethodConnect {
		s.handleConnect(conn, req)
	} else {
		s.handlePlainHTTP(conn, reader, req)
	}
}

func (s *HttpProxyServer) checkAuth(authHeader string) bool {
	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		return false
	}
	payload, err := base64.StdEncoding.DecodeString(authHeader[len(prefix):])
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(payload), ":", 2)
	if len(parts) != 2 {
		return false
	}
	return parts[0] == s.username && parts[1] == s.password
}

func (s *HttpProxyServer) handleConnect(conn net.Conn, req *http.Request) {
	host := req.URL.Host
	if !strings.Contains(host, ":") {
		host = host + ":443" // Default to HTTPS port for CONNECT
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	upstream, err := s.dial(ctx, "tcp", host)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		s.mu.Lock()
		s.failed++
		s.mu.Unlock()
		return
	}
	defer upstream.Close()

	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	s.relay(conn, upstream)
}

func (s *HttpProxyServer) handlePlainHTTP(conn net.Conn, clientReader *bufio.Reader, req *http.Request) {
	// Must have an absolute URL for proxy requests
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	host := req.URL.Host
	if !strings.Contains(host, ":") {
		host = host + ":80"
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	upstream, err := s.dial(ctx, "tcp", host)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		s.mu.Lock()
		s.failed++
		s.mu.Unlock()
		return
	}
	defer upstream.Close()

	// Rewrite request line to relative path
	req.RequestURI = ""
	
	// Remove Proxy-Connection header
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	
	// We need to write the modified request to the upstream
	err = req.Write(upstream)
	if err != nil {
		s.mu.Lock()
		s.failed++
		s.mu.Unlock()
		return
	}

	// For plain HTTP, we also need to copy any buffered data in the reader that wasn't part of the request
	// But `req.Write(upstream)` already writes the Body if it was parsed.
	// Actually, wait, `http.ReadRequest` reads the headers, but leaves the body in `req.Body`.
	// `req.Write(upstream)` will consume `req.Body`. This is correct.
	// But HTTP/1.1 might use keep-alive on the proxy connection.
	// We'll just do a bidirectional relay for simplicity, because some HTTP requests might be upgraded (e.g. WebSocket).
	// Oh, but `req.Write(upstream)` consumed the body. So if we start relaying now, we'll only relay SUBSEQUENT requests, which is fine for keep-alive, or WebSocket upgrades.
	// Actually, `http.ReadRequest` might wrap the connection. Let's just relay from `clientReader` instead of `conn` for the client->upstream direction to catch any buffered bytes.
	
	s.relayWithReader(conn, clientReader, upstream)
}

func (s *HttpProxyServer) relay(client net.Conn, upstream net.Conn) {
	s.relayWithReader(client, client, upstream)
}

func (s *HttpProxyServer) relayWithReader(clientConn net.Conn, clientReader io.Reader, upstream net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			defer cw.CloseWrite()
		} else {
			defer upstream.Close()
		}
		n, _ := io.Copy(upstream, clientReader)
		s.mu.Lock()
		s.bytesOut += uint64(n)
		s.mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		if cw, ok := clientConn.(interface{ CloseWrite() error }); ok {
			defer cw.CloseWrite()
		} else {
			defer clientConn.Close()
		}
		n, _ := io.Copy(clientConn, upstream)
		s.mu.Lock()
		s.bytesIn += uint64(n)
		s.mu.Unlock()
	}()

	wg.Wait()
}
