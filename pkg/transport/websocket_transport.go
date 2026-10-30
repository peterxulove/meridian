package transport

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"meridian/pkg/config"
)

// WSListener is the server-side WebSocket listener stub.
type WSListener struct {
	config config.ServerConfig
	connch chan net.Conn
	done   chan struct{}
	srv    *http.Server
	// fallback answers everything that is not a tunnel upgrade: probes, wrong
	// paths, and browsers. Nil-safe: newFallbackHandler always returns a
	// handler, and a 404 when no cover site is configured.
	fallback http.Handler
	once     sync.Once
}

func NewWSListener(cfg config.ServerConfig) *WSListener {
	return &WSListener{
		config:   cfg,
		connch:   make(chan net.Conn, 50),
		done:     make(chan struct{}),
		fallback: newFallbackHandler(cfg),
	}
}

func (l *WSListener) ListenAndServe() error {
	path := "/ws/"
	if l.config.WSSPath != "" {
		path = l.config.WSSPath
	}

	upgrader := websocket.Upgrader{
		ReadBufferSize:  64 * 1024,
		WriteBufferSize: 64 * 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins for the tunnel
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		// A plain GET on the tunnel path is an active probe, not a client:
		// the upgrader would answer "400 Bad Request" plus a
		// Sec-WebSocket-Version header, which is a different response than the
		// cover site gives for the same URL. Send it to the cover site.
		if !websocket.IsWebSocketUpgrade(r) {
			l.fallback.ServeHTTP(w, r)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		wsConn := &WSConn{conn: conn}
		select {
		case l.connch <- wsConn:
		case <-l.done:
			_ = wsConn.Close()
		case <-time.After(5 * time.Second):
			_ = wsConn.Close()
		}
	})
	mux.Handle("/", l.fallback)

	server := &http.Server{
		Addr:              l.config.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	l.srv = server

	if l.config.ServerCertFile != "" && l.config.ServerKeyFile != "" {
		// Mirror the tunnel ALPN list. Without it the client's
		// NextProtos{"meridian-1","h3"} has nothing to negotiate against and
		// the handshake dies with "tls: no application protocol".
		// http/1.1 comes first: gorilla's dialer upgrades over HTTP/1.1, so
		// negotiating a tunnel-only ALPN makes the handshake itself fail.
		server.TLSConfig = &tls.Config{
			NextProtos: alpnServerWS,
		}
		return server.ListenAndServeTLS(l.config.ServerCertFile, l.config.ServerKeyFile)
	}
	return server.ListenAndServe()
}

func (l *WSListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connch:
		return conn, nil
	case <-l.done:
		return nil, errors.New("listener closed")
	}
}

func (l *WSListener) Close() error {
	l.once.Do(func() {
		close(l.done)
		if l.srv != nil {
			_ = l.srv.Close()
		}
	})
	return nil
}

// newFallbackHandler builds the response used for anything that is not a
// tunnel upgrade.
//
// With FallbackURL set the listener becomes a transparent reverse proxy for a
// real site: same status codes, headers and body, so a prober that GETs the
// port sees the cover site rather than Go's "404 page not found". Without it
// the old 404 behaviour is kept, which is still a fingerprint — but an honest
// one, and better than silently proxying somewhere unexpected.
func newFallbackHandler(cfg config.ServerConfig) http.Handler {
	if cfg.FallbackURL == "" {
		return http.NotFoundHandler()
	}
	target, err := url.Parse(cfg.FallbackURL)
	if err != nil || target.Scheme == "" || target.Host == "" {
		fmt.Printf("  [WSS] invalid fallback_url %q, serving 404 instead\n", cfg.FallbackURL)
		return http.NotFoundHandler()
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	inner := proxy.Director
	proxy.Director = func(r *http.Request) {
		inner(r)
		// A cover site reached by address (loopback, typically) is the same
		// virtual host the probe asked for, so its own name must survive:
		// rewriting it to "127.0.0.1" sends the request to whatever the server
		// answers by default, which is usually a rejection. A cover site
		// reached by name is a different site, and needs its own Host.
		if net.ParseIP(target.Hostname()) == nil {
			r.Host = target.Host
		}
	}
	proxy.Transport = fallbackTransport(target.Scheme, cfg.FallbackSNI)
	// A cover site that is down must not leak Go's proxy error page.
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}
	return proxy
}

// fallbackTransport builds the connection used to reach the cover site.
//
// Two properties matter more than throughput. First, every phase has a
// deadline: a probe must never be able to hold a handler open by pointing the
// fallback at something that stops responding. Second, the TLS hop is pinned
// to HTTP/1.1 — an HTTP/2 upgrade here buys nothing and its preface exchange
// is one more way for the proxy to stall on a server that negotiated h2 but
// answers slowly.
func fallbackTransport(scheme, sni string) *http.Transport {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		DialContext:           dialer.DialContext,
		MaxIdleConns:          16,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
	}
	if scheme == "https" {
		tr.TLSClientConfig = &tls.Config{
			ServerName: sni,
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
		}
	}
	return tr
}

// ---------------------------------------------------------------------------
// WSConn — second WebSocket adapter (used by websocket_transport.go callers)
// ---------------------------------------------------------------------------

// WSConn is a net.Conn adapter around a gorilla WebSocket connection.
type WSConn struct {
	conn    *websocket.Conn
	reader  io.Reader
	writeMu sync.Mutex
	once    sync.Once
}

// Read implements io.Reader.
// It reads directly from the current WebSocket message instead of calling
// ReadMessage, which allocated and copied every frame before the caller could
// consume it. At 500 Mbps that extra copy is measurable.
func (c *WSConn) Read(b []byte) (int, error) {
	for {
		if c.reader != nil {
			n, err := c.reader.Read(b)
			if err == io.EOF {
				c.reader = nil
				if n > 0 {
					return n, nil
				}
				continue
			}
			if n == 0 && err == nil {
				continue
			}
			return n, err
		}

		typ, reader, err := c.conn.NextReader()
		if err != nil {
			return 0, err
		}
		if typ != websocket.BinaryMessage {
			_, _ = io.Copy(io.Discard, reader)
			continue
		}
		c.reader = reader
	}
}

// Write implements io.Writer.
func (c *WSConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	writer, err := c.conn.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return 0, err
	}
	if _, err := writer.Write(b); err != nil {
		_ = writer.Close()
		return 0, err
	}
	if err := writer.Close(); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *WSConn) Close() error {
	var err error
	c.once.Do(func() { err = c.conn.Close() })
	return err
}
func (c *WSConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *WSConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *WSConn) SetDeadline(t time.Time) error {
	if err := c.conn.SetReadDeadline(t); err != nil {
		return err
	}
	return c.conn.SetWriteDeadline(t)
}

func (c *WSConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *WSConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// WSDial dials a WebSocket server and returns a WSConn.
func WSDial(serverURL string, cfg config.ClientConfig) (*WSConn, error) {
	tlsConfig, err := ClientTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	// The upgrade runs over HTTP/1.1, but the ClientHello is cleartext: offer
	// the same list a browser would, and let the server pick http/1.1 (it
	// prefers it). Adding a tunnel-specific token here would name the protocol
	// to every DPI on the path.
	tlsConfig.NextProtos = alpnClientWS

	// websocket.DefaultDialer is a shared package-level value; mutating its
	// TLSClientConfig would leak this config into every other dialer user.
	dialer := &websocket.Dialer{
		TLSClientConfig:  tlsConfig,
		HandshakeTimeout: 15 * time.Second,
		ReadBufferSize:   64 * 1024,
		WriteBufferSize:  64 * 1024,
	}

	conn, _, err := dialer.Dial(serverURL, nil)
	if err != nil {
		return nil, err
	}
	return &WSConn{conn: conn}, nil
}
