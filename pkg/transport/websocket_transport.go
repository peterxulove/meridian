package transport

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
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
	once   sync.Once
}

func NewWSListener(cfg config.ServerConfig) *WSListener {
	return &WSListener{
		config: cfg,
		connch: make(chan net.Conn, 50),
		done:   make(chan struct{}),
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
			NextProtos: []string{"http/1.1", "meridian-1"},
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

	// The WebSocket upgrade is a plain HTTP/1.1 handshake, so the ALPN must
	// advertise http/1.1. Reusing the QUIC tunnel list ("meridian-1","h3")
	// makes gorilla reject the negotiated protocol even though TLS succeeds.
	tlsConfig.NextProtos = []string{"http/1.1", "meridian-1"}

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
