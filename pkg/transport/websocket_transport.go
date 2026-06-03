package transport

import (
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"meridian/pkg/config"
)

// WSListener is the server-side WebSocket listener stub.
type WSListener struct {
	config config.ServerConfig
	connch chan net.Conn
}

func NewWSListener(cfg config.ServerConfig) *WSListener {
	return &WSListener{config: cfg, connch: make(chan net.Conn, 50)}
}

func (l *WSListener) ListenAndServe() error {
	path := "/ws/"
	if l.config.WSSPath != "" {
		path = l.config.WSSPath
	}

	upgrader := websocket.Upgrader{
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
		l.connch <- wsConn
	})

	server := &http.Server{
		Addr:    l.config.ListenAddr,
		Handler: mux,
	}

	if l.config.ServerCertFile != "" && l.config.ServerKeyFile != "" {
		return server.ListenAndServeTLS(l.config.ServerCertFile, l.config.ServerKeyFile)
	}
	return server.ListenAndServe()
}

func (l *WSListener) Accept() (net.Conn, error) {
	conn, ok := <-l.connch
	if !ok {
		return nil, errors.New("listener closed")
	}
	return conn, nil
}

func (l *WSListener) Close() error { 
	close(l.connch)
	return nil 
}

// ---------------------------------------------------------------------------
// WSConn — second WebSocket adapter (used by websocket_transport.go callers)
// ---------------------------------------------------------------------------

// WSConn is a net.Conn adapter around a gorilla WebSocket connection.
type WSConn struct {
	conn   *websocket.Conn
	buf    []byte // leftover bytes from a partially consumed message
	closed bool
}

// Read implements io.Reader.
// Fix #11: previous code discarded the error from ReadMessage and returned (copy(b,msg), nil).
// If msg is empty on error, this would loop infinitely. Now errors are propagated.
func (c *WSConn) Read(b []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(b, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	_, msg, err := c.conn.ReadMessage()
	if err != nil {
		return 0, err // Fix: propagate error
	}
	n := copy(b, msg)
	if n < len(msg) {
		c.buf = msg[n:]
	}
	return n, nil
}

// Write implements io.Writer.
// Fix #10: previous code returned (0, nil) unconditionally.
func (c *WSConn) Write(b []byte) (int, error) {
	err := c.conn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil // Fix: return actual byte count
}

func (c *WSConn) Close() error { c.closed = true; return c.conn.Close() }
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
	dialer := websocket.DefaultDialer
	// Apply TLS config
	tlsConfig, err := ClientTLSConfig(cfg)
	if err == nil {
		dialer.TLSClientConfig = tlsConfig
	}
	conn, _, err := dialer.Dial(serverURL, nil)
	if err != nil {
		return nil, err
	}
	return &WSConn{conn: conn}, nil
}
