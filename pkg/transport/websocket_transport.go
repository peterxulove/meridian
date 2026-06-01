package transport

import (
	"errors"
	"net"
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
	_ = path
	return errors.New("transport: WebSocket server not yet implemented")
}

func (l *WSListener) Close() error { return nil }

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
// Currently a stub; a production implementation would perform the HTTP upgrade.
func WSDial(serverURL, path string) (*WSConn, error) {
	return nil, errors.New("transport: WSDial not yet implemented")
}
