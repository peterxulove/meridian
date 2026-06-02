package transport

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"meridian/pkg/config"
	"meridian/pkg/crypto"
)

// ---------------------------------------------------------------------------
// WSConnection — WebSocket adapter implementing net.Conn
// ---------------------------------------------------------------------------

// WSConnection wraps a gorilla WebSocket connection and exposes a net.Conn interface.
type WSConnection struct {
	conn   *websocket.Conn
	buf    []byte // leftover bytes from a partially consumed message
	closed bool
}

// Read implements io.Reader.
// Fix #11: previous code returned (0, nil) on any websocket error, which caused
// callers to spin in a busy loop waiting for data that never arrives. Now errors
// are propagated so callers can detect connection closure.
func (c *WSConnection) Read(b []byte) (int, error) {
	// Drain any leftover bytes from a previous message first.
	if len(c.buf) > 0 {
		n := copy(b, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}

	_, msg, err := c.conn.ReadMessage()
	if err != nil {
		return 0, err // Fix: propagate error instead of returning (0, nil)
	}
	n := copy(b, msg)
	if n < len(msg) {
		c.buf = msg[n:] // save unread bytes for next Read call
	}
	return n, nil
}

// Write implements io.Writer.
// Fix #10: previous code always returned (0, nil) regardless of outcome.
// net.Conn callers rely on the returned byte count to detect short writes.
func (c *WSConnection) Write(b []byte) (int, error) {
	err := c.conn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err // Fix: report error
	}
	return len(b), nil // Fix: return actual bytes written
}

func (c *WSConnection) Close() error {
	c.closed = true
	return c.conn.Close()
}

func (c *WSConnection) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *WSConnection) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *WSConnection) SetDeadline(t time.Time) error {
	if err := c.conn.SetReadDeadline(t); err != nil {
		return err
	}
	return c.conn.SetWriteDeadline(t)
}

func (c *WSConnection) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *WSConnection) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// HTTPPOSTTransport is a stub for the HTTP-POST mirror mode transport.
type HTTPPOSTTransport struct{ config config.ClientConfig }

func NewHTTPPOSTTransport(cfg config.ClientConfig) *HTTPPOSTTransport {
	return &HTTPPOSTTransport{config: cfg}
}

func (t *HTTPPOSTTransport) Dial(addr string) (net.Conn, error) {
	return nil, errors.New("transport: HTTP-POST transport not yet implemented")
}

// ---------------------------------------------------------------------------
// TLSConfig
// ---------------------------------------------------------------------------

// ServerTLSConfig builds a *tls.Config for the server.
func ServerTLSConfig(cfg config.ServerConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		NextProtos: []string{"meridian-1", "h3"},
		MinVersion: tls.VersionTLS13,
	}

	if cfg.ServerCertFile != "" && cfg.ServerKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ServerCertFile, cfg.ServerKeyFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	} else {
		// Generate self-signed cert if none provided
		cert, err := generateSelfSignedCert()
		if err == nil {
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
	}
	return tlsConfig, nil
}

// ClientTLSConfig builds a *tls.Config for the client.
func ClientTLSConfig(cfg config.ClientConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		NextProtos: []string{"meridian-1", "h3"},
		MinVersion: tls.VersionTLS13,
	}

	// Client side: REALITY mode uses SPKI pinning instead of normal CA chain.
	if cfg.RealityMode {
		tlsConfig.InsecureSkipVerify = true // CA chain verification bypassed; SPKI pin used instead.
		if len(cfg.RealitySPKIHash) > 0 {
			expectedSPKI := make([]byte, len(cfg.RealitySPKIHash))
			copy(expectedSPKI, cfg.RealitySPKIHash)
			tlsConfig.VerifyPeerCertificate = func(certs [][]byte, _ [][]*x509.Certificate) error {
				if len(certs) == 0 {
					return errors.New("transport: no certificates presented by server")
				}
				parsed, err := x509.ParseCertificate(certs[0])
				if err != nil {
					return errors.New("transport: failed to parse server certificate")
				}
				spkiDER, err := x509.MarshalPKIXPublicKey(parsed.PublicKey)
				if err != nil {
					return errors.New("transport: failed to marshal server SPKI")
				}
				h := sha256.Sum256(spkiDER)
				// Fix #9: was != 0 (rejects matching certs). Must be == 0 (reject when NOT equal).
				if subtle.ConstantTimeCompare(h[:], expectedSPKI) == 0 {
					return errors.New("transport: server SPKI hash does not match pinned value")
				}
				return nil
			}
		}
	}
	return tlsConfig, nil
}

// generateSelfSignedCert is a placeholder for self-signed certificate generation.
func generateSelfSignedCert() (tls.Certificate, error) {
	return tls.Certificate{}, errors.New("transport: self-signed cert generation not yet implemented")
}

// Ensure unused imports are used.
var (
	_ = strings.Split
	_ = crypto.GenerateKeyPair
	_ = io.EOF
)
