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

	"meridian/pkg/config"
	"meridian/pkg/crypto"
)


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
