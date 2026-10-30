package transport

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime/multipart"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"meridian/pkg/anti"
	"meridian/pkg/config"
	"meridian/pkg/crypto"
)

// HTTPPOSTTransport implements the HTTP-POST mirror mode: Meridian frames are
// wrapped in multipart/form-data uploads so traffic looks like a cloud storage
// backup, and the HTTP response body carries the downlink back to the client.
//
// Each Write() is one POST; the response body is buffered into a read queue so
// the caller sees a single bidirectional net.Conn. Because a POST only returns
// data when the client sends, the server piggybacks downlink bytes on whatever
// request arrives next (optionally an empty keepalive POST).
type HTTPPOSTTransport struct {
	config config.ClientConfig

	client *http.Client
	url    string

	// sessionID is the mirror session allocated by the server on the first
	// upload. Every subsequent POST must carry it, otherwise the server would
	// treat each request as a brand-new tunnel.
	sessionID string

	// tlsCfg, when set, overrides the config-derived TLS settings. Tests use
	// it to talk to a server with an ephemeral certificate.
	tlsCfg *tls.Config

	mu        sync.Mutex
	readBuf   []byte
	readCond  *sync.Cond
	closed    bool
	closeOnce sync.Once
}

func NewHTTPPOSTTransport(cfg config.ClientConfig) *HTTPPOSTTransport {
	t := &HTTPPOSTTransport{config: cfg}
	t.readCond = sync.NewCond(&t.mu)
	return t
}

// setTransportTLS installs an explicit TLS config and HTTP client, bypassing
// the certificate/REALITY setup in Dial. It exists so tests can point the
// transport at httptest.NewTLSServer, whose certificate is generated per run
// and therefore cannot be pinned ahead of time.
func setTransportTLS(t *HTTPPOSTTransport, tlsCfg *tls.Config) {
	t.tlsCfg = tlsCfg
}

// Dial prepares the transport. The remote address is ignored: the target is
// taken from cfg.UploadURL, which is what makes the traffic look like a
// third-party cloud upload rather than a connection to the tunnel server.
func (t *HTTPPOSTTransport) Dial(addr string) (net.Conn, error) {
	url := t.config.UploadURL
	if url == "" {
		host := addr
		if host == "" {
			host = t.config.ServerAddr
		}
		path := t.config.MirrorPath
		if path == "" {
			path = "/upload"
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		url = "https://" + strings.TrimSuffix(host, "/") + path
	}
	t.url = url

	tlsConfig := t.tlsCfg
	if tlsConfig == nil {
		var err error
		tlsConfig, err = ClientTLSConfig(t.config)
		if err != nil {
			return nil, err
		}
		// The mirror endpoint is plain HTTPS carrying multipart uploads, so
		// the ALPN must offer http/1.1. Leaving the QUIC tunnel list
		// ("meridian-1","h3") makes the TLS handshake complete but the server
		// then closes the connection with "no application protocol".
		tlsConfig.NextProtos = []string{"http/1.1"}
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}
	t.client = &http.Client{
		Transport: transport,
		Timeout:   t.config.DialTimeout,
	}
	return t, nil
}

// Write uploads one Meridian frame as a multipart form field and queues the
// response body for subsequent Read calls.
func (t *HTTPPOSTTransport) Write(b []byte) (int, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return 0, errors.New("transport: HTTP-POST connection closed")
	}
	t.mu.Unlock()

	if t.client == nil {
		return 0, errors.New("transport: HTTP-POST transport not dialed")
	}

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	if t.config.MirrorBoundary != "" {
		if err := w.SetBoundary(t.config.MirrorBoundary); err != nil {
			return 0, err
		}
	}

	field := t.config.MirrorPath
	if field == "" {
		field = "file"
	}
	part, err := w.CreateFormFile(field, "upload.tmp")
	if err != nil {
		return 0, err
	}
	if _, err := part.Write(b); err != nil {
		return 0, err
	}
	if err := w.Close(); err != nil {
		return 0, err
	}

	req, err := http.NewRequest(http.MethodPost, t.url, &body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("User-Agent", defaultMirrorUserAgent)

	t.mu.Lock()
	sid := t.sessionID
	t.mu.Unlock()
	if sid != "" {
		req.Header.Set(MirrorSessionHeader, sid)
	}
	if len(b) == 0 {
		req.Header.Set(mirrorPollHeader, "1")
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("transport: HTTP-POST upload rejected with status %d", resp.StatusCode)
	}

	// Remember the session the server handed us so later uploads join the
	// same tunnel instead of opening a new one per request.
	if newSID := resp.Header.Get(MirrorSessionHeader); newSID != "" && newSID != sid {
		t.mu.Lock()
		t.sessionID = newSID
		t.mu.Unlock()
	}

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	if len(payload) > 0 {
		t.mu.Lock()
		t.readBuf = append(t.readBuf, payload...)
		t.mu.Unlock()
		t.readCond.Broadcast()
	}
	return len(b), nil
}

// Read returns bytes received in response bodies, blocking until data arrives
// or the transport is closed.
//
// HTTP-POST is pull-based: the server can only hand downlink bytes back in a
// response to a request. So when nothing is pending we send an empty keepalive
// POST, which both keeps the session alive and polls for new downlink data.
// Without this the handshake would block forever waiting for ServerHello.
func (t *HTTPPOSTTransport) Read(b []byte) (int, error) {
	for {
		t.mu.Lock()
		if len(t.readBuf) > 0 {
			n := copy(b, t.readBuf)
			t.readBuf = t.readBuf[n:]
			t.mu.Unlock()
			return n, nil
		}
		closed := t.closed
		t.mu.Unlock()

		if closed {
			return 0, io.EOF
		}

		// Poll for downlink. This must not go through Write: Write appends to
		// readBuf and then takes t.mu, which would self-deadlock because
		// sync.Mutex is not reentrant.
		if err := t.pollOnce(); err != nil {
			return 0, err
		}

		t.mu.Lock()
		if len(t.readBuf) > 0 {
			t.mu.Unlock()
			continue
		}
		t.mu.Unlock()

		// Back off so an idle tunnel does not spin on HTTP requests.
		time.Sleep(mirrorPollInterval)
	}
}

// pollOnce sends one empty upload and queues whatever downlink the server
// returns. Callers must not hold t.mu; it appends to readBuf via queue.
func (t *HTTPPOSTTransport) pollOnce() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return io.EOF
	}
	sid := t.sessionID
	t.mu.Unlock()

	if t.client == nil {
		return errors.New("transport: HTTP-POST transport not dialed")
	}

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	if t.config.MirrorBoundary != "" {
		if err := w.SetBoundary(t.config.MirrorBoundary); err != nil {
			return err
		}
	}
	part, err := w.CreateFormFile("poll", "poll.tmp")
	if err != nil {
		return err
	}
	if _, err := part.Write(nil); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, t.url, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("User-Agent", defaultMirrorUserAgent)
	req.Header.Set(mirrorPollHeader, "1")
	if sid != "" {
		req.Header.Set(MirrorSessionHeader, sid)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("transport: HTTP-POST poll rejected with status %d", resp.StatusCode)
	}

	if newSID := resp.Header.Get(MirrorSessionHeader); newSID != "" && newSID != sid {
		t.mu.Lock()
		t.sessionID = newSID
		t.mu.Unlock()
	}

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if len(payload) > 0 {
		t.mu.Lock()
		t.readBuf = append(t.readBuf, payload...)
		t.mu.Unlock()
		t.readCond.Broadcast()
	}
	return nil
}

func (t *HTTPPOSTTransport) Close() error {
	t.closeOnce.Do(func() {
		t.mu.Lock()
		t.closed = true
		sid := t.sessionID
		t.mu.Unlock()
		t.readCond.Broadcast()

		// Tell the server to drop the session instead of waiting for its
		// reaper to time the session out.
		if sid != "" && t.client != nil && t.url != "" {
			req, err := http.NewRequest(http.MethodDelete, t.url, nil)
			if err == nil {
				req.Header.Set(MirrorSessionHeader, sid)
				if resp, err := t.client.Do(req); err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}
		}
		if t.client != nil {
			t.client.CloseIdleConnections()
		}
	})
	return nil
}

func (t *HTTPPOSTTransport) LocalAddr() net.Addr  { return httpPostAddr{} }
func (t *HTTPPOSTTransport) RemoteAddr() net.Addr { return httpPostAddr{} }

func (t *HTTPPOSTTransport) SetDeadline(_ time.Time) error      { return nil }
func (t *HTTPPOSTTransport) SetReadDeadline(_ time.Time) error  { return nil }
func (t *HTTPPOSTTransport) SetWriteDeadline(_ time.Time) error { return nil }

// httpPostAddr is a placeholder net.Addr; the transport has no socket of its own.
type httpPostAddr struct{}

func (httpPostAddr) Network() string { return "http-post" }
func (httpPostAddr) String() string  { return "http-post" }

// defaultMirrorUserAgent mimics a common backup client so the uploads blend in
// with ordinary cloud-storage traffic.
const defaultMirrorUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// mirrorPollInterval is how long the client waits between empty keepalive
// uploads when no downlink data is pending. It is deliberately short: the
// server long-polls for up to mirrorLongPollTimeout, so a request that
// returns empty really means "nothing queued right now".
const mirrorPollInterval = 2 * time.Millisecond

// mirrorPollHeader marks a request as a pure downlink poll (no payload).
const mirrorPollHeader = "Mir-Poll"

// ---------------------------------------------------------------------------
// TLSConfig
// ---------------------------------------------------------------------------

// ALPN lists.
//
// The client's list is the only one an observer can read: the TLS 1.3
// ClientHello travels in the clear (and, under QUIC, inside an Initial packet
// whose keys are derived from the public connection ID). Anything custom in it
// names the protocol on the wire, so the client offers exactly what a browser
// would. The server's list sits inside the encrypted ServerHello /
// EncryptedExtensions, so it can keep accepting the old "meridian-1" token to
// avoid breaking clients that have not been upgraded yet.
var (
	alpnClientQUIC = []string{"h3"}
	alpnClientWS   = []string{"h2", "http/1.1"}
	alpnServerQUIC = []string{"meridian-1", "h3"}
	alpnServerWS   = []string{"http/1.1", "meridian-1"}
)

// ServerTLSConfig builds a *tls.Config for the server.
func ServerTLSConfig(cfg config.ServerConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		NextProtos: alpnServerQUIC,
		MinVersion: tls.VersionTLS13,
	}

	if cfg.ServerCertFile != "" && cfg.ServerKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ServerCertFile, cfg.ServerKeyFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	} else {
		// Generate an ephemeral self-signed cert if none provided. Failure is
		// returned rather than swallowed: a server with no usable certificate
		// cannot complete a TLS handshake at all, and silently starting in
		// that state surfaces only as an opaque client-side timeout.
		cert, err := generateSelfSignedCert()
		if err != nil {
			return nil, fmt.Errorf("transport: no certificate configured and self-signed generation failed: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	return tlsConfig, nil
}

// ClientTLSConfig builds a *tls.Config for the client.
func ClientTLSConfig(cfg config.ClientConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		NextProtos: alpnClientWS,
		MinVersion: tls.VersionTLS13,
	}

	// Client side: REALITY mode can pin the server's SPKI key instead of
	// trusting a CA chain. Pinning is opt-in: a REALITY client with no pin is
	// downgraded to ordinary PKI verification rather than skipping the check
	// entirely, which is what it used to do (and meant that dropping one line
	// from the config silently disabled server authentication).
	if cfg.RealityMode {
		if len(cfg.RealitySPKIHash) > 0 {
			tlsConfig.InsecureSkipVerify = true // chain check replaced by the pin below
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

	// Apply the emulated TLS fingerprint last so it cannot clobber the REALITY
	// verification callback or the insecure-skip flag set above.
	anti.ApplyFingerprintWithSNI(tlsConfig, string(cfg.Fingerprint), cfg.SNISpoof)
	// The fingerprint may carry its own ALPN list. Replace it with the
	// browser-like one: whether the name is negotiated is irrelevant to us, the
	// MTP handshake identifies the tunnel, but a unique ALPN names the protocol
	// to every DPI that reads the ClientHello.
	tlsConfig.NextProtos = alpnClientWS

	return tlsConfig, nil
}

// generateSelfSignedCert mints an in-memory self-signed ECDSA certificate so
// a server with no configured cert/key still speaks TLS instead of failing.
//
// The certificate is ephemeral: it is regenerated on every start, so clients
// must authenticate it via REALITY SPKI pinning or InsecureSkipVerify rather
// than by trusting a stable identity.
func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("transport: key generation failed: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("transport: serial generation failed: %w", err)
	}

	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "meridian-ephemeral",
			Organization: []string{"Meridian"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * 365 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"meridian-ephemeral"},
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("transport: certificate creation failed: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("transport: key marshalling failed: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// Ensure unused imports are used.
var (
	_ = strings.Split
	_ = crypto.GenerateKeyPair
	_ = io.EOF
)

// serverMirrorTLS builds the TLS config for the HTTP-POST mirror endpoint.
//
// The mirror is plain HTTPS carrying multipart uploads, so ALPN must offer
// http/1.1. Offering only the tunnel ALPN makes the HTTP client fail with
// "protocol was given but is not supported".
func serverMirrorTLS(cfg config.ServerConfig) *tls.Config {
	tlsConfig := &tls.Config{
		NextProtos: []string{"http/1.1", "meridian-1"},
		MinVersion: tls.VersionTLS12,
	}

	if cfg.ServerCertFile != "" && cfg.ServerKeyFile != "" {
		if cert, err := tls.LoadX509KeyPair(cfg.ServerCertFile, cfg.ServerKeyFile); err == nil {
			tlsConfig.Certificates = []tls.Certificate{cert}
			return tlsConfig
		}
	}

	if cert, err := generateSelfSignedCert(); err == nil {
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	return tlsConfig
}
