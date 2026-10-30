package transport

import (
	"io"
	"net/http"
	"net/http/httptest"

	"testing"

	"meridian/pkg/config"
)

// TestClientALPNHasNoProtocolName guards the one field a passive observer can
// read straight out of the handshake: the ALPN list in the cleartext
// ClientHello. Any token that names the tunnel ("meridian-1") makes every
// later anti-detection measure pointless.
func TestClientALPNHasNoProtocolName(t *testing.T) {
	cfg, err := ClientTLSConfig(config.ClientConfig{
		SNISpoof:    "cover.example",
		Fingerprint: config.FingerprintChromeWin,
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, list := range map[string][]string{
		"quic": alpnClientQUIC,
		"ws":   alpnClientWS,
		"tls":  cfg.NextProtos,
	} {
		for _, p := range list {
			if !isBrowserALPN(p) {
				t.Errorf("%s ALPN offers %q, which a browser never sends", name, p)
			}
		}
	}
	if len(alpnClientQUIC) != 1 || alpnClientQUIC[0] != "h3" {
		t.Errorf("QUIC ALPN = %v, want [h3]", alpnClientQUIC)
	}
	if len(cfg.NextProtos) == 0 {
		t.Error("client TLS config has no ALPN, which makes the handshake fail")
	}
}

// TestRealityWithoutPinStillVerifiesCertificate guards a silent downgrade: a
// REALITY client with no SPKI pin used to skip certificate verification
// entirely, so deleting one config line turned the tunnel into an unverified
// TLS session.
func TestRealityWithoutPinStillVerifiesCertificate(t *testing.T) {
	cfg, err := ClientTLSConfig(config.ClientConfig{
		RealityMode: true,
		SNISpoof:    "cover.example",
		Fingerprint: config.FingerprintChromeWin,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify is set without a pin: the server certificate is not authenticated")
	}
	if cfg.ServerName != "cover.example" {
		t.Errorf("ServerName = %q, want the configured SNI", cfg.ServerName)
	}
}

func TestRealityWithPinDisablesChainCheck(t *testing.T) {
	cfg, err := ClientTLSConfig(config.ClientConfig{
		RealityMode:     true,
		SNISpoof:        "cover.example",
		RealitySPKIHash: []byte("0123456789abcdef0123456789abcdef"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.InsecureSkipVerify || cfg.VerifyPeerCertificate == nil {
		t.Error("expected chain check to be replaced by the SPKI pin")
	}
}

// TestFallbackServesCoverSite covers the probe path: a plain GET to the tunnel
// port (and to the tunnel path itself) must return the cover site, not Go's
// "404 page not found" or the upgrader's 400.
func TestFallbackServesCoverSite(t *testing.T) {
	cover := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "cover:"+r.URL.Path)
	}))
	defer cover.Close()

	l := NewWSListener(config.ServerConfig{
		ListenAddr:  "127.0.0.1:0",
		WSSPath:     "/ws/",
		FallbackURL: cover.URL,
	})
	srv := httptest.NewServer(l.fallback)
	defer srv.Close()

	for _, path := range []string{"/", "/index.html", "/ws/"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || string(body) != "cover:"+path {
			t.Errorf("GET %s = %d %q, want the cover site", path, resp.StatusCode, body)
		}
	}
}

func TestFallbackWithoutCoverIs404(t *testing.T) {
	l := NewWSListener(config.ServerConfig{ListenAddr: "127.0.0.1:0", WSSPath: "/ws/"})
	srv := httptest.NewServer(l.fallback)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when no fallback is configured", resp.StatusCode)
	}
}

// TestFallbackTransportIsBounded guards the probe path against stalls: every
// phase needs a deadline, and the TLS hop must not attempt an HTTP/2 upgrade
// (the preface exchange is one more place for a proxy to sit waiting).
func TestFallbackTransportIsBounded(t *testing.T) {
	tr := fallbackTransport("https", "cover.example")
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.ServerName != "cover.example" {
		t.Error("TLS hop does not verify against the configured cover name")
	}
	if got := tr.TLSClientConfig.NextProtos; len(got) != 1 || got[0] != "http/1.1" {
		t.Errorf("NextProtos = %v, want [http/1.1]", got)
	}
	if tr.ResponseHeaderTimeout <= 0 || tr.TLSHandshakeTimeout <= 0 {
		t.Error("fallback transport has unbounded phases: a stalled cover site would pin a probe")
	}
}

// TestFallbackKeepsVirtualHostForAddressTarget: when the cover site is reached
// by address (the usual loopback case) the request is still for the virtual
// host the probe named, so the Host header must survive. Rewriting it to the
// address sends the request to the server's default vhost, which is exactly
// the case that answers with a rejection.
func TestFallbackKeepsVirtualHostForAddressTarget(t *testing.T) {
	var gotHost string
	cover := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
	}))
	defer cover.Close()

	l := NewWSListener(config.ServerConfig{ListenAddr: "127.0.0.1:0", FallbackURL: cover.URL})
	srv := httptest.NewServer(l.fallback)
	defer srv.Close()

	req, err := http.NewRequest("GET", srv.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "cover.example"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotHost != "cover.example" {
		t.Errorf("Host forwarded as %q, want the probe's virtual host", gotHost)
	}
}

func isBrowserALPN(p string) bool {
	switch p {
	case "h3", "h2", "http/1.1":
		return true
	}
	return false
}
