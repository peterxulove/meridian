package transport

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"meridian/pkg/config"
)

// TestHTTPPOSTTransportHandshake drives the real client transport against the
// real mirror handler over TLS, without needing two running binaries.
//
// This covers the pull-based read path: the client uploads a frame, then polls
// with an empty upload until the server's reply (written by the tunnel
// handler) comes back.
func TestHTTPPOSTTransportHandshake(t *testing.T) {
	cfg := config.ServerConfig{MirrorPath: "/upload"}
	listener := NewMirrorListener(cfg)

	mux := http.NewServeMux()
	mux.Handle("/upload", listener.Handler())

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	host := srv.Listener.Addr().String()

	clientCfg := config.ClientConfig{
		MirrorPath:  "/upload",
		UploadURL:   "https://" + host + "/upload",
		DialTimeout: 10 * time.Second,
	}

	tr := NewHTTPPOSTTransport(clientCfg)
	tlsCfg, err := ClientTLSConfig(clientCfg)
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}
	tlsCfg.NextProtos = []string{"http/1.1"}
	// The test server uses its own self-signed cert.
	tlsCfg.InsecureSkipVerify = true
	tlsCfg.VerifyPeerCertificate = nil
	setTransportTLS(tr, tlsCfg)

	conn, err := tr.Dial(host)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	// Server side: accept the session the client's first upload creates, then
	// answer with a ServerHello once the ClientHello arrives.
	type result struct {
		got []byte
		err error
	}
	resCh := make(chan result, 1)

	go func() {
		sess, err := listener.Accept()
		if err != nil {
			resCh <- result{err: err}
			return
		}
		buf := make([]byte, 512)
		n, err := sess.Read(buf)
		if err != nil {
			resCh <- result{err: err}
			return
		}
		// Echo the payload back with a marker prefix, standing in for ServerHello.
		reply := append([]byte("SH:"), buf[:n]...)
		if _, err := sess.Write(reply); err != nil {
			resCh <- result{err: err}
			return
		}
		resCh <- result{got: buf[:n]}
	}()

	// Client writes its "ClientHello".
	if _, err := conn.Write([]byte("CH-1234567890")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Client reads the reply; Read must poll until the server answers.
	resp := make([]byte, 512)
	conn.(net.Conn).SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if got, want := string(resp[:n]), "SH:CH-1234567890"; got != want {
		t.Errorf("round-trip mismatch: got %q want %q", got, want)
	}

	select {
	case r := <-resCh:
		if r.err != nil {
			t.Fatalf("server side: %v", r.err)
		}
		if string(r.got) != "CH-1234567890" {
			t.Errorf("server received %q", string(r.got))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server side never completed")
	}
}

// writeMultipartReused keeps the multipart writer used by the client transport
// honest; the helper in httppost_transport_test.go covers the server side.
var _ = bytes.MinRead
