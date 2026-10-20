package transport

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"meridian/pkg/config"
)

// TestMirrorSessionRoundTrip exercises the session plumbing the HTTP-POST
// tunnel relies on: an upload feeds uplink bytes, and a later poll request
// returns whatever the tunnel handler wrote back as downlink.
func TestMirrorSessionRoundTrip(t *testing.T) {
	l := NewMirrorListener(config.ServerConfig{MirrorPath: "/upload"})

	// First upload: no session header → server allocates one.
	body := &bytes.Buffer{}
	writeMultipart(t, body, []byte("client-hello-bytes"))

	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=testboundary")
	w := httptest.NewRecorder()
	l.Handler().ServeHTTP(w, req)

	sid := w.Header().Get(MirrorSessionHeader)
	if sid == "" {
		t.Fatal("server did not allocate a mirror session")
	}

	// Accept delivers the reconstructed session to the tunnel handler.
	conn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

	// The tunnel handler reads the uploaded ClientHello.
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "client-hello-bytes" {
		t.Errorf("uplink mismatch: got %q", string(buf[:n]))
	}

	// The tunnel handler writes ServerHello; a poll request must carry it back.
	if _, err := conn.Write([]byte("server-hello-bytes")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	poll := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(nil))
	poll.Header.Set("Content-Type", "multipart/form-data; boundary=testboundary")
	poll.Header.Set(MirrorSessionHeader, sid)
	poll.Header.Set(mirrorPollHeader, "1")
	pw := httptest.NewRecorder()
	l.Handler().ServeHTTP(pw, poll)

	if got := pw.Body.String(); got != "server-hello-bytes" {
		t.Errorf("downlink mismatch: got %q", got)
	}

	// Second upload must reuse the same session, not create a new one.
	body2 := &bytes.Buffer{}
	writeMultipart(t, body2, []byte("more"))
	req2 := httptest.NewRequest(http.MethodPost, "/upload", body2)
	req2.Header.Set("Content-Type", "multipart/form-data; boundary=testboundary")
	req2.Header.Set(MirrorSessionHeader, sid)
	w2 := httptest.NewRecorder()
	l.Handler().ServeHTTP(w2, req2)

	if got := w2.Header().Get(MirrorSessionHeader); got != sid {
		t.Errorf("session not reused: got %q want %q", got, sid)
	}

	select {
	case <-l.connch:
		t.Error("reused session was handed to Accept again")
	case <-time.After(50 * time.Millisecond):
	}
}

func writeMultipart(t *testing.T, buf *bytes.Buffer, payload []byte) {
	t.Helper()
	buf.WriteString("--testboundary\r\n")
	buf.WriteString("Content-Disposition: form-data; name=\"file\"; filename=\"upload.tmp\"\r\n")
	buf.WriteString("Content-Type: application/octet-stream\r\n\r\n")
	buf.Write(payload)
	buf.WriteString("\r\n--testboundary--\r\n")
}
