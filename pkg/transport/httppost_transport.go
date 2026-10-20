// Package transport — HTTP-POST mirror server.
//
// The client (HTTPPOSTTransport) uploads each Meridian frame as a
// multipart/form-data POST and reads downlink bytes out of the response body.
// An HTTP request/response pair is inherently one-shot, so the server has to
// reconstruct a long-lived bidirectional stream out of many short requests.
//
// Design:
//   - Each POST carries a session cookie (or a Mir-Session header) that binds
//     it to a persistent tunnel session.
//   - The uploaded bytes are appended to that session's uplink queue, where
//     handleTCPTunnel reads them.
//   - The response body carries whatever downlink bytes are pending, so the
//     client's Write() doubles as a poll for downlink data.
package transport

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"meridian/pkg/config"
)

// MirrorSessionHeader is the header carrying the session id.
const MirrorSessionHeader = "Mir-Session"

// mirrorLongPollTimeout bounds how long a poll request waits for downlink
// bytes before returning an empty body.
const mirrorLongPollTimeout = 2 * time.Second

// ErrSessionNotFound is returned when a POST arrives without a valid session.
var ErrSessionNotFound = errors.New("transport: mirror session not found")

// MirrorSession is one long-lived tunnel reconstructed from many HTTP requests.
// It implements net.Conn so handleTCPTunnel can drive it unchanged.
type MirrorSession struct {
	id string

	mu        sync.Mutex
	up        []byte
	upCond    *sync.Cond
	down      []byte
	closed    bool
	closeOnce sync.Once

	lastSeen time.Time
}

func newMirrorSession(id string) *MirrorSession {
	s := &MirrorSession{id: id, lastSeen: time.Now()}
	s.upCond = sync.NewCond(&s.mu)
	return s
}

func (s *MirrorSession) ID() string { return s.id }

// touch records liveness; the reaper uses it to drop dead sessions.
func (s *MirrorSession) touch() {
	s.mu.Lock()
	s.lastSeen = time.Now()
	s.mu.Unlock()
}

// feed appends uplink bytes uploaded by the client.
func (s *MirrorSession) feed(b []byte) {
	s.mu.Lock()
	s.up = append(s.up, b...)
	s.lastSeen = time.Now()
	s.mu.Unlock()
	s.upCond.Broadcast()
}

// drainDownlink returns all pending downlink bytes.
func (s *MirrorSession) drainDownlink() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.down) == 0 {
		return nil
	}
	out := s.down
	s.down = nil
	return out
}

// Read implements net.Conn: blocks until uplink bytes are available.
func (s *MirrorSession) Read(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for len(s.up) == 0 {
		if s.closed {
			return 0, io.EOF
		}
		s.upCond.Wait()
	}

	n := copy(b, s.up)
	s.up = s.up[n:]
	return n, nil
}

// Write implements net.Conn: queues downlink bytes for the next response body.
func (s *MirrorSession) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, io.ErrClosedPipe
	}
	s.down = append(s.down, b...)
	return len(b), nil
}

func (s *MirrorSession) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.up = nil
		s.down = nil
		s.mu.Unlock()
		s.upCond.Broadcast()
	})
	return nil
}

func (s *MirrorSession) LocalAddr() net.Addr  { return httpPostAddr{} }
func (s *MirrorSession) RemoteAddr() net.Addr { return httpPostAddr{} }

func (s *MirrorSession) SetDeadline(_ time.Time) error      { return nil }
func (s *MirrorSession) SetReadDeadline(_ time.Time) error  { return nil }
func (s *MirrorSession) SetWriteDeadline(_ time.Time) error { return nil }

// MirrorListener accepts HTTP-POST uploads and hands each new session to the
// caller through Accept(), mirroring the net.Listener shape used by the
// WebSocket transport.
type MirrorListener struct {
	cfg    config.ServerConfig
	connch chan net.Conn
	done   chan struct{}

	mu       sync.Mutex
	sessions map[string]*MirrorSession
}

// NewMirrorListener creates an HTTP-POST mirror listener.
func NewMirrorListener(cfg config.ServerConfig) *MirrorListener {
	return &MirrorListener{
		cfg:      cfg,
		connch:   make(chan net.Conn, 50),
		done:     make(chan struct{}),
		sessions: make(map[string]*MirrorSession),
	}
}

func (l *MirrorListener) path() string {
	if l.cfg.MirrorPath != "" {
		return l.cfg.MirrorPath
	}
	return "/upload"
}

// Path returns the upload endpoint for logging.
func (l *MirrorListener) Path() string { return l.path() }

// session returns the session for id, creating it on first sight.
func (l *MirrorListener) session(id string) (*MirrorSession, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if s, ok := l.sessions[id]; ok {
		return s, false
	}
	s := newMirrorSession(id)
	l.sessions[id] = s
	return s, true
}

func (l *MirrorListener) lookup(id string) *MirrorSession {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sessions[id]
}

func (l *MirrorListener) drop(id string) {
	l.mu.Lock()
	if s, ok := l.sessions[id]; ok {
		s.Close()
		delete(l.sessions, id)
	}
	l.mu.Unlock()
}

// Accept blocks until a new session is created by an inbound POST.
func (l *MirrorListener) Accept() (net.Conn, error) {
	select {
	case c, ok := <-l.connch:
		if !ok {
			return nil, errors.New("transport: mirror listener closed")
		}
		return c, nil
	case <-l.done:
		return nil, errors.New("transport: mirror listener closed")
	}
}

func (l *MirrorListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	l.mu.Lock()
	for id, s := range l.sessions {
		s.Close()
		delete(l.sessions, id)
	}
	l.mu.Unlock()
	return nil
}

func (l *MirrorListener) Addr() net.Addr { return httpPostAddr{} }

// Handler returns the http.Handler serving uploads and negotiating sessions.
func (l *MirrorListener) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			l.handleUpload(w, r)
		case http.MethodDelete:
			l.handleClose(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

func (l *MirrorListener) handleUpload(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get(MirrorSessionHeader)

	if id == "" {
		// First contact: mint a session id and hand it back so the client can
		// reuse it for every subsequent upload.
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			http.Error(w, "session id generation failed", http.StatusInternalServerError)
			return
		}
		id = hex.EncodeToString(b)
	}

	sess, isNew := l.session(id)
	sess.touch()
	_ = isNew

	// Read the uploaded frame bytes. The client sends multipart/form-data, but
	// the raw body is exactly one Meridian frame, so the multipart wrapper is
	// stripped by parsing the first part.
	var payload []byte
	if r.MultipartForm == nil {
		if err := r.ParseMultipartForm(32 << 20); err == nil && r.MultipartForm != nil {
			for _, files := range r.MultipartForm.File {
				for _, fh := range files {
					f, err := fh.Open()
					if err != nil {
						continue
					}
					payload, _ = io.ReadAll(f)
					f.Close()
					break
				}
				break
			}
		}
	}
	if payload == nil {
		// Fall back to the raw body for non-multipart uploads.
		payload, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
	}

	if len(payload) > 0 {
		sess.feed(payload)
	}

	if isNew {
		select {
		case l.connch <- sess:
		default:
			// Backpressure: refuse rather than block the HTTP server.
			l.drop(id)
			http.Error(w, "too many pending sessions", http.StatusServiceUnavailable)
			return
		}
	}

	w.Header().Set(MirrorSessionHeader, id)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)

	// Piggyback pending downlink bytes on this response. A pure poll request
	// waits briefly for data to appear instead of returning empty immediately,
	// which keeps the client's polling rate sane without adding latency to
	// real traffic.
	if down := sess.drainDownlink(); len(down) > 0 {
		w.Write(down)
		return
	}

	if r.Header.Get(mirrorPollHeader) != "" {
		if down := sess.waitDownlink(mirrorLongPollTimeout); len(down) > 0 {
			w.Write(down)
		}
	}
}

// waitDownlink blocks until downlink bytes are queued or the timeout expires.
func (s *MirrorSession) waitDownlink(timeout time.Duration) []byte {
	deadline := time.Now().Add(timeout)
	for {
		s.mu.Lock()
		if len(s.down) > 0 || s.closed {
			out := s.down
			s.down = nil
			s.mu.Unlock()
			return out
		}
		s.mu.Unlock()

		if !time.Now().Before(deadline) {
			return nil
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (l *MirrorListener) handleClose(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get(MirrorSessionHeader)
	if id != "" {
		l.drop(id)
	}
	w.WriteHeader(http.StatusNoContent)
}

// reaper drops sessions that have gone quiet, so a client that disappears
// without sending DELETE does not leak memory on the server.
func (l *MirrorListener) reaper(timeout time.Duration) {
	ticker := time.NewTicker(timeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-l.done:
			return
		case <-ticker.C:
			// Collect candidates under l.mu, then reap outside it: taking
			// s.mu while holding l.mu risks a lock-order inversion with
			// handleUpload, which already holds s.mu via touch().
			l.mu.Lock()
			stale := make([]string, 0)
			for id, s := range l.sessions {
				s.mu.Lock()
				idle := time.Since(s.lastSeen)
				s.mu.Unlock()
				if idle > timeout {
					stale = append(stale, id)
				}
			}
			l.mu.Unlock()

			for _, id := range stale {
				l.drop(id)
			}
		}
	}
}

// ListenAndServe starts the mirror HTTP(S) server.
func (l *MirrorListener) ListenAndServe() error {
	go l.reaper(5 * time.Minute)

	mux := http.NewServeMux()
	mux.Handle(l.path(), l.Handler())

	srv := &http.Server{
		Addr:              l.cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
	}

	if l.cfg.ServerCertFile != "" && l.cfg.ServerKeyFile != "" {
		// The mirror is ordinary HTTPS; ALPN must allow HTTP/1.1 or the
		// client's transport cannot complete the request at all.
		srv.TLSConfig = serverMirrorTLS(l.cfg)
		return srv.ListenAndServeTLS(l.cfg.ServerCertFile, l.cfg.ServerKeyFile)
	}
	return srv.ListenAndServe()
}
