package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"meridian/pkg/config"
)

func TestRotatingWriterRollsAndKeepsBoundedFiles(t *testing.T) {
	dir := t.TempDir()
	// A nested path also checks that the directory is created for us: on a
	// router the log directory may not exist yet.
	path := filepath.Join(dir, "logs", "client.log")

	const (
		maxSize = 1024
		keep    = 2
	)
	w, err := newRotatingWriter(path, maxSize, keep)
	if err != nil {
		t.Fatalf("newRotatingWriter: %v", err)
	}

	line := strings.Repeat("x", 99) + "\n"
	for i := 0; i < 40; i++ {
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// path plus path.1 .. path.keep must exist, and nothing beyond keep.
	for _, p := range append([]string{path}, rotated(path, keep)...) {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected %s to exist: %v", p, err)
		}
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Fatalf("kept more files than configured (path.3 exists)")
	}

	for _, p := range append([]string{path}, rotated(path, keep)...) {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Size() > maxSize {
			t.Errorf("%s is %d bytes, want <= %d", p, st.Size(), maxSize)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		// Rotation happens between writes, so no line may be split across
		// files: a torn line is useless when reconstructing a timeline.
		if len(data) > 0 && data[len(data)-1] != '\n' {
			t.Errorf("%s does not end on a line boundary", p)
		}
	}
}

func rotated(path string, keep int) []string {
	out := make([]string, 0, keep)
	for i := 1; i <= keep; i++ {
		out = append(out, path+"."+strconv.Itoa(i))
	}
	return out
}

func TestSetupLoggingTeesIntoFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.log")
	t.Cleanup(closeLogging)

	if err := setupLogging(config.ClientConfig{
		LogFile:       path,
		LogRotateSize: 1 << 20,
		LogRotateKeep: 2,
	}); err != nil {
		t.Fatalf("setupLogging: %v", err)
	}

	logf("hello %d", 1)
	noteConn()
	noteEvent("dial_timeout", "socks5: dial example.com:443 failed: timeout")
	flushEvents(time.Minute)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	got := string(data)
	for _, want := range []string{"hello 1", "[Summary]", "conns=1", "dial_timeout=1"} {
		if !strings.Contains(got, want) {
			t.Errorf("log file missing %q; got:\n%s", want, got)
		}
	}
}

func TestLogTimestampsFollowConfiguredZone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tz.log")
	t.Cleanup(closeLogging)

	// The two routers disagree on the system zone, so the log clock has to come
	// from configuration; otherwise the same minute is two different times.
	if err := setupLogging(config.ClientConfig{
		LogFile:          path,
		LogRotateSize:    1 << 20,
		LogRotateKeep:    2,
		ScheduleTimezone: "UTC-7",
	}); err != nil {
		t.Fatalf("setupLogging: %v", err)
	}
	now := time.Now().UTC()
	wantA := now.Add(-7 * time.Hour).Format("2006-01-02 15:04")
	wantB := now.Add(-7*time.Hour + time.Minute).Format("2006-01-02 15:04")
	logf("zone check")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.Contains(string(data), wantA) && !strings.Contains(string(data), wantB) {
		t.Fatalf("log line lacks the configured zone timestamp %q: %s", wantA, data)
	}
}

func TestFormatSummaryOrdersByCountAndAddsSamples(t *testing.T) {
	conns := uint64(319)
	counts := map[string]uint64{"stream_idle": 3, "dial_timeout": 12, "limit_dropped": 1}
	samples := map[string]string{
		"dial_timeout":  "socks5: dial www.gstatic.com:443 failed: timeout",
		"stream_idle":   "tunnel: stream 7 idle for 10m0s, reclaimed",
		"limit_dropped": "socks5: connection limit reached (2048)",
	}

	line := formatSummary(conns, counts, samples, time.Minute)
	if !strings.Contains(line, "conns=319") {
		t.Errorf("summary lost the connection count: %s", line)
	}
	if !strings.Contains(line, "events=16") {
		t.Errorf("summary lost the event total: %s", line)
	}
	// The dominant reason has to be readable first.
	if strings.Index(line, "dial_timeout=12") > strings.Index(line, "stream_idle=3") {
		t.Errorf("reasons are not ordered by count: %s", line)
	}
	if !strings.Contains(line, "| dial_timeout: socks5: dial www.gstatic.com") {
		t.Errorf("summary lost the sample line: %s", line)
	}
}

func TestFormatSummaryQuietWhenIdle(t *testing.T) {
	if line := formatSummary(0, nil, nil, time.Minute); line != "" {
		t.Fatalf("idle interval produced a line: %q", line)
	}
}

func TestDialReasonClassifies(t *testing.T) {
	cases := map[string]string{
		"tunnel: dial timeout waiting for server response":  "dial_timeout",
		"context deadline exceeded":                         "dial_timeout",
		"dial tcp 1.2.3.4:443: connect: connection refused": "dial_refused",
		"lookup example.com: no such host":                  "dial_dns",
		"read tcp: connection reset by peer":                "dial_reset",
		"tunnel: lane saturated":                            "dial_lane_full",
		"something else entirely":                           "dial_other",
	}
	for msg, want := range cases {
		if got := dialReason(errString(msg)); got != want {
			t.Errorf("dialReason(%q) = %q, want %q", msg, got, want)
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }
