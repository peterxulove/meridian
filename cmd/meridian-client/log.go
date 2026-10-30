// Package main — client-side logging.
//
// Two problems this file solves, both observed on a busy router:
//
//  1. The only sink was stdout, which procd hands to syslog. OpenWrt's logd
//     keeps a small ring (64 KiB by default) and drops the oldest lines, so a
//     burst of 600 failed dials evicted the very window it happened in. The
//     client can now tee its lines into a size-rotated file.
//  2. One log line per failed connection is self-defeating under load: the
//     storm erases the evidence that explains it. Failures are counted per
//     reason and flushed as one summary line per interval, keeping a single
//     sample line per reason for context.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"meridian/pkg/config"
)

// logMu serialises every write. Concurrent goroutines used to interleave
// partial lines on stdout, which made the tunnel log unreadable under load.
var (
	logMu      sync.Mutex
	logOut     io.Writer = os.Stdout
	logRotator *rotatingWriter
	logVerbose bool
	logLoc     = time.Local
	// logSetupWarning is reported by main once logging is ready; a bad zone
	// must not stop the client, but it must not pass silently either.
	logSetupWarning error
)

// setupLogging installs the log destination described by cfg. An empty
// log_file keeps the historical stdout-only behaviour.
func setupLogging(cfg config.ClientConfig) error {
	logVerbose = cfg.LogVerbose || config.DebugMode
	// Timestamps follow an explicit log_timezone, else the schedule's zone (the
	// two routers disagree on the system zone), else the local zone.
	zone := cfg.LogTimezone
	if strings.TrimSpace(zone) == "" {
		zone = cfg.ScheduleTimezone
	}
	if strings.TrimSpace(zone) != "" {
		if loc, err := config.LoadScheduleLocation(zone); err != nil {
			logSetupWarning = err
		} else {
			logLoc = loc
		}
	}
	if strings.TrimSpace(cfg.LogFile) == "" {
		return nil
	}
	rw, err := newRotatingWriter(cfg.LogFile, int64(cfg.LogRotateSize), cfg.LogRotateKeep)
	if err != nil {
		return err
	}
	logMu.Lock()
	logRotator = rw
	// Keep stdout in the chain so `logread` and the console still work; the
	// file is what survives a storm.
	logOut = io.MultiWriter(os.Stdout, rw)
	logMu.Unlock()
	return nil
}

// closeLogging flushes and closes the rotating file, if any.
func closeLogging() {
	logMu.Lock()
	rw := logRotator
	logRotator = nil
	logOut = os.Stdout
	logLoc = time.Local
	logSetupWarning = nil
	logMu.Unlock()
	if rw != nil {
		rw.Close()
	}
}

// logf writes one timestamped line. Every client log line goes through here so
// that stdout and the file never disagree.
func logf(format string, args ...any) {
	ts := time.Now().In(logLoc).Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("[%s] "+format+"\n", append([]any{ts}, args...)...)

	logMu.Lock()
	defer logMu.Unlock()
	io.WriteString(logOut, line)
}

// logConnf logs a per-connection line, which is off unless log_verbose (or
// -debug) is set. The per-minute summary already reports connection counts.
func logConnf(format string, args ...any) {
	if !logVerbose {
		return
	}
	logf(format, args...)
}

// ─────────────────────────────────────────────────────────────────────────────
// Rotating file writer
// ─────────────────────────────────────────────────────────────────────────────

// rotatingWriter appends to path and rolls the file over once it would exceed
// maxSize. It keeps keep+1 files in total: path plus path.1 .. path.keep.
type rotatingWriter struct {
	mu      sync.Mutex
	path    string
	maxSize int64
	keep    int
	file    *os.File
	size    int64
}

func newRotatingWriter(path string, maxSize int64, keep int) (*rotatingWriter, error) {
	w := &rotatingWriter{path: path, maxSize: maxSize, keep: keep}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *rotatingWriter) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.file = f
	w.size = st.Size()
	return nil
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		if err := w.open(); err != nil {
			return 0, err
		}
	}
	// Rotate before the write so a line is never split across two files.
	if w.maxSize > 0 && w.size > 0 && w.size+int64(len(p)) > w.maxSize {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

// rotate shifts path.N-1 -> path.N ... path -> path.1 and starts a fresh file.
func (w *rotatingWriter) rotate() error {
	w.file.Close()
	w.file = nil
	for i := w.keep; i >= 1; i-- {
		from := w.path + "." + strconv.Itoa(i)
		to := w.path + "." + strconv.Itoa(i+1)
		if i == w.keep {
			os.Remove(from)
			continue
		}
		os.Rename(from, to)
	}
	if err := os.Rename(w.path, w.path+".1"); err != nil && !os.IsNotExist(err) {
		return err
	}
	return w.open()
}

func (w *rotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-interval event counters
// ─────────────────────────────────────────────────────────────────────────────

// eventCounter accumulates reasons for one reporting interval. The first and
// last sample of each reason are kept so the summary line can show what the
// failures actually looked like without printing them all.
type eventCounter struct {
	mu       sync.Mutex
	counts   map[string]uint64
	lastSeen map[string]string
	conns    uint64
}

var events = &eventCounter{
	counts:   make(map[string]uint64),
	lastSeen: make(map[string]string),
}

// summaryInterval is how often the counters are flushed. One minute is short
// enough to correlate an incident with the clock and long enough that the
// summary itself cannot flood a log file.
const summaryInterval = 60 * time.Second

// sampleLimit keeps one example readable inside a single log line.
const sampleLimit = 200

// noteConn counts a proxied connection attempt. Reported once per interval
// instead of one line per connection.
func noteConn() {
	events.mu.Lock()
	events.conns++
	events.mu.Unlock()
}

// noteEvent counts a failure (or a reclaim) under reason, remembering the most
// recent description of it.
func noteEvent(reason, format string, args ...any) {
	sample := fmt.Sprintf(format, args...)
	if len(sample) > sampleLimit {
		sample = sample[:sampleLimit] + "…"
	}
	events.mu.Lock()
	events.counts[reason]++
	events.lastSeen[reason] = sample
	events.mu.Unlock()
}

// snapshot takes the counters for the interval just ended and resets them.
func (e *eventCounter) snapshot() (conns uint64, counts map[string]uint64, samples map[string]string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	conns = e.conns
	counts = e.counts
	samples = e.lastSeen
	e.conns = 0
	e.counts = make(map[string]uint64)
	e.lastSeen = make(map[string]string)
	return conns, counts, samples
}

// formatSummary renders the interval as a single line, reasons sorted by
// descending count so the dominant one is read first. It returns "" when the
// interval saw neither connections nor events, so an idle client stays quiet.
func formatSummary(conns uint64, counts map[string]uint64, samples map[string]string, interval time.Duration) string {
	if conns == 0 && len(counts) == 0 {
		return ""
	}
	reasons := make([]string, 0, len(counts))
	var total uint64
	for r, n := range counts {
		reasons = append(reasons, r)
		total += n
	}
	sort.Slice(reasons, func(i, j int) bool {
		if counts[reasons[i]] != counts[reasons[j]] {
			return counts[reasons[i]] > counts[reasons[j]]
		}
		return reasons[i] < reasons[j]
	})

	var b strings.Builder
	fmt.Fprintf(&b, "[Summary] last %s: conns=%d events=%d", trimDuration(interval), conns, total)
	for _, r := range reasons {
		fmt.Fprintf(&b, " %s=%d", r, counts[r])
	}
	// Attach a sample for the top reasons only: more than three and the line
	// stops being scannable in a terminal.
	shown := 0
	for _, r := range reasons {
		if shown == 3 {
			break
		}
		if s := samples[r]; s != "" {
			fmt.Fprintf(&b, " | %s: %s", r, s)
			shown++
		}
	}
	return b.String()
}

// trimDuration renders 1m0s as 60s and keeps sub-minute intervals as seconds.
func trimDuration(d time.Duration) string {
	return strconv.Itoa(int(d.Seconds())) + "s"
}

// flushEvents writes the interval summary, if there is anything to report.
func flushEvents(interval time.Duration) {
	conns, counts, samples := events.snapshot()
	if line := formatSummary(conns, counts, samples, interval); line != "" {
		logf("%s", line)
	}
}

// startEventReporter flushes the counters once per interval until stop closes.
func startEventReporter(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				flushEvents(interval)
			case <-stop:
				flushEvents(interval)
				return
			}
		}
	}()
}

// dialReason classifies a dial error into a small, greppable set of reasons.
func dialReason(err error) string {
	if err == nil {
		return "dial_ok"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded"):
		return "dial_timeout"
	case strings.Contains(msg, "connection refused"):
		return "dial_refused"
	case strings.Contains(msg, "no such host") || strings.Contains(msg, "server misbehaving"):
		return "dial_dns"
	case strings.Contains(msg, "reset by peer") || strings.Contains(msg, "broken pipe") || strings.Contains(msg, "eof"):
		return "dial_reset"
	case strings.Contains(msg, "lane saturated"):
		return "dial_lane_full"
	default:
		return "dial_other"
	}
}
