package config

import (
	"testing"
	"time"
)

func TestNormalizeStreamIdleTimeout(t *testing.T) {
	cases := []struct {
		in, want time.Duration
	}{
		{0, 0},                               // disabled stays disabled
		{-time.Minute, 0},                    // a negative value cannot enable it
		{time.Second, minStreamIdleTimeout},  // too aggressive, raised to the floor
		{10 * time.Minute, 10 * time.Minute}, // passed through
	}
	for _, c := range cases {
		if got := NormalizeStreamIdleTimeout(c.in); got != c.want {
			t.Errorf("NormalizeStreamIdleTimeout(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestNormalizeMaxPendingDials(t *testing.T) {
	cases := []struct {
		in, want int
	}{
		{0, 0},
		{-5, 0},
		{64, 64},
		{100000, maxMaxPendingDials},
	}
	for _, c := range cases {
		if got := NormalizeMaxPendingDials(c.in); got != c.want {
			t.Errorf("NormalizeMaxPendingDials(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestNormalizeLogRotate(t *testing.T) {
	if size, keep := NormalizeLogRotate(0, 0); size != DefaultLogRotateSize || keep != DefaultLogRotateKeep {
		t.Errorf("zero values = (%d,%d), want defaults (%d,%d)", size, keep, DefaultLogRotateSize, DefaultLogRotateKeep)
	}
	if size, _ := NormalizeLogRotate(1, 0); size != minLogRotateSize {
		t.Errorf("tiny rotate size = %d, want floor %d", size, minLogRotateSize)
	}
	if _, keep := NormalizeLogRotate(1<<20, 1000); keep != maxLogRotateKeep {
		t.Errorf("huge keep = %d, want cap %d", keep, maxLogRotateKeep)
	}
	if size, keep := NormalizeLogRotate(1<<20, 5); size != 1<<20 || keep != 5 {
		t.Errorf("valid values were changed to (%d,%d)", size, keep)
	}
}

func TestNormalizeQUICFallback(t *testing.T) {
	failures, hold, minUp := NormalizeQUICFallback(0, 0, 0)
	if failures != 0 || hold != DefaultQUICFallbackHold || minUp != DefaultQUICFallbackMinUptime {
		t.Errorf("zero values = (%d,%v,%v), want (0,%v,%v)",
			failures, hold, minUp, DefaultQUICFallbackHold, DefaultQUICFallbackMinUptime)
	}

	if failures, _, _ := NormalizeQUICFallback(-1, 0, 0); failures != 0 {
		t.Errorf("negative failures = %d, want 0 (disabled)", failures)
	}
	if failures, _, _ := NormalizeQUICFallback(1000, 0, 0); failures != maxQUICFallbackFailures {
		t.Errorf("huge failures = %d, want cap %d", failures, maxQUICFallbackFailures)
	}

	if _, hold, _ := NormalizeQUICFallback(3, time.Second, 0); hold != minQUICFallbackHold {
		t.Errorf("tiny hold = %v, want floor %v", hold, minQUICFallbackHold)
	}
	if _, hold, _ := NormalizeQUICFallback(3, 48*time.Hour, 0); hold != maxQUICFallbackHold {
		t.Errorf("huge hold = %v, want cap %v", hold, maxQUICFallbackHold)
	}

	// A min-uptime of zero must not turn every connection into a failure.
	if _, _, minUp := NormalizeQUICFallback(3, 0, time.Millisecond); minUp != minQUICFallbackMinUptime {
		t.Errorf("tiny min uptime = %v, want floor %v", minUp, minQUICFallbackMinUptime)
	}
	if _, _, minUp := NormalizeQUICFallback(3, 0, time.Hour); minUp != maxQUICFallbackMinUptime {
		t.Errorf("huge min uptime = %v, want cap %v", minUp, maxQUICFallbackMinUptime)
	}

	if f, h, u := NormalizeQUICFallback(5, 15*time.Minute, 20*time.Second); f != 5 || h != 15*time.Minute || u != 20*time.Second {
		t.Errorf("valid values were changed to (%d,%v,%v)", f, h, u)
	}
}

func TestDefaultClientConfigIncludesNewLimits(t *testing.T) {
	cfg := DefaultClientConfig()
	if cfg.StreamIdleTimeout != DefaultStreamIdleTimeout {
		t.Errorf("StreamIdleTimeout = %v, want %v", cfg.StreamIdleTimeout, DefaultStreamIdleTimeout)
	}
	if cfg.MaxPendingDials != DefaultMaxPendingDials {
		t.Errorf("MaxPendingDials = %d, want %d", cfg.MaxPendingDials, DefaultMaxPendingDials)
	}
	if cfg.LogRotateSize != DefaultLogRotateSize || cfg.LogRotateKeep != DefaultLogRotateKeep {
		t.Errorf("log rotation defaults = (%d,%d)", cfg.LogRotateSize, cfg.LogRotateKeep)
	}
	if cfg.QUICFallbackFailures != DefaultQUICFallbackFailures ||
		cfg.QUICFallbackHold != DefaultQUICFallbackHold ||
		cfg.QUICFallbackMinUptime != DefaultQUICFallbackMinUptime {
		t.Errorf("QUIC fallback defaults = (%d,%v,%v), want (%d,%v,%v)",
			cfg.QUICFallbackFailures, cfg.QUICFallbackHold, cfg.QUICFallbackMinUptime,
			DefaultQUICFallbackFailures, DefaultQUICFallbackHold, DefaultQUICFallbackMinUptime)
	}
}
