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
}
