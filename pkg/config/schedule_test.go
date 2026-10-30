package config

import (
	"testing"
	"time"
)

func at(hour, minute int) time.Time {
	return time.Date(2026, 10, 30, hour, minute, 0, 0, time.Local)
}

func TestCompileTransportScheduleParsesWindows(t *testing.T) {
	got, err := CompileTransportSchedule([]TransportWindow{
		{Transport: TransportHysteria, From: "19:00", To: "03:00"},
		{Transport: TransportWebSocket, From: "03:00", To: "19:00"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].From != 19*60 || got[0].To != 3*60 {
		t.Fatalf("window = %d-%d, want %d-%d", got[0].From, got[0].To, 19*60, 3*60)
	}
}

func TestWindowWrapAroundMidnight(t *testing.T) {
	w := CompiledTransportWindow{Transport: TransportHysteria, From: 19 * 60, To: 3 * 60}
	cases := []struct {
		t    time.Time
		want bool
	}{
		{at(18, 59), false},
		{at(19, 0), true},
		{at(23, 30), true},
		{at(0, 0), true},
		{at(2, 59), true},
		{at(3, 0), false},
		{at(12, 0), false},
	}
	for _, c := range cases {
		if got := w.Contains(c.t); got != c.want {
			t.Errorf("Contains(%s) = %v, want %v", c.t.Format("15:04"), got, c.want)
		}
	}
}

func TestWindowWithinOneDay(t *testing.T) {
	w := CompiledTransportWindow{Transport: TransportWebSocket, From: 8 * 60, To: 18 * 60}
	if !w.Contains(at(8, 0)) || !w.Contains(at(17, 59)) {
		t.Error("expected daytime window to contain 08:00 and 17:59")
	}
	if w.Contains(at(18, 0)) || w.Contains(at(7, 59)) {
		t.Error("expected daytime window to exclude 18:00 and 07:59")
	}
}

func TestCompileTransportScheduleRejectsBadEntries(t *testing.T) {
	cases := []TransportWindow{
		{Transport: "QUIC+WebSocket", From: "19:00", To: "03:00"},
		{Transport: "SOCKS5", From: "19:00", To: "03:00"},
		{Transport: TransportHysteria, From: "25:00", To: "03:00"},
		{Transport: TransportHysteria, From: "19:70", To: "03:00"},
		{Transport: TransportHysteria, From: "seven", To: "03:00"},
		{Transport: TransportHysteria, From: "19:00", To: "19:00"},
	}
	for i, c := range cases {
		if _, err := CompileTransportSchedule([]TransportWindow{c}); err == nil {
			t.Errorf("case %d (%+v) accepted, want error", i, c)
		}
	}
}

func TestEmptyScheduleIsValid(t *testing.T) {
	got, err := CompileTransportSchedule(nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestLoadScheduleLocationFixedOffsets(t *testing.T) {
	cases := map[string]int{
		"UTC+8":    8 * 3600,
		"utc+08":   8 * 3600,
		"+08:00":   8 * 3600,
		"-0500":    -5 * 3600,
		"GMT+5:30": 5*3600 + 30*60,
	}
	for name, want := range cases {
		loc, err := LoadScheduleLocation(name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		_, got := time.Now().In(loc).Zone()
		if got != want {
			t.Errorf("%s: offset = %d, want %d", name, got, want)
		}
	}
}

func TestLoadScheduleLocationIANA(t *testing.T) {
	loc, err := LoadScheduleLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	_, got := time.Now().In(loc).Zone()
	if got != 8*3600 {
		t.Errorf("offset = %d, want %d", got, 8*3600)
	}
}

func TestLoadScheduleLocationRejectsGarbage(t *testing.T) {
	for _, name := range []string{"Mars/Olympus", "UTC+25", "GMT+8:99"} {
		if _, err := LoadScheduleLocation(name); err == nil {
			t.Errorf("%q accepted, want error", name)
		}
	}
}
