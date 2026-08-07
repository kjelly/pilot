package cmd

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeLokiRange(t *testing.T) {
	now := time.Date(2026, time.August, 7, 6, 0, 0, 0, time.UTC)
	const wantStart = "2026-08-07T05:00:00Z"
	const wantEnd = "2026-08-07T05:30:00Z"
	for _, tc := range []struct {
		name       string
		start, end string
		wantStart  string
		wantEnd    string
	}{
		{name: "both omitted preserves Loki default", wantStart: "", wantEnd: ""},
		{name: "unix seconds", start: "1786078800", end: "1786080600", wantStart: wantStart, wantEnd: wantEnd},
		{name: "unix milliseconds", start: "1786078800000", end: "1786080600000", wantStart: wantStart, wantEnd: wantEnd},
		{name: "unix microseconds", start: "1786078800000000", end: "1786080600000000", wantStart: wantStart, wantEnd: wantEnd},
		{name: "unix nanoseconds", start: "1786078800000000000", end: "1786080600000000000", wantStart: wantStart, wantEnd: wantEnd},
		{name: "rfc3339", start: wantStart, end: wantEnd, wantStart: wantStart, wantEnd: wantEnd},
		{name: "relative start and explicit now", start: "1h", end: "now", wantStart: "2026-08-07T05:00:00Z", wantEnd: "2026-08-07T06:00:00Z"},
		{name: "explicit start gets explicit now end", start: wantStart, wantStart: wantStart, wantEnd: "2026-08-07T06:00:00Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotStart, gotEnd, err := normalizeLokiRange(tc.start, tc.end, now)
			if err != nil {
				t.Fatalf("normalizeLokiRange() error = %v", err)
			}
			if gotStart != tc.wantStart || gotEnd != tc.wantEnd {
				t.Fatalf("normalizeLokiRange() = (%q, %q), want (%q, %q)", gotStart, gotEnd, tc.wantStart, tc.wantEnd)
			}
		})
	}
}

func TestNormalizeLokiRange_RejectsFutureOrBackwardsRange(t *testing.T) {
	now := time.Date(2026, time.August, 7, 6, 0, 0, 0, time.UTC)
	_, _, err := normalizeLokiRange("2026-08-07T07:00:00Z", "", now)
	if err == nil || !strings.Contains(err.Error(), "must be before end") {
		t.Fatalf("normalizeLokiRange() error = %v, want actionable start/end error", err)
	}
}
