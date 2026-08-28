package detection

import (
	"testing"
	"time"
)

// buildEntries creates n normalized entries for the same message (i.e.
// the same template), timestamped now.
func buildEntries(n int, host, site, severity, message string) []LogEntry {
	out := make([]LogEntry, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, NormalizeLogEntry(time.Now(), host, site, severity, message))
	}
	return out
}

func TestComputeLogHostScore_NoLogsIsInvalid(t *testing.T) {
	current := SummarizeLogWindow(nil)
	baseline := SummarizeLogWindow(nil)
	r := ComputeLogHostScore(current, baseline, 10.0/360.0)
	if r.Valid {
		t.Fatalf("expected Valid=false for an empty current window, got %+v", r)
	}
}

// TestComputeLogHostScore_NormalRepeatedLogsNoAnomaly (spec1.md §58): a
// template appearing at roughly its usual baseline-scaled rate must not
// score as an anomaly.
func TestComputeLogHostScore_NormalRepeatedLogsNoAnomaly(t *testing.T) {
	// Baseline: 360 occurrences over the (implied) 6h window == 10/10m,
	// current: 10 occurrences over 10m — right at the expected rate.
	baseline := SummarizeLogWindow(buildEntries(360, "h", "s", "info", "heartbeat ok"))
	current := SummarizeLogWindow(buildEntries(10, "h", "s", "info", "heartbeat ok"))
	scale := 10.0 / 360.0 // 10m current window / 6h(=360m) baseline window
	r := ComputeLogHostScore(current, baseline, scale)
	if !r.Valid {
		t.Fatal("expected Valid=true")
	}
	if r.Score != 0 {
		t.Errorf("expected no anomaly for a steady-rate template, got score=%v (%+v)", r.Score, r)
	}
}

// TestComputeLogHostScore_Burst (spec1.md §17.1/§58).
func TestComputeLogHostScore_Burst(t *testing.T) {
	baseline := SummarizeLogWindow(buildEntries(36, "h", "s", "warn", "retrying connection"))
	current := SummarizeLogWindow(buildEntries(240, "h", "s", "warn", "retrying connection"))
	scale := 10.0 / 360.0
	r := ComputeLogHostScore(current, baseline, scale)
	if !r.Valid || r.Score <= 0 {
		t.Fatalf("expected a burst anomaly, got %+v", r)
	}
	if r.Category != "burst" {
		t.Errorf("expected category=burst, got %q", r.Category)
	}
}

// TestComputeLogHostScore_NewTemplate (spec1.md §17.2/§58: "new error template").
func TestComputeLogHostScore_NewTemplate(t *testing.T) {
	baseline := SummarizeLogWindow(nil)
	current := SummarizeLogWindow(buildEntries(3, "h", "s", "error", "unexpected service crash detected"))
	r := ComputeLogHostScore(current, baseline, 10.0/360.0)
	if !r.Valid || r.Score <= 0 {
		t.Fatalf("expected a new-template anomaly, got %+v", r)
	}
	if r.Category != "new_template" {
		t.Errorf("expected category=new_template, got %q", r.Category)
	}
}

// TestComputeLogHostScore_RareTemplate (spec1.md §17.3/§58: "rare critical message").
func TestComputeLogHostScore_RareTemplate(t *testing.T) {
	baseline := SummarizeLogWindow(buildEntries(1, "h", "s", "warn", "disk latency spike"))
	current := SummarizeLogWindow(buildEntries(4, "h", "s", "warn", "disk latency spike"))
	r := ComputeLogHostScore(current, baseline, 10.0/360.0)
	if !r.Valid || r.Score <= 0 {
		t.Fatalf("expected a rare-template anomaly, got %+v", r)
	}
	if r.Category != "rare_template" {
		t.Errorf("expected category=rare_template, got %q", r.Category)
	}
}

// TestComputeLogHostScore_ErrorRateSpike (spec1.md §17.4).
func TestComputeLogHostScore_ErrorRateSpike(t *testing.T) {
	var baselineEntries []LogEntry
	baselineEntries = append(baselineEntries, buildEntries(95, "h", "s", "info", "request served")...)
	baselineEntries = append(baselineEntries, buildEntries(5, "h", "s", "error", "request failed A")...)
	baseline := SummarizeLogWindow(baselineEntries)

	var currentEntries []LogEntry
	currentEntries = append(currentEntries, buildEntries(5, "h", "s", "info", "request served")...)
	currentEntries = append(currentEntries, buildEntries(15, "h", "s", "error", "request failed B")...)
	current := SummarizeLogWindow(currentEntries)

	r := ComputeLogHostScore(current, baseline, 10.0/360.0)
	if !r.Valid || r.Score <= 0 {
		t.Fatalf("expected an error-rate anomaly, got %+v", r)
	}
}

// TestComputeLogHostScore_KnownCriticalPatternHardTrigger (spec1.md
// §17.5/§37/§56 Invariant C, Option B: score forced to 1.0).
func TestComputeLogHostScore_KnownCriticalPatternHardTrigger(t *testing.T) {
	baseline := SummarizeLogWindow(nil)
	current := SummarizeLogWindow(buildEntries(1, "h", "s", "crit", "kernel: Out of memory: Killed process 1234"))
	r := ComputeLogHostScore(current, baseline, 10.0/360.0)
	if !r.Valid || r.Score != 1.0 {
		t.Fatalf("expected a forced Score=1.0 hard trigger, got %+v", r)
	}
	if r.Category != "known_critical_pattern" {
		t.Errorf("expected category=known_critical_pattern, got %q", r.Category)
	}
}

// TestComputeLogHostScore_HardTriggerNeverSuppressedByNormalTemplates:
// even when most of the window's logs are ordinary chatter, a single
// hard-trigger line still wins (spec §56 Invariant C).
func TestComputeLogHostScore_HardTriggerNeverSuppressedByNormalTemplates(t *testing.T) {
	baseline := SummarizeLogWindow(buildEntries(360, "h", "s", "info", "heartbeat ok"))
	var currentEntries []LogEntry
	currentEntries = append(currentEntries, buildEntries(10, "h", "s", "info", "heartbeat ok")...)
	currentEntries = append(currentEntries, buildEntries(1, "h", "s", "crit", "segfault in worker thread")...)
	current := SummarizeLogWindow(currentEntries)

	r := ComputeLogHostScore(current, baseline, 10.0/360.0)
	if r.Score != 1.0 {
		t.Fatalf("hard trigger must win regardless of other normal templates, got score=%v", r.Score)
	}
}

func TestKnownCriticalPatterns_TableDriven(t *testing.T) {
	cases := []struct {
		line      string
		wantMatch bool
	}{
		{"kernel: Out of memory: Killed process 1234 (java)", true},
		{"Kernel panic - not syncing: Fatal exception", true},
		{"worker[42]: segfault at 0 ip 0000000000000000", true},
		{"scsi 0:0:0:0: I/O error, dev sda, sector 12345", true},
		{"mce: [Hardware Error]: uncorrectable ECC error detected", true},
		{"EXT4-fs error: filesystem now read-only", true},
		{"this is a perfectly normal informational log line", false},
		{"disk usage at 42 percent", false},
	}
	for _, c := range cases {
		t.Run(c.line, func(t *testing.T) {
			if got := matchesKnownCriticalPattern(c.line); got != c.wantMatch {
				t.Errorf("matchesKnownCriticalPattern(%q) = %v, want %v", c.line, got, c.wantMatch)
			}
		})
	}
}

// TestSummarizeLogWindow_CountsAndBoundedSamples (spec1.md §18: never
// pass every line, only up to LogMaxSamplesPerTemplate).
func TestSummarizeLogWindow_CountsAndBoundedSamples(t *testing.T) {
	entries := buildEntries(50, "h", "s", "error", "duplicate flood line")
	summary := SummarizeLogWindow(entries)
	if summary.TotalCount != 50 {
		t.Errorf("TotalCount = %d, want 50", summary.TotalCount)
	}
	if summary.ErrorCount != 50 {
		t.Errorf("ErrorCount = %d, want 50", summary.ErrorCount)
	}
	if len(summary.Templates) != 1 {
		t.Fatalf("expected exactly 1 template (duplicate flood collapses), got %d", len(summary.Templates))
	}
	for _, bucket := range summary.Templates {
		if bucket.Count != 50 {
			t.Errorf("bucket count = %d, want 50", bucket.Count)
		}
		if len(bucket.Samples) != LogMaxSamplesPerTemplate {
			t.Errorf("bucket samples = %d, want exactly %d (bounded)", len(bucket.Samples), LogMaxSamplesPerTemplate)
		}
	}
}
