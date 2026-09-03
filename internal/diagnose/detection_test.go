package diagnose

import (
	"strings"
	"testing"
)

func TestDetectionSteps_AlwaysIncludesStatusListAndJournal(t *testing.T) {
	steps := DetectionSteps("/var/lib/pilot/detection-engine/state.db", "")
	if len(steps) != 3 {
		t.Fatalf("DetectionSteps(\"\") returned %d steps, want 3", len(steps))
	}
	wantIDs := []string{"status", "signals_list", "journal"}
	for i, want := range wantIDs {
		if steps[i].ID != want {
			t.Errorf("steps[%d].ID = %q, want %q", i, steps[i].ID, want)
		}
		if steps[i].Module != "command" {
			t.Errorf("steps[%d].Module = %q, want \"command\" (never shell)", i, steps[i].Module)
		}
	}
	for _, step := range steps[:2] {
		if !strings.HasPrefix(step.Command, "sudo -n -u pilot-detect ") {
			t.Errorf("%s command = %q, want service-account execution", step.ID, step.Command)
		}
	}
	if !strings.Contains(steps[1].Command, "--db /var/lib/pilot/detection-engine/state.db") {
		t.Errorf("signals list command = %q, want configured db path", steps[1].Command)
	}
	if strings.Contains(steps[1].Command, "--json") {
		t.Errorf("signals list command = %q, must not pass unsupported --json", steps[1].Command)
	}
	got := testShlexSplit(steps[2].Command)
	found := false
	for _, tok := range got {
		if tok == "-n" {
			found = true
		}
	}
	if !found {
		t.Errorf("journal step command = %q, must be bounded with -n", steps[2].Command)
	}
}

func TestDetectionSteps_SignalIDAddsShowStep(t *testing.T) {
	const id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	steps := DetectionSteps("/var/lib/pilot/detection-engine/state.db", id)
	if len(steps) != 4 {
		t.Fatalf("DetectionSteps(id) returned %d steps, want 4", len(steps))
	}
	if steps[3].ID != "signal_show" {
		t.Fatalf("steps[3].ID = %q, want signal_show", steps[3].ID)
	}
	got := testShlexSplit(steps[3].Command)
	found := false
	for _, tok := range got {
		if tok == id {
			found = true
		}
	}
	if !found {
		t.Errorf("signal_show command = %q, must include the signal_id verbatim", steps[3].Command)
	}
	if !strings.Contains(steps[3].Command, "--db /var/lib/pilot/detection-engine/state.db") {
		t.Errorf("signal_show command = %q, want configured db path", steps[3].Command)
	}
	if strings.Contains(steps[3].Command, "--json") {
		t.Errorf("signal_show command = %q, must not pass unsupported --json", steps[3].Command)
	}
}

func TestDetectionConfigDBPathStepAndParser(t *testing.T) {
	step := DetectionConfigDBPathStep()
	if step.Module != "command" || !strings.Contains(step.Command, "sudo -n -u pilot-detect") || !strings.Contains(step.Command, "/usr/bin/grep -m 1 ^dbPath:") {
		t.Fatalf("config db path step = %+v, want fixed command-module service-account read", step)
	}
	path, err := DetectionDBPath(`dbPath: "/var/lib/pilot/detection-engine/state.db"`)
	if err != nil || path != "/var/lib/pilot/detection-engine/state.db" {
		t.Fatalf("DetectionDBPath() = %q, %v", path, err)
	}
	for _, raw := range []string{"", "not-db-path", "dbPath: relative.db", "dbPath: /var/lib/../secret.db", "dbPath: /safe.db;bad"} {
		if _, err := DetectionDBPath(raw); err == nil {
			t.Errorf("DetectionDBPath(%q) succeeded, want rejection", raw)
		}
	}
}

func TestSignalIDPattern_ValidatesULIDShape(t *testing.T) {
	valid := []string{"01ARZ3NDEKTSV4RRFFQ69G5FAV", "00000000000000000000000000"}
	for _, id := range valid {
		if !SignalIDPattern.MatchString(id) {
			t.Errorf("SignalIDPattern rejected valid-shaped ULID %q", id)
		}
	}
	invalid := []string{
		"",
		"too-short",
		"01ARZ3NDEKTSV4RRFFQ69G5FAV; rm -rf /", // injection attempt
		"01arz3ndektsv4rrffq69g5fav",           // lowercase not allowed
		"0000000000000000000000000I",           // I is excluded from Crockford
	}
	for _, id := range invalid {
		if SignalIDPattern.MatchString(id) {
			t.Errorf("SignalIDPattern accepted invalid input %q", id)
		}
	}
}
