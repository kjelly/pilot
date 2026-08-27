package accessgrants

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAppendAuditEvent_WritesJSONLWithModeAndFilledFields(t *testing.T) {
	stateDir := t.TempDir()
	if err := AppendAuditEvent(stateDir, AccessAuditEvent{
		Action:     AuditActionExplicitAccessReconcile,
		SourceKind: "temporary_grant",
		Resource:   "roster.yaml",
		Outcome:    "success",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	path := filepath.Join(stateDir, "access", "audit.jsonl")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("expected audit.jsonl to exist: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected mode 0600, got %o", info.Mode().Perm())
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		t.Fatal("expected at least one line")
	}
	var ev AccessAuditEvent
	if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
		t.Fatalf("malformed JSON line: %v", err)
	}
	if ev.ID == "" {
		t.Fatal("expected an auto-generated ID")
	}
	if ev.At.IsZero() {
		t.Fatal("expected an auto-filled timestamp")
	}
	if ev.Action != AuditActionExplicitAccessReconcile {
		t.Fatalf("unexpected action: %q", ev.Action)
	}
}

func TestAppendAuditEvent_AppendsAcrossMultipleCalls(t *testing.T) {
	stateDir := t.TempDir()
	for i := 0; i < 3; i++ {
		if err := AppendAuditEvent(stateDir, AccessAuditEvent{Action: AuditActionAccessDriftDetected, Outcome: "success"}); err != nil {
			t.Fatalf("unexpected error on call %d: %v", i, err)
		}
	}

	path := filepath.Join(stateDir, "access", "audit.jsonl")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	lines := 0
	ids := map[string]bool{}
	for scanner.Scan() {
		lines++
		var ev AccessAuditEvent
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			t.Fatalf("malformed JSON line %d: %v", lines, err)
		}
		ids[ev.ID] = true
	}
	if lines != 3 {
		t.Fatalf("expected 3 appended lines, got %d", lines)
	}
	if len(ids) != 3 {
		t.Fatalf("expected 3 distinct auto-generated IDs, got %d", len(ids))
	}
}

func TestAppendAuditEvent_RequiresStateDir(t *testing.T) {
	if err := AppendAuditEvent("", AccessAuditEvent{Action: "x"}); err == nil {
		t.Fatal("expected an error when stateDir is empty")
	}
}
