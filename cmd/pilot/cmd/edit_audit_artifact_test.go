package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCastAuditRecorder_WritesParseableAsciicastHeaderAndFrames(t *testing.T) {
	var buf bytes.Buffer
	rec, err := newCastAuditRecorder(&buf, "test session", 100, 30)
	if err != nil {
		t.Fatalf("newCastAuditRecorder() error = %v", err)
	}
	if err := rec.RecordActionStart(editAction{Action: "create_host"}); err != nil {
		t.Fatalf("RecordActionStart() error = %v", err)
	}
	if err := rec.RecordFrame(FrameEvent{Sequence: 1, ScreenID: "hosts.list", View: "編輯什麼？"}); err != nil {
		t.Fatalf("RecordFrame() error = %v", err)
	}
	if err := rec.RecordActionResult(editAction{Action: "create_host"}, nil); err != nil {
		t.Fatalf("RecordActionResult() error = %v", err)
	}

	scanner := bufio.NewScanner(&buf)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if len(lines) != 4 { // header + 3 events
		t.Fatalf("got %d lines, want 4 (header + 3 events):\n%v", len(lines), lines)
	}

	var header map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &header); err != nil {
		t.Fatalf("header line did not parse as JSON: %v", err)
	}
	if header["version"] != float64(2) {
		t.Fatalf("header version = %v, want 2", header["version"])
	}
	if header["width"] != float64(100) || header["height"] != float64(30) {
		t.Fatalf("header dims = %v/%v, want 100/30", header["width"], header["height"])
	}

	for _, line := range lines[1:] {
		var event []any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("event line did not parse as a JSON array: %v\nline: %s", err, line)
		}
		if len(event) != 3 || event[1] != "o" {
			t.Fatalf("event = %v, want [time, \"o\", text]", event)
		}
	}
	if !bytes.Contains([]byte(lines[2]), []byte("hosts.list")) && !bytes.Contains([]byte(lines[2]), []byte("編輯什麼")) {
		t.Fatalf("expected the frame event to carry the recorded view, got: %s", lines[2])
	}
}

func TestWritePlanAuditArtifacts_WritesAllFourFiles(t *testing.T) {
	dir := t.TempDir()
	meta := auditMetadata{SessionID: "abc123", Kind: "plan", PilotVersion: "0.2.0", Workspace: dir}
	scenario := editScenario{Version: 1, Steps: []editAction{{Action: "create_host", Host: "web-1"}}}
	result := &editPlanResult{
		BaseRevision:  "sha256:deadbeef",
		AffectedFiles: []string{"hosts.yml"},
		Diff:          "--- a/hosts.yml\n+++ b/hosts.yml\n",
		Blocking:      []string{"issue A"},
		Warnings:      []string{"warning B"},
	}

	if err := writePlanAuditArtifacts(dir, meta, scenario, result); err != nil {
		t.Fatalf("writePlanAuditArtifacts() error = %v", err)
	}

	for _, name := range []string{"metadata.json", "scenario.redacted.json", "diff.patch", "validation.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
	}

	metaData, err := os.ReadFile(filepath.Join(dir, "metadata.json"))
	if err != nil {
		t.Fatalf("read metadata.json: %v", err)
	}
	var gotMeta auditMetadata
	if err := json.Unmarshal(metaData, &gotMeta); err != nil {
		t.Fatalf("metadata.json did not parse: %v", err)
	}
	if gotMeta.SessionID != "abc123" || gotMeta.Kind != "plan" {
		t.Fatalf("gotMeta = %+v, want session_id=abc123 kind=plan", gotMeta)
	}

	validationData, err := os.ReadFile(filepath.Join(dir, "validation.json"))
	if err != nil {
		t.Fatalf("read validation.json: %v", err)
	}
	var gotValidation validationSummary
	if err := json.Unmarshal(validationData, &gotValidation); err != nil {
		t.Fatalf("validation.json did not parse: %v", err)
	}
	if len(gotValidation.Blocking) != 1 || gotValidation.Blocking[0] != "issue A" {
		t.Fatalf("gotValidation.Blocking = %v, want [issue A]", gotValidation.Blocking)
	}

	diffData, err := os.ReadFile(filepath.Join(dir, "diff.patch"))
	if err != nil {
		t.Fatalf("read diff.patch: %v", err)
	}
	if string(diffData) != result.Diff {
		t.Fatalf("diff.patch = %q, want %q", diffData, result.Diff)
	}
}

func TestGitRevision_EmptyForNonGitDirectory(t *testing.T) {
	dir := t.TempDir() // an OS temp dir is never inside a git working tree
	if rev := gitRevision(dir); rev != "" {
		t.Fatalf("gitRevision() = %q, want empty for a non-git directory", rev)
	}
}
