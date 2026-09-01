package changejournal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeEditApplyAudit(t *testing.T, auditDir, dirName string, meta editApplyAuditMetadata) {
	t.Helper()
	sessionDir := filepath.Join(auditDir, dirName)
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sessionDir, "metadata.json"), data, 0o644); err != nil {
		t.Fatalf("write metadata.json: %v", err)
	}
}

func TestQueryEditApplyChanges_MissingDirIsEmptyNotError(t *testing.T) {
	records, err := QueryEditApplyChanges(filepath.Join(t.TempDir(), "does-not-exist"), TimeWindow{})
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(records) != 0 {
		t.Fatalf("records = %v, want empty", records)
	}
}

func TestQueryEditApplyChanges_FiltersKindAndWindow(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	writeEditApplyAudit(t, dir, "1-apply", editApplyAuditMetadata{
		SessionID: "s1", Kind: "apply", Start: now.Add(-10 * time.Minute), Finish: now.Add(-9 * time.Minute), WorkspaceRevision: "abc123",
	})
	writeEditApplyAudit(t, dir, "2-plan", editApplyAuditMetadata{
		SessionID: "s2", Kind: "plan", Start: now.Add(-5 * time.Minute), Finish: now.Add(-4 * time.Minute),
	})
	writeEditApplyAudit(t, dir, "3-apply", editApplyAuditMetadata{
		SessionID: "s3", Kind: "apply", Start: now.Add(-2 * time.Hour), Finish: now.Add(-2 * time.Hour),
	})

	window := TimeWindow{Start: now.Add(-30 * time.Minute), End: now}
	records, err := QueryEditApplyChanges(dir, window)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %+v, want exactly 1 (plan excluded, out-of-window apply excluded)", records)
	}
	if records[0].ID != "s1" || records[0].Kind != ChangeKindEditApply || records[0].WorkspaceRevision != "abc123" {
		t.Errorf("record = %+v", records[0])
	}
}

type fakeDeployRunSource struct {
	runs []DeployRun
}

func (f fakeDeployRunSource) ListRuns(filter DeployRunFilter) ([]DeployRun, error) {
	return f.runs, nil
}

func TestQueryDeployChanges_FiltersWindowAndSorts(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	src := fakeDeployRunSource{runs: []DeployRun{
		{RunID: "r1", StartedAt: now.Add(-10 * time.Minute).Format(time.RFC3339), FinishedAt: now.Add(-9 * time.Minute).Format(time.RFC3339), Outcome: "success", Component: "docker", Hosts: []string{"web-1", "web-1", "web-2"}},
		{RunID: "r2", StartedAt: now.Add(-5 * time.Minute).Format(time.RFC3339), FinishedAt: now.Add(-4 * time.Minute).Format(time.RFC3339), Outcome: "failed", Components: []string{"prometheus"}, Hosts: []string{"web-1"}},
		{RunID: "r3", StartedAt: now.Add(-3 * time.Hour).Format(time.RFC3339), Outcome: "success"},
	}}
	window := TimeWindow{Start: now.Add(-30 * time.Minute), End: now}
	records, err := QueryDeployChanges(src, "", "", window, 10)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %+v, want 2", records)
	}
	// Most recent first.
	if records[0].ID != "r2" || records[1].ID != "r1" {
		t.Errorf("order = %s, %s, want r2, r1", records[0].ID, records[1].ID)
	}
	if len(records[1].Hosts) != 2 {
		t.Errorf("r1 hosts = %v, want deduplicated to 2", records[1].Hosts)
	}
	if records[0].Kind != ChangeKindDeploy {
		t.Errorf("kind = %q, want deploy", records[0].Kind)
	}
}

func TestQueryRecentChanges_MergesAndSorts(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	writeEditApplyAudit(t, dir, "1-apply", editApplyAuditMetadata{
		SessionID: "edit-1", Kind: "apply", Start: now.Add(-8 * time.Minute), Finish: now.Add(-7 * time.Minute),
	})
	src := fakeDeployRunSource{runs: []DeployRun{
		{RunID: "deploy-1", StartedAt: now.Add(-3 * time.Minute).Format(time.RFC3339), Outcome: "success"},
	}}
	window := TimeWindow{Start: now.Add(-30 * time.Minute), End: now}

	records, err := QueryRecentChanges(src, dir, "", "", window, 10)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %+v, want 2", records)
	}
	if records[0].ID != "deploy-1" || records[1].ID != "edit-1" {
		t.Errorf("order = %s, %s, want deploy-1, edit-1 (most recent first)", records[0].ID, records[1].ID)
	}
}

func TestQueryRecentChanges_NilDeployStoreIsFine(t *testing.T) {
	dir := t.TempDir()
	records, err := QueryRecentChanges(nil, dir, "", "", TimeWindow{}, 10)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(records) != 0 {
		t.Fatalf("records = %v, want empty", records)
	}
}

func TestQueryRecentChanges_RespectsLimit(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	src := fakeDeployRunSource{runs: []DeployRun{
		{RunID: "r1", StartedAt: now.Add(-1 * time.Minute).Format(time.RFC3339), Outcome: "success"},
		{RunID: "r2", StartedAt: now.Add(-2 * time.Minute).Format(time.RFC3339), Outcome: "success"},
		{RunID: "r3", StartedAt: now.Add(-3 * time.Minute).Format(time.RFC3339), Outcome: "success"},
	}}
	window := TimeWindow{Start: now.Add(-30 * time.Minute), End: now}
	records, err := QueryRecentChanges(src, t.TempDir(), "", "", window, 2)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %+v, want 2 (limit)", records)
	}
}
