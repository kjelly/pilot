package detection

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const editTestProfileYAML = `# A hand-authored comment that must survive an edit.
id: edit-test-v1
version: 1
notify:
  warning: dashboard
  critical: teams
  runbookURL: docs/runbooks/detection-engine.md
features:
  - name: cpu_utilization
    required: true
    category: cpu
    scaleFloor: 0.1
    validMin: 0
    validMax: 1
    promql: x
  - name: rootfs_used_ratio
    required: true
    category: storage
    scaleFloor: 0.1
    validMin: 0
    validMax: 1
    promql: x
`

func writeEditTestProfile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.yaml")
	if err := os.WriteFile(path, []byte(editTestProfileYAML), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestSetFeatureProfileNotifyOverride_AddsCategoryOverridePreservingComments(t *testing.T) {
	path := writeEditTestProfile(t)
	runbook := "docs/runbooks/storage-alerts.md"
	action := "check disk saturation dashboard first"
	if err := SetFeatureProfileNotifyOverride(path, NotifyOverrideEdit{
		Category: "storage", RunbookURL: &runbook, RecommendedAction: &action,
	}); err != nil {
		t.Fatalf("SetFeatureProfileNotifyOverride: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read edited file: %v", err)
	}
	if !strings.Contains(string(data), "# A hand-authored comment that must survive an edit.") {
		t.Fatalf("edit destroyed a pre-existing comment:\n%s", data)
	}

	p, err := LoadFeatureProfile(path)
	if err != nil {
		t.Fatalf("reload edited profile: %v", err)
	}
	got := p.EffectiveNotifyPolicyForCategory("storage")
	if got.RunbookURL != runbook || got.RecommendedAction != action {
		t.Fatalf("effective storage policy = %+v", got)
	}
	// Untouched category must still fall back to the profile default.
	if got := p.EffectiveNotifyPolicyForCategory("cpu"); got.RunbookURL != "docs/runbooks/detection-engine.md" {
		t.Fatalf("cpu policy = %+v, want unchanged profile default", got)
	}
}

func TestSetFeatureProfileNotifyOverride_RejectsUnknownCategory(t *testing.T) {
	path := writeEditTestProfile(t)
	runbook := "docs/runbooks/x.md"
	err := SetFeatureProfileNotifyOverride(path, NotifyOverrideEdit{Category: "network_error", RunbookURL: &runbook})
	if err == nil {
		t.Fatal("expected an error for a category no feature declares")
	}
	data, _ := os.ReadFile(path)
	if string(data) != editTestProfileYAML {
		t.Fatalf("a rejected edit must not modify the file on disk")
	}
}

func TestSetFeatureProfileNotifyOverride_EmptyStringClearsOneField(t *testing.T) {
	path := writeEditTestProfile(t)
	runbook := "docs/runbooks/storage-alerts.md"
	if err := SetFeatureProfileNotifyOverride(path, NotifyOverrideEdit{Category: "storage", RunbookURL: &runbook}); err != nil {
		t.Fatalf("initial set: %v", err)
	}
	empty := ""
	if err := SetFeatureProfileNotifyOverride(path, NotifyOverrideEdit{Category: "storage", RunbookURL: &empty}); err != nil {
		t.Fatalf("clear field: %v", err)
	}
	p, err := LoadFeatureProfile(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := p.EffectiveNotifyPolicyForCategory("storage"); got.RunbookURL != "docs/runbooks/detection-engine.md" {
		t.Fatalf("storage runbookURL = %q, want cleared back to the profile default", got.RunbookURL)
	}
}

func TestSetFeatureProfileNotifyOverride_ClearCategoryRemovesWholeEntry(t *testing.T) {
	path := writeEditTestProfile(t)
	runbook := "docs/runbooks/storage-alerts.md"
	if err := SetFeatureProfileNotifyOverride(path, NotifyOverrideEdit{Category: "storage", RunbookURL: &runbook}); err != nil {
		t.Fatalf("initial set: %v", err)
	}
	if err := SetFeatureProfileNotifyOverride(path, NotifyOverrideEdit{Category: "storage", ClearCategory: true}); err != nil {
		t.Fatalf("clear category: %v", err)
	}
	p, err := LoadFeatureProfile(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(p.NotifyByCategory) != 0 {
		t.Fatalf("NotifyByCategory = %+v, want empty after ClearCategory", p.NotifyByCategory)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "notifyByCategory") {
		t.Fatalf("clearing the only category override must remove the notifyByCategory key entirely:\n%s", data)
	}
}

func TestFeatureProfile_NotifySummaryByCategory_RoundTripsThroughDisk(t *testing.T) {
	path := writeEditTestProfile(t)
	action := "check disk saturation dashboard first"
	if err := SetFeatureProfileNotifyOverride(path, NotifyOverrideEdit{Category: "storage", RecommendedAction: &action}); err != nil {
		t.Fatalf("set: %v", err)
	}
	p, err := LoadFeatureProfile(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	found := false
	for _, s := range p.NotifySummaryByCategory() {
		if s.Category == "storage" {
			found = true
			if !s.Overridden || s.Policy.RecommendedAction != action {
				t.Fatalf("storage summary = %+v", s)
			}
		}
	}
	if !found {
		t.Fatal("storage category missing from NotifySummaryByCategory")
	}
}
