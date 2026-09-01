package repair

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/networkcheck"
)

// reapplyTestRepoRoot writes a fake canonical apply playbook under a
// temp dir and returns (repoRoot, relativePlaybookPath) — BuildReapplyPlan
// reads real file bytes for PlaybookHash, so tests need a real file, not
// a stubbed reader.
func reapplyTestRepoRoot(t *testing.T) (root, relPath string) {
	t.Helper()
	dir := t.TempDir()
	relPath = "playbooks/apply/prometheus-apply.yml"
	full := filepath.Join(dir, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("- hosts: prometheus\n  tasks: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, relPath
}

func reapplyTestContract(playbookPath string) contract.Contract {
	return contract.Contract{
		ID: "prometheus", Role: "prometheus",
		Playbooks:   contract.Playbooks{Apply: playbookPath},
		Specs:       []contract.Spec{{Path: "docs/verification/prometheus.md", Rows: contract.RowSelector{All: true}}},
		StagePolicy: contract.StagePolicy{Variable: "stage", Default: "sandbox"},
		Remediation: contract.Remediation{Actions: []contract.RemediationAction{
			{ID: "reapply", Risk: "R2", Executor: contract.RemediationActionExecutor{Kind: "canonical_apply"},
				MaxTargets: 1, RequiresApproval: true, Verification: contract.RemediationVerification{Spec: "docs/verification/prometheus.md"},
				Preflight: contract.RemediationPreflight{RequireIdempotencyEvidence: true, RequireDependencyHealth: true}},
		}},
	}
}

func reapplyTestResolvedInventory() networkcheck.ResolvedInventory {
	return networkcheck.ResolvedInventory{
		GroupHosts: map[string][]string{"prometheus": {"web-1"}},
		HostVars:   map[string]map[string]any{"web-1": {"ansible_host": "10.0.0.5", "stage": "sandbox"}},
	}
}

func noDeps(ctx context.Context, catalog contract.Catalog, resolved networkcheck.ResolvedInventory, host, component string) ([]DependencyStatus, error) {
	return nil, nil
}

func unhealthyDeps(ctx context.Context, catalog contract.Catalog, resolved networkcheck.ResolvedInventory, host, component string) ([]DependencyStatus, error) {
	return []DependencyStatus{{Component: "docker", Required: true, Healthy: false, Detail: "inactive"}}, nil
}

func fakePreview(supported bool, stdout string, exitCode int, err error) PreviewRunner {
	return func(ctx context.Context, playbookPath, inventory, host, stage string) (string, int, error) {
		return stdout, exitCode, err
	}
}

func TestBuildReapplyPlan_Success(t *testing.T) {
	root, relPath := reapplyTestRepoRoot(t)
	catalog := testCatalog(t, reapplyTestContract(relPath))
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	preview := fakePreview(true, "PLAY RECAP ***\nweb-1 : ok=1 changed=0\n", 0, nil)
	p, err := BuildReapplyPlan(context.Background(), catalog, reapplyTestResolvedInventory(), noDeps, preview,
		root, "/tmp/inv.yml", "plan-1", "inc-1", "web-1", "prometheus", "reapply", now)
	if err != nil {
		t.Fatalf("BuildReapplyPlan: %v", err)
	}
	if p.Risk != "R2" {
		t.Errorf("Risk = %q, want R2", p.Risk)
	}
	if p.Resolved.PlaybookHash == "" {
		t.Error("PlaybookHash is empty")
	}
	if p.Resolved.Stage != "sandbox" {
		t.Errorf("Stage = %q, want sandbox", p.Resolved.Stage)
	}
	if p.PlanHash == "" {
		t.Error("PlanHash is empty")
	}
	if !p.ExpiresAt.Equal(now.Add(ReapplyPlanTTL)) {
		t.Errorf("ExpiresAt = %v, want %v", p.ExpiresAt, now.Add(ReapplyPlanTTL))
	}
}

func TestBuildReapplyPlan_RejectsR1Action(t *testing.T) {
	root, relPath := reapplyTestRepoRoot(t)
	c := reapplyTestContract(relPath)
	c.Remediation.Actions[0].Risk = "R1"
	c.Remediation.Actions[0].Executor.Kind = "docker_restart"
	c.Remediation.Actions[0].Executor.Target = "pilot-prometheus"
	catalog := testCatalog(t, c)
	_, err := BuildReapplyPlan(context.Background(), catalog, reapplyTestResolvedInventory(), noDeps, fakePreview(true, "", 0, nil),
		root, "/tmp/inv.yml", "plan-1", "inc-1", "web-1", "prometheus", "reapply", time.Now())
	if err == nil {
		t.Fatal("expected an error: BuildReapplyPlan must refuse a non-R2/non-canonical_apply action")
	}
}

func TestBuildReapplyPlan_UnhealthyRequiredDependencyBlocksPlan(t *testing.T) {
	root, relPath := reapplyTestRepoRoot(t)
	catalog := testCatalog(t, reapplyTestContract(relPath))
	_, err := BuildReapplyPlan(context.Background(), catalog, reapplyTestResolvedInventory(), unhealthyDeps, fakePreview(true, "", 0, nil),
		root, "/tmp/inv.yml", "plan-1", "inc-1", "web-1", "prometheus", "reapply", time.Now())
	if err == nil {
		t.Fatal("expected an error: an unhealthy required dependency must block planning")
	}
}

func TestBuildReapplyPlan_MissingPlaybookFileErrors(t *testing.T) {
	root, _ := reapplyTestRepoRoot(t)
	catalog := testCatalog(t, reapplyTestContract("playbooks/apply/does-not-exist.yml"))
	_, err := BuildReapplyPlan(context.Background(), catalog, reapplyTestResolvedInventory(), noDeps, fakePreview(true, "", 0, nil),
		root, "/tmp/inv.yml", "plan-1", "inc-1", "web-1", "prometheus", "reapply", time.Now())
	if err == nil {
		t.Fatal("expected an error: the canonical playbook file does not exist")
	}
}

func TestBuildReapplyPlan_MissingRequiredSecretBlocksPlan(t *testing.T) {
	root, relPath := reapplyTestRepoRoot(t)
	c := reapplyTestContract(relPath)
	c.GroupVars = []contract.GroupVar{{Name: "alertmanager_config", Type: "string", Required: true, Secret: true}}
	catalog := testCatalog(t, c)
	resolved := reapplyTestResolvedInventory() // no alertmanager_config set
	_, err := BuildReapplyPlan(context.Background(), catalog, resolved, noDeps, fakePreview(true, "", 0, nil),
		root, "/tmp/inv.yml", "plan-1", "inc-1", "web-1", "prometheus", "reapply", time.Now())
	if err == nil {
		t.Fatal("expected an error: a missing required secret reference must block planning")
	}
}

func TestBuildReapplyPlan_ResolvedSecretNeverStoredAsValue(t *testing.T) {
	root, relPath := reapplyTestRepoRoot(t)
	c := reapplyTestContract(relPath)
	c.GroupVars = []contract.GroupVar{
		{Name: "alertmanager_config", Type: "string", Required: true, Secret: true},
		{Name: "retention_days", Type: "integer", Required: true, Secret: false},
	}
	catalog := testCatalog(t, c)
	resolved := reapplyTestResolvedInventory()
	resolved.HostVars["web-1"]["alertmanager_config"] = "TOP-SECRET-VALUE-MUST-NEVER-APPEAR-IN-PLAN"
	resolved.HostVars["web-1"]["retention_days"] = float64(30)

	p, err := BuildReapplyPlan(context.Background(), catalog, resolved, noDeps, fakePreview(true, "", 0, nil),
		root, "/tmp/inv.yml", "plan-1", "inc-1", "web-1", "prometheus", "reapply", time.Now())
	if err != nil {
		t.Fatalf("BuildReapplyPlan: %v", err)
	}
	if len(p.Resolved.SecretReferenceKeys) != 1 || p.Resolved.SecretReferenceKeys[0] != "alertmanager_config" {
		t.Fatalf("SecretReferenceKeys = %v, want [alertmanager_config]", p.Resolved.SecretReferenceKeys)
	}
	if len(p.Resolved.ResolvedInputKeys) != 1 || p.Resolved.ResolvedInputKeys[0] != "retention_days" {
		t.Fatalf("ResolvedInputKeys = %v, want [retention_days]", p.Resolved.ResolvedInputKeys)
	}
	// The actual secret value must never appear anywhere in the plan.
	for _, key := range p.Resolved.SecretReferenceKeys {
		if key == "TOP-SECRET-VALUE-MUST-NEVER-APPEAR-IN-PLAN" {
			t.Fatal("secret value leaked into SecretReferenceKeys")
		}
	}
}

func TestBuildReapplyPlan_AmbiguousTypeBlocksPlan(t *testing.T) {
	root, relPath := reapplyTestRepoRoot(t)
	c := reapplyTestContract(relPath)
	c.GroupVars = []contract.GroupVar{{Name: "retention_days", Type: "integer", Required: true}}
	catalog := testCatalog(t, c)
	resolved := reapplyTestResolvedInventory()
	resolved.HostVars["web-1"]["retention_days"] = "not-a-number" // declared integer, resolved as string
	_, err := BuildReapplyPlan(context.Background(), catalog, resolved, noDeps, fakePreview(true, "", 0, nil),
		root, "/tmp/inv.yml", "plan-1", "inc-1", "web-1", "prometheus", "reapply", time.Now())
	if err == nil {
		t.Fatal("expected an error: a type-inconsistent resolved input is ambiguous and must block planning")
	}
}

func TestBuildReapplyPlan_UnsupportedPreviewIsRecordedNotSkipped(t *testing.T) {
	root, relPath := reapplyTestRepoRoot(t)
	catalog := testCatalog(t, reapplyTestContract(relPath))
	preview := fakePreview(false, "", 2, nil) // nonzero exit, no PLAY RECAP -> unsupported
	p, err := BuildReapplyPlan(context.Background(), catalog, reapplyTestResolvedInventory(), noDeps, preview,
		root, "/tmp/inv.yml", "plan-1", "inc-1", "web-1", "prometheus", "reapply", time.Now())
	if err != nil {
		t.Fatalf("BuildReapplyPlan: %v", err)
	}
	if p.Resolved.PreviewRef == "" {
		t.Fatal("PreviewRef must still be set (and hashed) even when the preview is unsupported — never silently skipped")
	}
}

// TestBuildReapplyPlan_SkippedCheckModeTaskIsUnsupportedNotZeroChanges
// locks in a real finding from a live drift-injection test against
// alertmanager's own canonical apply playbook (2026-09-01): its
// config-rendering task is gated `when: not ansible_check_mode` (a
// common, legitimate pattern for a task that would fail on a fresh host
// with no parent directory yet). Under --check, ansible SKIPS it
// entirely instead of diffing, so a REAL, injected config drift
// produced changed=0 with no error — a preview that would silently tell
// a human approver "no changes" while real drift sat unfixed.
func TestBuildReapplyPlan_SkippedCheckModeTaskIsUnsupportedNotZeroChanges(t *testing.T) {
	root, relPath := reapplyTestRepoRoot(t)
	catalog := testCatalog(t, reapplyTestContract(relPath))
	preview := fakePreview(true, "PLAY RECAP ***\nweb-1 : ok=3 changed=0 unreachable=0 failed=0 skipped=8\n", 0, nil)
	p, err := BuildReapplyPlan(context.Background(), catalog, reapplyTestResolvedInventory(), noDeps, preview,
		root, "/tmp/inv.yml", "plan-1", "inc-1", "web-1", "prometheus", "reapply", time.Now())
	if err != nil {
		t.Fatalf("BuildReapplyPlan: %v", err)
	}
	if p.Resolved.PreviewSupported {
		t.Fatal("PreviewSupported = true, want false — a skipped check-mode task means the diff cannot be trusted")
	}
	if p.Resolved.PreviewUnsupportedReason == "" {
		t.Fatal("PreviewUnsupportedReason must explain why the preview is untrustworthy")
	}
}

func TestBuildReapplyPlan_BroadChangeSurfaceBlocksPlan(t *testing.T) {
	root, relPath := reapplyTestRepoRoot(t)
	catalog := testCatalog(t, reapplyTestContract(relPath))
	// ParseDiff counts files from --diff markers in the raw stdout —
	// build enough distinct file diffs to exceed the threshold.
	var stdout strings.Builder
	stdout.WriteString("PLAY RECAP ***\nweb-1 : ok=1 changed=1\n")
	for i := 0; i < ReapplyPreviewChangeThreshold+1; i++ {
		fmt.Fprintf(&stdout, "--- before: /etc/file%d.conf\n+++ after: /etc/file%d.conf\n@@ -1,1 +1,1 @@\n-old\n+new\n", i, i)
	}
	preview := fakePreview(true, stdout.String(), 0, nil)
	_, err := BuildReapplyPlan(context.Background(), catalog, reapplyTestResolvedInventory(), noDeps, preview,
		root, "/tmp/inv.yml", "plan-1", "inc-1", "web-1", "prometheus", "reapply", time.Now())
	if err == nil || !strings.Contains(err.Error(), ReapplyPreviewBlocked) {
		t.Fatalf("err = %v, want a %s error for an unexpectedly broad change surface", err, ReapplyPreviewBlocked)
	}
}

func TestBuildReapplyPlan_PlanHashChangesWhenDependencySnapshotChanges(t *testing.T) {
	root, relPath := reapplyTestRepoRoot(t)
	catalog := testCatalog(t, reapplyTestContract(relPath))
	now := time.Now()
	healthyDeps := func(ctx context.Context, catalog contract.Catalog, resolved networkcheck.ResolvedInventory, host, component string) ([]DependencyStatus, error) {
		return []DependencyStatus{{Component: "docker", Required: true, Healthy: true, Detail: "active"}}, nil
	}
	p1, err := BuildReapplyPlan(context.Background(), catalog, reapplyTestResolvedInventory(), healthyDeps, fakePreview(true, "", 0, nil),
		root, "/tmp/inv.yml", "plan-1", "inc-1", "web-1", "prometheus", "reapply", now)
	if err != nil {
		t.Fatalf("BuildReapplyPlan: %v", err)
	}
	healthyDeps2 := func(ctx context.Context, catalog contract.Catalog, resolved networkcheck.ResolvedInventory, host, component string) ([]DependencyStatus, error) {
		return []DependencyStatus{{Component: "docker", Required: true, Healthy: true, Detail: "different detail text"}}, nil
	}
	p2, err := BuildReapplyPlan(context.Background(), catalog, reapplyTestResolvedInventory(), healthyDeps2, fakePreview(true, "", 0, nil),
		root, "/tmp/inv.yml", "plan-2", "inc-1", "web-1", "prometheus", "reapply", now)
	if err != nil {
		t.Fatalf("BuildReapplyPlan: %v", err)
	}
	if p1.PlanHash == p2.PlanHash {
		t.Fatal("PlanHash must change when the dependency snapshot changes")
	}
}
