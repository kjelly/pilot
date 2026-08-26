package accessgrants

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/ansible"
)

type fakeRunner struct {
	exitCode int
	runErr   error
	lastArgs []string
}

func (f *fakeRunner) Run(_ context.Context, args ...string) (*ansible.Result, error) {
	f.lastArgs = args
	if f.runErr != nil {
		return nil, f.runErr
	}
	return &ansible.Result{ExitCode: f.exitCode}, nil
}

const reconcileTestRoster = `
schema_version: 3
freeipa:
  domain: ipa.pilot.internal
  admin: {principal: admin, password: x}
users:
  - name: vendor01
    ssh_keys: {authoritative: true, values: []}
groups: []
hosts:
  - name: db-special.ipa.pilot.internal
    ip_address: 10.0.0.5
hostgroups: []
hbac:
  rules: []
sudo:
  rules: []
grants:
  - name: vendor-project-x
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2026-08-31T18:00:00+08:00"}
    justification: {reason: "Project X maintenance"}
`

func writeReconcileTestRoster(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(reconcileTestRoster), 0o600); err != nil {
		t.Fatalf("write roster: %v", err)
	}
	return path
}

func TestReconcileOnce_RequiresRosterAndInventory(t *testing.T) {
	if _, _, err := ReconcileOnce(context.Background(), ReconcileOptions{Inventory: "inv.yml"}); err == nil {
		t.Fatal("expected an error when RosterFile is empty")
	}
	if _, _, err := ReconcileOnce(context.Background(), ReconcileOptions{RosterFile: "roster.yaml"}); err == nil {
		t.Fatal("expected an error when Inventory is empty")
	}
}

func TestReconcileOnce_InvokesConfiguredPlaybookAndInventory(t *testing.T) {
	rosterPath := writeReconcileTestRoster(t)
	runner := &fakeRunner{exitCode: 0}
	now := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)

	plan, result, err := ReconcileOnce(context.Background(), ReconcileOptions{
		RosterFile: rosterPath,
		Inventory:  "inv.yml",
		Playbook:   "playbooks/apply/freeipa-identity-apply.yml",
		Now:        now,
		Runner:     runner,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("unexpected exit code: %d", result.ExitCode)
	}
	if len(plan.HBACRules) != 1 || len(plan.SudoRules) != 0 {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if len(runner.lastArgs) < 4 || runner.lastArgs[0] != "playbooks/apply/freeipa-identity-apply.yml" {
		t.Fatalf("unexpected args: %v", runner.lastArgs)
	}
	if runner.lastArgs[1] != "-i" || runner.lastArgs[2] != "inv.yml" {
		t.Fatalf("expected -i inv.yml, got: %v", runner.lastArgs)
	}
	if runner.lastArgs[3] != "-e" || !strings.HasPrefix(runner.lastArgs[4], "@") {
		t.Fatalf("expected extra-vars passed as -e @<file>, got: %v", runner.lastArgs)
	}
}

func TestReconcileOnce_ReportsPlaybookFailure(t *testing.T) {
	rosterPath := writeReconcileTestRoster(t)
	runner := &fakeRunner{exitCode: 1}
	_, result, err := ReconcileOnce(context.Background(), ReconcileOptions{
		RosterFile: rosterPath,
		Inventory:  "inv.yml",
		Now:        time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC),
		Runner:     runner,
	})
	if err == nil {
		t.Fatal("expected an error when the playbook exits non-zero")
	}
	if result == nil || result.ExitCode != 1 {
		t.Fatalf("expected the failing result to still be returned, got: %v", result)
	}
}

func TestBuildExtraVars_SeparatesPresentFromPrune(t *testing.T) {
	rosterPath := writeReconcileTestRoster(t)
	// Active grant at "now" -> present; the same roster evaluated well
	// after not_after would be expired-but-still-Present (HBAC disables
	// rather than deletes) — pruning only happens for state: absent, which
	// this fixture doesn't exercise directly, so this test just checks the
	// present branch populates and the prune lists stay non-nil empty
	// slices rather than nil (so the JSON always encodes `[]`, never
	// `null`).
	plan, err := BuildPlan(rosterPath, time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ev := buildExtraVars(rosterPath, plan)
	if len(ev.PilotCompiledGrantHBACRules) != 1 {
		t.Fatalf("expected one present hbac rule, got: %+v", ev.PilotCompiledGrantHBACRules)
	}
	if ev.PilotCompiledGrantHBACPrune == nil || len(ev.PilotCompiledGrantHBACPrune) != 0 {
		t.Fatalf("expected an empty, non-nil prune list, got: %v", ev.PilotCompiledGrantHBACPrune)
	}
	if ev.PilotCompiledGrantSudoRules == nil || ev.PilotCompiledGrantSudoPrune == nil {
		t.Fatalf("expected non-nil empty sudo lists, got: %+v / %v", ev.PilotCompiledGrantSudoRules, ev.PilotCompiledGrantSudoPrune)
	}
}
