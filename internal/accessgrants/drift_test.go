package accessgrants

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/inventory"
)

func TestComputeDrift_NoDriftWhenLiveMatchesDesired(t *testing.T) {
	desiredHBAC := []inventory.CompiledHBACRule{{Name: "pilot-grant-login-x-1", Present: true}}
	desiredSudo := []inventory.CompiledSudoRule{{Name: "pilot-grant-sudo-x-1", Present: true}}
	desiredAuth := []inventory.CompiledAuthPolicyHost{{Host: "db1", Indicators: []string{"otp", "pkinit"}}}
	desiredAccounts := []inventory.CompiledAccountExpiration{{User: "vendor01", Present: true, Expiration: "20261231235959Z"}}
	live := LiveState{
		LiveHBACNames:  []string{"pilot-grant-login-x-1", "allow_all"},
		LiveSudoNames:  []string{"pilot-grant-sudo-x-1"},
		HBACExists:     map[string]bool{"pilot-grant-login-x-1": true},
		SudoExists:     map[string]bool{"pilot-grant-sudo-x-1": true},
		UserExpiration: map[string]string{"vendor01": "20261231235959Z"},
		HostAuthInd:    map[string][]string{"db1": {"pkinit", "otp"}},
	}
	report := ComputeDrift(desiredHBAC, desiredSudo, desiredAuth, desiredAccounts, live)
	if !report.Empty() {
		t.Fatalf("expected no drift, got: %+v", report.Items)
	}
}

func TestComputeDrift_HBACMissingWhenDesiredButNotLive(t *testing.T) {
	desiredHBAC := []inventory.CompiledHBACRule{{Name: "pilot-grant-login-x-1", Present: true}}
	live := LiveState{HBACExists: map[string]bool{}}
	report := ComputeDrift(desiredHBAC, nil, nil, nil, live)
	if len(report.Items) != 1 || report.Items[0].Category != "hbac_missing" || report.Items[0].Name != "pilot-grant-login-x-1" {
		t.Fatalf("expected exactly one hbac_missing item, got: %+v", report.Items)
	}
}

func TestComputeDrift_HBACOrphanWhenLiveButNotDesired(t *testing.T) {
	live := LiveState{LiveHBACNames: []string{"pilot-grant-login-orphaned-old-9999zzzz", "allow_all"}}
	report := ComputeDrift(nil, nil, nil, nil, live)
	if len(report.Items) != 1 || report.Items[0].Category != "hbac_orphan" || report.Items[0].Name != "pilot-grant-login-orphaned-old-9999zzzz" {
		t.Fatalf("expected exactly one hbac_orphan item (and no item for the hand-authored allow_all rule), got: %+v", report.Items)
	}
}

func TestComputeDrift_SudoOrphanAndMissing(t *testing.T) {
	desiredSudo := []inventory.CompiledSudoRule{{Name: "pilot-grant-sudo-wanted-1", Present: true}}
	live := LiveState{
		LiveSudoNames: []string{"pilot-grant-sudo-orphan-2"},
		SudoExists:    map[string]bool{},
	}
	report := ComputeDrift(nil, desiredSudo, nil, nil, live)
	var gotMissing, gotOrphan bool
	for _, item := range report.Items {
		if item.Category == "sudo_missing" && item.Name == "pilot-grant-sudo-wanted-1" {
			gotMissing = true
		}
		if item.Category == "sudo_orphan" && item.Name == "pilot-grant-sudo-orphan-2" {
			gotOrphan = true
		}
	}
	if !gotMissing || !gotOrphan || len(report.Items) != 2 {
		t.Fatalf("expected exactly one sudo_missing and one sudo_orphan, got: %+v", report.Items)
	}
}

func TestComputeDrift_AccountExpirationMismatch(t *testing.T) {
	desired := []inventory.CompiledAccountExpiration{{User: "vendor01", Present: true, Expiration: "20261231235959Z"}}
	live := LiveState{UserExpiration: map[string]string{"vendor01": "20270101000000Z"}}
	report := ComputeDrift(nil, nil, nil, desired, live)
	if len(report.Items) != 1 || report.Items[0].Category != "account_expiration" || report.Items[0].Name != "vendor01" {
		t.Fatalf("expected exactly one account_expiration item, got: %+v", report.Items)
	}
}

func TestComputeDrift_AccountExpirationClearedDesiredButLiveStillSet(t *testing.T) {
	desired := []inventory.CompiledAccountExpiration{{User: "vendor02", Present: false}}
	live := LiveState{UserExpiration: map[string]string{"vendor02": "20261231235959Z"}}
	report := ComputeDrift(nil, nil, nil, desired, live)
	if len(report.Items) != 1 || report.Items[0].Category != "account_expiration" {
		t.Fatalf("expected drift when desired clear but live still set, got: %+v", report.Items)
	}
}

func TestComputeDrift_AuthIndicatorMismatchIgnoresOrder(t *testing.T) {
	desired := []inventory.CompiledAuthPolicyHost{{Host: "db1", Indicators: []string{"otp", "pkinit"}}}
	live := LiveState{HostAuthInd: map[string][]string{"db1": {"pkinit", "otp"}}}
	if report := ComputeDrift(nil, nil, desired, nil, live); !report.Empty() {
		t.Fatalf("expected order-independent equality to produce no drift, got: %+v", report.Items)
	}

	live2 := LiveState{HostAuthInd: map[string][]string{"db1": {"otp"}}}
	report2 := ComputeDrift(nil, nil, desired, nil, live2)
	if len(report2.Items) != 1 || report2.Items[0].Category != "auth_indicator" {
		t.Fatalf("expected an auth_indicator drift item, got: %+v", report2.Items)
	}
}

func TestDriftReport_CountByCategory(t *testing.T) {
	report := DriftReport{Items: []DriftItem{
		{Category: "hbac_missing"}, {Category: "hbac_missing"}, {Category: "auth_indicator"},
	}}
	counts := report.CountByCategory()
	if counts["hbac_missing"] != 2 || counts["auth_indicator"] != 1 {
		t.Fatalf("unexpected counts: %+v", counts)
	}
}

// fakeDriftRunner mirrors fakeRunner (reconcile_test.go) but additionally
// writes a canned LiveState to whatever pilot_drift_output path the
// caller's extra-vars @file names — standing in for what the real
// freeipa-access-drift-probe.yml playbook would write.
type fakeDriftRunner struct {
	live     LiveState
	exitCode int
	runErr   error
	lastArgs []string
}

func (f *fakeDriftRunner) Run(_ context.Context, args ...string) (*ansible.Result, error) {
	f.lastArgs = args
	if f.runErr != nil {
		return nil, f.runErr
	}
	for i, a := range args {
		if a != "-e" || i+1 >= len(args) || !strings.HasPrefix(args[i+1], "@") {
			continue
		}
		data, err := os.ReadFile(strings.TrimPrefix(args[i+1], "@"))
		if err != nil {
			continue
		}
		var vars map[string]any
		if err := json.Unmarshal(data, &vars); err != nil {
			continue
		}
		outputPath, _ := vars["pilot_drift_output"].(string)
		if outputPath == "" {
			continue
		}
		live := f.live
		live.SchemaVersion = 1
		blob, err := json.Marshal(live)
		if err != nil {
			continue
		}
		_ = os.WriteFile(outputPath, blob, 0o600)
	}
	return &ansible.Result{ExitCode: f.exitCode}, nil
}

const driftTestRoster = `
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
    validity: {not_after: "2026-08-31T18:00:00Z"}
    justification: {reason: "Project X maintenance"}
`

func writeDriftTestRoster(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(driftTestRoster), 0o600); err != nil {
		t.Fatalf("write roster: %v", err)
	}
	return path
}

func TestDriftOnce_NoDriftWhenLiveMatchesCompiledPlan(t *testing.T) {
	rosterPath := writeDriftTestRoster(t)
	now := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	compiledName := inventory.CompiledLoginRuleName("vendor-project-x")

	runner := &fakeDriftRunner{live: LiveState{
		LiveHBACNames: []string{compiledName},
		HBACExists:    map[string]bool{compiledName: true},
	}}
	report, err := DriftOnce(context.Background(), DriftProbeOptions{
		RosterFile: rosterPath, Inventory: "inv.yml", Now: now, Runner: runner,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.Empty() {
		t.Fatalf("expected no drift, got: %+v", report.Items)
	}
	if len(runner.lastArgs) == 0 || runner.lastArgs[0] != DriftProbePlaybook {
		t.Fatalf("expected the drift-probe playbook to be invoked, got args: %v", runner.lastArgs)
	}
}

func TestDriftOnce_ReportsMissingCompiledRule(t *testing.T) {
	rosterPath := writeDriftTestRoster(t)
	now := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)

	runner := &fakeDriftRunner{live: LiveState{HBACExists: map[string]bool{}}}
	report, err := DriftOnce(context.Background(), DriftProbeOptions{
		RosterFile: rosterPath, Inventory: "inv.yml", Now: now, Runner: runner,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Items) != 1 || report.Items[0].Category != "hbac_missing" {
		t.Fatalf("expected exactly one hbac_missing item, got: %+v", report.Items)
	}
}

func TestDriftOnce_RecordsAuditEventWhenStateDirSet(t *testing.T) {
	rosterPath := writeDriftTestRoster(t)
	stateDir := t.TempDir()
	now := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	runner := &fakeDriftRunner{live: LiveState{HBACExists: map[string]bool{}}}

	if _, err := DriftOnce(context.Background(), DriftProbeOptions{
		RosterFile: rosterPath, Inventory: "inv.yml", Now: now, Runner: runner, StateDir: stateDir,
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(stateDir, "access", "audit.jsonl"))
	if err != nil {
		t.Fatalf("expected an audit log to be written: %v", err)
	}
	var ev AccessAuditEvent
	if err := json.Unmarshal(data[:strings.IndexByte(string(data), '\n')+1], &ev); err != nil {
		t.Fatalf("malformed audit event: %v (raw: %s)", err, data)
	}
	if ev.Action != AuditActionAccessDriftDetected || ev.Outcome != "success" || ev.ID == "" {
		t.Fatalf("unexpected audit event: %+v", ev)
	}
}

func TestRepairManaged_SkipsReconcileWhenNoDrift(t *testing.T) {
	rosterPath := writeDriftTestRoster(t)
	now := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	compiledName := inventory.CompiledLoginRuleName("vendor-project-x")
	driftRunner := &fakeDriftRunner{live: LiveState{
		LiveHBACNames: []string{compiledName},
		HBACExists:    map[string]bool{compiledName: true},
	}}

	before, plan, result, err := RepairManaged(context.Background(),
		DriftProbeOptions{RosterFile: rosterPath, Inventory: "inv.yml", Now: now, Runner: driftRunner},
		ReconcileOptions{RosterFile: rosterPath, Inventory: "inv.yml", Now: now, Runner: &fakeRunner{exitCode: 0}},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !before.Empty() {
		t.Fatalf("expected no drift found, got: %+v", before.Items)
	}
	if result != nil || len(plan.HBACRules) != 0 {
		t.Fatalf("expected ReconcileOnce to never be invoked when there is no drift to repair, got plan=%+v result=%v", plan, result)
	}
}

func TestRepairManaged_InvokesReconcileWhenDriftFound(t *testing.T) {
	rosterPath := writeDriftTestRoster(t)
	now := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	driftRunner := &fakeDriftRunner{live: LiveState{HBACExists: map[string]bool{}}}
	reconcileRunner := &fakeRunner{exitCode: 0}

	before, plan, result, err := RepairManaged(context.Background(),
		DriftProbeOptions{RosterFile: rosterPath, Inventory: "inv.yml", Now: now, Runner: driftRunner},
		ReconcileOptions{RosterFile: rosterPath, Inventory: "inv.yml", Now: now, Runner: reconcileRunner},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if before.Empty() {
		t.Fatal("expected drift to be found")
	}
	if result == nil || result.ExitCode != 0 {
		t.Fatalf("expected ReconcileOnce to run and succeed, got result=%v", result)
	}
	if len(plan.HBACRules) != 1 {
		t.Fatalf("expected the reconcile plan to compile the one grant, got: %+v", plan)
	}
	if reconcileRunner.lastArgs == nil {
		t.Fatal("expected the reconcile apply playbook to actually be invoked")
	}
}
