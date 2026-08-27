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
	report := ComputeDrift(desiredHBAC, desiredSudo, desiredAuth, desiredAccounts, nil, nil, live)
	if !report.Empty() {
		t.Fatalf("expected no drift, got: %+v", report.Items)
	}
}

func TestComputeDrift_HBACMissingWhenDesiredButNotLive(t *testing.T) {
	desiredHBAC := []inventory.CompiledHBACRule{{Name: "pilot-grant-login-x-1", Present: true}}
	live := LiveState{HBACExists: map[string]bool{}}
	report := ComputeDrift(desiredHBAC, nil, nil, nil, nil, nil, live)
	if len(report.Items) != 1 || report.Items[0].Category != "hbac_missing" || report.Items[0].Name != "pilot-grant-login-x-1" {
		t.Fatalf("expected exactly one hbac_missing item, got: %+v", report.Items)
	}
}

func TestComputeDrift_HBACOrphanWhenLiveButNotDesired(t *testing.T) {
	live := LiveState{LiveHBACNames: []string{"pilot-grant-login-orphaned-old-9999zzzz", "allow_all"}}
	report := ComputeDrift(nil, nil, nil, nil, nil, nil, live)
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
	report := ComputeDrift(nil, desiredSudo, nil, nil, nil, nil, live)
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
	report := ComputeDrift(nil, nil, nil, desired, nil, nil, live)
	if len(report.Items) != 1 || report.Items[0].Category != "account_expiration" || report.Items[0].Name != "vendor01" {
		t.Fatalf("expected exactly one account_expiration item, got: %+v", report.Items)
	}
}

func TestComputeDrift_AccountExpirationClearedDesiredButLiveStillSet(t *testing.T) {
	desired := []inventory.CompiledAccountExpiration{{User: "vendor02", Present: false}}
	live := LiveState{UserExpiration: map[string]string{"vendor02": "20261231235959Z"}}
	report := ComputeDrift(nil, nil, nil, desired, nil, nil, live)
	if len(report.Items) != 1 || report.Items[0].Category != "account_expiration" {
		t.Fatalf("expected drift when desired clear but live still set, got: %+v", report.Items)
	}
}

func TestComputeDrift_AuthIndicatorMismatchIgnoresOrder(t *testing.T) {
	desired := []inventory.CompiledAuthPolicyHost{{Host: "db1", Indicators: []string{"otp", "pkinit"}}}
	live := LiveState{HostAuthInd: map[string][]string{"db1": {"pkinit", "otp"}}}
	if report := ComputeDrift(nil, nil, desired, nil, nil, nil, live); !report.Empty() {
		t.Fatalf("expected order-independent equality to produce no drift, got: %+v", report.Items)
	}

	live2 := LiveState{HostAuthInd: map[string][]string{"db1": {"otp"}}}
	report2 := ComputeDrift(nil, nil, desired, nil, nil, nil, live2)
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
	// capturedVars is the extra-vars @file's decoded content, captured
	// here because DriftProbe deletes that temp file via defer as soon
	// as Run returns — a caller inspecting lastArgs after DriftOnce
	// returns can no longer read the file itself.
	capturedVars map[string]any
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
		f.capturedVars = vars
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

func intPtr(n int) *int { return &n }

func TestComputeDrift_PasswordPolicyMissingLiveDetected(t *testing.T) {
	desired := []inventory.CompiledPasswordPolicy{{Group: "role-privileged", State: "present", Priority: intPtr(10)}}
	live := LiveState{PasswordPolicy: map[string]LivePasswordPolicy{}}
	report := ComputeDrift(nil, nil, nil, nil, desired, nil, live)
	if len(report.Items) != 1 || report.Items[0].Category != "password_policy_missing" {
		t.Fatalf("expected a password_policy_missing item, got: %+v", report.Items)
	}
}

func TestComputeDrift_PasswordPolicyFieldMismatchOnlyForConfiguredFields(t *testing.T) {
	// desired only configures Priority — a live min_length mismatch must
	// never be reported since Pilot has no opinion on that field here.
	desired := []inventory.CompiledPasswordPolicy{{Group: "role-privileged", State: "present", Priority: intPtr(10)}}
	live := LiveState{PasswordPolicy: map[string]LivePasswordPolicy{
		"role-privileged": {Exists: true, Priority: intPtr(20), MinLength: intPtr(4)},
	}}
	report := ComputeDrift(nil, nil, nil, nil, desired, nil, live)
	if len(report.Items) != 1 || report.Items[0].Category != "password_policy_field" || !strings.Contains(report.Items[0].Detail, "priority") {
		t.Fatalf("expected exactly one priority field-mismatch item, got: %+v", report.Items)
	}
}

func TestComputeDrift_PasswordPolicyNoDriftWhenConfiguredFieldsMatch(t *testing.T) {
	desired := []inventory.CompiledPasswordPolicy{{Group: "role-privileged", State: "present", Priority: intPtr(10), MinLength: intPtr(16)}}
	live := LiveState{PasswordPolicy: map[string]LivePasswordPolicy{
		"role-privileged": {Exists: true, Priority: intPtr(10), MinLength: intPtr(16), HistorySize: intPtr(99)},
	}}
	report := ComputeDrift(nil, nil, nil, nil, desired, nil, live)
	if !report.Empty() {
		t.Fatalf("expected no drift (HistorySize is unconfigured, live-only), got: %+v", report.Items)
	}
}

func TestComputeDrift_PasswordPolicyOrphanDetected(t *testing.T) {
	desired := []inventory.CompiledPasswordPolicy{{Group: "role-retired", State: "absent"}}
	live := LiveState{PasswordPolicy: map[string]LivePasswordPolicy{"role-retired": {Exists: true, Priority: intPtr(5)}}}
	report := ComputeDrift(nil, nil, nil, nil, desired, nil, live)
	if len(report.Items) != 1 || report.Items[0].Category != "password_policy_orphan" {
		t.Fatalf("expected a password_policy_orphan item, got: %+v", report.Items)
	}
}

func TestComputeDrift_UserAuthTypeMismatchDetected(t *testing.T) {
	desired := []inventory.CompiledUserAuthType{{User: "alice", Allowed: []string{"otp", "pkinit"}}}
	live := LiveState{UserAuthType: map[string][]string{"alice": {"password"}}}
	report := ComputeDrift(nil, nil, nil, nil, nil, desired, live)
	if len(report.Items) != 1 || report.Items[0].Category != "user_auth_type" {
		t.Fatalf("expected a user_auth_type item, got: %+v", report.Items)
	}
}

func TestComputeDrift_UserAuthTypeNoDriftWhenMatchingIgnoringOrder(t *testing.T) {
	desired := []inventory.CompiledUserAuthType{{User: "alice", Allowed: []string{"otp", "pkinit"}}}
	live := LiveState{UserAuthType: map[string][]string{"alice": {"pkinit", "otp"}}}
	if report := ComputeDrift(nil, nil, nil, nil, nil, desired, live); !report.Empty() {
		t.Fatalf("expected no drift for the same set in a different order, got: %+v", report.Items)
	}
}

// TestDriftOnce_PasswordPolicyAndUserAuthTypeFeedThroughEndToEnd exercises
// DriftOnce -> BuildPlan -> DriftProbe -> ComputeDrift for both v3.2 axes
// together, confirming the probe actually receives the desired group/user
// identifiers DriftOnce is supposed to derive from the compiled plan.
func TestDriftOnce_PasswordPolicyAndUserAuthTypeFeedThroughEndToEnd(t *testing.T) {
	dir := t.TempDir()
	rosterPath := filepath.Join(dir, "roster.yaml")
	roster := `
schema_version: 3
freeipa:
  domain: ipa.pilot.internal
  admin: {principal: admin, password: x}
users:
  - name: alice
    ssh_keys: {authoritative: true, values: []}
    authentication: {allowed: [otp]}
groups:
  - name: role-privileged
    category: role
    membership: {users: [], groups: []}
hosts: []
hostgroups: []
hbac: {rules: []}
sudo: {rules: []}
password_policies:
  - name: privileged-users
    group: role-privileged
    priority: 10
`
	if err := os.WriteFile(rosterPath, []byte(roster), 0o600); err != nil {
		t.Fatalf("write roster: %v", err)
	}
	now := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)

	runner := &fakeDriftRunner{live: LiveState{
		UserAuthType:   map[string][]string{"alice": {"otp"}},
		PasswordPolicy: map[string]LivePasswordPolicy{"role-privileged": {Exists: true, Priority: intPtr(10)}},
	}}
	report, err := DriftOnce(context.Background(), DriftProbeOptions{
		RosterFile: rosterPath, Inventory: "inv.yml", Now: now, Runner: runner,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.Empty() {
		t.Fatalf("expected no drift when live matches desired for both axes, got: %+v", report.Items)
	}

	vars := runner.capturedVars
	if vars == nil {
		t.Fatal("could not recover extra-vars from the probe invocation")
	}
	groups, _ := vars["pilot_drift_password_policy_groups"].([]any)
	if len(groups) != 1 || groups[0] != "role-privileged" {
		t.Fatalf("expected pilot_drift_password_policy_groups to carry [role-privileged], got: %v", groups)
	}
	users, _ := vars["pilot_drift_users"].([]any)
	found := false
	for _, u := range users {
		if u == "alice" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected pilot_drift_users to include alice (for user_auth_type probing), got: %v", users)
	}
}
