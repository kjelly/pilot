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

const reconcileTestRosterWithSoDConflict = `
schema_version: 3
freeipa:
  domain: ipa.pilot.internal
  admin: {principal: admin, password: x}
users:
  - name: bob
    ssh_keys: {authoritative: true, values: []}
groups:
  - name: role-payment-create
    category: role
    membership: {users: [bob], groups: []}
  - name: role-payment-approve
    category: role
    membership: {users: [bob], groups: []}
hosts: []
hostgroups: []
hbac:
  rules: []
sudo:
  rules: []
security:
  conflicts:
    - name: payment-create-vs-approve
      mutually_exclusive: [role-payment-create, role-payment-approve]
`

func TestReconcileOnce_RefusesWhenSoDConflictExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(reconcileTestRosterWithSoDConflict), 0o600); err != nil {
		t.Fatalf("write roster: %v", err)
	}
	runner := &fakeRunner{exitCode: 0}

	_, _, err := ReconcileOnce(context.Background(), ReconcileOptions{
		RosterFile: path,
		Inventory:  "inv.yml",
		Now:        time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC),
		Runner:     runner,
	})
	if err == nil {
		t.Fatal("expected an error when a SoD conflict exists")
	}
	if !strings.Contains(err.Error(), "payment-create-vs-approve") {
		t.Fatalf("expected the error to name the conflicting rule, got: %v", err)
	}
	if runner.lastArgs != nil {
		t.Fatalf("expected ansible-playbook to never run when the policy gate fails, but it was invoked with: %v", runner.lastArgs)
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
	if ev.PilotCompiledAccountExpirations == nil || len(ev.PilotCompiledAccountExpirations) != 0 {
		t.Fatalf("expected an empty, non-nil account-expirations list when the roster has none, got: %v", ev.PilotCompiledAccountExpirations)
	}
}

const reconcileTestRosterWithAccountPolicies = `
schema_version: 3
freeipa:
  domain: ipa.pilot.internal
  admin: {principal: admin, password: x}
users:
  - name: vendor01
    ssh_keys: {authoritative: true, values: []}
  - name: vendor02
    ssh_keys: {authoritative: true, values: []}
groups: []
hosts: []
hostgroups: []
hbac:
  rules: []
sudo:
  rules: []
account_policies:
  - name: vendor01-contract
    user: vendor01
    type: contractor
    validity: {not_after: "2026-12-31T23:59:59Z"}
  - name: vendor02-contract
    user: vendor02
    state: absent
    type: contractor
    validity: {not_after: "2026-12-31T23:59:59Z"}
`

// TestBuildExtraVars_ThreadsAccountExpirations exercises v3.1 §7's wiring
// end to end (BuildPlan -> buildExtraVars): a present account_policy
// compiles to a set entry, and an all-absent one compiles to the explicit
// clear entry (empty Expiration) the apply playbook's task keys off.
func TestBuildExtraVars_ThreadsAccountExpirations(t *testing.T) {
	dir := t.TempDir()
	rosterPath := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(rosterPath, []byte(reconcileTestRosterWithAccountPolicies), 0o600); err != nil {
		t.Fatalf("write roster: %v", err)
	}

	plan, err := BuildPlan(rosterPath, time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ev := buildExtraVars(rosterPath, plan)
	if len(ev.PilotCompiledAccountExpirations) != 2 {
		t.Fatalf("expected two compiled account-expiration entries, got: %+v", ev.PilotCompiledAccountExpirations)
	}
	byUser := map[string]string{}
	for _, a := range ev.PilotCompiledAccountExpirations {
		byUser[a.User] = a.Expiration
	}
	if byUser["vendor01"] != "20261231235959Z" {
		t.Fatalf("expected vendor01 to compile to its not_after, got: %q", byUser["vendor01"])
	}
	if exp, ok := byUser["vendor02"]; !ok || exp != "" {
		t.Fatalf("expected vendor02 (all entries absent) to compile to an explicit clear (empty expiration), got: %q (present=%v)", exp, ok)
	}
}

const reconcileTestRosterWithPasswordPolicies = `
schema_version: 3
freeipa:
  domain: ipa.pilot.internal
  admin: {principal: admin, password: x}
users: []
groups:
  - name: role-privileged
    category: role
    membership: {users: [], groups: []}
hosts: []
hostgroups: []
hbac:
  rules: []
sudo:
  rules: []
password_policies:
  - name: privileged-users
    group: role-privileged
    priority: 10
    min_length: 16
    history_size: 0
    max_life: 90d
    min_life: 1h
    lockout:
      max_failures: 5
      failure_reset_interval: 15m
      lockout_duration: 15m
  - name: retired-policy
    state: absent
    group: role-privileged
`

// TestBuildExtraVars_ThreadsPasswordPolicies exercises v3.2 §7's wiring
// end to end (BuildPlan -> buildExtraVars): unit conversion (days/hours/
// seconds) survives the round trip, history_size: 0 stays a non-nil
// pointer to zero (not omitted as "unset"), and an absent entry carries
// no optional fields at all.
func TestBuildExtraVars_ThreadsPasswordPolicies(t *testing.T) {
	dir := t.TempDir()
	rosterPath := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(rosterPath, []byte(reconcileTestRosterWithPasswordPolicies), 0o600); err != nil {
		t.Fatalf("write roster: %v", err)
	}

	plan, err := BuildPlan(rosterPath, time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ev := buildExtraVars(rosterPath, plan)
	if len(ev.PilotCompiledPasswordPolicies) != 2 {
		t.Fatalf("expected two compiled password_policy entries, got: %+v", ev.PilotCompiledPasswordPolicies)
	}

	present := ev.PilotCompiledPasswordPolicies[0]
	if present.Group != "role-privileged" || present.State != "present" {
		t.Fatalf("unexpected present entry: %+v", present)
	}
	if present.Priority == nil || *present.Priority != 10 {
		t.Errorf("Priority = %v, want 10", present.Priority)
	}
	if present.HistorySize == nil || *present.HistorySize != 0 {
		t.Errorf("HistorySize = %v, want pointer to 0", present.HistorySize)
	}
	if present.MaxLifeDays == nil || *present.MaxLifeDays != 90 {
		t.Errorf("MaxLifeDays = %v, want 90", present.MaxLifeDays)
	}
	if present.MinLifeHours == nil || *present.MinLifeHours != 1 {
		t.Errorf("MinLifeHours = %v, want 1", present.MinLifeHours)
	}
	if present.LockoutFailureResetSeconds == nil || *present.LockoutFailureResetSeconds != 900 {
		t.Errorf("LockoutFailureResetSeconds = %v, want 900", present.LockoutFailureResetSeconds)
	}

	absent := ev.PilotCompiledPasswordPolicies[1]
	if absent.State != "absent" || absent.Group != "role-privileged" {
		t.Fatalf("unexpected absent entry: %+v", absent)
	}
	if absent.Priority != nil {
		t.Errorf("absent entry Priority = %v, want nil", absent.Priority)
	}
}

const reconcileTestRosterWithAuthPolicy = `
schema_version: 3
freeipa:
  domain: ipa.pilot.internal
  admin: {principal: admin, password: x}
users: []
groups: []
hosts: []
hostgroups: []
hbac:
  rules: []
sudo:
  rules: []
auth_policies:
  - name: gpu-strong-auth
    state: present
    targets: {hosts: [gpu01.ipa.pilot.internal], hostgroups: []}
    require_any: [otp, pkinit]
`

const reconcileTestRosterWithAuthPolicyRemoved = `
schema_version: 3
freeipa:
  domain: ipa.pilot.internal
  admin: {principal: admin, password: x}
users: []
groups: []
hosts: []
hostgroups: []
hbac:
  rules: []
sudo:
  rules: []
auth_policies: []
`

// TestReconcileOnce_AuthPolicyPruneAcrossTwoRuns exercises the real
// prune-tracking wiring end to end: a first reconcile with an
// auth_policies entry (StateDir set) records gpu01 as Pilot-managed;
// removing that entry from the roster and reconciling again must append
// an explicit-clear entry for gpu01 (Indicators empty) — the fix for the
// live-confirmed bug where a removed auth_policies entry left its host's
// krbPrincipalAuthInd stale forever (playbooks/apply/
// freeipa-identity-apply.yml's host-mod task never touches a host that
// simply isn't in pilot_compiled_auth_policy_hosts anymore).
func TestReconcileOnce_AuthPolicyPruneAcrossTwoRuns(t *testing.T) {
	dir := t.TempDir()
	rosterPath := filepath.Join(dir, "roster.yaml")
	stateDir := t.TempDir()
	now := time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC)

	if err := os.WriteFile(rosterPath, []byte(reconcileTestRosterWithAuthPolicy), 0o600); err != nil {
		t.Fatalf("write roster: %v", err)
	}
	runner := &fakeRunner{exitCode: 0}
	plan, _, err := ReconcileOnce(context.Background(), ReconcileOptions{
		RosterFile: rosterPath, Inventory: "inv.yml", Now: now, Runner: runner, StateDir: stateDir,
	})
	if err != nil {
		t.Fatalf("first ReconcileOnce() error = %v", err)
	}
	if len(plan.AuthPolicyHosts) != 1 || plan.AuthPolicyHosts[0].Host != "gpu01.ipa.pilot.internal" {
		t.Fatalf("first plan.AuthPolicyHosts = %+v, want exactly gpu01 with indicators", plan.AuthPolicyHosts)
	}
	store, err := openAuthPolicyStore(stateDir)
	if err != nil {
		t.Fatalf("openAuthPolicyStore() error = %v", err)
	}
	recorded, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(recorded) != 1 || recorded[0].Host != "gpu01.ipa.pilot.internal" || len(recorded[0].Indicators) != 2 {
		t.Fatalf("recorded state = %+v, want gpu01 with 2 indicators", recorded)
	}

	if err := os.WriteFile(rosterPath, []byte(reconcileTestRosterWithAuthPolicyRemoved), 0o600); err != nil {
		t.Fatalf("rewrite roster: %v", err)
	}
	plan2, _, err := ReconcileOnce(context.Background(), ReconcileOptions{
		RosterFile: rosterPath, Inventory: "inv.yml", Now: now, Runner: runner, StateDir: stateDir,
	})
	if err != nil {
		t.Fatalf("second ReconcileOnce() error = %v", err)
	}
	if len(plan2.AuthPolicyHosts) != 1 || plan2.AuthPolicyHosts[0].Host != "gpu01.ipa.pilot.internal" {
		t.Fatalf("second plan.AuthPolicyHosts = %+v, want exactly one prune entry for gpu01", plan2.AuthPolicyHosts)
	}
	if len(plan2.AuthPolicyHosts[0].Indicators) != 0 {
		t.Fatalf("prune entry Indicators = %v, want empty (explicit clear)", plan2.AuthPolicyHosts[0].Indicators)
	}

	recorded2, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(recorded2) != 0 {
		t.Fatalf("recorded state after removal = %+v, want empty — gpu01 is no longer Pilot-managed", recorded2)
	}
}
