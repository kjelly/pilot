package accessgrants

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const healthTestRosterNoGrants = `
schema_version: 3
freeipa:
  domain: ipa.pilot.internal
  admin: {principal: admin, password: x}
users:
  - name: vendor01
    ssh_keys: {authoritative: true, values: []}
groups: []
hosts: []
hostgroups: []
hbac:
  rules: []
sudo:
  rules: []
`

func writeHealthTestRoster(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write roster: %v", err)
	}
	return path
}

func TestEvaluateHealth_HealthyWhenNothingOutstanding(t *testing.T) {
	rosterPath := writeHealthTestRoster(t, healthTestRosterNoGrants)
	now := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	runner := &fakeDriftRunner{live: LiveState{}}

	health, err := EvaluateHealth(context.Background(), HealthOptions{
		DriftProbeOptions: DriftProbeOptions{RosterFile: rosterPath, Inventory: "inv.yml", Now: now, Runner: runner},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if health.Status != HealthHealthy || !health.FreeIPAReachable {
		t.Fatalf("expected a healthy report, got: %+v", health)
	}
}

// TestEvaluateHealth_CriticalWhenCompiledRuleMissing exercises drift
// dominating status: a present temporary_grant whose compiled HBAC rule
// doesn't exist live is both a reconcile-required grant AND a drift
// finding — drift must win (critical), not degraded.
func TestEvaluateHealth_CriticalWhenCompiledRuleMissing(t *testing.T) {
	rosterPath := writeDriftTestRoster(t) // has one present temporary_grant
	now := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	runner := &fakeDriftRunner{live: LiveState{HBACExists: map[string]bool{}}}

	health, err := EvaluateHealth(context.Background(), HealthOptions{
		DriftProbeOptions: DriftProbeOptions{RosterFile: rosterPath, Inventory: "inv.yml", Now: now, Runner: runner},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if health.Status != HealthCritical {
		t.Fatalf("expected critical (missing compiled rule), got: %+v", health)
	}
	if health.ReconcileRequiredTemporaryGrantCount != 1 {
		t.Fatalf("expected exactly one reconcile-required temporary grant, got: %+v", health)
	}
}

// TestEvaluateHealth_DegradedWithoutAnyDrift is the pure "reconcile
// required but nothing is actually wrong yet" case (§16.3's degraded
// definition): the compiled rule DOES exist live, matching desired.
func TestEvaluateHealth_DegradedWithoutAnyDrift(t *testing.T) {
	rosterPath := writeDriftTestRoster(t)
	now := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)

	// Resolve the real compiled name via the same production compiler
	// (CompileGrants/CompiledLoginRuleName includes a content hash) rather
	// than hand-guessing it, so this test can't silently drift out of
	// sync with the naming scheme.
	plan, err := BuildPlan(rosterPath, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hbacExists := map[string]bool{}
	for _, r := range plan.HBACRules {
		hbacExists[r.Name] = true
	}
	runner := &fakeDriftRunner{live: LiveState{HBACExists: hbacExists}}

	health, err := EvaluateHealth(context.Background(), HealthOptions{
		DriftProbeOptions: DriftProbeOptions{RosterFile: rosterPath, Inventory: "inv.yml", Now: now, Runner: runner},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if health.Status != HealthDegraded {
		t.Fatalf("expected degraded (reconcile-required grant, no drift), got: %+v", health)
	}
}

func TestEvaluateHealth_UnknownWhenProbeFails(t *testing.T) {
	rosterPath := writeHealthTestRoster(t, healthTestRosterNoGrants)
	now := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	runner := &fakeDriftRunner{runErr: errors.New("connection refused")}

	health, err := EvaluateHealth(context.Background(), HealthOptions{
		DriftProbeOptions: DriftProbeOptions{RosterFile: rosterPath, Inventory: "inv.yml", Now: now, Runner: runner},
	})
	if err != nil {
		t.Fatalf("expected a probe failure to be reported as unknown, not an error: %v", err)
	}
	if health.Status != HealthUnknown || health.FreeIPAReachable {
		t.Fatalf("expected unknown/unreachable, got: %+v", health)
	}
}

func TestEvaluateHealth_CountsActiveBreakglass(t *testing.T) {
	rosterPath := writeHealthTestRoster(t, `
schema_version: 3
freeipa:
  domain: ipa.pilot.internal
  admin: {principal: admin, password: x}
users:
  - name: alice
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
  - name: infra-emergency
    kind: breakglass
    subjects: {users: [alice], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    activation: {max_duration: 1h, require_reason: true, require_ticket: true}
`)
	now := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	stateDir := t.TempDir()
	runner := &fakeDriftRunner{live: LiveState{}}

	if _, err := Activate(context.Background(), ActivateOptions{
		RosterFile: rosterPath, Inventory: "inv.yml", Name: "infra-emergency",
		Reason: "test", Ticket: "T-1", Duration: time.Hour, StateDir: stateDir,
		Now: now, Runner: &fakeRunner{exitCode: 0},
	}); err != nil {
		t.Fatalf("activate: %v", err)
	}

	health, err := EvaluateHealth(context.Background(), HealthOptions{
		DriftProbeOptions: DriftProbeOptions{RosterFile: rosterPath, Inventory: "inv.yml", Now: now, Runner: runner},
		StateDir:          stateDir,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if health.ActiveBreakglassCount != 1 {
		t.Fatalf("expected one active breakglass activation, got: %+v", health)
	}
}
