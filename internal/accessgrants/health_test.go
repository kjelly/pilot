package accessgrants

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	if !strings.Contains(health.ProbeError, "connection refused") {
		t.Fatalf("the probe failure must be visible, got ProbeError %q", health.ProbeError)
	}
}

// TestEvaluateHealth_UnknownExplainsAProbeFailureOnOneCappedLine locks the
// diagnostic that tells a missing admin password (issue #179) apart from an
// unreachable FreeIPA. The fake runner replays a REAL ansible capture of both
// streams: the gate message is on stdout and stderr only has the hyphenated-
// group warning, yet the gate message is what the health line shows, in one
// line, and the vars file is forwarded to the probe.
func TestEvaluateHealth_UnknownExplainsAProbeFailureOnOneCappedLine(t *testing.T) {
	rosterPath := writeHealthTestRoster(t, healthTestRosterNoGrants)
	varsFile := filepath.Join(t.TempDir(), "main.yaml")
	stdout, stderr := readCapture(t, "gate_missing")
	runner := &fakeDriftRunner{exitCode: 2, stdout: stdout, stderr: stderr}

	health, err := EvaluateHealth(context.Background(), HealthOptions{
		DriftProbeOptions: DriftProbeOptions{
			RosterFile: rosterPath, Inventory: "inv.yml", Runner: runner, VarsFile: varsFile,
			Now: time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if health.Status != HealthUnknown {
		t.Fatalf("status = %q, want unknown", health.Status)
	}
	if strings.ContainsAny(health.ProbeError, "\n\r") || !strings.Contains(health.ProbeError, "No usable FreeIPA admin password") ||
		!strings.Contains(health.ProbeError, "Both are missing or too short") {
		t.Fatalf("ProbeError = %q, want one line carrying the whole gate message", health.ProbeError)
	}
	if strings.Contains(health.ProbeError, "Invalid characters") {
		t.Fatalf("the group-name warning must not be the reason: %q", health.ProbeError)
	}
	if got := len([]rune(health.ProbeError)); got > maxProbeErrorLen+3 {
		t.Fatalf("ProbeError is %d runes, want it capped near %d", got, maxProbeErrorLen)
	}
	if driftArgIndex(runner.lastArgs, "@"+varsFile) < 0 {
		t.Fatalf("EvaluateHealth did not forward the vars file: %v", runner.lastArgs)
	}
}

// TestEvaluateHealth_NeverDumpsAnUnrecognisedTranscript: output that holds no
// failure message is replaced by a fixed line, not embedded; and any other
// error text that reaches the health line has password-shaped pairs blanked
// and is capped.
func TestEvaluateHealth_NeverDumpsAnUnrecognisedTranscript(t *testing.T) {
	rosterPath := writeHealthTestRoster(t, healthTestRosterNoGrants)
	opts := func(r *fakeDriftRunner) HealthOptions {
		return HealthOptions{DriftProbeOptions: DriftProbeOptions{
			RosterFile: rosterPath, Inventory: "inv.yml", Runner: r,
			Now: time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC),
		}}
	}
	transcript := "PLAY [x]\nipa_admin_password: Hunter2Hunter2\n" + strings.Repeat("noise\n", 400)
	for name, runner := range map[string]*fakeDriftRunner{
		"stdout only": {exitCode: 2, stdout: transcript},
		"stderr only": {exitCode: 2, stderr: transcript},
	} {
		health, err := EvaluateHealth(context.Background(), opts(runner))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(health.ProbeError, "Hunter2") || strings.Contains(health.ProbeError, "noise") || !strings.Contains(health.ProbeError, "no recognisable failure message") {
			t.Errorf("%s: ProbeError = %q, want the fixed no-message line only", name, health.ProbeError)
		}
	}

	// summarizeProbeError is the second line of defence for errors that are
	// not an ansible failure.
	long := summarizeProbeError(errors.New("boom ipa_admin_password: Hunter2Hunter2 " + strings.Repeat("x", 2*maxProbeErrorLen)))
	if strings.Contains(long, "Hunter2") || len([]rune(long)) > maxProbeErrorLen+3 {
		t.Errorf("summarizeProbeError = %d runes %q", len([]rune(long)), long[:60])
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
