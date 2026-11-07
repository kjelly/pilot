package accessgrants

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const breakglassTestRoster = `
schema_version: 3
freeipa:
  domain: ipa.pilot.internal
  admin: {principal: admin, password: x}
users:
  - name: emergency-admin
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
    subjects: {users: [emergency-admin], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    activation: {max_duration: 1h, require_reason: true, require_ticket: true}
`

func writeBreakglassTestRoster(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(breakglassTestRoster), 0o600); err != nil {
		t.Fatalf("write roster: %v", err)
	}
	return path
}

func TestActivate_AppliesRuleAndRecordsState(t *testing.T) {
	rosterPath := writeBreakglassTestRoster(t)
	stateDir := t.TempDir()
	runner := &fakeRunner{exitCode: 0}
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

	activation, err := Activate(context.Background(), ActivateOptions{
		Lock:        testLock(t),
		RosterFile:  rosterPath,
		Inventory:   "inv.yml",
		StateDir:    stateDir,
		Name:        "infra-emergency",
		Duration:    45 * time.Minute,
		Reason:      "database outage",
		Ticket:      "INC-9921",
		ActivatedBy: "alice",
		Now:         now,
		Runner:      runner,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !activation.ExpiresAt.Equal(now.Add(45 * time.Minute)) {
		t.Fatalf("unexpected ExpiresAt: %v", activation.ExpiresAt)
	}
	if runner.lastArgs == nil {
		t.Fatal("expected ansible-playbook to be invoked")
	}

	statuses, err := Status(stateDir, "infra-emergency")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(statuses) != 1 || statuses[0].Reason != "database outage" || statuses[0].Ticket != "INC-9921" {
		t.Fatalf("unexpected statuses: %+v", statuses)
	}
	if !statuses[0].IsActive(now.Add(30 * time.Minute)) {
		t.Fatal("expected the activation to still be active 30m in")
	}
	if statuses[0].IsActive(now.Add(46 * time.Minute)) {
		t.Fatal("expected the activation to have expired after 46m")
	}
}

func TestActivate_RejectsDurationExceedingMaxDuration(t *testing.T) {
	rosterPath := writeBreakglassTestRoster(t)
	_, err := Activate(context.Background(), ActivateOptions{
		Lock:       testLock(t),
		RosterFile: rosterPath,
		Inventory:  "inv.yml",
		StateDir:   t.TempDir(),
		Name:       "infra-emergency",
		Duration:   2 * time.Hour, // exceeds the 1h max_duration
		Reason:     "x",
		Ticket:     "y",
		Runner:     &fakeRunner{exitCode: 0},
	})
	if err == nil {
		t.Fatal("expected an error when --duration exceeds activation.max_duration")
	}
}

func TestActivate_RequiresReasonAndTicketByDefault(t *testing.T) {
	rosterPath := writeBreakglassTestRoster(t)
	if _, err := Activate(context.Background(), ActivateOptions{
		Lock:       testLock(t),
		RosterFile: rosterPath, Inventory: "inv.yml", StateDir: t.TempDir(),
		Name: "infra-emergency", Duration: 30 * time.Minute, Ticket: "y",
		Runner: &fakeRunner{exitCode: 0},
	}); err == nil {
		t.Fatal("expected an error when --reason is omitted")
	}
	if _, err := Activate(context.Background(), ActivateOptions{
		Lock:       testLock(t),
		RosterFile: rosterPath, Inventory: "inv.yml", StateDir: t.TempDir(),
		Name: "infra-emergency", Duration: 30 * time.Minute, Reason: "x",
		Runner: &fakeRunner{exitCode: 0},
	}); err == nil {
		t.Fatal("expected an error when --ticket is omitted")
	}
}

func TestActivate_RejectsWhenSubjectAccountIsExpired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	content := breakglassTestRoster + `
account_policies:
  - name: emergency-admin-expired
    user: emergency-admin
    type: employee
    validity: {not_after: "2020-01-01T00:00:00Z"}
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write roster: %v", err)
	}

	_, err := Activate(context.Background(), ActivateOptions{
		Lock:       testLock(t),
		RosterFile: path, Inventory: "inv.yml", StateDir: t.TempDir(),
		Name: "infra-emergency", Duration: 30 * time.Minute, Reason: "x", Ticket: "y",
		Now: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC), Runner: &fakeRunner{exitCode: 0},
	})
	if err == nil {
		t.Fatal("expected activation to be refused when the subject's account is expired")
	}
}

func TestActivate_RejectsNonBreakglassGrant(t *testing.T) {
	rosterPath := writeReconcileTestRoster(t) // has a temporary_grant named vendor-project-x
	_, err := Activate(context.Background(), ActivateOptions{
		Lock:       testLock(t),
		RosterFile: rosterPath, Inventory: "inv.yml", StateDir: t.TempDir(),
		Name: "vendor-project-x", Duration: 30 * time.Minute, Reason: "x", Ticket: "y",
		Runner: &fakeRunner{exitCode: 0},
	})
	if err == nil {
		t.Fatal("expected an error when activating a non-breakglass grant")
	}
}

func TestDeactivate_MarksActiveActivationInactiveAndAppliesPrune(t *testing.T) {
	rosterPath := writeBreakglassTestRoster(t)
	stateDir := t.TempDir()
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

	if _, err := Activate(context.Background(), ActivateOptions{
		Lock:       testLock(t),
		RosterFile: rosterPath, Inventory: "inv.yml", StateDir: stateDir,
		Name: "infra-emergency", Duration: 45 * time.Minute, Reason: "x", Ticket: "y",
		Now: now, Runner: &fakeRunner{exitCode: 0},
	}); err != nil {
		t.Fatalf("activate: %v", err)
	}

	deactivateRunner := &fakeRunner{exitCode: 0}
	if err := Deactivate(context.Background(), DeactivateOptions{
		Lock:       testLock(t),
		RosterFile: rosterPath, Inventory: "inv.yml", StateDir: stateDir,
		Name: "infra-emergency", Now: now.Add(5 * time.Minute), Runner: deactivateRunner,
	}); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if deactivateRunner.lastArgs == nil {
		t.Fatal("expected deactivate to invoke ansible-playbook to prune the compiled rule")
	}

	statuses, err := Status(stateDir, "infra-emergency")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(statuses) != 1 || !statuses[0].Deactivated {
		t.Fatalf("expected the activation to be marked deactivated, got: %+v", statuses)
	}
	if statuses[0].IsActive(now.Add(6 * time.Minute)) {
		t.Fatal("expected a deactivated activation to report inactive even before its natural expiry")
	}
}

func TestDeactivate_NoOpWhenNothingActive(t *testing.T) {
	rosterPath := writeBreakglassTestRoster(t)
	stateDir := t.TempDir()
	if err := Deactivate(context.Background(), DeactivateOptions{
		Lock:       testLock(t),
		RosterFile: rosterPath, Inventory: "inv.yml", StateDir: stateDir,
		Name: "infra-emergency", Runner: &fakeRunner{exitCode: 0},
	}); err != nil {
		t.Fatalf("expected deactivating a never-activated grant to be a no-op, got: %v", err)
	}
}

func TestStatus_MostRecentFirst(t *testing.T) {
	rosterPath := writeBreakglassTestRoster(t)
	stateDir := t.TempDir()
	base := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

	for i, d := range []time.Duration{0, time.Hour, 2 * time.Hour} {
		if _, err := Activate(context.Background(), ActivateOptions{
			Lock:       testLock(t),
			RosterFile: rosterPath, Inventory: "inv.yml", StateDir: stateDir,
			Name: "infra-emergency", Duration: 10 * time.Minute, Reason: "x", Ticket: "y",
			Now: base.Add(d), Runner: &fakeRunner{exitCode: 0},
		}); err != nil {
			t.Fatalf("activate #%d: %v", i, err)
		}
	}

	statuses, err := Status(stateDir, "infra-emergency")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(statuses) != 3 || !statuses[0].ActivatedAt.Equal(base.Add(2*time.Hour)) {
		t.Fatalf("expected most-recent-first ordering, got: %+v", statuses)
	}
}

// An activation or a deactivation can fail after the playbook has already
// changed FreeIPA: the rule is applied (or pruned) and the state file cannot be
// written. The error must say which half is missing, so that the caller never
// reports "not activated" for access that is in effect (the step wording of
// pilot edit relies on it). A directory where the state file belongs is a real
// failure of the write that works for root as well.
func TestActivateAndDeactivate_FailingToRecordSaysFreeIPAWasChanged(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		run  func(t *testing.T, roster, stateDir string, runner *fakeRunner) error
		want string
	}{
		{"activate", func(t *testing.T, roster, stateDir string, runner *fakeRunner) error {
			_, err := Activate(context.Background(), ActivateOptions{
				Lock: testLock(t), RosterFile: roster, Inventory: "inv.yml", StateDir: stateDir,
				Name: "infra-emergency", Duration: 45 * time.Minute, Reason: "x", Ticket: "y", Now: now, Runner: runner,
			})
			return err
		}, "activation applied to FreeIPA but recording state failed"},
		{"deactivate", func(t *testing.T, roster, stateDir string, runner *fakeRunner) error {
			return Deactivate(context.Background(), DeactivateOptions{
				Lock: testLock(t), RosterFile: roster, Inventory: "inv.yml", StateDir: stateDir,
				Name: "infra-emergency", Now: now, Runner: runner,
			})
		}, "deactivation applied to FreeIPA but recording state failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stateDir := t.TempDir()
			if err := os.Mkdir(filepath.Join(stateDir, activationStateFilename), 0o700); err != nil {
				t.Fatal(err)
			}
			runner := &fakeRunner{exitCode: 0}
			err := tc.run(t, writeBreakglassTestRoster(t), stateDir, runner)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if runner.lastArgs == nil {
				t.Fatal("the playbook did not run: the case does not exercise a failure after the apply")
			}
		})
	}
}
