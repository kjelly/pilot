package accessgrants

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/freeipa"
)

const hygieneTestRoster = `
schema_version: 3
freeipa:
  domain: ipa.pilot.internal
  admin: {principal: admin, password: x}
users:
  - name: alice
    ssh_keys: {authoritative: true, values: ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE+W2fUehVce+VbyNG5lfFmw3Mbfo3VDY4jJgIOynSoH alice@example.com"]}
    authentication: {allowed: [otp]}
  - name: bob
    ssh_keys: {authoritative: true, values: [""]}
  - name: carol
    ssh_keys: {authoritative: true, values: []}
groups:
  - name: role-privileged
    category: role
    membership: {users: [alice, bob], groups: []}
hosts: []
hostgroups: []
hbac: {rules: []}
sudo: {rules: []}
security:
  privileged_identity:
    match_groups: [role-privileged]
    require: {auth_types: [otp, pkinit], no_password_only: true}
credential_policies:
  - name: privileged-ssh
    match: {users: [], groups: [role-privileged]}
    review: {interval: 180d, last_reviewed_at: "2020-01-01T00:00:00Z"}
`

func writeHygieneTestRoster(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(hygieneTestRoster), 0o600); err != nil {
		t.Fatalf("write roster: %v", err)
	}
	return path
}

func TestEvaluateIdentityHygiene_PerUserRows(t *testing.T) {
	rosterPath := writeHygieneTestRoster(t)
	now := time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC)

	report, err := EvaluateIdentityHygiene(context.Background(), HygieneOptions{RosterFile: rosterPath, Now: now})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Users) != 3 {
		t.Fatalf("expected 3 users, got: %+v", report.Users)
	}

	byName := map[string]UserHygiene{}
	for _, u := range report.Users {
		byName[u.Name] = u
	}

	alice := byName["alice"]
	if !alice.Privileged || alice.AuthCompliance != "pass" {
		t.Errorf("alice = %+v, want privileged+pass (allows otp, one of the required types)", alice)
	}
	if alice.SSHKeyCompliance != "pass" {
		t.Errorf("alice SSHKeyCompliance = %q, want pass (clean key, covered by privileged-ssh)", alice.SSHKeyCompliance)
	}
	if alice.CredentialReview != "overdue" {
		t.Errorf("alice CredentialReview = %q, want overdue (last_reviewed_at 2020, interval 180d)", alice.CredentialReview)
	}

	bob := byName["bob"]
	if !bob.Privileged || bob.AuthCompliance != "fail" {
		t.Errorf("bob = %+v, want privileged+fail (no authentication: block declared)", bob)
	}
	if bob.SSHKeyCompliance != "fail" {
		t.Errorf("bob SSHKeyCompliance = %q, want fail (blank key)", bob.SSHKeyCompliance)
	}

	carol := byName["carol"]
	if carol.Privileged {
		t.Errorf("carol = %+v, want not privileged (not in role-privileged)", carol)
	}
	if carol.AuthCompliance != "n/a" {
		t.Errorf("carol AuthCompliance = %q, want n/a (not privileged)", carol.AuthCompliance)
	}
	if carol.SSHKeyCompliance != "n/a" {
		t.Errorf("carol SSHKeyCompliance = %q, want n/a (no credential_policy covers her)", carol.SSHKeyCompliance)
	}
}

func TestEvaluateIdentityHygiene_ReportsAggregatedFindings(t *testing.T) {
	rosterPath := writeHygieneTestRoster(t)
	report, err := EvaluateIdentityHygiene(context.Background(), HygieneOptions{RosterFile: rosterPath, Now: time.Now()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.PrivilegedIdentityViolations) == 0 {
		t.Error("expected at least one privileged-identity violation (bob)")
	}
	if len(report.SSHFindings) == 0 {
		t.Error("expected at least one SSH finding (bob's blank key)")
	}
	if len(report.CredentialReviews) != 1 {
		t.Errorf("expected exactly one credential review status, got: %+v", report.CredentialReviews)
	}
	if report.StaleAccountStatus != "unsupported" {
		t.Errorf("StaleAccountStatus = %q, want unsupported (spec.md §12: no reliable data source)", report.StaleAccountStatus)
	}
}

func TestEvaluateIdentityHygiene_NeverMutatesRoster(t *testing.T) {
	rosterPath := writeHygieneTestRoster(t)
	before, err := os.ReadFile(rosterPath)
	if err != nil {
		t.Fatalf("read roster: %v", err)
	}
	if _, err := EvaluateIdentityHygiene(context.Background(), HygieneOptions{RosterFile: rosterPath, Now: time.Now()}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	after, err := os.ReadFile(rosterPath)
	if err != nil {
		t.Fatalf("read roster: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("expected EvaluateIdentityHygiene to never mutate the roster file")
	}
}

func TestEvaluateIdentityHygiene_CapabilityProbeSkippedWithoutInventory(t *testing.T) {
	rosterPath := writeHygieneTestRoster(t)
	report, err := EvaluateIdentityHygiene(context.Background(), HygieneOptions{RosterFile: rosterPath, Now: time.Now()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.CapabilityError == "" {
		t.Error("expected CapabilityError to explain the probe was skipped when Inventory is unset")
	}
	// Every control must report CapabilityUnknown, never a blank
	// zero-value string, whether the probe failed or was never
	// attempted at all.
	for name, state := range map[string]freeipa.CapabilityState{
		"GroupPasswordPolicy":     report.Capabilities.GroupPasswordPolicy,
		"PasswordLockoutPolicy":   report.Capabilities.PasswordLockoutPolicy,
		"UserAuthTypes":           report.Capabilities.UserAuthTypes,
		"AuthenticationIndicator": report.Capabilities.AuthenticationIndicator,
		"PrincipalExpiration":     report.Capabilities.PrincipalExpiration,
		"SudoNotBeforeAfter":      report.Capabilities.SudoNotBeforeAfter,
	} {
		if state != freeipa.CapabilityUnknown {
			t.Errorf("Capabilities.%s = %q, want unknown", name, state)
		}
	}
}

func TestEvaluateIdentityHygiene_CapabilityProbeRunsWhenInventorySet(t *testing.T) {
	rosterPath := writeHygieneTestRoster(t)
	runner := &capabilityAwareFakeRunner{capabilityResult: `{"schema_version":1,"capabilities":{"user_auth_types":"supported"}}`}
	report, err := EvaluateIdentityHygiene(context.Background(), HygieneOptions{
		RosterFile: rosterPath, Inventory: "inv.yml", Now: time.Now(), Runner: runner,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.CapabilityError != "" {
		t.Errorf("expected no CapabilityError when the probe succeeds, got: %q", report.CapabilityError)
	}
	if report.Capabilities.UserAuthTypes != freeipa.CapabilitySupported {
		t.Errorf("Capabilities.UserAuthTypes = %q, want supported", report.Capabilities.UserAuthTypes)
	}
}

func TestEvaluateIdentityHygiene_RecordsAuditEventWhenStateDirSet(t *testing.T) {
	rosterPath := writeHygieneTestRoster(t)
	stateDir := t.TempDir()
	if _, err := EvaluateIdentityHygiene(context.Background(), HygieneOptions{RosterFile: rosterPath, Now: time.Now(), StateDir: stateDir}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(stateDir, "access", "audit.jsonl"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected a non-empty audit log entry")
	}
}

func TestEvaluateIdentityHygiene_RequiresRosterFile(t *testing.T) {
	if _, err := EvaluateIdentityHygiene(context.Background(), HygieneOptions{}); err == nil {
		t.Fatal("expected an error when RosterFile is empty")
	}
}
