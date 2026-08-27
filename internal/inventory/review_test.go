package inventory

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateRoster_ReviewValidPassesClean(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: vendor-project-x
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2099-08-31T18:00:00Z"}
    justification: {reason: "Project X maintenance"}
    review: {interval: 30d, last_reviewed_at: "2026-08-01T10:00:00+08:00", reviewed_by: alice}
`)
	if v := ValidateRosterV3(root); len(v) != 0 {
		t.Fatalf("expected clean pass, got: %v", v)
	}
}

func TestValidateRoster_ReviewMissingIntervalRejected(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: vendor-project-x
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2099-08-31T18:00:00Z"}
    justification: {reason: "x"}
    review: {reviewed_by: alice}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "grant review interval") {
		t.Fatalf("expected missing review.interval to be rejected, got: %v", v)
	}
}

func TestValidateRoster_ReviewInvalidIntervalRejected(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: vendor-project-x
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2099-08-31T18:00:00Z"}
    justification: {reason: "x"}
    review: {interval: "30 days"}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "grant review interval") {
		t.Fatalf("expected malformed review.interval to be rejected, got: %v", v)
	}
}

func TestValidateRoster_ReviewUnknownKeyRejected(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: vendor-project-x
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2099-08-31T18:00:00Z"}
    justification: {reason: "x"}
    review: {interval: 30d, on_overdue: suspend}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "grant review keys") {
		t.Fatalf("expected on_overdue to be rejected as an unknown field (§14.2 fail-closed), got: %v", v)
	}
}

func TestValidateRoster_ReviewUnknownReviewedByRejected(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: vendor-project-x
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2099-08-31T18:00:00Z"}
    justification: {reason: "x"}
    review: {interval: 30d, reviewed_by: ghost-reviewer}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "grant review reviewed_by reference") {
		t.Fatalf("expected unknown reviewed_by to be rejected, got: %v", v)
	}
}

func TestValidateRoster_ReviewOnBreakglassRejected(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: infra-emergency
    kind: breakglass
    subjects: {users: [alice], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    activation: {max_duration: 1h, require_reason: true, require_ticket: true}
    review: {interval: 30d}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "grant keys") {
		t.Fatalf("expected review on a breakglass grant to be rejected as an unknown field, got: %v", v)
	}
}

const reviewTestRoster = `
schema_version: 3
freeipa:
  domain: ipa.pilot.internal
  admin: {principal: admin, password: x}
users:
  - name: vendor01
    ssh_keys: {authoritative: true, values: []}
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
  - name: vendor-project-x
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2099-08-31T18:00:00Z"}
    justification: {reason: "Project X maintenance"}
    review: {interval: 30d, last_reviewed_at: "2026-08-01T10:00:00Z", reviewed_by: alice}
  - name: no-review-tracked
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2099-08-31T18:00:00Z"}
    justification: {reason: "not review-tracked"}
`

func writeReviewTestRoster(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(reviewTestRoster), 0o600); err != nil {
		t.Fatalf("write roster: %v", err)
	}
	return path
}

func TestEvaluateReviewStatuses_UntrackedGrantIsInvisible(t *testing.T) {
	root := grantsRoster(t, "")
	statuses, err := EvaluateReviewStatuses(root, mustParseTime(t, "2026-09-01T00:00:00Z"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(statuses) != 0 {
		t.Fatalf("expected no review statuses on a roster with no review: blocks, got: %+v", statuses)
	}
}

func TestEvaluateReviewStatuses_NeverReviewedIsOverdue(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: vendor-project-x
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2099-08-31T18:00:00Z"}
    justification: {reason: "x"}
    review: {interval: 30d}
`)
	statuses, err := EvaluateReviewStatuses(root, mustParseTime(t, "2026-09-01T00:00:00Z"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(statuses) != 1 || statuses[0].State != ReviewOverdue || statuses[0].LastReviewedAt != nil {
		t.Fatalf("expected a never-reviewed grant to report overdue, got: %+v", statuses)
	}
}

func TestEvaluateReviewStatuses_CurrentDueOverdueClassification(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: vendor-project-x
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2099-08-31T18:00:00Z"}
    justification: {reason: "x"}
    review: {interval: 30d, last_reviewed_at: "2026-08-01T00:00:00Z"}
`)
	// next_due_at = 2026-08-31T00:00:00Z; due-soon starts 6 days before it
	// (30d/5), i.e. 2026-08-25T00:00:00Z.
	current, err := EvaluateReviewStatuses(root, mustParseTime(t, "2026-08-10T00:00:00Z"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if current[0].State != ReviewCurrent {
		t.Fatalf("expected current well before the deadline, got: %+v", current[0])
	}

	due, err := EvaluateReviewStatuses(root, mustParseTime(t, "2026-08-26T00:00:00Z"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if due[0].State != ReviewDue {
		t.Fatalf("expected due inside the last 1/5 of the interval, got: %+v", due[0])
	}

	overdue, err := EvaluateReviewStatuses(root, mustParseTime(t, "2026-09-01T00:00:00Z"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if overdue[0].State != ReviewOverdue {
		t.Fatalf("expected overdue after the deadline, got: %+v", overdue[0])
	}
}

func TestMarkGrantReviewedFile_UpdatesLastReviewedAtAndReviewedBy(t *testing.T) {
	path := writeReviewTestRoster(t)
	now := mustParseTime(t, "2026-09-01T12:00:00Z")

	if err := MarkGrantReviewedFile(path, "", "vendor-project-x", "alice", now); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	root, err := ReadRosterAsMapFile(path)
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := EvaluateReviewStatuses(root, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(statuses) != 1 || statuses[0].ReviewedBy != "alice" || statuses[0].LastReviewedAt == nil || !statuses[0].LastReviewedAt.Equal(now) {
		t.Fatalf("expected the mark to persist, got: %+v", statuses)
	}
}

func TestMarkGrantReviewedFile_RejectsGrantWithNoReviewPolicy(t *testing.T) {
	path := writeReviewTestRoster(t)
	if err := MarkGrantReviewedFile(path, "", "no-review-tracked", "alice", time.Now()); err == nil {
		t.Fatal("expected an error marking a grant with no review: block declared")
	}
}

func TestMarkGrantReviewedFile_RejectsUnknownGrant(t *testing.T) {
	path := writeReviewTestRoster(t)
	if err := MarkGrantReviewedFile(path, "", "does-not-exist", "alice", time.Now()); err == nil {
		t.Fatal("expected an error marking a nonexistent grant")
	}
}

func TestMarkGrantReviewedFile_RequiresReviewer(t *testing.T) {
	path := writeReviewTestRoster(t)
	if err := MarkGrantReviewedFile(path, "", "vendor-project-x", "", time.Now()); err == nil {
		t.Fatal("expected an error when reviewedBy is empty")
	}
}

func TestMarkGrantReviewedFile_EncryptedRosterSafeMutation(t *testing.T) {
	requireAnsibleVault(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(reviewTestRoster), 0o600); err != nil {
		t.Fatal(err)
	}
	vaultPasswordFile := writeVaultPasswordFile(t, filepath.Join(dir, "vault-pass"), "s3cret-pw")
	encryptFileForTest(t, path, vaultPasswordFile)
	now := mustParseTime(t, "2026-09-01T12:00:00Z")

	if err := MarkGrantReviewedFile(path, vaultPasswordFile, "vendor-project-x", "alice", now); err != nil {
		t.Fatalf("MarkGrantReviewedFile() error = %v", err)
	}

	plaintext := viewFileForTest(t, path, vaultPasswordFile)
	root, err := ReadRosterAsMapFile(writePlainCopy(t, dir, plaintext))
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := EvaluateReviewStatuses(root, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(statuses) != 1 || statuses[0].ReviewedBy != "alice" {
		t.Fatalf("expected the re-encrypted roster to carry the mark, got: %+v", statuses)
	}
}
