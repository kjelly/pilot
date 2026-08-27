package inventory

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const credentialPolicyReviewMarkTestRoster = `
schema_version: 3
freeipa:
  domain: ipa.pilot.internal
  admin: {principal: admin, password: x}
users:
  - name: alice
    ssh_keys: {authoritative: true, values: []}
groups:
  - name: role-privileged
    category: role
    membership: {users: [alice], groups: []}
hosts: []
hostgroups: []
hbac: {rules: []}
sudo: {rules: []}
credential_policies:
  - name: privileged-ssh
    match: {users: [], groups: [role-privileged]}
    review: {interval: 180d}
  - name: no-review-tracked
    match: {users: [], groups: [role-privileged]}
  - name: retired-policy
    state: absent
    match: {users: [], groups: [role-privileged]}
    review: {interval: 180d}
`

func writeCredentialPolicyReviewMarkTestRoster(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(credentialPolicyReviewMarkTestRoster), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMarkCredentialPolicyReviewedFile_UpdatesLastReviewedAtAndReviewedBy(t *testing.T) {
	path := writeCredentialPolicyReviewMarkTestRoster(t)
	now := mustParseTime(t, "2026-09-01T12:00:00Z")

	if err := MarkCredentialPolicyReviewedFile(path, "", "privileged-ssh", "alice", now); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	root, err := ReadRosterAsMapFile(path)
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := EvaluateCredentialReviewStatuses(root, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(statuses) != 1 || statuses[0].ReviewedBy != "alice" || statuses[0].LastReviewedAt == nil || !statuses[0].LastReviewedAt.Equal(now) {
		t.Fatalf("expected the mark to persist, got: %+v", statuses)
	}
	if statuses[0].State != ReviewCurrent {
		t.Fatalf("expected State=current right after marking, got: %v", statuses[0].State)
	}
}

func TestMarkCredentialPolicyReviewedFile_RejectsPolicyWithNoReviewBlock(t *testing.T) {
	path := writeCredentialPolicyReviewMarkTestRoster(t)
	if err := MarkCredentialPolicyReviewedFile(path, "", "no-review-tracked", "alice", time.Now()); err == nil {
		t.Fatal("expected an error marking a policy with no review: block declared")
	}
}

func TestMarkCredentialPolicyReviewedFile_RejectsUnknownPolicy(t *testing.T) {
	path := writeCredentialPolicyReviewMarkTestRoster(t)
	if err := MarkCredentialPolicyReviewedFile(path, "", "does-not-exist", "alice", time.Now()); err == nil {
		t.Fatal("expected an error marking a nonexistent credential_policy")
	}
}

func TestMarkCredentialPolicyReviewedFile_RejectsAbsentPolicy(t *testing.T) {
	path := writeCredentialPolicyReviewMarkTestRoster(t)
	if err := MarkCredentialPolicyReviewedFile(path, "", "retired-policy", "alice", time.Now()); err == nil {
		t.Fatal("expected an error marking a state: absent policy as reviewed")
	}
}

func TestMarkCredentialPolicyReviewedFile_RequiresReviewer(t *testing.T) {
	path := writeCredentialPolicyReviewMarkTestRoster(t)
	if err := MarkCredentialPolicyReviewedFile(path, "", "privileged-ssh", "", time.Now()); err == nil {
		t.Fatal("expected an error when reviewedBy is empty")
	}
}

func TestMarkCredentialPolicyReviewedFile_EncryptedRosterSafeMutation(t *testing.T) {
	requireAnsibleVault(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(credentialPolicyReviewMarkTestRoster), 0o600); err != nil {
		t.Fatal(err)
	}
	vaultPasswordFile := writeVaultPasswordFile(t, filepath.Join(dir, "vault-pass"), "s3cret-pw")
	encryptFileForTest(t, path, vaultPasswordFile)
	now := mustParseTime(t, "2026-09-01T12:00:00Z")

	if err := MarkCredentialPolicyReviewedFile(path, vaultPasswordFile, "privileged-ssh", "alice", now); err != nil {
		t.Fatalf("MarkCredentialPolicyReviewedFile() error = %v", err)
	}

	plaintext := viewFileForTest(t, path, vaultPasswordFile)
	root, err := ReadRosterAsMapFile(writePlainCopy(t, dir, plaintext))
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := EvaluateCredentialReviewStatuses(root, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(statuses) != 1 || statuses[0].ReviewedBy != "alice" {
		t.Fatalf("expected the re-encrypted roster to carry the mark, got: %+v", statuses)
	}
}
