package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const accessReviewCLIFixtureRoster = `
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
    review: {interval: 30d}
`

func writeAccessReviewCLIFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(accessReviewCLIFixtureRoster), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestAccessReviewListCmd_ReportsOverdueForNeverReviewedGrant(t *testing.T) {
	path := writeAccessReviewCLIFixture(t)

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"access", "review", "list", path})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, out.String())
	}
	got := out.String()
	if !strings.Contains(got, "vendor-project-x") || !strings.Contains(got, "state=overdue") {
		t.Fatalf("expected a never-reviewed grant to report overdue, got: %s", got)
	}
}

func TestAccessReviewMarkCmd_RequiresReviewer(t *testing.T) {
	path := writeAccessReviewCLIFixture(t)

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"access", "review", "mark", path, "vendor-project-x"})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--reviewer") {
		t.Fatalf("expected an error requiring --reviewer, got err=%v output=%s", err, out.String())
	}
}

func TestAccessReviewMarkCmd_UpdatesRosterAndRecordsAudit(t *testing.T) {
	path := writeAccessReviewCLIFixture(t)
	dataDir := t.TempDir()

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"--data-dir", dataDir, "access", "review", "mark", path, "vendor-project-x", "--reviewer", "alice", "--reason", "still required"})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, out.String())
	}

	var listOut bytes.Buffer
	rootCmd.SetArgs([]string{"access", "review", "list", path})
	rootCmd.SetOut(&listOut)
	rootCmd.SetErr(&listOut)
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, listOut.String())
	}
	if !strings.Contains(listOut.String(), "reviewed_by=alice") || strings.Contains(listOut.String(), "state=overdue") {
		t.Fatalf("expected the mark to be reflected on next list, got: %s", listOut.String())
	}

	auditPath := filepath.Join(dataDir, "access", "audit.jsonl")
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("expected an audit log to be written: %v", err)
	}
	if !strings.Contains(string(data), `"action":"access_review_marked"`) || !strings.Contains(string(data), `"reason":"still required"`) {
		t.Fatalf("expected the audit event to record the mark action and reason, got: %s", data)
	}
}

func TestAccessReviewMarkCmd_RejectsGrantWithNoReviewPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	content := strings.Replace(accessReviewCLIFixtureRoster, "    review: {interval: 30d}\n", "", 1)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"access", "review", "mark", path, "vendor-project-x", "--reviewer", "alice"})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	if err := rootCmd.Execute(); err == nil {
		t.Fatalf("expected an error marking a grant with no review policy, output: %s", out.String())
	}
}
