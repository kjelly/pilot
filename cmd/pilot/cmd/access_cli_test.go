package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const accessCLIFixtureRoster = `
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
    validity: {not_after: "2099-08-31T18:00:00Z"}
    justification: {reason: "Project X maintenance"}
account_policies:
  - name: vendor01-contract
    user: vendor01
    type: contractor
    validity: {not_after: "2099-12-31T23:59:59Z"}
`

const accessCLIFixtureBrokenRoster = `
schema_version: 3
freeipa:
  domain: ipa.pilot.internal
users: []
groups: []
hosts: []
hostgroups: []
grants:
  - name: broken
    kind: login
    subjects: {users: [], groups: []}
    targets: {hosts: [], hostgroups: []}
`

func writeAccessCLIFixture(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestAccessStatusCmd_TableReportsLifecycle(t *testing.T) {
	path := writeAccessCLIFixture(t, accessCLIFixtureRoster)

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"access", "status", path, "--format", "table"})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, out.String())
	}
	got := out.String()
	if !strings.Contains(got, "vendor-project-x") || !strings.Contains(got, "lifecycle=active") {
		t.Fatalf("expected table output to report the grant as active, got: %s", got)
	}
	if !strings.Contains(got, "vendor01-contract") || !strings.Contains(got, "native_expiration=20991231235959Z") {
		t.Fatalf("expected table output to report the account_policy's native expiration, got: %s", got)
	}
}

func TestAccessStatusCmd_JSONFormat(t *testing.T) {
	path := writeAccessCLIFixture(t, accessCLIFixtureRoster)

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"access", "status", path, "--format", "json"})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, out.String())
	}
	if !strings.Contains(out.String(), `"Kind": "temporary_grant"`) {
		t.Fatalf("expected JSON output to include the grant's kind, got: %s", out.String())
	}
	if !strings.Contains(out.String(), `"NativeExpiration": "20991231235959Z"`) {
		t.Fatalf("expected JSON output to include the account_policy's compiled native expiration, got: %s", out.String())
	}
}

func TestAccessStatusCmd_InvalidRosterFailsClosed(t *testing.T) {
	path := writeAccessCLIFixture(t, accessCLIFixtureBrokenRoster)

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"access", "status", path, "--format", "table"})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	if err := rootCmd.Execute(); err == nil {
		t.Fatalf("expected an error for a structurally invalid roster, output: %s", out.String())
	}
}

func TestAccessReconcileCmd_RequiresOnceFlag(t *testing.T) {
	path := writeAccessCLIFixture(t, accessCLIFixtureRoster)

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"access", "reconcile", path, "--inventory", "inv.yml"})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--once") {
		t.Fatalf("expected an error requiring --once, got err=%v output=%s", err, out.String())
	}
}
