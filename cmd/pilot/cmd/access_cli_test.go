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
  - name: vendor-project-x-sudo
    kind: sudo_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    validity: {not_before: "2099-08-21T15:00:00Z", not_after: "2099-08-31T18:00:00Z"}
    justification: {reason: "Project X sudo maintenance"}
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
	if !strings.Contains(got, "vendor-project-x-sudo") || !strings.Contains(got, "native_enforced=[20990821150000Z,20990831180000Z)") {
		t.Fatalf("expected table output to report the sudo grant's native-enforced validity window, got: %s", got)
	}
	if !strings.Contains(got, "vendor-project-x\tkind=temporary_grant") || !strings.Contains(got, "timing_enforcement=reconcile_required") {
		t.Fatalf("expected table output to classify the temporary_grant as timing_enforcement=reconcile_required (spec.md v3.1 §10.3), got: %s", got)
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
	if !strings.Contains(out.String(), `"NativeSudoNotBefore": "20990821150000Z"`) || !strings.Contains(out.String(), `"NativeSudoNotAfter": "20990831180000Z"`) {
		t.Fatalf("expected JSON output to include the sudo grant's compiled native validity window, got: %s", out.String())
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
