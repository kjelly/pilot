package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const accessExplainCLIFixtureRoster = `
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
  rules:
    - name: static-rule
      subjects: {users: [vendor01], groups: []}
      targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
      services: [sshd]
sudo:
  rules: []
grants: []
`

func TestAccessExplainCmd_ReportsStaticHBACSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(accessExplainCLIFixtureRoster), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"--data-dir", t.TempDir(), "access", "explain", path,
		"--user", "vendor01", "--host", "db-special.ipa.pilot.internal", "--service", "sshd", "--format", "table"})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, out.String())
	}
	if !strings.Contains(out.String(), "static_hbac") || !strings.Contains(out.String(), "static-rule") {
		t.Fatalf("expected the static_hbac source to be reported, got: %s", out.String())
	}
}

func TestAccessExplainCmd_RequiresUserAndHost(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(accessExplainCLIFixtureRoster), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"--data-dir", t.TempDir(), "access", "explain", path, "--user", "", "--host", "db-special.ipa.pilot.internal"})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--user") {
		t.Fatalf("expected an error requiring --user, got err=%v output=%s", err, out.String())
	}
}
