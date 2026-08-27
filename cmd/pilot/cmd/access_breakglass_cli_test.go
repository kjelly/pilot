package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const accessBreakglassCLIFixtureRoster = `
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

func TestAccessBreakglassActivateCmd_RequiresDuration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(accessBreakglassCLIFixtureRoster), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	rootCmd.SetArgs([]string{"--data-dir", t.TempDir(), "access", "breakglass", "activate", path, "infra-emergency", "--reason", "x", "--ticket", "y"})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--duration") {
		t.Fatalf("expected an error requiring --duration, got err=%v output=%s", err, out.String())
	}
}

func TestAccessBreakglassStatusCmd_NoActivationsRecorded(t *testing.T) {
	var out bytes.Buffer
	rootCmd.SetArgs([]string{"--data-dir", t.TempDir(), "access", "breakglass", "status", "--format", "table"})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, out.String())
	}
	if !strings.Contains(out.String(), "no activations recorded") {
		t.Fatalf("expected 'no activations recorded', got: %s", out.String())
	}
}
