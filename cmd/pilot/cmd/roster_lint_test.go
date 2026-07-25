package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const rosterLintFixtureValid = `
schema_version: 1
freeipa:
  domain: ipa.pilot.internal
users:
  - name: alice
    ssh_keys: {authoritative: true, values: []}
`

const rosterLintFixtureBroken = `
schema_version: 1
users:
  - name: Alice
`

func TestRosterLintCmd_CleanRosterPrintsOK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(rosterLintFixtureValid), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"roster", "lint", path})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, out.String())
	}
	if !strings.Contains(out.String(), "ok: no issues found") {
		t.Fatalf("output = %q, want ok: no issues found", out.String())
	}
}

func TestRosterLintCmd_BrokenRosterReportsViolationsAndFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(rosterLintFixtureBroken), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"roster", "lint", path})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Fatalf("expected an error for a broken roster, output: %s", out.String())
	}
	if !strings.Contains(out.String(), "user name") {
		t.Fatalf("output = %q, want a user name violation reported", out.String())
	}
}

func TestRosterLintCmd_EncryptedRosterReportsAClearError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte("$ANSIBLE_VAULT;1.1;AES256\n633864363...\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"roster", "lint", path})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "ansible-vault encrypted") {
		t.Fatalf("Execute() error = %v, want an ansible-vault-encrypted message", err)
	}
}
