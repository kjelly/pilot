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

func TestRosterLintCmd_CleanV1RosterPrintsMigrateNotice(t *testing.T) {
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
	if !strings.Contains(out.String(), "ok: schema v1 is valid") {
		t.Fatalf("output = %q, want ok: schema v1 is valid", out.String())
	}
	if !strings.Contains(out.String(), "pilot roster migrate "+path) {
		t.Fatalf("output = %q, want a notice pointing at `pilot roster migrate %s`", out.String(), path)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != rosterLintFixtureValid {
		t.Fatalf("plain lint (no --upgrade) modified the roster (err=%v)", err)
	}
}

func TestRosterLintCmd_CleanV2RosterPrintsSchemaV2OK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	v2 := strings.Replace(rosterLintFixtureValid, "schema_version: 1", "schema_version: 2\nnetgroups: []", 1)
	if err := os.WriteFile(path, []byte(v2), 0o600); err != nil {
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
	if !strings.Contains(out.String(), "ok: schema v2; no issues found") {
		t.Fatalf("output = %q, want ok: schema v2; no issues found", out.String())
	}
	if strings.Contains(out.String(), "notice:") {
		t.Fatalf("output = %q, did not expect a migrate notice for an already-v2 roster", out.String())
	}
}

func TestRosterLintCmd_FutureSchemaVersionReportsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte("schema_version: 999\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"roster", "lint", path})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Fatalf("expected an error for schema_version: 999, output: %s", out.String())
	}
	if !strings.Contains(out.String(), "newer than this pilot supports") {
		t.Fatalf("output = %q, want a newer-than-supported message", out.String())
	}
}

func TestRosterLintCmd_UpgradeFlagMigratesV1RosterInPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(rosterLintFixtureValid), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"roster", "lint", "--upgrade", path})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)
	// --upgrade is a persistent package-level flag var; cobra only sets it
	// when the flag is actually passed, so it would otherwise leak "true"
	// into any later test that doesn't pass --upgrade explicitly.
	defer func() { rosterLintUpgrade = false }()

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, out.String())
	}
	if !strings.Contains(out.String(), "Roster migrated successfully") || !strings.Contains(out.String(), "backup:") {
		t.Fatalf("output = %q, want a migration success report", out.String())
	}

	migrated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(migrated), "schema_version: 2") {
		t.Fatalf("roster on disk = %q, want it upgraded to schema_version: 2", migrated)
	}
}

func TestRosterLintCmd_UpgradeFlagNoOpOnV2Roster(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	v2 := strings.Replace(rosterLintFixtureValid, "schema_version: 1", "schema_version: 2\nnetgroups: []", 1)
	if err := os.WriteFile(path, []byte(v2), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"roster", "lint", "--upgrade", path})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)
	defer func() { rosterLintUpgrade = false }()

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, out.String())
	}
	if !strings.Contains(out.String(), "ok: schema v2; no issues found") {
		t.Fatalf("output = %q, want the plain v2 ok message, not a migration report", out.String())
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != v2 {
		t.Fatalf("--upgrade modified an already-v2 roster (err=%v)", err)
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
