package cmd

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

func TestRosterMigrateCmd_MigratesV1RosterAndPrintsReport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(rosterLintFixtureValid), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"roster", "migrate", path})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, out.String())
	}
	output := out.String()
	for _, want := range []string{"Roster migrated successfully", "schema:", "1 -> 2", "backup:", "original_sha256:", "new_sha256:", "HBAC effective access:", "unchanged"} {
		if !strings.Contains(output, want) {
			t.Fatalf("output = %q, want it to contain %q", output, want)
		}
	}
	// Never print roster content/secrets — the fixture's own domain value
	// is a convenient stand-in to prove the report doesn't echo the file.
	if strings.Contains(output, "ipa.pilot.internal") {
		t.Fatalf("output = %q, must not print roster content", output)
	}

	migrated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(migrated), "schema_version: 2") {
		t.Fatalf("roster on disk = %q, want it upgraded to schema_version: 2", migrated)
	}
}

func TestRosterMigrateCmd_AlreadyCurrentIsANoOp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	v2 := strings.Replace(rosterLintFixtureValid, "schema_version: 1", "schema_version: 2\nnetgroups: []", 1)
	if err := os.WriteFile(path, []byte(v2), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"roster", "migrate", path})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, out.String())
	}
	if !strings.Contains(out.String(), "already schema v2") {
		t.Fatalf("output = %q, want an already-current message", out.String())
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != v2 {
		t.Fatalf("an already-current migrate call modified the roster (err=%v)", err)
	}
}

func TestRosterMigrateCmd_DryRunDoesNotWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(rosterLintFixtureValid), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"roster", "migrate", "--dry-run", path})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)
	// --dry-run is a persistent package-level flag var; cobra only sets it
	// when the flag is actually passed, so it would otherwise leak "true"
	// into any later test that omits --dry-run.
	defer func() { rosterMigrateDryRun = false }()

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, out.String())
	}
	if !strings.Contains(out.String(), "dry run") {
		t.Fatalf("output = %q, want it to say this was a dry run", out.String())
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != rosterLintFixtureValid {
		t.Fatalf("--dry-run modified the roster (err=%v)", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".bak") {
			t.Fatalf("--dry-run created a backup file: %s", e.Name())
		}
	}
}

func TestRosterMigrateCmd_RejectsUnsupportedTargetVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(rosterLintFixtureValid), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"roster", "migrate", "--to", "3", path})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)
	// --to is a persistent package-level flag var; reset it so it doesn't
	// leak "3" into any later test that omits --to.
	defer func() { rosterMigrateTargetVersion = int(inventory.CurrentRosterSchemaVersion) }()

	if err := rootCmd.Execute(); err == nil {
		t.Fatalf("expected an error for --to 3, output: %s", out.String())
	}
}

func TestRosterMigrateCmd_InvalidV1DocumentReportsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	original := []byte(rosterLintFixtureBroken)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"roster", "migrate", path})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	if err := rootCmd.Execute(); err == nil {
		t.Fatalf("expected an error migrating an invalid v1 roster, output: %s", out.String())
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(original) {
		t.Fatalf("roster was modified despite failing validation (err=%v)", err)
	}
}

func TestRosterMigrateCmd_EncryptedWithoutVaultPasswordFileSuggestsTheFlag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte("$ANSIBLE_VAULT;1.1;AES256\n633864363...\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"roster", "migrate", path})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--vault-password-file") {
		t.Fatalf("Execute() error = %v, want a message suggesting --vault-password-file", err)
	}
}

func TestRosterMigrateCmd_EncryptedWithWrongVaultPasswordFileFailsCleanly(t *testing.T) {
	if _, err := exec.LookPath("ansible-vault"); err != nil {
		t.Skipf("ansible-vault not installed: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(rosterLintFixtureValid), 0o600); err != nil {
		t.Fatal(err)
	}
	correctPwFile := filepath.Join(dir, "vault-pass-correct")
	if err := os.WriteFile(correctPwFile, []byte("correct-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("ansible-vault", "encrypt", "--vault-password-file", correctPwFile, path).CombinedOutput(); err != nil {
		t.Fatalf("ansible-vault encrypt (test setup) failed: %v: %s", err, out)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	wrongPwFile := filepath.Join(dir, "vault-pass-wrong")
	if err := os.WriteFile(wrongPwFile, []byte("wrong-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"roster", "migrate", "--vault-password-file", wrongPwFile, path})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)
	defer func() { rosterMigrateVaultPassword = "" }()

	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected an error migrating with the wrong vault password")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("roster changed despite a failed decrypt (err=%v)", err)
	}
}

func TestRosterMigrateCmd_EncryptedRosterMigratesSuccessfully(t *testing.T) {
	if _, err := exec.LookPath("ansible-vault"); err != nil {
		t.Skipf("ansible-vault not installed: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(rosterLintFixtureValid), 0o600); err != nil {
		t.Fatal(err)
	}
	pwFile := filepath.Join(dir, "vault-pass")
	if err := os.WriteFile(pwFile, []byte("a-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("ansible-vault", "encrypt", "--vault-password-file", pwFile, path).CombinedOutput(); err != nil {
		t.Fatalf("ansible-vault encrypt (test setup) failed: %v: %s", err, out)
	}

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"roster", "migrate", "--vault-password-file", pwFile, path})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)
	defer func() { rosterMigrateVaultPassword = "" }()

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
	if !strings.HasPrefix(strings.TrimSpace(string(migrated)), "$ANSIBLE_VAULT") {
		t.Fatalf("migrated roster is not ansible-vault encrypted:\n%s", migrated)
	}
	viewOut, err := exec.Command("ansible-vault", "view", "--vault-password-file", pwFile, path).Output()
	if err != nil {
		t.Fatalf("ansible-vault view (test verification) failed: %v", err)
	}
	if !strings.Contains(string(viewOut), "schema_version: 2") {
		t.Fatalf("decrypted roster = %q, want schema_version: 2", viewOut)
	}
}
