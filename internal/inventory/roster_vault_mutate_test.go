package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// requireAnsibleVault/writeVaultPasswordFile/encryptFileForTest/viewFileForTest
// are shared package-level helpers already defined in
// roster_migrate_file_test.go.

func TestDecryptRosterToTempFile_ReturnsPlaintextAndCleansUp(t *testing.T) {
	requireAnsibleVault(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(minimalValidRoster), 0o600); err != nil {
		t.Fatal(err)
	}
	vaultPasswordFile := writeVaultPasswordFile(t, filepath.Join(dir, "vault-pass"), "s3cret-pw")
	encryptFileForTest(t, path, vaultPasswordFile)

	tmpPath, cleanup, err := DecryptRosterToTempFile(path, vaultPasswordFile)
	if err != nil {
		t.Fatalf("DecryptRosterToTempFile() error = %v", err)
	}
	defer cleanup()

	got, err := os.ReadFile(tmpPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != strings.TrimSpace(minimalValidRoster) {
		t.Fatalf("decrypted temp file content = %q, want %q", got, minimalValidRoster)
	}

	cleanup()
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatalf("expected cleanup() to remove the temp file, stat err = %v", err)
	}
}

func TestMutateEncryptedRosterFile_MutateSuccessReencryptsAndInstalls(t *testing.T) {
	requireAnsibleVault(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(removeFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	vaultPasswordFile := writeVaultPasswordFile(t, filepath.Join(dir, "vault-pass"), "s3cret-pw")
	encryptFileForTest(t, path, vaultPasswordFile)

	err := MutateEncryptedRosterFile(path, vaultPasswordFile, func(plaintextPath string) error {
		return RemoveRosterUser(plaintextPath, "dave", RemoveRosterUserOptions{})
	})
	if err != nil {
		t.Fatalf("MutateEncryptedRosterFile() error = %v", err)
	}

	installed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(installed)), "$ANSIBLE_VAULT") {
		t.Fatalf("installed roster is not ansible-vault encrypted:\n%s", installed)
	}

	plaintext := viewFileForTest(t, path, vaultPasswordFile)
	names, err := RosterUserNames(writePlainCopy(t, dir, plaintext))
	if err != nil {
		t.Fatal(err)
	}
	if contains(names, "dave") {
		t.Fatalf("expected dave to be removed from the re-encrypted roster, got %v", names)
	}
	if !contains(names, "alice") || !contains(names, "typo-user") {
		t.Fatalf("expected other users to survive untouched, got %v", names)
	}
}

func TestMutateEncryptedRosterFile_MutateFailureLeavesOriginalUntouched(t *testing.T) {
	requireAnsibleVault(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(removeFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	vaultPasswordFile := writeVaultPasswordFile(t, filepath.Join(dir, "vault-pass"), "s3cret-pw")
	encryptFileForTest(t, path, vaultPasswordFile)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	err = MutateEncryptedRosterFile(path, vaultPasswordFile, func(plaintextPath string) error {
		// typo-user is still referenced (no cascade) — RemoveRosterUser
		// must refuse without writing anything.
		return RemoveRosterUser(plaintextPath, "typo-user", RemoveRosterUserOptions{})
	})
	if err == nil {
		t.Fatalf("expected an error when the mutate callback fails")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("original roster bytes changed after a failed mutate callback")
	}
}

// writePlainCopy writes data to a fresh plaintext file under dir so the
// generic plaintext-path roster readers (RosterUserNames, etc.) can be
// reused to inspect ansible-vault view's decrypted output.
func writePlainCopy(t *testing.T, dir string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, "decrypted-view.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
