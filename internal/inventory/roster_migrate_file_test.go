package inventory

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ---- lock -----------------------------------------------------------------

func TestAcquireMutationLock_SecondAttemptFailsFast(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "test.lock")
	first, err := acquireMutationLock(lockPath)
	if err != nil {
		t.Fatalf("acquireMutationLock() error = %v", err)
	}
	defer first.release()

	if _, err := acquireMutationLock(lockPath); !errors.Is(err, ErrMutationLocked) {
		t.Fatalf("second acquireMutationLock() error = %v, want ErrMutationLocked", err)
	}
}

func TestAcquireMutationLock_ReleaseAllowsReacquisition(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "test.lock")
	first, err := acquireMutationLock(lockPath)
	if err != nil {
		t.Fatalf("acquireMutationLock() error = %v", err)
	}
	if err := first.release(); err != nil {
		t.Fatalf("release() error = %v", err)
	}
	second, err := acquireMutationLock(lockPath)
	if err != nil {
		t.Fatalf("acquireMutationLock() after release error = %v", err)
	}
	second.release()
}

func TestAcquireMutationLock_StaleLockFileAloneDoesNotBlock(t *testing.T) {
	// §17: "A stale file alone MUST NOT block migration." A leftover
	// sidecar file nobody holds an flock on must not prevent acquisition —
	// only the OS lock itself decides exclusivity.
	lockPath := filepath.Join(t.TempDir(), "test.lock")
	if err := os.WriteFile(lockPath, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	lock, err := acquireMutationLock(lockPath)
	if err != nil {
		t.Fatalf("acquireMutationLock() error = %v, want success despite a pre-existing unlocked file", err)
	}
	lock.release()
}

// ---- backup -----------------------------------------------------------------

func TestCreateRosterBackup_ExactBytesAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roster.yaml")
	original := []byte("schema_version: 1\nsome: content\n")

	backupPath, err := createRosterBackup(path, original, RosterSchemaV1, "20260101T000000Z")
	if err != nil {
		t.Fatalf("createRosterBackup() error = %v", err)
	}
	got, err := os.ReadFile(backupPath)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("backup content = %q, err = %v, want the exact original bytes", got, err)
	}
	info, err := os.Stat(backupPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %v, err = %v, want 0600", info.Mode().Perm(), err)
	}
	if !strings.Contains(backupPath, ".v1.20260101T000000Z.") || !strings.HasSuffix(backupPath, ".bak") {
		t.Fatalf("backupPath = %q, doesn't match the expected naming convention", backupPath)
	}
}

func TestCreateRosterBackup_RefusesToOverwriteExistingBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roster.yaml")
	original := []byte("schema_version: 1\n")

	if _, err := createRosterBackup(path, original, RosterSchemaV1, "20260101T000000Z"); err != nil {
		t.Fatalf("first createRosterBackup() error = %v", err)
	}
	if _, err := createRosterBackup(path, original, RosterSchemaV1, "20260101T000000Z"); err == nil {
		t.Fatal("expected the second createRosterBackup() with identical timestamp+content to fail (O_EXCL)")
	}
}

// ---- atomic replace -----------------------------------------------------

func TestAtomicReplaceFile_WritesContentAndRestoresMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := atomicReplaceFile(path, []byte("new"), 0o640); err != nil {
		t.Fatalf("atomicReplaceFile() error = %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "new" {
		t.Fatalf("content = %q, err = %v, want %q", got, err, "new")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v, err = %v, want 0640", info.Mode().Perm(), err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("dir entries = %v, err = %v, want exactly the roster file (no leftover temp)", entries, err)
	}
}

func TestAtomicReplaceFile_FailsCleanlyIntoNonexistentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-subdir", "roster.yaml")
	if err := atomicReplaceFile(path, []byte("data"), 0o600); err == nil {
		t.Fatal("expected an error writing into a nonexistent directory")
	}
}

// ---- MigrateRosterFile: success path --------------------------------------

func TestMigrateRosterFile_MinimalDocumentEndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	original := []byte("schema_version: 1\nfreeipa:\n  admin:\n    principal: admin\n    password: secret123\n")
	if err := os.WriteFile(path, original, 0o640); err != nil {
		t.Fatal(err)
	}

	result, err := MigrateRosterFile(path, RosterMigrationOptions{})
	if err != nil {
		t.Fatalf("MigrateRosterFile() error = %v", err)
	}
	if !result.Changed || result.FromVersion != 1 || result.ToVersion != 2 {
		t.Fatalf("result = %+v, want a changed v1->v2 migration", result)
	}
	if result.OriginalSHA256 == "" || result.NewSHA256 == "" || result.OriginalSHA256 == result.NewSHA256 {
		t.Fatalf("result SHA fields look wrong: %+v", result)
	}

	migrated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	root := mustParseRoster(t, string(migrated))
	if n, _ := toInt(root["schema_version"]); n != 2 {
		t.Fatalf("schema_version = %v, want 2", root["schema_version"])
	}
	if v := ValidateRosterV2(root); len(v) != 0 {
		t.Fatalf("migrated roster failed ValidateRosterV2: %v", v)
	}

	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("roster mode = %v, err = %v, want the original mode 0640 preserved", info.Mode().Perm(), err)
	}

	backupBytes, err := os.ReadFile(result.BackupPath)
	if err != nil || !bytes.Equal(backupBytes, original) {
		t.Fatalf("backup content = %q, err = %v, want the exact original bytes", backupBytes, err)
	}
	backupInfo, err := os.Stat(result.BackupPath)
	if err != nil || backupInfo.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %v, err = %v, want 0600", backupInfo.Mode().Perm(), err)
	}
	if !strings.Contains(filepath.Base(result.BackupPath), ".v1.") || !strings.HasSuffix(result.BackupPath, ".bak") {
		t.Fatalf("backup path %q doesn't match the expected naming convention", result.BackupPath)
	}
}

func TestMigrateRosterFile_DryRunDoesNotWriteAnything(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	original := []byte(minimalValidRoster)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := MigrateRosterFile(path, RosterMigrationOptions{DryRun: true})
	if err != nil {
		t.Fatalf("MigrateRosterFile() error = %v", err)
	}
	if !result.Changed || result.BackupPath != "" {
		t.Fatalf("dry-run result = %+v, want changed=true (a migration would happen) but no backup", result)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("dry-run modified the roster file (err=%v)", err)
	}
	// The mutation-lock sidecar file is an expected artifact of even a
	// dry-run acquiring the lock; only a backup or a leftover temp file
	// would indicate the dry run actually wrote something it shouldn't.
	assertNoBackupFiles(t, dir)
	for _, e := range direntNames(t, dir) {
		if e != "roster.yaml" && e != "roster.yaml.pilot-migrate.lock" {
			t.Fatalf("dry-run created an unexpected file: %s", e)
		}
	}
}

func direntNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	return names
}

// ---- M11: repeated migration is idempotent, no extra backup --------------

func TestMigrateRosterFile_RepeatedMigrationIsIdempotentWithoutExtraBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(minimalValidRoster), 0o600); err != nil {
		t.Fatal(err)
	}

	first, err := MigrateRosterFile(path, RosterMigrationOptions{})
	if err != nil {
		t.Fatalf("first MigrateRosterFile() error = %v", err)
	}
	if !first.Changed || first.FromVersion != 1 || first.ToVersion != 2 || first.BackupPath == "" {
		t.Fatalf("first result = %+v, want a changed v1->v2 migration with a backup", first)
	}
	if _, err := os.Stat(first.BackupPath); err != nil {
		t.Fatalf("backup file missing: %v", err)
	}

	second, err := MigrateRosterFile(path, RosterMigrationOptions{})
	if err != nil {
		t.Fatalf("second MigrateRosterFile() error = %v", err)
	}
	if second.Changed || second.BackupPath != "" {
		t.Fatalf("second result = %+v, want changed=false and no new backup", second)
	}
	if second.FromVersion != 2 || second.ToVersion != 2 {
		t.Fatalf("second result = %+v, want a v2->v2 no-op", second)
	}

	backups, err := filepath.Glob(path + ".v*.bak")
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 {
		t.Fatalf("found %d backup file(s), want exactly 1: %v", len(backups), backups)
	}
}

// ---- M9: invalid original document fails without mutation -----------------

func TestMigrateRosterFile_InvalidV1DocumentFailsWithoutMutation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	original := []byte("schema_version: 1\nusers:\n  - name: Alice\n") // uppercase name fails checkUsers
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := MigrateRosterFile(path, RosterMigrationOptions{}); err == nil {
		t.Fatal("expected an error migrating a document that fails schema v1 validation")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("roster was modified despite failing v1 validation (err=%v)", err)
	}
	assertNoBackupFiles(t, dir)
}

// ---- M12: future schema version fails closed, no mutation -----------------

func TestMigrateRosterFile_FutureSchemaVersionFailsClosedWithoutMutation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	original := []byte("schema_version: 999\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := MigrateRosterFile(path, RosterMigrationOptions{}); err == nil {
		t.Fatal("expected an error migrating an unsupported future schema version")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("roster was modified despite an unsupported schema version (err=%v)", err)
	}
	assertNoBackupFiles(t, dir)
}

func TestMigrateRosterFile_RejectsUnsupportedTargetVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(minimalValidRoster), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateRosterFile(path, RosterMigrationOptions{TargetVersion: 3}); err == nil {
		t.Fatal("expected an error for an unsupported TargetVersion")
	}
	assertNoBackupFiles(t, dir)
}

// ---- encrypted roster: fails closed, no mutation ---------------------------

func TestMigrateRosterFile_EncryptedRosterFailsClosedWithoutMutation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	original := []byte("$ANSIBLE_VAULT;1.1;AES256\n633864363...\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := MigrateRosterFile(path, RosterMigrationOptions{}); err != ErrRosterEncrypted {
		t.Fatalf("MigrateRosterFile() error = %v, want ErrRosterEncrypted", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("roster was modified despite being encrypted (err=%v)", err)
	}
	assertNoBackupFiles(t, dir)
}

// ---- M13: lock contention fails fast, no mutation --------------------------

// TestMigrateRosterFile_FailsFastWhenAlreadyLocked validates the same
// contract a genuine two-process race would (§17: "fail fast, do not
// queue, do not create backup, do not modify roster") but deterministically
// — by holding the lock directly rather than racing two goroutines against
// real scheduling, which would otherwise make this test flaky depending on
// which goroutine happens to reach the lock first.
func TestMigrateRosterFile_FailsFastWhenAlreadyLocked(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	original := []byte(minimalValidRoster)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	lock, err := acquireMutationLock(path + ".pilot-migrate.lock")
	if err != nil {
		t.Fatalf("acquireMutationLock() error = %v", err)
	}
	defer lock.release()

	if _, err := MigrateRosterFile(path, RosterMigrationOptions{}); !errors.Is(err, ErrMutationLocked) {
		t.Fatalf("MigrateRosterFile() error = %v, want ErrMutationLocked", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("roster was modified despite lock contention (err=%v)", err)
	}
	assertNoBackupFiles(t, dir)
}

// ---- EnsureRosterCurrent ---------------------------------------------------

func TestEnsureRosterCurrent_MigratesV1Roster(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(minimalValidRoster), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := EnsureRosterCurrent(path, RosterMigrationOptions{})
	if err != nil {
		t.Fatalf("EnsureRosterCurrent() error = %v", err)
	}
	if !result.Changed || result.FromVersion != 1 || result.ToVersion != 2 || result.BackupPath == "" {
		t.Fatalf("result = %+v, want a changed v1->v2 migration with a backup", result)
	}
}

func TestEnsureRosterCurrent_NoOpOnCurrentSchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	v2 := strings.Replace(minimalValidRoster, "schema_version: 1", "schema_version: 2\nnetgroups: []", 1)
	if err := os.WriteFile(path, []byte(v2), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := EnsureRosterCurrent(path, RosterMigrationOptions{})
	if err != nil {
		t.Fatalf("EnsureRosterCurrent() error = %v", err)
	}
	if result.Changed || result.BackupPath != "" {
		t.Fatalf("result = %+v, want a no-op", result)
	}
	assertNoBackupFiles(t, dir)
}

// TestEnsureRosterCurrent_IgnoresDryRunAndTargetVersionOptions locks in
// that automatic call sites can't accidentally turn into a preview-only or
// wrong-target migration just because a caller (or a copy-pasted opts
// value from elsewhere) happens to set those fields — EnsureRosterCurrent
// always performs a real upgrade to the current schema.
func TestEnsureRosterCurrent_IgnoresDryRunAndTargetVersionOptions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(minimalValidRoster), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := EnsureRosterCurrent(path, RosterMigrationOptions{DryRun: true, TargetVersion: 1})
	if err != nil {
		t.Fatalf("EnsureRosterCurrent() error = %v", err)
	}
	if !result.Changed || result.BackupPath == "" {
		t.Fatalf("result = %+v, want a real (non-dry-run) migration despite opts.DryRun/TargetVersion", result)
	}
	migrated, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(migrated), "schema_version: 2") {
		t.Fatalf("roster on disk = %q, err = %v, want it actually upgraded to schema_version: 2", migrated, err)
	}
}

func TestEnsureRosterCurrent_EncryptedRosterFailsClosedWithoutMutation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	original := []byte("$ANSIBLE_VAULT;1.1;AES256\n633864363...\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := EnsureRosterCurrent(path, RosterMigrationOptions{}); err != ErrRosterEncrypted {
		t.Fatalf("EnsureRosterCurrent() error = %v, want ErrRosterEncrypted", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("roster was modified despite being encrypted (err=%v)", err)
	}
}

func assertNoBackupFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".bak") {
			t.Fatalf("unexpected backup file created: %s", e.Name())
		}
	}
}

// ---- encrypted roster (M6/M7) ----------------------------------------------
//
// These tests use the real ansible-vault binary (never mocked) to prepare
// and independently verify fixtures — matching this repo's evidence-based
// testing convention elsewhere (internal/ansible, network_check_test.go,
// preflight_check_test.go all skip gracefully rather than mock when the
// real tool isn't on PATH).

func requireAnsibleVault(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ansible-vault"); err != nil {
		t.Skipf("ansible-vault not installed: %v", err)
	}
}

func writeVaultPasswordFile(t *testing.T, path, password string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(password+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func encryptFileForTest(t *testing.T, path, vaultPasswordFile string) {
	t.Helper()
	cmd := exec.Command("ansible-vault", "encrypt", "--vault-password-file", vaultPasswordFile, path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ansible-vault encrypt (test setup) failed: %v: %s", err, out)
	}
}

func viewFileForTest(t *testing.T, path, vaultPasswordFile string) []byte {
	t.Helper()
	cmd := exec.Command("ansible-vault", "view", "--vault-password-file", vaultPasswordFile, path)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("ansible-vault view (test verification) failed: %v", err)
	}
	return out
}

// TestMigrateRosterFile_EncryptedRoster_MigratesV1ToV2 is M6: backup must
// be byte-identical to the encrypted input, and the result must remain
// ansible-vault encrypted (never left as plaintext).
func TestMigrateRosterFile_EncryptedRoster_MigratesV1ToV2(t *testing.T) {
	requireAnsibleVault(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(minimalValidRoster), 0o600); err != nil {
		t.Fatal(err)
	}
	pwFile := writeVaultPasswordFile(t, filepath.Join(dir, "vault-pass"), "correct-horse-battery-staple")
	encryptFileForTest(t, path, pwFile)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	result, err := MigrateRosterFile(path, RosterMigrationOptions{VaultPasswordFile: pwFile})
	if err != nil {
		t.Fatalf("MigrateRosterFile() error = %v", err)
	}
	if !result.Changed || result.FromVersion != 1 || result.ToVersion != 2 || result.BackupPath == "" {
		t.Fatalf("result = %+v, want a changed v1->v2 migration with a backup", result)
	}

	backupBytes, err := os.ReadFile(result.BackupPath)
	if err != nil || !bytes.Equal(backupBytes, original) {
		t.Fatalf("backup content mismatch (err=%v): backup must be byte-identical to the original ciphertext", err)
	}
	backupInfo, err := os.Stat(result.BackupPath)
	if err != nil || backupInfo.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %v, err = %v, want 0600", backupInfo.Mode().Perm(), err)
	}

	migrated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(migrated)), "$ANSIBLE_VAULT") {
		t.Fatalf("migrated roster is not ansible-vault encrypted:\n%s", migrated)
	}
	if bytes.Equal(migrated, original) {
		t.Fatal("migrated ciphertext is byte-identical to the original — migration did not actually change anything")
	}

	plaintext := viewFileForTest(t, path, pwFile)
	root := mustParseRoster(t, string(plaintext))
	if n, _ := toInt(root["schema_version"]); n != 2 {
		t.Fatalf("decrypted schema_version = %v, want 2", root["schema_version"])
	}
	if v := ValidateRosterV2(root); len(v) != 0 {
		t.Fatalf("decrypted migrated roster failed ValidateRosterV2: %v", v)
	}
}

// TestMigrateRosterFile_EncryptedRoster_WrongPasswordFailsWithoutMutation is
// M7: migration fails, the original SHA-256 is unchanged, and no plaintext
// artifact remains — satisfied by construction here, since decrypt is the
// very first thing migrateEncryptedRosterFile does, before backup or any
// write.
func TestMigrateRosterFile_EncryptedRoster_WrongPasswordFailsWithoutMutation(t *testing.T) {
	requireAnsibleVault(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(minimalValidRoster), 0o600); err != nil {
		t.Fatal(err)
	}
	correctPwFile := writeVaultPasswordFile(t, filepath.Join(dir, "vault-pass-correct"), "correct-password")
	encryptFileForTest(t, path, correctPwFile)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	originalSHA := sha256Hex(original)

	wrongPwFile := writeVaultPasswordFile(t, filepath.Join(dir, "vault-pass-wrong"), "wrong-password")
	if _, err := MigrateRosterFile(path, RosterMigrationOptions{VaultPasswordFile: wrongPwFile}); err == nil {
		t.Fatal("expected an error migrating with the wrong vault password")
	}

	got, err := os.ReadFile(path)
	if err != nil || sha256Hex(got) != originalSHA {
		t.Fatalf("roster changed despite a failed decrypt (err=%v)", err)
	}
	assertNoBackupFiles(t, dir)
}

func TestMigrateRosterFile_EncryptedRoster_AlreadyV2IsNoOp(t *testing.T) {
	requireAnsibleVault(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	v2 := strings.Replace(minimalValidRoster, "schema_version: 1", "schema_version: 2\nnetgroups: []", 1)
	if err := os.WriteFile(path, []byte(v2), 0o600); err != nil {
		t.Fatal(err)
	}
	pwFile := writeVaultPasswordFile(t, filepath.Join(dir, "vault-pass"), "a-password")
	encryptFileForTest(t, path, pwFile)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	result, err := MigrateRosterFile(path, RosterMigrationOptions{VaultPasswordFile: pwFile})
	if err != nil {
		t.Fatalf("MigrateRosterFile() error = %v", err)
	}
	if result.Changed || result.BackupPath != "" {
		t.Fatalf("result = %+v, want a no-op", result)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("already-current encrypted roster was modified (err=%v)", err)
	}
	assertNoBackupFiles(t, dir)
}

func TestMigrateRosterFile_EncryptedRoster_DryRunDoesNotWrite(t *testing.T) {
	requireAnsibleVault(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(minimalValidRoster), 0o600); err != nil {
		t.Fatal(err)
	}
	pwFile := writeVaultPasswordFile(t, filepath.Join(dir, "vault-pass"), "a-password")
	encryptFileForTest(t, path, pwFile)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	result, err := MigrateRosterFile(path, RosterMigrationOptions{VaultPasswordFile: pwFile, DryRun: true})
	if err != nil {
		t.Fatalf("MigrateRosterFile() error = %v", err)
	}
	if !result.Changed || result.BackupPath != "" || result.NewSHA256 != "" {
		t.Fatalf("dry-run result = %+v, want changed=true, no backup, and no predicted NewSHA256 (nondeterministic re-encryption)", result)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("dry-run modified the encrypted roster (err=%v)", err)
	}
	assertNoBackupFiles(t, dir)
}

// TestMigrateRosterFile_EncryptedRoster_RepeatedMigrationNoExtraBackup is
// the encrypted-roster counterpart of M11.
func TestMigrateRosterFile_EncryptedRoster_RepeatedMigrationNoExtraBackup(t *testing.T) {
	requireAnsibleVault(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(minimalValidRoster), 0o600); err != nil {
		t.Fatal(err)
	}
	pwFile := writeVaultPasswordFile(t, filepath.Join(dir, "vault-pass"), "a-password")
	encryptFileForTest(t, path, pwFile)

	first, err := MigrateRosterFile(path, RosterMigrationOptions{VaultPasswordFile: pwFile})
	if err != nil {
		t.Fatalf("first MigrateRosterFile() error = %v", err)
	}
	if !first.Changed || first.BackupPath == "" {
		t.Fatalf("first result = %+v, want a changed migration with a backup", first)
	}

	second, err := MigrateRosterFile(path, RosterMigrationOptions{VaultPasswordFile: pwFile})
	if err != nil {
		t.Fatalf("second MigrateRosterFile() error = %v", err)
	}
	if second.Changed || second.BackupPath != "" {
		t.Fatalf("second result = %+v, want changed=false and no new backup", second)
	}

	backups, err := filepath.Glob(path + ".v*.bak")
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 {
		t.Fatalf("found %d backup file(s), want exactly 1: %v", len(backups), backups)
	}
}

func TestMigrateRosterFile_EncryptedRoster_InvalidV1ContentFailsWithoutMutation(t *testing.T) {
	requireAnsibleVault(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	invalid := "schema_version: 1\nusers:\n  - name: Alice\n" // uppercase name fails checkUsers
	if err := os.WriteFile(path, []byte(invalid), 0o600); err != nil {
		t.Fatal(err)
	}
	pwFile := writeVaultPasswordFile(t, filepath.Join(dir, "vault-pass"), "a-password")
	encryptFileForTest(t, path, pwFile)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := MigrateRosterFile(path, RosterMigrationOptions{VaultPasswordFile: pwFile}); err == nil {
		t.Fatal("expected an error migrating a document that fails schema v1 validation")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("encrypted roster was modified despite failing v1 validation (err=%v)", err)
	}
	assertNoBackupFiles(t, dir)
}
