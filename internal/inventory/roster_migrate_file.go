// roster_migrate_file.go is the filesystem-touching half of the v1 -> v2
// roster migration: locking, the persistent backup, atomic replacement,
// and rollback on failure, all wired around the pure transformation in
// roster_migrate.go. See MigrateRosterFile's doc comment for the exact
// transaction order.
package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// RosterMigrationOptions configures a MigrateRosterFile call.
type RosterMigrationOptions struct {
	// TargetVersion defaults to CurrentRosterSchemaVersion when zero. No
	// other value is currently supported — MigrateRosterFile only knows
	// how to migrate v1 -> v2.
	TargetVersion int
	// VaultPasswordFile, if set, lets MigrateRosterFile handle an
	// ansible-vault-encrypted roster: it decrypts using this file, migrates
	// in memory, and re-encrypts the candidate with the same file before
	// installing it (see migrateEncryptedRosterFile). An encrypted roster
	// with this left empty still fails closed with ErrRosterEncrypted, the
	// same posture every other roster helper already has — never guessed,
	// never auto-decrypted.
	VaultPasswordFile string
	// DryRun reports what would happen (FromVersion/ToVersion/Changed/
	// the SHA-256 the candidate would have) without creating a backup or
	// writing anything.
	DryRun bool
}

// RosterMigrationResult reports what MigrateRosterFile did. BackupPath is
// empty when Changed is false — a no-op migration (already at
// TargetVersion) never creates a backup, and neither does a dry run.
type RosterMigrationResult struct {
	FromVersion    int
	ToVersion      int
	Changed        bool
	BackupPath     string
	OriginalSHA256 string
	NewSHA256      string
}

// MigrateRosterFile upgrades the roster at path to opts.TargetVersion (v2
// if unset), as one transaction:
//
//  1. acquire the mutation lock (fails fast if another process holds it —
//     no backup, no read past this point)
//  2. read original bytes, record its mode, hash it
//  3. an ansible-vault-encrypted roster with no VaultPasswordFile fails
//     closed (ErrRosterEncrypted); with one, control passes to
//     migrateEncryptedRosterFile instead of the steps below
//  4. detect schema version; already-current is a no-op (Changed: false,
//     no backup); anything but v1 -> target v2 is an error
//  5. validate the original as v1, build the v2 candidate in memory
//     (MigrateRosterV1ToV2), validate the candidate as v2, and check the
//     semantic-equivalence fingerprint (ComputeRosterSemanticFingerprint)
//     — any failure here stops before anything is written
//  6. (unless DryRun) create the persistent backup, then atomically
//     replace the roster; if the replace fails, roll back to the exact
//     backed-up bytes and report the failure
//  7. reopen and re-validate the installed result
//
// A failure before backup creation leaves the original file completely
// untouched. A failure after backup creation is rolled back to the exact
// original bytes before returning an error.
func MigrateRosterFile(path string, opts RosterMigrationOptions) (RosterMigrationResult, error) {
	targetVersion := opts.TargetVersion
	if targetVersion == 0 {
		targetVersion = int(CurrentRosterSchemaVersion)
	}
	if targetVersion != int(RosterSchemaV2) {
		return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: unsupported target schema version %d (only %d is supported)", path, targetVersion, RosterSchemaV2)
	}

	lock, err := acquireMutationLock(path + ".pilot-migrate.lock")
	if err != nil {
		return RosterMigrationResult{}, err
	}
	defer lock.release()

	original, err := os.ReadFile(path)
	if err != nil {
		return RosterMigrationResult{}, fmt.Errorf("read roster %s: %w", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return RosterMigrationResult{}, fmt.Errorf("stat roster %s: %w", path, err)
	}
	originalMode := info.Mode().Perm()
	originalSHA := sha256Hex(original)

	if strings.HasPrefix(strings.TrimSpace(string(original)), "$ANSIBLE_VAULT") {
		if opts.VaultPasswordFile == "" {
			return RosterMigrationResult{}, ErrRosterEncrypted
		}
		return migrateEncryptedRosterFile(path, opts, original, originalMode, originalSHA, targetVersion)
	}

	detected, err := DetectRosterSchemaVersion(original)
	if err != nil {
		return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: %w", path, err)
	}

	if int(detected) == targetVersion {
		return RosterMigrationResult{
			FromVersion:    int(detected),
			ToVersion:      targetVersion,
			Changed:        false,
			OriginalSHA256: originalSHA,
			NewSHA256:      originalSHA,
		}, nil
	}
	if detected != RosterSchemaV1 {
		return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: no migration path from schema v%d to v%d", path, detected, targetVersion)
	}

	var originalRoot map[string]any
	if err := yaml.Unmarshal(original, &originalRoot); err != nil {
		return RosterMigrationResult{}, fmt.Errorf("parse roster %s: %w", path, err)
	}
	if v := ValidateRosterV1(originalRoot); len(v) != 0 {
		return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: original document fails schema v1 validation: %v", path, v)
	}

	originalNode := &yaml.Node{}
	if err := yaml.Unmarshal(original, originalNode); err != nil {
		return RosterMigrationResult{}, fmt.Errorf("parse roster %s: %w", path, err)
	}
	migratedNode, err := MigrateRosterV1ToV2(originalNode)
	if err != nil {
		return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: %w", path, err)
	}
	candidate, err := yaml.Marshal(migratedNode)
	if err != nil {
		return RosterMigrationResult{}, fmt.Errorf("render migrated roster %s: %w", path, err)
	}

	var candidateRoot map[string]any
	if err := yaml.Unmarshal(candidate, &candidateRoot); err != nil {
		return RosterMigrationResult{}, fmt.Errorf("parse migrated roster %s: %w", path, err)
	}
	if v := ValidateRosterV2(candidateRoot); len(v) != 0 {
		return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: candidate fails schema v2 validation: %v", path, v)
	}
	before := ComputeRosterSemanticFingerprint(originalRoot)
	after := ComputeRosterSemanticFingerprint(candidateRoot)
	if !RosterSemanticFingerprintsEqual(before, after) {
		return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: candidate would change authorization-affecting content, refusing to migrate", path)
	}

	newSHA := sha256Hex(candidate)
	if opts.DryRun {
		return RosterMigrationResult{
			FromVersion:    int(detected),
			ToVersion:      targetVersion,
			Changed:        true,
			OriginalSHA256: originalSHA,
			NewSHA256:      newSHA,
		}, nil
	}

	backupPath, err := createRosterBackup(path, original, detected, time.Now().UTC().Format("20060102T150405Z"))
	if err != nil {
		return RosterMigrationResult{}, fmt.Errorf("backup roster %s: %w", path, err)
	}

	if err := atomicReplaceFile(path, candidate, originalMode); err != nil {
		if restoreErr := atomicReplaceFile(path, original, originalMode); restoreErr != nil {
			return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: write failed (%v) AND rollback failed (%v); restore manually from backup %s", path, err, restoreErr, backupPath)
		}
		return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: write failed, rolled back to the original (backup at %s): %w", path, backupPath, err)
	}

	reopened, err := os.ReadFile(path)
	var reopenedRoot map[string]any
	if err == nil {
		err = yaml.Unmarshal(reopened, &reopenedRoot)
	}
	if err != nil || len(ValidateRosterV2(reopenedRoot)) != 0 {
		if restoreErr := atomicReplaceFile(path, original, originalMode); restoreErr != nil {
			return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: installed result failed re-validation AND rollback failed (%v); restore manually from backup %s", path, restoreErr, backupPath)
		}
		return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: installed result failed re-validation, rolled back to the original (backup at %s)", path, backupPath)
	}

	return RosterMigrationResult{
		FromVersion:    int(detected),
		ToVersion:      targetVersion,
		Changed:        true,
		BackupPath:     backupPath,
		OriginalSHA256: originalSHA,
		NewSHA256:      newSHA,
	}, nil
}

// migrateEncryptedRosterFile is MigrateRosterFile's branch for an
// ansible-vault-encrypted roster, following the migration spec's required
// encrypted-file flow:
//
//	decrypt into memory (ansibleVaultView; never a plaintext temp file)
//	    -> detect version (already-current is a no-op, same as plaintext)
//	    -> validate original as v1, migrate, validate candidate as v2,
//	       check the semantic fingerprint (identical to the plaintext path)
//	    -> write the candidate plaintext to a mode-0600 temp file
//	    -> ansible-vault encrypt that temp file in place
//	    -> atomically install the now-encrypted result
//
// original/originalMode/originalSHA are the still-encrypted bytes/mode/
// hash MigrateRosterFile already read before dispatching here, so the
// backup this creates is guaranteed to be the exact original ciphertext,
// never anything decrypted. Nothing this function returns, logs, or wraps
// into an error ever includes plaintext roster content or the vault
// password itself — only paths, exit statuses, and ansible-vault's own
// (non-secret) stderr text.
func migrateEncryptedRosterFile(path string, opts RosterMigrationOptions, original []byte, originalMode os.FileMode, originalSHA string, targetVersion int) (RosterMigrationResult, error) {
	plaintext, err := ansibleVaultView(path, opts.VaultPasswordFile)
	if err != nil {
		return RosterMigrationResult{}, fmt.Errorf("decrypt roster %s: %w", path, err)
	}

	detected, err := DetectRosterSchemaVersion(plaintext)
	if err != nil {
		return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: %w", path, err)
	}
	if int(detected) == targetVersion {
		return RosterMigrationResult{
			FromVersion:    int(detected),
			ToVersion:      targetVersion,
			Changed:        false,
			OriginalSHA256: originalSHA,
			NewSHA256:      originalSHA,
		}, nil
	}
	if detected != RosterSchemaV1 {
		return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: no migration path from schema v%d to v%d", path, detected, targetVersion)
	}

	var originalRoot map[string]any
	if err := yaml.Unmarshal(plaintext, &originalRoot); err != nil {
		return RosterMigrationResult{}, fmt.Errorf("parse roster %s: %w", path, err)
	}
	if v := ValidateRosterV1(originalRoot); len(v) != 0 {
		return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: original document fails schema v1 validation: %v", path, v)
	}

	plaintextNode := &yaml.Node{}
	if err := yaml.Unmarshal(plaintext, plaintextNode); err != nil {
		return RosterMigrationResult{}, fmt.Errorf("parse roster %s: %w", path, err)
	}
	migratedNode, err := MigrateRosterV1ToV2(plaintextNode)
	if err != nil {
		return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: %w", path, err)
	}
	candidatePlaintext, err := yaml.Marshal(migratedNode)
	if err != nil {
		return RosterMigrationResult{}, fmt.Errorf("render migrated roster %s: %w", path, err)
	}

	var candidateRoot map[string]any
	if err := yaml.Unmarshal(candidatePlaintext, &candidateRoot); err != nil {
		return RosterMigrationResult{}, fmt.Errorf("parse migrated roster %s: %w", path, err)
	}
	if v := ValidateRosterV2(candidateRoot); len(v) != 0 {
		return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: candidate fails schema v2 validation: %v", path, v)
	}
	before := ComputeRosterSemanticFingerprint(originalRoot)
	after := ComputeRosterSemanticFingerprint(candidateRoot)
	if !RosterSemanticFingerprintsEqual(before, after) {
		return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: candidate would change authorization-affecting content, refusing to migrate", path)
	}

	if opts.DryRun {
		return RosterMigrationResult{
			FromVersion:    int(detected),
			ToVersion:      targetVersion,
			Changed:        true,
			OriginalSHA256: originalSHA,
			// NewSHA256 deliberately omitted: ansible-vault salts each
			// encryption run independently, so re-encrypting the same
			// plaintext twice never produces the same ciphertext bytes —
			// unlike the plaintext path, a dry run has no way to predict
			// what NewSHA256 a real run would produce.
		}, nil
	}

	backupPath, err := createRosterBackup(path, original, detected, time.Now().UTC().Format("20060102T150405Z"))
	if err != nil {
		return RosterMigrationResult{}, fmt.Errorf("backup roster %s: %w", path, err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".migrate-*")
	if err != nil {
		return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: create temp file: %w", path, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // always clean up our own scratch file, success or failure
	if _, err := tmp.Write(candidatePlaintext); err != nil {
		tmp.Close()
		return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: write temp file: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: close temp file: %w", path, err)
	}

	if err := ansibleVaultEncryptInPlace(tmpPath, opts.VaultPasswordFile); err != nil {
		return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: encrypt candidate: %w (original untouched, backup at %s)", path, err, backupPath)
	}
	encryptedCandidate, err := os.ReadFile(tmpPath)
	if err != nil {
		return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: read encrypted candidate: %w (original untouched, backup at %s)", path, err, backupPath)
	}
	newSHA := sha256Hex(encryptedCandidate)

	if err := atomicReplaceFile(path, encryptedCandidate, originalMode); err != nil {
		if restoreErr := atomicReplaceFile(path, original, originalMode); restoreErr != nil {
			return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: write failed (%v) AND rollback failed (%v); restore manually from backup %s", path, err, restoreErr, backupPath)
		}
		return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: write failed, rolled back to the original (backup at %s): %w", path, backupPath, err)
	}

	reopened, err := os.ReadFile(path)
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(reopened)), "$ANSIBLE_VAULT") {
		if restoreErr := atomicReplaceFile(path, original, originalMode); restoreErr != nil {
			return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: installed result failed re-validation AND rollback failed (%v); restore manually from backup %s", path, restoreErr, backupPath)
		}
		return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: installed result failed re-validation (not ansible-vault encrypted), rolled back to the original (backup at %s)", path, backupPath)
	}
	reopenedPlaintext, err := ansibleVaultView(path, opts.VaultPasswordFile)
	if err != nil || len(ValidateRosterV2(mustYAMLMapOrNil(reopenedPlaintext))) != 0 {
		if restoreErr := atomicReplaceFile(path, original, originalMode); restoreErr != nil {
			return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: installed result failed re-validation AND rollback failed; restore manually from backup %s", path, backupPath)
		}
		return RosterMigrationResult{}, fmt.Errorf("migrate roster %s: installed result failed re-validation, rolled back to the original (backup at %s)", path, backupPath)
	}

	return RosterMigrationResult{
		FromVersion:    int(detected),
		ToVersion:      targetVersion,
		Changed:        true,
		BackupPath:     backupPath,
		OriginalSHA256: originalSHA,
		NewSHA256:      newSHA,
	}, nil
}

// mustYAMLMapOrNil parses data as a YAML mapping, returning nil (not an
// error) on failure — used only by migrateEncryptedRosterFile's final
// re-validation, where a parse failure and a validation failure should be
// handled identically (roll back).
func mustYAMLMapOrNil(data []byte) map[string]any {
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil
	}
	return root
}

// EnsureRosterCurrent is MigrateRosterFile's automatic-invocation
// counterpart: the one call every local mutating workflow that consumes a
// canonical roster should make before it does anything else — `pilot edit`
// roster entry, the MCP semantic roster driver (which drives the same TUI
// screens), `pilot deploy`/`pilot reconcile`'s preflight, and the NFS
// roster bootstrap/update paths. It always targets CurrentRosterSchemaVersion
// and never dry-runs, regardless of what opts says — the caller is about to
// proceed with the requested operation right after this returns, so
// "preview only" or "upgrade to some other version" don't make sense here.
// A no-op (already current) and a real migration both report success the
// same way MigrateRosterFile does; callers should surface
// result.Changed's backup path to the operator, but must never block the
// requested operation over a deterministic, validated, backed-up upgrade —
// see the roster-schema-v2 migration spec's "Do NOT ask for confirmation"
// requirement.
func EnsureRosterCurrent(path string, opts RosterMigrationOptions) (RosterMigrationResult, error) {
	opts.TargetVersion = int(CurrentRosterSchemaVersion)
	opts.DryRun = false
	return MigrateRosterFile(path, opts)
}

// createRosterBackup writes original's exact bytes to
// "<path>.v<fromVersion>.<timestamp>.<sha256 prefix>.bak", refusing to
// overwrite an existing backup (O_EXCL) and mode 0600 throughout — a
// roster can contain credentials, so this must never be more permissive
// than that, unlike cmd/edit_workspace_apply.go's restoreManagedFiles
// (0644), which exists for a different kind of managed file and is
// deliberately not reused here. timestamp is a parameter rather than
// computed internally so callers (and tests) control the exact backup
// filename instead of racing a clock.
func createRosterBackup(path string, original []byte, fromVersion RosterSchemaVersion, timestamp string) (string, error) {
	sum := sha256.Sum256(original)
	backupPath := fmt.Sprintf("%s.v%d.%s.%s.bak", path, fromVersion, timestamp, hex.EncodeToString(sum[:])[:8])

	f, err := os.OpenFile(backupPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("create backup %s: %w", backupPath, err)
	}
	defer f.Close()
	if _, err := f.Write(original); err != nil {
		return "", fmt.Errorf("write backup %s: %w", backupPath, err)
	}
	if err := f.Sync(); err != nil {
		return "", fmt.Errorf("sync backup %s: %w", backupPath, err)
	}
	return backupPath, nil
}

// atomicReplaceFile writes data into a same-directory temp file (mode
// 0600, per the atomic-replacement contract), fsyncs it, renames it over
// path, restores path's permissions to finalMode (the original roster's
// mode — the temp file's 0600 must not silently change what's actually
// installed), and fsyncs the parent directory so the rename itself is
// durable. Every failure path removes the temp file; a failure after the
// rename (restoring finalMode, syncing the directory) leaves path already
// replaced — MigrateRosterFile's own rollback covers that by re-invoking
// this function with the original bytes.
func atomicReplaceFile(path string, data []byte, finalMode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".migrate-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	cleanup = false

	if err := os.Chmod(path, finalMode); err != nil {
		return fmt.Errorf("restore roster mode: %w", err)
	}
	if dirFile, err := os.Open(dir); err == nil {
		_ = dirFile.Sync()
		dirFile.Close()
	}
	return nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
