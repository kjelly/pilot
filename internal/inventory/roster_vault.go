// roster_vault.go is the encrypted-roster half of v1 -> v2 migration: two
// thin wrappers around the real `ansible-vault` binary, following the same
// exec.LookPath("ansible-vault") resolution convention
// cmd/edit_tui_vault.go's interactive `ansible-vault edit` shellout already
// uses. See MigrateRosterFile's encrypted branch (roster_migrate_file.go)
// for how these fit into the full transaction.
package inventory

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"go.yaml.in/yaml/v3"
)

// ansibleVaultView decrypts path's ansible-vault-encrypted content into
// memory using vaultPasswordFile, without ever writing a plaintext file to
// disk. `ansible-vault view` (unlike `edit`, which opens a real editor
// against a temp file it creates itself) only ever reads path and prints
// the decrypted content to stdout — captured here via cmd.Output(), an
// in-memory pipe that is never logged, never written to a Writer, and
// never touches disk. Callers must not print or log the returned bytes.
func ansibleVaultView(path, vaultPasswordFile string) ([]byte, error) {
	if err := validateSecretSourceFile(path); err != nil {
		return nil, err
	}
	bin, err := exec.LookPath("ansible-vault")
	if err != nil {
		return nil, fmt.Errorf("ansible-vault not found on PATH: %w", err)
	}
	cmd := exec.Command(bin, "view", "--vault-password-file", vaultPasswordFile, path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ansible-vault view %s: %w: %s", path, err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// ansibleVaultEncryptInPlace encrypts path (an existing plaintext file) in
// place using vaultPasswordFile. There is no way to encrypt an arbitrary
// YAML document through the ansible-vault CLI without a real file for it
// to operate on, so the migration spec's encrypted flow is explicit about
// this shape: write the migrated plaintext to a mode-0600 temp file first
// (MigrateRosterFile does this), then call this on that temp file, then
// atomically install it — never call this on the live roster path itself.
func ansibleVaultEncryptInPlace(path, vaultPasswordFile string) error {
	bin, err := exec.LookPath("ansible-vault")
	if err != nil {
		return fmt.Errorf("ansible-vault not found on PATH: %w", err)
	}
	cmd := exec.Command(bin, "encrypt", "--vault-password-file", vaultPasswordFile, path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ansible-vault encrypt %s: %w: %s", path, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// DecryptRosterToTempFile decrypts the ansible-vault-encrypted roster at
// path into a fresh, mode-0600 temp plaintext file and returns its path
// plus a cleanup function the caller must always run (success or
// failure) to remove it. This is the read-only half of encrypted-roster
// support that `pilot roster remove-user`/`remove-group`'s Phase A-C
// (spec.md §16) run their local checks against — see
// MutateEncryptedRosterFile for the write half. Like ansibleVaultView,
// it never writes decrypted content to a predictable filename.
func DecryptRosterToTempFile(path, vaultPasswordFile string) (tempPath string, cleanup func(), err error) {
	plaintext, err := ansibleVaultView(path, vaultPasswordFile)
	if err != nil {
		return "", func() {}, fmt.Errorf("decrypt roster %s: %w", path, err)
	}
	tmpPath, cleanup, err := decryptedScratchFile(plaintext)
	if err != nil {
		return "", func() {}, fmt.Errorf("roster %s: write temp file: %w", path, err)
	}
	return tmpPath, cleanup, nil
}

// ViewEncryptedRoster decrypts the ansible-vault-encrypted roster at path
// into memory using vaultPasswordFile, without writing anything to disk
// — the exported counterpart of ansibleVaultView. Added for the outbound
// webhook's state projection builder (design spec §11.6), which needs a
// read-only, zero-temp-file decrypt path from outside this package,
// stricter than DecryptRosterToTempFile's ephemeral-but-real temp file.
func ViewEncryptedRoster(path, vaultPasswordFile string) ([]byte, error) {
	return ansibleVaultView(path, vaultPasswordFile)
}

// ReadRosterAsMapWithVault reads the roster at path as a plain map,
// transparently decrypting in memory via vaultPasswordFile when the file
// is ansible-vault-encrypted (ReadRosterAsMapFile alone returns
// ErrRosterEncrypted for those, and never touches vaultPasswordFile).
// vaultPasswordFile may be empty for a plaintext roster; passing it for
// an encrypted roster with no password file returns ErrRosterEncrypted
// unchanged, so callers can distinguish "no password available" from
// "decrypt failed" (design spec §11.6 point 4).
func ReadRosterAsMapWithVault(path, vaultPasswordFile string) (map[string]any, error) {
	root, err := readRosterAsMap(path)
	if err == nil {
		return root, nil
	}
	if !errors.Is(err, ErrRosterEncrypted) {
		return nil, err
	}
	if vaultPasswordFile == "" {
		return nil, err
	}
	plaintext, verr := ansibleVaultView(path, vaultPasswordFile)
	if verr != nil {
		return nil, fmt.Errorf("decrypt roster %s: %w", path, verr)
	}
	var out map[string]any
	if uerr := yaml.Unmarshal(plaintext, &out); uerr != nil {
		return nil, fmt.Errorf("parse decrypted roster %s: %w", path, uerr)
	}
	return out, nil
}

// MutateEncryptedRosterFile decrypts the ansible-vault-encrypted roster
// at path into a secure temp plaintext file, runs mutate against that
// temp path, and — only if mutate returns nil — re-encrypts the temp
// file in place and installs it over the original with writeLockedRoster.
// On any failure before that install (including mutate's own error) the
// original is left completely untouched; a failed install says itself
// whether it left the roster unchanged. The roster's lock is held from
// the decrypt to the install, so no other roster writer's change is lost
// in between, and the file path names is the one replaced: a symlinked
// roster stays a link. mutate must write only plaintextPath. This is the
// "prefer reusing the encrypted-roster mutation machinery already
// established by pilot roster migrate instead of inventing a second vault
// implementation" path spec.md §17 requires.
func MutateEncryptedRosterFile(path, vaultPasswordFile string, mutate func(plaintextPath string) error) error {
	lk, err := lockRosterFile(path)
	if err != nil {
		return err
	}
	defer lk.release() //nolint:errcheck

	tmpPath, cleanup, err := DecryptRosterToTempFile(lk.target, vaultPasswordFile)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := mutate(tmpPath); err != nil {
		return err
	}

	if err := ansibleVaultEncryptInPlace(tmpPath, vaultPasswordFile); err != nil {
		return fmt.Errorf("roster %s: encrypt candidate: %w (original untouched)", path, err)
	}
	encrypted, err := os.ReadFile(tmpPath)
	if err != nil {
		return fmt.Errorf("roster %s: read encrypted candidate: %w (original untouched)", path, err)
	}
	// writeLockedRoster's error says whether the roster was left unchanged.
	if err := writeLockedRoster(lk, encrypted); err != nil {
		return fmt.Errorf("roster %s: %w", path, err)
	}
	return nil
}
