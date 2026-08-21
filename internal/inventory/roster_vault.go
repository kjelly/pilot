// roster_vault.go is the encrypted-roster half of v1 -> v2 migration: two
// thin wrappers around the real `ansible-vault` binary, following the same
// exec.LookPath("ansible-vault") resolution convention
// cmd/edit_tui_vault.go's interactive `ansible-vault edit` shellout already
// uses. See MigrateRosterFile's encrypted branch (roster_migrate_file.go)
// for how these fit into the full transaction.
package inventory

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ansibleVaultView decrypts path's ansible-vault-encrypted content into
// memory using vaultPasswordFile, without ever writing a plaintext file to
// disk. `ansible-vault view` (unlike `edit`, which opens a real editor
// against a temp file it creates itself) only ever reads path and prints
// the decrypted content to stdout — captured here via cmd.Output(), an
// in-memory pipe that is never logged, never written to a Writer, and
// never touches disk. Callers must not print or log the returned bytes.
func ansibleVaultView(path, vaultPasswordFile string) ([]byte, error) {
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
	tmp, err := os.CreateTemp("", ".pilot-roster-decrypt-*.yaml")
	if err != nil {
		return "", func() {}, fmt.Errorf("roster %s: create temp file: %w", path, err)
	}
	tmpPath := tmp.Name()
	cleanup = func() { os.Remove(tmpPath) }
	if _, err := tmp.Write(plaintext); err != nil {
		tmp.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("roster %s: write temp file: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("roster %s: close temp file: %w", path, err)
	}
	return tmpPath, cleanup, nil
}

// MutateEncryptedRosterFile decrypts the ansible-vault-encrypted roster
// at path into a secure temp plaintext file, runs mutate against that
// temp path, and — only if mutate returns nil — re-encrypts the temp
// file in place and atomically installs it over the original. On any
// failure (including mutate's own error) the original is left completely
// untouched and nothing is re-encrypted. This is the "prefer reusing the
// encrypted-roster mutation machinery already established by pilot
// roster migrate instead of inventing a second vault implementation"
// path spec.md §17 requires.
func MutateEncryptedRosterFile(path, vaultPasswordFile string, mutate func(plaintextPath string) error) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	tmpPath, cleanup, err := DecryptRosterToTempFile(path, vaultPasswordFile)
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
	if err := atomicReplaceFile(path, encrypted, info.Mode().Perm()); err != nil {
		return fmt.Errorf("roster %s: write failed, original untouched: %w", path, err)
	}
	return nil
}
