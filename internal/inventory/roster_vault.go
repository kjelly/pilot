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
