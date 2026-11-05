// roster_vault.go is the encrypted-roster half of v1 -> v2 migration: two
// thin wrappers around the real `ansible-vault` binary, following the same
// exec.LookPath("ansible-vault") resolution convention
// cmd/edit_tui_vault.go's interactive `ansible-vault edit` shellout already
// uses. See MigrateRosterFile's encrypted branch (roster_migrate_file.go)
// for how these fit into the full transaction.
package inventory

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

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
// path into a fresh, mode-0600 temp plaintext file in its own private
// (0700) directory and returns its path plus a cleanup function the caller
// must always run (success or failure) to remove that directory. This is the read-only half of encrypted-roster
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

// ReadRosterPlaintext reads the roster at path once and returns its
// plaintext: the file's own bytes, or, when the file is ansible-vault
// encrypted, its content decrypted in memory with vaultPasswordFile
// (ansibleVaultView, the decryption planRosterMigration uses; never a
// plaintext file on disk). encrypted reports which. An encrypted roster
// with no vaultPasswordFile returns ErrRosterEncrypted unchanged;
// vaultPasswordFile is not read for a plaintext roster. It writes nothing
// and takes no lock. Callers must not print or log the plaintext.
func ReadRosterPlaintext(path, vaultPasswordFile string) (plaintext []byte, encrypted bool, err error) {
	data, err := readSecretSourceFile(path)
	if err != nil {
		return nil, false, err
	}
	if !strings.HasPrefix(strings.TrimSpace(string(data)), "$ANSIBLE_VAULT") {
		return data, false, nil
	}
	if vaultPasswordFile == "" {
		return nil, true, ErrRosterEncrypted
	}
	plaintext, err = ansibleVaultView(path, vaultPasswordFile)
	if err != nil {
		return nil, true, fmt.Errorf("decrypt roster %s: %w", path, err)
	}
	return plaintext, true, nil
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
// whether it left the roster unchanged or may have written part of it
// (errRosterPartlyWritten, an in-place install stopped part-way). The
// roster's lock is held from the decrypt to the install, so no other
// roster writer's change is lost in between, and the file path names is
// the one replaced: a symlinked roster stays a link. mutate must write
// only plaintextPath. This is the "prefer reusing the encrypted-roster
// mutation machinery already established by pilot roster migrate instead
// of inventing a second vault implementation" path spec.md §17 requires.
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

// ErrNoVaultSecret: ansible-vault found no vault secret — neither
// ANSIBLE_VAULT_PASSWORD_FILE nor ansible.cfg's vault_password_file —
// and, with no terminal and no input, could not prompt for one.
var ErrNoVaultSecret = errors.New("no vault secret is configured: set ANSIBLE_VAULT_PASSWORD_FILE or vault_password_file in ansible.cfg")

// ErrVaultDecryptFailed: the configured vault secret does not decrypt the
// file.
var ErrVaultDecryptFailed = errors.New("the configured vault secret does not decrypt the file")

// vaultViewWaitDelay bounds how long ViewVaultFileAmbient waits for
// ansible-vault's pipes to drain after it has exited or been killed: a
// helper it started (a vault password client script) may have inherited
// them and outlived it.
const vaultViewWaitDelay = 2 * time.Second

// ViewVaultFileAmbient decrypts the ansible-vault file at path into memory,
// finding the secret the way ansible-playbook does when pilot passes no
// --vault-password-file: ANSIBLE_VAULT_PASSWORD_FILE or ansible.cfg's
// vault_password_file, under env (added to this process's environment)
// and this process's working directory, as internal/ansible.Runner runs
// ansible-playbook.
//
// Without a secret ansible-vault prompts (captured: ansible-core 2.19.2).
// It prompts through Python's getpass, which opens the controlling
// terminal when there is one and reads stdin only when there is none; so
// closing stdin is not enough when pilot runs on a terminal: the prompt
// would go to the terminal and wait for a person. ansible-vault therefore
// runs in a new session (no controlling terminal) with no stdin: the prompt
// reads end-of-file and ends as ErrNoVaultSecret. A vault password client
// script that needs a terminal is unsupported and fails the same closed
// way.
//
// The read is bounded by ctx: when ctx ends, ansible-vault and every
// helper in its process group are killed and the error wraps ctx.Err().
func ViewVaultFileAmbient(ctx context.Context, path string, env []string) ([]byte, error) {
	if err := validateSecretSourceFile(path); err != nil {
		return nil, err
	}
	bin, err := exec.LookPath("ansible-vault")
	if err != nil {
		return nil, fmt.Errorf("ansible-vault not found on PATH: %w", err)
	}
	cmd := exec.CommandContext(ctx, bin, "view", path)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	// A new session: no controlling terminal to prompt on, and the process
	// group (the session's) holds ansible-vault and everything it starts.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = vaultViewWaitDelay
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("ansible-vault view %s: %w", path, ctxErr)
		}
		return nil, classifyVaultView(path, err, stderr.String())
	}
	return out, nil
}

// classifyVaultView names the two failures ansible-vault view reports
// (captured: testdata/ansible-vault-view-*.stderr).
func classifyVaultView(path string, err error, stderr string) error {
	switch {
	case strings.Contains(stderr, "EOFError"):
		return fmt.Errorf("ansible-vault view %s: %w", path, ErrNoVaultSecret)
	case strings.Contains(stderr, "Decryption failed"):
		return fmt.Errorf("ansible-vault view %s: %w", path, ErrVaultDecryptFailed)
	}
	return fmt.Errorf("ansible-vault view %s: %w: %s", path, err, strings.TrimSpace(stderr))
}
