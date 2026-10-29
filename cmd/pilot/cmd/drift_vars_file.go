// drift_vars_file.go resolves the vault vars file `pilot access drift`,
// `pilot identity drift` and `pilot access health` hand to the drift probe
// (issue #179). The probe takes the FreeIPA admin password vault-first, like
// freeipa-identity-apply.yml, so it needs the same `-e @<vault>` file apply
// gets; reading only the roster failed for a roster whose admin password is
// '{{ ipa_admin_password }}' or absent.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
)

// driftVarsFileFlagHelp and driftVaultPasswordFlagHelp are shared by the three
// drift-probe commands so their --help stays identical.
const (
	driftVarsFileFlagHelp = "ansible vault vars file with ipa_admin_password, passed to the probe as -e @file " +
		"(default: <inventory dir>/.vault/main.yaml when it exists)"
	driftVaultPasswordFlagHelp = "ansible-vault password file; decrypts an encrypted roster and an encrypted vars file"
)

// resolveDriftVarsFile returns the absolute vars file to pass to the drift
// probe, or "" for none. An explicit --vars-file must exist and is never
// silently replaced; otherwise <inventory dir>/.vault/main.yaml is used when
// present (the convention pilot deploy follows), and its absence is fine: the
// probe then falls back to the roster's own admin password. An encrypted vars
// file with no --vault-password-file fails here, before any probe, instead of
// as an ansible stack trace. The file's content is never read.
func resolveDriftVarsFile(inventoryPath, explicit, vaultPasswordFile string) (string, error) {
	path := explicit
	if path == "" {
		path = defaultVaultFile(inventoryPath)
		if path == "" {
			return "", nil
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve vars file %q: %w", path, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("--vars-file %s: %w", path, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("--vars-file %s is a directory, want a vars file", path)
	}
	if isVaultEncrypted(abs) && vaultPasswordFile == "" {
		return "", fmt.Errorf("%s is ansible-vault encrypted; pass --vault-password-file", abs)
	}
	return abs, nil
}
