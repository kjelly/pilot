// drift_vars_file.go resolves the vault vars file `pilot access drift`,
// `pilot identity drift` and `pilot access health` hand to the drift probe
// (issue #179). The probe takes the FreeIPA admin password vault-first, like
// freeipa-identity-apply.yml, so it needs the same `-e @<vault>` file apply
// gets; reading only the roster failed for a roster whose admin password is
// '{{ ipa_admin_password }}' or absent.
package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// driftVarsFileFlagHelp and driftVaultPasswordFlagHelp are shared by the three
// drift-probe commands so their --help stays identical.
const (
	driftVarsFileFlagHelp = "ansible vault vars file with ipa_admin_password, passed to the probe as -e @file " +
		"(default: <inventory dir>/.vault/main.yaml when it exists and can be read)"
	driftVaultPasswordFlagHelp = "ansible-vault password file, used for BOTH an encrypted roster and an encrypted vars file " +
		"(so they must share one vault password)"
)

// resolveDriftVarsFile returns the absolute vars file to pass to the drift
// probe, or "" for none.
//
// An explicit --vars-file is strict: it must exist, must not be a directory,
// and, when ansible-vault encrypted, needs --vault-password-file; each fails
// here, before any probe, instead of as an ansible stack trace, and the file is
// never silently replaced.
//
// Otherwise <inventory dir>/.vault/main.yaml is used when present (the
// convention pilot deploy follows) and its absence is fine: the probe falls
// back to the roster's own admin password. That auto-detected default is only
// ever a convenience, so it never fails the command: when it is encrypted and
// no --vault-password-file was given it is skipped with a one-line note on
// note (stderr), as before this flag existed, so a roster-literal user keeps
// working and `access health` still reports instead of erroring. The file's
// content is never read.
func resolveDriftVarsFile(note io.Writer, inventoryPath, explicit, vaultPasswordFile string) (string, error) {
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
	if err == nil && info.IsDir() {
		err = fmt.Errorf("%s is a directory, want a vars file", path)
	}
	if err != nil {
		if explicit == "" {
			fmt.Fprintf(note, "skipping %s: %v (pass --vars-file to use its ipa_admin_password)\n", abs, err)
			return "", nil
		}
		return "", fmt.Errorf("--vars-file %s: %w", path, err)
	}
	if isVaultEncrypted(abs) && vaultPasswordFile == "" {
		if explicit == "" {
			fmt.Fprintf(note, "skipping encrypted %s: pass --vault-password-file or --vars-file to use its ipa_admin_password\n", abs)
			return "", nil
		}
		return "", fmt.Errorf("%s is ansible-vault encrypted; pass --vault-password-file", abs)
	}
	return abs, nil
}
