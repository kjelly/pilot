package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/kjelly/pilot/internal/inventory"
)

// rosterCandidates lists the canonical rosters dir's vault must agree
// with: the roster editor's default .vault/ipa-identity.yaml plus every
// referenced freeipa_roster_file, resolved against dir, existing files
// only, each once. pilot edit's sync and the deploy preflight's drift
// warning both start from it, so they consider the same rosters.
func rosterCandidates(dir string, referenced []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, path := range append([]string{filepath.Join(dir, ".vault", "ipa-identity.yaml")}, referenced...) {
		path = strings.TrimSpace(path)
		if path == "" || strings.Contains(path, "{{") {
			continue
		}
		path = filepath.Clean(resolveRosterPath(dir, path))
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		if seen[path] {
			continue
		}
		seen[path] = true
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			out = append(out, path)
		}
	}
	return out
}

// referencedRosterFiles returns every freeipa_roster_file dir sets, read
// without Ansible: in hosts.yml (fleet vars and hosts) and at the top of
// group_vars/ and host_vars/ files.
func referencedRosterFiles(dir string) []string {
	var out []string
	if data, err := os.ReadFile(filepath.Join(dir, "hosts.yml")); err == nil {
		if hf, err := inventory.Parse(data); err == nil {
			out = append(out, hf.Vars["freeipa_roster_file"])
			for _, h := range hf.Hosts {
				out = append(out, h.Extra["freeipa_roster_file"])
			}
		}
	}
	for _, sub := range []string{"group_vars", "host_vars"} {
		_ = filepath.WalkDir(filepath.Join(dir, sub), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !hasManagedFileExtension(d.Name()) {
				return nil
			}
			var vars map[string]any
			if data, err := os.ReadFile(path); err == nil && yaml.Unmarshal(data, &vars) == nil {
				if rosterPath, ok := vars["freeipa_roster_file"].(string); ok {
					out = append(out, rosterPath)
				}
			}
			return nil
		})
	}
	return out
}

// isManagedVaultFile reports whether path is one of dir's own .vault/*.yml
// or *.yaml files — the set managedFileEntries tracks, so the only rosters
// a plan copies into its scratch workspace and a failed apply restores.
// pilot edit never writes a roster outside it (an absolute
// freeipa_roster_file pointing elsewhere, ~/.vault/...): a plan would
// change the real file and a rolled-back apply would leave it changed
// (PR #148 review).
func isManagedVaultFile(dir, path string) bool {
	vaultDir, err := filepath.Abs(filepath.Join(dir, ".vault"))
	if err != nil {
		return false
	}
	if vaultDir, err = filepath.EvalSymlinks(vaultDir); err != nil {
		return false
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	return err == nil && parent == vaultDir && hasManagedFileExtension(filepath.Base(path))
}

// syncRosterAdminPasswords carries an ipa_admin_password change saved to
// vaultPath into every workspace roster that still holds the old password
// as its freeipa.admin.password (issue #146): `pilot access`, `pilot
// identity drift` and `pilot roster remove-*` authenticate with the
// roster's copy, and freeipa-nfs-server-apply.yml refuses a roster that
// disagrees with the vault. It returns one banner line per roster it
// updated or that needs the operator, and never prints a password.
//
// Only the workspace's default vault is a source: .vault/main.yaml is the
// file deploy loads (defaultVaultFile) and so the one the rosters must
// match. A roster holding the same old password as some other vault file
// is no proof that it uses that file, so such a save only says so.
func syncRosterAdminPasswords(dir, vaultPath, oldPassword, newPassword string) []string {
	if !sameExistingFile(vaultPath, filepath.Join(dir, ".vault", "main.yaml")) {
		return []string{"ℹ️  只有 .vault/main.yaml 會自動同步名冊；若名冊用這份 vault 的密碼，請手動更新 freeipa.admin.password"}
	}
	var lines []string
	for _, path := range rosterCandidates(dir, referencedRosterFiles(dir)) {
		// Banners are not wrapped: lead with the outcome and the shortest path.
		shown := path
		if rel, err := filepath.Rel(dir, path); err == nil && !strings.HasPrefix(rel, "..") {
			shown = rel
		}
		if !isManagedVaultFile(dir, path) {
			stale, err := mutateRosterSourceValue(dir, path, func() (bool, error) {
				return inventory.RosterAdminPasswordDiffers(path, newPassword)
			})
			if stale || errors.Is(err, inventory.ErrRosterEncrypted) {
				lines = append(lines, fmt.Sprintf("⚠️  未同步 %s：不在這個 workspace 的 .vault/ 下，請手動更新 freeipa.admin.password", shown))
			}
			continue
		}
		result, err := mutateRosterSourceValue(dir, path, func() (inventory.RosterAdminSync, error) {
			return inventory.SyncRosterAdminPassword(path, oldPassword, newPassword)
		})
		switch {
		case errors.Is(err, inventory.ErrRosterEncrypted):
			lines = append(lines, fmt.Sprintf("⚠️  未同步 %s：ansible-vault 加密，請用 ansible-vault 手動更新 freeipa.admin.password", shown))
		case err != nil:
			lines = append(lines, fmt.Sprintf("⚠️  未同步 %s：%v", shown, err))
		case result == inventory.RosterAdminUpdated:
			lines = append(lines, fmt.Sprintf("🔁 已同步 %s 的 freeipa.admin.password", shown))
		case result == inventory.RosterAdminDiffers:
			lines = append(lines, fmt.Sprintf("⚠️  未同步 %s：freeipa.admin.password 原本就跟 ipa_admin_password 不同，請手動確認", shown))
		}
	}
	return lines
}

// encryptedVaultSyncHint is the banner after `ansible-vault edit` of the
// workspace's default vault: pilot cannot see what changed in it, so it
// cannot keep the rosters in step either.
func encryptedVaultSyncHint(dir, path string) string {
	if !sameExistingFile(path, filepath.Join(dir, ".vault", "main.yaml")) {
		return ""
	}
	return "ℹ️  加密的 .vault/main.yaml 不會自動同步名冊；若改了 ipa_admin_password，請手動更新名冊的 freeipa.admin.password"
}

// sameExistingFile reports whether a and b name the same existing file,
// however each is spelled.
func sameExistingFile(a, b string) bool {
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	return err == nil && os.SameFile(ai, bi)
}
