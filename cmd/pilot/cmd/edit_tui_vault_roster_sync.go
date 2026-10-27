package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kjelly/pilot/internal/inventory"
)

// workspaceRosterPaths lists the canonical rosters dir points at: the
// roster editor's default path and every host's freeipa_roster_file in
// hosts.yml, resolved the way deploy resolves them. Only existing files
// are returned.
func workspaceRosterPaths(dir string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(path string) {
		path = filepath.Clean(path)
		if seen[path] {
			return
		}
		seen[path] = true
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			out = append(out, path)
		}
	}
	add(filepath.Join(dir, ".vault", "ipa-identity.yaml"))
	if data, err := os.ReadFile(filepath.Join(dir, "hosts.yml")); err == nil {
		if hf, err := inventory.Parse(data); err == nil {
			for _, h := range hf.Hosts {
				if path := strings.TrimSpace(h.Extra["freeipa_roster_file"]); path != "" {
					add(resolveRosterPath(dir, path))
				}
			}
		}
	}
	return out
}

// syncRosterAdminPasswords carries an ipa_admin_password change into every
// workspace roster that still holds the old password as its
// freeipa.admin.password (issue #146): `pilot access`, `pilot identity
// drift` and `pilot roster remove-*` authenticate with the roster's copy,
// and freeipa-nfs-server-apply.yml refuses a roster that disagrees with
// the vault. It returns one banner line per roster it updated or that
// needs the operator, and never prints a password.
func syncRosterAdminPasswords(dir, oldPassword, newPassword string) []string {
	var lines []string
	for _, path := range workspaceRosterPaths(dir) {
		result, err := mutateRosterSourceValue(dir, path, func() (inventory.RosterAdminSync, error) {
			return inventory.SyncRosterAdminPassword(path, oldPassword, newPassword)
		})
		// Banners are not wrapped: lead with the outcome and the shortest path.
		shown := path
		if rel, relErr := filepath.Rel(dir, path); relErr == nil && !strings.HasPrefix(rel, "..") {
			shown = rel
		}
		switch {
		case errors.Is(err, inventory.ErrRosterEncrypted):
			lines = append(lines, fmt.Sprintf("⚠️  未同步 %s：ansible-vault 加密檔，請用 ansible-vault edit 手動更新 freeipa.admin.password", shown))
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
