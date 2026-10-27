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
	"github.com/kjelly/pilot/internal/secretpath"
)

// rosterCandidates lists the canonical rosters dir's vault must agree
// with: the roster editor's default .vault/ipa-identity.yaml plus every
// referenced freeipa_roster_file, resolved against dir, existing files
// only. Each file is listed once however many spellings name it (a link
// and its target, a relative and an absolute reference), under the first
// spelling inside dir's own .vault/ if there is one, so pilot edit's sync
// may write it. pilot edit's sync and the deploy preflight's drift warning
// both start from it, so they consider the same rosters.
//
// source is the real workspace when dir is a plan's scratch copy of it, ""
// otherwise. The copy holds every symlink as a plain file, so a file is
// identified by what its counterpart in source names (rosterIdentity): a
// .vault/ link and a reference to the file it points at are still one
// roster, as the apply sees them (PR #148 re-review).
func rosterCandidates(dir, source string, referenced []string) []string {
	index := map[string]int{}
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
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
			continue
		}
		file, err := rosterIdentity(dir, source, path)
		if err != nil {
			continue
		}
		if i, seen := index[file]; seen {
			if !isManagedVaultFile(dir, out[i]) && isManagedVaultFile(dir, path) {
				out[i] = path
			}
			continue
		}
		index[file] = len(out)
		out = append(out, path)
	}
	return out
}

// rosterIdentity is the canonical file path names, read through source for
// a path inside dir when dir is source's plan copy (rosterCandidates).
func rosterIdentity(dir, source, path string) (string, error) {
	if source != "" {
		if rel, err := filepath.Rel(dir, path); err == nil && !strings.HasPrefix(rel, "..") {
			return secretpath.Canonical(filepath.Join(source, rel))
		}
	}
	return secretpath.Canonical(path)
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
	vaultDir, err := secretpath.Canonical(filepath.Join(dir, ".vault"))
	if err != nil {
		return false
	}
	parent, err := secretpath.Canonical(filepath.Dir(path))
	return err == nil && parent == vaultDir && hasManagedFileExtension(filepath.Base(path))
}

// planScratchPath maps a freeipa_roster_file a plan's scratch copy
// inherited from source, the real workspace, onto the copy: pilot edit
// stores the reference as an absolute path into source's .vault/, so the
// copy's hosts.yml still names the real file, which a plan must leave
// alone while the apply writes it. Mapped onto the copy's own .vault/, a
// plan previews the roster writes the apply makes (PR #148 review). Any
// other path, and every path outside a plan (source ""), is kept.
func planScratchPath(dir, source, path string) string {
	resolved := resolveRosterPath(dir, strings.TrimSpace(path))
	if source == "" || resolved == "" || !isManagedVaultFile(source, resolved) {
		return path
	}
	return filepath.Join(dir, ".vault", filepath.Base(resolved))
}

// rosterSyncLine is one line pilot edit reports after a vault save: in the
// editor's banner as icon+text and, when manual (the operator must fix a
// roster pilot edit did not update), as a plan's or apply's warning.
type rosterSyncLine struct {
	icon, text string
	manual     bool
}

// rosterManualFix is the fix for a roster the sync did not update. pilot
// edit carries a password forward only on the save that changes it — a
// later save finds no change and syncs nothing — so it is a hand edit.
const rosterManualFix = "請手動把它的 freeipa.admin.password 改成 .vault/main.yaml 的 ipa_admin_password"

// rosterNotStringReason is why a roster whose password is a YAML number or
// boolean is left alone: Ansible compares typed values, so it never equals
// the vault's string, and only quoting it fixes that.
const rosterNotStringReason = "freeipa.admin.password 不是字串（例如沒加引號的數字），Ansible 比對時永遠不等於 vault 的字串，改的時候要加上引號"

// rosterSyncOnlyOnChange closes a report with any manual line.
var rosterSyncOnlyOnChange = rosterSyncLine{icon: "ℹ️  ", manual: true,
	text: "pilot edit 只在改變 ipa_admin_password 的這次存檔同步名冊，之後再存不會補；上面未同步的名冊請手動修改（加密名冊用 ansible-vault edit）"}

// rosterSyncAfterVaultSave is what pilot edit reports about the rosters
// after saving vaultPath from previous to saved: nothing unless the save
// changed ipa_admin_password. Only the workspace's default vault is a
// source: .vault/main.yaml is the file deploy loads (defaultVaultFile) and
// so the one the rosters must match. A roster holding the same old
// password as some other vault file is no proof that it uses that file,
// so such a save only says so; so does a new value Ansible would template
// (issue #146), since pilot cannot tell which password it resolves to.
// Lines never hold a password.
func rosterSyncAfterVaultSave(dir, planSource, vaultPath string, previous, saved []byte) []rosterSyncLine {
	oldPassword, newPassword := inventory.VaultAdminPassword(previous), inventory.VaultAdminPassword(saved)
	newTemplate := inventory.VaultAdminPasswordTemplate(saved)
	templated := newTemplate != "" && newTemplate != inventory.VaultAdminPasswordTemplate(previous)
	if !templated && (oldPassword == "" || newPassword == "" || oldPassword == newPassword) {
		return nil
	}
	if !sameExistingFile(vaultPath, filepath.Join(dir, ".vault", "main.yaml")) {
		return []rosterSyncLine{{icon: "ℹ️  ", manual: true,
			text: "只有 .vault/main.yaml 會自動同步名冊；若名冊用這份 vault 的密碼，請手動把名冊的 freeipa.admin.password 改成新值"}}
	}
	if templated {
		return []rosterSyncLine{{icon: "⚠️  ", manual: true,
			text: "未同步名冊：新的 ipa_admin_password 含 {{、{% 或 {#，Ansible 會當成模板展開，pilot 無法得知實際的密碼；請自行確認名冊的 freeipa.admin.password 跟它展開後的值相同"}}
	}
	return syncRosterAdminPasswords(dir, planSource, oldPassword, newPassword)
}

// syncRosterAdminPasswords carries an ipa_admin_password change saved to
// .vault/main.yaml into every workspace roster that still holds the old
// password as its freeipa.admin.password (issue #146): `pilot access`,
// `pilot identity drift` and `pilot roster remove-*` authenticate with the
// roster's copy, and freeipa-nfs-server-apply.yml refuses a roster that
// disagrees with the vault. It returns one line per roster it updated or
// that needs the operator, and never prints a password.
func syncRosterAdminPasswords(dir, planSource, oldPassword, newPassword string) []rosterSyncLine {
	referenced := referencedRosterFiles(dir)
	for i, path := range referenced {
		referenced[i] = planScratchPath(dir, planSource, path)
	}
	var lines []rosterSyncLine
	manual := func(shown, reason string) {
		lines = append(lines, rosterSyncLine{icon: "⚠️  ", manual: true,
			text: fmt.Sprintf("未同步 %s：%s；%s", shown, reason, rosterManualFix)})
	}
	for _, path := range rosterCandidates(dir, planSource, referenced) {
		shown := shownRosterPath(path, dir, planSource)
		if !isManagedVaultFile(dir, path) {
			stale, err := mutateRosterSourceValue(dir, path, func() (bool, error) {
				return inventory.RosterAdminPasswordDiffers(path, newPassword)
			})
			if stale || errors.Is(err, inventory.ErrRosterEncrypted) {
				manual(shown, "pilot edit 只改這個 workspace .vault/ 目錄裡的 *.yml、*.yaml（不含子目錄）")
			}
			continue
		}
		result, err := mutateRosterSourceValue(dir, path, func() (inventory.RosterAdminSync, error) {
			return inventory.SyncRosterAdminPassword(path, oldPassword, newPassword)
		})
		switch {
		case errors.Is(err, inventory.ErrRosterEncrypted):
			manual(shown, "ansible-vault 加密（用 ansible-vault edit）")
		case errors.Is(err, inventory.ErrMutationLocked):
			manual(shown, "另一個 pilot 名冊操作正鎖住它（等它結束）")
		case err != nil:
			manual(shown, rosterSyncReason(err, path, shown))
		case result == inventory.RosterAdminUpdated:
			lines = append(lines, rosterSyncLine{icon: "🔁 ", text: fmt.Sprintf("已同步 %s 的 freeipa.admin.password", shown)})
		case result == inventory.RosterAdminNotString:
			manual(shown, rosterNotStringReason)
		case result == inventory.RosterAdminDiffers:
			manual(shown, "freeipa.admin.password 原本就跟舊的 ipa_admin_password 不同，pilot 不知道它該用哪一個（請先確認）")
		}
	}
	for _, line := range lines {
		if line.manual {
			return append(lines, rosterSyncOnlyOnChange)
		}
	}
	return lines
}

// shownRosterPath is path relative to the workspace when it is inside it
// — the real workspace too, for a plan's scratch copy, so a plan and an
// apply name a roster alike — and absolute otherwise. Banners are not
// wrapped: they lead with the outcome and the shortest path.
func shownRosterPath(path string, workspaces ...string) string {
	for _, dir := range workspaces {
		if dir == "" {
			continue
		}
		if rel, err := filepath.Rel(dir, path); err == nil && !strings.HasPrefix(rel, "..") {
			return rel
		}
	}
	return path
}

// rosterSyncReason is SyncRosterAdminPassword's refusal as a banner reason:
// the roster under its shown name, without the path prefix and the closing
// "update ... by hand" the banner's own fix replaces.
func rosterSyncReason(err error, path, shown string) string {
	reason := strings.ReplaceAll(err.Error(), path, shown)
	reason = strings.TrimPrefix(reason, "roster "+shown+": ")
	for _, suffix := range []string{"; update freeipa.admin.password by hand", "; update it by hand"} {
		reason = strings.TrimSuffix(reason, suffix)
	}
	return reason
}

// encryptedVaultSyncHint is the banner after `ansible-vault edit` of the
// workspace's default vault: pilot cannot see what changed in it, so it
// cannot keep the rosters in step either.
func encryptedVaultSyncHint(dir, path string) string {
	if !sameExistingFile(path, filepath.Join(dir, ".vault", "main.yaml")) {
		return ""
	}
	return "ℹ️  加密的 .vault/main.yaml 不會自動同步名冊；若改了 ipa_admin_password，請手動把名冊的 freeipa.admin.password 改成新值（加密名冊用 ansible-vault edit）"
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
