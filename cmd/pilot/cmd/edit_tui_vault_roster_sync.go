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
		// Which file it is — inventory.RosterFileKey, so hard links of one
		// roster are one file as they are one lock: syncing them separately
		// would meet its own lock.
		key, err := rosterIdentityKey(dir, source, path)
		if err != nil {
			continue
		}
		// A link from elsewhere into .vault/ is listed under its .vault/
		// name, as a plan lists it (rosterWritePath), so both write it and
		// name it alike.
		root := dir
		if source != "" {
			root = source
		}
		if !isManagedVaultFile(dir, path) && isManagedVaultFile(root, file) {
			path = filepath.Join(dir, ".vault", filepath.Base(file))
		}
		if i, seen := index[key]; seen {
			if !isManagedVaultFile(dir, out[i]) && isManagedVaultFile(dir, path) {
				out[i] = path
			}
			continue
		}
		index[key] = len(out)
		out = append(out, path)
	}
	return out
}

// rosterIdentity is the canonical file path names, read through source for
// a path inside dir when dir is source's plan copy (rosterCandidates).
func rosterIdentity(dir, source, path string) (string, error) {
	return identityOf(dir, source, path, secretpath.Canonical)
}

// rosterIdentityKey is rosterIdentity's file as inventory.RosterFileKey
// names it: the canonical path, or one inode key for every hard link of a
// file.
func rosterIdentityKey(dir, source, path string) (string, error) {
	return identityOf(dir, source, path, inventory.RosterFileKey)
}

func identityOf(dir, source, path string, identity func(string) (string, error)) (string, error) {
	if source != "" {
		if rel, err := filepath.Rel(dir, path); err == nil && !strings.HasPrefix(rel, "..") {
			return identity(filepath.Join(source, rel))
		}
	}
	return identity(path)
}

// referencedRosterFiles returns every freeipa_roster_file dir sets, read
// without Ansible: in hosts.yml (fleet vars and hosts) and in
// group_vars/ and host_vars/ files, nested ones included.
//
// source is the real workspace when dir is a plan's scratch copy of it, ""
// otherwise. The copy holds only the files directly in group_vars/ and
// host_vars/ (managedFileEntries), so the nested ones are read from
// source, as the apply reads them; pilot edit never changes those.
func referencedRosterFiles(dir, source string) []string {
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
		for _, root := range []string{dir, source} {
			if root == "" {
				continue
			}
			_ = filepath.WalkDir(filepath.Join(root, sub), func(path string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() || !hasManagedFileExtension(d.Name()) {
					return nil
				}
				if root == source && filepath.Dir(path) == filepath.Join(source, sub) {
					return nil // the copy's own file, read above
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

// rosterWritePath is the file a freeipa_roster_file reference ref names
// for a write in scope: ref resolved against scope.dir, "" for an empty
// ref. On a plan's scratch copy ref means what it means to the apply, so
// it is resolved against the real workspace (planSource), relative or
// absolute: a file in the real .vault/ is mapped onto the copy's own
// .vault/, which the plan writes and diffs, so a plan previews the roster
// writes the apply makes (PR #148 review); any other file is the real one,
// which a plan only reads, or writes on a private copy (mutateRosterSource
// refuses it when that would change it). Resolved against the copy, a
// relative ref outside .vault/ named a file the copy does not have, so the
// plan took it for missing (PR #148 round 6, P2-2).
func (scope editWriteScope) rosterWritePath(ref string) string {
	ref = strings.TrimSpace(ref)
	if scope.planSource == "" || ref == "" {
		return resolveRosterPath(scope.dir, ref)
	}
	real := resolveRosterPath(scope.planSource, ref)
	if vault := vaultSpelling(scope.planSource, real); vault != "" {
		return filepath.Join(scope.dir, ".vault", filepath.Base(vault))
	}
	return real
}

// vaultSpelling is path's name among dir's own .vault/ files: path itself
// when it is spelled inside .vault/ (a link there to elsewhere included),
// the file it names when it is a symlink from elsewhere into .vault/, and
// "" for anything else. Such a file is one of the session's: a plan's copy
// holds it and an apply's rollback restores it, however it is reached.
func vaultSpelling(dir, path string) string {
	if isManagedVaultFile(dir, path) {
		return path
	}
	if target, err := secretpath.Canonical(path); err == nil && target != path && isManagedVaultFile(dir, target) {
		return target
	}
	return ""
}

// recordedPath is the absolute path pilot edit records in hosts.yml for
// rel, a path inside the workspace: inside scope.dir, except on a plan's
// scratch copy, where it is the real workspace's path, the one the apply
// records (a plan's diff must not name its scratch directory).
func (scope editWriteScope) recordedPath(rel string) (string, error) {
	base := scope.dir
	if scope.planSource != "" {
		base = scope.planSource
	}
	return filepath.Abs(filepath.Join(base, rel))
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

// rosterNotStringReason is why a roster whose password a YAML loader may
// read as a number, date or boolean is left alone: a typed comparison
// then never finds it equal to the vault's string, and only quoting it
// settles that.
const rosterNotStringReason = "freeipa.admin.password 沒加引號，YAML 可能把它讀成數字、日期或布林值而不是字串，跟 vault 的比對會不相等；改的時候要加上引號"

// rosterSyncOnlyOnChange closes a report with any manual line.
var rosterSyncOnlyOnChange = rosterSyncLine{icon: "ℹ️  ", manual: true,
	text: "pilot edit 只在改變 ipa_admin_password 的這次存檔同步名冊，之後再存不會補；上面未同步的名冊請手動修改（加密名冊用 ansible-vault edit）"}

// vaultRosterSync is a vault save's roster sync, prepared before the save
// writes the vault (prepareVaultRosterSync) and committed after it.
type vaultRosterSync struct {
	steps []vaultRosterStep
	// onlyOnChange closes the report with rosterSyncOnlyOnChange when
	// any of its lines needs the operator.
	onlyOnChange bool
}

// vaultRosterStep is one line of the save's report: line as it stands, or
// — for a roster the save will update — the prepared write, whose line
// commit decides.
type vaultRosterStep struct {
	line        rosterSyncLine
	path, shown string
	prepared    *inventory.PreparedRosterAdminSync
}

// release drops every prepared roster's lock without writing.
func (s *vaultRosterSync) release() {
	for _, step := range s.steps {
		if step.prepared != nil {
			step.prepared.Release()
		}
	}
}

// commit writes every prepared roster, once the vault is saved, and
// returns the report. A roster whose write fails now is a line for the
// operator: the vault is already saved.
func (s *vaultRosterSync) commit() []rosterSyncLine {
	var lines []rosterSyncLine
	manual := false
	for _, step := range s.steps {
		line := step.line
		if step.prepared != nil {
			if err := step.prepared.Commit(); err != nil {
				line = manualRosterLine(step.shown, rosterSyncReason(err, step.path, step.shown))
			} else {
				line = rosterSyncLine{icon: "🔁 ", text: fmt.Sprintf("已同步 %s 的 freeipa.admin.password", step.shown)}
			}
		}
		manual = manual || line.manual
		lines = append(lines, line)
	}
	if manual && s.onlyOnChange {
		lines = append(lines, rosterSyncOnlyOnChange)
	}
	return lines
}

func manualRosterLine(shown, reason string) rosterSyncLine {
	return rosterSyncLine{icon: "⚠️  ", manual: true,
		text: fmt.Sprintf("未同步 %s：%s；%s", shown, reason, rosterManualFix)}
}

// prepareVaultRosterSync prepares what saving vaultPath from previous to
// saved does to the rosters, before the save writes anything: nothing
// unless the save changes ipa_admin_password. Only the workspace's default
// vault is a source: .vault/main.yaml is the file deploy loads
// (defaultVaultFile) and so the one the rosters must match. A roster
// holding the same old password as some other vault file is no proof that
// it uses that file, so such a save only says so; so does a new value
// Ansible would template (issue #146), since pilot cannot tell which
// password it resolves to. Lines never hold a password.
//
// Every workspace roster that must follow the new password is locked and
// its change decided (inventory.PrepareRosterAdminSync), so the save
// writes the vault only once all of them can follow, and then commits
// them. A roster another pilot process holds, or whose lock file cannot be
// used, refuses the save (refused): nothing is written, rosterBusyBanner
// records the refusal on r — automation fails the step, plan and apply
// included — and the terminal stays in the editor with the edit unsaved,
// so saving again once the roster is free carries the password forward.
func prepareVaultRosterSync(r *editRouterModel, dir, vaultPath string, previous, saved []byte) (sync *vaultRosterSync, refused string) {
	sync = &vaultRosterSync{}
	fixed := func(icon, text string) *vaultRosterSync {
		sync.steps = []vaultRosterStep{{line: rosterSyncLine{icon: icon, manual: true, text: text}}}
		return sync
	}
	if inventory.VaultAdminPasswordText(previous) == inventory.VaultAdminPasswordText(saved) {
		return sync, ""
	}
	oldPassword, newPassword := inventory.VaultAdminPassword(previous), inventory.VaultAdminPassword(saved)
	templated := inventory.VaultAdminPasswordTemplate(saved) != ""
	// Each message is judged on the value it is about: what to do with the
	// saved value on the saved value, what pilot cannot know about the
	// old one on the old one (PR #148 round 6, P3-6: an old unquoted
	// value replaced by a quoted one was told to add quotes).
	notString := inventory.VaultAdminPasswordNotString(saved)
	// A value replaced (not added or removed) whose old or new form pilot
	// cannot read — an inline !vault value, an old template, an old value
	// a YAML loader may read as a number or date — leaves pilot unable to
	// tell which rosters held the old password (PR #148 round 5, P3-c).
	replaced := inventory.VaultAdminPasswordText(previous) != "" && inventory.VaultAdminPasswordText(saved) != ""
	encrypted := replaced && (inventory.VaultAdminPasswordEncrypted(previous) || inventory.VaultAdminPasswordEncrypted(saved))
	oldTemplated := replaced && inventory.VaultAdminPasswordTemplate(previous) != ""
	oldNotString := replaced && inventory.VaultAdminPasswordNotString(previous)
	if !templated && !notString && !encrypted && !oldTemplated && !oldNotString && (oldPassword == "" || newPassword == "") {
		return sync, ""
	}
	if !sameExistingFile(vaultPath, filepath.Join(dir, ".vault", "main.yaml")) {
		return fixed("ℹ️  ", "只有 .vault/main.yaml 會自動同步名冊；若名冊用這份 vault 的密碼，請手動把名冊的 freeipa.admin.password 改成新值"), ""
	}
	if templated {
		return fixed("⚠️  ", "未同步名冊：新的 ipa_admin_password 含 {{、{% 或 {#，Ansible 會當成模板展開，pilot 無法得知實際的密碼；請自行確認名冊的 freeipa.admin.password 跟它展開後的值相同"), ""
	}
	if notString {
		return fixed("⚠️  ", "未同步名冊：ipa_admin_password 沒加引號，YAML 可能把它讀成數字、日期或布林值；請把它加上引號，並手動把名冊的 freeipa.admin.password 改成同一個加引號的值"), ""
	}
	if encrypted {
		return fixed("⚠️  ", "未同步名冊：ipa_admin_password 原本或現在是 !vault 加密值，pilot 讀不到它，無法判斷哪些名冊用的是舊密碼；請手動確認每份名冊的 freeipa.admin.password 跟新的 ipa_admin_password 相同"), ""
	}
	if oldTemplated {
		return fixed("⚠️  ", "未同步名冊：原本的 ipa_admin_password 含 {{、{% 或 {#，Ansible 會把它當成模板展開，pilot 不知道舊密碼是什麼，無法判斷哪些名冊用的是它；請手動確認每份名冊的 freeipa.admin.password 跟新的 ipa_admin_password 相同"), ""
	}
	if oldNotString {
		return fixed("⚠️  ", "未同步名冊：原本的 ipa_admin_password 沒加引號，YAML 可能把它讀成數字、日期或布林值，pilot 無法判斷哪些名冊用的是它；新的值已存成加引號的字串，請手動確認每份名冊的 freeipa.admin.password 跟它相同（同樣加上引號）"), ""
	}
	return prepareRosterAdminPasswords(r, dir, oldPassword, newPassword)
}

// prepareRosterAdminPasswords prepares carrying an ipa_admin_password
// change saved to .vault/main.yaml into every workspace roster that still
// holds the old password as its freeipa.admin.password (issue #146):
// `pilot access`, `pilot identity drift` and `pilot roster remove-*`
// authenticate with the roster's copy, and freeipa-nfs-server-apply.yml
// refuses a roster that disagrees with the vault. It reports one line per
// roster it will update or that needs the operator, and refuses the save
// on a busy roster (prepareVaultRosterSync).
func prepareRosterAdminPasswords(r *editRouterModel, dir, oldPassword, newPassword string) (*vaultRosterSync, string) {
	scope := r.writeScope(dir)
	referenced := referencedRosterFiles(dir, scope.planSource)
	for i, path := range referenced {
		referenced[i] = scope.rosterWritePath(path)
	}
	sync := &vaultRosterSync{onlyOnChange: true}
	manual := func(shown, reason string) {
		sync.steps = append(sync.steps, vaultRosterStep{line: manualRosterLine(shown, reason)})
	}
	for _, path := range rosterCandidates(dir, scope.planSource, referenced) {
		shown := shownRosterPath(path, dir, scope.planSource)
		if !isManagedVaultFile(dir, path) {
			// Only read: pilot edit's sync never writes a roster outside
			// .vault/. A path the workspace may not use is skipped, as before.
			if validateSecretSourcePath(dir, path) != nil {
				continue
			}
			stale, err := inventory.RosterAdminPasswordDiffers(path, newPassword)
			if stale || errors.Is(err, inventory.ErrRosterEncrypted) {
				manual(shown, "pilot edit 只改這個 workspace .vault/ 目錄裡的 *.yml、*.yaml（不含子目錄）")
			}
			continue
		}
		prepared, err := mutateRosterSourceValue(scope, path, func(path string) (*inventory.PreparedRosterAdminSync, error) {
			return inventory.PrepareRosterAdminSync(path, oldPassword, newPassword)
		})
		if err == nil && prepared.Result == inventory.RosterAdminUpdated && scope.planSource != "" {
			// A plan writes its scratch copy, which no other process locks
			// and which is always writable; the apply locks and writes the
			// real roster, so the plan probes it to fail where the apply
			// would.
			real, rerr := rosterIdentity(dir, scope.planSource, path)
			if rerr == nil {
				rerr = inventory.ProbeRosterWrite(real)
			}
			if rerr != nil {
				prepared.Release()
				err = rerr
			}
		}
		switch {
		case errors.Is(err, inventory.ErrRosterEncrypted):
			manual(shown, "ansible-vault 加密（用 ansible-vault edit）")
		case errors.Is(err, inventory.ErrRosterNeedsHandEdit):
			manual(shown, rosterSyncReason(err, path, shown))
		case err != nil:
			// Fail closed: any other error means this roster must follow
			// the new password but cannot be written now — locked, an
			// unusable lock file, not writable, … — so the save is refused
			// rather than leaving it on the old password (PR #148 round 6,
			// P2-1).
			sync.release()
			return nil, rosterRefusal(r, shown, err)
		case prepared.Result == inventory.RosterAdminUpdated:
			sync.steps = append(sync.steps, vaultRosterStep{path: path, shown: shown, prepared: prepared})
		case prepared.Result == inventory.RosterAdminNotString:
			manual(shown, rosterNotStringReason)
		case prepared.Result == inventory.RosterAdminDiffers:
			manual(shown, "freeipa.admin.password 原本就跟舊的 ipa_admin_password 不同，pilot 不知道它該用哪一個（請先確認）")
		}
	}
	return sync, ""
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
