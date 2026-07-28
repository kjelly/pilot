// edit_tui_roster.go implements the roster screens of the `pilot edit`
// router (edit_tui.go): a manager for the canonical FreeIPA-identity
// roster file covering users and groups — add, full-detail preview, and
// per-field edit (scalars, membership, password/SSH keys). Every write
// goes through internal/inventory.Simulate{Add,Set}Roster{User,Group}
// first (mirroring freeipa-identity-apply.yml's own "Gate: canonical ..."
// assert chain) so a mistake is caught before it ever touches disk, then
// Append/SetRoster{User,Group} persists via yaml.Node surgery — never a
// full-struct remarshal, so no comment or section this wizard doesn't
// know about is disturbed. SetRosterUser/Group's own doc comment covers
// the two trade-offs specific to editing (vs. only ever appending): field
// order normalizes to alphabetical, and an edited entry's own inline
// comment/anchor (if any) is lost.
//
// Deliberately still out of scope: delete (state: absent for either
// entity — a declarative removal request out of this wizard's reach on
// purpose), and sudo/nfs_clients/migration. Host access (hostgroups and
// HBAC) is edited by the separate relationship editor. A user/group's name and a group's category are shown
// read-only in the detail screen — both are referenced by name elsewhere
// (hbac/sudo/membership), so renaming here would silently orphan those
// references.
package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/vaultfile"
)

func pushRosterPathPrompt(r *editRouterModel, dir string) tea.Cmd {
	def := filepath.Join(dir, ".vault", "ipa-identity.yaml")
	return r.transitionTo(newTextInputModel("Roster 檔路徑(canonical FreeIPA roster)", def, nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushTopMenu(r, dir, "")
		}
		return pushRosterManager(r, dir, strings.TrimSpace(m.Value()), "")
	})
}

func pushRosterManager(r *editRouterModel, dir, path, banner string) tea.Cmd {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			// A missing roster on first visit to a fresh workspace is
			// entirely foreseeable — offer to auto-generate the minimal
			// skeleton instead of killing the whole `pilot edit` session
			// over it (r.err would do exactly that, see
			// editRouterModel.Update's `r.err != nil` branch).
			return pushRosterCreateConfirm(r, dir, path)
		}
		r.err = fmt.Errorf("stat %s: %w", path, err)
		return nil
	}

	items := []string{"👤 Users", "👥 Groups", "🔐 Host access", "↩  返回"}
	title := fmt.Sprintf("管理 %s", path)
	return r.transitionTo(newSelectModel(title, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			// mirrors the trailing "↩ 返回" item.
			return pushTopMenu(r, dir, "")
		}
		switch m.Selected() {
		case 0:
			return pushRosterUsersMenu(r, dir, path, "")
		case 1:
			return pushRosterGroupsMenu(r, dir, path, "")
		case 2:
			return pushRosterHostAccessMenu(r, dir, path, "")
		case 3:
			return pushTopMenu(r, dir, "")
		}
		return nil
	})
}

// pushRosterCreateConfirm offers to auto-generate the smallest canonical
// roster skeleton when path doesn't exist yet — the same recoverable
// posture as pushVaultOpen's "不存在，要建立新的明文 vault 檔嗎？" confirm.
func pushRosterCreateConfirm(r *editRouterModel, dir, path string) tea.Cmd {
	question := fmt.Sprintf("%s 不存在，要建立最小 roster 骨架嗎？", path)
	return r.transitionTo(newConfirmModel(question, true), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(confirmModel)
		if !m.Value() {
			return pushTopMenu(r, dir, "")
		}
		return pushRosterCreatePrompt(r, dir, path)
	})
}

// pushRosterCreatePrompt supplies the one value WriteMinimalRosterSkeleton
// can't derive safely — the FreeIPA admin password — reusing
// .vault/main.yaml's ipa_admin_password when a real one is already there
// (existingFreeIPAAdminPassword) instead of making the operator retype a
// password this workspace already has on file (e.g. from an earlier NFS
// role bootstrap or roster creation). Only prompts when no reusable value
// exists — same widget/validation as pushNFSRoleBootstrap's own prompt.
func pushRosterCreatePrompt(r *editRouterModel, dir, path string) tea.Cmd {
	if existing := existingFreeIPAAdminPassword(dir); existing != "" {
		return pushRosterCreateWithPassword(r, dir, path, existing,
			"（沿用 .vault/main.yaml 現有的 ipa_admin_password，不用重新輸入）")
	}
	validate := func(value string) error {
		if len([]rune(value)) < 8 {
			return fmt.Errorf("FreeIPA admin password 至少需要 8 個字元")
		}
		return nil
	}
	return r.transitionTo(newSecretTextInputModel("FreeIPA admin password(不會顯示；至少 8 字元)", "", validate), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushTopMenu(r, dir, "")
		}
		return pushRosterCreateWithPassword(r, dir, path, m.Value(), "")
	})
}

// pushRosterCreateWithPassword writes the minimal roster skeleton plus
// keeps .vault/main.yaml's ipa_admin_password in sync, however password
// was obtained (typed fresh or reused) — the shared commit point for
// pushRosterCreatePrompt's two branches.
func pushRosterCreateWithPassword(r *editRouterModel, dir, path, password, extraNote string) tea.Cmd {
	domain := nfsBootstrapDomain(dir)
	if err := inventory.WriteMinimalRosterSkeleton(path, domain, "admin", password); err != nil {
		r.err = err
		return nil
	}

	vaultPath := filepath.Join(dir, ".vault", "main.yaml")
	vaultNote := ""
	if _, statErr := os.Stat(vaultPath); os.IsNotExist(statErr) {
		if vaultErr := inventory.WriteMinimalFreeIPAVault(vaultPath, password); vaultErr != nil {
			r.err = vaultErr
			return nil
		}
		vaultNote = fmt.Sprintf("；並建立 %s 的 ipa_admin_password", vaultPath)
	} else if statErr == nil {
		changed, vaultErr := inventory.FillFreeIPAAdminPassword(vaultPath, password)
		if vaultErr != nil {
			r.err = vaultErr
			return nil
		}
		if changed {
			vaultNote = fmt.Sprintf("；並填入 %s 的 ipa_admin_password", vaultPath)
		}
	}
	return pushRosterManager(r, dir, path, fmt.Sprintf("✅ 已建立最小 roster 骨架 %s%s%s", path, vaultNote, extraNote))
}

// existingFreeIPAAdminPassword reads .vault/main.yaml's ipa_admin_password
// when it's a genuine, already-filled value — not missing, not still
// CHANGE-ME, and not sitting inside an ansible-vault-encrypted file this
// process has no password to open. Every flow that would otherwise make
// the operator type the FreeIPA admin password again (roster creation,
// NFS role bootstrap) checks this first, since a workspace that already
// went through one of those flows already has it on file.
func existingFreeIPAAdminPassword(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, ".vault", "main.yaml"))
	if err != nil || isAnsibleVaultEncrypted(data) {
		return ""
	}
	doc, err := vaultfile.Parse(data)
	if err != nil {
		return ""
	}
	for _, e := range doc.Entries() {
		if e.Key != "ipa_admin_password" {
			continue
		}
		v := e.Value.Value
		if v == "" || v == "CHANGE-ME" || v == "CHANGE-ME-min-8-chars" {
			return ""
		}
		return v
	}
	return ""
}

func pushRosterUsersMenu(r *editRouterModel, dir, path, banner string) tea.Cmd {
	names, err := inventory.RosterUserNames(path)
	if err != nil {
		if errors.Is(err, inventory.ErrRosterEncrypted) {
			return pushRosterManager(r, dir, path, "⚠️  roster 已加密，無法在這裡預覽/編輯 users；請先 ansible-vault decrypt 或改用文字編輯器")
		}
		r.err = fmt.Errorf("read %s: %w", path, err)
		return nil
	}

	note := "目前沒有任何 user。"
	if len(names) > 0 {
		note = "選一個查看/編輯欄位，或新增一個。"
	}
	if banner == "" {
		banner = note
	} else {
		banner += "\n" + note
	}

	items := make([]string, 0, len(names)+2)
	for _, n := range names {
		items = append(items, "👤 "+n)
	}
	items = append(items, "➕ 新增 User", "↩  返回")

	return r.transitionTo(newSelectModel(fmt.Sprintf("Users — %s", path), items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			// mirrors "↩ 返回".
			return pushRosterManager(r, dir, path, "")
		}
		switch {
		case m.Selected() < len(names):
			return pushRosterUserDetail(r, dir, path, names[m.Selected()], "")
		case m.Selected() == len(names):
			return pushRosterAddUser(r, dir, path)
		default:
			return pushRosterManager(r, dir, path, "")
		}
	})
}

func pushRosterAddUser(r *editRouterModel, dir, path string) tea.Cmd {
	validate := func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}
	return r.transitionTo(newTextInputModel("新 user 的名稱(小寫英數字/底線/點/連字號)", "", validate), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushRosterUsersMenu(r, dir, path, "")
		}
		name := strings.TrimSpace(m.Value())
		violations, err := inventory.SimulateAddRosterUser(path, name)
		if err != nil {
			r.err = fmt.Errorf("%s: %w", path, err)
			return nil
		}
		if len(violations) > 0 {
			return pushRosterUsersMenu(r, dir, path, formatRosterViolations(violations))
		}
		if err := inventory.AppendRosterUser(path, name); err != nil {
			r.err = fmt.Errorf("write %s: %w", path, err)
			return nil
		}
		return pushRosterUsersMenu(r, dir, path, fmt.Sprintf(
			"✅ 已新增 user %s；選這個 user 可繼續編輯 email/ssh key/密碼等欄位。", name))
	})
}

func pushRosterGroupsMenu(r *editRouterModel, dir, path, banner string) tea.Cmd {
	names, err := inventory.RosterGroupNames(path)
	if err != nil {
		if errors.Is(err, inventory.ErrRosterEncrypted) {
			return pushRosterManager(r, dir, path, "⚠️  roster 已加密，無法在這裡預覽/編輯 groups；請先 ansible-vault decrypt 或改用文字編輯器")
		}
		r.err = fmt.Errorf("read %s: %w", path, err)
		return nil
	}

	note := "目前沒有任何 group。"
	if len(names) > 0 {
		note = "選一個查看/編輯欄位，或新增一個。"
	}
	if banner == "" {
		banner = note
	} else {
		banner += "\n" + note
	}

	items := make([]string, 0, len(names)+2)
	for _, n := range names {
		items = append(items, "👥 "+n)
	}
	items = append(items, "➕ 新增 Group", "↩  返回")

	return r.transitionTo(newSelectModel(fmt.Sprintf("Groups — %s", path), items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			// mirrors "↩ 返回".
			return pushRosterManager(r, dir, path, "")
		}
		switch {
		case m.Selected() < len(names):
			return pushRosterGroupDetail(r, dir, path, names[m.Selected()], "")
		case m.Selected() == len(names):
			return pushRosterAddGroupCategory(r, dir, path)
		default:
			return pushRosterManager(r, dir, path, "")
		}
	})
}

// rosterGroupCategories pairs each canonical group category with the name
// prefix freeipa-identity-apply.yml's "Gate: canonical group objects and
// category prefixes are valid" requires — kept in sync by hand with
// internal/inventory/roster_validate.go's groupCategoryPrefix (unexported,
// so duplicated here rather than shared).
var rosterGroupCategories = []struct {
	Category, Label string
}{
	{"team", "team-*(團隊/team)"},
	{"filesystem", "data-*(檔案系統存取/filesystem)"},
	{"access", "access-*(存取權限/access，給 HBAC 用)"},
	{"role", "role-*(職務角色/role，給 sudo 用)"},
}

func pushRosterAddGroupCategory(r *editRouterModel, dir, path string) tea.Cmd {
	items := make([]string, 0, len(rosterGroupCategories)+1)
	for _, c := range rosterGroupCategories {
		items = append(items, c.Label)
	}
	items = append(items, "↩  返回")
	return r.transitionTo(newSelectModel("新 group 的分類(決定名稱前綴規則)", items), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			// mirrors "↩ 返回".
			return pushRosterGroupsMenu(r, dir, path, "")
		}
		idx := m.Selected()
		if idx == len(items)-1 {
			return pushRosterGroupsMenu(r, dir, path, "")
		}
		return pushRosterAddGroupName(r, dir, path, rosterGroupCategories[idx].Category)
	})
}

func pushRosterAddGroupName(r *editRouterModel, dir, path, category string) tea.Cmd {
	validate := func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}
	label := fmt.Sprintf("新 group 的名稱(category=%s，記得帶前綴)", category)
	return r.transitionTo(newTextInputModel(label, "", validate), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushRosterAddGroupCategory(r, dir, path)
		}
		name := strings.TrimSpace(m.Value())
		violations, err := inventory.SimulateAddRosterGroup(path, name, category)
		if err != nil {
			r.err = fmt.Errorf("%s: %w", path, err)
			return nil
		}
		if len(violations) > 0 {
			return pushRosterGroupsMenu(r, dir, path, formatRosterViolations(violations))
		}
		if err := inventory.AppendRosterGroup(path, name, category); err != nil {
			r.err = fmt.Errorf("write %s: %w", path, err)
			return nil
		}
		return pushRosterGroupsMenu(r, dir, path, fmt.Sprintf(
			"✅ 已新增 group %s(category=%s)；選這個 group 可繼續編輯 membership 等欄位。", name, category))
	})
}

func formatRosterViolations(violations []inventory.RosterViolation) string {
	lines := make([]string, 0, len(violations)+1)
	lines = append(lines, fmt.Sprintf("⚠️  驗證沒過，尚未寫入(%d 項)：", len(violations)))
	for _, v := range violations {
		lines = append(lines, "  - "+v.String())
	}
	return strings.Join(lines, "\n")
}

// ---- shared field-map helpers -----------------------------------------
//
// Every field-edit widget below starts from RosterUser/RosterGroup's full
// field map, mutates the one field it owns on a clone, and hands the whole
// clone to SimulateSetRosterUser/Group — since the roster schema is closed
// (roster_validate.go's unknownKeys checks reject anything else), a full
// round-trip never silently drops a field this wizard has no widget for.

// cloneRosterFields returns a shallow copy of fields.
func cloneRosterFields(fields map[string]any) map[string]any {
	out := make(map[string]any, len(fields))
	for k, v := range fields {
		out[k] = v
	}
	return out
}

// rosterSubmap reads a nested map field (password/ssh_keys/membership),
// defaulting to an empty map when absent — display-only; see
// rosterSubmapClone for the mutate-and-write-back counterpart.
func rosterSubmap(fields map[string]any, key string) map[string]any {
	if sub, ok := fields[key].(map[string]any); ok {
		return sub
	}
	return map[string]any{}
}

// rosterSubmapClone is rosterSubmap plus a shallow copy, so a field-edit
// widget can set one nested key without disturbing sibling nested keys
// already on the roster entry.
func rosterSubmapClone(fields map[string]any, key string) map[string]any {
	return cloneRosterFields(rosterSubmap(fields, key))
}

func rosterStringSlice(m map[string]any, key string) []string {
	raw, _ := m[key].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func rosterStringOr(fields map[string]any, key, def string) string {
	if s, ok := fields[key].(string); ok && s != "" {
		return s
	}
	return def
}

func rosterDisplay(fields map[string]any, key string) string {
	if s, ok := fields[key].(string); ok && s != "" {
		return s
	}
	return "(未設定)"
}

// rosterStringValue is rosterDisplay's non-display counterpart: the raw
// current value (empty string if unset). Every text-input widget below
// must prefill from THIS, never from rosterDisplay's "(未設定)" — a
// careless save would otherwise literally write that placeholder text
// into the file if the user typed without first clearing the field
// (textInputModel prefills with the cursor at the end, not a blank box).
func rosterStringValue(fields map[string]any, key string) string {
	s, _ := fields[key].(string)
	return s
}

func rosterIntDisplay(fields map[string]any, key string) string {
	switch v := fields[key].(type) {
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.Itoa(int(v))
	}
	return "(未設定)"
}

// rosterIntValue is rosterIntDisplay's non-display counterpart — see
// rosterStringValue's doc comment for why edit widgets must prefill from
// this, not the display form.
func rosterIntValue(fields map[string]any, key string) string {
	switch v := fields[key].(type) {
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.Itoa(int(v))
	}
	return ""
}

func rosterBoolDisplay(m map[string]any, key string) string {
	return rosterBoolDisplayDefault(m, key, false)
}

func rosterBoolDisplayDefault(m map[string]any, key string, def bool) string {
	if b, ok := m[key].(bool); ok {
		return strconv.FormatBool(b)
	}
	return strconv.FormatBool(def)
}

// rosterSecretDisplay never echoes a password's actual value back in the
// preview screen — a more cautious default than the vault key-list
// screen's known plaintext-display limitation (edit_tui_vault.go), chosen
// deliberately since this screen has no such limitation to inherit.
func rosterSecretDisplay(pw map[string]any, key string) string {
	if s, ok := pw[key].(string); ok && s != "" {
		return "已設定"
	}
	return "未設定"
}

var rosterBoolChoices = []string{"true", "false"}

func rosterIntValidator(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if n, err := strconv.Atoi(s); err != nil || n < 0 {
		return fmt.Errorf("必須留空，或是一個非負整數")
	}
	return nil
}

// ---- users: full-detail preview + per-field edit -----------------------

// rosterApplyUserEdit re-reads name's current fields, applies mutate to a
// clone, and simulates-then-writes exactly like pushRosterAddUser's own
// gate chain (Simulate first, only write once it reports no violations).
// ok=false means nothing was written — either a validation rejection
// (banner explains why) or name no longer exists.
func rosterApplyUserEdit(path, name string, mutate func(map[string]any)) (banner string, ok bool, err error) {
	fields, found, err := inventory.RosterUser(path, name)
	if err != nil {
		return "", false, err
	}
	if !found {
		return fmt.Sprintf("⚠️  user %q 已不存在（可能被其他流程刪除）", name), false, nil
	}
	updated := cloneRosterFields(fields)
	mutate(updated)
	violations, _, err := inventory.SimulateSetRosterUser(path, name, updated)
	if err != nil {
		return "", false, err
	}
	if len(violations) > 0 {
		return formatRosterViolations(violations), false, nil
	}
	if err := inventory.SetRosterUser(path, name, updated); err != nil {
		return "", false, err
	}
	return "✅ 已更新", true, nil
}

// pushRosterEditUser is rosterApplyUserEdit plus navigation back to the
// (possibly changed) detail screen — the commit point every scalar/bool/
// enum/password field widget below routes through.
func pushRosterEditUser(r *editRouterModel, dir, path, name string, mutate func(map[string]any)) tea.Cmd {
	banner, _, err := rosterApplyUserEdit(path, name, mutate)
	if err != nil {
		r.err = err
		return nil
	}
	return pushRosterUserDetail(r, dir, path, name, banner)
}

// pushRosterUserDetail is the full field-detail preview for one user —
// every field in knownUserKeys (roster_validate.go) with its current
// value, each selectable to edit via a type-appropriate widget. name and
// state:absent are deliberately not offered — see this file's package doc
// comment.
func pushRosterUserDetail(r *editRouterModel, dir, path, name, banner string) tea.Cmd {
	fields, found, err := inventory.RosterUser(path, name)
	if err != nil {
		r.err = err
		return nil
	}
	if !found {
		return pushRosterUsersMenu(r, dir, path, fmt.Sprintf("⚠️  user %q 已不存在", name))
	}
	pw := rosterSubmap(fields, "password")
	values := rosterStringSlice(rosterSubmap(fields, "ssh_keys"), "values")

	items := []string{
		fmt.Sprintf("name：%s（唯讀，其他規則會用名稱互相參照）", name),
		fmt.Sprintf("state：%s", rosterStringOr(fields, "state", "present")),
		fmt.Sprintf("first：%s", rosterDisplay(fields, "first")),
		fmt.Sprintf("last：%s", rosterDisplay(fields, "last")),
		fmt.Sprintf("display_name：%s", rosterDisplay(fields, "display_name")),
		fmt.Sprintf("email：%s", rosterDisplay(fields, "email")),
		fmt.Sprintf("uid：%s", rosterIntDisplay(fields, "uid")),
		fmt.Sprintf("gid：%s", rosterIntDisplay(fields, "gid")),
		fmt.Sprintf("login_shell：%s", rosterDisplay(fields, "login_shell")),
		fmt.Sprintf("home_directory：%s", rosterDisplay(fields, "home_directory")),
		fmt.Sprintf("enabled：%s", rosterBoolDisplay(fields, "enabled")),
		fmt.Sprintf("password.initial：%s", rosterSecretDisplay(pw, "initial")),
		fmt.Sprintf("password.force_change：%s", rosterBoolDisplay(pw, "force_change")),
		fmt.Sprintf("password.preserve_existing：%s", rosterBoolDisplay(pw, "preserve_existing")),
		fmt.Sprintf("ssh_keys.values（共 %d 支公鑰）", len(values)),
		"↩  返回",
	}
	return r.transitionTo(newSelectModel(fmt.Sprintf("User %q — %s", name, path), items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushRosterUsersMenu(r, dir, path, "")
		}
		switch m.Selected() {
		case 0:
			return pushRosterUserDetail(r, dir, path, name, "name 不可修改：其他規則(membership/hbac/sudo)會用名稱互相參照")
		case 1:
			return pushRosterUserStateField(r, dir, path, name)
		case 2:
			return pushRosterUserTextField(r, dir, path, name, "first", "first(名)", rosterStringValue(fields, "first"))
		case 3:
			return pushRosterUserTextField(r, dir, path, name, "last", "last(姓)", rosterStringValue(fields, "last"))
		case 4:
			return pushRosterUserTextField(r, dir, path, name, "display_name", "display_name(顯示名稱)", rosterStringValue(fields, "display_name"))
		case 5:
			return pushRosterUserTextField(r, dir, path, name, "email", "email", rosterStringValue(fields, "email"))
		case 6:
			return pushRosterUserIntField(r, dir, path, name, "uid", rosterIntValue(fields, "uid"))
		case 7:
			return pushRosterUserIntField(r, dir, path, name, "gid", rosterIntValue(fields, "gid"))
		case 8:
			return pushRosterUserTextField(r, dir, path, name, "login_shell", "login_shell", rosterStringValue(fields, "login_shell"))
		case 9:
			return pushRosterUserTextField(r, dir, path, name, "home_directory", "home_directory", rosterStringValue(fields, "home_directory"))
		case 10:
			return pushRosterUserBoolField(r, dir, path, name, "enabled", "enabled")
		case 11:
			return pushRosterUserPasswordInitial(r, dir, path, name)
		case 12:
			return pushRosterUserPasswordBoolField(r, dir, path, name, "force_change", "password.force_change")
		case 13:
			return pushRosterUserPasswordBoolField(r, dir, path, name, "preserve_existing", "password.preserve_existing")
		case 14:
			return pushRosterUserSSHKeysList(r, dir, path, name)
		case 15:
			return pushRosterUsersMenu(r, dir, path, "")
		}
		return nil
	})
}

func pushRosterUserTextField(r *editRouterModel, dir, path, name, key, label, current string) tea.Cmd {
	return r.transitionTo(newTextInputModel(label, current, nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushRosterUserDetail(r, dir, path, name, "")
		}
		value := strings.TrimSpace(m.Value())
		return pushRosterEditUser(r, dir, path, name, func(f map[string]any) { f[key] = value })
	})
}

func pushRosterUserIntField(r *editRouterModel, dir, path, name, key, current string) tea.Cmd {
	return r.transitionTo(newTextInputModel(key+"(留空 = 未設定)", current, rosterIntValidator), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushRosterUserDetail(r, dir, path, name, "")
		}
		value := strings.TrimSpace(m.Value())
		return pushRosterEditUser(r, dir, path, name, func(f map[string]any) {
			if value == "" {
				f[key] = nil
				return
			}
			n, _ := strconv.Atoi(value)
			f[key] = n
		})
	})
}

func pushRosterUserBoolField(r *editRouterModel, dir, path, name, key, label string) tea.Cmd {
	return r.transitionTo(newSelectModel(label, rosterBoolChoices), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushRosterUserDetail(r, dir, path, name, "")
		}
		value := m.Selected() == 0
		return pushRosterEditUser(r, dir, path, name, func(f map[string]any) { f[key] = value })
	})
}

// rosterUserStateChoices deliberately excludes "absent" — this wizard does
// not support delete (see the package doc comment).
var rosterUserStateChoices = []string{"present", "disabled"}

func pushRosterUserStateField(r *editRouterModel, dir, path, name string) tea.Cmd {
	title := "state(不提供 absent — 這個精靈不支援刪除；如需刪除請直接編輯檔案)"
	return r.transitionTo(newSelectModel(title, rosterUserStateChoices), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushRosterUserDetail(r, dir, path, name, "")
		}
		value := rosterUserStateChoices[m.Selected()]
		return pushRosterEditUser(r, dir, path, name, func(f map[string]any) { f["state"] = value })
	})
}

func pushRosterUserPasswordInitial(r *editRouterModel, dir, path, name string) tea.Cmd {
	label := "password.initial 的新值(不會顯示；輸入後立即生效，且不會預填舊密碼)"
	return r.transitionTo(newSecretTextInputModel(label, "", nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushRosterUserDetail(r, dir, path, name, "")
		}
		value := m.Value()
		return pushRosterEditUser(r, dir, path, name, func(f map[string]any) {
			pw := rosterSubmapClone(f, "password")
			pw["initial"] = value
			f["password"] = pw
		})
	})
}

func pushRosterUserPasswordBoolField(r *editRouterModel, dir, path, name, key, label string) tea.Cmd {
	return r.transitionTo(newSelectModel(label, rosterBoolChoices), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushRosterUserDetail(r, dir, path, name, "")
		}
		value := m.Selected() == 0
		return pushRosterEditUser(r, dir, path, name, func(f map[string]any) {
			pw := rosterSubmapClone(f, "password")
			pw[key] = value
			f["password"] = pw
		})
	})
}

// pushRosterUserSSHKeysList is name's ssh_keys.values editor: an
// open-ended add/remove/edit-one-at-a-time list, modeled on group_vars'
// list-editing interaction shape (pushGroupVarsListItemsMenu et al.,
// edit_tui_groupvars.go) but persisting via SimulateSetRosterUser/
// SetRosterUser's yaml.Node surgery instead of a single-line flow-list
// rewrite. ssh_keys.authoritative is never exposed — the roster gate
// requires it fixed at true, so every write here just sets it.
func pushRosterUserSSHKeysList(r *editRouterModel, dir, path, name string) tea.Cmd {
	fields, found, err := inventory.RosterUser(path, name)
	if err != nil {
		r.err = err
		return nil
	}
	if !found {
		return pushRosterUsersMenu(r, dir, path, fmt.Sprintf("⚠️  user %q 已不存在", name))
	}
	values := rosterStringSlice(rosterSubmap(fields, "ssh_keys"), "values")
	return pushRosterUserSSHKeysListScreen(r, dir, path, name, values, "")
}

func pushRosterUserSSHKeysListScreen(r *editRouterModel, dir, path, name string, values []string, banner string) tea.Cmd {
	items := make([]string, 0, len(values)+2)
	for i, v := range values {
		items = append(items, fmt.Sprintf("%d: %s", i+1, v))
	}
	items = append(items, "➕ 新增公鑰", "↩  返回")
	title := fmt.Sprintf("%s 的 ssh_keys.values", name)
	return r.transitionTo(newSelectModel(title, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushRosterUserDetail(r, dir, path, name, "")
		}
		switch {
		case m.Selected() == len(items)-2:
			return pushRosterUserSSHKeysAdd(r, dir, path, name, values)
		case m.Selected() == len(items)-1:
			return pushRosterUserDetail(r, dir, path, name, "")
		default:
			return pushRosterUserSSHKeysItemAction(r, dir, path, name, values, m.Selected())
		}
	})
}

func pushRosterUserSSHKeysAdd(r *editRouterModel, dir, path, name string, values []string) tea.Cmd {
	validate := func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}
	return r.transitionTo(newTextInputModel("新公鑰(ssh-ed25519/ssh-rsa ...)", "", validate), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushRosterUserSSHKeysListScreen(r, dir, path, name, values, "")
		}
		newValues := append(append([]string{}, values...), strings.TrimSpace(m.Value()))
		return pushRosterCommitUserSSHKeys(r, dir, path, name, values, newValues)
	})
}

func pushRosterUserSSHKeysItemAction(r *editRouterModel, dir, path, name string, values []string, idx int) tea.Cmd {
	items := []string{"修改值", "移除", "返回"}
	return r.transitionTo(newSelectModel(fmt.Sprintf("公鑰 %d：%s", idx+1, values[idx]), items), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushRosterUserSSHKeysListScreen(r, dir, path, name, values, "")
		}
		switch m.Selected() {
		case 0:
			return pushRosterUserSSHKeysEditItem(r, dir, path, name, values, idx)
		case 1:
			newValues := append(append([]string{}, values[:idx]...), values[idx+1:]...)
			return pushRosterCommitUserSSHKeys(r, dir, path, name, values, newValues)
		case 2:
			return pushRosterUserSSHKeysListScreen(r, dir, path, name, values, "")
		}
		return nil
	})
}

func pushRosterUserSSHKeysEditItem(r *editRouterModel, dir, path, name string, values []string, idx int) tea.Cmd {
	validate := func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}
	return r.transitionTo(newTextInputModel("新值", values[idx], validate), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushRosterUserSSHKeysItemAction(r, dir, path, name, values, idx)
		}
		newValues := append([]string{}, values...)
		newValues[idx] = strings.TrimSpace(m.Value())
		return pushRosterCommitUserSSHKeys(r, dir, path, name, values, newValues)
	})
}

// pushRosterCommitUserSSHKeys re-validates and writes newValues as name's
// ssh_keys.values, landing back on the list screen either way — oldValues
// (not the rejected newValues) on a validation failure, so the screen
// always shows what's actually on disk.
func pushRosterCommitUserSSHKeys(r *editRouterModel, dir, path, name string, oldValues, newValues []string) tea.Cmd {
	banner, ok, err := rosterApplyUserEdit(path, name, func(f map[string]any) {
		ssh := rosterSubmapClone(f, "ssh_keys")
		ssh["authoritative"] = true
		ssh["values"] = newValues
		f["ssh_keys"] = ssh
	})
	if err != nil {
		r.err = err
		return nil
	}
	if !ok {
		return pushRosterUserSSHKeysListScreen(r, dir, path, name, oldValues, banner)
	}
	return pushRosterUserSSHKeysListScreen(r, dir, path, name, newValues, banner)
}

// ---- groups: full-detail preview + per-field edit -----------------------

// rosterApplyGroupEdit is rosterApplyUserEdit's group counterpart.
func rosterApplyGroupEdit(path, name string, mutate func(map[string]any)) (banner string, ok bool, err error) {
	fields, found, err := inventory.RosterGroup(path, name)
	if err != nil {
		return "", false, err
	}
	if !found {
		return fmt.Sprintf("⚠️  group %q 已不存在（可能被其他流程刪除）", name), false, nil
	}
	updated := cloneRosterFields(fields)
	mutate(updated)
	violations, _, err := inventory.SimulateSetRosterGroup(path, name, updated)
	if err != nil {
		return "", false, err
	}
	if len(violations) > 0 {
		return formatRosterViolations(violations), false, nil
	}
	if err := inventory.SetRosterGroup(path, name, updated); err != nil {
		return "", false, err
	}
	return "✅ 已更新", true, nil
}

func pushRosterEditGroup(r *editRouterModel, dir, path, name string, mutate func(map[string]any)) tea.Cmd {
	banner, _, err := rosterApplyGroupEdit(path, name, mutate)
	if err != nil {
		r.err = err
		return nil
	}
	return pushRosterGroupDetail(r, dir, path, name, banner)
}

// pushRosterGroupDetail is the full field-detail preview for one group —
// every field in knownGroupKeys (roster_validate.go). name/category/state
// are read-only: name and category together drive the name-prefix gate
// and are referenced by hbac/sudo/membership elsewhere; state's only other
// value is absent (delete), out of scope.
func pushRosterGroupDetail(r *editRouterModel, dir, path, name, banner string) tea.Cmd {
	fields, found, err := inventory.RosterGroup(path, name)
	if err != nil {
		r.err = err
		return nil
	}
	if !found {
		return pushRosterGroupsMenu(r, dir, path, fmt.Sprintf("⚠️  group %q 已不存在", name))
	}
	mem := rosterSubmap(fields, "membership")
	users := rosterStringSlice(mem, "users")
	groups := rosterStringSlice(mem, "groups")

	items := []string{
		fmt.Sprintf("name：%s（唯讀，其他規則會用名稱互相參照）", name),
		fmt.Sprintf("state：%s（唯讀，這個精靈不支援刪除/absent）", rosterStringOr(fields, "state", "present")),
		fmt.Sprintf("category：%s（唯讀，決定名稱前綴規則）", rosterStringOr(fields, "category", "")),
		fmt.Sprintf("type：%s", rosterStringOr(fields, "type", "posix")),
		fmt.Sprintf("description：%s", rosterDisplay(fields, "description")),
		fmt.Sprintf("gid：%s", rosterIntDisplay(fields, "gid")),
		fmt.Sprintf("membership.authoritative：%s", rosterBoolDisplayDefault(mem, "authoritative", true)),
		fmt.Sprintf("membership.users（共 %d 位）", len(users)),
		fmt.Sprintf("membership.groups（共 %d 個，不含自己）", len(groups)),
		"↩  返回",
	}
	return r.transitionTo(newSelectModel(fmt.Sprintf("Group %q — %s", name, path), items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushRosterGroupsMenu(r, dir, path, "")
		}
		switch m.Selected() {
		case 0, 1, 2:
			return pushRosterGroupDetail(r, dir, path, name, "這個欄位不可修改；如需變更請直接編輯檔案")
		case 3:
			return pushRosterGroupTypeField(r, dir, path, name)
		case 4:
			return pushRosterGroupTextField(r, dir, path, name, "description", "description", rosterStringValue(fields, "description"))
		case 5:
			return pushRosterGroupIntField(r, dir, path, name, "gid", rosterIntValue(fields, "gid"))
		case 6:
			return pushRosterGroupMembershipAuthoritative(r, dir, path, name)
		case 7:
			return pushRosterGroupMembershipUsers(r, dir, path, name)
		case 8:
			return pushRosterGroupMembershipGroups(r, dir, path, name)
		case 9:
			return pushRosterGroupsMenu(r, dir, path, "")
		}
		return nil
	})
}

var rosterGroupTypeChoices = []string{"posix", "nonposix", "external"}

func pushRosterGroupTypeField(r *editRouterModel, dir, path, name string) tea.Cmd {
	return r.transitionTo(newSelectModel("type", rosterGroupTypeChoices), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushRosterGroupDetail(r, dir, path, name, "")
		}
		value := rosterGroupTypeChoices[m.Selected()]
		return pushRosterEditGroup(r, dir, path, name, func(f map[string]any) { f["type"] = value })
	})
}

func pushRosterGroupTextField(r *editRouterModel, dir, path, name, key, label, current string) tea.Cmd {
	return r.transitionTo(newTextInputModel(label, current, nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushRosterGroupDetail(r, dir, path, name, "")
		}
		value := strings.TrimSpace(m.Value())
		return pushRosterEditGroup(r, dir, path, name, func(f map[string]any) { f[key] = value })
	})
}

func pushRosterGroupIntField(r *editRouterModel, dir, path, name, key, current string) tea.Cmd {
	return r.transitionTo(newTextInputModel(key+"(留空 = 未設定)", current, rosterIntValidator), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushRosterGroupDetail(r, dir, path, name, "")
		}
		value := strings.TrimSpace(m.Value())
		return pushRosterEditGroup(r, dir, path, name, func(f map[string]any) {
			if value == "" {
				f[key] = nil
				return
			}
			n, _ := strconv.Atoi(value)
			f[key] = n
		})
	})
}

func pushRosterGroupMembershipAuthoritative(r *editRouterModel, dir, path, name string) tea.Cmd {
	return r.transitionTo(newSelectModel("membership.authoritative", rosterBoolChoices), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushRosterGroupDetail(r, dir, path, name, "")
		}
		value := m.Selected() == 0
		return pushRosterEditGroup(r, dir, path, name, func(f map[string]any) {
			mem := rosterSubmapClone(f, "membership")
			mem["authoritative"] = value
			f["membership"] = mem
		})
	})
}

// pushRosterGroupMembershipUsers offers a checklist of every user already
// in the roster (RosterUserNames) instead of an open-ended list editor —
// unlike ssh_keys.values, a membership reference must already exist as a
// real roster entry (checkUniqueAndReferences), so picking from a fixed,
// known-valid option set can't produce an unresolvable reference at all.
func pushRosterGroupMembershipUsers(r *editRouterModel, dir, path, name string) tea.Cmd {
	fields, found, err := inventory.RosterGroup(path, name)
	if err != nil {
		r.err = err
		return nil
	}
	if !found {
		return pushRosterGroupsMenu(r, dir, path, fmt.Sprintf("⚠️  group %q 已不存在", name))
	}
	allUsers, err := inventory.RosterUserNames(path)
	if err != nil {
		r.err = err
		return nil
	}
	current := rosterStringSlice(rosterSubmap(fields, "membership"), "users")
	items := make([]multiSelectItem, len(allUsers))
	for i, u := range allUsers {
		items[i] = multiSelectItem{Label: u, Checked: hasRole(current, u)}
	}
	title := fmt.Sprintf("%s 的 membership.users(space 勾選、enter 完成)", name)
	return r.transitionTo(newMultiSelectModel(title, items), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(multiSelectModel)
		if m.Canceled() {
			return pushRosterGroupDetail(r, dir, path, name, "")
		}
		checked := m.CheckedLabels()
		return pushRosterEditGroup(r, dir, path, name, func(f map[string]any) {
			mem := rosterSubmapClone(f, "membership")
			mem["users"] = checked
			f["membership"] = mem
		})
	})
}

// pushRosterGroupMembershipGroups is pushRosterGroupMembershipUsers'
// counterpart for membership.groups — options exclude name itself,
// mirroring checkGroups' own self-membership rule so this screen can never
// even offer the one edit that rule always rejects.
func pushRosterGroupMembershipGroups(r *editRouterModel, dir, path, name string) tea.Cmd {
	fields, found, err := inventory.RosterGroup(path, name)
	if err != nil {
		r.err = err
		return nil
	}
	if !found {
		return pushRosterGroupsMenu(r, dir, path, fmt.Sprintf("⚠️  group %q 已不存在", name))
	}
	allGroups, err := inventory.RosterGroupNames(path)
	if err != nil {
		r.err = err
		return nil
	}
	options := make([]string, 0, len(allGroups))
	for _, g := range allGroups {
		if g != name {
			options = append(options, g)
		}
	}
	current := rosterStringSlice(rosterSubmap(fields, "membership"), "groups")
	items := make([]multiSelectItem, len(options))
	for i, g := range options {
		items[i] = multiSelectItem{Label: g, Checked: hasRole(current, g)}
	}
	title := fmt.Sprintf("%s 的 membership.groups(不含自己；space 勾選、enter 完成)", name)
	return r.transitionTo(newMultiSelectModel(title, items), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(multiSelectModel)
		if m.Canceled() {
			return pushRosterGroupDetail(r, dir, path, name, "")
		}
		checked := m.CheckedLabels()
		return pushRosterEditGroup(r, dir, path, name, func(f map[string]any) {
			mem := rosterSubmapClone(f, "membership")
			mem["groups"] = checked
			f["membership"] = mem
		})
	})
}
