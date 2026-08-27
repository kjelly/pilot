// edit_tui_roster.go implements the roster screens of the `pilot edit`
// router (edit_tui.go): a manager for the canonical FreeIPA-identity
// roster file covering users, groups, and sudo policy — add, full-detail
// preview, and per-field edit (scalars, membership, password/SSH keys,
// command groups, and sudo allow-lists). Every write
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
// purpose), and nfs_clients/migration. Host access (hostgroups and
// HBAC) and sudo authorization are edited by separate relationship editors.
// A user/group's name and a group's category are shown
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

	tea "charm.land/bubbletea/v2"

	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/tui"
	"github.com/kjelly/pilot/internal/vaultfile"
)

func pushRosterPathPrompt(r *editRouterModel, dir string) tea.Cmd {
	def := filepath.Join(dir, ".vault", "ipa-identity.yaml")
	spec := tui.InputSpec{ScreenID: "roster.path", Title: "Roster 檔路徑(canonical FreeIPA roster)", Default: def}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
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

	// This is the one place every path into roster editing passes through
	// — the interactive TUI (pushRosterPathPrompt -> here) and the MCP
	// semantic roster driver (which drives these same screens by ID, see
	// edit_automation_driver_roster.go's ensureRosterUsersList) alike — so
	// it's also the roster-schema-v2 migration spec's required "automatic
	// TUI/MCP migration" boundary: auto-upgrading here, once, covers both
	// instead of duplicating the call into every screen or driver.
	// Deliberately tolerant of failure (encrypted, invalid, locked): a
	// roster this can't migrate is not a reason to kill the whole `pilot
	// edit` session, since pushRosterUsersMenu/pushRosterGroupsMenu below
	// already have their own, less disruptive way of reporting exactly
	// that (e.g. the ErrRosterEncrypted banner) once something actually
	// tries to read it.
	if notice := ensureRosterSchemaCurrentBanner(path); notice != "" {
		if banner == "" {
			banner = notice
		} else {
			banner = notice + "\n" + banner
		}
	}

	choices := []tui.Choice{
		{ID: "roster.top.users", Label: "👤 Users"},
		{ID: "roster.top.groups", Label: "👥 Groups"},
		{ID: "roster.top.host_access", Label: "🔐 Host access"},
		{ID: "roster.top.sudo", Label: "🛡️  Sudo commands & rules"},
		{ID: "roster.top.access_governance", Label: "🏛️  Access governance"},
		{ID: "roster.top.back", Label: "↩  返回"},
	}
	title := fmt.Sprintf("管理 %s", path)
	spec := tui.SelectSpec{ScreenID: "roster.top", Title: title, Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
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
			return pushRosterSudoMenu(r, dir, path, "")
		case 4:
			return pushAccessGovernanceMenu(r, dir, path, "")
		case 5:
			return pushTopMenu(r, dir, "")
		}
		return nil
	})
}

// ensureRosterSchemaCurrentBanner attempts to auto-upgrade the roster at
// path to the current schema (inventory.EnsureRosterCurrent) and returns a
// banner note describing it — "" if nothing happened, whether because it
// was already current or because it couldn't be migrated (encrypted,
// invalid, locked). The required UX for a real upgrade is "Roster schema
// vN detected. Automatically upgraded to schema vM. Backup: <path>" — no
// confirmation prompt, since a deterministic, validated migration with a
// successfully created backup doesn't need one.
func ensureRosterSchemaCurrentBanner(path string) string {
	result, err := inventory.EnsureRosterCurrent(path, inventory.RosterMigrationOptions{})
	if err != nil || !result.Changed {
		return ""
	}
	return fmt.Sprintf("✅ Roster schema v%d detected. Automatically upgraded to schema v%d.\nBackup:\n  %s",
		result.FromVersion, result.ToVersion, result.BackupPath)
}

// rosterCreateConfirmScreenID and rosterCreatePasswordScreenID identify
// pushRosterCreateConfirm's and pushRosterCreatePrompt's own screens to the
// automation driver (resolveRosterCreatePrompt,
// edit_automation_driver_roster.go) the same way
// nfsRosterBootstrapPasswordScreenID identifies pushNFSRoleBootstrap's
// analogous prompt — without a stable ID, a generic "confirm"/"text-input"
// screen is indistinguishable from any other, and every ensureRosterXxxList
// helper's default branch (a bare choose("返回")) fails outright the moment
// it lands here instead of on the roster list it expected.
const (
	rosterCreateConfirmScreenID  = "roster.create_confirm"
	rosterCreatePasswordScreenID = "roster.create_password"
)

// pushRosterCreateConfirm offers to auto-generate the smallest canonical
// roster skeleton when path doesn't exist yet — the same recoverable
// posture as pushVaultOpen's "不存在，要建立新的明文 vault 檔嗎？" confirm.
func pushRosterCreateConfirm(r *editRouterModel, dir, path string) tea.Cmd {
	question := fmt.Sprintf("%s 不存在，要建立最小 roster 骨架嗎？", path)
	spec := tui.ConfirmSpec{ScreenID: rosterCreateConfirmScreenID, Title: question, Default: true}
	return r.transitionTo(r.uiFactory().Confirm(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.ConfirmScreen)
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
	spec := tui.InputSpec{
		ScreenID: rosterCreatePasswordScreenID,
		Title:    "FreeIPA admin password(不會顯示；至少 8 字元)",
		Secret:   true,
		Validate: validate,
	}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
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
	if err := inventory.WriteMinimalRosterSkeleton(path, "admin", password); err != nil {
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

	// A roster user's own name is its stable identity everywhere else in
	// the roster (membership/hbac/sudo all reference it), so it is also
	// this row's Choice.ID — no synthetic per-row ID needed.
	choices := make([]tui.Choice, 0, len(names)+2)
	for _, n := range names {
		choices = append(choices, tui.Choice{ID: n, Label: "👤 " + n})
	}
	choices = append(choices,
		tui.Choice{ID: "roster.users.list.add", Label: "➕ 新增 User"},
		tui.Choice{ID: "roster.users.list.back", Label: "↩  返回"},
	)

	spec := tui.SelectSpec{ScreenID: "roster.users.list", Title: fmt.Sprintf("Users — %s", path), Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
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
	spec := tui.InputSpec{ScreenID: "roster.user.add", Title: "新 user 的名稱(小寫英數字/底線/點/連字號)", Validate: validate}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
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

	// The group's own name is its stable identity — see
	// pushRosterUsersMenu.
	choices := make([]tui.Choice, 0, len(names)+2)
	for _, n := range names {
		choices = append(choices, tui.Choice{ID: n, Label: "👥 " + n})
	}
	choices = append(choices,
		tui.Choice{ID: "roster.groups.list.add", Label: "➕ 新增 Group"},
		tui.Choice{ID: "roster.groups.list.back", Label: "↩  返回"},
	)

	spec := tui.SelectSpec{ScreenID: "roster.groups.list", Title: fmt.Sprintf("Groups — %s", path), Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
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

// rosterGroupCategories lists the group categories sanctioned authoring
// surfaces may create. "access" is deliberately absent: it is a deprecated
// compatibility category (inventory.IsDeprecatedGroupCategory) that
// existing rosters may still reference, but nothing new may create it
// (spec.md §1, §6.1, §10). edit_tui_roster_test.go's
// TestRosterGroupCategories_MatchIsCreatableGroupCategory proves this list
// stays in sync with internal/inventory.IsCreatableGroupCategory, the
// canonical policy source of truth.
var rosterGroupCategories = []struct {
	Category, Label string
}{
	{"team", "team-*(團隊/team)"},
	{"filesystem", "data-*(檔案系統存取/filesystem)"},
	{"role", "role-*(授權角色/role，可供 HBAC / sudo 使用)"},
}

func pushRosterAddGroupCategory(r *editRouterModel, dir, path string) tea.Cmd {
	choices := make([]tui.Choice, 0, len(rosterGroupCategories)+1)
	for _, c := range rosterGroupCategories {
		choices = append(choices, tui.Choice{ID: "roster.group.add_category." + c.Category, Label: c.Label})
	}
	choices = append(choices, tui.Choice{ID: "roster.group.add_category.back", Label: "↩  返回"})
	spec := tui.SelectSpec{ScreenID: "roster.group.add_category", Title: "新 group 的分類(決定名稱前綴規則)", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			// mirrors "↩ 返回".
			return pushRosterGroupsMenu(r, dir, path, "")
		}
		idx := m.Selected()
		if idx == len(choices)-1 {
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
	spec := tui.InputSpec{ScreenID: "roster.group.add_name", Title: label, Validate: validate}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
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

// rosterEnumChoices turns one of this file's fixed enum option slices
// (rosterBoolChoices, rosterUserStateChoices, rosterGroupTypeChoices)
// into tui.Choices whose stable IDs are the owning screen's ID plus the
// option's own value — "roster.user.field_bool.true" and so on. The
// label is the bare value exactly as before, and the option order (which
// every one of these screens' callbacks reads back via Selected()) is
// preserved.
func rosterEnumChoices(screenID string, values []string) []tui.Choice {
	out := make([]tui.Choice, len(values))
	for i, v := range values {
		out[i] = tui.Choice{ID: screenID + "." + v, Label: v}
	}
	return out
}

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

	// Fixed field menu: one namespaced ID per roster field, so a row's
	// stable identity survives its label (which embeds the live value).
	choices := []tui.Choice{
		{ID: "roster.user.detail.name", Label: fmt.Sprintf("name：%s（唯讀，其他規則會用名稱互相參照）", name)},
		{ID: "roster.user.detail.state", Label: fmt.Sprintf("state：%s", rosterStringOr(fields, "state", "present"))},
		{ID: "roster.user.detail.first", Label: fmt.Sprintf("first：%s", rosterDisplay(fields, "first"))},
		{ID: "roster.user.detail.last", Label: fmt.Sprintf("last：%s", rosterDisplay(fields, "last"))},
		{ID: "roster.user.detail.display_name", Label: fmt.Sprintf("display_name：%s", rosterDisplay(fields, "display_name"))},
		{ID: "roster.user.detail.email", Label: fmt.Sprintf("email：%s", rosterDisplay(fields, "email"))},
		{ID: "roster.user.detail.uid", Label: fmt.Sprintf("uid：%s", rosterIntDisplay(fields, "uid"))},
		{ID: "roster.user.detail.gid", Label: fmt.Sprintf("gid：%s", rosterIntDisplay(fields, "gid"))},
		{ID: "roster.user.detail.login_shell", Label: fmt.Sprintf("login_shell：%s", rosterDisplay(fields, "login_shell"))},
		{ID: "roster.user.detail.home_directory", Label: fmt.Sprintf("home_directory：%s", rosterDisplay(fields, "home_directory"))},
		{ID: "roster.user.detail.enabled", Label: fmt.Sprintf("enabled：%s", rosterBoolDisplayDefault(fields, "enabled", true))},
		{ID: "roster.user.detail.password_initial", Label: fmt.Sprintf("password.initial：%s", rosterSecretDisplay(pw, "initial"))},
		{ID: "roster.user.detail.password_force_change", Label: fmt.Sprintf("password.force_change：%s", rosterBoolDisplay(pw, "force_change"))},
		{ID: "roster.user.detail.password_preserve_existing", Label: fmt.Sprintf("password.preserve_existing：%s", rosterBoolDisplayDefault(pw, "preserve_existing", true))},
		{ID: "roster.user.detail.ssh_keys", Label: fmt.Sprintf("ssh_keys.values（共 %d 支公鑰）", len(values))},
		{ID: "roster.user.detail.back", Label: "↩  返回"},
	}
	spec := tui.SelectSpec{ScreenID: "roster.user.detail", Title: fmt.Sprintf("User %q — %s", name, path), Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
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
	spec := tui.InputSpec{ScreenID: "roster.user.field_text", Title: label, Default: current}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushRosterUserDetail(r, dir, path, name, "")
		}
		value := strings.TrimSpace(m.Value())
		return pushRosterEditUser(r, dir, path, name, func(f map[string]any) { f[key] = value })
	})
}

func pushRosterUserIntField(r *editRouterModel, dir, path, name, key, current string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "roster.user.field_int", Title: key + "(留空 = 未設定)", Default: current, Validate: rosterIntValidator}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
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
	spec := tui.SelectSpec{ScreenID: "roster.user.field_bool", Title: label, Choices: rosterEnumChoices("roster.user.field_bool", rosterBoolChoices)}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
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
	spec := tui.SelectSpec{ScreenID: "roster.user.field_state", Title: title, Choices: rosterEnumChoices("roster.user.field_state", rosterUserStateChoices)}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushRosterUserDetail(r, dir, path, name, "")
		}
		value := rosterUserStateChoices[m.Selected()]
		return pushRosterEditUser(r, dir, path, name, func(f map[string]any) {
			f["state"] = value
			if value == "disabled" {
				// Keep the two user fields consistent. A disabled user must
				// not retain enabled: true, which the roster validator rejects.
				f["enabled"] = false
			}
		})
	})
}

func pushRosterUserPasswordInitial(r *editRouterModel, dir, path, name string) tea.Cmd {
	label := "password.initial 的新值(不會顯示；輸入後立即生效，且不會預填舊密碼)"
	spec := tui.InputSpec{ScreenID: "roster.user.field_password", Title: label, Secret: true}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
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
	spec := tui.SelectSpec{ScreenID: "roster.user.field_password_bool", Title: label, Choices: rosterEnumChoices("roster.user.field_password_bool", rosterBoolChoices)}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
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
	// An ssh_keys.values entry has no name field, so the key material
	// itself is its stable identity: unlike a positional ID, it still
	// designates the same key after another key is removed from the list.
	choices := make([]tui.Choice, 0, len(values)+2)
	for i, v := range values {
		choices = append(choices, tui.Choice{ID: v, Label: fmt.Sprintf("%d: %s", i+1, v)})
	}
	choices = append(choices,
		tui.Choice{ID: "roster.user.ssh_keys.list.add", Label: "➕ 新增公鑰"},
		tui.Choice{ID: "roster.user.ssh_keys.list.back", Label: "↩  返回"},
	)
	title := fmt.Sprintf("%s 的 ssh_keys.values", name)
	spec := tui.SelectSpec{ScreenID: "roster.user.ssh_keys.list", Title: title, Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushRosterUserDetail(r, dir, path, name, "")
		}
		switch {
		case m.Selected() == len(choices)-2:
			return pushRosterUserSSHKeysAdd(r, dir, path, name, values)
		case m.Selected() == len(choices)-1:
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
	spec := tui.InputSpec{ScreenID: "roster.user.ssh_keys.add", Title: "新公鑰(ssh-ed25519/ssh-rsa ...)", Validate: validate}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushRosterUserSSHKeysListScreen(r, dir, path, name, values, "")
		}
		newValues := append(append([]string{}, values...), strings.TrimSpace(m.Value()))
		return pushRosterCommitUserSSHKeys(r, dir, path, name, values, newValues)
	})
}

func pushRosterUserSSHKeysItemAction(r *editRouterModel, dir, path, name string, values []string, idx int) tea.Cmd {
	choices := []tui.Choice{
		{ID: "roster.user.ssh_keys.item_action.edit", Label: "修改值"},
		{ID: "roster.user.ssh_keys.item_action.remove", Label: "移除"},
		{ID: "roster.user.ssh_keys.item_action.back", Label: "返回"},
	}
	spec := tui.SelectSpec{ScreenID: "roster.user.ssh_keys.item_action", Title: fmt.Sprintf("公鑰 %d：%s", idx+1, values[idx]), Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
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
	spec := tui.InputSpec{ScreenID: "roster.user.ssh_keys.edit_item", Title: "新值", Default: values[idx], Validate: validate}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
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

	categoryLabel := fmt.Sprintf("category：%s（唯讀，決定名稱前綴規則）", rosterStringOr(fields, "category", ""))
	if inventory.IsDeprecatedGroupCategory(rosterStringOr(fields, "category", "")) {
		// Presentation only (spec.md §10) — the category itself stays
		// read-only and reconciled exactly like any other group.
		categoryLabel = "category：access（legacy；新 HBAC 不再需要 access group）"
	}
	choices := []tui.Choice{
		{ID: "roster.group.detail.name", Label: fmt.Sprintf("name：%s（唯讀，其他規則會用名稱互相參照）", name)},
		{ID: "roster.group.detail.state", Label: fmt.Sprintf("state：%s（唯讀，這個精靈不支援刪除/absent）", rosterStringOr(fields, "state", "present"))},
		{ID: "roster.group.detail.category", Label: categoryLabel},
		{ID: "roster.group.detail.type", Label: fmt.Sprintf("type：%s", rosterStringOr(fields, "type", "posix"))},
		{ID: "roster.group.detail.description", Label: fmt.Sprintf("description：%s", rosterDisplay(fields, "description"))},
		{ID: "roster.group.detail.gid", Label: fmt.Sprintf("gid：%s", rosterIntDisplay(fields, "gid"))},
		{ID: "roster.group.detail.membership_authoritative", Label: fmt.Sprintf("membership.authoritative：%s", rosterBoolDisplayDefault(mem, "authoritative", true))},
		{ID: "roster.group.detail.membership_users", Label: fmt.Sprintf("membership.users（共 %d 位）", len(users))},
		{ID: "roster.group.detail.membership_groups", Label: fmt.Sprintf("membership.groups（共 %d 個，不含自己）", len(groups))},
		{ID: "roster.group.detail.back", Label: "↩  返回"},
	}
	spec := tui.SelectSpec{ScreenID: "roster.group.detail", Title: fmt.Sprintf("Group %q — %s", name, path), Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
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
	spec := tui.SelectSpec{ScreenID: "roster.group.field_type", Title: "type", Choices: rosterEnumChoices("roster.group.field_type", rosterGroupTypeChoices)}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushRosterGroupDetail(r, dir, path, name, "")
		}
		value := rosterGroupTypeChoices[m.Selected()]
		return pushRosterEditGroup(r, dir, path, name, func(f map[string]any) { f["type"] = value })
	})
}

func pushRosterGroupTextField(r *editRouterModel, dir, path, name, key, label, current string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "roster.group.field_text", Title: label, Default: current}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushRosterGroupDetail(r, dir, path, name, "")
		}
		value := strings.TrimSpace(m.Value())
		return pushRosterEditGroup(r, dir, path, name, func(f map[string]any) { f[key] = value })
	})
}

func pushRosterGroupIntField(r *editRouterModel, dir, path, name, key, current string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "roster.group.field_int", Title: key + "(留空 = 未設定)", Default: current, Validate: rosterIntValidator}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
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
	spec := tui.SelectSpec{ScreenID: "roster.group.field_authoritative", Title: "membership.authoritative", Choices: rosterEnumChoices("roster.group.field_authoritative", rosterBoolChoices)}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
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
	choices := make([]tui.MultiSelectChoice, len(allUsers))
	for i, u := range allUsers {
		choices[i] = tui.MultiSelectChoice{Choice: tui.Choice{ID: u, Label: u}, Checked: hasRole(current, u)}
	}
	title := fmt.Sprintf("%s 的 membership.users(space 勾選、enter 完成)", name)
	spec := tui.MultiSelectSpec{ScreenID: "roster.group.members_users", Title: title, Choices: choices}
	return r.transitionTo(r.uiFactory().MultiSelect(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.MultiSelectScreen)
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
	choices := make([]tui.MultiSelectChoice, len(options))
	for i, g := range options {
		choices[i] = tui.MultiSelectChoice{Choice: tui.Choice{ID: g, Label: g}, Checked: hasRole(current, g)}
	}
	title := fmt.Sprintf("%s 的 membership.groups(不含自己；space 勾選、enter 完成)", name)
	spec := tui.MultiSelectSpec{ScreenID: "roster.group.members_groups", Title: title, Choices: choices}
	return r.transitionTo(r.uiFactory().MultiSelect(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.MultiSelectScreen)
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
