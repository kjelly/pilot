// edit_tui_groupvars.go implements the group_vars/ screens of the
// `pilot edit` router (edit_tui.go) — file picker (including "create
// from example") and the key-list editor built on internal/groupvars'
// already-clean Doc/Entry API.
package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/kjelly/pilot/internal/groupvars"
	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/tui"
)

// pushGroupVarsFilePicker lists group_vars files under <dir>/group_vars
// — the actual settings files being edited — but always offers to
// seed a missing one from the fixed, CWD-relative
// group_vars/*.example.yml templates (same split as inventory.go's
// copyMissingGroupVars: the shipped example templates live in one
// fixed place; the files this wizard reads/writes follow --dir).
//
// The "➕ 從範例建立" list is narrowed to roles actually used in this
// workspace's hosts.yml (best-effort: hosts.yml might not exist yet, e.g.
// group_vars/ was opened straight from the top menu, in which case nothing
// is filtered) — an already-existing file is always still listed and
// editable regardless of current role usage, since it may predate a roster
// change and a human already chose to create it.
//
// Nested examples (nestedGroupVarsExamples, inventory.go — currently just
// dns_zones) are listed too, so they're at least discoverable/scaffoldable
// instead of invisible, but selecting one never opens the normal editor:
// dns_zones is a 2-level nested list-of-maps with no top-level "key: value"
// line at all, so groupvars.Doc would show a confusingly empty screen
// (harmless, just useless) — point at hand-editing instead.
func pushGroupVarsFilePicker(r *editRouterModel, dir, banner string) tea.Cmd {
	targetDir := filepath.Join(dir, "group_vars")
	exampleDir := "group_vars"

	existing, missingExamples, err := scanGroupVars(targetDir, exampleDir)
	if err != nil {
		r.err = err
		return nil
	}

	hf := tryLoadHostsFile(dir)
	if hf != nil {
		missingExamples = filterStemsToUsedRoles(missingExamples, hf)
	}

	usedRoles := map[string]bool{}
	if hf != nil {
		for _, role := range inventory.UsedRoles(hf) {
			usedRoles[role] = true
		}
	}
	var nestedExisting, nestedMissing []nestedGroupVarsExample
	for _, ex := range nestedGroupVarsExamples {
		if !usedRoles[ex.Role] {
			continue
		}
		if _, statErr := os.Stat(filepath.Join(targetDir, ex.DestRel)); statErr == nil {
			nestedExisting = append(nestedExisting, ex)
		} else {
			nestedMissing = append(nestedMissing, ex)
		}
	}

	items := make([]string, 0, len(existing)+len(nestedExisting)+len(missingExamples)+len(nestedMissing)+1)
	for _, f := range existing {
		items = append(items, "📝 "+f)
	}
	for _, ex := range nestedExisting {
		items = append(items, "📝 "+ex.DestRel)
	}
	for _, stem := range missingExamples {
		items = append(items, fmt.Sprintf("➕ 從範例建立 %s.yml", stem))
	}
	for _, ex := range nestedMissing {
		items = append(items, fmt.Sprintf("➕ 從範例建立 %s", ex.DestRel))
	}
	items = append(items, "↩  返回")

	title := fmt.Sprintf("選一個 %s 底下的檔案", targetDir)
	return r.transitionTo(newSelectModelWithScreenID("group_vars.files", title, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			// mirrors the trailing "↩ 返回" item.
			return pushTopMenu(r, dir, "")
		}
		idx := m.Selected()
		switch {
		case idx == len(items)-1:
			return pushTopMenu(r, dir, "")
		case idx < len(existing):
			return pushGroupVarsEditor(r, dir, filepath.Join(targetDir, existing[idx]), "")
		case idx < len(existing)+len(nestedExisting):
			ex := nestedExisting[idx-len(existing)]
			dst := filepath.Join(targetDir, ex.DestRel)
			return pushGroupVarsFilePicker(r, dir, fmt.Sprintf(
				"ℹ️  %s 是巢狀清單設定，pilot edit 目前不支援結構化編輯，請直接用文字編輯器修改。", dst))
		case idx < len(existing)+len(nestedExisting)+len(missingExamples):
			stem := missingExamples[idx-len(existing)-len(nestedExisting)]
			src := filepath.Join(exampleDir, stem+".example.yml")
			dst := filepath.Join(targetDir, stem+".yml")
			data, rerr := os.ReadFile(src)
			if rerr != nil {
				r.err = fmt.Errorf("read %s: %w", src, rerr)
				return nil
			}
			data = autofillCrossRoleHostVars(hf, data)
			if merr := os.MkdirAll(targetDir, 0o755); merr != nil {
				r.err = fmt.Errorf("mkdir %s: %w", targetDir, merr)
				return nil
			}
			if werr := os.WriteFile(dst, data, 0o644); werr != nil {
				r.err = fmt.Errorf("write %s: %w", dst, werr)
				return nil
			}
			return pushGroupVarsEditor(r, dir, dst, fmt.Sprintf("已從 %s 建立 %s", src, dst))
		default:
			ex := nestedMissing[idx-len(existing)-len(nestedExisting)-len(missingExamples)]
			src := filepath.Join(exampleDir, ex.ExampleRel)
			dst := filepath.Join(targetDir, ex.DestRel)
			data, rerr := os.ReadFile(src)
			if rerr != nil {
				r.err = fmt.Errorf("read %s: %w", src, rerr)
				return nil
			}
			if merr := os.MkdirAll(filepath.Dir(dst), 0o755); merr != nil {
				r.err = fmt.Errorf("mkdir %s: %w", filepath.Dir(dst), merr)
				return nil
			}
			if werr := os.WriteFile(dst, data, 0o644); werr != nil {
				r.err = fmt.Errorf("write %s: %w", dst, werr)
				return nil
			}
			return pushGroupVarsFilePicker(r, dir, fmt.Sprintf(
				"已從 %s 建立 %s — 這是巢狀清單設定，pilot edit 目前不支援結構化編輯，請直接用文字編輯器修改。", src, dst))
		}
	})
}

// tryLoadHostsFile best-effort loads <dir>/hosts.yml for the role-usage
// filtering/autofill above — nil (not an error) if it doesn't exist yet or
// fails to parse, since group_vars/ can legitimately be edited before
// hosts.yml exists at all.
func tryLoadHostsFile(dir string) *inventory.HostsFile {
	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		return nil
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		return nil
	}
	return hf
}

// filterStemsToUsedRoles keeps only the stems that correspond to a role
// actually assigned to some host in hf.
func filterStemsToUsedRoles(stems []string, hf *inventory.HostsFile) []string {
	used := make(map[string]bool)
	for _, stem := range inventory.GroupVarsStemsForRoles(inventory.UsedRoles(hf)) {
		used[stem] = true
	}
	out := make([]string, 0, len(stems))
	for _, stem := range stems {
		if used[stem] {
			out = append(out, stem)
		}
	}
	return out
}

// groupVarsAutoHostVars is the cross-role host-pointer catalog consulted
// when scaffolding a brand-new group_vars/<stem>.yml from its .example.yml
// template: the same Var/Group pairs `pilot deploy`'s -e auto-detection
// already trusts (siteAutoHostVars, deploy_catalog.go), plus
// freeipa_server_ip (role freeipa-server) — a group_vars-only setting that
// never appears as a deploy-time -e, so it isn't in that catalog.
func groupVarsAutoHostVars() []autoHostVar {
	return append([]autoHostVar{
		{Var: "freeipa_server_ip", Group: "freeipa-server", Label: "FreeIPA server"},
	}, siteAutoHostVars()...)
}

// resolveSingleRoleHost returns the sole host in hf carrying role, or
// ("", false) if zero or more than one host has it — an ambiguous match is
// left blank for a human to fill in rather than guessed.
func resolveSingleRoleHost(hf *inventory.HostsFile, role string) (string, bool) {
	if hf == nil {
		return "", false
	}
	var match *inventory.Host
	for i := range hf.Hosts {
		if !hasRole(hf.Hosts[i].Roles, role) {
			continue
		}
		if match != nil {
			return "", false // ambiguous: more than one candidate host
		}
		match = &hf.Hosts[i]
	}
	if match == nil || match.AnsibleHost == "" {
		return "", false
	}
	return match.AnsibleHost, true
}

// autofillCrossRoleHostVars pre-fills any commented-out example line whose
// key is a known cross-role host pointer (groupVarsAutoHostVars) and whose
// target role resolves unambiguously in hf — the one case safe to write for
// real, since the value is fully derived, not guessed. Every other line —
// including that same key when its role is ambiguous or absent — is left
// exactly as the shipped example wrote it.
func autofillCrossRoleHostVars(hf *inventory.HostsFile, data []byte) []byte {
	if hf == nil {
		return data
	}
	doc := groupvars.Parse(data)
	for _, entry := range doc.Entries() {
		// An active non-empty value is a user override. An empty value has no
		// usable destination and can safely receive an unambiguous inventory
		// default, just like an inactive example line.
		if entry.Active && strings.TrimSpace(entry.Value) != "" {
			continue
		}
		for _, av := range groupVarsAutoHostVars() {
			if av.Var != entry.Key {
				continue
			}
			if host, ok := resolveSingleRoleHost(hf, av.Group); ok {
				_ = doc.SetValue(entry.Line, host)
			}
		}
	}
	return doc.Bytes()
}

// groupVarsFilesInWorkspace lists every real (non-`.example.yml`)
// group_vars/*.yml file under dir (the workspace root) — the same file set
// pilot edit's file picker offers for editing.
func groupVarsFilesInWorkspace(dir string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "group_vars", "*.yml"))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if strings.HasSuffix(m, ".example.yml") {
			continue
		}
		out = append(out, m)
	}
	return out, nil
}

// groupVarsKeyAlreadyConfigured reports whether key already has a real,
// active value in every group_vars/*.yml file that mentions it at all —
// i.e. whether pilot deploy's "偵測到...這次要用它嗎？" auto-detect prompt
// for this var would be entirely redundant. A key absent from every
// group_vars file is NOT considered configured (nothing to trust yet, fall
// back to the existing prompt).
func groupVarsKeyAlreadyConfigured(dir, key string) (bool, error) {
	files, err := groupVarsFilesInWorkspace(dir)
	if err != nil {
		return false, err
	}
	found := false
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return false, err
		}
		for _, entry := range groupvars.Parse(data).Entries() {
			if entry.Key != key {
				continue
			}
			found = true
			if !entry.Active || strings.TrimSpace(entry.Value) == "" {
				return false, nil
			}
		}
	}
	return found, nil
}

// persistAutoHostVarToGroupVars writes value into key's line in every
// group_vars/*.yml file that already has key as an entry (active or still
// commented-out), activating/overwriting it in place — same "one real
// value pilot can already see" motivation as autofillCrossRoleHostVars,
// just triggered after a deploy actually succeeds using that value rather
// than at file-creation time, so it also covers a workspace whose
// group_vars were instead backfilled via `pilot inventory generate`'s
// verbatim-copy path (which does not call autofillCrossRoleHostVars).
// Called only post-success: what's being persisted is proven-good, and
// groupVarsKeyAlreadyConfigured will see it configured on the next run.
func persistAutoHostVarToGroupVars(out io.Writer, dir, key, value string) error {
	files, err := groupVarsFilesInWorkspace(dir)
	if err != nil {
		return err
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		doc := groupvars.Parse(data)
		changed := false
		for _, entry := range doc.Entries() {
			if entry.Key != key || (entry.Active && entry.Value == value) {
				continue
			}
			if err := doc.SetValue(entry.Line, value); err != nil {
				return fmt.Errorf("set %s in %s: %w", key, f, err)
			}
			changed = true
		}
		if !changed {
			continue
		}
		if err := os.WriteFile(f, doc.Bytes(), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", f, err)
		}
		fmt.Fprintf(out, "ℹ️  已將 %s=%s 寫入 %s，下次不用再問\n", key, value, f)
	}
	return nil
}

func pushGroupVarsEditor(r *editRouterModel, dir, path, banner string) tea.Cmd {
	data, err := os.ReadFile(path)
	if err != nil {
		r.err = fmt.Errorf("read %s: %w", path, err)
		return nil
	}
	doc := groupvars.Parse(data)
	return pushGroupVarsEditorScreen(r, dir, path, doc, false, banner)
}

func pushGroupVarsEditorScreen(r *editRouterModel, dir, path string, doc *groupvars.Doc, dirty bool, banner string) tea.Cmd {
	entries := doc.Entries()
	listEntries := doc.ListEntries()
	items := make([]string, 0, len(entries)+len(listEntries)+2)
	for _, e := range entries {
		state := "已設定"
		if !e.Active {
			state = "未設定，使用內建預設"
		}
		items = append(items, fmt.Sprintf("%s = %s  [%s]", e.Key, e.Value, state))
	}
	for _, e := range listEntries {
		state := "已設定"
		if !e.Active {
			state = "未設定，使用內建預設"
		}
		items = append(items, fmt.Sprintf("%s = [%s]  [%s]", e.Key, strings.Join(e.Values, ", "), state))
	}
	items = append(items, "💾 存檔並離開", "🚪 不存檔離開")

	// A block-scalar key (e.g. alertmanager_config: |) or a flow-map key
	// (e.g. "labels: {a: 1}") is deliberately never offered as an item
	// above — Entries() excludes both because editing them here would
	// corrupt the file (see groupvars.Doc.Entries). Surface them instead
	// of silently disappearing. Flow lists get their own editable rows
	// below instead of this note — see ListEntries().
	if keys := doc.BlockScalarKeys(); len(keys) > 0 {
		note := fmt.Sprintf("ℹ️  %s 是多行 YAML 設定，pilot edit 不支援在這裡編輯，請直接改檔案 %s。", strings.Join(keys, "、"), path)
		if banner == "" {
			banner = note
		} else {
			banner += "\n" + note
		}
	}
	if keys := doc.FlowMapKeys(); len(keys) > 0 {
		note := fmt.Sprintf("ℹ️  %s 是巢狀設定(map)，pilot edit 不支援在這裡編輯，請直接改檔案 %s。", strings.Join(keys, "、"), path)
		if banner == "" {
			banner = note
		} else {
			banner += "\n" + note
		}
	}

	title := fmt.Sprintf("編輯 %s", path)
	return r.transitionTo(newSelectModelWithScreenID("group_vars.entries", title, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			// mirrors "🚪 不存檔離開" exactly, including its dirty gate.
			if !dirty {
				return pushGroupVarsFilePicker(r, dir, "")
			}
			return pushConfirmDiscardGroupVars(r, dir, path, doc)
		}
		idx := m.Selected()
		switch {
		case idx == len(items)-2:
			if err := os.WriteFile(path, doc.Bytes(), 0o644); err != nil {
				r.err = fmt.Errorf("write %s: %w", path, err)
				return nil
			}
			return pushGroupVarsFilePicker(r, dir, fmt.Sprintf("✅ 已存檔 %s", path))
		case idx == len(items)-1:
			if !dirty {
				return pushGroupVarsFilePicker(r, dir, "")
			}
			return pushConfirmDiscardGroupVars(r, dir, path, doc)
		case idx < len(entries):
			return pushGroupVarsEntryMenu(r, dir, path, doc, entries[idx], dirty)
		default:
			return pushGroupVarsListEntryMenu(r, dir, path, doc, listEntries[idx-len(entries)], dirty)
		}
	})
}

func pushConfirmDiscardGroupVars(r *editRouterModel, dir, path string, doc *groupvars.Doc) tea.Cmd {
	return r.transitionTo(newConfirmModelWithScreenID("confirm.discard", "有未存檔的修改，確定要放棄離開嗎？", false), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.ConfirmScreen)
		if m.Value() {
			return pushGroupVarsFilePicker(r, dir, "")
		}
		return pushGroupVarsEditorScreen(r, dir, path, doc, true, "")
	})
}

func pushGroupVarsEntryMenu(r *editRouterModel, dir, path string, doc *groupvars.Doc, e groupvars.Entry, dirty bool) tea.Cmd {
	title := fmt.Sprintf("%s 目前值：%s", e.Key, e.Value)
	banner := ""
	if e.Description != "" {
		banner = "──────────────────────────────────\n" + e.Description + "\n──────────────────────────────────"
	}
	items := []string{"修改值", "還原成內建預設(取消設定)", "返回"}
	return r.transitionTo(newSelectModelWithScreenID("group_vars.entry_action", title, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			// mirrors "返回" (case 2).
			return pushGroupVarsEditorScreen(r, dir, path, doc, dirty, "")
		}
		switch m.Selected() {
		case 0:
			return pushGroupVarsEditValue(r, dir, path, doc, e, dirty)
		case 1:
			if err := doc.CommentOut(e.Line); err != nil {
				r.err = err
				return nil
			}
			return pushGroupVarsEditorScreen(r, dir, path, doc, true, "")
		case 2:
			return pushGroupVarsEditorScreen(r, dir, path, doc, dirty, "")
		}
		return nil
	})
}

func pushGroupVarsEditValue(r *editRouterModel, dir, path string, doc *groupvars.Doc, e groupvars.Entry, dirty bool) tea.Cmd {
	label := fmt.Sprintf("%s 的新值", e.Key)
	return r.transitionTo(newTextInputModel(label, e.Value, nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushGroupVarsEntryMenu(r, dir, path, doc, e, dirty)
		}
		if err := doc.SetValue(e.Line, m.Value()); err != nil {
			r.err = err
			return nil
		}
		return pushGroupVarsEditorScreen(r, dir, path, doc, true, "")
	})
}

// ---- flow-list ("key: [a, b]") entries ------------------------------------
//
// Every mutation (add/remove/edit an item) returns straight to
// pushGroupVarsEditorScreen for a fresh re-render, the same convention the
// scalar entry flow above already uses (pushGroupVarsEditValue does the
// same) — it avoids ever holding a stale groupvars.ListEntry across a
// SetList call, since Entry.Line stays valid (SetList only ever rewrites
// that one line) but .Values would otherwise go stale.

func pushGroupVarsListEntryMenu(r *editRouterModel, dir, path string, doc *groupvars.Doc, e groupvars.ListEntry, dirty bool) tea.Cmd {
	title := fmt.Sprintf("%s 目前有 %d 個項目：[%s]", e.Key, len(e.Values), strings.Join(e.Values, ", "))
	banner := ""
	if e.Description != "" {
		banner = "──────────────────────────────────\n" + e.Description + "\n──────────────────────────────────"
	}
	items := []string{"編輯清單項目", "還原成內建預設(取消設定)", "返回"}
	return r.transitionTo(newSelectModelWithScreenID("group_vars.list_entry_action", title, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			// mirrors "返回" (case 2).
			return pushGroupVarsEditorScreen(r, dir, path, doc, dirty, "")
		}
		switch m.Selected() {
		case 0:
			return pushGroupVarsListItemsMenu(r, dir, path, doc, e, dirty)
		case 1:
			if err := doc.CommentOut(e.Line); err != nil {
				r.err = err
				return nil
			}
			return pushGroupVarsEditorScreen(r, dir, path, doc, true, "")
		case 2:
			return pushGroupVarsEditorScreen(r, dir, path, doc, dirty, "")
		}
		return nil
	})
}

func pushGroupVarsListItemsMenu(r *editRouterModel, dir, path string, doc *groupvars.Doc, e groupvars.ListEntry, dirty bool) tea.Cmd {
	items := make([]string, 0, len(e.Values)+2)
	items = append(items, e.Values...)
	items = append(items, "➕ 新增項目", "↩  返回")

	title := fmt.Sprintf("%s 的項目", e.Key)
	return r.transitionTo(newSelectModelWithScreenID("group_vars.list_items", title, items), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			// mirrors the trailing "↩ 返回" item.
			return pushGroupVarsListEntryMenu(r, dir, path, doc, e, dirty)
		}
		idx := m.Selected()
		switch {
		case idx == len(items)-1:
			return pushGroupVarsListEntryMenu(r, dir, path, doc, e, dirty)
		case idx == len(items)-2:
			return pushGroupVarsAddListItem(r, dir, path, doc, e, dirty)
		default:
			return pushGroupVarsListItemAction(r, dir, path, doc, e, idx, dirty)
		}
	})
}

func pushGroupVarsAddListItem(r *editRouterModel, dir, path string, doc *groupvars.Doc, e groupvars.ListEntry, dirty bool) tea.Cmd {
	return r.transitionTo(newTextInputModel("新項目的值", "", nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushGroupVarsListItemsMenu(r, dir, path, doc, e, dirty)
		}
		newValues := append(append([]string{}, e.Values...), m.Value())
		if err := doc.SetList(e.Line, newValues); err != nil {
			r.err = err
			return nil
		}
		return pushGroupVarsEditorScreen(r, dir, path, doc, true, "")
	})
}

func pushGroupVarsListItemAction(r *editRouterModel, dir, path string, doc *groupvars.Doc, e groupvars.ListEntry, itemIdx int, dirty bool) tea.Cmd {
	title := fmt.Sprintf("%s 項目：%s", e.Key, e.Values[itemIdx])
	items := []string{"修改值", "移除", "返回"}
	return r.transitionTo(newSelectModelWithScreenID("group_vars.list_item_action", title, items), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			// mirrors "返回" (case 2).
			return pushGroupVarsListItemsMenu(r, dir, path, doc, e, dirty)
		}
		switch m.Selected() {
		case 0:
			return pushGroupVarsEditListItemValue(r, dir, path, doc, e, itemIdx, dirty)
		case 1:
			newValues := append(append([]string{}, e.Values[:itemIdx]...), e.Values[itemIdx+1:]...)
			if err := doc.SetList(e.Line, newValues); err != nil {
				r.err = err
				return nil
			}
			return pushGroupVarsEditorScreen(r, dir, path, doc, true, "")
		case 2:
			return pushGroupVarsListItemsMenu(r, dir, path, doc, e, dirty)
		}
		return nil
	})
}

func pushGroupVarsEditListItemValue(r *editRouterModel, dir, path string, doc *groupvars.Doc, e groupvars.ListEntry, itemIdx int, dirty bool) tea.Cmd {
	label := fmt.Sprintf("%s 第 %d 項的新值", e.Key, itemIdx+1)
	return r.transitionTo(newTextInputModel(label, e.Values[itemIdx], nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushGroupVarsListItemAction(r, dir, path, doc, e, itemIdx, dirty)
		}
		newValues := append([]string{}, e.Values...)
		newValues[itemIdx] = m.Value()
		if err := doc.SetList(e.Line, newValues); err != nil {
			r.err = err
			return nil
		}
		return pushGroupVarsEditorScreen(r, dir, path, doc, true, "")
	})
}
