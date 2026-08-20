// edit_tui_hostvars.go implements the host_vars/<host>.yml screen of the
// `pilot edit` router (edit_tui.go). Unlike group_vars (edit_tui_groupvars.go
// — shared across a role, picked from a file list), host_vars here is
// host-scoped: exactly one file per host, holding only the vars that have no
// safe cross-host default (see internal/inventory/hostvars.go, e.g.
// prometheus_site_label). pushHostMenu only shows this screen's menu item
// when the host's current roles actually need it.
//
// The file is auto-scaffolded from inventory.GenerateHostVarsSkeleton on
// first entry if missing (same placeholder-only, never-invent-a-real-value
// rule as the vault skeleton), then reuses internal/groupvars' Doc editor
// as-is — the file shape ("key: value" plus a comment) is identical to a
// group_vars file. The one deliberate difference from the group_vars entry
// menu: there is no "還原成內建預設" option here, because these keys have no
// built-in default to fall back to — that's the entire reason they live in
// host_vars instead of group_vars.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/kjelly/pilot/internal/groupvars"
	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/tui"
)

func hostVarsPath(dir, name string) string {
	return filepath.Join(dir, "host_vars", name+".yml")
}

// loadOrScaffoldHostVarsDoc loads host_vars/<h.Name>.yml, scaffolding it from
// inventory.GenerateHostVarsSkeleton first if it doesn't exist yet. doc==nil
// with a nil error means h's current roles need no host_vars key at all —
// callers decide their own fallback for that case.
func loadOrScaffoldHostVarsDoc(dir string, h *inventory.Host) (path string, doc *groupvars.Doc, banner string, err error) {
	dst := hostVarsPath(dir, h.Name)
	if _, statErr := os.Stat(dst); statErr != nil {
		if !os.IsNotExist(statErr) {
			return "", nil, "", fmt.Errorf("stat %s: %w", dst, statErr)
		}
		rendered, ok := inventory.GenerateHostVarsSkeleton(*h)
		if !ok {
			return "", nil, "", nil
		}
		if merr := os.MkdirAll(filepath.Dir(dst), 0o755); merr != nil {
			return "", nil, "", fmt.Errorf("mkdir %s: %w", filepath.Dir(dst), merr)
		}
		if werr := os.WriteFile(dst, []byte(rendered), 0o644); werr != nil {
			return "", nil, "", fmt.Errorf("write %s: %w", dst, werr)
		}
		banner = fmt.Sprintf("已建立 %s", dst)
	}
	data, err := os.ReadFile(dst)
	if err != nil {
		return "", nil, "", fmt.Errorf("read %s: %w", dst, err)
	}
	return dst, groupvars.Parse(data), banner, nil
}

// newHostVarsKeys returns the host_vars keys that after (the host's roles
// post-edit) requires but before (its roles pre-edit) did not — i.e. keys a
// just-added role newly introduced.
func newHostVarsKeys(before, after []string) []string {
	beforeSet := map[string]bool{}
	for _, k := range inventory.HostVarsKeysForRoles(before) {
		beforeSet[k] = true
	}
	var out []string
	for _, k := range inventory.HostVarsKeysForRoles(after) {
		if !beforeSet[k] {
			out = append(out, k)
		}
	}
	return out
}

// missingHostVarsKeys filters keys down to the ones that are still blank in
// h — checked the same two places checkHostVarsCompleteness (workspace_
// completeness.go) reads a value from: hosts.yml's per-host extra vars, or
// host_vars/<h.Name>.yml.
func missingHostVarsKeys(dir string, h inventory.Host, keys []string) []string {
	fileValues, _ := readYAMLMap(hostVarsPath(dir, h.Name))
	var missing []string
	for _, k := range keys {
		if strings.TrimSpace(h.Extra[k]) != "" {
			continue
		}
		v, _ := fileValues[k].(string)
		if strings.TrimSpace(v) == "" {
			missing = append(missing, k)
		}
	}
	return missing
}

// pushForcedHostVarsPrompt generalizes freeipa-nfs-server's own forced
// roster-password prompt (pushNFSRoleBootstrap) to every role in
// hostVarsKeyCatalog: when a role just added via the checklist/preset/copy
// screens introduces a host_vars key with no safe default that's still
// blank, it jumps straight into that key's text input instead of leaving the
// user to notice the new host-menu item on their own (the original gap:
// checking "prometheus" alone gave zero feedback that prometheus_site_label
// now needed a value). Returns nil when nothing newly requires attention, so
// callers fall through to their normal follow-up screen.
func pushForcedHostVarsPrompt(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name string, beforeRoles []string) tea.Cmd {
	h := findHost(hf, name)
	if h == nil {
		return nil
	}
	newKeys := newHostVarsKeys(beforeRoles, h.Roles)
	if len(newKeys) == 0 {
		return nil
	}
	missing := missingHostVarsKeys(dir, *h, newKeys)
	if len(missing) == 0 {
		return nil
	}
	hvPath, doc, banner, err := loadOrScaffoldHostVarsDoc(dir, h)
	if err != nil {
		r.err = err
		return nil
	}
	if doc == nil {
		return nil
	}
	return pushForcedHostVarsPromptChain(r, dir, path, hf, name, hvPath, doc, missing, banner)
}

// forcedHostVarsPromptScreenIDPrefix identifies a pushForcedHostVarsPromptChain
// text-input screen to the automation driver (setRoleChecked's
// resolveRoleChecklistFollowUp, edit_automation_driver.go), which needs to
// tell this forced prompt apart from any other text-input screen and recover
// which host_vars key it's asking for — the screenID carries the key rather
// than the (presentation-facing, freely rewordable) label.
const forcedHostVarsPromptScreenIDPrefix = "host_vars.forced_prompt:"

func forcedHostVarsPromptScreenID(key string) string {
	return forcedHostVarsPromptScreenIDPrefix + key
}

// forcedHostVarsPromptKey extracts the host_vars key from a screen ID built
// by forcedHostVarsPromptScreenID, e.g. for automation driving that screen.
func forcedHostVarsPromptKey(screenID string) (string, bool) {
	if !strings.HasPrefix(screenID, forcedHostVarsPromptScreenIDPrefix) {
		return "", false
	}
	return strings.TrimPrefix(screenID, forcedHostVarsPromptScreenIDPrefix), true
}

// pushForcedHostVarsPromptChain walks remaining one text-input at a time,
// then lands on the normal list editor (dirty=true) so the user still gets
// an explicit save/discard choice, exactly like a manually-opened session.
func pushForcedHostVarsPromptChain(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name, hvPath string, doc *groupvars.Doc, remaining []string, banner string) tea.Cmd {
	if len(remaining) == 0 {
		return pushHostVarsEditorScreen(r, dir, path, hf, name, hvPath, doc, true, "")
	}
	key := remaining[0]
	for _, e := range doc.Entries() {
		if e.Key != key {
			continue
		}
		prompt := strings.TrimSpace(banner + "\n" + e.Description)
		label := fmt.Sprintf("角色需要新設定：%s 的新值", e.Key)
		return r.transitionTo(newTextInputModelWithScreenID(forcedHostVarsPromptScreenID(e.Key), label, e.Value, nil), prompt, func(r *editRouterModel, s screen) tea.Cmd {
			m := s.(tui.InputScreen)
			if !m.Canceled() {
				if err := doc.SetValue(e.Line, m.Value()); err != nil {
					r.err = err
					return nil
				}
			}
			return pushForcedHostVarsPromptChain(r, dir, path, hf, name, hvPath, doc, remaining[1:], "")
		})
	}
	return pushForcedHostVarsPromptChain(r, dir, path, hf, name, hvPath, doc, remaining[1:], banner)
}

func pushHostVarsEditor(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name string) tea.Cmd {
	h := findHost(hf, name)
	if h == nil {
		return pushHostList(r, dir, path, hf, "")
	}
	dst, doc, banner, err := loadOrScaffoldHostVarsDoc(dir, h)
	if err != nil {
		r.err = err
		return nil
	}
	if doc == nil {
		// pushHostMenu only renders this screen's menu item when h's roles
		// need at least one host_vars key; getting here regardless means
		// roles changed since the menu was drawn — just fall back to it.
		return pushHostMenu(r, dir, path, hf, name)
	}
	return pushHostVarsEditorScreen(r, dir, path, hf, name, dst, doc, false, banner)
}

func pushHostVarsEditorScreen(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name, hvPath string, doc *groupvars.Doc, dirty bool, banner string) tea.Cmd {
	entries := doc.Entries()
	items := make([]string, 0, len(entries)+2)
	for _, e := range entries {
		// These keys have no built-in default (that's why they live in
		// host_vars, not group_vars), so — unlike the group_vars editor —
		// "set vs. not set" is judged by whether a real value has been
		// typed in, not by Active/commented-out state (a freshly
		// scaffolded key is always active, just empty).
		state := "已設定"
		if e.Value == "" {
			state = "尚未填寫，必填！"
		}
		items = append(items, fmt.Sprintf("%s = %s  [%s]", e.Key, e.Value, state))
	}
	items = append(items, "💾 存檔並離開", "🚪 不存檔離開")

	title := fmt.Sprintf("編輯 %s", hvPath)
	return r.transitionTo(newSelectModelWithScreenID("host_vars.entries", title, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			// mirrors "🚪 不存檔離開" exactly, including its dirty gate.
			if !dirty {
				return pushHostMenu(r, dir, path, hf, name)
			}
			return pushConfirmDiscardHostVars(r, dir, path, hf, name, hvPath, doc)
		}
		idx := m.Selected()
		switch {
		case idx == len(items)-2:
			if err := os.WriteFile(hvPath, doc.Bytes(), 0o644); err != nil {
				r.err = fmt.Errorf("write %s: %w", hvPath, err)
				return nil
			}
			return pushHostMenu(r, dir, path, hf, name)
		case idx == len(items)-1:
			if !dirty {
				return pushHostMenu(r, dir, path, hf, name)
			}
			return pushConfirmDiscardHostVars(r, dir, path, hf, name, hvPath, doc)
		default:
			return pushHostVarsEntryMenu(r, dir, path, hf, name, hvPath, doc, entries[idx], dirty)
		}
	})
}

func pushConfirmDiscardHostVars(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name, hvPath string, doc *groupvars.Doc) tea.Cmd {
	return r.transitionTo(newConfirmModelWithScreenID("confirm.discard", "有未存檔的修改，確定要放棄離開嗎？", false), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.ConfirmScreen)
		if m.Value() {
			return pushHostMenu(r, dir, path, hf, name)
		}
		return pushHostVarsEditorScreen(r, dir, path, hf, name, hvPath, doc, true, "")
	})
}

func pushHostVarsEntryMenu(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name, hvPath string, doc *groupvars.Doc, e groupvars.Entry, dirty bool) tea.Cmd {
	title := fmt.Sprintf("%s 目前值：%s", e.Key, e.Value)
	banner := ""
	if e.Description != "" {
		banner = "──────────────────────────────────\n" + e.Description + "\n──────────────────────────────────"
	}
	items := []string{"修改值", "返回"}
	return r.transitionTo(newSelectModelWithScreenID("host_vars.entry_action", title, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			// mirrors "返回" (case 1).
			return pushHostVarsEditorScreen(r, dir, path, hf, name, hvPath, doc, dirty, "")
		}
		switch m.Selected() {
		case 0:
			return pushHostVarsEditValue(r, dir, path, hf, name, hvPath, doc, e, dirty)
		case 1:
			return pushHostVarsEditorScreen(r, dir, path, hf, name, hvPath, doc, dirty, "")
		}
		return nil
	})
}

func pushHostVarsEditValue(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name, hvPath string, doc *groupvars.Doc, e groupvars.Entry, dirty bool) tea.Cmd {
	label := fmt.Sprintf("%s 的新值", e.Key)
	return r.transitionTo(newTextInputModel(label, e.Value, nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushHostVarsEntryMenu(r, dir, path, hf, name, hvPath, doc, e, dirty)
		}
		if err := doc.SetValue(e.Line, m.Value()); err != nil {
			r.err = err
			return nil
		}
		return pushHostVarsEditorScreen(r, dir, path, hf, name, hvPath, doc, true, "")
	})
}
