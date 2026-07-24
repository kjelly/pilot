// edit_tui_groupvars.go implements the group_vars/ screens of the
// `pilot edit` router (edit_tui.go) — file picker (including "create
// from example") and the key-list editor built on internal/groupvars'
// already-clean Doc/Entry API.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/kjelly/pilot/internal/groupvars"
	"github.com/kjelly/pilot/internal/inventory"
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

	items := make([]string, 0, len(existing)+len(missingExamples)+1)
	for _, f := range existing {
		items = append(items, "📝 "+f)
	}
	for _, stem := range missingExamples {
		items = append(items, fmt.Sprintf("➕ 從範例建立 %s.yml", stem))
	}
	items = append(items, "↩  返回")

	title := fmt.Sprintf("選一個 %s 底下的檔案", targetDir)
	return r.transitionTo(newSelectModel(title, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
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
		default:
			stem := missingExamples[idx-len(existing)]
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
		if entry.Active {
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
	items := make([]string, 0, len(entries)+2)
	for _, e := range entries {
		state := "已設定"
		if !e.Active {
			state = "未設定，使用內建預設"
		}
		items = append(items, fmt.Sprintf("%s = %s  [%s]", e.Key, e.Value, state))
	}
	items = append(items, "💾 存檔並離開", "🚪 不存檔離開")

	title := fmt.Sprintf("編輯 %s", path)
	return r.transitionTo(newSelectModel(title, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
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
		default:
			return pushGroupVarsEntryMenu(r, dir, path, doc, entries[idx], dirty)
		}
	})
}

func pushConfirmDiscardGroupVars(r *editRouterModel, dir, path string, doc *groupvars.Doc) tea.Cmd {
	return r.transitionTo(newConfirmModel("有未存檔的修改，確定要放棄離開嗎？", false), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(confirmModel)
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
	return r.transitionTo(newSelectModel(title, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
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
		m := s.(textInputModel)
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
