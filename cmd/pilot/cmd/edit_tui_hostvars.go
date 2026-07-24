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

	tea "github.com/charmbracelet/bubbletea"

	"github.com/kjelly/pilot/internal/groupvars"
	"github.com/kjelly/pilot/internal/inventory"
)

func hostVarsPath(dir, name string) string {
	return filepath.Join(dir, "host_vars", name+".yml")
}

func pushHostVarsEditor(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name string) tea.Cmd {
	h := findHost(hf, name)
	if h == nil {
		return pushHostList(r, dir, path, hf, "")
	}
	dst := hostVarsPath(dir, name)
	banner := ""
	if _, err := os.Stat(dst); err != nil {
		if !os.IsNotExist(err) {
			r.err = fmt.Errorf("stat %s: %w", dst, err)
			return nil
		}
		rendered, ok := inventory.GenerateHostVarsSkeleton(*h)
		if !ok {
			// pushHostMenu only renders this screen's menu item when true;
			// getting here regardless means roles changed since the menu
			// was drawn — just fall back to the host menu.
			return pushHostMenu(r, dir, path, hf, name)
		}
		if merr := os.MkdirAll(filepath.Dir(dst), 0o755); merr != nil {
			r.err = fmt.Errorf("mkdir %s: %w", filepath.Dir(dst), merr)
			return nil
		}
		if werr := os.WriteFile(dst, []byte(rendered), 0o644); werr != nil {
			r.err = fmt.Errorf("write %s: %w", dst, werr)
			return nil
		}
		banner = fmt.Sprintf("已建立 %s", dst)
	}
	data, err := os.ReadFile(dst)
	if err != nil {
		r.err = fmt.Errorf("read %s: %w", dst, err)
		return nil
	}
	doc := groupvars.Parse(data)
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
	return r.transitionTo(newSelectModel(title, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
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
	return r.transitionTo(newConfirmModel("有未存檔的修改，確定要放棄離開嗎？", false), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(confirmModel)
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
	return r.transitionTo(newSelectModel(title, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
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
		m := s.(textInputModel)
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
