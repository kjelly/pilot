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

	"github.com/anomalyco/pilot/internal/groupvars"
)

// pushGroupVarsFilePicker lists group_vars files under <dir>/group_vars
// — the actual settings files being edited — but always offers to
// seed a missing one from the fixed, CWD-relative
// group_vars/*.example.yml templates (same split as inventory.go's
// copyMissingGroupVars: the shipped example templates live in one
// fixed place; the files this wizard reads/writes follow --dir).
func pushGroupVarsFilePicker(r *editRouterModel, dir, banner string) tea.Cmd {
	targetDir := filepath.Join(dir, "group_vars")
	exampleDir := "group_vars"

	existing, missingExamples, err := scanGroupVars(targetDir, exampleDir)
	if err != nil {
		r.err = err
		return nil
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
			return quitWizard(r)
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
			return quitWizard(r)
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
			return quitWizard(r)
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
			return quitWizard(r)
		}
		if err := doc.SetValue(e.Line, m.Value()); err != nil {
			r.err = err
			return nil
		}
		return pushGroupVarsEditorScreen(r, dir, path, doc, true, "")
	})
}
