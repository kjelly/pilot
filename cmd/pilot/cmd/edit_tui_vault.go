// edit_tui_vault.go implements the .vault/ screens of the `pilot edit`
// router (edit_tui.go): file picker, the plaintext-skeleton key-list
// editor built on internal/vaultfile, and the ansible-vault-encrypted
// case — which suspends the router's Program via tea.ExecProcess to
// run the real `ansible-vault edit` with stdio wired straight to the
// terminal, since that must never run while the Program also thinks
// it owns the terminal.
package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/kjelly/pilot/internal/vaultfile"
)

func pushVaultFilePicker(r *editRouterModel, dir, banner string) tea.Cmd {
	targetDir := filepath.Join(dir, ".vault")
	files, err := scanVaultFiles(targetDir)
	if err != nil {
		r.err = err
		return nil
	}

	items := make([]string, 0, len(files)+2)
	for _, f := range files {
		items = append(items, "📝 "+f)
	}
	items = append(items, "📍 輸入其他 vault 檔路徑", "↩  返回")

	title := fmt.Sprintf("選一個 %s 底下的 vault 檔", targetDir)
	return r.transitionTo(newSelectModel(title, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return quitWizard(r)
		}
		idx := m.Selected()
		switch {
		case idx == len(items)-1:
			return pushTopMenu(r, dir, "")
		case idx < len(files):
			return pushVaultOpen(r, dir, filepath.Join(targetDir, files[idx]))
		default:
			return pushVaultPathPrompt(r, dir, targetDir)
		}
	})
}

func pushVaultPathPrompt(r *editRouterModel, dir, targetDir string) tea.Cmd {
	def := filepath.Join(targetDir, "main.yaml")
	return r.transitionTo(newTextInputModel("vault 檔路徑", def, nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return quitWizard(r)
		}
		return pushVaultOpen(r, dir, strings.TrimSpace(m.Value()))
	})
}

// pushVaultOpen reads path and decides what screen comes next: a
// missing file offers to create a blank skeleton; an
// ansible-vault-encrypted file suspends the Program and shells out to
// the real editor; a plaintext skeleton opens the key-list editor.
func pushVaultOpen(r *editRouterModel, dir, path string) tea.Cmd {
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			r.err = fmt.Errorf("read %s: %w", path, err)
			return nil
		}
		question := fmt.Sprintf("%s 不存在，要建立新的明文 vault 檔嗎？", path)
		return r.transitionTo(newConfirmModel(question, true), "", func(r *editRouterModel, s screen) tea.Cmd {
			m := s.(confirmModel)
			if !m.Value() {
				return pushVaultFilePicker(r, dir, "")
			}
			if merr := os.MkdirAll(filepath.Dir(path), 0o700); merr != nil {
				r.err = fmt.Errorf("mkdir %s: %w", filepath.Dir(path), merr)
				return nil
			}
			skeleton := []byte("---\n")
			if werr := os.WriteFile(path, skeleton, 0o600); werr != nil {
				r.err = fmt.Errorf("write %s: %w", path, werr)
				return nil
			}
			return pushVaultEditorFromData(r, dir, path, skeleton, fmt.Sprintf("已建立 %s", path))
		})
	}
	return pushVaultEditorFromData(r, dir, path, data, "")
}

func pushVaultEditorFromData(r *editRouterModel, dir, path string, data []byte, banner string) tea.Cmd {
	if isAnsibleVaultEncrypted(data) {
		return pushAnsibleVaultShellout(r, dir, path)
	}
	doc, err := vaultfile.Parse(data)
	if err != nil {
		r.err = fmt.Errorf("%s 解析失敗: %w", path, err)
		return nil
	}
	if !doc.Editable() {
		r.err = fmt.Errorf("%s 是複雜 YAML（例如 roster/list/nested map）；目前 `pilot edit` 只支援編輯 top-level scalar 的明文 vault skeleton，請改用文字編輯器或先加密後走 ansible-vault edit", path)
		return nil
	}
	if len(doc.Entries()) == 0 {
		empty := "目前是空的 vault 檔。先新增一個 key。"
		if banner == "" {
			banner = empty
		} else {
			banner += "\n" + empty
		}
	}
	return pushVaultEditorScreen(r, dir, path, doc, false, banner)
}

// vaultShelloutDoneMsg is delivered by tea.ExecProcess's callback once
// `ansible-vault edit`'s subprocess exits and the router's Program
// resumes control of the terminal — special-cased directly in
// editRouterModel.Update (edit_tui.go) since it's not something any
// individual screen should have to know how to handle.
type vaultShelloutDoneMsg struct {
	dir string
	err error
}

// pushAnsibleVaultShellout suspends the router's Program to run the
// real `ansible-vault edit` with stdio wired directly to the
// terminal, then resumes and returns to the vault file picker —
// matching the pre-rewrite behavior, where this entirely bypassed the
// wizard's own key-list UI.
func pushAnsibleVaultShellout(r *editRouterModel, dir, path string) tea.Cmd {
	r.banner = fmt.Sprintf("偵測到 %s 是 ansible-vault 加密檔，改用 `ansible-vault edit`。", path)
	bin, lookErr := exec.LookPath("ansible-vault")
	if lookErr != nil {
		r.err = fmt.Errorf("ansible-vault 不在 PATH 上: %w", lookErr)
		return nil
	}
	cmd := exec.Command(bin, "edit", path)
	return tea.ExecProcess(cmd, func(err error) tea.Msg {
		if err != nil {
			err = fmt.Errorf("ansible-vault edit %s: %w", path, err)
		}
		return vaultShelloutDoneMsg{dir: dir, err: err}
	})
}

func pushVaultEditorScreen(r *editRouterModel, dir, path string, doc *vaultfile.Doc, dirty bool, banner string) tea.Cmd {
	entries := doc.Entries()
	items := make([]string, 0, len(entries)+3)
	for _, e := range entries {
		items = append(items, fmt.Sprintf("%s = %s", e.Key, truncateForErr(e.DisplayValue(), 80)))
	}
	items = append(items, "➕ 新增 key", "💾 存檔並離開", "🚪 不存檔離開")

	title := fmt.Sprintf("編輯 %s", path)
	return r.transitionTo(newSelectModel(title, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return quitWizard(r)
		}
		idx := m.Selected()
		switch {
		case idx == len(items)-3:
			return pushVaultAddKey(r, dir, path, doc, dirty)
		case idx == len(items)-2:
			if merr := os.MkdirAll(filepath.Dir(path), 0o700); merr != nil {
				r.err = fmt.Errorf("mkdir %s: %w", filepath.Dir(path), merr)
				return nil
			}
			if werr := os.WriteFile(path, doc.Bytes(), 0o600); werr != nil {
				r.err = fmt.Errorf("write %s: %w", path, werr)
				return nil
			}
			return pushVaultFilePicker(r, dir, fmt.Sprintf("✅ 已存檔 %s", path))
		case idx == len(items)-1:
			if !dirty {
				return pushVaultFilePicker(r, dir, "")
			}
			return pushConfirmDiscardVault(r, dir, path, doc)
		default:
			return pushVaultEntryMenu(r, dir, path, doc, entries[idx], dirty)
		}
	})
}

func pushConfirmDiscardVault(r *editRouterModel, dir, path string, doc *vaultfile.Doc) tea.Cmd {
	return r.transitionTo(newConfirmModel("有未存檔的修改，確定要放棄離開嗎？", false), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(confirmModel)
		if m.Value() {
			return pushVaultFilePicker(r, dir, "")
		}
		return pushVaultEditorScreen(r, dir, path, doc, true, "")
	})
}

func pushVaultAddKey(r *editRouterModel, dir, path string, doc *vaultfile.Doc, dirty bool) tea.Cmd {
	validate := func(s string) error {
		s = strings.TrimSpace(s)
		if s == "" {
			return fmt.Errorf("不能留空")
		}
		if doc.HasKey(s) {
			return fmt.Errorf("key %q 已存在", s)
		}
		return nil
	}
	return r.transitionTo(newTextInputModel("新的 key 名稱", "", validate), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return quitWizard(r)
		}
		key := strings.TrimSpace(m.Value())
		return pushVaultAddKeyValue(r, dir, path, doc, key, dirty)
	})
}

func pushVaultAddKeyValue(r *editRouterModel, dir, path string, doc *vaultfile.Doc, key string, dirty bool) tea.Cmd {
	return r.transitionTo(newSecretTextInputModel("值（多行請直接輸入 \\n）", "", nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return quitWizard(r)
		}
		doc.Add(key, strings.ReplaceAll(m.Value(), `\n`, "\n"))
		return pushVaultEditorScreen(r, dir, path, doc, true, "")
	})
}

func pushVaultEntryMenu(r *editRouterModel, dir, path string, doc *vaultfile.Doc, entry vaultfile.Entry, dirty bool) tea.Cmd {
	title := fmt.Sprintf("%s 目前值：%s", entry.Key, truncateForErr(entry.DisplayValue(), 120))
	items := []string{"修改值", "刪除", "返回"}
	return r.transitionTo(newSelectModel(title, items), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return quitWizard(r)
		}
		switch m.Selected() {
		case 0:
			return pushVaultEditValue(r, dir, path, doc, entry, dirty)
		case 1:
			doc.Delete(entry.Key)
			return pushVaultEditorScreen(r, dir, path, doc, true, "")
		case 2:
			return pushVaultEditorScreen(r, dir, path, doc, dirty, "")
		}
		return nil
	})
}

func pushVaultEditValue(r *editRouterModel, dir, path string, doc *vaultfile.Doc, entry vaultfile.Entry, dirty bool) tea.Cmd {
	label := fmt.Sprintf("%s 的新值（多行請直接輸入 \\n）", entry.Key)
	return r.transitionTo(newSecretTextInputModel(label, entry.EditValue(), nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return quitWizard(r)
		}
		doc.Set(entry.Key, strings.ReplaceAll(m.Value(), `\n`, "\n"))
		return pushVaultEditorScreen(r, dir, path, doc, true, "")
	})
}
