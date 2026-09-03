// edit_tui_snmp_credentials.go implements the SNMP credentials screens of
// the `pilot edit` router: the secret half of SNMP configuration
// (snmp_exporter_credentials, group_vars/snmp-exporter.example.yml) that
// must live in a vault file, never in monitoring/snmp/catalog.yml (spec
// §6.4 rule 3). This intentionally reuses the .vault/ file picker
// convention from edit_tui_vault.go but edits through
// monitoring.SNMPCredentialDoc instead of vaultfile.Doc, since a
// credentialRef's value is itself a nested map (username/authPassword/
// privPassword, or community) — a shape vaultfile.Doc deliberately refuses
// to touch (see internal/vaultfile's package doc).
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/kjelly/pilot/internal/monitoring"
	"github.com/kjelly/pilot/internal/tui"
)

func pushSNMPCredentialFilePicker(r *editRouterModel, dir, banner string) tea.Cmd {
	targetDir := filepath.Join(dir, ".vault")
	files, err := scanVaultFiles(targetDir)
	if err != nil {
		r.err = err
		return nil
	}

	choices := make([]tui.Choice, 0, len(files)+2)
	for _, f := range files {
		choices = append(choices, tui.Choice{ID: f, Label: "🔑 " + f})
	}
	choices = append(choices,
		tui.Choice{ID: "mon.snmp.cred.files.other_path", Label: "📍 輸入其他 vault 檔路徑"},
		tui.Choice{ID: "mon.snmp.cred.files.back", Label: "↩  返回"},
	)

	title := fmt.Sprintf("SNMP 認證 — 選一個 %s 底下的 vault 檔", targetDir)
	spec := tui.SelectSpec{ScreenID: "mon.snmp.cred.files", Title: title, Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushMonitoringManager(r, dir, "")
		}
		idx := m.Selected()
		switch {
		case idx == len(choices)-1:
			return pushMonitoringManager(r, dir, "")
		case idx < len(files):
			return pushSNMPCredentialsEditor(r, dir, filepath.Join(targetDir, files[idx]), "")
		default:
			return pushSNMPCredentialFilePathPrompt(r, dir, targetDir)
		}
	})
}

func pushSNMPCredentialFilePathPrompt(r *editRouterModel, dir, targetDir string) tea.Cmd {
	def := filepath.Join(targetDir, "main.yaml")
	spec := tui.InputSpec{ScreenID: "mon.snmp.cred.files.path", Title: "vault 檔路徑", Default: def}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushSNMPCredentialFilePicker(r, dir, "")
		}
		return pushSNMPCredentialsEditor(r, dir, strings.TrimSpace(m.Value()), "")
	})
}

func loadSNMPCredentialDocOrBanner(r *editRouterModel, path string) (*monitoring.SNMPCredentialDoc, string, bool) {
	doc, err := monitoring.LoadSNMPCredentialDoc(path)
	if err != nil {
		return nil, fmt.Sprintf("⚠️  %s 讀取失敗：%v", path, err), false
	}
	for _, key := range doc.OtherTopLevelKeys() {
		if rosterShapedKeys[key] {
			return nil, fmt.Sprintf("⚠️  %s 看起來是 FreeIPA roster 檔，請改從主選單選「roster — FreeIPA」編輯；不要在這裡動它。", path), false
		}
	}
	return doc, "", true
}

func pushSNMPCredentialsEditor(r *editRouterModel, dir, path, banner string) tea.Cmd {
	doc, errBanner, ok := loadSNMPCredentialDocOrBanner(r, path)
	if !ok {
		return pushSNMPCredentialFilePicker(r, dir, errBanner)
	}
	refs := doc.Refs()
	note := "選一個查看/編輯，或新增一個。密碼值不會顯示在畫面上。"
	if len(refs) == 0 {
		note = "目前沒有任何 credentialRef。"
	}
	if banner == "" {
		banner = note
	} else {
		banner += "\n" + note
	}

	choices := make([]tui.Choice, 0, len(refs)+3)
	for _, ref := range refs {
		choices = append(choices, tui.Choice{ID: ref, Label: "🔑 " + ref})
	}
	choices = append(choices,
		tui.Choice{ID: "mon.snmp.cred.editor.add", Label: "➕ 新增 credentialRef"},
		tui.Choice{ID: "mon.snmp.cred.editor.save", Label: "💾 存檔並離開"},
		tui.Choice{ID: "mon.snmp.cred.editor.discard", Label: "🚪 不存檔離開"},
	)

	title := fmt.Sprintf("SNMP 認證 — %s", path)
	spec := tui.SelectSpec{ScreenID: "mon.snmp.cred.editor", Title: title, Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushSNMPCredentialFilePicker(r, dir, "")
		}
		idx := m.Selected()
		switch {
		case idx == len(choices)-3:
			return pushSNMPCredentialAddRefID(r, dir, path, doc)
		case idx == len(choices)-2:
			if err := monitoring.WriteSNMPCredentialDoc(path, doc); err != nil {
				return pushSNMPCredentialsEditor(r, dir, path, fmt.Sprintf("⚠️  存檔失敗：%v", err))
			}
			return pushSNMPCredentialFilePicker(r, dir, fmt.Sprintf("✅ 已存檔 %s", path))
		case idx == len(choices)-1:
			return pushSNMPCredentialFilePicker(r, dir, "")
		default:
			return pushSNMPCredentialRefMenu(r, dir, path, doc, refs[idx])
		}
	})
}

func pushSNMPCredentialAddRefID(r *editRouterModel, dir, path string, doc *monitoring.SNMPCredentialDoc) tea.Cmd {
	validate := func(s string) error {
		s = strings.TrimSpace(s)
		if s == "" {
			return fmt.Errorf("不能留空")
		}
		if _, exists := doc.Get(s); exists {
			return fmt.Errorf("credentialRef %q 已存在", s)
		}
		return nil
	}
	spec := tui.InputSpec{ScreenID: "mon.snmp.cred.add.id", Title: "新 credentialRef(需與 SNMP catalog 的 authProfile.credentialRef 一致)", Validate: validate}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushSNMPCredentialsEditor(r, dir, path, "")
		}
		return pushSNMPCredentialAddKind(r, dir, path, doc, strings.TrimSpace(m.Value()))
	})
}

func pushSNMPCredentialAddKind(r *editRouterModel, dir, path string, doc *monitoring.SNMPCredentialDoc, ref string) tea.Cmd {
	choices := []tui.Choice{
		{ID: "v3", Label: "SNMPv3 (username + authPassword + privPassword)"},
		{ID: "v1v2c", Label: "SNMPv1 / SNMPv2c (community)"},
	}
	spec := tui.SelectSpec{ScreenID: "mon.snmp.cred.add.kind", Title: fmt.Sprintf("credentialRef %q 是哪種 SNMP 版本？", ref), Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushSNMPCredentialAddRefID(r, dir, path, doc)
		}
		if m.Selected() == 0 {
			return pushSNMPCredentialFieldPrompt(r, dir, path, doc, ref, monitoring.SNMPCredentialFields{}, []string{"username", "authPassword", "privPassword"}, 0)
		}
		return pushSNMPCredentialFieldPrompt(r, dir, path, doc, ref, monitoring.SNMPCredentialFields{}, []string{"community"}, 0)
	})
}

// pushSNMPCredentialFieldPrompt walks fieldOrder one field at a time
// (rather than one InputSpec with multiple fields, matching this codebase's
// existing wizard-per-field convention) collecting a value into fields,
// then commits once every field has been entered.
func pushSNMPCredentialFieldPrompt(r *editRouterModel, dir, path string, doc *monitoring.SNMPCredentialDoc, ref string, fields monitoring.SNMPCredentialFields, fieldOrder []string, i int) tea.Cmd {
	if i >= len(fieldOrder) {
		doc.Set(ref, fields)
		return pushSNMPCredentialsEditor(r, dir, path, fmt.Sprintf("✅ credentialRef %q 已在記憶體中更新，記得選「存檔並離開」。", ref))
	}
	field := fieldOrder[i]
	validate := func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}
	spec := tui.InputSpec{ScreenID: "mon.snmp.cred.field." + field, Title: fmt.Sprintf("credentialRef %q 的 %s", ref, field), Secret: true, Validate: validate}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushSNMPCredentialsEditor(r, dir, path, "")
		}
		fields[field] = m.Value()
		return pushSNMPCredentialFieldPrompt(r, dir, path, doc, ref, fields, fieldOrder, i+1)
	})
}

func pushSNMPCredentialRefMenu(r *editRouterModel, dir, path string, doc *monitoring.SNMPCredentialDoc, ref string) tea.Cmd {
	fields, _ := doc.Get(ref)
	kinds := make([]string, 0, len(fields))
	for k := range fields {
		kinds = append(kinds, k)
	}
	title := fmt.Sprintf("credentialRef %q 目前欄位：%s（值不顯示）", ref, strings.Join(kinds, ", "))
	choices := []tui.Choice{
		{ID: "mon.snmp.cred.ref.edit", Label: "修改值(v3: username/authPassword/privPassword)"},
		{ID: "mon.snmp.cred.ref.delete", Label: "🗑  刪除"},
		{ID: "mon.snmp.cred.ref.back", Label: "↩  返回"},
	}
	spec := tui.SelectSpec{ScreenID: "mon.snmp.cred.ref", Title: title, Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushSNMPCredentialsEditor(r, dir, path, "")
		}
		switch m.Selected() {
		case 0:
			_, isV3 := fields["username"]
			if isV3 {
				return pushSNMPCredentialFieldPrompt(r, dir, path, doc, ref, monitoring.SNMPCredentialFields{}, []string{"username", "authPassword", "privPassword"}, 0)
			}
			return pushSNMPCredentialFieldPrompt(r, dir, path, doc, ref, monitoring.SNMPCredentialFields{}, []string{"community"}, 0)
		case 1:
			doc.Delete(ref)
			return pushSNMPCredentialsEditor(r, dir, path, fmt.Sprintf("credentialRef %q 已在記憶體中刪除，記得選「存檔並離開」。", ref))
		default:
			return pushSNMPCredentialsEditor(r, dir, path, "")
		}
	})
}

var _ = os.IsNotExist // keep os imported for future error-path parity with edit_tui_vault.go
