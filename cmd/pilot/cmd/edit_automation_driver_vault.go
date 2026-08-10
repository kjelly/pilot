// edit_automation_driver_vault.go drives the .vault/ plaintext-skeleton
// screens (edit_tui_vault.go) for semantic edit-scenario actions —
// add_vault_key, set_vault_value, delete_vault_key, save_vault,
// discard_vault. The ansible-vault-ENCRYPTED shellout path
// (pushAnsibleVaultShellout) and any vault file failing doc.Editable()
// (nested YAML/roster) are deliberately not automatable here — that's not a
// gap, the wizard has no menu path there for a human either: picking such a
// file bounces back to this same picker with an explanatory banner instead
// of opening an editor (see pushVaultEditorFromData) — a human can just
// pick something else, but a scenario step targeting one is an authoring
// bug, so openVaultFile turns that bounce-back into the step's own fatal
// error rather than silently re-selecting the same file forever.
package cmd

import (
	"fmt"
	"path/filepath"
	"strings"
)

// normalizeVaultFileName appends ".yaml" to file when it doesn't already end
// in ".yaml"/".yml" — mirroring pushVaultPathPrompt's prefilled default
// (edit_tui_vault.go, "main.yaml") and scanVaultFiles' accepted suffix set
// (edit.go), the only two things that decide what a *human* ends up naming
// a new vault file. Without this, a scenario step with file: "main" created
// a literal extension-less ".vault/main" on a fresh workspace (openVaultFile
// used to join the raw name onto ".vault/" verbatim) — a file every
// .vault/main.yaml-hardcoded convention (deploy's defaultVaultFile,
// checkVaultCompleteness, `pilot inventory generate`'s --vault-out default,
// pushNFSRoleBootstrap's own ipa_admin_password reuse) then fails to find.
func normalizeVaultFileName(file string) string {
	switch strings.ToLower(filepath.Ext(file)) {
	case ".yaml", ".yml":
		return file
	default:
		return file + ".yaml"
	}
}

// openVaultFile resolves the router to the vault key-list editor screen
// for file, from wherever r.current currently is — the top menu, the file
// picker (whether file is already listed or needs to be typed in and
// created), or already the target file's own editor screen. Like
// openGroupVarsFile, it refuses to leave a *different* vault file's editor
// on the caller's behalf (that file may hold unsaved changes) rather than
// guessing a discard confirm's answer.
func (d *automationDriver) openVaultFile(r *editRouterModel, file string) error {
	file = normalizeVaultFileName(file)
	base := filepath.Base(file)
	for attempts := 0; attempts < 6; attempts++ {
		if _, ok := r.current.(confirmModel); ok {
			// "<path> 不存在，要建立新的明文 vault 檔嗎？" — only reached via
			// the "輸入其他 vault 檔路徑" branch below, for a genuinely new file.
			if err := d.confirmYesNo(r, true); err != nil {
				return err
			}
			continue
		}
		list, ok := r.current.(selectModel)
		if !ok {
			return fmt.Errorf("cannot navigate to vault file %q from %s screen", file, automationScreenID(r))
		}
		switch {
		case list.title == "要編輯什麼？":
			if err := d.choose(r, ".vault/"); err != nil {
				return err
			}
		case strings.Contains(list.title, "選一個") && strings.Contains(list.title, "vault 檔"):
			pickerTitle := list.title
			if err := d.choose(r, base); err != nil {
				// Not listed yet — take the "type a path" branch to create it.
				// The path must be exactly what the picker's own default would
				// resolve to (targetDir/file), constructed from d.dir since the
				// typed value is used verbatim, not joined with any directory.
				if err := d.choose(r, "輸入其他"); err != nil {
					return err
				}
				full := filepath.Join(d.dir, ".vault", file)
				if err := d.typeText(r, full, true); err != nil {
					return err
				}
				if err := d.enter(r); err != nil {
					return err
				}
			} else if again, ok := r.current.(selectModel); ok && again.title == pickerTitle {
				// Choosing an existing, listed file either opens its editor (a
				// different screen) or — for a parse failure or a file
				// doc.Editable() rejects — bounces right back to this same
				// picker with a banner explaining why (pushVaultEditorFromData).
				// That banner IS the fatal error here.
				return fmt.Errorf("%s", r.banner)
			}
		case strings.HasPrefix(list.title, "編輯 "):
			if strings.Contains(list.title, base) {
				return nil
			}
			return fmt.Errorf("vault editor is open on a different file (%s); save_vault or discard_vault it first", list.title)
		case strings.Contains(list.title, "選一個") && strings.Contains(list.title, "group_vars"):
			// A different workspace's file picker is a safely-closed-out state
			// (no pending edits live on a picker itself) — hop back to the top
			// menu first. An open group_vars *editor* is deliberately NOT
			// handled here, same reasoning as the different-file case above.
			if err := d.choose(r, "返回"); err != nil {
				return err
			}
		default:
			return fmt.Errorf("cannot navigate to vault file %q from screen %q", file, list.title)
		}
	}
	return fmt.Errorf("could not resolve navigation to vault file %q", file)
}

func (d *automationDriver) addVaultKey(r *editRouterModel, file, key, value string, secret bool) error {
	if err := d.openVaultFile(r, file); err != nil {
		return err
	}
	if err := d.choose(r, "新增 key"); err != nil {
		return err
	}
	if err := d.typeText(r, key, false); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if err := d.typeSecretOrPlain(r, value, secret, false); err != nil {
		return err
	}
	return d.enter(r)
}

func (d *automationDriver) setVaultValue(r *editRouterModel, file, key, value string, secret bool) error {
	if err := d.openVaultFile(r, file); err != nil {
		return err
	}
	if err := d.choose(r, key+" = "); err != nil {
		return err
	}
	if err := d.choose(r, "修改值"); err != nil {
		return err
	}
	if err := d.typeSecretOrPlain(r, value, secret, true); err != nil {
		return err
	}
	return d.enter(r)
}

func (d *automationDriver) deleteVaultKey(r *editRouterModel, file, key string) error {
	if err := d.openVaultFile(r, file); err != nil {
		return err
	}
	if err := d.choose(r, key+" = "); err != nil {
		return err
	}
	// No confirm here — matches pushVaultEntryMenu's immediate delete.
	return d.choose(r, "刪除")
}

func (d *automationDriver) saveVault(r *editRouterModel, file string) error {
	if err := d.openVaultFile(r, file); err != nil {
		return err
	}
	return d.choose(r, "存檔並離開")
}

func (d *automationDriver) discardVault(r *editRouterModel, file string) error {
	if err := d.openVaultFile(r, file); err != nil {
		return err
	}
	if err := d.choose(r, "不存檔離開"); err != nil {
		return err
	}
	if _, ok := r.current.(confirmModel); ok {
		return d.confirmYesNo(r, true)
	}
	return nil
}
