// edit_automation_driver_groupvars.go drives the group_vars/ screens
// (edit_tui_groupvars.go) for semantic edit-scenario actions —
// set_group_var, restore_group_var_default, save_group_vars,
// discard_group_vars.
package cmd

import (
	"fmt"
	"path/filepath"
	"strings"
)

// openGroupVarsFile resolves the router to the group_vars key-list editor
// screen for file, navigating from wherever r.current currently is (the top
// menu, the file picker, or already the target file's own editor screen —
// a no-op then), mirroring ensureHostsList's "resolve current position,
// take the shortest path" pattern rather than assuming a fixed starting
// screen. It deliberately does not try to leave a *different* group_vars
// file's editor for you: that file may hold unsaved changes, and guessing
// a discard confirm's answer on the caller's behalf would be silently
// destructive — the scenario must save_group_vars/discard_group_vars that
// file first.
func (d *automationDriver) openGroupVarsFile(r *editRouterModel, file string) error {
	base := filepath.Base(file)
	for attempts := 0; attempts < 6; attempts++ {
		list, ok := r.current.(selectModel)
		if !ok {
			return fmt.Errorf("cannot navigate to group_vars file %q from %s screen", file, automationScreenID(r))
		}
		switch {
		case list.title == "要編輯什麼？":
			if err := d.choose(r, "group_vars"); err != nil {
				return err
			}
		case strings.Contains(list.title, "選一個") && strings.Contains(list.title, "group_vars"):
			if err := d.choose(r, base); err != nil {
				return err
			}
		case strings.HasPrefix(list.title, "編輯 "):
			if strings.Contains(list.title, base) {
				return nil
			}
			return fmt.Errorf("group_vars editor is open on a different file (%s); save_group_vars or discard_group_vars it first", list.title)
		case strings.Contains(list.title, "選一個") && strings.Contains(list.title, "vault 檔"):
			// A different workspace's file picker is a safely-closed-out state
			// (no pending edits live on a picker itself) — hop back to the top
			// menu first. An open vault *editor* is deliberately NOT handled
			// here, same reasoning as the different-file case above.
			if err := d.choose(r, "返回"); err != nil {
				return err
			}
		default:
			return fmt.Errorf("cannot navigate to group_vars file %q from screen %q", file, list.title)
		}
	}
	return fmt.Errorf("could not resolve navigation to group_vars file %q", file)
}

func (d *automationDriver) setGroupVar(r *editRouterModel, file, key, value string) error {
	if err := d.openGroupVarsFile(r, file); err != nil {
		return err
	}
	if err := d.choose(r, key+" = "); err != nil {
		return err
	}
	if err := d.choose(r, "修改值"); err != nil {
		return err
	}
	if err := d.typeText(r, value, true); err != nil {
		return err
	}
	return d.enter(r)
}

func (d *automationDriver) restoreGroupVarDefault(r *editRouterModel, file, key string) error {
	if err := d.openGroupVarsFile(r, file); err != nil {
		return err
	}
	if err := d.choose(r, key+" = "); err != nil {
		return err
	}
	return d.choose(r, "還原成內建預設")
}

func (d *automationDriver) saveGroupVars(r *editRouterModel, file string) error {
	if err := d.openGroupVarsFile(r, file); err != nil {
		return err
	}
	return d.choose(r, "存檔並離開")
}

func (d *automationDriver) discardGroupVars(r *editRouterModel, file string) error {
	if err := d.openGroupVarsFile(r, file); err != nil {
		return err
	}
	if err := d.choose(r, "不存檔離開"); err != nil {
		return err
	}
	// pushGroupVarsEditorScreen only prompts a confirm when dirty; a clean
	// file returns straight to the file picker instead, so branch on what
	// screen we actually landed on rather than assuming a confirm exists.
	if _, ok := r.current.(confirmModel); ok {
		return d.confirmYesNo(r, true)
	}
	return nil
}
