// edit_automation_driver_groupvars.go drives the group_vars/ screens
// (edit_tui_groupvars.go) for semantic edit-scenario actions —
// set_group_var, restore_group_var_default, save_group_vars,
// discard_group_vars.
package cmd

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/kjelly/pilot/internal/tui"
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
		st := automationState(r)
		if st.Kind != tui.ScreenSelect {
			return fmt.Errorf("cannot navigate to group_vars file %q from %s screen", file, automationScreenID(r))
		}
		switch {
		case st.Title == "要編輯什麼？":
			if err := d.choose(r, "group_vars"); err != nil {
				return err
			}
		case strings.Contains(st.Title, "選一個") && strings.Contains(st.Title, "group_vars"):
			if err := d.choose(r, base); err != nil {
				return err
			}
		case strings.HasPrefix(st.Title, "編輯 "):
			if strings.Contains(st.Title, base) {
				return nil
			}
			return fmt.Errorf("group_vars editor is open on a different file (%s); save_group_vars or discard_group_vars it first", st.Title)
		case strings.Contains(st.Title, "選一個") && strings.Contains(st.Title, "vault 檔"):
			// A different workspace's file picker is a safely-closed-out state
			// (no pending edits live on a picker itself) — hop back to the top
			// menu first. An open vault *editor* is deliberately NOT handled
			// here, same reasoning as the different-file case above.
			if err := d.choose(r, "返回"); err != nil {
				return err
			}
		default:
			return fmt.Errorf("cannot navigate to group_vars file %q from screen %q", file, st.Title)
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
	if automationState(r).Kind == tui.ScreenConfirm {
		return d.confirmYesNo(r, true)
	}
	return nil
}

// setGroupVarList replaces a flow-list ("key: [a, b]") group_vars entry's
// items with values through the same list screens a human uses: every
// existing item is removed, then each value is added in order. Each
// remove/add returns the router to the file's editor screen
// (pushGroupVarsEditorScreen re-renders after every SetList), so the list
// screens are re-entered for each step. An empty values on an entry with
// no items is a no-op: the entry stays at its built-in default.
func (d *automationDriver) setGroupVarList(r *editRouterModel, file, key string, values []string) error {
	openItems := func() ([]string, error) {
		if err := d.openGroupVarsFile(r, file); err != nil {
			return nil, err
		}
		if err := d.choose(r, key+" = ["); err != nil {
			return nil, err
		}
		if err := d.choose(r, "編輯清單項目"); err != nil {
			return nil, err
		}
		if got := automationScreenID(r); got != "group_vars.list_items" {
			return nil, fmt.Errorf("expected group_vars.list_items screen for %s, got %s", key, got)
		}
		var items []string
		for _, it := range automationState(r).Items {
			if it.ID != "group_vars.list_items.add" && it.ID != "group_vars.list_items.back" {
				items = append(items, it.ID)
			}
		}
		return items, nil
	}
	backToEditor := func() error { return d.chooseByID(r, "group_vars.list_items", "group_vars.list_items.back") }

	for {
		items, err := openItems()
		if err != nil {
			return err
		}
		if len(items) == 0 {
			if err := backToEditor(); err != nil {
				return err
			}
			if err := d.choose(r, "返回"); err != nil {
				return err
			}
			break
		}
		if err := d.chooseByID(r, "group_vars.list_items", items[0]); err != nil {
			return err
		}
		if err := d.choose(r, "移除"); err != nil {
			return err
		}
	}
	for _, v := range values {
		if _, err := openItems(); err != nil {
			return err
		}
		if err := d.chooseByID(r, "group_vars.list_items", "group_vars.list_items.add"); err != nil {
			return err
		}
		if err := d.typeText(r, v, true); err != nil {
			return err
		}
		if err := d.enter(r); err != nil {
			return err
		}
	}
	return nil
}

// backfillGroupVars applies the editor's "從範例補上缺少的設定" item for file
// (docs/verification/dns.md §3.5 P3); it fails when the file already
// mentions every key its example offers, so a scenario never silently
// assumes a backfill happened.
func (d *automationDriver) backfillGroupVars(r *editRouterModel, file string) error {
	if err := d.openGroupVarsFile(r, file); err != nil {
		return err
	}
	return d.chooseByID(r, "group_vars.entries", "group_vars.entries.backfill")
}
