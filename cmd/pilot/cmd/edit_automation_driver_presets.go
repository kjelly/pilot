// edit_automation_driver_presets.go drives the role-preset screens
// (edit_tui_role_presets.go): applying a preset or another host's roles to
// the current host, and the full preset manager (create/rename/delete/
// restore). Every action here ends back at the host menu, mirroring
// setRoleChecked's "✅ 完成" tail, so a later action in the same scenario can
// resolve via ensureHostMenu exactly like after enable_role/disable_role.
package cmd

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/kjelly/pilot/internal/tui"
)

func (d *automationDriver) applyRolePreset(r *editRouterModel, step editAction) error {
	if err := d.ensureHostMenu(r, step.Host); err != nil {
		return err
	}
	if err := d.choose(r, "角色(roles)"); err != nil {
		return err
	}
	if err := d.choose(r, "套用常用角色範本"); err != nil {
		return err
	}
	// Matching "<label> — " (not the bare label) avoids a false match against
	// another preset's roles column; it also naturally fails with "label not
	// found" when there are no presets at all (the placeholder screen only
	// offers "↩  取消") — a real, expected error, not a silent no-op.
	if err := d.choose(r, step.Preset+" — "); err != nil {
		return err
	}
	// A preset can include freeipa-nfs-server and/or a role that needs its
	// own host_vars (e.g. prometheus) — same two detours a lone
	// enable_role can hit, resolved the same way (resolveRoleChangeFollowUp,
	// edit_automation_driver.go), not a blind "✅ 完成".
	return d.resolveRoleChangeFollowUp(r, step)
}

func (d *automationDriver) copyRolesFromHost(r *editRouterModel, step editAction) error {
	if err := d.ensureHostMenu(r, step.Host); err != nil {
		return err
	}
	if err := d.choose(r, "角色(roles)"); err != nil {
		return err
	}
	if err := d.choose(r, "複製自其他主機的角色"); err != nil {
		return err
	}
	// If there are no candidate hosts, choosing "複製自其他主機的角色" leaves
	// the router right back on the roles menu (banner-only) instead of a
	// picker — sourceHost+" — " then fails to match any of the roles menu's
	// own fixed labels, so this still surfaces a clear "label not found"
	// error rather than silently doing nothing.
	if err := d.choose(r, step.SourceHost+" — "); err != nil {
		return err
	}
	// Same NFS-bootstrap / forced-host-vars detours as applyRolePreset.
	return d.resolveRoleChangeFollowUp(r, step)
}

func (d *automationDriver) createRolePreset(r *editRouterModel, host, label string, roles []string) error {
	if err := d.ensureHostMenu(r, host); err != nil {
		return err
	}
	if err := d.choose(r, "角色(roles)"); err != nil {
		return err
	}
	if err := d.choose(r, "管理角色範本"); err != nil {
		return err
	}
	if err := d.choose(r, "新增範本"); err != nil {
		return err
	}
	if err := d.typeText(r, label, false); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if err := d.checkRoleChecklistItems(r, roles); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	// The checklist's own "zero checked roles" case silently discards the
	// whole create (both label and roles) and returns to the manager with a
	// banner instead of a distinguishable screen/error — checkRoleChecklistItems
	// above only ever reaches this enter() after checking every requested
	// role, so len(roles)>=1 (validated) should always yield >=1 checked; this
	// is a defensive backstop in case that invariant is ever violated.
	if strings.Contains(r.banner, "尚未儲存") {
		return fmt.Errorf("create_role_preset %q was not saved: %s", label, r.banner)
	}
	if err := d.choose(r, "返回"); err != nil {
		return err
	}
	return d.choose(r, "✅ 完成")
}

func (d *automationDriver) renameRolePreset(r *editRouterModel, host, oldLabel, newLabel string) error {
	if err := d.ensureHostMenu(r, host); err != nil {
		return err
	}
	if err := d.choose(r, "角色(roles)"); err != nil {
		return err
	}
	if err := d.choose(r, "管理角色範本"); err != nil {
		return err
	}
	if err := d.choose(r, oldLabel+" — "); err != nil {
		return err
	}
	if err := d.choose(r, "修改名稱與角色"); err != nil {
		return err
	}
	if err := d.typeText(r, newLabel, true); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	// A pure rename leaves the pre-filled role checklist untouched — every
	// existing preset already has >=1 role, so a bare enter() here can never
	// hit the zero-checked-roles discard path.
	if err := d.enter(r); err != nil {
		return err
	}
	if err := d.choose(r, "返回"); err != nil {
		return err
	}
	return d.choose(r, "✅ 完成")
}

func (d *automationDriver) deleteRolePreset(r *editRouterModel, host, label string) error {
	if err := d.ensureHostMenu(r, host); err != nil {
		return err
	}
	if err := d.choose(r, "角色(roles)"); err != nil {
		return err
	}
	if err := d.choose(r, "管理角色範本"); err != nil {
		return err
	}
	if err := d.choose(r, label+" — "); err != nil {
		return err
	}
	if err := d.choose(r, "刪除範本"); err != nil {
		return err
	}
	if err := d.confirmYesNo(r, true); err != nil {
		return err
	}
	if err := d.choose(r, "返回"); err != nil {
		return err
	}
	return d.choose(r, "✅ 完成")
}

func (d *automationDriver) restoreRolePresets(r *editRouterModel, host string) error {
	if err := d.ensureHostMenu(r, host); err != nil {
		return err
	}
	if err := d.choose(r, "角色(roles)"); err != nil {
		return err
	}
	if err := d.choose(r, "管理角色範本"); err != nil {
		return err
	}
	// Fails with "label not found" when role-presets.yml was never
	// customized — the item is only offered in that case, matching the
	// real menu exactly rather than pre-checking file existence ourselves.
	if err := d.choose(r, "還原為內建範本"); err != nil {
		return err
	}
	if err := d.confirmYesNo(r, true); err != nil {
		return err
	}
	if err := d.choose(r, "返回"); err != nil {
		return err
	}
	return d.choose(r, "✅ 完成")
}

// checkRoleChecklistItems toggles Space on every named role currently
// unchecked, in request order — the bulk form of setRoleChecked's
// single-role toggle, used by createRolePreset for a fresh (all-unchecked)
// checklist.
func (d *automationDriver) checkRoleChecklistItems(r *editRouterModel, roles []string) error {
	st := automationState(r)
	if st.Kind != tui.ScreenMultiSelect {
		return fmt.Errorf("expected role checklist screen")
	}
	items := automationLabels(st.Items)
	for _, role := range roles {
		idx, err := uniqueItemIndex(items, role)
		if err != nil {
			return err
		}
		cur := automationState(r)
		if cur.Kind != tui.ScreenMultiSelect {
			return fmt.Errorf("expected role checklist screen")
		}
		if cur.Items[idx].Checked {
			continue
		}
		if err := d.moveCursor(r, idx); err != nil {
			return err
		}
		if err := d.send(r, tea.KeyMsg{Type: tea.KeySpace}); err != nil {
			return err
		}
	}
	return nil
}
