// edit_automation_driver_roster_access.go drives the roster hostgroup
// and HBAC-rule screens (edit_tui_roster_access.go) for
// create_hostgroup/set_hostgroup_field, create_hbac_rule/
// set_hbac_groups/set_hbac_targets/set_hbac_services/
// set_hbac_disable_allow_all (Phase 6 increment 3), using the stable
// screen IDs added to those screens instead of title-substring
// matching, mirroring edit_automation_driver_roster.go's user pattern.
package cmd

import "fmt"

func (d *automationDriver) ensureRosterHostAccessMenu(r *editRouterModel) error {
	for attempts := 0; attempts < 8; attempts++ {
		switch automationScreenID(r) {
		case "roster.access.top":
			return nil
		case "edit.top":
			if err := d.choose(r, "roster"); err != nil {
				return err
			}
		case "roster.path":
			if err := d.enter(r); err != nil {
				return err
			}
		case rosterCreateConfirmScreenID:
			if err := d.resolveRosterCreatePrompt(r); err != nil {
				return err
			}
		case "roster.top":
			if err := d.choose(r, "🔐 Host access"); err != nil {
				return err
			}
		default:
			if err := d.choose(r, "返回"); err != nil {
				return fmt.Errorf("cannot navigate to roster host access menu from %s screen: %w", automationScreenID(r), err)
			}
		}
	}
	return fmt.Errorf("could not resolve navigation to roster host access menu")
}

func (d *automationDriver) ensureRosterHostgroupsList(r *editRouterModel) error {
	for attempts := 0; attempts < 8; attempts++ {
		switch automationScreenID(r) {
		case "roster.hostgroups.list":
			return nil
		case "edit.top":
			if err := d.choose(r, "roster"); err != nil {
				return err
			}
		case "roster.path":
			if err := d.enter(r); err != nil {
				return err
			}
		case rosterCreateConfirmScreenID:
			if err := d.resolveRosterCreatePrompt(r); err != nil {
				return err
			}
		case "roster.top":
			if err := d.choose(r, "🔐 Host access"); err != nil {
				return err
			}
		case "roster.access.top":
			if err := d.choose(r, "Hostgroups"); err != nil {
				return err
			}
		default:
			if err := d.choose(r, "返回"); err != nil {
				return fmt.Errorf("cannot navigate to roster hostgroups list from %s screen: %w", automationScreenID(r), err)
			}
		}
	}
	return fmt.Errorf("could not resolve navigation to roster hostgroups list")
}

func (d *automationDriver) createHostgroup(r *editRouterModel, hostgroup string) error {
	if err := d.ensureRosterHostgroupsList(r); err != nil {
		return err
	}
	if err := d.choose(r, "➕ 新增 Hostgroup"); err != nil {
		return err
	}
	if err := d.typeText(r, hostgroup, false); err != nil {
		return err
	}
	return d.enter(r)
}

func (d *automationDriver) ensureRosterHostgroupDetail(r *editRouterModel, hostgroup string) error {
	if automationScreenID(r) == "roster.hostgroup.detail" {
		if list, ok := r.current.(selectModel); ok && list.title == "Hostgroup "+hostgroup {
			return nil
		}
		if err := d.choose(r, "返回"); err != nil {
			return err
		}
	}
	if err := d.ensureRosterHostgroupsList(r); err != nil {
		return err
	}
	return d.choose(r, "🖥 "+hostgroup)
}

func (d *automationDriver) setHostgroupField(r *editRouterModel, hostgroup, field, value string) error {
	if err := d.ensureRosterHostgroupDetail(r, hostgroup); err != nil {
		return err
	}
	if err := d.choose(r, field); err != nil {
		return err
	}
	if err := d.typeText(r, value, true); err != nil {
		return err
	}
	return d.enter(r)
}

// setHostgroupHostgroups bulk-replaces a hostgroup's membership.hostgroups
// (nested hostgroup membership, roster.hostgroup.field_hostgroups) — a
// checklist screen, not a text field, so this drives it the same way
// setHBACTargets drives targets.hostgroups rather than going through
// setHostgroupField (which only handles text-input fields).
func (d *automationDriver) setHostgroupHostgroups(r *editRouterModel, hostgroup string, hostgroups []string) error {
	if err := d.ensureRosterHostgroupDetail(r, hostgroup); err != nil {
		return err
	}
	if err := d.choose(r, "membership.hostgroups"); err != nil {
		return err
	}
	return d.setChecklistSelection(r, hostgroups)
}

func (d *automationDriver) ensureRosterHBACList(r *editRouterModel) error {
	for attempts := 0; attempts < 8; attempts++ {
		switch automationScreenID(r) {
		case "roster.hbac.list":
			return nil
		case "edit.top":
			if err := d.choose(r, "roster"); err != nil {
				return err
			}
		case "roster.path":
			if err := d.enter(r); err != nil {
				return err
			}
		case rosterCreateConfirmScreenID:
			if err := d.resolveRosterCreatePrompt(r); err != nil {
				return err
			}
		case "roster.top":
			if err := d.choose(r, "🔐 Host access"); err != nil {
				return err
			}
		case "roster.access.top":
			if err := d.choose(r, "HBAC rules"); err != nil {
				return err
			}
		default:
			if err := d.choose(r, "返回"); err != nil {
				return fmt.Errorf("cannot navigate to roster HBAC list from %s screen: %w", automationScreenID(r), err)
			}
		}
	}
	return fmt.Errorf("could not resolve navigation to roster HBAC list")
}

// createHBACRule replays the full 3-checklist creation wizard
// (pushRosterAddHBACGroups -> ...Hostgroups -> ...Services) in one
// atomic step, matching the TUI: there is no "create an empty rule"
// primitive to decouple creation from these selections.
func (d *automationDriver) createHBACRule(r *editRouterModel, name string, groups, hostgroups, services []string) error {
	if err := d.ensureRosterHBACList(r); err != nil {
		return err
	}
	if err := d.choose(r, "➕ 新增登入規則"); err != nil {
		return err
	}
	if err := d.typeText(r, name, false); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if err := d.setChecklistSelection(r, groups); err != nil {
		return err
	}
	if err := d.setChecklistSelection(r, hostgroups); err != nil {
		return err
	}
	return d.setChecklistSelection(r, services)
}

func (d *automationDriver) ensureRosterHBACDetail(r *editRouterModel, name string) error {
	if automationScreenID(r) == "roster.hbac.detail" {
		if list, ok := r.current.(selectModel); ok && list.title == "HBAC rule "+name {
			return nil
		}
		if err := d.choose(r, "返回"); err != nil {
			return err
		}
	}
	if err := d.ensureRosterHBACList(r); err != nil {
		return err
	}
	return d.choose(r, "🔑 "+name)
}

func (d *automationDriver) setHBACGroups(r *editRouterModel, name string, groups []string) error {
	if err := d.ensureRosterHBACDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "subjects.groups"); err != nil {
		return err
	}
	return d.setChecklistSelection(r, groups)
}

func (d *automationDriver) setHBACTargets(r *editRouterModel, name string, hostgroups []string) error {
	if err := d.ensureRosterHBACDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "targets.hostgroups"); err != nil {
		return err
	}
	return d.setChecklistSelection(r, hostgroups)
}

func (d *automationDriver) setHBACServices(r *editRouterModel, name string, services []string) error {
	if err := d.ensureRosterHBACDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "services"); err != nil {
		return err
	}
	return d.setChecklistSelection(r, services)
}

// setHBACDisableAllowAll toggles the global hbac.disable_allow_all flag
// only when it doesn't already match want — selecting the menu item
// flips the current value directly (pushRosterHostAccessMenu case 2),
// so this reads the displayed state first to stay idempotent across a
// scenario replay.
func (d *automationDriver) setHBACDisableAllowAll(r *editRouterModel, want bool) error {
	if err := d.ensureRosterHostAccessMenu(r); err != nil {
		return err
	}
	list, ok := r.current.(selectModel)
	if !ok {
		return fmt.Errorf("expected roster host access menu screen, got %s", automationScreenID(r))
	}
	wantLabel := fmt.Sprintf("hbac.disable_allow_all：%t", want)
	for _, item := range list.automationItems() {
		if item == wantLabel {
			return nil
		}
	}
	return d.choose(r, "hbac.disable_allow_all")
}
