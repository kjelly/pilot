// edit_automation_driver_roster_sudo.go drives the roster sudo
// command-group and sudo-rule screens (edit_tui_roster_sudo.go) for
// create_sudo_command_group/set_sudo_command_group_commands,
// create_sudo_rule/set_sudo_rule_groups/set_sudo_rule_command_groups/
// set_sudo_rule_commands/set_sudo_rule_allow_mode (Phase 6 increment
// 3), using the stable screen IDs added to those screens instead of
// title-substring matching, mirroring
// edit_automation_driver_roster.go's user pattern.
package cmd

import "fmt"

func (d *automationDriver) ensureRosterSudoCommandGroupsList(r *editRouterModel) error {
	for attempts := 0; attempts < 8; attempts++ {
		switch automationScreenID(r) {
		case "roster.sudo.command_groups.list":
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
			if err := d.choose(r, "Sudo commands"); err != nil {
				return err
			}
		case "roster.sudo.top":
			if err := d.choose(r, "Command groups"); err != nil {
				return err
			}
		default:
			if err := d.choose(r, "返回"); err != nil {
				return fmt.Errorf("cannot navigate to roster sudo command groups list from %s screen: %w", automationScreenID(r), err)
			}
		}
	}
	return fmt.Errorf("could not resolve navigation to roster sudo command groups list")
}

func (d *automationDriver) createSudoCommandGroup(r *editRouterModel, name, commandsCSV string) error {
	if err := d.ensureRosterSudoCommandGroupsList(r); err != nil {
		return err
	}
	if err := d.choose(r, "➕ 新增 command group"); err != nil {
		return err
	}
	if err := d.typeText(r, name, false); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if err := d.typeText(r, commandsCSV, false); err != nil {
		return err
	}
	return d.enter(r)
}

func (d *automationDriver) ensureRosterSudoCommandGroupDetail(r *editRouterModel, name string) error {
	if automationScreenID(r) == "roster.sudo.command_group.detail" {
		if list, ok := r.current.(selectModel); ok && list.title == "Sudo command group "+name {
			return nil
		}
		if err := d.choose(r, "返回"); err != nil {
			return err
		}
	}
	if err := d.ensureRosterSudoCommandGroupsList(r); err != nil {
		return err
	}
	return d.choose(r, "⌘ "+name)
}

func (d *automationDriver) setSudoCommandGroupCommands(r *editRouterModel, name, commandsCSV string) error {
	if err := d.ensureRosterSudoCommandGroupDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "commands"); err != nil {
		return err
	}
	if err := d.typeText(r, commandsCSV, true); err != nil {
		return err
	}
	return d.enter(r)
}

func (d *automationDriver) ensureRosterSudoRulesList(r *editRouterModel) error {
	for attempts := 0; attempts < 8; attempts++ {
		switch automationScreenID(r) {
		case "roster.sudo.rules.list":
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
			if err := d.choose(r, "Sudo commands"); err != nil {
				return err
			}
		case "roster.sudo.top":
			if err := d.choose(r, "Sudo rules"); err != nil {
				return err
			}
		default:
			if err := d.choose(r, "返回"); err != nil {
				return fmt.Errorf("cannot navigate to roster sudo rules list from %s screen: %w", automationScreenID(r), err)
			}
		}
	}
	return fmt.Errorf("could not resolve navigation to roster sudo rules list")
}

// createSudoRule replays the full creation wizard (name -> role groups
// checklist -> command groups checklist -> extra commands text) in one
// atomic step, matching the TUI: there is no "create an empty rule"
// primitive to decouple creation from these selections.
func (d *automationDriver) createSudoRule(r *editRouterModel, name string, groups, commandGroups []string, extraCommandsCSV string) error {
	if err := d.ensureRosterSudoRulesList(r); err != nil {
		return err
	}
	if err := d.choose(r, "➕ 新增 sudo rule"); err != nil {
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
	if err := d.setChecklistSelection(r, commandGroups); err != nil {
		return err
	}
	if err := d.typeText(r, extraCommandsCSV, false); err != nil {
		return err
	}
	return d.enter(r)
}

func (d *automationDriver) ensureRosterSudoRuleDetail(r *editRouterModel, name string) error {
	if automationScreenID(r) == "roster.sudo.rule.detail" {
		if list, ok := r.current.(selectModel); ok && list.title == "Sudo rule "+name {
			return nil
		}
		if err := d.choose(r, "返回"); err != nil {
			return err
		}
	}
	if err := d.ensureRosterSudoRulesList(r); err != nil {
		return err
	}
	return d.choose(r, "⚙ "+name)
}

func (d *automationDriver) setSudoRuleGroups(r *editRouterModel, name string, groups []string) error {
	if err := d.ensureRosterSudoRuleDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "subjects.groups"); err != nil {
		return err
	}
	return d.setChecklistSelection(r, groups)
}

func (d *automationDriver) setSudoRuleCommandGroups(r *editRouterModel, name string, commandGroups []string) error {
	if err := d.ensureRosterSudoRuleDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "allow.command_groups"); err != nil {
		return err
	}
	return d.setChecklistSelection(r, commandGroups)
}

func (d *automationDriver) setSudoRuleCommands(r *editRouterModel, name, commandsCSV string) error {
	if err := d.ensureRosterSudoRuleDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "allow.commands"); err != nil {
		return err
	}
	if err := d.typeText(r, commandsCSV, true); err != nil {
		return err
	}
	return d.enter(r)
}

// setSudoRuleAllowMode drives pushRosterSudoRuleAllowMode. "all" answers
// the resulting confirm gate ("危險：可執行任何指令") with yes — the
// same explicit-confirmation-required gate deleteHost/discardHosts use
// for a destructive-shaped choice. "restricted" requires at least one
// existing command/command-group already set (pushRosterSudoRuleAllowMode's
// own guard) — callers must set those first via set_sudo_rule_commands/
// set_sudo_rule_command_groups.
func (d *automationDriver) setSudoRuleAllowMode(r *editRouterModel, name, mode string) error {
	if err := d.ensureRosterSudoRuleDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "allow.command_category"); err != nil {
		return err
	}
	if mode == "all" {
		if err := d.choose(r, "Allow all commands"); err != nil {
			return err
		}
		return d.confirmYesNo(r, true)
	}
	return d.choose(r, "Restricted allow-list")
}
