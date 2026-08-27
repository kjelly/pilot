// edit_automation_driver_roster_grants.go drives the grants/breakglass/
// explain screens (edit_tui_roster_grants.go, edit_tui_roster_breakglass.go)
// for create_grant/set_grant_subjects/set_grant_targets/set_grant_validity/
// set_grant_justification/set_grant_privilege/delete_grant/
// activate_breakglass/deactivate_breakglass, using the stable screen IDs
// added to those screens — mirroring edit_automation_driver_roster_access.go's
// HBAC-rule pattern.
package cmd

import (
	"fmt"

	"github.com/kjelly/pilot/internal/tui"
)

func (d *automationDriver) ensureAccessGovernanceMenu(r *editRouterModel) error {
	for attempts := 0; attempts < 9; attempts++ {
		switch automationScreenID(r) {
		case "roster.access_gov.top":
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
			if err := d.choose(r, "Access governance"); err != nil {
				return err
			}
		default:
			if err := d.choose(r, "返回"); err != nil {
				return fmt.Errorf("cannot navigate to Access governance menu from %s screen: %w", automationScreenID(r), err)
			}
		}
	}
	return fmt.Errorf("could not resolve navigation to Access governance menu")
}

func (d *automationDriver) ensureRosterGrantsList(r *editRouterModel) error {
	for attempts := 0; attempts < 10; attempts++ {
		switch automationScreenID(r) {
		case "roster.grants.list":
			return nil
		case "roster.access_gov.top":
			if err := d.choose(r, "Grants"); err != nil {
				return err
			}
		default:
			if err := d.ensureAccessGovernanceMenu(r); err != nil {
				return err
			}
		}
	}
	return fmt.Errorf("could not resolve navigation to roster grants list")
}

// createGrant replays the kind-branching creation wizard
// (pushAddGrantKind's chain, edit_tui_roster_grants.go) in one atomic
// step, matching the TUI: breakglass skips subjects.groups entirely
// (checkGrants forbids it), sudo_grant skips services (no PAM-service
// concept), and only temporary_grant/sudo_grant collect validity/
// justification. notBefore/reason/ticket may be "" (all optional or
// N/A depending on kind); maxDuration is breakglass-only.
func (d *automationDriver) createGrant(r *editRouterModel, kind, name string, groups, users, hostgroups, hosts, services []string, notBefore, notAfter, reason, ticket, maxDuration string) error {
	if err := d.ensureRosterGrantsList(r); err != nil {
		return err
	}
	if err := d.choose(r, "➕ 新增 grant"); err != nil {
		return err
	}
	if err := d.choose(r, kind); err != nil {
		return err
	}
	if err := d.typeText(r, name, false); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if err := d.setChecklistSelection(r, users); err != nil {
		return err
	}
	if kind != "breakglass" {
		if err := d.setChecklistSelectionByID(r, groups); err != nil {
			return err
		}
	}
	if err := d.setChecklistSelection(r, hostgroups); err != nil {
		return err
	}
	if err := d.setDirectHostsInput(r, hosts); err != nil {
		return err
	}
	if kind == "sudo_grant" {
		return d.finishGrantValidityJustification(r, notBefore, notAfter, reason, ticket)
	}
	if err := d.setChecklistSelection(r, services); err != nil {
		return err
	}
	if kind == "breakglass" {
		if err := d.typeText(r, maxDuration, false); err != nil {
			return err
		}
		return d.enter(r)
	}
	return d.finishGrantValidityJustification(r, notBefore, notAfter, reason, ticket)
}

// finishGrantValidityJustification drives the shared not_before -> not_after
// -> reason -> ticket tail both the temporary_grant and sudo_grant create
// paths end on.
func (d *automationDriver) finishGrantValidityJustification(r *editRouterModel, notBefore, notAfter, reason, ticket string) error {
	if err := d.typeText(r, notBefore, false); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if err := d.typeText(r, notAfter, false); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if err := d.typeText(r, reason, false); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if err := d.typeText(r, ticket, false); err != nil {
		return err
	}
	return d.enter(r)
}

func (d *automationDriver) ensureGrantDetail(r *editRouterModel, name string) error {
	if automationScreenID(r) == "roster.grants.detail" {
		if st := automationState(r); st.Kind == tui.ScreenSelect && st.Title == "Grant "+name {
			return nil
		}
		if err := d.choose(r, "返回"); err != nil {
			return err
		}
	}
	if err := d.ensureRosterGrantsList(r); err != nil {
		return err
	}
	return d.choose(r, name)
}

func (d *automationDriver) setGrantSubjects(r *editRouterModel, name string, users, groups []string) error {
	if err := d.ensureGrantDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "subjects.users"); err != nil {
		return err
	}
	if err := d.setChecklistSelection(r, users); err != nil {
		return err
	}
	if err := d.ensureGrantDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "subjects.groups"); err != nil {
		return err
	}
	return d.setChecklistSelectionByID(r, groups)
}

func (d *automationDriver) setGrantTargets(r *editRouterModel, name string, hostgroups, hosts []string) error {
	if err := d.ensureGrantDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "targets.hostgroups"); err != nil {
		return err
	}
	if err := d.setChecklistSelection(r, hostgroups); err != nil {
		return err
	}
	if err := d.ensureGrantDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "targets.hosts"); err != nil {
		return err
	}
	return d.setDirectHostsInput(r, hosts)
}

func (d *automationDriver) setGrantValidity(r *editRouterModel, name, notBefore, notAfter string) error {
	if err := d.ensureGrantDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "validity"); err != nil {
		return err
	}
	if err := d.typeText(r, notBefore, true); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if err := d.typeText(r, notAfter, true); err != nil {
		return err
	}
	return d.enter(r)
}

func (d *automationDriver) setGrantJustification(r *editRouterModel, name, reason, ticket string) error {
	if err := d.ensureGrantDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "justification"); err != nil {
		return err
	}
	if err := d.typeText(r, reason, true); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if err := d.typeText(r, ticket, true); err != nil {
		return err
	}
	return d.enter(r)
}

// setGrantActivation drives pushGrantMaxDuration (edit_tui_roster_grants.go)
// — the breakglass counterpart of setGrantValidity, editing
// activation.max_duration rather than validity.not_before/not_after.
func (d *automationDriver) setGrantActivation(r *editRouterModel, name, maxDuration string) error {
	if err := d.ensureGrantDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "activation.max_duration"); err != nil {
		return err
	}
	if err := d.typeText(r, maxDuration, true); err != nil {
		return err
	}
	return d.enter(r)
}

func (d *automationDriver) setGrantPrivilege(r *editRouterModel, name string, commandGroups []string) error {
	if err := d.ensureGrantDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "privilege.command_groups"); err != nil {
		return err
	}
	return d.setChecklistSelection(r, commandGroups)
}

// deleteGrant is a soft delete (state: absent, roster_grants.go's
// declarative convention — see SetRosterGrant's own doc comment) driven
// by toggling the detail screen's state item, which is idempotent: if
// the grant is already absent, choosing "state" again would flip it back
// to present, so this checks the current label first.
func (d *automationDriver) deleteGrant(r *editRouterModel, name string) error {
	if err := d.ensureGrantDetail(r, name); err != nil {
		return err
	}
	st := automationState(r)
	if st.Kind != tui.ScreenSelect {
		return fmt.Errorf("expected grant detail screen, got %s", automationScreenID(r))
	}
	for _, item := range st.Items {
		if item.Label == "state：absent（選取切換 present/absent）" {
			return nil
		}
	}
	return d.choose(r, "state：")
}

func (d *automationDriver) ensureBreakglassDetail(r *editRouterModel, name string) error {
	for attempts := 0; attempts < 11; attempts++ {
		if automationScreenID(r) == "roster.breakglass.detail" {
			if st := automationState(r); st.Kind == tui.ScreenSelect && st.Title == "Break-glass "+name {
				return nil
			}
			if err := d.choose(r, "返回"); err != nil {
				return err
			}
			continue
		}
		switch automationScreenID(r) {
		case "roster.breakglass.list":
			if err := d.choose(r, name); err != nil {
				return err
			}
		case "roster.access_gov.top":
			if err := d.choose(r, "Break-glass"); err != nil {
				return err
			}
		default:
			if err := d.ensureAccessGovernanceMenu(r); err != nil {
				return err
			}
		}
	}
	return fmt.Errorf("could not resolve navigation to breakglass detail for %s", name)
}

func (d *automationDriver) activateBreakglass(r *editRouterModel, name, duration, reason, ticket string) error {
	if err := d.ensureBreakglassDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "Activate"); err != nil {
		return err
	}
	if err := d.typeText(r, duration, false); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if err := d.typeText(r, reason, false); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if err := d.typeText(r, ticket, false); err != nil {
		return err
	}
	return d.enter(r)
}

func (d *automationDriver) deactivateBreakglass(r *editRouterModel, name string) error {
	if err := d.ensureBreakglassDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "Deactivate"); err != nil {
		return err
	}
	return d.choose(r, "是，立即停用")
}
