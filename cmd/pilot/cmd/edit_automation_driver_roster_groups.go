// edit_automation_driver_roster_groups.go drives the roster group
// screens (pushRosterGroupsMenu et al., edit_tui_roster.go) for
// create_group/set_group_field/set_group_members_users/
// set_group_members_groups (Phase 6 increment 3), using the stable
// screen IDs added to those screens (roster.groups.list,
// roster.group.add_category/add_name, roster.group.detail,
// roster.group.field_type/text/int/authoritative,
// roster.group.members_users/members_groups) instead of title-substring
// matching, mirroring edit_automation_driver_roster.go's user pattern.
package cmd

import (
	"fmt"
	"strings"

	"github.com/kjelly/pilot/internal/tui"
)

func (d *automationDriver) ensureRosterGroupsList(r *editRouterModel) error {
	for attempts := 0; attempts < 8; attempts++ {
		switch automationScreenID(r) {
		case "roster.groups.list":
			return nil
		case "edit.top":
			if err := d.choose(r, "roster"); err != nil {
				return err
			}
		case "roster.path":
			// Accept the prefilled default path (.vault/ipa-identity.yaml).
			if err := d.enter(r); err != nil {
				return err
			}
		case rosterCreateConfirmScreenID:
			if err := d.resolveRosterCreatePrompt(r); err != nil {
				return err
			}
		case "roster.top":
			if err := d.choose(r, "👥 Groups"); err != nil {
				return err
			}
		default:
			// Any other screen (roster.group.detail, or a sibling section's
			// screen like roster.users.list/roster.user.detail) climbs back
			// one level via its own "返回"/"↩  返回" item — see
			// ensureRosterUsersList's identical comment for why this is a
			// single generic step rather than an enumerated case list.
			if err := d.choose(r, "返回"); err != nil {
				return fmt.Errorf("cannot navigate to roster groups list from %s screen: %w", automationScreenID(r), err)
			}
		}
	}
	return fmt.Errorf("could not resolve navigation to roster groups list")
}

func (d *automationDriver) ensureRosterGroupDetail(r *editRouterModel, group string) error {
	if automationScreenID(r) == "roster.group.detail" {
		if st := automationState(r); st.Kind == tui.ScreenSelect && listTitleNamesGroup(st.Title, group) {
			return nil
		}
		if err := d.choose(r, "↩  返回"); err != nil {
			return err
		}
	}
	if err := d.ensureRosterGroupsList(r); err != nil {
		return err
	}
	return d.choose(r, "👥 "+group)
}

// listTitleNamesGroup reports whether title is pushRosterGroupDetail's
// title for exactly this group — `Group "name" — path`.
func listTitleNamesGroup(title, group string) bool {
	return strings.HasPrefix(title, fmt.Sprintf("Group %q ", group))
}

func (d *automationDriver) createGroup(r *editRouterModel, group, category string) error {
	if err := d.ensureRosterGroupsList(r); err != nil {
		return err
	}
	if err := d.choose(r, "➕ 新增 Group"); err != nil {
		return err
	}
	if err := d.choose(r, category); err != nil {
		return err
	}
	if err := d.typeText(r, group, false); err != nil {
		return err
	}
	return d.enter(r)
}

// rosterGroupSelectFields is set_group_field's fields whose widget is a
// select screen (roster.group.field_type/field_authoritative) rather
// than a text input.
var rosterGroupSelectFields = map[string]bool{
	"type":                      true,
	"membership.authoritative": true,
}

func (d *automationDriver) setGroupField(r *editRouterModel, group, field, value string) error {
	if err := d.ensureRosterGroupDetail(r, group); err != nil {
		return err
	}
	if err := d.choose(r, field); err != nil {
		return err
	}
	if rosterGroupSelectFields[field] {
		return d.choose(r, value)
	}
	if err := d.typeText(r, value, true); err != nil {
		return err
	}
	return d.enter(r)
}

func (d *automationDriver) setGroupMembersUsers(r *editRouterModel, group string, users []string) error {
	if err := d.ensureRosterGroupDetail(r, group); err != nil {
		return err
	}
	if err := d.choose(r, "membership.users"); err != nil {
		return err
	}
	return d.setChecklistSelection(r, users)
}

func (d *automationDriver) setGroupMembersGroups(r *editRouterModel, group string, groups []string) error {
	if err := d.ensureRosterGroupDetail(r, group); err != nil {
		return err
	}
	if err := d.choose(r, "membership.groups"); err != nil {
		return err
	}
	return d.setChecklistSelection(r, groups)
}
