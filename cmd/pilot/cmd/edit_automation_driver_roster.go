// edit_automation_driver_roster.go drives the roster user screens
// (edit_tui_roster.go) for semantic edit-scenario actions — create_user,
// set_user_field (Phase 6 increment 1, non-secret fields), and
// set_user_password/add_ssh_key/delete_ssh_key (Phase 6 increment 2,
// password.initial + ssh_keys.values) — see
// docs/superpowers/specs/2026-08-04-pilot-edit-mcp-semantic-tui-design.md's
// Phase 6 plan. Mirrors createHost/setHostField
// (edit_automation_driver.go) exactly, using the stable screen IDs
// edit_tui_roster.go now carries (roster.top, roster.users.list,
// roster.user.add, roster.user.detail, roster.user.field_text/int/
// bool/state, roster.user.field_password/field_password_bool,
// roster.user.ssh_keys.list/add/item_action/edit_item) instead of
// title-substring matching.
package cmd

import (
	"fmt"
	"strings"
)

// ensureRosterUsersList resolves the router to the roster users list
// screen from wherever it currently is — the top menu, the roster path
// prompt (accepts the prefilled default path), the roster top menu, or
// an open user detail screen. It does not handle a missing roster file
// (that flow requires a FreeIPA admin password prompt, out of scope for
// this increment) — automation requires the roster file to already
// exist at its default path.
func (d *automationDriver) ensureRosterUsersList(r *editRouterModel) error {
	for attempts := 0; attempts < 8; attempts++ {
		switch automationScreenID(r) {
		case "roster.users.list":
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
		case "roster.top":
			if err := d.choose(r, "👤 Users"); err != nil {
				return err
			}
		default:
			// Any other screen (roster.user.detail, roster.user.ssh_keys.list,
			// or a sibling section's screen like roster.group.detail) climbs
			// back one level via its own "返回"/"↩  返回" item — every detail
			// or sub-list screen has exactly one, and "返回" substring-matches
			// either form (uniqueItemIndex), so this is a single generic step
			// rather than enumerating every screen this function might see.
			if err := d.choose(r, "返回"); err != nil {
				return fmt.Errorf("cannot navigate to roster users list from %s screen: %w", automationScreenID(r), err)
			}
		}
	}
	return fmt.Errorf("could not resolve navigation to roster users list")
}

// ensureRosterUserDetail resolves the router to user's own detail
// screen, reusing it directly if a previous action in the same scenario
// already left the router there (pushRosterEditUser's commit path ends
// on the edited user's detail screen, not back at the list).
func (d *automationDriver) ensureRosterUserDetail(r *editRouterModel, user string) error {
	if automationScreenID(r) == "roster.user.detail" {
		if list, ok := r.current.(selectModel); ok && listTitleNamesUser(list.title, user) {
			return nil
		}
		if err := d.choose(r, "返回"); err != nil {
			return err
		}
	}
	if err := d.ensureRosterUsersList(r); err != nil {
		return err
	}
	return d.choose(r, "👤 "+user)
}

// listTitleNamesUser reports whether title is pushRosterUserDetail's
// title for exactly this user — `User "name" — path`.
func listTitleNamesUser(title, user string) bool {
	return strings.HasPrefix(title, fmt.Sprintf("User %q ", user))
}

func (d *automationDriver) createUser(r *editRouterModel, user string) error {
	if err := d.ensureRosterUsersList(r); err != nil {
		return err
	}
	if err := d.choose(r, "➕ 新增 User"); err != nil {
		return err
	}
	if err := d.typeText(r, user, false); err != nil {
		return err
	}
	return d.enter(r)
}

// rosterUserSelectFields is set_user_field's fields whose widget is
// itself a select screen (roster.user.field_bool/field_state) — the
// driver must choose(value) on that screen rather than type it.
var rosterUserSelectFields = map[string]bool{
	"state":   true,
	"enabled": true,
}

func (d *automationDriver) setUserField(r *editRouterModel, user, field, value string) error {
	if err := d.ensureRosterUserDetail(r, user); err != nil {
		return err
	}
	if err := d.choose(r, field); err != nil {
		return err
	}
	if rosterUserSelectFields[field] {
		return d.choose(r, value)
	}
	if err := d.typeText(r, value, true); err != nil {
		return err
	}
	return d.enter(r)
}

// setUserPassword drives pushRosterUserPasswordInitial, which always
// starts blank (it never prefills the old password — see that
// function's own label text), so replace=false is correct here, unlike
// setUserField's replace=true for a pre-filled scalar.
func (d *automationDriver) setUserPassword(r *editRouterModel, user, value string, secret bool) error {
	if err := d.ensureRosterUserDetail(r, user); err != nil {
		return err
	}
	if err := d.choose(r, "password.initial"); err != nil {
		return err
	}
	if err := d.typeSecretOrPlain(r, value, secret, false); err != nil {
		return err
	}
	return d.enter(r)
}

// addSSHKey drives pushRosterUserSSHKeysList's "➕ 新增公鑰" entry.
// ssh_keys.values items are public keys, never masked in the interactive
// TUI (pushRosterUserSSHKeysAdd uses a plain, unmasked text input), so
// this reads value literally rather than through typeSecretOrPlain.
func (d *automationDriver) addSSHKey(r *editRouterModel, user, value string) error {
	if err := d.ensureRosterUserDetail(r, user); err != nil {
		return err
	}
	if err := d.choose(r, "ssh_keys.values"); err != nil {
		return err
	}
	if err := d.choose(r, "➕ 新增公鑰"); err != nil {
		return err
	}
	if err := d.typeText(r, value, false); err != nil {
		return err
	}
	return d.enter(r)
}

// deleteSSHKey matches value against the list screen's "<n>: <value>"
// item text (uniqueItemIndex's substring match) — value must be the
// exact public key string, matching exactly one entry. choose() already
// sends Enter after moving the cursor, so no separate enter() call is
// needed after either selection below.
func (d *automationDriver) deleteSSHKey(r *editRouterModel, user, value string) error {
	if err := d.ensureRosterUserDetail(r, user); err != nil {
		return err
	}
	if err := d.choose(r, "ssh_keys.values"); err != nil {
		return err
	}
	if err := d.choose(r, value); err != nil {
		return err
	}
	return d.choose(r, "移除")
}
