// edit_automation_driver_roster_identity.go drives the v3.2 Identity
// hardening screens (pushIdentityHardeningMenu et al.,
// edit_tui_identity_hardening.go) for the structured actions
// edit_actions_registry.go registers: create_password_policy/
// set_password_policy_field/delete_password_policy,
// set_user_authentication_types, and create_credential_policy/
// set_credential_policy_field/delete_credential_policy. Mirrors
// edit_automation_driver_roster_groups.go's exact navigation/field-set
// shape.
//
// mark_identity_review, inspect_identity_hygiene, inspect_identity_drift,
// repair_identity_drift, and inspect_freeipa_capabilities are
// deliberately NOT registered actions — see edit_actions_registry.go's
// own header comment ("deploy/reconcile are deliberately NOT in this
// registry: they run through an entirely different path") for the
// precedent this follows: repair_identity_drift needs a live ansible
// run exactly like reconcile does, inspect_* needs either a live probe
// (capabilities/drift) or a data return this Run-returns-error-only
// registry has no channel for (hygiene) — those three belong to
// pilot_edit_inspect's read side (mcp_edit_resources.go) instead.
// mark_identity_review already has zero registry precedent even for
// v3.1's identical grant-review feature (grep editActionRegistry() for
// "review" — nothing), so credential_policy review isn't a new gap here,
// it's the same established boundary.
package cmd

import (
	"fmt"

	"github.com/kjelly/pilot/internal/tui"
)

func (d *automationDriver) ensureIdentityHardeningMenu(r *editRouterModel) error {
	for attempts := 0; attempts < 9; attempts++ {
		switch automationScreenID(r) {
		case "roster.identity.top":
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
			if err := d.choose(r, "Identity hardening"); err != nil {
				return err
			}
		default:
			if err := d.choose(r, "返回"); err != nil {
				return fmt.Errorf("cannot navigate to identity hardening menu from %s screen: %w", automationScreenID(r), err)
			}
		}
	}
	return fmt.Errorf("could not resolve navigation to identity hardening menu")
}

// ---- Password policies --------------------------------------------------

func (d *automationDriver) ensurePasswordPoliciesList(r *editRouterModel) error {
	for attempts := 0; attempts < 10; attempts++ {
		switch automationScreenID(r) {
		case "roster.password_policies.list":
			return nil
		case "roster.identity.top":
			if err := d.choose(r, "Password policies"); err != nil {
				return err
			}
		default:
			if err := d.ensureIdentityHardeningMenu(r); err != nil {
				return err
			}
		}
	}
	return fmt.Errorf("could not resolve navigation to password policies list")
}

func (d *automationDriver) ensurePasswordPolicyDetail(r *editRouterModel, name string) error {
	if automationScreenID(r) == "roster.password_policy.detail" {
		if st := automationState(r); st.Kind == tui.ScreenSelect && st.Title == "Password policy "+name {
			return nil
		}
		if err := d.choose(r, "返回"); err != nil {
			return err
		}
	}
	if err := d.ensurePasswordPoliciesList(r); err != nil {
		return err
	}
	return d.choose(r, "🔑 "+name)
}

// createPasswordPolicy replays pushRosterAddPasswordPolicy's three-screen
// chain (name -> group -> priority) — group and priority are co-required
// (checkPasswordPolicies rejects a present entry missing either), so
// AppendRosterPasswordPolicy is only ever called once both are already
// known; see that screen's doc comment for why a bare create-then-edit-
// fields-incrementally flow doesn't work here.
func (d *automationDriver) createPasswordPolicy(r *editRouterModel, name, group, priority string) error {
	if err := d.ensurePasswordPoliciesList(r); err != nil {
		return err
	}
	if err := d.choose(r, "➕ 新增 Password policy"); err != nil {
		return err
	}
	if err := d.typeText(r, name, false); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if err := d.typeText(r, group, false); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if err := d.typeText(r, priority, false); err != nil {
		return err
	}
	return d.enter(r)
}

// passwordPolicySelectFields is set_password_policy_field's fields whose
// widget is a select screen (state) rather than a text/int input — every
// other field (group/priority/min_length/history_size/max_life/min_life/
// lockout.*) is a plain InputSpec from the driver's point of view,
// whether or not it happens to validate as an integer.
var passwordPolicySelectFields = map[string]bool{"state": true}

func (d *automationDriver) setPasswordPolicyField(r *editRouterModel, name, field, value string) error {
	if err := d.ensurePasswordPolicyDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, field); err != nil {
		return err
	}
	if passwordPolicySelectFields[field] {
		return d.choose(r, value)
	}
	if err := d.typeText(r, value, true); err != nil {
		return err
	}
	return d.enter(r)
}

func (d *automationDriver) deletePasswordPolicy(r *editRouterModel, name string) error {
	if err := d.ensurePasswordPolicyDetail(r, name); err != nil {
		return err
	}
	st := automationState(r)
	if st.Kind == tui.ScreenSelect {
		for _, item := range st.Items {
			if item.Label == "state：absent" {
				return nil
			}
		}
	}
	if err := d.choose(r, "state"); err != nil {
		return err
	}
	return d.choose(r, "absent")
}

// ---- Credential policies -------------------------------------------------

func (d *automationDriver) ensureCredentialPoliciesList(r *editRouterModel) error {
	for attempts := 0; attempts < 10; attempts++ {
		switch automationScreenID(r) {
		case "roster.credential_policies.list":
			return nil
		case "roster.identity.top":
			if err := d.choose(r, "Credential policies"); err != nil {
				return err
			}
		default:
			if err := d.ensureIdentityHardeningMenu(r); err != nil {
				return err
			}
		}
	}
	return fmt.Errorf("could not resolve navigation to credential policies list")
}

func (d *automationDriver) ensureCredentialPolicyDetail(r *editRouterModel, name string) error {
	if automationScreenID(r) == "roster.credential_policy.detail" {
		if st := automationState(r); st.Kind == tui.ScreenSelect && st.Title == "Credential policy "+name {
			return nil
		}
		if err := d.choose(r, "返回"); err != nil {
			return err
		}
	}
	if err := d.ensureCredentialPoliciesList(r); err != nil {
		return err
	}
	return d.choose(r, "🗝️  "+name)
}

func (d *automationDriver) createCredentialPolicy(r *editRouterModel, name string) error {
	if err := d.ensureCredentialPoliciesList(r); err != nil {
		return err
	}
	if err := d.choose(r, "➕ 新增 Credential policy"); err != nil {
		return err
	}
	if err := d.typeText(r, name, false); err != nil {
		return err
	}
	return d.enter(r)
}

var credentialPolicySelectFields = map[string]bool{"state": true, "ssh.require_comment": true}
var credentialPolicyChecklistFields = map[string]bool{"match.users": true, "match.groups": true}

// setCredentialPolicyField sets any single-value field (state, a text/
// duration input, or the ssh.require_comment toggle) via value. Bulk-
// replacing match.users/match.groups (checklists, not single values) is
// setCredentialPolicyMembers instead — mirrors set_group_field's own
// split from set_group_members_users/set_group_members_groups exactly.
func (d *automationDriver) setCredentialPolicyField(r *editRouterModel, name, field, value string) error {
	if credentialPolicyChecklistFields[field] {
		return fmt.Errorf("field %q is a checklist — use setCredentialPolicyMembers, not setCredentialPolicyField", field)
	}
	if err := d.ensureCredentialPolicyDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, field); err != nil {
		return err
	}
	if credentialPolicySelectFields[field] {
		return d.choose(r, value)
	}
	if err := d.typeText(r, value, true); err != nil {
		return err
	}
	return d.enter(r)
}

func (d *automationDriver) setCredentialPolicyMembers(r *editRouterModel, name, field string, values []string) error {
	if !credentialPolicyChecklistFields[field] {
		return fmt.Errorf("field %q is not a checklist field (match.users/match.groups)", field)
	}
	if err := d.ensureCredentialPolicyDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, field); err != nil {
		return err
	}
	return d.setChecklistSelection(r, values)
}

func (d *automationDriver) deleteCredentialPolicy(r *editRouterModel, name string) error {
	if err := d.ensureCredentialPolicyDetail(r, name); err != nil {
		return err
	}
	st := automationState(r)
	if st.Kind == tui.ScreenSelect {
		for _, item := range st.Items {
			if item.Label == "state：absent" {
				return nil
			}
		}
	}
	if err := d.choose(r, "state"); err != nil {
		return err
	}
	return d.choose(r, "absent")
}

// ---- Per-user authentication types (spec.md §8) --------------------------

// setUserAuthenticationTypes bulk-replaces users[name].authentication.allowed
// via the checklist added to the existing user detail screen
// (pushRosterUserAuthenticationField, edit_tui_roster.go) — reuses
// ensureRosterUserDetail (edit_automation_driver_roster.go) exactly as
// every other per-user field action already does.
func (d *automationDriver) setUserAuthenticationTypes(r *editRouterModel, user string, allowed []string) error {
	if err := d.ensureRosterUserDetail(r, user); err != nil {
		return err
	}
	if err := d.choose(r, "authentication.allowed"); err != nil {
		return err
	}
	return d.setChecklistSelection(r, allowed)
}
