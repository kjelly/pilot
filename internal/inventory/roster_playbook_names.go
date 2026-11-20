package inventory

// A roster string is rendered inside the consuming playbook, so it can refer
// to a variable the playbook defines for itself — its play vars and what its
// first pre_tasks define — and not only to the inventory, the vars file and
// -e. Refusing a run for such a reference would refuse one that works, with
// no override, so the names below are known to the check (issue #165).
//
// Which names a roster string can see depends on when it is rendered, and
// that is earlier than the playbook's own set_fact of the settings (verified
// against ansible-core 2.19.2, TestRosterRenderedFieldsMatchAnsible):
//
//   - freeipa-identity: the users' passwords are first rendered by "Gate:
//     canonical user objects are structurally valid" (pre_task 8), which
//     loops over the users; the admin password by "Fill canonical roster
//     freeipa.server" (pre_task 3) when the roster has no freeipa.server, and
//     otherwise by "Normalize canonical FreeIPA settings" (pre_task 18), whose
//     default() filter turns an undefined reference into an empty password that
//     "Gate: admin credential present" then refuses without naming it. What the
//     settings task sets itself (identity_admin_principal, identity_admin_password,
//     ipa_hbac_services, ipa_sudo_command_groups) and what comes after it
//     (ipa_active_users, ...) is therefore NOT visible to any roster string,
//     and a reference to one of those is an undefined variable to Ansible and
//     to this check.
//   - freeipa-nfs-server: "Gate: required roster and stage authorization"
//     (pre_task 1) renders the admin password right after the roster load.
//
// So what is visible is the play's `vars:` plus what the pre_tasks before the
// first render define. TestRosterPlaybookNamesMatchThePlaybooks reads that
// from the real playbooks and fails when they no longer match these lists;
// the oracle test renders every listed name (and the ones just after the
// site) against ansible-core. Task-level vars (item, the loop variables of the
// normalize task) exist only inside one task and are not listed.

// identityPlayVars are the `vars:` of freeipa-identity-apply.yml's play.
var identityPlayVars = []string{
	"stage", "confirm_staging", "confirm_prod", "staging_attested_within_hours",
	"ipa_domain", "ipa_realm", "identity_hbac_test_host",
	"ipa_users", "ipa_groups", "ipa_hostgroups", "ipa_hbac_rules", "ipa_sudo_rules", "ipa_netgroups", "ipa_hbac_rules_absent",
	"freeipa_roster", "ipa_hbac_disable_allow_all", "ipa_identity_refresh_sssd_cache",
	"ipa_identity_cache_mutation_registers", "ipa_identity_cache_recovery_tags",
	"ipa_ssh_cache_program", "ipa_sudo_refresh_program",
}

// identityEarlyNames are what the first three pre_tasks of the identity play
// define: the roster load, the gateway lifecycle authority and the hostname
// probe (a registered result, defined even when the probe is skipped).
var identityEarlyNames = []string{
	"freeipa_roster", "ipa_gateway_lifecycle_designated_authority", "freeipa_detected_server_fqdn",
}

// nfsPlayVars are the `vars:` of freeipa-nfs-server-apply.yml's play.
var nfsPlayVars = []string{
	"stage", "confirm_staging", "confirm_prod", "staging_attested_within_hours",
	"nfs_exports_fragment", "nfs_pseudo_root",
	"nfs_server_packages_by_os_family", "nfs_server_service_by_os_family", "nfs_server_packages", "nfs_server_service",
}

// nfsEarlyNames are what the NFS play defines before the gate that first
// renders freeipa.admin.password: its first pre_task loads the roster.
var nfsEarlyNames = []string{"freeipa_roster"}

func nameSet(lists ...[]string) map[string]bool {
	set := map[string]bool{}
	for _, list := range lists {
		for _, name := range list {
			set[name] = true
		}
	}
	return set
}

// playbookDefinedNames is the names consumer's playbook defines for itself
// before it renders a roster string.
func playbookDefinedNames(consumer RosterVarConsumer) map[string]bool {
	switch consumer {
	case RosterConsumerFreeIPAIdentity:
		return nameSet(identityPlayVars, identityEarlyNames)
	case RosterConsumerFreeIPANFSServer:
		return nameSet(nfsPlayVars, nfsEarlyNames)
	}
	return nil
}

// A user's password is not captured where it is first rendered. The value the
// identity playbook SENDS for it is the one "Normalize canonical users and groups
// (shared with drift)" (pre_task 19) renders into ipa_users, and that is later
// than "Normalize canonical FreeIPA settings" (pre_task 18), whose set_fact
// defines names that outrank an inventory value (set_fact beats inventory vars;
// experiment E3 of issue #394: an inventory host variable identity_admin_password
// was reported by `ansible-inventory --list` as one value while the playbook sent
// the vault's admin password). So the names that are NOT the inventory's when a
// user's password is captured are the first-render set plus the settings names,
// the names of the normalize tasks themselves, and the names pilot puts on the
// Ansible engine's -e line, which a Go-engine run does not pass. Using the
// first-render set alone would send a silently wrong password.
// TestPasswordCaptureNamesMatchThePlaybook reads all but the last group from the
// real playbook and its include.

// identitySettingsNames are what "Normalize canonical FreeIPA settings"
// (pre_task 18) sets with set_fact beyond the play's own vars: defined by the time
// the normalize include captures the users' passwords.
var identitySettingsNames = []string{
	"identity_admin_principal", "identity_admin_password", "ipa_hbac_services", "ipa_sudo_command_groups",
}

// identityNormalizeTaskVars are the names that exist only inside the tasks of
// tasks/freeipa-identity-normalize-users-groups.yml: the loop variable of its
// tasks and the `vars:` of "Normalize canonical users for the compatibility
// reconciler", which renders password.initial.
var identityNormalizeTaskVars = []string{
	"item", "pilot_identity_with_credentials", "pilot_identity_roster_user",
}

// pilotExtraNames are the names pilot itself puts on an Ansible-engine run's -e
// line for freeipa-identity: the roster path, the target group, the hosts an
// optional-client check deferred, and the mixed run's engine and observation
// variables. Their values in an Ansible-engine run need not be what the
// inventory lists, and a Go-engine run does not know them, so a roster that refers
// to one is not resolved here.
var pilotExtraNames = []string{
	"freeipa_roster_file", "target_group", "pilot_deferred_hosts",
	"pilot_identity_users_groups_engine", "pilot_identity_auth_cache_output",
}

// passwordCaptureNames is the names whose value, when the identity playbook
// captures a user's password.initial, is not the inventory's (see above). Only the
// identity playbook renders a user's password: any other consumer has none.
func passwordCaptureNames(consumer RosterVarConsumer) map[string]bool {
	if consumer != RosterConsumerFreeIPAIdentity {
		return nil
	}
	return nameSet(identityPlayVars, identityEarlyNames, identitySettingsNames, identityNormalizeTaskVars, pilotExtraNames)
}

// PasswordCaptureNames is passwordCaptureNames as a fresh set, for the tests that
// pin it to what pilot passes and to the playbook.
func PasswordCaptureNames(consumer RosterVarConsumer) map[string]bool {
	return passwordCaptureNames(consumer)
}

// RosterPlaybookKnownNames is every name either consuming playbook defines
// for itself before it renders a roster string: what a lint that does not
// know the consumer takes as defined, so it never reports a reference the run
// it belongs to would resolve.
func RosterPlaybookKnownNames() map[string]bool {
	return nameSet(identityPlayVars, identityEarlyNames, nfsPlayVars, nfsEarlyNames)
}

// MissingRosterVarReferencesFor is what a deploy or reconcile run of consumer
// refuses: the references of refs that the playbook renders for this run
// (RosterVarReferencesRenderedBy) and that nothing defines — no set of defined
// (the run's variables), no template global or magic variable
// (MissingRosterVarReferences) and no name the playbook defines for itself
// before it renders (playbookDefinedNames).
func MissingRosterVarReferencesFor(consumer RosterVarConsumer, refs []RosterVarRef, facts RosterRenderFacts, defined ...map[string]bool) []RosterVarRef {
	sets := append(append([]map[string]bool{}, defined...), playbookDefinedNames(consumer))
	return MissingRosterVarReferences(RosterVarReferencesRenderedBy(consumer, refs, facts), sets...)
}

// UnjudgedRosterVarReferencesFor is what a deploy or reconcile run of consumer
// does not refuse but could be failing on: the references that nothing
// defines (as MissingRosterVarReferencesFor) and that the playbook renders
// only if a fact of the run that the check cannot decide
// (RosterFactUnknown) turns out one way. A precheck says it did not judge them.
func UnjudgedRosterVarReferencesFor(consumer RosterVarConsumer, refs []RosterVarRef, facts RosterRenderFacts, defined ...map[string]bool) []RosterVarRef {
	sets := append(append([]map[string]bool{}, defined...), playbookDefinedNames(consumer))
	return MissingRosterVarReferences(RosterVarReferencesMaybeRenderedBy(consumer, refs, facts), sets...)
}
