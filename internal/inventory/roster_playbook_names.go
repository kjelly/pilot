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
