package inventory

import (
	"strings"
	"testing"
)

// grantsRosterBase is a minimal schema-v3 roster with one of each group
// category (§4/§7's category policy) and one host/hostgroup, so grants
// fixtures below only need to add a `grants:` block. hbac/sudo stay empty
// — checkHBAC/checkSudo don't require any rules to be present.
const grantsRosterBase = `
schema_version: 3
freeipa:
  domain: ipa.pilot.internal
  admin: {principal: admin, password: x}
users:
  - name: alice
    ssh_keys: {authoritative: true, values: []}
  - name: vendor01
    ssh_keys: {authoritative: true, values: []}
groups:
  - name: team-sre
    category: team
    membership: {users: [alice], groups: []}
  - name: role-production-operator
    category: role
    membership: {users: [alice], groups: []}
  - name: access-legacy
    category: access
    membership: {users: [alice], groups: []}
  - name: data-secrets
    category: filesystem
    membership: {users: [], groups: []}
hosts:
  - name: db-special.ipa.pilot.internal
    ip_address: 10.0.0.5
hostgroups:
  - name: production-db
hbac:
  rules: []
sudo:
  rules: []
`

func grantsRoster(t *testing.T, grantsYAML string) map[string]any {
	t.Helper()
	return mustParseRoster(t, grantsRosterBase+grantsYAML)
}

func TestValidateRoster_TemporaryGrantUsersOnly(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: vendor-project-x
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2026-08-31T18:00:00+08:00"}
    justification: {reason: "Project X maintenance"}
`)
	if v := ValidateRosterV3(root); len(v) != 0 {
		t.Fatalf("expected clean pass, got: %v", v)
	}
}

func TestValidateRoster_TemporaryGrantTeamGroup(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: team-window
    kind: temporary_grant
    subjects: {users: [], groups: [team-sre]}
    targets: {hosts: [], hostgroups: [production-db]}
    services: [sshd]
    validity: {not_before: "2026-08-21T09:00:00+08:00", not_after: "2026-08-31T18:00:00+08:00"}
    justification: {reason: "team maintenance window"}
`)
	if v := ValidateRosterV3(root); len(v) != 0 {
		t.Fatalf("expected clean pass, got: %v", v)
	}
}

func TestValidateRoster_TemporaryGrantRoleGroup(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: role-window
    kind: temporary_grant
    subjects: {users: [], groups: [role-production-operator]}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2026-08-31T18:00:00+08:00"}
    justification: {reason: "role maintenance window"}
`)
	if v := ValidateRosterV3(root); len(v) != 0 {
		t.Fatalf("expected clean pass, got: %v", v)
	}
}

func TestValidateRoster_TemporaryGrantLegacyAccessGroup(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: legacy-window
    kind: temporary_grant
    subjects: {users: [], groups: [access-legacy]}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2026-08-31T18:00:00+08:00"}
    justification: {reason: "legacy compatibility window"}
`)
	if v := ValidateRosterV3(root); len(v) != 0 {
		t.Fatalf("expected clean pass, got: %v", v)
	}
}

func TestValidateRoster_TemporaryGrantFilesystemGroupRejected(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: bad-window
    kind: temporary_grant
    subjects: {users: [], groups: [data-secrets]}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2026-08-31T18:00:00+08:00"}
    justification: {reason: "should be rejected"}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "grant subject group category") {
		t.Fatalf("expected filesystem group to be rejected as a grant subject, got: %v", v)
	}
}

func TestValidateRoster_TemporaryGrantMixedUsersAndGroups(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: mixed-subjects
    kind: temporary_grant
    subjects: {users: [vendor01], groups: [team-sre]}
    targets: {hosts: [], hostgroups: [production-db]}
    services: [sshd]
    validity: {not_after: "2026-08-31T18:00:00+08:00"}
    justification: {reason: "mixed subjects"}
`)
	if v := ValidateRosterV3(root); len(v) != 0 {
		t.Fatalf("expected clean pass, got: %v", v)
	}
}

func TestValidateRoster_TemporaryGrantMixedHostsAndHostgroups(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: mixed-targets
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: [production-db]}
    services: [sshd]
    validity: {not_after: "2026-08-31T18:00:00+08:00"}
    justification: {reason: "mixed targets"}
`)
	if v := ValidateRosterV3(root); len(v) != 0 {
		t.Fatalf("expected clean pass, got: %v", v)
	}
}

func TestValidateRoster_SudoGrantRoleGroup(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: alice-prod-nginx
    kind: sudo_grant
    subjects: {users: [], groups: [role-production-operator]}
    targets: {hosts: [], hostgroups: [production-db]}
    privilege: {commands: [], command_groups: [], command_category: "all"}
    run_as: {users: [root], groups: []}
    options: []
    validity: {not_before: "2026-08-21T15:00:00+08:00", not_after: "2026-08-21T19:00:00+08:00"}
    justification: {reason: "incident response", ticket: "INC-4421"}
`)
	if v := ValidateRosterV3(root); len(v) != 0 {
		t.Fatalf("expected clean pass, got: %v", v)
	}
}

func TestValidateRoster_SudoGrantTeamGroupRejected(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: bad-sudo
    kind: sudo_grant
    subjects: {users: [], groups: [team-sre]}
    targets: {hosts: [], hostgroups: [production-db]}
    validity: {not_after: "2026-08-21T19:00:00+08:00"}
    justification: {reason: "should be rejected"}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "grant subject group category") {
		t.Fatalf("expected team group to be rejected as a sudo_grant subject, got: %v", v)
	}
}

func TestValidateRoster_BreakglassSubjectGroupsRejected(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: infra-emergency
    kind: breakglass
    subjects: {users: [], groups: [role-production-operator]}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    activation: {max_duration: 1h, require_reason: true, require_ticket: true}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "grant subject group category") {
		t.Fatalf("expected breakglass subjects.groups to be rejected, got: %v", v)
	}
}

func TestValidateRoster_BreakglassWithValidityRejected(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: infra-emergency
    kind: breakglass
    subjects: {users: [alice], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    activation: {max_duration: 1h}
    validity: {not_after: "2026-08-31T18:00:00+08:00"}
`)
	v := ValidateRosterV3(root)
	if !anyDetailContains(v, "validity") {
		t.Fatalf("expected breakglass carrying validity to be rejected as an unknown field, got: %v", v)
	}
}

func TestValidateRoster_BreakglassWithJustificationRejected(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: infra-emergency
    kind: breakglass
    subjects: {users: [alice], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    activation: {max_duration: 1h}
    justification: {reason: "should be rejected"}
`)
	v := ValidateRosterV3(root)
	if !anyDetailContains(v, "justification") {
		t.Fatalf("expected breakglass carrying justification to be rejected as an unknown field, got: %v", v)
	}
}

func TestValidateRoster_BreakglassValidDefinitionPassesClean(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: infra-emergency
    kind: breakglass
    subjects: {users: [alice], groups: []}
    targets: {hosts: [], hostgroups: [production-db]}
    services: [sshd]
    activation: {max_duration: 1h, require_reason: true, require_ticket: true}
    auth_policy: production-strong-auth
`)
	if v := ValidateRosterV3(root); len(v) != 0 {
		t.Fatalf("expected clean pass, got: %v", v)
	}
}

// TestValidateRoster_GrantTargetHostNotRequiredInRosterHosts locks in
// spec.md §7's explicit rule ("do not require top-level hosts:
// declaration") — a grant may target any FQDN-shaped enrolled host, not
// only one this same roster's `hosts:` list happens to also declare
// (found on a real vm-target: a grant targeting the FreeIPA server's own
// already-enrolled host, which this roster had no reason to redeclare,
// was wrongly rejected before this test existed).
func TestValidateRoster_GrantTargetHostNotRequiredInRosterHosts(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: not-in-hosts-list
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [elsewhere.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2026-08-31T18:00:00+08:00"}
    justification: {reason: "not declared under hosts:"}
`)
	v := ValidateRosterV3(root)
	if len(v) != 0 {
		t.Fatalf("expected a target host absent from roster hosts: to still pass, got: %v", v)
	}
}

func TestValidateRoster_GrantTargetHostMustBeFQDNShaped(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: malformed-host
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [not-an-fqdn], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2026-08-31T18:00:00+08:00"}
    justification: {reason: "malformed"}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "grant target host FQDN") {
		t.Fatalf("expected a non-FQDN-shaped target host to be rejected, got: %v", v)
	}
}

func TestValidateRoster_GrantInvalidTimeIntervalRejected(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: backwards-window
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_before: "2026-08-31T18:00:00+08:00", not_after: "2026-08-21T09:00:00+08:00"}
    justification: {reason: "backwards"}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "grant validity") {
		t.Fatalf("expected not_after <= not_before to be rejected, got: %v", v)
	}
}

func TestValidateRoster_GrantApprovalFieldRejected(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: needs-approval
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2026-08-31T18:00:00+08:00"}
    justification: {reason: "approval is out of scope in v3.0"}
    approval: {approved_by: alice}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "grant keys") || !anyDetailContains(v, "approval") {
		t.Fatalf("expected approval field to be rejected as unknown, got: %v", v)
	}
}

func TestValidateRoster_UnknownGrantKindRejected(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: mystery
    kind: login
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "grant kind") {
		t.Fatalf("expected unrecognized kind %q to be rejected, got: %v", "login", v)
	}
}

func TestValidateRoster_DuplicateGrantNamesRejected(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: dup
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2026-08-31T18:00:00+08:00"}
    justification: {reason: "first"}
  - name: dup
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2026-08-31T18:00:00+08:00"}
    justification: {reason: "second"}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "unique grant names") {
		t.Fatalf("expected duplicate grant names to be rejected, got: %v", v)
	}
}

// TestValidateRoster_PreV3Phase1GrantShapeFailsExplicit is the baseline
// compat check spec.md §5a/§19 require: a grant carrying only the
// already-shipped shape (name/kind/subjects/targets, no state/services/
// validity/justification/activation) must not be silently reclassified —
// it must fail closed with an actionable message naming exactly what's
// missing.
func TestValidateRoster_PreV3Phase1GrantShapeFailsExplicit(t *testing.T) {
	temporary := grantsRoster(t, `
grants:
  - name: pre-phase1
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
`)
	v := ValidateRosterV3(temporary)
	if !contains(ruleNames(v), "grant validity") || !contains(ruleNames(v), "grant justification") {
		t.Fatalf("expected pre-phase1 temporary_grant shape to fail closed on missing validity/justification, got: %v", v)
	}

	breakglass := grantsRoster(t, `
grants:
  - name: pre-phase1-bg
    kind: breakglass
    subjects: {users: [alice], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
`)
	bv := ValidateRosterV3(breakglass)
	if !contains(ruleNames(bv), "grant activation") {
		t.Fatalf("expected pre-phase1 breakglass shape to fail closed on missing activation, got: %v", bv)
	}
}

func TestValidateRoster_SudoGrantCommandDenylistReused(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: dangerous-sudo
    kind: sudo_grant
    subjects: {users: [alice], groups: []}
    targets: {hosts: [], hostgroups: [production-db]}
    privilege: {commands: [/bin/bash], command_groups: []}
    validity: {not_after: "2026-08-21T19:00:00+08:00"}
    justification: {reason: "should be rejected"}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "sudo command denylist") {
		t.Fatalf("expected the shared sudo command denylist to reject /bin/bash, got: %v", v)
	}
}

func TestValidateRoster_SudoGrantCommandGroupReferenceUnknown(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: dangling-command-group
    kind: sudo_grant
    subjects: {users: [alice], groups: []}
    targets: {hosts: [], hostgroups: [production-db]}
    privilege: {commands: [], command_groups: [web-service-manage]}
    validity: {not_after: "2026-08-21T19:00:00+08:00"}
    justification: {reason: "dangling"}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "sudo command group reference") {
		t.Fatalf("expected unknown privilege.command_groups reference to be rejected, got: %v", v)
	}
}

func TestValidateRoster_SudoGrantCommandCategoryAllExclusiveWithSpecific(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: bad-category
    kind: sudo_grant
    subjects: {users: [alice], groups: []}
    targets: {hosts: [], hostgroups: [production-db]}
    privilege: {commands: [/usr/bin/systemctl], command_groups: [], command_category: all}
    validity: {not_after: "2026-08-21T19:00:00+08:00"}
    justification: {reason: "should be rejected"}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "sudo allow command category") {
		t.Fatalf("expected command_category: all combined with specific commands to be rejected, got: %v", v)
	}
}

func anyDetailContains(violations []RosterViolation, substr string) bool {
	for _, v := range violations {
		if strings.Contains(v.Detail, substr) {
			return true
		}
	}
	return false
}
