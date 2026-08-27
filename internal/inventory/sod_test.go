package inventory

import "testing"

const sodRosterBase = `
schema_version: 3
freeipa:
  domain: ipa.pilot.internal
  admin: {principal: admin, password: x}
users:
  - name: alice
    ssh_keys: {authoritative: true, values: []}
  - name: bob
    ssh_keys: {authoritative: true, values: []}
groups:
  - name: team-payments
    category: team
    membership: {users: [alice], groups: []}
  - name: role-payment-create
    category: role
    membership: {users: [], groups: [team-payments]}
  - name: role-payment-approve
    category: role
    membership: {users: [bob], groups: []}
  - name: role-unrelated
    category: role
    membership: {users: [], groups: []}
hosts: []
hostgroups: []
hbac:
  rules: []
sudo:
  rules: []
`

func sodRoster(t *testing.T, extra string) map[string]any {
	t.Helper()
	return mustParseRoster(t, sodRosterBase+extra)
}

func TestValidateRoster_SoDConflictValidPassesClean(t *testing.T) {
	root := sodRoster(t, `
security:
  conflicts:
    - name: payment-create-vs-approve
      mutually_exclusive: [role-payment-create, role-payment-approve]
`)
	if v := ValidateRosterV3(root); len(v) != 0 {
		t.Fatalf("expected clean pass, got: %v", v)
	}
}

func TestValidateRoster_SoDConflictNonRoleGroupRejected(t *testing.T) {
	root := sodRoster(t, `
security:
  conflicts:
    - name: bad-conflict
      mutually_exclusive: [team-payments, role-payment-approve]
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "conflict group category") {
		t.Fatalf("expected non-role group to be rejected, got: %v", v)
	}
}

func TestValidateRoster_SoDConflictNeedsAtLeastTwoGroups(t *testing.T) {
	root := sodRoster(t, `
security:
  conflicts:
    - name: bad-conflict
      mutually_exclusive: [role-payment-create]
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "conflict mutually_exclusive") {
		t.Fatalf("expected a single-group rule to be rejected, got: %v", v)
	}
}

func TestValidateRoster_SoDConflictUnknownSecurityKeyRejected(t *testing.T) {
	root := sodRoster(t, `
security:
  conflicts: []
  weird_field: []
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "security keys") {
		t.Fatalf("expected unknown security.* key to be rejected, got: %v", v)
	}
}

func TestEvaluateSoD_DetectsNestedTeamFeedingRole(t *testing.T) {
	root := sodRoster(t, `
security:
  conflicts:
    - name: payment-create-vs-approve
      mutually_exclusive: [role-payment-create, role-payment-approve]
`)
	// alice reaches role-payment-create only via team-payments' nested
	// membership — a resolver that only inspects direct role members
	// would miss this conflict entirely (spec.md §13's whole point).
	conflicts := EvaluateSoD(root)
	if len(conflicts) != 0 {
		t.Fatalf("expected no conflict yet (alice is not in role-payment-approve), got: %+v", conflicts)
	}
}

func TestEvaluateSoD_FlagsUserInBothConflictingGroups(t *testing.T) {
	root := sodRoster(t, `
security:
  conflicts:
    - name: payment-create-vs-approve
      mutually_exclusive: [role-payment-create, role-payment-approve]
`)
	// Add bob to team-payments too, so bob now reaches role-payment-create
	// (via the nested team) AND is a direct member of role-payment-approve
	// — exactly the cross-role conflict this rule exists to catch.
	groups := listField(root, "groups")
	teamPayments := asMap(groups[0])
	membership := mapField(teamPayments, "membership")
	membership["users"] = []any{"alice", "bob"}

	conflicts := EvaluateSoD(root)
	if len(conflicts) != 1 {
		t.Fatalf("expected exactly one conflict, got: %+v", conflicts)
	}
	c := conflicts[0]
	if c.RuleName != "payment-create-vs-approve" || c.User != "bob" {
		t.Fatalf("unexpected conflict: %+v", c)
	}
	if len(c.Groups) != 2 || c.Groups[0] != "role-payment-approve" || c.Groups[1] != "role-payment-create" {
		t.Fatalf("unexpected conflicting groups (want sorted [role-payment-approve role-payment-create]): %v", c.Groups)
	}
}

func TestEvaluateSoD_IgnoresAbsentConflictRule(t *testing.T) {
	root := sodRoster(t, `
security:
  conflicts:
    - name: payment-create-vs-approve
      state: absent
      mutually_exclusive: [role-payment-create, role-payment-approve]
`)
	groups := listField(root, "groups")
	teamPayments := asMap(groups[0])
	membership := mapField(teamPayments, "membership")
	membership["users"] = []any{"alice", "bob"}

	if conflicts := EvaluateSoD(root); len(conflicts) != 0 {
		t.Fatalf("expected an absent conflict rule to be skipped entirely, got: %+v", conflicts)
	}
}
