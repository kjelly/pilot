package inventory

import "testing"

func TestValidateRoster_PrivilegedIdentityValidPassesClean(t *testing.T) {
	root := grantsRoster(t, `
security:
  privileged_identity:
    match_groups: [role-production-operator]
    require:
      auth_types: [otp, pkinit]
      no_password_only: true
`)
	if v := ValidateRosterV3(root); len(v) != 0 {
		t.Fatalf("expected clean pass, got: %v", v)
	}
}

func TestValidateRoster_PrivilegedIdentityAbsentIsFine(t *testing.T) {
	root := grantsRoster(t, ``)
	if v := ValidateRosterV3(root); len(v) != 0 {
		t.Fatalf("expected an absent privileged_identity block to pass clean, got: %v", v)
	}
}

func TestValidateRoster_PrivilegedIdentityEmptyMatchGroupsRejected(t *testing.T) {
	root := grantsRoster(t, `
security:
  privileged_identity:
    match_groups: []
    require: {auth_types: [otp]}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "privileged_identity match_groups") {
		t.Fatalf("expected empty match_groups to be rejected, got: %v", v)
	}
}

func TestValidateRoster_PrivilegedIdentityUnknownGroupReferenceRejected(t *testing.T) {
	root := grantsRoster(t, `
security:
  privileged_identity:
    match_groups: [role-does-not-exist]
    require: {auth_types: [otp]}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "privileged_identity match_groups reference") {
		t.Fatalf("expected unknown group reference to be rejected, got: %v", v)
	}
}

func TestValidateRoster_PrivilegedIdentityUnknownAuthTypeRejected(t *testing.T) {
	root := grantsRoster(t, `
security:
  privileged_identity:
    match_groups: [role-production-operator]
    require: {auth_types: [totp]}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "privileged_identity require auth_types") {
		t.Fatalf("expected unknown auth_types entry to be rejected, got: %v", v)
	}
}

func TestValidateRoster_PrivilegedIdentityNonBoolNoPasswordOnlyRejected(t *testing.T) {
	root := grantsRoster(t, `
security:
  privileged_identity:
    match_groups: [role-production-operator]
    require: {no_password_only: yes-please}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "privileged_identity require no_password_only") {
		t.Fatalf("expected non-bool no_password_only to be rejected, got: %v", v)
	}
}

func TestValidateRoster_PrivilegedIdentityUnknownFieldRejected(t *testing.T) {
	root := grantsRoster(t, `
security:
  privileged_identity:
    match_groups: [role-production-operator]
    require: {auth_types: [otp]}
    escalation_path: whatever
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "privileged_identity keys") {
		t.Fatalf("expected unknown top-level field to be rejected, got: %v", v)
	}
}

// TestEvaluatePrivilegedIdentityBaseline_NestedMembership locks in
// spec.md §9's own example: alice -> team-sre -> role-production-admin
// makes alice privileged even though she is never a direct member of the
// role group. Uses its own full roster (not grantsRosterBase) because it
// needs a role group whose membership nests another group — YAML string
// concatenation can't override grantsRosterBase's own flat `groups:`.
func TestEvaluatePrivilegedIdentityBaseline_NestedMembership(t *testing.T) {
	root := mustParseRoster(t, `
schema_version: 3
freeipa:
  domain: ipa.pilot.internal
  admin: {principal: admin, password: x}
users:
  - name: alice
    ssh_keys: {authoritative: true, values: []}
groups:
  - name: team-sre
    category: team
    membership: {users: [alice], groups: []}
  - name: role-production-admin
    category: role
    membership: {users: [], groups: [team-sre]}
hosts: []
hostgroups: []
hbac: {rules: []}
sudo: {rules: []}
security:
  privileged_identity:
    match_groups: [role-production-admin]
    require: {auth_types: [otp, pkinit], no_password_only: true}
`)
	v := EvaluatePrivilegedIdentityBaseline(root)
	if len(v) == 0 || v[0].User != "alice" {
		t.Fatalf("expected alice (reached via team-sre nested membership) to violate the baseline, got: %+v", v)
	}
}

// privilegedIdentityUserRoster builds a minimal standalone roster (not
// grantsRosterBase — that fixture's own `users:`/`groups:` can't be
// overridden via YAML string concatenation) with one user, alice, whose
// authentication.allowed is authYAML, directly in role-privileged.
func privilegedIdentityUserRoster(t *testing.T, authYAML, requireYAML string) map[string]any {
	t.Helper()
	return mustParseRoster(t, `
schema_version: 3
freeipa:
  domain: ipa.pilot.internal
  admin: {principal: admin, password: x}
users:
  - name: alice
    ssh_keys: {authoritative: true, values: []}
`+authYAML+`
groups:
  - name: role-privileged
    category: role
    membership: {users: [alice], groups: []}
hosts: []
hostgroups: []
hbac: {rules: []}
sudo: {rules: []}
security:
  privileged_identity:
    match_groups: [role-privileged]
    require: `+requireYAML+`
`)
}

func TestEvaluatePrivilegedIdentityBaseline_CompliantUserPasses(t *testing.T) {
	root := privilegedIdentityUserRoster(t, "    authentication: {allowed: [otp]}", "{auth_types: [otp, pkinit], no_password_only: true}")
	if v := EvaluatePrivilegedIdentityBaseline(root); len(v) != 0 {
		t.Fatalf("expected a compliant user (allows otp, one of the required types) to pass, got: %+v", v)
	}
}

func TestEvaluatePrivilegedIdentityBaseline_PasswordOnlyViolatesNoPasswordOnly(t *testing.T) {
	root := privilegedIdentityUserRoster(t, "    authentication: {allowed: [password, otp]}", "{auth_types: [otp], no_password_only: true}")
	// alice allows otp (satisfies auth_types) AND password (still allowed
	// alongside otp) — no_password_only only blocks a user whose allowed
	// set is *exclusively* password, so this must pass.
	if v := EvaluatePrivilegedIdentityBaseline(root); len(v) != 0 {
		t.Fatalf("expected alice (allows otp+password, not password-only) to pass, got: %+v", v)
	}
}

func TestEvaluatePrivilegedIdentityBaseline_UndeclaredUserTreatedAsPasswordOnly(t *testing.T) {
	root := grantsRoster(t, `
security:
  privileged_identity:
    match_groups: [role-production-operator]
    require: {no_password_only: true}
`)
	// alice (role-production-operator's direct member in grantsRosterBase)
	// declares no authentication: block at all — must be treated as
	// password-only, the least-privileged read, not silently compliant.
	v := EvaluatePrivilegedIdentityBaseline(root)
	if len(v) != 1 || v[0].User != "alice" {
		t.Fatalf("expected an undeclared privileged user to violate no_password_only, got: %+v", v)
	}
}

func TestPrivilegedUsers_ReturnsFullSetRegardlessOfCompliance(t *testing.T) {
	root := grantsRoster(t, `
security:
  privileged_identity:
    match_groups: [role-production-operator]
    require: {no_password_only: true}
`)
	// alice (grantsRosterBase's direct role-production-operator member)
	// declares no authentication: block — non-compliant, but must still
	// appear in the full privileged set.
	got := PrivilegedUsers(root)
	if len(got) != 1 || got[0] != "alice" {
		t.Fatalf("expected [alice], got: %v", got)
	}
}

func TestPrivilegedUsers_AbsentBlockReturnsNil(t *testing.T) {
	root := grantsRoster(t, ``)
	if got := PrivilegedUsers(root); got != nil {
		t.Fatalf("expected nil for no privileged_identity block, got: %v", got)
	}
}

func TestEvaluatePrivilegedIdentityBaseline_AbsentBlockIsNoop(t *testing.T) {
	root := grantsRoster(t, ``)
	if v := EvaluatePrivilegedIdentityBaseline(root); len(v) != 0 {
		t.Fatalf("expected no privileged_identity block to produce zero violations, got: %+v", v)
	}
}
