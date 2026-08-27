package inventory

import "testing"

func TestValidateRoster_GrantPolicyValidPassesClean(t *testing.T) {
	root := grantsRoster(t, `
auth_policies:
  - name: production-strong-auth
    targets: {hosts: [], hostgroups: [production-db]}
    require_any: [otp]
security:
  grant_policies:
    - name: production-login
      match: {kinds: [temporary_grant], hostgroups: [production-db]}
      require: {max_duration: 8h, reason: true, ticket: true, auth_policy: production-strong-auth}
`)
	if v := ValidateRosterV3(root); len(v) != 0 {
		t.Fatalf("expected clean pass, got: %v", v)
	}
}

func TestValidateRoster_GrantPolicyUnknownKindRejected(t *testing.T) {
	root := grantsRoster(t, `
security:
  grant_policies:
    - name: bad-policy
      match: {kinds: [breakglass]}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "grant_policy match kinds") {
		t.Fatalf("expected breakglass to be rejected as a grant_policy match kind (Phase 3 scope), got: %v", v)
	}
}

func TestValidateRoster_GrantPolicyInvalidDurationRejected(t *testing.T) {
	root := grantsRoster(t, `
security:
  grant_policies:
    - name: bad-policy
      require: {max_duration: 8x}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "grant_policy require max_duration") {
		t.Fatalf("expected invalid duration to be rejected, got: %v", v)
	}
}

func TestValidateRoster_GrantPolicyUnknownAuthPolicyReferenceRejected(t *testing.T) {
	root := grantsRoster(t, `
security:
  grant_policies:
    - name: bad-policy
      require: {auth_policy: ghost-policy}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "grant_policy require auth_policy reference") {
		t.Fatalf("expected unknown auth_policy reference to be rejected, got: %v", v)
	}
}

func TestValidateRoster_GrantPolicyUnknownHostgroupReferenceRejected(t *testing.T) {
	root := grantsRoster(t, `
security:
  grant_policies:
    - name: bad-policy
      match: {hostgroups: [ghost-group]}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "grant_policy match hostgroup reference") {
		t.Fatalf("expected unknown match.hostgroups reference to be rejected, got: %v", v)
	}
}

func TestEvaluateGrantPolicies_FlagsGrantExceedingMaxDuration(t *testing.T) {
	root := grantsRoster(t, `
security:
  grant_policies:
    - name: production-login
      match: {kinds: [temporary_grant], hostgroups: [production-db]}
      require: {max_duration: 8h}
grants:
  - name: too-long
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [], hostgroups: [production-db]}
    services: [sshd]
    validity: {not_before: "2026-08-21T09:00:00Z", not_after: "2026-08-22T09:00:00Z"}
    justification: {reason: "way too long"}
`)
	now := mustParseTime(t, "2026-08-20T00:00:00Z")
	violations, err := EvaluateGrantPolicies(root, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) != 1 || violations[0].Detail == "" {
		t.Fatalf("expected exactly one max_duration violation, got: %+v", violations)
	}
	if violations[0].PolicyName != "production-login" || violations[0].GrantName != "too-long" {
		t.Fatalf("unexpected violation: %+v", violations[0])
	}
}

func TestEvaluateGrantPolicies_PassesWithinMaxDuration(t *testing.T) {
	root := grantsRoster(t, `
security:
  grant_policies:
    - name: production-login
      match: {kinds: [temporary_grant], hostgroups: [production-db]}
      require: {max_duration: 8h}
grants:
  - name: fine
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [], hostgroups: [production-db]}
    services: [sshd]
    validity: {not_before: "2026-08-21T09:00:00Z", not_after: "2026-08-21T15:00:00Z"}
    justification: {reason: "well within budget"}
`)
	violations, err := EvaluateGrantPolicies(root, mustParseTime(t, "2026-08-20T00:00:00Z"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("expected no violations, got: %+v", violations)
	}
}

func TestEvaluateGrantPolicies_FlagsMissingReasonAndTicket(t *testing.T) {
	root := grantsRoster(t, `
security:
  grant_policies:
    - name: production-login
      match: {kinds: [temporary_grant]}
      require: {reason: true, ticket: true}
grants:
  - name: no-ticket
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2026-08-31T18:00:00Z"}
    justification: {reason: "has a reason but no ticket"}
`)
	violations, err := EvaluateGrantPolicies(root, mustParseTime(t, "2026-08-20T00:00:00Z"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) != 1 || violations[0].Detail == "" {
		t.Fatalf("expected exactly one missing-ticket violation, got: %+v", violations)
	}
}

func TestEvaluateGrantPolicies_FlagsGrantNotCoveredByRequiredAuthPolicy(t *testing.T) {
	root := grantsRoster(t, `
auth_policies:
  - name: production-strong-auth
    targets: {hosts: [], hostgroups: [production-db]}
    require_any: [otp]
security:
  grant_policies:
    - name: production-login
      match: {kinds: [temporary_grant]}
      require: {auth_policy: production-strong-auth}
grants:
  - name: uncovered
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2026-08-31T18:00:00Z"}
    justification: {reason: "targets a host outside the required auth_policy"}
`)
	violations, err := EvaluateGrantPolicies(root, mustParseTime(t, "2026-08-20T00:00:00Z"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) != 1 {
		t.Fatalf("expected exactly one auth_policy-coverage violation, got: %+v", violations)
	}
}

func TestEvaluateGrantPolicies_PassesWhenCoveredByAuthPolicy(t *testing.T) {
	root := grantsRoster(t, `
auth_policies:
  - name: production-strong-auth
    targets: {hosts: [], hostgroups: [production-db]}
    require_any: [otp]
security:
  grant_policies:
    - name: production-login
      match: {kinds: [temporary_grant]}
      require: {auth_policy: production-strong-auth}
grants:
  - name: covered
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [], hostgroups: [production-db]}
    services: [sshd]
    validity: {not_after: "2026-08-31T18:00:00Z"}
    justification: {reason: "targets exactly what the auth_policy covers"}
`)
	violations, err := EvaluateGrantPolicies(root, mustParseTime(t, "2026-08-20T00:00:00Z"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("expected no violations, got: %+v", violations)
	}
}

func TestEvaluateGrantPolicies_MatchesByHostgroupNameEvenWithoutHostMembership(t *testing.T) {
	// production-db (grantsRosterBase) has no membership.hosts declared —
	// a resolver that only compared expanded HOSTS (never hostgroup
	// names) would find both sides empty and silently fail to match.
	root := grantsRoster(t, `
security:
  grant_policies:
    - name: production-login
      match: {hostgroups: [production-db]}
      require: {max_duration: 1m}
grants:
  - name: too-long
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [], hostgroups: [production-db]}
    services: [sshd]
    validity: {not_after: "2026-08-31T18:00:00Z"}
    justification: {reason: "same hostgroup name, no host membership needed"}
`)
	violations, err := EvaluateGrantPolicies(root, mustParseTime(t, "2026-08-20T00:00:00Z"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) != 1 {
		t.Fatalf("expected the hostgroup-name match to fire (and then fail max_duration: 1m), got: %+v", violations)
	}
}

func TestEvaluateGrantPolicies_IgnoresNonMatchingKind(t *testing.T) {
	root := grantsRoster(t, `
security:
  grant_policies:
    - name: sudo-only-policy
      match: {kinds: [sudo_grant]}
      require: {max_duration: 30m}
grants:
  - name: login-grant
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2026-08-31T18:00:00Z"}
    justification: {reason: "should not be matched by a sudo_grant-only policy"}
`)
	violations, err := EvaluateGrantPolicies(root, mustParseTime(t, "2026-08-20T00:00:00Z"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("expected the login-kind grant to be unaffected by a sudo_grant-only policy, got: %+v", violations)
	}
}
