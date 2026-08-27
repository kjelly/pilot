package inventory

import "testing"

func TestValidateRoster_AccountPolicyValidPassesClean(t *testing.T) {
	root := grantsRoster(t, `
account_policies:
  - name: vendor01-contract
    user: vendor01
    type: contractor
    validity: {not_before: "2026-08-01T00:00:00Z", not_after: "2026-10-31T23:59:59Z"}
    sponsor: alice
    ticket: HR-2231
`)
	if v := ValidateRosterV3(root); len(v) != 0 {
		t.Fatalf("expected clean pass, got: %v", v)
	}
}

func TestValidateRoster_AccountPolicyUnknownUserReferenceRejected(t *testing.T) {
	root := grantsRoster(t, `
account_policies:
  - name: bad-policy
    user: ghost-user
    type: contractor
    validity: {not_after: "2026-10-31T23:59:59Z"}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "account_policy user reference") {
		t.Fatalf("expected unknown user reference to be rejected, got: %v", v)
	}
}

func TestValidateRoster_AccountPolicyMissingTypeRejected(t *testing.T) {
	root := grantsRoster(t, `
account_policies:
  - name: bad-policy
    user: vendor01
    validity: {not_after: "2026-10-31T23:59:59Z"}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "account_policy type") {
		t.Fatalf("expected missing type to be rejected, got: %v", v)
	}
}

func TestValidateRoster_AccountPolicyMissingValidityRejected(t *testing.T) {
	root := grantsRoster(t, `
account_policies:
  - name: bad-policy
    user: vendor01
    type: contractor
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "account_policy validity") {
		t.Fatalf("expected missing validity to be rejected, got: %v", v)
	}
}

func TestValidateRoster_AccountPolicyUnknownSponsorRejected(t *testing.T) {
	root := grantsRoster(t, `
account_policies:
  - name: bad-policy
    user: vendor01
    type: contractor
    validity: {not_after: "2026-10-31T23:59:59Z"}
    sponsor: ghost-sponsor
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "account_policy sponsor reference") {
		t.Fatalf("expected unknown sponsor reference to be rejected, got: %v", v)
	}
}

func TestValidateRoster_AccountPolicyDuplicateNamesRejected(t *testing.T) {
	root := grantsRoster(t, `
account_policies:
  - name: dup
    user: vendor01
    type: contractor
    validity: {not_after: "2026-10-31T23:59:59Z"}
  - name: dup
    user: vendor01
    type: contractor
    validity: {not_after: "2027-10-31T23:59:59Z"}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "unique account_policy names") {
		t.Fatalf("expected duplicate account_policy names to be rejected, got: %v", v)
	}
}

func TestEvaluateAccountLifecycle_FlagsGrantReachingExpiredAccountDirectly(t *testing.T) {
	root := grantsRoster(t, `
account_policies:
  - name: vendor01-contract
    user: vendor01
    type: contractor
    validity: {not_after: "2026-08-01T00:00:00Z"}
grants:
  - name: vendor-project-x
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2026-12-31T00:00:00Z"}
    justification: {reason: "still trying to use expired account"}
`)
	violations, err := EvaluateAccountLifecycle(root, mustParseTime(t, "2026-09-01T00:00:00Z"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) != 1 || violations[0].User != "vendor01" || violations[0].AccountLifecycle != GrantExpired {
		t.Fatalf("expected exactly one expired-account violation for vendor01, got: %+v", violations)
	}
}

func TestEvaluateAccountLifecycle_FlagsGroupMembershipReachingPendingAccount(t *testing.T) {
	root := grantsRoster(t, `
account_policies:
  - name: vendor01-not-yet-started
    user: vendor01
    type: contractor
    validity: {not_before: "2099-01-01T00:00:00Z", not_after: "2099-12-31T00:00:00Z"}
grants:
  - name: team-window
    kind: temporary_grant
    subjects: {users: [], groups: [team-sre]}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2026-12-31T00:00:00Z"}
    justification: {reason: "reached via team-sre group membership"}
`)
	// The base fixture's team-sre only has alice as a member, not vendor01
	// — add vendor01 to it so this test exercises group-membership
	// resolution rather than a direct subjects.users hit.
	groups := listField(root, "groups")
	teamSre := asMap(groups[0])
	mapField(teamSre, "membership")["users"] = []any{"alice", "vendor01"}

	violations, err := EvaluateAccountLifecycle(root, mustParseTime(t, "2026-09-01T00:00:00Z"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, v := range violations {
		if v.User == "vendor01" && v.AccountLifecycle == GrantPending {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a pending-account violation for vendor01 (reached via team-sre membership), got: %+v", violations)
	}
}

func TestEvaluateAccountLifecycle_NoViolationWhenAccountActive(t *testing.T) {
	root := grantsRoster(t, `
account_policies:
  - name: vendor01-contract
    user: vendor01
    type: contractor
    validity: {not_after: "2026-12-31T00:00:00Z"}
grants:
  - name: vendor-project-x
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2026-12-31T00:00:00Z"}
    justification: {reason: "account is active"}
`)
	violations, err := EvaluateAccountLifecycle(root, mustParseTime(t, "2026-09-01T00:00:00Z"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("expected no violations, got: %+v", violations)
	}
}

func TestEvaluateAccountLifecycle_UnconstrainedWhenNoAccountPolicyExists(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: vendor-project-x
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2026-12-31T00:00:00Z"}
    justification: {reason: "vendor01 has no account_policies entry at all"}
`)
	violations, err := EvaluateAccountLifecycle(root, mustParseTime(t, "2026-09-01T00:00:00Z"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("expected a user with no account_policies entries to be unconstrained, got: %+v", violations)
	}
}

func TestCompileAccountPolicies_PresentEntryCompilesNotAfter(t *testing.T) {
	root := grantsRoster(t, `
account_policies:
  - name: vendor01-contract
    user: vendor01
    type: contractor
    validity: {not_after: "2026-12-31T23:59:59Z"}
`)
	compiled, err := CompileAccountPolicies(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(compiled) != 1 {
		t.Fatalf("expected exactly one compiled entry, got: %+v", compiled)
	}
	got := compiled[0]
	if got.User != "vendor01" || !got.Present || got.Expiration != "20261231235959Z" {
		t.Fatalf("expected present vendor01 expiring 20261231235959Z, got: %+v", got)
	}
}

// §7.7: validity.not_before is never consulted by the compiler — a
// currently-pending entry still compiles Present with its not_after, since
// native enforcement has no not-before mechanism to defer to.
func TestCompileAccountPolicies_NotBeforeNeverConsulted(t *testing.T) {
	root := grantsRoster(t, `
account_policies:
  - name: vendor01-not-yet-started
    user: vendor01
    type: contractor
    validity: {not_before: "2099-01-01T00:00:00Z", not_after: "2099-12-31T23:59:59Z"}
`)
	compiled, err := CompileAccountPolicies(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(compiled) != 1 || !compiled[0].Present || compiled[0].Expiration != "20991231235959Z" {
		t.Fatalf("expected a pending entry to still compile Present with its not_after, got: %+v", compiled)
	}
}

// FreeIPA has exactly one krbPrincipalExpiration attribute per account —
// two present entries for the same user (e.g. original + renewal) must
// collapse to the LATEST not_after, regardless of roster order.
func TestCompileAccountPolicies_MultipleEntriesUseLatestNotAfter(t *testing.T) {
	root := grantsRoster(t, `
account_policies:
  - name: vendor01-renewed-contract
    user: vendor01
    type: contractor
    validity: {not_before: "2026-06-01T00:00:00Z", not_after: "2026-12-31T23:59:59Z"}
  - name: vendor01-first-contract
    user: vendor01
    type: contractor
    validity: {not_after: "2026-06-01T00:00:00Z"}
`)
	compiled, err := CompileAccountPolicies(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(compiled) != 1 || compiled[0].Expiration != "20261231235959Z" {
		t.Fatalf("expected the later renewal's not_after to win, got: %+v", compiled)
	}
}

// §7.4's explicit clear path: every entry for the user is state: absent.
func TestCompileAccountPolicies_AllAbsentEntriesCompileToExplicitClear(t *testing.T) {
	root := grantsRoster(t, `
account_policies:
  - name: vendor01-contract
    user: vendor01
    state: absent
    type: contractor
    validity: {not_after: "2026-12-31T23:59:59Z"}
`)
	compiled, err := CompileAccountPolicies(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(compiled) != 1 || compiled[0].Present || compiled[0].Expiration != "" {
		t.Fatalf("expected an all-absent user to compile to explicit clear (Present=false), got: %+v", compiled)
	}
}

// A mix of absent and present entries for the same user must NOT clear —
// the present entry's not_after still governs (only omission entirely, or
// every entry being absent, clears — §7.4).
func TestCompileAccountPolicies_MixedPresentAndAbsentKeepsPresentValue(t *testing.T) {
	root := grantsRoster(t, `
account_policies:
  - name: vendor01-old-contract
    user: vendor01
    state: absent
    type: contractor
    validity: {not_after: "2026-06-01T00:00:00Z"}
  - name: vendor01-current-contract
    user: vendor01
    type: contractor
    validity: {not_after: "2026-12-31T23:59:59Z"}
`)
	compiled, err := CompileAccountPolicies(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(compiled) != 1 || !compiled[0].Present || compiled[0].Expiration != "20261231235959Z" {
		t.Fatalf("expected the present entry's not_after to govern, got: %+v", compiled)
	}
}

// §7.4: "do not silently remove ... because a field was omitted
// ambiguously" — a user with NO account_policies entries at all is
// skipped entirely, not compiled to an explicit clear.
func TestCompileAccountPolicies_NoEntriesSkipsUserEntirely(t *testing.T) {
	root := grantsRoster(t, `grants: []`)
	compiled, err := CompileAccountPolicies(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(compiled) != 0 {
		t.Fatalf("expected no compiled entries when account_policies is absent, got: %+v", compiled)
	}
}

func TestEvaluateAccountPolicyStatuses_ReportsLifecycleAndNativeExpiration(t *testing.T) {
	root := grantsRoster(t, `
account_policies:
  - name: vendor01-contract
    user: vendor01
    type: contractor
    validity: {not_after: "2026-12-31T23:59:59Z"}
`)
	statuses, err := EvaluateAccountPolicyStatuses(root, mustParseTime(t, "2026-09-01T00:00:00Z"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("expected one status, got: %+v", statuses)
	}
	got := statuses[0]
	if got.Lifecycle != GrantActive || got.NativeExpiration != "20261231235959Z" {
		t.Fatalf("expected active lifecycle with the compiled native expiration, got: %+v", got)
	}
}

func TestEvaluateAccountPolicyStatuses_ClearedEntryReportsEmptyNativeExpiration(t *testing.T) {
	root := grantsRoster(t, `
account_policies:
  - name: vendor01-contract
    user: vendor01
    state: absent
    type: contractor
    validity: {not_after: "2026-12-31T23:59:59Z"}
`)
	statuses, err := EvaluateAccountPolicyStatuses(root, mustParseTime(t, "2026-09-01T00:00:00Z"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(statuses) != 1 || statuses[0].NativeExpiration != "" {
		t.Fatalf("expected an absent entry to report empty native expiration, got: %+v", statuses)
	}
}

func TestEvaluateAccountLifecycle_RenewalEntryKeepsAccountActive(t *testing.T) {
	root := grantsRoster(t, `
account_policies:
  - name: vendor01-first-contract
    user: vendor01
    type: contractor
    validity: {not_after: "2026-06-01T00:00:00Z"}
  - name: vendor01-renewed-contract
    user: vendor01
    type: contractor
    validity: {not_before: "2026-06-01T00:00:00Z", not_after: "2026-12-31T00:00:00Z"}
grants:
  - name: vendor-project-x
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2026-12-31T00:00:00Z"}
    justification: {reason: "renewed contract keeps the account active"}
`)
	violations, err := EvaluateAccountLifecycle(root, mustParseTime(t, "2026-09-01T00:00:00Z"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("expected the renewed (currently active) entry to clear the violation, got: %+v", violations)
	}
}
