package inventory

import (
	"testing"
	"time"
)

func TestValidateRoster_CredentialPolicyValidPassesClean(t *testing.T) {
	root := grantsRoster(t, `
credential_policies:
  - name: privileged-ssh
    state: present
    match: {users: [], groups: [role-production-operator]}
    ssh:
      allowed_algorithms: [ssh-ed25519, ecdsa-sha2-nistp256]
      require_comment: true
      max_age: 365d
    review:
      interval: 180d
      reviewed_by: alice
`)
	if v := ValidateRosterV3(root); len(v) != 0 {
		t.Fatalf("expected clean pass, got: %v", v)
	}
}

func TestValidateRoster_CredentialPolicyEmptyMatchRejected(t *testing.T) {
	root := grantsRoster(t, `
credential_policies:
  - name: bad-policy
    match: {users: [], groups: []}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "credential_policy match") {
		t.Fatalf("expected empty match to be rejected, got: %v", v)
	}
}

func TestValidateRoster_CredentialPolicyUnknownUserReferenceRejected(t *testing.T) {
	root := grantsRoster(t, `
credential_policies:
  - name: bad-policy
    match: {users: [ghost], groups: []}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "credential_policy match user reference") {
		t.Fatalf("expected unknown user reference to be rejected, got: %v", v)
	}
}

func TestValidateRoster_CredentialPolicyUnknownGroupReferenceRejected(t *testing.T) {
	root := grantsRoster(t, `
credential_policies:
  - name: bad-policy
    match: {users: [], groups: [role-does-not-exist]}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "credential_policy match group reference") {
		t.Fatalf("expected unknown group reference to be rejected, got: %v", v)
	}
}

func TestValidateRoster_CredentialPolicyBlankAlgorithmRejected(t *testing.T) {
	root := grantsRoster(t, `
credential_policies:
  - name: bad-policy
    match: {users: [], groups: [role-production-operator]}
    ssh: {allowed_algorithms: [""]}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "credential_policy ssh allowed_algorithms") {
		t.Fatalf("expected a blank algorithm entry to be rejected, got: %v", v)
	}
}

func TestValidateRoster_CredentialPolicyInvalidMaxAgeRejected(t *testing.T) {
	root := grantsRoster(t, `
credential_policies:
  - name: bad-policy
    match: {users: [], groups: [role-production-operator]}
    ssh: {max_age: not-a-duration}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "credential_policy ssh max_age") {
		t.Fatalf("expected invalid max_age to be rejected, got: %v", v)
	}
}

func TestValidateRoster_CredentialPolicyReviewMissingIntervalRejected(t *testing.T) {
	root := grantsRoster(t, `
credential_policies:
  - name: bad-policy
    match: {users: [], groups: [role-production-operator]}
    review: {reviewed_by: alice}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "credential_policy review interval") {
		t.Fatalf("expected missing review.interval to be rejected, got: %v", v)
	}
}

func TestValidateRoster_CredentialPolicyReviewUnknownReviewerRejected(t *testing.T) {
	root := grantsRoster(t, `
credential_policies:
  - name: bad-policy
    match: {users: [], groups: [role-production-operator]}
    review: {interval: 180d, reviewed_by: ghost}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "credential_policy review reviewed_by reference") {
		t.Fatalf("expected unknown reviewed_by to be rejected, got: %v", v)
	}
}

func TestValidateRoster_CredentialPolicyDuplicateNamesRejected(t *testing.T) {
	root := grantsRoster(t, `
credential_policies:
  - name: dup
    match: {users: [], groups: [role-production-operator]}
  - name: dup
    match: {users: [], groups: [team-sre]}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "unique credential_policy names") {
		t.Fatalf("expected duplicate names to be rejected, got: %v", v)
	}
}

func TestValidateRoster_CredentialPolicyOnOverdueFieldRejected(t *testing.T) {
	root := grantsRoster(t, `
credential_policies:
  - name: bad-policy
    match: {users: [], groups: [role-production-operator]}
    review: {interval: 180d, on_overdue: disable_account}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "credential_policy review keys") {
		t.Fatalf("expected on_overdue to be rejected as an unknown field (no automatic-consequence lever), got: %v", v)
	}
}

// TestValidateRoster_PrivilegedIdentitySSHKeyPolicyReference locks in the
// Phase 4 cross-reference privileged_identity.go deferred from Phase 3.
func TestValidateRoster_PrivilegedIdentitySSHKeyPolicyReference(t *testing.T) {
	root := grantsRoster(t, `
credential_policies:
  - name: privileged-ssh
    match: {users: [], groups: [role-production-operator]}
security:
  privileged_identity:
    match_groups: [role-production-operator]
    require: {ssh_key_policy: privileged-ssh}
`)
	if v := ValidateRosterV3(root); len(v) != 0 {
		t.Fatalf("expected a valid ssh_key_policy reference to pass clean, got: %v", v)
	}
}

func TestValidateRoster_PrivilegedIdentityUnknownSSHKeyPolicyReferenceRejected(t *testing.T) {
	root := grantsRoster(t, `
security:
  privileged_identity:
    match_groups: [role-production-operator]
    require: {ssh_key_policy: does-not-exist}
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "privileged_identity require ssh_key_policy reference") {
		t.Fatalf("expected unknown ssh_key_policy reference to be rejected, got: %v", v)
	}
}

// credentialPolicySSHRoster builds a standalone roster (not
// grantsRosterBase — SSH hygiene tests need real ssh_keys.values, which
// that fixture's users don't carry) with two users in role-privileged.
func credentialPolicySSHRoster(t *testing.T, aliceKeys, bobKeys, sshYAML string) map[string]any {
	t.Helper()
	return mustParseRoster(t, `
schema_version: 3
freeipa:
  domain: ipa.pilot.internal
  admin: {principal: admin, password: x}
users:
  - name: alice
    ssh_keys: {authoritative: true, values: [`+aliceKeys+`]}
  - name: bob
    ssh_keys: {authoritative: true, values: [`+bobKeys+`]}
groups:
  - name: role-privileged
    category: role
    membership: {users: [alice, bob], groups: []}
hosts: []
hostgroups: []
hbac: {rules: []}
sudo: {rules: []}
credential_policies:
  - name: privileged-ssh
    match: {users: [], groups: [role-privileged]}
    ssh: `+sshYAML+`
`)
}

func TestEvaluateSSHKeyHygiene_CleanKeysProduceNoFindings(t *testing.T) {
	root := credentialPolicySSHRoster(t,
		`"`+testSSHKeyEd25519+`"`,
		`"`+testSSHKeyECDSA+`"`,
		`{allowed_algorithms: [ssh-ed25519, ecdsa-sha2-nistp256]}`)
	if got := EvaluateSSHKeyHygiene(root); len(got) != 0 {
		t.Fatalf("expected zero findings for two clean, allowed keys, got: %+v", got)
	}
}

func TestEvaluateSSHKeyHygiene_BlankKeyRejected(t *testing.T) {
	root := credentialPolicySSHRoster(t, `""`, `"`+testSSHKeyECDSA+`"`, `{}`)
	got := EvaluateSSHKeyHygiene(root)
	if !hasSSHFinding(got, "alice", SSHFindingBlank) {
		t.Fatalf("expected a blank-key finding for alice, got: %+v", got)
	}
}

func TestEvaluateSSHKeyHygiene_MalformedKeyRejected(t *testing.T) {
	root := credentialPolicySSHRoster(t, `"ssh-ed25519 not-valid-base64!!!"`, `"`+testSSHKeyECDSA+`"`, `{}`)
	got := EvaluateSSHKeyHygiene(root)
	if !hasSSHFinding(got, "alice", SSHFindingMalformed) {
		t.Fatalf("expected a malformed-key finding for alice, got: %+v", got)
	}
}

func TestEvaluateSSHKeyHygiene_DisallowedAlgorithmRejected(t *testing.T) {
	root := credentialPolicySSHRoster(t,
		`"`+testSSHKeyEd25519+`"`, `"`+testSSHKeyECDSA+`"`,
		`{allowed_algorithms: [ssh-ed25519]}`) // ecdsa not allowed
	got := EvaluateSSHKeyHygiene(root)
	if !hasSSHFinding(got, "bob", SSHFindingDisallowedAlgorithm) {
		t.Fatalf("expected a disallowed-algorithm finding for bob's ecdsa key, got: %+v", got)
	}
	if hasSSHFinding(got, "alice", SSHFindingDisallowedAlgorithm) {
		t.Fatalf("did not expect alice's allowed ed25519 key to be flagged, got: %+v", got)
	}
}

func TestEvaluateSSHKeyHygiene_NoAllowlistConfiguredNeverFlagsAlgorithm(t *testing.T) {
	// spec.md §10: "Do not silently impose a hard-coded algorithm
	// allowlist" — an unset allowed_algorithms must never reject any
	// algorithm.
	root := credentialPolicySSHRoster(t, `"`+testSSHKeyEd25519+`"`, `"`+testSSHKeyECDSA+`"`, `{}`)
	got := EvaluateSSHKeyHygiene(root)
	if hasSSHFinding(got, "alice", SSHFindingDisallowedAlgorithm) || hasSSHFinding(got, "bob", SSHFindingDisallowedAlgorithm) {
		t.Fatalf("expected no algorithm findings when allowed_algorithms is unset, got: %+v", got)
	}
}

func TestEvaluateSSHKeyHygiene_RequireCommentRejectsCommentlessKey(t *testing.T) {
	root := credentialPolicySSHRoster(t,
		`"`+testSSHKeyEd25519NoComment+`"`, `"`+testSSHKeyECDSA+`"`,
		`{require_comment: true}`)
	got := EvaluateSSHKeyHygiene(root)
	if !hasSSHFinding(got, "alice", SSHFindingMissingComment) {
		t.Fatalf("expected a missing-comment finding for alice's commentless key, got: %+v", got)
	}
	if hasSSHFinding(got, "bob", SSHFindingMissingComment) {
		t.Fatalf("did not expect bob's commented key to be flagged, got: %+v", got)
	}
}

func TestEvaluateSSHKeyHygiene_DuplicateMaterialAcrossUsersDetected(t *testing.T) {
	// alice and bob share the exact same key material (different
	// comments) — duplicate detection must compare normalized material,
	// not the comment.
	root := credentialPolicySSHRoster(t,
		`"`+testSSHKeyEd25519+`"`, `"`+testSSHKeyEd25519NoComment+`"`, `{}`)
	got := EvaluateSSHKeyHygiene(root)
	if !hasSSHFinding(got, "", SSHFindingDuplicateMaterial) {
		t.Fatalf("expected a duplicate-material finding, got: %+v", got)
	}
}

func TestEvaluateSSHKeyHygiene_MaxAgeConfiguredReportsUnknownNeverGuessed(t *testing.T) {
	root := credentialPolicySSHRoster(t, `"`+testSSHKeyEd25519+`"`, `"`+testSSHKeyECDSA+`"`, `{max_age: 365d}`)
	got := EvaluateSSHKeyHygiene(root)
	if !hasSSHFinding(got, "alice", SSHFindingMaxAgeUnknown) || !hasSSHFinding(got, "bob", SSHFindingMaxAgeUnknown) {
		t.Fatalf("expected both users' keys to report max_age_unknown when ssh.max_age is configured, got: %+v", got)
	}
}

func TestEvaluateSSHKeyHygiene_MaxAgeUnconfiguredProducesNoFinding(t *testing.T) {
	root := credentialPolicySSHRoster(t, `"`+testSSHKeyEd25519+`"`, `"`+testSSHKeyECDSA+`"`, `{}`)
	got := EvaluateSSHKeyHygiene(root)
	if hasSSHFinding(got, "alice", SSHFindingMaxAgeUnknown) {
		t.Fatalf("did not expect a max_age finding when ssh.max_age is not configured, got: %+v", got)
	}
}

func hasSSHFinding(findings []SSHHygieneFinding, user, issue string) bool {
	for _, f := range findings {
		if f.User == user && f.Issue == issue {
			return true
		}
	}
	return false
}

func TestCredentialPolicyCoverage_ResolvesNestedGroupMembership(t *testing.T) {
	root := grantsRoster(t, `
credential_policies:
  - name: privileged-ssh
    match: {users: [vendor01], groups: [role-production-operator]}
`)
	got := CredentialPolicyCoverage(root)
	users := got["privileged-ssh"]
	if len(users) != 2 || users[0] != "alice" || users[1] != "vendor01" {
		t.Fatalf("expected [alice vendor01] (role member + direct user, sorted), got: %v", users)
	}
}

func TestCredentialPolicyCoverage_AbsentPolicyExcluded(t *testing.T) {
	root := grantsRoster(t, `
credential_policies:
  - name: retired
    state: absent
    match: {users: [], groups: [role-production-operator]}
`)
	got := CredentialPolicyCoverage(root)
	if _, has := got["retired"]; has {
		t.Fatalf("expected an absent policy to be excluded from coverage, got: %v", got)
	}
}

func TestEvaluateCredentialReviewStatuses_NeverReviewedIsOverdue(t *testing.T) {
	root := grantsRoster(t, `
credential_policies:
  - name: privileged-ssh
    match: {users: [], groups: [role-production-operator]}
    review: {interval: 180d}
`)
	statuses, err := EvaluateCredentialReviewStatuses(root, time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(statuses) != 1 || statuses[0].State != ReviewOverdue {
		t.Fatalf("expected a never-reviewed policy to report overdue, got: %+v", statuses)
	}
}

func TestEvaluateCredentialReviewStatuses_CurrentWithinInterval(t *testing.T) {
	root := grantsRoster(t, `
credential_policies:
  - name: privileged-ssh
    match: {users: [], groups: [role-production-operator]}
    review: {interval: 180d, last_reviewed_at: "2026-08-01T10:00:00+08:00"}
`)
	statuses, err := EvaluateCredentialReviewStatuses(root, time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(statuses) != 1 || statuses[0].State != ReviewCurrent {
		t.Fatalf("expected a recently-reviewed policy to report current, got: %+v", statuses)
	}
}

func TestEvaluateCredentialReviewStatuses_NoReviewBlockIsInvisible(t *testing.T) {
	root := grantsRoster(t, `
credential_policies:
  - name: privileged-ssh
    match: {users: [], groups: [role-production-operator]}
`)
	statuses, err := EvaluateCredentialReviewStatuses(root, time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(statuses) != 0 {
		t.Fatalf("expected a policy with no review: block to be invisible, got: %+v", statuses)
	}
}
