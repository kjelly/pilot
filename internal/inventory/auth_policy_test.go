package inventory

import "testing"

func TestValidateRoster_AuthPolicyValidPassesClean(t *testing.T) {
	root := grantsRoster(t, `
auth_policies:
  - name: production-strong-auth
    state: present
    targets: {hosts: [], hostgroups: [production-db]}
    require_any: [otp, pkinit]
`)
	if v := ValidateRosterV3(root); len(v) != 0 {
		t.Fatalf("expected clean pass, got: %v", v)
	}
}

func TestValidateRoster_AuthPolicyUnknownIndicatorRejected(t *testing.T) {
	root := grantsRoster(t, `
auth_policies:
  - name: bad-policy
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    require_any: [totp]
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "auth_policy indicator") {
		t.Fatalf("expected unknown indicator to be rejected, got: %v", v)
	}
}

func TestValidateRoster_AuthPolicyMissingTargetsRejected(t *testing.T) {
	root := grantsRoster(t, `
auth_policies:
  - name: bad-policy
    targets: {hosts: [], hostgroups: []}
    require_any: [otp]
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "auth_policy targets") {
		t.Fatalf("expected missing targets to be rejected, got: %v", v)
	}
}

func TestValidateRoster_AuthPolicyEmptyRequireAnyRejected(t *testing.T) {
	root := grantsRoster(t, `
auth_policies:
  - name: bad-policy
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    require_any: []
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "auth_policy require_any") {
		t.Fatalf("expected empty require_any to be rejected, got: %v", v)
	}
}

func TestValidateRoster_AuthPolicyUnknownHostgroupReferenceRejected(t *testing.T) {
	root := grantsRoster(t, `
auth_policies:
  - name: bad-policy
    targets: {hosts: [], hostgroups: [ghost-group]}
    require_any: [otp]
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "auth_policy target hostgroup reference") {
		t.Fatalf("expected unknown hostgroup reference to be rejected, got: %v", v)
	}
}

func TestValidateRoster_AuthPolicyDuplicateNamesRejected(t *testing.T) {
	root := grantsRoster(t, `
auth_policies:
  - name: dup
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    require_any: [otp]
  - name: dup
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    require_any: [pkinit]
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "unique auth_policy names") {
		t.Fatalf("expected duplicate names to be rejected, got: %v", v)
	}
}

func TestValidateRoster_AuthPolicyUnknownKeyRejected(t *testing.T) {
	root := grantsRoster(t, `
auth_policies:
  - name: bad-policy
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    require_any: [otp]
    require_all: [pkinit]
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "auth_policy keys") {
		t.Fatalf("expected unknown key to be rejected, got: %v", v)
	}
}
