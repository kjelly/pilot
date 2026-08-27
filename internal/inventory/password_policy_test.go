package inventory

import "testing"

func TestValidateRoster_PasswordPolicyValidPassesClean(t *testing.T) {
	root := grantsRoster(t, `
password_policies:
  - name: privileged-users
    state: present
    group: role-production-operator
    priority: 10
    min_length: 16
    history_size: 24
    max_life: 90d
    min_life: 1h
    lockout:
      max_failures: 5
      failure_reset_interval: 15m
      lockout_duration: 15m
`)
	if v := ValidateRosterV3(root); len(v) != 0 {
		t.Fatalf("expected clean pass, got: %v", v)
	}
}

func TestValidateRoster_PasswordPolicyUnknownGroupRejected(t *testing.T) {
	root := grantsRoster(t, `
password_policies:
  - name: bad-policy
    group: role-does-not-exist
    priority: 10
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "password_policy group reference") {
		t.Fatalf("expected unknown group reference to be rejected, got: %v", v)
	}
}

func TestValidateRoster_PasswordPolicyMissingGroupRejected(t *testing.T) {
	root := grantsRoster(t, `
password_policies:
  - name: bad-policy
    priority: 10
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "password_policy group") {
		t.Fatalf("expected missing group to be rejected, got: %v", v)
	}
}

// TestValidateRoster_PasswordPolicyDeprecatedAccessGroupRejected locks in
// spec.md v3.2 §7: "Do not use deprecated access-* as the new privileged
// grouping model."
func TestValidateRoster_PasswordPolicyDeprecatedAccessGroupRejected(t *testing.T) {
	root := grantsRoster(t, `
password_policies:
  - name: bad-policy
    group: access-legacy
    priority: 10
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "password_policy group category") {
		t.Fatalf("expected deprecated access-* group to be rejected, got: %v", v)
	}
}

func TestValidateRoster_PasswordPolicyMissingPriorityRejected(t *testing.T) {
	root := grantsRoster(t, `
password_policies:
  - name: bad-policy
    group: role-production-operator
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "password_policy priority") {
		t.Fatalf("expected missing priority to be rejected, got: %v", v)
	}
}

func TestValidateRoster_PasswordPolicyInvalidPriorityRejected(t *testing.T) {
	root := grantsRoster(t, `
password_policies:
  - name: bad-policy
    group: role-production-operator
    priority: 0
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "password_policy priority") {
		t.Fatalf("expected non-positive priority to be rejected, got: %v", v)
	}
}

func TestValidateRoster_PasswordPolicyDuplicateAmbiguousPriorityRejected(t *testing.T) {
	root := grantsRoster(t, `
password_policies:
  - name: policy-a
    group: role-production-operator
    priority: 10
  - name: policy-b
    group: team-sre
    priority: 10
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "password_policy priority uniqueness") {
		t.Fatalf("expected duplicate/ambiguous priority to be rejected, got: %v", v)
	}
}

func TestValidateRoster_PasswordPolicyInvalidDurationRejected(t *testing.T) {
	root := grantsRoster(t, `
password_policies:
  - name: bad-policy
    group: role-production-operator
    priority: 10
    max_life: not-a-duration
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "password_policy max_life") {
		t.Fatalf("expected invalid max_life duration to be rejected, got: %v", v)
	}
}

func TestValidateRoster_PasswordPolicyUnknownFieldRejected(t *testing.T) {
	root := grantsRoster(t, `
password_policies:
  - name: bad-policy
    group: role-production-operator
    priority: 10
    on_overdue: disable_account
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "password_policy keys") {
		t.Fatalf("expected unknown field to be rejected, got: %v", v)
	}
}

func TestValidateRoster_PasswordPolicyExplicitRemovalOnlyNeedsGroup(t *testing.T) {
	root := grantsRoster(t, `
password_policies:
  - name: retired-policy
    state: absent
    group: role-production-operator
`)
	if v := ValidateRosterV3(root); len(v) != 0 {
		t.Fatalf("expected an absent entry with no priority/fields to pass clean, got: %v", v)
	}
}

func TestValidateRoster_PasswordPolicyDuplicateNamesRejected(t *testing.T) {
	root := grantsRoster(t, `
password_policies:
  - name: dup-name
    group: role-production-operator
    priority: 10
  - name: dup-name
    group: team-sre
    priority: 20
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "unique password_policy names") {
		t.Fatalf("expected duplicate password_policy names to be rejected, got: %v", v)
	}
}

func TestCompilePasswordPolicies_ConvertsUnitsAndOmitsUnsetFields(t *testing.T) {
	root := grantsRoster(t, `
password_policies:
  - name: privileged-users
    group: role-production-operator
    priority: 10
    min_length: 16
    history_size: 0
    max_life: 90d
    min_life: 1h
    lockout:
      max_failures: 5
      failure_reset_interval: 15m
      lockout_duration: 1h
  - name: retired-policy
    state: absent
    group: role-production-operator
`)
	compiled, err := CompilePasswordPolicies(root)
	if err != nil {
		t.Fatalf("CompilePasswordPolicies() error = %v", err)
	}
	if len(compiled) != 2 {
		t.Fatalf("CompilePasswordPolicies() = %d entries, want 2", len(compiled))
	}

	p := compiled[0]
	if p.Group != "role-production-operator" || p.State != "present" {
		t.Fatalf("unexpected compiled entry: %+v", p)
	}
	if p.Priority == nil || *p.Priority != 10 {
		t.Errorf("Priority = %v, want 10", p.Priority)
	}
	if p.MinLength == nil || *p.MinLength != 16 {
		t.Errorf("MinLength = %v, want 16", p.MinLength)
	}
	// history_size: 0 is a legitimate explicit value, not "unset" —
	// must compile to a non-nil pointer to *0, never nil.
	if p.HistorySize == nil || *p.HistorySize != 0 {
		t.Errorf("HistorySize = %v, want pointer to 0 (explicit, not absent)", p.HistorySize)
	}
	if p.MaxLifeDays == nil || *p.MaxLifeDays != 90 {
		t.Errorf("MaxLifeDays = %v, want 90", p.MaxLifeDays)
	}
	if p.MinLifeHours == nil || *p.MinLifeHours != 1 {
		t.Errorf("MinLifeHours = %v, want 1", p.MinLifeHours)
	}
	if p.LockoutMaxFailures == nil || *p.LockoutMaxFailures != 5 {
		t.Errorf("LockoutMaxFailures = %v, want 5", p.LockoutMaxFailures)
	}
	if p.LockoutFailureResetSeconds == nil || *p.LockoutFailureResetSeconds != 900 {
		t.Errorf("LockoutFailureResetSeconds = %v, want 900", p.LockoutFailureResetSeconds)
	}
	if p.LockoutDurationSeconds == nil || *p.LockoutDurationSeconds != 3600 {
		t.Errorf("LockoutDurationSeconds = %v, want 3600", p.LockoutDurationSeconds)
	}

	removed := compiled[1]
	if removed.State != "absent" {
		t.Fatalf("expected second entry state=absent, got %+v", removed)
	}
	if removed.Priority != nil {
		t.Errorf("absent entry Priority = %v, want nil (fields never compiled for a removal)", removed.Priority)
	}
}

func TestCompilePasswordPolicies_OmitsAbsentOptionalFields(t *testing.T) {
	root := grantsRoster(t, `
password_policies:
  - name: minimal-policy
    group: role-production-operator
    priority: 5
`)
	compiled, err := CompilePasswordPolicies(root)
	if err != nil {
		t.Fatalf("CompilePasswordPolicies() error = %v", err)
	}
	p := compiled[0]
	for name, ptr := range map[string]*int{
		"MinLength":                  p.MinLength,
		"HistorySize":                p.HistorySize,
		"MaxLifeDays":                p.MaxLifeDays,
		"MinLifeHours":               p.MinLifeHours,
		"LockoutMaxFailures":         p.LockoutMaxFailures,
		"LockoutFailureResetSeconds": p.LockoutFailureResetSeconds,
		"LockoutDurationSeconds":     p.LockoutDurationSeconds,
	} {
		if ptr != nil {
			t.Errorf("%s = %v, want nil (absent from roster)", name, *ptr)
		}
	}
}
