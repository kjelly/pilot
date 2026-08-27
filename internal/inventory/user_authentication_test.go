package inventory

import "testing"

const userAuthRosterBase = `
schema_version: 3
freeipa:
  domain: ipa.pilot.internal
  admin: {principal: admin, password: x}
groups: []
hosts: []
hostgroups: []
hbac:
  rules: []
sudo:
  rules: []
`

func userAuthRoster(t *testing.T, usersYAML string) map[string]any {
	t.Helper()
	return mustParseRoster(t, userAuthRosterBase+usersYAML)
}

func TestValidateRoster_UserAuthenticationValidPassesClean(t *testing.T) {
	root := userAuthRoster(t, `
users:
  - name: alice
    ssh_keys: {authoritative: true, values: []}
    authentication:
      allowed: [otp, pkinit]
`)
	if v := ValidateRosterV3(root); len(v) != 0 {
		t.Fatalf("expected clean pass, got: %v", v)
	}
}

func TestValidateRoster_UserAuthenticationAbsentIsFine(t *testing.T) {
	root := userAuthRoster(t, `
users:
  - name: alice
    ssh_keys: {authoritative: true, values: []}
`)
	if v := ValidateRosterV3(root); len(v) != 0 {
		t.Fatalf("expected an absent authentication: block to pass clean, got: %v", v)
	}
}

func TestValidateRoster_UserAuthenticationEmptyAllowedRejected(t *testing.T) {
	root := userAuthRoster(t, `
users:
  - name: alice
    ssh_keys: {authoritative: true, values: []}
    authentication:
      allowed: []
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "user authentication allowed") {
		t.Fatalf("expected empty allowed to be rejected, got: %v", v)
	}
}

func TestValidateRoster_UserAuthenticationUnknownTypeRejected(t *testing.T) {
	root := userAuthRoster(t, `
users:
  - name: alice
    ssh_keys: {authoritative: true, values: []}
    authentication:
      allowed: [totp]
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "user authentication type") {
		t.Fatalf("expected unknown authentication type to be rejected, got: %v", v)
	}
}

func TestValidateRoster_UserAuthenticationUnknownKeyRejected(t *testing.T) {
	root := userAuthRoster(t, `
users:
  - name: alice
    ssh_keys: {authoritative: true, values: []}
    authentication:
      allowed: [otp]
      required: true
`)
	v := ValidateRosterV3(root)
	if !contains(ruleNames(v), "user authentication keys") {
		t.Fatalf("expected unknown authentication field to be rejected, got: %v", v)
	}
}

func TestCompileUserAuthTypes_OnlyCompilesUsersWithExplicitBlock(t *testing.T) {
	root := userAuthRoster(t, `
users:
  - name: alice
    ssh_keys: {authoritative: true, values: []}
    authentication:
      allowed: [pkinit, otp, otp]
  - name: bob
    ssh_keys: {authoritative: true, values: []}
`)
	compiled := CompileUserAuthTypes(root)
	if len(compiled) != 1 {
		t.Fatalf("expected exactly one compiled entry (bob has no authentication: block), got: %+v", compiled)
	}
	if compiled[0].User != "alice" {
		t.Fatalf("expected alice, got %q", compiled[0].User)
	}
	if got := compiled[0].Allowed; len(got) != 2 || got[0] != "otp" || got[1] != "pkinit" {
		t.Fatalf("expected sorted+deduplicated [otp pkinit], got %v", got)
	}
}

func TestCompileUserAuthTypes_SkipsAbsentUsers(t *testing.T) {
	root := userAuthRoster(t, `
users:
  - name: alice
    state: absent
    ssh_keys: {authoritative: true, values: []}
    authentication:
      allowed: [otp]
`)
	compiled := CompileUserAuthTypes(root)
	if len(compiled) != 0 {
		t.Fatalf("expected an absent user to never compile an auth-type entry, got: %+v", compiled)
	}
}
