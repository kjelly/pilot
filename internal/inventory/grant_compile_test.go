package inventory

import (
	"reflect"
	"testing"
)

func mustGrant(t *testing.T, doc string) map[string]any {
	t.Helper()
	root := mustParseRoster(t, "grants:\n"+doc)
	grants := listField(root, "grants")
	if len(grants) != 1 {
		t.Fatalf("expected exactly one grant in fixture, got %d", len(grants))
	}
	return asMap(grants[0])
}

func TestCompileTemporaryGrant_NoWrapperGroup(t *testing.T) {
	grant := mustGrant(t, `
  - name: vendor-project-x
    kind: temporary_grant
    subjects: {users: [vendor01], groups: [team-sre]}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
`)
	rule := CompileTemporaryGrant(grant, GrantActive)

	if rule.Name != "pilot-grant-login-vendor-project-x-"+shortHash("vendor-project-x") {
		t.Fatalf("unexpected compiled rule name: %s", rule.Name)
	}
	if len(rule.Users) != 1 || rule.Users[0] != "vendor01" {
		t.Fatalf("unexpected users: %v", rule.Users)
	}
	// No access-* wrapper group is ever synthesized — the compiled rule's
	// groups are exactly the grant's own subjects.groups, copied verbatim,
	// and nothing else.
	if len(rule.Groups) != 1 || rule.Groups[0] != "team-sre" {
		t.Fatalf("unexpected groups: %v", rule.Groups)
	}
	if !rule.Present || !rule.Enabled {
		t.Fatalf("expected an active grant to compile to Present+Enabled, got %+v", rule)
	}
}

func TestCompileTemporaryGrant_LifecycleStateMapping(t *testing.T) {
	grant := mustGrant(t, `
  - name: vendor-project-x
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
`)
	cases := []struct {
		lifecycle   GrantLifecycleState
		wantPresent bool
		wantEnabled bool
	}{
		{GrantPending, true, false},
		{GrantActive, true, true},
		{GrantExpired, true, false},
		{GrantAbsent, false, false},
	}
	for _, c := range cases {
		rule := CompileTemporaryGrant(grant, c.lifecycle)
		if rule.Present != c.wantPresent || rule.Enabled != c.wantEnabled {
			t.Errorf("lifecycle %s: got Present=%v Enabled=%v, want Present=%v Enabled=%v", c.lifecycle, rule.Present, rule.Enabled, c.wantPresent, c.wantEnabled)
		}
	}
}

func TestCompileTemporaryGrant_NameIsDeterministicAndStable(t *testing.T) {
	grant := mustGrant(t, `
  - name: vendor-project-x
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
`)
	a := CompileTemporaryGrant(grant, GrantActive)
	b := CompileTemporaryGrant(grant, GrantActive)
	if a.Name != b.Name {
		t.Fatalf("compiled rule name is not stable across repeated compiles: %s vs %s", a.Name, b.Name)
	}
}

func TestCompileSudoGrant_NativeAttributesAndNoWrapperGroup(t *testing.T) {
	grant := mustGrant(t, `
  - name: alice-prod-nginx
    kind: sudo_grant
    subjects: {users: [alice], groups: [role-production-operator]}
    targets: {hosts: [], hostgroups: [prod-web]}
    privilege: {command_groups: [web-service-manage], commands: []}
    run_as: {users: [root], groups: []}
    options: []
`)
	validity := GrantValidity{
		NotBefore: mustParseTime(t, "2026-08-21T15:00:00Z"),
		NotAfter:  mustParseTime(t, "2026-08-21T19:00:00Z"),
	}
	rule := CompileSudoGrant(grant, GrantActive, validity)

	if rule.Name != "pilot-grant-sudo-alice-prod-nginx-"+shortHash("alice-prod-nginx") {
		t.Fatalf("unexpected compiled rule name: %s", rule.Name)
	}
	if rule.SudoNotBefore != "20260821150000Z" {
		t.Fatalf("unexpected SudoNotBefore: %s", rule.SudoNotBefore)
	}
	if rule.SudoNotAfter != "20260821190000Z" {
		t.Fatalf("unexpected SudoNotAfter: %s", rule.SudoNotAfter)
	}
	if !rule.Present {
		t.Fatalf("expected an active sudo_grant to be Present")
	}
	if len(rule.Groups) != 1 || rule.Groups[0] != "role-production-operator" {
		t.Fatalf("unexpected groups: %v", rule.Groups)
	}
}

func TestCompileSudoGrant_CommandCategoryDefaultsToAllWhenUnspecific(t *testing.T) {
	grant := mustGrant(t, `
  - name: alice-prod-nginx
    kind: sudo_grant
    subjects: {users: [alice], groups: []}
    targets: {hosts: [], hostgroups: [prod-web]}
`)
	rule := CompileSudoGrant(grant, GrantActive, GrantValidity{NotAfter: mustParseTime(t, "2026-08-21T19:00:00Z")})
	if rule.CommandCategory != "all" {
		t.Fatalf("expected CommandCategory to default to all when no specific commands/command_groups are set, got %q", rule.CommandCategory)
	}

	specific := mustGrant(t, `
  - name: alice-specific
    kind: sudo_grant
    subjects: {users: [alice], groups: []}
    targets: {hosts: [], hostgroups: [prod-web]}
    privilege: {commands: [/usr/bin/systemctl]}
`)
	specificRule := CompileSudoGrant(specific, GrantActive, GrantValidity{NotAfter: mustParseTime(t, "2026-08-21T19:00:00Z")})
	if specificRule.CommandCategory != "" {
		t.Fatalf("expected CommandCategory to stay unset when specific commands are set, got %q", specificRule.CommandCategory)
	}
}

func TestCompileSudoGrant_OmittedNotBeforeStaysEmptyForIdempotency(t *testing.T) {
	grant := mustGrant(t, `
  - name: alice-prod-nginx
    kind: sudo_grant
    subjects: {users: [alice], groups: []}
    targets: {hosts: [], hostgroups: [prod-web]}
`)
	validity := GrantValidity{NotAfter: mustParseTime(t, "2026-08-21T19:00:00Z")}
	a := CompileSudoGrant(grant, GrantActive, validity)
	b := CompileSudoGrant(grant, GrantActive, validity)
	if a.SudoNotBefore != "" || b.SudoNotBefore != "" {
		t.Fatalf("expected an omitted not_before to stay unset (no synthesized 'now'), got a=%q b=%q", a.SudoNotBefore, b.SudoNotBefore)
	}
	if a.SudoNotAfter != b.SudoNotAfter {
		t.Fatalf("repeated compile is not idempotent: %q vs %q", a.SudoNotAfter, b.SudoNotAfter)
	}
}

func TestCompileSudoGrant_AbsentIsNotPresent(t *testing.T) {
	grant := mustGrant(t, `
  - name: alice-prod-nginx
    kind: sudo_grant
    subjects: {users: [alice], groups: []}
    targets: {hosts: [], hostgroups: [prod-web]}
`)
	rule := CompileSudoGrant(grant, GrantAbsent, GrantValidity{})
	if rule.Present {
		t.Fatalf("expected an absent sudo_grant to compile to Present=false")
	}
	if rule.SudoNotBefore != "" || rule.SudoNotAfter != "" {
		t.Fatalf("expected no native attributes on an absent compiled rule, got %+v", rule)
	}
}

func TestCompileGrants_IdempotentAcrossRepeatedCompiles(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: vendor-project-x
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2026-08-31T18:00:00+08:00"}
    justification: {reason: "Project X maintenance"}
  - name: alice-prod-nginx
    kind: sudo_grant
    subjects: {users: [alice], groups: []}
    targets: {hosts: [], hostgroups: [production-db]}
    validity: {not_after: "2026-08-21T19:00:00+08:00"}
    justification: {reason: "incident response"}
`)
	now := mustParseTime(t, "2026-08-25T00:00:00Z")

	hbac1, sudo1, err := CompileGrants(root, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hbac2, sudo2, err := CompileGrants(root, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hbac1) != 1 || len(sudo1) != 1 {
		t.Fatalf("expected one compiled hbac rule and one compiled sudo rule, got %d/%d", len(hbac1), len(sudo1))
	}
	if !reflect.DeepEqual(hbac1[0], hbac2[0]) {
		t.Fatalf("repeated CompileGrants is not idempotent for hbac: %+v vs %+v", hbac1[0], hbac2[0])
	}
	if !reflect.DeepEqual(sudo1[0], sudo2[0]) {
		t.Fatalf("repeated CompileGrants is not idempotent for sudo: %+v vs %+v", sudo1[0], sudo2[0])
	}
}

func TestCompileGrants_SkipsBreakglass(t *testing.T) {
	root := grantsRoster(t, `
grants:
  - name: infra-emergency
    kind: breakglass
    subjects: {users: [alice], groups: []}
    targets: {hosts: [], hostgroups: [production-db]}
    services: [sshd]
    activation: {max_duration: 1h}
`)
	hbac, sudo, err := CompileGrants(root, mustParseTime(t, "2026-08-25T00:00:00Z"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hbac) != 0 || len(sudo) != 0 {
		t.Fatalf("expected breakglass to be skipped by the Phase 1 reconcile compiler, got hbac=%v sudo=%v", hbac, sudo)
	}
}
