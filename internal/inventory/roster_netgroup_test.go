package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

// netgroupValidBaseRoster is a minimal but complete schema-v2 roster with
// one netgroup exercising every membership.* type (user, group, host,
// hostgroup) — the shared starting point every negative-case test below
// mutates exactly one reference of to prove it, and only it, fails.
const netgroupValidBaseRoster = `
schema_version: 2
freeipa:
  admin: {principal: admin, password: x}
users:
  - name: alice
groups:
  - name: team-devs
    category: team
    membership: {authoritative: true, users: [alice], groups: []}
hosts:
  - name: web01.ipa.pilot.internal
    ip_address: 192.168.50.21
hostgroups:
  - name: web-servers
    membership: {authoritative: true, hosts: [web01.ipa.pilot.internal], hostgroups: []}
netgroups:
  - name: ng-project-alpha-clients
    membership:
      authoritative: true
      users: [alice]
      groups: [team-devs]
      hosts: [web01.ipa.pilot.internal]
      hostgroups: [web-servers]
      netgroups: []
`

func TestCheckNetgroups_ValidBaseRosterPassesClean(t *testing.T) {
	if v := ValidateRosterV2(mustParseRoster(t, netgroupValidBaseRoster)); len(v) != 0 {
		t.Fatalf("expected the base fixture to pass clean, got: %v", v)
	}
}

func TestCheckNetgroups_NestedNetgroupReferencePassesClean(t *testing.T) {
	doc := netgroupValidBaseRoster + `  - name: ng-build-environment
    membership:
      authoritative: true
      users: []
      groups: []
      hosts: []
      hostgroups: []
      netgroups: [ng-project-alpha-clients]
`
	if v := ValidateRosterV2(mustParseRoster(t, doc)); len(v) != 0 {
		t.Fatalf("expected a valid nested-netgroup reference to pass clean, got: %v", v)
	}
}

// ---- M18-M22: unresolved membership references ---------------------------

func TestCheckNetgroups_M18_UnresolvedUserReference(t *testing.T) {
	doc := `
schema_version: 2
netgroups:
  - name: ng-a
    membership: {authoritative: true, users: [ghost], groups: [], hosts: [], hostgroups: [], netgroups: []}
`
	v := ValidateRosterV2(mustParseRoster(t, doc))
	if !contains(ruleNames(v), "netgroup membership user reference") {
		t.Fatalf("expected an unresolved user reference violation, got: %v", v)
	}
}

func TestCheckNetgroups_M19_UnresolvedGroupReference(t *testing.T) {
	doc := `
schema_version: 2
netgroups:
  - name: ng-a
    membership: {authoritative: true, users: [], groups: [ghost-group], hosts: [], hostgroups: [], netgroups: []}
`
	v := ValidateRosterV2(mustParseRoster(t, doc))
	if !contains(ruleNames(v), "netgroup membership group reference") {
		t.Fatalf("expected an unresolved group reference violation, got: %v", v)
	}
}

func TestCheckNetgroups_M20_UnresolvedHostReference(t *testing.T) {
	doc := `
schema_version: 2
netgroups:
  - name: ng-a
    membership: {authoritative: true, users: [], groups: [], hosts: [ghost.example.internal], hostgroups: [], netgroups: []}
`
	v := ValidateRosterV2(mustParseRoster(t, doc))
	if !contains(ruleNames(v), "netgroup membership host reference") {
		t.Fatalf("expected an unresolved host reference violation, got: %v", v)
	}
}

func TestCheckNetgroups_M21_UnresolvedHostgroupReference(t *testing.T) {
	doc := `
schema_version: 2
netgroups:
  - name: ng-a
    membership: {authoritative: true, users: [], groups: [], hosts: [], hostgroups: [ghost-hostgroup], netgroups: []}
`
	v := ValidateRosterV2(mustParseRoster(t, doc))
	if !contains(ruleNames(v), "netgroup membership hostgroup reference") {
		t.Fatalf("expected an unresolved hostgroup reference violation, got: %v", v)
	}
}

func TestCheckNetgroups_M22_UnresolvedNestedNetgroupReference(t *testing.T) {
	doc := `
schema_version: 2
netgroups:
  - name: ng-a
    membership: {authoritative: true, users: [], groups: [], hosts: [], hostgroups: [], netgroups: [ng-ghost]}
`
	v := ValidateRosterV2(mustParseRoster(t, doc))
	if !contains(ruleNames(v), "netgroup membership netgroup reference") {
		t.Fatalf("expected an unresolved nested netgroup reference violation, got: %v", v)
	}
}

// ---- M23/M24: self-reference and multi-node cycles -----------------------

func TestCheckNetgroups_M23_DirectSelfReference(t *testing.T) {
	doc := `
schema_version: 2
netgroups:
  - name: ng-a
    membership: {authoritative: true, users: [], groups: [], hosts: [], hostgroups: [], netgroups: [ng-a]}
`
	v := ValidateRosterV2(mustParseRoster(t, doc))
	if !contains(ruleNames(v), "netgroup self-reference") {
		t.Fatalf("expected a self-reference violation, got: %v", v)
	}
	if contains(ruleNames(v), "netgroup cycle") {
		t.Fatalf("did not expect a separate cycle violation for a trivial self-reference (already reported), got: %v", v)
	}
}

func TestCheckNetgroups_M24_MultiNodeCycle(t *testing.T) {
	// ng-a -> ng-b -> ng-c -> ng-a
	doc := `
schema_version: 2
netgroups:
  - name: ng-a
    membership: {authoritative: true, users: [], groups: [], hosts: [], hostgroups: [], netgroups: [ng-b]}
  - name: ng-b
    membership: {authoritative: true, users: [], groups: [], hosts: [], hostgroups: [], netgroups: [ng-c]}
  - name: ng-c
    membership: {authoritative: true, users: [], groups: [], hosts: [], hostgroups: [], netgroups: [ng-a]}
`
	v := ValidateRosterV2(mustParseRoster(t, doc))
	if !contains(ruleNames(v), "netgroup cycle") {
		t.Fatalf("expected a netgroup cycle violation, got: %v", v)
	}
}

func TestCheckNetgroups_TwoNodeMutualCycle(t *testing.T) {
	doc := `
schema_version: 2
netgroups:
  - name: ng-a
    membership: {authoritative: true, users: [], groups: [], hosts: [], hostgroups: [], netgroups: [ng-b]}
  - name: ng-b
    membership: {authoritative: true, users: [], groups: [], hosts: [], hostgroups: [], netgroups: [ng-a]}
`
	v := ValidateRosterV2(mustParseRoster(t, doc))
	if !contains(ruleNames(v), "netgroup cycle") {
		t.Fatalf("expected a netgroup cycle violation for a 2-node mutual cycle, got: %v", v)
	}
}

// ---- structural checks -----------------------------------------------------

func TestCheckNetgroups_NameMustMatchNamingConvention(t *testing.T) {
	doc := `
schema_version: 2
netgroups:
  - name: not-prefixed
    membership: {authoritative: true, users: [], groups: [], hosts: [], hostgroups: [], netgroups: []}
`
	v := ValidateRosterV2(mustParseRoster(t, doc))
	if !contains(ruleNames(v), "netgroup name") {
		t.Fatalf("expected a netgroup name violation, got: %v", v)
	}
}

func TestCheckNetgroups_StateMustBePresentOrAbsent(t *testing.T) {
	doc := `
schema_version: 2
netgroups:
  - name: ng-a
    state: enabled
    membership: {authoritative: true, users: [], groups: [], hosts: [], hostgroups: [], netgroups: []}
`
	v := ValidateRosterV2(mustParseRoster(t, doc))
	if !contains(ruleNames(v), "netgroup state") {
		t.Fatalf("expected a netgroup state violation, got: %v", v)
	}
}

func TestCheckNetgroups_MembershipAuthoritativeMustBeTrue(t *testing.T) {
	doc := `
schema_version: 2
netgroups:
  - name: ng-a
    membership: {authoritative: false, users: [], groups: [], hosts: [], hostgroups: [], netgroups: []}
`
	v := ValidateRosterV2(mustParseRoster(t, doc))
	if !contains(ruleNames(v), "netgroup membership authoritative") {
		t.Fatalf("expected a membership.authoritative violation, got: %v", v)
	}
}

func TestCheckNetgroups_MembershipAuthoritativeMissingDefaultsFail(t *testing.T) {
	doc := `
schema_version: 2
netgroups:
  - name: ng-a
    membership: {users: [], groups: [], hosts: [], hostgroups: [], netgroups: []}
`
	v := ValidateRosterV2(mustParseRoster(t, doc))
	if !contains(ruleNames(v), "netgroup membership authoritative") {
		t.Fatalf("expected a missing membership.authoritative to fail, got: %v", v)
	}
}

func TestCheckNetgroups_UnknownNetgroupKey(t *testing.T) {
	doc := `
schema_version: 2
netgroups:
  - name: ng-a
    not_a_real_key: true
    membership: {authoritative: true, users: [], groups: [], hosts: [], hostgroups: [], netgroups: []}
`
	v := ValidateRosterV2(mustParseRoster(t, doc))
	if !contains(ruleNames(v), "netgroup keys") {
		t.Fatalf("expected a netgroup keys violation, got: %v", v)
	}
}

func TestCheckNetgroups_UnknownMembershipKey(t *testing.T) {
	doc := `
schema_version: 2
netgroups:
  - name: ng-a
    membership: {authoritative: true, users: [], groups: [], hosts: [], hostgroups: [], netgroups: [], nickname: x}
`
	v := ValidateRosterV2(mustParseRoster(t, doc))
	if !contains(ruleNames(v), "netgroup membership keys") {
		t.Fatalf("expected a netgroup membership keys violation, got: %v", v)
	}
}

func TestCheckNetgroups_UniqueNetgroupNames(t *testing.T) {
	doc := `
schema_version: 2
netgroups:
  - name: ng-a
    membership: {authoritative: true, users: [], groups: [], hosts: [], hostgroups: [], netgroups: []}
  - name: ng-a
    membership: {authoritative: true, users: [], groups: [], hosts: [], hostgroups: [], netgroups: []}
`
	v := ValidateRosterV2(mustParseRoster(t, doc))
	if !contains(ruleNames(v), "unique netgroup names") {
		t.Fatalf("expected a duplicate netgroup name violation, got: %v", v)
	}
}

func TestCheckNetgroups_NameMustNotCollideWithHostgroup(t *testing.T) {
	doc := `
schema_version: 2
hostgroups:
  - name: ng-shared-name
    membership: {authoritative: true, hosts: [], hostgroups: []}
netgroups:
  - name: ng-shared-name
    membership: {authoritative: true, users: [], groups: [], hosts: [], hostgroups: [], netgroups: []}
`
	v := ValidateRosterV2(mustParseRoster(t, doc))
	if !contains(ruleNames(v), "netgroup/hostgroup name collision") {
		t.Fatalf("expected a netgroup/hostgroup name collision violation, got: %v", v)
	}
}

// ---- RosterNetgroupNames ----------------------------------------------------

func TestRosterNetgroupNames_ReturnsNamesInFileOrder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	doc := netgroupValidBaseRoster + `  - name: ng-build-environment
    membership: {authoritative: true, users: [], groups: [], hosts: [], hostgroups: [], netgroups: [ng-project-alpha-clients]}
`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	names, err := RosterNetgroupNames(path)
	if err != nil {
		t.Fatalf("RosterNetgroupNames() error = %v", err)
	}
	want := []string{"ng-project-alpha-clients", "ng-build-environment"}
	if len(names) != len(want) || names[0] != want[0] || names[1] != want[1] {
		t.Fatalf("RosterNetgroupNames() = %v, want %v", names, want)
	}
}

func TestRosterNetgroupNames_EncryptedRosterReturnsErrRosterEncrypted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte("$ANSIBLE_VAULT;1.1;AES256\n633864363...\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RosterNetgroupNames(path); err != ErrRosterEncrypted {
		t.Fatalf("RosterNetgroupNames() error = %v, want ErrRosterEncrypted", err)
	}
}

// TestCheckNetgroups_DiamondSharedDescendantIsNotACycle guards against the
// classic false-positive a global (rather than path-scoped) "visited" set
// would produce: ng-a nests both ng-b and ng-c, and both of those nest
// ng-d. ng-d is reached twice, but never while it's still on the current
// DFS path, so this is a DAG, not a cycle.
func TestCheckNetgroups_DiamondSharedDescendantIsNotACycle(t *testing.T) {
	doc := `
schema_version: 2
netgroups:
  - name: ng-a
    membership: {authoritative: true, users: [], groups: [], hosts: [], hostgroups: [], netgroups: [ng-b, ng-c]}
  - name: ng-b
    membership: {authoritative: true, users: [], groups: [], hosts: [], hostgroups: [], netgroups: [ng-d]}
  - name: ng-c
    membership: {authoritative: true, users: [], groups: [], hosts: [], hostgroups: [], netgroups: [ng-d]}
  - name: ng-d
    membership: {authoritative: true, users: [], groups: [], hosts: [], hostgroups: [], netgroups: []}
`
	v := ValidateRosterV2(mustParseRoster(t, doc))
	if len(v) != 0 {
		t.Fatalf("expected a diamond-shaped DAG (shared descendant, no cycle) to pass clean, got: %v", v)
	}
}
