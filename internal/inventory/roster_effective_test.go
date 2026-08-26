package inventory

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

const effectiveTestRosterFixture = `
schema_version: 1
freeipa: {domain: ipa.pilot.internal}
users: []
groups:
  - name: access-ops
    state: present
    category: access
    membership: {authoritative: true, users: [alice], groups: [access-ops-nested]}
  - name: access-ops-nested
    state: present
    category: access
    membership: {authoritative: true, users: [bob], groups: []}
  - name: access-cycle-a
    state: present
    category: access
    membership: {authoritative: true, users: [], groups: [access-cycle-b]}
  - name: access-cycle-b
    state: present
    category: access
    membership: {authoritative: true, users: [carol], groups: [access-cycle-a]}
  - name: role-deploy
    state: present
    category: role
    membership: {authoritative: true, users: [dave], groups: []}
  - name: team-x
    state: present
    category: team
    membership: {authoritative: true, users: [frank], groups: []}
hostgroups:
  - name: webhosts
    state: present
    membership: {authoritative: true, hosts: [web1.ipa.pilot.internal], hostgroups: [webhosts-nested]}
  - name: webhosts-nested
    state: present
    membership: {authoritative: true, hosts: [web2.ipa.pilot.internal], hostgroups: []}
hbac:
  rules:
    - name: allow-ops-web
      state: present
      enabled: true
      subjects: {users: [], groups: [access-ops]}
      targets: {hosts: [], hostgroups: [webhosts]}
      services: [sshd]
    - name: allow-admin-all
      state: present
      enabled: true
      subjects: {users: [admin], groups: []}
      targets: {hostcat: all}
      services: [sshd]
    - name: mixed-direct-and-nested
      state: present
      enabled: true
      subjects: {users: [eve], groups: [team-x, role-deploy]}
      targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: [webhosts]}
      services: [sshd]
    - name: absent-rule
      state: absent
      enabled: true
      subjects: {users: [zoe], groups: []}
      targets: {hostcat: all}
      services: [sshd]
sudo:
  command_groups:
    - name: cmdgrp-restart
      commands: ["/usr/bin/systemctl restart nginx"]
  rules:
    - name: sudo-ops-web
      state: present
      subjects: {users: [], groups: [role-deploy]}
      targets: {hosts: [], hostgroups: [webhosts]}
      allow: {command_groups: [cmdgrp-restart], commands: []}
      deny: {command_groups: []}
    - name: sudo-admin-all
      state: present
      subjects: {users: [admin], groups: []}
      targets: {hostcat: all}
      allow: {command_category: all}
    - name: sudo-legacy-implicit-all
      state: present
      subjects: {users: [dave], groups: []}
      targets: {hostcat: all}
      allow: {}
`

func writeEffectiveTestRoster(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ipa-identity.yaml")
	if err := os.WriteFile(path, []byte(effectiveTestRosterFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEffectiveGroupMembers_DirectAndNested(t *testing.T) {
	path := writeEffectiveTestRoster(t)
	got, err := EffectiveGroupMembers(path, "access-ops")
	if err != nil {
		t.Fatalf("EffectiveGroupMembers() error = %v", err)
	}
	want := []string{"alice", "bob"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("EffectiveGroupMembers(access-ops) = %v, want %v", got, want)
	}
}

func TestEffectiveGroupMembers_CycleIsSafe(t *testing.T) {
	path := writeEffectiveTestRoster(t)
	for _, group := range []string{"access-cycle-a", "access-cycle-b"} {
		got, err := EffectiveGroupMembers(path, group)
		if err != nil {
			t.Fatalf("EffectiveGroupMembers(%s) error = %v", group, err)
		}
		if want := []string{"carol"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("EffectiveGroupMembers(%s) = %v, want %v (mutual A<->B cycle must not hang or duplicate)", group, got, want)
		}
	}
}

func TestEffectiveGroupMembers_UnknownGroupReturnsEmpty(t *testing.T) {
	path := writeEffectiveTestRoster(t)
	got, err := EffectiveGroupMembers(path, "no-such-group")
	if err != nil {
		t.Fatalf("EffectiveGroupMembers() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("EffectiveGroupMembers(no-such-group) = %v, want empty", got)
	}
}

func TestEffectiveHostgroupHosts_DirectAndNested(t *testing.T) {
	path := writeEffectiveTestRoster(t)
	got, err := EffectiveHostgroupHosts(path, "webhosts")
	if err != nil {
		t.Fatalf("EffectiveHostgroupHosts() error = %v", err)
	}
	want := []string{"web1.ipa.pilot.internal", "web2.ipa.pilot.internal"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("EffectiveHostgroupHosts(webhosts) = %v, want %v", got, want)
	}
}

func TestEffectiveHBACAccessList_ResolvesNestedGroupsAndHostgroupsAndSkipsAbsent(t *testing.T) {
	path := writeEffectiveTestRoster(t)
	got, err := EffectiveHBACAccessList(path)
	if err != nil {
		t.Fatalf("EffectiveHBACAccessList() error = %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("EffectiveHBACAccessList() = %+v, want exactly 3 entries (absent-rule must be skipped)", got)
	}

	byRule := map[string]EffectiveHBACAccess{}
	for _, a := range got {
		byRule[a.Rule] = a
	}

	opsWeb, ok := byRule["allow-ops-web"]
	if !ok {
		t.Fatalf("expected rule allow-ops-web in %+v", got)
	}
	if want := []string{"alice", "bob"}; !reflect.DeepEqual(opsWeb.Users, want) {
		t.Fatalf("allow-ops-web.Users = %v, want %v (subjects.groups must expand through nested membership)", opsWeb.Users, want)
	}
	if opsWeb.AllHosts {
		t.Fatal("allow-ops-web.AllHosts = true, want false")
	}
	if want := []string{"web1.ipa.pilot.internal", "web2.ipa.pilot.internal"}; !reflect.DeepEqual(opsWeb.Hosts, want) {
		t.Fatalf("allow-ops-web.Hosts = %v, want %v (targets.hostgroups must expand through nested membership)", opsWeb.Hosts, want)
	}
	if want := []string{"sshd"}; !reflect.DeepEqual(opsWeb.Services, want) {
		t.Fatalf("allow-ops-web.Services = %v, want %v", opsWeb.Services, want)
	}

	adminAll, ok := byRule["allow-admin-all"]
	if !ok {
		t.Fatalf("expected rule allow-admin-all in %+v", got)
	}
	if !adminAll.AllHosts || len(adminAll.Hosts) != 0 {
		t.Fatalf("allow-admin-all = %+v, want all_hosts=true and no explicit Hosts", adminAll)
	}
	if want := []string{"admin"}; !reflect.DeepEqual(adminAll.Users, want) {
		t.Fatalf("allow-admin-all.Users = %v, want %v", adminAll.Users, want)
	}

	// spec.md §15/§18.5: the resolver must work unchanged when HBAC mixes
	// a direct user with a team-* group and a role-* group, and a direct
	// host with a hostgroup, all in the same rule.
	mixed, ok := byRule["mixed-direct-and-nested"]
	if !ok {
		t.Fatalf("expected rule mixed-direct-and-nested in %+v", got)
	}
	if want := []string{"dave", "eve", "frank"}; !reflect.DeepEqual(mixed.Users, want) {
		t.Fatalf("mixed-direct-and-nested.Users = %v, want %v (direct subjects.users union team-x + role-deploy membership)", mixed.Users, want)
	}
	if mixed.AllHosts {
		t.Fatal("mixed-direct-and-nested.AllHosts = true, want false")
	}
	if want := []string{"db-special.ipa.pilot.internal", "web1.ipa.pilot.internal", "web2.ipa.pilot.internal"}; !reflect.DeepEqual(mixed.Hosts, want) {
		t.Fatalf("mixed-direct-and-nested.Hosts = %v, want %v (direct targets.hosts union webhosts hostgroup expansion)", mixed.Hosts, want)
	}
}

func TestEffectiveSudoAccessList_ResolvesCommandGroupsAndAllowAll(t *testing.T) {
	path := writeEffectiveTestRoster(t)
	got, err := EffectiveSudoAccessList(path)
	if err != nil {
		t.Fatalf("EffectiveSudoAccessList() error = %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("EffectiveSudoAccessList() = %+v, want exactly 3 entries", got)
	}

	byRule := map[string]EffectiveSudoAccess{}
	for _, a := range got {
		byRule[a.Rule] = a
	}

	opsWeb, ok := byRule["sudo-ops-web"]
	if !ok {
		t.Fatalf("expected rule sudo-ops-web in %+v", got)
	}
	if want := []string{"dave"}; !reflect.DeepEqual(opsWeb.Users, want) {
		t.Fatalf("sudo-ops-web.Users = %v, want %v (subjects.groups role-deploy must resolve to its member)", opsWeb.Users, want)
	}
	if opsWeb.AllHosts {
		t.Fatal("sudo-ops-web.AllHosts = true, want false")
	}
	if want := []string{"web1.ipa.pilot.internal", "web2.ipa.pilot.internal"}; !reflect.DeepEqual(opsWeb.Hosts, want) {
		t.Fatalf("sudo-ops-web.Hosts = %v, want %v", opsWeb.Hosts, want)
	}
	if opsWeb.AllCommands {
		t.Fatal("sudo-ops-web.AllCommands = true, want false")
	}
	if want := []string{"/usr/bin/systemctl restart nginx"}; !reflect.DeepEqual(opsWeb.Commands, want) {
		t.Fatalf("sudo-ops-web.Commands = %v, want %v (allow.command_groups must resolve to its commands)", opsWeb.Commands, want)
	}

	adminAll, ok := byRule["sudo-admin-all"]
	if !ok {
		t.Fatalf("expected rule sudo-admin-all in %+v", got)
	}
	if !adminAll.AllHosts || !adminAll.AllCommands || len(adminAll.Commands) != 0 {
		t.Fatalf("sudo-admin-all = %+v, want all_hosts=true all_commands=true with no explicit Commands", adminAll)
	}

	legacyImplicit, ok := byRule["sudo-legacy-implicit-all"]
	if !ok {
		t.Fatalf("expected rule sudo-legacy-implicit-all in %+v", got)
	}
	if !legacyImplicit.AllCommands || len(legacyImplicit.Commands) != 0 {
		t.Fatalf("sudo-legacy-implicit-all = %+v, want all_commands=true with no explicit Commands (a bare allow:{} is freeipa-identity-apply.yml's documented implicit allow-all, not allow-nothing)", legacyImplicit)
	}
}

func TestSortedSetKeys_SortsAndDeduplicatesViaSetSemantics(t *testing.T) {
	m := map[string]bool{"b": true, "a": true, "c": true}
	got := sortedSetKeys(m)
	want := []string{"a", "b", "c"}
	if !sort.StringsAreSorted(got) || !reflect.DeepEqual(got, want) {
		t.Fatalf("sortedSetKeys() = %v, want %v", got, want)
	}
}
