package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRosterAccessRelationshipRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roster.yaml")
	fixture := `schema_version: 1
freeipa: {domain: ipa.pilot.internal}
users:
  - {name: alice, state: present}
groups:
  - name: access-webhosts-ssh
    state: present
    category: access
    membership: {authoritative: true, users: [alice], groups: []}
hostgroups: []
hbac:
  disable_allow_all: false
  rules: []
`
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AppendRosterHostgroup(path, "webhosts"); err != nil {
		t.Fatal(err)
	}
	hg, found, err := RosterHostgroup(path, "webhosts")
	if err != nil || !found {
		t.Fatalf("hostgroup lookup: found=%v err=%v", found, err)
	}
	mem := rosterMapForTest(hg, "membership")
	mem["hosts"] = []string{"web1.ipa.pilot.internal", "web2.ipa.pilot.internal"}
	hg["membership"] = mem
	if violations, _, err := SimulateSetRosterHostgroup(path, "webhosts", hg); err != nil || len(violations) != 0 {
		t.Fatalf("hostgroup simulation: violations=%v err=%v", violations, err)
	}
	if err := SetRosterHostgroup(path, "webhosts", hg); err != nil {
		t.Fatal(err)
	}
	rule := map[string]any{
		"name": "webhosts-ssh-access", "state": "present", "enabled": true,
		"subjects": map[string]any{"users": []string{}, "groups": []string{"access-webhosts-ssh"}},
		"targets":  map[string]any{"hosts": []string{}, "hostgroups": []string{"webhosts"}},
		"services": []string{"sshd"},
	}
	if violations, err := SimulateAddRosterHBACRule(path, rule); err != nil || len(violations) != 0 {
		t.Fatalf("HBAC simulation: violations=%v err=%v", violations, err)
	}
	if err := AppendRosterHBACRule(path, rule); err != nil {
		t.Fatal(err)
	}
	breakGlass := map[string]any{
		"name": "admin-breakglass", "state": "present", "enabled": true,
		"subjects": map[string]any{"users": []string{"admin"}, "groups": []string{}},
		"targets":  map[string]any{"hostcat": "all"},
		"services": []string{"sshd"},
	}
	if err := AppendRosterHBACRule(path, breakGlass); err != nil {
		t.Fatal(err)
	}
	if err := SetRosterHBACDisableAllowAll(path, true); err != nil {
		t.Fatal(err)
	}
	violations, err := ValidateRosterFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 0 {
		t.Fatalf("final roster violations: %v", violations)
	}
	names, err := RosterHBACRuleNames(path)
	if err != nil || len(names) != 2 || names[0] != "webhosts-ssh-access" || names[1] != "admin-breakglass" {
		t.Fatalf("HBAC names=%v err=%v", names, err)
	}
}

// TestAppendRosterNFSClientWithWildcardHostgroup exercises the exact
// append-hostgroup / set-membership-all / append-nfs_clients sequence used
// to opt a roster into "every managed host may become an NFS client" (see
// playbooks/apply/freeipa-nfs-client-apply.yml's membership.all wildcard,
// 2026-08-18) — the roster must still validate cleanly, and the resulting
// document must round-trip with the wildcard hostgroup properly wired to a
// present nfs_clients entry.
func TestAppendRosterNFSClientWithWildcardHostgroup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roster.yaml")
	fixture := `schema_version: 2
freeipa: {domain: ipa.pilot.internal}
users: []
groups: []
hostgroups: []
hbac: {disable_allow_all: false, rules: []}
`
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AppendRosterHostgroup(path, "nfs-clients-all"); err != nil {
		t.Fatal(err)
	}
	hg, found, err := RosterHostgroup(path, "nfs-clients-all")
	if err != nil || !found {
		t.Fatalf("hostgroup lookup: found=%v err=%v", found, err)
	}
	hg["membership"] = map[string]any{"all": true}
	if violations, _, err := SimulateSetRosterHostgroup(path, "nfs-clients-all", hg); err != nil || len(violations) != 0 {
		t.Fatalf("hostgroup simulation: violations=%v err=%v", violations, err)
	}
	if err := SetRosterHostgroup(path, "nfs-clients-all", hg); err != nil {
		t.Fatal(err)
	}
	if err := AppendRosterNFSClient(path, map[string]any{"hostgroup": "nfs-clients-all", "state": "present"}); err != nil {
		t.Fatal(err)
	}
	violations, err := ValidateRosterFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 0 {
		t.Fatalf("final roster violations: %v", violations)
	}
	root, err := readRosterAsMap(path)
	if err != nil {
		t.Fatal(err)
	}
	clients := listField(root, "nfs_clients")
	if len(clients) != 1 {
		t.Fatalf("nfs_clients = %v, want exactly one entry", clients)
	}
	entry := asMap(clients[0])
	if entry["hostgroup"] != "nfs-clients-all" || entry["state"] != "present" {
		t.Fatalf("nfs_clients[0] = %v, want hostgroup=nfs-clients-all state=present", entry)
	}
	rehg, found, err := RosterHostgroup(path, "nfs-clients-all")
	if err != nil || !found {
		t.Fatalf("re-read hostgroup: found=%v err=%v", found, err)
	}
	mem := rosterMapForTest(rehg, "membership")
	if all, _ := mem["all"].(bool); !all {
		t.Fatalf("hostgroup membership = %v, want all: true to survive the round trip", mem)
	}
}

func TestRosterSudoRelationshipRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roster.yaml")
	fixture := `schema_version: 1
groups:
  - name: role-ops
    state: present
    category: role
sudo:
  command_groups: []
  rules: []
`
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}

	commandGroup := map[string]any{
		"name": "ops-read", "state": "present",
		"commands": []string{"/usr/bin/journalctl -u nginx", "/usr/bin/systemctl status nginx"},
	}
	if violations, err := SimulateAddRosterSudoCommandGroup(path, commandGroup); err != nil || len(violations) != 0 {
		t.Fatalf("command group simulation: violations=%v err=%v", violations, err)
	}
	if err := AppendRosterSudoCommandGroup(path, commandGroup); err != nil {
		t.Fatal(err)
	}

	rule := map[string]any{
		"name": "ops-read-sudo", "state": "present", "enabled": true,
		"subjects": map[string]any{"users": []string{}, "groups": []string{"role-ops"}},
		"targets":  map[string]any{"hostcat": "all", "hosts": []string{}, "hostgroups": []string{}},
		"allow":    map[string]any{"command_groups": []string{"ops-read"}, "commands": []string{}},
		"deny":     map[string]any{"command_groups": []string{}, "commands": []string{}},
		"run_as":   map[string]any{"users": []string{"root"}, "groups": []string{}},
		"options":  []string{"!authenticate"},
	}
	if violations, err := SimulateAddRosterSudoRule(path, rule); err != nil || len(violations) != 0 {
		t.Fatalf("sudo rule simulation: violations=%v err=%v", violations, err)
	}
	if err := AppendRosterSudoRule(path, rule); err != nil {
		t.Fatal(err)
	}

	groupNames, err := RosterSudoCommandGroupNames(path)
	if err != nil || len(groupNames) != 1 || groupNames[0] != "ops-read" {
		t.Fatalf("RosterSudoCommandGroupNames() = %v, %v", groupNames, err)
	}
	ruleNames, err := RosterSudoRuleNames(path)
	if err != nil || len(ruleNames) != 1 || ruleNames[0] != "ops-read-sudo" {
		t.Fatalf("RosterSudoRuleNames() = %v, %v", ruleNames, err)
	}

	stored, found, err := RosterSudoRule(path, "ops-read-sudo")
	if err != nil || !found {
		t.Fatalf("RosterSudoRule() found=%v err=%v", found, err)
	}
	allow := mapField(stored, "allow")
	allow["commands"] = []string{"/usr/bin/id"}
	stored["allow"] = allow
	if violations, found, err := SimulateSetRosterSudoRule(path, "ops-read-sudo", stored); err != nil || !found || len(violations) != 0 {
		t.Fatalf("sudo rule set simulation: found=%v violations=%v err=%v", found, violations, err)
	}
	if err := SetRosterSudoRule(path, "ops-read-sudo", stored); err != nil {
		t.Fatal(err)
	}
	if violations, err := ValidateRosterFile(path); err != nil || len(violations) != 0 {
		t.Fatalf("final roster violations: %v err=%v", violations, err)
	}
}

func rosterMapForTest(m map[string]any, key string) map[string]any {
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return map[string]any{}
}
