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
	if err != nil || len(names) != 1 || names[0] != "webhosts-ssh-access" {
		t.Fatalf("HBAC names=%v err=%v", names, err)
	}
}

func rosterMapForTest(m map[string]any, key string) map[string]any {
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return map[string]any{}
}
