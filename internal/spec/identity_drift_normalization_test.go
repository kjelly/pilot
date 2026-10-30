package spec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestIdentityDriftSharedNormalizationInAnsible(t *testing.T) {
	path, err := filepath.Abs("../../playbooks/apply/tasks/freeipa-identity-normalize-users-groups.yml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	// Include twice: the plan cannot retain objects from an earlier include.
	include := map[string]any{"name": "shared normalization", "ansible.builtin.include_tasks": path}
	tasks := []any{include, include, map[string]any{
		"name": "assert actual apply defaults and empty-list semantics", "no_log": true,
		"ansible.builtin.assert": map[string]any{"that": []string{
			"ipa_users | length == 2", "ipa_groups | length == 1",
			"ipa_users[0].first == 'alice'", "ipa_users[0].last == 'alice'",
			"ipa_users[0].login_shell == '/bin/bash'", "ipa_users[0].home_directory == '/home/alice'",
			"ipa_users[0].ssh_keys is none", "ipa_users[0].enabled",
			"ipa_users[1].ssh_keys == []", "not ipa_users[1].enabled",
			"ipa_groups[0].desc == 'team-test'", "ipa_groups[0].membership.authoritative == false",
		}},
	}}
	vars := map[string]any{"freeipa_roster": map[string]any{
		"schema_version": 3,
		"grants":         []any{},
		"users":          []any{map[string]any{"name": "alice", "password": map[string]any{"initial": "PASSWORD_SENTINEL"}}, map[string]any{"name": "bob", "state": "disabled", "ssh_keys": map[string]any{"values": []any{}}}},
		"groups":         []any{map[string]any{"name": "team-test", "membership": map[string]any{"authoritative": false}}},
	}}
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skip("ansible-playbook not installed")
	}
	body, err := yaml.Marshal([]any{map[string]any{"hosts": "localhost", "connection": "local", "gather_facts": false, "vars": vars, "tasks": tasks}})
	if err != nil {
		t.Fatal(err)
	}
	pb := filepath.Join(t.TempDir(), "normalize.yml")
	if err := os.WriteFile(pb, body, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ansible-playbook", "-i", "localhost,", pb)
	cmd.Env = append(os.Environ(), "ANSIBLE_STDOUT_CALLBACK=default", "ANSIBLE_NOCOLOR=1")
	output, err := cmd.CombinedOutput()
	if strings.Contains(string(output), "PASSWORD_SENTINEL") {
		t.Fatal("normalization output leaked a password")
	}
	if err != nil {
		t.Fatalf("shared normalization failed: %v\n%s", err, output)
	}
}
