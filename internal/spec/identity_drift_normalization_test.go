package spec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// requireAnsibleForIdentityDrift fails instead of skipping when the required
// Ansible job (`make identity-secret-test`, PILOT_REQUIRE_CONTAINER_TESTS=1)
// has no ansible-playbook: a skipped normalization test proves nothing.
func requireAnsibleForIdentityDrift(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
			t.Fatalf("required ansible-playbook not installed: %v", err)
		}
		t.Skip("ansible-playbook not installed")
	}
}

// normalizationRun runs the shared users/groups normalization twice under real
// ansible-playbook (the plan cannot retain objects from an earlier include) and
// then the given assertions. vars are extra play vars.
func normalizationRun(t *testing.T, users []any, vars map[string]any, asserts []string) (string, error) {
	t.Helper()
	path, err := filepath.Abs("../../playbooks/apply/tasks/freeipa-identity-normalize-users-groups.yml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	include := map[string]any{"name": "shared normalization", "ansible.builtin.include_tasks": path}
	tasks := []any{include, include, map[string]any{
		"name": "assert the normalized objects", "no_log": true,
		"ansible.builtin.assert": map[string]any{"that": asserts},
	}}
	play := map[string]any{"freeipa_roster": map[string]any{
		"schema_version": 3,
		"grants":         []any{},
		"users":          users,
		"groups":         []any{map[string]any{"name": "team-test", "membership": map[string]any{"authoritative": false}}},
	}}
	for k, v := range vars {
		play[k] = v
	}
	body, err := yaml.Marshal([]any{map[string]any{"hosts": "localhost", "connection": "local", "gather_facts": false, "vars": play, "tasks": tasks}})
	if err != nil {
		t.Fatal(err)
	}
	pb := filepath.Join(t.TempDir(), "normalize.yml")
	if err := os.WriteFile(pb, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ansible-playbook", "-i", "localhost,", pb)
	cmd.Env = append(os.Environ(), "ANSIBLE_STDOUT_CALLBACK=default", "ANSIBLE_NOCOLOR=1")
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// TestIdentityDriftSharedNormalizationInAnsible: apply and the drift observer
// load one normalization. Unset, it produces exactly what apply always got
// (credential fields included); with pilot_identity_normalize_credentials false
// (the drift probe) it produces no credential field and never evaluates the
// password template, so a template that only renders under apply's vars cannot
// fail a read-only comparison and no password can reach the observer.
func TestIdentityDriftSharedNormalizationInAnsible(t *testing.T) {
	requireAnsibleForIdentityDrift(t)
	users := func(initial any) []any {
		return []any{
			map[string]any{"name": "alice", "password": map[string]any{"initial": initial}},
			map[string]any{"name": "bob", "state": "disabled", "ssh_keys": map[string]any{"values": []any{}}},
		}
	}
	// What apply has always produced for these roster users (the task was moved
	// unchanged out of freeipa-identity-apply.yml; this is its oracle).
	common := []string{
		"ipa_users | length == 2", "ipa_groups | length == 1",
		"ipa_users[0].name == 'alice'", "ipa_users[0].state == 'present'",
		"ipa_users[0].first == 'alice'", "ipa_users[0].last == 'alice'",
		"ipa_users[0].login_shell == '/bin/bash'", "ipa_users[0].home_directory == '/home/alice'",
		"ipa_users[0].ssh_keys is none", "ipa_users[0].enabled",
		"ipa_users[1].ssh_keys == []", "not ipa_users[1].enabled", "ipa_users[1].state == 'disabled'",
		"ipa_groups[0].desc == 'team-test'", "ipa_groups[0].membership.authoritative == false",
	}
	const sentinel = "PASSWORD_SENTINEL"

	t.Run("unset (apply): credential fields are produced exactly as before", func(t *testing.T) {
		out, err := normalizationRun(t, users(sentinel), nil, append(append([]string{}, common...),
			"ipa_users[0].password == 'PASSWORD_SENTINEL'", "ipa_users[0].force_password == false",
			"ipa_users[0].preserve_existing == true",
			"ipa_users[1].password is none", "ipa_users[1].force_password == false", "ipa_users[1].preserve_existing == true",
			// Same key order as the original task wrote it: ssh_keys last.
			"(ipa_users[0].keys() | list) == ['name', 'state', 'first', 'last', 'display_name', 'email', 'uid', 'gid', 'login_shell', 'home_directory', 'enabled', 'password', 'force_password', 'preserve_existing', 'ssh_keys']"))
		if err != nil {
			t.Fatalf("shared normalization failed: %v\n%s", err, out)
		}
		if strings.Contains(out, sentinel) {
			t.Fatal("normalization output leaked a password")
		}
	})

	t.Run("false (drift probe): no credential field, template never evaluated", func(t *testing.T) {
		// This initial password is a template over a variable the probe never has.
		out, err := normalizationRun(t, users("{{ pilot_variable_only_apply_has }}"),
			map[string]any{"pilot_identity_normalize_credentials": false},
			append(append([]string{}, common...),
				"'password' not in ipa_users[0]", "'force_password' not in ipa_users[0]", "'preserve_existing' not in ipa_users[0]",
				"'password' not in ipa_users[1]",
				"(ipa_users[0].keys() | list) == ['name', 'state', 'first', 'last', 'display_name', 'email', 'uid', 'gid', 'login_shell', 'home_directory', 'enabled', 'ssh_keys']"))
		if err != nil {
			t.Fatalf("normalization without credentials failed: %v\n%s", err, out)
		}
	})

	t.Run("false: a literal password never survives into the facts", func(t *testing.T) {
		out, err := normalizationRun(t, users(sentinel), map[string]any{"pilot_identity_normalize_credentials": false},
			append(append([]string{}, common...), "(ipa_users | to_json) is not search('PASSWORD_SENTINEL')"))
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if strings.Contains(out, sentinel) {
			t.Fatal("normalization output leaked a password")
		}
	})

	// Counter-example: with the flag unset the same undefined template does fail,
	// so the passing case above is the flag's doing, not a lenient template.
	t.Run("unset: the same undefined template fails closed (the control)", func(t *testing.T) {
		out, err := normalizationRun(t, users("{{ pilot_variable_only_apply_has }}"), nil, common)
		if err == nil {
			t.Fatalf("an undefined password template must fail the apply-side normalization:\n%s", out)
		}
		if strings.Contains(out, "pilot_variable_only_apply_has") && !strings.Contains(out, "FAILED") {
			t.Fatalf("unexpected output:\n%s", out)
		}
	})
}
