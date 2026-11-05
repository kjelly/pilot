package spec

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Exercise the introduced wrapper's actual import/reset order in one real
// Ansible process. Only normalization and its original exclusivity gate are
// extracted: native service lifecycle remains the separate target gate.
func TestRegression_IdentityRetirementFixtureReentry(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Fatal(err)
	}
	fixtureDir, err := filepath.Abs("../../playbooks/test/fixtures")
	if err != nil {
		t.Fatal(err)
	}
	read := func(path string, value any) {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := yaml.Unmarshal(raw, value); err != nil {
			t.Fatal(err)
		}
	}
	var wrapper, apply []map[string]any
	read(filepath.Join(fixtureDir, "freeipa-ssh-retirement-fixtures.yml"), &wrapper)
	read(sshKeysPlaybook, &apply)
	names := []string{"Load canonical roster under a namespace", "Detect FreeIPA server FQDN when roster omits freeipa.server", "Fill canonical roster freeipa.server for this reconcile", "Gate: canonical roster version and legacy fields are mutually exclusive",
		"Normalize canonical FreeIPA settings", "Normalize canonical users and groups (shared with drift)",
		"Normalize canonical hostgroups for the compatibility reconciler", "Normalize canonical netgroups for the compatibility reconciler",
		"Normalize canonical HBAC rules for the compatibility reconciler", "Normalize absent static HBAC rules for deletion (spec 2026-09-07 §6.1)",
		"Normalize canonical sudo rules for the compatibility reconciler", "Append v3.0 compiled grant HBAC rules (spec.md §9)",
		"Append v3.0 compiled grant sudo rules (spec.md §10)", "Select legacy admin settings", "Select active identity objects"}
	pre := []any{}
	for _, value := range apply[0]["pre_tasks"].([]any) {
		task := value.(map[string]any)
		if slices.Contains(names, fmt.Sprint(task["name"])) {
			if include, ok := task["ansible.builtin.include_tasks"].(map[string]any); ok {
				include["file"], err = filepath.Abs("../../playbooks/apply/" + include["file"].(string))
				if err != nil {
					t.Fatal(err)
				}
			}
			pre = append(pre, task)
		}
	}
	if len(pre) != len(names) {
		t.Fatalf("found %d normalization tasks, want %d", len(pre), len(names))
	}
	dir := t.TempDir()
	custom := filepath.Join(dir, "custom.yaml")
	if err := os.WriteFile(custom, []byte("schema_version: 3\nfreeipa: {server: ipa1.ipa.pilot.internal, admin: {principal: admin}}\nusers: [{name: lifecycle-only, first: Life, last: Cycle}]\ngroups: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	removals := []string{"canonical_group_removals", "ipa_group_membership_removals", "ipa_hostgroup_membership_removals",
		"ipa_netgroup_membership_removals", "ipa_hbac_removals", "ipa_sudo_removals"}
	var harness []map[string]any
	stages, resets := 0, 0
	for _, entry := range wrapper {
		path, imported := entry["ansible.builtin.import_playbook"].(string)
		if !imported {
			entry["hosts"] = "localhost"
			harness = append(harness, entry)
			continue
		}
		if path == "freeipa-identity-fixture-reset.yml" {
			harness = append(harness, map[string]any{"ansible.builtin.import_playbook": filepath.Join(fixtureDir, path),
				"vars": map[string]any{"fixtures_target_group": "localhost"}})
			resets++
			continue
		}
		vars := map[string]any{}
		for key, value := range apply[0]["vars"].(map[string]any) {
			vars[key] = value
		}
		vars["ipa_admin_password"] = "synthetic-fixture-only"
		vars["issue226_server_fqdn"] = "ipa1.ipa.pilot.internal"
		var expectedUsers []string
		expectedSchema := 0
		if path == "freeipa-identity-fixtures.yml" {
			var fixture []map[string]any
			read(filepath.Join(fixtureDir, path), &fixture)
			for key, value := range fixture[0]["vars"].(map[string]any) {
				vars[key] = value
			}
			vars["freeipa_roster_file"] = nil
			for _, value := range vars["ipa_users"].([]any) {
				expectedUsers = append(expectedUsers, value.(map[string]any)["name"].(string))
			}
		} else {
			roster := custom
			if strings.Contains(path, "canonical") {
				roster = filepath.Join(fixtureDir, "freeipa-identity-canonical.roster.yaml")
			} else if strings.Contains(fmt.Sprint(entry["vars"]), "freeipa-ssh-retirement-v2.roster.yaml") {
				roster = filepath.Join(fixtureDir, "freeipa-ssh-retirement-v2.roster.yaml")
				var original, isolated map[string]any
				read(filepath.Join(fixtureDir, "freeipa-identity-v2.roster.yaml"), &original)
				read(roster, &isolated)
				delete(isolated["freeipa"].(map[string]any), "server")
				if !reflect.DeepEqual(original, isolated) {
					t.Fatal("isolated v2 fixture drifted from the existing verification fixture objects")
				}
			}
			vars["freeipa_roster_file"] = roster
			var desired map[string]any
			read(roster, &desired)
			expectedSchema = desired["schema_version"].(int)
			for _, value := range desired["users"].([]any) {
				expectedUsers = append(expectedUsers, value.(map[string]any)["name"].(string))
			}
		}
		vars["expected_users"] = expectedUsers
		vars["expected_schema"] = expectedSchema
		checks := []string{"ipa_users | map(attribute='name') | list == expected_users", "freeipa_roster.schema_version | default(0) == expected_schema"}
		seed := map[string]any{}
		for _, name := range removals {
			checks = append(checks, name+" | default([]) | length == 0")
			seed[name] = []string{"previous-roster-removal-must-not-leak"}
		}
		harness = append(harness, map[string]any{"name": fmt.Sprintf("fixture stage %d", stages), "hosts": "localhost",
			"connection": "local", "gather_facts": false, "vars": vars, "pre_tasks": pre,
			"tasks": []any{map[string]any{"name": "effective normalized fixture state", "ansible.builtin.assert": map[string]any{"that": checks}},
				map[string]any{"name": "prior apply removal accumulator fixture", "ansible.builtin.set_fact": seed}}})
		stages++
	}
	if stages != 4 || resets != 3 {
		t.Fatalf("wrapper has %d stages and %d resets, want 4/3", stages, resets)
	}
	body, err := yaml.Marshal(harness)
	if err != nil {
		t.Fatal(err)
	}
	playbook := filepath.Join(dir, "reentry.yml")
	if err := os.WriteFile(playbook, body, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"apply", "check"} {
		args := []string{"-i", "localhost,", playbook}
		if mode == "check" {
			args = append(args, "--check", "--diff")
		}
		command := exec.Command("ansible-playbook", args...)
		command.Env = append(os.Environ(), "ANSIBLE_STDOUT_CALLBACK=default", "ANSIBLE_NOCOLOR=1")
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("four-play fixture %s: %v\n%s", mode, err, out)
		}
	}
	partial := exec.Command("ansible-playbook", "-i", "localhost,", playbook, "--tags", "identity")
	partial.Env = append(os.Environ(), "ANSIBLE_STDOUT_CALLBACK=default", "ANSIBLE_NOCOLOR=1")
	if out, err := partial.CombinedOutput(); err == nil || !strings.Contains(string(out), "SSH retirement fixtures require a standalone full run") {
		t.Fatalf("partial fixture selection did not fail at its scope gate: %v\n%s", err, out)
	}
}
