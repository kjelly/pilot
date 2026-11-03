package spec

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const retirementPreflight = "Validate durable SSH cache scope before managed mutations"

func TestRegression_IdentityRetirementPreflightBeforeMutations(t *testing.T) {
	raw, err := os.ReadFile(sshKeysPlaybook)
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	block := plays[0]["tasks"].([]any)[0].(map[string]any)["block"].([]any)
	seen := false
	for _, value := range block {
		task := value.(map[string]any)
		if task["name"] == retirementPreflight {
			seen = true
			if !slices.Contains(task["tags"].([]any), any("always")) {
				t.Fatal("scope guard must survive mutating row/component selections and skip-tags")
			}
		}
		if _, mutation := task["ansible.builtin.command"]; mutation {
			name := fmt.Sprint(task["name"])
			if strings.HasPrefix(name, "Ensure IPA groups") || strings.HasPrefix(name, "Prepare legacy authorization") || strings.HasPrefix(name, "Reconcile user") || strings.HasPrefix(name, "Set SSH public keys") {
				if !seen {
					t.Fatalf("%s precedes durable target guard", name)
				}
			}
		}
	}
	if !seen {
		t.Fatal("production scope guard missing")
	}
}

func TestRegression_IdentityRetirementPreflightRuntime(t *testing.T) {
	helper, err := os.ReadFile("../../playbooks/apply/files/freeipa-ssh-key-cache.py")
	if err != nil {
		t.Fatal(err)
	}
	production := identityTasks(t, []string{retirementPreflight})
	if len(production) != 1 {
		t.Fatal("production scope guard missing")
	}
	include := production[0].(map[string]any)["ansible.builtin.include_tasks"].(map[string]any)
	include["file"], err = filepath.Abs("../../playbooks/apply/tasks/freeipa-ssh-cache-preflight.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"missing", "cross-stage", "authorized retirement", "deferred still pending", "read-only"} {
		selectors := []string{"all", "tagged", "identity", "users", "passwords", "sshkeys", "groups", "hosts", "C9", "C13", "identity-skip-users"}
		if scenario != "missing" && scenario != "cross-stage" {
			selectors = []string{"all"}
		}
		if scenario == "authorized retirement" {
			selectors = []string{"all", "users", "identity-skip-hosts"}
		}
		for _, selector := range selectors {
			t.Run(scenario+"/"+selector, func(t *testing.T) {
				dir := t.TempDir()
				journal := filepath.Join(dir, "journal.json")
				initial := `{"version":1,"domain":"ipa.test","auth_pending":false,"users":{"omitted":{"keys":[],"epoch":"unchanged","hosts":["old"],"pending":["old"]}}}`
				if err := os.WriteFile(journal, []byte(initial), 0o600); err != nil {
					t.Fatal(err)
				}
				var roster = map[string]any{"hosts": []any{}}
				vars := map[string]any{"stage": "sandbox", "ipa_domain": "ipa.test",
					"ipa_ssh_cache_program": string(helper), "ipa_identity_ssh_cache_state_file": journal,
					"ipa_identity_cache_recovery_tags": []string{"identity", "users", "passwords", "groups", "hosts", "C9", "C13"},
					"freeipa_roster":                   roster}
				tasks := []any{}
				if scenario == "cross-stage" {
					tasks = append(tasks, map[string]any{"name": "cross-stage pending target", "tags": []string{"always"},
						"ansible.builtin.add_host": map[string]any{"name": "old", "groups": "prod"}})
				}
				if scenario == "authorized retirement" {
					roster["hosts"] = []any{map[string]any{"name": "retired.ipa.test", "state": "absent"}}
					vars["ipa_identity_ssh_cache_retirements"] = []any{map[string]any{"alias": "old", "fqdn": "retired.ipa.test",
						"stage": "sandbox", "reason": "approved", "origin": "test-plan"}}
				}
				if scenario == "deferred still pending" {
					vars["pilot_deferred_hosts"] = []string{"old"}
				}
				tasks = append(tasks, production...)
				marker := filepath.Join(dir, "mutation")
				// The file is an external side-effect oracle, independent of Ansible
				// task/result reporting and the journal's own desired state.
				tasks = append(tasks, map[string]any{"name": "managed mutation sentinel", "tags": []string{"always"},
					"ansible.builtin.command": map[string]any{"argv": []string{"touch", marker}}})
				args := []string{"--tags", selector}
				if selector == "identity-skip-users" {
					args = []string{"--tags", "identity", "--skip-tags", "users"}
				}
				if selector == "identity-skip-hosts" {
					args = []string{"--tags", "identity", "--skip-tags", "hosts"}
				}
				if scenario == "read-only" {
					args = []string{"--tags", "freeipa_host_absent_inspect"}
					// Read-only callers have no managed mutation; do not select the sentinel.
					tasks = tasks[:len(tasks)-1]
				}
				result := runGatewayTasks(t, dir, tasks, vars, nil, args...)
				retirementSelected := scenario == "authorized retirement" && selector == "all"
				allowed := retirementSelected || scenario == "read-only"
				_, markerErr := os.Stat(marker)
				if (markerErr == nil) != retirementSelected {
					t.Fatalf("mutation side effect despite pending scope refusal: %v", markerErr)
				}
				if (result.rc == 0) != allowed {
					t.Fatalf("rc=%d failures=%v stderr=%s\n%s", result.rc, result.failures, result.stderr, result.raw)
				}
				if !allowed && !strings.Contains(fmt.Sprint(result.failures), "SSH cache target") {
					t.Fatalf("wrong refusal reason: %v\n%s", result.failures, result.raw)
				}
				got, err := os.ReadFile(journal)
				if err != nil || string(got) != initial {
					t.Fatalf("read-only preflight changed journal: %v %s", err, got)
				}
				if _, err := os.Stat(journal + ".lock"); !os.IsNotExist(err) {
					t.Fatalf("read-only preflight created lock: %v", err)
				}
			})
		}
	}
}

// Run the real production preflight include with Ansible's actual tag selection.
// The sentinel proves refusal precedes any managed mutation; journal bytes (or
// absence) are a separate oracle. Native FreeIPA/SSSD behavior is a VM gate.
func TestRegression_IdentityRetirementCleanupSelection(t *testing.T) {
	helper, err := os.ReadFile("../../playbooks/apply/files/freeipa-ssh-key-cache.py")
	if err != nil {
		t.Fatal(err)
	}
	production := identityTasks(t, []string{retirementPreflight})
	include := production[0].(map[string]any)["ansible.builtin.include_tasks"].(map[string]any)
	include["file"], err = filepath.Abs("../../playbooks/apply/tasks/freeipa-ssh-cache-preflight.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"no-journal", "converged", "old-pending", "settled", "receipt-pending"} {
		for _, selector := range []string{"all", "tagged", "identity", "hosts", "users", "sshkeys", "client-cache", "identity-skip-hosts", "identity-skip-identity"} {
			t.Run(state+"/"+selector, func(t *testing.T) {
				dir := t.TempDir()
				journal := filepath.Join(dir, "journal.json")
				pending := []string{}
				if state == "old-pending" || state == "receipt-pending" {
					pending = []string{"old"}
				}
				data := map[string]any{"version": 1, "domain": "ipa.test", "auth_pending": false,
					"users": map[string]any{"omitted": map[string]any{"keys": []string{}, "epoch": "unchanged", "hosts": []string{"old"}, "pending": pending}}}
				if state == "settled" || state == "receipt-pending" {
					data["retired"] = map[string]any{"old": map[string]any{"alias": "old", "fqdn": "retired.ipa.test", "stage": "sandbox",
						"reason": "approved", "origin": "test-plan", "result": "retired", "discharged": 1, "recorded_at": 1}}
					// An actual writer creates this sidecar. Completed receipt
					// exemptions must confirm durability through that same lock.
					if err := os.WriteFile(journal+".lock", nil, 0600); err != nil {
						t.Fatal(err)
					}
				}
				initial, err := json.Marshal(data)
				if err != nil {
					t.Fatal(err)
				}
				if state != "no-journal" {
					if err := os.WriteFile(journal, initial, 0600); err != nil {
						t.Fatal(err)
					}
				}
				vars := map[string]any{"stage": "sandbox", "ipa_domain": "ipa.test", "ipa_ssh_cache_program": string(helper),
					"ipa_identity_ssh_cache_state_file": journal,
					"ipa_identity_cache_recovery_tags":  []string{"identity", "users", "passwords", "groups", "hosts", "client-cache", "C9", "C13"},
					"freeipa_roster":                    map[string]any{"hosts": []any{map[string]any{"name": "retired.ipa.test", "state": "absent"}}}}
				tasks := []any{map[string]any{"name": "enrolled retiring client", "tags": []string{"always"},
					"ansible.builtin.add_host": map[string]any{"name": "old", "groups": "freeipa-client", "ipa_client_fqdn": "retired.ipa.test"}}}
				tasks = append(tasks, production...)
				marker := filepath.Join(dir, "mutation")
				tasks = append(tasks, map[string]any{"name": "managed mutation sentinel", "tags": []string{"always"},
					"ansible.builtin.command": map[string]any{"argv": []string{"touch", marker}}})
				args := []string{"--tags", selector}
				if strings.HasPrefix(selector, "identity-skip-") {
					args = []string{"--tags", "identity", "--skip-tags", strings.TrimPrefix(selector, "identity-skip-")}
				}
				result := runGatewayTasks(t, dir, tasks, vars, nil, args...)
				allowed := state == "settled" || slices.Contains([]string{"all", "tagged", "identity", "hosts"}, selector)
				_, markerErr := os.Stat(marker)
				if (markerErr == nil) != allowed {
					t.Fatalf("retirement cleanup mutation sentinel: allowed=%v stat=%v rc=%d failures=%v", allowed, markerErr, result.rc, result.failures)
				}
				if (result.rc == 0) != allowed {
					t.Fatalf("allowed=%v rc=%d failures=%v\n%s", allowed, result.rc, result.failures, result.raw)
				}
				if !allowed && !strings.Contains(fmt.Sprint(result.failures), "Unfinished SSH cache target retirement requires") {
					t.Fatalf("wrong refusal: %v", result.failures)
				}
				got, err := os.ReadFile(journal)
				if state == "no-journal" {
					if !os.IsNotExist(err) {
						t.Fatalf("preflight created journal: %v", err)
					}
				} else if err != nil || string(got) != string(initial) {
					t.Fatalf("preflight changed journal: %v %s", err, got)
				}
				if state != "settled" && state != "receipt-pending" {
					if _, err := os.Stat(journal + ".lock"); !os.IsNotExist(err) {
						t.Fatalf("preflight created lock: %v", err)
					}
				}
			})
		}
	}
}

func TestRegression_IdentityRetirementRepeatedPreflightResetsAuthorization(t *testing.T) {
	dir := t.TempDir()
	helper, err := os.ReadFile("../../playbooks/apply/files/freeipa-ssh-key-cache.py")
	if err != nil {
		t.Fatal(err)
	}
	production := identityTasks(t, []string{retirementPreflight})
	include := production[0].(map[string]any)["ansible.builtin.include_tasks"].(map[string]any)
	include["file"], err = filepath.Abs("../../playbooks/apply/tasks/freeipa-ssh-cache-preflight.yml")
	if err != nil {
		t.Fatal(err)
	}
	settled := filepath.Join(dir, "settled.json")
	unfinished := filepath.Join(dir, "unfinished.json")
	completed := `{"version":1,"domain":"ipa.test","users":{},"retired":{"old":{"alias":"old","fqdn":"retired.ipa.test","stage":"sandbox","reason":"approved","origin":"test-plan"}}}`
	fresh := `{"version":1,"domain":"ipa.test","users":{}}`
	for path, body := range map[string]string{settled: completed, unfinished: fresh, settled + ".lock": ""} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	vars := map[string]any{"stage": "sandbox", "ipa_domain": "ipa.test", "ipa_ssh_cache_program": string(helper),
		"ipa_identity_ssh_cache_state_file": settled, "ipa_identity_cache_recovery_tags": []string{"identity", "users"},
		"freeipa_roster":                     map[string]any{"hosts": []any{map[string]any{"name": "retired.ipa.test", "state": "absent"}}},
		"ipa_identity_ssh_cache_retirements": []any{map[string]any{"alias": "old", "fqdn": "retired.ipa.test", "stage": "sandbox", "reason": "approved", "origin": "test-plan"}}}
	tasks := append([]any{}, production...)
	tasks = append(tasks, map[string]any{"name": "next imported identity scope", "tags": []string{"always"},
		"ansible.builtin.set_fact": map[string]any{"ipa_identity_ssh_cache_state_file": unfinished}})
	tasks = append(tasks, production...)
	marker := filepath.Join(dir, "mutation")
	tasks = append(tasks, map[string]any{"name": "managed mutation sentinel", "tags": []string{"always"},
		"ansible.builtin.command": map[string]any{"argv": []string{"touch", marker}}})
	result := runGatewayTasks(t, dir, tasks, vars, nil, "--tags", "users")
	if result.rc == 0 || !strings.Contains(fmt.Sprint(result.failures), "Unfinished SSH cache target retirement requires") {
		t.Fatalf("stale completed receipt authorized a later scope: rc=%d failures=%v\n%s", result.rc, result.failures, result.raw)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("mutation sentinel reached: %v", err)
	}
	for path, body := range map[string]string{settled: completed, unfinished: fresh} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != body {
			t.Fatalf("journal changed: %s %v", got, err)
		}
	}
}

func TestRegression_IdentityRetirementRefreshAndFinalReadback(t *testing.T) {
	tasks := identityTasks(t, []string{"Resolve enrolled SSH key cache targets", sudoRefreshResolve,
		"Read current SSH obligations after propagation and retirement", "Gate: every SSH key cache pair converged"})
	if len(tasks) != 4 {
		t.Fatalf("expected production selectors and final readback, got %d", len(tasks))
	}
	dir := t.TempDir()
	helper, err := os.ReadFile("../../playbooks/apply/files/freeipa-ssh-key-cache.py")
	if err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(dir, "journal.json")
	for _, pending := range []bool{false, true} {
		pairs := []string{}
		if pending {
			pairs = []string{"live"}
		}
		state := map[string]any{"version": 1, "domain": "ipa.test", "users": map[string]any{
			"alice": map[string]any{"epoch": "e", "keys": []string{}, "hosts": []string{"live"}, "pending": pairs}}}
		raw, _ := json.Marshal(state)
		if err := os.WriteFile(journal, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		vars := map[string]any{"ipa_domain": "ipa.test", "ipa_ssh_cache_program": string(helper),
			"ipa_identity_ssh_cache_state_file": journal, "ipa_identity_refresh_sssd_cache": true,
			"ipa_ssh_cache_retiring_aliases": []string{"old"}, "pilot_deferred_hosts": []string{},
			// A previous receipt must not hide newly pending work.
			"ipa_ssh_cache_ack": map[string]any{"stdout": `{"pending":[]}`}}
		inventory := []any{}
		for _, host := range []string{"old", "live"} {
			inventory = append(inventory, map[string]any{"name": "inventory " + host,
				"ansible.builtin.add_host": map[string]any{"name": host, "groups": "freeipa-client"}})
		}
		inventory = append(inventory, tasks...)
		inventory = append(inventory, map[string]any{"name": "selector external oracle", "ansible.builtin.assert": map[string]any{"that": []string{
			"'old' not in ipa_ssh_cache_hosts", "'live' in ipa_ssh_cache_hosts", "ipa_sudo_refresh_clients == ['live']"}}})
		result := runGatewayTasks(t, dir, inventory, vars, nil)
		if (result.rc != 0) != pending {
			t.Fatalf("pending=%v rc=%d failures=%v\n%s", pending, result.rc, result.failures, result.raw)
		}
		if pending && !strings.Contains(fmt.Sprint(result.failures), "Gate: every SSH key cache pair converged") {
			t.Fatalf("wrong final refusal: %v", result.failures)
		}
	}
}
