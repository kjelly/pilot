package spec

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestRegression_IdentitySSHCacheJournal(t *testing.T) {
	cmd := exec.Command("python3", "../../scripts/test-freeipa-ssh-key-cache.py")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("journal: %v\n%s", err, out)
	}
}

func TestRegression_IdentitySSHCacheStageScope(t *testing.T) {
	raw, err := os.ReadFile(sshKeysPlaybook)
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	var production []any
	for _, value := range plays[0]["tasks"].([]any) {
		block := value.(map[string]any)
		for _, inner := range block["block"].([]any) {
			task := inner.(map[string]any)
			switch task["name"] {
			case "Resolve enrolled SSH key cache targets", "Gate: SSH cache targets must match the authorized stage",
				"Gate: pending SSH cache targets exist in this inventory", "Gate: pending SSH cache targets match the authorized stage":
				production = append(production, task)
			}
		}
	}
	if len(production) != 4 {
		t.Fatal("production stage-scope tasks not found")
	}
	for _, scenario := range []string{"current enrollment", "undefined plan", "retained cross-stage work", "retained missing target"} {
		for _, tag := range []string{"all", "identity", "sshkeys", "client-cache", "users", "hbac", "freeipa_host_absent_inspect"} {
			t.Run(scenario+"/"+tag, func(t *testing.T) {
				groups := []string{"prod"}
				if scenario == "current enrollment" {
					groups = append(groups, "freeipa-client")
				}
				tasks := []any{map[string]any{
					"name": "cross-stage inventory fixture", "tags": []string{"always"},
					"ansible.builtin.add_host": map[string]any{"name": "client-prod", "groups": groups},
				}}
				tasks = append(tasks, production...)
				// Empty current users cannot suppress durable work for omitted users.
				vars := map[string]any{"stage": "sandbox", "ipa_active_users": []any{}}
				if scenario == "retained cross-stage work" || scenario == "retained missing target" {
					host := "client-prod"
					if scenario == "retained missing target" {
						host = "client-missing"
					}
					vars["ipa_ssh_cache_plan"] = map[string]any{"stdout": fmt.Sprintf(`{"work":[{"host":%q,"user":"omitted-user"}]}`, host)}
				}
				res := runGatewayTasks(t, t.TempDir(), tasks, vars, nil, "--tags", tag)
				mutation := tag != "hbac" && tag != "freeipa_host_absent_inspect"
				mustFail := mutation && scenario != "undefined plan"
				if (res.rc != 0) != mustFail {
					t.Fatalf("tag=%s rc=%d failures=%v\n%s", tag, res.rc, res.failures, res.raw)
				}
				if mustFail && scenario != "current enrollment" && !strings.Contains(fmt.Sprint(res.failures), "Gate: pending SSH cache targets") {
					t.Fatalf("retained work failed outside its actual-plan authorization gate: %v", res.failures)
				}
			})
		}
	}
}

// Keep the legacy non-key refresh predicate complete, without letting SSH-only
// changes or journal writes cause a fleet-wide cache flush.
func TestRegression_IdentitySSHCacheNonKeyMutationCoverage(t *testing.T) {
	raw, err := os.ReadFile(sshKeysPlaybook)
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	var want []string
	var walk func([]any)
	walk = func(tasks []any) {
		for _, v := range tasks {
			task := v.(map[string]any)
			if reg, ok := task["register"].(string); ok && reg != "ipa_sshkey" {
				if changed, exists := task["changed_when"]; exists && changed != false {
					want = append(want, reg)
				}
			}
			for _, section := range []string{"block", "rescue"} {
				if inner, ok := task[section].([]any); ok {
					walk(inner)
				}
			}
		}
	}
	walk(plays[0]["tasks"].([]any))
	var got []string
	for _, v := range plays[0]["vars"].(map[string]any)["ipa_identity_cache_mutation_registers"].([]any) {
		got = append(got, v.(string))
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("non-key mutation registers = %v; want %v", got, want)
	}
}

// Runs the production prepare → IPA → settle → delegate → ack → failure gate
// tasks with named localhost aliases. Only the IPA/SSSD processes are fakes;
// journal persistence, Ansible loops, tags, delegation and failure gates are real.
func TestRegression_IdentitySSHCacheRuntime(t *testing.T) {
	dir := t.TempDir()
	helper, err := os.ReadFile("../../playbooks/apply/files/freeipa-ssh-key-cache.py")
	if err != nil {
		t.Fatal(err)
	}
	keyfile := filepath.Join(dir, "key")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", keyfile).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	pub, err := os.ReadFile(keyfile + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	key := strings.TrimSpace(string(pub))
	for _, sub := range []string{"source", "cache"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name, value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("source/alice", key+"\n")
	write("source/bob", "")
	write("modified", "yes")
	write("ipa", `#!/usr/bin/env python3
import os,sys
from pathlib import Path
d=Path(os.environ['CACHE_TEST_DIR'])
if d.joinpath('modified').read_text() == 'yes':
 print(d.joinpath('modified.stdout').read_text(), end='')
 sys.exit(0)
print(d.joinpath('noop.stderr').read_text(), end='', file=sys.stderr)
sys.exit(1)
`)
	for name, fixture := range map[string]string{"modified.stdout": "user-mod-modified.stdout", "noop.stderr": "user-mod-no-modifications.stderr"} {
		content, err := os.ReadFile(filepath.Join(sshKeysFixtures, fixture))
		if err != nil {
			t.Fatal(err)
		}
		write(name, string(content))
	}
	write("sss_cache", `#!/usr/bin/env python3
import os,sys
from pathlib import Path
d=Path(os.environ['CACHE_TEST_DIR']); host=os.environ['CACHE_TEST_HOST']; user=sys.argv[-1]
if user == '-E':
 with d.joinpath('calls').open('a') as f: f.write(host+'/*\n')
 sys.exit(9 if d.joinpath('fail-global-'+host).exists() else 0)
with d.joinpath('calls').open('a') as f: f.write(host+'/'+user+'\n')
if d.joinpath('fail-'+host).exists(): sys.exit(9)
d.joinpath('cache',host+'-'+user).write_text(d.joinpath('source',user).read_text())
`)
	write("sss_ssh_authorizedkeys", `#!/usr/bin/env python3
import os,sys
from pathlib import Path
d=Path(os.environ['CACHE_TEST_DIR']); host=os.environ['CACHE_TEST_HOST']; user=sys.argv[-1]
if d.joinpath('lookup-fail-'+host).exists(): sys.exit(1)
print(d.joinpath('cache',host+'-'+user).read_text(), end='')
`)
	for _, binary := range []string{"ipa", "sss_cache", "sss_ssh_authorizedkeys"} {
		if err := os.Chmod(filepath.Join(dir, binary), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CACHE_TEST_DIR", dir)
	raw, err := os.ReadFile(sshKeysPlaybook)
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	// Delegation resolves connection settings from host variables. Declare
	// the provider explicitly instead of relying only on play connection=local.
	tasks := []any{map[string]any{"name": "test inventory provider", "tags": []string{"always"},
		"ansible.builtin.add_host": map[string]any{"name": "localhost", "ansible_connection": "local", "ansible_host": "127.0.0.1", "ansible_port": 22}}}
	for _, host := range []string{"client-a", "client-b"} {
		connection := "local"
		address := "127.0.0.3"
		if host == "client-b" {
			connection = "{{ 'ssh' if cache_test_unreachable | default(false) else 'local' }}"
			address = "127.0.0.2"
		}
		// Keep the deliberately unreachable SSH alias distinct from implicit
		// localhost/127.0.0.1. Otherwise Ansible can reuse its connection state
		// for the provider and the failure fixture also breaks localhost.
		tasks = append(tasks, map[string]any{"name": "test inventory " + host, "tags": []string{"always"},
			"ansible.builtin.add_host": map[string]any{"name": host, "groups": "freeipa-client", "ansible_connection": connection, "ansible_host": address, "ansible_port": 1}})
	}
	tasks = append(tasks, map[string]any{"name": "historical inventory alias", "tags": []string{"always"},
		"ansible.builtin.add_host": map[string]any{"name": "old-client", "groups": "{{ cache_test_old_groups | default('sandbox') }}", "ansible_connection": "local"}})
	var collect func([]any)
	collect = func(all []any) {
		for _, value := range all {
			task := value.(map[string]any)
			name, _ := task["name"].(string)
			tags, _ := task["tags"].([]any)
			if slices.Contains(tags, any("sshkeys")) || strings.Contains(name, "legacy authorization cache recovery") || name == "Refresh SSSD caches on enrolled FreeIPA clients" {
				delete(task, "become") // test runs unprivileged; production uses root
				if strings.HasPrefix(name, "Invalidate and verify") {
					task["environment"] = map[string]any{"CACHE_TEST_HOST": "{{ item.host }}", "CACHE_TEST_DIR": dir}
				}
				if name == "Refresh SSSD caches on enrolled FreeIPA clients" {
					task["environment"] = map[string]any{"CACHE_TEST_HOST": "{{ item }}", "CACHE_TEST_DIR": dir}
				}
				tasks = append(tasks, task)
			}
			if inner, ok := task["block"].([]any); ok {
				collect(inner)
			}
		}
	}
	collect(plays[0]["tasks"].([]any))
	vars := map[string]any{"ipa_domain": "ipa.test", "stage": "sandbox", "ipa_ssh_cache_program": string(helper),
		"ipa_identity_ssh_cache_state_file":     filepath.Join(dir, "journal.json"),
		"ipa_identity_refresh_sssd_cache":       true,
		"ipa_identity_cache_mutation_registers": plays[0]["vars"].(map[string]any)["ipa_identity_cache_mutation_registers"]}
	run := func(keys []any, deferred []string, check bool) ag82Run {
		t.Helper()
		vars["ipa_active_users"] = []any{map[string]any{"name": "alice", "ssh_keys": keys}, map[string]any{"name": "bob", "ssh_keys": []any{}}, map[string]any{"name": "unmanaged"}}
		if vars["cache_test_omit_users"] == true {
			vars["ipa_active_users"] = []any{}
		}
		vars["pilot_deferred_hosts"] = deferred
		write("calls", "")
		var args []string
		if check {
			args = []string{"--check", "--diff"}
		}
		if tag, ok := vars["cache_test_tag"].(string); ok && tag != "all" {
			args = append(args, "--tags", tag)
		}
		return runGatewayTasks(t, dir, tasks, vars, nil, args...)
	}
	assertRun := func(result ag82Run, success bool, hosts ...string) {
		t.Helper()
		if (result.rc == 0) != success {
			t.Fatalf("rc=%d failures=%v\n%s", result.rc, result.failures, result.raw)
		}
		calls, err := os.ReadFile(filepath.Join(dir, "calls"))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Fields(string(calls))
		slices.Sort(lines)
		slices.Sort(hosts)
		if !slices.Equal(lines, hosts) {
			t.Fatalf("cache calls=%v; want %v; failures=%v\n%s", lines, hosts, result.failures, result.raw)
		}
	}
	all := []string{"client-a/alice", "client-a/bob", "client-b/alice", "client-b/bob", "localhost/alice", "localhost/bob"}
	assertRun(run([]any{key}, nil, true), true)
	if _, err := os.Stat(filepath.Join(dir, "journal.json")); !os.IsNotExist(err) {
		t.Fatal("check mode wrote journal")
	}
	assertRun(run([]any{key}, nil, false), true, all...)
	write("modified", "no")
	assertRun(run([]any{key}, nil, false), true)
	write("source/alice", "")
	write("modified", "yes")
	// The fake reports both users modified, so both are invalidated; #115's
	// real no-key/no-modifications capture is used by the no-op runs above.
	assertRun(run([]any{}, nil, false), true, all...)
	write("source/alice", key+"\n")
	assertRun(run([]any{key}, nil, false), true, all...)
	write("source/alice", "")
	write("fail-client-a", "yes")
	partial := run([]any{}, nil, false)
	// One bounded retry after an invalidation error; other clients still run.
	assertRun(partial, false, append(slices.Clone(all), "client-a/alice", "client-a/bob")...)
	if !strings.Contains(fmt.Sprint(partial.failures), "PARTIAL") {
		t.Fatalf("partial failure not surfaced: %v", partial.failures)
	}
	if err := os.Remove(filepath.Join(dir, "fail-client-a")); err != nil {
		t.Fatal(err)
	}
	write("modified", "no")
	assertRun(run([]any{}, nil, false), true, "client-a/alice", "client-a/bob")
	assertRun(run([]any{}, nil, false), true)
	write("source/alice", key+"\n")
	write("modified", "yes")
	assertRun(run([]any{key}, []string{"client-b"}, false), false, "client-a/alice", "client-a/bob", "localhost/alice", "localhost/bob")
	write("modified", "no")
	assertRun(run([]any{key}, nil, false), true, "client-b/alice", "client-b/bob")
	assertRun(run([]any{key}, nil, false), true)
	write("source/alice", "")
	write("modified", "yes")
	vars["cache_test_unreachable"] = true
	assertRun(run([]any{}, nil, false), false, "client-a/alice", "client-a/bob", "localhost/alice", "localhost/bob")
	vars["cache_test_unreachable"] = false
	write("modified", "no")
	assertRun(run([]any{}, nil, false), true, "client-b/alice", "client-b/bob")
	write("source/alice", key+"\n")
	write("modified", "yes")
	write("lookup-fail-client-b", "yes")
	assertRun(run([]any{key}, nil, false), false, all...)
	if err := os.Remove(filepath.Join(dir, "lookup-fail-client-b")); err != nil {
		t.Fatal(err)
	}
	write("modified", "no")
	assertRun(run([]any{key}, nil, false), true, "client-b/alice", "client-b/bob")
	vars["ipa_user_mod"] = map[string]any{"changed": true}
	write("fail-global-client-a", "yes")
	assertRun(run([]any{key}, nil, false), false, "client-a/*", "client-b/*")
	if err := os.Remove(filepath.Join(dir, "fail-global-client-a")); err != nil {
		t.Fatal(err)
	}
	vars["ipa_user_mod"] = map[string]any{"changed": false}
	assertRun(run([]any{key}, nil, false), true, "client-a/*", "client-b/*")
	assertRun(run([]any{key}, nil, false), true)
	// A non-key mutation must remain recoverable while any client is deferred.
	vars["ipa_user_mod"] = map[string]any{"changed": true}
	assertRun(run([]any{key}, []string{"client-b"}, false), true, "client-a/*")
	vars["ipa_user_mod"] = map[string]any{"changed": false}
	assertRun(run([]any{key}, nil, false), true, "client-a/*", "client-b/*")
	assertRun(run([]any{key}, nil, false), true)
	// Crash after prepare, before settle/refresh: recovery is conservative even
	// when the next reconciliation finds no additional authorization changes.
	statePath := filepath.Join(dir, "journal.json")
	crash := exec.Command("python3", "-c", string(helper), "auth_prepare", statePath)
	crash.Stdin = strings.NewReader(`{"domain":"ipa.test"}`)
	if out, err := crash.CombinedOutput(); err != nil {
		t.Fatalf("crash prepare: %v %s", err, out)
	}
	assertRun(run([]any{key}, nil, false), true, "client-a/*", "client-b/*")
	assertRun(run([]any{key}, nil, false), true)

	// Retained work must be authorized from the current inventory, regardless
	// of whether the current roster still manages that user and under every
	// supported mutation tag. Actual production prepare/settle/gate/delegate
	// tasks execute; rejected plans may never call either SSSD process.
	for _, omitted := range []bool{false, true} {
		for _, host := range []string{"old-client", "missing-client"} {
			for _, tag := range []string{"all", "identity", "sshkeys", "users", "client-cache"} {
				raw, err := os.ReadFile(statePath)
				if err != nil {
					t.Fatal(err)
				}
				var state map[string]any
				if err := json.Unmarshal(raw, &state); err != nil {
					t.Fatal(err)
				}
				users := state["users"].(map[string]any)
				users["alice"].(map[string]any)["pending"] = []string{host}
				raw, err = json.Marshal(state)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(statePath, raw, 0600); err != nil {
					t.Fatal(err)
				}
				vars["cache_test_omit_users"] = omitted
				vars["cache_test_old_groups"] = "prod"
				vars["cache_test_tag"] = tag
				result := run([]any{key}, nil, false)
				assertRun(result, false)
				if !strings.Contains(fmt.Sprint(result.failures), "Gate: pending SSH cache targets") {
					t.Fatalf("wrong failure: %v", result.failures)
				}
				raw, err = os.ReadFile(statePath)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(raw), host) {
					t.Fatalf("lost unfinished work for %s", host)
				}
			}
		}
	}
}
