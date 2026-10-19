package spec

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Execute the canonical user-add task with the login-probe import's actual
// variables. An IPA adapter records the creation argv: first visibility must
// already include the key, before any later user-mod can race an SSH lookup.
func TestRegression_LoginProbeCanaryCreationAtomic(t *testing.T) {
	read := func(path string) []map[string]any {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var plays []map[string]any
		if err := yaml.Unmarshal(raw, &plays); err != nil {
			t.Fatal(err)
		}
		return plays
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v %s", err, out)
	}
	pub, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	public := strings.TrimSpace(string(pub))
	canonical := read("../../playbooks/test/fixtures/freeipa-client-fixtures.yml")[0]
	wrapper := read("../../playbooks/test/fixtures/login-probe-fixtures.yml")
	var imported map[string]any
	for _, play := range wrapper {
		if play["ansible.builtin.import_playbook"] == "freeipa-client-fixtures.yml" {
			imported = play["vars"].(map[string]any)
		}
	}
	if imported == nil {
		t.Fatal("missing canonical canary import")
	}
	var creation map[string]any
	var find func([]any)
	find = func(tasks []any) {
		for _, raw := range tasks {
			task := raw.(map[string]any)
			if strings.HasPrefix(task["name"].(string), "Fixtures — ensure IPA user") {
				creation = task
			}
			if block, ok := task["block"].([]any); ok {
				find(block)
			}
		}
	}
	find(canonical["tasks"].([]any))
	if creation == nil {
		t.Fatal("missing canonical user creation")
	}
	adapter := "#!/usr/bin/env python3\nimport os,json,sys\njson.dump(sys.argv[1:],open(os.environ['CAPTURE_ARGS'],'w'))\nprint('Added user')\n"
	if err := os.WriteFile(filepath.Join(dir, "ipa"), []byte(adapter), 0700); err != nil {
		t.Fatal(err)
	}
	inv, err := yaml.Marshal(map[string]any{"all": map[string]any{"hosts": map[string]any{"localhost": map[string]any{}}, "children": map[string]any{"login-probe": map[string]any{"hosts": map[string]any{"probe-source": map[string]any{"login_probe_fixture_pubkey_line": public}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range []bool{false, true} {
		name := "default unchanged"
		if canary {
			name = "canary first visibility has key"
		}
		t.Run(name, func(t *testing.T) {
			vars := map[string]any{}
			for k, v := range canonical["vars"].(map[string]any) {
				vars[k] = v
			}
			if canary {
				for k, v := range imported {
					vars[k] = v
				}
			}
			capture := filepath.Join(dir, "argv.json")
			task := map[string]any{}
			for k, v := range creation {
				task[k] = v
			}
			task["environment"] = map[string]any{"PATH": dir + ":" + os.Getenv("PATH"), "CAPTURE_ARGS": capture}
			out, ok := runLocalPlayInventory(t, string(inv), vars, []map[string]any{task})
			if !ok {
				t.Fatalf("creation failed:\n%s", out)
			}
			raw, err := os.ReadFile(capture)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			want := []string{"user-add", "pilotuser", "--first=Pilot", "--last=User"}
			if canary {
				want = []string{"user-add", "pilot-login-canary", "--first=Pilot", "--last=LoginCanary", "--sshpubkey=" + public}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("first visible identity creation argv=%v; want %v", got, want)
			}
		})
	}
	// Missing preflight data is allowed only in a fresh check-mode preview.
	empty, whitespace := "", " \t\n"
	for _, c := range []struct {
		name  string
		check bool
		key   *string
	}{
		{name: "missing key refuses mutation"},
		{name: "empty key refuses mutation", key: &empty},
		{name: "whitespace key refuses mutation", key: &whitespace},
		{name: "fresh check mode needs no generated key", check: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			vars := map[string]any{}
			for k, v := range canonical["vars"].(map[string]any) {
				vars[k] = v
			}
			for k, v := range imported {
				vars[k] = v
			}
			capture := filepath.Join(t.TempDir(), "argv.json")
			task := map[string]any{}
			for k, v := range creation {
				task[k] = v
			}
			task["environment"] = map[string]any{"PATH": dir + ":" + os.Getenv("PATH"), "CAPTURE_ARGS": capture}
			extra := []string{}
			if c.check {
				extra = append(extra, "--check")
			}
			missing := "all:\n  hosts:\n    localhost: {}\n  children:\n    login-probe:\n      hosts:\n        probe-source: {}\n"
			if c.key != nil {
				data, err := yaml.Marshal(map[string]any{"all": map[string]any{"hosts": map[string]any{"localhost": map[string]any{}}, "children": map[string]any{"login-probe": map[string]any{"hosts": map[string]any{"probe-source": map[string]any{"login_probe_fixture_pubkey_line": *c.key}}}}}})
				if err != nil {
					t.Fatal(err)
				}
				missing = string(data)
			}
			out, ok := runLocalPlayInventory(t, missing, vars, []map[string]any{task}, extra...)
			if ok != c.check {
				t.Fatalf("unexpected preview/mutation outcome:\n%s", out)
			}
			if _, err := os.Stat(capture); !os.IsNotExist(err) {
				t.Fatalf("creation ran without the required key: %v", err)
			}
		})
	}
}
