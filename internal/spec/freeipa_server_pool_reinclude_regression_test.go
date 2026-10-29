package spec

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Issue #157: site.yml includes tasks/freeipa-server-pool.yml from
// dns-apply.yml (hosts: dns) and again from freeipa-client-apply.yml
// (hosts: freeipa-client). set_fact outlives the include and the play, and
// the file built freeipa_server_pool_replicas by appending to its previous
// value, so on a host in both groups the second include listed every replica
// twice and its duplicate-FQDN gate failed the run. The tests in this file
// run the real task file with ansible-playbook; the Go test job has no
// Ansible, so `make freeipa-server-pool-test` (CI's Playbook lint job,
// PILOT_REQUIRE_CONTAINER_TESTS=1) runs them and fails instead of skipping.

const (
	freeipaServerPoolTasksPath = "../../playbooks/apply/tasks/freeipa-server-pool.yml"
	freeipaServerPoolTestFile  = "freeipa_server_pool_reinclude_regression_test.go"
	freeipaServerPoolDupGate   = "FreeIPA server pool — gate: no duplicate FQDNs in the pool (covers primary==replica FQDN too)"
)

// requireAnsibleForServerPool skips without ansible-playbook, or fails under
// PILOT_REQUIRE_CONTAINER_TESTS=1.
func requireAnsibleForServerPool(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
			t.Fatalf("ansible-playbook not installed: %v (PILOT_REQUIRE_CONTAINER_TESTS=1)", err)
		}
		t.Skipf("ansible-playbook not installed: %v", err)
	}
}

// freeipaServerPoolInventory puts localhost in both the dns and the
// freeipa-client group (a dns tier host that is also a FreeIPA client, the
// #157 shape), next to one primary and the given replicas.
func freeipaServerPoolInventory(replicas map[string]any) map[string]any {
	return map[string]any{"all": map[string]any{
		"vars": map[string]any{"freeipa_domain": "example.test"},
		"children": map[string]any{
			"freeipa-server":         map[string]any{"hosts": map[string]any{"ipa1": map[string]any{"ansible_host": "192.0.2.11"}}},
			"freeipa-server-replica": map[string]any{"hosts": replicas},
			"dns":                    map[string]any{"hosts": map[string]any{"localhost": localHostVars()}},
			"freeipa-client":         map[string]any{"hosts": map[string]any{"localhost": localHostVars()}},
		},
	}}
}

// realPoolInclude returns the task of playbooks/apply/<playbook> that
// includes the pool file, pointed at the file's absolute path (the play runs
// from a temporary directory).
func realPoolInclude(t *testing.T, playbook, name, abs string) map[string]any {
	t.Helper()
	task := findNamedTask(t, loadYAML(t, filepath.Join("..", "..", "playbooks", "apply", playbook)), name)
	include, _ := task["ansible.builtin.include_tasks"].(map[string]any)
	if include == nil || include["file"] != "tasks/freeipa-server-pool.yml" {
		t.Fatalf("%s: %q no longer includes tasks/freeipa-server-pool.yml: %v", playbook, name, task)
	}
	include["file"] = abs
	return task
}

// freeipaServerPoolPlaybooks returns the plays that include the pool file
// twice on localhost, by name.
func freeipaServerPoolPlaybooks(t *testing.T) map[string][]map[string]any {
	t.Helper()
	abs, err := filepath.Abs(freeipaServerPoolTasksPath)
	if err != nil {
		t.Fatal(err)
	}
	show := showTask([]string{"freeipa_server_pool", "freeipa_server_fqdns"})
	include := map[string]any{
		"name":                          "include the pool",
		"ansible.builtin.include_tasks": map[string]any{"file": abs, "apply": map[string]any{"tags": []any{"always"}}},
		"vars":                          map[string]any{"freeipa_domain": "example.test"},
		"tags":                          []any{"always"},
	}

	// site.yml's order: dns-apply.yml, then freeipa-client-apply.yml, each
	// with its own include task and the tasks that compute that include's
	// freeipa_domain.
	dnsPlaybook := loadYAML(t, "../../playbooks/apply/dns-apply.yml")
	clientVars := loadFirstPlay(t, "freeipa-client-apply.yml")["vars"].(map[string]any)
	clientPlaybook := loadYAML(t, "../../playbooks/apply/freeipa-client-apply.yml")
	site := []map[string]any{
		{"name": "like dns-apply.yml", "hosts": "dns", "gather_facts": false, "become": false, "tasks": []any{
			findNamedTask(t, dnsPlaybook, "DNS — detect FreeIPA in the inventory"),
			realPoolInclude(t, "dns-apply.yml", "DNS — compute the FreeIPA server pool", abs),
		}},
		{"name": "like freeipa-client-apply.yml", "hosts": "freeipa-client", "gather_facts": false, "become": false,
			"vars": map[string]any{"ipa_domain": clientVars["ipa_domain"]},
			"tasks": []any{
				findNamedTask(t, clientPlaybook, "FreeIPA server pool — resolve domain input for the shared task (avoid var-name collision)"),
				realPoolInclude(t, "freeipa-client-apply.yml", "FreeIPA server pool — compute desired pool + effective topology mode", abs),
				show,
			}},
	}
	return map[string][]map[string]any{
		"one play includes it twice": {{"name": "twice", "hosts": "freeipa-client", "gather_facts": false, "become": false,
			"tasks": []any{include, include, show}}},
		"site.yml: dns-apply.yml then freeipa-client-apply.yml": site,
	}
}

// TestRegression_FreeIPAServerPoolIsComputedAgainOnEveryInclude includes the
// pool file twice on one host, in one play and in site.yml's two plays. The
// second include must compute the same pool as the first. The duplicate-FQDN
// gate must still fail a pool whose replica has the primary's FQDN.
func TestRegression_FreeIPAServerPoolIsComputedAgainOnEveryInclude(t *testing.T) {
	requireAnsibleForServerPool(t)
	cases := []struct {
		name     string
		replicas map[string]any
		want     []string // pool FQDNs after the second include
		failTask string   // the gate that must fail instead
	}{
		{name: "one replica (legacy ipa2.<domain> default)",
			replicas: map[string]any{"ipa2": map[string]any{"ansible_host": "192.0.2.12"}},
			want:     []string{"ipa1.example.test", "ipa2.example.test"}},
		{name: "two replicas with explicit FQDNs",
			replicas: map[string]any{
				"ipa2": map[string]any{"ansible_host": "192.0.2.12", "freeipa_replica_fqdn": "ipa2.example.test"},
				"ipa3": map[string]any{"ansible_host": "192.0.2.13", "freeipa_replica_fqdn": "ipa3.example.test"},
			},
			want: []string{"ipa1.example.test", "ipa2.example.test", "ipa3.example.test"}},
		{name: "replica with the primary's FQDN still fails closed",
			replicas: map[string]any{"ipa2": map[string]any{"ansible_host": "192.0.2.12", "freeipa_replica_fqdn": "ipa1.example.test"}},
			failTask: freeipaServerPoolDupGate},
	}
	playbooks := freeipaServerPoolPlaybooks(t)
	for _, tc := range cases {
		for shape, plays := range playbooks {
			t.Run(tc.name+"/"+shape, func(t *testing.T) {
				t.Parallel()
				got, failed := tryInventoryPlaysIn(t, freeipaServerPoolInventory(tc.replicas), nil, plays)
				if tc.failTask != "" {
					if !strings.HasPrefix(failed, tc.failTask+": ") || !strings.Contains(failed, "ipa1.example.test") {
						t.Fatalf("want %q to fail on the duplicate FQDN, got failure %q, output %v", tc.failTask, failed, got)
					}
					return
				}
				if failed != "" {
					t.Fatalf("the second include failed: %s", failed)
				}
				var pool []string
				members, _ := got["freeipa_server_pool"].([]any)
				for _, m := range members {
					member, _ := m.(map[string]any)
					fqdn, _ := member["fqdn"].(string)
					pool = append(pool, fqdn)
				}
				if !slices.Equal(pool, tc.want) {
					t.Errorf("freeipa_server_pool after the second include = %v, want %v", pool, tc.want)
				}
				if !jsonEqual(got["freeipa_server_fqdns"], tc.want) {
					t.Errorf("freeipa_server_fqdns after the second include = %v, want %v", got["freeipa_server_fqdns"], tc.want)
				}
			})
		}
	}
}

// TestRegression_FreeIPAServerPoolRequiredAnsibleDoesNotSkip runs the
// runtime test without ansible-playbook on PATH and with
// PILOT_REQUIRE_CONTAINER_TESTS=1: it must fail, not skip.
func TestRegression_FreeIPAServerPoolRequiredAnsibleDoesNotSkip(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-test.v", "-test.run=^TestRegression_FreeIPAServerPoolIsComputedAgainOnEveryInclude$")
	cmd.Env = append(os.Environ(), "PILOT_REQUIRE_CONTAINER_TESTS=1", "PATH="+filepath.Join(t.TempDir(), "missing-tools"))
	out, err := cmd.CombinedOutput()
	if err == nil || strings.Contains(string(out), "--- SKIP") || !strings.Contains(string(out), "ansible-playbook not installed") {
		t.Fatalf("required Ansible must fail instead of skipping: err=%v\n%s", err, out)
	}
}

// TestRegression_FreeIPAServerPoolCIRequiresAnsible locks the CI wiring
// (AGENTS.md §5.7): `make freeipa-server-pool-test` selects every test in
// this file with PILOT_REQUIRE_CONTAINER_TESTS=1, and CI's Playbook lint job
// runs it after installing Ansible and Go.
func TestRegression_FreeIPAServerPoolCIRequiresAnsible(t *testing.T) {
	makefile, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^freeipa-server-pool-test:.*\n\tPILOT_REQUIRE_CONTAINER_TESTS=1 go test .* -run '([^']+)' ./internal/spec/`).FindSubmatch(makefile)
	if m == nil {
		t.Fatal("Makefile freeipa-server-pool-test must run go test with PILOT_REQUIRE_CONTAINER_TESTS=1")
	}
	run := regexp.MustCompile(strings.ReplaceAll(string(m[1]), "$$", "$"))
	src, err := parser.ParseFile(token.NewFileSet(), freeipaServerPoolTestFile, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, decl := range src.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || !strings.HasPrefix(fn.Name.Name, "Test") {
			continue
		}
		count++
		if !run.MatchString(fn.Name.Name) {
			t.Errorf("make freeipa-server-pool-test does not select %s", fn.Name.Name)
		}
	}
	if count < 3 {
		t.Fatalf("only %d tests found in %s", count, freeipaServerPoolTestFile)
	}

	data, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct{ Run, Uses string }
		}
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	ansible, goSetup, recipe := -1, -1, -1
	for i, step := range workflow.Jobs["playbook-lint"].Steps {
		if strings.Contains(step.Run, "pip install") && strings.Contains(step.Run, "ansible-core") {
			ansible = i
		}
		if strings.HasPrefix(step.Uses, "actions/setup-go@") {
			goSetup = i
		}
		if strings.TrimSpace(step.Run) == "make freeipa-server-pool-test" {
			recipe = i
		}
	}
	if recipe < 0 || ansible < 0 || goSetup < 0 || recipe <= ansible || recipe <= goSetup {
		t.Fatalf("CI's Playbook lint job must run make freeipa-server-pool-test after installing Ansible and Go: ansible=%d go=%d recipe=%d", ansible, goSetup, recipe)
	}
}
