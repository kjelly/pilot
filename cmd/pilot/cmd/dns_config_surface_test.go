package cmd

// Tests for the dns role's configuration surface
// (docs/verification/dns.md §3.5 P1–P6, §6 E7): every setting lives in the
// one flat group_vars/dns.yml, pilot edit can set each of them, older
// workspaces can backfill new keys, a group_vars/<name>/ directory that
// would make Ansible ignore group_vars/<name>.yml is reported, and the
// values pilot edit writes are the values Ansible actually sees.

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.yaml.in/yaml/v3"

	"github.com/kjelly/pilot/internal/groupvars"
)

const dnsSurfaceHosts = "hosts:\n  tier-1:\n    ansible_host: \"10.0.0.53\"\n    roles: [dns]\n"

// resetFlagsAfter restores every flag of cmds to its default value and
// clears its Changed bit once the test ends: rootCmd and its subcommands
// are package-level, so a flag set by one test would otherwise leak into
// the next (AGENTS.md §5.6, test shared state).
func resetFlagsAfter(t *testing.T, cmds ...*cobra.Command) {
	t.Helper()
	t.Cleanup(func() {
		for _, c := range cmds {
			c.Flags().VisitAll(func(f *pflag.Flag) {
				_ = f.Value.Set(f.DefValue)
				f.Changed = false
			})
		}
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	})
}

// runPilot executes the real cobra command tree and returns its error plus
// everything written to the command's out/err writers.
func runPilot(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	rootCmd.SetArgs(args)
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	err := rootCmd.Execute()
	return buf.String(), err
}

// chdirRepoRoot makes the fixed, CWD-relative group_vars/*.example.yml
// templates resolve to the real shipped files, as they do for an operator
// running pilot from a checkout or inside the pilot-cli image.
func chdirRepoRoot(t *testing.T) {
	t.Helper()
	t.Chdir(repoRootForTest(t))
}

func writeDNSWorkspace(t *testing.T) string {
	t.Helper()
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "hosts.yml"), []byte(dnsSurfaceHosts), 0o644); err != nil {
		t.Fatal(err)
	}
	return ws
}

func mkWorkspaceFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// P1 + P6: a dns host gets exactly one flat group_vars/dns.yml, and the
// scaffolded file activates nothing — no example zone or stub becomes real
// configuration before the operator edits it.
func TestInventoryGenerate_DNSHostScaffoldsOnlyFlatGroupVars(t *testing.T) {
	chdirRepoRoot(t)
	resetFlagsAfter(t, inventoryGenerateCmd)
	ws := writeDNSWorkspace(t)

	out, err := runPilot(t, "inventory", "generate", "--dir", ws, "--no-vault")
	if err != nil {
		t.Fatalf("inventory generate: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(ws, "group_vars", "dns")); !os.IsNotExist(err) {
		t.Fatalf("group_vars/dns/ must not be created (it would shadow dns.yml), stat err=%v", err)
	}
	entries, err := os.ReadDir(filepath.Join(ws, "group_vars"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if want := []string{"dns.yml"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("group_vars/ = %v, want %v", names, want)
	}
	data, err := os.ReadFile(filepath.Join(ws, "group_vars", "dns.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var effective map[string]any
	if err := yaml.Unmarshal(data, &effective); err != nil {
		t.Fatalf("scaffolded dns.yml is not valid YAML: %v", err)
	}
	for _, key := range []string{"dns_zones", "dns_stub_zones", "dns_freeipa_zones", "dns_listen_addr"} {
		if _, ok := effective[key]; ok {
			t.Fatalf("scaffolded dns.yml activates %s before the operator set it: %v", key, effective)
		}
	}
	if strings.Contains(out, "⚠️") {
		t.Fatalf("a clean workspace must not get a shadowing warning:\n%s", out)
	}
}

// P4: generate warns about a pre-existing shadowing directory.
func TestInventoryGenerate_WarnsAboutShadowedGroupVars(t *testing.T) {
	chdirRepoRoot(t)
	resetFlagsAfter(t, inventoryGenerateCmd)
	ws := writeDNSWorkspace(t)
	// What older pilot versions scaffolded for every dns host.
	mkWorkspaceFile(t, filepath.Join(ws, "group_vars", "dns.yml"), "dns_upstream: 9.9.9.9\n")
	mkWorkspaceFile(t, filepath.Join(ws, "group_vars", "dns", "zones.yaml"), "dns_zones: []\n")

	out, err := runPilot(t, "inventory", "generate", "--dir", ws, "--no-vault")
	if err != nil {
		t.Fatalf("inventory generate: %v\n%s", err, out)
	}
	if !strings.Contains(out, filepath.Join(ws, "group_vars", "dns.yml")+" is ignored by Ansible") {
		t.Fatalf("expected a shadowing warning for dns.yml, got:\n%s", out)
	}
}

// P4: lint fails on a shadowed file and passes once it is gone.
func TestInventoryLint_ShadowedGroupVarsIsAnError(t *testing.T) {
	resetFlagsAfter(t, inventoryLintCmd)
	ws := writeDNSWorkspace(t)
	hosts := filepath.Join(ws, "hosts.yml")

	if out, err := runPilot(t, "inventory", "lint", "--in", hosts); err != nil {
		t.Fatalf("clean workspace: lint error = %v\n%s", err, out)
	}

	mkWorkspaceFile(t, filepath.Join(ws, "group_vars", "dns.yml"), "dns_upstream: 9.9.9.9\n")
	mkWorkspaceFile(t, filepath.Join(ws, "group_vars", "dns", "zones.yaml"), "dns_zones: []\n")
	out, err := runPilot(t, "inventory", "lint", "--in", hosts)
	if err == nil {
		t.Fatalf("lint must fail when group_vars/dns/ shadows dns.yml:\n%s", out)
	}
	if !strings.Contains(out, "error: "+filepath.Join(ws, "group_vars", "dns.yml")) {
		t.Fatalf("lint output does not name the shadowed file:\n%s", out)
	}

	if err := os.RemoveAll(filepath.Join(ws, "group_vars", "dns")); err != nil {
		t.Fatal(err)
	}
	if out, err := runPilot(t, "inventory", "lint", "--in", hosts); err != nil {
		t.Fatalf("after removing the directory: lint error = %v\n%s", err, out)
	}
}

// P4: pilot edit's group_vars file picker warns, and stays quiet for a
// workspace without the pair.
func TestEditRouter_GroupVarsPickerWarnsAboutShadowedFile(t *testing.T) {
	chdirRepoRoot(t)
	ws := writeDNSWorkspace(t)
	mkWorkspaceFile(t, filepath.Join(ws, "group_vars", "dns.yml"), "dns_upstream: 9.9.9.9\n")

	r := newEditRouterModel(ws)
	d := automationDriver{}
	if err := d.choose(&r, "group_vars"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.banner, "不會生效") {
		t.Fatalf("no shadowing directory yet, but the picker warned: %q", r.banner)
	}

	mkWorkspaceFile(t, filepath.Join(ws, "group_vars", "dns", "zones.yaml"), "dns_zones: []\n")
	r = newEditRouterModel(ws)
	if err := d.choose(&r, "group_vars"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.banner, filepath.Join(ws, "group_vars", "dns.yml")+" 不會生效") {
		t.Fatalf("picker banner = %q, want a warning naming group_vars/dns.yml", r.banner)
	}
}

// P3: an older workspace dns.yml gains the new settings as commented
// defaults through the editor, and then they are editable like any other.
func TestEditAutomationDriver_BackfillGroupVarsFromExample(t *testing.T) {
	chdirRepoRoot(t)
	ws := writeDNSWorkspace(t)
	old := "---\ndns_upstream: 1.1.1.1\n"
	path := filepath.Join(ws, "group_vars", "dns.yml")
	mkWorkspaceFile(t, path, old)

	// Opening the file and leaving without choosing the backfill item
	// must not touch it.
	r := newEditRouterModel(ws)
	d := automationDriver{}
	if err := d.run(&r, editScenario{Version: 1, Steps: []editAction{
		{Action: "discard_group_vars", File: "dns.yml"},
	}}); err != nil {
		t.Fatalf("discard run: %v", err)
	}
	if data, _ := os.ReadFile(path); string(data) != old {
		t.Fatalf("file changed without choosing backfill:\n%s", data)
	}

	r = newEditRouterModel(ws)
	if err := d.run(&r, editScenario{Version: 1, Steps: []editAction{
		{Action: "backfill_group_vars", File: "dns.yml"},
		{Action: "set_group_var", File: "dns.yml", Key: "dns_cache_max_ttl", Value: "90"},
		{Action: "save_group_vars", File: "dns.yml"},
	}}); err != nil {
		t.Fatalf("backfill run: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), old) {
		t.Fatalf("existing lines changed:\n%s", data)
	}
	var effective map[string]any
	if err := yaml.Unmarshal(data, &effective); err != nil {
		t.Fatalf("invalid YAML after backfill: %v\n%s", err, data)
	}
	if want := map[string]any{"dns_upstream": "1.1.1.1", "dns_cache_max_ttl": 90}; !reflect.DeepEqual(effective, want) {
		t.Fatalf("effective values = %v, want %v (backfilled keys must stay commented)\n%s", effective, want, data)
	}
	doc := groupvars.Parse(data)
	listed := map[string]bool{}
	for _, e := range doc.ListEntries() {
		listed[e.Key] = true
	}
	for _, k := range []string{"dns_freeipa_zones", "dns_stub_zones", "dns_access_control"} {
		if !listed[k] {
			t.Fatalf("%s not editable after backfill:\n%s", k, data)
		}
	}

	// Nothing is missing any more: the action must fail rather than
	// pretend a backfill happened.
	r = newEditRouterModel(ws)
	err = d.run(&r, editScenario{Version: 1, Steps: []editAction{{Action: "backfill_group_vars", File: "dns.yml"}}})
	if err == nil {
		t.Fatal("backfill_group_vars on a complete file must fail")
	}
}

// E7 / P5: every pilot-edit-editable dns setting, written through the real
// router, is what Ansible itself resolves for the host.
func TestEditAutomationDriver_DNSGroupVarsRoundTripThroughAnsible(t *testing.T) {
	requireRealAnsible(t)
	chdirRepoRoot(t)
	resetFlagsAfter(t, inventoryGenerateCmd)
	ws := writeDNSWorkspace(t)

	r := newEditRouterModel(ws)
	d := automationDriver{}
	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "set_group_var_list", File: "dns.yml", Key: "dns_upstream", Values: []string{"1.1.1.1", "9.9.9.9"}},
		{Action: "set_group_var_list", File: "dns.yml", Key: "dns_freeipa_zones", Values: []string{"0.0.10.in-addr.arpa"}},
		{Action: "set_group_var_list", File: "dns.yml", Key: "dns_stub_zones", Values: []string{"corp.internal=10.0.1.2,10.0.1.3"}},
		{Action: "set_group_var_list", File: "dns.yml", Key: "dns_access_control", Values: []string{"10.0.0.0/8"}},
		{Action: "set_group_var", File: "dns.yml", Key: "dns_cache_max_ttl", Value: "120"},
		{Action: "set_group_var", File: "dns.yml", Key: "dns_cache_max_negative_ttl", Value: "30"},
		{Action: "set_group_var", File: "dns.yml", Key: "dns_dnssec_validation", Value: "false"},
		{Action: "save_group_vars", File: "dns.yml"},
	}}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	if out, err := runPilot(t, "inventory", "generate", "--dir", ws, "--no-vault"); err != nil {
		t.Fatalf("inventory generate: %v\n%s", err, out)
	}

	// --playbook-dir: without it ansible-inventory treats the CWD (the repo
	// root here) as the playbook directory and also loads its group_vars/.
	cmd := exec.Command("ansible-inventory", "-i", filepath.Join(ws, "inventory.yml"), "--playbook-dir", ws, "--host", "tier-1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("ansible-inventory --host tier-1: %v\n%s", err, stderr.String())
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("ansible-inventory output is not JSON: %v\n%s", err, raw)
	}
	want := map[string]any{
		"dns_upstream":               []any{"1.1.1.1", "9.9.9.9"},
		"dns_freeipa_zones":          []any{"0.0.10.in-addr.arpa"},
		"dns_stub_zones":             []any{"corp.internal=10.0.1.2,10.0.1.3"},
		"dns_access_control":         []any{"10.0.0.0/8"},
		"dns_cache_max_ttl":          float64(120),
		"dns_cache_max_negative_ttl": float64(30),
		"dns_dnssec_validation":      false,
	}
	for k, v := range want {
		if !reflect.DeepEqual(got[k], v) {
			t.Errorf("Ansible sees %s = %#v, want %#v", k, got[k], v)
		}
	}
	for _, k := range []string{"dns_zones", "dns_listen_addr"} {
		if v, ok := got[k]; ok {
			t.Errorf("Ansible sees %s = %#v, but nothing set it", k, v)
		}
	}
	if t.Failed() {
		data, _ := os.ReadFile(filepath.Join(ws, "group_vars", "dns.yml"))
		t.Logf("group_vars/dns.yml:\n%s", data)
	}
}
