package diagnose

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/kjelly/pilot/internal/networkcheck"
)

// pilot_diagnose_dns_architecture's "effective" layer
// (dns_architecture.go) is a Go copy of rules that live
// in the playbooks. The playbooks stay the single source (issue #62,
// AGENTS.md §5.7): this test runs the playbooks' own tasks — taken by name
// from dns-apply.yml, freeipa-server-apply.yml,
// freeipa-server-replica-apply.yml and tasks/freeipa-dns-client-resolver.yml,
// plus the shared tasks/freeipa-server-pool.yml and
// tasks/dns-tier-endpoints.yml they include — with ansible-playbook on
// fixture inventories, and fails when the Go model computes anything else.
// A renamed or removed task fails the test too, so a playbook change
// cannot silently leave the model behind. It lives here rather than in
// internal/spec because internal/spec cannot import this package (cycle
// through internal/contract).

const (
	resolverTasksPath      = "../../playbooks/apply/tasks/freeipa-dns-client-resolver.yml"
	dnsApplyPlaybook       = "../../playbooks/apply/dns-apply.yml"
	freeipaServerPlaybook  = "../../playbooks/apply/freeipa-server-apply.yml"
	freeipaReplicaPlaybook = "../../playbooks/apply/freeipa-server-replica-apply.yml"
	applyTasksDir          = "../../playbooks/apply/tasks"
)

// dnsTierModelTasks are dns-apply.yml's pre_tasks that compute the tier's
// effective configuration (gates and probes left out).
var dnsTierModelTasks = []string{
	"DNS — normalize settings from group_vars/dns.yml",
	"DNS — normalize list-shaped settings",
	"DNS — compute tier service addresses",
	"DNS — this host's service address",
	"DNS — detect FreeIPA in the inventory",
	"DNS — compute the FreeIPA server pool",
	"DNS — FreeIPA DNS servers and mode",
	"DNS — mode",
	"DNS — FreeIPA-bound zones",
	"DNS — reset parsed zone lists",
	"DNS — stub zones for FreeIPA",
	"DNS — stub zones from dns_stub_zones (zone=ip[,ip])",
	"DNS — zones from dns_zones (stub_addr = delegation, otherwise local data)",
}

// resolverModelTasks are the resolver task file's selection steps.
var resolverModelTasks = []string{
	"FreeIPA DNS client — normalize freeipa_domain / freeipa_dns_client_servers",
	"FreeIPA DNS client — init DNS-provider list",
	"FreeIPA DNS client — add primary freeipa-server if it provides DNS",
	"FreeIPA DNS client — add freeipa-server-replica hosts that provide their own DNS",
	"FreeIPA DNS client — dns tier service addresses",
	"FreeIPA DNS client — compute effective nameserver list for THIS host",
	"FreeIPA DNS client — compute effective resolver options for THIS host",
}

func readYAML(t *testing.T, path string, into any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, into); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func firstPlay(t *testing.T, path string) map[string]any {
	t.Helper()
	var plays []map[string]any
	readYAML(t, path, &plays)
	return plays[0]
}

func pickTasks(t *testing.T, source string, tasks []any, names []string) []any {
	t.Helper()
	var out []any
	for _, name := range names {
		found := false
		for _, raw := range tasks {
			if task, ok := raw.(map[string]any); ok && task["name"] == name {
				out, found = append(out, task), true
				break
			}
		}
		if !found {
			t.Fatalf("%s has no task %q: internal/diagnose/dns_architecture.go mirrors it, update both", source, name)
		}
	}
	return out
}

func pickVars(t *testing.T, source string, vars map[string]any, names ...string) map[string]any {
	t.Helper()
	out := map[string]any{}
	for _, name := range names {
		v, ok := vars[name]
		if !ok {
			t.Fatalf("%s has no play var %q: internal/diagnose/dns_architecture.go mirrors it, update both", source, name)
		}
		out[name] = v
	}
	return out
}

func emitTask(prefix, content string) map[string]any {
	return map[string]any{
		"name":                 "emit " + prefix,
		"ansible.builtin.copy": map[string]any{"dest": "{{ out_dir }}/" + prefix + "-{{ inventory_hostname }}.json", "content": "{{ " + content + " | to_json }}", "mode": "0600"},
	}
}

// dnsModelPlaybook assembles the canonical tasks into one playbook.
func dnsModelPlaybook(t *testing.T) []map[string]any {
	t.Helper()
	dns := firstPlay(t, dnsApplyPlaybook)
	server := firstPlay(t, freeipaServerPlaybook)
	replica := firstPlay(t, freeipaReplicaPlaybook)
	var resolver []any
	readYAML(t, resolverTasksPath, &resolver)
	base := func(name, hosts string, vars map[string]any, tasks []any) map[string]any {
		if vars == nil {
			vars = map[string]any{}
		}
		vars["ansible_python_interpreter"] = "{{ ansible_playbook_python }}"
		return map[string]any{"name": name, "hosts": hosts, "connection": "local", "gather_facts": false, "vars": vars, "tasks": tasks}
	}
	tierTasks := append(pickTasks(t, dnsApplyPlaybook, dns["pre_tasks"].([]any), dnsTierModelTasks),
		emitTask("tier", "{'addr': dns_service_addr, 'mode': dns_mode, 'upstream': dns_upstream_list, 'freeipa_servers': dns_freeipa_servers, 'stub_zones': dns_stub_zone_list, 'local_zones': dns_local_zone_list | map(attribute='name') | list, 'pool': freeipa_server_pool | default([])}"))
	resolverTasks := append(pickTasks(t, resolverTasksPath, resolver, resolverModelTasks),
		emitTask("resolver", "{'servers': freeipa_dns_client_effective_servers, 'options': freeipa_dns_client_effective_resolver_options}"))
	serverTasks := append(pickTasks(t, freeipaServerPlaybook, server["pre_tasks"].([]any), []string{"Normalize DNS forwarders to a list"}),
		emitTask("primary", "{'setup_dns': ipa_setup_dns | bool, 'forwarders': ipa_dns_forwarders_normalized}"))
	return []map[string]any{
		base("dns tier model", "dns", nil, tierTasks),
		base("resolver model", "freeipa-dns-client", nil, resolverTasks),
		base("primary forwarders", "freeipa-server", pickVars(t, freeipaServerPlaybook, server["vars"].(map[string]any), "ipa_dns_forwarders_raw", "ipa_setup_dns"), serverTasks),
		base("replica install", "freeipa-server-replica", pickVars(t, freeipaReplicaPlaybook, replica["vars"].(map[string]any), "ipa_setup_dns", "ipa_dns_forwarder_argv"),
			append(pickTasks(t, freeipaReplicaPlaybook, replica["pre_tasks"].([]any), []string{"Normalize DNS forwarders to a list"}),
				emitTask("replica", "{'setup_dns': ipa_setup_dns | bool, 'argv': ipa_dns_forwarder_argv}"))),
	}
}

type dnsModelScenario struct {
	name      string
	inventory string
	groupVars map[string]string
}

// Every scenario is valid for the playbooks' gates; the Go-only tests in
// internal/diagnose cover the invalid and templated inputs.
var dnsModelScenarios = []dnsModelScenario{
	{name: "no dns tier", inventory: `
all:
  children:
    freeipa-server:
      hosts:
        ipa: {ansible_host: 10.0.0.5, freeipa_domain: Example.Test., ipa_dns_forwarders: "[8.8.4.4, 1.0.0.1]"}
    freeipa-dns-client:
      hosts:
        c1: {ansible_host: 10.0.0.21}
        c2: {ansible_host: 10.0.0.22, freeipa_dns_client_servers: [10.9.9.9, 10.9.9.8]}
`},
	// r2 leaves freeipa_setup_dns unset (a DNS provider, issue #67) and
	// writes its forwarders as a string (one forwarder, issue #68); r1's
	// ipa_dns_forwarders wins over its freeipa_dns_forwarders.
	{name: "split tier with two DNS-providing replicas", inventory: `
all:
  children:
    freeipa-server:
      hosts:
        ipa: {ansible_host: 10.0.0.5, freeipa_domain: example.test, freeipa_dns_forwarders: "1.1.1.1 9.9.9.9"}
    freeipa-server-replica:
      hosts:
        r1: {ansible_host: 10.0.0.6, freeipa_setup_dns: true, freeipa_replica_fqdn: ipa2.example.test, freeipa_dns_forwarders: [9.9.9.9], ipa_dns_forwarders: "1.0.0.1 1.1.1.1"}
        r2: {ansible_host: 10.0.0.7, freeipa_replica_fqdn: ipa3.example.test, freeipa_dns_forwarders: 8.8.8.8}
    dns:
      hosts:
        t2: {ansible_host: 10.0.0.12, dns_listen_addr: 10.1.0.12}
        t1: {ansible_host: 10.0.0.11}
        t3: {ansible_host: 10.0.0.13, dns_upstream: "9.9.9.9, 1.0.0.1"}
    freeipa-dns-client:
      hosts:
        c1: {ansible_host: 10.0.0.21}
        r1: {}
`, groupVars: map[string]string{"dns.yml": `
dns_upstream: [1.1.1.1, 9.9.9.9]
dns_freeipa_zones: [Svc.Example.Test.]
dns_stub_zones: ["corp.example=10.9.0.1, 10.9.0.2"]
dns_zones:
  - {name: lab.example, stub_addr: 10.8.0.1}
  - {name: Local.Example., records: [{name: www, value: 10.8.0.9}]}
`}},
	{name: "primary without DNS", inventory: `
all:
  children:
    freeipa-server:
      hosts:
        ipa: {ansible_host: 10.0.0.5, freeipa_setup_dns: false}
    dns:
      hosts:
        t1: {ansible_host: 10.0.0.11}
    freeipa-dns-client:
      hosts:
        c1: {ansible_host: 10.0.0.21}
`},
	{name: "tier without FreeIPA", inventory: `
all:
  children:
    dns:
      hosts:
        t1: {ansible_host: 10.0.0.11, dns_zones: [{name: corp.example, stub_addr: [10.7.0.1, 10.7.0.2]}]}
    freeipa-dns-client:
      hosts:
        c1: {ansible_host: 10.0.0.21}
`},
}

func readEmitted(t *testing.T, dir, prefix, host string, into any) bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, prefix+"-"+host+".json"))
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, into); err != nil {
		t.Fatalf("%s-%s.json: %v", prefix, host, err)
	}
	return true
}

func TestRegression_DNSArchitectureModelMatchesPlaybooks(t *testing.T) {
	for _, bin := range []string{"ansible-playbook", "ansible-inventory"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed: %v", bin, err)
		}
	}
	playbook, err := yaml.Marshal(dnsModelPlaybook(t))
	if err != nil {
		t.Fatal(err)
	}
	tasksDir, err := filepath.Abs(applyTasksDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, sc := range dnsModelScenarios {
		t.Run(sc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			out := filepath.Join(dir, "out")
			for _, d := range []string{out, filepath.Join(dir, "group_vars")} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			// The playbooks include tasks/<file> relative to playbooks/apply
			// and the resolver includes dns-tier-endpoints.yml relative to
			// tasks/.
			if err := os.Symlink(tasksDir, filepath.Join(dir, "tasks")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(tasksDir, "dns-tier-endpoints.yml"), filepath.Join(dir, "dns-tier-endpoints.yml")); err != nil {
				t.Fatal(err)
			}
			files := map[string]string{"inventory.yml": sc.inventory, "play.yml": string(playbook)}
			for name, content := range sc.groupVars {
				files[filepath.Join("group_vars", name)] = content
			}
			for name, content := range files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			env := append(os.Environ(), "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False", "ANSIBLE_HOME="+filepath.Join(dir, ".ansible"))
			run := exec.Command("ansible-playbook", "-i", "inventory.yml", "play.yml", "-e", "out_dir="+out)
			run.Dir, run.Env = dir, env
			if output, err := run.CombinedOutput(); err != nil {
				t.Fatalf("ansible-playbook: %v\n%s", err, output)
			}
			list := exec.Command("ansible-inventory", "-i", "inventory.yml", "--list")
			list.Dir, list.Env = dir, env
			listJSON, err := list.Output()
			if err != nil {
				t.Fatalf("ansible-inventory: %v", err)
			}
			resolved, err := networkcheck.ParseInventoryList(listJSON)
			if err != nil {
				t.Fatal(err)
			}
			compareDNSModel(t, BuildDNSArchitectureModel(resolved), resolved, out)
		})
	}
}

type emittedZone struct {
	Name   string   `json:"name"`
	Addrs  []string `json:"addrs"`
	Source string   `json:"source"`
}

type emittedPoolMember struct {
	InventoryHost string `json:"inventory_host"`
	FQDN          string `json:"fqdn"`
	IP            string `json:"ip"`
	Kind          string `json:"kind"`
	DNSProvider   bool   `json:"dns_provider"`
}

func compareDNSModel(t *testing.T, m DNSArchModel, inv networkcheck.ResolvedInventory, out string) {
	t.Helper()
	want := func(what string, got, ansible any) {
		t.Helper()
		if !reflect.DeepEqual(got, ansible) {
			t.Errorf("%s: model %#v, playbook %#v", what, got, ansible)
		}
	}
	nonNil := func(s []string) []string {
		if s == nil {
			return []string{}
		}
		return s
	}

	if len(m.Tier) != len(inv.OrderedGroupHosts(DNSTierGroup)) {
		t.Fatalf("model has %d tier hosts, inventory %v", len(m.Tier), inv.OrderedGroupHosts(DNSTierGroup))
	}
	for _, tier := range m.Tier {
		var e struct {
			Addr           string              `json:"addr"`
			Mode           string              `json:"mode"`
			Upstream       []string            `json:"upstream"`
			FreeIPAServers []string            `json:"freeipa_servers"`
			StubZones      []emittedZone       `json:"stub_zones"`
			LocalZones     []string            `json:"local_zones"`
			Pool           []emittedPoolMember `json:"pool"`
		}
		if !readEmitted(t, out, "tier", tier.Host, &e) {
			t.Fatalf("playbook emitted nothing for tier host %s", tier.Host)
		}
		want(tier.Host+" addr", tier.Addr, e.Addr)
		want(tier.Host+" mode", tier.Mode, e.Mode)
		want(tier.Host+" upstream", nonNil(tier.Upstream), nonNil(e.Upstream))
		want(tier.Host+" freeipa servers", nonNil(tier.FreeIPAServers), nonNil(e.FreeIPAServers))
		zones := []emittedZone{}
		for _, z := range tier.StubZones {
			zones = append(zones, emittedZone{Name: z.Name, Addrs: nonNil(z.Addrs), Source: z.Source})
		}
		if e.StubZones == nil {
			e.StubZones = []emittedZone{}
		}
		want(tier.Host+" stub zones", zones, e.StubZones)
		want(tier.Host+" local zones", nonNil(tier.LocalZones), nonNil(e.LocalZones))
		if m.FreeIPAPresent {
			var pool []emittedPoolMember
			for _, p := range m.Providers {
				pool = append(pool, emittedPoolMember{InventoryHost: p.InventoryHost, FQDN: p.FQDN, IP: p.IP, Kind: p.Kind, DNSProvider: p.DNSProvider})
			}
			want(tier.Host+" server pool", pool, e.Pool)
		}
	}

	if len(m.Resolvers) != len(inv.OrderedGroupHosts(FreeIPADNSClientGroup)) {
		t.Fatalf("model has %d resolvers, inventory %v", len(m.Resolvers), inv.OrderedGroupHosts(FreeIPADNSClientGroup))
	}
	for _, r := range m.Resolvers {
		var e struct {
			Servers []string `json:"servers"`
			Options []string `json:"options"`
		}
		if !readEmitted(t, out, "resolver", r.Host, &e) {
			t.Fatalf("playbook emitted nothing for resolver host %s", r.Host)
		}
		want(r.Host+" resolver servers", r.Servers, e.Servers)
		want(r.Host+" resolver options", nonNil(r.Options), nonNil(e.Options))
	}

	for _, p := range m.Providers {
		switch p.Kind {
		case "primary":
			var e struct {
				SetupDNS   bool     `json:"setup_dns"`
				Forwarders []string `json:"forwarders"`
			}
			if !readEmitted(t, out, "primary", p.InventoryHost, &e) {
				t.Fatalf("playbook emitted nothing for primary %s", p.InventoryHost)
			}
			want(p.InventoryHost+" installs DNS", p.DNSProvider, e.SetupDNS)
			if e.SetupDNS {
				install := m.Forwarding.ServerInstallForwarders[0]
				want(p.InventoryHost+" install forwarders", nonNil(install.Forwarders), nonNil(e.Forwarders))
				want(p.InventoryHost+" global forwarders", nonNil(m.Forwarding.GlobalForwarders), nonNil(e.Forwarders))
			}
		case "replica":
			var e struct {
				SetupDNS bool     `json:"setup_dns"`
				Argv     []string `json:"argv"`
			}
			if !readEmitted(t, out, "replica", p.InventoryHost, &e) {
				t.Fatalf("playbook emitted nothing for replica %s", p.InventoryHost)
			}
			want(p.InventoryHost+" installs DNS", p.DNSProvider, e.SetupDNS)
			for _, install := range m.Forwarding.ServerInstallForwarders {
				if install.Host != p.InventoryHost {
					continue
				}
				if install.Error != "" {
					t.Errorf("%s: model rejects the forwarders (%s), playbook argv %v", p.InventoryHost, install.Error, e.Argv)
					continue
				}
				wantArgv := []string{"--no-forwarders"}
				if len(install.Forwarders) > 0 {
					wantArgv = nil
					for _, f := range install.Forwarders {
						wantArgv = append(wantArgv, "--forwarder="+f)
					}
				}
				want(p.InventoryHost+" install argv", wantArgv, e.Argv)
			}
		}
	}

	// Nothing emitted for a host the model does not know about.
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	var emitted []string
	for _, entry := range entries {
		emitted = append(emitted, strings.TrimSuffix(entry.Name(), ".json"))
	}
	sort.Strings(emitted)
	known := map[string]bool{}
	for _, tier := range m.Tier {
		known["tier-"+tier.Host] = true
	}
	for _, r := range m.Resolvers {
		known["resolver-"+r.Host] = true
	}
	for _, p := range m.Providers {
		known[fmt.Sprintf("%s-%s", p.Kind, p.InventoryHost)] = true
	}
	for _, name := range emitted {
		if !known[name] {
			t.Errorf("playbook emitted %s, which the model has no entry for", name)
		}
	}
}
