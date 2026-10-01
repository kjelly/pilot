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

// docs/verification/dns.md + playbooks/apply/dns-apply.yml: the dns role
// (unbound caching tier in front of FreeIPA DNS, automatic split
// forwarding). These tests lock the spec's row/input contract, the
// "settings come from group_vars, never play vars" rule that the old
// core-infra-provider dns role broke, the "leave the host resolver alone"
// design (dns.md §2 B9), and the apply-time gates G2-G10 with both
// passing and triggering inputs (AGENTS.md §5.12).

const (
	dnsSpecPath       = "../../docs/verification/dns.md"
	dnsPlaybookPath   = "../../playbooks/apply/dns-apply.yml"
	dnsEndpointsPath  = "../../playbooks/apply/tasks/dns-tier-endpoints.yml"
	dnsTemplatePath   = "../../playbooks/apply/templates/dns-unbound.conf.j2"
	dnsResolverPath   = "../../playbooks/apply/tasks/freeipa-dns-client-resolver.yml"
	dnsExampleVarPath = "../../group_vars/dns.example.yml"
)

func TestRegression_DNSSpecContract(t *testing.T) {
	s, err := Parse(dnsSpecPath)
	if err != nil {
		t.Fatalf("parse %s: %v", dnsSpecPath, err)
	}
	if s.SchemaVersion != 2 {
		t.Fatalf("schemaVersion=%d want 2", s.SchemaVersion)
	}
	if !slices.Equal(s.Roles, []string{"dns"}) {
		t.Errorf("targets.roles=%v want [dns]", s.Roles)
	}
	if fs := Lint(s); HasErrors(fs) {
		t.Fatalf("lint errors:\n%s", joinFindings(fs))
	}
	if len(s.Rows) != 20 {
		t.Fatalf("rows=%d want 20", len(s.Rows))
	}
	tagged := map[string]bool{"C1": true, "C2": true, "C3": true, "C4": true, "C5": true, "C6": true,
		"C8": true, "C9": true, "C10": true, "C11": true, "C18": true}
	for i, r := range s.Rows {
		if want := fmt.Sprintf("C%d", i+1); r.ID != want {
			t.Errorf("row[%d] id=%s want %s", i, r.ID, want)
		}
		switch {
		case tagged[r.ID]:
			if !slices.Equal(r.Tags, []string{"dns-" + r.ID}) {
				t.Errorf("%s tags=%v want [dns-%s]", r.ID, r.Tags, r.ID)
			}
		default:
			if !r.VerifyOnly {
				t.Errorf("%s must be verifyOnly (end-to-end behavior, see the spec's Traceability)", r.ID)
			}
		}
	}
	// Every input is required: a forgotten value must stop verify before it
	// runs instead of silently skipping a row ("none" opts a feature out).
	for _, in := range s.Inputs {
		if !in.Required {
			t.Errorf("input %s must be required (use the explicit value none)", in.Name)
		}
	}
	c20 := s.Rows[19]
	if c20.Scope != "aggregate" || c20.Become == nil || *c20.Become {
		t.Errorf("C20 must be an aggregate, become=false controller row; got scope=%s become=%v", c20.Scope, c20.Become)
	}
}

func dnsPlay(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(dnsPlaybookPath)
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	if len(plays) != 1 {
		t.Fatalf("plays=%d want 1", len(plays))
	}
	return plays[0]
}

// Play vars beat inventory group_vars/host_vars (AGENTS.md §4.5 point 3).
// The old core-infra-provider play declared `dns_zones: []` there and
// every group_vars dns_zones was silently ignored.
func TestRegression_DNSApplyPlayVarsDoNotShadowInventory(t *testing.T) {
	vars, _ := dnsPlay(t)["vars"].(map[string]any)
	allowed := map[string]bool{
		"stage": true, "confirm_staging": true, "confirm_prod": true, "staging_attested_within_hours": true,
		"dns_unbound_conf_path": true, "dns_legacy_unbound_conf_path": true, "dns_snapshot_dir": true,
	}
	for k := range vars {
		if !allowed[k] {
			t.Errorf("play var %q: settings an inventory supplies must not be play vars; default them with | default() instead", k)
		}
	}
	// Every key the example offers must be read from the inventory by name.
	raw, err := os.ReadFile(dnsPlaybookPath)
	if err != nil {
		t.Fatal(err)
	}
	example, err := os.ReadFile(dnsExampleVarPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"dns_upstream", "dns_freeipa_zones", "dns_stub_zones", "dns_access_control",
		"dns_cache_max_ttl", "dns_cache_max_negative_ttl", "dns_dnssec_validation", "dns_zones", "dns_provider"} {
		if !strings.Contains(string(raw), key+" | default(") {
			t.Errorf("dns-apply.yml must read %s from the inventory with a | default()", key)
		}
		if key != "dns_provider" && !strings.Contains(string(example), key) {
			t.Errorf("group_vars/dns.example.yml must document %s", key)
		}
	}
}

// dns.md §2 B9: unbound binds 127.0.0.1 + the service address, so the
// playbook never needs to touch the host's own resolver.
func TestRegression_DNSApplyLeavesHostResolverAlone(t *testing.T) {
	for _, path := range []string{dnsPlaybookPath, dnsTemplatePath} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for n, line := range strings.Split(string(raw), "\n") {
			code := strings.TrimSpace(line)
			if strings.HasPrefix(code, "#") {
				continue
			}
			for _, banned := range []string{"/etc/resolv.conf", "resolved.conf", "DNSStubListener", "netplan"} {
				if strings.Contains(code, banned) {
					t.Errorf("%s:%d touches the host resolver (%q): %s", filepath.Base(path), n+1, banned, code)
				}
			}
			if strings.HasPrefix(code, "interface:") && strings.Contains(code, "0.0.0.0") {
				t.Errorf("%s:%d binds 0.0.0.0, which collides with the systemd-resolved stub", filepath.Base(path), n+1)
			}
		}
	}
}

// The tier and its consumers derive tier addresses from one task file.
func TestRegression_DNSTierEndpointsAreSingleSource(t *testing.T) {
	for _, path := range []string{dnsPlaybookPath, dnsResolverPath} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "dns-tier-endpoints.yml") {
			t.Errorf("%s must include tasks/dns-tier-endpoints.yml", filepath.Base(path))
		}
		if strings.Contains(string(raw), "dns_listen_addr") && path == dnsResolverPath {
			t.Errorf("%s must not re-derive tier addresses from dns_listen_addr", filepath.Base(path))
		}
	}
	raw, err := os.ReadFile(dnsResolverPath)
	if err != nil {
		t.Fatal(err)
	}
	expr := string(raw)
	if !strings.Contains(expr, "dns_tier_endpoints | map(attribute='addr')") || !strings.Contains(expr, ")[:3]") {
		t.Errorf("the resolver must put tier addresses first and cap the list at 3 (glibc MAXNS, dns.md §2 B10)")
	}
}

// ── gate behavior: run the always-tagged pre_tasks for real ──────────────

const dnsGateInventory = `all:
  children:
    dns:
      hosts:
        tier-1:
          ansible_connection: local
          ansible_python_interpreter: "{{ ansible_playbook_python }}"
          ansible_host: 192.0.2.10
    freeipa-server:
      hosts:
        ipa-1:
          ansible_host: 192.0.2.2
          freeipa_domain: IPA.Example.Internal
`

type dnsGateRun struct {
	rc       int
	failures []string
	facts    map[string]any
	raw      string
}

func runDNSGates(t *testing.T, inventory, groupVars string, extra map[string]any) dnsGateRun {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	playbook, err := filepath.Abs(dnsPlaybookPath)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "group_vars"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "inventory.yml"), []byte(inventory), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "group_vars", "dns.yml"), []byte(groupVars), 0o644); err != nil {
		t.Fatal(err)
	}
	vars := map[string]any{
		"ansible_become": false,
		// G10 compares the service address with the host's own addresses;
		// pin the fact so the test does not depend on the CI machine's IPs.
		"ansible_all_ipv4_addresses": []string{"192.0.2.10"},
	}
	for k, v := range extra {
		vars[k] = v
	}
	ev, err := json.Marshal(vars)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ansible-playbook", "-i", filepath.Join(dir, "inventory.yml"), playbook,
		"--check", "--tags", "always", "-e", string(ev))
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_STDOUT_CALLBACK=json", "ANSIBLE_NOCOLOR=1")
	out, runErr := cmd.Output()
	res := dnsGateRun{raw: string(out), facts: map[string]any{}}
	if ee, ok := runErr.(*exec.ExitError); ok {
		res.rc = ee.ExitCode()
	} else if runErr != nil {
		t.Fatalf("ansible-playbook did not run: %v", runErr)
	}
	var cb struct {
		Plays []struct {
			Tasks []struct {
				Task  struct{ Name string } `json:"task"`
				Hosts map[string]struct {
					Failed  bool           `json:"failed"`
					Msg     any            `json:"msg"`
					Facts   map[string]any `json:"ansible_facts"`
					Results []struct {
						Facts map[string]any `json:"ansible_facts"`
					} `json:"results"`
				} `json:"hosts"`
			} `json:"tasks"`
		} `json:"plays"`
	}
	if err := json.Unmarshal(out, &cb); err != nil {
		t.Fatalf("parse JSON callback output: %v\n%s", err, out)
	}
	for _, p := range cb.Plays {
		for _, task := range p.Tasks {
			for _, h := range task.Hosts {
				if h.Failed {
					msg, _ := json.Marshal(h.Msg)
					res.failures = append(res.failures, task.Task.Name+": "+string(msg))
				}
				for k, v := range h.Facts {
					res.facts[k] = v
				}
				// A looped set_fact reports each step under results[];
				// the last item holds the accumulated value.
				for _, item := range h.Results {
					for k, v := range item.Facts {
						res.facts[k] = v
					}
				}
			}
		}
	}
	return res
}

func TestRegression_DNSApplyGatesPass(t *testing.T) {
	// group_vars written the way pilot edit writes them: flow lists, a
	// quoted stub entry, and a legacy dns_zones block. Every value must
	// reach the play (the old play-var bug made dns_zones vanish).
	gv := `dns_upstream: [1.1.1.1, "9.9.9.9@5353"]
dns_freeipa_zones: [0.0.10.in-addr.arpa]
dns_stub_zones: ["corp.internal=10.0.1.2,10.0.1.3"]
dns_access_control: [10.0.0.0/8]
dns_cache_max_ttl: 120
dns_dnssec_validation: false
dns_zones:
  - name: Pilot.LAN.
    records:
      - {name: core, value: 10.0.0.53}
`
	res := runDNSGates(t, dnsGateInventory, gv, nil)
	if res.rc != 0 || len(res.failures) > 0 {
		t.Fatalf("valid settings must pass the gates; rc=%d failures=%v", res.rc, res.failures)
	}
	if got := res.facts["dns_mode"]; got != "freeipa-split" {
		t.Errorf("dns_mode=%v want freeipa-split (FreeIPA DNS in the inventory)", got)
	}
	if got := res.facts["dns_service_addr"]; got != "192.0.2.10" {
		t.Errorf("dns_service_addr=%v want the host's ansible_host", got)
	}
	names := []string{}
	for _, z := range res.facts["dns_stub_zone_list"].([]any) {
		zone := z.(map[string]any)
		names = append(names, zone["name"].(string))
		if zone["name"] == "ipa.example.internal" && fmt.Sprint(zone["addrs"]) != "[192.0.2.2]" {
			t.Errorf("FreeIPA stub addrs=%v want [192.0.2.2]", zone["addrs"])
		}
		if zone["name"] == "corp.internal" && fmt.Sprint(zone["addrs"]) != "[10.0.1.2 10.0.1.3]" {
			t.Errorf("dns_stub_zones addrs=%v want [10.0.1.2 10.0.1.3]", zone["addrs"])
		}
	}
	// freeipa_domain is lower-cased and comes from the freeipa-server host
	// (a dns host is not in the freeipa groups that group_vars/freeipa targets).
	if want := []string{"ipa.example.internal", "0.0.10.in-addr.arpa", "corp.internal"}; !slices.Equal(names, want) {
		t.Errorf("stub zones=%v want %v", names, want)
	}
	if got := fmt.Sprint(res.facts["dns_upstream_list"]); got != "[1.1.1.1 9.9.9.9@5353]" {
		t.Errorf("dns_upstream_list=%s", got)
	}
	locals := res.facts["dns_local_zone_list"].([]any)
	if len(locals) != 1 || locals[0].(map[string]any)["name"] != "pilot.lan" {
		t.Errorf("dns_zones from group_vars must reach the play, normalized; got %v", locals)
	}
	if fmt.Sprint(res.facts["dns_cache_max_ttl_effective"]) != "120" || res.facts["dns_dnssec_validation_effective"] != false {
		t.Errorf("cache/dnssec from group_vars lost: ttl=%v dnssec=%v", res.facts["dns_cache_max_ttl_effective"], res.facts["dns_dnssec_validation_effective"])
	}
}

func TestRegression_DNSApplyForwardOnlyAndStringUpstream(t *testing.T) {
	inv := strings.SplitN(dnsGateInventory, "    freeipa-server:", 2)[0]
	res := runDNSGates(t, inv, "dns_upstream: \"1.1.1.1 9.9.9.9\"\n", nil)
	if res.rc != 0 {
		t.Fatalf("rc=%d failures=%v", res.rc, res.failures)
	}
	if res.facts["dns_mode"] != "forward-only" {
		t.Errorf("dns_mode=%v want forward-only without FreeIPA", res.facts["dns_mode"])
	}
	if got := fmt.Sprint(res.facts["dns_upstream_list"]); got != "[1.1.1.1 9.9.9.9]" {
		t.Errorf("a space-separated dns_upstream string (old example form) must split; got %s", got)
	}
}

func TestRegression_DNSApplyGatesTrigger(t *testing.T) {
	prodInv := strings.Replace(dnsGateInventory, "    freeipa-server:", "    prod:\n      hosts:\n        tier-1:\n    freeipa-server:", 1)
	ipaToo := strings.Replace(dnsGateInventory, "        ipa-1:\n", "        ipa-1:\n        tier-1:\n", 1)
	noIPA := strings.SplitN(dnsGateInventory, "    freeipa-server:", 2)[0]
	cases := []struct {
		name, inv, gv string
		extra         map[string]any
		want          string
	}{
		{"G2 provider", dnsGateInventory, "", map[string]any{"dns_provider": "bind9"}, "Gate G2"},
		{"G3 also a FreeIPA server", ipaToo, "", nil, "Gate G3"},
		{"G4 allow-all ACL", dnsGateInventory, "dns_access_control: [0.0.0.0/0]\n", nil, "Gate G4"},
		{"G4 bracketed -e string", dnsGateInventory, "", map[string]any{"dns_upstream": "[1.1.1.1]"}, "Gate G4"},
		{"G4 stub entry without =", dnsGateInventory, "dns_stub_zones: [corp.internal]\n", nil, "Gate G4"},
		{"G4 duplicate zone", dnsGateInventory, "dns_stub_zones: [\"ipa.example.internal=10.0.0.1\"]\n", nil, "Gate G4"},
		{"G4 FreeIPA zones without FreeIPA", noIPA, "dns_freeipa_zones: [svc.example]\n", nil, "Gate G4"},
		{"G4 negative cache cap", dnsGateInventory, "dns_cache_max_ttl: -1\n", nil, "Gate G4"},
		{"G9 prod single host", prodInv, "", map[string]any{"stage": "prod", "confirm_prod": true}, "Gate G9"},
		{"G10 shared listen address", dnsGateInventory, "dns_listen_addr: 10.0.0.53\n", nil, "Gate G10"},
		{"G10 wildcard", dnsGateInventory, "dns_listen_addr: 0.0.0.0\n", nil, "Gate G10"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runDNSGates(t, tc.inv, tc.gv, tc.extra)
			if res.rc == 0 {
				t.Fatalf("expected %s to fail the play", tc.want)
			}
			joined := strings.Join(res.failures, "\n")
			if !strings.Contains(joined, tc.want) {
				t.Fatalf("expected a %q failure, got:\n%s", tc.want, joined)
			}
		})
	}
}

// ── rendered config ──────────────────────────────────────────────────────

func renderDNSTemplate(t *testing.T, vars map[string]any) string {
	t.Helper()
	if _, err := exec.LookPath("ansible"); err != nil {
		t.Skipf("ansible not installed: %v", err)
	}
	src, err := filepath.Abs(dnsTemplatePath)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	dest := filepath.Join(dir, "pilot-dns.conf")
	ev, err := json.Marshal(vars)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ansible", "localhost", "-c", "local", "-m", "ansible.builtin.template",
		"-a", "src="+src+" dest="+dest, "-e", string(ev))
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False", "ANSIBLE_INVENTORY_UNPARSED_WARNING=False")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("render: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestRegression_DNSUnboundTemplateRender(t *testing.T) {
	base := map[string]any{
		"dns_mode": "freeipa-split", "dns_service_addr": "192.0.2.10",
		"dns_access_control_list":     []string{"10.0.0.0/8"},
		"dns_cache_max_ttl_effective": 300, "dns_cache_max_negative_ttl_effective": 60,
		"dns_upstream_list": []string{"192.0.2.53", "192.0.2.54@5353"},
		"dns_stub_zone_list": []map[string]any{
			{"name": "ipa.example.internal", "addrs": []string{"192.0.2.2", "192.0.2.3"}, "source": "FreeIPA"},
			{"name": "2.0.192.in-addr.arpa", "addrs": []string{"192.0.2.2"}, "source": "FreeIPA"},
		},
		"dns_local_zone_list": []map[string]any{
			{"name": "pilot.lan", "records": []map[string]any{{"name": "core", "value": "10.0.0.53"}}},
		},
	}
	for _, dnssec := range []bool{true, false} {
		t.Run(fmt.Sprintf("dnssec=%v", dnssec), func(t *testing.T) {
			vars := map[string]any{"dns_dnssec_validation_effective": dnssec}
			for k, v := range base {
				vars[k] = v
			}
			conf := renderDNSTemplate(t, vars)
			for _, want := range []string{
				"interface: 127.0.0.1\n", "interface: 192.0.2.10\n", "access-control: 10.0.0.0/8 allow",
				`identity: "pilot-dns:localhost"`, "hide-version: yes", "cache-max-ttl: 300", "cache-max-negative-ttl: 60",
				"serve-expired: no", "forward-addr: 192.0.2.54@5353",
				// dns.md §2 B3: every stub zone gets a transparent local-zone,
				// so a built-in local zone (RFC1918 reverse) cannot shadow it.
				`local-zone: "ipa.example.internal." transparent`, `local-zone: "2.0.192.in-addr.arpa." transparent`,
				"stub-addr: 192.0.2.3", `local-data: "core.pilot.lan. IN A 10.0.0.53"`,
			} {
				if !strings.Contains(conf, want) {
					t.Errorf("rendered config lacks %q:\n%s", want, conf)
				}
			}
			insecure := strings.Contains(conf, `domain-insecure: "ipa.example.internal."`)
			validatorOff := strings.Contains(conf, `module-config: "iterator"`)
			if insecure != dnssec || validatorOff == dnssec {
				t.Errorf("dnssec=%v: domain-insecure=%v module-config iterator=%v", dnssec, insecure, validatorOff)
			}
			if path, err := exec.LookPath("unbound-checkconf"); err == nil {
				f := filepath.Join(t.TempDir(), "unbound.conf")
				// Run the fragment as a whole config: drop the bind to an
				// address this machine does not own, and do not require an
				// unbound system user or chroot on the test machine.
				body := strings.Replace(conf, "interface: 192.0.2.10\n", "", 1)
				body = strings.Replace(body, "server:\n", "server:\n    username: \"\"\n    chroot: \"\"\n    directory: \""+t.TempDir()+"\"\n", 1)
				if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
				if out, err := exec.Command(path, f).CombinedOutput(); err != nil {
					t.Errorf("unbound-checkconf rejects the rendered config: %v\n%s", err, out)
				}
			}
		})
	}
}
