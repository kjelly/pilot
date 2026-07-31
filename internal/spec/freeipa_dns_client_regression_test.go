package spec

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestRegression_FreeipaDNSClientSpec locks the structural contract of
// docs/verification/freeipa-dns-client.md: 6 rows C1..C6, lint-clean, and a
// generated diagnostic playbook that covers every row.
func TestRegression_FreeipaDNSClientSpec(t *testing.T) {
	const specPath = "../../docs/verification/freeipa-dns-client.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6"}
	if len(s.Rows) != len(wantIDs) {
		t.Fatalf("rows=%d want=%d", len(s.Rows), len(wantIDs))
	}
	gotIDs := make([]string, 0, len(s.Rows))
	seen := map[string]bool{}
	for _, row := range s.Rows {
		if seen[row.ID] {
			t.Errorf("duplicate row ID %q", row.ID)
		}
		seen[row.ID] = true
		gotIDs = append(gotIDs, row.ID)
		if strings.TrimSpace(row.Command) == "" || strings.TrimSpace(row.Expected) == "" {
			t.Errorf("row %s has an empty command or expected value", row.ID)
		}
	}
	if strings.Join(gotIDs, ",") != strings.Join(wantIDs, ",") {
		t.Errorf("row IDs=%v want=%v", gotIDs, wantIDs)
	}
	if findings := Lint(s); HasErrors(findings) {
		t.Errorf("spec lint errors:\n%s", fsToString(findings))
	}

	pb, err := Generate(s, GenerateOptions{IncludeRaw: true})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	out := pb.RenderYAML()
	var plays []map[string]any
	if err := yaml.Unmarshal([]byte(out), &plays); err != nil {
		t.Fatalf("generated playbook does not parse as YAML: %v\n--- output ---\n%s", err, out)
	}
	covered := map[string]bool{}
	for _, tk := range pb.Tasks {
		for _, id := range tk.SourceIDs {
			covered[id] = true
		}
	}
	for _, id := range wantIDs {
		if !covered[id] {
			t.Errorf("spec row %s is not covered by any generated task", id)
		}
	}
}

// freeipaDNSClientContract is a minimal local decode of
// contracts/freeipa-dns-client.yaml — just the fields this test locks — so
// this test doesn't need to import internal/contract (which itself imports
// internal/spec).
type freeipaDNSClientContract struct {
	ID              string                       `yaml:"id"`
	Role            string                       `yaml:"role"`
	HostCardinality string                       `yaml:"hostCardinality"`
	Dependencies    []freeipaDNSClientDependency `yaml:"dependencies"`
	Site            freeipaDNSClientSite         `yaml:"site"`
	Playbooks       map[string]string            `yaml:"playbooks"`
	RegressionTests []string                     `yaml:"regressionTests"`
	Specs           []freeipaDNSClientSpecPath   `yaml:"specs"`
	GroupVars       []freeipaDNSClientGroupVar   `yaml:"groupVars"`
}

type freeipaDNSClientDependency struct {
	Component string `yaml:"component"`
	Required  bool   `yaml:"required"`
	Relation  string `yaml:"relation"`
}

type freeipaDNSClientSite struct {
	Include bool `yaml:"include"`
	OptIn   bool `yaml:"optIn"`
}

type freeipaDNSClientSpecPath struct {
	Path string `yaml:"path"`
}

type freeipaDNSClientGroupVar struct {
	Name   string `yaml:"name"`
	Type   string `yaml:"type"`
	Secret bool   `yaml:"secret"`
}

// TestRegression_FreeipaDNSClientContract locks the contract-shape
// requirements the spec/design depends on: day-2/opt-in (site.include:
// false), a required providerEndpoint dependency on freeipa-server, an
// optional planOnly dependency on freeipa-server-replica (the fallback
// nameserver), hostCardinality: one-or-more (unlike freeipa-dns.md's
// exactly-one — this component runs on ANY number of target hosts, not just
// the FreeIPA server itself), and NO secret groupVars (unlike every other
// freeipa-* component, this one needs no vault password at all — it only
// reads inventory IPs).
func TestRegression_FreeipaDNSClientContract(t *testing.T) {
	const contractPath = "../../contracts/freeipa-dns-client.yaml"
	raw, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatalf("read %s: %v", contractPath, err)
	}
	var c freeipaDNSClientContract
	if err := yaml.Unmarshal(raw, &c); err != nil {
		t.Fatalf("unmarshal %s: %v", contractPath, err)
	}

	if c.ID != "freeipa-dns-client" {
		t.Errorf("id = %q, want freeipa-dns-client", c.ID)
	}
	if c.HostCardinality != "one-or-more" {
		t.Errorf("hostCardinality = %q, want one-or-more", c.HostCardinality)
	}
	if c.Site.Include || !c.Site.OptIn {
		t.Errorf("site = {include:%v optIn:%v}, want {include:false optIn:true} (day-2/opt-in, matches freeipa-dns/freeipa-server-replica)", c.Site.Include, c.Site.OptIn)
	}
	if c.Playbooks["apply"] != "playbooks/apply/freeipa-dns-client-apply.yml" {
		t.Errorf("playbooks.apply = %q, want playbooks/apply/freeipa-dns-client-apply.yml", c.Playbooks["apply"])
	}
	if len(c.Specs) != 1 || c.Specs[0].Path != "docs/verification/freeipa-dns-client.md" {
		t.Errorf("specs = %v, want exactly docs/verification/freeipa-dns-client.md", c.Specs)
	}

	depByComponent := map[string]freeipaDNSClientDependency{}
	for _, d := range c.Dependencies {
		depByComponent[d.Component] = d
	}
	server, ok := depByComponent["freeipa-server"]
	if !ok || !server.Required || server.Relation != "providerEndpoint" {
		t.Errorf("freeipa-server dependency = %+v, want {required:true relation:providerEndpoint}", server)
	}
	replica, ok := depByComponent["freeipa-server-replica"]
	if !ok || replica.Required || replica.Relation != "planOnly" {
		t.Errorf("freeipa-server-replica dependency = %+v, want {required:false relation:planOnly}", replica)
	}

	for _, gv := range c.GroupVars {
		if gv.Secret {
			t.Errorf("groupVar %q is secret=true; this component should need no vault password (it only reads inventory IPs)", gv.Name)
		}
	}
}

// TestRegression_FreeipaDNSClientApplyPlaybook_SelfFirstOrdering locks the
// single trickiest correctness property of the apply playbook: when THIS
// host is itself one of the discovered DNS providers (e.g. run against the
// freeipa-server host, or a replica with freeipa_setup_dns=true), its own
// resolver must be pointed at itself (127.0.0.1) FIRST, with the other
// providers as fallback — matching what ipa-server-install/
// ipa-replica-install already do on that host, so this playbook reconciles
// rather than conflicts. A future edit that drops the self-check or the
// 127.0.0.1 preference would silently make a FreeIPA DNS host depend on
// network reachability to itself for its own name resolution.
func TestRegression_FreeipaDNSClientApplyPlaybook_SelfFirstOrdering(t *testing.T) {
	const playbookPath = "../../playbooks/apply/freeipa-dns-client-apply.yml"
	raw, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	playbook := string(raw)

	if !strings.Contains(playbook, "127.0.0.1") {
		t.Errorf("playbook must prefer 127.0.0.1 when this host is itself a DNS provider")
	}
	if !strings.Contains(playbook, "inventory_hostname in (freeipa_dns_providers") {
		t.Errorf("playbook must check whether inventory_hostname is itself one of the discovered DNS providers")
	}
	if !strings.Contains(playbook, "rejectattr('host', 'equalto', inventory_hostname)") {
		t.Errorf("playbook must exclude this host's own entry from the fallback list (else it would list itself twice)")
	}
	// Explicit override must win over inventory auto-detection, checked
	// BEFORE the self-first branch — else -e freeipa_dns_client_servers=...
	// would be silently ignored on a host that also happens to be a
	// FreeIPA DNS provider.
	effectiveIdx := strings.Index(playbook, "freeipa_dns_client_effective_servers:")
	overrideIdx := strings.Index(playbook, "if (freeipa_dns_client_servers | length > 0)")
	selfFirstIdx := strings.Index(playbook, "['127.0.0.1']")
	if effectiveIdx == -1 || overrideIdx == -1 || selfFirstIdx == -1 {
		t.Fatalf("could not find the effective-servers computation (effectiveIdx=%d overrideIdx=%d selfFirstIdx=%d)", effectiveIdx, overrideIdx, selfFirstIdx)
	}
	if !(effectiveIdx < overrideIdx && overrideIdx < selfFirstIdx) {
		t.Errorf("explicit freeipa_dns_client_servers override must be checked before the self-first/auto-detect branch")
	}
}

// TestRegression_FreeipaDNSClientApplyPlaybook_MultiOSCoverage locks that
// both supported OS families keep real mutation tasks: Debian/Ubuntu via
// systemd-resolved (nss-resolve/resolvectl path) and EL/RHEL via
// NetworkManager (community.general.nmcli). RHEL hosts in this pilot are
// almost always FreeIPA-related (server/replica/EL client) — losing this
// branch would silently leave every such host unconfigured.
func TestRegression_FreeipaDNSClientApplyPlaybook_MultiOSCoverage(t *testing.T) {
	const playbookPath = "../../playbooks/apply/freeipa-dns-client-apply.yml"
	raw, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	playbook := string(raw)

	for _, required := range []string{
		"ansible_os_family == 'Debian'",
		"ansible_os_family == 'RedHat'",
		"resolved.conf.d",
		"community.general.nmcli",
		"dns4_search",
		"nmcli device reapply",
	} {
		if !strings.Contains(playbook, required) {
			t.Errorf("playbook must contain %q (multi-OS DNS resolver coverage)", required)
		}
	}
}
