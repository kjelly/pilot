package diagnose

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/networkcheck"
)

// Fixtures under testdata/dnsarch are the real stdout of the probe scripts
// in dns_architecture_probe.go, run through `ansible <host> -m command -a
// <the step's JSON args>` against a disposable vm-target topology (FreeIPA
// 4.13.4 on AlmaLinux 9.8 with DNS, an Ubuntu 24.04 dns tier host with
// unbound 1.19.2, an Ubuntu 24.04 freeipa-dns-client consumer), as the
// AGENTS.md §5.6 rule requires. Addresses are the libvirt network's.
// docs/evidence/dns-architecture-diagnose/ records the run. The
// tier_external_* and client_el* captures came the same way from two
// single disposable VMs: an Ubuntu 24.04.4 host with only the dns role
// (unbound 1.19.2-1ubuntu3.10, forward-only to 1.1.1.1) and a stock
// AlmaLinux 9.8 host without systemd-resolved.
func fixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "dnsarch", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func fixtureResult(t *testing.T, stepID, name string) StepResult {
	t.Helper()
	return StepResult{Step: Step{ID: stepID}, Result: AdHocResult{Stdout: fixture(t, name)}}
}

// ---- scripts --------------------------------------------------------------------

// The step args go to Ansible as a JSON object, which Ansible templates:
// a Jinja delimiter in a script would be evaluated, and `${#var}` contains
// one. Every arg must stay one argv element.
func TestDNSArchScriptsHaveNoJinjaDelimiters(t *testing.T) {
	for name, script := range map[string]string{
		"provider": dnsArchProviderScript, "auth": dnsArchAuthScript,
		"tier": dnsArchTierScript, "client": dnsArchClientScript,
	} {
		for _, delim := range []string{"{{", "{%", "{#"} {
			if strings.Contains(script, delim) {
				t.Errorf("%s script contains Jinja delimiter %q", name, delim)
			}
		}
	}
	step := DNSArchTierStep("t1", "ipa1.example.test", ".", "example.test", []string{"192.0.2.1", "192.0.2.2"})
	var args struct {
		Argv []string `json:"argv"`
	}
	if err := json.Unmarshal([]byte(step.Command), &args); err != nil {
		t.Fatalf("step command is not JSON: %v", err)
	}
	want := []string{"sh", "-c", dnsArchTierScript, "pilot-dnsarch", "ipa1.example.test", ".", "example.test", "192.0.2.1", "192.0.2.2"}
	if !reflect.DeepEqual(args.Argv, want) {
		t.Fatalf("argv = %q, want %q", args.Argv, want)
	}
	if step.Module != "command" {
		t.Fatalf("module = %q, want command (no shell interprets the args)", step.Module)
	}
	// The auth step never carries anything but the principal and keytab
	// path: no password, no admin fallback.
	auth := DNSArchAuthStep("ipa", "reader/ipa1.example.test@EXAMPLE.TEST", "/etc/pilot/reader.keytab")
	if !strings.Contains(auth.Command, `"reader/ipa1.example.test@EXAMPLE.TEST","/etc/pilot/reader.keytab"]`) {
		t.Fatalf("auth step args = %s", auth.Command)
	}
	for _, forbidden := range []string{"admin", "password", "KRB5CCNAME=KCM", "kinit admin"} {
		if strings.Contains(dnsArchAuthScript, forbidden) {
			t.Errorf("auth script mentions %q", forbidden)
		}
	}
	if !strings.Contains(dnsArchAuthScript, `trap "kdestroy -q -c FILE:$cc`) {
		t.Error("auth script must destroy its private ccache on exit")
	}
}

// ---- section and output parsers ----------------------------------------------------

func TestParseDNSArchSections(t *testing.T) {
	sections := ParseDNSArchSections(fixture(t, "tier_stopped.txt"))
	if s := sections["unbound"]; !s.Complete || s.RC != 3 || s.Output != "inactive" {
		t.Fatalf("unbound section = %+v", s)
	}
	if s := sections["authority@192.168.122.5"]; !s.Complete || s.RC != 0 {
		t.Fatalf("authority section = %+v", s)
	}
	// A step that timed out mid-script leaves an open section.
	cut := ParseDNSArchSections("@@pilot-dnsarch whoami begin\nroot\n@@pilot-dnsarch whoami end rc=0\n@@pilot-dnsarch soa begin\n;; Got answer:\n")
	if !cut["whoami"].Complete || cut["soa"].Complete {
		t.Fatalf("sections = %+v, want whoami complete and soa incomplete", cut)
	}
}

func TestParseDigComments_RealCaptures(t *testing.T) {
	provider := ParseDNSArchSections(fixture(t, "provider.txt"))
	soa := ParseDigComments("192.168.122.5", "ipa.pilot.internal.", "SOA", provider["soa"].Output, provider["soa"].RC)
	if soa.Status != "NOERROR" || !soa.Authoritative || len(soa.Answers) != 1 || !strings.HasPrefix(soa.Answers[0], "ipa1.ipa.pilot.internal. hostmaster.") {
		t.Fatalf("soa = %+v", soa)
	}
	srv := ParseDigComments("192.168.122.5", "_ldap._tcp.ipa.pilot.internal.", "SRV", provider["srv_ldap"].Output, 0)
	if len(srv.Answers) != 1 || srv.Answers[0] != "0 100 389 ipa1.ipa.pilot.internal." {
		t.Fatalf("srv = %+v", srv)
	}

	tier := ParseDNSArchSections(fixture(t, "tier.txt"))
	internal := ParseDigComments("127.0.0.1", "ipa1.ipa.pilot.internal", "A", tier["internal"].Output, 0)
	if internal.Status != "NOERROR" || internal.Authoritative || !reflect.DeepEqual(internal.Answers, []string{"192.168.122.5"}) {
		t.Fatalf("internal via tier = %+v", internal)
	}
	external := ParseDigComments("127.0.0.1", ".", "NS", tier["external"].Output, 0)
	if external.Status != "NOERROR" || len(external.Answers) != 13 {
		t.Fatalf("external via tier = %+v", external)
	}

	// Should trigger: dig exits 9 with a diagnostic and no header when
	// nothing answers; that is an error, never "no records".
	failures := ParseDNSArchSections(fixture(t, "tier_failures.txt"))
	timeout := ParseDigComments("192.0.2.1", "ipa.pilot.internal.", "SOA", failures["authority@192.0.2.1"].Output, failures["authority@192.0.2.1"].RC)
	if timeout.Error != "communications error to 192.0.2.1#53: timed out; no servers could be reached" || timeout.Status != "" {
		t.Fatalf("timeout = %+v", timeout)
	}
	nx := ParseDigComments("127.0.0.1", "nx-pilot-dnsarch.ipa.pilot.internal", "A", failures["internal"].Output, 0)
	if nx.Status != "NXDOMAIN" || nx.Error != "" || len(nx.Answers) != 0 {
		t.Fatalf("nxdomain = %+v", nx)
	}
	refused := ParseDNSArchSections(fixture(t, "tier_stopped.txt"))["external"]
	if q := ParseDigComments("127.0.0.1", ".", "NS", refused.Output, refused.RC); !strings.Contains(q.Error, "connection refused") {
		t.Fatalf("refused = %+v", q)
	}
}

func TestParseUnboundZoneList_RealCapture(t *testing.T) {
	tier := ParseDNSArchSections(fixture(t, "tier.txt"))
	forwards := ParseUnboundZoneList(tier["forwards"].Output, "forward")
	if !reflect.DeepEqual(forwards, []DNSArchZoneServers{{Zone: ".", Servers: []string{"1.1.1.1"}}}) {
		t.Fatalf("forwards = %+v", forwards)
	}
	stubs := ParseUnboundZoneList(tier["stubs"].Output, "stub")
	if len(stubs) != 2 || stubs[0].Zone != "." || !reflect.DeepEqual(stubs[1], DNSArchZoneServers{Zone: "ipa.pilot.internal.", Servers: []string{"192.168.122.5"}}) {
		t.Fatalf("stubs = %+v", stubs)
	}
	// The documented two-server forms (docs/verification/dns.md §0.2).
	got := ParseUnboundZoneList("ipa.pilot.internal. IN stub noprime +i 192.0.2.1 192.168.122.2\n. IN forward 1.1.1.1 9.9.9.9", "forward")
	if !reflect.DeepEqual(got, []DNSArchZoneServers{{Zone: ".", Servers: []string{"1.1.1.1", "9.9.9.9"}}}) {
		t.Fatalf("forward list = %+v", got)
	}
}

func TestParseIPAOutput_RealCaptures(t *testing.T) {
	sections := ParseDNSArchSections(fixture(t, "auth_role.txt"))
	cfg := firstIPAEntry(sections["dnsconfig"])
	if cfg["Global forwarders"] != "8.8.8.8" || cfg["IPA DNS servers"] != "ipa1.ipa.pilot.internal" {
		t.Fatalf("dnsconfig = %v", cfg)
	}
	if rights := ParseIPARights(cfg["attributelevelrights"]); rights["idnsforwarders"] != "r" || rights["aci"] != "" {
		t.Fatalf("rights = %v", rights)
	}
	servers := ParseIPAAttributes(sections["dnsserver"].Output)
	if len(servers) != 1 || servers[0]["Forwarders"] != "8.8.8.8" || servers[0]["Forward policy"] != "only" {
		t.Fatalf("dnsserver = %v", servers)
	}
	zones := ParseIPAAttributes(sections["zones"].Output)
	if len(zones) != 4 || zones[1]["Zone name"] != "ipa.pilot.internal." {
		t.Fatalf("zones = %v", zones)
	}
	if got := SplitIPAList("192.0.2.1, 192.0.2.2"); !reflect.DeepEqual(got, []string{"192.0.2.1", "192.0.2.2"}) {
		t.Fatalf("SplitIPAList = %v", got)
	}
}

// ---- FreeIPA configuration and Kerberos -------------------------------------------

func TestBuildDNSArchObservedFreeIPA_ReadOnlyRoleReadsEverything(t *testing.T) {
	out, k := BuildDNSArchObservedFreeIPA("dd-ipa", "reader@IPA.PILOT.INTERNAL", "/etc/pilot/r.keytab", fixtureResult(t, "freeipa-config-dd-ipa", "auth_role.txt"))
	if k.State != "available" {
		t.Fatalf("kerberos = %+v", k)
	}
	if out.GlobalForwarders.State != FactObserved || !reflect.DeepEqual(out.GlobalForwarders.Value, []string{"8.8.8.8"}) {
		t.Fatalf("global forwarders = %+v", out.GlobalForwarders)
	}
	if out.ForwardPolicy.State != FactAbsent {
		t.Fatalf("global forward policy = %+v, want absent (unset, readable)", out.ForwardPolicy)
	}
	servers := out.ServerForwarders.Value.([]DNSArchServerForwarders)
	if servers[0].Server != "ipa1.ipa.pilot.internal" || servers[0].ForwardPolicy != "only" {
		t.Fatalf("server forwarders = %+v", servers)
	}
	zones := out.ForwardZones.Value.([]DNSArchForwardZone)
	if zones[0].Zone != "fwtest.example." || zones[0].Forwarders[0] != "192.0.2.53" || zones[0].ForwardPolicy != "only" {
		t.Fatalf("forward zones = %+v", zones)
	}
	if len(out.Zones.Value.([]string)) != 4 {
		t.Fatalf("zones = %+v", out.Zones)
	}
	if got := out.GlobalForwarders.Evidence; !reflect.DeepEqual(got, []string{"step:freeipa-config-dd-ipa#dnsconfig"}) {
		t.Fatalf("evidence = %v", got)
	}
}

// FreeIPA answers a principal without the DNS read permissions with "Global
// DNS configuration is empty" and "Number of entries returned 0" (rc 1),
// the same as when nothing exists. Reporting that as "no forwarders" would
// be a false absent; it must be permission_denied.
func TestBuildDNSArchObservedFreeIPA_MissingPermissionIsNotAbsent(t *testing.T) {
	out, k := BuildDNSArchObservedFreeIPA("dd-ipa", "reader@IPA.PILOT.INTERNAL", "/etc/pilot/r.keytab", fixtureResult(t, "freeipa-config-dd-ipa", "auth_norole.txt"))
	if k.State != "available" {
		t.Fatalf("kerberos = %+v, want available (kinit worked)", k)
	}
	for name, f := range map[string]DNSArchFact{
		"global forwarders": out.GlobalForwarders, "forward policy": out.ForwardPolicy,
		"server forwarders": out.ServerForwarders, "zones": out.Zones, "forward zones": out.ForwardZones,
	} {
		if f.State != FactPermissionDenied {
			t.Errorf("%s = %+v, want permission_denied", name, f)
		}
	}
	// Should pass: the same empty answers are absent when the rights
	// show the principal could read them and FreeIPA serves no DNS.
	empty := "@@pilot-dnsarch kinit begin\n@@pilot-dnsarch kinit end rc=0\n" +
		"@@pilot-dnsarch dnsconfig begin\n  dn: cn=dns,dc=x\n  attributelevelrights: {'idnsforwardpolicy': 'r', 'idnsforwarders': 'r'}\n@@pilot-dnsarch dnsconfig end rc=0\n" +
		"@@pilot-dnsarch forwardzones begin\n----------------------------\nNumber of entries returned 0\n----------------------------\n@@pilot-dnsarch forwardzones end rc=1\n"
	out, _ = BuildDNSArchObservedFreeIPA("ipa", "r@X", "/k", StepResult{Step: Step{ID: "s"}, Result: AdHocResult{Stdout: empty}})
	if out.GlobalForwarders.State != FactAbsent || out.ForwardZones.State != FactAbsent {
		t.Fatalf("readable empty config = %+v / %+v, want absent", out.GlobalForwarders, out.ForwardZones)
	}
}

func TestBuildDNSArchObservedFreeIPA_KinitFailureIsAuthRequired(t *testing.T) {
	out, k := BuildDNSArchObservedFreeIPA("dd-ipa", "reader@IPA.PILOT.INTERNAL", "/etc/pilot/missing.keytab", fixtureResult(t, "freeipa-config-dd-ipa", "kinit_missing.txt"))
	if k.State != FactAuthRequired || !strings.Contains(k.Detail, "Pre-authentication failed") {
		t.Fatalf("kerberos = %+v", k)
	}
	if out.GlobalForwarders.State != FactAuthRequired || out.ForwardZones.State != FactAuthRequired {
		t.Fatalf("facts = %+v", out)
	}
	unreachable := StepResult{Step: Step{ID: "s"}, Result: AdHocResult{Unreachable: true, Stdout: "Task failed: Failed to connect to the host via ssh"}}
	if _, k := BuildDNSArchObservedFreeIPA("gone", "r@X", "/k", unreachable); k.State != FactUnreachable {
		t.Fatalf("unreachable kerberos = %+v", k)
	}
}

// ---- tier, provider and client observations --------------------------------------

func tierHost() DNSArchTierHost {
	return DNSArchTierHost{Host: "dd-dns", State: "computed", Addr: "192.168.122.15", Mode: "freeipa-split", Upstream: []string{"1.1.1.1"},
		FreeIPAServers: []string{"192.168.122.5"}, StubZones: []DNSArchZone{{Name: "ipa.pilot.internal", Addrs: []string{"192.168.122.5"}, Source: "FreeIPA"}}}
}

func TestBuildDNSArchObservedTier_RealCaptures(t *testing.T) {
	ot := BuildDNSArchObservedTier(tierHost(), "ipa1.ipa.pilot.internal", ".", []string{"192.168.122.5"}, "ipa.pilot.internal", fixtureResult(t, "tier-dd-dns", "tier.txt"))
	if ot.UnboundActive.Value != true || ot.Identity.Value != "pilot-dns:dd-dns" || ot.RemoteUser != "root" {
		t.Fatalf("tier = %+v", ot)
	}
	if ot.ExternalResolution.State != FactObserved || !strings.Contains(ot.ExternalResolution.Detail, "not which upstream answered") {
		t.Fatalf("external = %+v", ot.ExternalResolution)
	}
	if q := ot.ProviderAuthority[0].Value.(DNSQueryResult); ot.ProviderAuthority[0].State != FactObserved || !q.Authoritative {
		t.Fatalf("authority = %+v", ot.ProviderAuthority[0])
	}

	stopped := BuildDNSArchObservedTier(tierHost(), "ipa1.ipa.pilot.internal", ".", []string{"192.168.122.5"}, "ipa.pilot.internal", fixtureResult(t, "tier-dd-dns", "tier_stopped.txt"))
	if stopped.UnboundActive.Value != false || stopped.Forwards.State != FactUnknown || stopped.Identity.State != FactUnknown || stopped.ExternalResolution.State != FactUnknown {
		t.Fatalf("stopped tier = %+v", stopped)
	}

	unreachable := BuildDNSArchObservedTier(tierHost(), "x", ".", nil, "", StepResult{Step: Step{ID: "tier-dd-dns"}, Result: AdHocResult{Unreachable: true, Stdout: "ssh: connect to host 192.0.2.1 port 22: Connection timed out"}})
	if unreachable.Reachable.State != FactUnreachable || unreachable.Forwards.State != FactUnknown {
		t.Fatalf("unreachable tier = %+v", unreachable)
	}
}

func TestBuildDNSArchObservedProviderAndClient_RealCaptures(t *testing.T) {
	p := DNSArchProvider{InventoryHost: "dd-ipa", Kind: "primary", FQDN: "ipa1.ipa.pilot.internal", IP: "192.168.122.5", DNSProvider: true}
	op := BuildDNSArchObservedProvider(p, "ipa.pilot.internal", "ipa1.ipa.pilot.internal", fixtureResult(t, "provider-dd-ipa", "provider.txt"))
	if op.NamedActive.Value != true || op.SOA.State != FactObserved || op.KerberosSRV.State != FactObserved || op.RemoteUser != "root" {
		t.Fatalf("provider = %+v", op)
	}
	c := BuildDNSArchObservedClient("dd-client", fixtureResult(t, "client-dd-client", "client.txt"))
	if !reflect.DeepEqual(c.Nameservers.Value, []string{"192.168.122.15", "192.168.122.5"}) || c.FirstHop.Value != "pilot-dns:dd-dns" || c.Lookup.State != FactObserved {
		t.Fatalf("client = %+v", c)
	}
}

// ---- model --------------------------------------------------------------------------

// inv builds a ResolvedInventory the way ParseInventoryList would: group
// order as listed, values as JSON decodes them.
func inv(groups map[string][]string, hostvars map[string]map[string]any) networkcheck.ResolvedInventory {
	r := networkcheck.ResolvedInventory{GroupHosts: map[string][]string{}, GroupOrder: map[string][]string{}, HostVars: hostvars}
	for g, hosts := range groups {
		r.GroupOrder[g] = hosts
		r.GroupHosts[g] = sortedCopy(hosts)
	}
	return r
}

func TestBuildDNSArchitectureModel_Scenarios(t *testing.T) {
	ipa := map[string]any{"ansible_host": "10.0.0.5", "freeipa_domain": "Example.Test."}
	cases := []struct {
		name  string
		inv   networkcheck.ResolvedInventory
		check func(t *testing.T, m DNSArchModel)
	}{
		{"no dns tier: consumers use FreeIPA only", inv(
			map[string][]string{"freeipa-server": {"ipa"}, "freeipa-dns-client": {"c1"}},
			map[string]map[string]any{"ipa": ipa, "c1": {"ansible_host": "10.0.0.9"}}),
			func(t *testing.T, m DNSArchModel) {
				if m.TierAssigned || m.FreeIPADomain != "example.test" || m.Forwarding.State != "configured" || m.Forwarding.GlobalForwarders[0] != "8.8.8.8" {
					t.Fatalf("model = %+v", m)
				}
				if r := m.Resolvers[0]; r.Selection != "freeipa_only" || !reflect.DeepEqual(r.Servers, []string{"10.0.0.5"}) || r.Options != nil {
					t.Fatalf("resolver = %+v", r)
				}
			}},
		{"split tier: tier first, FreeIPA last, at most 3", inv(
			map[string][]string{"freeipa-server": {"ipa"}, "dns": {"t2", "t1", "t3"}, "freeipa-dns-client": {"c1"}},
			map[string]map[string]any{"ipa": ipa, "t1": {"ansible_host": "10.0.0.11"}, "t2": {"ansible_host": "10.0.0.12", "dns_listen_addr": "10.1.0.12"}, "t3": {"ansible_host": "10.0.0.13", "dns_upstream": "9.9.9.9, 1.1.1.1", "dns_freeipa_zones": []any{"Svc.Example.Test."}}, "c1": {}}),
			func(t *testing.T, m DNSArchModel) {
				if r := m.Resolvers[0]; r.Selection != "tier_first" || !reflect.DeepEqual(r.Servers, []string{"10.1.0.12", "10.0.0.11", "10.0.0.13"}) || len(r.Options) != 2 {
					t.Fatalf("resolver = %+v", r)
				}
				t3 := m.Tier[2]
				if t3.Mode != "freeipa-split" || !reflect.DeepEqual(t3.Upstream, []string{"9.9.9.9", "1.1.1.1"}) || len(t3.StubZones) != 2 || t3.StubZones[1].Name != "svc.example.test" {
					t.Fatalf("t3 = %+v", t3)
				}
			}},
		{"primary only without DNS: tier is forward-only and dns_freeipa_zones is a G4 error", inv(
			map[string][]string{"freeipa-server": {"ipa"}, "dns": {"t1"}},
			map[string]map[string]any{"ipa": {"ansible_host": "10.0.0.5", "freeipa_setup_dns": false}, "t1": {"dns_freeipa_zones": "svc.example.test"}}),
			func(t *testing.T, m DNSArchModel) {
				if m.Tier[0].Mode != "forward-only" || len(m.Tier[0].Errors) != 1 || m.Forwarding.State != "not_applicable" {
					t.Fatalf("model = %+v", m)
				}
				if m.Tier[0].Addr != "t1" {
					t.Fatalf("tier addr = %q, want the inventory name when ansible_host is unset", m.Tier[0].Addr)
				}
			}},
		// r2 leaves freeipa_setup_dns unset: the replica playbook installs
		// DNS on it, so it is a DNS provider like r1 (issue #67).
		{"DNS-enabled replicas join the stubs and the resolver fallback", inv(
			map[string][]string{"freeipa-server": {"ipa"}, "freeipa-server-replica": {"r1", "r2"}, "dns": {"t1"}, "freeipa-dns-client": {"c1"}},
			map[string]map[string]any{"ipa": ipa, "r1": {"ansible_host": "10.0.0.6", "freeipa_setup_dns": "yes", "freeipa_replica_fqdn": "ipa2.example.test", "freeipa_dns_forwarders": []any{"9.9.9.9"}}, "r2": {"ansible_host": "10.0.0.7", "freeipa_replica_fqdn": "ipa3.example.test"}, "t1": {"ansible_host": "10.0.0.11"}, "c1": {}}),
			func(t *testing.T, m DNSArchModel) {
				if !reflect.DeepEqual(m.DNSProviderIPs(), []string{"10.0.0.5", "10.0.0.6", "10.0.0.7"}) || len(m.ProviderErrors) != 0 {
					t.Fatalf("providers = %+v errors %v", m.Providers, m.ProviderErrors)
				}
				if !reflect.DeepEqual(m.Tier[0].StubZones[0].Addrs, []string{"10.0.0.5", "10.0.0.6", "10.0.0.7"}) {
					t.Fatalf("stub = %+v", m.Tier[0].StubZones)
				}
				// At most 3 nameservers: the tier, then the first two providers.
				if r := m.Resolvers[0]; !reflect.DeepEqual(r.Servers, []string{"10.0.0.11", "10.0.0.5", "10.0.0.6"}) {
					t.Fatalf("resolver = %+v", r)
				}
				// r2's install-time forwarders: none (freeipa_dns_forwarders unset).
				if f := m.Forwarding.ServerInstallForwarders; len(f) != 3 || f[1].Host != "r1" || f[1].Forwarders[0] != "9.9.9.9" || f[2].Host != "r2" || len(f[2].Forwarders) != 0 {
					t.Fatalf("install forwarders = %+v", f)
				}
			}},
		{"explicit client override wins; provider resolves through itself", inv(
			map[string][]string{"freeipa-server": {"ipa"}, "freeipa-server-replica": {"r1"}, "dns": {"t1"}, "freeipa-dns-client": {"c1", "r1"}},
			map[string]map[string]any{"ipa": ipa, "r1": {"ansible_host": "10.0.0.6", "freeipa_setup_dns": true}, "t1": {}, "c1": {"freeipa_dns_client_servers": []any{"10.9.9.9"}}}),
			func(t *testing.T, m DNSArchModel) {
				if r := m.Resolvers[0]; r.Selection != "explicit_override" || !reflect.DeepEqual(r.Servers, []string{"10.9.9.9"}) {
					t.Fatalf("c1 = %+v", r)
				}
				if r := m.Resolvers[1]; r.Selection != "provider_self" || !reflect.DeepEqual(r.Servers, []string{"127.0.0.1", "10.0.0.5"}) {
					t.Fatalf("r1 = %+v", r)
				}
			}},
		{"invalid inputs fail closed the way the playbooks do", inv(
			map[string][]string{"freeipa-server": {"ipa"}, "freeipa-server-replica": {"r1", "r2"}, "freeipa-dns-client": {"c1"}},
			map[string]map[string]any{"ipa": ipa, "r1": {"ansible_host": "10.0.0.5", "freeipa_dns_forwarders": float64(5)}, "r2": {}, "c1": {"freeipa_dns_client_servers": "[10.0.0.10]"}}),
			func(t *testing.T, m DNSArchModel) {
				// Both replicas also default to ipa2.<domain>, so the pool
				// has a duplicate FQDN as well.
				if len(m.ProviderErrors) != 4 {
					t.Fatalf("provider errors = %v, want two missing replica FQDNs, a reused IP and a duplicate FQDN", m.ProviderErrors)
				}
				if r := m.Resolvers[0]; r.Error == "" {
					t.Fatalf("c1 = %+v, want the list-type gate error", r)
				}
				if f := m.Forwarding.ServerInstallForwarders[1]; f.Host != "r1" || !strings.Contains(f.Error, "neither a list nor a string") {
					t.Fatalf("r1 install forwarders = %+v", f)
				}
			}},
		{"templated values are unknown, not guessed", inv(
			map[string][]string{"freeipa-server": {"ipa"}, "dns": {"t1"}, "freeipa-dns-client": {"c1"}},
			map[string]map[string]any{"ipa": ipa, "t1": {"dns_upstream": "{{ upstreams }}"}, "c1": {}}),
			func(t *testing.T, m DNSArchModel) {
				if m.Tier[0].State != "unknown" || m.Tier[0].Unevaluated[0] != "inventory:hostvars[t1].dns_upstream" {
					t.Fatalf("tier = %+v", m.Tier[0])
				}
				if m.Resolvers[0].State != "computed" {
					t.Fatalf("resolver = %+v, want computed (it does not read dns_upstream)", m.Resolvers[0])
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.check(t, BuildDNSArchitectureModel(tc.inv)) })
	}
}

func TestBuildDNSArchitectureModel_ExtraResolverHostAndBound(t *testing.T) {
	hosts := make([]string, MaxDNSArchResolvers+5)
	hv := map[string]map[string]any{"ipa": {"ansible_host": "10.0.0.5"}}
	for i := range hosts {
		hosts[i] = "c" + strings.Repeat("x", i)
		hv[hosts[i]] = map[string]any{}
	}
	m := BuildDNSArchitectureModel(inv(map[string][]string{"freeipa-server": {"ipa"}, "freeipa-dns-client": hosts}, hv))
	if len(m.Resolvers) != MaxDNSArchResolvers || !m.ResolversTruncated {
		t.Fatalf("resolvers = %d truncated=%v", len(m.Resolvers), m.ResolversTruncated)
	}
	m = BuildDNSArchitectureModel(inv(map[string][]string{"freeipa-server": {"ipa"}}, map[string]map[string]any{"ipa": {"ansible_host": "10.0.0.5"}, "web": {}}), "web")
	if len(m.Resolvers) != 1 || m.Resolvers[0].Host != "web" || m.Resolvers[0].ManagedBy != nil {
		t.Fatalf("resolvers = %+v", m.Resolvers)
	}
}

// ---- differences and status ---------------------------------------------------------

func liveTopology(t *testing.T) (DNSArchModel, DNSArchObserved) {
	t.Helper()
	m := BuildDNSArchitectureModel(inv(
		map[string][]string{"freeipa-server": {"dd-ipa"}, "dns": {"dd-dns"}, "freeipa-dns-client": {"dd-client"}},
		map[string]map[string]any{"dd-ipa": {"ansible_host": "192.168.122.5"}, "dd-dns": {"ansible_host": "192.168.122.15"}, "dd-client": {"ansible_host": "192.168.122.9"}}), "dd-client")
	var o DNSArchObserved
	o.Providers = []DNSArchObservedProvider{BuildDNSArchObservedProvider(m.Providers[0], m.FreeIPADomain, "ipa1.ipa.pilot.internal", fixtureResult(t, "provider-dd-ipa", "provider.txt"))}
	o.FreeIPA, o.Kerberos = BuildDNSArchObservedFreeIPA("dd-ipa", "reader@IPA.PILOT.INTERNAL", "/etc/pilot/r.keytab", fixtureResult(t, "freeipa-config-dd-ipa", "auth_role.txt"))
	o.Tier = []DNSArchObservedTier{BuildDNSArchObservedTier(m.Tier[0], "ipa1.ipa.pilot.internal", ".", m.DNSProviderIPs(), m.FreeIPADomain, fixtureResult(t, "tier-dd-dns", "tier.txt"))}
	c := BuildDNSArchObservedClient("dd-client", fixtureResult(t, "client-dd-client", "client.txt"))
	o.Client = &c
	return m, o
}

func diffBySubject(diffs []DNSArchDifference, prefix string) (DNSArchDifference, bool) {
	for _, d := range diffs {
		if strings.HasPrefix(d.Subject, prefix) {
			return d, true
		}
	}
	return DNSArchDifference{}, false
}

func TestBuildDNSArchDifferences_LiveTopologyMatches(t *testing.T) {
	m, o := liveTopology(t)
	diffs := BuildDNSArchDifferences(m, o)
	for _, d := range diffs {
		if d.Status != "match" {
			t.Errorf("%s: status %s (%s), want match", d.Subject, d.Status, d.Detail)
		}
		if len(d.Evidence) == 0 {
			t.Errorf("%s has no evidence reference", d.Subject)
		}
	}
	for _, subject := range []string{"tier dd-dns forward zone .", "tier dd-dns stub zone ipa.pilot.internal", "tier dd-dns identity", "FreeIPA dd-ipa authoritative", "FreeIPA global forwarders", "FreeIPA dd-ipa server forwarders", "tier dd-dns answer for ipa1.ipa.pilot.internal", "client dd-client nameservers"} {
		if _, ok := diffBySubject(diffs, subject); !ok {
			t.Errorf("no comparison for %q in %+v", subject, diffs)
		}
	}
	status, findings := BuildDNSArchStatus(m, o, diffs)
	if status != "complete" || len(findings) != 1 || !strings.HasPrefix(findings[0], "external_resolution_forwarder_unproven") {
		t.Fatalf("status %s findings %v", status, findings)
	}
	paths := strings.Join(BuildDNSArchPaths(m, o), "\n")
	for _, want := range []string{"ipa.pilot.internal → 192.168.122.5 (FreeIPA)", "external . → 1.1.1.1", "server forwarders 8.8.8.8 (policy only)", "fwtest.example. → 192.0.2.53 (only)", "resolver dd-client (freeipa-dns-client, tier_first) → 192.168.122.15, 192.168.122.5"} {
		if !strings.Contains(paths, want) {
			t.Errorf("paths missing %q:\n%s", want, paths)
		}
	}
}

// Should trigger: every declared value pilot can compare is reported as a
// mismatch, with the inventory reference and the live step, when the live
// value differs.
func TestBuildDNSArchDifferences_DriftIsReported(t *testing.T) {
	m, o := liveTopology(t)
	m.Tier[0].Upstream = []string{"9.9.9.9"}
	m.Forwarding.GlobalForwarders = []string{"1.0.0.1"}
	m.Forwarding.ServerInstallForwarders[0].Forwarders = []string{"1.0.0.1"}
	m.Resolvers[0].Servers = []string{"192.168.122.5", "192.168.122.15"}
	o.Tier[0].Identity.Value = "pilot-dns:other"
	diffs := BuildDNSArchDifferences(m, o)
	for _, subject := range []string{"tier dd-dns forward zone .", "FreeIPA global forwarders", "FreeIPA dd-ipa server forwarders", "client dd-client nameservers", "tier dd-dns identity"} {
		d, _ := diffBySubject(diffs, subject)
		if d.Status != "mismatch" {
			t.Errorf("%s = %+v, want mismatch", subject, d)
		}
	}
	d, _ := diffBySubject(diffs, "tier dd-dns forward zone .")
	if d.Evidence[0] != "inventory:hostvars[dd-dns].dns_upstream" || d.Evidence[1] != "step:tier-dd-dns#forwards" {
		t.Fatalf("evidence = %v", d.Evidence)
	}
	status, findings := BuildDNSArchStatus(m, o, diffs)
	if status != "complete" || !strings.Contains(strings.Join(findings, "\n"), "declared_live_mismatch: FreeIPA global forwarders") {
		t.Fatalf("status %s findings %v", status, findings)
	}
}

func TestBuildDNSArchStatus_AuthRequiredKeepsOtherFacts(t *testing.T) {
	m, o := liveTopology(t)
	f := DNSArchFact{State: FactAuthRequired, Detail: "no approved read-only FreeIPA principal"}
	o.FreeIPA = DNSArchObservedFreeIPA{GlobalForwarders: f, ForwardPolicy: f, ServerForwarders: f, ForwardZones: f, Zones: f}
	o.Kerberos = DNSArchKerberos{State: "not_configured", Detail: f.Detail}
	diffs := BuildDNSArchDifferences(m, o)
	status, _ := BuildDNSArchStatus(m, o, diffs)
	if status != FactAuthRequired {
		t.Fatalf("status = %s, want auth_required", status)
	}
	if d, _ := diffBySubject(diffs, "FreeIPA global forwarders"); d.Status != FactAuthRequired {
		t.Fatalf("global forwarders comparison = %+v", d)
	}
	if d, _ := diffBySubject(diffs, "tier dd-dns forward zone ."); d.Status != "match" {
		t.Fatalf("tier comparison must still be made: %+v", d)
	}
}

func TestBuildDNSArchStatus_UnreachableAndStopped(t *testing.T) {
	m, o := liveTopology(t)
	o.Providers[0] = BuildDNSArchObservedProvider(m.Providers[0], m.FreeIPADomain, "ipa1.ipa.pilot.internal", StepResult{Step: Step{ID: "provider-dd-ipa"}, Result: AdHocResult{Unreachable: true, Stdout: "ssh: connect to host 192.168.122.5 port 22: Connection timed out"}})
	o.Tier[0] = BuildDNSArchObservedTier(m.Tier[0], "ipa1.ipa.pilot.internal", ".", m.DNSProviderIPs(), m.FreeIPADomain, fixtureResult(t, "tier-dd-dns", "tier_stopped.txt"))
	diffs := BuildDNSArchDifferences(m, o)
	status, findings := BuildDNSArchStatus(m, o, diffs)
	joined := strings.Join(findings, "\n")
	if status != "partial" || !strings.Contains(joined, "freeipa_dns_provider_unreachable: dd-ipa") || !strings.Contains(joined, "dns_tier_not_running: dd-dns") {
		t.Fatalf("status %s findings %v", status, findings)
	}
	if d, _ := diffBySubject(diffs, "FreeIPA dd-ipa authoritative"); d.Status != FactUnknown {
		t.Fatalf("authoritative comparison = %+v, want unknown (not absent)", d)
	}
	if d, _ := diffBySubject(diffs, "tier dd-dns forward zone ."); d.Status != FactUnknown {
		t.Fatalf("forward comparison = %+v, want unknown", d)
	}
}

func TestBuildDNSArchStatus_NoTierIsAFinding(t *testing.T) {
	m := BuildDNSArchitectureModel(inv(map[string][]string{"freeipa-server": {"ipa"}}, map[string]map[string]any{"ipa": {"ansible_host": "10.0.0.5"}}))
	_, findings := BuildDNSArchStatus(m, DNSArchObserved{Kerberos: DNSArchKerberos{State: "available"}}, nil)
	if !strings.HasPrefix(findings[0], "dns_tier_not_assigned") {
		t.Fatalf("findings = %v", findings)
	}
	if paths := BuildDNSArchPaths(m, DNSArchObserved{}); !strings.Contains(strings.Join(paths, "\n"), "dns tier: not assigned") {
		t.Fatalf("paths = %v", paths)
	}
}

// ---- observed is not succeeded; unknown is not complete -----------------------------

// withSection returns capture with its section key replaced by section
// fromKey of another real capture, so a single failure can be placed into
// an otherwise complete topology without inventing dig output.
func withSection(t *testing.T, capture, key, from, fromKey string) string {
	t.Helper()
	section := func(s, k string) (int, int) {
		begin := strings.Index(s, dnsArchMarker+k+" begin\n")
		end := strings.Index(s, dnsArchMarker+k+" end rc=")
		if begin < 0 || end < 0 {
			t.Fatalf("no complete %s section", k)
		}
		return begin, end + strings.Index(s[end:], "\n") + 1
	}
	b, e := section(capture, key)
	fb, fe := section(from, fromKey)
	moved := strings.ReplaceAll(from[fb:fe], dnsArchMarker+fromKey+" ", dnsArchMarker+key+" ")
	return capture[:b] + moved + capture[e:]
}

func liveWithTier(t *testing.T, tierStdout string) (DNSArchModel, DNSArchObserved, string, []string) {
	t.Helper()
	m, o := liveTopology(t)
	o.Tier[0] = BuildDNSArchObservedTier(m.Tier[0], "ipa1.ipa.pilot.internal", ".", m.DNSProviderIPs(), m.FreeIPADomain, StepResult{Step: Step{ID: "tier-dd-dns"}, Result: AdHocResult{Stdout: tierStdout}})
	status, findings := BuildDNSArchStatus(m, o, BuildDNSArchDifferences(m, o))
	return m, o, status, findings
}

// The external probe through the tier, captured on unbound 1.19.2
// (tier_external_servfail.txt: dnssec-failed.org through a tier forwarding
// to 1.1.1.1; tier_external_nxdomain.txt: a name under .invalid).
func TestBuildDNSArchObservedTier_ExternalAnswerIsNotResolution(t *testing.T) {
	servfail := BuildDNSArchObservedTier(tierHost(), "-", "dnssec-failed.org", nil, "", fixtureResult(t, "tier-pr73-cap", "tier_external_servfail.txt"))
	if f := servfail.ExternalResolution; f.State != FactError || !strings.Contains(f.Detail, "SERVFAIL") || strings.Contains(f.Detail, "proves") {
		t.Fatalf("SERVFAIL external = %+v, want error", f)
	}
	if _, ok := dnsAnswered(servfail.ExternalResolution); ok {
		t.Fatal("a SERVFAIL counts as an answer")
	}
	nx := BuildDNSArchObservedTier(tierHost(), "-", "pilot-dnsarch-nx.invalid", nil, "", fixtureResult(t, "tier-pr73-cap", "tier_external_nxdomain.txt"))
	if f := nx.ExternalResolution; f.State != FactAbsent || !strings.Contains(f.Detail, "NXDOMAIN") {
		t.Fatalf("NXDOMAIN external = %+v, want absent", f)
	}
	ok := BuildDNSArchObservedTier(tierHost(), "ipa1.ipa.pilot.internal", ".", nil, "", fixtureResult(t, "tier-dd-dns", "tier.txt"))
	if _, answered := dnsAnswered(ok.ExternalResolution); !answered || ok.ExternalName != "." {
		t.Fatalf("NOERROR external = %+v, want an answer", ok.ExternalResolution)
	}
}

func TestBuildDNSArchStatus_ExternalResolution(t *testing.T) {
	tier := fixture(t, "tier.txt")

	// Should pass: NOERROR with records is a resolution, reported with
	// the forwarder caveat.
	_, _, status, findings := liveWithTier(t, tier)
	if status != "complete" || len(findings) != 1 || !strings.HasPrefix(findings[0], "external_resolution_forwarder_unproven: dd-dns resolved .;") {
		t.Fatalf("status %s findings %v", status, findings)
	}

	// Should trigger: SERVFAIL is a failed lookup, never "resolved".
	_, o, status, findings := liveWithTier(t, withSection(t, tier, "external", fixture(t, "tier_external_servfail.txt"), "external"))
	joined := strings.Join(findings, "\n")
	if o.Tier[0].ExternalResolution.State != FactError || strings.Contains(joined, "external_resolution_forwarder_unproven") || !strings.Contains(joined, "external_resolution_failed: dd-dns did not resolve . (the tier answered . NS with SERVFAIL)") {
		t.Fatalf("SERVFAIL: status %s findings %v", status, findings)
	}

	// Should trigger: NXDOMAIN for the probe name is not a resolution.
	_, _, _, findings = liveWithTier(t, withSection(t, tier, "external", fixture(t, "tier_external_nxdomain.txt"), "external"))
	if joined := strings.Join(findings, "\n"); strings.Contains(joined, "forwarder_unproven") || !strings.Contains(joined, "external_resolution_failed: dd-dns") {
		t.Fatalf("NXDOMAIN: findings %v", findings)
	}

	// Should trigger: no answer at all (connection refused, from the
	// stopped-unbound capture) is unknown, so the report is partial.
	_, o, status, findings = liveWithTier(t, withSection(t, tier, "external", fixture(t, "tier_stopped.txt"), "external"))
	joined = strings.Join(findings, "\n")
	if o.Tier[0].ExternalResolution.State != FactUnknown || status != "partial" || !strings.Contains(joined, "external_resolution_unknown: dd-dns (no answer from 127.0.0.1: communications error to 127.0.0.1#53: connection refused") {
		t.Fatalf("refused: status %s findings %v", status, findings)
	}

	// Should trigger: a step that stopped inside the external section.
	cut := tier[:strings.Index(tier, dnsArchMarker+"external end")]
	_, _, status, findings = liveWithTier(t, cut)
	if status != "partial" || !strings.Contains(strings.Join(findings, "\n"), "external_resolution_unknown: dd-dns (no complete output") {
		t.Fatalf("cut: status %s findings %v", status, findings)
	}
}

// Every live fact pilot could not determine on a reachable host makes the
// report partial, and the finding names it.
func TestBuildDNSArchStatus_UnknownLiveFactsArePartial(t *testing.T) {
	refused := fixture(t, "tier_stopped.txt")
	m, o := liveTopology(t)
	provider := withSection(t, fixture(t, "provider.txt"), "ns", refused, "external")
	o.Providers[0] = BuildDNSArchObservedProvider(m.Providers[0], m.FreeIPADomain, "ipa1.ipa.pilot.internal", StepResult{Step: Step{ID: "provider-dd-ipa"}, Result: AdHocResult{Stdout: provider}})
	if o.Providers[0].NS.State != FactUnknown {
		t.Fatalf("ns = %+v", o.Providers[0].NS)
	}
	status, findings := BuildDNSArchStatus(m, o, BuildDNSArchDifferences(m, o))
	if status != "partial" || !strings.Contains(strings.Join(findings, "\n"), "live_fact_unknown: dd-ipa: ns (no answer from 192.168.122.5: communications error to 127.0.0.1#53: connection refused") {
		t.Fatalf("provider: status %s findings %v", status, findings)
	}

	m, o = liveTopology(t)
	client := fixture(t, "client.txt")
	c := BuildDNSArchObservedClient("dd-client", StepResult{Step: Step{ID: "client-dd-client"}, Result: AdHocResult{Stdout: client[:strings.Index(client, dnsArchMarker+"lookup end")]}})
	o.Client = &c
	status, findings = BuildDNSArchStatus(m, o, BuildDNSArchDifferences(m, o))
	if status != "partial" || !strings.Contains(strings.Join(findings, "\n"), "live_fact_unknown: dd-client: lookup") {
		t.Fatalf("client: status %s findings %v", status, findings)
	}

	m, o = liveTopology(t)
	o.FreeIPA.ForwardPolicy = DNSArchFact{State: FactUnknown, Detail: "FreeIPA did not report the principal's rights on idnsforwardpolicy"}
	if status, _ := BuildDNSArchStatus(m, o, BuildDNSArchDifferences(m, o)); status != "partial" {
		t.Fatalf("unknown forward policy: status %s, want partial", status)
	}

	// An unreachable provider from the tier (timeout, tier_failures.txt)
	// is a finding and leaves the report partial.
	m, o = liveTopology(t)
	tier := withSection(t, fixture(t, "tier.txt"), "authority@192.168.122.5", fixture(t, "tier_failures.txt"), "authority@192.0.2.1")
	o.Tier[0] = BuildDNSArchObservedTier(m.Tier[0], "ipa1.ipa.pilot.internal", ".", m.DNSProviderIPs(), m.FreeIPADomain, StepResult{Step: Step{ID: "tier-dd-dns"}, Result: AdHocResult{Stdout: tier}})
	status, findings = BuildDNSArchStatus(m, o, BuildDNSArchDifferences(m, o))
	if status != "partial" || !strings.Contains(strings.Join(findings, "\n"), "freeipa_dns_not_authoritative_from_tier: dd-dns") {
		t.Fatalf("authority timeout: status %s findings %v", status, findings)
	}
}

// A provider that answers SERVFAIL for the internal name is not a
// reference: a SERVFAIL through the tier must not "match" it.
func TestBuildDNSArchDifferences_ServfailIsNoAuthoritativeReference(t *testing.T) {
	servfail := fixture(t, "tier_external_servfail.txt")
	m, o := liveTopology(t)
	provider := withSection(t, fixture(t, "provider.txt"), "internal", servfail, "external")
	o.Providers[0] = BuildDNSArchObservedProvider(m.Providers[0], m.FreeIPADomain, "ipa1.ipa.pilot.internal", StepResult{Step: Step{ID: "provider-dd-ipa"}, Result: AdHocResult{Stdout: provider}})
	tier := withSection(t, fixture(t, "tier.txt"), "internal", servfail, "external")
	o.Tier[0] = BuildDNSArchObservedTier(m.Tier[0], "ipa1.ipa.pilot.internal", ".", m.DNSProviderIPs(), m.FreeIPADomain, StepResult{Step: Step{ID: "tier-dd-dns"}, Result: AdHocResult{Stdout: tier}})
	d, _ := diffBySubject(BuildDNSArchDifferences(m, o), "tier dd-dns answer for ipa1.ipa.pilot.internal")
	if d.Status != FactUnknown {
		t.Fatalf("comparison = %+v, want unknown (no authoritative answer)", d)
	}
}

// An AlmaLinux 9.8 host without systemd-resolved (client_el.txt;
// client_el_stock.txt is the same host before bind-utils was installed).
// resolvectl failing there is not a gap in the evidence, but a missing dig
// leaves the first hop unknown.
func TestBuildDNSArchStatus_ClientWithoutSystemdResolved(t *testing.T) {
	m, o := liveTopology(t)
	c := BuildDNSArchObservedClient("dd-client", fixtureResult(t, "client-dd-client", "client_el.txt"))
	if c.ResolvedDNS.State != FactNotApplicable || c.FirstHop.State != FactObserved {
		t.Fatalf("client = %+v", c)
	}
	o.Client = &c
	_, findings := BuildDNSArchStatus(m, o, BuildDNSArchDifferences(m, o))
	if joined := strings.Join(findings, "\n"); strings.Contains(joined, "live_fact_unknown") {
		t.Fatalf("findings %v, want no unknown live fact", findings)
	}

	stock := BuildDNSArchObservedClient("dd-client", fixtureResult(t, "client-dd-client", "client_el_stock.txt"))
	o.Client = &stock
	status, findings := BuildDNSArchStatus(m, o, BuildDNSArchDifferences(m, o))
	if status != "partial" || !strings.Contains(strings.Join(findings, "\n"), "live_fact_unknown: dd-client: first_hop_identity (environment: line 6: dig: command not found)") {
		t.Fatalf("status %s findings %v", status, findings)
	}
	// The same resolvectl failure with systemd-resolved active is unknown.
	active := strings.Replace(fixture(t, "client_el.txt"), "inactive\n@@pilot-dnsarch resolved end rc=3", "active\n@@pilot-dnsarch resolved end rc=0", 1)
	if c := BuildDNSArchObservedClient("dd-client", StepResult{Step: Step{ID: "c"}, Result: AdHocResult{Stdout: active}}); c.ResolvedDNS.State != FactUnknown {
		t.Fatalf("resolvectl with resolved active = %+v, want unknown", c.ResolvedDNS)
	}
}
