package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/diagnose"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The live outputs below are internal/diagnose/testdata/dnsarch: the real
// stdout of each probe on a disposable FreeIPA 4.13.4 + unbound 1.19.2
// vm-target topology (see that package's dns_architecture_test.go).
const (
	dnsArchReader = "pilot-dns-reader/ipa1.ipa.pilot.internal@IPA.PILOT.INTERNAL"
	dnsArchKeytab = "/etc/pilot/dns-reader.keytab"
)

func dnsArchFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRootForTest(t), "internal", "diagnose", "testdata", "dnsarch", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func writeDNSArchInventory(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "inventory.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// dnsArchOpts isolates the delivery history and reads contracts from the
// repository.
func dnsArchOpts(t *testing.T, inventory string, fake *diagnoseFakeRunner, reader diagnoseFreeIPAReader) diagnoseMCPToolsOptions {
	t.Helper()
	previous := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = previous })
	opts := baseDiagnoseOpts(t, inventory, fake.run)
	opts.WorkspaceDir = repoRootForTest(t)
	opts.FreeIPAReader = reader
	return opts
}

func respond(t *testing.T, host, stdout string) func() (string, int, error) {
	return func() (string, int, error) { return diagnoseOKDoc(t, host, 0, stdout), 0, nil }
}

// realUnreachable returns ansible's real callback document for a host
// whose SSH connection timed out (dd-gone, 192.0.2.1), captured with
// ansible-core 2.19.2; ansible itself exits 4.
func realUnreachable(t *testing.T) func() (string, int, error) {
	return func() (string, int, error) { return dnsArchFixture(t, "unreachable.json"), 4, nil }
}

const dnsArchLiveInventory = `
all:
  children:
    freeipa-server:
      hosts:
        dd-ipa: {ansible_connection: local, ansible_host: 192.168.122.5}
    dns:
      hosts:
        dd-dns: {ansible_connection: local, ansible_host: 192.168.122.15}
    freeipa-dns-client:
      hosts:
        dd-client: {ansible_connection: local, ansible_host: 192.168.122.9}
`

// liveRunner answers the four probes of the live topology.
func liveRunner(t *testing.T) *diagnoseFakeRunner {
	return &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		diagnose.DNSArchProviderStep("dd-ipa", "ipa.pilot.internal", "192.168.122.5", "ipa1.ipa.pilot.internal").Command:            respond(t, "dd-ipa", dnsArchFixture(t, "provider.txt")),
		diagnose.DNSArchAuthStep("dd-ipa", dnsArchReader, dnsArchKeytab).Command:                                                    respond(t, "dd-ipa", dnsArchFixture(t, "auth_role.txt")),
		diagnose.DNSArchTierStep("dd-dns", "ipa1.ipa.pilot.internal", ".", "ipa.pilot.internal", []string{"192.168.122.5"}).Command: respond(t, "dd-dns", dnsArchFixture(t, "tier.txt")),
		diagnose.DNSArchClientStep("dd-client", "ipa1.ipa.pilot.internal").Command:                                                  respond(t, "dd-client", dnsArchFixture(t, "client.txt")),
	}}
}

func callDNSArch(t *testing.T, opts diagnoseMCPToolsOptions, in diagnoseDNSArchitectureInput) diagnoseDNSArchitectureOutput {
	t.Helper()
	result, out, err := diagnoseDNSArchitectureHandler(opts)(context.Background(), &mcp.CallToolRequest{}, in)
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("handler() returned a tool error: %+v", result.Content)
	}
	return out
}

func dnsArchDiff(out diagnoseDNSArchitectureOutput, prefix string) (diagnose.DNSArchDifference, bool) {
	for _, d := range out.Differences {
		if strings.HasPrefix(d.Subject, prefix) {
			return d, true
		}
	}
	return diagnose.DNSArchDifference{}, false
}

func joinedFindings(out diagnoseDNSArchitectureOutput) string {
	return strings.Join(out.Findings, "\n")
}

// Split tier with an approved reader: every layer is filled in and the
// declared/live comparisons all match.
func TestDiagnoseDNSArchitecture_SplitTierWithReaderIsComplete(t *testing.T) {
	requireRealAnsible(t)
	fake := liveRunner(t)
	opts := dnsArchOpts(t, writeDNSArchInventory(t, dnsArchLiveInventory), fake, diagnoseFreeIPAReader{Principal: dnsArchReader, Keytab: dnsArchKeytab})
	out := callDNSArch(t, opts, diagnoseDNSArchitectureInput{ClientHost: "dd-client"})

	if out.Status != "complete" || out.AuditStatus != "persisted" || len(out.Steps) != 4 {
		t.Fatalf("status=%s audit=%s steps=%d findings=%v", out.Status, out.AuditStatus, len(out.Steps), out.Findings)
	}
	for _, d := range out.Differences {
		if d.Status != "match" {
			t.Errorf("%s = %s (%s)", d.Subject, d.Status, d.Detail)
		}
	}
	if out.Execution.Kerberos.State != "available" || out.Execution.RemoteUsers["dd-dns"] != "root" || out.Execution.ControllerUser == "" {
		t.Fatalf("execution = %+v", out.Execution)
	}
	var dns dnsArchComponent
	for _, c := range out.Supported.Components {
		if c.ID == "dns" {
			dns = c
		}
	}
	if !dns.Product || !dns.Assigned || dns.Hosts[0] != "dd-dns" || dns.RunState != "no_recorded_run" || dns.Contract != "contracts/dns.yaml" {
		t.Fatalf("dns component = %+v", dns)
	}
	if len(out.Declared) == 0 || out.Effective.Tier[0].Mode != "freeipa-split" {
		t.Fatalf("declared=%v effective=%+v", out.Declared, out.Effective)
	}
	record, err := os.ReadFile(filepath.Join(out.AuditDirectory, "record.json"))
	if err != nil || !strings.Contains(string(record), `"check": "dns_architecture"`) || strings.Contains(string(record), "password") {
		t.Fatalf("audit record = %s, %v", record, err)
	}
}

// Missing credentials: auth_required, nothing else lost, and no
// authenticated step is ever run.
func TestDiagnoseDNSArchitecture_MissingAuthKeepsOtherFacts(t *testing.T) {
	requireRealAnsible(t)
	fake := liveRunner(t)
	opts := dnsArchOpts(t, writeDNSArchInventory(t, dnsArchLiveInventory), fake, diagnoseFreeIPAReader{})
	out := callDNSArch(t, opts, diagnoseDNSArchitectureInput{ClientHost: "dd-client"})

	if out.Status != "auth_required" || out.Execution.Kerberos.State != "not_configured" {
		t.Fatalf("status=%s kerberos=%+v", out.Status, out.Execution.Kerberos)
	}
	for _, call := range fake.calls {
		if strings.Contains(call, "kinit") {
			t.Fatalf("an authenticated step ran without an approved reader: %s", call)
		}
	}
	if d, _ := dnsArchDiff(out, "FreeIPA global forwarders"); d.Status != "auth_required" {
		t.Fatalf("global forwarders = %+v", d)
	}
	for _, subject := range []string{"tier dd-dns forward zone .", "FreeIPA dd-ipa authoritative", "client dd-client nameservers"} {
		if d, _ := dnsArchDiff(out, subject); d.Status != "match" {
			t.Errorf("%s = %+v, want match without credentials", subject, d)
		}
	}
}

// Primary only, no dns group: the role exists in the product but is not
// assigned, and consumers resolve straight against FreeIPA.
func TestDiagnoseDNSArchitecture_NoTierPrimaryOnly(t *testing.T) {
	requireRealAnsible(t)
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		diagnose.DNSArchProviderStep("dd-ipa", "ipa.pilot.internal", "192.168.122.5", "ipa1.ipa.pilot.internal").Command: respond(t, "dd-ipa", dnsArchFixture(t, "provider.txt")),
		diagnose.DNSArchAuthStep("dd-ipa", dnsArchReader, dnsArchKeytab).Command:                                         respond(t, "dd-ipa", dnsArchFixture(t, "auth_role.txt")),
	}}
	inv := writeDNSArchInventory(t, `
all:
  children:
    freeipa-server:
      hosts:
        dd-ipa: {ansible_connection: local, ansible_host: 192.168.122.5}
    freeipa-dns-client:
      hosts:
        dd-client: {ansible_connection: local, ansible_host: 192.168.122.9}
`)
	out := callDNSArch(t, dnsArchOpts(t, inv, fake, diagnoseFreeIPAReader{Principal: dnsArchReader, Keytab: dnsArchKeytab}), diagnoseDNSArchitectureInput{})
	if !strings.Contains(joinedFindings(out), "dns_tier_not_assigned") || out.Effective.TierAssigned || len(fake.calls) != 2 {
		t.Fatalf("findings=%v calls=%v", out.Findings, fake.calls)
	}
	if r := out.Effective.Resolvers[0]; r.Selection != "freeipa_only" || r.Servers[0] != "192.168.122.5" {
		t.Fatalf("resolver = %+v", r)
	}
	for _, c := range out.Supported.Components {
		if c.ID == "dns" && (!c.Product || c.Assigned) {
			t.Fatalf("dns component = %+v, want in the product but not assigned", c)
		}
	}
	if !strings.Contains(strings.Join(out.Paths, "\n"), "dns tier: not assigned") {
		t.Fatalf("paths = %v", out.Paths)
	}
}

// A DNS-enabled replica that cannot be reached: partial, named as such,
// and its facts are unknown rather than absent.
func TestDiagnoseDNSArchitecture_DNSEnabledReplicaUnreachable(t *testing.T) {
	requireRealAnsible(t)
	fake := liveRunner(t)
	fake.byCommand[diagnose.DNSArchProviderStep("dd-gone", "ipa.pilot.internal", "192.0.2.1", "ipa1.ipa.pilot.internal").Command] = realUnreachable(t)
	fake.byCommand[diagnose.DNSArchTierStep("dd-dns", "ipa1.ipa.pilot.internal", ".", "ipa.pilot.internal", []string{"192.168.122.5", "192.0.2.1"}).Command] = respond(t, "dd-dns", dnsArchFixture(t, "tier.txt"))
	inv := writeDNSArchInventory(t, dnsArchLiveInventory+`    freeipa-server-replica:
      hosts:
        dd-gone: {ansible_connection: local, ansible_host: 192.0.2.1, freeipa_setup_dns: true, freeipa_replica_fqdn: ipa2.ipa.pilot.internal}
`)
	out := callDNSArch(t, dnsArchOpts(t, inv, fake, diagnoseFreeIPAReader{Principal: dnsArchReader, Keytab: dnsArchKeytab}), diagnoseDNSArchitectureInput{})
	if out.Status != "partial" || !strings.Contains(joinedFindings(out), "freeipa_dns_provider_unreachable: dd-gone (Task failed: Failed to connect to the host via ssh") {
		t.Fatalf("status=%s findings=%v", out.Status, out.Findings)
	}
	replica := out.Observed.Providers[1]
	if replica.Reachable.State != diagnose.FactUnreachable || replica.SOA.State != diagnose.FactUnknown {
		t.Fatalf("replica = %+v", replica)
	}
	if d, _ := dnsArchDiff(out, "FreeIPA dd-gone authoritative"); d.Status != diagnose.FactUnknown {
		t.Fatalf("replica authority = %+v, want unknown", d)
	}
	// The tier's stub must hold both providers; the captured tier only
	// has the primary, so the comparison reports the gap.
	if d, _ := dnsArchDiff(out, "tier dd-dns stub zone ipa.pilot.internal"); d.Status != "mismatch" {
		t.Fatalf("stub comparison = %+v, want mismatch (replica missing live)", d)
	}
	// The install-time forwarders of the replica cannot be confirmed in the
	// captured configuration, which lists only the primary's server entry.
	if d, _ := dnsArchDiff(out, "FreeIPA dd-gone server forwarders"); d.Status != "absent" {
		t.Fatalf("replica server forwarders = %+v, want absent", d)
	}
}

// An explicit freeipa_dns_client_servers override wins over the tier, and
// a live resolver that still lists the tier first is a mismatch.
func TestDiagnoseDNSArchitecture_ExplicitClientOverride(t *testing.T) {
	requireRealAnsible(t)
	fake := liveRunner(t)
	inv := writeDNSArchInventory(t, strings.Replace(dnsArchLiveInventory,
		"dd-client: {ansible_connection: local, ansible_host: 192.168.122.9}",
		"dd-client: {ansible_connection: local, ansible_host: 192.168.122.9, freeipa_dns_client_servers: [192.168.122.5]}", 1))
	out := callDNSArch(t, dnsArchOpts(t, inv, fake, diagnoseFreeIPAReader{Principal: dnsArchReader, Keytab: dnsArchKeytab}), diagnoseDNSArchitectureInput{ClientHost: "dd-client"})
	d, _ := dnsArchDiff(out, "client dd-client nameservers (explicit_override)")
	if d.Status != "mismatch" || !strings.Contains(strings.Join(d.Evidence, " "), "inventory:hostvars[dd-client].freeipa_dns_client_servers") {
		t.Fatalf("client comparison = %+v", d)
	}
	if !strings.Contains(joinedFindings(out), "declared_live_mismatch: client dd-client nameservers") {
		t.Fatalf("findings = %v", out.Findings)
	}
}

func TestDiagnoseDNSArchitecture_RejectsBadInputBeforeAnyCall(t *testing.T) {
	requireRealAnsible(t)
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	opts := dnsArchOpts(t, writeDNSArchInventory(t, dnsArchLiveInventory), fake, diagnoseFreeIPAReader{})
	for name, in := range map[string]diagnoseDNSArchitectureInput{
		"unknown client":     {ClientHost: "nope"},
		"group as client":    {ClientHost: "dns"},
		"bad internal name":  {InternalName: "a b;rm"},
		"zone apex as name":  {InternalName: "@"},
		"apex as external":   {ExternalName: "@"},
		"bad external name":  {ExternalName: "{{ lookup('pipe','id') }}"},
		"template in client": {ClientHost: "{{ x }}"},
	} {
		result, _, err := diagnoseDNSArchitectureHandler(opts)(context.Background(), &mcp.CallToolRequest{}, in)
		if err != nil || result == nil || !result.IsError {
			t.Errorf("%s: result=%+v err=%v, want a structured tool error", name, result, err)
		}
	}
	if len(fake.calls) != 0 {
		t.Fatalf("calls = %v, want none", fake.calls)
	}
}

func TestValidateFreeIPAReader(t *testing.T) {
	for _, ok := range []diagnoseFreeIPAReader{
		{},
		{Principal: dnsArchReader, Keytab: dnsArchKeytab},
		{Principal: "pilot-dns-reader@EXAMPLE.TEST", Keytab: "/etc/pilot/r.keytab"},
	} {
		if err := validateFreeIPAReader(ok); err != nil {
			t.Errorf("%+v rejected: %v", ok, err)
		}
	}
	for _, bad := range []diagnoseFreeIPAReader{
		{Principal: dnsArchReader},
		{Keytab: dnsArchKeytab},
		{Principal: "admin@IPA.PILOT.INTERNAL", Keytab: dnsArchKeytab},
		{Principal: "Admin/ipa1.ipa.pilot.internal@IPA.PILOT.INTERNAL", Keytab: dnsArchKeytab},
		{Principal: "reader@ipa.pilot.internal", Keytab: dnsArchKeytab},
		{Principal: "reader@X; id", Keytab: dnsArchKeytab},
		{Principal: dnsArchReader, Keytab: "relative.keytab"},
		{Principal: dnsArchReader, Keytab: "/etc/../root/admin.keytab"},
		{Principal: dnsArchReader, Keytab: "/etc/pilot/{{ x }}"},
		// A leading "-" would be a kinit option: -c picks the ccache.
		{Principal: "-c/tmp@IPA.PILOT.INTERNAL", Keytab: "/etc/krb5.keytab"},
		{Principal: "reader/-c@IPA.PILOT.INTERNAL", Keytab: dnsArchKeytab},
		{Principal: "reader@-IPA.PILOT.INTERNAL", Keytab: dnsArchKeytab},
		// FreeIPA's own service principals and other administrators.
		{Principal: "host/ipa1.ipa.pilot.internal@IPA.PILOT.INTERNAL", Keytab: "/etc/krb5.keytab"},
		{Principal: "DNS/ipa1.ipa.pilot.internal@IPA.PILOT.INTERNAL", Keytab: "/etc/named.keytab"},
		{Principal: "HTTP/ipa1.ipa.pilot.internal@IPA.PILOT.INTERNAL", Keytab: dnsArchKeytab},
		{Principal: "ldap/ipa1.ipa.pilot.internal@IPA.PILOT.INTERNAL", Keytab: dnsArchKeytab},
		{Principal: "ipa-dnskeysyncd/ipa1.ipa.pilot.internal@IPA.PILOT.INTERNAL", Keytab: dnsArchKeytab},
		{Principal: "administrator@IPA.PILOT.INTERNAL", Keytab: dnsArchKeytab},
		{Principal: "krbtgt/IPA.PILOT.INTERNAL@IPA.PILOT.INTERNAL", Keytab: dnsArchKeytab},
	} {
		if err := validateFreeIPAReader(bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

// The primary's FQDN as the inventory writes it (upper case, trailing dot)
// is normalized before it is validated and used, so the core comparison
// is still made (AGENTS.md §5.13).
func TestDiagnoseDNSArchitecture_NormalizesThePrimaryFQDN(t *testing.T) {
	requireRealAnsible(t)
	inv := strings.Replace(dnsArchLiveInventory, "dd-ipa: {ansible_connection: local, ansible_host: 192.168.122.5}", "dd-ipa: {ansible_connection: local, ansible_host: 192.168.122.5, freeipa_server_fqdn: IPA1.ipa.pilot.internal.}", 1)
	opts := dnsArchOpts(t, writeDNSArchInventory(t, inv), liveRunner(t), diagnoseFreeIPAReader{Principal: dnsArchReader, Keytab: dnsArchKeytab})
	out := callDNSArch(t, opts, diagnoseDNSArchitectureInput{ClientHost: "dd-client"})
	if d, ok := dnsArchDiff(out, "tier dd-dns answer for ipa1.ipa.pilot.internal equals FreeIPA's authoritative answer"); !ok || d.Status != "match" {
		t.Fatalf("internal comparison = %+v (found %v); findings %v", d, ok, out.Findings)
	}
}

// A primary FQDN that is not a DNS name, and tier hosts beyond the probe
// bound, are named and make the report partial; nothing is skipped
// silently.
func TestDiagnoseDNSArchitecture_SkippedProbesAreReported(t *testing.T) {
	requireRealAnsible(t)
	inv := strings.Replace(dnsArchLiveInventory, "dd-ipa: {ansible_connection: local, ansible_host: 192.168.122.5}", "dd-ipa: {ansible_connection: local, ansible_host: 192.168.122.5, freeipa_server_fqdn: ipa_1.bad}", 1)
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		diagnose.DNSArchProviderStep("dd-ipa", "ipa.pilot.internal", "192.168.122.5", "-").Command:           respond(t, "dd-ipa", dnsArchFixture(t, "provider.txt")),
		diagnose.DNSArchAuthStep("dd-ipa", dnsArchReader, dnsArchKeytab).Command:                             respond(t, "dd-ipa", dnsArchFixture(t, "auth_role.txt")),
		diagnose.DNSArchTierStep("dd-dns", "", ".", "ipa.pilot.internal", []string{"192.168.122.5"}).Command: respond(t, "dd-dns", dnsArchFixture(t, "tier.txt")),
		diagnose.DNSArchClientStep("dd-client", "localhost").Command:                                         respond(t, "dd-client", dnsArchFixture(t, "client.txt")),
	}}
	opts := dnsArchOpts(t, writeDNSArchInventory(t, inv), fake, diagnoseFreeIPAReader{Principal: dnsArchReader, Keytab: dnsArchKeytab})
	out := callDNSArch(t, opts, diagnoseDNSArchitectureInput{ClientHost: "dd-client"})
	if out.Status != "partial" || !strings.Contains(joinedFindings(out), `probe_skipped: the FreeIPA primary's FQDN "ipa_1.bad" is not a DNS name`) {
		t.Fatalf("status %s findings %v", out.Status, out.Findings)
	}
	if strings.Contains(out.Observed.Tier[0].InternalResolution.Detail, "no FreeIPA in the inventory") {
		t.Fatalf("tier internal resolution = %+v", out.Observed.Tier[0].InternalResolution)
	}

	var hosts strings.Builder
	for i := 1; i <= maxDNSArchProbeHosts+1; i++ {
		fmt.Fprintf(&hosts, "        t%d: {ansible_connection: local, ansible_host: 10.0.0.%d}\n", i, i)
	}
	many := "all:\n  children:\n    dns:\n      hosts:\n" + hosts.String()
	everything := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	for i := 1; i <= maxDNSArchProbeHosts; i++ {
		h := fmt.Sprintf("t%d", i)
		everything.byCommand[diagnose.DNSArchTierStep(h, "", ".", "", nil).Command] = respond(t, h, dnsArchFixture(t, "tier.txt"))
	}
	out = callDNSArch(t, dnsArchOpts(t, writeDNSArchInventory(t, many), everything, diagnoseFreeIPAReader{}), diagnoseDNSArchitectureInput{})
	if out.Status != "partial" || !strings.Contains(joinedFindings(out), "probe_skipped: dns tier hosts beyond the first 5 were not probed: t6") {
		t.Fatalf("status %s findings %v", out.Status, out.Findings)
	}
}
