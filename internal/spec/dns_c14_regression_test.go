package spec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// dns.md C14: a nonexistent internal name answered through the tier carries
// FreeIPA's SOA. Every FreeIPA DNS server puts its own FQDN in the SOA mname,
// and the tier's stub sends a query to any of them, so with a DNS-providing
// replica (default since issue #67) the answer carries either server's name.
// C14 compared it with the first server's only and failed about half the
// time on a two-server topology.
//
// The outputs below are real `dig` stdout captured 2026-10-13 from an Ubuntu
// 24.04.4 tier host (unbound 1.19.2) in front of a FreeIPA 4.13.4 primary
// (ipa1) and replica (ipa2); the tier answered ipa1 twice and ipa2 twice in
// four queries.
const (
	digTierNXDOMAIN = `;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: %STATUS%, id: 8675
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; AUTHORITY SECTION:
ipa.pilot.internal.	%TTL%	IN	SOA	%MNAME% hostmaster.ipa.pilot.internal. 1791885984 3600 900 1209600 3600
`
	digPrimarySOA = "ipa.pilot.internal.\t86400\tIN\tSOA\tipa1.ipa.pilot.internal. hostmaster.ipa.pilot.internal. 1791885934 3600 900 1209600 3600\n"
	digReplicaSOA = "ipa.pilot.internal.\t86400\tIN\tSOA\tipa2.ipa.pilot.internal. hostmaster.ipa.pilot.internal. 1791885984 3600 900 1209600 3600\n"
)

// runDNSC14 runs dns.md C14 as parsed with dig replaced by a fake: the tier
// (@127.0.0.1) answers tier, @10.0.0.1 answers primary and @10.0.0.2
// replica (an empty answer means no reply).
func runDNSC14(t *testing.T, tier, primary, replica, servers string) string {
	t.Helper()
	s, err := Parse(dnsSpecPath)
	if err != nil {
		t.Fatal(err)
	}
	var probe string
	for _, r := range s.Rows {
		if r.ID == "C14" {
			probe = r.Command
		}
	}
	if probe == "" {
		t.Fatal("dns.md has no C14")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"tier": tier, "primary": primary, "replica": replica} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fake := `#!/bin/sh
for a in "$@"; do
  case "$a" in
    @127.0.0.1) cat '` + dir + `/tier'; exit 0 ;;
    @10.0.0.1) cat '` + dir + `/primary'; exit 0 ;;
    @10.0.0.2) cat '` + dir + `/replica'; exit 0 ;;
  esac
done
exit 9
`
	if err := os.WriteFile(filepath.Join(bin, "dig"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", probe)
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"),
		"PILOT_VAR_FREEIPA_DOMAIN=ipa.pilot.internal",
		"PILOT_VAR_FREEIPA_DNS_SERVER_IPS="+servers,
		"PILOT_VAR_DNS_CACHE_MAX_NEGATIVE_TTL=60")
	got, err := cmd.Output()
	if err != nil {
		t.Fatalf("C14 probe failed to run: %v\n%s", err, got)
	}
	return strings.TrimSpace(string(got))
}

func tierAnswer(status, ttl, mname string) string {
	return strings.NewReplacer("%STATUS%", status, "%TTL%", ttl, "%MNAME%", mname).Replace(digTierNXDOMAIN)
}

func TestRegression_DNSC14AcceptsAnyFreeIPAServerSOA(t *testing.T) {
	const both = "10.0.0.1 10.0.0.2"
	// Should pass: either server's SOA.
	for _, mname := range []string{"ipa1.ipa.pilot.internal.", "ipa2.ipa.pilot.internal."} {
		if got := runDNSC14(t, tierAnswer("NXDOMAIN", "60", mname), digPrimarySOA, digReplicaSOA, both); got != "nxdomain-from-freeipa" {
			t.Errorf("tier answered with %s: C14 = %q, want nxdomain-from-freeipa", mname, got)
		}
	}
	// Should trigger.
	for name, tc := range map[string]struct{ tier, primary, replica, servers string }{
		// unbound's built-in RFC1918 reverse zones answer with this SOA
		// when a stub is shadowed (dns.md §0.2).
		"answer from a built-in local zone":               {tierAnswer("NXDOMAIN", "60", "localhost."), digPrimarySOA, digReplicaSOA, both},
		"server outside freeipa_dns_server_ips":           {tierAnswer("NXDOMAIN", "60", "ipa2.ipa.pilot.internal."), digPrimarySOA, digReplicaSOA, "10.0.0.1"},
		"not NXDOMAIN":                                    {tierAnswer("SERVFAIL", "60", "ipa1.ipa.pilot.internal."), digPrimarySOA, digReplicaSOA, both},
		"negative TTL above the cap":                      {tierAnswer("NXDOMAIN", "3600", "ipa1.ipa.pilot.internal."), digPrimarySOA, digReplicaSOA, both},
		"no FreeIPA server answers its SOA":               {tierAnswer("NXDOMAIN", "60", "ipa1.ipa.pilot.internal."), "", "", both},
		"no SOA in the tier's answer":                     {";; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1\n", digPrimarySOA, digReplicaSOA, both},
		"the tier does not answer (communications error)": {";; communications error to 127.0.0.1#53: connection refused\n;; no servers could be reached\n", digPrimarySOA, digReplicaSOA, both},
	} {
		if got := runDNSC14(t, tc.tier, tc.primary, tc.replica, tc.servers); !strings.HasPrefix(got, "bad ") {
			t.Errorf("%s: C14 = %q, want bad ...", name, got)
		}
	}
}
