package spec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// tasks/freeipa-dns-client-nameserver-check.yml judges the answers of every
// nameserver a freeipa-dns-client run is about to write
// (docs/verification/freeipa-dns-client.md §1.5). These run it through
// Ansible on localhost with the answers fed in. Every answer under
// testdata/dig-nscheck is the real stdout of the resolver's own query
// (dig +time=2 +tries=2 +noall +comments +answer [+norec] @<server>
// <name> <A|AAAA>), captured 2026-10-15 on the disposable pr92 topology:
// FreeIPA 4.13.4 on AlmaLinux 9.8 (192.168.122.4, a replica at
// 192.168.122.8 with named stopped), an unbound 1.19.2 dns tier on Ubuntu
// 24.04.4 (192.168.122.2) asked from the consumer, once with the tier's
// access-control refusing it, 1.1.1.1 for an explicit public resolver, and
// 192.0.2.1 (TEST-NET-1, nothing answers) for a timeout. v6only is a name
// with only an AAAA record added to the FreeIPA zone for the capture.

type nsCheckServer struct {
	Addr, Role, Host string
	Registered       bool
	A, AAAA          string // fixture names under testdata/dig-nscheck
}

func runNSCheck(t *testing.T, freeipaAnswered bool, servers ...nsCheckServer) (int, string) {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	var roles, results []map[string]any
	for _, s := range servers {
		role := map[string]any{"addr": s.Addr, "role": s.Role, "host": s.Host, "registered": s.Registered}
		roles = append(roles, role)
		for qtype, name := range map[string]string{"A": s.A, "AAAA": s.AAAA} {
			out, err := os.ReadFile(filepath.Join("testdata", "dig-nscheck", name))
			if err != nil {
				t.Fatal(err)
			}
			results = append(results, map[string]any{"item": []any{role, qtype}, "stdout": strings.TrimRight(string(out), "\n"), "rc": 0})
		}
	}
	task, err := filepath.Abs(filepath.Join("..", "..", "playbooks", "apply", "tasks", "freeipa-dns-client-nameserver-check.yml"))
	if err != nil {
		t.Fatal(err)
	}
	play := []map[string]any{{
		"name": "nameserver check", "hosts": "localhost", "connection": "local", "gather_facts": false,
		"vars": map[string]any{
			"freeipa_dns_ns_roles":            roles,
			"freeipa_dns_ns_results":          map[string]any{"results": results},
			"freeipa_dns_ns_name":             "ipa1.ipa.pilot.internal",
			"freeipa_dns_ns_freeipa_answered": freeipaAnswered,
		},
		"tasks": []any{map[string]any{"ansible.builtin.include_tasks": task}},
	}}
	body, err := yaml.Marshal(play)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "play.yml")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ansible-playbook", "-i", "localhost,", path)
	cmd.Env = append(os.Environ(), "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False", "ANSIBLE_DEPRECATION_WARNINGS=False")
	out, runErr := cmd.CombinedOutput()
	if ee, ok := runErr.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	} else if runErr != nil {
		t.Fatalf("ansible-playbook did not run: %v", runErr)
	}
	return 0, string(out)
}

func TestRegression_ResolverNameserverCheck(t *testing.T) {
	ipa := nsCheckServer{Addr: "192.168.122.4", Role: "freeipa", Host: "pr92-ipa", Registered: true, A: "freeipa_a_ok.txt", AAAA: "freeipa_aaaa_nodata.txt"}
	tier := nsCheckServer{Addr: "192.168.122.2", Role: "tier", Host: "pr92-dns", A: "tier_a_ok.txt", AAAA: "tier_aaaa_nodata.txt"}
	replicaDown := nsCheckServer{Addr: "192.168.122.8", Role: "freeipa", Host: "pr92-r2", Registered: true, A: "freeipa_a_connrefused.txt", AAAA: "freeipa_aaaa_connrefused.txt"}
	ipv6Only := nsCheckServer{Addr: "192.168.122.4", Role: "freeipa", Host: "pr92-ipa", Registered: true, A: "freeipa_v6only_a_nodata.txt", AAAA: "freeipa_v6only_aaaa_ok.txt"}
	publicResolver := nsCheckServer{Addr: "1.1.1.1", Role: "explicit", A: "explicit_a_nxdomain.txt", AAAA: "explicit_aaaa_nxdomain.txt"}
	tierRefusing := nsCheckServer{Addr: "192.168.122.2", Role: "tier", Host: "pr92-dns", A: "tier_a_refused.txt", AAAA: "tier_aaaa_refused.txt"}
	gone := nsCheckServer{Addr: "192.0.2.1", Role: "explicit", A: "unreachable_a_timeout.txt", AAAA: "unreachable_aaaa_timeout.txt"}

	for _, c := range []struct {
		name     string
		answered bool
		servers  []nsCheckServer
		rc       int
		want     []string
		not      []string
	}{
		// Should pass.
		{"tier and FreeIPA answer", true, []nsCheckServer{tier, ipa}, 0, nil, []string{"WARNING: localhost"}},
		{"a registered FreeIPA server is down", true, []nsCheckServer{tier, ipa, replicaDown}, 0,
			[]string{"WARNING: localhost: nameserver 192.168.122.8 (freeipa pr92-r2) did not answer", "check named on pr92-r2"}, nil},
		{"an IPv6-only answer is an address", true, []nsCheckServer{ipv6Only}, 0, nil, []string{"WARNING: localhost"}},
		{"nobody from FreeIPA answered: an unregistered server only warns", false,
			[]nsCheckServer{tier, {Addr: "192.168.122.8", Role: "freeipa", Host: "pr92-r2", A: "freeipa_a_connrefused.txt", AAAA: "freeipa_aaaa_connrefused.txt"}}, 0,
			[]string{"WARNING: localhost: nameserver 192.168.122.8"}, nil},
		{"an explicit server that does not answer only warns", true, []nsCheckServer{ipa, gone}, 0,
			[]string{"WARNING: localhost: nameserver 192.0.2.1 (explicit) did not answer", "explicit freeipa_dns_client_servers entry"}, nil},
		// Should trigger.
		{"an explicit server answers NXDOMAIN", true, []nsCheckServer{ipa, publicResolver}, 2,
			[]string{"the resolver was not changed", "1.1.1.1 (explicit)", "answers, but with no A or AAAA record for ipa1.ipa.pilot.internal", "fix or remove this freeipa_dns_client_servers entry"}, nil},
		{"the tier refuses the client", true, []nsCheckServer{tierRefusing, ipa}, 2,
			[]string{"192.168.122.2 (tier pr92-dns)", "apply playbooks/apply/dns-apply.yml to this dns tier host"}, nil},
		{"an unregistered FreeIPA server does not answer", true,
			[]nsCheckServer{tier, ipa, {Addr: "192.168.122.8", Role: "freeipa", Host: "pr92-r2", A: "freeipa_a_connrefused.txt", AAAA: "freeipa_aaaa_connrefused.txt"}}, 2,
			[]string{"192.168.122.8 (pr92-r2) does not answer and", "FreeIPA does not list it as a DNS server: promote it with DNS"}, nil},
		{"this host's own unregistered FreeIPA DNS does not answer", true,
			[]nsCheckServer{{Addr: "127.0.0.1", Role: "freeipa-self", Host: "pr92-r2", A: "freeipa_a_connrefused.txt", AAAA: "freeipa_aaaa_connrefused.txt"}, ipa}, 2,
			[]string{"127.0.0.1 (pr92-r2) does not answer and", "promote it with DNS"}, nil},
		{"nothing answers", false, []nsCheckServer{gone, replicaDown}, 2,
			[]string{"None of ['192.0.2.1', '192.168.122.8']", "answered ipa1.ipa.pilot.internal with an address"}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			rc, out := runNSCheck(t, c.answered, c.servers...)
			flat := strings.Join(strings.Fields(out), " ")
			if rc != c.rc {
				t.Fatalf("rc = %d, want %d:\n%s", rc, c.rc, out)
			}
			for _, w := range c.want {
				if !strings.Contains(flat, w) {
					t.Errorf("output lacks %q:\n%s", w, out)
				}
			}
			for _, w := range c.not {
				if strings.Contains(flat, w) {
					t.Errorf("output has %q:\n%s", w, out)
				}
			}
		})
	}
}
