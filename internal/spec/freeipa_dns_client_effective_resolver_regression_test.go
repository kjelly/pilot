package spec

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Issue #168: C3/C4/C5/C6/C7 read what pilot wrote or the first answer, never
// the nameservers glibc will actually ask. C8 and two playbook steps (a
// read-only report before the write, a gate after it) do. These tests keep
// them honest:
//
//   - C8 runs as the spec's own command text against a temporary resolv.conf,
//     with `dig` and `resolvectl` replaced by fakes that replay REAL captures
//     (testdata/dig-nscheck, testdata/dig-effective; provenance in their
//     READMEs). Every gate has a case that must pass and a case that must
//     trigger (AGENTS.md section 5.12).
//   - The classes C8 prints are compared with the ones the pre-write check
//     (tasks/freeipa-dns-client-nameserver-check.yml) computes for the same
//     captures (section 5.7: one fact, two implementations).
//   - The report and the gate run as the playbook's real tasks through
//     ansible-playbook on localhost. Only the path of /etc/resolv.conf is
//     substituted in a copy of the task file; nmcli and resolvectl are fakes
//     on PATH.

const (
	effectiveResolverFile = "../../playbooks/apply/tasks/freeipa-dns-client-effective-resolver.yml"
	c8PassToken           = "resolver-effective-ok"
	c8WrongToken          = "resolver-effective-wrong"
)

// digFixture names the captured dig outputs of one nameserver, relative to
// testdata/.
type digFixture struct{ A, AAAA string }

var c8Fixtures = map[string]digFixture{
	// FreeIPA 4.13 named, recursion desired (RD=1) as glibc asks, authoritative.
	"freeipa": {"dig-effective/freeipa_rd_a_ok.txt", "dig-effective/freeipa_rd_aaaa_nodata.txt"},
	// unbound dns tier.
	"tier": {"dig-nscheck/tier_a_ok.txt", "dig-nscheck/tier_aaaa_nodata.txt"},
	// FreeIPA name with only an AAAA record.
	"v6only": {"dig-nscheck/freeipa_v6only_a_nodata.txt", "dig-nscheck/freeipa_v6only_aaaa_ok.txt"},
	// 1.1.1.1 asked for a private name.
	"public": {"dig-nscheck/explicit_a_nxdomain.txt", "dig-nscheck/explicit_aaaa_nxdomain.txt"},
	// libvirt dnsmasq (the DHCP-supplied resolver of a vm-target) asked for the same name.
	"dnsmasq": {"dig-effective/dnsmasq_a_nxdomain.txt", "dig-effective/dnsmasq_aaaa_nxdomain.txt"},
	// The same three answers as printed by AlmaLinux 9's dig 9.16, whose
	// timeout text differs from 9.18's.
	"el-freeipa": {"dig-effective/el_freeipa_rd_a_ok.txt", "dig-effective/el_freeipa_rd_aaaa_nodata.txt"},
	"el-dnsmasq": {"dig-effective/el_dnsmasq_a_nxdomain.txt", "dig-effective/el_dnsmasq_aaaa_nxdomain.txt"},
	"el-timeout": {"dig-effective/el_unreachable_a_timeout.txt", "dig-effective/el_unreachable_aaaa_timeout.txt"},
	// unbound tier with ACL refusing the client.
	"refused": {"dig-nscheck/tier_a_refused.txt", "dig-nscheck/tier_aaaa_refused.txt"},
	// unbound tier whose FreeIPA upstream is unavailable.
	"servfail": {"dig-nscheck/tier_a_servfail.txt", "dig-nscheck/tier_aaaa_servfail.txt"},
	// TEST-NET-1: nothing answers.
	"timeout": {"dig-effective/unreachable_a_timeout.txt", "dig-effective/unreachable_aaaa_timeout.txt"},
	// FreeIPA name answered NOERROR with neither an A nor an AAAA record.
	"nodata": {"dig-nscheck/freeipa_v6only_a_nodata.txt", "dig-nscheck/freeipa_aaaa_nodata.txt"},
}

func c8Row(t *testing.T) Row {
	t.Helper()
	s, err := Parse("../../docs/verification/freeipa-dns-client.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range s.Rows {
		if r.ID == "C8" {
			return r
		}
	}
	t.Fatal("C8 not found in freeipa-dns-client.md")
	return Row{}
}

// c8Command returns the spec's C8 command with /etc/resolv.conf replaced.
func c8Command(t *testing.T, resolvConf string) string {
	t.Helper()
	row := c8Row(t)
	if row.Expected != "~"+c8PassToken {
		t.Fatalf("C8 expected = %q, want ~%s", row.Expected, c8PassToken)
	}
	if n := strings.Count(row.Command, "/etc/resolv.conf"); n != 1 {
		t.Fatalf("C8 command mentions /etc/resolv.conf %d times; the harness replaces exactly one", n)
	}
	return strings.ReplaceAll(row.Command, "/etc/resolv.conf", resolvConf)
}

// c8Env is a sandbox PATH holding only what C8 may use, plus fakes.
type c8Env struct {
	root, bin, digDir, resolv string
}

func newC8Env(t *testing.T) *c8Env {
	t.Helper()
	// Not t.TempDir(): its path carries the subtest name, and the path is
	// pasted into shell text unquoted (the spec's own command text and the
	// reader's conf= line), where a parenthesis or a space would break it.
	root, err := os.MkdirTemp("", "c8env")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	e := &c8Env{root: root, bin: filepath.Join(root, "bin"), digDir: filepath.Join(root, "dig"), resolv: filepath.Join(root, "resolv.conf")}
	for _, d := range []string{e.bin, e.digDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, tool := range []string{"awk", "mktemp", "rm", "cat", "cp", "sleep", "grep"} {
		path, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("%s not installed: %v", tool, err)
		}
		if err := os.Symlink(path, filepath.Join(e.bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func (e *c8Env) install(t *testing.T, name, script string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.bin, name), []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
}

// fakeDig replays the capture stored for (@server, query type). The row asks
// for `+noall +comments +answer`; the capture is what a real dig printed for
// the same options.
func (e *c8Env) fakeDig(t *testing.T) {
	t.Helper()
	e.install(t, "dig", `addr=; qtype=
for a in "$@"; do case $a in @*) addr=${a#@};; esac; qtype=$a; done
f="$FAKE_DIG_DIR/$addr.$qtype"
if [ -f "$f" ]; then
  cat "$f"
  if [ -f "$f.rc" ]; then exit "$(cat "$f.rc")"; fi
  exit 0
fi
echo "fake dig: no capture for $addr $qtype" >&2
exit 99
`)
}

func (e *c8Env) fakeResolvectl(t *testing.T, out string, rc int) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.root, "resolvectl.out"), []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	e.install(t, "resolvectl", fmt.Sprintf("cat %q\nexit %d\n", filepath.Join(e.root, "resolvectl.out"), rc))
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// serve stores the captures of one nameserver under the address the fake dig
// looks up. A capture may have a .rc sidecar with dig's exit status.
func (e *c8Env) serve(t *testing.T, addr string, fx digFixture) {
	t.Helper()
	for qtype, name := range map[string]string{"A": fx.A, "AAAA": fx.AAAA} {
		dst := filepath.Join(e.digDir, addr+"."+qtype)
		if err := os.WriteFile(dst, readFixture(t, name), 0o644); err != nil {
			t.Fatal(err)
		}
		if rc, err := os.ReadFile(filepath.Join("testdata", strings.TrimSuffix(name, ".txt")+".rc")); err == nil {
			if err := os.WriteFile(dst+".rc", rc, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// run executes the C8 command text under shell and returns stdout.
func (e *c8Env) run(t *testing.T, shell, resolvConf string) string {
	t.Helper()
	if err := os.WriteFile(e.resolv, []byte(resolvConf), 0o644); err != nil {
		t.Fatal(err)
	}
	shellPath, err := exec.LookPath(shell)
	if err != nil {
		t.Skipf("%s not installed", shell)
	}
	cmd := exec.Command(shellPath, "-c", c8Command(t, e.resolv))
	cmd.Env = []string{"PATH=" + e.bin, "FAKE_DIG_DIR=" + e.digDir, "TMPDIR=" + e.root}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("C8 under %s failed to run: %v\n%s", shell, err, out)
	}
	return strings.TrimSpace(string(out))
}

// c8Shells are the shells the row may run under: ansible's shell module uses
// /bin/sh, which is dash on Ubuntu and bash on EL.
func c8Shells() []string {
	var out []string
	for _, s := range []string{"sh", "bash", "dash"} {
		if _, err := exec.LookPath(s); err == nil {
			out = append(out, s)
		}
	}
	return out
}

var c8ServerRE = regexp.MustCompile(`(\S+)=(address|no_address|servfail|no_answer)(?:\(([A-Z0-9]+)\))?`)

// c8Servers parses the `servers=` tail of C8's single output line.
func c8Servers(t *testing.T, out string) map[string]string {
	t.Helper()
	_, tail, ok := strings.Cut(out, " servers=")
	if !ok {
		t.Fatalf("C8 output has no servers= tail: %q", out)
	}
	got := map[string]string{}
	for _, m := range c8ServerRE.FindAllStringSubmatch(tail, -1) {
		got[m[1]] = m[2]
		if m[3] != "" {
			got[m[1]] += "(" + m[3] + ")"
		}
	}
	return got
}

func TestRegression_FreeipaDNSClientC8Structure(t *testing.T) {
	row := c8Row(t)
	if strings.Contains(row.Command, "grep -q") {
		t.Errorf("C8 uses grep -q with a ~substring expected: quiet grep prints nothing, so the substring never matches")
	}
	if strings.Count(row.Command, c8PassToken) != 1 {
		t.Errorf("C8 must print %q from exactly one place", c8PassToken)
	}
	if strings.Contains(c8WrongToken, c8PassToken) {
		t.Errorf("the PASS token %q is a substring of the FAIL token %q", c8PassToken, c8WrongToken)
	}
	if !ansibleSplitArgsBalanced(row.Command) {
		t.Errorf("Ansible's split_args rejects the C8 command")
	}
	// glibc sets RD on its queries and waits for the answer, so C8 asks the
	// way glibc does: recursion desired (no +norec; the pre-write check uses
	// +norec only to ask a FreeIPA server what it owns), bounded to 2 s, one
	// try, and the comment/answer sections that the classification reads.
	for _, want := range []string{"+time=2", "+tries=1", "+noall", "+comments", "+answer"} {
		if !strings.Contains(row.Command, want) {
			t.Errorf("C8's dig query lacks %s", want)
		}
	}
	if strings.Contains(row.Command, "+norec") {
		t.Errorf("C8 must ask with recursion desired like glibc, not +norec")
	}
	// glibc MAXNS: only the first three nameserver lines count.
	if !strings.Contains(row.Command, "++c <= 3") {
		t.Errorf("C8 must consider only the first 3 nameserver lines (glibc MAXNS)")
	}
}

func TestRegression_FreeipaDNSClientC8EffectiveResolver(t *testing.T) {
	stubCapture := string(readFixture(t, "dig-effective/resolvectl_dns_stub.txt")) // resolvectl dns on a vm-target with the stub, see dig-effective/README.md
	cases := []struct {
		name       string
		resolv     string
		serve      map[string]string // address -> c8Fixtures key
		resolvectl string            // "" = no resolvectl on PATH
		noDig      bool
		wantPrefix string            // PASS token, or wrong token plus reason
		wantServer map[string]string // classes that must be printed
		notServer  []string          // addresses that must not be asked
	}{
		// Should pass.
		{"tier first, FreeIPA second", "search ipa.pilot.internal\nnameserver 10.0.0.2\nnameserver 10.0.0.4\noptions timeout:1 attempts:2\n",
			map[string]string{"10.0.0.2": "tier", "10.0.0.4": "freeipa"}, "", false,
			c8PassToken, map[string]string{"10.0.0.2": "address(NOERROR)", "10.0.0.4": "address(NOERROR)"}, nil},
		{"the host's own named at 127.0.0.1", "nameserver 127.0.0.1\n",
			map[string]string{"127.0.0.1": "freeipa"}, "", false,
			c8PassToken, map[string]string{"127.0.0.1": "address(NOERROR)"}, nil},
		{"an IPv6-only name answers with an AAAA record", "nameserver 10.0.0.4\n",
			map[string]string{"10.0.0.4": "v6only"}, "", false,
			c8PassToken, map[string]string{"10.0.0.4": "address(NOERROR)"}, nil},
		{"one server is down, another answers", "nameserver 10.0.0.2\nnameserver 10.0.0.4\n",
			map[string]string{"10.0.0.2": "timeout", "10.0.0.4": "freeipa"}, "", false,
			c8PassToken, map[string]string{"10.0.0.2": "no_answer", "10.0.0.4": "address(NOERROR)"}, nil},
		{"SERVFAIL on one server, another answers", "nameserver 10.0.0.2\nnameserver 10.0.0.4\n",
			map[string]string{"10.0.0.2": "servfail", "10.0.0.4": "freeipa"}, "", false,
			c8PassToken, map[string]string{"10.0.0.2": "servfail(SERVFAIL)", "10.0.0.4": "address(NOERROR)"}, nil},
		{"glibc ignores the 4th nameserver, a public one", "nameserver 10.0.0.2\nnameserver 10.0.0.3\nnameserver 10.0.0.4\nnameserver 1.1.1.1\n",
			map[string]string{"10.0.0.2": "tier", "10.0.0.3": "tier", "10.0.0.4": "freeipa", "1.1.1.1": "public"}, "", false,
			c8PassToken, map[string]string{"10.0.0.4": "address(NOERROR)"}, []string{"1.1.1.1"}},
		{"an indented or commented nameserver line is not a nameserver", "nameserver 10.0.0.4\n nameserver 1.1.1.1\n# nameserver 1.1.1.1\n",
			map[string]string{"10.0.0.4": "freeipa", "1.1.1.1": "public"}, "", false,
			c8PassToken, map[string]string{"10.0.0.4": "address(NOERROR)"}, []string{"1.1.1.1"}},
		// Should trigger.
		{"FreeIPA first, a public DNS after it", "nameserver 10.0.0.4\nnameserver 1.1.1.1\n",
			map[string]string{"10.0.0.4": "freeipa", "1.1.1.1": "public"}, "", false,
			c8WrongToken + " server-without-address", map[string]string{"10.0.0.4": "address(NOERROR)", "1.1.1.1": "no_address(NXDOMAIN)"}, nil},
		{"the third nameserver is a public DNS", "nameserver 10.0.0.2\nnameserver 10.0.0.4\nnameserver 1.1.1.1\n",
			map[string]string{"10.0.0.2": "tier", "10.0.0.4": "freeipa", "1.1.1.1": "public"}, "", false,
			c8WrongToken + " server-without-address", map[string]string{"1.1.1.1": "no_address(NXDOMAIN)"}, nil},
		{"dig 9.16 on EL, one server is down, another answers", "nameserver 10.0.0.2\nnameserver 10.0.0.4\n",
			map[string]string{"10.0.0.2": "el-timeout", "10.0.0.4": "el-freeipa"}, "", false,
			c8PassToken, map[string]string{"10.0.0.2": "no_answer", "10.0.0.4": "address(NOERROR)"}, nil},
		{"dig 9.16 on EL, no server answers", "nameserver 10.0.0.2\nnameserver 10.0.0.4\n",
			map[string]string{"10.0.0.2": "el-timeout", "10.0.0.4": "el-timeout"}, "", false,
			c8WrongToken + " no-server-returned-an-address", map[string]string{"10.0.0.2": "no_answer"}, nil},
		{"dig 9.16 on EL, the DHCP resolver does not know the name", "nameserver 10.0.0.4\nnameserver 192.168.122.1\n",
			map[string]string{"10.0.0.4": "el-freeipa", "192.168.122.1": "el-dnsmasq"}, "", false,
			c8WrongToken + " server-without-address", map[string]string{"192.168.122.1": "no_address(NXDOMAIN)"}, nil},
		{"the DHCP resolver does not know the name", "nameserver 10.0.0.4\nnameserver 192.168.122.1\n",
			map[string]string{"10.0.0.4": "freeipa", "192.168.122.1": "dnsmasq"}, "", false,
			c8WrongToken + " server-without-address", nil, nil},
		{"the tier refuses the client", "nameserver 10.0.0.2\nnameserver 10.0.0.4\n",
			map[string]string{"10.0.0.2": "refused", "10.0.0.4": "freeipa"}, "", false,
			c8WrongToken + " server-without-address", map[string]string{"10.0.0.2": "no_address(REFUSED)"}, nil},
		{"NOERROR without an A or AAAA record", "nameserver 10.0.0.2\nnameserver 10.0.0.4\n",
			map[string]string{"10.0.0.2": "nodata", "10.0.0.4": "freeipa"}, "", false,
			c8WrongToken + " server-without-address", map[string]string{"10.0.0.2": "no_address(NOERROR)"}, nil},
		{"no server answers", "nameserver 10.0.0.2\nnameserver 10.0.0.4\n",
			map[string]string{"10.0.0.2": "timeout", "10.0.0.4": "timeout"}, "", false,
			c8WrongToken + " no-server-returned-an-address", map[string]string{"10.0.0.2": "no_answer", "10.0.0.4": "no_answer"}, nil},
		{"every server returns SERVFAIL", "nameserver 10.0.0.2\nnameserver 10.0.0.4\n",
			map[string]string{"10.0.0.2": "servfail", "10.0.0.4": "servfail"}, "", false,
			c8WrongToken + " no-server-returned-an-address", map[string]string{"10.0.0.2": "servfail(SERVFAIL)"}, nil},
		{"resolv.conf has no nameserver", "search ipa.pilot.internal\n", nil, "", false,
			c8WrongToken + " no-server-returned-an-address", nil, nil},
		{"the systemd-resolved stub, and what is behind it is listed", "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch .\n",
			map[string]string{"192.168.122.1": "dnsmasq"}, stubCapture, false,
			c8WrongToken + " stub=127.0.0.53", map[string]string{"192.168.122.1": "no_address(NXDOMAIN)"}, nil},
		{"the stub with a resolvectl that is not installed", "nameserver 127.0.0.53\n", nil, "", false,
			c8WrongToken + " stub=127.0.0.53 resolvectl-not-found", nil, nil},
		{"the stub on a host whose resolv.conf has FreeIPA after it", "nameserver 127.0.0.53\nnameserver 10.0.0.4\n",
			map[string]string{"10.0.0.4": "freeipa", "192.168.122.1": "dnsmasq"}, stubCapture, false,
			c8WrongToken + " stub=127.0.0.53", map[string]string{"10.0.0.4": "address(NOERROR)"}, nil},
		{"dig is not installed", "nameserver 10.0.0.4\n", nil, "", true,
			c8WrongToken + " dig-not-found", nil, nil},
	}
	for _, shell := range c8Shells() {
		for _, tc := range cases {
			t.Run(shell+"/"+tc.name, func(t *testing.T) {
				e := newC8Env(t)
				if !tc.noDig {
					e.fakeDig(t)
				}
				if tc.resolvectl != "" {
					e.fakeResolvectl(t, tc.resolvectl, 0)
				}
				for addr, key := range tc.serve {
					e.serve(t, addr, c8Fixtures[key])
				}
				out := e.run(t, shell, tc.resolv)
				if !strings.HasPrefix(out, tc.wantPrefix) {
					t.Fatalf("C8 = %q, want prefix %q", out, tc.wantPrefix)
				}
				if strings.Contains(tc.wantPrefix, c8WrongToken) && strings.Contains(out, c8PassToken) {
					t.Errorf("a FAIL output contains the PASS token: %q", out)
				}
				if !strings.Contains(tc.wantPrefix, c8WrongToken) && strings.Contains(out, c8WrongToken) {
					t.Errorf("a PASS output contains the FAIL token: %q", out)
				}
				if len(tc.wantServer) > 0 {
					got := c8Servers(t, out)
					for addr, want := range tc.wantServer {
						if got[addr] != want {
							t.Errorf("server %s printed as %q, want %q (output %q)", addr, got[addr], want, out)
						}
					}
				}
				for _, addr := range tc.notServer {
					if strings.Contains(out, addr) {
						t.Errorf("C8 asked or printed %s, which glibc never asks: %q", addr, out)
					}
				}
			})
		}
	}
}

// TestRegression_FreeipaDNSClientDriftIsOnlyVisibleToC8 is the reproduction
// of issue #168 as a test: on a resolv.conf that lists FreeIPA first and a
// public DNS after it (with the options line and search domain the role
// writes), the config rows that read the file all pass, and only C8 fails.
// Without C8 nothing in the checklist notices the list was changed after
// pilot wrote it.
func TestRegression_FreeipaDNSClientDriftIsOnlyVisibleToC8(t *testing.T) {
	drifted := "# pilot-freeipa-dns-client: managed by tasks/freeipa-dns-client-resolver.yml\n" +
		"search ipa.pilot.internal\nnameserver 10.0.0.2\nnameserver 10.0.0.4\nnameserver 1.1.1.1\noptions timeout:1 attempts:2\n"
	s, err := Parse("../../docs/verification/freeipa-dns-client.md")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(newC8Env(t).root, "resolv.conf")
	if err := os.WriteFile(path, []byte(drifted), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"C4", "C5", "C7"} {
		var row Row
		for _, r := range s.Rows {
			if r.ID == id {
				row = r
			}
		}
		cmd := exec.Command("sh", "-c", strings.ReplaceAll(row.Command, "/etc/resolv.conf", path))
		out, runErr := cmd.CombinedOutput()
		switch {
		case strings.HasPrefix(row.Expected, "~"):
			if !strings.Contains(string(out), strings.TrimPrefix(row.Expected, "~")) {
				t.Errorf("%s no longer passes on the drifted file (rc %v, output %q): this test documents what the other rows cannot see", id, runErr, out)
			}
		default: // an exit-code row: 0
			if runErr != nil {
				t.Errorf("%s no longer passes on the drifted file: %v %s", id, runErr, out)
			}
		}
	}
	e := newC8Env(t)
	e.fakeDig(t)
	e.serve(t, "10.0.0.2", c8Fixtures["tier"])
	e.serve(t, "10.0.0.4", c8Fixtures["freeipa"])
	e.serve(t, "1.1.1.1", c8Fixtures["public"])
	for _, shell := range c8Shells() {
		if out := e.run(t, shell, drifted); !strings.HasPrefix(out, c8WrongToken+" server-without-address") || !strings.Contains(out, "1.1.1.1=no_address(NXDOMAIN)") {
			t.Errorf("under %s C8 = %q, want a FAIL naming 1.1.1.1", shell, out)
		}
	}
}

// TestRegression_FreeipaDNSClientC8LeavesNoTempFiles locks the trap: C8 writes
// every dig answer into a temp directory.
func TestRegression_FreeipaDNSClientC8LeavesNoTempFiles(t *testing.T) {
	e := newC8Env(t)
	e.fakeDig(t)
	e.serve(t, "10.0.0.4", c8Fixtures["freeipa"])
	for _, shell := range c8Shells() {
		out := e.run(t, shell, "nameserver 10.0.0.4\n")
		if !strings.HasPrefix(out, c8PassToken) {
			t.Fatalf("C8 under %s = %q", shell, out)
		}
		left, err := filepath.Glob(filepath.Join(e.root, "tmp.*"))
		if err != nil || len(left) != 0 {
			t.Errorf("C8 under %s left temp files behind: %v %v", shell, left, err)
		}
	}
}

// ---------------------------------------------------------------------------
// C8 and the pre-write nameserver check must classify one capture alike.
// ---------------------------------------------------------------------------

func digFixtureFiles(t *testing.T) (a, aaaa []string) {
	t.Helper()
	for _, dir := range []string{"dig-nscheck", "dig-effective"} {
		files, err := filepath.Glob(filepath.Join("testdata", dir, "*.txt"))
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(files)
		for _, f := range files {
			rel := filepath.ToSlash(strings.TrimPrefix(f, "testdata"+string(filepath.Separator)))
			base := filepath.Base(f)
			switch {
			case strings.Contains(base, "_aaaa_"):
				aaaa = append(aaaa, rel)
			case strings.Contains(base, "_a_"):
				a = append(a, rel)
			}
		}
	}
	return a, aaaa
}

// nsCheckClassify runs tasks/freeipa-dns-client-nameserver-check.yml on the
// given captures and returns the state it assigns to each address. The gate
// at the end of the file fails when the whole set has no working server; the
// facts it computed before are still read.
func nsCheckClassify(t *testing.T, servers map[string]digFixture) map[string]string {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	var roles, results []map[string]any
	addrs := make([]string, 0, len(servers))
	for addr := range servers {
		addrs = append(addrs, addr)
	}
	sort.Strings(addrs)
	for _, addr := range addrs {
		role := map[string]any{"addr": addr, "role": "tier", "host": "", "registered": false}
		roles = append(roles, role)
		for qtype, name := range map[string]string{"A": servers[addr].A, "AAAA": servers[addr].AAAA} {
			rc := 0
			if b, err := os.ReadFile(filepath.Join("testdata", strings.TrimSuffix(name, ".txt")+".rc")); err == nil {
				rc, _ = strconv.Atoi(strings.TrimSpace(string(b)))
			}
			results = append(results, map[string]any{"item": []any{role, qtype}, "stdout": strings.TrimRight(string(readFixture(t, name)), "\n"), "stderr": "", "rc": rc})
		}
	}
	task, err := filepath.Abs(filepath.Join("..", "..", "playbooks", "apply", "tasks", "freeipa-dns-client-nameserver-check.yml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	outFile := filepath.Join(dir, "classified.json")
	play := []map[string]any{{
		"name": "classify", "hosts": "localhost", "connection": "local", "gather_facts": false,
		"vars": map[string]any{
			"freeipa_dns_ns_roles":            roles,
			"freeipa_dns_ns_results":          map[string]any{"results": results},
			"freeipa_dns_ns_name":             "ipa1.ipa.pilot.internal",
			"freeipa_dns_ns_freeipa_answered": false,
		},
		"tasks": []any{
			map[string]any{
				"block":  []any{map[string]any{"ansible.builtin.include_tasks": task}},
				"rescue": []any{map[string]any{"ansible.builtin.debug": map[string]any{"msg": "the gate rejected this set, as expected for some of the captures"}}},
			},
			map[string]any{"ansible.builtin.copy": map[string]any{"dest": outFile, "content": "{{ freeipa_dns_ns_classified | to_json }}"}},
		},
	}}
	body, err := yaml.Marshal(play)
	if err != nil {
		t.Fatal(err)
	}
	pb := filepath.Join(dir, "play.yml")
	if err := os.WriteFile(pb, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ansible-playbook", "-i", "localhost,", pb)
	cmd.Env = append(os.Environ(), "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False", "ANSIBLE_DEPRECATION_WARNINGS=False")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ansible-playbook: %v\n%s", err, out)
	}
	var classified []struct {
		Addr  string `json:"addr"`
		State string `json:"state"`
	}
	if err := json.Unmarshal([]byte(readFile(t, outFile)), &classified); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range classified {
		got[c.Addr] = c.State
	}
	return got
}

// TestRegression_FreeipaDNSClientC8ClassesMatchTheNameserverCheck feeds every
// pairing of an A capture with an AAAA capture to both implementations.
func TestRegression_FreeipaDNSClientC8ClassesMatchTheNameserverCheck(t *testing.T) {
	aFiles, aaaaFiles := digFixtureFiles(t)
	if len(aFiles) < 6 || len(aaaaFiles) < 6 {
		t.Fatalf("only %d A and %d AAAA captures found; the corpus is incomplete", len(aFiles), len(aaaaFiles))
	}
	combos := map[string]digFixture{}
	label := map[string]string{}
	n := 0
	for _, a := range aFiles {
		for _, aaaa := range aaaaFiles {
			n++
			addr := fmt.Sprintf("10.%d.%d.1", n/250, n%250)
			combos[addr] = digFixture{a, aaaa}
			label[addr] = a + " + " + aaaa
		}
	}
	want := nsCheckClassify(t, combos)
	if len(want) != len(combos) {
		t.Fatalf("the nameserver check classified %d of %d servers", len(want), len(combos))
	}

	// C8 prints `address`, `no_address(<rcode>)`, `servfail(SERVFAIL)` or
	// `no_answer`; the nameserver check says address, no_address, servfail,
	// no_answer.
	addrs := make([]string, 0, len(combos))
	for addr := range combos {
		addrs = append(addrs, addr)
	}
	sort.Strings(addrs)
	classesSeen := map[string]bool{}
	for _, shell := range c8Shells() {
		for i := 0; i < len(addrs); i += 3 {
			end := i + 3
			if end > len(addrs) {
				end = len(addrs)
			}
			chunk := addrs[i:end]
			e := newC8Env(t)
			e.fakeDig(t)
			var resolv strings.Builder
			for _, addr := range chunk {
				e.serve(t, addr, combos[addr])
				resolv.WriteString("nameserver " + addr + "\n")
			}
			got := c8Servers(t, e.run(t, shell, resolv.String()))
			for _, addr := range chunk {
				class, _, _ := strings.Cut(got[addr], "(")
				classesSeen[class] = true
				if class != want[addr] {
					t.Errorf("under %s, C8 classifies %s as %q but the nameserver check says %q", shell, label[addr], got[addr], want[addr])
				}
			}
		}
	}
	for _, class := range []string{"address", "no_address", "servfail", "no_answer"} {
		if !classesSeen[class] {
			t.Errorf("no capture pairing produced the class %q; the comparison does not exercise it", class)
		}
	}
}

// ---------------------------------------------------------------------------
// The report and the gate, as the playbook's own tasks.
// ---------------------------------------------------------------------------

const (
	effReadBefore   = "FreeIPA DNS client — effective resolver before this run: read"
	effReport       = "FreeIPA DNS client — effective resolver before this run: report"
	effReadAfter    = "FreeIPA DNS client — effective resolver after the write: read"
	effReload       = "EL — regenerate /etc/resolv.conf from the connection profile (nmcli general reload dns-rc)"
	effReadReloaded = "EL — effective resolver after the reload: read again (waits up to 10 seconds)"
	effGate         = "FreeIPA DNS client — Gate: the resolver glibc uses is the one this run wrote"
	resolverFunc    = "FreeIPA DNS client — FreeIPA server FQDN actually resolves via DNS"
)

// TestRegression_FreeipaDNSClientEffectiveResolverPlacement locks where the
// two steps sit in the shared task file.
func TestRegression_FreeipaDNSClientEffectiveResolverPlacement(t *testing.T) {
	tasks := resolverTaskList(t)
	before := taskIndexByName(tasks, effReadBefore)
	report := taskIndexByName(tasks, effReport)
	ask := taskIndexByName(tasks, "FreeIPA DNS client — what each nameserver to be written is: reset")
	snap := taskIndexByName(tasks, resolverSnapshotTask)
	block := taskIndexByName(tasks, resolverBlockTask)
	if before < 0 || report != before+1 || ask < 0 || snap < 0 || block < 0 {
		t.Fatalf("report tasks not found in order: read=%d report=%d ask=%d snapshot=%d block=%d", before, report, ask, snap, block)
	}
	if report >= ask || ask >= snap || snap >= block {
		t.Errorf("the report must come before the nameserver questions and the snapshot (read=%d report=%d ask=%d snapshot=%d)", before, report, ask, snap)
	}
	inc, _ := tasks[before]["ansible.builtin.include_tasks"].(map[string]any)
	if inc["file"] != "freeipa-dns-client-effective-resolver.yml" {
		t.Errorf("report include = %v", inc)
	}
	for _, name := range []string{effReadBefore, effReport} {
		if w, ok := tasks[taskIndexByName(tasks, name)]["when"]; ok {
			t.Errorf("%q has when: %v; the report must run under --check and in a real run", name, w)
		}
	}

	inner := resolverBlockTasks(t, resolverTaskList(t))
	idx := map[string]int{}
	for _, name := range []string{"EL — fall back to `nmcli con up` if reapply was rejected", effReadAfter, effReload, effReadReloaded, effGate, resolverFunc} {
		idx[name] = taskIndexByName(inner, name)
		if idx[name] < 0 {
			t.Fatalf("block task %q not found", name)
		}
	}
	if idx["EL — fall back to `nmcli con up` if reapply was rejected"] >= idx[effReadAfter] || idx[effReadAfter] >= idx[effReload] ||
		idx[effReload] >= idx[effReadReloaded] || idx[effReadReloaded] >= idx[effGate] || idx[effGate] >= idx[resolverFunc] {
		t.Errorf("gate tasks out of order inside the block: %v", idx)
	}
	for _, name := range []string{effReadAfter, effGate} {
		if inner[idx[name]]["when"] != "not ansible_check_mode" {
			t.Errorf("%q: when = %v, want %q (a check run writes nothing, so there is nothing to compare)", name, inner[idx[name]]["when"], "not ansible_check_mode")
		}
	}
	if _, ok := inner[idx[effGate]]["ansible.builtin.assert"]; !ok {
		t.Errorf("the gate must be an assert, so a mismatch fails the block and reaches the rescue")
	}
	if inner[idx[effReload]]["failed_when"] != false {
		t.Errorf("the dns-rc reload registers its result and must not fail by itself: failed_when = %v", inner[idx[effReload]]["failed_when"])
	}

	reader := readEffectiveResolverTasks(t)
	read := reader[taskIndexByName(reader, "FreeIPA DNS client effective resolver — read what glibc uses (read-only)")]
	if read["check_mode"] != false || read["changed_when"] != false {
		t.Errorf("the reader must be read-only and run under --check: check_mode=%v changed_when=%v", read["check_mode"], read["changed_when"])
	}
	if _, secret := read["no_log"]; secret {
		t.Errorf("the reader handles no secrets and must not be no_log: the report is the point")
	}
	if reader[0]["ansible.builtin.set_fact"] == nil {
		t.Errorf("the reader's first task must reset the fact it owns (the file is included more than once per play)")
	}
}

func readEffectiveResolverTasks(t *testing.T) []map[string]any {
	t.Helper()
	var tasks []map[string]any
	if err := yaml.Unmarshal([]byte(readFile(t, effectiveResolverFile)), &tasks); err != nil {
		t.Fatal(err)
	}
	return tasks
}

// TestRegression_FreeipaDNSClientAppliesTagC8 locks C8 into the include's
// tags and its apply tags, and the internal-endpoint baseline's own tag.
func TestRegression_FreeipaDNSClientAppliesTagC8(t *testing.T) {
	var plays []map[string]any
	if err := yaml.Unmarshal([]byte(readFile(t, "../../playbooks/apply/freeipa-dns-client-apply.yml")), &plays); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, play := range plays {
		tasks, _ := play["tasks"].([]any)
		for _, raw := range tasks {
			task, _ := raw.(map[string]any)
			inc, ok := task["ansible.builtin.include_tasks"].(map[string]any)
			if !ok || inc["file"] != "tasks/freeipa-dns-client-resolver.yml" {
				continue
			}
			found = true
			apply, _ := inc["apply"].(map[string]any)
			for _, tags := range [][]any{task["tags"].([]any), apply["tags"].([]any)} {
				has := false
				for _, tag := range tags {
					has = has || tag == "C8"
				}
				if !has {
					t.Errorf("tags %v lack C8; --tags C8 would select nothing", tags)
				}
			}
		}
	}
	if !found {
		t.Fatal("resolver include not found in freeipa-dns-client-apply.yml")
	}
	// internal-endpoint's fleet baseline shares the file and is tagged C9: a
	// `--tags C9` run must reach the report and the gate too, because both
	// are tasks of the shared file under the include's apply tags.
	if !strings.Contains(readFile(t, "../../playbooks/apply/internal-endpoint-apply.yml"), "file: tasks/freeipa-dns-client-resolver.yml") {
		t.Errorf("internal-endpoint-apply.yml no longer includes the shared resolver file")
	}
}

type effScenario struct {
	name       string
	osFamily   string
	resolv     string
	allowed    []string
	dropin     bool   // pilot drop-in file exists (Debian management evidence)
	ignoreAuto string // what fake nmcli prints for ipv4.ignore-auto-dns ("" = no nmcli)
	resolvectl string // "" = no resolvectl
	reloadTo   string // what a successful `nmcli general reload dns-rc` rewrites resolv.conf to ("" = nothing changes)
	nmChanged  bool   // this run changed the NetworkManager profile
	lateWrite  string // content NetworkManager writes after two seconds (an asynchronous reapply)
	check      bool
	wantRC     int
	want       []string // substrings of the flattened output
	notWant    []string
	wantReload int // number of `general reload dns-rc` calls
	changed    int // PLAY RECAP changed=
}

func runEffectiveFlow(t *testing.T, sc effScenario) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("python3 not installed: %v", err)
	}
	e := newC8Env(t)
	resolverTasks := resolverTaskList(t)
	inner := resolverBlockTasks(t, resolverTasks)
	pick := func(tasks []map[string]any, name string) map[string]any {
		i := taskIndexByName(tasks, name)
		if i < 0 {
			t.Fatalf("task %q not found", name)
		}
		return tasks[i]
	}
	// Copy the reader with the host path of resolv.conf substituted. A plain
	// temp dir, not t.TempDir(): paths go into shell text.
	dir, err := os.MkdirTemp("", "c8flow")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.WriteFile(filepath.Join(dir, "freeipa-dns-client-effective-resolver.yml"),
		[]byte(strings.ReplaceAll(readFile(t, effectiveResolverFile), "/etc/resolv.conf", e.resolv)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.resolv, []byte(sc.resolv), 0o644); err != nil {
		t.Fatal(err)
	}
	dropin := filepath.Join(dir, "90-pilot-freeipa-dns-client.conf")
	if sc.dropin {
		writeFile(t, dropin, "[Resolve]\nDNS=192.0.2.1\n")
	}
	nmLog := filepath.Join(dir, "nmcli.log")
	nmActive, _ := filepath.Abs("testdata/dig-effective/nmcli_active.txt")
	nmIgnore := ""
	switch sc.ignoreAuto {
	case "yes":
		nmIgnore, _ = filepath.Abs("testdata/dig-effective/nmcli_ignore_auto_dns_managed.txt")
	case "no":
		nmIgnore, _ = filepath.Abs("testdata/dig-effective/nmcli_ignore_auto_dns_dhcp.txt")
	}
	if sc.ignoreAuto != "" {
		// The fake answers the two reads the reader makes with what a real
		// NetworkManager 1.54.3 printed (dig-effective/README.md).
		e.install(t, "nmcli", `echo "$*" >> "$FAKE_NM_LOG"
case "$*" in
  "-t -f NAME,DEVICE connection show --active") cat "$FAKE_NM_ACTIVE" ;;
  "-g ipv4.ignore-auto-dns connection show System eth0") cat "$FAKE_NM_IGNORE_AUTO_DNS" ;;
  "general reload dns-rc") if [ -n "$FAKE_NM_RELOAD_TO" ]; then cp "$FAKE_NM_RELOAD_TO" "$FAKE_RESOLV_CONF"; fi ;;
  *) echo "fake nmcli: unexpected arguments: $*" >&2; exit 64 ;;
esac
`)
	}
	reloadSrc := filepath.Join(dir, "reload-resolv.conf")
	if sc.reloadTo != "" {
		writeFile(t, reloadSrc, sc.reloadTo)
	}
	if sc.resolvectl != "" {
		e.fakeResolvectl(t, sc.resolvectl, 0)
	}

	vars := map[string]any{
		"ansible_python_interpreter":              python,
		"ansible_os_family":                       sc.osFamily,
		"freeipa_dns_client_effective_servers":    sc.allowed,
		"freeipa_dns_client_resolved_dropin_path": dropin,
		"freeipa_dns_client_resolv_conf_marker":   "pilot-freeipa-dns-client",
	}
	if sc.nmChanged {
		vars["freeipa_dns_client_nm_mod"] = map[string]any{"changed": true}
	}
	env := map[string]string{
		"PATH":                      e.bin + string(os.PathListSeparator) + filepath.Dir(python),
		"FAKE_NM_LOG":               nmLog,
		"FAKE_NM_ACTIVE":            nmActive,
		"FAKE_NM_IGNORE_AUTO_DNS":   nmIgnore,
		"FAKE_NM_RELOAD_TO":         "",
		"FAKE_RESOLV_CONF":          e.resolv,
		"ANSIBLE_NOCOLOR":           "1",
		"ANSIBLE_LOCALHOST_WARNING": "False",
	}
	if sc.reloadTo != "" {
		env["FAKE_NM_RELOAD_TO"] = reloadSrc
	}
	tasks := []any{
		pick(resolverTasks, effReadBefore),
		pick(resolverTasks, effReport),
	}
	if sc.lateWrite != "" {
		// NetworkManager rewrites resolv.conf some time after a reapply.
		// The write is scheduled right before the gate's first read, so the
		// short wait is what lets that read see it.
		lateSrc := filepath.Join(dir, "late-resolv.conf")
		writeFile(t, lateSrc, sc.lateWrite)
		tasks = append(tasks, map[string]any{
			"name":                  "schedule the late write of resolv.conf",
			"ansible.builtin.shell": "(sleep 2; cp " + lateSrc + " " + e.resolv + ") >/dev/null 2>&1 &",
			"changed_when":          false,
		})
	}
	tasks = append(tasks, map[string]any{"name": "block", "block": []any{
		pick(inner, effReadAfter), pick(inner, effReload), pick(inner, effReadReloaded), pick(inner, effGate),
	}})
	play := []map[string]any{{
		"name": "report and gate", "hosts": "localhost", "connection": "local", "gather_facts": false,
		"vars":        vars,
		"environment": env,
		"tasks":       tasks,
	}}
	body, err := yaml.Marshal(play)
	if err != nil {
		t.Fatal(err)
	}
	pb := filepath.Join(dir, "play.yml")
	if err := os.WriteFile(pb, body, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-i", "localhost,", pb}
	if sc.check {
		args = append(args, "--check")
	}
	cmd := exec.Command("ansible-playbook", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_DEPRECATION_WARNINGS=False")
	out, runErr := cmd.CombinedOutput()
	rc := 0
	if ee, ok := runErr.(*exec.ExitError); ok {
		rc = ee.ExitCode()
	} else if runErr != nil {
		t.Fatalf("ansible-playbook did not run: %v", runErr)
	}
	if rc != sc.wantRC {
		t.Fatalf("%s: ansible-playbook rc = %d, want %d:\n%s", sc.name, rc, sc.wantRC, out)
	}
	return string(out), nmLog
}

func TestRegression_FreeipaDNSClientEffectiveResolverReportAndGate(t *testing.T) {
	const (
		tier, ipa = "192.168.122.12", "192.168.122.13"
		dhcp      = "192.168.122.1"
		managed   = "# pilot-freeipa-dns-client: managed by tasks/freeipa-dns-client-resolver.yml\n"
	)
	allowed := []string{tier, ipa}
	good := "search ipa.pilot.internal\nnameserver " + tier + "\nnameserver " + ipa + "\noptions timeout:1 attempts:2\n"
	stubCapture := string(readFixture(t, "dig-effective/resolvectl_dns_stub.txt")) // its link DNS is the DHCP resolver 192.168.122.1
	cases := []effScenario{
		// ---- the report -------------------------------------------------
		{name: "report: a host pilot does not manage yet", osFamily: "Debian", resolv: "nameserver " + dhcp + "\n", allowed: allowed,
			want: []string{"the resolver in effect before this run is " + dhcp, "This run writes " + tier + ", " + ipa,
				"pilot does not manage this host's resolver yet", "Gate: the resolver glibc uses is the one this run wrote"},
			notWant: []string{"DRIFT"}, wantRC: 2},
		{name: "report: drift after pilot managed the host, a public DNS behind FreeIPA", osFamily: "Debian", dropin: true,
			resolv: good + "nameserver 1.1.1.1\n", allowed: allowed,
			want: []string{"the resolver in effect before this run is " + tier + ", " + ipa + ", 1.1.1.1", "DRIFT: pilot manages this host's resolver",
				"the servers in use that this run does not write are 1.1.1.1", "exists"},
			notWant: []string{"does not manage this host's resolver yet"}, wantRC: 2},
		{name: "report: a managed host that matches", osFamily: "Debian", dropin: true, resolv: managed + good, allowed: allowed,
			want:    []string{"every server in use is in the list this run writes"},
			notWant: []string{"DRIFT", "does not manage"}, wantRC: 0, changed: 0},
		{name: "report: the stub is named and so is what is behind it", osFamily: "Debian", dropin: true,
			resolv: "nameserver 127.0.0.53\noptions edns0 trust-ad\n", resolvectl: stubCapture, allowed: allowed,
			want: []string{"DRIFT", "resolv.conf points at the systemd-resolved stub 127.0.0.53", "are " + dhcp,
				"and resolvectl dns for the servers behind it"}, wantRC: 2},
		{name: "report: 4th nameserver is ignored", osFamily: "Debian", dropin: true,
			resolv: "nameserver " + tier + "\nnameserver " + ipa + "\nnameserver " + tier + "\nnameserver 1.1.1.1\n", allowed: allowed,
			want:    []string{"glibc ignores line 4 onward: 1.1.1.1", "every server in use is in the list this run writes"},
			notWant: []string{"DRIFT"}, wantRC: 0},
		{name: "report on EL: managed by the NetworkManager profile", osFamily: "RedHat", ignoreAuto: "yes", resolv: good, allowed: allowed,
			want:    []string{"NetworkManager connection System eth0 has ipv4.ignore-auto-dns=yes", "every server in use is in the list this run writes"},
			notWant: []string{"DRIFT"}, wantRC: 0},
		{name: "report on EL: not managed, DHCP DNS", osFamily: "RedHat", ignoreAuto: "no", resolv: "# Generated by NetworkManager\nnameserver " + dhcp + "\n",
			reloadTo: good, allowed: allowed,
			want: []string{"does not manage this host's resolver yet"}, notWant: []string{"DRIFT"}, wantRC: 0, wantReload: 1, changed: 1},
		{name: "report needs neither dig nor resolvectl nor nmcli", osFamily: "RedHat", resolv: good, allowed: allowed,
			want: []string{"does not manage this host's resolver yet"}, wantRC: 0},
		// ---- --check: the report runs, the gate does not -----------------
		{name: "check mode: report runs, gate is skipped", osFamily: "Debian", dropin: true, resolv: good + "nameserver 1.1.1.1\n", allowed: allowed, check: true,
			want: []string{"DRIFT", "skipping: [localhost]"}, notWant: []string{"Assertion failed", "fatal:"}, wantRC: 0},
		// ---- the gate ----------------------------------------------------
		{name: "gate passes: resolv.conf is what this run wrote", osFamily: "Debian", dropin: true, resolv: good, allowed: allowed, wantRC: 0, changed: 0},
		{name: "gate passes: a subset (the installer's zzz-ipa.conf leaves 127.0.0.1)", osFamily: "RedHat", ignoreAuto: "yes",
			resolv: "# Generated by NetworkManager\nsearch ipa.pilot.internal\nnameserver 127.0.0.1\n", allowed: []string{"127.0.0.1", ipa},
			wantRC: 0, wantReload: 0, changed: 0},
		{name: "gate triggers: Debian resolv.conf has a server this run did not write (no reload on Debian)", osFamily: "Debian", dropin: true,
			resolv: good + "nameserver 1.1.1.1\n", allowed: allowed,
			want: []string{"after writing " + tier + ", " + ipa + " the resolver glibc uses is " + tier + ", " + ipa + ", 1.1.1.1",
				"Not in the list this run wrote: 1.1.1.1", "The rescue that follows puts the resolver back"},
			notWant: []string{"nmcli general reload dns-rc was run"}, wantRC: 2},
		{name: "gate triggers: resolv.conf lists no nameserver", osFamily: "Debian", dropin: true, resolv: "search ipa.pilot.internal\n", allowed: allowed,
			want: []string{"the resolver glibc uses is empty", "resolv.conf lists no nameserver"}, wantRC: 2},
		{name: "gate triggers: resolv.conf is the stub again", osFamily: "Debian", dropin: true, resolv: "nameserver 127.0.0.53\n", resolvectl: stubCapture, allowed: allowed,
			want: []string{"resolv.conf points at the systemd-resolved stub 127.0.0.53"}, wantRC: 2},
		{name: "gate triggers: a server in the subset check must be in the list, not merely in the file", osFamily: "Debian", dropin: true,
			resolv: "nameserver " + ipa + "\nnameserver " + dhcp + "\n", allowed: allowed,
			want: []string{"Not in the list this run wrote: " + dhcp}, wantRC: 2},
		// ---- EL: reload, then a bounded re-read ----------------------------
		{name: "EL: a hand edit of resolv.conf is repaired by the reload", osFamily: "RedHat", ignoreAuto: "yes",
			resolv: "nameserver 1.1.1.1\n", reloadTo: good, allowed: allowed, wantRC: 0, wantReload: 1, changed: 1,
			want: []string{"DRIFT: pilot manages this host's resolver", "the servers in use that this run does not write are 1.1.1.1"}},
		{name: "EL: the reload cannot fix it (a source pilot does not manage), the gate triggers after 10 seconds", osFamily: "RedHat", ignoreAuto: "yes",
			resolv: "# Generated by NetworkManager\nnameserver " + dhcp + "\n", allowed: allowed, wantRC: 2, wantReload: 1,
			want: []string{"the resolver glibc uses is " + dhcp, "Not in the list this run wrote: " + dhcp,
				"nmcli general reload dns-rc was run (rc=0) and the file still did not match after 10 seconds",
				"global-dns"}},
		{name: "EL: NetworkManager writes the file late after a reapply, a short wait avoids the reload", osFamily: "RedHat", ignoreAuto: "yes",
			resolv: "nameserver " + dhcp + "\n", lateWrite: good, nmChanged: true, allowed: allowed, wantRC: 0, wantReload: 0},
	}
	for _, sc := range cases {
		t.Run(sc.name, func(t *testing.T) {
			out, nmLog := runEffectiveFlow(t, sc)
			t.Logf("ansible-playbook output:\n%s", out)
			flat := strings.Join(strings.Fields(out), " ")
			for _, w := range sc.want {
				if !strings.Contains(flat, strings.Join(strings.Fields(w), " ")) {
					t.Errorf("output lacks %q:\n%s", w, out)
				}
			}
			for _, w := range sc.notWant {
				if strings.Contains(flat, w) {
					t.Errorf("output has %q:\n%s", w, out)
				}
			}
			reloads := 0
			if b, err := os.ReadFile(nmLog); err == nil {
				reloads = strings.Count(string(b), "general reload dns-rc")
			}
			if reloads != sc.wantReload {
				t.Errorf("nmcli general reload dns-rc ran %d times, want %d", reloads, sc.wantReload)
			}
			if sc.wantRC == 0 && !sc.check {
				m := regexp.MustCompile(`changed=(\d+)`).FindStringSubmatch(out)
				if m == nil {
					t.Fatalf("no PLAY RECAP:\n%s", out)
				}
				if got, _ := strconv.Atoi(m[1]); got != sc.changed {
					t.Errorf("PLAY RECAP changed=%d, want %d (the report and the gate on a settled host must be a no-op):\n%s", got, sc.changed, out)
				}
			}
		})
	}
}
