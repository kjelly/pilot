package spec

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// dns.md B7, G4 and C5: an ACL that allows every source is rejected by the
// networks it covers, not by its spelling. Until v1.1 G4 rejected only the
// strings 0.0.0.0/0 and ::/0 and C5 grepped for the same two strings, so
// 1.2.3.4/0, ::0/0 or 0.0.0.0/1 + 128.0.0.0/1 opened the resolver to every
// source and passed both.

// Real `unbound-control get_option access-control` stdout, captured on
// 2026-10-01 from an Ubuntu 24.04.4 vm-target with unbound 1.19.2, one
// config per case. unbound prints the entries in reverse config order and
// keeps the spelling it was given. On that version unbound-checkconf
// rejects 0.0.0.0/00 ("cannot parse netblock") but accepts every other
// entry below.
const (
	unboundACLRFC1918     = "192.168.0.0/16 allow\n172.16.0.0/12 allow\n10.0.0.0/8 allow\n"
	unboundACLAllowAll    = "0.0.0.0/0 allow\n"
	unboundACLHostBitsAll = "1.2.3.4/0 allow\n"
	unboundACLV6ZeroAll   = "::0/0 allow\n"
	unboundACLV6All       = "::/0 allow\n"
	unboundACLHalves      = "128.0.0.0/1 allow\n0.0.0.0/1 allow\n"
	unboundACLPadded      = "10.0.0.0/08 allow\n"
	unboundACLSnoopAll    = "0.0.0.0/0 allow_snoop\n"
	unboundACLRefuseAll   = "0.0.0.0/0 refuse\n10.0.0.0/8 allow\n"
)

// dnsACLClassifier returns the Python program G4 runs on the controller,
// as written in dns-apply.yml.
func dnsACLClassifier(t *testing.T) string {
	t.Helper()
	tasks, _ := dnsPlay(t)["pre_tasks"].([]any)
	for _, raw := range tasks {
		task, _ := raw.(map[string]any)
		if task["name"] != "DNS — classify the dns_access_control networks" {
			continue
		}
		vars, _ := task["vars"].(map[string]any)
		if py, _ := vars["_acl_check_py"].(string); py != "" {
			return py
		}
	}
	t.Fatal("dns-apply.yml has no ACL classification task with vars._acl_check_py")
	return ""
}

func TestRegression_DNSACLClassifier(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("python3 not installed: %v", err)
	}
	program := dnsACLClassifier(t)
	cases := []struct {
		name                       string
		acl                        []string
		noncanonical, unrestricted []string
	}{
		{"RFC1918 default", []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}, nil, nil},
		{"IPv6 ULA", []string{"fd00::/8"}, nil, nil},
		{"half of IPv4 is not everything", []string{"0.0.0.0/1"}, nil, nil},
		{"IPv4 allow-all", []string{"0.0.0.0/0"}, nil, []string{"0.0.0.0/0"}},
		{"IPv6 allow-all", []string{"::/0"}, nil, []string{"::/0"}},
		{"zero-padded /00", []string{"0.0.0.0/00"}, []string{"0.0.0.0/00 (write 0.0.0.0/0)"}, []string{"0.0.0.0/0"}},
		{"zero-padded /000", []string{"0.0.0.0/000"}, []string{"0.0.0.0/000 (write 0.0.0.0/0)"}, []string{"0.0.0.0/0"}},
		{"host bits with /0", []string{"1.2.3.4/0"}, []string{"1.2.3.4/0 (write 0.0.0.0/0)"}, []string{"0.0.0.0/0"}},
		{"IPv6 ::0/0", []string{"::0/0"}, []string{"::0/0 (write ::/0)"}, []string{"::/0"}},
		{"IPv6 uncompressed /0", []string{"0:0:0:0:0:0:0:0/0"}, []string{"0:0:0:0:0:0:0:0/0 (write ::/0)"}, []string{"::/0"}},
		{"two IPv4 halves", []string{"0.0.0.0/1", "128.0.0.0/1"}, nil, []string{"0.0.0.0/0"}},
		{"two IPv6 halves", []string{"::/1", "8000::/1"}, nil, []string{"::/0"}},
		{"quarters plus a private range", []string{"10.0.0.0/8", "0.0.0.0/1", "128.0.0.0/2", "192.0.0.0/2"}, nil, []string{"0.0.0.0/0"}},
		{"one family open, the other not", []string{"10.0.0.0/8", "::/1", "8000::/1"}, nil, []string{"::/0"}},
		{"zero-padded /08", []string{"10.0.0.0/08"}, []string{"10.0.0.0/08 (write 10.0.0.0/8)"}, nil},
		{"host bits", []string{"10.1.2.3/8"}, []string{"10.1.2.3/8 (write 10.0.0.0/8)"}, nil},
		{"upper-case IPv6", []string{"FD00::/8"}, []string{"FD00::/8 (write fd00::/8)"}, nil},
		{"prefix too long", []string{"10.0.0.0/33"}, []string{"10.0.0.0/33"}, nil},
		{"zero-padded octet", []string{"010.0.0.0/8"}, []string{"010.0.0.0/8"}, nil},
		{"bare address", []string{"10.0.0.1"}, []string{"10.0.0.1 (write 10.0.0.1/32)"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := exec.Command(python, append([]string{"-c", program}, tc.acl...)...).Output()
			if err != nil {
				t.Fatalf("classifier failed: %v\n%s", err, out)
			}
			var got struct{ Noncanonical, Unrestricted []string }
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatalf("classifier output %q: %v", out, err)
			}
			if !slices.Equal(got.Noncanonical, tc.noncanonical) || !slices.Equal(got.Unrestricted, tc.unrestricted) {
				t.Errorf("acl=%v: noncanonical=%q unrestricted=%q, want %q and %q",
					tc.acl, got.Noncanonical, got.Unrestricted, tc.noncanonical, tc.unrestricted)
			}
		})
	}
}

// runDNSC5 runs dns.md C5 as parsed with unbound-control replaced by a fake
// that prints acl. A non-empty python3 replaces python3 with a script.
func runDNSC5(t *testing.T, acl, input, python3 string) string {
	t.Helper()
	s, err := Parse(dnsSpecPath)
	if err != nil {
		t.Fatal(err)
	}
	var probe string
	for _, r := range s.Rows {
		if r.ID == "C5" {
			probe = r.Command
		}
	}
	if probe == "" {
		t.Fatal("dns.md has no C5")
	}
	bin := t.TempDir()
	out := filepath.Join(t.TempDir(), "acl")
	if err := os.WriteFile(out, []byte(acl), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "unbound-control"), []byte("#!/bin/sh\ncat '"+out+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if python3 != "" {
		if err := os.WriteFile(filepath.Join(bin, "python3"), []byte(python3), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("sh", "-c", probe)
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "PILOT_VAR_DNS_ACCESS_CONTROL="+input)
	got, err := cmd.Output()
	if err != nil {
		t.Fatalf("C5 probe failed to run: %v\n%s", err, got)
	}
	return strings.TrimSpace(string(got))
}

func TestRegression_DNSC5RejectsEquivalentAllowAll(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skipf("python3 not installed: %v", err)
	}
	const rfc1918 = "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
	cases := []struct{ name, acl, input, python3, want string }{
		{"RFC1918", unboundACLRFC1918, rfc1918, "", "acl-ok"},
		{"refuse-all is not allow-all", unboundACLRefuseAll, "10.0.0.0/8", "", "acl-ok"},
		{"literal 0.0.0.0/0", unboundACLAllowAll, "0.0.0.0/0", "", "acl-bad missing= open=0.0.0.0/0"},
		{"1.2.3.4/0", unboundACLHostBitsAll, "1.2.3.4/0", "", "acl-bad missing= open=0.0.0.0/0"},
		{"::0/0", unboundACLV6ZeroAll, "::0/0", "", "acl-bad missing= open=::/0"},
		{"::/0", unboundACLV6All, "::/0", "", "acl-bad missing= open=::/0"},
		{"two halves", unboundACLHalves, "0.0.0.0/1 128.0.0.0/1", "", "acl-bad missing= open=0.0.0.0/0"},
		{"allow_snoop counts as allow", unboundACLSnoopAll, "10.0.0.0/8", "", "acl-bad missing= 10.0.0.0/8 open=0.0.0.0/0"},
		{"input spelled differently", unboundACLPadded, "10.0.0.0/8", "", "acl-bad missing= 10.0.0.0/8 open=none"},
		{"unbound not answering", "", "10.0.0.0/8", "", "acl-bad missing= 10.0.0.0/8 open=none"},
		{"no python3", unboundACLRFC1918, rfc1918, "#!/bin/sh\nexit 127\n", "acl-bad missing= open=unchecked"},
		{"missing input", unboundACLRFC1918, "", "", "missing-input"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runDNSC5(t, tc.acl, tc.input, tc.python3); got != tc.want {
				t.Errorf("C5 printed %q, want %q", got, tc.want)
			}
		})
	}
}
