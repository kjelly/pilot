package spec

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const (
	resolverOptionsTask    = "FreeIPA DNS client — compute effective resolver options for THIS host"
	resolverResolvConfTask = "Debian — write /etc/resolv.conf (glibc-resolver/dig path; symlink- and bind-mount-safe)"
	resolverNMTask         = "EL — set dns4/dns4_search/dns4_options on the active connection"
)

// resolverBlockTasks returns the tasks inside the resolver block.
func resolverBlockTasks(t *testing.T, tasks []map[string]any) []map[string]any {
	t.Helper()
	i := taskIndexByName(tasks, resolverBlockTask)
	if i < 0 {
		t.Fatalf("block task %q not found", resolverBlockTask)
	}
	raw, ok := tasks[i]["block"].([]any)
	if !ok {
		t.Fatalf("block task %q has no block list", resolverBlockTask)
	}
	var out []map[string]any
	for _, r := range raw {
		m, ok := r.(map[string]any)
		if !ok {
			t.Fatalf("block entry is %T, want a mapping", r)
		}
		out = append(out, m)
	}
	return out
}

// c7Command returns docs/verification/freeipa-dns-client.md C7 as parsed,
// with /etc/resolv.conf replaced by path.
func c7Command(t *testing.T, path string) string {
	t.Helper()
	s, err := Parse("../../docs/verification/freeipa-dns-client.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range s.Rows {
		if r.ID == "C7" {
			if r.Expected != "~resolver-timeout-ok" {
				t.Fatalf("C7 expected = %q, want ~resolver-timeout-ok", r.Expected)
			}
			return strings.ReplaceAll(r.Command, "/etc/resolv.conf", path)
		}
	}
	t.Fatal("C7 not found in freeipa-dns-client.md")
	return ""
}

// runC7 runs the C7 command against a resolv.conf with the given content.
func runC7(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", "-c", c7Command(t, path)).CombinedOutput()
	if err != nil {
		t.Fatalf("C7 command failed to run: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// renderDebianResolvConf runs the shared task file's own options task and
// Debian resolv.conf task on localhost, with the destination moved into a
// temporary directory, and returns the written file.
func renderDebianResolvConf(t *testing.T, servers []string) string {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	tasks := resolverTaskList(t)
	oi := taskIndexByName(tasks, resolverOptionsTask)
	if oi < 0 {
		t.Fatalf("task %q not found", resolverOptionsTask)
	}
	block := resolverBlockTasks(t, tasks)
	ri := taskIndexByName(block, resolverResolvConfTask)
	if ri < 0 {
		t.Fatalf("block task %q not found", resolverResolvConfTask)
	}
	dir := t.TempDir()
	dest := filepath.Join(dir, "resolv.conf")
	write := map[string]any{}
	for k, v := range block[ri] {
		write[k] = v
	}
	args := map[string]any{}
	for k, v := range write["ansible.builtin.copy"].(map[string]any) {
		args[k] = v
	}
	args["dest"] = dest
	delete(args, "owner")
	delete(args, "group")
	write["ansible.builtin.copy"] = args
	play := []map[string]any{{
		"name":         "render resolver options and resolv.conf",
		"hosts":        "localhost",
		"connection":   "local",
		"gather_facts": false,
		"vars": map[string]any{
			"ansible_os_family":                     "Debian",
			"freeipa_domain":                        "ipa.pilot.internal",
			"freeipa_dns_client_resolv_conf_marker": "pilot-freeipa-dns-client",
			"freeipa_dns_client_effective_servers":  servers,
		},
		"tasks": []map[string]any{tasks[oi], write},
	}}
	raw, err := yaml.Marshal(play)
	if err != nil {
		t.Fatal(err)
	}
	pb := filepath.Join(dir, "play.yml")
	if err := os.WriteFile(pb, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ansible-playbook", "-i", "localhost,", pb)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ansible-playbook: %v\n%s", err, out)
	}
	return readFile(t, dest)
}

// TestRegression_FreeipaDNSClientResolverTimeout locks C7: a consumer with
// a second nameserver to fail over to waits 1 second per server instead of
// glibc's 5 (a dns tier node that dropped packets made every lookup take 5
// to 20 seconds, docs/evidence/dns/2026-10-01-3f781fb.md E6), and a
// consumer with one nameserver keeps the glibc default. The Debian files
// are written by the shared task file's own tasks; C7 is the parsed spec
// command.
func TestRegression_FreeipaDNSClientResolverTimeout(t *testing.T) {
	cases := []struct {
		name        string
		servers     []string
		wantOptions bool
	}{
		{"one nameserver keeps the glibc default", []string{"192.0.2.1"}, false},
		{"tier and FreeIPA", []string{"192.0.2.11", "192.0.2.1"}, true},
		{"two tier nodes and FreeIPA", []string{"192.0.2.11", "192.0.2.12", "192.0.2.1"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := renderDebianResolvConf(t, tc.servers)
			hasOptions := strings.Contains(got, "\noptions timeout:1 attempts:2\n")
			if hasOptions != tc.wantOptions {
				t.Errorf("resolv.conf for %v: options line present = %v, want %v:\n%s", tc.servers, hasOptions, tc.wantOptions, got)
			}
			if strings.Count(got, "\nnameserver ") != len(tc.servers) {
				t.Errorf("resolv.conf for %v has the wrong nameserver lines:\n%s", tc.servers, got)
			}
			if out := runC7(t, got); out != "resolver-timeout-ok" {
				t.Errorf("C7 on the rendered file = %q, want resolver-timeout-ok:\n%s", out, got)
			}
		})
	}

	// Should trigger: C7 fails when the options do not match the
	// nameserver count, including a near miss like timeout:10.
	multi := renderDebianResolvConf(t, []string{"192.0.2.11", "192.0.2.1"})
	single := renderDebianResolvConf(t, []string{"192.0.2.1"})
	for name, content := range map[string]string{
		"two nameservers, no options":   strings.Replace(multi, "options timeout:1 attempts:2\n", "", 1),
		"two nameservers, timeout:10":   strings.Replace(multi, "timeout:1 ", "timeout:10 ", 1),
		"one nameserver, short timeout": single + "options timeout:1 attempts:2\n",
		// glibc applies options in order, so a later value overrides
		// timeout:1 attempts:2 although both tokens are still there.
		"two nameservers, overridden on the same line":         strings.Replace(multi, "options timeout:1 attempts:2\n", "options timeout:1 attempts:2 timeout:10 attempts:5\n", 1),
		"two nameservers, timeout overridden by a later line":  multi + "options timeout:10\n",
		"two nameservers, attempts overridden by a later line": multi + "options rotate attempts:5\n",
		"two nameservers, tab-separated later line":            multi + "options\ttimeout:3\n",
	} {
		if out := runC7(t, content); !strings.HasPrefix(out, "resolver-timeout-wrong ") {
			t.Errorf("C7 on %s = %q, want resolver-timeout-wrong:\n%s", name, out, content)
		}
	}

	// Should pass: what counts is the value glibc ends up with.
	for name, content := range map[string]string{
		"two nameservers, an earlier line overridden":                   strings.Replace(multi, "options timeout:1 attempts:2\n", "options timeout:10 attempts:5\noptions timeout:1 attempts:2\n", 1),
		"two nameservers, indented and commented lines are not options": multi + " options timeout:10\n# options timeout:10\n",
		"one nameserver, options without a timeout":                     single + "options edns0 trust-ad\n",
	} {
		if out := runC7(t, content); out != "resolver-timeout-ok" {
			t.Errorf("C7 on %s = %q, want resolver-timeout-ok:\n%s", name, out, content)
		}
	}
}

// glibcResolverOptions returns the timeout and attempts glibc's res_init()
// ends up with after it applies tokens, starting from its defaults
// (timeout 5, attempts 2) whatever the test host's /etc/resolv.conf says.
// RES_OPTIONS goes through the same res_setoptions() as the options lines
// of /etc/resolv.conf, after them.
func glibcResolverOptions(t *testing.T, tokens []string) (timeout, attempts int) {
	t.Helper()
	const probe = `import ctypes
libc = ctypes.CDLL("libc.so.6")
if libc.__res_init() != 0:
    raise SystemExit("res_init failed")
libc.__res_state.restype = ctypes.POINTER(ctypes.c_int * 2)
s = libc.__res_state().contents
print(s[0], s[1])
`
	cmd := exec.Command("python3", "-c", probe)
	cmd.Env = append(os.Environ(), "RES_OPTIONS=timeout:5 attempts:2 "+strings.Join(tokens, " "))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("cannot read glibc's resolver state: %v\n%s", err, out)
	}
	if _, err := fmt.Sscan(string(out), &timeout, &attempts); err != nil {
		t.Fatalf("glibc probe printed %q: %v", out, err)
	}
	return timeout, attempts
}

// TestRegression_FreeipaDNSClientC7MatchesGlibc checks C7's parser against
// glibc itself: for each set of options lines on a host with two
// nameservers, C7 passes exactly when glibc's effective values are
// timeout 1 and attempts 2, and otherwise prints glibc's values. A
// presence check accepted "timeout:1 attempts:2 timeout:10 attempts:5",
// which glibc runs with 10 seconds and 5 attempts.
func TestRegression_FreeipaDNSClientC7MatchesGlibc(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skipf("python3 not installed: %v", err)
	}
	cases := [][]string{
		{"options timeout:1 attempts:2"},
		{"options timeout:1 attempts:2 timeout:10 attempts:5"},
		{"options timeout:1 attempts:2", "options timeout:10"},
		{"options timeout:1 attempts:2", "options attempts:5"},
		{"options timeout:10 attempts:5", "options timeout:1 attempts:2"},
		{"options timeout:01 attempts:2x"},
		{"options timeout: attempts:2"},
		{"options timeout:1"},
		{"options edns0 timeout:2 rotate attempts:2"},
		{"options\ttimeout:1\tattempts:3"},
		// glibc reads the number with strtol(..., 10) and caps it
		// (timeout 30, attempts 5). awk's int() read "10e-1" as the
		// float 1, so these two passed (PR #37 review).
		{"options timeout:10e-1 attempts:2"},
		{"options timeout:1 attempts:20e-1"},
		{"options timeout: 1 attempts:2"},
		{"options timeout:\t1 attempts:2"},
		{"options timeout:+1 attempts:+2"},
		{"options timeout:-1"},
		{"options timeout:0x1 attempts:2"},
		{"options timeout:99 attempts:9"},
		{"options timeout:1.9 attempts:2.5"},
		{"options timeout:00000000001 attempts:002"},
		{"options timeout:999999999"},
		{"options timeout:1x attempts:2y"},
		{"options timeout: attempts:3"},
	}
	for _, lines := range cases {
		var tokens []string
		for _, l := range lines {
			tokens = append(tokens, strings.Fields(l)[1:]...)
		}
		timeout, attempts := glibcResolverOptions(t, tokens)
		want := "resolver-timeout-ok"
		if timeout != 1 || attempts != 2 {
			want = fmt.Sprintf("resolver-timeout-wrong nameservers=2 timeout=%d attempts=%d options=set", timeout, attempts)
		}
		content := "nameserver 192.0.2.11\nnameserver 192.0.2.1\n" + strings.Join(lines, "\n") + "\n"
		if got := runC7(t, content); got != want {
			t.Errorf("C7 on %q = %q; glibc uses timeout %d attempts %d, want %q", lines, got, timeout, attempts, want)
		}
	}

	// Ten or more significant digits overflow glibc's int and wrap
	// ("timeout:4294967297" runs with 1 second). C7 does not reproduce
	// the wrap; it fails closed.
	for _, line := range []string{"options timeout:4294967297 attempts:2", "options timeout:1 attempts:2147483650"} {
		timeout, attempts := glibcResolverOptions(t, strings.Fields(line)[1:])
		content := "nameserver 192.0.2.11\nnameserver 192.0.2.1\n" + line + "\n"
		got := runC7(t, content)
		if !strings.HasPrefix(got, "resolver-timeout-wrong ") || !strings.Contains(got, "=invalid") {
			t.Errorf("C7 on %q = %q (glibc: timeout %d attempts %d), want resolver-timeout-wrong with an invalid value", line, got, timeout, attempts)
		}
	}
}

// TestRegression_FreeipaDNSClientResolverTimeoutEL locks the EL half of C7:
// the nmcli task passes the same computed list (an empty list clears an
// earlier value), and C7 reads the file NetworkManager generates from it.
func TestRegression_FreeipaDNSClientResolverTimeoutEL(t *testing.T) {
	block := resolverBlockTasks(t, resolverTaskList(t))
	i := taskIndexByName(block, resolverNMTask)
	if i < 0 {
		t.Fatalf("block task %q not found", resolverNMTask)
	}
	args, _ := block[i]["community.general.nmcli"].(map[string]any)
	if got := args["dns4_options"]; got != "{{ freeipa_dns_client_effective_resolver_options }}" {
		t.Errorf("nmcli dns4_options = %v, want the computed freeipa_dns_client_effective_resolver_options", got)
	}

	// /etc/resolv.conf as NetworkManager 1.54.3 wrote it on an AlmaLinux 9
	// vm-target after this playbook ran with two nameservers and then with
	// one (2026-10-01).
	twoServers := "# Generated by NetworkManager\nsearch ipa.pilot.internal\nnameserver 192.168.122.1\nnameserver 1.1.1.1\noptions timeout:1 attempts:2\n"
	oneServer := "# Generated by NetworkManager\nsearch ipa.pilot.internal\nnameserver 1.1.1.1\n"
	for name, content := range map[string]string{"two nameservers": twoServers, "one nameserver": oneServer} {
		if out := runC7(t, content); out != "resolver-timeout-ok" {
			t.Errorf("C7 on NetworkManager's file with %s = %q, want resolver-timeout-ok", name, out)
		}
	}
	if out := runC7(t, strings.Replace(twoServers, "options timeout:1 attempts:2\n", "", 1)); !strings.HasPrefix(out, "resolver-timeout-wrong ") {
		t.Errorf("C7 on NetworkManager's two-server file without options = %q, want resolver-timeout-wrong", out)
	}
}
