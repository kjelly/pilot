package spec

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// regexArgModules and regexArgKeys: the module arguments Python compiles as
// regular expressions.
var (
	regexArgModules = []string{"lineinfile", "replace"}
	regexArgKeys    = []string{"regexp", "insertafter", "insertbefore", "after", "before"}
	// A doubled backslash before a regex escape or metacharacter: the regex
	// gets a literal backslash and then the bare character.
	doubledRegexEscape = regexp.MustCompile(`\\\\[sSdDwWbB.\[\](){}?*+|^$]`)
)

// regexArgsWithDoubledBackslashes returns "<task>: <arg> <value>" for each
// regex argument whose value, after YAML decoding, still holds a doubled
// backslash before a regex escape.
func regexArgsWithDoubledBackslashes(doc any) []string {
	var out []string
	visit := func(task map[string]any, _ []string) {
		for _, mod := range regexArgModules {
			for _, key := range []string{mod, "ansible.builtin." + mod} {
				args, ok := task[key].(map[string]any)
				if !ok {
					continue
				}
				for _, arg := range regexArgKeys {
					if v, ok := args[arg].(string); ok && doubledRegexEscape.MatchString(v) {
						out = append(out, fmt.Sprintf("%v: %s %q", task["name"], arg, v))
					}
				}
			}
		}
	}
	items, _ := doc.([]any)
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if _, isPlay := m["hosts"]; isPlay {
			for _, section := range []string{"pre_tasks", "tasks", "post_tasks", "handlers"} {
				walkTaskTree(m[section], nil, visit)
			}
			continue
		}
		walkTaskTree([]any{m}, nil, visit)
	}
	return out
}

// TestRegression_RegexArgsUseSingleBackslashes is a repo-wide lint over
// playbooks/**. A single-quoted (or plain) YAML scalar keeps both
// backslashes of `\\s`, so lineinfile/replace compile a literal backslash
// followed by `s`. freeipa-realm-replacement-apply.yml had three:
// `insertafter: '^\\[domain/'` failed every run with "unterminated character
// set at position 3", right after the client had enrolled in the new realm
// (the rescue then put the old realm back), and two `regexp`s never matched,
// so lineinfile appended instead of replacing (seen 2026-10-12).
// `TestRegression_JinjaTemplatesUseSingleBackslashes` covers `\\` inside
// `{{ }}`; this covers the text the module compiles.
func TestRegression_RegexArgsUseSingleBackslashes(t *testing.T) {
	checked := 0
	for _, path := range playbookFiles(t) {
		rel := strings.TrimPrefix(path, "../../")
		doc := loadYAML(t, path)
		for _, problem := range regexArgsWithDoubledBackslashes(doc) {
			t.Errorf("%s: %s: write one backslash in a single-quoted or plain scalar (two only inside double quotes)", rel, problem)
		}
		checked++
	}
	if checked < 50 {
		t.Fatalf("checked only %d playbook files; the walk is broken", checked)
	}
}

func TestRegexArgsWithDoubledBackslashes(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want int
	}{
		{"single-quoted doubled backslashes (the 2026-10-12 bug)", `
- hosts: all
  tasks:
    - name: pin
      ansible.builtin.lineinfile:
        path: /etc/sssd/sssd.conf
        regexp: '^ipa_server\\s*='
        insertafter: '^\\[domain/'
        line: x
`, 2},
		{"single-quoted single backslash", `
- hosts: all
  tasks:
    - name: pin
      lineinfile: {path: /etc/hosts, regexp: '\s{{ fqdn | regex_escape }}(\s|$)', line: x}
`, 0},
		{"double-quoted doubled backslash is one backslash", `
- hosts: all
  tasks:
    - name: pin
      lineinfile: {path: /etc/hosts, regexp: "^ipa_server\\s*=", line: x}
`, 0},
		{"replace in a task file, inside a block", `
- name: outer
  block:
    - name: fix
      ansible.builtin.replace:
        path: /etc/x
        regexp: 'a\\.b'
        replace: c
`, 1},
		{"a literal backslash before an ordinary letter is not flagged", `
- hosts: all
  tasks:
    - name: windows path
      lineinfile: {path: /etc/x, regexp: '^C:\\Users', line: x}
`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc any
			if err := yaml.Unmarshal([]byte(tc.yaml), &doc); err != nil {
				t.Fatal(err)
			}
			if got := regexArgsWithDoubledBackslashes(doc); len(got) != tc.want {
				t.Errorf("got %q, want %d", got, tc.want)
			}
		})
	}
}

// runRealmPinTasks runs the realm replacement's two lineinfile pins on
// localhost against hosts and sssdConf.
func runRealmPinTasks(t *testing.T, hosts, sssdConf string) (int, map[string]bool, []string) {
	t.Helper()
	return runRealmTasks(t,
		[]string{"Realm replacement — pin new server FQDN before enrollment", "Realm replacement — pin SSSD to the new server"},
		map[string]string{"/etc/hosts": hosts, "/etc/sssd/sssd.conf": sssdConf}, nil)
}

// TestRegression_RealmReplacementPinsReplaceTheirLines: the /etc/hosts pin
// replaces an existing line for the new server, the SSSD pin replaces
// ipa_server in place or adds it after the [domain/...] header, and a second
// run changes nothing. With the doubled backslashes the SSSD pin failed
// ("unterminated character set") and the hosts pin appended a second line.
func TestRegression_RealmReplacementPinsReplaceTheirLines(t *testing.T) {
	cases := []struct {
		name, hosts, sssd   string
		wantHosts, wantSSSD string
	}{
		{
			name:      "existing lines are replaced",
			hosts:     "127.0.0.1 localhost\n198.51.100.7 ipa1.new.example.test ipa1\n",
			sssd:      "[domain/new.example.test]\nid_provider = ipa\nipa_server = _srv_, ipa1.new.example.test\n\n[sssd]\nservices = nss, pam\n",
			wantHosts: "127.0.0.1 localhost\n192.0.2.10 ipa1.new.example.test ipa1\n",
			wantSSSD:  "[domain/new.example.test]\nid_provider = ipa\nipa_server = ipa1.new.example.test\n\n[sssd]\nservices = nss, pam\n",
		},
		{
			name:      "missing lines are added, ipa_server under the domain header",
			hosts:     "127.0.0.1 localhost\n",
			sssd:      "[domain/new.example.test]\nid_provider = ipa\n\n[sssd]\nservices = nss, pam\n",
			wantHosts: "127.0.0.1 localhost\n192.0.2.10 ipa1.new.example.test ipa1\n",
			wantSSSD:  "[domain/new.example.test]\nipa_server = ipa1.new.example.test\nid_provider = ipa\n\n[sssd]\nservices = nss, pam\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			hosts, sssd := filepath.Join(dir, "hosts"), filepath.Join(dir, "sssd.conf")
			if err := os.WriteFile(hosts, []byte(tc.hosts), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(sssd, []byte(tc.sssd), 0o600); err != nil {
				t.Fatal(err)
			}
			rc, _, failures := runRealmPinTasks(t, hosts, sssd)
			if rc != 0 {
				t.Fatalf("rc=%d failures=%v", rc, failures)
			}
			for _, f := range []struct{ path, want string }{{hosts, tc.wantHosts}, {sssd, tc.wantSSSD}} {
				got, err := os.ReadFile(f.path)
				if err != nil || string(got) != f.want {
					t.Errorf("%s = %q (err %v), want %q", filepath.Base(f.path), got, err, f.want)
				}
			}
			rc, changed, failures := runRealmPinTasks(t, hosts, sssd)
			for name, c := range changed {
				if c {
					t.Errorf("second run: %q changed", name)
				}
			}
			if rc != 0 {
				t.Errorf("second run: rc=%d failures=%v", rc, failures)
			}
		})
	}
}
