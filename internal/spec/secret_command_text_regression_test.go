package spec

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// PR #92 review: the replica forwarder task fed ipa_admin_password to kinit
// through `printf %s "{{ ipa_admin_password }}" | kinit` in a shell. Ansible
// substitutes the value into the command text before the shell parses it,
// so `$`, backticks and `$(...)` in a password are expanded (and run) by the
// shell, and kinit gets a different password. no_log hides output only. A
// free-form `command:` string is split into words, so quotes and spaces in
// the value change it as well. A secret goes to a program as stdin, or as
// one argv element.

// secretCommandTextAllowlist holds the sites that were already on main when
// this lint was added, each to be migrated to argv/stdin (issue #118). The
// lint fails for an entry that no longer matches, so the list only shrinks.
var secretCommandTextAllowlist = map[string]bool{
	"playbooks/apply/dcgm-exporter-apply.yml::Step 6: Generate bcrypt hash for basic auth (spec C9; only when the credential changed)":        true,
	"playbooks/apply/freeipa-dns-apply.yml::Kinit admin into the dedicated ccache":                                                            true,
	"playbooks/apply/freeipa-identity-apply.yml::Kinit admin":                                                                                 true,
	"playbooks/apply/freeipa-identity-apply.yml::Set password for users that need one (forced, or first-time onboard)":                        true,
	"playbooks/apply/freeipa-server-apply.yml::FreeIPA — 389-ds audit log: write dummy description to trigger audit log (spec C16)":           true,
	"playbooks/apply/freeipa-server-apply.yml::Kinit admin (for dnsconfig-mod)":                                                               true,
	"playbooks/apply/freeipa-server-replica-apply.yml::FreeIPA replica DNS self-register — kinit admin into the dedicated ccache":             true,
	"playbooks/apply/gateway-scope-apply.yml::Kinit admin":                                                                                    true,
	"playbooks/apply/host-monitoring-apply.yml::Step 8: Generate bcrypt hash for basic auth (spec C10; only when the credential changed)":     true,
	"playbooks/apply/internal-endpoint-apply.yml::Kinit as IPA admin (decommission verify query)":                                             true,
	"playbooks/apply/internal-endpoint-apply.yml::Kinit as IPA admin (identity + DNS reconcile)":                                              true,
	"playbooks/apply/pilot-access-directory-apply.yml::Kinit admin (management-plane operations only — never shipped to this host)":           true,
	"playbooks/apply/pilot-access-gateway-apply.yml::Kinit admin (management-plane operations only — never shipped to this host)":             true,
	"playbooks/apply/pilot-session-store-apply.yml::Kinit admin (management-plane operations only — never shipped to this host)":              true,
	"playbooks/apply/tasks/freeipa-client-host-dns.yml::FreeIPA client DNS backfill — kinit admin into the dedicated ccache":                  true,
	"playbooks/apply/tasks/freeipa-client-host-dns.yml::FreeIPA client DNS replace — kinit admin into the dedicated ccache":                   true,
	"playbooks/apply/tasks/freeipa-host-annotations.yml::FreeIPA host annotations — kinit admin into the dedicated ccache":                    true,
	"playbooks/apply/tasks/internal-endpoint-delete.yml::Kinit as IPA admin (delete sequence)":                                                true,
	"playbooks/check/freeipa-access-drift-probe.yml::Kinit admin for read-only drift probe":                                                   true,
	"playbooks/check/freeipa-capability-probe.yml::Kinit admin for read-only capability probe":                                                true,
	"playbooks/check/freeipa-identity-group-ever-applied.yml::Kinit admin for read-only identity probe":                                       true,
	"playbooks/check/freeipa-identity-user-ever-applied.yml::Kinit admin for read-only identity probe":                                        true,
	"playbooks/test/fixtures/dcgm-exporter-fake-metrics-fixtures.yml::Compute the htpasswd line (apr1-MD5; only when the credential changed)": true,
	"playbooks/test/fixtures/dns-fixtures.yml::Fixtures — kinit admin (ticket for the ipa CLI below)":                                         true,
	"playbooks/test/fixtures/freeipa-audit-demo.yml::Fixtures — kinit admin":                                                                  true,
	"playbooks/test/fixtures/freeipa-client-fixtures.yml::Fixtures — kinit admin (ticket for the ipa CLI below)":                              true,
	"playbooks/test/fixtures/freeipa-hostauthz-demo.yml::Cleanup — kinit admin":                                                               true,
	"playbooks/test/fixtures/freeipa-hostauthz-demo.yml::Fixtures — kinit admin":                                                              true,
	"playbooks/test/fixtures/freeipa-hostauthz-demo.yml::Fixtures — set stable password for hz_db via kadmin.local":                           true,
	"playbooks/test/fixtures/freeipa-hostauthz-demo.yml::Fixtures — set stable password for hz_web via kadmin.local":                          true,
	"playbooks/test/fixtures/freeipa-hostauthz-demo.yml::Restore — kinit admin":                                                               true,
	"playbooks/test/fixtures/freeipa-hostauthz-sim.yml::Sim[+] — kinit as {{ sim_local_user }}":                                               true,
	"playbooks/test/fixtures/pilot-access-transport-fixtures.yml::Fixtures — kinit admin":                                                     true,
}

var (
	jinjaExprRe   = regexp.MustCompile(`(?s)\{\{(.*?)\}\}`)
	identifierRe  = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)
	secretIdentRe = regexp.MustCompile(`(?i)password|passwd|secret`)
)

// commandText returns the text a shell, command, raw or expect task hands to
// a shell or to Ansible's word splitting: the free-form string, or cmd,
// _raw_params or command. argv elements are passed as they are and are not
// returned.
func commandText(task map[string]any) (string, bool) {
	module, raw := moduleArgs(task)
	if module == "" {
		return "", false
	}
	switch v := raw.(type) {
	case string:
		return v, true
	case map[string]any:
		for _, key := range []string{"cmd", "_raw_params", "command"} {
			if s, ok := v[key].(string); ok {
				return s, true
			}
		}
	}
	return "", false
}

// secretsInText returns the secret-looking variables a {{ }} expression in
// text reads.
func secretsInText(text string) []string {
	var found []string
	for _, m := range jinjaExprRe.FindAllStringSubmatch(text, -1) {
		for _, id := range identifierRe.FindAllString(m[1], -1) {
			if secretIdentRe.MatchString(id) && !slices.Contains(found, id) {
				found = append(found, id)
			}
		}
	}
	return found
}

// walkTaskMaps calls fn for every mapping in doc, so tasks in plays, blocks,
// rescue/always sections and task files are all visited.
func walkTaskMaps(doc any, fn func(map[string]any)) {
	switch v := doc.(type) {
	case map[string]any:
		fn(v)
		for _, child := range v {
			walkTaskMaps(child, fn)
		}
	case []any:
		for _, child := range v {
			walkTaskMaps(child, fn)
		}
	}
}

// secretCommandTextSites scans every YAML file under root/playbooks and
// returns "<path>::<task name>" -> the secrets its command text reads.
func secretCommandTextSites(t *testing.T, root string) map[string][]string {
	t.Helper()
	sites := map[string][]string{}
	err := filepath.WalkDir(filepath.Join(root, "playbooks"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || (filepath.Ext(p) != ".yml" && filepath.Ext(p) != ".yaml") {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		walkTaskMaps(loadYAML(t, p), func(task map[string]any) {
			text, ok := commandText(task)
			if !ok {
				return
			}
			if secrets := secretsInText(text); len(secrets) > 0 {
				name, _ := task["name"].(string)
				key := filepath.ToSlash(rel) + "::" + name
				sites[key] = append(sites[key], secrets...)
			}
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return sites
}

func TestRegression_NoSecretInCommandText(t *testing.T) {
	sites := secretCommandTextSites(t, filepath.Join("..", ".."))
	var keys []string
	for k := range sites {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !secretCommandTextAllowlist[k] {
			t.Errorf("%s puts %v into command text; pass it as stdin or one argv element (shell expansion and word splitting change it)", k, sites[k])
		}
	}
	for k := range secretCommandTextAllowlist {
		if _, ok := sites[k]; !ok {
			t.Errorf("allowlist entry %q no longer matches; remove it", k)
		}
	}
}

func TestSecretCommandTextScanClassifiesSites(t *testing.T) {
	doc := map[string]any{"tasks": []any{
		map[string]any{"name": "shell printf", "ansible.builtin.shell": map[string]any{"cmd": `printf %s "{{ ipa_admin_password }}" | kinit admin`}},
		map[string]any{"name": "free-form command", "command": "htpasswd -nbBC 10 {{ user }} {{ basic_auth_password }}"},
		map[string]any{"name": "loop item", "ansible.builtin.shell": "printf '%s' '{{ item.password }}' | ipa passwd x"},
		map[string]any{"name": "in a rescue", "block": []any{}, "rescue": []any{
			map[string]any{"name": "nested", "ansible.builtin.shell": "echo '{{ webhook_secret }}' > /x"},
		}},
		map[string]any{"name": "argv and stdin", "ansible.builtin.command": map[string]any{"argv": []any{"kinit", "admin@{{ ipa_realm }}", "--password={{ ipa_admin_password }}"}, "stdin": "{{ ipa_admin_password }}"}},
		map[string]any{"name": "no secret", "ansible.builtin.shell": "kinit -kt /etc/krb5.keytab host/{{ fqdn }}"},
		map[string]any{"name": "not a command", "ansible.builtin.copy": map[string]any{"content": "{{ ipa_admin_password }}", "dest": "/x"}},
	}}
	got := map[string][]string{}
	walkTaskMaps(doc, func(task map[string]any) {
		if text, ok := commandText(task); ok {
			if s := secretsInText(text); len(s) > 0 {
				got[task["name"].(string)] = s
			}
		}
	})
	want := map[string][]string{
		"shell printf":      {"ipa_admin_password"},
		"free-form command": {"basic_auth_password"},
		"loop item":         {"password"},
		"nested":            {"webhook_secret"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// findNamedTask returns the task called name anywhere in doc.
func findNamedTask(t *testing.T, doc any, name string) map[string]any {
	t.Helper()
	var found []map[string]any
	walkTaskMaps(doc, func(m map[string]any) {
		if m["name"] == name {
			found = append(found, m)
		}
	})
	if len(found) != 1 {
		t.Fatalf("want exactly one task named %q, found %d", name, len(found))
	}
	return found[0]
}

// TestRegression_ReplicaForwarderKinitPassesPasswordUnchanged runs the real
// task from freeipa-server-replica-apply.yml with ansible-playbook and a fake
// kinit that records its stdin and arguments. Before the fix (a shell
// printf), `demo$pilot92_missing_suffix` reached kinit as `demo`.
func TestRegression_ReplicaForwarderKinitPassesPasswordUnchanged(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	pb := filepath.Join("..", "..", "playbooks", "apply", "freeipa-server-replica-apply.yml")
	task := findNamedTask(t, loadYAML(t, pb), "FreeIPA replica DNS — kinit admin (for dnsserver-mod)")
	if task["no_log"] != true {
		t.Fatalf("the kinit task must keep no_log: true")
	}

	// %[1]s is a file the password would create if a shell ran part of it.
	for i, tmpl := range []string{
		"demo$pilot92_missing_suffix",
		"a`touch %[1]s`b",
		"x$(touch %[1]s)y",
		`q"uo'te\back slash`,
		"  spaced  ",
		"{{ not_jinja }}",
	} {
		// Index names keep the password out of t.TempDir()'s path.
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			dir := t.TempDir()
			marker := filepath.Join(dir, "pwned")
			password := tmpl
			if strings.Contains(tmpl, "%[1]s") {
				password = fmt.Sprintf(tmpl, marker)
			}
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			stdinFile, argsFile := filepath.Join(dir, "stdin"), filepath.Join(dir, "args")
			script := "#!/bin/sh\ncat > \"$FAKE_KINIT_STDIN\"\nprintf '%s\\n' \"$@\" > \"$FAKE_KINIT_ARGS\"\n"
			if err := os.WriteFile(filepath.Join(bin, "kinit"), []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			play := []map[string]any{{
				"name": "replica kinit", "hosts": "localhost", "connection": "local", "gather_facts": false,
				// !unsafe keeps a test password that looks like Jinja literal,
				// as a vault value is.
				"vars":        map[string]any{"ipa_admin_password": unsafeString(password), "ipa_realm": "IPA.PILOT.INTERNAL"},
				"environment": map[string]any{"PATH": bin + ":" + os.Getenv("PATH"), "FAKE_KINIT_STDIN": stdinFile, "FAKE_KINIT_ARGS": argsFile},
				"tasks":       []any{task},
			}}
			body, err := yaml.Marshal(play)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "play.yml")
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("ansible-playbook", "-i", "localhost,", path)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False", "ANSIBLE_DEPRECATION_WARNINGS=False")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("password %q: ansible-playbook: %v\n%s", password, err, out)
			}
			gotStdin, err := os.ReadFile(stdinFile)
			if err != nil {
				t.Fatal(err)
			}
			// kinit reads one line, so a trailing newline is not part of it.
			if strings.TrimSuffix(string(gotStdin), "\n") != password {
				t.Errorf("password %q: kinit stdin = %q", password, gotStdin)
			}
			gotArgs, err := os.ReadFile(argsFile)
			if err != nil {
				t.Fatal(err)
			}
			if string(gotArgs) != "admin@IPA.PILOT.INTERNAL\n" {
				t.Errorf("password %q: kinit args = %q, want the principal only", password, gotArgs)
			}
			if _, err := os.Stat(marker); err == nil {
				t.Errorf("password %q ran a command", password)
			}
		})
	}
}

// unsafeString marshals as a YAML !unsafe scalar, which Ansible never
// templates.
type unsafeString string

func (s unsafeString) MarshalYAML() (any, error) {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!unsafe", Value: string(s), Style: yaml.DoubleQuotedStyle}, nil
}
