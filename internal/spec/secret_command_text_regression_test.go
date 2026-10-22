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
// the value change it as well. A secret goes to a program as stdin. An argv
// element is not changed either, but any local user can read it in
// /proc/<pid>/cmdline, so it is only for programs with no other input (the
// FreeIPA installers); this lint does not look at argv.

// secretCommandTextAllowlist counts, per "<path>::<task name>", the tasks
// that were already on main when this lint was added, each to be migrated to
// stdin (issue #118). The lint fails when a key has more tasks than its count
// (a copied task with the same name is a new site) and when it has fewer, so
// the list only shrinks.
var secretCommandTextAllowlist = map[string]int{
	"playbooks/apply/dcgm-exporter-apply.yml::Step 6: Generate bcrypt hash for basic auth (spec C9; only when the credential changed)":             1,
	"playbooks/apply/freeipa-dns-apply.yml::Kinit admin into the dedicated ccache":                                                                 1,
	"playbooks/apply/freeipa-server-apply.yml::FreeIPA — 389-ds audit log: write dummy description to trigger audit log (spec C16)":                1,
	"playbooks/apply/gateway-scope-apply.yml::Kinit admin":                                                                                         1,
	"playbooks/apply/host-monitoring-apply.yml::Step 8: Generate bcrypt hash for basic auth (spec C10; only when the credential changed)":          1,
	"playbooks/apply/internal-endpoint-apply.yml::Kinit as IPA admin (decommission verify query)":                                                  1,
	"playbooks/apply/internal-endpoint-apply.yml::Kinit as IPA admin (identity + DNS reconcile)":                                                   1,
	"playbooks/apply/pilot-access-directory-apply.yml::Kinit admin (management-plane operations only — never shipped to this host)":                1,
	"playbooks/apply/pilot-access-gateway-apply.yml::Kinit admin (management-plane operations only — never shipped to this host)":                  1,
	"playbooks/apply/pilot-session-store-apply.yml::Kinit admin (management-plane operations only — never shipped to this host)":                   1,
	"playbooks/apply/tasks/freeipa-client-host-dns.yml::FreeIPA client DNS backfill — kinit admin into the dedicated ccache":                       1,
	"playbooks/apply/tasks/freeipa-client-host-dns.yml::FreeIPA client DNS replace — kinit admin into the dedicated ccache":                        1,
	"playbooks/apply/tasks/freeipa-host-annotations.yml::FreeIPA host annotations — kinit admin into the dedicated ccache":                         1,
	"playbooks/apply/tasks/internal-endpoint-delete.yml::Kinit as IPA admin (delete sequence)":                                                     1,
	"playbooks/check/freeipa-access-drift-probe.yml::Kinit admin for read-only drift probe":                                                        1,
	"playbooks/check/freeipa-capability-probe.yml::Kinit admin for read-only capability probe":                                                     1,
	"playbooks/check/freeipa-identity-group-ever-applied.yml::Kinit admin for read-only identity probe":                                            1,
	"playbooks/check/freeipa-identity-user-ever-applied.yml::Kinit admin for read-only identity probe":                                             1,
	"playbooks/test/fixtures/dcgm-exporter-fake-metrics-fixtures.yml::Compute the htpasswd line (apr1-MD5; only when the credential changed)":      1,
	"playbooks/test/fixtures/dns-fixtures.yml::Fixtures — kinit admin (ticket for the ipa CLI below)":                                              1,
	"playbooks/test/fixtures/freeipa-audit-demo.yml::Fixtures — kinit admin":                                                                       1,
	"playbooks/test/fixtures/freeipa-audit-demo.yml::Fixtures — set stable password for {{ audit_demo_user }} via kadmin.local (no forced change)": 1,
	"playbooks/test/fixtures/freeipa-audit-sim.yml::Sim — kinit as {{ audit_demo_user }} (Kerberos TGT)":                                           1,
	"playbooks/test/fixtures/freeipa-client-fixtures.yml::Fixtures — kinit admin (ticket for the ipa CLI below)":                                   1,
	"playbooks/test/fixtures/freeipa-hostauthz-demo.yml::Cleanup — kinit admin":                                                                    1,
	"playbooks/test/fixtures/freeipa-hostauthz-demo.yml::Fixtures — kinit admin":                                                                   1,
	"playbooks/test/fixtures/freeipa-hostauthz-demo.yml::Fixtures — set stable password for hz_db via kadmin.local":                                1,
	"playbooks/test/fixtures/freeipa-hostauthz-demo.yml::Fixtures — set stable password for hz_web via kadmin.local":                               1,
	"playbooks/test/fixtures/freeipa-hostauthz-demo.yml::Restore — kinit admin":                                                                    1,
	"playbooks/test/fixtures/freeipa-hostauthz-sim.yml::Sim[+] — kinit as {{ sim_local_user }}":                                                    1,
	"playbooks/test/fixtures/pilot-access-transport-fixtures.yml::Fixtures — kinit admin":                                                          1,
}

var (
	jinjaExprRe   = regexp.MustCompile(`(?s)\{\{(.*?)\}\}`)
	identifierRe  = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)
	secretIdentRe = regexp.MustCompile(`(?i)password|passwd|secret|(^|_)pass($|_)|(^|_)pwd($|_)|token|api_?key|(^|_)psk($|_)`)
	// Names of files that hold a secret are not the secret.
	secretPathIdentRe = regexp.MustCompile(`(?i)_(file|path|dir)$`)
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
			if secretIdentRe.MatchString(id) && !secretPathIdentRe.MatchString(id) && !slices.Contains(found, id) {
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

// secretSite is the tasks found under one "<path>::<task name>" key.
type secretSite struct {
	tasks   int
	secrets []string
}

// secretCommandTextSites scans every YAML file under root/playbooks for
// tasks whose command text reads a secret, keyed "<path>::<task name>".
func secretCommandTextSites(t *testing.T, root string) map[string]*secretSite {
	t.Helper()
	sites := map[string]*secretSite{}
	err := filepath.WalkDir(filepath.Join(root, "playbooks"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || (filepath.Ext(p) != ".yml" && filepath.Ext(p) != ".yaml") {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		walkTaskMaps(loadYAML(t, p), func(task map[string]any) {
			addSecretSite(sites, filepath.ToSlash(rel), task)
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return sites
}

func addSecretSite(sites map[string]*secretSite, file string, task map[string]any) {
	text, ok := commandText(task)
	if !ok {
		return
	}
	secrets := secretsInText(text)
	if len(secrets) == 0 {
		return
	}
	name, _ := task["name"].(string)
	key := file + "::" + name
	if sites[key] == nil {
		sites[key] = &secretSite{}
	}
	sites[key].tasks++
	for _, s := range secrets {
		if !slices.Contains(sites[key].secrets, s) {
			sites[key].secrets = append(sites[key].secrets, s)
		}
	}
}

// secretSiteProblems compares the sites with the allowlist.
func secretSiteProblems(sites map[string]*secretSite, allow map[string]int) []string {
	var problems []string
	for k, site := range sites {
		switch allowed := allow[k]; {
		case site.tasks > allowed && allowed == 0:
			problems = append(problems, fmt.Sprintf("%s puts %v into command text (%d tasks); pass it as stdin (shell expansion and word splitting change it)", k, site.secrets, site.tasks))
		case site.tasks > allowed:
			problems = append(problems, fmt.Sprintf("%s: %d tasks put %v into command text, %d allowlisted; pass it as stdin", k, site.tasks, site.secrets, allowed))
		case site.tasks < allowed:
			problems = append(problems, fmt.Sprintf("allowlist entry %q counts %d tasks, %d remain; lower it", k, allowed, site.tasks))
		}
	}
	for k := range allow {
		if sites[k] == nil {
			problems = append(problems, fmt.Sprintf("allowlist entry %q no longer matches; remove it", k))
		}
	}
	sort.Strings(problems)
	return problems
}

func TestRegression_NoSecretInCommandText(t *testing.T) {
	for _, p := range secretSiteProblems(secretCommandTextSites(t, filepath.Join("..", "..")), secretCommandTextAllowlist) {
		t.Error(p)
	}
}

func TestSecretCommandTextScanClassifiesSites(t *testing.T) {
	doc := map[string]any{"tasks": []any{
		map[string]any{"name": "shell printf", "ansible.builtin.shell": map[string]any{"cmd": `printf %s "{{ ipa_admin_password }}" | kinit admin`}},
		map[string]any{"name": "free-form command", "command": "htpasswd -nbBC 10 {{ user }} {{ basic_auth_password }}"},
		map[string]any{"name": "loop item", "ansible.builtin.shell": "printf '%s' '{{ item.password }}' | ipa passwd x"},
		map[string]any{"name": "short alias", "ansible.builtin.shell": "printf '%s\\n' '{{ audit_demo_user_pass }}' | kinit u"},
		map[string]any{"name": "token", "ansible.builtin.shell": "curl -H 'Authorization: Bearer {{ ingest_token }}' https://x"},
		map[string]any{"name": "in a rescue", "block": []any{}, "rescue": []any{
			map[string]any{"name": "nested", "ansible.builtin.shell": "echo '{{ webhook_secret }}' > /x"},
		}},
		map[string]any{"name": "copied", "ansible.builtin.shell": "echo '{{ a_password }}' | kinit a"},
		map[string]any{"name": "copied", "ansible.builtin.shell": "echo '{{ b_password }}' | kinit b"},
		map[string]any{"name": "argv and stdin", "ansible.builtin.command": map[string]any{"argv": []any{"kinit", "admin@{{ ipa_realm }}", "--password={{ ipa_admin_password }}"}, "stdin": "{{ ipa_admin_password }}"}},
		map[string]any{"name": "no secret", "ansible.builtin.shell": "kinit -kt /etc/krb5.keytab host/{{ fqdn }}"},
		map[string]any{"name": "secret file path", "ansible.builtin.shell": "test -s {{ ingest_token_file }} && ssh -i {{ login_key }} x"},
		map[string]any{"name": "not a command", "ansible.builtin.copy": map[string]any{"content": "{{ ipa_admin_password }}", "dest": "/x"}},
	}}
	sites := map[string]*secretSite{}
	walkTaskMaps(doc, func(task map[string]any) { addSecretSite(sites, "f.yml", task) })
	got := map[string]string{}
	for k, s := range sites {
		got[k] = fmt.Sprint(s.tasks, s.secrets)
	}
	want := map[string]string{
		"f.yml::shell printf":      "1 [ipa_admin_password]",
		"f.yml::free-form command": "1 [basic_auth_password]",
		"f.yml::loop item":         "1 [password]",
		"f.yml::short alias":       "1 [audit_demo_user_pass]",
		"f.yml::token":             "1 [ingest_token]",
		"f.yml::nested":            "1 [webhook_secret]",
		"f.yml::copied":            "2 [a_password b_password]",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", got, want)
	}

	// A copied task under an allowlisted name is a new site, and a migrated
	// one must lower the count.
	allow := map[string]int{"f.yml::copied": 1, "f.yml::shell printf": 2}
	for k := range want {
		if _, ok := allow[k]; !ok && k != "f.yml::copied" {
			allow[k] = 1
		}
	}
	problems := secretSiteProblems(sites, allow)
	if len(problems) != 2 || !strings.Contains(problems[0], `"f.yml::shell printf" counts 2 tasks, 1 remain`) || !strings.Contains(problems[1], "f.yml::copied: 2 tasks") {
		t.Fatalf("problems = %q", problems)
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

// TestRegression_FreeIPAKinitTasksPassPasswordUnchanged runs the real kinit
// tasks on this PR's DNS paths with ansible-playbook and a fake kinit that
// records its stdin, arguments and KRB5CCNAME. With a shell printf (before
// cdcd39b for the forwarder task, before the next candidate for the other
// two), `demo$pilot92_missing_suffix` reached kinit as `demo` and a backtick
// or $(...) in the password ran as a command.
func TestRegression_FreeIPAKinitTasksPassPasswordUnchanged(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
			t.Fatalf("required ansible-playbook not installed: %v", err)
		}
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	const realm = "IPA.PILOT.INTERNAL"
	for _, tc := range []struct {
		playbook, task, secretVar string
		vars                      map[string]any
		// ccache is the KRB5CCNAME the task itself sets, "" when an
		// enclosing block sets it.
		ccache bool
	}{
		{playbook: "freeipa-server-replica-apply.yml", task: "FreeIPA replica DNS — kinit admin (for dnsserver-mod)", secretVar: "ipa_admin_password"},
		{playbook: "freeipa-server-replica-apply.yml", task: "FreeIPA replica DNS self-register — kinit admin into the dedicated ccache", secretVar: "ipa_enroll_password",
			vars: map[string]any{"ipa_enroll_principal": "admin"}, ccache: true},
		{playbook: "freeipa-server-apply.yml", task: "Kinit admin (for dnsconfig-mod)", secretVar: "ipa_admin_password"},
		{playbook: "freeipa-identity-apply.yml", task: "Kinit admin", secretVar: "identity_admin_password",
			vars: map[string]any{"identity_admin_principal": "admin"}},
	} {
		task := findNamedTask(t, loadYAML(t, filepath.Join("..", "..", "playbooks", "apply", tc.playbook)), tc.task)
		if task["no_log"] != true {
			t.Fatalf("%s: the kinit task must keep no_log: true", tc.task)
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
			t.Run(fmt.Sprintf("%s/%d", tc.task, i), func(t *testing.T) {
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
				stdinFile, argsFile, ccFile := filepath.Join(dir, "stdin"), filepath.Join(dir, "args"), filepath.Join(dir, "ccname")
				script := "#!/bin/sh\ncat > \"$FAKE_KINIT_STDIN\"\nprintf '%s\\n' \"$@\" > \"$FAKE_KINIT_ARGS\"\nprintf '%s' \"$KRB5CCNAME\" > \"$FAKE_KINIT_CCNAME\"\n"
				if err := os.WriteFile(filepath.Join(bin, "kinit"), []byte(script), 0o755); err != nil {
					t.Fatal(err)
				}
				ccache := filepath.Join(dir, "krb5cc")
				// Ansible templates vault and -e values too, so a real
				// password containing {{ }} is rendered before any task
				// sees it (on ansible-core 2.19.2, ab{{ 6*7 }}cd reaches
				// kinit as ab42cd). That is outside these tasks; !unsafe
				// keeps the test value literal, so the last case checks
				// only that the task adds no templating of its own.
				vars := map[string]any{tc.secretVar: unsafeString(password), "ipa_realm": realm, "ipa_replica_dns_ccache_file": map[string]any{"path": ccache}}
				for k, v := range tc.vars {
					vars[k] = v
				}
				play := []map[string]any{{
					"name": "kinit", "hosts": "localhost", "connection": "local", "gather_facts": false,
					"vars":        vars,
					"environment": map[string]any{"PATH": bin + ":" + os.Getenv("PATH"), "FAKE_KINIT_STDIN": stdinFile, "FAKE_KINIT_ARGS": argsFile, "FAKE_KINIT_CCNAME": ccFile},
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
				if string(gotArgs) != "admin@"+realm+"\n" {
					t.Errorf("password %q: kinit args = %q, want the principal only", password, gotArgs)
				}
				if tc.ccache {
					if got, _ := os.ReadFile(ccFile); string(got) != ccache {
						t.Errorf("password %q: KRB5CCNAME = %q, want the dedicated cache %q", password, got, ccache)
					}
				}
				if _, err := os.Stat(marker); err == nil {
					t.Errorf("password %q ran a command", password)
				}
			})
		}
	}
}

// unsafeString marshals as a YAML !unsafe scalar, which Ansible never
// templates.
type unsafeString string

func (s unsafeString) MarshalYAML() (any, error) {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!unsafe", Value: string(s), Style: yaml.DoubleQuotedStyle}, nil
}
