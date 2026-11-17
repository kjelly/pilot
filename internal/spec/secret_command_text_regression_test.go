package spec

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
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
// the value change it as well. printf and dash's echo also rewrite `%` and
// `\`, so a `kadmin.local cpw` fed by printf sets another password than the
// one declared and still reports "changed".
//
// stdin is the only route that keeps a secret byte for byte. An argv element
// is not safe either (issue #118 review of this lint's first version):
// ansible.builtin.command defaults expand_argument_vars to true, so `$HOME`
// (any `$name`) in an argv element is expanded before exec (`$(...)` is not
// run; ansible-core 2.19.2), and any local user can read the element in
// /proc/<pid>/cmdline. This lint
// therefore flags a secret in the command text of a shell, command, raw,
// expect or script task and in the argv of a command task, and requires
// no_log: true on every task that passes a secret on stdin. The only argv
// exemption is the FreeIPA installers (ipa-server-install, ipa-replica-install,
// ipa-client-install): they take the admin password only as an option, and
// moving them to stdin is tracked separately (their argv still goes through
// expand_argument_vars).
//
// TestRegression_FreeIPAKinitTasksPassPasswordUnchanged is the runtime
// counterpart: it finds every task that passes a secret on stdin and runs it
// with real ansible-playbook and a fake program.
//
// What the lint does not see: a secret that reaches a task through a variable
// whose name does not look secret and that is set outside the task (play
// vars, set_fact, a loop item such as `item.value`), a secret in
// `environment:` or in the `responses` of expect, and no_log inherited from a
// block or play (a stdin task under such a block is still flagged: put
// no_log: true on the task itself).

// secretCommandTextAllowlist counts, per "<path>::<task name>", the tasks
// that put a secret into command text and are still to be migrated. Only the
// three htpasswd tasks are left; they are batch 3 of issue #118. The lint
// fails when a key has more
// tasks than its count (a copied task with the same name is a new site) and
// when it has fewer, so the list only shrinks.
var secretCommandTextAllowlist = map[string]int{
	"playbooks/apply/dcgm-exporter-apply.yml::Step 6: Generate bcrypt hash for basic auth (spec C9; only when the credential changed)":        1,
	"playbooks/apply/host-monitoring-apply.yml::Step 8: Generate bcrypt hash for basic auth (spec C10; only when the credential changed)":     1,
	"playbooks/test/fixtures/dcgm-exporter-fake-metrics-fixtures.yml::Compute the htpasswd line (apr1-MD5; only when the credential changed)": 1,
}

var (
	jinjaExprRe  = regexp.MustCompile(`(?s)\{\{(.*?)\}\}`)
	identifierRe = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)
	// secretIdentRe names the variables that hold a secret. The last three
	// groups were added with the argv rule: passphrases, credentials, key
	// material and one-time passwords (the tree has no variable of those
	// names today, so they only catch new ones).
	secretIdentRe = regexp.MustCompile(`(?i)password|passwd|secret|(^|_)pass($|_)|(^|_)pwd($|_)|token|api_?key|(^|_)psk($|_)|passphrase|credential|(^|_)(private|signing|master)_key($|_)|(^|_)otp($|_)`)
	// Names of files that hold a secret are not the secret.
	secretPathIdentRe = regexp.MustCompile(`(?i)_(file|path|dir)$`)
	// installerProgramRe is the one program whose argv may carry a secret.
	installerProgramRe = regexp.MustCompile(`^ipa-[a-z]+-install$`)
)

// secretModules are the modules whose arguments become a command line:
// shell, command, raw, expect and script (a script's arguments are command
// text as well).
var secretModules = append(slices.Clone(commandModules), "script")

// secretTaskModule returns the first command-running module a task uses
// (short, ansible.builtin. or ansible.legacy. name) and its arguments.
func secretTaskModule(task map[string]any) (string, any) {
	for _, m := range secretModules {
		for _, key := range []string{m, "ansible.builtin." + m, "ansible.legacy." + m} {
			if v, ok := task[key]; ok {
				return m, v
			}
		}
	}
	return "", nil
}

// commandText returns the text a shell, command, raw, expect or script task
// hands to a shell or to Ansible's word splitting: the free-form string, or
// cmd, _raw_params or command. argv elements are scanned by argvSecrets.
func commandText(task map[string]any) (string, bool) {
	module, raw := secretTaskModule(task)
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

// valueText flattens a YAML value (string, list, mapping) into text.
func valueText(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			parts = append(parts, valueText(e))
		}
		return strings.Join(parts, "\n")
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(x))
		for _, k := range keys {
			parts = append(parts, k+"\n"+valueText(x[k]))
		}
		return strings.Join(parts, "\n")
	default:
		return fmt.Sprint(x)
	}
}

// taskVars returns the task's own `vars:` block.
func taskVars(task map[string]any) map[string]any {
	vars, _ := task["vars"].(map[string]any)
	return vars
}

// secretsThroughVars returns the secret-looking variables text reads, either
// by name or through a variable of the task's own vars: block (an argv of
// "{{ args }}" with args defined in vars: reads what args reads).
func secretsThroughVars(text string, vars map[string]any) []string {
	found := secretsInText(text)
	seen := map[string]bool{}
	var visit func(text string)
	visit = func(text string) {
		for _, m := range jinjaExprRe.FindAllStringSubmatch(text, -1) {
			for _, id := range identifierRe.FindAllString(m[1], -1) {
				val, ok := vars[id]
				if !ok || seen[id] {
					continue
				}
				seen[id] = true
				for _, s := range secretsInText(valueText(val)) {
					if !slices.Contains(found, s) {
						found = append(found, s)
					}
				}
				visit(valueText(val))
			}
		}
	}
	visit(text)
	return found
}

// argvProgram returns the program an argv value starts with: the first list
// element, the first string literal of a Jinja list expression, or what a
// variable of the task's vars: block starts with. "" when it cannot tell.
func argvProgram(v any, vars map[string]any, depth int) string {
	if depth > 8 {
		return ""
	}
	switch x := v.(type) {
	case []any:
		if len(x) == 0 {
			return ""
		}
		return argvProgram(x[0], vars, depth+1)
	case string:
		s := strings.TrimSpace(x)
		if !strings.HasPrefix(s, "{{") {
			if fields := strings.Fields(s); len(fields) > 0 {
				return fields[0]
			}
			return ""
		}
		s = strings.TrimLeft(strings.TrimPrefix(s, "{{"), " \t\r\n[(")
		if s == "" {
			return ""
		}
		if q := s[0]; q == '\'' || q == '"' {
			if end := strings.IndexByte(s[1:], q); end >= 0 {
				return s[1 : 1+end]
			}
			return ""
		}
		id := identifierRe.FindString(s)
		if val, ok := vars[id]; ok && id != "" && strings.HasPrefix(s, id) {
			return argvProgram(val, vars, depth+1)
		}
	}
	return ""
}

// argvSecrets returns the secret-looking variables the argv of a command
// task reads, directly or through the task's own vars: block. The FreeIPA
// installers are the one exemption (see the header comment).
func argvSecrets(task map[string]any) []string {
	_, raw := secretTaskModule(task)
	args, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	argv, ok := args["argv"]
	if !ok {
		return nil
	}
	vars := taskVars(task)
	if installerProgramRe.MatchString(path.Base(argvProgram(argv, vars, 0))) {
		return nil
	}
	return secretsThroughVars(valueText(argv), vars)
}

// stdinSecrets returns the secret-looking variables the stdin of a command
// task reads, directly or through the task's own vars: block.
func stdinSecrets(task map[string]any) []string {
	_, raw := secretTaskModule(task)
	args, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	stdin, ok := args["stdin"]
	if !ok {
		return nil
	}
	return secretsThroughVars(valueText(stdin), taskVars(task))
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

// secretScan is what the lint finds in a tree: tasks that put a secret into
// command text or argv, and tasks that pass one on stdin without no_log.
type secretScan struct {
	text, argv, stdinNoLog map[string]*secretSite
	// stdin counts the tasks that pass a secret on stdin, no_log or not.
	stdin map[string]*secretSite
}

func newSecretScan() *secretScan {
	return &secretScan{text: map[string]*secretSite{}, argv: map[string]*secretSite{}, stdinNoLog: map[string]*secretSite{}, stdin: map[string]*secretSite{}}
}

func addSite(sites map[string]*secretSite, key string, secrets []string) {
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

// add classifies one task found in file.
func (sc *secretScan) add(file string, task map[string]any) {
	name, _ := task["name"].(string)
	key := file + "::" + name
	if text, ok := commandText(task); ok {
		if secrets := secretsInText(text); len(secrets) > 0 {
			addSite(sc.text, key, secrets)
		}
	}
	if secrets := argvSecrets(task); len(secrets) > 0 {
		addSite(sc.argv, key, secrets)
	}
	if secrets := stdinSecrets(task); len(secrets) > 0 {
		addSite(sc.stdin, key, secrets)
		if task["no_log"] != true {
			addSite(sc.stdinNoLog, key, secrets)
		}
	}
}

// secretCommandTextScan scans every YAML file under root/playbooks.
func secretCommandTextScan(t *testing.T, root string) *secretScan {
	t.Helper()
	sc := newSecretScan()
	err := filepath.WalkDir(filepath.Join(root, "playbooks"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || (filepath.Ext(p) != ".yml" && filepath.Ext(p) != ".yaml") {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		walkTaskMaps(loadYAML(t, p), func(task map[string]any) {
			sc.add(filepath.ToSlash(rel), task)
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return sc
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

// secretScanProblems is every problem of a scan: text sites against the
// ratchet allowlist, argv sites and stdin tasks without no_log with no
// allowlist at all.
func secretScanProblems(sc *secretScan, allow map[string]int) []string {
	problems := secretSiteProblems(sc.text, allow)
	for k, site := range sc.argv {
		problems = append(problems, fmt.Sprintf("%s puts %v into an argv element (%d tasks); pass it as stdin (expand_argument_vars expands it, /proc/<pid>/cmdline shows it)", k, site.secrets, site.tasks))
	}
	for k, site := range sc.stdinNoLog {
		problems = append(problems, fmt.Sprintf("%s passes %v on stdin without no_log: true (%d tasks); a failure would print it", k, site.secrets, site.tasks))
	}
	sort.Strings(problems)
	return problems
}

func TestRegression_NoSecretInCommandText(t *testing.T) {
	for _, p := range secretScanProblems(secretCommandTextScan(t, filepath.Join("..", "..")), secretCommandTextAllowlist) {
		t.Error(p)
	}
}

func TestSecretCommandTextScanClassifiesSites(t *testing.T) {
	cmd := func(name string, args any) map[string]any {
		return map[string]any{"name": name, "ansible.builtin.command": args}
	}
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
		map[string]any{"name": "script text", "ansible.builtin.script": "files/x.sh --key {{ signing_key }}"},
		map[string]any{"name": "script cmd", "script": map[string]any{"cmd": "x.sh {{ ldap_passphrase }}"}},
		map[string]any{"name": "new ident credential", "ansible.builtin.shell": "x {{ db_credential }} {{ otp }} {{ master_key }} {{ tls_private_key }}"},
		map[string]any{"name": "no secret", "ansible.builtin.shell": "kinit -kt /etc/krb5.keytab host/{{ fqdn }}"},
		map[string]any{"name": "secret file path", "ansible.builtin.shell": "test -s {{ ingest_token_file }} && ssh -i {{ login_key }} x"},
		map[string]any{"name": "not a command", "ansible.builtin.copy": map[string]any{"content": "{{ ipa_admin_password }}", "dest": "/x"}},
		map[string]any{"name": "not secret ids", "ansible.builtin.shell": "x {{ monkey }} {{ otpion }} {{ keyboard }} {{ public_key }} {{ ssh_key_path }}"},

		// argv: each element is expanded by expand_argument_vars and shows in
		// /proc/<pid>/cmdline.
		cmd("argv option", map[string]any{"argv": []any{"kinit", "admin@{{ ipa_realm }}", "--password={{ ipa_admin_password }}"}, "stdin": "{{ ipa_admin_password }}"}),
		cmd("argv plain", map[string]any{"argv": []any{"tool", "{{ api_token }}"}}),
		cmd("argv jinja list", map[string]any{"argv": "{{ ['tool', '--pw=' ~ ipa_admin_password] }}"}),
		cmd("argv through vars", map[string]any{"argv": "{{ tool_args }}"}),
		cmd("argv through two vars", map[string]any{"argv": "{{ more_args }}"}),
		cmd("argv no secret", map[string]any{"argv": []any{"kinit", "admin@{{ ipa_realm }}"}, "stdin": "{{ ipa_admin_password }}"}),
		cmd("installer list", map[string]any{"argv": []any{"ipa-client-install", "-U", "--password={{ ipa_enroll_password }}"}}),
		cmd("installer path", map[string]any{"argv": []any{"/usr/sbin/ipa-replica-install", "--password={{ ipa_enroll_password }}"}}),
		cmd("installer jinja", map[string]any{"argv": "{{\n  ['ipa-server-install', '-U', '-p', ipa_dm_password]\n  }}"}),
		cmd("installer through vars", map[string]any{"argv": "{{ install_args }}"}),
		cmd("installer name only later", map[string]any{"argv": []any{"kinit", "ipa-server-install", "{{ ipa_admin_password }}"}}),
		cmd("installer jinja later", map[string]any{"argv": "{{ ['kinit', 'ipa-client-install', ipa_admin_password] }}"}),
		cmd("installer stdin", map[string]any{"argv": []any{"ipa-client-install", "-U"}, "stdin": "{{ ipa_enroll_password }}"}),

		// stdin must be no_log.
		cmd("stdin with no_log", map[string]any{"argv": []any{"kinit", "admin"}, "stdin": "{{ ipa_admin_password }}"}),
		cmd("stdin json", map[string]any{"argv": []any{"python3", "x.py"}, "stdin": "{{ {'user': u, 'password': p} | to_json }}"}),
		cmd("stdin without secret", map[string]any{"argv": []any{"tool"}, "stdin": "{{ {'domain': ipa_domain} | to_json }}"}),
		cmd("stdin through vars", map[string]any{"argv": []any{"kinit", "admin"}, "stdin": "{{ pw }}"}),
		cmd("stdin literal", map[string]any{"argv": []any{"tool"}, "stdin": "hello\n"}),
	}}
	// The task-level fields (no_log, vars) live beside the module.
	setTask := func(name string, kv map[string]any) {
		for _, task := range doc["tasks"].([]any) {
			if m := task.(map[string]any); m["name"] == name {
				for k, v := range kv {
					m[k] = v
				}
				return
			}
		}
		t.Fatalf("no task %q", name)
	}
	setTask("argv option", map[string]any{"no_log": true})
	setTask("argv through vars", map[string]any{"vars": map[string]any{"tool_args": []any{"tool", "{{ ipa_admin_password }}"}}})
	setTask("argv through two vars", map[string]any{"vars": map[string]any{
		"more_args": "{{ base_args + ['x'] }}",
		"base_args": []any{"tool", "--key={{ webhook_secret }}"},
	}})
	setTask("installer through vars", map[string]any{"vars": map[string]any{
		"install_args": "{{ base + extra }}",
		"base":         []any{"ipa-server-install", "-p", "{{ ipa_dm_password }}"},
		"extra":        []any{"--setup-dns"},
	}})
	setTask("stdin with no_log", map[string]any{"no_log": true})
	setTask("stdin through vars", map[string]any{"vars": map[string]any{"pw": "{{ ipa_admin_password }}"}})
	setTask("stdin json", map[string]any{"no_log": true})
	setTask("installer stdin", map[string]any{"no_log": true})
	// A no_log that is not the literal true does not count.
	setTask("argv no secret", map[string]any{"no_log": "{{ hide }}"})

	sc := newSecretScan()
	walkTaskMaps(doc, func(task map[string]any) { sc.add("f.yml", task) })
	got := func(sites map[string]*secretSite) map[string]string {
		out := map[string]string{}
		for k, s := range sites {
			out[k] = fmt.Sprint(s.tasks, s.secrets)
		}
		return out
	}
	for _, c := range []struct {
		what string
		got  map[string]*secretSite
		want map[string]string
	}{
		{"text", sc.text, map[string]string{
			"f.yml::shell printf":         "1 [ipa_admin_password]",
			"f.yml::free-form command":    "1 [basic_auth_password]",
			"f.yml::loop item":            "1 [password]",
			"f.yml::short alias":          "1 [audit_demo_user_pass]",
			"f.yml::token":                "1 [ingest_token]",
			"f.yml::nested":               "1 [webhook_secret]",
			"f.yml::copied":               "2 [a_password b_password]",
			"f.yml::script text":          "1 [signing_key]",
			"f.yml::script cmd":           "1 [ldap_passphrase]",
			"f.yml::new ident credential": "1 [db_credential otp master_key tls_private_key]",
		}},
		{"argv", sc.argv, map[string]string{
			"f.yml::argv option":               "1 [ipa_admin_password]",
			"f.yml::argv plain":                "1 [api_token]",
			"f.yml::argv jinja list":           "1 [ipa_admin_password]",
			"f.yml::argv through vars":         "1 [ipa_admin_password]",
			"f.yml::argv through two vars":     "1 [webhook_secret]",
			"f.yml::installer name only later": "1 [ipa_admin_password]",
			"f.yml::installer jinja later":     "1 [ipa_admin_password]",
		}},
		{"stdin", sc.stdin, map[string]string{
			"f.yml::argv option":        "1 [ipa_admin_password]",
			"f.yml::argv no secret":     "1 [ipa_admin_password]",
			"f.yml::installer stdin":    "1 [ipa_enroll_password]",
			"f.yml::stdin with no_log":  "1 [ipa_admin_password]",
			"f.yml::stdin json":         "1 [password]",
			"f.yml::stdin through vars": "1 [ipa_admin_password]",
		}},
		{"stdin without no_log", sc.stdinNoLog, map[string]string{
			"f.yml::argv no secret":     "1 [ipa_admin_password]",
			"f.yml::stdin through vars": "1 [ipa_admin_password]",
		}},
	} {
		if fmt.Sprint(got(c.got)) != fmt.Sprint(c.want) {
			t.Errorf("%s: got %v, want %v", c.what, got(c.got), c.want)
		}
	}

	// A copied task under an allowlisted name is a new site, and a migrated
	// one must lower the count. Argv and stdin sites have no allowlist.
	allow := map[string]int{"f.yml::copied": 1, "f.yml::shell printf": 2}
	for k := range sc.text {
		if _, ok := allow[k]; !ok && k != "f.yml::copied" {
			allow[k] = 1
		}
	}
	problems := secretScanProblems(sc, allow)
	var textProblems, argvProblems, stdinProblems []string
	for _, p := range problems {
		switch {
		case strings.Contains(p, "argv element"):
			argvProblems = append(argvProblems, p)
		case strings.Contains(p, "without no_log"):
			stdinProblems = append(stdinProblems, p)
		default:
			textProblems = append(textProblems, p)
		}
	}
	if len(textProblems) != 2 || !strings.Contains(textProblems[0], `"f.yml::shell printf" counts 2 tasks, 1 remain`) || !strings.Contains(textProblems[1], "f.yml::copied: 2 tasks") {
		t.Errorf("text problems = %q", textProblems)
	}
	if len(argvProblems) != 7 || len(stdinProblems) != 2 {
		t.Errorf("argv problems = %q, stdin problems = %q", argvProblems, stdinProblems)
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

// stdinHostilePasswords are the secrets the runtime test hands every task
// that passes one on stdin. %[1]s is a file the value would create if any
// part of it ran as a command.
var stdinHostilePasswords = []string{
	"demo$pilot118_missing_suffix", // an unset shell variable
	"h$HOME/x",                     // a set variable: expand_argument_vars would expand it in argv
	"a`touch %[1]s`b",              // backticks
	"x$(touch %[1]s)y",             // command substitution
	`dq"dq`,                        // quotes
	`sq'sq`,
	`back\slash`, // backslash, which printf and dash's echo rewrite
	`trailing\`,
	"50%s%d%%", // printf directives
	"tab\there",
	"  spaced  ",
	"{{ not_jinja }}", // the task must add no templating of its own
	"all$HOME\"'\\%`id`$(id) \t end",
}

// stdinCase says how to run one task that passes a secret on stdin.
type stdinCase struct {
	// secretVars returns the play variables that carry the secret for a task
	// copy ("" means the single variable named by secret).
	secret     string
	secretVars func(value any) map[string]any
	// args are the arguments the program must get, and nothing else.
	args []string
	// stdinCopies is how many times the secret appears on stdin, one per
	// line (kadmin and `ipa user-mod --password` read it twice).
	stdinCopies int
	// ccacheVar is the {path: ...} variable the task's KRB5CCNAME names;
	// ccachePrefix what the task puts before the path; ccacheString says the
	// KRB5CCNAME comes from a string variable (pilot_krb5ccname) instead.
	ccacheVar, ccachePrefix string
	ccacheString            string
	// output is what the fake program prints (a real capture, redacted).
	output string
	// external names an existing runtime test that covers a task this
	// harness cannot run alone (a loop over users).
	external string
}

func kinitCase(secret string, args ...string) stdinCase {
	return stdinCase{secret: secret, args: args, stdinCopies: 1}
}

func (c stdinCase) cache(v, prefix string) stdinCase {
	c.ccacheVar, c.ccachePrefix = v, prefix
	return c
}

// kadminCase is `kadmin.local -q "cpw <user>"` with the password twice on stdin.
// The fake prints what kadmin.local prints on success (a real capture), so the
// task's own changed_when and nothing else decides the outcome.
func kadminCase(secret, user string) stdinCase {
	return stdinCase{secret: secret, args: []string{"-q", "cpw " + user}, stdinCopies: 2,
		output: "Authenticating as principal admin/admin@IPA.PILOT.INTERNAL with password.\nEnter password for principal \"" + user + "@IPA.PILOT.INTERNAL\": \nRe-enter password for principal \"" + user + "@IPA.PILOT.INTERNAL\": \nPassword for \"" + user + "@IPA.PILOT.INTERNAL\" changed.\n"}
}

const stdinRealm = "IPA.PILOT.INTERNAL"

// rosterSecret carries the password at freeipa_roster.freeipa.admin.password.
func rosterSecret(value any) map[string]any {
	return map[string]any{"freeipa_roster": map[string]any{"freeipa": map[string]any{"admin": map[string]any{"principal": "rosteradmin", "password": value}}}}
}

// stdinCases covers every task the lint finds that passes a secret on stdin:
// TestRegression_FreeIPAKinitTasksPassPasswordUnchanged fails for a task with
// no row here and for a row whose task is gone.
var stdinCases = map[string]stdinCase{
	"playbooks/apply/freeipa-dns-apply.yml::Kinit admin into the dedicated ccache":                                                  kinitCase("ipa_admin_password", "admin@"+stdinRealm).cache("freeipa_dns_ccache_file", ""),
	"playbooks/apply/freeipa-identity-apply.yml::Kinit admin":                                                                       kinitCase("identity_admin_password", "admin@"+stdinRealm),
	"playbooks/apply/freeipa-identity-apply.yml::Set password for users that need one (first-time onboard, or requested reset)":     {external: "TestRegression_IdentitySecretInputsRuntime"},
	"playbooks/apply/freeipa-nfs-server-apply.yml::Acquire Kerberos admin ticket":                                                   {secretVars: rosterSecret, args: []string{"rosteradmin"}, stdinCopies: 1},
	"playbooks/apply/freeipa-server-apply.yml::Kinit admin (for dnsconfig-mod)":                                                     kinitCase("ipa_admin_password", "admin@"+stdinRealm),
	"playbooks/apply/freeipa-server-replica-apply.yml::FreeIPA replica DNS self-register — kinit admin into the dedicated ccache":   kinitCase("ipa_enroll_password", "admin@"+stdinRealm).cache("ipa_replica_dns_ccache_file", ""),
	"playbooks/apply/freeipa-server-replica-apply.yml::FreeIPA replica DNS — kinit admin (for dnsserver-mod)":                       kinitCase("ipa_admin_password", "admin@"+stdinRealm),
	"playbooks/apply/gateway-scope-apply.yml::Kinit admin":                                                                          kinitCase("ipa_admin_password", "admin"),
	"playbooks/apply/internal-endpoint-apply.yml::Kinit as IPA admin (identity + DNS reconcile)":                                    kinitCase("ipa_admin_password", "admin"),
	"playbooks/apply/internal-endpoint-apply.yml::Kinit as IPA admin (decommission verify query)":                                   kinitCase("ipa_admin_password", "admin"),
	"playbooks/apply/pilot-access-directory-apply.yml::Kinit admin (management-plane operations only — never shipped to this host)": kinitCase("ipa_admin_password", "admin"),
	"playbooks/apply/pilot-access-gateway-apply.yml::Kinit admin (management-plane operations only — never shipped to this host)":   kinitCase("ipa_admin_password", "admin"),
	"playbooks/apply/pilot-access-target-policy-apply.yml::Kinit admin (FreeIPA hostgroup membership only)":                         kinitCase("ipa_admin_password", "admin"),
	"playbooks/apply/pilot-session-store-apply.yml::Kinit admin (management-plane operations only — never shipped to this host)":    kinitCase("ipa_admin_password", "admin"),
	"playbooks/apply/tasks/freeipa-client-host-dns.yml::FreeIPA client DNS backfill — kinit admin into the dedicated ccache":        kinitCase("ipa_enroll_password", "admin@"+stdinRealm).cache("ipa_client_dns_ccache_file", ""),
	"playbooks/apply/tasks/freeipa-client-host-dns.yml::FreeIPA client DNS replace — kinit admin into the dedicated ccache":         kinitCase("ipa_enroll_password", "admin@"+stdinRealm).cache("ipa_client_dns_replace_ccache_file", ""),
	"playbooks/apply/tasks/freeipa-host-access-policy.yml::FreeIPA host access policy — kinit admin into the dedicated ccache":      kinitCase("ipa_enroll_password", "admin@"+stdinRealm).cache("ipa_host_policy_ccache_file", "FILE:"),
	"playbooks/apply/tasks/freeipa-host-annotations.yml::FreeIPA host annotations — kinit admin into the dedicated ccache":          kinitCase("ipa_enroll_password", "admin@"+stdinRealm).cache("ipa_annotations_ccache_file", ""),
	"playbooks/apply/tasks/internal-endpoint-delete.yml::Kinit as IPA admin (delete sequence)":                                      {secret: "ipa_admin_password", args: []string{"admin"}, stdinCopies: 1, ccacheString: "pilot_krb5ccname"},
	"playbooks/check/freeipa-access-drift-probe.yml::Kinit admin for read-only drift probe":                                         kinitCase("identity_admin_password", "admin@"+stdinRealm),
	"playbooks/check/freeipa-capability-probe.yml::Kinit admin for read-only capability probe":                                      kinitCase("identity_admin_password", "admin@"+stdinRealm),
	"playbooks/check/freeipa-identity-group-ever-applied.yml::Kinit admin for read-only identity probe":                             kinitCase("identity_admin_password", "admin@"+stdinRealm),
	"playbooks/check/freeipa-identity-user-ever-applied.yml::Kinit admin for read-only identity probe":                              kinitCase("identity_admin_password", "admin@"+stdinRealm),
	"playbooks/decommission/freeipa-nfs-server-decommission.yml::Kinit as IPA admin": {secretVars: func(v any) map[string]any {
		return map[string]any{"nfs_decom_admin_password": v, "freeipa_roster": map[string]any{"freeipa": map[string]any{"admin": map[string]any{"principal": "rosteradmin"}}}}
	}, args: []string{"rosteradmin"}, stdinCopies: 1},
	"playbooks/test/fixtures/dns-fixtures.yml::Fixtures — kinit admin (ticket for the ipa CLI below)":                                              kinitCase("ipa_admin_password", "admin@"+stdinRealm),
	"playbooks/test/fixtures/freeipa-audit-demo.yml::Fixtures — kinit admin":                                                                       kinitCase("ipa_admin_password", "admin@"+stdinRealm),
	"playbooks/test/fixtures/freeipa-audit-demo.yml::Fixtures — does {{ audit_demo_user }} already have the declared password?":                    kinitCase("audit_demo_user_pass", "-c", "MEMORY:pilot-audit-demo-pwcheck", "audituser@"+stdinRealm),
	"playbooks/test/fixtures/freeipa-audit-demo.yml::Fixtures — set stable password for {{ audit_demo_user }} via kadmin.local (no forced change)": kadminCase("audit_demo_user_pass", "audituser"),
	"playbooks/test/fixtures/freeipa-hostauthz-demo.yml::Fixtures — does hz_web already have the declared password?":                               kinitCase("hz_web_password", "-c", "MEMORY:pilot-hz_web-pwcheck", "hz_web@"+stdinRealm),
	"playbooks/test/fixtures/freeipa-hostauthz-demo.yml::Fixtures — set stable password for hz_web via kadmin.local":                               kadminCase("hz_web_password", "hz_web"),
	"playbooks/test/fixtures/freeipa-hostauthz-demo.yml::Fixtures — does hz_db already have the declared password?":                                kinitCase("hz_db_password", "-c", "MEMORY:pilot-hz_db-pwcheck", "hz_db@"+stdinRealm),
	"playbooks/test/fixtures/freeipa-hostauthz-demo.yml::Fixtures — set stable password for hz_db via kadmin.local":                                kadminCase("hz_db_password", "hz_db"),
	"playbooks/test/fixtures/freeipa-audit-sim.yml::Sim — kinit as {{ audit_demo_user }} (Kerberos TGT)":                                           kinitCase("audit_demo_user_pass", "-r", "7d", "audituser"),
	"playbooks/test/fixtures/freeipa-client-fixtures.yml::Fixtures — kinit admin (ticket for the ipa CLI below)":                                   kinitCase("ipa_admin_password", "admin@"+stdinRealm),
	"playbooks/test/fixtures/freeipa-client-pwexpiry-canary.yml::Canary password — kinit admin":                                                    kinitCase("ipa_admin_password", "admin@"+stdinRealm),
	"playbooks/test/fixtures/freeipa-client-pwexpiry-fixtures.yml::Password-expiry fixtures — kinit admin":                                         kinitCase("ipa_admin_password", "admin@"+stdinRealm),
	"playbooks/test/fixtures/freeipa-hostauthz-demo.yml::Fixtures — kinit admin":                                                                   kinitCase("ipa_admin_password", "admin@"+stdinRealm),
	"playbooks/test/fixtures/freeipa-hostauthz-demo.yml::Restore — kinit admin":                                                                    kinitCase("ipa_admin_password", "admin@"+stdinRealm),
	"playbooks/test/fixtures/freeipa-hostauthz-demo.yml::Cleanup — kinit admin":                                                                    kinitCase("ipa_admin_password", "admin@"+stdinRealm),
	"playbooks/test/fixtures/freeipa-hostauthz-sim.yml::Sim[+] — kinit as {{ sim_local_user }}":                                                    kinitCase("sim_local_password", "-r", "7d", "simlocal"),
	"playbooks/test/fixtures/gateway-scope-retirement-fixtures.yml::Authenticate fixture admin":                                                    kinitCase("ipa_admin_password", "admin"),
	"playbooks/test/fixtures/login-probe-fixtures.yml::Fixtures — kinit admin":                                                                     kinitCase("ipa_admin_password", "admin@"+stdinRealm),
	"playbooks/test/fixtures/pilot-access-transport-fixtures.yml::Fixtures — kinit admin":                                                          kinitCase("ipa_admin_password", "admin@"+stdinRealm),
	"playbooks/test/fixtures/pilot-access-transport-fixtures.yml::Fixtures — does the E2E password already work?":                                  kinitCase("transport_fixture_user_password", "-c", "MEMORY:pilot-transport-e2e-pwcheck", "transportuser@"+stdinRealm),
	"playbooks/test/fixtures/pilot-access-transport-fixtures.yml::Fixtures — set the E2E password (only when it does not work yet)":                {secret: "transport_fixture_user_password", args: []string{"user-mod", "transportuser", "--password"}, stdinCopies: 2},
}

// stdinTasks returns every task under root/playbooks that passes a secret on
// stdin, keyed like the lint's sites. Several tasks may share a key.
func stdinTasks(t *testing.T, root string) map[string][]map[string]any {
	t.Helper()
	found := map[string][]map[string]any{}
	err := filepath.WalkDir(filepath.Join(root, "playbooks"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || (filepath.Ext(p) != ".yml" && filepath.Ext(p) != ".yaml") {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		walkTaskMaps(loadYAML(t, p), func(task map[string]any) {
			if len(stdinSecrets(task)) > 0 {
				name, _ := task["name"].(string)
				key := filepath.ToSlash(rel) + "::" + name
				found[key] = append(found[key], task)
			}
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func requireAnsiblePlaybook(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
			t.Fatalf("required ansible-playbook not installed: %v", err)
		}
		t.Skipf("ansible-playbook not installed: %v", err)
	}
}

// fakeProgram is a program that records every call (stdin, arguments and
// KRB5CCNAME, numbered) under $FAKE_DIR, prints $FAKE_DIR/out and exits with
// the code in $FAKE_DIR/rc.
const fakeProgram = `#!/bin/sh
d="$FAKE_DIR"
n=$(($(cat "$d/count" 2>/dev/null || echo 0) + 1))
echo "$n" > "$d/count"
cat > "$d/stdin.$n"
printf '%s\n' "$@" > "$d/args.$n"
printf '%s' "$KRB5CCNAME" > "$d/ccname.$n"
[ -f "$d/out" ] && cat "$d/out"
exit "$(cat "$d/rc" 2>/dev/null || echo 0)"
`

// stdinRun is what one run of a task copy per password recorded.
type stdinRun struct {
	dir       string
	marker    string
	passwords []string
	res       ag82Run
}

// runStdinTask runs a copy of task per hostile password in one
// ansible-playbook with the program replaced by a fake. strip removes the
// task keys that depend on the play it came from (conditions, tags,
// privilege escalation); the secret, the stdin and the environment stay.
func runStdinTask(t *testing.T, task map[string]any, c stdinCase, program string, keepNoLog bool, rewrite func(map[string]any)) stdinRun {
	t.Helper()
	dir := t.TempDir()
	run := stdinRun{dir: dir, marker: filepath.Join(dir, "pwned")}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, program), []byte(fakeProgram), 0o755); err != nil {
		t.Fatal(err)
	}
	if c.output != "" {
		if err := os.WriteFile(filepath.Join(dir, "out"), []byte(c.output), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ccache := filepath.Join(dir, "krb5cc")
	vars := map[string]any{
		"ipa_realm": stdinRealm, "identity_admin_principal": "admin", "ipa_enroll_principal": "admin",
		"dns_fixture_domain": "ipa.pilot.internal", "audit_demo_user": "audituser", "sim_local_user": "simlocal",
		"transport_fixture_user_effective": "transportuser",
	}
	if c.ccacheVar != "" {
		vars[c.ccacheVar] = map[string]any{"path": ccache}
	}
	if c.ccacheString != "" {
		vars[c.ccacheString] = "FILE:" + ccache
	}
	var tasks []any
	for i, tmpl := range stdinHostilePasswords {
		password := tmpl
		if strings.Contains(tmpl, "%[1]s") {
			password = fmt.Sprintf(tmpl, run.marker)
		}
		run.passwords = append(run.passwords, password)
		cp := map[string]any{}
		for k, v := range task {
			switch k {
			case "when", "tags", "become", "become_user", "run_once", "delegate_to", "loop", "with_items":
				continue
			}
			cp[k] = v
		}
		if !keepNoLog {
			delete(cp, "no_log")
		}
		cp["name"] = fmt.Sprintf("%s [%d]", task["name"], i)
		taskVars := map[string]any{}
		if c.secretVars != nil {
			for k, v := range c.secretVars(unsafeString(password)) {
				taskVars[k] = v
			}
		} else {
			taskVars[c.secret] = unsafeString(password)
		}
		cp["vars"] = taskVars
		if rewrite != nil {
			rewrite(cp)
		}
		tasks = append(tasks, cp)
	}
	env := map[string]any{"PATH": bin + string(os.PathListSeparator) + os.Getenv("PATH"), "FAKE_DIR": dir}
	run.res = runGatewayTasks(t, dir, []any{map[string]any{
		"name": "run the task copies", "environment": env, "block": tasks,
	}}, vars, nil)
	return run
}

// TestRegression_FreeIPAKinitTasksPassPasswordUnchanged finds every task under
// playbooks/ that passes a secret on stdin and runs it with real
// ansible-playbook and a fake program (kinit, kadmin.local, ipa) that records
// its stdin, arguments and KRB5CCNAME. With a shell printf or echo (before
// cdcd39b for the forwarder task, before issue #118 for the others),
// `demo$pilot118_missing_suffix` reached kinit as `demo`, a backtick or $(...)
// ran as a command, and printf rewrote `%` and `\`. Each task gets hostile
// values; the exact bytes must reach stdin, no secret may reach the argument
// list (where expand_argument_vars would expand `$HOME` and /proc shows it),
// and nothing may run.
func TestRegression_FreeIPAKinitTasksPassPasswordUnchanged(t *testing.T) {
	requireAnsiblePlaybook(t)
	root := filepath.Join("..", "..")
	found := stdinTasks(t, root)
	for key := range found {
		if _, ok := stdinCases[key]; !ok {
			t.Errorf("%s passes a secret on stdin and has no row in stdinCases; add one so the runtime test covers it", key)
		}
	}
	for key, c := range stdinCases {
		if found[key] == nil {
			t.Errorf("stdinCases row %q matches no task that passes a secret on stdin; remove it", key)
		}
		if c.external != "" && !testFuncExists(t, c.external) {
			t.Errorf("%s: external test %s does not exist in this package", key, c.external)
		}
	}
	if t.Failed() {
		return
	}
	keys := make([]string, 0, len(stdinCases))
	for key := range stdinCases {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		c := stdinCases[key]
		if c.external != "" {
			continue
		}
		for n, task := range found[key] {
			t.Run(fmt.Sprintf("%s#%d", key, n), func(t *testing.T) {
				t.Parallel()
				checkStdinTask(t, task, c)
			})
		}
	}
}

// testFuncExists reports whether a Test function of that name is declared in
// this package's test files.
func testFuncExists(t *testing.T, name string) bool {
	t.Helper()
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	decl := regexp.MustCompile(`(?m)^func ` + regexp.QuoteMeta(name) + `\(`)
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if decl.Match(body) {
			return true
		}
	}
	return false
}

// checkStdinTask runs one task per hostile password and checks what the fake
// program received.
func checkStdinTask(t *testing.T, task map[string]any, c stdinCase) {
	t.Helper()
	if task["no_log"] != true {
		t.Fatalf("the task passes a secret on stdin and must keep no_log: true")
	}
	_, raw := secretTaskModule(task)
	program := path.Base(argvProgram(raw.(map[string]any)["argv"], taskVars(task), 0))
	if program == "" || program == "." {
		t.Fatalf("cannot tell which program the task runs")
	}
	run := runStdinTask(t, task, c, program, true, nil)
	if run.res.rc != 0 {
		// no_log hides the reason: run the synthetic values again without it.
		diag := runStdinTask(t, task, c, program, false, nil)
		t.Fatalf("ansible-playbook rc=%d failures=%v\nwithout no_log: %v\n%s", run.res.rc, run.res.failures, diag.res.failures, diag.res.raw)
	}
	for i, password := range run.passwords {
		stdin, err := os.ReadFile(filepath.Join(run.dir, fmt.Sprintf("stdin.%d", i+1)))
		if err != nil {
			t.Fatalf("value %d: the program did not run: %v", i, err)
		}
		want := strings.Repeat(password+"\n", c.stdinCopies)
		if string(stdin) != want {
			t.Errorf("value %d (%q): stdin = %q, want %q", i, password, stdin, want)
		}
		args, err := os.ReadFile(filepath.Join(run.dir, fmt.Sprintf("args.%d", i+1)))
		if err != nil {
			t.Fatal(err)
		}
		if got := string(args); got != strings.Join(c.args, "\n")+"\n" {
			t.Errorf("value %d (%q): args = %q, want %q", i, password, got, c.args)
		}
		if strings.Contains(string(args), password) {
			t.Errorf("value %d: the secret reached the argument list", i)
		}
		if c.ccacheVar != "" || c.ccacheString != "" {
			ccFile := filepath.Join(run.dir, fmt.Sprintf("ccname.%d", i+1))
			got, _ := os.ReadFile(ccFile)
			want := c.ccachePrefix + filepath.Join(run.dir, "krb5cc")
			if c.ccacheString != "" {
				want = "FILE:" + filepath.Join(run.dir, "krb5cc")
			}
			if string(got) != want {
				t.Errorf("value %d: KRB5CCNAME = %q, want the task's own cache %q", i, got, want)
			}
		}
	}
	if _, err := os.Stat(run.marker); err == nil {
		t.Error("a password ran a command")
	}
}

// TestRegression_StdinHarnessDetectsAShellSpelling proves the runtime oracle
// above fires: the same harness, fed the spelling this issue removed (a shell
// printf pipe into kinit), must report the changed bytes and the command that
// ran. Without it a harness that never compares anything would pass.
func TestRegression_StdinHarnessDetectsAShellSpelling(t *testing.T) {
	requireAnsiblePlaybook(t)
	c := stdinCases["playbooks/apply/freeipa-server-apply.yml::Kinit admin (for dnsconfig-mod)"]
	task := map[string]any{
		"name":                  "old spelling",
		"ansible.builtin.shell": map[string]any{"cmd": `printf %s "{{ ipa_admin_password }}" | kinit admin@{{ ipa_realm }}`},
	}
	// A quote in the value breaks the shell line and fails the task; that is
	// also a changed outcome, and ignore_errors lets the other copies run.
	run := runStdinTask(t, task, c, "kinit", true, func(cp map[string]any) { cp["ignore_errors"] = true })
	changed := 0
	for i, password := range run.passwords {
		stdin, err := os.ReadFile(filepath.Join(run.dir, fmt.Sprintf("stdin.%d", i+1)))
		if err != nil || (string(stdin) != password+"\n" && string(stdin) != password) {
			changed++
		}
	}
	if changed < 5 {
		t.Errorf("the shell spelling changed %d of %d values, want at least 5: the oracle would not notice it", changed, len(run.passwords))
	}
	if _, err := os.Stat(run.marker); err != nil {
		t.Error("the shell spelling did not run the injected command: the oracle would not notice it")
	}
}

// unsafeString marshals as a YAML !unsafe scalar, which Ansible never
// templates.
type unsafeString string

func (s unsafeString) MarshalYAML() (any, error) {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!unsafe", Value: string(s), Style: yaml.DoubleQuotedStyle}, nil
}
