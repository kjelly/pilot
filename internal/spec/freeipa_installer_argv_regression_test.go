package spec

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// Issue #359: the FreeIPA installers (ipa-server-install, ipa-replica-install,
// ipa-client-install) take the admin, Directory Manager or enrollment password
// only as an option, so it is an element of the argv of an
// ansible.builtin.command task. The module defaults expand_argument_vars to
// true, and run_command then applies os.path.expandvars and
// os.path.expanduser to every argv element: `$NAME` and `${NAME}` of any
// variable set in the module's environment, and a leading `~`, `~/` or
// `~user`, are replaced before exec. The installer was then given a different
// password than the one declared, enrolled the host with it, and nothing
// failed on the controller. (An unset name, `$$`, `$(...)` and backticks are
// left alone, and stdin is never expanded: ansible-core 2.19.2 and 2.20.1.)
//
// TestRegression_NoSecretInCommandText lets an installer carry a secret in
// argv only with expand_argument_vars: false and no_log: true. This test is
// its runtime counterpart, as TestRegression_FreeIPAKinitTasksPassPasswordUnchanged
// is for stdin: it finds every task whose argv carries a secret, with the
// lint's own finder (argvSecrets), runs the real task, extracted by name from
// the real playbook, with real ansible-playbook and a fake program named like
// the installer, and requires the argv the program received to be the argv
// Ansible rendered. The rendered argv comes from a preceding task that
// evaluates the same argv expression under the same vars, so no element
// position is written down here.
//
// What this does not do: run a real installer (the fake records its argv and
// does not read stdin), or look at /proc/<pid>/cmdline, which the flag does
// not hide.

// installerArgvEnvName is a variable the play's environment: sets, which
// expand_argument_vars expands like HOME or PATH.
const installerArgvEnvName = "PILOT_359_ENV"

// installerArgvPasswords are the secrets the runtime test hands every task
// that carries one in argv. %[1]s is a file the value would create if any
// part of it ran as a command.
var installerArgvPasswords = []string{
	// What expand_argument_vars rewrites: the variables HOME and PATH, a
	// variable of the play's environment, and a leading `~`, `~/` or `~root`
	// (which only changes an element that is the whole secret, such as the -p
	// and -a of ipa-server-install).
	"$HOME-",
	"${HOME}",
	"${PATH}",
	"x${" + installerArgvEnvName + "}y",
	"~",
	"~/",
	"~root",
	// Other bytes a password may hold, and several kinds at once (the last one).
	"two words",
	"a`touch %[1]s`b",
	"x$(touch %[1]s)y",
	`dq"dq`,
	"sq'sq",
	`back\slash`,
	`trailing\`,
	"50%s%d%%",
	"tab\there",
	"  spaced  ",
	"two\nlines",
	"{{ not_jinja }}",
	"all$HOME\"'\\%`id`$(id) \t end",
	// The control: an unset name, which the option does not touch either way.
	"demo$pilot359_unset_name",
}

// installerArgvExpanded are the values that differ from what Ansible rendered
// when expand_argument_vars is on and the task is the server installer (whose
// -p and -a are whole elements); installerArgvUntouched must reach the
// program unchanged either way.
var (
	installerArgvExpanded  = []string{"$HOME-", "${HOME}", "${PATH}", "x${" + installerArgvEnvName + "}y", "~", "~/", "~root"}
	installerArgvUntouched = []string{"two words", "x$(touch %[1]s)y", "{{ not_jinja }}", "demo$pilot359_unset_name", `back\slash`}
)

// argvSecretValue is how the test hands a secret to Ansible: as !unsafe, so
// that nothing templates it, except for `~`. Ansible's loader resolves the
// scalar of an !unsafe tag like an untagged one (ansible-core 2.19.2:
// `!unsafe "~"` and `!unsafe "null"` load as None), so !unsafe would turn that
// value into an empty one; a quoted `~` is a string and has nothing to template.
func argvSecretValue(password string) any {
	if password == "~" {
		return password
	}
	return unsafeString(password)
}

// installerArgvCase says how to run one installer task.
type installerArgvCase struct {
	// vars are the play variables the task's argv reads, other than the
	// secrets: the test merges the secrets into the task's own vars:.
	vars map[string]any
}

// installerArgvIPA is the realm, domain and addresses of the tasks below (RFC
// 5737 documentation addresses).
func installerArgvIPA(more map[string]any) map[string]any {
	vars := map[string]any{
		"ipa_realm": "IPA.PILOT.INTERNAL", "ipa_domain": "ipa.pilot.internal", "ipa_enroll_principal": "admin",
	}
	for k, v := range more {
		vars[k] = v
	}
	return vars
}

// installerArgvCases covers every task the lint finds that carries a secret
// in argv: TestRegression_FreeIPAInstallerArgvPassesPasswordUnchanged fails
// for a task with no row here and for a row whose task is gone.
var installerArgvCases = map[string]installerArgvCase{
	"playbooks/apply/freeipa-server-apply.yml::FreeIPA — run ipa-server-install (native; first run is 8–12 min)": {vars: installerArgvIPA(map[string]any{
		"ipa_server_ip": "192.0.2.10", "ipa_server_fqdn": "ipa1.ipa.pilot.internal",
		"ipa_setup_dns": true, "ipa_dns_forwarders_normalized": []any{"192.0.2.53"},
		"ipa_setup_ntp": true, "ipa_ntp_servers": []any{"192.0.2.123"},
	})},
	"playbooks/apply/freeipa-client-apply.yml::FreeIPA client — run ipa-client-install (enroll into {{ ipa_realm }})": {vars: installerArgvIPA(map[string]any{
		"freeipa_server_fqdns": []any{"ipa1.ipa.pilot.internal", "ipa2.ipa.pilot.internal"}, "ipa_client_fqdn": "client1.ipa.pilot.internal",
	})},
	"playbooks/apply/freeipa-server-replica-apply.yml::FreeIPA replica — step 1/2: ipa-client-install (enroll into {{ ipa_realm }})": {vars: installerArgvIPA(map[string]any{
		"ipa_server_fqdn": "ipa1.ipa.pilot.internal", "ipa_replica_fqdn": "ipa2.ipa.pilot.internal",
	})},
	"playbooks/apply/freeipa-server-replica-apply.yml::FreeIPA replica — step 2/2: ipa-replica-install (promote; first run 8-12 min)": {vars: installerArgvIPA(map[string]any{
		"ipa_replica_setup_ca": true, "ipa_setup_dns": true, "ipa_dns_forwarder_argv": []any{"--forwarder=192.0.2.53"},
	})},
	"playbooks/apply/freeipa-realm-replacement-apply.yml::Realm replacement — enroll client in the new realm": {vars: map[string]any{
		"freeipa_realm_replacement_new_server_fqdn": "ipa1.new.pilot.internal", "freeipa_realm_replacement_new_domain": "new.pilot.internal",
		"freeipa_realm_replacement_new_realm": "NEW.PILOT.INTERNAL", "freeipa_realm_replacement_client_fqdn": "client1.new.pilot.internal",
	}},
}

// installerArgvServerKey is the task the self-test runs without the flag.
const installerArgvServerKey = "playbooks/apply/freeipa-server-apply.yml::FreeIPA — run ipa-server-install (native; first run is 8–12 min)"

// fakeArgvProgram records every call under $FAKE_DIR, numbered: its arguments
// as the NUL-terminated bytes it received (so quotes, spaces and newlines
// stay visible). It does not read stdin and exits 0.
const fakeArgvProgram = `#!/bin/sh
d="$FAKE_DIR"
n=$(($(cat "$d/count" 2>/dev/null || echo 0) + 1))
echo "$n" > "$d/count"
printf '%s\0' "$@" > "$d/args.$n"
exit 0
`

// cloneYAMLValue returns a deep copy of a decoded YAML value, so that the
// runtime test can change a copy of a task without touching the task other
// tests read.
func cloneYAMLValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = cloneYAMLValue(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = cloneYAMLValue(e)
		}
		return out
	default:
		return v
	}
}

// commandModuleKey returns the key a task spells its command module with.
func commandModuleKey(task map[string]any) string {
	for _, m := range secretModules {
		for _, key := range []string{m, "ansible.builtin." + m, "ansible.legacy." + m} {
			if _, ok := task[key]; ok {
				return key
			}
		}
	}
	return ""
}

// installerArgvRun is what one run of a task copy per password recorded.
type installerArgvRun struct {
	dir       string
	marker    string
	passwords []string
	res       ag82Run
}

// installerArgvOutcome is the argv Ansible rendered for one password and the
// arguments the program received.
type installerArgvOutcome struct {
	password           string
	rendered, received []string
}

// runInstallerArgvTask runs a copy of the task per password in one
// ansible-playbook, each after a task that renders the same argv expression
// under the same vars, with the installer replaced by a fake. The secrets are
// merged into the task's own vars: (the server and replica tasks build their
// argv there). creates: points at a path that does not exist; the keys that
// depend on the play are dropped. rewrite changes each copy of the task and
// its module mapping (the self-test removes the flag).
func runInstallerArgvTask(t *testing.T, task map[string]any, c installerArgvCase, program string, keepNoLog bool, rewrite func(cp, module map[string]any)) installerArgvRun {
	t.Helper()
	dir := t.TempDir()
	run := installerArgvRun{dir: dir, marker: filepath.Join(dir, "pwned")}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, program), []byte(fakeArgvProgram), 0o755); err != nil {
		t.Fatal(err)
	}
	key := commandModuleKey(task)
	if key == "" {
		t.Fatal("the task has no command module")
	}
	secrets := argvSecrets(task)
	var tasks []any
	for i, tmpl := range installerArgvPasswords {
		password := tmpl
		if strings.Contains(tmpl, "%[1]s") {
			password = fmt.Sprintf(tmpl, run.marker)
		}
		run.passwords = append(run.passwords, password)

		cp := map[string]any{}
		for k, v := range task {
			if slices.Contains(playScopedTaskKeys, k) {
				continue
			}
			cp[k] = cloneYAMLValue(v)
		}
		if !keepNoLog {
			delete(cp, "no_log")
		}
		cp["name"] = fmt.Sprintf("%s [%d]", task["name"], i)
		taskVars := map[string]any{}
		if own, ok := cp["vars"].(map[string]any); ok {
			for k, v := range own {
				taskVars[k] = v
			}
		}
		for _, s := range secrets {
			taskVars[s] = argvSecretValue(password)
		}
		cp["vars"] = taskVars
		module, _ := cp[key].(map[string]any)
		argv := cloneYAMLValue(module["argv"])
		module["creates"] = filepath.Join(dir, "no-such-marker")
		if rewrite != nil {
			rewrite(cp, module)
		}

		captureVars := map[string]any{"pilot_359_rendered_argv": argv}
		for k, v := range taskVars {
			captureVars[k] = v
		}
		tasks = append(tasks,
			map[string]any{
				"name": fmt.Sprintf("render the argv [%d]", i), "no_log": true, "vars": captureVars,
				"ansible.builtin.copy": map[string]any{
					"content": "{{ pilot_359_rendered_argv | to_json }}",
					"dest":    filepath.Join(dir, fmt.Sprintf("rendered.%d.json", i)),
				},
			},
			cp)
	}
	vars := installerArgvIPA(nil)
	for k, v := range c.vars {
		vars[k] = v
	}
	env := map[string]any{"PATH": bin + string(os.PathListSeparator) + os.Getenv("PATH"), "FAKE_DIR": dir, installerArgvEnvName: "from-the-play-environment"}
	run.res = runGatewayTasks(t, dir, []any{map[string]any{
		"name": "run the task copies", "environment": env, "block": tasks,
	}}, vars, nil)
	return run
}

// outcomes reads, per password, the argv Ansible rendered and the argv the
// fake installer received.
func (run installerArgvRun) outcomes(t *testing.T) []installerArgvOutcome {
	t.Helper()
	var out []installerArgvOutcome
	for i, password := range run.passwords {
		o := installerArgvOutcome{password: password}
		body, err := os.ReadFile(filepath.Join(run.dir, fmt.Sprintf("rendered.%d.json", i)))
		if err != nil {
			t.Fatalf("value %d (%q): the argv was not rendered: %v", i, password, err)
		}
		if err := json.Unmarshal(body, &o.rendered); err != nil {
			t.Fatalf("value %d (%q): the rendered argv is not a list of strings: %v\n%s", i, password, err, body)
		}
		got, err := os.ReadFile(filepath.Join(run.dir, fmt.Sprintf("args.%d", i+1)))
		if err != nil {
			t.Fatalf("value %d (%q): the installer did not run: %v", i, password, err)
		}
		if len(got) > 0 {
			if got[len(got)-1] != 0 {
				t.Fatalf("value %d (%q): the recorded argv does not end in NUL: %q", i, password, got)
			}
			o.received = strings.Split(string(got[:len(got)-1]), "\x00")
		}
		out = append(out, o)
	}
	return out
}

// changed reports whether the installer got other arguments than Ansible
// rendered after the program name (the fake records "$@", which has no
// argv[0]).
func (o installerArgvOutcome) changed() bool {
	return len(o.rendered) == 0 || !slices.Equal(o.rendered[1:], o.received)
}

// carries returns how many rendered elements contain the password.
func (o installerArgvOutcome) carries() int {
	n := 0
	for _, e := range o.rendered {
		if strings.Contains(e, o.password) {
			n++
		}
	}
	return n
}

// TestRegression_FreeIPAInstallerArgvPassesPasswordUnchanged finds every task
// under playbooks/ that carries a secret in argv and runs it with real
// ansible-playbook and a fake installer. Before issue #359 the five installer
// tasks had no expand_argument_vars: false, so `$HOME-`, `${PATH}`, a variable
// of the play's environment and a leading `~` reached the installer as
// something else, and the host was enrolled with a password nobody declared.
// For each value the argv the fake received must equal the argv Ansible
// rendered, the secret must be in the rendered argv, and nothing may run.
func TestRegression_FreeIPAInstallerArgvPassesPasswordUnchanged(t *testing.T) {
	requireAnsiblePlaybook(t)
	found := tasksPassingSecrets(t, filepath.Join("..", ".."), argvSecrets)
	for key, tasks := range found {
		if _, ok := installerArgvCases[key]; !ok {
			t.Errorf("%s carries a secret in argv and has no row in installerArgvCases; add one so the runtime test covers it", key)
		}
		for _, task := range tasks {
			if !isInstallerArgv(task) {
				t.Errorf("%s carries a secret in argv and is not a FreeIPA installer; TestRegression_NoSecretInCommandText flags it (pass the secret on stdin)", key)
			}
		}
	}
	for key := range installerArgvCases {
		if found[key] == nil {
			t.Errorf("installerArgvCases row %q matches no task that carries a secret in argv; remove it", key)
		}
	}
	if t.Failed() {
		return
	}
	keys := make([]string, 0, len(installerArgvCases))
	for key := range installerArgvCases {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		c := installerArgvCases[key]
		for n, task := range found[key] {
			t.Run(fmt.Sprintf("%s#%d", key, n), func(t *testing.T) {
				t.Parallel()
				checkInstallerArgvTask(t, task, c)
			})
		}
	}
}

// installerProgramOf is the program the task's argv starts with.
func installerProgramOf(t *testing.T, task map[string]any) string {
	t.Helper()
	argv, _ := commandArgv(task)
	program := path.Base(argvProgram(argv, taskVars(task), 0))
	if program == "" || program == "." {
		t.Fatalf("cannot tell which program the task runs")
	}
	return program
}

// checkInstallerArgvTask runs one task per password and checks what the fake
// installer received.
func checkInstallerArgvTask(t *testing.T, task map[string]any, c installerArgvCase) {
	t.Helper()
	if task["no_log"] != true {
		t.Fatalf("the task carries a secret in argv and must keep no_log: true")
	}
	program := installerProgramOf(t, task)
	run := runInstallerArgvTask(t, task, c, program, true, nil)
	if run.res.rc != 0 {
		// no_log hides the reason: run the synthetic values again without it.
		diag := runInstallerArgvTask(t, task, c, program, false, nil)
		t.Fatalf("ansible-playbook rc=%d failures=%v\nwithout no_log: %v\n%s", run.res.rc, run.res.failures, diag.res.failures, diag.res.raw)
	}
	for i, o := range run.outcomes(t) {
		if o.changed() {
			t.Errorf("value %d (%q): the installer received %q, Ansible rendered %q", i, o.password, o.received, o.rendered)
		}
		if o.carries() == 0 {
			t.Errorf("value %d (%q): the rendered argv does not carry the secret, so the comparison proves nothing: %q", i, o.password, o.rendered)
		}
	}
	if _, err := os.Stat(run.marker); err == nil {
		t.Error("a password ran a command")
	}
}

// TestRegression_InstallerArgvHarnessDetectsExpansion proves the runtime oracle
// above fires: the same harness, run on the server installer with the flag
// removed (the spelling issue #359 fixed), must report the variables and the
// leading `~` that expand_argument_vars rewrites, and must not report the
// values it leaves alone (an unset name, `$(...)`, a Jinja-looking string).
// Without it a harness that never compares anything would pass.
func TestRegression_InstallerArgvHarnessDetectsExpansion(t *testing.T) {
	requireAnsiblePlaybook(t)
	found := tasksPassingSecrets(t, filepath.Join("..", ".."), argvSecrets)
	tasks := found[installerArgvServerKey]
	if len(tasks) != 1 {
		t.Fatalf("want exactly one task %q, found %d", installerArgvServerKey, len(tasks))
	}
	task := tasks[0]
	if !expandArgumentVarsDisabled(task) {
		t.Fatalf("the task must set expand_argument_vars: false for this test to mean anything")
	}
	run := runInstallerArgvTask(t, task, installerArgvCases[installerArgvServerKey], installerProgramOf(t, task), true,
		func(cp, module map[string]any) {
			delete(module, "expand_argument_vars")
			if args, ok := cp["args"].(map[string]any); ok {
				delete(args, "expand_argument_vars")
			}
		})
	if run.res.rc != 0 {
		t.Fatalf("ansible-playbook rc=%d failures=%v", run.res.rc, run.res.failures)
	}
	outcomes := run.outcomes(t)
	changed := map[string]bool{}
	for _, o := range outcomes {
		changed[o.password] = o.changed()
	}
	for _, v := range installerArgvExpanded {
		if !changed[v] {
			t.Errorf("without the flag, %q reached the installer as rendered: the oracle would not notice expand_argument_vars", v)
		}
	}
	for _, tmpl := range installerArgvUntouched {
		v := tmpl
		if strings.Contains(tmpl, "%[1]s") {
			v = fmt.Sprintf(tmpl, run.marker)
		}
		if changed[v] {
			t.Errorf("%q is left alone by expand_argument_vars but the oracle reports it changed", v)
		}
	}
	if _, err := os.Stat(run.marker); err == nil {
		t.Error("a password ran a command")
	}
}
