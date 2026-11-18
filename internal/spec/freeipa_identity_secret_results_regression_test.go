package spec

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Issues #142 and #216: what Ansible prints of a task result must never carry
// a credential of the roster. `-v` prints the result of every task, a failed
// loop iteration prints its whole `item` even at the default verbosity
// (`loop_control.label` only changes the prefix), a skipped iteration prints
// its `item`, `set_fact` prints its facts, and a JSON stdout callback or
// ANSIBLE_LOG_PATH keep all of it. Two tasks of freeipa-identity-apply.yml put
// a credential there:
//
//   - #142: "Fill canonical roster freeipa.server for this reconcile" sets the
//     WHOLE roster as a fact when the roster omits freeipa.server, so its
//     result carries freeipa.admin.password and every users[].password.initial.
//   - #216: the loops over the normalized users (ipa_active_users) print each
//     user, and the user carries password, force_password and
//     preserve_existing; "Select active identity objects" printed the list.
//
// The two tests below run the WHOLE real playbook in one real ansible-playbook
// process. Only the FreeIPA boundary is faked: `ipa`, `kinit`, `kdestroy`,
// `hostname`, the SSSD tools and the ipalib RPC the password task calls. The
// secrets are random per run (never a committed literal), and each run is read
// four ways: the plain `-v` (and `-vvv`) stdout, ANSIBLE_LOG_PATH, and the JSON
// callback, which also attributes a leak to the task that printed it and shows
// that the task under test really ran. Each test has its own symptom: the
// first needs a roster without freeipa.server, the second one with it.

// identityResultsFQDN is what the fake `hostname -f` prints: the FQDN the
// playbook fills into a roster that omits freeipa.server.
const identityResultsFQDN = "ipa1.pilot-test.internal"

// identityResultsIPA fakes the FreeIPA server the way the other identity
// regressions do, answering the way FreeIPA 4.13.4 does for an empty
// directory: every listing says it found nothing, a group-show of Pilot's
// history marker says "not found" until the marker was added, and user-del says
// "not found". `user-mod --sshpubkey=` records the keys for the fake
// sss_ssh_authorizedkeys, so the playbook's own SSH-key propagation gate
// converges. A call is logged one line per call; the log never has a secret
// (every password goes through stdin or the ipalib fake).
const identityResultsIPA = `#!/bin/sh
echo "$*" >> "$FAKE_IPA_LOG"
D="$FAKE_IPA_DIR"
case "$1" in
  user-find|group-find|hbacrule-find|sudorule-find|hostgroup-find|netgroup-find|host-find|sudocmd-find|sudocmdgroup-find|hbacsvc-find|pwpolicy-find|automountlocation-find)
    echo "Number of entries returned 0"; exit 0;;
  user-add)
    if [ -n "$FAKE_IPA_FAIL_USERADD" ]; then echo "ipa: ERROR: $FAKE_IPA_FAIL_USERADD" >&2; exit 1; fi
    exit 0;;
  user-mod)
    seen=0; : > "$D/.keys-new"
    for a in "$@"; do case "$a" in --sshpubkey=*) seen=1; k="${a#--sshpubkey=}"; [ -n "$k" ] && printf '%s\n' "$k" >> "$D/.keys-new";; esac; done
    if [ $seen = 1 ]; then mv "$D/.keys-new" "$D/keys-$2"; fi
    exit 0;;
  user-show) echo "  User login: $2"; exit 0;;
  group-add)
    for a in "$@"; do case "$a" in --desc=*) printf '%s\n' "${a#--desc=}" > "$D/g-$2";; esac; done; exit 0;;
  group-show)
    case "$2" in pilot-internal-history-*)
      if [ -f "$D/g-$2" ]; then echo "  description: $(cat "$D/g-$2")"; exit 0; else echo "ipa: ERROR: $2: group not found" >&2; exit 2; fi;;
    esac
    echo "  Group name: $2"; exit 0;;
  user-del) echo "ipa: ERROR: $2: user not found" >&2; exit 2;;
  *) exit 0;;
esac
`

// identityResultsHarness is the fake FreeIPA the runs share; each run gets
// its own state directory.
type identityResultsHarness struct {
	bin  string
	root string
	runs int
}

func newIdentityResultsHarness(t *testing.T) *identityResultsHarness {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
			t.Fatalf("required ansible-playbook not installed: %v", err)
		}
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	h := &identityResultsHarness{bin: filepath.Join(t.TempDir(), "bin"), root: t.TempDir()}
	if err := os.Mkdir(h.bin, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, script := range map[string]string{
		"ipa": identityResultsIPA,
		// kinit records what the playbook feeds it, so a run can prove the
		// admin password reached it unchanged.
		"kinit":                  "#!/bin/sh\nprintf '%s ' \"$@\" >> \"$FAKE_KINIT_LOG\"; cat >> \"$FAKE_KINIT_LOG\"; echo >> \"$FAKE_KINIT_LOG\"\nexit 0\n",
		"kdestroy":               "#!/bin/sh\nexit 0\n",
		"hostname":               "#!/bin/sh\necho " + identityResultsFQDN + "\n",
		"sss_cache":              "#!/bin/sh\nexit 0\n",
		"sss_ssh_authorizedkeys": "#!/bin/sh\ncat \"$FAKE_IPA_DIR/keys-$3\" 2>/dev/null\nexit 0\n",
	} {
		if err := os.WriteFile(filepath.Join(h.bin, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// The ipalib the password task imports; it logs the principal and the
	// password it was handed, which is how a run proves the password reached
	// FreeIPA unchanged.
	fakeIdentityPasswordAPI(t, h.bin)
	return h
}

// identitySentinel is a random secret: letters and digits only, so that no
// JSON or shell escaping can hide it from a substring search.
func identitySentinel(t *testing.T, label string) string {
	t.Helper()
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "Sx" + label + "Q" + hex.EncodeToString(b)
}

// identitySSHKey is a well-formed ed25519 public key (the SSH-key journal
// parses the wire format) with random key material; a public key is no secret.
func identitySSHKey(t *testing.T, comment string) string {
	t.Helper()
	blob := append([]byte{0, 0, 0, 11}, []byte("ssh-ed25519")...)
	blob = append(blob, 0, 0, 0, 32)
	material := make([]byte, 32)
	if _, err := rand.Read(material); err != nil {
		t.Fatal(err)
	}
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(append(blob, material...)) + " " + comment
}

// identityResultsRoster is the canonical roster the runs apply. withServer
// false omits freeipa.server (issue #142's trigger), and every user carries a
// secret initial password: alice has an SSH key, bob is disabled, carol is to
// be deleted.
type identityResultsRoster struct {
	withServer bool
	secrets    map[string]string // label -> value
	keys       map[string]string // user -> public key
}

func newIdentityResultsRoster(t *testing.T, withServer bool) identityResultsRoster {
	t.Helper()
	r := identityResultsRoster{withServer: withServer, secrets: map[string]string{}, keys: map[string]string{}}
	for _, label := range []string{"RosterAdmin", "VaultAdmin", "Alice", "Bob", "Carol"} {
		r.secrets[label] = identitySentinel(t, label)
	}
	r.keys["alice"] = identitySSHKey(t, "alice")
	return r
}

func (r identityResultsRoster) file(t *testing.T, dir string) string {
	t.Helper()
	freeipa := map[string]any{"admin": map[string]any{"principal": "admin", "password": r.secrets["RosterAdmin"]}}
	if r.withServer {
		freeipa["server"] = identityResultsFQDN
	}
	doc := map[string]any{
		"schema_version": 3,
		"freeipa":        freeipa,
		"users": []any{
			map[string]any{"name": "alice", "first": "Alice", "last": "Example", "enabled": true,
				"password": map[string]any{"initial": r.secrets["Alice"], "force_change": true, "preserve_existing": true},
				"ssh_keys": map[string]any{"authoritative": true, "values": []any{r.keys["alice"]}}},
			map[string]any{"name": "bob", "first": "Bob", "last": "Example", "enabled": false,
				"password": map[string]any{"initial": r.secrets["Bob"]}},
			map[string]any{"name": "carol", "state": "absent",
				"password": map[string]any{"initial": r.secrets["Carol"]}},
		},
		"groups": []any{
			map[string]any{"name": "team-a", "category": "team",
				"membership": map[string]any{"authoritative": true, "users": []any{"alice"}}},
		},
	}
	path := filepath.Join(dir, "roster.yaml")
	body, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// identityRunOptions is one ansible-playbook run of the whole playbook.
type identityRunOptions struct {
	vars        map[string]any // -e @file; becomes, ipa_admin_password... are added
	verbosity   string         // "", "-v", "-vvv"
	json        bool           // ANSIBLE_STDOUT_CALLBACK=json instead of the default callback
	failUserAdd string         // `ipa user-add` fails with this reason
}

type identityRun struct {
	rc       int
	stdout   string
	stderr   string
	log      string // ANSIBLE_LOG_PATH
	tasks    []identityTask
	ipaCalls []string
	passwd   []identityPasswordCall
	kinit    string
}

// identityTask is a task of the JSON callback's output with its result on the
// one host.
type identityTask struct {
	name   string
	result map[string]any
}

func (h *identityResultsHarness) run(t *testing.T, opts identityRunOptions) identityRun {
	t.Helper()
	h.runs++
	dir := filepath.Join(h.root, fmt.Sprintf("run-%d", h.runs))
	if err := os.MkdirAll(filepath.Join(dir, "ipa"), 0o700); err != nil {
		t.Fatal(err)
	}
	vars := map[string]any{
		// The test runs unprivileged: the playbook's become tasks write
		// the SSH-key journal, which the test keeps in its own directory.
		"ansible_become":                    false,
		"ipa_identity_ssh_cache_state_file": filepath.Join(dir, "ssh-cache.json"),
	}
	for k, v := range opts.vars {
		vars[k] = v
	}
	varsFile := filepath.Join(dir, "vars.yml")
	body, err := yaml.Marshal(vars)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(varsFile, body, 0o600); err != nil {
		t.Fatal(err)
	}
	playbook, err := filepath.Abs(identityApplyPath)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"-i", "localhost,", "-c", "local", "-e", "target_group=localhost", "-e", "@" + varsFile}
	if opts.verbosity != "" {
		args = append(args, opts.verbosity)
	}
	args = append(args, playbook)
	callback := "default"
	if opts.json {
		callback = "json"
	}
	logPath := filepath.Join(dir, "ansible.log")
	cmd := exec.Command("ansible-playbook", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"PATH="+h.bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"ANSIBLE_STDOUT_CALLBACK="+callback, "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOG_PATH="+logPath,
		"ANSIBLE_LOCALHOST_WARNING=False", "ANSIBLE_INVENTORY_UNPARSED_WARNING=False",
		"ANSIBLE_PYTHON_INTERPRETER=/usr/bin/python3",
		"FAKE_IPA_LOG="+filepath.Join(dir, "ipa.log"), "FAKE_IPA_DIR="+filepath.Join(dir, "ipa"),
		"FAKE_KINIT_LOG="+filepath.Join(dir, "kinit.log"),
		"IDENTITY_API_CALLS="+filepath.Join(dir, "api-calls"), "IDENTITY_API_DISCONNECT="+filepath.Join(dir, "disconnects"),
		"FAKE_IPA_FAIL_USERADD="+opts.failUserAdd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	run := identityRun{}
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("ansible-playbook did not run: %v", err)
		}
		run.rc = ee.ExitCode()
	}
	run.stdout, run.stderr = stdout.String(), stderr.String()
	if raw, err := os.ReadFile(logPath); err == nil {
		run.log = string(raw)
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "ipa.log")); err == nil {
		run.ipaCalls = strings.Split(strings.TrimSpace(string(raw)), "\n")
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "kinit.log")); err == nil {
		run.kinit = string(raw)
	}
	run.passwd = identityPasswordCalls(t, dir)
	if opts.json {
		run.tasks = parseIdentityJSON(t, run.stdout)
	}
	return run
}

// parseIdentityJSON reads the JSON callback's output.
func parseIdentityJSON(t *testing.T, out string) []identityTask {
	t.Helper()
	var doc struct {
		Plays []struct {
			Tasks []struct {
				Task  struct{ Name string }     `json:"task"`
				Hosts map[string]map[string]any `json:"hosts"`
			} `json:"tasks"`
		} `json:"plays"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("parse the JSON callback output: %v\n%.2000s", err, out)
	}
	var tasks []identityTask
	for _, p := range doc.Plays {
		for _, task := range p.Tasks {
			result, ok := task.Hosts["localhost"]
			if !ok {
				continue
			}
			tasks = append(tasks, identityTask{name: task.Task.Name, result: result})
		}
	}
	return tasks
}

// task returns the result of the named task; fatal when the task did not run
// at all (a task that was skipped still has a result).
func (r identityRun) task(t *testing.T, name string) map[string]any {
	t.Helper()
	for _, task := range r.tasks {
		if task.name == name {
			return task.result
		}
	}
	t.Fatalf("task %q is not in the JSON callback output", name)
	return nil
}

// ran reports whether the named task ran at least once on the host: not
// skipped, and for a loop at least one iteration that was not skipped.
func (r identityRun) ran(t *testing.T, name string) bool {
	t.Helper()
	result := r.task(t, name)
	if skipped, _ := result["skipped"].(bool); skipped {
		return false
	}
	results, loop := result["results"].([]any)
	if !loop {
		return true
	}
	for _, each := range results {
		if m, ok := each.(map[string]any); ok {
			if skipped, _ := m["skipped"].(bool); !skipped {
				return true
			}
		}
	}
	return false
}

// iterated returns the `item` names of the iterations of a loop task that were
// not skipped. A no_log task has no item to show.
func (r identityRun) iterated(t *testing.T, name string) []string {
	t.Helper()
	var names []string
	results, _ := r.task(t, name)["results"].([]any)
	for _, each := range results {
		m, _ := each.(map[string]any)
		if skipped, _ := m["skipped"].(bool); skipped {
			continue
		}
		switch item := m["item"].(type) {
		case map[string]any:
			names = append(names, fmt.Sprint(item["name"]))
		case []any: // `subelements`: [user, group]
			if user, ok := item[0].(map[string]any); ok {
				names = append(names, fmt.Sprint(user["name"]))
			}
		}
	}
	return names
}

// identityLeaks lists the secrets (by label) found in text.
func identityLeaks(text string, secrets map[string]string) []string {
	var found []string
	for label, secret := range secrets {
		if strings.Contains(text, secret) {
			found = append(found, label)
		}
	}
	sort.Strings(found)
	return found
}

// leakingTasks names the tasks whose printed result carries a secret, so a
// failure says which task to fix.
func (r identityRun) leakingTasks(secrets map[string]string) []string {
	var names []string
	if len(r.tasks) > 0 {
		for _, task := range r.tasks {
			body, _ := json.Marshal(task.result)
			if len(identityLeaks(string(body), secrets)) > 0 {
				names = append(names, task.name)
			}
		}
		return names
	}
	for _, block := range strings.Split(r.stdout, "\nTASK [") {
		if len(identityLeaks(block, secrets)) == 0 {
			continue
		}
		names = append(names, "TASK ["+strings.SplitN(block, "]", 2)[0])
	}
	return names
}

// taskOutput is what one stream printed under the named task: the text between
// its "TASK [name]" line and the next task, or for the JSON callback the task's
// result. Empty when the task was not printed at all.
func (r identityRun) taskOutput(stream, name string) string {
	if len(r.tasks) > 0 && stream == "stdout" {
		for _, task := range r.tasks {
			if task.name == name {
				body, _ := json.Marshal(task.result)
				return string(body)
			}
		}
		return ""
	}
	text := r.stdout
	if stream == "ANSIBLE_LOG_PATH" {
		text = r.log
	}
	for _, chunk := range strings.Split(text, "TASK [")[1:] {
		if strings.HasPrefix(chunk, name+"]") {
			return chunk
		}
	}
	return ""
}

// assertNoSecrets fails when anything Ansible printed carries a secret.
func (r identityRun) assertNoSecrets(t *testing.T, what string, secrets map[string]string) {
	t.Helper()
	for stream, text := range map[string]string{"stdout": r.stdout, "stderr": r.stderr, "ANSIBLE_LOG_PATH": r.log} {
		if leaked := identityLeaks(text, secrets); len(leaked) > 0 {
			t.Errorf("%s: %s carries the secret of %v; printed by %v", what, stream, leaked, r.leakingTasks(secrets))
		}
	}
}

// requireHealthy fails unless the run converged.
func (r identityRun) requireHealthy(t *testing.T, what string) {
	t.Helper()
	if r.rc != 0 {
		t.Fatalf("%s: rc=%d\n%.4000s\n%.2000s", what, r.rc, r.stdout, r.stderr)
	}
}

// vars are the extra vars of a run against a roster file: the vault admin
// password is outside the roster, like main.yaml's.
func (r identityResultsRoster) vars(file string) map[string]any {
	return map[string]any{"freeipa_roster_file": file, "ipa_admin_password": r.secrets["VaultAdmin"]}
}

// requireLeakScanSees proves the leak scan can see what it looks for: a scan
// that cannot find a secret in text that holds it proves nothing.
func requireLeakScanSees(t *testing.T, secrets map[string]string) {
	t.Helper()
	for label, secret := range secrets {
		if got := identityLeaks("prefix "+secret+" suffix", secrets); !slices.Contains(got, label) {
			t.Fatalf("the leak scan does not see the secret of %s", label)
		}
	}
}

// TestRegression_IdentitySecretFillResultStaysOutOfOutput is issue #142: a
// roster without freeipa.server makes the playbook fill it in with a set_fact
// of the whole roster. Run at -v, with a JSON callback and into
// ANSIBLE_LOG_PATH, the result of that task must not carry the roster's admin
// password or a user's initial password, and the filled roster must still
// reconcile exactly as a roster that names the same server does.
func TestRegression_IdentitySecretFillResultStaysOutOfOutput(t *testing.T) {
	h := newIdentityResultsHarness(t)
	roster := newIdentityResultsRoster(t, false)
	requireLeakScanSees(t, roster.secrets)
	const fill = "Fill canonical roster freeipa.server for this reconcile"
	vars := roster.vars(roster.file(t, t.TempDir()))
	admin := map[string]string{"RosterAdmin": roster.secrets["RosterAdmin"], "VaultAdmin": roster.secrets["VaultAdmin"]}

	// The same roster naming the server the fake `hostname -f` prints: what
	// the filled roster must reconcile like.
	named := newIdentityResultsRoster(t, true)
	named.secrets, named.keys = roster.secrets, roster.keys
	reference := h.run(t, identityRunOptions{vars: named.vars(named.file(t, t.TempDir())), json: true})
	reference.requireHealthy(t, "reference run (freeipa.server named)")
	if reference.ran(t, fill) {
		t.Fatal("the reference run filled the server too: it must name it itself")
	}
	if len(reference.passwd) != 2 {
		t.Fatalf("the reference run must set the passwords of alice and bob, got %d calls", len(reference.passwd))
	}

	for _, mode := range []struct {
		name string
		opts identityRunOptions
	}{
		{"-v", identityRunOptions{verbosity: "-v"}},
		{"json callback", identityRunOptions{json: true}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			mode.opts.vars = vars
			run := h.run(t, mode.opts)
			run.requireHealthy(t, mode.name)
			// The admin passwords are printed by no other task. The users'
			// initial passwords are also what the loops of #216 print, so
			// they are read in what the fill task itself printed.
			run.assertNoSecrets(t, mode.name, admin)
			streams := []string{"stdout", "ANSIBLE_LOG_PATH"}
			if mode.opts.json {
				streams = streams[:1] // the log of the JSON callback is one document
			}
			for _, stream := range streams {
				out := run.taskOutput(stream, fill)
				if out == "" {
					t.Fatalf("%s: the fill task is not in the %s", mode.name, stream)
				}
				if leaked := identityLeaks(out, roster.secrets); len(leaked) > 0 {
					t.Errorf("%s: the fill task printed the secret of %v to %s", mode.name, leaked, stream)
				}
			}

			// Filling the server changes nothing else: the same FreeIPA
			// calls, the same passwords reaching the password API, and the
			// same admin password reaching kinit as for the roster that
			// names the server.
			if !slices.Equal(run.ipaCalls, reference.ipaCalls) {
				t.Errorf("ipa calls differ from the roster that names the server:\n got %q\nwant %q", run.ipaCalls, reference.ipaCalls)
			}
			sameCall := func(a, b identityPasswordCall) bool { return a.Principal == b.Principal && a.Password == b.Password }
			if !slices.EqualFunc(run.passwd, reference.passwd, sameCall) {
				t.Errorf("password API calls differ from the roster that names the server")
			}
			if run.kinit != reference.kinit || !strings.Contains(run.kinit, roster.secrets["VaultAdmin"]) {
				t.Errorf("kinit was not fed the admin password unchanged")
			}

			if !mode.opts.json {
				return
			}
			// The task under test really ran: it was not skipped, and its
			// result is the no_log placeholder, not the roster.
			if !run.ran(t, fill) {
				t.Fatalf("the fill task was skipped, so this run proves nothing about it")
			}
			result := run.task(t, fill)
			if result["censored"] == nil || result["ansible_facts"] != nil {
				t.Fatalf("the fill task printed its facts: %v", result)
			}
			if got := run.task(t, "Detect FreeIPA server FQDN when roster omits freeipa.server")["stdout"]; got != identityResultsFQDN {
				t.Fatalf("the detection did not run: %v", got)
			}
			if !run.ran(t, "Gate: canonical roster declares the FreeIPA server") {
				t.Fatal("the gate that needs the filled server did not run")
			}
		})
	}
}

// TestRegression_IdentitySecretUserLoopsStayOutOfOutput is issue #216: the
// tasks that loop over the normalized users printed each user, password
// included. The roster here names freeipa.server, so the fill task of #142
// is skipped and cannot be the source. Canonical and legacy (`-e ipa_users`)
// users are run at -v, -vvv, with a JSON callback and into ANSIBLE_LOG_PATH; a
// failing loop iteration shows its reason and the user at the default
// verbosity, but never the password; and the password still reaches FreeIPA
// unchanged.
func TestRegression_IdentitySecretUserLoopsStayOutOfOutput(t *testing.T) {
	h := newIdentityResultsHarness(t)
	roster := newIdentityResultsRoster(t, true)
	requireLeakScanSees(t, roster.secrets)
	file := roster.file(t, t.TempDir())
	vars := roster.vars(file)
	secretKeys := []string{"password", "force_password", "preserve_existing"}

	for _, mode := range []struct {
		name string
		opts identityRunOptions
	}{
		{"-v", identityRunOptions{verbosity: "-v"}},
		{"-vvv", identityRunOptions{verbosity: "-vvv"}},
		{"json callback", identityRunOptions{json: true}},
	} {
		t.Run("canonical roster "+mode.name, func(t *testing.T) {
			mode.opts.vars = vars
			run := h.run(t, mode.opts)
			run.requireHealthy(t, mode.name)
			run.assertNoSecrets(t, mode.name, roster.secrets)
			// Every credential reached the password API, unchanged.
			got := map[string]string{}
			for _, call := range run.passwd {
				got[call.Principal] = call.Password
			}
			if want := map[string]string{"alice": roster.secrets["Alice"], "bob": roster.secrets["Bob"]}; fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("password API calls = %v, want one per user with a password", len(run.passwd))
			}
			if !strings.Contains(run.kinit, roster.secrets["VaultAdmin"]) {
				t.Fatal("kinit was not fed the admin password")
			}
			if !mode.opts.json {
				return
			}
			if run.ran(t, "Fill canonical roster freeipa.server for this reconcile") {
				t.Fatal("the fill task ran: this test is for a roster that names the server")
			}
			// Each loop the issue lists ran over the users, and what a
			// loop prints of a user has none of the credential keys.
			want := map[string][]string{
				"Ensure IPA users exist":                              {"alice", "bob"},
				"Reconcile user first/last names":                     {"alice", "bob"},
				"Set SSH public keys for users (declarative replace)": {"alice"},
				"Reconcile canonical account enabled state":           {"alice", "bob"},
				"Delete canonical users explicitly marked absent":     {"carol"},
			}
			for name, users := range want {
				if got := run.iterated(t, name); !slices.Equal(got, users) {
					t.Errorf("%s iterated over %v, want %v", name, got, users)
				}
				results, _ := run.task(t, name)["results"].([]any)
				for _, each := range results {
					item, _ := each.(map[string]any)["item"].(map[string]any)
					for _, key := range secretKeys {
						if _, found := item[key]; found {
							t.Errorf("%s prints a user with the key %s", name, key)
						}
					}
				}
			}
			facts, _ := run.task(t, "Select active identity objects")["ansible_facts"].(map[string]any)
			for _, fact := range []string{"ipa_active_users", "ipa_absent_users"} {
				users, _ := facts[fact].([]any)
				if len(users) == 0 {
					t.Errorf("the selection printed no %s", fact)
				}
				for _, each := range users {
					for _, key := range secretKeys {
						if _, found := each.(map[string]any)[key]; found {
							t.Errorf("%s prints a user with the key %s", fact, key)
						}
					}
				}
			}
			for _, name := range []string{"Select the credentials of the active users", "Look up password state for users with a declared password",
				"Set password for users that need one (first-time onboard, or requested reset)"} {
				if run.task(t, name)["censored"] == nil {
					t.Errorf("%s is not no_log: it holds the credentials", name)
				}
			}
		})
	}

	legacy := func(passwordOf map[string]any) map[string]any {
		v := map[string]any{"ipa_admin_password": roster.secrets["VaultAdmin"],
			"ipa_groups": []any{map[string]any{"name": "team-a"}},
			"ipa_users": []any{
				map[string]any{"name": "dave", "first": "Dave", "last": "Lee", "password": roster.secrets["Alice"],
					"groups": []any{"team-a"}, "ssh_keys": []any{roster.keys["alice"]}},
				map[string]any{"name": "erin", "first": "Erin", "last": "Moss", "password": roster.secrets["Bob"], "force_password": true},
			}}
		for k, value := range passwordOf {
			v[k] = value
		}
		return v
	}
	for _, mode := range []struct {
		name string
		opts identityRunOptions
	}{
		{"-v", identityRunOptions{verbosity: "-v"}},
		{"json callback", identityRunOptions{json: true}},
	} {
		t.Run("legacy ipa_users "+mode.name, func(t *testing.T) {
			mode.opts.vars = legacy(nil)
			run := h.run(t, mode.opts)
			run.requireHealthy(t, mode.name)
			run.assertNoSecrets(t, mode.name, roster.secrets)
			got := map[string]string{}
			for _, call := range run.passwd {
				got[call.Principal] = call.Password
			}
			if want := map[string]string{"dave": roster.secrets["Alice"], "erin": roster.secrets["Bob"]}; fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("password API calls = %v, want the legacy passwords unchanged", len(run.passwd))
			}
			if !mode.opts.json {
				return
			}
			want := map[string][]string{
				"Ensure IPA users exist":                              {"dave", "erin"},
				"Reconcile user first/last names":                     {"dave", "erin"},
				"Set SSH public keys for users (declarative replace)": {"dave"},
				"Ensure user group membership":                        {"dave"},
				"Look up current user group memberships":              {"dave", "erin"},
			}
			for name, users := range want {
				if got := run.iterated(t, name); !slices.Equal(got, users) {
					t.Errorf("%s iterated over %v, want %v", name, got, users)
				}
			}
			// "Compute stale group memberships to remove" prints the item
			// of the lookup above: the user, credential-free.
			stale, _ := run.task(t, "Compute stale group memberships to remove")["results"].([]any)
			if len(stale) != 2 {
				t.Fatalf("the stale-membership computation ran over %d lookups, want 2", len(stale))
			}
		})
	}

	// A password that is a template (a legacy roster may write
	// `password: "{{ vault_x }}"`) is rendered for the password API only.
	t.Run("legacy password template", func(t *testing.T) {
		templated := identitySentinel(t, "Template")
		secrets := map[string]string{"Template": templated, "VaultAdmin": roster.secrets["VaultAdmin"]}
		v := legacy(map[string]any{"vault_erin_password": templated})
		v["ipa_users"] = []any{map[string]any{"name": "erin", "first": "Erin", "last": "Moss", "password": "{{ vault_erin_password }}"}}
		run := h.run(t, identityRunOptions{vars: v, verbosity: "-v"})
		run.requireHealthy(t, "legacy password template")
		run.assertNoSecrets(t, "legacy password template", secrets)
		if len(run.passwd) != 1 || run.passwd[0].Principal != "erin" || run.passwd[0].Password != templated {
			t.Fatalf("the rendered template did not reach the password API unchanged: %v", len(run.passwd))
		}
	})

	// An unrenderable template fails the run where it failed before: in a
	// task that is not no_log, naming the variable.
	t.Run("legacy password template that cannot be rendered", func(t *testing.T) {
		v := legacy(nil)
		v["ipa_users"] = []any{map[string]any{"name": "erin", "first": "Erin", "last": "Moss", "password": "{{ no_such_vault_variable }}"}}
		run := h.run(t, identityRunOptions{vars: v})
		if run.rc == 0 {
			t.Fatal("an initial password that cannot be rendered must fail the run")
		}
		if !strings.Contains(run.stdout+run.stderr, "no_such_vault_variable") {
			t.Fatalf("the failure does not name the variable:\n%.2000s", run.stdout)
		}
		if len(run.passwd) != 0 {
			t.Fatal("a password was set although the template could not be rendered")
		}
	})

	// A failing iteration prints its whole item at the default verbosity:
	// the reason and the user stay visible, the password does not.
	t.Run("a failing iteration shows the reason and the user", func(t *testing.T) {
		const reason = "synthetic user-add failure"
		run := h.run(t, identityRunOptions{vars: vars, failUserAdd: reason})
		if run.rc == 0 {
			t.Fatal("a failing `ipa user-add` must fail the run")
		}
		run.assertNoSecrets(t, "failing run", roster.secrets)
		out := run.stdout + run.stderr
		if !strings.Contains(out, reason) || !strings.Contains(out, "(item=alice)") {
			t.Fatalf("the failure does not show the reason and the user:\n%.3000s", out)
		}
		if len(run.passwd) != 0 {
			t.Fatal("a password was set although the user could not be created")
		}
	})
}
