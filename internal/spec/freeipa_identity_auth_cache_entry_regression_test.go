package spec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The authorization-cache entry playbook and the identity playbook share three
// inputs, and a drift between them is silent
// (docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md §5.6,
// AGENTS.md §5.7): the entry writes the journal the identity playbook settles, so
// if the two disagree about its path, its domain or the helper that moves it, an
// obligation is recorded where nothing reads it, and nothing fails.
//
//  1. the journal path  ipa_identity_ssh_cache_state_file | default('/var/lib/pilot-identity/ssh-cache.json')
//  2. ipa_domain        freeipa_domain | default('ipa.pilot.internal')
//  3. the helper        files/freeipa-ssh-key-cache.py, read from the same file
//
// A static test reads every occurrence in the files, and a runtime test has real
// Ansible work out both sides for every combination of the two inventory
// variables set and unset.

const (
	authCacheEntryFile    = "../../playbooks/apply/freeipa-identity-auth-cache.yml"
	authCacheIdentityFile = "../../playbooks/apply/freeipa-identity-apply.yml"
	authCachePreflight    = "../../playbooks/apply/tasks/freeipa-ssh-cache-preflight.yml"

	journalDefaultExpr = "ipa_identity_ssh_cache_state_file | default('/var/lib/pilot-identity/ssh-cache.json')"
	domainExpr         = "{{ freeipa_domain | default('ipa.pilot.internal') }}"
	programExpr        = "{{ lookup('file', playbook_dir ~ '/files/freeipa-ssh-key-cache.py') }}"
)

func readAuthCacheFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// yamlScalars returns every scalar string of a YAML document, in order. Comments
// are not scalars, so a comment that mentions a variable is not an occurrence.
func yamlScalars(t *testing.T, raw []byte) []string {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var out []string
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Kind == yaml.ScalarNode {
			out = append(out, n.Value)
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(&doc)
	return out
}

// sharedInputProblems reads the three shared inputs in the entry and in the files
// the identity playbook is made of, and returns what is not spelled the same.
func sharedInputProblems(t *testing.T, entry, identity []byte, preflight []byte) []string {
	t.Helper()
	var problems []string
	files := map[string][]byte{"the entry": entry, "freeipa-identity-apply.yml": identity, "tasks/freeipa-ssh-cache-preflight.yml": preflight}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	// 1. Every mention of the journal variable carries the one default, and the
	// entry mentions it at all (twice: prepare and probe).
	journal := regexp.MustCompile(`ipa_identity_ssh_cache_state_file\b[^\n]{0,80}`)
	counts := map[string]int{}
	for _, name := range names {
		for _, scalar := range yamlScalars(t, files[name]) {
			for _, m := range journal.FindAllString(scalar, -1) {
				counts[name]++
				if !strings.HasPrefix(m, journalDefaultExpr) {
					problems = append(problems, fmt.Sprintf("%s: %q is not followed by the shared default %q", name, m, "| default('/var/lib/pilot-identity/ssh-cache.json')"))
				}
			}
		}
	}
	if counts["the entry"] < 2 {
		problems = append(problems, fmt.Sprintf("the entry mentions the journal variable %d times, want its prepare and its probe", counts["the entry"]))
	}
	if counts["freeipa-identity-apply.yml"] < 5 || counts["tasks/freeipa-ssh-cache-preflight.yml"] < 1 {
		problems = append(problems, fmt.Sprintf("found the journal variable %d times in the identity playbook and %d in its preflight: the check has lost what it is meant to compare", counts["freeipa-identity-apply.yml"], counts["tasks/freeipa-ssh-cache-preflight.yml"]))
	}

	// 2 and 3. The play vars of the entry and of every play of the identity
	// playbook that declares them.
	playVar := func(raw []byte, key string) []string {
		var plays []map[string]any
		if err := yaml.Unmarshal(raw, &plays); err != nil {
			t.Fatal(err)
		}
		var values []string
		for _, play := range plays {
			vars, _ := play["vars"].(map[string]any)
			if v, ok := vars[key]; ok {
				values = append(values, fmt.Sprint(v))
			}
		}
		return values
	}
	for key, want := range map[string]string{"ipa_domain": domainExpr, "ipa_ssh_cache_program": programExpr} {
		if got := playVar(entry, key); len(got) != 1 || got[0] != want {
			problems = append(problems, fmt.Sprintf("the entry declares %s as %q, want exactly %q once", key, got, want))
		}
		got := playVar(identity, key)
		if len(got) == 0 {
			problems = append(problems, fmt.Sprintf("the identity playbook declares no %s: the check has lost what it is meant to compare", key))
		}
		for _, v := range got {
			if v != want {
				problems = append(problems, fmt.Sprintf("the identity playbook declares %s as %q, want %q", key, v, want))
			}
		}
	}
	// The entry runs the helper only through the shared variable, never a path of its own.
	for _, scalar := range yamlScalars(t, entry) {
		if strings.Contains(scalar, "freeipa-ssh-key-cache") && scalar != programExpr {
			problems = append(problems, fmt.Sprintf("the entry names the helper by its own path: %q", scalar))
		}
	}
	return problems
}

func TestRegression_AuthCacheEntryAndIdentityPlaybookShareTheirInputs(t *testing.T) {
	// The entry sits next to the identity playbook, so that playbook_dir (and with it
	// the helper) is the same directory for both: the helper is shared by construction.
	if filepath.Dir(authCacheEntryFile) != filepath.Dir(authCacheIdentityFile) {
		t.Fatal("the entry is not in the directory of the identity playbook: its playbook_dir would find another helper")
	}
	problems := sharedInputProblems(t, readAuthCacheFile(t, authCacheEntryFile), readAuthCacheFile(t, authCacheIdentityFile), readAuthCacheFile(t, authCachePreflight))
	for _, p := range problems {
		t.Error(p)
	}
}

// The check fires: a copy of the entry with one default changed, and one with the
// helper read from its own path, are each reported, and the real entry is not.
func TestRegression_AuthCacheSharedInputCheckFiresOnADriftedEntry(t *testing.T) {
	entry := readAuthCacheFile(t, authCacheEntryFile)
	identity := readAuthCacheFile(t, authCacheIdentityFile)
	preflight := readAuthCacheFile(t, authCachePreflight)
	if got := sharedInputProblems(t, entry, identity, preflight); len(got) != 0 {
		t.Fatalf("the real files already disagree: %q", got)
	}
	mutate := func(old, new string) []byte {
		if strings.Count(string(entry), old) == 0 {
			t.Fatalf("the entry has no %q to change", old)
		}
		// All of them: the first mention is often the entry's own header comment.
		return []byte(strings.ReplaceAll(string(entry), old, new))
	}
	for name, tc := range map[string]struct {
		entry []byte
		want  string
	}{
		"the journal default changed":  {mutate("/var/lib/pilot-identity/ssh-cache.json", "/var/lib/pilot-identity/other.json"), "is not followed by the shared default"},
		"the domain default changed":   {mutate("default('ipa.pilot.internal')", "default('example.test')"), "declares ipa_domain"},
		"the helper from its own path": {mutate("playbook_dir ~ '/files/freeipa-ssh-key-cache.py'", "playbook_dir ~ '/files/freeipa-ssh-key-cache-copy.py'"), "declares ipa_ssh_cache_program"},
		"the journal variable renamed": {mutate("ipa_identity_ssh_cache_state_file | default(", "ipa_identity_ssh_cache_statefile | default("), "mentions the journal variable"},
	} {
		t.Run(name, func(t *testing.T) {
			got := sharedInputProblems(t, tc.entry, identity, preflight)
			for _, p := range got {
				if strings.Contains(p, tc.want) {
					return
				}
			}
			t.Fatalf("problems %q do not include one about %q", got, tc.want)
		})
	}
}

// sharedInputsAtRuntime has real Ansible render the journal path, ipa_domain and
// the helper's digest as the entry and as the identity playbook spell them, for one
// combination of the two inventory variables.
func sharedInputsAtRuntime(t *testing.T, entry, identity []byte, setDomain, setJournal bool) (entrySide, identitySide map[string]string) {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	argvFourth := func(raw []byte, task string) string {
		var plays []map[string]any
		if err := yaml.Unmarshal(raw, &plays); err != nil {
			t.Fatal(err)
		}
		var found string
		var visit func(items []any)
		visit = func(items []any) {
			for _, item := range items {
				m, _ := item.(map[string]any)
				if name, _ := m["name"].(string); name == task {
					cmd, _ := m["ansible.builtin.command"].(map[string]any)
					argv, _ := cmd["argv"].([]any)
					if len(argv) == 5 {
						found = fmt.Sprint(argv[4])
					}
				}
				if block, ok := m["block"].([]any); ok {
					visit(block)
				}
			}
		}
		for _, play := range plays {
			for _, section := range []string{"pre_tasks", "tasks"} {
				items, _ := play[section].([]any)
				visit(items)
			}
		}
		if found == "" {
			t.Fatalf("no task %q with a five-element argv", task)
		}
		return found
	}
	playVar := func(raw []byte, key string) string {
		var plays []map[string]any
		if err := yaml.Unmarshal(raw, &plays); err != nil {
			t.Fatal(err)
		}
		vars, _ := plays[0]["vars"].(map[string]any)
		return fmt.Sprint(vars[key])
	}

	dir := t.TempDir()
	// playbook_dir of the harness must hold the same files/ directory.
	apply, err := filepath.Abs(filepath.Dir(authCacheEntryFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(apply, "files"), filepath.Join(dir, "files")); err != nil {
		t.Fatal(err)
	}
	harness := []map[string]any{{
		"hosts": "localhost", "gather_facts": false, "connection": "local",
		"vars": map[string]any{
			"entry_domain":     playVar(entry, "ipa_domain"),
			"identity_domain":  playVar(identity, "ipa_domain"),
			"entry_program":    playVar(entry, "ipa_ssh_cache_program"),
			"identity_program": playVar(identity, "ipa_ssh_cache_program"),
			"entry_journal":    argvFourth(entry, "Record the authorization-cache obligation (prepare)"),
			"entry_probe":      argvFourth(entry, "Read the authorization-cache obligation (probe)"),
			"identity_journal": argvFourth(identity, "Prepare legacy authorization cache recovery"),
		},
		"tasks": []any{map[string]any{
			"name": "show",
			"ansible.builtin.debug": map[string]any{"msg": "{{ {" +
				"'entry': {'domain': entry_domain, 'journal': entry_journal, 'probe_journal': entry_probe, 'helper': entry_program | hash('sha256')}," +
				"'identity': {'domain': identity_domain, 'journal': identity_journal, 'probe_journal': identity_journal, 'helper': identity_program | hash('sha256')}" +
				"} | to_json }}"},
		}},
	}}
	body, err := yaml.Marshal(harness)
	if err != nil {
		t.Fatal(err)
	}
	play := filepath.Join(dir, "harness.yml")
	if err := os.WriteFile(play, body, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-i", "localhost,", play}
	extra := map[string]any{}
	if setDomain {
		extra["freeipa_domain"] = "lab.example"
	}
	if setJournal {
		extra["ipa_identity_ssh_cache_state_file"] = "/srv/pilot state/journal.json"
	}
	if len(extra) > 0 {
		encoded, _ := json.Marshal(extra)
		args = append(args, "-e", string(encoded))
	}
	cmd := exec.Command("ansible-playbook", args...)
	// ANSIBLE_HOME moves ansible's default collection path with it (<home>/collections), and the json stdout callback
	// of ansible-core 2.19.15 lives in ansible.posix, which CI installs in the user's ~/.ansible/collections: with the
	// override alone the callback cannot be loaded and ansible-playbook ends with status 1 and no output (CI run
	// 42360313970). The user's collection directory stays on the path.
	cmd.Env = append(os.Environ(), "ANSIBLE_STDOUT_CALLBACK=json", "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False",
		"ANSIBLE_CACHE_PLUGIN_CONNECTION="+filepath.Join(dir, "factcache"), "ANSIBLE_HOME="+filepath.Join(dir, "home"),
		"ANSIBLE_COLLECTIONS_PATH="+usersAnsibleCollectionsPath())
	out, runErr := cmd.Output()
	var cb struct {
		Plays []struct {
			Tasks []struct {
				Task  struct{ Name string } `json:"task"`
				Hosts map[string]struct {
					Failed bool   `json:"failed"`
					Msg    string `json:"msg"`
				} `json:"hosts"`
			} `json:"tasks"`
		} `json:"plays"`
	}
	if err := json.Unmarshal(out, &cb); err != nil {
		t.Fatalf("parse the JSON callback (%v): %v\n%s", runErr, err, out)
	}
	for _, p := range cb.Plays {
		for _, task := range p.Tasks {
			h := task.Hosts["localhost"]
			if h.Failed {
				t.Fatalf("ansible-playbook failed at %q: %s", task.Task.Name, h.Msg)
			}
			if task.Task.Name != "show" {
				continue
			}
			var got struct {
				Entry    map[string]string `json:"entry"`
				Identity map[string]string `json:"identity"`
			}
			if err := json.Unmarshal([]byte(h.Msg), &got); err != nil {
				t.Fatalf("decode %q: %v", h.Msg, err)
			}
			return got.Entry, got.Identity
		}
	}
	t.Fatalf("the show task did not run:\n%s", out)
	return nil, nil
}

func TestRegression_AuthCacheEntryAndIdentityPlaybookResolveTheSameInputs(t *testing.T) {
	entry := readAuthCacheFile(t, authCacheEntryFile)
	identity := readAuthCacheFile(t, authCacheIdentityFile)
	// lookup('file') drops the file's trailing newline, so that is what both sides
	// hash.
	digest := sha256.Sum256([]byte(strings.TrimRight(string(readAuthCacheFile(t, "../../playbooks/apply/files/freeipa-ssh-key-cache.py")), "\n")))
	for _, tc := range []struct {
		name                  string
		setDomain, setJournal bool
		wantDomain            string
		wantJournal           string
	}{
		{"neither set", false, false, "ipa.pilot.internal", "/var/lib/pilot-identity/ssh-cache.json"},
		{"domain set", true, false, "lab.example", "/var/lib/pilot-identity/ssh-cache.json"},
		{"journal set (a path with a space)", false, true, "ipa.pilot.internal", "/srv/pilot state/journal.json"},
		{"both set", true, true, "lab.example", "/srv/pilot state/journal.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, i := sharedInputsAtRuntime(t, entry, identity, tc.setDomain, tc.setJournal)
			for _, side := range []struct {
				name string
				got  map[string]string
			}{{"entry", e}, {"identity", i}} {
				if side.got["domain"] != tc.wantDomain || side.got["journal"] != tc.wantJournal || side.got["probe_journal"] != tc.wantJournal || side.got["helper"] != hex.EncodeToString(digest[:]) {
					t.Errorf("%s resolves %v, want domain %q, journal %q and the helper with digest %x", side.name, side.got, tc.wantDomain, tc.wantJournal, digest)
				}
			}
			for key := range e {
				if e[key] != i[key] {
					t.Errorf("%s: the entry resolves %q and the identity playbook %q", key, e[key], i[key])
				}
			}
		})
	}
}

// The runtime check fires too: a copy of the entry whose journal default or domain
// default is not the identity playbook's resolves differently, and the comparison
// sees it.
func TestRegression_AuthCacheRuntimeCheckFiresOnADriftedEntry(t *testing.T) {
	entry := readAuthCacheFile(t, authCacheEntryFile)
	identity := readAuthCacheFile(t, authCacheIdentityFile)
	for name, mutated := range map[string]string{
		"journal default": strings.ReplaceAll(string(entry), "/var/lib/pilot-identity/ssh-cache.json", "/var/lib/pilot-identity/other.json"),
		"domain default":  strings.ReplaceAll(string(entry), "default('ipa.pilot.internal')", "default('example.test')"),
	} {
		t.Run(name, func(t *testing.T) {
			if mutated == string(entry) {
				t.Fatal("the mutation changed nothing")
			}
			e, i := sharedInputsAtRuntime(t, []byte(mutated), identity, false, false)
			for key := range e {
				if e[key] != i[key] {
					return
				}
			}
			t.Fatalf("a drifted entry resolves the same as the identity playbook: %v vs %v", e, i)
		})
	}
}

// The observation the identity playbook writes for the Go reconciler, as a
// structure (the runtime behaviour is internal/identityreconcile's
// TestIdentityObservationReportsWhatTheRunDid): the ack is registered under the name
// the observation reads, the observation is the last thing in the block and runs
// under any --tags, every read of a register that a tagged or conditional task sets
// is guarded, and nothing else in the playbook knows the output variable, so a run
// that is not handed one is the playbook it was.
func TestRegression_IdentityObservationStructure(t *testing.T) {
	raw := readAuthCacheFile(t, authCacheIdentityFile)
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	tasks, _ := plays[0]["tasks"].([]any)
	block, _ := tasks[0].(map[string]any)["block"].([]any)
	if len(block) < 3 {
		t.Fatalf("the identity block has %d tasks", len(block))
	}

	find := func(name string) (map[string]any, int) {
		for i, item := range block {
			if m, _ := item.(map[string]any); m["name"] == name {
				return m, i
			}
		}
		t.Fatalf("no task %q in the identity block", name)
		return nil, -1
	}
	ack, _ := find("Acknowledge legacy authorization cache recovery")
	if ack["register"] != "ipa_auth_cache_ack" {
		t.Errorf("the acknowledgement registers %v, want ipa_auth_cache_ack (the observation reads it)", ack["register"])
	}
	fqdn, fqdnAt := find("Read the host's FQDN for the authorization cache observation")
	observe, observeAt := find("Record what this run did about the authorization cache (observation for pilot)")
	if observeAt != len(block)-1 || fqdnAt != observeAt-1 {
		t.Errorf("the observation tasks are at %d and %d of %d: they must be the last two tasks of the block, so that an earlier failure leaves no observation", fqdnAt, observeAt, len(block))
	}
	for name, task := range map[string]map[string]any{"fqdn": fqdn, "observation": observe} {
		if tags := fmt.Sprint(task["tags"]); tags != "[always]" {
			t.Errorf("%s task tags = %s, want [always]: under --tags the run must still say what it did", name, tags)
		}
		when := fmt.Sprint(task["when"])
		for _, need := range []string{"not ansible_check_mode", "pilot_identity_auth_cache_output is defined"} {
			if !strings.Contains(when, need) {
				t.Errorf("%s task when = %s, want it to hold %q", name, when, need)
			}
		}
		if task["changed_when"] != false {
			t.Errorf("%s task changed_when = %v, want false: an always task must not make every run report a change", name, task["changed_when"])
		}
	}
	if observe["delegate_to"] != "localhost" || observe["become"] != false {
		t.Errorf("the observation delegates to %v with become %v, want localhost without become", observe["delegate_to"], observe["become"])
	}
	body := fmt.Sprint(observe["vars"])
	// Every register a task that is tagged otherwise, or conditional, sets.
	for _, reg := range []string{"ipa_auth_cache_ack", "ipa_sudo_refresh_results", "ipa_auth_cache_settle", "ipa_auth_cache_prepare"} {
		if !regexp.MustCompile(`\b` + reg + ` is defined`).MatchString(body) {
			t.Errorf("the observation reads %s without checking that it is defined", reg)
		}
	}
	// Nothing else in the playbook (nor its tasks files) knows the output variable, but the gate of
	// the mixed run (spec §8.4): the Go engine variable is refused without it, since the Go writes are
	// not seen by the settle task and the run must be able to say whether it acknowledged them.
	allowed := map[string]bool{}
	pre, _ := plays[0]["pre_tasks"].([]any)
	for _, item := range pre {
		if m, _ := item.(map[string]any); m["name"] == "Gate: the users/groups engine is ansible or go, and go brings the observation file" {
			gate, err := yaml.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			for _, scalar := range yamlScalars(t, gate) {
				allowed[scalar] = true
			}
		}
	}
	if len(allowed) == 0 {
		t.Error("the mixed run's gate is not among the pre_tasks")
	}
	for _, scalar := range yamlScalars(t, raw) {
		if strings.Contains(scalar, "pilot_identity_auth_cache_output") && !strings.Contains(scalar, "ipa_auth_cache_observe") && !allowed[scalar] &&
			scalar != "pilot_identity_auth_cache_output is defined" && scalar != "{{ pilot_identity_auth_cache_output }}" {
			t.Errorf("a scalar of the identity playbook mentions the output variable outside the observation: %q", scalar)
		}
	}
}

// The entry's own structure: every gate is a pre_task tagged always (no tag
// selection can skip one), the stage gates come first, and the tasks that do the
// work carry no tags (the gate refuses any tag selection, so none is needed, and a
// tag on them would suggest a selection that can never run).
func TestRegression_AuthCacheEntryStructure(t *testing.T) {
	var plays []map[string]any
	if err := yaml.Unmarshal(readAuthCacheFile(t, authCacheEntryFile), &plays); err != nil {
		t.Fatal(err)
	}
	if len(plays) != 1 {
		t.Fatalf("the entry has %d plays, want one", len(plays))
	}
	play := plays[0]
	pre, _ := play["pre_tasks"].([]any)
	work, _ := play["tasks"].([]any)
	if len(pre) < 7 {
		t.Fatalf("%d pre_tasks, want the stage gates and the entry's own", len(pre))
	}
	for i, item := range pre {
		m, _ := item.(map[string]any)
		if fmt.Sprint(m["tags"]) != "[always]" {
			t.Errorf("pre_task %d %q has tags %v, want [always]", i, m["name"], m["tags"])
		}
		if _, isAssert := m["ansible.builtin.assert"]; !isAssert {
			t.Errorf("pre_task %d %q is not an assert", i, m["name"])
		}
	}
	for i, want := range []string{"Gate: staging or prod requires explicit confirm", "Gate: stage must match this host's inventory environment group", "Gate: prod requires recent staging attestation"} {
		if m, _ := pre[i].(map[string]any); m["name"] != want {
			t.Errorf("pre_task %d is %v, want the stage gate %q first (AGENTS.md §4.3 point 4)", i, m["name"], want)
		}
	}
	for i, item := range work {
		m, _ := item.(map[string]any)
		if _, tagged := m["tags"]; tagged {
			t.Errorf("task %d %q carries tags %v", i, m["name"], m["tags"])
		}
		if cmd, isCommand := m["ansible.builtin.command"]; isCommand && m["changed_when"] != false {
			t.Errorf("task %d %q (command %v) must set changed_when: false: the entry's second run is checked for changed=0", i, m["name"], cmd)
		}
	}
	vars, _ := play["vars"].(map[string]any)
	for _, key := range []string{"pilot_identity_auth_cache_action", "pilot_identity_auth_cache_output", "ipa_identity_ssh_cache_state_file", "freeipa_domain"} {
		if _, declared := vars[key]; declared {
			t.Errorf("play vars declare %s: it is an input and a play var would shadow what the caller passes (AGENTS.md §4.5 point 3)", key)
		}
	}
}

// usersAnsibleCollectionsPath is the collection path a test that moves ANSIBLE_HOME still wants: the one the environment
// names, then the default directory of the real home (what ansible-galaxy installs into without -p).
func usersAnsibleCollectionsPath() string {
	var dirs []string
	if v := os.Getenv("ANSIBLE_COLLECTIONS_PATH"); v != "" {
		dirs = append(dirs, v)
	}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".ansible", "collections"))
	}
	return strings.Join(dirs, string(os.PathListSeparator))
}
