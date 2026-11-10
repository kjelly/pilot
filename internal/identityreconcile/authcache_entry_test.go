package identityreconcile

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The entry playbook (playbooks/apply/freeipa-identity-auth-cache.yml) and the
// identity playbook's observation, run through the real ansible-playbook on this
// machine as one local host (connection local, no become): the gates refuse what
// they are meant to refuse and the one case that must pass passes (AGENTS.md §5.12),
// the result file is what ParseAuthCacheResult accepts, and the journal goes
// absent -> owed -> settled -> owed the way the helper's own writer moves it.
//
// What this does not show is the real FreeIPA server, a remote host and become:
// those are the live runs (docs/evidence/freeipa-go-reconcile/pr-284.md) and the
// captures in testdata/authcache-*.

const (
	entryPlaybookPath    = "../../playbooks/apply/freeipa-identity-auth-cache.yml"
	identityPlaybookPath = "../../playbooks/apply/freeipa-identity-apply.yml"
	helperPath           = "../../playbooks/apply/files/freeipa-ssh-key-cache.py"
)

func requireAnsible(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skipf("python3 not installed: %v", err)
	}
}

// localFQDN is what the entry will report for this machine.
func localFQDN(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("hostname", "-f").Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		t.Fatalf("hostname -f gives nothing here (%v): the entry cannot run on this machine", err)
	}
	return strings.TrimSpace(string(out))
}

// entryEnv is a scratch inventory of local hosts, a result file and a journal.
type entryEnv struct {
	t       *testing.T
	dir     string
	inv     string
	out     string
	journal string
	hosts   []string
	env     []string // added to the environment of ansible-playbook
}

// newEntryEnv: hosts are local hosts of the group freeipa-server (plus any group
// in extraGroups, host -> groups), as an inventory file.
func newEntryEnv(t *testing.T, hosts []string, extraGroups map[string][]string) *entryEnv {
	t.Helper()
	requireAnsible(t)
	e := &entryEnv{t: t, dir: t.TempDir(), hosts: hosts}
	e.out = filepath.Join(e.dir, "result.json")
	e.journal = filepath.Join(e.dir, "state", "ssh-cache.json")
	if err := os.WriteFile(e.out, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// The test host never becomes: a host variable, so that it stays out of the way of
	// what the controller-side copy does with localhost's own variables (an extra
	// variable would override those too).
	hostVars := map[string]any{"ansible_connection": "local", "ansible_python_interpreter": "/usr/bin/python3", "ansible_become": false}
	children := map[string]any{"freeipa-server": map[string]any{"hosts": hostMap(hosts, hostVars)}}
	groups := map[string][]string{}
	for host, gs := range extraGroups {
		for _, g := range gs {
			groups[g] = append(groups[g], host)
		}
	}
	for g, members := range groups {
		children[g] = map[string]any{"hosts": hostMap(members, hostVars)}
	}
	e.inv = filepath.Join(e.dir, "inventory.yml")
	body, err := yaml.Marshal(map[string]any{"all": map[string]any{"children": children}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.inv, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return e
}

func hostMap(hosts []string, vars map[string]any) map[string]any {
	m := map[string]any{}
	for _, h := range hosts {
		m[h] = vars
	}
	return m
}

// entryOutcome is what a run left.
type entryOutcome struct {
	rc      int
	failed  []string // "<task>: <msg>" for each failed task
	ran     []string // names of the tasks that did not skip
	skipped []string
	stdout  string
	result  []byte
}

// run runs playbook with the inventory and the extra arguments. The result file
// path and the journal path go in as the JSON object form of -e, as Go will hand
// them.
func (e *entryEnv) run(playbook string, extra ...string) entryOutcome {
	e.t.Helper()
	return e.runWith(playbook, true, extra...)
}

// runWith is run, with or without the extra variable that gives the playbook the
// path of the result file.
func (e *entryEnv) runWith(playbook string, withOutput bool, extra ...string) entryOutcome {
	e.t.Helper()
	vars := map[string]string{"ipa_identity_ssh_cache_state_file": e.journal}
	if withOutput {
		vars["pilot_identity_auth_cache_output"] = e.out
	}
	encoded, _ := json.Marshal(vars)
	args := append([]string{"-i", e.inv, playbook, "-e", string(encoded)}, extra...)
	cmd := exec.Command("ansible-playbook", args...)
	cmd.Env = append(append(os.Environ(), "ANSIBLE_STDOUT_CALLBACK=json", "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False",
		"ANSIBLE_CACHE_PLUGIN_CONNECTION="+filepath.Join(e.dir, "factcache"), "ANSIBLE_HOME="+filepath.Join(e.dir, "ansible-home"),
		"ANSIBLE_PYTHON_INTERPRETER=/usr/bin/python3"), e.env...)
	out, runErr := cmd.Output()
	var exit *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exit) {
		e.t.Fatalf("ansible-playbook did not run: %v", runErr)
	}
	res := entryOutcome{stdout: string(out)}
	if exit != nil {
		res.rc = exit.ExitCode()
	}
	var cb struct {
		Plays []struct {
			Tasks []struct {
				Task  struct{ Name string } `json:"task"`
				Hosts map[string]struct {
					Failed  bool   `json:"failed"`
					Skipped bool   `json:"skipped"`
					Msg     any    `json:"msg"`
					Stdout  string `json:"stdout"`
				} `json:"hosts"`
			} `json:"tasks"`
		} `json:"plays"`
	}
	if err := json.Unmarshal(out, &cb); err != nil {
		e.t.Fatalf("parse the JSON callback (rc %d): %v\n%s", res.rc, err, out)
	}
	for _, p := range cb.Plays {
		for _, task := range p.Tasks {
			for _, h := range task.Hosts {
				switch {
				case h.Failed:
					msg, _ := json.Marshal(h.Msg)
					res.failed = append(res.failed, task.Task.Name+": "+string(msg)+" "+h.Stdout)
				case h.Skipped:
					res.skipped = append(res.skipped, task.Task.Name)
				default:
					res.ran = append(res.ran, task.Task.Name)
				}
			}
		}
	}
	var err error
	if res.result, err = os.ReadFile(e.out); err != nil {
		e.t.Fatal(err)
	}
	return res
}

// helper runs one action of the helper as the identity playbook does (the helper's
// own writer, on the journal of this env).
func (e *entryEnv) helper(action string, data map[string]any) {
	e.t.Helper()
	data["domain"] = "ipa.pilot.internal"
	in, _ := json.Marshal(data)
	cmd := exec.Command("python3", helperPath, action, e.journal)
	cmd.Stdin = strings.NewReader(string(in))
	if out, err := cmd.CombinedOutput(); err != nil {
		e.t.Fatalf("helper %s: %v\n%s", action, err, out)
	}
}

func (e *entryEnv) want(action AuthCacheAction) AuthCacheWant {
	return AuthCacheWant{Action: action, Host: e.hosts[0], FQDN: localFQDN(e.t)}
}

func (e *entryEnv) journalExists() bool {
	_, err := os.Stat(filepath.Dir(e.journal))
	return err == nil
}

// The entry's modes against a journal that goes absent -> owed -> settled -> owed:
// prepare says what was owed before it (and owes), probe says what is owed and
// changes nothing, and each result is one the parser accepts.
func TestAuthCacheEntryPrepareAndProbeFollowTheJournal(t *testing.T) {
	e := newEntryEnv(t, []string{"srv1"}, nil)
	probe := func(wantPending bool) {
		t.Helper()
		res := e.run(entryPlaybookPath, "-e", "pilot_identity_auth_cache_action=probe")
		if res.rc != 0 {
			t.Fatalf("probe failed: %v\n%s", res.failed, res.stdout)
		}
		got, err := ParseAuthCacheResult(res.rc, res.result, e.want(AuthCacheProbe))
		if err != nil || got.Pending != wantPending {
			t.Fatalf("probe result %q: %+v, %v; want pending=%v", res.result, got, err, wantPending)
		}
	}
	prepare := func(wantPrevious bool) {
		t.Helper()
		res := e.run(entryPlaybookPath, "-e", "pilot_identity_auth_cache_action=prepare")
		if res.rc != 0 {
			t.Fatalf("prepare failed: %v\n%s", res.failed, res.stdout)
		}
		got, err := ParseAuthCacheResult(res.rc, res.result, e.want(AuthCachePrepare))
		if err != nil || got.Previous != wantPrevious {
			t.Fatalf("prepare result %q: %+v, %v; want previous=%v", res.result, got, err, wantPrevious)
		}
	}

	// Absent: owed, and the read created nothing.
	probe(true)
	if e.journalExists() {
		t.Fatal("a probe of an absent journal created the journal directory")
	}
	// A prepare of an absent journal: it was owed (a journal that never recorded the
	// flag cannot show that earlier runs refreshed every client), and now it is on file.
	prepare(true)
	probe(true)
	// Settled by what the identity playbook does after a refresh: settle, ack.
	e.helper("auth_settle", map[string]any{"previous": true, "changed": false})
	e.helper("auth_ack", map[string]any{})
	probe(false)
	before, _ := os.ReadFile(e.journal)
	probe(false)
	if after, _ := os.ReadFile(e.journal); string(before) != string(after) {
		t.Fatal("a probe changed the journal")
	}
	// A prepare of a settled journal: nothing was owed before it, and it owes again.
	prepare(false)
	probe(true)
}

// Every refusal of the entry, with the control that does not refuse: the gate that
// fires says why, the helper never ran, no result was written and no journal was
// made. A run that passed all of them would still need to be proven to refuse.
func TestAuthCacheEntryRefusals(t *testing.T) {
	type refusal struct {
		name   string
		hosts  []string
		groups map[string][]string
		args   []string
		task   string // the gate that fires
		msg    string // in its message
	}
	good := []string{"-e", "pilot_identity_auth_cache_action=prepare"}
	for _, tc := range []refusal{
		{name: "check mode", args: append([]string{"--check"}, good...), task: "Gate: this entry is never a preview", msg: "does not run in check mode"},
		{name: "a tag selection", args: append([]string{"--tags", "sshkeys"}, good...), task: "Gate: this entry takes no --tags and no --skip-tags", msg: "takes no --tags"},
		{name: "a skip-tags selection", args: append([]string{"--skip-tags", "sshkeys"}, good...), task: "Gate: this entry takes no --tags and no --skip-tags", msg: "takes no --tags"},
		{name: "two hosts", hosts: []string{"srv1", "srv2"}, args: good, task: "Gate: exactly one host", msg: "exactly one host"},
		{name: "no action", args: nil, task: "Gate: the action is prepare or probe and the result path is absolute", msg: "must be prepare or probe"},
		{name: "an unknown action", args: []string{"-e", "pilot_identity_auth_cache_action=settle"}, task: "Gate: the action is prepare or probe and the result path is absolute", msg: "must be prepare or probe"},
		{name: "a relative result path", args: append([]string{"-e", `{"pilot_identity_auth_cache_output": "result.json"}`}, good...), task: "Gate: the action is prepare or probe and the result path is absolute", msg: "absolute path"},
		{name: "staging without the confirm flag", args: append([]string{"-e", "stage=staging"}, good...), groups: map[string][]string{"srv1": {"staging"}}, task: "Gate: staging or prod requires explicit confirm", msg: "requires confirm flag"},
		{name: "a staging host with the default stage", args: good, groups: map[string][]string{"srv1": {"staging"}}, task: "Gate: stage must match this host's inventory environment group", msg: "inventory 環境 group 不一致"},
		{name: "prod without the staging attestation", args: append([]string{"-e", "stage=prod", "-e", "confirm_prod=true", "-e", "staging_attested_within_hours=200"}, good...), groups: map[string][]string{"srv1": {"prod"}}, task: "Gate: prod requires recent staging attestation", msg: "attestation missing or older"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hosts := tc.hosts
			if hosts == nil {
				hosts = []string{"srv1"}
			}
			e := newEntryEnv(t, hosts, tc.groups)
			// A later -e of the same variable wins over the env's own, so the case
			// "a relative result path" replaces the real path.
			res := e.run(entryPlaybookPath, tc.args...)
			if res.rc == 0 {
				t.Fatalf("the entry ran: %v", res.ran)
			}
			var found bool
			for _, f := range res.failed {
				found = found || (strings.HasPrefix(f, tc.task) && strings.Contains(f, tc.msg))
			}
			if !found {
				t.Fatalf("no failure of %q holding %q; failed: %q", tc.task, tc.msg, res.failed)
			}
			for _, name := range append(res.ran, res.skipped...) {
				if strings.Contains(name, "authorization-cache obligation") || strings.Contains(name, "Write the result") {
					t.Fatalf("%q ran after a refusal", name)
				}
			}
			if len(res.result) != 0 {
				t.Fatalf("the result file holds %q after a refusal", res.result)
			}
			if e.journalExists() {
				t.Fatal("the journal directory was created by a refused run")
			}
			// Whatever the file holds, the parser takes a refusal for an entry failure.
			if _, err := ParseAuthCacheResult(res.rc, res.result, e.want(AuthCachePrepare)); !errors.Is(err, ErrAuthCacheResult) {
				t.Fatalf("the parser accepted a refused run: %v", err)
			}
		})
	}

	// The control: the same arguments without the fault run, and write a result.
	t.Run("control: nothing wrong", func(t *testing.T) {
		e := newEntryEnv(t, []string{"srv1"}, nil)
		res := e.run(entryPlaybookPath, good...)
		if res.rc != 0 || len(res.failed) != 0 {
			t.Fatalf("a valid run failed: %v\n%s", res.failed, res.stdout)
		}
		if _, err := ParseAuthCacheResult(res.rc, res.result, e.want(AuthCachePrepare)); err != nil {
			t.Fatalf("a valid run's result was rejected: %v (%q)", err, res.result)
		}
	})
}

// A journal of another domain, or a damaged one, fails the helper's task: the play
// stops, nothing is written to the result file, and Go refuses to write.
func TestAuthCacheEntryHelperFailureLeavesNoResult(t *testing.T) {
	e := newEntryEnv(t, []string{"srv1"}, nil)
	e.helper("auth_prepare", map[string]any{})
	e.helper("auth_ack", map[string]any{})
	for _, action := range []string{"prepare", "probe"} {
		t.Run("another domain/"+action, func(t *testing.T) {
			res := e.run(entryPlaybookPath, "-e", "pilot_identity_auth_cache_action="+action, "-e", "freeipa_domain=other.example")
			if res.rc == 0 || len(res.failed) == 0 || !strings.Contains(res.failed[0], "journal domain mismatch") {
				t.Fatalf("rc %d, failed %q: want the helper's journal domain mismatch", res.rc, res.failed)
			}
			if len(res.result) != 0 {
				t.Fatalf("a result was written: %q", res.result)
			}
		})
	}
	if err := os.WriteFile(e.journal, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("a damaged journal", func(t *testing.T) {
		res := e.run(entryPlaybookPath, "-e", "pilot_identity_auth_cache_action=probe")
		if res.rc == 0 || len(res.result) != 0 {
			t.Fatalf("rc %d, result %q, failed %q: a damaged journal must fail the probe", res.rc, res.result, res.failed)
		}
	})
}

// localhostBecomes puts an explicit `localhost` in the inventory with ansible_become
// set (a variable of the inventory, as an operator's group_vars would give) and a
// sudo on PATH that records every call and fails. The result file belongs to the
// user who runs pilot, so a write to it must never go through become: a variable
// of the delegated host beats the task's `become: false` keyword (found live on
// this machine: with only the keyword, the copy ran under sudo), which is why the
// writing tasks carry the same value as a task variable too.
func (e *entryEnv) localhostBecomes() (sudoLog string) {
	e.t.Helper()
	bin := filepath.Join(e.dir, "fake-bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		e.t.Fatal(err)
	}
	sudoLog = filepath.Join(e.dir, "sudo.log")
	script := "#!/bin/sh\necho \"sudo $*\" >> '" + sudoLog + "'\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "sudo"), []byte(script), 0o755); err != nil {
		e.t.Fatal(err)
	}
	e.env = append(e.env, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	body, err := os.ReadFile(e.inv)
	if err != nil {
		e.t.Fatal(err)
	}
	var inv map[string]any
	if err := yaml.Unmarshal(body, &inv); err != nil {
		e.t.Fatal(err)
	}
	children := inv["all"].(map[string]any)["children"].(map[string]any)
	children["ungrouped"] = map[string]any{"hosts": map[string]any{"localhost": map[string]any{
		"ansible_connection": "local", "ansible_python_interpreter": "/usr/bin/python3", "ansible_become": true, "ansible_become_method": "sudo"}}}
	if body, err = yaml.Marshal(inv); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(e.inv, body, 0o600); err != nil {
		e.t.Fatal(err)
	}
	return sudoLog
}

func TestAuthCacheResultIsWrittenWithoutBecomeWhateverLocalhostSays(t *testing.T) {
	t.Run("the entry", func(t *testing.T) {
		e := newEntryEnv(t, []string{"srv1"}, nil)
		sudoLog := e.localhostBecomes()
		res := e.run(entryPlaybookPath, "-e", "pilot_identity_auth_cache_action=probe")
		if res.rc != 0 {
			t.Fatalf("the entry failed: %v\n%s", res.failed, res.stdout)
		}
		if _, err := ParseAuthCacheResult(res.rc, res.result, e.want(AuthCacheProbe)); err != nil {
			t.Fatalf("result %q: %v", res.result, err)
		}
		if logged, _ := os.ReadFile(sudoLog); len(logged) != 0 {
			t.Fatalf("the controller-side copy went through sudo: %s", logged)
		}
	})
	t.Run("the identity playbook's observation", func(t *testing.T) {
		e := newEntryEnv(t, []string{"srv1"}, nil)
		sudoLog := e.localhostBecomes()
		res := e.runObservation(observationTasks(t), map[string]any{
			"ipa_auth_cache_prepare": map[string]any{"rc": 0, "stdout": `{"previous": true}`},
			"ipa_auth_cache_ack":     map[string]any{"rc": 0},
		})
		if res.rc != 0 {
			t.Fatalf("the observation failed: %v\n%s", res.failed, res.stdout)
		}
		if _, err := ParseAuthCacheResult(res.rc, res.result, e.want(AuthCacheObserve)); err != nil {
			t.Fatalf("result %q: %v", res.result, err)
		}
		if logged, _ := os.ReadFile(sudoLog); len(logged) != 0 {
			t.Fatalf("the controller-side copy went through sudo: %s", logged)
		}
	})
}

// The identity playbook's observation, through the real tasks and real Ansible,
// with the registers the earlier tasks leave set directly: acknowledged, not
// acknowledged (the refresh switched off, a deferred client, a tag selection that
// skipped the settle), refresh unfinished, and the two ways it writes nothing (no
// output path given, check mode). The registers here are what Ansible records for
// those tasks (rc, stdout, skipped); the live runs are the captures
// testdata/authcache-k18-*.
func TestIdentityObservationReportsWhatTheRunDid(t *testing.T) {
	requireAnsible(t)
	tasks := observationTasks(t)

	ran := func(rc int, stdout string) map[string]any {
		return map[string]any{"rc": rc, "stdout": stdout, "changed": false}
	}
	skipped := map[string]any{"skipped": true, "changed": false, "skip_reason": "Conditional result was False"}
	acked := map[string]any{
		"ipa_auth_cache_prepare":   ran(0, `{"previous": true}`),
		"ipa_auth_cache_settle":    ran(0, `{"dirty": true}`),
		"ipa_auth_cache_ack":       ran(0, ""),
		"ipa_sudo_refresh_results": map[string]any{"results": []any{map[string]any{"rc": 0, "item": "c1"}, map[string]any{"rc": 0, "item": "c2"}}},
	}
	with := func(base map[string]any, over map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range over {
			if v == nil {
				delete(out, k)
				continue
			}
			out[k] = v
		}
		return out
	}
	dirty := func(b bool) *bool { return &b }

	for _, tc := range []struct {
		name  string
		facts map[string]any
		extra []string
		want  AuthCacheResult // Host and FQDN are filled in
	}{
		{name: "acknowledged", facts: acked, want: AuthCacheResult{Prepared: true, Dirty: dirty(true), Refreshed: true, Acked: true}},
		{name: "the refresh option off: the ack was skipped", facts: with(acked, map[string]any{"ipa_auth_cache_ack": skipped, "ipa_sudo_refresh_results": skipped}),
			want: AuthCacheResult{Prepared: true, Dirty: dirty(true)}},
		{name: "a deferred client: the ack was skipped, the refresh ran for the others", facts: with(acked, map[string]any{"ipa_auth_cache_ack": skipped}),
			want: AuthCacheResult{Prepared: true, Dirty: dirty(true), Refreshed: true}},
		{name: "nothing was dirty: acknowledged without a refresh", facts: with(acked, map[string]any{
			"ipa_auth_cache_settle": ran(0, `{"dirty": false}`), "ipa_sudo_refresh_results": skipped}),
			want: AuthCacheResult{Prepared: true, Dirty: dirty(false), Acked: true}},
		{name: "a tag selection that skipped prepare, settle, the refresh and the ack", facts: with(acked, map[string]any{
			"ipa_auth_cache_prepare": nil, "ipa_auth_cache_settle": nil, "ipa_auth_cache_ack": nil, "ipa_sudo_refresh_results": nil}),
			want: AuthCacheResult{}},
		{name: "one client did not finish its refresh", facts: with(acked, map[string]any{"ipa_sudo_refresh_results": map[string]any{
			"results": []any{map[string]any{"rc": 0, "item": "c1"}, map[string]any{"rc": 1, "item": "c2"}}}}),
			want: AuthCacheResult{Prepared: true, Dirty: dirty(true), Acked: true}},
		{name: "one client was unreachable", facts: with(acked, map[string]any{"ipa_sudo_refresh_results": map[string]any{
			"results": []any{map[string]any{"rc": 0, "item": "c1"}, map[string]any{"unreachable": true, "item": "c2"}}}}),
			want: AuthCacheResult{Prepared: true, Dirty: dirty(true), Acked: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEntryEnv(t, []string{"srv1"}, nil)
			res := e.runObservation(tasks, tc.facts, tc.extra...)
			if res.rc != 0 {
				t.Fatalf("the observation failed: %v\n%s", res.failed, res.stdout)
			}
			got, err := ParseAuthCacheResult(res.rc, res.result, e.want(AuthCacheObserve))
			if err != nil {
				t.Fatalf("result %q rejected: %v", res.result, err)
			}
			want := tc.want
			want.Action, want.Host, want.FQDN = AuthCacheObserve, got.Host, got.FQDN
			if got.Action != want.Action || got.Prepared != want.Prepared || got.Refreshed != want.Refreshed || got.Acked != want.Acked || (got.Dirty == nil) != (want.Dirty == nil) || (got.Dirty != nil && *got.Dirty != *want.Dirty) {
				t.Fatalf("observation = %+v (dirty %v), want %+v (dirty %v): %s", got, deref(got.Dirty), want, deref(want.Dirty), res.result)
			}
		})
	}

	// Two ways to write nothing: the run was not handed an output path (every run of
	// the legacy engine), and a preview.
	t.Run("no output path: the observation never runs", func(t *testing.T) {
		e := newEntryEnv(t, []string{"srv1"}, nil)
		res := e.runObservationWithout(tasks, acked)
		if res.rc != 0 || len(res.result) != 0 {
			t.Fatalf("rc %d, result %q, failed %v", res.rc, res.result, res.failed)
		}
		if len(res.skipped) != 2 {
			t.Fatalf("skipped %q, want both observation tasks skipped", res.skipped)
		}
	})
	t.Run("check mode: skipped by its when, exit 0, the file stays empty", func(t *testing.T) {
		e := newEntryEnv(t, []string{"srv1"}, nil)
		res := e.runObservation(tasks, acked, "--check")
		if res.rc != 0 || len(res.result) != 0 {
			t.Fatalf("rc %d, result %q, failed %v", res.rc, res.result, res.failed)
		}
		// The point of this case: exit 0 with an empty file is a run that wrote nothing,
		// and the parser must not read it as anything but a rejection.
		if _, err := ParseAuthCacheResult(res.rc, res.result, e.want(AuthCacheObserve)); !errors.Is(err, ErrAuthCacheResult) {
			t.Fatalf("an exit 0 with no result was accepted: %v", err)
		}
	})
}

func deref(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

// observationTasks are the two tasks of the identity playbook's observation, read
// from the real file.
func observationTasks(t *testing.T) []any {
	t.Helper()
	raw, err := os.ReadFile(identityPlaybookPath)
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	tasks, _ := plays[0]["tasks"].([]any)
	block, _ := tasks[0].(map[string]any)["block"].([]any)
	var picked []any
	for _, item := range block {
		m, _ := item.(map[string]any)
		name, _ := m["name"].(string)
		if strings.Contains(name, "authorization cache observation") || strings.Contains(name, "observation for pilot") {
			picked = append(picked, m)
		}
	}
	if len(picked) != 2 {
		t.Fatalf("found %d observation tasks in the identity playbook, want 2", len(picked))
	}
	return picked
}

func (e *entryEnv) runObservation(tasks []any, facts map[string]any, extra ...string) entryOutcome {
	e.t.Helper()
	return e.runObservationPlay(tasks, facts, true, extra...)
}

func (e *entryEnv) runObservationWithout(tasks []any, facts map[string]any, extra ...string) entryOutcome {
	e.t.Helper()
	return e.runObservationPlay(tasks, facts, false, extra...)
}

// runObservationPlay runs the tasks on the host after one set_fact that stands for
// the registers the earlier tasks of the block leave.
func (e *entryEnv) runObservationPlay(tasks []any, facts map[string]any, withOutput bool, extra ...string) entryOutcome {
	e.t.Helper()
	var steps []any
	if len(facts) > 0 { // a tag selection that ran none of the earlier tasks leaves no register at all
		steps = append(steps, map[string]any{"name": "registers of the earlier tasks", "ansible.builtin.set_fact": facts})
	}
	play := []map[string]any{{"hosts": "freeipa-server", "gather_facts": false, "tasks": append(steps, tasks...)}}
	body, err := yaml.Marshal(play)
	if err != nil {
		e.t.Fatal(err)
	}
	path := filepath.Join(e.dir, "observation.yml")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		e.t.Fatal(err)
	}
	return e.runWith(path, withOutput, extra...)
}

// The names the Go side and the playbooks must agree on are written in both: the two
// variables, the schema string, and the action the entry takes. (The keys of each result
// are held to the parser by every test above that runs a playbook and parses what it
// wrote, so a key renamed on one side fails those.)
func TestAuthCacheNamesAgreeWithThePlaybooks(t *testing.T) {
	entry, err := os.ReadFile(entryPlaybookPath)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := os.ReadFile(identityPlaybookPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		file string
		body []byte
		want []string
	}{
		{"the entry", entry, []string{AuthCacheOutputVar, AuthCacheActionVar, AuthCacheSchema, "'" + string(AuthCachePrepare) + "'", "'" + string(AuthCacheProbe) + "'"}},
		{"the identity playbook", identity, []string{AuthCacheOutputVar, AuthCacheSchema, "action: " + string(AuthCacheObserve)}},
	} {
		for _, want := range tc.want {
			if !strings.Contains(string(tc.body), want) {
				t.Errorf("%s does not contain %q, which the Go side (authcache.go) names", tc.file, want)
			}
		}
	}
}
