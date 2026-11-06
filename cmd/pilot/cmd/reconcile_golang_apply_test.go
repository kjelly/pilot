package cmd

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/kjelly/pilot/internal/delivery"
	"github.com/kjelly/pilot/internal/identityreconcile"
	"github.com/kjelly/pilot/internal/outbound"
	"github.com/kjelly/pilot/internal/sshdial"
)

// These tests drive `pilot reconcile --engine golang --force --scope users-groups` through the
// real cobra tree against a TLS FreeIPA that answers from the captured fixtures and, for the
// writes of a scenario, from a small state kept here: the users of the capture plus the ones the
// scenario adds. ansible-playbook is a script that writes the entry's result file the way the
// playbook does (the captured shape), and the lock is the in-memory one. What they prove is the
// command's plumbing from the flags to the exit code, the delivery run, the journal in the store,
// the result file and the outbound event; the executor's own rules are in internal/identityreconcile.

// applyFake is the scripted server of a scenario.
type applyFake struct {
	f  *fakeIPA
	mu sync.Mutex
	// added are the users a user_add was answered for; user_find lists them after it.
	added []string
	// writes are the methods of every write command received, in order.
	writes []string
	// onWrite runs when a batch with a write arrives, before it is answered.
	onWrite func(methods []string)
	// failItem makes the answer to "<method>:<name>" a captured error item.
	failItem map[string]string
}

func newApplyFake(f *fakeIPA) *applyFake {
	a := &applyFake{f: f, failItem: map[string]string{}}
	f.respond = a.respond
	return a
}

func (a *applyFake) addedEntry(name string) map[string]any {
	// A user of the capture, renamed: what a real server lists for a user added with a first
	// and a last name.
	var env map[string]any
	if err := json.Unmarshal(a.f.fixture("user-find-states"), &env); err != nil {
		a.f.t.Fatal(err)
	}
	src := env["result"].(map[string]any)["result"].([]any)[0].(map[string]any)
	e := map[string]any{}
	for k, v := range src {
		e[k] = v
	}
	e["uid"] = []any{name}
	e["cn"] = []any{"P26 New"}
	e["displayname"] = []any{"P26 New"}
	e["givenname"] = []any{"P26"}
	e["sn"] = []any{"New"}
	e["homedirectory"] = []any{"/home/" + name}
	e["mail"] = []any{name + "@ipa.example.test"}
	e["ipauniqueid"] = []any{"0f0f0f0f-0000-4000-8000-" + fmt.Sprintf("%012d", len(a.added))}
	e["uidnumber"] = []any{"1927609999"}
	e["gidnumber"] = []any{"1927609999"}
	e["memberof_group"] = []any{"ipausers"}
	e["krbprincipalname"] = []any{name + "@IPA.PILOT.INTERNAL"}
	e["krbcanonicalname"] = []any{name + "@IPA.PILOT.INTERNAL"}
	e["dn"] = "uid=" + name + ",cn=users,cn=accounts,dc=ipa,dc=pilot,dc=internal"
	delete(e, "ipasshpubkey")
	delete(e, "sshpubkeyfp")
	delete(e, "mepmanagedentry")
	e["loginshell"] = []any{"/bin/bash"}
	return e
}

func (a *applyFake) respond(method string, params []any) (string, bool) {
	opts, _ := params[1].(map[string]any)
	switch method {
	case "user_find":
		if opts["preserved"] == true {
			return "", false
		}
		a.mu.Lock()
		added := slices.Clone(a.added)
		a.mu.Unlock()
		if len(added) == 0 {
			return "", false
		}
		var env map[string]any
		if err := json.Unmarshal(a.f.withAdmins(a.f.fixture("user-find-states")), &env); err != nil {
			a.f.t.Fatal(err)
		}
		res := env["result"].(map[string]any)
		list := res["result"].([]any)
		for _, name := range added {
			list = append(list, a.addedEntry(name))
		}
		res["result"], res["count"], res["summary"] = list, len(list), fmt.Sprintf("%d users matched", len(list))
		out, _ := json.Marshal(env)
		return string(out), true
	case "batch":
		cmds, _ := params[0].([]any)
		var methods []string
		items := make([]any, 0, len(cmds))
		wrote := false
		for _, c := range cmds {
			cm := c.(map[string]any)
			m, _ := cm["method"].(string)
			cp, _ := cm["params"].([]any)
			var args []any
			if len(cp) > 0 {
				args, _ = cp[0].([]any)
			}
			name := ""
			if len(args) > 0 {
				name, _ = args[0].(string)
			}
			methods = append(methods, m)
			if strings.HasSuffix(m, "_show") {
				return "", false
			}
			wrote = true
			if fixture, ok := a.failItem[m+":"+name]; ok {
				var env map[string]any
				_ = json.Unmarshal(a.f.fixture(fixture), &env)
				items = append(items, map[string]any{
					"error": env["error"].(map[string]any)["message"], "error_code": env["error"].(map[string]any)["code"],
					"error_name": env["error"].(map[string]any)["name"], "error_kw": map[string]any{},
				})
				continue
			}
			if m == "user_add" {
				a.mu.Lock()
				a.added = append(a.added, name)
				a.mu.Unlock()
			}
			items = append(items, map[string]any{"result": map[string]any{"uid": []any{name}}, "value": name, "summary": "ok", "error": nil})
		}
		if !wrote {
			return "", false
		}
		a.mu.Lock()
		a.writes = append(a.writes, methods...)
		hook := a.onWrite
		a.mu.Unlock()
		if hook != nil {
			hook(methods)
		}
		out, _ := json.Marshal(map[string]any{
			"result": map[string]any{"count": len(items), "results": items}, "error": nil, "id": 0,
			"principal": "admin@IPA.PILOT.INTERNAL", "version": "4.13.4",
		})
		return string(out), true
	}
	return "", false
}

func (a *applyFake) writeMethods() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.writes)
}

// fakeEntryPlaybook is ansible-playbook for the entry: it records its argv and writes the
// result file the way freeipa-identity-auth-cache.yml does (the captured shape), as the
// scenario's environment says.
const fakeEntryPlaybook = `#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ["P26_LOG"], "a") as f:
    f.write(json.dumps(args) + "\n")
mode = os.environ.get("P26_ENTRY", "ok")
if mode == "fail":
    sys.stdout.write("fatal: the entry failed\n")
    sys.exit(2)
vars = {}
for a in args:
    if a.startswith("{"):
        vars.update(json.loads(a))
action = vars["pilot_identity_auth_cache_action"]
res = {"schema": "pilot.identity-auth-cache/v1", "action": action, "host": os.environ.get("P26_HOST", "ipa-1"), "fqdn": "ipa.example.test"}
if action == "prepare":
    res["previous"] = os.environ.get("P26_PREVIOUS", "false") == "true"
else:
    res["pending"] = os.environ.get("P26_PENDING", "false") == "true"
if mode != "empty":
    with open(vars["pilot_identity_auth_cache_output"], "w") as f:
        json.dump(res, f)
`

// applyEnv is one scenario's world.
type applyEnv struct {
	t      *testing.T
	f      *fakeIPA
	a      *applyFake
	lock   *fakeIdentityLock
	dir    string
	log    string
	events string
}

func newApplyEnv(t *testing.T, roster string) *applyEnv { return newApplyEnvWith(t, roster, nil) }

// newApplyEnvWith is newApplyEnv with inventory groups (the environment groups the stage gate reads).
func newApplyEnvWith(t *testing.T, roster string, groups map[string][]string) *applyEnv {
	t.Helper()
	f := newFakeIPA(t, "p1-self")
	withFakeDialer(t, f)
	dir := golangWorkspace(t, roster, groups)
	e := &applyEnv{t: t, f: f, a: newApplyFake(f), dir: dir, lock: useFakeIdentityLock(t)}
	e.log = filepath.Join(dir, "playbook.log")
	e.events = filepath.Join(dir, "events.log")
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ansible-playbook"), []byte(fakeEntryPlaybook), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("P26_LOG", e.log)
	e.lock.Events = func(s string) { appendEvent(t, e.events, s) }
	return e
}

func applyArgs(more ...string) []string {
	return append([]string{"--engine", "golang", "--force", "--scope", "users-groups", "--component", "freeipa-identity", "--timeout", "2m"}, more...)
}

// rosterWithNewUser is the capture's roster plus one user the server does not have.
func rosterWithNewUser() string {
	return strings.Replace(captureRoster, "%s", "/bin/sh", 1) + "  - {name: p26-new, first: P26, last: New}\n"
}

func (e *applyEnv) playbookCalls() [][]string {
	e.t.Helper()
	var out [][]string
	for _, line := range readEvents(e.t, e.log) {
		var args []string
		if err := json.Unmarshal([]byte(line), &args); err != nil {
			e.t.Fatalf("bad playbook log line %q: %v", line, err)
		}
		out = append(out, args)
	}
	return out
}

// storeDB opens the delivery store the run wrote to.
func storeDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dataDir, "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

type storedRun struct {
	id, outcome string
	exit        int
}

func onlyRun(t *testing.T) storedRun {
	t.Helper()
	db := storeDB(t)
	rows, err := db.Query(`SELECT run_id, COALESCE(outcome, ''), COALESCE(exit_code, -1) FROM delivery_runs`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var runs []storedRun
	for rows.Next() {
		var r storedRun
		if err := rows.Scan(&r.id, &r.outcome, &r.exit); err != nil {
			t.Fatal(err)
		}
		runs = append(runs, r)
	}
	if len(runs) != 1 {
		t.Fatalf("the store holds %d runs, want 1: %+v", len(runs), runs)
	}
	return runs[0]
}

type storedEvent struct {
	op, typ, step string
	payload       map[string]any
	exit          sql.NullInt64
}

func runEvents(t *testing.T, runID string) []storedEvent {
	t.Helper()
	rows, err := storeDB(t).Query(`SELECT operation_id, type, COALESCE(step, ''), payload_json, exit_code FROM delivery_events WHERE run_id=? ORDER BY seq`, runID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []storedEvent
	for rows.Next() {
		var ev storedEvent
		var payload string
		if err := rows.Scan(&ev.op, &ev.typ, &ev.step, &payload, &ev.exit); err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal([]byte(payload), &ev.payload)
		out = append(out, ev)
	}
	return out
}

func eventTypes(evs []storedEvent) []string {
	var out []string
	for _, e := range evs {
		out = append(out, e.typ)
	}
	return out
}

func findEvent(evs []storedEvent, op string) *storedEvent {
	for i := range evs {
		if evs[i].op == op {
			return &evs[i]
		}
	}
	return nil
}

func readApplyDoc(t *testing.T, path string) identityreconcile.ApplyDocument {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the result file: %v", err)
	}
	doc, err := identityreconcile.ParseApplyDocument(data)
	if err != nil {
		t.Fatalf("the result file does not parse: %v\n%s", err, data)
	}
	return doc
}

// One run, from the flags to the exit code, for each way a users-groups run ends (spec §6.2,
// §6.3): what the command returns, how the delivery run ended and at which step, what the
// journal and the result file hold, what ran and in what order, and that nothing leaked.
func TestReconcileGolangApplyEndToEnd(t *testing.T) {
	type want struct {
		exit       int
		outcome    string
		failedStep string
		verdict    string
		// writes are the write methods the server received.
		writes []string
		// playbook are the actions the entry playbook was run with, in order.
		playbook []string
		// types are the delivery event types the journal must hold (all of them).
		events []string
		// errHas is a text the error must hold.
		errHas string
		// noFile: the result file must not exist (the run never reached the first read).
		noFile bool
	}
	for _, tc := range []struct {
		name   string
		gate   string
		roster string
		setup  func(t *testing.T, e *applyEnv)
		want   want
	}{
		{
			name: "a user is added: applied, verified, and the obligation owed (exit 4)", gate: "exit-code-passthrough-apply,entry-golang-apply-dispatch,apply-finish",
			roster: rosterWithNewUser(),
			want: want{exit: 4, outcome: "partial_failed", failedStep: "verify", verdict: "unsettled", writes: []string{"user_add"},
				playbook: []string{"prepare"}, events: []string{"identity.auth_cache", "identity.op", "identity.verify"}, errHas: "授權快取義務未結清"},
		},
		{
			name: "nothing to write and the probe finds nothing owed: success (exit 0)", gate: "exit-code-passthrough-apply",
			roster: strings.Replace(captureRoster, "%s", "/bin/sh", 1),
			setup:  func(t *testing.T, e *applyEnv) { t.Setenv("P26_PENDING", "false") },
			want:   want{exit: 0, outcome: "success", verdict: "ok", playbook: []string{"probe"}, events: []string{"identity.auth_cache"}},
		},
		{
			name: "nothing to write and the probe finds the obligation owed (exit 4)", gate: "exit-code-passthrough-apply",
			roster: strings.Replace(captureRoster, "%s", "/bin/sh", 1),
			setup:  func(t *testing.T, e *applyEnv) { t.Setenv("P26_PENDING", "true") },
			want: want{exit: 4, outcome: "partial_failed", failedStep: "verify", verdict: "unsettled", playbook: []string{"probe"},
				events: []string{"identity.auth_cache"}, errHas: "探測讀到先前的執行留下的義務"},
		},
		{
			name: "a plan with a blocked object: zero writes, no entry (exit 3)", gate: "exit-code-passthrough-apply",
			roster: strings.Replace(strings.Replace(captureRoster, "%s", "/bin/sh", 1), "{name: p1-keys, first: P1,", "{name: p1-keys, uid: 4242, first: P1,", 1),
			want:   want{exit: 3, outcome: "failed", failedStep: "apply", verdict: "blocked", errHas: "blocked objects"},
		},
		{
			name: "the entry fails: nothing is written (exit 1)", gate: "exit-code-1-apply",
			roster: rosterWithNewUser(),
			setup:  func(t *testing.T, e *applyEnv) { t.Setenv("P26_ENTRY", "fail") },
			want: want{exit: 1, outcome: "failed", failedStep: "apply", verdict: "failed", playbook: []string{"prepare"},
				errHas: "authorization cache entry failed"},
		},
		{
			name: "the entry writes no result: nothing is written (exit 1)", gate: "exit-code-1-apply",
			roster: rosterWithNewUser(),
			setup:  func(t *testing.T, e *applyEnv) { t.Setenv("P26_ENTRY", "empty") },
			want: want{exit: 1, outcome: "failed", failedStep: "apply", verdict: "failed", playbook: []string{"prepare"},
				errHas: "authorization cache entry failed"},
		},
		{
			name: "the entry names another host: nothing is written (exit 1)", gate: "exit-code-1-apply",
			roster: rosterWithNewUser(),
			setup:  func(t *testing.T, e *applyEnv) { t.Setenv("P26_HOST", "ipa-2") },
			want: want{exit: 1, outcome: "failed", failedStep: "apply", verdict: "failed", playbook: []string{"prepare"},
				errHas: "authorization cache entry failed"},
		},
		{
			name: "a write fails after another was applied: partial (exit 1)", gate: "exit-code-1-apply",
			roster: rosterWithNewUser() + "  - {name: p26-two, first: P26, last: Two}\n",
			setup: func(t *testing.T, e *applyEnv) {
				// The batch of S3 answers p26-new as added and p26-two with a duplicate.
				e.a.failItem["user_add:p26-two"] = "user-add-duplicate"
			},
			want: want{exit: 1, outcome: "partial_failed", failedStep: "apply", verdict: "partial", writes: []string{"user_add", "user_add"},
				playbook: []string{"prepare"}, events: []string{"identity.auth_cache", "identity.op", "identity.verify"}, errHas: "not every planned operation was applied"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("gate: %s", tc.gate)
			e := newApplyEnv(t, tc.roster)
			if tc.setup != nil {
				tc.setup(t, e)
			}
			result := filepath.Join(e.dir, "result.json")
			out, err := runReconcileCLI(t, applyArgs("--result-out", result)...)
			if got := processExitCode(err); got != tc.want.exit {
				if data, rerr := os.ReadFile(result); rerr == nil {
					if doc, perr := identityreconcile.ParseApplyDocument(data); perr == nil && doc.Plan3 != nil {
						raw, _ := json.Marshal(doc.Plan3.Operations)
						t.Logf("plan3: %s", raw)
					}
				}
				t.Fatalf("exit %d (err %v), want %d\n%s", got, err, tc.want.exit, out)
			}
			if tc.want.errHas != "" && (err == nil || !strings.Contains(err.Error(), tc.want.errHas)) {
				t.Fatalf("err = %v, want one holding %q\n%s", err, tc.want.errHas, out)
			}
			if got := e.a.writeMethods(); !slices.Equal(got, tc.want.writes) {
				t.Fatalf("the server received writes %v, want %v", got, tc.want.writes)
			}
			var actions []string
			for _, args := range e.playbookCalls() {
				for _, a := range args {
					if strings.HasPrefix(a, "{") {
						var v map[string]string
						_ = json.Unmarshal([]byte(a), &v)
						actions = append(actions, v["pilot_identity_auth_cache_action"])
					}
				}
			}
			if !slices.Equal(actions, tc.want.playbook) {
				t.Fatalf("the entry ran with %v, want %v", actions, tc.want.playbook)
			}
			// The lock was taken before anything ran and given back after: the events are in one order.
			evs := readEvents(t, e.events)
			if len(evs) < 2 || evs[0] != "lock ipa-1" || evs[len(evs)-1] != "release ipa-1" {
				t.Fatalf("lock events = %v, want the run between lock and release", evs)
			}
			run := onlyRun(t)
			if run.outcome != tc.want.outcome {
				t.Fatalf("the delivery run ended %q, want %q", run.outcome, tc.want.outcome)
			}
			wantRunExit := 1
			if tc.want.outcome == "success" {
				wantRunExit = 0
			}
			if run.exit != wantRunExit {
				t.Errorf("the run's exit code is %d, want %d (outcomeExitCode, not the command's)", run.exit, wantRunExit)
			}
			stored := runEvents(t, run.id)
			for _, typ := range tc.want.events {
				if !slices.Contains(eventTypes(stored), typ) {
					t.Errorf("the journal has no %s event: %v", typ, eventTypes(stored))
				}
			}
			if tc.want.failedStep != "" {
				ev := findEvent(stored, "step-"+tc.want.failedStep)
				if ev == nil || !ev.exit.Valid || ev.exit.Int64 != 1 {
					t.Errorf("no failed step_finished event for %s: %+v", tc.want.failedStep, ev)
				}
			}
			doc := readApplyDoc(t, result)
			if doc.Verdict != tc.want.verdict || doc.ExitCode != tc.want.exit || doc.Outcome != tc.want.outcome || doc.FailedStep != tc.want.failedStep {
				t.Errorf("result file: verdict %s exit %d outcome %s step %q; want %s %d %s %q", doc.Verdict, doc.ExitCode, doc.Outcome, doc.FailedStep, tc.want.verdict, tc.want.exit, tc.want.outcome, tc.want.failedStep)
			}
			if doc.RunID != run.id || doc.Schema != identityreconcile.ApplyDocumentSchema || !doc.Observed {
				t.Errorf("result file: run %q (store %q), schema %q, observed %v", doc.RunID, run.id, doc.Schema, doc.Observed)
			}
			assertNoSecretAnywhere(t, err, out, result)
		})
	}
}

// What the entry playbook is asked: the playbook of the entry, on the one host, with the stage
// variables and the output path as a JSON object, no tags and no vault.
func TestReconcileGolangApplyRunsTheEntryAsSpecified(t *testing.T) {
	e := newApplyEnv(t, rosterWithNewUser())
	out, err := runReconcileCLI(t, applyArgs()...)
	if processExitCode(err) != 4 {
		t.Fatalf("exit %d (%v)\n%s", processExitCode(err), err, out)
	}
	calls := e.playbookCalls()
	if len(calls) != 1 {
		t.Fatalf("the entry ran %d times, want once", len(calls))
	}
	args := calls[0]
	if !strings.HasSuffix(args[0], "playbooks/apply/freeipa-identity-auth-cache.yml") {
		t.Errorf("the playbook is %q", args[0])
	}
	joined := " " + strings.Join(args, " ") + " "
	for _, want := range []string{" --limit ipa-1 ", " -e stage=sandbox ", " -i "} {
		if !strings.Contains(joined, want) {
			t.Errorf("argv %v lacks %q", args, want)
		}
	}
	for _, bad := range []string{"--tags", "--skip-tags", "--check", "-t ", "--ask-vault-pass", "--vault-password-file"} {
		if strings.Contains(joined, bad) {
			t.Errorf("argv %v holds %q: the entry takes none", args, bad)
		}
	}
	if !strings.Contains(joined, `"pilot_identity_auth_cache_action":"prepare"`) || !strings.Contains(joined, `"pilot_identity_auth_cache_output":"/`) {
		t.Errorf("the entry's variables are not a JSON object with the action and an absolute output path: %v", args)
	}
	assertNoSecretAnywhere(t, err, out, "")
}

// A busy lock is a refusal before anything connects: no tunnel, no login, no run, no file, no
// playbook (spec §10.2 A9, the 0 case); the message names the lock and says nothing was written.
func TestReconcileGolangApplyWithABusyLockConnectsToNothing(t *testing.T) {
	e := newApplyEnv(t, rosterWithNewUser())
	e.lock.Err = fmt.Errorf("FreeIPA server ipa-1 的 /etc/ipa 鎖被另一輪 freeipa-identity 執行持有: %w", sshdial.ErrLockBusy)
	targets := withFakeDialer(t, e.f)
	result := filepath.Join(e.dir, "result.json")
	out, err := runReconcileCLI(t, applyArgs("--lock-wait", "0", "--result-out", result)...)
	if processExitCode(err) != 1 || err == nil || !strings.Contains(err.Error(), "沒有取得鎖，沒有任何寫入") || !errors.Is(err, sshdial.ErrLockBusy) {
		t.Fatalf("exit %d, err = %v\n%s", processExitCode(err), err, out)
	}
	if reqs := e.lock.Requests(); len(reqs) != 1 || reqs[0].Wait != 0 || !slices.Equal(reqs[0].Hosts, []string{"ipa-1"}) {
		t.Fatalf("the lock request = %+v, want a wait of 0 for the one host", reqs)
	}
	assertNoLogin(t, e.f)
	if len(*targets) != 0 {
		t.Fatalf("a tunnel was built: %+v", *targets)
	}
	if len(e.playbookCalls()) != 0 || len(e.a.writeMethods()) != 0 {
		t.Fatalf("the entry ran or a write was sent with the lock busy")
	}
	if _, serr := os.Stat(result); serr == nil {
		t.Fatal("a result file exists for a run that never started")
	}
	if _, serr := os.Stat(filepath.Join(dataDir, "history.db")); serr == nil {
		if rows, err := storeDB(t).Query(`SELECT 1 FROM delivery_runs`); err == nil {
			defer rows.Close()
			if rows.Next() {
				t.Fatal("a delivery run was recorded for a run that never started")
			}
		}
	}
	assertNoSecretAnywhere(t, err, out, result)
}

// The precheck is the lock's own derivation: an inventory it cannot lock is refused before
// the lock is built, the dialer made or anything connected (the funnel lint orders it in the
// source; this is the behavior).
func TestReconcileGolangApplyRefusesAnInventoryItCannotLockBeforeAnythingConnects(t *testing.T) {
	e := newApplyEnv(t, rosterWithNewUser())
	e.lock.PrecheckErr = errors.New("ansible_connection=docker: the lock is an ssh session")
	targets := withFakeDialer(t, e.f)
	out, err := runReconcileCLI(t, applyArgs()...)
	if processExitCode(err) != 1 || err == nil || !strings.Contains(err.Error(), "取鎖前檢查沒有通過") {
		t.Fatalf("exit %d, err = %v\n%s", processExitCode(err), err, out)
	}
	if reqs := e.lock.Requests(); len(reqs) != 0 {
		t.Fatalf("a lock was built after the precheck refused: %+v", reqs)
	}
	assertNoLogin(t, e.f)
	if len(*targets) != 0 || len(e.playbookCalls()) != 0 {
		t.Fatalf("something connected or ran: %v %v", *targets, e.playbookCalls())
	}
}

// --result-out is created before anything is read: a path that exists is refused with the
// file untouched, and a run that never reaches the first read leaves none.
func TestReconcileGolangApplyResultFileLifecycle(t *testing.T) {
	t.Run("an existing path is refused before anything is read", func(t *testing.T) {
		e := newApplyEnv(t, rosterWithNewUser())
		calls := toolCalls(t)
		result := filepath.Join(e.dir, "result.json")
		if err := os.WriteFile(result, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := runReconcileCLI(t, applyArgs("--result-out", result)...)
		if processExitCode(err) != 1 || err == nil || !strings.Contains(err.Error(), "已存在；不覆寫") {
			t.Fatalf("exit %d, err = %v\n%s", processExitCode(err), err, out)
		}
		if got := calls(); len(got) != 0 {
			t.Fatalf("read the workspace before refusing: %v", got)
		}
		if data, _ := os.ReadFile(result); string(data) != "keep" {
			t.Fatalf("the existing file was changed to %q", data)
		}
		assertNoLogin(t, e.f)
	})
	t.Run("a run that fails before the first read leaves no file", func(t *testing.T) {
		e := newApplyEnv(t, rosterWithNewUser())
		golangDialerFaults.fqdnErr = errors.New("the tunnel ssh failed")
		result := filepath.Join(e.dir, "result.json")
		out, err := runReconcileCLI(t, applyArgs("--result-out", result)...)
		if processExitCode(err) != 1 || err == nil || !strings.Contains(err.Error(), "the tunnel ssh failed") {
			t.Fatalf("exit %d, err = %v\n%s", processExitCode(err), err, out)
		}
		noPlan(t, result)
		if evs := readEvents(t, e.events); len(evs) != 2 || evs[0] != "lock ipa-1" || evs[1] != "release ipa-1" {
			t.Fatalf("lock events = %v: the lock must be given back when the run does not start", evs)
		}
	})
	t.Run("the result file is private and only written for a run that was observed", func(t *testing.T) {
		e := newApplyEnv(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1))
		result := filepath.Join(e.dir, "result.json")
		out, err := runReconcileCLI(t, applyArgs("--result-out", result)...)
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		info, serr := os.Stat(result)
		if serr != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("result file: %v %v", serr, info)
		}
		doc := readApplyDoc(t, result)
		if doc.Verdict != identityreconcile.VerdictOK || doc.Authorization.Owed || doc.Authorization.ProbePending == nil || *doc.Authorization.ProbePending {
			t.Fatalf("result file of an idle run: %+v", doc.Authorization)
		}
		if !strings.Contains(out, "result JSON：") {
			t.Fatalf("the file is not announced:\n%s", out)
		}
	})
}

// outputFile on its own: a write that fails removes the file (#274), and discard leaves a
// committed file alone.
func TestOutputFileRemovesWhatItCouldNotWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	o, err := reserveOutput("--result-out", path)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Size() != 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("the reserved file: %v %v", info, err)
	}
	_ = o.f.Close() // the next write fails
	if err := commitOutput(o, []byte("data")); err == nil {
		t.Fatal("a write on a closed file succeeded")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a file that could not be written was left behind (#274)")
	}
	// A committed file survives discard (the deferred call of every run).
	o, err = reserveOutput("--result-out", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := commitOutput(o, []byte("data")); err != nil {
		t.Fatal(err)
	}
	o.discard()
	if data, err := os.ReadFile(path); err != nil || string(data) != "data" {
		t.Fatalf("a committed file after discard: %q %v", data, err)
	}
	// nil is a reservation of nothing.
	var none *outputFile
	none.discard()
	if err := commitOutput(none, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if got, err := reserveOutput("--result-out", ""); got != nil || err != nil {
		t.Fatalf("an empty value reserved %v, %v", got, err)
	}
}

// The exit code is decided from the error, blocked first: a journal that also failed does not
// turn a blocked plan into another kind of failure, and a stop recorded on a result does not
// matter (it is not an input).
func TestGolangApplyExitCodeFollowsTheErrorOnly(t *testing.T) {
	journal := fmt.Errorf("%w: disk full", identityreconcile.ErrJournal)
	blocked := fmt.Errorf("%w: uid_or_gid_change alice", identityreconcile.ErrBlocked)
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{"success", nil, 0},
		{"blocked", blocked, 3},
		{"blocked and the journal failed", errors.Join(blocked, journal), 3},
		{"the journal failed alone", journal, 1},
		{"the obligation is owed", fmt.Errorf("verify failed: %w: x", identityreconcile.ErrUnsettled), 4},
		{"the writes failed", fmt.Errorf("%w: 1 failed", identityreconcile.ErrWrites), 1},
		{"verify failed", fmt.Errorf("%w: left", identityreconcile.ErrVerify), 1},
		{"writes failed and verify failed", errors.Join(identityreconcile.ErrWrites, identityreconcile.ErrVerify), 1},
		{"the entry failed", fmt.Errorf("%w: exit 2", identityreconcile.ErrEntry), 1},
		{"a destructive diff", fmt.Errorf("%w: user.delete x", identityreconcile.ErrDestructiveDiff), 1},
		{"another error", errors.New("boom"), 1},
	} {
		if got := golangApplyExitCode(tc.err); got != tc.want {
			t.Errorf("%s: exit %d, want %d", tc.name, got, tc.want)
		}
	}
}

// The step errors, row by row, through a real Transaction: the outcome and the step each
// kind of Result ends with (spec §6.1, §6.2, §7.6).
func TestGolangApplyStepsEndTheTransactionAsTheSpecSays(t *testing.T) {
	applied := identityreconcile.OpResult{Operation: identityreconcile.Operation{ID: "user.create:a", Object: "a"}, Outcome: identityreconcile.OutcomeSuccess}
	unknown := identityreconcile.OpResult{Operation: identityreconcile.Operation{ID: "user.create:a", Object: "a"}, Outcome: identityreconcile.OutcomeUnknown, Resolution: "still-unknown"}
	failed := identityreconcile.OpResult{Operation: identityreconcile.Operation{ID: "user.create:a", Object: "a"}, Outcome: identityreconcile.OutcomeFailed}
	no := false
	ran := identityreconcile.EntryReport{Ran: true}
	for _, tc := range []struct {
		name     string
		res      *identityreconcile.Result
		err      error
		outcome  delivery.Outcome
		step     string
		unsettle bool
	}{
		{"applied and verified, the entry ran", &identityreconcile.Result{Observed: true, Entry: ran, Ops: []identityreconcile.OpResult{applied}}, nil, delivery.OutcomePartialFailed, "verify", true},
		{"idle, the probe found it owing", &identityreconcile.Result{Observed: true, Entry: identityreconcile.EntryReport{Pending: ptr(true)}}, nil, delivery.OutcomePartialFailed, "verify", true},
		{"idle, the probe found nothing owed", &identityreconcile.Result{Observed: true, Entry: identityreconcile.EntryReport{Pending: &no}}, nil, delivery.OutcomeSuccess, "", false},
		{"a write failed after one was applied", &identityreconcile.Result{Observed: true, Entry: ran, Ops: []identityreconcile.OpResult{applied, failed}}, identityreconcile.ErrWrites, delivery.OutcomePartialFailed, "apply", false},
		{"every write failed: nothing changed", &identityreconcile.Result{Observed: true, Entry: ran, Ops: []identityreconcile.OpResult{failed}}, identityreconcile.ErrWrites, delivery.OutcomeFailed, "apply", false},
		{"an outcome is unknown", &identityreconcile.Result{Observed: true, Entry: ran, Ops: []identityreconcile.OpResult{unknown}}, identityreconcile.ErrWrites, delivery.OutcomePartialFailed, "apply", false},
		{"only the read after the writes failed, a write committed", &identityreconcile.Result{Observed: true, Entry: ran, Ops: []identityreconcile.OpResult{applied}}, identityreconcile.ErrVerify, delivery.OutcomePartialFailed, "verify", false},
		{"only the read after the writes failed, nothing committed", &identityreconcile.Result{Observed: true, Entry: ran}, identityreconcile.ErrVerify, delivery.OutcomeFailed, "verify", false},
		{"blocked before the entry", &identityreconcile.Result{Observed: true}, identityreconcile.ErrBlocked, delivery.OutcomeFailed, "apply", false},
		{"the entry failed", &identityreconcile.Result{Observed: true}, identityreconcile.ErrEntry, delivery.OutcomeFailed, "apply", false},
		{"blocked after the entry ran: failed, with the note", &identityreconcile.Result{Observed: true, Entry: ran}, identityreconcile.ErrBlocked, delivery.OutcomeFailed, "apply", false},
		{"the journal failed after a write", &identityreconcile.Result{Observed: true, Entry: ran, Ops: []identityreconcile.OpResult{applied}}, identityreconcile.ErrJournal, delivery.OutcomePartialFailed, "apply", false},
		{"Execute never got a result", nil, errors.New("no lock"), delivery.OutcomeFailed, "apply", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := delivery.Transaction{
				IdempotencyPolicy: delivery.IdempotencyNever, RollbackPolicy: delivery.RollbackNone,
				Apply:  func(context.Context) error { return applyStepError(tc.res, tc.err) },
				Verify: func(context.Context) error { return verifyStepError(tc.res, tc.err) },
			}
			res, err := tx.RunResult(context.Background())
			if res.Outcome != tc.outcome || res.FailedStep != tc.step {
				t.Fatalf("outcome %s at %q (err %v), want %s at %q", res.Outcome, res.FailedStep, err, tc.outcome, tc.step)
			}
			if errors.Is(err, identityreconcile.ErrUnsettled) != tc.unsettle {
				t.Fatalf("ErrUnsettled in %v: %v, want %v", err, errors.Is(err, identityreconcile.ErrUnsettled), tc.unsettle)
			}
			if tc.err != nil && err != nil && !errors.Is(err, tc.err) {
				t.Fatalf("the cause %v was lost from %v", tc.err, err)
			}
			if tc.outcome == delivery.OutcomePartialFailed && !errors.Is(err, delivery.ErrPartiallyApplied) {
				t.Fatalf("a partial_failed run's error does not wrap ErrPartiallyApplied: %v", err)
			}
			if tc.name == "blocked after the entry ran: failed, with the note" && !strings.Contains(err.Error(), "入口已執行") {
				t.Fatalf("the failure after the entry ran does not say so: %v", err)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

// publishedEvents reads the failure event a run left in the outbox, from the receiver or, when
// it was not delivered in time, from the outbox itself.
func outboxResults(t *testing.T) []string {
	t.Helper()
	db, err := outbound.OpenOutboxDB(filepath.Join(dataDir, "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT result FROM webhook_outbox ORDER BY sequence`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// The webhook of a users-groups run (spec §6.2): partial_failed is a failure whose class is
// verify_failed at verify, partial_or_unknown, no confirmed effects; only a run that wrote
// nothing and found nothing owed is a success, with the fixed effects.
func TestReconcileGolangApplyPublishesWhatTheSpecSays(t *testing.T) {
	for _, tc := range []struct {
		name        string
		roster      string
		pending     string
		wantResult  string
		wantClass   string
		wantPhase   string
		wantConfirm string
	}{
		{"an owed obligation is a failure at verify", rosterWithNewUser(), "", "failure", "verify_failed", "verify", ""},
		{"nothing written and nothing owed is a success", strings.Replace(captureRoster, "%s", "/bin/sh", 1), "false", "success", "", "", "identity.groups,identity.users"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newApplyEnv(t, tc.roster)
			capture := newWebhookCapture(0)
			srv := newWebhookServer(t, capture)
			writeOutboundWorkflowIntegrationsYAML(t, e.dir, srv.URL, fmt.Sprintf("      - operation: reconcile\n        result: %s\n        payload: snapshot\n", tc.wantResult))
			t.Setenv("PILOT_W_TEST_TOKEN", "w-test-secret")
			if tc.pending != "" {
				t.Setenv("P26_PENDING", tc.pending)
			}
			out, err := runReconcileCLI(t, applyArgs()...)
			_ = err
			if capture.count() != 1 {
				t.Fatalf("webhook deliveries = %d, want 1; outbox %v\n%s", capture.count(), outboxResults(t), out)
			}
			var body map[string]any
			if err := json.Unmarshal(capture.last(), &body); err != nil {
				t.Fatal(err)
			}
			op, _ := body["operation"].(map[string]any)
			state, _ := body["state"].(map[string]any)
			if op["result"] != tc.wantResult {
				t.Fatalf("operation.result = %v, want %s", op["result"], tc.wantResult)
			}
			var confirmed []string
			for _, c := range state["confirmed_effects"].([]any) {
				confirmed = append(confirmed, fmt.Sprint(c))
			}
			if strings.Join(confirmed, ",") != tc.wantConfirm {
				t.Errorf("confirmed_effects = %v, want [%s]", confirmed, tc.wantConfirm)
			}
			if tc.wantClass != "" {
				failure, _ := body["failure"].(map[string]any)
				if failure["class"] != tc.wantClass || failure["phase"] != tc.wantPhase {
					t.Errorf("failure = %v, want class %s at %s", failure, tc.wantClass, tc.wantPhase)
				}
				if state["application_consistency"] != "partial_or_unknown" {
					t.Errorf("application_consistency = %v", state["application_consistency"])
				}
			}
			if strings.Contains(string(capture.last()), golangTestPassword) {
				t.Fatal("the admin password is in the webhook body")
			}
		})
	}
}

// newWebhookServer is the receiver a scenario's integrations.yaml points at.
func newWebhookServer(t *testing.T, c *webhookCapture) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(c.handler())
	t.Cleanup(srv.Close)
	return srv
}
