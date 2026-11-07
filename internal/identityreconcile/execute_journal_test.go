package identityreconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/freeiparpc"
	"github.com/kjelly/pilot/internal/identitylock"
	"github.com/kjelly/pilot/internal/identitylock/identitylocktest"
)

// The journal (spec §7.7), the class rule for what a run records after it was
// cancelled (§4.4), the secrets rule (I6), the gate, and the guarantee that the
// executor is not reachable from anywhere yet.

func TestExecuteRecordsEachBatchBeforeAndAfterItIsSent(t *testing.T) {
	e := newRunEnv(t, fullRoster)
	seedFullRoster(e.f)
	var atFirstWrite []string
	e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
		if atFirstWrite == nil && isWrite(c.method) {
			atFirstWrite = e.journal.ids()
		}
		return nil, nil, false
	}
	e.mustApply()
	ids := e.journal.ids()
	if !slices.Equal(atFirstWrite, []string{"auth_cache", "S1-b1:sending"}) {
		t.Fatalf("when the first write arrived the journal held %v: the entry and the record of that batch, nothing after", atFirstWrite)
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("event id %s twice: a store refuses the second one with another payload", id)
		}
		seen[id] = true
	}
	// Every sending has its result after it, and the verification is last.
	for i, id := range ids {
		if base, ok := strings.CutSuffix(id, ":sending"); ok && !slices.Contains(ids[i+1:], base+":result") {
			t.Fatalf("%s has no result after it: %v", id, ids)
		}
	}
	if ids[len(ids)-1] != "verify" || ids[0] != "auth_cache" {
		t.Fatalf("journal = %v", ids)
	}
	for _, ev := range e.journal.events {
		switch ev.Kind {
		case EventOp, EventVerify, EventAuthCache:
		default:
			t.Fatalf("event kind %q", ev.Kind)
		}
	}
	// A result event lists the outcome of each of its operations.
	var sawResult bool
	for _, ev := range e.journal.events {
		if strings.HasSuffix(ev.ID, ":result") {
			sawResult = true
			rs := ev.Payload.(resultEvent).Results
			if len(rs) == 0 || rs[0].Outcome == "" {
				t.Fatalf("%s: %+v", ev.ID, rs)
			}
		}
	}
	if !sawResult || len(e.journal.problem) != 0 {
		t.Fatalf("results %v, problems %v", sawResult, e.journal.problem)
	}
}

// A batch whose record could not be written is not sent (fail closed): the record of
// a run is made of what was done, so what is not recorded is not done.
func TestExecuteDoesNotSendWhatItCouldNotRecord(t *testing.T) {
	e := newRunEnv(t, fullRoster)
	seedFullRoster(e.f)
	e.journal.failOn = func(ev Event) error {
		if ev.ID == "S3-b1:sending" {
			return errors.New("disk full")
		}
		return nil
	}
	res, err := e.execute()
	if !errors.Is(err, ErrWrites) {
		t.Fatalf("err = %v", err)
	}
	for _, w := range e.f.writes() {
		if strings.HasPrefix(w, "user_add") || strings.HasPrefix(w, "passwd") || strings.HasPrefix(w, "user_del") {
			t.Fatalf("a write was sent after its record failed: %v", e.f.writes())
		}
	}
	if res.outcomeOf("user.create:alice") != OutcomeNotExecuted || res.Stop == nil || res.Stop.Stage != "S3" || !strings.Contains(res.Stop.Reason, "journal") {
		t.Fatalf("outcomes:%s", describeOps(res))
	}
	if res.JournalError == "" || !errors.Is(err, ErrJournal) {
		t.Fatalf("the journal failure is not reported: %q / %v", res.JournalError, err)
	}
}

func TestExecuteWritesNothingWhenTheEntryCannotBeRecorded(t *testing.T) {
	e := newRunEnv(t, fullRoster)
	seedFullRoster(e.f)
	e.journal.failOn = func(ev Event) error {
		if ev.Kind == EventAuthCache {
			return errors.New("disk full")
		}
		return nil
	}
	res, err := e.execute()
	if !errors.Is(err, ErrJournal) || len(e.f.writes()) != 0 || len(res.Ops) != 0 {
		t.Fatalf("err %v, writes %v", err, e.f.writes())
	}
}

// A result that cannot be recorded does not undo the writes: the run finishes,
// reads, and reports the journal as failed.
func TestExecuteFinishesAndReportsAResultItCouldNotRecord(t *testing.T) {
	e := newRunEnv(t, fullRoster)
	seedFullRoster(e.f)
	e.journal.failOn = func(ev Event) error {
		if ev.ID == "S1-b1:result" {
			return errors.New("disk full")
		}
		return nil
	}
	res, err := e.execute()
	if !errors.Is(err, ErrJournal) || errors.Is(err, ErrWrites) || !res.Verify.OK() || res.Counts()[OutcomeSuccess] != len(res.Ops) {
		t.Fatalf("err %v, verify %+v, counts %v", err, res.Verify, res.Counts())
	}
}

// After the run's context is cancelled, the journal is still written on a context
// that is not, and bounded; so is the read after the writes (spec §4.4, T1).
func TestExecuteRecordsAndReadsAfterTheRunWasCancelled(t *testing.T) {
	e := newRunEnv(t, fullRoster)
	seedFullRoster(e.f)
	ctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
		if c.method == "user_add" && c.args[0] == "alice" {
			cancel() // Ctrl-C while the S3 batch is being answered
		}
		return nil, nil, false
	}
	res, err := executeWithin(ctx, e.f, e.opts)
	if !errors.Is(err, ErrWrites) {
		t.Fatalf("err = %v", err)
	}
	// The next stage's re-read found the context cancelled: it cannot prove its
	// precondition, so the password is not sent (and nothing after it is). A write
	// that was cut off in flight is unknown instead (the model does that for a
	// write on a cancelled context).
	if o := res.op("user.password.initialize:alice"); o.Outcome != OutcomeConflictFailed || slices.Contains(e.f.writes(), "passwd alice") {
		t.Fatalf("after the cancel:%s", describeOps(res))
	}
	if len(e.journal.problem) != 0 {
		t.Fatalf("the journal was written on the cancelled context: %v", e.journal.problem)
	}
	if !slices.Contains(e.journal.ids(), "verify") || !res.Verify.Done || res.Verify.ReadError != "" {
		t.Fatalf("journal %v, verify %+v: the read and its record come after a cancel", e.journal.ids(), res.Verify)
	}
	last := e.f.calls[len(e.f.calls)-1]
	if last.ctxErr != nil {
		t.Fatalf("the last read ran on a cancelled context: %v", last.ctxErr)
	}
}

// No secret reaches the journal, the result, an error or a formatting of either, on
// any path: the sentinel password is only ever in the command that sets it.
func TestExecuteKeepsThePasswordOutOfEverythingItReturnsAndRecords(t *testing.T) {
	roster := rosterWith("  - {name: ua, "+pw("a")+"}\n  - {name: ub, "+pw("b")+"}\n", "")
	for name, mod := range map[string]func(e *runEnv){
		"a clean run": func(e *runEnv) {},
		"a server error that echoes the password": func(e *runEnv) {
			e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
				if c.method == "passwd" {
					return nil, &freeiparpc.RPCError{Code: 4203, Name: "DatabaseError", Message: "rejected " + c.opts["password"].(string)}, true
				}
				return nil, nil, false
			}
		},
		"an unknown outcome whose error holds the password": func(e *runEnv) {
			e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
				if c.method == "passwd" {
					return nil, &freeiparpc.OutcomeUnknownError{Method: "passwd", Err: errors.New("write: " + c.opts["password"].(string))}, true
				}
				return nil, nil, false
			}
		},
		"a transport error before sending": func(e *runEnv) {
			e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
				if c.method == "passwd" {
					return nil, &freeiparpc.TransportError{Err: errors.New("dial " + c.opts["password"].(string)), Sent: false}, true
				}
				return nil, nil, false
			}
		},
		"a journal that fails": func(e *runEnv) {
			e.journal.failOn = func(ev Event) error { return errors.New("disk full") }
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newRunEnv(t, roster)
			mod(e)
			res, err := e.execute()
			sawPassword := false
			for _, c := range e.f.calls {
				if c.method == "passwd" {
					if pw, _ := c.opts["password"].(string); strings.Contains(pw, pwSecret) {
						sawPassword = true
					}
				} else if raw, _ := json.Marshal(c.opts); strings.Contains(string(raw), pwSecret) {
					t.Fatalf("the password is in a %s command", c.method)
				}
			}
			if !strings.Contains(name, "journal") && !sawPassword {
				t.Fatal("the password never reached the command that sets it: the rows prove nothing")
			}
			raw, _ := json.Marshal(res)
			text := strings.Join([]string{
				string(raw), fmt.Sprintf("%+v", res), fmt.Sprintf("%#v", e.opts.Passwords), fmt.Sprintf("%+v", e.opts), e.journal.all(), fmt.Sprint(err),
			}, "\n")
			if strings.Contains(text, pwSecret) {
				i := strings.Index(text, pwSecret)
				t.Fatalf("the password is in what the run returned or recorded: …%s…", text[max(0, i-60):min(len(text), i+60)])
			}
		})
	}
}

// The gate: lock, entry, host. Release closes it even though Lost does not.
func TestGateNeedsTheLockTheEntryAndTheHost(t *testing.T) {
	lock := &identitylocktest.Fake{Host: "ipa-1"}
	held, err := lock.Acquirer()(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx := held.Attach(context.Background())
	g := NewGate()
	if err := g.Check(context.Background(), "user_add"); !errors.Is(err, identitylock.ErrNoLock) {
		t.Fatalf("no lock in the context: %v", err)
	}
	if err := g.Check(ctx, "user_add"); err == nil || !strings.Contains(err.Error(), "not been observed") {
		t.Fatalf("a lock but no entry observed: %v", err)
	}
	g.open(held)
	if err := g.Check(ctx, "user_add"); err != nil {
		t.Fatalf("lock and entry: %v", err)
	}
	// The entry was observed on another host: the lock here does not open it.
	other := &identitylocktest.Fake{Host: "ipa-2"}
	heldOther, _ := other.Acquirer()(context.Background())
	if err := g.Check(heldOther.Attach(context.Background()), "user_add"); err == nil || !strings.Contains(err.Error(), "ipa-1") {
		t.Fatalf("the entry of another host: %v", err)
	}
	// Lost: the session ended without Release.
	lock.Lose()
	if err := g.Check(ctx, "user_add"); !errors.Is(err, identitylock.ErrLockLost) {
		t.Fatalf("a lost lock: %v", err)
	}
	// Released: Lost stays open, the gate does not (the reason the gate asks Active).
	lock2 := &identitylocktest.Fake{Host: "ipa-1"}
	held2, _ := lock2.Acquirer()(context.Background())
	g2 := NewGate()
	g2.open(held2)
	ctx2 := held2.Attach(context.Background())
	if err := g2.Check(ctx2, "user_add"); err != nil {
		t.Fatal(err)
	}
	_ = held2.Release()
	select {
	case <-held2.Lost():
		t.Fatal("Lost closed on Release: the test would not tell Active from Lost")
	default:
	}
	if err := g2.Check(ctx2, "user_add"); err == nil || !strings.Contains(err.Error(), "released") {
		t.Fatalf("a released lock: %v", err)
	}
	g2.close()
	if err := g2.Check(ctx2, "user_add"); err == nil {
		t.Fatal("a closed gate let a write through")
	}
}

// The gate wired into a client does what freeiparpc's test requires of any gate:
// every write is refused until the entry was observed, with the fake standing for
// the client.
func TestGateRefusesEveryWriteOfTheModelUntilTheEntryIsObserved(t *testing.T) {
	e := newRunEnv(t, fullRoster)
	for _, m := range []string{"user_add", "user_mod", "user_del", "user_enable", "user_disable", "passwd", "group_add", "group_mod", "group_del", "group_add_member", "group_remove_member"} {
		_, err := e.f.Call(e.ctx, freeiparpc.Command{Method: m, Args: []any{"x"}})
		var refused *freeiparpc.ErrWriteRefused
		if !errors.As(err, &refused) {
			t.Errorf("%s: %v", m, err)
		}
	}
	if len(e.f.writes()) != 0 {
		t.Fatalf("writes %v", e.f.writes())
	}
}

// The executor has two entry points: the users-groups apply of the reconcile command (P2-6) and the mixed
// run's Go phase (P2-7), each in a file of its own, under the lock of its run. Nothing else outside this
// package and its tests refers to the things that start a run.
func TestTheExecutorIsReachedOnlyFromTheUsersGroupsApplyAndTheMixedRun(t *testing.T) {
	startsARun := []string{"Execute", "NewGate", "NewAuthCacheEntry", "NewRosterPasswords", "Options"}
	entries := []string{"cmd/pilot/cmd/reconcile_golang_apply.go", "cmd/pilot/cmd/reconcile_golang_mixed.go"}
	problems := reachabilityProblems(t, map[string]string{}, startsARun)
	var want []string
	for _, entry := range entries {
		for _, n := range startsARun {
			want = append(want, entry+": identityreconcile."+n)
		}
	}
	slices.Sort(want)
	if !slices.Equal(problems, want) {
		t.Fatalf("the executor is referred to by %v, want exactly %v (the users-groups apply, the mixed run and nothing else)", problems, want)
	}
	// The scan sees a reference in any other file, through an import alias too.
	fake := map[string]string{"cmd/pilot/cmd/x.go": "package cmd\nimport ir \"github.com/kjelly/pilot/internal/identityreconcile\"\nfunc f() { ir.Execute(nil, nil, ir.Options{}) }\n"}
	if got := reachabilityProblems(t, fake, startsARun); len(got) != len(want)+2 {
		t.Fatalf("a reference through an import alias was not found: %v", got)
	}
}

func reachabilityProblems(t *testing.T, synthetic map[string]string, names []string) []string {
	t.Helper()
	sources := map[string]string{}
	for _, root := range []string{filepath.Join("..", "..", "cmd"), ".."} {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(filepath.Join("..", ".."), path)
			if d.IsDir() && (d.Name() == "testdata" || rel == filepath.Join("internal", "identityreconcile")) {
				return filepath.SkipDir
			}
			if !d.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
				data, rerr := os.ReadFile(path)
				if rerr != nil {
					return rerr
				}
				sources[rel] = string(data)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range synthetic {
		sources[k] = v
	}
	var problems []string
	fset := token.NewFileSet()
	for name, src := range sources {
		file, err := parser.ParseFile(fset, name, src, parser.ImportsOnly|parser.SkipObjectResolution)
		if err != nil {
			continue
		}
		local := ""
		for _, imp := range file.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == "github.com/kjelly/pilot/internal/identityreconcile" {
				local = "identityreconcile"
				if imp.Name != nil {
					local = imp.Name.Name
				}
			}
		}
		if local == "" {
			continue
		}
		full, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
		if err != nil {
			continue
		}
		ast.Inspect(full, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if x, ok := sel.X.(*ast.Ident); ok && x.Name == local && slices.Contains(names, sel.Sel.Name) {
					problems = append(problems, name+": "+local+"."+sel.Sel.Name)
				}
			}
			return true
		})
	}
	slices.Sort(problems)
	return problems
}

// How a planned operation's fields become a command's options: the forms the
// captures show the server takes.
func TestCommandOptionsAreTheFormsTheServerWasCapturedTaking(t *testing.T) {
	create := Operation{ID: "user.create:x", Kind: KindUserCreate, Object: "x", Fields: map[string]Change{
		"givenname": {To: "G"}, "sn": {To: "S"}, "loginshell": {To: ""}, "homedirectory": {To: "/home/x"},
		"displayname": {To: ""}, "mail": {To: []string{}}, "uidnumber": {To: "1234"}, "gidnumber": {To: "5678"},
	}}
	cmd, err := commandFor(create, "")
	if err != nil || cmd.Method != "user_add" {
		t.Fatalf("%+v %v", cmd, err)
	}
	want := map[string]any{"givenname": "G", "sn": "S", "loginshell": "", "homedirectory": "/home/x", "displayname": "", "mail": "", "uidnumber": int64(1234), "gidnumber": int64(5678)}
	if fmt.Sprint(cmd.Options) != fmt.Sprint(want) {
		t.Fatalf("add options %v, want %v", cmd.Options, want)
	}
	mod := Operation{ID: "user.update:x", Kind: KindUserUpdate, Object: "x", Fields: map[string]Change{"mail": {To: []string{}}, "loginshell": {To: ""}}}
	cmd, _ = commandFor(mod, "")
	if m, ok := cmd.Options["mail"].([]any); !ok || len(m) != 0 || cmd.Options["loginshell"] != "" || cmd.Method != "user_mod" {
		t.Fatalf("mod options %#v: an empty mail on a mod is an empty list (captured, K21)", cmd.Options)
	}
	one := Operation{ID: "u", Kind: KindUserUpdate, Object: "x", Fields: map[string]Change{"mail": {To: []string{"a@example.test"}}}}
	if cmd, _ = commandFor(one, ""); cmd.Options["mail"] != "a@example.test" {
		t.Fatalf("one mail: %#v", cmd.Options)
	}
	two := Operation{ID: "u", Kind: KindUserUpdate, Object: "x", Fields: map[string]Change{"mail": {To: []string{"a@example.test", "b@example.test"}}}}
	if cmd, _ = commandFor(two, ""); len(cmd.Options["mail"].([]any)) != 2 {
		t.Fatalf("two mails: %#v", cmd.Options)
	}
	g := Operation{ID: "g", Kind: KindMarkerCreate, Object: "m", Fields: map[string]Change{"description": {To: "d"}, "nonposix": {To: true}}}
	if cmd, _ = commandFor(g, ""); cmd.Method != "group_add" || cmd.Options["nonposix"] != true || cmd.Options["description"] != "d" {
		t.Fatalf("a marker: %+v", cmd)
	}
	mem := Operation{ID: "m", Kind: KindMemberGroupRemove, Object: "g", Members: []string{"a", "b"}}
	if cmd, _ = commandFor(mem, ""); cmd.Method != "group_remove_member" || fmt.Sprint(cmd.Options["group"]) != "[a b]" || cmd.Options["user"] != nil {
		t.Fatalf("a member removal: %+v", cmd)
	}
	pwc, _ := commandFor(Operation{ID: "p", Kind: KindPasswordReset, Object: "x"}, "the-password")
	if pwc.Method != "passwd" || pwc.Options["password"] != "the-password" || len(pwc.Args) != 1 || pwc.Args[0] != "x" {
		t.Fatalf("passwd: %+v", pwc)
	}
	del, _ := commandFor(Operation{ID: "d", Kind: KindUserDelete, Object: "x"}, "")
	if del.Method != "user_del" || len(del.Options) != 0 {
		t.Fatalf("a delete carries options (preserve?): %+v", del)
	}
}

// A write cut off by the operator's signal is unknown (the client cannot confirm
// anything, spec §4.4), is not sent again, and the read after the writes, made on a
// context that the signal did not cancel, says it was not applied.
func TestExecuteResolvesAWriteTheSignalCutOff(t *testing.T) {
	e := newRunEnv(t, fullRoster)
	seedFullRoster(e.f)
	ctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
		if c.method == "group_add" && c.args[0] == "team-a" {
			cancel() // S1's batch is being answered when the signal comes
		}
		return nil, nil, false
	}
	res, err := executeWithin(ctx, e.f, e.opts)
	if !errors.Is(err, ErrWrites) {
		t.Fatalf("err = %v", err)
	}
	if res.outcomeOf("group.create:team-a") != OutcomeSuccess {
		t.Fatalf("the batch in flight completed with its answer:%s", describeOps(res))
	}
	var cut int
	for _, o := range res.Ops {
		if o.Operation.Kind == KindMarkerCreate {
			cut++
			if o.Outcome != OutcomeUnknown || o.Resolution != resolutionNotApplied || o.Final() != OutcomeFailed {
				t.Fatalf("a marker create after the signal: %+v", o)
			}
		}
	}
	if cut != 2 || len(e.f.writes()) != 1 {
		t.Fatalf("%d markers cut off, writes %v: nothing is sent after the signal", cut, e.f.writes())
	}
	if len(e.journal.problem) != 0 || !res.Verify.Done || res.Verify.ReadError != "" {
		t.Fatalf("journal problems %v, verify %+v", e.journal.problem, res.Verify)
	}
}

// The journal never says "sending" of a batch the executor's own gate stopped, and
// a batch the client's gate refused (it was recorded, and was not sent) gets its
// result: not executed.
func TestExecuteJournalsWhatTheGatesStopped(t *testing.T) {
	t.Run("the executor's gate: no record of a batch that was never going to be sent", func(t *testing.T) {
		e := newRunEnv(t, fullRoster)
		seedFullRoster(e.f)
		e.entry.onPrepare = func() { e.lock.Lose() }
		_, err := e.execute()
		if !errors.Is(err, ErrWrites) {
			t.Fatalf("err = %v", err)
		}
		for _, id := range e.journal.ids() {
			if strings.HasSuffix(id, ":sending") {
				t.Fatalf("journal %v holds a sending of a batch the gate stopped", e.journal.ids())
			}
		}
	})
	t.Run("the client's gate: sending, then a result that says it was not executed", func(t *testing.T) {
		e := newRunEnv(t, fullRoster)
		seedFullRoster(e.f)
		e.f.writeGate = func(context.Context, string) error { return errors.New("closed by the client") }
		res, err := e.execute()
		if !errors.Is(err, ErrWrites) || len(e.f.writes()) != 0 || res.Verify.Done {
			t.Fatalf("err %v, writes %v, verify %+v", err, e.f.writes(), res.Verify)
		}
		ids := e.journal.ids()
		if !slices.Contains(ids, "S1-b1:sending") || !slices.Contains(ids, "S1-b1:result") {
			t.Fatalf("journal = %v", ids)
		}
		for _, ev := range e.journal.events {
			if ev.ID == "S1-b1:result" {
				for _, r := range ev.Payload.(resultEvent).Results {
					if r.Outcome != OutcomeNotExecuted {
						t.Fatalf("result %+v", r)
					}
				}
				if ev.Payload.(resultEvent).Stopped == nil || !strings.Contains(ev.Payload.(resultEvent).Stopped.Reason, "client refused") {
					t.Fatalf("the stop is not in the result event: %+v", ev.Payload)
				}
			}
		}
	})
}
