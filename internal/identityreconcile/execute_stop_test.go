package identityreconcile

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/freeiparpc"
)

// What stops the scheduling (spec §7.4), what a lost lock does (§4.4), what an
// unknown outcome becomes (§7.5, §7.6) and what the read after the writes finds.

// A batch is not a transaction: the item after the one that conflicted was
// applied, its answer is recorded, and nothing after the batch is sent.
func TestExecuteStopsAfterABatchWithAConflictAndRecordsEveryAnswer(t *testing.T) {
	roster := rosterWith("  - {name: ua}\n  - {name: ub}\n  - {name: uc}\n", "  - {name: team-b, category: team, membership: {users: [ua]}}\n")
	e2 := newRunEnv(t, roster)
	e2.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
		if c.method == "user_add" && c.args[0] == "ub" && f.users["ub"] == nil {
			f.addUser("ub", "x", "x") // someone else creates it first
		}
		return nil, nil, false
	}
	res, err := e2.execute()
	if !errors.Is(err, ErrWrites) {
		t.Fatalf("err = %v, want ErrWrites", err)
	}
	if res.outcomeOf("user.create:ua") != OutcomeSuccess || res.outcomeOf("user.create:ub") != OutcomeConflictFailed || res.outcomeOf("user.create:uc") != OutcomeSuccess {
		t.Fatalf("the batch's items:%s", describeOps(res))
	}
	if e2.f.users["uc"] == nil {
		t.Fatal("the item after the conflict was not applied: a batch is not a transaction")
	}
	if res.outcomeOf("group.member_user.add:team-b") != OutcomeNotExecuted || res.Stop == nil || res.Stop.Stage != "S3" {
		t.Fatalf("what follows:%s", describeOps(res))
	}
	if !res.Committed() || !res.Verify.Done || e2.f.finds != 3 {
		t.Fatalf("committed %v, verify %+v, reads %d: the read after the writes still happens", res.Committed(), res.Verify, e2.f.finds)
	}
}

// A conflict in the first stage that sends anything: nothing was applied, so the
// run is not committed, and it still reads once to say so.
func TestExecuteWithNothingAppliedIsNotCommitted(t *testing.T) {
	e := newRunEnv(t, rosterWith("", ""))
	e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
		if c.method == "group_add" && c.args[0] == "team-new" && f.groups["team-new"] == nil {
			f.addGroup("team-new", "x", false)
		}
		return nil, nil, false
	}
	res, err := e.execute()
	if !errors.Is(err, ErrWrites) || res.Committed() {
		t.Fatalf("err %v, committed %v:%s", err, res.Committed(), describeOps(res))
	}
	if res.outcomeOf("group.create:team-new") != OutcomeConflictFailed {
		t.Fatalf("outcomes:%s", describeOps(res))
	}
}

// The lock lost between two batches: the gate refuses the next one, what is not
// sent stays not executed, the read after the writes still happens, and the run is
// a failure that was committed.
func TestExecuteStopsWhenTheLockIsLostBetweenBatches(t *testing.T) {
	e := newRunEnv(t, fullRoster)
	seedFullRoster(e.f)
	e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
		if c.method == "user_add" && c.args[0] == "alice" { // S3: the lock goes after this batch is received
			e.lock.Lose()
		}
		return nil, nil, false
	}
	res, err := e.execute()
	if !errors.Is(err, ErrWrites) {
		t.Fatalf("err = %v", err)
	}
	// The batch that was in flight when the lock went completed with its real answer.
	if res.outcomeOf("user.create:alice") != OutcomeSuccess || res.outcomeOf("user.create:bob") != OutcomeSuccess {
		t.Fatalf("the batch in flight:%s", describeOps(res))
	}
	if res.outcomeOf("user.password.initialize:alice") != OutcomeNotExecuted || res.Stop == nil || !strings.Contains(res.Stop.Reason, "lock lost") {
		t.Fatalf("what followed:%s", describeOps(res))
	}
	if !res.Committed() || !res.Verify.Done || res.Verify.ReadError != "" {
		t.Fatalf("committed %v, verify %+v: reads need no lock and still run", res.Committed(), res.Verify)
	}
	for _, w := range e.f.writes() {
		if strings.HasPrefix(w, "passwd") || strings.HasPrefix(w, "user_del") {
			t.Fatalf("a write was sent after the lock was lost: %v", e.f.writes())
		}
	}
}

// The executor asks its own gate before every write, so a client built with another
// gate (here: none, an open one) does not take the requirement away.
func TestExecuteChecksItsOwnGateWhateverTheClientIsBuiltWith(t *testing.T) {
	e := newRunEnv(t, fullRoster)
	seedFullRoster(e.f)
	e.f.writeGate = nil // a client whose gate always lets a write through
	e.entry.onPrepare = func() { e.lock.Lose() }
	res, err := e.execute()
	if !errors.Is(err, ErrWrites) {
		t.Fatalf("err = %v", err)
	}
	if len(e.f.writes()) != 0 || res.Committed() || res.Verify.Done {
		t.Fatalf("writes %v, committed %v, verify %+v: the lock was lost before the first write", e.f.writes(), res.Committed(), res.Verify)
	}
	mustContain(t, res.Stop.Reason, "write gate", "the stop reason")
}

// An unknown outcome is not sent again, and the read after the writes classifies it.
func TestExecuteClassifiesAnUnknownOutcomeFromTheReadAfterTheWrites(t *testing.T) {
	roster := rosterWith("  - {name: ua}\n  - {name: ub}\n", "")
	unknown := func(apply bool) *runEnv {
		e := newRunEnv(t, roster)
		sent := 0
		e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
			if c.method == "user_add" && c.args[0] == "ub" {
				sent++
				if apply {
					f.addUser("ub", "ub", "ub") // the command was applied, the answer was lost
					f.users["ub"].shell, f.users["ub"].display, f.users["ub"].mail = "/bin/bash", "", nil
				}
				return nil, &freeiparpc.OutcomeUnknownError{Method: "user_add", Err: errors.New("EOF")}, true
			}
			return nil, nil, false
		}
		t.Cleanup(func() {
			if sent != 1 {
				t.Errorf("user_add ub was sent %d times: an unknown outcome is never sent again", sent)
			}
		})
		return e
	}
	t.Run("it had been applied: converged, and counted as applied", func(t *testing.T) {
		e := unknown(true)
		res, err := e.execute()
		o := res.op("user.create:ub")
		if o.Outcome != OutcomeUnknown || o.Resolution != resolutionConverged || o.Final() != OutcomeSuccess {
			t.Fatalf("ub: %+v", o)
		}
		// The unknown answer killed the whole batch's answer, so ua is unknown too and
		// resolved the same way; the run is not a failure of the writes then: every
		// planned operation ended applied and nothing was left unsent (spec §7.4).
		if o := res.op("user.create:ua"); o.Final() != OutcomeSuccess {
			t.Fatalf("ua: %+v", o)
		}
		if !res.Committed() {
			t.Fatal("a run with unknown outcomes was committed")
		}
		if err != nil {
			t.Fatalf("err = %v: an unknown outcome that converged, with nothing left unsent, is no failure", err)
		}
	})
	t.Run("it had not been applied: not-applied, failed", func(t *testing.T) {
		e := unknown(false)
		res, err := e.execute()
		o := res.op("user.create:ub")
		if o.Outcome != OutcomeUnknown || o.Resolution != resolutionNotApplied || o.Final() != OutcomeFailed {
			t.Fatalf("ub: %+v", o)
		}
		if !errors.Is(err, ErrWrites) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("the read after the writes fails: it stays unknown", func(t *testing.T) {
		e := unknown(true)
		e.f.onFind = func(f *fakeIPA, n int) {
			if n == 3 {
				f.intercept = nil
			}
		}
		// A third read that fails: the model's Find has no failure mode, so wrap it.
		failing := &findFailsFrom{fakeIPA: e.f, from: 3}
		res, err := Execute(e.ctx, failing, e.opts)
		o := res.op("user.create:ub")
		if o.Resolution != resolutionStillUnknown || o.Final() != OutcomeUnknown {
			t.Fatalf("ub: %+v", o)
		}
		if !errors.Is(err, ErrWrites) || !errors.Is(err, ErrVerify) || res.Verify.ReadError == "" {
			t.Fatalf("err = %v, verify %+v", err, res.Verify)
		}
	})
}

// findFailsFrom is the fake with a read that fails from the n-th user_find on.
type findFailsFrom struct {
	*fakeIPA
	from int
	n    int
}

func (f *findFailsFrom) Find(ctx context.Context, method string, args []any, opts map[string]any) ([]map[string]any, error) {
	if method == "user_find" && opts["preserved"] != true {
		f.n++
		if f.n >= f.from {
			return nil, errors.New("the server stopped answering")
		}
	}
	return f.fakeIPA.Find(ctx, method, args, opts)
}

// A password whose answer is lost stays unknown whatever is read: its value cannot
// be compared, the timestamp is only a hint.
func TestExecuteLeavesAnUnknownPasswordUnknown(t *testing.T) {
	e := newRunEnv(t, rosterWith("  - {name: ua, "+pw("a")+"}\n", ""))
	e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
		if c.method == "passwd" {
			u := f.users[c.args[0].(string)]
			u.hasPwd, u.lastPwd, u.exp = true, "20261107000001Z", "20261107000001Z" // it did happen
			return nil, &freeiparpc.OutcomeUnknownError{Method: "passwd", Err: errors.New("write tcp: " + pwSecret)}, true
		}
		return nil, nil, false
	}
	res, err := e.execute()
	o := res.op("user.password.initialize:ua")
	if o.Outcome != OutcomeUnknown || o.Resolution != resolutionStillUnknown || o.Final() != OutcomeUnknown || !errors.Is(err, ErrWrites) {
		t.Fatalf("ua: %+v, err %v", o, err)
	}
	mustContain(t, o.Detail, "krblastpwdchange is now set", "the hint")
	if sent := slices.Index(e.f.writes(), "passwd ua"); sent < 0 || slices.Index(e.f.writes()[sent+1:], "passwd ua") >= 0 {
		t.Fatalf("passwd was sent more than once: %v", e.f.writes())
	}
}

// What the read after the writes finds: it happens whatever the writes ended as;
// it separates what the run changed from what happened elsewhere; and an operation
// a server said it applied and that the read still shows is a failed run.
func TestExecuteVerifyReadsAfterAFailureAndSeparatesDriftFromResidue(t *testing.T) {
	roster := rosterWith("  - {name: ua}\n  - {name: other, login_shell: /bin/zsh}\n", "")
	t.Run("drift on an object the run did not touch does not fail it", func(t *testing.T) {
		e := newRunEnv(t, roster)
		o := e.f.addUser("other", "other", "other")
		o.shell, o.display, o.mail = "/bin/zsh", "", nil
		e.f.onFind = func(f *fakeIPA, n int) {
			if n == 3 {
				f.users["other"].shell = "/bin/sh" // someone changes an unrelated user after the writes
			}
		}
		res := e.mustApply()
		if !res.Verify.OK() || len(res.Verify.Remaining) != 0 || !slices.Equal(res.Verify.Unrelated, []string{"user.update:other"}) {
			t.Fatalf("verify = %+v", res.Verify)
		}
	})
	t.Run("a server that answers success and changes nothing leaves the operation in the plan: verify fails", func(t *testing.T) {
		e := newRunEnv(t, roster)
		e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
			if c.method == "user_add" && c.args[0] == "ua" {
				return json.RawMessage(`{"result":{},"value":"ua","summary":"Added user"}`), nil, true // success, no effect
			}
			return nil, nil, false
		}
		res, err := e.execute()
		if !errors.Is(err, ErrVerify) || errors.Is(err, ErrWrites) {
			t.Fatalf("err = %v, want ErrVerify only (every write was answered as a success)", err)
		}
		if !slices.Contains(res.Verify.Remaining, "user.create:ua") || res.Verify.OK() {
			t.Fatalf("verify = %+v", res.Verify)
		}
		mustContain(t, err.Error(), "user.create:ua", "the error names the operation")
	})
	t.Run("a write that failed: the read still happens and is reported beside it", func(t *testing.T) {
		e := newRunEnv(t, roster)
		e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
			if c.method == "user_add" {
				return nil, &freeiparpc.RPCError{Code: 4204, Name: "ACIError", Message: "Insufficient access"}, true
			}
			return nil, nil, false
		}
		res, err := e.execute()
		// The groups of S1 and S2 were applied before the users failed: the run is
		// committed, and the read after the writes still shows the users' creates as
		// what they are, left to do, beside the failure.
		if !errors.Is(err, ErrWrites) || !res.Verify.Done || !res.Committed() || !slices.Contains(res.Verify.Remaining, "user.create:ua") {
			t.Fatalf("err %v, verify %+v, committed %v", err, res.Verify, res.Committed())
		}
		if res.outcomeOf("user.create:ua") != OutcomeFailed {
			t.Fatalf("outcomes:%s", describeOps(res))
		}
	})
	t.Run("nothing was sent: nothing is read after", func(t *testing.T) {
		e := newRunEnv(t, roster)
		e.opts.Journal = &fakeJournal{failOn: func(ev Event) error {
			if ev.Kind == EventOp {
				return errors.New("disk full")
			}
			return nil
		}}
		res, err := e.execute()
		if !errors.Is(err, ErrWrites) || res.Verify.Done || len(e.f.writes()) != 0 || e.f.finds != 2 {
			t.Fatalf("err %v, verify %+v, writes %v, reads %d", err, res.Verify, e.f.writes(), e.f.finds)
		}
	})
}

// The K21 convergence through the writer: after "" was declared the server leaves
// the attribute out, and the plan made after the writes has nothing to do.
func TestExecuteConvergesOnEmptyValues(t *testing.T) {
	e := newRunEnv(t, "schema_version: 3\nusers:\n  - {name: ua, login_shell: \"\", display_name: \"\", email: \"\"}\ngroups:\n  - {name: team-a, category: team, description: \"\"}\n")
	e.f.addUser("ub", "ub", "ub") // an unrelated user with defaults, untouched
	res := e.mustApply()
	if res.Plan3 == nil || len(res.Plan3.Operations) != 0 || !res.Verify.OK() {
		t.Fatalf("plan3 %+v, verify %+v", res.Plan3, res.Verify)
	}
	if u := e.f.users["ua"]; u.shell != "" || u.display != "" || len(u.mail) != 0 {
		t.Fatalf("ua = %+v: the server did not leave the attributes out", u)
	}
	if g := e.f.groups["team-a"]; g.desc != "" {
		t.Fatalf("team-a = %+v", g)
	}
	// And a user that had values has them cleared by the mod forms.
	e2 := newRunEnv(t, e.roster)
	u := e2.f.addUser("ua", "ua", "ua")
	u.shell, u.display, u.mail = "/bin/zsh", "UA", []string{"ua@example.test"}
	g := e2.f.addGroup("team-a", "a team", false)
	_ = g
	e2.f.addGroup(HistoryMarkerName("team-a"), HistoryMarkerDescription("team-a"), true)
	res = e2.mustApply()
	if res.outcomeOf("user.update:ua") != OutcomeSuccess || res.outcomeOf("group.update:team-a") != OutcomeSuccess || !res.Verify.OK() {
		t.Fatalf("outcomes:%s", describeOps(res))
	}
	if u := e2.f.users["ua"]; u.shell != "" || u.display != "" || len(u.mail) != 0 {
		t.Fatalf("ua = %+v: the mod did not clear them", u)
	}
}
