package identityreconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/freeiparpc"
)

// More guards of Execute and its helpers that a mutation of the guard found the
// package green without (spec §5.12). Each test names the guard it makes fire and the
// row that lets it pass.

func TestExecuteRefusesAnIncompleteOrOutOfRangeCall(t *testing.T) {
	e := newRunEnv(t, fullRoster)
	seedFullRoster(e.f)
	cases := map[string]func(rpc *RPC, o *Options){
		"no client":             func(rpc *RPC, o *Options) { *rpc = nil },
		"no principal":          func(rpc *RPC, o *Options) { o.Desired.Principal = "" },
		"a negative limit":      func(rpc *RPC, o *Options) { o.BatchLimit = -1 },
		"a limit over MaxBatch": func(rpc *RPC, o *Options) { o.BatchLimit = MaxBatch + 1 },
	}
	for name, mod := range cases {
		var rpc RPC = e.f
		opts := e.opts
		mod(&rpc, &opts)
		if res, err := Execute(e.ctx, rpc, opts); err == nil || res != nil {
			t.Errorf("%s: accepted (%v, %v)", name, res, err)
		}
	}
	if len(e.f.calls) != 0 {
		t.Fatalf("a refused call sent %v", e.f.methodsCalled())
	}
	// The limits themselves are accepted: 1, and MaxBatch.
	for _, limit := range []int{1, MaxBatch} {
		e2 := newRunEnv(t, fullRoster)
		seedFullRoster(e2.f)
		e2.opts.BatchLimit = limit
		if _, err := e2.execute(); err != nil {
			t.Fatalf("a batch limit of %d: %v", limit, err)
		}
	}
}

// A gate left open by an earlier run is shut when this one starts: the entry runs
// with it shut, whatever the last run ended as.
func TestExecuteShutsAGateLeftOpen(t *testing.T) {
	e := newRunEnv(t, fullRoster)
	seedFullRoster(e.f)
	e.gate.open(e.held)
	var atEntry error
	e.entry.onPrepare = func() { atEntry = e.gate.Check(e.ctx, "user_add") }
	e.mustApply()
	if atEntry == nil {
		t.Fatal("the gate was still open when the entry ran")
	}
}

// The first read of a run is a precondition of everything: when it fails, nothing
// is planned, run or written, and the error says what was being read.
func TestExecuteStopsWhenItCannotReadBeforePlanning(t *testing.T) {
	e := newRunEnv(t, fullRoster)
	seedFullRoster(e.f)
	res, err := Execute(e.ctx, &findFailsFrom{fakeIPA: e.f, from: 1}, e.opts)
	if err == nil || !strings.Contains(err.Error(), "read before planning") || errors.Is(err, ErrWrites) {
		t.Fatalf("err = %v", err)
	}
	if e.entry.prepared != 0 || len(e.f.writes()) != 0 || len(res.Plan1.Operations) != 0 || len(e.journal.ids()) != 0 {
		t.Fatalf("prepares %d, writes %v, plan %v, journal %v", e.entry.prepared, e.f.writes(), kinds(res.Plan1), e.journal.ids())
	}
}

// The entry's own error is the one reported (not the "wrong result" message the
// check of its result would put in its place), and what the journal records of an
// entry that ran says that it ran.
func TestExecuteReportsTheEntrysOwnErrorAndRecordsThatItRan(t *testing.T) {
	e := newRunEnv(t, fullRoster)
	seedFullRoster(e.f)
	e.entry.err = errors.New("ansible-playbook exited 2")
	_, err := e.execute()
	if !errors.Is(err, ErrEntry) || !strings.Contains(err.Error(), "ansible-playbook exited 2") || strings.Contains(err.Error(), "not a prepare result") {
		t.Fatalf("err = %v", err)
	}
	e2 := newRunEnv(t, fullRoster)
	seedFullRoster(e2.f)
	e2.entry.previous = true
	e2.mustApply()
	raw, _ := json.Marshal(e2.journal.payloadOf("auth_cache"))
	if string(raw) != `{"entry_ran":true,"previous":true,"source":"this_run"}` {
		t.Fatalf("auth_cache = %s", raw)
	}
}

// An entry that ran and left Plan₂ empty ends there: no stage, no read after, no
// verification event: the journal holds the entry and nothing else.
func TestExecuteWithAnEmptyPlan2LeavesOnlyTheEntryInTheJournal(t *testing.T) {
	e := newRunEnv(t, rosterWith("", ""))
	e.entry.onPrepare = func() {
		e.f.addGroup("team-new", "team-new", false)
		e.f.addGroup(HistoryMarkerName("team-new"), HistoryMarkerDescription("team-new"), true)
	}
	res, err := e.execute()
	if err != nil || len(res.Ops) != 0 || res.Verify.Done || !slices.Equal(e.journal.ids(), []string{"auth_cache"}) {
		t.Fatalf("err %v, ops %d, verify %+v, journal %v", err, len(res.Ops), res.Verify, e.journal.ids())
	}
}

// A refusal whose record was made is not also a journal failure.
func TestARefusalWithAHealthyJournalIsNotAJournalError(t *testing.T) {
	e := newRunEnv(t, rosterWith("  - {name: alice, uid: 4242}\n", ""))
	e.f.addUser("alice", "alice", "alice")
	res, err := e.execute()
	if !errors.Is(err, ErrBlocked) || errors.Is(err, ErrJournal) || res.JournalError != "" {
		t.Fatalf("err = %v, journal error %q", err, res.JournalError)
	}
}

// The first journal failure is the one kept, the later ones are not.
func TestTheFirstJournalFailureIsTheOneReported(t *testing.T) {
	e := newRunEnv(t, fullRoster)
	seedFullRoster(e.f)
	n := 0
	e.journal.failOn = func(ev Event) error {
		if ev.Kind == EventOp {
			n++
			return fmt.Errorf("failure %d", n)
		}
		return nil
	}
	res, _ := e.execute()
	if n < 2 || res.JournalError != "failure 1" {
		t.Fatalf("%d failures, kept %q", n, res.JournalError)
	}
}

// Committed, Counts and Final: what a run changed, counted as the read after the
// writes resolved it.
func TestCommittedCountsAndFinalReadAnOperationAsItEnded(t *testing.T) {
	op := func(o Outcome, completed int, resolution string) OpResult {
		return OpResult{Outcome: o, Completed: completed, Resolution: resolution}
	}
	for _, tc := range []struct {
		name      string
		ops       []OpResult
		committed bool
	}{
		{"nothing", nil, false},
		{"only a conflict", []OpResult{op(OutcomeConflictFailed, 0, "")}, false},
		{"only a failure", []OpResult{op(OutcomeFailed, 0, "")}, false},
		{"only noops and not executed", []OpResult{op(OutcomeNoop, 0, ""), op(OutcomeNotExecuted, 0, "")}, false},
		{"a success", []OpResult{op(OutcomeSuccess, 0, "")}, true},
		{"an unknown outcome and nothing else: it may have been applied", []OpResult{op(OutcomeUnknown, 0, resolutionStillUnknown)}, true},
		{"an unknown one the read showed was applied", []OpResult{op(OutcomeUnknown, 0, resolutionConverged)}, true},
		{"an unknown one the read showed was not applied: nothing changed", []OpResult{op(OutcomeUnknown, 0, resolutionNotApplied)}, false},
		{"a member command that changed one member and then failed", []OpResult{op(OutcomeFailed, 1, "")}, true},
	} {
		if got := (Result{Ops: tc.ops}).Committed(); got != tc.committed {
			t.Errorf("%s: Committed = %v, want %v", tc.name, got, tc.committed)
		}
	}
	r := Result{Ops: []OpResult{
		op(OutcomeSuccess, 0, ""), op(OutcomeUnknown, 0, resolutionConverged), op(OutcomeUnknown, 0, resolutionNotApplied), op(OutcomeUnknown, 0, resolutionStillUnknown), op(OutcomeNoop, 0, ""),
	}}
	want := map[Outcome]int{OutcomeSuccess: 2, OutcomeFailed: 1, OutcomeUnknown: 1, OutcomeNoop: 1}
	if got := r.Counts(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("Counts = %v, want %v", got, want)
	}
	if (OpResult{Outcome: OutcomeUnknown}).Final() != OutcomeUnknown || (OpResult{Outcome: OutcomeConflictFailed, Resolution: resolutionConverged}).Final() != OutcomeConflictFailed {
		t.Fatal("Final changed an outcome that is not an unresolved unknown")
	}
}

// The lists a run reports are in order: the conflicts of the diff, and what Plan₂
// added and removed, however the maps they are made from are walked.
func TestPlanComparisonsAreSortedAndReportWhatWasRemovedToo(t *testing.T) {
	mk := func(kind string, objects ...string) Plan {
		var p Plan
		for _, o := range objects {
			p.Operations = append(p.Operations, Operation{Kind: kind, Object: o, ID: kind + ":" + o})
		}
		return p
	}
	delUsers := []string{"u5", "u1", "u4", "u2", "u3", "u6"}
	for i := 0; i < 20; i++ {
		got := newDestructive(Plan{}, mk(KindUserDelete, delUsers...))
		if !slices.IsSorted(got) || len(got) != 6 {
			t.Fatalf("newDestructive = %v", got)
		}
		c := comparePlans(mk(KindGroupCreate, "g6", "g1", "g5", "g2"), mk(KindUserCreate, "u5", "u1", "u4", "u2"))
		if !slices.IsSorted(c.Added) || !slices.IsSorted(c.Removed) || len(c.Added) != 4 || len(c.Removed) != 4 {
			t.Fatalf("comparePlans = %+v", c)
		}
	}
	c := comparePlans(mk(KindUserCreate, "a", "b"), mk(KindUserCreate, "b"))
	if len(c.Added) != 0 || !slices.Equal(c.Removed, []string{"user.create a"}) {
		t.Fatalf("an operation Plan₂ no longer has: %+v", c)
	}
}

// The first reason a run stopped for is the one it keeps.
func TestStopAtKeepsTheFirstReason(t *testing.T) {
	r := &runner{res: &Result{}}
	r.stopAt(S3, "first")
	r.stopAt(S5, "second")
	if !r.stopped || r.res.Stop == nil || r.res.Stop.Stage != "S3" || r.res.Stop.Reason != "first" {
		t.Fatalf("stop = %+v", r.res.Stop)
	}
}

// A run that sends nothing because everything it was planned to do was already done
// has no read to make and is a success: ok in identity.verify is true with read_done
// false, and no verification error.
func TestARunWhoseOperationsAreAllNoopsAndSentNothingSucceeds(t *testing.T) {
	e := newRunEnv(t, "schema_version: 3\nusers:\n  - {name: carol, state: absent}\n")
	e.f.addUser("carol", "carol", "carol")
	e.f.beforeShow(1, func() { delete(e.f.users, "carol") })
	res, err := e.execute()
	if err != nil || res.Verify.Done || res.outcomeOf("user.delete:carol") != OutcomeNoop || len(e.f.writes()) != 0 {
		t.Fatalf("err %v, verify %+v, writes %v:%s", err, res.Verify, e.f.writes(), describeOps(res))
	}
	if v := e.journal.verifyEvent(t); v["ok"] != true || v["writes_ok"] != true || v["read_done"] != false {
		t.Fatalf("verify = %v", v)
	}
	journalAccounts(t, e, res, err)
}

// What a failed run says about itself: the counts, and the stop when there is one.
func TestWritesSummaryNamesTheCountsAndTheStop(t *testing.T) {
	r := &runner{res: &Result{Ops: []OpResult{
		{Outcome: OutcomeSuccess}, {Outcome: OutcomeSuccess}, {Outcome: OutcomeConflictFailed}, {Outcome: OutcomeNotExecuted},
	}}}
	if got := r.writesSummary(); got != "2 success, 1 conflict-failed, 1 not_executed" {
		t.Fatalf("summary = %q", got)
	}
	r.res.Stop = &Stop{Stage: "S3", Reason: "user.create:ub conflict-failed"}
	if got := r.writesSummary(); got != "2 success, 1 conflict-failed, 1 not_executed; stopped at S3: user.create:ub conflict-failed" {
		t.Fatalf("summary = %q", got)
	}
	r.res.Verify = Verification{Done: true, ReadError: "the server stopped answering"}
	if got := r.verifySummary(); got != "the read failed: the server stopped answering" {
		t.Fatalf("verify summary = %q", got)
	}
	r.res.Verify = Verification{Done: true, Remaining: []string{"user.create:ua", "user.create:ub"}}
	if got := r.verifySummary(); got != "2 operation(s) still planned on objects this run changed: user.create:ua, user.create:ub" {
		t.Fatalf("verify summary = %q", got)
	}
}

// A read after the writes that fails leaves an unknown outcome unknown and touches
// nothing else; one that succeeds resolves an operation only when the read shows
// all of it, or none of it, still to do.
func TestTheReadAfterTheWritesResolvesOnlyWhatItCan(t *testing.T) {
	t.Run("the read fails: only the unknown ones are marked, the error is in the message", func(t *testing.T) {
		e := newRunEnv(t, rosterWith("  - {name: ua}\n  - {name: ub}\n", ""))
		e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
			if c.method == "user_add" && c.args[0] == "ub" {
				return nil, &freeiparpc.OutcomeUnknownError{Method: "user_add", Err: errors.New("EOF")}, true
			}
			return nil, nil, false
		}
		res, err := Execute(e.ctx, &findFailsFrom{fakeIPA: e.f, from: 3}, e.opts)
		if !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), "the read failed:") || !strings.Contains(err.Error(), "the server stopped answering") {
			t.Fatalf("err = %v", err)
		}
		for _, o := range res.Ops {
			if (o.Outcome == OutcomeUnknown) != (o.Resolution == resolutionStillUnknown) || (o.Outcome != OutcomeUnknown && o.Resolution != "") {
				t.Fatalf("%s: outcome %s resolution %q", o.Operation.ID, o.Outcome, o.Resolution)
			}
		}
	})
	t.Run("an operation left unsent on an object nothing else touched is drift, not residue", func(t *testing.T) {
		e := newRunEnv(t, rosterWith("  - {name: ua}\n  - {name: ub}\n  - {name: uc}\n", "  - {name: team-b, category: team, membership: {users: [uc]}}\n"))
		e.f.addUser("uc", "uc", "uc") // exists: no create, and team-b gets uc added in S6
		e.f.users["uc"].shell, e.f.users["uc"].display, e.f.users["uc"].mail = "/bin/bash", "", nil
		g := e.f.addGroup("team-b", "team-b", false)
		e.f.addGroup(HistoryMarkerName("team-b"), HistoryMarkerDescription("team-b"), true)
		_ = g
		e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
			if c.method == "user_add" && c.args[0] == "ub" && f.users["ub"] == nil {
				// someone else creates ub first, as the roster describes it
				u := f.addUser("ub", "ub", "ub")
				u.shell, u.display, u.mail = "/bin/bash", "", nil
			}
			return nil, nil, false
		}
		res, err := e.execute()
		if !errors.Is(err, ErrWrites) || errors.Is(err, ErrVerify) {
			t.Fatalf("err = %v, want ErrWrites only:%s", err, describeOps(res))
		}
		if res.outcomeOf("group.member_user.add:team-b") != OutcomeNotExecuted ||
			!slices.Contains(res.Verify.Unrelated, "group.member_user.add:team-b") || slices.Contains(res.Verify.Remaining, "group.member_user.add:team-b") {
			t.Fatalf("verify %+v:%s", res.Verify, describeOps(res))
		}
	})
	t.Run("a member command the read shows half of is still unknown", func(t *testing.T) {
		e := newRunEnv(t, rosterWith("  - {name: ua}\n  - {name: ub}\n", "  - {name: team-b, category: team, membership: {users: [ua, ub]}}\n"))
		e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
			if c.method == "group_add_member" && c.args[0] == "team-b" {
				f.groups["team-b"].users["ua"] = true // only the first member was added
				return nil, &freeiparpc.OutcomeUnknownError{Method: "group_add_member", Err: errors.New("EOF")}, true
			}
			return nil, nil, false
		}
		res, err := e.execute()
		o := res.op("group.member_user.add:team-b")
		if !errors.Is(err, ErrWrites) || o.Outcome != OutcomeUnknown || o.Resolution != resolutionStillUnknown || o.Final() != OutcomeUnknown {
			t.Fatalf("err %v, op %+v", err, o)
		}
	})
}

// What the timestamps say of a password whose outcome is unknown: a hint for each of
// the four states, and nothing for a user the read does not show.
func TestPasswordHintSaysWhatTheTimestampsShow(t *testing.T) {
	obs := func(u LiveUser) Observation { return Observation{Users: []LiveUser{u}} }
	init := Operation{Kind: KindPasswordInitialize, Object: "ua"}
	reset := Operation{Kind: KindPasswordReset, Object: "ua"}
	for _, tc := range []struct {
		name string
		op   Operation
		obs  Observation
		want string
	}{
		{"initialize, a password change is recorded", init, obs(LiveUser{Name: "ua", LastPwdChange: "20261107000001Z"}), "krblastpwdchange is now set"},
		{"initialize, none is recorded", init, obs(LiveUser{Name: "ua"}), "krblastpwdchange is still not set"},
		{"reset, the user is on a reset password", reset, obs(LiveUser{Name: "ua", LastPwdChange: "20261107000001Z", PwdExpiration: "20261107000001Z"}), "on a reset password, so a reset may have happened"},
		{"reset, the user is not", reset, obs(LiveUser{Name: "ua", LastPwdChange: "20261107000001Z", PwdExpiration: "20270107000001Z"}), "the user is not on a reset password"},
		{"a user the read does not show", init, obs(LiveUser{Name: "other"}), ""},
	} {
		got := passwordHint(tc.op, tc.obs)
		if tc.want == "" && got != "" || !strings.Contains(got, tc.want) {
			t.Errorf("%s: hint %q, want it to hold %q", tc.name, got, tc.want)
		}
	}
	// A reset on a user that has a change recorded is never read as an initialize.
	if got := passwordHint(reset, obs(LiveUser{Name: "ua", LastPwdChange: "20261107000001Z"})); strings.Contains(got, "still not set") || strings.Contains(got, "is now set") {
		t.Errorf("a reset read as an initialize: %q", got)
	}
}

// showEntry reads the entry out of a show answer, and says when there is none.
func TestShowEntryRefusesAnAnswerWithoutAnEntry(t *testing.T) {
	for name, raw := range map[string]string{"not JSON": "oops", "no result": `{"value":"x"}`, "a null result": `{"result":null}`, "a result that is not an entry": `{"result":"x"}`} {
		if _, err := showEntry(json.RawMessage(raw)); err == nil || !strings.Contains(err.Error(), "no entry") {
			t.Errorf("%s: %v", name, err)
		}
	}
	entry, err := showEntry(json.RawMessage(`{"result":{"uid":["ua"]},"value":"ua"}`))
	if err != nil || fmt.Sprint(entry["uid"]) != "[ua]" {
		t.Fatalf("an entry: %v %v", entry, err)
	}
}

var _ = context.Background
