package identityreconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/freeiparpc"
)

// The journal accounts for every planned operation (spec §7.4, §7.7): the batches
// that were sent have their result event, every other operation is in the one
// "not_sent" event with the stop, and identity.verify, last, says whether the run
// succeeded. Each scenario below is one way an operation fails to be sent, and each
// asserts what the journal says, not only what the Result does.

// payloadOf is the payload of the event with this id, nil when there is none.
func (j *fakeJournal) payloadOf(id string) any {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, e := range j.events {
		if e.ID == id {
			return e.Payload
		}
	}
	return nil
}

// verifyEvent is identity.verify as the store would hold it: its payload through JSON.
func (j *fakeJournal) verifyEvent(t *testing.T) map[string]any {
	t.Helper()
	p := j.payloadOf("verify")
	if p == nil {
		t.Fatalf("no identity.verify in the journal %v", j.ids())
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// notSent is the "not_sent" event of the journal, nil when there is none.
func (j *fakeJournal) notSent() *notSentEvent {
	if p, ok := j.payloadOf("not_sent").(notSentEvent); ok {
		return &p
	}
	return nil
}

// journalAccounts asserts that the journal alone says what became of each of ops:
// once, in a result event if its batch was sent and in the "not_sent" event if not,
// with the outcome the run ended it as, that the stop the journal names is the
// Result's, and that identity.verify is last and its ok is the run's verdict.
func journalAccounts(t *testing.T, e *runEnv, res *Result, err error) {
	t.Helper()
	seen := map[string]string{} // operation id -> where it was recorded
	outcomes := map[string]Outcome{}
	for _, ev := range e.journal.events {
		var ops []OpResult
		where := ev.ID
		switch p := ev.Payload.(type) {
		case resultEvent:
			ops = p.Results
		case notSentEvent:
			ops = p.Operations
		default:
			continue
		}
		for _, o := range ops {
			id := o.Operation.ID
			if prev, dup := seen[id]; dup {
				t.Fatalf("%s is in the journal twice (%s and %s): a sent operation is not also unsent", id, prev, where)
			}
			seen[id], outcomes[id] = where, o.Outcome
		}
	}
	for _, o := range res.Ops {
		got, ok := outcomes[o.Operation.ID]
		if !ok {
			t.Fatalf("the journal does not account for %s (it ended %s: %s):\n%s", o.Operation.ID, o.Outcome, o.Detail, e.journal.all())
		}
		if got != o.Outcome {
			t.Fatalf("the journal says %s was %s in %s, the result says %s", o.Operation.ID, got, seen[o.Operation.ID], o.Outcome)
		}
	}
	if len(seen) != len(res.Ops) {
		t.Fatalf("the journal accounts for %d operations, the run had %d", len(seen), len(res.Ops))
	}
	unsent := 0
	for _, o := range res.Ops {
		if seen[o.Operation.ID] == "not_sent" {
			unsent++
		}
	}
	if ns := e.journal.notSent(); (ns != nil) != (unsent > 0) {
		t.Fatalf("not_sent event %v with %d unsent operations", ns != nil, unsent)
	} else if ns != nil && !reflect.DeepEqual(ns.Stop, res.Stop) {
		t.Fatalf("the journal's stop %+v is not the result's %+v", ns.Stop, res.Stop)
	}
	ids := e.journal.ids()
	if ids[len(ids)-1] != "verify" {
		t.Fatalf("the last event is %s, not identity.verify: %v", ids[len(ids)-1], ids)
	}
	if ok := e.journal.verifyEvent(t)["ok"]; ok != (err == nil) {
		t.Fatalf("identity.verify says ok=%v for a run that returned %v", ok, err)
	}
}

// stopJournaled asserts the not_sent event of a run that stopped before its first
// command: every operation of the plan, not executed, the stop named, and nothing
// else recorded after it.
func stopJournaled(t *testing.T, e *runEnv, res *Result, plan Plan, stage string) {
	t.Helper()
	ns := e.journal.notSent()
	if ns == nil {
		t.Fatalf("no not_sent event in %v", e.journal.ids())
	}
	if ns.Stop == nil || ns.Stop.Stage != stage || ns.Stop.Reason == "" || !reflect.DeepEqual(ns.Stop, res.Stop) {
		t.Fatalf("stop in the journal %+v, in the result %+v, want stage %s", ns.Stop, res.Stop, stage)
	}
	if len(ns.Operations) != len(plan.Operations) {
		t.Fatalf("%d operations in the event, the plan has %d", len(ns.Operations), len(plan.Operations))
	}
	for i, o := range ns.Operations {
		if o.Operation.ID != plan.Operations[i].ID || o.Outcome != OutcomeNotExecuted || o.Stage != StageOf(o.Operation.Kind).String() {
			t.Fatalf("operation %d of the event: %+v", i, o)
		}
	}
	if ids := e.journal.ids(); ids[len(ids)-1] != "not_sent" {
		t.Fatalf("events after the stop: %v", ids)
	}
	for _, id := range e.journal.ids() {
		if id == "verify" || strings.HasSuffix(id, ":sending") {
			t.Fatalf("a run that stopped before its first command has %s in %v", id, e.journal.ids())
		}
	}
}

// aliceLive is alice as the planner expects her when the roster says nothing but her name.
func aliceLive(f *fakeIPA) *fUser {
	u := f.addUser("alice", "alice", "alice")
	u.shell, u.home, u.display, u.mail = "/bin/bash", "/home/alice", "alice alice", nil
	return u
}

func TestJournalAccountsForEveryOperationHoweverItWasNotSent(t *testing.T) {
	pwRoster := "schema_version: 3\nusers:\n  - {name: alice, " + pw("a") + "}\n"
	delRoster := "schema_version: 3\nusers:\n  - {name: carol, state: absent}\n"
	type scenario struct {
		name  string
		make  func(t *testing.T) *runEnv
		check func(t *testing.T, e *runEnv, res *Result, err error)
	}
	// The one scenario in which the journal refused the result of a batch: it cannot
	// hold that account, and the run says so (ErrJournal) and is not ok.
	const lossy = "a result the journal could not record"
	conflict := func(id string) func(t *testing.T, e *runEnv, res *Result, err error) {
		return func(t *testing.T, e *runEnv, res *Result, err error) {
			if !errors.Is(err, ErrWrites) || res.outcomeOf(id) != OutcomeConflictFailed {
				t.Fatalf("err %v:%s", err, describeOps(res))
			}
		}
	}
	for _, sc := range []scenario{
		{"a run that sent everything: no not_sent event, ok true", func(t *testing.T) *runEnv {
			e := newRunEnv(t, fullRoster)
			seedFullRoster(e.f)
			return e
		}, func(t *testing.T, e *runEnv, res *Result, err error) {
			if err != nil || e.journal.notSent() != nil {
				t.Fatalf("err %v, not_sent %+v", err, e.journal.notSent())
			}
		}},
		{"S3 conflict: what follows the batch is not executed, in the journal too", func(t *testing.T) *runEnv {
			e := newRunEnv(t, rosterWith("  - {name: ua}\n  - {name: ub}\n  - {name: uc}\n", "  - {name: team-b, category: team, membership: {users: [ua]}}\n"))
			e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
				if c.method == "user_add" && c.args[0] == "ub" && f.users["ub"] == nil {
					f.addUser("ub", "x", "x")
				}
				return nil, nil, false
			}
			return e
		}, func(t *testing.T, e *runEnv, res *Result, err error) {
			if !errors.Is(err, ErrWrites) || res.Stop == nil || res.Stop.Stage != "S3" {
				t.Fatalf("err %v:%s", err, describeOps(res))
			}
			ns := e.journal.notSent()
			if ns == nil || len(ns.Operations) != 1 || ns.Operations[0].Operation.ID != "group.member_user.add:team-b" || ns.Operations[0].Outcome != OutcomeNotExecuted {
				t.Fatalf("not_sent = %+v", ns)
			}
		}},
		{"S4 re-read conflict with nothing sent", func(t *testing.T) *runEnv {
			e := newRunEnv(t, pwRoster)
			aliceLive(e.f)
			e.f.beforeShow(1, func() { e.f.users["alice"].hasPwd, e.f.users["alice"].lastPwd = true, "20261107000001Z" })
			return e
		}, func(t *testing.T, e *runEnv, res *Result, err error) {
			conflict("user.password.initialize:alice")(t, e, res, err)
			if len(e.f.writes()) != 0 || res.Verify.Done || res.Stop == nil || res.Stop.Stage != "S4" {
				t.Fatalf("writes %v, verify %+v, stop %+v", e.f.writes(), res.Verify, res.Stop)
			}
			ns := e.journal.notSent()
			if ns == nil || len(ns.Operations) != 1 || !strings.Contains(ns.Operations[0].Detail, "no longer calls for") {
				t.Fatalf("the refusal and its reason are not in the journal: %+v", ns)
			}
			if v := e.journal.verifyEvent(t); v["read_done"] != false || v["writes_ok"] != false {
				t.Fatalf("verify = %v", v)
			}
		}},
		{"S8 re-read conflict with nothing sent", func(t *testing.T) *runEnv {
			e := newRunEnv(t, delRoster)
			e.f.addUser("carol", "carol", "carol")
			e.f.beforeShow(1, func() { e.f.users["carol"].preserved = true })
			return e
		}, func(t *testing.T, e *runEnv, res *Result, err error) {
			conflict("user.delete:carol")(t, e, res, err)
			if len(e.f.writes()) != 0 || res.Stop == nil || res.Stop.Stage != "S8" {
				t.Fatalf("writes %v, stop %+v", e.f.writes(), res.Stop)
			}
			if ns := e.journal.notSent(); ns == nil || !strings.Contains(ns.Operations[0].Detail, "preserved") {
				t.Fatalf("not_sent = %+v", ns)
			}
		}},
		{"a preserved user at S8 after S1 and S2 were sent: the read is fine and the run still failed", func(t *testing.T) *runEnv {
			e := newRunEnv(t, rosterWith("  - {name: carol, state: absent}\n", ""))
			e.f.addUser("carol", "carol", "carol")
			e.f.beforeShow(1, func() { e.f.users["carol"].preserved = true })
			return e
		}, func(t *testing.T, e *runEnv, res *Result, err error) {
			conflict("user.delete:carol")(t, e, res, err)
			if !res.Verify.Done || !res.Verify.OK() {
				t.Fatalf("verify %+v: the case is the one where the read is clean", res.Verify)
			}
			v := e.journal.verifyEvent(t)
			if v["ok"] != false || v["writes_ok"] != false || v["read_done"] != true {
				t.Fatalf("identity.verify = %v: the run failed, so ok is false whatever the read showed", v)
			}
			if ns := e.journal.notSent(); ns == nil || ns.Stop == nil || ns.Stop.Stage != "S8" || !strings.Contains(ns.Operations[0].Detail, "the user is preserved") {
				t.Fatalf("not_sent = %+v", ns)
			}
		}},
		{"S5 every member already left, S7 already disabled, S8 already gone: noops with no batch", func(t *testing.T) *runEnv {
			e := newRunEnv(t, rosterWith("  - {name: alice, state: disabled}\n  - {name: carol, state: absent}\n", "  - {name: team-b, category: team, membership: {users: [alice]}}\n"))
			aliceLive(e.f)
			e.f.addUser("carol", "carol", "carol")
			e.f.addUser("bob", "bob", "bob")
			g := e.f.addGroup("team-b", "team-b", false)
			g.users["alice"], g.users["bob"] = true, true
			shows := 0
			e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
				if c.method == "group_show" || c.method == "user_show" {
					shows++
					switch shows {
					case 1: // S5: bob left on his own
						delete(g.users, "bob")
					case 2: // S7: alice was disabled by someone else
						f.users["alice"].locked = true
					case 3: // S8: carol is gone
						delete(f.users, "carol")
					}
				}
				return nil, nil, false
			}
			return e
		}, func(t *testing.T, e *runEnv, res *Result, err error) {
			if err != nil {
				t.Fatalf("err %v:%s", err, describeOps(res))
			}
			for _, id := range []string{"group.member_user.remove:team-b", "user.disable:alice", "user.delete:carol"} {
				if res.outcomeOf(id) != OutcomeNoop {
					t.Fatalf("%s:%s", id, describeOps(res))
				}
			}
			ns := e.journal.notSent()
			if ns == nil || len(ns.Operations) != 3 || ns.Stop != nil {
				t.Fatalf("not_sent = %+v: three noops that no batch carried, and no stop", ns)
			}
		}},
		{"the client refused the batch: its result says so, what follows is not sent", func(t *testing.T) *runEnv {
			e := newRunEnv(t, fullRoster)
			seedFullRoster(e.f)
			e.f.writeGate = func(context.Context, string) error { return errors.New("closed by the client") }
			return e
		}, func(t *testing.T, e *runEnv, res *Result, err error) {
			if !errors.Is(err, ErrWrites) || len(e.f.writes()) != 0 {
				t.Fatalf("err %v writes %v", err, e.f.writes())
			}
			if res.op("group.create:team-a").Outcome != OutcomeNotExecuted || !contains(e.journal.ids(), "S1-b1:result") {
				t.Fatalf("%s", e.journal.all())
			}
			if ns := e.journal.notSent(); ns == nil || len(ns.Operations) != len(res.Ops)-1 {
				t.Fatalf("not_sent = %+v: everything but the batch the client refused", ns)
			}
		}},
		{"the executor's gate refused: no batch was recorded as sending", func(t *testing.T) *runEnv {
			e := newRunEnv(t, fullRoster)
			seedFullRoster(e.f)
			e.entry.onPrepare = func() { e.lock.Lose() }
			return e
		}, func(t *testing.T, e *runEnv, res *Result, err error) {
			if !errors.Is(err, ErrWrites) || res.Stop == nil || !strings.Contains(res.Stop.Reason, "write gate") {
				t.Fatalf("err %v stop %+v", err, res.Stop)
			}
			if ns := e.journal.notSent(); ns == nil || len(ns.Operations) != len(res.Ops) {
				t.Fatalf("not_sent = %+v: every operation was kept from going out", ns)
			}
		}},
		{"the journal refused a batch's record: it was not sent, and the journal says what that left", func(t *testing.T) *runEnv {
			e := newRunEnv(t, fullRoster)
			seedFullRoster(e.f)
			e.journal.failOn = func(ev Event) error {
				if ev.ID == "S3-b1:sending" {
					return errors.New("disk full")
				}
				return nil
			}
			return e
		}, func(t *testing.T, e *runEnv, res *Result, err error) {
			if !errors.Is(err, ErrJournal) || !errors.Is(err, ErrWrites) || res.Stop == nil || res.Stop.Stage != "S3" {
				t.Fatalf("err %v stop %+v", err, res.Stop)
			}
			if v := e.journal.verifyEvent(t); v["ok"] != false {
				t.Fatalf("verify = %v", v)
			}
		}},
		{"the lock was lost between batches", func(t *testing.T) *runEnv {
			e := newRunEnv(t, fullRoster)
			seedFullRoster(e.f)
			e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
				if c.method == "user_add" && c.args[0] == "alice" {
					e.lock.Lose()
				}
				return nil, nil, false
			}
			return e
		}, func(t *testing.T, e *runEnv, res *Result, err error) {
			if !errors.Is(err, ErrWrites) || res.Stop == nil || !strings.Contains(res.Stop.Reason, "lock lost") {
				t.Fatalf("err %v stop %+v", err, res.Stop)
			}
		}},
		{"a result the journal could not record: the run finished and ok is false", func(t *testing.T) *runEnv {
			e := newRunEnv(t, fullRoster)
			seedFullRoster(e.f)
			e.journal.failOn = func(ev Event) error {
				if ev.ID == "S1-b1:result" {
					return errors.New("disk full")
				}
				return nil
			}
			return e
		}, func(t *testing.T, e *runEnv, res *Result, err error) {
			if !errors.Is(err, ErrJournal) || errors.Is(err, ErrWrites) || !res.Verify.OK() {
				t.Fatalf("err %v verify %+v", err, res.Verify)
			}
			if v := e.journal.verifyEvent(t); v["ok"] != false || v["writes_ok"] != true || v["read_done"] != true {
				t.Fatalf("verify = %v: the writes were applied and read back, the record of one was not made", v)
			}
		}},
	} {
		t.Run(sc.name, func(t *testing.T) {
			e := sc.make(t)
			res, err := e.execute()
			sc.check(t, e, res, err)
			if !strings.HasPrefix(sc.name, lossy) {
				journalAccounts(t, e, res, err)
			}
		})
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// A run that stops before its first command still says in the journal what it did
// not run and why: one not_sent event with the plan's operations and the stage.
func TestJournalSaysWhyARunStoppedBeforeItsFirstCommand(t *testing.T) {
	t.Run("the first plan is blocked", func(t *testing.T) {
		e := newRunEnv(t, rosterWith("  - {name: alice, uid: 4242}\n", ""))
		e.f.addUser("alice", "alice", "alice")
		res, err := e.execute()
		if !errors.Is(err, ErrBlocked) {
			t.Fatalf("err = %v", err)
		}
		stopJournaled(t, e, res, res.Plan1, stopPlan1)
		mustContain(t, res.Stop.Reason, BlockedIDChange+" alice", "the reason")
	})
	t.Run("the entry fails: a fixed reason, never the playbook's text", func(t *testing.T) {
		e := newRunEnv(t, fullRoster)
		seedFullRoster(e.f)
		e.entry.err = errors.New("ansible-playbook exited 2: " + pwSecret)
		res, err := e.execute()
		if !errors.Is(err, ErrEntry) {
			t.Fatalf("err = %v", err)
		}
		stopJournaled(t, e, res, res.Plan1, stopEntry)
		if strings.Contains(e.journal.all(), pwSecret) || strings.Contains(e.journal.all(), "ansible-playbook") {
			t.Fatalf("the entry's own text is in the journal:\n%s", e.journal.all())
		}
	})
	t.Run("the read after the entry fails", func(t *testing.T) {
		e := newRunEnv(t, fullRoster)
		seedFullRoster(e.f)
		res, err := executeWithin(e.ctx, &findFailsFrom{fakeIPA: e.f, from: 2}, e.opts)
		if err == nil || !strings.Contains(err.Error(), "read after the entry") {
			t.Fatalf("err = %v", err)
		}
		stopJournaled(t, e, res, res.Plan1, stopRead2)
	})
	t.Run("the plan after the entry is blocked", func(t *testing.T) {
		e := newRunEnv(t, rosterWith("  - {name: alice, uid: 4242}\n", ""))
		e.entry.onPrepare = func() { e.f.addUser("alice", "alice", "alice") }
		res, err := e.execute()
		if !errors.Is(err, ErrBlocked) || res.Plan2 == nil {
			t.Fatalf("err = %v", err)
		}
		stopJournaled(t, e, res, *res.Plan2, stopPlan2)
	})
	t.Run("the plan after the entry holds a destructive operation the first did not", func(t *testing.T) {
		e := newRunEnv(t, rosterWith("  - {name: carol, state: absent}\n", ""))
		e.entry.onPrepare = func() { e.f.addUser("carol", "carol", "carol") }
		res, err := e.execute()
		if !errors.Is(err, ErrDestructiveDiff) || res.Plan2 == nil {
			t.Fatalf("err = %v", err)
		}
		stopJournaled(t, e, res, *res.Plan2, stopPlan2)
		mustContain(t, res.Stop.Reason, "user.delete carol", "the reason names the operation")
	})
	t.Run("a journal that cannot record the stop: reported beside the error", func(t *testing.T) {
		e := newRunEnv(t, rosterWith("  - {name: alice, uid: 4242}\n", ""))
		e.f.addUser("alice", "alice", "alice")
		e.journal.failOn = func(ev Event) error { return errors.New("disk full") }
		res, err := e.execute()
		if !errors.Is(err, ErrBlocked) || !errors.Is(err, ErrJournal) || res.JournalError == "" {
			t.Fatalf("err = %v, journal error %q", err, res.JournalError)
		}
	})
	t.Run("an idle run and a run whose plan after the entry is empty record no stop", func(t *testing.T) {
		e := newRunEnv(t, "schema_version: 3\nusers: [{name: alice}]\n")
		aliceLive(e.f)
		res := e.mustApply()
		if e.journal.notSent() != nil || res.Stop != nil {
			t.Fatalf("an idle run: not_sent %+v, stop %+v", e.journal.notSent(), res.Stop)
		}
	})
}

// What identity.verify's ok means: the run's verdict. It is never true for a run
// that returned an error.
func TestVerifyEventOKIsTheRunsVerdictNeverTheReadAlone(t *testing.T) {
	t.Run("a clean run", func(t *testing.T) {
		e := newRunEnv(t, fullRoster)
		seedFullRoster(e.f)
		res := e.mustApply()
		v := e.journal.verifyEvent(t)
		if v["ok"] != true || v["writes_ok"] != true || v["read_done"] != true || v["read_error"] != "" || res.Stop != nil {
			t.Fatalf("verify = %v", v)
		}
	})
	t.Run("a write that failed: the read shows the plan still to do", func(t *testing.T) {
		e := newRunEnv(t, rosterWith("  - {name: ua}\n", ""))
		e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
			if c.method == "user_add" {
				return nil, &freeiparpc.RPCError{Code: 4204, Name: "ACIError", Message: "Insufficient access"}, true
			}
			return nil, nil, false
		}
		res, err := e.execute()
		if err == nil {
			t.Fatal("no error")
		}
		if v := e.journal.verifyEvent(t); v["ok"] != false || v["writes_ok"] != false {
			t.Fatalf("verify = %v", v)
		}
		journalAccounts(t, e, res, err)
	})
	t.Run("every write applied and the read still shows an operation", func(t *testing.T) {
		e := newRunEnv(t, rosterWith("  - {name: ua}\n", ""))
		e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
			if c.method == "user_add" {
				return json.RawMessage(`{"result":{},"value":"ua","summary":"Added user"}`), nil, true
			}
			return nil, nil, false
		}
		res, err := e.execute()
		if !errors.Is(err, ErrVerify) {
			t.Fatalf("err = %v", err)
		}
		if v := e.journal.verifyEvent(t); v["ok"] != false || v["writes_ok"] != true || fmt.Sprint(v["remaining"]) != "[user.create:ua]" {
			t.Fatalf("verify = %v", v)
		}
		journalAccounts(t, e, res, err)
	})
	t.Run("the read after the writes failed", func(t *testing.T) {
		e := newRunEnv(t, rosterWith("  - {name: ua}\n", ""))
		res, err := executeWithin(e.ctx, &findFailsFrom{fakeIPA: e.f, from: 3}, e.opts)
		if !errors.Is(err, ErrVerify) {
			t.Fatalf("err = %v", err)
		}
		if v := e.journal.verifyEvent(t); v["ok"] != false || v["writes_ok"] != true || v["read_error"] == "" {
			t.Fatalf("verify = %v", v)
		}
		journalAccounts(t, e, res, err)
	})
}

// An unknown outcome that the read after the writes shows was applied, with nothing
// left unsent, is a run that did what it planned (spec §6, §7.4, D20): no ErrWrites.
// One that left an operation unsent is a failure, and says exactly that.
func TestAnUnknownOutcomeThatConvergedIsNotAWriteFailure(t *testing.T) {
	unknownUser := func(t *testing.T, roster string, apply bool) *runEnv {
		e := newRunEnv(t, roster)
		e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
			if c.method == "user_add" && c.args[0] == "ub" {
				if apply {
					f.addUser("ub", "ub", "ub")
					f.users["ub"].shell, f.users["ub"].display, f.users["ub"].mail = "/bin/bash", "", nil
					f.addUser("ua", "ua", "ua")
					f.users["ua"].shell, f.users["ua"].display, f.users["ua"].mail = "/bin/bash", "", nil
					f.groups["ipausers"].users["ua"], f.groups["ipausers"].users["ub"] = true, true
				}
				return nil, &freeiparpc.OutcomeUnknownError{Method: "user_add", Err: errors.New("EOF")}, true
			}
			return nil, nil, false
		}
		return e
	}
	t.Run("nothing was left unsent: the run is a success, the stop stays recorded", func(t *testing.T) {
		e := unknownUser(t, rosterWith("  - {name: ua}\n  - {name: ub}\n", ""), true)
		res, err := e.execute()
		if err != nil {
			t.Fatalf("err = %v:%s", err, describeOps(res))
		}
		o := res.op("user.create:ub")
		if o.Outcome != OutcomeUnknown || o.Resolution != resolutionConverged || o.Final() != OutcomeSuccess {
			t.Fatalf("ub: %+v", o)
		}
		if res.Stop == nil || res.Stop.Stage != "S3" || !res.Committed() || !res.Verify.OK() {
			t.Fatalf("stop %+v, committed %v, verify %+v", res.Stop, res.Committed(), res.Verify)
		}
		if v := e.journal.verifyEvent(t); v["ok"] != true || v["writes_ok"] != true || fmt.Sprint(v["unknown_resolved"]) != "map[user.create:ua:converged user.create:ub:converged]" {
			t.Fatalf("verify = %v", v)
		}
		journalAccounts(t, e, res, err)
	})
	t.Run("an operation was left unsent by the stop: a failure whose message counts it", func(t *testing.T) {
		roster := rosterWith("  - {name: ua}\n  - {name: ub}\n", "  - {name: team-b, category: team, membership: {users: [ua]}}\n")
		e := unknownUser(t, roster, true)
		res, err := e.execute()
		// The membership that was never sent is still in the plan made after the writes,
		// on a group the run created: the verification fails beside the writes.
		if !errors.Is(err, ErrWrites) || !errors.Is(err, ErrVerify) {
			t.Fatalf("err = %v:%s", err, describeOps(res))
		}
		// S1 and S2 were applied (group team-new, team-b and their markers), S3 was the
		// unknown that converged, and the S6 membership was never sent.
		want := "6 success, 1 not_executed; stopped at S3: user.create:ua unknown"
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("err = %v, want it to say %q", err, want)
		}
		if res.outcomeOf("group.member_user.add:team-b") != OutcomeNotExecuted {
			t.Fatalf("outcomes:%s", describeOps(res))
		}
		if v := e.journal.verifyEvent(t); v["ok"] != false || v["writes_ok"] != false {
			t.Fatalf("verify = %v", v)
		}
		journalAccounts(t, e, res, err)
	})
	t.Run("it had not been applied: still a failure", func(t *testing.T) {
		e := unknownUser(t, rosterWith("  - {name: ua}\n  - {name: ub}\n", ""), false)
		res, err := e.execute()
		if !errors.Is(err, ErrWrites) || res.op("user.create:ub").Final() != OutcomeFailed {
			t.Fatalf("err = %v:%s", err, describeOps(res))
		}
		journalAccounts(t, e, res, err)
	})
}
