package identityreconcile

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/delivery"
	"github.com/kjelly/pilot/internal/freeiparpc"
)

// The carry-ins of the P2-5 reviews that P2-6 closes.

// P3-1. An unknown create whose object the plan made from the read after the writes
// blocks (a concurrent writer gave it another uid) holds no operation in that plan, so
// "nothing left to do" read as converged and Remaining ignored a blocked object: the run
// returned nil, a false "applied". A blocked object this run changed, or may have, is left
// undone (spec §7.6, D20), and its unknown outcome stays unknown.
func TestABlockedObjectTheRunChangedIsNeverReadAsApplied(t *testing.T) {
	const roster = "  - {name: ub, uid: 1500}\n"
	// The user_add of ub leaves and its answer is lost. It was applied; whether the
	// uid is the declared one is what the case decides.
	unknown := func(t *testing.T, appliedUID string) *runEnv {
		e := newRunEnv(t, rosterWith(roster, ""))
		e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
			if c.method == "user_add" && c.args[0] == "ub" {
				u := f.addUser("ub", "ub", "ub")
				u.uid, u.gid = appliedUID, appliedUID
				u.shell, u.display, u.mail = "/bin/bash", "", nil
				f.groups["ipausers"].users["ub"] = true
				return nil, &freeiparpc.OutcomeUnknownError{Method: "user_add", Err: errors.New("EOF")}, true
			}
			return nil, nil, false
		}
		return e
	}

	t.Run("the declared uid: converged, no failure (the control)", func(t *testing.T) {
		e := unknown(t, "1500")
		res, err := e.execute()
		if err != nil {
			t.Fatalf("err = %v:%s", err, describeOps(res))
		}
		if o := res.op("user.create:ub"); o.Resolution != resolutionConverged || o.Final() != OutcomeSuccess {
			t.Fatalf("ub: %+v", o)
		}
		if len(res.Verify.Blocked) != 0 || !res.Verify.OK() {
			t.Fatalf("verify = %+v", res.Verify)
		}
	})

	t.Run("another uid: still unknown, a write failure and a verify failure, ok false", func(t *testing.T) {
		e := unknown(t, "1700")
		res, err := e.execute()
		if err == nil {
			t.Fatalf("Execute returned nil: a false applied.%s", describeOps(res))
		}
		if !errors.Is(err, ErrWrites) || !errors.Is(err, ErrVerify) {
			t.Fatalf("err = %v, want both ErrWrites (the unknown create) and ErrVerify (the blocked object)", err)
		}
		o := res.op("user.create:ub")
		if o.Resolution != resolutionStillUnknown || o.Final() != OutcomeUnknown {
			t.Fatalf("ub: %+v: an unknown create of a blocked object must stay unknown", o)
		}
		mustContain(t, o.Detail, "blocks this object", "the detail of the unresolved operation")
		if got := res.Verify.Blocked; len(got) != 1 || got[0] != BlockedIDChange+" ub" {
			t.Fatalf("verify.blocked = %v, want [%s ub]", got, BlockedIDChange)
		}
		if res.Verify.OK() {
			t.Fatal("the verification of a run that left a blocked object is ok")
		}
		mustContain(t, err.Error(), "blocked in the read after the writes", "the error")
		v := e.journal.verifyEvent(t)
		if v["ok"] != false || fmt.Sprint(v["blocked"]) != "["+BlockedIDChange+" ub]" || v["blocked_total"] != float64(1) {
			t.Fatalf("identity.verify = %v: ok must be false and name the blocked object", v)
		}
		journalAccounts(t, e, res, err)
	})

	t.Run("an object the run created and a concurrent writer then blocked: a verify failure too", func(t *testing.T) {
		// A success, not an unknown: the create answered. Between the answer and the
		// read after the writes someone changes the uid.
		e := newRunEnv(t, rosterWith(roster, ""))
		e.f.onFind = func(f *fakeIPA, n int) {
			if n == 3 && f.users["ub"] != nil {
				f.users["ub"].uid, f.users["ub"].gid = "1700", "1700"
			}
		}
		res, err := e.execute()
		if !errors.Is(err, ErrVerify) || errors.Is(err, ErrWrites) {
			t.Fatalf("err = %v, want ErrVerify alone (every write answered)%s", err, describeOps(res))
		}
		if got := res.Verify.Blocked; len(got) != 1 || got[0] != BlockedIDChange+" ub" {
			t.Fatalf("verify.blocked = %v", got)
		}
	})

	t.Run("an object the run only refused to touch is not counted: drift of something it did not change", func(t *testing.T) {
		// S8 finds carol preserved since the plan: a conflict, nothing sent. The read
		// after the writes blocks carol (preserved_user), and that is not this run's.
		// The case exists so the rule is not widened to every attempted object.
		const preserved = "preserved_user"
		e := newRunEnv(t, rosterWith("  - {name: ua}\n  - {name: carol, state: absent}\n", ""))
		e.f.addUser("carol", "carol", "carol")
		e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
			if c.method == "user_show" && len(c.args) == 1 && c.args[0] == "carol" {
				f.users["carol"].preserved = true
			}
			return nil, nil, false
		}
		res, err := e.execute()
		if err == nil {
			t.Fatalf("the run left carol undeleted and returned nil:%s", describeOps(res))
		}
		for _, b := range res.Verify.Blocked {
			if strings.Contains(b, "carol") {
				t.Fatalf("verify.blocked = %v: an object the run refused to touch is not one it changed (%s)", res.Verify.Blocked, preserved)
			}
		}
	})
}

// A journal that refuses the record of the entry stops the run like every other stop
// before the first command: the stop is kept, the plan's operations are listed as not
// executed, nothing is written, and the gate stays shut. It returned ErrJournal with no
// Stop, no not_sent event and the result unaccounted for (P2-5 review carry-in).
func TestAJournalThatRefusesTheRecordOfTheEntryStopsTheRunLikeAnyOtherStopBeforeTheFirstCommand(t *testing.T) {
	e := newRunEnv(t, fullRoster)
	seedFullRoster(e.f)
	e.journal.failOn = func(ev Event) error {
		if ev.ID == "auth_cache" {
			return errors.New("disk full")
		}
		return nil
	}
	res, err := e.execute()
	if !errors.Is(err, ErrJournal) || errors.Is(err, ErrWrites) {
		t.Fatalf("err = %v, want ErrJournal", err)
	}
	if res.Stop == nil || res.Stop.Stage != stopEntry {
		t.Fatalf("stop = %+v, want the entry stop: this ended with no Stop at all before", res.Stop)
	}
	if len(e.f.writes()) != 0 || res.Committed() || res.Verify.Done {
		t.Fatalf("writes %v, committed %v, verify %+v: nothing may be written when the entry's record is missing", e.f.writes(), res.Committed(), res.Verify)
	}
	if !res.Entry.Ran {
		t.Fatal("the entry ran and the report says it did not: the obligation is on the server whatever the journal holds")
	}
	if o := res.Obligation(); !o.Owed || o.Source != ObligationThisRun {
		t.Fatalf("obligation = %+v: the entry ran, so it is owed", o)
	}
	ns := e.journal.notSent()
	if ns == nil || len(ns.Operations) != len(res.Plan1.Operations) || ns.Stop == nil || ns.Stop.Stage != stopEntry {
		t.Fatalf("not_sent = %+v: every operation of the plan must be listed with the stop", ns)
	}
	for _, o := range ns.Operations {
		if o.Outcome != OutcomeNotExecuted {
			t.Fatalf("%s is %s, want not_executed", o.Operation.ID, o.Outcome)
		}
	}
	if err := e.gate.Check(e.ctx, "user_add"); err == nil {
		t.Fatal("the gate is open after a stop before the first command")
	}
}

// A run with many operations that stops before its first command lists every one of
// them in the journal, in events that are each bounded: nothing is lost to the bound,
// nothing is listed twice, and no event is the size of the plan.
func TestNotSentOperationsAreChunkedIntoBoundedEventsThatHoldEveryOperationOnce(t *testing.T) {
	var users strings.Builder
	for i := 0; i < 450; i++ {
		fmt.Fprintf(&users, "  - {name: u%04d}\n", i)
	}
	e := newRunEnv(t, rosterWith(users.String(), ""))
	e.entry.err = errors.New("the entry failed")
	res, err := e.execute()
	if !errors.Is(err, ErrEntry) {
		t.Fatalf("err = %v", err)
	}
	if len(res.Plan1.Operations) < 450 {
		t.Fatalf("the plan has %d operations, the case needs hundreds", len(res.Plan1.Operations))
	}
	var seen = map[string]int{}
	var parts []notSentEvent
	e.journal.mu.Lock()
	for _, ev := range e.journal.events {
		if !strings.HasPrefix(ev.ID, "not_sent") {
			continue
		}
		raw, _ := json.Marshal(ev.Payload)
		if len(raw) > notSentMaxBytes+16*1024 { // the bound, plus one operation's worth
			t.Errorf("%s is %d bytes", ev.ID, len(raw))
		}
		p := ev.Payload.(notSentEvent)
		if len(p.Operations) > notSentMaxOps {
			t.Errorf("%s holds %d operations, the bound is %d", ev.ID, len(p.Operations), notSentMaxOps)
		}
		parts = append(parts, p)
		for _, o := range p.Operations {
			seen[o.Operation.ID]++
		}
	}
	e.journal.mu.Unlock()
	if len(parts) < 2 {
		t.Fatalf("%d not_sent events for %d operations: the bound did not split them", len(parts), len(res.Plan1.Operations))
	}
	for i, p := range parts {
		if p.Part != i+1 || p.Parts != len(parts) || p.Stop == nil || p.Stop.Stage != stopEntry {
			t.Errorf("part %d is %d of %d, stop %+v", i+1, p.Part, p.Parts, p.Stop)
		}
	}
	for _, op := range res.Plan1.Operations {
		if seen[op.ID] != 1 {
			t.Errorf("%s is in %d not_sent events, want exactly 1", op.ID, seen[op.ID])
		}
	}
	if ids := e.journal.ids(); ids[0] != "not_sent" || ids[1] != "not_sent:2" {
		t.Fatalf("event ids = %v: the first part keeps the id not_sent, the next are not_sent:2, not_sent:3…", ids)
	}
	if len(e.journal.problem) != 0 {
		t.Fatalf("journal problems: %v", e.journal.problem)
	}
}

// The size bound on its own, with operations that hold many members (a group's
// removal holds every member): by bytes, not only by count, and an operation bigger than
// the bound is alone in its part.
func TestChunkOpResultsBoundsBySizeAndKeepsOrder(t *testing.T) {
	big := func(id string, members int) OpResult {
		m := make([]string, members)
		for i := range m {
			m[i] = fmt.Sprintf("member-%06d-with-a-longish-name-to-take-room", i)
		}
		return OpResult{Operation: Operation{ID: id, Kind: KindMemberUserRemove, Object: id, Members: m}, Outcome: OutcomeNotExecuted}
	}
	ops := []OpResult{big("a", 1500), big("b", 1500), big("c", 10), big("d", 5000), big("e", 10)}
	parts := chunkOpResults(ops)
	var order []string
	for i, part := range parts {
		raw, _ := json.Marshal(part)
		if len(part) > 1 && len(raw) > notSentMaxBytes {
			t.Errorf("part %d holds %d operations in %d bytes, the bound is %d", i+1, len(part), len(raw), notSentMaxBytes)
		}
		for _, o := range part {
			order = append(order, o.Operation.ID)
		}
	}
	if strings.Join(order, "") != "abcde" {
		t.Fatalf("order after chunking = %v", order)
	}
	if len(parts) < 3 {
		t.Fatalf("%d parts: the big operations were not separated", len(parts))
	}
	if got := chunkOpResults(nil); len(got) != 0 {
		t.Fatalf("no operations make %d parts", len(got))
	}
	if got := chunkOpResults(ops[:1]); len(got) != 1 || len(got[0]) != 1 {
		t.Fatalf("one operation makes %v", got)
	}
}

// identity.verify carries at most verifyListMax entries of each list and says how many
// there are; the Result keeps them all.
func TestTheVerifyEventBoundsItsListsAndSaysHowManyThereAre(t *testing.T) {
	var users strings.Builder
	users.WriteString("  - {name: ua}\n")
	for i := 0; i < 250; i++ {
		fmt.Fprintf(&users, "  - {name: d%04d}\n", i)
	}
	e := newRunEnv(t, rosterWith(users.String(), ""))
	for i := 0; i < 250; i++ {
		name := fmt.Sprintf("d%04d", i)
		e.f.addUser(name, name, name)
		u := e.f.users[name]
		u.shell, u.display, u.mail = "/bin/bash", "", nil
		e.f.groups["ipausers"].users[name] = true
	}
	// After the one write, someone changes the shell of every other user: 250 operations in
	// the plan made from the read after the writes, none on an object this run touched.
	e.f.onFind = func(f *fakeIPA, n int) {
		if n == 3 {
			for i := 0; i < 250; i++ {
				f.users[fmt.Sprintf("d%04d", i)].shell = "/bin/zsh"
			}
		}
	}
	res, err := e.execute()
	if err != nil {
		t.Fatalf("err = %v: drift of objects the run did not touch does not fail it%s", err, describeOps(res))
	}
	if len(res.Verify.Unrelated) != 250 {
		t.Fatalf("the Result holds %d unrelated operations, want all 250", len(res.Verify.Unrelated))
	}
	v := e.journal.verifyEvent(t)
	list, _ := v["unrelated"].([]any)
	if len(list) != verifyListMax || v["unrelated_total"] != float64(250) {
		t.Fatalf("the event holds %d of %v unrelated: want %d of 250", len(list), v["unrelated_total"], verifyListMax)
	}
}

// What an owed obligation is, from the entry's report, and that ErrUnsettled is a
// partial application for the transaction.
func TestObligationFollowsTheEntryReport(t *testing.T) {
	yes, no := true, false
	for _, tc := range []struct {
		name  string
		entry EntryReport
		want  Obligation
	}{
		{"the entry ran", EntryReport{Ran: true}, Obligation{Owed: true, Source: ObligationThisRun}},
		{"an idle probe found it owing", EntryReport{Pending: &yes}, Obligation{Owed: true, Source: ObligationPreviousRun}},
		{"an idle probe found nothing owed", EntryReport{Pending: &no}, Obligation{}},
		{"the run stopped before the entry", EntryReport{}, Obligation{}},
		{"the entry ran, whatever the probe says", EntryReport{Ran: true, Pending: &no}, Obligation{Owed: true, Source: ObligationThisRun}},
	} {
		if got := (Result{Entry: tc.entry}).Obligation(); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
	wrapped := fmt.Errorf("verify: %w", ErrUnsettled)
	if !errors.Is(wrapped, ErrUnsettled) || !errors.Is(wrapped, delivery.ErrPartiallyApplied) {
		t.Fatal("ErrUnsettled must be an ErrPartiallyApplied, so the transaction ends partial_failed")
	}
}
