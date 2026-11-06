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

// The refusals, stops and classifications of the stages that a mutation of the guard
// found the package green without (spec §5.12). Where the planner would never make
// the operation that reaches a defence, the runner is built by hand with a plan of
// its own: the defence is for a plan that is wrong.

// directRunner is a runner made by hand: the desired state, the observation the
// re-reads are compared with, and the operations of a plan the test writes itself.
// The gate is open, as it is between the entry and the end of a run.
func directRunner(e *runEnv, des Desired, users []LiveUser, groups []LiveGroup, ops ...Operation) *runner {
	e.gate.open(e.held)
	opts := e.opts
	opts.Desired, opts.BatchLimit = des, MaxBatch
	r := &runner{ctx: e.ctx, rpc: e.f, opts: opts, held: e.held, res: &Result{}, des: des}
	r.obs2 = Observation{Users: users, Groups: groups}
	r.prepare(Plan{Operations: ops})
	return r
}

func opWith(kind, object string, fields map[string]Change, members ...string) Operation {
	return Operation{ID: kind + ":" + object, Kind: kind, Object: object, Fields: fields, Members: members}
}

// An operation whose command cannot be built is not sent, fails as "not sent", stops
// the stage, and nothing that was before it in the stage goes out either.
func TestAnOperationWithoutACommandStopsItsStageUnsent(t *testing.T) {
	e := newRunEnv(t, rosterWith("", ""))
	bad := opWith(KindUserCreate, "bad", map[string]Change{"mail": {To: 5}})
	fine := opWith(KindUserCreate, "fine", map[string]Change{"givenname": {To: "F"}, "sn": {To: "F"}})
	alsoBad := opWith(KindUserCreate, "alsobad", map[string]Change{"mail": {To: 6}})
	later := opWith(KindMemberUserAdd, "admins", nil, "fine")
	r := directRunner(e, e.opts.Desired, nil, nil, fine, bad, alsoBad, later)
	r.runStages()
	if o := r.res.Ops[1]; o.Outcome != OutcomeFailed || o.Error != "not sent" || !strings.Contains(o.Detail, "mail is int") {
		t.Fatalf("bad: %+v", o)
	}
	// What is around it stays unsent, a second bad operation after it included: the
	// stage ended at the first.
	if r.res.Ops[0].Outcome != OutcomeNotExecuted || r.res.Ops[2].Outcome != OutcomeNotExecuted || r.res.Ops[3].Outcome != OutcomeNotExecuted || len(e.f.writes()) != 0 {
		t.Fatalf("what is around it:%s writes %v", describeOps(r.res), e.f.writes())
	}
	if r.res.Stop == nil || r.res.Stop.Stage != "S3" || !strings.Contains(r.res.Stop.Reason, "user.create:bad") {
		t.Fatalf("stop = %+v", r.res.Stop)
	}
}

// The kinds of S5 to S8 have a command whatever their fields: the branches that handle
// a failure to build one are not reachable from a plan, and this is why. A kind that
// gains a way to fail must get its own row for what the stage does then.
func TestTheCommandsOfStagesFiveToEightCannotFailToBuild(t *testing.T) {
	for _, kind := range []string{KindMemberUserRemove, KindMemberGroupRemove, KindMemberUserAdd, KindMemberGroupAdd, KindUserEnable, KindUserDisable, KindUserDelete, KindGroupDelete} {
		for _, o := range []Operation{{Kind: kind, Object: "x"}, {Kind: kind, Object: "x", Members: []string{"a"}}, {Kind: kind, Object: "x", Fields: map[string]Change{"mail": {To: 5}}}} {
			if _, err := commandFor(o, ""); err != nil {
				t.Errorf("%s: %v", kind, err)
			}
		}
	}
}

// A user the plan has a password for but the roster no longer declares is not sent
// one: the roster is what the run was bound to, and the re-read must not outlive it.
func TestAPasswordForAUserTheRosterDoesNotDeclareIsNotSent(t *testing.T) {
	e := newRunEnv(t, rosterWith("", ""))
	aliceLive(e.f)
	r := directRunner(e, e.opts.Desired, nil, nil, op(KindPasswordInitialize, "alice"))
	r.runStages()
	if o := r.res.Ops[0]; o.Outcome != OutcomeConflictFailed || !strings.Contains(o.Detail, "no longer declared") || slices.Contains(e.f.writes(), "passwd alice") {
		t.Fatalf("%+v writes %v", o, e.f.writes())
	}
}

// A removal for a group the roster does not declare, or declares without an
// authoritative membership, is not sent; a removal of member groups is held to the
// member groups of the live group, not its users.
func TestARemovalIsHeldToTheGroupsDeclarationAndKind(t *testing.T) {
	declared := func(authoritative bool) Desired {
		d := Desired{Principal: "admin"}
		d.Groups = []DesiredGroup{{Name: "team-b", Type: TypePosix, Authoritative: authoritative, UsersDeclared: true, GroupsDeclared: true}}
		return d
	}
	seed := func(e *runEnv) {
		aliceLive(e.f)
		g := e.f.addGroup("team-b", "team-b", false)
		c := e.f.addGroup("team-c", "c", false)
		g.users["alice"], g.groups[c.name] = true, true
	}
	for _, tc := range []struct {
		name string
		des  func(base Desired) Desired
		op   Operation
		want string
	}{
		{"the group is not declared", func(b Desired) Desired { return b }, op(KindMemberUserRemove, "team-b", "alice"), "no longer declared with an authoritative membership"},
		{"the group is declared without an authoritative membership", func(Desired) Desired { return declared(false) }, op(KindMemberUserRemove, "team-b", "alice"), "no longer declared with an authoritative membership"},
		{"a member group the plan did not list is in the live group", func(Desired) Desired { return declared(true) }, op(KindMemberGroupRemove, "team-b"), "the group has members the roster would remove that the plan did not list: team-c"},
		{"a member user the plan did not list is in the live group", func(Desired) Desired { return declared(true) }, op(KindMemberUserRemove, "team-b"), "the group has members the roster would remove that the plan did not list: alice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newRunEnv(t, rosterWith("", ""))
			seed(e)
			des := tc.des(Desired{Principal: "admin"})
			r := directRunner(e, des, nil, nil, tc.op, op(KindUserDelete, "later"))
			r.runStages()
			if o := r.res.Ops[0]; o.Outcome != OutcomeConflictFailed || !strings.Contains(o.Detail, tc.want) {
				t.Fatalf("%+v, want %q", o, tc.want)
			}
			if slices.ContainsFunc(e.f.writes(), func(w string) bool { return strings.HasPrefix(w, "group_remove_member") }) {
				t.Fatalf("a removal was sent: %v", e.f.writes())
			}
			if r.res.Ops[1].Outcome != OutcomeNotExecuted || r.res.Stop == nil || r.res.Stop.Stage != "S5" {
				t.Fatalf("what follows:%s", describeOps(r.res))
			}
		})
	}
}

// A conflict in one stage stops the stages after it before they read anything.
func TestAStopMeansTheLaterStagesDoNotEvenReadAnything(t *testing.T) {
	roster := rosterWith("  - {name: ua}\n  - {name: ub}\n  - {name: carol, state: absent}\n", "  - {name: team-b, category: team, membership: {users: [ua]}}\n")
	e := newRunEnv(t, roster)
	e.f.addUser("carol", "carol", "carol")
	e.f.addUser("bob", "bob", "bob")
	g := e.f.addGroup("team-b", "team-b", false)
	g.users["bob"] = true
	e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
		if c.method == "user_add" && c.args[0] == "ua" && f.users["ua"] == nil {
			f.addUser("ua", "x", "x") // S3 conflicts
		}
		return nil, nil, false
	}
	res, err := e.execute()
	if !errors.Is(err, ErrWrites) || res.Stop == nil || res.Stop.Stage != "S3" {
		t.Fatalf("err %v:%s", err, describeOps(res))
	}
	for _, c := range e.f.calls {
		if c.method == "user_show" || c.method == "group_show" {
			t.Fatalf("a stage after the stop read %s %v", c.method, c.args)
		}
	}
	if res.outcomeOf("group.member_user.remove:team-b") != OutcomeNotExecuted || res.outcomeOf("user.delete:carol") != OutcomeNotExecuted {
		t.Fatalf("outcomes:%s", describeOps(res))
	}
}

// With more than one batch in a stage, a stop in the first sends none of the others.
func TestAStopInTheFirstBatchSendsNoLaterBatchOfTheStage(t *testing.T) {
	e := newRunEnv(t, rosterWith("  - {name: u1}\n  - {name: u2}\n  - {name: u3}\n  - {name: u4}\n  - {name: u5}\n", ""))
	e.opts.BatchLimit = 2
	e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
		if c.method == "user_add" && c.args[0] == "u1" && f.users["u1"] == nil {
			f.addUser("u1", "x", "x")
		}
		return nil, nil, false
	}
	res, err := e.execute()
	if !errors.Is(err, ErrWrites) || res.outcomeOf("user.create:u1") != OutcomeConflictFailed || res.outcomeOf("user.create:u2") != OutcomeSuccess {
		t.Fatalf("err %v:%s", err, describeOps(res))
	}
	for _, id := range []string{"user.create:u3", "user.create:u4", "user.create:u5"} {
		if res.outcomeOf(id) != OutcomeNotExecuted {
			t.Fatalf("%s was sent after the stop:%s", id, describeOps(res))
		}
	}
	if slices.Contains(e.f.writes(), "user_add u3") {
		t.Fatalf("writes %v", e.f.writes())
	}
}

// A password is one call, and its refusals are the stage's: the executor's own gate,
// the client, and the journal each keep it from going out, and each says so.
func TestAPasswordCallIsRefusedByTheGateTheClientAndTheJournal(t *testing.T) {
	roster := rosterWith("  - {name: ua, "+pw("a")+"}\n", "")
	passwdSent := func(e *runEnv) bool {
		return slices.ContainsFunc(e.f.writes(), func(w string) bool { return strings.HasPrefix(w, "passwd") })
	}
	t.Run("the executor's gate, behind a client that does not ask one", func(t *testing.T) {
		e := newRunEnv(t, roster)
		e.f.writeGate = nil
		e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
			if c.method == "user_add" {
				e.lock.Lose() // after S3's batch is received, before S4
			}
			return nil, nil, false
		}
		res, err := e.execute()
		if !errors.Is(err, ErrWrites) || passwdSent(e) || res.outcomeOf("user.password.initialize:ua") != OutcomeNotExecuted || !strings.Contains(res.Stop.Reason, "write gate") {
			t.Fatalf("err %v writes %v stop %+v:%s", err, e.f.writes(), res.Stop, describeOps(res))
		}
		if slices.Contains(e.journal.ids(), "S4-c1:sending") {
			t.Fatalf("a call the gate stopped is in the journal as sending: %v", e.journal.ids())
		}
		journalAccounts(t, e, res, err)
	})
	t.Run("the client's gate", func(t *testing.T) {
		e := newRunEnv(t, roster)
		e.f.writeGate = func(ctx context.Context, method string) error {
			if method == "passwd" {
				return errors.New("closed by the client")
			}
			return e.gate.Check(ctx, method)
		}
		res, err := e.execute()
		if !errors.Is(err, ErrWrites) || passwdSent(e) || res.outcomeOf("user.password.initialize:ua") != OutcomeNotExecuted || !strings.Contains(res.Stop.Reason, "client refused") {
			t.Fatalf("err %v stop %+v:%s", err, res.Stop, describeOps(res))
		}
		if !slices.Contains(e.journal.ids(), "S4-c1:sending") || !slices.Contains(e.journal.ids(), "S4-c1:result") {
			t.Fatalf("journal %v: a call the client refused has its sending and its result", e.journal.ids())
		}
		journalAccounts(t, e, res, err)
	})
	t.Run("the journal", func(t *testing.T) {
		e := newRunEnv(t, roster)
		e.journal.failOn = func(ev Event) error {
			if ev.ID == "S4-c1:sending" {
				return errors.New("disk full")
			}
			return nil
		}
		res, err := e.execute()
		if !errors.Is(err, ErrJournal) || passwdSent(e) || res.outcomeOf("user.password.initialize:ua") != OutcomeNotExecuted || !strings.Contains(res.Stop.Reason, "journal") {
			t.Fatalf("err %v stop %+v:%s", err, res.Stop, describeOps(res))
		}
	})
}

// A run whose first command is a password still reads once after it.
func TestARunThatSendsOnlyAPasswordIsReadBack(t *testing.T) {
	e := newRunEnv(t, "schema_version: 3\nusers:\n  - {name: alice, "+pw("a")+"}\n")
	aliceLive(e.f)
	res := e.mustApply()
	if !res.Verify.Done || !res.Verify.OK() || res.outcomeOf("user.password.initialize:alice") != OutcomeSuccess {
		t.Fatalf("verify %+v:%s", res.Verify, describeOps(res))
	}
	if v := e.journal.verifyEvent(t); v["ok"] != true || v["read_done"] != true {
		t.Fatalf("verify = %v", v)
	}
}

// Every re-read asks for the whole entry (all: true, captured, K19), and says what
// it could not read: the server's own error, and an entry that does not parse.
func TestReReadsAskForEverythingAndSayWhatTheyCouldNotRead(t *testing.T) {
	t.Run("all: true on every show", func(t *testing.T) {
		e := newRunEnv(t, fullRoster)
		seedFullRoster(e.f)
		e.mustApply()
		shows := 0
		for _, c := range e.f.calls {
			if c.method == "user_show" || c.method == "group_show" {
				shows++
				if c.opts["all"] != true {
					t.Fatalf("%s %v without all: true: %v", c.method, c.args, c.opts)
				}
			}
		}
		if shows == 0 {
			t.Fatal("the run made no re-read: the check proves nothing")
		}
	})
	t.Run("the server's error is in what the operation says", func(t *testing.T) {
		e := newRunEnv(t, "schema_version: 3\nusers:\n  - {name: alice, "+pw("a")+"}\n")
		aliceLive(e.f)
		e.f.showFails("user_show", "alice", errACI)
		res, _ := e.execute()
		mustContain(t, res.op("user.password.initialize:alice").Detail, "ACIError", "the server's error")
	})
	t.Run("an entry that does not parse is a failed read", func(t *testing.T) {
		e := newRunEnv(t, "schema_version: 3\nusers:\n  - {name: alice, "+pw("a")+"}\n")
		aliceLive(e.f)
		e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
			if c.method == "user_show" {
				return json.RawMessage(`{"result":{"cn":["nobody"]},"value":"alice"}`), nil, true // no uid
			}
			return nil, nil, false
		}
		res, err := e.execute()
		if !errors.Is(err, ErrWrites) || res.outcomeOf("user.password.initialize:alice") != OutcomeConflictFailed || slices.Contains(e.f.writes(), "passwd alice") {
			t.Fatalf("err %v:%s", err, describeOps(res))
		}
		mustContain(t, res.op("user.password.initialize:alice").Detail, "could not be read before its password was set", "the reason")
	})
	t.Run("a group entry that does not parse is a failed read", func(t *testing.T) {
		got := readShown("group_show", freeiparpc.BatchItem{Result: json.RawMessage(`{"result":{"description":["x"]}}`)})
		if got.err == nil || got.present {
			t.Fatalf("shown = %+v", got)
		}
		if got := readShown("group_show", freeiparpc.BatchItem{Err: &freeiparpc.RPCError{Name: "NotFound", Code: 4001}}); got.err != nil || got.present {
			t.Fatalf("a group that is not found: %+v", got)
		}
	})
}

// The enable of a user is sent without a re-read (it only widens), and a user that is
// gone is a conflict that says so.
func TestEnablingNeedsNoReReadAndAGoneUserIsNamed(t *testing.T) {
	t.Run("enable only: no read, the command is sent", func(t *testing.T) {
		e := newRunEnv(t, "schema_version: 3\nusers:\n  - {name: alice}\n")
		u := aliceLive(e.f)
		u.locked = true
		res := e.mustApply()
		if res.outcomeOf("user.enable:alice") != OutcomeSuccess {
			t.Fatalf("outcomes:%s", describeOps(res))
		}
		for _, c := range e.f.calls {
			if c.method == "user_show" {
				t.Fatalf("the enable was re-read: %v", c.args)
			}
		}
	})
	t.Run("a user that is gone: the reason says so, and S8 does not run", func(t *testing.T) {
		e := newRunEnv(t, rosterWith("  - {name: carol, state: disabled}\n", "  - {name: team-d, category: team, state: absent}\n"))
		e.f.addUser("carol", "carol", "carol")
		e.f.addGroup("team-d", "d", false)
		e.f.beforeShow(1, func() { delete(e.f.users, "carol") })
		res, _ := e.execute()
		mustContain(t, res.op("user.disable:carol").Detail, "not there any more", "the reason")
		if res.outcomeOf("group.delete:team-d") != OutcomeNotExecuted || res.Stop == nil || res.Stop.Stage != "S7" {
			t.Fatalf("what follows:%s", describeOps(res))
		}
	})
}

// sameUser says why a user is not the one the plan observed; each reason is its own.
func TestSameUserSaysWhyAUserIsNotTheOneObserved(t *testing.T) {
	r := &runner{users2: map[string]LiveUser{
		"known": {Name: "known", UniqueID: "u1"}, "noid": {Name: "noid"}, "other": {Name: "other", UniqueID: "u9"},
	}}
	for _, tc := range []struct {
		name string
		now  LiveUser
		want string // "" for the same user
	}{
		{"known", LiveUser{UniqueID: "u1"}, ""},
		{"known", LiveUser{}, "no ipauniqueid"},
		{"noid", LiveUser{UniqueID: "u1"}, "no ipauniqueid"},
		{"noid", LiveUser{}, "no ipauniqueid"},
		{"known", LiveUser{UniqueID: "u2"}, "another ipauniqueid"},
		{"unobserved", LiveUser{UniqueID: "u1"}, "was not in the observation"},
	} {
		got := r.sameUser(tc.name, tc.now)
		if tc.want == "" && got != "" || !strings.Contains(got, tc.want) {
			t.Errorf("%s now %+v: %q, want %q", tc.name, tc.now, got, tc.want)
		}
	}
}

// sameGroup is true only for a group that was observed, with an ipauniqueid, and has
// the same one and the same gidnumber now.
func TestSameGroupNeedsTheObservationTheIdAndTheGid(t *testing.T) {
	r := &runner{groups2: map[string]LiveGroup{
		"g": {Name: "g", UniqueID: "u1", GIDNumber: "10"}, "noid": {Name: "noid", GIDNumber: "10"},
	}}
	for _, tc := range []struct {
		name string
		now  LiveGroup
		want bool
	}{
		{"g", LiveGroup{UniqueID: "u1", GIDNumber: "10"}, true},
		{"g", LiveGroup{UniqueID: "u2", GIDNumber: "10"}, false},
		{"g", LiveGroup{UniqueID: "u1", GIDNumber: "11"}, false},
		{"noid", LiveGroup{GIDNumber: "10"}, false},
		{"unobserved", LiveGroup{UniqueID: "u1", GIDNumber: "10"}, false},
	} {
		if got := r.sameGroup(tc.name, tc.now); got != tc.want {
			t.Errorf("%s now %+v: %v, want %v", tc.name, tc.now, got, tc.want)
		}
	}
}

// A user whose observation has no uidnumber cannot be shown to be the same user, so
// it is not deleted even when the user now has none either.
func TestAUserWithoutAUidnumberIsNotDeleted(t *testing.T) {
	e := newRunEnv(t, rosterWith("", ""))
	u := e.f.addUser("carol", "carol", "carol")
	rr := &runner{des: e.opts.Desired, opts: e.opts, rpc: e.f, ctx: e.ctx}
	rr.opts.BatchLimit = MaxBatch
	rr.users2 = map[string]LiveUser{"carol": {Name: "carol", UniqueID: u.uuid}} // no uidnumber
	e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) { return nil, nil, false }
	u.uid = ""
	rr.res = &Result{Ops: []OpResult{{Operation: op(KindUserDelete, "carol"), Stage: "S8", Outcome: OutcomeNotExecuted}}}
	rr.batches, rr.covered = map[Stage]int{}, map[int]bool{}
	if rr.deleteUsers([]int{0}) || rr.res.Ops[0].Outcome != OutcomeConflictFailed || !strings.Contains(rr.res.Ops[0].Detail, "uidnumber") {
		t.Fatalf("%+v", rr.res.Ops[0])
	}
	if slices.Contains(e.f.writes(), "user_del carol") {
		t.Fatalf("writes %v", e.f.writes())
	}
}

// A group the roster wrote with capitals has its marker under the name as written
// (the playbook hashes it so): the deletion finds that marker, with the right
// description, and goes ahead.
func TestAGroupWrittenWithCapitalsIsDeletedWithItsMarkerUnderThatName(t *testing.T) {
	e := newRunEnv(t, rosterWith("", "  - {name: team-D, category: team, state: absent}\n"))
	e.f.addGroup("team-d", "d", false)
	e.f.addGroup(HistoryMarkerName("team-D"), HistoryMarkerDescription("team-D"), true)
	res := e.mustApply()
	if res.outcomeOf("group.delete:team-d") != OutcomeSuccess || e.f.groups["team-d"] != nil {
		t.Fatalf("outcomes:%s", describeOps(res))
	}
}

// Groups are checked before any is deleted: one that fails keeps the others from
// being deleted too, and stops the stage.
func TestOneGroupThatFailsItsCheckKeepsEveryGroupDeletionBack(t *testing.T) {
	e := newRunEnv(t, rosterWith("", "  - {name: team-d, category: team, state: absent}\n  - {name: team-e, category: team, state: absent}\n"))
	e.f.addGroup("team-d", "d", false)
	e.f.addGroup("team-e", "e", false)
	e.f.beforeShow(1, func() { e.f.groups[HistoryMarkerName("team-d")].desc = "something else" }) // S8's group re-read: the first of the run, there are no users
	res, err := e.execute()
	if !errors.Is(err, ErrWrites) || res.outcomeOf("group.delete:team-d") != OutcomeConflictFailed || res.outcomeOf("group.delete:team-e") != OutcomeNotExecuted {
		t.Fatalf("err %v:%s", err, describeOps(res))
	}
	if res.Stop == nil || res.Stop.Stage != "S8" || !strings.Contains(res.Stop.Reason, "no group was deleted") {
		t.Fatalf("stop = %+v", res.Stop)
	}
	if slices.ContainsFunc(e.f.writes(), func(w string) bool { return strings.HasPrefix(w, "group_del") }) {
		t.Fatalf("a group was deleted: %v", e.f.writes())
	}
	journalAccounts(t, e, res, err)
}

// A user that fails its check keeps the groups from being read at all.
func TestAUserThatFailsItsCheckKeepsTheGroupStageFromReading(t *testing.T) {
	e := newRunEnv(t, rosterWith("  - {name: carol, state: absent}\n", "  - {name: team-d, category: team, state: absent}\n"))
	e.f.addUser("carol", "carol", "carol")
	e.f.addGroup("team-d", "d", false)
	e.f.beforeShow(1, func() { e.f.users["carol"].preserved = true })
	res, err := e.execute()
	if !errors.Is(err, ErrWrites) || res.outcomeOf("user.delete:carol") != OutcomeConflictFailed || res.outcomeOf("group.delete:team-d") != OutcomeNotExecuted {
		t.Fatalf("err %v:%s", err, describeOps(res))
	}
	for _, c := range e.f.calls {
		if c.method == "group_show" {
			t.Fatalf("the group stage read %v after a user failed its check", c.args)
		}
	}
	// A stage with no users does not stop on them.
	e2 := newRunEnv(t, rosterWith("", "  - {name: team-d, category: team, state: absent}\n"))
	e2.f.addGroup("team-d", "d", false)
	if res := e2.mustApply(); res.outcomeOf("group.delete:team-d") != OutcomeSuccess {
		t.Fatalf("outcomes:%s", describeOps(res))
	}
}

// The group's removal stops the stages after S5 when the group is gone, as it does
// when a member was added.
func TestAGoneGroupAtS5StopsTheLaterStages(t *testing.T) {
	roster := rosterWith("  - {name: alice}\n", "  - {name: team-b, category: team, membership: {users: [alice]}}\n  - {name: team-d, category: team, state: absent}\n")
	e := newRunEnv(t, roster)
	for _, n := range []string{"alice", "bob"} {
		e.f.addUser(n, n, n)
	}
	g := e.f.addGroup("team-b", "team-b", false)
	g.users["alice"], g.users["bob"] = true, true
	e.f.addGroup("team-d", "d", false)
	e.f.beforeShow(1, func() { delete(e.f.groups, "team-b") })
	res, err := e.execute()
	if !errors.Is(err, ErrWrites) || res.outcomeOf("group.member_user.remove:team-b") != OutcomeConflictFailed {
		t.Fatalf("err %v:%s", err, describeOps(res))
	}
	mustContain(t, res.op("group.member_user.remove:team-b").Detail, "not there any more", "the reason")
	if res.outcomeOf("group.delete:team-d") != OutcomeNotExecuted || res.Stop == nil || res.Stop.Stage != "S5" {
		t.Fatalf("what follows:%s", describeOps(res))
	}
}

// A password the server refuses stops the stage: the user after it is not sent one.
func TestAPasswordTheServerRefusesStopsTheNextUsersPassword(t *testing.T) {
	e := newRunEnv(t, rosterWith("  - {name: ua, "+pw("a")+"}\n  - {name: ub, "+pw("b")+"}\n", ""))
	e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
		if c.method == "passwd" {
			return nil, &freeiparpc.RPCError{Code: 4203, Name: "DatabaseError", Message: "refused"}, true
		}
		return nil, nil, false
	}
	res, err := e.execute()
	if !errors.Is(err, ErrWrites) || res.outcomeOf("user.password.initialize:ua") != OutcomeFailed || res.outcomeOf("user.password.initialize:ub") != OutcomeNotExecuted {
		t.Fatalf("err %v:%s", err, describeOps(res))
	}
	n := 0
	for _, w := range e.f.writes() {
		if strings.HasPrefix(w, "passwd") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d passwords were sent, want the one that was refused", n)
	}
}

// A show answer with no entry in it is a failed read that says so, not a parse error.
func TestAShowAnswerWithoutAnEntryIsNamedAsSuch(t *testing.T) {
	e := newRunEnv(t, "schema_version: 3\nusers:\n  - {name: alice, "+pw("a")+"}\n")
	aliceLive(e.f)
	e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
		if c.method == "user_show" {
			return json.RawMessage(`{"value":"alice","summary":null}`), nil, true
		}
		return nil, nil, false
	}
	res, _ := e.execute()
	mustContain(t, res.op("user.password.initialize:alice").Detail, "the show answer has no entry", "the reason")
}

// A user that is gone and a user that fails its check in the same stage: the one that
// failed stops the stage, and the one that is gone is not settled as a noop either,
// it stays unsent with the rest; the same for groups.
func TestAFailedCheckLeavesTheNoopsOfItsStageUnsettled(t *testing.T) {
	t.Run("users", func(t *testing.T) {
		e := newRunEnv(t, rosterWith("  - {name: carol, state: absent}\n  - {name: dave, state: absent}\n", ""))
		e.f.addUser("carol", "carol", "carol")
		e.f.addUser("dave", "dave", "dave")
		e.f.beforeShow(1, func() { e.f.users["carol"].preserved = true; delete(e.f.users, "dave") })
		res, err := e.execute()
		if !errors.Is(err, ErrWrites) || res.outcomeOf("user.delete:carol") != OutcomeConflictFailed || res.outcomeOf("user.delete:dave") != OutcomeNotExecuted {
			t.Fatalf("err %v:%s", err, describeOps(res))
		}
		journalAccounts(t, e, res, err)
	})
	t.Run("groups", func(t *testing.T) {
		e := newRunEnv(t, rosterWith("", "  - {name: team-d, category: team, state: absent}\n  - {name: team-e, category: team, state: absent}\n"))
		e.f.addGroup("team-d", "d", false)
		e.f.addGroup("team-e", "e", false)
		e.f.beforeShow(1, func() {
			e.f.groups[HistoryMarkerName("team-d")].desc = "something else"
			delete(e.f.groups, "team-e")
		})
		res, err := e.execute()
		if !errors.Is(err, ErrWrites) || res.outcomeOf("group.delete:team-d") != OutcomeConflictFailed || res.outcomeOf("group.delete:team-e") != OutcomeNotExecuted {
			t.Fatalf("err %v:%s", err, describeOps(res))
		}
		journalAccounts(t, e, res, err)
	})
}

// A group delete whose group the desired state does not list as absent (a plan that is
// not the roster's) is proved by the marker under the name of its object.
func TestAGroupDeleteOfAnObjectTheRosterDoesNotListUsesItsOwnName(t *testing.T) {
	e := newRunEnv(t, rosterWith("", ""))
	g := e.f.addGroup("team-x", "x", false)
	e.f.addGroup(HistoryMarkerName("team-x"), HistoryMarkerDescription("team-x"), true)
	r := directRunner(e, e.opts.Desired,
		nil, []LiveGroup{{Name: "team-x", UniqueID: g.uuid, GIDNumber: g.gid}}, op(KindGroupDelete, "team-x"))
	r.runStages()
	if r.res.Ops[0].Outcome != OutcomeSuccess || e.f.groups["team-x"] != nil {
		t.Fatalf("%+v", r.res.Ops[0])
	}
}
