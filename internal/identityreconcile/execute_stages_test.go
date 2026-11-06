package identityreconcile

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

// The checks before the steps that are not undone or that take access away (spec
// §7.3): each has a row that must pass and a row that must be refused, with what
// happened between the plan and the check made to happen by the test, just before
// the check's re-read.

// beforeShow runs fn once, just before the n-th re-read (a user_show or group_show
// batch) of the run is answered: the moment the world changes after the plan was
// made and before the stage that depends on it.
func (f *fakeIPA) beforeShow(n int, fn func()) {
	seen, last := 0, -1
	f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
		if c.method == "user_show" || c.method == "group_show" {
			if c.batchNo != last {
				last = c.batchNo
				seen++
				if seen == n {
					fn()
				}
			}
		}
		return nil, nil, false
	}
}

// sentTo is the members of the command of a method sent for an object, "" when none.
func (f *fakeIPA) sentMembers(method, object, typ string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c.method == method && len(c.args) > 0 && c.args[0] == object {
			raw, _ := c.opts[typ].([]any)
			var out []string
			for _, m := range raw {
				out = append(out, m.(string))
			}
			return out
		}
	}
	return nil
}

func pw(name string) string { return `password: {initial: "Pw-` + name + `-` + pwSecret + `"}` }

// S4

func TestExecutePasswordIsCheckedAgainstTheUserAsItIsNow(t *testing.T) {
	roster := rosterWith("  - {name: alice, "+pw("a")+"}\n  - {name: bob, "+pw("b")+"}\n", "  - {name: team-b, category: team, membership: {users: [alice]}}\n")
	t.Run("nothing changed: both are sent", func(t *testing.T) {
		e := newRunEnv(t, roster)
		res := e.mustApply()
		if res.outcomeOf("user.password.initialize:alice") != OutcomeSuccess || res.outcomeOf("user.password.initialize:bob") != OutcomeSuccess {
			t.Fatalf("outcomes:%s", describeOps(res))
		}
	})
	t.Run("someone set alice's password: not sent, the stages after S4 do not run, bob is still sent", func(t *testing.T) {
		e := newRunEnv(t, roster)
		e.f.beforeShow(1, func() {
			u := e.f.users["alice"]
			u.hasPwd, u.lastPwd, u.exp = true, "20261107000001Z", "20270107000001Z"
		})
		res, err := e.execute()
		if !errors.Is(err, ErrWrites) {
			t.Fatalf("err = %v, want ErrWrites", err)
		}
		if res.outcomeOf("user.password.initialize:alice") != OutcomeConflictFailed {
			t.Fatalf("alice's password:%s", describeOps(res))
		}
		if res.outcomeOf("user.password.initialize:bob") != OutcomeSuccess {
			t.Fatalf("bob's password:%s", describeOps(res))
		}
		if slices.Contains(e.f.writes(), "passwd alice") {
			t.Fatalf("passwd alice was sent: %v", e.f.writes())
		}
		if res.outcomeOf("group.member_user.add:team-b") != OutcomeNotExecuted || res.Stop == nil || res.Stop.Stage != "S4" {
			t.Fatalf("what follows S4 was not stopped:%s", describeOps(res))
		}
		mustContain(t, res.op("user.password.initialize:alice").Detail, "no longer calls for", "the conflict says why")
	})
	reset := rosterWith("  - {name: alice, password: {initial: \"Pw-"+pwSecret+"\", preserve_existing: false}}\n", "")
	seed := func(f *fakeIPA) {
		u := f.addUser("alice", "alice", "alice")
		u.display, u.mail, u.hasPwd = "alice alice", nil, true
		u.lastPwd, u.exp = "20260101000000Z", "20260401000000Z" // changed by the user: not on the reset password
	}
	t.Run("a reset for a user who left the reset password is sent", func(t *testing.T) {
		e := newRunEnv(t, reset)
		seed(e.f)
		res := e.mustApply()
		if res.outcomeOf("user.password.reset:alice") != OutcomeSuccess || !slices.Contains(e.f.writes(), "passwd alice") {
			t.Fatalf("outcomes:%s", describeOps(res))
		}
	})
	t.Run("someone reset it first: the user is on the reset password again, so no second reset", func(t *testing.T) {
		e := newRunEnv(t, reset)
		seed(e.f)
		e.f.beforeShow(1, func() { e.f.users["alice"].lastPwd, e.f.users["alice"].exp = "20261107000001Z", "20261107000001Z" })
		res, err := e.execute()
		if !errors.Is(err, ErrWrites) || res.outcomeOf("user.password.reset:alice") != OutcomeConflictFailed || slices.Contains(e.f.writes(), "passwd alice") {
			t.Fatalf("err %v, writes %v:%s", err, e.f.writes(), describeOps(res))
		}
	})
	t.Run("the user is gone", func(t *testing.T) {
		e := newRunEnv(t, reset)
		seed(e.f)
		e.f.beforeShow(1, func() { delete(e.f.users, "alice") })
		res, _ := e.execute()
		if res.outcomeOf("user.password.reset:alice") != OutcomeConflictFailed {
			t.Fatalf("outcomes:%s", describeOps(res))
		}
		mustContain(t, res.op("user.password.reset:alice").Detail, "not there any more", "a user that is gone")
	})
}

// S5

func TestExecuteRemovalsAreCheckedAgainstTheGroupAsItIsNow(t *testing.T) {
	roster := rosterWith("  - {name: alice}\n", "  - {name: team-b, category: team, membership: {users: [alice]}}\n  - {name: team-c, category: team, membership: {users: [alice]}}\n  - {name: team-d, category: team, state: absent}\n")
	seed := func(f *fakeIPA) {
		for _, n := range []string{"alice", "bob", "carol"} {
			f.addUser(n, n, n)
		}
		for _, n := range []string{"team-b", "team-c"} {
			g := f.addGroup(n, n, false)
			g.users["alice"], g.users["bob"], g.users["carol"] = true, true, true
		}
		f.addGroup("team-d", "d", false)
	}
	t.Run("nothing changed: every member to remove is removed", func(t *testing.T) {
		e := newRunEnv(t, roster)
		seed(e.f)
		res := e.mustApply()
		if res.outcomeOf("group.member_user.remove:team-b") != OutcomeSuccess || res.op("group.member_user.remove:team-b").Completed != 2 {
			t.Fatalf("outcomes:%s", describeOps(res))
		}
	})
	t.Run("a member the plan did not list was added: that group is not touched and the stages after S5 do not run, the other group is", func(t *testing.T) {
		e := newRunEnv(t, roster)
		seed(e.f)
		e.f.addUser("dave", "dave", "dave")
		e.f.beforeShow(1, func() { e.f.groups["team-b"].users["dave"] = true })
		res, err := e.execute()
		if !errors.Is(err, ErrWrites) {
			t.Fatalf("err = %v", err)
		}
		if res.outcomeOf("group.member_user.remove:team-b") != OutcomeConflictFailed || e.f.sentMembers("group_remove_member", "team-b", "user") != nil {
			t.Fatalf("team-b:%s", describeOps(res))
		}
		mustContain(t, res.op("group.member_user.remove:team-b").Detail, "dave", "the member the plan did not list")
		if res.outcomeOf("group.member_user.remove:team-c") != OutcomeSuccess {
			t.Fatalf("team-c:%s", describeOps(res))
		}
		if res.outcomeOf("group.delete:team-d") != OutcomeNotExecuted || res.Stop == nil || res.Stop.Stage != "S5" {
			t.Fatalf("what follows S5:%s", describeOps(res))
		}
		if !e.f.groups["team-b"].users["bob"] || !e.f.groups["team-b"].users["dave"] {
			t.Fatal("team-b lost members")
		}
	})
	t.Run("one member has already left: the rest is removed, and the command names only them", func(t *testing.T) {
		e := newRunEnv(t, roster)
		seed(e.f)
		e.f.beforeShow(1, func() { delete(e.f.groups["team-b"].users, "carol") })
		res := e.mustApply()
		if got := e.f.sentMembers("group_remove_member", "team-b", "user"); !slices.Equal(got, []string{"bob"}) {
			t.Fatalf("sent %v, want only bob", got)
		}
		if o := res.op("group.member_user.remove:team-b"); o.Outcome != OutcomeSuccess || o.Completed != 1 {
			t.Fatalf("team-b: %+v", o)
		}
	})
	t.Run("every member has already left: nothing is sent", func(t *testing.T) {
		e := newRunEnv(t, roster)
		seed(e.f)
		e.f.beforeShow(1, func() { delete(e.f.groups["team-b"].users, "carol"); delete(e.f.groups["team-b"].users, "bob") })
		res := e.mustApply()
		if e.f.sentMembers("group_remove_member", "team-b", "user") != nil || res.outcomeOf("group.member_user.remove:team-b") != OutcomeNoop {
			t.Fatalf("team-b:%s", describeOps(res))
		}
	})
	t.Run("the group is gone", func(t *testing.T) {
		e := newRunEnv(t, roster)
		seed(e.f)
		e.f.beforeShow(1, func() { delete(e.f.groups, "team-b") })
		res, _ := e.execute()
		if res.outcomeOf("group.member_user.remove:team-b") != OutcomeConflictFailed {
			t.Fatalf("team-b:%s", describeOps(res))
		}
	})
}

// S7

func TestExecuteDisableIsCheckedAgainstTheUserAsItIsNow(t *testing.T) {
	roster := rosterWith("  - {name: alice, state: disabled}\n  - {name: carol, state: disabled}\n", "  - {name: team-d, category: team, state: absent}\n")
	seed := func(f *fakeIPA) {
		f.addUser("carol", "carol", "carol")
		f.addGroup("team-d", "d", false)
	}
	t.Run("a user this run created, declared disabled, passes: it has no earlier observation to compare", func(t *testing.T) {
		e := newRunEnv(t, roster)
		seed(e.f)
		res := e.mustApply()
		if res.outcomeOf("user.disable:alice") != OutcomeSuccess || res.outcomeOf("user.disable:carol") != OutcomeSuccess || !e.f.users["alice"].locked {
			t.Fatalf("outcomes:%s", describeOps(res))
		}
	})
	t.Run("an existing user already disabled by someone else is a noop, not a conflict", func(t *testing.T) {
		e := newRunEnv(t, roster)
		seed(e.f)
		e.f.beforeShow(1, func() { e.f.users["carol"].locked = true })
		res := e.mustApply()
		if res.outcomeOf("user.disable:carol") != OutcomeNoop || slices.Contains(e.f.writes(), "user_disable carol") {
			t.Fatalf("outcomes:%s", describeOps(res))
		}
		if res.outcomeOf("group.delete:team-d") != OutcomeSuccess {
			t.Fatalf("a noop stopped S8:%s", describeOps(res))
		}
	})
	t.Run("an existing user deleted and added again is another user: no disable, S8 does not run", func(t *testing.T) {
		e := newRunEnv(t, roster)
		seed(e.f)
		e.f.beforeShow(1, func() {
			delete(e.f.users, "carol")
			e.f.addUser("carol", "carol", "carol")
		})
		res, err := e.execute()
		if !errors.Is(err, ErrWrites) || res.outcomeOf("user.disable:carol") != OutcomeConflictFailed || slices.Contains(e.f.writes(), "user_disable carol") {
			t.Fatalf("err %v, writes %v:%s", err, e.f.writes(), describeOps(res))
		}
		mustContain(t, res.op("user.disable:carol").Detail, "another ipauniqueid", "the reason")
		if res.outcomeOf("group.delete:team-d") != OutcomeNotExecuted || res.Stop == nil || res.Stop.Stage != "S7" {
			t.Fatalf("what follows S7:%s", describeOps(res))
		}
		// A user this run created is not held to an observation it does not have,
		// so alice's disable was sent.
		if res.outcomeOf("user.disable:alice") != OutcomeSuccess {
			t.Fatalf("alice:%s", describeOps(res))
		}
	})
	t.Run("the user is gone", func(t *testing.T) {
		e := newRunEnv(t, roster)
		seed(e.f)
		e.f.beforeShow(1, func() { delete(e.f.users, "carol") })
		res, _ := e.execute()
		if res.outcomeOf("user.disable:carol") != OutcomeConflictFailed {
			t.Fatalf("outcomes:%s", describeOps(res))
		}
	})
}

// S8

func TestExecuteDeletesAreCheckedAgainstTheObjectsAsTheyAreNow(t *testing.T) {
	roster := rosterWith("  - {name: carol, state: absent}\n  - {name: dave, state: absent}\n", "  - {name: team-d, category: team, state: absent}\n")
	seed := func(f *fakeIPA) {
		f.addUser("carol", "carol", "carol")
		f.addUser("dave", "dave", "dave")
		f.addGroup("team-d", "d", false)
	}
	// The S2 marker for team-d is created first (the plan puts it there), so the
	// first re-read is S8's users, the second S8's groups.
	t.Run("everything as planned: users, then the group after its marker", func(t *testing.T) {
		e := newRunEnv(t, roster)
		seed(e.f)
		res := e.mustApply()
		for _, id := range []string{"user.delete:carol", "user.delete:dave", "group.delete:team-d"} {
			if res.outcomeOf(id) != OutcomeSuccess {
				t.Fatalf("%s:%s", id, describeOps(res))
			}
		}
	})
	t.Run("a user already deleted is nothing to do", func(t *testing.T) {
		e := newRunEnv(t, roster)
		seed(e.f)
		e.f.beforeShow(1, func() { delete(e.f.users, "dave") })
		res := e.mustApply()
		if res.outcomeOf("user.delete:dave") != OutcomeNoop || res.outcomeOf("user.delete:carol") != OutcomeSuccess || slices.Contains(e.f.writes(), "user_del dave") {
			t.Fatalf("outcomes:%s", describeOps(res))
		}
	})
	for name, tc := range map[string]struct {
		change func(f *fakeIPA)
		reason string
	}{
		"deleted and added again (another ipauniqueid and uidnumber)": {func(f *fakeIPA) { delete(f.users, "carol"); f.addUser("carol", "carol", "carol") }, "another ipauniqueid"},
		"preserved":                {func(f *fakeIPA) { f.users["carol"].preserved = true }, "preserved"},
		"read fails with an error": {nil, ""},
		"uidnumber differs":        {func(f *fakeIPA) { f.users["carol"].uid = "1" }, "uidnumber"},
	} {
		if tc.change == nil {
			continue
		}
		t.Run("a user that is "+name+": neither user is deleted, the group is not", func(t *testing.T) {
			e := newRunEnv(t, roster)
			seed(e.f)
			e.f.beforeShow(1, func() { tc.change(e.f) })
			res, err := e.execute()
			if !errors.Is(err, ErrWrites) {
				t.Fatalf("err = %v", err)
			}
			if res.outcomeOf("user.delete:carol") != OutcomeConflictFailed {
				t.Fatalf("carol:%s", describeOps(res))
			}
			mustContain(t, res.op("user.delete:carol").Detail, tc.reason, "the reason")
			// dave passed every check and is not deleted either, nor is the group.
			if res.outcomeOf("user.delete:dave") != OutcomeNotExecuted || res.outcomeOf("group.delete:team-d") != OutcomeNotExecuted {
				t.Fatalf("what S8 stopped:%s", describeOps(res))
			}
			for _, w := range e.f.writes() {
				if strings.HasPrefix(w, "user_del") || strings.HasPrefix(w, "group_del") {
					t.Fatalf("a delete was sent: %v", e.f.writes())
				}
			}
			if e.f.users["dave"] == nil || e.f.groups["team-d"] == nil {
				t.Fatal("something was deleted")
			}
		})
	}
	// groups
	for name, change := range map[string]func(f *fakeIPA){
		"the group deleted and added again": func(f *fakeIPA) { delete(f.groups, "team-d"); f.addGroup("team-d", "d", false) },
		"the marker's description changed":  func(f *fakeIPA) { f.groups[HistoryMarkerName("team-d")].desc = "something else" },
		"the marker gone":                   func(f *fakeIPA) { delete(f.groups, HistoryMarkerName("team-d")) },
		"the group's gidnumber changed":     func(f *fakeIPA) { f.groups["team-d"].gid = "7" },
	} {
		t.Run("group deletion refused when "+name, func(t *testing.T) {
			e := newRunEnv(t, roster)
			seed(e.f)
			e.f.beforeShow(2, func() { change(e.f) }) // the second re-read of the run: S8's groups
			res, err := e.execute()
			if !errors.Is(err, ErrWrites) || res.outcomeOf("group.delete:team-d") != OutcomeConflictFailed {
				t.Fatalf("err %v:%s", err, describeOps(res))
			}
			// The users were deleted before: their check passed, and the group's is its own.
			if res.outcomeOf("user.delete:carol") != OutcomeSuccess {
				t.Fatalf("carol:%s", describeOps(res))
			}
			if slices.ContainsFunc(e.f.writes(), func(w string) bool { return strings.HasPrefix(w, "group_del") }) {
				t.Fatalf("a group was deleted: %v", e.f.writes())
			}
		})
	}
	t.Run("the group is already gone", func(t *testing.T) {
		e := newRunEnv(t, roster)
		seed(e.f)
		e.f.beforeShow(2, func() { delete(e.f.groups, "team-d") })
		res := e.mustApply()
		if res.outcomeOf("group.delete:team-d") != OutcomeNoop {
			t.Fatalf("outcomes:%s", describeOps(res))
		}
	})
}

// The checks that need the login, which no plan holds (the planner blocks it
// first): the executor's own, a defence behind it.
func TestExecuteNeverDeletesOrDisablesTheLogin(t *testing.T) {
	e := newRunEnv(t, rosterWith("", ""))
	r := &runner{des: e.opts.Desired, opts: e.opts}
	r.users2 = map[string]LiveUser{"admin": {Name: "admin", UniqueID: "u1", UIDNumber: "1"}}
	if v, why := r.disableVerdict(op(KindUserDisable, "admin"), shown{present: true, user: LiveUser{Name: "admin", UniqueID: "u1"}}); v != verdictConflict || !strings.Contains(why, "login") {
		t.Fatalf("disable the login: %v %q", v, why)
	}
	if v, _ := r.disableVerdict(op(KindUserDisable, "bob"), shown{present: true, user: LiveUser{Name: "bob", UniqueID: "u2"}}); v != verdictConflict {
		t.Fatalf("a user absent from the observation: %v", v)
	}
	r.users2["bob"] = LiveUser{Name: "bob", UniqueID: "u2"}
	if v, _ := r.disableVerdict(op(KindUserDisable, "bob"), shown{present: true, user: LiveUser{Name: "bob", UniqueID: "u2"}}); v != verdictOK {
		t.Fatalf("the user as observed: %v", v)
	}
	if v, _ := r.disableVerdict(op(KindUserDisable, "bob"), shown{present: true, user: LiveUser{Name: "bob", UniqueID: "u2", Locked: true}}); v != verdictNoop {
		t.Fatalf("already disabled: %v", v)
	}
	// A user without an ipauniqueid cannot be told from one added again.
	r.users2["eve"] = LiveUser{Name: "eve"}
	if v, why := r.disableVerdict(op(KindUserDisable, "eve"), shown{present: true, user: LiveUser{Name: "eve"}}); v != verdictConflict || !strings.Contains(why, "no ipauniqueid") {
		t.Fatalf("no ipauniqueid: %v %q", v, why)
	}
	// deletion: the login is refused before anything is sent.
	rr := &runner{des: e.opts.Desired, opts: e.opts, rpc: e.f, ctx: e.ctx}
	rr.opts.BatchLimit = MaxBatch
	rr.users2 = map[string]LiveUser{"admin": {Name: "admin", UniqueID: "00000000-0000-0000-0000-000000000001", UIDNumber: "1000001"}}
	rr.res = &Result{Ops: []OpResult{{Operation: op(KindUserDelete, "admin"), Stage: "S8", Outcome: OutcomeNotExecuted}}}
	rr.batches = map[Stage]int{}
	if rr.deleteUsers([]int{0}) || rr.res.Ops[0].Outcome != OutcomeConflictFailed || strings.Contains(strings.Join(e.f.writes(), ","), "user_del") {
		t.Fatalf("deleting the login: %+v", rr.res.Ops[0])
	}
}
