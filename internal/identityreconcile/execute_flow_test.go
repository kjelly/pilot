package identityreconcile

import (
	"errors"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/freeiparpc"
)

// compile-time: the real client is what the executor takes.
var _ RPC = (*freeiparpc.Client)(nil)

// A plan with a harmless group to create, so that the first plan always has a
// write and the entry runs; the rest of each roster is what the case is about.
const base2 = "schema_version: 3\n"

func rosterWith(users, groups string) string {
	if users == "" {
		users = "[]\n"
	} else {
		users = "\n" + users
	}
	return base2 + "users: " + users + "groups:\n  - {name: team-new, category: team}\n" + groups
}

func TestExecuteStopsBeforeTheEntryWhenThePlanIsBlocked(t *testing.T) {
	// alice exists with another uidnumber than the roster's: uid_or_gid_change.
	e := newRunEnv(t, rosterWith("  - {name: alice, uid: 4242}\n", ""))
	e.f.addUser("alice", "alice", "alice")
	res, err := e.execute()
	if !errors.Is(err, ErrBlocked) || !strings.Contains(err.Error(), BlockedIDChange+" alice") {
		t.Fatalf("err = %v, want ErrBlocked naming uid_or_gid_change alice", err)
	}
	if e.entry.prepared != 0 || len(e.f.writes()) != 0 || res.Entry.Ran || res.Plan2 != nil {
		t.Fatalf("a blocked first plan: prepares %d, writes %v, entry %+v, plan2 %v", e.entry.prepared, e.f.writes(), res.Entry, res.Plan2)
	}
	if len(res.Plan1.Blocked) != 1 || res.Plan1.Blocked[0].Reason != BlockedIDChange {
		t.Fatalf("plan1 blocked = %+v", res.Plan1.Blocked)
	}
}

// The entry's failure, in each of its forms, is zero writes.
func TestExecuteWritesNothingWhenTheEntryFails(t *testing.T) {
	for name, mod := range map[string]func(*fakeEntry){
		"the entry fails": func(e *fakeEntry) { e.err = errors.New("ansible-playbook exited 2") },
		"a result for another host": func(e *fakeEntry) {
			e.result = func(a AuthCacheAction) AuthCacheResult {
				return AuthCacheResult{Action: a, Host: "ipa-2", FQDN: testFQDN}
			}
		},
		"a probe's result for a prepare": func(e *fakeEntry) {
			e.result = func(AuthCacheAction) AuthCacheResult {
				return AuthCacheResult{Action: AuthCacheProbe, Host: "ipa-1", FQDN: testFQDN}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newRunEnv(t, fullRoster)
			seedFullRoster(e.f)
			mod(e.entry)
			res, err := e.execute()
			if !errors.Is(err, ErrEntry) {
				t.Fatalf("err = %v, want ErrEntry", err)
			}
			if len(e.f.writes()) != 0 || res.Entry.Ran || len(res.Ops) != 0 || res.Committed() {
				t.Fatalf("writes %v, entry %+v, ops %d", e.f.writes(), res.Entry, len(res.Ops))
			}
			if e.f.finds != 1 {
				t.Fatalf("%d reads: nothing is read after a failed entry", e.f.finds)
			}
			// The gate stays shut.
			if err := e.gate.Check(e.ctx, "user_add"); err == nil {
				t.Fatal("the gate is open after the entry failed")
			}
		})
	}
}

// The gate is shut until the entry has been observed, and shut again when the run
// ends, whatever it ended as.
func TestExecuteOpensTheGateOnlyBetweenTheEntryAndTheEnd(t *testing.T) {
	e := newRunEnv(t, fullRoster)
	seedFullRoster(e.f)
	if err := e.gate.Check(e.ctx, "user_add"); err == nil || !strings.Contains(err.Error(), "has not been observed") {
		t.Fatalf("before the run: %v", err)
	}
	var atEntry, afterEntry error
	e.entry.onPrepare = func() { atEntry = e.gate.Check(e.ctx, "user_add") }
	e.f.onFind = func(f *fakeIPA, n int) {
		if n == 2 {
			afterEntry = e.gate.Check(e.ctx, "user_add")
		}
	}
	e.mustApply()
	if atEntry == nil {
		t.Error("the gate was open while the entry was running")
	}
	if afterEntry != nil {
		t.Errorf("the gate is shut after the entry's result was observed: %v", afterEntry)
	}
	if err := e.gate.Check(e.ctx, "user_add"); err == nil {
		t.Error("the gate is open after the run ended")
	}
}

// Plan₂ is the authority: a blocked Plan₂ is zero writes, with the entry having run.
func TestExecuteStopsWhenThePlanAfterTheEntryIsBlocked(t *testing.T) {
	e := newRunEnv(t, rosterWith("  - {name: alice, uid: 4242}\n", ""))
	// Plan₁ is not blocked: alice does not exist. The entry runs; meanwhile alice is
	// created with another uid.
	e.entry.onPrepare = func() { e.f.addUser("alice", "alice", "alice") }
	res, err := e.execute()
	if !errors.Is(err, ErrBlocked) || e.entry.prepared != 1 || len(e.f.writes()) != 0 {
		t.Fatalf("err = %v, prepares %d, writes %v", err, e.entry.prepared, e.f.writes())
	}
	if !res.Entry.Ran || res.Plan2 == nil || len(res.Plan2.Blocked) != 1 {
		t.Fatalf("entry %+v, plan2 %+v", res.Entry, res.Plan2)
	}
	if !strings.Contains(e.journal.all(), "auth_cache") {
		t.Fatal("the entry that ran is not in the journal")
	}
}

// A destructive operation Plan₂ has and Plan₁ did not is zero writes (spec §7.3):
// each kind of the set, and the control that the same operation in both plans runs.
func TestExecuteStopsForADestructiveOperationThePlanBeforeTheEntryDidNotHave(t *testing.T) {
	type row struct {
		name     string
		roster   string
		seed     func(f *fakeIPA) // the state Plan₁ is made from
		external func(f *fakeIPA) // what happens while the entry runs
		want     string           // the operation Plan₂ gains, as listed in the error
	}
	userWithPassword := func(f *fakeIPA, onReset bool) {
		u := f.addUser("alice", "alice", "alice")
		u.display, u.mail = "alice alice", nil
		u.hasPwd, u.lastPwd, u.exp = true, "20260101000000Z", "20260101000000Z"
		if !onReset {
			u.exp = "20260401000000Z"
		}
	}
	rows := []row{
		{"user.delete", rosterWith("  - {name: carol, state: absent}\n", ""),
			func(f *fakeIPA) {}, func(f *fakeIPA) { f.addUser("carol", "carol", "carol") }, "user.delete carol"},
		{"group.delete", rosterWith("", "  - {name: team-old, category: team, state: absent}\n"),
			func(f *fakeIPA) {}, func(f *fakeIPA) { f.addGroup("team-old", "old", false) }, "group.delete team-old"},
		{"user.password.reset", rosterWith("  - {name: alice, password: {initial: \"Pw-"+pwSecret+"\", preserve_existing: false}}\n", ""),
			func(f *fakeIPA) { userWithPassword(f, true) },
			func(f *fakeIPA) { f.users["alice"].exp = "20260401000000Z" }, "user.password.reset alice"},
		{"group.member_user.remove", rosterWith("  - {name: alice}\n", "  - {name: team-b, category: team, membership: {users: [alice]}}\n"),
			func(f *fakeIPA) {
				f.addUser("alice", "alice", "alice")
				g := f.addGroup("team-b", "team-b", false)
				g.users["alice"] = true
			}, func(f *fakeIPA) { f.addUser("bob", "bob", "bob"); f.groups["team-b"].users["bob"] = true }, "group.member_user.remove team-b bob"},
		{"group.member_group.remove", rosterWith("", "  - {name: team-b, category: team, membership: {groups: []}}\n"),
			func(f *fakeIPA) { f.addGroup("team-b", "team-b", false) },
			func(f *fakeIPA) { f.addGroup("team-c", "c", false); f.groups["team-b"].groups["team-c"] = true }, "group.member_group.remove team-b team-c"},
		{"user.disable", rosterWith("  - {name: bob, state: disabled}\n", ""),
			func(f *fakeIPA) { u := f.addUser("bob", "bob", "bob"); u.locked = true },
			func(f *fakeIPA) { f.users["bob"].locked = false }, "user.disable bob"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			e := newRunEnv(t, r.roster)
			r.seed(e.f)
			e.entry.onPrepare = func() { r.external(e.f) }
			res, err := e.execute()
			if !errors.Is(err, ErrDestructiveDiff) || !strings.Contains(err.Error(), r.want) {
				t.Fatalf("err = %v, want ErrDestructiveDiff naming %q\nplan1 %v plan2 %v", err, r.want, kinds(res.Plan1), res.Plan2)
			}
			if len(e.f.writes()) != 0 || !res.Entry.Ran || len(res.Ops) != 0 || res.Committed() {
				t.Fatalf("writes %v, entry %+v, ops %d", e.f.writes(), res.Entry, len(res.Ops))
			}
			if len(res.Conflicts) == 0 {
				t.Fatal("the conflicts are not in the result")
			}
		})
	}
}

// Member granularity: the removal of bob was in the plan, the removal of carol was
// not: the plan changed by one member, and that member is the conflict.
func TestExecuteComparesRemovalsMemberByMember(t *testing.T) {
	e := newRunEnv(t, rosterWith("  - {name: alice}\n", "  - {name: team-b, category: team, membership: {users: [alice]}}\n"))
	e.f.addUser("alice", "alice", "alice")
	e.f.addUser("bob", "bob", "bob")
	e.f.addUser("carol", "carol", "carol")
	g := e.f.addGroup("team-b", "team-b", false)
	g.users["alice"], g.users["bob"] = true, true
	e.entry.onPrepare = func() { g.users["carol"] = true }
	res, err := e.execute()
	if !errors.Is(err, ErrDestructiveDiff) || !strings.Contains(err.Error(), "group.member_user.remove team-b carol") || strings.Contains(err.Error(), "bob") {
		t.Fatalf("err = %v, want the removal of carol only (bob was in the plan)\n%v", err, res.Conflicts)
	}
	if len(e.f.writes()) != 0 {
		t.Fatalf("writes %v", e.f.writes())
	}
}

// The same destructive operation in both plans runs; a non-destructive operation
// Plan₂ gained runs too and is reported as a change of the plan.
func TestExecuteRunsAnOperationBothPlansHaveAndReportsWhatPlan2Added(t *testing.T) {
	e := newRunEnv(t, rosterWith("  - {name: carol, state: absent}\n  - {name: alice, login_shell: /bin/zsh}\n", ""))
	e.f.addUser("carol", "carol", "carol")
	a := e.f.addUser("alice", "alice", "alice")
	a.shell, a.display, a.mail = "/bin/zsh", "alice alice", nil
	e.entry.onPrepare = func() { a.shell = "/bin/sh" } // an update Plan₁ did not have
	res := e.mustApply()
	if res.outcomeOf("user.delete:carol") != OutcomeSuccess || res.outcomeOf("user.update:alice") != OutcomeSuccess {
		t.Fatalf("outcomes:%s", describeOps(res))
	}
	if len(res.PlanChanged.Added) != 1 || res.PlanChanged.Added[0] != "user.update alice" || len(res.PlanChanged.Removed) != 0 {
		t.Fatalf("plan changed = %+v", res.PlanChanged)
	}
	if e.f.users["alice"].shell != "/bin/zsh" || e.f.users["carol"] != nil {
		t.Fatal("the plan was not applied")
	}
}

// An entry that ran and left nothing to write is an end without a write, not an
// error: a refresh too many.
func TestExecuteEndsWithoutWritesWhenThePlanAfterTheEntryIsEmpty(t *testing.T) {
	e := newRunEnv(t, rosterWith("", ""))
	e.entry.onPrepare = func() {
		e.f.addGroup("team-new", "team-new", false)
		e.f.addGroup(HistoryMarkerName("team-new"), HistoryMarkerDescription("team-new"), true)
	}
	res, err := e.execute()
	if err != nil || !res.Entry.Ran || res.Plan2 == nil || len(res.Plan2.Operations) != 0 || len(e.f.writes()) != 0 || res.Verify.Done {
		t.Fatalf("err %v, entry %+v, plan2 %+v, writes %v", err, res.Entry, res.Plan2, e.f.writes())
	}
}
