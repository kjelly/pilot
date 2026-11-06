package identityreconcile

import (
	"context"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/inventory"
)

// The self-lockout check (spec §7.10, D24) on plans made against small live
// states: every rule has a row that must be blocked and one that must not, and
// the pair that tells a plan which creates the engine's path to admins in the same
// run (blocked: there is none between S5 and S6) from one whose path already
// exists (not blocked).

const login = "adm"

type liveState struct {
	users  []LiveUser
	groups []LiveGroup
}

func lu(name string, locked bool) LiveUser {
	return LiveUser{Name: name, First: name, Last: name, Home: "/home/" + name, Shell: "/bin/bash", Locked: locked, LastPwdChange: "20260101000000Z", PwdExpiration: "20260401000000Z"}
}

func lg(name string, users, groups []string) LiveGroup {
	return LiveGroup{Name: name, Description: []string{name}, Type: TypePosix, MemberUsers: users, MemberGroups: groups}
}

// base: the login adm and bob are admins directly; carol is in ops.
func base() liveState {
	return liveState{
		users: []LiveUser{lu(login, false), lu("bob", false), lu("carol", false)},
		groups: []LiveGroup{
			lg("admins", []string{login, "bob"}, nil),
			lg("ops", []string{"carol"}, nil),
			lg("ipausers", []string{login, "bob", "carol"}, nil),
			lg("editors", nil, nil),
			lg("trust admins", nil, nil),
		},
	}
}

// roster groups, each with the live description so no update is planned.
func dgroup(name string, authoritative bool, users, groups []string) DesiredGroup {
	return DesiredGroup{Name: name, Description: name, Type: TypePosix, Authoritative: authoritative, Users: users, Groups: groups, UsersDeclared: true, GroupsDeclared: true}
}

func duser(name string, enabled bool) DesiredUser {
	return DesiredUser{Name: name, First: name, Last: name, Home: "/home/" + name, Shell: "/bin/bash", Enabled: enabled, PreserveExisting: true}
}

// planRaw plans against the live state exactly as given.
func planRaw(live liveState, d Desired) Plan {
	d.Principal = login
	groups := slices.Clone(live.groups)
	for _, g := range d.Groups {
		groups = withMarkers(groups, g.Name)
	}
	for _, n := range d.AbsentGroups {
		groups = withMarkers(groups, n)
	}
	var p Plan
	mustReturn(returnDeadline, "Build", func() { p = Build(d, live.users, groups) })
	return p
}

// plan plans against the live state with the reads consistent, as a real server's are:
// every user carries the memberof_group user_find gives it, the transitive closure of
// the group read (captured: the admin user lists admins, and admins lists it in
// member_user). A row that needs the two reads to disagree uses planRaw.
func plan(live liveState, d Desired) Plan {
	return planRaw(consistentReads(live), d)
}

// consistentReads gives each user the groups the group read puts it in, directly or
// through groups, written independently of the planner's own walk.
func consistentReads(live liveState) liveState {
	out := liveState{groups: live.groups, users: slices.Clone(live.users)}
	for i, u := range out.users {
		seen := map[string]bool{}
		var frontier []string
		for _, g := range live.groups {
			if slices.Contains(g.MemberUsers, u.Name) {
				frontier = append(frontier, g.Name)
			}
		}
		for len(frontier) > 0 {
			cur := frontier[0]
			frontier = frontier[1:]
			if seen[cur] {
				continue
			}
			seen[cur] = true
			for _, g := range live.groups {
				if slices.Contains(g.MemberGroups, cur) {
					frontier = append(frontier, g.Name)
				}
			}
		}
		out.users[i].MemberOf = sortedKeys(seen)
	}
	return out
}

func protectedBlocks(p Plan) []Blocked {
	var out []Blocked
	for _, b := range p.Blocked {
		if b.Reason == BlockedProtectedObject {
			out = append(out, b)
		}
	}
	return out
}

func TestSelfLockoutAtEveryStageBoundary(t *testing.T) {
	withOps := base()
	withOps.groups = append(slices.Clone(withOps.groups), lg("admins2", nil, nil))
	// admins already holds ops as a member group, and the login is in ops: the
	// login's second path exists in the live state.
	pathExists := base()
	pathExists.groups = []LiveGroup{
		lg("admins", []string{login, "bob"}, []string{"ops"}),
		lg("ops", []string{login, "carol"}, nil),
		lg("ipausers", []string{login, "bob", "carol"}, nil),
		lg("editors", nil, nil),
		lg("trust admins", nil, nil),
	}
	// FreeIPA accepts group cycles (captured, spec §9 point 7): admins in ops and
	// ops in admins, the login only in ops.
	cycle := base()
	cycle.groups = []LiveGroup{
		lg("admins", []string{"bob"}, []string{"ops"}),
		lg("ops", []string{login}, []string{"admins"}),
		lg("ipausers", []string{login, "bob"}, nil),
		lg("editors", nil, nil),
		lg("trust admins", nil, nil),
	}
	// The login's one path is through team-old, itself a member of admins; the login is not
	// a direct member.
	viaOldops := func() liveState {
		s := base()
		s.groups = []LiveGroup{
			lg("admins", []string{"bob"}, []string{"team-old"}), lg("team-old", []string{login}, nil),
			lg("ipausers", []string{login, "bob", "carol"}, nil), lg("editors", nil, nil), lg("trust admins", nil, nil),
		}
		return s
	}
	resetState := base()
	for i := range resetState.users { // every user is past the reset password: an expiration after the change
		resetState.users[i].PwdExpiration = "20990101000000Z"
	}

	passwordUser := func(name string, preserve bool) DesiredUser {
		u := duser(name, true)
		u.HasInitialPassword, u.PreserveExisting = true, preserve
		u.PasswordForm, u.PasswordFormRead = inventory.PasswordLiteral, true
		return u
	}
	for _, tc := range []struct {
		name  string
		live  liveState
		d     Desired
		block string // substring of the detail of the one protected_object entry, "" for none
		obj   string
	}{
		// S5: members removed before any is added.
		{"S5 the login removed from admins with no other path", base(),
			Desired{Groups: []DesiredGroup{dgroup("admins", true, []string{"bob"}, nil)}},
			"after S5 (group_remove_member) the login adm would not be a member of admins through any group", login},
		{"S5 the other admin removed, the login stays", base(),
			Desired{Groups: []DesiredGroup{dgroup("admins", true, []string{login}, nil)}}, "", ""},
		{"S5 and S6 the login moves into admins through a group created in the same plan (the pair's trigger)", base(),
			Desired{Groups: []DesiredGroup{dgroup("admins", true, nil, []string{"newops"}), dgroup("newops", true, []string{login}, nil)}},
			"after S5 (group_remove_member) the login adm would not be a member of admins", login},
		{"S5 and S6 the login moves into admins through a group whose path already exists (the pair's control)", pathExists,
			Desired{Groups: []DesiredGroup{dgroup("admins", true, nil, []string{"ops"}), dgroup("ops", true, []string{login, "carol"}, nil)}}, "", ""},
		{"S5 the only path is removed one level up: ops leaves admins while the login is only in ops", func() liveState {
			s := base()
			s.groups = []LiveGroup{lg("admins", []string{"bob"}, []string{"ops"}), lg("ops", []string{login}, nil), lg("ipausers", []string{login, "bob"}, nil), lg("editors", nil, nil), lg("trust admins", nil, nil)}
			return s
		}(), Desired{Groups: []DesiredGroup{dgroup("admins", true, []string{"bob"}, nil), dgroup("ops", true, []string{login}, nil)}},
			"after S5 (group_remove_member)", login},
		{"S5 a cycle in the live graph: the walk ends, and the removal of the login's one edge is found", cycle,
			Desired{Groups: []DesiredGroup{dgroup("admins", true, []string{"bob"}, []string{"ops"}), dgroup("ops", true, nil, []string{"admins"})}},
			"after S5 (group_remove_member)", login},
		{"a cycle in the live graph and a plan that leaves the login's edge alone", cycle,
			Desired{Groups: []DesiredGroup{dgroup("admins", true, []string{"bob"}, []string{"ops"}), dgroup("ops", true, []string{login}, []string{"admins"})}}, "", ""},
		// The path built in the same plan and the old one removed after it: S6 adds the
		// edges (the login to newops, newops to admins), S8 deletes oldops. Not blocked,
		// which needs the walk to remember a group the plan created and the edges it adds.
		{"S6 builds the new path and S8 deletes the old one: the new one is there by then", viaOldops(),
			Desired{Groups: []DesiredGroup{
				{Name: "admins", Description: "admins", Type: TypePosix, Authoritative: false, Groups: []string{"team-new"}, GroupsDeclared: true},
				dgroup("team-new", true, []string{login}, nil),
			}, AbsentGroups: []string{"team-old"}}, "", ""},
		{"... and when the new path is never built, deleting the old one cuts the login off at S8", viaOldops(),
			Desired{Groups: []DesiredGroup{dgroup("team-new", true, []string{login}, nil)}, AbsentGroups: []string{"team-old"}},
			"after S8 (user_del and group_del) the login adm would not be a member of admins", login},
		// S7: disabled.
		{"S7 the login disabled by the roster", base(),
			Desired{Users: []DesiredUser{duser(login, false)}},
			"the login adm would be disabled after S7 (user_enable and user_disable)", login},
		{"S7 another admin disabled", base(),
			Desired{Users: []DesiredUser{duser(login, true), duser("bob", false)}}, "", ""},
		{"S7 the login is disabled live and the roster enables it: the reads disagree, they cannot be of a login the engine is using", func() liveState {
			s := base()
			s.users[0] = lu(login, true)
			return s
		}(), Desired{Users: []DesiredUser{duser(login, true)}},
			"the reads disagree: user_find shows the login adm disabled, but the engine is using it", login},
		// S8: deleted, and the groups FreeIPA depends on.
		{"S8 the login deleted by the roster", base(),
			Desired{AbsentUsers: []string{login}},
			"the login adm would not exist after S8 (user_del and group_del)", login},
		{"S8 another user deleted", base(), Desired{AbsentUsers: []string{"carol"}}, "", ""},
		{"S8 admins deleted", base(), Desired{AbsentGroups: []string{"admins"}}, "would delete the group admins", "admins"},
		{"S8 ipausers deleted", base(), Desired{AbsentGroups: []string{"ipausers"}}, "would delete the group ipausers", "ipausers"},
		{"S8 editors deleted", base(), Desired{AbsentGroups: []string{"editors"}}, "would delete the group editors", "editors"},
		{"S8 trust admins deleted", base(), Desired{AbsentGroups: []string{"trust admins"}}, "would delete the group trust admins", "trust admins"},
		{"S8 another group deleted", base(), Desired{AbsentGroups: []string{"ops"}}, "", ""},
		{"S8 a user that has the name of a protected group is deleted: it is a user, not the group", func() liveState {
			s := base()
			s.users = append(s.users, lu("editors", false))
			return s
		}(), Desired{AbsentUsers: []string{"editors"}}, "", ""},
		// S4: the login's own password.
		{"S4 the login's own password reset", resetState,
			Desired{Users: []DesiredUser{passwordUser(login, false)}},
			"S4 (passwd) would reset the password of the login adm", login},
		{"S4 the login has no password change recorded and the roster gives it one: an initialize, which is never blocked (only a reset is)", func() liveState {
			s := base()
			s.users[0].LastPwdChange, s.users[0].PwdExpiration = "", ""
			return s
		}(), Desired{Users: []DesiredUser{passwordUser(login, true)}}, "", ""},
		{"S4 another user's password reset", resetState,
			Desired{Users: []DesiredUser{passwordUser(login, true), passwordUser("bob", false)}}, "", ""},
		{"S4 the login's password declared and preserved", resetState,
			Desired{Users: []DesiredUser{passwordUser(login, true)}}, "", ""},
		// Changes that leave the login alone.
		{"an empty plan", base(), Desired{}, "", ""},
		{"a group the login is not in changes", base(),
			Desired{Groups: []DesiredGroup{dgroup("ops", true, []string{"bob"}, nil)}}, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := plan(tc.live, tc.d)
			got := protectedBlocks(p)
			if tc.block == "" {
				if len(got) != 0 {
					t.Fatalf("blocked: %+v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("protected_object entries = %+v, want one (plan %v)", got, kinds(p))
			}
			if got[0].Object != tc.obj || !strings.Contains(got[0].Detail, tc.block) {
				t.Fatalf("blocked %+v, want object %q and detail holding %q", got[0], tc.obj, tc.block)
			}
		})
	}
}

// The detail says what to do about a lost path, and names the boundary.
func TestSelfLockoutDetailTellsTheOperatorToSplitTheChange(t *testing.T) {
	p := plan(base(), Desired{Groups: []DesiredGroup{dgroup("admins", true, nil, []string{"newops"}), dgroup("newops", true, []string{login}, nil)}})
	got := protectedBlocks(p)
	if len(got) != 1 || !strings.Contains(got[0].Detail, "Change the roster in two steps") || !strings.Contains(got[0].Detail, "ACIError") {
		t.Fatalf("blocked = %+v", got)
	}
}

// The reads must agree before the check can say what a plan takes away. user_find's
// transitive memberof_group and the group read are two reads of one fact: where they
// disagree, or show the login disabled although the engine is using it, the plan is
// blocked with the reason, not passed (spec §7.10, P2-5 review F3). They agree on a
// real server, so a read that cannot show the path is a read that cannot be trusted
// with a destructive plan.
func TestSelfLockoutRefusesReadsThatDisagree(t *testing.T) {
	harmless := Desired{Groups: []DesiredGroup{dgroup("ops", true, []string{"carol"}, nil)}}
	// The login is in admins by user_find and not by the group read.
	claimedNotShown := base()
	claimedNotShown.users[0].MemberOf = []string{"admins", "ipausers"}
	claimedNotShown.groups[0] = lg("admins", []string{"bob"}, nil)
	// ... in admins by the group read and not by user_find.
	shownNotClaimed := base()
	for i := range shownNotClaimed.users {
		shownNotClaimed.users[i].MemberOf = nil
	}
	// ... in admins by neither.
	neither := base()
	neither.groups[0] = lg("admins", []string{"bob"}, nil)
	neither = consistentReads(neither)
	// The reads agree: control.
	agree := consistentReads(base())
	for _, tc := range []struct {
		name string
		live liveState
		want string // "" for no protected_object entry
	}{
		{"user_find lists admins and the group read shows no path", claimedNotShown,
			"the reads disagree: user_find lists admins among the groups of the login adm, but the group read shows no path"},
		{"the group read shows a path and user_find does not list admins", shownNotClaimed,
			"the reads disagree: the group read shows a path from the login adm to admins, but user_find does not list it"},
		{"neither read has the login in admins", neither, "the login adm is not a member of admins in the reads"},
		{"the reads agree", agree, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A plan that touches nothing of the login's: the refusal is the reads', not
			// the plan's.
			got := protectedBlocks(planRaw(tc.live, harmless))
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("blocked: %+v", got)
				}
				return
			}
			if len(got) != 1 || got[0].Object != login || !strings.Contains(got[0].Detail, tc.want) {
				t.Fatalf("protected_object = %+v, want one on %s holding %q", got, login, tc.want)
			}
			// Once: a plan that also removes the login's other path adds no second entry.
			twice := protectedBlocks(planRaw(tc.live, Desired{Groups: []DesiredGroup{dgroup("admins", true, nil, nil)}, Users: []DesiredUser{duser(login, false)}}))
			if len(twice) != 1 || twice[0].Object != login {
				t.Fatalf("a plan on top of reads that disagree: %+v", twice)
			}
		})
	}
	// A login the reads do not show is not checked at all: Observe refuses such a run
	// before a plan is made.
	if got := protectedBlocks(Build(Desired{Principal: "nobody", AbsentUsers: []string{"nobody"}}, nil, nil)); len(got) != 0 {
		t.Fatalf("blocked for a login that is not live: %+v", got)
	}
}

// The walk ends on a graph with a cycle (FreeIPA accepts one, captured: A in B and B
// in A). It runs in a child process with a deadline: a walk that does not end would
// otherwise hang the package until its timeout instead of failing this test.
func TestSelfLockoutWalkEndsOnACycle(t *testing.T) {
	if os.Getenv("PILOT_TEST_SELFLOCK_CYCLE_CHILD") == "1" {
		cycleRows(t)
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSelfLockoutWalkEndsOnACycle$", "-test.v")
	cmd.Env = append(os.Environ(), "PILOT_TEST_SELFLOCK_CYCLE_CHILD=1")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("the walk did not end on a graph with a cycle within 30s (the guard that visits each group once is gone):\n%s", out)
	}
	if err != nil || !strings.Contains(string(out), "--- PASS: TestSelfLockoutWalkEndsOnACycle") {
		t.Fatalf("the child failed: %v\n%s", err, out)
	}
}

// cycleRows are the rows the child runs: each reads a graph whose groups form a cycle.
func cycleRows(t *testing.T) {
	g := func(groups ...LiveGroup) *simGraph {
		m := map[string]LiveGroup{}
		for _, x := range groups {
			m[x.Name] = x
		}
		return newSimGraph(map[string]LiveUser{login: lu(login, false)}, m)
	}
	for _, tc := range []struct {
		name string
		g    *simGraph
		want bool
	}{
		{"the login in x, x in y, y in x, admins out of reach", g(lg("x", []string{login}, []string{"y"}), lg("y", nil, []string{"x"}), lg("admins", []string{"bob"}, nil)), false},
		{"the same cycle with y in admins: the way out of the cycle is found", g(lg("x", []string{login}, []string{"y"}), lg("y", nil, []string{"x"}), lg("admins", nil, []string{"y"})), true},
		{"the login in a, a in b, b in c, c in b: the cycle holds no group the login is directly in, so none of its groups is a seed", g(lg("a", []string{login}, nil), lg("b", nil, []string{"a", "c"}), lg("c", nil, []string{"b"}), lg("admins", []string{"bob"}, nil)), false},
		{"a group in itself", g(lg("x", []string{login}, []string{"x"}), lg("admins", []string{"bob"}, nil)), false},
		{"a cycle that does not hold the login", g(lg("x", nil, []string{"y"}), lg("y", nil, []string{"x"}), lg("ops", []string{login}, nil), lg("admins", []string{"bob"}, nil)), false},
	} {
		if got := tc.g.reaches(login, adminsGroup); got != tc.want {
			t.Errorf("%s: reaches = %v, want %v", tc.name, got, tc.want)
		}
	}
	// Through the planner: reads that agree on a cycle, then the plan that cuts the
	// login's one edge.
	cycle := base()
	cycle.groups = []LiveGroup{
		lg("admins", []string{"bob"}, []string{"ops"}), lg("ops", []string{login}, []string{"admins"}),
		lg("ipausers", []string{login, "bob"}, nil), lg("editors", nil, nil), lg("trust admins", nil, nil),
	}
	if got := protectedBlocks(plan(cycle, Desired{Groups: []DesiredGroup{dgroup("ops", true, nil, []string{"admins"})}})); len(got) != 1 || got[0].Object != login {
		t.Errorf("a plan that cuts the login's edge in a cycle: %+v", got)
	}
	// A cycle the reads show without the login's path, user_find still claiming admins:
	// the reads disagree, and the walk over the cycle ends to say so.
	broken := base()
	broken.users[0].MemberOf = []string{"admins"}
	broken.groups = []LiveGroup{
		lg("x", []string{login}, []string{"y"}), lg("y", nil, []string{"x"}), lg("admins", []string{"bob"}, nil),
		lg("ipausers", []string{login}, nil), lg("editors", nil, nil), lg("trust admins", nil, nil),
	}
	if got := protectedBlocks(planRaw(broken, Desired{})); len(got) != 1 || !strings.Contains(got[0].Detail, "the reads disagree") {
		t.Errorf("reads that disagree over a cycle: %+v", got)
	}
}

// Every protected group, by name and case: FreeIPA stores lower case, and so does
// the plan's object name.
func TestProtectedGroupsAreTheFourFreeIPADependsOn(t *testing.T) {
	want := []string{"admins", "editors", "ipausers", "trust admins"}
	got := slices.Clone(protectedGroups)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("protectedGroups = %v, want %v (spec §7.10)", got, want)
	}
	for _, name := range []string{"Admins", "IPAUSERS"} {
		p := plan(base(), Desired{AbsentGroups: []string{name}})
		if got := protectedBlocks(p); len(got) != 1 || got[0].Object != strings.ToLower(name) {
			t.Fatalf("%s: %+v", name, got)
		}
	}
}
