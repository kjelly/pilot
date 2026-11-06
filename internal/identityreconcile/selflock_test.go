package identityreconcile

import (
	"slices"
	"strings"
	"testing"

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

func plan(live liveState, d Desired) Plan {
	d.Principal = login
	groups := slices.Clone(live.groups)
	for _, g := range d.Groups {
		groups = withMarkers(groups, g.Name)
	}
	for _, n := range d.AbsentGroups {
		groups = withMarkers(groups, n)
	}
	return Build(d, live.users, groups)
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
		// S7: disabled.
		{"S7 the login disabled by the roster", base(),
			Desired{Users: []DesiredUser{duser(login, false)}},
			"the login adm would be disabled after S7 (user_enable and user_disable)", login},
		{"S7 another admin disabled", base(),
			Desired{Users: []DesiredUser{duser(login, true), duser("bob", false)}}, "", ""},
		{"S7 the login is enabled by the roster and disabled live: enabling is never blocked", func() liveState {
			s := base()
			s.users[0] = lu(login, true)
			return s
		}(), Desired{Users: []DesiredUser{duser(login, true)}}, "", ""},
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
		// S4: the login's own password.
		{"S4 the login's own password reset", resetState,
			Desired{Users: []DesiredUser{passwordUser(login, false)}},
			"S4 (passwd) would reset the password of the login adm", login},
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

// The check follows the plan, not the roster: a plan that does not touch the
// login's path is never blocked on the path, however the live graph looks.
func TestSelfLockoutIsDifferentialOnTheLivePath(t *testing.T) {
	// The reads give the login but not a group graph that shows its path to
	// admins (as a read of an incomplete directory, or a test double, might):
	// nothing is known to be lost by removing a member, so no plan is blocked
	// on reach, but the login's existence and state are still checked.
	noPath := liveState{users: []LiveUser{lu(login, false), lu("bob", false)}, groups: []LiveGroup{lg("admins", []string{"bob"}, nil)}}
	if got := protectedBlocks(plan(noPath, Desired{Groups: []DesiredGroup{dgroup("admins", true, nil, nil)}})); len(got) != 0 {
		t.Fatalf("blocked on a path the reads never showed: %+v", got)
	}
	if got := protectedBlocks(plan(noPath, Desired{Users: []DesiredUser{duser(login, false)}})); len(got) != 1 {
		t.Fatalf("a disabled login with no visible path: %+v", got)
	}
	// A login the reads do not show is not checked at all: Observe refuses such a
	// run before a plan is made, and the plans of the earlier tests are made
	// without the login among the captured users.
	if got := protectedBlocks(Build(Desired{Principal: "nobody", AbsentUsers: []string{"nobody"}}, nil, nil)); len(got) != 0 {
		t.Fatalf("blocked for a login that is not live: %+v", got)
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
