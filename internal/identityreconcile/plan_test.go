package identityreconcile

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

var capturedGroupNames = []string{"p1-team", "p1-nonposix", "p1-parent", "p1-leaf", "p1-mid", "p1-top"}

func kinds(p Plan) []string {
	var out []string
	for _, op := range p.Operations {
		out = append(out, op.Kind+" "+op.Object)
	}
	return out
}

func only(t *testing.T, p Plan, want ...string) {
	t.Helper()
	if got := kinds(p); !slices.Equal(got, want) {
		t.Fatalf("operations = %v\nwant %v\nblocked %v", got, want, p.Blocked)
	}
}

func opNamed(p Plan, kind, object string) Operation {
	for _, op := range p.Operations {
		if op.Kind == kind && op.Object == object {
			return op
		}
	}
	return Operation{}
}

func reasons(p Plan) []string {
	var out []string
	for _, b := range p.Blocked {
		out = append(out, b.Reason+" "+b.Object)
	}
	return out
}

// The capture's own state plans only the markers it never had; with them,
// nothing at all (the no-op every rerun must reach).
func TestPlanAgainstTheCaptureIsANoOp(t *testing.T) {
	users, groups := capturedLive(t)
	p := Build(capturedDesired(), users, groups)
	if len(p.Blocked) != 0 {
		t.Fatalf("blocked: %v", p.Blocked)
	}
	for _, op := range p.Operations {
		if op.Kind != KindMarkerCreate {
			t.Fatalf("unexpected operation %s %s %v", op.Kind, op.Object, op.Fields)
		}
	}
	if len(p.Operations) != len(capturedGroupNames) {
		t.Fatalf("operations = %v", kinds(p))
	}
	only(t, Build(capturedDesired(), users, withMarkers(groups, capturedGroupNames...)))
}

func TestPlanChangesOnlyTheDifferingField(t *testing.T) {
	users, groups := capturedLive(t)
	d := capturedDesired()
	d.Users[5].Shell = "/bin/bash" // p1-self
	p := Build(d, users, withMarkers(groups, capturedGroupNames...))
	only(t, p, "user.update p1-self")
	if f := opNamed(p, KindUserUpdate, "p1-self").Fields; !reflect.DeepEqual(f, map[string]Change{"loginshell": {From: "/bin/sh", To: "/bin/bash"}}) {
		t.Fatalf("fields = %v", f)
	}
}

// The playbook always sends first, last, shell and home, filling defaults;
// display name, email, uid and gid only when declared.
func TestPlanComparesDefaultsButNotUndeclaredAttributes(t *testing.T) {
	users, groups := capturedLive(t)
	d := capturedDesired()
	u := &d.Users[2] // p1-nopw: two captured mails
	u.DisplayName = nil
	u.Shell = "/bin/bash" // the default when undeclared
	p := Build(d, users, withMarkers(groups, capturedGroupNames...))
	only(t, p, "user.update p1-nopw")
	if f := opNamed(p, KindUserUpdate, "p1-nopw").Fields; len(f) != 1 || f["loginshell"].To != "/bin/bash" {
		t.Fatalf("fields = %v", f)
	}
	email := "p1-nopw@example.test"
	u.Email = &email
	p = Build(d, users, withMarkers(groups, capturedGroupNames...))
	if f := opNamed(p, KindUserUpdate, "p1-nopw").Fields["mail"]; !reflect.DeepEqual(f.To, []string{email}) {
		t.Fatalf("a declared email must replace every captured mail: %v", f)
	}
}

func TestPlanRevokesAndAddsDirectMembers(t *testing.T) {
	users, groups := capturedLive(t)
	d := capturedDesired()
	d.Groups[0].Users = []string{"p1-nopw", "p1-reset", "p1-self"} // p1-team: drop p1-keys, add p1-reset
	p := Build(d, users, withMarkers(groups, capturedGroupNames...))
	only(t, p, "group.member_user.remove p1-team", "group.member_user.add p1-team")
	if m := opNamed(p, KindMemberUserRemove, "p1-team").Members; !slices.Equal(m, []string{"p1-keys"}) {
		t.Fatalf("removed %v", m)
	}
	d.Groups[0].Authoritative = false
	only(t, Build(d, users, withMarkers(groups, capturedGroupNames...)), "group.member_user.add p1-team")
}

// Nested membership compares direct members only: p1-top reaches p1-leaf
// and p1-deep indirectly, which must never be added or removed.
func TestPlanNestedMembershipIsDirectOnly(t *testing.T) {
	users, groups := capturedLive(t)
	d := capturedDesired()
	d.Groups[5].Groups = nil // p1-top declares no member groups
	p := Build(d, users, withMarkers(groups, capturedGroupNames...))
	only(t, p, "group.member_group.remove p1-top")
	if m := opNamed(p, KindMemberGroupRemove, "p1-top").Members; !slices.Equal(m, []string{"p1-mid"}) {
		t.Fatalf("removed %v", m)
	}
}

// An authoritative group that declares no members of a kind loses all of
// them, users outside the roster included; the plan reports it.
func TestPlanUndeclaredMembershipPrunesAndIsReported(t *testing.T) {
	users, groups := capturedLive(t)
	d := capturedDesired()
	d.Groups[1].Users, d.Groups[1].UsersDeclared = nil, false // p1-nonposix
	p := Build(d, users, withMarkers(groups, capturedGroupNames...))
	only(t, p, "group.member_user.remove p1-nonposix")
	if !slices.ContainsFunc(p.Reports.ImplicitMembershipPrune, func(r PruneReport) bool {
		return r.Group == "p1-nonposix" && slices.Equal(r.Kinds, []string{"users"})
	}) {
		t.Fatalf("prune report = %v", p.Reports.ImplicitMembershipPrune)
	}
}

// Password actions follow the playbook (spec §7.1) on the captured states.
func TestPlanPasswordActions(t *testing.T) {
	users := liveUsers(t, "user-find-states", "user-find-self0", "user-find-reset0")
	declare := func(preserve bool, names ...string) Desired {
		var d Desired
		for _, n := range names {
			u := byName(users, n)
			dn := u.DisplayName
			d.Users = append(d.Users, DesiredUser{Name: n, First: u.First, Last: u.Last, DisplayName: &dn, Shell: u.Shell, Home: u.Home, Enabled: !u.Locked, HasInitialPassword: true, PreserveExisting: preserve})
		}
		return d
	}
	all := []string{"p1-nopw", "p1-reset", "p1-self", "p1-self0", "p1-reset0"}
	only(t, Build(declare(true, all...), users, nil), "user.password.initialize p1-nopw")
	p := Build(declare(false, all...), users, nil)
	only(t, p, "user.password.initialize p1-nopw", "user.password.reset p1-self", "user.password.reset p1-self0")
	if !opNamed(p, KindPasswordReset, "p1-self").Destructive {
		t.Fatal("a reset overwrites the user's own password: destructive")
	}
	d := declare(true, "p1-nopw")
	d.Users[0].HasInitialPassword = false
	only(t, Build(d, users, nil))
}

func TestPlanEnabledState(t *testing.T) {
	users, groups := capturedLive(t)
	d := capturedDesired()
	d.Users[3].Enabled = true  // p1-off
	d.Users[5].Enabled = false // p1-self
	only(t, Build(d, users, withMarkers(groups, capturedGroupNames...)), "user.enable p1-off", "user.disable p1-self")
}

// New objects come with their dependencies: membership waits for both
// sides, a disabled new user is disabled after it exists, the marker after
// its group.
func TestPlanCreatesInDependencyOrder(t *testing.T) {
	d := Desired{
		Users: []DesiredUser{{Name: "carol", First: "Carol", Last: "C", Shell: "/bin/bash", Home: "/home/carol", HasInitialPassword: true, PreserveExisting: true}},
		Groups: []DesiredGroup{
			{Name: "team-new", Description: "team-new", Type: TypePosix, Authoritative: true, Users: []string{"carol"}, UsersDeclared: true, GroupsDeclared: true},
			{Name: "data-new", Description: "data-new", Type: TypeNonPosix, Authoritative: true, Groups: []string{"team-new"}, UsersDeclared: true, GroupsDeclared: true},
		},
	}
	p := Build(d, nil, nil)
	only(t, p,
		"group.create data-new", "group.create team-new",
		"group.marker.create "+HistoryMarkerName("data-new"), "group.marker.create "+HistoryMarkerName("team-new"),
		"user.create carol", "user.password.initialize carol",
		"group.member_user.add team-new", "group.member_group.add data-new",
		"user.disable carol",
	)
	if deps := opNamed(p, KindMemberUserAdd, "team-new").DependsOn; !slices.Equal(deps, []string{"group.create:team-new", "user.create:carol"}) {
		t.Fatalf("member add depends on %v", deps)
	}
	if deps := opNamed(p, KindMemberGroupAdd, "data-new").DependsOn; !slices.Equal(deps, []string{"group.create:data-new", "group.create:team-new"}) {
		t.Fatalf("nested add depends on %v", deps)
	}
	if deps := opNamed(p, KindMarkerCreate, HistoryMarkerName("team-new")).DependsOn; !slices.Equal(deps, []string{"group.create:team-new"}) {
		t.Fatalf("marker depends on %v", deps)
	}
	if f := opNamed(p, KindGroupCreate, "data-new").Fields["nonposix"]; f.To != true {
		t.Fatalf("non-POSIX create = %v", f)
	}
	if !reflect.DeepEqual(p, Build(d, nil, nil)) {
		t.Fatal("the same input planned twice differs")
	}
}

func TestPlanDeletions(t *testing.T) {
	users, groups := capturedLive(t)
	d := capturedDesired()
	d.Users = slices.DeleteFunc(d.Users, func(u DesiredUser) bool { return u.Name == "p1-deep" })
	d.Groups = slices.DeleteFunc(d.Groups, func(g DesiredGroup) bool { return g.Name == "p1-leaf" || g.Name == "p1-mid" })
	d.Groups[len(d.Groups)-1].Groups = nil // p1-top no longer nests p1-mid
	d.AbsentUsers = []string{"p1-deep", "p1-gone"}
	d.AbsentGroups = []string{"p1-leaf", "p1-mid"}
	live := withMarkers(groups, "p1-team", "p1-nonposix", "p1-parent", "p1-top", "p1-leaf")
	p := Build(d, users, live)
	only(t, p,
		"group.marker.create "+HistoryMarkerName("p1-mid"),
		"group.member_group.remove p1-top",
		"user.delete p1-deep",
		"group.delete p1-leaf", "group.delete p1-mid",
	)
	if op := opNamed(p, KindGroupDelete, "p1-mid"); !op.Destructive || !slices.Equal(op.DependsOn, []string{"group.marker.create:" + HistoryMarkerName("p1-mid")}) {
		t.Fatalf("p1-mid delete = %+v", op)
	}
}

func TestPlanBlocks(t *testing.T) {
	users, groups := capturedLive(t)
	marked := withMarkers(groups, capturedGroupNames...)
	cases := []struct {
		name   string
		edit   func(*Desired, *[]LiveUser, *[]LiveGroup)
		reason string
		object string
	}{
		{"uid change", func(d *Desired, _ *[]LiveUser, _ *[]LiveGroup) {
			uid := int64(42)
			d.Users[0].UID = &uid
		}, BlockedIDChange, "p1-keys"},
		{"group gid change", func(d *Desired, _ *[]LiveUser, _ *[]LiveGroup) {
			gid := int64(42)
			d.Groups[0].GID = &gid
		}, BlockedIDChange, "p1-team"},
		{"type mismatch", func(d *Desired, _ *[]LiveUser, _ *[]LiveGroup) { d.Groups[1].Type = TypePosix }, BlockedTypeMismatch, "p1-nonposix"},
		{"unrecognized type", func(_ *Desired, _ *[]LiveUser, g *[]LiveGroup) {
			for i := range *g {
				if (*g)[i].Name == "p1-team" {
					(*g)[i].Type = TypeUnrecognized
				}
			}
		}, BlockedTypeUnrecognized, "p1-team"},
		{"external group", func(d *Desired, _ *[]LiveUser, _ *[]LiveGroup) { d.Groups[0].Type = "external" }, BlockedExternalGroup, "p1-team"},
		{"preserved user", func(_ *Desired, u *[]LiveUser, _ *[]LiveGroup) {
			for i := range *u {
				if (*u)[i].Name == "p1-self" {
					(*u)[i].Preserved = true
				}
			}
		}, BlockedPreservedUser, "p1-self"},
		{"marker collision", func(_ *Desired, _ *[]LiveUser, g *[]LiveGroup) {
			for i := range *g {
				if (*g)[i].Name == HistoryMarkerName("p1-team") {
					(*g)[i].Description = []string{"something else"}
				}
			}
		}, BlockedMarkerCollision, "p1-team"},
		{"case collision", func(d *Desired, _ *[]LiveUser, _ *[]LiveGroup) {
			g := d.Groups[0]
			g.Name = "P1-Team"
			d.Groups = append(d.Groups, g)
		}, BlockedCaseCollision, "p1-team"},
		{"reference to absent", func(d *Desired, _ *[]LiveUser, _ *[]LiveGroup) {
			d.Users = slices.DeleteFunc(d.Users, func(u DesiredUser) bool { return u.Name == "p1-keys" })
			d.AbsentUsers = []string{"p1-keys"}
		}, BlockedReferenceToAbsent, "p1-team"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := capturedDesired()
			u, g := slices.Clone(users), slices.Clone(marked)
			tc.edit(&d, &u, &g)
			p := Build(d, u, g)
			if !slices.Contains(reasons(p), tc.reason+" "+tc.object) {
				t.Fatalf("blocked = %v, want %s %s", reasons(p), tc.reason, tc.object)
			}
			for _, op := range p.Operations {
				if op.Object == tc.object {
					t.Fatalf("a blocked object got %s", op.Kind)
				}
			}
		})
	}
}

func TestPlanReportsSSHKeysWithoutBodies(t *testing.T) {
	users, groups := capturedLive(t)
	keys := byName(users, "p1-keys").SSHKeys
	d := capturedDesired()
	d.Users[0].SSHKeys = keys[:1]   // p1-keys: drop one key
	d.Users[1].SSHKeys = []string{} // p1-nokeys: clearing matches no keys
	p := Build(d, users, withMarkers(groups, capturedGroupNames...))
	only(t, p)
	if len(p.Reports.SSHKeys) != 1 || p.Reports.SSHKeys[0].User != "p1-keys" || len(p.Reports.SSHKeys[0].Live) != 2 {
		t.Fatalf("ssh key report = %+v", p.Reports.SSHKeys)
	}
	for _, id := range append(p.Reports.SSHKeys[0].Declared, p.Reports.SSHKeys[0].Live...) {
		if strings.Contains(id, "AAAA") {
			t.Fatalf("report shows a key body: %s", id)
		}
	}
}
