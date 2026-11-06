package identityreconcile

import (
	"reflect"
	"slices"
	"testing"
	"time"
)

// The same desired and live state plan the same operations in the same
// order, whatever order the roster and the reads list them in (spec §10.1).
func TestPlanIsDeterministic(t *testing.T) {
	d := capturedDesired()
	d.Users[0].Shell = "/bin/zsh" // an update
	d.Users = append(d.Users, DesiredUser{Name: "p1-new", First: "n", Last: "n", Shell: "/bin/bash", Home: "/home/p1-new", Enabled: true, PreserveExisting: true})
	d.Groups[0].Users = []string{"p1-keys", "p1-new"} // add and revoke
	d.AbsentUsers = []string{"p1-reset0"}
	users, groups := capturedLive(t)
	first := Build(d, users, groups)
	if len(first.Operations) < 4 {
		t.Fatalf("the fixture should plan several operations, got %+v", first.Operations)
	}
	for i := 0; i < 3; i++ {
		rd := d
		rd.Users = slices.Clone(d.Users)
		rd.Groups = slices.Clone(d.Groups)
		slices.Reverse(rd.Users)
		slices.Reverse(rd.Groups)
		ru, rg := slices.Clone(users), slices.Clone(groups)
		slices.Reverse(ru)
		slices.Reverse(rg)
		if again := Build(rd, ru, rg); !reflect.DeepEqual(first, again) {
			t.Fatalf("reordered input planned differently:\n%+v\n%+v", first.Operations, again.Operations)
		}
		if again := Build(d, users, groups); !reflect.DeepEqual(first, again) {
			t.Fatal("the same input planned twice differs")
		}
	}
}

// A live change moves the observation fingerprint and the operations; the
// same live state keeps both (spec §10.1).
func TestLiveChangeMovesTheFingerprintAndThePlan(t *testing.T) {
	d := capturedDesired()
	users, groups := capturedLive(t)
	groups = withMarkers(groups, "p1-team", "p1-nonposix", "p1-parent", "p1-leaf", "p1-mid", "p1-top")
	doc := func(users []LiveUser) Document {
		plan := Build(d, users, groups)
		return NewDocument(d, Observation{Users: users, Groups: groups}, plan, Target{}, Server{}, "rev", time.Unix(0, 0), Stats{})
	}
	base := doc(users)
	if len(base.Operations) != 0 {
		t.Fatalf("the capture with markers should be a no-op, got %+v", base.Operations)
	}
	if same := doc(slices.Clone(users)); same.Observation.Fingerprint != base.Observation.Fingerprint || same.DesiredRevision != base.DesiredRevision {
		t.Fatal("the same state gave another fingerprint")
	}
	drifted := slices.Clone(users)
	for i := range drifted {
		if drifted[i].Name == "p1-nopw" {
			drifted[i].Shell = "/sbin/nologin"
		}
	}
	changed := doc(drifted)
	if changed.Observation.Fingerprint == base.Observation.Fingerprint {
		t.Fatal("a live change kept the observation fingerprint")
	}
	if len(changed.Operations) != 1 || changed.Operations[0].ID != KindUserUpdate+":p1-nopw" {
		t.Fatalf("the live change should plan one user.update, got %+v", changed.Operations)
	}
	if changed.DesiredRevision != base.DesiredRevision {
		t.Fatal("a live change moved the desired revision")
	}
}

const grantsBase = `
schema_version: 3
users:
  - name: alice
  - name: vendor01
groups:
  - name: team-sre
    category: team
    membership: {users: [alice], groups: []}
hosts:
  - name: db-special.ipa.pilot.internal
    ip_address: 10.0.0.5
hostgroups:
  - name: production-db
`

// Grants compile to HBAC and sudo rules only (grant_compile.go), so an
// expired grant leaves the users/groups plan as it is without grants
// (spec §10.1, the plan's "逾期 grants").
func TestExpiredGrantsLeaveTheUsersGroupsPlanAlone(t *testing.T) {
	without := desired(t, grantsBase)
	with := desired(t, grantsBase+`
grants:
  - name: vendor-window
    kind: temporary_grant
    subjects: {users: [vendor01], groups: [team-sre]}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: [production-db]}
    services: [sshd]
    validity: {not_before: "2020-01-01T00:00:00+08:00", not_after: "2020-01-02T00:00:00+08:00"}
    justification: {reason: "expired window"}
`)
	if !slices.Contains(with.NotInScope, "grants") {
		t.Fatalf("grants should be reported as not in scope, got %v", with.NotInScope)
	}
	users, groups := capturedLive(t)
	a, b := Build(without, users, groups), Build(with, users, groups)
	a.Reports.NotInScope, b.Reports.NotInScope = nil, nil
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("an expired grant changed the users/groups plan:\n%+v\n%+v", a, b)
	}
	if len(a.Operations) == 0 {
		t.Fatal("the comparison should cover a plan with operations")
	}
}
