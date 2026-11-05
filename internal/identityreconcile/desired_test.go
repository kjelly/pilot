package identityreconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const validRoster = `
schema_version: 3
freeipa:
  admin: {principal: ipa-admin}
users:
  - name: alice
  - name: bob
    first: Bob
    last: Builder
    display_name: Bob B
    email: bob@example.test
    uid: 1200
    gid: 1200
    login_shell: /bin/zsh
    home_directory: /srv/bob
    password: {initial: "x-not-read", preserve_existing: false}
    ssh_keys: {values: []}
  - {name: carol, state: disabled}
  - {name: dave, state: absent}
groups:
  - name: team-a
    category: team
    membership: {users: [alice, bob]}
  - name: data-a
    category: filesystem
    type: nonposix
    description: Data A
    membership: {authoritative: false, groups: [team-a]}
  - {name: role-old, category: role, state: absent}
hostgroups:
  - {name: hg-a}
`

func TestFromRosterFillsThePlaybookDefaults(t *testing.T) {
	d := desired(t, validRoster)
	if d.Principal != "ipa-admin" || d.SchemaVersion != 3 {
		t.Fatalf("principal/version = %s/%d", d.Principal, d.SchemaVersion)
	}
	alice := d.Users[0]
	want := DesiredUser{Name: "alice", First: "alice", Last: "alice", Shell: "/bin/bash", Home: "/home/alice", Enabled: true, PreserveExisting: true}
	if !reflect.DeepEqual(alice, want) {
		t.Fatalf("alice = %+v\nwant  %+v", alice, want)
	}
	bob := d.Users[1]
	if *bob.UID != 1200 || *bob.Email != "bob@example.test" || bob.Home != "/srv/bob" || !bob.HasInitialPassword || bob.PreserveExisting {
		t.Fatalf("bob = %+v", bob)
	}
	if bob.SSHKeys == nil || len(bob.SSHKeys) != 0 {
		t.Fatalf("ssh_keys.values: [] must mean clear (non-nil, empty), got %#v", bob.SSHKeys)
	}
	if alice.SSHKeys != nil {
		t.Fatal("undeclared ssh_keys must be unmanaged (nil)")
	}
	if d.Users[2].Enabled {
		t.Fatal("state: disabled defaults enabled to false")
	}
	if !slices.Equal(d.AbsentUsers, []string{"dave"}) || !slices.Equal(d.AbsentGroups, []string{"role-old"}) {
		t.Fatalf("absent = %v %v", d.AbsentUsers, d.AbsentGroups)
	}
	team, data := d.Groups[0], d.Groups[1]
	if team.Description != "team-a" || team.Type != TypePosix || !team.Authoritative || !slices.Equal(team.Users, []string{"alice", "bob"}) || team.GroupsDeclared {
		t.Fatalf("team-a = %+v", team)
	}
	if data.Type != TypeNonPosix || data.Authoritative || data.Description != "Data A" || !slices.Equal(data.Groups, []string{"team-a"}) {
		t.Fatalf("data-a = %+v", data)
	}
	if !slices.Equal(d.NotInScope, []string{"hostgroups"}) {
		t.Fatalf("not in scope = %v", d.NotInScope)
	}
}

// The desired state never holds a password value, so neither does the
// input of its fingerprint.
func TestDesiredStateHoldsNoPassword(t *testing.T) {
	d := desired(t, validRoster)
	if data, _ := json.Marshal(d); strings.Contains(string(data), "x-not-read") || strings.Contains(fmt.Sprintf("%+v", d), "x-not-read") {
		t.Fatal("the initial password reached the desired state")
	}
}

func TestFromRosterRefuses(t *testing.T) {
	for _, tc := range []struct {
		name, doc, want string
	}{
		{"legacy roster", "users: []\n", "no schema_version"},
		{"invalid roster", "schema_version: 3\nusers:\n  - {name: Bad}\n", "invalid"},
		{"string enabled", "schema_version: 3\nusers:\n  - {name: a, enabled: \"yes\"}\n", "true or false"},
		{"string authoritative", "schema_version: 3\nusers: [{name: a}]\ngroups:\n  - {name: team-a, category: team, membership: {authoritative: \"no\", users: [a]}}\n", "true or false"},
		{"string preserve_existing", "schema_version: 3\nusers:\n  - {name: a, password: {preserve_existing: \"false\"}}\n", "must be true or false"},
		{"text uid", "schema_version: 3\nusers:\n  - {name: a, uid: \"12x\"}\n", "non-negative integer"},
		{"numeric shell", "schema_version: 3\nusers:\n  - {name: a, login_shell: 5}\n", "must be a string"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := FromRoster(roster(t, tc.doc))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// A finder that records each call and answers from captured files.
type fakeFinder struct {
	answers map[string][]map[string]any // method + "/preserved" for the preserved read
	calls   []map[string]any
}

func (f *fakeFinder) Find(_ context.Context, method string, _ []any, opts map[string]any) ([]map[string]any, error) {
	f.calls = append(f.calls, map[string]any{"method": method, "opts": opts})
	key := method
	if opts["preserved"] == true {
		key += "/preserved"
	}
	a, ok := f.answers[key]
	if !ok {
		return nil, errors.New("no answer for " + key)
	}
	return a, nil
}

// admins adds admins to a captured user's memberof_group. A real admin
// entry (spec §9 K4) replaces this once captured.
func admins(t *testing.T, name string) []map[string]any {
	users := captured(t, "user-find-states")
	for _, u := range users {
		if uid := u["uid"].([]any); uid[0] == name {
			u["memberof_group"] = append(u["memberof_group"].([]any), "admins")
		}
	}
	return users
}

func TestObserveReadsEverythingWithAllAndChecksTheReader(t *testing.T) {
	f := &fakeFinder{answers: map[string][]map[string]any{
		"user_find":           admins(t, "p1-self"),
		"user_find/preserved": captured(t, "user-find-no-match"),
		"group_find":          captured(t, "group-find-states"),
	}}
	obs, err := Observe(context.Background(), f, "P1-Self")
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.Users) != 6 || len(obs.Groups) != 3 {
		t.Fatalf("observed %d users, %d groups", len(obs.Users), len(obs.Groups))
	}
	if len(f.calls) != 3 {
		t.Fatalf("calls = %v", f.calls)
	}
	for _, c := range f.calls {
		if c["opts"].(map[string]any)["all"] != true {
			t.Fatalf("%v read without all: true", c)
		}
	}
	if f.calls[1]["opts"].(map[string]any)["preserved"] != true {
		t.Fatalf("second read = %v, want the preserved users", f.calls[1])
	}

	for _, principal := range []string{"p1-keys", "nobody"} {
		f := &fakeFinder{answers: map[string][]map[string]any{"user_find": admins(t, "p1-self")}}
		if _, err := Observe(context.Background(), f, principal); err == nil || !strings.Contains(err.Error(), "admins") {
			t.Fatalf("reader %s: err = %v, want the admins refusal", principal, err)
		}
		if len(f.calls) != 1 {
			t.Fatalf("reader %s: kept reading after the refusal: %v", principal, f.calls)
		}
	}
}

func TestObserveFailsOnAFailedRead(t *testing.T) {
	f := &fakeFinder{answers: map[string][]map[string]any{
		"user_find":           admins(t, "p1-self"),
		"user_find/preserved": captured(t, "user-find-no-match"),
	}}
	if _, err := Observe(context.Background(), f, "p1-self"); err == nil {
		t.Fatal("a failed group read did not fail the observation")
	}
}
