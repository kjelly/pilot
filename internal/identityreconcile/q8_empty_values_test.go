package identityreconcile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/freeiparpc"
)

// Spec Q8 (the maintainer's confirmation is pending; this is the default taken
// from the K21 captures): an empty string in the roster is refused where
// FreeIPA refuses it and is "no value" where FreeIPA accepts it.
//
//   - first, last and home_directory: the roster adapter refuses "" before any
//     read or write, as it refuses null, telling the operator to leave the key out
//     or give a value;
//   - login_shell, display_name, email and a group's description: "" is no value.
//     The plan treats it as the same state as an attribute that is absent, so a
//     plan made against an object that has none has nothing to do (Plan₃ is
//     empty after a clean apply), and one made against an object that has a value
//     clears it.

// capturedRPCError is the error of a captured answer, nil when it succeeded.
func capturedRPCError(t *testing.T, name string) *freeiparpc.RPCError {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "freeiparpc", "testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Error *freeiparpc.RPCError `json:"error"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	return env.Error
}

// What the server did with "" is what the adapter does with "": each roster key
// is mapped to the captures of the option it becomes, and the adapter refuses the
// key exactly when the server refused the option, on add and on mod alike. If a
// later server version, or a re-capture, answers differently, this row is where it
// shows.
func TestTheAdapterRefusesEmptyValuesExactlyWhereTheServerDoes(t *testing.T) {
	rows := []struct {
		rosterKey string
		option    string
		add, mod  string // captures
	}{
		{"first", "givenname", "user-add-empty-givenname", "user-mod-empty-givenname"},
		{"last", "sn", "user-add-empty-sn", "user-mod-empty-sn"},
		{"home_directory", "homedirectory", "user-add-empty-homedirectory", "user-mod-empty-homedirectory"},
		{"login_shell", "loginshell", "user-add-empty-loginshell", "user-mod-empty-loginshell"},
		{"display_name", "displayname", "user-add-empty-displayname", "user-mod-empty-displayname"},
		{"email", "mail", "user-add-empty-mail", "user-mod-empty-mail"},
	}
	for _, r := range rows {
		t.Run(r.rosterKey, func(t *testing.T) {
			addErr, modErr := capturedRPCError(t, r.add), capturedRPCError(t, r.mod)
			if (addErr == nil) != (modErr == nil) {
				t.Fatalf("add and mod disagree about %s: %v / %v", r.option, addErr, modErr)
			}
			doc := userDoc(r.rosterKey, `""`)
			if addErr != nil {
				refusedByAdapter(t, doc, "users[1] (bob): "+r.rosterKey+" must not be empty", "leave it out")
				return
			}
			d := desired(t, doc)
			bob := d.Users[1]
			got := map[string]*string{"display_name": bob.DisplayName, "email": bob.Email}
			switch r.rosterKey {
			case "login_shell":
				if bob.Shell != "" {
					t.Fatalf("Shell = %q, want the empty value kept (no shell)", bob.Shell)
				}
			default:
				if got[r.rosterKey] == nil || *got[r.rosterKey] != "" {
					t.Fatalf("%s = %v, want an empty value that is managed (not nil)", r.rosterKey, got[r.rosterKey])
				}
			}
		})
	}
	t.Run("a group description", func(t *testing.T) {
		for _, name := range []string{"group-add-empty-description", "group-mod-empty-description"} {
			if e := capturedRPCError(t, name); e != nil {
				t.Fatalf("%s: the server refused an empty description: %v", name, e)
			}
		}
		d := desired(t, "schema_version: 3\nusers: [{name: alice}]\ngroups:\n  - {name: team-a, category: team, description: \"\"}\n")
		if d.Groups[0].Description != "" {
			t.Fatalf("Description = %q, want the empty value kept (no description, not the group's name)", d.Groups[0].Description)
		}
	})
}

// The refusal says what to do and shows no value, and a key that is left out or
// given a value is untouched.
func TestEmptyRequiredValuesAreRefusedLikeNullAndOtherValuesAreNot(t *testing.T) {
	for _, key := range []string{"first", "last", "home_directory"} {
		refusedByAdapter(t, userDoc(key, `""`), key+" must not be empty", "leave it out for the default, or give a value")
		refusedByAdapter(t, userDoc(key, "~"), key+" must be a string, not null")
		d := desired(t, userDoc(key, "x"))
		if d.Users[1].First+d.Users[1].Last+d.Users[1].Home == "" {
			t.Fatalf("%s: a value was lost", key)
		}
	}
	d := desired(t, "schema_version: 3\nusers: [{name: bob}]\n")
	if u := d.Users[0]; u.First != "bob" || u.Last != "bob" || u.Home != "/home/bob" {
		t.Fatalf("the defaults changed: %+v", u)
	}
	// An absent entry is not reconciled and its fields are not read.
	if d := desired(t, "schema_version: 3\nusers: [{name: bob, state: absent, first: \"\"}]\n"); len(d.AbsentUsers) != 1 {
		t.Fatalf("an absent user with an empty first was not accepted: %+v", d)
	}
}

// live states the plan is made against, read from the captures of the server
// after it was given "": the attribute is not there (K21).
func k21Cleared(t *testing.T) (LiveUser, LiveGroup) {
	t.Helper()
	u, err := parseUser(capturedOne(t, "user-show-after-empty-mods"))
	if err != nil {
		t.Fatal(err)
	}
	g, err := parseGroup(capturedOne(t, "group-show-after-empty-description"))
	if err != nil {
		t.Fatal(err)
	}
	return u, g
}

// A live user and group as they are after the server cleared the values are the
// state "" declares: a plan has nothing to do, so an apply converges and a preview
// shows no change for it.
func TestEmptyValuesAreTheStateOfAnObjectThatHasNone(t *testing.T) {
	u, g := k21Cleared(t)
	if u.Shell != "" || u.DisplayName != "" || len(u.Mail) != 0 || len(g.Description) != 0 {
		t.Fatalf("the capture is not a cleared object: %+v / %+v", u, g)
	}
	d := Desired{
		Principal: "admin",
		Users: []DesiredUser{{Name: u.Name, First: u.First, Last: u.Last, Home: u.Home, Shell: "", Enabled: true, PreserveExisting: true,
			DisplayName: ptr(""), Email: ptr("")}},
		Groups: []DesiredGroup{{Name: g.Name, Description: "", Type: TypePosix, Authoritative: true, UsersDeclared: true, GroupsDeclared: true}},
	}
	g.Type = TypePosix // the capture is a posix group; keep it so
	groups := withMarkers([]LiveGroup{g}, g.Name)
	if p := Build(d, []LiveUser{u}, groups); len(p.Operations) != 0 || len(p.Blocked) != 0 {
		t.Fatalf("a plan against the cleared objects: %v, blocked %v", kinds(p), p.Blocked)
	}
}

// And against an object that has values, "" is a change that clears them, shown
// as what it is: the live value to nothing.
func TestEmptyValuesClearWhatTheObjectHas(t *testing.T) {
	u, err := parseUser(capturedOne(t, "user-show-all-options"))
	if err != nil {
		t.Fatal(err)
	}
	if u.Shell == "" || u.DisplayName == "" || len(u.Mail) == 0 {
		t.Fatalf("the capture has no values to clear: %+v", u)
	}
	g := LiveGroup{Name: "grp", Description: []string{"a description"}, Type: TypePosix}
	d := Desired{
		Principal: "admin",
		Users: []DesiredUser{{Name: u.Name, First: u.First, Last: u.Last, Home: u.Home, Shell: "", Enabled: true, PreserveExisting: true,
			DisplayName: ptr(""), Email: ptr("")}},
		Groups: []DesiredGroup{{Name: "grp", Description: "", Type: TypePosix, Authoritative: true, UsersDeclared: true, GroupsDeclared: true}},
	}
	p := Build(d, []LiveUser{u}, withMarkers([]LiveGroup{g}, "grp"))
	upd := opNamed(p, KindUserUpdate, u.Name)
	if upd.ID == "" || len(upd.Fields) != 3 {
		t.Fatalf("user update = %+v, want loginshell, displayname and mail", upd)
	}
	for field, want := range map[string]any{"loginshell": "", "displayname": ""} {
		if c := upd.Fields[field]; c.To != want || c.From == "" {
			t.Errorf("%s = %+v, want %q cleared from a value", field, c, want)
		}
	}
	if c := upd.Fields["mail"]; !slices.Equal(c.To.([]string), []string{}) || c.From == nil {
		t.Errorf("mail = %+v, want the values cleared (an empty list)", c)
	}
	if gu := opNamed(p, KindGroupUpdate, "grp"); gu.ID == "" || gu.Fields["description"].To != "" {
		t.Errorf("group update = %+v", gu)
	}
	// A creation sends the empty values too: the server then leaves the attribute
	// out instead of filling in its default (K21).
	p = Build(d, nil, nil)
	cr := opNamed(p, KindUserCreate, u.Name)
	for _, f := range []string{"loginshell", "displayname"} {
		if c, ok := cr.Fields[f]; !ok || c.To != "" {
			t.Errorf("a create without %s = %+v: the server would fill in its default", f, c)
		}
	}
	if c, ok := cr.Fields["mail"]; !ok || len(c.To.([]string)) != 0 {
		t.Errorf("a create without mail = %+v: the server would add <uid>@<domain>", c)
	}
	if gc := opNamed(p, KindGroupCreate, "grp"); gc.Fields["description"].To != "" {
		t.Errorf("a group create = %+v", gc)
	}
}

// Only "" is no value: a non-empty value is compared as it was.
func TestANonEmptyEmailIsStillComparedAsAValue(t *testing.T) {
	u, err := parseUser(capturedOne(t, "user-show-all-options"))
	if err != nil {
		t.Fatal(err)
	}
	same := Desired{Principal: "admin", Users: []DesiredUser{{Name: u.Name, First: u.First, Last: u.Last, Home: u.Home, Shell: u.Shell, Enabled: true, PreserveExisting: true,
		DisplayName: ptr(u.DisplayName), Email: ptr(u.Mail[0])}}}
	if p := Build(same, []LiveUser{u}, nil); len(p.Operations) != 0 {
		t.Fatalf("the live values as declared: %v", kinds(p))
	}
	other := same
	other.Users = slices.Clone(same.Users)
	other.Users[0].Email = ptr("other@example.test")
	if p := Build(other, []LiveUser{u}, nil); !slices.Equal(kinds(p), []string{"user.update " + u.Name}) {
		t.Fatalf("another email: %v", kinds(p))
	}
	// A user with two mail values is not "the" email: it is replaced by the one.
	two := u
	two.Mail = []string{u.Mail[0], "second@example.test"}
	if p := Build(same, []LiveUser{two}, nil); !slices.Equal(kinds(p), []string{"user.update " + u.Name}) {
		t.Fatalf("two live mails: %v", kinds(p))
	}
	if !strings.Contains(strings.Join(u.Mail, ""), "@") {
		t.Fatal("the capture's mail is not an address")
	}
}

func ptr[T any](v T) *T { return &v }
