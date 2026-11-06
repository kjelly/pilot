package identityreconcile

import (
	"slices"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

// password_value_unsupported (spec §7.8): a password operation that is planned
// for a user whose password.initial the engine cannot set is blocked, with none
// of that user's operations planned; a run that needs no password operation is
// not blocked because of one it does not make.

const pwSecret = "Sentinel-Initial-Pw-1"

func passwordRoster(scalar string) string {
	return "schema_version: 3\nusers:\n  - {name: alice}\n  - name: bob\n    password:\n      initial: " + scalar + "\n"
}

func TestPasswordValueFormsDecideWhetherAPasswordOperationIsPlanned(t *testing.T) {
	// bob is new: a password initialize is planned for him.
	for _, tc := range []struct {
		name   string
		scalar string
		block  string // part of the detail, "" when the operation is planned
	}{
		{"a quoted string", `"` + pwSecret + `"`, ""},
		{"a plain string", pwSecret, ""},
		{"!unsafe", `!unsafe "` + pwSecret + `"`, ""},
		{"a template", `"{{ lookup('env', 'X') }}-` + pwSecret + `"`, "is a Jinja template"},
		{"an inline !vault value", "!vault |\n          $ANSIBLE_VAULT;1.1;AES256\n          6162636465", "is an inline !vault value"},
		{"yes, which YAML 1.1 reads as a boolean", `yes`, "may be read as something other than a string"},
		{"base 60, which YAML 1.1 reads as a number", `190:20:30`, "may be read as something other than a string"},
		{"an empty string", `""`, "is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := desiredForPlan(t, passwordRoster(tc.scalar))
			p := Build(d, []LiveUser{{Name: "alice", First: "alice", Last: "alice", Home: "/home/alice", Shell: "/bin/bash"}}, nil)
			if tc.block == "" {
				if !slices.Contains(kinds(p), "user.password.initialize bob") || len(p.Blocked) != 0 {
					t.Fatalf("operations %v, blocked %v", kinds(p), p.Blocked)
				}
				return
			}
			if len(p.Blocked) != 1 || p.Blocked[0].Reason != BlockedPasswordValue || p.Blocked[0].Object != "bob" || !strings.Contains(p.Blocked[0].Detail, tc.block) {
				t.Fatalf("blocked = %+v, want one %s for bob holding %q", p.Blocked, BlockedPasswordValue, tc.block)
			}
			// None of the user's operations is planned: a created user without its
			// password would be half of what the roster declares.
			if got := kinds(p); len(got) != 0 {
				t.Fatalf("operations planned for a blocked user: %v", got)
			}
			if strings.Contains(p.Blocked[0].Detail, pwSecret) {
				t.Fatalf("the detail shows the password: %q", p.Blocked[0].Detail)
			}
		})
	}
}

// Only a planned password operation blocks: the same unreadable forms on a user
// whose password is left alone (preserve_existing, a Kerberos key in place) block
// nothing, so a run that has no password work is not stopped by them, and a user
// with no password declared is not either.
func TestPasswordValueOnlyBlocksAPlannedPasswordOperation(t *testing.T) {
	live := LiveUser{Name: "bob", First: "bob", Last: "bob", Home: "/home/bob", Shell: "/bin/bash", LastPwdChange: "20260101000000Z", PwdExpiration: "20260401000000Z"}
	for _, scalar := range []string{`"{{ x }}"`, "!vault |\n          $ANSIBLE_VAULT;1.1;AES256\n          6162636465", `yes`, `""`} {
		d := desiredForPlan(t, passwordRoster(scalar))
		p := Build(d, []LiveUser{{Name: "alice", First: "alice", Last: "alice", Home: "/home/alice", Shell: "/bin/bash"}, live}, nil)
		if len(p.Blocked) != 0 || len(p.Operations) != 0 {
			t.Fatalf("%q: a user whose password needs no change blocked the plan: %v %v", scalar, kinds(p), p.Blocked)
		}
	}
	// The same forms with a reset wanted (not preserving, no longer on the reset
	// password) do block.
	reset := "schema_version: 3\nusers:\n  - name: bob\n    password:\n      initial: \"{{ x }}\"\n      preserve_existing: false\n"
	live.PwdExpiration = "20990101000000Z"
	p := Build(desiredForPlan(t, reset), []LiveUser{live}, nil)
	if len(p.Blocked) != 1 || p.Blocked[0].Reason != BlockedPasswordValue || len(p.Operations) != 0 {
		t.Fatalf("a reset of a template: %v %v", kinds(p), p.Blocked)
	}
	// And the user with the literal is planned, for the same state.
	literal := strings.Replace(reset, `"{{ x }}"`, `"`+pwSecret+`"`, 1)
	if p := Build(desiredForPlan(t, literal), []LiveUser{live}, nil); !slices.Equal(kinds(p), []string{"user.password.reset bob"}) || len(p.Blocked) != 0 {
		t.Fatalf("a reset of a literal: %v %v", kinds(p), p.Blocked)
	}
}

// A user whose forms were never read (a Desired built without the roster's bytes)
// is not sent a password: fail closed, not "a string".
func TestPasswordFormsThatWereNeverReadBlockTheOperation(t *testing.T) {
	d := desired(t, passwordRoster(`"`+pwSecret+`"`)) // FromRoster only
	if d.Users[1].PasswordFormRead {
		t.Fatal("FromRoster read the forms")
	}
	p := Build(d, nil, nil)
	if len(p.Blocked) != 1 || p.Blocked[0].Object != "bob" || !strings.Contains(p.Blocked[0].Detail, "password forms were not read") {
		t.Fatalf("blocked = %+v, want bob blocked for forms not read", p.Blocked)
	}
	d, err := d.WithPasswordForms([]byte(passwordRoster(`"` + pwSecret + `"`)))
	if err != nil {
		t.Fatal(err)
	}
	if p := Build(d, nil, nil); len(p.Blocked) != 0 {
		t.Fatalf("after reading the forms: %+v", p.Blocked)
	}
}

func TestWithPasswordFormsLeavesTheOriginalAndRefusesWhatItCannotRead(t *testing.T) {
	doc := passwordRoster(`"{{ x }}"`)
	d := desired(t, doc)
	read, err := d.WithPasswordForms([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if d.Users[1].PasswordFormRead || !read.Users[1].PasswordFormRead || read.Users[1].PasswordForm != inventory.PasswordTemplate {
		t.Fatalf("the original changed or the copy did not read: %+v / %+v", d.Users[1], read.Users[1])
	}
	for name, data := range map[string]string{
		"encrypted":       "$ANSIBLE_VAULT;1.1;AES256\n6162",
		"another roster":  "schema_version: 3\nusers: [{name: carol}]\n",
		"not a user list": "users: nope\n",
	} {
		if _, err := d.WithPasswordForms([]byte(data)); err == nil {
			t.Errorf("%s: the forms were read from bytes that are not the roster", name)
		} else if strings.Contains(err.Error(), pwSecret) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// FromRosterWithForms is the two together, and refuses what FromRoster refuses.
	if _, err := FromRosterWithForms(roster(t, doc), []byte(doc)); err != nil {
		t.Fatal(err)
	}
	if _, err := FromRosterWithForms(roster(t, "schema_version: 3\nusers: [{name: bob, password: {initial: 5}}]\n"), []byte("schema_version: 3\n")); err == nil {
		t.Fatal("FromRosterWithForms accepted a roster the adapter refuses")
	}
}
