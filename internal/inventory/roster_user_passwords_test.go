package inventory

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

const userPasswordSentinel = "Sentinel-Pw-8123"

// rosterWithInitial is a roster whose one user declares the scalar as its
// password.initial.
func rosterWithInitial(scalar string) []byte {
	return []byte("schema_version: 3\nusers:\n  - name: alice\n    password:\n      initial: " + scalar + "\n")
}

// The spellings of a password the roster can hold, each with the form Ansible
// reads it as: the same table the vault's readers and the admin-password
// compare are tested with (TestAdminPasswordFormsAreJudgedAlikeOnBothSides).
var passwordSpellings = []struct {
	name   string
	scalar string
	form   PasswordForm
	value  string
}{
	{"double-quoted", `"Pass-1"`, PasswordLiteral, "Pass-1"},
	{"plain string", `Pass-1`, PasswordLiteral, "Pass-1"},
	{"explicit !!str", `!!str Pass-1`, PasswordLiteral, "Pass-1"},
	{"!unsafe", `!unsafe "Pass-1"`, PasswordLiteral, "Pass-1"},
	{"!unsafe with Jinja", `!unsafe "Pa{{ss"`, PasswordLiteral, "Pa{{ss"},
	{"template", `"{{ ipa_admin_password }}"`, PasswordTemplate, ""},
	{"block template", `"{% if x %}a{% endif %}"`, PasswordTemplate, ""},
	{"unquoted number", `12345678`, PasswordNotString, ""},
	{"unquoted base 60", `190:20:30`, PasswordNotString, ""},
	{"explicit !!int", `!!int 7`, PasswordNotString, ""},
	{"unquoted boolean", `yes`, PasswordNotString, ""},
	{"quoted number", `"12345678"`, PasswordLiteral, "12345678"},
	{"!!str unquoted number", `!!str 012345678`, PasswordLiteral, "012345678"},
	{"null", `null`, PasswordAbsent, ""},
	{"empty", `""`, PasswordAbsent, ""},
	{"inline !vault", "!vault |\n          $ANSIBLE_VAULT;1.1;AES256\n          6162636465", PasswordEncrypted, ""},
	{"a list", `[a, b]`, PasswordNotString, ""},
	{"a mapping", `{a: b}`, PasswordNotString, ""},
}

func TestRosterUserPasswordsFormOfEverySpelling(t *testing.T) {
	for _, tt := range passwordSpellings {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RosterUserPasswords(rosterWithInitial(tt.scalar))
			if err != nil {
				t.Fatal(err)
			}
			want := RosterUserPassword{Form: tt.form, Value: tt.value}
			if got["alice"] != want || len(got) != 1 {
				t.Fatalf("got %v (form %s, value kept: %v), want %s", got, got["alice"].Form, got["alice"].Value != "", want.Form)
			}
		})
	}
}

// One classifier: every spelling gets the form the vault-side readers give the
// same scalar (AGENTS.md §5.7). If the roster side ever judged a form on its own,
// one of these rows would differ.
func TestRosterUserPasswordFormsAgreeWithTheVaultSide(t *testing.T) {
	for _, tt := range passwordSpellings {
		t.Run(tt.name, func(t *testing.T) {
			vault := []byte("ipa_admin_password: " + strings.ReplaceAll(tt.scalar, "\n          ", "\n  ") + "\n")
			vaultForm := PasswordAbsent
			switch {
			case VaultAdminPassword(vault) != "":
				vaultForm = PasswordLiteral
			case VaultAdminPasswordTemplate(vault) != "":
				vaultForm = PasswordTemplate
			case VaultAdminPasswordNotString(vault):
				vaultForm = PasswordNotString
			case VaultAdminPasswordEncrypted(vault):
				vaultForm = PasswordEncrypted
			}
			got, err := RosterUserPasswords(rosterWithInitial(tt.scalar))
			if err != nil {
				t.Fatal(err)
			}
			if got["alice"].Form != vaultForm {
				t.Fatalf("the roster side reads %s, the vault side %s", got["alice"].Form, vaultForm)
			}
			if got["alice"].Form == PasswordLiteral && got["alice"].Value != VaultAdminPassword(vault) {
				t.Fatal("the literal differs between the two sides")
			}
		})
	}
}

func TestRosterUserPasswordsReadsEveryUserAndFollowsYAMLAliases(t *testing.T) {
	data := []byte(`schema_version: 3
x-pw: &pw
  initial: "` + userPasswordSentinel + `"
x-base: &base
  password:
    initial: "{{ lookup('env', 'X') }}"
users:
  - name: nopw
  - name: nullpw
    password:
  - name: empty
    password: {}
  - name: aliased
    password: *pw
  - name: merged
    <<: *base
  - name: Mixed-Case
    password: {initial: "Pass-2"}
`)
	got, err := RosterUserPasswords(data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]PasswordForm{
		"nopw": PasswordAbsent, "nullpw": PasswordAbsent, "empty": PasswordAbsent,
		"aliased": PasswordLiteral, "merged": PasswordTemplate, "Mixed-Case": PasswordLiteral,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d users: %v", len(got), got)
	}
	for name, form := range want {
		if got[name].Form != form {
			t.Errorf("%s: form %s, want %s", name, got[name].Form, form)
		}
	}
	if got["aliased"].Value != userPasswordSentinel || got["Mixed-Case"].Value != "Pass-2" {
		t.Error("a literal behind an alias, or with a mixed-case name, was not read")
	}
	for name, p := range got {
		if p.Form != PasswordLiteral && p.Value != "" {
			t.Errorf("%s: a non-literal form carries a value", name)
		}
	}
}

func TestRosterUserPasswordsWithoutUsersIsEmpty(t *testing.T) {
	for name, doc := range map[string]string{"no key": "schema_version: 3\n", "null": "users:\n", "empty list": "users: []\n"} {
		got, err := RosterUserPasswords([]byte(doc))
		if err != nil || len(got) != 0 {
			t.Errorf("%s: %v, %v", name, got, err)
		}
	}
}

// What it refuses, and that no refusal shows a password of the document.
func TestRosterUserPasswordsRefusals(t *testing.T) {
	cyc := "users:\n  - &a\n    name: x\n    password: {initial: \"" + userPasswordSentinel + "\", <<: *a}\n"
	for name, tt := range map[string]struct {
		data string
		is   error
		want string
	}{
		"encrypted":           {"$ANSIBLE_VAULT;1.1;AES256\n6162", ErrRosterEncrypted, ""},
		"not YAML":            {"users: [\n  password: \"" + userPasswordSentinel, nil, "does not parse"},
		"cyclic":              {cyc, errCyclicYAML, ""},
		"users not a list":    {"users: {name: x, password: {initial: \"" + userPasswordSentinel + "\"}}\n", nil, "users is not a list"},
		"entry not a mapping": {"users:\n  - \"" + userPasswordSentinel + "\"\n", nil, "users[0] is not a mapping"},
		"no name":             {"users:\n  - password: {initial: \"" + userPasswordSentinel + "\"}\n", nil, "users[0] has no string name"},
		"name is a number":    {"users:\n  - name: 12\n    password: {initial: \"" + userPasswordSentinel + "\"}\n", nil, "no string name"},
		"the same name twice": {"users:\n  - name: a\n  - name: a\n    password: {initial: \"" + userPasswordSentinel + "\"}\n", nil, `"a" appears twice`},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := RosterUserPasswords([]byte(tt.data))
			if err == nil {
				t.Fatal("accepted")
			}
			if tt.is != nil && !errors.Is(err, tt.is) {
				t.Fatalf("err = %v, want %v", err, tt.is)
			}
			if tt.want != "" && !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to hold %q", err, tt.want)
			}
			if strings.Contains(err.Error(), userPasswordSentinel) {
				t.Fatalf("the error shows a password: %v", err)
			}
		})
	}
}

// A password that is not in a mapping at all is not readable: not-a-string,
// never absent.
func TestRosterUserPasswordsPasswordThatIsNotAMapping(t *testing.T) {
	got, err := RosterUserPasswords([]byte("users:\n  - name: a\n    password: \"" + userPasswordSentinel + "\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got["a"].Form != PasswordNotString || got["a"].Value != "" {
		t.Fatalf("got %v", got["a"])
	}
}

// No formatting of a value, alone or inside a map, shows the password.
func TestRosterUserPasswordNeverFormatsTheValue(t *testing.T) {
	got, err := RosterUserPasswords(rosterWithInitial(`"` + userPasswordSentinel + `"`))
	if err != nil {
		t.Fatal(err)
	}
	if got["alice"].Value != userPasswordSentinel {
		t.Fatal("the literal was not read")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if s := fmt.Sprintf(verb, got["alice"]) + fmt.Sprintf(verb, got); strings.Contains(s, userPasswordSentinel) {
			t.Fatalf("%s shows the password: %s", verb, s)
		}
	}
}
