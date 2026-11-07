package identityreconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/freeiparpc"
	"github.com/kjelly/pilot/internal/identitylock"
	"github.com/kjelly/pilot/internal/identitylock/identitylocktest"
)

// Guards of the small pieces of the writer (the entry, the password source, the
// options of a command, the group parser, the set comparison) that a mutation of the
// guard found the package green without (spec §5.12).

// A command is built for an operation only from fields the server takes in the form
// it takes them: each option has its own type, and a field that is not one is an
// error naming the operation, never a command.
func TestACommandIsBuiltOnlyFromFieldsOfTheRightForm(t *testing.T) {
	type row struct {
		name   string
		kind   string
		fields map[string]Change
		want   string // in the error
	}
	rows := []row{
		{"mail is not a list", KindUserCreate, map[string]Change{"mail": {To: "a@example.test"}}, "mail is string, want a list of strings"},
		{"uidnumber is not a string", KindUserCreate, map[string]Change{"uidnumber": {To: 7}}, "uidnumber is int, want a decimal string"},
		{"uidnumber is not a number", KindUserCreate, map[string]Change{"uidnumber": {To: "seven"}}, `uidnumber "seven" is not a number`},
		{"gidnumber is not a string", KindGroupCreate, map[string]Change{"gidnumber": {To: 7.5}}, "gidnumber is float64, want a decimal string"},
		{"gidnumber is not a number", KindGroupCreate, map[string]Change{"gidnumber": {To: "x"}}, `gidnumber "x" is not a number`},
		{"nonposix is not a boolean", KindGroupCreate, map[string]Change{"nonposix": {To: "yes"}}, "nonposix is string, want a boolean"},
		{"description is not a string", KindGroupCreate, map[string]Change{"description": {To: 1}}, "description is int, want a string"},
		{"givenname is not a string", KindUserCreate, map[string]Change{"givenname": {To: true}}, "givenname is bool, want a string"},
		{"a field with no option", KindUserCreate, map[string]Change{"favouritecolour": {To: "x"}}, `the field "favouritecolour" has no FreeIPA option`},
	}
	// The error comes out of every kind that has fields: add and mod, users and groups.
	for _, kind := range []string{KindGroupCreate, KindMarkerCreate, KindGroupUpdate, KindUserCreate, KindUserUpdate} {
		rows = append(rows, row{"a kind that takes fields: " + kind, kind, map[string]Change{"favouritecolour": {To: "x"}}, "no FreeIPA option"})
	}
	for _, r := range rows {
		cmd, err := commandFor(Operation{ID: r.kind + ":x", Kind: r.kind, Object: "x", Fields: r.fields}, "")
		if err == nil || !strings.Contains(err.Error(), r.want) || cmd.Method != "" {
			t.Errorf("%s: %+v, %v, want an error holding %q", r.name, cmd, err, r.want)
		}
		if err != nil && !strings.Contains(err.Error(), r.kind+":x") {
			t.Errorf("%s: the error does not name the operation: %v", r.name, err)
		}
	}
	// Every form that is right is built, for the same fields.
	good := map[string]Change{"mail": {To: []string{"a@example.test"}}, "uidnumber": {To: "7"}, "gidnumber": {To: "8"}, "nonposix": {To: true}, "description": {To: "d"}, "givenname": {To: "G"}}
	for _, kind := range []string{KindGroupCreate, KindUserCreate, KindUserUpdate} {
		if _, err := commandFor(Operation{ID: kind + ":x", Kind: kind, Object: "x", Fields: good}, ""); err != nil {
			t.Errorf("%s with fields of the right forms: %v", kind, err)
		}
	}
	if _, err := commandFor(Operation{ID: "p", Kind: KindPasswordInitialize, Object: "x"}, ""); err == nil {
		t.Error("a password command without a password was built")
	}
	if _, err := commandFor(Operation{ID: "b", Kind: "no.such.kind", Object: "x"}, ""); err == nil || !strings.Contains(err.Error(), "no command for the operation kind") {
		t.Errorf("an unknown kind: %v", err)
	}
}

// The password source: what it refuses, by name, and what it hands out.
func TestThePasswordSourceRefusesWhatItCannotHandOut(t *testing.T) {
	if _, err := NewRosterPasswords([]byte("users: [")); err == nil {
		t.Error("a roster that is not YAML was accepted")
	}
	if _, err := NewRosterPasswords([]byte("users:\n  - {name: Alice, password: {initial: a}}\n  - {name: alice, password: {initial: b}}\n")); err == nil || !strings.Contains(err.Error(), "differ only in case") {
		t.Errorf("two users that differ only in case: %v", err)
	}
	src, err := NewRosterPasswords([]byte("users:\n  - {name: Alice, password: {initial: \"a-" + pwSecret + "\"}}\n  - name: tpl\n    password: {initial: \"{{ lookup('env', 'X') }}\"}\n  - {name: none}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if pw, err := src.InitialPassword("alice"); err != nil || pw != "a-"+pwSecret {
		t.Errorf("alice (the lookup ignores case): %q, %v", pw, err)
	}
	if _, err := src.InitialPassword("nobody"); err == nil || !strings.Contains(err.Error(), "has no user") {
		t.Errorf("a user the roster does not have: %v", err)
	}
	if _, err := src.InitialPassword("tpl"); err == nil || !strings.Contains(err.Error(), "not a string written out") {
		t.Errorf("a template: %v", err)
	}
	if _, err := src.InitialPassword("none"); err == nil {
		t.Error("a user without a password was handed one")
	}
	for _, shown := range []string{fmt.Sprintf("%v", src), fmt.Sprintf("%+v", src), fmt.Sprintf("%#v", src), src.(fmt.Stringer).String()} {
		if strings.Contains(shown, pwSecret) || !strings.Contains(shown, "roster passwords (3 users)") {
			t.Errorf("a formatting of the source: %q", shown)
		}
	}
}

// The entry holds what it needs, and says which entry mode failed on which host.
func TestTheEntryIsBuiltOnlyFromWhatItNeedsAndNamesWhatFailed(t *testing.T) {
	out, err := NewAuthCacheOutput()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = out.Close() })
	lock := &identitylocktest.Fake{Host: "ipa-1"}
	held, err := lock.Acquirer()(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Release() })
	noop := func(context.Context, string) (int, error) { return 0, nil }
	for _, tc := range []struct {
		name string
		out  *AuthCacheOutput
		held *identitylock.Held
		fqdn string
		run  AuthCacheCommand
		want error
		text string
	}{
		{"no result file", nil, held, testFQDN, noop, nil, "result file"},
		{"no command", out, held, testFQDN, nil, nil, "result file and the command"},
		{"no lock", out, nil, testFQDN, noop, identitylock.ErrNoLock, ""},
		{"a lock without a host", out, &identitylock.Held{}, testFQDN, noop, identitylock.ErrNoLock, ""},
		{"no FQDN", out, held, "", noop, nil, "FQDN"},
		{"everything", out, held, testFQDN, noop, nil, ""},
	} {
		e, err := NewAuthCacheEntry(tc.out, tc.held, tc.fqdn, tc.run)
		switch {
		case tc.name == "everything":
			if err != nil || e == nil {
				t.Errorf("%s: %v", tc.name, err)
			}
		case err == nil || e != nil || tc.want != nil && !errors.Is(err, tc.want) || !strings.Contains(err.Error(), tc.text):
			t.Errorf("%s: %v, %v", tc.name, e, err)
		}
	}
	// What the entry runs, and what it says when the run fails.
	var seenMode string
	run := func(_ context.Context, vars string) (int, error) {
		var v map[string]string
		_ = json.Unmarshal([]byte(vars), &v)
		seenMode = v[AuthCacheActionVar]
		data, _ := RenderAuthCacheResult(AuthCacheResult{Action: AuthCacheAction(seenMode), Host: "ipa-1", FQDN: testFQDN, Pending: true, Previous: true})
		return 0, writeResultFile(v[AuthCacheOutputVar], data)
	}
	e, err := NewAuthCacheEntry(out, held, testFQDN, run)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := e.Prepare(context.Background()); err != nil || seenMode != "prepare" || res.Action != AuthCachePrepare || !res.Previous {
		t.Errorf("prepare: %+v, %v, mode %q", res, err, seenMode)
	}
	if res, err := e.Probe(context.Background()); err != nil || seenMode != "probe" || res.Action != AuthCacheProbe || !res.Pending {
		t.Errorf("probe: %+v, %v, mode %q", res, err, seenMode)
	}
	broken, _ := NewAuthCacheEntry(out, held, testFQDN, func(context.Context, string) (int, error) { return 0, errors.New("ansible-playbook is not installed") })
	if _, err := broken.Probe(context.Background()); err == nil || !strings.Contains(err.Error(), "authorization cache entry (probe) on ipa-1") || !strings.Contains(err.Error(), "not installed") {
		t.Errorf("a run that failed: %v", err)
	}
	if _, err := broken.Prepare(context.Background()); err == nil || !strings.Contains(err.Error(), "(prepare)") {
		t.Errorf("a prepare that failed: %v", err)
	}
	// A result that is for another host is refused by the entry.
	other, _ := NewAuthCacheEntry(out, held, "another.example.test", run)
	if _, err := other.Probe(context.Background()); !errors.Is(err, ErrAuthCacheResult) {
		t.Errorf("a result for another FQDN: %v", err)
	}
}

// writeResultFile is what the playbook does with the path it is handed.
func writeResultFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

// parseGroup says which group and which field it could not read.
func TestAGroupEntryThatCannotBeReadIsAnErrorNamingIt(t *testing.T) {
	good := func() map[string]any {
		return map[string]any{
			"cn": []any{"Team-A"}, "ipauniqueid": []any{"u1"}, "description": []any{"d"}, "gidnumber": []any{"10"},
			"objectclass": []any{"top", "groupofnames", "nestedgroup", "ipausergroup", "ipaobject"},
			"member_user": []any{"Alice"}, "member_group": []any{"Team-B"},
		}
	}
	g, err := parseGroup(good())
	if err != nil || g.Name != "team-a" || g.UniqueID != "u1" || g.GIDNumber != "10" || g.Type != TypeNonPosix || fmt.Sprint(g.MemberUsers, g.MemberGroups) != "[alice] [team-b]" {
		t.Fatalf("a good entry: %+v, %v", g, err)
	}
	for name, mod := range map[string]func(e map[string]any){
		"no cn":                            func(e map[string]any) { delete(e, "cn") },
		"an ipauniqueid not a list":        func(e map[string]any) { e["ipauniqueid"] = "u1" },
		"a description not a list":         func(e map[string]any) { e["description"] = "d" },
		"a gidnumber with two":             func(e map[string]any) { e["gidnumber"] = []any{"1", "2"} },
		"no objectclass":                   func(e map[string]any) { delete(e, "objectclass") },
		"an empty objectclass":             func(e map[string]any) { e["objectclass"] = []any{} },
		"an objectclass not a list":        func(e map[string]any) { e["objectclass"] = "top" },
		"a member_user not a list":         func(e map[string]any) { e["member_user"] = "alice" },
		"a member_group not a list":        func(e map[string]any) { e["member_group"] = 7 },
		"a member_group with a non-string": func(e map[string]any) { e["member_group"] = []any{7} },
	} {
		e := good()
		mod(e)
		got, err := parseGroup(e)
		if err == nil {
			t.Errorf("%s: accepted: %+v", name, got)
			continue
		}
		if name != "no cn" && !strings.Contains(err.Error(), "group team-a") {
			t.Errorf("%s: the error does not name the group: %v", name, err)
		}
	}
}

// The comparison of two value lists is by set: the order the server lists them in is
// not a difference.
func TestSameValuesIgnoresOrderAndNeedsTheSameCount(t *testing.T) {
	for _, tc := range []struct {
		live, want []string
		same       bool
	}{
		{[]string{"b", "a"}, []string{"a", "b"}, true},
		{[]string{"a"}, []string{"a"}, true},
		{nil, nil, true},
		{[]string{"a", "b"}, []string{"a"}, false},
		{[]string{"a"}, []string{"b"}, false},
		{[]string{"a", "a"}, []string{"a", "b"}, false},
		{[]string{"a"}, nil, false},
	} {
		if got := sameValues(tc.live, tc.want); got != tc.same {
			t.Errorf("sameValues(%v, %v) = %v, want %v", tc.live, tc.want, got, tc.same)
		}
	}
	live := []string{"b", "a"}
	_ = sortedCopy(live)
	if live[0] != "b" {
		t.Error("the comparison sorted the caller's list")
	}
}

// A password is decided for a user that is not live as it is for one with no password
// change recorded, and for neither when the roster has no password.
func TestPasswordActionForAUserThatDoesNotExist(t *testing.T) {
	declared := DesiredUser{Name: "x", HasInitialPassword: true, PreserveExisting: true}
	if got := passwordAction(declared, LiveUser{LastPwdChange: "20260101000000Z"}, false); got != KindPasswordInitialize {
		t.Errorf("a user that does not exist, whatever the zero value says: %q", got)
	}
	if got := passwordAction(declared, LiveUser{}, true); got != KindPasswordInitialize {
		t.Errorf("a user with no password change: %q", got)
	}
	if got := passwordAction(declared, LiveUser{LastPwdChange: "20260101000000Z"}, true); got != "" {
		t.Errorf("a user with a password, preserved: %q", got)
	}
	if got := passwordAction(DesiredUser{Name: "x"}, LiveUser{}, false); got != "" {
		t.Errorf("a roster without a password: %q", got)
	}
}

// FromRosterWithForms builds the desired state and records the forms; each of its two
// steps fails the whole.
func TestFromRosterWithFormsRecordsTheFormsAndFailsWithEitherStep(t *testing.T) {
	doc := "schema_version: 3\nusers:\n  - {name: alice, password: {initial: \"" + pwSecret + "\"}}\n"
	root := roster(t, doc)
	d, err := FromRosterWithForms(root, []byte(doc))
	if err != nil || len(d.Users) != 1 || !d.Users[0].PasswordFormRead {
		t.Fatalf("%+v, %v", d.Users, err)
	}
	if _, err := FromRosterWithForms(root, []byte("users: [")); err == nil {
		t.Error("bytes that are not a roster were accepted")
	}
	// With no user to look for, the bytes are still the roster's and must be one.
	if _, err := FromRosterWithForms(roster(t, "schema_version: 3\n"), []byte("users: [")); err == nil {
		t.Error("bytes that are not a roster were accepted for a roster with no users")
	}
	if _, err := FromRosterWithForms(map[string]any{"users": "not a list"}, []byte(doc)); err == nil {
		t.Error("a root that is not a roster was accepted")
	}
}

var _ = freeiparpc.Command{}

// The result file is made empty again before every run; when it cannot be, nothing
// runs: a playbook handed a path that cannot be a new empty file could be read back as
// whatever is there.
func TestAuthCacheOutputRunDoesNotRunWhenTheFileCannotBeMadeEmpty(t *testing.T) {
	out, err := NewAuthCacheOutput()
	if err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil { // the directory is gone: the file cannot be made again
		t.Fatal(err)
	}
	ran := false
	_, err = out.Run(context.Background(), AuthCacheWant{Action: AuthCacheProbe, Host: "ipa-1", FQDN: testFQDN}, func(context.Context, string) (int, error) {
		ran = true
		return 0, nil
	})
	if err == nil || ran || !strings.Contains(err.Error(), "authorization cache result file") {
		t.Fatalf("err = %v, ran %v", err, ran)
	}
}

// A result path that cannot be cleared is refused with the reason, and nothing runs: a
// directory with something in it stands where the file should be, and the run would
// otherwise read whatever is there as the playbook's answer.
func TestAuthCacheOutputRunRefusesAPathItCannotClear(t *testing.T) {
	out, err := NewAuthCacheOutput()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = out.Close() })
	if err := os.Remove(out.path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(out.path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out.path, "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ran := false
	_, err = out.Run(context.Background(), AuthCacheWant{Action: AuthCacheProbe, Host: "ipa-1", FQDN: testFQDN}, func(context.Context, string) (int, error) {
		ran = true
		return 0, nil
	})
	if err == nil || ran || !strings.Contains(err.Error(), "clear the authorization cache result file") {
		t.Fatalf("err = %v, ran %v", err, ran)
	}
}
