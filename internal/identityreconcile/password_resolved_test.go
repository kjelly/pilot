package identityreconcile

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/freeiparpc"
	"github.com/kjelly/pilot/internal/inventory"
)

// A password.initial that is exactly one bare {{ name }} is planned and sent when the
// run's variables resolve it to a string (issue #394), and refused by name, with none of
// the user's operations planned, when they do not. Every gate has a row that passes and
// rows that trigger, each naming its reason. The password is a value made for the run of
// the test: nothing in the repository holds one.

// runtimeSecret is a password generated for one test run.
func runtimeSecret(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 9)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return "Rt-" + hex.EncodeToString(buf)
}

// runWith is the run of the identity playbook whose host variables are vars.
func runWith(vars map[string]any) *inventory.RosterRunVars {
	return &inventory.RosterRunVars{HostVars: vars, Consumer: inventory.RosterConsumerFreeIPAIdentity}
}

// templatedRoster has bob (new) with the scalar as his password.initial, and alice with none.
func templatedRoster(scalar string) string {
	return "schema_version: 3\nusers:\n  - {name: alice}\n  - name: bob\n    password:\n      initial: " + scalar + "\n"
}

var resolvedAlice = LiveUser{Name: "alice", First: "alice", Last: "alice", Home: "/home/alice", Shell: "/bin/bash"}

func TestABareReferenceThatTheRunResolvesIsPlannedAndNotOtherwise(t *testing.T) {
	secret := runtimeSecret(t)
	for _, tc := range []struct {
		name   string
		scalar string
		vars   map[string]any
		block  string // part of the detail, "" when the operation is planned
	}{
		{"a vault string", `"{{ v }}"`, map[string]any{"v": secret}, ""},
		{"no spaces, whitespace control", `"{{- v -}}"`, map[string]any{"v": secret}, ""},
		{"a chain of two", `"{{ a }}"`, map[string]any{"a": "{{ v }}", "v": secret}, ""},
		{"a value that is !unsafe text", `"{{ v }}"`, map[string]any{"v": map[string]any{"__ansible_unsafe": "a{{ b }}-" + secret}}, ""},
		{"undefined", `"{{ missing_var }}"`, map[string]any{"v": secret}, "refers to missing_var, which nothing in the run defines"},
		{"a name the settings task sets", `"{{ identity_admin_password }}"`, map[string]any{"identity_admin_password": secret}, "refers to identity_admin_password, a name the identity playbook"},
		{"a play var", `"{{ ipa_domain }}"`, map[string]any{"ipa_domain": secret}, "refers to ipa_domain, a name the identity playbook"},
		{"an inline !vault value", `"{{ v }}"`, map[string]any{"v": map[string]any{"__ansible_vault": "$ANSIBLE_VAULT;1.1;AES256"}}, "refers to v, whose value is an inline !vault value"},
		{"an empty string", `"{{ v }}"`, map[string]any{"v": ""}, "refers to v, which is an empty string"},
		{"a number", `"{{ v }}"`, map[string]any{"v": 12345678.0}, "refers to v, which is not a string"},
		{"null", `"{{ v }}"`, map[string]any{"v": nil}, "refers to v, which is not a string"},
		{"a value that is a template that is not bare", `"{{ v }}"`, map[string]any{"v": "a{{ b }}"}, "refers to v, whose value is a template that is not a bare reference"},
		{"a filter", `"{{ v | default('') }}"`, map[string]any{"v": secret}, "is a Jinja template that is not exactly one bare"},
		{"text around it", `"x{{ v }}"`, map[string]any{"v": secret}, "is a Jinja template that is not exactly one bare"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := desiredForPlanWith(t, templatedRoster(tc.scalar), runWith(tc.vars))
			p := Build(d, []LiveUser{resolvedAlice}, nil)
			if tc.block == "" {
				if !slices.Contains(kinds(p), "user.password.initialize bob") || len(p.Blocked) != 0 {
					t.Fatalf("operations %v, blocked %v", kinds(p), p.Blocked)
				}
				return
			}
			if len(p.Blocked) != 1 || p.Blocked[0].Reason != BlockedPasswordValue || p.Blocked[0].Object != "bob" || !strings.Contains(p.Blocked[0].Detail, tc.block) {
				t.Fatalf("blocked = %+v, want one %s for bob holding %q", p.Blocked, BlockedPasswordValue, tc.block)
			}
			if got := kinds(p); len(got) != 0 {
				t.Fatalf("operations planned for a blocked user: %v", got)
			}
			if strings.Contains(p.Blocked[0].Detail, secret) {
				t.Fatalf("the detail shows a value: %q", p.Blocked[0].Detail)
			}
			if !strings.Contains(p.Blocked[0].Detail, "password.initial") {
				t.Fatalf("the detail does not name the field: %q", p.Blocked[0].Detail)
			}
		})
	}
}

// A run whose variables were not read: the reference is refused by name, and the cause
// (no vault file, or ansible-inventory failed) is in the message, not a value.
func TestABareReferenceWithoutTheRunsVariablesIsRefusedByName(t *testing.T) {
	d := desiredForPlanWith(t, templatedRoster(`"{{ ipa_default_initial_password }}"`), nil)
	p := Build(d, []LiveUser{resolvedAlice}, nil)
	if len(p.Blocked) != 1 || p.Blocked[0].Object != "bob" || p.Blocked[0].Reason != BlockedPasswordValue {
		t.Fatalf("blocked = %+v", p.Blocked)
	}
	detail := p.Blocked[0].Detail
	for _, want := range []string{"password.initial", "ipa_default_initial_password", "the run's variables were not read"} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail %q does not say %q", detail, want)
		}
	}
}

// A user with no planned password operation is never blocked by an unresolved password,
// whatever the reason (a run with no password work is not stopped by one).
func TestAnUnresolvedPasswordOnAUserWithNoPasswordOperationBlocksNothing(t *testing.T) {
	live := LiveUser{Name: "bob", First: "bob", Last: "bob", Home: "/home/bob", Shell: "/bin/bash", LastPwdChange: "20260101000000Z", PwdExpiration: "20260401000000Z"}
	for name, run := range map[string]*inventory.RosterRunVars{
		"no run variables":     nil,
		"the variable missing": runWith(map[string]any{}),
		"a shadowed name":      runWith(map[string]any{"identity_admin_password": "x"}),
		"an inline !vault":     runWith(map[string]any{"v": map[string]any{"__ansible_vault": "x"}}),
		"an empty string":      runWith(map[string]any{"v": ""}),
		"not a string":         runWith(map[string]any{"v": 7.0}),
	} {
		for _, scalar := range []string{`"{{ v }}"`, `"{{ identity_admin_password }}"`, `"x{{ v }}"`} {
			t.Run(name+" "+scalar, func(t *testing.T) {
				d := desiredForPlanWith(t, templatedRoster(scalar), run)
				p := Build(d, []LiveUser{resolvedAlice, live}, nil)
				if len(p.Blocked) != 0 || len(p.Operations) != 0 {
					t.Fatalf("a user whose password needs no change blocked the plan: %v %v", kinds(p), p.Blocked)
				}
			})
		}
	}
}

// The sent value is exactly what the run resolves, for hostile values too, and the plan
// and the source of the passwords agree on which users have one: for every roster and
// run, a user the plan lets through is a user the source has a value for, and no other.
func TestThePlanAndTheSourceAgreeOnWhichUsersHaveAPassword(t *testing.T) {
	secret := runtimeSecret(t)
	hostile := []string{"  lead and trail  ", "0123", "True", "密碼-🔑", "a`b$HOME%s\\n", "line1\nline2", strings.Repeat("x", 300)}
	type fixture struct {
		name   string
		scalar string
		run    *inventory.RosterRunVars
	}
	var fixtures []fixture
	for _, v := range hostile {
		fixtures = append(fixtures, fixture{fmt.Sprintf("hostile %q resolved", v), `"{{ v }}"`, runWith(map[string]any{"v": v})})
	}
	fixtures = append(fixtures,
		fixture{"a literal", `"` + secret + `"`, nil},
		fixture{"a whitespace-only literal", `"   "`, nil},
		fixture{"an empty literal", `""`, nil},
		fixture{"an !unsafe literal holding {{", `!unsafe "{{ v }}"`, runWith(map[string]any{"v": secret})},
		fixture{"a bare reference, run read", `"{{ v }}"`, runWith(map[string]any{"v": secret})},
		fixture{"a bare reference, run not read", `"{{ v }}"`, nil},
		fixture{"a bare reference, undefined", `"{{ v }}"`, runWith(map[string]any{})},
		fixture{"a bare reference, shadowed", `"{{ item }}"`, runWith(map[string]any{"item": secret})},
		fixture{"a bare reference, inline !vault", `"{{ v }}"`, runWith(map[string]any{"v": map[string]any{"__ansible_vault": "x"}})},
		fixture{"a bare reference, empty", `"{{ v }}"`, runWith(map[string]any{"v": ""})},
		fixture{"a bare reference, a list", `"{{ v }}"`, runWith(map[string]any{"v": []any{"a"}})},
		fixture{"a filter", `"{{ v | upper }}"`, runWith(map[string]any{"v": secret})},
		fixture{"an inline !vault value in the roster", "!vault |\n          $ANSIBLE_VAULT;1.1;AES256\n          6162636465", runWith(map[string]any{"v": secret})},
	)
	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			doc := templatedRoster(f.scalar)
			d := desiredForPlanWith(t, doc, f.run)
			src, err := NewRosterPasswords([]byte(doc), f.run)
			if err != nil {
				t.Fatal(err)
			}
			for _, u := range d.Users {
				if !u.HasInitialPassword {
					continue
				}
				planSends := passwordUnsupported(u) == ""
				got, srcErr := src.InitialPassword(u.Name)
				if planSends != (srcErr == nil && got != "") {
					t.Fatalf("%s: the plan lets the password through = %v, the source has a value = %v (error %v)", u.Name, planSends, srcErr == nil && got != "", srcErr)
				}
				if srcErr != nil && got != "" {
					t.Fatalf("%s: the source returned a value with an error", u.Name)
				}
			}
			// What is sent is the resolved value, byte for byte (the run's value, or the literal).
			if strings.HasPrefix(f.name, "hostile") {
				want := f.run.HostVars["v"].(string)
				if got, err := src.InitialPassword("bob"); err != nil || got != want {
					t.Fatalf("the value sent differs from the resolved one (error %v, equal %v)", err, got == want)
				}
			}
		})
	}
}

// Desired is fingerprinted into the published plan (DesiredRevision): it holds the form,
// the reason and the variable's name, and nothing that depends on the password, so two runs
// that resolve the same reference to different values plan identically, and no encoding of
// Desired or of the plan document holds a value.
func TestTheDesiredStateAndThePlanHoldNoResolvedValue(t *testing.T) {
	first, second := runtimeSecret(t), runtimeSecret(t)
	doc := templatedRoster(`"{{ v }}"`)
	d1 := desiredForPlanWith(t, doc, runWith(map[string]any{"v": first}))
	d2 := desiredForPlanWith(t, doc, runWith(map[string]any{"v": second}))
	if fingerprint(d1) != fingerprint(d2) {
		t.Fatal("DesiredRevision depends on the resolved value")
	}
	if u := d1.Users[1]; u.PasswordForm != inventory.PasswordTemplate || u.PasswordReason != inventory.PasswordValueOK || u.PasswordVar != "v" {
		t.Fatalf("bob = %+v", u)
	}
	plan := Build(d1, []LiveUser{resolvedAlice}, nil)
	obs := Observation{Users: []LiveUser{resolvedAlice}}
	document := NewDocument(d1, obs, plan, Target{}, Server{}, "test", time.Unix(0, 0), Stats{})
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	desiredJSON, _ := json.Marshal(d1)
	for what, text := range map[string]string{
		"the plan document": string(raw), "Desired as JSON": string(desiredJSON),
		"%+v of Desired": fmt.Sprintf("%+v", d1), "%#v of Desired": fmt.Sprintf("%#v", d1),
	} {
		for _, secret := range []string{first, second} {
			if strings.Contains(text, secret) {
				t.Errorf("%s holds a resolved value", what)
			}
		}
	}
	// The same reference that is undefined is another desired revision: the reason is part of it.
	d3 := desiredForPlanWith(t, doc, runWith(map[string]any{}))
	if fingerprint(d1) == fingerprint(d3) {
		t.Fatal("a resolved and an unresolved reference have the same DesiredRevision")
	}
}

// A run that sends a resolved password: the command carries exactly the value, once, and
// the value is in nothing the run returns or records: not the result, the journal, an
// error (a server that echoes the password included) or any formatting of them.
func TestARunThatSendsAResolvedPasswordKeepsItOutOfEverythingItRecords(t *testing.T) {
	roster := rosterWith("  - {name: ua, password: {initial: \"{{ v }}\"}}\n", "")
	for name, mod := range map[string]func(e *runEnv, secret string){
		"a clean run": func(e *runEnv, secret string) {},
		"a server error that echoes the password": func(e *runEnv, secret string) {
			e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
				if c.method == "passwd" {
					return nil, &freeiparpc.RPCError{Code: 4203, Name: "DatabaseError", Message: "rejected " + c.opts["password"].(string)}, true
				}
				return nil, nil, false
			}
		},
		"an unknown outcome whose error holds the password": func(e *runEnv, secret string) {
			e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
				if c.method == "passwd" {
					return nil, &freeiparpc.OutcomeUnknownError{Method: "passwd", Err: errors.New("write: " + c.opts["password"].(string))}, true
				}
				return nil, nil, false
			}
		},
		"a journal that fails": func(e *runEnv, secret string) {
			e.journal.failOn = func(ev Event) error { return errors.New("disk full") }
		},
	} {
		t.Run(name, func(t *testing.T) {
			secret := runtimeSecret(t)
			run := runWith(map[string]any{"v": secret})
			e := newRunEnvWith(t, roster, run)
			mod(e, secret)
			res, err := e.execute()
			sent := 0
			for _, c := range e.f.calls {
				if c.method == "passwd" {
					if pw, _ := c.opts["password"].(string); pw == secret {
						sent++
					}
				} else if raw, _ := json.Marshal(c.opts); strings.Contains(string(raw), secret) {
					t.Fatalf("the password is in a %s command", c.method)
				}
			}
			if !strings.Contains(name, "journal") && sent != 1 {
				t.Fatalf("the password was sent %d times, want exactly once, as the run resolved it", sent)
			}
			raw, _ := json.Marshal(res)
			text := strings.Join([]string{
				string(raw), fmt.Sprintf("%+v", res), fmt.Sprintf("%#v", e.opts.Passwords), fmt.Sprintf("%v", e.opts.Passwords), fmt.Sprintf("%+v", e.opts),
				fmt.Sprintf("%#v", e.opts.Desired), e.journal.all(), fmt.Sprint(err), fmt.Sprintf("%v %+v %#v", run, run, run),
			}, "\n")
			if i := strings.Index(text, secret); i >= 0 {
				t.Fatalf("the password is in what the run returned or recorded: …%s…", text[max(0, i-60):min(len(text), i+60)])
			}
		})
	}
}

// What an unresolved reference makes the run do: nothing is written, no entry runs, and the
// refusal is the plan's blocked list (the executor stops before the entry on a blocked plan).
func TestAnUnresolvedReferenceStopsTheRunBeforeAnyWrite(t *testing.T) {
	secret := runtimeSecret(t)
	roster := rosterWith("  - {name: ua, password: {initial: \"{{ v }}\"}}\n", "")
	e := newRunEnvWith(t, roster, runWith(map[string]any{"other": secret}))
	res, err := e.execute()
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("err = %v, want ErrBlocked", err)
	}
	if w := e.f.writes(); len(w) != 0 {
		t.Fatalf("writes %v", w)
	}
	if e.entry.prepared != 0 || e.entry.probed != 0 {
		t.Fatalf("the entry ran (%d prepare, %d probe)", e.entry.prepared, e.entry.probed)
	}
	if res == nil {
		t.Fatal("no result")
	}
	if text := fmt.Sprint(err) + e.journal.all(); strings.Contains(text, secret) {
		t.Fatal("a value in the error or the journal")
	}
}
