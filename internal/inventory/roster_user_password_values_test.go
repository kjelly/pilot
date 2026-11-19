package inventory

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// A user's password.initial that is exactly one bare {{ name }} is resolved from
// the run's variables by one resolver (RosterRunVars.UserInitialPassword). Every
// gate below has a row that passes and a row that triggers (AGENTS.md section
// 5.12), and the rows that trigger name the reason, so a different gate cannot
// pass for the one under test. Ansible's own behaviour for the same rows is the
// oracle test's (TestRosterUserPasswordValuesMatchAnsible); this table is its
// twin, without ansible-playbook.

func TestUserInitialPasswordResolvesOnlyWhatTheRunDecides(t *testing.T) {
	const ok = PasswordValueOK
	for _, tc := range []struct {
		name     string
		template string
		vars     string
		extra    []string
		want     string
		reason   PasswordValueReason
	}{
		// ---- G1: the template must be exactly one bare reference ----
		{"a bare reference", `{{ v }}`, `{"v": "pw-1"}`, nil, "pw-1", ok},
		{"a bare reference without spaces", `{{v}}`, `{"v": "pw-1"}`, nil, "pw-1", ok},
		{"whitespace control", `{{- v -}}`, `{"v": "pw-1"}`, nil, "pw-1", ok},
		{"a filter", `{{ v | default('') }}`, `{"v": "pw-1"}`, nil, "", PasswordReasonNotBare},
		{"a concatenation", `{{ a ~ b }}`, `{"a": "x", "b": "y"}`, nil, "", PasswordReasonNotBare},
		{"text before it", `x{{ v }}`, `{"v": "pw-1"}`, nil, "", PasswordReasonNotBare},
		{"text after it", `{{ v }}x`, `{"v": "pw-1"}`, nil, "", PasswordReasonNotBare},
		{"an attribute", `{{ v.sub }}`, `{"v": {"sub": "pw-1"}}`, nil, "", PasswordReasonNotBare},
		{"a raw block", `{% raw %}{{ v }}{% endraw %}`, `{"v": "pw-1"}`, nil, "", PasswordReasonNotBare},
		{"two references", `{{ a }}{{ b }}`, `{"a": "x", "b": "y"}`, nil, "", PasswordReasonNotBare},
		{"a lookup", `{{ lookup('env', 'HOME') }}`, `{}`, nil, "", PasswordReasonNotBare},
		{"a Jinja word", `{{ not }}`, `{}`, nil, "", PasswordReasonNotBare},
		{"a plain string", `pw-1`, `{"pw-1": "other"}`, nil, "", PasswordReasonNotBare},

		// ---- G5: what the lookup follows ----
		{"a vault string", `{{ v }}`, `{"v": "Pa ss"}`, nil, "Pa ss", ok},
		{"leading and trailing spaces are kept", `{{ v }}`, `{"v": "  pw  "}`, nil, "  pw  ", ok},
		{"a whitespace-only string is a password too", `{{ v }}`, `{"v": "   "}`, nil, "   ", ok},
		{"a chain of two", `{{ a }}`, `{"a": "{{ b }}", "b": "pw-1"}`, nil, "pw-1", ok},
		{"a chain with whitespace control", `{{ a }}`, `{"a": "{{- b -}}", "b": "pw-1"}`, nil, "pw-1", ok},
		{"a value that is !unsafe text holding {{", `{{ v }}`, `{"v": {"__ansible_unsafe": "a{{ b }}c"}}`, nil, "a{{ b }}c", ok},
		{"an undefined variable", `{{ v }}`, `{}`, nil, "", PasswordReasonUndefined},
		{"undefined at the end of a chain", `{{ a }}`, `{"a": "{{ b }}"}`, nil, "", PasswordReasonUndefined},
		{"a play var of the identity playbook", `{{ ipa_domain }}`, `{"ipa_domain": "ipa.test"}`, nil, "", PasswordReasonShadowed},
		{"a name the settings task sets: identity_admin_password", `{{ identity_admin_password }}`, `{"identity_admin_password": "inventory-value"}`, nil, "", PasswordReasonShadowed},
		{"a name the settings task sets: identity_admin_principal", `{{ identity_admin_principal }}`, `{"identity_admin_principal": "inventory-value"}`, nil, "", PasswordReasonShadowed},
		{"a name the settings task sets: ipa_hbac_services", `{{ ipa_hbac_services }}`, `{"ipa_hbac_services": "inventory-value"}`, nil, "", PasswordReasonShadowed},
		{"a name the settings task sets: ipa_sudo_command_groups", `{{ ipa_sudo_command_groups }}`, `{"ipa_sudo_command_groups": "inventory-value"}`, nil, "", PasswordReasonShadowed},
		{"the loop variable of the normalize task", `{{ item }}`, `{"item": "inventory-value"}`, nil, "", PasswordReasonShadowed},
		{"a task variable of the normalize task", `{{ pilot_identity_roster_user }}`, `{"pilot_identity_roster_user": "inventory-value"}`, nil, "", PasswordReasonShadowed},
		{"pilot's own -e name: freeipa_roster_file", `{{ freeipa_roster_file }}`, `{"freeipa_roster_file": "inventory-value"}`, nil, "", PasswordReasonShadowed},
		{"pilot's own -e name: target_group", `{{ target_group }}`, `{"target_group": "inventory-value"}`, nil, "", PasswordReasonShadowed},
		{"pilot's own -e name: pilot_deferred_hosts", `{{ pilot_deferred_hosts }}`, `{"pilot_deferred_hosts": "inventory-value"}`, nil, "", PasswordReasonShadowed},
		{"pilot's own -e name: pilot_identity_users_groups_engine", `{{ pilot_identity_users_groups_engine }}`, `{"pilot_identity_users_groups_engine": "inventory-value"}`, nil, "", PasswordReasonShadowed},
		{"pilot's own -e name: pilot_identity_auth_cache_output", `{{ pilot_identity_auth_cache_output }}`, `{"pilot_identity_auth_cache_output": "inventory-value"}`, nil, "", PasswordReasonShadowed},
		{"a shadowed name at the end of a chain", `{{ a }}`, `{"a": "{{ identity_admin_password }}", "identity_admin_password": "inventory-value"}`, nil, "", PasswordReasonShadowed},
		{"an implicit name: inventory_hostname", `{{ inventory_hostname }}`, `{}`, nil, "", PasswordReasonShadowed},
		{"an implicit name: an ansible_ fact", `{{ ansible_host }}`, `{"ansible_host": "192.0.2.1"}`, nil, "", PasswordReasonShadowed},
		{"a name passed with -e that the listing does not hold", `{{ v }}`, `{}`, []string{"v"}, "", PasswordReasonShadowed},
		{"an inline !vault value", `{{ v }}`, `{"v": {"__ansible_vault": "$ANSIBLE_VAULT;1.1;AES256"}}`, nil, "", PasswordReasonInlineVault},
		{"an inline !vault value at the end of a chain", `{{ a }}`, `{"a": "{{ v }}", "v": {"__ansible_vault": "$ANSIBLE_VAULT;1.1;AES256"}}`, nil, "", PasswordReasonInlineVault},
		{"a value that is a template that is not bare", `{{ v }}`, `{"v": "a{{ b }}"}`, nil, "", PasswordReasonNestedTemplate},
		{"a value with a filter", `{{ v }}`, `{"v": "{{ b | default('x') }}", "b": "y"}`, nil, "", PasswordReasonNestedTemplate},
		{"a cycle", `{{ a }}`, `{"a": "{{ b }}", "b": "{{ a }}"}`, nil, "", PasswordReasonChain},
		{"a reference to itself", `{{ a }}`, `{"a": "{{ a }}"}`, nil, "", PasswordReasonChain},
		// The first name and maxRunVarHops more are followed: maxRunVarHops+1 names.
		{"a chain exactly at the bound", `{{ v1 }}`, chainVars(maxRunVarHops + 1), nil, "end", ok},
		{"a chain longer than the bound", `{{ v1 }}`, chainVars(maxRunVarHops + 2), nil, "", PasswordReasonChain},

		// ---- G6: what the value must be ----
		{"an empty string", `{{ v }}`, `{"v": ""}`, nil, "", PasswordReasonEmpty},
		{"an !unsafe empty string", `{{ v }}`, `{"v": {"__ansible_unsafe": ""}}`, nil, "", PasswordReasonEmpty},
		{"null", `{{ v }}`, `{"v": null}`, nil, "", PasswordReasonNotString},
		{"a number", `{{ v }}`, `{"v": 12345678}`, nil, "", PasswordReasonNotString},
		{"a boolean", `{{ v }}`, `{"v": true}`, nil, "", PasswordReasonNotString},
		{"a list", `{{ v }}`, `{"v": ["a"]}`, nil, "", PasswordReasonNotString},
		{"a mapping", `{{ v }}`, `{"v": {"a": "b"}}`, nil, "", PasswordReasonNotString},
		{"a string that looks like a number", `{{ v }}`, `{"v": "0123"}`, nil, "0123", ok},
		{"a string that looks like a boolean", `{{ v }}`, `{"v": "True"}`, nil, "True", ok},

		// ---- G7: text that did not decode ----
		{"a value with U+FFFD", `{{ v }}`, "{\"v\": \"ab\\ufffdcd\"}", nil, "", PasswordReasonInvalidText},
		{"CJK, emoji and punctuation pass", `{{ v }}`, `{"v": "密碼-🔑-$HOME-%s-` + "`x`" + `"}`, nil, "密碼-🔑-$HOME-%s-`x`", ok},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := run(t, RosterConsumerFreeIPAIdentity, tc.vars, tc.extra...).UserInitialPassword(tc.template)
			if got != tc.want || reason != tc.reason {
				t.Fatalf("UserInitialPassword(%q) = (value kept: %v, %s), want (value kept: %v, %s)", tc.template, got != "", reason, tc.want != "", tc.reason)
			}
			if tc.reason != ok && got != "" {
				t.Fatal("a refusal carries a value")
			}
		})
	}
}

// chainVars is v1 -> v2 -> ... -> v<n> = "end": n names.
func chainVars(n int) string {
	var b strings.Builder
	b.WriteString("{")
	for i := 1; i < n; i++ {
		fmt.Fprintf(&b, `"v%d": "{{ v%d }}", `, i, i+1)
	}
	fmt.Fprintf(&b, `"v%d": "end"}`, n)
	return b.String()
}

// Only the identity playbook renders a user's password: a run vars set for any
// other consumer decides nothing here.
func TestUserInitialPasswordIsOnlyForTheIdentityConsumer(t *testing.T) {
	r := run(t, RosterConsumerFreeIPANFSServer, `{"v": "pw-1"}`)
	if got, reason := r.UserInitialPassword(`{{ v }}`); got != "" || reason != PasswordReasonNoRunVars {
		t.Fatalf("an NFS run resolved a user's password: value kept %v, %s", got != "", reason)
	}
	if got, reason := (RosterRunVars{HostVars: map[string]any{"v": "pw-1"}}).UserInitialPassword(`{{ v }}`); got != "" || reason != PasswordReasonNoRunVars {
		t.Fatalf("a run of no consumer resolved a user's password: value kept %v, %s", got != "", reason)
	}
}

// The reason a name is not the inventory's is the set the playbook has defined
// when it CAPTURES the password, which is a superset of the first-render set the
// admin-password and server facts use: the facts keep deciding with the smaller
// set, and the password with the larger one.
func TestThePasswordNameSetIsALargerSetThanTheFactsUse(t *testing.T) {
	facts, capture := playbookDefinedNames(RosterConsumerFreeIPAIdentity), PasswordCaptureNames(RosterConsumerFreeIPAIdentity)
	for name := range facts {
		if !capture[name] {
			t.Errorf("%s shadows the inventory at the first render but not at the capture", name)
		}
	}
	for _, name := range []string{"identity_admin_password", "identity_admin_principal", "ipa_hbac_services", "ipa_sudo_command_groups", "item", "freeipa_roster_file", "pilot_identity_users_groups_engine"} {
		if !capture[name] || facts[name] {
			t.Errorf("%s: shadows at the capture = %v, at the first render = %v; want true and false", name, capture[name], facts[name])
		}
	}
	// The facts' own behaviour is unchanged: a run that defines identity_admin_password in the
	// inventory still lets ipa_admin_password's chain resolve through it.
	r := run(t, RosterConsumerFreeIPAIdentity, `{"ipa_admin_password": "{{ identity_admin_password }}", "identity_admin_password": "x"}`)
	if r.AdminPasswordProvided() != RosterFactYes {
		t.Fatal("the admin-password fact changed with the password name set")
	}
	if got, reason := r.UserInitialPassword(`{{ ipa_admin_password }}`); got != "" || reason != PasswordReasonShadowed {
		t.Fatalf("a password referring through identity_admin_password was resolved: value kept %v, %s", got != "", reason)
	}
}

// userRun is the run of a roster the tests below read.
func userRun(t *testing.T, vars string) *RosterRunVars {
	t.Helper()
	r := run(t, RosterConsumerFreeIPAIdentity, vars)
	return &r
}

func initialsOf(t *testing.T, roster string, r *RosterRunVars) map[string]RosterUserPassword {
	t.Helper()
	got, err := RosterUserPasswords([]byte(roster), r)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// RosterUserPasswords sends a bare reference only through the resolver, and every
// other form stays what it was.
func TestRosterUserPasswordsResolvesABareReferenceThroughTheRun(t *testing.T) {
	secret := sentinelSecret(t)
	roster := "schema_version: 3\nusers:\n" +
		"  - {name: bare, password: {initial: \"{{ v }}\"}}\n" +
		"  - {name: missing, password: {initial: \"{{ nope }}\"}}\n" +
		"  - {name: filtered, password: {initial: \"{{ v | default('') }}\"}}\n" +
		"  - {name: literal, password: {initial: \"plain\"}}\n" +
		"  - {name: none}\n"
	vars := `{"v": "` + secret + `"}`

	t.Run("with the run's variables", func(t *testing.T) {
		got := initialsOf(t, roster, userRun(t, vars))
		if bare := got["bare"]; bare.Form != PasswordTemplate || bare.Reason != PasswordValueOK || bare.Value != secret || bare.Var != "v" || !bare.Sendable() {
			t.Fatalf("bare = %v (value matches %v)", bare, bare.Value == secret)
		}
		if m := got["missing"]; m.Reason != PasswordReasonUndefined || m.Value != "" || m.Sendable() || m.Var != "nope" {
			t.Fatalf("missing = %v", m)
		}
		if f := got["filtered"]; f.Reason != PasswordReasonNotBare || f.Value != "" || f.Sendable() || f.Var != "" {
			t.Fatalf("filtered = %v", f)
		}
		if l := got["literal"]; l.Form != PasswordLiteral || l.Value != "plain" || !l.Sendable() {
			t.Fatalf("literal = %v", l)
		}
		if n := got["none"]; n.Form != PasswordAbsent || n.Sendable() {
			t.Fatalf("none = %v", n)
		}
	})
	t.Run("a run whose variables were not read", func(t *testing.T) {
		got := initialsOf(t, roster, nil)
		if bare := got["bare"]; bare.Reason != PasswordReasonNoRunVars || bare.Value != "" || bare.Sendable() || bare.Var != "v" {
			t.Fatalf("bare with no run variables = %v", bare)
		}
		// A literal needs no variables.
		if !got["literal"].Sendable() {
			t.Fatal("a literal depends on the run's variables")
		}
		// A reference that is not bare is not bare, with or without them.
		if f := got["filtered"]; f.Reason != PasswordReasonNotBare {
			t.Fatalf("filtered with no run variables = %v", f)
		}
	})
}

// G2: !unsafe above the value makes it a literal, as it does for Ansible, and a
// value shared between !unsafe and normal YAML is ambiguous. A trigger row for each
// of the two, and the plain template that passes.
func TestRosterUserPasswordsJudgesATemplateWithItsTrust(t *testing.T) {
	secret := sentinelSecret(t)
	r := userRun(t, `{"x": "`+secret+`"}`)
	for _, tc := range []struct {
		name   string
		roster string
		users  []string // the users the row is about
		form   PasswordForm
		value  string
		reason PasswordValueReason
	}{
		{"a plain template resolves", "users:\n  - {name: u, password: {initial: \"{{ x }}\"}}\n", []string{"u"}, PasswordTemplate, secret, PasswordValueOK},
		{"users: !unsafe makes it the literal text", "users: !unsafe\n  - {name: u, password: {initial: \"{{ x }}\"}}\n", []string{"u"}, PasswordLiteral, "{{ x }}", PasswordValueOK},
		{"password: !unsafe makes it the literal text", "users:\n  - name: u\n    password: !unsafe {initial: \"{{ x }}\"}\n", []string{"u"}, PasswordLiteral, "{{ x }}", PasswordValueOK},
		{"the initial value tagged !unsafe is a literal", "users:\n  - {name: u, password: {initial: !unsafe \"{{ x }}\"}}\n", []string{"u"}, PasswordLiteral, "{{ x }}", PasswordValueOK},
		{"a whole document that is !unsafe", "--- !unsafe\nusers:\n  - {name: u, password: {initial: \"{{ x }}\"}}\n", []string{"u"}, PasswordLiteral, "{{ x }}", PasswordValueOK},
		{"a plain sibling of an !unsafe one is still a template", "users:\n  - {name: u, password: {initial: \"{{ x }}\"}}\n  - {name: lit, password: {initial: !unsafe \"{{ x }}\"}}\n", []string{"u"}, PasswordTemplate, secret, PasswordValueOK},
		{"a merge from an !unsafe mapping is ambiguous", "users:\n  - {name: a, password: &p !unsafe {initial: \"{{ x }}\"}}\n  - {name: b, password: {<<: *p}}\n", []string{"a", "b"}, PasswordAmbiguous, "", PasswordValueOK},
		{"an !unsafe mapping merging a plain one is ambiguous", "users:\n  - {name: a, password: &p {initial: \"{{ x }}\"}}\n  - {name: b, password: !unsafe {<<: *p}}\n", []string{"a", "b"}, PasswordAmbiguous, "", PasswordValueOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := initialsOf(t, tc.roster, r)
			for _, name := range tc.users {
				p := got[name]
				if p.Form != tc.form || p.Value != tc.value || p.Reason != tc.reason {
					t.Fatalf("%s: form %s, reason %s, value matches %v; want %s, %s, true", name, p.Form, p.Reason, p.Value == tc.value, tc.form, tc.reason)
				}
				if tc.form == PasswordAmbiguous && p.Sendable() {
					t.Fatalf("%s: an ambiguous password is sendable", name)
				}
			}
		})
	}
}

// A literal is never turned into something else by the run, and an inline !vault
// roster value stays refused (G3): the run's variables do not decrypt it.
func TestRosterUserPasswordsLeavesOtherFormsToTheirRules(t *testing.T) {
	r := userRun(t, `{"v": "pw"}`)
	roster := "users:\n" +
		"  - name: vault\n    password:\n      initial: !vault |\n        $ANSIBLE_VAULT;1.1;AES256\n        6162636465\n" +
		"  - {name: number, password: {initial: 12345678}}\n" +
		"  - {name: empty, password: {initial: \"\"}}\n"
	got := initialsOf(t, roster, r)
	if got["vault"].Form != PasswordEncrypted || got["vault"].Sendable() {
		t.Fatalf("an inline !vault value: %v", got["vault"])
	}
	if got["number"].Form != PasswordNotString || got["number"].Sendable() {
		t.Fatalf("an unquoted number: %v", got["number"])
	}
	if got["empty"].Form != PasswordAbsent || got["empty"].Sendable() {
		t.Fatalf("an empty string: %v", got["empty"])
	}
}

// For every spelling, with and without the run's variables: the password is
// sendable exactly when it has a value, and a value exists only where the rule
// says (so the plan, which asks the rule, and the source, which asks for the
// value, cannot differ).
func TestPasswordSendableIsExactlyHavingAValue(t *testing.T) {
	r := userRun(t, `{"ipa_admin_password": "from-the-run"}`)
	for _, tt := range passwordSpellings {
		for name, run := range map[string]*RosterRunVars{"no run": nil, "a run": r} {
			t.Run(tt.name+"/"+name, func(t *testing.T) {
				p := initialsOf(t, string(rosterWithInitial(tt.scalar)), run)["alice"]
				if p.Sendable() != (p.Value != "") {
					t.Fatalf("%v: Sendable = %v, has a value = %v", p, p.Sendable(), p.Value != "")
				}
				if got := DescribePasswordValue(p.Form, p.Reason, p.Var); (got == "") != p.Sendable() {
					t.Fatalf("%v: DescribePasswordValue = %q, Sendable = %v", p, got, p.Sendable())
				}
			})
		}
	}
}

// What a refusal says names the variable of a bare reference and never a value or
// the text of a template that is not bare; every reason has a text of its own.
func TestDescribePasswordValueNamesTheReasonAndNeverAValue(t *testing.T) {
	secret := sentinelSecret(t)
	seen := map[string]PasswordValueReason{}
	for reason := PasswordReasonNotBare; reason <= PasswordReasonInvalidText; reason++ {
		text := DescribePasswordValue(PasswordTemplate, reason, "the_var")
		if text == "" {
			t.Fatalf("%s has no text", reason)
		}
		if strings.Contains(text, secret) || !strings.Contains(text, "password.initial") {
			t.Fatalf("%s: %q", reason, text)
		}
		if other, dup := seen[text]; dup {
			t.Fatalf("%s and %s say the same thing", reason, other)
		}
		seen[text] = reason
		if reason != PasswordReasonNotBare && !strings.Contains(text, "the_var") {
			t.Errorf("%s does not name the variable: %q", reason, text)
		}
		if reason == PasswordReasonNotBare && strings.Contains(text, "the_var") {
			t.Errorf("a template that is not bare names a variable: %q", text)
		}
	}
	if DescribePasswordValue(PasswordTemplate, PasswordValueOK, "v") != "" || DescribePasswordValue(PasswordLiteral, PasswordValueOK, "") != "" {
		t.Fatal("a sendable password has a refusal text")
	}
	for form, want := range map[PasswordForm]string{
		PasswordEncrypted: "inline !vault", PasswordNotString: "other than a string", PasswordAmbiguous: "alias or merge key", PasswordAbsent: "is empty",
	} {
		if text := DescribePasswordValue(form, PasswordValueOK, ""); !strings.Contains(text, want) {
			t.Errorf("%s: %q does not say %q", form, text, want)
		}
	}
}

// G10 for the inventory package: the run's variables hold decrypted values, and no
// formatting of them, of a pointer to them, of a struct that holds them or of the
// passwords read with them shows one.
func TestRunVarsAndPasswordsNeverFormatAValue(t *testing.T) {
	secret := sentinelSecret(t)
	r := run(t, RosterConsumerFreeIPAIdentity, `{"v": "`+secret+`", "other": {"nested": "`+secret+`"}}`)
	holder := struct {
		Vars  RosterRunVars
		Ptr   *RosterRunVars
		Extra string
	}{r, &r, "x"}
	got := initialsOf(t, "users:\n  - {name: u, password: {initial: \"{{ v }}\"}}\n", &r)
	if got["u"].Value != secret {
		t.Fatal("the reference did not resolve")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		for what, text := range map[string]string{
			"run vars":          fmt.Sprintf(verb, r),
			"pointer":           fmt.Sprintf(verb, &r),
			"holder (exported)": fmt.Sprintf(verb, holder),
			"passwords":         fmt.Sprintf(verb, got),
			"one password":      fmt.Sprintf(verb, got["u"]),
		} {
			if strings.Contains(text, secret) {
				t.Errorf("%s of %s shows the value: %s", verb, what, text)
			}
		}
	}
	// JSON never carries it either: a struct of this type is never put in a plan
	// or a journal, and the tag makes sure it could not be by accident.
	if data, err := json.Marshal(got); err != nil || strings.Contains(string(data), secret) {
		t.Fatalf("JSON of the passwords shows the value (err %v): %s", err, data)
	}
}
