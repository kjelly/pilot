package inventory

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// run is RosterRunVars over a JSON document, as `ansible-inventory --list`
// prints a host's variables.
func run(t *testing.T, consumer RosterVarConsumer, hostVarsJSON string, extra ...string) RosterRunVars {
	t.Helper()
	vars := map[string]any{}
	if err := json.Unmarshal([]byte(hostVarsJSON), &vars); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, name := range extra {
		names[name] = true
	}
	return RosterRunVars{HostVars: vars, ExtraNames: names, Consumer: consumer}
}

// The run's variables decide the two facts that depend on the run, and what
// cannot be decided is Unknown: never a guess that could refuse a working run.
// This table is the twin of cmd's end-to-end oracle, whose rows run the same
// shapes through real ansible-inventory and the real playbook pre_tasks.
func TestRosterRunVarsAdminPasswordProvided(t *testing.T) {
	const unk, no, yes = RosterFactUnknown, RosterFactNo, RosterFactYes
	id := RosterConsumerFreeIPAIdentity
	for _, tc := range []struct {
		name  string
		vars  string
		extra []string
		want  RosterFact
	}{
		{"missing", `{}`, nil, no},
		{"null", `{"ipa_admin_password": null}`, nil, no},
		{"empty string", `{"ipa_admin_password": ""}`, nil, no},
		{"a string", `{"ipa_admin_password": "x"}`, nil, yes},
		{"false", `{"ipa_admin_password": false}`, nil, no},
		{"zero", `{"ipa_admin_password": 0}`, nil, no},
		{"a number", `{"ipa_admin_password": 7}`, nil, yes},
		{"an empty list", `{"ipa_admin_password": []}`, nil, no},
		{"a list", `{"ipa_admin_password": ["a"]}`, nil, yes},
		{"an empty mapping", `{"ipa_admin_password": {}}`, nil, no},
		{"an !unsafe empty string", `{"ipa_admin_password": {"__ansible_unsafe": ""}}`, nil, no},
		{"an !unsafe text", `{"ipa_admin_password": {"__ansible_unsafe": "{{ not_a_reference }}"}}`, nil, yes},
		{"an inline !vault value", `{"ipa_admin_password": {"__ansible_vault": "$ANSIBLE_VAULT;1.1;AES256"}}`, nil, unk},
		{"passed with -e only", `{}`, []string{"ipa_admin_password"}, unk},
		{"a template to a variable that is empty", `{"ipa_admin_password": "{{ empty_admin }}", "empty_admin": ""}`, nil, no},
		{"a template to a variable that is set", `{"ipa_admin_password": "{{ vault_admin }}", "vault_admin": "x"}`, nil, yes},
		{"a template to a variable that is undefined", `{"ipa_admin_password": "{{ vault_admin }}"}`, nil, no},
		{"a template to a variable that is null", `{"ipa_admin_password": "{{ vault_admin }}", "vault_admin": null}`, nil, no},
		{"a chain of references", `{"ipa_admin_password": "{{ a }}", "a": "{{- b -}}", "b": "x"}`, nil, yes},
		{"a chain that ends in an empty value", `{"ipa_admin_password": "{{ a }}", "a": "{{ b }}", "b": ""}`, nil, no},
		{"a chain that ends in !unsafe text", `{"ipa_admin_password": "{{ a }}", "a": {"__ansible_unsafe": "{{ b }}"}}`, nil, yes},
		{"a template with a filter", `{"ipa_admin_password": "{{ a | default('') }}", "a": "x"}`, nil, unk},
		{"a template with text around it", `{"ipa_admin_password": "x{{ a }}", "a": ""}`, nil, unk},
		{"a template with an attribute", `{"ipa_admin_password": "{{ a.b }}", "a": {"b": "x"}}`, nil, unk},
		{"a template to a name the playbook defines", `{"ipa_admin_password": "{{ stage }}", "stage": "sandbox"}`, nil, unk},
		{"a template to a magic name", `{"ipa_admin_password": "{{ inventory_hostname }}"}`, nil, unk},
		{"a template to an ansible_ fact", `{"ipa_admin_password": "{{ ansible_host }}"}`, nil, unk},
		{"a template to a name passed with -e only", `{"ipa_admin_password": "{{ pw }}"}`, []string{"pw"}, unk},
		{"a cycle", `{"ipa_admin_password": "{{ a }}", "a": "{{ ipa_admin_password }}"}`, nil, unk},
		{"a chain longer than the bound", chain(maxRunVarHops + 1), nil, unk},
		{"a chain exactly at the bound", chain(maxRunVarHops), nil, yes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(t, id, tc.vars, tc.extra...).AdminPasswordProvided(); got != tc.want {
				t.Fatalf("AdminPasswordProvided = %v, want %v", got, tc.want)
			}
		})
	}
}

// chain is ipa_admin_password -> v1 -> v2 ... -> v<n> = "x": n references.
func chain(n int) string {
	var b strings.Builder
	b.WriteString(`{"ipa_admin_password": "{{ v1 }}"`)
	for i := 1; i < n; i++ {
		b.WriteString(`, "v` + strconv.Itoa(i) + `": "{{ v` + strconv.Itoa(i+1) + ` }}"`)
	}
	b.WriteString(`, "v` + strconv.Itoa(n) + `": "x"}`)
	return b.String()
}

func TestRosterRunVarsServerDeclared(t *testing.T) {
	const unk, no, yes = RosterFactUnknown, RosterFactNo, RosterFactYes
	id := RosterConsumerFreeIPAIdentity
	for _, tc := range []struct {
		name  string
		vars  string
		extra []string
		want  RosterFact
	}{
		{"undefined: default('') makes it empty", `{}`, nil, no},
		{"an empty string", `{"srv": ""}`, nil, no},
		{"a blank string", `{"srv": "   "}`, nil, no},
		{"a string with a name", `{"srv": "ipa.example.test"}`, nil, yes},
		{"null is the text None", `{"srv": null}`, nil, yes},
		{"zero is the text 0", `{"srv": 0}`, nil, yes},
		{"false is the text False", `{"srv": false}`, nil, yes},
		{"an empty list is the text []", `{"srv": []}`, nil, yes},
		{"an empty mapping is the text {}", `{"srv": {}}`, nil, yes},
		{"an !unsafe empty string", `{"srv": {"__ansible_unsafe": ""}}`, nil, no},
		{"an !unsafe template text is a name", `{"srv": {"__ansible_unsafe": "{{ x }}"}}`, nil, yes},
		{"an inline !vault value", `{"srv": {"__ansible_vault": "$ANSIBLE_VAULT;1.1;AES256"}}`, nil, unk},
		{"a reference to an empty variable", `{"srv": "{{ srv2 }}", "srv2": ""}`, nil, no},
		{"a reference to a variable that is set", `{"srv": "{{ srv2 }}", "srv2": "ipa"}`, nil, yes},
		{"a reference to an undefined variable", `{"srv": "{{ srv2 }}"}`, nil, no},
		{"a filter is not followed", `{"srv": "{{ srv2 | default('x') }}", "srv2": ""}`, nil, unk},
		{"passed with -e only", `{}`, []string{"srv"}, unk},
		{"a cycle", `{"srv": "{{ srv2 }}", "srv2": "{{ srv }}"}`, nil, unk},
		{"Python strips the ASCII separators too", `{"srv": "\u001c\u001f"}`, nil, no},
		{"a zero-width space is not blank", `{"srv": "\u200b"}`, nil, yes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(t, id, tc.vars, tc.extra...).ServerDeclared("srv"); got != tc.want {
				t.Fatalf("ServerDeclared = %v, want %v", got, tc.want)
			}
		})
	}
}
