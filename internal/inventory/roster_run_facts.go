package inventory

import (
	"fmt"
	"strings"
)

// Two facts of a run that decide whether the freeipa-identity playbook renders
// the roster's admin password are the run's own variables: ipa_admin_password
// (the admin password is its `default(x, true)` fallback) and, when the roster's
// freeipa.server is a bare {{ name }}, that variable (a server that renders to an
// empty string is not declared). Both are read from `ansible-inventory --list`
// with the run's -e and vault arguments, whose values are raw: a template is
// not rendered, an !unsafe value is {"__ansible_unsafe": "..."}, an inline
// !vault value is {"__ansible_vault": "..."}.
//
// RosterRunVars decides them the one way that can never refuse a run that
// works: a value is known only where it is a literal or a chain of bare
// {{ name }} references that ends in one; anything else (a filter, an
// operator, an inline !vault value, a name the playbook or Ansible defines
// itself, a cycle, a chain longer than maxRunVarHops) is RosterFactUnknown.
//
// The same walk resolves a user's password.initial that is one bare reference
// (UserInitialPassword), where the name set that shadows the inventory is the
// one in force when the playbook captures the password, not when it first
// renders a roster string (passwordCaptureNames), and where a value that is not
// provably what the playbook sends is refused, never guessed. That includes a
// value that came through the {"__ansible_unsafe": x} marker: a genuine !unsafe
// string and a literal mapping of that shape list identically, so it is refused
// (PasswordReasonUnsafeMarker). ServerDeclared and AdminPasswordProvided still
// read through the marker, as they always have: the text decides nothing there
// that the mapping would decide differently.

// maxRunVarHops bounds the chain of bare references one lookup follows.
const maxRunVarHops = 8

// RosterRunVars is what a precheck knows about one host's run.
type RosterRunVars struct {
	// HostVars are the host's variables as `ansible-inventory --list` prints
	// them, with the run's -e and vault arguments applied.
	HostVars map[string]any
	// ExtraNames are the names the run passes with -e. One that HostVars does
	// not hold has a value nobody here can read, so it is unknown, not undefined.
	ExtraNames map[string]bool
	// Consumer is the apply playbook the run applies: the names it defines
	// for itself before it renders a roster string are not the inventory's
	// (a play `vars:` entry outranks an inventory value), so they are unknown.
	Consumer RosterVarConsumer
}

type runValueState int

const (
	runUnknown runValueState = iota
	runUndefined
	runKnown
)

// String never shows a variable: HostVars holds the decrypted values of the
// run's vars file, and a %v of a struct that holds one would print them all.
func (r RosterRunVars) String() string {
	return fmt.Sprintf("run variables (%d)", len(r.HostVars))
}

// GoString never shows a variable either, so %#v of anything that holds the run's
// variables is safe too.
func (r RosterRunVars) GoString() string { return r.String() }

// runValue is the outcome of looking one variable up: unknown, undefined, or
// a value (nil, string, bool, float64, []any or map[string]any: the types of
// a JSON document). reason says why it is unknown or undefined, for the
// message of a password that cannot be sent; it says nothing else.
type runValue struct {
	state  runValueState
	value  any
	reason PasswordValueReason
	// unsafeMarker is set where a single-key mapping {"__ansible_unsafe": text}
	// was unwrapped to its text. ansible-inventory --list prints a genuine
	// !unsafe string and a literal YAML mapping {__ansible_unsafe: text}
	// identically, but Ansible holds the first as an unsafe string and the
	// second as a dict, so the text cannot tell which one the run sends.
	unsafeMarker bool
}

// lookup follows name through chains of bare references. shadow is the set of
// names whose value in a run is not the inventory's: the names the playbook
// defines for itself at the point the value is read.
func (r RosterRunVars) lookup(name string, shadow map[string]bool, visited map[string]bool, depth int) runValue {
	if depth > maxRunVarHops || visited[name] {
		return runValue{state: runUnknown, reason: PasswordReasonChain}
	}
	visited[name] = true
	if implicitVarName(name) {
		return runValue{state: runUnknown, reason: PasswordReasonReserved}
	}
	if shadow[name] {
		return runValue{state: runUnknown, reason: PasswordReasonShadowed}
	}
	v, ok := r.HostVars[name]
	if !ok {
		if r.ExtraNames[name] {
			return runValue{state: runUnknown, reason: PasswordReasonShadowed}
		}
		return runValue{state: runUndefined, reason: PasswordReasonUndefined}
	}
	switch x := v.(type) {
	case string:
		if inner := bareTemplateName(x); inner != "" {
			return r.lookup(inner, shadow, visited, depth+1)
		}
		if jinjaDelimited(x) {
			return runValue{state: runUnknown, reason: PasswordReasonNestedTemplate}
		}
	case map[string]any:
		if len(x) == 1 {
			if text, ok := x["__ansible_unsafe"].(string); ok {
				return runValue{state: runKnown, value: text, unsafeMarker: true}
			}
			if _, ok := x["__ansible_vault"]; ok {
				return runValue{state: runUnknown, reason: PasswordReasonInlineVault}
			}
		}
	}
	return runValue{state: runKnown, value: v}
}

// UserInitialPassword resolves a user's password.initial that is exactly one bare
// {{ name }} to the string the identity playbook sends for it, from the run's
// variables, and says why not otherwise (never a value in the reason). It is the
// one resolver of a password reference: the plan and the source of the passwords
// both get their answer from it, through RosterUserPasswords.
//
// What the playbook sends is the template rendered at the "Normalize canonical
// users and groups" include, after the settings set_fact, so a name defined by
// the play, its early pre_tasks, the settings task, the normalize task itself or
// pilot's own -e is not the inventory's (passwordCaptureNames) and is refused,
// as is anything that is not a string the run decides: null, a number, a list, an
// inline !vault value, an empty string, a chain that loops or is longer than
// maxRunVarHops, and a value that is, or a chain that ends in, the
// {"__ansible_unsafe": x} marker (an !unsafe string or a literal mapping, which
// the listing cannot tell apart). A whitespace-only string is a password, as a literal one is.
// Only the identity consumer renders a user's password.
func (r RosterRunVars) UserInitialPassword(template string) (string, PasswordValueReason) {
	name := bareTemplateName(template)
	if name == "" {
		return "", PasswordReasonNotBare
	}
	if r.Consumer != RosterConsumerFreeIPAIdentity {
		return "", PasswordReasonNoRunVars
	}
	got := r.lookup(name, passwordCaptureNames(r.Consumer), map[string]bool{}, 0)
	if got.state != runKnown {
		return "", got.reason
	}
	if got.unsafeMarker {
		// {"__ansible_unsafe": x} is what a genuine !unsafe string and a literal
		// mapping both list as; Ansible sends the first as text and the second as
		// the JSON of a dict, and nothing in the listing says which it is.
		return "", PasswordReasonUnsafeMarker
	}
	text, ok := got.value.(string)
	switch {
	case !ok:
		return "", PasswordReasonNotString
	case text == "":
		return "", PasswordReasonEmpty
	case strings.ContainsRune(text, '\uFFFD'):
		return "", PasswordReasonInvalidText
	}
	return text, PasswordValueOK
}

// ServerDeclared is whether a freeipa.server that is exactly {{ name }} counts
// as declared: the playbook's condition is `server | default(”) | string |
// trim | length == 0`, so an undefined name and a value that renders to an
// empty or blank string are not declared; null is (None | string is the text
// None); a number, a boolean, a list or a mapping is.
func (r RosterRunVars) ServerDeclared(name string) RosterFact {
	got := r.lookup(name, playbookDefinedNames(r.Consumer), map[string]bool{}, 0)
	switch got.state {
	case runUnknown:
		return RosterFactUnknown
	case runUndefined:
		return RosterFactNo
	}
	if text, ok := got.value.(string); ok {
		if pyStrip(text) == "" {
			return RosterFactNo
		}
	}
	return RosterFactYes
}

// AdminPasswordProvided is whether the run's ipa_admin_password is defined and
// truthy, which is what `ipa_admin_password | default(<roster password>, true)`
// takes as "use it" (Python truthiness: not undefined, null, false, 0, an empty
// string, list or mapping).
func (r RosterRunVars) AdminPasswordProvided() RosterFact {
	got := r.lookup("ipa_admin_password", playbookDefinedNames(r.Consumer), map[string]bool{}, 0)
	switch got.state {
	case runUnknown:
		return RosterFactUnknown
	case runUndefined:
		return RosterFactNo
	}
	if truthy(got.value) {
		return RosterFactYes
	}
	return RosterFactNo
}

// truthy is Python's bool() of a value of a JSON document.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return x != ""
	case bool:
		return x
	case float64:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}
