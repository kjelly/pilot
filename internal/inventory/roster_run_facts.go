package inventory

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

// runValue is the outcome of looking one variable up: unknown, undefined, or
// a value (nil, string, bool, float64, []any or map[string]any: the types of
// a JSON document).
type runValue struct {
	state runValueState
	value any
}

// lookup follows name through chains of bare references.
func (r RosterRunVars) lookup(name string, visited map[string]bool, depth int) runValue {
	if depth > maxRunVarHops || visited[name] {
		return runValue{state: runUnknown}
	}
	visited[name] = true
	if implicitVarName(name) || playbookDefinedNames(r.Consumer)[name] {
		return runValue{state: runUnknown}
	}
	v, ok := r.HostVars[name]
	if !ok {
		if r.ExtraNames[name] {
			return runValue{state: runUnknown}
		}
		return runValue{state: runUndefined}
	}
	switch x := v.(type) {
	case string:
		if inner := bareTemplateName(x); inner != "" {
			return r.lookup(inner, visited, depth+1)
		}
		if jinjaDelimited(x) {
			return runValue{state: runUnknown}
		}
	case map[string]any:
		if len(x) == 1 {
			if text, ok := x["__ansible_unsafe"].(string); ok {
				return runValue{state: runKnown, value: text}
			}
			if _, ok := x["__ansible_vault"]; ok {
				return runValue{state: runUnknown}
			}
		}
	}
	return runValue{state: runKnown, value: v}
}

// ServerDeclared is whether a freeipa.server that is exactly {{ name }} counts
// as declared: the playbook's condition is `server | default(”) | string |
// trim | length == 0`, so an undefined name and a value that renders to an
// empty or blank string are not declared; null is (None | string is the text
// None); a number, a boolean, a list or a mapping is.
func (r RosterRunVars) ServerDeclared(name string) RosterFact {
	got := r.lookup(name, map[string]bool{}, 0)
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
	got := r.lookup("ipa_admin_password", map[string]bool{}, 0)
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
