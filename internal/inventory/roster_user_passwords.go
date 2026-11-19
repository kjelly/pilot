package inventory

import (
	"errors"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// The identity engine reads a roster through a decoded map[string]any, which has
// already lost what Ansible needs to know about a password scalar: whether it was
// quoted, tagged !unsafe or !vault, or a template. This file answers that from
// the roster's bytes, with the one classifier every other password check of this
// package uses (ansibleScalarKind, AGENTS.md §5.7), so the engine never judges a
// password form a second way.
//
// A password.initial that is exactly one bare {{ name }} reference is the one
// template the engine can still send: RosterUserPasswords resolves it through
// RosterRunVars.UserInitialPassword, the one resolver, over the effective
// variables of the run the Ansible engine would make. Every other template, and
// every reference that resolver cannot prove is the value the playbook would
// send, is refused by name (PasswordValueReason) and never sent.

// PasswordForm is how Ansible reads the password.initial scalar of a roster
// user.
type PasswordForm int

const (
	// PasswordAbsent: no password to set: the key is missing, null or empty.
	PasswordAbsent PasswordForm = iota
	// PasswordLiteral: a string Ansible uses as written (quoted, tagged !!str or
	// !unsafe, or plain and a string to YAML 1.1 and 1.2 alike; also a template
	// below an !unsafe mapping, list or document, which is never rendered).
	PasswordLiteral
	// PasswordTemplate: a string holding a Jinja delimiter, which Ansible
	// renders. Whether pilot can still tell what password it would set is the
	// RosterUserPassword's Reason: only a bare {{ name }} whose value the run's
	// variables decide is sendable.
	PasswordTemplate
	// PasswordNotString: a value a YAML loader may read as a number, boolean or
	// date (or a list or mapping): not a password.
	PasswordNotString
	// PasswordEncrypted: an inline !vault value, which only Ansible can decrypt.
	PasswordEncrypted
	// PasswordAmbiguous: a template-looking string that an alias or merge key
	// shares between a part of the document that is !unsafe and a part that is
	// not, so Ansible renders it or not depending on its loader's build order and
	// the text cannot say which (yamlTrust).
	PasswordAmbiguous
)

func (f PasswordForm) String() string {
	switch f {
	case PasswordAbsent:
		return "absent"
	case PasswordLiteral:
		return "literal"
	case PasswordTemplate:
		return "template"
	case PasswordNotString:
		return "not-a-string"
	case PasswordEncrypted:
		return "inline-vault"
	case PasswordAmbiguous:
		return "ambiguous"
	}
	return fmt.Sprintf("PasswordForm(%d)", int(f))
}

func passwordFormOf(kind scalarKind) PasswordForm {
	switch kind {
	case scalarLiteral:
		return PasswordLiteral
	case scalarTemplate:
		return PasswordTemplate
	case scalarNotString:
		return PasswordNotString
	case scalarEncrypted:
		return PasswordEncrypted
	case scalarAmbiguous:
		return PasswordAmbiguous
	}
	return PasswordAbsent
}

// PasswordValueReason is why a password.initial that is a template was not
// resolved to the password the identity playbook would send. It is a code, never
// text of the roster or of a variable's value: it goes into a plan, a journal
// and a message.
type PasswordValueReason int

const (
	// PasswordValueOK: resolved (a literal, or a bare reference whose value the
	// run's variables decide).
	PasswordValueOK PasswordValueReason = iota
	// PasswordReasonNotBare: the template is not exactly one {{ name }}.
	PasswordReasonNotBare
	// PasswordReasonNoRunVars: the run's variables were not read: the workspace
	// has no vault vars file, or ansible-inventory could not list them with it.
	PasswordReasonNoRunVars
	// PasswordReasonShadowed: the name is one the identity playbook defines for
	// itself before it captures the password, or one pilot passes with -e: what
	// the inventory says of it is not what the playbook renders.
	PasswordReasonShadowed
	// PasswordReasonInlineVault: the variable, or one on its chain of bare
	// references, is an inline !vault value, which only Ansible can decrypt.
	PasswordReasonInlineVault
	// PasswordReasonNestedTemplate: the variable, or one on its chain, holds a
	// template that is not a bare reference.
	PasswordReasonNestedTemplate
	// PasswordReasonChain: the chain of bare references loops or is longer than
	// maxRunVarHops.
	PasswordReasonChain
	// PasswordReasonUndefined: nothing in the run defines the variable (the
	// Ansible engine fails on it).
	PasswordReasonUndefined
	// PasswordReasonEmpty: the value is an empty string, which FreeIPA refuses.
	PasswordReasonEmpty
	// PasswordReasonNotString: the value is null, a number, a boolean, a list or
	// a mapping: Ansible would not send it as a password string.
	PasswordReasonNotString
	// PasswordReasonInvalidText: the value holds U+FFFD, which marks bytes that
	// did not decode: it is not text pilot can prove Ansible would send.
	PasswordReasonInvalidText
	// PasswordReasonReserved: the name is one Ansible reserves for its own
	// variables: a magic variable (inventory_hostname, groups, hostvars...), a
	// fact or other ansible_* variable, a role_* variable, or a Jinja global or
	// literal. Pilot does not resolve these: not that something defines them
	// before the password is read, but that they are not the inventory's to give.
	// Added after the others so the codes of the earlier reasons do not move.
	PasswordReasonReserved
)

func (r PasswordValueReason) String() string {
	switch r {
	case PasswordValueOK:
		return "ok"
	case PasswordReasonNotBare:
		return "not-bare"
	case PasswordReasonNoRunVars:
		return "no-run-vars"
	case PasswordReasonShadowed:
		return "shadowed"
	case PasswordReasonInlineVault:
		return "inline-vault"
	case PasswordReasonNestedTemplate:
		return "nested-template"
	case PasswordReasonChain:
		return "chain"
	case PasswordReasonUndefined:
		return "undefined"
	case PasswordReasonEmpty:
		return "empty"
	case PasswordReasonNotString:
		return "not-a-string"
	case PasswordReasonInvalidText:
		return "invalid-text"
	case PasswordReasonReserved:
		return "reserved"
	}
	return fmt.Sprintf("PasswordValueReason(%d)", int(r))
}

// PasswordSendable is whether a password.initial of this form and reason is a
// string the engine may send: a literal, or a template that resolved. It is the
// one rule the plan (which blocks the user otherwise) and the source of the
// passwords (which hands out nothing otherwise) both ask, so they cannot
// disagree about which users have a password.
func PasswordSendable(form PasswordForm, reason PasswordValueReason) bool {
	switch form {
	case PasswordLiteral:
		return true
	case PasswordTemplate:
		return reason == PasswordValueOK
	}
	return false
}

// DescribePasswordValue says why a password.initial of this form and reason
// cannot be sent, "" when it can (PasswordSendable). varName is the variable of a
// bare reference, "" otherwise: the text names it, because a variable name is an
// identifier from the roster and a value never is. The text holds no roster
// text and no value.
func DescribePasswordValue(form PasswordForm, reason PasswordValueReason, varName string) string {
	if PasswordSendable(form, reason) {
		return ""
	}
	ref := "password.initial refers to " + varName
	if varName == "" {
		ref = "password.initial refers to a variable"
	}
	switch form {
	case PasswordTemplate:
		switch reason {
		case PasswordReasonNotBare:
			return "password.initial is a Jinja template that is not exactly one bare {{ name }} reference: pilot does not render templates, and the Go engine sets only a password written out in the roster or a bare reference to a variable of the run; use the Ansible engine for it"
		case PasswordReasonNoRunVars:
			return ref + ", but the run's variables were not read (the workspace has no .vault/main.yaml, or ansible-inventory could not list them with it): use the Ansible engine for it"
		case PasswordReasonShadowed:
			return ref + ", a name the identity playbook or pilot's own -e defines before the playbook reads the password, so the inventory's value is not what the playbook would send: use the Ansible engine for it"
		case PasswordReasonReserved:
			return ref + ", a name Ansible reserves for its own variables (magic variables, facts, role variables, Jinja globals), which pilot does not resolve: use the Ansible engine for it"
		case PasswordReasonInlineVault:
			return ref + ", whose value is an inline !vault value (or reaches one): only Ansible can decrypt it; encrypt the whole vars file instead, or use the Ansible engine"
		case PasswordReasonNestedTemplate:
			return ref + ", whose value is a template that is not a bare reference: pilot does not render it; use the Ansible engine for it"
		case PasswordReasonChain:
			return ref + " through a chain of references that loops or is longer than pilot follows: use the Ansible engine for it"
		case PasswordReasonUndefined:
			return ref + ", which nothing in the run defines: the Ansible engine fails on it too"
		case PasswordReasonEmpty:
			return ref + ", which is an empty string: FreeIPA refuses an empty password"
		case PasswordReasonNotString:
			return ref + ", which is not a string (null, a number, a boolean, a list or a mapping): quote it so it stays one"
		case PasswordReasonInvalidText:
			return ref + ", whose value holds the replacement character U+FFFD: it did not decode as text, so pilot cannot prove what the playbook would send"
		}
		return ref + ": its value cannot be read"
	case PasswordEncrypted:
		return "password.initial is an inline !vault value: only Ansible can decrypt it; use the Ansible engine for it, or encrypt the whole roster file instead"
	case PasswordNotString:
		return "password.initial may be read as something other than a string: quote it so it stays one"
	case PasswordAmbiguous:
		return "password.initial is shared by a YAML alias or merge key between !unsafe and normal YAML, so whether Ansible renders it cannot be told from the text: write it out where it is used"
	}
	return "password.initial is empty: FreeIPA refuses an empty password"
}

// RosterUserPassword is what one roster user declares as password.initial.
// Value is set only when the password is sendable (PasswordSendable): a literal,
// or a bare reference that resolved. It is the password: it goes to the code that
// sets it and nowhere else, never into a message, a plan or a log.
type RosterUserPassword struct {
	Form PasswordForm
	// Reason is why a PasswordTemplate was not resolved (PasswordValueOK when it
	// was); for every other form it is PasswordValueOK and says nothing.
	Reason PasswordValueReason
	// Var is the variable of a template that is exactly one bare {{ name }}, ""
	// for any other value: a name from the roster, never a value.
	Var string
	// Value is the password. The tag keeps it out of any JSON: nothing marshals
	// this struct today, and nothing may begin to show a password by doing so.
	Value string `json:"-"`
}

// Sendable is PasswordSendable of the password's form and reason.
func (p RosterUserPassword) Sendable() bool { return PasswordSendable(p.Form, p.Reason) }

// String never shows Value.
func (p RosterUserPassword) String() string {
	if p.Form == PasswordTemplate {
		return "password(" + p.Form.String() + ", " + p.Reason.String() + ")"
	}
	return "password(" + p.Form.String() + ")"
}

// GoString never shows Value, so %#v of a struct holding one is safe too.
func (p RosterUserPassword) GoString() string { return p.String() }

// RosterUserPasswords reads the plaintext roster data and returns, for every
// entry of its users list that has a string name, the form of its
// password.initial (and the password when the engine can send it), keyed by the
// name as written. Aliases and merge keys are followed as YAML resolves them, and
// the form is judged with the document's trust map (newYAMLTrust, as the
// reference check does): a template below an !unsafe mapping, list or document is
// the literal text Ansible sends, and one shared by an alias or merge key between
// !unsafe and normal YAML is PasswordAmbiguous.
//
// A template that is exactly one bare {{ name }} is resolved with run
// (RosterRunVars.UserInitialPassword): run nil is a run whose variables were not
// read (PasswordReasonNoRunVars). An encrypted file (ErrRosterEncrypted: decrypt
// it first), a document that does not parse, a users key that is not a list, an
// entry that is not a mapping with a string name, and a name that appears twice
// are errors that never hold a value from the document.
func RosterUserPasswords(data []byte, run *RosterRunVars) (map[string]RosterUserPassword, error) {
	if strings.HasPrefix(strings.TrimSpace(string(data)), "$ANSIBLE_VAULT") {
		return nil, ErrRosterEncrypted
	}
	doc, err := parseYAMLDocument(data)
	if err != nil {
		if errors.Is(err, errCyclicYAML) {
			return nil, fmt.Errorf("read the users' passwords: %w", err)
		}
		return nil, fmt.Errorf("read the users' passwords: the roster does not parse")
	}
	trust := newYAMLTrust(doc)
	out := map[string]RosterUserPassword{}
	users, _ := mappingValue(documentRoot(doc), "users")
	if users == nil || users.Kind == yaml.ScalarNode && users.ShortTag() == "!!null" {
		return out, nil
	}
	if users.Kind != yaml.SequenceNode {
		return nil, errors.New("read the users' passwords: users is not a list")
	}
	for i, item := range users.Content {
		item = resolveAlias(item)
		if item == nil || item.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("read the users' passwords: users[%d] is not a mapping", i)
		}
		nameNode, _ := mappingValue(item, "name")
		if nameNode == nil || nameNode.Kind != yaml.ScalarNode || nameNode.ShortTag() != "!!str" {
			return nil, fmt.Errorf("read the users' passwords: users[%d] has no string name", i)
		}
		name := nameNode.Value
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("read the users' passwords: the user %q appears twice", name)
		}
		var initial *yaml.Node
		if pw, _ := mappingValue(item, "password"); pw != nil && pw.Kind == yaml.MappingNode {
			initial, _ = mappingValue(pw, "initial")
		} else if pw != nil && (pw.Kind != yaml.ScalarNode || pw.ShortTag() != "!!null") {
			// Not a mapping and not null: the engine's adapter refuses it by name
			// and kind; here it is a password nobody can read.
			out[name] = RosterUserPassword{Form: PasswordNotString}
			continue
		}
		kind := ansibleScalarKind(initial, trust)
		res := RosterUserPassword{Form: passwordFormOf(kind)}
		switch res.Form {
		case PasswordLiteral:
			res.Value = initial.Value
		case PasswordTemplate:
			res.Var = bareTemplateName(initial.Value)
			switch {
			case res.Var == "":
				res.Reason = PasswordReasonNotBare
			case run == nil:
				res.Reason = PasswordReasonNoRunVars
			default:
				res.Value, res.Reason = run.UserInitialPassword(initial.Value)
			}
		}
		out[name] = res
	}
	return out, nil
}
