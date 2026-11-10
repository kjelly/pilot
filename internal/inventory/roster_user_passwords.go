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

// PasswordForm is how Ansible reads the password.initial scalar of a roster
// user.
type PasswordForm int

const (
	// PasswordAbsent: no password to set: the key is missing, null or empty.
	PasswordAbsent PasswordForm = iota
	// PasswordLiteral: a string Ansible uses as written (quoted, tagged !!str or
	// !unsafe, or plain and a string to YAML 1.1 and 1.2 alike).
	PasswordLiteral
	// PasswordTemplate: a string holding a Jinja delimiter, which Ansible
	// renders: pilot cannot tell what password it would set.
	PasswordTemplate
	// PasswordNotString: a value a YAML loader may read as a number, boolean or
	// date (or a list or mapping): not a password.
	PasswordNotString
	// PasswordEncrypted: an inline !vault value, which only Ansible can decrypt.
	PasswordEncrypted
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
	}
	return PasswordAbsent
}

// RosterUserPassword is what one roster user declares as password.initial.
// Value is set only for PasswordLiteral and is the password: it goes to the
// code that sets it and nowhere else, never into a message, a plan or a log.
type RosterUserPassword struct {
	Form  PasswordForm
	Value string
}

// String never shows Value.
func (p RosterUserPassword) String() string { return "password(" + p.Form.String() + ")" }

// GoString never shows Value, so %#v of a struct holding one is safe too.
func (p RosterUserPassword) GoString() string { return p.String() }

// RosterUserPasswords reads the plaintext roster data and returns, for every
// entry of its users list that has a string name, the form of its
// password.initial (and the literal's value), keyed by the name as written.
// Aliases and merge keys are followed as YAML resolves them. An encrypted file
// (ErrRosterEncrypted: decrypt it first), a document that does not parse, a users
// key that is not a list, an entry that is not a mapping with a string name, and a
// name that appears twice are errors that never hold a value from the document.
func RosterUserPasswords(data []byte) (map[string]RosterUserPassword, error) {
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
		kind := ansibleScalarKind(initial)
		res := RosterUserPassword{Form: passwordFormOf(kind)}
		if res.Form == PasswordLiteral {
			res.Value = initial.Value
		}
		out[name] = res
	}
	return out, nil
}
