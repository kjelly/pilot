package inventory

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// A roster string that Ansible templates — password.initial: '{{ ipa_default_initial_password }}',
// where the value lives in .vault/main.yaml — fails at apply time when the
// variable is not defined, inside a no_log task that censors the reason. The
// functions below read the references out of a roster (RosterSecretVarReferences)
// and decide which ones nothing defines (MissingRosterVarReferences), so
// `pilot roster lint --vars-file` and the deploy/reconcile preflight say so
// before apply does (issue #165). Everything here judges a roster value with
// the one classifier the other password checks use (ansibleScalarKind,
// AGENTS.md §5.7), and nothing it returns or reports holds a scalar from the
// roster or the vars file: only variable names, field labels and line numbers.

// ErrVarsFileEncrypted: the vars file is ansible-vault encrypted and no vault
// password file was given.
var ErrVarsFileEncrypted = errors.New("inventory: vars file is ansible-vault encrypted, cannot read it without a vault password")

// ErrVarsFileNotMapping: the vars file is YAML but not a mapping of variable
// names, which `-e @file` refuses too.
var ErrVarsFileNotMapping = errors.New("inventory: vars file is not a YAML mapping of variable names")

// RosterAdminPasswordField is the Field of the RosterVarRef values found in
// the roster's freeipa.admin.password.
const RosterAdminPasswordField = "freeipa.admin.password"

// RosterVarRef is one variable a roster's secret string refers to.
type RosterVarRef struct {
	// Field names where the reference sits: "freeipa.admin.password" or
	// "users[alice].password.initial" (the position, users[2], when the
	// user's name is missing, repeated or not a plain name).
	Field string
	// Name is the root variable of the reference: "x" for {{ x }} and for
	// {{ x.y }}. It is an identifier by construction, never a free-form value.
	Name string
	// Admin is true for freeipa.admin.password, false for a user's
	// password.initial.
	Admin bool
}

// Violation is the finding lint prints for r: definedIn says where the
// variable should have been defined (the --vars-file path).
func (r RosterVarRef) Violation(definedIn string) RosterViolation {
	return RosterViolation{
		Rule:   "roster-reference",
		Detail: fmt.Sprintf("%s references %s, which %s does not define", r.Field, r.Name, definedIn),
	}
}

// RosterSecretVarReferences reads the variable references out of the two
// roster fields that hold a secret: freeipa.admin.password and every
// users[].password.initial (state: absent users included — the playbook
// renders them too). plaintext must be a decrypted roster. Aliases and merge
// keys are followed as YAML resolves them.
//
// Only a value Ansible templates is a candidate (ansibleScalarKind says
// scalarTemplate): a literal, an !unsafe or inline !vault value, an empty or
// non-string one has no reference. Each {{ ... }} of a string is read on its
// own, and only a bare variable (x or x.y, whitespace control - allowed) is
// a reference: anything with a filter, a test, an operator, a call or a
// subscript cannot be judged without evaluating it. A string with {% or {# is
// not read at all. Every field with such a part is listed in unchecked.
//
// The error never holds roster content: ErrRosterEncrypted for an encrypted
// document, a YAML error as its line numbers only.
func RosterSecretVarReferences(plaintext []byte) (refs []RosterVarRef, unchecked []string, err error) {
	if hasVaultHeader(plaintext) {
		return nil, nil, ErrRosterEncrypted
	}
	doc, err := parseYAMLDocument(plaintext)
	if err != nil {
		return nil, nil, withheldYAMLError("the roster", err)
	}
	add := func(field string, admin bool, value *yaml.Node) {
		if ansibleScalarKind(value) != scalarTemplate {
			return
		}
		roots, complete := templateVarRoots(value.Value)
		for _, name := range roots {
			refs = append(refs, RosterVarRef{Field: field, Name: name, Admin: admin})
		}
		if !complete {
			unchecked = append(unchecked, field)
		}
	}

	if _, value, _ := rosterAdminPassword(doc); value != nil {
		add(RosterAdminPasswordField, true, value)
	}

	users, _ := mappingValue(documentRoot(doc), "users")
	if users == nil || users.Kind != yaml.SequenceNode {
		return refs, unchecked, nil
	}
	items := make([]*yaml.Node, len(users.Content))
	names := make([]string, len(users.Content))
	counts := map[string]int{}
	for i, item := range users.Content {
		items[i] = resolveAlias(item)
		if items[i] == nil || items[i].Kind != yaml.MappingNode {
			continue
		}
		if name, _ := mappingValue(items[i], "name"); name != nil && name.Kind == yaml.ScalarNode && name.ShortTag() == "!!str" && plainUserLabel.MatchString(name.Value) {
			names[i] = name.Value
			counts[name.Value]++
		}
	}
	for i, item := range items {
		if item == nil || item.Kind != yaml.MappingNode {
			continue
		}
		password, _ := mappingValue(item, "password")
		if password == nil || password.Kind != yaml.MappingNode {
			continue
		}
		initial, _ := mappingValue(password, "initial")
		label := fmt.Sprintf("users[%d]", i)
		if names[i] != "" && counts[names[i]] == 1 {
			label = "users[" + names[i] + "]"
		}
		add(label+".password.initial", false, initial)
	}
	return refs, unchecked, nil
}

// plainUserLabel is what a user name must look like to be named in a field
// label; anything else is labelled by its position, so a label never carries
// free-form roster text.
var plainUserLabel = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}$`)

// jinjaVarPath is the one expression body a reference is read from: a bare
// variable, optionally with attribute access.
var jinjaVarPath = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$`)

// jinjaWords are Jinja's own words: a body that is just one of them is a
// syntax error for Jinja, not a variable that is missing.
var jinjaWords = map[string]bool{
	"and": true, "or": true, "not": true, "in": true, "is": true, "if": true, "else": true, "elif": true,
	"for": true, "endif": true, "endfor": true, "set": true, "block": true, "macro": true, "call": true,
	"filter": true, "import": true, "include": true, "from": true, "extends": true, "with": true, "as": true,
}

// templateVarRoots returns the root variable of every bare-variable {{ }} in
// s, in order and without repeats, and whether every {{ }} was of that kind:
// complete is false when s holds a block or comment tag, a {{ with a filter,
// operator, call, subscript or no closing }}, or a word of Jinja's own.
func templateVarRoots(s string) (roots []string, complete bool) {
	if strings.Contains(s, "{%") || strings.Contains(s, "{#") {
		return nil, false
	}
	complete = true
	seen := map[string]bool{}
	rest := s
	for {
		open := strings.Index(rest, "{{")
		if open < 0 {
			return roots, complete
		}
		rest = rest[open+2:]
		end := strings.Index(rest, "}}")
		if end < 0 {
			return roots, false
		}
		body := rest[:end]
		rest = rest[end+2:]
		// {{- x -}} only controls the whitespace around the tag. (A + is not
		// whitespace control in a variable tag: {{+ x +}} is a syntax error.)
		body = strings.TrimSpace(body)
		body = strings.TrimSpace(strings.TrimPrefix(body, "-"))
		body = strings.TrimSpace(strings.TrimSuffix(body, "-"))
		if !jinjaVarPath.MatchString(body) {
			complete = false
			continue
		}
		root, _, _ := strings.Cut(body, ".")
		if jinjaWords[root] {
			complete = false
			continue
		}
		if !seen[root] {
			seen[root] = true
			roots = append(roots, root)
		}
	}
}

// implicitVarNames are the names a template finds without any vars file,
// extra var or inventory variable: Jinja's literals and globals, which the
// parser or the environment supplies, and Ansible's magic variables.
// TestImplicitVarNamesAreNeverUndefinedInAnsible renders each against
// ansible-core: none may be "undefined". (Jinja's literals are exactly
// true/false/none in lower case or capitalised: TRUE is an undefined variable.)
var implicitVarNames = map[string]bool{
	"true": true, "false": true, "none": true, "True": true, "False": true, "None": true,
	"range": true, "lipsum": true, "dict": true, "cycler": true, "joiner": true, "namespace": true,
	"lookup": true, "query": true, "q": true, "now": true, "undef": true,
	"omit": true, "vars": true, "environment": true,
	"inventory_hostname": true, "inventory_hostname_short": true, "inventory_dir": true, "inventory_file": true,
	"groups": true, "group_names": true, "hostvars": true, "playbook_dir": true, "play_hosts": true,
}

// implicitVarPrefixes are families of magic variables: facts and the other
// ansible_* variables, and the role_* ones. They are not listed one by one, so
// one that does not exist in a given run is not reported either.
var implicitVarPrefixes = []string{"ansible_", "role_"}

func implicitVarName(name string) bool {
	if implicitVarNames[name] {
		return true
	}
	for _, prefix := range implicitVarPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// MissingRosterVarReferences returns, in the order given, the references of
// refs whose variable none of the sets in defined has and that no template
// finds on its own (Jinja's literals and globals, Ansible's magic variables).
// A variable a set has with a null value is defined, as it is for Ansible.
func MissingRosterVarReferences(refs []RosterVarRef, defined ...map[string]bool) []RosterVarRef {
	var missing []RosterVarRef
outer:
	for _, ref := range refs {
		if implicitVarName(ref.Name) {
			continue
		}
		for _, set := range defined {
			if set[ref.Name] {
				continue outer
			}
		}
		missing = append(missing, ref)
	}
	return missing
}

// RosterVarConsumer is an apply playbook that renders (templates) strings of
// the roster, and so is the one that fails when a reference is undefined.
type RosterVarConsumer int

const (
	// RosterConsumerFreeIPAIdentity is freeipa-identity-apply.yml: it renders
	// every users[].password.initial, state: absent ones too; and it renders
	// freeipa.admin.password as the fallback when ipa_admin_password is not
	// defined and non-empty, and also whenever the roster leaves
	// freeipa.server empty, because the play then fills freeipa.server in with
	// a combine over the whole freeipa mapping, which renders its strings.
	RosterConsumerFreeIPAIdentity RosterVarConsumer = iota + 1
	// RosterConsumerFreeIPANFSServer is freeipa-nfs-server-apply.yml: it
	// renders freeipa.admin.password, always, and no user's password.
	RosterConsumerFreeIPANFSServer
)

// RosterRenderFacts are the facts of one run that decide which roster fields
// the freeipa-identity playbook renders.
type RosterRenderFacts struct {
	// AdminPasswordProvided: the run has an ipa_admin_password that is defined
	// and non-empty, so the playbook takes the admin password from it.
	AdminPasswordProvided bool
	// ServerDeclared: the roster's freeipa.server is non-empty
	// (RosterFreeIPAServerDeclared).
	ServerDeclared bool
}

// RosterVarReferencesRenderedBy keeps the references the playbook of consumer
// renders: the fields it never renders cannot fail it, however undefined they
// are, and refusing a deployment for one would refuse a run that works.
// TestRosterRenderedFieldsMatchAnsible pins both playbooks' behaviour against
// ansible-core, running the playbooks' own pre_tasks.
func RosterVarReferencesRenderedBy(consumer RosterVarConsumer, refs []RosterVarRef, facts RosterRenderFacts) []RosterVarRef {
	var out []RosterVarRef
	for _, ref := range refs {
		switch {
		case consumer == RosterConsumerFreeIPAIdentity && !ref.Admin,
			consumer == RosterConsumerFreeIPAIdentity && ref.Admin && (!facts.AdminPasswordProvided || !facts.ServerDeclared),
			consumer == RosterConsumerFreeIPANFSServer && ref.Admin:
			out = append(out, ref)
		}
	}
	return out
}

// RosterFreeIPAServerDeclared reports whether the decrypted roster's
// freeipa.server is non-empty, the way the identity playbook asks (its
// "Detect FreeIPA server FQDN when roster omits freeipa.server" condition:
// the value as a trimmed string has a length): a missing, null or blank value
// is not declared. A document that does not parse declares nothing.
func RosterFreeIPAServerDeclared(plaintext []byte) bool {
	doc, err := parseYAMLDocument(plaintext)
	if err != nil {
		return false
	}
	freeipa, _ := mappingValue(documentRoot(doc), "freeipa")
	server, _ := mappingValue(freeipa, "server")
	switch {
	case server == nil:
		return false
	case server.Kind == yaml.ScalarNode:
		return server.ShortTag() != "!!null" && strings.TrimSpace(server.Value) != ""
	}
	return true
}

// VarsFileNames returns the top-level variable names the plaintext vars file
// defines, merge keys included. A name with a null value is defined. The
// error holds no file content: ErrVarsFileEncrypted for an encrypted file,
// ErrVarsFileNotMapping for a document that is not a mapping, and a YAML
// error as its line numbers only (a plaintext vault vars file is secret too,
// and yaml.v3 quotes values in some of its errors).
func VarsFileNames(plaintext []byte) (map[string]bool, error) {
	if hasVaultHeader(plaintext) {
		return nil, ErrVarsFileEncrypted
	}
	doc, err := parseYAMLDocument(plaintext)
	if err != nil {
		return nil, withheldYAMLError("the vars file", err)
	}
	names := map[string]bool{}
	root := resolveAlias(documentRoot(doc))
	switch {
	case root == nil || root.Kind == 0:
		return names, nil // an empty file defines nothing
	case root.Kind == yaml.ScalarNode && root.ShortTag() == "!!null":
		return names, nil
	case root.Kind != yaml.MappingNode:
		return nil, ErrVarsFileNotMapping
	}
	collectMappingKeys(root, map[*yaml.Node]bool{}, names)
	return names, nil
}

// collectMappingKeys adds every key of mapping to out, those of the mappings
// merged into it with <<, and theirs in turn. A mapping reached twice adds
// nothing the second time, which also ends a walk on a cycle.
func collectMappingKeys(mapping *yaml.Node, seen map[*yaml.Node]bool, out map[string]bool) {
	mapping = resolveAlias(mapping)
	if mapping == nil || mapping.Kind != yaml.MappingNode || seen[mapping] {
		return
	}
	seen[mapping] = true
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		key, value := resolveAlias(mapping.Content[i]), mapping.Content[i+1]
		if key == nil {
			continue
		}
		if key.ShortTag() == "!!merge" {
			sources := []*yaml.Node{resolveAlias(value)}
			if sources[0] != nil && sources[0].Kind == yaml.SequenceNode {
				sources = sources[0].Content
			}
			for _, source := range sources {
				collectMappingKeys(source, seen, out)
			}
			continue
		}
		if key.Kind == yaml.ScalarNode {
			out[key.Value] = true
		}
	}
}

// ReadVarsFileNames reads the vars file at path once and returns the
// top-level variable names it defines (VarsFileNames): the file's own bytes,
// or, for an ansible-vault encrypted file, its content decrypted in memory
// with vaultPasswordFile (the decryption ReadRosterPlaintext uses; never a
// plaintext file on disk). An encrypted file with no vaultPasswordFile is
// ErrVarsFileEncrypted. vaultPasswordFile is not read for a plaintext file.
// It writes nothing, and nothing it returns or errs with is file content.
func ReadVarsFileNames(path, vaultPasswordFile string) (map[string]bool, error) {
	plaintext, _, err := readFileMaybeVault(path, vaultPasswordFile, "vars file", ErrVarsFileEncrypted)
	if err != nil {
		return nil, err
	}
	return VarsFileNames(plaintext)
}

// hasVaultHeader reports whether data is an ansible-vault encrypted file.
func hasVaultHeader(data []byte) bool {
	return strings.HasPrefix(strings.TrimSpace(string(data)), "$ANSIBLE_VAULT")
}

// yamlErrorLine matches the "line N" positions in a yaml.v3 error.
var yamlErrorLine = regexp.MustCompile(`line \d+`)

// withheldYAMLError is what a document that does not parse reports: the line
// numbers of the YAML error and nothing else. yaml.v3's messages quote the
// text they stumbled on, and a roster or a vault vars file is a place where
// that text can be a password.
func withheldYAMLError(what string, err error) error {
	if errors.Is(err, errCyclicYAML) {
		return fmt.Errorf("%s: %w", what, errCyclicYAML)
	}
	where := ""
	if lines := yamlErrorLine.FindAllString(err.Error(), -1); len(lines) > 0 {
		where = " at " + strings.Join(lines, ", ")
	}
	return fmt.Errorf("%s is not valid YAML%s (the YAML error is withheld because it can quote file content)", what, where)
}
