package inventory

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"go.yaml.in/yaml/v3"
)

// A roster string that Ansible templates — password.initial: '{{ ipa_default_initial_password }}',
// where the value lives in .vault/main.yaml — fails at apply time when the
// variable is not defined: inside a no_log task (whose fatal result is
// censored), mid-run, after the dependency chain has been applied. The
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
// non-string one has no reference. !unsafe on any mapping, list or document
// that encloses the value makes it a literal; a value that an alias or merge
// key shares between an !unsafe part and a normal one is ambiguous (Ansible
// templates it or not depending on its loader's build order, see yamlTrust) and
// is not judged. Each {{ ... }} of a string is read on its own, and only a
// bare variable (x or x.y, whitespace control - allowed) is a reference:
// anything with a filter, a test, an operator, a call or a subscript cannot be
// judged without evaluating it. A string with {% or {# is not read at all.
// Every field with such a part, and every ambiguous one, is listed in
// unchecked.
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
	trust := newYAMLTrust(doc)
	add := func(field string, admin bool, value *yaml.Node) {
		switch ansibleScalarKind(value, trust) {
		case scalarAmbiguous:
			unchecked = append(unchecked, field)
			return
		case scalarTemplate:
		default:
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

// RosterFact is a fact of one run that may be unknowable from where pilot
// stands. The zero value is RosterFactUnknown, so a fact nobody filled in never
// triggers a refusal: the check judges a reference only when every fact that
// decides whether the playbook renders it is known (never refuse a run that
// would work; a run it cannot judge is left to the playbook's own gates).
type RosterFact int

const (
	// RosterFactUnknown: it depends on something the check cannot evaluate (a
	// template with a filter, an inline !vault value, a name the playbook
	// itself defines, a scalar shared between !unsafe and normal YAML).
	RosterFactUnknown RosterFact = iota
	// RosterFactNo: known not to hold.
	RosterFactNo
	// RosterFactYes: known to hold.
	RosterFactYes
)

// RosterRenderFacts are the facts of one run that decide which roster fields
// the freeipa-identity playbook renders.
type RosterRenderFacts struct {
	// SchemaVersionDefined: the roster has a schema_version. The identity
	// playbook ignores a roster without one: every task that renders a roster
	// string is conditioned on `freeipa_roster.schema_version is defined`.
	SchemaVersionDefined RosterFact
	// AdminPasswordProvided: the run has an ipa_admin_password that is defined
	// and truthy (`default(x, true)`), so the playbook takes the admin password
	// from it.
	AdminPasswordProvided RosterFact
	// ServerDeclared: the roster's freeipa.server counts as declared
	// (RosterFreeIPAServerDeclared).
	ServerDeclared RosterFact
}

// RosterVarReferencesRenderedBy keeps the references the playbook of consumer
// certainly renders: the fields it never renders cannot fail it, however
// undefined they are, and refusing a deployment for one would refuse a run
// that works. A reference whose rendering depends on a fact that is unknown is
// not in the result (RosterVarReferencesMaybeRenderedBy lists it).
// TestRosterRenderedFieldsMatchAnsible pins both playbooks' behaviour against
// ansible-core, running the playbooks' own pre_tasks.
func RosterVarReferencesRenderedBy(consumer RosterVarConsumer, refs []RosterVarRef, facts RosterRenderFacts) []RosterVarRef {
	var out []RosterVarRef
	for _, ref := range refs {
		if rendersAs(consumer, ref, facts) == RosterFactYes {
			out = append(out, ref)
		}
	}
	return out
}

// RosterVarReferencesMaybeRenderedBy keeps the references the playbook might
// render, depending on a fact that is unknown: the ones a precheck must not
// refuse and says it did not judge.
func RosterVarReferencesMaybeRenderedBy(consumer RosterVarConsumer, refs []RosterVarRef, facts RosterRenderFacts) []RosterVarRef {
	var out []RosterVarRef
	for _, ref := range refs {
		if rendersAs(consumer, ref, facts) == RosterFactUnknown {
			out = append(out, ref)
		}
	}
	return out
}

// rendersAs is whether the playbook of consumer renders ref in a run with
// facts: Yes, No, or Unknown when a fact it depends on is.
func rendersAs(consumer RosterVarConsumer, ref RosterVarRef, facts RosterRenderFacts) RosterFact {
	switch consumer {
	case RosterConsumerFreeIPANFSServer:
		if ref.Admin {
			return RosterFactYes
		}
		return RosterFactNo
	case RosterConsumerFreeIPAIdentity:
		if facts.SchemaVersionDefined == RosterFactNo {
			return RosterFactNo
		}
		var rendered RosterFact
		if !ref.Admin {
			// Every user's password.initial, absent users included.
			rendered = RosterFactYes
		} else {
			// The admin password is the fallback of ipa_admin_password
			// (`default(x, true)`), and the server fill-in's combine renders
			// the whole freeipa mapping when freeipa.server is not declared.
			switch {
			case facts.AdminPasswordProvided == RosterFactNo || facts.ServerDeclared == RosterFactNo:
				rendered = RosterFactYes
			case facts.AdminPasswordProvided == RosterFactYes && facts.ServerDeclared == RosterFactYes:
				rendered = RosterFactNo
			default:
				rendered = RosterFactUnknown
			}
		}
		if rendered == RosterFactYes && facts.SchemaVersionDefined == RosterFactUnknown {
			return RosterFactUnknown
		}
		return rendered
	}
	return RosterFactNo
}

// RosterSchemaVersionDefined reports whether the decrypted roster defines
// schema_version (a null value is defined, as it is for
// `freeipa_roster.schema_version is defined`). A document that does not parse
// is unknown.
func RosterSchemaVersionDefined(plaintext []byte) RosterFact {
	doc, err := parseYAMLDocument(plaintext)
	if err != nil {
		return RosterFactUnknown
	}
	if value, _ := mappingValue(documentRoot(doc), "schema_version"); value == nil {
		return RosterFactNo
	}
	return RosterFactYes
}

// pyStrip is Python's str.strip() with no argument — what Jinja's trim does:
// it removes unicode.IsSpace characters and also the four ASCII separators
// \x1c-\x1f that Python counts as whitespace and Go does not.
func pyStrip(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
	})
}

// RosterFreeIPAServerDeclared reports whether the decrypted roster's
// freeipa.server counts as declared for the identity playbook's "Detect
// FreeIPA server FQDN when roster omits freeipa.server" and "Fill canonical
// roster freeipa.server" pre_tasks, whose condition takes the server, applies
// default with an empty-string argument, string and trim, and asks for a length
// of 0. That default replaces only a value that is not defined, so:
//
//   - No: a missing key (or a missing freeipa mapping), and an empty or blank
//     string (Python's str.strip decides what is blank);
//   - Yes: a null (None | string is the text None), a non-blank literal, any
//     other scalar, a list or a mapping;
//   - the literal rules apply to a value that is certainly !unsafe (tagged, or
//     below an !unsafe mapping or document): its text is never templated;
//   - Unknown: a template, which Ansible renders before it counts the length,
//     and a value shared between !unsafe and normal YAML (yamlTrust). When the
//     whole value is exactly one bare {{ name }} (whitespace control allowed,
//     no attribute, filter or text around it) varName is that variable, so a
//     caller that knows the run's variables can decide it (RosterRunVars).
//
// A document that does not parse is Unknown.
func RosterFreeIPAServerDeclared(plaintext []byte) (fact RosterFact, varName string) {
	doc, err := parseYAMLDocument(plaintext)
	if err != nil {
		return RosterFactUnknown, ""
	}
	freeipa, _ := mappingValue(documentRoot(doc), "freeipa")
	server, _ := mappingValue(freeipa, "server")
	if server == nil {
		return RosterFactNo, ""
	}
	if server.Kind != yaml.ScalarNode {
		return RosterFactYes, ""
	}
	if server.ShortTag() == "!!null" {
		return RosterFactYes, ""
	}
	switch ansibleScalarKind(server, newYAMLTrust(doc)) {
	case scalarAbsent:
		return RosterFactNo, "" // an empty string
	case scalarLiteral:
		if pyStrip(server.Value) == "" {
			return RosterFactNo, ""
		}
		return RosterFactYes, ""
	case scalarNotString:
		return RosterFactYes, ""
	case scalarTemplate:
		return RosterFactUnknown, bareTemplateName(server.Value)
	}
	return RosterFactUnknown, "" // inline !vault, shared between !unsafe and normal YAML
}

// bareVarTag is a string that is exactly one {{ name }} and nothing else.
var bareVarTag = regexp.MustCompile(`^\{\{-?[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*-?\}\}$`)

// bareTemplateName is the variable of s when s is exactly one bare
// {{ name }} — Ansible then renders it to the variable's own value — and ""
// otherwise (text around it, an attribute, a filter, anything else).
func bareTemplateName(s string) string {
	m := bareVarTag.FindStringSubmatch(s)
	if m == nil || jinjaWords[m[1]] {
		return ""
	}
	return m[1]
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
