package inventory

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// The FreeIPA admin password lives in two files on purpose: the vault's
// ipa_admin_password, which `pilot deploy`/`pilot reconcile` load, and the
// canonical roster's freeipa.admin.password, the only credential that
// `pilot access`, `pilot identity drift` and `pilot roster remove-*` pass
// to their playbooks (issue #146). The helpers below keep the second in
// step with the first instead of letting a rotation leave it stale.

// RosterAdminSync is what SyncRosterAdminPassword (or
// CompareRosterAdminPassword) found in one roster. The zero value is not a
// result.
type RosterAdminSync int

const (
	// RosterAdminUpdated: the roster held the old password and now holds
	// the new one.
	RosterAdminUpdated RosterAdminSync = iota + 1
	// RosterAdminCurrent: the roster already held the new password.
	RosterAdminCurrent
	// RosterAdminDiffers: the roster held neither password and was left
	// alone; only the operator knows which one it should carry.
	RosterAdminDiffers
	// RosterAdminNotLiteral: there is no literal password to keep in step —
	// the field is absent, empty, null or a template such as
	// "{{ ipa_admin_password }}".
	RosterAdminNotLiteral
	// RosterAdminNotString: the password is written so a YAML loader may
	// read it as something other than a string — a number, date or boolean
	// (scalarNotString) — and a typed comparison with the vault's
	// string password would then fail: the operator must quote it. pilot
	// reports it, never judges it current and never rewrites it.
	RosterAdminNotString
)

// VaultAdminPassword returns a plaintext vault vars file's
// ipa_admin_password when it is a literal password (scalarLiteral: a
// string Ansible uses as written, !unsafe included), "" when data is
// encrypted or unparseable or the value is anything else — an inline
// !vault value, a template, a value a YAML loader may read as a number or
// date, or none.
func VaultAdminPassword(data []byte) string {
	value := vaultAdminValue(data)
	if ansibleScalarKind(value) != scalarLiteral {
		return ""
	}
	return value.Value
}

// VaultAdminPasswordReusable is VaultAdminPassword when the value can also
// be written into a new roster as a plain quoted string — no Jinja
// delimiter, which only !unsafe keeps literal — and "" otherwise; the
// NFS bootstrap then asks for the password instead.
func VaultAdminPasswordReusable(data []byte) string {
	if password := VaultAdminPassword(data); !jinjaDelimited(password) {
		return password
	}
	return ""
}

// VaultAdminPasswordNotString reports whether a plaintext vault vars
// file's ipa_admin_password is written so a YAML loader may read it as
// something other than a string (scalarNotString): pilot can then neither
// compare it with a roster nor carry it into one, and says to quote it.
func VaultAdminPasswordNotString(data []byte) bool {
	return ansibleScalarKind(vaultAdminValue(data)) == scalarNotString
}

// VaultAdminPasswordText is a plaintext vault vars file's
// ipa_admin_password as written, whatever it may be read as, "" when data
// is encrypted or has none: for telling whether a save changed it, never
// for showing — it may be a password.
func VaultAdminPasswordText(data []byte) string {
	if value := vaultAdminValue(data); value != nil && value.Kind == yaml.ScalarNode {
		return value.Value
	}
	return ""
}

func vaultAdminValue(data []byte) *yaml.Node {
	if strings.HasPrefix(strings.TrimSpace(string(data)), "$ANSIBLE_VAULT") {
		return nil
	}
	var doc yaml.Node
	if yaml.Unmarshal(data, &doc) != nil {
		return nil
	}
	value, _ := mappingValue(documentRoot(&doc), "ipa_admin_password")
	return value
}

// VaultAdminPasswordTemplate returns a plaintext vault vars file's
// ipa_admin_password when it is a string holding a Jinja delimiter ({{, {%
// or {#), "" otherwise. Ansible templates such a value, so pilot cannot
// tell which password it resolves to, nor keep a roster in step with it.
// The value may be a password: callers compare it and never show it.
func VaultAdminPasswordTemplate(data []byte) string {
	value := vaultAdminValue(data)
	if ansibleScalarKind(value) != scalarTemplate {
		return ""
	}
	return value.Value
}

// RosterAdminPasswordDiffers reports whether the plaintext roster at path
// stores a freeipa.admin.password, wherever YAML aliases or merge keys put
// it, that Ansible would not find equal to the vault's string
// vaultPassword: another literal string, or a number or boolean
// (RosterAdminNotString). A roster without a literal password, an inline
// !vault one included, never differs; an encrypted file returns
// ErrRosterEncrypted.
func RosterAdminPasswordDiffers(path, vaultPassword string) (bool, error) {
	result, err := CompareRosterAdminPassword(path, vaultPassword)
	return result == RosterAdminDiffers || result == RosterAdminNotString, err
}

// CompareRosterAdminPassword is what the plaintext roster at path holds
// against the vault's string vaultPassword, the way Ansible compares them
// (freeipa-nfs-server-apply.yml's drift gate): RosterAdminCurrent,
// RosterAdminDiffers, RosterAdminNotString or RosterAdminNotLiteral. An
// encrypted file returns ErrRosterEncrypted.
func CompareRosterAdminPassword(path, vaultPassword string) (RosterAdminSync, error) {
	_, doc, err := readRosterNode(path)
	if err != nil {
		return 0, err
	}
	_, value, _ := rosterAdminPassword(doc)
	switch ansibleScalarKind(value) {
	case scalarNotString:
		return RosterAdminNotString, nil
	case scalarLiteral:
		if value.Value == vaultPassword {
			return RosterAdminCurrent, nil
		}
		return RosterAdminDiffers, nil
	}
	return RosterAdminNotLiteral, nil
}

// SyncRosterAdminPassword replaces the plaintext roster's literal
// freeipa.admin.password with newPassword when it still holds
// oldPassword: PrepareRosterAdminSync, then Commit. Only that one scalar
// is rewritten; every other byte of the file, comments included, is kept.
// A symlinked roster is updated where it points, through writeLockedRoster.
// It never writes a roster that is encrypted, inline !vault included
// (ErrRosterEncrypted), held by another roster writer (ErrMutationLocked),
// or whose password it cannot rewrite on one line by itself (an alias, a
// merge key, a flow mapping, a block or multi-line scalar): those return
// an error asking for a manual update.
func SyncRosterAdminPassword(path, oldPassword, newPassword string) (RosterAdminSync, error) {
	prepared, err := PrepareRosterAdminSync(path, oldPassword, newPassword)
	if err != nil {
		return 0, err
	}
	if err := prepared.Commit(); err != nil {
		return 0, err
	}
	return prepared.Result, nil
}

// PreparedRosterAdminSync is one roster's admin password change, decided
// on a read under the roster's lock when it would write, and holding that
// lock until Commit writes it or Release drops it. A caller that must
// change several files together — pilot edit's vault save, which writes
// the vault only once every roster it must follow can follow — prepares
// all of them first.
type PreparedRosterAdminSync struct {
	// Result is what the sync found: RosterAdminUpdated when Commit will
	// write the roster.
	Result  RosterAdminSync
	lk      *rosterLock
	updated []byte
}

// PrepareRosterAdminSync decides SyncRosterAdminPassword's change to the
// roster at path. A first look without the lock keeps a roster that will
// not change free of lock files; it decides nothing. A roster that will
// change — or that read empty, a writer caught between truncating and
// writing it — is locked and decided again on a fresh read, and stays
// locked: the caller must Commit or Release it. Errors are
// SyncRosterAdminPassword's, ErrMutationLocked and ErrRosterLockFile
// among them, and leave nothing locked.
func PrepareRosterAdminSync(path, oldPassword, newPassword string) (*PreparedRosterAdminSync, error) {
	result, _, err := planRosterAdminSync(path, oldPassword, newPassword)
	emptyRead := err == nil && result == RosterAdminNotLiteral && rosterFileEmpty(path)
	if err != nil || (result != RosterAdminUpdated && !emptyRead) {
		return &PreparedRosterAdminSync{Result: result}, err
	}
	lk, err := lockRosterFile(path)
	if err != nil {
		return nil, err
	}
	result, updated, err := planRosterAdminSync(lk.target, oldPassword, newPassword)
	if err != nil || result != RosterAdminUpdated {
		lk.release() //nolint:errcheck
		return &PreparedRosterAdminSync{Result: result}, err
	}
	return &PreparedRosterAdminSync{Result: RosterAdminUpdated, lk: lk, updated: updated}, nil
}

// Commit writes the prepared change, if any, and releases the lock.
func (p *PreparedRosterAdminSync) Commit() error {
	if p.lk == nil {
		return nil
	}
	defer p.Release()
	return writeLockedRoster(p.lk, p.updated)
}

// Release drops the lock without writing. Safe to call more than once,
// and after Commit.
func (p *PreparedRosterAdminSync) Release() {
	if p.lk != nil {
		p.lk.release() //nolint:errcheck
		p.lk = nil
	}
}

// rosterFileEmpty reports whether the roster at path reads as nothing but
// whitespace.
func rosterFileEmpty(path string) bool {
	data, err := readSecretSourceFile(path)
	return err == nil && len(bytes.TrimSpace(data)) == 0
}

// planRosterAdminSync decides what SyncRosterAdminPassword does to the roster
// as it is on disk now and, for RosterAdminUpdated, returns its new bytes.
func planRosterAdminSync(path, oldPassword, newPassword string) (RosterAdminSync, []byte, error) {
	data, doc, err := readRosterNode(path)
	if err != nil {
		return 0, nil, err
	}
	mapping, value, direct := rosterAdminPassword(doc)
	kind := ansibleScalarKind(value)
	if kind == scalarEncrypted {
		return 0, nil, fmt.Errorf("roster %s: freeipa.admin.password is an inline !vault value: %w", path, ErrRosterEncrypted)
	}
	// !unsafe keeps a password literal for Ansible: kept when the roster's
	// had it, and needed when the new password holds a Jinja delimiter
	// (only a vault's !unsafe value can), so Ansible does not template it.
	unsafe := value != nil && value.ShortTag() == "!unsafe" || jinjaDelimited(newPassword)
	switch {
	case kind == scalarNotString:
		return RosterAdminNotString, nil, nil
	case kind != scalarLiteral:
		return RosterAdminNotLiteral, nil, nil
	case value.Value == newPassword:
		return RosterAdminCurrent, nil, nil
	case value.Value != oldPassword:
		return RosterAdminDiffers, nil, nil
	case !direct:
		return 0, nil, fmt.Errorf("roster %s: freeipa.admin.password comes from a YAML alias or merge key; update it by hand", path)
	case mapping.Style&yaml.FlowStyle != 0 || value.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0:
		return 0, nil, fmt.Errorf("roster %s: freeipa.admin.password is not a one-line block-mapping value; update it by hand", path)
	}
	updated, err := replaceScalar(data, value, newPassword, unsafe)
	if err != nil {
		return 0, nil, fmt.Errorf("roster %s: %w; update freeipa.admin.password by hand", path, err)
	}
	if err := sameRosterExceptAdminPassword(data, updated, newPassword); err != nil {
		return 0, nil, fmt.Errorf("roster %s: %w; update freeipa.admin.password by hand", path, err)
	}
	return RosterAdminUpdated, updated, nil
}

func readRosterNode(path string) ([]byte, *yaml.Node, error) {
	data, err := readSecretSourceFile(path)
	if err != nil {
		return nil, nil, err
	}
	if strings.HasPrefix(strings.TrimSpace(string(data)), "$ANSIBLE_VAULT") {
		return nil, nil, ErrRosterEncrypted
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("parse roster %s: %w", path, err)
	}
	return data, &doc, nil
}

func documentRoot(doc *yaml.Node) *yaml.Node {
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		return doc.Content[0]
	}
	return doc
}

// rosterAdminPassword returns the freeipa.admin mapping and the value YAML
// gives its password, following aliases and merge keys; direct is true
// only when every step of that path is written out where it is used, so
// the password scalar can be rewritten in place.
func rosterAdminPassword(doc *yaml.Node) (mapping, value *yaml.Node, direct bool) {
	node, direct := documentRoot(doc), true
	for _, key := range []string{"freeipa", "admin"} {
		next, here := mappingValue(node, key)
		if next == nil {
			return nil, nil, false
		}
		node, direct = next, direct && here
	}
	value, here := mappingValue(node, "password")
	return node, value, direct && here
}

// mappingValue returns key's value in mapping as YAML resolves it: the last
// explicit key wins, then the mappings merged in with <<, in order. here
// is false when the value is an alias or comes from a merge.
func mappingValue(mapping *yaml.Node, key string) (value *yaml.Node, here bool) {
	mapping = resolveAlias(mapping)
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil, false
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if k := mapping.Content[i]; k.Value == key && k.ShortTag() != "!!merge" {
			value = mapping.Content[i+1]
		}
	}
	if value != nil {
		return resolveAlias(value), value.Kind != yaml.AliasNode
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].ShortTag() != "!!merge" {
			continue
		}
		sources := []*yaml.Node{resolveAlias(mapping.Content[i+1])}
		if sources[0] != nil && sources[0].Kind == yaml.SequenceNode {
			sources = sources[0].Content
		}
		for _, source := range sources {
			if merged, _ := mappingValue(source, key); merged != nil {
				return merged, false
			}
		}
	}
	return nil, false
}

func resolveAlias(node *yaml.Node) *yaml.Node {
	for node != nil && node.Kind == yaml.AliasNode {
		node = node.Alias
	}
	return node
}

// scalarKind is how Ansible reads a password scalar (ansibleScalarKind).
type scalarKind int

const (
	// scalarAbsent: no password — missing, null or empty.
	scalarAbsent scalarKind = iota
	// scalarLiteral: a string Ansible uses as written — quoted, tagged
	// !!str, plain and read as a string by YAML 1.1 and 1.2 alike, or
	// tagged !unsafe (never templated, whatever it holds).
	scalarLiteral
	// scalarTemplate: a string holding a Jinja delimiter, which Ansible
	// templates.
	scalarTemplate
	// scalarNotString: a value a YAML loader may read as something other
	// than a string — an unquoted number, date or boolean, or a non-string
	// tag — which a typed comparison never finds equal to a string password.
	scalarNotString
	// scalarEncrypted: an inline !vault value.
	scalarEncrypted
)

// ansibleScalarKind classifies a password value the one way every vault-
// and roster-side check here judges it. YAML 1.2 (yaml.v3's tags) and YAML
// 1.1 (yaml11NonString, the resolver Ansible loads vars files with)
// disagree on unquoted scalars such as 012345678, 1e10, 190:20:30 and yes,
// so an unquoted value either may read as a non-string is
// scalarNotString: quoting it settles both.
func ansibleScalarKind(value *yaml.Node) scalarKind {
	if value == nil {
		return scalarAbsent
	}
	if value.Kind != yaml.ScalarNode {
		return scalarNotString
	}
	quoted := value.Style&(yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) != 0
	switch tag := value.ShortTag(); {
	case tag == "!vault":
		return scalarEncrypted
	case tag == "!unsafe":
		if value.Value == "" {
			return scalarAbsent
		}
		return scalarLiteral
	case tag == "!!null":
		return scalarAbsent
	case tag != "!!str":
		return scalarNotString
	case value.Value == "":
		return scalarAbsent
	case !quoted && value.Style&yaml.TaggedStyle == 0 && yaml11NonString.MatchString(value.Value):
		return scalarNotString
	case jinjaDelimited(value.Value):
		return scalarTemplate
	}
	return scalarLiteral
}

// yaml11NonString matches the plain scalars PyYAML's YAML 1.1 implicit
// resolvers (yaml/resolver.py) — what Ansible loads vars files with — read
// as something other than a string: booleans, null, ints (0-prefixed
// octal, base 60), floats (base 60, .inf, .nan), timestamps, and the merge
// and value indicators. TestYAML11NonStringMatchesAnsible checks it
// against the real loader.
var yaml11NonString = regexp.MustCompile(`^(?:` +
	`yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF` +
	`|~|null|Null|NULL|` +
	`|[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+` +
	`|[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN)` +
	`|[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]` +
	`|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?` +
	`|<<|=` +
	`)$`)

func jinjaDelimited(s string) bool {
	return strings.Contains(s, "{{") || strings.Contains(s, "{%") || strings.Contains(s, "{#")
}

// replaceScalar rewrites the one line holding node so it carries value as
// a double-quoted scalar — tagged !unsafe when unsafe — keeping the text
// before it and its line comment. node's column is where its tag, if any,
// begins, so an old tag is replaced along with the value.
func replaceScalar(data []byte, node *yaml.Node, value string, unsafe bool) ([]byte, error) {
	encoded, err := yaml.Marshal(&yaml.Node{Kind: yaml.ScalarNode, Style: yaml.DoubleQuotedStyle, Value: value})
	if err != nil {
		return nil, err
	}
	scalar := strings.TrimSuffix(string(encoded), "\n")
	if unsafe {
		scalar = "!unsafe " + scalar
	}
	if strings.Contains(scalar, "\n") {
		return nil, errors.New("the new password does not fit on one line")
	}
	lines := bytes.SplitAfter(data, []byte("\n"))
	i := node.Line - 1
	if i < 0 || i >= len(lines) {
		return nil, errors.New("freeipa.admin.password is outside the file")
	}
	line := string(lines[i])
	eol := line[len(strings.TrimRight(line, "\r\n")):]
	// yaml.v3 counts columns in characters, not bytes.
	runes := []rune(strings.TrimSuffix(line, eol))
	col := node.Column - 1
	if col < 0 || col > len(runes) {
		return nil, errors.New("freeipa.admin.password is outside its line")
	}
	// Keep whatever followed the old scalar: the spacing and the comment.
	rest := string(runes[col:])
	tail := rest[len(strings.TrimRight(rest, " \t")):]
	if node.LineComment != "" {
		at := strings.LastIndex(rest, node.LineComment)
		if at < 0 {
			return nil, errors.New("cannot find the comment after freeipa.admin.password")
		}
		tail = rest[len(strings.TrimRight(rest[:at], " \t")):]
	}
	lines[i] = []byte(string(runes[:col]) + scalar + tail + eol)
	return bytes.Join(lines, nil), nil
}

// sameRosterExceptAdminPassword proves the rewrite changed nothing but
// freeipa.admin.password, which must now be password.
func sameRosterExceptAdminPassword(before, after []byte, password string) error {
	var want, got any
	if err := yaml.Unmarshal(before, &want); err != nil {
		return err
	}
	if err := yaml.Unmarshal(after, &got); err != nil {
		return fmt.Errorf("rewritten roster does not parse: %w", err)
	}
	root, _ := want.(map[string]any)
	freeipa, _ := root["freeipa"].(map[string]any)
	admin, _ := freeipa["admin"].(map[string]any)
	if admin == nil {
		return errors.New("freeipa.admin is not a mapping")
	}
	admin["password"] = password
	if !reflect.DeepEqual(want, got) {
		return errors.New("rewriting freeipa.admin.password in place would change other roster content")
	}
	return nil
}
