package inventory

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"

	"go.yaml.in/yaml/v3"
)

// The FreeIPA admin password lives in two files on purpose: the vault's
// ipa_admin_password, which `pilot deploy`/`pilot reconcile` load, and the
// canonical roster's freeipa.admin.password, the only credential that
// `pilot access`, `pilot identity drift` and `pilot roster remove-*` pass
// to their playbooks (issue #146). The helpers below keep the second in
// step with the first instead of letting a rotation leave it stale.

// RosterAdminSync is what SyncRosterAdminPassword found in one roster. The
// zero value is not a result.
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
	// the field is absent, empty, not a string or a template such as
	// "{{ ipa_admin_password }}".
	RosterAdminNotLiteral
)

// VaultAdminPassword returns a plaintext vault vars file's
// ipa_admin_password, or "" when data is encrypted, unparseable, or holds
// no plain string for that key (an inline !vault value, a template, a
// number...).
func VaultAdminPassword(data []byte) string {
	if strings.HasPrefix(strings.TrimSpace(string(data)), "$ANSIBLE_VAULT") {
		return ""
	}
	var doc yaml.Node
	if yaml.Unmarshal(data, &doc) != nil {
		return ""
	}
	value, _ := mappingValue(documentRoot(&doc), "ipa_admin_password")
	if !literalAdminPassword(value) || value.ShortTag() != "!!str" {
		return ""
	}
	return value.Value
}

// VaultAdminPasswordTemplate returns a plaintext vault vars file's
// ipa_admin_password when it is a string holding a Jinja delimiter ({{, {%
// or {#), "" otherwise. Ansible templates such a value, so pilot cannot
// tell which password it resolves to, nor keep a roster in step with it.
// The value may be a password: callers compare it and never show it.
func VaultAdminPasswordTemplate(data []byte) string {
	if strings.HasPrefix(strings.TrimSpace(string(data)), "$ANSIBLE_VAULT") {
		return ""
	}
	var doc yaml.Node
	if yaml.Unmarshal(data, &doc) != nil {
		return ""
	}
	value, _ := mappingValue(documentRoot(&doc), "ipa_admin_password")
	if value == nil || value.Kind != yaml.ScalarNode || value.ShortTag() != "!!str" || !jinjaDelimited(value.Value) {
		return ""
	}
	return value.Value
}

// RosterAdminPasswordDiffers reports whether the plaintext roster at path
// stores a literal freeipa.admin.password, wherever YAML aliases or merge
// keys put it, other than vaultPassword. A roster without a literal
// password, an inline !vault one included, never differs; an encrypted
// file returns ErrRosterEncrypted.
func RosterAdminPasswordDiffers(path, vaultPassword string) (bool, error) {
	_, doc, err := readRosterNode(path)
	if err != nil {
		return false, err
	}
	_, value, _ := rosterAdminPassword(doc)
	if !literalAdminPassword(value) {
		return false, nil
	}
	return value.Value != vaultPassword, nil
}

// SyncRosterAdminPassword replaces the plaintext roster's literal
// freeipa.admin.password with newPassword when it still holds
// oldPassword. Only that one scalar is rewritten; every other byte of the
// file, comments included, is kept. A symlinked roster is updated where it
// points, and the file is replaced atomically with its mode and, where the
// process may set it, its owner. It never writes a roster that is
// encrypted, inline !vault included (ErrRosterEncrypted), held by another
// roster writer (ErrMutationLocked), or whose password it cannot rewrite
// on one line by itself (an alias, a merge key, a flow mapping, a block or
// multi-line scalar, a new password Ansible would template): those return
// an error asking for a manual update.
func SyncRosterAdminPassword(path, oldPassword, newPassword string) (RosterAdminSync, error) {
	// A first look without the lock, so a roster that will not change gets
	// no lock files. It decides nothing: the plan below does, on a fresh
	// read under the lock.
	result, _, err := planRosterAdminSync(path, oldPassword, newPassword)
	if err != nil || result != RosterAdminUpdated {
		return result, err
	}
	lk, err := lockRosterFile(path)
	if err != nil {
		return 0, err
	}
	defer lk.release() //nolint:errcheck
	result, updated, err := planRosterAdminSync(lk.target, oldPassword, newPassword)
	if err != nil || result != RosterAdminUpdated {
		return result, err
	}
	info, err := os.Stat(lk.target)
	if err != nil {
		return 0, err
	}
	if err := atomicReplaceFile(lk.target, updated, info.Mode().Perm()); err != nil {
		return 0, fmt.Errorf("write roster %s: %w", path, err)
	}
	keepOwner(lk.target, info)
	return RosterAdminUpdated, nil
}

// planRosterAdminSync decides what SyncRosterAdminPassword does to the roster
// as it is on disk now and, for RosterAdminUpdated, returns its new bytes.
func planRosterAdminSync(path, oldPassword, newPassword string) (RosterAdminSync, []byte, error) {
	data, doc, err := readRosterNode(path)
	if err != nil {
		return 0, nil, err
	}
	mapping, value, direct := rosterAdminPassword(doc)
	if value != nil && value.ShortTag() == "!vault" {
		return 0, nil, fmt.Errorf("roster %s: freeipa.admin.password is an inline !vault value: %w", path, ErrRosterEncrypted)
	}
	switch {
	case !literalAdminPassword(value):
		return RosterAdminNotLiteral, nil, nil
	case value.Value == newPassword:
		return RosterAdminCurrent, nil, nil
	case value.Value != oldPassword:
		return RosterAdminDiffers, nil, nil
	case !direct:
		return 0, nil, fmt.Errorf("roster %s: freeipa.admin.password comes from a YAML alias or merge key; update it by hand", path)
	case jinjaDelimited(newPassword):
		return 0, nil, fmt.Errorf("roster %s: the new password contains a Jinja delimiter ({{, {%% or {#) that Ansible would template; update freeipa.admin.password by hand", path)
	case mapping.Style&yaml.FlowStyle != 0 || value.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0:
		return 0, nil, fmt.Errorf("roster %s: freeipa.admin.password is not a one-line block-mapping value; update it by hand", path)
	}
	updated, err := replaceScalar(data, value, newPassword)
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

// literalAdminPassword reports whether value is a password Ansible reads as
// written: a non-empty plain scalar that is no template.
func literalAdminPassword(value *yaml.Node) bool {
	if value == nil || value.Kind != yaml.ScalarNode || value.Value == "" || jinjaDelimited(value.Value) {
		return false
	}
	switch value.ShortTag() {
	case "!!str", "!!int", "!!float":
		return true
	}
	return false
}

func jinjaDelimited(s string) bool {
	return strings.Contains(s, "{{") || strings.Contains(s, "{%") || strings.Contains(s, "{#")
}

// replaceScalar rewrites the one line holding node so it carries value as
// a double-quoted scalar, keeping the text before it and its line comment.
func replaceScalar(data []byte, node *yaml.Node, value string) ([]byte, error) {
	encoded, err := yaml.Marshal(&yaml.Node{Kind: yaml.ScalarNode, Style: yaml.DoubleQuotedStyle, Value: value})
	if err != nil {
		return nil, err
	}
	scalar := strings.TrimSuffix(string(encoded), "\n")
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
