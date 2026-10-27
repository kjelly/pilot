package inventory

import (
	"bytes"
	"errors"
	"fmt"
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

// RosterAdminSync is what SyncRosterAdminPassword found in one roster.
type RosterAdminSync int

const (
	// RosterAdminUpdated: the roster held the old password and now holds
	// the new one.
	RosterAdminUpdated RosterAdminSync = iota
	// RosterAdminCurrent: the roster already held the new password.
	RosterAdminCurrent
	// RosterAdminDiffers: the roster held neither password and was left
	// alone; only the operator knows which one it should carry.
	RosterAdminDiffers
	// RosterAdminNotLiteral: there is no literal password to keep in step —
	// the field is absent, empty or a template such as
	// "{{ ipa_admin_password }}".
	RosterAdminNotLiteral
)

// VaultAdminPassword returns a plaintext vault vars file's
// ipa_admin_password, or "" when data is encrypted, unparseable or has no
// string value for that key.
func VaultAdminPassword(data []byte) string {
	if strings.HasPrefix(strings.TrimSpace(string(data)), "$ANSIBLE_VAULT") {
		return ""
	}
	var vars map[string]any
	if yaml.Unmarshal(data, &vars) != nil {
		return ""
	}
	password, _ := vars["ipa_admin_password"].(string)
	return password
}

// RosterAdminPasswordDiffers reports whether the plaintext roster at path
// stores a literal freeipa.admin.password other than vaultPassword. A
// roster without a literal password never differs; an encrypted one
// returns ErrRosterEncrypted.
func RosterAdminPasswordDiffers(path, vaultPassword string) (bool, error) {
	_, doc, err := readRosterNode(path)
	if err != nil {
		return false, err
	}
	_, value := rosterAdminPasswordNode(doc)
	if !literalAdminPassword(value) {
		return false, nil
	}
	return value.Value != vaultPassword, nil
}

// SyncRosterAdminPassword replaces the plaintext roster's literal
// freeipa.admin.password with newPassword when it still holds
// oldPassword. Only that one scalar is rewritten; every other byte of the
// file, comments included, is kept. A layout it cannot rewrite in place (a
// flow mapping, a block or multi-line scalar) is an error and the file is
// left untouched, as is an encrypted roster (ErrRosterEncrypted).
func SyncRosterAdminPassword(path, oldPassword, newPassword string) (RosterAdminSync, error) {
	data, doc, err := readRosterNode(path)
	if err != nil {
		return 0, err
	}
	mapping, value := rosterAdminPasswordNode(doc)
	switch {
	case !literalAdminPassword(value):
		return RosterAdminNotLiteral, nil
	case value.Value == newPassword:
		return RosterAdminCurrent, nil
	case value.Value != oldPassword:
		return RosterAdminDiffers, nil
	}
	if mapping.Style&yaml.FlowStyle != 0 || value.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return 0, fmt.Errorf("roster %s: freeipa.admin.password is not a one-line block-mapping value; update it by hand", path)
	}
	updated, err := replaceScalar(data, value, newPassword)
	if err != nil {
		return 0, fmt.Errorf("roster %s: %w; update freeipa.admin.password by hand", path, err)
	}
	if err := sameRosterExceptAdminPassword(data, updated, newPassword); err != nil {
		return 0, fmt.Errorf("roster %s: %w; update freeipa.admin.password by hand", path, err)
	}
	if err := writeSecretSourceFile(path, updated, 0o600); err != nil {
		return 0, fmt.Errorf("write roster %s: %w", path, err)
	}
	return RosterAdminUpdated, nil
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

// rosterAdminPasswordNode returns the mapping holding freeipa.admin.password
// and its value node, or nils when the roster has no such field. A repeated
// key resolves to its last occurrence, as it does for Ansible.
func rosterAdminPasswordNode(doc *yaml.Node) (mapping, value *yaml.Node) {
	node := doc
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		node = node.Content[0]
	}
	for _, key := range []string{"freeipa", "admin", "password"} {
		if node.Kind != yaml.MappingNode {
			return nil, nil
		}
		var next *yaml.Node
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == key {
				next = node.Content[i+1]
			}
		}
		if next == nil {
			return nil, nil
		}
		if key == "password" {
			return node, next
		}
		node = next
	}
	return nil, nil
}

func literalAdminPassword(value *yaml.Node) bool {
	return value != nil && value.Kind == yaml.ScalarNode && value.Tag != "!!null" &&
		value.Value != "" && !strings.Contains(value.Value, "{{")
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
