// roster_identity_crud.go provides the same generic
// list/append/simulate-set/set primitives roster.go already has for
// hostgroups/grants/HBAC rules (RosterHostgroup/AppendRosterHostgroup/
// SimulateSetRosterHostgroup/SetRosterHostgroup), for the v3.2 top-level
// lists TUI screens and structured actions (§17/§18) need to drive:
// password_policies and credential_policies. RosterPrivilegedIdentity/Set
// at the bottom of this file cover security.privileged_identity — a
// singleton, not a list, since spec.md §9 declares at most one baseline
// per roster, so it needs its own (non-list-indexed) yaml.Node surgery
// rather than reusing appendTopLevelRosterEntry/replaceTopLevelRosterEntry.
package inventory

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// RosterPasswordPolicyNames returns password_policies[] names in file
// order.
func RosterPasswordPolicyNames(path string) ([]string, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	return namesOf(listField(root, "password_policies")), nil
}

// RosterPasswordPolicy returns one password_policies[] entry.
// found=false when no such policy exists.
func RosterPasswordPolicy(path, name string) (map[string]any, bool, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, false, err
	}
	entries := listField(root, "password_policies")
	idx, _ := findNamedEntry(entries, name)
	if idx < 0 {
		return nil, false, nil
	}
	return asMap(entries[idx]), true, nil
}

// AppendRosterPasswordPolicy appends a minimal password_policies[] stub —
// group/priority are left for the caller to fill in via
// SetRosterPasswordPolicy, since neither has a safe default (§7: this
// schema has no way to express "the global default policy", so group
// must always be explicit).
func AppendRosterPasswordPolicy(path, name string) error {
	return appendTopLevelRosterEntry(path, "password_policies", map[string]any{
		"name": name, "state": "present",
	})
}

// SimulateSetRosterPasswordPolicy reports what validating the roster at
// path would say if the named password_policies[] entry were replaced by
// updated, without writing anything.
func SimulateSetRosterPasswordPolicy(path, name string, updated map[string]any) ([]RosterViolation, bool, error) {
	return simulateSetRosterNested(path, "password_policies", name, updated, "password_policy")
}

// SetRosterPasswordPolicy replaces the named password_policies[] entry
// with updated. Callers should run SimulateSetRosterPasswordPolicy first.
func SetRosterPasswordPolicy(path, name string, updated map[string]any) error {
	return replaceTopLevelRosterEntry(path, "password_policies", name, updated)
}

// RosterCredentialPolicyNames returns credential_policies[] names in file
// order.
func RosterCredentialPolicyNames(path string) ([]string, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	return namesOf(listField(root, "credential_policies")), nil
}

// AppendRosterCredentialPolicy appends a minimal credential_policies[]
// stub — match is left empty for the caller to fill in (§10 requires at
// least one match.users/match.groups entry, which has no safe default).
func AppendRosterCredentialPolicy(path, name string) error {
	return appendTopLevelRosterEntry(path, "credential_policies", map[string]any{
		"name": name, "state": "present",
	})
}

// SimulateSetRosterCredentialPolicy reports what validating the roster at
// path would say if the named credential_policies[] entry were replaced
// by updated, without writing anything.
func SimulateSetRosterCredentialPolicy(path, name string, updated map[string]any) ([]RosterViolation, bool, error) {
	return simulateSetRosterNested(path, "credential_policies", name, updated, "credential_policy")
}

// SetRosterCredentialPolicy replaces the named credential_policies[]
// entry with updated. Callers should run SimulateSetRosterCredentialPolicy
// first.
func SetRosterCredentialPolicy(path, name string, updated map[string]any) error {
	return replaceTopLevelRosterEntry(path, "credential_policies", name, updated)
}

// RosterPrivilegedIdentity returns security.privileged_identity.
// found=false when the roster declares none — spec.md §9's baseline is
// entirely opt-in.
func RosterPrivilegedIdentity(path string) (fields map[string]any, found bool, err error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, false, err
	}
	security := mapField(root, "security")
	raw, has := security["privileged_identity"]
	if !has {
		return nil, false, nil
	}
	return asMap(raw), true, nil
}

// SimulateSetRosterPrivilegedIdentity reports what validating the roster
// at path would say if security.privileged_identity were replaced by
// updated, without writing anything.
func SimulateSetRosterPrivilegedIdentity(path string, updated map[string]any) ([]RosterViolation, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	securityClone := map[string]any{}
	for k, v := range mapField(root, "security") {
		securityClone[k] = v
	}
	securityClone["privileged_identity"] = updated
	root["security"] = securityClone
	return ValidateRoster(root), nil
}

// SetRosterPrivilegedIdentity replaces security.privileged_identity with
// updated via yaml.Node surgery — creating the security: mapping (and,
// within it, the privileged_identity: mapping) if the roster has never
// had either. Callers should run SimulateSetRosterPrivilegedIdentity
// first — this function does not validate anything itself.
func SetRosterPrivilegedIdentity(path string, updated map[string]any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if strings.HasPrefix(strings.TrimSpace(string(data)), "$ANSIBLE_VAULT") {
		return ErrRosterEncrypted
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("parse roster %s: %w", path, err)
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("roster %s: expected a top-level YAML mapping", path)
	}
	top := root.Content[0]
	securityNode := mappingChild(top, "security", yaml.MappingNode, "!!map")
	piNode := mappingChild(securityNode, "privileged_identity", yaml.MappingNode, "!!map")
	if err := piNode.Encode(updated); err != nil {
		return fmt.Errorf("encode roster security.privileged_identity: %w", err)
	}

	rendered, err := yaml.Marshal(&root)
	if err != nil {
		return fmt.Errorf("render roster %s: %w", path, err)
	}
	return os.WriteFile(path, rendered, 0o600)
}
