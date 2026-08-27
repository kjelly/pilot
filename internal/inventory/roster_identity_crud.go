// roster_identity_crud.go provides the same generic
// list/append/simulate-set/set primitives roster.go already has for
// hostgroups/grants/HBAC rules (RosterHostgroup/AppendRosterHostgroup/
// SimulateSetRosterHostgroup/SetRosterHostgroup), for the v3.2 top-level
// lists TUI screens and structured actions (§17/§18) need to drive:
// password_policies and credential_policies.
package inventory

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
