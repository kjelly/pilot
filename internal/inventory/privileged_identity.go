// privileged_identity.go validates and evaluates the v3.2 Identity &
// Credential Hardening spec's (spec.md §9, Phase 3)
// `security.privileged_identity:` block: a single organization-wide
// baseline (unlike password_policies/auth_policies, this is not a list —
// one roster declares one baseline) naming which groups make a user
// "privileged" and what strong-authentication floor every privileged user
// must meet.
package inventory

import (
	"fmt"
	"sort"
	"strings"
)

var (
	knownPrivilegedIdentityKeys        = []string{"match_groups", "require"}
	knownPrivilegedIdentityRequireKeys = []string{"auth_types", "no_password_only", "ssh_key_policy"}
)

// checkPrivilegedIdentity validates security.privileged_identity per
// spec.md §9. Absent entirely is not an error — the baseline is opt-in.
func checkPrivilegedIdentity(root map[string]any) []RosterViolation {
	security := mapField(root, "security")
	if _, has := security["privileged_identity"]; !has {
		return nil
	}
	var out []RosterViolation
	pi := mapField(security, "privileged_identity")
	if unk := unknownKeys(pi, knownPrivilegedIdentityKeys); len(unk) > 0 {
		out = append(out, RosterViolation{Rule: "privileged_identity keys", Detail: fmt.Sprintf("unknown privileged_identity field(s) %s", strings.Join(unk, ", "))})
	}

	groupNames := namesOf(listField(root, "groups"))
	matchGroups := stringListField(pi, "match_groups")
	if len(matchGroups) == 0 {
		out = append(out, RosterViolation{Rule: "privileged_identity match_groups", Detail: "privileged_identity.match_groups needs at least one group"})
	}
	for _, g := range matchGroups {
		if !contains(groupNames, g) {
			out = append(out, RosterViolation{Rule: "privileged_identity match_groups reference", Detail: fmt.Sprintf("privileged_identity.match_groups references unknown group %q", g)})
		}
	}

	require := mapField(pi, "require")
	if unk := unknownKeys(require, knownPrivilegedIdentityRequireKeys); len(unk) > 0 {
		out = append(out, RosterViolation{Rule: "privileged_identity require keys", Detail: fmt.Sprintf("unknown privileged_identity.require field(s) %s", strings.Join(unk, ", "))})
	}
	for _, t := range stringListField(require, "auth_types") {
		if !contains(knownUserAuthTypes, t) {
			out = append(out, RosterViolation{Rule: "privileged_identity require auth_types", Detail: fmt.Sprintf("privileged_identity.require.auth_types %q must be one of %s", t, strings.Join(knownUserAuthTypes, "/"))})
		}
	}
	if v, ok := require["no_password_only"]; ok {
		if _, isBool := v.(bool); !isBool {
			out = append(out, RosterViolation{Rule: "privileged_identity require no_password_only", Detail: "privileged_identity.require.no_password_only must be a boolean"})
		}
	}
	// Added in v3.2 Phase 4 alongside credential_policy.go — Phase 3
	// deliberately deferred this cross-reference check because
	// credential_policies did not exist yet.
	if sshKeyPolicy := stringField(require, "ssh_key_policy"); sshKeyPolicy != "" {
		if !contains(namesOf(listField(root, "credential_policies")), sshKeyPolicy) {
			out = append(out, RosterViolation{Rule: "privileged_identity require ssh_key_policy reference", Detail: fmt.Sprintf("privileged_identity.require.ssh_key_policy references unknown credential_policy %q", sshKeyPolicy)})
		}
	}
	return out
}

// PrivilegedIdentityViolation is one effectively-privileged user
// EvaluatePrivilegedIdentityBaseline found failing security.
// privileged_identity.require — spec.md §9's fail-before-write baseline.
type PrivilegedIdentityViolation struct {
	User   string
	Detail string
}

// EvaluatePrivilegedIdentityBaseline resolves security.privileged_identity.
// match_groups into its effective (direct + nested, via expandGroupMembers
// — "alice -> team-sre -> role-production-admin means Alice is
// privileged", spec.md §9's own example) membership, and checks every
// reached user's own authentication.allowed against require.auth_types/
// no_password_only.
//
// A privileged user who declares no authentication: block at all is
// treated as password-only — FreeIPA's own default behavior when
// ipauserauthtype is unset, and the least-privileged read consistent with
// fail-before-write (§21.1): an undeclared user is never assumed already
// compliant.
//
// require.auth_types semantics: "any one of these satisfies", the same
// convention auth_policies[].require_any already established elsewhere in
// this codebase (auth_policy.go's header comment) — a privileged user is
// compliant on this axis once their authentication.allowed intersects
// require.auth_types at all, not only if it is a superset of it.
//
// Callers MUST have already run ValidateRosterV3 (checkPrivilegedIdentity)
// — this does not re-validate shape.
func EvaluatePrivilegedIdentityBaseline(root map[string]any) []PrivilegedIdentityViolation {
	security := mapField(root, "security")
	if _, has := security["privileged_identity"]; !has {
		return nil
	}
	pi := mapField(security, "privileged_identity")
	require := mapField(pi, "require")
	requiredAuthTypes := stringListField(require, "auth_types")
	noPasswordOnly := boolFieldDefault(require, "no_password_only", false)

	groupsByName := rosterGroupsByName(root)
	privileged := map[string]bool{}
	for _, g := range stringListField(pi, "match_groups") {
		expandGroupMembers(groupsByName, g, map[string]bool{}, privileged)
	}

	usersByName := map[string]map[string]any{}
	for _, raw := range listField(root, "users") {
		u := asMap(raw)
		if name := stringField(u, "name"); name != "" {
			usersByName[name] = u
		}
	}

	var out []PrivilegedIdentityViolation
	for _, user := range sortedSetKeys(privileged) {
		u := usersByName[user]
		if u == nil || stateOrDefault(u, "present") == "absent" {
			continue
		}
		allowed := stringListField(mapField(u, "authentication"), "allowed")

		if len(requiredAuthTypes) > 0 && !stringSlicesIntersect(allowed, requiredAuthTypes) {
			out = append(out, PrivilegedIdentityViolation{User: user, Detail: fmt.Sprintf("does not allow any of the required strong authentication types %s", strings.Join(requiredAuthTypes, "/"))})
		}
		if noPasswordOnly && isPasswordOnly(allowed) {
			out = append(out, PrivilegedIdentityViolation{User: user, Detail: "authentication.allowed is password-only (or unset), violating require.no_password_only"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].User < out[j].User })
	return out
}

// PrivilegedUsers returns every user security.privileged_identity.
// match_groups reaches (direct + nested membership), regardless of
// whether they comply with require — the full privileged set, not just
// the non-compliant ones EvaluatePrivilegedIdentityBaseline reports.
// Empty (nil) when no privileged_identity block is declared.
func PrivilegedUsers(root map[string]any) []string {
	security := mapField(root, "security")
	if _, has := security["privileged_identity"]; !has {
		return nil
	}
	pi := mapField(security, "privileged_identity")
	groupsByName := rosterGroupsByName(root)
	privileged := map[string]bool{}
	for _, g := range stringListField(pi, "match_groups") {
		expandGroupMembers(groupsByName, g, map[string]bool{}, privileged)
	}
	return sortedSetKeys(privileged)
}

// EvaluatePrivilegedIdentityBaselineFile is
// EvaluatePrivilegedIdentityBaseline's file-reading counterpart,
// mirroring EvaluateGrantPoliciesFile's read/parse/dispatch shape.
func EvaluatePrivilegedIdentityBaselineFile(path string) ([]PrivilegedIdentityViolation, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	return EvaluatePrivilegedIdentityBaseline(root), nil
}

// isPasswordOnly reports whether allowed is either empty (FreeIPA's own
// default when ipauserauthtype is unset is password-only) or contains
// exactly "password" and nothing else.
func isPasswordOnly(allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, t := range allowed {
		if t != "password" {
			return false
		}
	}
	return true
}

// stringSlicesIntersect reports whether a and b share at least one value.
func stringSlicesIntersect(a, b []string) bool {
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	for _, y := range b {
		if set[y] {
			return true
		}
	}
	return false
}
