// account_policy.go implements the v3.0 Core Access Governance spec's
// (spec.md §15, Phase 3) `account_policies:` section: a per-user
// employment/engagement validity window. checkAccountPolicies validates
// the section's shape; EvaluateAccountLifecycle is the semantic check
// spec.md §15 requires — "account expired -> no grant may restore
// access" — a user whose account isn't currently active can't be granted
// anything via any temporary_grant/sudo_grant, however that grant reaches
// them (direct subjects.users, or a subjects.groups membership).
package inventory

import (
	"fmt"
	"strings"
	"time"
)

var knownAccountPolicyKeys = []string{"name", "state", "user", "type", "validity", "sponsor", "ticket"}

// checkAccountPolicies validates account_policies: per spec.md §15.
func checkAccountPolicies(root map[string]any) []RosterViolation {
	var out []RosterViolation

	allowedUsers := namesOf(listField(root, "users"))
	names := namesOf(listField(root, "account_policies"))
	if dupes := findDuplicates(names); len(dupes) > 0 {
		out = append(out, RosterViolation{Rule: "unique account_policy names", Detail: fmt.Sprintf("duplicate account_policy name(s): %s", strings.Join(dupes, ", "))})
	}

	for _, raw := range listField(root, "account_policies") {
		item := asMap(raw)
		label := labelOf(item)

		if unk := unknownKeys(item, knownAccountPolicyKeys); len(unk) > 0 {
			out = append(out, RosterViolation{Rule: "account_policy keys", Detail: fmt.Sprintf("account_policy %q: unknown field(s) %s", label, strings.Join(unk, ", "))})
		}
		state := stateOrDefault(item, "present")
		if state != "present" && state != "absent" {
			out = append(out, RosterViolation{Rule: "account_policy state", Detail: fmt.Sprintf("account_policy %q: state %q must be present/absent", label, state)})
		}

		user := stringField(item, "user")
		if user == "" {
			out = append(out, RosterViolation{Rule: "account_policy user", Detail: fmt.Sprintf("account_policy %q: user is required", label)})
		} else if !contains(allowedUsers, user) {
			out = append(out, RosterViolation{Rule: "account_policy user reference", Detail: fmt.Sprintf("account_policy %q: user references unknown roster user %q", label, user)})
		}

		// `type` is a free-form label (spec.md §15's example uses
		// "contractor") — no enum is defined, so only presence is
		// checked; inventing a closed taxonomy nobody has agreed to
		// would be exactly the mistake roster_grants.go's header comment
		// warns against repeating.
		if stringField(item, "type") == "" {
			out = append(out, RosterViolation{Rule: "account_policy type", Detail: fmt.Sprintf("account_policy %q: type is required", label)})
		}

		if _, ok := item["validity"]; !ok {
			out = append(out, RosterViolation{Rule: "account_policy validity", Detail: fmt.Sprintf("account_policy %q: validity is required", label)})
		} else if _, err := ParseGrantValidity(mapField(item, "validity")); err != nil {
			// ParseGrantValidity is reused verbatim: account_policies'
			// validity.{not_before,not_after} is structurally identical
			// to a grant's (§7/§8) — not_after required RFC3339,
			// not_before optional, not_after > not_before.
			out = append(out, RosterViolation{Rule: "account_policy validity", Detail: fmt.Sprintf("account_policy %q: %v", label, err)})
		}

		if sponsor := stringField(item, "sponsor"); sponsor != "" && !contains(allowedUsers, sponsor) {
			out = append(out, RosterViolation{Rule: "account_policy sponsor reference", Detail: fmt.Sprintf("account_policy %q: sponsor references unknown roster user %q", label, sponsor)})
		}
	}

	return out
}

// AccountLifecycleViolation is raised when a grant would currently reach
// a user whose account isn't active — spec.md §15's "account expired ->
// no grant may restore access".
type AccountLifecycleViolation struct {
	GrantName         string
	User              string
	AccountPolicyName string
	// AccountLifecycle is the user's most-recent account_policies entry's
	// lifecycle state at evaluation time (pending, expired, or absent —
	// never active, since an active account never triggers this).
	AccountLifecycle GrantLifecycleState
}

// EvaluateAccountLifecycle cross-checks every present temporary_grant/
// sudo_grant's resolved subject users (direct users, plus every member of
// any subjects.groups — group membership is expanded the same way
// EvaluateSoD resolves effective role membership) against
// account_policies. A user with zero account_policies entries is
// unconstrained (account lifecycle is opt-in per user, not exhaustive) —
// only a user who HAS at least one entry, none of which is currently
// active, violates. kind: breakglass is out of scope here for the same
// reason grant_security_policy.go excludes it (Phase 3's breakglass
// activation, not a validity-driven grant, is the actual gate for that
// path — see breakglass.go, added when this evaluator is wired into
// activation).
func EvaluateAccountLifecycle(root map[string]any, now time.Time) ([]AccountLifecycleViolation, error) {
	groupsByName := rosterGroupsByName(root)
	byUser := indexAccountPoliciesByUser(root)

	var out []AccountLifecycleViolation
	for _, raw := range listField(root, "grants") {
		grant := asMap(raw)
		kind := stringField(grant, "kind")
		if kind != grantKindTemporary && kind != grantKindSudo {
			continue
		}
		if stateOrDefault(grant, "present") == "absent" {
			continue
		}

		subjects := mapField(grant, "subjects")
		users := map[string]bool{}
		for _, u := range stringListField(subjects, "users") {
			users[u] = true
		}
		for _, g := range stringListField(subjects, "groups") {
			expandGroupMembers(groupsByName, g, map[string]bool{}, users)
		}

		grantName := stringField(grant, "name")
		for user := range users {
			active, policyName, lifecycle, err := accountLifecycleForUser(byUser, user, now)
			if err != nil {
				return nil, err
			}
			if !active && policyName != "" {
				out = append(out, AccountLifecycleViolation{
					GrantName:         grantName,
					User:              user,
					AccountPolicyName: policyName,
					AccountLifecycle:  lifecycle,
				})
			}
		}
	}
	return out, nil
}

// EvaluateAccountLifecycleFile is EvaluateAccountLifecycle's file-reading
// counterpart, mirroring RosterUserNames' read/parse/dispatch shape
// (roster.go).
func EvaluateAccountLifecycleFile(path string, now time.Time) ([]AccountLifecycleViolation, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	return EvaluateAccountLifecycle(root, now)
}

func indexAccountPoliciesByUser(root map[string]any) map[string][]map[string]any {
	byUser := map[string][]map[string]any{}
	for _, raw := range listField(root, "account_policies") {
		policy := asMap(raw)
		byUser[stringField(policy, "user")] = append(byUser[stringField(policy, "user")], policy)
	}
	return byUser
}

// accountLifecycleForUser reports whether user's account is currently
// active. A user with no account_policies entries at all is
// unconstrained: active is true, policyName is "" (nothing to blame a
// violation on — see EvaluateAccountLifecycle/AccountActiveForUser, which
// treat an empty policyName as "not actually a violation"). Otherwise
// active reflects whether ANY of the user's entries is currently
// GrantActive (e.g. a renewed contract), and policyName/lifecycle report
// the most recently inspected non-active entry when none is.
func accountLifecycleForUser(byUser map[string][]map[string]any, user string, now time.Time) (active bool, policyName string, lifecycle GrantLifecycleState, err error) {
	policies := byUser[user]
	if len(policies) == 0 {
		return true, "", "", nil
	}
	var mostRecent map[string]any
	var mostRecentLifecycle GrantLifecycleState
	for _, policy := range policies {
		state := stateOrDefault(policy, "present")
		validity, perr := ParseGrantValidity(mapField(policy, "validity"))
		if perr != nil {
			return false, "", "", fmt.Errorf("account_policy %q: %w", stringField(policy, "name"), perr)
		}
		lc := EvaluateGrantLifecycle(state, validity, now)
		if lc == GrantActive {
			return true, "", "", nil
		}
		mostRecent, mostRecentLifecycle = policy, lc
	}
	return false, stringField(mostRecent, "name"), mostRecentLifecycle, nil
}

// AccountActiveForUser reports whether user's account is currently
// active, per spec.md §15's dominance rule — a user with no
// account_policies entries at all is unconstrained (active). Exported for
// internal/accessgrants' breakglass activation gate (spec.md §14's
// subject is a single named user, so it needs exactly this per-user
// check, not the whole-roster EvaluateAccountLifecycle sweep).
func AccountActiveForUser(root map[string]any, user string, now time.Time) (active bool, policyName string, lifecycle GrantLifecycleState, err error) {
	return accountLifecycleForUser(indexAccountPoliciesByUser(root), user, now)
}

// AccountActiveForUserFile is AccountActiveForUser's file-reading
// counterpart, mirroring RosterUserNames' read/parse/dispatch shape
// (roster.go).
func AccountActiveForUserFile(path, user string, now time.Time) (active bool, policyName string, lifecycle GrantLifecycleState, err error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return false, "", "", err
	}
	return AccountActiveForUser(root, user, now)
}
