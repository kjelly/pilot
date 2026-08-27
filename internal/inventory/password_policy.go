// password_policy.go validates the v3.2 Identity & Credential Hardening
// spec's (spec.md §7, Phase 2) `password_policies:` section: declarative
// FreeIPA group password policies (min length, history, max/min life,
// lockout). This is purely structural — whether the exact field set maps
// onto a live FreeIPA target's krbPwdPolicy schema is a runtime concern
// spec.md §13's capability probing addresses separately, not something
// this validator can determine from the roster alone.
//
// This schema deliberately has no way to express "the global default
// policy" — every entry requires a `group:` — so a group-specific policy
// can never silently overwrite the global default (§7's explicit
// requirement) merely by omitting one.
package inventory

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

var (
	knownPasswordPolicyKeys        = []string{"name", "state", "group", "priority", "min_length", "history_size", "max_life", "min_life", "lockout"}
	knownPasswordPolicyLockoutKeys = []string{"max_failures", "failure_reset_interval", "lockout_duration"}
)

// checkPasswordPolicies validates the password_policies: list per
// spec.md v3.2 §7.
func checkPasswordPolicies(root map[string]any) []RosterViolation {
	var out []RosterViolation

	groupCategory := map[string]string{}
	for _, raw := range listField(root, "groups") {
		g := asMap(raw)
		groupCategory[stringField(g, "name")] = stringField(g, "category")
	}
	groupNames := namesOf(listField(root, "groups"))

	names := namesOf(listField(root, "password_policies"))
	if dupes := findDuplicates(names); len(dupes) > 0 {
		out = append(out, RosterViolation{Rule: "unique password_policy names", Detail: fmt.Sprintf("duplicate password_policy name(s): %s", strings.Join(dupes, ", "))})
	}

	var presentPriorities []string // string-encoded, file order, present entries with a valid priority only

	for _, raw := range listField(root, "password_policies") {
		item := asMap(raw)
		label := labelOf(item)

		if unk := unknownKeys(item, knownPasswordPolicyKeys); len(unk) > 0 {
			out = append(out, RosterViolation{Rule: "password_policy keys", Detail: fmt.Sprintf("password_policy %q: unknown field(s) %s", label, strings.Join(unk, ", "))})
		}

		state := stateOrDefault(item, "present")
		if state != "present" && state != "absent" {
			out = append(out, RosterViolation{Rule: "password_policy state", Detail: fmt.Sprintf("password_policy %q: state %q must be present/absent", label, state)})
		}

		group := stringField(item, "group")
		if group == "" {
			out = append(out, RosterViolation{Rule: "password_policy group", Detail: fmt.Sprintf("password_policy %q: group is required (the global default policy is never targeted by this schema)", label)})
		} else if !contains(groupNames, group) {
			out = append(out, RosterViolation{Rule: "password_policy group reference", Detail: fmt.Sprintf("password_policy %q: group references unknown group %q", label, group)})
		} else if IsDeprecatedGroupCategory(groupCategory[group]) {
			out = append(out, RosterViolation{Rule: "password_policy group category", Detail: fmt.Sprintf("password_policy %q: group %q uses the deprecated access-* category; use a role-*/team-* group instead (spec.md v3.2 §7)", label, group)})
		}

		if state == "present" {
			n, ok := toInt(item["priority"])
			switch {
			case !ok:
				out = append(out, RosterViolation{Rule: "password_policy priority", Detail: fmt.Sprintf("password_policy %q: priority is required and must be a positive integer", label)})
			case n <= 0:
				out = append(out, RosterViolation{Rule: "password_policy priority", Detail: fmt.Sprintf("password_policy %q: priority %d must be a positive integer", label, n)})
			default:
				presentPriorities = append(presentPriorities, strconv.Itoa(n))
			}
		}

		if raw, has := item["min_length"]; has {
			if n, ok := toInt(raw); !ok || n <= 0 {
				out = append(out, RosterViolation{Rule: "password_policy min_length", Detail: fmt.Sprintf("password_policy %q: min_length must be a positive integer", label)})
			}
		}
		if raw, has := item["history_size"]; has {
			if n, ok := toInt(raw); !ok || n < 0 {
				out = append(out, RosterViolation{Rule: "password_policy history_size", Detail: fmt.Sprintf("password_policy %q: history_size must be a non-negative integer", label)})
			}
		}
		if maxLife := stringField(item, "max_life"); maxLife != "" && !ValidAccessDuration(maxLife) {
			out = append(out, RosterViolation{Rule: "password_policy max_life", Detail: fmt.Sprintf("password_policy %q: max_life %q is not a valid duration (e.g. 90d, 24h)", label, maxLife)})
		}
		if minLife := stringField(item, "min_life"); minLife != "" && !ValidAccessDuration(minLife) {
			out = append(out, RosterViolation{Rule: "password_policy min_life", Detail: fmt.Sprintf("password_policy %q: min_life %q is not a valid duration (e.g. 1h, 30m)", label, minLife)})
		}

		lockout := mapField(item, "lockout")
		if unk := unknownKeys(lockout, knownPasswordPolicyLockoutKeys); len(unk) > 0 {
			out = append(out, RosterViolation{Rule: "password_policy lockout keys", Detail: fmt.Sprintf("password_policy %q: unknown lockout field(s) %s", label, strings.Join(unk, ", "))})
		}
		if raw, has := lockout["max_failures"]; has {
			if n, ok := toInt(raw); !ok || n <= 0 {
				out = append(out, RosterViolation{Rule: "password_policy lockout max_failures", Detail: fmt.Sprintf("password_policy %q: lockout.max_failures must be a positive integer", label)})
			}
		}
		if v := stringField(lockout, "failure_reset_interval"); v != "" && !ValidAccessDuration(v) {
			out = append(out, RosterViolation{Rule: "password_policy lockout failure_reset_interval", Detail: fmt.Sprintf("password_policy %q: lockout.failure_reset_interval %q is not a valid duration (e.g. 15m)", label, v)})
		}
		if v := stringField(lockout, "lockout_duration"); v != "" && !ValidAccessDuration(v) {
			out = append(out, RosterViolation{Rule: "password_policy lockout lockout_duration", Detail: fmt.Sprintf("password_policy %q: lockout.lockout_duration %q is not a valid duration (e.g. 15m)", label, v)})
		}
	}

	// FreeIPA requires cospriority to be unique across every group
	// password policy — two `state: present` entries claiming the same
	// priority would fail apply non-deterministically depending on which
	// FreeIPA processes first (§23's "duplicate/ambiguous priority" test).
	if dupes := findDuplicates(presentPriorities); len(dupes) > 0 {
		sort.Strings(dupes)
		out = append(out, RosterViolation{Rule: "password_policy priority uniqueness", Detail: fmt.Sprintf("priority value(s) claimed by more than one password_policy (FreeIPA requires unique priority): %s", strings.Join(dupes, ", "))})
	}

	return out
}
