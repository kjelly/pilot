// credential_policy.go validates the v3.2 Identity & Credential Hardening
// spec's (spec.md §10/§11, Phase 4) `credential_policies:` section: SSH
// public-key hygiene rules and optional review metadata, scoped to a set
// of matched users/groups.
//
// Every control this section governs is report-only or validation-only
// in v3.2 (spec.md §6's capability matrix: "SSH key syntax/algorithm
// policy — validation only", "SSH key max-age report — report only") —
// there is no FreeIPA-native backend and therefore no compiler/apply
// playbook counterpart the way password_policy_compile.go has one; see
// credential_policy_evaluate.go for the read-only evaluators this
// section's structural validation feeds.
package inventory

import (
	"fmt"
	"strings"
	"time"
)

var (
	knownCredentialPolicyKeys      = []string{"name", "state", "match", "ssh", "review"}
	knownCredentialPolicyMatchKeys = []string{"users", "groups"}
	knownCredentialPolicySSHKeys   = []string{"allowed_algorithms", "require_comment", "max_age"}
)

// checkCredentialPolicies validates the credential_policies: list per
// spec.md v3.2 §10/§11.
func checkCredentialPolicies(root map[string]any) []RosterViolation {
	var out []RosterViolation

	userNames := namesOf(listField(root, "users"))
	groupNames := namesOf(listField(root, "groups"))

	names := namesOf(listField(root, "credential_policies"))
	if dupes := findDuplicates(names); len(dupes) > 0 {
		out = append(out, RosterViolation{Rule: "unique credential_policy names", Detail: fmt.Sprintf("duplicate credential_policy name(s): %s", strings.Join(dupes, ", "))})
	}

	for _, raw := range listField(root, "credential_policies") {
		item := asMap(raw)
		label := labelOf(item)

		if unk := unknownKeys(item, knownCredentialPolicyKeys); len(unk) > 0 {
			out = append(out, RosterViolation{Rule: "credential_policy keys", Detail: fmt.Sprintf("credential_policy %q: unknown field(s) %s", label, strings.Join(unk, ", "))})
		}
		state := stateOrDefault(item, "present")
		if state != "present" && state != "absent" {
			out = append(out, RosterViolation{Rule: "credential_policy state", Detail: fmt.Sprintf("credential_policy %q: state %q must be present/absent", label, state)})
		}

		match := mapField(item, "match")
		if unk := unknownKeys(match, knownCredentialPolicyMatchKeys); len(unk) > 0 {
			out = append(out, RosterViolation{Rule: "credential_policy match keys", Detail: fmt.Sprintf("credential_policy %q: unknown match field(s) %s", label, strings.Join(unk, ", "))})
		}
		matchUsers := stringListField(match, "users")
		matchGroups := stringListField(match, "groups")
		if state == "present" && len(matchUsers)+len(matchGroups) == 0 {
			out = append(out, RosterViolation{Rule: "credential_policy match", Detail: fmt.Sprintf("credential_policy %q: needs at least one match.users or match.groups entry", label)})
		}
		for _, u := range matchUsers {
			if !contains(userNames, u) {
				out = append(out, RosterViolation{Rule: "credential_policy match user reference", Detail: fmt.Sprintf("credential_policy %q: match.users references unknown user %q", label, u)})
			}
		}
		for _, g := range matchGroups {
			if !contains(groupNames, g) {
				out = append(out, RosterViolation{Rule: "credential_policy match group reference", Detail: fmt.Sprintf("credential_policy %q: match.groups references unknown group %q", label, g)})
			}
		}

		ssh := mapField(item, "ssh")
		if unk := unknownKeys(ssh, knownCredentialPolicySSHKeys); len(unk) > 0 {
			out = append(out, RosterViolation{Rule: "credential_policy ssh keys", Detail: fmt.Sprintf("credential_policy %q: unknown ssh field(s) %s", label, strings.Join(unk, ", "))})
		}
		// allowed_algorithms is deliberately NOT checked against any
		// fixed enum here — spec.md §10: "Do not silently impose a
		// hard-coded algorithm allowlist." Pilot has no opinion on which
		// SSH algorithms are acceptable; it only enforces whatever
		// allowlist the roster author configures (or nothing, if unset).
		for _, alg := range stringListField(ssh, "allowed_algorithms") {
			if strings.TrimSpace(alg) == "" {
				out = append(out, RosterViolation{Rule: "credential_policy ssh allowed_algorithms", Detail: fmt.Sprintf("credential_policy %q: ssh.allowed_algorithms contains a blank entry", label)})
			}
		}
		if v, ok := ssh["require_comment"]; ok {
			if _, isBool := v.(bool); !isBool {
				out = append(out, RosterViolation{Rule: "credential_policy ssh require_comment", Detail: fmt.Sprintf("credential_policy %q: ssh.require_comment must be a boolean", label)})
			}
		}
		if maxAge := stringField(ssh, "max_age"); maxAge != "" && !ValidAccessDuration(maxAge) {
			out = append(out, RosterViolation{Rule: "credential_policy ssh max_age", Detail: fmt.Sprintf("credential_policy %q: ssh.max_age %q is not a valid duration (e.g. 365d)", label, maxAge)})
		}

		out = append(out, checkCredentialPolicyReview(item, label, userNames)...)
	}

	return out
}

// checkCredentialPolicyReview validates an optional review: block
// (spec.md §11) — the same shape and reuse-the-shared-key-list posture
// as checkGrantReview (roster_grants.go, v3.1 §14): review is opt-in
// metadata/reporting, so its absence is never a violation, and there is
// deliberately no on_overdue key at all — §11 requires "no automatic
// consequence" for an overdue review, and the simplest way to guarantee
// that is for the schema to have no lever for it in the first place.
func checkCredentialPolicyReview(item map[string]any, label string, allowedUsers []string) []RosterViolation {
	var out []RosterViolation
	reviewRaw, hasReview := item["review"]
	if !hasReview {
		return out
	}
	r := asMap(reviewRaw)
	if unk := unknownKeys(r, knownReviewKeys); len(unk) > 0 {
		out = append(out, RosterViolation{Rule: "credential_policy review keys", Detail: fmt.Sprintf("credential_policy %q: unknown review field(s) %s", label, strings.Join(unk, ", "))})
	}
	interval := stringField(r, "interval")
	if interval == "" {
		out = append(out, RosterViolation{Rule: "credential_policy review interval", Detail: fmt.Sprintf("credential_policy %q: review.interval is required", label)})
	} else if !ValidAccessDuration(interval) {
		out = append(out, RosterViolation{Rule: "credential_policy review interval", Detail: fmt.Sprintf("credential_policy %q: review.interval %q is not a valid duration (e.g. 180d)", label, interval)})
	}
	if lastReviewedAt := stringField(r, "last_reviewed_at"); lastReviewedAt != "" {
		if _, err := time.Parse(time.RFC3339, lastReviewedAt); err != nil {
			out = append(out, RosterViolation{Rule: "credential_policy review last_reviewed_at", Detail: fmt.Sprintf("credential_policy %q: review.last_reviewed_at %q must be RFC3339: %v", label, lastReviewedAt, err)})
		}
	}
	if reviewedBy := stringField(r, "reviewed_by"); reviewedBy != "" && !contains(allowedUsers, reviewedBy) {
		out = append(out, RosterViolation{Rule: "credential_policy review reviewed_by reference", Detail: fmt.Sprintf("credential_policy %q: review.reviewed_by references unknown roster user %q", label, reviewedBy)})
	}
	return out
}
