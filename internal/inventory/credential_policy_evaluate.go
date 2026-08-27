// credential_policy_evaluate.go implements spec.md v3.2 §10/§11's
// read-only evaluators: SSH public-key hygiene findings and credential
// review status. Both are report-only — neither ever mutates the roster
// or FreeIPA (§10: "max_age is report-only in v3.2"; §11: "no automatic
// consequence"). Callers MUST have already run ValidateRosterV3
// (checkCredentialPolicies) — these do not re-validate shape.
package inventory

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// SSH hygiene finding kinds (SSHHygieneFinding.Issue).
const (
	SSHFindingBlank               = "blank"
	SSHFindingMalformed           = "malformed"
	SSHFindingDisallowedAlgorithm = "disallowed_algorithm"
	SSHFindingMissingComment      = "missing_comment"
	SSHFindingDuplicateMaterial   = "duplicate_material"
	// SSHFindingMaxAgeUnknown is emitted for every matched key whenever a
	// policy configures ssh.max_age — this delivery has no reliable
	// source for a key's actual age (spec.md §10 explicitly forbids
	// inferring one from roster file mtime, account creation time, Git
	// history, or current time), so an age requirement can never be
	// evaluated as pass/fail, only reported as unknown (spec.md §10
	// Scenario D).
	SSHFindingMaxAgeUnknown = "max_age_unknown"
)

// SSHHygieneFinding is one credential_policies[] entry's matched-key
// finding. Duplicate-material findings carry an empty User/Key (the
// finding names every user sharing the material in Detail instead) since
// they are a property of the whole matched set, not one user's key.
type SSHHygieneFinding struct {
	PolicyName string
	User       string
	Key        string // the raw authorized_keys line (public key only — never a private key)
	Issue      string
	Detail     string
}

// EvaluateSSHKeyHygiene walks every present credential_policies[] entry,
// resolves match.users/match.groups into its effective (direct + nested)
// user set, and evaluates each matched user's ssh_keys.values against
// that policy's ssh: rules. Duplicate-material detection is scoped to
// each policy's own matched key set — the users a given policy actually
// governs is the meaningful blast radius for "these two credentials
// should be distinct," not the whole roster.
func EvaluateSSHKeyHygiene(root map[string]any) []SSHHygieneFinding {
	groupsByName := rosterGroupsByName(root)
	usersByName := map[string]map[string]any{}
	for _, raw := range listField(root, "users") {
		u := asMap(raw)
		if name := stringField(u, "name"); name != "" {
			usersByName[name] = u
		}
	}

	var out []SSHHygieneFinding
	for _, raw := range listField(root, "credential_policies") {
		policy := asMap(raw)
		if stateOrDefault(policy, "present") == "absent" {
			continue
		}
		name := stringField(policy, "name")
		match := mapField(policy, "match")
		matched := map[string]bool{}
		for _, u := range stringListField(match, "users") {
			matched[u] = true
		}
		for _, g := range stringListField(match, "groups") {
			expandGroupMembers(groupsByName, g, map[string]bool{}, matched)
		}

		ssh := mapField(policy, "ssh")
		allowedAlgorithms := stringListField(ssh, "allowed_algorithms")
		requireComment := boolFieldDefault(ssh, "require_comment", false)
		maxAgeConfigured := stringField(ssh, "max_age") != ""

		materialUsers := map[string][]string{}

		for _, user := range sortedSetKeys(matched) {
			u := usersByName[user]
			if u == nil || stateOrDefault(u, "present") == "absent" {
				continue
			}
			for _, rawKey := range stringListField(mapField(u, "ssh_keys"), "values") {
				parsed := ParseSSHAuthorizedKeyLine(rawKey)
				switch parsed.Issue {
				case SSHKeyIssueBlank:
					out = append(out, SSHHygieneFinding{PolicyName: name, User: user, Key: rawKey, Issue: SSHFindingBlank, Detail: "SSH key is blank"})
					continue
				case SSHKeyIssueMalformed:
					out = append(out, SSHHygieneFinding{PolicyName: name, User: user, Key: rawKey, Issue: SSHFindingMalformed, Detail: "SSH key is malformed or truncated"})
					continue
				}
				if len(allowedAlgorithms) > 0 && !contains(allowedAlgorithms, parsed.Algorithm) {
					out = append(out, SSHHygieneFinding{PolicyName: name, User: user, Key: rawKey, Issue: SSHFindingDisallowedAlgorithm, Detail: fmt.Sprintf("algorithm %q is not in the configured allowlist [%s]", parsed.Algorithm, strings.Join(allowedAlgorithms, ", "))})
				}
				if requireComment && parsed.Comment == "" {
					out = append(out, SSHHygieneFinding{PolicyName: name, User: user, Key: rawKey, Issue: SSHFindingMissingComment, Detail: "SSH key has no comment, and this policy requires one"})
				}
				if maxAgeConfigured {
					out = append(out, SSHHygieneFinding{PolicyName: name, User: user, Key: rawKey, Issue: SSHFindingMaxAgeUnknown, Detail: "key age cannot be reliably derived from roster data; ssh.max_age cannot be evaluated (spec.md §10)"})
				}
				materialUsers[parsed.NormalizedMaterial] = append(materialUsers[parsed.NormalizedMaterial], user)
			}
		}

		for _, material := range sortedMapKeys(materialUsers) {
			users := dedupe(materialUsers[material])
			if len(users) < 2 {
				continue
			}
			sort.Strings(users)
			out = append(out, SSHHygieneFinding{PolicyName: name, Issue: SSHFindingDuplicateMaterial, Detail: fmt.Sprintf("identical SSH key material shared by: %s", strings.Join(users, ", "))})
		}
	}

	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.PolicyName != b.PolicyName {
			return a.PolicyName < b.PolicyName
		}
		if a.User != b.User {
			return a.User < b.User
		}
		if a.Issue != b.Issue {
			return a.Issue < b.Issue
		}
		return a.Detail < b.Detail
	})
	return out
}

// EvaluateSSHKeyHygieneFile is EvaluateSSHKeyHygiene's file-reading
// counterpart, mirroring EvaluateGrantPoliciesFile's read/parse/dispatch
// shape.
func EvaluateSSHKeyHygieneFile(path string) ([]SSHHygieneFinding, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	return EvaluateSSHKeyHygiene(root), nil
}

// sortedMapKeys returns m's keys sorted — used wherever an intermediate
// map's keys must be walked in deterministic order before building
// findings (spec.md §23's "JSON output stable" hygiene test requirement).
func sortedMapKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// CredentialReviewStatus is one credential_policies[] entry's review
// metadata plus its computed state (spec.md §11) — the same shape as
// ReviewStatus (review.go, v3.1 §14's grant recertification), evaluated
// through the identical classifyReviewState classifier.
type CredentialReviewStatus struct {
	PolicyName     string
	Interval       string
	LastReviewedAt *time.Time
	ReviewedBy     string
	NextDueAt      time.Time
	State          ReviewState
}

// EvaluateCredentialReviewStatuses walks root's credential_policies[] and
// reports a CredentialReviewStatus for every present entry that declares
// a review: block — an entry with no review: block is invisible here
// (review is opt-in, §11). Callers MUST have already run ValidateRosterV3
// (checkCredentialPolicyReview).
func EvaluateCredentialReviewStatuses(root map[string]any, now time.Time) ([]CredentialReviewStatus, error) {
	var out []CredentialReviewStatus
	for _, raw := range listField(root, "credential_policies") {
		policy := asMap(raw)
		if stateOrDefault(policy, "present") == "absent" {
			continue
		}
		reviewRaw, hasReview := policy["review"]
		if !hasReview {
			continue
		}
		review := asMap(reviewRaw)
		name := stringField(policy, "name")

		interval, err := ParseAccessDuration(stringField(review, "interval"))
		if err != nil {
			return nil, fmt.Errorf("credential_policy %q: review.interval: %w", name, err)
		}
		var lastReviewedAt *time.Time
		if s := stringField(review, "last_reviewed_at"); s != "" {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				return nil, fmt.Errorf("credential_policy %q: review.last_reviewed_at: %w", name, err)
			}
			lastReviewedAt = &t
		}

		nextDueAt, state := classifyReviewState(interval, lastReviewedAt, now)
		out = append(out, CredentialReviewStatus{
			PolicyName: name, Interval: stringField(review, "interval"),
			LastReviewedAt: lastReviewedAt, ReviewedBy: stringField(review, "reviewed_by"),
			NextDueAt: nextDueAt, State: state,
		})
	}
	return out, nil
}

// EvaluateCredentialReviewStatusesFile is EvaluateCredentialReviewStatuses'
// file-reading counterpart.
func EvaluateCredentialReviewStatusesFile(path string, now time.Time) ([]CredentialReviewStatus, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	return EvaluateCredentialReviewStatuses(root, now)
}
