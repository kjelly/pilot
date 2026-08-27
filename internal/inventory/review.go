// review.go implements spec.md v3.1 §14: optional grant recertification
// metadata/reporting. review: is opt-in per grant (temporary_grant/
// sudo_grant only — roster_grants.go's checkGrantReview) and carries no
// enforcement of its own: EvaluateReviewStatuses only classifies
// current/due/overdue for reporting, and MarkGrantReviewedFile only
// updates last_reviewed_at/reviewed_by — neither ever touches FreeIPA or
// suspends a grant. §14.2 requires automatic on_overdue: suspend
// semantics to fail closed; this package achieves that by never accepting
// the key at all (see checkGrantReview's doc comment), so there is
// nothing here to "not enforce" — the schema itself has no lever for it.
package inventory

import (
	"errors"
	"fmt"
	"time"
)

// ReviewState is one review-tracked grant's current recertification
// state, evaluated against an injected clock (mirroring GrantLifecycleState's
// injected-clock convention).
type ReviewState string

const (
	ReviewCurrent ReviewState = "current"
	ReviewDue     ReviewState = "due"
	ReviewOverdue ReviewState = "overdue"
)

// ReviewStatus is one grants[] entry's review metadata plus its computed
// state — the shape `pilot access review list` reports.
type ReviewStatus struct {
	Name     string
	Kind     string
	Interval string
	// LastReviewedAt is nil when the grant has never been marked reviewed
	// — that always reports ReviewOverdue (never-reviewed access is the
	// most urgent case to recertify, not a settled one).
	LastReviewedAt *time.Time
	ReviewedBy     string
	// NextDueAt is the zero time.Time when LastReviewedAt is nil (there is
	// no prior review to add the interval to).
	NextDueAt time.Time
	State     ReviewState
}

// reviewDueSoonFraction is how far before NextDueAt a current review
// enters the "due" state — a documented judgment call (spec.md v3.1 §14
// does not define this boundary): the last 1/5 of the review interval
// counts as "coming due" rather than still "current". A 30d interval
// therefore reports "due" starting 6 days before the deadline.
const reviewDueSoonFraction = 5

// EvaluateReviewStatuses walks root's grants[] and reports a ReviewStatus
// for every present temporary_grant/sudo_grant that declares a review:
// block — a grant with no review: block is invisible here (review is
// opt-in, §14). Callers MUST have already run ValidateRoster
// (checkGrantReview).
func EvaluateReviewStatuses(root map[string]any, now time.Time) ([]ReviewStatus, error) {
	var out []ReviewStatus
	for _, raw := range listField(root, "grants") {
		grant := asMap(raw)
		kind := stringField(grant, "kind")
		if kind != grantKindTemporary && kind != grantKindSudo {
			continue
		}
		if stateOrDefault(grant, "present") == "absent" {
			continue
		}
		reviewRaw, hasReview := grant["review"]
		if !hasReview {
			continue
		}
		review := asMap(reviewRaw)
		name := stringField(grant, "name")

		interval, err := ParseAccessDuration(stringField(review, "interval"))
		if err != nil {
			return nil, fmt.Errorf("grant %q: review.interval: %w", name, err)
		}

		var lastReviewedAt *time.Time
		if s := stringField(review, "last_reviewed_at"); s != "" {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				return nil, fmt.Errorf("grant %q: review.last_reviewed_at: %w", name, err)
			}
			lastReviewedAt = &t
		}

		nextDueAt, state := classifyReviewState(interval, lastReviewedAt, now)
		out = append(out, ReviewStatus{
			Name:           name,
			Kind:           kind,
			Interval:       stringField(review, "interval"),
			LastReviewedAt: lastReviewedAt,
			ReviewedBy:     stringField(review, "reviewed_by"),
			NextDueAt:      nextDueAt,
			State:          state,
		})
	}
	return out, nil
}

// classifyReviewState is EvaluateReviewStatuses' and v3.2 §11's shared
// current/due/overdue classifier: a review with no prior last_reviewed_at
// is always ReviewOverdue (never-reviewed is the most urgent case to
// recertify, not a settled one — the zero NextDueAt returned alongside it
// is meaningless and callers must not render it). Otherwise nextDueAt is
// lastReviewedAt+interval, and the last 1/5 of the interval before that
// counts as "coming due" (reviewDueSoonFraction) rather than still
// current — a documented judgment call spec.md does not itself define.
func classifyReviewState(interval time.Duration, lastReviewedAt *time.Time, now time.Time) (nextDueAt time.Time, state ReviewState) {
	if lastReviewedAt == nil {
		return time.Time{}, ReviewOverdue
	}
	nextDueAt = lastReviewedAt.Add(interval)
	dueSoonAt := nextDueAt.Add(-interval / reviewDueSoonFraction)
	switch {
	case !now.Before(nextDueAt):
		return nextDueAt, ReviewOverdue
	case !now.Before(dueSoonAt):
		return nextDueAt, ReviewDue
	default:
		return nextDueAt, ReviewCurrent
	}
}

// EvaluateReviewStatusesFile is EvaluateReviewStatuses' file-reading
// counterpart, mirroring RosterUserNames' read/parse/dispatch shape.
func EvaluateReviewStatusesFile(path string, now time.Time) ([]ReviewStatus, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	return EvaluateReviewStatuses(root, now)
}

// markGrantReviewedPlaintext is MarkGrantReviewedFile's non-vault half:
// path MUST already be plaintext YAML.
func markGrantReviewedPlaintext(path, name, reviewedBy string, now time.Time) error {
	grant, found, err := RosterGrant(path, name)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("grant %q not found", name)
	}
	kind := stringField(grant, "kind")
	if kind != grantKindTemporary && kind != grantKindSudo {
		return fmt.Errorf("grant %q is kind %q; only temporary_grant/sudo_grant carry a review policy", name, kind)
	}
	reviewRaw, hasReview := grant["review"]
	if !hasReview {
		return fmt.Errorf("grant %q has no review policy declared — review.interval must already be set in the roster before it can be marked reviewed", name)
	}

	updatedReview := map[string]any{}
	for k, v := range asMap(reviewRaw) {
		updatedReview[k] = v
	}
	updatedReview["last_reviewed_at"] = now.UTC().Format(time.RFC3339)
	updatedReview["reviewed_by"] = reviewedBy

	updated := map[string]any{}
	for k, v := range grant {
		updated[k] = v
	}
	updated["review"] = updatedReview

	violations, _, err := SimulateSetRosterGrant(path, name, updated)
	if err != nil {
		return err
	}
	if len(violations) > 0 {
		return fmt.Errorf("marking grant %q as reviewed would fail roster validation: %v", name, violations)
	}
	return SetRosterGrant(path, name, updated)
}

// MarkGrantReviewedFile updates the named grant's review.last_reviewed_at
// (to now, UTC RFC3339) and review.reviewed_by (to reviewedBy) in the
// roster at path — plaintext or ansible-vault encrypted, given
// vaultPasswordFile (§14.1's `pilot access review mark`). reviewedBy is
// metadata only, per §14.3 — it is never treated as Approval evidence.
// It is an error to mark a grant that doesn't exist, isn't
// temporary_grant/sudo_grant, or has no review: block already declared —
// mark only updates an existing opt-in policy, it never silently enrolls
// a grant into review.
//
// Encrypted-roster handling reuses MutateEncryptedRosterFile
// (roster_vault.go) — the same decrypt/mutate/re-encrypt-in-place
// machinery `pilot roster migrate` already established — rather than a
// second implementation (§14.1's "encrypted roster safe mutation" test).
func MarkGrantReviewedFile(path, vaultPasswordFile, name, reviewedBy string, now time.Time) error {
	if reviewedBy == "" {
		return fmt.Errorf("reviewedBy is required")
	}
	err := markGrantReviewedPlaintext(path, name, reviewedBy, now)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrRosterEncrypted) {
		return err
	}
	if vaultPasswordFile == "" {
		return fmt.Errorf("%s is ansible-vault encrypted; pass a vault password file", path)
	}
	return MutateEncryptedRosterFile(path, vaultPasswordFile, func(plaintextPath string) error {
		return markGrantReviewedPlaintext(plaintextPath, name, reviewedBy, now)
	})
}
