package inventory

import (
	"fmt"
	"time"
)

// GrantLifecycleState is one of the four states spec.md §8 defines for a
// grants[] entry that carries a validity window (temporary_grant,
// sudo_grant). kind: breakglass never has a validity window (§6.3) and so
// never participates in this state machine — its "is it currently
// granting access" question is answered by runtime activation state
// instead (§14), a deliberately separate mechanism.
type GrantLifecycleState string

const (
	GrantPending GrantLifecycleState = "pending"
	GrantActive  GrantLifecycleState = "active"
	GrantExpired GrantLifecycleState = "expired"
	GrantAbsent  GrantLifecycleState = "absent"
)

// GrantValidity is a parsed validity.not_before/not_after window. NotAfter
// is always set for a grant kind that carries validity (temporary_grant,
// sudo_grant — §7 requires it); NotBefore may be the zero Time when the
// grant omits the optional not_before.
type GrantValidity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// ParseGrantValidity parses a grants[].validity map (RFC3339 strings) into
// a GrantValidity. It is the single parser roster_grants.go's structural
// validation and grant_compile.go's compiler both call, so "is this
// validity well-formed" is answered identically by both — see §7/§8/§9/§10.
func ParseGrantValidity(validity map[string]any) (GrantValidity, error) {
	var out GrantValidity
	notAfterStr := stringField(validity, "not_after")
	if notAfterStr == "" {
		return out, fmt.Errorf("validity.not_after is required")
	}
	notAfter, err := time.Parse(time.RFC3339, notAfterStr)
	if err != nil {
		return out, fmt.Errorf("validity.not_after %q must be RFC3339 with an offset or Z: %w", notAfterStr, err)
	}
	out.NotAfter = notAfter

	if notBeforeStr := stringField(validity, "not_before"); notBeforeStr != "" {
		notBefore, err := time.Parse(time.RFC3339, notBeforeStr)
		if err != nil {
			return out, fmt.Errorf("validity.not_before %q must be RFC3339 with an offset or Z: %w", notBeforeStr, err)
		}
		out.NotBefore = notBefore
	}

	if !out.NotBefore.IsZero() && !out.NotAfter.After(out.NotBefore) {
		return out, fmt.Errorf("validity.not_after must be after validity.not_before")
	}
	return out, nil
}

// EvaluateGrantLifecycle applies spec.md §8's state machine using an
// injected clock (now) and UTC comparison — callers MUST NOT substitute
// time.Now() directly so lifecycle decisions stay deterministic and
// testable (§8: "MUST use injected clock").
//
// state is the grant's own top-level `state: present|absent` field.
// validity is the grant's parsed validity window; it is meaningless (and
// ignored) when state is "absent".
func EvaluateGrantLifecycle(state string, validity GrantValidity, now time.Time) GrantLifecycleState {
	if state == "absent" {
		return GrantAbsent
	}
	now = now.UTC()
	if !validity.NotBefore.IsZero() && now.Before(validity.NotBefore.UTC()) {
		return GrantPending
	}
	if now.Before(validity.NotAfter.UTC()) {
		return GrantActive
	}
	return GrantExpired
}

// NextGrantTransition reports the next timestamp (UTC) at which state
// re-evaluates to a different GrantLifecycleState, or nil when there is
// none (already expired, or absent) — spec.md §9's `next_transition_at`.
func NextGrantTransition(state string, validity GrantValidity, now time.Time) *time.Time {
	switch EvaluateGrantLifecycle(state, validity, now) {
	case GrantPending:
		t := validity.NotBefore.UTC()
		return &t
	case GrantActive:
		t := validity.NotAfter.UTC()
		return &t
	default:
		return nil
	}
}
