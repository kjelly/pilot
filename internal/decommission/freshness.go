package decommission

import "context"

// CheckFreshness re-derives a fresh plan from current on-disk workspace/
// contract state and compares its hash to expectedHash (spec.md §28,
// INV-3). A mismatch means at least one plan-bound input changed since the
// plan was created; the caller MUST NOT execute the stale plan's fields —
// it gets back a *Error{Class: ErrPlanStale} and a freshly derived plan the
// caller may offer as the basis for a new one.
//
// This follows the same design principle spec.md §28 calls out for R2
// reapply freshness: execute against freshly re-derived server-side data,
// never against caller-supplied executable content.
func CheckFreshness(ctx context.Context, in PlanInput, expectedHash string) (*Plan, error) {
	fresh, err := PlanHost(ctx, in)
	if err != nil {
		return nil, err
	}
	if fresh.PlanHash != expectedHash {
		return fresh, newError(ErrPlanStale, "plan hash changed: stored=%s current=%s — re-plan required, cannot execute the stale plan", expectedHash, fresh.PlanHash)
	}
	return fresh, nil
}
