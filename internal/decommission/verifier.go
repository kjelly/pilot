// verifier.go implements spec.md §25's zero-residue verification formula.
// It never queries a live system itself (that is what a
// providers.Provider's Verify method does, per provider.go's contract) —
// it only evaluates the independently-collected []providers.Verification
// results a caller hands it (INV-10). In Phase 2, since no live provider
// is registered anywhere yet, the real `pilot host decommission apply`
// CLI path always passes an empty slice for a zero-role host — the
// formula below is vacuously satisfied (0 active residue, 0 unknown
// ownership) without a single live check having run. Phase 3+ providers
// populate this slice for real; nothing here needs to change when they
// do.
package decommission

import (
	"fmt"

	"github.com/kjelly/pilot/internal/decommission/providers"
)

// VerificationOutcome is EvaluateVerifications' result: spec.md §25's
// pass/block decision plus the counts/results that produced it, so a
// caller (Finalize, `pilot host decommission verify`, the TUI) can report
// exactly why finalization is or is not allowed to proceed.
type VerificationOutcome struct {
	Passed                bool
	ActiveResidueCount    int
	UnknownOwnershipCount int
	// OtherBlocking holds any result whose Status is not one of the
	// formula's named outcomes (pass/not_applicable/historical_only/
	// active_residue/unknown_ownership) — e.g.
	// unreachable_unverified — which also fails closed (INV-11): an
	// unverifiable check is never treated as a pass.
	OtherBlocking []providers.Verification
	Results       []providers.Verification
}

// BlockerDetails renders a short human-readable line per blocking result
// — active residue, unknown ownership, or any other non-clean status.
func (o VerificationOutcome) BlockerDetails() []string {
	var out []string
	for _, r := range o.Results {
		switch r.Status {
		case "pass", "not_applicable", "historical_only":
			continue
		default:
			out = append(out, fmt.Sprintf("%s/%s %q: %s (%s)", r.Provider, r.Kind, r.Identity, r.Status, r.Detail))
		}
	}
	return out
}

// EvaluateVerifications implements spec.md §25's exact formula: success
// requires every mandatory check to land in {pass, not_applicable,
// historical_only}, active_residue_count == 0, and
// unknown_active_ownership_count == 0. Phase 2 treats every result handed
// in as mandatory — there is no optional-check concept yet.
func EvaluateVerifications(results []providers.Verification) VerificationOutcome {
	out := VerificationOutcome{Results: results}
	for _, r := range results {
		switch r.Status {
		case "pass", "not_applicable", "historical_only":
			// clean — does not block.
		case "active_residue":
			out.ActiveResidueCount++
		case "unknown_ownership":
			out.UnknownOwnershipCount++
		default:
			// e.g. unreachable_unverified, or an empty/unrecognized
			// status — fail closed rather than silently treating it as
			// a pass (INV-11).
			out.OtherBlocking = append(out.OtherBlocking, r)
		}
	}
	out.Passed = out.ActiveResidueCount == 0 && out.UnknownOwnershipCount == 0 && len(out.OtherBlocking) == 0
	return out
}
