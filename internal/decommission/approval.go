// approval.go implements INV-4/HD5: host decommission requires an
// explicit human approval — in sandbox, staging, and production alike,
// with no autonomous exception — bound to EXACTLY (plan_id, plan_hash)
// per spec.md §30. It does not collect approval itself; that is the
// CLI's --confirm-host flag (spec.md §10.3 requirement 6) or the TUI's
// typed-host-name screen (spec.md §11.3), both of which call
// Store.RecordApproval once the operator has confirmed. This file only
// gates execution on one already having been recorded.
package decommission

// RequireApproval enforces that an "approve" decision has been persisted
// for EXACTLY (planID, planHash), regardless of environment — sandbox,
// staging, prod, or any other value callers use, there is no bypass.
// Returns an *Error{Class: ErrApprovalRequired} when none is found.
func RequireApproval(s *Store, planID, planHash, environment string) error {
	approved, err := s.ApprovedForHash(planID, planHash)
	if err != nil {
		return err
	}
	if !approved {
		return newError(ErrApprovalRequired,
			"host decommission requires explicit human approval for plan %s (environment=%q) bound to plan_hash %s — none found; there is no autonomous exception in any environment (INV-4)",
			planID, environment, shortHash(planHash))
	}
	return nil
}

// shortHash truncates h for compact log/error output; safe on any length.
func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
