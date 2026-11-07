package identityreconcile

import (
	"fmt"

	"github.com/kjelly/pilot/internal/delivery"
)

// ErrUnsettled is what a users-groups run ends with when every Go operation was
// applied and verified (or there was nothing to apply) and only the authorization
// cache obligation is owed: no playbook ran to settle it, so clients may keep an
// old authorization until their cache expires (spec §6.2, D13). It wraps
// delivery.ErrPartiallyApplied, so the transaction ends as partial_failed, and the
// command reads it for exit code 4. A caller wraps it with the message that says
// where the obligation comes from.
var ErrUnsettled = fmt.Errorf("authorization cache obligation not settled: %w", delivery.ErrPartiallyApplied)

// The sources of an owed obligation (the identity.auth_cache event's source).
const (
	// ObligationThisRun: the entry ran in this run, so the journal on the server owes
	// a refresh: Go has written, or the first plan said it would.
	ObligationThisRun = "this_run"
	// ObligationPreviousRun: nothing was written but the probe found the journal
	// owing, from an earlier run.
	ObligationPreviousRun = "previous_run"
)

// Obligation is whether the authorization cache is owed a refresh after a run, and
// where that comes from. A users-groups run never refreshes (it runs no playbook), so
// the obligation is owed whenever the entry ran or the probe found it so.
type Obligation struct {
	Owed   bool
	Source string // ObligationThisRun or ObligationPreviousRun when Owed
}

// Obligation reads the run's entry report: the entry ran (prepare), or the idle probe
// found the journal owing. A run that did neither (it stopped before the entry, or the
// probe found nothing owed) owes nothing it did not owe before.
func (r Result) Obligation() Obligation {
	switch {
	case r.Entry.Ran:
		return Obligation{Owed: true, Source: ObligationThisRun}
	case r.Entry.Pending != nil && *r.Entry.Pending:
		return Obligation{Owed: true, Source: ObligationPreviousRun}
	}
	return Obligation{}
}
