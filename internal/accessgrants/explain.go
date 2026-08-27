// explain.go implements spec.md §16's full 4-source picture: it combines
// internal/inventory's roster-based ExplainStaticHBAC/ExplainGrants/
// ExplainBreakglassDefinitions with this package's own breakglass
// activation state (internal/inventory cannot see that state without an
// import cycle — see that package's explain.go header comment).
package accessgrants

import (
	"time"

	"github.com/kjelly/pilot/internal/inventory"
)

// Explain returns every source (static_hbac, temporary_grant, sudo_grant,
// breakglass) that currently grants (user, host, service), evaluated
// against now. rosterFile MUST have already passed
// inventory.ValidateRosterFile.
func Explain(rosterFile, stateDir, user, host, service string, now time.Time) ([]inventory.ExplainSource, error) {
	root, err := inventory.ReadRosterAsMapFile(rosterFile)
	if err != nil {
		return nil, err
	}

	out := inventory.ExplainStaticHBAC(root, user, host, service)

	grantSources, err := inventory.ExplainGrants(root, user, host, service, now)
	if err != nil {
		return nil, err
	}
	out = append(out, grantSources...)

	// A breakglass definition candidate only becomes a real source once
	// it has a currently active activation (spec.md §14) — the
	// definition alone never grants anything.
	for _, candidate := range inventory.ExplainBreakglassDefinitions(root, user, host, service) {
		activations, err := Status(stateDir, candidate.Rule)
		if err != nil {
			return nil, err
		}
		for _, a := range activations {
			if !a.IsActive(now) {
				continue
			}
			expiresAt := a.ExpiresAt
			candidate.NextTransition = &expiresAt
			out = append(out, candidate)
			break
		}
	}

	return out, nil
}
