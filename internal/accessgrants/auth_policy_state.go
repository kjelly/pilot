// auth_policy_state.go implements spec.md §11's prune half: a stale
// krbPrincipalAuthInd left on a host after its governing auth_policies
// entry is removed from the roster (confirmed live — see
// playbooks/apply/freeipa-identity-apply.yml's host-mod task header
// comment). Unlike HBAC/sudo rules (CompiledLoginRuleName/
// CompiledSudoRuleName), krbPrincipalAuthInd is a plain attribute with no
// pilot-owned naming convention to diff against, so there is no way to
// tell "Pilot set this" from "an admin set this by hand" except by
// remembering what Pilot itself last set — the same reason breakglass.go
// keeps its own local statefile rather than trusting only the roster.
package accessgrants

import (
	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/statefile"
)

const authPolicyStateVersion = 1

const authPolicyStateFilename = "auth-policy-hosts.json"

// authPolicyHostRecord is one host's last-known Pilot-managed indicator
// set, as of the most recent successful reconcile.
type authPolicyHostRecord struct {
	Host       string   `json:"host"`
	Indicators []string `json:"indicators"`
}

func openAuthPolicyStore(stateDir string) (*statefile.Store[authPolicyHostRecord], error) {
	return statefile.New[authPolicyHostRecord](stateDir, authPolicyStateFilename, authPolicyStateVersion, "auth_policy_hosts")
}

// planAuthPolicyPrune diffs desired (this reconcile's freshly compiled
// auth_policies hosts) against stateDir's previously recorded state, and
// returns one CompiledAuthPolicyHost per host that WAS Pilot-managed but
// is no longer in desired — each with an empty Indicators, which the
// apply playbook's host-mod task treats as "explicitly clear
// krbPrincipalAuthInd" rather than "leave alone" (a bare host-mod with no
// --auth-ind flag at all does not clear it — that was the original bug).
func planAuthPolicyPrune(stateDir string, desired []inventory.CompiledAuthPolicyHost) ([]inventory.CompiledAuthPolicyHost, error) {
	store, err := openAuthPolicyStore(stateDir)
	if err != nil {
		return nil, err
	}
	previous, err := store.Load()
	if err != nil {
		return nil, err
	}
	desiredHosts := make(map[string]bool, len(desired))
	for _, h := range desired {
		desiredHosts[h.Host] = true
	}
	var prune []inventory.CompiledAuthPolicyHost
	for _, rec := range previous {
		if desiredHosts[rec.Host] {
			continue
		}
		prune = append(prune, inventory.CompiledAuthPolicyHost{Host: rec.Host})
	}
	return prune, nil
}

// recordAuthPolicyState overwrites stateDir's recorded state with desired
// — the caller MUST only call this after applyPlan has actually succeeded,
// so a failed apply never causes Pilot to "forget" indicators that may
// still be live on FreeIPA (mirroring breakglass.Activate's own
// apply-then-record ordering).
func recordAuthPolicyState(stateDir string, desired []inventory.CompiledAuthPolicyHost) error {
	store, err := openAuthPolicyStore(stateDir)
	if err != nil {
		return err
	}
	records := make([]authPolicyHostRecord, 0, len(desired))
	for _, h := range desired {
		records = append(records, authPolicyHostRecord{Host: h.Host, Indicators: h.Indicators})
	}
	return store.Save(records)
}
