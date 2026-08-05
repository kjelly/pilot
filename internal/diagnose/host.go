package diagnose

import (
	"fmt"

	"github.com/kjelly/pilot/internal/networkcheck"
)

// ValidateHost requires host to be an *exact* key in resolved.HostVars.
// Diagnose deliberately never treats an MCP caller's host string as an
// ansible *pattern* — unlike internal/tools/per_host_verify.go's
// listAnsibleHosts, which by design expands patterns/groups for
// `pilot verify` (the wrong helper to reuse here) — because a value like
// "all", "*", or a group name would otherwise silently "resolve" to the
// entire fleet instead of failing closed on an unknown single host.
func ValidateHost(resolved networkcheck.ResolvedInventory, host string) error {
	if _, ok := resolved.HostVars[host]; !ok {
		return fmt.Errorf("host %q is not a known inventory host", host)
	}
	return nil
}
