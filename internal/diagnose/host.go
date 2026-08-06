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

// ResolveSingletonGroupHost resolves the exactly-one host in inventory
// group group ("dashboard", "thanos-query" — both contractually
// hostCardinality: exactly-one, see contracts/dashboard.yaml and
// contracts/thanos-query.yaml). Unlike ValidateHost, there is no
// caller-supplied host to check here — the logs/metrics checks target a
// fixed central role, not an arbitrary host, so this resolves it directly
// from the inventory instead of asking the MCP caller to name it. Returns
// an error naming the group and actual host count when it's empty or has
// more than one host, since either means there's no safe host to guess.
func ResolveSingletonGroupHost(resolved networkcheck.ResolvedInventory, group string) (string, error) {
	hosts := resolved.GroupHosts[group]
	switch len(hosts) {
	case 0:
		return "", fmt.Errorf("inventory group %q has no hosts — is the %q role deployed in this inventory?", group, group)
	case 1:
		return hosts[0], nil
	default:
		return "", fmt.Errorf("inventory group %q has %d hosts, expected exactly one (hostCardinality: exactly-one)", group, len(hosts))
	}
}
