package accessdirectory

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/kjelly/pilot/internal/accessportal"
	"github.com/kjelly/pilot/internal/freeipaaccess"
)

// LoadScopeCatalog discovers every scope with a published target
// hostgroup (pilot-target-<scope> by default) and, for each, which
// Gateway instances currently serve it (pilot-gateway-<scope>) — the live
// source of truth pilot-access-directory reads for routing (spec.md D3:
// never derived from a Gateway's hostname).
//
// HostgroupFind's own result (spec.md §8.2) is name-only — it does not
// return the transitive host closure hostgroup_find omits
// (memberindirect_host) — so this still needs one HostgroupShow per
// discovered GATEWAY hostgroup to resolve GatewayFQDNs. Target
// hostgroups' own host closures are deliberately NOT resolved here: that
// happens once per scope inside accessportal.ResolveScopeAccess
// (ResolveGatewayScope), so a target hostgroup that fails to resolve
// surfaces as that one scope's resolve failing (see LoadDirectoryAccess),
// not as a catalog-load failure.
//
// A scope with a target hostgroup but no matching gateway hostgroup is
// not an error — it is exactly the "no_gateway" route state a caller
// must surface (spec.md §13.1: shown, but Connect disabled), not
// something to fail closed on. Likewise, a gateway hostgroup that
// HostgroupFind discovers but then fails to HostgroupShow (deleted
// concurrently, transient failure) degrades only that ONE scope to
// "no_gateway" rather than failing the whole catalog load — the same
// per-scope isolation LoadDirectoryAccess already applies to a broken
// target hostgroup, applied here to a broken gateway hostgroup so one
// scope's race/outage can never take every other scope's routing down
// with it.
func LoadScopeCatalog(ctx context.Context, provider freeipaaccess.Provider, finder freeipaaccess.HostgroupFinder, targetPrefix, gatewayPrefix string) ([]ScopeRoute, error) {
	targetGroups, err := finder.HostgroupFind(ctx, targetPrefix)
	if err != nil {
		return nil, fmt.Errorf("hostgroup_find %q: %w", targetPrefix, err)
	}
	gatewayGroups, err := finder.HostgroupFind(ctx, gatewayPrefix)
	if err != nil {
		return nil, fmt.Errorf("hostgroup_find %q: %w", gatewayPrefix, err)
	}

	// hostgroup_find is a substring match, not a prefix match (spec.md
	// §8.1/HostgroupFinder doc comment) — never trust a result as
	// prefixed without checking, even though "pilot-target-"/
	// "pilot-gateway-" style criteria behave like a prefix match today.
	gatewayByScope := make(map[string]string, len(gatewayGroups))
	for _, g := range gatewayGroups {
		if !strings.HasPrefix(g.Name, gatewayPrefix) {
			continue
		}
		gatewayByScope[strings.TrimPrefix(g.Name, gatewayPrefix)] = g.Name
	}

	routes := make([]ScopeRoute, 0, len(targetGroups))
	for _, t := range targetGroups {
		if !strings.HasPrefix(t.Name, targetPrefix) {
			continue
		}
		scope := strings.TrimPrefix(t.Name, targetPrefix)
		route := ScopeRoute{Scope: scope, TargetHostgroup: t.Name, GatewayHostgroup: gatewayPrefix + scope}

		if gwName, ok := gatewayByScope[scope]; ok {
			hg, err := provider.HostgroupShow(ctx, gwName)
			if err != nil {
				// Fail this ONE scope's gateway resolution closed (empty
				// GatewayFQDNs -> "no_gateway"), not the entire catalog —
				// see the doc comment above.
				route.GatewayHostgroup = gwName
			} else {
				route.GatewayHostgroup = gwName
				route.GatewayFQDNs = canonicalizedHostSet(hg)
			}
		}

		routes = append(routes, route)
	}

	sort.Slice(routes, func(i, j int) bool { return routes[i].Scope < routes[j].Scope })
	return routes, nil
}

// canonicalizedHostSet mirrors accessportal's own MemberHosts ∪
// IndirectMemberHosts ∪ canonicalize ∪ dedupe rule (spec.md §14) for
// gateway-instance hostgroups, the same treatment target hostgroups get
// inside accessportal.ResolveGatewayScope.
func canonicalizedHostSet(hg freeipaaccess.Hostgroup) []string {
	set := make(map[string]struct{}, len(hg.MemberHosts)+len(hg.IndirectMemberHosts))
	for _, h := range hg.MemberHosts {
		set[accessportal.CanonicalizeFQDN(h)] = struct{}{}
	}
	for _, h := range hg.IndirectMemberHosts {
		set[accessportal.CanonicalizeFQDN(h)] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}
