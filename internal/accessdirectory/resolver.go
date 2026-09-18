package accessdirectory

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/kjelly/pilot/internal/accessportal"
	"github.com/kjelly/pilot/internal/freeipaaccess"
)

// LoadDirectoryAccess computes one user's cross-scope access (spec.md
// §9/§10): one LoadScopeCatalog, one accessportal.LoadPolicySnapshot,
// then one accessportal.ResolveScopeAccess per discovered scope — never a
// second, duplicated authorization engine (spec.md §9/§49.12's explicit
// prohibition). Every scope's resolve reuses the SAME snapshot value, so
// HBACRuleFind/SudoRuleFind/UserShow and the referenced hostgroup/
// service-group/command-group expansions happen exactly once per call,
// regardless of how many scopes exist (spec.md §9.3) — and a host
// reachable via more than one scope is HostShow'd for annotations only
// once too, via the snapshot's shared hostAnnotationCache.
//
// Fail-closed semantics are per-scope, not per-call (spec.md §9.5/§20
// Case B/D): if one scope's ResolveScopeAccess errors — its
// target_hostgroup was deleted or became unreadable between
// LoadScopeCatalog and this call, a genuine transport failure, etc. —
// that scope simply contributes nothing to the merged result, exactly
// like a single host_show failure never takes down accessportal's whole
// listing. A user who genuinely has no access anywhere is a valid, empty
// DirectoryAccess, not an error. But if EVERY discovered scope fails to
// resolve, that is symptomatic of a real outage/misconfiguration (not
// "this user has no grants") and must not be silently rendered as an
// empty-but-successful result — it is returned as an error instead.
func LoadDirectoryAccess(ctx context.Context, provider freeipaaccess.Provider, finder freeipaaccess.HostgroupFinder, username, targetPrefix, gatewayPrefix string, now time.Time) (DirectoryAccess, error) {
	routes, err := LoadScopeCatalog(ctx, provider, finder, targetPrefix, gatewayPrefix)
	if err != nil {
		return DirectoryAccess{}, err
	}

	snapshot, err := accessportal.LoadPolicySnapshot(ctx, provider, username, now)
	if err != nil {
		return DirectoryAccess{}, err
	}

	byFQDN := map[string]*DirectoryTarget{}
	order := make([]string, 0)

	var lastErr error
	resolvedScopes := 0
	for _, route := range routes {
		gw := accessportal.GatewayConfig{ID: route.Scope, Scope: route.Scope, TargetHostgroup: route.TargetHostgroup}
		access, err := accessportal.ResolveScopeAccess(ctx, provider, snapshot, gw)
		if err != nil {
			lastErr = err
			continue
		}
		resolvedScopes++

		tr := TargetRoute{
			Scope:             route.Scope,
			TargetHostgroup:   route.TargetHostgroup,
			GatewayHostgroup:  route.GatewayHostgroup,
			GatewayCandidates: route.GatewayFQDNs,
			RouteStatus:       routeStatus(route),
		}

		for _, host := range access.Hosts {
			target, ok := byFQDN[host.FQDN]
			if !ok {
				target = &DirectoryTarget{FQDN: host.FQDN, SSH: host.SSH, Sudo: host.Sudo}
				byFQDN[host.FQDN] = target
				order = append(order, host.FQDN)
			}
			target.Routes = append(target.Routes, tr)
		}
	}

	if len(routes) > 0 && resolvedScopes == 0 {
		return DirectoryAccess{}, fmt.Errorf("resolve directory access for %q: every discovered scope failed, last error: %w", username, lastErr)
	}

	targets := make([]DirectoryTarget, 0, len(byFQDN))
	for _, fqdn := range order {
		t := *byFQDN[fqdn]
		sort.Slice(t.Routes, func(i, j int) bool { return t.Routes[i].Scope < t.Routes[j].Scope })
		targets = append(targets, t)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].FQDN < targets[j].FQDN })

	return DirectoryAccess{User: snapshot.User.Username, GeneratedAt: now, Targets: targets}, nil
}

func routeStatus(route ScopeRoute) string {
	if len(route.GatewayFQDNs) == 0 {
		return "no_gateway"
	}
	// TODO(spec.md §19 Phase 5): bounded TCP/22 reachability probe against
	// each GatewayFQDN candidate before calling this route "ready". Phase
	// 3 has no network probing yet, so "a live pilot-gateway-<scope>
	// member exists" is as far as readiness goes for now.
	return "ready"
}
