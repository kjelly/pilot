package accessportal

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/kjelly/pilot/internal/freeipaaccess"
)

// PolicySnapshot is everything about one user's FreeIPA policy that does
// NOT depend on which gateway scope it is being resolved against: their
// effective group membership, every HBAC/sudo rule (hbacrule_find/
// sudorule_find are already global, unfiltered by scope), and the
// referenced hostgroup/service-group/command-group expansions those rules
// point at. The one thing it deliberately excludes is the gateway's own
// target_hostgroup expansion — that's scope-specific and stays in
// ResolveScopeAccess (via the existing ResolveGatewayScope).
//
// Loading this once per user and calling ResolveScopeAccess once per
// scope is what keeps a cross-scope caller's (pilot-access-directory)
// FreeIPA query count at O(1) for the policy data regardless of how many
// scopes a user has access to (docs/tmp/now/spec.md §9.3) — the opposite
// of "M scopes × a full LoadUserAccess" duplicated per scope.
type PolicySnapshot struct {
	User           UserContext
	HBACRules      []freeipaaccess.HBACRule
	SudoRules      []freeipaaccess.SudoRule
	HostgroupHosts map[string]map[string]struct{}
	ServiceGroups  map[string]map[string]struct{}
	CommandGroups  map[string]map[string]struct{}
	GeneratedAt    time.Time

	// hostAnnotations is an unexported, shared-by-reference cache: copying
	// a PolicySnapshot by value (as ResolveScopeAccess's signature does)
	// still shares the same cache, so a host appearing in more than one
	// scope's target hostgroup is HostShow'd at most once for the whole
	// snapshot's lifetime, no matter how many times ResolveScopeAccess is
	// called against it (docs/tmp/now/spec.md §9.3).
	hostAnnotations *hostAnnotationCache
}

// hostAnnotationCache memoizes HostShow-derived annotations by canonical
// FQDN. A failed lookup is cached too (as "no annotations"), matching
// LoadUserAccess's existing per-host failure isolation — annotations are
// display-only asset metadata, never an authorization input, so a
// transient host_show failure must not retry indefinitely within one
// snapshot's short lifetime, and must never fail the whole listing.
type hostAnnotationCache struct {
	mu      sync.Mutex
	fetched map[string]bool
	byFQDN  map[string]map[string]string
}

func newHostAnnotationCache() *hostAnnotationCache {
	return &hostAnnotationCache{fetched: map[string]bool{}, byFQDN: map[string]map[string]string{}}
}

func (c *hostAnnotationCache) get(ctx context.Context, provider freeipaaccess.Provider, fqdn string) map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fetched[fqdn] {
		return c.byFQDN[fqdn]
	}
	c.fetched[fqdn] = true
	if host, err := provider.HostShow(ctx, fqdn); err == nil {
		c.byFQDN[fqdn] = host.Annotations
	}
	return c.byFQDN[fqdn]
}

// LoadPolicySnapshot loads the query plan spec.md §9.3/§21 describes for
// one user: one UserShow (via ResolveUserContext), one hbacrule_find, one
// sudorule_find, then one call per DISTINCT referenced hostgroup/
// service-group/command-group — never anything gateway-scope-specific.
func LoadPolicySnapshot(ctx context.Context, provider freeipaaccess.Provider, username string, now time.Time) (PolicySnapshot, error) {
	r := &Resolver{Provider: provider}

	userCtx, err := r.ResolveUserContext(ctx, username)
	if err != nil {
		return PolicySnapshot{}, err
	}

	hbacRules, err := provider.HBACRuleFind(ctx)
	if err != nil {
		return PolicySnapshot{}, fmt.Errorf("hbacrule_find: %w", err)
	}
	sudoRules, err := provider.SudoRuleFind(ctx)
	if err != nil {
		return PolicySnapshot{}, fmt.Errorf("sudorule_find: %w", err)
	}

	hostgroupHosts, err := r.expandReferencedHostgroups(ctx, hbacRules, sudoRules)
	if err != nil {
		return PolicySnapshot{}, err
	}
	serviceGroups, err := r.expandReferencedServiceGroups(ctx, hbacRules)
	if err != nil {
		return PolicySnapshot{}, err
	}
	commandGroups, err := r.expandReferencedCommandGroups(ctx, sudoRules)
	if err != nil {
		return PolicySnapshot{}, err
	}

	return PolicySnapshot{
		User:            userCtx,
		HBACRules:       hbacRules,
		SudoRules:       sudoRules,
		HostgroupHosts:  hostgroupHosts,
		ServiceGroups:   serviceGroups,
		CommandGroups:   commandGroups,
		GeneratedAt:     now,
		hostAnnotations: newHostAnnotationCache(),
	}, nil
}

// ResolveScopeAccess resolves one gateway scope's SSH/sudo access for a
// user against an already-loaded PolicySnapshot: gateway scope ∩
// effective FreeIPA SSH access, with sudo detail for every reachable host
// (spec.md §19/§21) — the same result LoadUserAccess has always computed,
// just with the scope-independent policy data factored out.
func ResolveScopeAccess(ctx context.Context, provider freeipaaccess.Provider, snapshot PolicySnapshot, gateway GatewayConfig) (UserAccess, error) {
	r := &Resolver{Provider: provider, Gateway: gateway}
	scope, err := r.ResolveGatewayScope(ctx)
	if err != nil {
		return UserAccess{}, err
	}

	effectiveGroups := make(map[string]struct{}, len(snapshot.User.EffectiveGroups))
	for _, g := range snapshot.User.EffectiveGroups {
		effectiveGroups[g] = struct{}{}
	}

	cache := snapshot.hostAnnotations
	if cache == nil {
		cache = newHostAnnotationCache()
	}

	result := UserAccess{User: snapshot.User.Username, GeneratedAt: snapshot.GeneratedAt}
	for _, fqdn := range sortedKeys(scope.Hosts) {
		ssh := resolveSSHAccess(snapshot.HBACRules, snapshot.User.Username, effectiveGroups, fqdn, snapshot.HostgroupHosts, snapshot.ServiceGroups)
		if !ssh.Allowed {
			// spec.md §9.3: My Hosts only lists hosts the user can SSH to.
			continue
		}
		sudo := resolveSudoAccess(snapshot.SudoRules, snapshot.GeneratedAt, snapshot.User.Username, effectiveGroups, fqdn, snapshot.HostgroupHosts, snapshot.CommandGroups)
		annotations := cache.get(ctx, provider, fqdn)
		result.Hosts = append(result.Hosts, HostAccess{FQDN: fqdn, SSH: ssh, Sudo: sudo, Annotations: annotations})
	}
	return result, nil
}
