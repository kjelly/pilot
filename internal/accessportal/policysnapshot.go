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
// effective group membership, the active HBAC/sudo rules matching that user
// (hbacrule_find/sudorule_find remain global, unfiltered by scope), and the
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

	// hostMetadata is an unexported, shared-by-reference cache: copying a
	// PolicySnapshot by value (as ResolveScopeAccess's signature does) still
	// shares the same cache, so a host appearing in more than one scope's
	// target hostgroup is HostShow'd at most once for the whole snapshot's
	// lifetime, no matter how many times ResolveScopeAccess is called
	// against it (docs/tmp/now/spec.md §9.3).
	hostMetadata *hostMetadataCache
}

// hostMetadataResult is one cached HostShow outcome — success or failure.
type hostMetadataResult struct {
	Host freeipaaccess.Host
	Err  error
}

// hostMetadataCache memoizes HostShow results by canonical FQDN for one
// snapshot (per-host recording spec §11.1/§51). Failures are cached too:
// annotations stay best-effort display data, but the recording policy is a
// runtime input, so the error is kept rather than collapsed into "no
// annotations" — a connect decision must be able to tell "absent" from
// "could not read". The map is guarded by mu; each entry's RPC runs under
// its own sync.Once, outside mu, so distinct hosts are fetched concurrently
// and one host is fetched exactly once.
type hostMetadataCache struct {
	mu      sync.Mutex
	entries map[string]*hostMetadataEntry
}

type hostMetadataEntry struct {
	once   sync.Once
	result hostMetadataResult
}

func newHostMetadataCache() *hostMetadataCache {
	return &hostMetadataCache{entries: map[string]*hostMetadataEntry{}}
}

func (c *hostMetadataCache) get(ctx context.Context, provider freeipaaccess.Provider, fqdn string) hostMetadataResult {
	c.mu.Lock()
	e, ok := c.entries[fqdn]
	if !ok {
		e = &hostMetadataEntry{}
		c.entries[fqdn] = e
	}
	c.mu.Unlock()
	e.once.Do(func() {
		host, err := provider.HostShow(ctx, fqdn)
		e.result = hostMetadataResult{Host: host, Err: err}
	})
	return e.result
}

// recordingAccessPolicy maps one cached HostShow outcome to the
// recording-policy facts a connect decision needs (per-host recording spec
// §11.2).
func recordingAccessPolicy(res hostMetadataResult) SSHRecordingAccessPolicy {
	return HostRecordingAccessPolicy(res.Host, res.Err)
}

// HostRecordingAccessPolicy converts one host_show result (host, err) to the
// recording policy the gateway resolves against (per-host recording spec
// §11): a failed host_show or an unreadable userclass is unknown, a
// malformed marker is invalid.
func HostRecordingAccessPolicy(host freeipaaccess.Host, err error) SSHRecordingAccessPolicy {
	switch p := host.SSHRecording; {
	case err != nil:
		return SSHRecordingAccessPolicy{Reason: "host_show_failed"}
	case p.Unreadable:
		return SSHRecordingAccessPolicy{Reason: "userclass_unreadable"}
	case !p.Valid:
		return SSHRecordingAccessPolicy{Known: true, Reason: p.Reason}
	default:
		return SSHRecordingAccessPolicy{Known: true, Valid: true, Override: p.Mode}
	}
}

// LoadPolicySnapshot loads the query plan spec.md §9.3/§21 describes for
// one user: one UserShow (via ResolveUserContext), one hbacrule_find, one
// sudorule_find, then one call per DISTINCT hostgroup/service-group/command-group
// referenced by an applicable rule — never anything gateway-scope-specific.
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

	// A snapshot belongs to one user. Rules that cannot match that user (or
	// are disabled/expired) cannot contribute SSH or sudo access, so their
	// referenced groups need no RPCs. Keep matching rules intact for provenance.
	effectiveGroups := make(map[string]struct{}, len(userCtx.EffectiveGroups))
	for _, name := range userCtx.EffectiveGroups {
		effectiveGroups[name] = struct{}{}
	}
	applicableHBAC := make([]freeipaaccess.HBACRule, 0, len(hbacRules))
	for _, rule := range hbacRules {
		if ok, _ := subjectMatch(rule.UserCategoryAll, rule.Users, rule.Groups, userCtx.Username, effectiveGroups); rule.Enabled && ok {
			applicableHBAC = append(applicableHBAC, rule)
		}
	}
	applicableSudo := make([]freeipaaccess.SudoRule, 0, len(sudoRules))
	for _, rule := range sudoRules {
		if ok, _ := subjectMatch(rule.UserCategoryAll, rule.Users, rule.Groups, userCtx.Username, effectiveGroups); sudoRuleActive(rule, now) && ok {
			applicableSudo = append(applicableSudo, rule)
		}
	}
	hbacRules, sudoRules = applicableHBAC, applicableSudo

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
		User:           userCtx,
		HBACRules:      hbacRules,
		SudoRules:      sudoRules,
		HostgroupHosts: hostgroupHosts,
		ServiceGroups:  serviceGroups,
		CommandGroups:  commandGroups,
		GeneratedAt:    now,
		hostMetadata:   newHostMetadataCache(),
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

	cache := snapshot.hostMetadata
	if cache == nil {
		cache = newHostMetadataCache()
	}

	result := UserAccess{User: snapshot.User.Username, GeneratedAt: snapshot.GeneratedAt}
	for _, fqdn := range sortedKeys(scope.Hosts) {
		ssh := resolveSSHAccess(snapshot.HBACRules, snapshot.User.Username, effectiveGroups, fqdn, snapshot.HostgroupHosts, snapshot.ServiceGroups)
		if !ssh.Allowed {
			// spec.md §9.3: My Hosts only lists hosts the user can SSH to.
			continue
		}
		sudo := resolveSudoAccess(snapshot.SudoRules, snapshot.GeneratedAt, snapshot.User.Username, effectiveGroups, fqdn, snapshot.HostgroupHosts, snapshot.CommandGroups)
		result.Hosts = append(result.Hosts, HostAccess{FQDN: fqdn, SSH: ssh, Sudo: sudo})
	}
	names := make([]string, len(result.Hosts))
	for i, host := range result.Hosts {
		names[i] = host.FQDN
	}
	metadata, err := queryBatch(ctx, names, func(ctx context.Context, fqdn string) (hostMetadataResult, error) {
		// Preserve per-host failure isolation: a failed read marks recording
		// policy unknown; it must never become an absent/valid policy.
		return cache.get(ctx, provider, fqdn), nil
	})
	if err != nil {
		return UserAccess{}, err
	}
	for i, meta := range metadata {
		if meta.Err == nil {
			result.Hosts[i].Annotations = meta.Host.Annotations
		}
		result.Hosts[i].SSHRecording = recordingAccessPolicy(meta)
	}
	return result, nil
}
