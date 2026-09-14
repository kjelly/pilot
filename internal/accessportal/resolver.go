package accessportal

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/kjelly/pilot/internal/freeipaaccess"
)

// sshService is Portal v1's only handled HBAC service (spec.md §15.3).
const sshService = "sshd"

// Resolver computes one gateway's scoped access using only
// internal/freeipaaccess.Provider — never roster, inventory, or local
// state.
type Resolver struct {
	Provider freeipaaccess.Provider
	Gateway  GatewayConfig
	// Now defaults to time.Now; overridable so sudo time-window tests are
	// deterministic.
	Now func() time.Time
}

// NewResolver builds a Resolver for one gateway instance.
func NewResolver(p freeipaaccess.Provider, gw GatewayConfig) *Resolver {
	return &Resolver{Provider: p, Gateway: gw}
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// ResolveGatewayScope expands gateway.target_hostgroup into its complete
// host set (spec.md §14). It fails closed (spec.md §9.5): any error here
// — target_hostgroup missing, unreadable, or a genuine transport failure
// — must be treated by the caller as "no hosts, deny", never as "fall
// back to some other scope."
func (r *Resolver) ResolveGatewayScope(ctx context.Context) (GatewayScope, error) {
	hg, err := r.Provider.HostgroupShow(ctx, r.Gateway.TargetHostgroup)
	if err != nil {
		return GatewayScope{}, fmt.Errorf("resolve gateway target hostgroup %q: %w", r.Gateway.TargetHostgroup, err)
	}
	hosts := make(map[string]struct{}, len(hg.MemberHosts)+len(hg.IndirectMemberHosts))
	for _, h := range hg.MemberHosts {
		hosts[CanonicalizeFQDN(h)] = struct{}{}
	}
	for _, h := range hg.IndirectMemberHosts {
		hosts[CanonicalizeFQDN(h)] = struct{}{}
	}
	return GatewayScope{
		GatewayID:       r.Gateway.ID,
		Scope:           r.Gateway.Scope,
		TargetHostgroup: r.Gateway.TargetHostgroup,
		Hosts:           hosts,
	}, nil
}

// ResolveUserContext loads a user's effective group membership. Direct
// and indirect groups both come from one user_show call — FreeIPA's own
// memberof plugin computes the transitive closure server-side (see
// internal/freeipaaccess.User's doc comment); this is a union, not a
// graph walk.
func (r *Resolver) ResolveUserContext(ctx context.Context, username string) (UserContext, error) {
	u, err := r.Provider.UserShow(ctx, username)
	if err != nil {
		return UserContext{}, fmt.Errorf("resolve user %q: %w", username, err)
	}
	effective := make(map[string]struct{}, len(u.DirectGroups)+len(u.IndirectGroups))
	for _, g := range u.DirectGroups {
		effective[g] = struct{}{}
	}
	for _, g := range u.IndirectGroups {
		effective[g] = struct{}{}
	}
	return UserContext{
		Username:        u.Username,
		DirectGroups:    slices.Clone(u.DirectGroups),
		EffectiveGroups: sortedKeys(effective),
	}, nil
}

// LoadUserAccess is the top-level per-user, per-gateway resolve (spec.md
// §19/§21): gateway scope ∩ effective FreeIPA SSH access, with sudo
// detail for every host the user can actually reach. Follows the §21
// Query Plan: one call each for gateway scope, user context, hbacrule_find
// and sudorule_find, then one call per DISTINCT hostgroup/service-group/
// sudo-command-group referenced by any rule (deduped) — never one call
// per host.
func (r *Resolver) LoadUserAccess(ctx context.Context, username string) (UserAccess, error) {
	scope, err := r.ResolveGatewayScope(ctx)
	if err != nil {
		return UserAccess{}, err
	}
	userCtx, err := r.ResolveUserContext(ctx, username)
	if err != nil {
		return UserAccess{}, err
	}
	effectiveGroups := make(map[string]struct{}, len(userCtx.EffectiveGroups))
	for _, g := range userCtx.EffectiveGroups {
		effectiveGroups[g] = struct{}{}
	}

	hbacRules, err := r.Provider.HBACRuleFind(ctx)
	if err != nil {
		return UserAccess{}, fmt.Errorf("hbacrule_find: %w", err)
	}
	sudoRules, err := r.Provider.SudoRuleFind(ctx)
	if err != nil {
		return UserAccess{}, fmt.Errorf("sudorule_find: %w", err)
	}

	hostgroupHosts, err := r.expandReferencedHostgroups(ctx, hbacRules, sudoRules)
	if err != nil {
		return UserAccess{}, err
	}
	serviceGroupServices, err := r.expandReferencedServiceGroups(ctx, hbacRules)
	if err != nil {
		return UserAccess{}, err
	}
	commandGroupCommands, err := r.expandReferencedCommandGroups(ctx, sudoRules)
	if err != nil {
		return UserAccess{}, err
	}

	now := r.now()
	hosts := sortedKeys(scope.Hosts)

	result := UserAccess{User: username, GeneratedAt: now}
	for _, fqdn := range hosts {
		ssh := resolveSSHAccess(hbacRules, username, effectiveGroups, fqdn, hostgroupHosts, serviceGroupServices)
		if !ssh.Allowed {
			// spec.md §9.3: My Hosts only lists hosts the user can SSH to.
			continue
		}
		sudo := resolveSudoAccess(sudoRules, now, username, effectiveGroups, fqdn, hostgroupHosts, commandGroupCommands)
		result.Hosts = append(result.Hosts, HostAccess{FQDN: fqdn, SSH: ssh, Sudo: sudo})
	}
	return result, nil
}

func resolveSSHAccess(
	rules []freeipaaccess.HBACRule,
	username string,
	effectiveGroups map[string]struct{},
	fqdn string,
	hostgroupHosts map[string]map[string]struct{},
	serviceGroupServices map[string]map[string]struct{},
) SSHAccess {
	var matched []RuleSource
	for _, rule := range rules {
		if ok, src := hbacRuleGrants(rule, username, effectiveGroups, fqdn, hostgroupHosts, sshService, serviceGroupServices); ok {
			matched = append(matched, src)
		}
	}
	return SSHAccess{Allowed: len(matched) > 0, Rules: matched}
}

func resolveSudoAccess(
	rules []freeipaaccess.SudoRule,
	now time.Time,
	username string,
	effectiveGroups map[string]struct{},
	fqdn string,
	hostgroupHosts map[string]map[string]struct{},
	commandGroupCommands map[string]map[string]struct{},
) SudoAccess {
	var matchedRules []SudoRuleSource
	allow := map[string]struct{}{}
	deny := map[string]struct{}{}
	anyCategoryAll := false
	anyDeny := false
	for _, rule := range rules {
		ok, src := sudoRuleGrants(rule, now, username, effectiveGroups, fqdn, hostgroupHosts)
		if !ok {
			continue
		}
		matchedRules = append(matchedRules, src)
		if rule.CommandCategoryAll {
			anyCategoryAll = true
		}
		for _, c := range rule.AllowCommands {
			allow[c] = struct{}{}
		}
		for _, g := range rule.AllowCommandGroups {
			maps.Copy(allow, commandGroupCommands[g])
		}
		if len(rule.DenyCommands) > 0 || len(rule.DenyCommandGroups) > 0 {
			anyDeny = true
		}
		for _, c := range rule.DenyCommands {
			deny[c] = struct{}{}
		}
		for _, g := range rule.DenyCommandGroups {
			maps.Copy(deny, commandGroupCommands[g])
		}
	}
	return SudoAccess{
		Scope:         sudoDisplayScope(len(matchedRules) > 0, anyCategoryAll, anyDeny),
		AllowCommands: sortedKeys(allow),
		DenyCommands:  sortedKeys(deny),
		Rules:         matchedRules,
	}
}

// expandReferencedHostgroups fetches, once per distinct name, the full
// host set (spec.md §14 logic) of every hostgroup any HBAC/sudo rule
// references — never gateway.TargetHostgroup redundantly if a rule
// happens to reference it too (map dedup handles that for free).
func (r *Resolver) expandReferencedHostgroups(ctx context.Context, hbacRules []freeipaaccess.HBACRule, sudoRules []freeipaaccess.SudoRule) (map[string]map[string]struct{}, error) {
	names := map[string]struct{}{}
	for _, rule := range hbacRules {
		for _, hg := range rule.Hostgroups {
			names[hg] = struct{}{}
		}
	}
	for _, rule := range sudoRules {
		for _, hg := range rule.Hostgroups {
			names[hg] = struct{}{}
		}
	}
	result := make(map[string]map[string]struct{}, len(names))
	for name := range names {
		hg, err := r.Provider.HostgroupShow(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("hostgroup_show %q: %w", name, err)
		}
		set := make(map[string]struct{}, len(hg.MemberHosts)+len(hg.IndirectMemberHosts))
		for _, h := range hg.MemberHosts {
			set[CanonicalizeFQDN(h)] = struct{}{}
		}
		for _, h := range hg.IndirectMemberHosts {
			set[CanonicalizeFQDN(h)] = struct{}{}
		}
		result[name] = set
	}
	return result, nil
}

func (r *Resolver) expandReferencedServiceGroups(ctx context.Context, hbacRules []freeipaaccess.HBACRule) (map[string]map[string]struct{}, error) {
	names := map[string]struct{}{}
	for _, rule := range hbacRules {
		for _, sg := range rule.ServiceGroups {
			names[sg] = struct{}{}
		}
	}
	result := make(map[string]map[string]struct{}, len(names))
	for name := range names {
		sg, err := r.Provider.HBACServiceGroupShow(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("hbacsvcgroup_show %q: %w", name, err)
		}
		set := make(map[string]struct{}, len(sg.Services))
		for _, s := range sg.Services {
			set[s] = struct{}{}
		}
		result[name] = set
	}
	return result, nil
}

func (r *Resolver) expandReferencedCommandGroups(ctx context.Context, sudoRules []freeipaaccess.SudoRule) (map[string]map[string]struct{}, error) {
	names := map[string]struct{}{}
	for _, rule := range sudoRules {
		for _, g := range rule.AllowCommandGroups {
			names[g] = struct{}{}
		}
		for _, g := range rule.DenyCommandGroups {
			names[g] = struct{}{}
		}
	}
	result := make(map[string]map[string]struct{}, len(names))
	for name := range names {
		cg, err := r.Provider.SudoCommandGroupShow(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("sudocmdgroup_show %q: %w", name, err)
		}
		set := make(map[string]struct{}, len(cg.Commands))
		for _, c := range cg.Commands {
			set[c] = struct{}{}
		}
		result[name] = set
	}
	return result, nil
}

func sortedKeys(m map[string]struct{}) []string {
	out := slices.Collect(maps.Keys(m))
	slices.Sort(out)
	return out
}

// CanonicalizeFQDN implements spec.md §14's FQDN canonicalization rule
// ("lowercase, trim trailing dot for identity comparison"), applied
// everywhere a host name enters a set this package compares against.
func CanonicalizeFQDN(fqdn string) string {
	return strings.ToLower(strings.TrimSuffix(fqdn, "."))
}
