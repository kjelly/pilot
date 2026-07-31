package networkcheck

import (
	"fmt"
	"sort"

	"github.com/kjelly/pilot/internal/contract"
)

// EdgeTarget classifies how an Edge's target host was resolved.
type EdgeTarget string

const (
	// TargetInventory means the provider component has at least one host
	// in this inventory; TargetHost is that host's resolved ansible_host.
	TargetInventory EdgeTarget = "inventory"
	// TargetExternal means the provider has no inventory host, but a
	// non-secret bound input resolved to an explicit override (§3.4 of the
	// plan); TargetHost carries whatever value that input held — which may
	// be a hostname/alias, not necessarily a raw IP.
	TargetExternal EdgeTarget = "external"
	// TargetSkip means neither of the above applied; SkipReason explains
	// why, and Required decides whether that is a preflight failure.
	TargetSkip EdgeTarget = "skip"
)

// Edge is one directed, resolved network reachability check: can
// SourceHost reach TargetHost:Port over Protocol.
type Edge struct {
	// Requirement is a stable id for this (consumer, provider, endpoint)
	// triple, independent of which hosts it expands to. Used as the
	// output/evidence key.
	Requirement string

	ConsumerComponent string
	ProviderComponent string
	EndpointName      string
	Scheme            string
	Protocol          string // "tcp" or "udp", derived from Scheme
	Port              int
	Required          bool

	SourceHost string
	SourceAddr string

	TargetKind EdgeTarget
	// TargetHost is set when TargetKind is TargetInventory or
	// TargetExternal; empty when TargetKind is TargetSkip.
	TargetHost string
	SkipReason string
}

// PlanOptions narrows what Plan expands.
type PlanOptions struct {
	// Components restricts planning to these consumer component IDs. Empty
	// means every component in the catalog is considered.
	Components []string
	// SourceHosts, when non-empty, restricts source hosts to this set
	// (already resolved from an ansible pattern by the caller — the
	// planner does not interpret ansible patterns itself).
	SourceHosts []string
}

// Plan expands the catalog's providerEndpoint dependencies against a
// resolved inventory into a sorted, deterministic list of Edges. Plan does
// not execute anything, run any shell command, or read secret values: it
// only reads GroupVar.Secret to decide whether an unresolved external
// override is safe to read.
func Plan(catalog contract.Catalog, inv ResolvedInventory, opts PlanOptions) ([]Edge, error) {
	components := catalog.Components()

	selected := make(map[string]bool, len(components))
	if len(opts.Components) == 0 {
		for _, c := range components {
			selected[c.ID] = true
		}
	} else {
		for _, id := range opts.Components {
			if _, ok := catalog.Component(id); !ok {
				return nil, fmt.Errorf("unknown component %q", id)
			}
			selected[id] = true
		}
	}

	var sourceFilter map[string]bool
	if len(opts.SourceHosts) > 0 {
		sourceFilter = make(map[string]bool, len(opts.SourceHosts))
		for _, h := range opts.SourceHosts {
			sourceFilter[h] = true
		}
	}

	var edges []Edge
	for _, consumer := range components {
		if !selected[consumer.ID] {
			continue
		}
		for _, dep := range consumer.Dependencies {
			if dep.Relation != "providerEndpoint" {
				continue
			}
			provider, ok := catalog.Component(dep.Component)
			if !ok {
				// A linted catalog cannot reach this — every dependency
				// component must exist (validateDependencyCycles walks the
				// same map). Skip defensively rather than fail the whole
				// plan on an unlinted/partial catalog.
				continue
			}

			sourceHosts := filterHosts(inv.GroupHosts[consumer.Role], sourceFilter)
			if len(sourceHosts) == 0 {
				continue
			}

			endpoints := selectEndpoints(provider.Endpoints, dep.Endpoints)
			providerHosts := inv.GroupHosts[provider.Role]

			for _, endpoint := range endpoints {
				requirement := fmt.Sprintf("%s->%s.%s", consumer.ID, provider.ID, endpoint.Name)
				protocol := protocolFor(endpoint.Scheme)
				for _, sourceHost := range sourceHosts {
					base := Edge{
						Requirement:       requirement,
						ConsumerComponent: consumer.ID,
						ProviderComponent: provider.ID,
						EndpointName:      endpoint.Name,
						Scheme:            endpoint.Scheme,
						Protocol:          protocol,
						Port:              endpoint.Port,
						Required:          dep.Required,
						SourceHost:        sourceHost,
						SourceAddr:        inv.HostAddr(sourceHost),
					}
					if len(providerHosts) > 0 {
						for _, targetHost := range providerHosts {
							e := base
							e.TargetKind = TargetInventory
							e.TargetHost = inv.HostAddr(targetHost)
							edges = append(edges, e)
						}
						continue
					}
					e := base
					target, skipReason := resolveExternalOverride(consumer, dep, inv, sourceHost)
					if skipReason != "" {
						e.TargetKind = TargetSkip
						e.SkipReason = skipReason
					} else {
						e.TargetKind = TargetExternal
						e.TargetHost = target
					}
					edges = append(edges, e)
				}
			}
		}
	}

	sort.Slice(edges, func(i, j int) bool {
		a, b := edges[i], edges[j]
		if a.Requirement != b.Requirement {
			return a.Requirement < b.Requirement
		}
		if a.SourceHost != b.SourceHost {
			return a.SourceHost < b.SourceHost
		}
		return a.TargetHost < b.TargetHost
	})
	return edges, nil
}

func filterHosts(hosts []string, filter map[string]bool) []string {
	if filter == nil {
		return hosts
	}
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if filter[h] {
			out = append(out, h)
		}
	}
	return out
}

// selectEndpoints returns provider's endpoints, restricted to filter
// (dependency.Endpoints) when non-empty, always excluding unix-socket
// endpoints — those are same-host only and have no network path to probe.
// Order is stable (by name) regardless of YAML authoring order.
func selectEndpoints(all []contract.Endpoint, filter []string) []contract.Endpoint {
	var allowed map[string]bool
	if len(filter) > 0 {
		allowed = make(map[string]bool, len(filter))
		for _, name := range filter {
			allowed[name] = true
		}
	}
	out := make([]contract.Endpoint, 0, len(all))
	for _, e := range all {
		if e.Scheme == "unix" {
			continue
		}
		if allowed != nil && !allowed[e.Name] {
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func protocolFor(scheme string) string {
	if scheme == "udp" {
		return "udp"
	}
	return "tcp"
}

// resolveExternalOverride implements §3.4 of the plan for a provider that
// has zero hosts in this inventory: look for the binding this dependency
// satisfies, and read its bound input's fully-rendered value for
// sourceHost. Returns ("", reason) when there is nothing safe to probe.
func resolveExternalOverride(consumer contract.Contract, dep contract.Dependency, inv ResolvedInventory, sourceHost string) (target, skipReason string) {
	var binding *contract.Binding
	for i := range consumer.Bindings {
		if consumer.Bindings[i].From.Component == dep.Component {
			binding = &consumer.Bindings[i]
			break
		}
	}
	if binding == nil {
		return "", fmt.Sprintf("provider %q has no hosts in this inventory and no binding declares an override input to check", dep.Component)
	}
	for i := range consumer.GroupVars {
		if consumer.GroupVars[i].Name == binding.Input && consumer.GroupVars[i].Secret {
			return "", fmt.Sprintf("input %q is a secret value; refusing to resolve an external target from it", binding.Input)
		}
	}
	value, ok := inv.HostVar(sourceHost, binding.Input)
	if !ok {
		return "", fmt.Sprintf("provider %q has no hosts in this inventory and input %q is not set for %s", dep.Component, binding.Input, sourceHost)
	}
	return value, ""
}
