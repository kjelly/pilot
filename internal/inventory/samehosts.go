package inventory

import "github.com/kjelly/pilot/internal/contract"

// SameHostsDependencyRoles projects contracts' required "sameHosts"
// dependencies onto role names: for every component whose contract
// declares a required sameHosts dependency (e.g. wazuh-manager requires
// docker on the same host, since Wazuh's own manager runs as Docker
// containers), it maps that component's role to its dependency's role
// (e.g. "wazuh-manager" -> ["docker"]). Only sameHosts is projected —
// providerEndpoint and other relations legitimately live on a different
// host and must stay something the operator places explicitly.
func SameHostsDependencyRoles(contracts []contract.Contract) map[string][]string {
	roleByID := make(map[string]string, len(contracts))
	for _, c := range contracts {
		roleByID[c.ID] = c.Role
	}
	edges := make(map[string][]string)
	for _, c := range contracts {
		for _, dep := range c.Dependencies {
			if !dep.Required || dep.Relation != "sameHosts" {
				continue
			}
			role, ok := roleByID[dep.Component]
			if !ok || role == c.Role {
				continue
			}
			edges[c.Role] = append(edges[c.Role], role)
		}
	}
	return edges
}

// ExpandSameHostsRoles returns hosts with each host's Roles extended by
// the transitive closure of required sameHosts contract dependencies
// (deps, from SameHostsDependencyRoles) — so a host declared with role
// "wazuh-manager" is treated as if it also carried "docker" without
// hosts.yml needing to name it too. The returned hosts are copies with
// their own Roles slice; the input hosts (and their Roles) are never
// mutated, so this is safe to use only for rendering the generated
// inventory without ever writing the implied role back into hosts.yml.
func ExpandSameHostsRoles(hosts []Host, deps map[string][]string) []Host {
	if len(deps) == 0 {
		return hosts
	}
	out := make([]Host, len(hosts))
	for i, h := range hosts {
		out[i] = h
		out[i].Roles = expandRoleClosure(h.Roles, deps)
	}
	return out
}

// expandRoleClosure walks deps breadth-first from roles, returning roles
// plus every reachable dependency role, each appearing once.
func expandRoleClosure(roles []string, deps map[string][]string) []string {
	seen := make(map[string]bool, len(roles))
	closure := append([]string(nil), roles...)
	for _, r := range roles {
		seen[r] = true
	}
	for i := 0; i < len(closure); i++ {
		for _, dep := range deps[closure[i]] {
			if !seen[dep] {
				seen[dep] = true
				closure = append(closure, dep)
			}
		}
	}
	return closure
}
