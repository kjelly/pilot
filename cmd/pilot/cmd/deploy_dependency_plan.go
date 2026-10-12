package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/delivery"
)

// Share menu policy with the automation schema. Existing day-2-only
// reconcilers remain hidden from deploy unless their catalog explicitly opts in.
func catalogEntryInWorkflow(entry deployPlaybook, reconcile bool) bool {
	if reconcile {
		return entry.Reconcile
	}
	return !entry.Reconcile || entry.Deploy
}

func isComponentApply(catalog contract.Catalog, components []string, playbook string) bool {
	for _, id := range components {
		if c, ok := catalog.Component(id); ok && c.Playbooks.Apply == playbook {
			return true
		}
	}
	return false
}

func dependencyTargetVars(extraVars []string, role string) []string {
	vars := make([]string, 0, len(extraVars)+1)
	for _, raw := range extraVars {
		if !strings.HasPrefix(raw, "target_group=") {
			vars = append(vars, raw)
		}
	}
	// Last extra-var wins, including overrides inside JSON or vars files.
	return append(vars, "target_group="+role)
}

// Inventory support scope includes bound services that are never mutated.
// Follow only actual apply edges to avoid deploying Docker on an S3 support
// host, or on every Docker host in the inventory.
func deploymentDependencyLimits(catalog contract.Catalog, components []string, scope delivery.Scope) (map[string]string, error) {
	hostSets := map[string]map[string]bool{}
	visiting := map[string]bool{}
	var visit func(contract.Contract, []string) error
	visit = func(c contract.Contract, hosts []string) error {
		if visiting[c.ID] {
			return fmt.Errorf("apply dependency cycle detected at component %q", c.ID)
		}
		visiting[c.ID] = true
		defer delete(visiting, c.ID)
		for _, dep := range c.Dependencies {
			if !dep.Required || !(dep.Relation == "sameHosts" || dep.Relation == "providerEndpoint" && dep.ApplyBeforeConsumer) {
				continue
			}
			provider, ok := catalog.Component(dep.Component)
			if !ok {
				return fmt.Errorf("component %q dependency %q is absent from catalog", c.ID, dep.Component)
			}
			depHosts := hosts
			if dep.Relation == "providerEndpoint" {
				depHosts = scope.HostsByRole[provider.Role]
				if len(depHosts) != 1 {
					return fmt.Errorf("managed provider %q must resolve exactly one host before apply; got %d", provider.ID, len(depHosts))
				}
			}
			if len(depHosts) == 0 {
				return fmt.Errorf("apply dependency %q resolves no mutation hosts", provider.ID)
			}
			if hostSets[provider.ID] == nil {
				hostSets[provider.ID] = map[string]bool{}
			}
			for _, host := range depHosts {
				hostSets[provider.ID][host] = true
			}
			if err := visit(provider, depHosts); err != nil {
				return err
			}
		}
		return nil
	}
	for _, id := range components {
		c, ok := catalog.Component(id)
		if !ok {
			return nil, fmt.Errorf("component %q is absent from catalog", id)
		}
		if err := visit(c, scope.HostsByRole[c.Role]); err != nil {
			return nil, err
		}
	}
	limits := make(map[string]string, len(hostSets))
	for id, set := range hostSets {
		hosts := make([]string, 0, len(set))
		for host := range set {
			hosts = append(hosts, host)
		}
		sort.Strings(hosts)
		limits[id] = strings.Join(hosts, ",")
	}
	return limits, nil
}

func hasManagedProviderDependency(catalog contract.Catalog, components []string) bool {
	chain, err := deploymentDependencyChain(catalog, components)
	if err != nil {
		return false
	}
	ids := append(append([]string(nil), components...), contractIDs(chain)...)
	for _, id := range ids {
		c, _ := catalog.Component(id)
		for _, dep := range c.Dependencies {
			if dep.Required && dep.Relation == "providerEndpoint" && dep.ApplyBeforeConsumer {
				return true
			}
		}
	}
	return false
}

// Fill endpoint bindings only from an unambiguous declared inventory provider.
// Existing values (including vault/JSON extra-vars resolved by Ansible) win.
func completeDependencyBindingVars(catalog contract.Catalog, component contract.Contract, scope delivery.Scope, hostVars map[string]map[string]any, extraVars []string) ([]string, error) {
	vars := append([]string(nil), extraVars...)
	for _, binding := range component.Bindings {
		if extraVarValue(vars, binding.Input) != "" {
			continue
		}
		configured := false
		for _, host := range scope.HostsByRole[component.Role] {
			if v, ok := hostVars[host][binding.Input]; ok && v != nil && fmt.Sprint(v) != "" {
				configured = true
				break
			}
		}
		if configured {
			continue
		}
		provider, ok := catalog.Component(binding.From.Component)
		if !ok {
			return nil, fmt.Errorf("binding %q provider %q is absent", binding.Input, binding.From.Component)
		}
		hosts := scope.HostsByRole[provider.Role]
		if len(hosts) != 1 {
			return nil, fmt.Errorf("binding %q needs exactly one inventory provider host; got %d", binding.Input, len(hosts))
		}
		address := hosts[0]
		if v, ok := hostVars[hosts[0]]["ansible_host"].(string); ok && v != "" {
			address = v
		}
		vars = append(vars, binding.Input+"="+address)
	}
	return vars, nil
}
