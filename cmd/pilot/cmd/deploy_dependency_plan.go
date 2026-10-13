package cmd

import (
	"fmt"
	"regexp"
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
	// Last extra-var wins over JSON and @file values earlier in extraVars;
	// ansibleExtraVarArgs repeats it after the operator's vars/vault file.
	return append(vars, "target_group="+role)
}

// ansibleExtraVarArgs renders extraVars as -e arguments, then the operator's
// vars/vault file, then the target_group Pilot resolved the deployment scope
// from. Ansible gives the last -e precedence. The vars file used to come
// last, so a target_group inside it retargeted the playbook away from the
// scope Pilot had resolved: a managed provider's dependency run matched no
// hosts and was reported as applied (PR #39 review). resolveDeploymentScope
// reads target_group only from extraVars, so that is the value Ansible must
// see.
func ansibleExtraVarArgs(extraVars []string, vault vaultInput) []string {
	args := make([]string, 0, 2*len(extraVars)+6)
	for _, value := range extraVars {
		args = append(args, "-e", value)
	}
	args = append(args, vault.args()...)
	if group := extraVarValue(extraVars, "target_group"); group != "" {
		args = append(args, "-e", "target_group="+group)
	}
	return args
}

var (
	ansiEscapeRe    = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	recapHostLineRe = regexp.MustCompile(`(?m)^\s*(\S+)\s*:\s+ok=\d+\s+changed=\d+`)
)

// playRecapHosts returns the hosts named in ansible-playbook's PLAY RECAP,
// and whether the output had a PLAY RECAP at all. A playbook whose plays
// matched no hosts prints the header with no host lines.
func playRecapHosts(output string) (map[string]bool, bool) {
	output = ansiEscapeRe.ReplaceAllString(output, "")
	idx := strings.LastIndex(output, "PLAY RECAP")
	if idx < 0 {
		return nil, false
	}
	hosts := map[string]bool{}
	for _, m := range recapHostLineRe.FindAllStringSubmatch(output[idx:], -1) {
		hosts[m[1]] = true
	}
	return hosts, true
}

// checkAppliedHosts rejects an ansible-playbook run that exited 0 without
// applying anything to the hosts it was run for (AGENTS.md §5.8). With
// requireEvery false, one of hosts in the PLAY RECAP is enough, and output
// without a recap (a non-default stdout callback) is left to the exit code.
// With requireEvery true, every host must be in the recap, and output without
// a recap fails: nothing confirms the run reached them.
func checkAppliedHosts(output string, hosts []string, requireEvery bool) error {
	if len(hosts) == 0 {
		return nil
	}
	recap, ok := playRecapHosts(output)
	if !ok {
		if requireEvery {
			return fmt.Errorf("輸出沒有 PLAY RECAP，無法確認已套用到 %s", strings.Join(hosts, ", "))
		}
		return nil
	}
	var missing []string
	for _, host := range hosts {
		if !recap[host] {
			missing = append(missing, host)
		}
	}
	if len(missing) == len(hosts) {
		return fmt.Errorf("playbook 沒有比對到任何預定主機（PLAY RECAP 沒有 %s），沒有套用任何變更", strings.Join(hosts, ", "))
	}
	if requireEvery && len(missing) > 0 {
		return fmt.Errorf("playbook 沒有套用到預定主機 %s（PLAY RECAP 沒有這些主機）", strings.Join(missing, ", "))
	}
	return nil
}

// deploymentAppliedHosts lists the hosts a deployment run changes: the
// included hosts of the applied components' roles. Bound providers,
// delegated-only hosts and the site-wide localhost play are not in it.
func deploymentAppliedHosts(applied []contract.Contract, scope delivery.Scope, included []string) []string {
	includedSet := make(map[string]bool, len(included))
	for _, host := range included {
		includedSet[host] = true
	}
	var hosts []string
	for _, component := range applied {
		for _, host := range scope.HostsByRole[component.Role] {
			if host != "localhost" && includedSet[host] {
				hosts = append(hosts, host)
			}
		}
	}
	return uniqueSortedHosts(hosts)
}

// appliedBeforeConsumer reports whether a deploy applies dep's provider
// before its consumer: required sameHosts dependencies always, and required
// providerEndpoint dependencies marked applyBeforeConsumer when
// managedProviders is set.
func appliedBeforeConsumer(dep contract.Dependency, managedProviders bool) bool {
	if !dep.Required {
		return false
	}
	switch dep.Relation {
	case "sameHosts":
		return true
	case "providerEndpoint":
		return managedProviders && dep.ApplyBeforeConsumer
	}
	return false
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
			if !appliedBeforeConsumer(dep, true) {
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
