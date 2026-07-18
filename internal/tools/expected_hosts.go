package tools

import (
	"fmt"
	"sort"
	"strings"
)

// hostSelection is one already-resolved execution-scope selector. Adapters
// resolve Ansible patterns, --limit, stage, and component selections against
// the actual inventory before calling resolveExpectedHosts.
type hostSelection struct {
	Name     string
	Provided bool
	Hosts    []string
}

// expectedHostInput keeps inventory facts separate from acceptance scope.
// SpecTargetHosts contains the inventory hosts selected by the spec targets;
// it never creates hosts that are absent from InventoryHosts.
type expectedHostInput struct {
	InventoryHosts      []string
	ExecutionSelections []hostSelection
	SpecTargetsDeclared bool
	SpecTargetHosts     []string
	TargetGroupOverride bool
}

type expectedHostResolution struct {
	Hosts    []string
	Findings []string
}

// resolveExpectedHosts applies the M0.2 expected-host contract without
// invoking Ansible. InventoryHosts is authoritative. Explicit execution
// selectors narrow that universe by intersection. Spec targets constrain the
// resulting scope unless an explicit target_group override records and accepts
// the intentional mismatch described by AGENTS.md §3.
func resolveExpectedHosts(in expectedHostInput) (expectedHostResolution, error) {
	universe, err := normalizeHostSet("inventory", in.InventoryHosts, nil)
	if err != nil {
		return expectedHostResolution{}, err
	}
	if len(universe) == 0 {
		return expectedHostResolution{}, fmt.Errorf("expected-host resolver: inventory host set is empty")
	}
	universeSet := stringSet(universe)

	resolved := append([]string(nil), universe...)
	executionSelectorProvided := false
	for _, selection := range in.ExecutionSelections {
		if !selection.Provided {
			continue
		}
		executionSelectorProvided = true
		name := strings.TrimSpace(selection.Name)
		if name == "" {
			return expectedHostResolution{}, fmt.Errorf("expected-host resolver: execution selection has no name")
		}
		hosts, err := normalizeHostSet(name, selection.Hosts, universeSet)
		if err != nil {
			return expectedHostResolution{}, err
		}
		if len(hosts) == 0 {
			return expectedHostResolution{}, fmt.Errorf("expected-host resolver: %s matched zero inventory hosts", name)
		}
		resolved = intersectHostSets(resolved, hosts)
		if len(resolved) == 0 {
			return expectedHostResolution{}, fmt.Errorf("expected-host resolver: execution selections have an empty intersection after %s", name)
		}
	}

	var findings []string
	if in.SpecTargetsDeclared {
		specHosts, err := normalizeHostSet("spec targets", in.SpecTargetHosts, universeSet)
		if err != nil {
			return expectedHostResolution{}, err
		}
		if in.TargetGroupOverride {
			if len(specHosts) == 0 {
				findings = append(findings, "target_group override replaced spec targets that matched no inventory hosts")
			} else if !sameHostSet(resolved, specHosts) {
				findings = append(findings, "target_group override replaced the spec target scope")
			} else {
				findings = append(findings, "target_group override explicitly confirmed the spec target scope")
			}
		} else {
			if len(specHosts) == 0 {
				return expectedHostResolution{}, fmt.Errorf("expected-host resolver: spec targets matched zero inventory hosts and no target_group override was provided")
			}
			if !executionSelectorProvided {
				resolved = specHosts
			} else {
				outside := differenceHostSets(resolved, specHosts)
				if len(outside) > 0 {
					return expectedHostResolution{}, fmt.Errorf(
						"expected-host resolver: execution scope contains hosts outside spec targets: %s",
						strings.Join(outside, ", "),
					)
				}
			}
		}
	} else if in.TargetGroupOverride {
		findings = append(findings, "target_group override supplied for a spec without declared targets")
	}

	return expectedHostResolution{Hosts: resolved, Findings: findings}, nil
}

func normalizeHostSet(label string, hosts []string, universe map[string]struct{}) ([]string, error) {
	set := make(map[string]struct{}, len(hosts))
	for _, raw := range hosts {
		host := strings.TrimSpace(raw)
		if host == "" {
			return nil, fmt.Errorf("expected-host resolver: %s contains an empty host", label)
		}
		if universe != nil {
			if _, ok := universe[host]; !ok {
				return nil, fmt.Errorf("expected-host resolver: %s contains host %q that is absent from inventory", label, host)
			}
		}
		set[host] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for host := range set {
		out = append(out, host)
	}
	sort.Strings(out)
	return out, nil
}

func stringSet(hosts []string) map[string]struct{} {
	out := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		out[host] = struct{}{}
	}
	return out
}

func intersectHostSets(left, right []string) []string {
	rightSet := stringSet(right)
	out := make([]string, 0, len(left))
	for _, host := range left {
		if _, ok := rightSet[host]; ok {
			out = append(out, host)
		}
	}
	return out
}

func differenceHostSets(left, right []string) []string {
	rightSet := stringSet(right)
	out := make([]string, 0)
	for _, host := range left {
		if _, ok := rightSet[host]; !ok {
			out = append(out, host)
		}
	}
	return out
}

func sameHostSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
