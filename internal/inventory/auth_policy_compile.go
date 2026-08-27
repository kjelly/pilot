// auth_policy_compile.go compiles the v3.0 Core Access Governance spec's
// (spec.md §11, Phase 2) `auth_policies:` section into a per-host
// authentication-indicator requirement. FreeIPA's own `ipa host-mod
// --auth-ind=` semantics are already "a ticket obtained via ANY one of
// these indicators satisfies the requirement" — exactly require_any's
// meaning — so compiling multiple policies covering the same host is just
// a set union, no additional Go-side OR/AND logic needed.
package inventory

import "sort"

// CompiledAuthPolicyHost is one host's resolved authentication-indicator
// requirement: the union of require_any indicators from every enabled
// (state: present) auth_policies entry whose resolved targets include
// this host.
type CompiledAuthPolicyHost struct {
	Host string
	// Indicators is sorted and deduplicated.
	Indicators []string
}

// CompileAuthPolicies resolves auth_policies: into one
// CompiledAuthPolicyHost per host any enabled policy reaches. Callers
// MUST have already run ValidateRosterV3 (checkAuthPolicies) — this does
// not re-validate shape.
func CompileAuthPolicies(root map[string]any) []CompiledAuthPolicyHost {
	hostgroupsByName := rosterHostgroupsByName(root)
	perHost := map[string]map[string]bool{}

	for _, raw := range listField(root, "auth_policies") {
		policy := asMap(raw)
		if stateOrDefault(policy, "present") == "absent" {
			continue
		}
		scope := resolveTargetScope(mapField(policy, "targets"), hostgroupsByName)
		indicators := stringListField(policy, "require_any")
		for h := range scope.hosts {
			if perHost[h] == nil {
				perHost[h] = map[string]bool{}
			}
			for _, ind := range indicators {
				perHost[h][ind] = true
			}
		}
	}

	hosts := make([]string, 0, len(perHost))
	for h := range perHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	out := make([]CompiledAuthPolicyHost, 0, len(hosts))
	for _, h := range hosts {
		indicators := make([]string, 0, len(perHost[h]))
		for ind := range perHost[h] {
			indicators = append(indicators, ind)
		}
		sort.Strings(indicators)
		out = append(out, CompiledAuthPolicyHost{Host: h, Indicators: indicators})
	}
	return out
}

// CompileAuthPoliciesFile is CompileAuthPolicies' file-reading
// counterpart, mirroring RosterUserNames' read/parse/dispatch shape
// (roster.go).
func CompileAuthPoliciesFile(path string) ([]CompiledAuthPolicyHost, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	return CompileAuthPolicies(root), nil
}
