// auth_policy.go validates the v3.0 Core Access Governance spec's (spec.md
// §11, Phase 2) `auth_policies:` section: host/hostgroup-scoped
// declarations of which Kerberos authentication indicators are required.
// This is purely structural — whether a given indicator is actually
// enforceable on a given FreeIPA/Kerberos target is a live-environment
// question spec.md §11 explicitly defers to real verification, not
// something this validator can determine from the roster alone.
package inventory

import (
	"fmt"
	"strings"
)

// knownAuthIndicators is spec.md §11's initial indicator set.
var knownAuthIndicators = []string{"otp", "radius", "pkinit", "hardened"}

var knownAuthPolicyKeys = []string{"name", "state", "targets", "require_any"}

// checkAuthPolicies validates the auth_policies: list per spec.md §11.
func checkAuthPolicies(root map[string]any) []RosterViolation {
	var out []RosterViolation

	hostNames := namesOf(listField(root, "hosts"))
	hostgroupNames := namesOf(listField(root, "hostgroups"))

	names := namesOf(listField(root, "auth_policies"))
	if dupes := findDuplicates(names); len(dupes) > 0 {
		out = append(out, RosterViolation{Rule: "unique auth_policy names", Detail: fmt.Sprintf("duplicate auth_policy name(s): %s", strings.Join(dupes, ", "))})
	}

	for _, raw := range listField(root, "auth_policies") {
		item := asMap(raw)
		label := labelOf(item)

		if unk := unknownKeys(item, knownAuthPolicyKeys); len(unk) > 0 {
			out = append(out, RosterViolation{Rule: "auth_policy keys", Detail: fmt.Sprintf("auth_policy %q: unknown field(s) %s", label, strings.Join(unk, ", "))})
		}

		state := stateOrDefault(item, "present")
		if state != "present" && state != "absent" {
			out = append(out, RosterViolation{Rule: "auth_policy state", Detail: fmt.Sprintf("auth_policy %q: state %q must be present/absent", label, state)})
		}

		targets := mapField(item, "targets")
		targetHosts := stringListField(targets, "hosts")
		targetHostgroups := stringListField(targets, "hostgroups")
		if len(targetHosts)+len(targetHostgroups) == 0 {
			out = append(out, RosterViolation{Rule: "auth_policy targets", Detail: fmt.Sprintf("auth_policy %q: needs at least one target host or hostgroup", label)})
		}
		for _, h := range targetHosts {
			if !contains(hostNames, h) {
				out = append(out, RosterViolation{Rule: "auth_policy target host reference", Detail: fmt.Sprintf("auth_policy %q: targets.hosts references unknown host %q", label, h)})
			}
		}
		for _, hg := range targetHostgroups {
			if !contains(hostgroupNames, hg) {
				out = append(out, RosterViolation{Rule: "auth_policy target hostgroup reference", Detail: fmt.Sprintf("auth_policy %q: targets.hostgroups references unknown hostgroup %q", label, hg)})
			}
		}

		requireAny := stringListField(item, "require_any")
		if len(requireAny) == 0 {
			out = append(out, RosterViolation{Rule: "auth_policy require_any", Detail: fmt.Sprintf("auth_policy %q: require_any needs at least one authentication indicator", label)})
		}
		for _, indicator := range requireAny {
			if !contains(knownAuthIndicators, indicator) {
				out = append(out, RosterViolation{Rule: "auth_policy indicator", Detail: fmt.Sprintf("auth_policy %q: require_any %q must be one of %s", label, indicator, strings.Join(knownAuthIndicators, "/"))})
			}
		}
	}

	return out
}
