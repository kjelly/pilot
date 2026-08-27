// grant_security_policy.go implements the v3.0 Core Access Governance
// spec's (spec.md §12, Phase 2) `security.grant_policies:` section:
// declarative requirements (max duration, reason/ticket, an applicable
// auth_policy) that any matching temporary_grant/sudo_grant must satisfy.
// checkGrantPolicies validates the section's shape; EvaluateGrantPolicies
// is the semantic cross-check spec.md §18 step 5 ("grant policy
// evaluation") runs before any mutation.
//
// kind: breakglass is out of scope for both — a breakglass grant has no
// validity/justification to check a duration or reason/ticket requirement
// against (its equivalent is activation.max_duration/require_reason/
// require_ticket, checked at definition time by roster_grants.go's
// checkGrantActivation already); wiring breakglass into grant_policies
// matching is deferred to Phase 3 alongside breakglass activation itself
// (spec.md §14, §21).
package inventory

import (
	"fmt"
	"strings"
	"time"
)

var knownSecurityTopLevelKeys = []string{"grant_policies", "conflicts", "privileged_identity"}

// checkSecurityTopLevelKeys rejects any security.* key besides the two
// Phase 2 defines, the same fail-closed posture checkTopLevelKeys already
// applies to the roster's own top level and to freeipa/freeipa.admin.
func checkSecurityTopLevelKeys(root map[string]any) []RosterViolation {
	if unk := unknownKeys(mapField(root, "security"), knownSecurityTopLevelKeys); len(unk) > 0 {
		return []RosterViolation{{Rule: "security keys", Detail: fmt.Sprintf("unknown security field(s): %s", strings.Join(unk, ", "))}}
	}
	return nil
}

var (
	knownGrantPolicyKeys        = []string{"name", "state", "match", "require"}
	knownGrantPolicyMatchKeys   = []string{"kinds", "hosts", "hostgroups"}
	knownGrantPolicyRequireKeys = []string{"max_duration", "reason", "ticket", "auth_policy"}
	// grantPolicyMatchableKinds excludes breakglass — see this file's
	// header comment on why breakglass matching is Phase 3 scope.
	grantPolicyMatchableKinds = []string{grantKindTemporary, grantKindSudo}
)

// checkGrantPolicies validates security.grant_policies: per spec.md §12.
func checkGrantPolicies(root map[string]any) []RosterViolation {
	var out []RosterViolation

	security := mapField(root, "security")
	hostNames := namesOf(listField(root, "hosts"))
	hostgroupNames := namesOf(listField(root, "hostgroups"))
	authPolicyNames := namesOf(listField(root, "auth_policies"))

	names := namesOf(listField(security, "grant_policies"))
	if dupes := findDuplicates(names); len(dupes) > 0 {
		out = append(out, RosterViolation{Rule: "unique grant_policy names", Detail: fmt.Sprintf("duplicate grant_policy name(s): %s", strings.Join(dupes, ", "))})
	}

	for _, raw := range listField(security, "grant_policies") {
		item := asMap(raw)
		label := labelOf(item)

		if unk := unknownKeys(item, knownGrantPolicyKeys); len(unk) > 0 {
			out = append(out, RosterViolation{Rule: "grant_policy keys", Detail: fmt.Sprintf("grant_policy %q: unknown field(s) %s", label, strings.Join(unk, ", "))})
		}
		state := stateOrDefault(item, "present")
		if state != "present" && state != "absent" {
			out = append(out, RosterViolation{Rule: "grant_policy state", Detail: fmt.Sprintf("grant_policy %q: state %q must be present/absent", label, state)})
		}

		match := mapField(item, "match")
		if unk := unknownKeys(match, knownGrantPolicyMatchKeys); len(unk) > 0 {
			out = append(out, RosterViolation{Rule: "grant_policy match keys", Detail: fmt.Sprintf("grant_policy %q: unknown match field(s) %s", label, strings.Join(unk, ", "))})
		}
		for _, kind := range stringListField(match, "kinds") {
			if !contains(grantPolicyMatchableKinds, kind) {
				out = append(out, RosterViolation{Rule: "grant_policy match kinds", Detail: fmt.Sprintf("grant_policy %q: match.kinds %q must be one of %s", label, kind, strings.Join(grantPolicyMatchableKinds, "/"))})
			}
		}
		for _, h := range stringListField(match, "hosts") {
			if !contains(hostNames, h) {
				out = append(out, RosterViolation{Rule: "grant_policy match host reference", Detail: fmt.Sprintf("grant_policy %q: match.hosts references unknown host %q", label, h)})
			}
		}
		for _, hg := range stringListField(match, "hostgroups") {
			if !contains(hostgroupNames, hg) {
				out = append(out, RosterViolation{Rule: "grant_policy match hostgroup reference", Detail: fmt.Sprintf("grant_policy %q: match.hostgroups references unknown hostgroup %q", label, hg)})
			}
		}

		require := mapField(item, "require")
		if unk := unknownKeys(require, knownGrantPolicyRequireKeys); len(unk) > 0 {
			out = append(out, RosterViolation{Rule: "grant_policy require keys", Detail: fmt.Sprintf("grant_policy %q: unknown require field(s) %s", label, strings.Join(unk, ", "))})
		}
		if maxDuration := stringField(require, "max_duration"); maxDuration != "" && !ValidAccessDuration(maxDuration) {
			out = append(out, RosterViolation{Rule: "grant_policy require max_duration", Detail: fmt.Sprintf("grant_policy %q: require.max_duration %q is not a valid duration (e.g. 30m, 1h, 8h, 24h, 7d)", label, maxDuration)})
		}
		for _, key := range []string{"reason", "ticket"} {
			if v, ok := require[key]; ok {
				if _, isBool := v.(bool); !isBool {
					out = append(out, RosterViolation{Rule: "grant_policy require flag", Detail: fmt.Sprintf("grant_policy %q: require.%s must be a boolean", label, key)})
				}
			}
		}
		if authPolicy := stringField(require, "auth_policy"); authPolicy != "" && !contains(authPolicyNames, authPolicy) {
			out = append(out, RosterViolation{Rule: "grant_policy require auth_policy reference", Detail: fmt.Sprintf("grant_policy %q: require.auth_policy references unknown auth_policy %q", label, authPolicy)})
		}
	}

	return out
}

// GrantPolicyViolation is one requirement EvaluateGrantPolicies found a
// matching grant failing to satisfy.
type GrantPolicyViolation struct {
	PolicyName string
	GrantName  string
	Detail     string
}

// EvaluateGrantPolicies cross-checks every temporary_grant/sudo_grant
// against every enabled security.grant_policies rule whose match criteria
// it satisfies (spec.md §12/§18 step 5). now is the injected clock a
// max_duration check evaluates an open-ended (no not_before) grant's
// window against — see §8's identical injected-clock requirement.
//
// Callers MUST have already run ValidateRosterV3 (checkGrantPolicies,
// checkGrants) — this does not re-validate shape, and returns an error
// only if a grant's own validity fails to parse despite that (a
// programmer error in the caller, not a normal user-facing outcome).
func EvaluateGrantPolicies(root map[string]any, now time.Time) ([]GrantPolicyViolation, error) {
	hostgroupsByName := rosterHostgroupsByName(root)
	security := mapField(root, "security")
	policies := listField(security, "grant_policies")

	var out []GrantPolicyViolation
	for _, raw := range listField(root, "grants") {
		grant := asMap(raw)
		kind := stringField(grant, "kind")
		if !contains(grantPolicyMatchableKinds, kind) {
			continue
		}
		if stateOrDefault(grant, "present") == "absent" {
			continue
		}
		grantName := stringField(grant, "name")
		grantScope := resolveTargetScope(mapField(grant, "targets"), hostgroupsByName)

		validity, err := ParseGrantValidity(mapField(grant, "validity"))
		if err != nil {
			return nil, fmt.Errorf("grant %q: %w", grantName, err)
		}

		for _, praw := range policies {
			policy := asMap(praw)
			if stateOrDefault(policy, "present") == "absent" {
				continue
			}
			policyName := stringField(policy, "name")
			match := mapField(policy, "match")

			if kinds := stringListField(match, "kinds"); len(kinds) > 0 && !contains(kinds, kind) {
				continue
			}
			if !matchGrantPolicyTargets(match, grantScope, hostgroupsByName) {
				continue
			}

			require := mapField(policy, "require")
			if maxDurationStr := stringField(require, "max_duration"); maxDurationStr != "" {
				maxDuration, _ := ParseAccessDuration(maxDurationStr) // already structurally validated
				start := validity.NotBefore
				if start.IsZero() {
					start = now
				}
				if validity.NotAfter.Sub(start) > maxDuration {
					out = append(out, GrantPolicyViolation{PolicyName: policyName, GrantName: grantName, Detail: fmt.Sprintf("grant window exceeds require.max_duration %s", maxDurationStr)})
				}
			}
			if boolFieldDefault(require, "reason", false) && stringField(mapField(grant, "justification"), "reason") == "" {
				out = append(out, GrantPolicyViolation{PolicyName: policyName, GrantName: grantName, Detail: "justification.reason is required by this policy"})
			}
			if boolFieldDefault(require, "ticket", false) && stringField(mapField(grant, "justification"), "ticket") == "" {
				out = append(out, GrantPolicyViolation{PolicyName: policyName, GrantName: grantName, Detail: "justification.ticket is required by this policy"})
			}
			if authPolicyName := stringField(require, "auth_policy"); authPolicyName != "" {
				if !grantCoveredByAuthPolicy(root, authPolicyName, grantScope, hostgroupsByName) {
					out = append(out, GrantPolicyViolation{PolicyName: policyName, GrantName: grantName, Detail: fmt.Sprintf("grant targets are not covered by required auth_policy %q", authPolicyName)})
				}
			}
		}
	}
	return out, nil
}

// EvaluateGrantPoliciesFile is EvaluateGrantPolicies' file-reading
// counterpart, mirroring RosterUserNames' read/parse/dispatch shape
// (roster.go).
func EvaluateGrantPoliciesFile(path string, now time.Time) ([]GrantPolicyViolation, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	return EvaluateGrantPolicies(root, now)
}

// targetScope is a resolved hosts/targets-shaped block: the flat hosts it
// reaches (including through nested hostgroup membership) AND the
// transitive closure of hostgroup NAMES it reaches (including through
// nested hostgroups, independent of whether those hostgroups have any
// host members declared yet). Matching/coverage needs both — a hostgroup
// with no host membership populated yet is common and still meaningful to
// match by name (spec.md §12's "nested hostgroups where applicable").
type targetScope struct {
	hosts          map[string]bool
	hostgroupNames map[string]bool
}

// resolveTargetScope resolves a subjects/targets-shaped block's
// targets.hosts/targets.hostgroups into a targetScope.
func resolveTargetScope(targets map[string]any, hostgroupsByName map[string]map[string]any) targetScope {
	scope := targetScope{hosts: map[string]bool{}, hostgroupNames: map[string]bool{}}
	for _, h := range stringListField(targets, "hosts") {
		scope.hosts[h] = true
	}
	hostgroups := stringListField(targets, "hostgroups")
	for _, hg := range hostgroups {
		expandHostgroupHosts(hostgroupsByName, hg, map[string]bool{}, scope.hosts)
	}
	for name := range hostgroupNameClosure(hostgroupsByName, hostgroups) {
		scope.hostgroupNames[name] = true
	}
	return scope
}

// hostgroupNameClosure returns the transitive closure of hostgroup names
// reachable from names via nested membership.hostgroups (each starting
// name included), independent of expandHostgroupHosts' host-membership
// walk — this is what lets two hostgroup-scoped blocks match by name
// alone even when neither hostgroup has any host members declared yet.
func hostgroupNameClosure(hostgroupsByName map[string]map[string]any, names []string) map[string]bool {
	out := map[string]bool{}
	var walk func(name string, visiting map[string]bool)
	walk = func(name string, visiting map[string]bool) {
		if visiting[name] {
			return
		}
		visiting[name] = true
		out[name] = true
		hg, ok := hostgroupsByName[name]
		if !ok {
			return
		}
		for _, nested := range stringListField(mapField(hg, "membership"), "hostgroups") {
			walk(nested, visiting)
		}
	}
	for _, n := range names {
		walk(n, map[string]bool{})
	}
	return out
}

// scopesOverlap reports whether a and b share any resolved host or any
// hostgroup name in their respective closures.
func scopesOverlap(a, b targetScope) bool {
	for h := range a.hosts {
		if b.hosts[h] {
			return true
		}
	}
	for n := range a.hostgroupNames {
		if b.hostgroupNames[n] {
			return true
		}
	}
	return false
}

// scopeCoveredBy reports whether every host and hostgroup name in narrow
// is also present in broad — narrow ⊆ broad. An empty narrow scope is
// never "covered" (nothing to check against is not a proof of coverage);
// checkGrants already guarantees a grant's own targets are never empty,
// so this only matters for a malformed caller.
func scopeCoveredBy(narrow, broad targetScope) bool {
	if len(narrow.hosts) == 0 && len(narrow.hostgroupNames) == 0 {
		return false
	}
	for h := range narrow.hosts {
		if !broad.hosts[h] {
			return false
		}
	}
	for n := range narrow.hostgroupNames {
		if !broad.hostgroupNames[n] {
			return false
		}
	}
	return true
}

// matchGrantPolicyTargets reports whether match applies to a grant whose
// resolved target scope is grantScope. An empty match.hosts+
// match.hostgroups (neither given) matches every target, mirroring how an
// unscoped policy is meant to apply everywhere rather than nowhere.
func matchGrantPolicyTargets(match map[string]any, grantScope targetScope, hostgroupsByName map[string]map[string]any) bool {
	matchHosts := stringListField(match, "hosts")
	matchHostgroups := stringListField(match, "hostgroups")
	if len(matchHosts) == 0 && len(matchHostgroups) == 0 {
		return true
	}
	policyScope := resolveTargetScope(map[string]any{"hosts": matchHosts, "hostgroups": matchHostgroups}, hostgroupsByName)
	return scopesOverlap(grantScope, policyScope)
}

// grantCoveredByAuthPolicy reports whether grantScope is covered by the
// named auth_policies entry's own resolved targets — the interpretation
// spec.md §12's `require.auth_policy` is given here: a grant_policy
// requiring auth_policy X means the grant may only reach targets that X's
// own targets (resolved, nested hostgroups included) already cover, i.e.
// strong authentication is mandated wherever this grant would apply. A
// named auth_policy that doesn't exist, or exists but is state: absent,
// covers nothing.
func grantCoveredByAuthPolicy(root map[string]any, authPolicyName string, grantScope targetScope, hostgroupsByName map[string]map[string]any) bool {
	for _, raw := range listField(root, "auth_policies") {
		policy := asMap(raw)
		if stringField(policy, "name") != authPolicyName || stateOrDefault(policy, "present") == "absent" {
			continue
		}
		policyScope := resolveTargetScope(mapField(policy, "targets"), hostgroupsByName)
		return scopeCoveredBy(grantScope, policyScope)
	}
	return false
}
