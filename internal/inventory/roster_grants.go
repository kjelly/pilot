// roster_grants.go validates the first-class `grants:` section schema v3
// introduces (see roster_validate.go's ValidateRosterV3), per the HBAC
// simplification spec §27.3 ("Temporary authorization") and §27.5
// ("Explain / inspection"): a grant is a temporary_grant or breakglass
// authorization using the same subjects/targets geometry as an HBAC rule
// (checkHBAC, roster_validate.go).
//
// The v2 -> v3 schema migration never synthesizes a populated grants
// entry — v2 has no equivalent concept, so migration only ever appends an
// empty list. This validator exists so `grants:` is a fully first-class,
// structurally-checked section from the moment schema v3 exists, ahead of
// whatever future feature actually authors grants.
package inventory

import (
	"fmt"
	"strings"
)

var (
	knownGrantKeys  = []string{"name", "kind", "subjects", "targets"}
	knownGrantKinds = []string{"temporary_grant", "breakglass"}
)

// checkGrants validates the grants: list. It deliberately stops short of
// §27.3's full login-vs-sudo distinction (login grants accept
// team/role/legacy-access subject groups; sudo grants accept role only) —
// §27 never names the field that would discriminate a login grant from a
// sudo grant, and guessing one here would repeat the exact mistake the v2
// -> v3 migration spec's §5 explicitly avoided for auth_policies/
// security.*/account_policies: picking a shape nobody has agreed to yet.
// What IS unconditional across both grant flavors per §27.3 is that a
// filesystem group can never be a grant subject, so that much is checked
// here (the same IsHBACSubjectGroupCategory allowance checkHBAC uses,
// which already excludes filesystem). The rest is deferred to whatever
// future spec defines grants authoring in full.
func checkGrants(root map[string]any) []RosterViolation {
	var out []RosterViolation

	groups := listField(root, "groups")
	grantSubjectGroupNames := namesWithCategoryFunc(groups, IsHBACSubjectGroupCategory)
	allowedUsers := append(namesOf(listField(root, "users")), "admin")
	hostNames := namesOf(listField(root, "hosts"))
	hostgroupNames := namesOf(listField(root, "hostgroups"))

	for _, raw := range listField(root, "grants") {
		item := asMap(raw)
		label := labelOf(item)

		kind := stringField(item, "kind")
		if !contains(knownGrantKinds, kind) {
			out = append(out, RosterViolation{Rule: "grant kind", Detail: fmt.Sprintf("grant %q: kind %q must be one of %s", label, kind, strings.Join(knownGrantKinds, "/"))})
		}
		if unk := unknownKeys(item, knownGrantKeys); len(unk) > 0 {
			out = append(out, RosterViolation{Rule: "grant keys", Detail: fmt.Sprintf("grant %q: unknown field(s) %s", label, strings.Join(unk, ", "))})
		}

		subjects := mapField(item, "subjects")
		subjUsers := stringListField(subjects, "users")
		subjGroups := stringListField(subjects, "groups")
		if len(subjUsers)+len(subjGroups) == 0 {
			out = append(out, RosterViolation{Rule: "grant subjects", Detail: fmt.Sprintf("grant %q: needs at least one subject user or group", label)})
		}
		for _, u := range subjUsers {
			if !contains(allowedUsers, u) {
				out = append(out, RosterViolation{Rule: "grant subject user reference", Detail: fmt.Sprintf("grant %q: subjects.users references unknown user %q", label, u)})
			}
		}
		for _, g := range subjGroups {
			if !contains(grantSubjectGroupNames, g) {
				out = append(out, RosterViolation{Rule: "grant subject group category", Detail: fmt.Sprintf("grant %q: subjects.groups %q must be a group with category team, role, or (legacy) access", label, g)})
			}
		}

		targets := mapField(item, "targets")
		targetHosts := stringListField(targets, "hosts")
		targetHostgroups := stringListField(targets, "hostgroups")
		if len(targetHosts)+len(targetHostgroups) == 0 {
			out = append(out, RosterViolation{Rule: "grant targets", Detail: fmt.Sprintf("grant %q: needs at least one target host or hostgroup", label)})
		}
		for _, h := range targetHosts {
			if !contains(hostNames, h) {
				out = append(out, RosterViolation{Rule: "grant target host reference", Detail: fmt.Sprintf("grant %q: targets.hosts references unknown host %q", label, h)})
			}
		}
		for _, hg := range targetHostgroups {
			if !contains(hostgroupNames, hg) {
				out = append(out, RosterViolation{Rule: "grant target hostgroup reference", Detail: fmt.Sprintf("grant %q: targets.hostgroups references unknown hostgroup %q", label, hg)})
			}
		}
	}

	return out
}
