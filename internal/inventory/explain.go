// explain.go implements the roster-based half of spec.md §16 (Phase 3):
// for a given (user, host, service), which static HBAC rules and which
// temporary_grant/sudo_grant entries currently grant it, and through what
// provenance path. This never queries live FreeIPA — like
// roster_effective.go's EffectiveHBACAccess/EffectiveSudoAccess, it is a
// roster-and-local-state introspection tool, the same posture every other
// read-only inspection surface in this package already takes.
//
// kind: breakglass is deliberately out of scope here — its "is it
// currently granting access" question depends on runtime activation
// state that lives in internal/accessgrants, not the roster
// (internal/inventory cannot import internal/accessgrants without a
// cycle, since accessgrants already imports inventory) — see
// internal/accessgrants/explain.go, which combines this file's output
// with breakglass activation state into spec.md §16's full 4-source
// picture.
package inventory

import "time"

// ExplainSource is one source of access explain reports for a
// (user, host, service) query — spec.md §16's static_hbac/temporary_grant/
// sudo_grant/breakglass source kinds.
type ExplainSource struct {
	Kind string // "static_hbac", "temporary_grant", "sudo_grant", or "breakglass"
	Rule string // the HBAC rule name, or the grant name

	// DirectUserHit/GroupPath describe how the subject side matched:
	// DirectUserHit if the query user was listed directly in
	// subjects.users, and/or GroupPath naming every declared
	// subjects.groups entry the user is an effective (possibly nested)
	// member of.
	DirectUserHit bool
	GroupPath     []string

	// DirectHostHit/HostgroupPath mirror the above for the target side.
	// AllHosts is true for a static_hbac rule using hostcat: all (grants
	// never support that — checkGrants requires explicit hosts/
	// hostgroups, spec.md §7).
	DirectHostHit bool
	HostgroupPath []string
	AllHosts      bool

	Service string // empty for a sudo_grant match — sudo has no PAM service concept

	// Lifecycle/Validity/NextTransition are set only for temporary_grant/
	// sudo_grant sources (spec.md §16: "Temporary source ... includes
	// validity and next transition").
	Lifecycle      GrantLifecycleState
	ValidityAfter  time.Time
	NextTransition *time.Time
}

// ExplainStaticHBAC returns every enabled, present hbac.rules entry that
// currently grants (user, host, service), with provenance.
func ExplainStaticHBAC(root map[string]any, user, host, service string) []ExplainSource {
	groupsByName := rosterGroupsByName(root)
	hostgroupsByName := rosterHostgroupsByName(root)

	var out []ExplainSource
	for _, raw := range listField(mapField(root, "hbac"), "rules") {
		item := asMap(raw)
		if stateOrDefault(item, "present") == "absent" || !boolFieldDefault(item, "enabled", true) {
			continue
		}
		if !contains(stringListField(item, "services"), service) {
			continue
		}

		subjects := mapField(item, "subjects")
		directUser, groupPath := matchSubject(groupsByName, subjects, user)
		if !directUser && len(groupPath) == 0 {
			continue
		}

		targets := mapField(item, "targets")
		allHosts := stringField(targets, "hostcat") == "all"
		directHost, hostgroupPath := allHosts, []string(nil)
		if !allHosts {
			directHost, hostgroupPath = matchTarget(hostgroupsByName, targets, host)
			if !directHost && len(hostgroupPath) == 0 {
				continue
			}
		}

		out = append(out, ExplainSource{
			Kind: "static_hbac", Rule: stringField(item, "name"),
			DirectUserHit: directUser, GroupPath: groupPath,
			DirectHostHit: directHost, HostgroupPath: hostgroupPath, AllHosts: allHosts,
			Service: service,
		})
	}
	return out
}

// ExplainGrants returns every present temporary_grant/sudo_grant entry
// that currently (lifecycle == active, evaluated against now) grants
// (user, host, service) — service is ignored for sudo_grant, which has no
// PAM service concept.
func ExplainGrants(root map[string]any, user, host, service string, now time.Time) ([]ExplainSource, error) {
	groupsByName := rosterGroupsByName(root)
	hostgroupsByName := rosterHostgroupsByName(root)

	var out []ExplainSource
	for _, raw := range listField(root, "grants") {
		grant := asMap(raw)
		kind := stringField(grant, "kind")
		if kind != grantKindTemporary && kind != grantKindSudo {
			continue
		}
		state := stateOrDefault(grant, "present")
		if state == "absent" {
			continue
		}
		if kind == grantKindTemporary && service != "" && !contains(stringListField(grant, "services"), service) {
			continue
		}

		subjects := mapField(grant, "subjects")
		directUser, groupPath := matchSubject(groupsByName, subjects, user)
		if !directUser && len(groupPath) == 0 {
			continue
		}
		targets := mapField(grant, "targets")
		directHost, hostgroupPath := matchTarget(hostgroupsByName, targets, host)
		if !directHost && len(hostgroupPath) == 0 {
			continue
		}

		validity, err := ParseGrantValidity(mapField(grant, "validity"))
		if err != nil {
			return nil, err
		}
		lifecycle := EvaluateGrantLifecycle(state, validity, now)
		if lifecycle != GrantActive {
			continue
		}

		out = append(out, ExplainSource{
			Kind: kind, Rule: stringField(grant, "name"),
			DirectUserHit: directUser, GroupPath: groupPath,
			DirectHostHit: directHost, HostgroupPath: hostgroupPath,
			Service:        service,
			Lifecycle:      lifecycle,
			ValidityAfter:  validity.NotAfter,
			NextTransition: NextGrantTransition(state, validity, now),
		})
	}
	return out, nil
}

// ExplainBreakglassDefinitions returns every present kind: breakglass
// grant whose subjects/targets/services match (user, host, service) —
// candidates only, since a breakglass definition alone never grants
// anything (spec.md §14). The Kind is "breakglass"; Lifecycle and
// NextTransition are left at their zero value here — internal/accessgrants'
// Explain cross-references each candidate's name against its own runtime
// activation state (this package cannot see that without an import
// cycle) and fills NextTransition with the activation's expiry only for
// candidates that currently have one active.
func ExplainBreakglassDefinitions(root map[string]any, user, host, service string) []ExplainSource {
	groupsByName := rosterGroupsByName(root)
	hostgroupsByName := rosterHostgroupsByName(root)

	var out []ExplainSource
	for _, raw := range listField(root, "grants") {
		grant := asMap(raw)
		if stringField(grant, "kind") != grantKindBreakglass || stateOrDefault(grant, "present") == "absent" {
			continue
		}
		if !contains(stringListField(grant, "services"), service) {
			continue
		}
		subjects := mapField(grant, "subjects")
		directUser, groupPath := matchSubject(groupsByName, subjects, user)
		if !directUser && len(groupPath) == 0 {
			continue
		}
		targets := mapField(grant, "targets")
		directHost, hostgroupPath := matchTarget(hostgroupsByName, targets, host)
		if !directHost && len(hostgroupPath) == 0 {
			continue
		}
		out = append(out, ExplainSource{
			Kind: grantKindBreakglass, Rule: stringField(grant, "name"),
			DirectUserHit: directUser, GroupPath: groupPath,
			DirectHostHit: directHost, HostgroupPath: hostgroupPath,
			Service: service,
		})
	}
	return out
}

// matchSubject reports whether user is a direct member of subjects.users,
// and which of subjects.groups (if any) user is an effective — possibly
// nested — member of.
func matchSubject(groupsByName map[string]map[string]any, subjects map[string]any, user string) (directHit bool, groupPath []string) {
	directHit = contains(stringListField(subjects, "users"), user)
	for _, g := range stringListField(subjects, "groups") {
		members := map[string]bool{}
		expandGroupMembers(groupsByName, g, map[string]bool{}, members)
		if members[user] {
			groupPath = append(groupPath, g)
		}
	}
	return directHit, groupPath
}

// matchTarget is matchSubject's host/hostgroup counterpart.
func matchTarget(hostgroupsByName map[string]map[string]any, targets map[string]any, host string) (directHit bool, hostgroupPath []string) {
	directHit = contains(stringListField(targets, "hosts"), host)
	for _, hg := range stringListField(targets, "hostgroups") {
		hosts := map[string]bool{}
		expandHostgroupHosts(hostgroupsByName, hg, map[string]bool{}, hosts)
		if hosts[host] {
			hostgroupPath = append(hostgroupPath, hg)
		}
	}
	return directHit, hostgroupPath
}
