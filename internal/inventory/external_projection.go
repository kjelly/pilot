// external_projection.go exposes the roster's declarative state in the
// typed shape the outbound webhook's user_host_access_v1 projection
// needs (docs/tmp/now/spec.md §11, §12): present/disabled users with
// resolved group membership, present groups/hostgroups with direct and
// transitive membership, present roster hosts, and effective login/sudo
// access already filtered to what would actually grant access right now
// (disabled/absent static rules omitted, only currently-active grants
// included, users intersected with the present+enabled user set).
//
// This file deliberately returns typed structs, not raw
// map[string]any — the same posture EffectiveHBACAccessFromRoster/
// EffectiveSudoAccessFromRoster already established — so
// internal/outbound never has to reach into roster internals (asMap,
// stringField, ...) itself. It cannot import internal/accessgrants
// (accessgrants already imports this package, so the reverse would
// cycle); breakglass activation state is passed in by the caller via
// BreakglassActivationInput instead of being looked up here.
package inventory

import (
	"sort"
	"time"
)

// ExternalUser is one state:present/disabled roster user (state:absent
// omitted) for the outbound webhook projection (design spec §11.2,
// §11.8).
type ExternalUser struct {
	Name        string
	DisplayName string
	Email       string
	UID         *int
	GID         *int
	// Enabled reflects both the roster's own enabled flag/state and
	// account-policy lifecycle (AccountActiveForUser) — never a raw
	// passthrough of the roster's `enabled:` field alone.
	Enabled bool
	// EffectiveGroups is every present group this user is a direct or
	// transitive member of, sorted and deduped. A disabled user can still
	// appear here — group membership display is independent of whether
	// the account is currently enabled (§11.8).
	EffectiveGroups []string
}

func userRosterEnabledFlag(u map[string]any) bool {
	return boolFieldDefault(u, "enabled", stateOrDefault(u, "present") == "present")
}

func intPtr(v any) *int {
	n, ok := toInt(v)
	if !ok {
		return nil
	}
	return &n
}

func effectiveGroupsForUser(groupsByName map[string]map[string]any, user string) []string {
	var out []string
	for name := range groupsByName {
		members := map[string]bool{}
		expandGroupMembers(groupsByName, name, map[string]bool{}, members)
		if members[user] {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// ExternalUsers returns every state:present/disabled roster user. now
// drives account-policy lifecycle evaluation — inject deterministically,
// never time.Now() at call sites that need reproducible output (design
// spec §11.8, INV-5's determinism requirement).
func ExternalUsers(root map[string]any, now time.Time) ([]ExternalUser, error) {
	groupsByName := rosterGroupsByName(root)
	out := []ExternalUser{}
	for _, raw := range listField(root, "users") {
		u := asMap(raw)
		state := stateOrDefault(u, "present")
		if state == "absent" {
			continue
		}
		name := stringField(u, "name")
		accountActive, _, _, err := AccountActiveForUser(root, name, now)
		if err != nil {
			return nil, err
		}
		out = append(out, ExternalUser{
			Name:            name,
			DisplayName:     stringField(u, "display_name"),
			Email:           stringField(u, "email"),
			UID:             intPtr(u["uid"]),
			GID:             intPtr(u["gid"]),
			Enabled:         userRosterEnabledFlag(u) && accountActive,
			EffectiveGroups: effectiveGroupsForUser(groupsByName, name),
		})
	}
	return out, nil
}

// presentEnabledUserSet is ExternalUsers' membership-only counterpart,
// used to intersect access-rule subject users against "present AND
// currently enabled" (design spec §12.4 rule 6).
func presentEnabledUserSet(root map[string]any, now time.Time) (map[string]bool, error) {
	users, err := ExternalUsers(root, now)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(users))
	for _, u := range users {
		if u.Enabled {
			set[u.Name] = true
		}
	}
	return set, nil
}

func intersectSorted(users []string, allowed map[string]bool) []string {
	out := make([]string, 0, len(users))
	for _, u := range users {
		if allowed[u] {
			out = append(out, u)
		}
	}
	sort.Strings(out)
	return out
}

// ExternalGroup is one state:present roster group's direct membership
// (design spec §11.2) — not transitively expanded; EffectiveGroups
// exists on ExternalUser for the user-centric transitive view, and
// ExternalHostgroup.EffectiveHostIDs for the hostgroup-centric one.
type ExternalGroup struct {
	Name        string
	Category    string
	Type        string
	Description string
	Users       []string
	Groups      []string
}

// ExternalGroups returns every state:present roster group.
func ExternalGroups(root map[string]any) []ExternalGroup {
	out := []ExternalGroup{}
	for _, raw := range listField(root, "groups") {
		g := asMap(raw)
		if stateOrDefault(g, "present") == "absent" {
			continue
		}
		membership := mapField(g, "membership")
		out = append(out, ExternalGroup{
			Name:        stringField(g, "name"),
			Category:    stringField(g, "category"),
			Type:        stringField(g, "type"),
			Description: stringField(g, "description"),
			Users:       sortedCopy(stringListField(membership, "users")),
			Groups:      sortedCopy(stringListField(membership, "groups")),
		})
	}
	return out
}

// ExternalHostgroup is one state:present roster hostgroup, with both its
// direct membership and its transitively-expanded effective host closure
// (design spec §11.2).
type ExternalHostgroup struct {
	Name             string
	Description      string
	HostIDs          []string
	Hostgroups       []string
	EffectiveHostIDs []string
}

// ExternalHostgroups returns every state:present roster hostgroup.
func ExternalHostgroups(root map[string]any) []ExternalHostgroup {
	hostgroupsByName := rosterHostgroupsByName(root)
	out := []ExternalHostgroup{}
	for _, raw := range listField(root, "hostgroups") {
		hg := asMap(raw)
		if stateOrDefault(hg, "present") == "absent" {
			continue
		}
		membership := mapField(hg, "membership")
		name := stringField(hg, "name")
		effective := map[string]bool{}
		expandHostgroupHosts(hostgroupsByName, name, map[string]bool{}, effective)
		out = append(out, ExternalHostgroup{
			Name:             name,
			Description:      stringField(hg, "description"),
			HostIDs:          sortedCopy(stringListField(membership, "hosts")),
			Hostgroups:       sortedCopy(stringListField(membership, "hostgroups")),
			EffectiveHostIDs: sortedSetKeysOrNil(effective),
		})
	}
	return out
}

// ExternalRosterHost is one state:present roster host mapping input (design
// spec §11.3). It deliberately exposes only name/address; state:absent roster
// hosts are omitted, and no other roster host field is exposed. The outbound
// projection uses it to resolve references to hosts.yml IDs, never as a
// second snapshot host entity.
type ExternalRosterHost struct {
	Name    string
	Address string
}

// ExternalRosterHosts returns every state:present roster host.
func ExternalRosterHosts(root map[string]any) []ExternalRosterHost {
	out := []ExternalRosterHost{}
	for _, raw := range listField(root, "hosts") {
		h := asMap(raw)
		if stateOrDefault(h, "present") == "absent" {
			continue
		}
		out = append(out, ExternalRosterHost{
			Name:    stringField(h, "name"),
			Address: stringField(h, "ip_address"),
		})
	}
	return out
}

// ExternalLoginAccess is one login-access entity for the outbound webhook
// projection (design spec §12.2): a static HBAC rule, an active
// temporary_grant, or an active breakglass activation (ExternalEffectiveAccess
// builds the breakglass entries from its breakglassActivations parameter,
// since this package has no access to runtime activation state itself).
type ExternalLoginAccess struct {
	Source     string // "static_hbac" | "temporary_grant"
	Rule       string
	Users      []string
	AllHosts   bool
	HostIDs    []string
	Services   []string
	ValidUntil *time.Time
}

// ExternalSudoAccess is sudo's counterpart (design spec §12.3): a static
// sudo rule or an active sudo_grant.
type ExternalSudoAccess struct {
	Source         string // "static_sudo" | "sudo_grant"
	Rule           string
	Users          []string
	AllHosts       bool
	HostIDs        []string
	AllCommands    bool
	Commands       []string
	DeniedCommands []string
	RunAsUsers     []string
	RunAsGroups    []string
	Options        []string
	ValidNotBefore *time.Time
	ValidNotAfter  *time.Time
}

// BreakglassActivationInput is one currently-active breakglass grant, as
// already resolved by the caller (internal/accessgrants.Status +
// Activation.IsActive(now)) — this package cannot import
// internal/accessgrants (it already imports this package).
type BreakglassActivationInput struct {
	Name      string
	ExpiresAt time.Time
}

// ExternalEffectiveAccess resolves every login/sudo access entity design
// spec §12.4 requires: static HBAC/sudo rules (disabled/absent omitted),
// currently-active temporary_grant/sudo_grant entries (pending/expired
// omitted), each intersected with the present+enabled user set — a rule
// whose resulting user set is empty is itself omitted (§12.4 rule 6).
// Breakglass entities are appended from breakglassActivations,
// deliberately not read from the roster/runtime directly.
func ExternalEffectiveAccess(root map[string]any, now time.Time, breakglassActivations []BreakglassActivationInput) (login []ExternalLoginAccess, sudo []ExternalSudoAccess, err error) {
	allowedUsers, err := presentEnabledUserSet(root, now)
	if err != nil {
		return nil, nil, err
	}

	for _, rule := range EffectiveHBACAccessFromRoster(root) {
		if !rule.Enabled {
			continue
		}
		users := intersectSorted(rule.Users, allowedUsers)
		if len(users) == 0 {
			continue
		}
		login = append(login, ExternalLoginAccess{
			Source:   "static_hbac",
			Rule:     rule.Rule,
			Users:    users,
			AllHosts: rule.AllHosts,
			HostIDs:  rule.Hosts,
			Services: rule.Services,
		})
	}

	for _, rule := range EffectiveSudoAccessFromRoster(root) {
		users := intersectSorted(rule.Users, allowedUsers)
		if len(users) == 0 {
			continue
		}
		sudo = append(sudo, ExternalSudoAccess{
			Source:         "static_sudo",
			Rule:           rule.Rule,
			Users:          users,
			AllHosts:       rule.AllHosts,
			HostIDs:        rule.Hosts,
			AllCommands:    rule.AllCommands,
			Commands:       rule.Commands,
			DeniedCommands: rule.DeniedCommands,
			RunAsUsers:     rule.RunAsUsers,
			RunAsGroups:    rule.RunAsGroups,
			Options:        rule.Options,
		})
	}

	groupsByName := rosterGroupsByName(root)
	hostgroupsByName := rosterHostgroupsByName(root)
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
		validity, verr := ParseGrantValidity(mapField(grant, "validity"))
		if verr != nil {
			return nil, nil, verr
		}
		if EvaluateGrantLifecycle(state, validity, now) != GrantActive {
			continue
		}

		subjects := mapField(grant, "subjects")
		userSet := map[string]bool{}
		for _, u := range stringListField(subjects, "users") {
			userSet[u] = true
		}
		for _, g := range stringListField(subjects, "groups") {
			expandGroupMembers(groupsByName, g, map[string]bool{}, userSet)
		}
		users := intersectSorted(sortedSetKeys(userSet), allowedUsers)
		if len(users) == 0 {
			continue
		}

		targets := mapField(grant, "targets")
		allHosts := stringField(targets, "hostcat") == "all"
		hosts := map[string]bool{}
		if !allHosts {
			for _, h := range stringListField(targets, "hosts") {
				hosts[h] = true
			}
			for _, hg := range stringListField(targets, "hostgroups") {
				expandHostgroupHosts(hostgroupsByName, hg, map[string]bool{}, hosts)
			}
		}
		validUntil := validity.NotAfter.UTC()
		name := stringField(grant, "name")

		switch kind {
		case grantKindTemporary:
			login = append(login, ExternalLoginAccess{
				Source:     "temporary_grant",
				Rule:       name,
				Users:      users,
				AllHosts:   allHosts,
				HostIDs:    sortedSetKeysOrNil(hosts),
				Services:   stringListField(grant, "services"),
				ValidUntil: &validUntil,
			})
		case grantKindSudo:
			privilege := mapField(grant, "privilege")
			runAs := mapField(grant, "run_as")
			allowCommands := stringListField(privilege, "commands")
			allowCommandGroups := stringListField(privilege, "command_groups")
			allCommands := len(allowCommands)+len(allowCommandGroups) == 0
			var notBefore *time.Time
			if !validity.NotBefore.IsZero() {
				nb := validity.NotBefore.UTC()
				notBefore = &nb
			}
			sudo = append(sudo, ExternalSudoAccess{
				Source:         "sudo_grant",
				Rule:           name,
				Users:          users,
				AllHosts:       allHosts,
				HostIDs:        sortedSetKeysOrNil(hosts),
				AllCommands:    allCommands,
				Commands:       sortedCopy(allowCommands),
				RunAsUsers:     sortedCopy(stringListField(runAs, "users")),
				RunAsGroups:    sortedCopy(stringListField(runAs, "groups")),
				Options:        sortedCopy(stringListField(grant, "options")),
				ValidNotBefore: notBefore,
				ValidNotAfter:  &validUntil,
			})
		}
	}

	maxExpiryByName := map[string]time.Time{}
	for _, act := range breakglassActivations {
		if cur, ok := maxExpiryByName[act.Name]; !ok || act.ExpiresAt.After(cur) {
			maxExpiryByName[act.Name] = act.ExpiresAt
		}
	}
	activeNames := make([]string, 0, len(maxExpiryByName))
	for name := range maxExpiryByName {
		activeNames = append(activeNames, name)
	}
	sort.Strings(activeNames)
	for _, name := range activeNames {
		expiresAt := maxExpiryByName[name]
		grant, ok := FindGrant(root, name)
		if !ok || stateOrDefault(grant, "present") == "absent" {
			continue
		}
		subjects := mapField(grant, "subjects")
		users := intersectSorted(stringListField(subjects, "users"), allowedUsers)
		if len(users) == 0 {
			continue
		}
		targets := mapField(grant, "targets")
		allHosts := stringField(targets, "hostcat") == "all"
		hosts := map[string]bool{}
		if !allHosts {
			for _, h := range stringListField(targets, "hosts") {
				hosts[h] = true
			}
			for _, hg := range stringListField(targets, "hostgroups") {
				expandHostgroupHosts(hostgroupsByName, hg, map[string]bool{}, hosts)
			}
		}
		expiresAtUTC := expiresAt.UTC()
		login = append(login, ExternalLoginAccess{
			Source:     "breakglass",
			Rule:       name,
			Users:      users,
			AllHosts:   allHosts,
			HostIDs:    sortedSetKeysOrNil(hosts),
			Services:   stringListField(grant, "services"),
			ValidUntil: &expiresAtUTC,
		})
	}

	return login, sudo, nil
}
