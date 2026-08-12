// roster_effective.go resolves the roster's nested relationships — group
// membership (a group can list other groups in membership.groups) and
// hostgroup membership (a hostgroup can list other hostgroups in
// membership.hostgroups) — into flat, transitively-expanded results.
// pilot_edit_inspect exposes these as effective_hbac_access/
// effective_sudo_access so an MCP caller never has to walk the nested
// group/hostgroup graph itself (and risk missing a multi-hop chain or an
// unguarded cycle) to answer "can user X reach host Y".
package inventory

import "sort"

// rosterGroupsByName indexes roster groups by name, skipping state: absent
// entries — an absent group's membership is meaningless for access
// resolution (it is being removed, not granting anything).
func rosterGroupsByName(root map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, raw := range listField(root, "groups") {
		g := asMap(raw)
		if stateOrDefault(g, "present") == "absent" {
			continue
		}
		if name := stringField(g, "name"); name != "" {
			out[name] = g
		}
	}
	return out
}

// rosterHostgroupsByName is rosterGroupsByName's hostgroup counterpart.
func rosterHostgroupsByName(root map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, raw := range listField(root, "hostgroups") {
		hg := asMap(raw)
		if stateOrDefault(hg, "present") == "absent" {
			continue
		}
		if name := stringField(hg, "name"); name != "" {
			out[name] = hg
		}
	}
	return out
}

// expandGroupMembers walks membership.groups recursively, collecting every
// directly- or transitively-reachable username into into. visiting guards
// against a cycle in the membership graph — checkGroups only rejects a
// group listing itself, not a longer A-lists-B-lists-A cycle, so this must
// defend against one rather than assume the roster is acyclic. An unknown
// group reference is skipped silently, matching the read-only display
// posture of RosterGroup/RosterHostgroup elsewhere in this package.
func expandGroupMembers(groupsByName map[string]map[string]any, name string, visiting map[string]bool, into map[string]bool) {
	if visiting[name] {
		return
	}
	g, ok := groupsByName[name]
	if !ok {
		return
	}
	visiting[name] = true
	defer delete(visiting, name)
	membership := mapField(g, "membership")
	for _, u := range stringListField(membership, "users") {
		into[u] = true
	}
	for _, gg := range stringListField(membership, "groups") {
		expandGroupMembers(groupsByName, gg, visiting, into)
	}
}

// expandHostgroupHosts is expandGroupMembers' hostgroup counterpart.
func expandHostgroupHosts(hostgroupsByName map[string]map[string]any, name string, visiting map[string]bool, into map[string]bool) {
	if visiting[name] {
		return
	}
	hg, ok := hostgroupsByName[name]
	if !ok {
		return
	}
	visiting[name] = true
	defer delete(visiting, name)
	membership := mapField(hg, "membership")
	for _, h := range stringListField(membership, "hosts") {
		into[h] = true
	}
	for _, hh := range stringListField(membership, "hostgroups") {
		expandHostgroupHosts(hostgroupsByName, hh, visiting, into)
	}
}

func sortedSetKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortedSetKeysOrNil is sortedSetKeys but reports an empty set as nil
// rather than an empty-but-non-nil slice, so a JSON field tagged omitempty
// (e.g. EffectiveHBACAccess.Hosts when AllHosts is true) is actually
// omitted.
func sortedSetKeysOrNil(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	return sortedSetKeys(m)
}

// EffectiveGroupMembers returns every username that is a member of
// groupName, directly (membership.users) or transitively through nested
// membership.groups.
func EffectiveGroupMembers(path, groupName string) ([]string, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	into := map[string]bool{}
	expandGroupMembers(rosterGroupsByName(root), groupName, map[string]bool{}, into)
	return sortedSetKeys(into), nil
}

// EffectiveHostgroupHosts is EffectiveGroupMembers' hostgroup counterpart.
func EffectiveHostgroupHosts(path, hostgroupName string) ([]string, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	into := map[string]bool{}
	expandHostgroupHosts(rosterHostgroupsByName(root), hostgroupName, map[string]bool{}, into)
	return sortedSetKeys(into), nil
}

// EffectiveHBACAccess is one HBAC rule's fully-resolved subject and target
// scope — subjects.groups and targets.hostgroups already expanded
// (recursively) into concrete usernames/host FQDNs, so a caller never needs
// to walk the nested group/hostgroup graph itself to answer "can user X
// reach host Y". It does not model FreeIPA's own implicit rules (e.g. a
// built-in allow_all) beyond what hbac.disable_allow_all's break-glass gate
// already requires the roster to declare explicitly — only rules present
// in the roster are represented here.
type EffectiveHBACAccess struct {
	Rule     string   `json:"rule"`
	Enabled  bool     `json:"enabled"`
	Users    []string `json:"users"`
	AllHosts bool     `json:"all_hosts"`
	Hosts    []string `json:"hosts,omitempty"`
	Services []string `json:"services"`
}

// EffectiveHBACAccessList resolves every rule in the roster at path.
// Rules with state: absent are omitted — they grant nothing.
func EffectiveHBACAccessList(path string) ([]EffectiveHBACAccess, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	return EffectiveHBACAccessFromRoster(root), nil
}

// EffectiveHBACAccessFromRoster is EffectiveHBACAccessList's in-memory
// counterpart, evaluating an already-parsed root directly instead of
// reading a path. Migration's semantic-equivalence fingerprint
// (roster_migrate.go) needs this: it compares a v1->v2 candidate that
// exists only in memory against the original, and writing the candidate
// to a temp file just to re-read it here would defeat the point of
// validating before ever touching disk.
func EffectiveHBACAccessFromRoster(root map[string]any) []EffectiveHBACAccess {
	groupsByName := rosterGroupsByName(root)
	hostgroupsByName := rosterHostgroupsByName(root)

	out := []EffectiveHBACAccess{}
	for _, raw := range listField(mapField(root, "hbac"), "rules") {
		item := asMap(raw)
		if stateOrDefault(item, "present") == "absent" {
			continue
		}

		subjects := mapField(item, "subjects")
		users := map[string]bool{}
		for _, u := range stringListField(subjects, "users") {
			users[u] = true
		}
		for _, g := range stringListField(subjects, "groups") {
			expandGroupMembers(groupsByName, g, map[string]bool{}, users)
		}

		targets := mapField(item, "targets")
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

		out = append(out, EffectiveHBACAccess{
			Rule:     stringField(item, "name"),
			Enabled:  boolFieldDefault(item, "enabled", true),
			Users:    sortedSetKeys(users),
			AllHosts: allHosts,
			Hosts:    sortedSetKeysOrNil(hosts),
			Services: stringListField(item, "services"),
		})
	}
	return out
}

// EffectiveSudoAccess is one sudo rule's fully-resolved subject, target,
// and command scope — mirrors EffectiveHBACAccess's resolution.
// DeniedCommandGroups is reported by name only (not expanded to commands,
// and not subtracted from Commands/AllCommands): this schema's deny
// semantics are narrower than "allow minus deny", and this function does
// not attempt to compute a final effective-permission set beyond what the
// roster declares.
type EffectiveSudoAccess struct {
	Rule                string   `json:"rule"`
	Users               []string `json:"users"`
	AllHosts            bool     `json:"all_hosts"`
	Hosts               []string `json:"hosts,omitempty"`
	AllCommands         bool     `json:"all_commands"`
	Commands            []string `json:"commands,omitempty"`
	DeniedCommandGroups []string `json:"denied_command_groups,omitempty"`
}

// EffectiveSudoAccessList resolves every rule in sudo.rules. Rules with
// state: absent are omitted.
func EffectiveSudoAccessList(path string) ([]EffectiveSudoAccess, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	return EffectiveSudoAccessFromRoster(root), nil
}

// EffectiveSudoAccessFromRoster is EffectiveSudoAccessList's in-memory
// counterpart — see EffectiveHBACAccessFromRoster's doc comment for why
// migration's semantic-equivalence fingerprint needs this shape.
func EffectiveSudoAccessFromRoster(root map[string]any) []EffectiveSudoAccess {
	groupsByName := rosterGroupsByName(root)
	hostgroupsByName := rosterHostgroupsByName(root)
	sudo := mapField(root, "sudo")
	commandGroupsByName := map[string]map[string]any{}
	for _, raw := range listField(sudo, "command_groups") {
		cg := asMap(raw)
		if name := stringField(cg, "name"); name != "" {
			commandGroupsByName[name] = cg
		}
	}

	out := []EffectiveSudoAccess{}
	for _, raw := range listField(sudo, "rules") {
		item := asMap(raw)
		if stateOrDefault(item, "present") == "absent" {
			continue
		}

		subjects := mapField(item, "subjects")
		users := map[string]bool{}
		for _, u := range stringListField(subjects, "users") {
			users[u] = true
		}
		for _, g := range stringListField(subjects, "groups") {
			expandGroupMembers(groupsByName, g, map[string]bool{}, users)
		}

		targets := mapField(item, "targets")
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

		// allow.command_category is only ever validated as absent or "all"
		// (roster_validate.go's checkSudoRules never requires one of
		// command_category/commands/command_groups to be set), and
		// freeipa-identity-apply.yml's own sudorule-add-allow-command task
		// treats a bare `allow: {}` as an implicit allow-all — the same
		// "omitted category defaults to all" convention as HBAC's hostcat.
		// This must mirror that default rather than reading
		// command_category literally, or a rule with allow: {} (a valid,
		// real roster shape) is misreported as "all_commands: false" with
		// zero commands — the opposite of what it actually grants.
		allow := mapField(item, "allow")
		allowCommands := stringListField(allow, "commands")
		allowCommandGroups := stringListField(allow, "command_groups")
		allCommands := len(allowCommands) == 0 && len(allowCommandGroups) == 0
		commands := map[string]bool{}
		if !allCommands {
			for _, c := range allowCommands {
				commands[c] = true
			}
			for _, cg := range allowCommandGroups {
				if group, ok := commandGroupsByName[cg]; ok {
					for _, c := range stringListField(group, "commands") {
						commands[c] = true
					}
				}
			}
		}

		out = append(out, EffectiveSudoAccess{
			Rule:                stringField(item, "name"),
			Users:               sortedSetKeys(users),
			AllHosts:            allHosts,
			Hosts:               sortedSetKeysOrNil(hosts),
			AllCommands:         allCommands,
			Commands:            sortedSetKeysOrNil(commands),
			DeniedCommandGroups: stringListField(mapField(item, "deny"), "command_groups"),
		})
	}
	return out
}
