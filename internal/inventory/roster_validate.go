package inventory

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// RosterViolation is one structural or semantic problem found in a roster.
// Rule names cross-reference the exact freeipa-identity-apply.yml
// "Gate: canonical ..." assert task each check mirrors, so a roster that
// passes ValidateRoster should also pass those gates at real-apply time —
// see that playbook's pre_tasks for the authoritative rules this replicates.
type RosterViolation struct {
	Rule   string
	Detail string
}

func (v RosterViolation) String() string {
	return fmt.Sprintf("[%s] %s", v.Rule, v.Detail)
}

// ValidateRosterFile reads and validates the roster at path. It returns
// ErrRosterEncrypted unchanged (same detection as RosterDomain) if the
// file can't be inspected without a vault password.
func ValidateRosterFile(path string) ([]RosterViolation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(strings.TrimSpace(string(data)), "$ANSIBLE_VAULT") {
		return nil, ErrRosterEncrypted
	}
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse roster %s: %w", path, err)
	}
	return ValidateRoster(root), nil
}

// ValidateRoster runs every structural/semantic check against an
// already-parsed roster document (a plain map[string]any, e.g. from
// yaml.Unmarshal(data, &root)).
func ValidateRoster(root map[string]any) []RosterViolation {
	var v []RosterViolation
	v = append(v, checkSchemaVersion(root)...)
	v = append(v, checkTopLevelKeys(root)...)
	v = append(v, checkMigration(root)...)

	users := listField(root, "users")
	groups := listField(root, "groups")
	hosts := listField(root, "hosts")
	hostgroups := listField(root, "hostgroups")

	v = append(v, checkUsers(users)...)
	v = append(v, checkGroups(groups)...)
	v = append(v, checkHosts(hosts)...)
	v = append(v, checkUniqueAndReferences(users, groups)...)
	v = append(v, checkHBAC(root, groups, hostgroups)...)
	v = append(v, checkSudo(root, groups)...)
	return v
}

// ---- Gate: canonical roster version -----------------------------------

func checkSchemaVersion(root map[string]any) []RosterViolation {
	v, ok := root["schema_version"]
	if !ok {
		return []RosterViolation{{Rule: "schema_version", Detail: "schema_version is required (must be 1)"}}
	}
	n, ok := toInt(v)
	if !ok || n != 1 {
		return []RosterViolation{{Rule: "schema_version", Detail: fmt.Sprintf("schema_version must be 1, got %v", v)}}
	}
	return nil
}

// ---- Gate: canonical top-level and FreeIPA keys are known ---------------

var (
	knownTopLevelKeys = []string{
		"schema_version", "freeipa", "users", "groups", "hosts",
		"hostgroups", "hbac", "sudo", "nfs", "nfs_clients",
		"migration", "policy_exceptions",
	}
	knownFreeIPAKeys      = []string{"domain", "realm", "server", "admin", "defaults", "safety"}
	knownFreeIPAAdminKeys = []string{"principal", "password"}
)

func checkTopLevelKeys(root map[string]any) []RosterViolation {
	var out []RosterViolation
	if unk := unknownKeys(root, knownTopLevelKeys); len(unk) > 0 {
		out = append(out, RosterViolation{Rule: "top-level keys", Detail: fmt.Sprintf("unknown top-level key(s): %s", strings.Join(unk, ", "))})
	}
	freeipa := mapField(root, "freeipa")
	if unk := unknownKeys(freeipa, knownFreeIPAKeys); len(unk) > 0 {
		out = append(out, RosterViolation{Rule: "freeipa keys", Detail: fmt.Sprintf("unknown freeipa field(s): %s", strings.Join(unk, ", "))})
	}
	admin := mapField(freeipa, "admin")
	if unk := unknownKeys(admin, knownFreeIPAAdminKeys); len(unk) > 0 {
		out = append(out, RosterViolation{Rule: "freeipa.admin keys", Detail: fmt.Sprintf("unknown freeipa.admin field(s): %s", strings.Join(unk, ", "))})
	}
	return out
}

// ---- Gate: canonical migration remains a dedicated fail-closed workflow -

func checkMigration(root map[string]any) []RosterViolation {
	if m := mapField(root, "migration"); len(m) > 0 {
		return []RosterViolation{{Rule: "migration", Detail: "migration must be empty — it remains a dedicated fail-closed workflow, not reconciled by this playbook"}}
	}
	return nil
}

// ---- Gate: canonical user objects are structurally valid -----------------

var (
	userNameRe            = regexp.MustCompile(`^[a-z_][a-z0-9_.-]*$`)
	knownUserKeys         = []string{"name", "state", "first", "last", "display_name", "email", "uid", "gid", "login_shell", "home_directory", "password", "ssh_keys", "enabled"}
	knownUserPasswordKeys = []string{"initial", "force_change", "preserve_existing"}
	knownUserSSHKeysKeys  = []string{"authoritative", "values"}
)

func checkUsers(users []any) []RosterViolation {
	var out []RosterViolation
	for _, raw := range users {
		u := asMap(raw)
		label := labelOf(u)

		if !userNameRe.MatchString(stringField(u, "name")) {
			out = append(out, RosterViolation{Rule: "user name", Detail: fmt.Sprintf("user %q: name must match %s", label, userNameRe.String())})
		}
		state := stateOrDefault(u, "present")
		if state != "present" && state != "disabled" && state != "absent" {
			out = append(out, RosterViolation{Rule: "user state", Detail: fmt.Sprintf("user %q: state %q must be present/disabled/absent", label, state)})
		}
		if unk := unknownKeys(u, knownUserKeys); len(unk) > 0 {
			out = append(out, RosterViolation{Rule: "user keys", Detail: fmt.Sprintf("user %q: unknown field(s) %s", label, strings.Join(unk, ", "))})
		}
		pw := mapField(u, "password")
		if unk := unknownKeys(pw, knownUserPasswordKeys); len(unk) > 0 {
			out = append(out, RosterViolation{Rule: "user password keys", Detail: fmt.Sprintf("user %q: unknown password field(s) %s", label, strings.Join(unk, ", "))})
		}
		sshKeys := mapField(u, "ssh_keys")
		if unk := unknownKeys(sshKeys, knownUserSSHKeysKeys); len(unk) > 0 {
			out = append(out, RosterViolation{Rule: "user ssh_keys keys", Detail: fmt.Sprintf("user %q: unknown ssh_keys field(s) %s", label, strings.Join(unk, ", "))})
		}
		if !boolFieldDefault(sshKeys, "authoritative", true) {
			out = append(out, RosterViolation{Rule: "user ssh_keys authoritative", Detail: fmt.Sprintf("user %q: ssh_keys.authoritative must be true", label)})
		}
		// The Ansible gate's own default for this specific check is
		// `enabled | default(false)` — not derived from state — so a
		// disabled user simply omitting `enabled` passes; only an
		// explicit enabled: true alongside state: disabled fails.
		if state == "disabled" && boolFieldDefault(u, "enabled", false) {
			out = append(out, RosterViolation{Rule: "user disabled+enabled", Detail: fmt.Sprintf("user %q: state: disabled requires enabled to not be true", label)})
		}
	}
	return out
}

// ---- Gate: canonical group objects and category prefixes are valid -----

var (
	knownGroupKeys           = []string{"name", "state", "category", "type", "description", "gid", "membership"}
	knownGroupMembershipKeys = []string{"authoritative", "users", "groups"}
	groupCategoryPrefix      = map[string]string{
		"team": "team-", "filesystem": "data-", "access": "access-", "role": "role-",
	}
)

func checkGroups(groups []any) []RosterViolation {
	var out []RosterViolation
	for _, raw := range groups {
		g := asMap(raw)
		name := stringField(g, "name")
		label := labelOf(g)

		state := stateOrDefault(g, "present")
		if state != "present" && state != "absent" {
			out = append(out, RosterViolation{Rule: "group state", Detail: fmt.Sprintf("group %q: state %q must be present/absent", label, state)})
		}

		category := stringField(g, "category")
		if prefix, ok := groupCategoryPrefix[category]; !ok {
			out = append(out, RosterViolation{Rule: "group category", Detail: fmt.Sprintf("group %q: category %q must be one of team/filesystem/access/role", label, category)})
		} else if !strings.HasPrefix(name, prefix) {
			out = append(out, RosterViolation{Rule: "group category prefix", Detail: fmt.Sprintf("group %q: category %q requires the name to start with %q", label, category, prefix)})
		}

		gtype := stringField(g, "type")
		if gtype == "" {
			gtype = "posix"
		}
		if gtype != "posix" && gtype != "nonposix" && gtype != "external" {
			out = append(out, RosterViolation{Rule: "group type", Detail: fmt.Sprintf("group %q: type %q must be posix/nonposix/external", label, gtype)})
		}

		if unk := unknownKeys(g, knownGroupKeys); len(unk) > 0 {
			out = append(out, RosterViolation{Rule: "group keys", Detail: fmt.Sprintf("group %q: unknown field(s) %s", label, strings.Join(unk, ", "))})
		}
		membership := mapField(g, "membership")
		if unk := unknownKeys(membership, knownGroupMembershipKeys); len(unk) > 0 {
			out = append(out, RosterViolation{Rule: "group membership keys", Detail: fmt.Sprintf("group %q: unknown membership field(s) %s", label, strings.Join(unk, ", "))})
		}
		if contains(stringListField(membership, "groups"), name) {
			out = append(out, RosterViolation{Rule: "group self-membership", Detail: fmt.Sprintf("group %q: cannot list itself in its own membership.groups", label)})
		}
	}
	return out
}

// ---- Gate: canonical host objects use FQDN and valid state --------------

var (
	hostFQDNRe    = regexp.MustCompile(`^[^.]+\.[^.]+\..+$`)
	ipv4LikeRe    = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3}){3}$`)
	knownHostKeys = []string{"name", "state", "ip_address", "description"}
)

func checkHosts(hosts []any) []RosterViolation {
	var out []RosterViolation
	for _, raw := range hosts {
		h := asMap(raw)
		label := labelOf(h)

		if !hostFQDNRe.MatchString(stringField(h, "name")) {
			out = append(out, RosterViolation{Rule: "host name", Detail: fmt.Sprintf("host %q: name must be FQDN-shaped", label)})
		}
		state := stateOrDefault(h, "present")
		if state != "present" && state != "absent" {
			out = append(out, RosterViolation{Rule: "host state", Detail: fmt.Sprintf("host %q: state %q must be present/absent", label, state)})
		}
		if !ipv4LikeRe.MatchString(stringField(h, "ip_address")) {
			out = append(out, RosterViolation{Rule: "host ip_address", Detail: fmt.Sprintf("host %q: ip_address must look like an IPv4 address", label)})
		}
		if unk := unknownKeys(h, knownHostKeys); len(unk) > 0 {
			out = append(out, RosterViolation{Rule: "host keys", Detail: fmt.Sprintf("host %q: unknown field(s) %s", label, strings.Join(unk, ", "))})
		}
	}
	return out
}

// ---- Gate: canonical names and direct references are unique/resolvable --

func checkUniqueAndReferences(users, groups []any) []RosterViolation {
	var out []RosterViolation
	userNames := namesOf(users)
	groupNames := namesOf(groups)

	if dupes := findDuplicates(userNames); len(dupes) > 0 {
		out = append(out, RosterViolation{Rule: "unique user names", Detail: fmt.Sprintf("duplicate user name(s): %s", strings.Join(dupes, ", "))})
	}
	if dupes := findDuplicates(groupNames); len(dupes) > 0 {
		out = append(out, RosterViolation{Rule: "unique group names", Detail: fmt.Sprintf("duplicate group name(s): %s", strings.Join(dupes, ", "))})
	}

	for _, raw := range groups {
		g := asMap(raw)
		label := labelOf(g)
		membership := mapField(g, "membership")
		for _, u := range stringListField(membership, "users") {
			if !contains(userNames, u) {
				out = append(out, RosterViolation{Rule: "group membership user reference", Detail: fmt.Sprintf("group %q: membership.users references unknown user %q", label, u)})
			}
		}
		for _, gg := range stringListField(membership, "groups") {
			if !contains(groupNames, gg) {
				out = append(out, RosterViolation{Rule: "group membership group reference", Detail: fmt.Sprintf("group %q: membership.groups references unknown group %q", label, gg)})
			}
		}
	}
	return out
}

// ---- Gate: canonical HBAC rules are safe and references are resolvable --

func checkHBAC(root map[string]any, groups, hostgroups []any) []RosterViolation {
	var out []RosterViolation
	hbac := mapField(root, "hbac")
	rules := listField(hbac, "rules")
	accessGroupNames := namesWithCategory(groups, "access")
	hostgroupNames := namesOf(hostgroups)
	allowedUsers := append(namesOf(listField(root, "users")), "admin")

	for _, raw := range rules {
		item := asMap(raw)
		label := labelOf(item)

		state := stateOrDefault(item, "present")
		if state != "present" && state != "absent" {
			out = append(out, RosterViolation{Rule: "hbac state", Detail: fmt.Sprintf("hbac rule %q: state %q must be present/absent", label, state)})
		}

		subjects := mapField(item, "subjects")
		subjUsers := stringListField(subjects, "users")
		subjGroups := stringListField(subjects, "groups")
		if len(subjUsers)+len(subjGroups) == 0 {
			out = append(out, RosterViolation{Rule: "hbac subjects", Detail: fmt.Sprintf("hbac rule %q: needs at least one subject user or group", label)})
		}

		targets := mapField(item, "targets")
		hostcat := stringField(targets, "hostcat")
		hasHostTargets := len(stringListField(targets, "hosts"))+len(stringListField(targets, "hostgroups")) > 0
		if hostcat != "all" && !hasHostTargets {
			out = append(out, RosterViolation{Rule: "hbac targets", Detail: fmt.Sprintf("hbac rule %q: targets must be hostcat: all, or list hosts/hostgroups", label)})
		}
		if hostcat == "all" && hasHostTargets {
			out = append(out, RosterViolation{Rule: "hbac targets", Detail: fmt.Sprintf("hbac rule %q: targets can't combine hostcat: all with hosts/hostgroups", label)})
		}

		if len(stringListField(item, "services")) == 0 {
			out = append(out, RosterViolation{Rule: "hbac services", Detail: fmt.Sprintf("hbac rule %q: needs at least one service", label)})
		}

		for _, g := range subjGroups {
			if !contains(accessGroupNames, g) {
				out = append(out, RosterViolation{Rule: "hbac subject group category", Detail: fmt.Sprintf("hbac rule %q: subjects.groups %q must be a group with category: access", label, g)})
			}
		}
		for _, u := range subjUsers {
			if !contains(allowedUsers, u) {
				out = append(out, RosterViolation{Rule: "hbac subject user reference", Detail: fmt.Sprintf("hbac rule %q: subjects.users references unknown user %q", label, u)})
			}
		}
		for _, hg := range stringListField(targets, "hostgroups") {
			if !contains(hostgroupNames, hg) {
				out = append(out, RosterViolation{Rule: "hbac target hostgroup reference", Detail: fmt.Sprintf("hbac rule %q: targets.hostgroups references unknown hostgroup %q", label, hg)})
			}
		}
	}
	return out
}

// ---- Gate: canonical sudo rules/commands are safe ------------------------

var (
	sudoDenylistBinaryRe = regexp.MustCompile(`^/(bin|usr/bin)/(bash|sh|su|sudo|env|python[^ /]*|perl|vim|less)$`)
	sudoDenylistMetaRe   = regexp.MustCompile("[*?;|`$<>]")
)

func checkSudo(root map[string]any, groups []any) []RosterViolation {
	var out []RosterViolation
	sudo := mapField(root, "sudo")
	roleGroupNames := namesWithCategory(groups, "role")
	rules := listField(sudo, "rules")

	for _, raw := range rules {
		item := asMap(raw)
		label := labelOf(item)

		state := stateOrDefault(item, "present")
		if state != "present" && state != "absent" {
			out = append(out, RosterViolation{Rule: "sudo state", Detail: fmt.Sprintf("sudo rule %q: state %q must be present/absent", label, state)})
		}

		subjects := mapField(item, "subjects")
		subjUsers := stringListField(subjects, "users")
		subjGroups := stringListField(subjects, "groups")
		if len(subjUsers)+len(subjGroups) == 0 {
			out = append(out, RosterViolation{Rule: "sudo subjects", Detail: fmt.Sprintf("sudo rule %q: needs at least one subject user or group", label)})
		}
		for _, g := range subjGroups {
			if !contains(roleGroupNames, g) {
				out = append(out, RosterViolation{Rule: "sudo subject group category", Detail: fmt.Sprintf("sudo rule %q: subjects.groups %q must be a group with category: role", label, g)})
			}
		}

		targets := mapField(item, "targets")
		hostcat := stringField(targets, "hostcat")
		hasHostTargets := len(stringListField(targets, "hosts"))+len(stringListField(targets, "hostgroups")) > 0
		if hostcat != "all" && !hasHostTargets {
			out = append(out, RosterViolation{Rule: "sudo targets", Detail: fmt.Sprintf("sudo rule %q: targets must be hostcat: all, or list hosts/hostgroups", label)})
		}
		if hostcat == "all" && hasHostTargets {
			out = append(out, RosterViolation{Rule: "sudo targets", Detail: fmt.Sprintf("sudo rule %q: targets can't combine hostcat: all with hosts/hostgroups", label)})
		}
	}

	var allCommands []string
	for _, raw := range listField(sudo, "command_groups") {
		allCommands = append(allCommands, stringListField(asMap(raw), "commands")...)
	}
	for _, raw := range rules {
		allow := mapField(asMap(raw), "allow")
		allCommands = append(allCommands, stringListField(allow, "commands")...)
	}
	for _, cmd := range dedupe(allCommands) {
		switch {
		case sudoDenylistBinaryRe.MatchString(cmd):
			out = append(out, RosterViolation{Rule: "sudo command denylist", Detail: fmt.Sprintf("sudo command %q is a shell-escape binary, not allowed", cmd)})
		case sudoDenylistMetaRe.MatchString(cmd):
			out = append(out, RosterViolation{Rule: "sudo command denylist", Detail: fmt.Sprintf("sudo command %q contains a shell metacharacter, not allowed", cmd)})
		}
	}
	return out
}

// ---- generic YAML-map helpers --------------------------------------------

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

func mapField(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	return asMap(m[key])
}

func listField(m map[string]any, key string) []any {
	if m == nil {
		return nil
	}
	return asList(m[key])
}

func stringField(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

func stringListField(m map[string]any, key string) []string {
	items := listField(m, key)
	out := make([]string, 0, len(items))
	for _, it := range items {
		if s, ok := it.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func boolFieldDefault(m map[string]any, key string, def bool) bool {
	if m == nil {
		return def
	}
	b, ok := m[key].(bool)
	if !ok {
		return def
	}
	return b
}

func stateOrDefault(m map[string]any, def string) string {
	if s := stringField(m, "state"); s != "" {
		return s
	}
	return def
}

func labelOf(m map[string]any) string {
	if name := stringField(m, "name"); name != "" {
		return name
	}
	return "unnamed"
}

func unknownKeys(m map[string]any, allowed []string) []string {
	allow := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		allow[a] = true
	}
	var out []string
	for k := range m {
		if !allow[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func namesOf(items []any) []string {
	out := make([]string, 0, len(items))
	for _, raw := range items {
		out = append(out, stringField(asMap(raw), "name"))
	}
	return out
}

func namesWithCategory(items []any, category string) []string {
	var out []string
	for _, raw := range items {
		m := asMap(raw)
		if stringField(m, "category") == category {
			out = append(out, stringField(m, "name"))
		}
	}
	return out
}

func findDuplicates(names []string) []string {
	seen := map[string]bool{}
	reported := map[string]bool{}
	var dupes []string
	for _, n := range names {
		if seen[n] && !reported[n] {
			dupes = append(dupes, n)
			reported[n] = true
		}
		seen[n] = true
	}
	sort.Strings(dupes)
	return dupes
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func dedupe(items []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range items {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	}
	return 0, false
}
