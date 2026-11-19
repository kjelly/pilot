package identityreconcile

import (
	"fmt"
	"strings"
)

// The HBAC part of the desired state (Phase 3a: docs/superpowers/specs/
// 2026-11-19-freeipa-go-reconcile-phase3-hbac-spec.md §3). Like the users and groups
// it follows playbooks/apply/freeipa-identity-apply.yml ("Normalize canonical HBAC
// rules for the compatibility reconciler"), the engine it must agree with.

// DesiredHBACRule is one roster HBAC rule that is not state: absent.
type DesiredHBACRule struct {
	Name       string   // as written: it is what the rule is created with
	Users      []string // lower case, sorted
	Groups     []string
	Services   []string
	Hosts      []string // lower case as written; a short name is completed at plan time
	Hostgroups []string
	// HostCategory is "all" when the rule names no host and no hostgroup, and "" when
	// it names some: the roster's targets.hostcat means the same thing, and the
	// validator refuses a rule that has neither.
	HostCategory string
	Enabled      bool
}

// DesiredHBAC is the roster's hbac section, and the objects the rules refer to that
// the roster itself declares (the playbook creates them before the rules are
// reconciled, so a rule may refer to one that FreeIPA does not have yet).
type DesiredHBAC struct {
	// Services are the hbac.services names, as written.
	Services []string
	Rules    []DesiredHBACRule
	// AbsentRules are the rules marked state: absent, as written.
	AbsentRules     []string
	DisableAllowAll bool

	// What the rest of the roster declares, for a rule's references (lower case).
	DeclaredHosts, DeclaredHostgroups []string
	// DeclaredUsers and DeclaredGroups are the users and groups of the roster that are
	// not state: absent; AbsentUsers and AbsentGroups are those that are.
	DeclaredUsers, DeclaredGroups []string
	AbsentUsers, AbsentGroups     []string
}

// HBACFromRoster reads the HBAC part of a roster that is read the way the users and
// groups are: a roster FromRoster refuses is refused here too.
func HBACFromRoster(root map[string]any) (DesiredHBAC, error) {
	var d DesiredHBAC
	base, err := FromRoster(root)
	if err != nil {
		return d, err
	}
	for _, u := range base.Users {
		d.DeclaredUsers = append(d.DeclaredUsers, strings.ToLower(u.Name))
	}
	for _, g := range base.Groups {
		d.DeclaredGroups = append(d.DeclaredGroups, strings.ToLower(g.Name))
	}
	for _, n := range base.AbsentUsers {
		d.AbsentUsers = append(d.AbsentUsers, strings.ToLower(n))
	}
	for _, n := range base.AbsentGroups {
		d.AbsentGroups = append(d.AbsentGroups, strings.ToLower(n))
	}
	if d.DeclaredHosts, err = declaredNames(root, "hosts"); err != nil {
		return d, err
	}
	if d.DeclaredHostgroups, err = declaredNames(root, "hostgroups"); err != nil {
		return d, err
	}

	hbac, err := optionalMapping(root, "hbac")
	if err != nil {
		return d, err
	}
	if d.DisableAllowAll, err = boolOr(hbac, "disable_allow_all", false); err != nil {
		return d, fmt.Errorf("hbac.%w", err)
	}
	services, err := rosterEntries(hbac, "services")
	if err != nil {
		return d, fmt.Errorf("hbac.%w", err)
	}
	for _, s := range services {
		if s.name == "" {
			return d, fmt.Errorf("hbac.services: a service has an empty name")
		}
		d.Services = append(d.Services, s.name)
	}
	rules, err := rosterEntries(hbac, "rules")
	if err != nil {
		return d, fmt.Errorf("hbac.%w", err)
	}
	for i, e := range rules {
		where := fmt.Sprintf("hbac.rules[%d] (%s)", i, e.name)
		if e.name == "" {
			return d, fmt.Errorf("hbac.rules[%d]: the name is empty", i)
		}
		state, err := stringOr(e.fields, "state", "present")
		if err != nil {
			return d, fmt.Errorf("%s: %w", where, err)
		}
		if state == "absent" {
			d.AbsentRules = append(d.AbsentRules, e.name)
			continue
		}
		r, err := desiredHBACRule(e)
		if err != nil {
			return d, fmt.Errorf("%s: %w", where, err)
		}
		d.Rules = append(d.Rules, r)
	}
	return d, nil
}

func desiredHBACRule(e rosterEntry) (DesiredHBACRule, error) {
	r := DesiredHBACRule{Name: e.name}
	var err error
	subjects, err := optionalMapping(e.fields, "subjects")
	if err != nil {
		return r, err
	}
	if r.Users, _, err = nameList(subjects, "users"); err != nil {
		return r, fmt.Errorf("subjects.%w", err)
	}
	if r.Groups, _, err = nameList(subjects, "groups"); err != nil {
		return r, fmt.Errorf("subjects.%w", err)
	}
	targets, err := optionalMapping(e.fields, "targets")
	if err != nil {
		return r, err
	}
	if r.Hosts, _, err = nameList(targets, "hosts"); err != nil {
		return r, fmt.Errorf("targets.%w", err)
	}
	if r.Hostgroups, _, err = nameList(targets, "hostgroups"); err != nil {
		return r, fmt.Errorf("targets.%w", err)
	}
	if len(r.Hosts)+len(r.Hostgroups) == 0 {
		r.HostCategory = "all"
	}
	if r.Services, _, err = nameList(e.fields, "services"); err != nil {
		return r, err
	}
	if r.Enabled, err = boolOr(e.fields, "enabled", true); err != nil {
		return r, err
	}
	return r, nil
}

// declaredNames is the lower-case names of the entries of a roster list that are not
// state: absent.
func declaredNames(root map[string]any, key string) ([]string, error) {
	entries, err := rosterEntries(root, key)
	if err != nil {
		return nil, err
	}
	var out []string
	for i, e := range entries {
		state, err := stringOr(e.fields, "state", "present")
		if err != nil {
			return nil, fmt.Errorf("%s[%d] (%s): %w", key, i, e.name, err)
		}
		if state != "absent" {
			out = appendUnique(out, strings.ToLower(e.name))
		}
	}
	return out, nil
}
