package accessportal

import (
	"time"

	"github.com/kjelly/pilot/internal/freeipaaccess"
)

// sudoRuleActive implements spec.md §17.1's time semantics: enabled AND
// (no NotBefore or now is past it) AND (no NotAfter or now is before it).
func sudoRuleActive(rule freeipaaccess.SudoRule, now time.Time) bool {
	if !rule.Enabled {
		return false
	}
	if rule.NotBefore != nil && now.Before(*rule.NotBefore) {
		return false
	}
	if rule.NotAfter != nil && !now.Before(*rule.NotAfter) {
		return false
	}
	return true
}

// sudoRuleGrants mirrors hbacRuleGrants's subject/host matching (sudo
// rules have no service concept) plus the active-window check.
func sudoRuleGrants(
	rule freeipaaccess.SudoRule,
	now time.Time,
	username string,
	effectiveGroups map[string]struct{},
	fqdn string,
	hostgroupHosts map[string]map[string]struct{},
) (bool, SudoRuleSource) {
	if !sudoRuleActive(rule, now) {
		return false, SudoRuleSource{}
	}
	userOK, _ := subjectMatch(rule.UserCategoryAll, rule.Users, rule.Groups, username, effectiveGroups)
	if !userOK {
		return false, SudoRuleSource{}
	}
	hostOK, _ := hostMatch(rule.HostCategoryAll, rule.Hosts, rule.Hostgroups, fqdn, hostgroupHosts)
	if !hostOK {
		return false, SudoRuleSource{}
	}
	return true, SudoRuleSource{Rule: rule.Name}
}

// sudoDisplayScope classifies a host's aggregate sudo access (spec.md
// §17.3): none (no active matching rule), limited (specific commands),
// all (a matching rule has cmdcategory=all and nothing denies), or
// all_with_deny (cmdcategory=all but some rule also denies specific
// commands).
func sudoDisplayScope(hasAnyRule, anyCommandCategoryAll, anyDeny bool) string {
	switch {
	case !hasAnyRule:
		return "none"
	case anyCommandCategoryAll && anyDeny:
		return "all_with_deny"
	case anyCommandCategoryAll:
		return "all"
	default:
		return "limited"
	}
}
