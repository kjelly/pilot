package accessportal

import (
	"slices"

	"github.com/kjelly/pilot/internal/freeipaaccess"
)

// subjectMatch implements spec.md §15.1 (and, minus service, §17's sudo
// user match): usercategory=all, or a direct username match, or the
// user's effective groups intersecting rule.Groups.
func subjectMatch(categoryAll bool, users, groups []string, username string, effectiveGroups map[string]struct{}) (bool, []string) {
	if categoryAll {
		return true, nil
	}
	if slices.Contains(users, username) {
		return true, nil
	}
	var via []string
	for _, g := range groups {
		if _, ok := effectiveGroups[g]; ok {
			via = append(via, g)
		}
	}
	return len(via) > 0, via
}

// hostMatch implements spec.md §15.2/§17: hostcategory=all, a direct FQDN
// match, or fqdn being a member of one of rule.Hostgroups — using the
// pre-expanded hostgroup→hosts sets the resolver built once per resolve
// call (spec.md §21 Query Plan), never a per-host lookup.
func hostMatch(categoryAll bool, hosts, hostgroups []string, fqdn string, hostgroupHosts map[string]map[string]struct{}) (bool, []string) {
	if categoryAll {
		return true, nil
	}
	fqdn = CanonicalizeFQDN(fqdn)
	if containsFQDN(hosts, fqdn) {
		return true, nil
	}
	var via []string
	for _, hg := range hostgroups {
		if members, ok := hostgroupHosts[hg]; ok {
			if _, ok := members[fqdn]; ok {
				via = append(via, hg)
			}
		}
	}
	return len(via) > 0, via
}

// containsFQDN reports whether fqdn (already canonicalized by the caller)
// appears in hosts, comparing after canonicalizing each entry — spec.md
// §14's "lowercase, trim trailing dot" rule applies to both sides.
func containsFQDN(hosts []string, fqdn string) bool {
	for _, h := range hosts {
		if CanonicalizeFQDN(h) == fqdn {
			return true
		}
	}
	return false
}

// serviceMatch implements spec.md §15.3, restricted to Portal v1's single
// fixed service "sshd".
func serviceMatch(categoryAll bool, services, serviceGroups []string, service string, serviceGroupServices map[string]map[string]struct{}) bool {
	if categoryAll {
		return true
	}
	if slices.Contains(services, service) {
		return true
	}
	for _, sg := range serviceGroups {
		if members, ok := serviceGroupServices[sg]; ok {
			if _, ok := members[service]; ok {
				return true
			}
		}
	}
	return false
}

// hbacRuleGrants reports whether rule grants username@fqdn access to
// service. A disabled rule never grants (spec.md §15: "disabled HBAC
// rule: never grants").
func hbacRuleGrants(
	rule freeipaaccess.HBACRule,
	username string,
	effectiveGroups map[string]struct{},
	fqdn string,
	hostgroupHosts map[string]map[string]struct{},
	service string,
	serviceGroupServices map[string]map[string]struct{},
) (bool, RuleSource) {
	if !rule.Enabled {
		return false, RuleSource{}
	}
	userOK, viaGroups := subjectMatch(rule.UserCategoryAll, rule.Users, rule.Groups, username, effectiveGroups)
	if !userOK {
		return false, RuleSource{}
	}
	hostOK, viaHostgroups := hostMatch(rule.HostCategoryAll, rule.Hosts, rule.Hostgroups, fqdn, hostgroupHosts)
	if !hostOK {
		return false, RuleSource{}
	}
	if !serviceMatch(rule.ServiceCategoryAll, rule.Services, rule.ServiceGroups, service, serviceGroupServices) {
		return false, RuleSource{}
	}
	return true, RuleSource{
		Rule:          rule.Name,
		DirectUser:    slices.Contains(rule.Users, username),
		ViaGroups:     viaGroups,
		DirectHost:    containsFQDN(rule.Hosts, CanonicalizeFQDN(fqdn)),
		ViaHostgroups: viaHostgroups,
	}
}
