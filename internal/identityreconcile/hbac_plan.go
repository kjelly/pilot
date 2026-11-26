package identityreconcile

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/kjelly/pilot/internal/inventory"
)

// The HBAC plan (Phase 3a: docs/superpowers/specs/2026-11-19-freeipa-go-reconcile-phase3-hbac-spec.md
// §4). It is the playbook's HBAC section as operations, in the playbook's order:
// services, rules, then what narrows access (the disable of a rule the roster wants
// disabled, the removal of members the rule no longer names, only on that rule), the
// categories, the additions, the enable of a rule the roster wants enabled, deletion,
// and last the lockdown of allow_all.

// HBAC operation kinds, in the order a plan lists them. Removals come before the
// categories and the additions come after them: a category and members exclude each
// other (K3), so a rule that goes from hosts to hostcat all must lose its hosts
// first, and one that goes the other way must lose the category first. The disable of
// a rule the roster wants disabled comes before every change that can widen the rule
// (categories, additions) and the enable of a rule the roster wants enabled after them.
const (
	KindHBACServiceCreate     = "hbac.service.create"
	KindHBACRuleCreate        = "hbac.rule.create"
	KindHBACRuleDisable       = "hbac.rule.disable"
	KindHBACHostRemove        = "hbac.rule.member_host.remove"
	KindHBACHostgroupRemove   = "hbac.rule.member_hostgroup.remove"
	KindHBACServiceRemove     = "hbac.rule.member_service.remove"
	KindHBACUserRemove        = "hbac.rule.member_user.remove"
	KindHBACGroupRemove       = "hbac.rule.member_group.remove"
	KindHBACCategoryUpdate    = "hbac.rule.category.update"
	KindHBACHostgroupAdd      = "hbac.rule.member_hostgroup.add"
	KindHBACHostAdd           = "hbac.rule.member_host.add"
	KindHBACServiceAdd        = "hbac.rule.member_service.add"
	KindHBACUserAdd           = "hbac.rule.member_user.add"
	KindHBACGroupAdd          = "hbac.rule.member_group.add"
	KindHBACRuleEnable        = "hbac.rule.enable"
	KindHBACRuleDelete        = "hbac.rule.delete"
	KindHBACAllowAllDisable   = "hbac.allow_all.disable"
	hbacRuleNameAllowAll      = "allow_all"
	hbacRuleNameSystemdUser   = "allow_systemd-user"
	hbacAdminUser             = "admin"
	hbacCategoryAll           = "all"
	hbacFieldHostCategory     = "hostcategory"
	hbacFieldServiceCategory  = "servicecategory"
	hbacFieldEnabled          = "enabled"
	hbacFieldName             = "name"
	hbacDetailAfterPlaybook   = "declared in the roster, but FreeIPA does not have it after the playbook phase"
	hbacDetailNotDeclaredHere = "neither in FreeIPA nor declared in the roster"
)

// HBACKinds is every HBAC operation kind, in plan order.
var HBACKinds = []string{
	KindHBACServiceCreate, KindHBACRuleCreate, KindHBACRuleDisable,
	KindHBACHostRemove, KindHBACHostgroupRemove, KindHBACServiceRemove, KindHBACUserRemove, KindHBACGroupRemove,
	KindHBACCategoryUpdate,
	KindHBACHostgroupAdd, KindHBACHostAdd, KindHBACServiceAdd, KindHBACUserAdd, KindHBACGroupAdd,
	KindHBACRuleEnable, KindHBACRuleDelete, KindHBACAllowAllDisable,
}

// Reasons an HBAC object is blocked instead of planned (spec §4.2). The collision
// of two rule names that differ only in case reuses BlockedCaseCollision.
const (
	BlockedAllowAllDelete       = "allow_all_delete"
	BlockedHBACReference        = "reference_unresolved"
	BlockedLockdownNoBreakGlass = "lockdown_no_break_glass"
	BlockedDuplicateRule        = "duplicate_rule"
	BlockedUserCategoryAll      = "user_category_all"
	BlockedNameCollisionGrant   = "name_collision_with_grant"
)

// HBACReports are findings of the HBAC plan that are neither operations nor blockers.
type HBACReports struct {
	// UnmanagedRules are the rules FreeIPA has that the roster does not mention. The
	// engine leaves them alone, as the playbook does (the built-in rules are not
	// listed).
	UnmanagedRules []string `json:"unmanaged_rules"`
}

// HBACPlan is what it takes to bring the live HBAC rules to the roster's. Like the
// users and groups plan it authorizes nothing: an apply reads and plans again.
type HBACPlan struct {
	Operations []Operation `json:"operations"`
	Blocked    []Blocked   `json:"blocked"`
	Reports    HBACReports `json:"reports"`
}

// Writes counts the planned write operations.
func (p HBACPlan) Writes() int { return len(p.Operations) }

// HBACInput is what BuildHBAC plans from.
type HBACInput struct {
	Desired DesiredHBAC
	Obs     HBACObservation
	// Preview: the plan is made before the playbook phase has run, so a host,
	// hostgroup or service the roster declares and FreeIPA does not have yet is
	// assumed to exist when the rules are reconciled (spec D8). In an apply the same
	// object is blocked: the playbook phase has run and should have created it.
	Preview bool
}

// BuildHBAC plans the HBAC operations from the live state to the desired one.
func BuildHBAC(in HBACInput) HBACPlan {
	b := &hbacBuilder{in: in, plan: HBACPlan{Operations: []Operation{}, Blocked: []Blocked{}}, byKind: map[string][]Operation{}, blocked: map[string]bool{}}
	b.plan.Reports.UnmanagedRules = []string{}
	b.index()
	b.collisions()
	b.services()
	b.rules()
	b.deletions()
	b.lockdown()
	b.finish()
	return b.plan
}

type hbacBuilder struct {
	in      HBACInput
	plan    HBACPlan
	byKind  map[string][]Operation
	blocked map[string]bool // rule (lower case) -> blocked

	live      map[string]LiveHBACRule
	liveSvc   map[string]bool
	liveHosts map[string]bool
	liveHG    map[string]bool
	declSvc   map[string]bool
	declHosts map[string]bool
	declHG    map[string]bool
	absentUsr map[string]bool
	absentGrp map[string]bool
	declUsr   map[string]bool
	declGrp   map[string]bool
	createdSv map[string]string // service (lower) -> the op that creates it
}

func (b *hbacBuilder) add(op Operation) string {
	op.ID = op.Kind + ":" + op.Object
	if op.DependsOn == nil {
		op.DependsOn = []string{}
	}
	sort.Strings(op.DependsOn)
	b.byKind[op.Kind] = append(b.byKind[op.Kind], op)
	return op.ID
}

func (b *hbacBuilder) block(reason, object, detail string) {
	b.plan.Blocked = append(b.plan.Blocked, Blocked{Reason: reason, Object: object, Detail: detail})
}

func set(names []string, f func(string) string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[f(n)] = true
	}
	return m
}

func lower(s string) string { return strings.ToLower(s) }

// host is a host name as FreeIPA stores it: a lower-case FQDN. A short name is
// completed with the server's domain, as FreeIPA does (K4).
func (b *hbacBuilder) host(name string) string { return completeHost(name, b.in.Obs.Domain) }

// completeHost is a host name as FreeIPA stores it: a lower-case FQDN, a short name
// completed with domain (K4). The planner and the writer's re-reads use this one.
func completeHost(name, domain string) string {
	n := lower(strings.TrimSuffix(name, "."))
	if !strings.Contains(n, ".") && domain != "" {
		return n + "." + domain
	}
	return n
}

func (b *hbacBuilder) index() {
	obs, d := b.in.Obs, b.in.Desired
	b.live = map[string]LiveHBACRule{}
	for _, r := range obs.Rules {
		b.live[lower(r.Name)] = r
	}
	b.liveSvc = map[string]bool{}
	for _, s := range obs.Services {
		b.liveSvc[lower(s.Name)] = true
	}
	b.liveHosts = set(obs.Hosts, b.host)
	b.liveHG = set(obs.Hostgroups, lower)
	b.declSvc = set(d.Services, lower)
	b.declHosts = set(d.DeclaredHosts, b.host)
	b.declHG = set(d.DeclaredHostgroups, lower)
	b.declUsr = set(d.DeclaredUsers, lower)
	b.declGrp = set(d.DeclaredGroups, lower)
	b.absentUsr = set(d.AbsentUsers, lower)
	b.absentGrp = set(d.AbsentGroups, lower)
	b.createdSv = map[string]string{}
}

// inGrantNamespace says whether a rule name is in the name-space of the rules the grant
// compiler owns (spec §3.3): the playbook creates, changes and deletes those, so the Go
// engine must never do either for a roster rule of that name, whatever its state. The
// prefix is internal/inventory's; FreeIPA rule names are not case-sensitive.
func inGrantNamespace(name string) bool {
	return strings.HasPrefix(lower(name), lower(inventory.CompiledLoginRulePrefix))
}

// collisions blocks the rule names that appear twice once case is ignored, the roster
// rules (present or absent) in the grant compiler's name-space, and the built-in allow_all
// when it is marked absent.
func (b *hbacBuilder) collisions() {
	d := b.in.Desired
	seen := map[string][]string{}
	for _, r := range d.Rules {
		seen[lower(r.Name)] = append(seen[lower(r.Name)], r.Name)
		b.grantCollision(r.Name)
	}
	for _, n := range d.AbsentRules {
		seen[lower(n)] = append(seen[lower(n)], n)
		b.grantCollision(n)
		if lower(n) == hbacRuleNameAllowAll {
			b.block(BlockedAllowAllDelete, n, "allow_all is a FreeIPA built-in rule: it cannot be deleted with state: absent, use hbac.disable_allow_all")
			b.blocked[lower(n)] = true
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		names := seen[k]
		if len(names) < 2 {
			continue
		}
		reason := BlockedCaseCollision
		if len(slices.Compact(slices.Clone(names))) == 1 {
			reason = BlockedDuplicateRule
		}
		b.block(reason, k, fmt.Sprintf("HBAC rule names are not case-sensitive in FreeIPA; the roster writes %s", strings.Join(names, ", ")))
		b.blocked[k] = true
	}
}

// grantCollision blocks a roster rule whose name is in the grant compiler's name-space.
func (b *hbacBuilder) grantCollision(name string) {
	if !inGrantNamespace(name) || b.blocked[lower(name)] {
		return
	}
	b.block(BlockedNameCollisionGrant, name, fmt.Sprintf("rule names that start with %s belong to the rules compiled from grants, which the playbook manages: the Go engine does not reconcile or delete them", inventory.CompiledLoginRulePrefix))
	b.blocked[lower(name)] = true
}

// services creates the HBAC service objects the roster declares and FreeIPA does not
// have.
func (b *hbacBuilder) services() {
	for _, name := range b.in.Desired.Services {
		k := lower(name)
		if b.liveSvc[k] {
			continue
		}
		b.createdSv[k] = b.add(Operation{Kind: KindHBACServiceCreate, Object: k, Fields: map[string]Change{hbacFieldName: {To: name}}})
	}
}

// reference says whether a name a rule refers to can be used: FreeIPA has it, or (in a
// preview) the roster declares it and the playbook phase will create it.
func (b *hbacBuilder) reference(live, declared map[string]bool, key string) (ok bool, detail string) {
	switch {
	case live[key]:
		return true, ""
	case declared[key] && b.in.Preview:
		return true, ""
	case declared[key]:
		return false, hbacDetailAfterPlaybook
	}
	return false, hbacDetailNotDeclaredHere
}

func (b *hbacBuilder) rules() {
	for _, r := range b.in.Desired.Rules {
		key := lower(r.Name)
		if b.blocked[key] {
			continue
		}
		b.rule(r, key)
	}
}

func (b *hbacBuilder) rule(r DesiredHBACRule, key string) {
	// The references first: a rule with one that cannot be used is blocked as a whole,
	// and nothing is planned for it.
	hosts := make([]string, 0, len(r.Hosts))
	for _, h := range r.Hosts {
		hosts = appendUnique(hosts, b.host(h))
	}
	sort.Strings(hosts)
	problems := 0
	for _, h := range hosts {
		if ok, detail := b.reference(b.liveHosts, b.declHosts, h); !ok {
			b.block(BlockedHBACReference, r.Name, fmt.Sprintf("host %s is %s", h, detail))
			problems++
		}
	}
	for _, g := range r.Hostgroups {
		if ok, detail := b.reference(b.liveHG, b.declHG, g); !ok {
			b.block(BlockedHBACReference, r.Name, fmt.Sprintf("hostgroup %s is %s", g, detail))
			problems++
		}
	}
	for _, s := range r.Services {
		if b.liveSvc[s] || b.declSvc[s] {
			continue
		}
		b.block(BlockedHBACReference, r.Name, fmt.Sprintf("service %s is %s", s, hbacDetailNotDeclaredHere))
		problems++
	}
	for _, u := range r.Users {
		// A user the roster marks absent is not blocked: the Go phase deletes it, the
		// rule loses it with it (K8), and adding it again fails on the server, as it
		// does for the playbook (spec Q1, P2 E49).
		if u != hbacAdminUser && !b.declUsr[u] && !b.absentUsr[u] {
			b.block(BlockedHBACReference, r.Name, fmt.Sprintf("user %s is %s", u, hbacDetailNotDeclaredHere))
			problems++
		}
	}
	for _, g := range r.Groups {
		if !b.declGrp[g] && !b.absentGrp[g] {
			b.block(BlockedHBACReference, r.Name, fmt.Sprintf("group %s is %s", g, hbacDetailNotDeclaredHere))
			problems++
		}
	}
	if problems > 0 {
		b.blocked[key] = true
		return
	}

	live, exists := b.live[key]
	var created string
	if !exists {
		fields := map[string]Change{hbacFieldName: {To: r.Name}}
		if r.HostCategory != "" {
			fields[hbacFieldHostCategory] = Change{To: r.HostCategory}
		}
		created = b.add(Operation{Kind: KindHBACRuleCreate, Object: key, Fields: fields})
		// What a created rule looks like: enabled, with the category it was created with.
		live = LiveHBACRule{Name: r.Name, Enabled: true, HostCategory: r.HostCategory}
	} else if live.UserCategory != "" && len(r.Users)+len(r.Groups) > 0 {
		b.block(BlockedUserCategoryAll, r.Name, "the rule has user category all, which excludes the users and groups the roster names; the playbook cannot clear it either")
		b.blocked[key] = true
		return
	}
	deps := func(extra ...string) []string {
		out := slices.Clone(extra)
		if created != "" {
			out = append(out, created)
		}
		return out
	}

	// A rule the roster wants disabled and that is enabled now (a rule this run creates is
	// enabled until then) is disabled before anything else is done to it: its members and
	// categories can only widen access, and a run that stops half way must not leave the
	// rule enabled with them (spec §4.3). Its operations wait for the disable. Enabling a
	// rule the roster wants enabled is the opposite: it comes last (below).
	var disable string
	if live.Enabled && !r.Enabled {
		disable = b.add(Operation{Kind: KindHBACRuleDisable, Object: key, Fields: map[string]Change{hbacFieldEnabled: {From: true, To: false}}, DependsOn: deps()})
		inner := deps
		deps = func(extra ...string) []string { return append(inner(extra...), disable) }
	}
	var converge []string // what the rule's enable waits for
	converge = append(converge, b.members(key, live, deps, KindHBACHostRemove, KindHBACHostAdd, live.Hosts, hosts, nil)...)
	converge = append(converge, b.members(key, live, deps, KindHBACHostgroupRemove, KindHBACHostgroupAdd, live.Hostgroups, r.Hostgroups, nil)...)
	converge = append(converge, b.members(key, live, deps, KindHBACServiceRemove, KindHBACServiceAdd, live.Services, r.Services, b.createdSv)...)
	converge = append(converge, b.members(key, live, deps, KindHBACUserRemove, KindHBACUserAdd, live.Users, r.Users, nil)...)
	converge = append(converge, b.members(key, live, deps, KindHBACGroupRemove, KindHBACGroupAdd, live.Groups, r.Groups, nil)...)

	// The categories: the roster rule has services (the validator requires one), so
	// its service category is cleared; its host category is all or cleared.
	fields := map[string]Change{}
	if live.HostCategory != r.HostCategory {
		fields[hbacFieldHostCategory] = Change{From: orNil(live.HostCategory), To: r.HostCategory}
	}
	if live.ServiceCategory != "" {
		fields[hbacFieldServiceCategory] = Change{From: live.ServiceCategory, To: ""}
	}
	if len(fields) > 0 && exists {
		converge = append(converge, b.add(Operation{Kind: KindHBACCategoryUpdate, Object: key, Fields: fields, DependsOn: deps()}))
	}

	// Enabling is the last thing done to a rule: it waits for every member and category
	// operation of the rule, so a rule is never enabled half built.
	if !live.Enabled && r.Enabled {
		b.add(Operation{Kind: KindHBACRuleEnable, Object: key, Fields: map[string]Change{hbacFieldEnabled: {From: false, To: true}}, DependsOn: deps(converge...)})
	}
}

func orNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// members plans the removal of what the rule has and the roster no longer names for it,
// and the addition of what the roster names and the rule does not have. Only this rule
// is touched (spec §4.3). created maps a service to the operation that creates it, so
// the addition waits for it.
func (b *hbacBuilder) members(rule string, _ LiveHBACRule, deps func(...string) []string, removeKind, addKind string, live, want []string, created map[string]string) (ids []string) {
	wantSet := set(want, lower)
	var stale, missing []string
	for _, m := range live {
		if !wantSet[m] {
			stale = append(stale, m)
		}
	}
	liveSet := set(live, lower)
	for _, m := range want {
		if !liveSet[lower(m)] {
			missing = append(missing, lower(m))
		}
	}
	sort.Strings(stale)
	sort.Strings(missing)
	if len(stale) > 0 {
		ids = append(ids, b.add(Operation{Kind: removeKind, Object: rule, Members: stale, Destructive: true, DependsOn: deps()}))
	}
	if len(missing) > 0 {
		var extra []string
		for _, m := range missing {
			if id, ok := created[m]; ok {
				extra = append(extra, id)
			}
		}
		ids = append(ids, b.add(Operation{Kind: addKind, Object: rule, Members: missing, DependsOn: deps(extra...)}))
	}
	return ids
}

// deletions plans the deletion of the rules marked absent that FreeIPA has. One it does
// not have is converged, not an error (K2).
func (b *hbacBuilder) deletions() {
	for _, n := range b.in.Desired.AbsentRules {
		key := lower(n)
		if b.blocked[key] {
			continue
		}
		if _, ok := b.live[key]; ok {
			b.add(Operation{Kind: KindHBACRuleDelete, Object: key, Destructive: true})
		}
	}
}

// lockdown plans the disabling of allow_all. It needs a rule that keeps the admin able
// to log in: enabled, with admin as a subject, on every host (the same test the roster
// validator makes). The proof with hbactest before and after is the writer's.
func (b *hbacBuilder) lockdown() {
	d := b.in.Desired
	if !d.DisableAllowAll {
		return
	}
	breakGlass := false
	for _, r := range d.Rules {
		if r.Enabled && r.HostCategory == hbacCategoryAll && slices.Contains(r.Users, hbacAdminUser) && !b.blocked[lower(r.Name)] {
			breakGlass = true
		}
	}
	if !breakGlass {
		b.block(BlockedLockdownNoBreakGlass, hbacRuleNameAllowAll, "hbac.disable_allow_all needs an enabled rule with admin as a subject on every host, and one that is not blocked")
		return
	}
	if live, ok := b.live[hbacRuleNameAllowAll]; ok && live.Enabled {
		b.add(Operation{Kind: KindHBACAllowAllDisable, Object: hbacRuleNameAllowAll, Fields: map[string]Change{hbacFieldEnabled: {From: true, To: false}}})
	}
}

// finish orders the operations by kind and reports the rules the roster does not mention.
func (b *hbacBuilder) finish() {
	for _, k := range HBACKinds {
		b.plan.Operations = append(b.plan.Operations, b.byKind[k]...)
	}
	mentioned := map[string]bool{}
	for _, r := range b.in.Desired.Rules {
		mentioned[lower(r.Name)] = true
	}
	for _, n := range b.in.Desired.AbsentRules {
		mentioned[lower(n)] = true
	}
	for _, r := range b.in.Obs.Rules {
		k := lower(r.Name)
		if mentioned[k] || k == hbacRuleNameAllowAll || k == hbacRuleNameSystemdUser {
			continue
		}
		b.plan.Reports.UnmanagedRules = append(b.plan.Reports.UnmanagedRules, r.Name)
	}
	sort.Strings(b.plan.Reports.UnmanagedRules)
	sort.SliceStable(b.plan.Blocked, func(i, j int) bool {
		if b.plan.Blocked[i].Object != b.plan.Blocked[j].Object {
			return b.plan.Blocked[i].Object < b.plan.Blocked[j].Object
		}
		return b.plan.Blocked[i].Detail < b.plan.Blocked[j].Detail
	})
}
