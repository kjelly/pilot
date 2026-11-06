package identityreconcile

import (
	"fmt"
	"slices"
	"strings"
)

// The self-lockout check (spec §7.10, decision D24): a plan is blocked when
// running it would take away what the engine itself needs, the login it reads
// and writes with. It is checked on the state the plan leaves after each stage,
// not only at the end: S5 removes members before S6 adds any, so a login that
// is moved from admins itself to admins through a new group is, between the two
// stages, a member of nothing that reaches admins, and S6's group_add_member
// would be refused with an ACIError with half the run applied.

// adminsGroup is the group whose members may read and write everything the
// engine does (Observe requires it of the login).
const adminsGroup = "admins"

// protectedGroups are never deleted by the engine: FreeIPA's own and the ones
// its default access depends on.
var protectedGroups = []string{"admins", "ipausers", "editors", "trust admins"}

// simGraph is the part of FreeIPA's state the check follows: which users exist
// and are enabled, and the direct members of each group.
type simGraph struct {
	users  map[string]*simUser
	groups map[string]*simGroup
}

type simUser struct{ enabled bool }

type simGroup struct{ users, groups map[string]bool }

func newSimGraph(users map[string]LiveUser, groups map[string]LiveGroup) *simGraph {
	g := &simGraph{users: map[string]*simUser{}, groups: map[string]*simGroup{}}
	for name, u := range users {
		g.users[name] = &simUser{enabled: !u.Locked}
	}
	for name, lg := range groups {
		sg := &simGroup{users: map[string]bool{}, groups: map[string]bool{}}
		for _, m := range lg.MemberUsers {
			sg.users[m] = true
		}
		for _, m := range lg.MemberGroups {
			sg.groups[m] = true
		}
		g.groups[name] = sg
	}
	return g
}

func (g *simGraph) group(name string) *simGroup {
	if sg, ok := g.groups[name]; ok {
		return sg
	}
	sg := &simGroup{users: map[string]bool{}, groups: map[string]bool{}}
	g.groups[name] = sg
	return sg
}

// reaches reports whether user is, directly or through groups, a member of
// target. FreeIPA accepts group cycles (captured: A in B and B in A), so each
// group is visited once and the walk ends on any graph.
func (g *simGraph) reaches(user, target string) bool {
	seen := map[string]bool{}
	var queue []string
	for name, sg := range g.groups {
		if sg.users[user] {
			queue = append(queue, name)
			seen[name] = true
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur == target {
			return true
		}
		for name, sg := range g.groups {
			if sg.groups[cur] && !seen[name] {
				seen[name] = true
				queue = append(queue, name)
			}
		}
	}
	return false
}

// apply runs the plan's operations of one stage on the graph, as FreeIPA runs
// them: a deleted user leaves every group, a deleted group leaves every group
// that held it and its members stop being members (captured, K7 and K8).
func (g *simGraph) apply(ops []Operation) {
	for _, op := range ops {
		switch op.Kind {
		case KindGroupCreate, KindMarkerCreate:
			g.group(op.Object)
		case KindUserCreate:
			g.users[op.Object] = &simUser{enabled: true}
		case KindMemberUserRemove:
			for _, m := range op.Members {
				delete(g.group(op.Object).users, m)
			}
		case KindMemberGroupRemove:
			for _, m := range op.Members {
				delete(g.group(op.Object).groups, m)
			}
		case KindMemberUserAdd:
			for _, m := range op.Members {
				g.group(op.Object).users[m] = true
			}
		case KindMemberGroupAdd:
			for _, m := range op.Members {
				g.group(op.Object).groups[m] = true
			}
		case KindUserEnable:
			if u := g.users[op.Object]; u != nil {
				u.enabled = true
			}
		case KindUserDisable:
			if u := g.users[op.Object]; u != nil {
				u.enabled = false
			}
		case KindUserDelete:
			delete(g.users, op.Object)
			for _, sg := range g.groups {
				delete(sg.users, op.Object)
			}
		case KindGroupDelete:
			delete(g.groups, op.Object)
			for _, sg := range g.groups {
				delete(sg.groups, op.Object)
			}
		}
	}
}

// protect blocks the plan when it would lock the engine out: the login must
// exist, be enabled and reach admins after every stage, its own password must not
// be reset, and the groups FreeIPA depends on must not be deleted. It adds at
// most one entry per object and reason, naming the first stage that fails.
//
// The login is the user the preview or run reads and writes as. It is checked when
// the reads show it (Observe refuses a run whose login is not among them), as
// enabled only when it is enabled to begin with, and its reach of admins is
// checked when the group graph read shows the path at all: a
// read whose graph cannot show a path that user_find's transitive memberof_group
// claims is a read that cannot say what a plan takes away, so it is not made to
// block every plan; on a real server the two agree.
func (b *builder) protect(principal string) {
	login := strings.ToLower(principal)
	graph := newSimGraph(b.liveUsers, b.liveGroups)
	baseline := graph.users[login] != nil
	followEnabled := baseline && graph.users[login].enabled
	followReach := baseline && graph.reaches(login, adminsGroup)

	reported := map[string]bool{}
	report := func(object, detail string) {
		if !reported[object] {
			reported[object] = true
			b.plan.Blocked = append(b.plan.Blocked, Blocked{Reason: BlockedProtectedObject, Object: object, Detail: detail})
		}
	}
	for _, s := range Stages {
		ops := operationsOf(b.plan, s)
		if s == S4 {
			for _, op := range ops {
				if op.Kind == KindPasswordReset && op.Object == login {
					report(login, fmt.Sprintf("%s (%s) would reset the password of the login %s, which the engine is using: the session and the next login would fail, and passwd is not read back", s, s.what(), login))
				}
			}
		}
		if s == S8 {
			for _, op := range ops {
				if op.Kind == KindGroupDelete && slices.Contains(protectedGroups, op.Object) {
					report(op.Object, fmt.Sprintf("%s (%s) would delete the group %s, which FreeIPA and the engine depend on", s, s.what(), op.Object))
				}
			}
		}
		graph.apply(ops)
		if !baseline {
			continue
		}
		after := fmt.Sprintf("after %s (%s)", s, s.what())
		switch u := graph.users[login]; {
		case u == nil:
			report(login, fmt.Sprintf("the login %s would not exist %s: the engine would lose the session it reads and writes with", login, after))
		case followEnabled && !u.enabled:
			report(login, fmt.Sprintf("the login %s would be disabled %s: the engine would lose the session it reads and writes with", login, after))
		case followReach && graph.groups[adminsGroup] != nil && !graph.reaches(login, adminsGroup):
			// (A deleted admins group is reported as that, once, at its own
			// deletion: the login's path to it is then not a second finding.)
			report(login, fmt.Sprintf("%s the login %s would not be a member of %s through any group: its next write would be refused with an ACIError, partway through the run. Change the roster in two steps: first add the new path to admins, apply, then remove the old one", after, login, adminsGroup))
		}
	}
}
