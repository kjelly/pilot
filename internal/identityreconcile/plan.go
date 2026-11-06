package identityreconcile

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/kjelly/pilot/internal/inventory"
)

// Operation kinds, in the order a plan lists them (spec §7.2, the
// playbook's order).
const (
	KindGroupCreate        = "group.create"
	KindGroupUpdate        = "group.update"
	KindMarkerCreate       = "group.marker.create"
	KindUserCreate         = "user.create"
	KindUserUpdate         = "user.update"
	KindPasswordInitialize = "user.password.initialize"
	KindPasswordReset      = "user.password.reset"
	KindMemberUserRemove   = "group.member_user.remove"
	KindMemberGroupRemove  = "group.member_group.remove"
	KindMemberUserAdd      = "group.member_user.add"
	KindMemberGroupAdd     = "group.member_group.add"
	KindUserEnable         = "user.enable"
	KindUserDisable        = "user.disable"
	KindUserDelete         = "user.delete"
	KindGroupDelete        = "group.delete"
)

// Kinds is every operation kind, in plan order.
var Kinds = []string{
	KindGroupCreate, KindGroupUpdate, KindMarkerCreate,
	KindUserCreate, KindUserUpdate,
	KindPasswordInitialize, KindPasswordReset,
	KindMemberUserRemove, KindMemberGroupRemove, KindMemberUserAdd, KindMemberGroupAdd,
	KindUserEnable, KindUserDisable,
	KindUserDelete, KindGroupDelete,
}

// Reasons an object is blocked instead of planned (spec §7.3).
const (
	BlockedIDChange          = "uid_or_gid_change"
	BlockedTypeMismatch      = "group_type_mismatch"
	BlockedTypeUnrecognized  = "group_type_unrecognized"
	BlockedExternalGroup     = "external_group"
	BlockedPreservedUser     = "preserved_user"
	BlockedMarkerCollision   = "marker_collision"
	BlockedCaseCollision     = "case_collision"
	BlockedReferenceToAbsent = "reference_to_absent"
	// BlockedPasswordValue: the user's password operation cannot be sent because
	// the password is not a string written out in the roster (a template, an
	// inline !vault value, a value YAML may read as a number, an empty string, or
	// a roster whose password forms were not read). Only an operation that is
	// planned is blocked on it; a user whose password needs no change is not.
	BlockedPasswordValue = "password_value_unsupported"
	// BlockedProtectedObject: running the plan would take away what the engine
	// itself needs: the login it uses, its path to admins, or a group FreeIPA
	// depends on (selflock.go).
	BlockedProtectedObject = "protected_object"
)

// Change is one attribute's live and desired value; From is nil for an
// object that does not exist yet.
type Change struct {
	From any `json:"from"`
	To   any `json:"to"`
}

// Operation is one planned FreeIPA write. Object names are lower case,
// as FreeIPA stores them.
type Operation struct {
	ID          string            `json:"id"`
	Kind        string            `json:"kind"`
	Object      string            `json:"object"`
	Fields      map[string]Change `json:"fields,omitempty"`
	Members     []string          `json:"members,omitempty"`
	Destructive bool              `json:"destructive"`
	DependsOn   []string          `json:"depends_on"`
}

// Blocked is an object the plan will not touch, and why.
type Blocked struct {
	Reason string `json:"reason"`
	Object string `json:"object"`
	Detail string `json:"detail"`
}

// SSHKeyReport is a user whose FreeIPA keys differ from the roster's. The
// Go engine does not change keys (the playbook's #138 block does); keys
// are named by fingerprint, never by body.
type SSHKeyReport struct {
	User        string   `json:"user"`
	Declared    []string `json:"declared"`
	Live        []string `json:"live"`
	InvalidKeys int      `json:"invalid_declared_keys,omitempty"`
}

// PruneReport is an authoritative group whose roster entry declares no
// members of a kind: every live direct member of that kind is removed,
// users outside the roster included (the playbook's semantics).
type PruneReport struct {
	Group string   `json:"group"`
	Kinds []string `json:"kinds"`
}

// Reports are findings that are neither operations nor blockers.
type Reports struct {
	SSHKeys                 []SSHKeyReport `json:"ssh_keys"`
	ImplicitMembershipPrune []PruneReport  `json:"implicit_membership_prune"`
	NotInScope              []string       `json:"not_in_scope"`
}

// Plan is what it takes to bring the live users and groups to the
// desired state. It authorizes nothing: an apply re-reads and re-plans.
type Plan struct {
	Operations []Operation `json:"operations"`
	Blocked    []Blocked   `json:"blocked"`
	Reports    Reports     `json:"reports"`
}

// Writes counts the planned write operations.
func (p Plan) Writes() int { return len(p.Operations) }

// Build plans the operations from live state to d. users holds every user
// the reads returned, preserved ones included (LiveUser.Preserved).
func Build(d Desired, users []LiveUser, groups []LiveGroup) Plan {
	b := &builder{
		principal:     d.Principal,
		plan:          Plan{Operations: []Operation{}, Blocked: []Blocked{}},
		liveUsers:     map[string]LiveUser{},
		preserved:     map[string]bool{},
		liveGroups:    map[string]LiveGroup{},
		blocked:       map[string]bool{},
		createdUsers:  map[string]string{},
		createdGroups: map[string]string{},
	}
	b.plan.Reports = Reports{SSHKeys: []SSHKeyReport{}, ImplicitMembershipPrune: []PruneReport{}, NotInScope: append([]string{}, d.NotInScope...)}
	for _, u := range users {
		if u.Preserved {
			b.preserved[u.Name] = true
			continue
		}
		b.liveUsers[u.Name] = u
	}
	for _, g := range groups {
		b.liveGroups[g.Name] = g
	}
	b.blockCollisions(d)
	b.blockReferences(d)
	b.groups(d)
	b.users(d)
	b.membership(d)
	b.deletions(d)
	b.protect(d.Principal)
	b.finish()
	return b.plan
}

type builder struct {
	principal     string
	plan          Plan
	liveUsers     map[string]LiveUser
	preserved     map[string]bool
	liveGroups    map[string]LiveGroup
	blocked       map[string]bool   // "user:<name>" or "group:<name>"
	createdUsers  map[string]string // name -> create op ID
	createdGroups map[string]string
}

func userKey(name string) string  { return "user:" + strings.ToLower(name) }
func groupKey(name string) string { return "group:" + strings.ToLower(name) }

func (b *builder) block(key, reason, object, detail string) {
	b.blocked[key] = true
	b.plan.Blocked = append(b.plan.Blocked, Blocked{Reason: reason, Object: strings.ToLower(object), Detail: detail})
}

func (b *builder) add(op Operation) string {
	op.ID = op.Kind + ":" + op.Object
	if op.DependsOn == nil {
		op.DependsOn = []string{}
	}
	sort.Strings(op.DependsOn)
	b.plan.Operations = append(b.plan.Operations, op)
	return op.ID
}

// blockCollisions blocks names that differ only in case: the validator
// compares them as written, FreeIPA stores them in lower case.
func (b *builder) blockCollisions(d Desired) {
	seen := map[string][]string{}
	for _, g := range d.Groups {
		seen[groupKey(g.Name)] = append(seen[groupKey(g.Name)], g.Name)
	}
	for _, n := range d.AbsentGroups {
		seen[groupKey(n)] = append(seen[groupKey(n)], n)
	}
	for _, u := range d.Users {
		seen[userKey(u.Name)] = append(seen[userKey(u.Name)], u.Name)
	}
	for _, n := range d.AbsentUsers {
		seen[userKey(n)] = append(seen[userKey(n)], n)
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if names := seen[k]; len(names) > 1 {
			b.block(k, BlockedCaseCollision, names[0], fmt.Sprintf("roster entries %s differ only in case; FreeIPA stores one lower-case name", strings.Join(names, ", ")))
		}
	}
}

// blockReferences blocks groups whose members name a state: absent object:
// the validator allows it, but once that object is deleted the playbook's
// group-add-member fails on every rerun.
func (b *builder) blockReferences(d Desired) {
	absentUsers, absentGroups := lowerSet(d.AbsentUsers), lowerSet(d.AbsentGroups)
	for _, g := range d.Groups {
		var refs []string
		for _, u := range g.Users {
			if absentUsers[u] {
				refs = append(refs, "user "+u)
			}
		}
		for _, m := range g.Groups {
			if absentGroups[m] {
				refs = append(refs, "group "+m)
			}
		}
		if len(refs) > 0 {
			b.block(groupKey(g.Name), BlockedReferenceToAbsent, g.Name, "members marked state: absent: "+strings.Join(refs, ", "))
		}
	}
}

func (b *builder) groups(d Desired) {
	for _, g := range sortedGroups(d.Groups) {
		key, name := groupKey(g.Name), strings.ToLower(g.Name)
		if b.blocked[key] {
			continue
		}
		if g.Type != TypePosix && g.Type != TypeNonPosix {
			b.block(key, BlockedExternalGroup, g.Name, "type: "+g.Type+" groups are not supported by the Go engine yet")
			continue
		}
		live, exists := b.liveGroups[name]
		if exists {
			switch {
			case live.Type == TypeUnrecognized:
				b.block(key, BlockedTypeUnrecognized, g.Name, "the FreeIPA group's object classes are not a known POSIX or non-POSIX set")
				continue
			case live.Type != g.Type:
				b.block(key, BlockedTypeMismatch, g.Name, fmt.Sprintf("FreeIPA has a %s group, the roster declares %s; FreeIPA cannot convert it in place", live.Type, g.Type))
				continue
			case g.GID != nil && live.GIDNumber != strconv.FormatInt(*g.GID, 10):
				b.block(key, BlockedIDChange, g.Name, fmt.Sprintf("gidnumber %s -> %d would change file group ownership", orNone(live.GIDNumber), *g.GID))
				continue
			}
		}
		if collision := b.markerCollision(g.Name); collision != "" {
			b.block(key, BlockedMarkerCollision, g.Name, collision)
			continue
		}
		var createID string
		if !exists {
			fields := map[string]Change{"description": {To: g.Description}}
			if g.GID != nil {
				fields["gidnumber"] = Change{To: strconv.FormatInt(*g.GID, 10)}
			}
			if g.Type == TypeNonPosix {
				fields["nonposix"] = Change{To: true}
			}
			createID = b.add(Operation{Kind: KindGroupCreate, Object: name, Fields: fields})
			b.createdGroups[name] = createID
		} else if !descriptionMatches(live.Description, g.Description) {
			b.add(Operation{Kind: KindGroupUpdate, Object: name, Fields: map[string]Change{"description": {From: listValue(live.Description), To: g.Description}}})
		}
		b.ensureMarker(g.Name, createID)
	}
}

// markerCollision is why the group's history marker cannot be used, "" if
// it can (missing or correct).
func (b *builder) markerCollision(group string) string {
	m, ok := b.liveGroups[HistoryMarkerName(group)]
	if !ok || slices.Contains(m.Description, HistoryMarkerDescription(group)) {
		return ""
	}
	return fmt.Sprintf("history marker %s exists without the description %q", HistoryMarkerName(group), HistoryMarkerDescription(group))
}

// ensureMarker plans the history marker when it is missing and returns
// the operation a deletion must wait for ("" when it exists).
func (b *builder) ensureMarker(group, after string) string {
	marker := HistoryMarkerName(group)
	if _, ok := b.liveGroups[marker]; ok {
		return ""
	}
	var deps []string
	if after != "" {
		deps = []string{after}
	}
	return b.add(Operation{Kind: KindMarkerCreate, Object: marker, Fields: map[string]Change{
		"description": {To: HistoryMarkerDescription(group)}, "nonposix": {To: true},
	}, DependsOn: deps})
}

func (b *builder) users(d Desired) {
	for _, u := range sortedUsers(d.Users) {
		key, name := userKey(u.Name), strings.ToLower(u.Name)
		if b.blocked[key] {
			continue
		}
		if b.preserved[name] {
			b.block(key, BlockedPreservedUser, u.Name, "a preserved FreeIPA user has this name")
			continue
		}
		live, exists := b.liveUsers[name]
		if exists {
			if detail := idChange(u, live); detail != "" {
				b.block(key, BlockedIDChange, u.Name, detail)
				continue
			}
		}
		// A password operation that cannot be sent blocks the user before any of
		// its operations is planned: the others would be a half of a user.
		if passwordAction(u, live, exists) != "" {
			if detail := passwordUnsupported(u); detail != "" {
				b.block(key, BlockedPasswordValue, u.Name, detail)
				continue
			}
		}
		var createID string
		if !exists {
			fields := map[string]Change{}
			for attr, v := range desiredAttrs(u) {
				fields[attr] = Change{To: v}
			}
			createID = b.add(Operation{Kind: KindUserCreate, Object: name, Fields: fields})
			b.createdUsers[name] = createID
		} else if changes := attrChanges(u, live); len(changes) > 0 {
			b.add(Operation{Kind: KindUserUpdate, Object: name, Fields: changes})
		}
		b.password(u, live, exists, createID)
		b.reportKeys(u, live)
	}
}

// desiredAttrs is what the playbook's user-add and user-mod send.
func desiredAttrs(u DesiredUser) map[string]any {
	out := map[string]any{"givenname": u.First, "sn": u.Last, "loginshell": u.Shell, "homedirectory": u.Home}
	if u.DisplayName != nil {
		out["displayname"] = *u.DisplayName
	}
	if u.Email != nil {
		out["mail"] = mailValues(*u.Email)
	}
	if u.UID != nil {
		out["uidnumber"] = strconv.FormatInt(*u.UID, 10)
	}
	if u.GID != nil {
		out["gidnumber"] = strconv.FormatInt(*u.GID, 10)
	}
	return out
}

func attrChanges(u DesiredUser, live LiveUser) map[string]Change {
	out := map[string]Change{}
	cmp := func(attr, from, to string) {
		if from != to {
			out[attr] = Change{From: from, To: to}
		}
	}
	cmp("givenname", live.First, u.First)
	cmp("sn", live.Last, u.Last)
	cmp("loginshell", live.Shell, u.Shell)
	cmp("homedirectory", live.Home, u.Home)
	if u.DisplayName != nil {
		cmp("displayname", live.DisplayName, *u.DisplayName)
	}
	if u.Email != nil {
		if want := mailValues(*u.Email); !sameValues(live.Mail, want) {
			out["mail"] = Change{From: listValue(live.Mail), To: want}
		}
	}
	return out
}

// An empty string in the roster means "no value" for login_shell, display_name,
// email and a group's description (spec Q8, decided as the default pending the
// maintainer's confirmation). FreeIPA agrees: given "" for any of them, add and
// mod succeed and the attribute is not there afterwards, on add instead of the
// default and on mod clearing a value (captured, K21). So desired "" and a live
// attribute that is absent are the same state, and a plan made against either
// has nothing to do: what a preview shows is what an apply converges to
// (Plan₃ empty), because both are this one Build.

// mailValues is the set of mail values an email key declares: none for "".
func mailValues(email string) []string {
	if email == "" {
		return []string{}
	}
	return []string{email}
}

// sameValues reports whether live holds exactly the values of want, in no
// particular order: FreeIPA does not keep a multi-valued attribute's order
// (captured), and an empty want is an attribute that is absent.
func sameValues(live, want []string) bool {
	if len(live) != len(want) {
		return false
	}
	return len(want) == 0 || slices.Equal(sortedCopy(live), sortedCopy(want))
}

func sortedCopy(in []string) []string {
	out := slices.Clone(in)
	sort.Strings(out)
	return out
}

// descriptionMatches reports whether a group's live description is what the roster
// declares: an empty declared description is no description at all.
func descriptionMatches(live []string, want string) bool {
	return sameValues(live, mailValues(want))
}

// passwordAction is the password operation the playbook's "Decide the password
// action for each user" takes for a user: only a user declaring password.initial
// has one; initialize without a Kerberos key, reset when not preserving and the
// user is no longer on the last reset password.
func passwordAction(u DesiredUser, live LiveUser, exists bool) string {
	switch {
	case !u.HasInitialPassword:
		return ""
	case !exists || live.LastPwdChange == "":
		return KindPasswordInitialize
	case !u.PreserveExisting && !onResetPassword(live):
		return KindPasswordReset
	}
	return ""
}

// passwordUnsupported is why the password of u cannot be sent, "" when it can.
// The engine sets only a password written out in the roster: anything Ansible
// would render or decrypt is not something it can read, and an empty one is
// refused by FreeIPA (RequirementError, captured K6). The text names the form,
// never the value.
func passwordUnsupported(u DesiredUser) string {
	if !u.PasswordFormRead {
		return "the roster's password forms were not read, so what password.initial holds is not known (Desired.WithPasswordForms)"
	}
	switch u.PasswordForm {
	case inventory.PasswordLiteral:
		return ""
	case inventory.PasswordTemplate:
		return "password.initial is a Jinja template: pilot does not render templates, and the Go engine sets only a password written out in the roster; use the Ansible engine for it"
	case inventory.PasswordEncrypted:
		return "password.initial is an inline !vault value: only Ansible can decrypt it; use the Ansible engine for it, or encrypt the whole roster file instead"
	case inventory.PasswordNotString:
		return "password.initial may be read as something other than a string: quote it so it stays one"
	}
	return "password.initial is empty: FreeIPA refuses an empty password"
}

func idChange(u DesiredUser, live LiveUser) string {
	var parts []string
	if u.UID != nil && live.UIDNumber != strconv.FormatInt(*u.UID, 10) {
		parts = append(parts, fmt.Sprintf("uidnumber %s -> %d", orNone(live.UIDNumber), *u.UID))
	}
	if u.GID != nil && live.GIDNumber != strconv.FormatInt(*u.GID, 10) {
		parts = append(parts, fmt.Sprintf("gidnumber %s -> %d", orNone(live.GIDNumber), *u.GID))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ", ") + " would change file ownership"
}

// password follows the playbook's "Decide the password action for each
// user": only users declaring password.initial; initialize without a
// Kerberos key, reset when not preserving and the user is no longer on
// the last reset password (expiration <= last change means still on it).
func (b *builder) password(u DesiredUser, live LiveUser, exists bool, createID string) {
	name := strings.ToLower(u.Name)
	var deps []string
	if createID != "" {
		deps = []string{createID}
	}
	switch passwordAction(u, live, exists) {
	case KindPasswordInitialize:
		b.add(Operation{Kind: KindPasswordInitialize, Object: name, DependsOn: deps})
	case KindPasswordReset:
		b.add(Operation{Kind: KindPasswordReset, Object: name, Destructive: true})
	}
}

func (b *builder) reportKeys(u DesiredUser, live LiveUser) {
	if u.SSHKeys == nil {
		return
	}
	if slices.Equal(u.SSHKeys, live.SSHKeys) && u.SSHKeysInvalid == 0 {
		return
	}
	b.plan.Reports.SSHKeys = append(b.plan.Reports.SSHKeys, SSHKeyReport{
		User: strings.ToLower(u.Name), Declared: keyIDs(u.SSHKeys), Live: keyIDs(live.SSHKeys), InvalidKeys: u.SSHKeysInvalid,
	})
}

func keyIDs(keys []string) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, sshKeyID(k))
	}
	return out
}

func (b *builder) membership(d Desired) {
	for _, g := range sortedGroups(d.Groups) {
		key, name := groupKey(g.Name), strings.ToLower(g.Name)
		if b.blocked[key] {
			continue
		}
		live := b.liveGroups[name]
		if g.Authoritative && (!g.UsersDeclared || !g.GroupsDeclared) {
			var kinds []string
			if !g.UsersDeclared {
				kinds = append(kinds, "users")
			}
			if !g.GroupsDeclared {
				kinds = append(kinds, "groups")
			}
			b.plan.Reports.ImplicitMembershipPrune = append(b.plan.Reports.ImplicitMembershipPrune, PruneReport{Group: name, Kinds: kinds})
		}
		groupDep := b.createdGroups[name]
		users := b.unblocked(g.Users, userKey)
		groups := b.unblocked(g.Groups, groupKey)
		if g.Authoritative {
			if stale := difference(live.MemberUsers, g.Users); len(stale) > 0 {
				b.add(Operation{Kind: KindMemberUserRemove, Object: name, Members: stale})
			}
			if stale := difference(live.MemberGroups, g.Groups); len(stale) > 0 {
				b.add(Operation{Kind: KindMemberGroupRemove, Object: name, Members: stale})
			}
		}
		if missing := difference(users, live.MemberUsers); len(missing) > 0 {
			b.add(Operation{Kind: KindMemberUserAdd, Object: name, Members: missing, DependsOn: b.deps(groupDep, missing, b.createdUsers)})
		}
		if missing := difference(groups, live.MemberGroups); len(missing) > 0 {
			b.add(Operation{Kind: KindMemberGroupAdd, Object: name, Members: missing, DependsOn: b.deps(groupDep, missing, b.createdGroups)})
		}
	}
	for _, u := range sortedUsers(d.Users) {
		key, name := userKey(u.Name), strings.ToLower(u.Name)
		if b.blocked[key] {
			continue
		}
		live, exists := b.liveUsers[name]
		switch {
		case !exists && !u.Enabled:
			b.add(Operation{Kind: KindUserDisable, Object: name, DependsOn: []string{b.createdUsers[name]}})
		case exists && live.Locked && u.Enabled:
			b.add(Operation{Kind: KindUserEnable, Object: name})
		case exists && !live.Locked && !u.Enabled:
			b.add(Operation{Kind: KindUserDisable, Object: name})
		}
	}
}

func (b *builder) unblocked(names []string, key func(string) string) []string {
	var out []string
	for _, n := range names {
		if !b.blocked[key(n)] {
			out = append(out, n)
		}
	}
	return out
}

func (b *builder) deps(groupDep string, members []string, created map[string]string) []string {
	var out []string
	if groupDep != "" {
		out = append(out, groupDep)
	}
	for _, m := range members {
		if id := created[m]; id != "" {
			out = append(out, id)
		}
	}
	return out
}

func (b *builder) deletions(d Desired) {
	for _, n := range sortedNames(d.AbsentUsers) {
		key, name := userKey(n), strings.ToLower(n)
		if b.blocked[key] {
			continue
		}
		if b.preserved[name] {
			b.block(key, BlockedPreservedUser, n, "the user to delete is preserved in FreeIPA")
			continue
		}
		if _, ok := b.liveUsers[name]; ok {
			b.add(Operation{Kind: KindUserDelete, Object: name, Destructive: true})
		}
	}
	for _, n := range sortedNames(d.AbsentGroups) {
		key, name := groupKey(n), strings.ToLower(n)
		if b.blocked[key] {
			continue
		}
		if _, ok := b.liveGroups[name]; !ok {
			continue
		}
		if collision := b.markerCollision(n); collision != "" {
			b.block(key, BlockedMarkerCollision, n, collision)
			continue
		}
		var deps []string
		if id := b.ensureMarker(n, ""); id != "" {
			deps = []string{id}
		}
		b.add(Operation{Kind: KindGroupDelete, Object: name, Destructive: true, DependsOn: deps})
	}
}

// finish orders operations by kind, then object, so a plan is stable.
func (b *builder) finish() {
	rank := map[string]int{}
	for i, k := range Kinds {
		rank[k] = i
	}
	sort.SliceStable(b.plan.Operations, func(i, j int) bool {
		a, c := b.plan.Operations[i], b.plan.Operations[j]
		if rank[a.Kind] != rank[c.Kind] {
			return rank[a.Kind] < rank[c.Kind]
		}
		return a.Object < c.Object
	})
	sort.SliceStable(b.plan.Blocked, func(i, j int) bool {
		a, c := b.plan.Blocked[i], b.plan.Blocked[j]
		if a.Object != c.Object {
			return a.Object < c.Object
		}
		return a.Reason < c.Reason
	})
}

func sortedUsers(in []DesiredUser) []DesiredUser {
	out := slices.Clone(in)
	sort.SliceStable(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

func sortedGroups(in []DesiredGroup) []DesiredGroup {
	out := slices.Clone(in)
	sort.SliceStable(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

func sortedNames(in []string) []string {
	out := slices.Clone(in)
	sort.SliceStable(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out
}

func lowerSet(names []string) map[string]bool {
	out := map[string]bool{}
	for _, n := range names {
		out[strings.ToLower(n)] = true
	}
	return out
}

// difference is a minus b, sorted.
func difference(a, b []string) []string {
	in := lowerSet(b)
	var out []string
	for _, v := range a {
		if !in[v] {
			out = appendUnique(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// isOnly reports whether values holds exactly want.
func isOnly(values []string, want string) bool {
	return len(values) == 1 && values[0] == want
}

// onResetPassword: an admin reset leaves the expiration at or before the
// last change; a user's own change moves it later, or (maxlife=0) drops it.
func onResetPassword(u LiveUser) bool {
	return u.PwdExpiration != "" && u.PwdExpiration <= u.LastPwdChange
}

func listValue(v []string) any {
	if len(v) == 1 {
		return v[0]
	}
	if v == nil {
		return []string{}
	}
	return v
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
