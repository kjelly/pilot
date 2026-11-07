package identityreconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/kjelly/pilot/internal/freeiparpc"
)

// A FreeIPA that the executor's tests write to: a small model of the server whose
// every answer the P2-4 captures show. It is a freeiparpc-shaped client (the RPC
// the executor takes), not a wire: the errors it returns are the captured ones,
// read out of the fixtures (a name, a code and a message nobody wrote by hand), and
// so are the member answers' reasons. What is modelled by hand is the state: which
// objects exist and who is in which group. It applies a WriteGate to each write
// the way freeiparpc.Client does, so a gate that refuses sends nothing here either.

type fUser struct {
	name, uuid, uid, gid      string
	first, last, display      string
	shell, home               string
	mail                      []string
	locked, preserved, hasPwd bool
	lastPwd, exp              string
}

type fGroup struct {
	name, uuid, gid, desc string
	nonposix              bool
	users, groups         map[string]bool
}

// call is one command the fake received.
type call struct {
	method string
	args   []any
	opts   map[string]any
	batch  bool
	// batchNo numbers the batch (one per Batch call) a batched command arrived in.
	batchNo int
	// ctxErr is the context's error as the command arrived.
	ctxErr error
}

type fakeIPA struct {
	t  *testing.T
	mu sync.Mutex

	users  map[string]*fUser
	groups map[string]*fGroup
	seq    int
	clock  int
	// batches counts the Batch calls.
	batches int

	// writeGate is the WriteGate of the client the fake stands for.
	writeGate func(ctx context.Context, method string) error

	calls []call
	finds int

	// intercept, when set, sees each command before the fake does and may answer
	// it itself (handled true); the way a test makes a write unknown, or lets an
	// external writer act between two commands.
	intercept func(f *fakeIPA, c call) (raw json.RawMessage, err error, handled bool)
	// onFind is called with the number of the find the executor is about to make
	// (1 for the first read of a run, 2 for the second…), before it is answered.
	onFind func(f *fakeIPA, n int)
}

func newFakeIPA(t *testing.T) *fakeIPA {
	t.Helper()
	f := &fakeIPA{t: t, users: map[string]*fUser{}, groups: map[string]*fGroup{}}
	f.addGroup("admins", "Account administrators group", false)
	f.addGroup("ipausers", "Default group for all users", false)
	f.addGroup("editors", "Limited admins who can edit other users", false)
	f.addGroup("trust admins", "Trusts administrators group", false)
	f.addUser("admin", "Administrator", "")
	f.groups["admins"].users["admin"] = true
	f.groups["ipausers"].users["admin"] = true
	return f
}

func (f *fakeIPA) nextID() (string, string) {
	f.seq++
	return fmt.Sprintf("00000000-0000-0000-0000-%012d", f.seq), strconv.Itoa(1000000 + f.seq)
}

// stamp is a krblastpwdchange value that grows with every password set.
func (f *fakeIPA) stamp() string {
	f.clock++
	return fmt.Sprintf("20261107%06dZ", f.clock)
}

func (f *fakeIPA) addGroup(name, desc string, nonposix bool) *fGroup {
	uuid, gid := f.nextID()
	g := &fGroup{name: name, uuid: uuid, gid: gid, desc: desc, nonposix: nonposix, users: map[string]bool{}, groups: map[string]bool{}}
	if nonposix {
		g.gid = ""
	}
	f.groups[name] = g
	return g
}

func (f *fakeIPA) addUser(name, first, last string) *fUser {
	uuid, id := f.nextID()
	u := &fUser{name: name, uuid: uuid, uid: id, gid: id, first: first, last: last, display: first + " " + last, shell: "/bin/bash", home: "/home/" + name, mail: []string{name + "@ipa.example.test"}}
	f.users[name] = u
	return u
}

// fixtureError is the error of a captured answer.
func fixtureError(t *testing.T, name string) *freeiparpc.RPCError {
	t.Helper()
	e := capturedRPCError(t, name)
	if e == nil {
		t.Fatalf("the capture %s is not an error", name)
	}
	return e
}

// fixtureResult is the result object of a captured successful answer.
func fixtureResult(t *testing.T, name string) json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "freeiparpc", "testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(data, &env); err != nil || env.Result == nil || string(env.Error) != "null" {
		t.Fatalf("the capture %s is not a success (%v)", name, err)
	}
	return env.Result
}

func (f *fakeIPA) errNamed(fixture, object string) *freeiparpc.RPCError {
	e := *fixtureError(f.t, fixture)
	if object != "" {
		e.Message = object + ": " + strings.TrimPrefix(e.Message[strings.Index(e.Message, ": ")+2:], "")
	}
	return &e
}

// readers

func (f *fakeIPA) memberOfDirect(user string) []string {
	var out []string
	for name, g := range f.groups {
		if g.users[user] {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// reachable is every group a user is in, directly or through groups; the walk
// ends on cycles.
func (f *fakeIPA) reachable(user string) []string {
	seen := map[string]bool{}
	var queue []string
	for _, g := range f.memberOfDirect(user) {
		seen[g] = true
		queue = append(queue, g)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for name, g := range f.groups {
			if g.groups[cur] && !seen[name] {
				seen[name] = true
				queue = append(queue, name)
			}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func list(vals ...string) []any {
	out := make([]any, len(vals))
	for i, v := range vals {
		out[i] = v
	}
	return out
}

func (f *fakeIPA) userEntry(u *fUser, transitive bool) map[string]any {
	e := map[string]any{
		"uid": list(u.name), "ipauniqueid": list(u.uuid), "givenname": list(u.first), "sn": list(u.last),
		"uidnumber": list(u.uid), "gidnumber": list(u.gid), "nsaccountlock": u.locked, "preserved": u.preserved,
	}
	if u.display != "" {
		e["displayname"] = list(u.display)
	}
	if u.shell != "" {
		e["loginshell"] = list(u.shell)
	}
	if u.home != "" {
		e["homedirectory"] = list(u.home)
	}
	if len(u.mail) > 0 {
		e["mail"] = list(u.mail...)
	}
	if u.lastPwd != "" {
		e["krblastpwdchange"] = []any{map[string]any{"__datetime__": u.lastPwd}}
	}
	if u.exp != "" {
		e["krbpasswordexpiration"] = []any{map[string]any{"__datetime__": u.exp}}
	}
	if !u.preserved {
		if transitive {
			e["memberof_group"] = list(f.reachable(u.name)...)
		} else {
			e["memberof_group"] = list(f.memberOfDirect(u.name)...)
		}
	}
	return e
}

func (f *fakeIPA) groupEntry(g *fGroup) map[string]any {
	classes := []string{"top", "groupofnames", "nestedgroup", "ipausergroup", "ipaobject"}
	if !g.nonposix {
		classes = append(classes, "posixgroup", "ipantgroupattrs")
	}
	e := map[string]any{"cn": list(g.name), "ipauniqueid": list(g.uuid), "objectclass": list(classes...)}
	if g.desc != "" {
		e["description"] = list(g.desc)
	}
	if g.gid != "" {
		e["gidnumber"] = list(g.gid)
	}
	if len(g.users) > 0 {
		e["member_user"] = list(sortedKeys(g.users)...)
	}
	if len(g.groups) > 0 {
		e["member_group"] = list(sortedKeys(g.groups)...)
	}
	return e
}

// Find implements Finder.
func (f *fakeIPA) Find(ctx context.Context, method string, _ []any, opts map[string]any) ([]map[string]any, error) {
	f.mu.Lock()
	if method == "user_find" && opts["preserved"] != true {
		f.finds++
		n := f.finds
		hook := f.onFind
		f.mu.Unlock()
		if hook != nil {
			hook(f, n)
		}
		f.mu.Lock()
	}
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{method: method, opts: opts, ctxErr: ctx.Err()})
	var out []map[string]any
	switch method {
	case "user_find":
		for _, name := range sortedKeys(f.users) {
			u := f.users[name]
			if u.preserved == (opts["preserved"] == true) {
				out = append(out, f.userEntry(u, true))
			}
		}
	case "group_find":
		for _, name := range sortedKeys(f.groups) {
			out = append(out, f.groupEntry(f.groups[name]))
		}
	default:
		return nil, fmt.Errorf("fakeIPA: find %s", method)
	}
	return out, nil
}

// the commands

func (f *fakeIPA) gateWrite(ctx context.Context, method string) error {
	if f.writeGate == nil {
		return nil
	}
	if err := f.writeGate(ctx, method); err != nil {
		return &freeiparpc.ErrWriteRefused{Method: method, Err: err}
	}
	return nil
}

func isWrite(method string) bool {
	switch method {
	case "user_show", "group_show", "user_find", "group_find", "ping":
		return false
	}
	return true
}

// cancelled is what the client does with a write on a context that is already
// cancelled: it cannot confirm anything, so the outcome is unknown, and nothing
// reached the model.
func cancelled(ctx context.Context, method string) error {
	if err := ctx.Err(); err != nil {
		if isWrite(method) {
			return &freeiparpc.OutcomeUnknownError{Method: method, Err: err}
		}
		return err
	}
	return nil
}

// Call implements RPC.
func (f *fakeIPA) Call(ctx context.Context, cmd freeiparpc.Command) (json.RawMessage, error) {
	if isWrite(cmd.Method) {
		if err := f.gateWrite(ctx, cmd.Method); err != nil {
			return nil, err
		}
	}
	if err := cancelled(ctx, cmd.Method); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.execLocked(ctx, call{method: cmd.Method, args: cmd.Args, opts: cmd.Options})
}

// Batch implements RPC.
func (f *fakeIPA) Batch(ctx context.Context, cmds []freeiparpc.Command) ([]freeiparpc.BatchItem, error) {
	for _, c := range cmds {
		if isWrite(c.Method) {
			if err := f.gateWrite(ctx, c.Method); err != nil {
				return nil, err
			}
		}
	}
	for _, c := range cmds {
		if err := cancelled(ctx, c.Method); err != nil {
			return nil, err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.batches++
	items := make([]freeiparpc.BatchItem, len(cmds))
	for i, c := range cmds {
		raw, err := f.execLocked(ctx, call{method: c.Method, args: c.Args, opts: c.Options, batch: true, batchNo: f.batches})
		var unknown *freeiparpc.OutcomeUnknownError
		if asUnknown(err, &unknown) {
			return nil, err // a batch that could not be answered: the writes may have happened
		}
		var rpcErr *freeiparpc.RPCError
		if asRPC(err, &rpcErr) {
			items[i].Err = rpcErr
			continue
		}
		if err != nil {
			return nil, err
		}
		items[i].Result = raw
	}
	return items, nil
}

func (f *fakeIPA) execLocked(ctx context.Context, c call) (json.RawMessage, error) {
	c.ctxErr = ctx.Err()
	f.calls = append(f.calls, c)
	if f.intercept != nil {
		if raw, err, handled := f.intercept(f, c); handled {
			return raw, err
		}
	}
	name := ""
	if len(c.args) > 0 {
		name, _ = c.args[0].(string)
	}
	str := func(key string) (string, bool) {
		v, ok := c.opts[key]
		if !ok {
			return "", false
		}
		s, _ := v.(string)
		return s, true
	}
	switch c.method {
	case "user_show":
		u, ok := f.users[name]
		if !ok {
			return nil, f.errNamed("user-show-not-found", name)
		}
		return resultOf(f.userEntry(u, false), name, ""), nil
	case "group_show":
		g, ok := f.groups[name]
		if !ok {
			return nil, f.errNamed("group-mod-not-found", name)
		}
		return resultOf(f.groupEntry(g), name, ""), nil
	case "user_add":
		if u, dup := f.users[name]; dup {
			if u.preserved {
				return nil, f.errNamed("user-add-duplicate-preserved", name)
			}
			return nil, f.errNamed("user-add-duplicate", name)
		}
		for opt, fixture := range map[string]string{"givenname": "user-add-empty-givenname", "sn": "user-add-empty-sn", "homedirectory": "user-add-empty-homedirectory"} {
			if v, ok := str(opt); ok && v == "" {
				return nil, fixtureError(f.t, fixture)
			}
		}
		u := f.addUser(name, "", "")
		u.first, u.last = optString(c.opts, "givenname"), optString(c.opts, "sn")
		u.display = u.first + " " + u.last
		u.shell, u.home = "/bin/sh", "/home/"+name
		u.mail = []string{name + "@ipa.example.test"}
		f.applyUserOptions(u, c.opts, false)
		f.groups["ipausers"].users[name] = true
		return resultOf(f.userEntry(u, false), name, `Added user "`+name+`"`), nil
	case "user_mod":
		u, ok := f.users[name]
		if !ok {
			return nil, f.errNamed("user-mod-not-found", name)
		}
		for opt, fixture := range map[string]string{"givenname": "user-mod-empty-givenname", "sn": "user-mod-empty-sn", "homedirectory": "user-mod-empty-homedirectory"} {
			if v, ok := str(opt); ok && v == "" {
				return nil, fixtureError(f.t, fixture)
			}
		}
		if !f.applyUserOptions(u, c.opts, true) {
			return nil, fixtureError(f.t, "user-mod-no-change")
		}
		return resultOf(f.userEntry(u, false), name, `Modified user "`+name+`"`), nil
	case "user_del":
		u, ok := f.users[name]
		if !ok {
			return nil, f.errNamed("user-del-not-found", name)
		}
		_ = u
		delete(f.users, name)
		for _, g := range f.groups {
			delete(g.users, name)
		}
		return json.RawMessage(`{"result":{"failed":[]},"value":["` + name + `"],"summary":"Deleted user \"` + name + `\""}`), nil
	case "user_enable", "user_disable":
		u, ok := f.users[name]
		if !ok {
			return nil, f.errNamed("user-enable-not-found", name)
		}
		switch {
		case c.method == "user_enable" && !u.locked:
			return nil, fixtureError(f.t, "user-enable-already-enabled")
		case c.method == "user_disable" && u.locked:
			return nil, fixtureError(f.t, "user-disable-already-disabled")
		}
		u.locked = c.method == "user_disable"
		return json.RawMessage(`{"result":true,"value":"` + name + `","summary":"ok"}`), nil
	case "passwd":
		pw := optString(c.opts, "password")
		if pw == "" {
			return nil, fixtureError(f.t, "passwd-empty-password")
		}
		u, ok := f.users[name]
		if !ok {
			return nil, fixtureError(f.t, "passwd-not-found")
		}
		u.hasPwd, u.lastPwd = true, f.stamp()
		u.exp = u.lastPwd // an admin reset: the expiration is the change time (captured, K6)
		return json.RawMessage(`{"result":true,"value":"` + name + `@IPA.EXAMPLE.TEST","summary":"Changed password"}`), nil
	case "group_add":
		if _, dup := f.groups[name]; dup {
			return nil, f.errNamed("group-add-duplicate", name)
		}
		g := f.addGroup(name, optString(c.opts, "description"), c.opts["nonposix"] == true)
		return resultOf(f.groupEntry(g), name, `Added group "`+name+`"`), nil
	case "group_mod":
		g, ok := f.groups[name]
		if !ok {
			return nil, f.errNamed("group-mod-not-found", name)
		}
		if d, ok := str("description"); ok {
			if d == g.desc {
				return nil, fixtureError(f.t, "group-mod-no-change")
			}
			g.desc = d
		}
		return resultOf(f.groupEntry(g), name, `Modified group "`+name+`"`), nil
	case "group_del":
		if _, ok := f.groups[name]; !ok {
			return nil, f.errNamed("group-del-not-found", name)
		}
		delete(f.groups, name)
		for _, g := range f.groups {
			delete(g.groups, name)
		}
		return json.RawMessage(`{"result":{"failed":[]},"value":["` + name + `"],"summary":"Deleted group \"` + name + `\""}`), nil
	case "group_add_member", "group_remove_member":
		g, ok := f.groups[name]
		if !ok {
			return nil, f.errNamed("group-add-member-to-missing-group", name)
		}
		return f.members(c, g), nil
	}
	return nil, fmt.Errorf("fakeIPA: no model of %s", c.method)
}

func optString(opts map[string]any, key string) string {
	s, _ := opts[key].(string)
	return s
}

func resultOf(entry map[string]any, value, summary string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"result": entry, "value": value, "summary": summary})
	return b
}

// applyUserOptions sets the user's attributes from the options; "" and [] leave an
// attribute out (captured, K21). It reports whether anything changed.
func (f *fakeIPA) applyUserOptions(u *fUser, opts map[string]any, modify bool) bool {
	changed := false
	set := func(dst *string, key string) {
		if v, ok := opts[key].(string); ok && v != *dst {
			*dst, changed = v, true
		}
	}
	set(&u.first, "givenname")
	set(&u.last, "sn")
	set(&u.shell, "loginshell")
	set(&u.display, "displayname")
	set(&u.home, "homedirectory")
	if v, ok := opts["mail"]; ok {
		var want []string
		switch m := v.(type) {
		case string:
			if m != "" {
				want = []string{m}
			}
		case []any:
			for _, x := range m {
				want = append(want, fmt.Sprint(x))
			}
		}
		if !sameSet(u.mail, want) {
			u.mail, changed = want, true
		}
	}
	return changed
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	sort.Strings(a)
	sort.Strings(b)
	return slices.Equal(a, b)
}

// members is a group_add_member or group_remove_member: a success whatever
// happened to each member, with the reasons FreeIPA gives (captured, K12, K13).
func (f *fakeIPA) members(c call, g *fGroup) json.RawMessage {
	adding := c.method == "group_add_member"
	completed := 0
	failed := map[string][][]string{"user": {}, "group": {}, "service": {}, "idoverrideuser": {}}
	for _, typ := range []string{"user", "group"} {
		raw, _ := c.opts[typ].([]any)
		for _, m := range raw {
			member := fmt.Sprint(m)
			set := g.users
			exists := f.users[member] != nil
			if typ == "group" {
				set = g.groups
				exists = f.groups[member] != nil
			}
			switch {
			case adding && typ == "group" && member == g.name:
				failed[typ] = append(failed[typ], []string{member, "A group may not be added as a member of itself"})
			case adding && !exists:
				failed[typ] = append(failed[typ], []string{member, "no such entry"})
			case adding && set[member]:
				failed[typ] = append(failed[typ], []string{member, "This entry is already a member"})
			case adding:
				set[member] = true
				completed++
			case !set[member]:
				failed[typ] = append(failed[typ], []string{member, "This entry is not a member"})
			default:
				delete(set, member)
				completed++
			}
		}
	}
	b, _ := json.Marshal(map[string]any{"completed": completed, "failed": map[string]any{"member": failed}, "result": f.groupEntry(g)})
	return b
}

// helpers for the tests

func (f *fakeIPA) methodsCalled() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		out = append(out, c.method)
	}
	return out
}

// writes are the write commands received, in order, as "method object".
func (f *fakeIPA) writes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if isWrite(c.method) {
			name := ""
			if len(c.args) > 0 {
				name, _ = c.args[0].(string)
			}
			out = append(out, c.method+" "+name)
		}
	}
	return out
}

func asUnknown(err error, target **freeiparpc.OutcomeUnknownError) bool {
	for e := err; e != nil; {
		if u, ok := e.(*freeiparpc.OutcomeUnknownError); ok {
			*target = u
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}

func asRPC(err error, target **freeiparpc.RPCError) bool {
	for e := err; e != nil; {
		if u, ok := e.(*freeiparpc.RPCError); ok {
			*target = u
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}
