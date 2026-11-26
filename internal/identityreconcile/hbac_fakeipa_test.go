package identityreconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/kjelly/pilot/internal/freeiparpc"
)

// A FreeIPA that the HBAC writer's tests write to: a small model of the server whose every
// answer the P3-0 captures show (capture_p3a_facts_test.go states each). It is an RPC the
// way fakeIPA is: the errors it returns are the captured ones, read out of the fixtures,
// and so are the answers' shapes; what is modelled by hand is the state (which rules,
// services, hosts, hostgroups, users and groups exist and who is on which rule).

type hRule struct {
	name, uuid               string // as created
	enabled                  bool
	hostCat, svcCat, userCat string
	users, groups, hosts     map[string]bool
	hostgroups, services     map[string]bool
}

func newHRule(name, uuid string) *hRule {
	return &hRule{name: name, uuid: uuid, enabled: true, users: map[string]bool{}, groups: map[string]bool{},
		hosts: map[string]bool{}, hostgroups: map[string]bool{}, services: map[string]bool{}}
}

type fakeHBAC struct {
	t  *testing.T
	mu sync.Mutex

	domain     string
	rules      map[string]*hRule // by lower-case name
	services   map[string]string // lower-case -> as created
	hosts      map[string]bool   // lower-case FQDN
	hostgroups map[string]bool
	users      map[string]bool
	groups     map[string]bool
	seq        int
	batches    int
	// noUniqueID makes the rules' entries leave out ipauniqueid, as a server that does not
	// return it would.
	noUniqueID bool

	// writeGate is the WriteGate of the client the fake stands for.
	writeGate func(ctx context.Context, method string) error

	calls []call
	// ruleFinds counts the hbacrule_find calls: the first read of a run is 1.
	ruleFinds int

	// intercept sees each command before the fake does and may answer it itself.
	intercept func(f *fakeHBAC, c call) (raw json.RawMessage, err error, handled bool)
	// findErr, when set, may fail a find: it is given the method and the number of
	// hbacrule_find calls so far (this one included).
	findErr func(method string, ruleFinds int) error
	// onFind is called with the number of the hbacrule_find the executor is about to
	// make, before it is answered: the way a test lets another writer act between reads.
	onFind func(f *fakeHBAC, n int)
}

// newFakeHBAC is a fresh server: the two built-in rules (captured: hbacrule-find-builtin),
// the built-in services sshd and sudo, the admin user, and the lab's domain.
func newFakeHBAC(t *testing.T) *fakeHBAC {
	t.Helper()
	f := &fakeHBAC{t: t, domain: lab, rules: map[string]*hRule{}, services: map[string]string{"sshd": "sshd", "sudo": "sudo"},
		hosts: map[string]bool{}, hostgroups: map[string]bool{}, users: map[string]bool{"admin": true}, groups: map[string]bool{}}
	all := f.newRule("allow_all")
	all.hostCat, all.svcCat, all.userCat = "all", "all", "all"
	f.newRule("allow_systemd-user")
	return f
}

func (f *fakeHBAC) uuid() string {
	f.seq++
	return fmt.Sprintf("00000000-0000-0000-0000-%012d", f.seq)
}

func (f *fakeHBAC) newRule(name string) *hRule {
	r := newHRule(name, f.uuid())
	f.rules[lower(name)] = r
	return r
}

// withRoster makes the objects the HBAC roster of hbacRosterDoc declares exist: what the
// users and groups phase and the playbook phase leave behind.
func (f *fakeHBAC) withRoster() *fakeHBAC {
	f.users["alice"] = true
	f.groups["team-a"] = true
	f.hostgroups["hg-a"] = true
	f.hosts["web1."+lab] = true
	return f
}

func (f *fakeHBAC) completeHost(name string) string { return completeHost(name, f.domain) }

func hbacNamesOf(m map[string]bool) []any {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return list(out...)
}

func (f *fakeHBAC) ruleEntry(r *hRule) map[string]any {
	e := map[string]any{
		"cn": list(r.name), "ipauniqueid": list(r.uuid), "ipaenabledflag": []any{r.enabled},
		"objectclass": list("ipaassociation", "ipahbacrule"), "accessruletype": list("allow"),
	}
	if f.noUniqueID {
		delete(e, "ipauniqueid")
	}
	for key, cat := range map[string]string{"hostcategory": r.hostCat, "servicecategory": r.svcCat, "usercategory": r.userCat} {
		if cat != "" {
			e[key] = list(cat)
		}
	}
	for key, m := range map[string]map[string]bool{
		"memberuser_user": r.users, "memberuser_group": r.groups, "memberhost_host": r.hosts,
		"memberhost_hostgroup": r.hostgroups, "memberservice_hbacsvc": r.services,
	} {
		if len(m) > 0 {
			e[key] = hbacNamesOf(m)
		}
	}
	return e
}

// Find implements Finder.
func (f *fakeHBAC) Find(ctx context.Context, method string, _ []any, opts map[string]any) ([]map[string]any, error) {
	f.mu.Lock()
	if method == "hbacrule_find" {
		f.ruleFinds++
		n := f.ruleFinds
		hook := f.onFind
		f.mu.Unlock()
		if hook != nil {
			hook(f, n)
		}
		f.mu.Lock()
	}
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{method: method, opts: opts, ctxErr: ctx.Err()})
	if f.findErr != nil {
		if err := f.findErr(method, f.ruleFinds); err != nil {
			return nil, err
		}
	}
	var out []map[string]any
	switch method {
	case "hbacrule_find":
		keys := make([]string, 0, len(f.rules))
		for k := range f.rules {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out = append(out, f.ruleEntry(f.rules[k]))
		}
	case "hbacsvc_find":
		for _, k := range sortedKeys(f.services) {
			out = append(out, map[string]any{"cn": list(f.services[k])})
		}
	case "host_find":
		for _, k := range sortedKeys(f.hosts) {
			out = append(out, map[string]any{"fqdn": list(k)})
		}
	case "hostgroup_find":
		for _, k := range sortedKeys(f.hostgroups) {
			out = append(out, map[string]any{"cn": list(k)})
		}
	default:
		return nil, fmt.Errorf("fakeHBAC: find %s", method)
	}
	return out, nil
}

func hbacIsWrite(method string) bool {
	switch method {
	case "hbacrule_show", "hbacrule_find", "hbacsvc_show", "hbacsvc_find", "host_find", "hostgroup_find", "hbactest", "env", "ping":
		return false
	}
	return true
}

func (f *fakeHBAC) gateWrite(ctx context.Context, method string) error {
	if f.writeGate == nil {
		return nil
	}
	if err := f.writeGate(ctx, method); err != nil {
		return &freeiparpc.ErrWriteRefused{Method: method, Err: err}
	}
	return nil
}

func hbacCancelled(ctx context.Context, method string) error {
	if err := ctx.Err(); err != nil {
		if hbacIsWrite(method) {
			return &freeiparpc.OutcomeUnknownError{Method: method, Err: err}
		}
		return err
	}
	return nil
}

// Call implements RPC.
func (f *fakeHBAC) Call(ctx context.Context, cmd freeiparpc.Command) (json.RawMessage, error) {
	if hbacIsWrite(cmd.Method) {
		if err := f.gateWrite(ctx, cmd.Method); err != nil {
			return nil, err
		}
	}
	if err := hbacCancelled(ctx, cmd.Method); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.execLocked(ctx, call{method: cmd.Method, args: cmd.Args, opts: cmd.Options})
}

// Batch implements RPC.
func (f *fakeHBAC) Batch(ctx context.Context, cmds []freeiparpc.Command) ([]freeiparpc.BatchItem, error) {
	for _, c := range cmds {
		if hbacIsWrite(c.Method) {
			if err := f.gateWrite(ctx, c.Method); err != nil {
				return nil, err
			}
		}
	}
	for _, c := range cmds {
		if err := hbacCancelled(ctx, c.Method); err != nil {
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
			return nil, err
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

func (f *fakeHBAC) errFixture(name string) error { return fixtureError(f.t, name) }

func jsonOf(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func (f *fakeHBAC) execLocked(ctx context.Context, c call) (json.RawMessage, error) {
	c.ctxErr = ctx.Err()
	c.ctx = ctx
	// Done is made now, so that two contexts that are cancelled later still have channels
	// of their own to tell them apart by (a context's channel is made on first use, and a
	// context cancelled before that shares one closed channel with all the others).
	_ = ctx.Done()
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
	rule := f.rules[lower(name)]
	switch c.method {
	case "env":
		return fixtureResult(f.t, "env-domain"), nil
	case "hbacrule_show":
		if rule == nil {
			return nil, f.errFixture("hbacrule-show-not-found")
		}
		return jsonOf(map[string]any{"result": f.ruleEntry(rule), "value": rule.name, "summary": nil}), nil
	case "hbacsvc_add":
		if _, ok := f.services[lower(name)]; ok {
			return nil, f.errFixture("hbacsvc-add-duplicate")
		}
		f.services[lower(name)] = name
		return jsonOf(map[string]any{"result": map[string]any{"cn": list(name)}, "value": name, "summary": "Added HBAC service \"" + name + "\""}), nil
	case "hbacrule_add":
		if rule != nil {
			return nil, f.errFixture("hbacrule-add-duplicate")
		}
		r := f.newRule(name)
		r.hostCat, _ = c.opts["hostcategory"].(string)
		r.svcCat, _ = c.opts["servicecategory"].(string)
		return jsonOf(map[string]any{"result": f.ruleEntry(r), "value": name, "summary": "Added HBAC rule \"" + name + "\""}), nil
	case "hbacrule_mod":
		return f.mod(c, rule)
	case "hbacrule_del":
		if rule == nil {
			return nil, f.errFixture("hbacrule-del-not-found")
		}
		delete(f.rules, lower(name))
		return jsonOf(map[string]any{"result": map[string]any{"failed": []any{}}, "value": list(rule.name), "summary": "Deleted HBAC rule \"" + rule.name + "\""}), nil
	case "hbacrule_enable", "hbacrule_disable":
		if rule == nil {
			return nil, f.errFixture("hbacrule-enable-not-found")
		}
		rule.enabled = c.method == "hbacrule_enable"
		word := map[bool]string{true: "Enabled", false: "Disabled"}[rule.enabled]
		return jsonOf(map[string]any{"result": true, "value": rule.name, "summary": word + " HBAC rule \"" + rule.name + "\""}), nil
	case "hbacrule_add_host", "hbacrule_remove_host", "hbacrule_add_service", "hbacrule_remove_service", "hbacrule_add_user", "hbacrule_remove_user":
		return f.members(c, rule)
	case "hbactest":
		return f.hbactest(c), nil
	}
	return nil, fmt.Errorf("fakeHBAC: %s", c.method)
}

// mod is hbacrule_mod on the categories (the only attributes the writer changes).
func (f *fakeHBAC) mod(c call, rule *hRule) (json.RawMessage, error) {
	if rule == nil {
		return nil, f.errFixture("hbacrule-mod-not-found")
	}
	changed := false
	for opt, field := range map[string]*string{"hostcategory": &rule.hostCat, "servicecategory": &rule.svcCat} {
		v, ok := c.opts[opt].(string)
		if !ok || v == *field {
			continue
		}
		if v == "all" && opt == "hostcategory" && len(rule.hosts)+len(rule.hostgroups) > 0 {
			return nil, f.errFixture("hbacrule-mod-hostcat-all-with-hosts")
		}
		if v == "all" && opt == "servicecategory" && len(rule.services) > 0 {
			return nil, f.errFixture("hbacrule-mod-servicecat-all-with-services")
		}
		*field = v
		changed = true
	}
	if !changed {
		return nil, f.errFixture("hbacrule-mod-no-change")
	}
	return jsonOf(map[string]any{"result": f.ruleEntry(rule), "value": rule.name, "summary": "Modified HBAC rule \"" + rule.name + "\""}), nil
}

// members is the add and remove commands, with the answers of the captures: HTTP-level
// success whatever happened to each member, completed, and failed.<area>.<kind> lists of
// [name, reason].
func (f *fakeHBAC) members(c call, rule *hRule) (json.RawMessage, error) {
	adding := strings.Contains(c.method, "_add_")
	if rule == nil {
		return nil, f.errFixture("hbacrule-add-user-rule-not-found")
	}
	type kindSpec struct {
		opt   string
		set   map[string]bool
		exist func(string) bool
		norm  func(string) string
	}
	id := func(s string) string { return lower(s) }
	var area string
	var kinds []kindSpec
	switch {
	case strings.HasSuffix(c.method, "_host"):
		area = "memberhost"
		if adding && rule.hostCat != "" {
			return nil, f.errFixture("hbacrule-add-host-while-hostcat-all")
		}
		kinds = []kindSpec{
			{"host", rule.hosts, func(n string) bool { return f.hosts[n] }, f.completeHost},
			{"hostgroup", rule.hostgroups, func(n string) bool { return f.hostgroups[n] }, id},
		}
	case strings.HasSuffix(c.method, "_service"):
		area = "memberservice"
		if adding && rule.svcCat != "" {
			return nil, f.errFixture("hbacrule-add-service-while-servicecat-all")
		}
		kinds = []kindSpec{{"hbacsvc", rule.services, func(n string) bool { _, ok := f.services[n]; return ok }, id}}
	default:
		area = "memberuser"
		kinds = []kindSpec{
			{"user", rule.users, func(n string) bool { return f.users[n] }, id},
			{"group", rule.groups, func(n string) bool { return f.groups[n] }, id},
		}
	}
	completed := 0
	failed := map[string]any{}
	for _, k := range kinds {
		fails := [][]string{}
		names, _ := c.opts[k.opt].([]any)
		for _, raw := range names {
			given, _ := raw.(string)
			n := k.norm(lower(given))
			switch {
			case adding && !k.exist(n):
				fails = append(fails, []string{given, reasonNoSuchEntry})
			case adding && k.set[n]:
				fails = append(fails, []string{given, reasonAlreadyMember})
			case adding:
				k.set[n] = true
				completed++
			case !k.set[n]:
				// Removing what is not a member, or does not exist, is the same answer (K2).
				fails = append(fails, []string{given, reasonNotMember})
			default:
				delete(k.set, n)
				completed++
			}
		}
		failed[k.opt] = fails
	}
	return jsonOf(map[string]any{"completed": completed, "failed": map[string]any{area: failed}, "result": f.ruleEntry(rule)}), nil
}

// hbactest answers as the captures show: value, summary, matched (null when nothing
// matched), notmatched. Only users named directly and hosts named directly or by category
// are modelled: that is what the lockdown's proof needs.
func (f *fakeHBAC) hbactest(c call) json.RawMessage {
	user, _ := c.opts["user"].(string)
	host := f.completeHost(lower(fmt.Sprint(c.opts["targethost"])))
	service, _ := c.opts["service"].(string)
	var matched, notmatched []any
	keys := make([]string, 0, len(f.rules))
	for k := range f.rules {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		r := f.rules[k]
		ok := r.enabled &&
			(r.userCat == "all" || r.users[lower(user)]) &&
			(r.hostCat == "all" || r.hosts[host]) &&
			(r.svcCat == "all" || r.services[lower(service)])
		if ok {
			matched = append(matched, r.name)
		} else {
			notmatched = append(notmatched, r.name)
		}
	}
	granted := len(matched) > 0
	return jsonOf(map[string]any{
		"warning": nil, "error": nil, "value": granted, "matched": nilIfEmpty(matched), "notmatched": nilIfEmpty(notmatched),
		"summary": "Access granted: " + map[bool]string{true: "True", false: "False"}[granted],
	})
}

func nilIfEmpty(l []any) any {
	if len(l) == 0 {
		return nil
	}
	return l
}

// callsOf is the methods the fake received, in order, of the commands (not the finds).
func (f *fakeHBAC) methods() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		out = append(out, c.method)
	}
	return out
}

// writes is the write commands the fake received, in order.
func (f *fakeHBAC) writes() []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []call
	for _, c := range f.calls {
		if hbacIsWrite(c.method) {
			out = append(out, c)
		}
	}
	return out
}

// ruleNamed is the rule by name, nil when there is none.
func (f *fakeHBAC) ruleNamed(name string) *hRule {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rules[lower(name)]
}
