package cmd

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
)

// A FreeIPA's HBAC for the scenarios of the mixed run (reconcile_golang_mixed_hbac_test.go): a small stateful
// model behind the fake server's respond hook, whose answers have the shapes the P3-0 captures show
// (internal/freeiparpc/testdata/hbac*, batch-hbac-mixed, env-domain; internal/freeiparpc/capture_p3a_facts_test.go
// states each). What the model decides by hand is the state: which rules, services, hosts and hostgroups exist
// and who is on which rule. The users and groups of a scenario are the users-groups fake's (applyFake).

type hbacFakeRule struct {
	name                     string // as created
	uuid                     string
	enabled                  bool
	hostCat, svcCat, userCat string
	users, groups, hosts     map[string]bool
	hostgroups, services     map[string]bool
}

type hbacFake struct {
	t  *testing.T
	mu sync.Mutex

	domain     string
	rules      map[string]*hbacFakeRule // lower-case name
	services   map[string]bool
	hosts      map[string]bool // lower-case FQDN
	hostgroups map[string]bool
	absent     map[string]bool // users that do not exist (a member command answers "no such entry")
	seq        int

	// writes are "<method>:<object>[:<members>]" of every HBAC write, in order.
	writes []string
	// hbactests are the answers given to hbactest, in order.
	hbactests []bool
	// onWrite runs when a command with HBAC writes arrives, before it is answered (a test logs it in order with
	// the playbook's runs, or cancels the run's context there).
	onWrite func(writes []string)
	// failMember makes the member command "<method>:<object>" answer "no such entry" for every member.
	failMember map[string]bool
	// failFind answers a find (or hbactest) with this body instead of the model's: a captured error.
	failFind map[string]string
	// denyAfterDisable makes hbactest deny once allow_all is disabled (a break-glass rule that does not work).
	denyAfterDisable bool
}

func newHBACFake(t *testing.T) *hbacFake {
	t.Helper()
	f := &hbacFake{t: t, domain: "ipa.pilot.internal", rules: map[string]*hbacFakeRule{}, services: map[string]bool{"sshd": true, "sudo": true},
		hosts: map[string]bool{}, hostgroups: map[string]bool{}, absent: map[string]bool{}, failMember: map[string]bool{}, failFind: map[string]string{}}
	all := f.newRule("allow_all")
	all.hostCat, all.svcCat, all.userCat = "all", "all", "all"
	f.newRule("allow_systemd-user")
	return f
}

func (f *hbacFake) newRule(name string) *hbacFakeRule {
	f.seq++
	r := &hbacFakeRule{name: name, uuid: fmt.Sprintf("00000000-0000-4000-8000-%012d", f.seq), enabled: true,
		users: map[string]bool{}, groups: map[string]bool{}, hosts: map[string]bool{}, hostgroups: map[string]bool{}, services: map[string]bool{}}
	f.rules[strings.ToLower(name)] = r
	return r
}

// install makes the fake answer the HBAC methods of the scenario's server; everything else is the
// users-groups fake's.
func (f *hbacFake) install(e *applyEnv) {
	next := e.a.respond
	e.f.respond = func(method string, params []any) (string, bool) {
		if body, ok := f.respond(method, params); ok {
			return body, true
		}
		return next(method, params)
	}
}

func (f *hbacFake) rule(name string) *hbacFakeRule {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rules[strings.ToLower(name)]
}

func (f *hbacFake) written() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.writes)
}

func hbacList(names ...string) []any {
	out := make([]any, len(names))
	for i, n := range names {
		out[i] = n
	}
	return out
}

func hbacSorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (f *hbacFake) ruleEntry(r *hbacFakeRule) map[string]any {
	e := map[string]any{
		"cn": hbacList(r.name), "ipauniqueid": hbacList(r.uuid), "ipaenabledflag": []any{r.enabled},
		"objectclass": hbacList("ipaassociation", "ipahbacrule"), "accessruletype": hbacList("allow"),
	}
	for key, cat := range map[string]string{"hostcategory": r.hostCat, "servicecategory": r.svcCat, "usercategory": r.userCat} {
		if cat != "" {
			e[key] = hbacList(cat)
		}
	}
	for key, m := range map[string]map[string]bool{
		"memberuser_user": r.users, "memberuser_group": r.groups, "memberhost_host": r.hosts,
		"memberhost_hostgroup": r.hostgroups, "memberservice_hbacsvc": r.services,
	} {
		if len(m) > 0 {
			e[key] = hbacList(hbacSorted(m)...)
		}
	}
	return e
}

func hbacFindAnswer(entries []map[string]any) string {
	if entries == nil {
		entries = []map[string]any{} // an empty find has a result list, not null (freeiparpc.Client.Find)
	}
	raw, _ := json.Marshal(map[string]any{
		"result": map[string]any{"result": entries, "count": len(entries), "truncated": false, "summary": fmt.Sprintf("%d matched", len(entries))},
		"error":  nil, "id": 0, "principal": "admin@IPA.PILOT.INTERNAL", "version": "4.13.4",
	})
	return string(raw)
}

func hbacSingleAnswer(item map[string]any) string {
	raw, _ := json.Marshal(map[string]any{"result": item, "error": nil, "id": 0, "principal": "admin@IPA.PILOT.INTERNAL", "version": "4.13.4"})
	return string(raw)
}

func isHBACWrite(method string) bool {
	return strings.HasPrefix(method, "hbac") && !slices.Contains([]string{"hbacrule_find", "hbacrule_show", "hbacsvc_find", "hbacsvc_show", "hbactest"}, method)
}

func (f *hbacFake) respond(method string, params []any) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if body, ok := f.failFind[method]; ok {
		return body, true
	}
	switch method {
	case "hbacrule_find":
		keys := make([]string, 0, len(f.rules))
		for k := range f.rules {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var out []map[string]any
		for _, k := range keys {
			out = append(out, f.ruleEntry(f.rules[k]))
		}
		return hbacFindAnswer(out), true
	case "hbacsvc_find":
		var out []map[string]any
		for _, k := range hbacSorted(f.services) {
			out = append(out, map[string]any{"cn": hbacList(k)})
		}
		return hbacFindAnswer(out), true
	case "host_find":
		var out []map[string]any
		for _, k := range hbacSorted(f.hosts) {
			out = append(out, map[string]any{"fqdn": hbacList(k)})
		}
		return hbacFindAnswer(out), true
	case "hostgroup_find":
		var out []map[string]any
		for _, k := range hbacSorted(f.hostgroups) {
			out = append(out, map[string]any{"cn": hbacList(k)})
		}
		return hbacFindAnswer(out), true
	case "hbactest":
		opts, _ := params[1].(map[string]any)
		user, _ := opts["user"].(string)
		granted := f.granted(strings.ToLower(user))
		f.hbactests = append(f.hbactests, granted)
		summary := "Access granted: False"
		var matched any
		if granted {
			summary, matched = "Access granted: True", hbacList("breakglass")
		}
		return hbacSingleAnswer(map[string]any{"value": granted, "summary": summary, "matched": matched, "notmatched": nil, "warning": nil, "error": nil}), true
	case "batch":
		cmds, _ := params[0].([]any)
		var hbacCmds int
		for _, c := range cmds {
			if m, _ := c.(map[string]any)["method"].(string); isHBACWrite(m) {
				hbacCmds++
			}
		}
		if hbacCmds == 0 {
			return "", false
		}
		items := make([]any, 0, len(cmds))
		var writes []string
		for _, c := range cmds {
			cm := c.(map[string]any)
			m, _ := cm["method"].(string)
			cp, _ := cm["params"].([]any)
			item, line := f.apply(m, cp)
			items = append(items, item)
			writes = append(writes, line)
		}
		f.record(writes)
		raw, _ := json.Marshal(map[string]any{"result": map[string]any{"count": len(items), "results": items}, "error": nil, "id": 0,
			"principal": "admin@IPA.PILOT.INTERNAL", "version": "4.13.4"})
		return string(raw), true
	}
	if isHBACWrite(method) {
		item, line := f.apply(method, params)
		f.record([]string{line})
		if item["error_name"] != nil {
			raw, _ := json.Marshal(map[string]any{"result": nil, "error": map[string]any{"code": item["error_code"], "message": item["error"], "name": item["error_name"], "data": map[string]any{}},
				"id": 0, "principal": "admin@IPA.PILOT.INTERNAL", "version": "4.13.4"})
			return string(raw), true
		}
		return hbacSingleAnswer(item), true
	}
	return "", false
}

// record logs writes and runs the hook (with the lock released: the hook may cancel a context).
func (f *hbacFake) record(writes []string) {
	f.writes = append(f.writes, writes...)
	hook := f.onWrite
	if hook != nil {
		f.mu.Unlock()
		hook(writes)
		f.mu.Lock()
	}
}

// granted is hbactest for the user on a host and service no rule restricts (the scenarios' rules are every host,
// every service): an enabled rule that names the user or has user category all.
func (f *hbacFake) granted(user string) bool {
	if f.denyAfterDisable && !f.rules["allow_all"].enabled {
		return false
	}
	for _, r := range f.rules {
		if r.enabled && (r.userCat == "all" || r.users[user]) && (r.hostCat == "all" || len(r.hosts)+len(r.hostgroups) > 0) {
			return true
		}
	}
	return false
}

func hbacItemError(name string, code int, text string) map[string]any {
	return map[string]any{"error": text, "error_code": code, "error_name": name, "error_kw": map[string]any{}}
}

// apply carries out one write command and answers it, with the line for the log.
func (f *hbacFake) apply(method string, cp []any) (map[string]any, string) {
	var args []any
	var opts map[string]any
	if len(cp) > 0 {
		args, _ = cp[0].([]any)
	}
	if len(cp) > 1 {
		opts, _ = cp[1].(map[string]any)
	}
	name := ""
	if len(args) > 0 {
		name, _ = args[0].(string)
	}
	key := strings.ToLower(name)
	line := method + ":" + key
	ok := func(extra map[string]any) map[string]any {
		item := map[string]any{"result": map[string]any{"cn": hbacList(name)}, "value": name, "summary": method, "error": nil}
		for k, v := range extra {
			item[k] = v
		}
		return item
	}
	switch method {
	case "hbacsvc_add":
		if f.services[key] {
			return hbacItemError("DuplicateEntry", 4002, name+": HBAC service already exists"), line
		}
		f.services[key] = true
		return ok(nil), line
	case "hbacrule_add":
		if _, exists := f.rules[key]; exists {
			return hbacItemError("DuplicateEntry", 4002, name+": HBAC rule already exists"), line
		}
		r := f.newRule(name)
		r.hostCat, _ = opts["hostcategory"].(string)
		r.svcCat, _ = opts["servicecategory"].(string)
		return ok(nil), line
	}
	r, exists := f.rules[key]
	if !exists {
		return hbacItemError("NotFound", 4001, name+": HBAC rule not found"), line
	}
	switch method {
	case "hbacrule_mod":
		changed := false
		for opt, dst := range map[string]*string{"hostcategory": &r.hostCat, "servicecategory": &r.svcCat} {
			if v, present := opts[opt].(string); present && v != *dst {
				if v == "all" && (len(r.hosts)+len(r.hostgroups) > 0) && opt == "hostcategory" {
					return hbacItemError("MutuallyExclusiveError", 4303, "host category cannot be set to 'all' while there are allowed hosts"), line
				}
				*dst, changed = v, true
			}
		}
		if !changed {
			return hbacItemError("EmptyModlist", 4202, "no modifications to be performed"), line
		}
		return ok(nil), line
	case "hbacrule_enable", "hbacrule_disable":
		r.enabled = method == "hbacrule_enable"
		return map[string]any{"result": true, "value": name, "summary": method, "error": nil}, line
	case "hbacrule_del":
		delete(f.rules, key)
		return map[string]any{"result": map[string]any{"failed": []any{}}, "value": hbacList(name), "summary": "Deleted", "error": nil}, line
	}
	// The member commands.
	type area struct {
		area  string
		kinds [2]string
	}
	var ar area
	var set [2]map[string]bool
	var exists2 [2]func(string) bool
	adding := strings.Contains(method, "_add_")
	switch {
	case strings.HasSuffix(method, "_user"):
		ar, set = area{"memberuser", [2]string{"user", "group"}}, [2]map[string]bool{r.users, r.groups}
		exists2 = [2]func(string) bool{func(n string) bool { return !f.absent[n] }, func(string) bool { return true }}
	case strings.HasSuffix(method, "_host"):
		ar, set = area{"memberhost", [2]string{"host", "hostgroup"}}, [2]map[string]bool{r.hosts, r.hostgroups}
		exists2 = [2]func(string) bool{func(n string) bool { return f.hosts[n] }, func(n string) bool { return f.hostgroups[n] }}
	case strings.HasSuffix(method, "_service"):
		ar, set = area{"memberservice", [2]string{"hbacsvc", "hbacsvcgroup"}}, [2]map[string]bool{r.services, {}}
		exists2 = [2]func(string) bool{func(n string) bool { return f.services[n] }, func(string) bool { return false }}
	default:
		return hbacItemError("CommandError", 905, "unknown command "+method), line
	}
	completed := 0
	failed := map[string]any{}
	var members []string
	for i, kind := range ar.kinds {
		list := []any{}
		given, _ := opts[kind].([]any)
		for _, g := range given {
			n := strings.ToLower(fmt.Sprint(g))
			if kind == "host" && !strings.Contains(n, ".") {
				n += "." + f.domain
			}
			members = append(members, n)
			switch {
			case f.failMember[line] && adding:
				list = append(list, []any{n, "no such entry"})
			case adding && !exists2[i](n):
				list = append(list, []any{n, "no such entry"})
			case adding && set[i][n]:
				list = append(list, []any{n, "This entry is already a member"})
			case adding && ((kind == "host" || kind == "hostgroup") && r.hostCat == "all"):
				return hbacItemError("MutuallyExclusiveError", 4303, "hosts cannot be added when host category='all'"), line
			case adding:
				set[i][n] = true
				completed++
			case !adding && !set[i][n]:
				list = append(list, []any{n, "This entry is not a member"})
			default:
				delete(set[i], n)
				completed++
			}
		}
		failed[ar.area+"_"+kind] = list
	}
	// The captured shape: failed.<area>.<kind>.
	nested := map[string]any{ar.area: map[string]any{ar.kinds[0]: failed[ar.area+"_"+ar.kinds[0]], ar.kinds[1]: failed[ar.area+"_"+ar.kinds[1]]}}
	sort.Strings(members)
	item := map[string]any{"result": f.ruleEntry(r), "completed": completed, "failed": nested, "error": nil}
	return item, line + ":" + strings.Join(members, ",")
}
