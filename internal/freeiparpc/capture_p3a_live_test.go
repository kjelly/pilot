package freeiparpc

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"testing"
)

// The capture harness of Phase 3a (HBAC): it sends the reads and writes the Go
// HBAC stage will rely on to a disposable FreeIPA server through the SSH tunnel and
// keeps what the server answered as fixtures (testdata/<name>.status, .headers and
// .json), the way capture_p24_live_test.go does for users and groups.
// docs/superpowers/specs/2026-11-19-freeipa-go-reconcile-phase3-hbac-spec.md §1.2
// lists what each capture decides (K1-K9).
//
// It is a live test: it runs only when PILOT_FREEIPA_LIVE_SSH, IPA_ADMIN_PASSWORD
// and PILOT_FREEIPA_CAPTURE_DIR are set (the variables of live_test.go name the
// server; the capture directory must exist and be empty):
//
//	PILOT_FREEIPA_LIVE_SSH=root@<server> PILOT_FREEIPA_LIVE_SSH_KEY=<key> \
//	PILOT_FREEIPA_LIVE_SSH_OPTS=StrictHostKeyChecking=no,UserKnownHostsFile=/dev/null \
//	IPA_ADMIN_PASSWORD="$(cat <file>)" PILOT_FREEIPA_CAPTURE_DIR=<empty dir> \
//	go test ./internal/freeiparpc -run '^TestLiveCaptureP3a$' -count=1 -v
//
// What it does to the server, and undoes: every object it creates is named
// p3acap-*, and a sweep at the end (and at the start, which refuses to run on
// leftovers) deletes everything with that prefix; the sweep is checked. The one
// thing it changes that is not its own is the built-in allow_all rule (K6): it is
// disabled and enabled again, and the harness checks it ended enabled.
//
// The harness writes the constant .headers file next to each fixture, as the earlier
// captures have; the P3a captures commit only .json and .status (the pull request would
// pass GitHub's 300-file compare limit, kjelly/pilot#314), so delete the .headers files
// before committing a new capture.
//
// No password is sent except the ones the user_add setup does not need: the
// harness creates its users without one.

const p3aCapPrefix = "p3acap-"

// p3aCapture reuses the plumbing of the P2-4 harness (post, keep, need, redaction,
// the scan for sent secrets); only the objects and the sweep are its own.
type p3aCapture struct {
	*p24Capture
	domain string
}

func p3a(n string) string { return p3aCapPrefix + n }

// find lists the names a find answers with under key, for the objects whose name
// starts with the harness prefix.
func (p *p3aCapture) find(method, key string, args []any, opts map[string]any) []string {
	p.t.Helper()
	o := map[string]any{"sizelimit": 0, "timelimit": 0}
	for k, v := range opts {
		o[k] = v
	}
	if args == nil {
		args = []any{p3aCapPrefix}
	}
	a := p.rpc("", method, args, o)
	p.need(a, method)
	var env struct {
		Result struct {
			Result []map[string]any `json:"result"`
		} `json:"result"`
	}
	if err := json.Unmarshal(a.body, &env); err != nil {
		p.t.Fatal(err)
	}
	var names []string
	for _, e := range env.Result.Result {
		if l, ok := e[key].([]any); ok && len(l) == 1 {
			names = append(names, fmt.Sprint(l[0]))
		}
	}
	return names
}

func (p *p3aCapture) leftovers() []string {
	p.t.Helper()
	var left []string
	for _, n := range p.find("hbacrule_find", "cn", nil, nil) {
		left = append(left, "hbacrule "+n)
	}
	for _, n := range p.find("hbacsvc_find", "cn", nil, nil) {
		left = append(left, "hbacsvc "+n)
	}
	for _, n := range p.find("hostgroup_find", "cn", nil, nil) {
		left = append(left, "hostgroup "+n)
	}
	for _, n := range p.find("host_find", "fqdn", nil, nil) {
		left = append(left, "host "+n)
	}
	for _, n := range p.find("user_find", "uid", nil, nil) {
		left = append(left, "user "+n)
	}
	for _, n := range p.find("group_find", "cn", nil, nil) {
		left = append(left, "group "+n)
	}
	return left
}

func (p *p3aCapture) sweep() {
	p.t.Helper()
	for _, n := range p.find("hbacrule_find", "cn", nil, nil) {
		p.rpc("", "hbacrule_del", []any{n}, nil)
	}
	for _, n := range p.find("hbacsvc_find", "cn", nil, nil) {
		p.rpc("", "hbacsvc_del", []any{n}, nil)
	}
	for _, n := range p.find("hostgroup_find", "cn", nil, nil) {
		p.rpc("", "hostgroup_del", []any{n}, nil)
	}
	for _, n := range p.find("host_find", "fqdn", nil, nil) {
		p.rpc("", "host_del", []any{n}, map[string]any{"updatedns": false})
	}
	for _, n := range p.find("user_find", "uid", nil, nil) {
		p.rpc("", "user_del", []any{n}, nil)
	}
	for _, n := range p.find("group_find", "cn", nil, nil) {
		p.rpc("", "group_del", []any{n}, nil)
	}
}

func (p *p3aCapture) host(short string) string { return p3a(short) + "." + p.domain }

func (p *p3aCapture) addHost(short string) {
	p.t.Helper()
	p.need(p.rpc("", "host_add", []any{p.host(short)}, map[string]any{"force": true}), "setup host_add "+short)
}

func (p *p3aCapture) addHostgroup(short string) {
	p.t.Helper()
	p.need(p.rpc("", "hostgroup_add", []any{p3a(short)}, map[string]any{"description": "p3a capture"}), "setup hostgroup_add "+short)
}

func (p *p3aCapture) addService(short string) {
	p.t.Helper()
	p.need(p.rpc("", "hbacsvc_add", []any{p3a(short)}, map[string]any{"description": "p3a capture"}), "setup hbacsvc_add "+short)
}

// addRule creates a rule without a category, so members can be attached.
func (p *p3aCapture) addRule(short string, opts map[string]any) {
	p.t.Helper()
	o := map[string]any{"description": "p3a capture"}
	for k, v := range opts {
		o[k] = v
	}
	p.need(p.rpc("", "hbacrule_add", []any{p3a(short)}, o), "setup hbacrule_add "+short)
}

func listOf(names ...string) []any {
	out := make([]any, len(names))
	for i, n := range names {
		out[i] = n
	}
	return out
}

func TestLiveCaptureP3a(t *testing.T) {
	dir := liveCaptureDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("%s is not empty; give the capture a new directory", dir)
	}
	e := setupLive(t)
	base := &p24Capture{t: t, c: e.admin(t), dir: dir, names: map[string]bool{}}
	t.Cleanup(base.c.CloseIdleConnections)
	p := &p3aCapture{p24Capture: base, domain: "ipa.pilot.internal"}

	if left := p.leftovers(); len(left) != 0 {
		t.Fatalf("the server holds leftovers of an earlier run: %v", left)
	}
	t.Cleanup(func() {
		// allow_all is the one object that is not the harness's own.
		p.rpc("", "hbacrule_enable", []any{"allow_all"}, nil)
		p.sweep()
		if left := p.leftovers(); len(left) != 0 {
			t.Errorf("the sweep left %v", left)
		}
		if a := p.rpc("", "hbacrule_show", []any{"allow_all"}, map[string]any{"all": true}); !a.ok() ||
			!jsonHasEnabledFlag(a.body, true) {
			t.Errorf("allow_all is not enabled at the end of the capture")
		}
	})

	p.setup()
	p.captureReads()
	p.captureRuleLifecycle()
	p.captureCategories()
	p.captureMembers()
	p.captureEnable()
	p.captureNames()
	p.captureMissing()
	p.captureHBACTest()
	p.captureAllowAll()
	p.captureBatch()

	t.Logf("%d fixtures written; %d secret-bearing values replaced by the placeholder", len(p.order), p.redact)
	if len(p.secrets) != 0 {
		t.Fatalf("the harness sent a secret it should not have")
	}
	t.Logf("written: %v", slices.Sorted(slices.Values(p.order)))
}

func jsonHasEnabledFlag(body []byte, want bool) bool {
	var env struct {
		Result struct {
			Result map[string]any `json:"result"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &env) != nil {
		return false
	}
	switch v := env.Result.Result["ipaenabledflag"].(type) {
	case bool:
		return v == want
	case []any:
		if len(v) == 1 {
			s := fmt.Sprint(v[0])
			return (s == "TRUE" || s == "true") == want
		}
	}
	return false
}

// setup makes the objects the captures use: two users, a group, two hosts, a
// hostgroup, a service. None has a password.
func (p *p3aCapture) setup() {
	p.addUser(p3a("u1"), nil)
	p.addUser(p3a("u2"), nil)
	p.addGroup(p3a("g1"), map[string]any{"description": "p3a capture"})
	p.addHost("h1")
	p.addHost("h2")
	p.addHostgroup("hg1")
	p.addService("svc1")
	p.addService("svc2")
}

// K1: what a find and a show answer with for the built-in rules, a bare rule and a
// rule with members of every kind.
func (p *p3aCapture) captureReads() {
	p.need(p.rpc("hbacrule-find-builtin", "hbacrule_find", []any{}, map[string]any{"all": true, "sizelimit": 0, "timelimit": 0}), "hbacrule-find-builtin")
	p.need(p.showAll("hbacrule-show-allow-all", "hbacrule_show", "allow_all"), "hbacrule-show-allow-all")
	p.need(p.rpc("hbacsvc-find-builtin", "hbacsvc_find", []any{}, map[string]any{"all": true, "sizelimit": 0, "timelimit": 0}), "hbacsvc-find-builtin")
	p.need(p.showAll("hbacsvc-show-sshd", "hbacsvc_show", "sshd"), "hbacsvc-show-sshd")
	p.need(p.rpc("hbacsvc-find-created", "hbacsvc_find", []any{p3aCapPrefix}, map[string]any{"all": true, "sizelimit": 0, "timelimit": 0}), "hbacsvc-find-created")
	p.need(p.rpc("host-find-pkey-only", "host_find", []any{p3aCapPrefix}, map[string]any{"pkey_only": true, "sizelimit": 0, "timelimit": 0}), "host-find-pkey-only")
	p.need(p.rpc("hostgroup-find-pkey-only", "hostgroup_find", []any{p3aCapPrefix}, map[string]any{"pkey_only": true, "sizelimit": 0, "timelimit": 0}), "hostgroup-find-pkey-only")
	// The domain FreeIPA completes a short host name with (K4).
	p.need(p.rpc("env-domain", "env", []any{"domain", "realm", "host"}, nil), "env-domain")
}

// K2: creating, modifying, deleting a rule; what a duplicate and a missing rule
// answer with.
func (p *p3aCapture) captureRuleLifecycle() {
	p.need(p.rpc("hbacrule-add-bare", "hbacrule_add", []any{p3a("r1")}, map[string]any{"description": "p3a capture"}), "hbacrule-add-bare")
	p.rpc("hbacrule-add-duplicate", "hbacrule_add", []any{p3a("r1")}, map[string]any{"description": "p3a capture"})
	p.need(p.rpc("hbacrule-add-categories", "hbacrule_add", []any{p3a("r2")}, map[string]any{"hostcategory": "all", "servicecategory": "all"}), "hbacrule-add-categories")
	p.need(p.showAll("hbacrule-show-categories", "hbacrule_show", p3a("r2")), "hbacrule-show-categories")
	p.need(p.showAll("hbacrule-show-bare", "hbacrule_show", p3a("r1")), "hbacrule-show-bare")
	p.rpc("hbacrule-mod-description", "hbacrule_mod", []any{p3a("r1")}, map[string]any{"description": "p3a capture changed"})
	p.rpc("hbacrule-mod-no-change", "hbacrule_mod", []any{p3a("r1")}, map[string]any{"description": "p3a capture changed"})
	p.rpc("hbacrule-mod-no-options", "hbacrule_mod", []any{p3a("r1")}, map[string]any{})
	p.addService("svc3")
	p.rpc("hbacsvc-add-duplicate", "hbacsvc_add", []any{p3a("svc3")}, map[string]any{"description": "p3a capture"})
	p.rpc("hbacrule-del", "hbacrule_del", []any{p3a("r2")}, nil)
	p.rpc("hbacrule-del-not-found", "hbacrule_del", []any{p3a("r2")}, nil)
}

// K3: the categories and the members exclude each other.
func (p *p3aCapture) captureCategories() {
	p.addRule("r3", map[string]any{"hostcategory": "all"})
	p.rpc("hbacrule-add-host-while-hostcat-all", "hbacrule_add_host", []any{p3a("r3")}, map[string]any{"host": listOf(p.host("h1"))})
	p.rpc("hbacrule-add-hostgroup-while-hostcat-all", "hbacrule_add_host", []any{p3a("r3")}, map[string]any{"hostgroup": listOf(p3a("hg1"))})
	p.addRule("r4", map[string]any{"servicecategory": "all"})
	p.rpc("hbacrule-add-service-while-servicecat-all", "hbacrule_add_service", []any{p3a("r4")}, map[string]any{"hbacsvc": listOf(p3a("svc1"))})
	// A rule with members, then the category set while the members are there.
	p.addRule("r5", nil)
	p.need(p.rpc("hbacrule-add-host-r5", "hbacrule_add_host", []any{p3a("r5")}, map[string]any{"host": listOf(p.host("h1"))}), "hbacrule-add-host-r5")
	p.need(p.rpc("hbacrule-add-service-r5", "hbacrule_add_service", []any{p3a("r5")}, map[string]any{"hbacsvc": listOf(p3a("svc1"))}), "hbacrule-add-service-r5")
	p.rpc("hbacrule-mod-hostcat-all-with-hosts", "hbacrule_mod", []any{p3a("r5")}, map[string]any{"hostcategory": "all"})
	p.rpc("hbacrule-mod-servicecat-all-with-services", "hbacrule_mod", []any{p3a("r5")}, map[string]any{"servicecategory": "all"})
	// Clearing a category: an empty value, and the category set on a rule that has none.
	p.rpc("hbacrule-mod-hostcat-clear", "hbacrule_mod", []any{p3a("r3")}, map[string]any{"hostcategory": ""})
	p.showAll("hbacrule-show-hostcat-cleared", "hbacrule_show", p3a("r3"))
	p.rpc("hbacrule-mod-hostcat-clear-again", "hbacrule_mod", []any{p3a("r3")}, map[string]any{"hostcategory": ""})
	p.rpc("hbacrule-mod-servicecat-all-both", "hbacrule_mod", []any{p3a("r4")}, map[string]any{"servicecategory": "all", "hostcategory": ""})
}

// K2 and K4: attaching and removing every kind of member, what an attach of a
// member that is already there and of one that does not exist answer with, and how a
// host is named in a show after being attached by its FQDN and by its short name.
func (p *p3aCapture) captureMembers() {
	p.addRule("r6", nil)
	p.need(p.rpc("hbacrule-add-user", "hbacrule_add_user", []any{p3a("r6")}, map[string]any{"user": listOf(p3a("u1"))}), "hbacrule-add-user")
	p.rpc("hbacrule-add-user-already", "hbacrule_add_user", []any{p3a("r6")}, map[string]any{"user": listOf(p3a("u1"))})
	p.need(p.rpc("hbacrule-add-group", "hbacrule_add_user", []any{p3a("r6")}, map[string]any{"group": listOf(p3a("g1"))}), "hbacrule-add-group")
	p.rpc("hbacrule-add-group-already", "hbacrule_add_user", []any{p3a("r6")}, map[string]any{"group": listOf(p3a("g1"))})
	p.need(p.rpc("hbacrule-add-host", "hbacrule_add_host", []any{p3a("r6")}, map[string]any{"host": listOf(p.host("h1"))}), "hbacrule-add-host")
	p.rpc("hbacrule-add-host-already", "hbacrule_add_host", []any{p3a("r6")}, map[string]any{"host": listOf(p.host("h1"))})
	p.need(p.rpc("hbacrule-add-hostgroup", "hbacrule_add_host", []any{p3a("r6")}, map[string]any{"hostgroup": listOf(p3a("hg1"))}), "hbacrule-add-hostgroup")
	p.rpc("hbacrule-add-hostgroup-already", "hbacrule_add_host", []any{p3a("r6")}, map[string]any{"hostgroup": listOf(p3a("hg1"))})
	p.need(p.rpc("hbacrule-add-service", "hbacrule_add_service", []any{p3a("r6")}, map[string]any{"hbacsvc": listOf(p3a("svc1"))}), "hbacrule-add-service")
	p.rpc("hbacrule-add-service-already", "hbacrule_add_service", []any{p3a("r6")}, map[string]any{"hbacsvc": listOf(p3a("svc1"))})
	p.need(p.showAll("hbacrule-show-all-members", "hbacrule_show", p3a("r6")), "hbacrule-show-all-members")

	// Several members in one call, one of which is already there.
	p.rpc("hbacrule-add-two-users-one-already", "hbacrule_add_user", []any{p3a("r6")}, map[string]any{"user": listOf(p3a("u1"), p3a("u2"))})
	// A member that does not exist, alone and next to one that does.
	p.rpc("hbacrule-add-user-missing", "hbacrule_add_user", []any{p3a("r6")}, map[string]any{"user": listOf(p3a("nouser"))})
	p.rpc("hbacrule-add-user-mixed-missing", "hbacrule_add_user", []any{p3a("r6")}, map[string]any{"user": listOf(p3a("u2"), p3a("nouser2"))})
	p.rpc("hbacrule-add-host-missing", "hbacrule_add_host", []any{p3a("r6")}, map[string]any{"host": listOf(p.host("nohost"))})
	p.rpc("hbacrule-add-hostgroup-missing", "hbacrule_add_host", []any{p3a("r6")}, map[string]any{"hostgroup": listOf(p3a("nohg"))})
	p.rpc("hbacrule-add-service-missing", "hbacrule_add_service", []any{p3a("r6")}, map[string]any{"hbacsvc": listOf(p3a("nosvc"))})
	p.rpc("hbacrule-add-group-missing", "hbacrule_add_user", []any{p3a("r6")}, map[string]any{"group": listOf(p3a("nogroup"))})

	// K4: a host named by its short name.
	p.rpc("hbacrule-add-host-short-name", "hbacrule_add_host", []any{p3a("r6")}, map[string]any{"host": listOf(p3a("h2"))})
	p.showAll("hbacrule-show-after-short-host", "hbacrule_show", p3a("r6"))
	// Upper case in a member name.
	p.rpc("hbacrule-add-host-upper-case", "hbacrule_add_host", []any{p3a("r6")}, map[string]any{"host": listOf("P3ACAP-H2." + p.domain)})

	// Removals: a member that is there, one that is not, one that does not exist.
	p.rpc("hbacrule-remove-user", "hbacrule_remove_user", []any{p3a("r6")}, map[string]any{"user": listOf(p3a("u2"))})
	p.rpc("hbacrule-remove-user-not-member", "hbacrule_remove_user", []any{p3a("r6")}, map[string]any{"user": listOf(p3a("u2"))})
	p.rpc("hbacrule-remove-user-missing", "hbacrule_remove_user", []any{p3a("r6")}, map[string]any{"user": listOf(p3a("nouser"))})
	p.rpc("hbacrule-remove-group", "hbacrule_remove_user", []any{p3a("r6")}, map[string]any{"group": listOf(p3a("g1"))})
	p.rpc("hbacrule-remove-host", "hbacrule_remove_host", []any{p3a("r6")}, map[string]any{"host": listOf(p.host("h1"))})
	p.rpc("hbacrule-remove-hostgroup", "hbacrule_remove_host", []any{p3a("r6")}, map[string]any{"hostgroup": listOf(p3a("hg1"))})
	p.rpc("hbacrule-remove-service", "hbacrule_remove_service", []any{p3a("r6")}, map[string]any{"hbacsvc": listOf(p3a("svc1"))})
	p.showAll("hbacrule-show-after-removals", "hbacrule_show", p3a("r6"))

	// A member's object deleted while it is on a rule: what the rule shows.
	p.need(p.rpc("hbacrule-add-user-for-delete", "hbacrule_add_user", []any{p3a("r6")}, map[string]any{"user": listOf(p3a("u2"))}), "hbacrule-add-user-for-delete")
	p.rpc("user-del-while-on-rule", "user_del", []any{p3a("u2")}, nil)
	p.showAll("hbacrule-show-after-member-user-del", "hbacrule_show", p3a("r6"))
}

// K2: enable and disable.
func (p *p3aCapture) captureEnable() {
	p.addRule("r7", nil)
	p.showAll("hbacrule-show-enabled", "hbacrule_show", p3a("r7"))
	p.rpc("hbacrule-enable-already", "hbacrule_enable", []any{p3a("r7")}, nil)
	p.rpc("hbacrule-disable", "hbacrule_disable", []any{p3a("r7")}, nil)
	p.showAll("hbacrule-show-disabled", "hbacrule_show", p3a("r7"))
	p.rpc("hbacrule-disable-already", "hbacrule_disable", []any{p3a("r7")}, nil)
	p.rpc("hbacrule-enable", "hbacrule_enable", []any{p3a("r7")}, nil)
	p.rpc("hbacrule-enable-not-found", "hbacrule_enable", []any{p3a("nosuchrule")}, nil)
	p.rpc("hbacrule-disable-not-found", "hbacrule_disable", []any{p3a("nosuchrule")}, nil)
}

// K7: whether a rule's name is case sensitive.
func (p *p3aCapture) captureNames() {
	p.need(p.rpc("hbacrule-add-mixed-case", "hbacrule_add", []any{"P3aCap-CaseRule"}, map[string]any{"hostcategory": "all", "servicecategory": "all"}), "hbacrule-add-mixed-case")
	p.rpc("hbacrule-add-lower-case-duplicate", "hbacrule_add", []any{"p3acap-caserule"}, map[string]any{"hostcategory": "all", "servicecategory": "all"})
	p.showAll("hbacrule-show-lower-case", "hbacrule_show", "p3acap-caserule")
	p.showAll("hbacrule-show-mixed-case", "hbacrule_show", "P3aCap-CaseRule")
	p.rpc("hbacrule-find-case", "hbacrule_find", []any{"P3ACAP-CASE"}, map[string]any{"all": true, "sizelimit": 0, "timelimit": 0})
	p.rpc("hbacsvc-add-mixed-case", "hbacsvc_add", []any{"P3aCap-CaseSvc"}, map[string]any{"description": "p3a capture"})
}

// K8: what a show and a mod answer with when the rule does not exist.
func (p *p3aCapture) captureMissing() {
	p.showAll("hbacrule-show-not-found", "hbacrule_show", p3a("nosuchrule"))
	p.rpc("hbacrule-mod-not-found", "hbacrule_mod", []any{p3a("nosuchrule")}, map[string]any{"description": "x"})
	p.rpc("hbacrule-add-user-rule-not-found", "hbacrule_add_user", []any{p3a("nosuchrule")}, map[string]any{"user": listOf(p3a("u1"))})
	p.rpc("hbacsvc-show-not-found", "hbacsvc_show", []any{p3a("nosuchsvc")}, nil)
}

// K5: hbactest, an access that is granted and one that is denied.
func (p *p3aCapture) captureHBACTest() {
	p.addRule("r8", map[string]any{"hostcategory": "all", "servicecategory": "all"})
	p.need(p.rpc("", "hbacrule_add_user", []any{p3a("r8")}, map[string]any{"user": listOf(p3a("u1"))}), "hbactest rule user")
	// allow_all would grant everything; it is disabled for the test and enabled
	// again right after (the cleanup enables it too).
	p.rpc("", "hbacrule_disable", []any{"allow_all"}, nil)
	p.rpc("hbactest-granted", "hbactest", []any{}, map[string]any{"user": p3a("u1"), "targethost": p.host("h1"), "service": "sshd"})
	p.rpc("hbactest-denied", "hbactest", []any{}, map[string]any{"user": p3a("u1"), "targethost": p.host("h1"), "service": "sudo-i-nonexistent"})
	p.rpc("hbactest-denied-user", "hbactest", []any{}, map[string]any{"user": "p3acap-nobody", "targethost": p.host("h1"), "service": "sshd"})
	p.rpc("hbactest-admin-granted", "hbactest", []any{}, map[string]any{"user": "admin", "targethost": p.host("h1"), "service": "sshd"})
	p.rpc("hbactest-target-host-missing", "hbactest", []any{}, map[string]any{"user": p3a("u1"), "targethost": p.host("nohost"), "service": "sshd"})
	// The break-glass shape the lockdown proves access with: admin, every host, with
	// allow_all disabled.
	p.addRule("breakglass", map[string]any{"hostcategory": "all", "servicecategory": "all"})
	p.need(p.rpc("", "hbacrule_add_user", []any{p3a("breakglass")}, map[string]any{"user": listOf("admin")}), "hbactest break-glass user")
	p.rpc("hbactest-breakglass-granted", "hbactest", []any{}, map[string]any{"user": "admin", "targethost": p.host("h1"), "service": "sshd"})
	p.rpc("hbacrule-disable-breakglass", "hbacrule_disable", []any{p3a("breakglass")}, nil)
	p.rpc("hbactest-breakglass-disabled", "hbactest", []any{}, map[string]any{"user": "admin", "targethost": p.host("h1"), "service": "sshd"})
	p.rpc("hbactest-rules-option", "hbactest", []any{}, map[string]any{"user": p3a("u1"), "targethost": p.host("h1"), "service": "sshd", "rules": listOf(p3a("r8"))})
	p.rpc("", "hbacrule_enable", []any{"allow_all"}, nil)
}

// K6: allow_all disabled and enabled.
func (p *p3aCapture) captureAllowAll() {
	p.showAll("hbacrule-show-allow-all-enabled", "hbacrule_show", "allow_all")
	p.rpc("hbacrule-disable-allow-all", "hbacrule_disable", []any{"allow_all"}, nil)
	p.showAll("hbacrule-show-allow-all-disabled", "hbacrule_show", "allow_all")
	p.rpc("hbacrule-disable-allow-all-again", "hbacrule_disable", []any{"allow_all"}, nil)
	p.rpc("hbacrule-enable-allow-all", "hbacrule_enable", []any{"allow_all"}, nil)
	p.rpc("hbacrule-enable-allow-all-again", "hbacrule_enable", []any{"allow_all"}, nil)
}

// A batch of mixed HBAC writes: what each item answers with, and one failing item.
func (p *p3aCapture) captureBatch() {
	p.addRule("r9", nil)
	p.batch("batch-hbac-mixed",
		Command{Method: "hbacrule_add_user", Args: []any{p3a("r9")}, Options: map[string]any{"user": listOf(p3a("u1"))}},
		Command{Method: "hbacrule_add_service", Args: []any{p3a("r9")}, Options: map[string]any{"hbacsvc": listOf(p3a("svc1"))}},
		Command{Method: "hbacrule_add_host", Args: []any{p3a("r9")}, Options: map[string]any{"host": listOf(p.host("nohost"))}},
		Command{Method: "hbacrule_disable", Args: []any{p3a("r9")}},
	)
	p.batch("batch-hbac-show",
		Command{Method: "hbacrule_show", Args: []any{p3a("r9")}, Options: map[string]any{"all": true}},
		Command{Method: "hbacrule_show", Args: []any{p3a("nosuchrule")}, Options: map[string]any{"all": true}},
	)
}
