package identityreconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/freeiparpc"
)

const hbacRosterDoc = `
schema_version: 3
users:
  - {name: alice}
  - {name: dave, state: absent}
groups:
  - {name: team-a, category: team}
hostgroups:
  - {name: hg-a}
hosts:
  - {name: web1.ipa.pilot.internal, ip_address: 192.0.2.11}
hbac:
  services:
    - {name: custom-svc}
  rules:
    - name: Login-Team
      subjects: {users: [alice], groups: [team-a]}
      targets: {hostgroups: [hg-a], hosts: [web1]}
      services: [sshd, custom-svc]
    - name: break-glass
      subjects: {users: [admin]}
      targets: {hostcat: all}
      services: [sshd]
    - name: parked
      enabled: false
      subjects: {users: [alice]}
      targets: {hostcat: all}
      services: [sshd]
    - name: old-rule
      state: absent
      subjects: {users: [alice]}
      targets: {hostcat: all}
      services: [sshd]
`

func hbacDesired(t *testing.T, doc string) DesiredHBAC {
	t.Helper()
	d, err := HBACFromRoster(roster(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestHBACFromRoster(t *testing.T) {
	d := hbacDesired(t, hbacRosterDoc)
	if len(d.Rules) != 3 || !slices.Equal(d.AbsentRules, []string{"old-rule"}) {
		t.Fatalf("rules %d, absent %v", len(d.Rules), d.AbsentRules)
	}
	r := d.Rules[0]
	if r.Name != "Login-Team" || r.HostCategory != "" || !r.Enabled ||
		!slices.Equal(r.Users, []string{"alice"}) || !slices.Equal(r.Groups, []string{"team-a"}) ||
		!slices.Equal(r.Hosts, []string{"web1"}) || !slices.Equal(r.Hostgroups, []string{"hg-a"}) ||
		!slices.Equal(r.Services, []string{"custom-svc", "sshd"}) {
		t.Errorf("first rule = %+v", r)
	}
	if bg := d.Rules[1]; bg.HostCategory != "all" || len(bg.Hosts)+len(bg.Hostgroups) != 0 {
		t.Errorf("a rule that names no host has hostcat all: %+v", bg)
	}
	if d.Rules[2].Enabled {
		t.Error("enabled: false is read as enabled")
	}
	if !slices.Equal(d.Services, []string{"custom-svc"}) || !slices.Equal(d.DeclaredHostgroups, []string{"hg-a"}) ||
		!slices.Equal(d.DeclaredHosts, []string{"web1.ipa.pilot.internal"}) || !slices.Equal(d.AbsentUsers, []string{"dave"}) {
		t.Errorf("declared: %+v", d)
	}
	if d.DisableAllowAll {
		t.Error("disable_allow_all defaults to false")
	}
	if on := hbacDesired(t, strings.Replace(hbacRosterDoc, "hbac:\n", "hbac:\n  disable_allow_all: true\n", 1)); !on.DisableAllowAll {
		t.Error("disable_allow_all: true is not read")
	}
}

func TestHBACFromRosterRefusesWhatFromRosterRefuses(t *testing.T) {
	root := roster(t, hbacRosterDoc)
	delete(root, "schema_version")
	if _, err := HBACFromRoster(root); err == nil {
		t.Fatal("a roster with no schema_version was read")
	}
	bad := roster(t, hbacRosterDoc)
	bad["hbac"].(map[string]any)["rules"] = "not a list"
	if _, err := HBACFromRoster(bad); err == nil {
		t.Fatal("hbac.rules that is not a list was read")
	}
}

func TestParseHBACRulesReadsTheCapturedShapes(t *testing.T) {
	rules, err := ParseHBACRules(captured(t, "hbacrule-find-builtin"))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]LiveHBACRule{}
	for _, r := range rules {
		names[r.Name] = r
	}
	all, ok := names["allow_all"]
	if !ok || !all.Enabled || all.HostCategory != "all" || all.ServiceCategory != "all" || all.UserCategory != "all" {
		t.Errorf("allow_all = %+v", all)
	}
	if _, ok := names["allow_systemd-user"]; !ok {
		t.Error("the second built-in rule is not read")
	}
	members, err := parseHBACRule(capturedOne(t, "hbacrule-show-all-members"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(members.Users, []string{"p3acap-u1"}) || !slices.Equal(members.Groups, []string{"p3acap-g1"}) ||
		!slices.Equal(members.Hosts, []string{"p3acap-h1.ipa.pilot.internal"}) || !slices.Equal(members.Hostgroups, []string{"p3acap-hg1"}) ||
		!slices.Equal(members.Services, []string{"p3acap-svc1"}) || members.HostCategory != "" || !members.Enabled {
		t.Errorf("members = %+v", members)
	}
	disabled, err := parseHBACRule(capturedOne(t, "hbacrule-show-disabled"))
	if err != nil || disabled.Enabled {
		t.Errorf("a disabled rule: %+v %v", disabled, err)
	}
	mixed, err := parseHBACRule(capturedOne(t, "hbacrule-show-mixed-case"))
	if err != nil || mixed.Name != "P3aCap-CaseRule" {
		t.Errorf("the stored spelling is kept: %+v %v", mixed, err)
	}
}

func TestParseHBACRuleRefusesWhatItDoesNotKnow(t *testing.T) {
	good := capturedOne(t, "hbacrule-show-bare")
	for name, mutate := range map[string]func(map[string]any){
		"no enabled flag":       func(e map[string]any) { delete(e, "ipaenabledflag") },
		"a text enabled flag":   func(e map[string]any) { e["ipaenabledflag"] = []any{"TRUE"} },
		"an unknown category":   func(e map[string]any) { e["hostcategory"] = []any{"some"} },
		"two names":             func(e map[string]any) { e["cn"] = []any{"a", "b"} },
		"a member that is text": func(e map[string]any) { e["memberuser_user"] = "alice" },
	} {
		e := map[string]any{}
		for k, v := range good {
			e[k] = v
		}
		mutate(e)
		if _, err := parseHBACRule(e); err == nil {
			t.Errorf("%s: read as a rule", name)
		}
	}
	if _, err := parseHBACRule(good); err != nil {
		t.Fatalf("the unmodified entry is refused: %v", err)
	}
}

type fakeHBACReader struct {
	finds []string
	fail  string
	env   json.RawMessage
}

func (f *fakeHBACReader) Find(_ context.Context, method string, _ []any, _ map[string]any) ([]map[string]any, error) {
	f.finds = append(f.finds, method)
	if method == f.fail {
		return nil, fmt.Errorf("%s: down", method)
	}
	switch method {
	case "hbacrule_find":
		return capturedList("hbacrule-find-builtin"), nil
	case "hbacsvc_find":
		return capturedList("hbacsvc-find-builtin"), nil
	case "host_find":
		return capturedList("host-find-pkey-only"), nil
	case "hostgroup_find":
		return capturedList("hostgroup-find-pkey-only"), nil
	}
	return nil, fmt.Errorf("unexpected %s", method)
}

func (f *fakeHBACReader) Call(_ context.Context, cmd freeiparpc.Command) (json.RawMessage, error) {
	f.finds = append(f.finds, cmd.Method)
	if cmd.Method == "env" && f.fail == "env" {
		return nil, fmt.Errorf("env: down")
	}
	return f.env, nil
}

func capturedList(name string) []map[string]any {
	data, err := os.ReadFile(filepath.Join("..", "freeiparpc", "testdata", name+".json"))
	if err != nil {
		panic(err)
	}
	var env struct {
		Result struct {
			Result []map[string]any `json:"result"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		panic(err)
	}
	return env.Result.Result
}

func capturedResult(t *testing.T, name string) json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "freeiparpc", "testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	return env.Result
}

func TestObserveHBACReadsFiveThingsAndTheDomain(t *testing.T) {
	f := &fakeHBACReader{env: capturedResult(t, "env-domain")}
	obs, err := ObserveHBAC(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"hbacrule_find", "hbacsvc_find", "host_find", "hostgroup_find", "env"}; !slices.Equal(f.finds, want) {
		t.Errorf("reads = %v, want %v", f.finds, want)
	}
	if obs.Domain != "ipa.pilot.internal" || len(obs.Rules) < 2 || len(obs.Services) == 0 {
		t.Errorf("observation = %+v", obs)
	}
	if !slices.Contains(obs.Hosts, "p3acap-h1.ipa.pilot.internal") || !slices.Contains(obs.Hostgroups, "p3acap-hg1") {
		t.Errorf("hosts %v hostgroups %v", obs.Hosts, obs.Hostgroups)
	}
}

func TestObserveHBACFailsOnAnyFailedRead(t *testing.T) {
	for _, m := range []string{"hbacrule_find", "hbacsvc_find", "host_find", "hostgroup_find", "env"} {
		f := &fakeHBACReader{env: capturedResult(t, "env-domain"), fail: m}
		if _, err := ObserveHBAC(context.Background(), f); err == nil || !strings.Contains(err.Error(), "down") {
			t.Errorf("%s fails but the observation did not: %v", m, err)
		}
	}
	f := &fakeHBACReader{env: json.RawMessage(`{"result": {}}`)}
	if _, err := ObserveHBAC(context.Background(), f); err == nil {
		t.Error("an env answer with no domain was accepted")
	}
}

// ---- the plan ---------------------------------------------------------------

const lab = "ipa.pilot.internal"

func builtinRules() []LiveHBACRule {
	return []LiveHBACRule{
		{Name: "allow_all", Enabled: true, HostCategory: "all", ServiceCategory: "all", UserCategory: "all"},
		{Name: "allow_systemd-user", Enabled: true},
	}
}

func baseObs(rules ...LiveHBACRule) HBACObservation {
	return HBACObservation{
		Rules:      append(builtinRules(), rules...),
		Services:   []LiveHBACService{{Name: "sshd"}, {Name: "sudo"}},
		Hosts:      []string{"web1." + lab},
		Hostgroups: []string{"hg-a"},
		Domain:     lab,
	}
}

func hbacKinds(p HBACPlan) []string {
	var out []string
	for _, op := range p.Operations {
		out = append(out, op.Kind+":"+op.Object)
	}
	return out
}

func hbacFind(p HBACPlan, kind, object string) *Operation {
	for i := range p.Operations {
		if p.Operations[i].Kind == kind && p.Operations[i].Object == object {
			return &p.Operations[i]
		}
	}
	return nil
}

// convergedObs is what FreeIPA holds once the roster of hbacRosterDoc is reconciled.
func convergedObs() HBACObservation {
	obs := baseObs(
		LiveHBACRule{Name: "Login-Team", Enabled: true, Users: []string{"alice"}, Groups: []string{"team-a"},
			Hosts: []string{"web1." + lab}, Hostgroups: []string{"hg-a"}, Services: []string{"custom-svc", "sshd"}},
		LiveHBACRule{Name: "break-glass", Enabled: true, HostCategory: "all", Users: []string{"admin"}, Services: []string{"sshd"}},
		LiveHBACRule{Name: "parked", Enabled: false, HostCategory: "all", Users: []string{"alice"}, Services: []string{"sshd"}},
	)
	obs.Services = append(obs.Services, LiveHBACService{Name: "custom-svc"})
	return obs
}

func TestBuildHBACPlansNothingWhenFreeIPAHoldsTheRoster(t *testing.T) {
	p := BuildHBAC(HBACInput{Desired: hbacDesired(t, hbacRosterDoc), Obs: convergedObs()})
	if p.Writes() != 0 || len(p.Blocked) != 0 {
		t.Fatalf("ops %v blocked %v", hbacKinds(p), p.Blocked)
	}
	if len(p.Reports.UnmanagedRules) != 0 {
		t.Errorf("the built-in rules are reported as unmanaged: %v", p.Reports.UnmanagedRules)
	}
}

func TestBuildHBACCreatesWhatIsMissingInThePlaybooksOrder(t *testing.T) {
	obs := baseObs()
	p := BuildHBAC(HBACInput{Desired: hbacDesired(t, hbacRosterDoc), Obs: obs, Preview: true})
	if len(p.Blocked) != 0 {
		t.Fatalf("blocked: %v", p.Blocked)
	}
	want := []string{
		"hbac.service.create:custom-svc",
		"hbac.rule.create:login-team", "hbac.rule.create:break-glass", "hbac.rule.create:parked",
		"hbac.rule.member_hostgroup.add:login-team", "hbac.rule.member_host.add:login-team",
		"hbac.rule.member_service.add:login-team", "hbac.rule.member_service.add:break-glass", "hbac.rule.member_service.add:parked",
		"hbac.rule.member_user.add:login-team", "hbac.rule.member_user.add:break-glass", "hbac.rule.member_user.add:parked",
		"hbac.rule.member_group.add:login-team",
		"hbac.rule.disable:parked",
	}
	if got := hbacKinds(p); !slices.Equal(got, want) {
		t.Fatalf("plan:\n got %v\nwant %v", got, want)
	}
	create := hbacFind(p, KindHBACRuleCreate, "login-team")
	if create.Fields["name"].To != "Login-Team" || create.Fields["hostcategory"].To != nil && create.Fields["hostcategory"].To != "" {
		t.Errorf("the create carries the roster's spelling and no category for a rule with hosts: %+v", create.Fields)
	}
	if c := hbacFind(p, KindHBACRuleCreate, "break-glass"); c.Fields["hostcategory"].To != "all" {
		t.Errorf("a rule that names no host is created with hostcategory all: %+v", c.Fields)
	}
	svc := hbacFind(p, KindHBACServiceAdd, "login-team")
	if svc == nil || !slices.Contains(svc.DependsOn, "hbac.service.create:custom-svc") || !slices.Contains(svc.DependsOn, "hbac.rule.create:login-team") {
		t.Errorf("a service addition waits for the service and the rule it is added to: %+v", svc)
	}
	if !slices.Equal(hbacFind(p, KindHBACServiceAdd, "login-team").Members, []string{"custom-svc", "sshd"}) {
		t.Error("service members are not the roster's")
	}
	// Short host names are completed with the server's domain.
	if h := hbacFind(p, KindHBACHostAdd, "login-team"); !slices.Equal(h.Members, []string{"web1." + lab}) {
		t.Errorf("host members = %v", h.Members)
	}
	// The plan names only what the roster names: the built-in rules are not unmanaged.
	if len(p.Reports.UnmanagedRules) != 0 {
		t.Errorf("unmanaged = %v", p.Reports.UnmanagedRules)
	}
	for _, op := range p.Operations {
		if op.Destructive {
			t.Errorf("%s is destructive in a plan that only creates", op.ID)
		}
	}
}

func TestBuildHBACRemovesOnlyFromTheRuleThatNoLongerNamesIt(t *testing.T) {
	obs := convergedObs()
	for i := range obs.Rules {
		switch obs.Rules[i].Name {
		case "Login-Team":
			// FreeIPA has a user, a group, a host, a hostgroup and a service the roster
			// does not name for this rule.
			obs.Rules[i].Users = []string{"alice", "bob"}
			obs.Rules[i].Groups = []string{"team-a", "team-z"}
			obs.Rules[i].Hosts = []string{"web1." + lab, "db1." + lab}
			obs.Rules[i].Hostgroups = []string{"hg-a", "hg-z"}
			obs.Rules[i].Services = []string{"custom-svc", "sshd", "sudo"}
		case "break-glass":
			// Another rule keeps its members; nothing is removed from it.
			obs.Rules[i].Users = []string{"admin"}
		}
	}
	p := BuildHBAC(HBACInput{Desired: hbacDesired(t, hbacRosterDoc), Obs: obs})
	want := []string{
		"hbac.rule.member_host.remove:login-team", "hbac.rule.member_hostgroup.remove:login-team",
		"hbac.rule.member_service.remove:login-team", "hbac.rule.member_user.remove:login-team",
		"hbac.rule.member_group.remove:login-team",
	}
	if got := hbacKinds(p); !slices.Equal(got, want) {
		t.Fatalf("plan:\n got %v\nwant %v", got, want)
	}
	for _, op := range p.Operations {
		if !op.Destructive {
			t.Errorf("%s is a removal and is not marked destructive", op.ID)
		}
	}
	if m := hbacFind(p, KindHBACHostRemove, "login-team").Members; !slices.Equal(m, []string{"db1." + lab}) {
		t.Errorf("host removal = %v", m)
	}
}

func TestBuildHBACMovesACategoryBetweenRemovalAndAddition(t *testing.T) {
	// hostcat all -> hosts: the category is cleared before the hosts are added.
	obs := convergedObs()
	for i := range obs.Rules {
		if obs.Rules[i].Name == "Login-Team" {
			obs.Rules[i].HostCategory = "all"
			obs.Rules[i].Hosts, obs.Rules[i].Hostgroups = nil, nil
		}
	}
	p := BuildHBAC(HBACInput{Desired: hbacDesired(t, hbacRosterDoc), Obs: obs})
	got := hbacKinds(p)
	cat, add := slices.Index(got, "hbac.rule.category.update:login-team"), slices.Index(got, "hbac.rule.member_host.add:login-team")
	if cat < 0 || add < 0 || cat > add {
		t.Fatalf("plan %v: the category must be cleared before a host is added", got)
	}
	if c := hbacFind(p, KindHBACCategoryUpdate, "login-team").Fields["hostcategory"]; c.From != "all" || c.To != "" {
		t.Errorf("category change = %+v", c)
	}

	// hosts -> hostcat all: the hosts are removed before the category is set.
	obs = convergedObs()
	for i := range obs.Rules {
		if obs.Rules[i].Name == "break-glass" {
			obs.Rules[i].HostCategory = ""
			obs.Rules[i].Hosts = []string{"web1." + lab}
		}
	}
	got = hbacKinds(BuildHBAC(HBACInput{Desired: hbacDesired(t, hbacRosterDoc), Obs: obs}))
	rm, set := slices.Index(got, "hbac.rule.member_host.remove:break-glass"), slices.Index(got, "hbac.rule.category.update:break-glass")
	if rm < 0 || set < 0 || rm > set {
		t.Fatalf("plan %v: the hosts must go before the category is set", got)
	}

	// A service category that the roster rule (which names services) does not have is cleared.
	obs = convergedObs()
	for i := range obs.Rules {
		if obs.Rules[i].Name == "parked" {
			obs.Rules[i].ServiceCategory = "all"
		}
	}
	p = BuildHBAC(HBACInput{Desired: hbacDesired(t, hbacRosterDoc), Obs: obs})
	if c := hbacFind(p, KindHBACCategoryUpdate, "parked"); c == nil || c.Fields["servicecategory"].To != "" {
		t.Errorf("the service category is not cleared: %v", hbacKinds(p))
	}
}

func TestBuildHBACEnablesAndDisablesOnlyOnADifferentState(t *testing.T) {
	obs := convergedObs()
	for i := range obs.Rules {
		switch obs.Rules[i].Name {
		case "parked":
			obs.Rules[i].Enabled = true
		case "break-glass":
			obs.Rules[i].Enabled = false
		}
	}
	got := hbacKinds(BuildHBAC(HBACInput{Desired: hbacDesired(t, hbacRosterDoc), Obs: obs}))
	want := []string{"hbac.rule.enable:break-glass", "hbac.rule.disable:parked"}
	if !slices.Equal(got, want) {
		t.Fatalf("plan %v, want %v", got, want)
	}
}

func TestBuildHBACDeletesAnAbsentRuleOnlyIfItExists(t *testing.T) {
	obs := convergedObs()
	if got := hbacKinds(BuildHBAC(HBACInput{Desired: hbacDesired(t, hbacRosterDoc), Obs: obs})); len(got) != 0 {
		t.Fatalf("a rule that is already gone is planned: %v", got)
	}
	obs.Rules = append(obs.Rules, LiveHBACRule{Name: "Old-Rule", Enabled: true, HostCategory: "all"})
	p := BuildHBAC(HBACInput{Desired: hbacDesired(t, hbacRosterDoc), Obs: obs})
	if op := hbacFind(p, KindHBACRuleDelete, "old-rule"); op == nil || !op.Destructive || len(p.Operations) != 1 {
		t.Fatalf("plan %v", hbacKinds(p))
	}
}

func TestBuildHBACReportsTheRulesItDoesNotManageAndLeavesThemAlone(t *testing.T) {
	obs := convergedObs()
	obs.Rules = append(obs.Rules, LiveHBACRule{Name: "by-hand", Enabled: true, HostCategory: "all", Users: []string{"bob"}})
	p := BuildHBAC(HBACInput{Desired: hbacDesired(t, hbacRosterDoc), Obs: obs})
	if p.Writes() != 0 || !slices.Equal(p.Reports.UnmanagedRules, []string{"by-hand"}) {
		t.Fatalf("ops %v unmanaged %v", hbacKinds(p), p.Reports.UnmanagedRules)
	}
}

func TestBuildHBACRuleNamesAreNotCaseSensitive(t *testing.T) {
	// FreeIPA keeps the spelling a rule was created with (K7): a rule that exists as
	// LOGIN-team is the roster's Login-Team, and is not created again.
	obs := convergedObs()
	for i := range obs.Rules {
		if obs.Rules[i].Name == "Login-Team" {
			obs.Rules[i].Name = "LOGIN-team"
		}
	}
	if p := BuildHBAC(HBACInput{Desired: hbacDesired(t, hbacRosterDoc), Obs: obs}); p.Writes() != 0 || len(p.Blocked) != 0 {
		t.Fatalf("plan %v blocked %v", hbacKinds(p), p.Blocked)
	}
	// Two roster rules that differ only in case are one rule to FreeIPA.
	doc := strings.Replace(hbacRosterDoc, "name: parked", "name: LOGIN-TEAM", 1)
	p := BuildHBAC(HBACInput{Desired: hbacDesired(t, doc), Obs: convergedObs()})
	if len(p.Blocked) != 1 || p.Blocked[0].Reason != BlockedCaseCollision || p.Blocked[0].Object != "login-team" {
		t.Fatalf("blocked = %+v", p.Blocked)
	}
	if hbacFind(p, KindHBACRuleCreate, "login-team") != nil || hbacFind(p, KindHBACRuleEnable, "login-team") != nil {
		t.Errorf("a blocked rule has operations: %v", hbacKinds(p))
	}
	// The same spelling twice is a duplicate, not a case collision.
	dup := strings.Replace(hbacRosterDoc, "name: parked", "name: Login-Team", 1)
	if p := BuildHBAC(HBACInput{Desired: hbacDesired(t, dup), Obs: convergedObs()}); len(p.Blocked) != 1 || p.Blocked[0].Reason != BlockedDuplicateRule {
		t.Fatalf("blocked = %+v", p.Blocked)
	}
}

func TestBuildHBACBlocksReferencesThatCannotBeUsed(t *testing.T) {
	// The hostgroup and the service are declared in the roster but FreeIPA does not
	// have them: a preview assumes the playbook phase creates them, an apply (which
	// runs after it) refuses.
	obs := convergedObs()
	obs.Hostgroups = nil
	obs.Services = []LiveHBACService{{Name: "sshd"}}
	desired := hbacDesired(t, hbacRosterDoc)
	if p := BuildHBAC(HBACInput{Desired: desired, Obs: obs, Preview: true}); len(p.Blocked) != 0 {
		t.Fatalf("preview blocked: %v", p.Blocked)
	}
	p := BuildHBAC(HBACInput{Desired: desired, Obs: obs})
	if len(p.Blocked) != 1 || p.Blocked[0].Reason != BlockedHBACReference || p.Blocked[0].Object != "Login-Team" ||
		!strings.Contains(p.Blocked[0].Detail, "hg-a") || !strings.Contains(p.Blocked[0].Detail, hbacDetailAfterPlaybook) {
		t.Fatalf("blocked = %+v", p.Blocked)
	}
	for _, op := range p.Operations {
		if strings.HasSuffix(op.Object, "login-team") {
			t.Errorf("a blocked rule has %s", op.ID)
		}
	}

	// A host that is neither in FreeIPA nor in the roster is blocked in a preview too.
	doc := strings.Replace(hbacRosterDoc, "hosts: [web1]", "hosts: [web1, ghost]", 1)
	p = BuildHBAC(HBACInput{Desired: hbacDesired(t, doc), Obs: convergedObs(), Preview: true})
	if len(p.Blocked) != 1 || !strings.Contains(p.Blocked[0].Detail, "ghost."+lab) || !strings.Contains(p.Blocked[0].Detail, hbacDetailNotDeclaredHere) {
		t.Fatalf("blocked = %+v", p.Blocked)
	}

	// A user the roster marks absent is not blocked (spec Q1): the server answers.
	doc = strings.Replace(hbacRosterDoc, "subjects: {users: [alice], groups: [team-a]}", "subjects: {users: [alice, dave], groups: [team-a]}", 1)
	if p := BuildHBAC(HBACInput{Desired: hbacDesired(t, doc), Obs: convergedObs()}); len(p.Blocked) != 0 || hbacFind(p, KindHBACUserAdd, "login-team") == nil {
		t.Fatalf("plan %v blocked %v", hbacKinds(p), p.Blocked)
	}
}

func TestBuildHBACRefusesAllowAllAsAbsentAndAUserCategory(t *testing.T) {
	// The roster validator refuses allow_all as absent before a plan is made; the plan
	// refuses it too, for a desired state that did not come through the validator.
	if _, err := HBACFromRoster(roster(t, strings.Replace(hbacRosterDoc, "name: old-rule", "name: allow_all", 1))); err == nil {
		t.Fatal("the roster validator lets allow_all be marked absent")
	}
	d := hbacDesired(t, hbacRosterDoc)
	d.AbsentRules = append(d.AbsentRules, "allow_all")
	p := BuildHBAC(HBACInput{Desired: d, Obs: convergedObs()})
	if len(p.Blocked) != 1 || p.Blocked[0].Reason != BlockedAllowAllDelete {
		t.Fatalf("blocked = %+v", p.Blocked)
	}
	if hbacFind(p, KindHBACRuleDelete, "allow_all") != nil {
		t.Error("allow_all is deleted")
	}

	obs := convergedObs()
	for i := range obs.Rules {
		if obs.Rules[i].Name == "parked" {
			obs.Rules[i].UserCategory = "all"
		}
	}
	p = BuildHBAC(HBACInput{Desired: hbacDesired(t, hbacRosterDoc), Obs: obs})
	if len(p.Blocked) != 1 || p.Blocked[0].Reason != BlockedUserCategoryAll || p.Blocked[0].Object != "parked" {
		t.Fatalf("blocked = %+v", p.Blocked)
	}
}

func TestBuildHBACLockdown(t *testing.T) {
	doc := strings.Replace(hbacRosterDoc, "hbac:\n", "hbac:\n  disable_allow_all: true\n", 1)
	p := BuildHBAC(HBACInput{Desired: hbacDesired(t, doc), Obs: convergedObs()})
	if got := hbacKinds(p); !slices.Equal(got, []string{"hbac.allow_all.disable:allow_all"}) {
		t.Fatalf("plan %v", got)
	}
	// allow_all already disabled: nothing to do.
	obs := convergedObs()
	obs.Rules[0].Enabled = false
	if p := BuildHBAC(HBACInput{Desired: hbacDesired(t, doc), Obs: obs}); p.Writes() != 0 {
		t.Fatalf("plan %v", hbacKinds(p))
	}
	// Without an enabled rule for admin on every host the lockdown is refused (the
	// roster validator refuses such a roster first; the plan does not rely on it), and so
	// is a break-glass rule that is itself blocked.
	if _, err := HBACFromRoster(roster(t, strings.Replace(doc, "subjects: {users: [admin]}", "subjects: {users: [alice]}", 1))); err == nil {
		t.Fatal("the roster validator lets disable_allow_all through with no break-glass rule")
	}
	for name, mutate := range map[string]func(*DesiredHBAC){
		"no admin subject": func(d *DesiredHBAC) { d.Rules[1].Users = []string{"alice"} },
		"disabled":         func(d *DesiredHBAC) { d.Rules[1].Enabled = false },
		"not every host":   func(d *DesiredHBAC) { d.Rules[1].HostCategory = ""; d.Rules[1].Hostgroups = []string{"hg-a"} },
		"blocked":          func(d *DesiredHBAC) { d.Rules[1].Services = []string{"no-such-service"} },
	} {
		d := hbacDesired(t, doc)
		mutate(&d)
		p := BuildHBAC(HBACInput{Desired: d, Obs: convergedObs()})
		found := false
		for _, b := range p.Blocked {
			found = found || b.Reason == BlockedLockdownNoBreakGlass
		}
		if !found || hbacFind(p, KindHBACAllowAllDisable, "allow_all") != nil {
			t.Errorf("%s: plan %v blocked %+v", name, hbacKinds(p), p.Blocked)
		}
	}
	// Not asked for: allow_all is left as it is, enabled.
	if p := BuildHBAC(HBACInput{Desired: hbacDesired(t, hbacRosterDoc), Obs: convergedObs()}); hbacFind(p, KindHBACAllowAllDisable, "allow_all") != nil {
		t.Error("allow_all is disabled without hbac.disable_allow_all")
	}
}

func TestBuildHBACOperationsAreInKindOrderAndHaveUniqueIDs(t *testing.T) {
	p := BuildHBAC(HBACInput{Desired: hbacDesired(t, hbacRosterDoc), Obs: baseObs(), Preview: true})
	seen := map[string]bool{}
	last := -1
	for _, op := range p.Operations {
		if seen[op.ID] {
			t.Errorf("%s twice", op.ID)
		}
		seen[op.ID] = true
		i := slices.Index(HBACKinds, op.Kind)
		if i < 0 || i < last {
			t.Errorf("%s is out of the kind order", op.ID)
		}
		last = i
	}
}
