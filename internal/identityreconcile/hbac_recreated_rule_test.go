package identityreconcile

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// A rule deleted and created again under the same name is not the rule the plan observed:
// it has another ipauniqueid. Every operation that narrows access (a disable and the five
// removals of H3, the delete of H7) is checked against it before it is sent, and the
// identity is checked before anything that would settle the operation as a noop. The
// control of every row is the same rule with the same ipauniqueid, which is sent.

const recreatedUUID = "00000000-0000-0000-0000-777777777777"

// narrowingCase is one operation kind: what is put on the converged server so that the
// plan has the operation, the operation, and the write that carries it out.
type narrowingCase struct {
	name  string
	setup func(f *fakeHBAC)
	op    string // the operation id
	write string // the write method of the operation
	rule  string // the rule the operation is on
}

func narrowingCases() []narrowingCase {
	onLogin := func(f *fakeHBAC) *hRule { return f.ruleNamed("Login-Team") }
	return []narrowingCase{
		{"host removal", func(f *fakeHBAC) { f.hosts["web2."+lab] = true; onLogin(f).hosts["web2."+lab] = true },
			"hbac.rule.member_host.remove:login-team", "hbacrule_remove_host", "Login-Team"},
		{"hostgroup removal", func(f *fakeHBAC) { f.hostgroups["hg-b"] = true; onLogin(f).hostgroups["hg-b"] = true },
			"hbac.rule.member_hostgroup.remove:login-team", "hbacrule_remove_host", "Login-Team"},
		{"service removal", func(f *fakeHBAC) { f.services["extra-svc"] = "extra-svc"; onLogin(f).services["extra-svc"] = true },
			"hbac.rule.member_service.remove:login-team", "hbacrule_remove_service", "Login-Team"},
		{"user removal", func(f *fakeHBAC) { f.users["bob"] = true; onLogin(f).users["bob"] = true },
			"hbac.rule.member_user.remove:login-team", "hbacrule_remove_user", "Login-Team"},
		{"group removal", func(f *fakeHBAC) { f.groups["team-b"] = true; onLogin(f).groups["team-b"] = true },
			"hbac.rule.member_group.remove:login-team", "hbacrule_remove_user", "Login-Team"},
		{"disable", func(f *fakeHBAC) { f.ruleNamed("parked").enabled = true },
			"hbac.rule.disable:parked", "hbacrule_disable", "parked"},
		{"delete", func(f *fakeHBAC) { f.newRule("Old-Rule").hostCat = "all" },
			"hbac.rule.delete:old-rule", "hbacrule_del", "old-rule"},
	}
}

func hasWrite(f *fakeHBAC, method string) bool {
	for _, c := range f.writes() {
		if c.method == method {
			return true
		}
	}
	return false
}

func TestExecuteHBACRecreatedRuleIsAConflictForEveryNarrowingKind(t *testing.T) {
	for _, tc := range narrowingCases() {
		// Control: the rule is the plan's, so the operation goes out.
		e := newHBACEnv(t, hbacRosterDoc, func(f *fakeHBAC) { f.converged(); tc.setup(f) })
		res := e.mustApply()
		if o := res.op(tc.op); o.Outcome != OutcomeSuccess || !hasWrite(e.f, tc.write) {
			t.Errorf("%s, same ipauniqueid: outcome %+v, writes %v", tc.name, o, e.writeMethods())
		}

		// The rule is deleted and created again (the same members, another ipauniqueid)
		// after the second plan: nothing is sent for the operation, and it is the conflict
		// that stops the run at its stage.
		e = newHBACEnv(t, hbacRosterDoc, func(f *fakeHBAC) { f.converged(); tc.setup(f) })
		e.f.onFind = func(f *fakeHBAC, n int) {
			if n == 3 {
				f.ruleNamed(tc.rule).uuid = recreatedUUID
			}
		}
		res, err := e.execute()
		stage := res.op(tc.op).Stage
		if !errors.Is(err, ErrWrites) || res.Stop == nil || res.Stop.Stage != stage {
			t.Errorf("%s, recreated: err %v stop %v\n%s", tc.name, err, res.Stop, describeHBACOps(res))
			continue
		}
		if o := res.op(tc.op); o.Outcome != OutcomeConflictFailed || !strings.Contains(o.Detail, "deleted and created again") {
			t.Errorf("%s, recreated: outcome %+v", tc.name, o)
		}
		if hasWrite(e.f, tc.write) {
			t.Errorf("%s, recreated: %s was sent to a rule that is not the plan's (writes %v)", tc.name, tc.write, e.writeMethods())
		}
	}
}

func TestExecuteHBACRecreatedRuleIsNotSettledAsANoop(t *testing.T) {
	// The rule is recreated and is already as the operation wants it: a rule that is not
	// the plan's one is a conflict, not "nothing to do".
	rows := []struct {
		name  string
		setup func(f *fakeHBAC)
		act   func(f *fakeHBAC) // what the other writer does at the re-read
		op    string
		rule  string
	}{
		{"disabled", func(f *fakeHBAC) { f.ruleNamed("parked").enabled = true },
			func(f *fakeHBAC) { r := f.ruleNamed("parked"); r.uuid, r.enabled = recreatedUUID, false },
			"hbac.rule.disable:parked", "parked"},
		{"the member has left", func(f *fakeHBAC) { f.users["bob"] = true; f.ruleNamed("Login-Team").users["bob"] = true },
			func(f *fakeHBAC) { r := f.ruleNamed("Login-Team"); r.uuid = recreatedUUID; delete(r.users, "bob") },
			"hbac.rule.member_user.remove:login-team", "Login-Team"},
	}
	for _, tc := range rows {
		// The same rule (same ipauniqueid) in the same state is a noop, as it always was.
		e := newHBACEnv(t, hbacRosterDoc, func(f *fakeHBAC) { f.converged(); tc.setup(f) })
		e.f.onFind = func(f *fakeHBAC, n int) {
			if n == 3 {
				r := f.ruleNamed(tc.rule)
				uuid := r.uuid
				tc.act(f)
				r.uuid = uuid
			}
		}
		if o := e.mustApply().op(tc.op); o.Outcome != OutcomeNoop {
			t.Errorf("%s, same ipauniqueid: outcome %+v", tc.name, o)
		}

		e = newHBACEnv(t, hbacRosterDoc, func(f *fakeHBAC) { f.converged(); tc.setup(f) })
		e.f.onFind = func(f *fakeHBAC, n int) {
			if n == 3 {
				tc.act(f)
			}
		}
		res, err := e.execute()
		if !errors.Is(err, ErrWrites) || res.Stop == nil || res.Stop.Stage != "H3" {
			t.Errorf("%s, recreated: err %v stop %v\n%s", tc.name, err, res.Stop, describeHBACOps(res))
			continue
		}
		if o := res.op(tc.op); o.Outcome != OutcomeConflictFailed {
			t.Errorf("%s, recreated: outcome %+v", tc.name, o)
		}
	}
}

func TestExecuteHBACARuleWithoutAnIpauniqueidIsNotTheRuleOfThePlan(t *testing.T) {
	// A server that does not return ipauniqueid cannot show that the rule is the plan's, so
	// nothing that narrows access is sent to an observed rule.
	for _, tc := range narrowingCases() {
		e := newHBACEnv(t, hbacRosterDoc, func(f *fakeHBAC) { f.converged(); tc.setup(f); f.noUniqueID = true })
		res, err := e.execute()
		stage := res.op(tc.op).Stage
		if !errors.Is(err, ErrWrites) || res.Stop == nil || res.Stop.Stage != stage {
			t.Errorf("%s: err %v stop %v\n%s", tc.name, err, res.Stop, describeHBACOps(res))
			continue
		}
		if o := res.op(tc.op); o.Outcome != OutcomeConflictFailed || !strings.Contains(o.Detail, "ipauniqueid") {
			t.Errorf("%s: outcome %+v", tc.name, o)
		}
		if hasWrite(e.f, tc.write) {
			t.Errorf("%s: %s was sent (writes %v)", tc.name, tc.write, e.writeMethods())
		}
	}

	// A rule this run created has no earlier observation: it is still disabled, with or
	// without an ipauniqueid.
	e := newHBACEnv(t, hbacRosterDoc, func(f *fakeHBAC) { f.noUniqueID = true })
	res := e.mustApply()
	if o := res.op("hbac.rule.create:parked"); o.Outcome != OutcomeSuccess {
		t.Fatalf("create outcome %+v\n%s", o, describeHBACOps(res))
	}
	if o := res.op("hbac.rule.disable:parked"); o.Outcome != OutcomeSuccess || e.f.ruleNamed("parked").enabled {
		t.Errorf("disable of a rule this run created: outcome %+v, enabled %v, writes %v", o, e.f.ruleNamed("parked").enabled, e.writeMethods())
	}
	if !slices.Contains(e.writeMethods(), "hbacrule_disable") {
		t.Errorf("writes %v", e.writeMethods())
	}
}

func TestHBACSameRuleFailsClosed(t *testing.T) {
	// sameRule is the check every narrowing operation goes through. What the plan did not
	// observe, or cannot tell apart by ipauniqueid, does not pass; only a rule this run
	// created is exempt (it has no earlier observation).
	r := &hbacRunner{
		obs2:    HBACObservation{Rules: []LiveHBACRule{{Name: "Seen", UniqueID: "u-1"}, {Name: "NoID"}}},
		created: map[string]bool{"made": true},
	}
	for _, tc := range []struct {
		name string
		live LiveHBACRule
		ok   bool
	}{
		{"seen", LiveHBACRule{Name: "Seen", UniqueID: "u-1"}, true},
		{"seen", LiveHBACRule{Name: "Seen", UniqueID: "u-2"}, false},
		{"seen", LiveHBACRule{Name: "Seen"}, false},
		{"noid", LiveHBACRule{Name: "NoID", UniqueID: "u-3"}, false},
		{"noid", LiveHBACRule{Name: "NoID"}, false},
		{"unseen", LiveHBACRule{Name: "Unseen", UniqueID: "u-4"}, false},
		{"made", LiveHBACRule{Name: "Made"}, true},
		{"made", LiveHBACRule{Name: "Made", UniqueID: "u-5"}, true},
	} {
		why := r.sameRule(tc.name, tc.live)
		if (why == "") != tc.ok {
			t.Errorf("sameRule(%q, %+v) = %q, want ok=%v", tc.name, tc.live, why, tc.ok)
		}
	}
}
