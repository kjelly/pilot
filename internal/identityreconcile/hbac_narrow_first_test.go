package identityreconcile

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/freeiparpc"
)

// The ordering invariant of the HBAC writer (spec §4.3): a rule the roster wants disabled
// is never enabled while it holds members the writer added, and a rule the roster wants
// enabled is enabled only after it holds all of its members. The oracle is the server: the
// state of the rule when each command arrives and when the run ends, whichever write the
// run stopped at.

// holdsMembers says whether the rule has any member.
func (r *hRule) holdsMembers() bool {
	return len(r.users)+len(r.groups)+len(r.hosts)+len(r.hostgroups)+len(r.services) > 0
}

// wantsAll says whether the rule holds every member the roster rule names (hosts as FQDN).
func (r *hRule) wantsAll(want DesiredHBACRule, domain string) bool {
	has := func(m map[string]bool, names []string, f func(string) string) bool {
		for _, n := range names {
			if !m[f(n)] {
				return false
			}
		}
		return true
	}
	id := func(s string) string { return lower(s) }
	return has(r.users, want.Users, id) && has(r.groups, want.Groups, id) &&
		has(r.hostgroups, want.Hostgroups, id) && has(r.services, want.Services, id) &&
		has(r.hosts, want.Hosts, func(s string) string { return completeHost(s, domain) })
}

// widening says whether a command can widen the access of the rule it names.
func widening(method string) bool {
	switch method {
	case "hbacrule_add_host", "hbacrule_add_service", "hbacrule_add_user", "hbacrule_mod":
		return true
	}
	return false
}

// invariantWatch records a violation at the moment a command arrives: a command that can
// widen a rule the roster wants disabled while the server holds it enabled, and the enable
// of a rule that does not yet hold the members the roster names for it.
func invariantWatch(e *hbacEnv, violations *[]string) {
	prev := e.f.intercept
	e.f.intercept = func(f *fakeHBAC, c call) (json.RawMessage, error, bool) {
		if len(c.args) > 0 {
			name, _ := c.args[0].(string)
			rule := f.rules[lower(name)]
			want, declared := declaredRule(e, name)
			switch {
			case rule == nil || !declared:
			case widening(c.method) && !want.Enabled && rule.enabled:
				*violations = append(*violations, fmt.Sprintf("%s on %s while it is enabled and the roster says disabled", c.method, name))
			case c.method == "hbacrule_enable" && want.Enabled && !rule.wantsAll(want, f.domain):
				*violations = append(*violations, fmt.Sprintf("hbacrule_enable on %s before it holds its members", name))
			}
		}
		if prev != nil {
			return prev(f, c)
		}
		return nil, nil, false
	}
}

func declaredRule(e *hbacEnv, name string) (DesiredHBACRule, bool) {
	for _, d := range e.opts.Desired.Rules {
		if lower(d.Name) == lower(name) {
			return d, true
		}
	}
	return DesiredHBACRule{}, false
}

// afterRunViolations is what the server holds when the run has ended, whatever it ended as.
func afterRunViolations(e *hbacEnv, wasDisabled map[string]bool) []string {
	var out []string
	for _, d := range e.opts.Desired.Rules {
		r := e.f.ruleNamed(d.Name)
		switch {
		case r == nil:
		case !d.Enabled && r.enabled && r.holdsMembers():
			out = append(out, fmt.Sprintf("%s is enabled with members and the roster says disabled", d.Name))
		case d.Enabled && wasDisabled[lower(d.Name)] && r.enabled && !r.wantsAll(d, e.f.domain):
			out = append(out, fmt.Sprintf("%s was enabled before it holds its members", d.Name))
		}
	}
	return out
}

// writeCount is the number of write commands a clean run sends.
func writeCount(t *testing.T, setup func(*fakeHBAC)) int {
	t.Helper()
	e := newHBACEnv(t, hbacRosterDoc, setup)
	e.mustApply()
	return len(e.f.writes())
}

// A server whose rule the roster wants disabled is enabled and has none of its members;
// and one the roster wants enabled is disabled and has none of its members.
func widenedServer(f *fakeHBAC) {
	f.converged()
	parked := f.ruleNamed("parked")
	parked.enabled = true
	parked.users, parked.services = map[string]bool{}, map[string]bool{}
	lt := f.ruleNamed("Login-Team")
	lt.enabled = false
	lt.users, lt.groups, lt.hosts, lt.hostgroups = map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	bg := f.ruleNamed("break-glass")
	bg.enabled = false
	bg.users = map[string]bool{}
}

func TestExecuteHBACNeverWidensARuleTheRosterWantsDisabledAndEnablesLast(t *testing.T) {
	for name, setup := range map[string]func(*fakeHBAC){
		"a fresh server: parked is created":             nil,
		"parked is enabled and has none of its members": widenedServer,
	} {
		n := writeCount(t, setup)
		if n < 5 {
			t.Fatalf("%s: a clean run sends %d writes", name, n)
		}
		// Stop the run at every write in turn, with a refusal and with an outcome that is
		// not known, and look at the server.
		for k := 1; k <= n; k++ {
			for _, unknown := range []bool{false, true} {
				label := fmt.Sprintf("%s: write %d of %d, unknown=%v", name, k, n, unknown)
				e := newHBACEnv(t, hbacRosterDoc, setup)
				wasDisabled := map[string]bool{}
				// What the server looks like before the run (setup has run).
				for _, d := range e.opts.Desired.Rules {
					if r := e.f.ruleNamed(d.Name); r != nil && !r.enabled {
						wasDisabled[lower(d.Name)] = true
					}
				}
				var violations []string
				seen := 0
				e.f.intercept = func(f *fakeHBAC, c call) (json.RawMessage, error, bool) {
					if !hbacIsWrite(c.method) {
						return nil, nil, false
					}
					seen++
					if seen != k {
						return nil, nil, false
					}
					if unknown {
						return nil, &freeiparpc.OutcomeUnknownError{Method: c.method, Err: errors.New("connection lost")}, true
					}
					return nil, f.errFixture("hbacrule-add-service-while-servicecat-all"), true
				}
				invariantWatch(e, &violations)
				res, err := e.execute()
				if err == nil || res.Stop == nil {
					t.Fatalf("%s: the run did not stop (%v)", label, err)
				}
				violations = append(violations, afterRunViolations(e, wasDisabled)...)
				if len(violations) > 0 {
					t.Errorf("%s: %s", label, strings.Join(violations, "; "))
				}
			}
		}
		// A run that ends well: parked is disabled with its members, the enabled rules are
		// enabled with theirs, and the enables are the last writes of the run.
		e := newHBACEnv(t, hbacRosterDoc, setup)
		var violations []string
		invariantWatch(e, &violations)
		e.mustApply()
		e.mustBeConverged()
		if len(violations) > 0 {
			t.Errorf("%s: %s", name, strings.Join(violations, "; "))
		}
		methods := e.writeMethods()
		firstEnable := slices.Index(methods, "hbacrule_enable")
		for i, m := range methods {
			if firstEnable >= 0 && i > firstEnable && (strings.HasPrefix(m, "hbacrule_add_") || m == "hbacrule_mod" || strings.HasPrefix(m, "hbacrule_remove_") || m == "hbacrule_disable") {
				t.Errorf("%s: %s at %d after the first enable at %d: %v", name, m, i, firstEnable, methods)
			}
		}
		if name != "a fresh server: parked is created" && !slices.Contains(methods, "hbacrule_enable") {
			t.Errorf("%s: no enable was sent: %v", name, methods)
		}
	}
}

// A rule created disabled by this run is disabled before anything is added to it, and a rule
// that is enabled now is disabled before its members are added.
func TestExecuteHBACDisablesBeforeTheFirstMemberIsAdded(t *testing.T) {
	for name, setup := range map[string]func(*fakeHBAC){
		"new rule":      nil,
		"existing rule": widenedServer,
	} {
		e := newHBACEnv(t, hbacRosterDoc, setup)
		e.mustApply()
		disable, firstAdd := -1, -1
		for i, c := range e.f.writes() {
			if len(c.args) == 0 || c.args[0] != "parked" {
				continue
			}
			if c.method == "hbacrule_disable" {
				disable = i
			}
			if strings.HasPrefix(c.method, "hbacrule_add_") && firstAdd < 0 {
				firstAdd = i
			}
		}
		if disable < 0 || firstAdd < 0 || disable > firstAdd {
			t.Errorf("%s: disable at write %d, first add at %d: %v", name, disable, firstAdd, e.writeMethods())
		}
		if p := e.f.ruleNamed("parked"); p.enabled || !p.users["alice"] || !p.services["sshd"] {
			t.Errorf("%s: parked ended %+v", name, p)
		}
	}
}

// ---- the plan -----------------------------------------------------------------

func TestBuildHBACOrdersDisableBeforeWideningAndEnableAfterIt(t *testing.T) {
	obs := convergedObs()
	for i := range obs.Rules {
		switch obs.Rules[i].Name {
		case "parked": // enabled, the roster says disabled; it has lost its members
			obs.Rules[i].Enabled = true
			obs.Rules[i].Users, obs.Rules[i].Services = nil, nil
		case "break-glass": // disabled, the roster says enabled; it has lost its members
			obs.Rules[i].Enabled = false
			obs.Rules[i].Users = nil
		}
	}
	p := BuildHBAC(HBACInput{Desired: hbacDesired(t, hbacRosterDoc), Obs: obs})
	if len(p.Blocked) != 0 {
		t.Fatalf("blocked %v", p.Blocked)
	}
	index := func(kind, obj string) int {
		for i, op := range p.Operations {
			if op.Kind == kind && op.Object == obj {
				return i
			}
		}
		t.Fatalf("no %s %s in %v", kind, obj, hbacKinds(p))
		return -1
	}
	disable := index(KindHBACRuleDisable, "parked")
	for _, k := range []string{KindHBACServiceAdd, KindHBACUserAdd} {
		add := index(k, "parked")
		if disable > add {
			t.Errorf("%s of parked is planned before its disable: %v", k, hbacKinds(p))
		}
		if !slices.Contains(p.Operations[add].DependsOn, p.Operations[disable].ID) {
			t.Errorf("%s of parked does not depend on its disable: %v", k, p.Operations[add].DependsOn)
		}
	}
	enable := index(KindHBACRuleEnable, "break-glass")
	userAdd := index(KindHBACUserAdd, "break-glass")
	if enable < userAdd || !slices.Contains(p.Operations[enable].DependsOn, p.Operations[userAdd].ID) {
		t.Errorf("the enable of break-glass is not after its member additions: %v %v", hbacKinds(p), p.Operations[enable].DependsOn)
	}
	// Every operation of the plan runs in a stage no earlier than the operations it depends on.
	stageOf := map[string]HBACStage{}
	for _, op := range p.Operations {
		stageOf[op.ID] = HBACStageOf(op.Kind)
	}
	for _, op := range p.Operations {
		for _, d := range op.DependsOn {
			if s, ok := stageOf[d]; ok && s > HBACStageOf(op.Kind) {
				t.Errorf("%s (%s) depends on %s, which runs later (%s)", op.ID, HBACStageOf(op.Kind), d, s)
			}
		}
	}
}

func TestHBACStagesNarrowBeforeTheyWidenAndEnableLast(t *testing.T) {
	if !(HBACStageOf(KindHBACRuleDisable) < HBACStageOf(KindHBACCategoryUpdate) &&
		HBACStageOf(KindHBACRuleDisable) < HBACStageOf(KindHBACUserAdd) &&
		HBACStageOf(KindHBACRuleDisable) > HBACStageOf(KindHBACRuleCreate)) {
		t.Errorf("disable runs in %s, creates in %s, categories in %s, additions in %s",
			HBACStageOf(KindHBACRuleDisable), HBACStageOf(KindHBACRuleCreate), HBACStageOf(KindHBACCategoryUpdate), HBACStageOf(KindHBACUserAdd))
	}
	for _, k := range []string{KindHBACHostAdd, KindHBACServiceAdd, KindHBACUserAdd, KindHBACGroupAdd, KindHBACHostgroupAdd, KindHBACCategoryUpdate} {
		if HBACStageOf(KindHBACRuleEnable) <= HBACStageOf(k) {
			t.Errorf("enable runs in %s, %s in %s", HBACStageOf(KindHBACRuleEnable), k, HBACStageOf(k))
		}
	}
	if HBACStageOf(KindHBACRuleEnable) >= HBACStageOf(KindHBACRuleDelete) {
		t.Error("the enable runs after the deletes")
	}
}
