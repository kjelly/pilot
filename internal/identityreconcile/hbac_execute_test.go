package identityreconcile

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/freeiparpc"
	"github.com/kjelly/pilot/internal/identitylock"
	"github.com/kjelly/pilot/internal/identitylock/identitylocktest"
)

// converged makes the rules the roster of hbacRosterDoc describes exist on the fake, as a
// reconciled server holds them.
func (f *fakeHBAC) converged() *fakeHBAC {
	f.withRoster()
	f.services["custom-svc"] = "custom-svc"
	lt := f.newRule("Login-Team")
	lt.users["alice"], lt.groups["team-a"] = true, true
	lt.hosts["web1."+lab], lt.hostgroups["hg-a"] = true, true
	lt.services["custom-svc"], lt.services["sshd"] = true, true
	bg := f.newRule("break-glass")
	bg.hostCat = "all"
	bg.users["admin"], bg.services["sshd"] = true, true
	pk := f.newRule("parked")
	pk.enabled, pk.hostCat = false, "all"
	pk.users["alice"], pk.services["sshd"] = true, true
	return f
}

// hbacEnv is one HBAC run's parts, wired as the command layer wires them.
type hbacEnv struct {
	t       *testing.T
	f       *fakeHBAC
	lock    *identitylocktest.Fake
	held    *identitylock.Held
	ctx     context.Context
	gate    *Gate
	entry   *fakeEntry
	journal *fakeJournal
	opts    HBACOptions
}

// newHBACEnv builds the desired state from the roster document and the server from setup
// (a roster's objects only, by default).
func newHBACEnv(t *testing.T, doc string, setup func(*fakeHBAC)) *hbacEnv {
	t.Helper()
	e := &hbacEnv{t: t, f: newFakeHBAC(t).withRoster(), gate: NewGate(), journal: &fakeJournal{}}
	if setup != nil {
		setup(e.f)
	}
	e.lock = &identitylocktest.Fake{Host: "ipa-1"}
	held, err := e.lock.Acquirer()(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	e.held = held
	t.Cleanup(func() { _ = held.Release() })
	e.ctx = held.Attach(context.Background())
	e.entry = &fakeEntry{host: "ipa-1", fqdn: testFQDN}
	e.f.writeGate = e.gate.Check
	e.opts = HBACOptions{Desired: hbacDesired(t, doc), Entry: e.entry, Gate: e.gate, Journal: e.journal, TestHost: testFQDN}
	return e
}

func (e *hbacEnv) execute() (*HBACResult, error) {
	e.t.Helper()
	var res *HBACResult
	var err error
	mustReturn(returnDeadline, "ExecuteHBAC", func() { res, err = ExecuteHBAC(e.ctx, e.f, e.opts) })
	return res, err
}

func (e *hbacEnv) mustApply() *HBACResult {
	e.t.Helper()
	res, err := e.execute()
	if err != nil {
		e.t.Fatalf("ExecuteHBAC: %v\nops: %s", err, describeHBACOps(res))
	}
	return res
}

func describeHBACOps(res *HBACResult) string {
	if res == nil {
		return "<no result>"
	}
	var b strings.Builder
	for _, o := range res.Ops {
		b.WriteString("\n  " + o.Stage + " " + o.Operation.ID + " " + string(o.Final()) + " " + strings.TrimSpace(o.Error+" "+o.Detail))
	}
	if res.Stop != nil {
		b.WriteString("\n  stopped at " + res.Stop.Stage + ": " + res.Stop.Reason)
	}
	return b.String()
}

func (r *HBACResult) outcomeOf(id string) Outcome {
	for _, o := range r.Ops {
		if o.Operation.ID == id {
			return o.Final()
		}
	}
	return ""
}

func (r *HBACResult) op(id string) OpResult {
	for _, o := range r.Ops {
		if o.Operation.ID == id {
			return o
		}
	}
	return OpResult{}
}

// plannedNow is the plan against what the fake holds now, as a preview would make it.
func (e *hbacEnv) plannedNow() HBACPlan {
	e.t.Helper()
	obs, err := ObserveHBAC(context.Background(), e.f)
	if err != nil {
		e.t.Fatal(err)
	}
	return BuildHBAC(HBACInput{Desired: e.opts.Desired, Obs: obs})
}

func (e *hbacEnv) mustBeConverged() {
	e.t.Helper()
	if p := e.plannedNow(); p.Writes() != 0 || len(p.Blocked) != 0 {
		e.t.Fatalf("the server is not what the roster says: ops %v blocked %v", hbacKinds(p), p.Blocked)
	}
}

// writeMethods is the methods of the write commands the fake received, in order.
func (e *hbacEnv) writeMethods() []string {
	var out []string
	for _, c := range e.f.writes() {
		out = append(out, c.method)
	}
	return out
}

// journalOps is the operation ids each kind of event of the journal accounts for.
func (e *hbacEnv) journalOps() (resulted, notSent []string) {
	e.journal.mu.Lock()
	defer e.journal.mu.Unlock()
	for _, ev := range e.journal.events {
		switch p := ev.Payload.(type) {
		case hbacResultEvent:
			for _, o := range p.Results {
				resulted = append(resulted, o.Operation.ID)
			}
		case notSentEvent:
			for _, o := range p.Operations {
				notSent = append(notSent, o.Operation.ID)
			}
		}
	}
	return resulted, notSent
}

func TestExecuteHBACAppliesTheRosterInStageOrder(t *testing.T) {
	e := newHBACEnv(t, hbacRosterDoc, nil)
	res := e.mustApply()
	e.mustBeConverged()

	if !res.Verify.OK() || res.Stop != nil || res.Entry.Ran != true || res.Entry.Previous == nil || *res.Entry.Previous {
		t.Fatalf("verify %+v stop %v entry %+v", res.Verify, res.Stop, res.Entry)
	}
	if res.Plan2 == nil || res.Plan2.Writes() != res.Plan1.Writes() || res.Plan3 == nil || res.Plan3.Writes() != 0 {
		t.Fatalf("plans: %d, %v, %v", res.Plan1.Writes(), res.Plan2, res.Plan3)
	}
	for _, o := range res.Ops {
		if o.Final() != OutcomeSuccess {
			t.Errorf("%s ended %s (%s %s)", o.Operation.ID, o.Final(), o.Error, o.Detail)
		}
	}
	// One entry, before the first write; the gate is shut again when the run ends.
	if e.entry.prepared != 1 || e.entry.probed != 0 {
		t.Errorf("entry prepared %d probed %d", e.entry.prepared, e.entry.probed)
	}
	if err := e.gate.Check(e.ctx, "hbacrule_add"); err == nil {
		t.Error("the gate is still open after the run")
	}
	if o := res.Obligation(); !o.Owed || o.Source != ObligationThisRun {
		t.Errorf("obligation %+v", o)
	}
	if !res.Committed() {
		t.Error("a run that wrote is not committed")
	}

	// The writes go out in the order of the stages: services, rules, the disable of the
	// rule the roster wants disabled (before anything is added to it), (no removals), (no
	// category changes), additions, (no enables).
	want := []string{
		"hbacsvc_add",
		"hbacrule_add", "hbacrule_add", "hbacrule_add",
		"hbacrule_disable",
		"hbacrule_add_host", "hbacrule_add_host", "hbacrule_add_service", "hbacrule_add_service", "hbacrule_add_service",
		"hbacrule_add_user", "hbacrule_add_user", "hbacrule_add_user", "hbacrule_add_user",
	}
	if got := e.writeMethods(); !slices.Equal(got, want) {
		t.Fatalf("writes:\n got %v\nwant %v", got, want)
	}
	// What was sent is what the playbook sends: the rule as written, with only its category.
	var adds []call
	for _, c := range e.f.writes() {
		if c.method == "hbacrule_add" {
			adds = append(adds, c)
		}
	}
	if adds[0].args[0] != "Login-Team" || adds[0].opts != nil || adds[1].args[0] != "break-glass" || adds[1].opts["hostcategory"] != "all" || len(adds[1].opts) != 1 {
		t.Errorf("hbacrule_add calls: %+v", adds)
	}
	// A second run has nothing to do.
	again, err := ExecuteHBAC(e.ctx, e.f, e.opts)
	if err != nil || again.Plan1.Writes() != 0 || again.Entry.Ran {
		t.Fatalf("second run: %v %+v", err, again)
	}
}

func TestExecuteHBACIsIdleWhenFreeIPAHoldsTheRoster(t *testing.T) {
	e := newHBACEnv(t, hbacRosterDoc, func(f *fakeHBAC) { f.converged() })
	res := e.mustApply()
	if res.Plan1.Writes() != 0 || res.Plan2 != nil || res.Entry.Ran || len(e.f.writes()) != 0 || e.entry.prepared != 0 || e.entry.probed != 0 {
		t.Fatalf("idle run: plan1 %d, plan2 %v, entry %+v, writes %v", res.Plan1.Writes(), res.Plan2, res.Entry, e.writeMethods())
	}
	if len(e.journal.events) != 0 {
		t.Errorf("an idle run recorded %v", e.journal.ids())
	}
	if o := res.Obligation(); o.Owed {
		t.Errorf("an idle run owes a refresh: %+v", o)
	}
	if res.Verify.Done || res.Committed() {
		t.Error("an idle run has a verification or is committed")
	}
}

func TestExecuteHBACRefusesABlockedPlanWithZeroWrites(t *testing.T) {
	// FreeIPA has no hostgroup hg-a, which the roster declares: after the playbook phase
	// it should be there, so the rule is blocked, and nothing at all is written.
	e := newHBACEnv(t, hbacRosterDoc, func(f *fakeHBAC) { delete(f.hostgroups, "hg-a") })
	res, err := e.execute()
	if !errors.Is(err, ErrBlocked) || !strings.Contains(err.Error(), "reference_unresolved Login-Team") {
		t.Fatalf("error = %v", err)
	}
	if len(e.f.writes()) != 0 || e.entry.prepared != 0 || res.Stop == nil || res.Stop.Stage != stopPlan1 || res.Plan2 != nil {
		t.Fatalf("writes %v entry %d stop %v", e.writeMethods(), e.entry.prepared, res.Stop)
	}
	resulted, notSent := e.journalOps()
	if len(resulted) != 0 || len(notSent) != len(res.Plan1.Operations) || len(notSent) == 0 {
		t.Errorf("journal: resulted %v, not sent %v, planned %d", resulted, notSent, len(res.Plan1.Operations))
	}
}

func TestExecuteHBACStopsWhenTheEntryFailsOrAnswersForAnotherHost(t *testing.T) {
	for name, setup := range map[string]func(*hbacEnv){
		"the entry fails":           func(e *hbacEnv) { e.entry.err = errors.New("playbook failed") },
		"a result for another host": func(e *hbacEnv) { e.entry.host = "ipa-2" },
		"the result of a probe, not a prepare": func(e *hbacEnv) {
			e.entry.result = func(AuthCacheAction) AuthCacheResult {
				return AuthCacheResult{Action: AuthCacheProbe, Host: "ipa-1", FQDN: testFQDN}
			}
		},
	} {
		e := newHBACEnv(t, hbacRosterDoc, nil)
		setup(e)
		res, err := e.execute()
		if !errors.Is(err, ErrEntry) || len(e.f.writes()) != 0 || res.Stop == nil || res.Stop.Stage != stopEntry || res.Entry.Ran {
			t.Errorf("%s: err %v writes %v stop %v entry %+v", name, err, e.writeMethods(), res.Stop, res.Entry)
		}
	}
}

func TestExecuteHBACWritesNothingWhenTheJournalRefuses(t *testing.T) {
	// The record that the entry ran is refused: nothing is written, and the run says the
	// entry did run (the obligation is on the server whatever the journal says).
	e := newHBACEnv(t, hbacRosterDoc, nil)
	e.journal.failOn = func(ev Event) error {
		if ev.Kind == EventAuthCache {
			return errors.New("disk full")
		}
		return nil
	}
	res, err := e.execute()
	if err == nil || !errors.Is(err, ErrJournal) || len(e.f.writes()) != 0 || !res.Entry.Ran {
		t.Fatalf("err %v writes %v entry %+v", err, e.writeMethods(), res.Entry)
	}
	// A journal that refuses the record of a batch: that batch is not sent.
	e = newHBACEnv(t, hbacRosterDoc, nil)
	e.journal.failOn = func(ev Event) error {
		if strings.HasSuffix(ev.ID, ":sending") {
			return errors.New("disk full")
		}
		return nil
	}
	res, err = e.execute()
	if err == nil || len(e.f.writes()) != 0 || res.Stop == nil || !strings.Contains(res.Stop.Reason, "journal refused") {
		t.Fatalf("err %v writes %v stop %v", err, e.writeMethods(), res.Stop)
	}
}

func TestExecuteHBACSendsNothingThroughAGateThatRefuses(t *testing.T) {
	// The client's gate refuses (the lock was lost, say): the commands never leave.
	e := newHBACEnv(t, hbacRosterDoc, nil)
	e.f.writeGate = func(context.Context, string) error { return errors.New("the lock is lost") }
	res, err := e.execute()
	if !errors.Is(err, ErrWrites) || len(e.f.writes()) != 0 || res.Stop == nil || res.Stop.Stage != "H1" || res.Committed() {
		t.Fatalf("err %v writes %v stop %v", err, e.writeMethods(), res.Stop)
	}
	for _, o := range res.Ops {
		if o.Outcome != OutcomeNotExecuted {
			t.Errorf("%s is %s, want not_executed", o.Operation.ID, o.Outcome)
		}
	}
	// The engine's own check, with a client that has no gate of its own: the lock is
	// given back while the entry runs, and the first batch is refused by the Gate.
	e = newHBACEnv(t, hbacRosterDoc, nil)
	e.f.writeGate = nil
	e.entry.onPrepare = func() { _ = e.held.Release() }
	res, err = e.execute()
	if !errors.Is(err, ErrWrites) || len(e.f.writes()) != 0 || res.Stop == nil || !strings.Contains(res.Stop.Reason, "write gate refused") {
		t.Fatalf("err %v writes %v stop %v", err, e.writeMethods(), res.Stop)
	}
}

func TestExecuteHBACRefusesADestructiveOperationThePlanDidNotHave(t *testing.T) {
	// Another writer puts bob on Login-Team while the entry runs: the roster does not
	// name him, so the second plan removes him, and the operator never saw that removal.
	e := newHBACEnv(t, hbacRosterDoc, func(f *fakeHBAC) { f.converged(); f.users["bob"] = true })
	e.f.ruleNamed("parked").enabled = false
	e.f.ruleNamed("break-glass").enabled = false // some work for the first plan
	e.entry.onPrepare = func() { e.f.ruleNamed("Login-Team").users["bob"] = true }
	res, err := e.execute()
	if !errors.Is(err, ErrDestructiveDiff) || len(e.f.writes()) != 0 {
		t.Fatalf("err %v writes %v", err, e.writeMethods())
	}
	if len(res.Conflicts) != 1 || !strings.Contains(res.Conflicts[0], "hbac.rule.member_user.remove login-team bob") || res.Stop.Stage != stopPlan2 {
		t.Fatalf("conflicts %v stop %v", res.Conflicts, res.Stop)
	}
	if !slices.Contains(res.PlanChanged.Added, "hbac.rule.member_user.remove login-team bob") {
		t.Errorf("plan changed: %+v", res.PlanChanged)
	}
	if !res.Entry.Ran || !res.Obligation().Owed {
		t.Error("the entry ran: the obligation is owed")
	}
}

func TestExecuteHBACAppliesWhatTheSecondPlanHoldsWhenItIsOnlySmaller(t *testing.T) {
	// The service the first plan creates is created by someone else while the entry runs.
	e := newHBACEnv(t, hbacRosterDoc, nil)
	e.entry.onPrepare = func() { e.f.services["custom-svc"] = "custom-svc" }
	res := e.mustApply()
	e.mustBeConverged()
	if slices.Contains(e.writeMethods(), "hbacsvc_add") || !slices.Contains(res.PlanChanged.Removed, "hbac.service.create custom-svc") {
		t.Fatalf("writes %v changed %+v", e.writeMethods(), res.PlanChanged)
	}
}

// movement: a rule that goes from hosts to hostcat all, and one that goes the other way.
func movedServer(f *fakeHBAC) {
	f.converged()
	lt := f.ruleNamed("Login-Team")
	lt.hostCat = "all"
	lt.hosts, lt.hostgroups = map[string]bool{}, map[string]bool{}
	bg := f.ruleNamed("break-glass")
	bg.hostCat = ""
	bg.hosts["web1."+lab] = true
}

func TestExecuteHBACMovesACategoryInTheOrderTheServerNeeds(t *testing.T) {
	e := newHBACEnv(t, hbacRosterDoc, movedServer)
	res := e.mustApply()
	e.mustBeConverged()
	want := []string{
		"hbacrule_remove_host",         // break-glass loses its host: H3
		"hbacrule_mod", "hbacrule_mod", // the categories: H4
		"hbacrule_add_host", "hbacrule_add_host", // Login-Team gets its host and hostgroup: H5
	}
	if got := e.writeMethods(); !slices.Equal(got, want) {
		t.Fatalf("writes:\n got %v\nwant %v", got, want)
	}
	// The category change names its value, and "" clears.
	var mods []call
	for _, c := range e.f.writes() {
		if c.method == "hbacrule_mod" {
			mods = append(mods, c)
		}
	}
	if mods[0].args[0] != "login-team" || mods[0].opts["hostcategory"] != "" || len(mods[0].opts) != 1 ||
		mods[1].args[0] != "break-glass" || mods[1].opts["hostcategory"] != "all" {
		t.Errorf("hbacrule_mod calls: %+v", mods)
	}
	_ = res

	// The firing case: with the stages in another order the server refuses (K3), so the
	// order is what makes it work and a test that reorders it fails.
	swapped := slices.Clone(HBACStages)
	i, j := slices.Index(swapped, H4), slices.Index(swapped, H5)
	swapped[i], swapped[j] = swapped[j], swapped[i]
	orig := HBACStages
	HBACStages = swapped
	t.Cleanup(func() { HBACStages = orig })
	e = newHBACEnv(t, hbacRosterDoc, movedServer)
	res, err := e.execute()
	HBACStages = orig
	if !errors.Is(err, ErrWrites) || res.Stop == nil {
		t.Fatalf("a run with the additions before the category change succeeded: %v", err)
	}
	failed := false
	for _, o := range res.Ops {
		failed = failed || (o.Final() == OutcomeFailed && strings.HasPrefix(o.Error, "MutuallyExclusiveError"))
	}
	if !failed {
		t.Fatalf("the server did not refuse the reordered stages: %s", describeHBACOps(res))
	}
}

func TestExecuteHBACRemovesOnlyWhatTheRuleNoLongerNamesAndNothingFromOthers(t *testing.T) {
	e := newHBACEnv(t, hbacRosterDoc, func(f *fakeHBAC) {
		f.converged()
		f.users["bob"], f.groups["team-z"], f.hostgroups["hg-z"] = true, true, true
		f.hosts["db1."+lab] = true
		lt := f.ruleNamed("Login-Team")
		lt.users["bob"], lt.groups["team-z"], lt.hostgroups["hg-z"], lt.hosts["db1."+lab] = true, true, true, true
		lt.services["sudo"] = true
		// A rule the roster does not mention keeps all of its members.
		by := f.newRule("by-hand")
		by.hostCat = "all"
		by.users["bob"], by.services["sshd"] = true, true
	})
	e.mustApply()
	e.mustBeConverged()
	lt := e.f.ruleNamed("Login-Team")
	if lt.users["bob"] || lt.groups["team-z"] || lt.hostgroups["hg-z"] || lt.hosts["db1."+lab] || lt.services["sudo"] {
		t.Errorf("a stale member is still on Login-Team: %+v", lt)
	}
	if by := e.f.ruleNamed("by-hand"); !by.users["bob"] || !by.services["sshd"] || by.hostCat != "all" {
		t.Errorf("a rule the roster does not mention was changed: %+v", by)
	}
	for _, c := range e.f.writes() {
		if len(c.args) == 0 || c.args[0] != "login-team" {
			t.Errorf("a write that is not on Login-Team: %s %v", c.method, c.args)
		}
	}
}

func TestExecuteHBACRechecksARemovalBeforeSendingIt(t *testing.T) {
	// The re-read before the removals is the third hbacrule_find of the run.
	setup := func(f *fakeHBAC) {
		f.converged()
		f.users["bob"] = true
		f.ruleNamed("Login-Team").users["bob"] = true
	}
	// Someone else puts one more member on the rule between the second plan and the
	// removal: the roster would remove him too, the plan did not list him, so nothing is
	// removed and the later stages (here the enable of break-glass) do not run. The
	// disable of parked is narrowing and is sent before the removals are looked at; it is
	// the only write.
	e := newHBACEnv(t, hbacRosterDoc, func(f *fakeHBAC) { setup(f); f.users["carl"] = true; f.ruleNamed("parked").enabled = true })
	e.f.ruleNamed("break-glass").enabled = false
	e.f.onFind = func(f *fakeHBAC, n int) {
		if n == 3 {
			f.ruleNamed("Login-Team").users["carl"] = true
		}
	}
	res, err := e.execute()
	if !errors.Is(err, ErrWrites) || !slices.Equal(e.writeMethods(), []string{"hbacrule_disable"}) || res.Stop == nil || res.Stop.Stage != "H3" {
		t.Fatalf("err %v writes %v stop %v\n%s", err, e.writeMethods(), res.Stop, describeHBACOps(res))
	}
	if o := res.op("hbac.rule.member_user.remove:login-team"); o.Outcome != OutcomeConflictFailed || !strings.Contains(o.Detail, "carl") {
		t.Errorf("removal outcome %+v", o)
	}
	if res.outcomeOf("hbac.rule.enable:break-glass") != OutcomeNotExecuted {
		t.Errorf("a stage after the conflict ran: %s", describeHBACOps(res))
	}

	// The member has already left: nothing is sent for it, and that is not a conflict.
	e = newHBACEnv(t, hbacRosterDoc, setup)
	e.f.onFind = func(f *fakeHBAC, n int) {
		if n == 3 {
			delete(f.ruleNamed("Login-Team").users, "bob")
		}
	}
	res = e.mustApply()
	if o := res.op("hbac.rule.member_user.remove:login-team"); o.Outcome != OutcomeNoop || len(e.f.writes()) != 0 {
		t.Errorf("removal outcome %+v, writes %v", o, e.writeMethods())
	}
}

func TestExecuteHBACRechecksADisableAndADeleteBeforeSendingThem(t *testing.T) {
	doc := hbacRosterDoc
	// A disable of a rule that was deleted and created again is not the plan's rule.
	e := newHBACEnv(t, doc, func(f *fakeHBAC) { f.converged(); f.ruleNamed("parked").enabled = true })
	e.f.onFind = func(f *fakeHBAC, n int) {
		if n == 3 {
			f.ruleNamed("parked").uuid = "00000000-0000-0000-0000-999999999999"
		}
	}
	res, err := e.execute()
	if !errors.Is(err, ErrWrites) || len(e.f.writes()) != 0 {
		t.Fatalf("err %v writes %v", err, e.writeMethods())
	}
	if o := res.op("hbac.rule.disable:parked"); o.Outcome != OutcomeConflictFailed || !strings.Contains(o.Detail, "not the one") {
		t.Errorf("disable outcome %+v", o)
	}
	// A rule that is already disabled by then is a noop.
	e = newHBACEnv(t, doc, func(f *fakeHBAC) { f.converged(); f.ruleNamed("parked").enabled = true })
	e.f.onFind = func(f *fakeHBAC, n int) {
		if n == 3 {
			f.ruleNamed("parked").enabled = false
		}
	}
	if o := e.mustApply().op("hbac.rule.disable:parked"); o.Outcome != OutcomeNoop {
		t.Errorf("disable outcome %+v", o)
	}
	// A delete of a rule that is already gone is a noop; of one that is another rule
	// (created again since the plan) is a conflict; the roster's other rules are fine.
	withOld := func(f *fakeHBAC) { f.converged(); f.newRule("Old-Rule").hostCat = "all" }
	e = newHBACEnv(t, doc, withOld)
	e.f.onFind = func(f *fakeHBAC, n int) {
		if n == 3 {
			delete(f.rules, "old-rule")
		}
	}
	if o := e.mustApply().op("hbac.rule.delete:old-rule"); o.Outcome != OutcomeNoop {
		t.Errorf("delete outcome %+v", o)
	}
	e = newHBACEnv(t, doc, withOld)
	e.f.onFind = func(f *fakeHBAC, n int) {
		if n == 3 {
			f.ruleNamed("old-rule").uuid = "00000000-0000-0000-0000-888888888888"
		}
	}
	res, err = e.execute()
	if !errors.Is(err, ErrWrites) || len(e.f.writes()) != 0 {
		t.Fatalf("err %v writes %v", err, e.writeMethods())
	}
	if o := res.op("hbac.rule.delete:old-rule"); o.Outcome != OutcomeConflictFailed {
		t.Errorf("delete outcome %+v", o)
	}
	// An ordinary delete is sent and works.
	e = newHBACEnv(t, doc, withOld)
	e.mustApply()
	if e.f.ruleNamed("Old-Rule") != nil {
		t.Error("the absent rule is still there")
	}
	e.mustBeConverged()
}

func TestExecuteHBACRuleThatAppearsAfterThePlanIsAConflictNotATakeOver(t *testing.T) {
	// FreeIPA answers DuplicateEntry to the rule's creation: the rule is somebody
	// else's, the plan no longer describes the server, and the run stops there.
	e := newHBACEnv(t, hbacRosterDoc, nil)
	e.f.intercept = func(f *fakeHBAC, c call) (json.RawMessage, error, bool) {
		if c.method == "hbacrule_add" && c.args[0] == "break-glass" {
			return nil, f.errFixture("hbacrule-add-duplicate"), true
		}
		return nil, nil, false
	}
	res, err := e.execute()
	if !errors.Is(err, ErrWrites) || res.Stop == nil || res.Stop.Stage != "H2" {
		t.Fatalf("err %v stop %v", err, res.Stop)
	}
	if o := res.op("hbac.rule.create:break-glass"); o.Outcome != OutcomeConflictFailed || !strings.HasPrefix(o.Error, "DuplicateEntry (4002)") {
		t.Errorf("create outcome %+v", o)
	}
	for _, m := range e.writeMethods() {
		if strings.HasPrefix(m, "hbacrule_add_") {
			t.Errorf("a member was added after the conflict: %v", e.writeMethods())
		}
	}
	if !res.Committed() {
		t.Error("the rules created before the conflict are changes: committed")
	}
	if o := res.Obligation(); !o.Owed {
		t.Error("the entry ran")
	}
}

func TestExecuteHBACAMemberAnotherWriterAddedAfterThePlanIsANoopNotAFailure(t *testing.T) {
	// alice is missing from Login-Team when the plan is made, and is put there before the
	// command arrives: FreeIPA answers "already a member", which is what the plan wanted.
	e := newHBACEnv(t, hbacRosterDoc, func(f *fakeHBAC) {
		f.converged()
		f.ruleNamed("Login-Team").users = map[string]bool{}
	})
	e.f.intercept = func(f *fakeHBAC, c call) (json.RawMessage, error, bool) {
		if c.method == "hbacrule_add_user" && c.opts["user"] != nil {
			f.rules["login-team"].users["alice"] = true
		}
		return nil, nil, false
	}
	res := e.mustApply()
	o := res.op("hbac.rule.member_user.add:login-team")
	if o.Outcome != OutcomeNoop || o.Completed != 0 || o.Error != "" {
		t.Fatalf("outcome %+v", o)
	}
	e.mustBeConverged()
}

func TestExecuteHBACFailureStopsTheStagesAfterIt(t *testing.T) {
	// A rule Old-Rule that the roster marks absent gives a stage after H5 something to do.
	e := newHBACEnv(t, hbacRosterDoc, func(f *fakeHBAC) { f.newRule("Old-Rule").hostCat = "all" })
	e.f.intercept = func(f *fakeHBAC, c call) (json.RawMessage, error, bool) {
		if c.method == "hbacrule_add_service" && c.args[0] == "break-glass" {
			return nil, f.errFixture("hbacrule-add-service-while-servicecat-all"), true
		}
		return nil, nil, false
	}
	res, err := e.execute()
	if !errors.Is(err, ErrWrites) || res.Stop == nil || res.Stop.Stage != "H5" {
		t.Fatalf("err %v stop %v", err, res.Stop)
	}
	if o := res.op("hbac.rule.member_service.add:break-glass"); o.Outcome != OutcomeFailed || !strings.HasPrefix(o.Error, "MutuallyExclusiveError (4303)") {
		t.Errorf("outcome %+v", o)
	}
	// The batch that failed was sent whole, and the stage after it (the delete of
	// Old-Rule, H7) was not.
	if res.outcomeOf("hbac.rule.delete:old-rule") != OutcomeNotExecuted || slices.Contains(e.writeMethods(), "hbacrule_del") || e.f.ruleNamed("Old-Rule") == nil {
		t.Errorf("a stage after the failure ran: %s", describeHBACOps(res))
	}
	// The rule the roster wants disabled was disabled before the stage that failed added
	// its members: the stop leaves it disabled, not enabled with alice and sshd.
	if pk := e.f.ruleNamed("parked"); pk == nil || pk.enabled {
		t.Errorf("parked is enabled after the failure: %+v", pk)
	}
	if res.outcomeOf("hbac.rule.disable:parked") != OutcomeSuccess {
		t.Errorf("the disable of parked (H3) was %s: %s", res.outcomeOf("hbac.rule.disable:parked"), describeHBACOps(res))
	}
	resulted, notSent := e.journalOps()
	planned := map[string]int{}
	for _, o := range res.Ops {
		planned[o.Operation.ID]++
	}
	seen := map[string]int{}
	for _, id := range append(slices.Clone(resulted), notSent...) {
		seen[id]++
	}
	for id := range planned {
		if seen[id] != 1 {
			t.Errorf("%s is in the journal %d times, want once (result %v, not sent %v)", id, seen[id], resulted, notSent)
		}
	}
}

func TestExecuteHBACUnknownOutcomeIsResolvedByTheReadAfterTheWrites(t *testing.T) {
	const solo = `
schema_version: 3
users:
  - {name: alice}
hbac:
  rules:
    - name: solo
      subjects: {users: [alice]}
      targets: {hostcat: all}
      services: [sshd]
`
	lastWrite := func(c call) bool { return c.method == "hbacrule_add_user" }
	for name, tc := range map[string]struct {
		applied bool
		want    string
		fails   bool
	}{
		"the command was applied":     {true, resolutionConverged, false},
		"the command was not applied": {false, resolutionNotApplied, true},
	} {
		e := newHBACEnv(t, solo, nil)
		e.f.intercept = func(f *fakeHBAC, c call) (json.RawMessage, error, bool) {
			if !lastWrite(c) {
				return nil, nil, false
			}
			if tc.applied {
				f.rules["solo"].users["alice"] = true
			}
			return nil, &freeiparpc.OutcomeUnknownError{Method: c.method, Err: errors.New("connection lost")}, true
		}
		res, err := e.execute()
		o := res.op("hbac.rule.member_user.add:solo")
		if o.Outcome != OutcomeUnknown || o.Resolution != tc.want || (err != nil) != tc.fails {
			t.Errorf("%s: outcome %s resolution %q err %v", name, o.Outcome, o.Resolution, err)
		}
		if tc.fails && !errors.Is(err, ErrWrites) {
			t.Errorf("%s: err %v", name, err)
		}
		if res.Stop == nil || res.Stop.Stage != "H5" {
			t.Errorf("%s: an unknown outcome stops the scheduling: %v", name, res.Stop)
		}
		if !res.Committed() && tc.applied {
			t.Errorf("%s: an applied unknown is a change", name)
		}
	}
}

func TestExecuteHBACVerificationReportsWhatIsLeft(t *testing.T) {
	// A server that says "Disabled" and does not disable (enable and disable of a rule that
	// is already in the state answer like a change, so the answer proves nothing): the read
	// after the writes is what shows it.
	e := newHBACEnv(t, hbacRosterDoc, nil)
	e.f.intercept = func(f *fakeHBAC, c call) (json.RawMessage, error, bool) {
		if c.method == "hbacrule_disable" {
			return jsonOf(map[string]any{"result": true, "value": "parked", "summary": `Disabled HBAC rule "parked"`}), nil, true
		}
		return nil, nil, false
	}
	res, err := e.execute()
	if !errors.Is(err, ErrVerify) || errors.Is(err, ErrWrites) {
		t.Fatalf("err %v", err)
	}
	if res.Verify.OK() || !slices.Equal(res.Verify.Remaining, []string{"hbac.rule.disable:parked"}) {
		t.Fatalf("verify %+v", res.Verify)
	}
	// The read after the writes fails (the fourth hbacrule_find of this run): the run is
	// not verified, and says so.
	e = newHBACEnv(t, hbacRosterDoc, nil)
	e.f.findErr = func(method string, n int) error {
		if method == "hbacrule_find" && n == 4 {
			return errors.New("the server went away")
		}
		return nil
	}
	res, err = e.execute()
	if !errors.Is(err, ErrVerify) || errors.Is(err, ErrWrites) || !res.Verify.Done || !strings.Contains(res.Verify.ReadError, "went away") || res.Verify.OK() {
		t.Fatalf("err %v verify %+v", err, res.Verify)
	}
	// The ordinary run is verified.
	e = newHBACEnv(t, hbacRosterDoc, nil)
	if res = e.mustApply(); !res.Verify.Done || !res.Verify.OK() {
		t.Fatalf("verify %+v", res.Verify)
	}
}

func TestExecuteHBACBatchesAtMostTheBatchLimit(t *testing.T) {
	e := newHBACEnv(t, hbacRosterDoc, nil)
	e.opts.BatchLimit = 1
	res := e.mustApply()
	if e.f.batches != len(res.Ops) {
		t.Errorf("%d batches for %d operations at a limit of 1", e.f.batches, len(res.Ops))
	}
	e = newHBACEnv(t, hbacRosterDoc, nil)
	res = e.mustApply()
	// One batch per stage that has operations at the default limit.
	stages := map[string]bool{}
	for _, o := range res.Ops {
		stages[o.Stage] = true
	}
	if e.f.batches != len(stages) {
		t.Errorf("%d batches for %d stages", e.f.batches, len(stages))
	}
}

func TestExecuteHBACRefusesWhatItCannotRun(t *testing.T) {
	e := newHBACEnv(t, hbacRosterDoc, nil)
	if _, err := ExecuteHBAC(context.Background(), e.f, e.opts); !errors.Is(err, identitylock.ErrNoLock) {
		t.Errorf("a context without the lock: %v", err)
	}
	for name, mutate := range map[string]func(*HBACOptions){
		"no entry":                   func(o *HBACOptions) { o.Entry = nil },
		"no gate":                    func(o *HBACOptions) { o.Gate = nil },
		"no journal":                 func(o *HBACOptions) { o.Journal = nil },
		"a batch limit over the max": func(o *HBACOptions) { o.BatchLimit = MaxBatch + 1 },
		"a negative batch limit":     func(o *HBACOptions) { o.BatchLimit = -1 },
		"a lockdown without a host": func(o *HBACOptions) {
			o.Desired.DisableAllowAll = true
			o.TestHost = ""
		},
	} {
		opts := e.opts
		mutate(&opts)
		if _, err := ExecuteHBAC(e.ctx, e.f, opts); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if len(e.f.calls) != 0 {
		t.Errorf("a refused run read or wrote: %v", e.f.methods())
	}
	if _, err := ExecuteHBAC(e.ctx, nil, e.opts); err == nil {
		t.Error("no client: accepted")
	}
}

func TestObservingAndPlanningNeverWrite(t *testing.T) {
	// What a preview does: the reads, and the plan with the playbook phase assumed. No
	// command that writes is sent, and the client's own allowlist keeps the reads read-only.
	f := newFakeHBAC(t)
	obs, err := ObserveHBAC(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	p := BuildHBAC(HBACInput{Desired: hbacDesired(t, hbacRosterDoc), Obs: obs, Preview: true})
	if p.Writes() == 0 || len(f.writes()) != 0 {
		t.Fatalf("plan %d, writes %v", p.Writes(), f.methods())
	}
	for _, m := range []string{"hbacrule_find", "hbacsvc_find", "host_find", "hostgroup_find", "env"} {
		if !slices.Contains(f.methods(), m) {
			t.Errorf("%s was not read", m)
		}
		if hbacIsWrite(m) {
			t.Errorf("%s is counted as a write", m)
		}
	}
}

func TestHBACResultCountsTheOutcomesAsTheyEnded(t *testing.T) {
	e := newHBACEnv(t, hbacRosterDoc, nil)
	res := e.mustApply()
	if got := res.Counts()[OutcomeSuccess]; got != len(res.Ops) {
		t.Errorf("counts %v for %d operations", res.Counts(), len(res.Ops))
	}
	if (HBACResult{}).Committed() || (HBACResult{}).Obligation().Owed {
		t.Error("an empty result is committed or owes a refresh")
	}
}
