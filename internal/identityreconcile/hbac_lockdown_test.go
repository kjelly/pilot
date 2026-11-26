package identityreconcile

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/freeiparpc"
)

// The lockdown of allow_all (H8): the proofs, the disable, the rollback. The server is the
// fake of hbac_fakeipa_test.go, whose hbactest answers like the captures; a proof that must
// fail is the captured answer of a denied access (hbactest-denied-user), not a shape written
// for the test.

var lockdownRoster = strings.Replace(hbacRosterDoc, "hbac:\n", "hbac:\n  disable_allow_all: true\n", 1)

func (e *hbacEnv) hbactestCalls() []call {
	e.f.mu.Lock()
	defer e.f.mu.Unlock()
	var out []call
	for _, c := range e.f.calls {
		if c.method == "hbactest" {
			out = append(out, c)
		}
	}
	return out
}

func (e *hbacEnv) allowAllEnabled() bool { return e.f.ruleNamed("allow_all").enabled }

// answerHBACTest makes the n-th hbactest (1 is the proof before the disable) answer with the
// captured fixture, and lets the others through.
func answerHBACTest(t *testing.T, e *hbacEnv, n int, fixture string) {
	t.Helper()
	count := 0
	prev := e.f.intercept
	e.f.intercept = func(f *fakeHBAC, c call) (json.RawMessage, error, bool) {
		if c.method == "hbactest" {
			count++
			if count == n {
				return fixtureResult(t, fixture), nil, true
			}
		}
		if prev != nil {
			return prev(f, c)
		}
		return nil, nil, false
	}
}

func interceptWrite(e *hbacEnv, method string, answer func(f *fakeHBAC, c call) (json.RawMessage, error)) {
	prev := e.f.intercept
	e.f.intercept = func(f *fakeHBAC, c call) (json.RawMessage, error, bool) {
		if c.method == method {
			raw, err := answer(f, c)
			return raw, err, true
		}
		if prev != nil {
			return prev(f, c)
		}
		return nil, nil, false
	}
}

func TestExecuteHBACLockdownDisablesAllowAllAfterTheProofsHold(t *testing.T) {
	e := newHBACEnv(t, lockdownRoster, nil)
	res := e.mustApply()
	e.mustBeConverged()
	if e.allowAllEnabled() {
		t.Fatal("allow_all is still enabled")
	}
	rep := res.Lockdown
	if rep == nil || rep.Before != "granted" || rep.After != "granted" || !rep.Disabled || rep.Rollback != "" {
		t.Fatalf("lockdown report %+v", rep)
	}
	if res.outcomeOf("hbac.allow_all.disable:allow_all") != OutcomeSuccess || !res.Verify.OK() {
		t.Fatalf("outcome %s verify %+v", res.outcomeOf("hbac.allow_all.disable:allow_all"), res.Verify)
	}
	// The lockdown is the last write of the run, and exactly two proofs bracket it.
	writes := e.f.writes()
	last := writes[len(writes)-1]
	if last.method != "hbacrule_disable" || last.args[0] != "allow_all" || res.Ops[len(res.Ops)-1].Operation.Kind != KindHBACAllowAllDisable {
		t.Fatalf("the last write is %s %v", last.method, last.args)
	}
	proofs := e.hbactestCalls()
	if len(proofs) != 2 {
		t.Fatalf("%d proofs, want 2", len(proofs))
	}
	for _, p := range proofs {
		if p.opts["user"] != "admin" || p.opts["targethost"] != testFQDN || p.opts["service"] != "sshd" {
			t.Errorf("proof asked %v", p.opts)
		}
	}
	// The order of the calls: the roster's own disable (parked, H3), then the proof, the
	// disable of allow_all and the proof again; no rollback.
	var order []string
	for _, m := range e.f.methods() {
		if m == "hbactest" || m == "hbacrule_disable" || m == "hbacrule_enable" {
			order = append(order, m)
		}
	}
	if want := []string{"hbacrule_disable", "hbactest", "hbacrule_disable", "hbactest"}; !slices.Equal(order, want) {
		t.Fatalf("calls %v, want %v", order, want)
	}
	// The journal's result event of the stage carries the report.
	e.journal.mu.Lock()
	found := false
	for _, ev := range e.journal.events {
		if p, ok := ev.Payload.(hbacResultEvent); ok && p.Stage == "H8" && p.Lockdown != nil && p.Lockdown.After == "granted" {
			found = true
		}
	}
	e.journal.mu.Unlock()
	if !found {
		t.Error("the journal's H8 result event holds no lockdown report")
	}
	// A second run has nothing to do.
	if again, err := ExecuteHBAC(e.ctx, e.f, e.opts); err != nil || again.Plan1.Writes() != 0 {
		t.Fatalf("second run: %v", err)
	}
}

func TestExecuteHBACLockdownIsNotAttemptedWhenTheProofBeforeFails(t *testing.T) {
	for name, tc := range map[string]struct {
		setup func(*testing.T, *hbacEnv)
		want  string
	}{
		"admin is denied": {func(t *testing.T, e *hbacEnv) { answerHBACTest(t, e, 1, "hbactest-denied-user") }, "denied"},
		"the proof cannot be asked": {func(t *testing.T, e *hbacEnv) {
			interceptWrite(e, "hbactest", func(f *fakeHBAC, c call) (json.RawMessage, error) { return nil, errors.New("tunnel closed") })
		}, "error: tunnel closed"},
		"the answer has no value": {func(t *testing.T, e *hbacEnv) {
			interceptWrite(e, "hbactest", func(f *fakeHBAC, c call) (json.RawMessage, error) {
				return json.RawMessage(`{"summary": "Access granted: True", "warning": null, "error": null}`), nil
			})
		}, "no value"},
		"the value is text": {func(t *testing.T, e *hbacEnv) {
			interceptWrite(e, "hbactest", func(f *fakeHBAC, c call) (json.RawMessage, error) {
				return json.RawMessage(`{"value": "True", "error": null}`), nil
			})
		}, "error:"},
		"the answer carries an error": {func(t *testing.T, e *hbacEnv) {
			interceptWrite(e, "hbactest", func(f *fakeHBAC, c call) (json.RawMessage, error) {
				return json.RawMessage(`{"value": true, "error": "internal"}`), nil
			})
		}, "answered an error"},
	} {
		e := newHBACEnv(t, lockdownRoster, nil)
		tc.setup(t, e)
		res, err := e.execute()
		if !errors.Is(err, ErrWrites) || res.Lockdown == nil || !strings.Contains(res.Lockdown.Before, tc.want) || res.Lockdown.Disabled || res.Lockdown.Rollback != "" {
			t.Errorf("%s: err %v report %+v", name, err, res.Lockdown)
			continue
		}
		if !e.allowAllEnabled() {
			t.Errorf("%s: allow_all was disabled", name)
		}
		for _, c := range e.f.writes() {
			if len(c.args) > 0 && c.args[0] == "allow_all" {
				t.Errorf("%s: a write on allow_all: %s", name, c.method)
			}
		}
		o := res.op("hbac.allow_all.disable:allow_all")
		if o.Outcome != OutcomeConflictFailed || res.Stop == nil || res.Stop.Stage != "H8" || len(e.hbactestCalls()) != 1 {
			t.Errorf("%s: outcome %+v stop %v, %d proofs", name, o, res.Stop, len(e.hbactestCalls()))
		}
		// The earlier stages did their work: the roster's rules are there, only allow_all is.
		if !res.Committed() || e.f.ruleNamed("break-glass") == nil {
			t.Errorf("%s: the earlier stages' work is missing", name)
		}
	}
}

func TestExecuteHBACLockdownPutsAllowAllBackWhenTheProofAfterFails(t *testing.T) {
	e := newHBACEnv(t, lockdownRoster, nil)
	answerHBACTest(t, e, 2, "hbactest-denied-user")
	res, err := e.execute()
	if !errors.Is(err, ErrWrites) {
		t.Fatalf("err %v", err)
	}
	rep := res.Lockdown
	if rep == nil || rep.Before != "granted" || rep.After != "denied" || !rep.Disabled || rep.Rollback != "re-enabled" {
		t.Fatalf("report %+v", rep)
	}
	if !e.allowAllEnabled() {
		t.Fatal("allow_all was not put back")
	}
	o := res.op("hbac.allow_all.disable:allow_all")
	if o.Final() != OutcomeFailed || !strings.Contains(o.Detail, "allow_all was re-enabled") || strings.Contains(o.Detail, "FAILED") {
		t.Fatalf("outcome %+v", o)
	}
	writes := e.writeMethods()
	if got := writes[len(writes)-2:]; !slices.Equal(got, []string{"hbacrule_disable", "hbacrule_enable"}) {
		t.Fatalf("the last writes are %v", got)
	}
	// The verification sees allow_all enabled again: the lockdown is still wanted, so it
	// is what is left, and the run is not verified either.
	if !errors.Is(err, ErrVerify) || !slices.Contains(res.Verify.Remaining, "hbac.allow_all.disable:allow_all") {
		t.Errorf("verify %+v err %v", res.Verify, err)
	}
}

func TestExecuteHBACLockdownSaysSoWhenTheRollbackFails(t *testing.T) {
	e := newHBACEnv(t, lockdownRoster, nil)
	answerHBACTest(t, e, 2, "hbactest-denied-user")
	interceptWrite(e, "hbacrule_enable", func(f *fakeHBAC, c call) (json.RawMessage, error) {
		if c.args[0] == "allow_all" {
			return nil, f.errFixture("hbacrule-enable-not-found")
		}
		return nil, nil
	})
	// interceptWrite takes over every hbacrule_enable: the roster's own rules are not
	// enabled by this run (none is disabled in it), so only the rollback arrives here.
	res, err := e.execute()
	if !errors.Is(err, ErrWrites) {
		t.Fatalf("err %v", err)
	}
	rep := res.Lockdown
	if rep == nil || !rep.Disabled || !strings.HasPrefix(rep.Rollback, "FAILED:") {
		t.Fatalf("report %+v", rep)
	}
	o := res.op("hbac.allow_all.disable:allow_all")
	if o.Final() != OutcomeFailed || !strings.Contains(o.Detail, "FAILED") || !strings.Contains(o.Detail, "check HBAC access now") || strings.Contains(o.Detail, "was re-enabled") {
		t.Fatalf("outcome %+v", o)
	}
	if e.allowAllEnabled() {
		t.Fatal("the fake enabled allow_all in spite of the refusal")
	}
	// The read after the writes sees allow_all disabled, which would make the unknown
	// disable look converged: the operation is failed, and stays failed.
	if o.Resolution != "" {
		t.Errorf("a failed lockdown was resolved: %q", o.Resolution)
	}
}

func TestExecuteHBACLockdownDoesNotPutAllowAllBackWhenTheServerRefusedTheDisable(t *testing.T) {
	e := newHBACEnv(t, lockdownRoster, nil)
	interceptWrite(e, "hbacrule_disable", func(f *fakeHBAC, c call) (json.RawMessage, error) {
		if c.args[0] == "allow_all" {
			return nil, f.errFixture("hbacrule-disable-not-found")
		}
		return nil, nil
	})
	// The roster's own rule "parked" is disabled by this command too: let that one through.
	prev := e.f.intercept
	e.f.intercept = func(f *fakeHBAC, c call) (json.RawMessage, error, bool) {
		if c.method == "hbacrule_disable" && c.args[0] != "allow_all" {
			f.rules[lower(c.args[0].(string))].enabled = false
			return jsonOf(map[string]any{"result": true, "value": c.args[0], "summary": "Disabled HBAC rule"}), nil, true
		}
		return prev(f, c)
	}
	res, err := e.execute()
	if !errors.Is(err, ErrWrites) {
		t.Fatalf("err %v", err)
	}
	rep := res.Lockdown
	if rep == nil || rep.Disabled || rep.Rollback != "" || rep.After != "" {
		t.Fatalf("report %+v", rep)
	}
	if slices.Contains(e.writeMethods(), "hbacrule_enable") || len(e.hbactestCalls()) != 1 {
		t.Errorf("writes %v, %d proofs", e.writeMethods(), len(e.hbactestCalls()))
	}
	if o := res.op("hbac.allow_all.disable:allow_all"); o.Outcome != OutcomeConflictFailed || !strings.Contains(o.Detail, "allow_all was not touched") {
		t.Errorf("outcome %+v", o)
	}
}

func TestExecuteHBACLockdownPutsAllowAllBackWhenTheDisableIsUnknown(t *testing.T) {
	for name, applied := range map[string]bool{"it was applied": true, "it was not applied": false} {
		e := newHBACEnv(t, lockdownRoster, nil)
		prev := e.f.intercept
		e.f.intercept = func(f *fakeHBAC, c call) (json.RawMessage, error, bool) {
			if c.method == "hbacrule_disable" && c.args[0] == "allow_all" {
				if applied {
					f.rules["allow_all"].enabled = false
				}
				return nil, &freeiparpc.OutcomeUnknownError{Method: c.method, Err: errors.New("connection lost")}, true
			}
			if prev != nil {
				return prev(f, c)
			}
			return nil, nil, false
		}
		res, err := e.execute()
		if !errors.Is(err, ErrWrites) {
			t.Fatalf("%s: err %v", name, err)
		}
		rep := res.Lockdown
		if rep == nil || rep.Rollback != "re-enabled" || rep.Disabled || !e.allowAllEnabled() {
			t.Errorf("%s: report %+v, allow_all enabled %v", name, rep, e.allowAllEnabled())
		}
		o := res.op("hbac.allow_all.disable:allow_all")
		if o.Outcome != OutcomeFailed || o.Final() != OutcomeFailed || !strings.Contains(o.Detail, "allow_all was re-enabled") {
			t.Errorf("%s: outcome %+v", name, o)
		}
	}
}

func TestExecuteHBACLockdownDoesNotRunWhenAnEarlierStageStopped(t *testing.T) {
	e := newHBACEnv(t, lockdownRoster, nil)
	interceptWrite(e, "hbacrule_add_service", func(f *fakeHBAC, c call) (json.RawMessage, error) {
		return nil, f.errFixture("hbacrule-add-service-while-servicecat-all")
	})
	res, err := e.execute()
	if !errors.Is(err, ErrWrites) || res.Stop == nil || res.Stop.Stage != "H5" {
		t.Fatalf("err %v stop %v", err, res.Stop)
	}
	if res.Lockdown != nil || len(e.hbactestCalls()) != 0 || !e.allowAllEnabled() {
		t.Errorf("the lockdown ran: %+v, %d proofs, allow_all enabled %v", res.Lockdown, len(e.hbactestCalls()), e.allowAllEnabled())
	}
	if res.outcomeOf("hbac.allow_all.disable:allow_all") != OutcomeNotExecuted {
		t.Errorf("outcome %s", res.outcomeOf("hbac.allow_all.disable:allow_all"))
	}
}

func TestExecuteHBACLockdownOfAnAllowAllAnotherWriterAlreadyDisabledIsANoop(t *testing.T) {
	e := newHBACEnv(t, lockdownRoster, nil)
	// allow_all is disabled by someone else after the plan was made, while the first
	// proof is asked: nothing is sent for it.
	first := true
	prev := e.f.intercept
	e.f.intercept = func(f *fakeHBAC, c call) (json.RawMessage, error, bool) {
		if c.method == "hbactest" && first {
			first = false
			f.rules["allow_all"].enabled = false
		}
		if prev != nil {
			return prev(f, c)
		}
		return nil, nil, false
	}
	res := e.mustApply()
	o := res.op("hbac.allow_all.disable:allow_all")
	if o.Outcome != OutcomeNoop || !strings.Contains(o.Detail, "already disabled") {
		t.Fatalf("outcome %+v", o)
	}
	for _, c := range e.f.writes() {
		if len(c.args) > 0 && c.args[0] == "allow_all" {
			t.Errorf("a write on allow_all: %s", c.method)
		}
	}
	if len(e.hbactestCalls()) != 1 {
		t.Errorf("%d proofs, want the one before", len(e.hbactestCalls()))
	}
}

func TestExecuteHBACLockdownStillProvesAndRollsBackAfterTheRunWasCancelled(t *testing.T) {
	// The run is cancelled right after the disable went out (Ctrl-C, --timeout): the proof
	// and the rollback still happen, on a context that is not the run's.
	e := newHBACEnv(t, lockdownRoster, nil)
	ctx, cancel := context.WithCancel(e.ctx)
	t.Cleanup(cancel)
	e.ctx = ctx
	answerHBACTest(t, e, 2, "hbactest-denied-user")
	prev := e.f.intercept
	e.f.intercept = func(f *fakeHBAC, c call) (json.RawMessage, error, bool) {
		if c.method == "hbacrule_disable" && c.args[0] == "allow_all" {
			f.rules["allow_all"].enabled = false
			cancel()
			return jsonOf(map[string]any{"result": true, "value": "allow_all", "summary": `Disabled HBAC rule "allow_all"`}), nil, true
		}
		return prev(f, c)
	}
	res, err := e.execute()
	if !errors.Is(err, ErrWrites) {
		t.Fatalf("err %v", err)
	}
	rep := res.Lockdown
	if rep == nil || rep.After != "denied" || rep.Rollback != "re-enabled" || !e.allowAllEnabled() {
		t.Fatalf("report %+v, allow_all enabled %v", rep, e.allowAllEnabled())
	}
	for _, c := range e.f.calls {
		if c.method == "hbacrule_enable" && c.ctxErr != nil {
			t.Errorf("the rollback went out on a cancelled context: %v", c.ctxErr)
		}
	}
}

// shortenLockdownBudgets makes the proof's and the rollback's budgets short enough to use up.
func shortenLockdownBudgets(t *testing.T, proof, rollback time.Duration) {
	t.Helper()
	p, r := lockdownProofTimeout, lockdownRollbackTimeout
	lockdownProofTimeout, lockdownRollbackTimeout = proof, rollback
	t.Cleanup(func() { lockdownProofTimeout, lockdownRollbackTimeout = p, r })
}

// blockUntilDone makes the n-th call of method (1 is the first) wait until its context is
// done, as a server that does not answer does, and fail with the context's error.
func blockUntilDone(e *hbacEnv, method string, n int) {
	count := 0
	prev := e.f.intercept
	e.f.intercept = func(f *fakeHBAC, c call) (json.RawMessage, error, bool) {
		if c.method == method {
			count++
			if count == n {
				<-c.ctx.Done()
				return nil, c.ctx.Err(), true
			}
		}
		if prev != nil {
			return prev(f, c)
		}
		return nil, nil, false
	}
}

func (e *hbacEnv) callsOf(method string, arg string) []call {
	e.f.mu.Lock()
	defer e.f.mu.Unlock()
	var out []call
	for _, c := range e.f.calls {
		if c.method == method && (arg == "" || (len(c.args) > 0 && c.args[0] == arg)) {
			out = append(out, c)
		}
	}
	return out
}

func TestExecuteHBACLockdownRollsBackEvenWhenTheProofUsedUpItsTime(t *testing.T) {
	// The proof after the disable never answers and uses up its whole budget. The enable
	// of allow_all must still go out, on a context with time left (spec §6 step 5).
	shortenLockdownBudgets(t, 50*time.Millisecond, VerifyTimeout)
	e := newHBACEnv(t, lockdownRoster, nil)
	blockUntilDone(e, "hbactest", 2)
	res, err := e.execute()
	if !errors.Is(err, ErrWrites) {
		t.Fatalf("err %v", err)
	}
	rep := res.Lockdown
	if rep == nil || !rep.Disabled || !strings.HasPrefix(rep.After, "error:") || !strings.Contains(rep.After, "deadline") {
		t.Fatalf("report %+v", rep)
	}
	enables := e.callsOf("hbacrule_enable", "allow_all")
	if len(enables) != 1 {
		t.Fatalf("%d hbacrule_enable allow_all writes, want the rollback's one (writes %v)", len(enables), e.writeMethods())
	}
	if enables[0].ctxErr != nil {
		t.Errorf("the rollback went out on a context that was done: %v", enables[0].ctxErr)
	}
	if rep.Rollback != "re-enabled" || !e.allowAllEnabled() {
		t.Errorf("rollback %q, allow_all enabled %v", rep.Rollback, e.allowAllEnabled())
	}
	o := res.op("hbac.allow_all.disable:allow_all")
	if o.Final() != OutcomeFailed || !strings.Contains(o.Detail, "allow_all was re-enabled") {
		t.Errorf("outcome %+v", o)
	}
}

func TestExecuteHBACLockdownRollbackIsBoundedAndSaysSoWhenItUsesUpItsTime(t *testing.T) {
	// The branches that put allow_all back: the proof after the disable denies, and the
	// disable's outcome is unknown. In both the enable is the one that never answers, and
	// the stage ends within the rollback's own budget with the rollback FAILED, not
	// re-enabled.
	for name, setup := range map[string]func(e *hbacEnv){
		"the proof after denies": func(e *hbacEnv) { answerHBACTest(t, e, 2, "hbactest-denied-user") },
		"the disable is unknown": func(e *hbacEnv) {
			prev := e.f.intercept
			e.f.intercept = func(f *fakeHBAC, c call) (json.RawMessage, error, bool) {
				if c.method == "hbacrule_disable" && c.args[0] == "allow_all" {
					return nil, &freeiparpc.OutcomeUnknownError{Method: c.method, Err: errors.New("connection lost")}, true
				}
				if prev != nil {
					return prev(f, c)
				}
				return nil, nil, false
			}
		},
	} {
		shortenLockdownBudgets(t, VerifyTimeout, 50*time.Millisecond)
		e := newHBACEnv(t, lockdownRoster, nil)
		setup(e)
		blockUntilDone(e, "hbacrule_enable", 1)
		start := time.Now()
		res, err := e.execute()
		if !errors.Is(err, ErrWrites) {
			t.Fatalf("%s: err %v", name, err)
		}
		if time.Since(start) > 10*time.Second {
			t.Errorf("%s: the stage took %v", name, time.Since(start))
		}
		rep := res.Lockdown
		if rep == nil || !strings.HasPrefix(rep.Rollback, "FAILED:") || !strings.Contains(rep.Rollback, "deadline") {
			t.Errorf("%s: report %+v", name, rep)
			continue
		}
		o := res.op("hbac.allow_all.disable:allow_all")
		if o.Final() != OutcomeFailed || !strings.Contains(o.Detail, "check HBAC access now") || strings.Contains(o.Detail, "was re-enabled") {
			t.Errorf("%s: outcome %+v", name, o)
		}
	}
}

func TestExecuteHBACLockdownProofAndRollbackEachHaveAContextOfTheirOwn(t *testing.T) {
	// The rollback does not run on the proof's context: not the same one (a proof that used
	// its time up would take the rollback's with it), and bounded by a deadline of its own.
	e := newHBACEnv(t, lockdownRoster, nil)
	answerHBACTest(t, e, 2, "hbactest-denied-user")
	res, err := e.execute()
	if !errors.Is(err, ErrWrites) || res.Lockdown == nil || res.Lockdown.Rollback != "re-enabled" {
		t.Fatalf("err %v report %+v", err, res.Lockdown)
	}
	proofs := e.hbactestCalls()
	enables := e.callsOf("hbacrule_enable", "allow_all")
	if len(proofs) != 2 || len(enables) != 1 {
		t.Fatalf("%d proofs, %d enables", len(proofs), len(enables))
	}
	proof, rollback := proofs[1].ctx, enables[0].ctx
	if proof.Done() == rollback.Done() {
		t.Error("the rollback ran on the proof's context")
	}
	if _, ok := proof.Deadline(); !ok {
		t.Error("the proof after the disable has no deadline of its own")
	}
	rd, ok := rollback.Deadline()
	if !ok {
		t.Fatal("the rollback has no deadline")
	}
	pd, _ := proof.Deadline()
	if !rd.After(pd) {
		t.Errorf("the rollback's deadline %v is not later than the proof's %v: it was not built when the rollback ran", rd, pd)
	}
}

func TestParseHBACTestReadsTheValueOfTheCapturedAnswers(t *testing.T) {
	for fixture, want := range map[string]bool{
		"hbactest-granted": true, "hbactest-breakglass-granted": true, "hbactest-rules-option": true,
		"hbactest-denied-user": false, "hbactest-breakglass-disabled": false, "hbactest-admin-granted": false,
	} {
		got, err := parseHBACTest(fixtureResult(t, fixture))
		if err != nil || got != want {
			t.Errorf("%s: %v %v, want %v", fixture, got, err, want)
		}
	}
	for name, raw := range map[string]string{
		"no value":      `{"summary": "Access granted: True", "error": null}`,
		"a text value":  `{"value": "True", "error": null}`,
		"an error":      `{"value": true, "error": "boom"}`,
		"not an object": `[]`,
	} {
		if _, err := parseHBACTest(json.RawMessage(raw)); err == nil {
			t.Errorf("%s: read as a proof", name)
		}
	}
}
