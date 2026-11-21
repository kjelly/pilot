package identityreconcile

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/kjelly/pilot/internal/identitylock"
)

// The HBAC writer (Phase 3a, docs/superpowers/specs/2026-11-19-freeipa-go-reconcile-phase3-hbac-spec.md
// §5). ExecuteHBAC carries out an HBAC plan under the lock the run already holds, in the
// stages H1 to H8 of hbac_stage.go, and reads the result back. It is Execute's twin for the
// HBAC rules: the same flow (read, plan, entry, read, plan, stages, read, plan), the same
// outcomes, the same journal and gate, with its own plan and stages. It runs after the
// users and groups of the same run, in the same journal, so its events carry the prefix
// "hbac:" (the id of an event is unique within a run).

// HBACOptions is what ExecuteHBAC needs besides the client and the lock in its context.
type HBACOptions struct {
	// Desired is the roster's HBAC part (HBACFromRoster).
	Desired DesiredHBAC
	// Entry records the authorization cache obligation before the first write. An
	// obligation that is already owed is no problem: the entry says so (Previous).
	Entry Entry
	// Gate is the write gate of the client; ExecuteHBAC opens it after the entry's
	// result was observed and closes it when the run ends, as Execute does.
	Gate *Gate
	// Journal records the run.
	Journal Journal
	// BatchLimit is the most commands per batch, 1 to MaxBatch; 0 is MaxBatch.
	BatchLimit int
	// TestHost is the FreeIPA server's FQDN, the host the lockdown proves admin's access
	// to with hbactest. It is required when the roster asks for the lockdown.
	TestHost string
}

// HBACResult is what an HBAC run did. ExecuteHBAC returns it with every error it also
// returns, so a caller reports the operations and outcomes of a failed run.
type HBACResult struct {
	// Observed: the first read was made and Plan1 was built from it.
	Observed bool      `json:"observed"`
	Plan1    HBACPlan  `json:"plan1"`
	Plan2    *HBACPlan `json:"plan2,omitempty"`
	// Plan3 is the plan made from the read after the writes; nil when there was none.
	Plan3       *HBACPlan   `json:"plan3,omitempty"`
	Entry       EntryReport `json:"entry"`
	PlanChanged PlanChange  `json:"plan_changed"`
	// Conflicts are the destructive operations of Plan₂ that Plan₁ did not hold.
	Conflicts []string     `json:"conflicts,omitempty"`
	Ops       []OpResult   `json:"operations"`
	Stop      *Stop        `json:"stop,omitempty"`
	Verify    Verification `json:"verify"`
	// Lockdown is what the lockdown stage did, nil when the plan had none.
	Lockdown *LockdownReport `json:"lockdown,omitempty"`
	// JournalError is the first event that could not be recorded.
	JournalError string `json:"journal_error,omitempty"`
}

// Committed reports whether the run changed FreeIPA or may have (spec §6.1).
func (r HBACResult) Committed() bool {
	for _, o := range r.Ops {
		if f := o.Final(); f == OutcomeSuccess || f == OutcomeUnknown || o.Completed > 0 {
			return true
		}
	}
	return false
}

// Counts is the number of operations of each outcome, the resolved ones as they ended.
func (r HBACResult) Counts() map[Outcome]int {
	out := map[Outcome]int{}
	for _, o := range r.Ops {
		out[o.Final()]++
	}
	return out
}

// Obligation is whether the authorization cache is owed a refresh after this run: the
// entry ran. The HBAC stage never refreshes by itself; the settle that follows it does.
func (r HBACResult) Obligation() Obligation {
	if r.Entry.Ran {
		return Obligation{Owed: true, Source: ObligationThisRun}
	}
	return Obligation{}
}

// ExecuteHBAC carries out the HBAC plan under the lock in ctx. The context must carry it
// (identitylock.Held.Attach, as for Execute). The flow:
//
//	Read₁, Plan₁; blocked: stop. Nothing to write: stop (no entry, no write).
//	The entry (prepare), its result observed, the gate open.
//	Read₂, Plan₂, the authority from here: blocked or a destructive operation Plan₁ did
//	not have: stop. The stages H1 to H8, each batch after the checks its stage asks for.
//	Read₃ and Plan₃ (Verification), after the writes whatever they ended as.
//
// It returns a nil error only for a run that ended as it planned: nothing to do, or every
// planned operation applied (success or noop, an unknown outcome counting as applied when
// the read after the writes shows it was) and verified. Every other end is an error that
// wraps one of the Err values of execute.go. The result is returned whatever the error.
func ExecuteHBAC(ctx context.Context, rpc RPC, opts HBACOptions) (*HBACResult, error) {
	held, err := identitylock.Require(ctx)
	if err != nil {
		return nil, err
	}
	switch {
	case rpc == nil:
		return nil, errors.New("identityreconcile: no FreeIPA client")
	case opts.Entry == nil, opts.Gate == nil, opts.Journal == nil:
		return nil, errors.New("identityreconcile: ExecuteHBAC needs an Entry, a Gate and a Journal")
	case opts.BatchLimit < 0 || opts.BatchLimit > MaxBatch:
		return nil, fmt.Errorf("identityreconcile: the batch limit is 1 to %d", MaxBatch)
	case opts.Desired.DisableAllowAll && opts.TestHost == "":
		return nil, errors.New("identityreconcile: the lockdown of allow_all needs the host to run hbactest for")
	}
	if opts.BatchLimit == 0 {
		opts.BatchLimit = MaxBatch
	}
	opts.Gate.close()
	defer opts.Gate.close()
	r := &hbacRunner{ctx: ctx, rpc: rpc, opts: opts, held: held, res: &HBACResult{}}
	return r.res, r.run()
}

// hbacRunner is the state of one ExecuteHBAC.
type hbacRunner struct {
	ctx  context.Context
	rpc  RPC
	opts HBACOptions
	held *identitylock.Held
	res  *HBACResult

	obs2    HBACObservation
	created map[string]bool // rules the plan creates (lower case)

	stopped bool
	sent    bool // a write has left
	batches map[HBACStage]int
	covered map[int]bool // operations whose batch or call has a "result" event
}

func (r *hbacRunner) run() error {
	obs1, err := ObserveHBAC(r.ctx, r.rpc)
	if err != nil {
		return fmt.Errorf("read before planning: %w", err)
	}
	r.res.Plan1 = BuildHBAC(HBACInput{Desired: r.opts.Desired, Obs: obs1})
	r.res.Observed = true
	if len(r.res.Plan1.Blocked) > 0 {
		err := hbacBlockedError(r.res.Plan1)
		return r.refuse(stopPlan1, err.Error(), r.res.Plan1, err)
	}
	if r.res.Plan1.Writes() == 0 {
		return nil // nothing to do: no entry, no write
	}

	prep, err := r.opts.Entry.Prepare(r.ctx)
	if err == nil && (prep.Action != AuthCachePrepare || prep.Host != r.held.Host) {
		err = fmt.Errorf("the entry's result is a %q result for %q, not a prepare result for the locked host %q", prep.Action, prep.Host, r.held.Host)
	}
	if err != nil {
		return r.refuse(stopEntry, "the authorization cache entry failed or its result was rejected", r.res.Plan1, fmt.Errorf("%w: %v", ErrEntry, err))
	}
	r.res.Entry = EntryReport{Ran: true, Previous: &prep.Previous}
	if err := r.record(Event{Kind: EventAuthCache, ID: "hbac:auth_cache", Payload: map[string]any{
		"source": ObligationThisRun, "entry_ran": true, "previous": prep.Previous, "observed_acked": false,
	}}); err != nil {
		return r.refuse(stopEntry, "the journal refused the record that the entry ran, so nothing was written", r.res.Plan1,
			errors.New("the authorization cache entry ran but its record could not be written: nothing was written"))
	}
	r.opts.Gate.open(r.held)

	obs2, err := ObserveHBAC(r.ctx, r.rpc)
	if err != nil {
		err = fmt.Errorf("read after the entry (the entry ran, nothing was written): %w", err)
		return r.refuse(stopRead2, err.Error(), r.res.Plan1, err)
	}
	r.obs2 = obs2
	plan2 := BuildHBAC(HBACInput{Desired: r.opts.Desired, Obs: obs2})
	r.res.Plan2 = &plan2
	r.res.PlanChanged = comparePlans(hbacAsPlan(r.res.Plan1), hbacAsPlan(plan2))
	if len(plan2.Blocked) > 0 {
		err := hbacBlockedError(plan2)
		return r.refuse(stopPlan2, err.Error(), plan2, err)
	}
	if conflicts := newDestructiveHBAC(r.res.Plan1, plan2); len(conflicts) > 0 {
		r.res.Conflicts = conflicts
		err := fmt.Errorf("%w: %s", ErrDestructiveDiff, strings.Join(conflicts, ", "))
		return r.refuse(stopPlan2, err.Error(), plan2, err)
	}
	if plan2.Writes() == 0 {
		return nil // the entry ran and there is nothing left to write: a refresh too many, harmless
	}

	r.prepare(plan2)
	r.runStages()
	r.recordNotSent()
	return r.finish()
}

// hbacAsPlan is an HBAC plan as the Plan the comparison helpers of execute.go take.
func hbacAsPlan(p HBACPlan) Plan { return Plan{Operations: p.Operations, Blocked: p.Blocked} }

func hbacBlockedError(p HBACPlan) error { return blockedError(hbacAsPlan(p)) }

// hbacDestructive reports whether an operation is in the set the executor compares
// between Plan₁ and Plan₂: what the plan marks destructive (a member removed, a rule
// deleted) and the narrowing operations that are not data lost but access revoked, which
// an operator reviewing a plan must equally have seen (a rule disabled, allow_all
// disabled).
func hbacDestructive(op Operation) bool {
	switch op.Kind {
	case KindHBACRuleDisable, KindHBACAllowAllDisable:
		return true
	}
	return op.Destructive
}

// newDestructiveHBAC lists the destructive operations of plan2 that plan1 did not hold,
// by kind, object and member (the same comparison newDestructive makes for the users and
// groups).
func newDestructiveHBAC(plan1, plan2 HBACPlan) []string {
	before := keySet(hbacAsPlan(plan1), hbacDestructive)
	var out []string
	for k := range keySet(hbacAsPlan(plan2), hbacDestructive) {
		if !before[k] {
			out = append(out, strings.TrimSuffix(strings.ReplaceAll(k, "|", " "), " "))
		}
	}
	sort.Strings(out)
	return out
}

func (r *hbacRunner) record(ev Event) error {
	err := record(r.ctx, r.opts.Journal, ev)
	if err != nil && r.res.JournalError == "" {
		r.res.JournalError = err.Error()
	}
	return err
}

// refuse ends a run that stops before its first command: the Stop is kept, the journal
// gets the "not_sent" event holding every operation of the plan, and a failure to record
// it is reported beside err.
func (r *hbacRunner) refuse(stage, reason string, plan HBACPlan, err error) error {
	r.res.Stop = &Stop{Stage: stage, Reason: reason}
	ops := make([]OpResult, len(plan.Operations))
	for i, op := range plan.Operations {
		ops[i] = OpResult{Operation: op, Stage: HBACStageOf(op.Kind).String(), Outcome: OutcomeNotExecuted}
	}
	r.recordNotSentOps(ops)
	if r.res.JournalError != "" {
		err = errors.Join(err, fmt.Errorf("%w: %s", ErrJournal, r.res.JournalError))
	}
	return err
}

func (r *hbacRunner) recordNotSentOps(ops []OpResult) {
	parts := chunkOpResults(ops)
	for i, part := range parts {
		ev := notSentEvent{Phase: "not_sent", Stop: r.res.Stop, Operations: part}
		id := "hbac:not_sent"
		if len(parts) > 1 {
			ev.Part, ev.Parts = i+1, len(parts)
			if i > 0 {
				id = fmt.Sprintf("hbac:not_sent:%d", i+1)
			}
		}
		_ = r.record(Event{Kind: EventOp, ID: id, Payload: ev})
	}
}

// recordNotSent writes the "not_sent" event of a run that went through the stages: every
// operation that is not in a batch or call that was sent and has its result recorded.
func (r *hbacRunner) recordNotSent() {
	var ops []OpResult
	for i, o := range r.res.Ops {
		if !r.covered[i] {
			ops = append(ops, o)
		}
	}
	if len(ops) == 0 {
		return
	}
	r.recordNotSentOps(ops)
}

// prepare sets up the state the stages share from Plan₂: one result per operation, not
// executed until something says otherwise.
func (r *hbacRunner) prepare(plan2 HBACPlan) {
	r.created = map[string]bool{}
	r.batches = map[HBACStage]int{}
	r.covered = map[int]bool{}
	for _, op := range plan2.Operations {
		r.res.Ops = append(r.res.Ops, OpResult{Operation: op, Stage: HBACStageOf(op.Kind).String(), Outcome: OutcomeNotExecuted})
		if op.Kind == KindHBACRuleCreate {
			r.created[lower(op.Object)] = true
		}
	}
}

// stopAt ends the scheduling: what is not sent stays not executed. The first reason is
// the one kept.
func (r *hbacRunner) stopAt(s HBACStage, reason string) {
	r.stopped = true
	if r.res.Stop == nil {
		r.res.Stop = &Stop{Stage: s.String(), Reason: reason}
	}
}

func (r *hbacRunner) settle(i int, c classified) {
	o := &r.res.Ops[i]
	o.Outcome, o.Completed, o.Error, o.Detail = c.Outcome, c.Completed, c.Error, c.Detail
}

func (r *hbacRunner) conflict(i int, detail string) {
	r.settle(i, classified{Outcome: OutcomeConflictFailed, Detail: detail})
}

// finish reads the result back and ends the run: the verdict is the writes' and the
// verification's, and the journal's last event says it.
func (r *hbacRunner) finish() error {
	r.verify()
	var errs []error
	counts := r.res.Counts()
	applied := counts[OutcomeConflictFailed]+counts[OutcomeFailed]+counts[OutcomeUnknown]+counts[OutcomeNotExecuted] == 0
	if !applied {
		errs = append(errs, fmt.Errorf("%w: %s", ErrWrites, r.writesSummary()))
	}
	if r.res.Verify.Done && !r.res.Verify.OK() {
		errs = append(errs, fmt.Errorf("%w: %s", ErrVerify, r.verifySummary()))
	}
	r.recordVerify(len(errs) == 0 && r.res.JournalError == "", applied)
	if r.res.JournalError != "" {
		errs = append(errs, fmt.Errorf("%w: %s", ErrJournal, r.res.JournalError))
	}
	return errors.Join(errs...)
}

func (r *hbacRunner) writesSummary() string {
	counts := r.res.Counts()
	var parts []string
	for _, o := range []Outcome{OutcomeSuccess, OutcomeNoop, OutcomeConflictFailed, OutcomeFailed, OutcomeUnknown, OutcomeNotExecuted} {
		if counts[o] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[o], o))
		}
	}
	s := strings.Join(parts, ", ")
	if r.res.Stop != nil {
		s += fmt.Sprintf("; stopped at %s: %s", r.res.Stop.Stage, r.res.Stop.Reason)
	}
	return s
}

func (r *hbacRunner) verifySummary() string {
	v := r.res.Verify
	if v.ReadError != "" {
		return "the read failed: " + v.ReadError
	}
	var parts []string
	if len(v.Remaining) > 0 {
		parts = append(parts, fmt.Sprintf("%d operation(s) still planned on objects this run changed: %s", len(v.Remaining), strings.Join(v.Remaining, ", ")))
	}
	if len(v.Blocked) > 0 {
		parts = append(parts, fmt.Sprintf("%d object(s) this run changed are blocked in the read after the writes: %s", len(v.Blocked), strings.Join(v.Blocked, ", ")))
	}
	return strings.Join(parts, "; ")
}

// attempted is the set of objects the run tried to change: the object of every operation
// that was not left unexecuted.
func (r *hbacRunner) attempted() map[string]bool {
	out := map[string]bool{}
	for _, o := range r.res.Ops {
		if o.Outcome != OutcomeNotExecuted {
			out[lower(o.Operation.Object)] = true
		}
	}
	return out
}

// touched is the set of objects the run changed or may have: an operation that was
// applied, changed a member, or has an outcome that is still unknown.
func (r *hbacRunner) touched() map[string]bool {
	out := map[string]bool{}
	for _, o := range r.res.Ops {
		if f := o.Final(); f == OutcomeSuccess || f == OutcomeUnknown || o.Completed > 0 {
			out[lower(o.Operation.Object)] = true
		}
	}
	return out
}

// verify is Read₃ and Plan₃: it reads the whole HBAC state again, on a context detached
// from the run's cancellation and bounded by VerifyTimeout, plans again, and resolves the
// operations whose outcome was unknown. It reads only when something was sent.
func (r *hbacRunner) verify() {
	if !r.sent {
		return
	}
	r.res.Verify.Done = true
	rctx, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), VerifyTimeout)
	defer cancel()
	obs3, err := ObserveHBAC(rctx, r.rpc)
	if err != nil {
		r.res.Verify.ReadError = err.Error()
		for i := range r.res.Ops {
			if r.res.Ops[i].Outcome == OutcomeUnknown {
				r.res.Ops[i].Resolution = resolutionStillUnknown
			}
		}
		return
	}
	plan3 := BuildHBAC(HBACInput{Desired: r.opts.Desired, Obs: obs3})
	r.res.Plan3 = &plan3
	attempted := r.attempted()
	for _, op := range plan3.Operations {
		if attempted[lower(op.Object)] {
			r.res.Verify.Remaining = append(r.res.Verify.Remaining, op.ID)
		} else {
			r.res.Verify.Unrelated = append(r.res.Verify.Unrelated, op.ID)
		}
	}
	// A blocked object has no operation in the plan: what the run changed, or may have,
	// and the plan blocks is left undone.
	touched := r.touched()
	blocked := map[string]bool{}
	for _, b := range plan3.Blocked {
		if touched[lower(b.Object)] {
			blocked[lower(b.Object)] = true
			r.res.Verify.Blocked = append(r.res.Verify.Blocked, b.Reason+" "+b.Object)
		}
	}
	r.resolveUnknown(plan3, blocked)
}

// resolveUnknown classifies each unknown outcome from the plan made after the writes:
// converged when the plan no longer holds it, not applied when it still holds all of it,
// and still unknown when that cannot be said (a partly held member operation, a blocked
// object).
func (r *hbacRunner) resolveUnknown(plan3 HBACPlan, blocked map[string]bool) {
	left := keySet(hbacAsPlan(plan3), func(Operation) bool { return true })
	for i := range r.res.Ops {
		o := &r.res.Ops[i]
		if o.Outcome != OutcomeUnknown {
			continue
		}
		if blocked[lower(o.Operation.Object)] {
			o.Resolution = resolutionStillUnknown
			o.Detail = strings.TrimSpace(o.Detail + " (the read after the writes blocks this object, so it cannot be said whether the operation applied)")
			continue
		}
		keys := opKeys(o.Operation)
		still := 0
		for _, k := range keys {
			if left[k] {
				still++
			}
		}
		switch {
		case still == 0:
			o.Resolution = resolutionConverged
		case still == len(keys):
			o.Resolution = resolutionNotApplied
		default:
			o.Resolution = resolutionStillUnknown
		}
	}
}

// recordVerify writes hbac:verify, the last event of a run that went through the stages.
func (r *hbacRunner) recordVerify(ok, writesOK bool) {
	v := r.res.Verify
	resolutions := map[string]string{}
	for _, o := range r.res.Ops {
		if o.Resolution != "" {
			resolutions[o.Operation.ID] = o.Resolution
		}
	}
	_ = r.record(Event{Kind: EventVerify, ID: "hbac:verify", Payload: map[string]any{
		"ok": ok, "writes_ok": writesOK, "read_done": v.Done, "read_error": v.ReadError,
		"remaining": boundedList(v.Remaining), "remaining_total": len(v.Remaining),
		"blocked": boundedList(v.Blocked), "blocked_total": len(v.Blocked),
		"unrelated": boundedList(v.Unrelated), "unrelated_total": len(v.Unrelated),
		"unknown_resolved": resolutions, "stop": r.res.Stop, "lockdown": r.res.Lockdown,
	}})
}
