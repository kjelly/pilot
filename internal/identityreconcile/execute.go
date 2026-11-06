package identityreconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/kjelly/pilot/internal/freeiparpc"
	"github.com/kjelly/pilot/internal/identitylock"
)

// The Go writer (spec §7). Execute carries out a plan under a lock the run already
// holds, in the stages of stage.go, and reads the result back. It has no entry
// point in this change: nothing in cmd calls it (P2-6 wires it into the
// users-groups scope, P2-7 into the mixed run), and a test fails if anything outside
// this package does.

// MaxBatch is the most commands the executor puts in one batch (spec §7.3; the
// value is a first estimate that the performance work of P2-8 may change, the rest
// of the rules do not depend on it).
const MaxBatch = 25

// VerifyTimeout bounds the read after the writes, which runs on a context detached
// from the run's cancellation: after Ctrl-C, --timeout or a lost lock the run still
// reads once to say what it left (spec §4.4, E3).
const VerifyTimeout = 60 * time.Second

// What ended a run that did not apply its plan. Execute wraps them, so a caller
// tells them apart with errors.Is and reads the details from the Result.
var (
	// ErrBlocked: the plan, made before or after the entry, has blocked objects.
	// Nothing was written.
	ErrBlocked = errors.New("the plan has blocked objects: nothing was written")
	// ErrDestructiveDiff: the plan made after the entry holds a destructive
	// operation the first plan did not: nothing was written. The operator reviewed
	// the first plan, and a run does not confirm a destructive one nobody saw.
	ErrDestructiveDiff = errors.New("the plan made after the authorization cache entry holds destructive operations that the first plan did not: nothing was written; preview again")
	// ErrEntry: the authorization cache entry failed or its result was rejected.
	// Nothing was written.
	ErrEntry = errors.New("the authorization cache entry failed: nothing was written")
	// ErrWrites: an operation did not end as success or noop, or the writes stopped.
	ErrWrites = errors.New("not every planned operation was applied")
	// ErrVerify: the read after the writes failed, or it still shows an operation
	// on an object the run changed.
	ErrVerify = errors.New("the read after the writes does not show what was applied")
	// ErrJournal: an event of the run could not be recorded. Before the first write
	// that stops the run; after it the run is finished and reported as failed.
	ErrJournal = errors.New("the run journal could not be written")
)

// RPC is the FreeIPA client the executor reads and writes with:
// *freeiparpc.Client. The client must be built with a WriteGate (freeiparpc.New
// refuses one without), and the Gate of Options is what it should be built with;
// the executor also asks the Gate itself before every write.
type RPC interface {
	Finder
	Call(ctx context.Context, cmd freeiparpc.Command) (json.RawMessage, error)
	Batch(ctx context.Context, cmds []freeiparpc.Command) ([]freeiparpc.BatchItem, error)
}

// Options is what Execute needs besides the client and the lock in its context.
type Options struct {
	// Desired is the roster's users and groups, with its password forms read
	// (FromRosterWithForms).
	Desired Desired
	// Passwords gives the password of a user whose plan has a password operation.
	Passwords PasswordSource
	// Entry records the authorization cache obligation before the first write.
	Entry Entry
	// Gate is the write gate of the client. Execute opens it after the entry's
	// result was observed, and closes it when the run ends.
	Gate *Gate
	// Journal records the run.
	Journal Journal
	// ProbeWhenIdle: when the first plan has nothing to write, read the
	// obligation with the entry's probe (the users-groups scope: spec §7.2 step 3).
	ProbeWhenIdle bool
	// BatchLimit is the most commands per batch, 1 to MaxBatch; 0 is MaxBatch.
	BatchLimit int
}

// EntryReport is what the entry did or found.
type EntryReport struct {
	// Ran: prepare ran and its result was accepted: the obligation is recorded.
	Ran bool `json:"ran"`
	// Previous: the obligation was already owed before this run's prepare.
	Previous *bool `json:"previous,omitempty"`
	// Pending: what the probe of an idle run found (nil when it did not run).
	Pending *bool `json:"pending,omitempty"`
}

// OpResult is one planned operation and what became of it.
type OpResult struct {
	Operation Operation `json:"operation"`
	Stage     string    `json:"stage"`
	Outcome   Outcome   `json:"outcome"`
	// Completed is how many members a member command changed.
	Completed int `json:"completed,omitempty"`
	// Error is FreeIPA's error name and code, or "not sent" or "outcome unknown".
	Error  string `json:"error,omitempty"`
	Detail string `json:"detail,omitempty"`
	// Resolution is what the read after the writes made of an unknown outcome:
	// converged, not-applied or still-unknown.
	Resolution string `json:"resolution,omitempty"`
}

// Final is the outcome once the read after the writes has resolved an unknown one:
// converged counts as applied, not-applied as failed, and still-unknown stays
// unknown.
func (r OpResult) Final() Outcome {
	if r.Outcome != OutcomeUnknown {
		return r.Outcome
	}
	switch r.Resolution {
	case resolutionConverged:
		return OutcomeSuccess
	case resolutionNotApplied:
		return OutcomeFailed
	}
	return OutcomeUnknown
}

// How the read after the writes classifies an unknown outcome (spec §7.5).
const (
	resolutionConverged    = "converged"
	resolutionNotApplied   = "not-applied"
	resolutionStillUnknown = "still-unknown"
)

// Stop says where the executor stopped scheduling and why.
type Stop struct {
	Stage  string `json:"stage"`
	Reason string `json:"reason"`
}

// Verification is the read after the writes and the plan made from it.
type Verification struct {
	// Done: the read was attempted (it is not when nothing was sent).
	Done bool `json:"done"`
	// ReadError is why it failed, "" when it did not.
	ReadError string `json:"read_error,omitempty"`
	// Remaining are the operations the plan made from that read still holds on the
	// objects this run tried to change: Plan₃ is not empty in the spec's sense.
	Remaining []string `json:"remaining,omitempty"`
	// Unrelated are the operations it holds on other objects: drift that is not a
	// result of this run's writes. It does not fail the verification.
	Unrelated []string `json:"unrelated,omitempty"`
}

// OK reports whether the read was done, succeeded and shows nothing left on what
// the run changed.
func (v Verification) OK() bool { return v.Done && v.ReadError == "" && len(v.Remaining) == 0 }

// PlanChange is how the plan made after the entry differs from the first one.
type PlanChange struct {
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
}

// Result is what a run did. Execute returns it with every error it also returns,
// so a caller reports the operations and outcomes of a failed run.
type Result struct {
	Plan1 Plan  `json:"plan1"`
	Plan2 *Plan `json:"plan2,omitempty"`
	// Plan3 is the plan made from the read after the writes; nil when there was no
	// such read or it failed.
	Plan3       *Plan       `json:"plan3,omitempty"`
	Entry       EntryReport `json:"entry"`
	PlanChanged PlanChange  `json:"plan_changed"`
	// Conflicts are the destructive operations of Plan₂ that Plan₁ did not hold.
	Conflicts []string     `json:"conflicts,omitempty"`
	Ops       []OpResult   `json:"operations"`
	Stop      *Stop        `json:"stop,omitempty"`
	Verify    Verification `json:"verify"`
	// JournalError is the first event that could not be recorded.
	JournalError string `json:"journal_error,omitempty"`
}

// Committed reports whether the run changed FreeIPA or may have: an operation
// that succeeded, a member command that changed a member, or an unknown outcome.
// It is the condition for calling a failed run partial (spec §6.1, E4).
func (r Result) Committed() bool {
	for _, o := range r.Ops {
		// Final, not Outcome: an unknown outcome that the read after the writes
		// showed was not applied did not change anything.
		if f := o.Final(); f == OutcomeSuccess || f == OutcomeUnknown || o.Completed > 0 {
			return true
		}
	}
	return false
}

// Counts is the number of operations of each outcome, the resolved ones as they
// ended.
func (r Result) Counts() map[Outcome]int {
	out := map[Outcome]int{}
	for _, o := range r.Ops {
		out[o.Final()]++
	}
	return out
}

// Execute carries out the users and groups plan under the lock in ctx. The context
// must carry it (identitylock.Held.Attach: not Bind, whose cancellation would turn
// an in-flight write into an unknown outcome and hide the answer it got). The steps
// are the flow of spec §7.2 and the stages of §7.3:
//
//	Read₁, Plan₁; blocked: stop. Nothing to write: stop (or probe, ProbeWhenIdle).
//	The entry (prepare), its result observed, the gate open.
//	Read₂, Plan₂, the authority from here: blocked or a destructive operation Plan₁
//	did not have: stop. The stages, each batch after the checks its stage asks for.
//	Read₃ and Plan₃ (Verification), after the writes whatever they ended as.
//
// It returns a nil error only for a run that ended as it planned: nothing to do, or
// everything applied and verified. Every other end is an error that wraps one of
// the Err values above. The Result is returned whatever the error.
func Execute(ctx context.Context, rpc RPC, opts Options) (*Result, error) {
	held, err := identitylock.Require(ctx)
	if err != nil {
		return nil, err
	}
	switch {
	case rpc == nil:
		return nil, errors.New("identityreconcile: no FreeIPA client")
	case opts.Entry == nil, opts.Gate == nil, opts.Journal == nil:
		return nil, errors.New("identityreconcile: Execute needs an Entry, a Gate and a Journal")
	case opts.Desired.Principal == "":
		return nil, errors.New("identityreconcile: the desired state has no login principal")
	case opts.BatchLimit < 0 || opts.BatchLimit > MaxBatch:
		return nil, fmt.Errorf("identityreconcile: the batch limit is 1 to %d", MaxBatch)
	}
	if opts.BatchLimit == 0 {
		opts.BatchLimit = MaxBatch
	}
	opts.Gate.close()
	defer opts.Gate.close()
	r := &runner{ctx: ctx, rpc: rpc, opts: opts, held: held, res: &Result{}, des: opts.Desired}
	return r.res, r.run()
}

// runner is the state of one Execute.
type runner struct {
	ctx  context.Context
	rpc  RPC
	opts Options
	held *identitylock.Held
	res  *Result
	des  Desired

	dx      desiredIndex
	obs2    Observation
	users2  map[string]LiveUser // Plan₂'s observation: the identity a delete is checked against
	groups2 map[string]LiveGroup
	created map[string]bool // users the plan creates in S3

	stopped bool
	sent    bool // a command has left
	batches map[Stage]int
}

func (r *runner) principal() string { return strings.ToLower(r.opts.Desired.Principal) }

func (r *runner) run() error {
	obs1, err := Observe(r.ctx, r.rpc, r.opts.Desired.Principal)
	if err != nil {
		return fmt.Errorf("read before planning: %w", err)
	}
	r.res.Plan1 = Build(r.des, obs1.Users, obs1.Groups)
	if len(r.res.Plan1.Blocked) > 0 {
		return blockedError(r.res.Plan1)
	}
	if r.res.Plan1.Writes() == 0 {
		return r.idle()
	}

	prep, err := r.opts.Entry.Prepare(r.ctx)
	if err == nil && (prep.Action != AuthCachePrepare || prep.Host != r.held.Host) {
		// An Entry that is not AuthCacheEntry is held to the same: the result is for
		// the host this run holds, and is a prepare's.
		err = fmt.Errorf("the entry's result is a %q result for %q, not a prepare result for the locked host %q", prep.Action, prep.Host, r.held.Host)
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrEntry, err)
	}
	r.res.Entry = EntryReport{Ran: true, Previous: &prep.Previous}
	if err := r.record(Event{Kind: EventAuthCache, ID: "auth_cache", Payload: map[string]any{
		"source": "this_run", "entry_ran": true, "previous": prep.Previous,
	}}); err != nil {
		// Nothing has been written yet: no write without the record of the run.
		return fmt.Errorf("%w: %v", ErrJournal, err)
	}
	r.opts.Gate.open(r.held)

	obs2, err := Observe(r.ctx, r.rpc, r.opts.Desired.Principal)
	if err != nil {
		return fmt.Errorf("read after the entry (the entry ran, nothing was written): %w", err)
	}
	r.obs2 = obs2
	plan2 := Build(r.des, obs2.Users, obs2.Groups)
	r.res.Plan2 = &plan2
	r.res.PlanChanged = comparePlans(r.res.Plan1, plan2)
	if len(plan2.Blocked) > 0 {
		return blockedError(plan2)
	}
	if conflicts := newDestructive(r.res.Plan1, plan2); len(conflicts) > 0 {
		r.res.Conflicts = conflicts
		return fmt.Errorf("%w: %s", ErrDestructiveDiff, strings.Join(conflicts, ", "))
	}
	if plan2.Writes() == 0 {
		return nil // the entry ran and there is nothing left to write: a refresh too many, harmless
	}

	r.prepare(plan2)
	r.runStages()
	return r.finish()
}

// idle ends a run whose first plan has nothing to write: no entry, no write. With
// ProbeWhenIdle it reads the obligation the way the users-groups scope reports it.
func (r *runner) idle() error {
	if !r.opts.ProbeWhenIdle {
		return nil
	}
	res, err := r.opts.Entry.Probe(r.ctx)
	if err == nil && (res.Action != AuthCacheProbe || res.Host != r.held.Host) {
		err = fmt.Errorf("the entry's result is a %q result for %q, not a probe result for the locked host %q", res.Action, res.Host, r.held.Host)
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrEntry, err)
	}
	r.res.Entry = EntryReport{Pending: &res.Pending}
	if err := r.record(Event{Kind: EventAuthCache, ID: "auth_cache", Payload: map[string]any{
		"source": "previous_run", "entry_ran": false, "probe_pending": res.Pending,
	}}); err != nil {
		return fmt.Errorf("%w: %v", ErrJournal, err)
	}
	return nil
}

// record writes one event to the journal on a detached, bounded context and
// remembers the first failure.
func (r *runner) record(ev Event) error {
	err := record(r.ctx, r.opts.Journal, ev)
	if err != nil && r.res.JournalError == "" {
		r.res.JournalError = err.Error()
	}
	return err
}

func blockedError(p Plan) error {
	parts := make([]string, 0, len(p.Blocked))
	for _, b := range p.Blocked {
		parts = append(parts, b.Reason+" "+b.Object)
	}
	return fmt.Errorf("%w: %s", ErrBlocked, strings.Join(parts, ", "))
}

// opKey is how two plans' operations are compared, member by member for the
// operations that name members: a removal of one more member is another removal.
func opKeys(op Operation) []string {
	if len(op.Members) == 0 {
		return []string{op.Kind + "|" + op.Object + "|"}
	}
	keys := make([]string, 0, len(op.Members))
	for _, m := range op.Members {
		keys = append(keys, op.Kind+"|"+op.Object+"|"+m)
	}
	return keys
}

func keySet(p Plan, keep func(Operation) bool) map[string]bool {
	out := map[string]bool{}
	for _, op := range p.Operations {
		if keep(op) {
			for _, k := range opKeys(op) {
				out[k] = true
			}
		}
	}
	return out
}

// newDestructive lists the destructive operations of plan2 that plan1 did not hold,
// by kind, object and member (spec §7.3, the rule that compares the two plans).
func newDestructive(plan1, plan2 Plan) []string {
	before := keySet(plan1, func(op Operation) bool { return destructiveKind(op.Kind) })
	var out []string
	for k := range keySet(plan2, func(op Operation) bool { return destructiveKind(op.Kind) }) {
		if !before[k] {
			out = append(out, strings.TrimSuffix(strings.ReplaceAll(k, "|", " "), " "))
		}
	}
	sort.Strings(out)
	return out
}

// comparePlans reports every operation, destructive or not, that one plan has and
// the other does not (the plan_changed of spec §6.2).
func comparePlans(plan1, plan2 Plan) PlanChange {
	all := func(Operation) bool { return true }
	k1, k2 := keySet(plan1, all), keySet(plan2, all)
	var c PlanChange
	for k := range k2 {
		if !k1[k] {
			c.Added = append(c.Added, strings.TrimSuffix(strings.ReplaceAll(k, "|", " "), " "))
		}
	}
	for k := range k1 {
		if !k2[k] {
			c.Removed = append(c.Removed, strings.TrimSuffix(strings.ReplaceAll(k, "|", " "), " "))
		}
	}
	sort.Strings(c.Added)
	sort.Strings(c.Removed)
	return c
}

// prepare sets up the state the stages share from Plan₂: one result per operation,
// not executed until something says otherwise, the observation deletes are
// compared with, and the users the plan creates.
func (r *runner) prepare(plan2 Plan) {
	r.users2 = map[string]LiveUser{}
	for _, u := range r.obs2.Users {
		r.users2[u.Name] = u
	}
	r.groups2 = map[string]LiveGroup{}
	for _, g := range r.obs2.Groups {
		r.groups2[g.Name] = g
	}
	r.created = map[string]bool{}
	r.batches = map[Stage]int{}
	for _, op := range plan2.Operations {
		s := StageOf(op.Kind)
		r.res.Ops = append(r.res.Ops, OpResult{Operation: op, Stage: s.String(), Outcome: OutcomeNotExecuted})
		if op.Kind == KindUserCreate {
			r.created[op.Object] = true
		}
	}
}

// stopAt ends the scheduling: what is not sent stays not executed. The first reason
// is the one kept.
func (r *runner) stopAt(s Stage, reason string) {
	r.stopped = true
	if r.res.Stop == nil {
		r.res.Stop = &Stop{Stage: s.String(), Reason: reason}
	}
}

// settle records what became of operation i.
func (r *runner) settle(i int, c classified) {
	o := &r.res.Ops[i]
	o.Outcome, o.Completed, o.Error, o.Detail = c.Outcome, c.Completed, c.Error, c.Detail
}

func (r *runner) conflict(i int, detail string) {
	r.settle(i, classified{Outcome: OutcomeConflictFailed, Detail: detail})
}

// finish reads the result back and ends the run: the verdict is the writes' and the
// verification's.
func (r *runner) finish() error {
	r.verify()
	var errs []error
	counts := r.res.Counts()
	if r.res.Stop != nil || counts[OutcomeConflictFailed]+counts[OutcomeFailed]+counts[OutcomeUnknown]+counts[OutcomeNotExecuted] > 0 {
		errs = append(errs, fmt.Errorf("%w: %s", ErrWrites, r.writesSummary()))
	}
	if r.res.Verify.Done && !r.res.Verify.OK() {
		errs = append(errs, fmt.Errorf("%w: %s", ErrVerify, r.verifySummary()))
	}
	if r.res.JournalError != "" {
		errs = append(errs, fmt.Errorf("%w: %s", ErrJournal, r.res.JournalError))
	}
	return errors.Join(errs...)
}

func (r *runner) writesSummary() string {
	counts := r.res.Counts()
	parts := []string{}
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

func (r *runner) verifySummary() string {
	v := r.res.Verify
	if v.ReadError != "" {
		return "the read failed: " + v.ReadError
	}
	return fmt.Sprintf("%d operation(s) still planned on objects this run changed: %s", len(v.Remaining), strings.Join(v.Remaining, ", "))
}

// attempted is the set of objects the run tried to change: the object of every
// operation that was not left unexecuted.
func (r *runner) attempted() map[string]bool {
	out := map[string]bool{}
	for _, o := range r.res.Ops {
		if o.Outcome != OutcomeNotExecuted {
			out[o.Operation.Object] = true
		}
	}
	return out
}

// verify is Read₃ and Plan₃ (spec §7.6): it reads the whole managed state again,
// on a context detached from the run's cancellation and bounded by VerifyTimeout,
// plans again, and resolves the operations whose outcome was unknown. It reads only
// when something was sent; a run that stopped before its first command has nothing
// to verify.
func (r *runner) verify() {
	if !r.sent {
		return
	}
	r.res.Verify.Done = true
	rctx, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), VerifyTimeout)
	defer cancel()
	obs3, err := Observe(rctx, r.rpc, r.opts.Desired.Principal)
	if err != nil {
		r.res.Verify.ReadError = err.Error()
		for i := range r.res.Ops {
			if r.res.Ops[i].Outcome == OutcomeUnknown {
				r.res.Ops[i].Resolution = resolutionStillUnknown
			}
		}
		r.recordVerify()
		return
	}
	plan3 := Build(r.des, obs3.Users, obs3.Groups)
	r.res.Plan3 = &plan3
	attempted := r.attempted()
	for _, op := range plan3.Operations {
		if attempted[op.Object] {
			r.res.Verify.Remaining = append(r.res.Verify.Remaining, op.ID)
		} else {
			r.res.Verify.Unrelated = append(r.res.Verify.Unrelated, op.ID)
		}
	}
	r.resolveUnknown(plan3, obs3)
	r.recordVerify()
}

// resolveUnknown classifies each unknown outcome from the plan made after the
// writes (spec §7.5): the operation is converged when the plan no longer holds it,
// not applied when the plan still holds all of it, and still unknown when that
// cannot be said: a password (its value cannot be compared; the timestamps are only
// a hint), or an operation whose members the plan holds in part.
func (r *runner) resolveUnknown(plan3 Plan, obs3 Observation) {
	left := keySet(plan3, func(Operation) bool { return true })
	for i := range r.res.Ops {
		o := &r.res.Ops[i]
		if o.Outcome != OutcomeUnknown {
			continue
		}
		if isPasswordKind(o.Operation.Kind) {
			o.Resolution = resolutionStillUnknown
			o.Detail = strings.TrimSpace(o.Detail + " " + passwordHint(o.Operation, obs3))
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

// passwordHint is what the timestamps say about a password whose outcome is
// unknown. It is a hint, never a verdict: the value cannot be read back (§7.5).
func passwordHint(op Operation, obs Observation) string {
	for _, u := range obs.Users {
		if u.Name != op.Object {
			continue
		}
		switch {
		case op.Kind == KindPasswordInitialize && u.LastPwdChange != "":
			return "(hint: krblastpwdchange is now set, so the password may have been set)"
		case op.Kind == KindPasswordInitialize:
			return "(hint: krblastpwdchange is still not set, so the password was probably not set)"
		case onResetPassword(u):
			return "(hint: the user is on a reset password, so a reset may have happened)"
		default:
			return "(hint: the user is not on a reset password)"
		}
	}
	return ""
}

// recordVerify writes the verification event.
func (r *runner) recordVerify() {
	v := r.res.Verify
	resolutions := map[string]string{}
	for _, o := range r.res.Ops {
		if o.Resolution != "" {
			resolutions[o.Operation.ID] = o.Resolution
		}
	}
	_ = r.record(Event{Kind: EventVerify, ID: "verify", Payload: map[string]any{
		"ok": v.OK(), "read_error": v.ReadError, "remaining": v.Remaining, "unrelated": v.Unrelated, "unknown_resolved": resolutions,
	}})
}

// sortedKeys is the keys of m in order.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// showEntry is the user or group entry of a show item: the item's result object
// holds it under "result" (captured, K19).
func showEntry(item json.RawMessage) (map[string]any, error) {
	var r struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(item, &r); err != nil || r.Result == nil {
		return nil, errors.New("the show answer has no entry")
	}
	return r.Result, nil
}
