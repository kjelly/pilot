package delivery

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/store"
)

type fakeWriter struct {
	events []store.Event
	finish store.RunFinished
	err    error
}

func (w *fakeWriter) AppendEvent(_ context.Context, event store.Event) error {
	if w.err != nil {
		return w.err
	}
	w.events = append(w.events, event)
	return nil
}
func (w *fakeWriter) Finish(_ context.Context, finish store.RunFinished) error {
	w.finish = finish
	return nil
}

func TestTransactionSuccessRunsOrderedSteps(t *testing.T) {
	var calls []string
	step := func(name string) StepFunc {
		return func(context.Context) error { calls = append(calls, name); return nil }
	}
	w := &fakeWriter{}
	outcome, err := (Transaction{Writer: w, Preflight: step("preflight"), Preview: step("preview"), Apply: step("apply"), Verify: step("verify"), Idempotency: step("idempotency"), IdempotencyPolicy: IdempotencyAlways}).Run(context.Background())
	if err != nil || outcome != OutcomeSuccess {
		t.Fatalf("outcome=%s err=%v", outcome, err)
	}
	if got := len(calls); got != 5 {
		t.Fatalf("calls=%v", calls)
	}
	if w.finish.Outcome != string(OutcomeSuccess) || len(w.events) != 5 {
		t.Fatalf("finish=%+v events=%+v", w.finish, w.events)
	}
}

func TestTransactionVerifyFailureRollsBack(t *testing.T) {
	var calls []string
	step := func(name string, err error) StepFunc {
		return func(context.Context) error { calls = append(calls, name); return err }
	}
	outcome, err := (Transaction{Apply: step("apply", nil), Verify: step("verify", errors.New("bad row")), Rollback: step("rollback", nil), RollbackPolicy: RollbackPlaybook}).Run(context.Background())
	if outcome != OutcomeRolledBack || err == nil {
		t.Fatalf("outcome=%s err=%v", outcome, err)
	}
	if len(calls) != 3 || calls[2] != "rollback" {
		t.Fatalf("calls=%v", calls)
	}
}

func TestTransactionEvidenceFailureFailsClosed(t *testing.T) {
	w := &fakeWriter{err: errors.New("sqlite down")}
	outcome, err := (Transaction{Writer: w, Apply: func(context.Context) error { return nil }}).Run(context.Background())
	if outcome != OutcomeEvidenceFailed || err == nil {
		t.Fatalf("outcome=%s err=%v", outcome, err)
	}
}

func TestTransactionCancellationAndAuthorizationHaveDistinctOutcomes(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want Outcome
	}{
		{name: "cancelled", err: ErrCancelled, want: OutcomeCancelled},
		{name: "authorization", err: ErrAuthorizationRequired, want: OutcomeAuthorizationRequired},
	} {
		t.Run(test.name, func(t *testing.T) {
			writer := &fakeWriter{}
			outcome, err := (Transaction{Writer: writer, Preflight: func(context.Context) error { return test.err }}).Run(context.Background())
			if outcome != test.want || !errors.Is(err, test.err) {
				t.Fatalf("outcome=%s err=%v", outcome, err)
			}
			if writer.finish.Outcome != string(test.want) {
				t.Fatalf("finish=%+v", writer.finish)
			}
		})
	}
}

func TestTransactionStageIdempotencyPolicy(t *testing.T) {
	for _, stage := range []string{"sandbox", "staging", "prod"} {
		t.Run(stage, func(t *testing.T) {
			calls := 0
			_, err := (Transaction{Stage: stage, IdempotencyPolicy: IdempotencyStageGTEStaging, Idempotency: func(context.Context) error { calls++; return nil }}).Run(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if stage != "sandbox" {
				want = 1
			}
			if calls != want {
				t.Fatalf("calls=%d want=%d", calls, want)
			}
		})
	}
}

func TestOutcomeExitCodeTreatsRollbackAsFailedTransaction(t *testing.T) {
	if got := outcomeExitCode(OutcomeRolledBack); got != 1 {
		t.Fatalf("rolled_back exit=%d want 1", got)
	}
	if got := outcomeExitCode(OutcomeCancelled); got != 0 {
		t.Fatalf("cancelled exit=%d want 0", got)
	}
}

// TestRunResultReportsFailedStep locks the outbound webhook's
// FailureInfo.Phase source (design spec §19, §10): RunResult must name
// exactly which step failed, and Run (kept for every pre-existing
// caller) must still return the identical Outcome/error RunResult does.
func TestRunResultReportsFailedStep(t *testing.T) {
	failing := func(name string) error { return errors.New(name + " boom") }
	cases := []struct {
		name        string
		txn         Transaction
		wantStep    string
		wantOutcome Outcome
	}{
		{
			name:        "verify failure with no rollback",
			txn:         Transaction{Apply: func(context.Context) error { return nil }, Verify: func(context.Context) error { return failing("verify") }},
			wantStep:    "verify",
			wantOutcome: OutcomeFailed,
		},
		{
			name: "apply failure with rollback",
			txn: Transaction{
				Apply:          func(context.Context) error { return failing("apply") },
				RollbackPolicy: RollbackSnapshot,
				Rollback:       func(context.Context) error { return nil },
			},
			wantStep:    "apply",
			wantOutcome: OutcomeRolledBack,
		},
		{
			name: "rollback itself fails",
			txn: Transaction{
				Apply:          func(context.Context) error { return failing("apply") },
				RollbackPolicy: RollbackSnapshot,
				Rollback:       func(context.Context) error { return failing("rollback") },
			},
			wantStep:    "rollback",
			wantOutcome: OutcomeRollbackFailed,
		},
		{
			name:        "preflight failure",
			txn:         Transaction{Preflight: func(context.Context) error { return failing("preflight") }},
			wantStep:    "preflight",
			wantOutcome: OutcomeFailed,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result, err := c.txn.RunResult(context.Background())
			if err == nil {
				t.Fatal("expected an error")
			}
			if result.Outcome != c.wantOutcome {
				t.Fatalf("Outcome = %s, want %s", result.Outcome, c.wantOutcome)
			}
			if result.FailedStep != c.wantStep {
				t.Fatalf("FailedStep = %q, want %q", result.FailedStep, c.wantStep)
			}
			// Run must return the exact same Outcome/error RunResult does.
			outcome2, err2 := c.txn.Run(context.Background())
			if outcome2 != c.wantOutcome {
				t.Fatalf("Run outcome = %s, want %s", outcome2, c.wantOutcome)
			}
			if (err2 == nil) != (err == nil) {
				t.Fatalf("Run err presence = %v, RunResult err presence = %v", err2 != nil, err != nil)
			}
		})
	}
}

// A step whose error says a reconciler had already committed part of its work ends
// the run as partial_failed with that step named, whichever step it is, and is not
// rolled back (spec §6.1, D13). The same error without the sentinel is an ordinary
// failure that the rollback policy handles, so the rows below also show that the
// sentinel is what changes the outcome.
func TestTransactionPartiallyAppliedIsPartialFailedAndNeverRolledBack(t *testing.T) {
	committed := fmt.Errorf("2 operations were applied, then one failed: %w", ErrPartiallyApplied)
	for _, tc := range []struct {
		step     string
		err      error
		want     Outcome
		wantStep string
	}{
		{"apply", committed, OutcomePartialFailed, "apply"},
		{"verify", committed, OutcomePartialFailed, "verify"},
		{"idempotency", committed, OutcomePartialFailed, "idempotency"},
		// The control: the same failures without the sentinel are rolled back.
		{"apply", errors.New("bad"), OutcomeRolledBack, "apply"},
		{"verify", errors.New("bad"), OutcomeRolledBack, "verify"},
		{"idempotency", errors.New("bad"), OutcomeRolledBack, "idempotency"},
	} {
		t.Run(tc.step+"/"+string(tc.want), func(t *testing.T) {
			var calls []string
			step := func(name string, err error) StepFunc {
				return func(context.Context) error { calls = append(calls, name); return err }
			}
			tx := Transaction{
				Writer:   &fakeWriter{},
				Apply:    step("apply", nil),
				Verify:   step("verify", nil),
				Rollback: step("rollback", nil), RollbackPolicy: RollbackPlaybook,
				Idempotency: step("idempotency", nil), IdempotencyPolicy: IdempotencyAlways,
			}
			switch tc.step {
			case "apply":
				tx.Apply = step("apply", tc.err)
			case "verify":
				tx.Verify = step("verify", tc.err)
			case "idempotency":
				tx.Idempotency = step("idempotency", tc.err)
			}
			res, err := tx.RunResult(context.Background())
			if res.Outcome != tc.want || res.FailedStep != tc.wantStep || err == nil {
				t.Fatalf("result = %+v, err = %v; want %s at %s", res, err, tc.want, tc.wantStep)
			}
			if tc.want == OutcomePartialFailed {
				if !errors.Is(err, ErrPartiallyApplied) {
					t.Errorf("err = %v does not wrap ErrPartiallyApplied", err)
				}
				if slices.Contains(calls, "rollback") {
					t.Errorf("a partially applied run was rolled back: %v", calls)
				}
			} else if !slices.Contains(calls, "rollback") {
				t.Errorf("an ordinary failure was not rolled back: %v", calls)
			}
			if w := tx.Writer.(*fakeWriter); w.finish.Outcome != string(tc.want) || w.finish.ExitCode != 1 {
				t.Errorf("the run's terminal record = %+v, want %s with exit code 1", w.finish, tc.want)
			}
		})
	}
}

// ctxCheckingWriter fails an append on a cancelled context the way the real
// store does (RunWriter.appendEvent takes its connection with ctx), so a step
// evidence write that still uses the run's context shows here.
type ctxCheckingWriter struct {
	events []store.Event
}

func (w *ctxCheckingWriter) AppendEvent(ctx context.Context, event store.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	w.events = append(w.events, event)
	return nil
}
func (w *ctxCheckingWriter) Finish(context.Context, store.RunFinished) error { return nil }

// T2 of spec §4.4: the evidence of a step is written after the run's context was
// cancelled (Ctrl-C, --timeout, a lost lock): the step's own error and outcome
// survive, and the step_finished event is in the record. Before this, the append
// failed on the cancelled context, the step's error was dropped and the run ended
// as evidence_failed.
func TestTransactionStepEvidenceIsWrittenAfterTheContextWasCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := &ctxCheckingWriter{}
	cause := fmt.Errorf("interrupted after one operation: %w", ErrPartiallyApplied)
	res, err := (Transaction{
		Writer: w,
		Apply:  func(context.Context) error { cancel(); return cause },
	}).RunResult(ctx)
	if res.Outcome != OutcomePartialFailed || res.FailedStep != "apply" || !errors.Is(err, ErrPartiallyApplied) {
		t.Fatalf("result = %+v, err = %v; want partial_failed at apply", res, err)
	}
	if len(w.events) != 1 || w.events[0].Step != "apply" || *w.events[0].ExitCode != 1 {
		t.Fatalf("the step evidence of the cancelled step was not recorded: %+v", w.events)
	}
}

// A store that really fails is still evidence_failed with the cancellation
// detached: the class rule moves the append off the cancelled context, it does not
// hide a failing store (spec §4.4, last bullet).
func TestTransactionStepEvidenceStillFailsClosedWhenTheStoreFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res, err := (Transaction{
		Writer: &fakeWriter{err: errors.New("sqlite down")},
		Apply:  func(context.Context) error { cancel(); return errors.New("apply failed") },
	}).RunResult(ctx)
	if res.Outcome != OutcomeEvidenceFailed || err == nil {
		t.Fatalf("result = %+v, err = %v; want evidence_failed", res, err)
	}
}

// The same, through the real delivery store: a cancelled context does not make the
// store refuse the step event, and the run's terminal row says partial_failed.
func TestTransactionStepEvidenceReachesTheRealStoreAfterCancellation(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "history.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w, err := store.StartRun(ctx, st, store.RunStarted{Stage: "sandbox", Component: "freeipa-identity", Playbook: "none", Inventory: "inventory.yml", Hosts: []string{"ipa-1"}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := (Transaction{
		Writer: w,
		Apply:  func(context.Context) error { cancel(); return fmt.Errorf("cut off: %w", ErrPartiallyApplied) },
	}).RunResult(ctx)
	if res.Outcome != OutcomePartialFailed || err == nil {
		t.Fatalf("result = %+v, err = %v", res, err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var steps int
	if err := db.QueryRow(`SELECT COUNT(*) FROM delivery_events WHERE run_id=? AND type=? AND step='apply'`, w.RunID(), store.EventStepFinished).Scan(&steps); err != nil || steps != 1 {
		t.Fatalf("step_finished events for apply = %d, %v; want 1", steps, err)
	}
	var outcome string
	if err := db.QueryRow(`SELECT outcome FROM delivery_runs WHERE run_id=?`, w.RunID()).Scan(&outcome); err != nil || outcome != string(OutcomePartialFailed) {
		t.Fatalf("terminal outcome = %q, %v; want partial_failed", outcome, err)
	}
}

// flakyWriter fails the first n AppendEvent calls and the first n Finish calls with
// err, then succeeds. attempts counts every call.
type flakyWriter struct {
	failFor  int
	err      error
	appends  int
	finishes int
	events   []store.Event
	finish   store.RunFinished
}

func (w *flakyWriter) AppendEvent(_ context.Context, event store.Event) error {
	w.appends++
	if w.appends <= w.failFor {
		return w.err
	}
	w.events = append(w.events, event)
	return nil
}

func (w *flakyWriter) Finish(_ context.Context, finish store.RunFinished) error {
	w.finishes++
	if w.finishes <= w.failFor {
		return w.err
	}
	w.finish = finish
	return nil
}

func fastEvidenceRetry(t *testing.T, budget time.Duration) {
	t.Helper()
	oldBudget, oldPause := evidenceRetryBudget, evidenceRetryPause
	evidenceRetryBudget, evidenceRetryPause = budget, time.Millisecond
	t.Cleanup(func() { evidenceRetryBudget, evidenceRetryPause = oldBudget, oldPause })
}

// F7 (minimal-PoC five-node run): under host load the evidence store timed out once,
// and a deploy that had applied everything ended as evidence_failed with exit 1.
// A transient store error is retried, for the step records and for the terminal one.
func TestTransactionRetriesATransientEvidenceFailure(t *testing.T) {
	fastEvidenceRetry(t, 5*time.Second)
	for name, transient := range map[string]error{
		"attempt timed out": fmt.Errorf("append delivery event: %w", context.DeadlineExceeded),
		"sqlite busy":       errors.New("database is locked (5) (SQLITE_BUSY)"),
	} {
		t.Run(name, func(t *testing.T) {
			w := &flakyWriter{failFor: 2, err: transient}
			res, err := (Transaction{Writer: w, Apply: func(context.Context) error { return nil }}).RunResult(context.Background())
			if err != nil || res.Outcome != OutcomeSuccess {
				t.Fatalf("result = %+v, err = %v; want success after the store recovered", res, err)
			}
			if w.appends != 3 || len(w.events) != 1 || w.events[0].Step != "apply" {
				t.Fatalf("appends = %d events = %+v; want one record written on the third attempt", w.appends, w.events)
			}
			if w.finishes != 3 || w.finish.Outcome != string(OutcomeSuccess) {
				t.Fatalf("finishes = %d finish = %+v; want the terminal record written on the third attempt", w.finishes, w.finish)
			}
		})
	}
}

// The other half: a store that keeps timing out still ends as evidence_failed, and
// one error that is not transient is not retried at all.
func TestTransactionEvidenceFailureStillFailsClosedAfterTheRetryBudget(t *testing.T) {
	fastEvidenceRetry(t, 30*time.Millisecond)
	w := &flakyWriter{failFor: 1 << 30, err: context.DeadlineExceeded}
	res, err := (Transaction{Writer: w, Apply: func(context.Context) error { return nil }}).RunResult(context.Background())
	if res.Outcome != OutcomeEvidenceFailed || err == nil {
		t.Fatalf("result = %+v, err = %v; want evidence_failed", res, err)
	}
	if w.appends < 2 {
		t.Fatalf("appends = %d; a transient failure must be retried before giving up", w.appends)
	}

	fastEvidenceRetry(t, 5*time.Second)
	w = &flakyWriter{failFor: 1 << 30, err: errors.New("disk I/O error")}
	res, err = (Transaction{Writer: w, Apply: func(context.Context) error { return nil }}).RunResult(context.Background())
	if res.Outcome != OutcomeEvidenceFailed || err == nil {
		t.Fatalf("result = %+v, err = %v; want evidence_failed", res, err)
	}
	if w.appends != 1 {
		t.Fatalf("appends = %d; a non-transient error must not be retried", w.appends)
	}
	for _, conflict := range []error{store.ErrEvidenceConflict, store.ErrRunFinished} {
		w = &flakyWriter{failFor: 1 << 30, err: fmt.Errorf("wrapped: %w", conflict)}
		_, _ = (Transaction{Writer: w, Apply: func(context.Context) error { return nil }}).RunResult(context.Background())
		if w.appends != 1 {
			t.Fatalf("%v: appends = %d; a final store answer must not be retried", conflict, w.appends)
		}
	}
}

// When the step did its work and only its record is missing, the error says so
// (the operator saw "evidence_failed" and could not tell whether anything had run).
func TestTransactionEvidenceFailureSaysTheStepItselfSucceeded(t *testing.T) {
	fastEvidenceRetry(t, 5*time.Millisecond)
	_, err := (Transaction{Writer: &flakyWriter{failFor: 1 << 30, err: errors.New("disk I/O error")}, Apply: func(context.Context) error { return nil }}).RunResult(context.Background())
	if err == nil || !strings.Contains(err.Error(), "apply step itself finished successfully") {
		t.Fatalf("err = %v; want it to say the apply step itself finished successfully", err)
	}
	_, err = (Transaction{Writer: &flakyWriter{failFor: 1 << 30, err: errors.New("disk I/O error")}, Apply: func(context.Context) error { return errors.New("apply failed") }}).RunResult(context.Background())
	if err == nil || strings.Contains(err.Error(), "finished successfully") {
		t.Fatalf("err = %v; a failed step must not be described as successful", err)
	}
}
