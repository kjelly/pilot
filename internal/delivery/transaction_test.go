package delivery

import (
	"context"
	"errors"
	"testing"

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
