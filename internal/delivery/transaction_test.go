package delivery

import (
	"context"
	"errors"
	"testing"

	"github.com/anomalyco/pilot/internal/store"
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
