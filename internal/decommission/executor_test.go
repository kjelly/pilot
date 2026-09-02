package decommission

import (
	"context"
	"errors"
	"testing"
)

// countingStep is a test-only StepExecutor fake: Inspect always reports
// "not converged" (so Execute must run to make progress) and Execute
// simply increments a call counter and reports success.
type countingStep struct {
	inspectCalls int
	executeCalls int
}

func (s *countingStep) Inspect(ctx context.Context) (bool, error) {
	s.inspectCalls++
	return false, nil
}

func (s *countingStep) Execute(ctx context.Context) error {
	s.executeCalls++
	return nil
}

// failOnceStep fails Execute the first time it is called, then succeeds.
type failOnceStep struct {
	inspectCalls int
	executeCalls int
	failed       bool
}

func (s *failOnceStep) Inspect(ctx context.Context) (bool, error) {
	s.inspectCalls++
	return false, nil
}

func (s *failOnceStep) Execute(ctx context.Context) error {
	s.executeCalls++
	if !s.failed {
		s.failed = true
		return errors.New("simulated transient failure")
	}
	return nil
}

// TestExecutor_ResumeDoesNotReplayCompletedDestructiveStep proves HD18/
// INV-9: (a) a step that already succeeded is never re-run across two
// "resume" invocations (a fresh Executor built over the same *ExecStep
// slice, as a real resume would after reloading persisted step state),
// and (b) a step that fails once then succeeds lets resume continue from
// exactly that step, without re-running the steps before it that already
// completed.
func TestExecutor_ResumeDoesNotReplayCompletedDestructiveStep(t *testing.T) {
	t.Run("single completed step is never re-run across two resume invocations", func(t *testing.T) {
		fake := &countingStep{}
		step := NewExecStep("s1", "fake-provider", "fake_action", fake)

		if err := NewExecutor([]*ExecStep{step}).Run(context.Background()); err != nil {
			t.Fatalf("first Run() error = %v", err)
		}
		if step.State != StepCompleted {
			t.Fatalf("state after first Run = %s, want completed", step.State)
		}
		if fake.executeCalls != 1 {
			t.Fatalf("executeCalls after first Run = %d, want 1", fake.executeCalls)
		}

		// Simulate a resume: a brand-new Executor over the SAME step
		// (state persisted/reloaded as completed).
		if err := NewExecutor([]*ExecStep{step}).Run(context.Background()); err != nil {
			t.Fatalf("second (resume) Run() error = %v", err)
		}
		if fake.executeCalls != 1 {
			t.Fatalf("executeCalls after resume Run = %d, want still 1 (must not replay a completed destructive step)", fake.executeCalls)
		}
		if fake.inspectCalls != 1 {
			t.Fatalf("inspectCalls after resume Run = %d, want still 1 (a completed step must not even be re-inspected)", fake.inspectCalls)
		}
	})

	t.Run("resume continues from the failed step without re-running earlier completed steps", func(t *testing.T) {
		first := &countingStep{}
		second := &failOnceStep{}
		steps := []*ExecStep{
			NewExecStep("s1", "fake-provider", "first_action", first),
			NewExecStep("s2", "fake-provider", "second_action", second),
		}

		err := NewExecutor(steps).Run(context.Background())
		if err == nil {
			t.Fatal("first Run() expected an error from the failing second step")
		}
		if steps[0].State != StepCompleted {
			t.Fatalf("s1 state = %s, want completed", steps[0].State)
		}
		if steps[1].State != StepFailedRetryable {
			t.Fatalf("s2 state = %s, want failed_retryable", steps[1].State)
		}
		if first.executeCalls != 1 {
			t.Fatalf("s1 executeCalls = %d, want 1", first.executeCalls)
		}
		if second.executeCalls != 1 {
			t.Fatalf("s2 executeCalls after first attempt = %d, want 1", second.executeCalls)
		}

		// Resume: a fresh Executor over the SAME steps (as a real resume
		// would after reloading persisted state).
		if err := NewExecutor(steps).Run(context.Background()); err != nil {
			t.Fatalf("resume Run() error = %v", err)
		}
		if first.executeCalls != 1 {
			t.Fatalf("s1 executeCalls after resume = %d, want still 1 (completed step replayed)", first.executeCalls)
		}
		if first.inspectCalls != 1 {
			t.Fatalf("s1 inspectCalls after resume = %d, want still 1 (completed step re-inspected)", first.inspectCalls)
		}
		if second.executeCalls != 2 {
			t.Fatalf("s2 executeCalls after resume = %d, want 2 (retried once)", second.executeCalls)
		}
		if steps[0].State != StepCompleted || steps[1].State != StepCompleted {
			t.Fatalf("final states = %s, %s, want completed, completed", steps[0].State, steps[1].State)
		}
	})
}

func TestExecutor_InspectConvergedSkipsExecute(t *testing.T) {
	step := NewExecStep("s1", "fake-provider", "action", convergedStep{})
	if err := NewExecutor([]*ExecStep{step}).Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if step.State != StepCompleted {
		t.Fatalf("state = %s, want completed", step.State)
	}
}

type convergedStep struct{}

func (convergedStep) Inspect(ctx context.Context) (bool, error) { return true, nil }
func (convergedStep) Execute(ctx context.Context) error {
	panic("Execute must not be called when Inspect already reports converged")
}
