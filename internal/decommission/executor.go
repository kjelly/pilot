// executor.go implements the step state machine spec.md §27.1 requires
// (pending -> running -> completed/skipped_attested/failed_retryable/
// failed_terminal) and its resume rule (§27.2, INV-9, HD18): a retryable
// step is re-inspected before it runs again, and a step already converged
// is marked completed WITHOUT mutating again — a completed destructive
// step is never blindly replayed.
//
// Phase 2 registers no live provider (providers/provider.go's package
// doc), so nothing in the real `pilot host decommission apply` CLI path
// ever builds a non-empty step list today — the only executable plan
// shape in this phase (a zero-role host, or one whose only reference is
// AUTO_REMOVE workspace cleanup with no component requiring a live
// provider step) has an empty TeardownOrder/Components. This machinery
// exists now, exercised by an in-package test-only StepExecutor fake
// (executor_test.go), so Phase 3+'s real providers only need to implement
// StepExecutor — the resume semantics around it are already correct and
// already tested.
package decommission

import (
	"context"
	"fmt"
)

// StepState is one decommission step's explicit lifecycle state (spec.md
// §27.1).
type StepState string

const (
	StepPending         StepState = "pending"
	StepRunning         StepState = "running"
	StepCompleted       StepState = "completed"
	StepSkippedAttested StepState = "skipped_attested"
	StepFailedRetryable StepState = "failed_retryable"
	StepFailedTerminal  StepState = "failed_terminal"
)

// StepExecutor is what one plan step needs in order to run. It is kept
// deliberately provider-agnostic and minimal — Phase 3+'s concrete
// providers (FreeIPA client, Wazuh agent, internal-endpoint) each
// implement it by wrapping their real cleanup action; nothing in this
// package assumes which provider produced it.
type StepExecutor interface {
	// Inspect reports whether the step's target state is already
	// converged — called before Execute (including on a fresh, never-run
	// step) so a step whose effect already exists is marked completed
	// without mutating again (INV-9/HD18).
	Inspect(ctx context.Context) (converged bool, err error)
	// Execute performs the step's one destructive action. Only called
	// when Inspect reports the step is not yet converged.
	Execute(ctx context.Context) error
}

// ExecStep is one plan step under execution: stable ID (used to key
// persisted state and resume), the StepExecutor that knows how to run it,
// and its current lifecycle state.
type ExecStep struct {
	ID       string
	Provider string
	Action   string
	State    StepState
	Attempts int
	Err      string

	exec StepExecutor
}

// NewExecStep builds one ExecStep in state pending, wrapping exec.
func NewExecStep(id, provider, action string, exec StepExecutor) *ExecStep {
	return &ExecStep{ID: id, Provider: provider, Action: action, State: StepPending, exec: exec}
}

// Executor walks an ordered list of steps, honoring each one's persisted
// State — so calling Run twice on the same steps (a "resume") never
// re-executes a step already StepCompleted/StepSkippedAttested (HD18).
type Executor struct {
	steps []*ExecStep
}

// NewExecutor builds an Executor over steps, in the order they must run.
func NewExecutor(steps []*ExecStep) *Executor {
	return &Executor{steps: steps}
}

// Steps returns the executor's steps in order, reflecting their current
// state after any Run call.
func (e *Executor) Steps() []*ExecStep { return e.steps }

// Run executes every step that is not yet StepCompleted/
// StepSkippedAttested, in order, stopping at the first failure (INV-9:
// forward-recovery saga, not a rollback — a failed step never triggers
// compensating action against steps before it). Calling Run again after a
// failure (a resume) picks up exactly where it left off: completed steps
// are skipped without calling Inspect/Execute on them again; the failed
// step is re-inspected (spec.md §27.2) before it is retried.
func (e *Executor) Run(ctx context.Context) error {
	for _, s := range e.steps {
		switch s.State {
		case StepCompleted, StepSkippedAttested:
			continue
		case StepFailedTerminal:
			return fmt.Errorf("decommission: step %s (%s/%s) previously failed terminally and cannot be retried", s.ID, s.Provider, s.Action)
		}

		if err := ctx.Err(); err != nil {
			return err
		}

		s.State = StepRunning
		converged, err := s.exec.Inspect(ctx)
		if err != nil {
			s.Attempts++
			s.State = StepFailedRetryable
			s.Err = err.Error()
			return fmt.Errorf("decommission: inspect step %s (%s/%s): %w", s.ID, s.Provider, s.Action, err)
		}
		if converged {
			// Already done (e.g. a resume re-inspecting a step that
			// actually succeeded before a crash recorded it) — mark
			// completed without mutating again (INV-9/HD18).
			s.State = StepCompleted
			s.Err = ""
			continue
		}

		s.Attempts++
		if err := s.exec.Execute(ctx); err != nil {
			s.State = StepFailedRetryable
			s.Err = err.Error()
			return fmt.Errorf("decommission: execute step %s (%s/%s): %w", s.ID, s.Provider, s.Action, err)
		}
		s.State = StepCompleted
		s.Err = ""
	}
	return nil
}
