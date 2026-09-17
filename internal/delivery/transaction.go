// Package delivery provides the deterministic transaction state machine shared
// by deploy frontends and disposable-target test commands.
package delivery

import (
	"context"
	"errors"
	"fmt"

	"github.com/kjelly/pilot/internal/store"
)

// Outcome is the terminal, machine-readable delivery result.
type Outcome string

const (
	OutcomeSuccess               Outcome = "success"
	OutcomeFailed                Outcome = "failed"
	OutcomePartialSuccess        Outcome = "partial_success"
	OutcomePartialFailed         Outcome = "partial_failed"
	OutcomeCancelled             Outcome = "cancelled"
	OutcomeRolledBack            Outcome = "rolled_back"
	OutcomeRollbackFailed        Outcome = "rollback_failed"
	OutcomeEvidenceFailed        Outcome = "evidence_failed"
	OutcomeAuthorizationRequired Outcome = "authorization_required"
)

// IdempotencyPolicy decides whether a second identical apply must run after
// verification. The frontend resolves stage-specific policy before Run.
type IdempotencyPolicy string

const (
	IdempotencyAlways          IdempotencyPolicy = "always"
	IdempotencyStageGTEStaging IdempotencyPolicy = "stage>=staging"
	IdempotencyNever           IdempotencyPolicy = "never"
)

// RollbackPolicy names the recovery mechanism available to this transaction.
type RollbackPolicy string

const (
	RollbackNone     RollbackPolicy = "none"
	RollbackSnapshot RollbackPolicy = "snapshot"
	RollbackPlaybook RollbackPolicy = "playbook"
)

// StepFunc performs one deterministic transaction stage.
type StepFunc func(context.Context) error

// EventWriter is implemented by store.RunWriter. Keeping the narrow interface
// makes transaction semantics testable without a SQLite dependency.
type EventWriter interface {
	AppendEvent(context.Context, store.Event) error
	Finish(context.Context, store.RunFinished) error
}

// Transaction is an explicit delivery state machine. Apply, verify, and
// idempotency all use the same frontend-resolved arguments; the concrete
// commands live in the supplied functions, not in this package.
type Transaction struct {
	Writer      EventWriter
	Preflight   StepFunc
	Preview     StepFunc
	Apply       StepFunc
	Verify      StepFunc
	Idempotency StepFunc
	Rollback    StepFunc

	IdempotencyPolicy IdempotencyPolicy
	RollbackPolicy    RollbackPolicy
	Stage             string
}

// Result is Transaction.RunResult's structured outcome — design spec
// docs/tmp/now/spec.md §10: a backward-compatible addition so callers
// that need to know WHICH step failed (the outbound webhook's
// FailureInfo.Phase, design spec §19) never have to parse an error
// string to find out.
type Result struct {
	Outcome    Outcome
	FailedStep string
}

// Run executes the transaction and returns just its Outcome — kept for
// every existing caller. It is now a thin wrapper over RunResult.
func (t Transaction) Run(ctx context.Context) (Outcome, error) {
	result, err := t.RunResult(ctx)
	return result.Outcome, err
}

// RunResult executes the transaction in order and always attempts
// terminal evidence when a writer was provided. An applicable verify
// failure therefore can never be reported as a successful deployment.
func (t Transaction) RunResult(ctx context.Context) (result Result, err error) {
	defer func() {
		if t.Writer == nil {
			return
		}
		finishErr := t.Writer.Finish(ctx, store.RunFinished{Outcome: string(result.Outcome), ExitCode: outcomeExitCode(result.Outcome)})
		if finishErr != nil && err == nil {
			result.Outcome = OutcomeEvidenceFailed
			result.FailedStep = "evidence"
			err = fmt.Errorf("persist delivery terminal evidence: %w", finishErr)
		}
	}()
	if err := t.runStep(ctx, "preflight", t.Preflight); err != nil {
		result.FailedStep = "preflight"
		if errors.Is(err, ErrCancelled) {
			result.Outcome = OutcomeCancelled
			return result, err
		}
		if errors.Is(err, ErrAuthorizationRequired) {
			result.Outcome = OutcomeAuthorizationRequired
			return result, err
		}
		if errors.Is(err, errEvidencePersistence) {
			result.FailedStep = "evidence"
			result.Outcome = OutcomeEvidenceFailed
			return result, err
		}
		result.Outcome = OutcomeFailed
		return result, err
	}
	if err := t.runStep(ctx, "preview", t.Preview); err != nil {
		result.FailedStep = "preview"
		if errors.Is(err, ErrCancelled) {
			result.Outcome = OutcomeCancelled
			return result, err
		}
		if errors.Is(err, errEvidencePersistence) {
			result.FailedStep = "evidence"
			result.Outcome = OutcomeEvidenceFailed
			return result, err
		}
		result.Outcome = OutcomeFailed
		return result, err
	}
	if err := t.runStep(ctx, "apply", t.Apply); err != nil {
		if errors.Is(err, ErrCancelled) {
			result.FailedStep = "apply"
			result.Outcome = OutcomeCancelled
			return result, err
		}
		if errors.Is(err, errEvidencePersistence) {
			result.FailedStep = "evidence"
			result.Outcome = OutcomeEvidenceFailed
			return result, err
		}
		return t.failWithRollbackResult(ctx, "apply", err)
	}
	if err := t.runStep(ctx, "verify", t.Verify); err != nil {
		if errors.Is(err, ErrCancelled) {
			result.FailedStep = "verify"
			result.Outcome = OutcomeCancelled
			return result, err
		}
		if errors.Is(err, errEvidencePersistence) {
			result.FailedStep = "evidence"
			result.Outcome = OutcomeEvidenceFailed
			return result, err
		}
		return t.failWithRollbackResult(ctx, "verify", err)
	}
	if t.shouldRunIdempotency() {
		if err := t.runStep(ctx, "idempotency", t.Idempotency); err != nil {
			if errors.Is(err, ErrCancelled) {
				result.FailedStep = "idempotency"
				result.Outcome = OutcomeCancelled
				return result, err
			}
			if errors.Is(err, errEvidencePersistence) {
				result.FailedStep = "evidence"
				result.Outcome = OutcomeEvidenceFailed
				return result, err
			}
			return t.failWithRollbackResult(ctx, "idempotency", err)
		}
	}
	result.Outcome = OutcomeSuccess
	return result, nil
}

func (t Transaction) shouldRunIdempotency() bool {
	switch t.IdempotencyPolicy {
	case IdempotencyAlways:
		return true
	case IdempotencyStageGTEStaging:
		return t.Stage == "staging" || t.Stage == "prod"
	default:
		return false
	}
}

func (t Transaction) failWithRollbackResult(ctx context.Context, step string, cause error) (Result, error) {
	if t.RollbackPolicy == RollbackNone || t.Rollback == nil {
		return Result{Outcome: OutcomeFailed, FailedStep: step}, fmt.Errorf("%s failed: %w", step, cause)
	}
	if err := t.runStep(ctx, "rollback", t.Rollback); err != nil {
		return Result{Outcome: OutcomeRollbackFailed, FailedStep: "rollback"}, fmt.Errorf("%s failed: %w; rollback failed: %v", step, cause, err)
	}
	return Result{Outcome: OutcomeRolledBack, FailedStep: step}, fmt.Errorf("%s failed: %w; rollback completed", step, cause)
}

func (t Transaction) runStep(ctx context.Context, name string, fn StepFunc) error {
	if fn == nil {
		return nil
	}
	err := fn(ctx)
	if t.Writer != nil {
		exit := 0
		if err != nil {
			exit = 1
		}
		if appendErr := t.Writer.AppendEvent(ctx, store.Event{OperationID: "step-" + name, Type: store.EventStepFinished, Step: name, Payload: map[string]any{"status": stepStatus(err)}, ExitCode: &exit}); appendErr != nil {
			return fmt.Errorf("persist %s evidence: %w", name, fmt.Errorf("%w: %v", errEvidencePersistence, appendErr))
		}
	}
	return err
}

func stepStatus(err error) string {
	if err == nil {
		return "success"
	}
	return "failed"
}

func outcomeExitCode(outcome Outcome) int {
	if outcome == OutcomeSuccess || outcome == OutcomePartialSuccess || outcome == OutcomeCancelled {
		return 0
	}
	return 1
}

// ErrAuthorizationRequired lets a frontend stop before mutations while still
// recording a semantically distinct terminal outcome.
var ErrAuthorizationRequired = errors.New("delivery authorization required")

// ErrCancelled lets interactive frontends finish an auditable transaction as
// cancelled without relabelling an intentional refusal as a failed mutation.
var ErrCancelled = errors.New("delivery cancelled")

var errEvidencePersistence = errors.New("delivery evidence persistence failed")
