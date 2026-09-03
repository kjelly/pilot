package decommission

import (
	"errors"
	"fmt"
)

// ErrorClass is decommission's stable, machine-readable error taxonomy
// (spec.md §41). CLI exit behavior distinguishes user-fixable blockers
// (surfaced as a structured blocked Plan, not a Go error) from these
// process-level errors (bad input, stale plan, workspace malformed, ...).
type ErrorClass string

const (
	ErrHostNotFound                  ErrorClass = "host_not_found"
	ErrPlanBlocked                   ErrorClass = "plan_blocked"
	ErrPlanExpired                   ErrorClass = "plan_expired"
	ErrPlanStale                     ErrorClass = "plan_stale"
	ErrApprovalRequired              ErrorClass = "approval_required"
	ErrApprovalHashMismatch          ErrorClass = "approval_hash_mismatch"
	ErrDependencyCycle               ErrorClass = "dependency_cycle"
	ErrRequiredProviderLoss          ErrorClass = "required_provider_loss"
	ErrRetentionRequired             ErrorClass = "retention_required"
	ErrHostUnreachable               ErrorClass = "host_unreachable"
	ErrOwnershipUnknown              ErrorClass = "ownership_unknown"
	ErrExternalStateUnsupported      ErrorClass = "external_state_unsupported"
	ErrControlPlaneRequiresDedicated ErrorClass = "control_plane_host_requires_dedicated_workflow"
	ErrCleanupFailedRetryable        ErrorClass = "cleanup_failed_retryable"
	ErrCleanupFailedTerminal         ErrorClass = "cleanup_failed_terminal"
	ErrActiveResidue                 ErrorClass = "active_residue"
	ErrFinalizationFailed            ErrorClass = "finalization_failed"
	ErrAlreadyCompleted              ErrorClass = "already_completed"
	// ErrReferenceRequiresAuthorization is Phase 4's addition to spec.md
	// §41's "suggested, not exhaustive" list: a reference-driven provider
	// (e.g. internal-endpoint) found something it CAN safely remove, but
	// an explicit operator-owned authorization it never grants itself is
	// missing (e.g. internal-endpoints.yaml's own safety.
	// allow_endpoint_delete flag, spec.md §32) — distinct from
	// ownership_unknown (ownership IS known here) and from
	// external_state_unsupported (a provider IS registered and DOES know
	// how to clean this up).
	ErrReferenceRequiresAuthorization ErrorClass = "reference_requires_authorization"
	// ErrWorkspaceMalformed is not part of spec.md §41's taxonomy (that
	// list is about lifecycle/blocker outcomes); it covers the CLI's
	// third `plan` exit case — "malformed workspace: error" (spec.md
	// §10.1) — e.g. hosts.yml missing or unparsable.
	ErrWorkspaceMalformed ErrorClass = "workspace_malformed"
)

// Error is decommission's typed error. Class is machine-readable; Message
// is human detail. Never carries a secret value (spec.md §31.10).
type Error struct {
	Class   ErrorClass
	Message string
}

func (e *Error) Error() string {
	if e.Message == "" {
		return string(e.Class)
	}
	return fmt.Sprintf("%s: %s", e.Class, e.Message)
}

func newError(class ErrorClass, format string, args ...any) *Error {
	return &Error{Class: class, Message: fmt.Sprintf(format, args...)}
}

// ClassOf returns err's ErrorClass, or "" if err is nil or not an *Error.
func ClassOf(err error) ErrorClass {
	var e *Error
	if errors.As(err, &e) {
		return e.Class
	}
	return ""
}
