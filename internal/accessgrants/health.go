// health.go implements spec.md v3.1 §16: `pilot access health` — a
// one-shot inspection that runs once and exits, never a monitor.
package accessgrants

import (
	"context"
	"time"

	"github.com/kjelly/pilot/internal/inventory"
)

// Health statuses, per §16.3.
const (
	HealthHealthy  = "healthy"
	HealthDegraded = "degraded"
	HealthCritical = "critical"
	HealthUnknown  = "unknown"
)

// Health is `pilot access health`'s report (§16.1).
type Health struct {
	EvaluatedAt time.Time `json:"evaluated_at"`
	// FreeIPAReachable is false whenever the drift probe itself could not
	// complete (kinit/connectivity failure) — every drift-derived count
	// below is meaningless in that case and left at zero.
	FreeIPAReachable bool `json:"freeipa_reachable"`

	// Drift counts (§16.1). CompiledGrantHBACDriftCount/SudoDriftCount
	// fold together this delivery's "missing" and "orphan" drift
	// categories (§12.2/§12.3) — see DriftReport.CountByCategory for the
	// raw per-category breakdown this collapses.
	CompiledGrantHBACDriftCount int `json:"compiled_grant_hbac_drift_count"`
	SudoDriftCount              int `json:"sudo_drift_count"`
	AuthPolicyDriftCount        int `json:"auth_policy_drift_count"`
	AccountExpirationDriftCount int `json:"account_expiration_drift_count"`
	// StaticHBACDriftCount is always 0 in this delivery — static HBAC
	// attribute drift is explicitly out of scope (see drift.go's header
	// comment); this field exists so the JSON shape already matches
	// §16.1's full list and a future delivery can populate it without a
	// breaking schema change.
	StaticHBACDriftCount int `json:"static_hbac_drift_count"`

	// ReviewOverdueCount is always 0 in this delivery — access
	// recertification (§14) is Phase 5, not yet implemented.
	ReviewOverdueCount int `json:"review_overdue_count"`

	ActiveBreakglassCount                int `json:"active_breakglass_count"`
	ReconcileRequiredTemporaryGrantCount int `json:"reconcile_required_temporary_grant_count"`

	Status string `json:"status"`
}

// HealthOptions configures a single health evaluation.
type HealthOptions struct {
	DriftProbeOptions
	// StateDir enables reading breakglass activation state
	// (accessgrants.Status) — empty leaves ActiveBreakglassCount at 0
	// rather than failing the whole health check.
	StateDir string
}

// EvaluateHealth runs DriftOnce and folds its result together with grant-
// status/breakglass state into one Health report (§16). A drift-probe
// failure (FreeIPA unreachable) is NOT propagated as an error — it is
// reported as Status: unknown with FreeIPAReachable: false, since "cannot
// determine health" is itself a valid, non-fatal health answer (§16.3).
func EvaluateHealth(ctx context.Context, opts HealthOptions) (Health, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	health := Health{EvaluatedAt: now.UTC()}

	driftOpts := opts.DriftProbeOptions
	driftOpts.Now = now
	report, driftErr := DriftOnce(ctx, driftOpts)
	if driftErr != nil {
		health.Status = HealthUnknown
		return health, nil
	}
	health.FreeIPAReachable = true

	counts := report.CountByCategory()
	health.CompiledGrantHBACDriftCount = counts["hbac_missing"] + counts["hbac_orphan"]
	health.SudoDriftCount = counts["sudo_missing"] + counts["sudo_orphan"]
	health.AuthPolicyDriftCount = counts["auth_indicator"]
	health.AccountExpirationDriftCount = counts["account_expiration"]

	statuses, err := inventory.EvaluateGrantStatusesFile(opts.RosterFile, now)
	if err != nil {
		return Health{}, err
	}
	for _, s := range statuses {
		// Every present temporary_grant needs a future Pilot reconcile to
		// enforce its next transition (§10.2/§10.3) — including one whose
		// window has already passed: an expired-but-not-yet-reconciled
		// grant means its HBAC rule may STILL be enabled, which is the
		// most urgent case, not a settled one.
		if s.Kind == "temporary_grant" && s.State != "absent" {
			health.ReconcileRequiredTemporaryGrantCount++
		}
	}
	if opts.StateDir != "" {
		for _, s := range statuses {
			if s.Kind != "breakglass" || s.State == "absent" {
				continue
			}
			activations, err := Status(opts.StateDir, s.Name)
			if err != nil {
				return Health{}, err
			}
			for _, a := range activations {
				if a.IsActive(now) {
					health.ActiveBreakglassCount++
				}
			}
		}
	}

	gate, err := EvaluatePolicyGate(opts.RosterFile, now)
	if err != nil {
		return Health{}, err
	}

	switch {
	case !gate.Empty() || health.AccountExpirationDriftCount > 0 || health.AuthPolicyDriftCount > 0 ||
		health.SudoDriftCount > 0 || health.CompiledGrantHBACDriftCount > 0:
		health.Status = HealthCritical
	case health.ReconcileRequiredTemporaryGrantCount > 0:
		health.Status = HealthDegraded
	default:
		health.Status = HealthHealthy
	}
	return health, nil
}
