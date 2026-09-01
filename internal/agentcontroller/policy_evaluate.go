package agentcontroller

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kjelly/pilot/internal/policy"
)

// GatherPolicyInput assembles a live policy.PolicyInput for plan (design
// doc §12 steps 1-3: reload incident, re-check alert firing, revalidate
// plan freshness) — the ONE piece of IO internal/policy's pure
// EvaluatePolicy deliberately excludes. client is used to re-resolve the
// plan through the SAME repair MCP path pilot_repair_plan/pilot_repair_
// apply already use, so "is this plan still current" and "what does the
// contract say about autonomy for this action" both come from pilot's
// own, single, already-audited contract loader — this binary never
// parses contracts/*.yaml itself.
//
// Known, deliberate scope limits (documented here rather than silently
// left out):
//   - GlobalKillSwitch/ComponentKillSwitch (design doc guards 4/5) are
//     not backed by a separate dedicated on/off primitive. A global stop
//     is already available two ways — `autonomy disable` (this function's
//     caller must check AutonomyMode itself; EvaluatePolicy also
//     short-circuits on it) and tripping the "global" circuit breaker,
//     which carries the SAME audited-reset guarantee a kill switch would
//     need. GlobalKillSwitch here is wired to the global breaker's own
//     state (deliberately, not a bug); ComponentKillSwitch is always
//     false — a per-component manual kill is redundant with that
//     component's own breaker scope, which an operator can trip/reset
//     through the exact same `autonomy reset-breaker` CLI. A dedicated
//     third mechanism was assessed as unwarranted duplication for MVP.
//   - MaintenanceMode is always false — no maintenance-window concept
//     exists elsewhere in this codebase to source it from yet.
func (s *Store) GatherPolicyInput(ctx context.Context, client *RepairClient, cfg policy.Config, plan StoredPlan, environment string, now time.Time) (policy.PolicyInput, policy.ComponentAutonomy, error) {
	incident, err := s.GetIncident(plan.IncidentID)
	if err != nil {
		return policy.PolicyInput{}, policy.ComponentAutonomy{}, fmt.Errorf("reload incident %s: %w", plan.IncidentID, err)
	}
	if incident == nil {
		return policy.PolicyInput{}, policy.ComponentAutonomy{}, fmt.Errorf("incident %s no longer exists", plan.IncidentID)
	}

	wire, planErr := client.Plan(ctx, plan.IncidentID, plan.Host, plan.Component, plan.Action)
	planFresh := planErr == nil && wire.PlanHash == plan.PlanHash
	repairInfraHealthy := planErr == nil
	var autonomy policy.ComponentAutonomy
	if planErr == nil {
		autonomy = wire.Autonomy()
	}

	lastActionAt, err := s.LastActionAt(plan.Host, plan.Component, plan.Action)
	if err != nil {
		return policy.PolicyInput{}, policy.ComponentAutonomy{}, err
	}

	hostWindow := cfg.Defaults.HostBudgetWindow
	if hostWindow <= 0 {
		hostWindow = 6 * time.Hour
	}
	hostCount, err := s.CountApprovedActionsForHost(plan.Host, now.Add(-hostWindow))
	if err != nil {
		return policy.PolicyInput{}, policy.ComponentAutonomy{}, err
	}

	componentWindow := cfg.Defaults.ComponentBudgetWindow
	if componentWindow <= 0 {
		componentWindow = time.Hour
	}
	componentCount, err := s.CountApprovedActionsForComponent(plan.Component, now.Add(-componentWindow))
	if err != nil {
		return policy.PolicyInput{}, policy.ComponentAutonomy{}, err
	}

	priorFailures, err := s.CountPolicyRunsForIncident(plan.IncidentID)
	if err != nil {
		return policy.PolicyInput{}, policy.ComponentAutonomy{}, err
	}

	humanRejected, err := s.HasHumanRejection(plan.Host, plan.Component, plan.Action)
	if err != nil {
		return policy.PolicyInput{}, policy.ComponentAutonomy{}, err
	}

	globalBreaker, err := s.BreakerState(BreakerScopeGlobal)
	if err != nil {
		return policy.PolicyInput{}, policy.ComponentAutonomy{}, err
	}
	componentBreaker, err := s.BreakerState(BreakerScopeComponent(plan.Component))
	if err != nil {
		return policy.PolicyInput{}, policy.ComponentAutonomy{}, err
	}
	hostBreaker, err := s.BreakerState(BreakerScopeHost(plan.Host))
	if err != nil {
		return policy.PolicyInput{}, policy.ComponentAutonomy{}, err
	}

	in := policy.PolicyInput{
		Plan:                        policy.Plan{Host: plan.Host, Component: plan.Component, Action: plan.Action, Risk: plan.Risk},
		Environment:                 environment,
		IncidentSeverity:            incident.Severity,
		IncidentSource:              incident.Source,
		AlertStillFiring:            !isTerminalStatus(incident.Status),
		PriorActionsHostWindow:      hostCount,
		PriorActionsComponentWindow: componentCount,
		PriorFailuresIncident:       priorFailures,
		LastActionAt:                lastActionAt,
		MaintenanceMode:             false,
		GlobalKillSwitch:            globalBreaker.State == BreakerOpen,
		ComponentKillSwitch:         false,
		PlanFresh:                   planFresh,
		NoHumanRejection:            !humanRejected,
		AuditWritable:               s.HealthCheck(),
		RepairInfraHealthy:          repairInfraHealthy,
		GlobalBreakerOpen:           globalBreaker.State == BreakerOpen,
		ComponentBreakerOpen:        componentBreaker.State == BreakerOpen,
		HostBreakerOpen:             hostBreaker.State == BreakerOpen,
	}
	return in, autonomy, nil
}

// EvaluateAndRecord runs EvaluatePolicy and persists the decision (design
// doc §12 step 6) — this is the ONE place a policy decision is ever
// written, so shadow and enforced modes share it exactly (they differ
// only in what the CALLER does with an allow_auto result afterward).
func (s *Store) EvaluateAndRecord(cfg policy.Config, autonomy policy.ComponentAutonomy, in policy.PolicyInput, plan StoredPlan, mode string, now time.Time) (policy.PolicyDecision, error) {
	decision := policy.EvaluatePolicy(cfg, autonomy, in, now)
	reasonsJSON, _ := json.Marshal(decision.Reasons)
	if _, err := s.RecordPolicyDecision(plan.IncidentID, plan.ID, plan.PlanHash, decision.Decision, decision.PolicyID, decision.PolicyVersion, string(reasonsJSON), mode, now); err != nil {
		return decision, fmt.Errorf("persist policy decision: %w", err)
	}
	return decision, nil
}
