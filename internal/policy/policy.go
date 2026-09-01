// Package policy implements Agent Monitoring Phase 4's deterministic
// autonomy policy engine: EvaluatePolicy is a PURE function (design doc
// §10) — every guard is a plain input field, never an IO call, so every
// allow/deny path is table-testable without a database or the network.
// Gathering the facts that fill PolicyInput (budgets, cooldowns, breaker
// state, plan freshness) is the caller's job (internal/agentcontroller),
// deliberately kept out of this package.
//
// Fundamental invariant (design doc §2): Agent recommendation != authorization.
// This package never reads Agent prose or confidence scores — only
// already-resolved, already-typed facts an operator or the controller's
// own trusted code computed.
package policy

import "time"

// Decision values (design doc §5).
const (
	DecisionAllowAuto    = "allow_auto"
	DecisionRequireHuman = "require_human"
	DecisionDeny         = "deny"
)

// Mode values (design doc §9) — disabled: policy is never consulted for
// execution; shadow: evaluate and persist would_allow_auto, never
// mutate; enforced: allow_auto actually authorizes execution.
const (
	ModeDisabled = "disabled"
	ModeShadow   = "shadow"
	ModeEnforced = "enforced"
)

// Plan is the minimal subset of a repair plan the policy engine needs —
// deliberately not internal/repair.Plan itself, so this package has no
// dependency on internal/repair (a pure decision core should not import
// an execution package).
type Plan struct {
	Host      string
	Component string
	Action    string
	Risk      string
}

// PolicyInput is every trusted, already-resolved fact EvaluatePolicy
// needs (design doc §5, extended). The design doc's own PolicyInput
// struct names 12 fields but the guard list in §6 has 15 items — four of
// them (plan freshness, no human rejection, audit DB writable, repair
// infra healthy) have no corresponding field in the doc's own struct.
// Rather than leave those guards unenforceable by the pure evaluator
// (silently trusting the caller to check them out-of-band, which is
// exactly the kind of gap "Unknown state is never allow" (§6) warns
// against), they are added here as explicit fields — PlanFresh,
// NoHumanRejection, AuditWritable, RepairInfraHealthy — so all 15 guards
// are represented in one place and covered by the same table tests.
type PolicyInput struct {
	Plan                        Plan
	Environment                 string // sandbox | staging | prod
	IncidentSeverity            string
	IncidentSource              string
	AlertStillFiring            bool
	PriorActionsHostWindow      int
	PriorActionsComponentWindow int
	PriorFailuresIncident       int
	LastActionAt                *time.Time
	MaintenanceMode             bool
	GlobalKillSwitch            bool
	ComponentKillSwitch         bool

	// PlanFresh is the caller's own repair.VerifyPlanFresh result
	// (guard §6.11: "plan hash/inventory/contract still current").
	PlanFresh bool
	// NoHumanRejection is false when a REJECTED approval already exists
	// for this exact plan (guard §6.13).
	NoHumanRejection bool
	// AuditWritable is the caller's own DB/change-journal writability
	// probe (guard §6.14).
	AuditWritable bool
	// RepairInfraHealthy is the caller's own repair MCP reachability
	// probe (guard §6.15).
	RepairInfraHealthy bool

	// GlobalBreakerOpen/ComponentBreakerOpen/HostBreakerOpen are the
	// caller's own circuit_breakers lookups (design doc §8) — modeled
	// as three explicit scopes rather than a single bool so a reason
	// string can name exactly which scope tripped.
	GlobalBreakerOpen    bool
	ComponentBreakerOpen bool
	HostBreakerOpen      bool
}

// PolicyDecision is EvaluatePolicy's pure output (design doc §5).
type PolicyDecision struct {
	Decision      string // allow_auto | require_human | deny
	PolicyID      string
	PolicyVersion string
	Reasons       []string
	EvaluatedAt   time.Time
}

// EnvironmentPolicy is one environment's default autonomy posture
// (design doc §4/§14).
type EnvironmentPolicy string

const (
	EnvAllowR1   EnvironmentPolicy = "allow_r1"
	EnvHumanOnly EnvironmentPolicy = "human_only"
)

// Config is the declarative, versioned policy configuration (design doc
// §14) — no natural-language policy, no dynamic code engine.
type Config struct {
	SchemaVersion int                          `yaml:"schema_version"`
	AutonomyMode  string                       `yaml:"autonomy_mode"`
	Defaults      ConfigDefaults               `yaml:"defaults"`
	Environments  map[string]EnvironmentPolicy `yaml:"environments"`
}

type ConfigDefaults struct {
	Cooldown              time.Duration `yaml:"cooldown"`
	HostBudgetCount       int           `yaml:"host_budget_count"`
	HostBudgetWindow      time.Duration `yaml:"host_budget_window"`
	ComponentBudgetCount  int           `yaml:"component_budget_count"`
	ComponentBudgetWindow time.Duration `yaml:"component_budget_window"`
}

// DefaultConfig returns design doc §7's initial bounded defaults, with
// every environment at its documented default posture (§4) and
// autonomy_mode disabled — a fresh deployment never auto-executes
// anything until an operator deliberately opts in.
func DefaultConfig() Config {
	return Config{
		SchemaVersion: 1,
		AutonomyMode:  ModeDisabled,
		Defaults: ConfigDefaults{
			Cooldown: 30 * time.Minute, HostBudgetCount: 2, HostBudgetWindow: 6 * time.Hour,
			ComponentBudgetCount: 5, ComponentBudgetWindow: time.Hour,
		},
		Environments: map[string]EnvironmentPolicy{
			"sandbox": EnvAllowR1, "staging": EnvAllowR1, "prod": EnvHumanOnly,
		},
	}
}

// componentAutonomy is one component action's per-environment autonomy
// opt-in (design doc §4's `autonomy:` block) — the caller resolves this
// from the plan's own contract action, same "never Agent input" rule
// every other execution-relevant field in this system follows.
type ComponentAutonomy struct {
	Sandbox string // "allowed" | "human" | "" (missing = human required)
	Staging string
	Prod    string
}

// Allowed reports whether env explicitly allows autonomy for this
// action — design doc §4: "Missing autonomy block = human required."
func (a ComponentAutonomy) Allowed(env string) bool {
	switch env {
	case "sandbox":
		return a.Sandbox == "allowed"
	case "staging":
		return a.Staging == "allowed"
	case "prod":
		return a.Prod == "allowed"
	default:
		return false
	}
}

// EvaluatePolicy is the pure deterministic decision core (design doc
// §10/§15). cfg.AutonomyMode == disabled always requires human
// regardless of every other guard — this is checked FIRST and short-
// circuits everything else, matching §9's "disabled: policy not used
// for execution" (the policy is not even consulted, not "consulted and
// happens to deny").
func EvaluatePolicy(cfg Config, autonomy ComponentAutonomy, in PolicyInput, now time.Time) PolicyDecision {
	d := PolicyDecision{PolicyID: "agent-monitoring-r1-autonomy", PolicyVersion: "1", EvaluatedAt: now}

	deny := func(reason string) PolicyDecision {
		d.Decision = DecisionDeny
		d.Reasons = append(d.Reasons, reason)
		return d
	}
	human := func(reason string) PolicyDecision {
		d.Decision = DecisionRequireHuman
		d.Reasons = append(d.Reasons, reason)
		return d
	}

	if cfg.AutonomyMode == ModeDisabled {
		return human("autonomy_mode is disabled")
	}

	// Guard 2: risk exactly R1.
	if in.Plan.Risk != "R1" {
		return deny("plan risk is not R1 — autonomy never covers R2/R3/R4")
	}
	// Guard 1 (one exact host) is a Plan-construction-time invariant
	// (internal/repair.BuildPlan already refuses anything else) — there
	// is no "multi-host plan" shape for this function to even receive,
	// so it is not re-checked here as a separate branch.

	envPolicy, knownEnv := cfg.Environments[in.Environment]
	if !knownEnv {
		return human("unknown environment " + in.Environment)
	}
	if envPolicy == EnvHumanOnly {
		return human("environment " + in.Environment + " is human-only by default policy")
	}

	// Guard 3: action contract allows autonomy in this environment.
	if !autonomy.Allowed(in.Environment) {
		return human("component action has no autonomy opt-in for " + in.Environment)
	}

	// Guard 4/5: kill switches.
	if in.GlobalKillSwitch {
		return deny("global kill switch is engaged")
	}
	if in.ComponentKillSwitch {
		return deny("component kill switch is engaged")
	}

	// Guard 6: maintenance/suppression.
	if in.MaintenanceMode {
		return human("maintenance mode is active")
	}

	// Circuit breakers (design doc §8, not one of §6's numbered 15 —
	// deny, not human: an open breaker means something is already going
	// wrong; escalate by denying autonomy outright rather than quietly
	// falling back to a human queue that may not be watched).
	if in.GlobalBreakerOpen {
		return deny("global circuit breaker is open")
	}
	if in.ComponentBreakerOpen {
		return deny("component circuit breaker is open")
	}
	if in.HostBreakerOpen {
		return deny("host circuit breaker is open")
	}

	// Guard 7: cooldown.
	if in.LastActionAt != nil {
		cooldown := cfg.Defaults.Cooldown
		if cooldown <= 0 {
			cooldown = 30 * time.Minute
		}
		if now.Sub(*in.LastActionAt) < cooldown {
			return human("cooldown active for this host/component/action")
		}
	}

	// Guard 8/9: budgets. Design doc §15's test table is explicit here
	// ("budget exhausted -> deny", unlike cooldown's "deny/human per
	// spec") — deny, not human, so an exhausted budget cannot be routed
	// around by a human approving more repairs than the cap allows.
	hostBudget := cfg.Defaults.HostBudgetCount
	if hostBudget <= 0 {
		hostBudget = 2
	}
	if in.PriorActionsHostWindow >= hostBudget {
		return deny("host auto-repair budget exhausted for this window")
	}
	componentBudget := cfg.Defaults.ComponentBudgetCount
	if componentBudget <= 0 {
		componentBudget = 5
	}
	if in.PriorActionsComponentWindow >= componentBudget {
		return deny("component auto-repair budget exhausted for this window")
	}

	// Guard 10: max one auto R1 per incident episode, AND no prior
	// failed autonomous repair for this episode (design doc §7/§6.10)
	// — both are covered by the same PriorFailuresIncident>0 check:
	// any prior attempt (successful or not) already consumed this
	// episode's one auto-repair budget.
	if in.PriorFailuresIncident > 0 {
		return human("incident episode already had a prior autonomous repair attempt")
	}

	// Guard 12: source incident must still be firing right before
	// execution — an alert that already resolved on its own needs no
	// repair at all.
	if !in.AlertStillFiring {
		return deny("source alert is no longer firing")
	}

	// Guard 13: no human rejection already recorded against this plan.
	if !in.NoHumanRejection {
		return human("a human has already rejected this exact plan")
	}

	// Guard 11: plan hash/inventory/contract must still be current.
	if !in.PlanFresh {
		return deny("plan is stale — contract or inventory changed since it was built")
	}

	// Guard 14/15: infrastructure health.
	if !in.AuditWritable {
		return deny("audit/change-journal persistence is not writable")
	}
	if !in.RepairInfraHealthy {
		return deny("repair MCP infrastructure is not healthy")
	}

	d.Decision = DecisionAllowAuto
	d.Reasons = []string{"all autonomy guards passed"}
	return d
}
