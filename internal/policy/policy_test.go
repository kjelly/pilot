package policy

import (
	"testing"
	"time"
)

// basePlan is a Risk R1 plan that satisfies every guard on its own — each
// test case below starts from this baseline and mutates exactly the one
// input the case exists to exercise, per design doc §15's table.
func baseInput() PolicyInput {
	return PolicyInput{
		Plan:               Plan{Host: "host-1", Component: "alertmanager", Action: "restart", Risk: "R1"},
		Environment:        "sandbox",
		AlertStillFiring:   true,
		LastActionAt:       nil,
		PlanFresh:          true,
		NoHumanRejection:   true,
		AuditWritable:      true,
		RepairInfraHealthy: true,
	}
}

func baseAutonomy() ComponentAutonomy {
	return ComponentAutonomy{Sandbox: "allowed", Staging: "allowed", Prod: "human"}
}

func TestEvaluatePolicy_TableCases(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	enforced := DefaultConfig()
	enforced.AutonomyMode = ModeEnforced

	cases := []struct {
		name     string
		cfg      Config
		autonomy ComponentAutonomy
		mutate   func(*PolicyInput)
		want     string
	}{
		{
			name:     "sandbox eligible -> allow",
			cfg:      enforced,
			autonomy: baseAutonomy(),
			mutate:   func(in *PolicyInput) {},
			want:     DecisionAllowAuto,
		},
		{
			name:     "prod -> human",
			cfg:      enforced,
			autonomy: baseAutonomy(),
			mutate:   func(in *PolicyInput) { in.Environment = "prod" },
			want:     DecisionRequireHuman,
		},
		{
			name:     "no component opt-in -> human",
			cfg:      enforced,
			autonomy: ComponentAutonomy{}, // no environment allowed
			mutate:   func(in *PolicyInput) {},
			want:     DecisionRequireHuman,
		},
		{
			name:     "cooldown active -> human",
			cfg:      enforced,
			autonomy: baseAutonomy(),
			mutate: func(in *PolicyInput) {
				recent := now.Add(-5 * time.Minute)
				in.LastActionAt = &recent
			},
			want: DecisionRequireHuman,
		},
		{
			name:     "host budget exhausted -> deny",
			cfg:      enforced,
			autonomy: baseAutonomy(),
			mutate:   func(in *PolicyInput) { in.PriorActionsHostWindow = 2 },
			want:     DecisionDeny,
		},
		{
			name:     "component budget exhausted -> deny",
			cfg:      enforced,
			autonomy: baseAutonomy(),
			mutate:   func(in *PolicyInput) { in.PriorActionsComponentWindow = 5 },
			want:     DecisionDeny,
		},
		{
			name:     "prior failed auto repair -> human",
			cfg:      enforced,
			autonomy: baseAutonomy(),
			mutate:   func(in *PolicyInput) { in.PriorFailuresIncident = 1 },
			want:     DecisionRequireHuman,
		},
		{
			name:     "stale plan -> deny",
			cfg:      enforced,
			autonomy: baseAutonomy(),
			mutate:   func(in *PolicyInput) { in.PlanFresh = false },
			want:     DecisionDeny,
		},
		{
			name:     "alert resolved -> deny",
			cfg:      enforced,
			autonomy: baseAutonomy(),
			mutate:   func(in *PolicyInput) { in.AlertStillFiring = false },
			want:     DecisionDeny,
		},
		{
			name:     "global kill switch -> deny",
			cfg:      enforced,
			autonomy: baseAutonomy(),
			mutate:   func(in *PolicyInput) { in.GlobalKillSwitch = true },
			want:     DecisionDeny,
		},
		{
			name:     "component kill switch -> deny",
			cfg:      enforced,
			autonomy: baseAutonomy(),
			mutate:   func(in *PolicyInput) { in.ComponentKillSwitch = true },
			want:     DecisionDeny,
		},
		{
			name:     "global breaker open -> deny",
			cfg:      enforced,
			autonomy: baseAutonomy(),
			mutate:   func(in *PolicyInput) { in.GlobalBreakerOpen = true },
			want:     DecisionDeny,
		},
		{
			name:     "component breaker open -> deny",
			cfg:      enforced,
			autonomy: baseAutonomy(),
			mutate:   func(in *PolicyInput) { in.ComponentBreakerOpen = true },
			want:     DecisionDeny,
		},
		{
			name:     "host breaker open -> deny",
			cfg:      enforced,
			autonomy: baseAutonomy(),
			mutate:   func(in *PolicyInput) { in.HostBreakerOpen = true },
			want:     DecisionDeny,
		},
		{
			name:     "unknown environment -> human",
			cfg:      enforced,
			autonomy: baseAutonomy(),
			mutate:   func(in *PolicyInput) { in.Environment = "canary" },
			want:     DecisionRequireHuman,
		},
		{
			name:     "human rejection recorded -> human",
			cfg:      enforced,
			autonomy: baseAutonomy(),
			mutate:   func(in *PolicyInput) { in.NoHumanRejection = false },
			want:     DecisionRequireHuman,
		},
		{
			name:     "audit not writable -> deny",
			cfg:      enforced,
			autonomy: baseAutonomy(),
			mutate:   func(in *PolicyInput) { in.AuditWritable = false },
			want:     DecisionDeny,
		},
		{
			name:     "repair infra unhealthy -> deny",
			cfg:      enforced,
			autonomy: baseAutonomy(),
			mutate:   func(in *PolicyInput) { in.RepairInfraHealthy = false },
			want:     DecisionDeny,
		},
		{
			name:     "risk not R1 -> deny",
			cfg:      enforced,
			autonomy: baseAutonomy(),
			mutate:   func(in *PolicyInput) { in.Plan.Risk = "R2" },
			want:     DecisionDeny,
		},
		{
			name:     "maintenance mode -> human",
			cfg:      enforced,
			autonomy: baseAutonomy(),
			mutate:   func(in *PolicyInput) { in.MaintenanceMode = true },
			want:     DecisionRequireHuman,
		},
		{
			name:     "mode disabled -> human regardless of guards",
			cfg:      DefaultConfig(), // AutonomyMode defaults to disabled
			autonomy: baseAutonomy(),
			mutate:   func(in *PolicyInput) {},
			want:     DecisionRequireHuman,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := baseInput()
			tc.mutate(&in)
			got := EvaluatePolicy(tc.cfg, tc.autonomy, in, now)
			if got.Decision != tc.want {
				t.Fatalf("Decision = %q, want %q (reasons: %v)", got.Decision, tc.want, got.Reasons)
			}
			if len(got.Reasons) == 0 {
				t.Fatal("Reasons must never be empty")
			}
			if got.PolicyID == "" || got.PolicyVersion == "" {
				t.Fatal("PolicyID/PolicyVersion must always be set")
			}
			if !got.EvaluatedAt.Equal(now) {
				t.Fatalf("EvaluatedAt = %v, want %v", got.EvaluatedAt, now)
			}
		})
	}
}

// TestEvaluatePolicy_R2NeverEligible locks in the phase-exit-gate
// invariant "no R2/R3/R4 is auto-eligible" (design doc §18) across every
// risk value, not just R2.
func TestEvaluatePolicy_R2NeverEligible(t *testing.T) {
	now := time.Now()
	cfg := DefaultConfig()
	cfg.AutonomyMode = ModeEnforced
	autonomy := baseAutonomy()

	for _, risk := range []string{"R2", "R3", "R4", "", "r1"} {
		in := baseInput()
		in.Plan.Risk = risk
		got := EvaluatePolicy(cfg, autonomy, in, now)
		if got.Decision == DecisionAllowAuto {
			t.Fatalf("risk %q must never allow_auto, got %+v", risk, got)
		}
	}
}

// TestEvaluatePolicy_ProdDefaultIsHuman locks in "prod default remains
// human" (design doc §18) even when a component action's autonomy block
// explicitly opts prod in — the environment-level default (§4) is a
// separate gate from the per-action opt-in (guard 3), and EnvHumanOnly
// wins regardless of what the action contract says.
func TestEvaluatePolicy_ProdDefaultIsHuman(t *testing.T) {
	now := time.Now()
	cfg := DefaultConfig()
	cfg.AutonomyMode = ModeEnforced
	autonomy := ComponentAutonomy{Sandbox: "allowed", Staging: "allowed", Prod: "allowed"}

	in := baseInput()
	in.Environment = "prod"
	got := EvaluatePolicy(cfg, autonomy, in, now)
	if got.Decision == DecisionAllowAuto {
		t.Fatalf("prod must default to human/deny even with an explicit opt-in, got %+v", got)
	}
}

// TestEvaluatePolicy_ShadowModeStillEvaluates documents that shadow mode
// (design doc §9/§16) runs the SAME evaluator as enforced — the only
// difference is what the caller does with an allow_auto result (persist
// would_allow_auto vs. actually execute). The pure decision core has no
// notion of "shadow" as a distinct branch; the caller decides.
func TestEvaluatePolicy_ShadowModeStillEvaluates(t *testing.T) {
	now := time.Now()
	cfg := DefaultConfig()
	cfg.AutonomyMode = ModeShadow
	autonomy := baseAutonomy()

	got := EvaluatePolicy(cfg, autonomy, baseInput(), now)
	if got.Decision != DecisionAllowAuto {
		t.Fatalf("shadow mode must still evaluate guards normally, got %+v", got)
	}
}

func TestComponentAutonomy_Allowed(t *testing.T) {
	a := ComponentAutonomy{Sandbox: "allowed", Staging: "human", Prod: ""}
	if !a.Allowed("sandbox") {
		t.Error("sandbox should be allowed")
	}
	if a.Allowed("staging") {
		t.Error("staging=human should not be allowed")
	}
	if a.Allowed("prod") {
		t.Error("prod empty (missing block) should not be allowed")
	}
	if a.Allowed("canary") {
		t.Error("unknown environment should never be allowed")
	}
}

func TestDefaultConfig_MatchesDesignDocDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.AutonomyMode != ModeDisabled {
		t.Errorf("AutonomyMode = %q, want disabled — a fresh deployment must never auto-execute", cfg.AutonomyMode)
	}
	if cfg.Defaults.Cooldown != 30*time.Minute {
		t.Errorf("Cooldown = %v, want 30m", cfg.Defaults.Cooldown)
	}
	if cfg.Defaults.HostBudgetCount != 2 || cfg.Defaults.HostBudgetWindow != 6*time.Hour {
		t.Errorf("host budget = %d/%v, want 2/6h", cfg.Defaults.HostBudgetCount, cfg.Defaults.HostBudgetWindow)
	}
	if cfg.Defaults.ComponentBudgetCount != 5 || cfg.Defaults.ComponentBudgetWindow != time.Hour {
		t.Errorf("component budget = %d/%v, want 5/1h", cfg.Defaults.ComponentBudgetCount, cfg.Defaults.ComponentBudgetWindow)
	}
	if cfg.Environments["prod"] != EnvHumanOnly {
		t.Errorf("prod environment = %q, want human_only", cfg.Environments["prod"])
	}
	if cfg.Environments["sandbox"] != EnvAllowR1 || cfg.Environments["staging"] != EnvAllowR1 {
		t.Error("sandbox/staging should default to allow_r1")
	}
}
