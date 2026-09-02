// remediation_cli.go implements the human-operator-only CLI surface for
// Agent Monitoring Phase 3's authority-separation model (design doc
// §2/§7): `incident show`, `remediation propose/show/approve/reject/
// execute`. None of this is ever called by `serve`'s own scheduler loop
// or by the Agent — actor identity for approve/reject comes from the
// operator invoking this CLI (--actor), never from Agent-supplied text.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/kjelly/pilot/internal/agentcontroller"
	"github.com/kjelly/pilot/internal/policy"
	"github.com/kjelly/pilot/internal/repair"
	"github.com/spf13/cobra"
)

func newIncidentCmd() *cobra.Command {
	incidentCmd := &cobra.Command{Use: "incident", Short: "Inspect incidents"}

	var dbPath string
	show := &cobra.Command{
		Use:   "show <incident-id>",
		Short: "Show one incident's current state",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := agentcontroller.OpenStoreReadOnly(dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			inc, err := store.GetIncident(args[0])
			if err != nil {
				return err
			}
			if inc == nil {
				return fmt.Errorf("no such incident: %s", args[0])
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(inc)
		},
	}
	show.Flags().StringVar(&dbPath, "db", "", "path to state.db (required)")
	show.MarkFlagRequired("db")
	incidentCmd.AddCommand(show)
	return incidentCmd
}

// repairClientFlags are shared by every remediation subcommand that
// talks to pilot's repair MCP family (propose, execute).
type repairClientFlags struct {
	pilotBinary string
	dir         string
	inventory   string
}

func (f *repairClientFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.pilotBinary, "pilot-binary", "pilot", "path to (or PATH-resolvable name of) the pilot binary to spawn for repair MCP calls")
	cmd.Flags().StringVar(&f.dir, "dir", ".", "workspace root passed to the spawned `pilot mcp serve --dir` (contracts/*.yaml resolve relative to it)")
	cmd.Flags().StringVar(&f.inventory, "inventory", "", "ansible inventory path repair actions may target (required)")
	cmd.MarkFlagRequired("inventory")
}

func (f *repairClientFlags) client() *agentcontroller.RepairClient {
	return &agentcontroller.RepairClient{PilotBinary: f.pilotBinary, Dir: f.dir, Inventory: f.inventory}
}

// requireManagedIncidentSubject is the SNMP monitoring integration spec
// §10.6 fail-closed guard: `remediation propose`/`reapply-propose` are
// the ONLY two places a repair/reapply plan is ever created from an
// incident_id (everything downstream — approve/execute/auto-execute —
// operates on an already-PROPOSED plan, never re-derives host/subject
// from the incident again), so refusing here is sufficient to guarantee
// no plan is EVER created for a non-managed-host subject — there is no
// other path into remediation_plans/reapply_plans that skips this call.
func requireManagedIncidentSubject(store *agentcontroller.Store, incidentID string) error {
	inc, err := store.GetIncident(incidentID)
	if err != nil {
		return fmt.Errorf("look up incident %s: %w", incidentID, err)
	}
	if inc == nil {
		return fmt.Errorf("incident %s not found", incidentID)
	}
	if !inc.Subject.Managed {
		return fmt.Errorf(
			"incident %s subject %q (kind=%q) is not a managed host — repair/autonomy is refused for external subjects (SNMP monitoring integration spec §10.6)",
			incidentID, inc.Subject.ID, inc.Subject.Kind)
	}
	return nil
}

func newRemediationCmd() *cobra.Command {
	remediationCmd := &cobra.Command{Use: "remediation", Short: "Human-approved R1 remediation workflow (Agent Monitoring Phase 3)"}

	remediationCmd.AddCommand(
		newRemediationProposeCmd(),
		newRemediationShowCmd(),
		newRemediationApproveCmd(),
		newRemediationRejectCmd(),
		newRemediationExecuteCmd(),
		newRemediationAutoExecuteCmd(),
		newReapplyProposeCmd(),
		newReapplyShowCmd(),
		newReapplyApproveCmd(),
		newReapplyRejectCmd(),
		newReapplyExecuteCmd(),
	)
	return remediationCmd
}

func newRemediationProposeCmd() *cobra.Command {
	var dbPath, incidentID, host, component, action string
	flags := &repairClientFlags{}
	cmd := &cobra.Command{
		Use:   "propose",
		Short: "Resolve an incident+host+component+action into an immutable R1 plan and persist it as PROPOSED",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := agentcontroller.OpenStore(dbPath)
			if err != nil {
				return err
			}
			defer store.Close()

			if err := requireManagedIncidentSubject(store, incidentID); err != nil {
				return err
			}

			wire, err := flags.client().Plan(cmd.Context(), incidentID, host, component, action)
			if err != nil {
				return fmt.Errorf("resolve plan via repair MCP: %w", err)
			}
			p, err := wire.ToPlan()
			if err != nil {
				return err
			}
			if err := store.CreatePlan(p); err != nil {
				return err
			}
			fmt.Printf("plan %s PROPOSED: %s on %s (%s), risk=%s, hash=%s, expires=%s\n",
				p.ID, p.Action, p.Host, p.Component, p.Risk, p.PlanHash, p.ExpiresAt.Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to state.db (required)")
	cmd.MarkFlagRequired("db")
	cmd.Flags().StringVar(&incidentID, "incident", "", "incident ID this plan is for (required)")
	cmd.MarkFlagRequired("incident")
	cmd.Flags().StringVar(&host, "host", "", "exact inventory hostname (required)")
	cmd.MarkFlagRequired("host")
	cmd.Flags().StringVar(&component, "component", "", "component ID from contracts/*.yaml (required)")
	cmd.MarkFlagRequired("component")
	cmd.Flags().StringVar(&action, "action", "", "remediation action id (required)")
	cmd.MarkFlagRequired("action")
	flags.register(cmd)
	return cmd
}

func newRemediationShowCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "show <plan-id>",
		Short: "Show one remediation plan's current state and approval history",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := agentcontroller.OpenStoreReadOnly(dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			p, err := store.GetPlan(args[0])
			if err != nil {
				return err
			}
			if p == nil {
				return fmt.Errorf("no such plan: %s", args[0])
			}
			approvals, err := store.ListApprovals(args[0])
			if err != nil {
				return err
			}
			out := struct {
				Plan      *agentcontroller.StoredPlan      `json:"plan"`
				Approvals []agentcontroller.ApprovalRecord `json:"approvals"`
			}{Plan: p, Approvals: approvals}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(out)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to state.db (required)")
	cmd.MarkFlagRequired("db")
	return cmd
}

func newRemediationApproveCmd() *cobra.Command {
	var dbPath, planHash, actor, reason string
	cmd := &cobra.Command{
		Use:   "approve <plan-id>",
		Short: "Record human approval of an exact plan hash — default is no-op/reject if you don't run this",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := agentcontroller.OpenStore(dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			rec, err := store.Approve(args[0], planHash, actor, reason, time.Now())
			if err != nil {
				return err
			}
			fmt.Printf("plan %s APPROVED by %s at %s\n", rec.PlanID, rec.Actor, rec.CreatedAt.Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to state.db (required)")
	cmd.MarkFlagRequired("db")
	cmd.Flags().StringVar(&planHash, "plan-hash", "", "the EXACT plan_hash shown by `remediation show` — approval is rejected if this does not match (required)")
	cmd.MarkFlagRequired("plan-hash")
	cmd.Flags().StringVar(&actor, "actor", "", "your own operator identity — never Agent-supplied text (required)")
	cmd.MarkFlagRequired("actor")
	cmd.Flags().StringVar(&reason, "reason", "", "why you are approving this plan")
	return cmd
}

func newRemediationRejectCmd() *cobra.Command {
	var dbPath, planHash, actor, reason string
	cmd := &cobra.Command{
		Use:   "reject <plan-id>",
		Short: "Record human rejection of a plan — terminal; propose a new plan instead of reconsidering this one",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := agentcontroller.OpenStore(dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			rec, err := store.Reject(args[0], planHash, actor, reason, time.Now())
			if err != nil {
				return err
			}
			fmt.Printf("plan %s REJECTED by %s at %s\n", rec.PlanID, rec.Actor, rec.CreatedAt.Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to state.db (required)")
	cmd.MarkFlagRequired("db")
	cmd.Flags().StringVar(&planHash, "plan-hash", "", "the EXACT plan_hash shown by `remediation show` (required)")
	cmd.MarkFlagRequired("plan-hash")
	cmd.Flags().StringVar(&actor, "actor", "", "your own operator identity (required)")
	cmd.MarkFlagRequired("actor")
	cmd.Flags().StringVar(&reason, "reason", "", "why you are rejecting this plan")
	return cmd
}

func newRemediationExecuteCmd() *cobra.Command {
	var dbPath string
	flags := &repairClientFlags{}
	cmd := &cobra.Command{
		Use:   "execute <plan-id>",
		Short: "Execute an APPROVED plan: one typed action on one exact host, then verify — never process exit code alone",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := agentcontroller.OpenStore(dbPath)
			if err != nil {
				return err
			}
			defer store.Close()

			started := time.Now()
			p, err := store.MarkExecuting(args[0], started)
			if err != nil {
				return fmt.Errorf("cannot execute: %w", err)
			}

			result, applyErr := flags.client().Apply(cmd.Context(), agentcontroller.RepairPlanFromStored(p))
			finished := time.Now()
			finalResult := result.Result
			if applyErr != nil {
				finalResult = agentcontroller.PlanStateExecutionFailed
			}
			if finalResult == "" {
				finalResult = agentcontroller.PlanStateVerificationInconclusive
			}
			if finishErr := store.FinishRun(p.ID, finalResult, result.AuditDirectory, "", started, finished); finishErr != nil {
				return fmt.Errorf("record run outcome: %w", finishErr)
			}
			if applyErr != nil {
				return fmt.Errorf("repair apply: %w", applyErr)
			}
			fmt.Printf("plan %s -> %s (execution_ok=%v verify_passed=%v)\n", p.ID, result.Result, result.ExecutionOK, result.VerifyPassed)
			if result.Result != agentcontroller.PlanStateAppliedVerified {
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to state.db (required)")
	cmd.MarkFlagRequired("db")
	flags.register(cmd)
	return cmd
}

// newRemediationAutoExecuteCmd implements Agent Monitoring Phase 4's
// unified execution path (design doc §3/§12): evaluate a PROPOSED plan
// against the live policy facts, persist that decision unconditionally,
// and — ONLY in enforced mode with an allow_auto decision — authorize
// execution via the EXACT SAME Store.Approve/MarkExecuting/FinishRun
// sequence `remediation approve` + `remediation execute` use for a
// human, differing only in actor identity (agentcontroller.PolicyActor).
// There is no separate "autoRestart" shortcut anywhere in this path.
func newRemediationAutoExecuteCmd() *cobra.Command {
	var dbPath, environment string
	var cooldown, hostBudgetWindow, componentBudgetWindow time.Duration
	var hostBudgetCount, componentBudgetCount int
	flags := &repairClientFlags{}
	cmd := &cobra.Command{
		Use:   "auto-execute <plan-id>",
		Short: "Policy-gated autonomous execution: evaluate a PROPOSED plan; execute only if allow_auto AND autonomy mode is enforced",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := agentcontroller.OpenStore(dbPath)
			if err != nil {
				return err
			}
			defer store.Close()

			now := time.Now()
			if recovered, rerr := store.RecoverOrphanedExecutingPlans(now); rerr != nil {
				return fmt.Errorf("recover orphaned plans: %w", rerr)
			} else if recovered > 0 {
				fmt.Printf("recovered %d orphaned EXECUTING plan(s) from an unclean shutdown\n", recovered)
			}

			p, err := store.GetPlan(args[0])
			if err != nil {
				return err
			}
			if p == nil {
				return fmt.Errorf("no such plan: %s", args[0])
			}
			if p.State != agentcontroller.PlanStateProposed {
				return fmt.Errorf("plan %s is %s, not PROPOSED — auto-execute only evaluates a freshly proposed plan", p.ID, p.State)
			}

			autonomyState, err := store.AutonomyMode()
			if err != nil {
				return err
			}
			cfg := policy.DefaultConfig()
			cfg.AutonomyMode = autonomyState.Mode
			// Design doc §7: "Configuration may tighten these [bounded
			// defaults]." Flags default to DefaultConfig()'s own values
			// (cmd.Flags().Changed checks are unnecessary — an unset flag
			// just re-supplies the same default), so a deployment that
			// never passes them behaves identically to before these flags
			// existed.
			cfg.Defaults.Cooldown = cooldown
			cfg.Defaults.HostBudgetCount = hostBudgetCount
			cfg.Defaults.HostBudgetWindow = hostBudgetWindow
			cfg.Defaults.ComponentBudgetCount = componentBudgetCount
			cfg.Defaults.ComponentBudgetWindow = componentBudgetWindow

			client := flags.client()
			in, compAutonomy, err := store.GatherPolicyInput(cmd.Context(), client, cfg, *p, environment, now)
			if err != nil {
				return fmt.Errorf("gather policy facts: %w", err)
			}

			decision, err := store.EvaluateAndRecord(cfg, compAutonomy, in, *p, autonomyState.Mode, now)
			if err != nil {
				return err
			}
			fmt.Printf("policy decision: %s (mode=%s) reasons=%v\n", decision.Decision, autonomyState.Mode, decision.Reasons)

			switch {
			case autonomyState.Mode == policy.ModeDisabled:
				fmt.Println("autonomy disabled: leaving plan PROPOSED for human review")
				return nil
			case autonomyState.Mode == policy.ModeShadow:
				fmt.Println("shadow mode: decision recorded, no execution — leaving plan PROPOSED")
				return nil
			case decision.Decision != policy.DecisionAllowAuto:
				fmt.Println("not allow_auto: leaving plan PROPOSED for human review")
				return nil
			}

			actor := agentcontroller.PolicyActor(decision.PolicyID, decision.PolicyVersion)
			reason := fmt.Sprintf("policy allow_auto: %v", decision.Reasons)
			if _, err := store.Approve(p.ID, p.PlanHash, actor, reason, now); err != nil {
				return fmt.Errorf("policy auto-approve: %w", err)
			}

			started := time.Now()
			executing, err := store.MarkExecuting(p.ID, started)
			if err != nil {
				return fmt.Errorf("cannot execute: %w", err)
			}
			result, applyErr := client.Apply(cmd.Context(), agentcontroller.RepairPlanFromStored(executing))
			finished := time.Now()
			finalResult := result.Result
			if applyErr != nil {
				finalResult = agentcontroller.PlanStateExecutionFailed
			}
			if finalResult == "" {
				finalResult = agentcontroller.PlanStateVerificationInconclusive
			}
			if finishErr := store.FinishRun(executing.ID, finalResult, result.AuditDirectory, "", started, finished); finishErr != nil {
				return fmt.Errorf("record run outcome: %w", finishErr)
			}

			if finalResult != agentcontroller.PlanStateAppliedVerified {
				// Design doc §8/§13: any failed/inconclusive autonomous
				// outcome trips the affected component AND host breakers
				// immediately (single-strike, not "repeated" — the
				// conservative MVP choice documented in
				// policy_evaluate.go: a tripped breaker never silently
				// self-clears, so favoring an over-eager trip over a
				// missed one is the safer failure mode here).
				breakerReason := fmt.Sprintf("autonomous execution result=%s plan=%s", finalResult, executing.ID)
				if berr := store.TripBreaker(agentcontroller.BreakerScopeComponent(executing.Component), breakerReason, finished); berr != nil {
					fmt.Printf("warning: failed to trip component breaker: %v\n", berr)
				}
				if berr := store.TripBreaker(agentcontroller.BreakerScopeHost(executing.Host), breakerReason, finished); berr != nil {
					fmt.Printf("warning: failed to trip host breaker: %v\n", berr)
				}
				fmt.Printf("plan %s -> %s — breakers tripped for component:%s and host:%s, operator reset required\n",
					executing.ID, finalResult, executing.Component, executing.Host)
				if applyErr != nil {
					return fmt.Errorf("repair apply: %w", applyErr)
				}
				os.Exit(1)
			}
			fmt.Printf("plan %s -> %s (execution_ok=%v verify_passed=%v)\n", executing.ID, result.Result, result.ExecutionOK, result.VerifyPassed)
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to state.db (required)")
	cmd.MarkFlagRequired("db")
	cmd.Flags().StringVar(&environment, "environment", "", "sandbox | staging | prod — this evaluation's trust tier (required)")
	cmd.MarkFlagRequired("environment")
	def := policy.DefaultConfig().Defaults
	cmd.Flags().DurationVar(&cooldown, "cooldown", def.Cooldown, "minimum time between actions on the same host/component/action")
	cmd.Flags().IntVar(&hostBudgetCount, "host-budget-count", def.HostBudgetCount, "max approved actions per host within --host-budget-window")
	cmd.Flags().DurationVar(&hostBudgetWindow, "host-budget-window", def.HostBudgetWindow, "window --host-budget-count is measured over")
	cmd.Flags().IntVar(&componentBudgetCount, "component-budget-count", def.ComponentBudgetCount, "max approved actions per component within --component-budget-window")
	cmd.Flags().DurationVar(&componentBudgetWindow, "component-budget-window", def.ComponentBudgetWindow, "window --component-budget-count is measured over")
	flags.register(cmd)
	return cmd
}

// ---- Agent Monitoring Phase 5: R2 canonical-apply reapply ------------
//
// reapply-propose/show/approve/reject/execute mirror the R1 propose/
// show/approve/reject/execute commands exactly, on their OWN plan
// family (reapply_plans/reapply_approvals/reapply_runs) — an R1
// approval can never authorize R2 (design doc §12), and there is
// deliberately no `reapply auto-execute` counterpart anywhere in this
// binary: R2 is always human-approved, in every environment, enforced
// by simply never having built an autonomous entry point for it.

func newReapplyProposeCmd() *cobra.Command {
	var dbPath, incidentID, host, component, action string
	flags := &repairClientFlags{}
	cmd := &cobra.Command{
		Use:   "reapply-propose",
		Short: "Resolve an incident+host+component+R2-action into an immutable canonical-apply plan and persist it as PROPOSED",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := agentcontroller.OpenStore(dbPath)
			if err != nil {
				return err
			}
			defer store.Close()

			if err := requireManagedIncidentSubject(store, incidentID); err != nil {
				return err
			}

			wire, err := flags.client().ReapplyPlan(cmd.Context(), incidentID, host, component, action)
			if err != nil {
				return fmt.Errorf("resolve reapply plan via repair MCP: %w", err)
			}
			p, err := wire.ToReapplyPlan()
			if err != nil {
				return err
			}
			if err := store.CreateReapplyPlan(p); err != nil {
				return err
			}
			fmt.Printf("reapply plan %s PROPOSED: %s on %s (%s), risk=%s, playbook=%s, preview_changed=%d, hash=%s, expires=%s\n",
				p.ID, p.Action, p.Host, p.Component, p.Risk, p.Resolved.PlaybookPath, p.Resolved.PreviewEstimatedChanged, p.PlanHash, p.ExpiresAt.Format(time.RFC3339))
			if p.Resolved.PreviewSummary != "" {
				fmt.Printf("--- preview summary ---\n%s\n-----------------------\n", p.Resolved.PreviewSummary)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to state.db (required)")
	cmd.MarkFlagRequired("db")
	cmd.Flags().StringVar(&incidentID, "incident", "", "incident ID this plan is for (required)")
	cmd.MarkFlagRequired("incident")
	cmd.Flags().StringVar(&host, "host", "", "exact inventory hostname (required)")
	cmd.MarkFlagRequired("host")
	cmd.Flags().StringVar(&component, "component", "", "component ID from contracts/*.yaml (required)")
	cmd.MarkFlagRequired("component")
	cmd.Flags().StringVar(&action, "action", "", "R2 canonical_apply remediation action id (required)")
	cmd.MarkFlagRequired("action")
	flags.register(cmd)
	return cmd
}

func newReapplyShowCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "reapply-show <plan-id>",
		Short: "Show one R2 reapply plan's current state, resolved metadata, and approval history",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := agentcontroller.OpenStoreReadOnly(dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			p, err := store.GetReapplyPlan(args[0])
			if err != nil {
				return err
			}
			if p == nil {
				return fmt.Errorf("no such reapply plan: %s", args[0])
			}
			approvals, err := store.ListReapplyApprovals(args[0])
			if err != nil {
				return err
			}
			out := struct {
				Plan      *agentcontroller.StoredReapplyPlan      `json:"plan"`
				Approvals []agentcontroller.ReapplyApprovalRecord `json:"approvals"`
			}{Plan: p, Approvals: approvals}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(out)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to state.db (required)")
	cmd.MarkFlagRequired("db")
	return cmd
}

func newReapplyApproveCmd() *cobra.Command {
	var dbPath, planHash, actor, reason string
	cmd := &cobra.Command{
		Use:   "reapply-approve <plan-id>",
		Short: "Record human approval of an exact R2 plan hash — R2 is ALWAYS human-approved, in every environment",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := agentcontroller.OpenStore(dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			rec, err := store.ApproveReapply(args[0], planHash, actor, reason, time.Now())
			if err != nil {
				return err
			}
			fmt.Printf("reapply plan %s APPROVED by %s at %s\n", rec.PlanID, rec.Actor, rec.CreatedAt.Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to state.db (required)")
	cmd.MarkFlagRequired("db")
	cmd.Flags().StringVar(&planHash, "plan-hash", "", "the EXACT plan_hash shown by `remediation reapply-show` — approval is rejected if this does not match (required)")
	cmd.MarkFlagRequired("plan-hash")
	cmd.Flags().StringVar(&actor, "actor", "", "your own operator identity — never Agent-supplied text (required)")
	cmd.MarkFlagRequired("actor")
	cmd.Flags().StringVar(&reason, "reason", "", "why you are approving this plan")
	return cmd
}

func newReapplyRejectCmd() *cobra.Command {
	var dbPath, planHash, actor, reason string
	cmd := &cobra.Command{
		Use:   "reapply-reject <plan-id>",
		Short: "Record human rejection of an R2 plan — terminal; propose a new plan instead of reconsidering this one",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := agentcontroller.OpenStore(dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			rec, err := store.RejectReapply(args[0], planHash, actor, reason, time.Now())
			if err != nil {
				return err
			}
			fmt.Printf("reapply plan %s REJECTED by %s at %s\n", rec.PlanID, rec.Actor, rec.CreatedAt.Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to state.db (required)")
	cmd.MarkFlagRequired("db")
	cmd.Flags().StringVar(&planHash, "plan-hash", "", "the EXACT plan_hash shown by `remediation reapply-show` (required)")
	cmd.MarkFlagRequired("plan-hash")
	cmd.Flags().StringVar(&actor, "actor", "", "your own operator identity (required)")
	cmd.MarkFlagRequired("actor")
	cmd.Flags().StringVar(&reason, "reason", "", "why you are rejecting this plan")
	return cmd
}

func newReapplyExecuteCmd() *cobra.Command {
	var dbPath string
	flags := &repairClientFlags{}
	cmd := &cobra.Command{
		Use:   "reapply-execute <plan-id>",
		Short: "Execute an APPROVED R2 plan: canonical apply on one exact host, then verify — never process exit code alone",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := agentcontroller.OpenStore(dbPath)
			if err != nil {
				return err
			}
			defer store.Close()

			now := time.Now()
			if recovered, rerr := store.RecoverOrphanedExecutingReapplyPlans(now); rerr != nil {
				return fmt.Errorf("recover orphaned reapply plans: %w", rerr)
			} else if recovered > 0 {
				fmt.Printf("recovered %d orphaned EXECUTING reapply plan(s) from an unclean shutdown\n", recovered)
			}

			started := time.Now()
			p, err := store.MarkReapplyExecuting(args[0], started)
			if err != nil {
				return fmt.Errorf("cannot execute: %w", err)
			}

			result, applyErr := flags.client().ReapplyApply(cmd.Context(), agentcontroller.ReapplyPlanWireFromStored(p))
			finished := time.Now()
			finalResult := result.Result
			if applyErr != nil {
				finalResult = repair.ReapplyApplyFailedPartial
			}
			if finalResult == "" {
				finalResult = repair.ReapplyAppliedVerificationFailed
			}
			if finishErr := store.FinishReapplyRun(p.ID, finalResult, result.Changed, result.AuditDirectory, "", started, finished); finishErr != nil {
				return fmt.Errorf("record run outcome: %w", finishErr)
			}
			if applyErr != nil {
				return fmt.Errorf("reapply apply: %w", applyErr)
			}
			fmt.Printf("reapply plan %s -> %s (execution_ok=%v changed=%d verify_passed=%v)\n", p.ID, result.Result, result.ExecutionOK, result.Changed, result.VerifyPassed)
			if result.Result != repair.ReapplyAppliedVerified {
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to state.db (required)")
	cmd.MarkFlagRequired("db")
	flags.register(cmd)
	return cmd
}
