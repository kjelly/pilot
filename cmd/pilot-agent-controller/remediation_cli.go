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

func newRemediationCmd() *cobra.Command {
	remediationCmd := &cobra.Command{Use: "remediation", Short: "Human-approved R1 remediation workflow (Agent Monitoring Phase 3)"}

	remediationCmd.AddCommand(
		newRemediationProposeCmd(),
		newRemediationShowCmd(),
		newRemediationApproveCmd(),
		newRemediationRejectCmd(),
		newRemediationExecuteCmd(),
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
