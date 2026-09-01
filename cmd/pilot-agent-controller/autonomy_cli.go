// autonomy_cli.go implements Agent Monitoring Phase 4's operator
// administration surface (design doc §9): `autonomy status/enable/
// disable/reset-breaker`. Like remediation_cli.go's approve/reject,
// actor identity always comes from the CLI caller (--actor), never from
// Agent-supplied text, and every mode/breaker change is persisted with
// actor/reason/time (design doc §9: "Persist actor/reason/time").
package main

import (
	"fmt"
	"time"

	"github.com/kjelly/pilot/internal/agentcontroller"
	"github.com/kjelly/pilot/internal/policy"
	"github.com/spf13/cobra"
)

func newAutonomyCmd() *cobra.Command {
	autonomyCmd := &cobra.Command{Use: "autonomy", Short: "Administer Agent Monitoring Phase 4's autonomy mode and circuit breakers"}
	autonomyCmd.AddCommand(
		newAutonomyStatusCmd(),
		newAutonomyEnableCmd(),
		newAutonomyDisableCmd(),
		newAutonomyKillCmd(),
		newAutonomyResetBreakerCmd(),
	)
	return autonomyCmd
}

func newAutonomyStatusCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the current autonomy mode and every circuit breaker that has ever tripped",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := agentcontroller.OpenStoreReadOnly(dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			st, err := store.AutonomyMode()
			if err != nil {
				return err
			}
			fmt.Printf("mode: %s (set by %s at %s: %s)\n", st.Mode, st.Actor, st.UpdatedAt.Format(time.RFC3339), st.Reason)
			breakers, err := store.ListBreakers()
			if err != nil {
				return err
			}
			if len(breakers) == 0 {
				fmt.Println("breakers: none have ever tripped")
				return nil
			}
			for _, b := range breakers {
				fmt.Printf("breaker %-24s %-6s reason=%q\n", b.Scope, b.State, b.Reason)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to state.db (required)")
	cmd.MarkFlagRequired("db")
	return cmd
}

func newAutonomyEnableCmd() *cobra.Command {
	var dbPath, mode, actor, reason string
	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Turn autonomy on in shadow (evaluate/log only) or enforced (may actually execute) mode",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := agentcontroller.OpenStore(dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			st, err := store.SetAutonomyMode(mode, actor, reason, time.Now())
			if err != nil {
				return err
			}
			fmt.Printf("autonomy mode -> %s (by %s)\n", st.Mode, st.Actor)
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to state.db (required)")
	cmd.MarkFlagRequired("db")
	cmd.Flags().StringVar(&mode, "mode", policy.ModeShadow, "shadow (evaluate/persist would_allow_auto, never mutate) or enforced (allow_auto actually authorizes execution)")
	cmd.Flags().StringVar(&actor, "actor", "", "your own operator identity — never Agent-supplied text (required)")
	cmd.MarkFlagRequired("actor")
	cmd.Flags().StringVar(&reason, "reason", "", "why you are enabling autonomy (required — design doc §9: persist actor/reason/time)")
	cmd.MarkFlagRequired("reason")
	return cmd
}

func newAutonomyDisableCmd() *cobra.Command {
	var dbPath, actor, reason string
	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Turn autonomy off — human-approved R1 and observe-only diagnosis remain available (design doc §19 rollback)",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := agentcontroller.OpenStore(dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			st, err := store.SetAutonomyMode(policy.ModeDisabled, actor, reason, time.Now())
			if err != nil {
				return err
			}
			fmt.Printf("autonomy mode -> %s (by %s)\n", st.Mode, st.Actor)
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to state.db (required)")
	cmd.MarkFlagRequired("db")
	cmd.Flags().StringVar(&actor, "actor", "", "your own operator identity (required)")
	cmd.MarkFlagRequired("actor")
	cmd.Flags().StringVar(&reason, "reason", "", "why you are disabling autonomy (required)")
	cmd.MarkFlagRequired("reason")
	return cmd
}

// newAutonomyKillCmd is the manual emergency-stop primitive design doc
// guards 4/5 ("global kill switch off"/"component kill switch off")
// require. It is deliberately implemented as TripBreaker on the SAME
// scope an automatic verification-failure trip would use (see
// internal/agentcontroller/policy_evaluate.go's doc comment) — one
// audited on/off mechanism per scope, not two: an operator-engaged kill
// and an automatically-tripped breaker carry the identical "does not
// self-clear, reset must be audited" contract, so they share state
// rather than duplicating it.
func newAutonomyKillCmd() *cobra.Command {
	var dbPath, reason string
	cmd := &cobra.Command{
		Use:   "kill <scope>",
		Short: `Manually engage the kill switch for a scope: "global", "component:<id>", or "host:<name>" — blocks autonomy immediately until reset-breaker`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := agentcontroller.OpenStore(dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			if err := store.TripBreaker(args[0], reason, time.Now()); err != nil {
				return err
			}
			fmt.Printf("kill switch engaged for %s — autonomy blocked until `autonomy reset-breaker %s`\n", args[0], args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to state.db (required)")
	cmd.MarkFlagRequired("db")
	cmd.Flags().StringVar(&reason, "reason", "", "why you are engaging the kill switch (required)")
	cmd.MarkFlagRequired("reason")
	return cmd
}

func newAutonomyResetBreakerCmd() *cobra.Command {
	var dbPath, actor, reason string
	cmd := &cobra.Command{
		Use:   "reset-breaker <scope>",
		Short: `Close a tripped breaker. scope is exactly what "autonomy status" prints: "global", "component:<id>", or "host:<name>"`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := agentcontroller.OpenStore(dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			if err := store.ResetBreaker(args[0], actor, reason, time.Now()); err != nil {
				return err
			}
			fmt.Printf("breaker %s -> CLOSED (by %s)\n", args[0], actor)
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to state.db (required)")
	cmd.MarkFlagRequired("db")
	cmd.Flags().StringVar(&actor, "actor", "", "your own operator identity (required) — a tripped breaker never self-clears")
	cmd.MarkFlagRequired("actor")
	cmd.Flags().StringVar(&reason, "reason", "", "why you believe it is safe to reset (required)")
	cmd.MarkFlagRequired("reason")
	return cmd
}
