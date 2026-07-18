package cmd

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anomalyco/pilot/internal/store"
)

var (
	runsLimit     int
	runsHost      string
	runsComponent string
)

var runsCmd = &cobra.Command{Use: "runs", Short: "Query append-only delivery evidence"}
var runsListCmd = &cobra.Command{Use: "list", Short: "List recent delivery runs", Args: cobra.NoArgs, RunE: runRunsList}
var runsShowCmd = &cobra.Command{Use: "show <run-id>", Short: "Show one run and host-by-row evidence", Args: cobra.ExactArgs(1), RunE: runRunsShow}
var runsLastSuccessCmd = &cobra.Command{Use: "last-success", Short: "Show a host's most recent successful delivery", Args: cobra.NoArgs, RunE: runRunsLastSuccess}
var runsPendingSpecCmd = &cobra.Command{Use: "pending-spec <spec-path>", Short: "List recorded hosts not passing a spec", Args: cobra.ExactArgs(1), RunE: runRunsPendingSpec}
var runsDiffCmd = &cobra.Command{Use: "diff <run-a> <run-b>", Short: "Diff host-by-row evidence between two runs", Args: cobra.ExactArgs(2), RunE: runRunsDiff}
var runsAffectedCmd = &cobra.Command{Use: "affected", Short: "List recorded runs for a component", Args: cobra.NoArgs, RunE: runRunsAffected}

func init() {
	runsListCmd.Flags().IntVar(&runsLimit, "limit", 50, "maximum runs to display")
	runsListCmd.Flags().StringVar(&runsHost, "host", "", "only runs that included this host")
	runsListCmd.Flags().StringVar(&runsComponent, "component", "", "only runs that selected this contract component")
	runsLastSuccessCmd.Flags().StringVar(&runsHost, "host", "", "host to query (required)")
	runsAffectedCmd.Flags().StringVar(&runsComponent, "component", "", "contract component to query (required)")
	runsAffectedCmd.Flags().IntVar(&runsLimit, "limit", 50, "maximum runs to display")
	runsCmd.AddCommand(runsListCmd, runsShowCmd, runsLastSuccessCmd, runsPendingSpecCmd, runsDiffCmd, runsAffectedCmd)
	rootCmd.AddCommand(runsCmd)
}

func runRunsList(cmd *cobra.Command, _ []string) error {
	s, err := openSpecStore()
	if err != nil {
		return err
	}
	defer s.Close()
	runs, err := s.ListRuns(store.RunFilter{Limit: runsLimit, Host: runsHost, Component: runsComponent})
	if err != nil {
		return err
	}
	for _, run := range runs {
		writeRunLine(cmd, run)
	}
	return nil
}

func runRunsShow(cmd *cobra.Command, args []string) error {
	s, err := openSpecStore()
	if err != nil {
		return err
	}
	defer s.Close()
	run, evidence, err := s.GetRun(args[0])
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "run_id: %s\noutcome: %s\nstage: %s\ncomponents: %s\nplaybook: %s\ninventory: %s\nhosts: %s\nstarted_at: %s\nfinished_at: %s\n", run.RunID, run.Outcome, run.Stage, strings.Join(run.Components, ","), run.Playbook, run.Inventory, strings.Join(run.Hosts, ","), run.StartedAt, run.FinishedAt)
	if len(run.Metadata) > 0 {
		encoded, err := json.Marshal(run.Metadata)
		if err != nil {
			return fmt.Errorf("encode recorded run metadata: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "metadata: %s\n", encoded)
	}
	for _, row := range evidence {
		flags := make([]string, 0, 3)
		if row.Redacted {
			flags = append(flags, "redacted")
		}
		if row.StdoutTruncated {
			flags = append(flags, "stdout_truncated")
		}
		if row.StderrTruncated {
			flags = append(flags, "stderr_truncated")
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\t%s\trc=%d\t%s\n", row.SpecPath, row.RowID, row.Host, row.ProbeStatus, row.Verdict, row.ExitCode, strings.Join(flags, ","))
	}
	return nil
}

func runRunsLastSuccess(cmd *cobra.Command, _ []string) error {
	if runsHost == "" {
		return fmt.Errorf("--host is required")
	}
	s, err := openSpecStore()
	if err != nil {
		return err
	}
	defer s.Close()
	run, err := s.LastSuccess(runsHost)
	if err != nil {
		return err
	}
	writeRunLine(cmd, run)
	return nil
}

func runRunsPendingSpec(cmd *cobra.Command, args []string) error {
	s, err := openSpecStore()
	if err != nil {
		return err
	}
	defer s.Close()
	pending, err := s.PendingSpec(args[0])
	if err != nil {
		return err
	}
	for _, item := range pending {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\t%s\n", item.Host, item.Verdict, item.ProbeStatus, item.RunID, item.FinishedAt)
	}
	return nil
}

func runRunsDiff(cmd *cobra.Command, args []string) error {
	s, err := openSpecStore()
	if err != nil {
		return err
	}
	defer s.Close()
	diffs, err := s.DiffRuns(args[0], args[1])
	if err != nil {
		return err
	}
	for _, diff := range diffs {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\t%s\n", diff.SpecPath, diff.RowID, diff.Host, diff.Before, diff.After)
	}
	return nil
}

func runRunsAffected(cmd *cobra.Command, _ []string) error {
	if runsComponent == "" {
		return fmt.Errorf("--component is required")
	}
	s, err := openSpecStore()
	if err != nil {
		return err
	}
	defer s.Close()
	runs, err := s.ListRuns(store.RunFilter{Limit: runsLimit, Component: runsComponent})
	if err != nil {
		return err
	}
	for _, run := range runs {
		writeRunLine(cmd, run)
	}
	return nil
}

func writeRunLine(cmd *cobra.Command, run store.DeliveryRun) {
	exit := ""
	if run.ExitCode != nil {
		exit = strconv.Itoa(*run.ExitCode)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\t%s\t%s\n", run.RunID, run.Outcome, exit, strings.Join(run.Components, ","), strings.Join(run.Hosts, ","), run.StartedAt)
}
