package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/monitoring"
)

// monitoringValidateCmd is pure local validation (spec.md §32) — it never
// touches a network or a remote host, unlike `target test`.
var monitoringValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate monitoring/targets.yml and monitoring/scrape-profiles.yml (schema + cross-reference checks only — no network access)",
	Args:  cobra.NoArgs,
	RunE:  runMonitoringValidate,
}

func init() {
	addMonitoringDirFlag(monitoringValidateCmd)
	monitoringCmd.AddCommand(monitoringValidateCmd)
}

func runMonitoringValidate(cmd *cobra.Command, _ []string) error {
	ws := resolveMonitoringWorkspace(monDir)
	tf, pf, err := ws.load()
	if err != nil {
		return err
	}
	r := monitoring.Validate(tf, pf)
	printViolations(cmd.OutOrStdout(), r)
	if !r.OK() {
		// Non-zero exit on failure (spec.md §75); `target list`/`profile
		// list` stay exit 0 even on an empty registry — this command is the
		// only one whose whole job is to fail loudly.
		return fmt.Errorf("validation failed: %d error(s)", len(r.Errors))
	}
	fmt.Fprintln(cmd.OutOrStdout(), "OK")
	return nil
}
