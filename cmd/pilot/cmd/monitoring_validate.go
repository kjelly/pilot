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

var monValidateSNMPCatalog string

func init() {
	addMonitoringDirFlag(monitoringValidateCmd)
	monitoringValidateCmd.Flags().StringVar(&monValidateSNMPCatalog, "snmp-catalog", "", "override the workspace's monitoring/snmp/catalog.yml path (default: <dir>/monitoring/snmp/catalog.yml)")
	monitoringCmd.AddCommand(monitoringValidateCmd)
}

func runMonitoringValidate(cmd *cobra.Command, _ []string) error {
	ws := resolveMonitoringWorkspace(monDir)
	if monValidateSNMPCatalog != "" {
		ws.SNMPCatalogPath = monValidateSNMPCatalog
	}
	tf, pf, err := ws.load()
	if err != nil {
		return err
	}
	catalog, err := ws.loadSNMPCatalog()
	if err != nil {
		return err
	}
	if err := catalog.Validate(); err != nil {
		return fmt.Errorf("snmp catalog %s: %w", ws.SNMPCatalogPath, err)
	}
	r := monitoring.Validate(tf, pf, catalog)
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
