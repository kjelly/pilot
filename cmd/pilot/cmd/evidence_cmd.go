package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/evidence"
)

var (
	evidenceClosureRoot      string
	evidenceClosurePlaybooks []string
	evidenceClosureSpecs     []string
)

var evidenceCmd = &cobra.Command{
	Use:   "evidence",
	Short: "Inspect actual-run evidence inputs (AGENTS.md §1.2, docs/actual-run-evidence.md)",
}

var evidenceClosureCmd = &cobra.Command{
	Use:   "closure [-- <ansible extra-vars>...]",
	Short: "Print discovered execution inputs and unresolved closure limits",
	Long: `Resolves the playbooks (import_playbook, include_tasks/import_tasks, template
and copy sources, scripts, vars files, lookup('file'|'template'|'fileglob')),
the verification specs, their contracts and the -e @files inside the repository,
and prints them with Git blob ids as JSON. This is the same list
'vm-target test --evidence-record' writes into a record; a gate compares the
blob ids with HEAD instead of trusting a hand-written dependency list.
Templated references are matched as globs and marked dynamic; references the
resolver cannot follow are listed under "unresolved". External plugin, collection
and Python discovery paths are not fingerprinted, so current records always mark
ambient discovery unresolved and cannot qualify for automatic reuse. Exact-candidate
evidence remains usable.`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(evidenceClosurePlaybooks) == 0 {
			return fmt.Errorf("at least one --playbook is required")
		}
		c, err := evidence.ComputeClosure(evidence.ClosureInput{Root: evidenceClosureRoot, Playbooks: evidenceClosurePlaybooks, Specs: evidenceClosureSpecs, ExtraArgs: args})
		if err != nil {
			return err
		}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(c)
	},
}

func init() {
	wd, _ := os.Getwd()
	evidenceClosureCmd.Flags().StringVar(&evidenceClosureRoot, "root", wd, "repository root the run executes from")
	evidenceClosureCmd.Flags().StringArrayVar(&evidenceClosurePlaybooks, "playbook", nil, "playbook the run executes (repeatable)")
	evidenceClosureCmd.Flags().StringArrayVar(&evidenceClosureSpecs, "spec", nil, "verification spec the run verifies (repeatable)")
	evidenceCmd.AddCommand(evidenceClosureCmd)
	rootCmd.AddCommand(evidenceCmd)
}
