package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/anomalyco/pilot/internal/store"
)

var showProposalCmd = &cobra.Command{
	Use:   "show-proposal <proposal-id>",
	Short: "Show a single proposal from the audit log",
	Long: `Read pilot's SQLite history database and print a single
proposal's metadata, args, and (if recorded) result.

The proposal ID is the short hash printed at approval time and
stored in the on-disk YAML artifact under
~/.local/share/pilot/proposals/<id>.yaml.`,
	Args: cobra.ExactArgs(1),
	RunE: runShowProposal,
}

func runShowProposal(cmd *cobra.Command, args []string) error {
	cfg := loadConfig()
	st, err := store.Open(filepath.Join(cfg.DataDir, "history.db"))
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = st.Close() }()

	p, err := st.GetProposal(args[0])
	if err != nil {
		return fmt.Errorf("get proposal %q: %w", args[0], err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "ID:\t%s\n", p.ID)
	fmt.Fprintf(w, "Run ID:\t%s\n", shortID(p.RunID))
	fmt.Fprintf(w, "Tool:\t%s\n", p.Tool)
	fmt.Fprintf(w, "Host:\t%s\n", p.Host)
	fmt.Fprintf(w, "Risk:\t%s\n", p.RiskLevel)
	if p.CISControl != "" {
		fmt.Fprintf(w, "CIS:\t%s\n", p.CISControl)
	}
	fmt.Fprintf(w, "Status:\t%s\n", p.Status)
	fmt.Fprintf(w, "Reversible:\t%v\n", p.Reversible)
	if p.DryRun {
		fmt.Fprintf(w, "Dry-run:\tyes\n")
	}
	fmt.Fprintf(w, "Created:\t%s\n", p.CreatedAt.Local().Format("2006-01-02 15:04:05"))
	if p.ReviewedAt != nil {
		fmt.Fprintf(w, "Reviewed:\t%s\n", p.ReviewedAt.Local().Format("2006-01-02 15:04:05"))
	}
	if p.AppliedAt != nil {
		fmt.Fprintf(w, "Applied:\t%s\n", p.AppliedAt.Local().Format("2006-01-02 15:04:05"))
	}
	if p.FilePath != "" {
		fmt.Fprintf(w, "Artifact:\t%s\n", p.FilePath)
	}
	_ = w.Flush()

	if p.Rationale != "" {
		fmt.Fprintln(os.Stdout, "\nRationale:")
		fmt.Fprintf(os.Stdout, "  %s\n", p.Rationale)
	}

	fmt.Fprintln(os.Stdout, "\nArgs:")
	// Pretty-print JSON if possible.
	var pretty interface{}
	if err := json.Unmarshal(p.Args, &pretty); err == nil {
		out, _ := json.MarshalIndent(pretty, "  ", "  ")
		fmt.Fprintf(os.Stdout, "  %s\n", string(out))
	} else {
		fmt.Fprintf(os.Stdout, "  %s\n", string(p.Args))
	}

	// Note: ResultContent / ResultIsError are stored on the in-memory
	// agent.Proposal but not persisted to SQLite. Inspect the on-disk
	// YAML artifact (FilePath) for full result text.
	return nil
}
