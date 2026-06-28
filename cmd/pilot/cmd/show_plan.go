package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/anomalyco/pilot/internal/store"
)

var showPlanCmd = &cobra.Command{
	Use:   "show-plan <plan-id>",
	Short: "Show a plan from the audit log",
	Long: `Read pilot's SQLite history database and print a single plan's
metadata, summary, and operation list. Status is one of:
pending | approved | rejected | executed | failed.`,
	Args: cobra.ExactArgs(1),
	RunE: runShowPlan,
}

func runShowPlan(cmd *cobra.Command, args []string) error {
	cfg := loadConfig()
	st, err := store.Open(filepath.Join(cfg.DataDir, "history.db"))
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = st.Close() }()

	p, err := st.GetPlan(args[0])
	if err != nil {
		return fmt.Errorf("get plan %q: %w", args[0], err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "ID:\t%s\n", p.ID)
	fmt.Fprintf(w, "Run:\t%s\n", shortID(p.RunID))
	fmt.Fprintf(w, "Title:\t%s\n", p.Title)
	fmt.Fprintf(w, "Status:\t%s\n", p.Status)
	fmt.Fprintf(w, "Created:\t%s\n", p.CreatedAt.Local().Format("2006-01-02 15:04:05"))
	if p.ReviewedAt != nil {
		fmt.Fprintf(w, "Reviewed:\t%s\n", p.ReviewedAt.Local().Format("2006-01-02 15:04:05"))
	}
	if p.ExecutedAt != nil {
		fmt.Fprintf(w, "Executed:\t%s\n", p.ExecutedAt.Local().Format("2006-01-02 15:04:05"))
	}
	if p.Summary != "" {
		fmt.Fprintf(w, "Summary:\t%s\n", p.Summary)
	}
	_ = w.Flush()

	fmt.Fprintln(os.Stdout, "\nOperations:")
	for i, op := range p.Operations {
		fmt.Fprintf(os.Stdout, "  [%d] %-7s %-22s %s\n",
			i+1, strings.ToUpper(op.RiskLevel), op.Tool, op.Rationale)
	}
	return nil
}
