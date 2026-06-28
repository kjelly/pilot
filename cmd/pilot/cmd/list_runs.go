package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/anomalyco/pilot/internal/store"
)

var (
	listRunsLimit  int
	listRunsBatch  string
)

var listRunsCmd = &cobra.Command{
	Use:   "list-runs",
	Short: "List pilot runs from the audit log",
	Long: `Read pilot's SQLite history database and print a table of past
runs. Each row shows the run ID, start time, mode, playbook, status,
and (when in dry-run mode) a flag.

By default the most recent 20 runs are shown; pass --limit to change.`,
	RunE: runListRuns,
}

func init() {
	listRunsCmd.Flags().IntVar(&listRunsLimit, "limit", 20, "maximum number of runs to show")
	listRunsCmd.Flags().StringVar(&listRunsBatch, "batch", "", "show only runs with this batch id")
}

func runListRuns(cmd *cobra.Command, args []string) error {
	cfg := loadConfig()
	st, err := store.Open(filepath.Join(cfg.DataDir, "history.db"))
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = st.Close() }()

	runs, err := st.ListRuns(listRunsBatch, listRunsLimit)
	if err != nil {
		return fmt.Errorf("list runs: %w", err)
	}
	if len(runs) == 0 {
		fmt.Fprintln(os.Stderr, "No runs found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSTARTED\tMODE\tPLAYBOOK\tSTATUS\tDRY-RUN")
	for _, r := range runs {
		dry := ""
		if r.DryRun {
			dry = "yes"
		}
		playbook := r.Playbook
		if playbook == "" {
			playbook = "(chat)"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			shortID(r.ID),
			r.StartedAt.Local().Format(time.RFC3339),
			r.Mode,
			truncatePath(playbook, 50),
			r.Status,
			dry,
		)
	}
	_ = w.Flush()
	_ = context.Background() // keep import for future use
	return nil
}

func truncatePath(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-(n-3):]
}
