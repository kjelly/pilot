package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anomalyco/pilot/internal/docs"
)

var searchDocsCmd = &cobra.Command{
	Use:   "search-docs <query>",
	Short: "Search the local Ansible documentation index",
	Long: `Query the local bleve (BM25) index of Ansible module docs.
Useful for ad-hoc lookups outside of an agent run.`,
	Args: cobra.MinimumNArgs(1),
	RunE: runSearchDocs,
}

var searchK int

func init() {
	searchDocsCmd.Flags().IntVar(&searchK, "k", 5, "number of results")
}

func runSearchDocs(cmd *cobra.Command, args []string) error {
	cfg := loadConfig()
	query := strings.Join(args, " ")

	blevePath := moduleBlevePath(cfg.DataDir)
	modIdx := docs.NewModuleIndex(blevePath)
	if err := modIdx.Open(); err != nil {
		slog.Warn("module index not found (run `pilot index-docs` first)", "path", blevePath, "err", err)
		return err
	}
	defer func() { _ = modIdx.Close() }()
	if modIdx.Size() == 0 {
		fmt.Fprintln(os.Stderr, "Module index is empty.")
		return nil
	}
	matches, err := modIdx.Search(query, searchK)
	if err != nil {
		return fmt.Errorf("search: %w", err)
	}
	printMatches(query, matches, modIdx)
	return nil
}

func printMatches(query string, matches []docs.Match, idx interface {
	ChunkByIndex(int) docs.Chunk
}) {
	fmt.Printf("## search-docs: %q (%d results)\n\n", query, len(matches))
	for i, m := range matches {
		c := idx.ChunkByIndex(m.Index)
		if c.ID == "" {
			continue
		}
		fmt.Printf("### %d. %s [%s] (score=%.3f)\n", i+1, c.Ref, c.Section, m.Score)
		if path, ok := c.Metadata["path"].(string); ok {
			fmt.Printf("_%s_\n", path)
		}
		for _, line := range strings.Split(c.Text, "\n") {
			fmt.Printf("  %s\n", line)
		}
		fmt.Println()
	}
}
