package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anomalyco/pilot/internal/docs"
	"github.com/anomalyco/pilot/internal/ollama"
)

var searchDocsCmd = &cobra.Command{
	Use:   "search-docs <query>",
	Short: "Search the local Ansible documentation index",
	Long: `Query the local index of Ansible module docs (and indexed
user playbooks). Useful for ad-hoc lookups outside of an agent run.

Module docs use a bleve (BM25) index. User playbooks use the older
vector index. The two are merged when --source is "all".`,
	Args: cobra.MinimumNArgs(1),
	RunE: runSearchDocs,
}

var (
	searchK      int
	searchSource string
)

func init() {
	searchDocsCmd.Flags().IntVar(&searchK, "k", 5, "number of results")
	searchDocsCmd.Flags().StringVar(&searchSource, "source", "all", "modules|playbooks|all")
}

func runSearchDocs(cmd *cobra.Command, args []string) error {
	cfg := loadConfig()
	query := strings.Join(args, " ")

	var source docs.Source
	switch searchSource {
	case "modules":
		source = docs.SourceModule
	case "playbooks":
		source = docs.SourcePlaybook
	case "all", "":
		source = ""
	default:
		return fmt.Errorf("invalid --source: %s (use modules|playbooks|all)", searchSource)
	}

	// Try to open the bleve-backed module index.
	blevePath := moduleBlevePath(cfg.DataDir)
	modIdx := docs.NewModuleIndex(blevePath)
	modErr := modIdx.Open()
	if modErr != nil {
		slog.Warn("module index not found (run `pilot index-docs` first)", "path", blevePath, "err", modErr)
	}
	if source == docs.SourceModule {
		if modErr != nil {
			return modErr
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

	// Load the playbook index (self-built, vector-based).
	pbIdx := docs.NewIndex()
	pbPath := docs.PathFor(cfg.DataDir, docs.SourcePlaybook)
	if err := pbIdx.Load(pbPath); err != nil {
		slog.Warn("playbook index not found", "path", pbPath)
	}

	// Playbook search still needs an embedder; set up the Ollama client
	// only when the playbook path is in scope.
	ctx := context.Background()
	client := ollama.NewClient(cfg.OllamaURL, cfg.Model)
	client.SetEmbeddingModel(playbookEmbedMod)

	if source == docs.SourcePlaybook {
		if pbIdx.Size() == 0 {
			fmt.Fprintln(os.Stderr, "Playbook index is empty.")
			return nil
		}
		matches, err := pbIdx.Search(ctx, client, query, searchK, docs.SourcePlaybook)
		if err != nil {
			return fmt.Errorf("search playbooks: %w", err)
		}
		printMatches(query, matches, pbIdx)
		return nil
	}

	// "all": search both indices and merge by score.
	if modErr == nil {
		defer func() { _ = modIdx.Close() }()
	}
	modMatches := []docs.Match{}
	if modErr == nil && modIdx.Size() > 0 {
		m, err := modIdx.Search(query, searchK)
		if err != nil {
			return fmt.Errorf("search modules: %w", err)
		}
		modMatches = m
	}
	pbMatches := []docs.Match{}
	if pbIdx.Size() > 0 {
		m, err := pbIdx.Search(ctx, client, query, searchK, docs.SourcePlaybook)
		if err != nil {
			return fmt.Errorf("search playbooks: %w", err)
		}
		pbMatches = m
	}
	printMerged(query, modMatches, pbMatches, modIdx, pbIdx)
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

func printMerged(query string, modMatches, pbMatches []docs.Match, modIdx *docs.ModuleIndex, pbIdx *docs.Index) {
	type tagged struct {
		m       docs.Match
		fromMod bool
	}
	all := make([]tagged, 0, len(modMatches)+len(pbMatches))
	for _, m := range modMatches {
		all = append(all, tagged{m, true})
	}
	for _, m := range pbMatches {
		all = append(all, tagged{m, false})
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].m.Score > all[j].m.Score
	})
	fmt.Printf("## search-docs: %q (%d results)\n\n", query, len(all))
	for i, t := range all {
		var c docs.Chunk
		if t.fromMod {
			c = modIdx.ChunkByIndex(t.m.Index)
		} else {
			c = pbIdx.ChunkByIndex(t.m.Index)
		}
		if c.ID == "" {
			continue
		}
		src := "module"
		if !t.fromMod {
			src = "playbook"
		}
		fmt.Printf("### %d. [%s] %s [%s] (score=%.3f)\n", i+1, src, c.Ref, c.Section, t.m.Score)
		if path, ok := c.Metadata["path"].(string); ok {
			fmt.Printf("_%s_\n", path)
		}
		for _, line := range strings.Split(c.Text, "\n") {
			fmt.Printf("  %s\n", line)
		}
		fmt.Println()
	}
}
