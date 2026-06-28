package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/anomalyco/pilot/internal/docs"
	"github.com/anomalyco/pilot/internal/ollama"
)

var indexPlaybooksCmd = &cobra.Command{
	Use:   "index-playbooks [dir...]",
	Short: "Index user playbooks for RAG search",
	Long: `Walk the given directories (default: ./playbooks and
~/.local/share/pilot/playbooks), parse each .yml/.yaml file
as a playbook, embed it, and append to the playbooks index.

Existing entries are NOT removed (use --refresh to clear first).`,
	RunE: runIndexPlaybooks,
}

var (
	indexPlaybooksRecursive bool
	indexPlaybooksRefresh   bool
	indexPlaybooksQuiet     bool
)

func init() {
	indexPlaybooksCmd.Flags().BoolVar(&indexPlaybooksRecursive, "recursive", false, "walk into subdirectories")
	indexPlaybooksCmd.Flags().BoolVar(&indexPlaybooksRefresh, "refresh", false, "discard existing index and rebuild from scratch")
	indexPlaybooksCmd.Flags().BoolVar(&indexPlaybooksQuiet, "quiet", false, "suppress progress output")
}

func runIndexPlaybooks(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	cfg := loadConfig()

	dirs := args
	if len(dirs) == 0 {
		home, _ := os.UserHomeDir()
		dirs = []string{"./playbooks", home + "/.local/share/pilot/playbooks"}
	}

	client := ollama.NewClient(cfg.OllamaURL, cfg.Model)
	if err := client.Ping(ctx); err != nil {
		return fmt.Errorf("ollama not reachable: %w", err)
	}
	client.SetEmbeddingModel(playbookEmbedMod)

	if !indexPlaybooksQuiet {
		fmt.Fprintf(os.Stderr, "🔍 Discovering playbooks in: %v\n", dirs)
	}
	files, err := docs.DiscoverPlaybooks(dirs, indexPlaybooksRecursive)
	if err != nil {
		return fmt.Errorf("discover: %w", err)
	}
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "No playbooks found.")
		return nil
	}
	if !indexPlaybooksQuiet {
		fmt.Fprintf(os.Stderr, "📦 Found %d playbook files\n", len(files))
	}

	// Parse and chunk
	var chunks []docs.Chunk
	playbookCount := 0
	for _, f := range files {
		pb, err := docs.ParsePlaybook(f)
		if err != nil {
			if !indexPlaybooksQuiet {
				fmt.Fprintf(os.Stderr, "  ! skip %s: %v\n", f, err)
			}
			continue
		}
		chunks = append(chunks, docs.ChunkPlaybook(pb)...)
		playbookCount++
	}
	if !indexPlaybooksQuiet {
		fmt.Fprintf(os.Stderr, "🧩 %d chunks from %d playbooks\n", len(chunks), playbookCount)
	}

	// Load existing or fresh
	path := docs.PathFor(cfg.DataDir, docs.SourcePlaybook)
	idx := docs.NewIndex()
	if !indexPlaybooksRefresh {
		if err := idx.Load(path); err == nil && idx.Size() > 0 {
			if !indexPlaybooksQuiet {
				fmt.Fprintf(os.Stderr, "📚 Existing index: %d chunks (merging)\n", idx.Size())
			}
		}
	}

	if !indexPlaybooksQuiet {
		fmt.Fprintln(os.Stderr, "🧮 Embedding…")
	}
	start := time.Now()
	lastPct := -1
	progress := func(done, total int, last docs.Chunk) {
		if indexPlaybooksQuiet {
			return
		}
		pct := done * 100 / total
		if pct == lastPct {
			return
		}
		lastPct = pct
		bar := makeProgressBar(pct, 30)
		fmt.Fprintf(os.Stderr, "\r  %s %3d%% (%d/%d, %s)", bar, pct, done, total, time.Since(start).Round(time.Second))
	}
	if err := idx.Build(ctx, client, chunks, progress); err != nil {
		return fmt.Errorf("build: %w", err)
	}
	if !indexPlaybooksQuiet {
		fmt.Fprintln(os.Stderr)
	}

	if err := idx.Save(path); err != nil {
		return err
	}
	if !indexPlaybooksQuiet {
		fmt.Fprintf(os.Stderr, "💾 Saved to %s\n", path)
		fmt.Fprintf(os.Stderr, "✓ Done. %d total chunks in playbooks index. Built in %s.\n",
			idx.Size(), time.Since(start).Round(time.Second))
	}
	return nil
}
