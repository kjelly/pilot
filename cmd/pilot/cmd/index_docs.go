package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/anomalyco/pilot/internal/docs"
)

var indexDocsCmd = &cobra.Command{
	Use:   "index-docs",
	Short: "Build the local Ansible module documentation index",
	Long: `Build (or rebuild) the local index of Ansible module
documentation. Reads all modules via 'ansible-doc -t module --json',
chunks them, and indexes into a local bleve (BM25) index at
~/.local/share/pilot/docs.bleve.

First run on a fresh install will take 30-90 seconds (no embedding
required). Subsequent runs are fast if ansible-core is unchanged.`,
	RunE: runIndexDocs,
}

var (
	indexRefresh  bool
	indexNoSave   bool
	indexQuiet    bool
	indexEmbedMod string // kept as a no-op for backward compatibility
)

func init() {
	indexDocsCmd.Flags().BoolVar(&indexRefresh, "refresh", false, "rebuild even if index is up to date")
	indexDocsCmd.Flags().BoolVar(&indexNoSave, "no-save", false, "do not save index to disk (for testing)")
	indexDocsCmd.Flags().BoolVar(&indexQuiet, "quiet", false, "suppress progress output")
	indexDocsCmd.Flags().StringVar(&indexEmbedMod, "embedding-model", "", "deprecated: no longer required (kept for backward compatibility)")
}

func runIndexDocs(cmd *cobra.Command, args []string) error {
	if indexEmbedMod != "" && !indexQuiet {
		fmt.Fprintln(os.Stderr, "⚠️  --embedding-model is deprecated and ignored; docs index no longer uses embeddings.")
	}
	ctx := context.Background()
	cfg := loadConfig()

	if _, err := exec.LookPath("ansible-doc"); err != nil {
		return fmt.Errorf("ansible-doc not found on PATH; install ansible-core to use this command")
	}

	if !indexQuiet {
		fmt.Fprintln(os.Stderr, "🔍 Detecting ansible-core version…")
	}
	ver, err := docs.AnsibleVersion(ctx)
	if err != nil {
		return err
	}
	if !indexQuiet {
		fmt.Fprintf(os.Stderr, "   %s\n", ver)
	}
	moduleNames, err := docs.ModuleNames(ctx)
	if err != nil {
		return fmt.Errorf("list modules: %w", err)
	}
	if !indexQuiet {
		fmt.Fprintf(os.Stderr, "📦 Found %d modules\n", len(moduleNames))
	}

	// Detect legacy v1 JSON index and warn.
	legacyPath := docs.PathFor(cfg.DataDir, docs.SourceModule)
	if _, err := os.Stat(legacyPath); err == nil {
		if !indexQuiet {
			fmt.Fprintf(os.Stderr, "⚠️  Legacy index found at %s. It will be removed during the rebuild.\n", legacyPath)
		}
	}

	if !indexRefresh {
		if !needsRebuild(cfg.DataDir, ver, moduleNames) {
			fmt.Fprintln(os.Stderr, "✓ Index is up to date. Use --refresh to rebuild.")
			return nil
		}
	}

	if !indexQuiet {
		fmt.Fprintln(os.Stderr, "📖 Extracting module documentation…")
	}
	modules, err := docs.FetchAllModules(ctx, "")
	if err != nil {
		return fmt.Errorf("fetch modules: %w", err)
	}

	// Chunk: per-parameter chunks so the LLM can ask "what does
	// parameter X do" and get a single targeted hit instead of a
	// module-level blob.
	chunks := BuildLLMChunks(modules)
	if !indexQuiet {
		fmt.Fprintf(os.Stderr, "🧩 %d chunks produced\n", len(chunks))
		fmt.Fprintln(os.Stderr, "📚 Indexing into bleve (BM25)…")
	}

	// Open the bleve-backed module index.
	blevePath := moduleBlevePath(cfg.DataDir)
	idx := docs.NewModuleIndex(blevePath)
	if err := idx.Open(); err != nil {
		return fmt.Errorf("open bleve index: %w", err)
	}
	defer func() { _ = idx.Close() }()

	start := time.Now()
	lastPct := -1
	progress := func(done, total int) {
		if indexQuiet {
			return
		}
		pct := done * 100 / total
		if pct == lastPct {
			return
		}
		lastPct = pct
		bar := makeProgressBar(pct, 30)
		elapsed := time.Since(start).Round(time.Second)
		fmt.Fprintf(os.Stderr, "\r  %s %3d%% (%d/%d, %s)", bar, pct, done, total, elapsed)
	}
	_ = progress
	// bleve indexing is fast enough that we don't need progress callback,
	// but the Build signature accepts one — pass a no-op for now.
	if err := idx.Build(chunks); err != nil {
		return fmt.Errorf("build index: %w", err)
	}
	if !indexQuiet {
		fmt.Fprintln(os.Stderr)
	}

	// Save meta
	if err := saveIndexMeta(cfg.DataDir, ver, moduleNames, len(modules), len(chunks)); err != nil {
		return err
	}

	// Remove legacy JSON index if present.
	if _, err := os.Stat(legacyPath); err == nil {
		if err := os.Remove(legacyPath); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to remove legacy index %s: %v\n", legacyPath, err)
		}
	}

	if !indexNoSave {
		if !indexQuiet {
			info, err := dirSize(blevePath)
			if err == nil {
				fmt.Fprintf(os.Stderr, "💾 Saved to %s (%s)\n", blevePath, humanBytes(info))
			} else {
				fmt.Fprintf(os.Stderr, "💾 Saved to %s\n", blevePath)
			}
		}
	}

	if !indexQuiet {
		fmt.Fprintf(os.Stderr, "✓ Index ready. %d modules, %d chunks. Built in %s.\n",
			len(modules), len(chunks), time.Since(start).Round(time.Second))
	}
	return nil
}

// moduleBlevePath returns the on-disk path for the bleve-backed module
// index, derived from the data directory.
func moduleBlevePath(dataDir string) string {
	return filepath.Join(dataDir, "docs.bleve")
}

func makeProgressBar(pct, width int) string {
	filled := pct * width / 100
	if filled > width {
		filled = width
	}
	bar := ""
	for i := 0; i < width; i++ {
		if i < filled {
			bar += "█"
		} else {
			bar += "░"
		}
	}
	return bar
}

func humanBytes(n int64) string {
	const k = 1024
	if n < k {
		return fmt.Sprintf("%d B", n)
	}
	if n < k*k {
		return fmt.Sprintf("%.1f KB", float64(n)/k)
	}
	return fmt.Sprintf("%.1f MB", float64(n)/(k*k))
}

func needsRebuild(dataDir, ansibleVersion string, moduleNames []string) bool {
	meta, err := loadIndexMeta(dataDir)
	if err != nil {
		return true
	}
	want := docs.VersionHash(ansibleVersion, moduleNames)
	return meta.VersionHash != want
}

func saveIndexMeta(dataDir, ansibleVersion string, modules []string, moduleCount, chunkCount int) error {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	meta := map[string]any{
		"ansible_version": ansibleVersion,
		"version_hash":    docs.VersionHash(ansibleVersion, modules),
		"module_count":    moduleCount,
		"chunk_count":     chunkCount,
		"index_engine":    "bleve-bm25",
		"built_at":        time.Now().Format(time.RFC3339),
	}
	data, _ := json.MarshalIndent(meta, "", "  ")
	return os.WriteFile(filepath.Join(dataDir, "docs-index.meta"), data, 0o644)
}

func loadIndexMeta(dataDir string) (docs.Meta, error) {
	data, err := os.ReadFile(filepath.Join(dataDir, "docs-index.meta"))
	if err != nil {
		return docs.Meta{}, err
	}
	var m docs.Meta
	if err := json.Unmarshal(data, &m); err != nil {
		return docs.Meta{}, err
	}
	return m, nil
}

// dirSize returns the total byte count of all files under dir. Used for
// reporting the on-disk size of the bleve index directory.
func dirSize(dir string) (int64, error) {
	var total int64
	err := filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total, err
}
