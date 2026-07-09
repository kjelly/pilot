package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/anomalyco/pilot/internal/docs"
)

// ensureDocsIndex makes sure the module index is fresh. If the
// installed ansible-core version (or the module list) has changed,
// rebuild. Returns true if a rebuild was performed.
func ensureDocsIndex(ctx context.Context, dataDir string) (rebuilt bool, err error) {
	ver, err := docs.AnsibleVersion(ctx)
	if err != nil {
		// ansible not on PATH — skip silently
		return false, nil
	}
	modNames, err := docs.ModuleNames(ctx)
	if err != nil {
		return false, err
	}
	meta, err := loadIndexMeta(dataDir)
	if err != nil {
		// No meta — definitely need to build
		fmt.Fprintf(os.Stderr, "⚠️  Documentation index missing. Run `pilot index-docs` (this may take 30-90 sec).\n")
		return false, nil
	}
	want := docs.VersionHash(ver, modNames)
	if meta.VersionHash == want {
		return false, nil // up to date
	}
	if runStrictIndex {
		return false, fmt.Errorf("ansible-core version changed (was: %s, now: %s); run `pilot index-docs` to rebuild (or drop --strict-index)", meta.AnsibleVersion, ver)
	}
	if runNoIndexOnStart {
		fmt.Fprintf(os.Stderr, "⚠️  ansible-core version changed (%s → %s). Continuing without rebuild (--no-index-on-start).\n", meta.AnsibleVersion, ver)
		return false, nil
	}
	fmt.Fprintf(os.Stderr, "🔄 ansible-core version changed (%s → %s), rebuilding docs index…\n", meta.AnsibleVersion, ver)
	return true, runIndexDocsSubcommand(ctx, dataDir, ver, modNames)
}

// runIndexDocsSubcommand is a stripped-down version of index-docs
// for auto-rebuild. It does not take CLI flags — bleve (BM25) is used
// for the docs index; no embedding is required.
func runIndexDocsSubcommand(ctx context.Context, dataDir, ansibleVersion string, moduleNames []string) error {
	modules, err := docs.FetchAllModules(ctx, "")
	if err != nil {
		return err
	}
	chunks := BuildLLMChunks(modules)
	fmt.Fprintf(os.Stderr, "  📖 %d modules, %d chunks\n", len(modules), len(chunks))

	blevePath := moduleBlevePath(dataDir)
	idx := docs.NewModuleIndex(blevePath)
	if err := idx.Open(); err != nil {
		return err
	}
	defer func() { _ = idx.Close() }()
	start := time.Now()
	if err := idx.Build(chunks); err != nil {
		return err
	}
	if err := saveIndexMeta(dataDir, ansibleVersion, moduleNames, len(modules), len(chunks)); err != nil {
		return err
	}
	// Remove legacy JSON index if present.
	legacy := docs.PathFor(dataDir, docs.SourceModule)
	if _, err := os.Stat(legacy); err == nil {
		_ = os.Remove(legacy)
	}
	fmt.Fprintf(os.Stderr, "  ✓ Index rebuilt in %s\n", time.Since(start).Round(time.Second))
	return nil
}
