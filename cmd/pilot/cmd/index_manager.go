package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/anomalyco/pilot/internal/app"
	"github.com/anomalyco/pilot/internal/docs"
	"github.com/anomalyco/pilot/internal/ollama"
	"github.com/anomalyco/pilot/internal/store"
)

// playbookEmbedMod is the embedding model used for the playbook index
// (vector cosine similarity). The docs index no longer uses embeddings.
var playbookEmbedMod = "nomic-embed-text"

// ensureDocsIndex makes sure the module index is fresh. If the
// installed ansible-core version (or the module list) has changed,
// rebuild. Returns true if a rebuild was performed.
func ensureDocsIndex(ctx context.Context, dataDir string) (rebuilt bool, err error) {
	if err := ensurePlaybooksIndex(ctx, dataDir); err != nil {
		fmt.Fprintf(os.Stderr, "warning: ensurePlaybooksIndex: %v\n", err)
	}

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

// mustEmbedClient returns an Ollama client configured for embedding
// (used only by the playbook index path).
func mustEmbedClient(ctx context.Context, dataDir string) docs.Embedder {
	cfg := loadConfig()
	client := newEmbedderClient(cfg.OllamaURL, cfg.Model, playbookEmbedMod)
	st, err := store.Open(filepath.Join(dataDir, "history.db"))
	if err == nil {
		return app.NewCachedEmbedder(client, st)
	}
	return client
}

// newEmbedderClient is a small constructor used by the playbook path.
func newEmbedderClient(baseURL, model, embedModel string) *ollama.Client {
	c := ollama.NewClient(baseURL, model)
	c.SetEmbeddingModel(embedModel)
	return c
}

// ensurePlaybooksIndex performs incremental RAG updates for playbooks.
// It discovers all playbooks in `./playbooks` and `~/.local/share/pilot/playbooks`,
// parses and embeds any playbooks that are new or have modified mtime or size.
func ensurePlaybooksIndex(ctx context.Context, dataDir string) error {
	dirs := []string{"./playbooks", filepath.Join(dataDir, "playbooks")}
	files, err := docs.DiscoverPlaybooks(dirs, true)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return nil
	}

	indexPath := docs.PathFor(dataDir, docs.SourcePlaybook)
	idx := docs.NewIndex()
	_ = idx.Load(indexPath) // Load existing index if present

	// Create a map of existing indexed file path -> metadata for quick checks.
	indexedFiles := make(map[string]struct {
		size  int64
		mtime int64
	})

	for _, c := range idx.Chunks() {
		if c.Source == docs.SourcePlaybook {
			var sizeVal, mtimeVal int64
			if sz, ok := c.Metadata["size"].(int); ok {
				sizeVal = int64(sz)
			} else if sz, ok := c.Metadata["size"].(float64); ok {
				sizeVal = int64(sz)
			}
			if mt, ok := c.Metadata["mtime"].(int); ok {
				mtimeVal = int64(mt)
			} else if mt, ok := c.Metadata["mtime"].(float64); ok {
				mtimeVal = int64(mt)
			}
			indexedFiles[c.Ref] = struct {
				size  int64
				mtime int64
			}{size: sizeVal, mtime: mtimeVal}
		}
	}

	client := mustEmbedClient(ctx, dataDir)

	var playbooksToEmbed []string
	for _, f := range files {
		stat, err := os.Stat(f)
		if err != nil {
			continue
		}
		info, ok := indexedFiles[f]
		if !ok || info.size != stat.Size() || info.mtime != stat.ModTime().Unix() {
			playbooksToEmbed = append(playbooksToEmbed, f)
		}
	}

	if len(playbooksToEmbed) == 0 {
		return nil
	}

	fmt.Fprintf(os.Stderr, "🔄 Auto-indexing %d modified or new playbooks...\n", len(playbooksToEmbed))

	var chunks []docs.Chunk
	for _, f := range playbooksToEmbed {
		stat, err := os.Stat(f)
		if err != nil {
			continue
		}
		pb, err := docs.ParsePlaybook(f)
		if err != nil {
			continue
		}
		// Create new chunks and add size + mtime metadata
		pbChunks := docs.ChunkPlaybook(pb)
		for i := range pbChunks {
			if pbChunks[i].Metadata == nil {
				pbChunks[i].Metadata = make(map[string]any)
			}
			pbChunks[i].Metadata["size"] = stat.Size()
			pbChunks[i].Metadata["mtime"] = stat.ModTime().Unix()
		}
		chunks = append(chunks, pbChunks...)
	}

	if len(chunks) == 0 {
		return nil
	}

	// Incrementally build embeddings and append
	if err := idx.BuildIncremental(ctx, client, chunks); err != nil {
		return err
	}

	if err := idx.Save(indexPath); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ Auto-indexed playbooks. Total playbooks chunks: %d\n", idx.Size())
	return nil
}
