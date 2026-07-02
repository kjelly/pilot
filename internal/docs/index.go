package docs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Index is an in-memory vector index of Chunks plus an embedded LRU
// query cache. The on-disk format is JSON for debuggability.
type Index struct {
	mu sync.RWMutex

	chunks  []Chunk
	vectors [][]float32

	cache *LRU

	// meta captured at build time
	meta Meta
}

// Meta is the metadata stored alongside the index. Used to detect
// whether the index needs rebuilding (e.g. ansible-core version changed).
type Meta struct {
	AnsibleVersion string `json:"ansible_version"`
	ModuleCount    int    `json:"module_count"`
	ChunkCount     int    `json:"chunk_count"`
	EmbeddingModel string `json:"embedding_model"`
	EmbeddingDim   int    `json:"embedding_dim"`
	// VersionHash is a content-derived identifier we compare against
	// a freshly-computed hash to decide whether to rebuild.
	VersionHash string `json:"version_hash"`
	BuiltAt     string `json:"built_at"`
}

// Embedder is the minimal interface the index needs from the Ollama
// client. Decoupling lets us stub it in tests.
type Embedder interface {
	Embeddings(ctx context.Context, text string) ([]float32, error)
	BatchEmbeddings(ctx context.Context, texts []string) ([][]float32, error)
	EmbeddingModel() string
}

// NewIndex creates an empty index.
func NewIndex() *Index {
	return &Index{cache: NewLRU(1000)}
}

// Chunks returns a snapshot of all chunks (for debugging/inspection).
func (idx *Index) Chunks() []Chunk {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	out := make([]Chunk, len(idx.chunks))
	copy(out, idx.chunks)
	return out
}

// Size returns the number of chunks in the index.
func (idx *Index) Size() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return len(idx.chunks)
}

// RemoveRef removes all chunks and vectors associated with a specific Ref.
func (idx *Index) RemoveRef(ref string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	var newChunks []Chunk
	var newVectors [][]float32
	for i, c := range idx.chunks {
		if c.Ref == ref {
			continue
		}
		newChunks = append(newChunks, c)
		newVectors = append(newVectors, idx.vectors[i])
	}
	idx.chunks = newChunks
	idx.vectors = newVectors
	idx.meta.ChunkCount = len(idx.chunks)
	idx.cache.Clear()
}

// Append adds chunks and their corresponding vectors to the index.
func (idx *Index) Append(chunks []Chunk, vectors [][]float32) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	idx.chunks = append(idx.chunks, chunks...)
	idx.vectors = append(idx.vectors, vectors...)
	idx.meta.ChunkCount = len(idx.chunks)
	idx.cache.Clear()
}

// BuildProgress is a callback invoked after each batch is embedded.
// done/total reflect chunk count, not batch count.
type BuildProgress func(done, total int, last Chunk)

// Build constructs a new index from the given chunks, embedding them
// via the embedder. The progress callback (if non-nil) is called after
// each batch of up to 16 chunks.
func (idx *Index) Build(ctx context.Context, emb Embedder, chunks []Chunk, progress BuildProgress) error {
	idx.mu.Lock()
	idx.chunks = make([]Chunk, 0, len(chunks))
	idx.vectors = make([][]float32, 0, len(chunks))
	idx.mu.Unlock()

	const batchSize = 16
	total := len(chunks)
	for start := 0; start < total; start += batchSize {
		end := start + batchSize
		if end > total {
			end = total
		}
		batch := chunks[start:end]
		texts := make([]string, len(batch))
		for i, c := range batch {
			texts[i] = c.Text
		}
		vecs, err := emb.BatchEmbeddings(ctx, texts)
		if err != nil {
			return fmt.Errorf("embed batch %d-%d: %w", start, end, err)
		}
		idx.mu.Lock()
		for i, v := range vecs {
			idx.chunks = append(idx.chunks, batch[i])
			idx.vectors = append(idx.vectors, v)
		}
		idx.mu.Unlock()

		if progress != nil {
			progress(end, total, batch[len(batch)-1])
		}
	}

	idx.mu.Lock()
	dim := 0
	if len(idx.vectors) > 0 {
		dim = len(idx.vectors[0])
	}
	idx.meta = Meta{
		ChunkCount:     len(idx.chunks),
		EmbeddingModel: emb.EmbeddingModel(),
		EmbeddingDim:   dim,
	}
	idx.mu.Unlock()
	return nil
}

// BuildIncremental embeds the given chunks and appends/updates them in the index.
// If a chunk's Ref already exists, the old entries for that Ref are removed first.
func (idx *Index) BuildIncremental(ctx context.Context, emb Embedder, chunks []Chunk) error {
	if len(chunks) == 0 {
		return nil
	}

	// 1. Group chunks by Ref to remove their old versions
	refsToRemove := make(map[string]bool)
	for _, c := range chunks {
		if c.Ref != "" {
			refsToRemove[c.Ref] = true
		}
	}
	for ref := range refsToRemove {
		idx.RemoveRef(ref)
	}

	// 2. Build embeddings for new chunks in batches
	const batchSize = 16
	total := len(chunks)
	newVectors := make([][]float32, 0, total)
	newChunks := make([]Chunk, 0, total)

	for start := 0; start < total; start += batchSize {
		end := start + batchSize
		if end > total {
			end = total
		}
		batch := chunks[start:end]
		texts := make([]string, len(batch))
		for i, c := range batch {
			texts[i] = c.Text
		}
		vecs, err := emb.BatchEmbeddings(ctx, texts)
		if err != nil {
			return fmt.Errorf("embed batch %d-%d: %w", start, end, err)
		}
		newChunks = append(newChunks, batch...)
		newVectors = append(newVectors, vecs...)
	}

	// 3. Append to main index
	idx.Append(newChunks, newVectors)
	return nil
}

// Search returns the top-k chunks most similar to the query, ranked
// by cosine similarity. Results from a small LRU cache are reused.
// If source is empty, all sources are considered.
//
// Returns an error when embedding the query fails (network error,
// Ollama unreachable, etc.) so callers can distinguish "no chunks
// matched" from "we couldn't tell". The previous behaviour of
// silently returning nil was misleading: the model would receive
// empty search results and might conclude "no relevant docs
// exist" when in fact the index was temporarily unreachable.
func tokenize(s string) []string {
	var words []string
	var cur strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == '-' {
			cur.WriteRune(r)
		} else {
			if cur.Len() > 0 {
				words = append(words, cur.String())
				cur.Reset()
			}
		}
	}
	if cur.Len() > 0 {
		words = append(words, cur.String())
	}
	return words
}

func (idx *Index) Search(ctx context.Context, emb Embedder, query string, k int, source Source) ([]Match, error) {
	if k <= 0 {
		k = 5
	}
	idx.mu.RLock()
	if len(idx.chunks) == 0 {
		idx.mu.RUnlock()
		return nil, nil
	}
	// Cache hit
	if cached, ok := idx.cache.Get(cacheKey(query, k, source)); ok {
		idx.mu.RUnlock()
		if matches, ok := cached.([]Match); ok {
			return matches, nil
		}
	}
	idx.mu.RUnlock()

	qvec, err := emb.Embeddings(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("embed query %q: %w", query, err)
	}
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	lowerQuery := strings.ToLower(query)
	qtokens := tokenize(query)

	// Filter by source if requested, then sort
	type cand struct {
		idx   int
		score float64
	}
	cands := make([]cand, 0, len(idx.vectors))
	for i, v := range idx.vectors {
		if source != "" && idx.chunks[i].Source != source {
			continue
		}

		// Lexical score calculations
		lexicalScore := 0.0
		chunk := idx.chunks[i]
		lowerRef := strings.ToLower(chunk.Ref)
		lowerText := strings.ToLower(chunk.Text)

		if lowerQuery == lowerRef {
			lexicalScore += 2.0
		} else if strings.Contains(lowerRef, lowerQuery) {
			lexicalScore += 1.0
		}

		matchedTokens := 0
		if len(qtokens) > 0 {
			for _, token := range qtokens {
				if strings.Contains(lowerRef, token) {
					lexicalScore += 0.5
				}
				if strings.Contains(lowerText, token) {
					matchedTokens++
				}
			}
			overlapRatio := float64(matchedTokens) / float64(len(qtokens))
			lexicalScore += 0.5 * overlapRatio
		}

		cands = append(cands, cand{i, Cosine(qvec, v) + lexicalScore})
	}
	// Sort desc by score. With ~80k chunks this used to be O(n²)
	// bubble sort; sort.Slice is O(n log n) and well within budget.
	sort.Slice(cands, func(i, j int) bool {
		return cands[i].score > cands[j].score
	})
	if k > len(cands) {
		k = len(cands)
	}
	out := make([]Match, k)
	for i := 0; i < k; i++ {
		out[i] = Match{Index: cands[i].idx, Score: cands[i].score}
	}
	idx.cache.Put(cacheKey(query, k, source), out)
	return out, nil
}

// ChunkByIndex returns the chunk at the given index (used after Search).
func (idx *Index) ChunkByIndex(i int) Chunk {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	if i < 0 || i >= len(idx.chunks) {
		return Chunk{}
	}
	return idx.chunks[i]
}

func cacheKey(q string, k int, s Source) string {
	// Pre-size the buffer to avoid the fmt.Sprintf allocation.
	// Worst case: source (16) + "|" + q (varies) + "|" + k (up to 20 digits)
	buf := make([]byte, 0, 16+len(q)+24)
	buf = append(buf, s...)
	buf = append(buf, '|')
	buf = append(buf, q...)
	buf = append(buf, '|')
	buf = strconv.AppendInt(buf, int64(k), 10)
	return string(buf)
}

// ----- Persistence ------------------------------------------------------

// Save serializes the index to a single JSON file. The file is written
// atomically (tmp + rename) to avoid corruption on crash.
func (idx *Index) Save(path string) error {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	payload := indexFile{
		Version: 1,
		Meta:    idx.meta,
		Chunks:  idx.chunks,
		Vectors: idx.vectors,
	}
	tmp := path + ".tmp"
	jsonData, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, jsonData, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load reads an index file produced by Save.
func (idx *Index) Load(path string) error {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var payload indexFile
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}
	if payload.Version != 1 {
		return fmt.Errorf("unsupported index version: %d", payload.Version)
	}
	idx.chunks = payload.Chunks
	idx.vectors = payload.Vectors
	idx.meta = payload.Meta
	return nil
}

// Meta returns a copy of the current metadata.
func (idx *Index) Meta() Meta {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.meta
}

// indexFile is the on-disk envelope. We use a struct with JSON tags
// (rather than yaml) because floats-as-JSON is more compact.
type indexFile struct {
	Version int         `json:"version"`
	Meta    Meta        `json:"meta"`
	Chunks  []Chunk     `json:"chunks"`
	Vectors [][]float32 `json:"vectors"`
}

// PathFor returns the canonical on-disk path for an index file
// of the given source, under the data dir.
func PathFor(dataDir string, source Source) string {
	switch source {
	case SourceModule:
		return filepath.Join(dataDir, "docs-index.json")
	case SourcePlaybook:
		return filepath.Join(dataDir, "playbooks-index.json")
	}
	return filepath.Join(dataDir, "index-"+string(source)+".json")
}

// MetaPathFor returns the canonical on-disk path for index metadata.
func MetaPathFor(dataDir string) string {
	return filepath.Join(dataDir, "docs-index.meta")
}
