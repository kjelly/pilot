package docs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blevesearch/bleve/v2"
	"github.com/blevesearch/bleve/v2/mapping"
)

// ModuleIndex is a BM25-backed index over Ansible module chunks.
// Backed by bleve; one bleve document per Chunk (per module-section).
// Pure text — no embedding model required.
type ModuleIndex struct {
	path string
	idx  bleve.Index

	mu     sync.RWMutex
	chunks []Chunk // parallel to bleve doc IDs; ChunkByIndex(i) returns chunks[i]
}

// NewModuleIndex constructs (but does not open) a ModuleIndex rooted at
// the given path. The path will be a directory containing bleve's files.
func NewModuleIndex(path string) *ModuleIndex {
	return &ModuleIndex{path: path}
}

// bleveOpenTimeoutOrDefault bounds the underlying bbolt.Open. bbolt's
// flock retry loop has no upper bound, so a stuck lock (e.g. another pilot
// process left over from a SIGKILL) would hang the agent loop forever.
// 30 s is generous for a 100 MB local index.
//
// Override at test time by setting the package-level variable
// bleveOpenTimeoutForTest BEFORE calling Open(). Tests should always
// defer-undo the override.
var bleveOpenTimeoutForTest time.Duration

func bleveOpenTimeoutOrDefault() time.Duration {
	if bleveOpenTimeoutForTest > 0 {
		return bleveOpenTimeoutForTest
	}
	return 30 * time.Second
}

// Open creates or opens the underlying bleve index. Must be called before
// any other method. On a successful open of an existing index, the
// in-memory chunks slice is reloaded from the sidecar chunks file.
func (m *ModuleIndex) Open() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.idx != nil {
		return nil
	}
	if err := ensureParentDir(m.path); err != nil {
		return err
	}
	// bleve.Open -> bbolt.Open -> flock(LOCK_EX|LOCK_NB) with no Timeout.
	// We can't pass options into bleve.Open, so we race the open against
	// a timer in a goroutine and surface a context-deadline-style error.
	type openResult struct {
		idx bleve.Index
		err error
	}
	resCh := make(chan openResult, 1)
	go func() {
		idx, err := bleve.Open(m.path)
		resCh <- openResult{idx: idx, err: err}
	}()
	var (
		idx bleve.Index
		err error
	)
	select {
	case r := <-resCh:
		idx, err = r.idx, r.err
	case <-time.After(bleveOpenTimeoutOrDefault()):
		return fmt.Errorf("open bleve index: timed out after %s (likely a stale bbolt lock — another pilot or stale process holds %s; remove the file and retry)", bleveOpenTimeoutOrDefault(), filepath.Join(m.path, "store", "root.bolt"))
	}
	if isMissingIndex(err) {
		idx, err = bleve.New(m.path, moduleIndexMapping())
		if err != nil {
			return fmt.Errorf("create bleve index: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("open bleve index: %w", err)
	}
	m.idx = idx
	// Restore the in-memory chunks slice from the sidecar file if present.
	chunks, err := loadChunksSidecar(m.path)
	if err != nil {
		return fmt.Errorf("load chunks sidecar: %w", err)
	}
	m.chunks = chunks
	return nil
}

// Close releases the bleve index. Safe to call multiple times.
func (m *ModuleIndex) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.idx == nil {
		return nil
	}
	err := m.idx.Close()
	m.idx = nil
	return err
}

// Size returns the number of indexed chunks.
func (m *ModuleIndex) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.chunks)
}

// ChunkByIndex returns the chunk at the given internal index, as used
// by Match.Index. The in-memory chunks slice is the source of truth
// for chunk content; bleve only holds the searchable text.
func (m *ModuleIndex) ChunkByIndex(i int) Chunk {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if i < 0 || i >= len(m.chunks) {
		return Chunk{}
	}
	return m.chunks[i]
}

// Build creates a fresh index containing the given chunks, replacing any
// previous content. No embedding is required — the bleve BM25 scoring
// runs over the chunk text directly.
func (m *ModuleIndex) Build(chunks []Chunk) error {
	return m.rebuild(chunks)
}

// BuildIncremental upserts chunks by their ID. A chunk with an ID that
// already exists replaces the old version; a chunk with a new ID is
// appended. Chunks whose IDs are not in the input are left untouched.
// The total size only changes for newly added IDs.
func (m *ModuleIndex) BuildIncremental(chunks []Chunk) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.idx == nil {
		return fmt.Errorf("module index not opened")
	}
	if len(chunks) == 0 {
		return nil
	}

	// 1. Index the input chunks by ID for fast lookup.
	incoming := make(map[string]Chunk, len(chunks))
	for _, c := range chunks {
		incoming[c.ID] = c
	}

	// 2. Build the new in-memory slice: walk existing, replace if the
	//    ID is in the input; otherwise keep as-is.
	merged := make([]Chunk, 0, len(m.chunks)+len(incoming))
	replacedIDs := make(map[string]struct{})
	for _, existing := range m.chunks {
		if c, ok := incoming[existing.ID]; ok {
			merged = append(merged, c)
			replacedIDs[existing.ID] = struct{}{}
		} else {
			merged = append(merged, existing)
		}
	}
	// 3. Append any input chunks whose ID was brand new.
	for _, c := range chunks {
		if _, replaced := replacedIDs[c.ID]; !replaced {
			merged = append(merged, c)
		}
	}

	// 4. In bleve, delete-then-index the input (idempotent: re-index
	//    of an existing ID replaces; new IDs are added).
	batch := m.idx.NewBatch()
	for id := range incoming {
		batch.Delete(id)
	}
	for _, c := range chunks {
		doc := moduleDocFromChunk(c)
		if err := batch.Index(c.ID, doc); err != nil {
			return fmt.Errorf("index %q: %w", c.ID, err)
		}
	}
	if err := m.idx.Batch(batch); err != nil {
		return fmt.Errorf("index batch: %w", err)
	}

	// 5. Stable sort by ID for deterministic ChunkByIndex results.
	sort.SliceStable(merged, func(i, j int) bool {
		return merged[i].ID < merged[j].ID
	})
	m.chunks = merged
	if err := saveChunksSidecar(m.path, m.chunks); err != nil {
		return fmt.Errorf("save chunks sidecar: %w", err)
	}
	return nil
}

// Search runs a BM25 query and returns the top-k matches sorted by
// descending score.
func (m *ModuleIndex) Search(query string, k int) ([]Match, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.idx == nil {
		return nil, fmt.Errorf("module index not opened")
	}
	query = strings.TrimSpace(query)
	if query == "" || k <= 0 {
		return nil, nil
	}
	req := bleve.NewSearchRequest(bleve.NewMatchQuery(query))
	req.Size = k
	res, err := m.idx.Search(req)
	if err != nil {
		return nil, fmt.Errorf("bleve search: %w", err)
	}
	if len(res.Hits) == 0 {
		return nil, nil
	}
	// Build an ID -> chunk-index lookup once.
	idIndex := make(map[string]int, len(m.chunks))
	for i, c := range m.chunks {
		idIndex[c.ID] = i
	}
	out := make([]Match, 0, len(res.Hits))
	for _, hit := range res.Hits {
		idx, ok := idIndex[hit.ID]
		if !ok {
			continue
		}
		out = append(out, Match{Index: idx, Score: hit.Score})
	}
	return out, nil
}

// rebuild wipes and recreates the index.
func (m *ModuleIndex) rebuild(chunks []Chunk) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.idx == nil {
		return fmt.Errorf("module index not opened")
	}
	// Drop everything from the in-memory slice.
	m.chunks = m.chunks[:0]
	// Drop everything from bleve by enumerating all docs and deleting.
	allReq := bleve.NewSearchRequest(bleve.NewMatchAllQuery())
	allReq.Size = 1000000
	allRes, err := m.idx.Search(allReq)
	if err != nil {
		return fmt.Errorf("enumerate for delete: %w", err)
	}
	if len(allRes.Hits) > 0 {
		delBatch := m.idx.NewBatch()
		for _, hit := range allRes.Hits {
			delBatch.Delete(hit.ID)
		}
		if err := m.idx.Batch(delBatch); err != nil {
			return fmt.Errorf("delete batch: %w", err)
		}
	}
	if len(chunks) == 0 {
		return nil
	}
	batch := m.idx.NewBatch()
	newChunks := make([]Chunk, 0, len(chunks))
	for _, c := range chunks {
		doc := moduleDocFromChunk(c)
		if err := batch.Index(c.ID, doc); err != nil {
			return fmt.Errorf("index %q: %w", c.ID, err)
		}
		newChunks = append(newChunks, c)
	}
	if err := m.idx.Batch(batch); err != nil {
		return fmt.Errorf("index batch: %w", err)
	}
	sort.SliceStable(newChunks, func(i, j int) bool {
		return newChunks[i].ID < newChunks[j].ID
	})
	m.chunks = newChunks
	if err := saveChunksSidecar(m.path, m.chunks); err != nil {
		return fmt.Errorf("save chunks sidecar: %w", err)
	}
	return nil
}

// moduleDoc is the bleve document shape. Only fields that drive search
// relevance live here; everything else is reconstructed from the
// in-memory Chunk slice on retrieval.
type moduleDoc struct {
	Ref      string `json:"ref"`
	Module   string `json:"module"`
	Section  string `json:"section"`
	Text     string `json:"text"`
	Metadata string `json:"metadata_json"`
}

func moduleDocFromChunk(c Chunk) moduleDoc {
	moduleName := c.Ref
	if name, ok := c.Metadata["name"].(string); ok && name != "" {
		moduleName = name
	}
	return moduleDoc{
		Ref:     c.Ref,
		Module:  moduleName,
		Section: c.Section,
		Text:    c.Text,
	}
}

// moduleIndexMapping is the bleve schema. Text fields use English
// analyzer (Porter stemming + English stopword removal). Keyword
// fields are used for exact-match filtering (ref, section).
func moduleIndexMapping() *mapping.IndexMappingImpl {
	// Use a fresh text mapping as the default.
	textFieldMapping := bleve.NewTextFieldMapping()
	textFieldMapping.Analyzer = "en"

	keywordFieldMapping := bleve.NewKeywordFieldMapping()
	keywordFieldMapping.Store = false
	keywordFieldMapping.IncludeInAll = false

	docMapping := bleve.NewDocumentMapping()
	docMapping.AddFieldMappingsAt("ref", keywordFieldMapping)
	docMapping.AddFieldMappingsAt("module", keywordFieldMapping)
	docMapping.AddFieldMappingsAt("section", keywordFieldMapping)
	docMapping.AddFieldMappingsAt("text", textFieldMapping)

	m := bleve.NewIndexMapping()
	m.DefaultMapping = docMapping
	m.DefaultAnalyzer = "en"
	return m
}

func ensureParentDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}

func isMissingIndex(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "does not exist") || strings.Contains(msg, "no such file or directory")
}

// chunksSidecarPath is the JSON file that holds the in-memory chunks
// slice alongside the bleve directory. bleve's own files are the
// search index; this sidecar is the source of truth for chunk
// metadata (Metadata map, full ID, etc.) that bleve doesn't need to
// index but we need to surface on retrieval.
func chunksSidecarPath(blevePath string) string {
	return filepath.Join(blevePath, "chunks.json")
}

func saveChunksSidecar(blevePath string, chunks []Chunk) error {
	data, err := json.Marshal(chunks)
	if err != nil {
		return err
	}
	return os.WriteFile(chunksSidecarPath(blevePath), data, 0o644)
}

func loadChunksSidecar(blevePath string) ([]Chunk, error) {
	data, err := os.ReadFile(chunksSidecarPath(blevePath))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // fresh / unbuilt index
		}
		return nil, err
	}
	var chunks []Chunk
	if err := json.Unmarshal(data, &chunks); err != nil {
		return nil, err
	}
	return chunks, nil
}
