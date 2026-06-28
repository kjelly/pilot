package docs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// fakeEmbedder returns deterministic vectors based on the input
// length. Vectors are unit-length to make cosine == 1 for identical.
type fakeEmbedder struct {
	dim int
}

func (f *fakeEmbedder) Embeddings(ctx context.Context, text string) ([]float32, error) {
	return f.make(text), nil
}

func (f *fakeEmbedder) BatchEmbeddings(ctx context.Context, texts []string) ([][]float32, error) {
	out := make([][]float32, len(texts))
	for i, t := range texts {
		out[i] = f.make(t)
	}
	return out, nil
}

func (f *fakeEmbedder) EmbeddingModel() string { return "fake" }

func (f *fakeEmbedder) make(text string) []float32 {
	v := make([]float32, f.dim)
	// Use a simple hash → index → unit vector
	sum := 0.0
	for i := 0; i < f.dim; i++ {
		v[i] = float32((len(text)*7 + i*3) % 17)
		sum += float64(v[i]) * float64(v[i])
	}
	// Normalize
	for i := range v {
		v[i] = float32(float64(v[i]) / (sum + 1))
	}
	return v
}

func TestIndexBuildAndSearch(t *testing.T) {
	idx := NewIndex()
	emb := &fakeEmbedder{dim: 16}

	chunks := []Chunk{
		{ID: "m:lineinfile:description", Source: SourceModule, Ref: "lineinfile", Section: "description",
			Text: "manage lines in files"},
		{ID: "m:copy:description", Source: SourceModule, Ref: "copy", Section: "description",
			Text: "copy files to target"},
		{ID: "m:service:description", Source: SourceModule, Ref: "service", Section: "description",
			Text: "manage services via init scripts"},
	}
	if err := idx.Build(context.Background(), emb, chunks, nil); err != nil {
		t.Fatal(err)
	}
	if idx.Size() != 3 {
		t.Errorf("Size: %d", idx.Size())
	}
	matches, err := idx.Search(context.Background(), emb, "lineinfile text", 2, "")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no matches")
	}
	if matches[0].Index < 0 {
		t.Error("bad index")
	}
}

func TestIndexFilterBySource(t *testing.T) {
	idx := NewIndex()
	emb := &fakeEmbedder{dim: 8}
	chunks := []Chunk{
		{ID: "m:a:desc", Source: SourceModule, Ref: "a", Section: "description", Text: "module alpha"},
		{ID: "m:b:desc", Source: SourceModule, Ref: "b", Section: "description", Text: "module bravo"},
		{ID: "p:x:desc", Source: SourcePlaybook, Ref: "x", Section: "description", Text: "playbook x"},
	}
	if err := idx.Build(context.Background(), emb, chunks, nil); err != nil {
		t.Fatal(err)
	}
	// Filter to modules only
	m, err := idx.Search(context.Background(), emb, "x", 5, SourceModule)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(m) != 2 {
		t.Errorf("modules-only: got %d", len(m))
	}
	for _, match := range m {
		if idx.ChunkByIndex(match.Index).Source != SourceModule {
			t.Errorf("non-module result leaked: %s", idx.ChunkByIndex(match.Index).Source)
		}
	}
}

func TestIndexSaveLoad(t *testing.T) {
	idx := NewIndex()
	emb := &fakeEmbedder{dim: 8}
	chunks := []Chunk{
		{ID: "m:ping:desc", Source: SourceModule, Ref: "ping", Section: "description", Text: "test connectivity"},
	}
	if err := idx.Build(context.Background(), emb, chunks, nil); err != nil {
		t.Fatal(err)
	}

	tmp := filepath.Join(t.TempDir(), "idx.json")
	if err := idx.Save(tmp); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tmp); err != nil {
		t.Fatal(err)
	}

	idx2 := NewIndex()
	if err := idx2.Load(tmp); err != nil {
		t.Fatal(err)
	}
	if idx2.Size() != 1 {
		t.Errorf("loaded size: %d", idx2.Size())
	}
	c := idx2.ChunkByIndex(0)
	if c.Ref != "ping" {
		t.Errorf("ref: %s", c.Ref)
	}
}

func TestIndexBuildProgress(t *testing.T) {
	idx := NewIndex()
	emb := &fakeEmbedder{dim: 4}
	chunks := make([]Chunk, 20)
	for i := range chunks {
		chunks[i] = Chunk{ID: "x", Source: SourceModule, Ref: "r", Section: "s", Text: "hello"}
	}
	calls := 0
	var lastDone int
	progress := func(done, total int, last Chunk) {
		calls++
		lastDone = done
	}
	if err := idx.Build(context.Background(), emb, chunks, progress); err != nil {
		t.Fatal(err)
	}
	if calls == 0 {
		t.Error("progress not called")
	}
	if lastDone != 20 {
		t.Errorf("lastDone: %d", lastDone)
	}
}
