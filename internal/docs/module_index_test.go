package docs

import (
	"os"
	"path/filepath"
	"testing"
)

// sampleModuleChunks returns a small fixture: 3 Ansible modules,
// each with 2-3 sections. Total 8 chunks across 3 refs.
func sampleModuleChunks() []Chunk {
	return []Chunk{
		{
			ID:      "modules:ansible.builtin.copy:description",
			Source:  SourceModule,
			Ref:     "ansible.builtin.copy",
			Section: "description",
			Text:    "Copies a file from the local or remote machine to a location on the managed host.",
			Metadata: map[string]any{
				"name":     "ansible.builtin.copy",
				"category": "Files",
			},
		},
		{
			ID:      "modules:ansible.builtin.copy:options",
			Source:  SourceModule,
			Ref:     "ansible.builtin.copy",
			Section: "options",
			Text:    "dest: path absolute on remote. src: path on controller. mode: permissions.",
			Metadata: map[string]any{
				"name":     "ansible.builtin.copy",
				"category": "Files",
			},
		},
		{
			ID:      "modules:ansible.builtin.file:description",
			Source:  SourceModule,
			Ref:     "ansible.builtin.file",
			Section: "description",
			Text:    "Sets attributes of files, directories, symlinks. Also creates/removes them.",
			Metadata: map[string]any{
				"name":     "ansible.builtin.file",
				"category": "Files",
			},
		},
		{
			ID:      "modules:ansible.builtin.file:options",
			Source:  SourceModule,
			Ref:     "ansible.builtin.file",
			Section: "options",
			Text:    "path: file/directory to modify. state: file|directory|link|absent|touch|hard.",
			Metadata: map[string]any{
				"name":     "ansible.builtin.file",
				"category": "Files",
			},
		},
		{
			ID:      "modules:ansible.builtin.service:description",
			Source:  SourceModule,
			Ref:     "ansible.builtin.service",
			Section: "description",
			Text:    "Control services on remote hosts. Supports systemd, init.d, upstart, etc.",
			Metadata: map[string]any{
				"name":     "ansible.builtin.service",
				"category": "System",
			},
		},
		{
			ID:      "modules:ansible.builtin.service:options",
			Source:  SourceModule,
			Ref:     "ansible.builtin.service",
			Section: "options",
			Text:    "name: name of service. state: started|stopped|restarted|reloaded. enabled: yes|no.",
			Metadata: map[string]any{
				"name":     "ansible.builtin.service",
				"category": "System",
			},
		},
		{
			ID:      "modules:ansible.builtin.service:examples",
			Source:  SourceModule,
			Ref:     "ansible.builtin.service",
			Section: "examples",
			Text:    "- service: name=httpd state=started enabled=yes\n- service: name=nginx state=restarted",
			Metadata: map[string]any{
				"name":     "ansible.builtin.service",
				"category": "System",
			},
		},
		{
			ID:      "modules:ansible.builtin.copy:examples",
			Source:  SourceModule,
			Ref:     "ansible.builtin.copy",
			Section: "examples",
			Text:    "- copy: src=/etc/foo.conf dest=/etc/foo.conf mode=0644 owner=root",
			Metadata: map[string]any{
				"name":     "ansible.builtin.copy",
				"category": "Files",
			},
		},
	}
}

func newTestModuleIndex(t *testing.T) (*ModuleIndex, string) {
	t.Helper()
	dir := t.TempDir()
	idx := NewModuleIndex(filepath.Join(dir, "modules.bleve"))
	if err := idx.Open(); err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	return idx, dir
}

func TestModuleIndex_Open_CreatesDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "modules.bleve")
	idx := NewModuleIndex(path)
	if err := idx.Open(); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer idx.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected bleve path to exist: %v", err)
	}
}

func TestModuleIndex_BuildAndSearch_RanksByRelevance(t *testing.T) {
	idx, _ := newTestModuleIndex(t)
	chunks := sampleModuleChunks()
	if err := idx.Build(chunks); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got, want := idx.Size(), len(chunks); got != want {
		t.Fatalf("Size = %d, want %d", got, want)
	}

	matches, err := idx.Search("copy file permissions", 3)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected at least one match")
	}
	top := idx.ChunkByIndex(matches[0].Index)
	if top.Ref != "ansible.builtin.copy" {
		t.Errorf("top match Ref = %q, want ansible.builtin.copy", top.Ref)
	}
}

func TestModuleIndex_Search_ServiceQuery(t *testing.T) {
	idx, _ := newTestModuleIndex(t)
	if err := idx.Build(sampleModuleChunks()); err != nil {
		t.Fatalf("Build: %v", err)
	}

	matches, err := idx.Search("restart nginx httpd systemd", 3)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected at least one match")
	}
	top := idx.ChunkByIndex(matches[0].Index)
	if top.Ref != "ansible.builtin.service" {
		t.Errorf("top match Ref = %q, want ansible.builtin.service", top.Ref)
	}
}

func TestModuleIndex_Search_EmptyQuery(t *testing.T) {
	idx, _ := newTestModuleIndex(t)
	if err := idx.Build(sampleModuleChunks()); err != nil {
		t.Fatalf("Build: %v", err)
	}
	matches, err := idx.Search("", 5)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected no matches for empty query, got %d", len(matches))
	}
}

func TestModuleIndex_BuildIncremental_ReplacesByRef(t *testing.T) {
	idx, _ := newTestModuleIndex(t)
	if err := idx.Build(sampleModuleChunks()); err != nil {
		t.Fatalf("Build: %v", err)
	}
	originalSize := idx.Size()

	updated := []Chunk{
		{
			ID:      "modules:ansible.builtin.copy:description",
			Source:  SourceModule,
			Ref:     "ansible.builtin.copy",
			Section: "description",
			Text:    "Copies a file. THIS TEXT IS NEW AND SHOULD RANK HIGHEST FOR 'banana'.",
			Metadata: map[string]any{
				"name":     "ansible.builtin.copy",
				"category": "Files",
			},
		},
	}
	if err := idx.BuildIncremental(updated); err != nil {
		t.Fatalf("BuildIncremental: %v", err)
	}
	if got := idx.Size(); got != originalSize {
		t.Errorf("Size after incremental = %d, want %d (ref replacement, not append)", got, originalSize)
	}

	matches, err := idx.Search("banana", 3)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected banana to match the new chunk")
	}
	top := idx.ChunkByIndex(matches[0].Index)
	if top.Text != updated[0].Text {
		t.Errorf("top match text = %q, want the updated chunk text", top.Text)
	}
}

func TestModuleIndex_BuildIncremental_AddsNewRef(t *testing.T) {
	idx, _ := newTestModuleIndex(t)
	if err := idx.Build(sampleModuleChunks()); err != nil {
		t.Fatalf("Build: %v", err)
	}
	originalSize := idx.Size()

	newChunks := []Chunk{
		{
			ID:      "modules:ansible.builtin.debug:description",
			Source:  SourceModule,
			Ref:     "ansible.builtin.debug",
			Section: "description",
			Text:    "Print statements during playbook execution without affecting the target host.",
			Metadata: map[string]any{
				"name":     "ansible.builtin.debug",
				"category": "System",
			},
		},
	}
	if err := idx.BuildIncremental(newChunks); err != nil {
		t.Fatalf("BuildIncremental: %v", err)
	}
	if got := idx.Size(); got != originalSize+1 {
		t.Errorf("Size = %d, want %d (one new ref)", got, originalSize+1)
	}
}

func TestModuleIndex_ChunkByIndex_Roundtrip(t *testing.T) {
	idx, _ := newTestModuleIndex(t)
	chunks := sampleModuleChunks()
	if err := idx.Build(chunks); err != nil {
		t.Fatalf("Build: %v", err)
	}
	for i := 0; i < idx.Size(); i++ {
		got := idx.ChunkByIndex(i)
		if got.ID == "" {
			t.Errorf("ChunkByIndex(%d).ID is empty", i)
		}
		if got.Text == "" {
			t.Errorf("ChunkByIndex(%d).Text is empty", i)
		}
	}
}

func TestModuleIndex_PersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	blevePath := filepath.Join(dir, "modules.bleve")
	chunks := sampleModuleChunks()

	// Build & close.
	{
		idx := NewModuleIndex(blevePath)
		if err := idx.Open(); err != nil {
			t.Fatalf("first Open: %v", err)
		}
		if err := idx.Build(chunks); err != nil {
			t.Fatalf("first Build: %v", err)
		}
		if err := idx.Close(); err != nil {
			t.Fatalf("first Close: %v", err)
		}
	}

	// Reopen in a fresh ModuleIndex; in-memory state should be restored.
	idx2 := NewModuleIndex(blevePath)
	if err := idx2.Open(); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer idx2.Close()
	if got, want := idx2.Size(), len(chunks); got != want {
		t.Errorf("reopen Size = %d, want %d", got, want)
	}
	matches, err := idx2.Search("service systemd", 3)
	if err != nil {
		t.Fatalf("reopen Search: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected service to match after reopen")
	}
	top := idx2.ChunkByIndex(matches[0].Index)
	if top.Ref != "ansible.builtin.service" {
		t.Errorf("reopen top match Ref = %q, want ansible.builtin.service", top.Ref)
	}
}
