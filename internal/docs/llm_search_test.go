package docs

import (
	"path/filepath"
	"strings"
	"testing"
)

func llmSampleChunks() []Chunk {
	return []Chunk{
		{
			ID:      "modules:ansible.builtin.copy:synopsis",
			Source:  SourceModule,
			Ref:     "ansible.builtin.copy",
			Section: "synopsis",
			Text:    "Copies a file from the local or remote machine to a location on the managed host.",
			Metadata: map[string]any{
				"name":    "ansible.builtin.copy",
				"section": "synopsis",
			},
		},
		{
			ID:      "modules:ansible.builtin.copy:param:mode",
			Source:  SourceModule,
			Ref:     "ansible.builtin.copy",
			Section: "param",
			Text:    "copy.mode (type=str)\nPermissions the destination file or directory should have.",
			Metadata: map[string]any{
				"name":       "ansible.builtin.copy",
				"section":    "param",
				"param_name": "mode",
				"param_type": "str",
			},
		},
		{
			ID:      "modules:ansible.builtin.service:synopsis",
			Source:  SourceModule,
			Ref:     "ansible.builtin.service",
			Section: "synopsis",
			Text:    "Control services on remote hosts. Supports systemd, init.d, upstart, etc.",
			Metadata: map[string]any{
				"name":    "ansible.builtin.service",
				"section": "synopsis",
			},
		},
		{
			ID:      "modules:ansible.builtin.service:param:enabled",
			Source:  SourceModule,
			Ref:     "ansible.builtin.service",
			Section: "param",
			Text:    "service.enabled (type=bool)\nWhether the service should start on boot.",
			Metadata: map[string]any{
				"name":       "ansible.builtin.service",
				"section":    "param",
				"param_name": "enabled",
				"param_type": "bool",
			},
		},
		{
			ID:      "modules:ansible.builtin.service:param:state",
			Source:  SourceModule,
			Ref:     "ansible.builtin.service",
			Section: "param",
			Text:    "service.state (type=str, choices=started|stopped|restarted|reloaded)\nDesired state of the service.",
			Metadata: map[string]any{
				"name":       "ansible.builtin.service",
				"section":    "param",
				"param_name": "state",
				"param_type": "str",
			},
		},
		{
			ID:      "modules:ansible.builtin.service:examples",
			Source:  SourceModule,
			Ref:     "ansible.builtin.service",
			Section: "examples",
			Text:    "- service: name=httpd state=started enabled=yes",
			Metadata: map[string]any{
				"name":    "ansible.builtin.service",
				"section": "examples",
			},
		},
	}
}

func newLLMTestIndex(t *testing.T) *ModuleIndex {
	t.Helper()
	dir := t.TempDir()
	idx := NewModuleIndex(filepath.Join(dir, "modules.bleve"))
	if err := idx.Open(); err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	return idx
}

func TestSearchLLM_PrefersParamOverSynopsis(t *testing.T) {
	idx := newLLMTestIndex(t)
	if err := idx.Build(llmSampleChunks()); err != nil {
		t.Fatalf("Build: %v", err)
	}
	// "service" matches both synopsis and params; with PreferParam the
	// param chunks should be at the top.
	matches, err := idx.SearchLLM("service", SearchLLMOpts{
		Limit:        5,
		PreferParam:  true,
		PrefixMatchRef: true,
	})
	if err != nil {
		t.Fatalf("SearchLLM: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no matches")
	}
	top := idx.ChunkByIndex(matches[0].Index)
	if top.Metadata["section"] != "param" {
		t.Errorf("top should be a param chunk with PreferParam, got section=%v", top.Metadata["section"])
	}
}

func TestSearchLLM_ModuleFilter(t *testing.T) {
	idx := newLLMTestIndex(t)
	if err := idx.Build(llmSampleChunks()); err != nil {
		t.Fatalf("Build: %v", err)
	}
	matches, err := idx.SearchLLM("copy file", SearchLLMOpts{
		Limit:  5,
		Module: "ansible.builtin.copy",
	})
	if err != nil {
		t.Fatalf("SearchLLM: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected copy chunks")
	}
	for _, m := range matches {
		c := idx.ChunkByIndex(m.Index)
		if c.Ref != "ansible.builtin.copy" {
			t.Errorf("module filter leaked: got ref=%s", c.Ref)
		}
	}
}

func TestSearchLLM_PrefixMatchFindsShortRef(t *testing.T) {
	idx := newLLMTestIndex(t)
	if err := idx.Build(llmSampleChunks()); err != nil {
		t.Fatalf("Build: %v", err)
	}
	matches, err := idx.SearchLLM("servic", SearchLLMOpts{
		Limit:         3,
		PrefixMatchRef: true,
	})
	if err != nil {
		t.Fatalf("SearchLLM: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected prefix match on 'servic'")
	}
	top := idx.ChunkByIndex(matches[0].Index)
	if top.Ref != "ansible.builtin.service" {
		t.Errorf("prefix match top ref = %s, want ansible.builtin.service", top.Ref)
	}
}

func TestSearchLLM_EmptyQueryReturnsNil(t *testing.T) {
	idx := newLLMTestIndex(t)
	if err := idx.Build(llmSampleChunks()); err != nil {
		t.Fatalf("Build: %v", err)
	}
	matches, err := idx.SearchLLM("", SearchLLMOpts{Limit: 5})
	if err != nil {
		t.Fatalf("SearchLLM: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches for empty query, got %d", len(matches))
	}
}

func TestDedupeByParam_KeepsFirst(t *testing.T) {
	idx := newLLMTestIndex(t)
	chunks := llmSampleChunks()
	// Add a duplicate to simulate two chunks for the same param.
	chunks = append(chunks, Chunk{
		ID:      "modules:ansible.builtin.service:param:enabled:alt",
		Source:  SourceModule,
		Ref:     "ansible.builtin.service",
		Section: "param",
		Text:    "alternate description",
		Metadata: map[string]any{
			"param_name": "enabled",
			"section":    "param",
		},
	})
	if err := idx.Build(chunks); err != nil {
		t.Fatalf("Build: %v", err)
	}
	matches, err := idx.SearchLLM("enabled", SearchLLMOpts{Limit: 5})
	if err != nil {
		t.Fatalf("SearchLLM: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no matches")
	}
	deduped := DedupeByParam(matches, idx)
	for _, m := range deduped {
		c := idx.ChunkByIndex(m.Index)
		if pn, _ := c.Metadata["param_name"].(string); pn == "enabled" {
			// Only the first should remain.
			if c.ID != "modules:ansible.builtin.service:param:enabled" {
				t.Errorf("wrong duplicate kept: %s", c.ID)
			}
		}
	}
}

func TestScoreSummary_NormalisesFirstToOne(t *testing.T) {
	matches := []Match{
		{Index: 0, Score: 4.0},
		{Index: 1, Score: 2.0},
		{Index: 2, Score: 1.0},
	}
	got := ScoreSummary(matches)
	if len(got) != 3 {
		t.Fatalf("got %d, want 3", len(got))
	}
	if got[0] != 1.0 {
		t.Errorf("first score = %v, want 1.0", got[0])
	}
	if got[1] >= 1.0 || got[1] <= 0 {
		t.Errorf("middle score should be in (0, 1), got %v", got[1])
	}
}

func TestSearchLLM_SectionFilter(t *testing.T) {
	idx := newLLMTestIndex(t)
	if err := idx.Build(llmSampleChunks()); err != nil {
		t.Fatalf("Build: %v", err)
	}
	matches, err := idx.SearchLLM("param service enabled", SearchLLMOpts{
		Limit:   3,
		Section: "param",
	})
	if err != nil {
		t.Fatalf("SearchLLM: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected section-filtered matches")
	}
	for _, m := range matches {
		c := idx.ChunkByIndex(m.Index)
		if sec, _ := c.Metadata["section"].(string); sec != "param" {
			t.Errorf("section filter leaked: got %s", sec)
		}
	}
}

func TestFirstToken(t *testing.T) {
	cases := map[string]string{
		"hello world":   "hello",
		"service.name":  "service",
		"foo":           "foo",
		"  spaced  ":    "",
	}
	for in, want := range cases {
		got := firstToken(in)
		// Leading-space case returns "" because IsSpace is true at
		// index 0; that's the documented behaviour.
		if in == "  spaced  " {
			if got != "" {
				t.Errorf("firstToken(%q) = %q, want \"\"", in, got)
			}
			continue
		}
		if got != want {
			t.Errorf("firstToken(%q) = %q, want %q", in, got, want)
		}
	}
	_ = strings.TrimSpace // ensure import stays
}
