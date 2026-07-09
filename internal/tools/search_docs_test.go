package tools

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anomalyco/pilot/internal/docs"
)

func newLLMTestModuleIndex(t *testing.T) *docs.ModuleIndex {
	t.Helper()
	dir := t.TempDir()
	idx := docs.NewModuleIndex(filepath.Join(dir, "modules.bleve"))
	if err := idx.Open(); err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	return idx
}

func llmTestSampleChunks() []docs.Chunk {
	return []docs.Chunk{
		{
			ID:      "modules:ansible.builtin.copy:synopsis",
			Source:  docs.SourceModule,
			Ref:     "ansible.builtin.copy",
			Section: "synopsis",
			Text:    "Copies a file from the local or remote machine to a location on the managed host.",
			Metadata: map[string]any{
				"name":    "ansible.builtin.copy",
				"section": "synopsis",
			},
		},
		{
			ID:      "modules:ansible.builtin.service:param:enabled",
			Source:  docs.SourceModule,
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
			Source:  docs.SourceModule,
			Ref:     "ansible.builtin.service",
			Section: "param",
			Text:    "service.state (type=str, choices=started|stopped|restarted|reloaded)\nDesired state of the service.",
			Metadata: map[string]any{
				"name":       "ansible.builtin.service",
				"section":    "param",
				"param_name": "state",
				"param_type": "str",
				"choices":    []string{"started", "stopped", "restarted", "reloaded"},
				"required":   false,
			},
		},
	}
}

func TestSearchDocsTool_ReturnsJSONWithStructuredFields(t *testing.T) {
	idx := newLLMTestModuleIndex(t)
	if err := idx.Build(llmTestSampleChunks()); err != nil {
		t.Fatalf("Build: %v", err)
	}
	tool := NewSearchDocsTool(idx)

	res, err := tool.Execute(context.Background(), json.RawMessage(`{"query":"enabled service","source":"modules","limit":3}`))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected success, got error: %s", res.Content)
	}
	// Body must be valid JSON.
	var payload struct {
		Query   string      `json:"query"`
		Count   int         `json:"count"`
		Results []SearchHit `json:"results"`
	}
	if err := json.Unmarshal([]byte(res.Content), &payload); err != nil {
		t.Fatalf("result is not JSON: %v\n%s", err, res.Content)
	}
	if payload.Count == 0 {
		t.Fatal("expected at least one result")
	}
	foundParam := false
	for _, h := range payload.Results {
		if h.Section == "param" && h.ParamName == "enabled" {
			foundParam = true
			if h.ParamType != "bool" {
				t.Errorf("param_type = %q, want bool", h.ParamType)
			}
			if h.Confidence <= 0 || h.Confidence > 1 {
				t.Errorf("confidence out of [0,1]: %v", h.Confidence)
			}
		}
	}
	if !foundParam {
		t.Errorf("expected a param hit for 'enabled', got: %+v", payload.Results)
	}
}

func TestSearchDocsTool_PrefixMatchOnModule(t *testing.T) {
	idx := newLLMTestModuleIndex(t)
	if err := idx.Build(llmTestSampleChunks()); err != nil {
		t.Fatalf("Build: %v", err)
	}
	tool := NewSearchDocsTool(idx)

	res, err := tool.Execute(context.Background(), json.RawMessage(`{"query":"servic","source":"modules","limit":2}`))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.IsError {
		t.Fatalf("error: %s", res.Content)
	}
	var payload struct {
		Results []SearchHit `json:"results"`
	}
	_ = json.Unmarshal([]byte(res.Content), &payload)
	if len(payload.Results) == 0 {
		t.Fatalf("expected prefix match, got empty: %s", res.Content)
	}
	if !strings.HasPrefix(payload.Results[0].Ref, "ansible.builtin.service") {
		t.Errorf("expected service prefix match, got ref=%s", payload.Results[0].Ref)
	}
}

func TestSearchDocsTool_ModuleFilter(t *testing.T) {
	idx := newLLMTestModuleIndex(t)
	if err := idx.Build(llmTestSampleChunks()); err != nil {
		t.Fatalf("Build: %v", err)
	}
	tool := NewSearchDocsTool(idx)

	res, err := tool.Execute(context.Background(), json.RawMessage(`{"query":"anything","module":"ansible.builtin.copy","source":"modules","limit":3}`))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var payload struct {
		Results []SearchHit `json:"results"`
	}
	_ = json.Unmarshal([]byte(res.Content), &payload)
	for _, h := range payload.Results {
		if h.Ref != "ansible.builtin.copy" {
			t.Errorf("module filter leaked: got %s", h.Ref)
		}
	}
}

func TestSearchDocsTool_BodyTruncated(t *testing.T) {
	idx := newLLMTestModuleIndex(t)
	long := strings.Repeat("copy dest ", 800) // 6400 chars, contains "dest"
	chunks := []docs.Chunk{
		{
			ID:      "modules:ansible.builtin.copy:param:dest",
			Source:  docs.SourceModule,
			Ref:     "ansible.builtin.copy",
			Section: "param",
			Text:    long,
			Metadata: map[string]any{
				"section":    "param",
				"param_name": "dest",
				"param_type": "path",
			},
		},
	}
	if err := idx.Build(chunks); err != nil {
		t.Fatalf("Build: %v", err)
	}
	tool := NewSearchDocsTool(idx)
	res, err := tool.Execute(context.Background(), json.RawMessage(`{"query":"dest","source":"modules","limit":1}`))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var payload struct {
		Results []SearchHit `json:"results"`
	}
	_ = json.Unmarshal([]byte(res.Content), &payload)
	if len(payload.Results) == 0 {
		t.Fatal("expected one result")
	}
	if len(payload.Results[0].Text) > 850 {
		t.Errorf("body not truncated: %d chars", len(payload.Results[0].Text))
	}
}

func TestSearchDocsTool_NoIndexBuilt_Graceful(t *testing.T) {
	tool := NewSearchDocsTool(nil)
	res, err := tool.Execute(context.Background(), json.RawMessage(`{"query":"x","source":"modules"}`))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.IsError {
		t.Errorf("expected error when index missing, got: %s", res.Content)
	}
	if !strings.Contains(res.Content, "not built") {
		t.Errorf("error should mention 'not built', got: %s", res.Content)
	}
}

func TestSearchDocsTool_EmptyQuery_Rejected(t *testing.T) {
	idx := newLLMTestModuleIndex(t)
	if err := idx.Build(llmTestSampleChunks()); err != nil {
		t.Fatalf("Build: %v", err)
	}
	tool := NewSearchDocsTool(idx)
	_, err := tool.Execute(context.Background(), json.RawMessage(`{"query":""}`))
	if err == nil {
		t.Fatal("expected error for empty query")
	}
	if !strings.Contains(err.Error(), "query is required") {
		t.Errorf("expected 'query is required' in error, got: %v", err)
	}
}

func TestSearchDocsTool_StripsSearchTextTail(t *testing.T) {
	idx := newLLMTestModuleIndex(t)
	chunks := []docs.Chunk{
		{
			ID:      "modules:ansible.builtin.copy:param:dest",
			Source:  docs.SourceModule,
			Ref:     "ansible.builtin.copy",
			Section: "param",
			Text:    "copy.dest (type=path)\nThe remote absolute path.\n\n[search-text]\nHow to set the remote path. Hidden noise.",
			Metadata: map[string]any{
				"section":    "param",
				"param_name": "dest",
				"param_type": "path",
			},
		},
	}
	if err := idx.Build(chunks); err != nil {
		t.Fatalf("Build: %v", err)
	}
	tool := NewSearchDocsTool(idx)
	res, err := tool.Execute(context.Background(), json.RawMessage(`{"query":"dest","source":"modules","limit":1}`))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if strings.Contains(res.Content, "[search-text]") {
		t.Errorf("search-text tail leaked into LLM output: %s", res.Content)
	}
	if strings.Contains(res.Content, "Hidden noise") {
		t.Errorf("BM25-only noise leaked: %s", res.Content)
	}
}

func TestSearchDocsTool_PopulatesRelatedExampleAndSuggestedNext(t *testing.T) {
	idx := newLLMTestModuleIndex(t)
	chunks := []docs.Chunk{
		{
			ID:      "modules:ansible.builtin.service:param:state",
			Source:  docs.SourceModule,
			Ref:     "ansible.builtin.service",
			Section: "param",
			Text:    "service.state (type=str, choices=started|stopped|restarted)",
			Metadata: map[string]any{
				"section":    "param",
				"param_name": "state",
				"param_type": "str",
				"choices":    []string{"started", "stopped", "restarted"},
			},
		},
		{
			ID:       "modules:ansible.builtin.service:example",
			Source:   docs.SourceModule,
			Ref:      "ansible.builtin.service",
			Section:  "example",
			Text:     "- service: name=httpd state=started enabled=yes",
			Metadata: map[string]any{"section": "examples"},
		},
	}
	if err := idx.Build(chunks); err != nil {
		t.Fatalf("Build: %v", err)
	}
	tool := NewSearchDocsTool(idx)
	res, err := tool.Execute(context.Background(), json.RawMessage(`{"query":"restart service","source":"modules","limit":3}`))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var payload struct {
		Results []SearchHit `json:"results"`
	}
	_ = json.Unmarshal([]byte(res.Content), &payload)
	if len(payload.Results) == 0 {
		t.Fatal("no results")
	}
	var paramHit *SearchHit
	for i := range payload.Results {
		if payload.Results[i].Section == "param" {
			paramHit = &payload.Results[i]
		}
	}
	if paramHit == nil {
		t.Fatal("no param hit")
	}
	if paramHit.RelatedExampleID != "modules:ansible.builtin.service:example" {
		t.Errorf("RelatedExampleID = %q, want modules:ansible.builtin.service:examples", paramHit.RelatedExampleID)
	}
	if len(paramHit.SuggestedNext) == 0 {
		t.Fatal("SuggestedNext empty")
	}
	// First suggestion should be generate_playbook
	if paramHit.SuggestedNext[0].Tool != "generate_playbook" {
		t.Errorf("SuggestedNext[0].Tool = %q, want generate_playbook", paramHit.SuggestedNext[0].Tool)
	}
}

func TestSearchDocsTool_LimitClamped(t *testing.T) {
	idx := newLLMTestModuleIndex(t)
	if err := idx.Build(llmTestSampleChunks()); err != nil {
		t.Fatalf("Build: %v", err)
	}
	tool := NewSearchDocsTool(idx)
	// Ask for 100 — should be clamped to 20.
	res, err := tool.Execute(context.Background(), json.RawMessage(`{"query":"service","source":"modules","limit":100}`))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var payload struct {
		Count int `json:"count"`
	}
	_ = json.Unmarshal([]byte(res.Content), &payload)
	if payload.Count > 20 {
		t.Errorf("count = %d, want <= 20", payload.Count)
	}
}
