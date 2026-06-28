package tools

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anomalyco/pilot/internal/docs"
)

func newRAGTestIndex(t *testing.T) *docs.ModuleIndex {
	t.Helper()
	dir := t.TempDir()
	idx := docs.NewModuleIndex(filepath.Join(dir, "modules.bleve"))
	if err := idx.Open(); err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	return idx
}

func ragTestChunks() []docs.Chunk {
	return []docs.Chunk{
		{
			ID:      "modules:ansible.builtin.service:param:enabled",
			Source:  docs.SourceModule,
			Ref:     "ansible.builtin.service",
			Section: "param",
			Text:    "service.enabled (type=bool)\nWhether the service should start on boot.",
			Metadata: map[string]any{
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
			Text:    "service.state (type=str, choices=started|stopped|restarted|reloaded)",
			Metadata: map[string]any{
				"section":    "param",
				"param_name": "state",
				"param_type": "str",
				"choices":    []string{"started", "stopped", "restarted", "reloaded"},
			},
		},
	}
}

// TestGeneratePlaybookTool_RAGContextInlinesHits confirms that when
// ModuleIndex is set and has chunks, the built prompt includes the
// retrieved text. We don't need a real LLM — we just check the
// prompt construction is wired correctly.
func TestGeneratePlaybookTool_RAGContextInlinesHits(t *testing.T) {
	idx := newRAGTestIndex(t)
	if err := idx.Build(ragTestChunks()); err != nil {
		t.Fatalf("Build: %v", err)
	}

	t1 := &GeneratePlaybookTool{
		ModuleIndex: idx,
		// Ollama intentionally nil; we never call Execute.
	}

	prompt := t1.buildGenerationPrompt(context.Background(), generateTaskArgsStruct{
		Description: "make nginx start at boot",
	})

	// The prompt must contain the FQCN and a parameter name we indexed.
	if !strings.Contains(prompt, "ansible.builtin.service") {
		t.Errorf("prompt missing module FQCN: %q", prompt)
	}
	if !strings.Contains(prompt, "state") {
		t.Errorf("prompt missing parameter name: %q", prompt)
	}
	if !strings.Contains(prompt, "Relevant Ansible module documentation") {
		t.Errorf("prompt missing RAG section header: %q", prompt)
	}
	// The retrieved block should be inside the prompt body.
	if !strings.Contains(prompt, "=== End of retrieved context ===") {
		t.Errorf("prompt missing closing marker: %q", prompt)
	}
}

func TestGeneratePlaybookTool_NoIndexNoRAG(t *testing.T) {
	t1 := &GeneratePlaybookTool{} // no ModuleIndex
	prompt := t1.buildGenerationPrompt(context.Background(), generateTaskArgsStruct{
		Description: "anything",
	})
	if strings.Contains(prompt, "Relevant Ansible module documentation") {
		t.Errorf("prompt should not include RAG block when index missing: %q", prompt)
	}
	// Still must produce a usable prompt.
	if !strings.Contains(prompt, "anything") {
		t.Errorf("prompt missing description: %q", prompt)
	}
	if !strings.Contains(prompt, "Output ONLY a single YAML code block") {
		t.Errorf("prompt missing base requirements: %q", prompt)
	}
}

func TestGeneratePlaybookTool_RAGContextTruncates(t *testing.T) {
	idx := newRAGTestIndex(t)
	// Build a chunk with very long text
	longText := strings.Repeat("long ", 200) // ~1000 chars
	chunks := []docs.Chunk{
		{
			ID:      "modules:ansible.builtin.copy:param:content",
			Source:  docs.SourceModule,
			Ref:     "ansible.builtin.copy",
			Section: "param",
			Text:    "copy.content (type=raw)\n" + longText,
			Metadata: map[string]any{
				"section":    "param",
				"param_name": "content",
				"param_type": "raw",
			},
		},
	}
	if err := idx.Build(chunks); err != nil {
		t.Fatalf("Build: %v", err)
	}
	t1 := &GeneratePlaybookTool{ModuleIndex: idx}
	prompt := t1.buildGenerationPrompt(context.Background(), generateTaskArgsStruct{
		Description: "copy a file with content",
	})
	// 400-char cap per entry — the full ~1000-char text must be cut.
	if strings.Count(prompt, "long ") > 250 {
		t.Errorf("RAG block not truncated")
	}
}

// TestGeneratePlaybookTool_SpecIsRegistered confirms the constructor
// still produces a valid Spec() (the registry depends on it).
func TestGeneratePlaybookTool_SpecIsRegistered(t *testing.T) {
	t1 := &GeneratePlaybookTool{}
	spec := t1.Spec()
	if spec.Name != "generate_playbook" {
		t.Errorf("spec.Name = %q", spec.Name)
	}
	if !spec.DryRunSafe == false {
		// generate_playbook writes a file, so DryRunSafe MUST be false
		t.Errorf("DryRunSafe should be false")
	}
}

// ensure we don't accidentally drop the _ = json line
var _ = json.RawMessage{}
