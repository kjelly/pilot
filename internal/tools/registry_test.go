package tools

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/anomalyco/pilot/internal/ansible"
	"github.com/anomalyco/pilot/internal/ollama"
)

func TestRegistryRegisterAndGet(t *testing.T) {
	r := NewRegistry()
	spec := &Spec{
		Name:        "test_tool",
		Description: "a test",
		Parameters:  json.RawMessage(`{"type":"object"}`),
		Execute:     func(ctx context.Context, args json.RawMessage) (*Result, error) { return &Result{Content: "ok"}, nil },
	}
	if err := r.Register(spec); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := r.Register(spec); err == nil {
		t.Fatal("expected duplicate register error")
	}
	got, ok := r.Get("test_tool")
	if !ok || got.Name != "test_tool" {
		t.Fatal("get returned wrong tool")
	}
	if len(r.List()) != 1 {
		t.Fatalf("list: got %d", len(r.List()))
	}
}

func TestRegistryOllamaTools(t *testing.T) {
	r := NewRegistry()
	r.MustRegister(&Spec{
		Name:        "x",
		Description: "x",
		Parameters:  json.RawMessage(`{"type":"object"}`),
		Execute:     func(ctx context.Context, args json.RawMessage) (*Result, error) { return nil, nil },
	})
	ot := r.OllamaTools()
	if len(ot) != 1 {
		t.Fatalf("ollama tools: got %d", len(ot))
	}
	if ot[0].Type != "function" || ot[0].Function.Name != "x" {
		t.Fatalf("bad ollama tool: %+v", ot[0])
	}
}

func TestDefaultRegistryHasCoreTools(t *testing.T) {
	runner := ansible.NewRunner()
	oc := ollama.NewClient("http://localhost:11434", "test")
	r := DefaultRegistry(oc, runner, "/tmp/gen", "you are a test")
	want := []string{"read_file", "run_command", "run_ansible", "generate_playbook", "ask_user", "run_inspec"}
	got := map[string]bool{}
	for _, n := range r.List() {
		got[n] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing tool %q in default registry; have: %v", w, r.List())
		}
	}
}

func TestReadFileToolReads(t *testing.T) {
	t.Setenv("HOME", "/tmp")
	tmp := t.TempDir()
	// write a fake file
	path := tmp + "/test.txt"
	if err := writeFile(path, "line1\nline2\nline3\n"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", tmp)
	tf := &ReadFileTool{}
	args := json.RawMessage(`{"path":"` + path + `"}`)
	res, err := tf.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res.IsError {
		t.Fatalf("got error result: %s", res.Content)
	}
	if res.Content == "" {
		t.Fatal("empty content")
	}
}

func TestReadFileToolBlocksShadow(t *testing.T) {
	tf := &ReadFileTool{}
	args := json.RawMessage(`{"path":"/etc/shadow"}`)
	res, err := tf.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected error for /etc/shadow, got: %s", res.Content)
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

func TestRegistryOllamaToolsCache(t *testing.T) {
	r := NewRegistry()
	r.MustRegister(&Spec{
		Name:        "a",
		Description: "a",
		Parameters:  json.RawMessage(`{"type":"object"}`),
		Execute:     func(ctx context.Context, args json.RawMessage) (*Result, error) { return &Result{Content: "a"}, nil },
	})
	r.MustRegister(&Spec{
		Name:        "b",
		Description: "b",
		Parameters:  json.RawMessage(`{"type":"object"}`),
		Execute:     func(ctx context.Context, args json.RawMessage) (*Result, error) { return &Result{Content: "b"}, nil },
	})

	first := r.OllamaTools()
	second := r.OllamaTools()
	if &first[0] == &second[0] {
		// Same backing array means cache hit. We can't compare
		// pointer-of-slice directly; instead check that the slice
		// headers point at the same backing array by mutating first
		// and seeing second reflect the change.
		// Note: OllamaTools returns a slice value, not a pointer,
		// so identity comparison isn't meaningful. The test below
		// uses InvalidateCache to verify the recompute path.
	}

	// Mutating a returned slice shouldn't affect the cache.
	first[0].Function.Name = "MUTATED"
	third := r.OllamaTools()
	if third[0].Function.Name == "MUTATED" {
		t.Fatal("cache leaked mutation")
	}

	// After invalidation, the recomputed slice reflects the registered names.
	r.InvalidateCache()
	fourth := r.OllamaTools()
	if len(fourth) != 2 {
		t.Fatalf("expected 2 tools after InvalidateCache, got %d", len(fourth))
	}
}

func TestRegistryOllamaToolsRegisterInvalidatesCache(t *testing.T) {
	r := NewRegistry()
	r.MustRegister(&Spec{
		Name:        "a",
		Description: "a",
		Parameters:  json.RawMessage(`{"type":"object"}`),
		Execute:     func(ctx context.Context, args json.RawMessage) (*Result, error) { return nil, nil },
	})
	first := r.OllamaTools()
	if len(first) != 1 {
		t.Fatalf("first: want 1, got %d", len(first))
	}
	r.MustRegister(&Spec{
		Name:        "b",
		Description: "b",
		Parameters:  json.RawMessage(`{"type":"object"}`),
		Execute:     func(ctx context.Context, args json.RawMessage) (*Result, error) { return nil, nil },
	})
	second := r.OllamaTools()
	if len(second) != 2 {
		t.Fatalf("after register: want 2 (cache invalidated), got %d", len(second))
	}
}

func TestRegistryOllamaToolsSorted(t *testing.T) {
	r := NewRegistry()
	for _, n := range []string{"zebra", "alpha", "mango"} {
		n := n
		r.MustRegister(&Spec{
			Name:        n,
			Description: n,
			Parameters:  json.RawMessage(`{"type":"object"}`),
			Execute:     func(ctx context.Context, args json.RawMessage) (*Result, error) { return nil, nil },
		})
	}
	got := r.OllamaTools()
	want := []string{"alpha", "mango", "zebra"}
	for i, w := range want {
		if got[i].Function.Name != w {
			t.Errorf("position %d: want %q, got %q", i, w, got[i].Function.Name)
		}
	}
}

// TestWithProposalMeta_InjectsFields pins fix "B": every tool's schema
// gains the _rationale / _risk_level / _cis_control properties so the
// model has a declared channel to supply proposal metadata, while the
// tool's own properties are preserved.
func TestWithProposalMeta_InjectsFields(t *testing.T) {
	in := json.RawMessage(`{"type":"object","properties":{"command":{"type":"string"}},"required":["command"]}`)
	out := withProposalMeta(in)

	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Required   []string                   `json:"required"`
	}
	if err := json.Unmarshal(out, &schema); err != nil {
		t.Fatalf("augmented schema is not valid JSON: %v", err)
	}
	for _, k := range []string{"command", "_rationale", "_risk_level", "_cis_control"} {
		if _, ok := schema.Properties[k]; !ok {
			t.Errorf("expected property %q in augmented schema", k)
		}
	}
	// Meta fields must stay optional — never forced into "required".
	for _, r := range schema.Required {
		if r == "_rationale" || r == "_risk_level" || r == "_cis_control" {
			t.Errorf("meta field %q must not be required", r)
		}
	}
}

// TestWithProposalMeta_EmptyAndNonObject pins the fail-open behaviour:
// an empty schema is synthesised into an object; a non-object schema is
// returned untouched rather than breaking the tool.
func TestWithProposalMeta_EmptyAndNonObject(t *testing.T) {
	// Empty → synthesised object schema carrying the meta fields.
	out := withProposalMeta(nil)
	var schema struct {
		Type       string                     `json:"type"`
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(out, &schema); err != nil {
		t.Fatalf("empty input should yield valid JSON, got %q: %v", out, err)
	}
	if schema.Type != "object" {
		t.Errorf("synthesised schema should have type=object, got %q", schema.Type)
	}
	if _, ok := schema.Properties["_rationale"]; !ok {
		t.Error("synthesised schema should carry _rationale")
	}

	// Non-object JSON (a bare string) is returned verbatim.
	weird := json.RawMessage(`"not a schema"`)
	if got := withProposalMeta(weird); string(got) != string(weird) {
		t.Errorf("non-object schema should be returned untouched, got %q", got)
	}
}
