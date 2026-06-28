package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/anomalyco/pilot/internal/ollama"
	"github.com/anomalyco/pilot/internal/sanitizer"
	"github.com/anomalyco/pilot/internal/tools"
)

// scriptedOllama is a minimal /api/chat + /api/tags stub that returns
// a queue of responses. The agent loop drives one response per
// iteration, so this lets us script a multi-iteration ReAct cycle.
type scriptedOllama struct {
	mu       sync.Mutex
	queue    []ollama.ChatResponse
	embedDim int
}

func (s *scriptedOllama) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tags", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"models":[{"name":"qwen2.5:3b"}]}`)
	})
	mux.HandleFunc("/api/embeddings", func(w http.ResponseWriter, r *http.Request) {
		// Deterministic embedding: hash the prompt into a vector of
		// the configured dimension.
		prompt := ""
		if r.Body != nil {
			buf := make([]byte, 4096)
			n, _ := r.Body.Read(buf)
			prompt = string(buf[:n])
		}
		vec := make([]float32, s.embedDim)
		seed := 0
		for _, c := range prompt {
			seed = seed*131 + int(c)
		}
		for i := range vec {
			vec[i] = float32((seed+i)%97) / 97.0
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"embedding":[`)
		for i, v := range vec {
			if i > 0 {
				fmt.Fprint(w, ",")
			}
			fmt.Fprintf(w, "%v", v)
		}
		fmt.Fprint(w, `]}`)
	})
	mux.HandleFunc("/api/chat", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if len(s.queue) == 0 {
			http.Error(w, "no scripted response", http.StatusInternalServerError)
			return
		}
		resp := s.queue[0]
		s.queue = s.queue[1:]
		w.Header().Set("Content-Type", "application/json")
		// Use json marshal so embedded strings are properly escaped.
		out := `{"model":"` + resp.Model + `","message":{"role":"assistant","content":` + jsonString(resp.Message.Content) + `,"tool_calls":` + jsonToolCalls(resp.Message.ToolCalls) + `},"done":true}`
		fmt.Fprint(w, out)
	})
	return mux
}

func jsonString(s string) string {
	// Minimal escape.
	r := ""
	for _, c := range s {
		switch c {
		case '"':
			r += `\"`
		case '\\':
			r += `\\`
		case '\n':
			r += `\n`
		default:
			r += string(c)
		}
	}
	return `"` + r + `"`
}

func jsonToolCalls(tcs []ollama.ToolCall) string {
	if len(tcs) == 0 {
		return "null"
	}
	s := "["
	for i, tc := range tcs {
		if i > 0 {
			s += ","
		}
		args := string(tc.Function.Arguments)
		s += `{"function":{"name":` + jsonString(tc.Function.Name) + `,"arguments":` + jsonString(args) + `}}`
	}
	s += "]"
	return s
}

// TestAgentLoopEndToEndWithScriptedLLM drives the agent loop with a
// scripted Ollama server that returns:
//   1. an assistant message asking for a tool call (read_file)
//   2. a final assistant message (no more tool calls)
// The loop should reach the iteration cap's "done" path without
// errors and emit one tool result.
func TestAgentLoopEndToEndWithScriptedLLM(t *testing.T) {
	so := &scriptedOllama{embedDim: 4}
	so.queue = []ollama.ChatResponse{
		// Round 1: model calls read_file.
		{
			Message: ollama.Message{
				Role: "assistant",
				Content: "I'll read the file.",
				ToolCalls: []ollama.ToolCall{
					{Function: ollama.ToolCallFunction{
						Name: "read_file",
						Arguments: []byte(`{"path":"/etc/hostname"}`),
					}},
				},
			},
		},
		// Round 2: model produces final answer.
		{
			Message: ollama.Message{
				Role:    "assistant",
				Content: "Hostname is web01.",
			},
		},
	}
	srv := httptest.NewServer(so.handler())
	defer srv.Close()

	c := ollama.NewClient(srv.URL, "qwen2.5:3b")
	redactor := sanitizer.New()

	// Build a registry with just read_file. Approver auto-approves
	// everything so we don't need a human in the loop.
	registry := tools.NewRegistry()
	registry.MustRegister(&tools.Spec{
		Name: "read_file",
		Execute: func(_ context.Context, _ json.RawMessage) (*tools.Result, error) {
			return &tools.Result{Content: "web01\n"}, nil
		},
	})

	// Auto-approve all decisions.
	approver := testApprover{decision: DecisionApproved}

	loop := NewLoop(Config{
		RunID:     "test-run",
		DataDir:   t.TempDir(),
		Ollama:    c,
		Tools:     registry,
		Sanitizer: redactor,
		Approver:  &approver,
		Stream:    false,
		MaxIter:   5,
	})

	if err := loop.Run(context.Background(), "what's the hostname?"); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if approver.calls == 0 {
		t.Error("expected at least one approval call")
	}

	// Inspect last assistant message — should mention web01.
	last := loop.history[len(loop.history)-1]
	if !strings.Contains(last.Content, "web01") {
		t.Errorf("final message = %q, expected to contain %q", last.Content, "web01")
	}
}

// testApprover is a minimal Approver for the integration test.
type testApprover struct {
	decision Decision
	calls    int
	mu       sync.Mutex
}

func (a *testApprover) Ask(p *Proposal) Decision {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	return a.decision
}

// Compile-time checks that test infra is importable.
var _ = http.MethodGet
var _ = strings.Contains

// TestToolArgsSizeCapRejectsOversizedPayload verifies that the
// agent loop rejects tool calls whose JSON-encoded args exceed
// maxToolArgsBytes, even if the rest of the loop would otherwise
// proceed.
func TestToolArgsSizeCapRejectsOversizedPayload(t *testing.T) {
	so := &scriptedOllama{embedDim: 4}
	// One scripted response: model asks for a giant read_file call.
	bigArgs := []byte(`{"path":"` + strings.Repeat("x", maxToolArgsBytes+100) + `"}`)
	so.queue = []ollama.ChatResponse{
		{
			Message: ollama.Message{
				Role: "assistant",
				Content: "trying to read huge file",
				ToolCalls: []ollama.ToolCall{
					{Function: ollama.ToolCallFunction{
						Name:      "read_file",
						Arguments: bigArgs,
					}},
				},
			},
		},
		// And a follow-up so the loop doesn't hit max iterations.
		{Message: ollama.Message{Role: "assistant", Content: "done"}},
	}
	srv := httptest.NewServer(so.handler())
	defer srv.Close()

	c := ollama.NewClient(srv.URL, "qwen2.5:3b")
	redactor := sanitizer.New()
	registry := tools.NewRegistry()
	registry.MustRegister(&tools.Spec{
		Name:    "read_file",
		Execute: func(_ context.Context, _ json.RawMessage) (*tools.Result, error) { return &tools.Result{Content: "x"}, nil },
	})
	approver := &testApprover{decision: DecisionApproved}
	loop := NewLoop(Config{
		RunID:     "test-oversized",
		DataDir:   t.TempDir(),
		Ollama:    c,
		Tools:     registry,
		Sanitizer: redactor,
		Approver:  approver,
		MaxIter:   5,
	})
	if err := loop.Run(context.Background(), "read something"); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The Approver must NOT have been called — the size-cap rejection
	// happens before approval.
	if approver.calls != 0 {
		t.Errorf("expected 0 approval calls (size cap should reject), got %d", approver.calls)
	}
	// The model's second message ("done") should still be appended.
	last := loop.history[len(loop.history)-1]
	if !strings.Contains(last.Content, "done") {
		t.Errorf("expected final message 'done', got %q", last.Content)
	}
}
