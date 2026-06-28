package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/anomalyco/pilot/internal/ollama"
)

// Result is the outcome of a tool execution
type Result struct {
	Content  string          `json:"content"`
	IsError  bool            `json:"is_error"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

// Executor is the function signature for tool implementations
type Executor func(ctx context.Context, args json.RawMessage) (*Result, error)

// Spec describes a tool that the LLM can invoke
type Spec struct {
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	RiskLevel    string          `json:"-"` // low / medium / high
	Reversible   bool            `json:"-"`
	Parameters   json.RawMessage `json:"parameters"`
	DoubleConfirm bool           `json:"-"`
	// DryRunSafe indicates the tool can be safely executed under
	// --dry-run-all (e.g. read_file, run_command in read-only mode,
	// run_inspec, ask_user, run_ansible with --check).
	// When false, the agent loop intercepts the call and records a
	// "[DRY-RUN] would call …" proposal instead of executing.
	DryRunSafe   bool            `json:"-"`
	Execute      Executor        `json:"-"`

	// Interceptor is an optional pre-execution hook run by the agent
	// loop. It can mutate args, surface a synthetic dry-run preview,
	// or short-circuit by returning a non-nil Result (with IsError
	// if the short-circuit represents an error). When the agent is
	// NOT in DryRun mode, Interceptor is still consulted so that
	// argument rewrites (e.g. force-check=true on run_ansible) take
	// effect; the tool then runs normally unless the Interceptor
	// returned a non-nil Result.
	//
	// Returning (nil, nil) means "no interception, proceed normally".
	// Returning (nil, err) is a hard error.
	Interceptor Interceptor     `json:"-"`
}

// Interceptor is the signature of Spec.Interceptor. The agent loop
// passes the resolved tool args; the interceptor can return a
// synthetic Result to skip execution entirely.
type Interceptor func(ctx context.Context, args json.RawMessage) (*Result, error)


// Registry holds all available tools. The OllamaTools() output is
// cached and invalidated on Register/Delete; the cache is safe for
// concurrent reads.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]*Spec

	ollamaCache atomic.Pointer[[]ollama.Tool]
}

func NewRegistry() *Registry {
	return &Registry{tools: make(map[string]*Spec)}
}

// Register adds a tool to the registry
func (r *Registry) Register(spec *Spec) error {
	if spec.Name == "" {
		return fmt.Errorf("tool name required")
	}
	if spec.Execute == nil {
		return fmt.Errorf("tool %s: executor required", spec.Name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.tools[spec.Name]; exists {
		return fmt.Errorf("tool %s already registered", spec.Name)
	}
	r.tools[spec.Name] = spec
	r.ollamaCache.Store(nil)
	return nil
}

// MustRegister panics on error - for use in init()
func (r *Registry) MustRegister(spec *Spec) {
	if err := r.Register(spec); err != nil {
		panic(err)
	}
}

// Get retrieves a tool by name
func (r *Registry) Get(name string) (*Spec, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	return t, ok
}

// List returns all registered tool names sorted alphabetically
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.tools))
	for n := range r.tools {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// OllamaTools converts registered tools to Ollama's tool format.
// The result is cached and reused across calls; the cache is invalidated
// whenever Register mutates the registry. Each call returns a FRESH
// slice that does not alias the cache, so callers can safely mutate
// the returned value.
func (r *Registry) OllamaTools() []ollama.Tool {
	if cached := r.ollamaCache.Load(); cached != nil {
		out := make([]ollama.Tool, len(*cached))
		copy(out, *cached)
		return out
	}
	r.mu.RLock()
	out := make([]ollama.Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, ollama.Tool{
			Type: "function",
			Function: ollama.ToolFunction{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  t.Parameters,
			},
		})
	}
	r.mu.RUnlock()
	// Sort for stable ordering (deterministic prompt construction).
	sort.Slice(out, func(i, j int) bool { return out[i].Function.Name < out[j].Function.Name })
	// Store a private copy in the cache. Callers get their own copy.
	cached := make([]ollama.Tool, len(out))
	copy(cached, out)
	r.ollamaCache.Store(&cached)
	return out
}

// InvalidateCache drops the cached OllamaTools output. Call this if
// you mutated a Spec in place without going through Register.
func (r *Registry) InvalidateCache() {
	r.ollamaCache.Store(nil)
}
