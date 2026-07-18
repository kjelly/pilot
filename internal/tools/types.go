// Package tools hosts VerifySpecTool, the execution engine behind
// `pilot verify`. The LLM tool registry that used to live here was
// retired on 2026-07-17 when the agent surface was removed; only the
// minimal tool-call types VerifySpecTool still speaks survive.
package tools

import (
	"context"
	"encoding/json"
)

// Result is the outcome of a tool execution.
type Result struct {
	Content  string          `json:"content"`
	IsError  bool            `json:"is_error"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

// Executor is the function signature for tool implementations.
type Executor func(ctx context.Context, args json.RawMessage) (*Result, error)

// Spec describes an invokable tool: VerifySpecTool publishes itself
// through this so `pilot verify` can call Execute uniformly.
type Spec struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	RiskLevel   string          `json:"-"` // low / medium / high
	Reversible  bool            `json:"-"`
	Parameters  json.RawMessage `json:"parameters"`
	DryRunSafe  bool            `json:"-"`
	Execute     Executor        `json:"-"`
}
