package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/anomalyco/pilot/internal/tools"
)

// callTool drives handleToolsCall for one tool and returns the decoded
// ToolsCallResult, capturing the JSON written to the server's stdout pipe.
func callTool(t *testing.T, s *Server, name string, args json.RawMessage) ToolsCallResult {
	t.Helper()
	r, w, _ := os.Pipe()
	s.stdout = w
	params, _ := json.Marshal(ToolsCallParams{Name: name, Arguments: args})
	s.handleToolsCall(context.Background(), Request{JSONRPC: "2.0", Method: "tools/call", ID: 1, Params: params})
	w.Close()

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	r.Close()

	var resp Response
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v\n%s", err, buf.String())
	}
	// resp.Result decodes into a map; re-marshal to get a typed result.
	raw, _ := json.Marshal(resp.Result)
	var res ToolsCallResult
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("unmarshal ToolsCallResult: %v", err)
	}
	return res
}

// TestHandleToolsCall_RunsInterceptor is the regression guard for the MCP
// interceptor-bypass bug: the MCP dispatch must run a tool's Interceptor
// with the same contract as the agent loop — a returned Result short-circuits
// Execute, and a returned error surfaces as an error result.
func TestHandleToolsCall_RunsInterceptor(t *testing.T) {
	t.Run("short-circuit result skips Execute", func(t *testing.T) {
		var executed bool
		reg := tools.NewRegistry()
		reg.MustRegister(&tools.Spec{
			Name:       "sc",
			Parameters: json.RawMessage(`{"type":"object"}`),
			Interceptor: func(ctx context.Context, args json.RawMessage) (*tools.Result, error) {
				return &tools.Result{Content: "intercepted", IsError: false}, nil
			},
			Execute: func(ctx context.Context, args json.RawMessage) (*tools.Result, error) {
				executed = true
				return &tools.Result{Content: "executed"}, nil
			},
		})
		res := callTool(t, NewServer(reg), "sc", json.RawMessage(`{}`))
		if executed {
			t.Error("Execute ran despite the interceptor short-circuiting")
		}
		if len(res.Content) == 0 || res.Content[0].Text != "intercepted" {
			t.Errorf("want interceptor content, got %+v", res.Content)
		}
	})

	t.Run("interceptor error surfaces as error result", func(t *testing.T) {
		reg := tools.NewRegistry()
		reg.MustRegister(&tools.Spec{
			Name:       "boom",
			Parameters: json.RawMessage(`{"type":"object"}`),
			Interceptor: func(ctx context.Context, args json.RawMessage) (*tools.Result, error) {
				return nil, context.Canceled
			},
			Execute: func(ctx context.Context, args json.RawMessage) (*tools.Result, error) {
				t.Fatal("Execute must not run when the interceptor errors")
				return nil, nil
			},
		})
		res := callTool(t, NewServer(reg), "boom", json.RawMessage(`{}`))
		if !res.IsError {
			t.Errorf("want IsError=true, got %+v", res)
		}
	})

	t.Run("nil interceptor result proceeds to Execute", func(t *testing.T) {
		reg := tools.NewRegistry()
		reg.MustRegister(&tools.Spec{
			Name:       "proceed",
			Parameters: json.RawMessage(`{"type":"object"}`),
			Interceptor: func(ctx context.Context, args json.RawMessage) (*tools.Result, error) {
				return nil, nil
			},
			Execute: func(ctx context.Context, args json.RawMessage) (*tools.Result, error) {
				return &tools.Result{Content: "executed"}, nil
			},
		})
		res := callTool(t, NewServer(reg), "proceed", json.RawMessage(`{}`))
		if len(res.Content) == 0 || res.Content[0].Text != "executed" {
			t.Errorf("want Execute to run, got %+v", res.Content)
		}
	})
}
