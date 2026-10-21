// mcp_tool_recovery.go closes a real gap confirmed 2026-08-21: the
// go-sdk's jsonrpc2 layer dispatches every tool *call* request in its own
// goroutine (jsonrpc2.Async — see mcp/server.go's handleReceive), and
// neither that dispatch path nor pilot's own handlers install a
// recover(). An unrecovered panic in one tool handler therefore crashes
// the whole `pilot mcp serve` process — killing every other concurrent
// AND future call on the same stdio session, not just the one that
// panicked (reproduced: one panicking call took down 10/10 otherwise-fine
// concurrent calls). addRecoveredTool is the single choke point every
// tool registration goes through instead of calling mcp.AddTool
// directly, so a bug in any one handler degrades to that one call
// failing rather than the whole server dying.
package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// addRecoveredTool registers t on server with h wrapped so a panic inside
// h — including one raised by anything h calls into — becomes an
// internal_error CallToolResult on that one call, instead of an
// unrecovered panic that crashes the process.
func addRecoveredTool[In, Out any](server *mcp.Server, t *mcp.Tool, h mcp.ToolHandlerFor[In, Out]) {
	recovered := recoverToolPanic(t.Name, h)
	mcp.AddTool(server, t, func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
		result, output, err := recovered(ctx, req, in)
		diagnostic := strings.HasPrefix(t.Name, "pilot_diagnose_")
		if err != nil {
			if diagnostic {
				return nil, output, typedToolError(toolErrorResult(mcpToolError{Code: mcpErrInternal, Message: err.Error()}), true)
			}
			return result, output, err
		}
		if diagnostic && result != nil && result.IsError {
			return nil, output, typedToolError(result, diagnostic)
		}
		if diagnostic {
			output, err = sanitizeDiagnoseOutput(output)
		}
		return result, output, err
	})
}

func recoverToolPanic[In, Out any](name string, h mcp.ToolHandlerFor[In, Out]) mcp.ToolHandlerFor[In, Out] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in In) (result *mcp.CallToolResult, output Out, err error) {
		defer func() {
			if r := recover(); r != nil {
				result = toolErrorResult(mcpToolError{
					Code:    mcpErrInternal,
					Message: fmt.Sprintf("tool %q panicked: %v", name, r),
				})
				err = nil
			}
		}()
		return h(ctx, req, in)
	}
}
