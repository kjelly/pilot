package cmd

import (
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// contentText extracts the text of a single-TextContent CallToolResult,
// the shape toolErrorResult always produces.
func contentText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if len(result.Content) != 1 {
		t.Fatalf("Content = %+v, want exactly one entry", result.Content)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("Content[0] = %#v, want *mcp.TextContent", result.Content[0])
	}
	return text.Text
}

func TestToolErrorResult_MarksIsError(t *testing.T) {
	result := toolErrorResult(mcpToolError{Code: mcpErrWorkspaceChanged, Message: "workspace changed"})
	if !result.IsError {
		t.Fatal("expected IsError = true")
	}
}

func TestToolErrorResult_ContentRoundTripsAsJSON(t *testing.T) {
	toolErr := mcpToolError{
		Code:           mcpErrUnsupportedAction,
		Message:        "nope",
		Step:           1,
		Action:         "set_vault_value",
		AuditDirectory: "/tmp/whatever",
	}
	result := toolErrorResult(toolErr)
	raw := contentText(t, result)

	var decoded mcpToolError
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("Content text did not decode as mcpToolError JSON: %v\ntext: %s", err, raw)
	}
	if decoded != toolErr {
		t.Fatalf("decoded = %+v, want %+v", decoded, toolErr)
	}
}
