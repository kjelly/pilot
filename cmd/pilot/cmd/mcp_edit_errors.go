// mcp_edit_errors.go is the MCP tools' structured error shape — see
// the spec's "Structured Errors" section. Tool-level failures are
// reported inside CallToolResult.Content (IsError: true) rather than
// as a returned Go error, per the SDK's own CallToolResult.IsError doc
// comment: doing so is what lets a caller see WHY something failed
// (code, step, screen) instead of only a stringified message.
package cmd

import (
	"encoding/json"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// mcpToolError is the JSON shape every MCP tool error result carries.
// Only a subset of spec's full error-code list is reachable from the
// read-only capabilities/inspect/plan tools this phase implements
// (invalidScenario, unsupportedAction, workspaceChanged,
// validationFailed, recordingFailed); the rest
// (write_disabled/workspace_locked/path_outside_workspace/
// secret_policy_violation/unexpected_screen/target_not_found/
// ambiguous_target/save_failed/apply_failed/rollback_failed) belong to
// apply/vault/roster phases and aren't produced here, but the type is
// shared so those phases reuse it rather than inventing another.
type mcpToolError struct {
	Code           string `json:"code"`
	Message        string `json:"message"`
	Step           int    `json:"step,omitempty"`
	Action         string `json:"action,omitempty"`
	ScreenID       string `json:"screen_id,omitempty"`
	RolledBack     bool   `json:"rolled_back"`
	AuditDirectory string `json:"audit_directory,omitempty"`
}

func (e mcpToolError) Error() string { return e.Code + ": " + e.Message }

const (
	mcpErrInvalidScenario   = "invalid_scenario"
	mcpErrUnsupportedAction = "unsupported_action"
	mcpErrWorkspaceChanged  = "workspace_changed"
	mcpErrValidationFailed  = "validation_failed"
	mcpErrRecordingFailed   = "recording_failed"
)

// toolErrorResult builds the CallToolResult a handler returns for a
// business/tool-level failure — err's structured fields are preserved
// as JSON in Content, matching spec's error JSON exactly, rather than
// being flattened to a plain string.
func toolErrorResult(err mcpToolError) *mcp.CallToolResult {
	data, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		// json.Marshal on this fixed, all-JSON-safe struct cannot
		// realistically fail; fall back to the plain Error() string
		// rather than losing the error entirely.
		data = []byte(err.Error())
	}
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}
}
