package cmd

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/kjelly/pilot/internal/diagnosesession"
	"github.com/kjelly/pilot/internal/workspaceintegrity"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type workspaceIntegrityInput struct {
	Scope           string `json:"scope,omitempty" jsonschema:"currently supported: monitoring"`
	InvestigationID string `json:"investigation_id,omitempty" jsonschema:"optional correlation session id; omit to start a new investigation"`
}

type workspaceIntegrityOutput struct {
	workspaceintegrity.Report
	InvestigationID string `json:"investigation_id"`
	AuditStatus     string `json:"audit_status"`
	AuditError      string `json:"audit_error,omitempty"`
}

func registerWorkspaceTools(server *mcp.Server, opts editMCPToolsOptions) {
	addRecoveredTool(server, &mcp.Tool{
		Name:        "pilot_workspace_integrity",
		Description: "always-read-only filesystem-aware reference closure for workspace assets; distinguishes missing, parse_error and complete sources and never returns file contents",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in workspaceIntegrityInput) (*mcp.CallToolResult, workspaceIntegrityOutput, error) {
		if in.Scope != "" && in.Scope != "monitoring" {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: "scope must be monitoring"}), workspaceIntegrityOutput{}, nil
		}
		auditRoot := opts.AuditDir
		if auditRoot == "" {
			auditRoot = filepath.Join(opts.Dir, ".pilot", "audit", "edit")
		}
		session, err := diagnosesession.Start(auditRoot, in.InvestigationID, "workspace/"+in.Scope)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), workspaceIntegrityOutput{}, nil
		}
		report := workspaceintegrity.Monitoring(opts.Dir)
		summary := fmt.Sprintf("scope=%s verdict=%s references=%d", in.Scope, report.Verdict, len(report.References))
		_, appendErr := diagnosesession.Append(auditRoot, session.ID, "pilot_workspace_integrity", summary)
		out := workspaceIntegrityOutput{Report: report, InvestigationID: session.ID, AuditStatus: "persisted"}
		if appendErr != nil {
			out.AuditStatus = "failed"
			out.AuditError = appendErr.Error()
		}
		return nil, out, nil
	})
	addRecoveredTool(server, &mcp.Tool{
		Name:        "pilot_diagnose_session_start",
		Description: "start a bounded append-only diagnosis investigation session for correlating structured MCP calls",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in struct {
		Subject string `json:"subject,omitempty"`
	}) (*mcp.CallToolResult, diagnosesession.Record, error) {
		auditRoot := opts.AuditDir
		if auditRoot == "" {
			auditRoot = filepath.Join(opts.Dir, ".pilot", "audit", "edit")
		}
		rec, err := diagnosesession.Start(auditRoot, "", in.Subject)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnosesession.Record{}, nil
		}
		return nil, rec, nil
	})
	addRecoveredTool(server, &mcp.Tool{
		Name:        "pilot_diagnose_session_get",
		Description: "read a bounded replayable diagnosis investigation session and its correlated tool summaries",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in struct {
		InvestigationID string `json:"investigation_id"`
	}) (*mcp.CallToolResult, diagnosesession.Record, error) {
		auditRoot := opts.AuditDir
		if auditRoot == "" {
			auditRoot = filepath.Join(opts.Dir, ".pilot", "audit", "edit")
		}
		rec, err := diagnosesession.Get(auditRoot, in.InvestigationID)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: err.Error()}), diagnosesession.Record{}, nil
		}
		return nil, rec, nil
	})
}
