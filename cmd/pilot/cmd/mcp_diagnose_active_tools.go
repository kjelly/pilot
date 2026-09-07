package cmd

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/kjelly/pilot/internal/diagnose"
	"github.com/kjelly/pilot/internal/diagnosesession"
	"github.com/kjelly/pilot/internal/monitoring"
	"github.com/kjelly/pilot/internal/workspaceintegrity"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type diagnoseSNMPProbeInput struct {
	Target          string `json:"target" jsonschema:"exact monitoring target name from monitoring/targets.yml"`
	InvestigationID string `json:"investigation_id,omitempty" jsonschema:"optional diagnosis session id returned by pilot_workspace_integrity or pilot_diagnose_session_start"`
}

type diagnoseSNMPProbeOutput struct {
	diagnoseAuditStatus
	Target             string                    `json:"target"`
	Address            string                    `json:"address"`
	Profile            string                    `json:"profile"`
	Modules            []string                  `json:"modules,omitempty"`
	ProbeOID           string                    `json:"probe_oid"`
	CredentialResolved bool                      `json:"credential_resolved"`
	Transport          string                    `json:"transport"`
	Verdict            string                    `json:"verdict"`
	Workspace          workspaceintegrity.Report `json:"workspace"`
	AuditDirectory     string                    `json:"audit_directory,omitempty"`
	InvestigationID    string                    `json:"investigation_id,omitempty"`
}

func registerActiveDiagnoseTools(server *mcp.Server, opts diagnoseMCPToolsOptions) {
	addRecoveredTool(server, &mcp.Tool{
		Name:        "pilot_diagnose_snmp_probe",
		Description: "bounded read-only SNMP target probe using the exact registry target; credentials are resolved server-side and are never accepted or returned",
	}, diagnoseSNMPProbeHandler(opts))
}

func diagnoseSNMPProbeHandler(opts diagnoseMCPToolsOptions) mcp.ToolHandlerFor[diagnoseSNMPProbeInput, diagnoseSNMPProbeOutput] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in diagnoseSNMPProbeInput) (result *mcp.CallToolResult, out diagnoseSNMPProbeOutput, err error) {
		root := diagnoseWorkspaceRoot(opts)
		out = diagnoseSNMPProbeOutput{Target: in.Target, ProbeOID: "1.3.6.1.2.1.1.3.0", Transport: "not_attempted", Verdict: "insufficient_evidence", Workspace: workspaceintegrity.Monitoring(root), InvestigationID: in.InvestigationID}
		start := time.Now()
		sessionID, sessionErr := newID()
		if sessionErr != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: sessionErr.Error()}), diagnoseSNMPProbeOutput{}, nil
		}
		auditOpts := opts
		if auditOpts.AuditDir == "" {
			auditOpts.AuditDir = filepath.Join(root, ".pilot", "audit", "edit")
		}
		auditDir, auditErr := prepareDiagnoseAuditDir(auditOpts, "snmp_probe", sessionID, start)
		if auditErr != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: auditErr.Error()}), diagnoseSNMPProbeOutput{}, nil
		}
		out.AuditDirectory = auditDir
		defer func() {
			rec := diagnoseAuditRecord{
				SessionID: sessionID, Check: "snmp_probe", PilotVersion: rootCmd.Version,
				GitRevision: gitRevision(filepath.Dir(opts.Inventory)), MCPClient: mcpClientString(req),
				Inventory: opts.Inventory, Host: in.Target, Params: map[string]string{"target": in.Target},
				Start: start, Finish: time.Now(),
			}
			auditState := auditStatusFor(writeDiagnoseAudit(auditDir, rec))
			out.diagnoseAuditStatus = auditState
			if in.InvestigationID != "" {
				if _, appendErr := diagnosesession.Append(auditOpts.AuditDir, in.InvestigationID, "pilot_diagnose_snmp_probe", fmt.Sprintf("target=%s verdict=%s transport=%s", in.Target, out.Verdict, out.Transport)); appendErr != nil {
					out.AuditStatus = "failed"
					out.AuditError = appendErr.Error()
				}
			}
		}()
		if out.Workspace.Verdict != "complete" {
			return nil, out, nil
		}
		targets, err := monitoring.LoadTargets(filepath.Join(root, "monitoring", "targets.yml"))
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: err.Error()}), diagnoseSNMPProbeOutput{}, nil
		}
		profiles, err := monitoring.LoadProfiles(filepath.Join(root, "monitoring", "scrape-profiles.yml"))
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: err.Error()}), diagnoseSNMPProbeOutput{}, nil
		}
		var target monitoring.Target
		found := false
		for _, candidate := range targets.Targets {
			if candidate.Name == in.Target {
				target, found = candidate, true
				break
			}
		}
		if !found {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("monitoring target %q not found", in.Target)}), diagnoseSNMPProbeOutput{}, nil
		}
		profile, ok := profiles.Profiles[target.Profile]
		if !ok || !profile.IsSNMP() || profile.SNMP == nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("target %q is not backed by an SNMP profile", in.Target)}), diagnoseSNMPProbeOutput{}, nil
		}
		catalog, err := monitoring.LoadSNMPCatalog(filepath.Join(root, "monitoring", "snmp", "catalog.yml"))
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: err.Error()}), diagnoseSNMPProbeOutput{}, nil
		}
		if validation := monitoring.Validate(targets, profiles, catalog); !validation.OK() {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: "monitoring registry is invalid: " + strings.Join(validation.Errors, "; ")}), diagnoseSNMPProbeOutput{}, nil
		}
		auth, ok := catalog.AuthProfiles[profile.SNMP.AuthProfile]
		if !ok || strings.TrimSpace(auth.CredentialRef) == "" {
			out.Profile, out.Address, out.Modules = target.Profile, target.Address, append([]string(nil), profile.SNMP.Modules...)
			out.Verdict = "insufficient_evidence"
			return nil, out, nil
		}
		out.Profile, out.Address, out.Modules = target.Profile, target.Address, append([]string(nil), profile.SNMP.Modules...)
		resolved, resolveErr := resolveDiagnoseInventoryReadOnly(ctx, opts)
		if resolveErr != nil {
			out.Verdict = "insufficient_evidence"
			return nil, out, nil
		}
		exporterHost, hostErr := diagnose.ResolveSingletonGroupHost(resolved, "snmp-exporter")
		if hostErr != nil {
			out.Verdict = "exporter_down"
			return nil, out, nil
		}
		if len(profile.SNMP.Modules) == 0 {
			out.Verdict = "insufficient_evidence"
			return nil, out, nil
		}
		module := profile.SNMP.Modules[0]
		steps := diagnose.SNMPExporterProbeSteps(target.Address, module)
		runner := opts.AdHocRunner
		if runner == nil {
			runner = realDiagnoseAdHocRunner()
		}
		results := diagnose.RunSteps(ctx, runner, opts.Inventory, exporterHost, steps, minDiagnoseTimeout(opts.StepTimeout, 5*time.Second))
		if len(results) == 0 || results[0].Result.RunErr != nil || results[0].Result.Unreachable {
			out.Verdict = "exporter_down"
			out.Transport = "unreachable"
			return nil, out, nil
		}
		body, status, hasStatus := diagnose.SplitHTTPStatus(results[0].Result.Stdout)
		out.CredentialResolved = true
		out.Transport = "exporter_reachable"
		switch {
		case hasStatus && status >= 200 && status < 300 && strings.TrimSpace(body) != "":
			out.Verdict = "healthy"
		case hasStatus && status >= 500:
			out.Verdict = "snmp_auth_or_device_failure"
		default:
			out.Verdict = "insufficient_evidence"
		}
		return nil, out, nil
	}
}

func minDiagnoseTimeout(configured, maximum time.Duration) time.Duration {
	if configured <= 0 || configured > maximum {
		return maximum
	}
	return configured
}
