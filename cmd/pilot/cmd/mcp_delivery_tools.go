package cmd

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/diagnose"
	"github.com/kjelly/pilot/internal/diagnosesession"
	"github.com/kjelly/pilot/internal/monitoring"
	"github.com/kjelly/pilot/internal/store"
	"github.com/kjelly/pilot/internal/workspaceintegrity"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type diagnoseDeliveryInput struct {
	Host            string `json:"host"`
	Component       string `json:"component"`
	InvestigationID string `json:"investigation_id,omitempty" jsonschema:"optional diagnosis session id returned by pilot_workspace_integrity or pilot_diagnose_session_start"`
}
type diagnoseDeliveryOutput struct {
	InvestigationID string            `json:"investigation_id,omitempty"`
	AuditStatus     string            `json:"audit_status,omitempty"`
	AuditError      string            `json:"audit_error,omitempty"`
	Host            string            `json:"host"`
	Component       string            `json:"component"`
	Desired         deliveryDesired   `json:"desired"`
	Selection       deliverySelection `json:"selection"`
	Execution       deliveryExecution `json:"execution"`
	Verdict         string            `json:"verdict"`
}
type deliveryDesired struct {
	Assigned bool   `json:"assigned"`
	Source   string `json:"source,omitempty"`
}
type deliverySelection struct {
	Selected          bool     `json:"selected"`
	Mode              string   `json:"mode,omitempty"`
	Limit             []string `json:"limit,omitempty"`
	PlannedComponents []string `json:"planned_components,omitempty"`
	OptIn             bool     `json:"opt_in"`
	Reason            string   `json:"reason"`
}
type deliveryExecution struct {
	LatestRunID          string   `json:"latest_run_id,omitempty"`
	Playbook             string   `json:"playbook,omitempty"`
	EffectiveHosts       []string `json:"effective_hosts,omitempty"`
	SelectedComponents   []string `json:"selected_components,omitempty"`
	SelectedTags         []string `json:"selected_tags,omitempty"`
	ComponentTagSelected bool     `json:"component_tag_selected"`
}

type deliveryRunGetInput struct {
	RunID string `json:"run_id"`
}
type deliveryRunGetOutput struct {
	Run               store.DeliveryRun   `json:"run"`
	Evidence          []store.RunEvidence `json:"evidence"`
	EvidenceTruncated bool                `json:"evidence_truncated,omitempty"`
}

func registerDeliveryTools(server *mcp.Server, opts diagnoseMCPToolsOptions) {
	addRecoveredTool(server, &mcp.Tool{Name: "pilot_diagnose_delivery", Description: "read-only delivery selection and history diagnosis for one exact host/component; selection is derived from the canonical dependency planner and durable run records"}, diagnoseDeliveryHandler(opts))
	addRecoveredTool(server, &mcp.Tool{Name: "pilot_delivery_run_get", Description: "read-only full drill-down for a run_id returned by pilot_diagnose_recent_changes"}, deliveryRunGetHandler())
	addRecoveredTool(server, &mcp.Tool{Name: "pilot_diagnose_monitoring_pipeline", Description: "read-only root-cause chain from monitoring registry through SNMP assets, delivery selection, rendered configuration and observable scrape/series evidence"}, diagnoseMonitoringPipelineHandler(opts))
}

func diagnoseDeliveryHandler(opts diagnoseMCPToolsOptions) mcp.ToolHandlerFor[diagnoseDeliveryInput, diagnoseDeliveryOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in diagnoseDeliveryInput) (*mcp.CallToolResult, diagnoseDeliveryOutput, error) {
		ctx = withDeployAnsibleRuntime(ctx, scopedDiagnoseAnsibleRuntime(opts.AnsibleRuntime))
		resolved, err := resolveDiagnoseInventoryReadOnly(ctx, opts)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: err.Error()}), diagnoseDeliveryOutput{}, nil
		}
		if err := diagnose.ValidateHost(resolved, in.Host); err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrHostNotFound, Message: err.Error()}), diagnoseDeliveryOutput{}, nil
		}
		root := diagnoseWorkspaceRoot(opts)
		loader, err := contract.NewLoader(root)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: err.Error()}), diagnoseDeliveryOutput{}, nil
		}
		catalog, err := loader.LoadDefaultCatalog()
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: err.Error()}), diagnoseDeliveryOutput{}, nil
		}
		comp, known := catalog.Component(in.Component)
		assigned := false
		if known {
			if groups, groupErr := resolveInventoryGroups(ctx, opts.Inventory); groupErr == nil {
				assigned = comp.Role == "all" || roleHasHostInScope(groups, map[string]bool{in.Host: true}, comp.Role)
			}
		}
		out := diagnoseDeliveryOutput{Host: in.Host, Component: in.Component, Desired: deliveryDesired{Assigned: assigned, Source: "hosts.yml"}, Selection: deliverySelection{Mode: "site", Limit: []string{in.Host}, Reason: "not_selected"}}
		if !known {
			out.Verdict = "component_unknown"
			out.InvestigationID, out.AuditStatus, out.AuditError = appendDeliveryInvestigation(opts, in.InvestigationID, fmt.Sprintf("delivery host=%s component=%s verdict=%s", in.Host, in.Component, out.Verdict))
			return nil, out, nil
		}
		playbook := "playbooks/site.yml"
		out.Selection.OptIn = comp.Site.OptIn
		selectedComponents, planErr := componentsForPlaybook(ctx, catalog, playbook, opts.Inventory, in.Host, "", nil)
		if planErr == nil {
			out.Selection.PlannedComponents = append([]string(nil), selectedComponents...)
			out.Selection.Selected = deliveryContains(selectedComponents, in.Component)
			if !out.Selection.Selected {
				out.Selection.Reason = "excluded_by_site_component_expansion"
			}
		} else {
			out.Selection.Reason = planErr.Error()
		}
		st, openErr := openSpecStore()
		if openErr == nil {
			defer st.Close()
			runs, listErr := st.ListRuns(store.RunFilter{Host: in.Host, Component: in.Component, Limit: 1})
			if listErr == nil && len(runs) > 0 {
				r := runs[0]
				selectedTags := deliveryMetadataStrings(r, "selected_tags")
				if len(selectedTags) == 0 {
					if raw, ok := r.Metadata["tags"].(string); ok {
						selectedTags = splitDeliveryTags(raw)
					}
				}
				out.Execution = deliveryExecution{LatestRunID: r.RunID, Playbook: r.Playbook, EffectiveHosts: r.Hosts, SelectedComponents: r.Components, SelectedTags: selectedTags, ComponentTagSelected: deliveryContains(selectedTags, in.Component)}
				out.Selection.Mode = deliveryMetadataString(r, "selection_mode", "history")
				out.Selection.Limit = r.Hosts
				// A historical run is evidence of what happened then, not an
				// override of the current canonical selection planner.
			}
		}
		if !out.Selection.Selected {
			out.Verdict = "component_not_selected"
		} else {
			out.Verdict = "selected"
		}
		out.InvestigationID, out.AuditStatus, out.AuditError = appendDeliveryInvestigation(opts, in.InvestigationID, fmt.Sprintf("delivery host=%s component=%s verdict=%s selected=%t", in.Host, in.Component, out.Verdict, out.Selection.Selected))
		return nil, out, nil
	}
}

func appendDeliveryInvestigation(opts diagnoseMCPToolsOptions, id, summary string) (string, string, string) {
	if id == "" {
		return "", "not_requested", ""
	}
	_, err := diagnosesession.Append(opts.AuditDir, id, "pilot_diagnose_delivery", summary)
	if err != nil {
		return id, "failed", err.Error()
	}
	return id, "persisted", ""
}

func deliveryRunGetHandler() mcp.ToolHandlerFor[deliveryRunGetInput, deliveryRunGetOutput] {
	return func(_ context.Context, _ *mcp.CallToolRequest, in deliveryRunGetInput) (*mcp.CallToolResult, deliveryRunGetOutput, error) {
		if in.RunID == "" {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: "run_id is required"}), deliveryRunGetOutput{}, nil
		}
		st, err := openSpecStore()
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), deliveryRunGetOutput{}, nil
		}
		defer st.Close()
		run, evidence, err := st.GetRun(in.RunID)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: err.Error()}), deliveryRunGetOutput{}, nil
		}
		const maxEvidence = 200
		truncated := len(evidence) > maxEvidence
		if truncated {
			evidence = evidence[:maxEvidence]
		}
		return nil, deliveryRunGetOutput{Run: run, Evidence: evidence, EvidenceTruncated: truncated}, nil
	}
}

func deliveryContains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func deliveryMetadataString(r store.DeliveryRun, key, fallback string) string {
	if r.Metadata != nil {
		if value, ok := r.Metadata[key].(string); ok && value != "" {
			return value
		}
	}
	return fallback
}

func deliveryMetadataStrings(r store.DeliveryRun, key string) []string {
	if r.Metadata == nil {
		return nil
	}
	var out []string
	switch values := r.Metadata[key].(type) {
	case []any:
		out = make([]string, 0, len(values))
		for _, value := range values {
			if item, ok := value.(string); ok && item != "" {
				out = append(out, item)
			}
		}
	case []string:
		out = append([]string(nil), values...)
	}
	return out
}

func splitDeliveryTags(raw string) []string {
	var out []string
	for _, value := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' }) {
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

type monitoringPipelineInput struct {
	Target          string `json:"target"`
	InvestigationID string `json:"investigation_id,omitempty" jsonschema:"optional diagnosis session id returned by pilot_workspace_integrity or pilot_diagnose_session_start"`
}
type monitoringPipelineOutput struct {
	InvestigationID string                    `json:"investigation_id,omitempty"`
	AuditStatus     string                    `json:"audit_status,omitempty"`
	AuditError      string                    `json:"audit_error,omitempty"`
	Target          string                    `json:"target"`
	Verdict         string                    `json:"verdict"`
	Stages          map[string]string         `json:"stages"`
	RootCause       string                    `json:"root_cause,omitempty"`
	Workspace       workspaceintegrity.Report `json:"workspace"`
}

func diagnoseMonitoringPipelineHandler(opts diagnoseMCPToolsOptions) mcp.ToolHandlerFor[monitoringPipelineInput, monitoringPipelineOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in monitoringPipelineInput) (result *mcp.CallToolResult, out monitoringPipelineOutput, err error) {
		defer func() {
			out.InvestigationID, out.AuditStatus, out.AuditError = appendPipelineInvestigation(opts, in.InvestigationID, out)
		}()
		ctx = withDeployAnsibleRuntime(ctx, scopedDiagnoseAnsibleRuntime(opts.AnsibleRuntime))
		out = monitoringPipelineOutput{Target: in.Target, Stages: map[string]string{}, Workspace: workspaceintegrity.Monitoring(diagnoseWorkspaceRoot(opts))}
		for _, stage := range []string{"registry", "scrape_profile", "workspace_assets", "snmp_catalog_assets", "component_assignment", "deploy_selection", "snmp_exporter_selection", "snmp_exporter_config", "runtime", "prometheus_target", "prometheus_scrape", "scrape", "thanos_series"} {
			out.Stages[stage] = "unknown"
		}
		if out.Workspace.Verdict == "complete" {
			out.Stages["workspace_assets"] = "ok"
		} else {
			out.Stages["workspace_assets"] = "incomplete"
		}
		root := diagnoseWorkspaceRoot(opts)
		tf, err := monitoring.LoadTargets(filepath.Join(root, "monitoring", "targets.yml"))
		if err != nil {
			out.Stages["registry"] = "parse_error"
			out.Verdict = "insufficient_evidence"
			out.RootCause = err.Error()
			return nil, out, nil
		}
		pf, err := monitoring.LoadProfiles(filepath.Join(root, "monitoring", "scrape-profiles.yml"))
		if err != nil {
			out.Stages["registry"] = "parse_error"
			out.Verdict = "insufficient_evidence"
			out.RootCause = err.Error()
			return nil, out, nil
		}
		var target monitoring.Target
		found := false
		for _, item := range tf.Targets {
			if item.Name == in.Target {
				target, found = item, true
				break
			}
		}
		if !found {
			out.Stages["registry"] = "missing"
			out.Verdict = "insufficient_evidence"
			out.RootCause = fmt.Sprintf("target %q is not in monitoring registry", in.Target)
			return nil, out, nil
		}
		out.Stages["registry"] = "ok"
		profile, ok := pf.Profiles[target.Profile]
		if !ok {
			out.Stages["scrape_profile"] = "missing"
			out.Verdict = "workspace_incomplete"
			out.RootCause = "scrape profile is missing"
			return nil, out, nil
		}
		out.Stages["scrape_profile"] = "ok"
		if profile.IsSNMP() {
			out.Stages["snmp_catalog_assets"] = out.Stages["workspace_assets"]
		} else {
			out.Stages["snmp_catalog_assets"] = "not_applicable"
			out.Stages["snmp_exporter_config"] = "not_applicable"
			out.Stages["component_assignment"] = "not_applicable"
			out.Stages["deploy_selection"] = "not_applicable"
			out.Stages["prometheus_target"] = "not_applicable"
			out.Stages["prometheus_scrape"] = "not_applicable"
			out.Stages["scrape"] = "not_applicable"
			out.Stages["thanos_series"] = "not_applicable"
			out.Verdict = "insufficient_evidence"
			out.RootCause = "target profile is not an SNMP pipeline"
			return nil, out, nil
		}
		snmpCatalog, catalogErr := monitoring.LoadSNMPCatalog(filepath.Join(root, "monitoring", "snmp", "catalog.yml"))
		if catalogErr != nil {
			out.Stages["registry"] = "parse_error"
			out.Verdict = "workspace_incomplete"
			out.RootCause = catalogErr.Error()
			return nil, out, nil
		}
		if validation := monitoring.Validate(tf, pf, snmpCatalog); !validation.OK() {
			out.Stages["registry"] = "invalid"
			out.Verdict = "insufficient_evidence"
			out.RootCause = strings.Join(validation.Errors, "; ")
			return nil, out, nil
		}

		root = diagnoseWorkspaceRoot(opts)
		loader, err := contract.NewLoader(root)
		if err != nil {
			out.Verdict = "insufficient_evidence"
			out.RootCause = err.Error()
			return nil, out, nil
		}
		catalog, err := loader.LoadDefaultCatalog()
		if err != nil {
			out.Verdict = "insufficient_evidence"
			out.RootCause = err.Error()
			return nil, out, nil
		}
		exporter, known := catalog.Component("snmp-exporter")
		if !known {
			out.Stages["component_assignment"] = "missing"
			out.Verdict = "insufficient_evidence"
			out.RootCause = "snmp-exporter contract is missing"
			return nil, out, nil
		}
		groups, err := resolveInventoryGroups(ctx, opts.Inventory)
		if err != nil {
			out.Stages["component_assignment"] = "unknown"
			out.Verdict = "insufficient_evidence"
			out.RootCause = err.Error()
			return nil, out, nil
		}
		assigned := exporter.Role == "all" || len(groups[exporter.Role]) > 0
		if !assigned {
			out.Stages["component_assignment"] = "not_assigned"
			out.Stages["deploy_selection"] = "not_selected"
			out.Stages["snmp_exporter_selection"] = "not_selected"
			out.Verdict = "component_not_selected"
			out.RootCause = "no snmp-exporter host is assigned in the active inventory"
			return nil, out, nil
		}
		out.Stages["component_assignment"] = "assigned"
		// Site-wide selection is the canonical planner used by deploy. The
		// component's own apply playbook would trivially select itself and
		// would hide the exact opt-in omission this diagnosis is meant to
		// explain.
		selected, err := componentsForPlaybook(ctx, catalog, "playbooks/site.yml", opts.Inventory, "", "", nil)
		if err != nil {
			out.Stages["deploy_selection"] = "unknown"
			out.Verdict = "insufficient_evidence"
			out.RootCause = err.Error()
			return nil, out, nil
		}
		if !deliveryContains(selected, exporter.ID) {
			out.Stages["deploy_selection"] = "not_selected"
			out.Stages["snmp_exporter_selection"] = "not_selected"
			out.Verdict = "component_not_selected"
			out.RootCause = "canonical deployment selection excluded snmp-exporter"
			return nil, out, nil
		}
		out.Stages["deploy_selection"] = "selected"
		out.Stages["snmp_exporter_selection"] = "selected"
		st, err := openSpecStore()
		if err != nil {
			out.Stages["snmp_exporter_config"] = "unknown"
			out.Verdict = "insufficient_evidence"
			out.RootCause = err.Error()
			return nil, out, nil
		}
		defer st.Close()
		runs, err := st.ListRuns(store.RunFilter{Component: exporter.ID, Limit: 1})
		if err != nil || len(runs) == 0 {
			out.Stages["snmp_exporter_config"] = "missing"
			out.Stages["runtime"] = "not_applicable"
			out.Stages["prometheus_target"] = "missing"
			out.Stages["prometheus_scrape"] = "not_applicable"
			out.Stages["scrape"] = "not_applicable"
			out.Stages["thanos_series"] = "absent"
			out.Verdict = "renderer_not_applied"
			out.RootCause = "no snmp-exporter delivery run is recorded"
			return nil, out, nil
		}
		latest := runs[0]
		if latest.Outcome != "success" && latest.Outcome != "partial_success" {
			out.Stages["snmp_exporter_config"] = "apply_failed"
			out.Stages["runtime"] = "unknown"
			out.Verdict = "insufficient_evidence"
			out.RootCause = "latest snmp-exporter delivery did not succeed"
			return nil, out, nil
		}
		// A successful history event proves that the apply transaction was
		// accepted; it does not prove that the managed files survived on the
		// target.  Probe only contract-declared metadata and the fixed runtime
		// state command, never arbitrary paths supplied by the caller.
		runner := opts.AdHocRunner
		if runner == nil {
			runner = realDiagnoseAdHocRunner()
		}
		exporterHosts := groups[exporter.Role]
		if len(exporterHosts) == 0 {
			out.Stages["snmp_exporter_config"] = "unknown"
			out.Stages["runtime"] = "unknown"
		} else {
			artifactResults := diagnose.RunSteps(ctx, runner, opts.Inventory, exporterHosts[0], diagnose.ArtifactSteps(artifactPaths(exporter.Diagnostics.Artifacts)), minDiagnoseTimeout(opts.StepTimeout, 5*time.Second))
			present, missing := false, false
			if len(exporter.Diagnostics.Artifacts) == 0 {
				present = true
			}
			for i := range exporter.Diagnostics.Artifacts {
				base := i * 3
				if base >= len(artifactResults) || artifactResults[base].Result.RC != 0 || artifactResults[base].Result.RunErr != nil {
					missing = true
				} else {
					present = true
				}
			}
			switch {
			case present && !missing:
				out.Stages["snmp_exporter_config"] = "present"
			case present:
				out.Stages["snmp_exporter_config"] = "incomplete"
			default:
				out.Stages["snmp_exporter_config"] = "missing"
			}
			if runtimeStep := diagnose.RuntimeStateStep(exporter.Diagnostics.Runtime.Kind, exporter.Diagnostics.Runtime.Name); runtimeStep != nil {
				runtimeResults := diagnose.RunSteps(ctx, runner, opts.Inventory, exporterHosts[0], []diagnose.Step{*runtimeStep}, minDiagnoseTimeout(opts.StepTimeout, 5*time.Second))
				if len(runtimeResults) > 0 && runtimeResults[0].Result.RunErr == nil && !runtimeResults[0].Result.Unreachable {
					state := strings.TrimSpace(runtimeResults[0].Result.Stdout)
					if state == "running" || runtimeResults[0].Result.RC == 0 {
						out.Stages["runtime"] = "running"
					} else {
						out.Stages["runtime"] = "down"
					}
				} else {
					out.Stages["runtime"] = "unknown"
				}
			}
		}
		prometheusHosts := groups["prometheus"]
		if len(prometheusHosts) == 0 {
			out.Stages["prometheus_target"] = "missing"
		} else {
			path := filepath.Join("/etc/pilot/prometheus/targets", profile.JobName+".json")
			probe := diagnose.RunSteps(ctx, runner, opts.Inventory, prometheusHosts[0], diagnose.ArtifactSteps([]string{path}), minDiagnoseTimeout(opts.StepTimeout, 5*time.Second))
			if len(probe) > 0 && probe[0].Result.RC == 0 && probe[0].Result.RunErr == nil {
				out.Stages["prometheus_target"] = "present"
			} else {
				out.Stages["prometheus_target"] = "missing"
			}
		}
		if out.Stages["prometheus_target"] == "missing" {
			out.Stages["prometheus_scrape"] = "not_applicable"
			out.Stages["scrape"] = "not_applicable"
			out.Stages["thanos_series"] = "absent"
		} else {
			out.Stages["prometheus_scrape"] = "unknown"
			out.Stages["scrape"] = "unknown"
			out.Stages["thanos_series"] = "unknown"
		}
		switch {
		case out.Stages["snmp_exporter_config"] == "missing":
			out.Verdict = "exporter_not_configured"
			out.RootCause = "delivery is recorded, but the exporter configuration artifacts are absent"
		case out.Stages["runtime"] == "down":
			out.Verdict = "exporter_down"
			out.RootCause = "exporter configuration is present but the runtime is not running"
		default:
			out.Verdict = "insufficient_evidence"
			out.RootCause = "delivery is applied, but downstream scrape and series evidence is unavailable"
		}
		return nil, out, nil
	}
}

func appendPipelineInvestigation(opts diagnoseMCPToolsOptions, id string, out monitoringPipelineOutput) (string, string, string) {
	if id == "" {
		return "", "not_requested", ""
	}
	summary := fmt.Sprintf("pipeline target=%s verdict=%s stages=%v", out.Target, out.Verdict, out.Stages)
	if _, err := diagnosesession.Append(opts.AuditDir, id, "pilot_diagnose_monitoring_pipeline", summary); err != nil {
		return id, "failed", err.Error()
	}
	return id, "persisted", ""
}
