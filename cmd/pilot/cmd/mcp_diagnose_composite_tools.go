// mcp_diagnose_composite_tools.go implements Agent Monitoring Phase 2's
// four bounded, read-only composite diagnostics: pilot_diagnose_
// host_health, pilot_diagnose_component, pilot_diagnose_network_path,
// pilot_diagnose_recent_changes. Each asks Pilot a domain question
// instead of assembling low-level commands — the narrow pilot_diagnose_*
// tools in mcp_diagnose_tools.go remain available for drill-down. No
// mutation is introduced here; every tool registers under the SAME
// --enable-diagnose flag as the narrow tools, through the same
// addRecoveredTool choke point.
package cmd

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/kjelly/pilot/internal/changejournal"
	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/diagnose"
	"github.com/kjelly/pilot/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerDiagnoseCompositeTools(server *mcp.Server, opts diagnoseMCPToolsOptions) {
	addRecoveredTool(server, &mcp.Tool{
		Name:        "pilot_diagnose_host_health",
		Description: "one-call composite host health check: exact host reachability, uptime/boot, load, CPU saturation trend from Thanos (best-effort, skipped with a note if thanos-query isn't deployed), memory pressure, filesystem free bytes/inode pressure, bounded failed-systemd-units list, clock sync state, interface/link summary, node_exporter scrape/up state, bounded OOM/kernel error evidence, and the active Detection Engine signal summary for this host (best-effort, skipped with a note if detection-engine isn't deployed). Pilot reports deterministic findings only — verdict is healthy/degraded/unreachable/insufficient_evidence, not a root-cause guess.",
	}, diagnoseHostHealthHandler(opts))
	addRecoveredTool(server, &mcp.Tool{
		Name:        "pilot_diagnose_component",
		Description: "one-call composite component health check driven by a component's own contracts/*.yaml `diagnostics` block (never an arbitrary command): runtime present/running state (docker container or systemd unit), readiness endpoint status, bounded recent error log tail, TCP reachability to this component's own providerEndpoint dependencies (resolved from the target host's actual configured hostvar, never a caller-supplied host:port), and the verification spec this component's contract declares. Components without a `diagnostics` block return an error naming which components currently have one.",
	}, diagnoseComponentHandler(opts))
	addRecoveredTool(server, &mcp.Tool{
		Name:        "pilot_diagnose_network_path",
		Description: "one-call composite network path check FROM one real inventory host TO a declared contract endpoint (never an arbitrary host:port): name_resolution, routing, transport (TCP connect to the declared port), tls (only when the endpoint's scheme is https — never uses -k/insecure to turn a certificate failure into success), and application_readiness (only when the destination component declares a readiness path). Verdict is reachable, blocked_at_<layer>, unreachable, or insufficient_evidence.",
	}, diagnoseNetworkPathHandler(opts))
	addRecoveredTool(server, &mcp.Tool{
		Name:        "pilot_diagnose_recent_changes",
		Description: "answers \"what changed shortly before this incident?\" by querying pilot's own durable mutation records — MCP edit-apply audit sessions and pilot deploy run history — in [start, end], never [now-lookback, now] once time has already passed while an Agent was investigating. Returns compact records (kind, actor/workspace revision, hosts, components, result, audit reference), not full transcripts. Never labels a Detection Engine signal revision as a deployment change — this tool has no Detection Engine source at all.",
	}, diagnoseRecentChangesHandler(opts))
}

// ---- pilot_diagnose_host_health -----------------------------------------

type diagnoseHostHealthInput struct {
	Host     string `json:"host" jsonschema:"exact inventory hostname — must be an exact ansible-inventory key, never a pattern/group/wildcard"`
	Lookback string `json:"lookback,omitempty" jsonschema:"Go duration for the Thanos CPU-saturation-trend window, default 30m"`
}

type diagnoseHostHealthOutput struct {
	Host                 string                     `json:"host"`
	ResolvedAddr         string                     `json:"resolved_addr,omitempty"`
	Reachable            bool                       `json:"reachable"`
	UptimeSeconds        float64                    `json:"uptime_seconds,omitempty"`
	Load1                float64                    `json:"load1,omitempty"`
	Load5                float64                    `json:"load5,omitempty"`
	Load15               float64                    `json:"load15,omitempty"`
	MemTotalKiB          int64                      `json:"mem_total_kib,omitempty"`
	MemAvailableKiB      int64                      `json:"mem_available_kib,omitempty"`
	Filesystems          []diagnose.FilesystemUsage `json:"filesystems,omitempty"`
	FailedUnits          []string                   `json:"failed_units,omitempty"`
	ClockSynchronized    bool                       `json:"clock_synchronized"`
	Interfaces           []string                   `json:"interfaces,omitempty"`
	NodeExporterActive   bool                       `json:"node_exporter_active"`
	KernelErrorLines     []string                   `json:"kernel_error_lines,omitempty"`
	ThanosCPUTrendJSON   string                     `json:"thanos_cpu_trend_json,omitempty"`
	ThanosNote           string                     `json:"thanos_note,omitempty"`
	DetectionSignalsJSON string                     `json:"detection_signals_json,omitempty"`
	DetectionNote        string                     `json:"detection_note,omitempty"`
	Verdict              string                     `json:"verdict"`
	Steps                []diagnoseStepEvidence     `json:"steps"`
	AuditDirectory       string                     `json:"audit_directory"`
}

func diagnoseHostHealthHandler(opts diagnoseMCPToolsOptions) mcp.ToolHandlerFor[diagnoseHostHealthInput, diagnoseHostHealthOutput] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in diagnoseHostHealthInput) (*mcp.CallToolResult, diagnoseHostHealthOutput, error) {
		lookback := in.Lookback
		if lookback == "" {
			lookback = "30m"
		}
		if _, err := time.ParseDuration(lookback); err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("lookback: %v", err)}), diagnoseHostHealthOutput{}, nil
		}

		ctx = withDeployAnsibleRuntime(ctx, scopedDiagnoseAnsibleRuntime(opts.AnsibleRuntime))
		resolved, err := resolveDiagnoseInventory(ctx, opts)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("resolve inventory: %v", err)}), diagnoseHostHealthOutput{}, nil
		}
		if err := diagnose.ValidateHost(resolved, in.Host); err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrHostNotFound, Message: err.Error()}), diagnoseHostHealthOutput{}, nil
		}

		sessionID, err := newID()
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnoseHostHealthOutput{}, nil
		}
		start := time.Now()
		auditDir, err := prepareDiagnoseAuditDir(opts, "host_health", sessionID, start)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnoseHostHealthOutput{}, nil
		}

		runner := opts.AdHocRunner
		if runner == nil {
			runner = realDiagnoseAdHocRunner()
		}

		hostSteps := diagnose.HostHealthSteps()
		hostResults := diagnose.RunSteps(ctx, runner, opts.Inventory, in.Host, hostSteps, opts.StepTimeout)
		reachable := true
		for _, r := range hostResults {
			if r.Result.Unreachable {
				reachable = false
				break
			}
		}
		health := diagnose.BuildHostHealthOutput(reachable, hostResults)

		allResults := append([]diagnose.StepResult{}, hostResults...)
		out := diagnoseHostHealthOutput{
			Host: in.Host, ResolvedAddr: resolved.HostAddr(in.Host), Reachable: reachable,
			UptimeSeconds: health.UptimeSeconds, Load1: health.Load1, Load5: health.Load5, Load15: health.Load15,
			MemTotalKiB: health.MemTotalKiB, MemAvailableKiB: health.MemAvailableKiB,
			Filesystems: health.Filesystems, FailedUnits: health.FailedUnits,
			ClockSynchronized: health.ClockSynchronized, Interfaces: health.Interfaces,
			NodeExporterActive: health.NodeExporterActive, KernelErrorLines: health.KernelErrorLines,
			Verdict: health.Verdict, AuditDirectory: auditDir,
		}

		// Best-effort Thanos CPU trend — never a hard failure.
		if thanosHost, thErr := diagnose.ResolveSingletonGroupHost(resolved, diagnose.ThanosQueryGroup); thErr != nil {
			out.ThanosNote = thErr.Error()
		} else {
			query := fmt.Sprintf(`100 - (avg(rate(node_cpu_seconds_total{mode="idle",pilot_host=%q}[%s])) * 100)`, in.Host, lookback)
			thanosSteps := diagnose.MetricsSteps(query, "", "", "", "")
			thanosResults := diagnose.RunSteps(ctx, runner, opts.Inventory, thanosHost, thanosSteps, opts.StepTimeout)
			allResults = append(allResults, thanosResults...)
			if len(thanosResults) > 0 {
				r := thanosResults[0].Result
				switch {
				case r.RunErr != nil:
					out.ThanosNote = r.RunErr.Error()
				case r.Unreachable:
					out.ThanosNote = "thanos-query host unreachable"
				default:
					if body, _, split := diagnose.SplitHTTPStatus(r.Stdout); split {
						out.ThanosCPUTrendJSON = body
					} else {
						out.ThanosCPUTrendJSON = strings.TrimSpace(r.Stdout)
					}
				}
			}
		}

		// Best-effort Detection Engine active signal summary — never a
		// hard failure. Go-side substring filter, not a full JSON schema
		// dependency: this is a "does anything mention this host" signal
		// summary, not a structured cross-reference.
		if detHost, detErr := diagnose.ResolveSingletonGroupHost(resolved, diagnose.DetectionEngineGroup); detErr != nil {
			out.DetectionNote = detErr.Error()
		} else {
			detSteps := diagnose.DetectionSteps("")
			detResults := diagnose.RunSteps(ctx, runner, opts.Inventory, detHost, detSteps, opts.StepTimeout)
			allResults = append(allResults, detResults...)
			for _, r := range detResults {
				if r.Step.ID != "signals_list" {
					continue
				}
				switch {
				case r.Result.RunErr != nil:
					out.DetectionNote = r.Result.RunErr.Error()
				case r.Result.Unreachable:
					out.DetectionNote = "detection-engine host unreachable"
				case strings.Contains(r.Result.Stdout, in.Host):
					out.DetectionSignalsJSON = strings.TrimSpace(r.Result.Stdout)
				default:
					out.DetectionNote = "no active signal mentions this host"
				}
			}
		}

		rec := diagnoseAuditRecord{
			SessionID: sessionID, Check: "host_health", PilotVersion: rootCmd.Version,
			GitRevision: gitRevision(filepath.Dir(opts.Inventory)), MCPClient: mcpClientString(req),
			Inventory: opts.Inventory, Host: in.Host, Params: map[string]string{"lookback": lookback},
			Start: start, Finish: time.Now(), Steps: stepAuditList(allResults),
		}
		_ = writeDiagnoseAudit(auditDir, rec)
		out.Steps = stepEvidenceList(allResults)
		return nil, out, nil
	}
}

// ---- pilot_diagnose_component --------------------------------------------

type diagnoseComponentInput struct {
	Host      string `json:"host" jsonschema:"exact inventory hostname — must be an exact ansible-inventory key, never a pattern/group/wildcard"`
	Component string `json:"component" jsonschema:"component ID from contracts/*.yaml — must have a diagnostics block AND be assigned to host"`
}

type diagnoseComponentOutput struct {
	Host                string                              `json:"host"`
	Component           string                              `json:"component"`
	RuntimeConfigured   bool                                `json:"runtime_configured"`
	RuntimePresent      bool                                `json:"runtime_present"`
	RuntimeRunning      bool                                `json:"runtime_running"`
	ReadinessConfigured bool                                `json:"readiness_configured"`
	ReadinessHTTPStatus int                                 `json:"readiness_http_status,omitempty"`
	ReadinessOK         bool                                `json:"readiness_ok"`
	RecentErrorLines    []string                            `json:"recent_error_lines,omitempty"`
	DependencyResults   []diagnose.DependencyEndpointResult `json:"dependency_results,omitempty"`
	VerifySpec          string                              `json:"verify_spec,omitempty"`
	Verdict             string                              `json:"verdict"`
	Steps               []diagnoseStepEvidence              `json:"steps"`
	AuditDirectory      string                              `json:"audit_directory"`
}

func diagnoseComponentHandler(opts diagnoseMCPToolsOptions) mcp.ToolHandlerFor[diagnoseComponentInput, diagnoseComponentOutput] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in diagnoseComponentInput) (*mcp.CallToolResult, diagnoseComponentOutput, error) {
		ctx = withDeployAnsibleRuntime(ctx, scopedDiagnoseAnsibleRuntime(opts.AnsibleRuntime))
		resolved, err := resolveDiagnoseInventory(ctx, opts)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("resolve inventory: %v", err)}), diagnoseComponentOutput{}, nil
		}
		if err := diagnose.ValidateHost(resolved, in.Host); err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrHostNotFound, Message: err.Error()}), diagnoseComponentOutput{}, nil
		}

		root, err := resolveContractRoot("")
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("resolve contract root: %v", err)}), diagnoseComponentOutput{}, nil
		}
		loader, err := contract.NewLoader(root)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: err.Error()}), diagnoseComponentOutput{}, nil
		}
		catalog, err := loader.LoadDefaultCatalog()
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: err.Error()}), diagnoseComponentOutput{}, nil
		}
		comp, ok := catalog.Component(in.Component)
		if !ok {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("unknown component %q", in.Component)}), diagnoseComponentOutput{}, nil
		}
		if comp.Diagnostics.Runtime.Kind == "" {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("component %q has no diagnostics block configured", in.Component)}), diagnoseComponentOutput{}, nil
		}

		readinessURL := ""
		if comp.Diagnostics.Readiness.Endpoint != "" {
			for _, e := range comp.Endpoints {
				if e.Name == comp.Diagnostics.Readiness.Endpoint {
					readinessURL = fmt.Sprintf("%s://127.0.0.1:%d%s", e.Scheme, e.Port, comp.Diagnostics.Readiness.Path)
				}
			}
		}

		var depChecks []diagnose.DependencyEndpointCheck
		hostVars := resolved.HostVars[in.Host]
		for _, binding := range comp.Bindings {
			depComp, ok := catalog.Component(binding.From.Component)
			if !ok {
				continue
			}
			var depEndpoint contract.Endpoint
			found := false
			for _, e := range depComp.Endpoints {
				if e.Name == binding.From.Endpoint {
					depEndpoint = e
					found = true
				}
			}
			if !found {
				continue
			}
			hostValue, hasHostValue := hostVars[binding.Input]
			hostStr, isStr := hostValue.(string)
			if !hasHostValue || !isStr || hostStr == "" {
				continue
			}
			depChecks = append(depChecks, diagnose.DependencyEndpointCheck{Component: binding.From.Component, Host: hostStr, Port: depEndpoint.Port})
		}

		sessionID, err := newID()
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnoseComponentOutput{}, nil
		}
		start := time.Now()
		auditDir, err := prepareDiagnoseAuditDir(opts, "component", sessionID, start)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnoseComponentOutput{}, nil
		}

		runner := opts.AdHocRunner
		if runner == nil {
			runner = realDiagnoseAdHocRunner()
		}
		steps := diagnose.ComponentSteps(comp.Diagnostics.Runtime.Kind, comp.Diagnostics.Runtime.Name, readinessURL,
			comp.Diagnostics.Logs.Source, comp.Diagnostics.Runtime.Name, depChecks)
		results := diagnose.RunSteps(ctx, runner, opts.Inventory, in.Host, steps, opts.StepTimeout)

		reachable := true
		for _, r := range results {
			if r.Result.Unreachable {
				reachable = false
			}
		}
		compOut := diagnose.BuildComponentOutput(comp.Diagnostics.Runtime.Kind, comp.Diagnostics.VerifySpec, depChecks, reachable, results)

		rec := diagnoseAuditRecord{
			SessionID: sessionID, Check: "component", PilotVersion: rootCmd.Version,
			GitRevision: gitRevision(filepath.Dir(opts.Inventory)), MCPClient: mcpClientString(req),
			Inventory: opts.Inventory, Host: in.Host, Params: map[string]string{"component": in.Component},
			Start: start, Finish: time.Now(), Steps: stepAuditList(results),
		}
		_ = writeDiagnoseAudit(auditDir, rec)

		out := diagnoseComponentOutput{
			Host: in.Host, Component: in.Component,
			RuntimeConfigured: compOut.RuntimeConfigured, RuntimePresent: compOut.RuntimePresent, RuntimeRunning: compOut.RuntimeRunning,
			ReadinessConfigured: compOut.ReadinessConfigured, ReadinessHTTPStatus: compOut.ReadinessHTTPStatus, ReadinessOK: compOut.ReadinessOK,
			RecentErrorLines: compOut.RecentErrorLines, DependencyResults: compOut.DependencyResults,
			VerifySpec: compOut.VerifySpec, Verdict: compOut.Verdict, Steps: stepEvidenceList(results), AuditDirectory: auditDir,
		}
		return nil, out, nil
	}
}

// ---- pilot_diagnose_network_path -----------------------------------------

type diagnoseNetworkPathInput struct {
	SourceHost string `json:"source_host" jsonschema:"exact inventory hostname to probe FROM — must be an exact ansible-inventory key"`
	Component  string `json:"component" jsonschema:"destination component ID from contracts/*.yaml"`
	Endpoint   string `json:"endpoint" jsonschema:"destination endpoint name from that component's contracts/*.yaml endpoints[]"`
	Host       string `json:"host,omitempty" jsonschema:"destination host override — only needed when the destination component's hostCardinality is not exactly-one"`
}

type diagnoseNetworkPathOutput struct {
	SourceHost     string                            `json:"source_host"`
	DestHost       string                            `json:"dest_host"`
	DestPort       int                               `json:"dest_port"`
	Scheme         string                            `json:"scheme"`
	Layers         []diagnose.NetworkPathLayerResult `json:"layers"`
	Verdict        string                            `json:"verdict"`
	Steps          []diagnoseStepEvidence            `json:"steps"`
	AuditDirectory string                            `json:"audit_directory"`
}

func diagnoseNetworkPathHandler(opts diagnoseMCPToolsOptions) mcp.ToolHandlerFor[diagnoseNetworkPathInput, diagnoseNetworkPathOutput] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in diagnoseNetworkPathInput) (*mcp.CallToolResult, diagnoseNetworkPathOutput, error) {
		ctx = withDeployAnsibleRuntime(ctx, scopedDiagnoseAnsibleRuntime(opts.AnsibleRuntime))
		resolved, err := resolveDiagnoseInventory(ctx, opts)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("resolve inventory: %v", err)}), diagnoseNetworkPathOutput{}, nil
		}
		if err := diagnose.ValidateHost(resolved, in.SourceHost); err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrHostNotFound, Message: err.Error()}), diagnoseNetworkPathOutput{}, nil
		}

		root, err := resolveContractRoot("")
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("resolve contract root: %v", err)}), diagnoseNetworkPathOutput{}, nil
		}
		loader, err := contract.NewLoader(root)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: err.Error()}), diagnoseNetworkPathOutput{}, nil
		}
		catalog, err := loader.LoadDefaultCatalog()
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: err.Error()}), diagnoseNetworkPathOutput{}, nil
		}
		destComp, ok := catalog.Component(in.Component)
		if !ok {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("unknown component %q", in.Component)}), diagnoseNetworkPathOutput{}, nil
		}
		var destEndpoint contract.Endpoint
		found := false
		for _, e := range destComp.Endpoints {
			if e.Name == in.Endpoint {
				destEndpoint = e
				found = true
			}
		}
		if !found {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("component %q has no endpoint %q", in.Component, in.Endpoint)}), diagnoseNetworkPathOutput{}, nil
		}

		destHost := in.Host
		if destHost == "" {
			destHost, err = diagnose.ResolveSingletonGroupHost(resolved, destComp.Role)
			if err != nil {
				return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("host is required for a non-singleton destination component: %v", err)}), diagnoseNetworkPathOutput{}, nil
			}
		} else if verr := diagnose.ValidateHost(resolved, destHost); verr != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrHostNotFound, Message: verr.Error()}), diagnoseNetworkPathOutput{}, nil
		}
		destAddr := resolved.HostAddr(destHost)
		if destAddr == "" {
			destAddr = destHost
		}

		readinessPath := ""
		if destComp.Diagnostics.Readiness.Endpoint == in.Endpoint {
			readinessPath = destComp.Diagnostics.Readiness.Path
		}

		sessionID, err := newID()
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnoseNetworkPathOutput{}, nil
		}
		start := time.Now()
		auditDir, err := prepareDiagnoseAuditDir(opts, "network_path", sessionID, start)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnoseNetworkPathOutput{}, nil
		}

		runner := opts.AdHocRunner
		if runner == nil {
			runner = realDiagnoseAdHocRunner()
		}
		steps := diagnose.NetworkPathSteps(destAddr, destEndpoint.Port, destEndpoint.Scheme, readinessPath)
		results := diagnose.RunSteps(ctx, runner, opts.Inventory, in.SourceHost, steps, opts.StepTimeout)

		reachable := true
		for _, r := range results {
			if r.Result.Unreachable {
				reachable = false
			}
		}
		hasTLS := destEndpoint.Scheme == "https"
		hasReadiness := readinessPath != ""
		pathOut := diagnose.BuildNetworkPathOutput(destAddr, destEndpoint.Port, destEndpoint.Scheme, hasTLS, hasReadiness, reachable, results)

		rec := diagnoseAuditRecord{
			SessionID: sessionID, Check: "network_path", PilotVersion: rootCmd.Version,
			GitRevision: gitRevision(filepath.Dir(opts.Inventory)), MCPClient: mcpClientString(req),
			Inventory: opts.Inventory, Host: in.SourceHost,
			Params: map[string]string{"component": in.Component, "endpoint": in.Endpoint, "dest_host": destHost},
			Start:  start, Finish: time.Now(), Steps: stepAuditList(results),
		}
		_ = writeDiagnoseAudit(auditDir, rec)

		out := diagnoseNetworkPathOutput{
			SourceHost: in.SourceHost, DestHost: destAddr, DestPort: destEndpoint.Port, Scheme: destEndpoint.Scheme,
			Layers: pathOut.Layers, Verdict: pathOut.Verdict, Steps: stepEvidenceList(results), AuditDirectory: auditDir,
		}
		return nil, out, nil
	}
}

// ---- pilot_diagnose_recent_changes ----------------------------------------

type diagnoseRecentChangesInput struct {
	Host      string `json:"host,omitempty" jsonschema:"optional: filter deploy-history records to this exact inventory host"`
	Component string `json:"component,omitempty" jsonschema:"optional: filter deploy-history records to this component"`
	Start     string `json:"start" jsonschema:"RFC3339 window start — the Agent Controller should pass [incident_start-lookback, incident_start], not [now-lookback, now]"`
	End       string `json:"end" jsonschema:"RFC3339 window end"`
	Limit     int    `json:"limit,omitempty" jsonschema:"maximum records returned, default 20"`
}

type diagnoseRecentChangesOutput struct {
	Records        []diagnoseChangeRecordJSON `json:"records"`
	AuditDirectory string                     `json:"audit_directory"`
}

type diagnoseChangeRecordJSON struct {
	ID                string   `json:"id"`
	Kind              string   `json:"kind"`
	StartedAt         string   `json:"started_at"`
	FinishedAt        string   `json:"finished_at,omitempty"`
	WorkspaceRevision string   `json:"workspace_revision,omitempty"`
	InventoryRef      string   `json:"inventory_ref,omitempty"`
	Hosts             []string `json:"hosts,omitempty"`
	Components        []string `json:"components,omitempty"`
	Result            string   `json:"result,omitempty"`
	AuditRef          string   `json:"audit_ref,omitempty"`
}

// storeDeployRunSource adapts *store.Store to changejournal.DeployRunSource
// — a trivial field-for-field conversion (internal/changejournal cannot
// import internal/store's full surface without risking an import cycle
// back through cmd/pilot/cmd, so it declares its own narrow mirror types).
type storeDeployRunSource struct{ s *store.Store }

func (a storeDeployRunSource) ListRuns(filter changejournal.DeployRunFilter) ([]changejournal.DeployRun, error) {
	runs, err := a.s.ListRuns(store.RunFilter{Limit: filter.Limit, Host: filter.Host, Component: filter.Component})
	if err != nil {
		return nil, err
	}
	out := make([]changejournal.DeployRun, len(runs))
	for i, r := range runs {
		out[i] = changejournal.DeployRun{
			RunID: r.RunID, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt, Outcome: r.Outcome,
			Component: r.Component, Components: r.Components, Inventory: r.Inventory, Hosts: r.Hosts,
		}
	}
	return out, nil
}

func diagnoseRecentChangesHandler(opts diagnoseMCPToolsOptions) mcp.ToolHandlerFor[diagnoseRecentChangesInput, diagnoseRecentChangesOutput] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in diagnoseRecentChangesInput) (*mcp.CallToolResult, diagnoseRecentChangesOutput, error) {
		startTime, err := time.Parse(time.RFC3339, in.Start)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("start: %v", err)}), diagnoseRecentChangesOutput{}, nil
		}
		endTime, err := time.Parse(time.RFC3339, in.End)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: fmt.Sprintf("end: %v", err)}), diagnoseRecentChangesOutput{}, nil
		}
		if !startTime.Before(endTime) {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: "start must be before end"}), diagnoseRecentChangesOutput{}, nil
		}
		limit := in.Limit
		if limit <= 0 {
			limit = 20
		}

		sessionID, err := newID()
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnoseRecentChangesOutput{}, nil
		}
		start := time.Now()
		auditDir, err := prepareDiagnoseAuditDir(opts, "recent_changes", sessionID, start)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnoseRecentChangesOutput{}, nil
		}

		var deploySource changejournal.DeployRunSource
		if st, openErr := openSpecStore(); openErr == nil {
			defer st.Close()
			deploySource = storeDeployRunSource{s: st}
		}

		window := changejournal.TimeWindow{Start: startTime, End: endTime}
		records, err := changejournal.QueryRecentChanges(deploySource, opts.AuditDir, in.Host, in.Component, window, limit)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), diagnoseRecentChangesOutput{}, nil
		}

		rec := diagnoseAuditRecord{
			SessionID: sessionID, Check: "recent_changes", PilotVersion: rootCmd.Version,
			GitRevision: gitRevision(filepath.Dir(opts.Inventory)), MCPClient: mcpClientString(req),
			Inventory: opts.Inventory, Host: in.Host,
			Params: map[string]string{"component": in.Component, "start": in.Start, "end": in.End},
			Start:  start, Finish: time.Now(),
		}
		_ = writeDiagnoseAudit(auditDir, rec)

		out := diagnoseRecentChangesOutput{AuditDirectory: auditDir}
		for _, r := range records {
			out.Records = append(out.Records, diagnoseChangeRecordJSON{
				ID: r.ID, Kind: string(r.Kind), StartedAt: r.StartedAt.Format(time.RFC3339),
				FinishedAt: formatIfNonZero(r.FinishedAt), WorkspaceRevision: r.WorkspaceRevision,
				InventoryRef: r.InventoryRef, Hosts: r.Hosts, Components: r.Components,
				Result: r.Result, AuditRef: r.AuditRef,
			})
		}
		return nil, out, nil
	}
}

func formatIfNonZero(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}
