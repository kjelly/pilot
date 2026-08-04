// mcp_edit_tools.go implements the three read-only MCP tools spec's
// Phase 3 exposes: pilot_edit_capabilities, pilot_edit_inspect,
// pilot_edit_plan. mcpAllowedActionNames is the single place that
// decides which editActionRegistry() entries MCP ever exposes —
// capabilities and plan both call it, so they can never disagree
// (Core Invariant #2's "唯一契約來源" requirement, applied at the MCP
// policy layer specifically).
package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kjelly/pilot/internal/groupvars"
	"github.com/kjelly/pilot/internal/inventory"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const editCapabilitiesSchemaVersion = 1

// castTerminalWidth/Height are session.cast metadata only — matching
// teatest's WithInitialTermSize(100, 30) convention already used
// throughout this package's tests. The automation path never depends
// on a real terminal size (selectModel/multiSelectModel fall back to a
// fixed window until a WindowSizeMsg arrives, which automation never
// sends), so these are just plausible display dimensions for a human
// or player replaying the cast.
const (
	castTerminalWidth  = 100
	castTerminalHeight = 30
)

// mcpVaultActionNames are editActionRegistry() entries MCP must never
// expose until Phase 5's secret-safe recording lands (see spec's
// "後續階段" section).
var mcpVaultActionNames = map[string]bool{
	"add_vault_key":    true,
	"set_vault_value":  true,
	"delete_vault_key": true,
	"save_vault":       true,
	"discard_vault":    true,
}

// mcpAllowedActionNames is which editActionRegistry() action names MCP
// currently exposes — everything except the vault actions above.
func mcpAllowedActionNames() map[string]bool {
	allowed := make(map[string]bool)
	for _, def := range editActionRegistry() {
		if mcpVaultActionNames[def.Spec.Name] {
			continue
		}
		allowed[def.Spec.Name] = true
	}
	return allowed
}

// validationSummary is the {blocking, warnings} shape both
// pilot_edit_inspect's "completeness" and pilot_edit_plan's
// "validation" fields use.
type validationSummary struct {
	Blocking []string `json:"blocking"`
	Warnings []string `json:"warnings"`
}

// editMCPToolsOptions is the canonicalized, server-lifetime config
// every tool handler closes over. None of the three tools takes a
// workspace path argument, so an MCP tool call can never redirect Dir
// or AuditDir — they're fixed once, at server startup (mcp.go).
type editMCPToolsOptions struct {
	Dir          string
	AuditDir     string
	WriteEnabled bool
}

// registerEditTools adds the read-only tools to server, plus
// pilot_edit_apply only when opts.WriteEnabled — a read-only server
// (no --allow-write) never even lists a mutation tool, rather than
// listing one that always errors, matching spec's "Read-only default"
// section.
func registerEditTools(server *mcp.Server, opts editMCPToolsOptions) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "pilot_edit_capabilities",
		Description: "list the semantic edit actions this MCP server currently allows, reflecting real server policy (not just the global action registry)",
	}, capabilitiesHandler(opts))
	mcp.AddTool(server, &mcp.Tool{
		Name:        "pilot_edit_inspect",
		Description: "read the workspace's non-secret configuration summary an agent needs to plan semantic actions",
	}, inspectHandler(opts))
	mcp.AddTool(server, &mcp.Tool{
		Name:        "pilot_edit_plan",
		Description: "validate and rehearse a semantic action scenario against a temporary copy of the workspace, through the real pilot edit TUI, without touching the real workspace",
	}, planHandler(opts))
	if opts.WriteEnabled {
		mcp.AddTool(server, &mcp.Tool{
			Name:        "pilot_edit_apply",
			Description: "apply a previously-created plan's exact scenario to the real workspace through the real pilot edit TUI, under a mutation lock with automatic rollback on failure",
		}, applyHandler(opts))
	}
}

// ---- pilot_edit_capabilities ------------------------------------------------

type capabilitiesInput struct{}

type capabilitiesOutput struct {
	SchemaVersion int                  `json:"schema_version"`
	Workspace     string               `json:"workspace"`
	WriteEnabled  bool                 `json:"write_enabled"`
	Actions       []semanticActionSpec `json:"actions"`
	Unsupported   map[string]string    `json:"unsupported"`
}

func capabilitiesHandler(opts editMCPToolsOptions) mcp.ToolHandlerFor[capabilitiesInput, capabilitiesOutput] {
	return func(_ context.Context, _ *mcp.CallToolRequest, _ capabilitiesInput) (*mcp.CallToolResult, capabilitiesOutput, error) {
		allowed := mcpAllowedActionNames()
		var actions []semanticActionSpec
		for _, def := range editActionRegistry() {
			if allowed[def.Spec.Name] {
				actions = append(actions, def.Spec)
			}
		}
		unsupported := map[string]string{"deploy": "not part of pilot edit MCP"}
		for name := range mcpVaultActionNames {
			unsupported[name] = "secret-safe recording is not enabled"
		}
		out := capabilitiesOutput{
			SchemaVersion: editCapabilitiesSchemaVersion,
			Workspace:     opts.Dir,
			WriteEnabled:  opts.WriteEnabled,
			Actions:       actions,
			Unsupported:   unsupported,
		}
		return nil, out, nil
	}
}

// ---- pilot_edit_inspect ------------------------------------------------

type inspectInput struct {
	IncludeGroupVars     bool `json:"include_group_vars"`
	IncludeVaultMetadata bool `json:"include_vault_metadata"`
}

type inspectHost struct {
	Name        string   `json:"name"`
	AnsibleHost string   `json:"ansible_host,omitempty"`
	AnsibleUser string   `json:"ansible_user,omitempty"`
	Env         string   `json:"env,omitempty"`
	Roles       []string `json:"roles,omitempty"`
}

type inspectRolePreset struct {
	Label string   `json:"label"`
	Roles []string `json:"roles"`
}

type inspectOutput struct {
	WorkspaceRevision string                       `json:"workspace_revision"`
	Hosts             []inspectHost                `json:"hosts"`
	RolePresets       []inspectRolePreset          `json:"role_presets"`
	GroupVars         map[string]map[string]string `json:"group_vars,omitempty"`
	Completeness      validationSummary            `json:"completeness"`
}

func inspectHandler(opts editMCPToolsOptions) mcp.ToolHandlerFor[inspectInput, inspectOutput] {
	return func(_ context.Context, _ *mcp.CallToolRequest, in inspectInput) (*mcp.CallToolResult, inspectOutput, error) {
		revision, err := computeWorkspaceRevision(opts.Dir)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidScenario, Message: err.Error()}), inspectOutput{}, nil
		}

		var hosts []inspectHost
		if data, err := os.ReadFile(filepath.Join(opts.Dir, "hosts.yml")); err == nil {
			if hf, err := inventory.Parse(data); err == nil {
				for _, h := range hf.Hosts {
					hosts = append(hosts, inspectHost{
						Name:        h.Name,
						AnsibleHost: h.AnsibleHost,
						AnsibleUser: h.AnsibleUser,
						Env:         h.Env,
						Roles:       h.Roles,
					})
				}
			}
		}

		var presets []inspectRolePreset
		if loaded, _, err := loadRolePresets(opts.Dir); err == nil {
			for _, p := range loaded {
				presets = append(presets, inspectRolePreset{Label: p.Label, Roles: p.Roles})
			}
		}

		var groupVars map[string]map[string]string
		if in.IncludeGroupVars {
			groupVars = map[string]map[string]string{}
			entries, err := managedFileEntries(opts.Dir)
			if err == nil {
				for _, e := range entries {
					if filepath.Dir(e.RelPath) != "group_vars" {
						continue
					}
					values := map[string]string{}
					for _, entry := range groupvars.Parse(e.Content).Entries() {
						if entry.Active {
							values[entry.Key] = entry.Value
						}
					}
					groupVars[filepath.Base(e.RelPath)] = values
				}
			}
		}

		var blocking []string
		for _, c := range checkWorkspaceCompleteness(opts.Dir) {
			if c.OK {
				continue
			}
			for _, d := range c.Details {
				blocking = append(blocking, fmt.Sprintf("%s: %s", c.Label, d))
			}
		}

		out := inspectOutput{
			WorkspaceRevision: revision,
			Hosts:             hosts,
			RolePresets:       presets,
			GroupVars:         groupVars,
			Completeness:      validationSummary{Blocking: blocking},
		}
		return nil, out, nil
	}
}

// ---- pilot_edit_plan ------------------------------------------------

type planInput struct {
	BaseRevision string       `json:"base_revision"`
	Scenario     editScenario `json:"scenario"`
}

type planOutput struct {
	PlanID        string            `json:"plan_id"`
	BaseRevision  string            `json:"base_revision"`
	ScenarioHash  string            `json:"scenario_hash"`
	Valid         bool              `json:"valid"`
	AffectedFiles []string          `json:"affected_files"`
	Diff          string            `json:"diff"`
	Validation    validationSummary `json:"validation"`
	Audit         auditRefs         `json:"audit"`
}

func planHandler(opts editMCPToolsOptions) mcp.ToolHandlerFor[planInput, planOutput] {
	return func(_ context.Context, req *mcp.CallToolRequest, in planInput) (*mcp.CallToolResult, planOutput, error) {
		allowed := mcpAllowedActionNames()
		for i, step := range in.Scenario.Steps {
			if !allowed[step.Action] {
				return toolErrorResult(mcpToolError{
					Code:    mcpErrUnsupportedAction,
					Message: fmt.Sprintf("action %q is not exposed by this MCP server", step.Action),
					Step:    i + 1,
					Action:  step.Action,
				}), planOutput{}, nil
			}
		}

		currentRevision, err := computeWorkspaceRevision(opts.Dir)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidScenario, Message: err.Error()}), planOutput{}, nil
		}
		if in.BaseRevision == "" || in.BaseRevision != currentRevision {
			return toolErrorResult(mcpToolError{
				Code:    mcpErrWorkspaceChanged,
				Message: fmt.Sprintf("workspace revision is %s, base_revision was %q", currentRevision, in.BaseRevision),
			}), planOutput{}, nil
		}

		scenarioHash, err := computeScenarioHash(in.Scenario)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidScenario, Message: err.Error()}), planOutput{}, nil
		}
		planID, err := newID()
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), planOutput{}, nil
		}

		start := time.Now()
		auditDir := filepath.Join(opts.AuditDir, fmt.Sprintf("%s-%s-plan", start.UTC().Format("20060102T150405Z"), planID))
		if err := os.MkdirAll(auditDir, 0o755); err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), planOutput{}, nil
		}

		castFile, err := os.Create(filepath.Join(auditDir, "session.cast"))
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), planOutput{}, nil
		}
		defer castFile.Close()
		recorder, err := newCastAuditRecorder(castFile, in.Scenario.Title, castTerminalWidth, castTerminalHeight)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), planOutput{}, nil
		}

		sink, err := newAutomationTraceSink(filepath.Join(auditDir, "trace.jsonl"))
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), planOutput{}, nil
		}
		defer func() { _ = sink.close() }()

		sessionOpts := editAgentSessionOptions{
			Trace:    func(event automationTraceEvent) { sink.add(event) },
			Recorder: recorder,
		}
		result, err := planEditScenario(opts.Dir, in.Scenario, sessionOpts)

		meta := auditMetadata{
			SessionID:         planID,
			Kind:              "plan",
			PilotVersion:      rootCmd.Version,
			GitRevision:       gitRevision(opts.Dir),
			Workspace:         opts.Dir,
			Start:             start,
			Finish:            time.Now(),
			ScenarioHash:      scenarioHash,
			WorkspaceRevision: currentRevision,
			Width:             castTerminalWidth,
			Height:            castTerminalHeight,
			Recorder:          "session.cast",
		}
		if client := req.ClientInfo(); client != nil {
			meta.MCPClient = fmt.Sprintf("%s/%s", client.Name, client.Version)
		}

		if err != nil {
			_ = writeJSONFile(filepath.Join(auditDir, "metadata.json"), meta)
			return toolErrorResult(mcpToolError{
				Code:           mcpErrInvalidScenario,
				Message:        err.Error(),
				AuditDirectory: auditDir,
			}), planOutput{}, nil
		}

		if err := writePlanAuditArtifacts(auditDir, meta, in.Scenario, result); err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error(), AuditDirectory: auditDir}), planOutput{}, nil
		}

		out := planOutput{
			PlanID:        planID,
			BaseRevision:  result.BaseRevision,
			ScenarioHash:  scenarioHash,
			Valid:         len(result.Blocking) == 0,
			AffectedFiles: result.AffectedFiles,
			Diff:          result.Diff,
			Validation:    validationSummary{Blocking: result.Blocking, Warnings: result.Warnings},
			Audit: auditRefs{
				Directory: auditDir,
				Recording: "session.cast",
				Trace:     "trace.jsonl",
				Diff:      "diff.patch",
			},
		}
		return nil, out, nil
	}
}

// ---- pilot_edit_apply ------------------------------------------------

type applyInput struct {
	PlanID           string `json:"plan_id"`
	ExpectedRevision string `json:"expected_revision"`
}

type applyOutput struct {
	SessionID      string            `json:"session_id"`
	PlanID         string            `json:"plan_id"`
	Result         string            `json:"result"` // "applied" (only value on the non-error path)
	RevisionBefore string            `json:"revision_before"`
	RevisionAfter  string            `json:"revision_after"`
	AffectedFiles  []string          `json:"affected_files"`
	Validation     validationSummary `json:"validation"`
	RolledBack     bool              `json:"rolled_back"`
	Audit          auditRefs         `json:"audit"`
}

// findPlanDirectory locates plan_id's audit directory — plan directories
// are named "<timestamp>-<plan_id>-plan", and there's no separate
// lookup index for a single-field reverse lookup by suffix. The two
// failure modes (zero matches vs. more than one) map to different MCP
// error codes, so the caller gets matches back rather than a single
// collapsed error.
func findPlanDirectory(auditRoot, planID string) (matches []string, err error) {
	return filepath.Glob(filepath.Join(auditRoot, "*-"+planID+"-plan"))
}

func applyHandler(opts editMCPToolsOptions) mcp.ToolHandlerFor[applyInput, applyOutput] {
	return func(_ context.Context, req *mcp.CallToolRequest, in applyInput) (*mcp.CallToolResult, applyOutput, error) {
		if !opts.WriteEnabled {
			return toolErrorResult(mcpToolError{Code: mcpErrWriteDisabled, Message: "server was not started with --allow-write"}), applyOutput{}, nil
		}

		matches, err := findPlanDirectory(opts.AuditDir, in.PlanID)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrTargetNotFound, Message: err.Error()}), applyOutput{}, nil
		}
		if len(matches) == 0 {
			return toolErrorResult(mcpToolError{Code: mcpErrTargetNotFound, Message: fmt.Sprintf("no plan found for plan_id %q", in.PlanID)}), applyOutput{}, nil
		}
		if len(matches) > 1 {
			return toolErrorResult(mcpToolError{Code: mcpErrAmbiguousTarget, Message: fmt.Sprintf("plan_id %q matches multiple audit directories: %v", in.PlanID, matches)}), applyOutput{}, nil
		}
		planDir := matches[0]

		metaData, err := os.ReadFile(filepath.Join(planDir, "metadata.json"))
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrTargetNotFound, Message: fmt.Sprintf("read plan metadata: %v", err)}), applyOutput{}, nil
		}
		var planMeta auditMetadata
		if err := json.Unmarshal(metaData, &planMeta); err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrTargetNotFound, Message: fmt.Sprintf("parse plan metadata: %v", err)}), applyOutput{}, nil
		}

		scenarioData, err := os.ReadFile(filepath.Join(planDir, "scenario.redacted.json"))
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrTargetNotFound, Message: fmt.Sprintf("read plan scenario: %v", err)}), applyOutput{}, nil
		}
		var scenario editScenario
		if err := json.Unmarshal(scenarioData, &scenario); err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrTargetNotFound, Message: fmt.Sprintf("parse plan scenario: %v", err)}), applyOutput{}, nil
		}

		currentRevision, err := computeWorkspaceRevision(opts.Dir)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidScenario, Message: err.Error()}), applyOutput{}, nil
		}
		if currentRevision != planMeta.WorkspaceRevision || currentRevision != in.ExpectedRevision {
			return toolErrorResult(mcpToolError{
				Code:    mcpErrWorkspaceChanged,
				Message: fmt.Sprintf("workspace revision is %s; plan's base_revision was %s, request's expected_revision was %q", currentRevision, planMeta.WorkspaceRevision, in.ExpectedRevision),
			}), applyOutput{}, nil
		}

		sessionID, err := newID()
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), applyOutput{}, nil
		}
		start := time.Now()
		auditDir := filepath.Join(opts.AuditDir, fmt.Sprintf("%s-%s-apply", start.UTC().Format("20060102T150405Z"), sessionID))
		if err := os.MkdirAll(auditDir, 0o755); err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), applyOutput{}, nil
		}

		castFile, err := os.Create(filepath.Join(auditDir, "session.cast"))
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), applyOutput{}, nil
		}
		defer castFile.Close()
		recorder, err := newCastAuditRecorder(castFile, scenario.Title, castTerminalWidth, castTerminalHeight)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), applyOutput{}, nil
		}

		sink, err := newAutomationTraceSink(filepath.Join(auditDir, "trace.jsonl"))
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error()}), applyOutput{}, nil
		}
		defer func() { _ = sink.close() }()

		sessionOpts := editAgentSessionOptions{
			Trace:    func(event automationTraceEvent) { sink.add(event) },
			Recorder: recorder,
		}
		result, err := applyEditScenario(opts.Dir, sessionID, scenario, sessionOpts)

		meta := auditMetadata{
			SessionID:         sessionID,
			Kind:              "apply",
			PilotVersion:      rootCmd.Version,
			GitRevision:       gitRevision(opts.Dir),
			Workspace:         opts.Dir,
			Start:             start,
			Finish:            time.Now(),
			ScenarioHash:      planMeta.ScenarioHash,
			WorkspaceRevision: currentRevision,
			Width:             castTerminalWidth,
			Height:            castTerminalHeight,
			Recorder:          "session.cast",
		}
		if client := req.ClientInfo(); client != nil {
			meta.MCPClient = fmt.Sprintf("%s/%s", client.Name, client.Version)
		}

		if err != nil {
			_ = writeJSONFile(filepath.Join(auditDir, "metadata.json"), meta)
			if errors.Is(err, errWorkspaceLocked) {
				return toolErrorResult(mcpToolError{Code: mcpErrWorkspaceLocked, Message: err.Error(), AuditDirectory: auditDir}), applyOutput{}, nil
			}
			return toolErrorResult(mcpToolError{Code: mcpErrRollbackFailed, Message: err.Error(), AuditDirectory: auditDir}), applyOutput{}, nil
		}

		if err := writeApplyAuditArtifacts(auditDir, meta, scenario, result); err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrRecordingFailed, Message: err.Error(), AuditDirectory: auditDir}), applyOutput{}, nil
		}

		if result.RolledBack {
			return toolErrorResult(mcpToolError{
				Code:           mcpErrApplyFailed,
				Message:        result.ScenarioErr.Error(),
				RolledBack:     true,
				AuditDirectory: auditDir,
			}), applyOutput{}, nil
		}

		out := applyOutput{
			SessionID:      sessionID,
			PlanID:         in.PlanID,
			Result:         "applied",
			RevisionBefore: result.RevisionBefore,
			RevisionAfter:  result.RevisionAfter,
			AffectedFiles:  result.AffectedFiles,
			Validation:     validationSummary{Blocking: result.Blocking, Warnings: result.Warnings},
			RolledBack:     false,
			Audit: auditRefs{
				Directory: auditDir,
				Recording: "session.cast",
				Trace:     "trace.jsonl",
				Diff:      "diff.patch",
			},
		}
		return nil, out, nil
	}
}
