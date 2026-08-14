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

	"gopkg.in/yaml.v3"

	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/vaultfile"
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

// mcpSecretActionNames are editActionRegistry() entries that carry a
// secret value — exposed via MCP as of Phase 5 (vault) and Phase 6
// increment 2 (roster password), but only under the value_env-only
// policy validateNoLiteralSecretValues enforces, and with their
// advertised capabilities schema tightened (capabilitiesHandler) to
// drop the literal "value" field entirely. add_ssh_key/delete_ssh_key
// are deliberately NOT here: ssh_keys.values are public keys, not
// secrets, and the interactive TUI itself never masks them.
var mcpSecretActionNames = map[string]bool{
	"add_vault_key":     true,
	"set_vault_value":   true,
	"delete_vault_key":  true,
	"save_vault":        true,
	"discard_vault":     true,
	"set_user_password": true,
}

// mcpAllowedActionNames is which editActionRegistry() action names MCP
// currently exposes — every registered action, including the secret
// ones (Phase 5/6); mcpAllowedActionNames alone doesn't enforce the
// value_env-only rule, see validateNoLiteralSecretValues.
func mcpAllowedActionNames() map[string]bool {
	allowed := make(map[string]bool)
	for _, def := range editActionRegistry() {
		allowed[def.Spec.Name] = true
	}
	return allowed
}

// validateNoLiteralSecretValues rejects any scenario step targeting a
// secret action that carries a literal Value — MCP callers must use
// ValueEnv (an environment variable *name*) exclusively for secret
// content, per spec's "MCP arguments" section. Called before any temp
// copy (plan) or real mutation (apply) is attempted, so a rejected
// scenario never gets far enough to type a literal secret into the
// router at all.
func validateNoLiteralSecretValues(scenario editScenario) error {
	for i, step := range scenario.Steps {
		if !mcpSecretActionNames[step.Action] {
			continue
		}
		if step.Value != "" {
			return mcpToolError{
				Code:    mcpErrSecretPolicyViolation,
				Message: fmt.Sprintf("action %q must use value_env, not a literal value", step.Action),
				Step:    i + 1,
				Action:  step.Action,
			}
		}
	}
	return nil
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
		Description: "list the semantic *edit* (mutation) actions this MCP server currently allows, reflecting real server policy (not just the global action registry); read-only queries are served by pilot_edit_inspect, not by an action here",
	}, capabilitiesHandler(opts))
	mcp.AddTool(server, &mcp.Tool{
		Name:        "pilot_edit_inspect",
		Description: "read-only query over the workspace's non-secret configuration: inventory hosts (name/IP/roles), role presets, and — via opt-in flags — group_vars, vault metadata, the FreeIPA roster (users, groups, hostgroups, HBAC rules, sudo rules, plus server-resolved effective_hbac_access/effective_sudo_access that answer \"which users can log in to / run sudo on which hosts\" with nested group membership already expanded), and DNS zones/records with resolved IPs, and internal-endpoint manifest entries (dns/route/tls) with resolved IPs",
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
	registerEditResources(server, opts)
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

// mcpValueOnlyOptionalFields is the Optional field list capabilities
// advertises for a vault action whose registry Spec allows a literal
// "value" — MCP's real contract only accepts value_env
// (validateNoLiteralSecretValues), so the advertised schema is
// tightened to match rather than echoing the more-permissive global
// registry, per Core Invariant #1.
var mcpValueOnlyOptionalFields = []string{"value_env"}

func capabilitiesHandler(opts editMCPToolsOptions) mcp.ToolHandlerFor[capabilitiesInput, capabilitiesOutput] {
	return func(_ context.Context, _ *mcp.CallToolRequest, _ capabilitiesInput) (*mcp.CallToolResult, capabilitiesOutput, error) {
		allowed := mcpAllowedActionNames()
		var actions []semanticActionSpec
		for _, def := range editActionRegistry() {
			if !allowed[def.Spec.Name] {
				continue
			}
			spec := def.Spec
			if mcpSecretActionNames[spec.Name] && len(spec.Optional) > 0 {
				spec.Optional = mcpValueOnlyOptionalFields
				spec.Description += " (MCP requires value_env; a literal value is rejected)"
			}
			actions = append(actions, spec)
		}
		unsupported := map[string]string{
			"deploy": "not part of pilot edit MCP",
			// Every action here mutates; agents looking for a query/list
			// action land on this map, so point them at the actual read path.
			"query": "read-only queries (hosts, roster users/groups/HBAC/sudo, effective access, DNS) are served by the pilot_edit_inspect tool or the pilot:// resources, not a semantic action",
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

// inspectInput's flags are all opt-in extras, so every field carries
// ,omitempty — without it the SDK's inferred input schema marks each
// one required, and a client sending only {"include_roster": true}
// gets rejected with "missing properties" instead of a result.
type inspectInput struct {
	IncludeGroupVars         bool `json:"include_group_vars,omitempty" jsonschema:"also return each group_vars/*.yml file's top-level keys and values"`
	IncludeVaultMetadata     bool `json:"include_vault_metadata,omitempty" jsonschema:"also return .vault/ file metadata (filename, encrypted, key names — never key values)"`
	IncludeRoster            bool `json:"include_roster,omitempty" jsonschema:"also return the FreeIPA roster: users, groups, hostgroups, HBAC rules, sudo command groups and rules, plus effective_hbac_access/effective_sudo_access — per-rule lists of concrete usernames and host FQDNs with nested group/hostgroup membership already expanded, answering 'which users can log in to / run sudo on which hosts'"`
	IncludeDNS               bool `json:"include_dns,omitempty" jsonschema:"also return FreeIPA DNS zones and records, each record's target_host cross-resolved to its inventory IP (resolved_ip)"`
	IncludeInternalEndpoints bool `json:"include_internal_endpoints,omitempty" jsonschema:"also return internal-endpoint manifest entries (dns/route/tls), every inventory_host reference cross-resolved to its inventory IP (resolved_ip)"`
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

// inspectVaultFile is a .vault/ file's metadata — filename, whether
// it's ansible-vault encrypted, and (for a plaintext skeleton only)
// its key *names*. Never Key values — see spec's "MCP 可讀但不可修改"
// vault scope ("filename、是否加密及 key name metadata").
type inspectVaultFile struct {
	Filename  string   `json:"filename"`
	Encrypted bool     `json:"encrypted"`
	Keys      []string `json:"keys,omitempty"`
}

// inspectRosterUser is one FreeIPA roster user's non-secret fields —
// Phase 6 increment 1 scope (users only). Never password.initial,
// never ssh_keys.values.
type inspectRosterUser struct {
	Name        string `json:"name"`
	State       string `json:"state"`
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	UID         *int   `json:"uid,omitempty"`
	GID         *int   `json:"gid,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// inspectRosterGroup is one roster group's fields plus its *direct*
// (non-transitive) membership references. See EffectiveHBACAccess/
// EffectiveSudoAccess in internal/inventory for the transitively-resolved
// view — a group's membership.groups can itself list other groups, so the
// direct list here does not by itself answer "who is really in this group".
type inspectRosterGroup struct {
	Name         string   `json:"name"`
	State        string   `json:"state"`
	Category     string   `json:"category,omitempty"`
	Type         string   `json:"type,omitempty"`
	Description  string   `json:"description,omitempty"`
	MemberUsers  []string `json:"member_users,omitempty"`
	MemberGroups []string `json:"member_groups,omitempty"`
}

// inspectRosterHostgroup is inspectRosterGroup's hostgroup counterpart —
// membership.hostgroups can itself nest further hostgroups.
type inspectRosterHostgroup struct {
	Name             string   `json:"name"`
	State            string   `json:"state"`
	Description      string   `json:"description,omitempty"`
	MemberHosts      []string `json:"member_hosts,omitempty"`
	MemberHostgroups []string `json:"member_hostgroups,omitempty"`
}

// inspectHBACRule is one HBAC rule's raw (non-expanded) fields — see
// inspectOutput.EffectiveHBACAccess for the resolved view a caller should
// use to answer "can user X reach host Y" without re-walking
// subject/target group nesting itself.
type inspectHBACRule struct {
	Name             string   `json:"name"`
	State            string   `json:"state"`
	Enabled          bool     `json:"enabled"`
	SubjectUsers     []string `json:"subject_users,omitempty"`
	SubjectGroups    []string `json:"subject_groups,omitempty"`
	AllHosts         bool     `json:"all_hosts"`
	TargetHosts      []string `json:"target_hosts,omitempty"`
	TargetHostgroups []string `json:"target_hostgroups,omitempty"`
	Services         []string `json:"services,omitempty"`
}

type inspectSudoCommandGroup struct {
	Name     string   `json:"name"`
	Commands []string `json:"commands,omitempty"`
}

// inspectSudoRule mirrors inspectHBACRule — see
// inspectOutput.EffectiveSudoAccess for the resolved view.
type inspectSudoRule struct {
	Name               string   `json:"name"`
	State              string   `json:"state"`
	SubjectUsers       []string `json:"subject_users,omitempty"`
	SubjectGroups      []string `json:"subject_groups,omitempty"`
	AllHosts           bool     `json:"all_hosts"`
	TargetHosts        []string `json:"target_hosts,omitempty"`
	TargetHostgroups   []string `json:"target_hostgroups,omitempty"`
	AllCommands        bool     `json:"all_commands"`
	AllowCommands      []string `json:"allow_commands,omitempty"`
	AllowCommandGroups []string `json:"allow_command_groups,omitempty"`
	DenyCommandGroups  []string `json:"deny_command_groups,omitempty"`
}

// inspectDNSRecord's ResolvedIP cross-references TargetHost against
// inspectOutput.Hosts (the ansible inventory, always populated) so a
// caller never needs a second lookup to turn a service name into an IP.
// It is left empty when TargetHost doesn't match a known inventory host,
// or when the record uses explicit Values instead of a target host.
type inspectDNSRecord struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	State      string   `json:"state"`
	TTL        int      `json:"ttl,omitempty"`
	Values     []string `json:"values,omitempty"`
	TargetHost string   `json:"target_host,omitempty"`
	ResolvedIP string   `json:"resolved_ip,omitempty"`
}

type inspectDNSZone struct {
	Name                    string             `json:"name"`
	State                   string             `json:"state"`
	RecordsMode             string             `json:"records_mode,omitempty"`
	AcknowledgeSplitHorizon bool               `json:"acknowledge_split_horizon,omitempty"`
	Records                 []inspectDNSRecord `json:"records,omitempty"`
}

type inspectOutput struct {
	WorkspaceRevision   string                          `json:"workspace_revision"`
	Hosts               []inspectHost                   `json:"hosts"`
	RolePresets         []inspectRolePreset             `json:"role_presets"`
	GroupVars           map[string]map[string]string    `json:"group_vars,omitempty"`
	VaultFiles          []inspectVaultFile              `json:"vault_files,omitempty"`
	RosterUsers         []inspectRosterUser             `json:"roster_users,omitempty"`
	RosterGroups        []inspectRosterGroup            `json:"roster_groups,omitempty"`
	RosterHostgroups    []inspectRosterHostgroup        `json:"roster_hostgroups,omitempty"`
	HBACRules           []inspectHBACRule               `json:"hbac_rules,omitempty"`
	SudoCommandGroups   []inspectSudoCommandGroup       `json:"sudo_command_groups,omitempty"`
	SudoRules           []inspectSudoRule               `json:"sudo_rules,omitempty"`
	EffectiveHBACAccess []inventory.EffectiveHBACAccess `json:"effective_hbac_access,omitempty"`
	EffectiveSudoAccess []inventory.EffectiveSudoAccess `json:"effective_sudo_access,omitempty"`
	DNSZones            []inspectDNSZone                `json:"dns_zones,omitempty"`
	InternalEndpoints   []inspectInternalEndpoint       `json:"internal_endpoints,omitempty"`
	Completeness        validationSummary               `json:"completeness"`
}

// looksLikeRosterFile distinguishes the roster file from other
// .vault/*.yml(.yaml) files (e.g. main.yaml's ipa_admin_password) by
// the presence of a top-level "users" key — the roster's own schema
// always declares one (possibly empty), and nothing else under .vault/
// does.
func looksLikeRosterFile(content []byte) bool {
	var root map[string]any
	if err := yaml.Unmarshal(content, &root); err != nil {
		return false
	}
	_, ok := root["users"]
	return ok
}

func rosterBoolFieldOr(fields map[string]any, key string, def bool) bool {
	if b, ok := fields[key].(bool); ok {
		return b
	}
	return def
}

func inspectHandler(opts editMCPToolsOptions) mcp.ToolHandlerFor[inspectInput, inspectOutput] {
	return func(_ context.Context, _ *mcp.CallToolRequest, in inspectInput) (*mcp.CallToolResult, inspectOutput, error) {
		revision, err := computeWorkspaceRevision(opts.Dir)
		if err != nil {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidScenario, Message: err.Error()}), inspectOutput{}, nil
		}

		hosts := buildInspectHosts(opts.Dir)

		var presets []inspectRolePreset
		if loaded, _, err := loadRolePresets(opts.Dir); err == nil {
			for _, p := range loaded {
				presets = append(presets, inspectRolePreset{Label: p.Label, Roles: p.Roles})
			}
		}

		var groupVars map[string]map[string]string
		if in.IncludeGroupVars {
			groupVars = buildInspectGroupVars(opts.Dir)
		}

		var vaultFiles []inspectVaultFile
		if in.IncludeVaultMetadata {
			entries, err := managedFileEntries(opts.Dir)
			if err == nil {
				for _, e := range entries {
					if !e.IsSecret {
						continue
					}
					vf := inspectVaultFile{Filename: filepath.Base(e.RelPath), Encrypted: isAnsibleVaultEncrypted(e.Content)}
					if !vf.Encrypted {
						if doc, err := vaultfile.Parse(e.Content); err == nil {
							for _, entry := range doc.Entries() {
								vf.Keys = append(vf.Keys, entry.Key)
							}
						}
					}
					vaultFiles = append(vaultFiles, vf)
				}
			}
		}

		var roster inspectRosterData
		if in.IncludeRoster {
			roster = buildInspectRoster(opts.Dir)
		}

		var dnsZones []inspectDNSZone
		if in.IncludeDNS {
			dnsZones = buildInspectDNSZones(opts.Dir, hosts)
		}

		var internalEndpoints []inspectInternalEndpoint
		if in.IncludeInternalEndpoints {
			internalEndpoints = buildInspectInternalEndpoints(opts.Dir, hosts)
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
			WorkspaceRevision:   revision,
			Hosts:               hosts,
			RolePresets:         presets,
			GroupVars:           groupVars,
			VaultFiles:          vaultFiles,
			RosterUsers:         roster.Users,
			RosterGroups:        roster.Groups,
			RosterHostgroups:    roster.Hostgroups,
			HBACRules:           roster.HBACRules,
			SudoCommandGroups:   roster.SudoCommandGroups,
			SudoRules:           roster.SudoRules,
			EffectiveHBACAccess: roster.EffectiveHBACAccess,
			EffectiveSudoAccess: roster.EffectiveSudoAccess,
			DNSZones:            dnsZones,
			InternalEndpoints:   internalEndpoints,
			Completeness:        validationSummary{Blocking: blocking},
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
	RedactedDiff  bool              `json:"redacted_diff"`
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
		if err := validateNoLiteralSecretValues(in.Scenario); err != nil {
			return toolErrorResult(err.(mcpToolError)), planOutput{}, nil
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
			RedactedDiff:  result.RedactedDiff,
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
	RedactedDiff   bool              `json:"redacted_diff"`
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
		if err := validateNoLiteralSecretValues(scenario); err != nil {
			// Defense-in-depth: scenario.redacted.json should already have
			// Value cleared for vault steps (redactScenarioForAudit ran when
			// the plan was written) — this only fires if that ever regresses
			// or a plan directory was tampered with.
			return toolErrorResult(err.(mcpToolError)), applyOutput{}, nil
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
			RedactedDiff:   result.RedactedDiff,
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
