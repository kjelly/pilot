package cmd

import "strings"

// promptDefinition is the stable automation contract for one deploy/reconcile
// decision. Label text is intentionally absent: it is UI-only and may be
// localized without changing an agent's scenario.
type promptDefinition struct {
	ID             string   `json:"id"`
	Kind           string   `json:"kind"`
	Requirement    string   `json:"requirement"` // always or conditional
	Default        any      `json:"default"`
	AcceptedValues []string `json:"accepted_values,omitempty"`
	IDPattern      string   `json:"id_pattern,omitempty"`
}

type promptWorkflowSchema struct {
	Version int                `json:"version"`
	Prompts []promptDefinition `json:"prompts"`
}

const (
	promptInventory                  = "inventory"
	promptTopologyPreview            = "topology_preview"
	promptPreflight                  = "preflight"
	promptScope                      = "scope"
	promptComponent                  = "component"
	promptInfraRole                  = "infra_role"
	promptTargetGroup                = "target_group"
	promptStage                      = "stage"
	promptStageConfirmStaging        = "stage.confirm_staging"
	promptStageAttestationHours      = "stage.staging_attestation_hours"
	promptStageConfirmProd           = "stage.confirm_prod"
	promptLimit                      = "limit"
	promptTags                       = "tags"
	promptVaultUseDefault            = "vault.use_default"
	promptVaultNeedFile              = "vault.need_file"
	promptVaultFile                  = "vault.file"
	promptVaultDecryptMethod         = "vault.decrypt_method"
	promptVaultPasswordFile          = "vault.password_file"
	promptBecomePassword             = "become_password"
	promptExtraVars                  = "extra_vars"
	promptExecutionPreview           = "execution.preview"
	promptExecutionConfirmPreview    = "execution.confirm_preview"
	promptExecutionApplyAfterPreview = "execution.apply_after_preview"
	promptExecutionConfirmApply      = "execution.confirm_apply"
	promptS3AccessMode               = "s3.access_mode"
	promptS3ConfigPath               = "s3.config_path"
)

func promptSchemaFor(action string) promptWorkflowSchema {
	prompts := []promptDefinition{
		{ID: promptInventory, Kind: "text", Requirement: "always", Default: "inventory.yml"},
		{ID: promptTopologyPreview, Kind: "confirm", Requirement: "always", Default: true},
		{ID: promptPreflight, Kind: "select", Requirement: "always", Default: "full", AcceptedValues: []string{"full", "static", "skip"}},
		{ID: "preflight.continue_after_failure", Kind: "confirm", Requirement: "conditional", Default: false},
		{ID: promptComponent, Kind: "select", Requirement: "conditional", AcceptedValues: deployComponentIDs(action)},
		{ID: promptInfraRole, Kind: "select", Requirement: "conditional"},
		{ID: promptTargetGroup, Kind: "text", Requirement: "conditional", Default: ""},
		{ID: "target_host", Kind: "select", Requirement: "conditional"},
		{ID: promptStage, Kind: "select", Requirement: "always", Default: "sandbox", AcceptedValues: []string{"sandbox", "staging", "prod"}},
		{ID: promptStageConfirmStaging, Kind: "confirm", Requirement: "conditional", Default: false},
		{ID: promptStageAttestationHours, Kind: "text", Requirement: "conditional", Default: "24"},
		{ID: promptStageConfirmProd, Kind: "text", Requirement: "conditional"},
		{ID: promptLimit, Kind: "text", Requirement: "always", Default: ""},
		{ID: promptTags, Kind: "text", Requirement: "always", Default: ""},
		{ID: promptVaultUseDefault, Kind: "confirm", Requirement: "conditional", Default: true},
		{ID: promptVaultNeedFile, Kind: "select", Requirement: "conditional", Default: "none", AcceptedValues: []string{"none", "file"}},
		{ID: promptVaultFile, Kind: "text", Requirement: "conditional"},
		{ID: promptVaultDecryptMethod, Kind: "select", Requirement: "conditional", AcceptedValues: []string{"password_file", "ask"}},
		{ID: promptVaultPasswordFile, Kind: "text", Requirement: "conditional"},
		{ID: promptBecomePassword, Kind: "confirm", Requirement: "always", Default: false},
		{ID: promptExtraVars, Kind: "text", Requirement: "always", Default: ""},
		{ID: promptExecutionPreview, Kind: "confirm", Requirement: "always", Default: true},
		{ID: promptExecutionConfirmPreview, Kind: "confirm", Requirement: "conditional", Default: true},
		{ID: promptExecutionApplyAfterPreview, Kind: "confirm", Requirement: "conditional", Default: false},
		{ID: promptExecutionConfirmApply, Kind: "confirm", Requirement: "conditional", Default: true},
		{ID: promptS3AccessMode, Kind: "select", Requirement: "conditional", Default: "anonymous", AcceptedValues: []string{"anonymous", "signed"}},
		{ID: promptS3ConfigPath, Kind: "text", Requirement: "conditional", Default: defaultSeaweedfsS3ConfigPath},
		{ID: "decommission.confirm", Kind: "confirm", Requirement: "conditional", Default: false},
		{ID: "auto_host_var.<var>.use_detected", IDPattern: "auto_host_var.*.use_detected", Kind: "confirm", Requirement: "conditional", Default: true},
		{ID: "auto_host_var.<var>.value", IDPattern: "auto_host_var.*.value", Kind: "text", Requirement: "conditional", Default: ""},
	}
	if action == "deploy" {
		prompts = append(prompts, promptDefinition{ID: promptScope, Kind: "select", Requirement: "always", Default: "site", AcceptedValues: []string{"site", "component"}})
	}
	return promptWorkflowSchema{Version: 1, Prompts: prompts}
}

func deployComponentIDs(action string) []string {
	ids := make([]string, 0, len(deployCatalog))
	for _, entry := range deployCatalog {
		if action == "reconcile" && !entry.Reconcile {
			continue
		}
		ids = append(ids, entry.Key)
	}
	return ids
}

func promptDefinitionFor(action, id string) (promptDefinition, bool) {
	for _, definition := range promptSchemaFor(action).Prompts {
		if definition.ID == id || (definition.IDPattern != "" && promptIDMatches(definition.IDPattern, id)) {
			return definition, true
		}
	}
	return promptDefinition{}, false
}

func promptIDMatches(pattern, id string) bool {
	parts := strings.Split(pattern, "*")
	return len(parts) == 2 && strings.HasPrefix(id, parts[0]) && strings.HasSuffix(id, parts[1]) && len(id) > len(parts[0])+len(parts[1])
}
