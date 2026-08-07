package cmd

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// ExecutionMode is how an external agent (an "actions schema" consumer)
// must invoke this action: structured is a direct editActionRegistry
// call, prompt_answers replays a standalone TUI's prompts (deploy/
// reconcile), and unsupported names the empty end of the enum used by
// unsupportedOperation entries rather than any live spec.
type ExecutionMode string

const (
	ExecutionModeStructured    ExecutionMode = "structured"
	ExecutionModePromptAnswers ExecutionMode = "prompt_answers"
	ExecutionModeUnsupported   ExecutionMode = "unsupported"
)

// SideEffectClassification categorizes what an action does to the
// workspace: read never writes, write mutates a file the action names
// in its own Verification, and destructive removes a whole entity
// (delete_host) or runs a real apply against live infrastructure
// (deploy) rather than editing an in-repo file.
type SideEffectClassification string

const (
	SideEffectRead        SideEffectClassification = "read"
	SideEffectWrite       SideEffectClassification = "write"
	SideEffectDestructive SideEffectClassification = "destructive"
)

// SecretHandling declares whether an action's value/value_env fields
// may ever carry a real secret, matching the same value_env rules
// validateAddOrEditExtraVar/validateAddOrSetVaultValue/
// validateSetGroupVar already enforce.
type SecretHandling string

const (
	SecretHandlingNone                SecretHandling = "none"
	SecretHandlingValueEnvRequired    SecretHandling = "value_env_required"
	SecretHandlingValueEnvRecommended SecretHandling = "value_env_recommended"
)

// verificationMethod is how a caller can confirm an action actually
// took effect after running it.
type verificationMethod string

const (
	verificationMethodFileContent  verificationMethod = "file_content"
	verificationMethodExitCode     verificationMethod = "exit_code"
	verificationMethodPromptOutput verificationMethod = "prompt_output"
	verificationMethodNone         verificationMethod = "none"
)

type verificationSpec struct {
	Method    verificationMethod `json:"method"`
	Path      string             `json:"path,omitempty"`
	Assertion string             `json:"assertion,omitempty"`
}

type semanticActionSpec struct {
	Name                     string                   `json:"name"`
	Description              string                   `json:"description"`
	Required                 []string                 `json:"required,omitempty"`
	Optional                 []string                 `json:"optional,omitempty"`
	Values                   map[string][]string      `json:"values,omitempty"`
	Standalone               bool                     `json:"standalone,omitempty"`
	ExecutionMode            ExecutionMode            `json:"execution_mode"`
	SideEffectClassification SideEffectClassification `json:"side_effect_classification"`
	SecretHandling           SecretHandling           `json:"secret_handling,omitempty"`
	Answer                   *semanticPromptSpec      `json:"answer,omitempty"`
	Verification             *verificationSpec        `json:"verification,omitempty"`
}

type semanticPromptSpec struct {
	Required      []string `json:"required"`
	ExactlyOneOf  []string `json:"exactly_one_of"`
	SecretAllowed bool     `json:"secret_allowed"`
}

// unsupportedOperation declares an operation domain that has no
// semantic action anywhere in editActionRegistry — kept separate from
// semanticActionSpec (which only ever describes something you *can*
// call) so a schema consumer can tell "no action for this" apart from
// "here is the action, and here's what it can do."
type unsupportedOperation struct {
	Operation   string `json:"operation"`
	Reason      string `json:"reason"`
	Alternative string `json:"alternative,omitempty"`
}

// secretsPolicy documents the value_env rules validateAddOrEditExtraVar
// (hosts.yml extra_vars: required — the file is plaintext and
// committed), validateAddOrSetVaultValue (.vault/: recommended — the
// file is ansible-vault encrypted, so a literal value isn't unsafe, just
// discouraged), and validateSetGroupVar (group_vars: rejected outright —
// those hold non-secret role settings) already enforce in code, so an
// external caller never has to rediscover the rule per-action.
type secretsPolicy struct {
	ReferencesOnly bool   `json:"references_only"`
	ValueEnvField  string `json:"value_env_field"`
	ExtraVars      string `json:"extra_vars"`
	GroupVars      string `json:"group_vars"`
	Vault          string `json:"vault"`
}

// pilotCapabilities is the full payload `pilot actions schema` prints —
// every semantic action's contract plus the surrounding policy (routing
// modes, known gaps, secret rules) an external caller needs to drive
// pilot without re-deriving them from source.
type pilotCapabilities struct {
	PilotVersion          string                 `json:"pilot_version"`
	SchemaVersion         int                    `json:"schema_version"`
	Actions               []semanticActionSpec   `json:"actions"`
	SupportedRoutingModes []string               `json:"supported_routing_modes"`
	UnsupportedOperations []unsupportedOperation `json:"unsupported_operations,omitempty"`
	SecretsPolicy         *secretsPolicy         `json:"secrets_policy"`
}

// semanticActionSpecs is the single source of truth for the action names and
// input contract exposed to agents and enforced by scenario validation. The
// edit-workflow actions come from editActionRegistry (edit_actions_registry.go);
// deploy/reconcile are appended separately since they run through a different
// execution path (prompt_automation.go), not the edit router.
func semanticActionSpecs() []semanticActionSpec {
	registry := editActionRegistry()
	specs := make([]semanticActionSpec, 0, len(registry)+2)
	for _, def := range registry {
		specs = append(specs, def.Spec)
	}
	specs = append(specs,
		semanticActionSpec{
			Name:                     "deploy",
			Description:              "answer the deploy TUI and run its guarded transaction",
			Required:                 []string{"inventory", "answers"},
			Standalone:               true,
			ExecutionMode:            ExecutionModePromptAnswers,
			SideEffectClassification: SideEffectDestructive,
			SecretHandling:           SecretHandlingNone,
			Answer:                   &semanticPromptSpec{Required: []string{"prompt"}, ExactlyOneOf: []string{"select", "text", "confirm"}, SecretAllowed: false},
			Verification: &verificationSpec{
				Method:    verificationMethodExitCode,
				Assertion: "deployment playbook executed successfully",
			},
		},
		semanticActionSpec{
			Name:                     "reconcile",
			Description:              "answer the reconcile TUI and run its guarded transaction",
			Required:                 []string{"inventory", "answers"},
			Standalone:               true,
			ExecutionMode:            ExecutionModePromptAnswers,
			SideEffectClassification: SideEffectWrite,
			SecretHandling:           SecretHandlingNone,
			Answer:                   &semanticPromptSpec{Required: []string{"prompt"}, ExactlyOneOf: []string{"select", "text", "confirm"}, SecretAllowed: false},
			Verification: &verificationSpec{
				Method:    verificationMethodExitCode,
				Assertion: "reconciliation completed; idempotent nature verified",
			},
		},
	)
	return specs
}

func semanticActionSpecFor(name string) (semanticActionSpec, bool) {
	for _, spec := range semanticActionSpecs() {
		if spec.Name == name {
			return spec, true
		}
	}
	return semanticActionSpec{}, false
}

var actionsCmd = &cobra.Command{
	Use:   "actions",
	Short: "列出 semantic TUI actions 與其輸入契約",
}

var actionsListCmd = &cobra.Command{
	Use:   "list",
	Short: "列出可用 action 名稱",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return writeActionsList(cmd.OutOrStdout())
	},
}

var actionsSchemaCmd = &cobra.Command{
	Use:   "schema",
	Short: "輸出 machine-readable JSON action schema",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return writeActionsSchema(cmd.OutOrStdout())
	},
}

func init() {
	actionsCmd.AddCommand(actionsListCmd, actionsSchemaCmd)
	rootCmd.AddCommand(actionsCmd)
}

func writeActionsList(out io.Writer) error {
	for _, spec := range semanticActionSpecs() {
		if _, err := fmt.Fprintf(out, "%s\t%s\n", spec.Name, spec.Description); err != nil {
			return fmt.Errorf("write actions list: %w", err)
		}
	}
	return nil
}

func writeActionsSchema(out io.Writer) error {
	capabilities := pilotCapabilities{
		PilotVersion:          rootCmd.Version,
		SchemaVersion:         1,
		Actions:               semanticActionSpecs(),
		SupportedRoutingModes: []string{string(ExecutionModeStructured), string(ExecutionModePromptAnswers)},
		UnsupportedOperations: []unsupportedOperation{
			{
				Operation:   "FreeIPA Roster Entity Deletion",
				Reason:      "editActionRegistry only creates roster users/groups/hostgroups/HBAC rules/sudo rules/sudo command groups and edits their fields; no semantic action removes an entity outright (state:absent is deliberately out of scope for users/groups per edit_tui_roster.go)",
				Alternative: "Direct edit of the roster YAML (.vault/ipa-identity.yaml) followed by `pilot roster lint`",
			},
			{
				Operation:   "FreeIPA Roster NFS/Migration/Policy-Exception Sections",
				Reason:      "the roster's nfs, nfs_clients, migration, and policy_exceptions top-level sections have no editActionRegistry actions; migration in particular is deliberately kept a dedicated fail-closed workflow, not reconciled by this playbook",
				Alternative: "Direct manipulation of the roster YAML skeleton for these sections",
			},
		},
		SecretsPolicy: &secretsPolicy{
			ReferencesOnly: true,
			ValueEnvField:  "value_env",
			ExtraVars:      "value_env_required",
			GroupVars:      "rejected",
			Vault:          "value_env_recommended",
		},
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(capabilities); err != nil {
		return fmt.Errorf("write actions schema: %w", err)
	}
	return nil
}
