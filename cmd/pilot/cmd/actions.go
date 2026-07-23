package cmd

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

type semanticActionSpec struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Required    []string            `json:"required,omitempty"`
	Optional    []string            `json:"optional,omitempty"`
	Values      map[string][]string `json:"values,omitempty"`
	Standalone  bool                `json:"standalone,omitempty"`
	Answer      *semanticPromptSpec `json:"answer,omitempty"`
}

type semanticPromptSpec struct {
	Required      []string `json:"required"`
	ExactlyOneOf  []string `json:"exactly_one_of"`
	SecretAllowed bool     `json:"secret_allowed"`
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
		semanticActionSpec{Name: "deploy", Description: "answer the deploy TUI and run its guarded transaction", Required: []string{"inventory", "answers"}, Standalone: true, Answer: &semanticPromptSpec{Required: []string{"prompt"}, ExactlyOneOf: []string{"select", "text", "confirm"}, SecretAllowed: false}},
		semanticActionSpec{Name: "reconcile", Description: "answer the reconcile TUI and run its guarded transaction", Required: []string{"inventory", "answers"}, Standalone: true, Answer: &semanticPromptSpec{Required: []string{"prompt"}, ExactlyOneOf: []string{"select", "text", "confirm"}, SecretAllowed: false}},
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
	payload := struct {
		Version int                  `json:"version"`
		Actions []semanticActionSpec `json:"actions"`
	}{Version: 1, Actions: semanticActionSpecs()}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(payload); err != nil {
		return fmt.Errorf("write actions schema: %w", err)
	}
	return nil
}
