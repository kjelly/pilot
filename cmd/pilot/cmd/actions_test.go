package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSemanticActionCatalogIsStable(t *testing.T) {
	want := []string{
		"create_host", "set_host_field", "enable_role", "disable_role",
		"delete_host", "add_extra_var", "edit_extra_var", "delete_extra_var", "discard_hosts",
		"apply_role_preset", "copy_roles_from_host", "create_role_preset", "rename_role_preset",
		"delete_role_preset", "restore_role_presets",
		"set_group_var", "restore_group_var_default", "save_group_vars", "discard_group_vars",
		"add_vault_key", "set_vault_value", "delete_vault_key", "save_vault", "discard_vault",
		"save_hosts", "deploy", "reconcile",
	}
	specs := semanticActionSpecs()
	if len(specs) != len(want) {
		t.Fatalf("spec count = %d, want %d", len(specs), len(want))
	}
	for i, spec := range specs {
		if spec.Name != want[i] {
			t.Fatalf("spec %d name = %q, want %q", i, spec.Name, want[i])
		}
		if spec.Description == "" {
			t.Fatalf("spec %q has no description", spec.Name)
		}
	}
}

func TestWriteActionsSchemaIsMachineReadable(t *testing.T) {
	var out bytes.Buffer
	if err := writeActionsSchema(&out); err != nil {
		t.Fatalf("writeActionsSchema() error = %v", err)
	}
	var schema struct {
		Version int `json:"version"`
		Actions []struct {
			Name     string   `json:"name"`
			Required []string `json:"required"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(out.Bytes(), &schema); err != nil {
		t.Fatalf("schema is not JSON: %v\n%s", err, out.String())
	}
	if schema.Version != 1 || len(schema.Actions) != 27 {
		t.Fatalf("schema metadata = version %d, actions %d", schema.Version, len(schema.Actions))
	}
	if !strings.Contains(out.String(), `"name": "deploy"`) || !strings.Contains(out.String(), `"answers"`) {
		t.Fatalf("schema omitted deploy answer contract:\n%s", out.String())
	}
}

func TestActionsListIncludesEverySemanticAction(t *testing.T) {
	var out bytes.Buffer
	if err := writeActionsList(&out); err != nil {
		t.Fatalf("writeActionsList() error = %v", err)
	}
	for _, name := range []string{
		"create_host", "set_host_field", "enable_role", "disable_role",
		"delete_host", "add_extra_var", "edit_extra_var", "delete_extra_var", "discard_hosts",
		"apply_role_preset", "copy_roles_from_host", "create_role_preset", "rename_role_preset",
		"delete_role_preset", "restore_role_presets",
		"set_group_var", "restore_group_var_default", "save_group_vars", "discard_group_vars",
		"add_vault_key", "set_vault_value", "delete_vault_key", "save_vault", "discard_vault",
		"save_hosts", "deploy", "reconcile",
	} {
		if !strings.Contains(out.String(), name) {
			t.Fatalf("actions list omitted %q:\n%s", name, out.String())
		}
	}
}

// TestEditActionRegistryCoversEverySpecAndSwitch is the drift guard
// edit_actions_registry.go exists to make structurally impossible to
// violate: every registry entry has a name/Validate/Run, no name is
// duplicated, and semanticActionSpecs() is exactly the registry plus
// the two standalone (deploy/reconcile) specs that intentionally live
// outside the registry.
func TestEditActionRegistryCoversEverySpecAndSwitch(t *testing.T) {
	registry := editActionRegistry()
	if len(registry) == 0 {
		t.Fatal("editActionRegistry() is empty")
	}
	seen := map[string]bool{}
	for _, def := range registry {
		if def.Spec.Name == "" {
			t.Fatal("registry entry has empty spec name")
		}
		if seen[def.Spec.Name] {
			t.Fatalf("duplicate registry entry %q", def.Spec.Name)
		}
		seen[def.Spec.Name] = true
		if def.Validate == nil {
			t.Fatalf("registry entry %q has no Validate", def.Spec.Name)
		}
		if def.Run == nil {
			t.Fatalf("registry entry %q has no Run", def.Spec.Name)
		}
	}
	for _, standalone := range []string{"deploy", "reconcile"} {
		if seen[standalone] {
			t.Fatalf("standalone action %q must not be in editActionRegistry", standalone)
		}
	}
	specs := semanticActionSpecs()
	if len(specs) != len(registry)+2 {
		t.Fatalf("semanticActionSpecs() len = %d, want registry(%d)+2 standalone", len(specs), len(registry))
	}
}
