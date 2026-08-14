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
		"create_user", "set_user_field", "set_user_password", "add_ssh_key", "delete_ssh_key",
		"create_group", "set_group_field", "set_group_members_users", "set_group_members_groups",
		"create_hostgroup", "set_hostgroup_field", "set_hostgroup_hostgroups",
		"create_hbac_rule", "set_hbac_groups", "set_hbac_targets", "set_hbac_services", "set_hbac_disable_allow_all",
		"create_sudo_command_group", "set_sudo_command_group_commands",
		"create_sudo_rule", "set_sudo_rule_groups", "set_sudo_rule_command_groups", "set_sudo_rule_commands", "set_sudo_rule_allow_mode",
		"create_dns_manifest", "create_dns_zone", "set_dns_zone_field",
		"create_dns_record", "set_dns_record_field", "set_dns_record_values", "set_dns_record_target_host",
		"create_internal_endpoint_manifest", "create_internal_endpoint", "set_internal_endpoint_state",
		"set_internal_endpoint_dns", "set_internal_endpoint_route_direct", "set_internal_endpoint_route_proxy",
		"set_internal_endpoint_tls_disabled", "set_internal_endpoint_tls_freeipa", "set_internal_endpoint_tls_sink",
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
		PilotVersion  string `json:"pilot_version"`
		SchemaVersion int    `json:"schema_version"`
		Actions       []struct {
			Name     string   `json:"name"`
			Required []string `json:"required"`
		} `json:"actions"`
		SupportedRoutingModes []string `json:"supported_routing_modes"`
		UnsupportedOperations []struct {
			Operation   string `json:"operation"`
			Reason      string `json:"reason"`
			Alternative string `json:"alternative"`
		} `json:"unsupported_operations"`
		SecretsPolicy *struct {
			ReferencesOnly bool   `json:"references_only"`
			ValueEnvField  string `json:"value_env_field"`
			ExtraVars      string `json:"extra_vars"`
			GroupVars      string `json:"group_vars"`
			Vault          string `json:"vault"`
		} `json:"secrets_policy"`
	}
	if err := json.Unmarshal(out.Bytes(), &schema); err != nil {
		t.Fatalf("schema is not JSON: %v\n%s", err, out.String())
	}
	if schema.PilotVersion == "" {
		t.Error("pilot_version is empty")
	}
	if schema.SchemaVersion != 1 || len(schema.Actions) != 67 {
		t.Fatalf("schema metadata = schema_version %d, actions %d", schema.SchemaVersion, len(schema.Actions))
	}
	if !strings.Contains(out.String(), `"name": "deploy"`) || !strings.Contains(out.String(), `"answers"`) {
		t.Fatalf("schema omitted deploy answer contract:\n%s", out.String())
	}
	if len(schema.SupportedRoutingModes) == 0 {
		t.Error("supported_routing_modes is empty")
	}
	if schema.SecretsPolicy == nil {
		t.Fatal("secrets_policy is missing from schema")
	}
	if schema.SecretsPolicy.ExtraVars != "value_env_required" {
		t.Errorf("secrets_policy.extra_vars = %q, want value_env_required", schema.SecretsPolicy.ExtraVars)
	}
	if schema.SecretsPolicy.GroupVars != "rejected" {
		t.Errorf("secrets_policy.group_vars = %q, want rejected", schema.SecretsPolicy.GroupVars)
	}
	if schema.SecretsPolicy.Vault != "value_env_recommended" {
		t.Errorf("secrets_policy.vault = %q, want value_env_recommended", schema.SecretsPolicy.Vault)
	}
	// Every declared unsupported operation must name a real gap, not one
	// of the 57 actions actually in the catalog — otherwise the schema
	// would contradict itself.
	known := map[string]bool{}
	for _, spec := range semanticActionSpecs() {
		known[spec.Name] = true
	}
	for _, op := range schema.UnsupportedOperations {
		if op.Reason == "" {
			t.Errorf("unsupported operation %q has empty reason", op.Operation)
		}
		if op.Alternative == "" {
			t.Errorf("unsupported operation %q has empty alternative", op.Operation)
		}
		if known[op.Operation] {
			t.Errorf("unsupported operation %q collides with an action name that IS in the catalog", op.Operation)
		}
	}
}

// TestAllActionsHaveNonEmptyMetadata verifies that every action in the
// registry has the Hufu-Pilot integration metadata populated: an
// execution mode, a side-effect classification, and (except for the
// two read-only leave-without-saving actions per file kind) a
// verification method.
func TestAllActionsHaveNonEmptyMetadata(t *testing.T) {
	specs := semanticActionSpecs()
	if len(specs) == 0 {
		t.Fatal("semanticActionSpecs() returned empty slice")
	}
	for _, spec := range specs {
		t.Run(spec.Name, func(t *testing.T) {
			if spec.ExecutionMode == "" {
				t.Errorf("action %q missing execution_mode", spec.Name)
			}
			if spec.SideEffectClassification == "" {
				t.Errorf("action %q missing side_effect_classification", spec.Name)
			}
			if spec.Verification == nil {
				t.Errorf("action %q missing verification", spec.Name)
			}
		})
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
		"create_user", "set_user_field", "set_user_password", "add_ssh_key", "delete_ssh_key",
		"create_group", "set_group_field", "set_group_members_users", "set_group_members_groups",
		"create_hostgroup", "set_hostgroup_field", "set_hostgroup_hostgroups",
		"create_hbac_rule", "set_hbac_groups", "set_hbac_targets", "set_hbac_services", "set_hbac_disable_allow_all",
		"create_sudo_command_group", "set_sudo_command_group_commands",
		"create_sudo_rule", "set_sudo_rule_groups", "set_sudo_rule_command_groups", "set_sudo_rule_commands", "set_sudo_rule_allow_mode",
		"create_dns_manifest", "create_dns_zone", "set_dns_zone_field",
		"create_dns_record", "set_dns_record_field", "set_dns_record_values", "set_dns_record_target_host",
		"create_internal_endpoint_manifest", "create_internal_endpoint", "set_internal_endpoint_state",
		"set_internal_endpoint_dns", "set_internal_endpoint_route_direct", "set_internal_endpoint_route_proxy",
		"set_internal_endpoint_tls_disabled", "set_internal_endpoint_tls_freeipa", "set_internal_endpoint_tls_sink",
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
