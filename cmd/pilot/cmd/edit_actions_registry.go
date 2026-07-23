// edit_actions_registry.go is the single source of truth for every
// semantic edit-scenario action: its exposed spec (actions.go's
// semanticActionSpecs), its scenario-JSON validation rule
// (edit_automation.go's validateEditAction), and its driver execution
// (edit_automation_driver.go's automationDriver.runStep). All three are
// generated from editActionRegistry so a new action can never exist in
// one without existing in all three — before this file, those three
// switches were hand-synced across separate files, which is exactly
// the kind of drift that silently either rejects a valid action or
// accepts one with no execution path.
//
// deploy/reconcile are deliberately NOT in this registry: they run
// through an entirely different path (prompt_automation.go's
// promptAutomation, answering the standalone deploy/reconcile TUIs
// rather than driving the edit router), so semanticActionSpecs()
// appends their two specs after the registry's.
package cmd

import (
	"fmt"
	"strings"
)

// editActionDef ties one action's schema, validation, and execution
// together so they can never drift apart.
type editActionDef struct {
	Spec     semanticActionSpec
	Validate func(editAction) error
	Run      func(d *automationDriver, r *editRouterModel, step editAction) error
}

func editActionRegistry() []editActionDef {
	return []editActionDef{
		{
			Spec:     semanticActionSpec{Name: "create_host", Description: "create a host through the hosts TUI", Required: []string{"host"}},
			Validate: validateCreateHost,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.createHost(r, step.Host)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:        "set_host_field",
				Description: "set one supported non-secret host field",
				Required:    []string{"host", "field", "value"},
				Values:      map[string][]string{"field": {"ansible_host", "ansible_user", "ssh_key_file", "env"}},
			},
			Validate: validateSetHostField,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setHostField(r, step.Host, step.Field, step.Value)
			},
		},
		{
			Spec:     semanticActionSpec{Name: "enable_role", Description: "enable one role in a host role checklist", Required: []string{"host", "role"}},
			Validate: validateHostRoleAction("enable_role"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.enableRole(r, step.Host, step.Role)
			},
		},
		{
			Spec:     semanticActionSpec{Name: "disable_role", Description: "disable one role in a host role checklist", Required: []string{"host", "role"}},
			Validate: validateHostRoleAction("disable_role"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.disableRole(r, step.Host, step.Role)
			},
		},
		{
			Spec:     semanticActionSpec{Name: "delete_host", Description: "delete a host from hosts.yml (in-memory until save_hosts)", Required: []string{"host"}},
			Validate: validateDeleteHost,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.deleteHost(r, step.Host)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:        "add_extra_var",
				Description: "add a new extra host var (fails if the key already exists — use edit_extra_var to change one)",
				Required:    []string{"host", "key"},
				Optional:    []string{"value", "value_env"},
			},
			Validate: validateAddOrEditExtraVar("add_extra_var"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				value, secret, err := resolveValueOrEnv(step)
				if err != nil {
					return err
				}
				return d.addExtraVar(r, step.Host, step.Key, value, secret)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:        "edit_extra_var",
				Description: "change an existing extra host var's value",
				Required:    []string{"host", "key"},
				Optional:    []string{"value", "value_env"},
			},
			Validate: validateAddOrEditExtraVar("edit_extra_var"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				value, secret, err := resolveValueOrEnv(step)
				if err != nil {
					return err
				}
				return d.editExtraVar(r, step.Host, step.Key, value, secret)
			},
		},
		{
			Spec:     semanticActionSpec{Name: "delete_extra_var", Description: "delete an extra host var", Required: []string{"host", "key"}},
			Validate: validateDeleteExtraVar,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.deleteExtraVar(r, step.Host, step.Key)
			},
		},
		{
			Spec:     semanticActionSpec{Name: "discard_hosts", Description: "leave the hosts.yml editor without saving, discarding every change made this session"},
			Validate: validateNoParamsAction("discard_hosts"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.discardHosts(r)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:        "apply_role_preset",
				Description: "add a role preset's roles to a host's role set (host is the navigation entry point; role-presets.yml is shared, not host-specific)",
				Required:    []string{"host", "preset"},
			},
			Validate: validateApplyRolePreset,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.applyRolePreset(r, step.Host, step.Preset)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:        "copy_roles_from_host",
				Description: "add another host's roles to this host's role set",
				Required:    []string{"host", "source_host"},
			},
			Validate: validateCopyRolesFromHost,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.copyRolesFromHost(r, step.Host, step.SourceHost)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:        "create_role_preset",
				Description: "create a role preset via any host's roles menu (role-presets.yml is shared, not host-specific — host just names the navigation entry point)",
				Required:    []string{"host", "label", "roles"},
			},
			Validate: validateCreateRolePreset,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.createRolePreset(r, step.Host, step.Label, step.Roles)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:        "rename_role_preset",
				Description: "rename an existing role preset without changing its roles (preset = existing label, label = new label)",
				Required:    []string{"host", "preset", "label"},
			},
			Validate: validateRenameRolePreset,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.renameRolePreset(r, step.Host, step.Preset, step.Label)
			},
		},
		{
			Spec:     semanticActionSpec{Name: "delete_role_preset", Description: "delete a role preset", Required: []string{"host", "preset"}},
			Validate: validateDeleteRolePreset,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.deleteRolePreset(r, step.Host, step.Preset)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:        "restore_role_presets",
				Description: "delete role-presets.yml, reverting to the built-in defaults (fails if it was never customized)",
				Required:    []string{"host"},
			},
			Validate: validateRestoreRolePresets,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.restoreRolePresets(r, step.Host)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:        "set_group_var",
				Description: "set an existing group_vars key's value (group_vars are non-secret role settings, e.g. FreeIPA realm, DNS addresses; value_env is not offered here)",
				Required:    []string{"file", "key", "value"},
			},
			Validate: validateSetGroupVar,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setGroupVar(r, step.File, step.Key, step.Value)
			},
		},
		{
			Spec:     semanticActionSpec{Name: "restore_group_var_default", Description: "comment a group_vars key back out, reverting to the playbook's built-in default", Required: []string{"file", "key"}},
			Validate: validateGroupVarsFileKeyAction("restore_group_var_default"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.restoreGroupVarDefault(r, step.File, step.Key)
			},
		},
		{
			Spec:     semanticActionSpec{Name: "save_group_vars", Description: "save a group_vars file and return to the file picker", Required: []string{"file"}},
			Validate: validateFileOnlyAction("save_group_vars"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.saveGroupVars(r, step.File)
			},
		},
		{
			Spec:     semanticActionSpec{Name: "discard_group_vars", Description: "leave a group_vars file without saving", Required: []string{"file"}},
			Validate: validateFileOnlyAction("discard_group_vars"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.discardGroupVars(r, step.File)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:        "add_vault_key",
				Description: "add a new key to a plaintext .vault/ skeleton file (creating the file first if needed); value_env is strongly recommended for real secrets",
				Required:    []string{"file", "key"},
				Optional:    []string{"value", "value_env"},
			},
			Validate: validateAddOrSetVaultValue("add_vault_key"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				value, secret, err := resolveValueOrEnv(step)
				if err != nil {
					return err
				}
				return d.addVaultKey(r, step.File, step.Key, value, secret)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:        "set_vault_value",
				Description: "change an existing .vault/ key's value; value_env is strongly recommended for real secrets",
				Required:    []string{"file", "key"},
				Optional:    []string{"value", "value_env"},
			},
			Validate: validateAddOrSetVaultValue("set_vault_value"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				value, secret, err := resolveValueOrEnv(step)
				if err != nil {
					return err
				}
				return d.setVaultValue(r, step.File, step.Key, value, secret)
			},
		},
		{
			Spec:     semanticActionSpec{Name: "delete_vault_key", Description: "delete a key from a plaintext .vault/ skeleton file", Required: []string{"file", "key"}},
			Validate: validateVaultFileKeyAction("delete_vault_key"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.deleteVaultKey(r, step.File, step.Key)
			},
		},
		{
			Spec:     semanticActionSpec{Name: "save_vault", Description: "save a .vault/ file and return to the file picker", Required: []string{"file"}},
			Validate: validateFileOnlyAction("save_vault"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.saveVault(r, step.File)
			},
		},
		{
			Spec:     semanticActionSpec{Name: "discard_vault", Description: "leave a .vault/ file without saving", Required: []string{"file"}},
			Validate: validateFileOnlyAction("discard_vault"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.discardVault(r, step.File)
			},
		},
		{
			Spec:     semanticActionSpec{Name: "save_hosts", Description: "save hosts.yml and finish the edit TUI"},
			Validate: validateNoParamsAction("save_hosts"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.saveHosts(r)
			},
		},
	}
}

func validateCreateHost(step editAction) error {
	if strings.TrimSpace(step.Host) == "" {
		return fmt.Errorf("create_host requires host")
	}
	if hasSecretName(step.Host) {
		return fmt.Errorf("secret-like host names are not allowed")
	}
	return nil
}

func validateSetHostField(step editAction) error {
	if strings.TrimSpace(step.Host) == "" {
		return fmt.Errorf("set_host_field requires host")
	}
	if strings.TrimSpace(step.Field) == "" {
		return fmt.Errorf("set_host_field requires field")
	}
	if hasSecretName(step.Field) {
		return fmt.Errorf("secret values are not accepted")
	}
	spec, _ := semanticActionSpecFor("set_host_field")
	allowed := false
	for _, field := range spec.Values["field"] {
		if step.Field == field {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("unsupported host field")
	}
	if step.Field == "env" && !isValidEnvChoice(step.Value) {
		return fmt.Errorf("unsupported env value %q", step.Value)
	}
	return nil
}

func isValidEnvChoice(v string) bool {
	for _, c := range envChoices {
		if v == c {
			return true
		}
	}
	return false
}

func validateDeleteHost(step editAction) error {
	if strings.TrimSpace(step.Host) == "" {
		return fmt.Errorf("delete_host requires host")
	}
	return nil
}

// validateAddOrEditExtraVar covers add_extra_var/edit_extra_var: unlike
// .vault/, hosts.yml is plaintext and committed, so a secret-shaped key name
// is rejected here regardless of whether the value itself comes via
// value_env — the key name alone would still land in cleartext hosts.yml.
func validateAddOrEditExtraVar(name string) func(editAction) error {
	return func(step editAction) error {
		if strings.TrimSpace(step.Host) == "" {
			return fmt.Errorf("%s requires host", name)
		}
		if strings.TrimSpace(step.Key) == "" {
			return fmt.Errorf("%s requires key", name)
		}
		if hasSecretName(step.Key) {
			return fmt.Errorf("secret-like extra var keys are not allowed")
		}
		return validateValueOrEnv(step, name)
	}
}

func validateDeleteExtraVar(step editAction) error {
	if strings.TrimSpace(step.Host) == "" {
		return fmt.Errorf("delete_extra_var requires host")
	}
	if strings.TrimSpace(step.Key) == "" {
		return fmt.Errorf("delete_extra_var requires key")
	}
	return nil
}

func validateApplyRolePreset(step editAction) error {
	if strings.TrimSpace(step.Host) == "" {
		return fmt.Errorf("apply_role_preset requires host")
	}
	if strings.TrimSpace(step.Preset) == "" {
		return fmt.Errorf("apply_role_preset requires preset")
	}
	return nil
}

func validateCopyRolesFromHost(step editAction) error {
	if strings.TrimSpace(step.Host) == "" {
		return fmt.Errorf("copy_roles_from_host requires host")
	}
	if strings.TrimSpace(step.SourceHost) == "" {
		return fmt.Errorf("copy_roles_from_host requires source_host")
	}
	return nil
}

func validateCreateRolePreset(step editAction) error {
	if strings.TrimSpace(step.Host) == "" {
		return fmt.Errorf("create_role_preset requires host")
	}
	if strings.TrimSpace(step.Label) == "" {
		return fmt.Errorf("create_role_preset requires label")
	}
	if len(step.Roles) == 0 {
		return fmt.Errorf("create_role_preset requires at least one role")
	}
	for _, role := range step.Roles {
		if hasSecretName(role) {
			return fmt.Errorf("secret-like role names are not allowed")
		}
	}
	return nil
}

func validateRenameRolePreset(step editAction) error {
	if strings.TrimSpace(step.Host) == "" {
		return fmt.Errorf("rename_role_preset requires host")
	}
	if strings.TrimSpace(step.Preset) == "" {
		return fmt.Errorf("rename_role_preset requires preset (the existing label)")
	}
	if strings.TrimSpace(step.Label) == "" {
		return fmt.Errorf("rename_role_preset requires label (the new label)")
	}
	return nil
}

func validateDeleteRolePreset(step editAction) error {
	if strings.TrimSpace(step.Host) == "" {
		return fmt.Errorf("delete_role_preset requires host")
	}
	if strings.TrimSpace(step.Preset) == "" {
		return fmt.Errorf("delete_role_preset requires preset")
	}
	return nil
}

func validateRestoreRolePresets(step editAction) error {
	if strings.TrimSpace(step.Host) == "" {
		return fmt.Errorf("restore_role_presets requires host")
	}
	return nil
}

func validateGroupVarsFileKeyAction(name string) func(editAction) error {
	return func(step editAction) error {
		if strings.TrimSpace(step.File) == "" {
			return fmt.Errorf("%s requires file", name)
		}
		if strings.TrimSpace(step.Key) == "" {
			return fmt.Errorf("%s requires key", name)
		}
		return nil
	}
}

func validateSetGroupVar(step editAction) error {
	if strings.TrimSpace(step.File) == "" {
		return fmt.Errorf("set_group_var requires file")
	}
	if strings.TrimSpace(step.Key) == "" {
		return fmt.Errorf("set_group_var requires key")
	}
	if step.ValueEnv != "" {
		return fmt.Errorf("set_group_var does not accept value_env: group_vars hold non-secret role settings, not secrets")
	}
	return nil
}

func validateFileOnlyAction(name string) func(editAction) error {
	return func(step editAction) error {
		if strings.TrimSpace(step.File) == "" {
			return fmt.Errorf("%s requires file", name)
		}
		return nil
	}
}

func validateVaultFileKeyAction(name string) func(editAction) error {
	return func(step editAction) error {
		if strings.TrimSpace(step.File) == "" {
			return fmt.Errorf("%s requires file", name)
		}
		if strings.TrimSpace(step.Key) == "" {
			return fmt.Errorf("%s requires key", name)
		}
		return nil
	}
}

// validateAddOrSetVaultValue deliberately does NOT call hasSecretName on
// step.Key: .vault/ exists specifically to hold secret-shaped key names
// (password, token, ...), unlike hosts.yml/group_vars where that guard
// keeps secrets out of plaintext-committed files. The guard that matters
// here is value/value_env (see validateValueOrEnv), not the key name.
func validateAddOrSetVaultValue(name string) func(editAction) error {
	return func(step editAction) error {
		if strings.TrimSpace(step.File) == "" {
			return fmt.Errorf("%s requires file", name)
		}
		if strings.TrimSpace(step.Key) == "" {
			return fmt.Errorf("%s requires key", name)
		}
		return validateValueOrEnv(step, name)
	}
}

func validateHostRoleAction(name string) func(editAction) error {
	return func(step editAction) error {
		if strings.TrimSpace(step.Host) == "" {
			return fmt.Errorf("%s requires host", name)
		}
		if strings.TrimSpace(step.Role) == "" {
			return fmt.Errorf("%s requires role", name)
		}
		if hasSecretName(step.Role) {
			return fmt.Errorf("secret-like role names are not allowed")
		}
		return nil
	}
}

// editActionHasAnyParam reports whether step carries any field beyond
// Action — used to validate no-argument actions like save_hosts. Kept
// in sync with editAction's field set by hand (there is no reflection
// magic here on purpose: a compile error from a struct literal missing
// a new field would be a worse failure mode than this one line lagging
// briefly behind a new editAction field during a single PR).
func editActionHasAnyParam(step editAction) bool {
	return step.Host != "" || step.Field != "" || step.Value != "" || step.ValueEnv != "" || step.Role != "" ||
		step.Key != "" || step.File != "" || step.Label != "" || step.Preset != "" || step.SourceHost != "" || len(step.Roles) > 0 ||
		step.Inventory != "" || len(step.Answers) > 0
}

func validateNoParamsAction(name string) func(editAction) error {
	return func(step editAction) error {
		if editActionHasAnyParam(step) {
			return fmt.Errorf("%s does not accept parameters", name)
		}
		return nil
	}
}
