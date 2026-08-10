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
	"strconv"
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
			Spec: semanticActionSpec{
				Name:                     "create_host",
				Description:              "create a host through the hosts TUI",
				Required:                 []string{"host"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "hosts.yml",
					Assertion: "host appears in inventory",
				},
			},
			Validate: validateCreateHost,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.createHost(r, step.Host)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_host_field",
				Description:              "set one supported non-secret host field",
				Required:                 []string{"host", "field", "value"},
				Values:                   map[string][]string{"field": {"ansible_host", "ansible_user", "ssh_key_file", "env"}},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "hosts.yml",
					Assertion: "field value updated in inventory",
				},
			},
			Validate: validateSetHostField,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setHostField(r, step.Host, step.Field, step.Value)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "enable_role",
				Description:              "enable one role in a host role checklist",
				Required:                 []string{"host", "role"},
				Optional:                 []string{"host_vars"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "hosts.yml",
					Assertion: "role appears in host's role list",
				},
			},
			Validate: validateEnableRole,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.enableRole(r, step.Host, step.Role, step.HostVars)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "disable_role",
				Description:              "disable one role in a host role checklist",
				Required:                 []string{"host", "role"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "hosts.yml",
					Assertion: "role absent from host's role list",
				},
			},
			Validate: validateHostRoleAction("disable_role"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.disableRole(r, step.Host, step.Role)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "delete_host",
				Description:              "delete a host from hosts.yml (in-memory until save_hosts)",
				Required:                 []string{"host"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectDestructive,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "hosts.yml",
					Assertion: "host absent from inventory; confirm save_hosts was called",
				},
			},
			Validate: validateDeleteHost,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.deleteHost(r, step.Host)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "add_extra_var",
				Description:              "add a new extra host var (fails if the key already exists — use edit_extra_var to change one)",
				Required:                 []string{"host", "key"},
				Optional:                 []string{"value", "value_env"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingValueEnvRequired,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "hosts.yml",
					Assertion: "key appears in host's extra_vars; value_env reference resolved",
				},
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
				Name:                     "edit_extra_var",
				Description:              "change an existing extra host var's value",
				Required:                 []string{"host", "key"},
				Optional:                 []string{"value", "value_env"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingValueEnvRequired,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "hosts.yml",
					Assertion: "key value updated; value_env reference resolved",
				},
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
			Spec: semanticActionSpec{
				Name:                     "delete_extra_var",
				Description:              "delete an extra host var",
				Required:                 []string{"host", "key"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "hosts.yml",
					Assertion: "key absent from host's extra_vars",
				},
			},
			Validate: validateDeleteExtraVar,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.deleteExtraVar(r, step.Host, step.Key)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "discard_hosts",
				Description:              "leave the hosts.yml editor without saving, discarding every change made this session",
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectRead,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodNone,
					Assertion: "no file write occurred",
				},
			},
			Validate: validateNoParamsAction("discard_hosts"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.discardHosts(r)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "apply_role_preset",
				Description:              "add a role preset's roles to a host's role set (host is the navigation entry point; role-presets.yml is shared, not host-specific)",
				Required:                 []string{"host", "preset"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "hosts.yml",
					Assertion: "host's roles match preset definition",
				},
			},
			Validate: validateApplyRolePreset,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.applyRolePreset(r, step.Host, step.Preset)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "copy_roles_from_host",
				Description:              "add another host's roles to this host's role set",
				Required:                 []string{"host", "source_host"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "hosts.yml",
					Assertion: "target host has identical roles to source",
				},
			},
			Validate: validateCopyRolesFromHost,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.copyRolesFromHost(r, step.Host, step.SourceHost)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "create_role_preset",
				Description:              "create a role preset via any host's roles menu (role-presets.yml is shared, not host-specific — host just names the navigation entry point)",
				Required:                 []string{"host", "label", "roles"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "role-presets.yml",
					Assertion: "preset appears in role-presets.yml",
				},
			},
			Validate: validateCreateRolePreset,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.createRolePreset(r, step.Host, step.Label, step.Roles)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "rename_role_preset",
				Description:              "rename an existing role preset without changing its roles (preset = existing label, label = new label)",
				Required:                 []string{"host", "preset", "label"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "role-presets.yml",
					Assertion: "old label absent, new label present in presets",
				},
			},
			Validate: validateRenameRolePreset,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.renameRolePreset(r, step.Host, step.Preset, step.Label)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "delete_role_preset",
				Description:              "delete a role preset",
				Required:                 []string{"host", "preset"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "role-presets.yml",
					Assertion: "preset absent from role-presets.yml",
				},
			},
			Validate: validateDeleteRolePreset,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.deleteRolePreset(r, step.Host, step.Preset)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "restore_role_presets",
				Description:              "delete role-presets.yml, reverting to the built-in defaults (fails if it was never customized)",
				Required:                 []string{"host"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "role-presets.yml",
					Assertion: "role-presets.yml matches built-in defaults",
				},
			},
			Validate: validateRestoreRolePresets,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.restoreRolePresets(r, step.Host)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_group_var",
				Description:              "set an existing group_vars key's value (group_vars are non-secret role settings, e.g. FreeIPA realm, DNS addresses; value_env is not offered here)",
				Required:                 []string{"file", "key", "value"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "group_vars",
					Assertion: "key=value in group_vars file; value_env rejected",
				},
			},
			Validate: validateSetGroupVar,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setGroupVar(r, step.File, step.Key, step.Value)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "restore_group_var_default",
				Description:              "comment a group_vars key back out, reverting to the playbook's built-in default",
				Required:                 []string{"file", "key"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "group_vars",
					Assertion: "key commented out in group_vars file",
				},
			},
			Validate: validateGroupVarsFileKeyAction("restore_group_var_default"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.restoreGroupVarDefault(r, step.File, step.Key)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "save_group_vars",
				Description:              "save a group_vars file and return to the file picker",
				Required:                 []string{"file"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "group_vars",
					Assertion: "file written to disk; TUI returns to file picker",
				},
			},
			Validate: validateFileOnlyAction("save_group_vars"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.saveGroupVars(r, step.File)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "discard_group_vars",
				Description:              "leave a group_vars file without saving",
				Required:                 []string{"file"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectRead,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodNone,
					Assertion: "no file write occurred",
				},
			},
			Validate: validateFileOnlyAction("discard_group_vars"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.discardGroupVars(r, step.File)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "add_vault_key",
				Description:              "add a new key to a plaintext .vault/ skeleton file (creating the file first if needed); value_env is strongly recommended for real secrets",
				Required:                 []string{"file", "key"},
				Optional:                 []string{"value", "value_env"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingValueEnvRecommended,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/",
					Assertion: "key appears in encrypted vault file",
				},
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
				Name:                     "set_vault_value",
				Description:              "change an existing .vault/ key's value; value_env is strongly recommended for real secrets",
				Required:                 []string{"file", "key"},
				Optional:                 []string{"value", "value_env"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingValueEnvRecommended,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/",
					Assertion: "key value updated in encrypted vault file",
				},
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
			Spec: semanticActionSpec{
				Name:                     "delete_vault_key",
				Description:              "delete a key from a plaintext .vault/ skeleton file",
				Required:                 []string{"file", "key"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/",
					Assertion: "key absent from vault file",
				},
			},
			Validate: validateVaultFileKeyAction("delete_vault_key"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.deleteVaultKey(r, step.File, step.Key)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "save_vault",
				Description:              "save a .vault/ file and return to the file picker",
				Required:                 []string{"file"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/",
					Assertion: "file encrypted and written; TUI returns to file picker",
				},
			},
			Validate: validateFileOnlyAction("save_vault"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.saveVault(r, step.File)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "discard_vault",
				Description:              "leave a .vault/ file without saving",
				Required:                 []string{"file"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectRead,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodNone,
					Assertion: "no file write occurred",
				},
			},
			Validate: validateFileOnlyAction("discard_vault"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.discardVault(r, step.File)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "create_user",
				Description:              "create a FreeIPA roster user (Phase 6 increment 1: users only)",
				Required:                 []string{"user"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "user appears in roster",
				},
			},
			Validate: validateCreateUser,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.createUser(r, step.User)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_user_field",
				Description:              "set one non-secret roster user field (see set_user_password/add_ssh_key/delete_ssh_key for password.initial/ssh_keys.values)",
				Required:                 []string{"user", "field", "value"},
				Values:                   map[string][]string{"field": {"state", "first", "last", "display_name", "email", "uid", "gid", "login_shell", "home_directory", "enabled"}},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "field value updated for roster user",
				},
			},
			Validate: validateSetUserField,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setUserField(r, step.User, step.Field, step.Value)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_user_password",
				Description:              "set a roster user's password.initial (secret; MCP requires value_env)",
				Required:                 []string{"user"},
				Optional:                 []string{"value", "value_env"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingValueEnvRequired,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "password.initial set; value_env reference resolved",
				},
			},
			Validate: validateSetUserPassword,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				value, secret, err := resolveValueOrEnv(step)
				if err != nil {
					return err
				}
				return d.setUserPassword(r, step.User, value, secret)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "add_ssh_key",
				Description:              "append one ssh public key to a roster user's ssh_keys.values (not secret — a public key)",
				Required:                 []string{"user", "value"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "value appended to roster user's ssh_keys.values",
				},
			},
			Validate: validateUserSSHKeyAction("add_ssh_key"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.addSSHKey(r, step.User, step.Value)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "delete_ssh_key",
				Description:              "remove one ssh public key from a roster user's ssh_keys.values (matched by exact value)",
				Required:                 []string{"user", "value"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "value absent from roster user's ssh_keys.values",
				},
			},
			Validate: validateUserSSHKeyAction("delete_ssh_key"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.deleteSSHKey(r, step.User, step.Value)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "create_group",
				Description:              "create a FreeIPA roster group (category determines the required name prefix)",
				Required:                 []string{"name", "category"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "group appears in roster with the requested category",
				},
			},
			Validate: validateCreateGroup,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.createGroup(r, step.Name, step.Category)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_group_field",
				Description:              "set one roster group field (see set_group_members_users/set_group_members_groups for membership.users/membership.groups)",
				Required:                 []string{"name", "field", "value"},
				Values:                   map[string][]string{"field": {"type", "description", "gid", "membership.authoritative"}},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "field value updated for roster group",
				},
			},
			Validate: validateSetGroupField,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setGroupField(r, step.Name, step.Field, step.Value)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_group_members_users",
				Description:              "bulk-replace a roster group's membership.users (the whole set, not one item — matching the interactive checklist)",
				Required:                 []string{"name"},
				Optional:                 []string{"users"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "group's membership.users matches the requested set",
				},
			},
			Validate: validateGroupNameOnly("set_group_members_users"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setGroupMembersUsers(r, step.Name, step.Users)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_group_members_groups",
				Description:              "bulk-replace a roster group's membership.groups (the whole set, not one item — matching the interactive checklist)",
				Required:                 []string{"name"},
				Optional:                 []string{"groups"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "group's membership.groups matches the requested set",
				},
			},
			Validate: validateGroupNameOnly("set_group_members_groups"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setGroupMembersGroups(r, step.Name, step.Groups)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "create_hostgroup",
				Description:              "create a FreeIPA roster hostgroup (a group of enrolled hosts, for HBAC targets)",
				Required:                 []string{"name"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "hostgroup appears in roster",
				},
			},
			Validate: validateEntityNameOnly("create_hostgroup"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.createHostgroup(r, step.Name)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_hostgroup_field",
				Description:              "set one roster hostgroup field; membership.hosts's value is a comma-separated list of enrolled host FQDNs, matching the interactive text field exactly",
				Required:                 []string{"name", "field", "value"},
				Values:                   map[string][]string{"field": {"description", "membership.hosts"}},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "field value updated for roster hostgroup",
				},
			},
			Validate: validateHostgroupField,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setHostgroupField(r, step.Name, step.Field, step.Value)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "create_hbac_rule",
				Description:              "create an HBAC login rule (access group -> hostgroup -> PAM service), replaying the full creation wizard in one step",
				Required:                 []string{"name"},
				Optional:                 []string{"groups", "hostgroups", "services"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "HBAC rule appears in roster with the requested subjects/targets/services",
				},
			},
			Validate: validateEntityNameOnly("create_hbac_rule"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.createHBACRule(r, step.Name, step.Groups, step.Hostgroups, step.Services)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_hbac_groups",
				Description:              "bulk-replace an HBAC rule's subjects.groups (the whole set — access-category groups only)",
				Required:                 []string{"name"},
				Optional:                 []string{"groups"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "HBAC rule's subjects.groups matches the requested set",
				},
			},
			Validate: validateEntityNameOnly("set_hbac_groups"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setHBACGroups(r, step.Name, step.Groups)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_hbac_targets",
				Description:              "bulk-replace an HBAC rule's targets.hostgroups (the whole set)",
				Required:                 []string{"name"},
				Optional:                 []string{"hostgroups"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "HBAC rule's targets.hostgroups matches the requested set",
				},
			},
			Validate: validateEntityNameOnly("set_hbac_targets"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setHBACTargets(r, step.Name, step.Hostgroups)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_hbac_services",
				Description:              "bulk-replace an HBAC rule's allowed PAM services (the whole set)",
				Required:                 []string{"name"},
				Optional:                 []string{"services"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "HBAC rule's allowed services matches the requested set",
				},
			},
			Validate: validateEntityNameOnly("set_hbac_services"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setHBACServices(r, step.Name, step.Services)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_hbac_disable_allow_all",
				Description:              "set the global hbac.disable_allow_all flag (idempotent — a no-op if already at the requested value)",
				Required:                 []string{"value"},
				Values:                   map[string][]string{"value": {"true", "false"}},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "global hbac.disable_allow_all matches the requested value",
				},
			},
			Validate: validateBoolValueAction("set_hbac_disable_allow_all"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setHBACDisableAllowAll(r, step.Value == "true")
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "create_sudo_command_group",
				Description:              "create a reusable sudo command group; value is a comma-separated list of full sudo commands",
				Required:                 []string{"name"},
				Optional:                 []string{"value"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "sudo command group appears in roster with the requested commands",
				},
			},
			Validate: validateEntityNameOnly("create_sudo_command_group"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.createSudoCommandGroup(r, step.Name, step.Value)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_sudo_command_group_commands",
				Description:              "bulk-replace a sudo command group's commands; value is a comma-separated list of full sudo commands",
				Required:                 []string{"name"},
				Optional:                 []string{"value"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "sudo command group's commands matches the requested set",
				},
			},
			Validate: validateEntityNameOnly("set_sudo_command_group_commands"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setSudoCommandGroupCommands(r, step.Name, step.Value)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "create_sudo_rule",
				Description:              "create a sudo rule (role group -> command groups/commands), replaying the full creation wizard in one step; value is a comma-separated list of extra full sudo commands",
				Required:                 []string{"name"},
				Optional:                 []string{"groups", "command_groups", "value"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "sudo rule appears in roster with the requested subjects/command groups/commands",
				},
			},
			Validate: validateEntityNameOnly("create_sudo_rule"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.createSudoRule(r, step.Name, step.Groups, step.CommandGroups, step.Value)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_sudo_rule_groups",
				Description:              "bulk-replace a sudo rule's subjects.groups (the whole set — role-category groups only)",
				Required:                 []string{"name"},
				Optional:                 []string{"groups"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "sudo rule's subjects.groups matches the requested set",
				},
			},
			Validate: validateEntityNameOnly("set_sudo_rule_groups"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setSudoRuleGroups(r, step.Name, step.Groups)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_sudo_rule_command_groups",
				Description:              "bulk-replace a sudo rule's allow.command_groups (the whole set)",
				Required:                 []string{"name"},
				Optional:                 []string{"command_groups"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "sudo rule's allow.command_groups matches the requested set",
				},
			},
			Validate: validateEntityNameOnly("set_sudo_rule_command_groups"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setSudoRuleCommandGroups(r, step.Name, step.CommandGroups)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_sudo_rule_commands",
				Description:              "bulk-replace a sudo rule's extra allow.commands; value is a comma-separated list of full sudo commands",
				Required:                 []string{"name"},
				Optional:                 []string{"value"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "sudo rule's extra allow.commands matches the requested set",
				},
			},
			Validate: validateEntityNameOnly("set_sudo_rule_commands"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setSudoRuleCommands(r, step.Name, step.Value)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_sudo_rule_allow_mode",
				Description:              `set a sudo rule's command scope: "all" (dangerous — any command) or "restricted" (requires at least one command/command group already set)`,
				Required:                 []string{"name", "value"},
				Values:                   map[string][]string{"value": {"all", "restricted"}},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "sudo rule's command scope matches the requested mode",
				},
			},
			Validate: validateSudoRuleAllowMode,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setSudoRuleAllowMode(r, step.Name, step.Value)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "create_dns_manifest",
				Description:              "create the minimal freeipa-dns manifest skeleton (only way to produce the file at all)",
				Required:                 []string{"domain", "realm", "server"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "freeipa-dns.yaml",
					Assertion: "manifest file created with the requested domain/realm/server",
				},
			},
			Validate: validateCreateDNSManifest,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.createDNSManifest(r, step.Domain, step.Realm, step.Server)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "create_dns_zone",
				Description:              "create a freeipa-dns zone (absolute FQDN, e.g. example.com.)",
				Required:                 []string{"zone"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "freeipa-dns.yaml",
					Assertion: "zone appears in the manifest",
				},
			},
			Validate: validateDNSZoneNameOnly("create_dns_zone"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.createDNSZone(r, step.Zone)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_dns_zone_field",
				Description:              "set one freeipa-dns zone field; state:absent is a safe declarative delete request — real deletion happens later at apply time behind its own allow_zone_delete/confirm_dns_zone_delete gates",
				Required:                 []string{"zone", "field", "value"},
				Values:                   map[string][]string{"field": {"state", "records_mode", "acknowledge_split_horizon"}},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "freeipa-dns.yaml",
					Assertion: "zone field updated; state:absent only takes effect at apply time",
				},
			},
			Validate: validateSetDNSZoneField,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setDNSZoneField(r, step.Zone, step.Field, step.Value)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "create_dns_record",
				Description:              `create an A/AAAA/CNAME record; exactly one of target_host (resolves an inventory host's ansible_host) or values (explicit list) must be set — CNAME always requires values (a single full FQDN) and rejects target_host`,
				Required:                 []string{"zone", "record_type", "record_name"},
				Optional:                 []string{"target_host", "values"},
				Values:                   map[string][]string{"record_type": {"A", "AAAA", "CNAME"}},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "freeipa-dns.yaml",
					Assertion: "record appears under the zone with the requested type/target",
				},
			},
			Validate: validateCreateDNSRecord,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.createDNSRecord(r, step.Zone, step.RecordType, step.RecordName, step.TargetHost, step.Values)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_dns_record_field",
				Description:              "set one freeipa-dns record field (see set_dns_record_values/set_dns_record_target_host for the value-source field); state:absent only affects this record's own type, not other types at the same owner name",
				Required:                 []string{"zone", "record_name", "record_type", "field", "value"},
				Values:                   map[string][]string{"field": {"state", "ttl"}},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "freeipa-dns.yaml",
					Assertion: "record field updated; state:absent only takes effect at apply time",
				},
			},
			Validate: validateSetDNSRecordField,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setDNSRecordField(r, step.Zone, step.RecordName, step.RecordType, step.Field, step.Value)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_dns_record_values",
				Description:              "bulk-replace a record's explicit values (clears target.inventory_host)",
				Required:                 []string{"zone", "record_name", "record_type"},
				Optional:                 []string{"values"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "freeipa-dns.yaml",
					Assertion: "record's explicit values matches the requested set",
				},
			},
			Validate: validateDNSRecordIdentityOnly("set_dns_record_values"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setDNSRecordValues(r, step.Zone, step.RecordName, step.RecordType, step.Values)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_dns_record_target_host",
				Description:              "set a record's target.inventory_host, resolved against hosts.yml at apply time (clears explicit values); not valid for CNAME",
				Required:                 []string{"zone", "record_name", "record_type", "target_host"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "freeipa-dns.yaml",
					Assertion: "record's target.inventory_host matches the requested host",
				},
			},
			Validate: validateSetDNSRecordTargetHost,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setDNSRecordTargetHost(r, step.Zone, step.RecordName, step.RecordType, step.TargetHost)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "save_hosts",
				Description:              "save hosts.yml and finish the edit TUI",
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "hosts.yml",
					Assertion: "hosts.yml written; TUI exits edit workflow",
				},
			},
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

func validateCreateUser(step editAction) error {
	if strings.TrimSpace(step.User) == "" {
		return fmt.Errorf("create_user requires user")
	}
	if hasSecretName(step.User) {
		return fmt.Errorf("secret-like user names are not allowed")
	}
	return nil
}

func validateSetUserField(step editAction) error {
	if strings.TrimSpace(step.User) == "" {
		return fmt.Errorf("set_user_field requires user")
	}
	if strings.TrimSpace(step.Field) == "" {
		return fmt.Errorf("set_user_field requires field")
	}
	if hasSecretName(step.Field) {
		return fmt.Errorf("secret values are not accepted")
	}
	spec, _ := semanticActionSpecFor("set_user_field")
	allowed := false
	for _, field := range spec.Values["field"] {
		if step.Field == field {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("unsupported user field")
	}
	switch step.Field {
	case "state":
		valid := false
		for _, s := range rosterUserStateChoices {
			if step.Value == s {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("unsupported state value %q", step.Value)
		}
	case "uid", "gid":
		if _, err := strconv.Atoi(step.Value); err != nil {
			return fmt.Errorf("%s must be an integer", step.Field)
		}
	case "enabled":
		if step.Value != "true" && step.Value != "false" {
			return fmt.Errorf(`enabled must be "true" or "false"`)
		}
	}
	return nil
}

func validateSetUserPassword(step editAction) error {
	if strings.TrimSpace(step.User) == "" {
		return fmt.Errorf("set_user_password requires user")
	}
	return validateValueOrEnv(step, "set_user_password")
}

func validateUserSSHKeyAction(name string) func(editAction) error {
	return func(step editAction) error {
		if strings.TrimSpace(step.User) == "" {
			return fmt.Errorf("%s requires user", name)
		}
		if strings.TrimSpace(step.Value) == "" {
			return fmt.Errorf("%s requires value", name)
		}
		return nil
	}
}

func validateCreateGroup(step editAction) error {
	if strings.TrimSpace(step.Name) == "" {
		return fmt.Errorf("create_group requires name")
	}
	if hasSecretName(step.Name) {
		return fmt.Errorf("secret-like group names are not allowed")
	}
	valid := false
	for _, c := range rosterGroupCategories {
		if step.Category == c.Category {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("unsupported group category %q", step.Category)
	}
	return nil
}

func validateSetGroupField(step editAction) error {
	if strings.TrimSpace(step.Name) == "" {
		return fmt.Errorf("set_group_field requires name")
	}
	if strings.TrimSpace(step.Field) == "" {
		return fmt.Errorf("set_group_field requires field")
	}
	spec, _ := semanticActionSpecFor("set_group_field")
	allowed := false
	for _, field := range spec.Values["field"] {
		if step.Field == field {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("unsupported group field")
	}
	switch step.Field {
	case "type":
		valid := false
		for _, c := range rosterGroupTypeChoices {
			if step.Value == c {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("unsupported type value %q", step.Value)
		}
	case "gid":
		if _, err := strconv.Atoi(step.Value); err != nil {
			return fmt.Errorf("gid must be an integer")
		}
	case "membership.authoritative":
		if step.Value != "true" && step.Value != "false" {
			return fmt.Errorf(`membership.authoritative must be "true" or "false"`)
		}
	}
	return nil
}

func validateGroupNameOnly(name string) func(editAction) error {
	return func(step editAction) error {
		if strings.TrimSpace(step.Name) == "" {
			return fmt.Errorf("%s requires name", name)
		}
		return nil
	}
}

// validateEntityNameOnly is validateGroupNameOnly's shared counterpart
// for hostgroup/HBAC/sudo entities — kept as a distinct name from the
// group-specific one since it's used across several unrelated entity
// kinds (hostgroups, HBAC rules, sudo command groups, sudo rules), not
// just groups.
func validateEntityNameOnly(name string) func(editAction) error {
	return func(step editAction) error {
		if strings.TrimSpace(step.Name) == "" {
			return fmt.Errorf("%s requires name", name)
		}
		return nil
	}
}

func validateHostgroupField(step editAction) error {
	if strings.TrimSpace(step.Name) == "" {
		return fmt.Errorf("set_hostgroup_field requires name")
	}
	if strings.TrimSpace(step.Field) == "" {
		return fmt.Errorf("set_hostgroup_field requires field")
	}
	spec, _ := semanticActionSpecFor("set_hostgroup_field")
	for _, field := range spec.Values["field"] {
		if step.Field == field {
			return nil
		}
	}
	return fmt.Errorf("unsupported hostgroup field")
}

func validateBoolValueAction(name string) func(editAction) error {
	return func(step editAction) error {
		if step.Value != "true" && step.Value != "false" {
			return fmt.Errorf(`%s requires value "true" or "false"`, name)
		}
		return nil
	}
}

func validateSudoRuleAllowMode(step editAction) error {
	if strings.TrimSpace(step.Name) == "" {
		return fmt.Errorf("set_sudo_rule_allow_mode requires name")
	}
	if step.Value != "all" && step.Value != "restricted" {
		return fmt.Errorf(`set_sudo_rule_allow_mode requires value "all" or "restricted"`)
	}
	return nil
}

func validateCreateDNSManifest(step editAction) error {
	if strings.TrimSpace(step.Domain) == "" {
		return fmt.Errorf("create_dns_manifest requires domain")
	}
	if strings.TrimSpace(step.Realm) == "" {
		return fmt.Errorf("create_dns_manifest requires realm")
	}
	if strings.TrimSpace(step.Server) == "" {
		return fmt.Errorf("create_dns_manifest requires server")
	}
	return nil
}

func validateDNSZoneNameOnly(name string) func(editAction) error {
	return func(step editAction) error {
		if strings.TrimSpace(step.Zone) == "" {
			return fmt.Errorf("%s requires zone", name)
		}
		return nil
	}
}

func validateSetDNSZoneField(step editAction) error {
	if strings.TrimSpace(step.Zone) == "" {
		return fmt.Errorf("set_dns_zone_field requires zone")
	}
	if strings.TrimSpace(step.Field) == "" {
		return fmt.Errorf("set_dns_zone_field requires field")
	}
	spec, _ := semanticActionSpecFor("set_dns_zone_field")
	allowed := false
	for _, field := range spec.Values["field"] {
		if step.Field == field {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("unsupported dns zone field")
	}
	switch step.Field {
	case "state":
		if step.Value != "present" && step.Value != "absent" {
			return fmt.Errorf(`state must be "present" or "absent"`)
		}
	case "records_mode":
		if step.Value != "merge" && step.Value != "authoritative" {
			return fmt.Errorf(`records_mode must be "merge" or "authoritative"`)
		}
	case "acknowledge_split_horizon":
		if step.Value != "true" && step.Value != "false" {
			return fmt.Errorf(`acknowledge_split_horizon must be "true" or "false"`)
		}
	}
	return nil
}

func validateCreateDNSRecord(step editAction) error {
	if strings.TrimSpace(step.Zone) == "" {
		return fmt.Errorf("create_dns_record requires zone")
	}
	if strings.TrimSpace(step.RecordName) == "" {
		return fmt.Errorf("create_dns_record requires record_name")
	}
	valid := false
	for _, t := range dnsRecordTypeChoices {
		if step.RecordType == t {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("unsupported record_type %q", step.RecordType)
	}
	hasTarget := step.TargetHost != ""
	hasValues := len(step.Values) > 0
	if step.RecordType == "CNAME" {
		if step.TargetHost != "" {
			return fmt.Errorf("create_dns_record: CNAME records cannot use target_host")
		}
		if !hasValues {
			return fmt.Errorf("create_dns_record: CNAME requires values")
		}
		return nil
	}
	if hasTarget == hasValues {
		return fmt.Errorf("create_dns_record requires exactly one of target_host or values")
	}
	return nil
}

func validateSetDNSRecordField(step editAction) error {
	if strings.TrimSpace(step.Zone) == "" {
		return fmt.Errorf("set_dns_record_field requires zone")
	}
	if strings.TrimSpace(step.RecordName) == "" {
		return fmt.Errorf("set_dns_record_field requires record_name")
	}
	if strings.TrimSpace(step.RecordType) == "" {
		return fmt.Errorf("set_dns_record_field requires record_type")
	}
	spec, _ := semanticActionSpecFor("set_dns_record_field")
	allowed := false
	for _, field := range spec.Values["field"] {
		if step.Field == field {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("unsupported dns record field")
	}
	switch step.Field {
	case "state":
		if step.Value != "present" && step.Value != "absent" {
			return fmt.Errorf(`state must be "present" or "absent"`)
		}
	case "ttl":
		if _, err := strconv.Atoi(step.Value); err != nil {
			return fmt.Errorf("ttl must be an integer")
		}
	}
	return nil
}

func validateDNSRecordIdentityOnly(name string) func(editAction) error {
	return func(step editAction) error {
		if strings.TrimSpace(step.Zone) == "" {
			return fmt.Errorf("%s requires zone", name)
		}
		if strings.TrimSpace(step.RecordName) == "" {
			return fmt.Errorf("%s requires record_name", name)
		}
		if strings.TrimSpace(step.RecordType) == "" {
			return fmt.Errorf("%s requires record_type", name)
		}
		return nil
	}
}

func validateSetDNSRecordTargetHost(step editAction) error {
	if err := validateDNSRecordIdentityOnly("set_dns_record_target_host")(step); err != nil {
		return err
	}
	if step.RecordType == "CNAME" {
		return fmt.Errorf("set_dns_record_target_host: CNAME records cannot use target_host")
	}
	if strings.TrimSpace(step.TargetHost) == "" {
		return fmt.Errorf("set_dns_record_target_host requires target_host")
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

// validateEnableRole is validateHostRoleAction("enable_role") plus
// host_vars validation: keys must be non-empty and non-secret-shaped,
// since host_vars/<host>.yml is plain YAML, not vault (secrets belong in
// add_vault_key instead).
func validateEnableRole(step editAction) error {
	if err := validateHostRoleAction("enable_role")(step); err != nil {
		return err
	}
	for key := range step.HostVars {
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("enable_role host_vars key must not be empty")
		}
		if hasSecretName(key) {
			return fmt.Errorf("secret-like host_vars keys are not allowed")
		}
	}
	return nil
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
		step.Inventory != "" || len(step.Answers) > 0 || step.User != ""
}

func validateNoParamsAction(name string) func(editAction) error {
	return func(step editAction) error {
		if editActionHasAnyParam(step) {
			return fmt.Errorf("%s does not accept parameters", name)
		}
		return nil
	}
}
