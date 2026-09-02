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

	"github.com/kjelly/pilot/internal/inventory"
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
				Description:              "set one supported non-secret host field; ansible_host on a freeipa-client host, changing between two IP literals, requires confirm (spec.md §11.7 — the Day-2 DNS-replacement acknowledgement)",
				Required:                 []string{"host", "field", "value"},
				Optional:                 []string{"confirm"},
				Values:                   map[string][]string{"field": {"ansible_host", "ansible_user", "ssh_key_file", "env", "deployment_availability"}},
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
				return d.setHostField(r, step.Host, step.Field, step.Value, step.Confirm)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "enable_role",
				Description:              "enable one role in a host role checklist; host_vars is required (not just optional) when role has its own required per-host settings with no safe default (e.g. prometheus needs host_vars.prometheus_site_label) — omitting it fails at run time, not at validation time, since whether a value is still missing depends on the workspace's existing host_vars/<host>.yml; value/value_env supplies the FreeIPA admin password when newly enabling freeipa-nfs-server triggers its own roster-bootstrap prompt",
				Required:                 []string{"host", "role"},
				Optional:                 []string{"host_vars", "value", "value_env"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingValueEnvRecommended,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "hosts.yml",
					Assertion: "role appears in host's role list",
				},
			},
			Validate: validateEnableRole,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.enableRole(r, step)
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
				Description:              "add a role preset's roles to a host's role set (host is the navigation entry point; role-presets.yml is shared, not host-specific); host_vars/value/value_env answer any forced prompt a newly-added role triggers (e.g. freeipa-nfs-server's roster bootstrap, prometheus's site label)",
				Required:                 []string{"host", "preset"},
				Optional:                 []string{"host_vars", "value", "value_env"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingValueEnvRecommended,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "hosts.yml",
					Assertion: "host's roles match preset definition",
				},
			},
			Validate: validateApplyRolePreset,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.applyRolePreset(r, step)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "copy_roles_from_host",
				Description:              "add another host's roles to this host's role set; host_vars/value/value_env answer any forced prompt a newly-added role triggers (e.g. freeipa-nfs-server's roster bootstrap, prometheus's site label)",
				Required:                 []string{"host", "source_host"},
				Optional:                 []string{"host_vars", "value", "value_env"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingValueEnvRecommended,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "hosts.yml",
					Assertion: "target host has identical roles to source",
				},
			},
			Validate: validateCopyRolesFromHost,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.copyRolesFromHost(r, step)
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
				Description:              "set one roster hostgroup field; membership.hosts accepts a comma-separated list of enrolled host FQDNs for semantic automation, and the interactive editor presents the same values as a multi-select checklist",
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
				Name:                     "set_hostgroup_hostgroups",
				Description:              "bulk-replace a hostgroup's membership.hostgroups (the whole set of nested hostgroups) — freeipa-identity-apply.yml reconciles this authoritatively alongside membership.hosts",
				Required:                 []string{"name"},
				Optional:                 []string{"hostgroups"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "hostgroup's membership.hostgroups matches the requested set",
				},
			},
			Validate: validateEntityNameOnly("set_hostgroup_hostgroups"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setHostgroupHostgroups(r, step.Name, step.Hostgroups)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "create_hbac_rule",
				Description:              "create an HBAC login rule (users/groups -> hosts/hostgroups -> PAM service), replaying the full creation wizard in one step. groups accepts team/role/legacy-access category groups",
				Required:                 []string{"name"},
				Optional:                 []string{"groups", "users", "hostgroups", "hosts", "services"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "HBAC rule appears in roster with the requested subjects/targets/services",
				},
			},
			Validate: validateEntityNameAndHosts("create_hbac_rule"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.createHBACRule(r, step.Name, step.Groups, step.Users, step.Hostgroups, step.Hosts, step.Services)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_hbac_groups",
				Description:              "bulk-replace an HBAC rule's subjects.groups (the whole set — team/role/legacy-access category groups only); preserves subjects.users",
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
				Name:                     "set_hbac_users",
				Description:              "bulk-replace an HBAC rule's subjects.users (the whole set — roster users or admin); preserves subjects.groups",
				Required:                 []string{"name"},
				Optional:                 []string{"users"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "HBAC rule's subjects.users matches the requested set",
				},
			},
			Validate: validateEntityNameOnly("set_hbac_users"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setHBACUsers(r, step.Name, step.Users)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_hbac_targets",
				Description:              "bulk-replace both of an HBAC rule's explicit target collections — targets.hostgroups and targets.hosts — clearing hostcat; omitting hosts defaults it to empty, matching this action's pre-existing hostgroups-only behavior",
				Required:                 []string{"name"},
				Optional:                 []string{"hostgroups", "hosts"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "HBAC rule's targets.hostgroups and targets.hosts match the requested sets",
				},
			},
			Validate: validateEntityNameAndHosts("set_hbac_targets"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setHBACTargets(r, step.Name, step.Hostgroups, step.Hosts)
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
				Name:                     "create_grant",
				Description:              "create a v3.0 access-governance grant (temporary_grant/sudo_grant/breakglass — spec.md §6), replaying the full kind-branching creation wizard in one step. breakglass forbids groups (a breakglass subject is always a direct named user) and services/validity/justification are kind-conditional per roster_grants.go's checkGrants",
				Required:                 []string{"name", "kind"},
				Optional:                 []string{"groups", "users", "hostgroups", "hosts", "services", "not_before", "not_after", "reason", "ticket", "max_duration"},
				Values:                   map[string][]string{"kind": {"temporary_grant", "sudo_grant", "breakglass"}},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "grant appears in roster with the requested kind/subjects/targets and kind-conditional fields",
				},
			},
			Validate: validateCreateGrant,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.createGrant(r, step.Kind, step.Name, step.Groups, step.Users, step.Hostgroups, step.Hosts, step.Services, step.NotBefore, step.NotAfter, step.Reason, step.Ticket, step.MaxDuration)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_grant_subjects",
				Description:              "bulk-replace a grant's subjects.users and subjects.groups (both sets, in one step — a breakglass grant's groups must stay empty)",
				Required:                 []string{"name"},
				Optional:                 []string{"users", "groups"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "grant's subjects.users/subjects.groups match the requested sets",
				},
			},
			Validate: validateEntityNameOnly("set_grant_subjects"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setGrantSubjects(r, step.Name, step.Users, step.Groups)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_grant_targets",
				Description:              "bulk-replace a grant's targets.hostgroups and targets.hosts (both sets, in one step)",
				Required:                 []string{"name"},
				Optional:                 []string{"hostgroups", "hosts"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "grant's targets.hostgroups/targets.hosts match the requested sets",
				},
			},
			Validate: validateEntityNameAndHosts("set_grant_targets"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setGrantTargets(r, step.Name, step.Hostgroups, step.Hosts)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_grant_validity",
				Description:              "set a temporary_grant/sudo_grant's validity.not_before (optional, RFC3339) and validity.not_after (required, RFC3339) — not applicable to breakglass, which has no validity window (spec.md §6.3)",
				Required:                 []string{"name", "not_after"},
				Optional:                 []string{"not_before"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "grant's validity.not_before/not_after match the requested values",
				},
			},
			Validate: validateSetGrantValidity,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setGrantValidity(r, step.Name, step.NotBefore, step.NotAfter)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_grant_justification",
				Description:              "set a temporary_grant/sudo_grant's justification.reason (required) and justification.ticket (optional) — not applicable to breakglass",
				Required:                 []string{"name", "reason"},
				Optional:                 []string{"ticket"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "grant's justification.reason/justification.ticket match the requested values",
				},
			},
			Validate: validateSetGrantJustification,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setGrantJustification(r, step.Name, step.Reason, step.Ticket)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_grant_privilege",
				Description:              "bulk-replace a sudo_grant's privilege.command_groups (an empty set compiles to command_category: all, matching create_grant's own default — see CompileSudoGrant); free-form privilege.commands is out of this action's scope, author those directly in the roster",
				Required:                 []string{"name"},
				Optional:                 []string{"command_groups"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "grant's privilege.command_groups matches the requested set",
				},
			},
			Validate: validateEntityNameOnly("set_grant_privilege"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setGrantPrivilege(r, step.Name, step.CommandGroups)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_grant_activation",
				Description:              "set a kind: breakglass grant's activation.max_duration (spec.md §6.3/§17: `set_grant_activation`, breakglass only — the runtime-window cap enforced by activate_breakglass; not applicable to temporary_grant/sudo_grant, which use set_grant_validity instead)",
				Required:                 []string{"name", "max_duration"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "grant's activation.max_duration matches the requested value",
				},
			},
			Validate: validateSetGrantActivation,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setGrantActivation(r, step.Name, step.MaxDuration)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "delete_grant",
				Description:              "soft-delete a grant (state: absent — grants are declarative like every other roster entity here, never physically removed by this action)",
				Required:                 []string{"name"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectDestructive,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "grant's state is absent",
				},
			},
			Validate: validateEntityNameOnly("delete_grant"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.deleteGrant(r, step.Name)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "activate_breakglass",
				Description:              "activate a kind: breakglass grant for a bounded duration (spec.md §14) — duration must not exceed the grant's own activation.max_duration; reason/ticket are required unless the grant's activation explicitly disables require_reason/require_ticket. Applies one compiled HBAC rule immediately (not a full grants reconcile) and records the activation in local state — never rewrites the grant definition",
				Required:                 []string{"name", "duration"},
				Optional:                 []string{"reason", "ticket", "inventory"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "breakglass grant definition is unchanged; activation is recorded in local state, not the roster",
				},
			},
			Validate: validateActivateBreakglass,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.activateBreakglass(r, step.Name, step.Duration, step.Reason, step.Ticket)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "deactivate_breakglass",
				Description:              "end a breakglass grant's active authorization early (idempotent — a no-op if nothing is currently active)",
				Required:                 []string{"name"},
				Optional:                 []string{"inventory"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectDestructive,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "breakglass grant's activation is marked deactivated in local state",
				},
			},
			Validate: validateEntityNameOnly("deactivate_breakglass"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.deactivateBreakglass(r, step.Name)
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
				Name:                     "create_internal_endpoint_manifest",
				Description:              "create the minimal internal-endpoints manifest skeleton (only way to produce the file at all) — declares no freeipa identity block, unlike freeipa-dns",
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "internal-endpoints.yaml",
					Assertion: "manifest file created with an empty endpoints list",
				},
			},
			Validate: validateNoParamsAction("create_internal_endpoint_manifest"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.createInternalEndpointManifest(r)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "create_internal_endpoint",
				Description:              "create an internal-endpoint (direct route, tls.mode: disabled by default — use set_internal_endpoint_route_proxy/set_internal_endpoint_tls_freeipa afterward to change either)",
				Required:                 []string{"fqdn", "zone", "target_host"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "internal-endpoints.yaml",
					Assertion: "endpoint appears in the manifest with the requested fqdn/zone/target",
				},
			},
			Validate: validateCreateInternalEndpoint,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.createInternalEndpoint(r, step.FQDN, step.Zone, step.TargetHost)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_internal_endpoint_state",
				Description:              "set an internal-endpoint's state; state:absent is a safe declarative delete request — real deletion happens later at apply time behind its own safety.allow_endpoint_delete/confirm_endpoint_delete gates",
				Required:                 []string{"fqdn", "value"},
				Values:                   map[string][]string{"value": {"present", "absent"}},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "internal-endpoints.yaml",
					Assertion: "endpoint state updated; state:absent only takes effect at apply time",
				},
			},
			Validate: validateSetInternalEndpointState,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setInternalEndpointState(r, step.FQDN, step.Value)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_internal_endpoint_dns",
				Description:              "set an internal-endpoint's dns.zone and (optionally) dns.ttl together",
				Required:                 []string{"fqdn", "zone"},
				Optional:                 []string{"dns_ttl"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "internal-endpoints.yaml",
					Assertion: "endpoint dns.zone/dns.ttl updated",
				},
			},
			Validate: validateSetInternalEndpointDNS,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setInternalEndpointDNS(r, step.FQDN, step.Zone, step.DNSTTL)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_internal_endpoint_route_direct",
				Description:              "set an internal-endpoint's route to direct mode; exactly one of target_host (resolved via hosts.yml) or target_address (literal IP) must be set",
				Required:                 []string{"fqdn"},
				Optional:                 []string{"target_host", "target_address"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "internal-endpoints.yaml",
					Assertion: "endpoint route set to direct with the requested target",
				},
			},
			Validate: validateSetInternalEndpointRouteDirect,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setInternalEndpointRouteDirect(r, step.FQDN, step.TargetHost, step.TargetAddress)
			},
		},
		{
			Spec: semanticActionSpec{
				Name: "set_internal_endpoint_route_proxy",
				Description: "set an internal-endpoint's route to reverse_proxy mode; exactly one of upstream_host/upstream_address must be set; " +
					"upstream_tls_verify is required when upstream_scheme=https and rejected when http (spec.md §12.4.1/§12.4.4)",
				Required:                 []string{"fqdn", "proxy_host", "upstream_scheme", "upstream_port"},
				Optional:                 []string{"upstream_host", "upstream_address", "upstream_tls_verify", "upstream_sni"},
				Values:                   map[string][]string{"upstream_scheme": {"http", "https"}, "upstream_tls_verify": {"true", "false"}},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "internal-endpoints.yaml",
					Assertion: "endpoint route set to reverse_proxy with the requested proxy/upstream",
				},
			},
			Validate: validateSetInternalEndpointRouteProxy,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setInternalEndpointRouteProxy(r, step.FQDN, step.ProxyHost, step.UpstreamScheme, step.UpstreamHost, step.UpstreamAddress, step.UpstreamPort, step.UpstreamTLSVerify, step.UpstreamSNI)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_internal_endpoint_tls_disabled",
				Description:              "disable TLS termination for an internal-endpoint's frontend (independent of any upstream TLS, spec.md §14)",
				Required:                 []string{"fqdn"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "internal-endpoints.yaml",
					Assertion: "endpoint tls.mode set to disabled",
				},
			},
			Validate: validateFQDNOnly("set_internal_endpoint_tls_disabled"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setInternalEndpointTLSDisabled(r, step.FQDN)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_internal_endpoint_tls_freeipa",
				Description:              "enable FreeIPA-issued TLS termination for an internal-endpoint's frontend; tls_port is optional (0/absent means the scheme default, spec.md §14)",
				Required:                 []string{"fqdn"},
				Optional:                 []string{"tls_port"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "internal-endpoints.yaml",
					Assertion: "endpoint tls.mode set to freeipa (and tls.port, if requested)",
				},
			},
			Validate: validateSetInternalEndpointTLSFreeIPA,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setInternalEndpointTLSFreeIPA(r, step.FQDN, step.TLSPort)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_internal_endpoint_tls_sink",
				Description:              "set a direct+tls.freeipa endpoint's certificate sink (spec.md §22) — only valid once route.mode=direct and tls.mode=freeipa are already set",
				Required:                 []string{"fqdn", "cert_file", "key_file", "reload_unit"},
				Optional:                 []string{"key_owner", "key_group", "key_mode"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "internal-endpoints.yaml",
					Assertion: "endpoint tls.sink updated with the requested cert/key/reload unit",
				},
			},
			Validate: validateSetInternalEndpointTLSSink,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setInternalEndpointTLSSink(r, step.FQDN, step.CertFile, step.KeyFile, step.KeyOwner, step.KeyGroup, step.KeyMode, step.ReloadUnit)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "create_monitoring_target",
				Description:              "add an external monitoring target — an address Prometheus scrapes that Pilot does not manage via Ansible/SSH (spec.md §2/§8); profile must already exist (spec.md §35)",
				Required:                 []string{"name", "address", "profile"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "monitoring/targets.yml",
					Assertion: "target appears in the registry with the requested address/profile",
				},
			},
			Validate: validateCreateMonitoringTarget,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.createMonitoringTarget(r, step.Name, step.Address, step.Profile)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_monitoring_target_address",
				Description:              "change a monitoring target's address (host:port)",
				Required:                 []string{"name", "address"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "monitoring/targets.yml",
					Assertion: "target address updated",
				},
			},
			Validate: validateMonitoringTargetNameAnd("address"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setMonitoringTargetAddress(r, step.Name, step.Address)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_monitoring_target_profile",
				Description:              "change which scrape profile a monitoring target uses (must already exist, spec.md §35)",
				Required:                 []string{"name", "profile"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "monitoring/targets.yml",
					Assertion: "target profile updated",
				},
			},
			Validate: validateMonitoringTargetNameAnd("profile"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setMonitoringTargetProfile(r, step.Name, step.Profile)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_monitoring_target_site",
				Description:              "set a monitoring target's logical site label (spec.md §8.4); value may be empty to clear it",
				Required:                 []string{"name"},
				Optional:                 []string{"site"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "monitoring/targets.yml",
					Assertion: "target site updated",
				},
			},
			Validate: validateEntityNameOnly("set_monitoring_target_site"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setMonitoringTargetSite(r, step.Name, step.Site)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_monitoring_target_label",
				Description:              "add or update one label on a monitoring target (key/value reuse the generic key/value fields); reserved keys pilot_target/pilot_source are rejected at validate time (spec.md §8.6)",
				Required:                 []string{"name", "key", "value"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "monitoring/targets.yml",
					Assertion: "target label added/updated with the requested key/value",
				},
			},
			Validate: validateSetMonitoringTargetLabel,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setMonitoringTargetLabel(r, step.Name, step.Key, step.Value)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "enable_monitoring_target",
				Description:              "enable a monitoring target (default state; makes it appear in Prometheus file_sd output, spec.md §8.5)",
				Required:                 []string{"name"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "monitoring/targets.yml",
					Assertion: "target enabled",
				},
			},
			Validate: validateEntityNameOnly("enable_monitoring_target"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setMonitoringTargetEnabled(r, step.Name, true)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "disable_monitoring_target",
				Description:              "disable a monitoring target — kept in the registry, excluded from Prometheus file_sd output (spec.md §8.5)",
				Required:                 []string{"name"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "monitoring/targets.yml",
					Assertion: "target disabled",
				},
			},
			Validate: validateEntityNameOnly("disable_monitoring_target"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setMonitoringTargetEnabled(r, step.Name, false)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "delete_monitoring_target",
				Description:              "remove a monitoring target from the registry (registry only — no remote host action, spec.md §28)",
				Required:                 []string{"name"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectDestructive,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "monitoring/targets.yml",
					Assertion: "target no longer present in the registry",
				},
			},
			Validate: validateEntityNameOnly("delete_monitoring_target"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.deleteMonitoringTarget(r, step.Name)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "create_monitoring_profile",
				Description:              "add a scrape profile (shared scrape behavior referenced by name from monitoring targets, spec.md §9-11)",
				Required:                 []string{"name", "job_name"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "monitoring/scrape-profiles.yml",
					Assertion: "profile appears in the registry with the requested jobName",
				},
			},
			Validate: validateCreateMonitoringProfile,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.createMonitoringProfile(r, step.Name, step.JobName)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_monitoring_profile_job_name",
				Description:              "rename a scrape profile's Prometheus job_name (must stay globally unique and non-reserved: prometheus/node, spec.md §18/§63)",
				Required:                 []string{"name", "job_name"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "monitoring/scrape-profiles.yml",
					Assertion: "profile jobName updated",
				},
			},
			Validate: validateMonitoringProfileNameAnd("job_name"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setMonitoringProfileJobName(r, step.Name, step.JobName)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_monitoring_profile_scheme",
				Description:              "set a scrape profile's scheme",
				Required:                 []string{"name", "scheme"},
				Values:                   map[string][]string{"scheme": {"http", "https"}},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "monitoring/scrape-profiles.yml",
					Assertion: "profile scheme updated",
				},
			},
			Validate: validateSetMonitoringProfileScheme,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setMonitoringProfileScheme(r, step.Name, step.Scheme)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_monitoring_profile_metrics_path",
				Description:              "set a scrape profile's metrics HTTP path (default /metrics, spec.md §10)",
				Required:                 []string{"name", "metrics_path"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "monitoring/scrape-profiles.yml",
					Assertion: "profile metricsPath updated",
				},
			},
			Validate: validateMonitoringProfileNameAnd("metrics_path"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setMonitoringProfileMetricsPath(r, step.Name, step.MetricsPath)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_monitoring_profile_scrape_interval",
				Description:              "set a scrape profile's scrape interval (e.g. 15s; empty uses the Prometheus global default, spec.md §10)",
				Required:                 []string{"name"},
				Optional:                 []string{"scrape_interval"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "monitoring/scrape-profiles.yml",
					Assertion: "profile scrapeInterval updated",
				},
			},
			Validate: validateEntityNameOnly("set_monitoring_profile_scrape_interval"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setMonitoringProfileTextField(r, step.Name, "scrapeInterval", step.ScrapeInterval)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_monitoring_profile_scrape_timeout",
				Description:              "set a scrape profile's scrape timeout (e.g. 10s; empty uses the Prometheus global default, spec.md §10)",
				Required:                 []string{"name"},
				Optional:                 []string{"scrape_timeout"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "monitoring/scrape-profiles.yml",
					Assertion: "profile scrapeTimeout updated",
				},
			},
			Validate: validateEntityNameOnly("set_monitoring_profile_scrape_timeout"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setMonitoringProfileTextField(r, step.Name, "scrapeTimeout", step.ScrapeTimeout)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_monitoring_profile_auth_ref",
				Description:              "set a scrape profile's authRef — a reference into the monitoring_auth vault-backed secret map (spec.md §12/§46); this action never carries a secret value itself",
				Required:                 []string{"name"},
				Optional:                 []string{"auth_ref"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "monitoring/scrape-profiles.yml",
					Assertion: "profile authRef updated",
				},
			},
			Validate: validateEntityNameOnly("set_monitoring_profile_auth_ref"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setMonitoringProfileTextField(r, step.Name, "authRef", step.AuthRef)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_monitoring_profile_tls",
				Description:              "set a scrape profile's TLS options; tls_server_name and/or tls_insecure_skip_verify may be given independently (spec.md §44) — insecureSkipVerify:true is flagged as a warning, not blocked, at validate time",
				Required:                 []string{"name"},
				Optional:                 []string{"tls_server_name", "tls_insecure_skip_verify"},
				Values:                   map[string][]string{"tls_insecure_skip_verify": {"true", "false"}},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "monitoring/scrape-profiles.yml",
					Assertion: "profile tls settings updated",
				},
			},
			Validate: validateSetMonitoringProfileTLS,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setMonitoringProfileTLS(r, step.Name, step.TLSServerName, step.TLSInsecureSkipVerify)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "delete_monitoring_profile",
				Description:              "remove a scrape profile — refused if any target still references it (spec.md §50, no cascade delete)",
				Required:                 []string{"name"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectDestructive,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      "monitoring/scrape-profiles.yml",
					Assertion: "profile no longer present in the registry",
				},
			},
			Validate: validateEntityNameOnly("delete_monitoring_profile"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.deleteMonitoringProfile(r, step.Name)
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
		// ---- v3.2 Identity & Credential Hardening (spec.md §18) --------
		{
			Spec: semanticActionSpec{
				Name:                     "create_password_policy",
				Description:              "create a FreeIPA group password policy (spec.md §7) — group/priority are co-required and set together at creation, since a password_policy missing either never passes roster validation",
				Required:                 []string{"name", "group", "priority"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "password_policy appears in roster with group/priority set",
				},
			},
			Validate: validateCreatePasswordPolicy,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.createPasswordPolicy(r, step.Name, step.Group, step.Priority)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:        "set_password_policy_field",
				Description: "set one password_policies[] field",
				Required:    []string{"name", "field", "value"},
				Values: map[string][]string{"field": {
					"state", "group", "priority", "min_length", "history_size", "max_life", "min_life",
					"lockout.max_failures", "lockout.failure_reset_interval", "lockout.lockout_duration",
				}},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "field value updated for password_policy",
				},
			},
			Validate: validateSetPasswordPolicyField,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setPasswordPolicyField(r, step.Name, step.Field, step.Value)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "delete_password_policy",
				Description:              "soft-delete a password_policy (state: absent — never physically removed by this action)",
				Required:                 []string{"name"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectDestructive,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "password_policy's state is absent",
				},
			},
			Validate: validateEntityNameOnly("delete_password_policy"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.deletePasswordPolicy(r, step.Name)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "set_user_authentication_types",
				Description:              "bulk-replace a user's authentication.allowed (spec.md §8) — the whole set, not one item; empty clears the authentication: block entirely",
				Required:                 []string{"user"},
				Optional:                 []string{"users"},
				Values:                   map[string][]string{"users": inventory.KnownUserAuthTypes()},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "user's authentication.allowed matches the requested set",
				},
			},
			Validate: validateSetUserAuthenticationTypes,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.setUserAuthenticationTypes(r, step.User, step.Users)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "create_credential_policy",
				Description:              "create a credential_policy (spec.md §10/§11 SSH hygiene + review) — match.users/match.groups are required before it can pass validation",
				Required:                 []string{"name"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "credential_policy appears in roster",
				},
			},
			Validate: validateEntityNameOnly("create_credential_policy"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.createCredentialPolicy(r, step.Name)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:        "set_credential_policy_field",
				Description: "set one credential_policy field, or bulk-replace match.users/match.groups (Users/Groups, not Value, for those two)",
				Required:    []string{"name", "field"},
				Values: map[string][]string{"field": {
					"state", "match.users", "match.groups", "ssh.allowed_algorithms", "ssh.require_comment", "ssh.max_age",
				}},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectWrite,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "field value updated for credential_policy",
				},
			},
			Validate: validateSetCredentialPolicyField,
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				if step.Field == "match.users" {
					return d.setCredentialPolicyMembers(r, step.Name, step.Field, step.Users)
				}
				if step.Field == "match.groups" {
					return d.setCredentialPolicyMembers(r, step.Name, step.Field, step.Groups)
				}
				return d.setCredentialPolicyField(r, step.Name, step.Field, step.Value)
			},
		},
		{
			Spec: semanticActionSpec{
				Name:                     "delete_credential_policy",
				Description:              "soft-delete a credential_policy (state: absent — never physically removed by this action)",
				Required:                 []string{"name"},
				ExecutionMode:            ExecutionModeStructured,
				SideEffectClassification: SideEffectDestructive,
				SecretHandling:           SecretHandlingNone,
				Verification: &verificationSpec{
					Method:    verificationMethodFileContent,
					Path:      ".vault/ipa-identity.yaml",
					Assertion: "credential_policy's state is absent",
				},
			},
			Validate: validateEntityNameOnly("delete_credential_policy"),
			Run: func(d *automationDriver, r *editRouterModel, step editAction) error {
				return d.deleteCredentialPolicy(r, step.Name)
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
	if step.Field == "deployment_availability" {
		value := inventory.DeploymentAvailability(step.Value)
		if value != inventory.DeploymentAvailabilityRequired && value != inventory.DeploymentAvailabilityOptional {
			return fmt.Errorf("unsupported deployment_availability value %q", step.Value)
		}
	}
	if step.Confirm != "" && step.Confirm != "yes" && step.Confirm != "no" {
		return fmt.Errorf("set_host_field confirm must be %q or %q", "yes", "no")
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
	if inventory.IsDeprecatedGroupCategory(step.Category) {
		return fmt.Errorf("create_group: category %q is deprecated and cannot be created; use team or role for HBAC subjects", step.Category)
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

// validateEntityNameAndHosts is validateEntityNameOnly plus a check that
// every entry in step.Hosts is FQDN-shaped — the action-level rejection
// spec.md §7.5/§12.6 requires for obviously malformed direct-host values
// before ever driving the TUI with them. Entity/referential validation
// (e.g. whether the host is actually enrolled) remains authoritative in
// Simulate*/roster validation, not here.
func validateEntityNameAndHosts(name string) func(editAction) error {
	return func(step editAction) error {
		if err := validateEntityNameOnly(name)(step); err != nil {
			return err
		}
		for _, h := range step.Hosts {
			if !inventory.ValidRosterHostFQDN(h) {
				return fmt.Errorf("%s: hosts entry %q is not FQDN-shaped", name, h)
			}
		}
		return nil
	}
}

// validateCreateGrant checks create_grant's structural preconditions
// (name, kind enum, FQDN-shaped hosts) before ever driving the TUI —
// roster_grants.go's checkGrants remains authoritative for the
// kind-conditional field requirements (e.g. temporary_grant/sudo_grant
// needing validity/justification) once the write actually happens.
func validateCreateGrant(step editAction) error {
	if err := validateEntityNameAndHosts("create_grant")(step); err != nil {
		return err
	}
	switch step.Kind {
	case "temporary_grant", "sudo_grant", "breakglass":
	default:
		return fmt.Errorf("create_grant requires kind to be one of temporary_grant/sudo_grant/breakglass, got %q", step.Kind)
	}
	return nil
}

func validateSetGrantValidity(step editAction) error {
	if err := validateEntityNameOnly("set_grant_validity")(step); err != nil {
		return err
	}
	if strings.TrimSpace(step.NotAfter) == "" {
		return fmt.Errorf("set_grant_validity requires not_after")
	}
	return nil
}

func validateSetGrantJustification(step editAction) error {
	if err := validateEntityNameOnly("set_grant_justification")(step); err != nil {
		return err
	}
	if strings.TrimSpace(step.Reason) == "" {
		return fmt.Errorf("set_grant_justification requires reason")
	}
	return nil
}

func validateSetGrantActivation(step editAction) error {
	if err := validateEntityNameOnly("set_grant_activation")(step); err != nil {
		return err
	}
	if !inventory.ValidAccessDuration(strings.TrimSpace(step.MaxDuration)) {
		return fmt.Errorf("set_grant_activation requires max_duration in <count>m|h|d form (e.g. 30m, 1h, 7d), got %q", step.MaxDuration)
	}
	return nil
}

func validateActivateBreakglass(step editAction) error {
	if err := validateEntityNameOnly("activate_breakglass")(step); err != nil {
		return err
	}
	if !inventory.ValidAccessDuration(strings.TrimSpace(step.Duration)) {
		return fmt.Errorf("activate_breakglass requires duration in <count>m|h|d form (e.g. 30m, 1h, 7d), got %q", step.Duration)
	}
	return nil
}

func validateCreateMonitoringTarget(step editAction) error {
	if strings.TrimSpace(step.Name) == "" {
		return fmt.Errorf("create_monitoring_target requires name")
	}
	if strings.TrimSpace(step.Address) == "" {
		return fmt.Errorf("create_monitoring_target requires address")
	}
	if strings.TrimSpace(step.Profile) == "" {
		return fmt.Errorf("create_monitoring_target requires profile")
	}
	return nil
}

// validateMonitoringTargetNameAnd is set_monitoring_target_address/-profile's
// shared validator factory: name plus exactly one other named field, both
// required — the monitoring counterpart to validateFQDNOnly's single-field
// pattern, generalized to two fields since these two actions (unlike
// set_monitoring_target_site, which allows an empty value to clear the
// field) always require a real replacement value.
func validateMonitoringTargetNameAnd(field string) func(editAction) error {
	return func(step editAction) error {
		if strings.TrimSpace(step.Name) == "" {
			return fmt.Errorf("set_monitoring_target_%s requires name", field)
		}
		var value string
		switch field {
		case "address":
			value = step.Address
		case "profile":
			value = step.Profile
		}
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("set_monitoring_target_%s requires %s", field, field)
		}
		return nil
	}
}

func validateSetMonitoringTargetLabel(step editAction) error {
	if strings.TrimSpace(step.Name) == "" {
		return fmt.Errorf("set_monitoring_target_label requires name")
	}
	if strings.TrimSpace(step.Key) == "" {
		return fmt.Errorf("set_monitoring_target_label requires key")
	}
	if step.Value == "" {
		return fmt.Errorf("set_monitoring_target_label requires value")
	}
	return nil
}

func validateCreateMonitoringProfile(step editAction) error {
	if strings.TrimSpace(step.Name) == "" {
		return fmt.Errorf("create_monitoring_profile requires name")
	}
	if strings.TrimSpace(step.JobName) == "" {
		return fmt.Errorf("create_monitoring_profile requires job_name")
	}
	return nil
}

// validateMonitoringProfileNameAnd mirrors validateMonitoringTargetNameAnd
// for the profile fields that always require a real replacement value
// (job_name, metrics_path) rather than allowing an empty clear
// (scrape_interval/scrape_timeout/auth_ref use validateEntityNameOnly
// instead, since "" is a legitimate "use the default" value for those).
func validateMonitoringProfileNameAnd(field string) func(editAction) error {
	return func(step editAction) error {
		if strings.TrimSpace(step.Name) == "" {
			return fmt.Errorf("set_monitoring_profile_%s requires name", field)
		}
		var value string
		switch field {
		case "job_name":
			value = step.JobName
		case "metrics_path":
			value = step.MetricsPath
		}
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("set_monitoring_profile_%s requires %s", field, field)
		}
		return nil
	}
}

func validateSetMonitoringProfileScheme(step editAction) error {
	if strings.TrimSpace(step.Name) == "" {
		return fmt.Errorf("set_monitoring_profile_scheme requires name")
	}
	if step.Scheme != "http" && step.Scheme != "https" {
		return fmt.Errorf(`set_monitoring_profile_scheme requires scheme "http" or "https"`)
	}
	return nil
}

func validateSetMonitoringProfileTLS(step editAction) error {
	if strings.TrimSpace(step.Name) == "" {
		return fmt.Errorf("set_monitoring_profile_tls requires name")
	}
	if step.TLSServerName == "" && step.TLSInsecureSkipVerify == "" {
		return fmt.Errorf("set_monitoring_profile_tls requires tls_server_name and/or tls_insecure_skip_verify")
	}
	if step.TLSInsecureSkipVerify != "" && step.TLSInsecureSkipVerify != "true" && step.TLSInsecureSkipVerify != "false" {
		return fmt.Errorf(`set_monitoring_profile_tls requires tls_insecure_skip_verify "true" or "false"`)
	}
	return nil
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

func validateCreateInternalEndpoint(step editAction) error {
	if strings.TrimSpace(step.FQDN) == "" {
		return fmt.Errorf("create_internal_endpoint requires fqdn")
	}
	if strings.TrimSpace(step.Zone) == "" {
		return fmt.Errorf("create_internal_endpoint requires zone")
	}
	if strings.TrimSpace(step.TargetHost) == "" {
		return fmt.Errorf("create_internal_endpoint requires target_host")
	}
	return nil
}

// validateFQDNOnly is internal-endpoint's counterpart to
// validateDNSZoneNameOnly/validateEntityNameOnly: a factory for actions
// whose only required identity field is fqdn.
func validateFQDNOnly(name string) func(editAction) error {
	return func(step editAction) error {
		if strings.TrimSpace(step.FQDN) == "" {
			return fmt.Errorf("%s requires fqdn", name)
		}
		return nil
	}
}

func validateSetInternalEndpointState(step editAction) error {
	if strings.TrimSpace(step.FQDN) == "" {
		return fmt.Errorf("set_internal_endpoint_state requires fqdn")
	}
	if step.Value != "present" && step.Value != "absent" {
		return fmt.Errorf(`set_internal_endpoint_state requires value "present" or "absent"`)
	}
	return nil
}

func validateSetInternalEndpointDNS(step editAction) error {
	if strings.TrimSpace(step.FQDN) == "" {
		return fmt.Errorf("set_internal_endpoint_dns requires fqdn")
	}
	if strings.TrimSpace(step.Zone) == "" {
		return fmt.Errorf("set_internal_endpoint_dns requires zone")
	}
	if step.DNSTTL != "" {
		if _, err := strconv.Atoi(step.DNSTTL); err != nil {
			return fmt.Errorf("dns_ttl must be an integer")
		}
	}
	return nil
}

func validateSetInternalEndpointRouteDirect(step editAction) error {
	if strings.TrimSpace(step.FQDN) == "" {
		return fmt.Errorf("set_internal_endpoint_route_direct requires fqdn")
	}
	hasHost := strings.TrimSpace(step.TargetHost) != ""
	hasAddress := strings.TrimSpace(step.TargetAddress) != ""
	if hasHost == hasAddress {
		return fmt.Errorf("set_internal_endpoint_route_direct requires exactly one of target_host or target_address")
	}
	return nil
}

func validateSetInternalEndpointRouteProxy(step editAction) error {
	if strings.TrimSpace(step.FQDN) == "" {
		return fmt.Errorf("set_internal_endpoint_route_proxy requires fqdn")
	}
	if strings.TrimSpace(step.ProxyHost) == "" {
		return fmt.Errorf("set_internal_endpoint_route_proxy requires proxy_host")
	}
	if step.UpstreamScheme != "http" && step.UpstreamScheme != "https" {
		return fmt.Errorf(`set_internal_endpoint_route_proxy requires upstream_scheme "http" or "https"`)
	}
	if strings.TrimSpace(step.UpstreamPort) == "" {
		return fmt.Errorf("set_internal_endpoint_route_proxy requires upstream_port")
	}
	if port, err := strconv.Atoi(step.UpstreamPort); err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("upstream_port must be a valid TCP port")
	}
	hasHost := strings.TrimSpace(step.UpstreamHost) != ""
	hasAddress := strings.TrimSpace(step.UpstreamAddress) != ""
	if hasHost == hasAddress {
		return fmt.Errorf("set_internal_endpoint_route_proxy requires exactly one of upstream_host or upstream_address")
	}
	// spec.md §12.4.1/§12.4.4: upstream_tls_verify is meaningful only for
	// an https upstream and must not be silently ignored for an http one.
	switch step.UpstreamScheme {
	case "https":
		if step.UpstreamTLSVerify != "true" && step.UpstreamTLSVerify != "false" {
			return fmt.Errorf(`set_internal_endpoint_route_proxy requires upstream_tls_verify "true" or "false" when upstream_scheme is https`)
		}
	case "http":
		if step.UpstreamTLSVerify != "" {
			return fmt.Errorf("set_internal_endpoint_route_proxy: upstream_tls_verify is not allowed when upstream_scheme is http")
		}
	}
	return nil
}

func validateSetInternalEndpointTLSFreeIPA(step editAction) error {
	if strings.TrimSpace(step.FQDN) == "" {
		return fmt.Errorf("set_internal_endpoint_tls_freeipa requires fqdn")
	}
	if step.TLSPort != "" {
		if port, err := strconv.Atoi(step.TLSPort); err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("tls_port must be a valid TCP port")
		}
	}
	return nil
}

func validateSetInternalEndpointTLSSink(step editAction) error {
	if strings.TrimSpace(step.FQDN) == "" {
		return fmt.Errorf("set_internal_endpoint_tls_sink requires fqdn")
	}
	if strings.TrimSpace(step.CertFile) == "" {
		return fmt.Errorf("set_internal_endpoint_tls_sink requires cert_file")
	}
	if strings.TrimSpace(step.KeyFile) == "" {
		return fmt.Errorf("set_internal_endpoint_tls_sink requires key_file")
	}
	if strings.TrimSpace(step.ReloadUnit) == "" {
		return fmt.Errorf("set_internal_endpoint_tls_sink requires reload_unit")
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

// validateHostVarsMap is validateEnableRole's host_vars check, shared with
// apply_role_preset/copy_roles_from_host since all three can trigger the
// same pushForcedHostVarsPrompt detour (resolveRoleChangeFollowUp).
func validateHostVarsMap(step editAction) error {
	for key := range step.HostVars {
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("host_vars key must not be empty")
		}
		if hasSecretName(key) {
			return fmt.Errorf("secret-like host_vars keys are not allowed")
		}
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
	if err := validateHostVarsMap(step); err != nil {
		return err
	}
	return validateOptionalValueOrEnv(step, "apply_role_preset")
}

func validateCopyRolesFromHost(step editAction) error {
	if strings.TrimSpace(step.Host) == "" {
		return fmt.Errorf("copy_roles_from_host requires host")
	}
	if strings.TrimSpace(step.SourceHost) == "" {
		return fmt.Errorf("copy_roles_from_host requires source_host")
	}
	if err := validateHostVarsMap(step); err != nil {
		return err
	}
	if err := validateOptionalValueOrEnv(step, "copy_roles_from_host"); err != nil {
		return err
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
	if err := validateHostVarsMap(step); err != nil {
		return err
	}
	return validateOptionalValueOrEnv(step, "enable_role")
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

// ---- v3.2 Identity & Credential Hardening validators (spec.md §18) -----

func validateCreatePasswordPolicy(step editAction) error {
	if strings.TrimSpace(step.Name) == "" {
		return fmt.Errorf("create_password_policy requires name")
	}
	if strings.TrimSpace(step.Group) == "" {
		return fmt.Errorf("create_password_policy requires group")
	}
	if strings.TrimSpace(step.Priority) == "" {
		return fmt.Errorf("create_password_policy requires priority")
	}
	if n, err := strconv.Atoi(step.Priority); err != nil || n <= 0 {
		return fmt.Errorf("create_password_policy: priority must be a positive integer")
	}
	return nil
}

func validateSetPasswordPolicyField(step editAction) error {
	if strings.TrimSpace(step.Name) == "" {
		return fmt.Errorf("set_password_policy_field requires name")
	}
	if strings.TrimSpace(step.Field) == "" {
		return fmt.Errorf("set_password_policy_field requires field")
	}
	spec, _ := semanticActionSpecFor("set_password_policy_field")
	allowed := false
	for _, field := range spec.Values["field"] {
		if step.Field == field {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("unsupported password_policy field %q", step.Field)
	}
	if step.Field != "state" && step.Value == "" && step.ValueEnv == "" {
		return fmt.Errorf("set_password_policy_field requires value (or value_env)")
	}
	return nil
}

func validateSetUserAuthenticationTypes(step editAction) error {
	if strings.TrimSpace(step.User) == "" {
		return fmt.Errorf("set_user_authentication_types requires user")
	}
	spec, _ := semanticActionSpecFor("set_user_authentication_types")
	for _, t := range step.Users {
		allowed := false
		for _, known := range spec.Values["users"] {
			if t == known {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("set_user_authentication_types: unsupported authentication type %q", t)
		}
	}
	return nil
}

func validateSetCredentialPolicyField(step editAction) error {
	if strings.TrimSpace(step.Name) == "" {
		return fmt.Errorf("set_credential_policy_field requires name")
	}
	if strings.TrimSpace(step.Field) == "" {
		return fmt.Errorf("set_credential_policy_field requires field")
	}
	spec, _ := semanticActionSpecFor("set_credential_policy_field")
	allowed := false
	for _, field := range spec.Values["field"] {
		if step.Field == field {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("unsupported credential_policy field %q", step.Field)
	}
	switch step.Field {
	case "match.users", "match.groups":
		// Users/Groups carries the bulk-replace selection for these two —
		// an empty selection (clearing membership down to nothing) is
		// valid, so no non-empty check here.
	default:
		if step.Value == "" && step.ValueEnv == "" {
			return fmt.Errorf("set_credential_policy_field requires value (or value_env) for field %q", step.Field)
		}
	}
	return nil
}
