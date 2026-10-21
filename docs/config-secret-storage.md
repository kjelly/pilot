# Inventory settings and external secrets

`group_vars/**` and `host_vars/**` contain nonsecret configuration and references.
Pilot rejects credential values in both trees before editing, planning, validating
or deploying. Private repositories follow the same rule. Nested YAML maps, lists,
aliases, merges and embedded YAML configurations are checked too. Encrypted
Ansible Vault files and `!vault` values also belong outside these directories.

Component contracts identify secret inputs, including inputs whose names do not
say “password”. Ansible connection credentials and undeclared credential names
(including SNMP community/authentication/privacy passwords) are checked as well.
Diagnostics identify the file, field path and line without printing its value.
Vault, SNMP credential and roster editors also require their source files to be
outside both vars trees, including paths reached through symlinks or file aliases.
The destination is checked again when saving or launching an external editor.
Directory symlinks anywhere inside either vars tree make secret-source writes
fail closed, even when the selected source is otherwise external. Keep these
vars trees as real directories. Symlinks to external `.vault` sources remain
supported when they do not expose the source through a vars tree.

For example, a versioned `group_vars/dashboard.yml` may contain:

```yaml
grafana_admin_password: "{{ vault_grafana_admin_password }}"
```

Define `vault_grafana_admin_password` in an encrypted external vars file, load it
through the existing deploy Vault-file prompt, or provide the required input
directly through the existing secure injection mechanism. Existing encrypted
`.vault/main.yaml` files outside the vars trees remain supported. An external
secret-store lookup should live in that external source; the inventory contains
only the variable reference. Pure dotted references are supported as well.

References must contain only a variable name or dotted variable path. Literal
prefixes/suffixes, quoted expressions, concatenation and filters such as
`default('password')` cannot be used to store a credential inside a template.
Nonsecret paths such as `ansible_ssh_private_key_file`, `freeipa_roster_file` and
credential references remain configuration. Empty/null skeleton entries remain
allowed; required-secret validation still determines whether deployment inputs
are complete.

To migrate an existing workspace:

1. Use the reported file/field/line to locate the value locally. Avoid copying it
   into an issue, terminal transcript or command argument.
2. Copy the existing value to your approved encrypted vars file or external
   secret store outside `group_vars/` and `host_vars/`. Preserve the credential;
   Pilot does not rotate, remove or move it automatically.
3. Replace the inventory value with a pure external variable reference, or omit
   it when the existing secure injection mechanism supplies the input directly.
4. Validate the workspace again, then use the normal deployment preview before
   applying changes. Removed credentials can remain in Git history; follow your
   organization's existing exposure and credential-rotation procedure if needed.

Migration diffs containing a previously stored credential are redacted. Existing
noncompliant workspaces are blocked before the editor renders their values;
perform the migration in a local editor that does not record the credential.
