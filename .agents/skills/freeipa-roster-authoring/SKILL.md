---
name: freeipa-roster-authoring
description: Generate or update the pilot repo's canonical FreeIPA identity roster YAML from explicit requirements, preserving schema and safety boundaries. Use when a user asks to create, complete, migrate, or review a FreeIPA roster containing users, groups, hosts, hostgroups, HBAC, sudo, NFS, or automount declarations.
---

# FreeIPA Roster Authoring

Produce a canonical `schema_version: 1` roster consumable by
`playbooks/apply/freeipa-identity-apply.yml`. Treat it as a declarative
authorization document, not as an inventory or ad-hoc Ansible extra-vars file.

## Required workflow

1. Inspect repository sources before writing:

   - `playbooks/apply/freeipa-identity.roster.example.yaml` for field shape.
   - `internal/inventory/roster_validate.go` and `cmd/pilot/cmd/roster_lint.go`
     for enforced rules.
   - `docs/runbooks/freeipa-identity.md` and
     `docs/verification/freeipa-identity.md` for vault and loading rules.
   - The actual inventory and relevant role playbooks when the request includes
     hosts, hostgroups, NFS, or automount. Use target facts; never infer an
     alias-to-FQDN mapping from convention alone.

2. Convert the request into an input contract. Record confirmed values for the
   FreeIPA domain, realm, server FQDN, admin principal, users, groups, hosts,
   hostgroups, authorization intent, NFS servers/clients, and removal boundary.
   Separate unknowns from confirmed values. Ask for missing values that affect
   access, deletion, identity, network exports, or data paths; never silently
   invent them.

3. Generate only canonical fields. Start from the repository example or an
   existing roster and preserve unrelated sections where practical. Keep
   `schema_version: 1`; do not introduce an unimplemented version. Use exact
   names such as `freeipa_roster_file`, `service_principal`, `nfs_clients`,
   `password.initial`, and `ssh_keys.authoritative`.

4. Enforce these invariants:

   - User names match `^[a-z_][a-z0-9_.-]*$`; user/group names are unique.
   - Group categories are `team`, `filesystem`, `access`, or `role`, with
     prefixes `team-`, `data-`, `access-`, or `role-` respectively.
   - Group membership references existing users/groups and never itself.
   - Hosts use the real FQDN and IPv4 address; do not turn an inventory alias
     into an FQDN without checking target facts.
   - HBAC/sudo subjects, targets, hostgroups, services, command groups, and
     referenced groups resolve to declared objects.
   - `migration` stays empty unless the user explicitly requests its separate
     fail-closed workflow.
   - NFS servers have a real FQDN and matching
     `service_principal.principal` (`nfs/<fqdn>`), keytab, share source,
     ownership group, export clients/options, and automount values as needed.
     An empty `shares: []` is only a bootstrap stub and must be called out.
   - Never put real passwords, vault passwords, private keys, or other secrets
     in repo-tracked files or examples. Keep the real roster outside the repo,
     mode 600, and encrypted with `ansible-vault`.

5. Validate every plaintext candidate:

   ```bash
   go run ./cmd/pilot roster lint <roster-file>
   ```

   Require `ok: no issues found`, then inspect YAML and all references. For an
   encrypted roster, do not rewrite blindly: use `ansible-vault view` or a
   secure temporary plaintext copy only for validation, then remove the copy.
   Lint success does not replace target `--check --diff` or apply/verify when
   deployment evidence is requested.

6. Report what was generated, placeholders or confirmations still required,
   and the namespaced loading contract:

   ```bash
   go run ./cmd/pilot ... \
     -e target_group=<confirmed-target-group> \
     -e freeipa_roster_file=<absolute-roster-path> \
     --vault-password-file <vault-password-file>
   ```

   Never recommend `-e @<canonical-roster>`: top-level `groups` and `hosts`
   collide with Ansible magic variables. Use `freeipa_roster_file`.

## Editing an existing roster

Make the smallest semantic change. Before removing a user, group, rule,
membership, host, or export, identify the access/data impact and get explicit
confirmation unless it is already authorized. Preserve secrets by editing via
`ansible-vault edit`; do not print decrypted content in chat or logs. Re-run
lint after every structural change and check all references after renames.

If a `freeipa-nfs-server` inventory host lacks an `nfs.servers` entry, do not
guess its FQDN or shares. Pilot may append a derived minimal stub, but the
operator must review and complete site-specific shares, ACLs, exports, and
automount data before apply.

## Output contract

Return the roster path or patch plus a compact validation summary. Clearly label
`REQUIRED_CONFIRMATION` values and never claim deployment readiness until lint
passes and all required site facts and secrets are supplied.
