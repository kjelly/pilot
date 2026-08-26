---
name: freeipa-roster-authoring
description: Generate or update the pilot repo's canonical FreeIPA identity roster YAML from explicit requirements, preserving schema and safety boundaries. Use when a user asks to create, complete, migrate, or review a FreeIPA roster containing users, groups, hosts, hostgroups, HBAC, sudo, NFS, or automount declarations.
---

# FreeIPA Roster Authoring

Produce a canonical `schema_version: 2` roster consumable by
`playbooks/apply/freeipa-identity-apply.yml`. Treat it as a declarative
authorization document, not as an inventory or ad-hoc Ansible extra-vars file.

An existing `schema_version: 1` roster does not need hand conversion: `pilot
edit`, the MCP roster driver, and `pilot deploy`/`pilot reconcile`'s preflight
all call `EnsureRosterCurrent` before touching a roster, which upgrades it to
v2 automatically (validated, backed up, atomic) the first time any of them
open it. Use `pilot roster migrate <roster-file>` to upgrade one explicitly
(add `--vault-password-file <path>` for an ansible-vault-encrypted roster) or
`pilot roster lint <roster-file>` to check without upgrading. Never hand-edit
`schema_version` — always go through one of these.

## Required workflow

1. Inspect repository sources before writing:

   - `playbooks/apply/freeipa-identity.roster.example.yaml` for field shape.
   - `internal/inventory/roster_validate.go`, `internal/inventory/roster_netgroup.go`,
     and `cmd/pilot/cmd/roster_lint.go` for enforced rules.
   - `docs/runbooks/freeipa-identity.md` and
     `docs/verification/freeipa-identity.md` for vault and loading rules.
   - The actual inventory and relevant role playbooks when the request includes
     hosts, hostgroups, netgroups, NFS, or automount. Use target facts; never
     infer an alias-to-FQDN mapping from convention alone.

2. Convert the request into an input contract. Record confirmed values for the
   FreeIPA domain, realm, server FQDN, admin principal, users, groups, hosts,
   hostgroups, authorization intent, NFS servers/clients, and removal boundary.
   Separate unknowns from confirmed values. Ask for missing values that affect
   access, deletion, identity, network exports, or data paths; never silently
   invent them.

3. Generate only canonical fields. Start from the repository example or an
   existing roster and preserve unrelated sections where practical. Keep
   `schema_version: 2`; do not introduce an unimplemented version, and do not
   generate `freeipa.domain`/`freeipa.realm` for a new roster (migration-
   compatibility fields for old v1 rosters only — deployment naming now comes
   from `group_vars/freeipa.yml`). Use exact names such as
   `freeipa_roster_file`, `service_principal`, `nfs_clients`,
   `password.initial`, and `ssh_keys.authoritative`.

4. Enforce these invariants:

   - User names match `^[a-z_][a-z0-9_.-]*$`; user/group names are unique.
   - New groups use category `team`, `filesystem`, or `role`, with prefixes
     `team-`, `data-`, or `role-` respectively. Never generate a new
     `category: access` group — it is deprecated compatibility data only.
     An existing roster's `access-*` group may be preserved as-is when
     editing (do not rename, delete, or reclassify it); just never author a
     new one.
   - HBAC `subjects.groups` accepts `team-*` and `role-*` groups directly
     (no wrapper `access-*` group needed), plus legacy `access-*` groups
     already present in the roster for backward compatibility. It rejects
     `filesystem` (`data-*`) groups and any unknown group name.
   - HBAC `subjects.users` and direct HBAC users are first-class: list a
     roster user name (or `admin`) directly in `subjects.users` instead of
     wrapping them in a group. HBAC `targets.hosts` accepts direct already-
     enrolled host FQDNs the same way, alongside or instead of
     `targets.hostgroups` — useful for a one-off/exception grant that
     doesn't warrant a new hostgroup.
   - Group membership references existing users/groups and never itself.
   - Hosts use the real FQDN and IPv4 address; do not turn an inventory alias
     into an FQDN without checking target facts.
   - A hostgroup's `membership.hostgroups` (nested hostgroups) is now fully
     reconciled, same as `membership.hosts` — both are authoritative.
   - `membership.all: true` on a hostgroup is a wildcard meaningful only to
     `nfs_clients[]` targeting (`playbooks/apply/freeipa-nfs-client-apply.yml`):
     it matches every freeipa-nfs-client host, present and future, without
     listing hosts individually. Only use it when the request is explicitly
     "every managed host may mount NFS" — it is not a general HBAC/sudo/group
     wildcard, and combining it with `hosts`/`hostgroups` on the same
     hostgroup is redundant (`all` alone already covers everything).
   - HBAC/sudo subjects, targets, hostgroups, services, command groups, and
     referenced groups resolve to declared objects.
   - Netgroups (`netgroups:`) are optional and v2-only. Each needs a unique
     name matching `^ng-[a-z0-9][a-z0-9_.-]*$` that does not collide with any
     hostgroup name, `membership.authoritative: true` (the only value this
     validator accepts), and every `membership.users`/`groups`/`hosts`/
     `hostgroups`/`netgroups` entry must reference something else declared in
     the same roster. A netgroup must not directly or transitively contain
     itself — `pilot roster lint` rejects any cycle, so check by hand before
     nesting netgroups more than one level deep, since Ansible-side apply
     does not repeat that specific check (see `internal/inventory/roster_netgroup.go`).
   - `migration` stays empty unless the user explicitly requests its separate
     fail-closed workflow.
   - NFS servers have a real FQDN and matching
     `service_principal.principal` (`nfs/<fqdn>`), keytab, share source,
     ownership group, export clients/options, and automount values as needed.
     An empty `shares: []` is only a bootstrap stub and must be called out.
     Export `clients[].type` may be `network`, `host`, `hostgroup`, or
     `netgroup` (`hostgroup`/`netgroup` render as `@value`; the others render
     as a bare value) — `raw` also exists but is a migration compatibility
     escape hatch only, never generate it for new authoring.
   - Never put real passwords, vault passwords, private keys, or other secrets
     in repo-tracked files or examples. Keep the real roster outside the repo,
     mode 600, and encrypted with `ansible-vault`.

5. Validate every plaintext candidate:

   ```bash
   go run ./cmd/pilot roster lint <roster-file>
   ```

   Require `ok: schema v2; no issues found` (a v1 roster instead shows `ok:
   schema v1 is valid` plus a notice to run `pilot roster migrate` — pass
   `--upgrade` to have lint do that itself), then inspect YAML and all
   references. For an encrypted roster, `pilot roster lint`/`pilot roster
   migrate --vault-password-file <path>` decrypt in memory and never leave a
   plaintext copy on disk — do not manually decrypt to a temp file for this.
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
