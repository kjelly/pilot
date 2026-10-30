---
name: freeipa-roster-authoring
description: Generate or update the pilot repo's canonical FreeIPA identity roster YAML from explicit requirements, preserving schema and safety boundaries. Use when a user asks to create, complete, migrate, or review a FreeIPA roster containing users, groups, hosts, hostgroups, HBAC, sudo, NFS, or automount declarations.
---

# FreeIPA Roster Authoring

Produce a canonical roster at the current schema, `schema_version: 3`
(`CurrentRosterSchemaVersion` in `internal/inventory/roster_version.go`),
consumable by `playbooks/apply/freeipa-identity-apply.yml`. Treat it as a
declarative authorization document, not as an inventory or ad-hoc Ansible
extra-vars file.

An existing v1 or v2 roster does not need hand conversion: `pilot edit`, the
MCP roster driver, and `pilot deploy`/`pilot reconcile`'s preflight all call
`EnsureRosterCurrent` before touching a roster, which upgrades it to v3
(validated, backed up, atomic) the first time any of them open it. Use `pilot
roster migrate <roster-file>` to upgrade one explicitly (add
`--vault-password-file <path>` for an ansible-vault-encrypted roster). Never
hand-edit `schema_version`. The v2 -> v3 step only sets the version and adds an
empty `grants: []`.

## Required workflow

1. Inspect repository sources before writing:

   - `playbooks/apply/freeipa-identity.roster.example.yaml` for field shape.
     It is still a v2 document: after copying it, upgrade the copy with
     `pilot roster lint --upgrade <copy>` (step 5) instead of editing the
     version.
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
   `schema_version: 3`; do not introduce an unimplemented version, and do not
   generate `freeipa.domain`/`freeipa.realm` for a new roster (migration-
   compatibility fields for old v1 rosters only — deployment naming now comes
   from `group_vars/freeipa.yml`). Use exact names such as
   `freeipa_roster_file`, `service_principal`, `nfs_clients`,
   `password.initial`, and `ssh_keys.authoritative`.

   The v3-only sections (`grants`, `auth_policies`, `security`,
   `account_policies`, `password_policies`, `credential_policies`) are access
   governance. Write them only when the request is about them, take their shape
   from the validators that enforce it (`internal/inventory/roster_grants.go`,
   `auth_policy.go`, `grant_security_policy.go`, `sod.go`,
   `account_policy.go`, `password_policy.go`, `credential_policy.go`,
   `privileged_identity.go`), and prefer `pilot edit`'s roster editors
   ("Access governance", "Identity hardening") and `pilot access` for grants
   and break-glass. Leave `grants: []` empty otherwise.

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
   - Netgroups (`netgroups:`) are optional, v2 and later. Each needs a unique
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

5. Validate every candidate:

   ```bash
   go run ./cmd/pilot roster lint <roster-file>
   ```

   Require exit 0 and `ok: schema v3; no issues found`, then inspect YAML and
   all references. An older roster prints `ok: schema v2 is valid` and a
   `notice:` line pointing at `pilot roster migrate <file>`; `--upgrade`
   upgrades it in place and leaves a backup of the original beside it
   (`<file>.v2.<UTC time>.<sha>.bak`, plaintext if the roster was) plus
   `<file>.pilot-migrate.lock` / `.pilot-remove.lock`. `warning:` lines do not
   fail lint, but a dangling host reference makes the outbound webhook
   snapshot fail closed, so fix it.

   **Lint cannot read an encrypted roster.** It has no vault option: on an
   ansible-vault file it exits 1 with "is ansible-vault encrypted; decrypt it
   first". It also reads the path more than once, so a pipe or `<(...)` fails
   ("cannot resolve secret source path"). Lint a decrypted copy in a private
   directory and delete it whatever the result; never under the repository or
   `./tmp`, never printed:

   ```bash
   d=$(mktemp -d) && chmod 700 "$d"
   (umask 077; ansible-vault view --vault-password-file <vault-pass> <roster> > "$d/roster.yaml")
   go run ./cmd/pilot roster lint "$d/roster.yaml"; rm -rf "$d"
   ```

   `pilot roster migrate --vault-password-file` decrypts in memory, but on a
   roster already at v3 it only reports "already schema v3; nothing to do"
   without validating anything, so it is not a lint. Lint success does not
   replace target `--check --diff` or apply/verify when deployment evidence is
   requested.

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
confirmation unless it is already authorized. Prefer `pilot edit`'s roster
editors (Users, Groups, Host access, Sudo, Access governance, Identity
hardening): they validate and lock the file. Otherwise edit with
`ansible-vault edit`; do not print decrypted content in chat or logs. Re-run
lint after every structural change and check all references after renames.

## Revoking access and removing objects

What a change does in FreeIPA on the next `freeipa-identity-apply.yml` run
(`playbooks/apply/freeipa-identity-apply.yml`):

| Roster change | FreeIPA result |
|---|---|
| user `state: disabled` | `ipa user-disable`: reversible, the account and its data stay. `enabled: true` beside it is a lint error. |
| user `state: absent` | `ipa user-del` without `--preserve`: **permanent**. FreeIPA keeps no copy and can no longer prove the user ever existed. |
| group `state: absent` | `ipa group-del`, after a permanent marker group `pilot-internal-history-g-<sha256(name)>` records that the name was managed. |
| host, HBAC rule, sudo rule, netgroup `state: absent` | the object is deleted (`host-del`, `hbacrule-del`, `sudorule-del`, `netgroup-del`). `allow_all` cannot be absent; use `hbac.disable_allow_all`. |
| entry deleted from the YAML | **nothing is disabled or deleted.** The FreeIPA object stays, a user stays enabled with its password; only roster-managed memberships that listed it are removed (group and hostgroup membership is authoritative). |

Rules that follow:

- To revoke a user's access, set `state: disabled`. Use `state: absent` only
  when the person explicitly confirms permanent deletion.
- A `state: absent` entry is a tombstone: keep it in the roster for good.
  Deleting that line later is not a revocation and removes the only local
  record that the object was deleted; `pilot roster remove-user` refuses it.
- Never delete a user or group entry by hand to "remove" it. To undo an entry
  that was never applied (a mistaken local addition), use
  `pilot roster remove-user|remove-group <roster> <name> -i <inventory> --dry-run`
  (`--vault-password-file` for an encrypted roster), then without `--dry-run`.
  It asks FreeIPA first and refuses once the object has been applied; there is
  no `--force`.

If a `freeipa-nfs-server` inventory host lacks an `nfs.servers` entry, do not
guess its FQDN or shares. Pilot may append a derived minimal stub, but the
operator must review and complete site-specific shares, ACLs, exports, and
automount data before apply.

## Output contract

Return the roster path or patch plus a compact validation summary. Clearly label
`REQUIRED_CONFIRMATION` values and never claim deployment readiness until lint
passes and all required site facts and secrets are supplied.
