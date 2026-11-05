# `pilot edit` wizard behaviour and gotchas

> Reference for the `pilot-trec-verification` skill.
> Read before authoring or changing any `pilot edit` drive script.
> Covers CI=1, text-field pre-fill, the vault/group_vars cursor reset, the
> single-keypress y/n change, the vault editor's nested-YAML refusal,
> `inventory generate` backfill, the `host_vars/` editor, the top-menu /
> freeipa-dns items, and the roster editor with its few hand-edit exceptions.

Every normative rule below also appears as a one-line entry in
`../SKILL.md`'s rules table; the detail here is the evidence behind it.

---

## `CI=1` is required for every `pilot edit`/`pilot deploy` invocation

Both commands are 100% Bubble Tea (`cmd/pilot/cmd/edit_tui.go`,
`deploy_tui.go`). Every screen triggers bubbletea's package-init OSC
background-colour query the first time any `tea.Program` runs in the process;
under a bare PTY nothing answers it and the run hangs ~5s.

Always set it — do **not** special-case it to "only when the role checklist is
involved". `[Bubble Tea rewrite 2026-07-17]`

`[live 2026-09-24]` The hang did not reproduce on bubbletea v2.0.9. Without
`CI=1`, `origin/main` `583df40` and a build with the lipgloss v2.0.6 stack each
rendered the top menu in under 50 ms in all 3 runs under `trec drive`, and
exited 0. Pilot's own code never reads `CI`. Keep setting it anyway: the rule
costs nothing, and dropping it has only been checked on those two builds.

## Text-entry fields pre-fill with the cursor at the end

Every value field (`ansible_host`, `ansible_user`, ssh key path, vault entry
values, `host_vars`/`group_vars` value edits) pre-fills the current value with
the cursor at the end, so plain `TEXT` **appends** rather than replaces.
Deliberate — `bubbles/textinput` under the hood, kept identical to the old
promptui readline behaviour, and covered by `tui_textinput.go`'s
`TestTextInputModel_TypingReplacesRatherThanAppending`.

Use `REPLACE_TEXT_AND_ENTER` (Ctrl-U first), or `BACKSPACE <n>` with n ≥ the
current value's length (over-backspacing is harmless) before typing.

## The vault/group_vars key-list screen resets the cursor to the top

The key-list screens rebuild with the cursor back at row 0 after **every**
field edit — there is no auto-advance to the next entry. A script that edits
field 0 then sends `ENTER` again re-opens field 0, not field 1.

**Symptom:** the file saves cleanly with your *last* value in one key and every
other key still at `CHANGE-ME`, and the cast looks green throughout. `[live
2026-07-17, v8: seven intended values all typed into `ipa_admin_password`,
final state `pilot-secret-key`]`

**Label-based fix `[live 2026-09-24]`:** the reset still happens, but selecting
each key by its row text makes it harmless. The script added a probe key (row
1), set `node_exporter_basic_auth_password` (row 0), then ran
`ACTIVATE pilot_trec_probe = WITH ENTER` after the list had reset to row 0.
It opened the probe key, and both values landed where intended on disk. This
needs no index and passes `--strict`. Each row reads `<key> = <value>`, where
the value is `<已設定>` once set, so the full `<key> =` is a unique label
unless another key's name ends with the same text (the match is a substring).

**Fix:** send `DOWN <index>` before the `ENTER` for *every* entry, recomputing
the index from the top each time.

## Verify the file on disk after every save

`✅ 已存檔` proves a save happened, not that the right fields got the right
values — the cursor reset above is invisible in a green cast. `grep` each key
you intended to set and compare the actual value against what you meant to type.

Treat a mismatch as a script bug to fix and re-run, **never** as evidence of a
wizard write-path bug — check the transcript for where your keystrokes actually
landed first.

## `pilot deploy`'s y/n prompts finalise on a single keypress

`confirmModel` (`tui_confirm.go`) answers immediately on `y`/`Y`/`n`/`N`. Enter
still works, using the shown default, but only when no y/n was typed first.

**Do not send a trailing `ENTER`.** Sending `TEXT n` then `ENTER` the old way
leaks that stray `ENTER` on to whatever screen comes *next*, silently submitting
its default before your script's own steps for that screen ever run. Send just
`n` (or `y`) and move on to the next `EXPECT`.
`[live 2026-07-17: derailed a `pilot deploy` preflight-mode select this way]`

## The vault editor refuses nested-structure YAML — not a licence to hand-edit

`pilot edit`'s `.vault/` editor declines 「複雜 YAML（例如
roster/list/nested map）」 and suggests a text editor (`edit_tui_vault.go`).
For a FreeIPA roster that refusal is not the way in: the top-menu `roster`
item has its own editor (last section of this file). Everything the wizard edits —
scalar vault entries, `hosts.yml`, `group_vars/`, `host_vars/`, the roster
fields listed below — must go through it. Hand-edit only what no screen
covers, and name the reason in the evidence record.

## `pilot inventory generate --dir <path>` backfills and scaffolds

It backfills missing `group_vars/<role>.yml` from `.example.yml` and writes a
vault skeleton listing every secret key the roles you selected actually need.
Read its output before writing the vault-fill script.

## There is a real `host_vars/` editor — don't hand-write those files

Reachable from a host's own menu as a conditional item,
`host_vars/<host>.yml(必填、無安全預設值的設定)`, appearing only when that
host's current roles imply a key with no safe cross-host default
(`internal/inventory.HostVarsKeysForRoles` — today just `prometheus_site_label`
for the `prometheus` role). Selecting it auto-scaffolds the file if missing and
reuses the same flat, scalar-only key-list editor `group_vars/` uses.
`[added after 2026-07-23; confirmed live 2026-07-25, round 16]`

Don't hand-write `host_vars/*.yml` for a key this screen covers — use the wizard.

## Top-menu items beyond hosts/group_vars/vault

- `roster` — the canonical FreeIPA roster editor (see the last section).
- `freeipa-dns manifest` (`cmd/pilot/cmd/edit_tui_dns.go`) — append/edit CRUD
  for `docs/specs/freeipa-dns.md`'s DNS zones/records manifest: zone
  state/records_mode/split-horizon-ack, and A/AAAA/CNAME records including a
  `target.inventory_host` picker sourced from `hosts.yml`. Same
  Simulate-then-write gate as the roster screens
  (`inventory.ValidateDNSManifest`). Unlike roster users/groups, `state: absent`
  is offered directly on a zone or record — a declarative reconcile request, not
  an in-wizard delete; real deletion happens at apply time behind its own safety
  gates. `[added 2026-07-30, between `roster` and `🔍 檢查設定完整性`]`
- `🔍 檢查設定完整性` — advisory report sharing its checks with `pilot deploy`'s
  hard completeness gate (`workspace_completeness.go`/`deploy_completeness.go`).
  Run it before deploying to catch a missing/`CHANGE-ME` vault key, an unfilled
  host_vars key, or a roster structural violation without waiting for a real
  preflight. It only warns (✅/❌ banner) — it never blocks a save or exit.

**Navigate the top menu by `SELECT <label text>`, not by counting `DOWN`.**
Inserting an item shifts every item at or after it by +1; the `freeipa-dns`
insertion broke four unrelated existing teatest/PTY tests the same day, all
fixed-count `DOWN` loops landing on the wrong item. If you must count,
re-verify against the live item list (`PILOT_DEBUG_MENU=1`, or an MCP
`trec drive --interactive` session's `SCREEN` reply, see `mcp-mode.md`), not
an old transcript. `SELECT` needs the Huh `--pointer`
described in `select-labels.md`.

## The FreeIPA identity roster: use the `roster` editor

`[re-checked against source 2026-10-31; rows below not yet re-driven live]`

Top menu `roster — FreeIPA users/groups/sudo(...)` asks for
`Roster 檔路徑(canonical FreeIPA roster)`, default
`<dir>/.vault/ipa-identity.yaml`. A missing file gets an offer to create a
minimal skeleton, and an older schema is upgraded automatically with a backup
(`pushRosterManager`, `edit_tui_roster.go`). The `管理 <path>` menu:

| Item | What it edits | Code |
|---|---|---|
| `👤 Users` | `➕ 新增 User`; per field: `state` (`present`/`disabled`), `first`, `last`, `display_name`, `email`, `uid`, `gid`, `login_shell`, `home_directory`, `enabled`, `password.initial` (masked), `password.force_change`, `password.preserve_existing`, `ssh_keys.values` (add/modify/remove; writes `authoritative: true`), `authentication.allowed` | `pushRosterUserDetail` |
| `👥 Groups` | add (category `team-*`/`data-*`/`role-*`, then name); `type`, `description`, `gid`, `membership.authoritative`, `membership.users`, `membership.groups` | `pushRosterGroupDetail` |
| `🔐 Host access` | `Hostgroups` (add; `description`, `membership.hosts`, `membership.hostgroups`); `HBAC rules` (add; `subjects.groups`, `subjects.users`, `targets.hostgroups`, `targets.hosts`, `services`; `🗑  Delete login rule` sets `state: absent`, `♻️  Restore login rule` undoes it); the `hbac.disable_allow_all` toggle | `edit_tui_roster_access.go` |
| `🛡️  Sudo commands & rules` | `Command groups` (add; `commands`); `Sudo rules` (add; `subjects.groups`, `allow.command_category`, `allow.command_groups`, `allow.commands`) | `edit_tui_roster_sudo.go` |
| `🏛️  Access governance` | `🔑 Static HBAC` (the HBAC editor above), `⏳ Grants` (`temporary_grant`/`sudo_grant`/`breakglass`: add, per-field edit, `state` present/absent), `🚨 Break-glass` activate/deactivate/history, `🔍 Explain access` (read-only) | `edit_tui_roster_grants.go`, `edit_tui_roster_breakglass.go` |
| `🔒 Identity hardening` | `🔑 Password policies`, `🗝️  Credential policies (SSH hygiene)` (add, fields, `state`), `🛡️  Privileged identity baseline`, `🩺 Hygiene report (read-only)` | `edit_tui_identity_hardening.go` |

Every write is checked by the roster validator first and refused, showing the
violation, rather than writing anything invalid. A valid write lands on disk at
once; there is no separate save step, so the `✅` banner is the save
confirmation. Still read the roster back afterwards (rule 6). The roster
screens refuse an ansible-vault-encrypted roster
(`⚠️  roster 已加密，無法在這裡預覽/編輯 users；…`); keep a disposable
workspace's roster plaintext, as the wizard writes it.

Two more roster writes happen without the `roster` menu:

- **NFS-role-add bootstrap** (`edit_tui.go`'s `pushNFSRoleBootstrap`): when a
  host's role checklist (or a role preset/copy-roles action) newly checks
  `freeipa-nfs-server` and that host has no `freeipa_roster_file`, the wizard
  sets it to `<workspace>/.vault/ipa-identity.yaml`. If that file is missing it
  writes a minimal roster at the current schema: `freeipa.admin.{principal,
  password}`, empty `netgroups`/`grants`, and one `nfs.servers` entry for the
  host with `shares: []`. The admin password is reused from `.vault/main.yaml`
  when it already holds a real one, otherwise a masked prompt asks once; a
  missing `.vault/main.yaml` is created, and an empty or `CHANGE-ME`
  `ipa_admin_password` in it is filled, from the same value. If the roster exists, a
  missing `nfs.servers` entry is appended instead (`autofixNFSRosterEntry`).
  Never fires for `freeipa-nfs-client`.
- **Admin password sync**: changing `ipa_admin_password` in `.vault/main.yaml`
  through the `.vault/` editor also updates `freeipa.admin.password` in the
  rosters under the workspace's `.vault/`; a roster it cannot update is listed
  as not synced (AGENTS.md §5.7, `edit_tui_vault_roster_sync.go`).

A user without an `ssh_keys` field, which is what `➕ 新增 User` writes, is
fine. `freeipa-identity-apply.yml` has handled it since round 16 (`792c8bcb`),
so do not hand-add an empty `ssh_keys` block. Add keys with `ssh_keys.values`.

### The only roster hand edits: what no screen covers

Hand-edit only these, record each one and its reason in the evidence record,
and run `./pilot roster lint <roster-file>` afterwards. It checks the same
rules `freeipa-identity-apply.yml` enforces, without a live target.

- **`netgroups`** — no screen; the only `netgroup` match in
  `cmd/pilot/cmd/edit_tui*.go` is a code comment.
- **NFS shares and clients**: `nfs.servers[].shares[]` (exports, ownership,
  ACL, automount) and `nfs_clients`. The bootstrap above writes `shares: []`
  and nothing edits them; `edit_tui_roster.go`'s header lists `nfs_clients` as
  out of scope.
- **An HBAC rule's `targets.hostcat` and `enabled`.** New rules get explicit
  `hosts`/`hostgroups` and `enabled: true` (`pushRosterAddHBACServices`), and
  editing targets deletes `hostcat` (`pushRosterHBACTargets`,
  `pushRosterHBACHosts`). So the admin break-glass rule that
  `hbac.disable_allow_all` requires (`subjects.users: [admin]`,
  `targets.hostcat: all`, enabled; `freeipa-identity-apply.yml`'s
  `Gate: enabled admin break-glass rule exists`) is a hand edit. Add it before
  you flip the toggle.
- **A sudo rule's `options`** (for example `!authenticate`), **`subjects.users`,
  `targets`, `deny`, `run_as` and `enabled`.** `newRosterSudoRule` writes
  `options: []`, `hostcat: all`, `run_as.users: [root]` and `enabled: true`;
  `pushRosterSudoRuleDetail` edits only `subjects.groups` and the three
  `allow.*` fields.
- **Removing users, groups, hostgroups, sudo rules and command groups.** The
  user `state` picker offers only `present`/`disabled`
  (`rosterUserStateChoices`), a group's `state` is shown read-only, and the
  other three have no delete. For a user or group never applied to FreeIPA,
  use `pilot roster remove-user`/`remove-group` instead of editing; they
  refuse an entry FreeIPA shows was ever applied.
- **`freeipa.*` apart from `admin.password`** (`admin.principal`, `server`,
  `defaults`, `safety`). If `freeipa.admin.password` already differs from the
  vault, the sync above does not repair it; AGENTS.md §5.7 names a hand edit of
  the roster as the fix (`TestFreeIPARosterDriftRecoveryIsAHandEdit`).
- **`auth_policies`, `account_policies`, `security.grant_policies`,
  `security.conflicts`, `policy_exceptions` and `migration`** — no screen
  (`edit_tui_roster_grants.go`'s header: no roster CRUD primitives yet). A
  credential policy's `review` decisions go through `pilot identity review`,
  not an edit.
- **Roster `hosts[]` entries other than `freeipa-client` hosts.** The manager
  adds an entry, with `ansible_host` as `ip_address`, for every `hosts.yml`
  host tagged `freeipa-client` (`AutoFillFreeIPAClientRosterHosts`); no screen
  adds other hosts or edits an entry.
