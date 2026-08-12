# `pilot edit` wizard behaviour and gotchas

> Reference for the `pilot-trec-verification` skill.
> Read before authoring or changing any `pilot edit` drive script.
> Covers CI=1, text-field pre-fill, the vault/group_vars cursor reset, the
> single-keypress y/n change, the nested-YAML exception, `inventory generate`
> backfill, the `host_vars/` editor, and the top-menu / roster / freeipa-dns items.

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

## The vault editor refuses nested-structure YAML — a real exception

`pilot edit`'s vault editor explicitly declines 「複雜 YAML（例如
roster/list/nested map）」 and tells you to use a text editor. That is a
legitimate, tool-endorsed exception to "no hand-edited YAML" — but **only** for
files the tool itself declines. Everything the wizard *will* edit (scalar vault
entries, `hosts.yml`, `group_vars`) must still go through it.

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

- `roster` — append-only FreeIPA Users/Groups CRUD against a canonical roster
  (see below).
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
re-verify against the live item list (`PILOT_DEBUG_MENU=1`), not an old
transcript.

## The FreeIPA identity roster is no longer 100% hand-authored

Two features cover part of it, narrowing but not eliminating the nested-YAML
hand-edit exception. `[live 2026-07-25, round 16]`

**NFS-role-add bootstrap** (`edit_tui.go`'s `pushNFSRoleBootstrap`): the moment
a host's role checklist (or a role preset/copy-roles action) newly checks
`freeipa-nfs-server` and that host has no `freeipa_roster_file` yet, the wizard
auto-derives `<workspace>/.vault/ipa-identity.yaml`, sets that host's
`freeipa_roster_file` extra var to it, prompts once for the FreeIPA admin
password (masked `EchoPassword` input — never appears in a
`--secret-env`/`--secret-file`-protected recording), and writes a *minimal*
roster: `schema_version: 1`, `freeipa.admin.{principal, password}`, and one
`nfs.servers` entry for that host with `shares: []`. It also creates/fills
`.vault/main.yaml`'s `ipa_admin_password` from the same value, never clobbering
an existing non-`CHANGE-ME` one. Fires only for `freeipa-nfs-server`, never
`freeipa-nfs-client`.

**Roster manager** (top-menu `roster` → `👤 Users` / `👥 Groups`): append-only.
Adding a user writes only `{name, state: present}`; adding a group writes only
`{name, state: present, category}` (category from a 4-way picker —
`team-`/`data-`/`access-`/`role-`, matching the runbook §2 prefix rule). Both
dry-run against the roster validator first and refuse, showing the violation,
rather than writing anything invalid.

Neither screen can set membership, passwords, `ssh_keys`, HBAC/sudo rules,
hostgroups, or NFS shares/exports — those still need a hand edit under the
tool-endorsed exception above. `./pilot roster lint <file>` validates a
hand-edited roster against the same rules the apply playbook enforces, without
a live target.

**Every user needs an explicit `ssh_keys: { authoritative: true, values: [...] }`
block added by hand before a real `freeipa-identity` reconcile, even if the list
is empty.** A user with no `ssh_keys` field crashes
`freeipa-identity-apply.yml`'s user-normalization task on `ansible-core 2.19.x`.
Suspected playbook bug, not a trec-driver issue — full writeup in
`docs/runbooks/minimal-poc-architecture.md` §6.
