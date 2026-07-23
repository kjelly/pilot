# Semantic action catalog expansion — 2026-07-23

> Evidence class: Go feature implementation + local-only smoke verification.
> No VM was created or touched; this is not a minimal-poc clean-room rebuild round.
> Verified at: 2026-07-23 (Asia/Taipei)
> Current runbook: [`minimal-poc-architecture.md`](../../runbooks/minimal-poc-architecture.md) §3.3

## Why this exists

Round 14 (`2026-07-23-round-14.md`) found that `pilot edit --actions` covered only 6 actions,
leaving `group_vars/`/`.vault/` editing, role presets, extra host vars, host deletion, and
unchecking a role to interactive `pilot edit` (`trec drive`/`trec mcp`) only. This work closes
every one of those gaps under two hard constraints given by the requester: every new action must
genuinely drive the real live menu (never a shortcut that mutates `hosts.yml`/group_vars/vault data
directly), and a `trec` recording of an `--actions` run must be able to show what each action did.

## What was built

- A single-source-of-truth action registry (`edit_actions_registry.go`) generating the spec list
  (`pilot actions schema`), scenario validation, and driver dispatch from one list of ~25 entries,
  replacing three independently hand-synced switches (already fragile at the original 6 actions).
- New actions: `disable_role`; `set_host_field`'s `env` field; `delete_host`; `add_extra_var`/
  `edit_extra_var`/`delete_extra_var`; `discard_hosts`; `apply_role_preset`/`copy_roles_from_host`/
  `create_role_preset`/`rename_role_preset`/`delete_role_preset`/`restore_role_presets`;
  `set_group_var`/`restore_group_var_default`/`save_group_vars`/`discard_group_vars`;
  `add_vault_key`/`set_vault_value`/`delete_vault_key`/`save_vault`/`discard_vault`.
- A `confirmYesNo` primitive (previously the driver could only accept a confirm screen's own
  default via a blind Enter — no way to override a `defaultYes=false` confirm, needed for
  delete/discard actions).
- A `value_env` field (mutually exclusive with `value`) on vault/extra-var actions, reading the real
  secret from an environment variable at execution time — mirroring `trec drive`'s `TEXT_ENV`/
  `--secret-env` convention so a real secret never has to sit in scenario JSON in cleartext. A
  `typeSecretOrPlain` primitive records a `«redacted»` placeholder in `--trace-out` instead of the
  literal characters for these steps.
- Two permanent exclusions, documented rather than "fixed": the `ansible-vault`-encrypted shellout
  (a real subprocess swap, not a screen) and any vault file with nested YAML (the wizard's own
  `doc.Editable()` check rejects this for a human too).
- `hasSecretName` deliberately NOT applied to vault key names (unlike host/field/role names) — it
  exists to keep secrets out of plaintext-committed files, and `.vault/` is the sanctioned exception.

## Real bugs found + fixed (via the end-to-end smoke, not the unit tests)

Every action was first built and unit-tested in isolation per area (hosts.yml, role presets,
group_vars, vault), each passing its own tests. Two real bugs only surfaced when a composed
scenario spanning all four areas was run through the actual compiled binary under `trec`:

1. **`save_hosts` froze the router for any step after it in the same scenario.** `save_hosts`
   unconditionally chose "離開" (quit) after saving, setting `r.quit = true`. Once set,
   `editRouterModel.Update` short-circuits *every* future message straight to `tea.Quit` without
   processing it — so a `group_vars`/`.vault` action later in the same scenario would silently
   never navigate anywhere (every `choose`/`moveCursor`/`enter` became a no-op) until the bounded
   navigation loop gave up with a generic "could not resolve navigation" error. Fixed by having
   `save_hosts` stop at the top menu it already lands on (via "存檔並離開") without also choosing
   "離開" — nothing downstream depends on `r.quit` being true, and a hosts.yml-only scenario ending
   here still returns from `d.run` normally.
2. **Switching workspaces (e.g. `group_vars` → `.vault`) had no navigation path.** `openGroupVarsFile`/
   `openVaultFile` only recognized their own file picker/editor screens plus the top menu; landing on
   a *different* workspace's file picker (e.g. after `save_group_vars`) produced "cannot navigate to
   vault file ... from screen ...". Fixed by teaching each helper to recognize the other workspace's
   file picker as a safely-closed-out state (no pending edits live on a picker itself) and hop back
   to the top menu first — deliberately **not** extended to an open *editor* screen, since that may
   hold unsaved changes and guessing a discard confirm's answer would be silently destructive.

Both are now locked in by `TestEditAutomationDriverHostsGroupVarsVaultOneScenario` (hosts → group_vars
→ vault, one scenario, `d.run` directly) in addition to the real-binary smoke below.

## Real-binary smoke evidence

Two `trec`-recorded runs against the actual compiled `pilot` binary (not just Go tests calling
internal functions directly), in a disposable workspace under `tmp/pilot-semantic-actions-r15/`
(gitignored, left in place for review — not deleted as part of this work):

| Cast | Scenario | Flags | Result |
|---|---|---|---|
| `casts/01-hosts-groupvars-visual.cast` | create/set_host_field(`ansible_host`,`env`)/enable_role/add+edit_extra_var/apply_role_preset/create+delete_host/save_hosts/set_group_var/save_group_vars | `--presentation --trace-out` | PASS, exit 0, `trec verify` clean (no secret-scan findings) — every step's real screen visible in the cast |
| `casts/02-vault-secret.cast` | add_vault_key/set_vault_value (both `value_env`-sourced, real disposable `openssl rand` secrets)/save_vault | `--trace-out` only (no `--presentation`, by design — see below) | PASS, exit 0, `trec verify` clean; trace shows `«redacted»` placeholders, not the literal secret; grep confirmed neither secret appears anywhere in the cast or trace; grep confirmed the real secret **did** land in the actual `.vault/main.yaml` on disk |

A third attempt (superseded, not kept) combined both scenarios under `--presentation` with a
non-secret placeholder standing in for the vault value — `trec verify`'s own secret scanner flagged
it anyway (the vault key-list screen's `View()` renders the saved value in plain text). That is
exactly the risk the `value_env`+`--presentation` mutual exclusion exists to prevent, confirmed
empirically rather than just asserted: **never run a `value_env` scenario with `--presentation`**;
the two evidence casts above show why they're split.

## Test suite

`go test ./cmd/pilot/cmd/... -count=1`: 323 passed (up from 276 before this work; the 47 new tests
are one-driver-test-per-new-action plus validation-rejection cases, following the existing
`TestEditAutomationDriverMultiHostFlow` pattern of "drive via scenario → assert final persisted
structure/file content matches an interactive session"). `go test ./... -count=1`: 824 passed, 20
packages, no regressions elsewhere. `go vet ./...`: clean.

## Not done in this pass

- No VM was created; no `pilot deploy`/`reconcile` step was exercised (the new actions are all
  local-disk `pilot edit` operations — hosts.yml/group_vars/.vault only). A future minimal-poc-update
  round should still exercise the new actions against real infrastructure when convenient, but
  nothing here required it.
- The Go source changes described above are **not yet committed** (working tree changes only, same
  as round 14's own outstanding fix) — pending explicit confirmation before committing.
