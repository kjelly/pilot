---
name: pilot-trec-verification
description: |
  Re-run and re-verify ANY pilot runbook or spec (docs/runbooks/*.md,
  docs/verification/*.md) end-to-end using only `pilot`'s sanctioned
  `edit`/`generate`/`deploy`/`vm-target` subcommands — never hand-edited
  inventory YAML, never direct `ansible-playbook` calls — with every
  interactive wizard step scripted and every step (wizard or read-only
  check) recorded via `trec` as evidence. Not specific to any one
  runbook or demo topology: works for whatever set of hosts/roles the
  runbook-under-test declares. Use when the user asks to "重新驗證"
  a runbook, "re-verify" a deployment guide, wants a pilot deploy/edit
  session "錄影"/recorded, needs fresh evidence for an existing
  docs/runbooks/*.md or docs/verification/*.md file, or is rebuilding a
  pilot vm-target environment from scratch and re-confirming it against
  a spec. Covers: computing deployCatalog/role-checklist indices fresh
  from source (never hardcode from memory or a prior session), building
  a disposable inventory workspace under the repo's gitignored `./tmp`
  directory, choosing between a one-shot site-wide deploy vs
  per-component deploy, and the concrete trec/promptui gotchas that
  make scripted TUI runs silently derail. Also covers driving `pilot`
  through `trec`'s stdio MCP server (`trec mcp`) — the `run` /
  `terminal_start` / `terminal_write` / `terminal_read` / `terminal_close`
  tool contract — for the exploratory, stateful steps of this workflow
  when the calling agent's shell tool spawns a one-shot subprocess per
  call and cannot keep a `trec drive --interactive` PTY's stdin open
  across turns.
---

# pilot-trec-verification

> Recipe for driving `pilot edit` / `pilot inventory generate` /
> `pilot deploy` / `pilot vm-target` entirely through their interactive
> wizards — scripted via `trec drive` and recorded via `trec` — to
> re-run and re-verify **any** runbook or spec in this repo. Pairs with
> the `verified-runbook` skill: this skill produces the real commands,
> real output, and `trec` recordings; `verified-runbook` turns that
> evidence into a compliant document.

This skill is deliberately generic. It does not assume any fixed set of
hosts, roles, or IPs — those come from whichever runbook/spec you are
re-verifying. Numbers baked into a prior session (catalog indices, role
checklist positions, DOWN-arrow counts) are **not reusable** across
sessions: `cmd/pilot/cmd/deploy_catalog.go` and
`internal/inventory/contracts.go` can gain/reorder entries at any time.
**Always recompute indices from the current source**, every run.

---

## 0. Hard preconditions

- Read the runbook/spec you are re-verifying in full before doing
  anything — it defines the host topology, roles, and vars you need.
- If the task's instructions say editing/deployment may only go through
  `pilot edit` / `pilot inventory generate` / `pilot deploy` (no
  hand-edited `hosts.yml`/`inventory.yml`/`group_vars`, no direct
  `ansible-playbook`), treat that as a hard constraint for this session
  even if not restated — it is the point of this skill.
- Confirm the `pilot` binary in `$PATH` is freshly built
  (`go build -o ./pilot ./cmd/pilot`) before driving it. A stale binary
  silently missing a feature (e.g. the `.vault/` menu) looks identical
  to a wizard bug and wastes a debugging cycle.
- Confirm `trec` is installed (`which trec`); it is the recorder +
  keystroke driver for every interactive step. `trec drive --help` /
  `trec --help` for the current flag set — don't assume flags from
  memory. `trec --help` also lists an `mcp` subcommand (stdio MCP
  server) — see `references/mcp-mode.md` for when to use it instead of a
  plain shell call.
- Decide up front whether the calling agent has a genuinely persistent
  PTY/shell available for `trec drive --interactive`, or whether every
  shell tool call is an independent one-shot subprocess (true for this
  session's `Bash` tool, and for most agent harnesses). One-shot
  `trec drive --script <file>` runs are unaffected either way — but any
  exploratory or diagnostic step that needs to look at the screen and
  react (confirming a menu's real item list, debugging a stuck wizard)
  needs a stateful session. If `mcp__trec__*` tools (e.g.
  `terminal_start`) aren't already available via `ToolSearch`, and the
  task needs one, register `trec mcp` as an MCP server rather than
  trying to fake a persistent PTY with one-shot Bash calls. See
  `references/mcp-mode.md`.
- Test artifacts (the disposable inventory workspace, `trec` scripts,
  `.cast` recordings) go under the repo's own `./tmp/` directory
  (gitignored — see `.gitignore`), **never** loose inside the tracked
  project tree (e.g. never a top-level `demo-3vm/`-style dir), unless
  the user explicitly says otherwise.

---

## 1. Decide scope from the runbook, not from habit

Read the runbook/spec and extract:

- The host list and their roles (what the demo/topology actually needs).
- Which components require secrets (vault) vs plain group_vars.
- The runbook's own §4 Verify section — that's what you'll re-run at
  the end, and what decides whether the rebuild actually worked.

Do not assume the previous session's role set, IPs, or component list
still apply — VM rebuilds get new DHCP leases, and the runbook itself
may have been updated since the last run.

---

## 2. Compute catalog/checklist indices fresh — every time

Two Go source files are the ground truth for every index you'll need
in a `trec` script. Read them fresh at the start of each session:

```bash
grep -n 'Key:' cmd/pilot/cmd/deploy_catalog.go       # pilot deploy's single-component list
grep -n 'Name:' internal/inventory/contracts.go       # pilot edit's role checklist (order roleContracts is defined in)
```

- **`deploy_catalog.go`'s `Key:` order no longer matches `pilot deploy`'s
  "單一元件" menu `[live 2026-09-24]`.** The menu is contract-driven
  (`挑一個要佈署的元件 (contract 驅動)`). It listed 29 rows in a different
  order and without day-2 entries such as `freeipa-identity`, so a
  `DOWN <n>` computed from that file lands on the wrong component. Select
  by label (`ACTIVATE <row text> WITH ENTER`), or count on the live screen.
- `contracts.go`'s `roleContracts` order is exactly the role checklist
  order in `pilot edit`'s role editor (re-checked live 2026-09-24: 32
  rows, same order).
- **Count every entry, not just the ones you plan to touch.** The most
  common index bug in this workflow: forgetting a vault entry (e.g.
  `alertmanager_config`) you don't intend to edit still occupies a slot
  before "➕ 新增 key"/"💾 存檔並離開" — miscounting it sends the wizard
  into the wrong menu silently. Before writing `DOWN <n>` to reach a
  save/exit item, count the **actual current item list**, not what you
  remember from the runbook prose.
- **`hosts.yml`/`group_vars`/`.vault` menus are data-dependent, not
  source-order-fixed** — unlike `deploy_catalog.go`/`contracts.go`,
  their item count depends on the *current contents* of the files being
  edited (existing hosts, existing group_vars keys including ones
  buried in commented-out example prose, existing vault keys). A static
  `grep` on source can't tell you this; you need the live menu.
- **Set `PILOT_DEBUG_MENU=1` to get the live item list for free**, for
  every single-choice menu in `pilot edit`/`pilot deploy` (the
  `internal/tui` Huh select adapter; checklists are not dumped). Each
  item is printed as the row renders, label plus description column.
  `[2026-09-24]` Between `521366e` (2026-08-21) and the fix that moved
  the dump into `internal/tui`, the variable printed nothing: the dump
  lost its only caller when the hand-written widgets were deleted. On
  a binary from that window, read the item list from an MCP
  `trec drive --interactive` session's `SCREEN` reply instead
  (`references/mcp-mode.md`). The dump prints each menu's full
  item list to stderr, one line per item, 0-based and in the exact
  order `DOWN <n>` counts from (cursor always starts at row 0 on a
  fresh menu) — e.g. `[pilot:menu]   3: 離開`. Stderr is captured into
  the same PTY stream `trec` records, so it shows up in the `.cast`
  and in `trec transcript` output right before that menu renders — no
  extra step needed beyond adding the env var to the driven command.
  This is strictly better than eyeballing the rendered screen or
  recomputing from source: it reflects the *actual* live item list at
  the moment the menu is shown, including any file-content drift.
  Prepend it to every driving invocation in this skill, e.g.:
  ```bash
PILOT_DEBUG_MENU=1 trec drive --script "$SCRATCH/scripts/edit-hosts.txt" \
    --key-delay 150 --settle-delay 400 --timeout <generous> \
    -o "$SCRATCH/casts/evidence/01-edit-hosts.cast" -- pilot edit --dir "$SCRATCH/demo"
  ```
  It's a no-op for normal human interactive use (gated behind the env
  var; doesn't touch the rendered menu itself).
  **Caveat `[live 2026-07-17, independently reproduced]`: don't combine
  `PILOT_DEBUG_MENU=1` with `SELECT` in the same recorded run.** The
  extra stderr lines it interleaves into the same PTY stream actively
  confuse `SELECT`'s screen-scan — a script that passes cleanly without
  the env var can fail with "not reached after 150 presses" *with* it,
  on a label that genuinely is on screen. Use it only for one-off
  interactive exploration/diagnosis (confirming a menu's real item
  list, debugging why a `DOWN <n>` landed wrong) — omit it from the
  actual scripted/recorded run once you know the indices or labels you
  need.
- This still doesn't remove the need to *reach* the menu you want to
  count — you still have to drive the wizard forward to it. When in
  doubt, step through the wizard once yourself before writing the full
  script. If you have a real interactive terminal, do this by hand. If
  you're an agent whose shell tool only spawns one-shot subprocesses
  (this session's `Bash` tool included), you cannot hold `trec drive
  --interactive`'s stdin open across calls to do this — use `trec
  mcp`'s stateful tools instead (`references/mcp-mode.md`): start a
  `trec drive --interactive` session with `PILOT_DEBUG_MENU=1` set on
  the driven process and read each step's `SCREEN` reply, rather than
  guessing from a short throwaway script and hoping it matches.

See `references/index-computation.md` for a worked walkthrough.

---

## 3. Disposable workspace under `./tmp`

```bash
SCRATCH="$(git rev-parse --show-toplevel)/tmp/pilot-verify-<slug>"
mkdir -p "$SCRATCH/demo/group_vars" "$SCRATCH/scripts" \
  "$SCRATCH/casts/exploration" "$SCRATCH/casts/failed" \
  "$SCRATCH/casts/evidence" "$SCRATCH/evidence"
```

`pilot edit --dir <path>` and `pilot inventory generate --dir <path>`
both accept an arbitrary target directory — there is no need to touch
`demo-3vm/` or any other in-repo *tracked* inventory directory to do a
disposable re-verification run. Point every wizard at `$SCRATCH/demo`
and leave the tracked project tree untouched. `./tmp/` is already
listed in `.gitignore`, so artifacts here never show up in `git
status` as untracked additions — pick a `<slug>` specific enough that
concurrent runs (or a future session) don't collide on the same path.

---

### 3a. Recording evidence lifecycle — hard gate for every checkpoint

Never use one undifferentiated `casts/` directory. It causes exploratory,
failed, and shareable recordings to be mistaken for one another. Create the
three directories above before the first recording and enforce this contract:

| Directory | Allowed contents | May support a PASS / walkthrough claim? |
|---|---|---|
| `$SCRATCH/casts/exploration/` | live-menu discovery and bounded diagnosis; `END_SESSION` / `QUIT` are allowed | No |
| `$SCRATCH/casts/failed/` | any failed, aborted, timed-out, in-progress, or unsafe recording and its `.result.json` | No |
| `$SCRATCH/casts/evidence/` | one completed, reviewable checkpoint per cast, after its verification gate passes | Yes |

Use MCP interactive sessions only to discover the current screen or repair a
driver. They belong in `exploration/`; close them normally when possible, but
never promote them to evidence. Once a workflow is understood, write a fresh,
strict-linted script for the final recording. Do not continue recovering from
a derailment in the same evidence candidate: stop at the first unexpected
screen or result, preserve that cast in `failed/`, and start a new checkpoint
cast after correcting the script.

Every deliverable wizard script must visibly save/apply, choose the product's
own exit action, then end with `WAIT_CHILD_EXIT@<timeout>` and `ASSERT_EXIT 0`.
Before running it, require:

```bash
trec drive lint --strict "$SCRATCH/scripts/<checkpoint>.drive"
```

`--strict` rejects a bare `DOWN` in a menu ("DOWN is position-dependent; prefer
FOCUS/ACTIVATE unless driving a scrolling checklist") and any `ENTER` or
`TEXT_AND_ENTER` that no `EXPECT`/`ASSERT` guards `[live 2026-09-24]`. In
`pilot edit` menus, use `ACTIVATE <label> WITH ENTER` (an alias of `CHOOSE`) or
`FOCUS <label>` (an alias of `SELECT`) with the Huh `--pointer` from §4. For a
scrolling checklist, `CHECKLIST_DOWN` is the form `--strict` accepts.

`[live 2026-09-24]` The deploy, role-checklist and vault flows were re-driven
under `--strict` and the Huh `--pointer`, with label-based navigation only
(rules 13, 14 and 20). The scenario was a single-host `host-monitoring`
rollout on a disposable VM: `pilot edit` built `hosts.yml` (role via the
checklist), `pilot inventory generate`, `pilot edit` filled `.vault/`, then
`pilot deploy` ran preflight, preview and the real apply (✅ 套用完成). All
four casts passed `trec verify`, and `pilot verify` then passed 11/11.

Immediately after the child exits, verify that *one cast*, not a mixed
directory, is eligible for promotion:

```bash
trec verify "$SCRATCH/casts/evidence/<checkpoint>.cast"
```

For MCP-created casts, use `mcp__trec__cast_verify` on that single path. The
gate passes only when the result is `status=success`, `exit_code=0`, the sole
final `SESSION_END` is successful, integrity matches, and `safe_to_share=true`.
`terminal_close` is permitted only after polling `terminal_read` to observe
`running=false` and `exit_code=0`; closing a live wizard produces an aborted
recording even if it already saved.

Maintain `$SCRATCH/evidence/recording-manifest.md` as the reviewed index of
deliverable recordings. Each row must include the checkpoint, final cast path,
driver path (or `read-only command`), `trec verify`/`cast_verify` verdict,
secret-scan verdict, and the observed state claim. A later state-changing
checkpoint must not start until the current row is complete and passing. The
final evidence audit reads only this manifest and `casts/evidence/`; it must
never infer success from casts in `exploration/` or `failed/`.

`pilot edit --actions` / `deploy --actions` casts and JSONL traces may prove
automation behavior, but are not visual walkthrough evidence: keep them out
of `casts/evidence/` unless the user explicitly asks for action-mode evidence
and the manifest labels them as such. A two-event wrapper result does not show
the UI a reviewer needs to audit.

---

## 4. Build the inventory workspace via the wizards

Order: `pilot edit` (hosts.yml → group_vars/ → .vault/) → `pilot
inventory generate` → `pilot edit` again to fill in generated
group_vars/vault placeholders.

Drive every interactive step with `trec drive`:

```bash
CI=1 trec drive --script "$SCRATCH/scripts/edit-hosts.txt" \
  --key-delay 150 --settle-delay 400 --timeout <generous> \
  --pointer '^\s*┃?\s*>\s' \
  -o "$SCRATCH/casts/evidence/01-edit-hosts.cast" --title "pilot edit -- build hosts.yml" \
  -- pilot edit --presentation --dir "$SCRATCH/demo"
```

The `--pointer` is required for any script that uses `SELECT`, `FOCUS`,
`ACTIVATE`, `CHOOSE` or `TOGGLE`. Huh v2 draws every menu row behind a `┃ `
border, and trec's default pointer regex never matches that. See
`references/select-labels.md`.

Always include `--presentation` in a TREC-wrapped `pilot edit`, `pilot deploy`,
or `pilot reconcile` command. It keeps automation recordings in their
presentation-oriented mode; it is required even when the recording is driven
by low-level TREC keyboard operations.

### Recording-first rule for `pilot edit`

For every `pilot edit` cast that will be used as evidence, drive the ordinary
wizard with TREC's low-level keyboard operations (`DOWN`, `ENTER`, `TEXT`,
`CTRLU`, `SPACE`, and so on). This is what puts the actual input events in the
cast and makes the recording self-explanatory. The reference pattern is an
input trail such as `↓`, `Enter`, `Ctrl+U`, then the replacement text — not a
single opaque semantic operation.

Do **not** wrap `pilot edit --actions <scenario.json>` in an evidence recording.
That interface is useful for non-recorded automation and its JSONL trace, but
it drives Bubble Tea models inside the process; TREC consequently sees rendered
output without the matching PTY input events. When a scenario is a convenient
way to describe the desired edit, first explore the live wizard, then compile
its steps into guarded `trec drive` keyboard instructions for the recording.

### Exploration casts are not deliverable evidence

Use exploration only to discover the live menu shape or diagnose one bounded
transition. `END_SESSION` / `QUIT` are valid for that purpose, but deliberately
finalize the recording as non-successful; they are not a harmless shortcut for
a saved wizard. Keep those casts in the scratch directory for diagnosis and do
not merge them into a walkthrough.

For a deliverable `pilot edit` walkthrough, require all of the following in a
single visual cast:

1. ordinary wizard driven by low-level TREC input (not `--actions`);
2. the relevant menu/form screens and the save confirmation are visible;
3. after saving, return to the top menu and choose `離開` normally;
4. finish with `WAIT_CHILD_EXIT@<timeout>` and `ASSERT_EXIT 0`;
5. pass `trec verify` with `status=success`, a final `SESSION_END`, matching
   digest, and a clean secret scan.

When assembling a replay, create an explicit, reviewed list of these visual
evidence casts. Do not merge an entire cast directory, and do not treat
`--status success` as sufficient: a successful action-driven cast can contain
only a banner and semantic markers rather than the UI a viewer needs to audit.
Keep failed, aborted, ended, and in-progress casts separate as diagnostics.

---

## 4b. Screen-driving rules — the complete checklist

Every rule below is normative and self-contained. The reference file in the
last column holds the evidence, the live-confirmation dates, and the failure
stories behind it — open it when you are working on that screen, when a rule
surprises you, or before you argue a rule is wrong. **Do not skip a rule
because you have not read its reference.**

### Always

| # | Rule | Detail |
|---|---|---|
| 1 | Set `CI=1` on **every** `pilot edit`/`pilot deploy` invocation, full stop. Without it the run hung ~5s on bubbletea's OSC background-colour query under a bare PTY (not reproduced on bubbletea v2.0.9, 2026-09-24). | `references/pilot-edit-wizard.md` |
| 2 | Pass `--presentation` on every TREC-wrapped `pilot edit`/`deploy`/`reconcile`. | §4 |
| 3 | Recompute every catalog/checklist index from current source each session; never reuse a number from a prior run or from the runbook prose. | §2, `references/index-computation.md` |
| 4 | Never combine `PILOT_DEBUG_MENU=1` with `SELECT` in a recorded run — its stderr lines confuse `SELECT`'s screen scan. Use it for exploration only. | §2 |
| 5 | Verify success **by content** (`✅ 已存檔`, `✅ 套用完成`), never by exit code — a derailed script exits 0 just as cleanly. | `references/timing.md` |
| 6 | After every save, `grep` the file on disk and compare each value against what you meant to type. A green cast proves a save happened, not that the right fields got the right values. | `references/pilot-edit-wizard.md` |
| 7 | `EXPECT <text unique to the screen you expect to be on>` immediately after every `ENTER`, so a missed transition fails at the step it happened. Guard input after a screen change with `EXPECT` (it waits), not `ASSERT` (it checks once): `EXPECT_QUIET` does not prove the frame is final. | `references/role-checklist.md`, `references/timing.md` |
| 8 | Never `EXPECT` a string that already occurred earlier in the stream (e.g. `PLAY RECAP`); anchor on a string unique to the moment. | `references/deploy-wizard.md` |
| 9 | End every `pilot edit` drive by exiting the wizard (`SELECT 離開` + `ENTER`), then `WAIT_CHILD_EXIT@<timeout>` + `ASSERT_EXIT 0`. Stopping after the last edit turns a successful edit into red evidence. | `references/timing.md` |
| 10 | Pass `--timeout` explicitly, at least as large as your longest `EXPECT@` value; do not rely on a per-step override. | `references/timing.md` |
| 11 | Keep `--key-delay` at ~150ms; below ~100ms a long `DOWN`/`SPACE` burst silently drops a keystroke. | `references/timing.md` |

### Navigation

| # | Rule | Detail |
|---|---|---|
| 12 | `SELECT` is the default for `pilot edit`'s menus. Run with `--pointer '^\s*┃?\s*>\s'`, because Huh v2 rows start with `┃ ` and the default pointer regex never matches them. `SELECT` only moves the pointer — **every `SELECT` still needs its own `ENTER`** (or use `ACTIVATE <label> WITH ENTER`). | `references/select-labels.md` |
| 13 | Select `pilot deploy`'s menus by label (`ACTIVATE <row text> WITH ENTER`) after the rule-18 settle. It worked on every menu from scope select to preflight on 2026-09-24. The catalog order no longer follows `deploy_catalog.go`, so a `DOWN <n>` computed from source is wrong. | `references/deploy-wizard.md` |
| 14 | On the role checklist use `TOGGLE <text unique to that row>`. The Huh checklist renders every row (32 on 2026-09-24), not the old 15-row window, so a content scan reaches them all. Role names recur in other rows' descriptions (`host-monitoring` appears in `prometheus`'s), so match on row-unique text. `CHECKLIST_DOWN <n>` + `SPACE` is the lint-accepted positional fallback. | `references/role-checklist.md` |
| 15 | Never write `DOWN 0`; for index 0 omit the `DOWN` line entirely. | `references/role-checklist.md` |
| 16 | Pick a `SELECT`/`TOGGLE` label substring unique to one row. Collisions come from three easy-to-miss sources: another row's hint text, another row's *description* prose, and `runEdit`/`runDeploy`'s own static startup banner (never cleared — no alt-screen). | `references/select-labels.md`, `references/known-gotchas.md` |
| 17 | Use `TOGGLE docker-apply.yml`, not `TOGGLE docker` — bare `docker` is ambiguous across three rows. | `references/known-gotchas.md` |
| 18 | After every `EXPECT` for a new `pilot deploy` screen, add a ~150ms settle pause before the first keystroke — `EXPECT` succeeding does not prove the new Program is reading input yet. | `references/deploy-wizard.md` |
| 19 | A sub-editor's save/exit returns to its **immediate parent menu**. Verify the actual next screen for every return step; budget one extra return per nesting level. | `references/known-gotchas.md` |
| 20 | The vault/group_vars key-list screen rebuilds with the cursor back at the **top** after every field edit — there is no auto-advance (still true on 2026-09-24). Select each key by label, `ACTIVATE <key> = WITH ENTER`, so the reset cannot misdirect you. A `DOWN <index>` recomputed from the top also works, but `--strict` rejects it. | `references/pilot-edit-wizard.md` |

### Text entry and confirms

| # | Rule | Detail |
|---|---|---|
| 21 | Prefer `REPLACE_TEXT_AND_ENTER` (sends Ctrl-U first) over `TEXT_AND_ENTER` for any field that may already hold a value — pre-filled fields put the cursor at the end, so plain `TEXT` **appends**. Only a brand-new item's name is guaranteed blank. | `references/known-gotchas.md`, `references/pilot-edit-wizard.md` |
| 22 | `pilot deploy`'s y/n prompts finalise on a **single** `y`/`n` keypress — do not send a trailing `ENTER`, or it leaks into the next screen and submits its default. | `references/pilot-edit-wizard.md` |
| 23 | The real-apply gate defaults to **No**. A script of bare `ENTER`s records a preview, not a deploy — you must send a single `y`. Check the cast for `✅ 套用完成`. | `references/deploy-wizard.md` |
| 24 | Script the two easily-missed confirms between the inventory-path prompt and the preflight menu (topology graph `[Y/n]`, manual sudo password `[y/N]`) or the run stalls on unscripted input. | `references/deploy-wizard.md` |
| 25 | For `freeipa-identity` with a canonical roster, answer **`y`** to the `.vault/main.yaml` prompt; do **not** redirect it at the roster path. The roster loads separately via the `freeipa_roster_file` host var. | `references/freeipa-identity-prompt.md` |
| 26 | Declare `--secret-env`/`--secret-file` for **every** vault key that already holds a real value in the target workspace, not just the ones this script sets — older builds re-rendered every set value in plaintext. Since the key list started showing `<已設定>` (seen 2026-09-24), trec's scan flags `…password = <已設定>` as `inline-secret-assignment`, so also redact that marker. | `references/known-gotchas.md` |

### Live-host checks

| # | Rule | Detail |
|---|---|---|
| 27 | Add `-o StrictHostKeyChecking=accept-new` (or `ssh-keygen -R <ip>`) to every raw `ssh` after a VM rebuild. | `references/known-gotchas.md` |
| 28 | Add `-o ControlMaster=no` to any live-SSH re-auth check meant to prove a credential/policy state changed — a multiplexed session silently reuses the old authentication. | `references/known-gotchas.md` |
| 29 | Before reporting a "Real bug" against a playbook or the wizard, cross-verify three ways: read the surrounding code, replay the cast with `trec transcript`, and `grep` the on-disk files your report claims were written. | `references/known-gotchas.md` |

## 5. Choose the deploy strategy: one-shot vs per-component

`pilot deploy`'s "全站部署(site.yml)" option applies every component
`playbooks/site.yml` imports, and inventory group membership (not the
menu selection) decides what actually runs — an empty group is skipped
automatically. Prefer this over looping "單一元件" once per role.

But `site.yml` structurally cannot cover everything:

- It has a **safety-valve assertion** that fails the whole run if `-e
  target_group=` is passed at the top level — because that would
  override every sub-playbook's target group at once, defeating the
  "empty group ⇒ skip" protection for every other component. Any
  component whose correct target isn't its literal inventory group
  (e.g. a role that needs to run against a host that isn't a member of
  that role's own default group) needs either a `vars: target_group:
  <fixed-group>` pinned *inside that one `import_playbook` entry* in
  `site.yml` itself (safe — it only overrides that one import, not the
  global safety valve), or a genuinely separate single-playbook
  `pilot deploy` invocation with `-e target_group=<host/group>`.
- Some components are **intentionally excluded** from `site.yml` by
  design (check the playbook's own top-of-file comments and
  `site.yml`'s own "注意" comments before assuming an exclusion is a
  bug) — data-driven day-2 reconcilers (user/permission rosters) are
  the common case; they need their own vault file and their own
  `pilot deploy` run.
- Before concluding "site.yml covers it all", diff `site.yml`'s
  `import_playbook` list against the **full** `deployCatalog` list from
  §2. A component present in the catalog but absent from `site.yml`'s
  imports will silently not deploy under the site-wide option — this
  is not a wizard bug, and it doesn't show up as a failure; it shows up
  later as a missing feature during verification.

Run each remaining component the same `trec drive`-scripted way as the
site-wide deploy, just via `pilot deploy`'s "單一元件" path with the
catalog index from §2.

---

## 6. Record read-only verification with plain `trec` (no script needed)

Once deploy is done, re-run the runbook's own §4 Verify commands
(SSH+sudo checks, `ipa hbactest`-style policy queries, HTTP API/metrics
checks, log queries, …) and wrap the whole batch in one recording:

```bash
trec -o "$SCRATCH/casts/evidence/0N-verify.cast" --title "Re-verify: <what>" -- bash "$SCRATCH/scripts/verify.sh"
```

`trec` (no `drive` subcommand) is a plain recorder for a non-interactive
command — no keystroke script needed since these are read-only checks,
not TUI prompts. Put all the verification commands in one shell script
with `echo "=== section ==="` headers so the resulting transcript reads
like the runbook's own §4, then feed the real output back into the
runbook using `verified-runbook`'s rules (real output only, no
"expected").

---

---

## References

Load a reference when you reach the screen or decision it covers — the core
above is complete on its own for planning and for every normative rule.

| Reference | Read it when |
|---|---|
| `references/index-computation.md` | Turning `deploy_catalog.go`/`contracts.go` into a script; includes the off-by-one bug class. |
| `references/pilot-edit-wizard.md` | Authoring or changing a `pilot edit` drive script. |
| `references/deploy-wizard.md` | Authoring or changing a `pilot deploy` drive script. |
| `references/role-checklist.md` | Driving the role checklist, or before claiming it can't be driven. |
| `references/select-labels.md` | Choosing `SELECT` vs `DOWN <n>`, a `SELECT` sticks at the first/last row, or it reports `no pointer row found`. |
| `references/timing.md` | Setting `--key-delay`/`--settle-delay`/`--timeout`, or a run exits 0 having done nothing. |
| `references/freeipa-identity-prompt.md` | Deploying or reconciling `freeipa-identity`. |
| `references/known-gotchas.md` | A step behaves unexpectedly; skim once before a first full run. |
| `references/mcp-mode.md` | A step needs live back-and-forth with the screen (menu discovery, diagnosis). |
| `references/filing-policy.md` | You have a finding and must decide where it belongs. |

Sibling skills:

- `_shared/clean-room-contract.md` (this repo) — the shared clean-room,
  Pilot-ownership, wizard-input, serialization, and evidence contract that the
  `minimal-poc-*` skills execute; read it when a task is a full clean-room
  rebuild rather than a single spec run.
- `verified-runbook` (global, `~/.agents/skills/`) — use it for the document
  write-up once you have real output and recordings in hand.
- `vm-target-spec-testing` (this repo) — use it when the task is testing a
  *single* spec/playbook pair on disposable VMs, rather than re-verifying an
  existing multi-component runbook.
- `trec-tui-drive` (global) — the `trec drive` DSL reference
  (`SELECT`/`EXPECT`/`ASSERT`/`WAIT_CHILD_EXIT`/`ASSERT_EXIT`/…) and its own
  reliability rules. Read it alongside this skill's rules table rather than
  trusting either source alone.
- `trec-mcp` (global) — the full `trec mcp` tool contract. **Only needed in MCP
  mode**; see `references/mcp-mode.md`.
