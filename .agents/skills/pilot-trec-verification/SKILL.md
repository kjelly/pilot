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
  server) — see §4a for when to use it instead of a plain shell call.
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
  trying to fake a persistent PTY with one-shot Bash calls. See §4a.
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

- `deploy_catalog.go`'s `Key:` order is exactly the order
  `pilot deploy`'s "單一元件" menu shows — the Nth line is index N-1.
- `contracts.go`'s `roleContracts` order is exactly the role checklist
  order in `pilot edit`'s role editor.
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
  *every* `promptSelectIndex` menu in `pilot edit`/`pilot deploy`
  (shared helper, `cmd/pilot/cmd/deploy.go`): it prints each menu's full
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
    -o "$SCRATCH/casts/01-edit-hosts.cast" -- pilot edit --dir "$SCRATCH/demo"
  ```
  It's a no-op for normal human interactive use (gated behind the env
  var; doesn't touch the rendered menu itself).
- This still doesn't remove the need to *reach* the menu you want to
  count — you still have to drive the wizard forward to it. When in
  doubt, step through the wizard once yourself before writing the full
  script. If you have a real interactive terminal, do this by hand. If
  you're an agent whose shell tool only spawns one-shot subprocesses
  (this session's `Bash` tool included), you cannot hold `trec drive
  --interactive`'s stdin open across calls to do this — use `trec
  mcp`'s stateful tools instead (§4a), with `PILOT_DEBUG_MENU=1` set on
  the driven process, rather than guessing from a short throwaway
  script and hoping it matches.

See `references/index-computation.md` for a worked walkthrough.

---

## 3. Disposable workspace under `./tmp`

```bash
SCRATCH="$(git rev-parse --show-toplevel)/tmp/pilot-verify-<slug>"
mkdir -p "$SCRATCH/demo/group_vars" "$SCRATCH/casts" "$SCRATCH/scripts"
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

## 4. Build the inventory workspace via the wizards

Order: `pilot edit` (hosts.yml → group_vars/ → .vault/) → `pilot
inventory generate` → `pilot edit` again to fill in generated
group_vars/vault placeholders.

Drive every interactive step with `trec drive`:

```bash
CI=1 trec drive --script "$SCRATCH/scripts/edit-hosts.txt" \
  --key-delay 150 --settle-delay 400 --timeout <generous> \
  -o "$SCRATCH/casts/01-edit-hosts.cast" --title "pilot edit -- build hosts.yml" \
  -- pilot edit --dir "$SCRATCH/demo"
```

- **`CI=1` is now required for every `pilot edit`/`pilot deploy`
  invocation, full stop** — as of the 2026-07-17 Bubble Tea rewrite
  (see `cmd/pilot/cmd/edit_tui.go`/`deploy_tui.go`), both commands are
  100% Bubble Tea, not just the one role-checklist screen from before.
  Every screen triggers bubbletea's package-init OSC background-color
  query the first time any `tea.Program` runs in the process; without
  `CI=1` it hangs ~5s on that query under a bare PTY with nothing to
  answer it. Don't special-case this to "only when the role checklist
  is involved" anymore — always set it.
- Text-entry fields (ansible_host, ansible_user, ssh key path, vault
  entry values, …) still **pre-fill the current/default value with the
  cursor at the end** — plain `TEXT` appends instead of replacing, same
  as before the rewrite (now `bubbles/textinput` under the hood instead
  of promptui's readline, deliberately kept identical — see
  `tui_textinput.go`'s `TestTextInputModel_TypingReplacesRatherThanAppending`).
  Always `BACKSPACE <n>` (n ≥ the current value's length;
  over-backspacing is harmless) before typing a new value.
- **`pilot deploy`'s yes/no prompts now finalize on a single `y`/`n`
  keypress — do not send a trailing `ENTER` after it.** Before the
  rewrite, promptui's confirm was a line-editor requiring Enter to
  submit; the new `confirmModel` (`tui_confirm.go`) answers immediately
  on `y`/`Y`/`n`/`N` (Enter still works too, using the shown default,
  but only when no y/n was typed first). Sending `TEXT n` then `ENTER`
  the old way sends that stray `ENTER` on to whatever screen comes
  *next*, silently submitting its default choice before your script's
  own steps for that screen ever run — confirmed live 2026-07-17,
  it derailed a `pilot deploy` preflight-mode select this way. Send
  just `n` (or `y`) and move on to the next `EXPECT`.
- `pilot edit`'s vault editor explicitly refuses nested-structure YAML
  ("複雜 YAML（例如 roster/list/nested map）") and tells you to use a
  text editor instead. That is a legitimate, tool-endorsed exception to
  "no hand-edited YAML" — but only for files the tool itself declines;
  everything the wizard *will* edit (scalar vault entries, hosts.yml,
  group_vars) must still go through it.
- `pilot inventory generate --dir <path>` backfills missing
  `group_vars/<role>.yml` from `.example.yml` and writes a vault
  skeleton listing every secret key the roles you selected actually
  need — read its output before writing the vault-fill script.

### Timing: avoid dropped keys without stalling the run

- `--key-delay` below ~100ms on a long burst of repeated `DOWN`/`SPACE`
  presses (e.g. selecting many roles in the checklist) can silently
  drop one keystroke, landing the cursor one row off with no error.
  150ms has been reliable; don't go much lower purely to save time.
- A script that runs out of instructions while the target program is
  still waiting on a prompt does **not** make `trec drive` hang
  forever — but it also does not mean the intended action happened.
  **Always verify success by content, not exit code**: grep the output
  for the wizard's own confirmation text (`✅ 已存檔`, `✅ 套用完成`),
  not just `trec drive: process exited 0`. A derailed script exits 0
  just as cleanly as a correct one, having done nothing you intended.
- If a run derails (lands on the wrong menu item), nothing is corrupted
  — `pilot edit`/`deploy` only write on an explicit save/apply step —
  but nothing was saved either. Fix the index bug and rerun from
  scratch; there is no partial state to reconcile.
- For a long real command (`pilot deploy`'s actual apply can run
  15–40+ minutes for a full site.yml), give `trec drive --timeout` a
  generous ceiling and run the whole thing under `run_in_background`.
  There is no more scripted input needed after the last confirm
  keypress — `trec drive` just keeps recording until the child process
  exits on its own.
- **Always pass `--timeout` explicitly for a long run, even if your last
  step is an `EXPECT@<ms>` with its own generous per-step timeout.** A
  run was observed to get killed by the *default* `--timeout` (120s)
  while still legitimately waiting on a final `EXPECT@3600000 PLAY
  RECAP` step — the per-step override did not reliably supersede the
  global default in every build. Set `--timeout` to at least as large as
  your longest `EXPECT@` value; don't rely on the per-step value alone.

### SELECT is now reliable for `pilot edit` — re-verified live 2026-07-17

The previous version of this section documented `SELECT` failing with a
stale-pointer bug specifically when a menu came right after (or later
in the same script than) the one bubbletea screen that used to exist
(the role checklist), while the rest of `pilot edit` was still
promptui. The root cause was never `SELECT` itself — it was **switching
between two different rendering libraries mid-session** (promptui's
inline scrolling vs. bubbletea's screen model), which left trec's
screen-tracking confused across that boundary.

As of the 2026-07-17 rewrite, `pilot edit` is **one continuous Bubble
Tea `tea.Program` for the whole invocation** (see `edit_tui.go`'s
router) — every screen, including the role checklist, is now the same
rendering model throughout, so that boundary no longer exists. Re-ran
a full `trec drive --script` walkthrough (`CI=1`, default `--pointer`)
covering: top menu → hosts.yml → add host → host menu → roles menu →
role checklist (toggle + confirm) → **back to roles menu, then host
menu, then host list, all via `SELECT` immediately after the
checklist** → save → top menu → quit. Every `SELECT` matched correctly
on the first try; the process exited 0 with the expected file written.
**`SELECT` is the recommended default for `pilot edit` now** — prefer
it over `DOWN <n>` counting, since it survives a menu's item count
drifting (see §2) without needing to recompute an index.

One real gotcha hit during that same re-verification, worth carrying
forward: **pick a label substring unique to one row.** A first attempt
used `SELECT 完成` intending to match the roles menu's "✅ 完成" row, but
the checklist's own row also contains "完成" in its hint text ("space
勾選/取消、enter 完成") — `SELECT` matched that row instead and
re-entered the checklist. Using `SELECT ✅ 完成` (the emoji prefix is
part of the rendered row and unique) fixed it immediately. This is the
`trec-tui-drive` skill's own rule #1 ("label 選畫面上該行獨有的子字串"),
restated here because it's easy to reach for the shortest label that
merely *looks* unique and be wrong. Also remember `SELECT` only moves
the pointer — it does **not** submit; every `SELECT` still needs its
own following `ENTER`.

`DOWN <n>` index counting still works identically to before (cursor
resets to 0 on every fresh menu) and remains a fine fallback if you
ever hit a `SELECT` mismatch — but there is no longer a known reason to
reach for it by default in `pilot edit`.

A second, subtler gotcha found in that same re-verification, worth
knowing about explicitly: **`runEdit`'s own static banner — printed
once via plain `fmt.Fprintln` *before* the router's `tea.Program` ever
starts, so it's never cleared (neither `pilot edit` nor `pilot deploy`
uses the alternate screen buffer) — stays visible in scrollback for the
rest of the session and can collide with a `SELECT` label.** The banner
line is literally `"═══ pilot edit — hosts.yml / group_vars / .vault
編輯精靈 ═══"`, which contains both `hosts.yml` and `group_vars` as
substrings. `SELECT group_vars` failed 150/150 presses, pointer
permanently stuck at row 0, in a script otherwise identical to a
working one — because trec's direction heuristic (walk the screen for
another line containing the label to decide up-vs-down) found the
label in the banner line *above* the already-topmost menu row and
picked "up" forever, a no-op once already at row 0. The fix was a more
specific label that isn't also a substring of the banner — `SELECT
group_vars/` (the trailing slash, part of the real menu row's text,
isn't in the banner) matched correctly and the run completed exit 0.
This is the same "unique substring" rule as above, just against a
*different, easy-to-forget* source of false matches — the static
preamble text isn't a screen you're navigating, but `SELECT` doesn't
know that, and it never scrolls out of the buffer since there's no
alt-screen. When a `SELECT` mismatches with the pointer "stuck at the
very first (or very last) row" symptom, check whether the label
appears anywhere in `runEdit`/`runDeploy`'s own startup banner text
before assuming it's a wizard bug.

### `pilot deploy` is architecturally different — many short Programs, not one

Unlike `pilot edit`, `pilot deploy`'s wizard is a long, strictly linear
sequence with no revisitable menus (see `deploy_tui.go`'s package doc
comment for why), so its rewrite kept the pre-existing shape of **one
brand-new `tea.Program` per individual prompt**, run one after another
in plain Go code — the same shape promptui's blocking `Run()` calls
already had, just bubbletea underneath. This has its own timing
consequence `pilot edit` doesn't: **there is a real gap, between one
prompt's Program exiting and the next one's Program starting, where the
terminal briefly reverts to cooked/echoed mode.** A keystroke sent into
that gap gets swallowed into the kernel's line-buffered input instead
of delivered to the new screen, and can resurface much later as garbled
echoed text once some later reader (even a spawned `ansible-playbook`
subprocess) finally drains it — confirmed live 2026-07-17: navigation
keys meant for the preflight-mode select arrived after that screen had
already defaulted, then echoed out verbatim once `ansible-playbook`
started running with no raw-mode reader active.

Mitigation: after every `EXPECT` for a new `pilot deploy` screen, add a
short settle pause (~150ms was reliable) *before* sending that screen's
first keystroke — don't rely on `EXPECT` succeeding as proof the new
Program is already reading input.

**Prefer `DOWN <n>` over `SELECT` for `pilot deploy`'s menus specifically**
— revised after a second, distinct finding during the
2026-07-17 3-VM-demo re-verification
(`docs/runbooks/archived/3vm-freeipa-wazuh-grafana-demo.md` §7 — archived
2026-07-17 as a strict subset of `docs/runbooks/minimal-poc-architecture.md`,
which covers the same topology plus more; the finding itself still stands):
right after the
scope-select screen ("單一元件") transitioned into the 20-item catalog
select, `SELECT <first catalog label>` immediately mismatched and drove
the pointer to the *last* row instead, then reported "not reached after
150 presses" stuck at the bottom — even though the catalog screen's own
cursor genuinely starts at row 0 (confirmed by removing `SELECT`
entirely and using a bare `ENTER`, which worked). The apparent cause:
`SELECT`'s row-scan can lock onto a stale pointer marker left in
scrollback by the *just-exited* scope-select Program (still visible
above the new screen, since neither Program uses the alt-screen buffer)
and compute the wrong direction from that stale position — a different
mechanism than the keystroke-swallowing gap above, but the same root
cause (many short-lived Programs, not one). `DOWN <n>` (absolute count
from `deploy_catalog.go`'s `Key:` order, per §2) does not have this
failure mode — it doesn't do a screen row-scan, so a stale pointer
elsewhere in scrollback can't mislead it. Use `SELECT` for `pilot
deploy` only if you've verified it against the current build for that
specific screen transition; default to `DOWN <n>`.

---

## 4a. Driving trec via MCP server mode (stateful sessions)

Every `trec drive --script <file>` invocation in this skill (§4, §5) is
a single one-shot command — it works identically whether you run it as
a plain shell command or as one call to `trec mcp`'s `run` tool,
because script mode owns its own stdin/child lifecycle and needs no
follow-up call. Nothing above requires MCP mode.

MCP mode matters for the steps that are inherently a back-and-forth
with a live screen: confirming a menu's real item list before writing
`DOWN <n>`/`SELECT` into a script (§2), or diagnosing a run that
derailed, or re-verifying whether `SELECT` is safe against the current
`trec` build (the note above). Those need `trec drive --interactive`'s
live PTY, which in turn needs *something* to hold its stdin open across
multiple send-then-read turns. An agent whose shell tool spawns an
independent subprocess per call — this session's `Bash` tool included —
cannot do that directly: a command sent via one `Bash` call cannot see
the screen state and send a follow-up keystroke in a later `Bash` call
to the *same* process.

Use `trec mcp`'s session tools instead (full contract: the global
`trec-mcp` skill; DSL syntax and reliability rules: the global
`trec-tui-drive` skill — this skill doesn't duplicate either):

- `terminal_start` — launch the wizard (e.g. `pilot edit --dir
  "$SCRATCH/demo"`, always with `CI=1` — see §4 — and
  `PILOT_DEBUG_MENU=1` to get each menu's live item list for free — see
  §2) and keep the returned `session_id`.
- `terminal_write` — send one DSL line at a time to that session
  (`TEXT`, `ENTER`, `SNAPSHOT`, `EXPECT ...`, `SELECT <label>`, …) —
  same vocabulary as a `--script` file, one step per call.
- `terminal_read` — pull the accumulated `OK|ERR` / `CURSOR` / `SCREEN`
  reply and decide the next step from the actual rendered screen,
  instead of a remembered or assumed item order.
- `terminal_close` — call this once the exploration is done, every
  time. An unclosed session leaks the child process; `session_list`
  can audit for ones you forgot.

Treat the resulting MCP-driven walkthrough as throwaway reconnaissance,
not the recorded evidence: once you've confirmed the real item
list/order from the screen, write (or fix) the final `trec drive
--script <file>` run per §4/§5 and record *that* as the evidence cast.
If `trec`'s MCP server isn't already connected in this session (check
via `ToolSearch` for `mcp__trec__*`), register it (e.g. `claude mcp add
trec -- trec mcp`) rather than approximating a persistent PTY with
repeated one-shot `Bash` calls — those cannot share process state
between calls no matter how they're sequenced.

---

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
trec -o "$SCRATCH/casts/0N-verify.cast" --title "Re-verify: <what>" -- bash "$SCRATCH/scripts/verify.sh"
```

`trec` (no `drive` subcommand) is a plain recorder for a non-interactive
command — no keystroke script needed since these are read-only checks,
not TUI prompts. Put all the verification commands in one shell script
with `echo "=== section ==="` headers so the resulting transcript reads
like the runbook's own §4, then feed the real output back into the
runbook using `verified-runbook`'s rules (real output only, no
"expected").

---

## 7. Known gotchas (all discovered the hard way — check first)

- **Stale `pilot` binary**: a `pilot` binary at a fixed path
  (`$(which pilot)` may be a symlink into the repo) can predate a
  feature added to source — rebuild before trusting wizard menu shape.
- **Leaked `trec mcp` sessions**: forgetting `terminal_close` after an
  §4a exploration leaves the wizard's child process (and, if it got as
  far as a save/apply step, potentially unflushed state) running
  unattended. Call `session_list` before ending a task that used MCP
  mode to check for anything you forgot to close.
- **Ansible fact-cache poisoning across VM rebuilds**: if
  `ansible.cfg` has `fact_caching = jsonfile` keyed by
  `inventory_hostname`, and a preflight/check play runs any module
  under `connection: local` for that same hostname, the *controller's*
  discovered Python interpreter gets cached under that hostname's key —
  a later real-SSH play for the same hostname then tries to use it and
  fails with `The module interpreter '...' was not found`, with an
  error that looks entirely unrelated to fact caching. Fix at the
  source (use `delegate_to: localhost` for the local-only task, not a
  play-level `connection: local`), and/or clear the specific
  `~/.ansible/<cache-dir>/s1_<hostname>` files for hostnames being
  reused before a fresh preflight.
- **`known_hosts` churn**: VM rebuilds at the same IP get a new host
  key; a stale `known_hosts` entry breaks any direct `ssh`/`sshpass`
  verification step with `Host key verification failed` — expect to
  `ssh-keygen -R <ip>` (or `-o StrictHostKeyChecking=accept-new`)
  before the first real connection each rebuild.
- **Kerberos realm case**: `kinit user@<realm>` needs the realm in the
  case FreeIPA actually configured (conventionally uppercase) — check
  `/etc/krb5.conf`'s `default_realm`, don't assume it matches the
  lowercase DNS domain string used elsewhere.
- **`kinit`'s forced-password-change flow is exactly 3 lines** (old
  password, new password, new password repeat) — a 4-line heredoc
  produces a confusing "Password mismatch"/early-EOF failure that looks
  like a wrong password, not an extra line.
- **Direct SSH/`ipa passwd`/live credential mutations are treated as
  "Remote Shell Writes" by this environment's safety classifier** even
  when the target is a disposable sandbox VM the same session just
  built — a prior approval for this class of action does not carry
  over to a new session/rebuild. Expect to ask again via
  `AskUserQuestion`, scoped to the specific action.
- **A local `ControlMaster`/`ControlPersist` SSH config silently reuses
  an already-authenticated multiplexed connection** for a later "fresh"
  `ssh`/`sshpass` call to the same `user@host` — this can mask a real
  auth-layer change (password rotation, a forced-password-change state,
  an HBAC/sudo deny) with a stale "it still works" result, since the new
  invocation never actually re-authenticates. Confirmed live,
  2026-07-16: an account genuinely in FreeIPA's "must change" state
  still let a second `sshpass` call straight through with no error,
  purely by reusing the first call's multiplexed session; adding
  `-o ControlMaster=no` (or running `ssh -O exit <user>@<host>` first)
  correctly surfaced the real block on the next attempt. Always add
  `-o ControlMaster=no` to any live-SSH re-auth check meant to prove a
  credential/policy state actually changed.

---

## References

- `references/index-computation.md` — worked example of reading
  `deploy_catalog.go`/`contracts.go` and turning them into a correct
  `trec` script, including the off-by-one class of bug.
- The sibling `verified-runbook` skill (global, `~/.agents/skills/`) —
  use it for the actual document write-up once you have real output
  and recordings in hand.
- The sibling `vm-target-spec-testing` skill (this repo) — use it when
  the task is testing a *single* spec/playbook pair on disposable VMs,
  rather than re-verifying an existing multi-component runbook.
- The sibling `trec-mcp` skill (global) — the full `trec mcp` tool
  contract (`run`/`terminal_start`/`terminal_write`/`terminal_read`/
  `terminal_close`/`session_list`) referenced by §4a.
- The sibling `trec-tui-drive` skill (global) — the current `trec
  drive` DSL reference (`SELECT`/`EXPECT`/`ASSERT`/`WAIT_CHILD_EXIT`/
  `ASSERT_EXIT`/…) and its own reliability rules; read it alongside
  this skill's §4 `SELECT`/timing findings (pilot-specific: reliable
  for `pilot edit`, needs a settle pause between screens for `pilot
  deploy`) rather than trusting either source alone.
