# `SELECT` reliability and label collisions in `pilot edit`

> Reference for the `pilot-trec-verification` skill.
> Read when choosing between `SELECT` and `DOWN <n>` for `pilot edit`, or when a
> `SELECT` sticks at the first/last row.

---

## Huh v2 menus need a custom `--pointer`

`[live 2026-09-24]` Since the Huh v2 adapters (`internal/tui`, `5cc7ab1`,
2026-08-20), every `pilot edit` menu row is drawn behind Huh's `┃ ` field
border, so the pointer row reads `┃ > hosts.yml — …`. `trec drive`'s default
`--pointer` (`^\s*(?:❯|▸|›|→|»|>)\s`) is anchored at the start of the line and
never matches it.

A strict-lint-clean script whose only navigation was `ACTIVATE 離開 WITH ENTER`
on the top menu failed on both `origin/main` `583df40` and a build with the
newer Charm stack:

```
SELECT "離開": not reached after 150 presses (no pointer row found)
```

The same script exited 0 with:

```bash
--pointer '^\s*┃?\s*>\s'
```

Pass it on every `trec drive` run, script or `--interactive`, that uses
`SELECT`, `FOCUS`, `ACTIVATE`, `CHOOSE` or `TOGGLE`. The `┃?` keeps plain `> `
rows matching too. `pilot deploy` renders through the same `internal/tui`
adapters (`deploy_tui.go`), but only `pilot edit` was re-checked.

## `SELECT` is the recommended default for `pilot edit`

`pilot edit` is **one continuous Bubble Tea `tea.Program` for the whole
invocation** (`edit_tui.go`'s router) — every screen, including the role
checklist, uses the same rendering model.

An older stale-pointer bug attributed to `SELECT` was in fact caused by
switching between two rendering libraries mid-session (promptui's inline
scrolling vs. bubbletea's screen model), which confused trec's screen-tracking
across that boundary. That boundary no longer exists.

`[re-verified live 2026-07-17]` A full `trec drive --script` walkthrough (`CI=1`,
default `--pointer`) covering top menu → hosts.yml → add host → host menu →
roles menu → role checklist (toggle + confirm) → **back to roles menu, then host
menu, then host list, all via `SELECT` immediately after the checklist** → save →
top menu → quit: every `SELECT` matched on the first try, exit 0, expected file
written. (That run predates the Huh v2 adapters. The same walkthrough now needs
the `--pointer` above.)

Prefer `SELECT` over `DOWN <n>` here because it survives a menu's item count
drifting (see `../SKILL.md` §2) without recomputing an index.

**Two standing caveats:**

- **The role checklist** (multi-select) — pre-Huh this was an exception that
  needed `DOWN <n>` + `SPACE`. The Huh checklist renders every row, and
  `TOGGLE <row-unique text>` works there (live 2026-09-24). See
  `role-checklist.md`.
- **`SELECT` only moves the pointer — it does not submit.** Every `SELECT` needs
  its own following `ENTER`.

`DOWN <n>` index counting still works identically (cursor resets to 0 on every
fresh menu) and remains a fine fallback on a `SELECT` mismatch — but there is no
longer a known reason to reach for it by default in `pilot edit`.

## Pick a label substring unique to one row

`[live 2026-07-17]` `SELECT 完成`, intended for the roles menu's `✅ 完成` row,
matched the checklist's own hint text instead (`space 勾選/取消、enter 完成`) and
re-entered the checklist. `SELECT ✅ 完成` — the emoji prefix is part of the
rendered row and unique — fixed it immediately.

This is the `trec-tui-drive` skill's own rule #1 (`label 選畫面上該行獨有的子字串`),
restated because it's easy to reach for the shortest label that merely *looks*
unique and be wrong.

## The startup banner is in scrollback forever and can steal a `SELECT`

`runEdit`'s static banner is printed once via plain `fmt.Fprintln` **before** the
router's `tea.Program` starts, so it is never cleared — neither `pilot edit` nor
`pilot deploy` uses the alternate screen buffer. It stays visible in scrollback
for the whole session.

The banner line is literally
`"═══ pilot edit — hosts.yml / group_vars / .vault 編輯精靈 ═══"`, which contains
both `hosts.yml` and `group_vars` as substrings.

**Symptom:** `SELECT group_vars` failed 150/150 presses with the pointer
permanently stuck at row 0, in a script otherwise identical to a working one.
trec's direction heuristic — walk the screen for another line containing the
label to decide up-vs-down — found the label in the banner line *above* the
already-topmost menu row and picked "up" forever, a no-op at row 0.

**Fix:** a more specific label that isn't also a banner substring —
`SELECT group_vars/` (the trailing slash is part of the real menu row's text but
not in the banner) matched correctly and the run completed exit 0.

**Generalize:** when a `SELECT` mismatches with the pointer "stuck at the very
first (or very last) row", check whether the label appears anywhere in
`runEdit`/`runDeploy`'s own startup banner before assuming a wizard bug. The
static preamble isn't a screen you're navigating, but `SELECT` doesn't know
that, and it never scrolls out of the buffer.
