# Driving trec via MCP server mode (stateful sessions)

> Reference for the `pilot-trec-verification` skill.
> Read ONLY when a step needs a live back-and-forth with the screen
> (menu discovery, diagnosing a derailed run). Not needed for `trec drive
> --script` runs. Pair with the global `trec-mcp` skill, which you also only
> need in this mode.

---

## When MCP mode is and isn't needed

Every `trec drive --script <file>` invocation in this skill works identically as
a plain shell command or as one call to `trec mcp`'s `run` tool — script mode
owns its own stdin/child lifecycle and needs no follow-up call. **Nothing in the
main workflow requires MCP mode.**

MCP mode matters only for steps that are inherently a back-and-forth with a live
screen:

- confirming a menu's real item list before writing `DOWN <n>`/`SELECT` into a
  script (`../SKILL.md` §2);
- diagnosing a run that derailed;
- re-verifying whether `SELECT` is safe against the current `trec` build.

Those need `trec drive --interactive`'s live PTY, which needs *something* to hold
its stdin open across multiple send-then-read turns. An agent whose shell tool
spawns an independent subprocess per call — this session's `Bash` tool included —
cannot do that: a command sent via one call cannot see the screen state and send a
follow-up keystroke in a later call to the *same* process.

## The session tools

Full contract: the global `trec-mcp` skill. DSL syntax and reliability rules: the
global `trec-tui-drive` skill. This file duplicates neither.

What `terminal_write` does depends on what `terminal_start` launched
`[live 2026-09-24]`:

| `terminal_start` launches | `terminal_write` sends | How to observe |
|---|---|---|
| `trec drive --interactive` wrapping the wizard, e.g. `trec drive --interactive --pointer '^\s*┃?\s*>\s' -o "$SCRATCH/casts/exploration/<name>.cast" -- env CI=1 pilot edit --presentation --dir "$SCRATCH/demo"` | one newline-terminated DSL line per call (`EXPECT …`, `ACTIVATE <label> WITH ENTER`, `TEXT …`, `SNAPSHOT`, …) — the same vocabulary as a `--script` file | `terminal_read` returns `OK`/`ERR`, `CURSOR` and `SCREEN` for each line; the child's exit shows up as `trec drive: process exited 0` with `running=false` |
| the wizard itself, e.g. `env CI=1 pilot edit --presentation --dir "$SCRATCH/demo"` | raw bytes, typed verbatim | `terminal_key` for keys (`ENTER`, `DOWN`, `ESCAPE`, `CTRLU`, …), `terminal_write` only for literal text, `terminal_expect` / `terminal_read_screen` to see the screen |

- **In the raw mode a DSL line is just text.** `ENTER\n` typed the word `ENTER`
  into the `hosts.yml 路徑` field (the path became `…/hosts.ymlENTER`), and the
  trailing `\n` — Ctrl+J, not Enter — submitted it.
- **Give `trec drive --interactive` an `-o` path under `$SCRATCH`.** Without one
  it writes `record_<timestamp>.cast` and its `.result.json` into the MCP
  server's working directory, which was the repo root.
- **`--pointer '^\s*┃?\s*>\s'` applies here too**; see `select-labels.md`.
  `WAIT_CHILD_EXIT` and `ASSERT_EXIT` are script-only.
- **`terminal_read_screen` can lag the raw stream.** Wait with `terminal_expect`
  or `terminal_wait_quiet` before reading it.
- **`terminal_close`** — call once the exploration is done, every time. An
  unclosed session leaks the child process; `session_list` can audit for ones you
  forgot.

**For a recording that must be evidence, do not call `terminal_close` while the
wizard is still running.** First use the wizard's own exit item (for `pilot edit`,
return to the top menu and choose `離開`), then poll `terminal_read` until it
reports `running=false` and `exit_code=0`. Only then `terminal_close`, then
`cast_verify`. Closing an active session is an operator termination: a
save/bootstrap may already have succeeded, but the cast is rightly finalized as
`aborted`, not `success`.

## MCP walkthroughs are reconnaissance, not evidence

Once you've confirmed the real item list/order from the screen, write (or fix) the
final `trec drive --script <file>` run per `../SKILL.md` §4/§5 and record *that*
as the evidence cast.

If `trec`'s MCP server isn't already connected (check via `ToolSearch` for
`mcp__trec__*`), register it (e.g. `claude mcp add trec -- trec mcp`) rather than
approximating a persistent PTY with repeated one-shot `Bash` calls — those cannot
share process state between calls no matter how they're sequenced.
