# The role checklist (`multiSelect`) screen

> Reference for the `pilot-trec-verification` skill.
> Read before driving the role checklist, and before concluding it cannot be
> driven. Includes the `DOWN 0` history and the wrong-screen false alarm.

---

## Use `DOWN <n>` + `SPACE`, not `SELECT` — and don't re-litigate this

**A previous agent session concluded the role checklist "can't be reliably
driven by `trec drive --script` for a full ~19-role pass" and proposed
hand-writing `hosts.yml` outside the wizard as a documented exception. That
conclusion was wrong — don't repeat it.**

This exact screen has been driven successfully by scripted `trec drive --script`
across multiple independent from-scratch rebuilds:
`docs/runbooks/minimal-poc-architecture.md` v5.2, v6.0 and v7.0 each built a
multi-host, ~19-role `hosts.yml` this way with zero hand-edited YAML.

`hosts.yml` has **no** tool-endorsed hand-edit exception — unlike the vault's
nested-YAML refusal. Treating it as one without first ruling out the proven
method violates this skill's §0 precondition as much as silently hand-editing
would.

Those rounds succeeded because they toggled each role with `DOWN <n>` then
`SPACE`. That matters structurally, not stylistically:

- `multiSelectModel` (`cmd/pilot/cmd/tui_multiselect.go`) renders only a
  **scrolling window** of the item list (`listVisibleRows`, capped at 15 rows by
  default). With ~19+ roles most rows are off-screen at any moment, and `SELECT`
  works by scanning the *currently rendered* screen text — so it cannot reliably
  target a scrolled-out row.
- The screen's own title (`主機 "<host>" 的角色`) and its in-screen hint line
  (`☑ 逐項勾選角色(...)`) routinely share substrings with role names or with each
  other — the same collision class documented in `select-labels.md`, one more
  reason content-based matching is fragile here specifically.
- `up`/`down` in `multiSelectModel.Update` is pure `cursor++`/`cursor--` with no
  dependency on what's rendered, and `windowStart` auto-follows the cursor. So
  `DOWN <n>` + `SPACE` is fully content-independent and immune to both problems.

Get the role's position from `internal/inventory/contracts.go`
(`roleContracts` order), not from memory — the same "recompute indices fresh"
discipline as `../SKILL.md` §2.

**If a `SELECT`-based script gets the checklist's pointer stuck, the fix is to
switch that screen's navigation to `DOWN`/`SPACE` — not to conclude the wizard
can't do the job.**

## Never write `DOWN 0`

For index 0, omit the `DOWN` line entirely — the cursor already starts at row 0
on every fresh screen.

**On a current `trec` build** (commit `6f77bfc` and later) `DOWN 0` is a hard
parse error caught before the driven program even starts —
`parsePositiveCount` replaced the old `atoiOr1`/`atoiOrDef` silent fallback:

```
$ trec drive --script script.txt -- pilot edit --dir demo
trec drive: load script: line 2: DOWN needs a positive count
```

(exit 2). `[re-verified live 2026-07-17]`

**On any build at or before `f7bf88e`/`efd26ad`** it silently misbehaved as
`DOWN 1`, because `drive.go` treated any non-positive count as invalid input and
fell back to `1`. Live-reproduced: a script sending `DOWN 0` → `SPACE` on the
checklist checked `freeipa-client` (row 1), not `freeipa-server` (row 0),
deterministically. This was hit and fixed once before, in v5.2's changelog.

**Practical upshot:** check `trec --version`/build before treating "the wrong
checklist row got checked" as this bug. A current build refuses to run the
script at all, which makes the mistake self-evident. Either way the rule is
unchanged. This remains the single most likely explanation for a wrong-row
symptom on an older build, or a script load failure mentioning `DOWN` on a
current one — check your script for a literal `DOWN 0` before suspecting
`multiSelectModel`'s cursor logic, which is correct.

Commit `6f77bfc` also normalizes extra/leading whitespace between an opcode and
its argument in the plain-text script format. If a `TEXT` payload genuinely needs
leading whitespace, use a JSON step: `{"kind":"text","text":" hello"}`. See
`trec`'s own `skills/trec-tui-drive/SKILL.md` rules 8/9 for the authoritative
wording.

Self-catch either failure by reading the saved `hosts.yml` back before trusting
the wizard's exit code — see `timing.md`.

## If `SELECT` targets a label that "isn't there", check which screen you're on

`☑ 逐項勾選角色(...)` is the **roles-menu** item that *leads into* the checklist.
It does not appear anywhere on the checklist screen itself, whose own hint line
reads `↑/↓ 移動　space 勾選/取消　enter 完成`.

So a script that does `SELECT 逐項勾選角色` a *second* time while already inside
the checklist will correctly fail to find that text — it is genuinely not part of
the current screen. That's a "which screen am I actually on" bug, not a
scrollback bug.

The classic cause of the missed transition: a bare `SELECT` never submits, it
only moves the pointer, and the following `ENTER` was missing.

**Fix:** `EXPECT <text unique to the screen you expect to be on>` immediately
after every `ENTER`, so a missed transition fails loudly at the exact step it
happened instead of surfacing as a confusing mismatch several steps later.

`[live 2026-07-17]` A full `hosts.yml`-build script — top menu → hosts.yml → add
host → host menu → roles menu → checklist → back through roles menu/host
menu/host list → save → quit — using nothing but disambiguated `SELECT` labels
and zero `DOWN` lines ran clean end to end. The router's lack of an alt-screen
buffer is not by itself a blocker when labels are chosen correctly and
transitions are confirmed with `EXPECT`.
