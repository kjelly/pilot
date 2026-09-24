# Timing and `trec drive` flags

> Reference for the `pilot-trec-verification` skill.
> Read before setting `--key-delay` / `--settle-delay` / `--timeout`, or when a
> run exits 0 having done nothing.

---

## `--key-delay`: keep it at ~150ms

Below ~100ms, a long burst of repeated `DOWN`/`SPACE` presses (e.g. selecting
many roles in the checklist) can silently drop one keystroke, landing the cursor
one row off with no error. 150ms has been reliable — don't go much lower purely
to save time.

## Verify success by content, never by exit code

A script that runs out of instructions while the target program is still waiting
on a prompt does **not** make `trec drive` hang forever — but it also doesn't
mean the intended action happened. **A derailed script exits 0 just as cleanly as
a correct one, having done nothing you intended.**

Grep the output for the wizard's own confirmation text (`✅ 已存檔`,
`✅ 套用完成`), not `trec drive: process exited 0`.

## End every `pilot edit` drive by actually exiting the wizard

Navigate back to the top menu, `SELECT 離開` + `ENTER`, then `WAIT_CHILD_EXIT` +
`ASSERT_EXIT 0`.

A script that stops after its last edit — or ends with `QUIT` — leaves the wizard
alive at a menu. `trec drive` then waits out `--timeout`, kills the child, and
writes `status: failed` / `exit_code: -1` into the `.result.json`, turning a
perfectly successful edit into red evidence. `[all four edit casts of the
2026-07-17 minimal-poc run failed this way despite every save succeeding]`

## `EXPECT_QUIET` does not prove the frame is final — guard input with `EXPECT`

`[live 2026-09-24, origin/main 583df40]` On the fleet-vars add screen, after
`TEXT_AND_ENTER scratch_var`, the renderer changed the label `變數名稱` to
`變數值` by moving the cursor and writing only `值` plus erase-line. trec's
emulator showed `┃ 變數名稱值`.

- `EXPECT_QUIET 500` returned once the stream had been quiet for 500 ms.
- The next `ASSERT 變數值` failed.
- The renderer's corrective full-line redraw arrived a few milliseconds later.

With `EXPECT 變數值` in place of the `ASSERT`, the same flow passed on the same
binary.

After any step that changes the screen, guard the next input with
`EXPECT <text>`, which waits up to its timeout, not `ASSERT`, which checks once.
A build with lipgloss v2.0.6 (ultraviolet 2026-08-11) rewrites whole lines and
did not show the transient frame. The rule holds either way.

## A derailed run corrupts nothing

`pilot edit`/`deploy` only write on an explicit save/apply step — so a run that
lands on the wrong menu item leaves nothing corrupted, but nothing saved either.
Fix the index bug and rerun from scratch; there is no partial state to reconcile.

## `--timeout`: always explicit, always ≥ your longest `EXPECT@`

`pilot deploy`'s actual apply can run 15–40+ minutes for a full `site.yml`. Give
`--timeout` a generous ceiling and run the whole thing under
`run_in_background`. No scripted input is needed after the last confirm keypress —
`trec drive` just keeps recording until the child exits on its own.

**Pass `--timeout` explicitly even when your last step is an `EXPECT@<ms>` with
its own generous per-step timeout.** A run was observed getting killed by the
*default* `--timeout` (120s) while still legitimately waiting on a final
`EXPECT@3600000 PLAY RECAP` — the per-step override did not reliably supersede the
global default in every build. Set `--timeout` to at least your longest `EXPECT@`
value; don't rely on the per-step value alone.
