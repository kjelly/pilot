# `pilot deploy`'s wizard: architecture, prompts, confirm chain

> Reference for the `pilot-trec-verification` skill.
> Read before authoring or changing any `pilot deploy` drive script.

---

## Architecturally different from `pilot edit`: many short Programs, not one

`pilot deploy`'s wizard is a long, strictly linear sequence with no revisitable
menus (see `deploy_tui.go`'s package doc comment for why), so it runs **one
brand-new `tea.Program` per individual prompt**, one after another in plain Go
code.

That has a timing consequence `pilot edit` doesn't: **there is a real gap between
one prompt's Program exiting and the next one's starting, where the terminal
briefly reverts to cooked/echoed mode.** A keystroke sent into that gap is
swallowed into the kernel's line-buffered input instead of delivered to the new
screen, and can resurface much later as garbled echoed text once some later
reader — even a spawned `ansible-playbook` subprocess — finally drains it.

`[live 2026-07-17]` Navigation keys meant for the preflight-mode select arrived
after that screen had already defaulted, then echoed out verbatim once
`ansible-playbook` started running with no raw-mode reader active.

**Mitigation:** after every `EXPECT` for a new `pilot deploy` screen, add a short
settle pause (~150ms was reliable) *before* sending that screen's first
keystroke. Don't rely on `EXPECT` succeeding as proof the new Program is already
reading input.

## Prefer `DOWN <n>` over `SELECT` for `pilot deploy`'s menus

**Symptom:** right after the scope-select screen (`單一元件`) transitioned into
the 20-item catalog select, `SELECT <first catalog label>` immediately mismatched
and drove the pointer to the *last* row, then reported "not reached after 150
presses" stuck at the bottom — even though the catalog screen's cursor genuinely
starts at row 0 (confirmed by removing `SELECT` entirely and using a bare
`ENTER`, which worked).

**Cause:** `SELECT`'s row-scan can lock onto a stale pointer marker left in
scrollback by the *just-exited* scope-select Program — still visible above the
new screen, since neither Program uses the alt-screen buffer — and compute the
wrong direction from that stale position. A different mechanism from the
keystroke-swallowing gap above, but the same root cause: many short-lived
Programs, not one.

`DOWN <n>` (absolute count from `deploy_catalog.go`'s `Key:` order, per
`../SKILL.md` §2) doesn't do a screen row-scan, so a stale pointer elsewhere in
scrollback can't mislead it.

Use `SELECT` for `pilot deploy` only if you've verified it against the current
build for that specific screen transition; default to `DOWN <n>`.

`[live 2026-07-17, 3-VM-demo re-verification — finding recorded in
`docs/runbooks/archived/3vm-freeipa-wazuh-grafana-demo.md` §7, archived as a
strict subset of `docs/runbooks/minimal-poc-architecture.md`; the finding itself
still stands]`

## Two easily-missed prompts before the confirm chain

`[confirmed live 2026-08-12 against HEAD `88b62db`]` Between the inventory-path
prompt and the preflight menu, and again right after the vault-file prompt, two
more confirms fire. **Script both or the run stalls waiting on unscripted
input:**

- 「要不要先看一下這份 inventory 的拓樸圖？」 `[Y/n]` — shows a topology graph of
  role placement; safe to answer `n`.
- 「這次套用要手動輸入 sudo(become)密碼嗎？」 `[y/N]` — default No; answer `n` when
  every target host's `ansible_user` already has passwordless sudo/root (true for
  this repo's vm-target-provisioned hosts, which connect as `root` directly).

## The confirm chain — exact prompts, exact defaults

After the preflight and the stage/`--limit`/`--tags`/vault/`-e` questions,
`pilot deploy` runs this fixed sequence. Strings are from `deploy.go` — **do not
paraphrase them in `EXPECT`s.**

1. 「要先預覽(--check --diff)再決定要不要真的套用嗎？」 `[Y/n]` — default **Yes**.
2. 「確定要執行預覽指令嗎？」 `[Y/n]` — default **Yes**; answering it runs the
   **preview**, streaming the full ansible output.
3. On a clean preview: 「✅ 預覽完成，沒有錯誤。」 followed by
   「預覽看起來沒問題，要接著套用真正的變更嗎？」 `[y/N]` — default **No**. A bare
   `ENTER` here aborts with 「先在這裡停下來，沒有套用任何變更。」 and exits 0 — a
   run that *looks* fine but applied nothing. You must send a single `y` (no
   trailing `ENTER` — see `pilot-edit-wizard.md`).
4. 「確定要執行正式套用指令嗎？」 `[Y/n]` for the real apply — a **different**
   literal string from step 2, not a repeat of it. Only now does anything mutate.

Steps 2 and 4 emit distinct strings, confirmed by reading
`executeDeploymentTransaction` directly (`question := "確定要執行正式套用指令嗎？"`,
then `if check { question = "確定要執行預覽指令嗎？" }`).
`[verified against HEAD `88b62db`; treat two-string behavior as authoritative for
that revision and later]`

**Two anchoring rules, worth keeping as defensive practice against a future
refactor reintroducing a shared string:**

- **Don't `EXPECT` a string that already occurred.** 「PLAY RECAP」 appears
  multiple times (preflight recap, screen redraws). An `EXPECT` on `PLAY RECAP`
  alone can match stale scrollback while the preview is still streaming — anchor
  the post-preview step on 「✅ 預覽完成」 or 「要接著套用真正的變更嗎」 instead.
- **The apply gate defaults to No.** No drive script reaches a real apply by only
  ever sending `ENTER` — if every confirm in your script is a bare `ENTER`, you
  recorded a preview, not a deploy. Check the cast for 「✅ 套用完成」 before
  calling it evidence.
