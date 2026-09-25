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

## Select `pilot deploy`'s menus by label

`[live 2026-09-24]` With the Huh `--pointer` (`select-labels.md`),
`ACTIVATE <row text> WITH ENTER` picked the right row on every menu of a
single-component run. Each new screen got `EXPECT <prompt>`,
`EXPECT_QUIET 200` and a guard (`ENTER_IF`/`TEXT_IF`/the `ACTIVATE` itself)
before its first keystroke. The menus covered: 單一元件, the catalog (row 23
of 29), the stage, and the preflight mode. The script passed
`trec drive lint --strict`, and the run went through preview and the real
apply to `✅ 套用完成`.

Use labels rather than counting. The catalog
(`挑一個要佈署的元件 (contract 驅動)`) follows `deploy_catalog.go`'s order but
leaves out `Reconcile: true` and experimental entries, so row numbers do not
match `Key:` line numbers (`../SKILL.md` §2).

The prompts of that run, in order (sandbox stage, no `staging`/`prod` group):

1. `Inventory 檔路徑` (default `inventory.yml`)
2. `要不要先看一下這份 inventory 的拓樸圖？` `[Y/n]`
3. `要佈署什麼？` — 全站部署 / 單一元件
4. `挑一個要佈署的元件 (contract 驅動)`
5. `要限定只套用到哪個 group/host 嗎？` (`-e target_group=`; empty = the component's group)
6. `要套用到哪個 stage？`
7. `--limit`, then `--tags` (empty = none)
8. `偵測到 …/.vault/main.yaml，這次佈署要用它當密碼變數檔嗎？` `[Y/n]`
9. `這次套用要手動輸入 sudo(become)密碼嗎？` `[y/N]`
10. `還有其他 -e 變數要帶嗎？`
11. `要先跑前置檢查(preflight)嗎？` — full / static only / skip
12. the confirm chain below

**History (pre-Huh, 2026-07-17):** `SELECT <first catalog label>` right after
the scope select mismatched and drove the pointer to the last row ("not reached
after 150 presses"). The cause was a stale pointer marker left in scrollback by
the just-exited scope-select Program; `DOWN <n>` from `deploy_catalog.go`
avoided it at the time. That finding is recorded in
`docs/runbooks/archived/3vm-freeipa-wazuh-grafana-demo.md` §7. It did not
reproduce on 2026-09-24. If you fall back to `DOWN <n>`, count only the
entries the menu shows (`../SKILL.md` §2).

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
