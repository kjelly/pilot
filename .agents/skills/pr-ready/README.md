# pr-ready — Codex / Claude Code / agy 通用 GitHub Draft PR 修復 Skill

這是 **Skill + 原生 subagents + fail-closed Quality Gate**，不是會獨立執行的排程 daemon。呼叫 Skill 的 Agent 需要實際具備 Git、GitHub CLI、Python 與必要的網路權限，才能執行修復、驗證、push、Ready transition。未達品質門檻時不得轉 Ready；絕不自動 merge 或繞過 branch protection。

Ready 前必須包含最新 `main`：gate 獨立讀取遠端 base tip，確認它是 PR HEAD 的祖先，並核對 PR Base SHA。尚未包含時先將已確認的最新 base 合併到原 PR 分支，再跑相關驗證/CI 與新的獨立審查；沒有衝突也要檢查。讀取失敗或對齊無法確認時維持 Draft。

## 安裝（repo 內建，不另外安裝）

這個 skill 是 pilot repository 專用，沒有全域安裝與安裝腳本。canonical 內容就是
`.agents/skills/pr-ready/`（Codex 與 agy 直接讀這裡）；Claude Code 透過
`.claude/skills/pr-ready` 與 `.claude/agents/pr-*.md` 的 symlink 讀同一份，
Codex 的角色定義是 `.codex/agents/pr-*.toml` 的位元組副本。
`cmd/pilot/cmd/agent_skill_consistency_test.go` 鎖住這些連結與副本，`make skill-test` 跑 `tests/`。
改角色 prompt 時三個平台副本與 `.codex/agents` 要一起改，測試會擋漏改。
模型只釘在角色定義檔（見 SKILL.md 的 Project runtime configuration），orchestrator 用當前 session 的模型。

前置：`git`、`gh`（執行 `gh auth login`）、`python3`，以及你要使用的 CLI（Codex CLI / Claude Code / agy）。

| 平台 | Skill | 原生 agents |
|---|---|---|
| Codex | `.agents/skills/pr-ready` | `.codex/agents/pr-*.toml`（副本） |
| Claude Code | `.claude/skills/pr-ready`（symlink） | `.claude/agents/pr-*.md`（symlink） |
| agy CLI / App / IDE | `.agents/skills/pr-ready` | `platforms/agy/agents/`（要用 agy 時複製到 `.agents/agents/`，並把 `/.agents/agents/` 寫進 `$(git rev-parse --git-path info/exclude)`，原因見 checkout 契約） |

共用 `SKILL.md`、`scripts/`、`references/`，不用每個平台維護三套 prompt。

## 呼叫方式

在已登入 GitHub、擁有 repo 原始碼的工作目錄啟動任一 CLI：

**Codex CLI**

```text
$pr-ready 處理 https://github.com/OWNER/REPO/pull/123
$pr-ready 處理目前 branch 對應的單一 Draft PR
```

**Claude Code**

```text
/pr-ready 處理 https://github.com/OWNER/REPO/pull/123
```

**Antigravity CLI（agy）**

```text
/pr-ready 處理 https://github.com/OWNER/REPO/pull/123
```

若 Skill 沒有顯示，重新啟動 CLI；Codex 可使用 `/skills`，Claude Code 透過 `/` 查看命令選單，agy 使用 `/skills` 查看。

## 流程

1. 每次只處理一個 PR；多個或全部項目先請使用者選一個。主 Agent 先依 checkout 契約（`.agents/skills/_shared/single-item-checkout.md`，以 repo 根目錄路徑引用；Claude Code 經 `.claude/skills/pr-ready` symlink 讀本 skill，相對的 `../_shared` 連結不會解析）先做 snapshot，再選定 PR 與蒐集證據規則，最後用 `checkout_preflight.py` 以完整 SHA 在目前乾淨 checkout 精確 land 該 PR 的原始 head branch（不以名稱 checkout、不建立 per-PR worktrees），之後才分析 PR/CI/Issue/review。
2. 每則 review 意見（人、bot 或之前的自動審查）都先當成待驗證的主張分類（`valid`/`invalid`/`needs_evidence`/`nonblocking`），只有成立的才交給 Coder。不成立的意見不改 code：獨立 Reviewer 在看不到主 Agent 結論的情況下確認後，主 Agent 在 GitHub 回覆反證，記錄在 evidence 的 `disputed_review_comments`（見 `references/review-comments.md`）。同一主張沒有新證據又被提出時交給人決定，不再來回修改或回覆。
3. SA 判斷根因與架構；Coder 修復並測試；Reviewer 在**獨立 context** 進行審查。Coder 的本機測試只跑 diff 觸及的 package 與新增的 regression，全套 `go test ./...` 交給 CI 的 `Go test` job（SKILL.md「Pilot: cycle-time rules」）。
4. 若 Reviewer 提出 P0/P1/P2，回交 Coder 修復；連續 3 次有效修正未收斂則 SA 再評估。Reviewer 只剩 P3/P4 時這一輪就結束：主 Agent 回覆並 resolve thread、記進 PR body 或 follow-up issue，不再派 Coder。
5. push 與 evidence 準備好後，主 Agent 保持 session 執行 `pr_gate.py --wait --ready --restore-sha "$START_SHA" --restore-branch="$START_BRANCH"` 持續等待 CI；每次重新確認 HEAD、review/evidence 未變與所有 gate。CI 完成後自動 final PR-branch preflight → 復原起始 branch/SHA → 重查 remote/pins → Ready → post-action verification；復原失敗不改 PR 狀態，Ready 後不再切分支。START_SHA 使用起始 branch 當下 tip；若起始為 detached HEAD，使用記錄的 SHA 並省略 --restore-branch。pending 本身不結束 invocation；只有明確 timeout、取消、runtime 限制或真正 blocker 才 checkpoint。僅在同一個最新 commit SHA 上，確認 acceptance criteria、測試、lint、static analysis、required CI、review threads（每個都已 resolve，P3/P4 也一樣，否則 pr-review-merge 會再轉回 Draft）及衝突後，才執行 `gh pr ready`。
6. 不可更新、無法修復或無法驗證的 PR 保持 Draft，輸出 DRAFT-BLOCKED 與 blocker。

## Quality Gate 腳本（可單獨使用）

每個 PR 的狀態放在 `.pr-ready/<N>/`（N 為 PR 編號；同一個 checkout 會依序服務不同 PR）。已存在 `.pr-ready/<N>/evidence.json`（格式見 `references/evidence-schema.md`）時，在已切到原 PR head branch 的目前 checkout 執行（`$SNAP` 是 checkout 契約取得的 snapshot 目錄；單獨使用時可改用 `.agents/skills/pr-ready` 的實體路徑）：

```bash
python3 "$SNAP/.agents/skills/pr-ready/scripts/pr_gate.py" \
  --repo OWNER/REPO --pr 123 \
  --evidence .pr-ready/123/evidence.json --worktree .

# push、review 與 evidence 準備好後的預設流程；保持 session 等到自動 Ready：
python3 "$SNAP/.agents/skills/pr-ready/scripts/pr_gate.py" \
  --repo OWNER/REPO --pr 123 \
  --evidence .pr-ready/123/evidence.json --worktree . --wait --ready --restore-sha "$START_SHA" --restore-branch="$START_BRANCH"
```

- `WAITING-CI`：其他 gate 通過，保持 session 等待 CI；每 30 秒重新驗證 pins 與全部 gate。`--poll-interval` 上限 60 秒。
- `WAIT-INTERRUPTED`：明確 `--wait-timeout` 或 SIGINT/SIGTERM 中斷；預設無 timeout。狀態保存在 `.pr-ready/N/wait-status.json`，不覆寫 Root checkpoint；`ready_invoked` 表示是否已嘗試 Ready，若為 true 必須重查遠端狀態。
- `GATE-PASS`：門檻檢查通過，**尚未變更 PR 狀態**。
- `READY`：GitHub 已確認從 Draft 改為 Ready、HEAD 未變。
- `DRAFT-BLOCKED`：資料不足或至少一項品質門檻不合格（exit code 2）。
- `receipt_reuse`：receipt 或獨立 review 的 SHA 是 HEAD 的祖先、且中間只改了 base branch `.github/pr-evidence.json` 的 `evidence_only_paths`（例如 `docs/evidence/**` 的 evidence commit）時，gate 自己跑 `git diff` 判斷後接受，並在這個欄位列出；base branch 從 `refs/remotes/<--base-remote>/<base>` 讀（預設 `origin`），本機沒有 fetch 到就回到嚴格的 HEAD 綁定。其他任何 delta 都要重跑。

驗證命令可由 `scripts/run_check.py` 執行並產生 SHA-bound receipt；腳本不會自動編造 acceptance criteria / reviewer 結論。`gh pr checks --required` 和 GraphQL reviewThreads 資訊不可存取時採 **fail-closed**；branch 沒有 required checks 時 `--required` 以 exit 1、stdout 為空、stderr 恰為 `no required checks reported on the '<branch>' branch` 結束，gate 只在這個完全吻合的情況視為 0 個 required checks，其餘 checks 仍須全部通過；stdout 有 JSON 就一律照 JSON 判斷（名稱含這段文字的 required check 失敗仍然是失敗），訊息混在其他輸出、大小寫不同或其他 exit status 一律 fail-closed。wait 模式一律讀取完整 review/comment body 與 edit metadata，新增或修改就停下交給 Root triage；非 wait 模式 evidence 有 `disputed_review_comments` 時，gate 另外讀取 PR 的 conversation comments 與 reviews，確認被反駁的意見與回覆都在這個 PR 上、回覆在意見之後、inline 回覆在同一個 thread 且仍是最新一則、其他回覆內含原意見的 URL；反駁本身對不對由獨立 Reviewer 判斷，gate 判斷不了。

## 本機測試

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile scripts/*.py
```

wait 模式也會固定 evidence JSON 與引用的本機 report/log/artifact（PR 自己 commit 的檔案固定為它在 PR head 的 Git blob，復原起始 branch 後仍以同一事實驗證；未被 Git 追蹤的 `.pr-ready` 檔案固定 bytes）、PR HEAD/base/branch、fetched base policy ref、title/body；任何變動均停止。同時查詢完整 current-HEAD Actions runs，workflow 尚未完成（即使可見 checks 全綠、dependent jobs 還沒建立）仍等待；new run/rerun 不得遮掉之前 active run/attempt，API/metadata 不完整則阻擋，確定空清單支援無 Actions 的 repo。歷史 terminal workflow 結論只證明已結束，仍以 current checks/exemption 決定品質。pending exemption 仍持續等待；真正的 non-CI blocker、未知 metadata/API error 則立即停止。主 Agent 必須持續監看 attached process，不可把 local attestations 搬進 GitHub Actions 或背景放著就結束。

純單元測試不會連接 GitHub，亦不會更動任何真實 PR。需在實際 repo/authenticated `gh` 環境驗證 end-to-end。

## 外部規格

- [OpenAI / Codex skills](https://learn.chatgpt.com/docs/build-skills)
- [OpenAI / Codex subagents](https://learn.chatgpt.com/docs/agent-configuration/subagents)
- [Claude Code skills](https://code.claude.com/docs/en/skills)
- [Claude Code subagents](https://code.claude.com/docs/en/sub-agents)
- [Antigravity skills](https://antigravity.google/docs/skills)
- [Antigravity custom subagents](https://antigravity.google/docs/subagents)
- [GitHub CLI PR checks](https://cli.github.com/manual/gh_pr_checks)
