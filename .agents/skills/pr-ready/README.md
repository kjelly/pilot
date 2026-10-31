# pr-ready — Codex / Claude Code / agy 通用 GitHub Draft PR 修復 Skill

這是 **Skill + 原生 subagents + fail-closed Quality Gate**，不是會獨立執行的排程 daemon。呼叫 Skill 的 Agent 需要實際具備 Git、GitHub CLI、Python 與必要的網路權限，才能執行修復、驗證、push、Ready transition。未達品質門檻時不得轉 Ready；絕不自動 merge 或繞過 branch protection。

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
| agy CLI / App / IDE | `.agents/skills/pr-ready` | `platforms/agy/agents/`（要用 agy 時複製到 `.agents/agents/`） |

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

1. 每次只處理一個 PR；多個或全部項目先請使用者選一個。主 Agent 先依 checkout 契約（`.agents/skills/_shared/single-item-checkout.md`，以 repo 根目錄路徑引用；Claude Code 經 `.claude/skills/pr-ready` symlink 讀本 skill，相對的 `../_shared` 連結不會解析）做 preflight 與 snapshot，在目前乾淨 checkout 切到該 PR 原始 head branch，再分析 PR/CI/Issue/review；不建立 per-PR worktrees。
2. SA 判斷根因與架構；Coder 修復並測試；Reviewer 在**獨立 context** 進行審查。
3. 若 Reviewer 提出 P0/P1/P2，回交 Coder 修復；連續 3 次有效修正未收斂則 SA 再評估。
4. 僅在同一個最新 commit SHA 上，確認 acceptance criteria、測試、lint、static analysis、required CI、review threads 及衝突後，才執行 `gh pr ready`。
5. 不可更新、無法修復或無法驗證的 PR 保持 Draft，輸出 DRAFT-BLOCKED 與 blocker。
6. 不論結果，結束時依契約的 restore step 切回起始 branch：僅在 checkout 乾淨、該 PR branch 沒有未 push 的 commit、且回去的路徑通過 preflight 時才切；否則停在該 PR branch 並說明原因。

## Quality Gate 腳本（可單獨使用）

每個 PR 的狀態放在 `.pr-ready/<N>/`（N 為 PR 編號；同一個 checkout 會依序服務不同 PR）。已存在 `.pr-ready/<N>/evidence.json`（格式見 `references/evidence-schema.md`）時，在已切到原 PR head branch 的目前 checkout 執行（`$SNAP` 是 checkout 契約取得的 snapshot 目錄；單獨使用時可改用 `.agents/skills/pr-ready` 的實體路徑）：

```bash
python3 "$SNAP/.agents/skills/pr-ready/scripts/pr_gate.py" \
  --repo OWNER/REPO --pr 123 \
  --evidence .pr-ready/123/evidence.json --worktree .

# 狀態為 GATE-PASS 後，準備將 Draft 轉成 Ready for Review：
python3 "$SNAP/.agents/skills/pr-ready/scripts/pr_gate.py" \
  --repo OWNER/REPO --pr 123 \
  --evidence .pr-ready/123/evidence.json --worktree . --ready
```

- `GATE-PASS`：門檻檢查通過，**尚未變更 PR 狀態**。
- `READY`：GitHub 已確認從 Draft 改為 Ready、HEAD 未變。
- `DRAFT-BLOCKED`：資料不足或至少一項品質門檻不合格（exit code 2）。

驗證命令可由 `scripts/run_check.py` 執行並產生 SHA-bound receipt；腳本不會自動編造 acceptance criteria / reviewer 結論。`gh pr checks --required` 和 GraphQL reviewThreads 資訊不可存取時採 **fail-closed**。

## 本機測試

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile scripts/*.py
```

純單元測試不會連接 GitHub，亦不會更動任何真實 PR。需在實際 repo/authenticated `gh` 環境驗證 end-to-end。

## 外部規格

- [OpenAI / Codex skills](https://learn.chatgpt.com/docs/build-skills)
- [OpenAI / Codex subagents](https://learn.chatgpt.com/docs/agent-configuration/subagents)
- [Claude Code skills](https://code.claude.com/docs/en/skills)
- [Claude Code subagents](https://code.claude.com/docs/en/sub-agents)
- [Antigravity skills](https://antigravity.google/docs/skills)
- [Antigravity custom subagents](https://antigravity.google/docs/subagents)
- [GitHub CLI PR checks](https://cli.github.com/manual/gh_pr_checks)
