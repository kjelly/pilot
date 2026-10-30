# pr-ready — Codex / Claude Code / agy 通用 GitHub Draft PR 修復 Skill

這是 **Skill + 原生 subagents + fail-closed Quality Gate**，不是會獨立執行的排程 daemon。呼叫 Skill 的 Agent 需要實際具備 Git、GitHub CLI、Python 與必要的網路權限，才能執行修復、驗證、push、Ready transition。未達品質門檻時不得轉 Ready；絕不自動 merge 或繞過 branch protection。

## 一次安裝三平台（Linux/macOS/WSL）

前置：`git`、`gh`（執行 `gh auth login`）、`python3`，以及已安裝的 Codex CLI / Claude Code / agy（只需安裝你要使用的 CLI）。

將壓縮檔解壓後進入 `pr-ready` 目錄：

```bash
bash scripts/install.sh --global
```

更新已安裝版本：先自行備份任何修改過的 agent 定義，再執行：

```bash
bash scripts/install.sh --global --force
```

不想使用符號連結時改用 `--copy`（後續更新需要重新執行安裝器）：

```bash
bash scripts/install.sh --global --copy
```

只安裝到某個 Git 儲存庫（可提交配置供團隊使用）：

```bash
bash scripts/install.sh --project /path/to/your/repo
```

**注意：**不要在尚有相同名字的 `.claude/skills/pr-ready`、`.codex/agents/pr-*` 等自訂檔案上強制覆蓋；預設發現衝突會中止而非覆寫。

## 三平台 Skill 和原生 Agent 位置

| 平台 | 全域 Skill | 專案 Skill | 原生 agents |
|---|---|---|---|
| Codex | `~/.agents/skills/pr-ready` | `.agents/skills/pr-ready` | `~/.codex/agents/pr-*.toml` / `.codex/agents/` |
| Claude Code | `~/.claude/skills/pr-ready` | `.claude/skills/pr-ready` | `~/.claude/agents/pr-*.md` / `.claude/agents/` |
| agy CLI | `~/.gemini/antigravity-cli/skills/pr-ready` | `.agents/skills/pr-ready` | `~/.gemini/config/agents/pr-*.md` / `.agents/agents/` |
| Antigravity App/IDE | `~/.gemini/config/skills/pr-ready` | `.agents/skills/pr-ready` | 同 agy 原生 agents |

共用 `SKILL.md`、`scripts/`、`references/`，不用每個平台維護三套 prompt。`install.sh` 會安裝 SA、Coder、Reviewer **原生 agent 定義**，沒有強制指定模型，使用平台原本的模型與權限規則。

## 呼叫方式

在已登入 GitHub、擁有 repo 原始碼的工作目錄啟動任一 CLI：

**Codex CLI**

```text
$pr-ready 處理 https://github.com/OWNER/REPO/pull/123
$pr-ready 處理目前 repo 所有 Draft PR，最多同時兩個
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

1. 主 Agent 讀取 PR/CI/Issue/review，建立依賴 DAG，隔離 worktrees。
2. SA 判斷根因與架構；Coder 修復並測試；Reviewer 在**獨立 context** 進行審查。
3. 若 Reviewer 提出 P0/P1/P2，回交 Coder 修復；連續 3 次有效修正未收斂則 SA 再評估。
4. 僅在同一個最新 commit SHA 上，確認 acceptance criteria、測試、lint、static analysis、required CI、review threads 及衝突後，才執行 `gh pr ready`。
5. 不可更新、無法修復或無法驗證的 PR 保持 Draft，輸出 DRAFT-BLOCKED 與 blocker。

## Quality Gate 腳本（可單獨使用）

已存在 `.pr-ready/evidence.json`（格式見 `references/evidence-schema.md`）時，從原 PR branch worktree 執行：

```bash
python3 /path/to/pr-ready/scripts/pr_gate.py \
  --repo OWNER/REPO --pr 123 \
  --evidence .pr-ready/evidence.json --worktree .

# 狀態為 GATE-PASS 後，準備將 Draft 轉成 Ready for Review：
python3 /path/to/pr-ready/scripts/pr_gate.py \
  --repo OWNER/REPO --pr 123 \
  --evidence .pr-ready/evidence.json --worktree . --ready
```

- `GATE-PASS`：門檻檢查通過，**尚未變更 PR 狀態**。
- `READY`：GitHub 已確認從 Draft 改為 Ready、HEAD 未變。
- `DRAFT-BLOCKED`：資料不足或至少一項品質門檻不合格（exit code 2）。

驗證命令可由 `scripts/run_check.py` 執行並產生 SHA-bound receipt；腳本不會自動編造 acceptance criteria / reviewer 結論。`gh pr checks --required` 和 GraphQL reviewThreads 資訊不可存取時採 **fail-closed**。

## 本機測試

```bash
python3 -m unittest discover -s tests -v
bash -n scripts/install.sh
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
