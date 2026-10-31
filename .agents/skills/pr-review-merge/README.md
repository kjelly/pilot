# pr-review-merge — Cross-platform GitHub PR Review & Merge Skill

**目標：**使用 `gh` 對非草稿（Ready）PR 做獨立 Code Review；符合品質門檻者直接合併，有明確阻擋項目的 PR 留下原因並轉 Draft；狀態不明或 CI/核准尚未完成則保留 Ready (`WAITING`)。

支援 **Codex CLI / Claude Code / Google Antigravity CLI (`agy`) / Antigravity IDE**。Skill 共用 `SKILL.md`、GitHub 安全腳本、JSON Evidence Contract，各工具有原生 Subagent 定義。

## 安裝（repo 內建，不另外安裝）

這個 skill 是 pilot repository 專用，沒有全域安裝與安裝腳本。canonical 內容就是
`.agents/skills/pr-review-merge/`（Codex 與 agy 直接讀這裡）；Claude Code 透過
`.claude/skills/pr-review-merge` 與 `.claude/agents/prm-*.md` 的 symlink 讀同一份，
Codex 的角色定義是 `.codex/agents/prm-*.toml` 的位元組副本。
`cmd/pilot/cmd/agent_skill_consistency_test.go` 鎖住這些連結與副本，
`make skill-test` 跑 `tests/`。改角色 prompt 時三個平台副本與 `.codex/agents` 要一起改，
測試會擋漏改。模型只釘在角色定義檔，orchestrator 用當前 session 的模型。

要求：`bash`、`python3 >= 3.10`、`gh`、`git`，以及具必要權限的 `gh auth login`。
執行 `gh auth status` 確認授權。

## 使用

**Codex CLI**

```text
$pr-review-merge 審查 kjelly/pilot 所有非 Draft PR；合格則 merge，不合格轉 Draft 並留言。
```

**Claude Code / agy CLI / Antigravity IDE**

```text
/pr-review-merge 審查 kjelly/pilot 所有非 Draft PR；合格則 merge，不合格轉 Draft 並留言。
```

指定 PR：

```text
/pr-review-merge 審查 kjelly/pilot #42 #43 #44
```

**參數及預設策略：**最多 2 個獨立 Reviewer Subagents 並行、Merge 串行、預設 merge commit（本 repo 慣例；`apply_decision.py --method` 預設 `merge`）、禁止管理員繞過/Auto-merge/刪除分支（GitHub 的 deleteBranchOnMerge 會自己刪）。CI Pending、等待 Approval 或 Merge Queue 為 `WAITING`，不自動轉 Draft；`CHANGES_REQUESTED`（等原 reviewer 重新審查）、Reviewer 確認與本 PR 無關而失敗的 check、沒有新證據就重提已被反駁的 finding，也是 `WAITING`，否則 pr-ready 會再把它轉回 Ready。重大安全/資料毀損風險若需要額外人類簽核，亦保持 WAITING。

**Actual-run 紀錄：**base branch 的 `.github/pr-evidence.json` 要求 `actual-run` 紀錄時，`review_gate.py` 以 GitHub API 在 PR 的 **base SHA** 讀這份 manifest（不讀 head，PR 不能放寬自己的要求），並檢查 reviewer evidence 的 `target_validation`：缺少或格式錯、`blocked`、PR 改到 manifest `required_paths`（`playbooks/**`、`docs/verification/**`、`contracts/**`）卻寫 `not-needed`、或 `required` 卻沒有 HEAD 上已提交且寫明 tested revision 的 `docs/evidence/**` 紀錄（tested revision 等於 HEAD，或是 HEAD 的祖先且之後只改 evidence-only 檔案），一律 `WAITING`，不會 merge。manifest 格式、glob 與 evidence-only delta 規則沿用 issue-to-pr 的 `scripts/repo_evidence.py`（依路徑載入）。轉 Draft 仍只來自 reviewer 對缺紀錄開的 blocking `P1` finding。

## 內部安全檢查（供 Agent 呼叫）

```bash
# 取得完整（跨分頁）Ready PR 清單
python3 scripts/list_ready.py --repo OWNER/REPO

# Reviewer 綁定 HEAD/Base SHA 的證據檔產生後，進行唯讀 Quality Gate
python3 scripts/review_gate.py --repo OWNER/REPO --pr 123 --evidence /safe/state/123/review.json

# 乾跑（不變更 GitHub）
python3 scripts/apply_decision.py --repo OWNER/REPO --pr 123 --evidence /safe/state/123/review.json

# 真正執行：僅在通過 live gate 時才合併或降草稿
python3 scripts/apply_decision.py --repo OWNER/REPO --pr 123 --evidence /safe/state/123/review.json --execute
```

`apply_decision.py` 不會相信先前的 gate 結果，會在 mutation 前重新檢查 HEAD/Base 與 GitHub API 狀態，並使用同一 repository 的跨程序寫入鎖（POSIX `flock`）。`gh pr merge --match-head-commit` 可防止合併錯誤的 HEAD；結果還要遠端驗證 `state == MERGED`。Draft 先留言具體 blocking findings 才執行 `gh pr ready --undo`。

**重要限制：**程式可強制校對 SHA、CI、threads、規則、PR 狀態與 Evidence Schema，但**無法機械證明 Reviewer 真實獨立、分析完整或程式邏輯完全正確**。Agent 必須確實調用獨立 reviewer 並提供可追溯證據。不可單憑 `Review PASS` 字串進行 Merge。

## 測試

```bash
python3 -m unittest discover -s tests -v
```

測試使用模擬 `gh`，**不碰真實 GitHub**；contents/compare API 的回應取自 `tests/fixtures/github_api.json`（對 kjelly/pilot 唯讀 `gh api` 的實際擷取）。`apply_decision.py` 的寫入鎖在測試中指向每個測試自己的暫存 `PRM_STATE_DIR`，不碰 `~/.cache/pr-review-merge`，兩個同時跑的 `make skill-test` 不會互搶。必須在自己的 repository 上做一次 end-to-end 驗證，才能確認平台版本、GitHub 權限、branch rules 和 Agent subagent runtime 均正常。

## 與其他 Skill 的關係

- `issue-to-pr`：Issue → 建立 Ready PR。
- `pr-review-merge`：Ready PR → `MERGED` / `DRAFT-BLOCKED` / `WAITING`。
- `pr-ready`：修復 Draft PR → Ready PR。

所有規則及契約見 [SKILL.md](SKILL.md)、[Quality Gate](references/quality-gate.md)、[Evidence Contract](references/evidence-contract.md) 及 [Platforms](references/platforms.md)。

## 參考規格

- [GitHub CLI PR merge](https://cli.github.com/manual/gh_pr_merge)
- [GitHub CLI PR ready](https://cli.github.com/manual/gh_pr_ready)
- [GitHub CLI PR checks](https://cli.github.com/manual/gh_pr_checks)
- [GitHub REST branch rules](https://docs.github.com/en/rest/repos/rules#get-rules-for-a-branch)
- [Codex agents](https://learn.chatgpt.com/docs/agent-configuration/subagents)
- [Antigravity skills](https://www.antigravity.google/docs/skills)
