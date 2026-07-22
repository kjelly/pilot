# Actual-run evidence 與 candidate revision 規則

本文件定義 pilot repo 如何同時做到「每條操作都真的跑過」與「runbook/spec 不隨每次
重測無限膨脹」。它是 `AGENTS.md` §1 的細節規範。

## 1. 四種內容必須分開

| 內容 | Canonical location | 更新方式 |
|---|---|---|
| Acceptance contract | `docs/verification/<feature>.md` | 只在需求或驗收語意改變時更新 |
| 目前操作流程 | `docs/runbooks/<feature>.md` | 只保留現在可執行的步驟、rollback 與有效 gotcha |
| Sanitized evidence 摘要 | `docs/evidence/<feature>/<date>-<tested-revision>.md` | 每個被接受的 candidate 一份，不混入 runbook |
| 完整原始輸出 | Gitignored `.verification/` 或暫時的受控驗收儲存 | 不提交 Git；只在一次性驗收與診斷期間保存 |

Runbook 與 spec 不得當成 chronological test journal。重跑時更新「最後驗證」摘要與
latest evidence link；舊結果留在獨立 evidence record 或 Git history。

## 2. Candidate-first 工作流

1. 在一般 worktree 開發並跑快速測試。此時 worktree 可以是 dirty。
2. 完成本輪 spec、playbook、fixture、code、inventory contract 與依賴鎖檔後，凍結成
   本地 candidate commit。
3. 從 candidate revision 建立乾淨、隔離的 checkout，確認沒有 tracked modification、
   會參與測試的 untracked file 或外部 overlay。
4. 在該 checkout 對實際 target 讀 inventory facts，再跑 dry-run、apply、verify、
   idempotency 與必要的 rollback/failure path。
5. inventory/spec 不一致時，無論選 A 改環境或 B 改 spec，都要重讀 facts 並從正式鏈
   起點重跑。失敗就修改原工作樹並產生新 candidate；舊 candidate 的 evidence 不得沿用。
6. 成功後產生 sanitized evidence record，以後續 evidence-only commit 提交。它必須引用
   tested commit、tested tree 與 execution-affecting file hashes。
7. 若 rebase/squash 改寫 commit ID，必須重新證明 execution-affecting file hashes 未變；
   任何內容差異都需要新 candidate 與新 evidence run。

「完整測試前不得有 commit」不是本 repo 的規則。本地 candidate commit 是凍結測試輸入，
不代表發布、merge 或部署授權。

## 3. Evidence record 最小欄位

每份 sanitized evidence record 至少包含：

- feature/spec 與 apply playbook；
- run ID、UTC 時間與操作者；
- tested commit ID、tree ID、execution-affecting file hashes；
- target 類型、inventory 來源與實際 host/group 摘要；
- dry-run、apply、verify、idempotency 的真實 verdict、exit code 與摘要數字；
- target image digest，以及會影響結果之外部 state fingerprint（若適用）；
- redaction 類別；
- 失敗時的真實結論，不得改寫成 PASS。

完整 stdout/stderr、逐 row payload、秘密值與內部 operational identifiers 不放入
committed evidence summary。

`.verification/` 是一次性驗收與診斷的 staging location，不是 durable archive。接受
candidate 的前提是提交一份可獨立判讀的 sanitized evidence summary，不是封存 raw
artifact。成功候選的 raw stdout/stderr/cast 在摘要提交後可以清除；失敗候選的 raw
evidence 保留到修正已由新 candidate 驗證即可。命令若讀取秘密，只記 secret-file
reference 或 stable command ID，不記展開後的秘密值。

Agent 判讀先讀 command result 或 compact summary：candidate/tree、exit code、duration、
`PLAY RECAP` 與 verify verdict counts。只有 audit、baseline comparison、使用者明確要求，
或失敗診斷才讀 raw artifact；失敗時先以 `FAILED!`、`fatal:`、`unreachable`、`PLAY RECAP`
定位，再開啟受影響 task 的有限上下文。只有 audit 要求、被接受的 known deviation，或仍會
影響目前操作的失敗才提交 sanitized failure record；已被後續 candidate 取代的一般失敗
不得塞回 runbook。

## 4. 何時 evidence 失效

下列任一內容在正式測試後改變，既有 evidence 立即失效：

- verification spec 的 command、Expected、target 或變數契約；
- apply/site/preflight/fixture playbook；
- 執行路徑上的 Go code、script、template 或 dependency lock；
- inventory role/group contract 或 target image；
- 會改變結果的 vault key、外部服務或環境設定。

只修改拼字、說明文字、latest link 或 evidence metadata，且 execution-affecting file hash
沒有改變時，可以只補 evidence-only commit，不必重跑。

## 5. 文件內容預算

- runbook 保留 current procedure，不保留逐版完整測試輸出。
- verification spec 保留 acceptance contract，不放大型演練敘事。
- 只有仍影響目前操作的事故，才濃縮成 gotcha；開發過程由 issue、commit 與 evidence
  record 保存。
- Coding agent 預設只讀 command result、compact summary 與 sanitized evidence，不讀 raw
  artifact；只有 audit、failure diagnosis、baseline comparison 或使用者明確要求時才載入。
