# Actual-run evidence 與 candidate revision 規則

本文件定義 pilot repo 如何同時做到「每條操作都真的跑過」與「runbook/spec 不隨每次
重測無限膨脹」。它是 `AGENTS.md` §1 的細節規範。

## 1. 四種內容必須分開

| 內容 | Canonical location | 更新方式 |
|---|---|---|
| Acceptance contract | `docs/verification/<feature>.md` | 只在需求或驗收語意改變時更新 |
| 目前操作流程 | `docs/runbooks/<feature>.md` | 只保留現在可執行的步驟、rollback 與有效 gotcha |
| Sanitized evidence 摘要 | `docs/evidence/<feature>/<change>.md`（一個變更一份，例如 `issue-214.md`）與 `docs/evidence/<feature>/LATEST.md` | 同一變更的每個 candidate **就地覆寫**同一份 record；被取代的 candidate 由 Git history 保存。`LATEST.md` 由 pilot 在鏈成功時改寫，指向目前有效的 record；spec/runbook 只連到 `LATEST.md`，重新驗證就不必再改 spec/runbook。既有的 `<date>-<tested-revision>.md` 不必改名 |
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
6. 跑鏈時帶 `--evidence-record docs/evidence/<feature>/<change>.md`（`vm-target test` 與
   `vm-target topology test` 都支援），pilot 在鏈結束時寫出 record 的機器產生部分（§3.1），
   操作者只補兩段手寫內容，再以後續 evidence-only commit 提交；成功時 pilot 同步改寫
   `LATEST.md`。record 引用的 tested commit、tested tree 與執行閉包的檔案 hash 由 pilot
   算出，不手抄。
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

### 3.1 機器產生與手寫的分界

`pilot vm-target test --evidence-record <file>`（topology test 同）寫出的 record 以
`<!-- pilot-evidence-record v1 … -->` 標記開頭，接一個 ```json 區塊（schema
`pilot-evidence-record/v1`），之後的表格只是同一份資料的人類可讀版。pilot 填的欄位：

- `candidate`：tested commit、tree 與來源（`git`：從執行所在的 checkout 讀，checkout
  有修改或未追蹤檔案時標 `dirty`；`flag`：從 `git archive` 複本執行時用
  `--evidence-candidate`/`--evidence-tree` 提供；`unknown` 的 record 沒有 gate 會接受）；
- `pilot_binary` 的 SHA-256 與版本、`tooling` 的 ansible-playbook 版本；
- `targets`（節點、group、IP、base image 路徑與 SHA-256）與 `inventory`（pilot 這次
  render 出的 host/group 名稱，不含連線變數）；
- `steps`：L1/L3/L4/L5/L6 與 rollback 各自的狀態、時間與每台主機的 PLAY RECAP 計數，
  沒跑到的步驟標 `not-run`；`verify`：每份 spec 的 verdict 與 pass/fail/skip；
- `closure`：執行閉包——playbook、`import_playbook`、`include_tasks`/`import_tasks`、
  `template`/`copy`/`script` 的來源、`vars_files`/`include_vars`、`lookup('file'|
  'template'|'fileglob')`、spec、對應的 contract、repo 內的 `-e @file`、`ansible.cfg`／
  `requirements.yml`，每個檔案附 mode、Git blob id 與 SHA-256。含模板的路徑展開成 glob
  並標 `dynamic`；整個 basename 都是變數的引用（例如 `{{ freeipa_roster_file }}`）
  列在 `unresolved`，repo 外的檔案（vault）只列路徑在 `external`，不讀也不 hash。
  Go code 不列：它以 `pilot_binary` 的 hash 代表，gate 另以「純 base import」規則
  證明。這份清單就是 reviewer 做 `target_reuse` 盤點時的 `execution_paths`，不必再手列；
- `redaction`：掃描每個步驟擷取的輸出，找 `-e @file`（明文 YAML）裡 secret 命名的
  key 與 `-e key=value` 的 secret 值；只記 key 與命中次數，不記值；加密的 vault 檔列在
  `skipped`。命中時 record 仍會寫出，但 pilot 在 stderr 警告，原始輸出不得提交。

操作者只寫兩段：`## Failure paths and arms (fill in)`（鏈外另外跑的失敗路徑／對照
arm：注入的故障、預期 rc、復原後狀態、artifact）與 `## Not covered / limits (fill in)`。
同一變更的下一個 candidate 覆寫 record 時，這兩段會帶著「carried over from <舊
candidate>」註記保留下來，重新檢查後改寫即可。`pilot evidence closure --playbook …
--spec … -- -e @…` 可以單獨印出閉包，給 reviewer 或 gate 對照。

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

合入較新的 base 不會自動讓既有 actual-run 有效或失效。只有 base manifest 明確
標為 `kind: target-run`、獨立 reviewer 對最新 HEAD/base 完成執行依賴盤點、
且 gate 證明盤點範圍的 Git blob/mode 未變，並驗證其他差異是純 upstream 匯入
或逐項確認不影響執行的變更，才可沿用原 candidate 的 target evidence。
新增或改動執行依賴、無法建立完整依賴範圍時仍需重跑；不改寫 tested revision，
也不沿用舊 review/CI。欄位與機器判定見
[共用 target evidence 規則](../.agents/skills/_shared/target-evidence-reuse.md)。

## 5. 文件內容預算

- runbook 保留 current procedure，不保留逐版完整測試輸出。
- verification spec 保留 acceptance contract，不放大型演練敘事。
- 只有仍影響目前操作的事故，才濃縮成 gotcha；開發過程由 issue、commit 與 evidence
  record 保存。
- Coding agent 預設只讀 command result、compact summary 與 sanitized evidence，不讀 raw
  artifact；只有 audit、failure diagnosis、baseline comparison 或使用者明確要求時才載入。
