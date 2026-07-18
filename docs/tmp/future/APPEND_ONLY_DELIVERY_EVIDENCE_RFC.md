# RFC：Append-only Delivery Evidence Data Model

> 狀態：Final — accepted for production implementation
> 日期：2026-07-18
> 前置：`docs/tmp/future/IMPLEMENTATION_PLAN.md` M0.3
> 接受依據：2026-07-18 使用者要求關閉 review findings 並全面開始 production
> implementation；本版已固定 event/evidence idempotency、cancel finalization
> 與 maintenance audit identity。
>
> **實作標示：資料模型已決策，schema/store/runtime 尚未實作。**
> 現行 schema 仍是 v12，尚無 `delivery_events`、`verify_evidence`、
> `RunWriter`、heartbeat 或 generation rotation。
>
> Final 代表 schema/store implementation contract 已定案，不代表 schema v13 已
> 存在。M0.3 可依本 RFC 開工；完成仍須通過 §10 的 executable acceptance tests。

## 1. 決策摘要

1. 採 immutable event stream，不採可更新的 run row。
2. `delivery_runs` 是 SQL view，不是可寫 table。
3. 每個 run 使用一個 `RunWriter`；writer 以 mutex 序列化同 process append，並以
   SQLite `BEGIN IMMEDIATE` transaction 原子配置 seq 與 INSERT。
4. heartbeat、step 與 terminal 全走同一 append API。
5. `run_finished` 唯一且必須是最後一筆；heartbeat goroutine stop-and-join 後才能
   append terminal。
6. schema 以 trigger 拒絕 event／evidence 的 UPDATE／DELETE。
7. event 與 evidence append 都有 caller-stable operation/idempotency key；不確定
   commit 後重試不會產生重複事實。
8. M0.3 的 retention 是 retain-all。database generation rotation／archive prune
   屬 P5，使用獨立 `evidence_admin_events` stream，不把 maintenance event 塞進
   delivery run。

## 2. Schema v13

### 2.1 `delivery_events`

欄位：

- `event_id INTEGER PRIMARY KEY`
- `run_id TEXT NOT NULL`
- `seq INTEGER NOT NULL`
- `operation_id TEXT NOT NULL`
- `type TEXT NOT NULL`
- `step TEXT`
- `payload_json TEXT NOT NULL`
- `exit_code INTEGER`
- `created_at TEXT NOT NULL`

約束：

- `UNIQUE(run_id, seq)`
- `UNIQUE(run_id, operation_id)`
- 每 run 至多一筆 `run_started`
- 每 run 至多一筆 `run_finished`
- `run_started` 必須是 seq 1
- terminal 後不得 append

Event types：

- `run_started`
- `run_heartbeat`
- `authorization_recorded`
- `step_finished`
- `evidence_health_changed`
- `run_finished`

### 2.2 `verify_evidence`

欄位：

- `evidence_id INTEGER PRIMARY KEY`
- `run_id TEXT NOT NULL`
- `spec_path TEXT NOT NULL`
- `row_id TEXT NOT NULL`
- `host TEXT NOT NULL`
- `attempt INTEGER NOT NULL`
- `operation_id TEXT NOT NULL`
- `content_hash TEXT NOT NULL`
- `command TEXT NOT NULL`
- `expected TEXT NOT NULL`
- `stdout TEXT`
- `stderr TEXT`
- `exit_code INTEGER`
- `probe_status TEXT NOT NULL`
- `verdict TEXT NOT NULL`
- `redacted INTEGER NOT NULL`
- `stdout_truncated INTEGER NOT NULL`
- `stderr_truncated INTEGER NOT NULL`
- `started_at TEXT NOT NULL`
- `finished_at TEXT NOT NULL`

Evidence append 前必須確認：

- run 已有 `run_started`；
- run 尚未 terminal；
- `(spec_path, row_id, host)` 屬於本次 resolved verify scope。

約束：

- `UNIQUE(run_id, spec_path, row_id, host, attempt)`
- `UNIQUE(run_id, operation_id)`

`AppendEvidence` 重試命中同一 unique key 時讀回既有 row：

- `content_hash` 相同 → 視為同一 append 已成功，回 nil。
- `content_hash` 不同 → `ErrEvidenceConflict`，整個 run 不得成功。

同一次 run 重跑同一 probe 必須增加 `attempt`；不同 run 永遠有新的 run ID。

不對 SQL view 建 FK；上述 invariant 由同一 SQLite transaction 驗證。

### 2.3 `delivery_runs` view

由 event projection 得出：

- run start／last heartbeat／finish time；
- stage、component、playbook、inventory hash、host set；
- outcome、final exit code；
- `running`／`abandoned`／terminal state；
- evidence health。

view 不保存可被 UPDATE 的衍生狀態。

## 3. Append API

`internal/store` 提供：

```go
type RunWriter struct {
    // unexported DB handle, run ID, mutex and heartbeat lifecycle
}

func StartRun(ctx context.Context, db *Store, start RunStarted) (*RunWriter, error)
func (w *RunWriter) AppendEvent(ctx context.Context, event Event) error
func (w *RunWriter) AppendEvidence(ctx context.Context, rows []VerifyEvidence) error
func (w *RunWriter) Finish(ctx context.Context, finish RunFinished) error
```

不提供 update/delete event API。

每次 append：

1. 取得 writer mutex。
2. `BEGIN IMMEDIATE`。
3. 確認 run 存在且未 terminal。
4. 先以 `(run_id, operation_id)` 查重；存在且 payload hash 相同就回傳已成功，
   不同則回 conflict。
5. 讀取當前最大 seq 並配置 `next = max + 1`。
6. INSERT event。
7. COMMIT。
8. 釋放 mutex。

mutex 建立同 process happens-before；SQLite write transaction 防止意外的跨 writer
seq collision。`UNIQUE(run_id, seq)` 是最後防線，不是 allocator。

## 4. Heartbeat 與 terminal

預設：

- heartbeat interval：10 秒；
- lease：45 秒；
- grace period：15 秒。

最新 heartbeat `expires_at` 未過期 → `running`；過期且沒有 terminal →
`abandoned`。

Finish sequence：

1. cancel heartbeat context；
2. wait goroutine join；
3. 使用 `context.WithoutCancel(parent)` 衍生獨立 finalization context，再加 5 秒
   timeout；不沿用已取消的 request context；
4. append 唯一 terminal event；
5. close writer；
6. 後續 append 回 `ErrRunFinished`。

terminal persist 失敗時 CLI 必須回 non-zero `evidence_failed`，不得顯示 success。
資料庫內沒有 terminal 的 run 由 heartbeat lease 投影為 abandoned；不捏造補寫
成功 terminal。

Heartbeat append 失敗：

- 第一次失敗記憶體標記 evidence health degraded；
- 下一個成功 append 先寫 `evidence_health_changed`；
- 連續失敗超過 lease/2 時 transaction 停止新 mutation，最終 outcome
  `evidence_failed`；
- 不得在無法保存 evidence 的情況下宣稱 deploy success。

## 5. Terminal matrix

| 情境 | 行為 |
|---|---|
| 正常成功 | join heartbeat，`run_finished(success, 0)` |
| step 失敗 | 執行 policy rollback／cleanup，寫 terminal failure |
| 使用者在失敗前取消 | `run_finished(cancelled, 0)` |
| 使用者拒絕在 preflight failure 後繼續 | `run_finished(preflight_failed, non-zero)` |
| context cancel／SIGINT／SIGTERM | cleanup，寫 `cancelled` 或當前 failure |
| panic | recover、best-effort cleanup、寫 `panic`，再 re-panic／回錯 |
| SIGKILL／斷電 | 無 terminal；heartbeat lease 到期後 view 顯示 `abandoned` |

## 6. Append-only enforcement

Schema 建立 trigger：

- UPDATE `delivery_events` → abort；
- DELETE `delivery_events` → abort；
- UPDATE `verify_evidence` → abort；
- DELETE `verify_evidence` → abort。

Migration 只能在新 database generation 執行，不會暫時關閉 production DB 的
append-only trigger。

測試必須以 raw SQL 直接嘗試 UPDATE／DELETE，不能只測 store API 不提供方法。

## 7. Retention 與 prune（P5，不在 M0.3 critical path）

M0.3 固定 retain-all，不實作 prune。P5 採 generation rotation，並新增獨立的
append-only `evidence_admin_events`：

- `admin_event_id INTEGER PRIMARY KEY`
- `seq INTEGER NOT NULL UNIQUE`
- `operation_id TEXT NOT NULL UNIQUE`
- `type TEXT NOT NULL`（`archive_created`／`archive_prune_requested`／
  `archive_prune_finished`／`archive_prune_failed`）
- `payload_json TEXT NOT NULL`
- `created_at TEXT NOT NULL`

它不帶 delivery `run_id`，因此不違反每個 delivery run 必須以 `run_started`
開始的 invariant。P5 generation rotation：

1. 暫停新的 run start；既有 active run 完成或明確拒絕 rotation。
2. 建立新 SQLite generation。
3. 將仍在 retention window 的完整 closed runs依原順序 copy 到新 generation。
4. 驗證 row count、run hash 與 terminal invariant。
5. 原子切換 active database pointer。
6. 舊 generation 改為 `0600` read-only archive。
7. 新 generation 的 admin stream append `archive_created`，保存 archive hash、
   範圍與路徑。

`pilot runs prune --before <t>` 的語意是刪除符合 policy 的 **archive files**，不是
對 active tables DELETE rows。刪除前：

- 顯示 archive run/time range；
- 要求明確確認；
- active DB 先 append `archive_prune_requested`；
- 成功後 append `archive_prune_finished`；刪除失敗 append
  `archive_prune_failed`，不使用會誤稱已成功的單一事件。

因此 active/archived database 內部仍維持 immutable。

## 8. Redaction、大小與檔案權限

- matcher 使用記憶體原始結果。
- persist 順序：evaluate → redact → truncate → persist。
- SQLite、NDJSON、Markdown report 共用 redaction pipeline。
- stdout／stderr 各上限 64 KiB，保存 truncated flag。
- pilot 無法取得 plaintext 時，secret-bearing output 不持久化。
- evidence DB、report 與 archive 權限一律 `0600`。
- event command 保存 input reference，不保存 secret materialization。

## 9. Migration

- base schema 與 v12→v13 migration 同一變更完成；v12→v13 只新增 active
  delivery tables/view/triggers，不做 generation rotation。
- `spec_checkpoints` 保留為最新狀態 cache，不搬成歷史 evidence。
- 舊 NDJSON 不自動匯入；需要 replay 時透過 historical adapter 明確標記來源。
- standalone `pilot verify` 也建立 run start／heartbeat／finish。

## 10. 驗收

- 並行 heartbeat、step、evidence、finish 在 `go test -race` 下無 race。
- seq 連續且唯一，terminal 唯一且最後。
- terminal 後 append 一律失敗。
- 同 operation 重試且 hash 相同不重複；hash 不同 fail closed。
- 同 host × row × attempt 不可產生兩筆不同 evidence。
- raw SQL UPDATE／DELETE 一律被 trigger 拒絕。
- v12→v13 migration replay 可重複驗證。
- 兩次 verify 產生兩個 run，前次 evidence 未改寫。
- heartbeat lease 可正確投影 running／abandoned。
- redaction corpus 不在任何持久化 sink 找到 secret。
- cancelled context 下仍用 bounded finalization context 寫 terminal；若 store
  故障則 CLI 非零且 run 最終投影 abandoned。

P5 另驗收 generation rotation hash／count、admin event 三態與 active DB 無 row
DELETE；不阻擋 M0.3。

## 11. 非目標

- M0.3 不提供 evidence query UX；查詢命令屬 P5。
- 不以 event stream 取代 metrics/logging。
- 不承諾 SIGKILL 後能補寫 terminal。
- 不允許以「修復舊 row」方式更正 evidence；更正必須是新 event 或新 run。
