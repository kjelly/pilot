# 原始問題

`it-core` 的 `disk_io_busy` baseline warning 經常短暫出現後自動解決。需要建立一個針對「特定主機 × 特定事件」的自動學習機制，以 LLM 輔助判斷已知週期性模式是否應暫時抑制通知；不得全域排除訊號或掩蓋真正的儲存故障。

# 報告內文

## 1. 問題與已知事實

2026-09-08 04:47:45 UTC 至 2026-09-09 06:07:45 UTC，`it-core` 已記錄 133 個同時符合下列條件的 episode：

- `detector_source=baseline`
- `dominant_feature=disk_io_busy`
- `category=storage`

統計如下：

| Profile | Episode 數 | 已解決 episode 中位持續時間 | 範圍 |
|---|---:|---:|---:|
| v1 | 125 | 135 秒 | 60–705 秒 |
| v2 | 5 | 375 秒 | 180–450 秒 |
| v3 | 3（其中 1 個仍 active） | 960 秒 | 810–1110 秒 |

範例 resolved event 的 `disk_io_busy=0.3873`，表示五分鐘平均 busy 約 39%。這個數值本身不是足以認定儲存故障的證據；它只是相對於該主機 baseline 出現了變化。

現行 `linux-host-v1` profile 已正確處理一件事：`disk_io_busy` 設為 `critical: false`，因此它不能單獨升級成 critical。但 warning 仍完全依賴相對 baseline，造成短暫的週期性工作反覆 fire/resolve，對 Teams 與 SRE 造成通知疲勞。

## 2. 現行 LLM 流程的限制

目前 FLM provider 已啟用，主 provider 是 `flm`，fallback 是 `ollama-chat`。它只會收到已通過本地 candidate 門檻的當前 telemetry：

- `subject_id`、`subject_kind`、`site`
- 當前 feature 值，例如 `disk_io_busy`

它不會收到同一台主機的歷史 episode 次數、持續時間、間隔、時間週期或先前 suppression 決定。現行融合策略也只能讓模型提高 score；模型判定 `BENIGN` 時會回退到本地 score，不能抑制通知。

因此「LLM 已被呼叫」不等於「LLM 已經學會這是正常模式」，更不等於事件可安全排除。

## 3. 目標與非目標

### 目標

- 對 `subject_id + subject_kind + profile_id + feature` 建立獨立、可稽核、可撤銷的學習狀態。
- 僅在重複短暫且缺乏壓力佐證的模式下，讓 LLM 建議暫時抑制 warning 通知。
- 保留原始 anomaly、episode、metrics 和模型決定，讓 SRE 能追溯被抑制的原因。
- 一旦有明確儲存壓力或其他高風險訊號，立即略過／撤銷 suppression。

### 非目標

- 不刪除 `disk_io_busy` feature，也不全域調高所有主機的門檻。
- 不允許 LLM 改寫 feature profile、inventory、Alertmanager 或系統設定。
- 不允許 LLM 抑制 critical、人工建立的告警或明確的容量／可用性事件。
- 不把未驗證的 LLM 自由文字當作控制指令。

## 4. 建議架構

```text
Thanos metrics
  → deterministic local detector
  → host-feature history aggregator
  → deterministic eligibility gate
  → LLM suppression advisor
  → validated, time-bounded suppression policy
  → lifecycle / outbox / Alertmanager
```

### 4.1 Deterministic eligibility gate

LLM 不是每 cycle 都要呼叫。只有全部條件成立時才建立「學習審查候選」：

1. 事件是 warning，且只由單一可抑制 feature 主導，例如 `disk_io_busy`。
2. 同一 host-feature 在觀察窗口（建議 24 小時）至少出現指定次數，例如 10 次。
3. 多數 episode 持續時間低於上限，例如 15 分鐘。
4. 沒有 critical transition、持續性容量告警、資料遺失或服務不可用。
5. 沒有 I/O pressure 的佐證；細節見第 5 節。

這個 gate 由 Go 程式決定，不能由 LLM 放寬。它同時限制成本與降低模型對偶發真實事件的影響。

### 4.2 Host-feature history aggregator

聚合器從 SQLite episode/history 與 feature sample 產生最小必要摘要：

- `subject_id`、`subject_kind`、`site`、`profile_id`、profile version、feature name。
- 1 小時、24 小時、7 天的 fire 次數與 resolved 次數。
- episode 持續時間的 min / median / p95 / max。
- 相鄰 episode 的間隔、變異係數和時間桶分布，用來辨識週期性。
- 最近與歷史的 raw value 範圍，而不是完整 metrics 序列。
- 壓力佐證特徵的摘要，以及是否存在 critical 或其他 feature 共現。
- 現有 suppression policy、到期時間與最近一次模型 verdict。

歷史資料以 `subject_id + subject_kind + profile_id + feature` 做 key。profile version 必須被記錄，但不應默默跨版本沿用 policy；版本變更後應進入重新評估。

### 4.3 LLM suppression advisor

LLM 僅接收上述結構化、已聚合且無敏感資訊的摘要。輸出必須使用嚴格 schema，例如：

```json
{
  "schema_version": 1,
  "decision": "suppress_warning",
  "confidence": "high",
  "ttl_minutes": 1440,
  "reason_code": "periodic_nonimpacting_io",
  "required_recheck": true
}
```

允許值只能是：

- `suppress_warning`：建立短期 policy。
- `keep_alerting`：維持目前行為。
- `uncertain`：維持目前行為。

程式必須驗證 enum、TTL 範圍、schema version 與 decision 的 eligibility。任何 timeout、解析失敗、schema 不合或 circuit open 都 fail closed，維持原本通知行為。

## 5. 儲存壓力的佐證訊號

在允許抑制 `disk_io_busy` 前，profile 應新增或接入下列 feature，避免只靠 busy time 判斷：

- CPU iowait ratio。
- Linux PSI：`/proc/pressure/io` 的 `some` 與 `full`。
- 裝置 queue depth 或 average request latency（Prometheus 若已有對應 exporter metric）。
- filesystem 使用率與 inode 使用率。
- 檔案系統錯誤、I/O error、timeout、read-only remount 等 log signal。

下列任一情況必須否決 suppression 或立即撤銷既有 suppression：

- I/O PSI / iowait / latency 超過明確門檻。
- `disk_io_busy` 高於絕對高壓門檻並持續，例如超過 80%。
- 任一 critical signal、服務 SLO 失敗、磁碟錯誤或容量即將耗盡。
- 同時有 `load1_per_cpu`、CPU、記憶體等其他強 contributor。

## 6. Policy 與 lifecycle 行為

### 6.1 抑制不是刪除

當 policy 生效時：

1. 本地 detector、baseline sample 與 lifecycle 仍照常執行。
2. episode 仍寫入 SQLite，並標記 `notification_suppressed=true`、policy ID 與 reason code。
3. 不向 Alertmanager 送出該 warning 的 firing／refresh；或以獨立低優先級 audit event 記錄。
4. Prometheus 要暴露 suppressed event counter 與 active suppression gauge。
5. CLI / dashboard 必須可以顯示「被抑制，非正常」的事件。

### 6.2 有效期限與撤銷

- 初次 policy TTL 建議 24 小時；不得永久有效。
- 每次續約都必須重新通過 deterministic gate 並重新詢問 LLM。
- profile version、特徵定義或壓力佐證規則變動時，舊 policy 失效。
- operator 必須可以手動 `approve`、`revoke` 或對 host-feature 建立短期 denylist。
- critical path 永遠略過 suppression policy。

## 7. SQLite 資料模型

新增兩張表即可；原始 `signal_episodes` 與 `signal_history` 不應被覆寫。

```sql
CREATE TABLE learned_suppressions (
  policy_id TEXT PRIMARY KEY,
  subject_id TEXT NOT NULL,
  subject_kind TEXT NOT NULL,
  profile_id TEXT NOT NULL,
  profile_version INTEGER NOT NULL,
  feature TEXT NOT NULL,
  decision TEXT NOT NULL,
  confidence TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  evidence_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  revoked_reason TEXT,
  UNIQUE(subject_id, subject_kind, profile_id, profile_version, feature)
);

CREATE TABLE suppression_decisions (
  decision_id TEXT PRIMARY KEY,
  policy_id TEXT,
  subject_id TEXT NOT NULL,
  subject_kind TEXT NOT NULL,
  profile_id TEXT NOT NULL,
  feature TEXT NOT NULL,
  eligibility_json TEXT NOT NULL,
  model_protocol TEXT,
  prompt_version INTEGER,
  response_status TEXT NOT NULL,
  decision TEXT NOT NULL,
  created_at TEXT NOT NULL
);
```

`eligibility_json` 保存聚合後的非敏感 evidence；不要保存 API key、完整原始 prompt、完整 metrics 或模型自由文字。

## 8. 介面與可觀測性

新增唯讀 CLI：

```bash
pilot-detection-engine suppressions list --db /var/lib/pilot/detection-engine/state.db
pilot-detection-engine suppressions show <policy-id> --db ...
pilot-detection-engine learning explain --subject it-core --feature disk_io_busy --db ...
```

新增受控 mutation CLI：

```bash
pilot-detection-engine suppressions revoke <policy-id> --db ...
pilot-detection-engine suppressions approve <candidate-id> --ttl 24h --db ...
```

Prometheus metrics 至少包含：

- `pilot_detection_suppression_active{feature,subject_kind}`
- `pilot_detection_suppressed_notifications_total{feature,reason_code}`
- `pilot_detection_suppression_decisions_total{decision,result}`
- `pilot_detection_suppression_expired_total{feature}`

Alertmanager／Teams 顯示時，若事件被抑制，應以 audit 摘要而非正常 firing 告警呈現。

## 9. 分階段實作

### Phase 1 — 先降低誤報風險

1. 為 `disk_io_busy` 補上 I/O PSI、iowait、latency／queue 或 log error 的 feature。
2. 為 disk busy 設定絕對 warning floor，或要求至少一個壓力佐證。
3. 保留目前 `critical: false`。
4. 實作 host-feature episode 統計與 `learning explain` 唯讀 CLI。

### Phase 2 — 決定支援與稽核

1. 新增 migration、aggregator 與 deterministic eligibility gate。
2. 新增嚴格 LLM suppression response schema、timeout、validation 與 fail-closed 行為。
3. 寫入 `suppression_decisions`，但先採 shadow mode：只記錄「會抑制什麼」，不影響 Alertmanager。
4. 以 `it-core/disk_io_busy` 跑至少 7 天，對照 shadow decision、真實 I/O 壓力與人工判定。

### Phase 3 — 有期限的 warning suppression

1. 僅對驗證過的 feature 啟用 policy 寫入與 outbox suppression。
2. 預設 TTL 24 小時、critical bypass、壓力佐證撤銷與 operator revoke。
3. 顯示 suppressed audit trail、metrics 與 Teams 摘要。
4. 建立週期性 re-evaluation，過期後自動回到正常告警。

## 10. 驗收條件

- 同一 host 的週期性 `disk_io_busy` warning 可產生 learning candidate；不同 host 不會共用 policy。
- 沒有足夠歷史或模型結果不合法時，通知維持原狀。
- LLM 無法建立永久 policy、無法抑制 critical、無法抑制具壓力佐證的事件。
- policy 到期、profile 版本變更、I/O PSI/iowait/latency 觸發或 operator revoke 後，下一個事件立即恢復通知。
- 被抑制事件仍可在 SQLite、CLI、dashboard 和 metrics 中追溯。
- Shadow mode 對 `it-core/disk_io_busy` 產生可稽核 evidence，並不改變 Alertmanager 行為。
