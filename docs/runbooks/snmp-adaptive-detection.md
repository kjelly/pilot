# Runbook — SNMP Adaptive Detection (Phase 5)

> 撰寫日期：2026-09-02 (UTC)
> 對齊規範：`docs/superpowers/specs/2026-09-01-snmp-monitoring-integration-spec.md`
> §9.10、§15 Phase 5；`docs/verification/snmp-monitoring-integration.md` C14-C15
> 維護者：sre

---

## 0. 目標與範圍

實作 spec §9.10 的 `network-device-ifmib-v1` Detection Engine feature
profile,證明 Phase 5 exit gate：fixture anomaly 產生 SignalEvent、
normal/stale/missing/ambiguous 四條負向測試 PASS、真實 Thanos chain 真的
discover 到 `pilot_target`、SignalEvent 的 subject labels 正確。

Exit gate：
```
fixture anomaly produces SignalEvent
normal/stale/missing/ambiguous negative lanes PASS
real Thanos chain discovers pilot_target
SignalEvent subject labels correct
```

## 1. 實作內容

- `monitoring/detection/feature-profiles/network-device-ifmib-v1.yaml`：
  新檔,只用通用 IF-MIB device-level aggregate 特徵（interface_error_rate/
  interface_discard_rate 必要、admin_up_oper_down_ratio/
  aggregate_interface_utilization_ratio 選用),`identity.label=pilot_target`/
  `kind=network_device`/`cohortLabel=detection_cohort`,
  `sampling.maxSampleAge=90s`（比 managed-host 預設的 45s 寬,因為 SNMP
  裝置輪詢頻率天生比 node_exporter scrape 低)。這個檔完全靠 Phase 4 新增
  的 `IdentityProfile`/`SamplingProfile` 機制掛進既有引擎,沒有新增任何
  平行的 detection service。
- `internal/detection/engine_snmp_test.go`：新檔,四支測試涵蓋 Phase 5
  exit gate 的四個非即時可驗證項目（另一項「real Thanos chain discovers
  pilot_target」只能靠真機驗證,見 §3):
  - `TestEngine_SNMPProfile_FixtureAnomalyProducesSignalEvent`：載入真的
    profile 檔（不是手key的複本),用假 Thanos httptest server 跑
    120 輪 warm-up + 2 輪 spike,驗證真的建立 episode,且
    `SubjectKind=network_device`、`PilotHost=""`。
  - `TestEngine_SNMPProfile_NegativeLanes`：normal/stale/missing/ambiguous
    四條,且用 profile 自己的 90s/5s sampling（不是全域預設的 45s),證明
    真的吃到 profile override。
  - `TestEngine_SNMPProfile_AlertPayloadCorrelatesWithAgentControllerContract`：
    「agent correlation」——`internal/detection` 不能 import
    `internal/agentcontroller`（沒有既有的依賴關係,加了也沒必要),所以
    把 `agentcontroller.normalizeSubject`（Phase 3 加的)的 precedence 規則
    原樣抄一份在測試裡驗證兩邊的 label 契約沒有 drift：
    `buildAlertPayload` 一定會填 `pilot_subject`/`pilot_subject_kind`,
    對應到 `normalizeSubject` 最優先那個分支,`Managed` 算出來一定是
    false,而且完全不帶 `pilot_host`。
  - `TestNetworkDeviceProfile_DeviceLevelAggregate`：C15 的 cardinality
    policy——靜態檢查 profile 檔每個 feature 的 PromQL,輸出的 `by (...)`
    分組一定含 `pilot_target`、絕不含 `ifIndex`（`ifIndex` 只能出現在
    `on (...)` join clause 裡,那是 join key,不是輸出分組)。

## 2. 真機證據（real Thanos chain discovers pilot_target)

用 disposable VM 建了 3 台真機拓樸,沿用 Phase 2
（`docs/runbooks/snmp-monitoring-registry.md`)與既有
`docs/runbooks/detection-engine.md` 的角色：

- `snmp-dev`：真的 `snmpd`,模擬 SNMPv3 網路裝置。
- `prom-site`：docker + snmp-exporter + Prometheus（含真的 Monitoring
  Target Registry SNMP target)+ Thanos Sidecar。
- `detect-central`：host-monitoring + docker + alertmanager +
  thanos-query + **pilot-detection-engine**（指向真的 Thanos Query,設定
  `featureProfilePath` 為這次新增的 `network-device-ifmib-v1.yaml`)。

真的跑了幾輪 15s cycle 後，`pilot-detection-engine status --json`：

```json
{"state":"healthy","source":{"healthy":true},"subjects":{"active":1},"last_cycle":{"success":true}}
```

直接查 `state.db` 的 `baseline_samples`：

```
core-sw-01|network_device|hq||interface_error_rate|1788318420|0.0
core-sw-01|network_device|hq||interface_discard_rate|1788318420|0.5
```

`subject_id=core-sw-01`、`subject_kind=network_device`、`pilot_host`
確實是空字串——跟 Phase 4 的設計完全吻合,而且這是真的 snmpd → 真的
snmp-exporter → 真的 Prometheus（compile 過的 Monitoring Target
Registry)→ 真的 Thanos Query 這條鏈路產生的,不是 fixture。

## 3. 找到並修的問題

`aggregate_interface_utilization_ratio` 的 PromQL 有真的語法 bug：
`group_left\n(ifHighSpeed{...})`（`group_left` 後面直接接換行再接一個以
`{` 開頭的括號表達式)對 PromQL parser 是歧義的——它會試著把這個括號表達式
解讀成 `group_left` 選用的 include-label 清單,結果碰到 `{` 就炸開。真機
上直接對活的 Thanos Query 下這條 query 得到
`400 bad_data: unexpected "{" in grouping opts`。修法：`group_left`
後面補上明確的空括號 `group_left()` 再接右邊運算元。修完後對真實資料重跑
`replay` 乾淨無誤（"discovered 1 hosts"）。

這是單純的 PromQL 語法問題,跟 label 形狀假設無關——label 形狀本身
（`ifInErrors`/`ifAdminStatus`/...帶 `ifIndex`,加上 Prometheus target-label
來的 `pilot_target`/`site`/`detection_cohort`)第一次就對了,`interface_error_rate`
（必要 feature)直接對真實產生的 label 驗證過。

## 4. 測試證據

```
$ go test ./internal/detection/... ./cmd/pilot-detection-engine/... -v
... 158 個 PASS ...
--- PASS: TestEngine_SNMPProfile_FixtureAnomalyProducesSignalEvent
--- PASS: TestEngine_SNMPProfile_NegativeLanes
    --- PASS: TestEngine_SNMPProfile_NegativeLanes/normal
    --- PASS: TestEngine_SNMPProfile_NegativeLanes/stale
    --- PASS: TestEngine_SNMPProfile_NegativeLanes/missing
    --- PASS: TestEngine_SNMPProfile_NegativeLanes/ambiguous
--- PASS: TestEngine_SNMPProfile_AlertPayloadCorrelatesWithAgentControllerContract
--- PASS: TestNetworkDeviceProfile_DeviceLevelAggregate
ok  	github.com/kjelly/pilot/internal/detection	0.7s
ok  	github.com/kjelly/pilot/cmd/pilot-detection-engine	0.0s
```

`go test ./...`：只剩既有 baseline 的 4 個失敗（與本次改動無關,已在
Phase 3/4 runbook 記錄過)。

## 5. Exit gate 對照

| Exit gate 項目 | 狀態 | 證據 |
|---|---|---|
| fixture anomaly produces SignalEvent | ✅ | `TestEngine_SNMPProfile_FixtureAnomalyProducesSignalEvent` |
| normal/stale/missing/ambiguous negative lanes PASS | ✅ | `TestEngine_SNMPProfile_NegativeLanes`(4 個 subtest) |
| real Thanos chain discovers pilot_target | ✅ | §2 真機 3-VM 拓樸,`status.json`/`state.db` 真實輸出 |
| SignalEvent subject labels correct | ✅ | fixture 測試斷言 `SubjectKind=network_device`/`PilotHost=""`;真機 `state.db` 同樣驗證 |

## 6. 已知留白

- 真機那輪只跑到「真的 discover 到 subject、baseline_samples 有真實資料」
  這一步,**沒有**在真機上真的逼出一個 SignalEvent（沒對 snmpd 灌真的
  error/discard storm)——SignalEvent 產生的證據全部來自 fixture 測試,不
  是真機。這是刻意的時間/風險取捨：真的在 disposable VM 上模擬出穩定的
  SNMP 介面錯誤率需要額外對 snmpd 的 hack 或换成真的可控裝置,而 fixture
  測試已經用「真的 label 形狀」跑過完整的 warm-up→spike→episode 建立
  流程,足以驗證程式邏輯本身正確。
- `TestEngine_SNMPProfile_AlertPayloadCorrelatesWithAgentControllerContract`
  是手動把 `agentcontroller.normalizeSubject` 的邏輯抄一份到
  `internal/detection` 的測試裡驗證,不是真的呼叫該函式（因為套件之間沒有
  依賴關係,加依賴不值得)。這代表兩邊如果未來各自演化,這個手抄邏輯需要
  手動保持同步——沒有編譯期或測試期的自動防線防止 drift,純粹靠人工紀律。
- Model Provider（FLM/NPU)輸入尚未真的接上 SNMP subject——`Candidate`
  目前仍是 `{Host, Site, LocalScore, Current}`（Linux-host 專用形狀),要等
  Phase 6 把它改成 spec §9.11 的 `{Subject SubjectKey, LocalScore,
  Current}` 之後,SNMP subject 才能真的送進 model provider 走 Stage B。
