# Runbook — Agent Controller generic subject + read-only diagnosis (Phase 3)

> 撰寫日期：2026-09-02 (UTC)
> 對齊規範：`docs/superpowers/specs/2026-09-01-snmp-monitoring-integration-spec.md`
> §15 Phase 3；`docs/verification/snmp-monitoring-integration.md` C10-C13
> 維護者：sre

---

## 0. 目標與範圍

證明 Phase 3 exit gate：stop SNMP agent → alert firing（Phase 2 已證）、
Alertmanager → controller incident、subject.id/kind/site 正確、
FakeDispatcher 收到 V2、structured diagnosis 回傳 evidence、repair plan
拒絕 external subject。

## 1. 實作內容

- `internal/agentcontroller`：新增 `IncidentSubject{ID, Kind, Site,
  Managed}`；`normalizeAlert`（normalize.go）依 spec §10.1 固定優先序從
  labels 算出 subject（`pilot_subject` > `pilot_host` > `pilot_target`
  > 無）；`IncidentEvent`/`Incident` 都新增 `Subject` 欄位；SQLite
  schemaV5 migration 對既有 `incidents` 表加 `subject_id`/
  `subject_kind`/`managed` 三欄並回填既有列（既有列一律是
  managed_host，因為這個 store 從來沒有別種 subject）。
- 新增 `IncidentEnvelopeV2`（`Subject` 取代扁平 Host/Site/Component 身分
  欄位，`DiagnosticPolicy` 多一個 `external_subject_mutation_allowed`）；
  `AgentDispatcher`/`FakeDispatcher`/`HTTPDispatcher`/
  `Store.EnqueueRun`/`queue.go` 的 `dispatchOne` 全部改用 V2；
  `IncidentEnvelopeV1`/`NewIncidentEnvelopeV1` 保留供 decode/test 相容
  （spec §10.2 明文允許）。
- Repair 邊界：`cmd/pilot-agent-controller/remediation_cli.go` 新增
  `requireManagedIncidentSubject`，在 `remediation propose`/
  `reapply-propose`（R1/R2 兩條路徑唯一會從 incident_id 建立 plan 的
  地方，下游 approve/execute/auto-execute 都只操作已建立的 plan，不會
  重新從 incident 取 host/subject）一律先查 incident 的 subject，非
  managed_host 直接拒絕，不進 `repair.BuildPlan`。
- `pilot_diagnose_monitoring_target`（`internal/diagnose/
  monitoring_target.go` + `cmd/pilot/cmd/mcp_diagnose_tools.go`）：載入
  workspace 的 Monitoring Target Registry，解析 exact target 名稱、要求
  `kind: snmp`，載入該 profile 的 `diagnosticProfile` query pack
  （`monitoring/snmp/diagnostic-profiles/network-device-ifmib-v1.yaml`
  新增），透過既有 Thanos 診斷路徑（跟 `pilot_diagnose_metrics` 同一支
  ad-hoc 機制）跑固定 PromQL 樣板（`__TARGET__`/`__WINDOW__`/`__TOPN__`
  佔位符取代，絕不字串拼接未 escape 的 target），回傳結構化
  `MonitoringTargetDiagnosis`（scrape health、device facts、bounded
  interface top-N、evidence 陣列）。Window 預設 30m/上限 6h，top_n 預設
  10/上限 20，不接受萬用字元/regex。

## 2. 測試證據

全部透過 Go 單元/整合測試驗證（無需 disposable VM——這個 Phase 是
純邏輯/資料模型變更，不涉及新的 apply playbook）：

```
$ go test ./internal/agentcontroller/... -v
...
--- PASS: TestNormalizeSubject_PilotHostPrecedence
--- PASS: TestNormalizeSubject_PilotTargetNeverManaged
--- PASS: TestNormalizeSubject_GenericPilotSubjectTakesPrecedence
--- PASS: TestNormalizeSubject_NoSubjectLabelsIsEmpty
--- PASS: TestNormalizeSubject_NeverInventedFromInstanceOrGeneratorURL
--- PASS: TestNewIncidentEnvelopeV2_CarriesSubjectAndStaysZeroMutation
--- PASS: TestIngestEvent_PersistsSubjectAndSurvivesDispatchListing
--- PASS: TestSchemaV5_BackfillsManagedHostSubjectForPreExistingRows
--- PASS: TestScheduler_DispatchesIncidentEnvelopeV2WithSubject
ok  	github.com/kjelly/pilot/internal/agentcontroller	45.1s   (全部既有測試也全綠，含 schemaV1-V4 既有 migration)

$ go test ./cmd/pilot-agent-controller/... -v
--- PASS: TestRequireManagedIncidentSubject

$ go test ./internal/diagnose/... ./cmd/pilot/cmd/... -run "MonitoringTarget" -v
--- PASS: TestLoadDiagnosticProfile_Valid
--- PASS: TestMonitoringTargetDiagnosisSteps_SubstitutesTargetWindowTopN
--- PASS: TestMonitoringTargetDiagnosisSteps_EscapesTargetName
--- PASS: TestParsePromInstantVector_SortsDescendingAndSkipsUnparsable
--- PASS: TestDiagnoseMonitoringTargetHandler_RejectsPatternTarget
--- PASS: TestDiagnoseMonitoringTargetHandler_RejectsWindowOverMax
--- PASS: TestDiagnoseMonitoringTargetHandler_UnknownTargetRejected
--- PASS: TestDiagnoseMonitoringTargetHandler_SuccessReturnsStructuredEvidence
```

`go test ./...`：只剩 baseline 既有的 4 個失敗（sandbox 無 `/dev/tty`
的 bubbletea 測試 x3、log-shipping 一個既有 bug，皆與本次改動無關，
`git stash` 對照過）。另外 `TestRepairClient_CapabilitiesAndPlan_RealSubprocess`
在跑滿整套 `go test ./...`（併發系統負載大）時偶爾因 context deadline
exceeded 失敗，單獨跑兩次（`-run TestRepairClient_CapabilitiesAndPlan_RealSubprocess`）
皆 PASS——研判是併發負載下真的 subprocess 啟動+MCP handshake 逼近既有
timeout 的既有 flake，非本次改動造成（本次沒有動到
`repairclient.go`/其 subprocess 啟動機制，只動了
`remediation_cli.go` 的 propose 指令與 model/normalize/store/incident/
queue/dispatcher 的 Subject/V2 資料層）。

## 3. Exit gate 對照

| Exit gate 項目 | 狀態 | 證據 |
|---|---|---|
| stop SNMP agent → alert firing | ✅ | Phase 2 runbook 已用真實 Prometheus 證明 `SNMPTargetDown` 會 fire |
| Alertmanager → controller incident | ⚠️ 部分 | Phase 1 runbook 已證明真實 Alertmanager webhook → incident 全鏈；本次只用單元測試證明「若收到 SNMP 形狀的 alert，subject 算得對」，**沒有**重跑一次真實 Prometheus fire SNMPTargetDown → 真實 Alertmanager → 真實 controller 的端到端鏈路（見 §5 已知留白） |
| subject.id/core kind/site correct | ✅ | `TestNormalizeSubject_*`、`TestIngestEvent_PersistsSubjectAndSurvivesDispatchListing` |
| FakeDispatcher receives V2 | ✅ | `TestScheduler_DispatchesIncidentEnvelopeV2WithSubject` |
| structured diagnosis returns evidence | ✅ | `TestDiagnoseMonitoringTargetHandler_SuccessReturnsStructuredEvidence` |
| repair plan rejects target | ✅ | `TestRequireManagedIncidentSubject` |

## 4. 找到並修的問題

- `IncidentSubject.Site` 沒有獨立的 persisted 欄位——刻意設計成跟既有
  `incidents.site` 欄位共用同一個來源（`normalizeSubject` 跟
  `normalizeAlert` 本來就從同一個 `labels["site"]` 取值），
  `GetIncident`/`ListIncidentsNeedingDispatch` 讀出來後才組回
  `Subject.Site`，避免多一個永遠要保持同步的欄位。寫測試時一度手動只設
  `ev.Subject.Site` 沒同步設 `ev.Site`，才發現這個設計含義需要寫清楚
  （已在程式碼註解記錄）。

## 5. 已知留白

- 沒有重跑一次「真實 Prometheus fire SNMPTargetDown → 真實 Alertmanager
  → 真實 pilot-agent-controller 建立 incident」的端到端 disposable VM
  證據——Phase 1 與 Phase 2 各自的 runbook 已經分別證明這兩段鏈路是通的
  （不同 alert 形狀），但沒有把兩者接起來重跑一次。之後有真實
  SNMPv3 裝置/Prometheus/Alertmanager/controller 四件一起測試時應該補上。
- Detection Engine 尚未產生任何帶 `pilot_subject`/`pilot_subject_kind`
  的 SignalEvent（Phase 4/5 才做），所以
  `pilot_diagnose_monitoring_target` 目前完全沒有 `active_signals`
  填值邏輯——欄位存在（`ActiveSignals []SignalSummary`），但沒有任何
  程式碼會填它，等 Phase 5 SNMP adaptive detection 落地後要補上。
- MCP `pilot://monitoring/*` resources 與 `pilot edit` TUI 尚未針對
  `pilot_diagnose_monitoring_target`/SNMP subject 做任何專屬呈現——這屬於
  spec §11 CLI/TUI/MCP resources 範圍，Phase 2 已經做了 CLI 的
  profile/target add 部分，TUI 互動選單與 MCP resources 呈現仍待補。
