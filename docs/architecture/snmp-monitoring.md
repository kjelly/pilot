# SNMP Monitoring Architecture

> 完整規格：
> `docs/superpowers/specs/2026-09-01-snmp-monitoring-integration-spec.md`
> （目前 Phase 0 — contract/verification skeleton 已落地，尚未有 apply
> mutation 或真實 SNMP telemetry 證據）。這份文件只整理架構全貌，不重複
> 規格的 normative 細節，衝突時一律以該規格為準。

## 1. 資料流

```
Switch / Router / UPS / PDU / BMC
       │ SNMPv3 authPriv, UDP 161
       ▼
site-local snmp_exporter (pilot-snmp-exporter, :9116, loopback default)
       │ /snmp?target=...&module=...&auth=...
       ▼
per-site Prometheus
  file_sd registry + deterministic rules
  labels: pilot_target, pilot_protocol=snmp, pilot_subject_kind, site
       │
       ▼
     Thanos
       │
       ├─────────────────────────────┐
       ▼                             ▼
Prometheus hard rules        pilot-detection-engine
target down / hard fault     baseline / cohort / FLM (SubjectKey-generic)
       │                             │
       └──────────────┬──────────────┘
                       ▼
                  Alertmanager
                       │ webhook
                       ▼
             pilot-agent-controller
                       │ IncidentEnvelopeV2 (mutation_allowed: false)
                       ▼
             external Agent Runtime
                       │ read-only structured tools
                       ▼
       pilot_diagnose_monitoring_target / metrics / detection
```

## 2. 核心不變量

同規格 §4：

- SNMP device 使用 `pilot_target`/generic subject identity；**絕不**填入
  或偽造 `pilot_host`。
- Detection Engine 只透過 Thanos 讀 SNMP metrics；**絕不**直接 poll UDP 161。
- Prometheus deterministic hard alert 與 Detection Engine adaptive signal
  是兩條 peer path，不是誰取代誰。
- Agent recommendation 不構成執行授權；external subject 一律被 repair
  plane 拒絕（spec §10.6）。

## 3. 為什麼是這個切法

- **擴充既有元件，不建立平行系統。** `internal/monitoring`（registry）、
  `internal/detection`（anomaly detection）、`internal/agentcontroller`
  （incident orchestration）都是既有、已在生產路徑上的套件；SNMP 只是
  這三者的一個新 subject kind/profile kind，不是第二套 device
  inventory、第二套 detect engine，或第二套 incident 系統（spec §20）。
- **Telemetry 與 detection 分離。** `snmp_exporter` 只做協定轉譯
  （SNMP → Prometheus exposition），聚合/異常判斷完全在 PromQL + Detection
  Engine 側完成；exporter 本身不做任何統計判斷。
- **Deterministic first, adaptive second。** Prometheus hard rule
  （`SNMPTargetDown`/`SNMPExporterDown`）先於 adaptive baseline/cohort
  上線（spec Phase 3 早於 Phase 5），確保「設備不可達」這種硬條件不需要
  等 adaptive detection 收斂就能告警。
- **Read-only by construction, not by policy alone。** Detection Engine
  與 Agent Runtime 在網路層就沒有到 SNMP 裝置的路徑（spec §6.6 網路邊界
  表：兩者到 SNMP device 皆為 `none`），而不是只靠應用層邏輯避免誤用。

## 4. 元件邊界

- **Runtime**：`snmp_exporter`（quay.io/prometheus/snmp-exporter 官方
  image），per-site 一個容器，預設與該 site 的 Prometheus co-locate、
  只聽 loopback。credential 只存在 exporter host 的 root-owned
  `snmp-exporter.env`（0600），從不進 registry YAML、Prometheus
  config、Alertmanager payload 或 LLM prompt（spec §13.1）。
- **Non-secret catalog**：`monitoring/snmp/catalog.yml` + generated
  module 檔——version-controlled、無 secret，`credentialRef` 只是一個
  key。
- **Registry schema v2**：`internal/monitoring`的 `Profile`/`Target`
  新增 `Kind: snmp` 分支；v1 schema 與現有 direct-Prometheus 行為
  byte-equivalent 保留（spec §7.1）。
- **Detection identity**：新增泛用 `SubjectKey{ID, Kind, Site}`，SNMP
  device 走 `Kind: network_device` 等，不與 managed Linux host 的
  `pilot_host` 混用（spec §9.2）。
- **Incident normalization**：`internal/agentcontroller` 新增
  `IncidentSubject{Managed: bool}`，只有既有 managed-host path 能產生
  `Managed: true`；SNMP/external alert 一律 `Managed: false`，並在
  `internal/repair` 層被 fail-closed 擋下（spec §10.1/§10.6）。

## 5. 目前實作進度

僅 Phase 0（contract/verification skeleton，無 apply mutation）。詳細
6-phase rollout 與各 phase exit gate 見規格 §15。
