# Detection Plane Architecture

> 完整規格：`docs/superpowers/specs/2026-08-28-detection-engine-spec.md`
> 這份文件只整理架構全貌，不重複規格的 normative 細節——公式、狀態機、
> schema 都以該份 spec 為準，這裡衝突時一律以 spec 為準。

## 1. 資料流

```
Managed Hosts
    │ existing exporters / instrumentation
    ▼
Per-site Prometheus  ──(pilot_host label, spec §9)──┐
    │ known-condition rules                          │
    ▼                                                 │
Thanos Sidecar → Thanos Query (:10912, never :10902) ◄┘
    │ Prometheus-compatible query API
    ▼
pilot-detection-engine
    │
    ├── robust-baseline-v1（每主機歷史）
    ├── cohort-outlier-v1（同 cohort peer）
    ├── local candidate gate（>=0.65）
    │
    └── optional Model Provider（Stage B，預設 disabled）
    │
    ▼
SignalEvent（fingerprint 不含 score/severity/category）
    │ SQLite（episode + history + outbox 同一 transaction）
    ▼
Alertmanager outbox（claim/lease/retry/dead）
    │
    ▼
Alertmanager → SRE Agent / Human / Incident Consumer
```

Detection Engine 的正式輸出邊界是 SignalEvent；下游 consumer（人工、
SRE agent、告警路由）不屬於這個 component 的 contract。Detection Engine
**永不**直接連 managed host（不 SSH、不 scrape node_exporter、不讀
`/proc`）——所有 telemetry 都經過 Prometheus → Thanos 這條既有鏈路。

## 2. 為什麼是這個切法

- **Detection 可以 probabilistic；infrastructure mutation 必須維持
  deterministic/gated/audited/verified。** SignalEvent 不是 root cause、
  不直接觸發 infrastructure command——Pilot 仍是唯一的 mutation owner。
- **Provider failure 不是 Detection Plane outage。** Stage A（統計偵測）
  完全不依賴模型；Model Provider 只能 escalate local score，不能
  suppress，且斷線/停用時整條鏈路照常運作（`fused_score = local_score`）。
- **pilot_host 是唯一可信身分，不猜 IP。** Stage A-0 把這個 producer
  規則做在 Prometheus 這一層（inventory hostname → label），Detection
  Engine 自己完全不做身分推斷。

## 3. Stage 邊界

| Stage | 內容 | Model Provider |
|---|---|---|
| A-0 | `pilot_host` producer + Thanos port修正 | 不涉及 |
| A-1 | Engine Core（source/baseline/cohort/lifecycle/store/outbox/scheduler） | disabled |
| A-2 | Pilot Delivery（contract/inventory/catalog/site/deploy/backup/MCP/verification） | disabled |
| B-1/B-2 | Model Provider adapter + fusion + 真實 provider 證據 | enabled（opt-in） |

## 4. 元件邊界

- **Runtime**：`cmd/pilot-detection-engine` 單一靜態二進位（`CGO_ENABLED=0`，
  pure-Go SQLite driver），非 docker container——跟 thanos-query/
  alertmanager 不同，這是本專案第一個「controller 建置後複製二進位到目標
  主機」的角色（見 spec §6.3）。
- **State**：`internal/detection` 套件擁有全部演算法與 SQLite 存取；
  `cmd/pilot-detection-engine` 只是很薄的 CLI/systemd 包裝層。
- **Delivery**：`playbooks/apply/detection-engine-apply.yml`（Stage A-2）
  負責 preflight gate、二進位/設定佈署、systemd 生命週期；不重新實作任何
  演算法邏輯。
- **Dependencies**（`contracts/detection-engine.yaml`）：
  `host-monitoring`（sameHosts，只借用 textfile collector 發布自己的健康
  指標）、`thanos-query`（providerEndpoint，`query`，永遠 `:10912`）、
  `alertmanager`（providerEndpoint，`api`，`:9093`）。

## 5. 已知限制（Stage A）

- MVP 每個 host 同時最多一個 adaptive anomaly episode。
- Signal sink 只有 Alertmanager（webhook/Kafka 是 future work）。
- 不支援 HA/active-active；不做 online learning/fine-tuning；不做
  auto-remediation；沒有 inbound HTTP API。
- 完整清單見 spec §2 Non-Goals、§66 Final Invariants。
