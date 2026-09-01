# Pilot SNMP Exporter × Detection Engine × SRE Agent 整合實作規格

**文件狀態：** `IMPLEMENTATION_READY`
**規格版本：** v1.0
**日期：** 2026-09-01
**目標 Repository：** `kjelly/pilot`
**事實快照基準：** `main@c39739018a39961d421deb439db8cc8921619a5f`
**主要語言：** Go、Ansible、Prometheus configuration
**目標讀者：** Coding Agent、Pilot Maintainer、SRE

> `IMPLEMENTATION_READY` 只表示規格已收斂到可以開始實作，不表示任何程式碼、VM 驗證、真實 SNMPv3 設備證據或 production gate 已完成。

---

## 0. 規範用語與變更規則

本文件中的 **MUST、MUST NOT、SHOULD、SHOULD NOT、MAY** 為規範性要求。

實作者開始前 MUST 重新讀取 current worktree，至少確認下列路徑沒有與本規格假設產生衝突：

```text
internal/monitoring/
internal/detection/
internal/agentcontroller/
internal/diagnose/
internal/policy/
internal/repair/
cmd/pilot/cmd/monitoring*.go
cmd/pilot/cmd/mcp_diagnose_tools.go
cmd/pilot-agent-controller/
playbooks/apply/prometheus-apply.yml
playbooks/apply/detection-engine-apply.yml
playbooks/apply/agent-controller-apply.yml
contracts/
monitoring/
docs/architecture/agent-monitoring.md
docs/architecture/detection-plane.md
docs/network-firewall-matrix.md
```

若 current worktree 已改變本文件定義的核心邊界，實作者 MUST：

```text
STOP
→ 更新本規格
→ review
→ 再實作
```

不得在程式碼中默默採用另一套「也合理」的架構。

---

## 1. 目的

本規格定義 Pilot 導入 Prometheus `snmp_exporter`，並將 SNMP telemetry 整合進既有：

```text
Monitoring Target Registry
→ Prometheus
→ Thanos
→ Detection Engine
→ Alertmanager
→ Agent Controller
→ SRE Agent / Agent Runtime
```

完整目標如下：

1. 由 Pilot 部署並管理每個 site 的 `snmp_exporter`。
2. 使用既有 Monitoring Target Registry 描述 switch、router、UPS、PDU、BMC 等「受監控但不受 Pilot 主機生命週期管理」的設備。
3. 由 per-site Prometheus 經 `snmp_exporter` scrape SNMP 設備。
4. 先以 deterministic Prometheus rules 處理已知硬條件。
5. 將經 PromQL 聚合後的 device-level features 交給 Detection Engine 做 statistical/adaptive anomaly detection。
6. 沿用現有 NPU/FLM ModelProvider，只對 candidate 做 semantic classification；不得把 raw SNMP walk 或完整 interface time-series 丟給 LLM。
7. 讓 Agent Controller 將 SNMP alert 正規化為 generic monitored subject incident。
8. 提供 SRE Agent 一個 bounded、read-only、structured SNMP/monitoring-target diagnosis tool。
9. 明確禁止本階段透過 Agent 對外部網路設備執行 `snmpset`、SSH CLI 或任何 configuration mutation。

核心不變量：

```text
SNMP device != Pilot managed host
Telemetry collection != anomaly detection
Anomaly detection != diagnosis
Agent recommendation != authorization
External monitored subject != repair target
```

---

## 2. Current Pilot 事實快照

本規格建立時已確認 current repository 具備以下基礎：

| 能力 | Current shape | 本規格處理方式 |
|---|---|---|
| External monitoring registry | `internal/monitoring` 已有 target/profile schema、validate、compile、CLI、TUI、structured actions | 擴充 schema，不建立第二套 SNMP device registry |
| Prometheus external target | `prometheus-apply.yml` 可由 registry 產生 file_sd 與 scrape jobs | 新增 `kind: snmp` compiler path |
| Detection Engine | `internal/detection` 已有 baseline、cohort、SignalEvent、SQLite、Alertmanager outbox、FLM/Ollama/OpenAI provider | 泛化 subject identity；不建立平行 detect engine |
| Detection identity | 目前以 `pilot_host` 為主要 subject identity | 新增 `SubjectKey`；SNMP 不得偽裝成 `pilot_host` |
| Feature profile | 目前一次載入一個 feature profile，PromQL 多以 `pilot_host,site` 聚合 | 支援 identity metadata 與多 profile binding |
| Agent Controller | 可接收 Alertmanager webhook，支援 Prometheus rule 與 Detection Engine source | 擴充 generic subject normalization 與 Envelope V2 |
| Agent Runtime adapter | 已有 `FakeDispatcher`、generic `HTTPDispatcher` | 不在本規格綁定特定 vendor runtime；沿用 adapter boundary |
| Repair/autonomy | 現有 R1/R2 僅針對 Pilot managed host/component | external SNMP subject MUST 被 repair plane 拒絕 |

本規格不得破壞以下既有行為：

```text
monitoring schema v1 workspace
existing direct Prometheus external targets
linux-host-v1 detection behavior
pilot_host identity for managed hosts
existing Alertmanager incident dedup
existing R1/R2 repair policy
provider disabled / unavailable 時的 local-only detection
```

---

## 3. Scope

### 3.1 In Scope

本規格包含：

```text
snmp-exporter Pilot role / contract / deploy catalog
site-local deployment topology
SNMP non-secret catalog + secret resolution
Monitoring Registry schema v2
SNMP scrape profile compilation
Prometheus file_sd / relabel / deterministic alerts
SNMP target connectivity test
Detection Engine SubjectKey generalization
per-profile identity and sample-age policy
multi-profile detection configuration
SNMP device-level feature profile
SignalEvent generic subject labels
Agent Controller generic subject model
IncidentEnvelopeV2
pilot_diagnose_monitoring_target
SRE Agent read-only evidence flow
migration / rollback / verification / production gates
```

### 3.2 Explicit Non-Goals

v1.0 MUST NOT 實作：

```text
SNMP traps / trap receiver
SNMP write / snmpset
SSH/Telnet/API network-device configuration
switch/router automated remediation
vendor-specific configuration backup/restore
network change plan / rollback engine
LLM tool-calling directly against SNMP devices
Detection Engine 直接連 UDP 161
Agent Runtime 直接取得 SNMP credentials
將每個 interface 當成 Detection Engine episode subject
將完整 raw OID tree 或 raw time-series 送進模型
用 LLM 取代 Prometheus hard-condition rules
重新建立另一套 metrics storage
重新建立另一套 device inventory
Kubernetes/Consul/SRV discovery
active-active SNMP exporter HA
automatic MIB generator execution on production hosts
```

---

## 4. Architecture Invariants

| ID | Invariant |
|---|---|
| I1 | Pilot inventory 描述 Pilot 管理的主機；Monitoring Target Registry 描述 Prometheus 監控的 endpoint。兩者 MUST NOT 自動互相轉換。 |
| I2 | SNMP device MUST 使用 `pilot_target` / generic subject identity；MUST NOT 填入或偽造 `pilot_host`。 |
| I3 | Detection Engine MUST 只透過 Thanos/Prometheus-compatible API 取得 SNMP metrics；MUST NOT 直接 poll SNMP。 |
| I4 | SNMP username、auth password、privacy password、community MUST NOT 出現在 `monitoring/targets.yml`、`monitoring/scrape-profiles.yml`、Prometheus config、Alertmanager payload、Detection SQLite、Agent evidence 或 LLM prompt。 |
| I5 | production 預設 MUST 使用 SNMPv3 `authPriv`；v1/v2c 僅允許在 sandbox/staging 明確 opt-in。 |
| I6 | Prometheus deterministic hard alert 與 Detection Engine adaptive signal 為兩條 peer path；不得要求 LLM 判斷 target 是否可達、PSU 是否故障等硬條件。 |
| I7 | Detection Engine model output 只能 escalate/categorize candidate，MUST NOT suppress deterministic hard trigger。 |
| I8 | Agent Controller 是 incident orchestrator，不是第二個 anomaly detector。 |
| I9 | Agent recommendation 不構成執行授權。external subject MUST NOT 通過現有 repair/autonomy execution path。 |
| I10 | Subject identity MUST 來自受控 label；MUST NOT 從 `instance`、reverse DNS、SNMP `sysName` 或自然語言猜測。 |
| I11 | 一個 `(subject, site, feature)` 每 cycle 只允許一條聚合後 series；多條 series MUST 判為 `ambiguous_series`，不得任意挑一條。 |
| I12 | LLM failure、SNMP timeout、missing feature、malformed reply 都 MUST NOT 被表示成 `normal`。 |

---

## 5. Target Architecture

```text
 Switch / Router / UPS / PDU / BMC
        │
        │ SNMPv3 authPriv, UDP 161
        ▼
┌──────────────────────────┐
│ site-local snmp_exporter │
│ default: same host as    │
│ per-site Prometheus      │
│ HTTP :9116               │
└────────────┬─────────────┘
             │ /snmp?target=...&module=...&auth=...
             ▼
┌──────────────────────────┐
│ per-site Prometheus      │
│                          │
│ file_sd registry         │
│ deterministic rules      │
│ labels:                  │
│   pilot_target           │
│   pilot_protocol=snmp    │
│   pilot_subject_kind     │
│   site                   │
└────────────┬─────────────┘
             │
             ▼
           Thanos
             │
             ├─────────────────────────────┐
             │                             │
             ▼                             ▼
  Prometheus hard rules          pilot-detection-engine
  target down / hard fault       baseline / cohort / FLM
             │                             │
             └──────────────┬──────────────┘
                            ▼
                       Alertmanager
                            │ webhook
                            ▼
                  pilot-agent-controller
                            │
                            ▼
                  external Agent Runtime
                            │
                 read-only structured tools
                            ▼
       pilot_diagnose_monitoring_target / metrics / detection
```

### 5.1 Deployment Topology Decision

v1 production baseline：

```text
每個 Prometheus site 一個 snmp_exporter
SHOULD 與該 site 的 Prometheus co-locate
Prometheus 以 127.0.0.1:9116 存取 exporter
```

若因管理網段路由必須分離 exporter host：

1. Prometheus host MUST 顯式設定 `snmp_exporter_endpoint`。
2. 不得用 registry target/profile 保存 exporter address。
3. exporter HTTP endpoint MUST 使用 network ACL，並 SHOULD 使用 exporter-toolkit TLS/basic-auth。
4. 不做依 site 自動猜測 exporter host；沒有 explicit endpoint 就 fail closed。

---

## 6. SNMP Exporter Component

### 6.1 New Pilot Role

新增 role/component：

```text
snmp-exporter
```

預期檔案：

```text
contracts/snmp-exporter.yaml
playbooks/apply/snmp-exporter-apply.yml
docs/verification/snmp-exporter.md
docs/runbooks/snmp-exporter.md
```

部署 catalog、inventory role catalog、`playbooks/site.yml` 與 role preset MUST 同步註冊。

### 6.2 Runtime

初始預設：

```yaml
snmp_exporter_version: v0.30.1
snmp_exporter_image: quay.io/prometheus/snmp-exporter
snmp_exporter_container_name: pilot-snmp-exporter
snmp_exporter_port: 9116
snmp_exporter_listen_address: 127.0.0.1
snmp_exporter_module_concurrency: 1
snmp_exporter_config_dir: /etc/pilot/snmp-exporter
snmp_exporter_data_dir: /var/lib/pilot/snmp-exporter
```

版本 MUST 可由 inventory override。Production release SHOULD pin image digest；只 pin floating tag 不足以達成 production supply-chain gate。

container MUST：

```text
read-only config mounts
no-new-privileges
cap-drop ALL
no host network by default
no Docker socket
no SSH key
no Pilot vault file mount
restart unless-stopped or equivalent reviewed lifecycle
```

config 變更時 SHOULD restart container；不得假設未驗證的 hot reload 行為。

### 6.3 Filesystem

```text
/etc/pilot/snmp-exporter/
├── catalog.yml
├── modules/
│   └── *.yml
├── auths.yml
├── web-config.yml          # only when non-loopback endpoint protection is enabled
└── snmp-exporter.env       # root:root 0600
```

權限：

| Path | Mode | Requirement |
|---|---:|---|
| config directory | `0750` | root-owned |
| module files | `0644` or stricter | MUST contain no secret |
| `auths.yml` | `0640` or stricter | MAY contain env references; MUST NOT contain resolved password when env expansion is used |
| env file | `0600` | MUST contain resolved credentials only here |
| web config | `0640` or stricter | password hash / TLS private path protected |

### 6.4 Non-secret SNMP Catalog

新增：

```text
monitoring/snmp/catalog.yml
monitoring/snmp/generated/*.yml
```

`catalog.yml` 為可提交版控的非 secret registry：

```yaml
schemaVersion: 1

modules:
  if_mib:
    file: generated/if_mib.yml

  vendor_core_switch:
    file: generated/vendor-core-switch.yml

authProfiles:
  core-switch-v3:
    version: 3
    securityLevel: authPriv
    authProtocol: SHA256
    privProtocol: AES
    credentialRef: core-switch-v3

  lab-v2c:
    version: 2
    securityLevel: noAuthNoPriv
    credentialRef: lab-v2c
```

規則：

1. module/auth profile name MUST 符合 `^[a-z0-9][a-z0-9_-]{0,63}$`。
2. module file MUST 是 `monitoring/snmp/` 下的相對 regular file；拒絕 absolute path、`..` 與 symlink escape。
3. catalog MUST NOT 包含 username、password、privacy password、community。
4. `credentialRef` 只是一個 key，不是 credential value。
5. playbook MUST 交叉檢查 module file 真的宣告 catalog 中的 module ID。
6. production stage MUST 拒絕 `version < 3` 或 `securityLevel != authPriv`，除非使用明確、審核過的 break-glass 變數；break-glass 不得成為預設。

Secret input 由 vault 提供：

```yaml
snmp_exporter_credentials:
  core-switch-v3:
    username: "..."
    authPassword: "..."
    privPassword: "..."

  lab-v2c:
    community: "..."
```

playbook MUST 使用 `no_log: true` 處理 credential render。

### 6.5 Generated Module Policy

1. MIB generator MUST 在 development/build environment 執行，不得在 production host 自動下載 MIB 或執行 generator。
2. generated module files MUST 進版控或 artifact provenance 流程。
3. proprietary MIB 若授權不允許提交，MUST 由外部 artifact path + checksum 提供。
4. module 更新 MUST 觸發 golden diff review；不得把巨大 generated diff 混入無關功能變更。

### 6.6 Network Boundary

| Source | Destination | Protocol/Port | Purpose |
|---|---|---|---|
| Prometheus | local/separate SNMP Exporter | TCP `9116` | `/snmp` and `/metrics` |
| SNMP Exporter | devices | UDP `161` by default | read-only SNMP polling |
| SNMP Exporter | devices | TCP/custom port only when explicitly configured | exceptional transport |
| Detection Engine | SNMP device | **none** | prohibited |
| Agent Controller / Agent Runtime | SNMP device | **none** | prohibited |

若 exporter HTTP endpoint 非 loopback，MUST 更新 `docs/network-firewall-matrix.md`，並限制只有該 site Prometheus 可存取。

---

## 7. Monitoring Target Registry Schema v2

### 7.1 Compatibility

現有 schema v1 MUST 保持可讀、可驗證、可編譯，且 direct Prometheus target output MUST byte-equivalent。

loader 行為：

```text
schemaVersion: 1
→ profile.kind 視為 prometheus
→ 不要求任何 SNMP field
```

writer 行為：

```text
只有 v1 fields → MAY 保持 v1
使用任何 v2-only field → MUST 寫成 schemaVersion: 2
```

CLI SHOULD 提供明確 migration：

```text
pilot monitoring migrate --to 2
```

migration MUST 是 deterministic、idempotent，且不得改變既有 direct scrape semantics。

### 7.2 Profile Model

擴充 `internal/monitoring.Profile`：

```go
type Profile struct {
    JobName           string       `yaml:"jobName"`
    Kind              string       `yaml:"kind,omitempty"` // prometheus | snmp
    SubjectKind       string       `yaml:"subjectKind,omitempty"`
    DiagnosticProfile string       `yaml:"diagnosticProfile,omitempty"`

    Scheme            string       `yaml:"scheme,omitempty"`
    MetricsPath       string       `yaml:"metricsPath,omitempty"`
    ScrapeInterval    string       `yaml:"scrapeInterval,omitempty"`
    ScrapeTimeout     string       `yaml:"scrapeTimeout,omitempty"`
    AuthRef           string       `yaml:"authRef,omitempty"`
    TLS               *TLSConfig   `yaml:"tls,omitempty"`

    SNMP              *SNMPProfile `yaml:"snmp,omitempty"`
}

type SNMPProfile struct {
    Modules     []string `yaml:"modules"`
    AuthProfile string   `yaml:"authProfile"`
}
```

`Kind` effective default：

```text
empty → prometheus
```

### 7.3 Target Model

擴充 `internal/monitoring.Target`：

```go
type Target struct {
    Name              string            `yaml:"name"`
    Address           string            `yaml:"address"`
    Profile           string            `yaml:"profile"`
    Site              string            `yaml:"site,omitempty"`
    DetectionCohort   string            `yaml:"detectionCohort,omitempty"`
    Enabled           *bool             `yaml:"enabled,omitempty"`
    Labels            map[string]string `yaml:"labels,omitempty"`
}
```

v1 不加入 target-level SNMP context/engineID。需要 context 的設備留待後續 schema extension，不得先用自由格式 query string 繞過 schema。

### 7.4 SNMP Profile Validation

`kind: snmp` MUST 符合：

1. `snmp` block 必填。
2. `snmp.modules` 至少一個，順序保留但不得重複。
3. `snmp.authProfile` 必填。
4. module/auth ID 必須存在於 `monitoring/snmp/catalog.yml`。
5. `subjectKind` 必填，格式 `^[a-z0-9][a-z0-9_-]{0,63}$`。
6. `scheme`、`metricsPath`、HTTP `authRef`、`tls` MUST 為空；SNMP profile 不得混用 direct HTTP scrape field。
7. 每個引用該 profile 的 enabled target MUST 有 `site`。
8. target address MUST 是 host/IP 或 upstream 支援的 `[transport://]host[:port]`，不得含 HTTP path/query/fragment。
9. `scrapeTimeout` MUST 小於 `scrapeInterval`。
10. target/profile YAML 使用 strict known-fields decoding；`community`、`username`、`password`、`privPassword` 等未知 secret key MUST 直接 reject。

`kind: prometheus` MUST 拒絕非空 `snmp` block。

### 7.5 Reserved Labels

擴充 reserved label：

```text
pilot_target
pilot_source
pilot_protocol
pilot_subject_kind
detection_cohort
__address__
__param_target
```

所有 `__*` user label MUST reject。

compiler 自動設定：

```text
pilot_target=<target.name>
pilot_source=external
pilot_protocol=snmp
pilot_subject_kind=<profile.subjectKind>
site=<target.site>
detection_cohort=<target.detectionCohort>   # only when non-empty
```

user labels 不得覆寫上述值。

### 7.6 Example Registry

`monitoring/scrape-profiles.yml`：

```yaml
schemaVersion: 2

profiles:
  core-switch:
    kind: snmp
    jobName: snmp-core-switch
    subjectKind: network_device
    diagnosticProfile: network-device-ifmib-v1
    scrapeInterval: 30s
    scrapeTimeout: 20s
    snmp:
      modules:
        - if_mib
        - vendor_core_switch
      authProfile: core-switch-v3

  external-linux:
    kind: prometheus
    jobName: external-linux
    scheme: https
    metricsPath: /metrics
```

`monitoring/targets.yml`：

```yaml
schemaVersion: 2

targets:
  - name: core-sw-01
    address: 10.20.0.11
    profile: core-switch
    site: hq
    detectionCohort: arista-core-7050
    labels:
      vendor: arista
      model: "7050"
      device_role: core_switch

  - name: core-sw-02
    address: udp://10.20.0.12:161
    profile: core-switch
    site: hq
    detectionCohort: arista-core-7050
    labels:
      vendor: arista
      model: "7050"
      device_role: core_switch
```

---

## 8. Prometheus Integration

### 8.1 Compile Semantics

現有 direct Prometheus profile compile path MUST 保持不變。

SNMP profile compile path：

1. 只編譯 `enabled != false` 的 target。
2. 只編譯 `target.site == prometheus_site_label` 的 SNMP target。
3. empty site 對 SNMP 為 validation error，不存在 global SNMP target fallback。
4. 每個 target 生成一個 file_sd entry，不合併 labels。
5. 每個 profile 生成一個 job，`jobName` 全域唯一。
6. exporter endpoint 來自 Prometheus host deployment variable，不來自 target/profile registry。

預期 file_sd：

```json
[
  {
    "targets": ["10.20.0.11"],
    "labels": {
      "pilot_target": "core-sw-01",
      "pilot_source": "external",
      "pilot_protocol": "snmp",
      "pilot_subject_kind": "network_device",
      "site": "hq",
      "detection_cohort": "arista-core-7050",
      "vendor": "arista",
      "model": "7050",
      "device_role": "core_switch"
    }
  }
]
```

### 8.2 Generated Scrape Job

```yaml
- job_name: snmp-core-switch
  scrape_interval: 30s
  scrape_timeout: 20s
  metrics_path: /snmp

  params:
    module:
      - if_mib
      - vendor_core_switch
    auth:
      - core-switch-v3

  file_sd_configs:
    - files:
        - /etc/prometheus/targets/snmp-core-switch.json

  relabel_configs:
    - source_labels: [__address__]
      target_label: __param_target

    - source_labels: [__param_target]
      target_label: instance

    - target_label: __address__
      replacement: 127.0.0.1:9116
```

若 `snmp_exporter_endpoint` 被 explicit override，最後一個 replacement 使用該值。

Prometheus config MUST NOT 包含 SNMP password/community；只包含 module/auth **名稱**。

### 8.3 SNMP Exporter Self-scrape

Prometheus MUST 另外 scrape exporter 自己的 `/metrics`：

```yaml
- job_name: snmp-exporter
  static_configs:
    - targets: ["127.0.0.1:9116"]
      labels:
        site: hq
        component: snmp-exporter
```

self-scrape 與 device scrape MUST 是不同 job，避免 `up` 語意混淆。

### 8.4 Deterministic Rules

v1 seed MUST 至少新增：

```yaml
- alert: SNMPTargetDown
  expr: up{pilot_protocol="snmp"} == 0
  for: 5m
  labels:
    severity: critical
    source: prometheus-rule
    component: snmp
  annotations:
    summary: "SNMP target is not scrapeable"

- alert: SNMPExporterDown
  expr: up{job="snmp-exporter"} == 0
  for: 2m
  labels:
    severity: critical
    source: prometheus-rule
    component: snmp-exporter
  annotations:
    summary: "SNMP exporter is not scrapeable"
```

v1 default MUST NOT 自動啟用以下高誤報規則：

```text
任一 ifOperStatus != up
任一 admin-up/oper-down
任一 interface error > 0
任一 BGP peer down
任一 temperature 超過 vendor-independent 固定值
```

上述規則需由 module/vendor-specific rule pack opt-in，並有真實設備證據。

### 8.5 Cardinality Policy

1. Prometheus MAY 保存 per-interface metrics。
2. Detection Engine MUST 使用 device-level aggregate PromQL，不得讓每個 `ifIndex` 直接成為 detection subject。
3. user-provided unbounded text label SHOULD 在 scrape/relabel 階段 drop；例如非常長的 description、location 或 vendor-specific free text。
4. `ifAlias`/`ifDescr` 是否保留由 module review 決定；不得在未評估 cardinality 前全部保留。

---

## 9. Detection Engine Generalization

### 9.1 No Parallel Engine

MUST 擴充既有：

```text
internal/detection
```

不得新增平行：

```text
internal/snmpdetect
internal/networkdetect
second detection service
```

### 9.2 SubjectKey

新增 generic subject：

```go
type SubjectKey struct {
    ID   string
    Kind string
    Site string
}
```

managed Linux host：

```text
ID   = inventory hostname
Kind = managed_host
Site = existing site label
```

SNMP device：

```text
ID   = monitoring target name
Kind = network_device / ups / pdu / ...
Site = target site
```

禁止：

```text
core-sw-01 → pilot_host=core-sw-01
```

### 9.3 Feature Profile Identity Metadata

擴充 `FeatureProfile`：

```go
type FeatureProfile struct {
    ID       string          `yaml:"id"`
    Version  int             `yaml:"version"`
    Identity IdentityProfile `yaml:"identity,omitempty"`
    Sampling SamplingProfile `yaml:"sampling,omitempty"`
    Features []Feature       `yaml:"features"`
}

type IdentityProfile struct {
    Label       string `yaml:"label"`
    Kind        string `yaml:"kind"`
    SiteLabel   string `yaml:"siteLabel"`
    CohortLabel string `yaml:"cohortLabel,omitempty"`
}

type SamplingProfile struct {
    MaxSampleAge       string `yaml:"maxSampleAge,omitempty"`
    FutureSkewTolerance string `yaml:"futureSkewTolerance,omitempty"`
}
```

Backward-compatible defaults：

```yaml
identity:
  label: pilot_host
  kind: managed_host
  siteLabel: site
sampling:
  maxSampleAge: 45s
  futureSkewTolerance: 5s
```

SNMP profile：

```yaml
identity:
  label: pilot_target
  kind: network_device
  siteLabel: site
  cohortLabel: detection_cohort
sampling:
  maxSampleAge: 90s
  futureSkewTolerance: 5s
```

### 9.4 Sample Classification

`GroupSamplesByKey` MUST 接受 profile identity metadata，不再 hard-code `pilot_host`。

規則：

1. identity label missing → invalid reason `missing_identity`。
2. site label missing MAY 使用 empty site only for legacy managed-host compatibility；SNMP profile MUST 視為 invalid。
3. same `(subject ID, kind, site, feature)` 有多條 result → `ambiguous_series`。
4. profile-specific `maxSampleAge` 取代 global hard-coded 45 seconds。
5. invalid/missing feature 不得 zero-fill。
6. required feature invalid → whole subject cycle invalid，lifecycle 不前進。
7. invalid cycle 不得被記為 normal/recovered。

### 9.5 Multiple Feature Profiles

現有 single `FeatureProfilePath` config MUST 向下相容，並新增：

```yaml
featureProfiles:
  - path: /etc/pilot/detection/linux-host-v1.yaml
    enabled: true

  - path: /etc/pilot/detection/network-device-ifmib-v1.yaml
    enabled: true
```

兼容規則：

```text
只有 featureProfilePath → 舊 single-profile mode
featureProfiles 非空 → multi-profile mode
兩者同時設定 → config validation error
```

每個 profile 以自己的 identity label 發現 subject。不同 profile MUST 維持獨立 baseline、fingerprint、lifecycle 與 episode。

### 9.6 Cohort

1. `identity.cohortLabel` 為空時，cohort detector 對該 profile disabled；baseline detector 仍正常運作。
2. SNMP target 的 cohort 只來自 compiler-controlled `detection_cohort` label。
3. cohort peer MUST 同 profile、同 subject kind、同 cohort ID；不得把 switch 與 UPS 放在同一 cohort。
4. cohort label missing 不得自動用 vendor/model 猜測。

### 9.7 Persistence Migration

所有以 `pilot_host` 作為 persisted identity 的 table MUST migration 到 generic subject key。

已知至少包含：

```text
baseline_samples
signal_episodes
```

coding agent MUST 重新檢查 current schema，找出其他含 host identity 的 table/index/query。

migration MUST：

1. 在單一 SQLite transaction 內建立 next table、copy、verify row count、swap table。
2. 新增：

```text
subject_id TEXT NOT NULL
subject_kind TEXT NOT NULL
site TEXT NOT NULL DEFAULT ''
pilot_host TEXT NULL        # compatibility mirror only
```

3. legacy row backfill：

```text
subject_id = pilot_host
subject_kind = managed_host
pilot_host = original pilot_host
```

4. non-managed subject：

```text
pilot_host = NULL
```

5. uniqueness/primary key MUST 使用 `(subject_id, subject_kind, site, ...)`，不得繼續只用 `pilot_host`。
6. migration 前 MUST 產生 SQLite backup。
7. migration row-count 或 integrity check failure MUST rollback，service 不得帶半套 schema 啟動。
8. 舊 binary rollback 需要 restore pre-migration backup；不得宣稱 new schema 可由舊 binary 直接讀取。

### 9.8 Signal Fingerprint and Alert Payload

fingerprint MUST 包含：

```text
subject_id
subject_kind
site
profile_id
profile_version
```

Detection Engine Alertmanager labels：

```text
alertname=PilotAdaptiveAnomaly
source=detection-engine
pilot_subject=<subject_id>
pilot_subject_kind=<subject_kind>
site=<site>
severity=<severity>
```

managed host 額外保留：

```text
pilot_host=<subject_id>
```

SNMP/external target SHOULD 額外保留：

```text
pilot_target=<subject_id>
```

annotations 保持：

```text
signal_id
score
confidence
category_hint
top_contributors
profile
```

`signal_id` 仍是 Agent Controller 對 Detection Engine warning→critical transition 的 stable episode identity。

### 9.9 Observability Compatibility

新增 generic metric，例如：

```text
pilot_detection_subject_anomaly_score{
  pilot_subject="...",
  pilot_subject_kind="...",
  detector="..."
}
```

原本以 `pilot_host` 為 label 的 metric SHOULD 在 managed-host subject 上暫時保留一個 compatibility release；SNMP subject 不得塞入舊 host metric。

### 9.10 Base SNMP Detection Profile

新增：

```text
monitoring/detection/feature-profiles/network-device-ifmib-v1.yaml
```

初始 profile MUST 只使用通用 IF-MIB、device-level aggregate features：

```yaml
id: network-device-ifmib-v1
version: 1

identity:
  label: pilot_target
  kind: network_device
  siteLabel: site
  cohortLabel: detection_cohort

sampling:
  maxSampleAge: 90s
  futureSkewTolerance: 5s

features:
  - name: interface_error_rate
    required: true
    category: network_error
    scaleFloor: 0.01
    cohort: true
    validMin: 0
    validMax: 1000000
    promql: |
      sum by (pilot_target, site, detection_cohort) (
        rate(ifInErrors{pilot_protocol="snmp",pilot_target!=""}[5m])
        +
        rate(ifOutErrors{pilot_protocol="snmp",pilot_target!=""}[5m])
      )

  - name: interface_discard_rate
    required: true
    category: network_discard
    scaleFloor: 0.01
    cohort: true
    validMin: 0
    validMax: 1000000
    promql: |
      sum by (pilot_target, site, detection_cohort) (
        rate(ifInDiscards{pilot_protocol="snmp",pilot_target!=""}[5m])
        +
        rate(ifOutDiscards{pilot_protocol="snmp",pilot_target!=""}[5m])
      )

  - name: admin_up_oper_down_ratio
    required: false
    category: link_state
    scaleFloor: 0.01
    cohort: true
    validMin: 0
    validMax: 1
    promql: |
      sum by (pilot_target, site, detection_cohort) (
        (ifAdminStatus{pilot_protocol="snmp",pilot_target!=""} == 1)
        and on (pilot_target, site, detection_cohort, ifIndex)
        (ifOperStatus{pilot_protocol="snmp",pilot_target!=""} != 1)
      )
      /
      clamp_min(
        sum by (pilot_target, site, detection_cohort) (
          ifAdminStatus{pilot_protocol="snmp",pilot_target!=""} == 1
        ),
        1
      )

  - name: aggregate_interface_utilization_ratio
    required: false
    category: network_utilization
    scaleFloor: 0.05
    cohort: true
    validMin: 0
    validMax: 2
    promql: |
      max by (pilot_target, site, detection_cohort) (
        (
          rate(ifHCInOctets{pilot_protocol="snmp",pilot_target!=""}[5m])
          +
          rate(ifHCOutOctets{pilot_protocol="snmp",pilot_target!=""}[5m])
        ) * 8
        /
        on (pilot_target, site, detection_cohort, ifIndex)
        group_left
        (ifHighSpeed{pilot_protocol="snmp",pilot_target!=""} * 1000000)
      )
```

實作者 MUST 用實際 generated metric labels 驗證上述 PromQL；如果 upstream module label shape 不同，先更新 spec/profile，再實作。不得在 code 裡暗改 query。

vendor CPU、memory、temperature、PSU、BGP feature MUST 放在額外 profile 或新版本，不得假設所有 vendor 指標名稱相同。

### 9.11 Model Provider / NPU / FLM

現有 ModelProvider、ManagedProvider、FallbackProvider、retry、circuit breaker 與 rate limiter MUST 沿用。

candidate input MUST 改為 generic subject：

```go
type Candidate struct {
    Subject    SubjectKey
    LocalScore LocalScoreResult
    Current    map[string]float64
}
```

FLM evidence example：

```text
candidate_id=...
subject_id=core-sw-01
subject_kind=network_device
site=hq
interface_error_rate=47.2
interface_discard_rate=0.3
aggregate_interface_utilization_ratio=0.94
```

禁止送入：

```text
完整 snmpwalk
所有 OID
數千筆 raw sample
credential
community
username/password
```

model failure 行為：

```text
transport failure
malformed output
retry exhausted
circuit open
fallback unavailable

→ preserve local statistical result
→ mark provider observability degraded
→ MUST NOT turn anomaly into normal
```

---

## 10. Agent Controller and SRE Agent Integration

### 10.1 Generic Incident Subject

新增：

```go
type IncidentSubject struct {
    ID      string `json:"id,omitempty"`
    Kind    string `json:"kind,omitempty"`
    Site    string `json:"site,omitempty"`
    Managed bool   `json:"managed"`
}
```

Alert normalization precedence MUST 為：

```text
1. labels.pilot_subject
   + labels.pilot_subject_kind
2. labels.pilot_host
   → kind=managed_host, managed=true
3. labels.pilot_target
   + labels.pilot_subject_kind
   → managed=false
4. no subject
   → global/service-scoped incident
```

禁止 fallback：

```text
instance
reverse DNS
sysName
generatorURL
annotation prose
```

`managed=true` 只能由受控 managed-host path 產生；external target user label 不得自行把它改成 true。

### 10.2 IncidentEnvelopeV2

新增 V2；current repository 尚未綁定特定 real Agent Runtime，因此本次可做 coordinated wire upgrade。

```go
type IncidentEnvelopeV2 struct {
    SchemaVersion    int                      `json:"schema_version"`
    IncidentID       string                   `json:"incident_id"`
    Source           string                   `json:"source"`
    Status           string                   `json:"status"`
    Subject          IncidentSubject          `json:"subject"`
    Alert            IncidentEnvelopeAlertV2  `json:"alert"`
    DiagnosticPolicy IncidentDiagnosticPolicy `json:"diagnostic_policy"`
}

type IncidentEnvelopeAlertV2 struct {
    Name      string `json:"name"`
    Severity  string `json:"severity"`
    Component string `json:"component,omitempty"`
    Category  string `json:"category,omitempty"`
}
```

固定 policy：

```json
{
  "mutation_allowed": false,
  "raw_command_allowed": false,
  "workspace_write_allowed": false,
  "external_subject_mutation_allowed": false
}
```

V1 MAY 保留 decode/test compatibility，但新 dispatcher request MUST 使用 V2。HTTPDispatcher documentation 與 tests MUST 同步更新。

### 10.3 Incident Identity

保持現有規則：

```text
Detection Engine source
→ annotations.signal_id 為 episode identity

Prometheus rule source
→ Alertmanager fingerprint 為 episode identity
```

generic subject 只提供 scope/correlation，不取代上述 episode identity。

### 10.4 New Structured Diagnose Tool

新增 MCP diagnose tool：

```text
pilot_diagnose_monitoring_target
```

input：

```go
type DiagnoseMonitoringTargetInput struct {
    Target string `json:"target"`
    Window string `json:"window,omitempty"`
    TopN   int    `json:"top_n,omitempty"`
}
```

限制：

```text
Target 必須是 exact monitoring target name
不得接受 regex/group/wildcard
Window default 30m
Window max 6h
TopN default 10
TopN max 20
read-only
不連 UDP 161
不存取 vault
不呼叫 snmp_exporter /snmp endpoint
```

執行流程：

```text
load Monitoring Target Registry
→ resolve exact target + profile
→ require profile.kind == snmp
→ select diagnosticProfile
→ run bounded server-owned PromQL queries through existing Thanos diagnosis path
→ optionally query active Detection Engine signal
→ construct structured report
```

output：

```go
type MonitoringTargetDiagnosis struct {
    Subject       IncidentSubject       `json:"subject"`
    Profile       string                `json:"profile"`
    Scrape        ScrapeHealth          `json:"scrape"`
    Device        map[string]MetricFact `json:"device,omitempty"`
    Interfaces    InterfaceSummary      `json:"interfaces,omitempty"`
    ActiveSignals []SignalSummary       `json:"active_signals,omitempty"`
    Evidence      []DiagnosisEvidence   `json:"evidence"`
    Warnings      []string              `json:"warnings,omitempty"`
}
```

每項 evidence MUST 記錄：

```text
tool/query-pack name
query time range
subject ID
sanitized summary
reference to raw bounded response or stored evidence
```

不得把任意 Agent-supplied PromQL 當成此工具的 query。若 Agent 需要任意 PromQL，仍使用既有 `pilot_diagnose_metrics`，兩者權限與 audit 必須分開。

### 10.5 Diagnostic Profiles

新增：

```text
monitoring/snmp/diagnostic-profiles/network-device-ifmib-v1.yaml
```

query pack 至少包含：

```text
SNMP target up
scrape duration
interface count
admin-up/oper-down top interfaces
top input/output error rate
top discard rate
aggregate utilization
active Detection Engine SignalEvent
```

query pack MUST 使用固定模板與 exact target label matcher：

```promql
pilot_target="<escaped exact target>"
```

不得以字串串接未 escape 的 target。

### 10.6 Repair and Autonomy Boundary

現有 repair plane MUST 加入 fail-closed guard：

```text
subject.managed == false
or subject.kind != managed_host
→ pilot_repair_plan reject
→ remediation auto-execute reject
```

禁止 action：

```text
snmpset
SSH CLI
interface bounce
VLAN change
route change
ACL change
device reboot
config replace
```

SRE Agent MAY 回傳 advisory recommendation：

```json
{
  "kind": "manual_network_investigation",
  "subject": "core-sw-01",
  "reason": "CRC errors concentrated on Ethernet47"
}
```

但 controller MUST NOT 將其轉換為現有 R1/R2 plan。

若未來要做 network-device mutation，必須另立：

```text
Network Device Action Plane
vendor adapter
typed change plan
diff / approval / apply / verify / rollback
```

不在本規格範圍。

---

## 11. CLI, TUI, Structured Actions and MCP Resources

### 11.1 CLI

新增/擴充行為：

```bash
pilot monitoring profile add \
  --name core-switch \
  --kind snmp \
  --job-name snmp-core-switch \
  --subject-kind network_device \
  --diagnostic-profile network-device-ifmib-v1 \
  --snmp-auth-profile core-switch-v3 \
  --snmp-module if_mib \
  --snmp-module vendor_core_switch \
  --scrape-interval 30s \
  --scrape-timeout 20s

pilot monitoring target add \
  --name core-sw-01 \
  --address 10.20.0.11 \
  --profile core-switch \
  --site hq \
  --detection-cohort arista-core-7050 \
  --label vendor=arista \
  --label model=7050

pilot monitoring validate --snmp-catalog monitoring/snmp/catalog.yml
```

`pilot monitoring target test` 對 SNMP profile MUST：

1. 透過 explicit `--snmp-exporter-url` 呼叫 exporter，不直接 poll UDP。
2. 只傳 target、module/auth ID，不讀 credential。
3. response body size bounded。
4. 顯示 exporter reachability、target scrape status、sample metric count。
5. 不在 output 顯示 request Authorization 或 config secret。

### 11.2 TUI

Monitoring Profile editor 對 `kind: snmp` MUST：

```text
kind 使用 select，不是自由文字
module 從 catalog multi-select
auth profile 從 catalog select
subject kind 使用 validated input/select
HTTP scheme/path/auth/TLS fields 隱藏或 disabled
```

Target editor 對 SNMP profile MUST 要求 site，並提供 detection cohort 欄位。

所有 TUI mutation 最終 MUST 經過同一個 domain validation，不得只靠 UI 防錯。

### 11.3 Structured Actions

至少新增：

```text
set_monitoring_profile_kind
set_monitoring_profile_subject_kind
set_monitoring_profile_diagnostic_profile
set_monitoring_profile_snmp_auth_profile
set_monitoring_profile_snmp_modules
set_monitoring_target_detection_cohort
```

規則：

1. `--actions` schema、MCP edit tools、automation driver、TUI driver 必須共享同一 semantic action contract。
2. module list MUST 是 typed string array，不得用 comma-separated free text 當 public contract。
3. actions 不接受任何 credential value。
4. `pilot_edit_inspect` 與 `pilot://monitoring/*` resource 可顯示 auth profile **名稱**，不得顯示 resolved credential。

---

## 12. Failure Semantics

| Failure | Required behavior |
|---|---|
| missing SNMP credentialRef | apply preflight fail；不得寫入半套 config |
| missing module file | apply/validate fail |
| v2c profile in prod | fail closed，除非 explicit reviewed break-glass |
| exporter container down | `SNMPExporterDown`；device incidents不得假裝正常 |
| one target timeout | 該 target `up=0`；不得阻塞其他 target scrape |
| malformed target address | registry validation fail |
| SNMP scrape stale | Detection cycle invalid，不是 normal |
| multiple series after aggregate query | `ambiguous_series` |
| required feature missing | subject cycle invalid，lifecycle 不前進 |
| optional feature missing | feature excluded，不 zero-fill |
| model timeout/malformed output | local score preserved；provider degraded |
| Alertmanager replay | existing dedup semantics preserved |
| Agent result malformed | `AGENT_FAILED`，不得存 partial diagnosis |
| diagnose query pack missing | structured error；不得 fallback 到 arbitrary shell |
| external subject enters repair | reject before planning/execution |

---

## 13. Security Requirements

### 13.1 Credential Ownership

唯一允許的 secret path：

```text
Ansible Vault / external secret input
→ snmp-exporter apply playbook (no_log)
→ root-owned env/config on exporter host
→ snmp_exporter process
```

禁止：

```text
Git repository
Monitoring Target Registry
Prometheus config
file_sd JSON
Thanos labels
Alertmanager labels/annotations
Detection SQLite
Agent Controller SQLite
Agent prompt/evidence
CLI stdout/stderr
verification evidence
```

### 13.2 SNMP Version Policy

| Stage | Default policy |
|---|---|
| sandbox | v3 preferred；v2c explicit allowed |
| staging | v3 required unless reviewed exception |
| prod | v3 `authPriv` required |

Production exception MUST 同時要求：

```text
confirm insecure SNMP
reason
expiry
owner
restricted management network evidence
```

不得提供永久、無到期的 global allow flag。

### 13.3 Exporter Endpoint Protection

loopback co-location 為預設。若非 loopback：

```text
bind only default-routed/private address, never 0.0.0.0 by default
firewall allow only site Prometheus
TLS/basic auth SHOULD be enabled
/snmp endpoint MUST NOT be Internet reachable
Agent Runtime MUST NOT have direct network reach
```

`/snmp?target=` 具有 proxy/scan 性質；endpoint 暴露範圍必須比一般 `/metrics` 更嚴格。

### 13.4 Read-only Device Access

SNMP auth profile MUST 使用 read-only view。即使設備帳號技術上可 write，也不符合本規格 production gate。

實機證據需包含：

```text
read-only account/view configuration
snmpset 被設備拒絕或 write OID 不在 view
```

測試證據不得包含 password。

---

## 14. Observability

至少提供：

```text
snmp_exporter self metrics
Prometheus up{job="snmp-exporter"}
Prometheus up{pilot_protocol="snmp"}
per-target scrape duration
per-profile target count
registry validation status
Detection subject cycle validity
Detection invalid reason counts
Detection generic anomaly score
model provider stats
Agent incident / run / diagnosis status
```

Pilot status/verification output SHOULD 顯示：

```text
site
exporter endpoint mode: loopback | remote
loaded module count
loaded auth profile count (names only)
enabled SNMP target count
last successful scrape count
```

不得輸出 credential count 對應值或 secret existence detail，避免旁路資訊洩漏；只需顯示 catalog reference 是否 resolved。

---

## 15. Implementation Phases

### Phase 0 — Contract and Verification Skeleton

新增 specification-aligned contract、verification files、network matrix 與 test topology skeleton。

Exit gate：

```text
spec lint clean
contract parsed
no apply mutation yet
all new public schemas have unit-test skeleton
```

### Phase 1 — SNMP Exporter Role and Catalog

實作：

```text
snmp-exporter contract/playbook/deploy catalog
catalog parser/validator
vault credential render
container hardening
self metrics
loopback deployment
```

Exit gate：

```text
fresh VM apply PASS
config negative tests PASS
real or lab SNMPv3 target scrape PASS
second apply changed=0
secret scan PASS
```

### Phase 2 — Monitoring Registry SNMP Schema and Compiler

實作：

```text
schema v2
v1 compatibility
CLI/TUI/actions/MCP resources
SNMP file_sd compile
site filtering
Prometheus relabel job
```

Exit gate：

```text
v1 golden unchanged
v2 SNMP golden PASS
promtool config PASS
up{pilot_protocol="snmp"}=1
wrong-site target not compiled
```

### Phase 3 — Deterministic Alerts and Read-only Agent Diagnosis

實作：

```text
SNMPTargetDown / SNMPExporterDown
Agent generic subject normalization
IncidentEnvelopeV2
pilot_diagnose_monitoring_target
diagnostic profile
repair external-subject guard
```

Exit gate：

```text
stop SNMP agent → alert firing
Alertmanager → controller incident
subject.id/core kind/site correct
FakeDispatcher receives V2
structured diagnosis returns evidence
repair plan rejects target
```

### Phase 4 — Detection Engine Subject Generalization

實作：

```text
SubjectKey
identity metadata
profile-specific sample age
multi-profile config
SQLite migration
generic alert labels
generic metrics
CLI/MCP compatibility aliases
```

Exit gate：

```text
existing linux-host fixtures unchanged
DB migration/backfill PASS
managed host alert retains pilot_host
SNMP subject never gets pilot_host
rollback backup procedure proven
```

### Phase 5 — SNMP Adaptive Detection

實作：

```text
network-device-ifmib-v1 profile
real PromQL aggregate validation
baseline/cohort behavior
SignalEvent to Alertmanager
agent correlation
```

Exit gate：

```text
fixture anomaly produces SignalEvent
normal/stale/missing/ambiguous negative lanes PASS
real Thanos chain discovers pilot_target
SignalEvent subject labels correct
```

### Phase 6 — NPU/FLM Semantic Classification

實作：

```text
generic subject candidate wire
FLM evidence update
Ollama/OpenAI schema compatibility update
fallback/retry/circuit tests
```

Exit gate：

```text
model sees only aggregate features
malformed FLM reply preserves local anomaly
fallback lane PASS
no secret/raw OID in captured prompts
```

---

## 16. Expected Repository Changes

### 16.1 New Files

```text
contracts/snmp-exporter.yaml
playbooks/apply/snmp-exporter-apply.yml
docs/architecture/snmp-monitoring.md
docs/verification/snmp-exporter.md
docs/verification/snmp-monitoring-integration.md
docs/runbooks/snmp-exporter.md
docs/runbooks/snmp-monitoring.md
monitoring/snmp/catalog.yml
monitoring/snmp/generated/if_mib.yml
monitoring/snmp/diagnostic-profiles/network-device-ifmib-v1.yaml
monitoring/detection/feature-profiles/network-device-ifmib-v1.yaml
internal/monitoring/snmp_catalog.go
internal/monitoring/snmp_catalog_test.go
internal/detection/subject.go
internal/detection/subject_test.go
internal/diagnose/monitoring_target.go
internal/diagnose/monitoring_target_test.go
```

實際 test file 可依 current package layout 調整，但 domain boundary 不得改變。

### 16.2 Modified Areas

```text
internal/monitoring/model.go
internal/monitoring/load.go
internal/monitoring/validate.go
internal/monitoring/compile.go
internal/detection/config.go
internal/detection/featureprofile.go
internal/detection/source.go
internal/detection/engine.go
internal/detection/store.go
internal/detection/episode.go
internal/detection/metrics.go
internal/detection/model_*.go
internal/agentcontroller/model.go
internal/agentcontroller/normalize.go
internal/agentcontroller/dispatcher.go
internal/repair/* guard path
cmd/pilot/cmd/monitoring*.go
cmd/pilot/cmd/edit_*monitoring*.go
cmd/pilot/cmd/edit_actions_registry.go
cmd/pilot/cmd/mcp_edit_resources.go
cmd/pilot/cmd/mcp_diagnose_tools.go
cmd/pilot/cmd/deploy_catalog.go
cmd/pilot-agent-controller/*
playbooks/apply/prometheus-apply.yml
playbooks/apply/detection-engine-apply.yml
playbooks/apply/agent-controller-apply.yml
playbooks/site.yml
inventory example / role catalog / contracts
docs/network-firewall-matrix.md
README.md
```

---

## 17. Verification Topology

### 17.1 Disposable Topology

最低 topology：

```text
snmp-device-1
  - Linux VM/container with read-only SNMPv3 agent
  - exposes IF-MIB-compatible counters

prom-site-1
  - docker
  - snmp-exporter
  - prometheus + thanos sidecar

central-observe
  - thanos-query
  - detection-engine
  - alertmanager
  - agent-controller with FakeDispatcher
```

若 current test infrastructure 需要 object storage，沿用現有 SeaweedFS/MinIO/Thanos disposable pattern；不得另建只供本功能使用的 metrics store。

### 17.2 Required Positive Lanes

1. SNMPv3 target scrape 成功。
2. Prometheus file_sd 含 exact target labels。
3. Thanos query 可見 target metrics。
4. target stop 後 `SNMPTargetDown` firing。
5. controller 建立 subject-aware incident。
6. diagnostic tool 回傳 bounded evidence。
7. Detection fixture 產生 adaptive SignalEvent。
8. FLM fake/real adapter lane保留 local detection。
9. idempotent apply `changed=0`。

### 17.3 Required Negative Lanes

1. unknown module。
2. unknown auth profile。
3. secret key 出現在 registry YAML。
4. SNMP profile 混用 HTTP TLS/auth fields。
5. empty site。
6. target 使用 reserved label。
7. prod 使用 v2c。
8. wrong-site target 被編譯。
9. duplicate module。
10. stale sample。
11. duplicate series / ambiguous result。
12. missing required feature。
13. malformed FLM response。
14. external subject repair plan。
15. exporter endpoint unauthorized access when remote mode enabled。

### 17.4 Real-device Production Gate

Mock SNMP agent 只足以達成 `VERIFICATION_READY`，不足以達成 `PRODUCTION_READY`。

production gate 至少需要：

```text
每個啟用 module family 至少一台真實設備
SNMPv3 authPriv
read-only view proof
24h staging soak
scrape success rate review
scrape duration p95 review
metric cardinality review
false-positive review
Alertmanager → Agent Controller real chain
secret scan
rollback drill
```

---

## 18. Acceptance Criteria

| ID | Acceptance |
|---|---|
| AC1 | schema v1 direct Prometheus workspace load/validate/compile golden 完全不變。 |
| AC2 | schema v2 可由 CLI、TUI、structured action 建立等價 SNMP profile/target。 |
| AC3 | registry 中出現 credential-like key 時 strict decoder/validator fail。 |
| AC4 | catalog module/auth reference 完整，unknown reference fail。 |
| AC5 | prod stage 對 SNMPv2c fail closed。 |
| AC6 | snmp-exporter 在 fresh VM 部署成功，container hardening 符合規格。 |
| AC7 | credential 只存在 root-owned secret path，repo/rendered Prometheus/evidence 無明碼。 |
| AC8 | Prometheus 對同 site target scrape `up=1`，wrong-site target 不出現在 config。 |
| AC9 | generated Prometheus config 通過 `promtool check config`。 |
| AC10 | 停止 target 後 `SNMPTargetDown` 進入 Alertmanager。 |
| AC11 | managed host identity 舊路徑維持 `pilot_host`，SNMP identity 使用 `pilot_target`/generic subject。 |
| AC12 | Detection Engine SQLite migration 完整 backfill，integrity check PASS。 |
| AC13 | SNMP profile 90 秒內 sample 不被舊 45 秒 hard-code 誤判 stale。 |
| AC14 | 同一 feature 回傳多條未聚合 series 時明確 `ambiguous_series`。 |
| AC15 | SNMP Detection SignalEvent labels 含 `pilot_subject`、`pilot_subject_kind`、`site`，不含偽造 `pilot_host`。 |
| AC16 | Agent Controller 對 Detection/Prometheus SNMP alert 正確建立 `IncidentSubject{Managed:false}`。 |
| AC17 | FakeDispatcher/HTTPDispatcher 收到 `IncidentEnvelopeV2`，policy 全為 read-only。 |
| AC18 | `pilot_diagnose_monitoring_target` 只接受 exact target，回傳 bounded structured evidence。 |
| AC19 | external subject 呼叫任何 repair/autonomy path 都在 plan/execute 前被拒絕。 |
| AC20 | model provider disabled/unavailable/malformed 時 local anomaly evidence 保留。 |
| AC21 | config/apply 第二次執行 `changed=0`。 |
| AC22 | disposable topology 正向與負向 lanes 全部有 actual-run evidence。 |
| AC23 | 真實設備 staging soak 通過後才可宣稱 production ready。 |
| AC24 | architecture、runbook、verification、firewall matrix、README 同步。 |

---

## 19. Rollout and Rollback

### 19.1 Rollout Order

```text
1. deploy exporter only
2. add one sandbox SNMP target
3. verify Prometheus/Thanos telemetry
4. enable deterministic target-down alert
5. enable Agent read-only diagnosis
6. migrate Detection Engine subject schema
7. enable adaptive SNMP profile in shadow/observe mode
8. enable FLM semantic classification
9. staging soak
10. production rollout site by site
```

不得一次在所有 site 同時導入 exporter、schema migration、adaptive detection 與 Agent integration。

### 19.2 Feature Disable

SNMP monitoring disable MUST 可透過：

```text
disable target/profile
remove SNMP scrape jobs on next apply
keep existing direct Prometheus targets unchanged
stop/disable SNMP feature profile
leave historical Thanos data untouched
```

### 19.3 Detection DB Rollback

SQLite migration 前 MUST 自動 backup。若需要 rollback 舊 Detection Engine binary：

```text
stop service
restore pre-migration DB backup
restore old config/profile
start old binary
verify status/integrity
```

不得直接用舊 binary 開啟新 subject schema DB。

---

## 20. Resolved Design Decisions

| Question | Decision |
|---|---|
| 是否建立獨立 SNMP device inventory？ | 否，擴充既有 Monitoring Target Registry。 |
| SNMP device 是否加入 `host-monitoring`？ | 否。 |
| 是否把 device name 放進 `pilot_host`？ | 否。 |
| Detection Engine 是否直接 poll SNMP？ | 否，只讀 Thanos。 |
| exporter 部署位置？ | 每 site 一個，預設與 Prometheus co-locate。 |
| SNMP credential 放哪？ | exporter host secret path；registry 只放 auth profile name。 |
| production SNMP version？ | v3 `authPriv`。 |
| 先做 deterministic 還是 adaptive？ | deterministic first。 |
| interface-level anomaly 是否直接進 Detection Engine？ | 否，先 PromQL 聚合為 device-level feature。 |
| 是否讓 Agent 自動修改 switch/router？ | 否，本規格完全禁止。 |
| 是否重寫新的 detect package？ | 否，擴充 `internal/detection`。 |
| 是否需要特定 Agent Runtime adapter？ | 否，沿用 generic dispatcher；特定 runtime 為獨立 integration。 |

---

## 21. Definition of Done

只有同時滿足以下條件，才可將本規格標記為完成：

```text
all AC1–AC24 pass
all schema/golden/unit tests pass
fresh disposable topology actual-run pass
negative lanes actual-run pass
idempotency pass
no secret leak
managed-host regression pass
repair boundary pass
real SNMPv3 device staging evidence pass
24h soak pass
network/firewall documentation updated
runbook contains deploy, diagnose, rotate credential, rollback procedures
```

不得以：

```text
spec lint
unit test only
mock exporter only
static code review
LLM explanation quality
```

取代真實 telemetry chain 與 security boundary 證據。

---

## Appendix A — End-to-end Example

### A.1 Device Registration

```bash
pilot monitoring profile add \
  --name core-switch \
  --kind snmp \
  --job-name snmp-core-switch \
  --subject-kind network_device \
  --diagnostic-profile network-device-ifmib-v1 \
  --snmp-auth-profile core-switch-v3 \
  --snmp-module if_mib \
  --scrape-interval 30s \
  --scrape-timeout 20s

pilot monitoring target add \
  --name core-sw-01 \
  --address 10.20.0.11 \
  --profile core-switch \
  --site hq \
  --detection-cohort arista-core-7050 \
  --label vendor=arista \
  --label device_role=core_switch

pilot monitoring validate --snmp-catalog monitoring/snmp/catalog.yml
```

### A.2 Data Path

```text
Prometheus
  GET http://127.0.0.1:9116/snmp
      ?target=10.20.0.11
      &module=if_mib
      &auth=core-switch-v3

snmp_exporter
  SNMPv3 GET/GETBULK → 10.20.0.11:161

Prometheus series
  ifInErrors{
    pilot_target="core-sw-01",
    pilot_protocol="snmp",
    pilot_subject_kind="network_device",
    site="hq",
    ifIndex="47"
  }
```

### A.3 Adaptive Detection

```text
raw per-interface series
→ PromQL aggregate by pilot_target/site/cohort
→ network-device-ifmib-v1
→ robust baseline/cohort
→ candidate
→ optional FLM semantic classification
→ SignalEvent
→ Alertmanager
```

### A.4 Agent Diagnosis

```json
{
  "schema_version": 2,
  "incident_id": "...",
  "source": "detection-engine",
  "status": "firing",
  "subject": {
    "id": "core-sw-01",
    "kind": "network_device",
    "site": "hq",
    "managed": false
  },
  "alert": {
    "name": "PilotAdaptiveAnomaly",
    "severity": "critical",
    "component": "snmp",
    "category": "network_error"
  },
  "diagnostic_policy": {
    "mutation_allowed": false,
    "raw_command_allowed": false,
    "workspace_write_allowed": false,
    "external_subject_mutation_allowed": false
  }
}
```

SRE Agent 呼叫：

```json
{
  "target": "core-sw-01",
  "window": "30m",
  "top_n": 10
}
```

Pilot 回傳 evidence；Agent 只能提出 advisory next action，不能執行設備變更。

---

## Appendix B — Prohibited Shortcuts

以下實作一律視為規格違反：

```text
把 switch 加到 host-monitoring group
用 pilot_host 保存外部設備名稱
Detection Engine 直接 import SNMP client
Agent prompt 中放 community/password
profile YAML 直接放 community
Prometheus config 放 SNMP password
讓 LLM 分析完整 snmpwalk
讓 LLM 自己計算 rate/MAD/trend
將每個 ifIndex 建立獨立 SignalEvent
Agent 自動執行 snmpset
將 external target 送進 pilot_repair_apply
用 reverse DNS 猜 subject
SNMP timeout 被回報為 normal
model malformed reply 被回報為 benign
```

