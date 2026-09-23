# Pilot Host Annotations → Prometheus Target Labels 實作規格

**文件狀態：** `IMPLEMENTED`（2026-09-23，candidate `8fafdc6`，vm-target 驗證見 `docs/evidence/prometheus-host-metadata/2026-09-23-8fafdc6.md`）
**規格版本：** v1.1
**日期：** 2026-09-23
**目標 Repository：** `kjelly/pilot`
**事實快照基準：** `main@c0890f66479c2aed189fd216ddeec87f72bb7306`
**主要語言：** Go、Ansible、Prometheus configuration
**目標讀者：** Coding Agent、Pilot Maintainer、SRE

> `IMPLEMENTATION_READY` 只表示本規格已收斂到可開始實作；不表示程式碼、VM 實跑、Prometheus reload、Grafana 查詢或 production rollout 已完成。

---

## 0. 規範用語與實作前提

本文件中的 **MUST、MUST NOT、SHOULD、SHOULD NOT、MAY** 為規範性要求。

實作者開始前 MUST 重新讀取 current worktree，至少確認下列路徑與本規格假設一致：

```text
hosts.example.yml
internal/inventory/inventory.go
internal/inventory/annotations.go
internal/inventory/secret.go
playbooks/apply/prometheus-apply.yml
playbooks/apply/files/pilot-alert-rules-seed.yml
group_vars/prometheus.example.yml
docs/verification/prometheus.md
docs/runbooks/metrics-alerting.md
docs/superpowers/specs/2026-09-09-host-annotations-freeipa-sync-spec.md
internal/spec/prometheus_regression_test.go
```

若 current worktree 已改變以下核心邊界，實作者 MUST 先更新本規格再實作：

```text
hosts.yml 不再是 simplified inventory canonical source
pilot_annotations 不再存在於 generated inventory hostvars
node/DCGM auto-discovery 不再使用 inventory host identity
pilot_host 不再是 managed-host canonical metrics identity
Prometheus role 不再由 playbooks/apply/prometheus-apply.yml render scrape config
```

---

## 1. 目的

Pilot 已允許 operator 在 `hosts.yml` 記錄 descriptive host metadata：

```yaml
hosts:
  gpu-a01:
    ansible_host: "10.20.30.41"
    roles: [freeipa-client, host-monitoring, dcgm-exporter]
    env: prod
    annotations:
      location: "DC1/Rack-A03/U18"
      project: "llm-training"
      owner: "ai-platform"
      asset_tag: "IT-2026-00128"
      note: "H100 training node"
```

目前這些 annotations 已投影到 generated inventory：

```yaml
pilot_annotations:
  location: "DC1/Rack-A03/U18"
  project: "llm-training"
  owner: "ai-platform"
```

本規格新增一條**受控 observability projection**：

```text
hosts.yml
  annotations
      │
      ▼
generated inventory
  pilot_annotations
      │
      │ explicit allowlist mapping
      ▼
Prometheus static_configs.labels
      │
      ├── pilot_host="gpu-a01"
      ├── pilot_location="DC1/Rack-A03/U18"
      ├── pilot_project="llm-training"
      └── pilot_owner="ai-platform"
      │
      ▼
node/DCGM metrics → Thanos → Grafana
```

目標是讓使用者可以直接使用 PromQL / Grafana variables 按 `hosts.yml` 中的穩定 host metadata 分群，例如：

```promql
label_values(up{job="node"}, pilot_project)
```

以及：

```promql
avg by (pilot_project) (
  rate(node_cpu_seconds_total{job="node", mode!="idle"}[5m])
)
```

---

## 2. Current Pilot 事實快照

### 2.1 Host annotations 已是正式 typed metadata

目前 `internal/inventory.Host` 已包含：

```go
Annotations map[string]string
```

其語意已被既有 Host Annotations spec 限定為：

- descriptive metadata；
- non-secret；
- 不控制 role/env/deploy/HBAC/sudo/repair；
- `hosts.yml` 是 canonical source；
- FreeIPA 只是 projection。

本規格 MUST 延續此語意。

### 2.2 Generated inventory 已包含 `pilot_annotations`

`pilot inventory generate` 已將 annotations render 為 namespaced hostvar：

```yaml
all:
  hosts:
    gpu-a01:
      ansible_host: "10.20.30.41"
      pilot_annotations:
        location: "DC1/Rack-A03/U18"
        project: "llm-training"
```

因此本功能 **MUST NOT 新增第二份 metadata registry**。

### 2.3 Prometheus managed-host auto-discovery 已有 per-host target block

目前 `prometheus-apply.yml` 的 node exporter auto-discovery 已採：

```yaml
static_configs:
  - targets:
      - "10.20.30.41:9100"
    labels:
      pilot_host: gpu-a01
```

DCGM exporter 亦採相同 managed-host identity pattern。

因此本功能不需要修改 exporter，也不需要把 metadata 寫入 node_exporter/DCGM exporter process。

### 2.4 `pilot_host` 是既有 canonical managed-host identity

Detection Engine、Agent Controller 與 Prometheus verification 已把：

```text
pilot_host = inventory_hostname
```

當成 managed-host canonical identity。

本規格新增的 annotation labels MUST 是 additive metadata，MUST NOT 取代或改寫 `pilot_host`。

---

## 3. Scope

### 3.1 In Scope

本規格包含：

```text
Prometheus annotation-label allowlist mapping
mapping validation / fail-closed gates
managed-host target-label builder
node exporter metadata labels
DCGM exporter metadata labels
backward-compatible opt-in behavior
Prometheus config verification
live target-label / metric-label verification
Grafana / PromQL usage examples
documentation / regression tests
```

### 3.2 Explicit Non-Goals

v1 MUST NOT：

```text
改變 hosts.yml annotations schema
新增另一份 host metadata database
從 FreeIPA 反向同步 metadata 到 Prometheus
根據 annotation 決定監控 target selection
根據 annotation 決定 role/env/deployment/access/repair policy
自動把所有 annotation 變成 Prometheus label
把 free-text note 預設 promotion 到所有 metrics
從 IP / reverse DNS 猜 inventory hostname
替 explicit node_exporter_targets 猜 annotation
替 explicit dcgm_exporter_targets 猜 annotation
修改 node_exporter binary 或 exporter collectors
修改 DCGM exporter binary
建立 Grafana dashboard provisioning framework
把 roles 陣列直接展開成 Prometheus labels
把 env 隱式轉成 annotation
建立 generic arbitrary Ansible-hostvar → Prometheus-label bridge
```

---

## 4. Architecture Invariants

| ID | Invariant |
|---|---|
| I1 | `hosts.yml.annotations` 仍是 descriptive metadata；promotion 到 metrics 不得賦予 policy semantics。 |
| I2 | `pilot_host` MUST 永遠由 inventory identity 產生，不得由 annotation 覆寫。 |
| I3 | 只有 `prometheus_host_annotation_labels` 明確 allowlist 的 annotation 才可進 Prometheus。 |
| I4 | 未設定 mapping 時，rendered Prometheus node/DCGM config MUST 與本功能導入前語意等價。 |
| I5 | explicit target override 沒有 canonical host mapping時 MUST 維持現況，不得 reverse-DNS 或猜 host。 |
| I6 | node exporter 與 DCGM exporter MUST 使用同一套 annotation promotion semantics，不得各自實作不同規則。 |
| I7 | Promoted label name MUST 使用 `pilot_` namespace，避免與 exporter 原生 labels 衝突。 |
| I8 | Secret-like annotation key MUST fail closed，不得被 promotion，即使 raw inventory 繞過 `hosts.yml` lint。 |
| I9 | `__*`、canonical identity labels 與 monitoring reserved labels MUST NOT 被 mapping 佔用。 |
| I10 | annotation value MUST 原值投影；不得 lowercase、slugify、截斷或自行改寫。 |
| I11 | missing annotation MUST 表示 label 不存在；不得 render 空字串 label。 |
| I12 | label mapping 修改只改 observability dimensions；不得改 target address、port、authentication 或 scrape selection。 |
| I13 | deterministic rendering MUST preserved；同一 inventory/config 多次 apply 必須產生 byte-stable Prometheus target blocks。 |
| I14 | Detection Engine / Agent Controller canonical subject identity 仍以 `pilot_host` 為準；不得改用 `pilot_project`、`pilot_owner` 等 metadata。 |

---

## 5. 為何採 target labels，而不是新增 info exporter

Prometheus `static_configs.labels` 是對 static targets 附加 labels 的標準機制；該 labels 會附加到從 target scrape 的 metrics。

Pilot 目前已經對每個 managed host 建立獨立 `static_configs` entry，因此 annotation promotion 只需擴充既有 labels map：

```yaml
- targets: ["10.20.30.41:9100"]
  labels:
    pilot_host: "gpu-a01"
    pilot_location: "DC1/Rack-A03/U18"
    pilot_project: "llm-training"
```

相較新增 `pilot_host_info` exporter/textfile collector，本方案：

- 不新增 daemon；
- 不改 node_exporter collector contract；
- 不需 Grafana 做 PromQL join 才能分群；
- 可直接對任何 node/DCGM metric 用 promoted dimension filter / group by；
- 完全沿用 Pilot 現有 per-host target rendering。

代價是：任何 promoted label value 改變都會改變 time-series label set，因此這些欄位 SHOULD 是低變動、適合 grouping 的 metadata。

---

## 6. Public Configuration Contract

新增 Prometheus role variable：

```yaml
prometheus_host_annotation_labels:
  location: pilot_location
  project: pilot_project
  owner: pilot_owner
```

語意：

```text
<annotation source key>: <prometheus target label name>
```

例如：

```yaml
annotations:
  location: "DC1/Rack-A03/U18"
  project: "llm-training"
  owner: "ai-platform"
  asset_tag: "IT-2026-00128"
  note: "H100 training node"
```

搭配：

```yaml
prometheus_host_annotation_labels:
  location: pilot_location
  project: pilot_project
  owner: pilot_owner
```

MUST 產生：

```yaml
labels:
  pilot_host: "gpu-a01"
  pilot_location: "DC1/Rack-A03/U18"
  pilot_project: "llm-training"
  pilot_owner: "ai-platform"
```

MUST NOT 產生：

```yaml
pilot_asset_tag: ...
pilot_note: ...
```

除非 operator 顯式把它們加入 mapping。

### 6.1 Backward-compatible default

`prometheus_host_annotation_labels` 預設 MUST 為空 mapping：

```yaml
{}
```

但 **MUST NOT** 在 play-level `vars:` 寫死：

```yaml
prometheus_host_annotation_labels: {}
```

因為 Ansible play vars 會覆蓋 `group_vars` / `host_vars`，這會重踩目前 `prometheus-apply.yml` 已修過的 precedence 問題。

所有使用點 MUST 採：

```jinja2
prometheus_host_annotation_labels | default({}, true)
```

### 6.2 建議 production mapping

`group_vars/prometheus.example.yml` SHOULD 提供但不強制啟用：

```yaml
# 將 hosts.yml annotations 中「穩定、適合 Grafana grouping」的欄位
# promotion 成 managed-host Prometheus target labels。
# 未列出的 annotations 不會進 metrics；留空即完全維持舊行為。
#
# prometheus_host_annotation_labels:
#   location: pilot_location
#   project: pilot_project
#   owner: pilot_owner
```

不應預設 promotion：

```text
note
description
comment
last_task
maintenance_message
updated_at
```

這些通常屬高變動或自由文字。

---

## 7. Mapping Validation

所有 validation MUST 在 Prometheus host 發生任何 mutation 前完成。

### 7.1 Mapping type

有效：

```yaml
prometheus_host_annotation_labels:
  project: pilot_project
```

以下 MUST fail：

```yaml
prometheus_host_annotation_labels:
  - project
```

### 7.2 Source annotation key

source key MUST 符合既有 annotation contract：

```regex
^[a-z][a-z0-9_.-]{0,62}$
```

### 7.3 Secret-like source key

MUST 使用與 `internal/inventory/secret.go` 等價的 deny pattern：

```regex
(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|vault|credential)
```

例如以下 mapping MUST fail：

```yaml
prometheus_host_annotation_labels:
  service.api_key: pilot_service_api_key
```

理由：raw/manual inventory 可以繞過 `hosts.yml` parser，因此 Prometheus apply path 自己仍需 fail closed。

### 7.4 Destination label namespace

v1 destination label MUST：

```regex
^pilot_[a-z][a-z0-9_]*$
```

使用固定 `pilot_` namespace 的理由：

- 避免與 exporter labels collision；
- Grafana 查詢可一眼識別 Pilot-owned dimension；
- 避免 source annotation 中的 `.` / `-` 直接變成不一致 label 名稱；
- 不需自動 normalization，避免 `a-b` / `a.b` / `a_b` collision。

### 7.5 Reserved destination labels

以下 MUST reject：

```text
pilot_host
pilot_target
pilot_source
pilot_protocol
pilot_subject
pilot_subject_kind
```

此清單 MUST 以 playbook 內**單一** reserved-label 變數（例如
`_pilot_prometheus_reserved_target_labels`）宣告一次，validation gate 與
regression test 都引用它，不得在多處各自手寫。實作前 MUST 重新
`grep -rhoE 'pilot_[a-z_]+' playbooks/apply/prometheus-apply.yml playbooks/apply/detection-engine-apply.yml internal/detection internal/agentcontroller`
盤點目前真正被當成 **label name**（不是 metric name）使用的 `pilot_*`，有新增就補進清單。

> 註：Detection Engine 的 cohort label 實際名稱是 `detection_cohort`（無 `pilot_`
> 前綴，見 `internal/detection/engine.go`），已被 §7.4 namespace gate 擋下，
> 不需要也不應該列成 `pilot_detection_cohort`（該名稱在 repo 中不存在）。

另外所有：

```text
__*
```

MUST reject。

`job`、`instance`、`site` 因為不符合 `pilot_` prefix，會在 namespace gate 就被拒絕。

### 7.6 Duplicate destination

以下 MUST fail：

```yaml
prometheus_host_annotation_labels:
  project: pilot_group
  owner: pilot_group
```

不得依 YAML/map iteration order 決定誰覆蓋誰。

### 7.7 Missing source value

若某 host 沒有 mapping 中指定的 annotation：

```yaml
annotations:
  project: "llm-training"
```

mapping：

```yaml
prometheus_host_annotation_labels:
  project: pilot_project
  location: pilot_location
```

該 host MUST render：

```yaml
labels:
  pilot_host: gpu-a01
  pilot_project: llm-training
```

MUST NOT render：

```yaml
pilot_location: ""
```

### 7.8 Value 型別與空值

`hosts.yml` parser 已保證 value 為非空、無前後空白的字串
（`internal/inventory.ValidateAnnotationValue`），但 raw/manual inventory 可繞過。
因此 helper MUST：

- 以 `| string` 轉型後再寫入 labels（避免 YAML int/bool 被原樣 render）；
- 轉型後為空字串的 value 視同 missing（§7.7），不 render 該 label；
- 不對 value 做其他改寫（I10）。

---

## 8. Managed-host Label Builder

### 8.1 共用 label builder（先算一份 per-host labels dict，node/DCGM 共讀）

node exporter 與 DCGM exporter MUST 共用**同一份** target-label semantics（I6）。
v1 推薦（選項 A）在 pre_tasks、node/DCGM auto-discovery 之前，先對兩個 group 的
聯集算一次 per-host labels，之後兩條路徑都只讀它：

```yaml
- name: "Resolve Prometheus host-annotation label mapping, sorted by source key"
  ansible.builtin.set_fact:
    _pilot_prometheus_annotation_label_items: >-
      {{ prometheus_host_annotation_labels | default({}, true)
         | dict2items | sort(attribute='key') }}
  tags: [always]

# (§16.1 validation gates 放在這裡)

- name: "Build managed-host Prometheus target labels (pilot_host + allowlisted annotations)"
  ansible.builtin.set_fact:
    _pilot_prometheus_host_labels: >-
      {{ (_pilot_prometheus_host_labels | default({}))
         | combine({item: ({'pilot_host': item} | combine(_labels))}) }}
  vars:
    _ann: "{{ hostvars[item].pilot_annotations | default({}, true) }}"
    _labels: >-
      {%- set out = {} -%}
      {%- for m in _pilot_prometheus_annotation_label_items -%}
        {%- set v = (_ann.get(m.key, '') | string) -%}
        {%- if v | length > 0 -%}{%- set _ = out.update({m.value: v}) -%}{%- endif -%}
      {%- endfor -%}
      {{ out }}
  loop: "{{ (groups.get('host-monitoring', []) + groups.get('dcgm-exporter', [])) | unique | sort }}"
  loop_control:
    label: "{{ item }}"
  tags: [always]
```

node / DCGM 既有的「Build one static_configs entry per auto-discovered host」loop
保留，只把 `'labels': {'pilot_host': item}` 改成
`'labels': _pilot_prometheus_host_labels[item]`。

上面 Jinja 是**示意**，實作 MUST 在真 ansible-core（repo 目前版本）上以 §20 harness
驗證其輸出後才定稿（ansible-core 2.19 對 `{% set %}`/`.update()` 與 dict 回傳型別
在 dict 方法名稱（如 `.values`）與 dict 回傳型別上有已知坑，repo 內 freeipa-dns 實作已踩過）。不論寫法，MUST：

- 從 `{'pilot_host': item}` 起算，annotation 不可覆寫 `pilot_host`（I2，gate 已擋）；
- 只取 mapping 中存在、`| string` 後非空的 annotation（I11、§7.8）；
- 依 sorted mapping 處理（§8.2）；
- annotation → label 表達式在 playbook 中只出現一次。

`_pilot_prometheus_host_labels` 是 `set_fact` 累加值；若同一 play 需重算，MUST
先以 `set_fact` reset 為 `{}`（task `vars:` 蓋不掉 `set_fact`，AGENTS.md §4.0）。

**選項 B**（抽成 `playbooks/apply/tasks/prometheus-managed-host-static-config.yml`）
只在 A 不可行時採用，且 include MUST 寫成：

```yaml
ansible.builtin.include_tasks:
  file: tasks/prometheus-managed-host-static-config.yml
  apply:
    tags: [always]
tags: [always]
```

理由：include 本身的 `tags:` **不會**繼承到被 include 的 task；只標 include，
`--tags C13` 之類 tag-scoped apply 會跳過 helper 內部，`*_auto_static_configs`
永遠沒建出，node/DCGM job 靜默消失（AGENTS.md §4.4 同類 bug）。

### 8.2 Deterministic order

source mapping 必須排序後處理（上面的 `dict2items | sort(attribute='key')`）。

另注意：scrape block 以 `to_nice_yaml` 序列化，它本身會把 labels key 依字母排序；
因此 rendered 順序是 `pilot_host` → 其他 `pilot_*` 字母序，verification regex
MUST 使用 `^[[:space:]]*-?[[:space:]]*<key>:` 形式（list item 的 `-` 會落在字母序
最前的 key 前面），不得假設 `pilot_host` 之後緊接特定 key。

### 8.3 Target address

target address 維持現況：

```jinja2
(hostvars[item].ansible_host | default(item, true)) ~ ':<port>'
```

本功能 MUST NOT 改動 address/port 計算（I12）。

---

## 9. Node Exporter Integration

目前 node auto-discovery：

```text
groups['host-monitoring']
→ sorted host names
→ one static_configs per host
→ labels.pilot_host
```

修改後：

```text
groups['host-monitoring']
→ sorted host names
→ shared label builder (§8.1)
→ port 9100
→ pilot_host + promoted annotations
```

### 9.1 Explicit override semantics 不變

若 operator 顯式設定：

```yaml
node_exporter_targets:
  - "10.20.30.41:9100"
```

則 MUST 維持目前 flat/unlabeled override：

```yaml
static_configs:
  - targets:
      - "10.20.30.41:9100"
```

MUST NOT：

- reverse DNS；
- 掃 inventory 比對 IP；
- 嘗試找同 address host；
- promotion annotation。

理由：explicit override 沒有可信的 canonical inventory identity mapping。

---

## 10. DCGM Exporter Integration

DCGM auto-discovery MUST 使用與 node exporter 完全相同的 label builder：

```text
groups['dcgm-exporter']
→ sorted host names
→ shared label builder (§8.1)
→ port 9400
→ pilot_host + promoted annotations
```

同一台：

```yaml
annotations:
  project: "llm-training"
  location: "DC1/Rack-A03/U18"
```

若同時屬於：

```text
host-monitoring
dcgm-exporter
```

node 與 dcgm jobs MUST 得到一致的 metadata labels：

```text
pilot_host
auto-promoted pilot_project
auto-promoted pilot_location
```

explicit `dcgm_exporter_targets` override 維持目前 unlabeled semantics。

---

## 11. Time-series / Cardinality Semantics

Prometheus time series identity 由 metric name + 完整 label set 決定。

因此：

```text
pilot_project="project-a"
→
pilot_project="project-b"
```

會讓該 target 後續 samples 成為新的 series identity。

### 11.1 重要判斷

因 Pilot 現在已經有 per-host `pilot_host`，新增一個穩定、單值 annotation label 通常**不會讓單次 scrape 的 active series 數量倍增**；每個既有 sample 仍只有一個 label set。

主要風險是：

```text
metadata value churn
→ 全部受影響 metric families 同時換 label set
→ retention window 內 old/new series 並存
→ TSDB index / query / alert identity churn
```

因此 SHOULD promotion：

```text
location
project
owner
hardware_pool
rack
team
```

SHOULD NOT promotion：

```text
note
status_message
ticket
last_user
last_update
timestamp
free-form description
```

---

## 12. Alerting / Incident Identity 影響

Promoted target labels 也會存在於：

```promql
up{job="node", ...}
```

以及可能保留 labels 的 alert expression 結果中。

目前 deterministic Prometheus-rule incident 對 Agent Controller 的 episode identity 使用 Alertmanager fingerprint；因此若一個 promoted label 在 alert firing 期間改值，可能形成新的 Alertmanager fingerprint。

### 12.1 v1 決策

本規格 **不修改 Agent Controller dedup contract**，避免把 metadata feature 擴大成 incident identity migration。

因此：

- mapping 預設 MUST 為空；
- production SHOULD 只 promotion 穩定 grouping dimensions；
- `note` 等高 churn 欄位 SHOULD NOT promotion；
- rollout runbook MUST 提醒 operator：新增/修改 mapping 會改變既有 series labels，可能使正在 firing 的 deterministic alert 形成新 fingerprint（例如 seed rule `HostDown: up != 1` 會保留全部 target labels）。
- promoted labels 也會出現在 Alertmanager 通知內容（含 Teams proxy 渲染的 labels），runbook SHOULD 說明。

### 12.2 不變的 canonical subject

Agent Controller 仍 MUST 使用：

```text
pilot_host
```

作 managed-host subject identity。

`pilot_project` / `pilot_owner` / `pilot_location` 只能存在於 generic Labels map，不能成為 Host/Subject ID。

---

## 13. Grafana / PromQL Contract

本功能不需要修改 Grafana backend 才能使用。

### 13.1 Project variable

推薦 dashboard variable：

```promql
label_values(up{job="node"}, pilot_project)
```

### 13.2 Location variable

```promql
label_values(up{job="node", pilot_project=~"$project"}, pilot_location)
```

### 13.3 Host variable

```promql
label_values(
  up{
    job="node",
    pilot_project=~"$project",
    pilot_location=~"$location"
  },
  pilot_host
)
```

### 13.4 Metric filtering

```promql
node_memory_MemAvailable_bytes{
  job="node",
  pilot_project=~"$project",
  pilot_location=~"$location",
  pilot_host=~"$host"
}
```

### 13.5 Grouping

```promql
avg by (pilot_project) (
  100 * (
    1 - avg by (pilot_host, pilot_project) (
      rate(node_cpu_seconds_total{job="node", mode="idle"}[5m])
    )
  )
)
```

### 13.6 Cross-site Thanos

現有：

```text
external_labels.site
```

保持不變。

因此跨站 dashboard 可形成：

```text
site
└── pilot_project
    └── pilot_location
        └── pilot_host
```

---

## 14. Prometheus Config Example

Input：

```yaml
# hosts.yml
hosts:
  gpu-a01:
    ansible_host: "10.20.30.41"
    roles: [host-monitoring, dcgm-exporter]
    env: prod
    annotations:
      location: "DC1/Rack-A03/U18"
      project: "llm-training"
      owner: "ai-platform"
      note: "H100 training node"
```

```yaml
# group_vars/prometheus.yml
prometheus_host_annotation_labels:
  location: pilot_location
  owner: pilot_owner
  project: pilot_project
```

Expected node job：

```yaml
- job_name: node
  basic_auth:
    username: prometheus
    password_file: /etc/prometheus/node-exporter-basic-auth-password
  static_configs:
    - targets:
        - 10.20.30.41:9100
      labels:
        pilot_host: gpu-a01
        pilot_location: DC1/Rack-A03/U18
        pilot_owner: ai-platform
        pilot_project: llm-training
```

Expected dcgm job：

```yaml
- job_name: dcgm
  basic_auth:
    username: prometheus
    password_file: /etc/prometheus/dcgm-exporter-basic-auth-password
  static_configs:
    - targets:
        - 10.20.30.41:9400
      labels:
        pilot_host: gpu-a01
        pilot_location: DC1/Rack-A03/U18
        pilot_owner: ai-platform
        pilot_project: llm-training
```

`note` MUST NOT 出現，因為 mapping 未 allowlist。

---

## 15. Required File Changes

### 15.1 新增

```text
docs/verification/prometheus-host-metadata.md
internal/spec/prometheus_host_metadata_regression_test.go
cmd/pilot/cmd/prometheus_host_metadata_render_test.go   # §20 render harness
playbooks/apply/tasks/prometheus-managed-host-static-config.yml   # 僅在 §8.1 選 B 時
```

### 15.2 修改

```text
playbooks/apply/prometheus-apply.yml
group_vars/prometheus.example.yml
hosts.example.yml
docs/verification/prometheus.md
docs/runbooks/metrics-alerting.md
docs/superpowers/specs/2026-09-09-host-annotations-freeipa-sync-spec.md
docs/README.md                # 若 verification/runbook index 目前要求登錄
cmd/pilot/cmd/tag_coverage_test.go   # specTagMap 登記第三份對應 prometheus-apply.yml 的 spec
docs/verification/prometheus.md      # C15/C18 regex 若受 label 增加影響需同步
```

### 15.3 不需要修改

```text
internal/inventory/inventory.go
internal/inventory/annotations.go
node_exporter deployment contract
dcgm_exporter deployment contract
internal/detection/*
internal/agentcontroller/*
playbooks/apply/dashboard-apply.yml
```

除非 current worktree 在實作時已改變上述假設。

---

## 16. `prometheus-apply.yml` Detailed Changes

### 16.1 Validation pre_tasks

在 target rendering 前新增：

```text
Gate: prometheus_host_annotation_labels is mapping
Gate: source annotation keys are valid
Gate: source annotation keys are not secret-like
Gate: destination labels use pilot_ namespace
Gate: destination labels are not reserved
Gate: destination labels are unique
```

所有 gate MUST：

- `tags: [always]`；
- 發生在任何 config directory/file/container mutation 前；
- 錯誤訊息包含 offending source/destination key；
- 不輸出任何 annotation value。

### 16.2 Node auto-discovery refactor

現有直接 `set_fact` 建 `prometheus_node_exporter_auto_static_configs` 的 loop 保留，只把 `labels` 改成讀 §8.1 的 shared label builder。

保留：

```text
prometheus_node_exporter_auto_hosts
prometheus_node_exporter_targets
prometheus_node_exporter_static_configs
prometheus_node_exporter_scrape_block
```

外部行為與變數命名盡量維持，降低 regression surface。

### 16.3 DCGM auto-discovery refactor

比照 node path，改用同一 label builder。

不得另複製一份 annotation 表達式。

### 16.4 No-op requirement

當：

```yaml
prometheus_host_annotation_labels: {}
```

或完全未定義時，node/DCGM rendered labels MUST 只有目前既有：

```yaml
pilot_host: <inventory_hostname>
```

---

### 16.5 Tag traceability

- 新增的 validation gate 與 label-builder task MUST 帶 `tags: [always]`（它們是
  node/DCGM scrape block 的前置 fact，AGENTS.md §4.4）；若同時對應新 spec row，
  另加 row tag（例如 `[always, M1]`）。
- `docs/verification/prometheus-host-metadata.md` MUST 登記進
  `cmd/pilot/cmd/tag_coverage_test.go` 的 `specTagMap`（`prometheus-apply.yml`
  已對應 `prometheus.md` 與 `prometheus-external-targets.md`，本 spec 為第三份）；
  沒有對應 task 的 row 進豁免表並附理由。
- MUST 跑 `internal/spec` 中名稱含 `AlwaysTagPrerequisite` 的 lint，並分別以
  「無 `--tags`」與「只給 `--tags C13`」各跑一次 `--check --diff`，確認 node/DCGM
  job 都仍被 render。

## 17. Documentation Changes

### 17.1 `group_vars/prometheus.example.yml`

新增：

- public variable 說明；
- opt-in example；
- stable-vs-free-text guidance；
- label churn warning；
- explicit target override 不支援 metadata promotion 的說明。

### 17.2 `hosts.example.yml`

目前 annotations comment 說明其不控制 monitoring selection；此原則保留。

補充：

```text
prometheus role 可選擇把部分 annotation 複製成 target labels，
但只是在「已經被選中的 target」上加 descriptive dimensions，
不會因 annotation 決定是否監控。
```

### 17.3 Host Annotations spec

在 `2026-09-09-host-annotations-freeipa-sync-spec.md` 加 amendment / cross-reference：

```text
2026-09-23 起，selected annotations MAY additionally project to Prometheus
managed-host target labels under explicit allowlist；此 projection 不改變
§3.2 的 descriptive-only / no-policy invariant。
```

不得把歷史 spec 改寫成「annotation 可以控制 monitoring selection」。

### 17.4 `docs/runbooks/metrics-alerting.md`

新增：

- mapping example；
- rendered target labels example；
- Grafana variable / PromQL example；
- rollout churn warning；
- rollback 操作。

---

## 18. Verification Spec

新增：

```text
docs/verification/prometheus-host-metadata.md
```

不要把 optional feature 強制塞進現有 `docs/verification/prometheus.md` 的 PASS 條件，否則沒有啟用 mapping 的合法 Prometheus deployment 會被誤判 FAIL。

### 18.1 Verification topology

測試 inventory 至少需要：

```text
meta-prom    prometheus
meta-node    host-monitoring
meta-gpu     host-monitoring + dcgm-exporter   # 若測試環境有 GPU
```

至少一台 managed target 必須有：

```yaml
pilot_annotations:
  location: "DC1/Rack-A03/U18"
  project: "llm-training"
  owner: "ai-platform"
  note: "must-not-be-promoted"
```

Prometheus mapping：

```yaml
prometheus_host_annotation_labels:
  location: pilot_location
  project: pilot_project
  owner: pilot_owner
```

### 18.2 Required checks

verification spec 只放「在**一次**啟用 mapping 的部署上，於 target 執行即可觀察」的 row。
需要另一種部署狀態（mapping 未設、explicit override）或「apply 應失敗」的案例，
`pilot verify` 做不到（row 是在已部署 host 上跑的檢查指令），MUST 移到 §19/§20 的
測試或 §21 的額外 live 情境，不得寫成 verification row。

| ID | Category | Check | Expected |
|---|---|---|---|
| M1 | config | node job target 有 `pilot_host` | present |
| M2 | config | node job target 有 `pilot_project: llm-training` | present |
| M3 | config | node job target 有 `pilot_location: DC1/Rack-A03/U18` | present |
| M4 | config | 未 allowlist 的 `note` 值不在 prometheus.yml | absent |
| M5 | config | mapping 有、host 缺的 annotation 不 render empty destination label | absent |
| M6 | metrics | `up{job="node",pilot_project="llm-training"}` 有 sample | present |
| M7 | metrics | 真 node exporter metric（`node_uname_info` 或 `node_cpu_seconds_total`）帶 `pilot_project`/`pilot_location` | present |
| M8 | metrics | 真 node metric 不含 `pilot_note` label | absent |
| M9 | dcgm | DCGM job 的 Pilot metadata labels 與同 host node job 一致（config 層） | pass / conditional |

M9 conditional：vm-target 沒有 GPU。可只驗 config 渲染——把一台 VM 同時列入
Prometheus inventory 的 `dcgm-exporter` group（不必真的部署 dcgm-exporter），
比對 rendered `job_name: dcgm` block；若要驗 DCGM 真 metric，使用真實 GPU 主機。

移出 verification、改由其他層涵蓋：

| 原案例 | 改由 |
|---|---|
| secret-like / reserved / duplicate / invalid destination fail before mutation | §20 render harness（預期 non-zero + 錯誤訊息只含 key）+ §21 L10 |
| mapping unset 時只有 `pilot_host` | §20 V1 + 既有 `prometheus.md` C15/C18 PASS（§21 L11） |
| explicit override 不猜 metadata | §20 V9 |
| idempotency `changed=0` | `pilot vm-target test` 內建 L6 |

### 18.3 真 metric 驗證

不能只 grep config。

至少需要一條 Prometheus API query 證明 label 已進 TSDB：

```promql
node_uname_info{
  job="node",
  pilot_project="llm-training",
  pilot_location="DC1/Rack-A03/U18"
}
```

若目前 node_exporter release/collector 不保證 `node_uname_info`，可選擇現有環境穩定存在的 `node_cpu_seconds_total`，但 verification 必須查 **真正 exporter metric**，不能只查 config text。

---

## 19. Go Regression Tests

新增：

```text
internal/spec/prometheus_host_metadata_regression_test.go
```

至少鎖定：

1. `docs/verification/prometheus-host-metadata.md` row IDs 與 count。
2. verification 必須包含：
   - `pilot_host`
   - `pilot_project`
   - `pilot_location`
   - node metric query
   - non-promoted `note` negative check
3. 不得在 verification command 中出現 exporter password。
4. `prometheus-apply.yml` 必須有 shared label builder（§8.1）。
5. node 與 dcgm path 都必須引用同一 label builder，且 playbook 內 annotation
   → label 表達式只出現一次（防止複製）。
   若採 §8.1 B：include 必須帶 `apply: {tags: [always]}`。
6. playbook 必須包含 secret-like gate。
7. playbook 必須包含 reserved-label gate。
8. playbook 必須保留 explicit override path。
9. group vars example 必須說明 feature opt-in/default no-op。
10. reserved-label 清單只宣告一次，gate 引用該變數。
11. verification spec 不含 M8–M10 舊版那種「apply 應失敗」或需要不同部署狀態的 row（§18.2）。

如果 repo 已有更適合的 playbook/source regression test package，應沿用既有 pattern，不要為本功能建立新的 test framework。

---

## 20. Unit / Static Test Cases

V1–V12 驗的是 Jinja/Ansible 行為，純 Go 字串比對驗不到。MUST 沿用 repo 既有
「Go test 呼叫真 `ansible-playbook`」模式（`cmd/pilot/cmd/*_test.go`，如
`deploy_exitcode_regression_test.go`），新增 render harness：

- 以 fixture inventory（含 `pilot_annotations`、`host-monitoring`/`dcgm-exporter` group）
  對 localhost 跑 `prometheus-apply.yml` 的 pre_tasks（`--check` 或
  `--tags always` + 一個只 dump `prometheus_node_exporter_scrape_block` /
  `prometheus_dcgm_exporter_scrape_block` 的 debug 出口），解析 JSON callback 結果比對；
- 失敗案例（V4–V8）斷言 non-zero，且輸出含 offending key、不含 annotation value；
- `ansible-playbook` 不在 PATH 時 `t.Skip`，比照既有測試；
- expected 值 MUST 來自實際 render 結果轉錄（AGENTS.md §5.6），不得手寫猜測。

### V1 — empty mapping

Input：

```yaml
prometheus_host_annotation_labels: {}
```

Expected：

```yaml
labels:
  pilot_host: gpu-a01
```

### V2 — selected annotations

Input：

```yaml
pilot_annotations:
  project: llm-training
  location: DC1/Rack-A03/U18
  note: temp

prometheus_host_annotation_labels:
  project: pilot_project
  location: pilot_location
```

Expected：

```yaml
labels:
  pilot_host: gpu-a01
  pilot_location: DC1/Rack-A03/U18
  pilot_project: llm-training
```

No `pilot_note`.

### V3 — missing source annotation

mapping 有 `owner`，host 沒有 `owner`。

Expected：完全沒有 `pilot_owner` key。

### V4 — secret-like source

```yaml
prometheus_host_annotation_labels:
  token: pilot_token
```

Expected：preflight fail。

### V5 — invalid destination

```yaml
prometheus_host_annotation_labels:
  project: project-name
```

Expected：fail。

### V6 — no Pilot namespace

```yaml
prometheus_host_annotation_labels:
  project: project
```

Expected：fail。

### V7 — reserved identity

```yaml
prometheus_host_annotation_labels:
  project: pilot_host
```

Expected：fail。

### V8 — duplicate destination

```yaml
prometheus_host_annotation_labels:
  project: pilot_group
  owner: pilot_group
```

Expected：fail。

### V9 — node explicit override

Expected：不含 `pilot_host` 與 promoted metadata，維持現有 contract。

### V10 — node/DCGM consistency

同一 auto-discovered host：兩 job 的 Pilot-owned metadata labels 必須相同。

### V11 — deterministic order

同一 mapping 以不同 YAML key order 載入，rendered labels order/result MUST deterministic。

### V12 — special annotation value

例如：

```yaml
location: "DC1/Rack A-03/U18"
```

Expected：value 原樣被 YAML-safe serialize，不自行 slugify。

### V13 — non-string / empty value from raw inventory

raw inventory `pilot_annotations: {rack: 12, owner: ""}` + mapping 含 `rack`、`owner`。

Expected：`pilot_rack: "12"`（字串），沒有 `pilot_owner`。

### V14 — tag-scoped apply

以 `--tags C13` 跑，node job 仍 render 且帶 promoted labels（AGENTS.md §4.4）。

---

## 21. Live Validation Procedure

實作者 MUST 完成一次真實 Prometheus scrape，不得只跑 syntax/unit test。

### Phase L1 — 建立 target metadata

以 generated inventory 路徑建立至少一台：

```yaml
annotations:
  location: "DC1/Rack-A03/U18"
  project: "llm-training"
  owner: "ai-platform"
  note: "not-promoted"
```

確認 generated inventory 中存在 `pilot_annotations`。

### Phase L2 — apply host-monitoring

node_exporter 必須成功部署並可由 Prometheus 使用既有 Basic Auth contract scrape。

### Phase L3 — apply Prometheus with mapping

設定：

```yaml
prometheus_host_annotation_labels:
  location: pilot_location
  project: pilot_project
  owner: pilot_owner
```

apply MUST 成功。

### Phase L4 — config validation

Prometheus host：

```bash
docker exec pilot-prometheus promtool check config /etc/prometheus/prometheus.yml
```

MUST PASS。

### Phase L5 — target API

透過 Prometheus API 確認 active target labels 至少包含：

```text
pilot_host
pilot_project
pilot_location
pilot_owner
```

### Phase L6 — TSDB metric

PromQL 查詢真實 node metric，確認 promoted labels 已附加。

### Phase L7 — negative label

`note` 未 allowlist，MUST 不存在於 metric labels。

### Phase L8 — idempotency

相同 input 重跑：

```text
changed=0
```

至少 Prometheus role 自己管理的 config/container path 必須冪等。

### Phase L9 — mapping change

只改：

```yaml
project: project-b
```

重新 apply 後：

- target labels 更新；
- Prometheus config valid；
- 新 samples 帶 `pilot_project="project-b"`；
- 文件證據必須明確記錄 old/new series identity churn 是預期行為。

### Phase L10 — invalid mapping fail-closed

分別以 secret-like source、reserved destination、duplicate destination 重跑 apply，
MUST 在任何 mutation 前失敗（PLAY RECAP `changed=0`、prometheus.yml hash 不變）。

### Phase L11 — rollback / unset

移除 mapping 重跑 apply，`prometheus.md` 既有 C15/C18 仍 PASS，rendered labels 只剩
`pilot_host`。

---

## 22. Rollout Strategy

### 22.1 Phase 1 — code + tests only

完成：

```text
helper
validation
node integration
dcgm integration
unit/static tests
docs
```

mapping default `{}`，production 無行為變更。

### 22.2 Phase 2 — staging opt-in

staging 設定：

```yaml
prometheus_host_annotation_labels:
  location: pilot_location
  project: pilot_project
  owner: pilot_owner
```

觀察：

```text
prometheus_tsdb_head_series
Prometheus memory
query latency
Thanos query behavior
Grafana variables
Alertmanager firing alerts
```

### 22.3 Phase 3 — production gradual enablement

按 site 啟用，不一次全 fleet rollout。

production rollout 前 SHOULD 確認：

- mapping 只含穩定欄位；
- 沒有正在處理、會因 fingerprint churn 造成混淆的重要 HostDown alert；
- Grafana dashboard variables 已準備好；
- Thanos query 能看到新 labels。

---

## 23. Rollback

本功能 rollback 不需要降版 schema。

只要：

```yaml
prometheus_host_annotation_labels: {}
```

或移除該設定，再 apply Prometheus。

Expected：

```text
新 scrape samples 回到只有既有 target labels
舊 metadata-labelled series 依 TSDB retention 自然消退
不修改 hosts.yml
不修改 FreeIPA annotations
不修改 node_exporter/DCGM deployment
```

不得為了 rollback 刪除 `hosts.yml.annotations`；它們仍有 Portal / FreeIPA descriptive metadata 用途。

---

## 24. Security Requirements

| Requirement | 規則 |
|---|---|
| Secrets | secret-like source key 必須 fail closed |
| Namespace | destination 只允許 `pilot_*` |
| Reserved identity | annotation 不得覆寫 `pilot_host`/`pilot_target`/subject labels |
| Values | annotation value 會進 Prometheus/Thanos，視為 observability-visible metadata |
| RBAC | 本功能不新增任何 access-control semantics |
| Logging | validation error 只需輸出 key，不需輸出 value |
| FreeIPA | 不從 FreeIPA 回讀再 promotion；generated inventory hostvars 是 runtime source |

Operator 文件 MUST 明確說明：

```text
被 promotion 的 annotation 會出現在 Prometheus / Thanos / Grafana 可查詢資料中。
```

即使 annotation 本來就禁止 secret，仍不可讓使用者誤以為該欄位只存在本機 inventory。

---

## 25. Performance / Cardinality Guardrails

v1 不新增 arbitrary hard cap，但文件 MUST 提供以下 operational guidance：

- 建議 promotion 欄位數量保持少量（通常 3–8 個）。
- 避免 user ID、ticket ID、request ID、timestamp、free-form note。
- 優先採穩定 infrastructure dimensions：project/location/owner/pool/rack。
- 在 pilot_host 已唯一識別 host 的前提下，asset tag 對 grouping 通常價值有限，卻增加 label surface；除非確實有 Grafana/PromQL 使用需求才 promotion。

若未來實測出現 TSDB/index 壓力，再新增可量測的 hard ceiling；v1 不用猜一個任意上限。

---

## 26. Acceptance Criteria

### Functional

- [ ] `prometheus_host_annotation_labels` 可在 group_vars/host_vars 正常生效。
- [ ] 未設定 mapping 時現有 node/DCGM behavior 不變。
- [ ] node auto-discovery metrics 帶 selected metadata labels。
- [ ] DCGM auto-discovery metrics 使用同一套 metadata labels。
- [ ] missing annotations 不產生 empty label。
- [ ] unmapped annotations 不進 metrics。
- [ ] explicit overrides 不猜 metadata。

### Safety

- [ ] secret-like mapping source fail before mutation。
- [ ] invalid destination label fail before mutation。
- [ ] non-`pilot_` destination fail。
- [ ] reserved identity destination fail。
- [ ] duplicate destination fail。
- [ ] annotation 仍不影響 monitoring selection/access/repair policy。

### Compatibility

- [ ] existing `pilot_host` label 保留。
- [ ] existing Detection Engine managed-host identity 不變。
- [ ] existing Agent Controller managed-host subject identity 不變。
- [ ] existing prometheus verification 在 mapping 未啟用時仍 PASS。
- [ ] existing explicit target semantics 不變。

### Quality

- [ ] `go test ./...` PASS。
- [ ] relevant Ansible syntax/lint checks PASS。
- [ ] `promtool check config` PASS。
- [ ] feature verification spec PASS。
- [ ] live Prometheus metric query 證明 labels 真正進 TSDB。
- [ ] idempotent rerun `changed=0`。

---

## 27. Definition of Done

本功能只有在以下全部完成後才算完成：

```text
[ ] current worktree assumptions re-validated
[ ] mapping validation implemented
[ ] shared managed-host label builder implemented (§8.1)
[ ] node exporter path uses shared label builder
[ ] DCGM exporter path uses shared label builder
[ ] default no-op compatibility verified
[ ] group_vars example documented
[ ] hosts.example.yml annotation comment updated
[ ] Host Annotations spec cross-reference added
[ ] dedicated verification spec added
[ ] Go regression tests added
[ ] ansible render harness (§20) added
[ ] specTagMap registration + AlwaysTagPrerequisite lint pass
[ ] tag-scoped (--tags C13) render verified
[ ] full go test passes
[ ] Prometheus config passes promtool
[ ] live node exporter scrape proves metadata labels
[ ] non-promoted annotation negative case verified
[ ] invalid/secret/reserved mappings fail closed
[ ] idempotency proven
[ ] evidence artifact committed under docs/evidence/
```

---

## 28. Recommended Implementation Order for Coding Agent

```text
1. Re-read current repository and record current main SHA.
2. Add regression tests describing expected mapping/validation/helper behavior.
3. Add mapping validation gates to prometheus-apply.yml.
4. Add shared label builder (§8.1, option A preferred).
5. Refactor node auto-discovery to the builder without enabling metadata yet.
6. Run tests and prove node legacy rendering unchanged with empty mapping.
7. Add annotation promotion to helper.
8. Refactor DCGM auto-discovery to same builder.
9. Add §20 render harness cases V1–V14.
10. Add group_vars + hosts.example documentation.
11. Add dedicated verification spec, regression lock, specTagMap entry.
12. Run go test ./....
13. Run live apply with mapping.
14. Verify promtool config.
15. Verify /api/v1/targets labels.
16. Verify real node metric labels through PromQL.
17. Verify unmapped note absent.
18. Verify invalid/secret/reserved mappings fail before mutation.
19. Re-run apply and prove changed=0.
20. Record docs/evidence and update runbook/spec status.
```

---

## 29. Final Target State

完成後 Pilot 的 host metadata flow 應為：

```text
                         hosts.yml
                            │
                            │ canonical descriptive metadata
                            ▼
                    annotations{key:value}
                            │
             ┌──────────────┴───────────────┐
             │                              │
             ▼                              ▼
      generated inventory               FreeIPA
       pilot_annotations             userClass/location
             │
             │ explicit Prometheus allowlist
             ▼
   managed-host target label builder
             │
       ┌─────┴─────┐
       ▼           ▼
   node:9100    dcgm:9400
       │           │
       └─────┬─────┘
             ▼
         Prometheus
             │
             ▼
           Thanos
             │
             ▼
           Grafana

Dimensions:
  site
  pilot_host
  pilot_project
  pilot_location
  pilot_owner
```

核心原則保持不變：

```text
annotation = descriptive metadata
promotion = observability decoration
pilot_host = canonical managed-host identity
monitoring selection = roles / inventory semantics
policy / access / repair = annotation-independent
```

---

## 30. Reference Notes

Prometheus 官方 configuration contract：

- `static_config.labels` 會套用到從該 target scrape 的 metrics。
- Prometheus label set 是 time-series identity 的一部分；新增/修改 label value 會形成新的 time series。
- `__*` label namespace 保留給 Prometheus internals。
- 為 ecosystem compatibility，label name 應維持 `[a-zA-Z_][a-zA-Z0-9_]*`；本規格進一步收斂成 Pilot-owned `pilot_*` lowercase namespace。

相關 Pilot 文件：

```text
docs/superpowers/specs/2026-09-09-host-annotations-freeipa-sync-spec.md
docs/verification/prometheus.md
docs/runbooks/host-monitoring.md
docs/runbooks/metrics-alerting.md
internal/inventory/inventory.go
internal/inventory/annotations.go
internal/inventory/secret.go
playbooks/apply/prometheus-apply.yml
```

---

## 31. 變更紀錄

| 日期 | 版本 | 變更 |
|---|---|---|
| 2026-09-23 | v1.0 | 初版 |
| 2026-09-23 | v1.1 | 可實作性評估後修正：§8.1 改為單一 shared label builder（或 include 必須 `apply: {tags: [always]}`，避免 tag-scoped apply 靜默丟 job）；§7.5 移除不存在的 `pilot_detection_cohort`、reserved 清單改單一宣告；新增 §7.8 value `| string` 與空值處理；§18.2 移除 `pilot verify` 無法執行的 fail-case / 異狀態 row，改由 §20 render harness 與 §21 L10/L11 涵蓋；§20 指定沿用既有 Go→`ansible-playbook` 測試模式並新增 V13/V14；新增 §16.5 tag traceability（specTagMap、AlwaysTagPrerequisite）；§8.2 補 `to_nice_yaml` key 排序對 regex 的影響；§12 補 HostDown/Teams 通知影響；檔案搬到 `docs/superpowers/specs/` |
| 2026-09-23 | v1.2 | 實作完成：採 §8.1 選項 A（單一 per-host label builder，無 task 檔）；render harness 放 `internal/spec/prometheus_host_metadata_render_test.go`（非 §15 原寫的 `cmd/pilot/cmd`）；verification spec row ID 用 repo 慣例 C1–C10（tag namespace `host-meta-Cx`）；L1–L11 於 vm-target 實跑通過，production rollout（§22 Phase 2/3）尚未進行 |
