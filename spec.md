# Pilot External Prometheus Exporter Target 實作規格

## 1. 文件目的

本規格定義 Pilot 如何支援：

> **Prometheus scrape 非 Pilot / Ansible 管理之 exporter endpoint。**

目前 Pilot 的 `host-monitoring` 機制會從 inventory 中的 `host-monitoring` group 自動產生 `node_exporter` targets，而 Prometheus 亦支援透過 `prometheus_scrape_configs` 直接覆寫任意 scrape configuration。

現行架構存在以下限制：

1. 外部 exporter 必須透過自由格式 `prometheus_scrape_configs` 管理。
2. Pilot 無法理解這些 exporter 的結構與生命週期。
3. Pilot CLI/TUI 無法列出、驗證、修改這些 exporter。
4. Agent 若要新增 exporter，只能修改任意 Prometheus YAML。
5. `prometheus_scrape_configs` 是整段覆寫，容易誤刪 Prometheus self-scrape 或其他 jobs。
6. 無法清楚區分：

   * Pilot managed host
   * Prometheus monitored endpoint
7. 不適合 NAS、UPS、switch、VMware、資料庫 appliance、第三方服務等「可監控但不可由 Pilot 管理」的設備。

本次改版必須建立正式的 **Monitoring Target Model**，並使用 Prometheus `file_sd_configs` 將 target registry 與 Prometheus 主設定解耦。

---

# 2. 核心設計原則

Pilot 必須明確區分兩種概念：

```text
Managed Host
    =
Pilot 可以透過 Ansible / structured action 管理其 OS 或服務

Monitoring Target
    =
Prometheus 可以 scrape 的 endpoint
```

兩者：

* 可以同時存在；
* 可以互相對應；
* 但不得互相依賴。

例如：

```text
Linux Server
├── Managed Host: yes
└── Monitoring Target: yes

NAS
├── Managed Host: no
└── Monitoring Target: yes

UPS
├── Managed Host: no
└── Monitoring Target: yes

Prometheus Server
├── Managed Host: yes
└── Monitoring Target: self
```

Ansible lifecycle 與 monitoring lifecycle 必須分離。

---

# 3. 非目標

本階段不實作以下功能：

1. 不自動安裝 external exporter。
2. 不透過 SSH 管理 external target。
3. 不替 external target 建立 Ansible inventory host。
4. 不實作 Kubernetes service discovery。
5. 不實作 Consul service discovery。
6. 不實作 FreeIPA DNS SRV discovery。
7. 不實作 Prometheus HTTP SD。
8. 不建立 exporter marketplace。
9. 不自動推論 exporter 類型。
10. 不允許 Monitoring Target 觸發 arbitrary Ansible playbook。
11. 不移除既有 `host-monitoring` role。
12. 不移除既有 `node_exporter_targets`。
13. 不完全移除 `prometheus_scrape_configs`。

`prometheus_scrape_configs` 必須保留作為 advanced escape hatch。

---

# 4. 現行架構相容性

目前 Prometheus contract 已定義：

```yaml
dependencies:
  - component: host-monitoring
    required: false
    relation: providerEndpoint
```

並透過：

```yaml
bindings:
  - input: node_exporter_targets
    requiredWhenDependencySelected: false
    sourceSelection: all
    from:
      component: host-monitoring
      endpoint: metrics
```

自動取得由 Pilot 管理之 node exporter。此行為必須保留。

目前 playbook 亦會將：

```yaml
prometheus_scrape_configs
```

與：

```yaml
prometheus_node_exporter_scrape_block
```

一起放入：

```yaml
scrape_configs:
```

新的 external monitoring target 機制不得破壞此行為。

---

# 5. 最終架構

目標架構：

```text
                         Pilot Workspace
                              │
              ┌───────────────┴────────────────┐
              │                                │
          hosts.yml                       monitoring/
              │                                │
        Managed Hosts                  External Targets
              │                                │
        host-monitoring                       │
              │                                │
     node_exporter targets                     │
              │                                │
              └──────────────┬─────────────────┘
                             │
                     Target Compiler
                             │
                       file_sd JSON
                             │
                             ▼
                        Prometheus
                             │
                             ▼
                           Thanos
```

---

# 6. Workspace 結構

新增：

```text
<workspace>/
├── hosts.yml
├── group_vars/
├── host_vars/
├── monitoring/
│   ├── targets.yml
│   └── scrape-profiles.yml
└── ...
```

未啟用 external monitoring target 時：

```text
monitoring/
```

可以不存在。

不能因為檔案不存在而造成既有 workspace 無法使用。

---

# 7. Monitoring Target Schema

## 7.1 檔案

```text
monitoring/targets.yml
```

Schema version：

```yaml
schemaVersion: 1
```

基本格式：

```yaml
schemaVersion: 1

targets:
  - name: nas01
    address: nas01.pilot.internal:9633
    profile: storage-exporter
    site: taipei
    enabled: true
    labels:
      owner: storage
      environment: prod
```

---

# 8. Monitoring Target 欄位

每個 target：

```yaml
name: string
address: string
profile: string
site: string
enabled: bool
labels:
  string: string
```

## 8.1 `name`

必填。

必須：

* 非空；
* workspace 內唯一；
* 建議只接受：

```regex
^[A-Za-z0-9][A-Za-z0-9._-]*$
```

例如：

```text
nas01
ups-a
postgres.accounting
legacy_server_01
```

---

## 8.2 `address`

必填。

格式：

```text
host:port
```

合法：

```text
10.0.0.20:9100
nas01.pilot.internal:9633
db01.example.internal:9187
[2001:db8::1]:9100
```

不合法：

```text
https://10.0.0.20:9100
10.0.0.20
nas01
```

scheme 必須由 scrape profile 決定。

---

## 8.3 `profile`

必填。

必須指向：

```text
monitoring/scrape-profiles.yml
```

內已存在的 profile。

不存在時：

```text
pilot validate
```

必須失敗。

---

## 8.4 `site`

選填。

表示此 exporter 所屬邏輯 site。

例如：

```yaml
site: taipei
```

Target compiler 必須將其轉為 Prometheus label：

```yaml
site: taipei
```

若 target 沒有指定 `site`：

不得自動套用 Prometheus server 的 `prometheus_site_label`。

原因：

```text
Prometheus site
≠
exporter physical/logical site
```

除非未來另有明確繼承規則。

---

## 8.5 `enabled`

選填。

預設：

```yaml
enabled: true
```

若：

```yaml
enabled: false
```

則 target：

* 保留在 registry；
* 不輸出至 Prometheus `file_sd`；
* `pilot monitoring target list` 必須顯示 disabled 狀態。

---

## 8.6 `labels`

選填。

型別：

```yaml
map[string]string
```

例如：

```yaml
labels:
  environment: prod
  owner: storage
  device_type: nas
```

系統保留 label：

```text
pilot_target
pilot_source
```

使用者不得覆寫。

Target compiler 必須自動加入：

```yaml
pilot_target: nas01
pilot_source: external
```

若有 site：

```yaml
site: taipei
```

---

# 9. Scrape Profile Schema

檔案：

```text
monitoring/scrape-profiles.yml
```

範例：

```yaml
schemaVersion: 1

profiles:
  external-node:
    jobName: external-node
    scheme: https
    metricsPath: /metrics
    scrapeInterval: 15s
    authRef: external-node-auth

  postgres:
    jobName: postgres-exporter
    scheme: http
    metricsPath: /metrics

  storage-exporter:
    jobName: storage
    scheme: https
    metricsPath: /metrics
    tls:
      caRef: pilot-root-ca
```

---

# 10. Scrape Profile 欄位

第一版至少支援：

```yaml
jobName: string
scheme: http|https
metricsPath: string
scrapeInterval: duration
scrapeTimeout: duration

authRef: string

tls:
  caRef: string
  serverName: string
  insecureSkipVerify: bool
```

其中只有：

```text
jobName
```

必填。

其餘預設：

```yaml
scheme: http
metricsPath: /metrics
```

`scrapeInterval`、`scrapeTimeout` 未指定時使用 Prometheus global 設定。

---

# 11. Profile 設計原則

禁止把完整 Prometheus scrape job YAML 塞入 profile，例如禁止：

```yaml
rawConfig: |
  static_configs:
    ...
```

也禁止 target 自己攜帶：

```yaml
scheme:
basic_auth:
tls_config:
relabel_configs:
```

Target 只能引用 profile。

目的：

```text
target = endpoint instance

profile = scrape behavior
```

避免 target registry 演變成第二份任意 `prometheus.yml`。

---

# 12. Credential Model

本階段不得在：

```text
monitoring/targets.yml
monitoring/scrape-profiles.yml
```

直接保存 password/token。

必須透過 reference。

例如：

```yaml
authRef: external-node-auth
```

第一版可先支援 Basic Auth。

建議新增：

```text
group_vars/prometheus.yml
```

或 vault-backed monitoring secrets：

```yaml
monitoring_auth:
  external-node-auth:
    type: basic
    username: prometheus
    password: ...
```

其中 password 必須符合 Pilot 現有 secret / Ansible Vault 慣例。

不得產生：

```yaml
password: plaintext
```

到 git-tracked monitoring YAML。

---

# 13. Target Compiler

新增內部模組，建議：

```text
internal/monitoring/
```

大致結構：

```text
internal/monitoring/
├── model.go
├── load.go
├── validate.go
├── compiler.go
├── file_sd.go
└── *_test.go
```

---

# 14. Go Domain Model

建議資料結構：

```go
type TargetFile struct {
    SchemaVersion int      `yaml:"schemaVersion"`
    Targets       []Target `yaml:"targets"`
}

type Target struct {
    Name    string            `yaml:"name"`
    Address string            `yaml:"address"`
    Profile string            `yaml:"profile"`
    Site    string            `yaml:"site,omitempty"`
    Enabled *bool             `yaml:"enabled,omitempty"`
    Labels  map[string]string `yaml:"labels,omitempty"`
}

type ProfileFile struct {
    SchemaVersion int                `yaml:"schemaVersion"`
    Profiles      map[string]Profile `yaml:"profiles"`
}

type Profile struct {
    JobName        string     `yaml:"jobName"`
    Scheme         string     `yaml:"scheme,omitempty"`
    MetricsPath    string     `yaml:"metricsPath,omitempty"`
    ScrapeInterval string     `yaml:"scrapeInterval,omitempty"`
    ScrapeTimeout  string     `yaml:"scrapeTimeout,omitempty"`
    AuthRef        string     `yaml:"authRef,omitempty"`
    TLS            *TLSConfig `yaml:"tls,omitempty"`
}

type TLSConfig struct {
    CARef              string `yaml:"caRef,omitempty"`
    ServerName         string `yaml:"serverName,omitempty"`
    InsecureSkipVerify bool   `yaml:"insecureSkipVerify,omitempty"`
}
```

實際命名可依 repository coding convention 調整。

---

# 15. File SD 輸出

Prometheus target 不直接寫死進主 `prometheus.yml`。

Pilot 必須產生：

```text
/etc/pilot/prometheus/targets/
```

建議每個 profile/job 一個檔案：

```text
/etc/pilot/prometheus/targets/
├── external-node.json
├── postgres-exporter.json
└── storage.json
```

---

# 16. File SD JSON 格式

例如 registry：

```yaml
targets:
  - name: nas01
    address: nas01.pilot.internal:9633
    profile: storage-exporter
    site: taipei
    labels:
      environment: prod

  - name: nas02
    address: nas02.pilot.internal:9633
    profile: storage-exporter
    site: taipei
```

應編譯成：

```json
[
  {
    "targets": [
      "nas01.pilot.internal:9633"
    ],
    "labels": {
      "pilot_target": "nas01",
      "pilot_source": "external",
      "site": "taipei",
      "environment": "prod"
    }
  },
  {
    "targets": [
      "nas02.pilot.internal:9633"
    ],
    "labels": {
      "pilot_target": "nas02",
      "pilot_source": "external",
      "site": "taipei"
    }
  }
]
```

每個 target 獨立 entry，以保證 labels 不互相污染。

---

# 17. Prometheus Scrape Config

Target compiler 必須依據 profiles 自動建立 scrape jobs。

例如：

```yaml
profiles:
  storage-exporter:
    jobName: storage
    scheme: https
    metricsPath: /metrics
```

Prometheus：

```yaml
- job_name: storage
  scheme: https
  metrics_path: /metrics
  file_sd_configs:
    - files:
        - /etc/prometheus/targets/storage.json
```

---

# 18. Job Grouping

多個 profile 可以：

```yaml
jobName: storage
```

但第一版建議要求：

> `jobName` 必須在 profiles 中唯一。

否則：

```text
profile-a:
  jobName: storage
  scheme: http

profile-b:
  jobName: storage
  scheme: https
```

會產生語意衝突。

Validator 必須拒絕此情況。

---

# 19. Docker Volume

現有 Prometheus container 必須增加 read-only bind mount：

```text
/etc/pilot/prometheus/targets
    ->
/etc/prometheus/targets
```

Docker 內：

```text
/etc/prometheus/targets/*.json
```

Prometheus `file_sd_configs` 使用 container path。

Host path / container path 必須分開定義，避免重複目前 password file path 類似問題。

建議變數：

```yaml
prometheus_targets_host_dir: /etc/pilot/prometheus/targets
prometheus_targets_container_dir: /etc/prometheus/targets
```

---

# 20. Config Render 順序

最終：

```yaml
scrape_configs:

  # existing advanced/manual block
  {{ prometheus_scrape_configs }}

  # existing Pilot managed node exporters
  {{ prometheus_node_exporter_scrape_block }}

  # new external monitoring profiles
  {{ prometheus_external_scrape_block }}
```

不得改變既有：

```text
prometheus_scrape_configs
node_exporter
```

行為。

---

# 21. `prometheus_scrape_configs` 定位

保留：

```yaml
prometheus_scrape_configs
```

但文件必須明確標示：

```text
Advanced escape hatch
```

正常 external exporter 不再推薦使用它。

推薦順序：

```text
Pilot managed node exporter
        ↓
host-monitoring

External exporter
        ↓
monitoring/targets.yml

特殊 Prometheus 功能
        ↓
prometheus_scrape_configs
```

---

# 22. Target Generation Ownership

> 本節已依 `playbooks/apply/prometheus-apply.yml` 現況修正。原稿假設 apply
> playbook 有一道「render 到暫存 → `promtool check config` → 驗證通過才裝上
> 正式路徑/才 restart」的既有機制可以沿用；現況調查後確認**這個機制不存在**。
> 現有檔案裡每個 artifact（`prometheus.yml`、`alert-rules.yml`、
> `objstore.yml`、node-exporter password file）都是直接 `ansible.builtin.copy`
> 到最終路徑、`register:` 記 `changed`，再把這些 `changed` 旗標併成單一布林值
> 餵給 `pilot-prometheus` container 的 `restart:` 判斷式（見該檔第 482-485
> 行）；失敗處理是檔案級的 `rescue:`（只刪掉含密碼的 `objstore.yml`、把原始
> 錯誤 fail 出來，容器保留原狀供 `docker logs` 除錯），不是整份 config 的
> 原子安裝或 rollback。因此 external target 這個功能必須套用**同一種**現有
> 模式，而不是引入一套只有這個功能才有的驗證關卡。

Prometheus apply 時：

1. `pilot monitoring validate`（純 Go、離線、見 §32）必須先跑過且 PASS，
   涵蓋 schema、`profile` 是否存在、`jobName` 是否唯一/保留字、`address`
   格式、`authRef`/TLS 參照等所有靜態正確性——這些原本就是 registry 檔案
   自身的屬性，不需要啟動 Prometheus 或呼叫 `promtool` 就能驗證完畢。
2. Ansible apply 只做「渲染 + 交給既有 restart/health-check 機制把關」：
   1. 讀取 target registry + profiles（已通過步驟 1，不重新驗證）。
   2. 在記憶體中編譯成每個 `jobName` 一份 file_sd JSON。
   3. 用 `ansible.builtin.copy`（`dest=.../targets/<jobName>.json`）逐檔
      寫到最終路徑並各自 `register` 一個 changed 旗標——`copy` 模組本身
      已對單一檔案做「寫暫存檔 → rename」，§23 要求的 atomic update 不需要
      再另外實作。
   4. 若某個 `jobName` 已不再有任何 target（profile 被刪除或全部
      target 移除），用 `ansible.builtin.file: state=absent` 清掉對應舊
      JSON（§49 的 GC），同樣各自 `register`。
   5. 依 §20 的順序，把 external scrape block 併進既有 render
      `prometheus.yml` 那兩個任務（有/無 alertmanager 各一份，第 316/339
      行）的 `scrape_configs:`，接在 `prometheus_node_exporter_scrape_block`
      之後。
   6. 把步驟 3-5 新增的所有 changed 旗標，併入現有
      `prometheus_yml_result is changed or alert_rules_result is changed or
      node_exporter_password_file_result is changed`（第 482-485 行）這個
      既有的單一 restart 判斷式，而不是另建一套獨立的 restart 邏輯。
   7. 沿用既有「Wait for Prometheus to become ready」（`/-/ready`，
      retries 30、delay 2，第 514-521 行）當作這次改動唯一的 runtime 把關：
      任何步驟 1 沒抓到的錯誤（例如 compiler 本身有 bug），要嘛在這裡讓
      Prometheus 進程真的啟動失敗、apply 直接 fail，要嘛應該更早在 §71
      的 golden test 被抓到——這條 wait 迴圈不是為本功能新增的，是既有
      "有沒有把 Prometheus 弄壞" 的唯一訊號來源，本功能沿用它。
   8. `rescue:` 延用現有模式（第 557-569 行）：只多一步——若這次 apply
      有渲染 `monitoring_auth` 對應的 password file，一併刪除（跟現有刪除
      `objstore.yml` 的理由相同：含密碼的檔案不留在失敗現場），然後照舊
      `fail` 出原始錯誤、容器維持原狀。**不**嘗試回滾已寫入的 file_sd
      JSON 或 `prometheus.yml` 內容——現有 rescue 本來就不做這件事，本功能
      沒有理由自己發明一套更強的保證。

3. **刻意不引入 apply-time 的 `promtool check config` 前置關卡。**
   全 repo 目前唯一使用 `promtool` 的地方是
   `docs/verification/prometheus.md` 的 C10（`promtool check rules`），而
   且是**套用後、唯讀**的驗證 row（`docker exec pilot-prometheus promtool
   check rules ...`），不是 apply playbook 裡的前置 gate。若要對
   `prometheus.yml` 的語法正確性有同等保證，應該比照 C10 的姿勢新增一條
   **套用後、唯讀**的驗證 row（見 §56 新增的 Cxx 建議：
   `docker exec pilot-prometheus promtool check config
   /etc/prometheus/prometheus.yml`），而不是在 playbook 裡插入一個目前
   repo 完全沒有先例的「渲染到暫存 → 跑 promtool → 決定要不要正式安裝」
   機制。若未來確實需要 apply-time hard fail（而非套用後才發現 config
   壞掉），那是一個獨立的新基礎設施項目（需要一次性容器或背景 exec 呼叫
   `promtool`、外加暫存路徑與正式路徑的切換邏輯），依 §80 的原則列為明確
   follow-up，不在本次範圍內實作。

不得：

```text
先覆蓋 production config
→ 再發現 invalid config
```

但「不得」的實際落地方式是：把所有能在 Go 端靜態驗證的錯誤在步驟 1 擋掉，
其餘交給既有 render-then-health-check-then-rescue 流程，而非假裝 repo 裡
存在一個尚未建置的 validate-before-restart 前置關卡。

---

# 23. Atomic Update

所有產生檔案應採：

```text
temporary file
→ validate
→ atomic rename
```

或等效 Ansible-safe 實作。

不得讓 Prometheus 在 target JSON 寫一半時讀到 malformed JSON。

---

# 24. Prometheus Reload

如果目前 Pilot Prometheus 使用 container restart 作為 config change mechanism，可先延用。

但 external `file_sd` target JSON 本身不應要求 restart。

Prometheus 原生會自動重新讀取 `file_sd`。

因此期望：

### profile 改變

例如：

```text
http → https
```

需要：

```text
render prometheus.yml
→ validate
→ reload/restart
```

### target add/remove

只有：

```text
targets/*.json
```

改變時：

```text
不應 restart Prometheus
```

除非現有 playbook 架構暫時無法避免。

第一版如果仍 restart，必須在 TODO / follow-up 明確標記優化。

---

# 25. CLI

新增：

```text
pilot monitoring
```

至少提供：

```text
pilot monitoring target list
pilot monitoring target add
pilot monitoring target edit
pilot monitoring target remove
pilot monitoring target enable
pilot monitoring target disable
pilot monitoring target test

pilot monitoring profile list
pilot monitoring profile add
pilot monitoring profile edit
pilot monitoring profile remove

pilot monitoring validate
```

---

# 26. `target list`

例如：

```bash
pilot monitoring target list
```

輸出：

```text
NAME        ADDRESS                         PROFILE           SITE      STATUS
nas01       nas01.pilot.internal:9633       storage-exporter  taipei    enabled
legacy01    10.20.30.40:9100                external-node     taipei    enabled
db01        db01.pilot.internal:9187        postgres          taipei    disabled
```

如可合理提供，可額外顯示：

```text
JOB
SCHEME
```

但不得讓 output 過度寬。

---

# 27. `target add`

例如：

```bash
pilot monitoring target add \
  --name nas01 \
  --address nas01.pilot.internal:9633 \
  --profile storage-exporter \
  --site taipei
```

支援 labels：

```bash
pilot monitoring target add \
  --name nas01 \
  --address nas01.pilot.internal:9633 \
  --profile storage-exporter \
  --label environment=prod \
  --label owner=storage
```

CLI 寫入：

```text
monitoring/targets.yml
```

必須保證：

* schema valid；
* target name 不重複；
* profile 存在；
* address valid。

---

# 28. `target remove`

例如：

```bash
pilot monitoring target remove nas01
```

必須：

1. 顯示要刪除 target。
2. interactive shell 下要求 confirmation。
3. automation / MCP structured action 應提供 explicit confirmation field 或相同 safety contract。
4. 只移除 target registry。
5. 不執行任何 remote host action。

---

# 29. `target test`

這是此功能的重要能力。

例如：

```bash
pilot monitoring target test nas01
```

測試 pipeline：

```text
Resolve target
      ↓
Resolve profile
      ↓
DNS resolution
      ↓
TCP connection
      ↓
TLS handshake（若 https）
      ↓
Authentication
      ↓
GET metricsPath
      ↓
HTTP status validation
      ↓
Prometheus/OpenMetrics payload validation
```

輸出例如：

```text
Target: nas01
Address: nas01.pilot.internal:9633
Profile: storage-exporter

[PASS] profile exists
[PASS] DNS nas01.pilot.internal -> 10.20.10.15
[PASS] TCP 10.20.10.15:9633
[PASS] TLS certificate
[PASS] GET /metrics -> 200
[PASS] metrics payload

Result: PASS
```

---

# 30. `target test` 安全限制

必須：

* 設 connect timeout；
* 設 HTTP timeout；
* 限制 response body 大小；
* 不 follow 任意跨 host redirect；
* 不印出 Authorization header；
* 不印 password/token；
* 不把 credential 放入 process argv；
* TLS error 必須完整報告但不可輸出 secret。

建議：

```text
connect timeout: 5s
request timeout: 10s
max response: 8 MiB
```

實際值可調整。

---

# 31. Metrics Validation

不要自行實作完整 Prometheus parser。

優先考慮：

```text
Prometheus 官方 parser library
```

若依賴不合理，第一版至少驗證：

* HTTP 2xx；
* response body 非空；
* Content-Type 為 Prometheus/OpenMetrics 常見格式；
* body 可被 Prometheus parser 解析。

避免只檢查：

```text
HTTP 200
```

因為這可能只是 HTML login page。

---

# 32. `pilot monitoring validate`

必須執行 pure local validation。

不得連 remote endpoint。

檢查：

```text
targets.yml schema
profiles.yml schema
duplicate target names
unknown profiles
duplicate jobName
invalid host:port
reserved labels
invalid scheme
invalid duration
unknown authRef
invalid TLS reference
```

---

# 33. Pilot Workspace Validate 整合

若 Pilot 已有全 workspace validation：

```text
pilot validate
```

或同等機制，必須把 monitoring validation 接進去。

因此：

```text
pilot validate
```

應能發現：

```text
external monitoring target references unknown profile
```

而不必等到 Prometheus apply。

---

# 34. TUI 整合

> 本節已依 `pilot edit` 現況修正。`pilot edit` 早已不是舊的
> promptui 巢狀迴圈架構——現行是單一長駐的 Bubble Tea
> `editRouterModel`（`cmd/pilot/cmd/edit_tui.go`），每個畫面用注入的
> `tui.Factory`（production 用 Huh v2，`tui.NewHuhFactory()`）產生
> `tui.SelectSpec` / `tui.InputSpec` / `tui.ConfirmSpec` /
> `tui.MultiSelectSpec`，畫面之間靠 `r.transitionTo(...)` 換頁、
> callback 決定下一步。原稿的樹狀選單只是概念，沒有對應到任何實際的
> API 呼叫方式；以下改成直接對應現有程式的做法。

在 `pushTopMenu`（`cmd/pilot/cmd/edit_tui.go`）的 `choices` slice 裡新增
一項（目前已有 9 項：hosts.yml、group_vars、vault、roster、
freeipa-dns、internal-endpoints、完整性檢查、快速建立、離開），並在同一
函式的 `switch m.Selected()` 補上對應 case，指到新檔案
`edit_tui_monitoring.go` 的入口函式。

新畫面群組的檔案結構、資料流、存檔慣例，直接照抄最近一個同類功能
`edit_tui_internal_endpoints.go`（internal-endpoints manifest 編輯器，
1279 行）已經驗證過的模式，而不是重新設計：

```text
pushMonitoringManifestPathPrompt(r, dir)
  — 問 monitoring/targets.yml 路徑（比照 pushInternalEndpointManifestPathPrompt）
      ↓
pushMonitoringManifestManager(r, dir, path, banner)
  — 檔案不存在 → 問要不要建立最小骨架（schemaVersion:1, targets:[]，
    比照 inventory.CreateMinimalInternalEndpointManifest 新增一個對應 helper）
  — 檔案存在 → 選單：Exporter Targets / Scrape Profiles / 返回
      ↓
pushMonitoringTargetsMenu(r, dir, path, banner)
  — 每個 target 的 name 是它在 registry 裡的主鍵，也是這一列的 Choice.ID
    （比照 pushInternalEndpointsMenu 用 fqdn 當 ID 的作法）
  — 加上「➕ 新增 target」「↩ 返回」
      ↓
pushMonitoringTargetDetail(r, dir, path, name, banner)
  — 逐欄位一列：address / profile / site / enabled / labels（共 N 個）
  — profile 欄位必須是 pushMonitoringTargetProfileSelect（tui.SelectSpec，
    列出 scrape-profiles.yml 現有 profile），不是 tui.InputSpec 自由輸入
    ——直接對應 §35 原本就要求的「不可讓使用者輸入 arbitrary profile
    string 而不驗證」
  — enabled 欄位用 tui.ConfirmSpec 或兩選項 tui.SelectSpec
  — labels 是巢狀 CRUD，比照 pushExtraVarsMenu（edit_tui.go）／
    pushFleetVarsMenu 現成的「key=value 清單 + 新增/編輯/刪除」模式，
    不需要另外發明
      ↓
pushMonitoringProfilesMenu / pushMonitoringProfileDetail
  — 結構同上，欄位為 §10 定義的 jobName/scheme/metricsPath/…
```

**每個新畫面都要有穩定、唯一的 `ScreenID`**（`tui.SelectSpec.ScreenID` /
`InputSpec.ScreenID` / `ConfirmSpec.ScreenID`），不可留空。理由不是風格
偏好，是既有程式碼自己註記的教訓（見 `edit_tui.go` 裡
`nfsRosterBootstrapPasswordScreenID` 的註解）：沒有穩定 ID，
`--actions` JSON scenario（automation driver）就無法對到這個畫面、
`pilot-trec-verification` 之類靠腳本驅動 TUI 的錄影驗收也會失敗。

**這代表 §77「預期至少涉及」清單漏了一項必要交付物**：每個既有功能都有
自己的 `cmd/pilot/cmd/edit_automation_driver_<feature>.go`（例如
`edit_automation_driver_internal_endpoint.go`），把 `--actions` scenario
的動作對應到上面這些 `ScreenID`；還有
`cmd/pilot/cmd/edit_automation_driver_screenid_test.go` 這類回歸測試，
專門檢查「TUI 用到的每個 `ScreenID` 都有 driver 支援」。本功能必須同時
新增 `edit_automation_driver_monitoring.go`（+ 對應 test），否則新畫面
群組上不了非互動路徑，且很可能直接讓既有的 screenid 覆蓋率測試 fail。

**存檔慣例**：比照 `edit_tui_internal_endpoints.go` 檔頭註解的作法——
每次寫入前先呼叫 `internal/inventory` 對應的 `Simulate{Add,Set}...`
做 dry-run 驗證，通過才呼叫 `Append/Set...` 真的寫檔（用 `yaml.Node`
局部改寫，不是整份 struct 重新 marshal）。§51「save 前必須重新
validate」「不因單一 field edit 大幅重排整份檔案」直接繼承這個既有機制，
不需要另外設計一套。

**回歸測試提醒**：`pushTopMenu` 的選單順序曾經因為插入新項目，讓既有
4 個依 index 導航的測試靜默壞掉（已修復，但這是真實發生過的坑，非假設
風險）。本功能改動 `pushTopMenu` 後必須跑全套 `go test`，不能只測
monitoring 相關的新測試。

---

# 35. TUI Target Editor

Target 表單：

```text
Name
Address
Profile
Site
Enabled
Labels
```

Profile 必須：

```text
select list
```

不可讓使用者輸入 arbitrary profile string 而不驗證。

---

# 36. TUI Profile Editor

欄位：

```text
Name
Job Name
Scheme
Metrics Path
Scrape Interval
Scrape Timeout
Auth Reference
TLS configuration
```

第一版若 TLS/Auth editor 複雜，可允許：

```text
CLI / YAML advanced configuration
```

但 load/save schema 必須完整支援。

---

# 37. Contract Model

Monitoring target 不得成為新的 inventory role，例如禁止：

```text
external-monitoring
external-host
monitoring-target
```

因為 inventory role 代表：

```text
Pilot 可以對 host 套用 component lifecycle
```

Monitoring target 是 reference/resource。

---

# 38. Prometheus Contract 修改

目前：

```text
contracts/prometheus.yaml
```

需要新增外部 monitoring 資料來源的描述。

但不要偽裝成 component dependency。

推薦新增 generic resource input，例如若 contract schema 可擴展：

```yaml
resourceInputs:
  - type: monitoringTargets
    source: monitoring/targets.yml
    required: false
```

若現有 contract schema 不適合，第一版可以只在 Prometheus component implementation 處理，並建立 follow-up contract schema。

禁止把它寫成：

```yaml
dependencies:
  - component: external-monitoring
```

因為 external target 不是 component。

---

# 39. Managed Node Exporter 與 External Target

既有：

```text
host-monitoring
    ↓
node_exporter_targets
```

必須保留。

最終 Prometheus target sources：

```text
Source A
Pilot managed host-monitoring

Source B
external monitoring target registry

Source C
advanced prometheus_scrape_configs
```

---

# 40. 重複 Endpoint 處理

可能發生：

```text
host-monitoring
    10.0.0.10:9100

external target
    10.0.0.10:9100
```

第一版應允許，因為：

* job 可以不同；
* profile 可以不同；
* authentication 可以不同。

但：

```text
pilot monitoring validate
```

應產生 warning：

```text
warning: endpoint 10.0.0.10:9100 is also managed by host-monitoring
```

不得直接 fail。

---

# 41. Target Label

External target 自動加：

```yaml
pilot_source: external
pilot_target: <target name>
```

Managed host-monitoring 建議也逐步補：

```yaml
pilot_source: managed
```

但如果這會造成 breaking change，可留待後續。

不得覆蓋 Prometheus built-in：

```text
job
instance
```

除非有明確設計。

---

# 42. DNS

Target `address` 可使用：

```text
IP
FQDN
```

例如：

```text
nas01.pilot.internal:9633
```

Pilot 不需要在 registry 展開 IP。

Prometheus 應直接使用 hostname，以允許 DNS address change。

`target test` 時可以顯示目前 DNS resolution。

---

# 43. IPv6

address parser 必須使用標準 Go `net.SplitHostPort` 或相同 semantics。

支援：

```text
[2001:db8::1]:9100
```

不得自行用：

```text
strings.Split(address, ":")
```

---

# 44. TLS

HTTPS profile：

```yaml
scheme: https
```

至少支援：

```yaml
tls:
  serverName: exporter.example.internal
  insecureSkipVerify: false
```

如果：

```yaml
insecureSkipVerify: true
```

`pilot monitoring validate` 必須顯示 security warning，但第一版可允許。

例如：

```text
warning: profile storage-exporter disables TLS certificate verification
```

---

# 45. CA Reference

若 Pilot 已有 FreeIPA CA / CA distribution model，profile 的：

```yaml
tls:
  caRef: pilot-root-ca
```

未來可整合。

第一版若無 generic CA registry，允許：

```text
caRef
```

只接受既有定義，或先不實作 `caRef` 實際解析。

不能把 arbitrary local path 作為預設 public schema，例如避免：

```yaml
caFile: ../../secret.pem
```

若第一版無法完整實作 `caRef`：

* schema 可以暫不加入；
* 不得留下半實作 credential path injection。

---

# 46. Authentication

至少考慮：

```text
none
basic
bearer
```

第一版最低要求：

```text
none
basic
```

Profile：

```yaml
authRef: external-node-auth
```

Secret registry：

```yaml
monitoring_auth:
  external-node-auth:
    type: basic
    username: prometheus
    password: ...
```

Prometheus config 應使用：

```yaml
basic_auth:
  username: prometheus
  password_file: ...
```

而非直接 render password。

---

# 47. Secret File

如果需要 password file：

```text
/etc/pilot/prometheus/secrets/
```

container：

```text
/etc/prometheus/secrets/
```

permission：

```text
0600
```

不得放在：

```text
targets/*.json
```

File SD JSON 必須完全不含 secret。

---

# 48. Generated File Ownership

推薦：

```text
/etc/pilot/prometheus/targets/*.json
```

owner/group 應符合 Prometheus container 能讀取的權限。

不可 world-writable。

---

# 49. Garbage Collection

若 profile 被刪除，例如原有：

```text
storage.json
```

新 configuration 不再包含 storage profile：

Pilot apply 必須移除舊：

```text
/etc/pilot/prometheus/targets/storage.json
```

否則會留下 stale generated files。

只允許刪除：

```text
Pilot-owned generated target files
```

不能：

```text
rm -rf /etc/pilot/prometheus/targets/*
```

除非整個 directory 已定義為 100% Pilot generated ownership。

推薦在檔案加入 generated manifest 或全 directory ownership。

---

# 50. Profile Remove Safety

執行：

```bash
pilot monitoring profile remove storage-exporter
```

如果仍有 target：

```yaml
profile: storage-exporter
```

必須拒絕。

例如：

```text
cannot remove profile "storage-exporter":
used by targets: nas01, nas02
```

不可 cascade delete。

---

# 51. Serialization

CLI/TUI 更新 YAML 時：

* 保持 deterministic ordering；
* 不因單一 field edit 大幅重排整份檔案；
* 不產生重複 keys；
* save 前必須重新 validate。

如果既有 Pilot 有 YAML persistence helper，優先重用。

---

# 52. Structured Actions / Agent Support

此功能必須設計成 Agent 不需要修改 raw YAML。

未來或本次直接提供 structured actions：

```text
monitoring.target.list
monitoring.target.get
monitoring.target.add
monitoring.target.update
monitoring.target.remove
monitoring.target.test

monitoring.profile.list
monitoring.profile.get
monitoring.profile.add
monitoring.profile.update
monitoring.profile.remove

monitoring.validate
```

---

# 53. Structured Action Safety

以下：

```text
list
get
validate
test
```

為 read-only。

以下：

```text
add
update
enable
disable
```

為 workspace mutation。

以下：

```text
remove
```

為 destructive workspace mutation。

必須套用 Pilot 現有 structured action confirmation / receipt / evidence 慣例。

不得因 external target 是「非 managed」就跳過 audit。

---

# 54. MCP / Agent 重要限制

Agent 不應：

```text
直接 edit prometheus.yml
直接修改 generated file_sd JSON
直接寫 /etc/pilot/prometheus/targets/*
```

Agent 應只改：

```text
monitoring/targets.yml
monitoring/scrape-profiles.yml
```

或使用 structured actions。

Generated artifacts 永遠由 Pilot compiler 產生。

---

# 55. Apply Workflow

> 已依 §22 的修正同步調整：拿掉 §22 原本假設、但現況不存在的
> 「暫存檔 + `promtool check config` 前置關卡」，改成
> `playbooks/apply/prometheus-apply.yml` 現有的「直接渲染到最終路徑
> → changed 旗標併入既有單一 restart 判斷式 → `/-/ready` 健康檢查 →
> `rescue:` 只清密碼檔並 fail-loud」模式。這不是把驗證拿掉，是把「language
> 驗證」（pure Go、apply 前）跟「有沒有把 Prometheus 弄壞」（既有
> health-check、apply 中）兩件事對應到 repo 已經在用的兩個不同機制，而不是
> 發明一個兩者都做、但目前不存在的第三種機制。

Prometheus apply 最終流程：

```text
Prepare
  ↓
`pilot monitoring validate`（純 Go、apply 前、離線）
— schema、profile 存在、jobName 唯一/非保留字、address 格式、
  authRef/TLS 參照 全部在這一步擋掉；未通過就不進入 Ansible apply
  ↓
Load workspace monitoring config（Ansible 讀取，不重新驗證）
  ↓
Compile profiles and targets（記憶體內）
  ↓
Render file_sd JSON 直接到 {{ prometheus_targets_host_dir }}/*.json
（ansible.builtin.copy，逐檔 register changed；copy 本身即
 write-temp-then-rename，不需要另外的暫存路徑步驟）
  ↓
移除不再有 target 的舊 file_sd JSON（ansible.builtin.file: state=absent，
GC，§49；同樣 register changed）
  ↓
把 external scrape block 併入既有 render prometheus.yml 任務
（§20 順序：prometheus_scrape_configs → prometheus_node_exporter_scrape_block
 → 新的 external block；一樣直接渲染到最終路徑，非暫存）
  ↓
把以上所有 changed 旗標併入既有的單一 restart 判斷式
（pilot-prometheus docker_container 任務的 restart: 條件）
  ↓
既有 Wait for Prometheus /-/ready 健康檢查
— 這是本功能唯一可用的 apply-time runtime 把關，取代原本設想的
  「apply 前 promtool」
  ↓
既有 rescue:（清掉 monitoring_auth 產生的 password file，理由同既有
  objstore.yml 清理；fail-loud，不 rollback 已寫入的 config 內容）
  ↓
Verify targets（`pilot verify` 的套用後、唯讀新增 checks，見 §56 C15-C18
  以及本節新增的 promtool-check-config row，同款姿勢比照既有 C10）
```

---

# 56. Runtime Verification

新增 verification checks。

例如：

## C15 — external scrape config

如果存在 external target：

```text
prometheus.yml
```

必須包含：

```text
file_sd_configs
```

---

## C16 — file_sd generated

例如：

```text
/etc/pilot/prometheus/targets/*.json
```

存在且合法 JSON。

---

## C17 — external target visible

Prometheus API：

```text
/api/v1/targets
```

必須可以找到：

```text
pilot_source="external"
```

至少一筆 target。

---

## C18 — enabled external target UP

若測試環境有已知 exporter：

```promql
up{pilot_source="external"} == 1
```

必須成功。

此 check 若 deployment 沒設定 external target，應：

```text
N/A
```

而非 fail。

---

## C-new — prometheus.yml 語法有效（promtool check config）

> 見 §22/§55 的修正：apply playbook 本身不跑 `promtool`；語法正確性改成
> 這裡——套用後、唯讀的驗證 row，姿勢完全比照
> `docs/verification/prometheus.md` 既有的 C10（`promtool check rules`）。
> 實際編號併入該文件時，由既有序號延伸決定，這裡先用 `C-new` 佔位，不假裝
> 已知道會排到第幾號。

```bash
docker exec pilot-prometheus promtool check config /etc/prometheus/prometheus.yml
```

exit code 必須為 0。這一條同時涵蓋 external scrape block 本身的語法正確性，
以及它跟既有 `prometheus_scrape_configs`/`prometheus_node_exporter_scrape_block`
組合後的整份 `prometheus.yml` 是否仍然合法——是本功能對「config 語法正確」
這件事唯一的把關點，取代原本設想、但不存在的 apply-time 前置關卡。

---

# 57. Validation Scope

Verification spec 必須明確區分：

### configuration correctness

```text
targets.yml valid
profile valid
file_sd generated
Prometheus config valid
```

### connectivity correctness

```text
target reachable
metrics response valid
Prometheus scrape UP
```

External target unavailable 不應造成：

```text
prometheus container apply impossible
```

除非 target 明確標示為 required，第一版不提供 required semantics。

---

# 58. Failure Semantics

若 external exporter unreachable：

Prometheus 本身仍應成功部署。

例如：

```text
nas01 DOWN
```

不得讓：

```text
pilot deploy prometheus
```

fail 在 config render 階段。

但：

```text
pilot monitoring target test nas01
```

必須 fail。

Prometheus runtime：

```text
up{pilot_target="nas01"} = 0
```

由 alerts 處理。

---

# 59. Optional Required Target

第一版不要加入：

```yaml
required: true
```

避免 deployment availability 與 third-party endpoint availability 綁死。

如果未來需要再另案設計。

---

# 60. Alert Rules

本次不自動建立 exporter-specific alert rules。

但應確保使用者可以寫：

```promql
up{
  pilot_source="external",
  pilot_target="nas01"
} == 0
```

未來可以新增 generic：

```text
ExternalTargetDown
```

但不是本規格必要項。

---

# 61. Default Generic External Target Alert

若本次實作成本低，可新增：

```yaml
- alert: ExternalTargetDown
  expr: up{pilot_source="external"} == 0
  for: 5m
```

但需注意：

* 不是所有 exporter 都是 critical；
* 第三方 maintenance 可能造成 alert noise。

因此建議本次 **不自動加入**。

---

# 62. File Naming

不要直接用 target name 作 file name。

應使用：

```text
jobName
```

並做安全 sanitize。

例如：

```text
postgres-exporter
```

→

```text
postgres-exporter.json
```

profile name 與 job name 不一致時，以 compiler internal deterministic mapping 為準。

---

# 63. Reserved Names

建議禁止 profile jobName：

```text
prometheus
node
```

因為目前：

```text
job="prometheus"
job="node"
```

已有既有語意。

除非明確允許 override。

第一版應直接 validator fail。

---

# 64. Compatibility

既有 workspace：

```text
沒有 monitoring/targets.yml
```

必須等效於：

```yaml
schemaVersion: 1
targets: []
```

既有：

```text
prometheus_scrape_configs
```

不得失效。

既有：

```text
host-monitoring
```

不得改變。

---

# 65. Migration

不需要 migration existing configuration。

如果使用者現在已在：

```yaml
prometheus_scrape_configs:
```

手動定義 external exporters：

Pilot 不自動轉換。

文件提供人工 migration guide：

```text
raw scrape job
    ↓
scrape profile
+
monitoring targets
```

---

# 66. Documentation

新增：

```text
docs/verification/prometheus-external-targets.md
```

或整合至：

```text
docs/verification/prometheus.md
```

建議獨立文件，Prometheus spec 再引用。

新增 runbook：

```text
docs/runbooks/prometheus-external-targets.md
```

內容至少包括：

1. architecture
2. add exporter
3. add profile
4. authentication
5. TLS
6. target test
7. Prometheus query
8. troubleshooting
9. migration from `prometheus_scrape_configs`

---

# 67. CLI Help

例如：

```bash
pilot monitoring target add --help
```

必須清楚說明：

> This registers a Prometheus scrape endpoint. It does not enroll or configure the remote host through Ansible.

避免使用者誤認 Pilot 會管理遠端設備。

---

# 68. Testing

至少新增以下 unit tests。

## Target parsing

* valid targets
* empty file
* missing file
* invalid schema version
* duplicate name
* invalid address
* IPv6
* missing profile

## Profile parsing

* valid profile
* invalid scheme
* duplicate job name
* invalid duration
* reserved job name

## Compiler

* one target
* multiple targets same profile
* multiple profiles
* labels
* site
* disabled target
* deterministic output

## file_sd

* JSON valid
* one entry per target
* reserved labels protected
* secret never rendered

---

# 69. CLI Tests

至少：

```text
target list
target add
target edit
target remove
target enable
target disable
profile add
profile remove
validate
```

並測試：

```text
profile still in use → remove rejected
```

---

# 70. Prometheus Regression Tests

修改既有：

```text
internal/spec/prometheus_regression_test.go
```

或新增適當 regression tests。

至少驗證：

1. node exporter 原行為仍存在。
2. self scrape 原行為仍存在。
3. custom `prometheus_scrape_configs` 仍存在。
4. external file_sd scrape block 正確。
5. target directory mount 正確。
6. empty external targets 不產生 invalid config。

---

# 71. Golden Test

建議建立 golden fixtures：

```text
testdata/monitoring/
├── basic/
├── multi-profile/
├── disabled/
├── tls/
└── invalid/
```

Compiler output 使用 golden test。

避免未來小改動無意間改變 Prometheus config。

---

# 72. Idempotency

同一份：

```text
targets.yml
scrape-profiles.yml
```

連續 apply：

第二次必須：

```text
changed=0
```

或符合 Pilot 現有 idempotency contract。

Generated JSON serialization 必須 deterministic，不能因 map iteration 順序每次改變。

---

# 73. Security Tests

至少驗證：

```text
password 不出現在 file_sd JSON
password 不出現在 prometheus.yml
password 不出現在 CLI logs
password 不出現在 target test output
```

若使用 password_file：

驗證：

```text
file permission
container mount
path correctness
```

---

# 74. Error Messages

錯誤必須帶 actionable context。

錯誤：

```text
unknown profile
```

應為：

```text
monitoring target "nas01" references unknown scrape profile
"storage-exporter"
```

錯誤：

```text
invalid address
```

應為：

```text
monitoring target "nas01":
address "nas01.pilot.internal" must include an explicit port
```

---

# 75. CLI Exit Code

以下必須 non-zero：

```text
pilot monitoring validate
pilot monitoring target test
```

發生 failure 時。

`target list` 即使 registry 為空仍 exit 0。

---

# 76. Empty State

```bash
pilot monitoring target list
```

沒有 targets 時：

```text
No external monitoring targets configured.
```

不要視為 error。

---

# 77. Repository Suggested Changes

> 已依 §34 的修正補上原本漏列的 automation driver 交付物——`pilot edit`
> 的每個既有功能都是「`edit_tui_<feature>.go`（畫面）+
> `edit_automation_driver_<feature>.go`（把 `--actions` JSON scenario 對應
> 到畫面的 `ScreenID`）+ 對應 test」三件一組（例如
> `edit_tui_internal_endpoints.go` +
> `edit_automation_driver_internal_endpoint.go` +
> `edit_automation_driver_internal_endpoint_test.go`）。只列 TUI 畫面、
> 漏掉 driver，這個功能就進不了 `--actions` 非互動路徑，且很可能讓既有的
> `edit_automation_driver_screenid_test.go`（檢查「TUI 用到的每個
> `ScreenID` 都有 driver 支援」）直接 fail。

預期至少涉及：

```text
internal/monitoring/
cmd/pilot/cmd/edit_tui_monitoring.go
cmd/pilot/cmd/edit_automation_driver_monitoring.go
cmd/pilot/cmd/edit_automation_driver_monitoring_test.go
cmd/pilot/cmd/                                            # 其餘：CLI 子命令、pushTopMenu 選單項目、MCP tool 註冊
playbooks/apply/prometheus-apply.yml
contracts/prometheus.yaml
docs/verification/
docs/runbooks/
internal/spec/
```

以及相關 TUI/MCP structured-action 程式碼——尤其是上面明列的 automation
driver 檔案，不得只完成 `edit_tui_monitoring.go` 就視為 TUI 整合已完成。

Coding agent 必須先搜尋 repository 現行：

```text
workspace loading
YAML editing
structured actions
TUI edit routing
contract parsing
secret handling
```

的既有 pattern，再決定實際 file placement。

禁止為本功能建立一套平行 framework。

---

# 78. 實作順序

## Phase 1 — Domain Model

完成：

```text
internal/monitoring
targets.yml
scrape-profiles.yml
validation
compiler
tests
```

完成條件：

```text
pure Go tests pass
```

---

## Phase 2 — Prometheus Integration

完成：

```text
file_sd JSON generation
scrape block generation
Docker volume
promtool validation
garbage collection
```

完成條件：

```text
external target 可出現在 Prometheus targets API
```

---

## Phase 3 — CLI

完成：

```text
list
add
edit
remove
enable
disable
test
validate
```

---

## Phase 4 — TUI

完成：

```text
Pilot edit Monitoring
Target editor
Profile editor
```

---

## Phase 5 — Agent / Structured Actions

完成：

```text
structured monitoring operations
audit/receipt
MCP exposure where appropriate
```

---

## Phase 6 — Verification / Documentation

完成：

```text
verification spec
runbook
regression tests
idempotency
```

---

# 79. Acceptance Criteria

整體功能必須符合以下條件。

## AC1

一台完全不存在於 Pilot `hosts.yml` 的 exporter：

```text
10.20.30.40:9100
```

可以被加入：

```text
monitoring/targets.yml
```

並由 Prometheus scrape。

---

## AC2

Pilot 不會嘗試 SSH/Ansible 到該 target。

---

## AC3

使用者不需要修改：

```text
prometheus_scrape_configs
```

即可新增 exporter。

---

## AC4

增加 target 不會覆蓋：

```text
Prometheus self scrape
Pilot managed node exporter
```

---

## AC5

`pilot monitoring target test` 可以獨立測試 exporter。

---

## AC6

Target 可使用：

```text
IPv4
IPv6
FQDN
```

---

## AC7

Target labels 正確出現在 Prometheus。

---

## AC8

Disabled target 不會出現在 Prometheus。

---

## AC9

不存在 profile 時 validation fail。

---

## AC10

刪除仍被 target 使用的 profile 必須被阻止。

---

## AC11

Secrets 不得出現在：

```text
targets.yml
file_sd JSON
prometheus.yml
logs
```

---

## AC12

既有沒有 monitoring config 的 workspace 行為完全不變。

---

## AC13

既有：

```text
host-monitoring -> node_exporter_targets
```

行為完全不變。

---

## AC14

既有：

```text
prometheus_scrape_configs
```

仍可使用。

---

## AC15

重複 apply 必須符合 Pilot idempotency requirement。

---

# 80. Completion Definition

Coding agent 不得只完成資料結構或 CLI。

功能完成必須同時包含：

```text
Schema
    +
Validation
    +
Compiler
    +
Prometheus integration
    +
CLI
    +
TUI
    +
Tests
    +
Verification
    +
Documentation
```

若 repository 目前某一層架構尚不足，例如 structured action contract 無 generic resource 支援：

不得用不合理 hack 強行塞進 existing component dependency。

應：

1. 保持 domain model 正確；
2. 完成本次可安全完成的 integration；
3. 建立明確 TODO / follow-up；
4. 在 implementation report 說明限制。

---

# 81. Coding Agent 執行要求

正式修改前，Coding Agent 必須先調查：

```text
internal/inventory
contracts/
prometheus contract
prometheus apply playbook
pilot edit TUI
structured actions
MCP edit tools
secret/vault implementation
verification specs
regression tests
```

不得只根據本規格推測 API。

如本規格中的建議 file path、type name、CLI routing 與 repository 現有 abstraction 衝突：

> 優先沿用 repository 現有 abstraction，但不得改變本規格定義的 domain boundary 與使用者行為。

尤其不得為了少改程式而把：

```text
Monitoring Target
```

重新包裝成：

```text
Inventory Host / Role
```

---

# 82. 最重要的不變量

實作完成後，以下敘述必須成立：

> **Pilot inventory 描述「Pilot 管理什麼主機」；Monitoring Target Registry 描述「Prometheus 要監控什麼 endpoint」。**

以及：

> **Prometheus target discovery 不得依賴 Ansible lifecycle。**

以及：

> **Agent 新增 external exporter 時，不需要也不應直接修改 arbitrary Prometheus YAML。**

這三項為本改版最主要的架構約束。

