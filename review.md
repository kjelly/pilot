# 原始問題

調查為何已在 `it-core` 指派 `snmp-exporter` 角色、以「全部部署」並設定
`--limit it-core` 後，SNMP exporter 與 Prometheus 的 SNMP scrape 設定仍未套用，
導致 `hq_forti_firewall` 沒有 SNMP 資料；並將完整事故調查寫入本報告。

# 報告內文

## 結論

本次不是 SNMP 設備回應失敗，也不是使用者沒有設定 `it-core`。實際的「全部部署」
run 已把主機範圍限制到 `it-core`（相依性使 `freeipa` 同時進入 scope），但 component
selection 與 Ansible tags **沒有包含 `prometheus` 或 `snmp-exporter`**。因此這兩個
role 沒有被 apply，受管主機上也沒有產生 exporter 設定、SNMP file_sd target 或
Prometheus SNMP scrape job。

這是 deploy/reconcile scope 的行為缺陷：全站／全部部署的 component 展開排除了 opt-in
component，即使該 component 已被明確指派給 `--limit` 所選主機。

## 影響

- `hq_forti_firewall` 沒有可觀察到的 Prometheus target 或 SNMP metrics。
- `/etc/pilot/snmp-exporter/` 未建立，故沒有 SNMP exporter 可用設定。
- Prometheus 的 target directory 只保留既有 `pve.json`，沒有 Forti/SNMP target。
- Pilot MCP 的 SNMP target 診斷無法執行，因 controller workspace 缺少 diagnostic
  query pack。

## 調查範圍與方法

所有環境事實均由下列唯讀方式取得：

1. Pilot MCP：監控 registry、Thanos PromQL、component/target diagnosis 與受管主機
   的安全唯讀 command。
2. `infra-deploy` 上的既有 `pilot-cli:latest`：使用下列等價的唯讀 bind mount 檢視
   正在使用的 controller workspace 與 history database。

   ```bash
   ssh -T ubuntu@infra-deploy docker run --rm \
     -v ./infra-config:/pilot/config:ro \
     -v ./infra-config/.pilot-data:/root/.local/share/pilot:ro \
     pilot-cli:latest ...
   ```

未執行 deploy、reconcile、寫入 vault 或對 SNMP UDP/161 的直接探測。

## 實際證據

### 1. Controller workspace 的 SNMP registry 部分正確，但支援檔案不完整

container 看到的 `/pilot/config/monitoring/` 僅有：

- `targets.yml`
- `scrape-profiles.yml`
- `snmp/catalog.yml`

缺少：

- `monitoring/snmp/generated/if_mib.yml`
- `monitoring/snmp/diagnostic-profiles/network-device-ifmib-v1.yaml`

registry 內容則確認 Forti target 已正確關聯到：

- `kind: snmp`
- `subjectKind: network_device`
- `diagnosticProfile: network-device-ifmib-v1`
- module `if_mib`
- SNMPv3 `authPriv`、SHA-256 與 AES256 profile
- target site `core`

`pilot monitoring validate --dir /pilot/config` 回傳 `OK`。這只代表 registry schema 與
cross-reference 可通過；它沒有驗證 catalog 所指向的 generator module 檔或 diagnostic
profile 檔真的存在，因此不能證明 exporter apply 可完成。

### 2. 最新「全部部署」run 實際 scope

history database 的最新成功 run：

| 欄位 | 實際值 |
|---|---|
| run 開始 | `2026-09-03T07:38:09Z` |
| run 完成 | `2026-09-03T07:42:17Z` |
| outcome | `success` |
| playbook | `playbooks/site.yml` |
| hosts | `freeipa`, `it-core` |
| primary component | `audit-log-forwarding` |
| `prometheus` tag selected | `false` |
| `snmp-exporter` tag selected | `false` |
| `prometheus` in selected components | `false` |
| `snmp-exporter` in selected components | `false` |

這證明 `--limit it-core` 的 host scope 有效；`freeipa` 是 deployment dependency
expansion 的結果。問題在 component/tag scope，而非 host limit。

同一時間附近的三筆失敗 run 也都是 `audit-log-forwarding` component，並非
Prometheus 或 SNMP exporter apply。

### 3. `it-core` 的生效狀態

Pilot MCP 對 `it-core` 的唯讀檢查得到：

| 項目 | 實際結果 |
|---|---|
| Prometheus readiness | HTTP 200 |
| `/etc/pilot/prometheus/prometheus.yml` mtime | `2026-09-03 03:23:47 UTC` |
| `/etc/pilot/prometheus/targets/` | 僅有 `pve.json` |
| `/etc/pilot/snmp-exporter/` | 目錄不存在 |
| `up{job=~".*snmp.*"}` | 空 vector |
| `up{pilot_target="hq_forti_firewall"}` | 空 vector |

Prometheus 可以服務 readiness endpoint，但最新部署沒有更新其設定，因此並未開始
scrape SNMP。

### 4. MCP SNMP target diagnosis 的限制

`pilot_diagnose_monitoring_target(target="hq_forti_firewall")` 在載入
`/pilot/config/monitoring/snmp/diagnostic-profiles/network-device-ifmib-v1.yaml`
時失敗，因為該檔案不存在。

這會阻止 MCP 執行固定 PromQL 診斷包；它不是 Prometheus scrape job 未生成的直接
原因，但同樣顯示 controller workspace 的 SNMP asset 不完整。

## 根因鏈

```text
it-core 已指派 snmp-exporter role
        │
        ├─ 全部部署正確限制到 it-core（並展開相依性 freeipa）
        │
        └─ component/tag 展開排除 opt-in 的 prometheus、snmp-exporter
                │
                ├─ snmp-exporter playbook 未執行
                │     └─ /etc/pilot/snmp-exporter/ 未建立
                │
                └─ Prometheus SNMP renderer 未套用
                      ├─ 無 hq_forti_firewall file_sd JSON
                      ├─ prometheus.yml 無 SNMP job
                      └─ Thanos 無 SNMP time series
```

## 相關但獨立的問題

先前 Prometheus deploy 曾在 pre-task 的 external monitoring scrape block 因
`monitoring_all_scrape_jobs` 未定義而停止。已在工作樹修正為：只要 final renderer
因 `always` tag 執行，所有外部監控解析、驗證與 job compiler prerequisite 也在相同
`always` scope 執行，並新增回歸測試。

此修正避免「renderer 執行、compiler 被 tags 跳過」的 undefined-variable 問題；但它
不會自行修正本事故的 component selection 缺陷，也不會把尚未部署的 exporter 安裝到
`it-core`。

## 不應下的結論

目前證據不足以判定：

- FortiGate 的 SNMPv3 帳密、SHA-256/AES256 相容性或 UDP/161 網路可達性是否有問題。
- `pilot-snmp-exporter` container 的現有 runtime 狀態；controller 的 Docker diagnostic
  存取受到 Docker socket permission 問題限制，而且 exporter 設定目錄已證實不存在。

必須先讓 exporter 與 Prometheus 的設定確實套用，才有意義進行設備層診斷。

## 修正建議與驗收條件

1. 修正 deployment component selection：當使用「全部部署」搭配 `--limit <host>` 時，
   應將該 scope 內主機**明確已指派**的 role 納入 component plan；不應因 component
   的 opt-in 標記而排除。未被任何 scope host 指派的 opt-in component 則維持不選取。
2. 補齊 workspace bootstrap/backfill：將 SNMP catalog 參照的 module 檔與 diagnostic
   profile 一起放入 `infra-config/monitoring/snmp/`，而非只保留 `catalog.yml`。
3. 使用含修正的 `pilot-cli` image 後，再執行 scope 為 `it-core` 的全量部署。
4. 驗收必須同時符合：
   - `/etc/pilot/snmp-exporter/auths.yml` 存在。
   - `/etc/pilot/prometheus/targets/` 出現 Forti 對應的 JSON。
   - `prometheus.yml` 含 SNMP job 與 snmp-exporter self-scrape。
   - `up{pilot_target="hq_forti_firewall"}` 與 `up{job="snmp-exporter"}` 有 time series。
   - MCP target diagnosis 可載入 `network-device-ifmib-v1` diagnostic profile。

## 報告限制

本報告記錄的是 2026-09-03 調查時的 controller workspace、history DB 與 `it-core`
生效狀態。它不包含 vault 值、SNMP credential 值、或任何非唯讀設備操作。
