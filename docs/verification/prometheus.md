# Verification Spec — prometheus (per-site Prometheus + Thanos Sidecar)

> 版本：v1.16
> 對齊規範：pilot 通用 container-backed 服務規範（比照 `seaweedfs-s3.md`/
> `keycloak.md` 的 docker container 模式）
> 維護者：sre
> 2026-09-21 C16–C19（dcgm-exporter 自動 GPU scrape）已在真實 vm-target 上
> 完整驗證（fresh apply、認證後成功 scrape、真實 GPU 指標、冪等重跑），
> 證據見 `docs/evidence/prometheus/2026-09-21-79172c6.md`；過程中發現並修好
> 兩個真實 bug（見該檔 §5）。
> 2026-10-12 C20（container 讀到的 `prometheus.yml` 與主機檔案相同）已在
> 真實 vm-target 上驗證：先用修正前的程式重現「設定變更後 container 沒重啟、
> 仍讀舊 inode、`/-/reload` 無效」，再確認修正後重跑 apply 會重啟並載入新設定、
> 冪等重跑 `changed=0`，證據見 `docs/evidence/prometheus/2026-10-12-c12c4a8.md`；
> 檢查改成 `no_log` 後在 `1c24223` 重跑（fresh host、舊 inode 自癒、設定變更
> 重啟，`-vvv` 不再印出掛載檔的 hash），證據見
> `docs/evidence/prometheus/2026-10-12-1c24223.md`。
> 2026-10-12 C21/C22（Sidecar 能寫 TSDB 目錄、這一站的 block 真的進了 bucket）
> 已在真實 vm-target 上驗證：先用修正前的程式重現 `/prometheus:ro` 讓每次上傳
> 都失敗，再確認全新安裝與升級兩條路徑都上傳成功、冪等重跑 `changed=0`，證據見
> `docs/evidence/thanos-long-term-retention/2026-10-12-0c2a8e2.md`。
> 2026-10-12 PR #39 review 後的 C8/C22（只讀 `global.external_labels.site`）
> 在有 `kind: snmp` profile 的真實 vm-target 上重驗：同一個狀態下舊 C22 被
> Thanos 以 `unquote label value` 拒絕、新 C22 PASS，證據見
> `docs/evidence/thanos-long-term-retention/2026-10-12-1660889.md`。

> 跟 `thanos-query.md` 是一對「站台 / 中央」關係——本檔是**每個機房/站台**
> 各自跑一份的角色（`prometheus` group，類比 `wazuh-fim`），`thanos-query.md`
> 是**中央**彙總查詢角色（類比 `wazuh-manager`/`log-server`）。跟既有的
> 「agent 端填一個 central_host 變數」模式不同：這裡是**反向關係**——本角色
> 完全不需要知道中央在哪裡（Thanos Sidecar 只被動等中央的 Thanos Query 來
> 連），站台可以在中央還沒部署前就先獨立運作、獨立寫入/查詢本機資料。

## 1. 目標系統

| Hostname   | Group        | Address | User | Port | IdentityFile |
|------------|--------------|---------|------|------|--------------|
| site-a     | prometheus   |         |      |      |              |
| site-b     | prometheus   |         |      |      |              |

> `prometheus` group 是本檔預設目標。同一個 group 底下可以有多台主機，各自
> 代表不同機房/站台——`prometheus_site_label`（見 §1.5）就是用來讓
> `thanos-query.md` 的全局查詢分得出資料來自哪一站。

## 1.5 依賴變數契約

在套用或驗證此主機時，Playbook 與變數參數必須嚴格遵守以下命名，禁止擅自縮寫或發明新變數：

| 變數名稱 | 說明/用途 | 是否必填 | 預設值 |
|---------|----------|---------|--------|
| `prometheus_site_label` | 這個站台的識別名稱，以 JSON 字串（雙引號）寫進 Prometheus `global.external_labels.site`；`thanos-query.md` 的全局查詢靠這個欄位分辨資料來源站台 | 是 | 無（空字串會被 gate 擋下） |
| `thanos_s3_target_host` | 備份目的地 SeaweedFS S3 gateway（或其他 S3 endpoint）的 IP/FQDN；套用時 pin 進 `/etc/hosts` 的 `thanos_s3_alias` 別名 | 否（見下方 escape hatch） | 空字串 |
| `thanos_s3_alias` | 上面那個 IP 對應的 `/etc/hosts` 別名，Thanos objstore 設定一律指向這個別名 | 否 | `thanos-s3-backend` |
| `thanos_s3_port` | S3 gateway port | 否 | `8333` |
| `thanos_s3_bucket` | 存放 metrics TSDB blocks 的 bucket 名稱；**必須跟 `thanos-query.md` 那台用同一個值**，否則中央讀不到這一站上傳的資料 | 否 | `pilot-thanos-metrics` |
| `thanos_s3_endpoint` | 完整覆寫 S3 endpoint（`host:port`），跳過 `thanos_s3_alias` 的 `/etc/hosts` pin，改指向外部/獨立 S3 | 否 | `"{{ thanos_s3_alias }}:{{ thanos_s3_port }}"` |
| `thanos_aws_access_key_id` | S3 access key；一律用 vault 帶入，不進版控（拋棄式沙盒測試除外） | 是 | 無 |
| `thanos_aws_secret_access_key` | S3 secret key | 是 | 無 |
| `prometheus_scrape_interval` | 全域 scrape 間隔。host-health 規則啟用時必須是單一 Prometheus duration（例如 `15s`，不接受 `1m30s`），且 `login_probe_stale_seconds` ≥ 3 × 此值，playbook 會擋 | 否 | `15s` |
| `prometheus_retention_time` | 本機 TSDB 保留時間。長期保存在 S3（保留期限由 `thanos-query.md` 的 Compactor 決定），本機這份只是 Thanos Sidecar 的上傳緩衝：S3 中斷超過這個時間，中斷期間的資料就會遺失 | 否 | `24h` |
| `prometheus_scrape_configs` | 完整覆寫 `scrape_configs:` 區塊內容（多行字串，可依主機覆寫成不同的 scrape job） | 否 | 只 scrape 自己（`localhost:9090`） |
| `alertmanager_target_host` | 中央 Alertmanager 主機的 IP/FQDN；套用時 pin 進 `/etc/hosts` 的 `alertmanager_alias` 別名，並把 `alerting.alertmanagers` 區塊寫進 `prometheus.yml` | 否（見下方 escape hatch） | 空字串 |
| `alertmanager_alias` | 上面那個 IP 對應的 `/etc/hosts` 別名；`prometheus.yml` 的 `alerting.alertmanagers` 指向這個固定別名 | 否 | `alertmanager-backend` |
| `alertmanager_port` | Alertmanager API port | 否 | `9093` |
| `prometheus_alert_rules_file` | 站台 alert rules YAML 檔案路徑（相對於 `playbooks/apply/`）；檔案內容**不會**經過 Jinja 處理，所以 Prometheus 的 `{{ $labels.X }}` template 語法會原封不動保留。覆寫方式：`-e prometheus_alert_rules_file=host_vars/mysite-alerts.yml` | 否 | `files/pilot-alert-rules-seed.yml`（Watchdog canary + PrometheusDown + HostDown；另有 SSH session recording 的 `PilotRecordingIncomplete`、`PilotSessionStoreIngestErrors`、`PilotRecordingDeniedConnects`、`PilotSessionStoreMetricsStale`，只在 gateway/store 主機的 node_exporter textfile 有對應 series 時才可能觸發） |
| `node_exporter_targets` | 要 scrape 的 node_exporter target 清單（`host:port` 字串陣列）；留空時自動展開這份 inventory 的 `host-monitoring` group（見 `docs/verification/host-monitoring.md`）所有主機的 9100 port | 否 | 空陣列（自動偵測） |
| `node_exporter_basic_auth_user` | 抓 node_exporter 用的 HTTP Basic Auth 使用者名稱（非機密） | 否 | `prometheus` |
| `node_exporter_basic_auth_password` | 抓 node_exporter 用的 HTTP Basic Auth 密碼；**必須跟 `host-monitoring.md` 的 `node_exporter_basic_auth_password` 用同一個值**，否則會被 401 擋下，`up{job="node"}` 永遠是 0（見下方 escape hatch） | 僅在有 node-exporter target 時必填 | 無 |
| `dcgm_exporter_targets` | 要 scrape 的 dcgm-exporter target 清單（`host:port` 字串陣列）；留空時自動展開這份 inventory 的 `dcgm-exporter` group（見 `docs/verification/dcgm-exporter.md`）所有主機的 9400 port | 否 | 空陣列（自動偵測） |
| `dcgm_exporter_basic_auth_user` | 抓 dcgm-exporter 用的 HTTP Basic Auth 使用者名稱（非機密） | 否 | `prometheus` |
| `dcgm_exporter_basic_auth_password` | 抓 dcgm-exporter 用的 HTTP Basic Auth 密碼；**必須跟 `dcgm-exporter.md` 的 `dcgm_exporter_basic_auth_password` 用同一個值**，否則會被 401 擋下，`up{job="dcgm"}` 永遠是 0（見下方 escape hatch）；跟 `node_exporter_basic_auth_password` 是獨立的一組，不需要相同 | 僅在有 dcgm-exporter target 時必填 | 無 |
| `prometheus_host_health_alert_rules_enabled` | 是否渲染並載入 `host-health-alert-rules.yml`（GitHub issue #11 的確定性主機 I/O / 監控缺口 / login probe 告警，`playbooks/apply/templates/pilot-host-health-alert-rules.yml.j2`）；`false` 時檔案被移除、`rule_files` 不再引用 | 否 | `true` |
| `host_io_stall_ratio_threshold` | `HostIOStall`：PSI `io full` stall 比例（5 分鐘 rate，0–1）超過此值 | 否 | `0.25` |
| `host_io_stall_for` | `HostIOStall` 的 `for:` | 否 | `10m` |
| `host_disk_latency_seconds_threshold` | `HostDiskLatencyHigh`：每次 block I/O 平均完成時間（秒，與 detection-engine `linux-host-v1` 的 `disk_io_latency_seconds` 同一段 PromQL / device filter）超過此值 | 否 | `0.1` |
| `host_disk_latency_min_ops_per_second` | `HostDiskLatencyHigh` 只看每秒完成 I/O 數高於此值的裝置（避免極少量 I/O 的單次慢操作誤報） | 否 | `1` |
| `host_disk_queue_depth_threshold` | `HostDiskQueueDeep`：平均 in-flight request 數超過此值 | 否 | `10` |
| `host_disk_latency_for` | `HostDiskLatencyHigh` / `HostDiskQueueDeep` 的 `for:` | 否 | `10m` |
| `host_metrics_missing_for` | `HostMetricsMissing`（`up{job="node"}==0`，但這台主機在 `host_metrics_missing_success_window` 內有一次成功登入＝監控資料缺口，與 `HostDown` 分開）的 `for:`。最多 9m（seed `HostDown` 是 10m，兩個 rule group 的評估時間點最多差 1m；playbook 會擋），它才能在 Alertmanager 抑制同主機的 `HostDown{job="node"}`（`alertmanager.md` §1.7） | 否 | `3m` |
| `host_metrics_missing_success_window` | `HostMetricsMissing` 只採信 target 自己的 last-success 時間戳在這段時間內有變化（`changes()`）。playbook 會擋：時間窗 + 15s（probe 的 textfile 寫出間隔）不得超過 `host_metrics_missing_for`（否則掛掉的主機可能觸發它），且每台 login-probe 主機的 `login_probe_interval` + `login_probe_total_timeout` + 15s + 2 × `prometheus_scrape_interval` 必須嚴格小於時間窗（否則資料缺口期間會中斷；`prometheus-apply.yml` 與 `login-probe-apply.yml` 都檢查，`alertmanager.md` §1.7）；至少涵蓋兩次 scrape。時間參數必須寫在 inventory，修改後套用兩個角色，不可只用一次 apply 的 `-e` 覆寫（runbook §6） | 否 | `150s` |
| `login_probe_alert_for` | `PilotLoginProbeAccountDenied`/`AuthFailed`/`LoginStalled`/`HostKeyMismatch`/`SessionFailed` 的 `for:`（probe 預設 60 秒一輪，3m ≈ 連續 3 輪） | 否 | `3m` |
| `login_probe_transport_alert_for` | `PilotLoginProbeTransportFailed` 的 `for:`（規則本身排除 `up{job="node"}==0` 的主機：整台掛掉的主機只產生 `HostDown`） | 否 | `5m` |
| `login_probe_alert_keep_firing_for` | 所有 login-probe 告警與 `HostMetricsMissing` 的 `keep_firing_for:`，避免單輪恢復（或 probe 單輪失敗、重啟）造成 resolve/re-fire 抖動。啟用 host-health 規則時最多 5m，playbook 會擋；它也決定資料缺口變成主機掛掉後，`HostDown` 還被抑制多久（預設約 8m，見 `alertmanager.md` §1.7） | 否 | `5m` |
| `login_probe_stale_seconds` | `PilotLoginProbeStale`：probe textfile 的寫入時間戳在此秒數內沒有變化（`changes()`，不依賴探測主機時鐘；daemon 每 15 秒寫一次）。必須 ≥ 3 × `prometheus_scrape_interval`（playbook 會擋），否則健康的 probe 會被當成停擺 | 否 | `180` |

> **為何 `prometheus_site_label` 是必填、跟 `wazuh_manager_host` 不一樣**：
> `wazuh_manager_host`/`siem_forward_host` 空著時還有「純本機」意義（本機
> FIM/稽核規則照常生效，只是不轉送）；`prometheus_site_label` 空著卻沒有
> 合理預設——外部標籤本來就是「每一站不同」的值，寫死一個預設（例如
> `"default"`）會讓多站真的部署下去時，第二站忘記覆寫就悄悄跟第一站標籤
> 撞名、Thanos Query 端會把兩站資料錯誤地當成同一個 replica 去重疊，而不是
> 顯式失敗。所以直接 gate 擋下，強迫每次套用都要想清楚這一站的名字。
>
> **為何 `thanos_s3_bucket` 沒有 gate 檢查兩邊是否一致**：spec 的驗證範圍
> 只到「這台主機自己能不能讀寫這個 bucket」（C9）；「central 是否真的用
> 同一個 bucket」屬於部署時的人工契約（跟兩份 group_vars 檔案要填同一個
> 值一樣），會在 `thanos-query.md` C9/C10（發現 StoreAPI + 全局查詢帶
> site label）間接曝露出來——如果兩邊 bucket 不同，中央的 Store Gateway
> 永遠讀不到這一站上傳的歷史資料。
>
> **為何 `alertmanager_target_host` 是 escape hatch 而非必填**：本專案
> 的 alerting 採用「站台 Prometheus 自己 eval rules → push 到中央
> Alertmanager」的分層，跟 `dashboard.md` 的 `thanos_query_target_host`
> 是同一種模式——每站 Prometheus 必須知道中央 Alertmanager 在哪裡才能
> 把 firing 的告警推過去。`alertmanager_target_host` 留空（`alertmanager.md`
> 還沒部署、或刻意只做本機規則評估不外送）時，apply playbook 不會加
> `alerting.alertmanagers` 區塊，Prometheus 仍會在內部評估 rules（C10
> 跟 C12 仍然 pass），但告警推不出去——C11 會如預期 fail，記在 §5
> 例外。這跟「先上 Prometheus、後上 Alertmanager」逐步部署的順序相容，
> 不會因為「Alertmanager 還沒準備好」就把站台 Prometheus 套用 block 起來。
>
> **Thanos Sidecar 以 Prometheus 的 uid（65534）執行、`/prometheus` 可寫**：
> Sidecar 上傳 block 前，會先在 TSDB 目錄裡建立 `thanos/upload/<ulid>`
> 暫存目錄，上傳成功後寫入 `thanos.shipper.json`，所以它需要對
> `/prometheus` 的**寫入**權限，不是唯讀。資料目錄屬於 Prometheus 的
> `65534:65534`、權限 `0755`，而 `thanosio/thanos` image 預設以 uid 1001
> 執行，所以 Sidecar 必須用 `user: 65534:65534` 跑。只拿掉 `:ro` 不夠：
> 2026-10-12 在本機用同一組 image 實測，`:ro` 時上傳失敗並記錄
> `create upload dir: mkdir /prometheus/thanos: read-only file system`，
> 只拿掉 `:ro` 時改成 Permission denied，兩者都是 `thanos_shipper_uploads_total 0`；
> 加上 `user: 65534:65534` 後才真的上傳。上傳失敗時
> `thanos_shipper_upload_failures_total` 仍然是 0（那個錯誤走的是另一條路徑），
> 所以 C21/C22 直接檢查寫入權限與 bucket 裡的 block，不看這個 counter。
>
> **`node_exporter_targets` 自動偵測、`node_exporter_basic_auth_*` 有條件必填**：
> 跟 `alertmanager_target_host` 同一種「留空退化、不 block 套用」精神，但
> 方向相反——這裡預設會**主動**從 inventory 的 `host-monitoring` group 展開
> 所有主機（見 `host-monitoring.md`），不需要手動逐台填 IP；只有明確要
> override 成別的清單時才需要帶 `node_exporter_targets`。`node_exporter`
> 強制要求 HTTP Basic Auth（見 `host-monitoring.md` §1.5 的理由），所以只要
> 展開出來的 target 清單非空，apply playbook 就會在任何 mutation 前 gate
> 檢查 `node_exporter_basic_auth_user`/`password` 是否都有值——這跟
> `restic_s3_target_host`「沒有目的地就直接 fail」是同一種「escape hatch
> 只擋『用不到』的情況，用得到就不准漏填」設計。這組密碼**必須**跟
> `host-monitoring.md` 那邊用同一個值，操作者責任，跟 `thanos_s3_bucket`
> 兩邊要填同一個值是同一種契約。
>
> **`dcgm_exporter_targets` 自動偵測、`dcgm_exporter_basic_auth_*` 有條件必填**：
> 跟 `node_exporter_targets` 完全同一種模式——自動從 inventory 的
> `dcgm-exporter` group 展開所有主機（見 `dcgm-exporter.md`），只有明確要
> override 成別的清單時才需要帶 `dcgm_exporter_targets`；只要展開出來的
> target 清單非空，apply playbook 就會在任何 mutation 前 gate 檢查
> `dcgm_exporter_basic_auth_user`/`password` 是否都有值，這組密碼**必須**跟
> `dcgm-exporter.md` 那邊用同一個值。跟 node-exporter 的密碼是完全獨立的
> 一組（不需要相同、不會互相 fallback）。「自動偵測」採 declarative
> desired-state 語意：被指派 `dcgm-exporter` role 的主機就是應被 scrape 的
> 主機，不是在套用時臨時掃 port——`dcgm-exporter` group 可以混編沒有 GPU
> 的候選主機，這些主機的 target 會長期呈現 `up=0`（不是 bug，見 §5）；
> 若不希望 scrape 這些候選主機，用 `dcgm_exporter_targets` explicit override
> 縮小清單，不要指望本 spec 用瞬時 port probe 隱藏它們。由 Kubernetes GPU
> Operator（或其他機制）自行管理 `:9400` 的主機，只有在它也遵守相同 Basic
> Auth contract 時才適合掛進這個自動 job；否則應改走
> `docs/verification/prometheus-external-targets.md` 的 external monitoring
> profile，避免誤用共用密碼。

## 2. Checklist

C23/C24 的 tagged apply 必須讓執行中的 Prometheus 載入目前的規則與啟用狀態。除了檔案語法，驗收還須比較 API 中的實際 threshold、停用後規則消失、重新啟用，以及磁碟已更新但記憶體仍舊時的重試；未變更 render 的重跑仍須完成一次成功 reload，PLAY RECAP 保持 changed=0。

| ID  | Category      | Check                                                     | Expected | Command |
|-----|---------------|------------------------------------------------------------|----------|---------|
| C1  | docker        | `pilot-prometheus` container 存在且 running                  | ~pilot-prometheus | docker ps --no-trunc 2>/dev/null | grep -m1 -oE 'pilot-prometheus' | head -n1 |
| C2  | docker        | `pilot-thanos-sidecar` container 存在且 running               | ~pilot-thanos-sidecar | docker ps --no-trunc 2>/dev/null | grep -m1 -oE 'pilot-thanos-sidecar' | head -n1 |
| C3  | http          | Prometheus `/-/healthy`（9090）回 200                        | ~200 | curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:9090/-/healthy |
| C4  | http          | Prometheus `/-/ready`（9090）回 200                          | ~200 | curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:9090/-/ready |
| C5  | http          | Thanos Sidecar `/-/healthy`（10902）回 200                   | ~200 | curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:10902/-/healthy |
| C6  | http          | Thanos Sidecar `/-/ready`（10902）回 200                     | ~200 | curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:10902/-/ready |
| C7  | metrics       | Prometheus 自我 scrape 成功（`up{job="prometheus"}==1`）       | ~"1"] | curl -fsS 'http://127.0.0.1:9090/api/v1/query?query=up' | grep -o '"value":\[[0-9.]*,"1"\]' |
| C8  | config        | `prometheus.yml` 的 `global.external_labels.site` 是非空、加了雙引號的字串（不是 scrape job 裡的 `site` label） | 0 | sh -c 'site=$(awk "/^global:/{g=1;next} /^[^[:space:]]/{g=0} g&&/^  external_labels:/{e=1;next} g&&/^  [^[:space:]]/{e=0} g&&e&&/^    site:/{sub(/^    site:[[:space:]]*/,\"\");print;exit}" /etc/pilot/prometheus/prometheus.yml); case $site in \"?*\") ;; *) exit 1;; esac' |
| C9  | object-storage | Thanos Sidecar 可讀取 object storage bucket（`thanos tools bucket ls`） | 0 | sh -c 'docker exec pilot-thanos-sidecar thanos tools bucket ls --objstore.config-file=/etc/thanos/objstore.yml >/dev/null 2>&1' |
| C10 | config        | `alert-rules.yml` 存在且語法有效（`promtool check rules`）       | 0 | sh -c 'docker exec pilot-prometheus promtool check rules /etc/prometheus/alert-rules.yml >/dev/null 2>&1' |
| C11 | config        | `prometheus.yml` 含 `alerting.alertmanagers` 區塊（僅在 `alertmanager_target_host` 有設時 render） | 0 | sh -c 'grep -qE "^[[:space:]]*alerting:" /etc/pilot/prometheus/prometheus.yml' |
| C12 | http          | Prometheus 已載入 rules（`/api/v1/rules` 回含 `"name":` 的 group/rules 列表） | 0 | sh -c 'curl -fsS http://127.0.0.1:9090/api/v1/rules | grep -q "\"name\":"' |
| C13 | config        | `prometheus.yml` 含自動探索到的 node-exporter scrape job（僅在 inventory 有 `host-monitoring` 主機、或明確帶 `node_exporter_targets` 時 render） | 0 | sh -c 'grep -qE "^[[:space:]]*job_name:[[:space:]]*node$" /etc/pilot/prometheus/prometheus.yml' |
| C14 | metrics       | 至少一個 node-exporter target 被成功（認證通過）scrape（`up{job="node"}==1`；僅在有 node-exporter target 時適用） | ~"1"] | curl -fsS 'http://127.0.0.1:9090/api/v1/query?query=up%7Bjob%3D%22node%22%7D' | grep -o '"value":\[[0-9.]*,"1"\]' |
| C15 | config        | `prometheus.yml` 的 node-exporter scrape job 帶 `pilot_host` label（僅在 auto-discovery 情境下 render；明確帶 `node_exporter_targets` override 時沒有此 label，見 §5） | 0 | awk '/^- /{if (sec ~ /job_name: node/ && sec ~ /pilot_host:/) f=1; sec=$0 ORS; next} {sec=sec $0 ORS} END{if (sec ~ /job_name: node/ && sec ~ /pilot_host:/) f=1; print (f?0:1)}' /etc/pilot/prometheus/prometheus.yml |
| C16 | config        | `prometheus.yml` 含自動探索到的 dcgm-exporter scrape job（僅在 inventory 有 `dcgm-exporter` 主機、或明確帶 `dcgm_exporter_targets` 時 render） | 0 | sh -c 'grep -qE "^[[:space:]]*job_name:[[:space:]]*dcgm$" /etc/pilot/prometheus/prometheus.yml' |
| C17 | metrics       | 至少一個 dcgm-exporter target 被成功（認證通過）scrape（`up{job="dcgm"}==1`；僅在有 dcgm-exporter target 時適用） | ~"1"] | curl -fsS 'http://127.0.0.1:9090/api/v1/query?query=up%7Bjob%3D%22dcgm%22%7D' | grep -o '"value":\[[0-9.]*,"1"\]' |
| C18 | config        | `prometheus.yml` 的 dcgm-exporter scrape job 帶 `pilot_host` label（僅在 auto-discovery 情境下 render；明確帶 `dcgm_exporter_targets` override 時沒有此 label，見 §5） | 0 | awk '/^- /{if (sec ~ /job_name: dcgm/ && sec ~ /pilot_host:/) f=1; sec=$0 ORS; next} {sec=sec $0 ORS} END{if (sec ~ /job_name: dcgm/ && sec ~ /pilot_host:/) f=1; print (f?0:1)}' /etc/pilot/prometheus/prometheus.yml |
| C19 | metrics       | 收到真正的 GPU 硬體指標，不只是 exporter 自身存活（`DCGM_FI_DEV_GPU_UTIL{job="dcgm"}` 至少一筆 sample；僅在有 dcgm-exporter target 時適用） | present | curl -fsS 'http://127.0.0.1:9090/api/v1/query?query=DCGM_FI_DEV_GPU_UTIL%7Bjob%3D%22dcgm%22%7D' | grep -o '"metric"' |
| C20 | config        | 執行中的 `pilot-prometheus` 讀到的 `prometheus.yml` 與主機上的檔案內容相同（不是 bind mount 留下的舊檔） | 0 | sh -c 'h=$(sha256sum < /etc/pilot/prometheus/prometheus.yml) && c=$(docker exec pilot-prometheus cat /etc/prometheus/prometheus.yml | sha256sum) && [ "$h" = "$c" ]' |
| C21 | object-storage | Thanos Sidecar 以自己的執行身分能在 `/prometheus` 建立目錄（上傳前要建 `thanos/upload/<ulid>`） | 0 | docker exec pilot-thanos-sidecar sh -c 'd=/prometheus/.pilot-write-probe.$$ && mkdir "$d" && rmdir "$d"' |
| C22 | object-storage | object storage 裡有這一站（`global.external_labels.site`）6 小時內的 block（Sidecar 真的在上傳，不只是讀得到 bucket） | 0 | sh -c 'site=$(awk "/^global:/{g=1;next} /^[^[:space:]]/{g=0} g&&/^  external_labels:/{e=1;next} g&&/^  [^[:space:]]/{e=0} g&&e&&/^    site:/{sub(/^    site:[[:space:]]*/,\"\");print;exit}" /etc/pilot/prometheus/prometheus.yml); case $site in \"?*\") ;; *) exit 1;; esac; since=$(date -u -d "-6 hours" +%Y-%m-%dT%H:%M:%SZ); docker exec pilot-thanos-sidecar thanos tools bucket inspect --objstore.config-file=/etc/thanos/objstore.yml --output=tsv --selector="site=$site" 2>/dev/null | awk -F "\t" -v since="$since" "NR>1 && \$3 >= since {f=1} END {exit !f}"' |
| C23 | config        | `host-health-alert-rules.yml`（issue #11：I/O stall、磁碟延遲、監控資料缺口、login probe 告警，門檻由 §1.5 變數渲染）存在且語法有效（`promtool check rules`）；`prometheus_host_health_alert_rules_enabled=false` 時檔案不存在且 `prometheus.yml` 不引用它也算通過 | 0 | sh -c 'if [ -f /etc/pilot/prometheus/host-health-alert-rules.yml ]; then docker exec pilot-prometheus promtool check rules /etc/prometheus/host-health-alert-rules.yml >/dev/null 2>&1; elif grep -q host-health-alert-rules /etc/pilot/prometheus/prometheus.yml; then exit 1; fi' |
| C24 | http          | Prometheus 已載入 host-health 與 login probe 規則（`/api/v1/rules` 含 `HostIOStall`、`HostDiskLatencyHigh`、`HostMetricsMissing`、`PilotLoginProbeAccountDenied`、`PilotLoginProbeStale`）；停用時同 C23 判斷 | 0 | sh -c 'if [ ! -f /etc/pilot/prometheus/host-health-alert-rules.yml ]; then exit 0; fi; r=$(curl -fsS http://127.0.0.1:9090/api/v1/rules) || exit 1; for n in HostIOStall HostDiskLatencyHigh HostMetricsMissing PilotLoginProbeAccountDenied PilotLoginProbeStale; do case "$r" in *"\"name\":\"$n\""*) ;; *) exit 1;; esac; done' |

> C7 只驗證「Prometheus 有沒有成功 scrape 到至少一個 target」，不綁定
> 特定 job 名稱字面值以外的東西——`up` 查詢不加 label matcher，因為
> `prometheus_scrape_configs` 允許逐站覆寫成不同 job，這條 row 要對任何
> 覆寫都成立。
> C9 直接呼叫 sidecar container 內建的 `thanos` binary 做一次 bucket
> list，不靠等 2 小時 TSDB block 真的上傳（Thanos 預設 `--tsdb.path` 的
> block 上傳週期跟 `--storage.tsdb.min-block-duration` 掛鉤，等一個真實
> block 週期才能驗證「有沒有真的上傳過東西」不切實際）——這條只驗證
> 「object storage 這一段的連線/認證是通的」，「有沒有真的搬過資料」交給
> `thanos-query.md` C10（全局查詢帶 site label）間接證明。
> C14 的 URL 對 `{`/`}` 做了 percent-encoding（`%7B`/`%7D`）——curl 會把未
> 轉義的 `{...}` 當成自己的 URL globbing 語法解析，直接對這個 endpoint 測
> 過，不轉義會是 `400`（curl 端錯誤，連 Prometheus 都沒真的收到請求）。
> C14 同時是「認證有正確設定」的間接證明：`node_exporter_basic_auth_*`
> 帶錯的話，Prometheus 端的 scrape 會被 401 擋下，`up{job="node"}` 永遠是
> 0，C14 fail——這條檢查的是**認證後**能不能拿到真資料，不是只確認
> 「連線通不通」。
> C13 刻意**不**錨定 `^-\s*job_name:`（曾經這樣寫過，實測在真的 vm-target
> 上失敗）：apply playbook 用 `to_nice_yaml` 把 scrape job 的 dict 序列化，
> 該 filter 預設會把 key 依字母序排列，所以真實輸出是 `- basic_auth:` 開頭、
> `job_name: node` 變成清單項目裡的第二行（不是第一行）。只錨 `^\s*job_name:`
> 對 key 順序無感，兩種排法都抓得到。
> C15 驗證的是 pilot Detection Engine 的 canonical subject identity 前提
> （見 `detection-engine` spec §9）：auto-discovery 從 `host-monitoring` group
> 展開時，每個 host 各自一個 `static_configs` 項目、帶
> `labels.pilot_host = <inventory_hostname>`；`node_exporter_targets` 明確
> override 時沒有這個 label（沒有 hostname 映射可用，見 §9.3），所以本行跟
> C13/C14 一樣需要 escape hatch，但條件更窄——即使 `host-monitoring` 有主機，
> 只要當次套用帶了 `node_exporter_targets` override，本行也預期 fail。
> C15 與 C18 的 Command 用 `awk` 把 `pilot_host:` 的比對限定在各自
> `job_name: node`/`job_name: dcgm` 那個 list item 的範圍內，而不是對整份
> `prometheus.yml` 做無範圍的 `grep pilot_host:`——2026-09-21 對 vm-target
> 實測發現：兩個 job 都會 render `pilot_host` label 時（node 沒有 target、
> dcgm 有 target 的情境），無範圍 grep 版本的 C15 會被 dcgm job 的
> `pilot_host` 行誤判成 PASS，即使 node-exporter 那段根本沒 render 出來。
> 已改成範圍限定版本，兩者互不干擾，實測對「只有其中一個 job 有 target」的
> 情境驗證過正確 PASS/FAIL。
> C16–C19 是 dcgm-exporter 的自動 GPU scrape 整合（見 `dcgm-exporter.md` §5），
> 跟 C13–C15 是同一套 escape hatch/驗證邏輯，只是 job 名稱換成 `dcgm`、
> port 換成 9400：
> C16 一樣刻意不錨 `^-\s*job_name:`（同 C13 的 `to_nice_yaml` key 字母序理由）。
> C17 一樣對 `{`/`}` 做 percent-encoding（同 C14 的 curl globbing 理由），且
> 同時是「`dcgm_exporter_basic_auth_*` 帶對了」的間接證明——帶錯會被 401
> 擋下，`up{job="dcgm"}` 永遠是 0。
> C18 跟 C15 一樣驗證 pilot Detection Engine 的 canonical subject identity
> 前提，auto-discovery 情境下每個 host 各自帶 `labels.pilot_host`；explicit
> override 沒有這個 label。
> C19 驗證的是「認證後真的抓到 GPU 硬體本身的指標」，不是只抓到
> dcgm-exporter process 自己還活著（那件事已經被 C17 的 `up==1` 間接證明）——
> `DCGM_FI_DEV_GPU_UTIL` 是 `dcgm-exporter.md` 故意排除在自己 spec 外的
> 端到端證明（見該檔 §2 C6/C9 註解），改由本行補上；只在有真實 GPU 的主機
> 才會有非零 series，`dcgm-exporter` group 混編非 GPU 候選主機時，那些主機
> 的 target 只會停在 `up=0`、抓不到任何 series，不影響本行判定（本行只要求
> group 裡「至少一筆」）。
> C20 驗證的是 container 實際讀到的設定，不是主機上的檔案：`prometheus.yml`
> 是單檔 bind mount，`copy` 用 rename 換掉檔案後主機路徑指向新的 inode，
> 沒有重啟的 container 仍然讀舊的那份，`/-/reload` 也只會重讀舊檔。C8/C11/
> C13/C16 都只 grep 主機上的檔案，container 讀舊檔時它們照樣 PASS。
> 2026-10-12 正式環境就是這個狀態：新的 dcgm-exporter target 已寫進主機的
> `prometheus.yml`，container 仍在用幾週前的版本。本行在 container 不存在或
> `docker exec` 失敗時也會 fail（空輸出的 hash 跟主機檔案對不上）。

> C8 與 C22 只讀 `global:` → `external_labels:` → `site:` 這一行（`awk` 依縮排
> 限定範圍），不是整份檔案裡的 `site:`：設了 `kind: snmp` profile 時，
> snmp-exporter 的 scrape job 也有 `labels.site`，2026-10-12 PR #39 review 在
> vm-target 上重現舊版 C22 把兩個值串成 `review-site\nreview-site`，
> `thanos tools bucket inspect --selector` 解析失敗，C22 永遠 FAIL；舊版 C8 在
> 沒有 external_labels 時也會被這一行騙成 PASS。playbook 以 `to_json` 渲染
> site，這個雙引號字串就是 Thanos `--selector` 要的格式（Thanos 用 Go
> `strconv.Unquote` 解析），C22 原樣傳入，不再自己加引號。
> `internal/spec/prometheus_site_selector_behavior_test.go` 用 vm-target 上 SNMP
> profile 渲染出的 `prometheus.yml` 實際跑這兩行。

## 3. 證據收集

- 工具：`pilot verify docs/verification/prometheus.md -i <inventory> -l prometheus`
- 輸出格式：`.verification/prometheus-<UTC>.{ndjson,md}`
- 預期 row 數：24
- 最新 actual-run evidence：login-probe topology 的 candidate run（有 seaweedfs-s3、Alertmanager 與
  login probe），candidate、run ID 與 row 結果見 `docs/runbooks/login-probe.md` §0.5，目前有效的
  evidence record 由那裡連結。這裡刻意不寫 candidate 與 run ID：evidence-only commit 不改 spec，
  提交 evidence 之後 manifest 裡 spec 的 hash 仍然相符。
- 歷史 Sanitized 摘要：`docs/evidence/thanos-long-term-retention/2026-10-12-1660889.md`
  （2026-10-12，candidate `f4d4db9` 全新安裝、`1660889` 升級，tree 見該檔；真實
  vm-target，站台設了 `kind: snmp` profile，有 seaweedfs-s3 與中央 thanos-query；
  兩個 candidate 都 `pass=14 fail=8`，C8/C21/C22 PASS，C11/C13–C19 因該次
  topology 沒有 Alertmanager/host-monitoring/dcgm-exporter 而預期 fail；同一狀態下
  `c52884e` 的 C22 FAIL）。C21/C22 修正前的重現與升級路徑見
  `docs/evidence/thanos-long-term-retention/2026-10-12-0c2a8e2.md`。
  C20 的證據見 `docs/evidence/prometheus/2026-10-12-1c24223.md`（舊 inode 自癒、
  設定變更與 `--tags C8` 重啟、`-vvv` 不印掛載檔 hash；修正前的重現見
  `docs/evidence/prometheus/2026-10-12-c12c4a8.md` §2），C16–C19 的 GPU scrape
  證據見 `docs/evidence/prometheus/2026-09-21-79172c6.md`

## 4. PASS / FAIL 規則

- C1–C24 全部 `status=pass` → **PASS**：這一站的 Prometheus + Thanos Sidecar 已就緒，本機監控、上傳鏈路（C21/C22 證明 block 真的進了 object storage）、alerting 評估鏈路、node-exporter/dcgm-exporter scrape 鏈路、pilot_host canonical identity 與 host-health/login-probe 規則都通
- 任一 fail → **FAIL**，常見修法：
  - C1/C2 fail → container 沒起；`docker ps -a` / `docker logs pilot-prometheus` / `docker logs pilot-thanos-sidecar`
  - C3/C4 fail → Prometheus 還沒 ready 或設定檔有誤；`docker logs pilot-prometheus`
  - C5/C6 fail → Sidecar 連不到 Prometheus（`--prometheus.url` 錯）或連不到 object storage；`docker logs pilot-thanos-sidecar`
  - C7 fail → scrape 設定有誤或 target 打不到；檢查 `prometheus_scrape_configs`
  - C8 fail → `prometheus_site_label` 沒有渲染進 `global.external_labels.site`，或不是加了雙引號的字串（舊版 playbook 渲染的設定檔，重跑 apply）
  - C9 fail → S3 憑證/bucket 有誤，或 bucket 尚未預先建立（見 §5）
  - C10 fail → `prometheus_alert_rules` 語法有誤；`docker exec pilot-prometheus cat /etc/prometheus/alert-rules.yml` 看內容
  - C11 fail → 預期 fail 見 §5（Alertmanager 尚未部署）；若非預期則檢查 `alertmanager_target_host` 是否帶入
  - C12 fail → Prometheus 還沒完成 rules reload；`docker logs pilot-prometheus | grep -i rule`
  - C13/C14 fail → 預期 fail 見 §5（inventory 沒有 `host-monitoring` 主機）；若非預期，C13 fail 檢查
    `groups['host-monitoring']` 是否真的有機器，C14 fail（但 C13 pass）通常是
    `node_exporter_basic_auth_user`/`password` 跟 `host-monitoring.md` 那邊不一致
    （401）——`docker logs pilot-prometheus | grep -i node` 看 scrape 錯誤訊息
  - C15 fail → 預期 fail 見 §5（inventory 沒有 `host-monitoring` 主機，或本次套用帶了 `node_exporter_targets` override）；若非預期，檢查 `prometheus-apply.yml` 的 auto-discovery 迴圈是否真的走到（`groups['host-monitoring']` 非空且未 override）
  - C16/C17 fail → 預期 fail 見 §5（inventory 沒有 `dcgm-exporter` 主機）；若非預期，C16 fail 檢查
    `groups['dcgm-exporter']` 是否真的有機器，C17 fail（但 C16 pass）通常是
    `dcgm_exporter_basic_auth_user`/`password` 跟 `dcgm-exporter.md` 那邊不一致
    （401），或該主機沒有真實 GPU（`dcgm-exporter.md` C1–C9 本身就 fail，見該檔 §5）
    ——`docker logs pilot-prometheus | grep -i dcgm` 看 scrape 錯誤訊息
  - C18 fail → 預期 fail 見 §5（inventory 沒有 `dcgm-exporter` 主機，或本次套用帶了 `dcgm_exporter_targets` override）；若非預期，檢查 auto-discovery 迴圈是否真的走到（`groups['dcgm-exporter']` 非空且未 override）
  - C19 fail（但 C17 pass）→ 該 target 是真的容器活著但沒有真實 GPU 裝置傳進去；檢查 `dcgm-exporter.md` C6（GPU 裝置真的傳進容器）是否 pass
  - C21 fail → Sidecar 不能寫 `/prometheus`：`docker inspect pilot-thanos-sidecar` 看 volume 是否還是 `:ro`、`User` 是否為 `65534:65534`；`docker logs pilot-thanos-sidecar | grep upload` 會看到 `mkdir /prometheus/thanos` 失敗
  - C22 fail（C21 pass）→ 全新主機第一個 block 要等大約 3 小時才會產生（見 §5）；超過這個時間仍 fail，`docker logs pilot-thanos-sidecar | grep -i upload` 看上傳錯誤，並檢查 C9（S3 憑證/bucket）
  - C20 fail → container 還在讀舊的 `prometheus.yml`（`stat -c %i` 主機檔案跟 `docker exec pilot-prometheus stat -c %i /etc/prometheus/prometheus.yml` 不同）；重跑 apply 會偵測到並重啟 container，`/-/reload` 無效

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C9 | SeaweedFS 不會自動生出不存在的 bucket，套用前需手動 `weed shell` 建好 `thanos_s3_bucket`（跟 `restic-backup.md` §5 Bug 5 同一個坑），否則本行 fail 且 sidecar log 會顯示 retry | SeaweedFS 目的地 | 無（預建 bucket 是常態操作） |
| C22 | Prometheus 要等 head 涵蓋約 3 小時才會切出第一個 2h block，Sidecar 才有東西上傳；全新主機套用後大約 3 小時內本行預期 fail。沒有 S3 目的地（C9 fail）時本行也會 fail | 剛套用的全新主機、沒有 S3 的環境 | 套用後約 3 小時 |
| C11 | `alertmanager_target_host` 未填或中央 Alertmanager 尚未套用完成時，本行預期 fail（apply playbook 不會 render `alerting.alertmanagers` 區塊） | Alertmanager 尚未部署的環境 | 直到 `alertmanager.md` PASS 為止 |
| C13, C14 | inventory 沒有 `host-monitoring` group 主機、且未明確帶 `node_exporter_targets` 時，這兩行預期 fail（apply playbook 不會 render node-exporter scrape job） | 尚未部署 `host-monitoring` 的環境 | 直到至少一台 `host-monitoring.md` PASS 為止 |
| C15 | 同上，或本次套用明確帶了 `node_exporter_targets` override（該情況下 C13/C14 仍可能 PASS，但 C15 預期 fail——explicit override 沒有 inventory hostname 映射，見 §9.3） | 尚未部署 `host-monitoring` 的環境，或使用 `node_exporter_targets` override 的環境 | 直到 auto-discovery 情境下至少一台 `host-monitoring.md` PASS 為止 |
| C16, C17 | inventory 沒有 `dcgm-exporter` group 主機、且未明確帶 `dcgm_exporter_targets` 時，這兩行預期 fail（apply playbook 不會 render dcgm-exporter scrape job）；`dcgm-exporter` group 若混編沒有真實 GPU 的候選主機，那些主機的 target 會長期呈現 `up=0`，這也是預期行為（desired-state 語意，不做瞬時 port probe 排除，見 §1.5） | 尚未部署 `dcgm-exporter` 的環境，或 `dcgm-exporter` group 混編非 GPU 候選主機 | 無（後者是常態設計，不會解除；前者直到至少一台 `dcgm-exporter.md` PASS 為止） |
| C18 | 同 C16/C17，或本次套用明確帶了 `dcgm_exporter_targets` override（該情況下 C16/C17 仍可能 PASS，但 C18 預期 fail——explicit override 沒有 inventory hostname 映射） | 尚未部署 `dcgm-exporter` 的環境，或使用 `dcgm_exporter_targets` override 的環境 | 直到 auto-discovery 情境下至少一台 `dcgm-exporter.md` PASS 為止 |
| C19 | 同 C16/C17 的前提；另外即使 C17 PASS（exporter process 活著、認證通過），若該主機實際沒有 GPU 裝置傳進容器（`dcgm-exporter.md` C6 fail 的情境），本行預期 fail——`up==1` 不保證有真實 GPU series | 尚未部署 `dcgm-exporter` 的環境，或 exporter 容器沒有真實 GPU 裝置的環境 | 直到至少一台真實 GPU 主機的 `dcgm-exporter.md` C1–C9 全數 PASS 為止 |

## 6. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-06 | v1.0 | 初版 | sre |
| 2026-07-07 | v1.1 | 新增 C10–C12：seed alert rules + alerting.alertmanagers 區塊（escape hatch 跟 `alertmanager_target_host` 連動） | sre |
| 2026-08-10 | v1.2 | 新增 C13–C14：自動從 inventory 的 `host-monitoring` group 展開 node-exporter scrape target（`node_exporter_targets`，escape hatch 跟 `alertmanager_target_host` 同一種模式），並對認證後成功 scrape 做端到端驗證（node_exporter 強制 Basic Auth，見 `host-monitoring.md` v1.1） | sre |
| 2026-08-28 | v1.3 | 新增 C15：Detection Engine Stage A-0（見 `docs/superpowers/specs/2026-08-28-detection-engine-spec.md` §9）需要 canonical `pilot_host` producer——auto-discovery 從 `host-monitoring` group 展開時，每個 host 改成各自一個 `static_configs` 項目並帶 `labels.pilot_host = inventory_hostname`；`node_exporter_targets` explicit override 行為不變（無 label） | sre |
| 2026-09-21 | v1.4 | 新增 C16–C19：自動從 inventory 的 `dcgm-exporter` group 展開 GPU metrics scrape target（`dcgm_exporter_targets`，跟 `node_exporter_targets`/C13–C15 同一套 auto-discovery/escape-hatch/`pilot_host` label 模式，固定 job 名稱 `dcgm`、port 9400），並對認證後成功 scrape 到真實 GPU 硬體指標（`DCGM_FI_DEV_GPU_UTIL`，不只是 exporter 存活）做端到端驗證；補上 `dcgm-exporter.md` §5 原先列為已知留白的 Prometheus 整合。對 disposable vm-target（假 dcgm-exporter fixture）實跑 apply + `pilot verify` 全通過（C9/C11/C13/C14 因該次測試環境沒有 seaweedfs-s3/alertmanager/host-monitoring 而預期 fail，C1–C8/C10/C12/C15–C19 全 PASS）；同時修正 C15 的 Command——舊版對整份 `prometheus.yml` 做無範圍 `grep pilot_host:`，實測發現 dcgm job 有 target、node job 沒有 target時會被 dcgm 那行 label 誤判成 PASS，已改成 `awk` 範圍限定到各自 `job_name:` 區塊，C18 新增時直接採用限定版寫法 | pilot |
| 2026-10-12 | v1.5 | 新增 C20：執行中的 container 讀到的 `prometheus.yml` 必須與主機檔案相同。正式環境的 dcgm-exporter target 已寫進主機檔案卻一直沒被 scrape：apply playbook 用 `combine()` 合併兩個互斥的 prometheus.yml render 結果，有 Alertmanager 時被跳過的那個帶著 `changed: false` 蓋掉另一個的 `changed: true`，container 從未因設定變更重啟，單檔 bind mount 一直指向舊 inode。playbook 改成分別檢查兩個結果，並在 container task 前比對 container 實際看到的單檔 bind mount（`tasks/container-file-mount-drift.yml`），內容不同就重啟，已經卡住的部署重跑 apply 即可恢復 | pilot |
| 2026-10-12 | v1.6 | 新增 C21/C22，`prometheus_retention_time` 預設由 `6h` 改為 `24h`。正式環境的 Thanos Sidecar 從來沒有上傳成功：`/prometheus` 以 `:ro` 掛載，上傳前建立 `thanos/upload` 目錄失敗，Store Gateway 載入 0 個 block，歷史資料只剩本機 6 小時。只拿掉 `:ro` 仍會因 uid 不同被拒（本機實測），所以 Sidecar 改以 `65534:65534` 執行並可寫入。C9 只檢查讀得到 bucket，抓不到這個問題；C21 檢查 Sidecar 的實際寫入權限，C22 檢查 bucket 裡有這一站 6 小時內的 block。本地緩衝改為 24 小時，S3 中斷不超過一天不會掉資料；長期保留期限見 `thanos-query.md` v1.3 | pilot |
| 2026-10-12 | v1.7 | C8/C22 只讀 `global.external_labels.site`，`prometheus.yml` 的 site 改以 JSON 字串渲染。PR #39 review 在 vm-target 上發現：設了 `kind: snmp` profile 時 snmp-exporter job 的 `site` label 也被抓進 C22 的 selector，Thanos 拒絕解析，C22 永遠 FAIL；同一個寫法讓 C8 在沒有 external_labels 時仍然 PASS。新增 `prometheus_site_selector_behavior_test.go` 用 SNMP 渲染結果實際跑這兩行 | pilot |
| 2026-10-14 | v1.8 | 保留主線新增的 C20–C22（執行中 container 的設定掛載、Sidecar 寫入權限與實際上傳），將 issue #11 的 host-health rule file 驗收改編為 C23–C24；container traceability 同時覆蓋設定掛載漂移與載入的告警規則 | pilot |
| 2026-10-15 | v1.9 | PR #80 review（GitHub issue #11）：login-probe 告警都帶 `probe_host`，配合 `alertmanager.md` §1.7 的新 inhibit；`PilotLoginProbeTransportFailed` 排除 node scrape 也失敗的主機；`HostMetricsMissing` 只採信仍在寫 textfile 的 probe；`HostMetricsMissing` 與 `PilotLoginProbeStale` 加上 `action_required="true"`；`host_metrics_missing_for` 必須短於 10m。row 未變 | sre |
| 2026-10-15 | v1.10 | PR #80 第三輪 review：`HostMetricsMissing` 加 `keep_firing_for`（probe 單輪失敗或重啟時不中斷，否則被它抑制的 `HostDown` 會送出）；probe 新鮮度與 `PilotLoginProbeStale` 改用寫入時間戳的 `changes()`，不再依賴探測主機時鐘；標頭版本對齊變更紀錄。row 未變 | sre |
| 2026-10-15 | v1.11 | PR #80 第四輪 review：`prometheus-apply.yml` 新增兩道 gate——`login_probe_stale_seconds` ≥ 3 × `prometheus_scrape_interval`（`prometheus_scrape_interval` 必須是單一 duration），`host_metrics_missing_for` ≥ `login_probe_stale_seconds`；promtool 證明兩者各自防止的誤報。row 未變 | sre |
| 2026-10-15 | v1.12 | PR #80 第五輪 review：`prometheus_scrape_interval` 一列寫明單一 duration 與 3 倍的限制。row 未變 | sre |
| 2026-10-15 | v1.13 | PR #80 第六輪 review：新增 `host_metrics_missing_success_window`（預設 2m）；`HostMetricsMissing` 改看 target 自己的 last-success 時間戳，取代 `host_metrics_missing_for` ≥ `login_probe_stale_seconds` 的 gate。row 未變 | sre |
| 2026-10-16 | v1.14 | PR #80 第七輪 review：`host_metrics_missing_success_window` 預設改為 140s，兩道 gate 改為「時間窗 + 15s ≤ `host_metrics_missing_for`」與「probe 主機的 interval + total_timeout + 15s + 一次 scrape ≤ 時間窗」。row 未變 | sre |
| 2026-10-16 | v1.15 | PR #80 第八輪 review：`host_metrics_missing_success_window` 預設改為 150s，probe 間隔 gate 改為 interval + timeout + 15s + 2 × scrape，`login-probe-apply.yml` 也檢查；`host_metrics_missing_for` 上限改為 9m；§3 改為指向 runbook §0.5 | sre |
| 2026-10-20 | v1.16 | #123：probe-round bound 改為嚴格小於時間窗，keep_firing_for 上限 5m；時間參數必須持久化於 inventory。row 未變 | sre |
