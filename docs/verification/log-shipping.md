# Verification Spec — log-shipping (Promtail：log-server → dashboard Loki)

> 版本：v1.3
> 對齊規範：pilot 通用 container-backed 服務規範（比照 `audit-log-forwarding.md`
> 的「client 端疊一個轉送 agent、central 端固定變數」模式）
> 維護者：sre

> 這是疊在 `log-server.md`**之上**、不修改它本體的一個角色（見
> `log-server.md` 該檔自己留的伏筆："查詢/dashboard 需求可日後在此之上
> 疊 Promtail→Loki，不影響本 spec"）。目標 group 跟 `log-server.md` 相同
> （同一台主機、兩個角色疊加），把 `{{ siem_log_root }}`（預設
> `/var/log/siem`）底下已經落地的檔案 tail 起來，轉送進
> `dashboard.md` 那台主機的 Loki，讓 Grafana 可以查。跟既有的
> `audit-log-forwarding.md`（client 填 `-e central_host`）是同一種
> 「agent 端知道中央位址」慣例——跟 `thanos-query.md` 那組「中央自動探索
> 站台」的反向模式不同，這裡沒有反過來的理由：Promtail 本來就需要主動
> push，沒有「中央自動發現 log-server 有哪些」的對應機制。

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Hostname / Inventory group | log-server（跟 `log-server.md` 同一台，角色疊加） |
| OS / version | Ubuntu 24.04 LTS / EL9 |
| 角色 | Promtail docker container，tail 本機 `siem_log_root` 下的檔案並 push 到中央 Loki |
| 套用範圍 | `/etc/pilot/promtail/`、`/etc/hosts`（一行 alias pin） |
| 風險等級 | Low（唯讀 tail 既有日誌檔，不寫入來源系統；對外只有出站 HTTP push） |

## 1.5 依賴變數契約

在套用或驗證此主機時，Playbook 與變數參數必須嚴格遵守以下命名，禁止擅自縮寫或發明新變數：

| 變數名稱 | 說明/用途 | 是否必填 | 預設值 |
|---------|----------|---------|--------|
| `loki_target_host` | `dashboard.md` 中央主機的 IP/FQDN（Loki 所在地） | 否（見下方 escape hatch） | 空字串 |
| `loki_alias` | 上面那個 IP 對應的 `/etc/hosts` 別名 | 否 | `pilot-loki-backend` |
| `loki_port` | Loki push API port | 否 | `3100` |
| `loki_endpoint` | 完整覆寫 Loki push endpoint（`host:port`），跳過 `loki_alias` 的 `/etc/hosts` pin | 否 | `"{{ loki_alias }}:{{ loki_port }}"` |
| `siem_log_root` | 要 tail 的根目錄；**必須跟 `log-server.md` 用同一個值**，否則 tail 不到東西。**一律被 scrape**（`job=promtail_job_label`），不會被下面的 wazuh 偵測覆寫掉 | 否 | `/var/log/siem` |
| `promtail_job_label` | Promtail 幫 `siem_log_root` 這批日誌打的 `job` label 值，Loki 查詢用來篩選 | 否 | `pilot-siem` |
| `promtail_wazuh_job_label` | 同主機偵測到 wazuh-manager 容器時，額外（**加開一個 scrape job，不是取代**）幫它的 `alerts.log` 等檔案打的 `job` label 值 | 否 | `{{ promtail_job_label }}-wazuh-alerts` |

> `loki_target_host` 留空時套用不會 fail（跟 `dashboard.md` 的
> `thanos_query_target_host` 同一種「上游還沒接上」正常狀態），Promtail
> 會照樣起來、只是 push 目標打不通，C6（跨主機功能性驗證）會如預期
> fail——見 §5。
>
> `siem_log_root` 跟 `log-server.md` 共用同一組變數名稱、同一個值，
> 是刻意設計（比照 `thanos_s3_bucket` 同時給 `prometheus.md` 跟
> `thanos-query.md` 共用的理由）：避免兩邊各自維護一份路徑、只在跑到
> C6 那一刻才發現對不上。
>
> **v1.0 曾經讓同主機的 wazuh-manager 容器（真的 alerts-log volume，用
> `docker inspect` 動態解析）取代 `siem_log_root`，理由是「log-server 空、
> wazuh-manager 是實際上的 SIEM 接收端」——這個假設在真實站台被證明是錯的
> （見 `log-server.md` v1.1 的 incident 記錄：那台主機其實從沒有真正的
> 514/tcp 接收端，local6/auth/authpriv 全部石沉大海）。v1.1 修正為兩者並存：
> `siem_log_root` 一律 scrape（對齊 C3 的固定字串期待），wazuh 的 alerts-log
> 只在偵測到容器時額外加開第二個 job，兩條資料流各自獨立進 Loki，用
> `job` label 區分查詢。**
>
> **v1.2 補上 `host` label（跨主機覆蓋率的實際證明）**：v1.1 讓多台主機的
> `local6`/`auth`/`authpriv` 都進同一個 `job="pilot-siem"` stream，但沒有
> 任何 label 能分辨「這筆資料來自哪台主機」——只能查到「有沒有任何一筆」，
> 查不出「這六台裡面到底哪幾台真的有資料」，這正是它想證明「所有主機都被
> 收集到」時會卡住的地方。v1.2 加一個 Promtail `pipeline_stages`：從
> `filename`（Promtail 對每個被 `__path__` glob 到的檔案自動附的內建
> label，值是完整路徑）用 regex 抓出 `%HOSTNAME%` 那一段（rsyslog 落地時
> 已經用來源主機名分檔，見 `log-server.md`），變成一個真正的 `host` label。
> 這樣才能用 `sum by (host) (count_over_time({job="pilot-siem"}[7d]))`
> 這種查詢直接列出六台裡面每台各有幾筆，而不必逐台肉眼比對 log 內容裡的
> hostname 字串。wazuh-alerts job 同理，改用 Promtail 的 `json` pipeline
> stage 解析每行告警 JSON 的 `agent.name` 欄位（見本 spec §4.1 對這欄位的
> 實測描述）升成同名的 `host` label，讓兩個 job 可以用同一個 label 名稱
> 查詢。同時把 wazuh-alerts job 的 scrape glob 從 `**/*.log`（同時掃到
> `archives.log`/`api.log`/`cluster.log` 等 Wazuh 預設不會寫入內容的檔案，
> 只會製造「target 存在但讀取位置永遠是 0，看起來像壞了但其實只是本來就
> 沒東西」的假訊號）收斂成只掃 `alerts/*.log`——raw audit trail 的完整性已
> 由 `siem_log_root` 這條 rsyslog 路徑負責，不需要靠 Wazuh 的 archives 機制
> 重複提供，那條路徑預設也沒開（`ossec.conf` 的 `<logall>`/`<logall_json>`
> 預設 `no`）。
>
> **v1.3 修正 v1.2 自己引入的 bug**：`alerts/*.log` 這個 glob 收斂得太粗——
> Wazuh manager 對每一筆告警其實同時落地兩份檔案在同一個目錄下：
> `alerts.log`（純文字，`** Alert ...` 格式）跟 `alerts.json`（結構化
> JSON，每行一筆）。`*.log` 這個 glob 只會吃到純文字那份，但 `json`
> pipeline stage 需要真正的 JSON 才能解析出 `agent.name`——餵給純文字內容
> 時每一行都解析失敗，`host` label 永遠不會被設定，整條 wazuh-alerts job
> 的 host 篩選能力形同虛設，卻不會出現在任何錯誤訊息裡（Promtail 對解析
> 失敗的 json stage 預設只是靜默跳過該 stage，原始行照樣送進 Loki，只是
> 沒有 `host` label）。實測 2026-08-07（minimal-poc round 20）：Loki 的
> `/loki/api/v1/series` 查詢對 `{job="pilot-siem-wazuh-alerts"}` 只回報
> `{filename, job}` 兩個 label，完全沒有 `host`。修法：把 `__path__`
> 從 `alerts/*.log` 改成明確指定 `alerts/alerts.json`——兩份檔案 Wazuh
> 一律同時寫、不受 `<logall>`/`<logall_json>` 影響（那兩個設定管的是
> archives 而非 alerts），所以這個修法不需要額外開啟任何 Wazuh manager
> 設定。

## 2. Checklist

| ID  | Category | Check                                                              | Expected | Command |
|-----|----------|----------------------------------------------------------------------|----------|---------|
| C1  | docker   | `pilot-promtail` container 存在且 running                             | ~pilot-promtail | docker ps --no-trunc 2>/dev/null | grep -m1 -oE 'pilot-promtail' | head -n1 |
| C2  | http     | Promtail `/ready`（9080）回 200                                       | ~200 | curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:9080/ready |
| C3  | config   | Promtail 設定檔含 `siem_log_root` 的 scrape glob                       | 0 | grep -qE '__path__:\s*/var/log/siem/\*\*/\*\.log' /etc/pilot/promtail/promtail-config.yml; echo $? |
| C4  | config   | Promtail 設定檔的 push 目標指向 `pilot-loki-backend` 別名                | 0 | grep -qE 'url:\s*"http://pilot-loki-backend:3100/loki/api/v1/push"' /etc/pilot/promtail/promtail-config.yml; echo $? |
| C5  | network  | `/etc/hosts` 已 pin `pilot-loki-backend` 別名                          | 0 | grep -qE '\spilot-loki-backend$' /etc/hosts; echo $? |
| C6  | functional | 本機注入唯一測試訊息，透過 Promtail 轉送後，向中央 Loki 查詢確實查到    | ~PILOT-LOGSHIP-SELFTEST | sh -c 'logger -p local6.info "PILOT-LOGSHIP-SELFTEST-$$"; sleep 6; curl -fsS -G http://pilot-loki-backend:3100/loki/api/v1/query --data-urlencode "query={job=\"pilot-siem\"}" | grep -o "PILOT-LOGSHIP-SELFTEST-[0-9]*"; true' |
| C7  | dir      | Promtail positions 檔目錄存在（記錄 tail 進度，重啟不重複轉送）          | present | test -d /var/lib/pilot/promtail |
| C8  | config   | Promtail 設定檔含 `host` label 的 pipeline stage（從 `filename` 抽取來源主機名）| 0 | grep -qE 'source:\s*filename' /etc/pilot/promtail/promtail-config.yml; echo $? |
| C9  | functional | 本機注入唯一測試訊息，向中央 Loki 用「本機 hostname」當 `host` label 篩選查詢確實查到——證明的不只是「資料有沒有進 Loki」（C6 已驗），而是「這筆資料能不能用 `host` label 篩出**這一台**」| ~PILOT-LOGSHIP-HOSTLABEL | sh -c 'logger -p local6.info "PILOT-LOGSHIP-HOSTLABEL-$$"; sleep 6; curl -fsS -G http://pilot-loki-backend:3100/loki/api/v1/query --data-urlencode "query={job=\"pilot-siem\", host=\"$(hostname)\"}" | grep -o "PILOT-LOGSHIP-HOSTLABEL-[0-9]*"; true' |

> C3/C4 的路徑/別名是固定字串，不是變數內插——`siem_log_root`/`loki_alias`
> 若被覆寫成非預設值，這兩行在該環境下屬已知偏差（見 §5），不是本 spec
> 的責任範圍（比照 `prometheus.md` C8 只驗預設情境的既有慣例）。
> C6/C9 用 `~contains` 而非 `^` 錨點，且用 `; true` 吸收 grep 找不到時的
> non-zero rc，避免 wrapper 把「還沒轉送到」的合法 FAIL 結果變成不可
> 判讀的 ansible FAILED 輸出（`verification-spec-template.md` 陷阱 2）。
> 測試訊息帶 `$$`（shell PID）是為了讓每次驗證的字串都不同，避免查到
> 上一輪驗證留下的舊資料造成偽陽性；`grep -o` 只驗證有匹配到這個模式
> （不驗證精確 PID 值），因為 Command/Expected 欄位不能因每次執行而變。
> C9 的 `$(hostname)` 跟 C6/C9 的 `$$` 是同一種道理——這段 shell
> 語法本身是固定字串，只是**執行時**在不同主機/不同次會展開成不同值，不
> 算違反「Command 欄位不能因每次執行而變」的規則（規則管的是欄位文字本
> 身，不是它執行後的結果）。C9 特別選「用本機自己的 hostname 當 label
> 篩選」而不是查全部再肉眼比對，是因為要證明的正是「這個 label 真的等於
> 這台主機的名字」，不是「Loki 裡面有某個 host label 存在」。

## 3. 證據收集

- 工具：`pilot verify docs/verification/log-shipping.md -i <inventory> -l log-server`
- 輸出格式：`.verification/log-shipping-<UTC>.{ndjson,md}`
- 預期 row 數：9

## 4. PASS / FAIL 規則

- C1–C5, C7, C8 全部 pass 且 C6, C9 pass → **PASS**：日誌確實從這台轉送到中央 Loki，且能用 `host` label 篩出這一台
- C1–C5, C7, C8 pass 但 C6 或 C9 fail → Promtail 本身健康（設定/label 都對），只是還沒接到中央 Loki，或 label 值跟預期的 hostname 不一致（見 §1.5、§5）
- 任一 C1–C5, C7, C8 fail → **FAIL**，常見修法：
  - C1 fail → container 沒起；`docker logs pilot-promtail`
  - C2 fail → 設定檔語法錯或掛載路徑錯
  - C3/C4 fail → apply playbook 的 template task 沒 render 成功
  - C5 fail → `loki_target_host` 沒填或 `/etc/hosts` pin task 沒跑到
  - C6 fail → 先確認 C1–C5 都 pass；再檢查中央 `dashboard.md` 的 Loki 是否真的在跑（`dashboard.md` C1/C3）、網路是否可達（`pilot-loki-backend` 別名解析、防火牆）
  - C7 fail → 目錄沒建立（volume 掛載會自動建，除非 apply 漏了 file task）
  - C8 fail → apply playbook 的 `pipeline_stages` template 沒 render 成功（同 C3/C4 的成因）
  - C9 fail 但 C6 pass → label 抽取邏輯本身有問題（regex 對不上實際檔案路徑），不是轉送本身壞了；檢查 `docker logs pilot-promtail` 有沒有 pipeline stage 的 parse error

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C6, C9 | `loki_target_host` 未填或 `dashboard.md` 尚未部署時，這兩行預期 fail | dashboard 尚未上線的環境 | 直到 `dashboard.md` PASS 為止 |
| C3, C4 | `siem_log_root`/`loki_alias` 被覆寫成非預設值時，這兩行的固定字串比對會 fail（功能本身仍正常，只是驗證用的字串跟著變了） | 覆寫了預設路徑/別名的環境 | 視站台設定 |

## 6. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-06 | v1.0 | 初版 | sre |
| 2026-08-06 | v1.1 | 修真實 incident 的下游影響：v1.0 讓同機 wazuh-manager 容器的 alerts-log 路徑取代 `siem_log_root`，配上 `log-server.md` 當時的 bug（同機有 wazuh-manager 時整個跳過部署），local6/auth/authpriv 轉送全部石沉大海，Promtail 只看得到 Wazuh 自己的告警文字。改為 `siem_log_root` 一律 scrape、wazuh alerts-log 只在偵測到容器時額外加開第二個 job（`promtail_wazuh_job_label`），兩者並存不互斥。實測 2026-08-06：兩台全新 vm-target（client 轉送 local6/auth,authpriv → 同機 wazuh-manager+log-server 的接收端 → Promtail → Loki），`pilot verify` 7/7 全綠，`curl` 直接向 Loki 查詢確認兩筆測試訊息都真的進了 `job="pilot-siem"` | sre |
| 2026-08-06 | v1.2 | 補上跨主機覆蓋率的實際查詢能力：新增 C8（config，`host` label 的 pipeline stage 存在）與 C9（functional，用本機 hostname 當 `host` label 篩選查得到自己剛注入的訊息）；`pilot-siem` job 用 Promtail 內建的 `filename` label + regex 抽出 `%HOSTNAME%`，`pilot-siem-wazuh-alerts` job 改用 `json` pipeline stage 解析每行告警的 `agent.name` 欄位，兩者統一升成同名 `host` label。同時把 wazuh-alerts job 的 glob 從 `**/*.log` 收斂成只掃 `alerts/*.log`——`archives.log`/`api.log`/`cluster.log` 等檔案在 Wazuh 預設設定（`<logall>`/`<logall_json>` 都是 `no`）下永遠不會有新內容，繼續掃它們只會製造「target 讀取位置永遠 0，看起來像壞了」的假訊號，而 raw audit trail 的完整性已經由 `siem_log_root` 這條路徑負責，不需要靠 Wazuh 的 archives 機制重複提供。實測 2026-08-06：`pilot verify` 9/9 全綠，`curl` 用 `{job="pilot-siem", host="<hostname>"}` 篩選查詢確實只查到該台自己注入的訊息 | sre |
| 2026-08-07 | v1.3 | 修 v1.2 自己引入的 bug：wazuh-alerts job 的 `alerts/*.log` glob 只吃到 Wazuh 同時落地的純文字版告警檔，`json` pipeline stage 對純文字內容解析永遠失敗、`host` label 永遠不會被設定——而且不會報錯，看起來像「job 有資料，只是沒篩選能力」而非明顯故障。real incident：minimal-poc round 20 對一個全新 clean-room 拓樸做深入 Loki 查核時，`/loki/api/v1/series` 對這個 job 查出來只有 `filename`/`job` 兩個 label，完全沒有 `host`。修法：`__path__` 從 `alerts/*.log` 改成明確指定同目錄下 Wazuh 一律會寫的 `alerts/alerts.json`（不受 `<logall>`/`<logall_json>` 影響，那兩個設定管的是 archives 而非 alerts）。修前修後都在同一組 3 台主機（AlmaLinux 9 + 2×Ubuntu 24.04）實測確認：修前 host label 完全空白；修後 `{job="pilot-siem-wazuh-alerts"}` 每一筆都有正確的 `host` label | sre |
