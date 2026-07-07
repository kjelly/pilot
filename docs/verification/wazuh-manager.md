# Verification Spec — wazuh-manager（Wazuh 中央伺服器：FIM/who-data 告警引擎 + CVE 弱點掃描 + 選填轉送 SIEM，Docker 部署）

> 版本：v2.0
> 對齊規範：pilot 通用 config-only 服務規範；為 `wazuh-fim.md`（agent 端 FIM +
> auditd who-data）提供中央分析/告警引擎，轉送目標為 `docs/verification/log-server.md`
> （rsyslog 中央接收端）。三份 spec 搭配構成一組 Shape 3（agent → manager →
> SIEM）鏈路。
> 維護者：sre

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Hostname / Inventory group | wazuh-manager |
| OS / version | Ubuntu 24.04 LTS |
| 角色 | Wazuh **single-node**（manager + indexer + dashboard，同一台主機、三個 Docker 容器）：接收 agent 送來的 FIM(syscheck)/who-data 事件、跑規則引擎產生告警、跑 CVE 弱點掃描（vulnerability-detection），選填把告警轉送至中央 SIEM(`log-server`) |
| 套用範圍 | `/opt/pilot/wazuh-docker/`（官方 wazuh-docker 發行包 + 憑證 + `wazuh_manager.conf`）、官方 single-node compose 專案（`single-node-wazuh.manager-1`/`single-node-wazuh.indexer-1`/`single-node-wazuh.dashboard-1` 三容器與其 named volumes）、`vm.max_map_count` sysctl、`/etc/hosts`（`siem-log-server` 別名） |
| 前置依賴 | `docs/verification/docker.md` 8/8 PASS（`docker.io` + `docker.service` + compose v2 plugin，由 `core-infra-provider-apply.yml -e infra_role=docker` 佈署） |
| 風險等級 | High（對外開 1514/1515 收 agent 連線、443 供 dashboard；告警規則/轉送設定錯誤會導致資安事件漏判或漏送） |
| **資源需求（v1.0 實測踩過的雷，見 §5）** | 官方建議 1–25 agents：**4 vCPU / 8 GiB RAM / 50 GB 磁碟**。CVE feed 解壓後常駐磁碟用量 ~7–9 GB（Docker 部署下位於 `wazuh_queue` named volume 內，磁碟壓力不變）；磁碟不足會讓 `wazuh-db`/`wazuh-analysisd` 寫入失敗，**所有告警（含 FIM）都會靜默停止產生**，且不會有明顯的服務關閉徵兆（容器仍顯示 running）。本 spec 的 vm-target SOP（§7）用 60GB 磁碟、8192MB 記憶體、4 vCPU，不要沿用 `log-server`/`audit-log-forwarding`（20GB/2048MB/2vCPU）的規格 |

> 為何選 Wazuh manager 而非只用 auditd+rsyslog（`audit-log-forwarding.md`）：
> 那份 spec 只做「轉送原始 audit/auth 日誌」，沒有規則引擎、沒有 FIM 專屬的
> who-data 關聯分析、也沒有 CVE 弱點掃描能力。此 spec 是同一個 SIEM 收斂
> 鏈路上「多一層本地端分析」的角色，兩者可以並存於同一台主機（不互斥）。
>
> 為何改用 Docker（v2.0，取代 v1.0 的 `wazuh-install.sh -a` 原生安裝）：
> 本 repo 的網路服務型角色（`prometheus.md`/`thanos-query.md`/`dashboard.md`/
> `log-shipping.md`/`seaweedfs-s3.md`）已收斂到 Docker 部署——升級/回滾是換
> image tag、不污染主機套件、狀態集中在可列舉的 named volumes。Wazuh 官方
> 維護 `wazuh-docker` 發行包（manager/indexer/dashboard 三個官方 image +
> 驗證過的 compose 拓撲），是新增角色中唯一適合遷移的：純網路服務、不碰
> 主機核心（對照 `wazuh-fim.md`/`audit-log-forwarding.md` 的 agent/auditd
> 必須留在主機上）。
>
> 為何用官方 `wazuh-docker` single-node 發行包（compose + 官方憑證產生容器）
> 而非手刻三個 `docker_container` task：CVE 弱點掃描在 Wazuh 4.8+ 架構下
> **需要 Wazuh indexer**（OpenSearch 基礎）才能真正儲存/關聯掃描結果；
> indexer 的憑證鏈（root CA、indexer 憑證、filebeat 憑證、dashboard 憑證）
> 手動產生極度容易做錯且沒有回頭路——這正是 v1.0 選官方 `wazuh-install.sh`
> 而非手刻 apt 安裝的同一個理由，Docker 化不改變這個取捨。官方
> `generate-indexer-certs.yml`（`wazuh/wazuh-certs-generator` 容器）+
> `docker-compose.yml`（三服務、TLS 佈線、`/wazuh-config-mount` 設定注入機制）
> 是官方驗證過的整包流程；本 playbook 只疊加我們自己要的「選填轉送到
> log-server」設定，不重造官方已經做好的部分。

## 1.5 依賴變數契約

在套用或驗證此主機時，Playbook 與變數參數必須嚴格遵守以下命名，禁止擅自縮寫或發明新變數：

| 變數名稱 | 說明/用途 | 是否必填 | 預設值 |
|---------|----------|---------|--------|
| `siem_forward_host` | 中央 SIEM（`log-server`）的 IP 或 FQDN；套用時會被 pin 進 `/etc/hosts` 的 `siem-log-server` 別名，供 `<syslog_output>` 使用 | 否 | 空字串（不轉送） |
| `siem_forward_port` | Wazuh manager 轉送告警的目的埠（UDP，`<syslog_output><port>`） | 否 | `514` |
| `wazuh_docker_version` | 官方 `wazuh-docker` 發行包版本（GitHub tag `v<版本>`，同時決定三個官方 image 的 tag） | 否 | `4.14.1`（本 spec 實測版本；見 §7） |

> `siem_forward_host` 沿用 `audit-log-forwarding.md` 同一個變數名稱與別名機制
> （`siem-log-server`）：兩份 spec 轉的都是同一個 SIEM 目的地，統一命名讓一套
> `-e siem_forward_host=<log-server IP>` 同時適用兩支 playbook，不用記兩個變數名。
> **選填**：log server 不一定先於 manager 存在——本機告警引擎與 CVE 掃描
> （C1–C9）跟「是否有中央 SIEM」無關，應該獨立可用。未提供時 apply 跳過
> `/etc/hosts` pin 與 `<syslog_output>` 區塊，C10/C11 這時不適用（見 §5）。
> 待 log server 就緒後，用同一份 playbook 帶
> `-e siem_forward_host=<log-server IP/FQDN>` 再跑一次即可補上轉送，不需要
> 重建容器或重新產生憑證（`<syslog_output>` 注入走官方
> `/wazuh-config-mount` 機制 + 重啟 manager 容器）。

## 2. Checklist

| ID  | Category  | Check                                                              | Expected | Command |
|-----|-----------|------------------------------------------------------------------------|----------|---------|
| C1  | container | manager 容器（`single-node-wazuh.manager-1`）為 running                | 0        | sh -c 'docker ps --filter name=wazuh.manager --filter status=running -q | grep -q . && echo 0 || echo 1' |
| C2  | container | indexer 容器（`single-node-wazuh.indexer-1`，CVE 掃描結果的儲存/關聯引擎）為 running | 0 | sh -c 'docker ps --filter name=wazuh.indexer --filter status=running -q | grep -q . && echo 0 || echo 1' |
| C3  | container | dashboard 容器（`single-node-wazuh.dashboard-1`，443 Web UI）為 running | 0        | sh -c 'docker ps --filter name=wazuh.dashboard --filter status=running -q | grep -q . && echo 0 || echo 1' |
| C4  | functional| indexer HTTPS API 已就緒（未帶憑證回 401，證明 OpenSearch + security plugin 已完成啟動，不只是容器活著） | 0 | sh -c '[ "$(curl -sk -o /dev/null -w "%{http_code}" https://127.0.0.1:9200)" = "401" ] && echo 0 || echo 1' |
| C5  | network   | agent 連線埠 1514/tcp 確實在監聽（`wazuh-remoted`，compose port mapping） | 0        | sh -c 'ss -lnt | grep -q ":1514" && echo 0 || echo 1' |
| C6  | network   | 註冊埠 1515/tcp 確實在監聽（`wazuh-authd`，agent 自動註冊用）          | 0        | sh -c 'ss -lnt | grep -q ":1515" && echo 0 || echo 1' |
| C7  | config    | CVE 弱點掃描（`vulnerability-detection`）在容器內生效中的 `ossec.conf` 已啟用（證明 `/wazuh-config-mount` 注入確實發生） | 0 | sh -c 'docker exec single-node-wazuh.manager-1 grep -A1 "<vulnerability-detection>" /var/ossec/etc/ossec.conf | grep -q "<enabled>yes</enabled>" && echo 0 || echo 1' |
| C8  | disk      | 磁碟可用空間 ≥ 5GB（CVE feed 常駐用量的安全邊界，避免 §5 的靜默寫入失敗） | 0        | sh -c '[ "$(df --output=avail -B1G / | tail -1 | tr -d " ")" -ge 5 ] && echo 0 || echo 1' |
| C9  | functional| 規則引擎可比對出一筆已知規則並判定為需告警（`wazuh-logtest` 灌入一行完整的 sshd 失敗登入 syslog 訊息，不需要真實 agent） | 0 | sh -c 'printf "%s\n" "Jul  6 00:00:00 wazuh-fim sshd[12345]: Failed password for invalid user test from 10.0.0.9 port 12345 ssh2" | docker exec -i single-node-wazuh.manager-1 timeout 15 /var/ossec/bin/wazuh-logtest 2>&1 | grep -qF "Alert to be generated." && echo 0 || echo 1' |
| C10 | forward   | `/etc/hosts` 已 pin `siem-log-server` 別名                            | 0        | getent hosts siem-log-server >/dev/null 2>&1; echo $? |
| C11 | forward   | 容器內生效中的 `ossec.conf` 含指向 `siem-log-server` 的 `<syslog_output>` 區塊（證明 host 端設定注入 + 容器重啟後真的生效，不只是 host 檔案改了） | 0 | sh -c 'docker exec single-node-wazuh.manager-1 grep -qE "<server>siem-log-server</server>" /var/ossec/etc/ossec.conf && echo 0 || echo 1' |

> C1–C11 全部用**正邏輯 rc**（`; echo $?` 或 `sh -c '... && echo 0 || echo 1'`
> 外殼），讓外層指令恆回 0，避免 ansible ad-hoc 把「沒監聽/沒命中」的合法
> FAIL 判定結果誤判成 task FAILED 而把 rc 吃掉
> （見 `verification-spec-template.md` 陷阱 1）。
> 多列含字面 `|`（管線），依 `verification-spec-template.md` 的多 pipe 寫法
> 約定，Command 欄位**不要**用 `\|` 跳脫——跳脫符不會被 parser 還原，會原封
> 不動留在指令字串裡、在真正執行時破壞 shell 語意。故意讓表格視覺上「被切成
> 更多欄」，parser 會自動把多出來的欄位接回 Command。
> **不用 docker 的 Go template 語法**（`docker inspect -f '{{.State.Running}}'`
> 之類）——`{{ }}` 會被 ansible ad-hoc 當 Jinja 模板吃掉，改用
> `docker ps --filter` 的組合達到同樣效果（`%{http_code}` 是 curl 語法、單大
> 括號，不受影響）。
> 容器名稱 `single-node-wazuh.manager-1` 是官方 compose 專案的確定性命名
> （project=`single-node`（apply playbook 明確指定，見 §6）+ service
> `wazuh.manager` + replica 1），spec Command 欄是一次寫死的靜態文字，依賴
> playbook 不改 project name 這個契約。
> C1–C3/C7/C9/C11 的 docker CLI 不加 `sudo`：`pilot verify` 的 ad-hoc 管線
> 本來就以 `become=true`（root）執行每條 Command（用
> `pilot verify --probe '<cmd>'` 可看到 `module: shell (become=true)`）。
> **不要**假設 ansible 使用者在 `docker` group——實測 vm-target 上
> `id ubuntu` 只有 `ubuntu sudo wheel`，沒有 docker group；`docker.md` C5
> 不帶 sudo 能過也是同一個原因（become），不是 group 成員資格。
> C9 的測試行必須是**完整的 syslog 格式**（含時間戳、hostname、`sshd[pid]:`）
> 確保配對到 `sshd`/`5710` 這條具名規則而非泛用規則 1002；斷言字串用
> `wazuh-logtest` 只在告警等級門檻（`<log_alert_level>`，出廠預設 3）以上
> 才會印出的 `Alert to be generated.`——兩者都是 v1.0 實測 vm-target 才發現
> 的坑（見 `docs/runbooks/wazuh-manager.md` §5）。
> `pilot spec --lint` 會對 C9 印出一條 warn：「reverse-logic grep for a
> failure token with a numeric expected」。這是**已知的誤報**——lint 規則的
> 啟發式看到 command 裡有 `| grep` 且字面上出現 `Failed`（來自我們刻意灌入
> 的、跟真實 sshd 記錄一字不差的失敗登入訊息）就假設這是反邏輯 grep，但
> C9 整段其實已經包在 `sh -c '... && echo 0 || echo 1'` 的正邏輯外殼裡，
> `Failed` 只是測試資料的一部分，不是被拿來反向判斷健康與否的 token。
>
> C8 的 5GB 門檻是本 spec 選定的保守值（CVE feed 本身常駐 ~7GB，v1.0 安裝時
> 曾短暫額外用到 8GB+ 的解壓緩衝——見 §5 的磁碟全滿事故；Docker 部署下這些
> 資料位於 named volume，同樣落在 `/var/lib/docker`，磁碟壓力不變，且還要
> 加上三個官方 image 本身 ~3–4GB），不是官方文件的正式門檻；正式站台請直接
> 照 §1 的官方建議（50GB+）規劃磁碟，不要只滿足這條檢查的最低值。
> **真正的 FIM+who-data 端到端證明**（agent 端改檔案 → manager 產生含
> who-data 欄位的告警 → 轉送到 log-server 落地）是跨主機 Shape 3
> cross-check，不放進本 spec，做法見 `docs/runbooks/wazuh-fim.md` §4。

## 3. 證據收集

- 工具：`go run ./cmd/pilot vm-target verify --name wazuh-manager docs/verification/wazuh-manager.md`
- 輸出格式：`.verification/wazuh-manager-<UTC>.{ndjson,md}`
- 預期 row 數：11（C1–C11）

## 4. PASS / FAIL 規則

- 全部 C1–C11 `status=pass` → **PASS**
- 任一 `status=fail` → **FAIL**，列出 fail id + actual + want

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C10, C11 | 這兩條的前提是套用時提供了 `siem_forward_host`（見 §1.5，選填）。若 log server 尚未存在、套用時未帶這個變數，playbook 會跳過轉送設定，C10/C11 在 `pilot verify` 會回報 `fail`——這是**預期行為**，不是 bug：此時應只驗證 C1–C9（本機告警引擎 + CVE 掃描），待 log server 就緒、補跑一次 apply 帶上 `siem_forward_host` 後再驗全部 11 條 | 無 log server 的獨立部署 / log server 尚未就緒的過渡期 | 補上 `siem_forward_host` 並重新 apply 後即解除 |
| — | **磁碟全滿會靜默吃掉所有告警，這是 v1.0 實測 vm-target 踩到的真事故，不是理論風險**：v1.0 第一次實測用了 20GB 磁碟，CVE feed 下載/解壓當下瞬間衝到 100% 磁碟用量，`wazuh-db`/`wazuh-analysisd` 持續報 `SQLite: database or disk is full`，**但服務狀態全程顯示正常**——只有告警安靜地生不出來。Docker 部署下 CVE feed 位於 `wazuh_queue` named volume（`/var/lib/docker/volumes/single-node_wazuh_queue/`），磁碟壓力相同，container `running` 狀態同樣不會反映這種內部寫入失敗。診斷方式：`docker exec single-node-wazuh.manager-1 tail -n 40 /var/ossec/logs/ossec.log` 看 `disk is full` 字樣，或直接 `df -h /`。修法：磁碟給足（§1 的官方建議），這就是為何 §7 SOP 把 vm-target 磁碟從其他 spec 慣用的 20GB 提高到 60GB | 所有環境 | 永久（設計如此的容量規劃提醒，非暫時偏差） |
| — | **官方 compose 檔的管理者密碼是寫死的出廠預設值**（indexer `admin`/`SecretPassword`、API `wazuh-wui`/`MyS3cr37P450r.*-`、dashboard `kibanaserver`/`kibanaserver`），本 playbook 不改它們——這跟 v1.0（官方安裝腳本隨機產生密碼）是一個**安全性上的退步**，屬 Docker 化的已知取捨：官方變更 indexer 密碼的流程需要 bcrypt hash 進 `internal_users.yml` + 跑 `securityadmin` 重新載入 + 同步改 compose 三處 env，官方文件有完整步驟但不是一個變數就能帶過的事。sandbox/demo 可接受（9200/443/55000 只在實驗網段）；**正式站台上線前必須照官方文件把三組密碼全部改掉**，屬部署後手動加固項目，本 spec 不驗證 | sandbox / demo | 正式站台上線前依官方文件變更全部出廠密碼 |
| — | `vm.max_map_count=262144` 是 **host 層級** sysctl（官方 indexer 的硬性要求），由 apply playbook 以 `ansible.posix.sysctl` 持久化設定——這是本角色唯一必須碰主機設定的地方，容器本身無法自帶 | 所有環境 | 永久（官方要求，非暫時偏差） |
| — | Enrollment 使用官方 image 出廠預設（`use_password=no`，開放式註冊，任何知道 IP 的 agent 都能自動註冊）。這對 sandbox/demo 足夠，正式站台若要防止未授權 agent 冒名註冊，應在 `<auth>` 加 `use_password=yes` 並透過 vault 分發密碼，屬於本 spec 範圍外的加固項目 | sandbox / demo | 正式站台上線前檢討 |
| — | 官方 single-node compose 內含 `wazuh-dashboard`（443 埠的 Web UI）；本任務的需求（FIM+who-data 告警產生 + CVE 掃描 + 轉送 SIEM）不需要它，但官方 compose 的三服務是一組驗證過的整體（dashboard 也是 indexer TLS 憑證鏈的一環），拆掉它偏離官方拓撲的風險大於省下的資源。多一個 dashboard 容器對這個 spec 的驗證目標無害（C3 只驗容器 running），443/9200/55000 的存取控制屬網段規劃範疇 | 所有環境 | 永久（設計如此的取捨，非暫時偏差） |
| — | 官方 compose 同時把 `514/udp` 映射到 host（Wazuh 自己的 syslog 收集端點）。本專案的 SIEM 鏈路方向是 manager **送出** 到 log-server，不使用這個收入埠；若未來要在同一台主機同時跑 rsyslog 接收端（`log-server.md`）會撞埠，兩角色目前設計上就不同機，不視為衝突 | 所有環境 | 永久（記錄埠使用事實） |

## 6. Playbook 對應

對應 apply playbook：`playbooks/apply/wazuh-manager-apply.yml`

| Spec ID | Apply task | 備註 |
|---------|------------|------|
| — | `sysctl vm.max_map_count=262144`（`ansible.posix.sysctl`，持久化） | 官方 indexer 硬性要求，先於容器啟動 |
| C1, C2, C3 | `get_url` 官方 `wazuh-docker` 發行包 → `unarchive` 至 `/opt/pilot/wazuh-docker/` → 官方 `generate-indexer-certs.yml` 產生憑證（一次性，以 `root-ca.pem` 存在與否冪等）→ `community.docker.docker_compose_v2` 起官方 single-node 專案（project name 明確指定 `single-node`，容器名 `single-node-wazuh.{manager,indexer,dashboard}-1` 因此為確定值） | 官方發行包 + 官方憑證產生容器，不手刻憑證鏈（見 §1 的理由） |
| C4 | `uri` 等待 `https://127.0.0.1:9200` 回 401（indexer security plugin 就緒） | 首次啟動 indexer 初始化需 ~1 分鐘，playbook 內建等待 |
| C5, C6 | `wait_for` 1514/tcp（官方 compose 出廠 port mapping 即滿足） | 只等待就緒，不另外管理 |
| C7 | 無獨立 apply task（官方 `wazuh_manager.conf` 出廠即 `<vulnerability-detection><enabled>yes`，經 `/wazuh-config-mount` 注入） | 只驗證，不管理 |
| C8 | 無獨立 apply task（純環境健檢） | apply 前應先確認磁碟規劃（§1），不是 apply 事後補救 |
| C9 | 無獨立 apply task（規則引擎的功能性自證，verify 時才觸發 `wazuh-logtest`） | — |
| C10 | `lineinfile /etc/hosts` pin `siem-log-server` | 必須在 `<syslog_output>` render 之前 |
| C11 | `blockinfile` 插入 `<syslog_output>` 區塊到 host 端 `config/wazuh_cluster/wazuh_manager.conf`（檔案末端新增一個 `<ossec_config>` 區塊；Wazuh 的 XML parser 允許同一份檔案有多個 `<ossec_config>` 根節點並全部合併，v1.0 已實測——見 `docs/runbooks/wazuh-manager.md` §5）→ **漂移偵測**：`docker exec` 探測容器內生效的 `ossec.conf` 是否含轉送區塊，缺了就 **recreate**（不是 restart）manager 容器並硬斷言收斂 | 只新增管理區塊，不動官方出廠 `wazuh_manager.conf` 的其餘預設設定。**必須 recreate 不能 restart**：官方 image 的 `0-wazuh-init` 在首次開機結尾刪掉 `/var/ossec/data_tmp`，單純 restart 時 init 腳本會因空的 `multigroups` 目錄找不到 `data_tmp` 而 exit 1，永遠跑不到 `mount_files`（config 注入）——vm-target 實測踩到的雷，見 runbook §5 |

## 7. SOP

### 7.1 標準情境：log server 已存在（轉送啟用，驗證全部 11 條）

```bash
LOG_SERVER_IP=$(go run ./cmd/pilot vm-target show-inventory --name log-server \
    | awk '/ansible_host:/{print $2; exit}')

# 1. 起 VM —— 注意規格：60GB 磁碟 / 8192MB 記憶體 / 4 vCPU（見 §1、§5 磁碟事故）
go run ./cmd/pilot vm-target up --name wazuh-manager \
    --ssh-user ubuntu --disk 60 --memory 8192 --vcpus 4 \
    --ssh-timeout 8m --boot-timeout 8m

# 2. docker preflight（docker.io + docker.service + compose v2；docker.md 的前置依賴）
go run ./cmd/pilot vm-target run --name wazuh-manager \
    playbooks/apply/core-infra-provider-apply.yml \
    -e target_group=all -e infra_role=docker

# 3. apply（首次會拉三個官方 image ~3-4GB + indexer 初始化，playbook 內建等待）
go run ./cmd/pilot vm-target run --name wazuh-manager \
    playbooks/apply/wazuh-manager-apply.yml \
    -e siem_forward_host=$LOG_SERVER_IP

# 4. verify
go run ./cmd/pilot vm-target verify --name wazuh-manager \
    docs/verification/wazuh-manager.md

# 5. 冪等檢查
go run ./cmd/pilot vm-target run --name wazuh-manager \
    playbooks/apply/wazuh-manager-apply.yml \
    -e siem_forward_host=$LOG_SERVER_IP
```

### 7.2 過渡情境：log server 尚不存在（先跑本機告警引擎 + CVE 掃描，之後再補轉送）

```bash
go run ./cmd/pilot vm-target run --name wazuh-manager \
    playbooks/apply/wazuh-manager-apply.yml
# verify 時 C10/C11 預期 fail（見 §5），只看 C1-C9 是否全 pass
```

> vm-target 的 inventory 只有單一 host key（見 `vm-target-basics.md`），
> playbook 的 `hosts:` 預設 `wazuh-manager` 與該 host key 同名，不需要
> `-e target_group=` override（同 `log-server.md` 的設計）。

## 8. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-06 | v1.0 | 初版：Wazuh all-in-one（manager+indexer+dashboard，官方 `wazuh-install.sh -a`）規則引擎/告警 + CVE 弱點掃描 + 選填轉送至 `log-server.md`。實測踩過磁碟全滿靜默吃掉告警的事故，spec 規格與 checklist 已反映修正（見 §1、§5） | sre |
| 2026-07-06 | v2.0 | **改為 Docker 部署**：官方 `wazuh-docker` single-node 發行包（三官方 image + 官方憑證產生容器 + compose），對齊本 repo 其他網路服務型角色的 Docker 收斂。C1–C4 從 dpkg/systemd 檢查改為容器/indexer API 檢查，C7/C9/C11 改在容器內驗證生效中的 `ossec.conf`（證明 `/wazuh-config-mount` 注入鏈路）。新增已知偏差：出廠預設密碼（相對 v1.0 隨機密碼是退步，正式站台須手動變更）、`vm.max_map_count` host sysctl、514/udp 埠映射事實。磁碟事故教訓（60GB 規格）原樣沿用 | sre |
