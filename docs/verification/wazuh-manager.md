# Verification Spec — wazuh-manager（Wazuh 中央伺服器：FIM/who-data 告警引擎 + CVE 弱點掃描 + 選填轉送 SIEM）

> 版本：v1.0
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
| 角色 | Wazuh **all-in-one**（manager + indexer + dashboard，同一台主機）：接收 agent 送來的 FIM(syscheck)/who-data 事件、跑規則引擎產生告警、跑 CVE 弱點掃描（vulnerability-detection），選填把告警轉送至中央 SIEM(`log-server`) |
| 套用範圍 | `/etc/apt/sources.list.d/wazuh.list`、官方 `wazuh-install.sh -a` 安裝的全部元件（`wazuh-manager`/`wazuh-indexer`/`wazuh-dashboard`/`filebeat`）、`/var/ossec/etc/ossec.conf`（新增 `<syslog_output>` 區塊）、`/etc/hosts`（`siem-log-server` 別名） |
| 風險等級 | High（對外開 1514/1515 收 agent 連線、443 供 dashboard；告警規則/轉送設定錯誤會導致資安事件漏判或漏送） |
| **資源需求（實測踩過的雷，見 §5）** | 官方建議 1–25 agents：**4 vCPU / 8 GiB RAM / 50 GB 磁碟**。CVE feed 解壓後常駐磁碟用量 ~7–9 GB；磁碟不足會讓 `wazuh-db`/`wazuh-analysisd` 寫入失敗，**所有告警（含 FIM）都會靜默停止產生**，且不會有明顯的服務關閉徵兆（`systemctl is-active` 仍顯示 active）。本 spec 的 vm-target SOP（§7）用 60GB 磁碟、8192MB 記憶體、4 vCPU，不要沿用 `log-server`/`audit-log-forwarding`（20GB/2048MB/2vCPU）的規格 |

> 為何選 Wazuh manager 而非只用 auditd+rsyslog（`audit-log-forwarding.md`）：
> 那份 spec 只做「轉送原始 audit/auth 日誌」，沒有規則引擎、沒有 FIM 專屬的
> who-data 關聯分析、也沒有 CVE 弱點掃描能力。此 spec 是同一個 SIEM 收斂
> 鏈路上「多一層本地端分析」的角色，兩者可以並存於同一台主機（不互斥）。
>
> 為何用官方 `wazuh-install.sh -a`（all-in-one 組裝腳本）而非手刻
> `apt install wazuh-manager` + 手動接 indexer：CVE 弱點掃描（見需求）在
> Wazuh 4.8+ 架構下**需要 Wazuh indexer**（OpenSearch 基礎）才能真正儲存/
> 關聯掃描結果——`vulnerability-detection` 模組本身不再像舊版那樣直接寫
> `alerts.log` 就結束。indexer 的憑證（root CA、indexer 憑證、filebeat 憑證、
> dashboard 憑證）手動產生極度容易做錯且沒有回頭路；官方腳本把「產生憑證 →
> 裝 indexer → 裝 manager 並接上 indexer 連線設定 → 裝 dashboard」整包驗證過
> 的流程封裝起來，是本專案目前最低風險的做法。本 playbook 只在這個腳本跑完
> 後，疊加我們自己要的「選填轉送到 log-server」設定，不重造官方已經做好的部分。

## 1.5 依賴變數契約

在套用或驗證此主機時，Playbook 與變數參數必須嚴格遵守以下命名，禁止擅自縮寫或發明新變數：

| 變數名稱 | 說明/用途 | 是否必填 | 預設值 |
|---------|----------|---------|--------|
| `siem_forward_host` | 中央 SIEM（`log-server`）的 IP 或 FQDN；套用時會被 pin 進 `/etc/hosts` 的 `siem-log-server` 別名，供 `<syslog_output>` 使用 | 否 | 空字串（不轉送） |
| `siem_forward_port` | Wazuh manager 轉送告警的目的埠（UDP，`<syslog_output><port>`） | 否 | `514` |
| `wazuh_install_script_version` | `packages.wazuh.com` 上 `wazuh-install.sh` 腳本所屬版本路徑（`https://packages.wazuh.com/<版本>/wazuh-install.sh`） | 否 | `4.14`（本 spec 實測版本；見 §7） |

> `siem_forward_host` 沿用 `audit-log-forwarding.md` 同一個變數名稱與別名機制
> （`siem-log-server`）：兩份 spec 轉的都是同一個 SIEM 目的地，統一命名讓一套
> `-e siem_forward_host=<log-server IP>` 同時適用兩支 playbook，不用記兩個變數名。
> **選填**：log server 不一定先於 manager 存在——本機告警引擎與 CVE 掃描
> （C1–C9）跟「是否有中央 SIEM」無關，應該獨立可用。未提供時 apply 跳過
> `/etc/hosts` pin 與 `<syslog_output>` 區塊，C10/C11 這時不適用（見 §5）。
> 待 log server 就緒後，用同一份 playbook 帶
> `-e siem_forward_host=<log-server IP/FQDN>` 再跑一次即可補上轉送，不需要
> 重新安裝或重新產生 agent 憑證。

## 2. Checklist

| ID  | Category  | Check                                                              | Expected | Command |
|-----|-----------|------------------------------------------------------------------------|----------|---------|
| C1  | package   | `wazuh-manager` 已安裝                                               | 0        | dpkg -s wazuh-manager >/dev/null 2>&1; echo $? |
| C2  | package   | `wazuh-indexer` 已安裝（CVE 掃描結果的儲存/關聯引擎）                  | 0        | dpkg -s wazuh-indexer >/dev/null 2>&1; echo $? |
| C3  | service   | `wazuh-manager.service` 為 active                                    | 0        | systemctl is-active wazuh-manager >/dev/null 2>&1; echo $? |
| C4  | service   | `wazuh-indexer.service` 為 active                                    | 0        | systemctl is-active wazuh-indexer >/dev/null 2>&1; echo $? |
| C5  | network   | agent 連線埠 1514/tcp 確實在監聽（`wazuh-remoted`）                   | 0        | sh -c 'ss -lnt | grep -q ":1514" && echo 0 || echo 1' |
| C6  | network   | 註冊埠 1515/tcp 確實在監聽（`wazuh-authd`，agent 自動註冊用）          | 0        | sh -c 'ss -lnt | grep -q ":1515" && echo 0 || echo 1' |
| C7  | config    | CVE 弱點掃描（`vulnerability-detection`）已啟用                       | 0        | grep -A1 '<vulnerability-detection>' /var/ossec/etc/ossec.conf | grep -q '<enabled>yes</enabled>'; echo $? |
| C8  | disk      | 磁碟可用空間 ≥ 5GB（CVE feed 常駐用量的安全邊界，避免 §5 的靜默寫入失敗） | 0        | sh -c '[ "$(df --output=avail -B1G / | tail -1 | tr -d " ")" -ge 5 ] && echo 0 || echo 1' |
| C9  | functional| 規則引擎可比對出一筆已知規則並判定為需告警（`wazuh-logtest` 灌入一行完整的 sshd 失敗登入 syslog 訊息，不需要真實 agent） | 0 | sh -c 'printf "%s\n" "Jul  6 00:00:00 wazuh-fim sshd[12345]: Failed password for invalid user test from 10.0.0.9 port 12345 ssh2" | sudo timeout 15 /var/ossec/bin/wazuh-logtest 2>&1 | grep -qF "Alert to be generated." && echo 0 || echo 1' |
| C10 | forward   | `/etc/hosts` 已 pin `siem-log-server` 別名                            | 0        | getent hosts siem-log-server >/dev/null 2>&1; echo $? |
| C11 | forward   | `<syslog_output>` 設定含指向 `siem-log-server` 的區塊                 | 0        | grep -qE '<server>siem-log-server</server>' /var/ossec/etc/ossec.conf; echo $? |

> C1–C11 全部用**正邏輯 rc**（`; echo $?` 或原生 rc），C5/C6/C9 用
> `sh -c '... && echo 0 || echo 1'` 讓外層指令恆回 0，避免 ansible ad-hoc 把
> 「沒監聽/沒命中」的合法 FAIL 判定結果誤判成 task FAILED 而把 rc 吃掉
> （見 `verification-spec-template.md` 陷阱 1）。
> C7/C8 含字面 `|`（`grep -A1 ... | grep -q ...`、`df ... | tail -1 | tr -d ...`），
> 依 `verification-spec-template.md` 的多 pipe 寫法約定，Command 欄位**不要**
> 用 `\|` 跳脫——跳脫符不會被 parser 還原，會原封不動留在指令字串裡、在真正
> 執行時破壞 shell 語意。故意讓表格視覺上「被切成更多欄」，parser 會自動把
> 多出來的欄位接回 Command（見 `pilot spec <file> --lint` 或直接讀模板文件的
> 「三個實測踩過的陷阱」段落）。C9 一開始的草稿誤犯過這個錯，也誤用了不存在
> 於 `wazuh-logtest` 輸出裡的字串 `Level:`，且原本灌入的測試訊息缺少
> syslog 表頭（hostname/process/pid），導致連 decoder 都配對不到、只會落到
> 泛用規則 1002（`Unknown problem`）——這條泛用規則本身也會印出
> `level: '2'`，如果只 grep 小寫 `level:` 兩種情況都會誤判 PASS。改用
> **完整的 syslog 格式測試行**（含時間戳、hostname、`sshd[pid]:`）確保配對到
> `sshd`/`5710` 這條具名規則，並改抓 `wazuh-logtest` 只在告警等級門檻
> （`<log_alert_level>`，出廠預設 3）以上才會印出的
> `Alert to be generated.` 字串，兩者都是實測 vm-target 才發現、光讀
> Wazuh 文件不會知道的坑（見 §5）。
> `pilot spec --lint` 會對 C9 印出一條 warn：「reverse-logic grep for a
> failure token with a numeric expected」。這是**已知的誤報**——lint 規則的
> 啟發式看到 command 裡有 `| grep` 且字面上出現 `Failed`（來自我們刻意灌入
> 的、跟真實 sshd 記錄一字不差的失敗登入訊息）就假設這是反邏輯 grep，但
> C9 整段其實已經包在 `sh -c '... && echo 0 || echo 1'` 的正邏輯外殼裡（跟
> C5/C6 完全相同的包法），`Failed` 只是測試資料的一部分，不是被拿來反向判斷
> 健康與否的 token。為了讓 wazuh-logtest 真的配對到具名規則（而不是落到泛用
> 規則 1002），測試行必須是跟真實 sshd log 一模一樣的格式，所以不改寫這個
> 字面詞去閃避 lint 誤報。
>
> C8 的 5GB 門檻是本 spec 選定的保守值（CVE feed 本身常駐 ~7GB，加上安裝時
> 曾短暫額外用到 8GB+ 的解壓緩衝——見 §5 的磁碟全滿事故），不是官方文件的
> 正式門檻；正式站台請直接照 §1 的官方建議（50GB+）規劃磁碟，不要只滿足這條
> 檢查的最低值。
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
| — | **磁碟全滿會靜默吃掉所有告警，這是實測 vm-target 才踩到的真事故，不是理論風險**：本 playbook 第一次實測時用了 20GB 磁碟（沿用 `log-server`/`audit-log-forwarding` 的規格），CVE feed 下載/解壓當下瞬間衝到 100% 磁碟用量，`wazuh-db`/`wazuh-analysisd` 開始持續報 `SQLite: database or disk is full`／`Cannot save Syscollector`／`Cannot save Syscheck`，**但 `systemctl is-active wazuh-manager` 全程顯示 `active`，服務沒有崩潰、沒有明顯錯誤退出碼**——只有告警安靜地生不出來。診斷方式：`sudo tail -f /var/ossec/logs/ossec.log` 看到 `disk is full` 字樣，或直接 `df -h /`。修法：磁碟給足（§1 的官方建議），這就是為何 §7 SOP 把 vm-target 磁碟從其他 spec 慣用的 20GB 提高到 60GB | 所有環境 | 永久（設計如此的容量規劃提醒，非暫時偏差） |
| — | Wazuh dashboard（443）與 indexer 管理者密碼由官方安裝腳本**隨機產生**、存在目標主機本地的 `~/wazuh-install-files.tar`（`wazuh-install-files/wazuh-passwords.txt`），**不經過** ansible-vault，也**不會**被本 playbook 複製離開目標主機。這符合本專案「機密不進 git」的精神（且比 vault 一組固定密碼更安全——每次部署都是新隨機值），但代表：忘記在套用後立刻保存這個檔案，密碼就只能重置找回，不能重新讀出明文。正式站台部署後應立刻依官方文件將這個檔案搬到安全處保管，playbook 本身不做這件事 | 所有環境 | 永久（設計如此，非暫時偏差） |
| — | 本 playbook 用官方 `wazuh-install.sh -a -i`（`-i` = 忽略硬體門檻檢查）而非嚴格擋在資源不足時失敗；vm-target 沙盒環境用 §1 建議的規格即可通過真正的門檻不需要 `-i`，保留這個旗標只是避免不同虛擬化環境的 CPU 型號探測誤判。**這不是繞過磁碟規劃的理由**——上面那條磁碟全滿事故已證明資源不足會真的壞事，不是官方門檻在自我保護過度 | sandbox / demo | 正式站台上線前依官方文件重新確認資源門檻 |
| — | Enrollment 使用套件出廠預設（`use_password=no`，開放式註冊，任何知道 IP 的 agent 都能自動註冊）。這對 sandbox/demo 足夠，正式站台若要防止未授權 agent 冒名註冊，應在 `<auth>` 加 `use_password=yes` 並透過 vault 分發密碼，屬於本 spec 範圍外的加固項目 | sandbox / demo | 正式站台上線前檢討 |
| — | 官方安裝腳本額外裝了 `wazuh-dashboard`（443 埠的 Web UI）；本任務的需求（FIM+who-data 告警產生 + CVE 掃描 + 轉送 SIEM）不需要它，但如 §1 說明，all-in-one 腳本目前沒有「裝 indexer+manager、跳過 dashboard」的單一旗標（分開裝的 `-wi`/`-ws`/`-wd` 是給多機叢集用，需要額外的 `-c config.yml`/`-g` 憑證產生流程，複雜度更高、風險更大）。多裝一個 dashboard 對這個 spec 的驗證目標無害，只是多用一些資源，不在本 spec 的 checklist 內驗證 | 所有環境 | 永久（設計如此的取捨，非暫時偏差） |

## 6. Playbook 對應

對應 apply playbook：`playbooks/apply/wazuh-manager-apply.yml`

| Spec ID | Apply task | 備註 |
|---------|------------|------|
| C1, C2 | `download wazuh-install.sh` → `run wazuh-install.sh -a -i`（只在 `wazuh-manager` 套件尚未安裝時執行一次，async 長時間執行） | 官方腳本，不手刻 apt install（見 §1 的理由） |
| C3, C4 | `ensure wazuh-manager/wazuh-indexer enabled+started` | 安裝腳本本身已 enable+start；這裡是冪等的二次確認 |
| C5, C6, C7 | 無獨立 apply task（安裝腳本出廠預設即滿足） | 只驗證，不管理 |
| C8 | 無獨立 apply task（純環境健檢） | apply 前應先確認磁碟規劃（§1），不是 apply 事後補救 |
| C9 | 無獨立 apply task（規則引擎的功能性自證，verify 時才觸發 `wazuh-logtest`） | — |
| C10 | `lineinfile /etc/hosts` pin `siem-log-server` | 必須在 `<syslog_output>` render 之前 |
| C11 | `lineinfile` 插入 `<syslog_output>` 區塊到 `ossec.conf`（檔案末端新增一個 `<ossec_config>` 區塊；實測確認 Wazuh 的 XML parser 允許同一份檔案有多個 `<ossec_config>` 根節點並全部合併，套件出廠設定本身也是這樣分兩段——見 §5 的說明與 `docs/runbooks/wazuh-manager.md` §5） | 只新增管理區塊，不動套件出廠的其餘預設設定 |

## 7. SOP

### 7.1 標準情境：log server 已存在（轉送啟用，驗證全部 11 條）

```bash
LOG_SERVER_IP=$(go run ./cmd/pilot vm-target show-inventory --name log-server \
    | awk '/ansible_host:/{print $2; exit}')

# 1. 起 VM —— 注意規格：60GB 磁碟 / 8192MB 記憶體 / 4 vCPU（見 §1、§5 磁碟事故）
go run ./cmd/pilot vm-target up --name wazuh-manager \
    --ssh-user ubuntu --disk 60 --memory 8192 --vcpus 4 \
    --ssh-timeout 8m --boot-timeout 8m

# 2. apply（官方安裝腳本跑起來要幾分鐘，playbook 內用 async 等待）
go run ./cmd/pilot vm-target run --name wazuh-manager \
    playbooks/apply/wazuh-manager-apply.yml \
    -e siem_forward_host=$LOG_SERVER_IP

# 3. verify
go run ./cmd/pilot vm-target verify --name wazuh-manager \
    docs/verification/wazuh-manager.md

# 4. 冪等檢查
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
