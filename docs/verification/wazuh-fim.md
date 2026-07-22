# Verification Spec — wazuh-fim（Wazuh agent：檔案完整性監控 FIM + auditd who-data）

> 版本：v1.2
> 對齊規範：pilot 通用 config-only 服務規範；註冊目標為
> `docs/verification/wazuh-manager.md`（Wazuh 中央伺服器），兩份 spec 搭配構成
> 一組 Shape 3（agent+server）；`wazuh-manager.md` 再選填轉送至
> `docs/verification/log-server.md`，三份合起來是完整的 agent → manager → SIEM
> 鏈路。
> 維護者：sre

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Hostname / Inventory group | wazuh-fim（vm-target 測試時用單一 host，見 §7） |
| OS / version | Ubuntu 24.04 LTS |
| 角色 | 一般受管主機：Wazuh agent，對可設定的目錄清單（預設 `/etc`、`/boot`）做即時檔案完整性監控（FIM），搭配 auditd 取得 who-data（誰在什麼時候用什麼程序改了檔案），並向中央 Wazuh manager 註冊回報 |
| 套用範圍 | `/etc/apt/sources.list.d/wazuh.list`、`/var/ossec/etc/ossec.conf`（`<syscheck>` 新增 whodata 監控目錄、`<client><server><address>`）、`/etc/hosts`（`wazuh-manager` 別名）、`/var/ossec/etc/client.keys`（註冊憑證） |
| 風險等級 | High（FIM 規則設定錯誤會漏判未授權變更；未成功註冊等於這台主機的告警完全送不出去） |

## 1.5 依賴變數契約

在套用或驗證此主機時，Playbook 與變數參數必須嚴格遵守以下命名，禁止擅自縮寫或發明新變數：

| 變數名稱 | 說明/用途 | 是否必填 | 預設值 |
|---------|----------|---------|--------|
| `wazuh_manager_host` | 中央 Wazuh manager（`wazuh-manager` 角色）的 IP 或 FQDN；套用時會被 pin 進 `/etc/hosts` 的 `wazuh-manager` 別名，並用於 agent 註冊（`agent-auth`） | 否 | 空字串（不註冊） |
| `wazuh_fim_directories` | FIM whodata 監控的目錄清單（list）；**可依主機覆寫**，讓不同主機監控不同路徑（例：web 主機加 `/var/www`，DB 主機加 `/etc/mysql`） | 否 | `["/etc", "/boot"]` |
| `wazuh_repo_channel` | `packages.wazuh.com` apt repo 版本 channel | 否 | `4.x` |

> **`wazuh_manager_host` 選填**：跟 `audit-log-forwarding.md` 的 `siem_forward_host`
> 同一個設計理由——manager 不一定先於 agent 存在。未提供時，apply 仍會安裝
> `wazuh-agent` + auditd、把 FIM whodata 規則寫進 `ossec.conf`，只是跳過
> `/etc/hosts` 的 `wazuh-manager` 別名 pin 與 `agent-auth` 註冊（C7–C9 這時
> 不適用，見 §5）；`ossec.conf` 的 `<client><server><address>` 會 fallback
> 成 `127.0.0.1`（純佔位，agent 服務仍會啟動，只是連不到任何 manager，事件
> 會在本機排隊）。等 manager 就緒後，帶
> `-e wazuh_manager_host=<manager IP/FQDN>` 重新套用即可補上註冊，不需要
> 重裝 agent 或重寫 FIM 規則。
>
> 為何不直接把 `wazuh_manager_host` 的原始 IP 寫進 `ossec.conf`：跟
> `audit-log-forwarding.md` 的 `siem_forward_host` 同一個理由——不同站台
> manager IP 不同，spec 的 Command/Expected 欄位是固定字串，無法內插執行期
> 變數。做法是 apply playbook 先把 `wazuh_manager_host` pin 進 `/etc/hosts`
> 的固定別名 `wazuh-manager`，`<address>` 一律用這個別名，spec 就能用固定
> 字串驗證（C8），不受站台 IP 影響。
>
> **`wazuh_fim_directories` 可依主機覆寫（v1.1 起）**：不同角色的主機通常要
> 盯不同的路徑——這點跟 `wazuh_manager_host`/`siem_forward_host` 不一樣，
> 不是「有沒有」的二元選填，是「每台主機的值可能都不同」。這正是本 spec
> 的 C5/C6 從 v1.0 的「檢查字面上是不是 `/etc`」改成 v1.1「檢查有沒有至少
> 一個目錄被設定 whodata」的原因：spec 的 Command/Expected 欄位是**跨所有
> 適用主機共用的固定字串**，一旦目錄清單允許逐主機不同，就不能再用
> `grep '.../etc</directories>'` 這種綁死特定路徑字面值的檢查，否則覆寫了
> 清單的主機會非預期地 fail。實際監控了哪些路徑，去讀該主機的
> `group_vars`/`host_vars`（或直接 `sudo grep 'check_all="yes"
> whodata="yes"' /var/ossec/etc/ossec.conf` 看 apply 後的真實結果），不是
> 這份通用 spec 的驗證責任——這份 spec 只保證「不管清單是什麼，FIM whodata
> 機制本身確實有生效」。

## 2. Checklist

| ID  | Category  | Check                                                                 | Expected | Command |
|-----|-----------|------------------------------------------------------------------------|----------|---------|
| C1  | package   | `wazuh-agent` 已安裝                                                   | 0        | if command -v rpm >/dev/null 2>&1; then rpm -q wazuh-agent >/dev/null; else dpkg-query -W -f='${Status}\n' wazuh-agent 2>/dev/null | grep -qx 'install ok installed'; fi |
| C2  | package   | `auditd`／EL `audit` 已安裝（who-data provider 依賴）                   | 0        | if command -v rpm >/dev/null 2>&1; then rpm -q audit >/dev/null; else dpkg-query -W -f='${Status}\n' auditd 2>/dev/null | grep -qx 'install ok installed'; fi |
| C3  | service   | `wazuh-agent.service` 為 active                                        | 0        | systemctl is-active wazuh-agent >/dev/null 2>&1; echo $? |
| C4  | service   | `auditd.service` 為 active                                             | 0        | systemctl is-active auditd >/dev/null 2>&1; echo $? |
| C5  | config    | 至少一個目錄設定了 FIM + whodata（`check_all="yes" whodata="yes"`，不綁定特定路徑——見 §1.5） | 0 | grep -qE '<directories check_all="yes" whodata="yes">' /var/ossec/etc/ossec.conf; echo $? |
| C6  | config    | who-data provider 為 `audit`（明確宣告，不依賴套件預設）                | 0        | grep -qE '<provider>audit</provider>' /var/ossec/etc/ossec.conf; echo $? |
| C7  | register  | `/etc/hosts` 已 pin `wazuh-manager` 別名                               | 0        | getent hosts wazuh-manager >/dev/null 2>&1; echo $? |
| C8  | register  | `ossec.conf` 的 `<address>` 指向 `wazuh-manager` 別名                  | 0        | grep -qE '<address>wazuh-manager</address>' /var/ossec/etc/ossec.conf; echo $? |
| C9  | register  | 已完成向 manager 註冊（`client.keys` 非空）                             | 0        | sh -c 'test -s /var/ossec/etc/client.keys && echo 0 || echo 1' |

> C1–C9 全部用**正邏輯 rc**（`; echo $?` 或原生 rc），C9 用
> `sh -c '... && echo 0 || echo 1'` 讓外層指令恆回 0，避免「未註冊」的合法
> FAIL 判定結果被 ansible ad-hoc 誤判成 task FAILED（見
> `verification-spec-template.md` 陷阱 1）。
> C5（v1.1 起）刻意不檢查特定路徑字面值，只檢查「至少一個 whodata 目錄」
> ——真正監控了哪些路徑是逐主機可變的（`wazuh_fim_directories`，見 §1.5），
> 不是這份通用 spec 能用固定字串驗證的東西。v1.0 原本分開檢查 `/etc`
> （C5）跟 `/boot`（C6）兩條，v1.1 合併成一條、把原本的 C7（provider 檢查）
> 遞補成 C6，後面的 register 系列（原 C8/C9/C10）依序遞補成 C7/C8/C9——
> **這是一次 row ID 重排**，舊版證據/文件裡的 C7-C10 對應到這版的 C6-C9，
> 引用時注意版本。
> **真正的 FIM+who-data 端到端證明**（在這台改監控目錄底下的檔案 → manager
> 產生的告警含 who-data 欄位如操作者/程序 → 轉送到 log-server 落地）不放進
> 本 spec，是跨主機 Shape 3 cross-check，做法見
> `docs/runbooks/wazuh-fim.md` §4（在這台觸發變更、去 manager 讀 alerts 驗證、
> 再去 log-server 讀檔驗證轉送）。

## 3. 證據收集

- 工具：`go run ./cmd/pilot vm-target verify --name wazuh-fim docs/verification/wazuh-fim.md`
- 輸出格式：`.verification/wazuh-fim-<UTC>.{ndjson,md}`
- 預期 row 數：9（C1–C9）

## 4. PASS / FAIL 規則

- 全部 C1–C9 `status=pass` → **PASS**
- 任一 `status=fail` → **FAIL**，列出 fail id + actual + want

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C7, C8, C9 | 這三條的前提是套用時提供了 `wazuh_manager_host`（見 §1.5，選填）。若 manager 尚未存在、套用時未帶這個變數，playbook 會跳過 `/etc/hosts` pin 與註冊，C7–C9 在 `pilot verify` 會回報 `fail`——這是**預期行為**，不是 bug：此時應只驗證 C1–C6（本機 FIM 規則 + 服務），待 manager 就緒、補跑一次 apply 帶上 `wazuh_manager_host` 後再驗全部 9 條 | 無 manager 的獨立部署 / manager 尚未就緒的過渡期 | 補上 `wazuh_manager_host` 並重新 apply 後即解除 |
| C9 | 本 spec 只驗證「client.keys 非空」（agent 端已取得憑證），**不**驗證「manager 端也認得這把憑證、連線真的建立成功」——那需要去 manager 端跑 `agent_control -l` 或看 `wazuh-remoted` 的連線狀態，屬於跨主機 Shape 3 cross-check，做法見 `docs/runbooks/wazuh-fim.md` §4 | 所有環境 | 永久（設計如此，非暫時偏差） |
| C5 | 只驗證「至少一個目錄設定 whodata」，不驗證特定站台實際監控的路徑清單是否符合預期（那是逐主機的 `wazuh_fim_directories` 設定責任，見 §1.5）；若要確保某台主機**一定**監控了某個特定路徑，需要另外針對該主機寫查核（例如部署後手動 `grep` 確認），不在本通用 spec 範圍內 | 所有環境 | 永久（設計如此，非暫時偏差） |
| — | Enrollment 使用開放式註冊（manager 端 `use_password=no` 出廠預設），見 `wazuh-manager.md` §5 對應說明 | sandbox / demo | 正式站台上線前檢討 |

## 6. Playbook 對應

對應 apply playbook：`playbooks/apply/wazuh-fim-apply.yml`

| Spec ID | Apply task | 備註 |
|---------|------------|------|
| C1 | `add wazuh apt repo + GPG key` → `install wazuh-agent` | apt-only |
| C2 | `install auditd` | who-data provider=audit 的執行期依賴 |
| C3 | `ensure wazuh-agent enabled+started` | 只在設定檔真的變更或剛完成註冊時才重啟 |
| C4 | `ensure auditd enabled+started` | — |
| C5, C6 | `blockinfile` 附加一個新的 `<ossec_config><syscheck>...</syscheck></ossec_config>` 區塊到 `ossec.conf` 檔案末端，`<directories>` 清單用 Jinja loop 依 `wazuh_fim_directories` 逐項展開 | 實測確認 Wazuh 的 XML parser 允許同一份檔案有多個 `<ossec_config>` 根節點並全部合併（套件出廠設定本身也是這樣分兩段），且對同一路徑重複宣告時會**聯集**選項（原本的 `scheduled` 疊加我們新增的 `whodata`），不會互相覆蓋或衝突——見 `docs/runbooks/wazuh-fim.md` §5。只新增管理區塊，不動套件出廠的其餘 `<syscheck>` 預設設定 |
| C7 | `lineinfile /etc/hosts` pin `wazuh-manager` | 必須在改 `<address>` 之前 |
| C8 | `lineinfile` 改 `ossec.conf` 的 `<address>` | 套件出廠預設只有一個 `<address>` 標籤，可安全用單一 regex 取代 |
| C9 | `agent-auth -m wazuh-manager`（只在 `client.keys` 為空且 manager 已提供時執行一次） | 非「每次都跑」，避免每次 apply 都重新註冊、破壞冪等性 |

## 7. SOP

### 7.1 標準情境：manager 已存在（註冊啟用，驗證全部 9 條）

```bash
MANAGER_IP=$(go run ./cmd/pilot vm-target show-inventory --name wazuh-manager \
    | awk '/ansible_host:/{print $2; exit}')

# 1. 起 client VM
go run ./cmd/pilot vm-target up --name wazuh-fim \
    --ssh-user ubuntu --disk 20 --memory 2048 --vcpus 2 \
    --ssh-timeout 8m --boot-timeout 8m

# 2. apply（預設目錄清單：/etc、/boot）
go run ./cmd/pilot vm-target run --name wazuh-fim \
    playbooks/apply/wazuh-fim-apply.yml \
    -e wazuh_manager_host=$MANAGER_IP

# 2a. 或者:自訂這台主機要監控的路徑(例:web 主機多盯 /var/www)
go run ./cmd/pilot vm-target run --name wazuh-fim \
    playbooks/apply/wazuh-fim-apply.yml \
    -e wazuh_manager_host=$MANAGER_IP \
    -e '{"wazuh_fim_directories": ["/etc", "/boot", "/var/www"]}'

# 3. verify
go run ./cmd/pilot vm-target verify --name wazuh-fim \
    docs/verification/wazuh-fim.md

# 4. 冪等檢查（重跑一次，PLAY RECAP 應 changed=0，且不會重新註冊）
go run ./cmd/pilot vm-target run --name wazuh-fim \
    playbooks/apply/wazuh-fim-apply.yml \
    -e wazuh_manager_host=$MANAGER_IP

# 5. Shape 3 cross-check（見 docs/runbooks/wazuh-fim.md §4 的完整鏈路）
go run ./cmd/pilot vm-target exec --name wazuh-fim -- \
    sudo sh -c 'echo "# PILOT-FIM-SELFTEST" >> /etc/pilot-fim-selftest.conf'
```

> 真實 inventory 部署時，`wazuh_fim_directories` 不要每次用 `-e` 帶——放進
> 該主機的 `host_vars/<hostname>.yml`（一次設定，永久生效），見
> `group_vars/wazuh-fim.example.yml` 的說明。

### 7.2 過渡情境：manager 尚不存在（先裝 agent + FIM 規則，之後再補註冊）

```bash
go run ./cmd/pilot vm-target run --name wazuh-fim \
    playbooks/apply/wazuh-fim-apply.yml
# verify 時 C7-C9 預期 fail（見 §5），只看 C1-C6 是否全 pass

# 之後 manager 就緒：
go run ./cmd/pilot vm-target run --name wazuh-fim \
    playbooks/apply/wazuh-fim-apply.yml \
    -e wazuh_manager_host=$MANAGER_IP
```

> vm-target 的 inventory 只有單一 host key（見 `vm-target-basics.md`），
> playbook 的 `hosts:` 預設 `wazuh-fim` 與該 host key 同名，不需要
> `-e target_group=` override（同 `log-server.md`/`audit-log-forwarding.md` 的設計）。

## 8. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-06 | v1.0 | 初版：Wazuh agent FIM（`/etc`、`/boot` whodata）+ auditd who-data provider + 向 `wazuh-manager.md` 註冊 | sre |
| 2026-07-06 | v1.1 | `wazuh_fim_directories` 改為可依主機覆寫的變數清單（不同主機可監控不同路徑），預設仍是 `["/etc", "/boot"]`；對應把 C5/C6（原本各自綁死 `/etc`/`/boot` 字面值）合併成單一「至少一個 whodata 目錄」的通用檢查，原 C7-C10 遞補成 C6-C9（row 數 10 → 9），見 §1.5、§2 的重排說明 | sre |
| 2026-07-22 | v1.2 | C1/C2 package probe 改為 Ubuntu dpkg 與 EL rpm 雙平台；相同候選指令已在 Ubuntu 24.04 與 AlmaLinux 9 的目標 inventory 實跑通過 | sre |
