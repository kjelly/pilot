# Verification Spec — audit-log-forwarding（auditd 稽核規則 + rsyslog 轉送至 SIEM）

> 版本：v1.5
> 對齊規範：pilot 通用 config-only 服務規範；轉送目標為
> `docs/verification/log-server.md`（rsyslog 中央接收端），兩份 spec 搭配構成
> 一組 Shape 3（client+server）。
> 維護者：sre

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Hostname / Inventory group | audit-log-forwarding（vm-target 測試時用單一 host，見 §7） |
| OS / version | Ubuntu 24.04 LTS / AlmaLinux 9 |
| 角色 | 一般受管主機：本機 auditd 稽核（setuid/setgid、sudo、`/etc/passwd`、`/etc/sudoers`）+ rsyslog 轉送 `auth,authpriv.*`/`local6.*` 到中央 SIEM |
| 套用範圍 | `/etc/audit/rules.d/99-custom.rules`、`/etc/logrotate.d/{auditd,syslog}`（Debian 與 RedHat family 上都會另外從 distro 內建的 `/etc/logrotate.d/rsyslog` 移除重複的 `{{ audit_syslog_path }}` 宣告，見 C20）、`/etc/rsyslog.d/99-siem-forward.conf`、`/etc/hosts`（`siem-log-server` 別名） |
| 風險等級 | High（auditd 規則寫錯可能導致稽核死鎖或漏記；rsyslog 轉送設定錯誤只會漏送，不影響本機既有日誌） |

## 1.5 依賴變數契約

在套用或驗證此主機時，Playbook 與變數參數必須嚴格遵守以下命名，禁止擅自縮寫或發明新變數：

| 變數名稱 | 說明/用途 | 是否必填 | 預設值 |
|---------|----------|---------|--------|
| `siem_forward_host` | 中央 SIEM（`log-server`）的 IP 或 FQDN；套用時會被 pin 進 `/etc/hosts` 的 `siem-log-server` 別名 | 否 | 空字串（不轉送） |
| `siem_forward_port` | rsyslog 轉送目的埠（TCP，`@@`） | 否 | `514` |
| `audit_logrotate_rotate` | `/etc/logrotate.d/auditd` 保留檔案數 | 否 | `14` |
| `audit_logrotate_maxage` | `/etc/logrotate.d/auditd` `maxage`（天） | 否 | `90` |
| `syslog_logrotate_rotate` | `/etc/logrotate.d/syslog` 保留檔案數 | 否 | `14` |
| `syslog_logrotate_maxage` | `/etc/logrotate.d/syslog` `maxage`（天） | 否 | `90` |

> 為何轉送設定不直接把 `siem_forward_host` 的原始 IP 寫進
> `/etc/rsyslog.d/99-siem-forward.conf`：不同站台的 IP 不同，spec 的 Command/
> Expected 欄位在撰寫時是固定字串，無法內插執行期變數。做法是 apply
> playbook 先把 `siem_forward_host` pin 進 `/etc/hosts` 的固定別名
> `siem-log-server`，轉送設定一律用這個別名，spec 就能用固定字串驗證
> （C15/C16/C17），不受站台 IP 影響——與 `freeipa-client.md` 先 pin `/etc/hosts`
> 再enroll的做法同一個道理。
>
> **`siem_forward_host` 是選填（v1.1 起）**：log server 不一定先於 client 存在
> ——本機 auditd 稽核（C1–C14, C18）跟「是否有中央 SIEM」無關，應該獨立可用。
> 若套用時未提供 `siem_forward_host`（或給空字串），apply playbook 會跳過
> `/etc/hosts` pin（Step 6）與 `99-siem-forward.conf` 的產生（Step 7），只做
> 本機稽核；轉送相關的 C15–C17 這時就不適用（見 §5）。等 log server 就緒後，
> 用同一份 playbook 帶 `-e siem_forward_host=<log-server IP/FQDN>` 再跑一次即可
> 補上轉送，不需要重新安裝或重新套用稽核規則。

## 2. Checklist

| ID  | Category  | Check                                                                 | Expected | Command |
|-----|-----------|------------------------------------------------------------------------|----------|---------|
| C1  | package   | Ubuntu `auditd`／EL `audit` 已安裝                                     | 0        | if command -v rpm >/dev/null 2>&1; then rpm -q audit >/dev/null; else dpkg-query -W -f='${Status}\n' auditd 2>/dev/null | grep -qx 'install ok installed'; fi |
| C2  | package   | Ubuntu `audispd-plugins` 已安裝；EL8+ 的 audisp 由 `audit` 套件提供      | 0        | if command -v rpm >/dev/null 2>&1; then rpm -q audit >/dev/null; else dpkg-query -W -f='${Status}\n' audispd-plugins 2>/dev/null | grep -qx 'install ok installed'; fi |
| C3  | file      | 自訂稽核規則檔存在                                                      | present  | test -f /etc/audit/rules.d/99-custom.rules |
| C4  | rule      | setuid 提權執行監控規則存在（`euid!=uid` + `euid=0` execve）             | 0        | grep -qE '^-a always,exit .*-S execve .*-C uid!=euid .*-F euid=0' /etc/audit/rules.d/99-custom.rules; echo $? |
| C5  | rule      | setgid 提權執行監控規則存在（`egid!=gid` + `egid=0` execve）             | 0        | grep -qE '^-a always,exit .*-S execve .*-C gid!=egid .*-F egid=0' /etc/audit/rules.d/99-custom.rules; echo $? |
| C6  | rule      | setuid/setgid **變更**監控規則存在（`chmod`/`fchmod`/`fchmodat`）        | 0        | grep -qE '^-a always,exit .*-S (chmod|fchmod|fchmodat)' /etc/audit/rules.d/99-custom.rules; echo $? |
| C7  | rule      | `sudo` 執行監控規則存在                                                 | 0        | grep -qE '^-w /usr/bin/sudo -p x' /etc/audit/rules.d/99-custom.rules; echo $? |
| C8  | rule      | `/etc/passwd` 異動監控規則存在                                          | 0        | grep -qE '^-w /etc/passwd -p wa' /etc/audit/rules.d/99-custom.rules; echo $? |
| C9  | rule      | `/etc/sudoers` 異動監控規則存在                                         | 0        | grep -qE '^-w /etc/sudoers -p wa' /etc/audit/rules.d/99-custom.rules; echo $? |
| C10 | kernel    | 規則確實載入核心稽核清單（`auditctl -l` 含 `sudoers_changes` key）       | 0        | sh -c 'sudo auditctl -l 2>/dev/null | grep -q sudoers_changes; echo $?' |
| C11 | functional| 真的執行一次 `sudo` 後，`/var/log/audit/audit.log` 有對應的稽核事件記錄  | 0        | sh -c 'sudo -n true >/dev/null 2>&1; sleep 1; sudo grep -q "key=\"privileged-sudo\"" /var/log/audit/audit.log && echo 0 || echo 1' |
| C12 | file      | `/etc/logrotate.d/auditd` 存在                                         | present  | test -f /etc/logrotate.d/auditd |
| C13 | file      | `/etc/logrotate.d/syslog` 存在                                         | present  | test -f /etc/logrotate.d/syslog |
| C14 | logrotate | 兩份 logrotate 策略檔語法正確（dry-run 不出錯）                         | 0        | logrotate -d /etc/logrotate.d/auditd /etc/logrotate.d/syslog >/dev/null 2>&1; echo $? |
| C15 | forward   | `/etc/hosts` 已 pin `siem-log-server` 別名                             | 0        | getent hosts siem-log-server >/dev/null 2>&1; echo $? |
| C16 | forward   | 轉送設定含 `local6.*` → `siem-log-server` 的 TCP 轉送規則                | 0        | grep -qE '^local6\.\*[[:space:]]+@@siem-log-server:' /etc/rsyslog.d/99-siem-forward.conf; echo $? |
| C17 | forward   | 轉送設定含 `auth,authpriv.*` → `siem-log-server` 的 TCP 轉送規則         | 0        | grep -qE '^auth,authpriv\.\*[[:space:]]+@@siem-log-server:' /etc/rsyslog.d/99-siem-forward.conf; echo $? |
| C18 | service   | `auditd.service` 為 active                                             | 0        | systemctl is-active auditd >/dev/null 2>&1; echo $? |
| C19 | service   | `rsyslog.service` 為 active                                            | 0        | systemctl is-active rsyslog >/dev/null 2>&1; echo $? |
| C20 | logrotate | `/etc/logrotate.d/` 下沒有任何 log path 被兩份以上的 policy 檔重複宣告（不限於本模組管理的 auditd/syslog 兩個檔案，涵蓋 distro 內建的 `rsyslog` 等所有檔案） | 0        | sh -c 'test -z "$(grep -rhoE "^/[^ {]+" /etc/logrotate.d/ 2>/dev/null | sort | uniq -d)" && echo 0 || echo 1' |
| C21 | rule      | audisp-syslog plugin 已啟用且 facility 釘死 local6（沒有這條，local6 永遠不會有任何流量，跟轉送/接收設定是否正確無關） | 0        | sh -c 'grep -q "^active = yes" /etc/audit/plugins.d/syslog.conf && grep -q "^args = LOG_INFO LOG_LOCAL6" /etc/audit/plugins.d/syslog.conf && echo 0 || echo 1' |

> C1–C20 全部用**正邏輯 rc**（`; echo $?` 或原生 rc，C11 用
> `sh -c '... && echo 0 || echo 1'` 讓外層指令恆回 0），不用反邏輯 grep + 數字
> expected（見 `verification-spec-template.md` 陷阱 1）。
> C11 原本設計用 `ausearch -k privileged-sudo`，但實測（見 §7 SOP 的 vm-target
> 實跑）發現這個 Ubuntu 24.04 audit 版本的 enriched 欄位格式在
> `key="..."` 與下一個欄位（如 `ARCH=...`）之間**沒有空格**，導致
> `ausearch` 的 parser 找不到事件（即使 `/var/log/audit/audit.log` 裡明明有
> `key="privileged-sudo"`）。改成直接 `grep` 原始 `audit.log` 迴避這個
> ausearch 解析陷阱，且更直接（少一層查詢工具的行為依賴）。
> C4/C5 用 `-C uid!=euid`/`-C gid!=egid` + `-F euid=0`/`egid=0` 而非只看
> `-S execve`：只看 `-S execve` 會連完全不涉及 setuid/setgid 提權的一般
> 執行都算過，違背「setuid/setgid 執行監控」的字面需求。
> C10/C11 需要 root 才能讀 `/var/log/audit/audit.log`，Command 內明寫 `sudo`
> 而非依賴 ansible `become`，跟 `freeipa-server.md` C2 的 `sudo ipactl status`
> 同一個理由（inventory 的 `ansible_user` 不一定是 root）。
> **規則順序是硬約束**：核心稽核的 `-a always,exit` filterlist 由上到下
> 評估、**第一條符合就停**（像 iptables），不是「全部評估後合併」。
> `/usr/bin/sudo` 本身是 setuid-root binary，若把 C4/C5 的泛用
> setuid/setgid execve 規則排在 C7 的 `-w /usr/bin/sudo` 之前，所有 sudo
> 呼叫都會先被泛用規則吃掉、`key=privileged-sudo` 永遠不會出現——這是實測
> vm-target 時踩到的真實 bug（見 §7），修法是 `audit.rules.j2` 把
> sudo/passwd/sudoers 的**具體**規則放在 setuid/setgid **泛用**規則之前。

## 3. 證據收集

- 工具：`go run ./cmd/pilot vm-target verify --name <target> docs/verification/audit-log-forwarding.md`
- 輸出格式：`.verification/audit-log-forwarding-<UTC>.{ndjson,md}`
- 預期 row 數：21（C1–C21）

## 4. PASS / FAIL 規則

- 全部 C1–C21 `status=pass` → **PASS**
- 任一 `status=fail` → **FAIL**，列出 fail id + actual + want

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C10/C11/C16/C17 | 本 spec 只驗證「client 端規則正確載入 + 本機稽核事件正確產生 + 轉送設定正確指向別名」，**不**驗證「訊息真的被 log-server 收到」——那是跨主機 Shape 3 cross-check，做法見 `docs/runbooks/audit-log-forwarding.md` §4（在這台注入、去 log-server 讀檔驗證） | 所有環境 | 永久（設計如此，非暫時偏差） |
| C6 | `chmod`/`fchmod`/`fchmodat` 規則沒有加 `-F auid>=1000 -F auid!=unset`（CIS 常見寫法會加，用來排除系統自身的 chmod 呼叫），本 spec 選擇不排除，讓 sandbox 環境的驗證更單純；正式站台若稽核量太大可在規則加此過濾，但要同步改 C6 的 grep pattern | sandbox / 測試環境 | 正式站台上線前檢討 |
| C15, C16, C17 | 這三條的前提是套用時提供了 `siem_forward_host`（見 §1.5，v1.1 起選填）。若 log server 尚未存在、套用時未帶這個變數，playbook 會跳過轉送設定，C15–C17 在 `pilot verify` 會回報 `fail`（`/etc/hosts` 沒有別名、`99-siem-forward.conf` 不存在）——這是**預期行為**，不是 bug：此時應只驗證 C1–C14, C18–C20（本機稽核 + logrotate + auditd 服務），待 log server 就緒、補跑一次 apply 帶上 `siem_forward_host` 後再驗全部 20 條 | 無 log server 的獨立部署 / log server 尚未就緒的過渡期 | 補上 `siem_forward_host` 並重新 apply 後即解除 |

> **C20 的由來**：v1.2 的 C14 只對本模組自己管理的兩個檔案跑
> `logrotate -d /etc/logrotate.d/auditd /etc/logrotate.d/syslog`，範圍太窄，
> 抓不到「我們的檔案跟 distro 內建檔案互相衝突」這類跨檔案問題。實際 incident：
> Ubuntu 的 `rsyslog` 套件本身就內建 `/etc/logrotate.d/rsyslog`，預設也會列出
> `/var/log/syslog`（跟其他路徑如 `mail.log`/`kern.log`/`auth.log` 共用一個
> block）；本 playbook 的 Step 5 又另外 render 了 `/etc/logrotate.d/syslog`
> 管同一個路徑，兩份檔案對同一個 log path 重複宣告，logrotate 會直接中止
> **整台機器**的 rotation（`error: syslog:N duplicate log entry for
> /var/log/syslog`），不是只有我們自己的兩個檔案受影響。詳見
> `docs/runbooks/audit-log-forwarding.md` §5.5。C20 直接掃描
> `/etc/logrotate.d/` 整個目錄找重複路徑，才會抓到這類問題；C14 本身維持
> 原範圍不變（驗證的是我們自己兩個檔案的語法正確性，跟 §5.4 的
> insecure-permissions 教訓有關，換成掃全目錄反而會誤觸 distro 自己檔案
> 沒有 `su` 宣告的已知雜訊）。
>
> **v1.3 的修法一開始只蓋到 Debian family，v1.4 補上 RedHat family**：
> v1.3 的 Step 5a–5d 只在 `ansible_os_family == "Debian"` 時檢查
> `/etc/logrotate.d/rsyslog`。round-19 clean-room 重建（AlmaLinux 9 的
> `freeipa-server`）跑 C20 時當場抓到同一類 bug 也在 RedHat family 上發生：
> `rsyslog-logrotate` RPM 套件同樣把 `/etc/logrotate.d/rsyslog` 這個檔名
> 內建成一個共用 block（`cron`/`maillog`/`messages`/`secure`/`spooler`），
> 跟本模組 render 的 `/etc/logrotate.d/syslog`（此時 `audit_syslog_path`
> 已解析成 `/var/log/messages`）對同一路徑重複宣告，會踩到跟 Ubuntu 一樣的
> `duplicate log entry` 全機中止。修法：拿掉 Step 5a–5d 的
> `ansible_os_family` 條件，只靠 `distro_rsyslog_logrotate.stat.exists`
> 本身把關——因為兩個 family 內建檔案剛好都叫 `rsyslog`、都是「多行路徑 +
> 一個共用 block」的格式，同一套 `grep`/`lineinfile` 邏輯兩邊都適用。已在
> `freeipa-server` 實測 `--check --diff` 預覽、真套用、`changed=0` 冪等重跑
> 全部通過，C20 20/20 全綠（含 client-vm/nexus 兩台 Debian family）。

> **C21 的由來**：minimal-poc round 20（2026-08-07）對一個全新 clean-room
> 拓樸做深入 Loki/SIEM 查核時發現，即使 `log-server.md` 的接收端（TCP/514）
> 與本模組的 `99-siem-forward.conf` 轉送規則都已正確部署，三台主機上
> `/var/log/siem/<host>/audit.log` 仍然完全不存在——因為 Debian 與 EL9 的
> `audispd-plugins`（round 20 之前 RedHat family 的 Step 1a 沒裝這個套件，
> 只裝了 `audit`）都預設出貨 `/etc/audit/plugins.d/syslog.conf` 為
> `active = no`；沒有這一步，auditd 從來不會真的把任何事件放上 local6，
> 轉送/接收設定再正確也沒有東西可轉。Step 1a 補裝 `audispd-plugins`
> （RedHat family），新增 Step 6e/6f 把 `active` 打開、把 `args` 的
> facility 明確釘死 `LOG_LOCAL6`（plugin 的 man page 沒說沒給 facility 時
> 的預設值是什麼，不能賭），Step 8a 只在這兩個值真的改變時才 restart
> auditd。已在 round 20 的 3 台主機（AlmaLinux 9 + 2 台 Ubuntu 24.04）
> 實測：修前 `audit.log` 三台全無；修後三台皆產生，且 C21 直接 grep 驗證
> `active`/`args` 兩個值。

## 6. Playbook 對應

對應 apply playbook：`playbooks/apply/audit-log-forwarding-apply.yml`

| Spec ID | Apply task | 備註 |
|---------|------------|------|
| C1, C2 | `install auditd + audispd-plugins` | apt/dnf 依 `ansible_os_family` |
| C3–C9 | `template audit.rules.j2 → /etc/audit/rules.d/99-custom.rules` | 用 `ansible.builtin.template` 模組（非 inline copy），對應本任務明確要求 |
| C10 | `augenrules --load` | 規則檔改完要重新載入才會進 `auditctl -l` |
| C11 | 無獨立 apply task（規則生效後的功能性自證，verify 時才觸發 `sudo -n true`） | — |
| C12, C13, C14 | `template /etc/logrotate.d/{auditd,syslog}` | `rotate`/`maxage` 走 `audit_logrotate_*`/`syslog_logrotate_*` 變數 |
| C15 | `lineinfile /etc/hosts` pin `siem-log-server` | 必須在轉送設定 render 之前（同 freeipa-client `/etc/hosts` 先於 enroll 的教訓） |
| C16, C17 | `template 99-siem-forward.conf` | `auth,authpriv.*` + `local6.*` 都用 `@@`（TCP）轉送 |
| C18, C19 | `ensure auditd + rsyslog enabled+restarted` | rsyslog 只在轉送設定真的變更時才 restart |
| C20 | `stat` + `shell`（計算 distro rsyslog 檔還剩幾個其他路徑）+ `lineinfile`/`file`（Step 5a–5d，Debian 與 RedHat family 都跑，只看 `/etc/logrotate.d/rsyslog` 是否存在，不再用 `ansible_os_family` 額外過濾） | 只移除 `{{ audit_syslog_path }}` 這一行，其他路徑（Debian：`mail.log`/`kern.log`/`auth.log`...；RHEL：`cron`/`maillog`/`secure`/`spooler`...）留給 distro 自己的檔案繼續管；如果那份檔案原本就只列這一個路徑，改成整份移除，避免留下沒有檔名的空 block 讓 logrotate 解析失敗 |
| C21 | `lineinfile`（Step 6e/6f，打開 `active` + 釘死 `args` facility，兩者都在 `--check` 模式下跳過）+ `command`（Step 8c 用 `pgrep` 確認 plugin process 是否真的在跑）+ Step 8a（Debian，`systemd: state: restarted`）/ Step 8b（RedHat，`pkill -HUP -x auditd`，見上方 v1.5 說明為何不能用 `systemctl restart` 或 `service`） | RedHat family 的 Step 1a 同步補裝 `audispd-plugins`（EL9 上這是 `audit` 套件以外的獨立 RPM）；Step 8a/8b 的觸發條件同時看「這次有沒有改到檔案」跟「plugin process 是否真的在跑」，避免前一輪失敗的 apply 留下「檔案已對、但從未 reload」的殘留狀態 |

## 7. SOP

### 7.1 標準情境：log server 已存在（轉送啟用，驗證全部 20 條）

```bash
# 前置：log-server 必須先 apply（見 docs/verification/log-server.md §7）並記下其 IP
LOG_SERVER_IP=$(go run ./cmd/pilot vm-target show-inventory --name log-server \
    | awk '/ansible_host:/{print $2; exit}')

# 1. 起 client VM
go run ./cmd/pilot vm-target up --name audit-log-forwarding \
    --ssh-user ubuntu --disk 20 --memory 2048 --vcpus 2 \
    --ssh-timeout 8m --boot-timeout 8m

# 2. apply（siem_forward_host 指向 log-server 的當下 IP）
go run ./cmd/pilot vm-target run --name audit-log-forwarding \
    playbooks/apply/audit-log-forwarding-apply.yml \
    -e siem_forward_host=$LOG_SERVER_IP

# 3. verify（本機規則/服務/轉送設定，全部 20 條）
go run ./cmd/pilot vm-target verify --name audit-log-forwarding \
    docs/verification/audit-log-forwarding.md

# 4. 冪等檢查（重跑一次 apply，PLAY RECAP 應 changed=0）
go run ./cmd/pilot vm-target run --name audit-log-forwarding \
    playbooks/apply/audit-log-forwarding-apply.yml \
    -e siem_forward_host=$LOG_SERVER_IP

# 5. Shape 3 cross-check（在 client 注入一筆稽核事件的轉送測試訊息，
#    去 log-server 讀檔確認真的收到 —— 見 docs/runbooks/audit-log-forwarding.md §4）
go run ./cmd/pilot vm-target exec --name audit-log-forwarding -- \
    logger -p local6.info "PILOT-E2E-FORWARD-TEST"
sleep 2
go run ./cmd/pilot vm-target exec --name log-server -- \
    sudo grep -r "PILOT-E2E-FORWARD-TEST" /var/log/siem/
```

### 7.2 過渡情境：log server 尚不存在（只裝本機稽核，之後再補轉送）

```bash
# 1. apply 時不帶 siem_forward_host — 只做本機稽核 + logrotate，不轉送
go run ./cmd/pilot vm-target run --name audit-log-forwarding \
    playbooks/apply/audit-log-forwarding-apply.yml

# 2. verify（pilot verify 沒有「只驗證部分 row」的選項，會照跑全部 20 條；
#    C15-C17 這時預期回報 fail——屬設計如此，見 §5，判讀報告時忽略這三條，
#    只看 C1-C14, C18-C20 是否全 pass）
go run ./cmd/pilot vm-target verify --name audit-log-forwarding \
    docs/verification/audit-log-forwarding.md

# 3. 等 log server 就緒後，補一次 apply 帶上 siem_forward_host 即可補齊轉送，
#    不需要重裝 auditd 或重套用稽核規則（Step 1-5 都是冪等的）：
go run ./cmd/pilot vm-target run --name audit-log-forwarding \
    playbooks/apply/audit-log-forwarding-apply.yml \
    -e siem_forward_host=$LOG_SERVER_IP
```

> vm-target 的 inventory 只有單一 host key（見 `vm-target-basics.md`），
> playbook 的 `hosts:` 預設 `audit-log-forwarding` 與該 host key 同名，
> 不需要 `-e target_group=` override（同 `log-server.md` 的設計）。

## 8. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-06 | v1.0 | 初版：auditd 規則（setuid/setgid 變更+執行、sudo、passwd/sudoers 監控）+ logrotate + rsyslog 轉送至 `log-server.md` | sre |
| 2026-07-06 | v1.1 | `siem_forward_host` 改為選填：log server 不一定先於 client 存在，本機稽核（C1-C14, C18, C19）應獨立可用；未提供時 apply 跳過 `/etc/hosts` pin 與 `99-siem-forward.conf`，C15-C17 對應標記為已知偏差（§5），待 log server 就緒後補跑 apply 即可補齊轉送 | sre |
| 2026-07-22 | v1.2 | C1/C2 改為 Ubuntu dpkg 與 EL rpm 雙平台 probe；EL logrotate 使用 `/var/log/messages` 與 `root` group，避免不存在的 Ubuntu `syslog` group | sre |
| 2026-08-06 | v1.3 | 新增 C20：全目錄掃描 `/etc/logrotate.d/` 偵測跨檔案的重複 log path 宣告；修 5 台 Ubuntu 主機的真實 incident——`rsyslog` 套件內建的 `/etc/logrotate.d/rsyslog` 跟本模組自己的 `/etc/logrotate.d/syslog` 都宣告了 `/var/log/syslog`，logrotate 因此對全機 rotation 整個中止（`duplicate log entry`）；apply playbook Step 5a–5d 在 Debian family 上從 distro 檔案移除重複路徑（詳見 `docs/runbooks/audit-log-forwarding.md` §5.5） | sre |
| 2026-08-06 | v1.4 | round-19 minimal-poc clean-room 重建時，C20 在 AlmaLinux 9 的 `freeipa-server` 上當場抓到 v1.3 的修法漏了 RedHat family：`rsyslog-logrotate` RPM 同樣把 `/etc/logrotate.d/rsyslog` 內建成一個共用 block（`cron`/`maillog`/`messages`/`secure`/`spooler`），跟本模組 render 的 `/etc/logrotate.d/syslog`（`audit_syslog_path=/var/log/messages`）重複宣告，會踩到同一種全機 rotation 中止；拿掉 Step 5a–5d 的 `ansible_os_family == "Debian"` 限制，改成只靠 `distro_rsyslog_logrotate.stat.exists` 把關，兩個 family 共用同一套 `grep`/`lineinfile` 邏輯；已在 `freeipa-server` 實測 check-mode 預覽、真套用、`changed=0` 冪等重跑全部通過，C20 20/20 全綠 | sre |
| 2026-08-07 | v1.5 | 新增 C21：啟用 audisp-syslog plugin（EL9 補裝 `audispd-plugins`，Step 6e/6f 把 `/etc/audit/plugins.d/syslog.conf` 的 `active` 打開、`args` facility 釘死 `LOG_LOCAL6`，Step 8a/8b 條件式 restart auditd）。real incident：minimal-poc round 20 對一個全新 clean-room 拓樸做深入 Loki 查核時，即使接收端（`log-server.md`）與轉送規則（C15–C17）都已正確部署，三台主機的 `/var/log/siem/<host>/audit.log` 仍完全不存在——因為這個 plugin 出貨時預設停用，auditd 從未真的產生任何 local6 流量。修的過程中連續踩到四個子問題，都在同一組 3 台主機（AlmaLinux 9 + 2×Ubuntu 24.04）現場實測確認：(1) Step 6e/6f 一開始沒有 `when: not ansible_check_mode`，在套件真的還沒裝的主機上 `--check` 預覽會直接失敗（同檔案 Step 8 的 auditd 啟動早就有這個 guard，這次沒套用到新任務上）；(2) AlmaLinux/RHEL 的 `auditd.service` 出貨 `RefuseManualStop=yes`，`ansible.builtin.systemd: state: restarted`（本質是 stop 再 start）的 stop 那一半會被系統拒絕，錯誤訊息是 `Operation refused, unit auditd.service may be requested by dependency only`；(3) 原本想改用 RHEL 傳統的 `service auditd restart` SysV wrapper 繞過限制，但 minimal EL9 image 根本沒裝 `initscripts`/`chkconfig`，`service` 這支指令完全不存在（`command not found`）；改成直接送 `SIGHUP` 給 auditd（`man auditd(8)` SIGNALS 明載「SIGHUP causes auditd to reconfigure」，訊號直接送給 process，完全不經過 systemd 的 stop 路徑，`RefuseManualStop` 對它沒有作用），實測送出後 audisp-syslog plugin process 確實重新起來、一筆真實 audit 事件（SSH session open）立刻被轉送到中央 SIEM；(4) 光靠「這次 apply 有沒有改到檔案」判斷要不要 reload 不夠：上一輪失敗的 apply 已經把 `active`/`args` 改好、但在真正 reload 之前就因為問題 (2) 而 rescue 中止，導致下一輪重跑時 lineinfile 兩個 task 都回報 unchanged（檔案本來就對了），Step 8a/8b 的 reload 就永遠不會觸發——即使 apply 回報 `failed=0`、看起來全綠，auditd 實際上仍在用舊設定跑，plugin 從未真的生效。新增 Step 8c 直接檢查 `audisp-syslog` process 是否真的在跑（`pgrep -x audisp-syslog`），跟檔案是否改變並列進 Step 8a/8b 的觸發條件，讓 reload 判斷不再只依賴這次 run 自己的異動旗標 | sre |
