# Verification Spec — audit-log-forwarding（auditd 稽核規則 + rsyslog 轉送至 SIEM）

> 版本：v1.1
> 對齊規範：pilot 通用 config-only 服務規範；轉送目標為
> `docs/verification/log-server.md`（rsyslog 中央接收端），兩份 spec 搭配構成
> 一組 Shape 3（client+server）。
> 維護者：sre

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Hostname / Inventory group | audit-log-forwarding（vm-target 測試時用單一 host，見 §7） |
| OS / version | Ubuntu 24.04 LTS |
| 角色 | 一般受管主機：本機 auditd 稽核（setuid/setgid、sudo、`/etc/passwd`、`/etc/sudoers`）+ rsyslog 轉送 `auth,authpriv.*`/`local6.*` 到中央 SIEM |
| 套用範圍 | `/etc/audit/rules.d/99-custom.rules`、`/etc/logrotate.d/{auditd,syslog}`、`/etc/rsyslog.d/99-siem-forward.conf`、`/etc/hosts`（`siem-log-server` 別名） |
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
| C1  | package   | `auditd` 已安裝                                                        | 0        | dpkg -s auditd >/dev/null 2>&1; echo $? |
| C2  | package   | `audispd-plugins` 已安裝                                               | 0        | dpkg -s audispd-plugins >/dev/null 2>&1; echo $? |
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

> C1–C19 全部用**正邏輯 rc**（`; echo $?` 或原生 rc，C11 用
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
- 預期 row 數：19（C1–C19）

## 4. PASS / FAIL 規則

- 全部 C1–C19 `status=pass` → **PASS**
- 任一 `status=fail` → **FAIL**，列出 fail id + actual + want

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C10/C11/C16/C17 | 本 spec 只驗證「client 端規則正確載入 + 本機稽核事件正確產生 + 轉送設定正確指向別名」，**不**驗證「訊息真的被 log-server 收到」——那是跨主機 Shape 3 cross-check，做法見 `docs/runbooks/audit-log-forwarding.md` §4（在這台注入、去 log-server 讀檔驗證） | 所有環境 | 永久（設計如此，非暫時偏差） |
| C6 | `chmod`/`fchmod`/`fchmodat` 規則沒有加 `-F auid>=1000 -F auid!=unset`（CIS 常見寫法會加，用來排除系統自身的 chmod 呼叫），本 spec 選擇不排除，讓 sandbox 環境的驗證更單純；正式站台若稽核量太大可在規則加此過濾，但要同步改 C6 的 grep pattern | sandbox / 測試環境 | 正式站台上線前檢討 |
| C15, C16, C17 | 這三條的前提是套用時提供了 `siem_forward_host`（見 §1.5，v1.1 起選填）。若 log server 尚未存在、套用時未帶這個變數，playbook 會跳過轉送設定，C15–C17 在 `pilot verify` 會回報 `fail`（`/etc/hosts` 沒有別名、`99-siem-forward.conf` 不存在）——這是**預期行為**，不是 bug：此時應只驗證 C1–C14, C18–C19（本機稽核 + logrotate + auditd 服務），待 log server 就緒、補跑一次 apply 帶上 `siem_forward_host` 後再驗全部 19 條 | 無 log server 的獨立部署 / log server 尚未就緒的過渡期 | 補上 `siem_forward_host` 並重新 apply 後即解除 |

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

## 7. SOP

### 7.1 標準情境：log server 已存在（轉送啟用，驗證全部 19 條）

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

# 3. verify（本機規則/服務/轉送設定，全部 19 條）
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

# 2. verify（pilot verify 沒有「只驗證部分 row」的選項，會照跑全部 19 條；
#    C15-C17 這時預期回報 fail——屬設計如此，見 §5，判讀報告時忽略這三條，
#    只看 C1-C14, C18, C19 是否全 pass）
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
