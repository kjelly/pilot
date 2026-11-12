# Verification Spec — audit-log-forwarding（auditd 稽核規則 + rsyslog 轉送至 SIEM）

> 版本：v2.2
> 對齊規範：pilot 通用 config-only 服務規範；轉送目標為
> `docs/verification/log-server.md`（rsyslog 中央接收端），兩份 spec 搭配構成
> 一組 Shape 3（client+server）。
> 維護者：sre

> 最後驗證（TCP 鏈與 C20 distro policy 改寫，PR #188）：2026-10-30，candidate
> `c97caf38cb0694274b65a5e2a07537fafe69421e`，tree `c13922899fc1bfaa26ec5f496c3d626b3202f86a`。
> 全新三機 L3/L4 通過，receiver 11/11、sender 66/66、L6 三台 changed=0；單獨的
> `/var/log/syslog` stanza（BASE 重現事故、本版不會）、glob 在 Step 1d 拒絕（真實與 `--check`）、
> EL 只剩一個路徑時移除檔案、保留 mode/owner/group 與 symlink 均通過。
> [完整驗證摘要](../evidence/audit-log-forwarding/2026-10-30-c97caf38cb06.md)。
> RELP/mTLS 最後驗證於 `34cfabea416eb9645aaa323e541198ae39bbbe96`，本輪未重跑，
> [該次摘要](../evidence/siem-relp-mtls/2026-10-20-34cfabe-review.md)。
>
> v2.1（issue #324：C23，本模組不再讓同機 Wazuh 的 `wazuh_fim` 稽核 watch 在每次套用時消失）
> 的 sanitized 驗證摘要由後續的 evidence-only commit 記錄；上面的驗證摘要是 v2.1 之前的 candidate，
> 不涵蓋這次變更。§5 的實測事實來自 2026-11-12 的拋棄式 Ubuntu 24.04.4 與 AlmaLinux 9.8 VM。

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Hostname / Inventory group | audit-log-forwarding（vm-target 測試時用單一 host，見 §7） |
| OS / version | Ubuntu 24.04 LTS / AlmaLinux 9 |
| 角色 | 一般受管主機：本機 auditd 稽核（setuid/setgid、sudo、`/etc/passwd`、`/etc/sudoers`）+ rsyslog 轉送 `auth,authpriv.*`/`local6.*` 到中央 SIEM |
| 套用範圍 | `/etc/audit/rules.d/99-custom.rules`、`/etc/logrotate.d/{auditd,syslog}`（Debian 與 RedHat family 上都會另外從 distro 內建的 `/etc/logrotate.d/rsyslog` 移除重複的 `{{ audit_syslog_path }}` 宣告，見 C20）、`/etc/rsyslog.d/99-siem-forward.conf`、`/etc/hosts`（`siem-log-server` 別名） |
| 風險等級 | High（auditd 規則寫錯可能導致稽核死鎖或漏記；rsyslog 轉送設定錯誤或佇列耗盡可能漏送，佇列滿時的 backpressure 也可能延遲本機日誌） |

## 1.5 依賴變數契約

在套用或驗證此主機時，Playbook 與變數參數必須嚴格遵守以下命名，禁止擅自縮寫或發明新變數：

| 變數名稱 | 說明/用途 | 是否必填 | 預設值 |
|---------|----------|---------|--------|
| `siem_forward_host` | 中央 SIEM（`log-server`）的 IP 或 FQDN；套用時會被 pin 進 `/etc/hosts` 的 `siem-log-server` 別名 | 否 | 空字串（不轉送） |
| `siem_forward_port` | rsyslog `omfwd` 轉送目的埠（TCP） | 否 | `514` |
| `siem_forward_transport` | `tcp` 或 `relp`；RELP 強制 mTLS，連線失敗不得降回 TCP | 否 | `tcp` |
| `siem_relp_port` | RELP 專用 TCP 埠；不改變共用的 `siem_forward_port` | 否 | `20514` |
| `siem_relp_ca_pem` | 信任 CA 的 PEM；由部署端提供，不自動簽發或信任未知 CA | RELP 必填 | — |
| `siem_relp_cert_pem` | 本機 client 憑證 PEM（同機兼 receiver 時須有雙用途） | RELP 必填 | — |
| `siem_relp_key_pem` | 對應的未加密私鑰 PEM；只從 vault/私密變數提供，禁止提交 | RELP 必填 | — |
| `siem_relp_server_name` | 接收端憑證的精確小寫 DNS 名稱，不接受 wildcard | RELP 必填 | — |
| `audit_logrotate_rotate` | `/etc/logrotate.d/auditd` 保留檔案數 | 否 | `14` |
| `audit_logrotate_maxage` | `/etc/logrotate.d/auditd` `maxage`（天） | 否 | `90` |
| `syslog_logrotate_rotate` | `/etc/logrotate.d/syslog` 保留檔案數 | 否 | `14` |
| `syslog_logrotate_maxage` | `/etc/logrotate.d/syslog` `maxage`（天） | 否 | `90` |

> v2.1 起 re-arm 另有三個只能用 `-e` 覆寫、**不是** inventory 輸入的旋鈕（不在上表，也不進 contract 的
> `groupVars`）：`audit_whodata_endpoint_timeout`（等 auditd 與 Wazuh endpoint 回來的上限，預設 30 秒）、
> `audit_whodata_watch_timeout`（重啟 `wazuh-agent` 之後等 `wazuh_fim` watch 回來的上限，預設 60 秒）、
> `audit_whodata_poll_interval`（輪詢間隔，預設 1 秒）。預設值寫在 `tasks/audit-whodata-rearm.yml`，
> 測試用它把上限縮短；正式站台不需要設定。
>
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

Queue-engine acceptance: RELP → TCP → RELP must retain an explicit classic
engine for both actions, including when the TCP receiver is unavailable and
shutdown must spool in-memory messages. Enabling RELP from an existing unpinned
TCP configuration must refuse before changing TLS/config or restarting rsyslog
unless both queues have positive classic-format evidence. An empty spool is not
proof: an auto-selected engine can first materialize during shutdown. Existing
legacy TCP configuration remains compatible; queue migration is operator-managed.

RELP/mTLS acceptance contract: both OS families must
reject untrusted/expired certificates, missing client certificates and incorrect
peer names; a TCP listener without RELP ACK must not pass C22. Normal receiver
restart, confirmed outage, and disk-spill followed by a clean client restart must
recover every numbered ID, with duplicates counted separately. Existing TCP
configuration remains supported. TLS material changes must reload the daemon;
failed validation must restore the previous keys and configuration. Removing the
role removes its private TLS material and helper, while pending audit spool stays.
After a real daemon rejects an incorrect server certificate, correcting the peer
must drain the numbered backlog without restarting the sender. Removing a client
from the permitted-name list must deny it; restoring the name must resume it.
Rotating same-name leaf certificates/keys must take effect and remain idempotent.
Explicitly switching back to TCP retires private RELP keys after loading TCP.
Sudden power loss, exhausted storage and downstream Loki durability are outside
this transport contract; RELP ACK does not imply final-file fsync. Production PKI
issuance/renewal is operator-managed; tests use an isolated disposable CA.
The contract starts at accepted client rsyslog messages. mTLS authenticates the
transport peer; existing `%HOSTNAME%` payload-based routing is preserved and is
not a cryptographic binding between a certificate and every message's hostname.
RELP session/connection timeouts are 5/3 seconds; its action queues allow
1 second of shutdown drain and 10 seconds for the current action to finish,
so self-forwarding must not inherit the module's 90-second session wait.
RELP senders must support `tls.permanentFailureDisablesAction="off"` and
`queue.diskQueueType="disk"` (upstream 8.2608.0+ or an equivalent vendor backport).
The established classic disk engine is explicit; experimental segmented auto
selection is outside this contract. Existing segmented stores or unknown engine
markers must fail before replacing TLS/config, preserving all backlog for an
operator-approved migration. Otherwise TLS authentication errors
can permanently disable forwarding and discard later messages despite unlimited
retries. Unsupported modules must fail before TLS/config replacement. Production
repository selection/upgrades are operator-managed; pilot does not silently add
upstream repositories. Check mode defers this installed-module capability check.

C16/C17 的 probe 會驗證兩個 action 的目標、TCP 埠、完整 queue/retry 參數，
比對設定檔寫入時間與服務啟動時間，並在注入對應 facility 訊息後讀取服務
process 的 `/proc/<pid>/task/*/comm`，確認獨立 queue worker 確實存在。
全域語法檢查由 apply 的 `rsyslogd -N1` 在重啟前執行；verify 不會重啟服務。

每個 action 的記憶體佇列上限為 10,000 筆，達 8,000 筆開始落盤、降至 2,000 筆
回到記憶體；各有固定且互不相同的檔名前綴，磁碟預算各 256 MiB（rsyslog 可超出
一筆完整記錄），單檔 1 MiB。spool 位於 Ubuntu 的
`/var/spool/rsyslog/pilot-siem`、EL 的 `/var/lib/rsyslog/pilot-siem`，由 rsyslog
執行帳號擁有、權限 0700。乾淨關機保存待送訊息；重試次數不限，間隔從 1 秒開始、
最長 10 秒。不因低 severity 主動丟棄，但有限容量用盡時仍會受 enqueue timeout
限制；應監控該檔案系統的可用空間。decommission 保留 spool 中的稽核歷史。

預設 TCP 模式沒有接收端持久化 ACK；`ResendLastMSGOnReconnect` 可重送
最後一筆，也可能造成重複。不能保證斷線瞬間在途訊息、斷電或長到耗盡容量的中斷
零遺失。跨主機驗收需分別統計 unique ID、遺失與重複，並涵蓋持續送訊息時重啟
接收端、確認停機後送訊息，以及落盤後在接收端仍停機時乾淨重啟 client。

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
| C16 | forward   | `local6.*` 的有界磁碟輔助佇列與持續重試設定正確；設定已載入，注入訊息後服務內有對應的獨立 queue worker | 0 | sudo /usr/local/libexec/pilot-siem-queue-check local6; echo $? |
| C17 | forward   | `auth,authpriv.*` 使用另一個有界磁碟輔助佇列；設定已載入，注入兩種 facility 後服務內有對應的獨立 queue worker | 0 | sudo /usr/local/libexec/pilot-siem-queue-check auth authpriv; echo $? |
| C18 | service   | `auditd.service` 為 active                                             | 0        | systemctl is-active auditd >/dev/null 2>&1; echo $? |
| C19 | service   | `rsyslog.service` 為 active                                            | 0        | systemctl is-active rsyslog >/dev/null 2>&1; echo $? |
| C20 | logrotate | `/etc/logrotate.d/` 下沒有任何 log path 被兩份以上的 policy 檔重複宣告（不限於本模組管理的 auditd/syslog 兩個檔案，涵蓋 distro 內建的 `rsyslog` 等所有檔案） | 0        | sh -c 'test -z "$(grep -rhoE "^/[^ {]+" /etc/logrotate.d/ 2>/dev/null | sort | uniq -d)" && echo 0 || echo 1' |
| C21 | rule      | audisp-syslog plugin 已啟用且 facility 釘死 local6（沒有這條，local6 永遠不會有任何流量，跟轉送/接收設定是否正確無關） | 0        | sh -c 'grep -q "^active = yes" /etc/audit/plugins.d/syslog.conf && grep -q "^args = LOG_INFO LOG_LOCAL6" /etc/audit/plugins.d/syslog.conf && echo 0 || echo 1' |
| C22 | functional| 驗證實際 daemon 連線；RELP 模式另外驗證 mTLS peer 與 RELP open/syslog ACK | 0 | sudo /usr/local/libexec/pilot-siem-relp-check sender; echo $? |
| C23 | functional| 與同機 Wazuh who-data 共存：`wazuh-agent` 為 active、`ossec.conf` 設了 whodata、且 `/var/ossec/queue/sockets/audit` 上有 `audisp-af_unix` 的 listener 時，kernel 稽核清單必須仍有 `wazuh_fim` watch（本模組載入規則或重啟 auditd 之後它不得消失）；沒有這三個前提之一時不適用，回 0 | 0 | sh -c 'systemctl is-active --quiet wazuh-agent || { echo 0; exit 0; }; sudo grep -q "whodata=.yes" /var/ossec/etc/ossec.conf || { echo 0; exit 0; }; command -v ss >/dev/null 2>&1 || { echo 1; exit 0; }; sudo ss -xHap 2>/dev/null | grep -F /var/ossec/queue/sockets/audit | grep LISTEN | grep -q audisp-af_unix || { echo 0; exit 0; }; sudo auditctl -l 2>/dev/null | grep -qE "(key=|-k[[:space:]]+)wazuh_fim([[:space:]]|$)" && echo 0 || echo 1' |

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
>
> **C23（v2.1，issue #324）**：kernel 稽核清單是同機各元件共用的狀態。`augenrules --load`
> 讀進來的 `/etc/audit/audit.rules` 以 `-D` 開頭，每次載入都先清掉整份清單，包括 Wazuh
> agent 的 who-data 為 `wazuh_fim` key 加的 watch；Ubuntu 24.04 的 `auditd.service` 在
> `ExecStartPost` 也執行 `augenrules --load`，所以重啟 auditd 同樣會清掉。清掉之後 endpoint
> 與連線都還在，Wazuh 的自癒次數有限（見 §5 的實測），用完之後 who-data 退回 real-time 而不再恢復；
> C1–C22 沒有任何一條看得到這個狀態。
> C23 把這個外部可觀察的結果獨立成一條：who-data 有三個前提（agent 為 active、`ossec.conf`
> 設了 whodata、af_unix plugin 的 listener 在 endpoint 上），三者都成立時 kernel 就必須有
> `wazuh_fim` watch。三者缺一，who-data 本來就不是 live（例如 EL 上 auditd 還沒被告知載入 Wazuh
> agent 套件的 `af_wazuh.conf`，因此 endpoint 尚未建立，見 §5 的已知限制；或 `ss` 看得到的 socket
> 檔仍在，listener 卻已經不在；或 Ubuntu 22.04 的內建 af_unix，沒有外部 `audisp-af_unix` 行程，見 §5），
> C23 不適用，回 0，不把別的元件的缺口算在本 spec 頭上。`ss` 不存在而前三個前提成立時回 1：無法證明就不能算通過。
> 比對 `wazuh_fim` 的樣式與 `wazuh-transaction.py` 的 `AuditRuntime.ready` 相同（同樣的字面
> 樣式，`TestRegression_WhodataWatchPatternHasOneSource` 鎖住三處一致）。
> apply 端對應的行為見 §6 與 `docs/runbooks/audit-log-forwarding.md` §5.6。

## 3. 證據收集

- 工具：`go run ./cmd/pilot vm-target verify --name <target> docs/verification/audit-log-forwarding.md`
- 輸出格式：`.verification/audit-log-forwarding-<UTC>.{ndjson,md}`
- 預期 row 數：23（C1–C23）

## 4. PASS / FAIL 規則

- 全部 C1–C23 `status=pass` → **PASS**
- 任一 `status=fail` → **FAIL**，列出 fail id + actual + want

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C10/C11/C16/C17/C22 | 本 spec 只驗證「client 端規則正確載入 + 本機稽核事件正確產生 + 轉送設定正確指向別名 + rsyslogd 對轉送埠的連線已建立」（C22），**不**驗證「訊息真的被 log-server 收到」——那是跨主機 Shape 3 cross-check，做法見 `docs/runbooks/audit-log-forwarding.md` §4（在這台注入、去 log-server 讀檔驗證） | 所有環境 | 永久（設計如此，非暫時偏差） |
| C6 | `chmod`/`fchmod`/`fchmodat` 規則沒有加 `-F auid>=1000 -F auid!=unset`（CIS 常見寫法會加，用來排除系統自身的 chmod 呼叫），本 spec 選擇不排除，讓 sandbox 環境的驗證更單純；正式站台若稽核量太大可在規則加此過濾，但要同步改 C6 的 grep pattern | sandbox / 測試環境 | 正式站台上線前檢討 |
| C15, C16, C17, C22 | 這四條的前提是套用時提供了 `siem_forward_host`（見 §1.5，v1.1 起選填）。若 log server 尚未存在、套用時未帶這個變數，playbook 會跳過轉送設定，C15–C17 在 `pilot verify` 會回報 `fail`（`/etc/hosts` 沒有別名、`99-siem-forward.conf` 不存在）——這是**預期行為**，不是 bug：此時應只驗證 C1–C14, C18–C20（本機稽核 + logrotate + auditd 服務），待 log server 就緒、補跑一次 apply 帶上 `siem_forward_host` 後再驗全部 23 條 | 無 log server 的獨立部署 / log server 尚未就緒的過渡期 | 補上 `siem_forward_host` 並重新 apply 後即解除 |
| C23 | 只在 who-data 本來就是 live 的主機上才有意義（前提見 §2 的 C23 說明）；沒有 Wazuh、agent 未啟動、未設 whodata、或沒有 af_unix listener 的主機一律回 0。C23 只證明 kernel 的 `wazuh_fim` watch 在，不證明事件已送到 manager（那是 `wazuh-fim.md` 與 `wazuh-manager.md` 的跨主機 cross-check） | 所有環境 | 永久（設計如此，非暫時偏差） |

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

> **C23 的由來與保證範圍（v2.1，issue #324）**：`audit-log-forwarding` 每次套用都無條件執行
> `augenrules --load`（Step 3）。2026-11-12 在拋棄式 Ubuntu 24.04.4 VM（log-server、audit-log-forwarding、
> wazuh-fim 與真實 manager 同機，Wazuh agent 4.14.x）上以 BASE（`f1000213`）實測：完整鏈套用後
> `wazuh_fim` watch 為 2 條、listener 在；第一次重跑 audit-log-forwarding，Wazuh 記下
> `Detected Audit rules manipulation: Audit rules removed.`，watch 在數秒內自行補回（自癒）。再連續執行
> 7 次 `augenrules --load`（Step 3 的指令，間隔 12 秒）：第 1 次之後 watch 仍為 2，第 2 次起為 0——
> listener 還在、agent 仍為 active，`ossec.log` 出現 `Real-time file integrity monitoring started`
> （who-data 退回 real-time），之後沒有自行恢復；重啟一次 `wazuh-agent`，3 秒內 watch 回到 2 條。
> 所以「Wazuh 不會自行補回」只在它的自癒次數用完之後才成立，取決於之前被清過幾次，這正是不能依賴它的
> 原因；對已經退回 real-time 的主機，一次 `systemctl restart wazuh-agent` 是唯一的處理方式。Ubuntu 24.04
> 的 `systemctl restart auditd`（Step 8a）在同一台 VM 上 listener 立即重新建立；agent 的自癒次數還沒用完
> 時 Wazuh 自行補回，同樣不保證，設計不依賴它。v2.1 的保證，以及它**不**保證的部分：
>
> - 已收斂的主機（規則檔已是目前內容、`augenrules --check` 回報沒有差異、kernel 已有本模組管理的
>   所有 key）上，套用不再執行 `augenrules --load`，不重啟 auditd，也不重啟 agent；`changed=0`。
>   「只在規則檔變了才載入」不夠：規則檔沒變而 kernel 清單被外部清掉（`auditctl -D`）、或只跑了
>   `--tags C3` 之後，kernel 會永遠與檔案不同步。載入的條件是下列任一成立：這次 run 改了規則檔、
>   `augenrules --check` 回報有差異或讀不出結果（規則的參數被改但 key 不變，只有它看得到）、kernel
>   缺少本模組管理的 key（逐 key 計數比較）。
> - 載入或重啟 auditd 之前，guard 先**當場**重讀 agent 與 kernel 清單（不使用 play 開始時的快照：
>   Step 1 的套件安裝可能在 play 中途才讓 `auditctl` 出現），再讀 Wazuh 協調器的唯讀 `writer-inspect`。
>   以 typed reason 在 kernel 清單未被動到之前失敗：`wazuh_writer_active`（有 Wazuh writer 或 journal
>   在進行，或協調器沒有回答）、`whodata_state_unreadable`（讀不到 agent 狀態，或 agent 為 active 而
>   `auditctl -l` 讀不出來）、`wazuh_agent_transitioning`（agent 正在啟動、停止或自動重啟，who-data 是否
>   live 無法判定，請等它穩定後重跑）。`auditctl` 不存在表示 who-data 不可能 live，不是拒絕的理由。
>   拒絕之前這次 run 的其他步驟（套件、設定檔）可能已經執行，被還原的只有規則檔。檢查與動作之間仍有
>   一小段空窗，本模組沒有鎖定 Wazuh 的協調器，這是已接受並記載的限制。沒有 `wazuh-agent` unit 的主機
>   不受影響，也不會建立協調器的狀態目錄。
> - 集合 S 是第一次擾動之前由 guard 當場讀到的 `wazuh_fim` watch（agent 為 active 且 kernel 清單可讀）；
>   之後同一次 run 的第二個 guard 不會覆蓋它。這次 run 的最後一次擾動之後（Step 3、Step 8a，或失敗路徑
>   的 rescue 重載），等 auditd 與 af_unix listener 回來（有上限），重啟一次 `wazuh-agent`，再有上限地等
>   kernel 的 `wazuh_fim` watch 涵蓋 S；沒有涵蓋就以 typed reason 失敗（`endpoint_not_ready`、
>   `agent_restart_failed`、`watches_not_restored`、`kernel_unreadable`），不會靜默成功。agent 為
>   inactive／不存在、或 S 為空（例如 EL 上 endpoint 尚未建立）的主機，永遠不會被本模組啟動或重啟 agent；
>   這類主機只會因為上一條的擾動前檢查而拒絕。agent 不是 pilot 管理的也一樣處理（清掉 watch 的是本模組）。
> - 失敗路徑（rescue）只在「這次 run 載入過」且「規則檔被還原或移除，或載入本身失敗」時才重載 kernel
>   清單，重載後重新建立 who-data；最後的錯誤訊息如實說明規則檔、kernel 清單與 who-data 各自的結果，
>   不再寫死「已還原」。
> - Step 8b（EL 的 `pkill -HUP -x auditd`）不經過 `augenrules`，**已量過、不視為擾動**：2026-11-12 在
>   AlmaLinux 9.8（Wazuh agent 4.14.x）上，who-data 已 live 時（`audispd-plugins` 已安裝、agent 已重啟、
>   並以 `pkill -HUP -x auditd` 讓 auditd 載入 plugin）連續 6 次對 auditd 送 SIGHUP（間隔 8 秒）：
>   `wazuh_fim` watch 維持 2 條、kernel 清單總數維持 8 條，`audisp-af_unix` 的 PID、已建立的 af_unix 連線
>   與 listener 都不變，`ossec.log` 沒有 `Audit rules removed`；以真實 playbook 在 syslog plugin 設定
>   漂移（Step 8b 的 HUP 路徑）下重跑，結果相同，agent 未被碰。涵蓋範圍只有：plugin 設定變更觸發的 HUP
>   與單純的 HUP、EL 9.8、Wazuh agent 4.14.x；其他組合沒有量過。
> - 已知限制（既有的 wazuh-fim 順序缺口，不在本修正範圍，沒有修）：EL 的 Step 1a 會安裝 `audispd-plugins`，
>   但 Wazuh agent 套件在 audit-log-forwarding 的 SIGHUP **之後**才裝 `/etc/audit/plugins.d/af_wazuh.conf`，
>   auditd 還沒被告知載入它。2026-11-12 在拋棄式 AlmaLinux 9.8 上實測：audit-log-forwarding 先於 wazuh-fim 的
>   全新同機鏈套用完成後，`/var/ossec/queue/sockets/audit` 沒有 listener，who-data 不是 live；之後
>   `pkill -HUP -x auditd`（EL 的 auditd 拒絕 `systemctl restart`）listener 才出現，who-data 才 live。這段
>   期間 C23 回 0（前提不成立），本模組也不會碰 agent。who-data 已 live 的 EL 主機被外部 `auditctl -D` 清掉
>   後再套用：watch 被補回（agent 重啟一次），下一次套用 `changed=0`。
> - Ubuntu 22.04 沒有涵蓋，也沒有 capture：它的 auditd 內建 af_unix（`builtin_af_unix`），沒有外部
>   `audisp-af_unix` 行程。re-arm 與 C23 的 listener 前提都只認 `audisp-af_unix` 在 endpoint 上 LISTEN，所以
>   在 22.04 上，若 who-data 是 live 的，擾動之後 re-arm 以 `endpoint_not_ready` 失敗、不重啟 agent
>   （kernel 清單已被清掉，需要手動 `systemctl restart wazuh-agent`），C23 一律回 0（不適用）。要支援
>   需要 22.04 的真實 capture，不用猜的 predicate。aarch64 同樣沒有實測。
> - Step 8（C18）啟動原本停止的 auditd 不追蹤（auditd 停止時 who-data 本來就不 live）；host decommission
>   的 `augenrules --load`（`playbooks/decommission/audit-log-forwarding-decommission.yml`）是整機退役的
>   一部分，不在範圍內；被 v2.1 之前的版本清掉 watch、至今未重啟 agent 的主機，不會被這個版本自動修復，
>   需要重啟 `wazuh-agent` 一次（見 runbook §5.6）。

## 6. Playbook 對應

對應 apply playbook：`playbooks/apply/audit-log-forwarding-apply.yml`

| Spec ID | Apply task | 備註 |
|---------|------------|------|
| C1, C2 | `install auditd + audispd-plugins` | apt/dnf 依 `ansible_os_family` |
| C3–C9 | `template audit.rules.j2 → /etc/audit/rules.d/99-custom.rules` | 用 `ansible.builtin.template` 模組（非 inline copy），對應本任務明確要求 |
| C10 | `augenrules --load`（Step 3；只在需要時載入，條件見 §5 的 C23 說明） | 規則檔改完要重新載入才會進 `auditctl -l`；Step 3a 以唯讀 helper `files/audit-whodata.py probe` 決定要不要載入（已收斂的主機不載入）；Step 3c 在載入前當場重讀 agent／kernel 並檢查 Wazuh writer，Step 3d 記下「已嘗試載入」供 rescue 判斷 |
| C11 | 無獨立 apply task（規則生效後的功能性自證，verify 時才觸發 `sudo -n true`） | — |
| C12, C13, C14 | `template /etc/logrotate.d/{auditd,syslog}` | `rotate`/`maxage` 走 `audit_logrotate_*`/`syslog_logrotate_*` 變數 |
| C15 | `lineinfile /etc/hosts` pin `siem-log-server` | 必須在轉送設定 render 之前（同 freeipa-client `/etc/hosts` 先於 enroll 的教訓） |
| C16, C17 | 建立私有 spool、安裝 runtime probe、render `99-siem-forward.conf`、驗證並載入設定 | 兩個獨立的 `omfwd` TCP action；單獨 `--tags C16` 或 `C17` 也會驗證與重啟；中斷後重跑會依寫入/啟動時間修復未載入的設定 |
| C18, C19 | `ensure auditd + rsyslog enabled+restarted` | rsyslog 只在轉送設定真的變更時才 restart |
| C20 | `stat` + `shell`（用 `files/logrotate-drop-path.awk` 依 logrotate 自己的解析規則算出拿掉該路徑後的 distro rsyslog policy，含引號/縮排/`~` 路徑）+ `copy`/`file`（Step 5a–5d，Debian 與 RedHat family 都跑，只看 `/etc/logrotate.d/rsyslog` 是否存在，不再用 `ansible_os_family` 額外過濾） | 只移除 `{{ audit_syslog_path }}` 這個路徑，其他路徑（Debian：`mail.log`/`kern.log`/`auth.log`...；RHEL：`cron`/`maillog`/`secure`/`spooler`...）留給 distro 自己的檔案繼續管；如果那個 stanza 只列這一個路徑就整個 stanza 移除；整份檔案除了空白與註解已無內容時才刪檔，避免留下沒有檔名的空 block 讓 logrotate 解析失敗。無法安全改寫（policy 本身 logrotate 就拒絕、路徑寫法讓各版 logrotate 解讀不同、保留的 glob 或尾端加斜線的同名路徑仍會比對到該路徑）時 task 失敗；這個檢查在 Step 1d 的 preflight 先跑一次，失敗發生在第一次設定檔寫入之前（Step 0a–1c 的套件安裝更早，不在此限）。計算結果寫進 0700 暫存目錄的檔案（不經 task result，所以 policy 內有非 UTF-8 位元組也照常套用），Step 5e 在任何結束路徑都會移除該目錄 |
| C21 | `lineinfile`（Step 6e/6f，打開 `active` + 釘死 `args` facility，兩者都在 `--check` 模式下跳過）+ `command`（Step 8c 用 `pgrep` 確認 plugin process 是否真的在跑）+ Step 8a（Debian，`systemd: state: restarted`）/ Step 8b（RedHat，`pkill -HUP -x auditd`，見上方 v1.5 說明為何不能用 `systemctl restart` 或 `service`） | RedHat family 的 Step 1a 同步補裝 `audispd-plugins`（EL9 上這是 `audit` 套件以外的獨立 RPM）；Step 8a/8b 的觸發條件同時看「這次有沒有改到檔案」跟「plugin process 是否真的在跑」，避免前一輪失敗的 apply 留下「檔案已對、但從未 reload」的殘留狀態；v2.1 起 Debian 的 Step 8a 之前多了 Step 8d（Wazuh writer／狀態檢查）與 Step 8e（記下已嘗試重啟 auditd），8a/8b 本身的條件與動作不變（C23） |
| C22 | 無獨立 apply task（轉送連線的功能性自證，verify 時送一筆 `logger` 測試訊息）；SELinux 主機上由 `tasks/rsyslog-selinux-tcp-port.yml`（Step 6g）把非預設的 `siem_forward_port` 標成 `syslogd_port_t` | rsyslogd（`syslogd_t`）只能連 `syslogd_port_t`/`rsh_port_t`（tcp/514） |
| C23 | 無獨立 apply task（verify-only：kernel 的 `wazuh_fim` watch 是 Wazuh 自己建立的，本模組只負責不讓它消失）。維持它的是三段：擾動前 `tasks/audit-whodata-guard.yml`（Step 3c、Step 8d）、擾動後 `tasks/audit-whodata-rearm.yml`（Step 10，在 block 之後；以及 rescue 的重載之後）、唯讀 probe 與 bounded 等待的 `files/audit-whodata.py`（guard 內當場讀取 S 的 probe、Step 3a、re-arm 的 `rearm`） | 擾動點只有 Step 3 的 `augenrules --load` 與 Step 8a 的 Debian auditd restart（Ubuntu 24.04 的 unit 在 `ExecStartPost` 也 `augenrules --load`）；Step 8b 的 EL SIGHUP 不經過 `augenrules`，已在 EL 9.8 量過不影響 Wazuh 的 watch 與連線（§5），不視為擾動。re-arm 之後的失敗不回滾已套用的規則與轉送設定（兩者是獨立子系統，回滾無助於 who-data）；re-arm 之前的失敗由 rescue 還原規則檔，並且只在載入過、而且規則檔被還原或載入本身失敗時才重載，重載後再 re-arm |

## 7. SOP

### 7.1 標準情境：log server 已存在（轉送啟用，驗證全部 23 條）

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

# 3. verify（本機規則/服務/轉送設定，全部 23 條）
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

# 2. verify（pilot verify 沒有「只驗證部分 row」的選項，會照跑全部 23 條；
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
| 2026-09-14 | v1.6 | docs/superpowers/specs/2026-09-14-apt-repository-fault-tolerance-spec.md Phase 4：Step 0a 的 `apt_repository` 不再自帶 `update_cache: true`（改 `false`），移除獨立的「Step 0b: Refresh Ubuntu APT metadata after enabling universe」；Step 1（`auditd`/`audispd-plugins`/`rsyslog`）改走共用 `playbooks/apply/tasks/apt-package-install.yml`（required source=`ubuntu-os`），由該 framework 自己的 cache-first 狀態機在 universe 剛啟用、候選套件還沒 refresh 出來時自動 refresh——且對無關的第三方 repo 失敗容忍，只有 Ubuntu archive 本身壞掉才 fatal。原本 Step 0a/0b 的 `update_cache: true` 都是全域刷新，跟 freeipa-client C1/C8 是同一種缺陷（無關 repo 壞掉會擋下 universe 啟用/audispd-plugins 安裝）。更新 `internal/spec/audit_log_forwarding_regression_test.go` 對應斷言（不再找 Step 0b 文字，改斷言 install task 走 `tasks/apt-package-install.yml`）。詳見 `docs/verification/apt-repository-tolerance.md` | pilot |
| 2026-08-07 | v1.5 | 新增 C21：啟用 audisp-syslog plugin（EL9 補裝 `audispd-plugins`，Step 6e/6f 把 `/etc/audit/plugins.d/syslog.conf` 的 `active` 打開、`args` facility 釘死 `LOG_LOCAL6`，Step 8a/8b 條件式 restart auditd）。real incident：minimal-poc round 20 對一個全新 clean-room 拓樸做深入 Loki 查核時，即使接收端（`log-server.md`）與轉送規則（C15–C17）都已正確部署，三台主機的 `/var/log/siem/<host>/audit.log` 仍完全不存在——因為這個 plugin 出貨時預設停用，auditd 從未真的產生任何 local6 流量。修的過程中連續踩到四個子問題，都在同一組 3 台主機（AlmaLinux 9 + 2×Ubuntu 24.04）現場實測確認：(1) Step 6e/6f 一開始沒有 `when: not ansible_check_mode`，在套件真的還沒裝的主機上 `--check` 預覽會直接失敗（同檔案 Step 8 的 auditd 啟動早就有這個 guard，這次沒套用到新任務上）；(2) AlmaLinux/RHEL 的 `auditd.service` 出貨 `RefuseManualStop=yes`，`ansible.builtin.systemd: state: restarted`（本質是 stop 再 start）的 stop 那一半會被系統拒絕，錯誤訊息是 `Operation refused, unit auditd.service may be requested by dependency only`；(3) 原本想改用 RHEL 傳統的 `service auditd restart` SysV wrapper 繞過限制，但 minimal EL9 image 根本沒裝 `initscripts`/`chkconfig`，`service` 這支指令完全不存在（`command not found`）；改成直接送 `SIGHUP` 給 auditd（`man auditd(8)` SIGNALS 明載「SIGHUP causes auditd to reconfigure」，訊號直接送給 process，完全不經過 systemd 的 stop 路徑，`RefuseManualStop` 對它沒有作用），實測送出後 audisp-syslog plugin process 確實重新起來、一筆真實 audit 事件（SSH session open）立刻被轉送到中央 SIEM；(4) 光靠「這次 apply 有沒有改到檔案」判斷要不要 reload 不夠：上一輪失敗的 apply 已經把 `active`/`args` 改好、但在真正 reload 之前就因為問題 (2) 而 rescue 中止，導致下一輪重跑時 lineinfile 兩個 task 都回報 unchanged（檔案本來就對了），Step 8a/8b 的 reload 就永遠不會觸發——即使 apply 回報 `failed=0`、看起來全綠，auditd 實際上仍在用舊設定跑，plugin 從未真的生效。新增 Step 8c 直接檢查 `audisp-syslog` process 是否真的在跑（`pgrep -x audisp-syslog`），跟檔案是否改變並列進 Step 8a/8b 的觸發條件，讓 reload 判斷不再只依賴這次 run 自己的異動旗標 | sre |
| 2026-10-14 | v1.7 | 新增 C22：送出 local6 測試訊息後，`rsyslogd` 對轉送埠必須有 ESTABLISHED 的 TCP 連線。起因：PR #79 讓 inventory 的 `siem_forward_port` 生效後，AlmaLinux 9.8（SELinux Enforcing）上 `siem_forward_port: 2514` 的 client 設定完全正確（C16/C17 pass），但 `syslogd_t` 不能連 `unreserved_port_t`，rsyslog 回報 `cannot connect ... Permission denied`、所有訊息丟失、apply 成功；C22 在該狀態實測 FAIL，標成 `syslogd_port_t` 之後 PASS。apply 端的修正在 `tasks/rsyslog-selinux-tcp-port.yml`（Step 6g） | pilot |
| 2026-10-14 | v1.8 | C22 改成送出訊息後每 2 秒檢查一次、最多 8 秒，並只承認目的地是 `siem-log-server` 解析出之位址的連線。v1.7 只等 3 秒且不看目的地：log-server 剛重啟時 client 的轉送暫停中會誤判 FAIL，連到別台主機的同一個埠則會誤判 PASS（PR #79 複審）。仍在 15 秒預設的單列逾時內；log-server 重啟後 30 秒內 rsyslog 的轉送暫停重試，這段時間內 C22 仍可能 FAIL | pilot |
| 2026-10-20 | v1.9 | #122：C16/C17 驗證有界磁碟輔助 action queue、持續重試與已載入的獨立 queue worker；C22 改讀 omfwd 埠並等待最多 12 秒。明列 TCP 在途訊息與有限容量邊界 | pilot |
| 2026-10-20 | v2.0 | RELP/mTLS opt-in：精確 peer 名稱、CA/cert/key、TLS 失敗保留 queue、固定 classic engine 並拒絕格式自動轉換；C22 驗證真實 daemon 與 RELP ACK。驗收見本輪 evidence 摘要 | pilot |
| 2026-11-12 | v2.1 | issue #324：新增 C23（與同機 Wazuh who-data 共存：kernel 稽核清單在 agent active、已設 whodata、listener 存在時必須仍有 `wazuh_fim` watch）。起因：Step 3 每次套用都無條件 `augenrules --load`（audit.rules 以 `-D` 開頭，且 `augenrules --load` 在「No change」時照樣 `auditctl -R`），Ubuntu 24.04 的 auditd 重啟也會載入，兩者都清掉 Wazuh 的 who-data watch 而 C1–C22 全綠。apply 端：Step 3 只在需要時載入（規則檔本次有變、`augenrules --check` 有差異或讀不出、kernel 缺少本模組管理的 key）；擾動前讀 Wazuh 協調器的唯讀 `writer-inspect` 並在 writer 進行中時失敗；擾動後（Step 3、Step 8a、rescue 的重載）有上限地等 auditd/listener 回來、重啟一次 `wazuh-agent`、再有上限地等 `wazuh_fim` watch 涵蓋套用前的集合，否則 typed 失敗；rescue 只在載入過且規則檔被還原或載入失敗時重載，最後訊息如實說明結果。沒有放寬或移除任何既有 Expected；C1–C22 不變。**目標環境實跑結果尚未產生**，由後續 evidence-only commit 記錄 | pilot |
| 2026-11-12 | v2.2 | issue #324 獨立 review 與拋棄式 VM 實測後的修正（沒有放寬或移除任何 Expected，C1–C23 不變）：guard 改為在擾動前當場重讀 agent 與 kernel 清單並在那一刻讀取 S（原本用 play 開始時的快照，auditctl 在 Step 1 之後才出現時會誤拒絕）；`auditctl` 不存在是 who-data 不可能 live，不是拒絕；agent 狀態明確分成 absent/inactive/active/transitioning/unknown，`activating` 等轉換中以 `wazuh_agent_transitioning` 拒絕；補上 `augenrules --check` 這個載入條件的測試與反例；§5 以 2026-11-12 的實測取代未註明來源的描述（BASE 的 Wazuh 自癒次數有限、EL 9.8 的 SIGHUP 不是擾動、EL 同機鏈 endpoint 尚未 live 的既有順序缺口），並明列 Ubuntu 22.04 的行為（`endpoint_not_ready`，未涵蓋） | pilot |
