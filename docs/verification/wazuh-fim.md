# Verification Spec — wazuh-fim（Wazuh agent：檔案完整性監控 FIM + auditd who-data）

> 版本：v1.7
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
| `wazuh_version` | 選填的 exact stable `4.14.x` release：新安裝固定為該版本；已安裝且相容的 agent 保留，版本變更另需單次 `wazuh_upgrade=true` 授權（目標 4.14.9-1，禁止降級） | 否 | 未設定（新安裝採觀察到的 manager release，無 manager 時 `4.14.1`；相容的既有 agent 保留） |
| `wazuh_manager_inventory_host` | 與 enrollment endpoint 精確對應、可 SSH 探測原生版本的 inventory host（其 `ansible_host`／gathered FQDN／inventory 名稱必須唯一對應 `wazuh_manager_host`） | 啟用 enrollment 時：`wazuh-manager` group 恰好一台則自動推導，否則必填 | inventory `wazuh-manager` group 唯一 host |

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

### 版本與受控升級驗收契約（Issue #244）

manager 的有效版本是相容性上限；repository 的最新版本不是部署目標。
有 manager 時，套用前必須從 inventory 中明確對應的 manager 主機讀取有效版本；
探測錯誤、模糊對應或已安裝 agent 較新，都必須在設定、註冊與重啟之前拒絕。
一般套用保留相容的既有 agent；新安裝固定完整套件版本。
共同目標 `wazuh_version` 選填；升級另需單次 `wazuh_upgrade=true` 授權。
既有 agent 的版本變更還必須觀察到明確對應的 manager；省略 enrollment endpoint
不能讓 row-only 套用繞過原有中央連線的相容性上限。無 manager 的一般保留與新安裝仍可使用。
一般套用保留 Debian / RedHat family 支援，包含 Ubuntu 22.04；4.14.x agent
升級目標為 4.14.9-1，禁止自動降級。升級平台驗收涵蓋 Ubuntu 24.04
amd64 / AlmaLinux 9 x86_64，其他平台與 Ubuntu 22.04 的實跑範圍須由各自
candidate evidence 明列，不能把程式相容性當作已完成實機驗證。

先備妥可重裝的舊套件，再停止 agent 並冷備份 `/var/ossec`、enrollment key、
設定與服務狀態；備份未驗證不得替換套件。失敗需恢復原套件、資料與服務，
確認原 identity；恢復失敗不可報成功。未完成的持久交易阻止一般套用。
舊套件 metadata 仍顯示相同版本時，回復也必須真正重新安裝留存的舊套件，
不能讓 package module 的 already-present 成為省略回復的理由。Debian 的
no-download reinstall 使用該留存檔的 native cache basename 與同一個 private
cache directory，原生計畫不得順便設定其他 package；EL 同版本使用 reinstall，
新版退回舊版使用 downgrade，兩者都沿用已驗證的 private policy／artifact。
root-only 備份保留於 `/var/backups/pilot/wazuh`，不自動清除。
受控交易只接受可由冷 tar 備份後刪除、重建的 layout：`/var/ossec` 必須是
真實目錄，既有 `/etc/hosts` 與版本 pin 必須是 regular single-link file，全部
祖先不得為 symlink。選取來源本身或其子樹有 mount（包含同裝置 bind mount）時，
在 reserve 與停機之前拒絕；不支援刪除、重建 mount root。
備份 store 可位於獨立的一般 filesystem，但不得有 subtree/bind ancestry、
子 mount、或與來源互為實體 alias。來源 layout 在 staging、冷備份前與回復前重驗。
檢查涵蓋所有選取樹的每個 lstat entry：內部 symlink 的完整解析目標必須留在
capture set；每組 regular-file inode 的所有 hardlink 名稱都必須被捕捉。未知外部
資料 alias、FIFO/device 或不完整 inode group 直接拒絕，不能只備份連結本身。
元件的 `/etc/audit/plugins.d/af_wazuh.conf` 與 `/var/ossec/etc/af_wazuh.conf`
是明列的共同 capture set，回復須重建並驗證原兩個名稱的 hardlink identity。
live 外部 runtime 只支援已確認的 `/var/ossec/queue/sockets/audit`：記錄並保留
該 socket 與三個真實祖先目錄的 device/inode/security metadata，以及 auditd、
audisp listener 的 PID/start/exe/argv、boot 與 kernel audit settings。其他外部
endpoint／writer 直接拒絕。回復時只 prune 其他 persistent objects；sealed archive
不得置換 socket 或把祖先轉成 alias。套件替換、回復重播與原服務啟動後都重驗。
boot／listener／anchor 改變時保留 journal 並拒絕自動回復，不猜測 HUP／respawn。
啟用 audit plugin 卻缺少健康 endpoint 的舊主機，須先完成明確的前置修復。
EL 的 who-data endpoint 由一般套用建立，否則套用失敗（Issue #323；只涉及 RedHat family）：EL 的 `audit`
套件不含 af_unix plugin，`/sbin/audisp-af_unix` 由 `audispd-plugins` 提供（Debian family 的安裝清單仍只有
`auditd`，Ubuntu 24.04 上 who-data 以它運作；Debian 的安裝清單與行為不變），所以 RedHat family 的 Step 4 與 `audit`
一起安裝 `audispd-plugins`。agent
首次啟動時寫入 `/etc/audit/plugins.d/af_wazuh.conf`（`active = yes`），但 EL 上沒有東西讓執行中的 auditd 載入
它：auditd 拒絕 `systemctl restart`，minimal EL9 沒有 `service` 指令，Wazuh 自己的重啟失敗並記錄
`Could not launch command to restart Auditd`，syscheckd 退回 real-time 而沒有 who-data。因此一般套用在最後
一次 agent 服務變更（Step 11 的重啟）之後執行 Step 11a（tag C11；只在 RedHat family、只在一般套用、
`--check` 不執行；進入前先取得 `agent-service` 與 `audit-service` 快照），由 coordinator 的
`agent-whodata-ensure` 在既有的 host-wide writer／component lock 與 idle 檢查之下確保 endpoint；只在需要時
才變更主機：
- endpoint 是有 listener 的 socket，且 `wazuh-syscheckd` 已連線：不送訊號、不重啟、回報 unchanged；這條
  路徑不要求任何 `wazuh_fim` watch。
- listener 存在，但 syscheckd 在有上限的寬限內仍未連線：重啟一次 `wazuh-agent`，不送訊號。
- endpoint 不存在：先有上限地等待 `af_wazuh.conf` 出現且 `active = yes`（全新主機上 Step 11 緊接在 Step 10
  之後重啟 agent，檔案可能尚未寫出）；再對 auditd 主程序（systemd `MainPID`，以 pidfd 持有，執行檔必須是
  `/usr/sbin/auditd`）送恰好一次 SIGHUP；有上限地等待 endpoint 以有 listener 的 socket 出現；然後重啟一次
  `wazuh-agent`，並要求 syscheckd 已連線且至少一條 `wazuh_fim` kernel watch 出現（只有本次套用自己重啟 agent
  之後才要求 watch）。全新主機的第一次套用因此會重啟 agent 兩次（Step 11 一次、本步驟一次）；第二次套用
  不送訊號、不重啟、`changed=0`。
- 下列情形以 typed refusal 讓套用失敗，既有 rescue 隨後執行（rescue 永遠不重啟 auditd，SIGHUP 不回復）：
  plugin 在上限內始終不是 `active = yes`（不送訊號）；endpoint 路徑存在但不是 socket；socket 存在但沒有任何
  listener；單一次 SIGHUP 之後 endpoint 仍未出現（不重啟 agent）；重啟之後 stream 或 watch 沒有出現。
就緒判斷不看 listener 是哪個程序（外部的 `audisp-af_unix` 或 auditd 內建的 af_unix 都算），只看 `ss -xHap`：
endpoint 路徑上有 LISTEN，且有 ESTAB 的 server 端、其 inode 與 `wazuh-syscheckd` 的 ESTAB client 互指（與 C11
相同的判斷）。受控升級的 admission gate 不變，仍使用自己的精確 listener 與 watch 證明。
舊主機（較早 revision 在 EL 上安裝：只有 `audit`、沒有 `audispd-plugins`、沒有 endpoint）須先完成一次含本
revision 的一般套用，才能帶 `wazuh_upgrade=true`。在尚未修復的舊主機上，受控 agent 升級仍以
`configured external audit endpoint is unavailable before upgrade` 拒絕，不送訊號、不重啟、不改動 agent。拒絕
發生在 `agent-reserve` 之中，早於交易對 staged RPM 的簽章驗證，但 RPM 已先由 stage 下載（經 dnf，repository
設定 `gpgcheck=1`），所以被拒絕的這次執行使 `/var/backups/pilot/wazuh` 增加約 22 MB，主要是 staged
RPM：觀察到 `rpm-stage` 在拒絕後至少約 3 分鐘仍存在；保留的 root-only `agent-policy-<owner>` 目錄也留下。
上述順序的依據是全新 AlmaLinux 9 VM（×3）上的順序探測（觀察到的事實）：僅安裝 `audispd-plugins`（不論在 agent
之前或同時）沒有 endpoint、沒有 `wazuh_fim` watch；之後單獨對 auditd 主程序 HUP 有 endpoint（`ss -xHap` 只有一筆由 `audisp-af_unix` 持有的 LISTEN，沒有 ESTAB 連線）
但沒有 watch（60 秒內持續為 0）；單獨重啟 agent 什麼都沒有；HUP 之後再重啟 agent 兩者皆有；重新開機單獨即生效。操作者另觀察到
EL 上 `systemctl restart auditd` 被拒絕。Ubuntu 22.04（auditd 以內建的 `builtin_af_unix` 提供 af_unix，未安裝
`audispd-plugins`）與 aarch64 依維護者決定不在本契約與 evidence 的涵蓋範圍（不要求實跑）。由未變更的 admission gate 推論，
未以升級嘗試原生執行：Ubuntu 22.04 沒有外部的 `audisp-af_unix` listener，受控 agent 升級預期以
`exact external audit listener is missing or ambiguous` 拒絕。
已知限制（其他元件）：`audit-log-forwarding` 在 issue #324 之前每次套用都會執行 `augenrules --load`，
把同機 kernel 稽核清單整份清掉，包括 who-data 的 `wazuh_fim` watch。較早的一次實測（同機 Ubuntu 24.04）：
watch 由 2 條清為 0，auditd 主程序與連線不變，套用後 90 秒、手動 `augenrules --load` 後 10 分鐘仍為 0；
`audit-log-forwarding` 有設定漂移時重啟 auditd（新的 MainPID），agent 的連線隨之中斷，watch 在探測的至少
90 秒內持續為 0；重啟 `wazuh-agent` 後約 2 秒內重新建立。2026-11-12 以 BASE（`f1000213`）在拋棄式
Ubuntu 24.04.4 VM（同機 log-server、audit-log-forwarding、wazuh-fim 與真實 manager）量到它依賴被清過幾次：
前兩次清除 Wazuh 記下 `Detected Audit rules manipulation: Audit rules removed.` 並在數秒內自行補回；
連續第三次起 watch 為 0，listener 仍在、agent 仍為 active，`ossec.log` 出現
`Real-time file integrity monitoring started`（退回 real-time），之後沒有自行恢復；一次
`systemctl restart wazuh-agent` 後 3 秒內回到 2 條。由未變更的 admission gate 推論，未以升級嘗試原生執行：
此狀態下受控 agent 升級預期以 `native Wazuh audit client/watch readiness timed out` 拒絕，直到執行
`systemctl restart wazuh-agent`。
`audit-log-forwarding` v2.1（issue #324，其 spec 的 C23）改由該模組負責：只在需要時才載入規則
（已收斂的主機完全不載入、不重啟 auditd、不重啟 agent）；載入、Debian 上重啟 auditd、或失敗時的重載
這些擾動之前，先當場重讀 agent 與 kernel 清單，再讀本節協調器的唯讀 `writer-inspect`，有 Wazuh writer
或 journal 在進行時拒絕；擾動之後，若擾動前 agent 為 active 且 kernel 有 `wazuh_fim` watch，等 auditd 與
af_unix listener 回來、重啟一次 `wazuh-agent`，再有上限地等 `wazuh_fim` watch 涵蓋擾動前的集合，否則以
typed reason 失敗。#324 本身沒有改 wazuh-fim 的 playbook、coordinator 與 spec row；Step 11a 的 no-op 路徑與 C11 仍不補回 watch，
也不驗證這件事（Step 11a 只在 EL 自己重啟 agent 之後才要求至少一條 watch）；驗證在 `audit-log-forwarding` 的 C23。仍然存在的限制：
(a) 被 v2.1 之前的版本清掉 watch、至今沒重啟 agent 的主機不會被自動修復，需要重啟 `wazuh-agent` 一次；
(b) `writer-inspect` 是檢查不是鎖，檢查與動作之間有一小段空窗；
(c) EL 上 `audit-log-forwarding` 的 `pkill -HUP -x auditd`（Step 8b）已在 AlmaLinux 9.8 量過：who-data 已 live
時連續 6 次 SIGHUP，watch、kernel 清單總數、`audisp-af_unix` PID 與連線都不變，因此不視為擾動、不做 re-arm
（只量過 plugin 設定變更觸發的 HUP 與單純 HUP）；
(d) Ubuntu 22.04 與 aarch64 同樣沒有涵蓋；
(e) EL 的順序缺口（在 #324 之前量到，已由 Issue #323 修復，不屬於 #324）：EL 上 `audit-log-forwarding`（它的 Step 1a
會安裝 `audispd-plugins`）先於 wazuh-fim 的全新同機鏈，Wazuh agent 套件在 audit-log-forwarding 的 SIGHUP **之後**
才安裝 `/etc/audit/plugins.d/af_wazuh.conf`，auditd 尚未被告知載入它，所以當時套用完成後 endpoint 沒有 listener、
who-data 不是 live（2026-11-12，拋棄式 AlmaLinux 9.8、在 #323 合併之前的 main 上實測）。#323 的 Step 11a 在 agent
最後一次服務變更之後建立 endpoint，因此含 #323 的鏈套用完成後 EL 的 who-data 是 live 的；此時 `audit-log-forwarding`
若再需要載入規則，就適用上面的 guard 與 re-arm。Step 11a 的穩態（no-op）路徑與 C11 仍刻意不要求 `wazuh_fim`
watch：這是 verify 與 `changed=0` 的穩定性設計，與 #324 是否修復無關。
套件 staging 目錄及其祖先也須通過型別與 alias 檢查；留存套件只從精確的
root-only transaction directory 使用，回復不寫回 global package cache。
Debian 交易同時冷備份 `/usr/sbin/policy-rc.d` 的內容、metadata 或不存在狀態。
安裝時的暫時101 hook 只在同 owner／phase 下生效；installer 返回後必須以 sealed
原狀清理，並在 native 成功 proof 前驗證。若 audit boot／endpoint 已變而阻止
資料回復，確認舊 installer 工作停止後，仍可獨立恢復這個 global hook；component
journal 繼續保留失敗狀態。未知 foreign hook drift 必須拒絕覆寫。
升級期間 agent 暫停收送事件。交易驗收必須有 candidate-bound target evidence；
原 C1–C9 的成功不代表版本交易已被驗證。
有保留 audit endpoint 的交易，提交還須觀察已安裝 binary 對應的實際 syscheck
process、它與原 listener 的 connected stream 及原 kernel who-data watches。
這些是本機提交條件，不等同事件送達；正式 candidate／失敗回復驗收另須在
明示的測試 fixture 產生新 nonce，於 manager index 驗證新的 who-data event 與
audit user/process attribution。產品流程不自行寫入任意操作者監控目錄來造事件。
完成套用後，Debian 以 native dpkg／APT hold 防止 ordinary updater 漂移，
保留 APT preference 作為額外限制；不宣稱 preference 能壓過外部更高 priority。
EL 依賴啟用的全域 DNF versionlock plugin 與精確 owned rule，原生 resolving
transaction 必須證明規則有效；其他 package 的 lock 不得被移除或停用。
versionlock dependency 安裝屬一般準備，失敗的 Wazuh 升級不移除新引入的 dependency；
升級原狀指的是準備完成後 admission 的套件、資料及 hold／lock／設定快照，
不是整台主機回到 invocation 前。準備前記錄 plugin presence，遇 disabled、redirected、
foreign Wazuh ownership，或尚未安裝 plugin 卻已有待啟用的 lock 規則時先拒絕。
升級只對 Wazuh 使用同一份 fingerprinted private policy 與已驗證的留存套件；
同版本有不同 authenticated payload hash、非官方 provider 或 unknown plugin context
均拒絕。回復保留原 hold／owned-rule／foreign-rule／設定及不存在狀態。
APT 的明示套件替換可能清除 hold，交易須重新設定並驗證 hold 後才可完成；
不宣稱授權套件替換的每個瞬間都有 hold。
持久升級交易只接受已安裝且已 enrolled 的 agent；新安裝維持一般 exact-version
安裝與既有 enrollment retry 契約，不建立升級 journal，也不宣稱提供 fresh rollback。

所有 Wazuh 套用（包含一般設定、新安裝、升級與回復）都在第一個主機 mutation
與共享 coordinator copy 之前取得同一個 host-wide writer owner，涵蓋同主機
central、agent 與 `/etc/hosts`，直到設定、服務、原生驗證及 rescue 結束才釋放。
取得 owner 後重新讀取套件與 manager 事實，先前的讀取不能當成 mutation 授權。
manager 版本讀取使用共享 reader lock，允許正常 fleet forks 同時觀察穩定版本；
中央 writer 或未完成中央交易會拒絕外部讀取。同主機 agent writer 不變更中央版本，
因此不阻止穩定 manager readers。尚未結束的 agent journal 只允許相同 owner
執行指定階段的自身驗證。

controller 被中斷時 writer marker 保留，即使是沒有升級 journal 的一般套用。
操作者須先透過 writer-inspect 動作確認 owner 與 journal，確認前次 controller
及遠端 package/Compose 工作都已停止，再以單次 `wazuh_writer_resume_owner`
指定同一 UUID，並明示 `wazuh_confirm_previous_operation_stopped=true`。
若有升級 journal，`wazuh_recovery_owner` 也必須是同一 owner；不可換 token、
按 PID 猜測、等待 TTL 或強制刪掉未知 marker。沒有未完成 journal 時，一般失敗
可在所有 mutator/rescue 結束後釋放 owner，之後依原 retry 契約重跑。
回復舊版不存在的 pin 時，刪除及 parent directory fsync 必須先於 restored phase；
重播與完成回復還須驗證 pin 的存在/不存在及內容。

此 ownership 契約只協調本版 Wazuh entrypoints；其他角色的重疊維護、舊版
controller 與外部 root 編輯仍需由操作者維持獨占資源時段，不能宣稱已自動隔離。
唯一的例外是 `audit-log-forwarding`（v2.1）：它在載入規則或重啟 auditd 之前會讀這個協調器的
唯讀 `writer-inspect`，有 writer 或 journal 在進行時拒絕。這是檢查而不是鎖，不能宣稱已隔離。
受控套件交易的獨占時段也包含 apt/dnf 的自動更新工作；操作者須先讓它們停止，
本流程不自動停用主機的 updater 排程。installing／recovering journal 涵蓋套件替換
及重新建立 native guard 的間隔，中斷時只可同 owner 明確回復。

### 版本相容性細節（Issue #244，A 部分；與上節的受控升級並存）

manager 的有效版本 M 是 agent 的相容性上限；repository 的最新版本不是部署目標。
不變式：對每台有觀察到 manager M 的 agent，套用前與套用後的已安裝版本 V 都滿足
V ≤ M。

- 啟用 enrollment 時，在任何 repository、套件、設定、`/etc/hosts` 或註冊變更**之前**，
  先從 inventory 中明確對應的 manager 主機讀取原生有效版本 M，並把 enrollment
  endpoint 綁定到那台 inventory 主機（名稱、`ansible_host`、gathered FQDN 或 canonical
  數字位址必須唯一對應；DNS 巧合不算）。manager 不在 inventory、探測失敗、對應模糊或
  M 不是 4.14.x，都在上述任何變更之前以 typed reason 拒絕；`/etc/hosts` 別名只 pin 這個
  已綁定的位址。
- 新安裝固定完整套件版本：`wazuh_version`，未指定時為 M（`<版本>-1`）；沒有 manager 時為
  `4.14.1-1`；高於 M 者拒絕。Debian 經共用 APT framework，只安裝與 APT 已驗證 metadata
  的 SHA256 及 package identity 相符、且由宣告的官方 source 提供的 exact 位元組；EL 由
  coordinator 暫存官方 exact RPM，先對只含官方 key 的 private RPM key ring 驗簽（綁定
  provider、官方 URL 與 payload hash），才交給 `dnf` 安裝。
- 相容（V ≤ M）的既有 agent 原樣保留，包含 build 號。未帶單次 `wazuh_upgrade=true` 授權的任何
  版本變更——升級、降級、或與 `wazuh_version` 不同——一律 typed 拒絕，且在第一個 agent 變更之前；
  V > M（例如 manager 4.14.1、agent 較新的欄位 fleet）也拒絕，沒有降級路徑。授權的升級只接受
  4.14.x → 4.14.9-1，並走上節的 durable transaction（冷備份、同 owner 回復）。
- 套件以原生機制保護：Debian 為 dpkg／APT hold 加 `/etc/apt/preferences.d/pilot-wazuh-agent`
  preference（只是額外限制，不宣稱能壓過外部更高 priority）；EL 為啟用的全域 DNF versionlock
  plugin 加精確的 owned rule（原生 resolving transaction 證明不會替換）。foreign ownership
  （managed preference 路徑上的外來內容、與 Wazuh 重疊的 versionlock rule、停用或重導的
  plugin、plugin 尚未安裝卻已有待啟用的 rule）在變更前拒絕；其他套件的 rule 不移除。
  保護是冪等的：已受保護時不回報 changed。
- 平台：Debian／RedHat family、x86_64；只支援 stable 4.14.x release 與官方 `4.x` APT／yum
  channel（Debian 的 exact 安裝會拒絕其他 source）。升級、備份與回復的範圍見上節。
- 為何 C10 與 manager 的 C12 都 fail closed：agent 與 manager 的任何偏差（agent 較新）不被視為健康。
  這類既有 skew 需手動把 manager 升到不低於 agent 的版本，之後再套用本 spec。manager 端另有對稱的
  fail closed：manager 上登記了「從未連線」（`agent_control -i` 顯示 `Client version: (null)`）或
  pre-4.14 的 agent 時，manager 的套用閘門與 C12 以 typed 原因拒絕並指出該 agent 的數字 ID；這是被接受的
  skew fail-closed 行為，不是 bug。要解除，先在 manager 容器內以 `manage_agents -r <ID>` 移除該 agent
  （已連線但較舊、或已斷線但仍回報版本的 agent 不受影響）。
- 保護的邊界：APT `hold` 加 preference 擋的是 ordinary updater（`apt upgrade`、unattended-upgrades）
  與 pilot 自己的 apply；它**不**擋操作者明確下達的 `apt-get install wazuh-agent=<版本>`——那是 apt 的
  語意（明確指定版本會覆寫 hold 與 preference，原生 `apt-get -s install wazuh-agent=4.14.9-1` 仍規劃升級）。
  EL 的 versionlock plugin 則連明確指定的其他版本也找不到（排除過濾）。因此「不被降級或升級」只對 pilot
  的 apply 路徑與 ordinary updater 成立；有人手動明確升到比 manager 新的版本時，由下一次 apply 的
  `V <= M` 檢查在任何變更之前以 typed 原因拒絕。
- enrollment endpoint 與 inventory manager 對不上時，typed 原因（`Wazuh endpoint identity is unknown,
  ambiguous or different`）會顯示；helper 的輸入（inventory 紀錄、原始值）仍被 `no_log` 隱藏，只顯示固定字面值。
- 已知限制：EL 新安裝成功時，coordinator 為 exact RPM 在
  `/var/backups/pilot/wazuh/{agent-policy,rpm-fresh}-<本次隨機 token>` 留下 root-only 的暫存目錄
  （private key ring、已驗證的 RPM；後續的 dnf 安裝要用它），不會自動清除。被拒絕或失敗的 stage 不留下
  這兩個目錄（只移除本次呼叫自己建立的；既有的不動），只剩空的 `/var/backups/pilot/wazuh/agent.lock`。
- 已知限制（備份不自動清除）：每次一般（非升級）套用都會在 `/var/backups/pilot/wazuh` 留下一個
  `normal-<owner>-<operation>` 設定／服務快照目錄（3 個檔案，實測每次約 28–32 KB；同一台主機的
  中央一般套用不產生），不會被後續套用移除，所以隨套用次數線性增加；升級嘗試另留 `agent-<owner>`
  冷備份。只有 `writer-inspect` 顯示沒有 journal 與 writer 時，才可以**以 owner 目錄為單位**手動
  刪除已結束的 `normal-<owner>-*`、`agent-<owner>` 與 `agent-policy-<owner>`；不得刪除 `*.lock`、
  仍被 journal 引用的目錄或其中的檔案。這個目錄若納入 restic（見 `group_vars/restic-backup.example.yml`，該範例已建議納入
  `/var/backups/pilot/wazuh`），備份體積會隨之增加。

| ID  | Category  | Check                                                                 | Expected | Command |
|-----|-----------|------------------------------------------------------------------------|----------|---------|
| C1  | package   | `wazuh-agent` 已安裝（Debian 的 native hold 狀態仍是已安裝）           | 0        | if command -v rpm >/dev/null 2>&1; then rpm -q wazuh-agent >/dev/null; else dpkg-query -W -f='${Status}\n' wazuh-agent 2>/dev/null | grep -qxE '(install|hold) ok installed'; fi |
| C2  | package   | `auditd`／EL `audit`＋`audispd-plugins` 已安裝（who-data provider 與 EL 的 af_unix plugin 依賴） | 0        | if command -v rpm >/dev/null 2>&1; then rpm -q audit audispd-plugins >/dev/null; else dpkg-query -W -f='${Status}\n' auditd 2>/dev/null | grep -qx 'install ok installed'; fi |
| C3  | service   | `wazuh-agent.service` 為 active                                        | 0        | systemctl is-active wazuh-agent >/dev/null 2>&1; echo $? |
| C4  | service   | `auditd.service` 為 active                                             | 0        | systemctl is-active auditd >/dev/null 2>&1; echo $? |
| C5  | config    | 至少一個目錄設定了 FIM + whodata（`check_all="yes" whodata="yes"`，不綁定特定路徑——見 §1.5） | 0 | grep -qE '<directories check_all="yes" whodata="yes">' /var/ossec/etc/ossec.conf; echo $? |
| C6  | config    | who-data provider 為 `audit`（明確宣告，不依賴套件預設）                | 0        | grep -qE '<provider>audit</provider>' /var/ossec/etc/ossec.conf; echo $? |
| C7  | register  | `/etc/hosts` 已 pin `wazuh-manager` 別名                               | 0        | getent hosts wazuh-manager >/dev/null 2>&1; echo $? |
| C8  | register  | `ossec.conf` 的 `<address>` 指向 `wazuh-manager` 別名                  | 0        | grep -qE '<address>wazuh-manager</address>' /var/ossec/etc/ossec.conf; echo $? |
| C9  | register  | 已完成向 manager 註冊（`client.keys` 非空）                             | 0        | sh -c 'test -s /var/ossec/etc/client.keys && echo 0 || echo 1' |
| C10 | functional | 套件與 native agent release 相同、exact package 受 native hold／versionlock 保護、服務 active、沒有未完成交易 | 0 | sh -c 'if test -f /etc/debian_version; then wazuh_family=Debian; elif test -f /etc/redhat-release; then wazuh_family=RedHat; else exit 1; fi; /usr/local/sbin/pilot-wazuh-transaction agent-verify --family "$wazuh_family" >/dev/null && echo 0 || echo 1' |
| C11 | functional | EL：who-data endpoint 是 socket，有 listener，且 `wazuh-syscheckd` 已連線（endpoint 路徑上有 LISTEN，以及 ESTAB 的 server 端，其 inode 與 `wazuh-syscheckd` 的 ESTAB client 互指；不看 listener 是哪個程序）；非 RPM 主機（Debian family）此列不涵蓋（直接為 0） | 0 | if command -v rpm >/dev/null 2>&1; then if test -S /var/ossec/queue/sockets/audit && ss -xHap 2>/dev/null | awk -v e=/var/ossec/queue/sockets/audit '$2=="LISTEN" && $5==e {l=1} $2=="ESTAB" && $5==e {s[$6" "$8]=1} $2=="ESTAB" && /wazuh-syscheckd/ {c[$8" "$6]=1} END {if (l) for (k in s) if (k in c) exit 0; exit 1}'; then echo 0; else echo 1; fi; else echo 0; fi |

> C1–C11 全部用**正邏輯 rc**（`; echo $?` 或原生 rc），C9 用
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
> C10 的確切 shell 已在 disposable Ubuntu 24.04 與 AlmaLinux 9 的 4.14.1
> native agent 上探測過；正式驗收須以各 candidate 的 target evidence 證明目前契約。
> 此 row 驗證本機有效版本、pin 與可用性；manager 上限及遠端 identity 另由
> apply 的跨主機 probe 與 topology evidence 驗證，不能由 C10 單獨推論。
> 一般／fresh／既有主機的 C10-only 套用在 writer 內執行 stable agent-verify；
> 版本交易以相同 native version、pin、active proof 加 identity／registry 驗證後
> 才提交，不在 commit 後增加新的可失敗操作。獨立 verify 的 C10 另驗 idle state。
> C10 由安裝在目標上的 root-only coordinator 執行，因此需要 verify 時的 privilege escalation。
> C11（Issue #323）驗證 EL 上 who-data 的本機管線真的接上了，而不是設定文字或檔案存在：原本一個設定了
> `af_wazuh.conf`、但 endpoint 從未建立的 EL 主機通過全部 C1–C10。只看 `test -S` 不夠（plugin 停用後 socket
> 檔仍殘留而沒有 listener），所以另外要求 `ss -xHap` 看到 endpoint 路徑上有 LISTEN，以及 ESTAB 的 server 端，並且它的 inode 與
> `wazuh-syscheckd` 的 ESTAB client 互指（兩端各自的 inode 與對端 inode 互換）。刻意**不**看 listener 是
> 哪個程序：EL 的外部 `audisp-af_unix` 與 auditd 內建的 af_unix 都是合法的 listener，不能因為程序名稱不同
> 而判定一台運作中的主機失敗。刻意**不**要求 kernel `wazuh_fim` watch：`audit-log-forwarding` 每次套用的
> `augenrules --load` 在 #324 之前會把 watch 清為 0 而 endpoint 與連線不變（#324 已改由 `audit-log-forwarding` 處理，見 §2 上方），但本列的穩態判斷不應依賴另一個模組的行為：要求 watch 會讓
> 同機共用的主機在該模組又清掉 watch 時 verify 失敗，也會讓一般套用的 no-op 路徑不再冪等；apply 自己重啟 agent 之後仍要求
> 至少一條 watch，那是該次修復的證明，不是穩態斷言。判斷是否為 EL 用 `command -v rpm`，與 C1／C2 相同，也與 apply 以 `ansible_os_family == 'RedHat'` 決定是否執行 Step 11a
> 一致（不用 `/etc/redhat-release`：沒有該檔的 RedHat family 主機，Step 11a 會執行，這列就必須真的觀察，不能直接印 0）。
> 沒有 `rpm` 的主機（Debian family）這列直接印 0，不涵蓋：Debian 的 who-data
> endpoint 與 watch 沒有任何 row 斷言（見 §2 上方；watch 在 #324 之前被 `audit-log-forwarding` 清掉的問題，見 §2 上方）。C11 讀取 process 名稱與 root 擁有的 socket 路徑，
> 需要 verify 時的 privilege escalation（`ss ` 觸發 `spec.NeedsBecome`）。檢查它是否會誤判：用 `pilot verify
> --probe '<cmd>' -i <inv> -l <host>` 在同一條管線下看實際 rc 與 stdout，不要憑猜測改 Expected。

## 3. 證據收集

- 工具：`go run ./cmd/pilot vm-target verify --name wazuh-fim docs/verification/wazuh-fim.md`
- 輸出格式：`.verification/wazuh-fim-<UTC>.{ndjson,md}`
- 預期 row 數：11（C1–C11）

## 4. PASS / FAIL 規則

- 全部 C1–C11 `status=pass` → **PASS**
- 任一 `status=fail` → **FAIL**，列出 fail id + actual + want

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C7, C8, C9 | 這三條的前提是套用時提供了 `wazuh_manager_host`（見 §1.5，選填）。若 manager 尚未存在、套用時未帶這個變數，playbook 會跳過 `/etc/hosts` pin 與註冊，C7–C9 在 `pilot verify` 會回報 `fail`——這是**預期行為**，不是 bug：此時應驗證 C1–C6、C10 與 C11（本機 FIM 規則、服務、native version／pin 與 EL 的本機 who-data endpoint），待 manager 就緒、補跑一次 apply 帶上 `wazuh_manager_host` 後再驗全部 11 條 | 無 manager 的獨立部署 / manager 尚未就緒的過渡期 | 補上 `wazuh_manager_host` 並重新 apply 後即解除 |
| C9 | 本 spec 只驗證「client.keys 非空」（agent 端已取得憑證），**不**驗證「manager 端也認得這把憑證、連線真的建立成功」——那需要去 manager 端跑 `agent_control -l` 或看 `wazuh-remoted` 的連線狀態，屬於跨主機 Shape 3 cross-check，做法見 `docs/runbooks/wazuh-fim.md` §4 | 所有環境 | 永久（設計如此，非暫時偏差） |
| C5 | 只驗證「至少一個目錄設定 whodata」，不驗證特定站台實際監控的路徑清單是否符合預期（那是逐主機的 `wazuh_fim_directories` 設定責任，見 §1.5）；若要確保某台主機**一定**監控了某個特定路徑，需要另外針對該主機寫查核（例如部署後手動 `grep` 確認），不在本通用 spec 範圍內 | 所有環境 | 永久（設計如此，非暫時偏差） |
| C11 | 只涵蓋 EL（RedHat family）：Debian family 直接為 0，不斷言任何 who-data 狀態（Ubuntu 22.04 的 `builtin_af_unix` 與 aarch64 依維護者決定不在涵蓋範圍）；不要求 kernel `wazuh_fim` watch（穩態 no-op 與 verify 不依賴它；在 #324 之前 `audit-log-forwarding` 的 `augenrules --load` 會把 watch 清為 0，現在由該模組的 C23 驗證）；不辨識 listener 是哪個程序，只證明 endpoint 的 server 端與 `wazuh-syscheckd` 互相連線 | 所有環境 | 永久（設計如此：watch 由 `audit-log-forwarding` 的 C23 驗證，本 row 的穩態判斷不依賴另一個模組的行為）；Debian family 不由本 row 涵蓋 |
| — | Enrollment 使用開放式註冊（manager 端 `use_password=no` 出廠預設），見 `wazuh-manager.md` §5 對應說明 | sandbox / demo | 正式站台上線前檢討 |

## 6. Playbook 對應

對應 apply playbook：`playbooks/apply/wazuh-fim-apply.yml`

| Spec ID | Apply task | 備註 |
|---------|------------|------|
| C1 | Debian APT／RedHat DNF repository + 簽章的 exact `wazuh-agent` install family；既有版本保留、明示升級；native hold／versionlock | 共用 manager 相容性 gate（先讀 manager 原生版本）；未授權的版本變更 typed 拒絕 |
| C2 | `install auditd`（Debian）；`dnf install audit audispd-plugins python3-dnf-plugin-versionlock`（RedHat） | who-data provider=audit 的執行期依賴；EL 的 af_unix plugin `/sbin/audisp-af_unix` 由 `audispd-plugins` 提供，Debian 由 `auditd` 提供；Debian 的安裝清單不變 |
| C3 | `ensure wazuh-agent enabled+started` | 只在設定檔真的變更或剛完成註冊時才重啟 |
| C4 | `ensure auditd enabled+started` | — |
| C5, C6 | `blockinfile` 附加一個新的 `<ossec_config><syscheck>...</syscheck></ossec_config>` 區塊到 `ossec.conf` 檔案末端，`<directories>` 清單用 Jinja loop 依 `wazuh_fim_directories` 逐項展開 | 實測確認 Wazuh 的 XML parser 允許同一份檔案有多個 `<ossec_config>` 根節點並全部合併（套件出廠設定本身也是這樣分兩段），且對同一路徑重複宣告時會**聯集**選項（原本的 `scheduled` 疊加我們新增的 `whodata`），不會互相覆蓋或衝突——見 `docs/runbooks/wazuh-fim.md` §5。只新增管理區塊，不動套件出廠的其餘 `<syscheck>` 預設設定 |
| C7 | `lineinfile /etc/hosts` pin `wazuh-manager` | 必須在改 `<address>` 之前 |
| C8 | `lineinfile` 改 `ossec.conf` 的 `<address>` | 套件出廠預設只有一個 `<address>` 標籤，可安全用單一 regex 取代 |
| C9 | `agent-auth -m wazuh-manager`（只在 `client.keys` 為空且 manager 已提供時執行一次） | 非「每次都跑」，避免每次 apply 都重新註冊、破壞冪等性 |
| C10 | coordinator `agent-verify`（native release、exact pin、服務 active） | 在設定區塊之外執行：驗證失敗不會觸發設定 rollback |
| C11 | Step 11a：coordinator `agent-whodata-ensure`（只在 RedHat family 的一般套用、`--check` 不執行）：endpoint 已有 listener 且 syscheckd 已連線則只驗證；listener 在但未連線則重啟一次 agent；endpoint 不存在且 plugin `active = yes` 則對 auditd 主程序送一次 SIGHUP、等 endpoint、重啟一次 agent、再證明連線與至少一條 `wazuh_fim` watch | 排在 Step 11 的 agent 重啟之後、Step 11b／C10 之前，在一般套用的 rollback block 之內；單獨 `--tags C11` 可重跑；typed refusal 讓套用失敗，rescue 不重啟 auditd、不回復 SIGHUP；Debian family 不執行 |

## 7. SOP

### 7.1 標準情境：manager 已存在（註冊啟用，驗證全部 11 條）

> **Issue #244 起的前提**：啟用 enrollment 時，manager 必須是**同一份 inventory** 的 host
> （`wazuh-manager` group 或 `wazuh_manager_inventory_host`），apply 才能在動 agent 之前讀它的
> 原生版本。下面這組單一 VM 加外部 `MANAGER_IP` 的指令因此只適用於省略 `wazuh_manager_host`
> 的 §7.2 情境；要驗證完整鏈路請用多節點拓樸
> （`docs/topologies/wazuh-version-topology.yaml`，manager 與 agent 在同一份 inventory）。

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
# verify 時 C7-C9 預期 fail（見 §5），檢查 C1-C6、C10 與 C11 是否全 pass

# 之後 manager 就緒：
go run ./cmd/pilot vm-target run --name wazuh-fim \
    playbooks/apply/wazuh-fim-apply.yml \
    -e wazuh_manager_host=$MANAGER_IP
```

> vm-target 的 inventory 只有單一 host key（見 `vm-target-basics.md`），
> playbook 的 `hosts:` 預設 `wazuh-fim` 與該 host key 同名，不需要
> `-e target_group=` override（同 `log-server.md`/`audit-log-forwarding.md` 的設計）。

目前 candidate-bound 多平台／跨主機 actual-run 結果見
[evidence](../evidence/wazuh-manager/LATEST.md)；本機 C10 不代替 agent transport 或實際 who-data event 驗收。

## 8. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-06 | v1.0 | 初版：Wazuh agent FIM（`/etc`、`/boot` whodata）+ auditd who-data provider + 向 `wazuh-manager.md` 註冊 | sre |
| 2026-07-06 | v1.1 | `wazuh_fim_directories` 改為可依主機覆寫的變數清單（不同主機可監控不同路徑），預設仍是 `["/etc", "/boot"]`；對應把 C5/C6（原本各自綁死 `/etc`/`/boot` 字面值）合併成單一「至少一個 whodata 目錄」的通用檢查，原 C7-C10 遞補成 C6-C9（row 數 10 → 9），見 §1.5、§2 的重排說明 | sre |
| 2026-07-22 | v1.2 | C1/C2 package probe 改為 Ubuntu dpkg 與 EL rpm 雙平台；相同候選指令已在 Ubuntu 24.04 與 AlmaLinux 9 的目標 inventory 實跑通過 | sre |
| 2026-11-04 | Issue #244 | 原生 installed/candidate 必須相容於實際 manager；fresh exact signed package、穩態 APT hold／DNF versionlock，明示升級保留 cold data/config、enrollment、audit endpoint 與同 owner recovery；C10 驗本機版本與 protection，完整鏈路另以 target evidence 驗收。 | sre |
| 2026-11-05 | Issue #244 (A) | 版本相容契約：先讀 manager 原生版本再動 agent、新安裝固定完整版本、相容的既有 agent 保留、任何版本變更與 agent 新於 manager 一律 typed 拒絕；native hold／versionlock 保護；C1 接受 native hold 狀態；新增 C10（原生版本、pin、服務）。升級與回復不在本版範圍。 | pilot |
| 2026-11-06 | Issue #244 (A) | 原生實跑後修正：安裝的 coordinator 可直接執行（shebang）；enrollment 拒絕的 typed 原因可見；被拒絕的 EL stage 不留私有目錄；明確記載 apt hold 與明確版本安裝的語意、manager 端「從未連線／pre-4.14 agent」fail closed 與移除方式。未放寬任何 Expected。 | pilot |
| 2026-11-09 | Issue #244 (B) | 以已合併的 A（#271）為基底重新整合受控升級（B）：版本契約由 A 負責、B 只加 writer／transaction／reader／preview；未授權的版本變更仍 typed 拒絕，單次 `wazuh_upgrade=true` 才進入受控交易；版本升為 v1.5。未放寬任何 Expected。 | pilot |
| 2026-11-10 | Issue #244 (B) | 文件補記（無 Expected 變更，C1–C10 不變；不新增、不收緊、不放寬任何 row）：記載 EL 的一般套用不建立 who-data endpoint（缺 `audispd-plugins`）與其後果——受控 agent 升級以 `configured external audit endpoint is unavailable before upgrade` 拒絕、不改動 agent，拒絕後留下 `agent-policy-<owner>` 與約 22 MB 的備份根目錄增長（主要是 staged RPM）；實測過的手動修復順序與順序探測結果；Ubuntu 22.04 與 aarch64 不在涵蓋範圍；`audit-log-forwarding` 的 `augenrules --load` 與 auditd 重啟會清除同機 `wazuh_fim` watch 的既有行為；備份不自動清除的已知限制。這些是已知限制的記載，不是新的保證；一般套用建立 who-data 的設計已自本版範圍移除。 | pilot |
| 2026-11-12 | Issue #324 | 文件更新（無 Expected 變更，不新增、不收緊、不放寬任何 row）：`audit-log-forwarding` v2.1 改由該模組負責不讓 `augenrules --load`／auditd 重啟清掉同機的 `wazuh_fim` watch（只在需要時載入；擾動前讀本協調器的唯讀 `writer-inspect` 並在 writer 進行中時拒絕；擾動後重啟 `wazuh-agent` 並有上限地等 watch 回來，否則 typed 失敗）。更新「已知限制（其他元件）」與 ownership 契約的例外說明，並列出仍存在的限制。wazuh-fim 的 playbook、coordinator 與 spec row 都沒有改。目標環境實跑結果見 `docs/evidence/audit-log-forwarding/LATEST.md`。 | pilot |
| 2026-11-12 | Issue #324 | 文件修正（無 Expected 變更，不新增、不收緊、不放寬任何 row）：「已知限制（其他元件）」改記 2026-11-12 在拋棄式 Ubuntu 24.04.4 VM 以 BASE 量到的 Wazuh 自癒行為（前兩次清除自行補回、連續第三次起退回 real-time 且不再恢復），EL 9.8 上 Step 8b 的 SIGHUP 已量過不是擾動，並明記既有的 EL 順序缺口（audit-log-forwarding 的 SIGHUP 先於 Wazuh agent 套件安裝 `af_wazuh.conf`，同機全新鏈套用後 endpoint 尚未 live，之後需要 `pkill -HUP -x auditd`；這個缺口已由 Issue #323 修復，不屬於 #324，與 main 整合後的鏈實跑見 `docs/evidence/audit-log-forwarding/LATEST.md`）。 | pilot |
| 2026-11-12 | Issue #323 | EL 的一般套用建立 who-data endpoint，否則套用失敗：RedHat family 的 Step 4 安裝 `audispd-plugins`（C2 的 EL 檢查收緊為 `rpm -q audit audispd-plugins`）；新增 Step 11a（tag C11，只在 RedHat family 的一般套用）以 coordinator `agent-whodata-ensure` 在 agent 最後一次服務變更之後確保 endpoint：已存在且 syscheckd 已連線則不變更；listener 在但未連線則重啟一次 agent；endpoint 不存在且 plugin 啟用則一次 SIGHUP、等待、一次 agent 重啟並證明連線與至少一條 watch；其餘情形 typed refusal。新增 C11（EL；endpoint 為 socket 且 `wazuh-syscheckd` 已連線；不看 listener 程序、不要求 watch，原因見 §2 與 #324；Debian family 不涵蓋）。row 數 10 → 11；C1–C10 的 ID 與 Expected 不變，C2 的 EL 檢查收緊，沒有放寬任何 Expected。受控升級的 admission gate 不變；舊的 EL 主機須先完成一次一般套用才能升級。原生驗收以各 candidate 的 target evidence 為準（`docs/evidence/wazuh-fim/`）。 | pilot |
