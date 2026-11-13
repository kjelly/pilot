# Runbook — audit-log-forwarding

對齊 [verification spec v2.0](../verification/audit-log-forwarding.md)、
[apply playbook](../../playbooks/apply/audit-log-forwarding-apply.yml) 與
[audit rules template](../../playbooks/templates/audit.rules.j2)。

## 0. 目標與範圍

在受管主機安裝 auditd 規則、啟用 audisp-syslog，將 `local6` 與
`auth,authpriv` 送到中央 SIEM。預設是具有磁碟輔助佇列的 TCP；
RELP/mTLS 的輸入、輪替與保證邊界見 [RELP runbook](./siem-relp-mtls.md)。

## 0.5 目前有效的事實快照

2026-10-30，候選 `c97caf38cb0694274b65a5e2a07537fafe69421e`，
tree `c13922899fc1bfaa26ec5f496c3d626b3202f86a`（PR #188：Step 1d preflight 與 Step 5a–5e 的
distro rsyslog policy 改寫），正式 target run 由乾淨隔離 checkout 執行。
實際 inventory：`log-server = pr188-log`；
`audit-log-forwarding = pr188-log, pr188-u24, pr188-el9`。前兩台 Ubuntu 24.04.4
（logrotate 3.21.0）、後者 AlmaLinux 9.8（SELinux Enforcing，logrotate 3.18.0）；
對齊採 A，中央主機也部署 forwarding。TCP 預設，未使用 vault。

Fresh L3/L4 通過，receiver **11/11**、sender **66/66**，L6 三台 **changed=0**；
套用後三台 `logrotate -d` 無重複、無解析錯誤，`logrotate.service` 成功。
邊界案例（單獨的 `/var/log/syslog` stanza 以 BASE/本版對照、glob 在 Step 1d 於第一次設定檔寫入前拒絕、
EL 只剩一個路徑時移除檔案、保留 mode/owner/group 與 symlink）均通過；BASE 在單獨 stanza 與 glob
兩種情況都留下 `duplicate log entry`。測試 VM 已清理。
完整版本、指紋與驗證範圍見 [本輪證據摘要](../evidence/audit-log-forwarding/2026-10-30-c97caf38cb06.md)。

issue #324（spec 的 C23：本模組不再清掉同機 Wazuh 的 who-data watch，見 §5.6）已對目標環境實跑：
全新 Ubuntu 24.04 與 AlmaLinux 9 VM 的 `topology test --ephemeral`（含已合併的 Issue #323）通過 L1–L6，verify 全部 PASS、
無 FAIL，第二次 apply `changed=0`；tested candidate、各份 verify 的數字、失敗路徑（外部 `-D`、規則檔被改、agent 停止、
Wazuh writer 進行中、rescue）與未涵蓋範圍見[最新 evidence](../evidence/audit-log-forwarding/LATEST.md)。
上面 2026-10-30 的快照是 #324 之前的 candidate，不涵蓋 #324。

RELP/mTLS、大流量、輪替與 decommission 本輪未重跑；RELP/mTLS 最後驗證於 `34cfabea416eb9645aaa323e541198ae39bbbe96`，
見 [該次證據摘要](../evidence/siem-relp-mtls/2026-10-20-34cfabe-review.md)。

## 1. 部署契約

目標群組預設為 `audit-log-forwarding`，平台為 Ubuntu 24.04 與 AlmaLinux 9。
`stage` 必須符合實際 inventory 的環境群組；staging/prod 另需相應確認。
中央接收端先部署，主機與目的埠從本次實際 inventory 或明確的站台變數取得。

`siem_forward_host` 未指定時，apply 先從 inventory 的 log-server、再從 wazuh-manager
解析目標；兩者都沒有時只做本機稽核，不建立新的轉送設定。這種模式不滿足 C15–C17/C22，
不能標成「完整 SIEM 轉送已通過」。

TCP 使用 `siem_forward_port`，須是 1–65535 的十進位整數，並與 inventory 接收端埠一致。
RELP 改用獨立的 `siem_relp_port`，兩端明確選用 RELP，並提供每台主機的憑證與私鑰。
變數清單以 spec §1.5 及 [group_vars 範例](../../group_vars/audit-log-forwarding.example.yml) 為準。

## 2. 目前使用的驗收流程

本輪使用 [三機拓樸](../topologies/audit-forward-queue-topology.yaml)：
先讀 vm-target topology inventory 的實際 group/host，再由 vm-target topology test 完成
fresh check mode → apply → 兩份 spec verify → 第二次 apply 的 changed=0。

RELP 測試入口為 [siem-relp-chain.yml](../../playbooks/test/siem-relp-chain.yml)，其
[套件前置](../../playbooks/test/fixtures/siem-relp-runtime.yml) 只允許拋棄式 aq-* VM，
不能當作正式主機的套件來源管理。正式 apply 是上述 apply playbook，
需要接收端的設定、相同的協定與埠，以及部署方管理的私密 PEM。

稽核/auth 的跨主機驗收使用 [編號訊息 harness](../../scripts/audit-forward-queue-test.py)，
分別統計 unique ID、遺失與重複。只看 TCP 連線、設定檔內容或本機舊日誌，不足以證明補送。

## 3. 驗證與復原

spec 共 C1–C23。C16/C17 會注入對應 facility，檢查真實 daemon 的獨立 queue worker，
並確認 profile／設定已載入；C22 在 RELP 模式還必須通過雙向 TLS 與 RELP ACK。
全部目標與全部 row 通過，才是完整的 forwarding 驗收；C23 只在同機有運作中的 Wazuh who-data 時才有內容（§5.6）。

設定變更在 block/rescue 內執行；失敗會還原原設定與 TLS 材料並嘗試恢復服務。
角色移除只能走正式 host decommission provider；待送 spool 保留供稽核／復原，
私密 sender 目錄與元件 helper 會清除。

## 4. TCP 與 RELP 的補送邊界

TCP socket 成功寫入或取得 TCP ACK，只代表資料到達對方的 TCP stack，不能證明 receiver
應用程式已處理。先前 [TCP 驗收](../evidence/audit-forward-queue/2026-10-20-b9a58332.md)
在持續送訊息時重啟 receiver，收到 1,437/1,440，遺失 3 筆在途訊息；
確認停機後的補送與落盤重啟則完整送達。此限制由 RELP 的應用層 ACK 與重試改善。

兩種模式的每個 action 仍各有 256 MiB 磁碟預算。RELP 可能重送，ACK 也不代表最終檔案
已 fsync；斷電、容量耗盡、上游尚未交給 rsyslog 的資料及後續 Loki 不在傳輸保證內。

## 5. 仍影響操作的注意事項

### 5.1 稽核規則順序

sudo/passwd/sudoers 的具體規則必須在泛用 setuid/setgid execve 規則之前；
audit 核心 filterlist 第一條符合即停止，順序錯誤會讓 sudo 事件只留下泛用 key。

### 5.2 事件與 audisp facility

C11 直接檢查新的 sudo 稽核事件；Ubuntu enriched 欄位格式可能讓 ausearch 找不到實際存在的事件。
audisp-syslog 必須為 active，且 args 固定為 LOG_INFO LOG_LOCAL6，否則 local6 轉送沒有來源。

### 5.3 檢查必須能失敗

Direct queue、未載入的新設定、以及服務未載入 forwarding fragment 都應讓 probe 失敗。
numeric Expected 使用實際 rc，不能用會把 FAIL 吞成成功的 wrapper。

### 5.4 關機與儲存空間

RELP 的 session/connect timeout 與 queue 關機界限見 RELP runbook。
無限次重試不等於無限容量，需監控 spool 所在檔案系統。

### 5.5 distro logrotate 的重複宣告

Ubuntu 與 EL 的 distro rsyslog policy 都可能已宣告 syslog/messages。
apply 會先安裝 logrotate，再移除重複的路徑宣告並保留其他 stanza；C20 檢查全機重複項，
避免任一元件的重複規則使整個 logrotate 中止。

### 5.6 與同機 Wazuh who-data 共用 kernel 稽核清單（issue #324）

kernel 的稽核規則清單是同機各元件共用的：Wazuh agent 的 who-data 把 `wazuh_fim` key 的 watch 放在
同一份清單裡。`augenrules --load`（它讀進來的 `/etc/audit/audit.rules` 以 `-D` 開頭，而且 augenrules
在回報「No change」時照樣呼叫 `auditctl -R`）與 Ubuntu 24.04 的 auditd 重啟（`ExecStartPost` 也載入規則）
都會先清掉整份清單。2026-11-12 在拋棄式 Ubuntu 24.04.4 VM（同機 log-server、audit-log-forwarding、
wazuh-fim 與真實 manager）以舊版實測：前兩次清除 Wazuh 自行補回（記下 `Detected Audit rules manipulation:
Audit rules removed.`，watch 數秒內回到 2 條）；連續第三次起 watch 為 0，listener 仍在、agent 仍為 active，
`ossec.log` 出現 `Real-time file integrity monitoring started`（退回 real-time），之後沒有自行恢復；
一次 `systemctl restart wazuh-agent` 後 3 秒內回到 2 條。「Wazuh 不會自行補回」只在它的自癒次數用完之後才成立，
所以不能依賴它。C1–C22 沒有任何一條看得到這個狀態。現在的行為（apply playbook Step 3、Step 8d/8e/8a、
Step 10、rescue；spec §5 與 §6 有完整說明）：

- 只在需要時才載入：規則檔這次有變、`augenrules --check` 回報有差異或讀不出結果（規則參數被改但 key 不變時
  只有它看得到）、或 kernel 缺少本模組管理的 rule key。已收斂的主機不載入、不重啟 auditd、不重啟 agent
  （`changed=0`）。`--tags C3`..`C9` 只改檔不載入，之後的完整套用或 `--tags C10` 會補上（kernel 與檔案不同步時
  下一次一定會載入）。
- 載入或重啟 auditd 之前，guard 先當場重讀 agent 與 kernel 清單（不用 play 開始時的快照：Step 1 的套件
  安裝可能在 play 中途才讓 `auditctl` 出現），再讀 Wazuh 協調器的唯讀 `writer-inspect`（只在主機有
  `wazuh-agent` unit 時），在 kernel 清單被動到之前失敗：`wazuh_writer_active`（有 Wazuh writer 或 journal
  在進行，例如受控 agent 升級，或協調器沒有回答）、`whodata_state_unreadable`（讀不到 agent 狀態，或 agent
  為 active 而 `auditctl -l` 讀不出來）、`wazuh_agent_transitioning`（agent 正在啟動、停止或自動重啟，who-data
  是否 live 無法判定）。處理方式：等 Wazuh 的操作或 agent 穩定（或用 owner token 回復）後重跑。`auditctl`
  不存在不是拒絕的理由（那時 who-data 不可能 live）。拒絕之前這次 run 的其他步驟（套件、設定檔）可能已經執行，
  被還原的只有規則檔。這是檢查不是鎖，檢查到動作之間有一小段空窗。
- 擾動前 agent 為 active 且 kernel 有 `wazuh_fim` watch 的主機（集合 S，由 guard 在第一次擾動之前當場讀取）：
  這次 run 的最後一次擾動之後，等 auditd 與 `/var/ossec/queue/sockets/audit` 上的 `audisp-af_unix` listener
  回來、重啟一次 `wazuh-agent`、再有上限地等 watch 回來（預設 30 秒與 60 秒，可用
  `-e audit_whodata_endpoint_timeout=`、`-e audit_whodata_watch_timeout=` 調整）。沒有回來就以 typed reason
  失敗：`endpoint_not_ready`、`agent_restart_failed`、`watches_not_restored`、`kernel_unreadable`（錯誤訊息列出
  還缺的 watch）。這一步失敗不回滾已套用的規則與轉送設定；修好原因後 `systemctl restart wazuh-agent` 並用 C23
  確認。
- agent 不存在、已停止、或擾動前 kernel 沒有 `wazuh_fim` watch（例如 Issue #323 之前套用的 EL 舊主機，endpoint 尚未建立，見下）的主機：
  本模組永遠不啟動或重啟 agent。這類主機只會被上面的擾動前檢查拒絕（有 `wazuh-agent` unit、而且 Wazuh
  writer／journal 在進行中、讀不到狀態或 agent 在轉換中時；agent 已停止正是受控升級進行中的樣子），拒絕發生
  在 kernel 清單被動到之前；沒有 `wazuh-agent` unit 的主機完全不受 Wazuh 影響。
- 失敗路徑：rescue 只在這次 run 載入過、而且規則檔被還原或移除（或載入本身失敗）時才重載 kernel 清單；
  重載之後重新建立 who-data。最後的錯誤訊息如實說明規則檔、kernel 清單與 who-data 各自的結果。

**被舊版清掉 watch 的主機（一次性處理）**：這個版本不會自動修復已經被舊版清掉、至今沒重啟 agent 的主機
（沒有新的 heal 路徑）。在那台主機上確認 `sudo auditctl -l | grep wazuh_fim` 沒有輸出但
`systemctl is-active wazuh-agent` 為 active 後，執行一次 `sudo systemctl restart wazuh-agent`，再用 spec C23
確認 watch 回來。

仍然存在的限制：

- EL 上 Step 8b 的 `pkill -HUP -x auditd` 不經過 `augenrules`，已在 AlmaLinux 9.8（Wazuh agent 4.14.x）量過
  不視為擾動：who-data 已 live 時連續 6 次 SIGHUP（間隔 8 秒），`wazuh_fim` watch 與 kernel 清單總數不變、
  `audisp-af_unix` 的 PID、連線與 listener 不變；以真實 playbook 在 plugin 設定漂移下重跑結果相同。只量過
  plugin 設定變更觸發的 HUP 與單純 HUP。
- EL 的順序缺口（#324 之前量到，已由 Issue #323 的 wazuh-fim Step 11a 修復，不屬於 #324）：audit-log-forwarding 的 Step 1a 會安裝
  `audispd-plugins`，但 Wazuh agent 套件在 audit-log-forwarding 的 SIGHUP 之後才安裝
  `/etc/audit/plugins.d/af_wazuh.conf`，auditd 尚未被告知載入它。2026-11-12 在拋棄式 AlmaLinux 9.8 上，
  audit-log-forwarding 先於 wazuh-fim 的全新同機鏈套用完成後，endpoint 沒有 listener、who-data 不是 live；
  之後 `pkill -HUP -x auditd` 才讓 listener 出現。這時 C23 回 0，本模組不碰 agent。who-data 已 live 的 EL 主機被
  外部 `auditctl -D` 清掉後再套用：watch 被補回（agent 重啟一次），下一次套用 `changed=0`。
- Ubuntu 22.04 沒有涵蓋、沒有 capture：auditd 內建 af_unix，沒有外部 `audisp-af_unix` 行程。re-arm 與 C23 只認
  `audisp-af_unix` 在 endpoint 上 LISTEN，所以 who-data 在 22.04 上 live 時，擾動之後 re-arm 以
  `endpoint_not_ready` 失敗、不重啟 agent（kernel 清單已被清掉，需要手動 `systemctl restart wazuh-agent`），
  C23 一律回 0。aarch64 同樣沒有實測。
- Step 8（C18）啟動原本停止的 auditd 不追蹤；host decommission 的 `augenrules --load` 是整機退役的一部分，
  不在範圍內。
