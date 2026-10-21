# Runbook — audit-log-forwarding

對齊 [verification spec v2.0](../verification/audit-log-forwarding.md)、
[apply playbook](../../playbooks/apply/audit-log-forwarding-apply.yml) 與
[audit rules template](../../playbooks/templates/audit.rules.j2)。

## 0. 目標與範圍

在受管主機安裝 auditd 規則、啟用 audisp-syslog，將 `local6` 與
`auth,authpriv` 送到中央 SIEM。預設是具有磁碟輔助佇列的 TCP；
RELP/mTLS 的輸入、輪替與保證邊界見 [RELP runbook](./siem-relp-mtls.md)。

## 0.5 目前有效的事實快照

2026-10-20，候選 `34cfabea416eb9645aaa323e541198ae39bbbe96`，
tree `67f0299bcd8a39fc77ffd0e85821e6576ebd7211`，正式 target run 由乾淨隔離 checkout 執行。
實際 inventory：`log-server = aq-log`；
`audit-log-forwarding = aq-log, aq-ubuntu, aq-el`。前兩台 Ubuntu 24.04.4、後者 AlmaLinux 9.8
（SELinux Enforcing）；對齊採 A，中央主機也部署 forwarding 以提供本機 selftest。
使用獨立測試 CA 與私密 PEM 輸入（`siem_relp_ca_pem`、`siem_relp_cert_pem`、
`siem_relp_key_pem`），未使用正式 vault／PKI。

Fresh L3/L4 通過，receiver **11/11**、sender **66/66**，L6 三台 **changed=0**。
三台 × 四種 TLS 狀態的 **12 項** rollback 負例、兩種 OS 的 C19 程序保留均通過；
負例後再次 **77/77**、全鏈三台 **changed=0**。整庫普通 Go、race、build、vet、
golangci-lint 與阻擋性 playbook／CI 同等檢查通過；L2 ansible-lint 仍有 advisory findings。
測試 VM 已清理，共用 cache services 保留運行。

本輪未重跑大流量、輪替與 decommission；歷史結果保留原候選歸屬。
完整版本、指紋與驗證範圍見 [本輪證據摘要](../evidence/siem-relp-mtls/2026-10-20-34cfabe-review.md)。

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

spec 共 C1–C22。C16/C17 會注入對應 facility，檢查真實 daemon 的獨立 queue worker，
並確認 profile／設定已載入；C22 在 RELP 模式還必須通過雙向 TLS 與 RELP ACK。
全部目標與全部 row 通過，才是完整的 forwarding 驗收。

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
