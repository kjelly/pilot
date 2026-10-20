# Runbook — log-server

對齊 [verification spec v2.0](../verification/log-server.md) 與
[apply playbook](../../playbooks/apply/log-server-apply.yml)。

## 0. 目標與範圍

接收 audit/auth 日誌，經專屬 siemReceiver ruleset 寫入
`siem_log_root/<hostname>/{audit,auth}.log`。預設 TCP；
選用 RELP 時強制 mTLS，遠端純 TCP 會被 loopback 綁定限制。
完整 TLS 契約見 [RELP runbook](./siem-relp-mtls.md)。

## 0.5 目前有效的事實快照

2026-10-20，候選 `be23874ca4153ed009671b96ae21c239b6061267`，
tree `b92729e5be05fa98cef56f0ef1ca6c2c1014ad96`，由乾淨隔離 checkout 執行。
實際 inventory：`log-server = aq-log`；
`audit-log-forwarding = aq-log, aq-ubuntu, aq-el`。前兩台 Ubuntu 24.04、後者 AlmaLinux 9
（SELinux Enforcing）；對齊採 A，中央主機也部署 forwarding 以提供本機 selftest。
測試使用獨立 CA 與每台私密 PEM（`siem_relp_ca_pem`、`siem_relp_cert_pem`、
`siem_relp_key_pem`），未使用正式 vault／PKI。

Fresh L3/L4 通過，receiver **11/11**、sender **66/66**，L6 三台 **changed=0**；
整庫 build、vet、race 及阻擋性 playbook 檢查通過。重啟及停機補送各 **1,440/1,440**，
落盤後重啟 client **72,000/72,000**、重複 **4**。mTLS 負例、輪替、rollback、peer 撤除、
TCP 私密材料退役及重新啟用均通過。decommission 保留 **6,000/6,000** 待送 ID 與
9 個 spool 檔案的原 SHA256。測試 VM 已全部清理，共用 cache services 維持運行。

完整版本、image／source 指紋與驗收範圍見 [本輪證據摘要](../evidence/siem-relp-mtls/2026-10-20-be23874c.md)。

## 1. 目標與輸入

預設目標群組為 `log-server`。本 spec 的 package row 使用 dpkg，正式完整 row 驗收平台
為 Ubuntu 24.04；AlmaLinux 9 的 forwarding 與 SELinux 行為另由 sender spec／跨主機演練驗證。
`stage` 必須符合 inventory 的 staging/prod 環境群組，並具備相應確認。

TCP 預設埠 514，根目錄預設 `/var/log/siem`，保留 rotate=14、maxage=90。
實際變數以 spec §1.5 與 [group_vars 範例](../../group_vars/log-server.example.yml) 為準。
RELP 使用獨立埠，預設 20514；須提供 CA、server cert/key 與允許的 client DNS 名稱清單。

`siem_log_root` 必須是獨立絕對路徑，不能指向共用目錄或以 symlink 繞到共用樹。
目錄由 rsyslog 執行帳號擁有，才能建立各來源主機的子目錄。
`siem_receiver_tcp_port` 必須是十進位 1–65535；非預設埠的 SELinux type 不可屬於其他服務。
先前建立的 port label 不會自動刪除。

## 2. 部署與驗收流程

先讀實際 inventory，確認接收端與同機 forwarding 的角色都存在，再部署 receiver、sender。
本輪使用 [三機拓樸](../topologies/audit-forward-queue-topology.yaml) 與
[RELP 測試 chain](../../playbooks/test/siem-relp-chain.yml) 跑全新 target 的
check mode → apply → verify → 第二次 apply。上游套件前置只限測試 VM，
正式主機由部署方先提供具有必要能力的套件與 PKI。

spec 共 C1–C11。C4 檢查實際載入的 transport、有效材料、daemon listener 與 TCP loopback 限制。
C7/C8 每次注入新的 local6/authpriv nonce，等待它寫入目前設定的根目錄，不能用舊 selftest PASS。
它們是同機 selftest；跨主機訊息與故障補送的證明由
[audit forwarding 流程](./audit-log-forwarding.md) 提供。

## 3. 自我轉送與來源身分

所有 imtcp/imrelp input 綁定 siemReceiver ruleset，收到的日誌直接分檔後 stop。
中央主機也會收集自己的稽核；若網路輸入落回 default ruleset，就會再次匹配 sender，
造成無限自我轉送並填滿磁碟。C11 允許 input 的其他屬性，但一定要有正確的 ruleset。

mTLS 驗證的是 peer。檔案路徑的 HOSTNAME 仍來自訊息 payload，沒有與憑證身分綁定；
不能把每個目錄的名稱當成已驗證的來源主機。

## 4. 根目錄權限與復原

非 /var/log 的根目錄由 AppArmor local rule 或 SELinux var_log_t mapping 提供 rsyslog 寫入權限。
換根目錄時，先同時保留新舊 grant，直到確認服務已跑新設定、持有 listener，才縮小 AppArmor grant。

block/rescue 還原本輪前的 drop-in、logrotate、TLS profile 與材料；
只有安全確認服務使用舊設定後，才撤除本輪新增的根目錄 grant。
無法確認安全撤除時保留 grant，避免把仍運行的服務切斷寫入權限。
舊 port label 與接收日誌不視為本輪可任意刪除的資源。

## 5. 維護注意事項

- 重啟必須由設定／材料／有效權限或載入時間的變更觸發，不能每次 apply 都 restarted。
- UFW/firewalld 的站台政策仍需另行驗證；本輪拋棄式環境未啟用它們。
- RELP 啟用時只對網路開放 mTLS listener；舊 TCP 只留 loopback，其他遠端 TCP client 需同步遷移。
- ACK、容量、重複、葉憑證輪替與單張撤銷的邊界，以 RELP runbook 為準。
