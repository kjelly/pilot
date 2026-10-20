# SIEM 的 RELP 與 mTLS

## 0. 目標

讓 audit/auth 日誌以雙向憑證驗證的 RELP 送到中央 rsyslog，並在斷線後補送未確認的訊息。

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

既有 TCP 是預設值。RELP 必須明確開啟，而且一律使用 mTLS，沒有驗證失敗後降回 TCP 的路徑。
兩端共用獨立的 `siem_relp_port`，預設 20514；它不得等於舊 TCP 埠。

| 位置 | 設定 |
|------|------|
| 接收端 | `siem_receiver_relp_enabled: true`；`siem_relp_client_names` 列出允許的 client 憑證 DNS 名稱 |
| 轉送端 | `siem_forward_transport: relp`；`siem_relp_server_name` 是 server 憑證的 DNS 名稱 |
| 各主機 | 由私密 host/vault 變數提供 `siem_relp_ca_pem`、`siem_relp_cert_pem`、`siem_relp_key_pem` |

名稱使用精確的小寫 FQDN，不能用 wildcard。server 憑證需要 `serverAuth`，client 憑證需要
`clientAuth`；同機兼任兩端時使用雙用途憑證。私鑰須能無互動載入，並與該主機的憑證匹配。
pilot 不簽發 CA、不自動續期；正式 PKI 的簽發、期限監控與更新由部署方管理。
設定範例見 [receiver](../../group_vars/log-server.example.yml) 與
[sender](../../group_vars/audit-log-forwarding.example.yml)；私鑰不得寫入公開範例。

轉送端必須支援 `tls.permanentFailureDisablesAction="off"` 與 `queue.diskQueueType="disk"`，
即上游 rsyslog 8.2608.0+ 或具有相同能力的 vendor backport。apply 會以實際模組解析檢查能力，失敗時在替換 live
憑證與轉送設定前停止。僅設定無限重試，無法避免舊模組在 TLS 認證錯誤後永久停用 action。
正式套件來源與升級由部署方管理，production apply 不會新增第三方 repository。

RELP 切回 TCP 時保留兩個 action 的 classic engine pin，再啟用 RELP 時不會改變
spool 格式。既有 TCP 若未明確固定 classic，且兩個 queue 都沒有可確認的 classic
格式證據，apply 會在變更 TLS／轉送設定或重啟服務前拒絕啟用 RELP。空 spool 不能
證明安全：auto engine 可能直到停機保存記憶體佇列時才首次寫出 segmented 資料。
這種既有狀態須由操作者完成遷移規劃；pilot 不會自動轉換或刪除 backlog。
簽章驗證且固定版本的上游套件前置只存在於限定 `aq-*` VM 的測試 fixture。
選項語意見 [rsyslog 官方文件](https://docs.rsyslog.com/doc/reference/parameters/omrelp-tls-permanentfailuredisablesaction.html)。

RELP 明確固定 classic disk engine。8.2608 的新 queue 預設 auto 會選用實驗性的 segmented engine，
不在本功能的支援契約內。既有 `.segq` store、segmented 或未知 `.da-engine` marker 會讓 apply
在替換 TLS／設定前失敗，完整保留 backlog。先由部署方安排排空與格式遷移；pilot 不會自動轉換或刪除。
格式選擇見 [官方 queue 參數](https://docs.rsyslog.com/doc/rainerscript/queue_parameters.html)。

先部署 receiver，再部署 sender，最後執行兩份 spec。啟用 RELP 時，receiver 的舊 TCP
listener 限制在 `127.0.0.1`，遠端 client 必須通過 mTLS；既有遠端 TCP client 需要一併遷移。
既存防火牆規則不會被當成此功能的專屬資源刪除，防繞過的邊界是實際 listener 綁定位址。
中央主機自己的 audit/auth 仍走 sender → 專屬 `siemReceiver` ruleset，避免自我轉送迴圈。
切換期間尚存的舊 TCP 連線仍有原來的在途訊息風險；需安排維護與排空，不能把
RELP 穩態的補送結果當成舊 TCP 遷移過程的零遺失保證。

## 2. 驗收與維護

[receiver spec](../verification/log-server.md) 的 C4 檢查有效憑證、設定載入時間、實際服務的
RELP listener 及舊 TCP 的 loopback 限制。[sender spec](../verification/audit-log-forwarding.md)
的 C16/C17 檢查兩個獨立 action queue 與實際 worker；C22 除了驗證 daemon 本身已建立連線，
還會以本機 client 憑證驗證 server 身分，完成 RELP open/syslog 交易並等待成功 ACK。
只有 TCP/TLS 握手成功不能通過 C22。verify 不會替服務重啟。

私密材料各自位於 `/etc/rsyslog.d/pilot-relp-sender/` 與
`/etc/rsyslog.d/pilot-relp-receiver/`。目錄 0750、PEM 0640，Ubuntu 為 root:syslog，
EL 為 root:root；Ansible 對私鑰輸入與還原使用 `no_log` 並關閉 diff。

輪替時更新相同輸入並重新 apply；PEM 或 desired profile 有變會重啟 rsyslog，重新載入材料。
本輪驗收涵蓋同一 CA、相同 DNS 身分的 leaf/key 輪替；跨 CA 的信任鏈遷移由部署方規劃。
套用失敗會還原此輪之前的 PEM、profile 與設定。peer 名單變更也需要 apply 與重新驗收。
從名單撤除名稱可以停止該身分連入；同名憑證的單張撤銷及 CRL/OCSP 管理不在本自動化範圍。

明確將 sender 改回 `tcp`、receiver 關閉 RELP，會恢復原本 TCP 網路接收。
確認服務已載入非 RELP 設定後，才刪除該角色的 CA/cert/key；desired profile 保留供 verify。
移除 forwarding 角色則由正式 host decommission provider 清除 sender 私密目錄與 helper；
若同機 receiver 仍擁有共用 helper，會保留它。待送 spool 保留，不視為可丟棄的設定檔。

## 3. 從實測得到的設定

RELP session timeout 為 5 秒、connect timeout 為 3 秒；queue 關機排空為 1 秒，
目前 action 最多允許 10 秒完成。中央主機會轉送自己的日誌，若沿用模組的 90 秒預設等待，
receiver 停機可能卡到 systemd timeout。這組界限仍需配合實際負載與停機時間評估。

每個 action 有 10,000 筆記憶體 queue，8,000 筆開始落盤、降到 2,000 筆回到記憶體，
各有 256 MiB 磁碟預算。Ubuntu spool 在 `/var/spool/rsyslog/pilot-siem`，
EL 在 `/var/lib/rsyslog/pilot-siem`。需監控容量，無限次重試不代表無限儲存空間。

## 4. 保證的邊界

本功能改善 rsyslog 已接受訊息後的傳輸確認與補送。RELP 可能重送未確定的交易，不能宣稱
exactly-once；消費端需要自行處理重複。ACK 不等於最終檔案已 fsync，也不涵蓋斷電、儲存空間
耗盡、client 上游尚未交給 rsyslog 的訊息或後續 Loki 的持久化。
參考 [rsyslog 的可靠日誌說明](https://docs.rsyslog.com/doc/whitepapers/reliable_logging.html)。

mTLS 驗證傳輸 peer；現有 `%HOSTNAME%` 分檔仍取自訊息 payload，沒有把每筆 payload 的
hostname 與憑證名稱做密碼學綁定。允許的 peer 可以提供自己的 payload hostname，不能把
目錄名稱當成已驗證的主機身分。
