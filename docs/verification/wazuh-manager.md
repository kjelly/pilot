# Verification Spec — wazuh-manager（Wazuh 中央伺服器：FIM/who-data 告警引擎 + CVE 弱點掃描 + 選填轉送 SIEM，Docker 部署）

> 版本：v2.1（Issue #211、Issue #244 A 與 B）
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
| 角色 | Wazuh **single-node**（manager + indexer + dashboard，同一台主機、三個 Docker 容器）：接收 agent 送來的 FIM(syscheck)/who-data 事件、跑規則引擎產生告警、跑 CVE 弱點掃描（vulnerability-detection），選填把告警轉送至中央 SIEM(`log-server`) |
| 套用範圍 | `/opt/pilot/wazuh-docker/`（官方 wazuh-docker 發行包 + 憑證 + `wazuh_manager.conf`）、官方 single-node compose 專案（`single-node-wazuh.manager-1`/`single-node-wazuh.indexer-1`/`single-node-wazuh.dashboard-1` 三容器與其 named volumes）、`vm.max_map_count` sysctl、`/etc/hosts`（`siem-log-server` 別名） |
| 前置依賴 | `docs/verification/docker.md` 8/8 PASS（`docker.io` + `docker.service` + compose v2 plugin，由 `playbooks/apply/docker-apply.yml` 佈署，2026-07-17 起獨立 playbook） |
| 風險等級 | High（對外開 1514/1515 收 agent 連線、443 供 dashboard；告警規則/轉送設定錯誤會導致資安事件漏判或漏送） |
| **資源需求（v1.0 實測踩過的雷，見 §5）** | 官方建議 1–25 agents：**4 vCPU / 8 GiB RAM / 50 GB 磁碟**。CVE feed 解壓後常駐磁碟用量 ~7–9 GB（Docker 部署下位於 `wazuh_queue` named volume 內，磁碟壓力不變）；磁碟不足會讓 `wazuh-db`/`wazuh-analysisd` 寫入失敗，**所有告警（含 FIM）都會靜默停止產生**，且不會有明顯的服務關閉徵兆（容器仍顯示 running）。本 spec 的 vm-target SOP（§7）用 60GB 磁碟、8192MB 記憶體、4 vCPU，不要沿用 `log-server`/`audit-log-forwarding`（20GB/2048MB/2vCPU）的規格 |

> 為何選 Wazuh manager 而非只用 auditd+rsyslog（`audit-log-forwarding.md`）：
> 那份 spec 只做「轉送原始 audit/auth 日誌」，沒有規則引擎、沒有 FIM 專屬的
> who-data 關聯分析、也沒有 CVE 弱點掃描能力。此 spec 是同一個 SIEM 收斂
> 鏈路上「多一層本地端分析」的角色，兩者可以並存於同一台主機（不互斥）。
>
> 為何改用 Docker（v2.0，取代 v1.0 的 `wazuh-install.sh -a` 原生安裝）：
> 本 repo 的網路服務型角色（`prometheus.md`/`thanos-query.md`/`dashboard.md`/
> `log-shipping.md`/`seaweedfs-s3.md`）已收斂到 Docker 部署——升級/回滾是換
> image tag、不污染主機套件、狀態集中在可列舉的 named volumes。Wazuh 官方
> 維護 `wazuh-docker` 發行包（manager/indexer/dashboard 三個官方 image +
> 驗證過的 compose 拓撲），是新增角色中唯一適合遷移的：純網路服務、不碰
> 主機核心（對照 `wazuh-fim.md`/`audit-log-forwarding.md` 的 agent/auditd
> 必須留在主機上）。
>
> 為何用官方 `wazuh-docker` single-node 發行包（compose + 官方憑證產生容器）
> 而非手刻三個 `docker_container` task：CVE 弱點掃描在 Wazuh 4.8+ 架構下
> **需要 Wazuh indexer**（OpenSearch 基礎）才能真正儲存/關聯掃描結果；
> indexer 的憑證鏈（root CA、indexer 憑證、filebeat 憑證、dashboard 憑證）
> 手動產生極度容易做錯且沒有回頭路——這正是 v1.0 選官方 `wazuh-install.sh`
> 而非手刻 apt 安裝的同一個理由，Docker 化不改變這個取捨。官方
> `generate-indexer-certs.yml`（`wazuh/wazuh-certs-generator` 容器）+
> `docker-compose.yml`（三服務、TLS 佈線、`/wazuh-config-mount` 設定注入機制）
> 是官方驗證過的整包流程；本 playbook 只疊加我們自己要的「選填轉送到
> log-server」設定，不重造官方已經做好的部分。

## 1.5 依賴變數契約

在套用或驗證此主機時，Playbook 與變數參數必須嚴格遵守以下命名，禁止擅自縮寫或發明新變數：

| 變數名稱 | 說明/用途 | 是否必填 | 預設值 |
|---------|----------|---------|--------|
| `siem_forward_host` | 中央 SIEM（`log-server`）的 IP 或 FQDN；host rsyslog 使用 `/etc/hosts` 的 `siem-log-server` 別名；inventory 有 log-server 時自動選用第一台 | 否 | 空字串（不轉送） |
| `siem_forward_port` | rsyslog TCP 轉送目的埠；必須與 receiver TCP 埠一致 | 否 | `514` |
| `siem_forward_transport` | `tcp` 或 `relp`；RELP 強制 mTLS，沿用 audit-log-forwarding 的輸入契約 | 否 | `tcp` |
| `siem_relp_port` | RELP receiver 目的埠 | 否 | `20514` |
| `siem_relp_server_name` | 明確 TLS server DNS identity | RELP 必填 | 無 |
| `siem_relp_ca_pem` | CA PEM private deployment input | RELP 必填 | 無 |
| `siem_relp_cert_pem` | Client certificate PEM private deployment input | RELP 必填 | 無 |
| `siem_relp_key_pem` | Client private-key PEM from vault | RELP 必填 | 無 |
| `wazuh_docker_version` | 官方 `wazuh-docker` 發行包版本（GitHub tag `v<版本>`，同時決定三個官方 image 的 tag） | 否 | `4.14.1`（本 spec 實測版本；見 §7） |
| `wazuh_version` | 選填的共同 release（與 wazuh-fim agent 共用）；與明示且不同的 `wazuh_docker_version` 衝突時拒絕。新安裝固定該版本；對既有 stack 變更版本需單次 `wazuh_upgrade=true`（只支援 4.14.1 → 4.14.9），否則 typed 拒絕且不改動任何東西 | 否 | 未設定（沿用 `wazuh_docker_version`） |

`siem_forward_host` 與 `siem_forward_port` 沿用 audit-log-forwarding 的契約。
manager 本地告警與 CVE 功能可獨立運作；未指定目的地且 inventory 無 log-server
時停用管理的 imfile reader。啟用轉送目前支援 Ubuntu；SELinux 主機須停在
fail-closed gate，不會重新標記 Docker volume 或放寬系統 policy。

轉送路徑是 **Docker-inspected logs mount Source → host rsyslog imfile → TCP /
RELP mTLS → log-server `<siem_log_root>/<manager hostname>/wazuh-alerts.log`**。
reader 用獨立 local5/tag/ruleset、state files 與 256MiB disk-assisted queue，
不進 audit/auth 預設 forwarding ruleset。首次 reader 安裝會讀目前 alerts.json；
不清除既有 state/queue。Wazuh 在日期目錄建立新 inode 再 hardlink 成 current；reader 對現有實體
year/month 目錄依序補 default ACL，未來子目錄繼承，避免只保護 alerts 根目錄而漏掉
既有 month。只補目前 JSON 的 access ACL，不遞迴改歷史檔案。TCP 沒有接收端
落盤確認且 reconnect 可能重複最後一筆；需要 authenticated acknowledged transport
時選 RELP。log-server 的同一份 retention policy 涵蓋獨立 wazuh-alerts.log。

啟用 RELP 時，固定五秒的 native immark 只進同一個 `pilotWazuhForward` /
`wazuh_alerts` action、client、queue；不產生第二個 Wazuh engine alert，也不建立額外
transport。這是稀疏輸出在 receiver 重啟後仍自主處理回應、重連與重送的必要條件。
保留字 `PILOT-WAZUH-TRANSPORT-HEARTBEAT-v1` 的 syslog/rsyslogd 整筆 marker
在 receiver 寫檔前丟棄；JSON `full_log` 內包含相同字串仍須照常保存。TCP 與停用
轉送不啟用這個 input。每分鐘 12 筆 marker 共用既有 queue 上限；不承諾任意長時間
停機或 queue 已滿時仍有相同延遲。不得刪除 backlog 來恢復進度。

immark 是 singleton；角色在 Wazuh/TLS mutation 前拒絕 foreign、重複、loaded-only
或無法判定 ownership 的 module/include 設定，並以 native parser 驗證精確能力。
只能重用本角色的固定設定，不能接管 operator 的 immark。C11 同時要求已載入的
RELP heartbeat module/thread；active 或磁碟設定正確本身不代表 runtime 已更新。
失敗時還原本次 snapshot，native validation 後重新載入原設定；不刪 queue/state。

遷移或停用時會移除本 playbook 過去管理的 `<syslog_output>`，並 recreate manager
讓 live config 同步；不改 operator 自行建立的其他輸出。C11 只證明本機有效 reader /
transport 設定，**不證明 delivery**。啟用轉送必須同時通過
[wazuh-alert-delivery.md](wazuh-alert-delivery.md) 的 fresh nonce cross-host row。
該 fixture 使用 controller 原本的 inventory 連線，不建立 receiver→manager SSH trust。
目前 actual-run 結果見 [evidence](../evidence/wazuh-manager/LATEST.md)。

## 2. Checklist

### 版本與受控升級驗收契約（Issue #244）

manager、indexer、dashboard 的 Wazuh release 必須完全一致（包含 patch）。
manager 讀取 control info、dashboard 讀取 Wazuh plugin package.json、indexer
讀取原生 `/usr/share/wazuh-indexer/VERSION.json`；同時檢查官方 image 的不可變
identity 與發行 provenance，不能拿底層 OpenSearch 版本代替 Wazuh release。
running 或可變 image tag 不足以證明版本與資料健康。
既有 `wazuh_docker_version` 預設 4.14.1 不變；共同目標 `wazuh_version` 選填，
同時指定兩者必須一致。升級另需單次 `wazuh_upgrade=true` 授權；
本次唯一支援的中央轉換為 4.14.1 → 4.14.9，其餘轉換與降級在停機前拒絕。

交易獨占 inspect、quiesce、backup、switch、verify、rollback 全程。
停機前先檢查舊版本、目標 images、資料與備份容量。停止三個元件後，
冷備份全部實際 project persistent volumes、bind mount 設定、憑證、Compose
設定及原 image identities；驗證備份後才同時切換。保留操作者設定、
credentials、憑證及 enrollment identity。成功需驗證有效版本、可用性及既有資料。
失敗時停止新版，恢復原資料與設定，以原 image identities 啟動，並驗證
舊版可用性及代表性資料。只改回舊 tag 不算恢復，恢復失敗必須明確回報。
未完成的持久交易阻止一般套用，只能進入明確的同交易 recovery 流程。
root-only 備份保留於 `/var/backups/pilot/wazuh`，不自動清除。
已知限制：每次中央升級嘗試（含失敗後回復）在 `/var/backups/pilot/wazuh/central-<owner>` 留下一份
完整冷備份，每次嘗試約 9–11 GiB（4.14.1 → 4.14.9 single-node 測試資料集上的觀察值：備份根目錄增加 8.9–10.6 GiB；
隨資料量成長），重複嘗試會累積並
最終使停機前的備份容量檢查拒絕下一次升級。只有 `writer-inspect` 顯示沒有 journal 與 writer 時，才可以
**以 owner 目錄為單位**手動刪除已結束嘗試的 `central-<owner>`；不得刪除 `*.lock`、`image-provenance.json`
或仍被 journal 引用的目錄。納入 restic（見 `group_vars/restic-backup.example.yml`，該範例已建議納入
`/var/backups/pilot/wazuh`）時，這些冷備份會讓備份體積成倍增加，應先清理或另行評估。
中央 project 與所有選取的 volume data source 必須是真實目錄且祖先沒有 symlink；
來源本身或子樹有 mount（包含同裝置 bind mount）時，在授予 reserve／停機權限前
拒絕。此交易不支援刪除、重建 mount root。backup store 可位於一般獨立 filesystem，
但不得有 subtree/bind ancestry、子 mount、或與來源互為實體 alias。discovery、
停機前與回復前共用相同 layout 檢查；留存 archives 限於原 transaction 的 private directory。
整個 project 與每個 persistent source 的所有 lstat entry 都須形成封閉 capture set：
內部 symlink 完整解析後仍在此集合，regular-file inode 的所有 hardlink 名稱都已
捕捉。同 volume 的完整 hardlink group 可以保留；未知外部名稱、外部資料 symlink
或未支援的 special file 在授予停機權限前拒絕。冷資料另封存內容 hash、ownership、
mode、ACL/xattrs 與 link groups，恢復後須先驗證完整集合再啟動與提交。
這是停止整個 single-node stack 的操作；期間中央停止接收與查詢事件。
交易驗收必須有 candidate-bound target evidence；原 C1–C11 不代表交易已驗證。

一般設定、新安裝、升級、回復與明示的 canary 都必須先取得同一個 host-wide
writer owner，包含共享 coordinator copy 與 `/etc/hosts`；同主機 agent 也使用
此 owner 協調，不能只各鎖自己的 upgrade helper。所有 native planning 必須
在 claim 後重讀。穩定的 manager readers 使用共享鎖，可同時服務多個 agent，
中央 writer 或未完成中央 journal 則拒絕外部讀取。

controller 中斷後 marker 不自動失效。writer-inspect 動作提供 owner/phase；
操作者須確認前次 controller 及所有遠端工作都已停止，再以單次
`wazuh_writer_resume_owner` 指定相同 owner，並明示
`wazuh_confirm_previous_operation_stopped=true`。有中央 journal 時再選擇
`wazuh_recover=true`，journal owner 必須相同。沒有 TTL、PID 猜測或自動接管；
任何未完成 journal 都阻止一般 release。正常的 early exit 必須先完成 durable
writer release，不能用 end_host 跳過 cleanup。此協調只涵蓋本版 Wazuh
entrypoints，其他角色、舊版 controller 或外部 root 修改仍須獨占維護時段。

版本升級 run 保留現有設定，只完成版本交易；欲改 forwarding 等設定，必須另跑
一般 apply。升級完成後以相同參數重跑，第一次重跑即須 changed=0：官方 Docker bundle 只在
作用中的 project 目錄缺少 compose 檔時才下載，不因請求的版本字串與保留的 project 目錄不同而下載。
C12 是不注入事件的目前狀態原生 oracle，不把「曾產生 backup 檔」
當作回復已成功的證明。首次開發 probe 已在 4.14.1 disposable manager 真跑；正式
candidate 驗收須涵蓋 fresh、upgrade、故障回復與 idempotency。canary 以唯一
synthetic nonce 從原生 analysis socket 注入，必須以 agent `000`、精確 rule
`5760`（上游 `5716` 的 Failed password 子規則）進入 indexer；不發出真實登入。
canary 只在明確授權的版本交易與 opt-in fixture 執行，普通 C12 不注入事件。
canary 涵蓋 analysis → Filebeat → indexer，agent transport 另由 topology 實測。

#### Host reader、current queue 與回復後 replay

啟用 host forwarding 的中央版本交易，另需單次明示
`wazuh_ack_rsyslog_downtime_and_replay=true`；此 boolean 預設為 false。
它確認 shared rsyslog／socket 停機及 restored current file 的 replay／duplicates，
並確認操作者已排除同機 audit-log-forwarding、log-server、其他 rsyslog mutator、
套件／policy 維護及外部 service/socket 操作，涵蓋整個交易、中斷及 recovery 時段。
這是合作式獨占維護假設；Wazuh writer 只序列化參與本協定的 Wazuh entrypoints，
沒有跨角色 global lock。boundary fingerprints 可偵測漂移，不能取代此假設。
ack 不取代 upgrade、exact owner 或 stopped-operation confirmation；同 owner
journal recovery 沿用原授權。no-op／check 不停 reader，也不要求未使用的 pause 授權。

preview 可建立已授權 writer／lock 與 Ansible 執行 metadata，及單次 invocation 的 root-private
/run 工具暫存；不得建立部署目錄、覆寫 installed coordinator／helpers，或改 configuration、
packages／pins、service 與 reader data。configured preview 仍以 desired code 做真實唯讀
觀察：三個工具須綁定 owner／operation、scope identity、完整 member set 與 desired hashes，
連 local C11 的 nested child tools 也使用同一驗證 closure。此 capability 僅供 central preview
及 ordinary enable-admit preview，不授予 apply、recovery、exposure 或 durable receipt 權限。
retained receipt 的原 fingerprints 不可改成 desired hashes；不相容必須明確拒絕。
暫存須在 outer always、writer release 前，驗明仍屬本 invocation 且 children 已結束後清理；
foreign replacement 或不確定狀態保留證據並回報，不刪除未知內容，亦不掩蓋原失敗。
「children 已結束」指沒有 tool child 仍在執行：coordinator 只經 `subprocess.run` 啟動 child，
它在成功、失敗與逾時時都會回收直接 child，所以 preview 自己的 in-process 拒絕（例如版本 gate）
或已回收的失敗 child 都不是 in-flight，仍須發出清理憑證並釋放 writer、不留 scope／marker。
只有名稱或持有暫存 scope 的存活 descendant（cleanup 的 `/proc` census 判定）、缺少／非 true／
foreign 的回應與 foreign replacement 才保留 scope 與 writer，並以 typed reason 揭露原因。
coordinator 與 cleanup 的 task 因 `no_log` 隱藏失敗原因；只揭露 typed、有界（可列印 ASCII、
不含引號、反斜線與大括號，至多 300 字元）且無秘密的 `error_kind`（refused／native）與固定訊息，
不輸出 tool stdout／stderr／argv。每個 `Refused()` 訊息必須是固定字面值，唯一例外是 Runner 的
`operation … rc=N` 與 delivery 固定 ValueError 的轉述，由測試逐一列出並鎖住。

停機前以唯讀 admission 資格化同 effective version 的目前 owned forwarding baseline：
profile、transport／TLS、input／ruleset／action、exclusive cursor namespace、queue 與
loaded runtime 一致，啟用時本機 C11 健康；不要求舊版 ordinary apply 或整體 C12 曾成功。
原 manager 4.14.1／registered agents 4.14.9 的 repair 仍以目標 4.14.9 對所有 retained
agents 作版本上界檢查，未知版本仍拒絕。須資格化實際選定的 native engine 與 queue file family，
包含選用的 diskQueueType=disk 或 LinkedList，不能從其中一種的實驗推論另一種，
也不能悄改 transport／engine。版本交易不兼做 legacy UDP 遷移或目的地／TLS／profile
變更；已知不支援的 layout、activation、ownership、engine 或混合轉換在停機前拒絕。
符合 baseline、owner 與 ack 的 configured upgrade 須有 reader lifecycle 支援。
真正 version-only selection 保留目前實際設定：從未有 host reader、僅 legacy container UDP
者可先完成版本 repair，不在交易內遷移 host forwarding；既有健康 reader 則保留其目前
profile。欲改目的地／TLS／profile 的 mixed request 必須拒絕，先以 current profile 作版本
交易，再另以新版 ordinary apply 收斂，不能靜默忽略或混入設定變更。

原先已有 manager／agent skew 的故障回復可恢復精確舊資料、images、設定與 native availability，
但不能宣稱 fleet 健康。相同已觀察到的原始 skew 須持久標記
`restored_preexisting_incompatible_baseline`、`overall_success=false`、`c12_pass=false`；
所有實體恢復與 reader custody 證明完成後可 finalize／release exact owner，不因已知舊 skew
永久留鎖。真正 restore／reader／identity 失敗或未知 registry 仍留存 journal。明示 recovery
須回報 degraded 非零結果，完成後另以新 owner 明示重試 upgrade；recover 不自動升級中央
或降級 agents。C12 永遠驗目前實際版本相容性，不因回復完成而變成 PASS。

- **從未設定**：須證明 Wazuh-owned profile/input、相關 FD/activation、cursor、queue 均不存在，
  才可走無 reader pause/replay 的 standalone 路徑；不能把未知狀態當作未設定。
- **已停用且收斂**：證明 owned input／heartbeat／FD 已卸載，保留 queue/cursor 且不自動
  啟用。成功 switch、未 cold restore 時原樣保留，不另停 shared service 或建立 replay receipt。
  cold restore 可能失效的 retained cursor 須在交易停機前取得 ack，並在無 owned 存取的
  offline 狀態 archive／retire／發布空 generation。cursor 與 queue 皆不存在時記錄確切 absence；
  cursor 缺少但 queue 非空仍須保留 queue，不人工 drain。另一輪 cold restore 記錄另一個 generation。
- **已啟用**：完整執行下列 pause/resume/recovery 與 receiver 驗收，不以停用替代。

上文「loaded runtime 一致」的釐清（不是新增條件）：它依 mode 判斷，且 admission、每個 boundary（pause／resume／
final／retire／recovery／rollback）與明示 recovery 使用同一個判斷，不得在 admission 通過後於後續 boundary
改用較嚴的條件：

- 從未設定與已停用：以 live rsyslogd 為權威。process 沒有映射 `imfile.so`，即證明 owned input
  從未被這個 process 載入（`31-pilot-wazuh.conf` 一律載入 imfile），此時 profile／include 的 mtime 晚於
  rsyslog 啟動時間不構成拒絕：在沒有先前 Wazuh reader 設定的主機上，保持 forwarding 關閉的一般 apply 不重啟 rsyslog（啟用轉為停用的轉換則會重啟）。imfile 已映射
  （例如操作者自己的 imfile input）時，仍須證明 include／profile 已載入，並以 FD 排除證明 owned input
  已卸載。
- retained engine 資格化（精確的 `rsyslogd`、套件與 `imfile.so` 的 on-disk identity，它們決定日後
  重播保留的 cursor／queue 的軟體）在資格化執行的地方一律比對 on-disk identity：已啟用的 reader 一律執行；
  已停用的 reader 只在有保留的 cursor 或 queue 時執行；從未設定不執行資格化。live process 映射的
  `imfile.so` 與 on-disk identity 一致，只對已啟用且正在執行的 reader 另行要求。停用 reader 的 live process
  沒有映射 imfile 是正常狀態，不是 identity 漂移。

停用狀態 cold restore 後仍有 retained cursor/queue 者，須在中央 finalize 前持久保存 root-owned
replay-pending receipt，綁定 source/profile、current cursor generation 與 queued-resource
identities；它不授予自動啟用權限。之後 ordinary apply 真正要求 re-enable 時，是新的操作：
須再次明示同一 boolean，並在任何 config／restart mutation 前驗 receipt 與目前 layout。
此 receipt 只記錄本機 replay ACK／cursor generation／queue custody，不是遠端 delivery
certificate。新 ACK 且本次 selected local mutation 已提交、原生 enabled convergence／C11
成功後，持久保留 acknowledged history，再解除 pending admission；不刪 queue，receiver
outage 本身不阻止本機 ACK 完成。selected mutation/rescue 尚未完成時不得清除 pending；
失敗保留 receipt 與本次 recovery authority，不靜默覆寫未知 receipt。其後獨立 C12 或遠端
challenge 失敗仍如實回報，不重設已 exposed generation。candidate 的 target-only queued nonce
及 fresh event 實際 receiver 驗收仍是必要且獨立的證據，不能以此 local receipt 代替。

需要 shared pause 的 unit 支援範圍限 Ubuntu 24.04 的實際 canonical `rsyslog.service` 與
`syslog.socket` 關係：default-config ExecStart、無額外 drop-in／activation，
service enabled/active，socket STATIC/active，Datagram `/run/systemd/journal/syslog`、
RemoveOnStop=no；每次 admission 重讀 unit fragments、依賴／aliases、engine、
有效 include graph、loaded MAC/profile 與 prior states。未知 override 或 graph 停機前拒絕。
先凍結 producer，再持久記錄 pause intent，以同一組 owned systemd jobs 請求停止 socket
與 service；Requires 關係可能連帶停止 service，不能假設兩次 stop 中間它仍運作。
不 enable/disable STATIC socket、不改 unit policy；依原 active 狀態與 native dependency
順序恢復，並驗原 enablement 未變。RemoveOnStop=no 可留下 socket pathname：
驗收須有 jobs 完成、原 invocation/process/cgroup 與 reader/queue FDs 消失、kernel socket
不再被持有／接收／觸發 activation；pathname 消失既非必要亦非充分條件。

source admission、外部 FD exclusion、pause、rollback 與 post-start watch 共用實際 Docker
volume、封閉 inode/hardlink 集合及 mount projection。proc FD 的 `(deleted)` 是舊 dentry
標籤，不等於資料 inode 已消失；仍由全部內部 alias 覆蓋的同一 inode 可接受。下列情形必須
拒絕：外部 alias／mount、未知 reader/writer、PID 或 FD-slot reuse；位於 `alerts/` 之下
（最後 dentry 標籤或任一封閉 alias 在 alerts）的 nlink=0 orphan 或未知 inode——這是 reader
custody，不論由誰持有（含所選 stack 的 container）；以及 reader（rsyslog）、主機 process、
非所選 stack container 持有的**任何** nlink=0 orphan 或未知 inode。唯一不拒絕的是所選 stack
自己的 producer container（cgroup 與 Docker inspect 的 container id 精確相符、且不是 reader）
持有、位於同一 volume 但 `alerts/` 之外的 nlink=0 orphan 或 layout 之後新建的 inode：例如
Wazuh 每日 00:00 UTC 輪替後 Wazuh API process 仍持有 `logs/api.log.<date> (deleted)`
（nlink=0）。它們不是 rsyslog imfile 輸入集合，不承載 reader 要接手的 alert 資料；若一併
拒絕，每次輪替後 admission 都會被 container 內部自己的行為擋下，且操作者只能重啟 Wazuh
container 才能放掉 FD。這只忽略該 FD，不授權它：非 orphan 的 container FD 仍要完整通過封閉
group／mount／flags 檢查，其餘路徑（含 reader 自己的 FD）不變。不能用去掉 suffix、特定 FD
編號或 512 offset 豁免。watch 證明不是 drain 證明。

資格化精確 native build 與完整 canonical single-line input/module attrs；額外 multiline、
regex、trim、rate、delay 等 record-processing 選項不得繼承此證明。先停止三個 producer
並排除外部存取，凍結 current 與所有相關 retained inode groups 的 identity、封閉 aliases、
長度、時間及完整紀錄邊界。cursor basename 須以 inode 與精確 native
SipHash-2-4(first512,key00..0f,little-endian hex) 綁定集合；小於 512 bytes 沒有 hash suffix，
filename JSON 欄僅為資訊，不能以路徑 stat 選取 rotated inode。空檔／缺 state 或未資格化
rotation 必須在可辨識的 admission 階段拒絕；不能把缺 state 當作讀完。

pre-stop barrier 須有界讀取 coherent native cursor，嚴格驗 schema、唯一 keys、整數型別、
source/fingerprint、namespace 與全部相關 groups；每組邏輯 curr_offs、strt_offs 均達凍結 EOF，
且沒有 pending line/message segment。prev_was_nl=0 可是正常結果。native writer 是
O_TRUNC 原地更新，live 空白／部分 JSON 或變動可有界重讀，不能假設 atomic rename。
任何／全部 kernel FD 到 EOF 都不能替代此邏輯 barrier；它亦不代表資料已 durable enqueue。

持久記錄原 invocation 的 stop intent，再驗真正 StopProof：Result、ExecMainCode／Status、
確切 exit、cgroup／FD／job 與 activation socket 均符合；timeout、forced kill 或 survivor 不算
save。停止後必須重驗同一凍結 source 及最終 native cursor，再 fsync/seal 完整 CURRENT
cursor 與 queue，持久發布綁定 owner/cycle/data epoch、build/profile、StopProof、source、
cursor 與 queue checkpoint 的 handoff certificate，之後才可 queue-sealed／成功返回 pause。
舊 drain boolean、pre-stop sample 或 stopped-but-uncertified 狀態均不授予 capture、restore、
remove 或 cursor retire/reset；資料回復開始前另持久記錄由該 certificate 派生的 restore intent。
部分回復 retry 依此 intent／CURRENT custody 完成，不能把舊 cursor 重新綁到已換掉的 source。

失敗後僅在安全時取消：相同 owner、原 static unit／真實 StopProof、未變 source/data epoch、
結構有效且 source-bound native cursor，以及冷 fsync 的 CURRENT cursor/queue，可形成
獨立 SAME_EPOCH_RESUME_ONLY custody，僅重新啟動原 reader/input；offset 可落後 EOF，
但不能 restore、retire/reset/reconcile generation 或冒充 handoff。malformed／foreign cursor
仍保留停止狀態與 owner。recovering 中、任何 restore intent 之前，同 owner 可作一次有界
重新 drain；不因缺完整 certificate 盲目遞迴 pause，也不以晚期失敗授予冷回復權限。

冷備份／回復仍驗既有 15-root 與全部實際 persistent sources、原 images、內容、
ownership、ACL/xattrs 及 link closure；ordinary ACL journal 不跨新舊 inode 重播。
rollback 先再次凍結 producer、graceful-stop reader，seal 此時 **CURRENT durable queue**：
fsync/hash 並在 Docker 舊資料 restore 前後維持相同 bytes/identities，直到 reader restart。
不以初始 checkpoint 覆蓋、不刪除／人工 drain／改名 queue。停機前須預留容量，
保留 CURRENT queue 的 private sealed evidence-only copy 供外部 nonce/hash oracle 使用；
此 copy 永遠不是 restore authority，不得 replay 到 live queue。payload 留在目標 root-only
private store，僅輸出 typed nonce/hash booleans；不公開 queue、設定或 key 的原文。

正常成功升級保留 native cursor。cold restore 後，對 quiescent/exclusive 的 owned cursor
先 archive/checksum/fsync，再以同 filesystem 原子 rename 保留舊 generation、發布空新 generation。
每個 reader boundary 在 effect 前持久記錄 typed intent，effect 後 fsync proof，包含
old/prepared/retired/new identities、queue custody、unit/invocation 與 producer 狀態。
在請求任何會 activation reader 的 socket/service start **之前**標記 generation 可能已 exposed；
retry 不 reset 可能已讀取的
generation，不在 activation 後還原 retired cursor。若 exposed 後必須再次 restore data，
須重新 quiesce、seal 當時 CURRENT queue，另建 recorded generation，不重用初始 queue proof。
恢復有效 config／transport／heartbeat、ACL/current-file watchability 的 reader，再啟動 producer；
驗 rotation、原 unit/socket states、適用的 C11/C12 與 boundary fingerprints。
未知 identities、alias/mount、namespace drift 或保存失敗保留 custody，不猜測或接管 foreign state。
版本／資料／identity 與 reader 最終 proof、必要的 replay receipt 全部 durable 後，才 finalize、
移除 journal 並 exact-owner release；完成／unlink 中斷可冪等銜接，不刪未知 owner。

回復允許 restored current file 至少一次重讀及 duplicates，沒有 exactly-once 或整體排序承諾。
保存範圍是最後成功 graceful checkpoint 中 **仍在 CURRENT durable queue 的完整紀錄**，
加上可重讀的 restored current file；不承諾 unread/not-yet-queued、partial/uncommitted、
noncurrent 歷史、shared-input 停機期間未保留的流量，或 TCP 已出 queue 但 receiver 尚未
確認落盤的 network window。queue cap、突發主機損失與 receiver 故障仍適用原 transport 邊界。

candidate-bound 故障驗收須在 backup 完成且 target runtime 真正運作後，以獨立 fixture
產生 target-only real-engine nonce；它不在舊 source/archive，卻在 rollback 的 CURRENT
sealed queue evidence，且 hashes 對應 restore 前後的 live queue。receiver 在 checkpoint／
restore 時不可接收；恢復 transport 後，target nonce 必須先抵達實際 receiver，再產生並驗證
另一個 fresh old-runtime nonce，同驗 C11/C12、舊資料／設定／identity、安全 metadata 與 replay counts。
每次 delivery challenge 獨立且不可重用；資格化所選 TCP/RELP 與 native engine，不悄改選擇。
本機 C11、isolated engine prototype、停用／從未設定情境都不替代 enabled recovery delivery。
不新增在任意 operator monitored directory 寫測試資料的 runtime hook；既有 retained-agent
版本 bound、native package protection、agent audit/enrollment、host owner 與 sealed cold recovery
保證均不得減弱。整條不可變 candidate/native chain 與相關故障驗收完成前，不宣稱本契約通過。

### 版本契約細節（Issue #244，A 部分；與上節的受控升級並存）

manager、indexer、dashboard 的 Wazuh release 必須完全一致（包含 patch）。manager 讀取
`wazuh-control info`，dashboard 讀取 Wazuh plugin `package.json`，indexer 讀取原生
`/usr/share/wazuh-indexer/VERSION.json`；同時檢查 image 的不可變官方 repository digest，不能以
可變 tag 或底層 OpenSearch 版本代替 Wazuh release。running 本身不證明版本與資料健康。

- 既有 `wazuh_docker_version` 預設 `4.14.1` 不變；共同目標 `wazuh_version` 選填，兩者同時
  指定必須一致，且只接受 exact stable `4.14.x`。
- 新安裝（沒有任何 `single-node` Compose project）固定所要求的 release。
- 既有 stack 在任何 Compose／bundle 變更之前先被原生觀察：release 必須與要求完全相同，
  否則 typed 拒絕（升級須帶單次 `wazuh_upgrade=true`，見上節；降級一律拒絕）；缺件、停止、版本混合、
  無官方 digest、native daemon 或 indexer 不健康的 stack 也 fail closed，不被當成「不存在」。
  已註冊 agent 的版本若高於 manager（欄位 fleet 的 skew）同樣拒絕，直到 manager 以其他方式
  升到不低於所有 agent 的版本。這個 gate 唯讀，且被拒絕時 Compose 設定、image 與資料都不變。
- 已註冊但**從未連線**的 agent（原生 `agent_control -i` rc 0，`Client version: (null)`）、或回報 pre-4.14
  版本的 agent，沒有可比較的 4.14.x 版本，因此同樣讓 manager 的套用閘門與 C12 fail closed，typed 原因帶出
  該 agent 的數字 ID（只有 ID，不含名稱或 IP）：`unknown retained agent version in manager registry
  (agent ID <ID>)`。這是被接受的 skew fail-closed 行為（使用者決定 A4），不是 bug；要解除，在 manager
  容器內以 `manage_agents -r <ID>` 移除該 agent（`docker exec single-node-wazuh.manager-1
  /var/ossec/bin/manage_agents -r <ID>`）。已連線但較舊、或已斷線（Disconnected）但仍回報版本的 agent
  不受影響。
- dashboard 與 indexer 的 release 各自獨立讀取：dashboard 讀 Wazuh plugin 的 `package.json`（不是
  OpenSearch Dashboards 的根 `package.json`，其頂層 `version` 是 OpenSearch 版本），indexer 讀
  `VERSION.json`；任何一個與 manager 不同都 fail closed。
- 因為 manager 的有效版本是 agent 的相容性上限，wazuh-fim 在動 agent 之前會讀取同一個 native
  值（見 `wazuh-fim.md`）。
- C12 是不注入事件的目前狀態原生 oracle：三個 release 相同、所有已註冊 agent 版本不超過
  manager、native daemon 與 indexer API 健康。它在 apply 的設定區塊之外執行，驗證失敗不會觸發
  設定 rollback。Compose 設定或 image 的版本變更、備份與回復見上節的受控交易。

| ID  | Category  | Check                                                              | Expected | Command |
|-----|-----------|------------------------------------------------------------------------|----------|---------|
| C1  | container | manager 容器（`single-node-wazuh.manager-1`）為 running                | 0        | sh -c 'docker ps --filter name=wazuh.manager --filter status=running -q | grep -q . && echo 0 || echo 1' |
| C2  | container | indexer 容器（`single-node-wazuh.indexer-1`，CVE 掃描結果的儲存/關聯引擎）為 running | 0 | sh -c 'docker ps --filter name=wazuh.indexer --filter status=running -q | grep -q . && echo 0 || echo 1' |
| C3  | container | dashboard 容器（`single-node-wazuh.dashboard-1`，443 Web UI）為 running | 0        | sh -c 'docker ps --filter name=wazuh.dashboard --filter status=running -q | grep -q . && echo 0 || echo 1' |
| C4  | functional| indexer HTTPS API 已就緒（未帶憑證回 401，證明 OpenSearch + security plugin 已完成啟動，不只是容器活著） | 0 | sh -c '[ "$(curl -sk -o /dev/null -w "%{http_code}" https://127.0.0.1:9200)" = "401" ] && echo 0 || echo 1' |
| C5  | network   | agent 連線埠 1514/tcp 確實在監聽（`wazuh-remoted`，compose port mapping） | 0        | sh -c 'ss -lnt | grep -q ":1514" && echo 0 || echo 1' |
| C6  | network   | 註冊埠 1515/tcp 確實在監聽（`wazuh-authd`，agent 自動註冊用）          | 0        | sh -c 'ss -lnt | grep -q ":1515" && echo 0 || echo 1' |
| C7  | config    | CVE 弱點掃描（`vulnerability-detection`）在容器內生效中的 `ossec.conf` 已啟用（證明 `/wazuh-config-mount` 注入確實發生） | 0 | sh -c 'docker exec single-node-wazuh.manager-1 grep -A1 "<vulnerability-detection>" /var/ossec/etc/ossec.conf | grep -q "<enabled>yes</enabled>" && echo 0 || echo 1' |
| C8  | disk      | 磁碟可用空間 ≥ 5GB（CVE feed 常駐用量的安全邊界，避免 §5 的靜默寫入失敗） | 0        | sh -c '[ "$(df --output=avail -B1G / | tail -1 | tr -d " ")" -ge 5 ] && echo 0 || echo 1' |
| C9  | functional| 規則引擎可比對出一筆已知規則並判定為需告警（`wazuh-logtest` 灌入一行完整的 sshd 失敗登入 syslog 訊息，不需要真實 agent） | 0 | sh -c 'printf "%s\n" "Jul  6 00:00:00 wazuh-fim sshd[12345]: Failed password for invalid user test from 10.0.0.9 port 12345 ssh2" | docker exec -i single-node-wazuh.manager-1 timeout 15 /var/ossec/bin/wazuh-logtest 2>&1 | grep -qF "Alert to be generated." && echo 0 || echo 1' |
| C10 | forward   | `/etc/hosts` 已 pin `siem-log-server` 別名                            | 0        | getent hosts siem-log-server >/dev/null 2>&1; echo $? |
| C11 | forward | Host rsyslog has loaded the dedicated imfile/transport pipeline and can read the current real alert file (local check only; delivery requires wazuh-alert-delivery.md) | 0 | sh -c '/usr/local/libexec/pilot-wazuh-delivery local && echo 0 || echo 1' |
| C12 | functional | 三個原生 Wazuh release 相同、沒有未完成交易、所有 retained agent 版本不超過 manager，且 native daemon / indexer API 健康 | 0 | sh -c '/usr/local/sbin/pilot-wazuh-transaction central-verify >/dev/null && echo 0 || echo 1' |

C1–C9 and C12 establish the local Wazuh stack and its native version/health contract. C10 establishes the host destination alias;
C11 establishes the loaded local ingestion and transport state. Their numeric
positive-logic verdict wrappers always return shell rc 0 and print 0/1.

## 3. Evidence

Actual-run revisions, targets, verdicts and failure-path coverage are recorded in
[current evidence](../evidence/wazuh-manager/LATEST.md). The immutable candidate
must run fresh check/apply/verify/idempotency and the real-alert cross-host challenge.

## 4. PASS / FAIL

When forwarding is configured, require C1–C12 **and** the receiver row in
[wazuh-alert-delivery.md](wazuh-alert-delivery.md). Blocking the selected transport
must fail the receiver row even when the manager's C11 still passes. C11 must
never be reported alone as proof of delivery. Each receiver verification consumes
its challenge and needs a newly emitted real alert on the next invocation.

Standalone deployments without a destination verify C1–C9 and C12; C10/C11 and the
delivery cross-check are inapplicable. A receiver in inventory enables forwarding
automatically unless that inventory omits the optional dependency.

## 5. Operational boundaries

- Official Wazuh single-node 4.14.1 images include default credentials. Production
  operators must rotate those under the official Wazuh procedure.
- Keep at least 50GB disk / 8GB RAM / 4 vCPU; a full Docker data filesystem can
  silently stop real alert generation despite running containers.
- The official host 514/UDP mapping is Wazuh's own input, unused by this outbound
  pipeline. log-server uses TCP/RELP, so colocation does not collide with it.
- Config injection uses `/wazuh-config-mount/etc/ossec.conf`; manager **recreation**
  is required because a plain restart can fail the official initialization path.
- Reader permissions are scoped to volume traversal, alerts directory listing,
  current JSON file read, and parent-first default ACLs on existing physical date
  directories and future descendants. Shared-mask conflicts fail closed; existing
  reader/other-principal effective rights are preserved. Docker parent
  directories never become world-readable. SELinux forwarding is fail-closed.
- Queued delivery is bounded by the queue's disk cap. Abrupt host loss and queue
  exhaustion are outside the graceful-restart guarantee; operator monitoring is
  still required. First installation can replay the current alert file.

## 6. Traceability

Docker bundle/cert generation/compose covers C1–C3; indexer readiness covers C4;
manager port waits cover C5/C6; C7/C8/C9 are derived or verify-only. Host destination
resolution and pin cover C10. `tasks/wazuh-alert-forward.yml`, legacy output
migration and live-config convergence cover C11. The cross-host fixture and
receiver helper independently verify real-engine delivery. C12 uses the root-only
read-only native coordinator; ordinary verification never injects a canary.

## 7. Target verification plan

Use `playbooks/test/wazuh-alert-delivery.yml` for the integrated fresh topology
chain. It imports Docker, log-server, manager and the controller diagnostic fixture.
Verify manager and log-server specs on their actual groups and the delivery spec
on the receiver. The fixture produces an ephemeral challenge/alert on each apply;
these diagnostic emissions are excluded from configuration change counts.
Do not reuse a challenge for negative or recovery trials.

The current procedure and evidence link are in [wazuh-manager](../runbooks/wazuh-manager.md).

Issue #244 版本契約的 target chain 用 `docs/topologies/wazuh-version-topology.yaml`（三台：manager 兼
agent、Ubuntu 24.04 agent 兼 log-server receiver、AlmaLinux 9 agent）與
`playbooks/test/fixtures/wazuh-version-topology.yml`（docker、receiver、manager、agents 依序）。receiver 在
inventory 內，manager 才會轉送（`siem_forward_host` 由 log-server group 推導），C10 與 C11 才適用；
沒有 receiver 時 forwarding 保持關閉，C10 與 C11 無法通過，而 `topology test --verify` 沒有 row 篩選，鏈路因此驗不到全 PASS。該 run 只驗
manager 與 wazuh-fim 的列；receiver 的 self-forwarding 與 real-alert delivery（上面的 fresh nonce 檢查）
不在其範圍。

## 變更紀錄

| 日期 | PR | 驗收語意變更 |
|------|----|-------------|
| 2026-11-03 | Issue #211 | Replace UDP syslog_output with host imfile over TCP/RELP; distinguish local C11 health from a fresh real-alert receiver delivery oracle. |
| 2026-11-05 | Issue #244 | Preview 不部署控制工具；單次 root-private desired-code closure 保持 installed assets／reader data 不變，retained provenance 不遷移。 |
| 2026-11-05 | Issue #244 | 封閉 inode FD 身分區分 deleted dentry 與 orphan；精確 native logical cursor barrier 加 StopProof 後 CURRENT handoff，取消時 resume-only custody 不授予冷回復。 |
| 2026-11-05 | Issue #244 | Source admission 只忽略所選 stack producer container 持有、`alerts/` 之外的 nlink=0／新建 inode（Wazuh 每日輪替留下的 `api.log.<date> (deleted)`）；reader、主機 process、非所選 container 持有的 orphan，以及任何 `alerts/` 內的 orphan／未知 inode 仍拒絕。原因：舊規則在每次 00:00 UTC 輪替後把 Wazuh 自己的 API process 當成未授權 source user 拒絕 admission；未放寬任何 custody 相關 Expected。 |
| 2026-11-05 | Issue #244 | Preview 清理語意：in-process 拒絕或已回收的失敗 child 不再造成「未 settled」（原本任何拒絕都讓 host-wide writer 與 `/run` scope 留住，連版本 gate 也是）；仍保留存活 scope descendant、未知／偽造回應與 foreign replacement。被 `no_log` 隱藏的 coordinator／cleanup 失敗改以 typed、無秘密的 `error_kind` 與固定訊息揭露。未放寬任何 Expected。 |
| 2026-11-04 | Issue #244 | 原生中央版本一致與 retained-agent 上界；明示版本交易保留完整冷資料/images，回復區分原始 skew；host reader 採 CURRENT queue custody、cursor generation 及本機 replay ACK，實際 receiver delivery 另驗。 |
| 2026-11-05 | Issue #244 (A) | 新增 `wazuh_version` 與 C12：manager、indexer、dashboard 的原生 release 一致且所有已註冊 agent 不高於 manager；既有 stack 的任何 release 變更與 agent 新於 manager 一律在變更前 typed 拒絕。升級、備份與回復不在本版範圍。未放寬任何既有 Expected。 |
| 2026-11-06 | Issue #244 (A) | 原生實跑後修正：從未連線或 pre-4.14 agent 的 fail closed 帶出 agent ID 並記載 `manage_agents -r` 解除方式；target chain 加入 log receiver 使 C10/C11 適用；dashboard/indexer 各自獨立讀取 release。未放寬任何 Expected。 |
| 2026-11-09 | Issue #244 (B) | 以已合併的 A（#271）為基底重新整合受控升級（B）：版本契約由 A 負責、B 只加 writer／transaction／reader／preview；未帶 `wazuh_upgrade=true` 的版本變更仍 typed 拒絕；版本標示加上 B。未放寬任何 Expected。 |
| 2026-11-10 | Issue #244 (B) | 原生實跑發現：從已停用且收斂的 reader 升級在 pause 之後被拒絕而無法回復（要求 live rsyslogd 映射 `imfile.so`，停用狀態本來就沒有），從未設定的全新 manager 在一般 apply 後無法升級（要求 include／profile 不晚於 rsyslog 啟動，而在沒有先前 reader 設定的主機上，保持 forwarding 關閉的一般 apply 不重啟 rsyslog）。釐清「loaded runtime 一致」依 mode 判斷（既有 reader mode 條文的說明，不是新增或收緊的條件）：停用與從未設定以 live rsyslogd 未映射 imfile 作為 owned input 未載入的證明；engine identity 在資格化執行的地方比對 on-disk identity（已啟用一律、已停用僅在有保留 cursor／queue 時、從未設定不執行），live imfile 映射只對已啟用且執行中的 reader 要求；admission、boundary 與 recovery 共用同一判斷。升級後以相同參數重跑時，官方 Docker bundle 只在作用中的 project 缺少 compose 檔時才下載，第一次重跑即 changed=0（先前第一次重跑會再下載一次不會被使用的 bundle 並回報 changed）。補記備份不自動清除的已知限制。未放寬任何 Expected。 |
