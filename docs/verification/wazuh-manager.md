# Verification Spec — wazuh-manager（Wazuh 中央伺服器：FIM/who-data 告警引擎 + CVE 弱點掃描 + 選填轉送 SIEM，Docker 部署）

> 版本：v2.1（Issue #211）
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

`siem_forward_host` 與 `siem_forward_port` 沿用 audit-log-forwarding 的契約。
manager 本地告警與 CVE 功能可獨立運作；未指定目的地且 inventory 無 log-server
時停用管理的 imfile reader。啟用轉送目前支援 Ubuntu；SELinux 主機須停在
fail-closed gate，不會重新標記 Docker volume 或放寬系統 policy。

轉送路徑是 **Docker-inspected logs mount Source → host rsyslog imfile → TCP /
RELP mTLS → log-server `<siem_log_root>/<manager hostname>/wazuh-alerts.log`**。
reader 用獨立 local5/tag/ruleset、state files 與 256MiB disk-assisted queue，
不進 audit/auth 預設 forwarding ruleset。首次 reader 安裝會讀目前 alerts.json；
不清除既有 state/queue。rotation 後由 default ACL 延續讀取權限。TCP 沒有接收端
落盤確認且 reconnect 可能重複最後一筆；需要 authenticated acknowledged transport
時選 RELP。log-server 的同一份 retention policy 涵蓋獨立 wazuh-alerts.log。

遷移或停用時會移除本 playbook 過去管理的 `<syslog_output>`，並 recreate manager
讓 live config 同步；不改 operator 自行建立的其他輸出。C11 只證明本機有效 reader /
transport 設定，**不證明 delivery**。啟用轉送必須同時通過
[wazuh-alert-delivery.md](wazuh-alert-delivery.md) 的 fresh nonce cross-host row。
該 fixture 使用 controller 原本的 inventory 連線，不建立 receiver→manager SSH trust。
目前 actual-run 結果仍待驗證，見 [evidence](../evidence/wazuh-manager/LATEST.md)。

## 2. Checklist

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

C1–C9 establish the local Wazuh stack. C10 establishes the host destination alias;
C11 establishes the loaded local ingestion and transport state. Their numeric
positive-logic verdict wrappers always return shell rc 0 and print 0/1.

## 3. Evidence

Development target chain passed 23 rows and second apply changed=0. Native
probes proved C11 remains locally healthy while blocked receiver delivery fails,
then fresh-nonce delivery recovers. These are development results; the final
immutable candidate evidence remains pending.
The immutable candidate must run fresh check/apply/verify/idempotency plus the
cross-host challenge. See [current evidence](../evidence/wazuh-manager/LATEST.md).

## 4. PASS / FAIL

When forwarding is configured, require C1–C11 **and** the receiver row in
[wazuh-alert-delivery.md](wazuh-alert-delivery.md). Blocking the selected transport
must fail the receiver row even when the manager's C11 still passes. C11 must
never be reported alone as proof of delivery. Each receiver verification consumes
its challenge and needs a newly emitted real alert on the next invocation.

Standalone deployments without a destination verify C1–C9; C10/C11 and the
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
  current JSON file read, and inherited read access on rotation. Docker parent
  directories never become world-readable. SELinux forwarding is fail-closed.
- Queued delivery is bounded by the queue's disk cap. Abrupt host loss and queue
  exhaustion are outside the graceful-restart guarantee; operator monitoring is
  still required. First installation can replay the current alert file.

## 6. Traceability

Docker bundle/cert generation/compose covers C1–C3; indexer readiness covers C4;
manager port waits cover C5/C6; C7/C8/C9 are derived or verify-only. Host destination
resolution and pin cover C10. `tasks/wazuh-alert-forward.yml`, legacy output
migration and live-config convergence cover C11. The cross-host fixture and
receiver helper independently verify real-engine delivery.

## 7. Target verification plan

Use `playbooks/test/wazuh-alert-delivery.yml` for the integrated fresh topology
chain. It imports Docker, log-server, manager and the controller diagnostic fixture.
Verify manager and log-server specs on their actual groups and the delivery spec
on the receiver. The fixture produces an ephemeral challenge/alert on each apply;
these diagnostic emissions are excluded from configuration change counts.
Do not reuse a challenge for negative or recovery trials.

The current procedure and evidence link are in [wazuh-manager](../runbooks/wazuh-manager.md).

## 變更紀錄

| 日期 | PR | 驗收語意變更 |
|------|----|-------------|
| 2026-11-03 | Issue #211 | Replace UDP syslog_output with host imfile over TCP/RELP; distinguish local C11 health from a fresh real-alert receiver delivery oracle. |
