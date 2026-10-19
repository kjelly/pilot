# Issue #11 評估報告 — 外部 SSH/PAM 登入探測與 I/O pressure 告警

> 對應 issue：<https://github.com/kjelly/pilot/issues/11>
> 「Add external SSH/PAM login probe and I/O pressure alerts」（2026-09-24 開立，無留言、無 label）
> 評估日期：2026-10-13
> 評估基準 revision：`db10268`（main）
> 文件性質：**修法評估與交付切法建議**，不是 spec。依 AGENTS.md §0.2 的 authoring
> model，正式交付要先落成 `docs/verification/<feature>.md`，再寫 playbook。本檔
> 列出的所有「待驗證」項目都必須在 Phase 0 以真實 vm-target 擷取確認，不准照本檔
> 的推測直接寫進 spec 或 classifier。

---

## 實作狀態（2026-10-13 更新）

依本報告的切法已完成 Phase 0–3 與 Phase 4 的拓樸演練；本報告下文保留評估當時的推測，
被真實擷取推翻或修正的地方如下（細節見 `docs/evidence/login-probe/2026-10-13-phase0-ssh-capture.md`）：

| 本報告原本的推測 | 實測結果 | 實作採用 |
|---|---|---|
| U5：`Server accepts key` 標記可區分 auth 與 account | 成立（Ubuntu OpenSSH 9.6p1、AlmaLinux 9 OpenSSH 9.9p1） | `account` stage |
| `pkill -STOP sssd_be` 會落在 `account` 或 `timeout` | SSSD process 卡住時登入是**卡住**（client server-alive 逾時），不是 PAM 拒絕 | 獨立 `timeout` stage + `PilotLoginProbeLoginStalled`（critical） |
| `ipa user-disable` 落在 auth 或 account 待定 | `account`（SSSD 仍回傳停用帳號的 key） | — |
| §3.1.2：用 IP 連一律 host-key 失敗 | **錯誤**：`sss_ssh_knownhostsproxy` 以 IP 也查得到 enrolled key | 仍以 FQDN 連線（身分），playbook 對不可解析的 FQDN fail closed |
| §3.1.6：IPA 若接受帶 options 的 key 就用 options 強化 | IPA 接受，但 `sss_ssh_authorizedkeys` **不傳遞 options**，forced command 無效 | 只靠 sshd-only HBAC + 無 sudo；`Match User` drop-in 留作後續 |
| S5 用停掉 IPA 製造全站失敗 | IPA 停掉時 SSSD offline cache 讓登入照常成功 | storm 演練改用全站 HBAC 停用 |
| §3.2.5：EL9 PSI 預設停用 | 成立（`CONFIG_PSI_DEFAULT_DISABLED=y`，無 `/proc/pressure`） | `HostDiskLatencyHigh`/`HostDiskQueueDeep` + `HostPSIUnavailable`（info） |
| 未預期 | SSSD 從使用者快取提供 authorized keys：換 canary key 後最長 `entry_cache_timeout` 才生效 | runbook 的兩步輪替流程；chain 在第一次查詢 canary 前就登記 key |
| 未預期 | `sssctl user-checks` 一律 exit 0，判斷結果在 stderr | `pilot diagnose` login 檢查解析 stderr 的 `pam_acct_mgmt:` |

告警名稱以實作為準：`PilotLoginProbe{AccountDenied,AuthFailed,LoginStalled,HostKeyMismatch,SessionFailed,TransportFailed,Stale,NoTargets}`、
`Host{IOStall,DiskLatencyHigh,DiskQueueDeep,PSIUnavailable,MetricsMissing}`。

---

## 0. 結論摘要

1. **Issue 其實是三個獨立子題**，應拆成三條交付線，而不是一個 feature：
   - (A) 外部 SSH/PAM 登入探測（新元件，含 Go daemon + canary 身分）
   - (B) 確定性的主機 I/O stall / 磁碟延遲 / 監控資料缺口告警（Prometheus rule + Alertmanager inhibit）
   - (C) 對拋棄式 topology 做四種情境演練並留 evidence
2. **(A) 建議新增 `login-probe` 元件**：一個 Go daemon `pilot-login-probe`（放在每站的
   Prometheus 主機上），每 60 秒對目標主機 spawn **OpenSSH client** 做 pubkey 登入，
   把結果寫進 node_exporter textfile collector。不要自己用 `x/crypto/ssh` 重做 SSH
   信任鏈，而是**原封沿用 `pilot-access-gateway` 已經實跑過的 `sss_ssh_knownhostsproxy`
   host-key 信任路徑**（§3.1）。
3. **(B) 建議走 Prometheus 確定性規則**（新的第三份 rule file，Jinja 渲染門檻），
   而不是塞進 detection-engine 的 adaptive profile；兩者是 peer path，跟
   `docs/architecture/snmp-monitoring.md` §3「Deterministic first, adaptive second」
   的既有決策一致。I/O stall 用 PSI（`node_pressure_io_*`），但 **AlmaLinux 9 的 PSI
   預設可能停用**，必須有 fallback（§3.2）。
4. **最大的技術風險是 failure 分類**：從 SSH client 端分辨「authentication 失敗」與
   「PAM account 拒絕」靠的是 OpenSSH 的 debug 訊息與斷線時序，AGENTS.md §5.6 規定
   這類 classifier 的 fixture 必須來自真實擷取。所以 **Phase 0 是「先擷取、再設計
   classifier」**，不是先寫程式（§4）。
5. 粗估工作量 2 週左右（Phase 0–4），其中 Phase 0 的擷取結果會決定 Phase 2 的
   classifier 形狀，不能省。

---

## 1. Issue 需求拆解與驗收對照

| # | Issue 原文要求 | 子題 | 本報告對應 |
|---|---|---|---|
| R1 | 每 60 秒從主機外部做 synthetic SSH login；專用、最小權限、無 sudo 的目錄帳號；非互動指令 | A | §3.1、§3.3 |
| R2 | 驗證真實 SSH authentication + PAM account 路徑；transport / authentication / PAM-account 失敗分開回報；憑證與私鑰不進 log 與 metrics | A | §3.1.3、§3.1.5 |
| R3 | 對持續性 host I/O stall、block-device latency、監控樣本缺失告警；門檻與持續時間可設定 | B | §3.2 |
| R4 | `sssctl user-checks -a acct -s sshd <canary>` 作為輔助診斷；外部 SSH 探測才是 availability signal | A | §3.1.6 |
| AC1 | 間隔、timeout、目標選擇、測試身分、告警門檻全部可設定；不 hard-code 位址與憑證 | A+B | §3.1.4、§3.2.3 |
| AC2 | `sssd.service` active 時，PAM account 拒絕仍要告警 | A | §3.1.3、§4 Phase 4 S2 |
| AC3 | I/O 壓力與資料缺口是不同的告警；恢復後 login alert 自動清除、不造成 alert storm | B | §3.2.2、§3.2.4 |
| AC4 | 在拋棄式 target 上演練成功登入 / PAM 拒絕 / I/O 壓力 / metrics 缺失四種情境並留 evidence | C | §4 Phase 4 |

---

## 2. Repo 現況事實快照（評估依據）

### 2.1 可以直接沿用的既有能力

| 能力 | 位置 | 對本 issue 的意義 |
|---|---|---|
| node_exporter + textfile collector（`/var/lib/node_exporter/textfile`，mode 1777） | `playbooks/apply/host-monitoring-apply.yml`、`docs/verification/host-monitoring.md` C11 | 探測器可以**不開 port、不做 Basic Auth**，直接把 metrics 寫 textfile，由既有 `job="node"` 帶上去 |
| Go daemon 寫 textfile 的既有樣式（`internal/promtext`：Registry / `WriteLoop` / `*_last_write_timestamp_seconds`） | `cmd/pilot-session-store/metrics.go`、`cmd/pilot-access-gateway/main.go`、`cmd/pilot-detection-engine/main.go` | 探測器照抄；series 先以 0 預置（repo 已踩過 `increase()` 看不到第一次事件的坑） |
| Prometheus 自動探索 `host-monitoring` group，每台主機帶 `pilot_host=<inventory_hostname>` + allowlisted annotation labels | `playbooks/apply/prometheus-apply.yml` 約 300–420 行 | 告警規則可以用 `pilot_host` 當唯一主機身分；探測器輸出的 per-target label **不可**叫 `pilot_host`（會被改名成 `exported_pilot_host`） |
| 第二份獨立 rule file 的前例（`prometheus_snmp_alert_rules_file`） | `prometheus-apply.yml` 第 146–151 行 | (B) 的規則可以放第三份 rule file，不必手動合併進 seed |
| seed rule 的 stale 告警樣式（`PilotSessionStoreMetricsStale`） | `playbooks/apply/files/pilot-alert-rules-seed.yml` | 探測器自身失效的告警照抄 |
| Alertmanager v0.27.0，receiver mode `null` / `teams` / `custom`，`group_wait 30s / group_interval 5m / repeat_interval 12h` | `playbooks/apply/alertmanager-apply.yml` | 支援 `inhibit_rules`；目前**沒有**任何 inhibit 規則 |
| Prometheus v2.53.0 | `prometheus-apply.yml` 第 77 行 | 支援 `keep_firing_for`（2.42+），可用來擋 flapping |
| detection-engine `linux-host-v1` 已有 `disk_io_busy` / `disk_io_queue_depth` / `disk_io_latency_seconds` 三個 storage feature（adaptive，`critical: false`） | `monitoring/detection/feature-profiles/linux-host-v1.yaml` | (B) 的 PromQL 可與它共用同一套 device filter 與公式，避免兩邊定義分岔 |
| Gateway 的 OpenSSH 信任路徑：`ProxyCommand sss_ssh_knownhostsproxy`、`StrictHostKeyChecking yes`、`GlobalKnownHostsFile /var/lib/sss/pubconf/known_hosts`、`BatchMode yes` | `cmd/pilot/cmd/portal_ssh.go` 的 `pilotSSHConfig`（有 `TestPilotSSHConfigMatchesApplyPlaybook` 鎖住與 playbook 一致） | 探測器的 ssh_config 直接沿用這組，符合 AGENTS.md §5.9「不准 apply 時 `ssh-keyscan` 快照、不准 TOFU」 |
| freeipa-identity roster 支援 `users[].ssh_keys`、`hbac.rules`、`sudo.rules`、`disable_allow_all` | `playbooks/apply/freeipa-identity.roster.example.yaml` | canary 帳號、HBAC 規則可以資料驅動；不需要新語法 |
| 測試用 IPA 帳號只准走 `freeipa-client-fixtures.yml`（`ipa_fixture_manage_sudorule: false` 只建 user 不掛 sudo） | `playbooks/test/fixtures/freeipa-client-fixtures.yml`、AGENTS.md §4.1 | Phase 4 的 canary fixture 必須 import 這支 |
| `pilot diagnose` MCP 已會跑 `sssctl domain-status` | `cmd/pilot/cmd/mcp_diagnose_tools.go`（測試在 `mcp_diagnose_tools_test.go:822`） | R4 的 `sssctl user-checks` 掛在同一個診斷工具最自然 |
| Go 二進位「controller 建置後複製到目標主機」的交付樣式（`*_artifact_path` + sha256 + Dockerfile bake + `TestDockerfileBakesEveryDistArtifactGroupVarsExpects`） | `contracts/detection-engine.yaml`、`images/Dockerfile.pilot-cli` | 新 daemon 照 detection-engine 的交付路徑 |
| `vm-target topology test --ephemeral` 與多 VM topology 宣告 | `docs/topologies/*.yaml`、`docs/runbooks/vm-target.md` §3.7 | Phase 4 演練用 |
| 新元件要碰的檔案清單（可從 commit 反推） | `2713b5b`（snmp-exporter Phase 0，22 檔）、`6e3ab65`（dcgm-exporter，16 檔） | §5 的檔案清單直接照這兩個 commit 核對 |

### 2.2 目前沒有的東西（gap）

1. **沒有任何「主動探測」元件**。所有監控都是 exporter 被 scrape；`internal/availability`
   只做部署前的 TCP 可達性探測，`internal/networkcheck` 是 `pilot network check` 的一次性
   Ansible ad-hoc 探測，兩者都不是 60 秒常駐探測。
2. `golang.org/x/crypto` 只是 **indirect** 依賴（`go.mod` 第 59 行），repo 內沒有任何
   Go code 自己當 SSH client；gateway/portal 都 spawn 系統 OpenSSH。
3. 告警只有 `up != 1` 10 分鐘的 `HostDown`，沒有「scrape 失敗但主機其實還活著」這種
   區分，也沒有任何 I/O / latency 的確定性規則。
4. `playbooks/apply/files/pilot-alert-rules-seed.yml` **刻意不經 Jinja**（避免與
   `{{ $labels }}` 衝突），所以 issue 要的「門檻可設定」不能直接在 seed 檔做。
5. `docs/runbooks/host-monitoring.md` §0 已明文：同一批主機要加別的監控 agent
   （舉例就寫了 blackbox_exporter）一律新開獨立 component，不塞進 `host-monitoring`。

---

## 3. 方案評估

### 3.1 子題 A：外部 SSH/PAM 登入探測

#### 3.1.1 探測器實作選項比較

| 選項 | 做法 | 優點 | 缺點 / 否決理由 |
|---|---|---|---|
| **A1（建議）** Go daemon spawn OpenSSH client | `cmd/pilot-login-probe` 每輪對每個 target 執行 `ssh -F <pinned ssh_config> -v -o BatchMode=yes ... <fqdn> /bin/true`，解析 exit code + stderr 的 debug 行 | 信任鏈與 gateway 完全相同（`sss_ssh_knownhostsproxy`）；真的走到 sshd 的 `AuthorizedKeysCommand sss_ssh_authorizedkeys` + PAM account；不新增 crypto code；OpenSSH debug 字串多年穩定 | 要解析 stderr（§5.6：fixture 必須真實擷取）；每輪 fork 一個 process（60 秒一次，可忽略） |
| A2 Go in-process `x/crypto/ssh` | 直接在 daemon 內做 SSH handshake | 錯誤型別結構化（`unable to authenticate` vs `EOF`）、有 `BannerCallback` | **host-key 信任沒有現成路徑**：`/var/lib/sss/pubconf/known_hosts` 是 `sss_ssh_knownhostsproxy` 每次連線前才寫入的，不先跑 proxy 就讀不到；要自己對 IPA 查 `ipaSshPubKey` 等於重做一套信任鏈，違反 §5.9 的精神 |
| A3 上游 exporter（`treydock/ssh_exporter`、blackbox `ssh_banner`） | 以既有 exporter 做 `/probe?target=` | 不用寫 Go | blackbox 只摸 banner，不做認證；ssh_exporter 的失敗原因只有 `timeout/error/command-*`，**分不出 auth 與 PAM account**，也沒有 SSSD host-key 信任路徑；多一個第三方 binary 要 pin 版本與 checksum |
| A4 Ansible cron / `pilot network check` 延伸 | 以 Ansible ad-hoc 定時跑 `ssh` | 零新 binary | 60 秒一次 fork ansible 太重；結果沒有 metrics 路徑；無法做 hysteresis |

**選 A1。** 它跟 repo 既有的三個 Go daemon（detection-engine / agent-controller /
session-store）是同一種交付形狀，而且把最難的信任問題交給已經在正式環境跑的 gateway
路徑。

#### 3.1.2 元件形狀（建議）

| 項目 | 建議 |
|---|---|
| 元件 / role / group 名稱 | `login-probe`（contract `contracts/login-probe.yaml`，group `login-probe`） |
| 部署位置 | 每站一台，預設與該站 `prometheus` 同機（minimal-poc 的 `nexus` 已同時是 `freeipa-client` + `host-monitoring` + `prometheus`），但以獨立 group 宣告，不綁死 |
| `hostCardinality` | `zero-or-more`（opt-in），比照 `snmp-exporter` |
| `dependencies` | `freeipa-client`（`sameHosts`, required：提供 `sss_ssh_knownhostsproxy` 與 canary 解析）、`host-monitoring`（`sameHosts`, required：textfile collector） |
| `site.include` | 第一版 `false` / `optIn: true`；通過 Phase 4 後再評估改 `true`（§5.7 第 5 點：改 true 當天要跑一次真實全站 deploy） |
| Runtime | 單一靜態 Go binary，systemd service，專屬系統帳號 `pilot-login-probe`（`NoNewPrivileges`、`ProtectSystem=strict`、`ReadWritePaths=` 只給 textfile 目錄）；需要能執行 `/usr/bin/sss_ssh_knownhostsproxy` 與讀 `/var/lib/sss/pubconf/known_hosts` |
| 設定檔 | `/etc/pilot/login-probe/config.yml`（root:pilot-login-probe 0640）+ 私鑰 `/etc/pilot/login-probe/id_ed25519`（0600，owner 為服務帳號） |
| Metrics 輸出 | `/var/lib/node_exporter/textfile/pilot_login_probe.prom`，每輪重寫，另有 `pilot_login_probe_metrics_last_write_timestamp_seconds` |
| 目標清單 | apply 時由 inventory 渲染進 config：預設 `groups['freeipa-client']`，可用 `login_probe_targets` 明確覆寫 |
| 目標身分 | `probe_target` = 小寫 inventory_hostname（§5.13：`ansible_host` 是連線位址，不是身分）；SSH 連線的 `HostName` 用 **FQDN**，因為 `sss_ssh_knownhostsproxy -p %p %h` 是拿 `%h` 去 IPA 查 host object；FQDN 由 `freeipa_domain` 推導（§5.7 第 2 點的既有做法） |

> **FQDN 解析是前提**：proxy 本身也要能把 FQDN 解析成 IP。PoC topology 目前靠
> `/etc/hosts` pin（topology 檔的 `freeipa-server=ipa1.ipa.pilot.internal` 寫法）或
> `freeipa-dns-client`。login-probe playbook 應比照既有
> `tasks/resolve-hosts-alias-target.yml` 的 pin 慣例，或在 pre_tasks assert FQDN 可解析，
> 不要靜默退回用 IP（用 IP 連會讓 host-key 查不到 → 一律 transport 失敗）。

#### 3.1.3 Failure 分類設計（必須由 Phase 0 擷取定案）

Issue 要求 transport / authentication / PAM-account 分開回報。從 OpenSSH client 端
可觀察到的訊號（**以下為依 OpenSSH 原始碼行為的推測，Phase 0 要逐一擷取確認**）：

| stage（label 值） | 預期訊號 | 典型成因 |
|---|---|---|
| `transport` | exit 255 + `Connection timed out` / `Connection refused` / `No route to host` / `Could not resolve hostname` / proxy 本身錯誤 | sshd 掛、防火牆、DNS、主機下線 |
| `hostkey` | exit 255 + `Host key verification failed.` | IPA 的 host object 沒有 key、主機重裝未 re-enroll、MITM |
| `auth` | exit 255 + `Permission denied (publickey...)`，debug 行**沒有** `Server accepts key` | canary 不存在、key 不在 IPA、`sss_ssh_authorizedkeys` 失敗、SSSD 離線且無 cache |
| `account` | debug 行出現 `Server accepts key`，**沒有** `Authenticated to`，接著 `Connection closed by <ip> port 22`（可能先收到 PAM banner）。sshd 端對應 `fatal("Access denied for user %s by PAM account configuration")` | HBAC 拒絕、帳號被 disable、`pam_sss` 逾時（sssd_be 卡住但 service 仍 active ← **issue 的核心情境**） |
| `session` | `Authenticated to` 出現後指令非 0 結束或 session 建立失敗 | `pam_session` 失敗（mkhomedir）、shell 不可用 |
| `timeout` | daemon 自己的總 timeout 到期 | 任何階段卡死 |
| `ok` | `Authenticated to` + 指令 exit 0 | 成功 |

Phase 0 要擷取的真實情境至少：成功、未知帳號、key 不在 IPA、HBAC 規則移除、
`ipa user-disable`、`pkill -STOP sssd_be`（service active 但後端卡住）、`pkill -STOP
sssd_pam`、sshd 停止、port 被 DROP、host-key 不符、FQDN 不可解析。每一種都要存
stdout/stderr/exit code 到 `internal/loginprobe/testdata/`，classifier 的單元測試同時要有
「應分類成 X」與「不應分類成 X」兩種案例（§5.12）。

> 兩個已知的分類盲區，報告先點出來：
> 1. `account` 與某些 `transport` 情況（例如 sshd 在 auth 中途被 kill）都以 EOF 結束；
>    靠「`Server accepts key` 已出現」這個 debug 標記區分。Phase 0 若證實這個標記不
>    穩定，fallback 是把 `account` 定義成「key 已被接受後斷線」並在 spec 寫明限制。
> 2. `ipa user-disable` 到底落在 `auth` 還是 `account`，取決於 SSSD 對 locked 帳號是否
>    還回傳 authorized keys；不要猜，擷取為準。

#### 3.1.4 設定契約（變數名稱草案，spec 定案前可改）

| 變數 | 預設 | 說明 |
|---|---|---|
| `login_probe_interval` | `60s` | 每輪間隔（R1） |
| `login_probe_connect_timeout` | `10s` | OpenSSH `ConnectTimeout` |
| `login_probe_total_timeout` | `30s` | 單一 target 的總 timeout（含 proxy、auth、指令） |
| `login_probe_concurrency` | `4` | 同時探測的 target 數 |
| `login_probe_target_group` | `freeipa-client` | 自動展開的 inventory group |
| `login_probe_targets` | `[]` | 明確覆寫：`[{name, fqdn, address, port}]` |
| `login_probe_ssh_port` | `22` | 預設 port |
| `login_probe_user` | `pilot-login-canary` | canary 帳號 |
| `login_probe_command` | `/bin/true` | 非互動檢查指令 |
| `login_probe_ssh_private_key` | （vault，必填） | ed25519 私鑰內容，`no_log` |
| `login_probe_textfile_path` | `/var/lib/node_exporter/textfile/pilot_login_probe.prom` | 輸出 |
| `login_probe_artifact_path` / `login_probe_artifact_sha256` | （必填 / 選填） | 比照 detection-engine 的 binary 交付 |

全部進 `contracts/login-probe.yaml` 的 `groupVars`、`group_vars/login-probe.example.yml`、
`internal/inventory/vault.go` 新增 `login-probe` vault section（只有私鑰一個 key）。

#### 3.1.5 Metrics 草案

```
pilot_login_probe_success{probe_target}                       gauge 0/1（最近一次）
pilot_login_probe_last_success_timestamp_seconds{probe_target} gauge
pilot_login_probe_last_stage{probe_target,stage}               gauge 0/1（stage ∈ ok|transport|hostkey|auth|account|session|timeout，每輪恰好一個為 1）
pilot_login_probe_attempts_total{probe_target}                 counter
pilot_login_probe_failures_total{probe_target,stage}           counter（所有 stage 先預置 0）
pilot_login_probe_duration_seconds{probe_target}               gauge（最近一次）
pilot_login_probe_targets                                      gauge（設定的 target 數）
pilot_login_probe_metrics_last_write_timestamp_seconds         gauge
```

- label 只有固定 enum 與 `probe_target`；**不得**有 `pilot_host` / `instance` / `job` /
  `site`（會與 Prometheus target label 衝突被改名）。
- 不記錄任何 stderr 原文、指令輸出或 key 路徑以外的檔案內容。
- journal log：只記 `target`、`stage`、`duration`、經過白名單過濾的 OpenSSH 錯誤行；
  任何含 `-----BEGIN` 或私鑰路徑內容的字串一律 redact。spec 要有一列像
  `agent-controller.md` 那樣「textfile 與 log 不含 secret」的檢查。

#### 3.1.6 Canary 身分與輔助診斷

- canary 由 **freeipa-identity roster** 管理（正式環境）：`users` 一筆
  `pilot-login-canary`（`ssh_keys.authoritative: true`、無 sudo 規則）、`hbac.rules`
  一條只允許 `sshd` 到被探測的 hostgroup。測試環境走 §4.1 的 fixtures。
- 建議 **pubkey** 而非 GSSAPI：BatchMode 下最單純、沒有 ticket 生命週期問題、而且
  pubkey 路徑正好不跑 PAM auth stack、只跑 account + session，跟 issue 要驗的
  「PAM account path」對齊。GSSAPI 可以當 Phase 5 的可選模式。
- 強化（Phase 0 要先確認 IPA 是否接受帶 options 的 key）：若 `ipa user-mod --sshpubkey`
  接受 `command="/bin/true",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding`
  前綴，就把限制寫在 key 本身；不接受的話，fallback 是比照
  `pilot-access-target-policy` 在 target 加 `Match User pilot-login-canary` 的 sshd drop-in
  （這是每台 target 的 mutation，列為可選 Phase）。
- `sssctl user-checks -a acct -s sshd pilot-login-canary` 掛進 `pilot diagnose` 的 host
  診斷工具（已有 `sssctl domain-status` 的同一個 composite），同時列入 runbook 的
  「告警觸發後第一個要跑的指令」；它不是 availability signal（R4）。

#### 3.1.7 不可忽略的營運副作用

- 每台 target 每天會多 **1440 次** canary 登入，`audit-log-forwarding`、`wazuh-fim`、
  sshd journal 都會看到。交付時要一併給 SIEM 側的降噪建議（例如 Wazuh rule 對
  `pilot-login-canary` 降級），並在 runbook 寫明；不能等上線後才被問。
- canary 私鑰若外洩，攻擊者可以用無 sudo 的帳號登入所有被探測主機；用 key options
  或 sshd Match 限制 + HBAC 只開 sshd 把影響縮到「能連上但什麼都不能做」，並寫進
  spec 的風險欄。
- 若 target 啟用 `pam_mkhomedir`，canary 第一次登入會在每台主機建 home；接受或改
  `home_directory` 到固定路徑，Phase 0 一併確認行為。

### 3.2 子題 B：I/O pressure、磁碟延遲、監控資料缺口告警

#### 3.2.1 放哪一層：Prometheus 確定性規則，不是 detection-engine

| 選項 | 評估 |
|---|---|
| **B1（建議）** 新增第三份 rule file（例如 `prometheus_host_health_alert_rules_file`），以 **Jinja template** 渲染門檻與 `for:`，Prometheus 自己的 `{{ $labels }}` 用 `{% raw %}` 包住 | 符合 issue「門檻與持續時間可設定」；沿用 `prometheus_snmp_alert_rules_file` 的獨立覆寫慣例；跟 detection-engine 的 adaptive 偵測是 peer path |
| B2 加進 `linux-host-v1` profile | profile 已經有 `disk_io_*` 三個 feature，但刻意 `critical: false`、`warning` 需要 corroboration，是 **adaptive** 判斷；issue 要的是固定門檻、可與登入失敗做時間關聯的硬規則。改 profile 也會改 SignalEvent fingerprint（profile `version` 要升） |
| B3 改既有 seed 檔 | seed 檔不經 Jinja，門檻寫死；只能靠整份換檔覆寫，不符合「可設定」 |

#### 3.2.2 規則草案（名稱與門檻為草案）

| alert | expr（概念） | 預設 `for` | severity | 說明 |
|---|---|---|---|---|
| `HostIOStall` | `rate(node_pressure_io_stalled_seconds_total{job="node"}[5m]) > {{ host_io_stall_ratio_threshold }}`（預設 0.25，即 5 分鐘內 25% 時間全體 task 卡在 I/O） | 10m | warning | PSI full stall；需 kernel PSI |
| `HostIOWaitHigh` | `rate(node_pressure_io_waiting_seconds_total[5m]) > …` | 10m | info/warning | PSI some；可選 |
| `HostDiskLatencyHigh` | 與 `linux-host-v1` 的 `disk_io_latency_seconds` **同一段 PromQL**（read+write time / completed ops，同一組 device filter）`> {{ host_disk_latency_seconds_threshold }}`（預設 0.1） | 10m | warning | 不依賴 PSI，是 EL9 的 fallback |
| `HostDiskQueueDeep` | `rate(node_disk_io_time_weighted_seconds_total[5m]) > …` | 10m | warning | 可選 |
| `HostMetricsMissing` | `up{job="node"} == 0 and on (pilot_host) label_replace(pilot_login_probe_success == 1, "pilot_host", "$1", "probe_target", "(.*)")` | 3m | warning | **scrape 掉了但 SSH 探測還成功** → 監控資料缺口，與 `HostDown` 語意不同 |
| `PilotLoginProbeAccountDenied` | `label_replace(pilot_login_probe_last_stage{stage="account"} == 1, "pilot_host", …)` | 3m（= 3 輪） | critical | AC2 |
| `PilotLoginProbeAuthFailed` | 同上 `stage="auth"` | 3m | critical | |
| `PilotLoginProbeTransportFailed` | `stage=~"transport\|hostkey\|timeout"` | 5m | warning | 會被 `HostDown` inhibit |
| `PilotLoginProbeStale` | `time() - pilot_login_probe_metrics_last_write_timestamp_seconds > 180` | 5m | warning | 探測器自己掛了 |
| `PilotLoginProbeNoTargets` | `pilot_login_probe_targets == 0` | 15m | info | 設定錯誤 |

- 所有 login-probe 告警都用 `label_replace` 把 `probe_target` 投影成 `pilot_host`，
  讓 Alertmanager 的 `inhibit_rules` 可以用 `equal: [pilot_host]` 關聯，也讓 dashboard
  與 `pilot diagnose` 用同一個身分查。
- `keep_firing_for: {{ login_probe_alert_keep_firing_for }}`（預設 5m）擋 flapping，
  配合既有 `group_interval 5m` / `repeat_interval 12h`；AC3 的「恢復後清除、不 storm」
  在 Phase 4 以 `changes(ALERTS{alertname="PilotLoginProbeAccountDenied"}[30m])` 證明
  只有一次 firing→resolved 轉換。

#### 3.2.3 門檻變數（放 prometheus role 的 group_vars 契約）

`host_io_stall_ratio_threshold`、`host_io_stall_for`、`host_disk_latency_seconds_threshold`、
`host_disk_latency_for`、`host_metrics_missing_for`、`login_probe_alert_for`、
`login_probe_alert_keep_firing_for`。全部進 `contracts/prometheus.yaml` 的 `groupVars`
與 `docs/verification/prometheus.md` §1.5；規則檔的 rendering 要有 regression test
（golden 檔，含 `{% raw %}` 區段不被 Jinja 吃掉的斷言）。

#### 3.2.4 Alertmanager 側

- 新增 `inhibit_rules`：`HostDown` 抑制同 `pilot_host` 的 `PilotLoginProbeTransportFailed`
  與 `HostMetricsMissing`；`PilotLoginProbeStale` 抑制同 site 的所有 `PilotLoginProbe*`
  （探測器掛了不要連帶噴每台 target）。
- `receiver_mode: custom` 的使用者自帶整份 `alertmanager.yml`，inhibit 規則要寫進
  `docs/verification/alertmanager.md` 的說明與 example，而不是只改 `null`/`teams` 模板。
- `group_by` 目前沒指定（Alertmanager 預設按 route 全部 group）；若 IPA 整站故障，
  所有 target 同時 `account`/`auth` 失敗會是一則通知，不會 storm。保持現狀即可，但
  Phase 4 要實測一次「全部 target 同時失敗」的通知數。

#### 3.2.5 PSI 在 AlmaLinux 9 的可用性（待驗證，影響規則設計）

node_exporter 的 `pressure` collector 預設啟用，但 RHEL/AlmaLinux 9 kernel 編譯時
`CONFIG_PSI_DEFAULT_DISABLED=y`，**沒有 `psi=1` 開機參數時 `/proc/pressure/*` 讀取會回
`Operation not supported`**，`node_pressure_*` series 不會出現，`HostIOStall` 永遠不會
觸發。Ubuntu 24.04 預設開啟（本機 dev box 實測 `/proc/pressure/io` 可讀）。Phase 0 要在
`almalinux-9` vm-target 實測並決定：

1. 只靠 `HostDiskLatencyHigh` / `HostDiskQueueDeep` 當 EL9 的覆蓋（建議，零 mutation），
   runbook 寫明 PSI 規則在 EL9 不適用；或
2. `host-monitoring-apply.yml` 對 EL9 加 `psi=1` 到 kernel cmdline（需要重開機，屬於
   高風險 mutation，**不建議**在這個 issue 內做）。

另外要加一條 `HostPSIUnavailable`（`absent` 類）或至少在 verification spec 用一列
記錄「這台主機 PSI 是否可用」，避免 EL9 主機靜默沒有 I/O stall 告警而沒人知道（§5.12：
每個 gate 都要證明它會觸發）。

### 3.3 子題 C：情境演練與 evidence

Phase 4 的 topology 與注入方法見 §4；這裡先列原則：

- 演練用 `pilot vm-target topology test --ephemeral` 跑完 apply → verify → 冪等，再用
  per-run 的注入腳本（放 `tmp/` 或 `.verification/`，不提交）觸發四種情境。
- 每種情境的證據：注入指令與時間、Alertmanager `GET /api/v2/alerts` 的 sanitized 輸出、
  Prometheus 查詢結果、target 上 `systemctl is-active sssd`（AC2 要證明 active）、
  `sssctl user-checks` 輸出、恢復後的 resolved 證明與 `changes(ALERTS…)` 計數。
- 若演練過程中要 `sss_cache` 才能讓告警出現或消失，依 AGENTS.md §5.9 第 5 點視為 bug，
  不准當 workaround 寫進 evidence。

---

## 4. 建議的交付切法

### Phase 0 — 真實擷取與設計決策（1–2 天，無任何正式交付物）

| 任務 | 產出 |
|---|---|
| 2 台 vm-target（`almalinux-9` FreeIPA server + Ubuntu `freeipa-client`），以 `freeipa-client-fixtures.yml` 建 canary（`ipa_fixture_manage_sudorule: false`） | — |
| 對 §3.1.3 列出的每個情境擷取 `ssh -v` stderr、stdout、exit code（含 `pkill -STOP sssd_be` 這個 issue 核心情境） | `internal/loginprobe/testdata/*.txt` + `docs/evidence/login-probe/<date>-phase0-ssh-capture.md` |
| 確認 IPA 是否接受帶 options 的 `sshpubkey`；確認 `pam_mkhomedir` 行為；確認 `ipa_hbac_refresh`（預設 5s）下 HBAC 變更多久反映，不靠 `sss_cache` | 寫進 capture evidence 的決策表 |
| 在 `almalinux-9` vm-target 讀 `/proc/pressure/io`，確認 PSI 是否可用 | 決定 §3.2.5 的走法 |
| 確認 `systemd-run -p IOWriteBandwidthMax="/dev/vda 1M"` + `dd oflag=direct` 能否在 virtio 磁碟上穩定製造 PSI stall（cgroup v2） | 決定 Phase 4 S3 的注入方法 |

**Exit gate**：classifier 決策表每一列都有對應的真實擷取；沒有擷取到的情境不得進 spec。

### Phase 1 — Spec first（1 天）

- `docs/verification/login-probe.md`（§1 目標系統、§1.5 變數契約、checklist：binary/版本/
  帳號/unit 硬化/service active/textfile 存在且含 `pilot_login_probe_success`/log 與
  textfile 不含 secret/至少一個 target 最近一次 `ok`…），`pilot spec --lint` 0 errors。
- `contracts/login-probe.yaml`、`group_vars/login-probe.example.yml`、
  `internal/inventory/catalog.go` + `contracts.go` + `vault.go`、`cmd/pilot/cmd/deploy_catalog.go`。
- `internal/spec/login_probe_regression_test.go`（row 連號、無 vague expected、tag 覆蓋）；
  `tag_coverage_test.go` 的 `specTagMap` 登記。
- `docs/verification/prometheus.md` / `alertmanager.md` 加上 (B) 的變數與 row。
- 跑完整 `go test ./...`：`edit_tui_role_presets_test.go` 的固定終端高度（52 列）很可能
  被新 role 擠爆（§5.7 第 3 點已預告），這次順手改成依 role 數計算。

### Phase 2 — Go daemon（2–3 天）

- `internal/loginprobe`：config 載入與驗證、scheduler（固定間隔、overrun 跳過不堆積，
  比照 detection-engine 的 `TestScheduler_OverrunSkipsInsteadOfBacklogging`）、OpenSSH
  runner（固定 argv、pinned ssh_config、`-F`、`-v`、總 timeout）、classifier（Phase 0
  fixture 驅動，pass/trigger 雙向測試）、promtext metrics、redaction。
- `cmd/pilot-login-probe/main.go`：薄包裝，`-config`、`-once`（單次執行印 JSON，給
  runbook 與 `pilot diagnose` 用）。
- `images/Dockerfile.pilot-cli` bake binary；`dist/` 期望由
  `TestDockerfileBakesEveryDistArtifactGroupVarsExpects` 鎖住。
- `go test -race ./...` 綠。

### Phase 3 — Playbook 與告警（2–3 天）

- `playbooks/apply/login-probe-apply.yml`：stage/confirm/cross-check gate（`tags: [always]`，
  §4.3）、block/rescue（rescue 全 `always`，§4.4）、建帳號、複製 binary + sha256 驗證、
  渲染 config 與 ssh_config、寫私鑰（`no_log`）、systemd unit、`/etc/hosts` pin 或
  FQDN 解析 assert、health（`-once` 跑一輪至少一個 target 回 `ok` 或明確 stage）。
  Row tag 對齊 spec；`--list-tags` 無撞號。
- `prometheus-apply.yml`：第三份 rule file（Jinja 模板 + `{% raw %}`）、門檻變數、
  golden regression test；`promtool check rules` 進 spec row。
- `alertmanager-apply.yml`：`inhibit_rules`；`custom` 模式的文件與 example。
- `pilot diagnose`：host composite 加 `sssctl user-checks -a acct -s sshd <login_probe_user>`
  （唯讀；只在 target 有 sssd 時執行）。
- 對**全新** vm-target 跑 `--check --diff`（§4.0 round-13 教訓）。

### Phase 4 — Topology 演練與 evidence（2–3 天）

Topology `docs/topologies/login-probe-topology.yaml`：

| node | base image | groups |
|---|---|---|
| `lp-ipa` | almalinux-9 | `freeipa-server` |
| `lp-mon` | ubuntu-24.04 | `freeipa-client`、`host-monitoring`、`prometheus`、`alertmanager`、`login-probe` |
| `lp-target` | ubuntu-24.04 | `freeipa-client`、`host-monitoring` |
| `lp-target-el`（可選） | almalinux-9 | `freeipa-client`、`host-monitoring`（驗 PSI fallback） |

Fixtures `playbooks/test/fixtures/login-probe-fixtures.yml`：import
`freeipa-client-fixtures.yml` 建 canary（不掛 sudo）+ `ipa hbacrule-add login-probe-canary`
只允許 sshd 到 target hostgroup。

情境：

| # | 情境 | 注入（target 側，除非註明） | 預期 | 恢復 |
|---|---|---|---|---|
| S1 | 成功登入 | 無 | `pilot_login_probe_success==1`、無告警 | — |
| S2a | PAM account 拒絕（HBAC） | `lp-ipa`：`ipa hbacrule-remove-user` 或 `hbacrule-disable` | ≤ 3 輪內 `stage="account"`，`PilotLoginProbeAccountDenied` firing；同時 `systemctl is-active sssd` = active；`sssctl user-checks` 顯示 acct 失敗 | 加回規則 → resolved，`changes(ALERTS…)` = 1 次轉換 |
| S2b | PAM account 拒絕（後端卡住但 service active） | `pkill -STOP sssd_be`（或 `sssd_pam`） | 同上（或 `timeout`，依 Phase 0 擷取結果定） | `pkill -CONT` |
| S3 | I/O 壓力 | `systemd-run -p IOWriteBandwidthMax=… dd oflag=direct`（或 `stress-ng --hdd`） | `HostIOStall`（Ubuntu）/ `HostDiskLatencyHigh`（EL9）firing；login 告警**不**觸發 | 停掉 unit |
| S4a | 監控資料缺口 | `systemctl stop node_exporter` 或 DROP 9100 | `HostMetricsMissing` firing（3m），login probe 仍 `ok`，`HostDown` 10m 後才來且 inhibit transport 告警 | 恢復 |
| S4b | 探測器自身失效 | `lp-mon`：`systemctl stop pilot-login-probe` | `PilotLoginProbeStale` firing，且 inhibit 其餘 `PilotLoginProbe*` | 啟動 |
| S5 | 全站 IPA 故障 | `lp-ipa`：停 `ipa` 服務 | 所有 target 同時失敗只產生**一則** Alertmanager 通知（驗 storm） | 啟動 |

Evidence：`docs/evidence/login-probe/<date>-<rev>.md`（sanitized，不含 cast 路徑），
runbook `docs/runbooks/login-probe.md` 含 §0.5 事實快照、告警處置 SOP（第一步跑
`sssctl user-checks`）、SIEM 降噪建議。`AGENTS.md` §4.3 清點改 41 支、`DELIVERY.md`
playbook 對照表；`group_vars/restic-backup.example.yml` **不需要**改（只寫 `/etc`，
無資料）。

### Phase 5 — 可選後續

`site.include: true`、Grafana dashboard panel、`pilot host decommission` 對 target 退役時
重新渲染 login-probe target 清單（否則退役主機會一直 `transport` 失敗直到下次 apply）、
per-host annotation 停用探測、GSSAPI 模式、target 側 sshd `Match User` 限制。

---

## 5. 檔案清單（新增 / 修改）

| 類別 | 路徑 | 動作 |
|---|---|---|
| Spec | `docs/verification/login-probe.md` | 新增 |
| Spec | `docs/verification/prometheus.md`、`docs/verification/alertmanager.md` | 修改（變數 + row） |
| Contract | `contracts/login-probe.yaml`、`contracts/prometheus.yaml`（新 groupVars） | 新增 / 修改 |
| Inventory | `internal/inventory/catalog.go`、`contracts.go`、`vault.go`、`inventory.example.yml` | 修改 |
| Deploy | `cmd/pilot/cmd/deploy_catalog.go`、`deploy_test.go`、`contract_test.go`、`edit_tui_*_test.go`、`tag_coverage_test.go` | 修改 |
| Go | `cmd/pilot-login-probe/`、`internal/loginprobe/`（含 `testdata/` 真實擷取） | 新增 |
| Image | `images/Dockerfile.pilot-cli`、`dockerfile_artifact_consistency_test.go` | 修改 |
| Playbook | `playbooks/apply/login-probe-apply.yml`、`playbooks/apply/templates/login-probe-*.j2` | 新增 |
| Playbook | `playbooks/apply/prometheus-apply.yml` + `templates/pilot-host-health-alert-rules.yml.j2`、`playbooks/apply/alertmanager-apply.yml` | 修改 / 新增 |
| Diagnose | `cmd/pilot/cmd/mcp_diagnose_tools.go` + test | 修改 |
| Tests | `internal/spec/login_probe_regression_test.go`、rule template golden test、classifier 雙向測試 | 新增 |
| Test infra | `docs/topologies/login-probe-topology.yaml`、`playbooks/test/fixtures/login-probe-fixtures.yml`、`playbooks/test/login-probe-chain.yml` | 新增 |
| Docs | `docs/runbooks/login-probe.md`、`docs/evidence/login-probe/*.md`、`group_vars/login-probe.example.yml`、`docs/README.md`、`AGENTS.md` §4.3、`DELIVERY.md` | 新增 / 修改 |

---

## 6. 風險、未知與假設（需使用者確認）

依 AGENTS.md §0.2，以下是本評估**自行假設**、尚未經使用者確認的事項：

| # | 假設 / 未知 | 若不成立的影響 |
|---|---|---|
| U1 | canary 用 **pubkey**（不是 GSSAPI / password） | 若要求驗 Kerberos 路徑，Phase 2 的 runner 要加 keytab + `kinit` 生命週期 |
| U2 | 探測器部署在**每站 Prometheus 主機**，該主機已是 `freeipa-client` + `host-monitoring` | 若探測器要放在非 IPA 成員主機，§3.1.1 的信任路徑不成立，必須回到 A2 自建信任鏈 |
| U3 | 預設目標 = `freeipa-client` group 全部主機 | 若只想探測一部分，用 `login_probe_targets` 覆寫即可，不影響設計 |
| U4 | 第一版 opt-in（`site.include: false`） | 若要求納入全站 deploy，Phase 4 要多跑一次真實全站 deploy（§5.7 第 5 點） |
| U5 | OpenSSH `-v` 的 `Server accepts key` / `Authenticated to` 標記足以區分 auth 與 account | Phase 0 證偽時，`account` 的定義退化為「key 被接受後斷線」，spec 寫明限制 |
| U6 | EL9 的 PSI 預設停用，不在本 issue 內改 kernel cmdline | 若使用者要求 EL9 也要 PSI 規則，需加入 `psi=1` + 重開機的高風險 mutation |
| U7 | 每台 target 每天 1440 次 canary 登入的 SIEM 噪音可接受，降噪另案 | 若不可接受，間隔要放大（issue 明寫 60 秒）或在 Phase 3 一併交付 Wazuh 規則 |
| U8 | 告警 severity：account/auth = critical，transport/metrics-missing = warning | 純營運偏好，spec 定案前確認 |
| U9 | I/O 門檻預設值（stall 25%、latency 100 ms、`for` 10m） | 純營運偏好；可設定是硬需求，預設值不是 |

其他風險：

- **分類器永遠比對不到**（§5.12 的 8 個前例）：對策是 Phase 0 擷取 + 雙向測試 +
  Phase 4 每種 stage 真的觸發一次。
- **探測器是每站單點**：掛了只會 `PilotLoginProbeStale`，不會誤報 target；可接受。
- **`/etc/hosts` pin 與 FQDN**：若站台沒有 DNS，playbook 要負責 pin；pin 錯會變成
  `transport`/`hostkey` 失敗，Phase 4 S1 會抓到。
- **canary 私鑰輪替**：目前沒有自動輪替；runbook 要寫手動輪替 SOP（改 vault + roster
  + 重新 apply 兩邊）。

---

## 7. 不建議的做法（明確排除）

- 把探測塞進 `host-monitoring-apply.yml`：違反該 spec 開頭與 runbook §0 的明文決策。
- 用 `ssh-keyscan` 在 apply 時產生 known_hosts：§5.9 第 2 點已否決過一次（gateway）。
- 在 seed rule 檔寫死門檻：不符合 AC1。
- 先寫 classifier 再找 fixture 對上：§5.6 明文禁止；Phase 0 必須在前。
- 用 `sss_cache` 讓演練「過」：§5.9 第 5 點視為 bug。
- 把 I/O 告警做成 detection-engine profile 改動：adaptive 與 deterministic 是兩條路，
  且會改 fingerprint。
