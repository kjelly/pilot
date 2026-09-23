# Pilot Access Gateway — Per-Host SSH Session Recording 實作規格

> Status: IMPLEMENTATION-READY (rev 2.3)
> Baseline repository: `https://github.com/kjelly/pilot`
> Baseline revision: `c0890f66479c2aed189fd216ddeec87f72bb7306` (`main`, 2026-09-23)
> Revision: rev 2.3（2026-09-23）。依 baseline 程式碼逐項核對、獨立 review 與使用者決策修訂，變更摘要見 §40。
> Scope: Pilot Access Gateway / FreeIPA host policy / SSH PTY recording / Session Store
> Primary goal: **SSH terminal recording 預設停用，只有明確 opt-in 的目標主機才開啟錄影；
> 一旦主機被標記為錄影，任何連線路徑都不得在預設 production 設定下靜默變成不錄。**

---

## 0. Executive summary

本規格不重做既有的 session recording subsystem。在它上面加一層 **per-host recording policy**：

```text
hosts.yml            ssh_recording: terminal_output
   │  pilot inventory generate
   ▼
inventory.yml        pilot_ssh_recording: "terminal_output"
   │  freeipa-client-apply.yml → tasks/freeipa-host-access-policy.yml
   ▼
FreeIPA host         userClass: pilot.policy.ssh-recording=terminal_output
   │  pilot-access-gateway：每次 POST /v1/connect/authorize 都 fresh host_show
   ▼
effective mode       host override > gateway recording.mode > built-in metadata
   │
   ├─ metadata         → 既有 plain SSH path，不建立 recorder、不回任何 ingest credential
   └─ terminal_output  → 既有 two-phase recorded path + per-session ingest token → pilot-session-store
```

同時修掉 baseline 已存在、會讓這個功能「看起來有做、實際沒效果或一上線就壞」的缺陷（見 §0.4）。

### 0.1 使用者已確認的決策（2026-09-23）

| ID | 決策 | 影響 |
|---|---|---|
| D-A | host 層 `ssh_recording` 這版只開放 `off` / `terminal_output`。`terminal_io` 保留給未來版本 | hosts.yml 寫 `terminal_io` → lint error；FreeIPA 出現 `pilot.policy.ssh-recording=terminal_io` → 視為 unknown → deny connect。gateway 全域 `recording.mode: terminal_io` 維持既有行為不動 |
| D-B | Session Store ingest 改用 **per-session 短效 token**（HMAC 簽章，綁定 session 身分），取代全站共用的靜態 bearer token | 新 package `internal/ingesttoken`；gateway 簽發、store 驗證；vault key 由 `pilot_session_store_ingest_token` 換成 `pilot_session_store_ingest_signing_key` |
| D-C | 原 rev 1 中標為「可選／推薦」的項目全部納入這版：asciicast export、`pilot access recording show`、metrics、store schema 新增 `recording_policy_source` 欄位 | §28–§31 |
| D-D | Phase 0 若判定 FreeIPA rights（GER）不可用（分支 N），以 **canary** 偵測 userclass 是否被 ACI 隱藏：gateway playbook 在 gateway 自己的 host object 寫入 canary，gateway 每個 snapshot 都確認看得到，看不到就 deny 所有連線 | §9、§10、§15.2、§27.1 |
| D-E | `pilot access recording show` 由 **gateway host 上的 root** 執行：讀 gateway config、用 gateway keytab 直接查 FreeIPA、沿用同一個 resolver | §29 |
| D-F | Session Store schema v1→v2 migration 前**自動備份**（`VACUUM INTO`，先檢查剩餘空間）；回滾 = 還原備份 + 換回舊 binary | §21.3 |

### 0.2 Coding agent 的技術決策（非使用者確認；review 時可推翻）

1. hosts.yml 的非字串值（YAML bool/int）不在 `Parse()` 報錯，而是比照 `DeploymentAvailability` 由 `Lint()` 報 error。`Generate` 遇到 lint error 會拒絕輸出，所以效果仍是 fail closed，但不會讓 `pilot edit` 整個打不開。
2. structured action 沿用既有的 `set_host_field`（新增 `field=ssh_recording`），不新增 `set_ssh_recording`。
3. Gateway 的 Ansible 變數沿用 2026-09-16 設計 spec §34 已命名、但尚未實作的 `pilot_session_recording_*` / `pilot_session_store_*`。
4. Metrics 依 repo 既有慣例寫 node_exporter textfile collector（比照 `internal/detection/metrics.go`），不引入 `client_golang`，也不新增 TCP listener。
5. `failure_grace`（持續失敗多久才 fail closed）從 `flush_interval` 拆出來成為獨立設定。baseline 把 `flush_interval` 同時當 grace 用，這正是 idle session 被誤殺的原因之一。
6. `fail_closed` 下 recorder 改用 backpressure（佇列滿時暫停 relay，不丟 event）；`best_effort` 維持丟棄 + `recording_gap`。
7. 互動式 Portal 與 Directory handoff 兩條連線路徑抽出共用的連線核心，行為（authorize、錄影、audit）完全一致。
8. `session_started` audit kind 不新增發送點（baseline 從未發送；生命週期以 `target_connect_started` → `recording_started` → `session_ended` 表達）。
9. policy 相關 struct 的 zero value 一律 **fail closed**（`Valid=false`／`Known=false` → deny）。寧可讓漏掉的解析路徑在測試中立刻失敗，也不要讓它靜默變成「不錄」。因此既有 fake provider 必須改為明確回傳「absent 且 valid」（§10、§34）。
10. `pilot-session-store` 的 site order 從 55 移到 51（freeipa-client 50 之後、gateway 52 之前），讓全站部署自然符合「先 store、後 gateway」的升級順序。
11. 新 task file 以 `ansible.builtin.command` + `stdin:` 執行 kinit，不使用 `ansible.builtin.shell`。
12. 本文件位於 `docs/superpowers/specs/2026-09-23-pilot-access-gateway-per-host-session-recording-spec.md`。程式碼註解引用時寫 `per-host recording spec §N`，不要只寫 `spec.md §N`（repo 內已有多處 `spec.md` 引用指向其他文件）。
13. Phase 1–7 各自可 merge（測試綠燈）；但在 Phase 8 完成前，不得把此功能部署到 staging／prod，也不得對外宣稱可用。

### 0.3 假設、風險與 destructive boundary

**假設**
- Gateway 與 `pilot` binary 由同一支 gateway playbook 同版部署，所以 `ConnectAuthorizeRequest` 新增欄位不需版本協商。
- Session Store 與 Gateway 必須同版升級，順序為先 store、後 gateway（§0.2 第 10 點調整 site order 後，全站部署自然符合）。混版期間（token 格式與 finish body 都已改變）recorded 連線會失敗並 fail closed；metadata 連線不受影響。
- baseline 沒有任何 playbook 部署的 gateway 啟用過 terminal recording（Step 11 每次 apply 都整份覆寫 `access-gateway.yaml`，其中沒有 `recording:` 區塊）。因此移除 FileSink fallback、改掉 ingest token 格式都不會影響既有的正式錄影。
- FreeIPA 預設 ACI 允許已認證 principal 讀 host 的 `userclass`；baseline 的 annotations 已在 gateway 上實際讀到過（`docs/evidence/pilot-access-gateway/2026-09-16-host-annotations-in-portal.md`）。

**已接受的風險（rev 1 決策，保留）**
- connect 時 target 的 host_show 失敗就 deny，**連沒有錄影需求的主機也一樣**（無法得知是否應錄影）。暫時性 FreeIPA 讀取失敗會讓連線被拒。
- recorder 跑在使用者自己 uid 的 process 內。per-session token 能防止跨 session 偽造，但使用者仍可能竄改**自己這個 session** 的錄影內容（例如 ForceCommand 被停用、或逃出 portal 時）。這是架構限制，本版不處理。
- 所有 gateway 共用同一把 signing key：一台 gateway 被攻破，就能替任何 gateway 簽 token。
- `recording.max_session_duration`（預設 24h）到期後 token 失效；在 `fail_closed` 下 recorded session 會被終止。
- signing key 輪替期間仍在進行的 recorded session 會被 store 拒絕（§16.2）。
- replay 與 export 的區分由呼叫端宣告（`purpose=`）。auditor 可以用 replay 取得資料後自行轉檔，store 只會留下 `recording_replayed`。保證的是「每次讀取 payload 都留 audit」，而不是「export 無法繞過」。
- 分支 N 的 canary 只能偵測全站性的 ACI 設定錯誤；只針對個別 host 隱藏 userclass 的 ACI 偵測不到。

**Destructive boundary（這版會刪除或覆寫的東西）**
- Gateway：刪除手動佈署殘留的 `/etc/pilot/session-store-ingest-token`（Phase 8 evidence 手動串接時留下的舊 bearer token）。
- Session Store：刪除 `/etc/pilot/session-store-ingest.token`；`ingest.token_file` 設定欄位移除（config loader 為 `KnownFields(true)`，舊 config 會被拒，必須由 playbook 重新產生）。
- Session Store index DB：schema v1 → v2 migration（只 `ALTER TABLE ADD COLUMN`，不刪資料）。
- FreeIPA host `userClass`：只新增／刪除符合 `pilot.policy.ssh-recording=` 的值；其他值一律不動。
- `cmd/pilot/cmd` 的 local FileSink 錄影路徑與 `defaultRecordingPath` 移除。

### 0.4 Baseline 已核對的事實（c0890f6）

本規格依賴或修正的現況，全部以程式碼行號為準：

| # | 事實 | 位置 |
|---|---|---|
| F1 | 互動式 Portal 的 Connect **完全不看 `RecordingMode`**，authorize 後直接跑 plain ssh，也不發 audit event | `cmd/pilot/cmd/portal_ssh.go:116-134` |
| F2 | Directory handoff 的 one-shot path 會依 `RecordingMode` 分流 plain／recorded | `cmd/pilot/cmd/portal_session_connect.go:151-195` |
| F3 | recorded path 先做 Phase A 認證、啟動 Phase B PTY child，**之後**才呼叫 `NewHTTPSink`（store `/v1/sessions/start`） | `portal_session_connect.go:241-273` |
| F4 | `session_store_url` 空白時退回 local FileSink（未加密、使用者自己擁有的檔案） | `portal_session_connect.go:177-179, 274-281` |
| F5 | Gateway playbook Step 11 整份覆寫 `/etc/pilot/access-gateway.yaml`，其中沒有 `recording:`；contract 也沒有 recording groupVars | `playbooks/apply/pilot-access-gateway-apply.yml:741-765`、`contracts/pilot-access-gateway.yaml` |
| F6 | authorize 成功時一律回傳 store URL/CA/ingest token，包含 metadata mode | `internal/gatewayapi/routes.go:115-123` |
| F7 | `fail_closed` 以「距離上次成功寫入」判斷持續失敗，並把 `flush_interval`（預設 500ms）當 grace。**健康但 500ms 無終端流量的 session 會被砍** | `internal/sessionrecording/recorder.go:305-341`、`cmd/pilot-access-gateway/config.go:107` |
| F8 | `runWriter` 以 defer 呼叫 `sink.Close()`，而 HTTPSink `Close()` 固定送 `complete: true`，fail closed 後也一樣 | `recorder.go:307`、`httpsink.go:136-142` |
| F9 | HTTPSink 一個 event 送一個 request，完全沒有 retry | `httpsink.go:123-125, 144-166` |
| F10 | finish 不帶 last seq，store 無法偵測尾端遺失 | `internal/sessionstore/store.go:197-221`（`FinishSession`）、`:379-403`（replay 的 completeness 與 `detectGaps`） |
| F11 | `best_effort` 下 sink 寫入失敗不發 `recording_gap`（只有佇列滿才發） | `recorder.go:269-286, 318-326` |
| F12 | resize 只在 SIGWINCH 時記錄；`pty.Start` 沒有設定大小 | `recorder.go:176-201`、`portal_ssh_recording.go:117` |
| F13 | ssh client 整個 session 都在 raw mode，`terminal_io` 的 input 幾乎全部被 redact 成 byte count | `internal/sessionrecording/redaction.go:12-52` |
| F14 | Gateway `host_show` 走 JSON-RPC（`all: true`），`parseHost` 只保留 `pilot.annotation.` 開頭的 userClass，其餘丟棄；比對**分大小寫** | `internal/freeipaaccess/kerberos.go:312-321`、`normalize.go:13-38, 177-182` |
| F15 | `hostAnnotationCache` 是 per-snapshot，但 host_show 錯誤被當成「沒有 annotation」；鎖在網路呼叫期間一直持有 | `internal/accessportal/policysnapshot.go:44-71` |
| F16 | FreeIPA annotations reconciler 在 client host 上以 `kinit admin` + `-e xmlrpc_uri=https://{{ freeipa_admin_server_fqdn }}/ipa/xml` 執行；prefix 比對不分大小寫；非 `pilot.annotation.` 的值一律視為 foreign 保留 | `playbooks/apply/tasks/freeipa-host-annotations.yml` |
| F17 | `include_tasks` 的 tags 不會傳進被 include 的 task；annotations include 沒有 `apply:`，直接用 `--tags` 跑這支 playbook 時會靜默跳過 | `playbooks/apply/freeipa-client-apply.yml:915-917` |
| F18 | `pilot verify` probe 沒有 Kerberos ticket，跑不了 `ipa host-show`；因此 annotations 刻意沒有 freeipa-client verification row | `docs/verification/freeipa-client.md` |
| F19 | repo 內沒有任何真實擷取的 `ipa host-show --all --raw` fixture；`internal/freeipaaccess/testdata/host_show.json` 沒有 userclass | — |
| F20 | Session Store ingest 使用單一靜態 bearer token；不比對 path 與 body 的 `session_id`；finish 後仍收 events | `cmd/pilot-session-store/ingest_api.go:40-56, 123-153` |
| F21 | store schema 只有 `PRAGMA user_version` gate（`SchemaVersion = 1`），沒有 migration step；`internal/store/sqlite.go` 有 `migrateSteps` 範本 | `internal/sessionstore/schema.go:28-115` |
| F22 | 讀取／replay 不留任何 audit；沒有 export 指令 | `cmd/pilot-session-store/read_api.go:137-230` |
| F23 | repo 沒有 `client_golang`；既有服務以 node_exporter textfile 輸出 metrics（`/var/lib/node_exporter/textfile`） | `internal/detection/metrics.go:148-175`、`playbooks/apply/host-monitoring-apply.yml:69-74` |
| F24 | gateway 與 store 的 systemd unit 都是 `ProtectSystem=strict` | gateway playbook `:958-966`、store playbook `:492-509` |
| F25 | seq 在 enqueue 前就配號（從 1 起），佇列滿被丟棄的 event 會在 store 端形成 seq gap | `recorder.go:257-267`、`store.go:387-403` |
| F26 | `set_host_field` 的 field 白名單與 enum 驗證在 `validateSetHostField`；driver 以 ScreenID 操作 TUI | `cmd/pilot/cmd/edit_actions_registry.go:55-70, 2176-2210`、`edit_automation_driver.go:207-216` |
| F27 | verification 最後一列：`pilot-access-gateway.md` 為 AG40、`pilot-session-store.md` 為 SS18、`pilot-access-directory.md` 為 AD30、`freeipa-client.md` 為 C12 | — |
| F28 | recorder 的 input relay 對 outer stdin 做 blocking read，`Run` 回傳後該 goroutine 可能仍在讀；one-shot process 會結束所以無害，但互動 TUI 會繼續執行 | `recorder.go:117-154` |
| F29 | `Config.recordingMode()` 在未設定時直接替換成 `metadata`，resolver 無法分辨 built-in default 與明確設定 | `cmd/pilot-access-gateway/config.go:177-182` |
| F30 | site order：gateway 52、directory 53、session store 55（store 在 gateway 之後） | `contracts/*.yaml` `site:`、`playbooks/site.yml:141-156` |
| F31 | gateway socket 為 `0660`、group = portal user group；portal group 成員被 sshd `Match Group … ForceCommand` 鎖在 `pilot-session`，無法執行任意 CLI | gateway playbook `:925-938, 1068-1082` |
| F32 | `internal/spec/pilot_access_gateway_regression_test.go:19` 鎖住完整的 AG ID 清單；`cmd/pilot/cmd/tag_coverage_test.go:148-180` 有 gateway／directory／store 的 row 豁免表（SS03 的理由提到 bearer token） | — |
| F33 | 既有 fake provider 回傳 `freeipaaccess.Host{FQDN: fqdn}`（無 policy 欄位） | `cmd/pilot/cmd/portal_client_test.go:38`、`internal/gatewayapi/server_test.go:41`、`internal/directoryapi/server_test.go:43`、`internal/accessportal`／`internal/accessdirectory` 的 fake |

---

## 1. Goals

- **G1 — Default off**：沒有 host 設定、也沒有 gateway 設定時，effective mode = `metadata`。不建立 recorder、terminal event queue、HTTPS sink 或任何 local recording file，也不回傳任何 ingest credential。
- **G2 — Per-host opt-in**：只有 `ssh_recording: terminal_output` 的主機，其 SSH session 走 recorded path。
- **G3 — Stateless Gateway**：Gateway 不讀 hosts.yml／inventory／roster，也不保存 host policy。policy 只來自 FreeIPA host object。
- **G4 — Fresh decision**：每次 `POST /v1/connect/authorize` 都依當次 FreeIPA 讀取結果決定 effective mode。不得使用 Portal 列表時的 cache，也不接受 client 或 Directory 傳入 mode；`session_id` 不是 policy proof。
- **G5 — Authentication stays unrecorded**：維持 two-phase flow（Phase A 不錄影認證 + ControlMaster；Phase B 經 ControlMaster attach PTY 後才開始錄）。
- **G6 — Durable recording only**：production 錄影只寫 `pilot-session-store`。不存在 local file fallback。
- **G7 — Transparency**：effective mode 非 `metadata` 時，SSH 啟動前在使用者 terminal 顯示錄影提示；Portal 與 Directory 列表顯示錄影標記。
- **G8 — No bypass**：互動式 Portal Connect 與 Directory handoff 使用同一套連線核心；任何路徑都遵守 effective mode。
- **G9 — Recorded never silently unrecorded**：預設 `failure_policy: fail_closed` 下，錄影後端無法持續寫入時終止 session；已知有遺失的錄影一律 `complete=false`。

## 2. Non-goals

1. host 層 `terminal_io`（D-A，延後）與 input 側 password prompt redaction heuristic。
2. target 端 eBPF / auditd 指令重建；影片或截圖錄影；指令語意解析；terminal 內容搜尋。
3. per-user、per-HBAC-rule、hostgroup 繼承的錄影 policy；policy expression language。
4. FreeIPA custom LDAP schema；FreeIPA → hosts.yml 反向同步。
5. 即時觀看、session takeover。
6. 每台 gateway 各自一把 signing key、自動 key rotation（本版只提供手動輪替程序）。
7. 把 `directory_id` 綁進錄影 metadata（Gateway 目前拿不到可信的 directory id；欄位維持空字串）。
8. Directory 列表顯示 **effective** mode（Directory 不知道各 gateway 的 default；只顯示 host override，見 §24.2）。
9. 讓 recorder 從使用者 process 移到 gateway daemon。

---

## 3. Host schema（hosts.yml）

新增 reserved host field：

```yaml
ssh_recording: off | terminal_output
```

- 省略 = inherit gateway default。
- `off` = 明確不錄 PTY（可 override 非 metadata 的 gateway default）。
- `terminal_output` = 錄 terminal output + resize。
- `terminal_io` → lint error：`host "db-01": ssh_recording "terminal_io" is reserved for a future release (typed input cannot yet be redacted reliably); use terminal_output or off`。
- 其他任何值（含 YAML bool/int：`true`、`false`、`yes`、`1`、`output`、`enabled`…）→ lint error：
  `host "db-01": unknown ssh_recording "output" (must be off|terminal_output, or omitted; quote the value if YAML parsed it as a boolean or number)`。

`ssh_recording` 不得進 `Host.Extra`，也不得寫在 `annotations:` 底下（annotations 維持 descriptive-only，`inventory.go:38-43` 的語意不變）。`annotations.ssh_recording` 是一般 annotation key，**不具任何 policy 效果**，也不會被自動搬移成 policy（由 §34.1 的 `TestParse_AnnotationSSHRecordingHasNoPolicyEffect` 與 §34.3 的 `_NotInAnnotations` 鎖住）。

## 4. Policy precedence

```text
1. valid host override
2. gateway recording.mode
3. built-in default metadata
```

| FreeIPA host marker | Gateway `recording.mode` | Effective | policy source |
|---|---|---|---|
| absent | absent | `metadata` | `built_in_default` |
| absent | `metadata` | `metadata` | `gateway_default` |
| absent | `terminal_output` | `terminal_output` | `gateway_default` |
| absent | `terminal_io` | `terminal_io` | `gateway_default` |
| `off` | any | `metadata` | `host` |
| `terminal_output` | any | `terminal_output` | `host` |
| `terminal_io`（D-A 保留值） | any | **deny** `recording_policy_invalid` | — |
| malformed／duplicate／unknown | any | **deny** `recording_policy_invalid` | — |
| host_show 失敗、userclass 不可讀（分支 R）、或 canary 看不到（分支 N），見 §9、§10 | any | **deny** `recording_policy_unavailable` | — |

repo 內 gateway 的 built-in default 維持 `metadata`，本規格不得改變。

---

## 5. Inventory Go model（`internal/inventory`）

```go
// SSHRecording is a host's per-host SSH terminal recording policy
// (per-host recording spec §3). The zero value means "inherit the gateway default",
// which is NOT the same as SSHRecordingOff.
type SSHRecording string

const (
    SSHRecordingOff            SSHRecording = "off"
    SSHRecordingTerminalOutput SSHRecording = "terminal_output"
)

func (r SSHRecording) Valid() bool // "" | off | terminal_output
```

- `Host` 新增 `SSHRecording SSHRecording`。
- `Parse()` 的 switch 新增 `case "ssh_recording":`，比照 `deployment_availability`：string 原樣保存，非 string 以 `fmt.Sprint(v)` 保存（之後由 Lint 拒絕），**不得落入 `Extra`**。
- `Lint()` 驗證 `Valid()`，錯誤訊息如 §3（`terminal_io` 用專屬訊息）。
- `Render()`（`internal/inventory/render.go`）在 `SSHRecording != ""` 時輸出 `ssh_recording: <value>`，位置在 `deployment_availability` 之後、`annotations` 之前。
- `Generate()`（`inventory.go:363-398`）在 `SSHRecording != ""` 時輸出 `pilot_ssh_recording: "<value>"`（一律經 `quoteScalar`，避免 Ansible 以 YAML 1.1 把 `off` 解析成 false），位置在 `deployment_availability` 之後。
- Lint 新增 collision 檢查：`Extra` 中出現 `pilot_ssh_recording` 或 `pilot_annotations`（兩者都由 `Generate` 產生）→ lint error，避免同一 host var 被輸出兩次。
- 以下只複製部分欄位的函式，逐一確認是否需要帶上新欄位，並在測試中鎖住決定：
  - `ExpandSameHostsRoles`：整個 struct 複製，自然帶上。
  - `internal/decommission/planner.go:389` `canonicalInventoryHash`：**要**納入（它影響 FreeIPA 狀態），但欄位必須是 `SSHRecording string \`json:",omitempty"\``，讓沒有設定的 host hash 不變，既有的 pending decommission plan 不會因升級而失效。
  - `internal/outbound` `ProjectedHost`：不需要。
  - MCP `buildInspectHosts`：不需要，比照 annotations。

## 6. Generated inventory contract

```yaml
all:
  hosts:
    db-prod-01:
      ansible_host: "10.0.0.31"
      pilot_ssh_recording: "terminal_output"
    no-record-01:
      ansible_host: "10.0.0.51"
      pilot_ssh_recording: "off"
    web-01:
      ansible_host: "10.0.0.21"   # 省略 = 不輸出 pilot_ssh_recording
```

`pilot_ssh_recording` 與 `pilot_annotations` 一樣以 inventory host var 傳入，不列入 `contracts/freeipa-client.yaml` groupVars。

---

## 7. FreeIPA representation

- 屬性：host `userClass`。managed value 格式：`pilot.policy.ssh-recording=<mode>`，`<mode>` ∈ {`off`, `terminal_output`}。
- inherit = FreeIPA 上不存在任何 managed value。
- **Managed 判定**：userClass 值以 case-insensitive 比對 prefix `pilot.policy.ssh-recording=`，符合者即為 managed（LDAP 的 userClass equality 不分大小寫；兩端必須一致，否則一端當 foreign、另一端當 policy，會造成 fail-open）。
- **合法 managed value**：prefix 的大小寫必須完全是 `pilot.policy.ssh-recording=`，值必須完全等於 `off` 或 `terminal_output`。
- 分類：
  - 0 個 managed value → absent（合法）。
  - 恰好 1 個且合法 → valid。
  - ≥2 個 managed value → `CONFLICT_DUPLICATE_SSH_RECORDING_POLICY`。
  - prefix 大小寫不符、或 `=` 後為空 → `CONFLICT_MALFORMED_SSH_RECORDING_POLICY`。
  - 值不在合法集合（含 `terminal_io`）→ `CONFLICT_UNKNOWN_SSH_RECORDING_POLICY`。
- Pilot 只擁有符合上述 managed 判定的值。`pilot.annotation.*`、`pilot.other-policy.*`、任何外部值都是 foreign，不得刪改。
- 不使用 `pilot.annotation.*`：annotation contract 是「display enrichment，無 deployment／access 語意」，policy 必須有獨立 namespace。

## 8. FreeIPA projection（`playbooks/apply/tasks/freeipa-host-access-policy.yml`，新檔）

### 8.1 Include

在 `playbooks/apply/freeipa-client-apply.yml` 中、annotations include（`:915-917`）**之後**加入：

```yaml
- name: "FreeIPA host access policy — reconcile pilot_ssh_recording to FreeIPA userClass"
  ansible.builtin.include_tasks:
    file: tasks/freeipa-host-access-policy.yml
    apply:
      tags: [freeipa-client, host-access-policy]
  tags: [freeipa-client, host-access-policy]
```

同一 PR 一併修正 F17：annotations include 改成相同的 `file:` + `apply: tags: [freeipa-client, host-annotations]` 形式。

不得把 policy reconcile 塞進 `freeipa-host-annotations.yml`，兩者的 ownership 與 failure semantics 不同。

### 8.2 結構

照 `freeipa-host-annotations.yml` 已實證的 Phase A–F 結構實作。所有 set_fact／register 變數一律使用 `ipa_host_policy_` prefix，不得重用 `ipa_annotations_*`（AGENTS.md §4.0 變數 precedence 教訓）。

1. **Phase A — 驗證 desired（mutation 前）**
   - `pilot_ssh_recording` undefined → desired = absent。
   - 已定義時必須 `is string` 且 ∈ {`off`, `terminal_output`}。否則 fail，並提示「inventory.yml 中未加引號的 `off` 會被 Ansible 解析成 boolean，請重新 `pilot inventory generate` 或加引號」。
2. **Phase B — 讀 live 狀態**
   - 未 enroll（`/etc/ipa/default.conf` 不存在）時：check mode 印 BLOCKED 後跳過；real run 則 fail（沿用 annotations v1.6 的全新主機教訓）。
   - `kinit admin@<REALM>` 以 `ansible.builtin.command`（argv）+ `stdin: "{{ ipa_enroll_password }}"` + `environment: {KRB5CCNAME: "FILE:<tempfile>"}` 執行，`no_log: true`；在 `always:` 中 `kdestroy`。不使用 shell pipe（annotations 的 `printf | kinit` 不照抄）。Phase 2 的 live 執行必須證明 kinit 從 stdin 讀密碼成功（AGENTS.md §5.6）。
   - 以 argv 形式執行 `ipa -e xmlrpc_uri=https://{{ freeipa_admin_server_fqdn }}/ipa/xml host-show <fqdn> --all --raw`，`check_mode: false`，`changed_when: false`。
   - rc≠0 時分兩類：stderr 符合 Phase 0 真實擷取的「not found」訊息 → `HOST_ABSENT`；其他 → `FREEIPA_UNREACHABLE`。兩者 real run 都 fail，check mode 印 BLOCKED。不得像 annotations 那樣把所有 rc≠0 都當成 HOST_ABSENT。
3. **Phase C — 解析**：`regex_findall('(?im)^[ \t]*userclass: (.+)$')` 取出全部值，依 §7 分類成 managed／foreign。
4. **Phase D — 衝突 gate（mutation 前）**：出現 DUPLICATE／MALFORMED／UNKNOWN 時，以對應 code fail，並列出衝突值。**不得自動刪除**未知的 managed value。
5. **Phase E — Mutation**：依 §8.3 矩陣，只使用 `ipa host-mod <fqdn> --delattr=userclass=<exact live value>` 與 `--addattr=userclass=<desired>`（argv 形式）。每個 mutation task 都 `when: ... and not ansible_check_mode`，`changed_when: rc == 0`。**禁止** `--setattr=userclass=`、`ipa host-add`、`ansible.builtin.shell`。
6. **Phase F — post-write verify（只在有 mutation 時）**：重新 host-show 並 assert
   - managed value 集合**恰好**等於 desired（0 或 1 個，大小寫與值完全一致）；
   - foreign 集合與 Phase C 讀到的集合**完全相同**（case-insensitive 比較）；
   - `pilot.annotation.*` 值與 Phase C 完全相同。
7. **Check mode**：讀 live、算出 plan、以 debug 印出 `ipa_host_policy_plan: {add: [...], delete: [...], noop: <bool>}`，零 mutation。

### 8.3 Reconcile matrix

| Desired | Live | Action |
|---|---|---|
| absent | absent | NOOP |
| absent | valid marker | DELETE marker |
| off | absent | ADD `…=off` |
| off | `off` | NOOP |
| off | `terminal_output` | DELETE old → ADD `…=off` |
| terminal_output | absent | ADD |
| terminal_output | `terminal_output` | NOOP |
| terminal_output | `off` | DELETE old → ADD new |
| any | malformed／duplicate／unknown | FAIL（mutation 前） |

第二次 apply 必須 `changed=0`。

---

## 9. Phase 0 — 真實擷取（實作任何 parser 前必做）

依 AGENTS.md §5.6，在 disposable vm-target（FreeIPA server + 一台已 enroll 的 client + gateway）上擷取真實輸出，sanitize 後存成 fixture。只能依這些 fixture 撰寫 parser 與 expected string：

1. `ipa host-show <fqdn> --all --raw` 的 stdout／stderr。userClass equality 不分大小寫，同一 host 無法同時擁有只差大小寫的兩個值，因此在同一台 host 上**依序**建立下列狀態，每個狀態各擷取一次，擷取後還原：
   - (a) 1 個 foreign 值 + 1 個 `pilot.annotation.*` + 1 個合法 marker `pilot.policy.ssh-recording=terminal_output`；
   - (b) 兩個不同值的 marker（`=off` 與 `=terminal_output`）；
   - (c) 只有大小寫變體 `Pilot.Policy.SSH-Recording=terminal_output`。
   → `internal/spec/testdata/freeipa-host-show-raw-userclass-{valid,duplicate,casevariant}.txt`
2. 對不存在 host 的 `host-show` stderr + rc；FreeIPA 443 被擋時的 stderr + rc。
   → `internal/spec/testdata/freeipa-host-show-not-found.txt`、`…-unreachable.txt`
3. 以 gateway service principal（keytab）送 JSON-RPC `host_show`：`{"all": true}` 與 `{"all": true, "rights": true}` 兩種 request 的 response。
   → `internal/freeipaaccess/testdata/host_show_userclass.json`、`host_show_userclass_rights.json`

**GER 分支決策（依第 3 項結果，coding agent 自行判定並寫進 evidence）**
- **分支 R（rights 可用）**：`rights: true` 對 gateway principal 成功，且 `attributelevelrights.userclass` 含 `r`。實作時 gateway 的 host_show 一律帶 `rights: true`；`userclass` 權限不含 `r` → `Known=false`（`recording_policy_unavailable`）。這可偵測「ACI 藏住 userclass 導致 policy 被看成 absent」的 fail-open。
- **分支 N（rights 不可用）**：request 報錯，或回應缺 `userclass` 權限資訊。此時不帶 `rights`，改用 canary（D-D）：
  - gateway playbook 以 admin 在 gateway **自己的** host object 上維持恰好一個 userClass 值 `pilot.policy.userclass-canary=1`（addattr／delattr 規則與 §8 相同；它不是 `pilot.policy.ssh-recording=` managed value，§8 的 reconciler 與 annotations reconciler 都會把它當 foreign 保留）；
  - gateway 每個 policy snapshot 都對自己的 FQDN 做一次 host_show（經 §11.1 cache，同一 snapshot 最多一次），檢查 canary 是否存在；
  - 不存在或 host_show 失敗 → 該 snapshot 內**所有** host 的 `SSHRecording` 一律 `Known=false`（`Reason="canary_missing"`）→ 所有連線 deny `recording_policy_unavailable`；listing 照常列出，但顯示 policy unavailable；
  - 在 `docs/verification/pilot-access-gateway.md` §7 與 runbook 寫明 canary 的用途與限制（只偵測全站性的 ACI 錯誤）。
- 兩個分支都由 live L3 以真實 gateway principal 證明預設 ACI 下讀得到 userclass。
- **只實作被選中的分支**，不提供 runtime 切換或設定開關。Phase 0 evidence 記錄選擇結果；另一分支的條文視為不適用。

Evidence：`docs/evidence/pilot-access-gateway/<date>-phase0-userclass-capture.md`（只寫 sanitized 事實與分支結論）。

---

## 10. FreeIPA read model（`internal/freeipaaccess`）

```go
// HostRecordingPolicy is the parsed pilot.policy.ssh-recording marker
// state of one FreeIPA host (per-host recording spec §7).
type HostRecordingPolicy struct {
    Present    bool   // at least one managed value exists
    Mode       string // "off" | "terminal_output" when Valid && Present
    Valid      bool   // absent, or exactly one well-formed known value
    Unreadable bool   // branch R only: attributelevelrights says userclass is not readable
    Reason     string // "duplicate" | "malformed" | "unknown_value" | "userclass_unreadable"; never raw LDAP data
}

type Host struct {
    FQDN         string
    Annotations  map[string]string
    SSHRecording HostRecordingPolicy
}
```

- `normalize.go` 新增 `const pilotSSHRecordingPolicyPrefix = "pilot.policy.ssh-recording="` 與 `func parseHostSSHRecordingPolicy(userClass []string) HostRecordingPolicy`，規則完全依 §7。
- `parseHost` 對 userclass 的每個值：managed（case-insensitive prefix）→ 交給 policy parser；`pilot.annotation.` → 既有 `parseAnnotations`（不改其邏輯）；其他 → 忽略。policy marker 不得出現在 `Annotations`。
- 分支 R：`kerberos.go` 的 `host_show` params 加 `"rights": true`，並解析 `attributelevelrights.userclass`；不含 `r` 時 `SSHRecording = {Unreadable: true, Valid: false, Reason: "userclass_unreadable"}`。accessportal 把 `Unreadable` 對應成 `Known=false`（→ `recording_policy_unavailable`，與 §4 一致），而不是 invalid。
- 分支 N：`Host` 另外新增 `UserClassCanary bool`，由 `parseHost` 判斷是否存在（case-insensitive）`pilot.policy.userclass-canary=1`。
- `Reason` 只能是上述固定字串。
- **Zero value fail closed**：`HostRecordingPolicy{}` 的 `Valid=false`，會導致 deny。`parseHost` 對沒有 managed value 的 host 必須明確產生 `{Present: false, Valid: true}`。新增 `func NewHostWithoutPolicy(fqdn string) Host` 供測試使用，並把 F33 列出的所有 fake provider 改為使用它（或明確填入 absent-valid policy）。

## 11. AccessPortal（`internal/accessportal`）

### 11.1 hostMetadataCache 取代 hostAnnotationCache

```go
type hostMetadataResult struct {
    Host freeipaaccess.Host
    Err  error
}
```

- 仍然 per-snapshot（在 `LoadPolicySnapshot`／`ResolveScopeAccess` 內建立），**不得**有 package-global cache。
- 每個 FQDN 在同一 snapshot 內只呼叫一次 `HostShow`，成功與失敗都 cache。
- 全域 mutex 只保護 map 本身；網路呼叫在鎖外（per-FQDN entry 以 `sync.Once` 或等價機制避免重複 RPC）。
- 只對「SSH allowed 且在 scope 內」的 host 呼叫（維持 baseline 行為），不新增 O(host) 的額外呼叫。
- 分支 N：`accessportal.GatewayConfig` 新增 `CanaryFQDN string`。gateway 以 config 的 `gateway.fqdn` 填入；Directory 與其他呼叫端留空（不檢查）。`ResolveScopeAccess` 在 `CanaryFQDN` 非空時，經同一個 cache 對它做一次 host_show，並檢查 `freeipaaccess.Host.UserClassCanary`；失敗或不存在 → 覆寫該次結果中每個 HostAccess 的 `SSHRecording` 為 `{Known: false, Reason: "canary_missing"}`。

### 11.2 HostAccess

```go
// SSHRecordingAccessPolicy is one host's recording-policy facts as seen
// by a single fresh policy snapshot (per-host recording spec §11.2).
type SSHRecordingAccessPolicy struct {
    Override string // "" (inherit) | "off" | "terminal_output"; only meaningful when Known && Valid
    Known    bool   // false: host_show failed, userclass unreadable (branch R), or canary missing (branch N)
    Valid    bool   // false: malformed/duplicate/unknown marker (only meaningful when Known)
    Reason   string // "host_show_failed" | "userclass_unreadable" | "canary_missing" | "duplicate" | "malformed" | "unknown_value"
}

type HostAccess struct {
    FQDN         string
    SSH          SSHAccess
    Sudo         SudoAccess
    Annotations  map[string]string
    SSHRecording SSHRecordingAccessPolicy
}
```

Zero value（`Known=false`）fail closed。`ResolveScopeAccess` 必須為每個 HostAccess 明確填入這個欄位。

### 11.3 行為

- **Listing**（`GET /v1/access`、Portal My Hosts、Directory）：某台 host_show 失敗時，該 host 仍然列出（HBAC 解析本身已成功），`Known=false`，annotations 為空。不得讓整份列表失敗。
- **Connect**：target 的 `SSHRecording` 來自同一次 fresh snapshot（不另外呼叫 host_show）。`Known=false` 或 `Valid=false` 時由 §13 的 resolver 回傳 error，gateway deny。

## 12. Directory（`internal/accessdirectory`）

`DirectoryTarget` 新增 `Recording accessportal.SSHRecordingAccessPolicy`（取自 `ResolveScopeAccess` 的 HostAccess）。`internal/directoryapi/types.go` 的 `TargetJSON` 新增 `Recording DirectoryRecordingJSON \`json:"recording"\``，其中 `DirectoryRecordingJSON{Status string}` 的 Status ∈ `inherit|off|terminal_output|unknown|invalid`（不含 effective）。同一 FQDN 出現在多個 scope 時，取任一個 `Known && Valid` 的值；全部都是 `!Known` 則 `Known=false`；只要任何一個是 `Known && !Valid`，就用那個值（invalid 優先）。Directory 只顯示 host override（§24.2），不計算 effective mode。

---

## 13. Gateway effective policy resolver（`internal/gatewayapi/recording_policy.go`，新檔）

```go
var (
    ErrRecordingPolicyUnknown = errors.New("recording policy unavailable")
    ErrRecordingPolicyInvalid = errors.New("recording policy invalid")
)

// ResolveRecordingMode applies per-host recording spec §4's precedence. gatewayDefault is
// the gateway config's recording.mode ("" = unset). It returns the
// effective mode (metadata | terminal_output | terminal_io) and its
// source (host | gateway_default | built_in_default).
func ResolveRecordingMode(gatewayDefault string, host accessportal.SSHRecordingAccessPolicy) (mode, source string, err error)
```

- `!host.Known` → `ErrRecordingPolicyUnknown`；`!host.Valid` → `ErrRecordingPolicyInvalid`。
- `Override == ""`：`gatewayDefault == ""` → (`metadata`, `built_in_default`)；否則 (`gatewayDefault`, `gateway_default`)。
- `Override == "off"` → (`metadata`, `host`)；`"terminal_output"` → (`terminal_output`, `host`)。
- 其他 `Override` → `ErrRecordingPolicyInvalid`。
- 純函式，不做 I/O。gateway default 的合法性仍由 config loader 負責。
- 呼叫端必須傳入 config 的**原始值**（未設定時為 `""`），不得傳入 `Config.recordingMode()` 替換過的值（F29）。`RecordingPolicy` 新增 `DefaultMode string`（原始值）；既有的 `Mode` 欄位改名或移除，避免誤用。

## 14. Gateway config（`cmd/pilot-access-gateway/config.go`）

```yaml
gateway:
  recording:
    mode: metadata                     # gateway-wide default；metadata|terminal_output|terminal_io
    failure_policy: fail_closed        # 預設由 best_effort 改為 fail_closed
    queue_events: 1024
    flush_interval: 500ms              # 語意改為：event 在 batch 中等待送出的最長時間
    failure_grace: 10s                 # 新增：持續無法寫入多久才 fail closed
    max_session_duration: 24h          # 新增：per-session token 的 exp；範圍 1h..168h
    session_store_url: https://session-store.pilot.internal:8443
    session_store_ca_file: /etc/ipa/ca.crt
    session_store_ingest_signing_key_file: /etc/pilot/session-store-ingest-signing.key   # 取代 session_store_ingest_token_file
  metrics:
    textfile_path: /var/lib/node_exporter/textfile/pilot_access_gateway.prom           # 空白 = 停用
```

驗證規則（全部在 `LoadConfig` 階段，失敗則 gateway 不啟動）：
- `failure_grace` 必須 ≥ 1s，且 ≥ 2 × `flush_interval`。`max_session_duration` 必須在 1h..168h。
- `session_store_url` 非空時：必須是 `https://`，且 `session_store_ingest_signing_key_file` 必填。key 檔必須是 64 個 hex 字元（32 bytes），不得 group/world 可存取（比照 store 的 `loadIngestToken` 檢查）。
- `mode` 為 `terminal_output`／`terminal_io` 時 `session_store_url` 必填（gateway-wide 錄影沒有後端，視為設定錯誤）。
- 舊欄位 `session_store_ingest_token_file` 因 `KnownFields(true)` 會被拒；錯誤訊息需指引改用 `session_store_ingest_signing_key_file`。
- `RecordingPolicy`（`internal/gatewayapi/server.go:64-73`）改為保存 signer（`*ingesttoken.Signer`），不再保存 raw token 字串。signing key 只在記憶體中，不得寫 log。

## 15. ConnectAuthorize（`internal/gatewayapi`）

### 15.1 Request / Response

```go
type ConnectAuthorizeRequest struct {
    Target    string `json:"target"`
    // SessionID is bound into the per-session ingest token when the
    // effective mode records. It never influences the HBAC/scope decision.
    SessionID string `json:"session_id,omitempty"`
}

type ConnectAuthorizeResponse struct {
    // existing fields…
    DenyReason            string `json:"deny_reason,omitempty"`             // 只用於 recording 相關 deny
    RecordingPolicySource string `json:"recording_policy_source,omitempty"` // host|gateway_default|built_in_default
    RecordingFailureGraceMS int64 `json:"recording_failure_grace_ms,omitempty"`
    // RecordingSessionStoreIngestToken 保留欄位名，內容改為 §16 的 PIT1 per-session token
}
```

### 15.2 處理順序

1. fresh `LoadUserAccess`（baseline 已如此）。
2. 找 target、確認 SSH allowed（HBAC／scope deny 行為與 baseline 相同，`DenyReason` 留空）。
3. （分支 N）同一 snapshot 的 canary 檢查失敗時，所有 target 的 `SSHRecording.Known` 已是 false（§9），會在下一步 deny。
4. 以 target 的 `SSHRecording` 呼叫 `ResolveRecordingMode`：
   - `ErrRecordingPolicyUnknown` → deny `recording_policy_unavailable`；
   - `ErrRecordingPolicyInvalid` → deny `recording_policy_invalid`。
5. effective mode 為 terminal 時：
   - 沒有設定 session store → deny `recording_backend_unavailable`；
   - `SessionID` 不是合法 UUID → deny `recording_session_id_invalid`；
   - 否則簽發 PIT1 token（§16）。
6. 以上全部通過才 `Allowed = true`。**不得**先設 `Allowed = true` 再發現 policy 問題。
7. 回應：
   - `metadata`：`RecordingMode = "metadata"` + `RecordingPolicySource`；**不得**帶 store URL／CA／token／queue／flush／grace。
   - terminal：帶齊 mode、source、failure_policy、queue、flush、grace、store URL、CA file、token。

### 15.3 Log

每個 recording 相關 deny 以 `slog.Info("connect authorize denied", "user", …, "target", …, "gateway_id", …, "reason_code", …)` 記錄。不得 log token、signing key 或 host_show 原始內容。

## 16. Per-session ingest token（`internal/ingesttoken`，新 package，D-B）

### 16.1 格式（PIT1）

```text
pit1.<base64url-nopad(claims JSON)>.<base64url-nopad(HMAC-SHA256(key, "pit1." + base64url(claims)))>
```

```json
{
  "sid": "0b6f…-uuid",
  "usr": "alice",
  "gw": "gpu-01",
  "scp": "gpu",
  "tgt": "db-prod-01.ipa.pilot.internal",
  "mode": "terminal_output",
  "src": "host",
  "iat": 1790000000,
  "sby": 1790000900,
  "exp": 1790086400,
  "jti": "9f3c1a…(32 hex)",
  "kid": "a1b2c3d4e5f60718"
}
```

- `sby`（start-by）= `iat + 900s`（涵蓋 authorize 之後使用者輸入 Kerberos 密碼的時間，見 §18.3）；`exp` = `iat + max_session_duration`。
- `jti` = 每次簽發隨機產生的 128-bit 值（hex）。store 在 start 時記下，之後的 events／finish 必須帶同一個 `jti`（§21.2）。
- `kid` = `hex(SHA-256("pilot-ingest-kid-v1" || key))[:16]`，只用來診斷 key 不一致，不是機密。
- API：
  - `NewSigner(key []byte, now func() time.Time)`、`(*Signer).Mint(Claims) (string, error)`；
  - `NewVerifier(key []byte, now func() time.Time)`、`(*Verifier).Verify(token string) (Claims, error)`：檢查格式、kid、簽章、claims、`iat` 與 `exp`，**不檢查 `sby`**。錯誤 reason：`malformed`、`unknown_key`、`bad_signature`、`not_yet_valid`、`expired`、`invalid_claims`；
  - `(*Verifier).CheckStartWindow(Claims) error`：只由 store 的 start handler 呼叫，`now > sby + skew` → `start_window_closed`。
  - events／finish **不得**檢查 `sby`，否則超過 start window（15 分鐘）的 session 會全部失敗。
- 驗章一律使用 `hmac.Equal`；claims 以 strict JSON decode（`DisallowUnknownFields`）；`mode` 只能是 `terminal_output`／`terminal_io`；`sid` 必須是 UUID；`jti` 必須存在且為 32 個小寫 hex 字元；`exp > iat` 且 `exp - iat ≤ 168h`；允許時鐘偏差 60s。任一不符 → `invalid_claims`。
- token 與 key 不得出現在 log、error message、audit event、metrics 或 evidence。

### 16.2 Key 管理

- vault key：`pilot_session_store_ingest_signing_key`（`openssl rand -hex 32`）。gateway 與 store 使用同一個值。
- Gateway 檔案：`/etc/pilot/session-store-ingest-signing.key`，`pilot-gateway:pilot-gateway 0400`。
- Store 檔案：`/etc/pilot/session-store-ingest-signing.key`，`{{ pilot_session_store_user }}` 0400。
- 輪替（手動，寫進 runbook）：更新 vault → 先 apply session store、再 apply 全部 gateway。輪替期間仍在進行的 recorded session 會因 `unknown_key` 被 store 拒絕：`fail_closed` 下被終止，`best_effort` 下標記 incomplete。

## 17. Access list JSON（`GET /v1/access`）

```go
type RecordingJSON struct {
    Status    string `json:"status"`              // inherit|off|terminal_output|unknown|invalid
    Effective string `json:"effective,omitempty"` // metadata|terminal_output|terminal_io；unknown/invalid 時為空
}

type HostJSON struct {
    // existing…
    Recording RecordingJSON `json:"recording"`
}

type AccessResponse struct {
    // existing…
    RecordingDefault string `json:"recording_default"` // 這台 gateway 的 effective default（未設定時為 metadata）
}
```

`Effective` 由 server 以 `ResolveRecordingMode` 算出，Portal 不得自行重算。列表不會回傳任何 store URL 或 token。

---

## 18. 連線核心：互動 Portal 與 Directory handoff 共用（`cmd/pilot/cmd`）

### 18.1 共用函式

從 `runPortalOneShotConnect` 抽出：

```go
// portalSessionDeps bundles the injectable dependencies shared by both
// connect paths (per-host recording spec §18.1).
type portalSessionDeps struct {
    Client        *portalClient
    Credentials   portalCredentialSession
    Emitter       *sessionaudit.Emitter
    SSHConfigPath string
    Stdin         io.Reader // recorded path's outer input; see §18.1 cancelable stdin
    Stdout        io.Writer // recorded path's outer output
    Notice        io.Writer // pre-connect notice and user-facing errors (stderr)
}

// runPortalTargetSession runs one fully authorized target session for both
// the interactive Portal Connect action and the Directory handoff
// one-shot path (per-host recording spec §18). It re-authorizes fresh,
// then takes the plain or recorded path strictly from the authorize response.
func runPortalTargetSession(ctx context.Context, deps portalSessionDeps, sessionID, target string) error
```

- 既有的 package var `recordingStdin`／`recordingStdout` 改由 `portalSessionDeps` 注入。
- `runPortalOneShotConnect` 改成呼叫它（行為與 AG35–AG40 的既有保證相同）。
- `connectToHost`（`portal_ssh.go:116-134`）改成：以 `uuid.NewString()` 產生 session id、以 `sessionaudit.NewEmitter("pilot-access-gateway")` 建立 emitter，然後呼叫同一個函式。error 仍轉成既有的 confirm prompt，不結束 TUI。
- **Cancelable stdin（F28）**：`enterRawMode`／`watchResize` 目前靠把 input／output type-assert 成 `*os.File` 才能設定 raw mode 與取得大小（`recorder.go:155-201`）。包裝過的 reader 會讓 raw mode 失效（雙重 echo、行緩衝、Ctrl-C 送到 pilot），因此：
  - recorder `Options` 新增 `Terminal *os.File`：專門用來設定 raw mode、讀取大小、監看 SIGWINCH，與讀取用的 input reader 分開。`Terminal == nil` 時維持 baseline 的 type-assert 行為。
  - recorder 新增 `func (r *Recorder) InputDone() <-chan struct{}`：input relay goroutine 結束時 close。
  - 互動路徑：`Terminal = os.Stdin`，`Stdin` 為 `github.com/muesli/cancelreader`（已在 go.sum，改為 direct dependency）包裝的 `os.Stdin`。`Run` 返回後，呼叫端先 `Cancel()`，再等 `InputDone()`（上限 1s），才回到下一個 TUI prompt。不得遺留仍在讀 stdin 的 goroutine（否則下一個 Bubble Tea program 會漏掉按鍵）。
  - one-shot 路徑：`Terminal = os.Stdin`，`Stdin = os.Stdin`（process 隨即結束，沿用 baseline）。
- 兩條路徑都在 `ConnectAuthorize` request 中帶 `session_id`。
- `DenyReason` 不為空時，顯示／回報對使用者有意義的訊息：
  - `recording_policy_unavailable`：`Connection not started: this host's recording policy could not be verified.`
  - `recording_policy_invalid`：`Connection not started: this host's recording policy is misconfigured. Contact an administrator.`
  - `recording_backend_unavailable`：`Connection not started: session recording is required for this host but the recording service is not configured.`
  - `recording_session_id_invalid`：`Connection not started: internal session id error.`

### 18.2 metadata

`recordingConfig.enabled() == false` 時仍走 `runPortalOneShotConnectPlain`，保持 baseline 的 plain ssh 行為。

### 18.3 terminal（recorded path 的順序，修正 F3）

1. fresh authorize 成功，effective mode 為 terminal（authorize 在 `credentials.Ensure` **之前**，維持 AG38「被拒時不觸發憑證」的既有保證）。
2. `credentials.Ensure`（可能提示使用者輸入 Kerberos 密碼）。失敗 → 結束，不做後續步驟（尚未 start，不需 Finish）。token 的 start window 為 900s（§16.1），足以涵蓋密碼輸入。
3. 在使用者 terminal（stderr）印出錄影提示（§24.3）。
4. 以 authorize 回傳的 token 建立 HTTPSink，並完成 `POST /v1/sessions/start`。失敗 → 發出 `recording_failed`，**不做 Phase A、不對 target 建立任何 SSH 連線**，以非零結束。若失敗原因是 `start_window_closed`，訊息提示使用者重新連線。
5. Phase A（不錄影認證 + ControlMaster）。
6. Phase B：先以 `term.GetSize(Options.Terminal 的 fd)` 取得大小（`Terminal` 為 nil 或取不到時用 80×24；互動路徑的 input 是 cancelreader，不能拿來取大小），`startRecorded` 改用 `pty.StartWithSize` 以該大小啟動 child，避免與 ssh 第一次回報 window size 競爭（修正 F12）。同一個大小傳入 recorder 的 `Options.InitialSize`。
7. recorder 在啟動任何 relay 之前，先把 `InitialSize` 以 seq=1 的 `resize` event 放進佇列；然後開始 relay，caller 發出 `recording_started`。
8. 結束時依 §19 收尾並 `Finish`。

**start 成功之後的任何失敗**（Phase A、Phase B 啟動、recorder 建立、panic recovery 等），都必須呼叫 `sink.Finish(ctx, FinishInfo{Complete: false, LastSeq: <目前已配出的最後 seq，未配過為 0>, Reason: <Phase A 失敗為 target_connect_failed；Phase B 啟動失敗為 session_start_failed；recorder 建立失敗或 panic recovery 為 internal_error>})`，並發出對應的 audit event。不得留下已 start 卻永遠沒有 finish 的 session。

### 18.4 移除 FileSink fallback（修正 F4）

刪除 `defaultRecordingPath`、`recordingConfig.LocalPath` 與 portal path 中建立 FileSink 的分支。terminal mode 但 authorize 回應缺 store URL 或 token 時（正常情況下 gateway 已 deny）→ `recording_failed`，不連 target。若 `sessionrecording.FileSink` 在 production code 已無 caller，連同其 test 一起刪除。

### 18.5 不得存在的 override

不讀 hosts.yml、env、CLI flag、`SSH_ORIGINAL_COMMAND` 來決定 mode。不支援 `--record=false`、`PILOT_RECORD=false` 或任何使用者控制的開關。

## 19. Recorder（`internal/sessionrecording/recorder.go`）

### 19.1 參數

`New` 改為接收 options struct：

```go
type Options struct {
    Mode          string
    SessionID     string
    FailurePolicy string        // best_effort | fail_closed
    QueueEvents   int
    FlushInterval time.Duration // batch 最長等待時間
    FailureGrace  time.Duration // fail_closed 的持續失敗門檻；0 時預設 10s
    InitialSize   Winsize       // {Rows, Cols}；Run 開始時以 seq=1 的 resize event 送出
    Terminal      *os.File      // raw mode／大小／SIGWINCH 用的 outer terminal；nil 時沿用 baseline 的 type-assert（§18.1）
    Identity      AuditIdentity // User, TargetFQDN, GatewayID, GatewayScope：帶進 recorder 發出的每個 audit event
}
```

### 19.2 Pending 與 watchdog（修正 F7）

- `pending`：已配 seq、但尚未被 sink 成功確認的 event 數。enqueue 成功 +1；`WriteBatch` 成功 −n；`best_effort` 丟棄 −n。
- `progressAt`：`pending` 由 0 變 1 時設為 now；每次 `WriteBatch` 成功時設為 now。
- 獨立的 watchdog goroutine（ticker = `FailureGrace/4`，最小 50ms）：`FailurePolicy == fail_closed && pending > 0 && now − progressAt ≥ FailureGrace` → fail closed。
- `pending == 0`（閒置但健康）時**永遠不得**觸發 fail closed。
- watchdog 與 writer 分開執行；sink 呼叫卡住時，watchdog 仍以 wall-clock 判定。

### 19.3 Backpressure 與丟棄

- `fail_closed`：佇列滿時 enqueue **阻塞**（select：佇列送出／fail-closed signal／writer 已停止 signal／ctx.Done），不丟 event。writer 已停止時 enqueue 立即返回並計為 drop，producer 不得永久卡住。relay 因此暫停，由 watchdog 以 `FailureGrace` 為上限。這是對 baseline「relay 永不因錄影停頓」設計的刻意變更，只適用 fail_closed。
- `best_effort`：維持非阻塞；佇列滿就丟棄，標記 incomplete，並發出 rate-limited `recording_gap`（每 2 秒最多一次，沿用 baseline）。
- sink 回傳 **permanent** error（§20.2）：`fail_closed` 立即 fail closed（不等 grace）；`best_effort` 丟棄該 batch、標記 incomplete、發出 `recording_gap`（`result="sink_error"`，修正 F11），之後的 batch 繼續嘗試。

### 19.4 Batching

writer 把 event 累積成 batch，任一條件成立就 `WriteBatch`：128 個 event、編碼後 64 KiB、或最早一筆已等待 `FlushInterval`。

### 19.5 Fail closed 與取消契約

- writer 使用由 `Run` 的 ctx 衍生的 `writerCtx`。以下情況 `Run` 會 cancel 它：fail closed 觸發時、drain 期限到時、`Run` 本身的 ctx 結束時。HTTPSink 的 retry 與進行中的 request 都以 `writerCtx` 為準，因此 cancel 後會立刻中止。
- fail closed：發出 `recording_failed`（含 `Identity`）→ cancel `writerCtx` → 等 writer 結束（上限 `FailureGrace + 5s`）→ `Run` 回傳 `ErrRecordingFailedClosed`。caller kill ssh child，並發出 `session_ended`（`result="recording failed closed"`）。
- 不論 sink 是否卡住，`Run` 都必須在上述上限內返回，不得無限期等待 writer。

### 19.6 收尾與 completeness（修正 F8）

- 正常結束：在 `FailureGrace` 期限內 flush 剩餘 batch；期限到仍未完成 → cancel `writerCtx`，`Reason="drain_timeout"`。
- `Complete = true` 必須同時滿足：沒有丟棄、沒有 sink error、沒有 fail closed、drain 在期限內完成、正常結束。任一條件不成立即為 `false`。
- 呼叫 `sink.Finish(ctx, FinishInfo{Complete, LastSeq, Reason})`（獨立 5s timeout）。`LastSeq` = recorder 配出的最後一個 seq（含被丟棄的）。Finish 失敗 → 發出 `recording_failed`（session 已結束，不影響 exit code）。`Reason` 只寫進 client 端 audit，不送到 store。
- 不得在 defer 中無條件以 `complete=true` 收尾。

### 19.7 Sink interface

```go
type FinishInfo struct {
    Complete bool
    LastSeq  uint64
    Reason   string // "" | fail_closed | dropped | sink_error | drain_timeout | target_connect_failed | session_start_failed | internal_error
}

type Sink interface {
    WriteBatch(ctx context.Context, events []TerminalEvent) error
    Finish(ctx context.Context, info FinishInfo) error
}
```

`NullSink` 與測試用的 memSink 同步改寫。

## 20. HTTPSink（`internal/sessionrecording/httpsink.go`）

### 20.1 Requests

- `NewHTTPSink` 保持「建構時即送出 start」。token 以 `Authorization: Bearer <PIT1>` 送出。
- start body 的 `directory_id` 一律為空（Non-goal 7）。
- `WriteBatch` → `POST /v1/sessions/{id}/events` `{"events": [...]}`（ingest schema 不變）。
- `Finish` → `POST /v1/sessions/{id}/finish` `{"ended_at": "...", "complete": <bool>, "last_seq": <n>}`。store 端 `ended_at` 與 `last_seq` 皆為必填：`ended_at` 必須是 RFC3339Nano，缺少或無法解析 → 400（不再像 baseline `ingest_api.go:167-172` 那樣以 now() 代替）；`last_seq` 必須 ≥ 已儲存的最大 seq，否則 400；沒有任何 event 時允許 0。

### 20.2 Retry

- **Transient**（連線錯誤、timeout、HTTP 408/429/5xx）：以 100ms 起、倍增、上限 2s 的 backoff 重送**同一個 batch**（同樣的 seq 與 payload，依賴 store 的 idempotency），直到成功或 ctx 被取消。
- **Permanent**（其他 4xx，含 401/403/409/400）：回傳 wrap 了 `ErrSinkPermanent` 的 error。
- **start 與 finish** 使用同一套 transient retry，但總時間上限 5s。start 在上限內沒有成功 → `NewHTTPSink` 回傳 error（caller 不做 Phase A）。finish 在上限內沒有成功 → 回傳 error（caller 發出 `recording_failed`）。
- finish 的 `ended_at` 只在第一次嘗試前算一次，retry 時重送完全相同的 body，讓 store 能判定為 idempotent。
- 每個 request timeout 5s。error message 不得包含 token 或 response body 中的敏感資料（response body 截斷 4096 bytes 的既有行為保留，但 store 端保證不回傳 token）。

---

## 21. Session Store（`cmd/pilot-session-store`、`internal/sessionstore`）

### 21.1 Config

```yaml
ingest:
  listen_addr: ...
  tls_cert_file: ...
  tls_key_file: ...
  signing_key_file: /etc/pilot/session-store-ingest-signing.key   # 取代 token_file
metrics:
  textfile_path: /var/lib/node_exporter/textfile/pilot_session_store.prom   # 空白 = 停用
```

### 21.2 Ingest 認證與綁定（D-B，修正 F20）

- 每個 ingest request 都以 `ingesttoken.Verifier` 驗證 bearer PIT1。失敗 → 401，body 為 `{"error": "unauthorized"}`（唯一例外：start window 已過時 body 為 `{"error": "start_window_closed"}`，讓 client 能提示重新連線；這不洩漏任何秘密），log 帶 `reason`、`kid`、path 中的 session id（不帶 token）。
- `POST /v1/sessions/start`：
  - 必須在 `sby` 之前（`start_window_closed` → 401）。
  - body 的 `session_id`/`user`/`gateway_id`/`scope`/`target`/`recording_mode` 必須逐一等於 claims 的 `sid`/`usr`/`gw`/`scp`/`tgt`/`mode`，否則 403 `claims_mismatch`。
  - `directory_id` 非空 → 400 `unbound_field`。
  - `recording_policy_source` 取自 claims `src`，不從 body 取；claims `jti` 存入 `ingest_jti`（不經 read API 對外輸出）。
  - 同一 `sid` 重送、metadata 與 `jti` 都相同且尚未 finish → 200（idempotent）；metadata 或 `jti` 不同 → 409（既有 `StartSession` conflict 語意；同一 sid 不得被第二張 token 接手）；該 sid 已 finish → 409 `session_finished`（sid 可由使用者經 `SSH_ORIGINAL_COMMAND` 指定，不得讓已結束的 session 被重新開啟）。
- `POST /v1/sessions/{id}/events` 與 `/finish`：
  - token 在 `exp` 之前；path `{id}` 必須等於 claims `sid`（否則 403 `session_id_mismatch`）；
  - session 必須存在；
  - 已儲存 session 的 `user`／`gateway_id`／`scope`／`target`／`recording_mode` 必須逐一等於 claims 的 `usr`／`gw`／`scp`／`tgt`／`mode`，且已儲存的 `ingest_jti` 必須等於 claims `jti`，否則 403 `claims_mismatch`（sid 由使用者可控，且會出現在 notice 與 audit 中，不是秘密；沒有這一步，別人可以替同一個 sid 取得 token，寫入或提前結束他人的錄影）；
  - events：session 已 finish（`ended_at` 非空）→ 409 `session_finished`；
  - finish：session 已 finish，且 `ended_at`（解析後以 UTC 時間比較）與 `last_seq` 都與已記錄的相同 → 200（idempotent，讓 client 在「store 已 commit、client 卻 timeout」後的 retry 不會誤報失敗；不比對 `complete`，因為儲存的值是 store 依 §21.4 重算的）；不同 → 409 `session_finished`；
  - 每個 event 的 `session_id` 必須等於 path `{id}`（否則 400）；
  - 其餘 idempotency 規則不變（相同 seq + 相同 payload → no-op；不同 payload → 409）。

### 21.3 Schema v2 migration（修正 F21）

比照 `internal/store/sqlite.go` 的 `migrateSteps` 模式，引入 migration runner：

```sql
ALTER TABLE sessions ADD COLUMN recording_policy_source TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN last_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN ingest_jti TEXT NOT NULL DEFAULT '';
```

`SchemaVersion = 2`。v1 DB 升級後既有資料完整保留；全新 DB 直接建立 v2 shape。版本比 binary 新時仍然拒絕開啟（保留 baseline 行為）。

**Migration 前自動備份（D-F）**：
- 只有在 `installed < SchemaVersion` 且 `installed > 0`（既有 DB）時執行，在任何 `ALTER` 之前。
- 先檢查 DB 所在 filesystem 的可用空間 ≥ 2 × DB 檔案大小，不足 → 啟動失敗，訊息指出需要多少空間，**不做 migration**。
- `VACUUM INTO '<index_db_path>.pre-v<installed>.bak'`；目標檔已存在則拒絕覆寫並啟動失敗（避免蓋掉上一次的備份）；完成後設為 0600，owner 與 DB 相同。
- `VACUUM INTO` 必須在任何 transaction **之外**執行（SQLite 不允許在 transaction 內 VACUUM）。備份成功後，才把所有 migration steps 與 `PRAGMA user_version` 更新包在**同一個** transaction 中執行；migration 失敗 → rollback 該 transaction，保留備份，啟動失敗。
- 回滾程序（寫進 runbook）。舊版 store 的 config 要求 `ingest.token_file`，且以 `KnownFields(true)` 拒絕新欄位；升級後的 gateway 簽發的 PIT1 舊 store 也不認得。因此回滾必須包含設定與 gateway：
  1. 升級前：在 vault 中**保留**舊的 `pilot_session_store_ingest_token`，直到確認升級成功才移除（新增的 `pilot_session_store_ingest_signing_key` 與它並存）。
  2. 回滾 store：停止 store → 以備份檔取代 `index.db` → 以升級前的 repo revision 重新 apply `pilot-session-store-apply.yml`（還原舊 binary、舊 config 與舊 token 檔）。
  3. 回滾 gateway：舊版 gateway 會忽略 `pilot.policy.*` marker（F14），被標記的主機會**靜默不錄**，違反 G9。因此回滾一律先從 hosts.yml 移除所有 `ssh_recording`，並重新 apply freeipa-client，讓 FreeIPA 上的 marker 全部消失；之後才以升級前的 revision 重新 apply gateway。runbook 必須明寫「回滾期間 per-host 錄影停用」，由執行回滾的 operator 確認後才進行。
  4. 重新升級前，先把 `index.db.pre-v1.bak` 移到別處，否則備份檔已存在會讓新版 store 拒絕啟動（設計如此，避免覆蓋上一次的備份）。
  5. 確認升級成功後，手動刪除備份檔，並從 vault 移除舊 token。
- 備份檔含加密後的 payload，與 DB 同樣受 restic backup 範圍涵蓋（`/var/lib/pilot-session-store`）。

### 21.4 Completeness（修正 F10）

finish 時：

```text
complete = request.complete
        && 在 [1, last_seq] 範圍內沒有任何 gap
        && 已儲存的最大 seq == last_seq
```

`last_seq` 寫入 DB。replay 回應的 gap 清單包含尾端 gap（`max_seq+1 .. last_seq`）。`pilot session replay` 對 incomplete session 維持印出 `*** RECORDING INCOMPLETE ***` 與 gap 範圍。

read API 的 `sessionSummaryJSON`（list／show／replay 共用）新增 `recording_policy_source` 與 `last_seq`；`pilot session show` 輸出這兩個欄位。

### 21.5 讀取 audit（修正 F22）

- read API 的 replay endpoint 新增可選 query `purpose=replay|export`，未帶時為 `replay`。
- 每次 replay/export 請求（成功或失敗）以 `sessionaudit.NewEmitter("pilot-session-store")` 發出事件：
  - kind：`recording_replayed` 或 `recording_exported`；
  - `Auditor`：SO_PEERCRED 解析出的 username；
  - `User`／`TargetFQDN`／`GatewayID`／`GatewayScope`／`RecordingMode`：取自 session summary（找不到 session 時為空）；
  - `SessionID`；`Result`：`ok`／`denied`／`not_found`／`error`。
  - **不得**帶任何 terminal payload。
- auditor group 權限檢查維持 `role-pilot-session-auditor`。一般 Portal 使用者不得列出或重播錄影。
- `purpose` 由呼叫端宣告，只影響 audit 的 kind，不影響權限或回傳內容（見 §0.3 風險）。

## 22. Session audit（`internal/sessionaudit`）

- 新增 kind：`recording_replayed`、`recording_exported`。
- `SessionAuditEvent` 新增 `Auditor string json:"auditor,omitempty"`、`RecordingPolicySource string json:"recording_policy_source,omitempty"`。
- 以下事件必須帶 `session_id`、`user`、`target_fqdn`、`gateway_id`、`gateway_scope`、`recording_mode`（與 `recording_policy_source`，若已知）：`gateway_authorize_allowed`、`target_connect_started`、`target_connect_failed`、`recording_started`、`recording_gap`、`recording_failed`、`session_ended`。互動式 Portal 路徑也一樣要發這些事件（修正 F1 的 audit 缺口）。
- `gateway_authorize_denied` 的 `Result` 只放 `DenyReason` 或 `authorize call failed`，不得塞 error dump。
- terminal payload（`tty_input`／`tty_output`）不得進入 sessionaudit、syslog、journald、Loki 或任何一般 log，只能進 `sessionrecording.Sink`。

## 23. Recording mode semantics

| mode | 保存 | 不保存 |
|---|---|---|
| `metadata` | session lifecycle audit（authorize、connect、end、exit code） | tty output／input／resize |
| `terminal_output` | tty output、resize、lifecycle | tty input（不進 event pipeline） |
| `terminal_io`（只能由 gateway 全域 default 產生） | tty output、input、resize、lifecycle | — |

`terminal_io` 的已知限制（F13）必須寫進 runbook 與 gateway group_vars example：`typed input is recorded only as redacted byte counts on the Gateway SSH relay path; terminal_io does not capture command text today.` 不得宣稱 redaction 保證 secret 不外洩。

Canonical durable format 維持 `sessionrecording.TerminalEvent`，正式命名為 **Pilot Terminal Recording v1（PTR/1）**，schema_version 1，不變更。

---

## 24. UX

### 24.1 Portal My Hosts / Host Detail（`cmd/pilot/cmd/portal_tui*.go`）

依 `HostJSON.Recording` 顯示：

| Status / Effective | 列表 | Host Detail |
|---|---|---|
| effective `terminal_output` | `db-prod-01.ipa.pilot.internal   [REC output]` | `SSH recording: terminal output (host policy)` 或 `(gateway default)` |
| effective `terminal_io` | `[REC input+output]` | `SSH recording: input + output (gateway default; input stored as redacted byte counts)` |
| effective `metadata` | 無標記 | `SSH recording: off` |
| `unknown` | `[REC policy unavailable]` | `SSH recording: policy unavailable — Connect will be refused` |
| `invalid` | `[REC policy invalid]` | `SSH recording: policy misconfigured — Connect will be refused` |

Host Detail 的 Connect 確認問句在 effective 為 terminal 時加一行 `This session will be recorded.`。

### 24.2 Directory 列表（`cmd/pilot/cmd/directory_tui.go`）

只依 host override 顯示（Directory 不知道各 gateway 的 default）：`Override == "terminal_output"` → `[REC]`；`!Known` 或 `!Valid` → `[REC ?]`；其他 → 無標記。實際是否錄影以 gateway 在 SSH 前印出的提示為準。

### 24.3 Pre-connect notice（兩條路徑相同）

authorize 回傳 terminal mode 後、store start 之前，寫到 stderr：

- `terminal_output`：`This SSH session is recorded by Pilot (terminal output). Session ID: <uuid>`
- `terminal_io`：`This SSH session is recorded by Pilot (terminal output and input; typed input is stored as redacted byte counts). Session ID: <uuid>`

metadata 不印任何提示。不新增額外的 Yes/No（互動式 Portal 既有的 Connect 確認保留）。

## 25. `pilot edit`

- Host 選單（`hostMenuItems`，`edit_tui.go:590-628`）新增 `SSH recording` 項目，item ID `hosts.item.ssh_recording`；選取後推入 ScreenID `hosts.item.ssh_recording` 的選單（比照 `pushDeploymentAvailabilityMenu`），choice ID 與 `set_host_field` 的 value 相同：`inherit`（Inherit gateway default）、`off`（Off）、`terminal_output`（Terminal output）。InitialID 取目前值（空 = `inherit`）。
- 選 inherit → 從 host 移除欄位；其他 → 寫入值。save → reload 必須 round-trip。
- `set_host_field`：`Values["field"]` 加入 `ssh_recording`；`validateSetHostField` 驗證 value ∈ {`inherit`, `off`, `terminal_output`}；driver `setHostField` 依 ScreenID 選擇對應 choice。
- `TestSemanticActionCatalogIsStable` 不需變更（沒有新 action），但 `set_host_field` 的 Values 變更要更新對應的 catalog/MCP 測試。

## 26. `hosts.example.yml` 與 DELIVERY.md

`hosts.example.yml` 新增：

```yaml
  db-prod-01:
    ansible_host: "10.0.0.31"
    roles: [freeipa-client, linux-servers]
    env: prod
    # SSH terminal recording policy for sessions through pilot-access-gateway.
    #   omitted          = inherit the gateway default (built-in default: metadata = no terminal recording)
    #   terminal_output  = record terminal output (recommended recording mode)
    #   off              = explicit no-terminal-recording override
    # terminal_io is reserved for a future release.
    ssh_recording: terminal_output
```

DELIVERY.md 在 §1.6（`deployment_availability`）之後新增一節，說明 `ssh_recording` 的語意、啟用或停用單台主機的流程（改 hosts.yml → `pilot inventory lint` → `pilot inventory generate` → 部署 freeipa-client → 以 `ipa host-show <fqdn> --all --raw` 確認 marker），並寫明「錄影主機需要 gateway 已設定 session store，否則該主機的連線會被拒絕」。

## 27. Gateway / Store 部署（playbooks + contracts，修正 F5）

### 27.1 `playbooks/apply/pilot-access-gateway-apply.yml`

- vars 預設：`pilot_session_recording_failure_policy: fail_closed`、`pilot_session_recording_queue_events: 1024`、`pilot_session_recording_flush_interval: 500ms`、`pilot_session_recording_failure_grace: 10s`、`pilot_session_recording_max_session_duration: 24h`、`pilot_session_store_url: ""`、`pilot_session_store_ca_file: /etc/ipa/ca.crt`。
- `pilot_session_recording_mode` 與 `pilot_session_store_ingest_signing_key` **不給預設值**（以 `is defined` 判斷）。mode 未定義時，Step 11 不輸出 `mode:` 這一行，gateway 回報的 source 才會是 `built_in_default`（F29）。
- pre_tasks（放在 stage gate 之後、任何 mutation 之前）以 assert 驗證：
  - mode（若已定義）與 failure_policy 的 enum；
  - mode 非 metadata 時 `pilot_session_store_url` 非空；
  - url 非空時必須是 `https://`，且 signing key 已定義、為 64 個 hex 字元。
- Step 11 的 config 內容加入 `recording:`（依上述 vars）與 `metrics:`（§31）。url 為空時不輸出 store 相關三欄。
- 新增 task：url 非空時寫入 signing key 檔（`pilot-gateway:pilot-gateway 0400`，`no_log: true`）；url 為空時 `state: absent`。另一個 task 刪除舊的 `/etc/pilot/session-store-ingest-token`。
- 設定或 key 檔變更時重啟 gateway service（沿用 `gateway_config_copy` 的 restart 條件，把 key 檔的 register 也納入）。
- metrics 啟用時，gateway service unit 加 `ReadWritePaths=` textfile 目錄（F24）。
- 檢查 textfile 目錄的 `stat` task 與決定 metrics 路徑的 `set_fact` 都必須標 `tags: [always]`，因為 Step 11 與 unit file 會讀它們（AGENTS.md §4.4）。
- 分支 N：新增以 admin 維持 gateway 自己 host object 上 canary（`pilot.policy.userclass-canary=1`）的 task 組，並比照 §8 的結構：argv、addattr／delattr、check mode 零 mutation、post-write verify、kinit 走 `command` + `stdin`。
- 新 task 的 row tag 見 §33。

### 27.1a Site order

`contracts/pilot-session-store.yaml` 的 `site.order` 從 55 改為 51；`playbooks/site.yml` 中 `pilot-session-store-apply.yml` 的 import 移到 `pilot-access-gateway-apply.yml` 之前（freeipa-client 之後），並更新相鄰註解。`cmd/pilot/cmd/site_yml_consistency_test.go` 必須保持綠燈；若它或 `deploy_test.go` 鎖了舊順序，一併更新。

### 27.2 `playbooks/apply/pilot-session-store-apply.yml`

- `pilot_session_store_ingest_token` → `pilot_session_store_ingest_signing_key`（assert 64 hex）。
- `pilot_session_store_ingest_signing_key_file: /etc/pilot/session-store-ingest-signing.key`。
- 刪除舊的 `/etc/pilot/session-store-ingest.token`。
- config 改成 `signing_key_file:`，加入 `metrics:`；metrics 啟用時 unit 加 `ReadWritePaths=`。

### 27.3 Contracts

- `contracts/pilot-access-gateway.yaml`：groupVars 新增上述 `pilot_session_recording_*`（`pilot_session_recording_mode` 為 required: false、無 default）、`pilot_session_store_url`、`pilot_session_store_ca_file`、`pilot_session_store_ingest_signing_key`（secret, required: false）；regressionTests 新增 §34 的 test 檔，並把 `cmd/pilot-access-gateway/config_test.go` 改成 `internal/gatewayconfig/config_test.go`；traceability 對應 §33 的新 row。
- `contracts/pilot-session-store.yaml`：`pilot_session_store_ingest_token` 換成 `pilot_session_store_ingest_signing_key`；regressionTests 新增 `internal/ingesttoken/ingesttoken_test.go` 等；traceability 對應 §33。
- `contracts/freeipa-client.yaml`：regressionTests 新增 `internal/spec/freeipa_host_access_policy_regression_test.go`。
- `contracts/pilot-access-directory.yaml`：traceability 新增 AD31 的 unit-test-evidence exemption（regressionTests 已涵蓋 `resolver_test.go`、`directory_tui_test.go`）。

### 27.4 group_vars examples

- `group_vars/pilot-access-gateway.example.yml`：新增 recording 變數說明（含 `terminal_io` 限制、`fail_closed` 預設與 `best_effort` 的差別、`max_session_duration`）。
- `group_vars/pilot-session-store.example.yml`：`pilot_session_store_ingest_token` 換成 signing key，移除「Gateway 需手動對應設定」那段，改成「gateway 以同一個 vault key `pilot_session_store_ingest_signing_key` 由 playbook 自動設定」。

---

## 28. `pilot session export`（D-C）

```bash
pilot session export <session-id> --format asciicast-v2 --output session.cast [--force]
```

- 先呼叫 read API 的 show 取得 session summary（`started_at` 等），再呼叫 replay endpoint 並帶 `purpose=export`（因此會留下 `recording_exported` audit）。權限同 replay（auditor group）。
- 輸出 asciicast v2：
  - header：`{"version": 2, "width": <cols>, "height": <rows>, "timestamp": <started_at unix>, "title": "pilot session <id>"}`，width/height 取自第一個 resize event（§18.3 保證存在；舊錄影沒有時用 80×24）；
  - `tty_output` → `[t, "o", data]`；`tty_input` → `[t, "i", data]`；`resize` 則寫成 `[t, "r", "<cols>x<rows>"]`；
  - `t = offset_nanos / 1e9`；
  - UTF-8 解碼**依 stream 串流進行**：同一 stream 中，event 結尾不完整的 multibyte 序列要保留，接到下一個同 stream 的 event 再解碼（recorder 以 4096 bytes 切塊，CJK 字元常被切開）。只有真正無效的 byte 才以 U+FFFD 取代；session 結束時殘留的不完整序列也以 U+FFFD 取代。export 本質上會失真，canonical storage 不變。
- Marker event（`[t, "m", "..."]`）：
  - incomplete session → 在 t=0 加 `pilot: RECORDING INCOMPLETE`；
  - 每個 gap → `pilot: gap seq <from>-<to>`；
  - `redacted_bytes > 0` 的 input → `pilot: input redacted (<n> bytes)`（不輸出 data）。
- `--output` 檔案以 0600 建立；已存在且未帶 `--force` 時拒絕；`--output -` 寫到 stdout。
- 程式位置：`cmd/pilot/cmd/session_export.go`；轉換邏輯放在可單元測試的 `internal/sessionrecording/asciicast.go`。

## 29. `pilot access recording show <host>`（D-C）

```bash
sudo pilot access recording show <host-fqdn> [--format text|json] [--config /etc/pilot/access-gateway.yaml]
```

依 D-E，由 gateway host 上的 root 執行（F31：portal user 被 ForceCommand 鎖住，admin／root 又不在 socket 的 group 內，所以不經過 gateway socket）：

- 非 root（`os.Geteuid() != 0`）→ 錯誤 `must run as root on a pilot-access-gateway host`，exit 2。
- config loader（`Config`、`LoadConfig`、驗證）從 `cmd/pilot-access-gateway/config.go` 搬到新 package `internal/gatewayconfig`，gateway daemon 與這個 CLI 共用同一份（`cmd/` 下的 main package 無法被 import，也**不得**複製一份 parser）。`cmd/pilot-access-gateway/config_test.go` 隨之搬移。CLI 從中取得原始 `recording.mode`、FreeIPA servers、keytab、service principal。
- 以同一個 `freeipaaccess` client 與 keytab 對該 host 呼叫 `host_show`（分支 R 帶 rights；分支 N 同時檢查 gateway 自己 host 的 canary），再用 `ResolveRecordingMode` 算出 effective mode 與 source。
- **不做** HBAC 判斷，只回報 recording policy。host 不存在於 FreeIPA → `host not found in FreeIPA`，exit 1。
- 唯讀，不讀 hosts.yml，不寫任何東西。程式位置：`cmd/pilot/cmd/access_recording_cli.go`。
- 輸出：

```text
Host:             db-prod-01.ipa.pilot.internal
Host policy:      terminal_output        (inherit|off|terminal_output|unknown|invalid)
Gateway default:  metadata               (unset → built-in metadata)
Effective:        terminal_output
Policy source:    host
FreeIPA source:   userClass pilot.policy.ssh-recording
```

json 格式的欄位：`host`、`host_policy`、`gateway_default`、`effective`、`policy_source`、`reason`（unknown／invalid 時）。

## 30. Retention 與 key model

- per-host policy 不控制 retention；維持 `pilot_session_store_retention_days`。不支援 `ssh_recording.retention_days`。
- AES-256-GCM 與 master key 模型不變：key 檔不得 group/world 可存取、key 不得寫 log、`key_id` 只是 metadata、AAD 綁定 `session_id` + `seq` + `stream`。

## 31. Metrics（D-C，node_exporter textfile）

新增小型共用 helper `internal/promtext`（counter/gauge vec + 以 temp file + rename 原子寫入，比照 `internal/detection/metrics.go:148-175`；不重構 detection-engine）。

- **Gateway daemon**：啟動時立即寫一次，之後每 15 秒、以及關閉時各寫一次 `metrics.textfile_path`（0644）。gateway 是 socket-activated，沒有任何連線之前 process 不存在，所以 AG55 的檢查指令要先觸發一次 socket（例如以 root 連 `/v1/health`）再檢查檔案。
  - `pilot_gateway_connect_authorize_total{result="allowed|denied", reason="none|recording_policy_unavailable|recording_policy_invalid|recording_backend_unavailable|recording_session_id_invalid|access_denied|error"}`
  - `pilot_gateway_recording_authorized_sessions_total{mode="metadata|terminal_output|terminal_io", source="host|gateway_default|built_in_default"}`
  - `pilot_gateway_metrics_last_write_timestamp_seconds`
- **Session store**：同樣寫法（啟動時立即寫、每 15 秒、關閉時）。
  - `pilot_session_store_ingest_requests_total{endpoint="start|events|finish", code="2xx|4xx|5xx"}`
  - `pilot_session_store_ingest_auth_failures_total{reason="malformed|unknown_key|bad_signature|not_yet_valid|expired|start_window_closed|invalid_claims|claims_mismatch|session_id_mismatch|session_finished"}`
  - `pilot_session_store_sessions_finished_total{mode="terminal_output|terminal_io", complete="true|false"}`
  - `pilot_session_store_gap_ranges_detected_total`
  - `pilot_session_store_read_requests_total{action="list|show|replay|export", result="ok|denied|not_found|error"}`
  - `pilot_session_store_metrics_last_write_timestamp_seconds`
- 禁止使用 `username`、`session_id`、`target_fqdn` 這類高 cardinality label。
- recorder 端的 sink failure／gap 在使用者自己的短命 process 內發生，不另外輸出 metrics；可觀測性由 store 端的 `sessions_finished_total{complete="false"}`、`gap_ranges_detected_total` 與 `recording_gap`／`recording_failed` audit event 提供。
- playbook 以 `stat` 檢查 `/var/lib/node_exporter/textfile`：存在才設定 `textfile_path`，不存在時留空並印出 debug 說明（soft，不 fail；與 detection-engine 的硬 gate 不同，因為 metrics 對 gateway／store 不是必要功能）。

---

## 32. Source of truth 與一致性

- hosts.yml = desired source；FreeIPA = runtime projection；Gateway = read-only consumer。
- Gateway 不得有跨 request 的 policy cache。每次 authorize 都用當次 snapshot。
- source 已修改但 FreeIPA 尚未 reconcile 時，runtime 以 FreeIPA 現況為準。runbook 必須寫明這點。

## 33. Verification spec 變更

**Spec-first**：每個 Phase 開始寫 code 或 playbook 前，先把該 Phase 的 row 寫進對應的 `docs/verification/*.md`，並跑 `go run ./cmd/pilot spec <file> --lint`。row 的 Command 欄必須先以 `pilot verify --probe` 在目標環境試跑過才能寫入（AGENTS.md §1、§1.4）。下表 ID 為暫定；實作時若已被佔用則順延，並同步 contract traceability。

### 33.1 `docs/verification/pilot-access-gateway.md`

| ID | Check | 證據類型 |
|---|---|---|
| AG37（改寫） | `session_id` 不影響 HBAC／scope 決策；只在 effective mode 為 terminal 時要求它是合法 UUID，並綁進 ingest token | unit-test-evidence：沿用 `TestRunPortalOneShotConnect_Allowed`／`_Denied`，新增 `TestConnectAuthorize_SessionIDOnlyBindsToken` |
| AG41 | `access-gateway.yaml` 含 playbook 產生的 `recording:` 區塊，mode／failure_policy 為合法值 | live，tag `AG41`（Step 11） |
| AG42 | 設定 store 時 signing key 檔為 `pilot-gateway:pilot-gateway 400`；未設定時不存在 | live，tag `AG42` |
| AG43 | 舊的 `/etc/pilot/session-store-ingest-token` 不存在 | live，tag `AG43` |
| AG44 | resolver 依 §4 precedence 產生 mode 與 source | unit-test-evidence：`TestResolveRecordingMode` |
| AG45 | policy unknown／invalid／保留值 `terminal_io` → Allowed=false 且帶對應 DenyReason | unit-test-evidence：`TestConnectAuthorize_RecordingPolicyDenies` |
| AG46 | effective terminal 但沒有 store → deny `recording_backend_unavailable` | unit-test-evidence：`TestConnectAuthorize_TerminalWithoutStoreDenied` |
| AG47 | metadata 回應不含 store URL／CA／token | unit-test-evidence：`TestConnectAuthorize_MetadataCarriesNoIngestCredential` |
| AG48 | terminal 回應的 token claims 綁定 sid／user／gateway／scope／target／mode／source，且每次簽發的 `jti` 都不同 | unit-test-evidence：`TestConnectAuthorize_MintsBoundIngestToken` |
| AG49 | 兩次 authorize 之間 host policy 由 absent 改為 terminal_output，第二次立即生效 | unit-test-evidence：`TestConnectAuthorize_FreshPolicyEachRequest` |
| AG50 | 互動式 Portal Connect 對 terminal mode 走 recorded path | unit-test-evidence：`TestConnectToHost_TerminalModeUsesRecordedPath` |
| AG51 | recorded path 在 store start 失敗時不啟動任何 ssh process（Phase A 也不做） | unit-test-evidence：`TestPortalTargetSession_StoreStartFailureNoSSH` |
| AG52 | terminal mode 不寫任何 local recording file | unit-test-evidence：`TestPortalTargetSession_NoLocalRecordingFile` |
| AG53 | fail_closed 下閒置但健康的 session 超過 3×failure_grace 仍存活 | unit-test-evidence：`TestRecorderFailClosedIdleSessionSurvives` |
| AG54 | terminal mode 印出 pre-connect notice；metadata 不印 | unit-test-evidence：`TestPortalTargetSession_RecordingNotice` |
| AG55 | textfile 目錄存在時 metrics 檔存在，且含 `pilot_gateway_connect_authorize_total` | live，tag `AG55` |
| AG56 | 分支 R：某 host 的 userclass 不可讀 → 只有該 host 的連線 deny `recording_policy_unavailable`；分支 N：gateway 自己 host 上恰好有一個 canary，canary 消失 → 所有連線 deny | 分支 R：unit-test-evidence `TestConnectAuthorize_UserClassUnreadableDenies`；分支 N：live，tag `AG56`（canary task）+ unit-test-evidence `TestConnectAuthorize_CanaryMissingDeniesAll` |
| AG57 | `sudo pilot access recording show <host>` 依 §29 輸出 host policy、gateway default、effective、source；非 root 被拒 | unit-test-evidence：`TestAccessRecordingShow_*`，另有 live L20 |

同步更新 `internal/spec/pilot_access_gateway_regression_test.go:19` 的 `wantIDs`，以及 `cmd/pilot/cmd/tag_coverage_test.go` 中 gateway／store／directory 的豁免表（unit-test-evidence 的 row 要加進豁免並附理由；SS03 的理由改為 PIT1）。

§4（多主機性質）新增 L1–L22 的結果摘要，並連到 evidence。§7 依 Phase 0 分支寫入 rights 檢查（分支 R）或 canary 的用途與限制（分支 N）。

### 33.2 `docs/verification/pilot-session-store.md`

| ID | Check | 證據類型 |
|---|---|---|
| SS03（改寫） | ingest 只接受有效 PIT1；缺少、簽章錯誤、過期、kid 不符 → 401 | unit-test-evidence：`TestIngestAPIRejectsInvalidSessionToken` |
| SS04（改寫） | signing key 沒有任何路徑進入 read API | structural-absence |
| SS19 | start body 與 claims 不一致 → 403；`directory_id` 非空 → 400 | unit-test-evidence：`TestIngestAPIStartMustMatchClaims` |
| SS20 | path id 與 claims sid 不同 → 403；event.session_id 與 path 不同 → 400；同一 sid 但 claims（user／gateway／scope／target／mode）或 `jti` 與已儲存的不同 → 403 `claims_mismatch`；已存在且未 finish 的 sid 以不同 `jti` start → 409 | unit-test-evidence：`TestIngestAPISessionIDBinding`、`TestIngestAPIRejectsOtherUsersTokenForSameSID`、`TestIngestAPIRejectsSecondTokenForSameSID` |
| SS21 | finish 後的 events → 409 | unit-test-evidence：`TestIngestAPIRejectsEventsAfterFinish` |
| SS22 | 尾端遺失（max_seq < last_seq）→ complete=false，replay 列出尾端 gap | unit-test-evidence：`TestStoreFinishDetectsTrailingGap` |
| SS23 | v1 DB 升級到 v2 後保留資料並新增三欄（`recording_policy_source`、`last_seq`、`ingest_jti`） | unit-test-evidence：`TestStoreMigratesV1ToV2` |
| SS24 | signing key 檔 owner／mode 正確；舊 token 檔不存在 | live，tag `SS24` |
| SS25 | replay／export 發出 audit event，且不含 payload | unit-test-evidence：`TestReadAPIAuditsReplayAndExport` |
| SS26 | textfile 目錄存在時 metrics 檔存在 | live，tag `SS26` |
| SS27 | 既有 v1 DB 升級時先產生 `index.db.pre-v1.bak`（0600）；空間不足或備份檔已存在時不 migrate 並啟動失敗 | unit-test-evidence：`TestStoreMigrationBacksUpBeforeAlter`、`TestStoreMigrationRefusesWithoutSpace`、`TestStoreMigrationRefusesExistingBackup` |

§4 新增 disk-full live gate（L18）結果與 evidence 連結；原「disk full 未模擬」的已知缺口改為已驗證。

### 33.3 `docs/verification/pilot-access-directory.md`

| ID | Check | 證據類型 |
|---|---|---|
| AD31 | Directory 列表依 host override 顯示 `[REC]`／`[REC ?]`，inherit／off 不顯示 | unit-test-evidence：`TestDirectoryResolve_CarriesRecordingOverride`、`TestDirectoryHostLabel_RecordingBadge` |

### 33.4 `docs/verification/freeipa-client.md`

**不新增 row**（F18：`pilot verify` 沒有 Kerberos，與 annotations 相同）。在「不在 checklist 逐行覆蓋」段落新增一項：host access policy projection 由 in-play Phase F post-write verify + `internal/spec/freeipa_host_access_policy_regression_test.go` + live evidence（L2、L6、L7、L9–L11、L17）證明。

---

## 34. Tests

### 34.1 Inventory（`internal/inventory`）

`TestParseSSHRecording_Omitted`、`_Off`、`_TerminalOutput`、`TestLintSSHRecording_RejectsTerminalIOReserved`、`_RejectsBool`、`_RejectsUnknown`、`TestGenerate_SSHRecordingQuoted`、`TestGenerate_OmittedSSHRecordingNotRendered`、`TestParse_SSHRecordingNotCopiedIntoExtra`、`TestParse_AnnotationSSHRecordingHasNoPolicyEffect`、`TestLint_GeneratedKeyCollisionInExtra`、`TestRender_SSHRecordingRoundTrip`、`TestCanonicalInventoryHash_IncludesSSHRecording`（在 `internal/decommission`）。

### 34.2 pilot edit / actions（`cmd/pilot/cmd`）

`TestHostMenu_SSHRecordingChoices`、`TestHostMenu_SSHRecordingInheritRemovesField`、`TestSetHostField_SSHRecording`（inherit／off／terminal_output 合法；terminal_io／其他拒絕）。

### 34.3 FreeIPA normalize（`internal/freeipaaccess`）

依 Phase 0 fixture：`TestParseHostSSHRecording_Absent`、`_Off`、`_TerminalOutput`、`_DuplicateInvalid`、`_EmptyInvalid`、`_UnknownInvalid`、`_TerminalIOReservedInvalid`、`_CaseVariantPrefixMalformed`、`_NotInAnnotations`、`TestParseHost_RealUserClassFixture`。分支 R 另加 `TestParseHost_UserClassUnreadableIsUnavailable`（`Unreadable=true`，accessportal 對應為 `Known=false`）。分支 N 另加 `TestParseHost_UserClassCanary`。

### 34.4 AccessPortal / Directory

`TestResolveScopeAccess_CarriesRecordingOverride`、`_HostShowFailureMarksPolicyUnknown`、`_AnnotationsStillBestEffort`、`_OneHostShowPerFQDN`（並行下也只呼叫一次，`-race`）、`TestHostMetadataCache_NotHeldAcrossRPC`、（分支 N）`TestResolveScopeAccess_CanaryMissingMarksAllUnknown`、`TestResolveScopeAccess_EmptyCanaryFQDNSkipsCheck`、`TestDirectoryResolve_CarriesRecordingOverride`（含 §12 的多 scope 合併規則）、`TestDirectoryHostLabel_RecordingBadge`（`cmd/pilot/cmd/directory_tui_test.go`）。

### 34.5 Gateway

`TestResolveRecordingMode`（table-driven，涵蓋 §4 每一列，含 raw default `""` → `built_in_default`）；`internal/gatewayconfig` 的 `TestLoadConfig_Recording*`（新預設、grace/flush 關係、url 必須 https、terminal default 需要 store、舊欄位被拒、key 檔 hex 與權限、mode 未設定時保留原始空值）；§33.1 列出的 `TestConnectAuthorize_*`；`TestConnectAuthorize_DeniedHBACHasNoRecordingFields`；`TestAccess_RecordingJSON`。

### 34.6 Ingest token（`internal/ingesttoken`）

Mint→Verify round-trip；`malformed`／`unknown_key`／`bad_signature`／`not_yet_valid`／`expired`／`invalid_claims` 各一；`CheckStartWindow` 在 `sby + 60s` 之後（例如 `sby + 61s`）回傳 `start_window_closed`，在 `sby + 59s` 仍通過；`TestVerify_DoesNotCheckStartWindow`（`iat+1000s` 時 Verify 仍成功）；claims 使用 unknown field 被拒；缺少或格式錯誤的 `jti` → `invalid_claims`；`TestMint_UniqueJTI`（連續兩次 Mint 的 `jti` 不同）；token 字串不出現在任何 error message 中。store 端另有 `TestIngestAPIEventsAcceptedAfterStartWindow`（`iat+1000s` 送 events → 200）。

### 34.7 Recorder / HTTPSink（`internal/sessionrecording`）

`TestRecorderFailClosedIdleSessionSurvives`、`TestRecorderFailClosedSustainedFailureTerminates`（hung sink：watchdog 仍依 wall-clock 觸發，且 `Run` 在 `FailureGrace + 5s` 內返回）、`TestRecorderEnqueueReturnsAfterWriterStops`、`TestRecorderDrainTimeoutCancelsWriter`、`TestRecorderDefaultFailureGrace`、`TestRecorderFailClosedBackpressureNoDrops`、`TestRecorderFailClosedPermanentErrorImmediate`、`TestRecorderBestEffortSinkErrorEmitsGap`、`TestRecorderBestEffortQueueFullDropsAndIncomplete`、`TestRecorderFinishCompleteOnlyWhenClean`、`TestRecorderInitialResizeIsFirstEvent`、`TestRecorderAuditEventsCarryIdentity`、`TestHTTPSinkBatchingThresholds`、`TestHTTPSinkRetriesTransientSameBatch`、`TestHTTPSinkPermanentErrorNoRetry`、`TestHTTPSinkFinishCarriesLastSeq`、`TestAsciicastExport*`（header、o／i／r、gap／incomplete／redacted marker、非 UTF-8）。

### 34.8 Portal（`cmd/pilot/cmd`）

§33.1 列出的 `TestConnectToHost_*`／`TestPortalTargetSession_*`；`TestPortalTargetSession_MetadataPlainPathUnchanged`；`TestPortalTargetSession_DenyReasonMessages`；`TestConnectToHost_NoStdinReaderLeftAfterRecordedSession`（F28，以可觀察的 fake cancelreader 驗證 recorded session 結束後已 Cancel，且 `InputDone()` 已 close）；`TestConnectToHost_RecordedSessionPTY`（真實 PTY 層級測試，以 `creack/pty` 建立 outer terminal：session 中處於 raw mode、結束後恢復原 termios，且結束後寫入 outer terminal 的下一個 byte 會被呼叫端讀到、不被遺留的 goroutine 吃掉）；`TestPortalTargetSession_FailureAfterStartFinishesIncomplete`（Phase A 失敗與 Phase B 啟動失敗都會送出 `complete=false` 的 finish）；`TestPortalTargetSession_EnsureAfterAuthorize`（被拒時不呼叫 `credentials.Ensure`）；`TestSessionExport_*`（權限、`--force`、0600、stdout、呼叫 show 取得 `started_at`）；`TestAccessRecordingShow_*`（非 root 被拒、各 policy 狀態輸出、json 格式、host 不存在）。既有的 `TestRunPortalOneShotConnect_*` 在 fake provider 依 §10 改為回傳 absent-valid policy 之後，全數保持綠燈；唯一例外是 `TestRunPortalOneShotConnect_RecordingEnabledSkipsPlainPath`（`portal_session_connect_test.go:66`）：它以沒有 store 的 `RecordingPolicy{Mode: "terminal_io"}` 建構 gateway，Phase 5 改名 `Mode` 並新增 `recording_backend_unavailable` 後必須改寫——Phase 5 先改成「gateway 設了 store、host override 為 terminal_output」的版本，Phase 6 再改用 `runPortalTargetSession` 的 recorded path 斷言。

### 34.9 Session Store

§33.2 列出的 `TestIngestAPI*`、`TestStore*`、`TestReadAPIAudits*`；`TestIngestAPIFinishIdempotentRetry`、`TestIngestAPIFinishDifferentBodyConflict`（改變 `ended_at` 或 `last_seq` → 409）、`TestIngestAPIFinishOnlyCompleteDiffers`（只有 `complete` 不同 → 200）、`TestIngestAPIFinishRequiresEndedAt`、`TestIngestAPIStartOnFinishedSessionConflict`、`TestIngestAPIFinishRequiresLastSeq`；`TestReadAPISummaryIncludesPolicySourceAndLastSeq`；`TestLoadConfig_SigningKeyFile`（取代 token_file）；`TestMetricsTextfile*`。

### 34.10 Playbook static regression

`internal/spec/freeipa_host_access_policy_regression_test.go`：
1. 只使用 `pilot.policy.ssh-recording=` namespace，prefix 比對 case-insensitive；
2. 不碰 `pilot.annotation.*`；
3. 沒有 `--setattr=userclass=`；
4. 有 foreign 保留的 post-write gate；
5. duplicate／malformed／unknown code 出現在第一個 `--addattr` 之前；
6. 每個 mutation task 都有 `not ansible_check_mode`；
7. 有 post-write re-read（exact match）；
8. desired absent 時會 delete；
9. 沒有 `ipa host-add`，也沒有 `ansible.builtin.shell`，ipa 一律 argv 形式；
10. kinit 為 `no_log: true`；
11. 每個 ipa 呼叫都帶 `xmlrpc_uri` override；
12. 變數一律 `ipa_host_policy_` prefix；
13. include 位於 annotations include 之後，且兩個 include 都有 `apply: tags`；
14. HOST_ABSENT 與 FREEIPA_UNREACHABLE 分開判斷；
15. 以 Go `regexp` 套用 playbook 中同一個 userclass regex 到 Phase 0 的真實 fixture，取出的值與預期完全相同；
16. playbook 判斷 HOST_ABSENT 所用的字串，確實出現在 Phase 0 的 not-found fixture 中，且**不**出現在 unreachable fixture 中。

以上 1–16 屬 Phase 2。另外，gateway／store playbook 的新 task 要被 `always` tag 前置 lint（AGENTS.md §4.4）涵蓋，`TestSpecPlaybookTagAlignment` 要納入 §33 的新 row；這兩項分別在交付對應 task／row 的 Phase 4（store）、Phase 5（gateway）、Phase 7（metrics 相關 row）完成。

---

## 35. Live verification（Phase 8）

**Topology**（`pilot vm-target topology test`）：FreeIPA server ×1、Access Gateway ×1、Directory ×1、target ×2（A 無 policy、B 視情境設定）、Session Store ×1、測試使用者 ×1（同時是 portal user 與 session auditor）。

- check-mode 與 fresh-host 驗證必須以 `--ephemeral` 對全新 VM 跑過（AGENTS.md §4.0）。
- L-scenario 可使用既有的 `ag-*` long-lived fixture pool，但結束後必須恢復 baseline 狀態。
- signing key 使用一次性產生、只放在 `.verification/` 的測試 key，不寫入任何真實 vault。

| # | 情境 | 必須觀察到 |
|---|---|---|
| L1 | Target A 沒有 marker，經 Directory 連線 | authorize `recording_mode=metadata`；沒有 notice；store 沒有該 sid |
| L2 | B 設 `ssh_recording: terminal_output` 並 apply | `ipa host-show` 出現 `pilot.policy.ssh-recording=terminal_output` |
| L3 | 經 Directory handoff 連 B，執行 `echo PILOT_RECORDING_MARKER_123` | 出現 notice；store 有 session（target=B、mode=terminal_output、policy_source=host、complete=true）；replay 看得到 marker |
| L4 | 直接 SSH 進 gateway，從 Portal My Hosts 連 B | 列表出現 `[REC output]`；session 被錄且 complete=true（F1 已修正） |
| L5 | 同一使用者、同一 gateway 連 A | 不錄影 |
| L6 | B 改成 `off` 並 apply | marker 變為 `=off`；連線為 metadata |
| L7 | 移除 B 的欄位並 apply | marker 消失；連線為 metadata |
| L8 | 手動在 B 建立 `pilot.policy.ssh-recording=banana` | deny `recording_policy_invalid`；target 上沒有任何 SSH 連線紀錄（沒做 Phase A） |
| L9 | 手動建立兩個 managed marker | connect deny；freeipa-client apply 在 mutation 前以 DUPLICATE fail |
| L10 | 手動建立 `Pilot.Policy.SSH-Recording=terminal_output` | connect deny；apply 以 MALFORMED fail |
| L11 | 手動加 `external-provisioning` foreign 值後改 B 的 policy 並 apply | foreign 值與 annotation 值不變 |
| L12 | B 為錄影主機，停止 session store | 出現 notice 後以 `recording_failed` 結束；target 上沒有 SSH 連線紀錄 |
| L13 | 錄影進行中讓 store 無法連線（fail_closed） | 約 `failure_grace` 後 session 被終止；有 `recording_failed`；replay 顯示 incomplete |
| L14 | 錄影 session 閒置 20 分鐘（明顯超過 900s start window + 60s skew，以及 3×failure_grace）後再輸入並結束 | session 存活；events 持續被 store 接受；complete=true（F7 與 §16.1 的 start window 都已修正） |
| L15 | (a) 用 L3 的 token 對另一個 sid 送 events；(b) finish 後再送 events；(c) 第二個使用者以 L3 session 的 sid 取得 token（`pilot-connect <同一 sid> <fqdn>`）後，對該 sid 送 events | (a) 403 `session_id_mismatch`；(b) 409 `session_finished`；(c) start 409、events 403 `claims_mismatch`，原錄影不受影響（token 不得寫入 evidence） |
| L16 | 手動在 B 建立 `pilot.policy.ssh-recording=terminal_io` | deny `recording_policy_invalid` |
| L17 | freeipa-client、gateway、session store 第二次 apply | 皆 `changed=0 failed=0` |
| L18 | store 狀態目錄放在 disposable loop filesystem，錄影中填滿磁碟 | ingest 失敗；`recording_failed`；session incomplete；fail_closed 終止 session；清掉 loop device。不得在 production／共用的 root filesystem 上做 |
| L19 | auditor 執行 replay 與 export | 出現 `recording_replayed`／`recording_exported` audit，且不含 payload；export 的 `.cast` 可用 asciinema 播放 |
| L20 | 在 gateway 以 root 執行 `pilot access recording show` 查 A 與 B；以非 root 執行一次 | A：inherit／metadata／built_in_default；B：terminal_output／host；非 root 被拒 |
| L21 | 分支 N：手動刪除 gateway 自己 host 上的 canary，再連 B 與 A；重新 apply gateway | 兩者都 deny `recording_policy_unavailable`；apply 後 canary 恢復，連線恢復正常。分支 R：改以 unit test 證明，本列記為 N/A 並寫明原因 |
| L22 | 以既有資料的 v1 store DB 升級到新版 store | 產生 `index.db.pre-v1.bak`（0600）；migration 後舊 session 仍可 list／replay；依 runbook 回滾程序還原後，舊 binary 可再次開啟；回滾後 FreeIPA 上沒有任何 `pilot.policy.ssh-recording=` marker，gateway 端連 B 為 metadata |

L8–L10、L12、L13、L16、L18、L21、L22 會刻意破壞 FreeIPA、store 或 DB 狀態，執行時需由使用者在該 session 中核准；coding agent 在執行前說明要做什麼、如何還原。

## 36. Required commands before completion

```bash
gofmt -l .                     # 必須沒有輸出
go vet ./...
go build ./...
go test -race -count=1 ./...
make lint                      # golangci-lint
python3 scripts/check-yaml-duplicate-keys.py
make playbook-lint
go run ./cmd/pilot spec docs/verification/pilot-access-gateway.md --lint
go run ./cmd/pilot spec docs/verification/pilot-session-store.md --lint
go run ./cmd/pilot spec docs/verification/pilot-access-directory.md --lint
go run ./cmd/pilot spec docs/verification/freeipa-client.md --lint
go test -count=1 -run TestShellSyntax ./internal/spec/
go run ./cmd/pilot contract lint
ansible-playbook --list-tags playbooks/apply/pilot-access-gateway-apply.yml
ansible-playbook --list-tags playbooks/apply/pilot-session-store-apply.yml
ansible-playbook --list-tags playbooks/apply/freeipa-client-apply.yml
```

不得只跑新增的 test package。完整 target test 依 AGENTS.md §1.5 以凍結的 candidate commit 從乾淨 checkout 執行。

## 37. Evidence

- `docs/evidence/pilot-access-gateway/<date>-phase0-userclass-capture.md`（Phase 0）
- `docs/evidence/pilot-access-gateway/<date>-per-host-session-recording.md`（Phase 8）：candidate commit／tree、topology、gateway recording 設定（不含 key）、A／B 的 source policy 與 FreeIPA raw marker、authorize response（token 以 `<redacted>` 取代）、L1–L22 verdict、idempotency、cleanup。
- 原始輸出只放 `.verification/`。evidence 中不得出現：signing key、PIT1 token、master key、Kerberos／`ipa_admin_password`、原始 terminal input。

## 38. Implementation phases

依相依性排序。每個 Phase 可獨立 merge（`go test -race -count=1 ./...` 保持綠燈），但 Phase 8 完成前不得部署到 staging／prod（§0.2 第 13 點）。每個 Phase 開始前先依 §33 寫好該 Phase 的 verification rows。

| Phase | 內容 | 完成條件 |
|---|---|---|
| 0 | §9：真實擷取 + GER 分支判定 | fixtures 已提交；evidence 記錄分支 R／N |
| 1 | §3、§5、§6、§25、§26：inventory schema、lint、generate、render、decommission hash、`pilot edit`、`set_host_field`、example、DELIVERY.md | §34.1、§34.2 綠燈 |
| 2 | §7、§8：FreeIPA projection task file、兩個 include 的 `apply: tags`、static regression、§33.4 文件 | §34.10 第 1–16 項綠燈；vm-target 通過 L2、L6、L7、L11，L9／L10 的「apply 在 mutation 前 fail」部分，以及 freeipa-client 的 L17（L9／L10 的 connect deny 部分在 Phase 8 驗） |
| 3 | §10–§12：policy parser（含被選中分支的 rights 或 canary 解析）、fake provider 更新（F33）、hostMetadataCache、`GatewayConfig.CanaryFQDN`（分支 N）、HostAccess／DirectoryTarget／Directory `TargetJSON` | §34.3 與 §34.4 綠燈（`TestDirectoryHostLabel_RecordingBadge` 除外，屬 Phase 6）；既有測試全綠 |
| 4 | store↔sink wire contract 與 recorder 可靠性：§16（ingesttoken，含 `jti`）、§21.1–§21.4（store 認證與綁定、migration v2 與自動備份、`last_seq`、trailing gap、finish／start idempotency、read API 新欄位）、§27.2（store playbook／contract／example）、§19.1–§19.3、§19.5、§19.6（Options、watchdog、backpressure、取消契約、completeness；`Terminal`／`InputDone` 可在此或 Phase 6 加入）、§19.7 的 `Finish`（`Write` 暫不改）、§20.1 的 finish body、§20.2 的錯誤分類與 retry（此時套用在單一 event 的 `Write` 與 start／finish） | §34.6 綠燈；§34.9 綠燈（`TestReadAPIAudits*`、`TestMetricsTextfile*` 除外，屬 Phase 7）；§34.7 中的 `TestRecorderFailClosed*`、`TestRecorderEnqueueReturnsAfterWriterStops`、`TestRecorderDrainTimeoutCancelsWriter`、`TestRecorderDefaultFailureGrace`、`TestRecorderBestEffort*`、`TestRecorderFinishCompleteOnlyWhenClean`、`TestRecorderAuditEventsCarryIdentity`、`TestHTTPSinkRetriesTransientSameBatch`（以單一 event 為 batch）、`TestHTTPSinkPermanentErrorNoRetry`、`TestHTTPSinkFinishCarriesLastSeq`；SS03、SS04、SS19–SS24、SS27 |
| 5 | §13–§15、§17、§27.1、§27.1a、§27.3、§27.4：`internal/gatewayconfig`、resolver、config（`fail_closed` 預設在這裡生效，Phase 4 已修好 watchdog）、authorize、token 簽發、canary task（分支 N）、access JSON、gateway playbook、site order、contract、example | §34.5 綠燈；AG37、AG41–AG49、AG56 |
| 6 | §18、§19.4、§19.7 的 `WriteBatch`、§22–§24：共用連線核心、connect 順序與「start 後失敗必 finish」、cancelable stdin 與 `Terminal`／`InputDone`、FileSink 移除、`pty.StartWithSize` 與 `InitialSize`、notice、Portal／Directory badge、batching、audit 欄位 | §34.7 中的 `TestHTTPSinkBatchingThresholds`、`TestRecorderInitialResizeIsFirstEvent`，以及 §34.8（`TestSessionExport_*`、`TestAccessRecordingShow_*` 除外，屬 Phase 7）與 `TestDirectoryHostLabel_RecordingBadge` 綠燈；AG50–AG54、AD31 |
| 7 | §21.5、§28、§29、§31：讀取 audit、asciicast export、`pilot access recording show`、metrics | `TestAsciicastExport*`、`TestSessionExport_*`、`TestAccessRecordingShow_*`、`TestReadAPIAudits*`、`TestMetricsTextfile*` 綠燈；AG55、AG57、SS25、SS26 |
| 8 | §35 L1–L22、§36、§37，以及 verification 文件的 live 摘要 | 全部通過並提交 sanitized evidence |

## 39. Acceptance criteria

- **AC1**：全新／預設設定下，沒有 host policy 的主機 = metadata，不產生任何 TerminalEvent，也不回傳 ingest credential。
- **AC2**：只有 `ssh_recording: terminal_output` 的主機被錄；同一 gateway 的其他主機不錄（L3、L5）。
- **AC3**：`off` 可 override 非 metadata 的 gateway default（`TestResolveRecordingMode`）。
- **AC4**：`terminal_io` 在 hosts.yml 被 lint 拒絕，在 FreeIPA 上則 deny（L16）。
- **AC5**：runtime policy 只來自 `pilot.policy.ssh-recording=`；Gateway 不讀 roster／inventory。
- **AC6**：host_show 失敗、policy 無法解析、userclass 不可讀（分支 R）或 canary 消失（分支 N）時 deny，不得默默不錄（L8–L10、L21、AG45、AG56）。
- **AC7**：互動式 Portal 與 Directory handoff 兩條路徑都遵守 effective mode（L3、L4）。
- **AC8**：Phase A 維持不錄影；store start 失敗時不對 target 建立 SSH（L12、AG51）。
- **AC9**：錄影只寫 pilot-session-store，不存在 local file fallback（AG52）。
- **AC10**：預設 failure policy 為 `fail_closed`；閒置健康、以及超過 start window（15 分鐘）的 session 都不會被誤殺；sink 卡住時 session 仍會在期限內終止（L13、L14、AG53）。
- **AC11**：metadata session 拿不到任何 ingest credential；terminal session 的 token 只能寫入自己這個 session（AG47、AG48、L15）。
- **AC12**：錄影 session 在 SSH 啟動前顯示 notice（AG54、L3）。
- **AC13**：FreeIPA foreign userClass 不被改動（L11）。
- **AC14**：source 移除 policy 後 managed marker 消失（L7）。
- **AC15**：check mode 零 mutation，並在全新主機上以 `--ephemeral` 驗證過。
- **AC16**：第二次 apply `changed=0`（L17）。
- **AC17**：任何已知遺失都是 `complete=false`，replay 顯示 `RECORDING INCOMPLETE`，含尾端 gap（SS22、L13）。
- **AC18**：disk-full live gate 完成（L18）。
- **AC19**：replay／export 留下 audit（L19、SS25）；asciicast export 可播放。
- **AC20**：`pilot access recording show` 與 metrics 依 §29、§31 運作（AG55、AG57、SS26、L20）。
- **AC21**：§36 全部指令綠燈。
- **AC22**：verification rows 與 sanitized evidence 已提交，且不含任何 secret。
- **AC23**：store schema migration 前自動備份，並能依 runbook 回滾（SS27、L22）。
- **AC24**：互動式 Portal 在 recorded session 結束後不遺留 stdin reader（`TestConnectToHost_NoStdinReaderLeftAfterRecordedSession`、L4 結束後回到 Portal 選單時按鍵正常）。

## 40. 變更紀錄

| 日期 | 版本 | 變更 |
|---|---|---|
| 2026-09-23 | rev 1 | 初版 |
| 2026-09-23 | rev 2 | 依 baseline 核對（§0.4 F1–F27）與使用者決策 D-A／D-B／D-C 修訂：host enum 限 off／terminal_output；新增 per-session ingest token（取代靜態 bearer token）；修正互動式 Portal 繞過錄影（F1）、gateway playbook 未串接 recording（F5）、fail_closed 誤殺閒置 session（F7）、completeness 固定為 true（F8）、store start 晚於 Phase A（F3）；拆出 `failure_grace`；新增 Phase 0 真實擷取與 GER 分支；移除 FileSink fallback；freeipa-client 不新增 row（F18）；metrics 改用 textfile collector；所有「可選／推薦」項目改為明確納入並定義規格；移除沒有依據的敘述（HTTPSink retry、`session_started`） |
| 2026-09-23 | rev 2.1 | 依獨立 review 與使用者決策 D-D／D-E／D-F 修訂：token 的 start window 只在 start 檢查（避免超過 5 分鐘的 session 全部失敗）；recorder 取消契約與 writer-stopped enqueue；互動 Portal 改用 cancelable stdin（F28）；policy zero value fail closed 並列出需更新的 fake（F33）；分支 N 改用 canary；`pilot access recording show` 改由 gateway root 執行並抽出 `internal/gatewayconfig`；migration 前自動備份；finish／start idempotency；asciicast 依 stream 串流解碼；`pty.StartWithSize`；resolver 使用原始 default（F29）；store site order 移到 gateway 之前（F30）；kinit 改用 `command` + `stdin`；Phase 0 fixture 依序擷取；Phase 表重排，讓 watchdog 修正早於 `fail_closed` 預設生效；補上 row 清單 regression test 與 tag 豁免表的更新 |
| 2026-09-23 | rev 2.2 | 第二輪 review 修正：PIT1 新增 `jti`，store 在 events／finish 比對已儲存的 claims 與 `jti`，防止他人以同一 sid 取得 token 後寫入或結束別人的錄影；互動路徑的 raw mode 改用獨立的 `Options.Terminal`，並新增 `InputDone()`；分支 N canary 經 `GatewayConfig.CanaryFQDN` 實作（Directory 不檢查）；分支 R 的 userclass 不可讀統一為 unavailable；connect 順序明定 authorize → `credentials.Ensure` → notice → start，start window 改為 900s，start 後任何失敗都必須送出 incomplete finish；finish idempotency 只比對 `ended_at` 與 `last_seq`；回滾程序補上 config、vault 舊 token 與 gateway；migration 新增 `ingest_jti` 欄位；Phase 表的完成條件只包含該 Phase 交付的測試，retry／錯誤分類移到 Phase 4 |
| 2026-09-23 | rev 2.3 | 一致性修正：`start_window_closed` 有專屬 401 body；start window 測試點移到 skew 之外（`iat+1000s`、L14 閒置 20 分鐘）；`jti` 格式驗證、唯一性測試並納入 AG48；finish 的 `ended_at` 改為必填 RFC3339Nano 並以 UTC 時間比較；`FinishInfo.Reason` 補上 `session_start_failed`／`internal_error`；PTY 大小改由 `Options.Terminal` 取得；AG56 分支 R 改為只 deny 該 host；回滾前必須先移除所有 marker，避免舊 gateway 靜默不錄；Phase 2 只要求 §34.10 第 1–16 項；列出必須改寫的 `TestRunPortalOneShotConnect_RecordingEnabledSkipsPlainPath`；canary 測試移到 §34.4；修正行號引用 |
