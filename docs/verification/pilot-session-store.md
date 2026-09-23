# Verification Spec — Pilot Session Store

> 版本：v1.0（2026-09-18：Phase 8 landing gate 已對新建的 `ag-sessionstore01`
> vm-target 全部真實跑過，見
> [`docs/evidence/pilot-access-directory/2026-09-18-phase8-session-store.md`](../evidence/pilot-access-directory/2026-09-18-phase8-session-store.md)——
> 含真實 fresh topology E2E(真 Gateway → HTTPSink → ingest → `pilot session
> replay`)、SS13 兩個方向(auditor 成員允許/非成員在 socket 層即被拒)、
> store restart 資料保存。仍有兩項 spec.md §44 landing gate 項目未在活體
> 環境模擬(disk full、對真實 DB 檔案的 corrupt payload 獨立活體重驗——後者
> 已有 unit test 涵蓋，見 evidence doc「Known gaps」一節)，比照
> AGENTS.md §5.6 誠實記錄，不假裝已驗收)
> v1.1（2026-09-23）：per-host recording spec Phase 4——ingest 改用 per-session
> PIT1 token（SS03/SS04 改寫，新增 SS19–SS24、SS27）、schema v2 migration 與
> 升級前自動備份、finish 帶 `last_seq` 偵測尾端遺失。fresh-host `--check --diff`、
> apply、第二次 apply `changed=0` 與 PIT1 活體 ingest 見
> `docs/evidence/pilot-access-gateway/2026-09-23-phase4-session-store-ingest-token.md`。
> 對齊規範：docs/tmp/now/spec.md §28-§29/§35（Pilot Access Directory、
> Gateway Handoff 與 SSH Session Recording 實作規格）；
> `docs/superpowers/specs/2026-09-23-pilot-access-gateway-per-host-session-recording-spec.md`
> §16/§21/§27.2
> 維護者：sre
>
> 2026-09-23 per-host recording Phase 7：新增 SS25（replay／export audit）與 SS26（metrics textfile）；candidate `31f5c23` 對 `phr-store` 實跑 SS24／SS26 probe PASS、第二次 apply `changed=0`，並以 root（非 auditor）觸發 replay 確認 `recording_replayed` denied audit event，見 [`docs/evidence/pilot-access-gateway/2026-09-23-phase7-read-audit-export-metrics.md`](../evidence/pilot-access-gateway/2026-09-23-phase7-read-audit-export-metrics.md)。

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Inventory group | `pilot-session-store`（或明確 `target_group`） |
| 角色 | terminal recording 的獨立、optional、stateful persistence backend：加密 durable index(`internal/sessionstore`)+ TLS-mandatory ingest API(`pilot-access-gateway` 的 `HTTPSink` 送 event 進來)+ 獨立 Unix socket 的 admin read/replay API(`pilot session list/show/replay`)。從不參與授權決策——只是已經被 Gateway 決定要收的 session 的啞巴、append-only 記錄器 |
| 前置需求 | 已是 FreeIPA client（`freeipa-client-apply.yml`）且有轉發 DNS 記錄——這台主機自己的機器 keytab 是 `ipa-getcert` 核發 ingest TLS 憑證的基礎（trust `/etc/ipa/ca.crt`，spec.md §28.2），不需要走 admin 密碼 |
| 套用範圍 | 一台以上的 Session Store 主機安裝（`hostCardinality: one-or-more`）；這台主機從不是 SSH portal ingress——沒有 ForceCommand、沒有 HBAC rule |
| 風險等級 | **High（stateful，持有已加密但仍是唯一副本的 terminal recording；遺失 = 永久遺失稽核紀錄）** |

## 1.5 依賴變數契約

| 變數名稱 | 說明 | 必填 |
|---|---|---|
| `session_store_fqdn` | 明確指定 FQDN；未填則用 `ansible_fqdn` | 否 |
| `ipa_admin_password` | vault 提供，only used at apply-time 建立 `role-pilot-session-auditor` group，從不落地在這台主機上 | 是（secret） |
| `pilot_binary_path` / `pilot_session_store_binary_path` | 本機建置好的二進位路徑 | 是 |
| `pilot_session_store_retention_days` | 保留天數，無內建預設值(spec.md §28.5 明確禁止硬編碼公司 policy) | 是 |
| `pilot_session_store_key_id` | 加密金鑰識別碼(metadata，不是金鑰本身) | 是 |
| `pilot_session_store_master_key` | AES-256 master key，64 hex 字元，vault 提供 | 是（secret） |
| `pilot_session_store_ingest_signing_key` | per-session ingest token（PIT1）的 HMAC signing key，64 hex 字元，vault 提供；與 pilot-access-gateway 使用同一個值（per-host recording spec §16）。取代舊的 `pilot_session_store_ingest_token`（已移除） | 是（secret） |
| `pilot_session_store_ingest_port` | ingest HTTPS 監聽 port，預設 8443 | 否 |

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| SS01 | config | config `KnownFields(true)`，未知欄位 fail — 由 `cmd/pilot-session-store` 的 `TestLoadConfigRejectsForbiddenFields` 涵蓋，非單一 shell 指令 | 0 | true |
| SS02 | ingest | ingest API 僅 TLS，真的能用 FreeIPA CA 驗證 | 0 | sh -c 'curl --silent --show-error --cacert /etc/ipa/ca.crt --max-time 5 --output /dev/null --write-out "%{http_code}" https://$(hostname -f):8443/v1/sessions/start \| grep -qE "^[45][0-9][0-9]$"' |
| SS03 | ingest auth | ingest API 只接受有效的 per-session PIT1 token（per-host recording spec §16/§21.2）；缺少、格式錯誤、簽章錯誤、過期、kid 不符（含舊式靜態 bearer）一律 401 — `cmd/pilot-session-store` 的 `TestIngestAPIRejectsInvalidSessionToken` 涵蓋，需要第二個未授權的 client，非單一 host 指令 | 0 | true |
| SS04 | 權限分離 | ingest signing key 與 PIT1 token 完全沒有 read/replay 能力（不同 listener，read API 從不載入 signing key）— 結構性不存在，非單一 host 指令 | 0 | true |
| SS05 | read socket | read/replay API 僅 Unix socket 存在 | 0 | test -S /run/pilot-session-store/session-store.sock |
| SS06 | idempotency | ingest 同 seq 重送、payload 相同 → no-op success — `internal/sessionstore` 的 `TestStoreIngestIdempotentRetry` 涵蓋，非單一 shell 指令 | 0 | true |
| SS07 | idempotency | ingest 同 seq 重送、payload 不同 → conflict — `internal/sessionstore` 的 `TestStoreIngestConflictingRetryFails`/`TestStoreStartSessionConflict` 涵蓋，非單一 shell 指令 | 0 | true |
| SS08 | encryption | payload at rest 不是 plaintext — 見 §4 活體檢查(直接 `strings` index.db，不能找到已知明文標記字串);`internal/sessionstore` 的 `TestStoreReplayTamperedCiphertextFails` 已證明存的是 AEAD ciphertext 不是原文 | 0 | true |
| SS09 | encryption | master key file mode 非 0600 時拒絕啟動 — `internal/sessionstore` 的 `TestLoadMasterKeyFile_RejectsWorldReadable` 涵蓋 | 0 | true |
| SS10 | retention | `retention_days` 缺值/非正整數時 apply 直接 fail — pre_tasks assert，非單一 shell 指令 | 0 | true |
| SS11 | retention | retention sweep：先更新 index 再刪 payload——`internal/sessionstore` 的 `TestStoreDeleteSessionPayloadRetentionOrder`；只清掉過期的 session——`cmd/pilot-session-store` 的 `TestRunRetentionSweepPurgesOnlyOldSessions` | 0 | true |
| SS12 | replay | sequence 有缺口時回報 gap（`RECORDING INCOMPLETE`）— `internal/sessionstore` 的 `TestStoreReplayDetectsGap` 涵蓋 | 0 | true |
| SS13 | read authz | 非 `role-pilot-session-auditor` 成員呼叫 read socket 一律拒絕 — **部分涵蓋，見下方說明，非單一 host 指令** | 0 | true |
| SS14 | idempotency | 第二次 apply changed=0（多次重跑的性質，由 evidence doc 記錄） | 0 | true |
| SS15 | staging/prod gate | stage gate 符合 repo policy — apply playbook 的 `pre_tasks` assert | 0 | true |
| SS16 | site-wide | site-wide deploy 實際跑到這個 component，不是假 success | 0 | true |
| SS17 | stateless-except | 除了宣告的 state dir，restart 後不會在別處留下狀態 | 0 | test -d /var/lib/pilot-session-store && sh -c '! find / -xdev -maxdepth 3 -name "pilot-session-store*" -not -path "/etc/pilot/*" -not -path "/var/lib/pilot-session-store*" -not -path "/usr/local/libexec/*" -not -path "/etc/systemd/system/*" 2>/dev/null \| grep -q .' |
| SS18 | topology | fresh vm-target topology E2E PASS（真實 Gateway → HTTPSink → ingest → `pilot session replay`）— 見 §4，本 checklist 尚未執行過 | 0 | true |
| SS19 | ingest binding | start 的 body 必須逐欄等於 token claims（session_id/user/gateway_id/scope/target/recording_mode），否則 403 `claims_mismatch`；`directory_id` 非空 → 400 `unbound_field`（未被 token 綁定的欄位不可信）— `TestIngestAPIStartMustMatchClaims` | 0 | true |
| SS20 | ingest binding | events/finish 的 path id 必須等於 token sid（否則 403）、event 的 session_id 必須等於 path（否則 400）；同一 sid 但 claims 或 `jti` 與已儲存的不同 → 403 `claims_mismatch`（sid 可由使用者指定，不是秘密）；已存在且未 finish 的 sid 以不同 `jti` start → 409 — `TestIngestAPISessionIDBinding`、`TestIngestAPIRejectsOtherUsersTokenForSameSID`、`TestIngestAPIRejectsSecondTokenForSameSID` | 0 | true |
| SS21 | finish | finish 後的 events 與 start 一律 409 `session_finished`；finish 必須帶 RFC3339Nano `ended_at` 與 `last_seq`，重送相同 `ended_at`/`last_seq` 為 idempotent — `TestIngestAPIRejectsEventsAfterFinish`、`TestIngestAPIFinishIdempotentRetry`、`TestIngestAPIFinishRequiresEndedAt`、`TestIngestAPIFinishRequiresLastSeq` | 0 | true |
| SS22 | completeness | finish 的 `last_seq` 揭露尾端遺失：`[1,last_seq]` 內任何缺口或最大已存 seq ≠ last_seq → complete=false，replay 列出尾端 gap — `internal/sessionstore` 的 `TestStoreFinishDetectsTrailingGap` | 0 | true |
| SS23 | schema | v1 DB 升級到 v2（新增 `recording_policy_source`、`last_seq`、`ingest_jti` 三欄）後既有資料完整保留 — `internal/sessionstore` 的 `TestStoreMigratesV1ToV2` | 0 | true |
| SS24 | secrets | ingest signing key 檔為 `pilot-session-store:pilot-session-store 400`，且舊的靜態 bearer token 檔已不存在 | 0 | test "$(stat -c '%U:%G %a' /etc/pilot/session-store-ingest-signing.key)" = "pilot-session-store:pilot-session-store 400" && test ! -e /etc/pilot/session-store-ingest.token |
| SS25 | read audit | 每個 replay／export 請求（成功或失敗）都以 `pilot-session-store` 發出 `recording_replayed`／`recording_exported` audit event，帶 auditor 與被錄 session 的身分，不含任何 terminal payload；`?purpose=` 只影響 audit kind — `TestReadAPIAuditsReplayAndExport` | 0 | true |
| SS26 | metrics | node_exporter textfile 目錄存在時寫出 0644 的 `pilot_session_store.prom`，含 `pilot_session_store_ingest_requests_total`；目錄不存在時不寫（metrics 是 soft 功能） | 0 | f=/var/lib/node_exporter/textfile/pilot_session_store.prom; if test -d /var/lib/node_exporter/textfile; then grep -q '^# TYPE pilot_session_store_ingest_requests_total counter$' "$f" && test "$(stat -c %a "$f")" = 644; else test ! -e "$f"; fi |
| SS27 | schema | 既有 v1 DB 升級前先以 `VACUUM INTO` 產生 `index.db.pre-v1.bak`（0600）；剩餘空間不足 2× DB 或備份檔已存在時不 migrate、啟動失敗 — `TestStoreMigrationBacksUpBeforeAlter`、`TestStoreMigrationRefusesWithoutSpace`、`TestStoreMigrationRefusesExistingBackup` | 0 | true |

## 3. 不在這份 checklist 逐行覆蓋、但已用其他方式驗證過（或該用其他方式驗證）的項目

- **SS04 ingest token 與 read/replay 完全分離**：架構性——`cmd/pilot-session-store/ingest_api.go` 與 `read_api.go` 是完全不同的 `http.Server`／不同的 listener（TLS TCP vs Unix socket）／不同的 auth 機制（bearer token vs SO_PEERCRED+group），程式碼裡沒有任何共用的 credential 檢查路徑。
- **SS08 payload at rest 加密**：`internal/sessionstore/encryption.go` 的 `Encryptor.seal`/`open`（AES-256-GCM，per-event unique nonce，AAD 綁 session_id/seq/stream）+ `store_test.go` 的加密往返測試；活體檢查留給 §4（直接讀 index.db 的 bytes，確認找不到已知明文內容）。
- **SS13 read socket authz**：`cmd/pilot-session-store/read_api.go` 的 `authorizedPeer`（SO_PEERCRED 解出 UID → `internal/identity.LookupUsername` → `internal/identity.IsMemberOfGroup`），與 `internal/directoryapi`/`internal/gatewayapi` 同一套身分鏈，非本元件獨有邏輯。單元測試涵蓋範圍：`TestReadAPIUnknownAuditorGroupFailsClosed` 驗證「auditor group 完全不存在 → deny」，`TestReadAPINoAuditorGroupAllowsAnyPeer` 驗證「沒設定 auditor_group → 允許任何人」——兩者都不是「group 存在、呼叫者不是成員 → deny」這個 SS13 真正宣稱的情境，這個子情境本 repo 沒有任何單元測試涵蓋（`internal/directoryapi`/`internal/gatewayapi` 的同構測試也一樣沒有）。**2026-09-18 已用兩個真實系統帳號活體驗證補上這個缺口**（`alice` 在 group 裡→允許，`bob` 不在→在 socket 檔案權限層就被拒絕，見 evidence doc），單元測試本身仍未補上（活體驗證不能取代它，只是暫時填補這個 repo 目前對這個情境完全沒有自動化驗證的洞）。

## 4. Landing gate 活體驗收記錄

2026-09-18 對新建的 `ag-sessionstore01` vm-target（FreeIPA client，enrolled 到既有 `ag-spike-ipa` realm）跑過全部下列項目，見
[`docs/evidence/pilot-access-directory/2026-09-18-phase8-session-store.md`](../evidence/pilot-access-directory/2026-09-18-phase8-session-store.md)：

- **SS02/SS05**：完整 apply 跑過，ingest TLS 憑證真的用 `ipa-getcert` 核發、read socket 真的在正確路徑存在（活體 curl/`stat` 探測，非只有 apply playbook 自己的 capability probe）。
- **SS03/SS06**：真實 ingest 呼叫——錯 token 401、重送同一筆 event 200(no-op)。
- **SS08**：對已跑起來的 store 送一筆真實 event 後，直接對 `/var/lib/pilot-session-store/index.db` 做 `grep -c`，確認明文標記字串完全找不到。
- **SS12**：刻意跳號(seq=1,3 漏 2)後 `pilot session replay` 印出 `*** RECORDING INCOMPLETE ***`。
- **SS13**：見上方 §3 的補充說明——兩個真實系統帳號都測過。
- **SS14**：連續 apply 兩次，第二次 `changed=0`。
- **SS16**：透過 `playbooks/site.yml --tags freeipa,pilot-session-store` 跑，元件的 play 確實有執行(非 skip)。
- **SS18**：真實 `alice` 密碼登入 → `pilot-connect` → Gateway(`ag-gw01`)recorder → `HTTPSink` → TLS ingest → `pilot session replay`，內容逐字元一致(含 `whoami`→`alice`、自訂 marker 字串)。
- 額外(spec.md §44 landing gate 明列但不對應單一 SS 編號)：**store restart** 後既有 session 仍完整可列可重播。

**仍未在活體環境驗證**（spec.md §44 landing gate 明列，見 evidence doc「Known gaps」一節誠實記錄，不假裝已驗收）：

- **disk full**：未模擬——需要獨立 loop device 或填滿共用 vm-target 的真實根磁碟，風險/設置成本超過這次驗收的範圍。
- **corrupt payload 活體重驗**：`TestStoreReplayTamperedCiphertextFails` 已在單元測試層級驗證過(竄改 ciphertext byte 會讓 AES-GCM 認證失敗)，但沒有對活體 DB 檔案獨立重跑過。

## 5. Gotcha 記錄

- **read socket 不能沿用 Gateway/Directory 共用的 `/run/pilot`**：Gateway/Directory 的 socket 是透過 systemd `.socket` unit 的 `SocketUser`/`SocketGroup`/`SocketMode` 取得決定性權限；`pilot-session-store` 的 read API 是 Go process 自己直接 `net.Listen("unix", ...)`，沒有 socket activation。如果沿用共用的 `/run/pilot`（可能已經被 Gateway/Directory 的某個 unit 用**它們自己的** User/Group 建立過），這個 process 可能連 bind 都會因為目錄權限被拒絕。改用專屬的 `RuntimeDirectory=pilot-session-store` + `UMask=0007` + service unit 的 `Group=role-pilot-session-auditor` 三者搭配，才能讓 auditor group 成員真的連得上這個 socket（Unix domain socket 的 `connect()` 需要對 socket 檔案有 write 權限，不是只要 read/search）。
- **`ipa-getcert request` 的 argv 陷阱**：沿用 `playbooks/apply/tasks/internal-endpoint-cert-request.yml` 已經踩過的坑——一定要用 `argv:`（list）不能用 free-form 字串（`-C` 的值含空白會被 shlex 截斷）；`-o`/`-O` 是單一 `user:group` 字串，不是分開的 group flag；`-w` 會同步等到憑證核發完成，不需要另外寫 poll-until-issued 迴圈。
- **每次要對新 binary 做活體測試前，先確認 `dist/pilot-linux-amd64`/`dist/pilot-session-store-linux-amd64` 是用當下 HEAD 重新建置的**——舊 binary 不會有新加的子指令，容易誤判成程式碼本身的 bug（Phase 4/7 都踩過同一個坑）。

## 6. 明確不在本 repo 範圍的項目

- 站台網路層需求（防火牆/network policy 限制 ingest API 的來源網段只允許 Gateway 主機）：比照 `pilot-access-gateway.md` 的 AG31，是站台網路團隊的責任，不是本 repo 的程式行為。
- 加密金鑰的實際保管/輪替流程（HSM、金鑰託管服務）：spec.md §28.4 只要求「vault 提供、config 只 reference key file/key ID」，金鑰本身的生命週期治理不在本 repo 範圍。
