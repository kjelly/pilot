# Verification Spec — Pilot Access Gateway

> 版本：DRAFT v0.8（2026-09-23：per-host SSH session recording Phase 5——gateway 依 host policy 解析 effective recording mode、簽發 per-session PIT1 ingest token，新增 AG41–AG49、AG56，改寫 AG37；Phase 6 再新增 AG50–AG54（互動式 Portal 與 Directory handoff 共用同一個連線核心），Phase 7 再新增 AG55（metrics textfile）與 AG57（`pilot access recording show`），candidate `31f5c23` 已對 `phr-gw`／`phr-store` 實跑（textfile 目錄存在與不存在兩種情形的 AG55 probe 皆 PASS、第二次 apply `changed=0`），見 [`docs/evidence/pilot-access-gateway/2026-09-23-phase7-read-audit-export-metrics.md`](../evidence/pilot-access-gateway/2026-09-23-phase7-read-audit-export-metrics.md)，見 `docs/superpowers/specs/2026-09-23-pilot-access-gateway-per-host-session-recording-spec.md`；candidate `e50827d` 已對 vm-target `phr-gw` 實跑：fresh `--check --diff` `failed=0`、apply 後第二次 `changed=0`、AG41–AG43 probe PASS，見 [`docs/evidence/pilot-access-gateway/2026-09-23-phase5-gateway-recording-policy.md`](../evidence/pilot-access-gateway/2026-09-23-phase5-gateway-recording-policy.md)；以下為 v0.7 之前的紀錄：vm-target 已對 AG01-AG30 實測；AG31 為站台網路層需求，非本 repo 範圍，見 §5；AG32-AG33 的 Portal session-scoped `kinit` / GSSAPI-only Connect 已於 2026-09-16 完成 vm-target + trec E2E，見 [`docs/evidence/pilot-access-gateway/2026-09-16-portal-session-ticket.md`](../evidence/pilot-access-gateway/2026-09-16-portal-session-ticket.md)；2026-09-14 追加：`pilot_access_gateway_install_forcecommand` 預設改為 `true`；2026-09-15 追加：`site.include` 改為 `true`，不再是 single-component-only，見 §5；2026-09-16 追加：`pilot_access_gateway_portal_automember` 預設也改為 `true`——兩者相加，FreeIPA 帳號登入這台 gateway 預設就是「只能進 portal，拿不到 shell」，不需要額外傳參數，見 §5；2026-09-18 追加：每次 apply 現在也會把這台 gateway 自己發布進 `pilot-gateway-<gateway_scope>`，供 `pilot-access-directory` 路由用，見 §5；2026-09-18 再追加：ForceCommand wrapper 改 exec `pilot portal-session`，新增 `pilot-connect <session-id> <fqdn>` one-shot handoff dispatcher，AG34-AG40；同日稍後已完成真實 vm-target 活體驗證——`alice` 經 Directory（`ag-directory01`）分別 handoff 到 GPU Gateway（`ag-gw01`→`ag-target01`，`whoami`=alice）與 DMZ Gateway（`ag-gw02`→新建的 `ag-target02`，`whoami`=alice），以及把 dmz target 的 `pilot-connect` 直接送去 GPU gateway 被正確 deny（wrong-scope injection），見 [`docs/evidence/pilot-access-directory/2026-09-18-phase5-gateway-handoff.md`](../evidence/pilot-access-directory/2026-09-18-phase5-gateway-handoff.md)）
> 對齊規範：docs/superpowers/specs/2026-09-14-pilot-access-gateway-stateless-freeipa-portal-spec.md（Pilot Access Gateway — Stateless FreeIPA-backed Portal），§50-§58
> 維護者：sre

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Inventory group | `pilot-access-gateway`（或明確 `target_group`） |
| 角色 | stateless、read-only、FreeIPA-backed SSH/sudo access gateway 後端（`pilot-access-gateway.service`）+ 使用者 TUI 入口（`pilot portal`）；Portal 可在 session 內短暫取得使用者 TGT，但不得保存密碼或 persistent ccache |
| 前置需求 | 已是 FreeIPA client（`freeipa-client-apply.yml`）且有轉發 DNS 記錄；主機具備 `kinit`/`klist`/`kdestroy`；`pilot-target-<scope>` hostgroup 已由 `pilot gateway-scope reconcile` 建立（Phase 6）。Portal 使用者群組（`gateway_portal_user_group`）與 `pilot-access-gateway-login` HBAC rule **不再需要操作者手動用 freeipa-identity roster 預先建立**——2026-09-15 起本 playbook 自己 idempotent 建立兩者（見 §5 gotcha），只有「群組成員（誰是 portal user）」仍是 roster 管的身分資料 |
| 套用範圍 | 單一 gateway 主機的安裝；`pilot_access_gateway_install_forcecommand` **預設已改為 `true`**（2026-09-14，在 §55.1 鎖定回歸測試已於 Phase 8 對 disposable vm-target 跑過並取得核准之後）——沒有明確帶 `-e pilot_access_gateway_install_forcecommand=false` 就會安裝 ForceCommand。**2026-09-15 起 `site.include: true`，不再是 single-component-only**：把 `pilot-access-gateway` 加進某台主機 `hosts.yml` 的 roles 清單，本身就是操作者的核准動作，之後每次全站部署（`playbooks/site.yml`）都會照常套用這個角色，跟其他角色（`docker`/`freeipa-client`……）的語意一致，不需要每次額外打 `--tags pilot-access-gateway`。§0 G4/§55.1 的規則本身沒有變——**只是核准時機點從「每次部署都要重新確認」改成「第一次把這個 role 加進某台主機的當下」**：把 role 加進 `hosts.yml` 之前，仍然要先在該主機（或同等的 disposable vm-target）跑過鎖定回歸測試，之後才能放心讓它隨全站部署自動套用 |
| 風險等級 | **High（預設即安裝 ForceCommand，登入路徑劫持等級變更；2026-09-16 起 `pilot_access_gateway_portal_automember` 也預設 `true`，兩者相加代表「每個 FreeIPA 帳號」預設都會被劫持進 portal，不再只有 roster 明確列名的人）**——要暫時退回舊的 opt-in 行為，明確帶 `-e pilot_access_gateway_install_forcecommand=false` 和/或 `-e pilot_access_gateway_portal_automember=false` |

## 1.5 依賴變數契約

| 變數名稱 | 說明 | 必填 |
|---|---|---|
| `gateway_id` | 這台 gateway 的 instance id，例如 `gpu-01` | 是 |
| `gateway_scope` | scope 名稱，決定 `pilot-target-<scope>` | 是 |
| `gateway_fqdn` | 這台 gateway 的 FQDN；預設 `ansible_fqdn` | 否 |
| `freeipa_servers` | FreeIPA server FQDN 清單（JSON list，見下方 gotcha） | 否，**2026-09-15 起自動從 `group_vars/freeipa.yml` 的 `freeipa_domain`（或 `freeipa_server_fqdn`）推導**，慣例是 `ipa1.<domain>`——跟 `freeipa-client-apply.yml` 自己用的推導慣例一致（同一份 inventory 上其他 freeipa-client 主機已經用這個慣例 enroll 成功，代表這個值對這個站台是對的）；只有主機名不照慣例時才需要明確填 |
| `ipa_realm` | Kerberos realm，例如 `IPA.PILOT.INTERNAL` | 否，**2026-09-15 起自動從 `freeipa_domain`（或 `freeipa_realm`）推導成大寫**，同上 |
| `ipa_admin_password` | 只在**安裝當下**用來建立 reader service principal + keytab；只能來自 vault，執行期完全不用 | 是 |
| `pilot_binary_path` / `pilot_access_gateway_binary_path` | 本機已建置好的兩個 binary 路徑 | 是 |
| `gateway_portal_user_group` | Portal 使用者群組；本 playbook 會自己 idempotent 建立這個**真正的 FreeIPA 群組**（絕不是 local fallback，見 §5 gotcha）——但群組**成員**（誰是 portal user）仍是 roster 管的身分資料，不由本 playbook 填 | 否，預設 `role-pilot-portal-user` |
| `pilot_access_gateway_install_forcecommand` | 是否安裝 sshd ForceCommand；§55.1 鎖定回歸測試通過前必須是 `false` | 否，**預設 `true`**（2026-09-14 起；§55.1 已在 Phase 8 通過） |
| `pilot_access_gateway_portal_automember` | **預設 `true`**（2026-09-16 起）：本 playbook 自己在 `gateway_effective_portal_user_group` 上建立 FreeIPA automember rule（`uid=.*`），讓每個 FreeIPA 帳號自動成為 portal 使用者，不用在 freeipa-identity roster 逐一列名單——跟預設已開的 `pilot_access_gateway_install_forcecommand` 相加，「FreeIPA 帳號登入這台 gateway 只能進 portal、拿不到 shell」是預設行為，不需要額外傳參數。要改回「只有 roster 明確列出的人才是 portal 使用者」，明確帶 `-e pilot_access_gateway_portal_automember=false`；設回 `false` 不會自動撤銷已建立的 automember rule（比照 `gateway_portal_user_group`/HBAC rule 的 additive-only 原則，見 §5 gotcha） | 否，**預設 `true`** |
| `pilot_access_gateway_portal_automember_exclude_users` | `pilot_access_gateway_portal_automember` 為 `true` 時，永遠不自動加入 portal 群組的帳號清單（見 §5 gotcha：`admin` 的 break-glass 例外） | 否，預設 `["admin"]` |
| `pilot_session_recording_mode` | gateway 預設 recording mode（`metadata`／`terminal_output`／`terminal_io`）。**刻意沒有預設值**：未設定時 config 不寫 `mode:`，gateway 用 built-in `metadata`，resolver 的 source 為 `built_in_default`；host 的 FreeIPA `pilot.policy.ssh-recording` marker 會覆蓋它（per-host recording spec §4）。terminal mode 需要 `pilot_session_store_url` | 否 |
| `pilot_session_recording_failure_policy` | `fail_closed`（store 無法確認寫入時結束 session）或 `best_effort`（繼續連線但把錄影標為 incomplete）；對 metadata session 無效果 | 否，預設 `fail_closed` |
| `pilot_session_recording_queue_events` / `_flush_interval` / `_failure_grace` / `_max_session_duration` | recorder queue 大小、batch 最長等待、fail_closed 的寬限期（≥1s 且 ≥2×flush_interval）、ingest token lifetime（1h–168h） | 否，預設 `1024` / `500ms` / `10s` / `24h` |
| `pilot_session_store_url` | `pilot-session-store` 的 ingest URL，必須是 `https://`；未設定時 gateway 不簽發任何 ingest token，effective mode 為 terminal 的連線一律 deny `recording_backend_unavailable` | 否 |
| `pilot_session_store_ca_file` | 驗證 store TLS 憑證用的 CA | 否，預設 `/etc/ipa/ca.crt` |
| `pilot_session_store_ingest_signing_key` | PIT1 ingest token 的 HMAC signing key（64 個 hex 字元），必須與 `pilot-session-store` 的同名變數相同；只能來自 vault，安裝成 `/etc/pilot/session-store-ingest-signing.key`（0400） | 設定 `pilot_session_store_url` 時必填 |

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| AG01 | config | gateway config 含 id/scope/target_hostgroup | 0 | grep -q "id: gpu-01" /etc/pilot/access-gateway.yaml && grep -q "scope: gpu" /etc/pilot/access-gateway.yaml && grep -q "target_hostgroup: pilot-target-gpu" /etc/pilot/access-gateway.yaml |
| AG02 | identity | pilot-gateway service account存在 | 0 | id pilot-gateway |
| AG03 | keytab | service keytab owner/mode正確 | 0 | test "$(stat -c '%U:%G %a' /etc/pilot/pilot-access-gateway.keytab)" = "pilot-gateway:pilot-gateway 400" |
| AG04 | freeipa | FreeIPA CA存在 | 0 | test -s /etc/ipa/ca.crt |
| AG06 | freeipa | FreeIPA JSON-RPC ping（透過 /v1/health） | 0 | sh -c 'v="$(curl -fsS --unix-socket /run/pilot/access-gateway.sock http://localhost/v1/health)" || exit; case "$v" in *"\"freeipa\":\"reachable\""*) exit 0;; *) exit 1;; esac' |
| AG09 | socket | Unix socket name/mode/group正確 | 0 | test "$(stat -c '%U:%G %a' /run/pilot/access-gateway.sock)" = "pilot-gateway:role-pilot-portal-user 660" |
| AG12 | scope | configured target hostgroup存在 | 0 | sh -c 'v="$(curl -fsS --unix-socket /run/pilot/access-gateway.sock http://localhost/v1/health)" || exit; case "$v" in *"\"target_scope\":\"ok\""*) exit 0;; *) exit 1;; esac' |
| AG19 | stateless | 沒有 local DB/state | 0 | test ! -d /var/lib/pilot |
| AG30 | idempotency | 第二次 apply changed=0(多次重跑的性質,由 evidence doc 記錄,非單一 shell 指令可驗證) | 0 | true |
| AG32 | ssh-policy | Portal Connect 只允許 GSSAPI，不委派 TGT 到 target，也不退回 password/kbd-interactive/pubkey | 0 | bash -c 'v="$(ssh -G -F /etc/pilot/ssh_config target.invalid 2>/dev/null)" || exit; has() { grep -qx "$1" <<< "$v"; }; has "gssapiauthentication yes" && has "gssapidelegatecredentials no" && has "preferredauthentications gssapi-with-mic" && has "batchmode yes" && has "passwordauthentication no" && has "kbdinteractiveauthentication no" && has "pubkeyauthentication false"' |
| AG33 | kerberos | Portal session ticket helper 依賴的 Kerberos client binaries存在 | 0 | test -x /usr/bin/kinit && test -x /usr/bin/klist && test -x /usr/bin/kdestroy |
| AG34 | handoff | ForceCommand wrapper 已改為 exec `pilot portal-session`（Phase 5 dispatcher），不再是舊版永遠互動的 `pilot portal` | 0 | grep -q 'exec /usr/bin/pilot portal-session' /usr/local/libexec/pilot-session |
| AG35 | handoff | 合法 `pilot-connect <uuid> <fqdn>` 語法可被解析、不再落入舊版「忽略 SSH_ORIGINAL_COMMAND、一律進互動 TUI」行為 — 由 `TestParsePortalSSHOriginalCommand_ValidConnect` 涵蓋，非單一 shell 指令；活體「一路連到真實 target」驗證見 §6 | 0 | true |
| AG36 | handoff | 任意/畸形指令一律 deny，不再靜默落回互動 TUI（spec.md D7「其他全部拒絕」，Phase 5 的行為變更） — 由 `TestParsePortalSSHOriginalCommand_Rejects`（涵蓋 shell metacharacter、`user@host`、IP literal、leading `-`、trailing `.`、embedded newline、錯誤 token 數、非法 UUID、Directory 自己的 `pilot-directory-connect` 語法）；活體 SSH 探測見 §7/`scripts/pilot-access-gateway-lockout-test.sh` 涵蓋，非單一 shell 指令 | 0 | true |
| AG37 | handoff | `session_id` 不影響 HBAC／scope 決策（spec.md §17.2：不把 session ID 當 proof）；只在 effective recording mode 為 terminal 時要求它是合法 UUID，並綁進 ingest token（per-host recording spec §17） — 由 `TestRunPortalOneShotConnect_Allowed`／`_Denied`（authorize 結果只取決於 target 是否在 scope 內）與 `internal/gatewayapi` 的 `TestConnectAuthorize_SessionIDOnlyBindsToken`（空、非 UUID、合法 UUID 三種 sid 對 metadata 連線結果相同、都不能讓 scope 外 target 變成 allow；terminal mode 下非 UUID 一律 deny `recording_session_id_invalid`） 涵蓋，非單一 shell 指令 | 0 | true |
| AG38 | handoff | one-shot connect 仍是每次呼叫都 fresh authorize，從未信任 Directory 先前的判斷（D1/D6） — 由 `TestRunPortalOneShotConnect_Denied`：即使呼叫端「已經」構造出語法合法的 `pilot-connect` 指令，target 不在這台 gateway 的 `target_hostgroup` 範圍內時一樣被拒，且憑證/SSH 都不會被觸發 涵蓋，非單一 shell 指令 | 0 | true |
| AG39 | handoff | wrong-scope target 經 one-shot connect 路徑一樣 deny（沿用既有 `ConnectAuthorize`，不是另一套判斷） — 與 AG38 相同：`internal/gatewayapi.handleConnectAuthorize` 完全沒有因為呼叫來源是互動 Portal 還是 one-shot handoff而改變邏輯，兩條路徑呼叫同一個 handler，非單一 shell 指令 | 0 | true |
| AG40 | handoff | target session 結束後，one-shot connect process 以 ssh child 的 exit code 結束（spec.md §18 point 6/7） — 由 `TestRunPortalOneShotConnect_PropagatesSSHExitCode`（用真的 `sh -c "exit 7"` 產生真的 `*exec.ExitError`，確認透過 `portalSessionExitError`/`ExitCoder` 原樣傳出） 涵蓋，非單一 shell 指令 | 0 | true |
| AG41 | recording | `access-gateway.yaml` 含 playbook 產生的 `recording:` 區塊；`failure_policy` 為合法值；`mode` 未設定（built-in metadata）或為合法值 | 0 | grep -Eq '^  recording:$' /etc/pilot/access-gateway.yaml && grep -Eq '^    failure_policy: (fail_closed|best_effort)$' /etc/pilot/access-gateway.yaml && if grep -Eq '^    mode: ' /etc/pilot/access-gateway.yaml; then grep -Eq '^    mode: (metadata|terminal_output|terminal_io)$' /etc/pilot/access-gateway.yaml; fi |
| AG42 | recording | 設定 session store 時，PIT1 signing key 檔為 `pilot-gateway:pilot-gateway 400`；未設定 store 時該檔不存在 | 0 | if grep -q '^    session_store_url: ' /etc/pilot/access-gateway.yaml; then test "$(stat -c '%U:%G %a' /etc/pilot/session-store-ingest-signing.key)" = "pilot-gateway:pilot-gateway 400"; else test ! -e /etc/pilot/session-store-ingest-signing.key; fi |
| AG43 | recording | 舊版靜態 bearer token 檔 `/etc/pilot/session-store-ingest-token` 已移除 | 0 | test ! -e /etc/pilot/session-store-ingest-token |
| AG44 | recording | resolver 依 per-host recording spec §4 precedence（host override > gateway default > built-in metadata）產生 mode 與 source — 由 `internal/gatewayapi` 的 `TestResolveRecordingMode`（table-driven，含 raw default `""` → `built_in_default`） 涵蓋，非單一 shell 指令 | 0 | true |
| AG45 | recording | host policy unknown／invalid／保留值 `terminal_io` → Allowed=false 且帶對應 `deny_reason` — 由 `TestConnectAuthorize_RecordingPolicyDenies`（host_show 失敗、userclass 不可讀 → `recording_policy_unavailable`；重複 marker、保留值、zero-value policy → `recording_policy_invalid`） 涵蓋，非單一 shell 指令 | 0 | true |
| AG46 | recording | effective mode 為 terminal 但沒有設定 session store → deny `recording_backend_unavailable`（沒有 local recording fallback） — 由 `TestConnectAuthorize_TerminalWithoutStoreDenied` 涵蓋，非單一 shell 指令 | 0 | true |
| AG47 | recording | metadata 回應不含 store URL／CA／ingest token／recorder 參數 — 由 `TestConnectAuthorize_MetadataCarriesNoIngestCredential`（host 未設定與 `off` 兩種情形都比對原始 JSON） 涵蓋，非單一 shell 指令 | 0 | true |
| AG48 | recording | terminal 回應的 ingest token claims 綁定 sid／user／gateway／scope／target／mode／source，lifetime = `max_session_duration`，且每次簽發的 `jti` 都不同 — 由 `TestConnectAuthorize_MintsBoundIngestToken` 涵蓋，非單一 shell 指令 | 0 | true |
| AG49 | recording | 兩次 authorize 之間 host policy 由 absent 改為 `terminal_output`，第二次立即生效（gateway 沒有跨 request 的 policy cache） — 由 `TestConnectAuthorize_FreshPolicyEachRequest` 涵蓋，非單一 shell 指令 | 0 | true |
| AG50 | recording | 互動式 Portal Connect 對 effective terminal mode 走 recorded path（與 Directory handoff 共用 `runPortalTargetSession`），不走 plain ssh — 由 `cmd/pilot/cmd` 的 `TestConnectToHost_TerminalModeUsesRecordedPath` 涵蓋，非單一 shell 指令 | 0 | true |
| AG51 | recording | recorded path 在 session store start 失敗時不啟動任何 ssh process（Phase A 也不做） — 由 `TestPortalTargetSession_StoreStartFailureNoSSH`；start 之後 Phase A／Phase B 失敗仍送 `complete=false` 的 finish，見 `TestPortalTargetSession_FailureAfterStartFinishesIncomplete` 涵蓋，非單一 shell 指令 | 0 | true |
| AG52 | recording | terminal mode 不在 gateway 寫任何 local recording file（FileSink fallback 已移除） — 由 `TestPortalTargetSession_NoLocalRecordingFile` 涵蓋，非單一 shell 指令 | 0 | true |
| AG53 | recording | `fail_closed` 下閒置但健康（沒有 pending event）的 session 超過 3×`failure_grace` 仍存活 — 由 `internal/sessionrecording` 的 `TestRecorderFailClosedIdleSessionSurvives`（6×grace） 涵蓋，非單一 shell 指令 | 0 | true |
| AG54 | recording | terminal mode 在 SSH 前印出錄影提示（含 session id）；metadata 不印 — 由 `TestPortalTargetSession_RecordingNotice` 涵蓋，非單一 shell 指令 | 0 | true |
| AG55 | metrics | node_exporter textfile 目錄存在時，gateway 被 socket 喚醒後寫出 0644 的 `pilot_access_gateway.prom`，含 `pilot_gateway_connect_authorize_total`；目錄不存在時不寫（metrics 是 soft 功能） | 0 | curl -fsS --unix-socket /run/pilot/access-gateway.sock -o /dev/null http://localhost/v1/health; f=/var/lib/node_exporter/textfile/pilot_access_gateway.prom; if test -d /var/lib/node_exporter/textfile; then for i in 1 2 3 4 5; do test -s "$f" && break; sleep 1; done; grep -q '^# TYPE pilot_gateway_connect_authorize_total counter$' "$f" && test "$(stat -c %a "$f")" = 644; else test ! -e "$f"; fi |
| AG56 | recording | Phase 0 分支 R：gateway principal 對某台 host 的 `userclass` 沒有讀取權限 → 只有該 host 的連線 deny `recording_policy_unavailable`，同一 snapshot 的其他 host 不受影響 — 由 `internal/gatewayapi` 的 `TestConnectAuthorize_UserClassUnreadableDenies`；rights 解析見 `internal/freeipaaccess` 的 `TestParseHost_UserClassUnreadableIsUnavailable` 涵蓋，非單一 shell 指令 | 0 | true |
| AG57 | recording | `sudo pilot access recording show <host>` 以 gateway 自己的 keytab 讀 host policy，依 §29 輸出 host policy、gateway default、effective、source（text／json）；非 root exit 2、host 不存在 exit 1 — 由 `cmd/pilot/cmd` 的 `TestAccessRecordingShow_*` 涵蓋（活體 L20 見 §4），非單一 shell 指令 | 0 | true |

## 3. 不在這份 checklist 逐行覆蓋、但已用其他方式驗證過的項目

以下 AG 編號直接引用 spec.md §52 的原始清單，但**不是**每一項都適合寫成單一 shell checklist row——很多是 unit test 的性質（`internal/peercred`、`internal/identity`、`internal/freeipaaccess`、`internal/accessportal`、`internal/gatewayapi` 各自的測試套件），不是 apply playbook 的某個 task 產生的結果：

- **AG05 service principal Kerberos auth**：AG06 的 `/v1/health` 呼叫本身就需要先成功完成 Kerberos 認證才拿得到 `"freeipa":"reachable"`，兩者共用同一個真實動作。
- **AG07 required read capabilities / AG08 mutation denied**：Phase 0 evidence（`docs/evidence/pilot-access-gateway/2026-09-14-phase0-transport-spike.md`）已對同一種 reader principal 實測：讀成功、寫（`user_add`）被 FreeIPA 用 `ACIError` 擋下，且不需要額外授權設定——bare service principal 預設就是零寫入權限。
- **AG10 SO_PEERCRED identity / AG11 $USER spoof blocked**：`internal/peercred`（真實 self-connect socket 測試）+ Phase 3/4 evidence 的活體 `env USER=root LOGNAME=root` 測試，兩者都證明過。
- **AG13 nested target hostgroup expansion / AG14 HBAC ∩ gateway scope / AG15 live sudo correctness**：`internal/accessportal`（Phase 2, 28 個測試,含真實巢狀/cycle fixture）+ Phase 3-5 對真實 `gpu-a`/`gpu-b`/HBAC/sudo rule 的活體 curl 驗證。
- **AG16 FreeIPA outage fail closed**：`internal/gatewayapi`/`internal/accessportal` 的錯誤路徑測試（resolve 失敗一律回 503/deny，見 Phase 3 `handleConnectAuthorize` 的 "resolve failed, denying" 分支）；**已於 Phase 8 對 vm-target 真的斷線實測**（停 `ag-spike-ipa` 的 `httpd`，`/v1/health`/`/v1/access` 立即回 503、`freeipa:"unreachable"`、`{"error":"access service unavailable"}`；重啟 `httpd` 後下一次請求自動恢復 200，見 Phase 8 evidence doc）——跨主機的破壞性動作，不適合寫成單一 host 的 checklist row。
- **AG17 no roster dependency / AG18 no inventory dependency**：結構性——`internal/freeipaaccess`/`internal/accessportal`/`internal/gatewayapi` 沒有任何程式碼 import roster/inventory 套件（可用 `go list -deps` 驗證），且 `internal/gatewayconfig/config.go` 的 `KnownFields(true)` 會讓任何試圖塞 `roster_file`/`inventory_file` 的 config 直接載入失敗（`TestLoadConfigRejectsForbiddenFields`）。
- **AG22 ~/.ssh/config ignored / AG23 forwarding disabled / AG24 strict host key checking**：Phase 5 `TestPilotSSHConfigDirectives`（對真實 OpenSSH 跑 `ssh -G`，含一個「有毒」`~/.ssh/config` 的活體驗證）。

## 4. Phase 8 完成的項目（多主機/多 session 性質，非單一 host 的 shell checklist row）

- **2026-09-24 per-host SSH session recording L1–L22**（candidate `ad7c463`，見 [`docs/evidence/pilot-access-gateway/2026-09-24-per-host-session-recording.md`](../evidence/pilot-access-gateway/2026-09-24-per-host-session-recording.md)）：Directory handoff 與互動式 Portal 對標記 `terminal_output` 的主機都會錄影（notice、`complete: true`、replay 看得到 marker），未標記主機維持 metadata；policy 無效、重複、大小寫變體、保留值 `terminal_io` 一律 deny 且 target 沒有任何登入；store 停止時不建立 SSH；store 中途不可達或磁碟滿時 fail_closed 在約 `failure_grace` 後結束 session，且觸發後不再轉送任何未錄影的 I/O；閒置超過 20 分鐘的錄影 session 仍然 `complete: true`；token 不能跨 session／跨使用者使用；`pilot access recording show` 對真實 FreeIPA 回報正確；回滾程序可還原。全新 VM 上本 spec 的 verify 為 35/35。
- **AG20 portal ForceCommand / AG21 admin shell unaffected / AG25 remote whoami == portal user**：spec.md §55.1 的 3 步鎖定回歸測試已對 `ag-gw01`（disposable vm-target）完整跑過並取得人員核准（見 Phase 8 evidence doc）：(1) `alice`（`role-pilot-portal-user` 成員）SSH 登入直接進入 `pilot portal` TUI，畫面顯示 `User alice`，Ctrl+C 結束整個連線而非取得 shell，`ssh alice@host whoami`（無 PTY）不執行請求的指令、exit 1；(2) `root`（非 portal-user）SSH 登入拿到完全正常的 interactive shell（`whoami` → `root`）；(3) 把旗標設回 `false` 重新 apply，drop-in 被移除、sshd reload，兩種帳號都恢復正常 shell（`alice` 的 `whoami` → `alice`）。過程中還發現並修正一個真的可用性 gap：新增了 rollback 用的 Step 19/20/21 對應任務，讓旗標從 `true` 改回 `false` 時 playbook 會真的移除 drop-in，而不是只是跳過重新安裝。

- **AG32/AG33 session-scoped Kerberos login E2E**：第一跳用 SSH key 進 Portal；Connect 時由 Portal 以遮罩輸入取得該 SSH 使用者的 Kerberos 密碼，固定 principal 為該使用者、以 fixed argv `kinit -F -l 1h` 取得不可轉送的一小時 TGT、把 ccache 放在 user-owned runtime temp dir；同一 Portal session 重用有效 TGT，失效/遺失後重新提示；Portal 結束只清理自己建立的 ccache。目標主機停用 password/kbd-interactive 時仍須以 GSSAPI 成功，且失敗時不得出現 target password prompt。本項需以互動 TUI vm-target evidence 驗證，不能只靠 checklist 靜態設定。

  **2026-09-15 補充（`scripts/pilot-access-gateway-lockout-test.sh`）**：上面 3 步測試只涵蓋「無 PTY 時指令不執行」跟「root 不受影響」，沒有涵蓋其他標準的 restricted-shell 逃逸手法。已把當天對 `ag-gw01`/`ag-gw02` 活體驗證過的 5 類額外探測寫成可重跑腳本（假設 ForceCommand 已經是啟用狀態，純讀取、不會 mutate 任何東西）：(1) `ssh -tt` 帶指令注入，用 gateway 上的即時 process tree 證明注入的指令從未執行、只跑了 `pilot-session`→`pilot portal`；(2) client 端 `-o RemoteCommand=...` 覆寫；(3) local port forwarding，用 server 端真的回傳 `administratively prohibited` 的 channel 拒絕證明，不只是 client 行為；(4) SFTP subsystem 請求；(5) `sshd -T -C` 對 portal group 實際生效的 `ForceCommand`/`DisableForwarding`/`PermitUserRC`/`X11Forwarding`/`AllowTcpForwarding`/`AllowAgentForwarding`/`PermitTunnel`。對 `ag-gw01`/`ag-gw02` 兩台都跑過，11 項全過。
- **AG26 same-scope gateways return equivalent target set / AG27 different-scope gateways return isolated target sets**：新增第二台 gateway `ag-gw02`。先設成與 `ag-gw01` 相同的 `scope=gpu`（`gateway_id=gpu-02`），對 `alice` 查詢 `/v1/access`，兩台回傳的 `hosts` 陣列（`gpu-a`/`gpu-b`，含相同 HBAC/sudo rule 名稱）逐字元相同，只有 `gateway.id` 不同（AG26）。接著把 `ag-gw02` 重新設成 `scope=dmz`（新建的 `pilot-target-dmz` hostgroup，成員 `dmz-a`），並額外幫 `alice` 建一條真的 HBAC rule（`pilot-grant-login-dmz-test`）授予她對 `dmz-a` 的 sshd 存取——此時 `ag-gw01`（`scope=gpu`）完全看不到 `dmz-a`（即使 alice 對它有真實權限），`ag-gw02`（`scope=dmz`）也完全看不到 `gpu-a`/`gpu-b`，證明每台 gateway 的交集運算只吃自己的 `target_hostgroup`，不會因為使用者在別的 scope 有權限就外溢（見 Phase 8 evidence doc 的完整 curl 輸出）。
- **AG28 service alias does not mix scopes**：架構性——`internal/freeipaaccess`/`internal/accessportal`/`internal/gatewayapi`/`cmd/pilot-access-gateway` 沒有任何程式碼碰 DNS 或 VIP（`go list -deps` 可驗證沒有 import 任何 DNS 相關套件），每台 gateway 的 scope 完全由它自己的 `/etc/pilot/access-gateway.yaml` 決定，AG26/27 已證明這個交集運算是嚴格 per-gateway 的——「同一個 DNS/VIP 混用不同 scope 的 gateway」是操作面/部署拓樸的錯誤（把不同 scope 的 gateway 放到同一個 service alias 後面），不是這個 repo 的程式碼能防呆的範圍，比照 AG31 的處理方式記錄為操作規則而非可測試的程式行為。
- **2026-09-16 portal 可用性 + ssh_config 三項修復**（見 `docs/evidence/pilot-access-gateway/2026-09-16-portal-usability-and-ssh-config-fixes.md`）：(1) `My Identity`/`Refresh` 原本用 Yes/No confirm 顯示唯讀資訊，兩個選項行為完全相同，已改成單一 `OK` 的 acknowledge prompt；(2) `access-gateway.yaml` 的 `cache_ttl`/`connect_max_age` 從沒有任何程式碼讀取（`accessportal.LoadUserAccess` 每次都直接查 FreeIPA），已從 Config struct 與 Step 11 模板移除，避免誤導操作者以為存取決策有快取；(3) Connect 用的 `/etc/pilot/ssh_config` 原本靠 Step 13 在 apply 當下 `ssh-keyscan` 產生的靜態快照（`GlobalKnownHostsFile /etc/pilot/ssh_known_hosts`）做 host-key 驗證，apply 之後才加入 scope 的主機會連不上，且 `ssh-keyscan` 本身是完全不驗證的 TOFU；已改用 `sss_ssh_knownhostsproxy`（`ProxyCommand`，跟 `freeipa-client-apply.yml` 自己的 `04-ipa.conf` 同一招）動態經 SSSD/FreeIPA 解析。三項都在 `ag-gw01`/`ag-gw02`/`ag-target01` 上用真正的 `pilot portal` TUI（純 GSSAPI，經 `trec` 操作）重新驗證過。
- **2026-09-16 My Hosts 顯示主機註解/資產資訊**（見 `docs/evidence/pilot-access-gateway/2026-09-16-host-annotations-in-portal.md`）：`internal/freeipaaccess.Provider.HostShow`早就存在但從沒被 resolver 呼叫過；現在 `LoadUserAccess` 對每台通過 SSH-allowed 篩選的主機都會呼叫它，解析 `userclass` 裡 `pilot.annotation.*` 前綴的值（host-annotations spec，2026-09-09）填進 `HostAccess.Annotations`，一路透傳到 `gatewayapi.HostJSON` 與 portal TUI。My Hosts 列表行會加一段排序過的 `[key=value, ...]` 摘要，選進主機明細畫面則顯示完整 `Annotations:` 區塊；沒有註解的主機兩處都不顯示。刻意把它當成「錦上添花」而非授權輸入——單一主機 `host_show` 失敗不會讓整個 `/v1/access` 掛掉，只是那台主機沒有註解資訊。真的在 `ag-spike-ipa` 用 admin kinit + `ipa host-mod` 對 `ag-target01` 設了真實 userClass（非捏造 fixture），透過真正的 `pilot portal` TUI（純 GSSAPI）驗證兩處畫面都正確顯示。順手修了 `runPortalMyHosts` 的「無可存取主機」訊息同一種 Yes/No-顯示唯讀訊息 的舊 bug（跟前一條的 My Identity/Refresh 同一類，前次漏抓）。
- **2026-09-16 `pilot_access_gateway_portal_automember` end-to-end**（實測當下預設仍是 `false`，需明確帶 `-e ...=true`；同日稍後改成預設 `true`，見下方 §5 gotcha，行為本身未變）：對 `ag-spike-ipa`/`ag-gw01` 實測（見 `docs/evidence/pilot-access-gateway/2026-09-16-portal-automember.md`）——`-e pilot_access_gateway_portal_automember=true` 首次 apply 建立 automember rule + inclusive/exclusive condition（`changed`），第二次 apply 四個 automember task 全部 `ok`（idempotent）；既有帳號（`bob`）透過全量 `automember-rebuild` 正確回填進 `role-pilot-portal-user`；全新建立的帳號（`newhire01`）在 `ipa user-add` 當下就立即是群組成員，不需要等 rebuild；`admin` 帳號在整個過程中從未被自動加入（exclusive-regex 生效）；`ag-gw01` 上的 `getent group role-pilot-portal-user` 也正確反映更新後的成員（SSSD 傳播）。測試後已手動清掉全部 fixture（`newhire01` 帳號、automember rule/condition、把 `role-pilot-portal-user` 還原成只有 `alice`），恢復 Phase 8 的既有基準狀態。
- **grant / breakglass active rule**：`pilot-access-gateway` 架構上完全不讀 grant JSON（spec.md §57 明文）——它只讀 FreeIPA 當下的 HBAC/sudo rule 狀態，不區分某條 rule 是手動建立還是由 `internal/inventory` 的 grant compiler（`pilot access breakglass activate` 等）產生。這個屬性已經被 Phase 8 的 AG26/27 測試間接證明：`pilot-grant-login-gpu-test`/`pilot-grant-sudo-gpu-test`（沿用 grant compiler 的命名慣例）與新建的 `pilot-grant-login-dmz-test` 全部是真實、當下 active 的 FreeIPA rule，gateway 對它們的處理跟任何其他 HBAC/sudo rule 完全一樣——沒有任何特殊分支代碼路徑。

## 5. Gotcha 記錄

- **2026-09-23：per-host SSH session recording（Phase 5）**——三件操作者需要知道的事：
  (1) **每次 authorize 都即時讀 FreeIPA**，沒有跨 request 的 policy cache：`hosts.yml` 改了 `ssh_recording` 但 `freeipa-client` 尚未 reconcile 到 FreeIPA 時，gateway 依 FreeIPA 現況決定（AG49）。
  (2) **Phase 0 分支 R**：gateway principal 以 `host_show` + `rights: true` 讀 `attributelevelrights.userclass`，沒有 `r` 權限就把該 host 視為 policy 不可讀，deny `recording_policy_unavailable`（AG56）；FreeIPA 不會因為沒有讀取權限就靜默回傳空 `userclass` 被誤判成「沒有設定」。
  (3) **`site.yml` 的順序已改成 `pilot-session-store` 在 `pilot-access-gateway` 之前**（contract `site.order` 51），讓全站部署時 gateway 第一次指向 store 前，store 已經在跑且 signing key 已就位；兩邊的 `pilot_session_store_ingest_signing_key` 必須是同一個 vault 值，否則每個錄影 session 的 start 都會被 store 以 401 拒絕，fail_closed 下使用者連不上 target。舊版靜態 bearer token（`/etc/pilot/session-store-ingest-token`）由本 playbook 刪除（AG43）。
- **2026-09-15：`site.include` 改成 `true`，`pilot-access-gateway` 不再是 single-component-only**——一路上發現兩次真的問題：全站部署（`playbooks/site.yml`）從架構上就無法跑到這個元件（從沒被 `import_playbook` 進去），`pilot deploy` 的 wizard 卻仍然把它列進「已選擇/已部署」，一次還被記成 delivery 歷史的 `success` run，實際上主機從沒被真的套用過。討論後拍板：與其永遠維持「single-component-only、每次都要單獨呼叫」，改成跟其他角色一致的語意——`hosts.yml` 把 `pilot-access-gateway` 加進某台主機的 roles 清單，本身就是操作者的核准動作,之後每次全站部署都會照常套用。`site.yml` 已補上 `import_playbook: apply/pilot-access-gateway-apply.yml`（`tags: [freeipa, pilot-access-gateway]`，緊接在 `freeipa-client` 之後,對應 sameHosts 依賴）;`contracts/pilot-access-gateway.yaml` 的 `site` 區塊改成 `{include: true, order: 52, tags: [pilot-access-gateway], optIn: false}`。**§0 G4/§55.1 的規則沒有變，只是核准時機點改變**：把 role 加進 `hosts.yml` 之前,仍然要先在該主機或同等 disposable vm-target 上跑過鎖定回歸測試——加了 role 之後,之後每次全站部署都不會再重新問一次。`cmd/pilot/cmd/site_yml_consistency_test.go` 的 `TestSiteYMLImportsEveryReachableComponent` 會鎖住這個 `site.include`/`site.yml` 一致性,避免第三次重演同一種落差。
- **2026-09-15：`freeipa_servers`/`ipa_realm` 改成 `required: false`，會自動推導**——真實站台實測時發現：`group_vars/pilot-access-gateway.yml` 若還是原始範本的 `freeipa_servers: []`/`ipa_realm: ""`，contract 的 `required: true` 會讓 `pilot deploy` 在連 ansible 都還沒跑之前就直接擋下（`requires input "freeipa_servers"`），即使該站台的 `group_vars/freeipa.yml` 早就正確設好 `freeipa_domain`。已改成比照 `freeipa-client-apply.yml` 自己的既有慣例：`gateway_effective_ipa_realm`/`gateway_effective_freeipa_servers` 依序檢查「明確填的 `ipa_realm`/`freeipa_servers`」→「`freeipa_realm`/`freeipa_server_fqdn`」→「`freeipa_domain` 推導成 `大寫(domain)`/`ipa1.<domain>`」，跟同一份 inventory 上其他 freeipa-client 主機使用的是同一條推導路徑，不需要重複填一次已經在 `group_vars/freeipa.yml` 設定過的資訊。`default(X, true)` 讓「明確設成空字串/空陣列」（範本沒填完就直接套用的常見情況）也一起走推導，不會被誤判成「使用者刻意覆寫成空」。
- `-e freeipa_servers=[...]` 這種寫法 Ansible 不會可靠解析成 list（同 Phase 6 發現的坑），必須用 `-e '{"freeipa_servers": [...]}'` 的 JSON 物件形式。
- `ipa service-add` 要求目標主機已有正向 DNS record；`freeipa-client-apply.yml` 的自動 DNS 註冊在本次實測未必觸發，需要先確認（`getent hosts <fqdn>`）或手動 `ipa dnsrecord-add`。
- **不要**建一個跟 FreeIPA 群組同名的 local fallback group（例如 `gateway_portal_user_group`）——nsswitch 的 `files` 來源比 `sss` 先查，會讓 local 群組永久遮蔽真正的 FreeIPA 群組。2026-09-15 起本 playbook 會用 `ipa group-add` 自己建立**真正的 FreeIPA 群組**（見下方新增的 gotcha）；這條規則限制的是「local Unix group 替代品」，不是「自動建立真正的 FreeIPA 群組」，兩者是完全不同的操作。
- systemd `.socket` 的 `ListenStream=` 路徑所在目錄，若靠 `.service` 單元的 `RuntimeDirectory=` 建立，重啟 **service**（不只是 socket）會把整個目錄連同 socket 檔一起刪掉——`RuntimeDirectory=` 要放在 `.socket` 單元本身。
- **CRITICAL（Phase 8）**：`internal/freeipaaccess.NewClient` 原本在建構時就同步載入 keytab/CA/krb5.conf，任何一個檔案有問題都會讓 `cmd/pilot-access-gateway` 的 `main()` 直接 exit——因為這個服務是 socket-activated，每個新連線都會再觸發一次必死的 service start，很快撞到 systemd 的 start-rate-limit，**連 socket 單元本身都會變成 `failed`**，即使後來把 keytab 修好也不會自動恢復，要人工 `systemctl reset-failed`。已修成：keytab/CA/krb5.conf 的載入延後到第一次真正呼叫時才做（跟既有的 session 建立一樣是 lazy + per-call retry），壞掉時服務照樣活著、`/v1/health`/`/v1/access` 回 503 degraded（跟 FreeIPA 斷線的行為一致），檔案修好後**下一次請求就自動恢復**，不需要重啟。見 `internal/freeipaaccess/kerberos_test.go` 的 `TestNewClientDoesNotEagerlyLoadCredentials`/`TestClientRetriesCredentialLoadOnEveryCall`。
- **Gateway 主機自己也需要一條 HBAC rule 才能讓 portal 使用者登入**：`pilot-access-gateways` hostgroup 只是 management inventory classification（spec.md §57 明文說它不代表 target 存取權），實際上 SSH 登入 gateway 主機本身（觸發 ForceCommand 之前，PAM/SSSD 的 account 階段就會先檢查）也需要一條 HBAC rule 授權。Phase 8 測試時手動建了 `pilot-access-gateway-login`（`role-pilot-portal-user` → `pilot-access-gateways` → `sshd`）才能讓 §55.1 的鎖定回歸測試跑起來；**2026-09-15 起這條規則已改成本 playbook 自己 idempotent 建立**（見下一條 gotcha），不再需要操作者手動預先準備。
- **2026-09-15：`gateway_portal_user_group` 與 `pilot-access-gateway-login` HBAC rule 改成本 playbook 自己 idempotent 建立，不再要求操作者先手動編輯 freeipa-identity roster**——起因是這個 gate 在真實站台（infra-deploy）第一次隨全站部署觸發時直接擋下整條 delivery transaction，逼操作者離線去手動改 roster、重跑 `freeipa-identity-apply.yml`，才能重跑一次 pilot-access-gateway。這其實跟 Step 3 早就在自己管理的 `pilot-access-gateways` hostgroup 是同一類「元件自己需要的 FreeIPA scaffolding」，沒有理由用不同規則處理。改成：`ipa group-add`（群組）→ `ipa hbacrule-add`（規則本身）→ `ipa hbacrule-add-host --hostgroups=pilot-access-gateways`（授權對象）→ `ipa hbacrule-add-service --hbacsvcs=sshd`（服務）→ `ipa hbacrule-add-user --groups=<group>`（把 portal 群組掛進規則），全部沿用 Step 3 已經驗證過的 `command`+`register`+`changed_when`+`failed_when`（容忍 `already exists`/`already a member`）冪等寫法。**這不會重演本檔案警告過的 local-fallback-group 事故**——`ipa group-add` 建的是真正的 FreeIPA 群組（跟 freeipa-identity roster 建出來的東西一樣，一樣走 SSSD），事故當年建的是「同名的 local Unix 群組」，是完全不同的操作。**群組成員（誰是 portal user）仍然刻意不在這裡管**，還是 roster 管的身分資料——只有「群組/規則本身存在」這種結構性 scaffolding 被自動化，跟 `gateway-scope-apply.yml` 對 `pilot-target-<scope>` 劃的「可以自動建 scaffolding、不可以自動管人的身分/成員」界線一致。舊的 `getent`-based gate 沒有拿掉，只是意義改變：現在代表「SSSD 沒跟上剛剛的變更」而不是「操作者忘記做前置準備」。
- libvirt 的 vm-target IP 會被回收重用：舊 VM 留下的 `~/.ssh/known_hosts` host key 換了新 VM 但 IP 相同時，SSH 會直接拒絕（`REMOTE HOST IDENTIFICATION HAS CHANGED`），要先 `ssh-keygen -R <ip>` 清掉舊條目。
- FreeIPA 使用者密碼被 admin 用 `ipa passwd` 重設後會進入「must change at next login」狀態；`ssh user@host`（純 `password`/`keyboard-interactive` 認證）在這個狀態下會被 sshd 直接斷線（`monitor_read: unpermitted request 104`），不會進入互動改密碼流程——要先用 `kinit <user>`（透過任一台已 enroll 的主機）做一次改密碼，之後 SSH 才能正常登入（同一份 v5.1 舊教訓，這次換成 SSH 層再踩一次）。
- **`pilot_access_gateway_install_forcecommand` 預設在 2026-09-14 從 `false` 改成 `true`**（§55.1 已在 Phase 8 通過之後的政策決定）——這代表沒有明確帶 `-e pilot_access_gateway_install_forcecommand=false` 的每一次 apply（包含任何未來新裝的 gateway 主機）都會安裝 ForceCommand。§0 G4/§55.1 的規則本身沒有改變：不得對非 disposable 主機部署、正式環境每次啟用都要人員明確核准——**改預設值不會、也不能取代這個核准**，只是把「忘記帶旗標」的結果從「安全」變成「危險」。對任何非 disposable 主機套用這支 playbook 前，務必先確認這一點，必要時明確帶 `-e pilot_access_gateway_install_forcecommand=false`。
- 曾意外發現另一個真的 bug（已修）：選到沒有真實機器的 placeholder fixture host（`gpu-a`/`gpu-b`）按 Connect，SSH 解析失敗的錯誤會直接把整個 `pilot portal` process 炸掉、退回 shell（`connectToHost` 把 `sshLauncher` 的 error 原樣往上丟，一路 unwind 出 `runPortal`）——跟 spec.md 「退出 remote SSH 後回到同一個 pilot portal」的設計意圖相反。已修成：Connect 失敗（無論是 authorize API 錯誤或 ssh 本身失敗）一律顯示訊息並回到 portal 選單，永不往外拋（見 `cmd/pilot/cmd/portal_ssh_test.go` 的 `TestConnectToHostSSHFailureReturnsToPortal`）。
- **2026-09-15 新增 Step 3b（防線，非功能變更）**：`pilot-access-gateway-apply.yml` 每次套用時，會主動偵測並移除該主機在任何 `pilot-target-<scope>` hostgroup 裡的殘留成員資格（絕不動 Step 3 自己的 `pilot-access-gateways`）。起因是 `pilot gateway-scope --hosts all` 曾經（已修）把 gateway 主機自己也發布成自己的 target（見 `docs/verification/pilot-gateway-scope.md` §1.6）；這一步是獨立的第二層防護，冪等，涵蓋任何未來讓主機先進了某個 target scope、之後才升級成 gateway 的情境。`ipa hostgroup-find` 零結果時 exit code 是 1（非 0），這支偵測任務因此用 `failed_when: false`，別誤改成預設的失敗判斷。

- **2026-09-16：`pilot_access_gateway_portal_automember`——讓每個 FreeIPA 帳號自動成為 portal 使用者，不用在 roster 逐一列名單**——起因是 infra-deploy 站台實際問題：`gateway_portal_user_group` 的成員刻意留給 roster 管（見上面 2026-09-15 那條 gotcha），但當操作者要的其實是「任何 FreeIPA 帳號都能用這台跳板機」而非「精選幾個人」時，逐一在 roster 列名單既不是目標也維護不動。在 `gateway_effective_portal_user_group` 上建立 FreeIPA automember rule（`ipa automember-add --type=group` + `automember-add-condition --key=uid --inclusive-regex=.*`），比照 `gateway-scope-apply.yml` 對 hostgroup 已經用過的同一招，只是對象從 hostgroup 換成 user group。真的對 vm-target（`ag-spike-ipa`/`ag-gw01`）驗證過兩個非顯而易見的真實 gotcha：
  1. **`uid=.*` 會連 FreeIPA 內建的 `admin` 帳號都一起掃進去**——這台站台通常會有一條 `admin-breakglass-access` 這類 hostcat=all 的 HBAC rule，專門讓 `admin` 在任何情況下都能緊急 SSH 進任何主機（包含這台 gateway）取得真正的 shell；一旦 `admin` 也被自動收進 portal 群組、又剛好這台 gateway 開了 ForceCommand，`admin` 登入這台 gateway 也會被劫持進 portal session，break-glass 路徑形同失效。已加一個 exclusive-regex 條件（`--key=uid --exclusive-regex=^admin$`）擋住，預設排除清單是 `pilot_access_gateway_portal_automember_exclude_users: ["admin"]`；真的要求零例外的站台可以把這個清單設成空 list。
  2. **`ipa automember-rebuild --type=group --users=<name>`（帶 `--users=` 鎖定特定帳號）會忽略 exclusive-regex 條件，把本該排除的帳號重新加回去**——即使規則上已經有 `exclusive-regex=^admin$`，對 `admin` 單獨跑一次帶 `--users=admin` 的 rebuild 還是會把 admin 加回 `role-pilot-portal-user`；不帶 `--users=`/`--hosts=` 的**全量** `ipa automember-rebuild --type=group` 則正確遵守 exclusion。Playbook 因此**一律用不帶篩選的全量 rebuild**做既有帳號的一次性回填（automember 條件只在物件「新建當下」評估一次，回填是為了涵蓋規則建立前就存在的帳號），絕不能為了「只回填某個人」而加 `--users=`。
  這個功能刻意保持 additive-only：把 `pilot_access_gateway_portal_automember` 改回 `false` 不會自動撤銷已經建立的 automember rule/condition，跟 `gateway_portal_user_group`/`pilot-access-gateway-login` 的既有原則一致——真的要撤銷要手動 `ipa automember-del <group> --type=group`。
  **同日追加，預設改為 `true`**：使用者明確要求「這要成為預設行為，不要額外傳參數」——`pilot-access-gateway-install_forcecommand` 早就預設 `true`（Phase 8 §55.1 通過後的政策決定），本功能單獨存在時只決定「誰在 portal 群組」，不改變任何登入行為，實際的 shell-vs-portal 劫持完全由已經驗證過的 ForceCommand 機制負責；因此把兩者的預設值對齊、一起預設開啟，不需要重跑一次 §55.1 鎖定回歸測試（那個測試驗的是 ForceCommand 本身的行為，不是「誰進得了 portal 群組」）。`contracts/pilot-access-gateway.yaml` 的 `pilot_access_gateway_portal_automember` 已改成 `default: true`。**站台/gateway 若真的需要「只有 roster 明確列名的人能用 portal」**（例如多租戶、不同 scope 各自精選使用者的站台），部署時要明確帶 `-e pilot_access_gateway_portal_automember=false`——這不再是自動推導出來的行為，需要操作者主動選擇退出。
- **2026-09-16：delegation 路徑在停用密碼登入後仍可用，但使用者端必須主動要求 GSSAPI ticket delegation**：對 `ag-gw01`/`ag-target01` 實測（見 `docs/evidence/pilot-access-gateway/2026-09-16-gssapi-no-password-fallback.md`），把兩台主機的 `PasswordAuthentication`/`KbdInteractiveAuthentication`/`ChallengeResponseAuthentication`/`PubkeyAuthentication` **全部關掉**、只留 GSSAPI，兩段連線都成功：(1) alice 帶 forwardable Kerberos ticket 用 `GSSAPIDelegateCredentials=yes` 登入 gateway，sshd 提供的認證方式只剩 `gssapi-keyex,gssapi-with-mic`；(2) 在 gateway 上用真正的 `/etc/pilot/ssh_config`（跟 `connectToHost` 完全一樣的指令 `ssh -F /etc/pilot/ssh_config <target>`）連到 `ag-target01`，同樣只靠 GSSAPI 成功——用的是 hop 1 delegate 進來的 ticket。反例對照組：不開 `GSSAPIDelegateCredentials` 的話，gateway 上的 session 完全沒有 ticket cache，hop 2 直接 `Permission denied`，證明 delegation 是此路徑的必要條件。`ipa-client-install` 產生的 `/etc/ssh/ssh_config.d/04-ipa.conf` 預設**沒有**打開 `GSSAPIAuthentication`/`GSSAPIDelegateCredentials`，一般 OpenSSH client 預設也沒開；同日的 `freeipa-client.md` v1.8 C12 已補上 enrolled client 的預設設定。這段只描述「沿用使用者既有 TGT」的 delegation 路徑；若第一跳是 SSH key、沒有可委派 TGT，則改走 AG32/AG33 已實測的 Portal session-scoped `kinit` 路徑，兩者都不會把 credential 再委派到 target。
- **2026-09-16：`sss_ssh_knownhostsproxy` 當 `ProxyCommand` 不會自動滿足 `StrictHostKeyChecking`**——這是修 known_hosts 靜態快照問題時，在 vm-target 上真的踩到的：把 `ProxyCommand` 改成 `sss_ssh_knownhostsproxy -p %p %h` 之後，如果順手把 `GlobalKnownHostsFile` 整條拿掉（以為 ProxyCommand 自己就會處理 host key），會得到 `No ED25519 host key is known for <target> and you have requested strict checking. Host key verification failed.`——`sss_ssh_knownhostsproxy` 只負責轉送連線 bytes，不負責回答「這把 key 信不信任」這個問題。真正的答案在 `GlobalKnownHostsFile /var/lib/sss/pubconf/known_hosts`——這是 SSSD 自己持續維護、對應每台已解析主機 `ipaSshPubKey` 的快取檔，兩個設定要一起用才完整，缺一個都會連不上（缺 ProxyCommand 就沒有動態解析能力，缺 GlobalKnownHostsFile 就沒有信任來源）。

- **2026-09-18：新增 Step 3c/3d——每次 apply 把這台 gateway 自己發布進 `pilot-gateway-<gateway_scope>`，並自我清掉舊 scope 殘留的成員資格**（`docs/tmp/now/spec.md` §7，這份 Directory/handoff/recording 規格的 Phase 2；evidence:
  [`docs/evidence/pilot-access-directory/2026-09-18-phase2-gateway-scope-instance-publication.md`](../evidence/pilot-access-directory/2026-09-18-phase2-gateway-scope-instance-publication.md)）。
  這是一個**新的、跟 `pilot-target-<scope>` 平行但完全不同**的 hostgroup 家族：
  `pilot-target-<scope>` 回答「這個 scope 的目標主機有哪些」（既有 `pilot
  gateway-scope` CLI 管理），`pilot-gateway-<scope>` 回答「這個 scope 由哪幾台
  gateway *實例* 服務」（未來 `pilot-access-directory` 路由查詢用，尚未實作，
  只有這個 playbook 端的發布邏輯先落地）。實作沿用 Step 3/3b 已經驗證過的
  `hostgroup-add`/`hostgroup-add-member`（Step 3c）+
  `hostgroup-find --hosts=.. --raw` 探測、`regex_findall` 挑出 `pilot-gateway-`
  前綴、排除當前 scope 後逐一 `hostgroup-remove-member`（Step 3d）寫法，沒有
  發明新模式。真的在 `ag-gw01`（`scope=gpu`）/`ag-gw02` 上驗證過：兩台同 scope
  gateway 正確共存於同一個 hostgroup；把 `ag-gw02` 的 `gateway_scope` 從
  `gpu` 改回 `dmz` 後，它會自動離開 `pilot-gateway-gpu`、加入
  `pilot-gateway-dmz`，`ag-gw01` 不受影響；兩台主機最終都復原回本次測試前的
  基準設定（`ag-gw01`=gpu、`ag-gw02`=dmz），沒有在這兩台共用 vm-target 上留下
  殘留 drift。第二次 apply 這幾個新 task 全部 `ok`（無 `changed`）。

## 6. Phase 5 — Directory → Gateway handoff dispatcher（2026-09-18，unit-test + vm-target 活體皆已驗證）

`docs/tmp/now/spec.md` §16-§19：ForceCommand wrapper（`/usr/local/libexec/pilot-session`）
從無條件 `exec /usr/bin/pilot portal` 改成 `exec /usr/bin/pilot portal-session`——
一個會自己讀 `$SSH_ORIGINAL_COMMAND`（在 Go 裡，從不經過 shell）的 hidden
dispatcher（`cmd/pilot/cmd/portal_session.go`）：

- 空指令 → 沿用既有互動 `pilot portal` TUI（行為不變）。
- 精確符合 `pilot-connect <uuid> <fqdn>` 語法 → 新的 one-shot connect
  （`cmd/pilot/cmd/portal_session_connect.go`，`runPortalOneShotConnect`）：
  對 `/run/pilot/access-gateway.sock` 呼叫既有、未修改的
  `POST /v1/connect/authorize`（沒有第二套授權邏輯），拒絕就非 0 結束、
  不碰 SSH；允許就重用既有 `buildConnectSSHCmd`/session-scoped Kerberos
  憑證流程連到 target，process 以 ssh child 的 exit code 結束。
- 其他任何字串（畸形語法、shell metacharacter、`user@host`、IP literal、
  leading `-`、trailing `.`、embedded newline、非法 UUID、Directory 自己的
  `pilot-directory-connect` 語法……）→ deny，非 0 結束，從不落入互動 TUI。
  **這是相對 Phase 7/8 baseline 的行為變更**：舊版對任何非空指令一律靜默
  忽略、直接進互動選單（不算安全問題——從未把指令交給 shell——但也從未
  明確拒絕過）。

`session_id` 只做 UUID 語法檢查，從未進入 `ConnectAuthorize` 呼叫本身
（spec.md §17.2「不把 session ID 當 proof」）——跨元件關聯（Directory 端的
同一個 session_id 也要出現在這裡）已由這份 Directory/Gateway Handoff 規格的
Phase 6（`internal/sessionaudit`）落地：`runPortalOneShotConnect` 改成透過
`sessionaudit.Emitter` 送出 `gateway_authorize_allowed`/
`gateway_authorize_denied`/`target_connect_started`/`session_ended`（不再是
裸的 `slog.Info`/`slog.Warn`），單元測試證明內容正確，真實 syslog/中央 log
活體重建仍待 vm-target 驗證（見
`docs/verification/pilot-access-directory.md` AD26）。

單元測試（`portal_session_test.go`/`portal_session_connect_test.go`，共 9
個）用真正的 `internal/gatewayapi.Server`（fake FreeIPA provider，非 mock）
證明：合法語法解析正確；上面列的每一種畸形/惡意輸入都被拒絕；denied
target 不觸發憑證或 SSH；憑證失敗不觸發 SSH；一個真的 `*exec.ExitError`
（用 `sh -c "exit 7"` 產生，非手刻字串）會原樣透過 `portalSessionExitError`
傳出成這個 process 自己的 exit code。

**2026-09-18 已完成的 vm-target 活體驗證**（見
[`docs/evidence/pilot-access-directory/2026-09-18-phase5-gateway-handoff.md`](../evidence/pilot-access-directory/2026-09-18-phase5-gateway-handoff.md)，
不再是「待補」）：

- 真人 `alice` 經 `pilot directory`（`ag-directory01`）Connect 到
  `ag-target01.ipa.pilot.internal`（gpu scope，經 `ag-gw01`）——真的落地到
  target shell，`whoami`/`id` 確認身分是 alice，回到 Directory TUI。
- 同一使用者 Connect 到新建的 `ag-target02.ipa.pilot.internal`（dmz scope，
  經 `ag-gw02`，臨時加入 `pilot-target-dmz` 取代不存在真實機器的
  `dmz-a` fixture）——同樣真的落地，`whoami`=alice。
- wrong-scope injection 活體驗證：把 `pilot-connect <uuid>
  ag-target02.ipa.pilot.internal`（dmz target）直接送給 `ag-gw01`（GPU-only
  gateway）——`gateway_handoff_authorize_denied`，`pilot-session: access
  denied`，process exit 1，`ag-gw01` process tree 全程沒有任何 ssh child
  往 target 方向啟動（AG39 從此不只有 fake-gateway 單元測試）。
- `scripts/pilot-access-gateway-lockout-test.sh` 新增的 6 類語法拒絕探測
  也額外用兩個具體案例（shell metacharacter、IP literal）對 `ag-gw01`
  手動複查過，client 端訊息與 server 端 process tree 都符合預期。

## 7. 明確不在本 repo 範圍的項目

- **AG31 out-of-scope SSH egress blocked by network policy**：站台網路層需求（防火牆/network policy 擋非 scope 內的 SSH 流量），非本 repo 範圍——`pilot-access-gateway` 本身沒有、也不打算有網路層 enforcement 能力，這是站台網路團隊的責任。
