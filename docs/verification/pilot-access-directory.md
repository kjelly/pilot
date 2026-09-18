# Verification Spec — Pilot Access Directory

> 版本：DRAFT v0.2（2026-09-18：Phase 4 的 4 項 landing gate——真人 SSH Directory
> TUI、arbitrary remote command 無 shell、idempotent apply、site-wide deployment
> 實際執行 component——已對新建的 `ag-directory01` vm-target 全部真實跑過，見
> [`docs/evidence/pilot-access-directory/2026-09-18-phase4-directory-tui-deploy-integration.md`](../evidence/pilot-access-directory/2026-09-18-phase4-directory-tui-deploy-integration.md)。
> 下方 checklist 本身仍是逐行對應 spec.md §37 AD01-AD30 的完整清單，尚未逐行跑
> 過 `pilot vm-target verify`/`pilot vm-target topology test`——那次全量 topology
> E2E（AD30，需要 §45 的多主機拓樸）仍待執行，完成後才能把版本改成正式 vX.X，
> 比照 `docs/verification/pilot-access-gateway.md` 的既有慣例，見 AGENTS.md §5.6）
> 對齊規範：docs/tmp/now/spec.md §10-§14/§31/§37（Pilot Access Directory、Gateway
> Handoff 與 SSH Session Recording 實作規格）
> 維護者：sre

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Inventory group | `pilot-access-directory`（或明確 `target_group`） |
| 角色 | stateless、read-only、FreeIPA-backed 跨 scope discovery/routing 後端（`pilot-access-directory.service`）+ 使用者 TUI 入口（`pilot directory`）。Directory 是 discovery/routing projection（spec.md D1），**不是**新的授權權威——每次 connect 前仍由對應 Gateway 做完整 fresh authorize |
| 前置需求 | 已是 FreeIPA client（`freeipa-client-apply.yml`）且有轉發 DNS 記錄；`pilot-target-<scope>`/`pilot-gateway-<scope>` hostgroup 由既有 `pilot gateway-scope` CLI（target）與 `pilot-access-gateway-apply.yml`（gateway instance，Phase 2）各自建立——Directory 本身從不寫入這兩個 hostgroup 家族 |
| 套用範圍 | 單一 Directory 主機的安裝（`hostCardinality: exactly-one`，spec.md D4）；`pilot_access_directory_install_forcecommand` 預設 `true`——沒有明確帶 `-e pilot_access_directory_install_forcecommand=false` 就會安裝 ForceCommand，比照 `pilot-access-gateway` 的既有政策：正式環境部署前必須先在 disposable vm-target 上跑過等效的鎖定回歸測試 |
| 風險等級 | **High（預設即安裝 ForceCommand，是使用者 SSH 登入後唯一看到的 shell 替代品）** |

## 1.5 依賴變數契約

| 變數名稱 | 說明 | 必填 |
|---|---|---|
| `directory_id` | 這個 Directory instance 的識別碼 | 是 |
| `directory_fqdn` | 明確指定 FQDN；未填則用 `ansible_fqdn`（D4 要求必須是這台主機真正 enroll 的 FQDN，不是 alias） | 否 |
| `freeipa_servers` / `ipa_realm` | 未填則從 `group_vars/freeipa.yml` 的 `freeipa_domain` 推導，跟 `pilot-access-gateway` 同一套規則 | 否 |
| `ipa_admin_password` | vault 提供，only used at apply-time for hostgroup/HBAC/keytab scaffolding，從不落地在這台主機上 | 是（secret） |
| `pilot_binary_path` / `pilot_access_directory_binary_path` | 本機建置好的二進位路徑 | 是 |
| `directory_portal_user_group` | 預設 `role-pilot-portal-user`——跟 `pilot-access-gateway` 共用同一個群組名稱（同一批人，兩種入口） | 否 |
| `pilot_access_directory_install_forcecommand` | 預設 `true` | 否 |

## 2. Checklist

每一行的 ID/文字直接對應 spec.md §37 的 AD01-AD30 原始定義，不新增編號。凡是能用單一
host 上的一條指令驗證的，Command 欄就是那條真指令；不能的（unit test/多主機/多次重跑
性質），Expected/Command 維持 `0`/`true` 佔位，實際證據在 §3/§4 說明去哪裡找。

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| AD01 | config | config `KnownFields(true)`，未知欄位 fail — 由 `cmd/pilot-access-directory` 的 `TestLoadConfigRejectsForbiddenFields` 涵蓋，非單一 shell 指令 | 0 | true |
| AD02 | socket | Directory API 僅 Unix socket，不 listen TCP | 0 | sh -c '! ss -ltnp 2>/dev/null \| grep -q pilot-access-directory' |
| AD17 | stateless | restart 後不需 local persistent state（沒有 local DB/state 目錄） | 0 | test ! -d /var/lib/pilot-access-directory |
| AD18 | 進入點 | `ssh access` 進 Directory TUI — 本行只驗證 ForceCommand drop-in 已安裝且 sshd 語法合法；「真人 SSH 進去看到 TUI」是 §4 的 vm-target 活體驗證 | 0 | sh -c 'grep -q "ForceCommand /usr/local/libexec/pilot-directory-session" /etc/ssh/sshd_config.d/91-pilot-access-directory.conf && sshd -t' |
| AD19 | forcecommand | arbitrary remote command 無法取得 Directory shell — 直接對 Go 二進位（略過 shell wrapper 的 `[ -t 0 ]` TTY 閘門）餵一個惡意 `SSH_ORIGINAL_COMMAND`，必須非 0 結束 | 0 | sh -c 'env SSH_ORIGINAL_COMMAND="sh -c id" /usr/bin/pilot directory-session; test $? -ne 0' |
| AD27 | staging/prod gate | stage gate 符合 repo policy — apply playbook 的 `pre_tasks` assert，非單一 shell 指令 | 0 | true |
| AD28 | idempotency | 第二次 apply changed=0（多次重跑的性質，由 evidence doc 記錄，非單一 shell 指令可驗證） | 0 | true |
| AD30 | topology | fresh vm-target topology E2E PASS — 見 §4，本 checklist 尚未執行過 | 0 | true |

其餘 AD 編號（AD03-AD05、AD06-AD16、AD20-AD26、AD29）不是單一 host 的靜態設定 checklist
row——是跨 scope 聚合、跨 host 路由、race 條件、結構性（no import）或 TUI 互動性質，逐一列
在 §3/§4。

## 3. 不在這份 checklist 逐行覆蓋、但已用其他方式驗證過（或該用其他方式驗證）的項目

- **AD03 user identity 來自 SO_PEERCRED，不信任 `$USER`/`$LOGNAME`**：架構性——`internal/directoryapi/connctx.go` 的 `connContext` 只從 `peercred.FromConn`（真實 kernel `SO_PEERCRED`）取得 UID，再用 `internal/identity.LookupUsername` 解析成使用者名稱；請求本身的任何欄位/環境變數都不會影響這個值。與 `pilot-access-gateway` 共用完全相同的 `internal/peercred`/`internal/identity` 套件，該套件自己的測試已涵蓋一般情況；env spoof 的活體對照組（`env USER=root LOGNAME=root` 之後身分仍解析為真正連線者）留給 §4 vm-target 驗收時一併做。
- **AD04 非 portal group user 無法呼叫 user-facing API**：`internal/directoryapi`（`portal_group_test.go`）——`TestHandleIdentity_PortalUserGroupUnknownGroupDenies`/`TestHandleAccess_PortalUserGroupUnknownGroupDenies`/`TestHandleConnectResolve_PortalUserGroupUnknownGroupDenies` 都用真實 `Server`+假 provider 驗證非成員一律 401，`TestHandleHealth_IgnoresPortalUserGroup` 驗證 `/v1/health` 刻意不受這個閘門影響。
- **AD06 Directory 不讀 roster / inventory / hosts.yml**：結構性——`internal/accessdirectory`/`internal/directoryapi`/`cmd/pilot-access-directory` 沒有任何程式碼 import `internal/inventory` 或任何 roster 套件（可用 `go list -deps` 驗證），且 `cmd/pilot-access-directory/config.go` 的 `KnownFields(true)` 會讓任何試圖塞 `roster_file`/`inventory_file` 的 config 直接載入失敗（比照 Gateway 的 `TestLoadConfigRejectsForbiddenFields`）。
- **AD07 scope 來自 `pilot-target-*`/`pilot-gateway-*`，不是 hostname 推導**：結構性——`internal/accessdirectory.LoadScopeCatalog` 的唯一輸入是 `HostgroupFinder.HostgroupFind`/`Provider.HostgroupShow`，程式碼裡沒有任何地方讀取自己的 `ansible_fqdn`/hostname 去猜 scope（D3 的具體實作）。
- **AD09 同 target 多 scope 被合併成 Routes**：`internal/accessdirectory.TestLoadDirectoryAccess_SharedTargetMergesIntoOneEntryWithTwoRoutes`（一個 host 同時是 `pilot-target-gpu`/`pilot-target-dmz` 成員時，merge 成一個 `DirectoryTarget` 帶兩個 `Routes`，而非兩筆重複列）。
- **AD05 global My Hosts = 所有 scope effective SSH allow 的 union**：`internal/accessdirectory`（9 個 fake-provider 測試，含跨 scope merge/dedup/query-count 斷言）+ Phase 3 evidence（`docs/evidence/pilot-access-directory/2026-09-18-phase3-directory-backend.md`）已對 `ag-spike-ipa`/`ag-gw01`/`ag-gw02` 的真實 gpu/dmz 兩個 scope 活體驗證過 alice/bob 的交集結果。
- **AD08 no-gateway target 顯示 unavailable、Connect disabled**：`internal/accessdirectory.TestLoadDirectoryAccess_NoGatewayScopeSurfacesRouteStatus` + `cmd/pilot/cmd` 的 `TestDirectoryTargetIsReadyAndLabel`/`directory_tui.go` 的 `directoryTargetIsReady` 邏輯（Connect 選項在該分支完全不會出現）。
- **AD10 `/v1/connect/resolve` 每次 fresh evaluate**：`internal/directoryapi` 的 `TestHandleConnectResolve_SessionIDIsFreshEveryCall`；架構性——`handleConnectResolve` 每次呼叫都重新 `LoadDirectoryAccess`，沒有任何 cache 層可以繞過。
- **AD11 denied target 不可由手動 API target injection resolve**：`internal/directoryapi.TestHandleConnectResolve_TargetInjectionIsInert`。
- **AD12 gateway candidate 必須為 `pilot-gateway-<scope>` member**：`internal/accessdirectory`'s `LoadScopeCatalog`——`GatewayCandidates` 只可能來自該 scope 對應 `pilot-gateway-<scope>` hostgroup 的 `HostgroupShow` 結果，沒有其他資料來源。
- **AD13 gateway candidate host key 經 `sss_ssh_knownhostsproxy`/SSSD 驗證通過**：`/etc/pilot/directory_ssh_config` 與 `cmd/pilot/cmd/portal_ssh.go` 的 `pilotSSHConfig` 常數同一份 directive set（`TestPilotSSHConfigDirectives` 已對後者活體驗證過 `ssh -G`），Directory 的 apply playbook Step 13 安裝的是完全相同內容——尚未對 Directory 自己的 config 檔另跑一次 `ssh -G`，屬於 Phase 5 vm-target 驗收時要補的項目。
- **AD14 Gateway transport failure可 retry下一 same-scope instance**：`cmd/pilot/cmd.TestConnectToGatewayFailoverTriesNextCandidate`。
- **AD15 Gateway explicit authorization deny不得 retry繞過**：Phase 4 的 `connectToGateway` 仍無法從 ssh exit code分辨「明確 deny」與「session 正常結束」——Phase 5（2026-09-18）已在 Gateway 端把 one-shot connect 協定做出來（`cmd/pilot/cmd/portal_session_connect.go`），deny 時 `pilot-session` 回傳非 0 exit 且不啟動 SSH，但 Directory 端仍是單純「transport failure 就 failover」，沒有另外辨識「這是 deny 不是網路問題」。要證明「deny 不會被當成 transport failure 而重試」需要活體 multi-gateway topology（一台故意 deny、下一台 same-scope 不應該被嘗試），尚未執行。目前只有「transport failure 會重試」這一半（AD14）與 Gateway 端 deny 本身（AG38/AG39，unit test）已驗證。
- **AD16 FreeIPA outage fail closed**：`internal/directoryapi` 的錯誤路徑測試 + Phase 3 evidence 已對 `ag-gw01` 上跑的 `pilot-access-directory` 二進位真的指向不存在的 FreeIPA server，`/v1/health`/`/v1/access` 立即回 503。
- **AD20 Directory selection可 handoff到正確 scope Gateway**：`cmd/pilot/cmd.TestConnectToGatewayAllowed` + `TestRunPortalOneShotConnect_Allowed`（unit test），**2026-09-18 已完成真人活體驗證**：`alice` 經 `pilot directory`（`ag-directory01`）分別 Connect 到 gpu scope 的 `ag-target01`（經 `ag-gw01`）與 dmz scope 的 `ag-target02`（經 `ag-gw02`），兩條 scope 都正確路由到各自的 Gateway，見 `docs/verification/pilot-access-gateway.md` §6 / `docs/evidence/pilot-access-directory/2026-09-18-phase5-gateway-handoff.md`。
- **AD21 remote target `whoami` 為原登入 user / AD22 target exit 後回 Directory**：`cmd/pilot/cmd.TestConnectToGatewaySSHFailureReturnsToDirectory`/`TestConnectToGatewayCredentialFailureReturnsToDirectory`/`TestRunPortalOneShotConnect_PropagatesSSHExitCode`（unit test），**2026-09-18 已完成真人活體驗證**：上述兩次真實 Connect 落地後 `whoami`/`id` 都確認是 `alice`（非 gateway 帳號、非其他人），`exit` 離開 target 後乾淨回到 Directory 頂層選單。
- **AD23 HBAC 在 list/connect 間被 revoke → connect deny / AD24 target移出 scope後 connect deny**：架構性——`handleConnectResolve` 每次都重新 `LoadDirectoryAccess`（同 AD10），一個 revoke 在下一次呼叫必然反映；尚未對這個 race window 做過真實的「list 完再 revoke 再 connect」時序性活體測試。
- **AD25 session_id 每次 connect fresh unique / AD26 same session_id 出現在 Directory + Gateway metadata**：AD25 由 `internal/directoryapi.TestHandleConnectResolve_SessionIDIsFreshEveryCall` 涵蓋。AD26 由 Phase 6（`internal/sessionaudit`）落地：`handleConnectResolve` 對同一個 `session_id` 送出 `directory_connect_requested`/`directory_route_resolved`，`connectToGateway` 送出 `directory_gateway_attempt`/`directory_gateway_connected`，同一個 `session_id` 也是 `pilot-connect <session-id> <fqdn>` 送給 Gateway 的那個 ID，Gateway 端 `runPortalOneShotConnect` 用它送出 `gateway_authorize_allowed`/`gateway_authorize_denied`/`target_connect_started`/`session_ended`（`internal/sessionaudit` 的 4 個單元測試 + Gateway/Directory 兩邊既有測試涵蓋事件內容，未逐一列舉）。**單元測試覆蓋「同一個 session_id 貫穿兩端程式碼路徑」，尚未對真實 syslog/`audit-log-forwarding` 管線做過活體「從中央 log 用一個 session ID 重建完整鏈路」的 vm-target 驗證**，待審核者親自跑。
- **AD29 site-wide deploy實際跑到 component，不是假 success**：`cmd/pilot/cmd/site_yml_consistency_test.go`/`tag_coverage_test.go` 已涵蓋 `pilot-access-directory` 的 `site.yml`/tag 對齊，尚未跑過真實 site-wide deploy 拿活體證據。

## 4. 尚未執行的多主機/topology 性質項目

- **AD30 fresh vm-target topology E2E**：需要至少 `ipa1`/`directory-01`/`gw-gpu-01`/`gw-gpu-02`/`gw-dmz-01`/`gpu-target-01`/`dmz-target-01`（spec.md §45 的最小拓樸子集）全部從零 up 一次，跑 `pilot vm-target topology test`，記錄結果到新的 evidence doc。這一步仍未執行——2026-09-18 的驗收重用了既有的 `ag-spike-ipa`/`ag-gw01`/`ag-gw02`/`ag-target01` 加新建的 `ag-directory01`，不是從零 up 的完整 topology spec 跑法。
- Phase 4 landing gate（spec.md §44）本身的四項——「真人 SSH Directory TUI」「arbitrary remote command無 shell」「idempotent apply」「site-wide deployment實際執行 component」——**已於 2026-09-18 對 `ag-directory01` 全部真實驗證通過**，見
  [`docs/evidence/pilot-access-directory/2026-09-18-phase4-directory-tui-deploy-integration.md`](../evidence/pilot-access-directory/2026-09-18-phase4-directory-tui-deploy-integration.md)。

## 5. Gotcha 記錄

- **`freeipa-client-apply.yml` 的新版 `freeipa-server-pool.yml` gate 需要真的 `freeipa-server` inventory group**：header comment 裡舊的 `-e ipa_server_ip=<ip>` 單目標寫法在 `freeipa-client-ha` 落地後不再夠用（會在 `groups['freeipa-server']` 長度檢查卡住）；改用 `pilot vm-target run --group freeipa-server=<既有 IPA server 目標> --group <name>=<新 client> --name <新 client> ... -e target_group=<name>`（不能用 `all`，否則 server host 也會被拉進同一輪 play，DNS 註冊 gate 會把 `ipa_client_fqdn` 誤判成 server 自己的 fqdn）。跑 `playbooks/site.yml` 本身則相反——site.yml 會擋掉任何 `-e target_group=`，`--group` 的 key 要換成元件在 `deploy_catalog.go` 裡的 `DefaultGroup`（例如 `pilot-access-directory`）。詳見 Phase 4 evidence doc。
- 每次要對新 binary 做活體測試前，先確認 `dist/pilot-linux-amd64` 是用**當下** HEAD 重新建置的——舊 binary 不會有新加的 `pilot` 子命令，ForceCommand 會報 `unknown command`，容易誤判成程式碼本身的 bug。

## 6. 明確不在本 repo 範圍的項目

- 站台網路層需求（防火牆/network policy 限制 Directory ingress、Directory→Gateway 只能走特定網段）：比照 `pilot-access-gateway.md` 的 AG31，是站台網路團隊的責任，不是本 repo 的程式行為。
