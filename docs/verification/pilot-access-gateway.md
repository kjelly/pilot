# Verification Spec — Pilot Access Gateway

> 版本：DRAFT v0.4（vm-target 已對 AG01-AG30 實測；AG31 為站台網路層需求，非本 repo 範圍，見 §5；2026-09-14 追加：`pilot_access_gateway_install_forcecommand` 預設改為 `true`；2026-09-15 追加：`site.include` 改為 `true`，不再是 single-component-only，見 §5）
> 對齊規範：docs/superpowers/specs/2026-09-14-pilot-access-gateway-stateless-freeipa-portal-spec.md（Pilot Access Gateway — Stateless FreeIPA-backed Portal），§50-§58
> 維護者：sre

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Inventory group | `pilot-access-gateway`（或明確 `target_group`） |
| 角色 | stateless、read-only、FreeIPA-backed SSH/sudo access gateway 後端（`pilot-access-gateway.service`）+ 使用者 TUI 入口（`pilot portal`） |
| 前置需求 | 已是 FreeIPA client（`freeipa-client-apply.yml`）且有轉發 DNS 記錄；`pilot-target-<scope>` hostgroup 已由 `pilot gateway-scope reconcile` 建立（Phase 6）。Portal 使用者群組（`gateway_portal_user_group`）與 `pilot-access-gateway-login` HBAC rule **不再需要操作者手動用 freeipa-identity roster 預先建立**——2026-09-15 起本 playbook 自己 idempotent 建立兩者（見 §5 gotcha），只有「群組成員（誰是 portal user）」仍是 roster 管的身分資料 |
| 套用範圍 | 單一 gateway 主機的安裝；`pilot_access_gateway_install_forcecommand` **預設已改為 `true`**（2026-09-14，在 §55.1 鎖定回歸測試已於 Phase 8 對 disposable vm-target 跑過並取得核准之後）——沒有明確帶 `-e pilot_access_gateway_install_forcecommand=false` 就會安裝 ForceCommand。**2026-09-15 起 `site.include: true`，不再是 single-component-only**：把 `pilot-access-gateway` 加進某台主機 `hosts.yml` 的 roles 清單，本身就是操作者的核准動作，之後每次全站部署（`playbooks/site.yml`）都會照常套用這個角色，跟其他角色（`docker`/`freeipa-client`……）的語意一致，不需要每次額外打 `--tags pilot-access-gateway`。§0 G4/§55.1 的規則本身沒有變——**只是核准時機點從「每次部署都要重新確認」改成「第一次把這個 role 加進某台主機的當下」**：把 role 加進 `hosts.yml` 之前，仍然要先在該主機（或同等的 disposable vm-target）跑過鎖定回歸測試，之後才能放心讓它隨全站部署自動套用 |
| 風險等級 | **High（預設即安裝 ForceCommand，登入路徑劫持等級變更）**——要暫時退回舊的 opt-in 行為，明確帶 `-e pilot_access_gateway_install_forcecommand=false` |

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

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| AG01 | config | gateway config 含 id/scope/target_hostgroup | 0 | grep -q "id: gpu-01" /etc/pilot/access-gateway.yaml && grep -q "scope: gpu" /etc/pilot/access-gateway.yaml && grep -q "target_hostgroup: pilot-target-gpu" /etc/pilot/access-gateway.yaml |
| AG02 | identity | pilot-gateway service account存在 | 0 | id pilot-gateway |
| AG03 | keytab | service keytab owner/mode正確 | 0 | test "$(stat -c '%U:%G %a' /etc/pilot/pilot-access-gateway.keytab)" = "pilot-gateway:pilot-gateway 400" |
| AG04 | freeipa | FreeIPA CA存在 | 0 | test -s /etc/ipa/ca.crt |
| AG06 | freeipa | FreeIPA JSON-RPC ping（透過 /v1/health） | 0 | curl -s --unix-socket /run/pilot/access-gateway.sock http://localhost/v1/health \| grep -q '"freeipa":"reachable"' |
| AG09 | socket | Unix socket name/mode/group正確 | 0 | test "$(stat -c '%U:%G %a' /run/pilot/access-gateway.sock)" = "pilot-gateway:role-pilot-portal-user 660" |
| AG12 | scope | configured target hostgroup存在 | 0 | curl -s --unix-socket /run/pilot/access-gateway.sock http://localhost/v1/health \| grep -q '"target_scope":"ok"' |
| AG19 | stateless | 沒有 local DB/state | 0 (empty) | test ! -d /var/lib/pilot |
| AG30 | idempotency | 第二次 apply changed=0(多次重跑的性質,由 evidence doc 記錄,非單一 shell 指令可驗證) | 0 | true |

## 3. 不在這份 checklist 逐行覆蓋、但已用其他方式驗證過的項目

以下 AG 編號直接引用 spec.md §52 的原始清單，但**不是**每一項都適合寫成單一 shell checklist row——很多是 unit test 的性質（`internal/peercred`、`internal/identity`、`internal/freeipaaccess`、`internal/accessportal`、`internal/gatewayapi` 各自的測試套件），不是 apply playbook 的某個 task 產生的結果：

- **AG05 service principal Kerberos auth**：AG06 的 `/v1/health` 呼叫本身就需要先成功完成 Kerberos 認證才拿得到 `"freeipa":"reachable"`，兩者共用同一個真實動作。
- **AG07 required read capabilities / AG08 mutation denied**：Phase 0 evidence（`docs/evidence/pilot-access-gateway/2026-09-14-phase0-transport-spike.md`）已對同一種 reader principal 實測：讀成功、寫（`user_add`）被 FreeIPA 用 `ACIError` 擋下，且不需要額外授權設定——bare service principal 預設就是零寫入權限。
- **AG10 SO_PEERCRED identity / AG11 $USER spoof blocked**：`internal/peercred`（真實 self-connect socket 測試）+ Phase 3/4 evidence 的活體 `env USER=root LOGNAME=root` 測試，兩者都證明過。
- **AG13 nested target hostgroup expansion / AG14 HBAC ∩ gateway scope / AG15 live sudo correctness**：`internal/accessportal`（Phase 2, 28 個測試,含真實巢狀/cycle fixture）+ Phase 3-5 對真實 `gpu-a`/`gpu-b`/HBAC/sudo rule 的活體 curl 驗證。
- **AG16 FreeIPA outage fail closed**：`internal/gatewayapi`/`internal/accessportal` 的錯誤路徑測試（resolve 失敗一律回 503/deny，見 Phase 3 `handleConnectAuthorize` 的 "resolve failed, denying" 分支）；**已於 Phase 8 對 vm-target 真的斷線實測**（停 `ag-spike-ipa` 的 `httpd`，`/v1/health`/`/v1/access` 立即回 503、`freeipa:"unreachable"`、`{"error":"access service unavailable"}`；重啟 `httpd` 後下一次請求自動恢復 200，見 Phase 8 evidence doc）——跨主機的破壞性動作，不適合寫成單一 host 的 checklist row。
- **AG17 no roster dependency / AG18 no inventory dependency**：結構性——`internal/freeipaaccess`/`internal/accessportal`/`internal/gatewayapi` 沒有任何程式碼 import roster/inventory 套件（可用 `go list -deps` 驗證），且 `cmd/pilot-access-gateway/config.go` 的 `KnownFields(true)` 會讓任何試圖塞 `roster_file`/`inventory_file` 的 config 直接載入失敗（`TestLoadConfigRejectsForbiddenFields`）。
- **AG22 ~/.ssh/config ignored / AG23 forwarding disabled / AG24 strict host key checking**：Phase 5 `TestPilotSSHConfigDirectives`（對真實 OpenSSH 跑 `ssh -G`，含一個「有毒」`~/.ssh/config` 的活體驗證）。

## 4. Phase 8 完成的項目（多主機/多 session 性質，非單一 host 的 shell checklist row）

- **AG20 portal ForceCommand / AG21 admin shell unaffected / AG25 remote whoami == portal user**：spec.md §55.1 的 3 步鎖定回歸測試已對 `ag-gw01`（disposable vm-target）完整跑過並取得人員核准（見 Phase 8 evidence doc）：(1) `alice`（`role-pilot-portal-user` 成員）SSH 登入直接進入 `pilot portal` TUI，畫面顯示 `User alice`，Ctrl+C 結束整個連線而非取得 shell，`ssh alice@host whoami`（無 PTY）不執行請求的指令、exit 1；(2) `root`（非 portal-user）SSH 登入拿到完全正常的 interactive shell（`whoami` → `root`）；(3) 把旗標設回 `false` 重新 apply，drop-in 被移除、sshd reload，兩種帳號都恢復正常 shell（`alice` 的 `whoami` → `alice`）。過程中還發現並修正一個真的可用性 gap：新增了 rollback 用的 Step 19/20/21 對應任務，讓旗標從 `true` 改回 `false` 時 playbook 會真的移除 drop-in，而不是只是跳過重新安裝。

  **2026-09-15 補充（`scripts/pilot-access-gateway-lockout-test.sh`）**：上面 3 步測試只涵蓋「無 PTY 時指令不執行」跟「root 不受影響」，沒有涵蓋其他標準的 restricted-shell 逃逸手法。已把當天對 `ag-gw01`/`ag-gw02` 活體驗證過的 5 類額外探測寫成可重跑腳本（假設 ForceCommand 已經是啟用狀態，純讀取、不會 mutate 任何東西）：(1) `ssh -tt` 帶指令注入，用 gateway 上的即時 process tree 證明注入的指令從未執行、只跑了 `pilot-session`→`pilot portal`；(2) client 端 `-o RemoteCommand=...` 覆寫；(3) local port forwarding，用 server 端真的回傳 `administratively prohibited` 的 channel 拒絕證明，不只是 client 行為；(4) SFTP subsystem 請求；(5) `sshd -T -C` 對 portal group 實際生效的 `ForceCommand`/`DisableForwarding`/`PermitUserRC`/`X11Forwarding`/`AllowTcpForwarding`/`AllowAgentForwarding`/`PermitTunnel`。對 `ag-gw01`/`ag-gw02` 兩台都跑過，11 項全過。
- **AG26 same-scope gateways return equivalent target set / AG27 different-scope gateways return isolated target sets**：新增第二台 gateway `ag-gw02`。先設成與 `ag-gw01` 相同的 `scope=gpu`（`gateway_id=gpu-02`），對 `alice` 查詢 `/v1/access`，兩台回傳的 `hosts` 陣列（`gpu-a`/`gpu-b`，含相同 HBAC/sudo rule 名稱）逐字元相同，只有 `gateway.id` 不同（AG26）。接著把 `ag-gw02` 重新設成 `scope=dmz`（新建的 `pilot-target-dmz` hostgroup，成員 `dmz-a`），並額外幫 `alice` 建一條真的 HBAC rule（`pilot-grant-login-dmz-test`）授予她對 `dmz-a` 的 sshd 存取——此時 `ag-gw01`（`scope=gpu`）完全看不到 `dmz-a`（即使 alice 對它有真實權限），`ag-gw02`（`scope=dmz`）也完全看不到 `gpu-a`/`gpu-b`，證明每台 gateway 的交集運算只吃自己的 `target_hostgroup`，不會因為使用者在別的 scope 有權限就外溢（見 Phase 8 evidence doc 的完整 curl 輸出）。
- **AG28 service alias does not mix scopes**：架構性——`internal/freeipaaccess`/`internal/accessportal`/`internal/gatewayapi`/`cmd/pilot-access-gateway` 沒有任何程式碼碰 DNS 或 VIP（`go list -deps` 可驗證沒有 import 任何 DNS 相關套件），每台 gateway 的 scope 完全由它自己的 `/etc/pilot/access-gateway.yaml` 決定，AG26/27 已證明這個交集運算是嚴格 per-gateway 的——「同一個 DNS/VIP 混用不同 scope 的 gateway」是操作面/部署拓樸的錯誤（把不同 scope 的 gateway 放到同一個 service alias 後面），不是這個 repo 的程式碼能防呆的範圍，比照 AG31 的處理方式記錄為操作規則而非可測試的程式行為。
- **grant / breakglass active rule**：`pilot-access-gateway` 架構上完全不讀 grant JSON（spec.md §57 明文）——它只讀 FreeIPA 當下的 HBAC/sudo rule 狀態，不區分某條 rule 是手動建立還是由 `internal/inventory` 的 grant compiler（`pilot access breakglass activate` 等）產生。這個屬性已經被 Phase 8 的 AG26/27 測試間接證明：`pilot-grant-login-gpu-test`/`pilot-grant-sudo-gpu-test`（沿用 grant compiler 的命名慣例）與新建的 `pilot-grant-login-dmz-test` 全部是真實、當下 active 的 FreeIPA rule，gateway 對它們的處理跟任何其他 HBAC/sudo rule 完全一樣——沒有任何特殊分支代碼路徑。

## 5. Gotcha 記錄

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

## 6. 明確不在本 repo 範圍的項目

- **AG31 out-of-scope SSH egress blocked by network policy**：站台網路層需求（防火牆/network policy 擋非 scope 內的 SSH 流量），非本 repo 範圍——`pilot-access-gateway` 本身沒有、也不打算有網路層 enforcement 能力，這是站台網路團隊的責任。
