# Verification Spec — Pilot Access Gateway

> 版本：DRAFT v0.2（vm-target 已對 AG01-AG30 實測；AG31 為站台網路層需求，非本 repo 範圍，見 §5）
> 對齊規範：docs/tmp/now/spec.md（Pilot Access Gateway — Stateless FreeIPA-backed Portal），§50-§58
> 維護者：sre

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Inventory group | `pilot-access-gateway`（或明確 `target_group`） |
| 角色 | stateless、read-only、FreeIPA-backed SSH/sudo access gateway 後端（`pilot-access-gateway.service`）+ 使用者 TUI 入口（`pilot portal`） |
| 前置需求 | 已是 FreeIPA client（`freeipa-client-apply.yml`）且有轉發 DNS 記錄；`pilot-target-<scope>` hostgroup 已由 `pilot gateway-scope reconcile` 建立（Phase 6） |
| 套用範圍 | 單一 gateway 主機的安裝；`pilot_access_gateway_install_forcecommand` 預設仍是 `false`——§55.1 的鎖定回歸測試已在 Phase 8 對 disposable vm-target 跑過並取得核准，但正式環境每次啟用仍需要重新走一次人員核准（spec.md §0 G4 rule 3），不會因為這裡驗證過就自動視為已核准 |
| 風險等級 | Medium（讀取真實 FreeIPA 存取資料）；一旦 `pilot_access_gateway_install_forcecommand=true` 則為 High（登入路徑劫持等級變更，見 §4） |

## 1.5 依賴變數契約

| 變數名稱 | 說明 | 必填 |
|---|---|---|
| `gateway_id` | 這台 gateway 的 instance id，例如 `gpu-01` | 是 |
| `gateway_scope` | scope 名稱，決定 `pilot-target-<scope>` | 是 |
| `gateway_fqdn` | 這台 gateway 的 FQDN；預設 `ansible_fqdn` | 否 |
| `freeipa_servers` | FreeIPA server FQDN 清單（JSON list，見下方 gotcha） | 是 |
| `ipa_realm` | Kerberos realm，例如 `IPA.PILOT.INTERNAL` | 是 |
| `ipa_admin_password` | 只在**安裝當下**用來建立 reader service principal + keytab；只能來自 vault，執行期完全不用 | 是 |
| `pilot_binary_path` / `pilot_access_gateway_binary_path` | 本機已建置好的兩個 binary 路徑 | 是 |
| `gateway_portal_user_group` | Portal 使用者群組；**必須是既有的 FreeIPA 群組**，本 playbook 不建立 local fallback（見 §2 gotcha） | 否，預設 `role-pilot-portal-user` |
| `pilot_access_gateway_install_forcecommand` | 是否安裝 sshd ForceCommand；**Phase 8 前必須是 false** | 否，預設 `false` |

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
- **AG26 same-scope gateways return equivalent target set / AG27 different-scope gateways return isolated target sets**：新增第二台 gateway `ag-gw02`。先設成與 `ag-gw01` 相同的 `scope=gpu`（`gateway_id=gpu-02`），對 `alice` 查詢 `/v1/access`，兩台回傳的 `hosts` 陣列（`gpu-a`/`gpu-b`，含相同 HBAC/sudo rule 名稱）逐字元相同，只有 `gateway.id` 不同（AG26）。接著把 `ag-gw02` 重新設成 `scope=dmz`（新建的 `pilot-target-dmz` hostgroup，成員 `dmz-a`），並額外幫 `alice` 建一條真的 HBAC rule（`pilot-grant-login-dmz-test`）授予她對 `dmz-a` 的 sshd 存取——此時 `ag-gw01`（`scope=gpu`）完全看不到 `dmz-a`（即使 alice 對它有真實權限），`ag-gw02`（`scope=dmz`）也完全看不到 `gpu-a`/`gpu-b`，證明每台 gateway 的交集運算只吃自己的 `target_hostgroup`，不會因為使用者在別的 scope 有權限就外溢（見 Phase 8 evidence doc 的完整 curl 輸出）。
- **AG28 service alias does not mix scopes**：架構性——`internal/freeipaaccess`/`internal/accessportal`/`internal/gatewayapi`/`cmd/pilot-access-gateway` 沒有任何程式碼碰 DNS 或 VIP（`go list -deps` 可驗證沒有 import 任何 DNS 相關套件），每台 gateway 的 scope 完全由它自己的 `/etc/pilot/access-gateway.yaml` 決定，AG26/27 已證明這個交集運算是嚴格 per-gateway 的——「同一個 DNS/VIP 混用不同 scope 的 gateway」是操作面/部署拓樸的錯誤（把不同 scope 的 gateway 放到同一個 service alias 後面），不是這個 repo 的程式碼能防呆的範圍，比照 AG31 的處理方式記錄為操作規則而非可測試的程式行為。
- **grant / breakglass active rule**：`pilot-access-gateway` 架構上完全不讀 grant JSON（spec.md §57 明文）——它只讀 FreeIPA 當下的 HBAC/sudo rule 狀態，不區分某條 rule 是手動建立還是由 `internal/inventory` 的 grant compiler（`pilot access breakglass activate` 等）產生。這個屬性已經被 Phase 8 的 AG26/27 測試間接證明：`pilot-grant-login-gpu-test`/`pilot-grant-sudo-gpu-test`（沿用 grant compiler 的命名慣例）與新建的 `pilot-grant-login-dmz-test` 全部是真實、當下 active 的 FreeIPA rule，gateway 對它們的處理跟任何其他 HBAC/sudo rule 完全一樣——沒有任何特殊分支代碼路徑。

## 5. Gotcha 記錄

- `-e freeipa_servers=[...]` 這種寫法 Ansible 不會可靠解析成 list（同 Phase 6 發現的坑），必須用 `-e '{"freeipa_servers": [...]}'` 的 JSON 物件形式。
- `ipa service-add` 要求目標主機已有正向 DNS record；`freeipa-client-apply.yml` 的自動 DNS 註冊在本次實測未必觸發，需要先確認（`getent hosts <fqdn>`）或手動 `ipa dnsrecord-add`。
- **不要**建一個跟 FreeIPA 群組同名的 local fallback group（例如 `gateway_portal_user_group`）——nsswitch 的 `files` 來源比 `sss` 先查，會讓 local 群組永久遮蔽真正的 FreeIPA 群組。
- systemd `.socket` 的 `ListenStream=` 路徑所在目錄，若靠 `.service` 單元的 `RuntimeDirectory=` 建立，重啟 **service**（不只是 socket）會把整個目錄連同 socket 檔一起刪掉——`RuntimeDirectory=` 要放在 `.socket` 單元本身。
- **CRITICAL（Phase 8）**：`internal/freeipaaccess.NewClient` 原本在建構時就同步載入 keytab/CA/krb5.conf，任何一個檔案有問題都會讓 `cmd/pilot-access-gateway` 的 `main()` 直接 exit——因為這個服務是 socket-activated，每個新連線都會再觸發一次必死的 service start，很快撞到 systemd 的 start-rate-limit，**連 socket 單元本身都會變成 `failed`**，即使後來把 keytab 修好也不會自動恢復，要人工 `systemctl reset-failed`。已修成：keytab/CA/krb5.conf 的載入延後到第一次真正呼叫時才做（跟既有的 session 建立一樣是 lazy + per-call retry），壞掉時服務照樣活著、`/v1/health`/`/v1/access` 回 503 degraded（跟 FreeIPA 斷線的行為一致），檔案修好後**下一次請求就自動恢復**，不需要重啟。見 `internal/freeipaaccess/kerberos_test.go` 的 `TestNewClientDoesNotEagerlyLoadCredentials`/`TestClientRetriesCredentialLoadOnEveryCall`。
- **Gateway 主機自己也需要一條 HBAC rule 才能讓 portal 使用者登入**：`pilot-access-gateways` hostgroup 只是 management inventory classification（spec.md §57 明文說它不代表 target 存取權），實際上 SSH 登入 gateway 主機本身（觸發 ForceCommand 之前，PAM/SSSD 的 account 階段就會先檢查）也需要一條 HBAC rule 授權——這是站台/`freeipa-identity` 該預先建立好的前置條件，不是這支 apply playbook 的責任（比照 `gateway_portal_user_group` 必須先在 FreeIPA 存在的處理原則）。Phase 8 測試時額外建了 `pilot-access-gateway-login`（`role-pilot-portal-user` → `pilot-access-gateways` → `sshd`）才能讓 §55.1 的鎖定回歸測試跑起來。
- libvirt 的 vm-target IP 會被回收重用：舊 VM 留下的 `~/.ssh/known_hosts` host key 換了新 VM 但 IP 相同時，SSH 會直接拒絕（`REMOTE HOST IDENTIFICATION HAS CHANGED`），要先 `ssh-keygen -R <ip>` 清掉舊條目。
- FreeIPA 使用者密碼被 admin 用 `ipa passwd` 重設後會進入「must change at next login」狀態；`ssh user@host`（純 `password`/`keyboard-interactive` 認證）在這個狀態下會被 sshd 直接斷線（`monitor_read: unpermitted request 104`），不會進入互動改密碼流程——要先用 `kinit <user>`（透過任一台已 enroll 的主機）做一次改密碼，之後 SSH 才能正常登入（同一份 v5.1 舊教訓，這次換成 SSH 層再踩一次）。

## 6. 明確不在本 repo 範圍的項目

- **AG31 out-of-scope SSH egress blocked by network policy**：站台網路層需求（防火牆/network policy 擋非 scope 內的 SSH 流量），非本 repo 範圍——`pilot-access-gateway` 本身沒有、也不打算有網路層 enforcement 能力，這是站台網路團隊的責任。
