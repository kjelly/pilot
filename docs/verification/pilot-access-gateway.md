# Verification Spec — Pilot Access Gateway

> 版本：DRAFT v0.1（vm-target 已對 AG01-AG19、AG29、AG30 實測；AG20-AG28、AG31 留給 Phase 8）
> 對齊規範：docs/tmp/now/spec.md（Pilot Access Gateway — Stateless FreeIPA-backed Portal），§50-§58
> 維護者：sre

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Inventory group | `pilot-access-gateway`（或明確 `target_group`） |
| 角色 | stateless、read-only、FreeIPA-backed SSH/sudo access gateway 後端（`pilot-access-gateway.service`）+ 使用者 TUI 入口（`pilot portal`） |
| 前置需求 | 已是 FreeIPA client（`freeipa-client-apply.yml`）且有轉發 DNS 記錄；`pilot-target-<scope>` hostgroup 已由 `pilot gateway-scope reconcile` 建立（Phase 6） |
| 套用範圍 | 單一 gateway 主機的安裝；不含 sshd ForceCommand（Phase 8 才開啟，見 §55.1 gate） |
| 風險等級 | Medium（讀取真實 FreeIPA 存取資料；尚未啟用 ForceCommand，不會鎖使用者登入） |

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
- **AG16 FreeIPA outage fail closed**：`internal/gatewayapi`/`internal/accessportal` 的錯誤路徑測試（resolve 失敗一律回 503/deny，見 Phase 3 `handleConnectAuthorize` 的 "resolve failed, denying" 分支）；尚未在 vm-target 上真的斷線實測（需要動網路，留給之後）。
- **AG17 no roster dependency / AG18 no inventory dependency**：結構性——`internal/freeipaaccess`/`internal/accessportal`/`internal/gatewayapi` 沒有任何程式碼 import roster/inventory 套件（可用 `go list -deps` 驗證），且 `cmd/pilot-access-gateway/config.go` 的 `KnownFields(true)` 會讓任何試圖塞 `roster_file`/`inventory_file` 的 config 直接載入失敗（`TestLoadConfigRejectsForbiddenFields`）。
- **AG22 ~/.ssh/config ignored / AG23 forwarding disabled / AG24 strict host key checking**：Phase 5 `TestPilotSSHConfigDirectives`（對真實 OpenSSH 跑 `ssh -G`，含一個「有毒」`~/.ssh/config` 的活體驗證）。

## 4. 明確延後到 Phase 8 的項目（不是這份文件目前要驗收的範圍）

- **AG20 portal ForceCommand / AG21 admin shell unaffected / AG25 remote whoami == portal user**：需要真的裝上 sshd ForceCommand，而這個 playbook 目前預設 `pilot_access_gateway_install_forcecommand: false`（spec.md §0 G4/§55.1 gate——沒做過 vm-target 鎖定回歸測試前不得對任何主機開啟）。
- **AG26 same-scope gateways return equivalent target set / AG27 different-scope gateways return isolated target sets / AG28 service alias does not mix scopes**：需要至少兩台 gateway + 兩個 scope 的多節點拓樸（Phase 8 Multi-Gateway E2E）。
- **AG31 out-of-scope SSH egress blocked by network policy**：站台網路層需求，非本 repo 範圍。

## 5. Gotcha 記錄

- `-e freeipa_servers=[...]` 這種寫法 Ansible 不會可靠解析成 list（同 Phase 6 發現的坑），必須用 `-e '{"freeipa_servers": [...]}'` 的 JSON 物件形式。
- `ipa service-add` 要求目標主機已有正向 DNS record；`freeipa-client-apply.yml` 的自動 DNS 註冊在本次實測未必觸發，需要先確認（`getent hosts <fqdn>`）或手動 `ipa dnsrecord-add`。
- **不要**建一個跟 FreeIPA 群組同名的 local fallback group（例如 `gateway_portal_user_group`）——nsswitch 的 `files` 來源比 `sss` 先查，會讓 local 群組永久遮蔽真正的 FreeIPA 群組。
- systemd `.socket` 的 `ListenStream=` 路徑所在目錄，若靠 `.service` 單元的 `RuntimeDirectory=` 建立，重啟 **service**（不只是 socket）會把整個目錄連同 socket 檔一起刪掉——`RuntimeDirectory=` 要放在 `.socket` 單元本身。
