# FreeIPA 主機生命週期 Runbook — 新增與刪除

## 0. 目標

記錄把一台主機納入 FreeIPA（enrollment）、以及徹底移除一台已 enrollment 主機
（decommission）這兩個操作的標準指令與驗證步驟，讓兩者都可重複、有真實證據，
而不是各自臨場拼指令。

## 0.5 目前有效的事實快照

- 目標環境：2 台 disposable `pilot vm-target` — `hd-ipa1`（almalinux-9，FreeIPA
  server，`root@192.168.122.2`，domain `ipa.pilot.internal` / realm
  `IPA.PILOT.INTERNAL`）、`hd-client1`（ubuntu-24.04，`ubuntu@192.168.122.3`）。
- workspace：`hosts.yml` 兩台機器，`hd-ipa1`（role `freeipa-server`，帶
  `freeipa_roster_file`）與 `hd-client1.ipa.pilot.internal`（role
  `freeipa-client`，**key 本身就是 FQDN** — 見 §3.1 的命名規則）。
- vault：`~/.vault/main.yaml` 內 `ipa_admin_password`（只確認存在，未保存值）。
- 對齊決定：A。`hosts.yml` 的 host key 直接用 FreeIPA FQDN，對齊
  `providerFQDN`（`internal/decommission/planner.go`）既有慣例。
- 測試狀態：本次證據基於目前 working tree **尚未 commit** 的兩個修正（見 §5）：
  `cmd/pilot/cmd/host_decommission.go`、
  `internal/decommission/{planner.go,references.go,references_test.go}`。
  尚未 freeze 成 immutable candidate；正式驗收前建議依 AGENTS.md §1 走一次乾淨
  checkout 完整測試，把本文件的 tested revision 換成真正的 commit/tree ID。
- 正式結果：新增（enrollment）`ok=63 changed=8`；刪除（decommission apply）
  `STATUS completed`，並以 `ipa host-show`/`ipa dnsrecord-show`/
  `/etc/ipa/default.conf` 三項獨立核對確認零殘留。
- Evidence：[2026-09-11 add/remove + 2 bugs found+fixed](../evidence/host-decommission/2026-09-11-add-remove-freeipa-host.md)。

## 1. 邊界與前置

兩個操作各自的邊界：

| 操作 | 入口 | 主要 playbook / 元件 |
|------|------|----------------------|
| 新增（enrollment） | `pilot deploy`（互動精靈）或直接 `ansible-playbook`/`pilot vm-target run` | `playbooks/apply/freeipa-client-apply.yml`（component `freeipa-client`） |
| 納入身分/授權（day-2，選用） | `pilot reconcile` 或直接跑 apply | `playbooks/apply/freeipa-identity-apply.yml`（canonical roster：users/groups/hostgroups/hbac/sudo/host） |
| 刪除（decommission） | `pilot host decommission plan/apply` | 內部依序驅動 `playbooks/decommission/freeipa-client-decommission.yml`（本機解除註冊）+ `freeipa-identity-apply.yml`（伺服器端 roster 收斂與 `ipa host-del`/`dnsrecord-del`） |

前置：

- FreeIPA server 已由 `freeipa-server-apply.yml` 部署且 `ipactl status` 全綠。
- 新增與刪除都需要 `ipa_admin_password`（走 `-e @~/.vault/main.yaml`，絕不寫進
  hosts.yml/roster 明文）。
- 刪除操作需要 `hosts.yml`（不是單純的 `inventory.yml`）——`pilot host
  decommission` 只認 workspace 目錄下的 `hosts.yml`。

## 2. 新增 FreeIPA 主機

### 2.1 `hosts.yml` 加入條目

```yaml
hosts:
  new-host.ipa.pilot.internal:        # 見 §3.1：FQDN 命名規則同樣適用於新增的主機
    ansible_host: "10.0.0.20"
    ansible_user: "ubuntu"
    roles: [freeipa-client]
```

有 FreeIPA 原生 DNS 時，enrollment 會自動幫這台主機在 FreeIPA DNS 補
A/AAAA record（`freeipa_client_register_dns`，預設沿用 server 的
`freeipa_setup_dns`），不需要另外手動加。

### 2.2 展開 inventory 並套用 enrollment

```bash
pilot inventory generate --in hosts.yml --out inventory.yml   # 或用 pilot edit 互動編輯

# 互動精靈（推薦，正式主機日常操作走這條）：
pilot deploy

# 或直接組指令（可重複、適合腳本化/CI）：
ansible-playbook -i inventory.yml playbooks/apply/freeipa-client-apply.yml \
  --limit new-host.ipa.pilot.internal \
  -e ipa_server_ip=<FreeIPA server IP> \
  -e @~/.vault/main.yaml \
  --check --diff        # 先預覽

ansible-playbook -i inventory.yml playbooks/apply/freeipa-client-apply.yml \
  --limit new-host.ipa.pilot.internal \
  -e ipa_server_ip=<FreeIPA server IP> \
  -e @~/.vault/main.yaml
```

`pilot vm-target` 測試時等價指令（見 evidence §3 的真實輸出）：

```bash
pilot vm-target run --name <vm> playbooks/apply/freeipa-client-apply.yml \
  -e target_group=all -e ipa_server_ip=<server-vm-ip> -e ipa_verify_user=admin \
  -e @~/.vault/main.yaml
```

### 2.3 （選用）納入 canonical roster 的群組/HBAC/sudo

只有這台主機需要被 hostgroup/netgroup/HBAC/sudo 規則涵蓋時才需要——單純
enrollment（能登入、能被 SSSD 認得）不需要碰 roster。用 `pilot edit` 的
roster manager，或直接編輯 roster 的 `hosts:`/`hostgroups:` 區塊（schema 見
`playbooks/apply/freeipa-identity.roster.example.yaml`），然後：

```bash
ansible-playbook -i inventory.yml playbooks/apply/freeipa-identity-apply.yml \
  -e freeipa_roster_file=~/.vault/ipa-identity.yaml \
  -e @~/.vault/main.yaml
```

### 2.4 驗證

```bash
ssh <user>@<new-host> 'test -f /etc/ipa/default.conf && echo ENROLLED'
ansible <freeipa-server> -i inventory.yml -m shell -a \
  'echo "<admin密碼>" | kinit admin; ipa host-show new-host.ipa.pilot.internal'
pilot verify --dir . docs/verification/freeipa-client.md
```

## 3. 刪除 FreeIPA 主機（decommission）

### 3.1 命名規則（先讀，否則會卡在假的 blocker）

`hosts.yml` 裡這台主機的 **key 必須是它在 FreeIPA 的真實 FQDN**
（`providerFQDN` 的既有慣例：優先用 `host.Name`，不是 `ansible_host`）。用短
名（例如 `hd-client1`）會讓「這台主機自己的 service principal」被誤判成
「未知的 service principal」，plan 直接卡死在：

```
blocker[ownership_unknown]: freeipa-client: unknown/unproven service principal blocks host deletion:
  host <短名> still has service principal(s) managed by it: host/<短名>.<domain>@...
```

修法是把 `hosts.yml` 的 key 改成 FQDN，不是改程式碼（見 evidence §5）。

### 3.2 Plan → 檢查 → Apply

```bash
pilot host decommission plan --dir . --host "<fqdn>"
# status=executable 才往下走；status=blocked 先看 blockers 逐一排除
# （常見：unknown service principal — 先透過該 principal 的擁有元件清掉,
#   例如 internal-endpoint 的 HTTP/<fqdn>、NFS 的 nfs/<fqdn>）

pilot host decommission show --id <plan-id>      # 需要時看完整 plan 內容

pilot host decommission apply --dir . --id <plan-id> --confirm-host "<fqdn>"
# STATUS completed 且有 receipt 才算真正完成；
# STATUS blocked 代表尚未收斂（見 §5 bug #2 — 若卡在
# active_residue 且一直不動，先確認 workspace 裡「任何一台主機」
# （通常是 FreeIPA server 自己）有宣告 freeipa_roster_file，而不是
# 只檢查這台要刪除的主機本身）
```

失敗/中斷後恢復，不會重跑已完成的步驟（idempotent）：

```bash
pilot host decommission resume --dir . --id <plan-id>
```

### 3.3 獨立驗證（不要只信工具自己回報的 STATUS）

```bash
ansible <freeipa-server> -i inventory.yml -m shell -a \
  'echo "<admin密碼>" | kinit admin; ipa host-show <fqdn>; ipa dnsrecord-show <domain> <short-name>'
# 兩者都應該回「not found」

ssh <user>@<retiring-host> 'test -f /etc/ipa/default.conf && echo STILL_ENROLLED || echo UNINSTALLED'
```

`hosts.yml`/`inventory.yml` 會在 `apply` 完成時自動移除這台主機、重新產生
`inventory.yml`（`final_inventory_revision` 會變）；不需要也不應該手動再改一次
hosts.yml 去刪它。

## 4. Rollback

- **新增**：enrollment 尚未完成前中斷，重跑同一條 apply 指令即可（幂等）；已
  enrollment 但想撤銷，走 §3 的刪除流程，不要手動 `ipa-client-install
  --uninstall`（會跳過伺服器端 roster/host-del 收斂，留下殘留 host object）。
- **刪除**：`plan` 完全唯讀，不會動任何東西。`apply` 一旦執行到 central
  cleanup（`ipa host-del`）就不可逆——沒有「復原」路徑，只能重新走一次 §2
  新增流程。`apply` 中途失敗，用 `pilot host decommission resume` 接續，不要
  重新 `plan` 再 `apply`（會重跑已完成的破壞性步驟）。

## 5. 踩過的雷（2026-09-11，真實 bug，已修復）

完整證據見 [evidence](../evidence/host-decommission/2026-09-11-add-remove-freeipa-host.md)。

1. **`no_log` 把「SSH 連不上」偽裝成「Kerberos 認證失敗」**：`pilot host
   decommission plan/apply` 在乾淨/一次性環境（例如 `docker run --rm` 的
   pilot-cli 容器）下第一次一定連不上目標主機——因為它沒有像 `pilot
   deploy`/`reconcile`/`edit`/`mcp` 一樣先建立自己的 ansible SSH ControlPath
   scratch 目錄，仰賴 `ansible.cfg` 預設的 `~/.ansible/cp/...` 早就存在，一次性
   容器裡從來不存在這個目錄。錯誤訊息因為 `freeipa-identity-apply.yml`「Kinit
   admin」任務的 `no_log: true` 被整個蓋成 `{"censored": ...}`，看起來像密碼/
   realm 錯誤，實際上是 `unix_listener: cannot bind to path ...: No such file
   or directory`。已修復（`buildHostDecommissionProviders` 現在跟其他指令一樣
   呼叫 `prepareDeployAnsibleRuntime`）。
2. **decommission 對「一般 client 主機」永遠卡死在 `active_residue`**：roster
   路徑只看「要刪除的那台主機自己」的 `freeipa_roster_file`，但正常情況下只有
   FreeIPA server（或 nfs-server/nfs-client）才會宣告這個欄位——一般 client
   主機從來不會有。結果是本機解除註冊會成功，但伺服器端的 roster 收斂／
   `ipa host-del` 永遠是靜默 no-op，`apply` 永遠回報 `blocked:
   active_residue`，無法收斂也無法重跑出不同結果。已修復（`rosterPathFor` 現在
   會 fallback 掃 workspace 裡任何一台主機宣告的 `freeipa_roster_file`）。
3. **命名**：見 §3.1，`hosts.yml` 的 host key 不是 FQDN 時，unknown-service-
   principal 的 gate 會誤判成真的未知 principal——這是命名慣例問題，不是
   bug，照 §3.1 把 key 改成 FQDN 即可。
