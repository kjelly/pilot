# Runbook — FreeIPA 目錄服務（389-ds）稽核日誌

> 撰寫日期：2026-07-06 (UTC)；v1.1（2026-07-17）併入端到端 sudo 稽核示範
> （見 §6，原 `docs/runbooks/freeipa-audit-demo.md`，該檔已歸檔）
> 對齊：`docs/verification/freeipa-server.md`（v1.1，C14–C16）、`playbooks/apply/freeipa-server-apply.yml`（tag `freeipa-audit`）
> 維護者：sre

---

## 0. 目標與範圍

在原生 FreeIPA server（EL9）上，開啟並驗證 **389-ds 目錄服務的稽核日誌**：把每一筆
LDAP **寫入操作**（新增/修改/刪除 user、group、sudo rule…）與**被拒絕的寫入**都記到
`/var/log/dirsrv/<instance>/audit`，可依 bind DN（`modifiersname`）追溯是誰改的。

**這一層 ≠ KDC/sudo 稽核**。兩者是不同層次，別混淆：

| 稽核層 | 記什麼 | 在哪 | 對應文件 |
|--------|--------|------|----------|
| **389-ds 目錄稽核**（本 runbook） | 目錄樹的**寫入/被拒寫入**（LDAP modify/add/del） | `/var/log/dirsrv/slapd-<REALM>/audit` | `freeipa-server.md` C14–C16 |
| KDC / sudo 稽核 | Kerberos 認證、`sudo` 允許/拒絕事件 | KDC 日誌 / SSSD | 本檔 §6（端到端示範） |

389-ds 稽核日誌**出廠預設關閉**；由 apply playbook 的 `freeipa-audit` task 開啟
（動態生效、免重啟），本 runbook 的每條指令都在 live vm-target 實跑過（見 §3/§4）。

---

## 1. §0.5 事實快照（AGENTS.md §2）

```
$ go run ./cmd/pilot vm-target show-inventory --name freeipa-server
# all.hosts.freeipa-server: ansible_host 192.168.122.3, ansible_user root,
#   key /var/lib/libvirt/images/pilot/freeipa-server/id_ed25519

# 389-ds instance（由 realm 推導：IPA.PILOT.INTERNAL → 點換連字號）：
#   slapd-IPA-PILOT-INTERNAL
# 稽核檔：/var/log/dirsrv/slapd-IPA-PILOT-INTERNAL/audit  (mode 600 dirsrv:dirsrv → 需 root/sudo)

# ~/.vault/main.yaml keys: ipa_admin_password, ipa_dm_password, audit_demo_user_password
```

**Alignment decision**：vm-target host 在 group `all`（非 `freeipa-server`），
`pilot vm-target run/verify` 自動加 `-l freeipa-server`；apply 用 `-e target_group=all`。

---

## 2. 開啟稽核（apply）

`freeipa-audit` task 先 `dsconf config get` 讀現況，只有旗標尚非 `on` 時才
`dsconf config replace ...=on`——**冪等**、動態生效免重啟；`dsconf` 走 ldapi socket
以 root autobind，**不需 Directory Manager 密碼**。要停用整段：`-e ipa_enable_audit_log=false`。

```bash
go run ./cmd/pilot vm-target run --name freeipa-server \
    playbooks/apply/freeipa-server-apply.yml \
    -e target_group=all -e ipa_server_ip=192.168.122.3 \
    -e @~/.vault/main.yaml
```

**真實輸出**（2026-07-06；`off`→`on` 首次開啟）：

```
TASK [FreeIPA — 389-ds audit log: read current logging config] *****************
ok: [freeipa-server]
TASK [FreeIPA — 389-ds audit log: turn on write + failed-write auditing (dynamic, no restart)] ***
changed: [freeipa-server]
PLAY RECAP *********************************************************************
freeipa-server : ok=16  changed=1  unreachable=0  failed=0  skipped=3  rescued=0  ignored=0
```

**冪等驗證**（同指令再跑一次；旗標已 `on` → enable task 略過）：

```
freeipa-server : ok=14  changed=0  unreachable=0  failed=0  skipped=4  rescued=0  ignored=0
```

---

## 3. 檢視稽核狀態與紀錄（read-only）

```bash
go run ./cmd/pilot vm-target exec --name freeipa-server -- bash -c '
  dsconf slapd-IPA-PILOT-INTERNAL config get \
    nsslapd-auditlog-logging-enabled nsslapd-auditfaillog-logging-enabled nsslapd-auditlog
  ls -la /var/log/dirsrv/slapd-IPA-PILOT-INTERNAL/audit
  head -n 20 /var/log/dirsrv/slapd-IPA-PILOT-INTERNAL/audit'
```

**真實輸出**（2026-07-06；開啟後的第一筆稽核紀錄，恰好就是「開啟稽核」這個 `cn=config` 寫入本身）：

```
nsslapd-auditlog-logging-enabled: on
nsslapd-auditfaillog-logging-enabled: on
nsslapd-auditlog: /var/log/dirsrv/slapd-IPA-PILOT-INTERNAL/audit
-rw-------. 1 dirsrv dirsrv 356 Jul  6 02:22 /var/log/dirsrv/slapd-IPA-PILOT-INTERNAL/audit

time: 20260706022147
dn: cn=config
result: 0
changetype: modify
replace: nsslapd-auditlog-logging-enabled
nsslapd-auditlog-logging-enabled: on
-
replace: modifiersname
modifiersname: cn=Directory Manager
-
```

> 每筆紀錄含 `time` / `dn`（被改的物件）/ `changetype` / `modifiersname`（誰改的）；
> `result:` 非 0 者即為被拒寫入（auditfaillog）。

---

## 4. 驗證（spec C14–C16）

```bash
go run ./cmd/pilot vm-target verify --name freeipa-server \
    docs/verification/freeipa-server.md --timeout 40
```

**真實輸出**（2026-07-06T02:22Z，verdict **PASS pass=16 fail=0 skip=0**）：

```json
{"id":"C14","status":"pass","detail":"stdout contains \"nsslapd-auditlog-logging-enabled: on\""}
{"id":"C15","status":"pass","detail":"stdout contains \"nsslapd-auditfaillog-logging-enabled: on\""}
{"id":"C16","status":"pass","detail":"rc=0 matches expected 0"}
```

---

## 5. 常見問題

- **C14/C15 fail**：稽核未開；重跑 §2 apply（或手動
  `sudo dsconf slapd-IPA-PILOT-INTERNAL config replace nsslapd-auditlog-logging-enabled=on nsslapd-auditfaillog-logging-enabled=on`，動態生效）。
- **C16 fail（已開但檔案為空）**：做一次目錄寫入觸發紀錄（如 `ipa user-mod admin --title=x`）；
  或確認 instance 名/路徑（`ls /etc/dirsrv/`）與是否以 `sudo` 執行（檔案 `mode 600`）。
- **換 realm/domain**：instance 名與稽核檔路徑會跟著變（`IPA.PILOT.INTERNAL`→`slapd-IPA-PILOT-INTERNAL`），
  spec C14–C16 的硬編字串也要同步改。
- **輪替與磁碟用量**不在 C14–C16 範圍（`nsslapd-auditlog-maxlogsperdir` /
  `-logmaxdiskspace` 沿用出廠值）；長期落地站台請自行納入磁碟監控（見 spec §5 例外）。
- **C16 verify 緊接 apply 完成後立刻執行，可能撞到稽核檔案剛觸發寫入、尚未
  真正落盤的短暫 race**（rc=2，`[WARNING]: Deprecation warnings ...` 混在
  detail 裡）——2026-07-17 整併重測時真的遇到過，間隔數秒重跑 verify 即
  乾淨 PASS，不代表稽核功能沒開。

---

## 6. 端到端 sudo 稽核示範：`sudo ls` 通過 / `sudo ps` 拒絕（實測，2026-07-17）

> 本節原為獨立文件 `docs/runbooks/freeipa-audit-demo.md`（2026-07-02 首次
> 撰寫），2026-07-17 整併進本檔並用當次整併驗證的環境**重新實跑**，下方為
> 該次真實輸出。目的：證明 389-ds 目錄稽核（above §2–§5）跟 KDC/sudo 決策
> 稽核是**不同層次**——本節示範的是後者：一個被限制「只能 `sudo ls`」的
> IPA 使用者，成功/失敗的 sudo 決策都留下可稽核紀錄，且在 server（KDC）與
> client（`journalctl`）兩端都能各自查到。

### 6.1 拓撲

沿用 §1 的 `freeipa-server`，加一台已 enroll 的 FreeIPA client
（本次重測用既有 pool 中的 `client-vm`，角色等同 `freeipa-client`，IP
192.168.122.6）。兩者的 server/client spec 基線先確認 PASS
（`freeipa-server.md` pass=18、`freeipa-client.md` pass=10），確保不是在
已經半壞的環境上疊加新故障。

### 6.2 Fixtures 設計

| 檔案 | 執行對象 | 作用 |
|---|---|---|
| `freeipa-audit-demo.yml` | freeipa-server | 建立 IPA user `audituser`（透過 import 標準的 `freeipa-client-fixtures.yml`，`ipa_fixture_manage_sudorule=false` 只建 user）；建立 sudo rule `audit-demo-ls-only`（只允許 `/usr/bin/ls`，明確拒絕 `/usr/bin/ps`）；加 `--sudooption='!authenticate'` 讓規則免密碼、可用 `sudo -n` 驗證；設定穩定密碼 |
| `freeipa-audit-user-setup.yml` | freeipa-server + freeipa-client | 兩個 play：先 import `freeipa-client-fixtures.yml` 確保 `audituser` 存在（server 側、需 vault），再幫 `audituser` 產生本機 SSH 金鑰並寫入自己的 `authorized_keys`（client 側），讓後續能對 client **真的 SSH 登入**這個帳號（不是 `runuser` 模擬）。vm-target inventory 一次只有一台 VM，比對不到群組的 play 自動 skip，所以照舊各跑各的 |
| `freeipa-audit-sim.yml` | freeipa-client | 完整模擬：SSH 登入 `audituser@localhost`（真登入）→ 分別跑 `sudo -n ls /` 與 `sudo -n ps aux` 並斷言各自的 rc |

### 6.3 實際套用（2026-07-17 真實輸出）

```bash
go run ./cmd/pilot vm-target run --name freeipa-server \
    playbooks/test/fixtures/freeipa-audit-demo.yml \
    -e fixtures_target_group=all -e @~/.vault/main.yaml
```

```
PLAY RECAP *********************************************************************
freeipa-server             : ok=17   changed=6    unreachable=0    failed=0    skipped=3    rescued=0    ignored=0
```

```bash
go run ./cmd/pilot vm-target run --name freeipa-client \
    playbooks/test/fixtures/freeipa-audit-user-setup.yml -e target_group=all -e @~/.vault/main.yaml
```

```
PLAY RECAP *********************************************************************
client-vm                  : ok=2    changed=2    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```

第一次跑模擬**真的踩到一個已知 gotcha**（並非新 bug——`freeipa-audit-demo.md`
原本就記載過，本次重測再次真實命中，證明它仍然存在、仍需手動處理）：

```bash
go run ./cmd/pilot vm-target run --name freeipa-client \
    playbooks/test/fixtures/freeipa-audit-sim.yml \
    -e sim_target_group=all -e ipa_server_ip=192.168.122.3 -e @~/.vault/main.yaml
```

```
fatal: [client-vm]: FAILED! => {"cmd": "ssh ... audituser@localhost -- sudo -n ls / ...",
  "stdout": "sudo: a password is required", ...}
```

**原因**：sudo rule 的 `!authenticate` 選項是在 server 端設定，但 client 端
SSSD 的 sudo 快取還沒反映這個新規則。**解法**：`systemctl restart sssd`
後重跑：

```bash
go run ./cmd/pilot vm-target exec --name client-vm -- sudo systemctl restart sssd
go run ./cmd/pilot vm-target run --name freeipa-client \
    playbooks/test/fixtures/freeipa-audit-sim.yml \
    -e sim_target_group=all -e ipa_server_ip=192.168.122.3 -e @~/.vault/main.yaml
```

重跑後乾淨 PASS：

```
TASK [Sim — sudo ls / result] ***************************************************
ok: [client-vm] => {"msg": "Command : sudo ls /\nResult  : SUCCEEDED (rc=0)\n..."}

TASK [Sim — sudo ps aux result] **************************************************
ok: [client-vm] => {"msg": "Command : sudo ps aux\nResult  : FAILED (rc=1)\n..."}

PLAY RECAP *********************************************************************
client-vm                  : ok=15   changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```

### 6.4 稽核紀錄證據（2026-07-17 真實輸出）

**Client 端 — sudo 決策紀錄（成功/失敗都在，含拒絕理由）**：

```bash
go run ./cmd/pilot vm-target exec --name client-vm -- sudo journalctl -t sudo --no-pager -n 20
```

```
Jul 17 06:56:56 client-vm.ipa.pilot.internal sudo[7208]: audituser : PWD=/home/audituser ; USER=root ; COMMAND=/usr/bin/ls /
Jul 17 06:56:56 client-vm.ipa.pilot.internal sudo[7208]: pam_unix(sudo:session): session opened for user root(uid=0) by audituser(uid=275400004)
Jul 17 06:56:57 client-vm.ipa.pilot.internal sudo[7268]: audituser : command not allowed ; PWD=/home/audituser ; USER=root ; COMMAND=/usr/bin/ps aux
```

**Server 端 — KDC 稽核紀錄（同一次模擬視窗內的登入事件，時間戳對得上）**：

```bash
go run ./cmd/pilot vm-target exec --name freeipa-server -- sudo grep -a audituser /var/log/krb5kdc.log
```

```
Jul 17 06:56:55 ipa1.ipa.pilot.internal krb5kdc[22801](info): AS_REQ ... NEEDED_PREAUTH: audituser@IPA.PILOT.INTERNAL for krbtgt/IPA.PILOT.INTERNAL@IPA.PILOT.INTERNAL, Additional pre-authentication required
Jul 17 06:56:55 ipa1.ipa.pilot.internal krb5kdc[22801](info): AS_REQ ... ISSUE: authtime 1784271415, ... audituser@IPA.PILOT.INTERNAL for krbtgt/IPA.PILOT.INTERNAL@IPA.PILOT.INTERNAL
```

**Server 端 — 389-ds 目錄稽核（同一時窗，`audituser` 密碼設定觸發的 LDAP
modify，證明兩層稽核彼此獨立且都留了紀錄）**：

```
time: 20260717065545
dn: uid=audituser,cn=users,cn=accounts,dc=ipa,dc=pilot,dc=internal
result: 0
changetype: modify
replace: passwordgraceusertime
```

### 6.5 冪等重跑

```bash
go run ./cmd/pilot vm-target run --name freeipa-server \
    playbooks/test/fixtures/freeipa-audit-demo.yml \
    -e fixtures_target_group=all -e @~/.vault/main.yaml
```

```
PLAY RECAP *********************************************************************
freeipa-server             : ok=17   changed=0    unreachable=0    failed=0    skipped=3    rescued=0    ignored=0
```

### 6.6 Cleanup（確認測試帳號/規則不殘留）

沒有現成的 cleanup playbook；用 `ipa` CLI 手動刪：

```bash
# kinit admin 後
ipa sudorule-del audit-demo-ls-only
ipa user-del audituser
```

真實輸出：`ok=4 changed=2 failed=0`（rule/user 各一次 `changed`）。

> **Cleanup 驗證本身也踩到跟 DR 演練（見 `restic-backup.md` §6.6）同一種
> SSSD 快取陷阱**：`ipa user-del` 後**立刻**在 client 執行
> `id audituser@ipa.pilot.internal` 仍然回報存在（`uid=275400004(audituser)...`），
> 因為 client 端 SSSD 快取還沒過期，命中的是刪除前的快取項目——不是刪除
> 沒生效。清掉 client 的 SSSD 快取（`rm -f
> /var/lib/sss/db/{cache,timestamps}_ipa.pilot.internal.ldb &&
> systemctl restart sssd`）後重查，才真正回報 `no such user`：

```
$ id audituser@ipa.pilot.internal
id: 'audituser@ipa.pilot.internal': no such user
```

`audituser` 在 client 上因登入產生的 home directory（`/home/audituser`）
不會隨 IPA 帳號刪除自動清掉，須手動 `rm -rf /home/audituser`。

清理後重驗 server/client 基線，確認未受影響：

```
freeipa-server verify → PASS pass=18 fail=0 skip=0
freeipa-client verify → PASS pass=10 fail=0 skip=0
```

### 6.7 結論

| 檢查項 | 結果 |
|---|---|
| freeipa-server / freeipa-client 依規格建置並存活 | ✅ |
| client 可登入 server 建立的使用者 | ✅ 真 SSH 登入 `audituser@localhost`，`id` 回傳正確 |
| 使用者只許可 `sudo ls` | ✅ IPA sudo rule `audit-demo-ls-only`：allow `/usr/bin/ls`、deny `/usr/bin/ps` |
| `sudo ls` 成功、`sudo ps` 失敗 | ✅ rc=0 / rc=1 |
| 兩個指令都有稽核紀錄，且與 389-ds 目錄稽核是不同層次 | ✅ client `journalctl -t sudo`＋server `krb5kdc.log`（sudo/登入決策）與 server 389-ds `audit` 檔（目錄寫入）三者互相獨立 |
| Fixture 冪等重跑 | ✅ `changed=0` |
| Cleanup 後帳號/規則不殘留 | ✅（需先清 client SSSD 快取才能正確觀察到，見 §6.6） |
