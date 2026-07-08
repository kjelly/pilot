# Runbook — FreeIPA 目錄服務（389-ds）稽核日誌

> 撰寫日期：2026-07-06 (UTC)
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
| KDC / sudo 稽核 | Kerberos 認證、`sudo` 允許/拒絕事件 | KDC 日誌 / SSSD | [[freeipa-audit-demo]] |

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
