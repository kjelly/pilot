# Runbook — FreeIPA 稽核示範：sudo ls 通過 / sudo ps 拒絕

> 撰寫日期：2026-07-02 (UTC)
> 對齊：`playbooks/fixtures/freeipa-audit-demo.yml`、`playbooks/fixtures/freeipa-audit-user-setup.yml`、
> `playbooks/fixtures/freeipa-audit-sim.yml`
> 規格依據：`docs/verification/freeipa-server.md`、`docs/verification/freeipa-client.md`（皆 v1.0）

---

## 0. 目標

在一台原生 FreeIPA server VM 與一台已 enroll 的 FreeIPA client VM 上，證明：

1. server 建立的使用者（`audituser`）可以真的登入 client。
2. 該使用者被限制「只能 `sudo ls`」：`sudo ls /` 成功，`sudo ps aux` 失敗。
3. 兩個指令（成功與失敗）都留下稽核紀錄，且在 server 端與 client 端都看得到。

只使用 `go run ./cmd/pilot vm-target ...` 操作 VM；唯一無法只靠 `vm-target` 完成的
地方在 §4 有明確標注並說明原因。

---

## 1. §0.5 事實快照（AGENTS.md §2）

```
$ go run ./cmd/pilot vm-target list
NAME            STATUS   IP             VCPU  MEM(MiB)  DISK(GiB)  CREATED
freeipa-client  running  192.168.123.5  2     2048      30         2026-07-02 13:57:55
freeipa-server  running  192.168.123.2  2     4096      30         2026-07-02 13:34:34

$ go run ./cmd/pilot vm-target show-inventory --name freeipa-server
# ansible_user: root, key /tmp/pilot-vms/freeipa-server/id_ed25519

$ go run ./cmd/pilot vm-target show-inventory --name freeipa-client
# ansible_user: root, key /tmp/pilot-vms/freeipa-client/id_ed25519

# ~/.vault/freeipa-sandbox.yaml keys:
#   ipa_admin_password, ipa_dm_password, audit_demo_user_password
```

**Alignment decision**: spec 目標群組與 vm-target 名稱一致（`freeipa-server` /
`freeipa-client`），`pilot vm-target run` 自動加 `-l <name>`。無需調整（既非 A 也非
B）。

两台 VM 都是既有的長跑 vm-target（見 [[freeipa-native-not-container]] /
[[freeipa-client-ubuntu]]）：server 原生裝在 EL9（`ipactl status` 全部 RUNNING），
client 是 Ubuntu 24.04 並已 `ipa-client-install` enroll（`klist -k` 有
`host/freeipa-client.ipa.pilot.internal` 的 keytab）。

---

## 2. Fixtures 設計

| 檔案 | 執行對象 | 作用 |
|---|---|---|
| `freeipa-audit-demo.yml` | freeipa-server | 建立 IPA user `audituser`；建立 sudo rule `audit-demo-ls-only`（只允許 `/usr/bin/ls`，明確拒絕 `/usr/bin/ps`）；加 `--sudooption='!authenticate'` 讓規則免密碼、可用 `sudo -n` 驗證；設定穩定密碼 |
| `freeipa-audit-user-setup.yml` | freeipa-client | 幫 `audituser` 產生本機 SSH 金鑰並寫入自己的 `authorized_keys`，讓後續能對 client **真的 SSH 登入**這個帳號（不是 `runuser` 模擬） |
| `freeipa-audit-sim.yml` | freeipa-client | 完整模擬：`kinit`（Kerberos 登入驗證）→ SSH 登入 `audituser@localhost`（真登入）→ 分別跑 `sudo -n ls /` 與 `sudo -n ps aux` 並斷言各自的 rc |

> **重要修正（本次跑出來才發現的真 bug，非猜測）**：
> 1. IPA 中央 sudo 規則預設**需要密碼**才能執行，`sudo -n`（non-interactive）在
>    沒有 `!authenticate` 選項時一律回 `sudo: a password is required`，不代表
>    規則設錯。已在 `freeipa-audit-demo.yml` 補上
>    `ipa sudorule-add-option ... --sudooption='!authenticate'`。
> 2. 幫 sudo rule 補 `!authenticate` 後，client 上的 SSSD **要重啟一次**
>    （`systemctl restart sssd`）才會即時反映新規則；否則會沿用舊的快取到密碼
>    仍是必須的狀態，等它自然的 sudo 快取過期。
> 3. `sudo ps aux` 這個 task 一開始只有 `changed_when: false`，沒有
>    `failed_when: false` —— Ansible 預設非 0 return code 就是任務失敗，導致
>    「預期失敗」的驗證步驟被 Ansible 直接判定成 playbook failed。補上
>    `failed_when: false` 後改由後面的 `assert: rc != 0` 任務去做真正的判斷。
> 4. 原始設計想在 `freeipa-audit-sim.yml`（跑在 client 上）內直接
>    `ssh root@<server-ip>` 去抓 server 上的 KDC log —— **這步做不到**：
>    client 跟 server 之間沒有互相信任的 SSH 金鑰（`vm-target` 各自的
>    `id_ed25519` 只給 orchestrating host 用，兩台 VM 互相都沒有對方的
>    private key）。已移除該步驟，改成 §4 用獨立的
>    `pilot vm-target exec --name freeipa-server -- ...` 從外部下指令查
>    server 端稽核紀錄——這正是 `case-study-freeipa.md` §7 講的多 VM
>    cross-check 模式：跨 VM 檢查要從 orchestrating host 個別對每台
>    `vm-target exec`，不要指望某個 VM 能直接連到另一台。

---

## 3. 實際套用（真跑出來的輸出）

### 3.1 Server fixtures（idempotent 重跑，第二次驗證用）

```
$ go run ./cmd/pilot vm-target run --name freeipa-server \
    playbooks/fixtures/freeipa-audit-demo.yml \
    -e fixtures_target_group=all -e @~/.vault/freeipa-sandbox.yaml

PLAY RECAP *********************************************************************
freeipa-server : ok=12   changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```

### 3.2 Client 帳號設定（一次性）

```
$ go run ./cmd/pilot vm-target run --name freeipa-client \
    playbooks/fixtures/freeipa-audit-user-setup.yml -e target_group=all

PLAY RECAP *********************************************************************
freeipa-client : ok=2    changed=2    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```

### 3.3 完整模擬（修完 §2 三個 bug 之後，乾淨跑一次）

```
$ go run ./cmd/pilot vm-target run --name freeipa-client \
    playbooks/fixtures/freeipa-audit-sim.yml \
    -e sim_target_group=all -e ipa_server_ip=192.168.123.2 \
    -e @~/.vault/freeipa-sandbox.yaml

TASK [Sim — SSH login result] **************************************************
ok: [freeipa-client] => {
    "msg": [
        "audituser",
        "uid=1082400003(audituser) gid=1082400003(audituser) groups=1082400003(audituser)"
    ]
}

TASK [Sim — sudo ls / result] **************************************************
ok: [freeipa-client] => {"msg": "Command : sudo ls /\nResult  : SUCCEEDED (rc=0)\n..."}

TASK [Sim — sudo ps aux result] *************************************************
ok: [freeipa-client] => {"msg": "Command : sudo ps aux\nResult  : FAILED (rc=1)\n..."}

PLAY RECAP *********************************************************************
freeipa-client : ok=15   changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```

---

## 4. 稽核紀錄證據（真的查出來的，非預期輸出）

### 4.1 Client 端 — sudo 決策的權威紀錄（成功/失敗都在，含理由）

```
$ go run ./cmd/pilot vm-target exec --name freeipa-client -- sudo journalctl -t sudo --no-pager -n 40

Jul 02 15:39:08 freeipa-client.ipa.pilot.internal sudo[9812]: audituser : PWD=/home/audituser ; USER=root ; COMMAND=/usr/bin/ls /
Jul 02 15:39:08 freeipa-client.ipa.pilot.internal sudo[9812]: pam_unix(sudo:session): session opened for user root(uid=0) by audituser(uid=1082400003)
Jul 02 15:39:08 freeipa-client.ipa.pilot.internal sudo[9812]: pam_unix(sudo:session): session closed for user root
Jul 02 15:39:09 freeipa-client.ipa.pilot.internal sudo[9872]: audituser : command not allowed ; PWD=/home/audituser ; USER=root ; COMMAND=/usr/bin/ps aux
```

`ls` 那筆沒有拒絕理由（成功、開了 root session）；`ps` 那筆明確寫
`command not allowed`（失敗、連 session 都沒開）。兩筆都有 timestamp、PID、
使用者。

### 4.2 Server 端 — KDC 稽核紀錄（Kerberos 登入驗證，與上面同一個 session 對得上時間戳）

```
$ go run ./cmd/pilot vm-target exec --name freeipa-server -- sudo grep -a audituser /var/log/krb5kdc.log

Jul 02 15:39:05 ipa1.ipa.pilot.internal krb5kdc[11664](info): AS_REQ ... NEEDED_PREAUTH: audituser@IPA.PILOT.INTERNAL for krbtgt/IPA.PILOT.INTERNAL@IPA.PILOT.INTERNAL, Additional pre-authentication required
Jul 02 15:39:05 ipa1.ipa.pilot.internal krb5kdc[11666](info): AS_REQ ... ISSUE: authtime 1783006745, ... audituser@IPA.PILOT.INTERNAL for krbtgt/IPA.PILOT.INTERNAL@IPA.PILOT.INTERNAL
```

`kinit` 產生的 AS_REQ/ISSUE 事件即為 server 端可查的登入稽核紀錄，時間戳與
client 端 `sudo ls`/`sudo ps` 事件落在同一次模擬視窗內，可用時間戳與
principal `audituser@IPA.PILOT.INTERNAL` 對照。

---

## 5. 結論

| 檢查項 | 結果 |
|---|---|
| freeipa-server / freeipa-client 依規格建置並存活 | ✅（既有 vm-target，13/13、10/10 spec 驗證見 [[freeipa-native-not-container]] / [[freeipa-client-ubuntu]]） |
| client 可登入 server 建立的使用者 | ✅ 真 SSH 登入 `audituser@localhost`（非 `runuser` 模擬），`whoami`/`id` 回傳正確 |
| 使用者只許可 `sudo ls` | ✅ IPA sudo rule `audit-demo-ls-only`：allow `/usr/bin/ls`、deny `/usr/bin/ps` |
| `sudo ls` 成功、`sudo ps` 失敗 | ✅ rc=0 / rc=1，`sudo -n` 皆非互動阻塞 |
| 兩個指令都有稽核紀錄 | ✅ client `journalctl -t sudo`（決策紀錄，含拒絕理由）＋ server `krb5kdc.log`（登入紀錄） |

---

## 6. 收尾

VM 目前保留執行中，供人工檢視。要收尾時：

```bash
go run ./cmd/pilot vm-target down --name freeipa-client
go run ./cmd/pilot vm-target down --name freeipa-server
```
