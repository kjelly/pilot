# Runbook — restic-backup（跨主機通用 restic 備份到 S3）

> 撰寫日期：2026-07-06 (UTC)；v1.1 補 FreeIPA 災難復原演練（見 §6）
> 對齊：`docs/verification/restic-backup.md`（v1.1）、`playbooks/apply/restic-backup-apply.yml`
> 維護者：sre
>
> 想**重跑**§6 的 FreeIPA 災難復原演練？照抄步驟清單見
> `docs/runbooks/restic-backup-dr-drill-test-plan.md`——本檔 §6 是帶完整真實
> 輸出的紀錄，那份是抽掉逐字輸出、方便直接複製貼上的可重複測試計畫。

---

## 0. 目標與範圍

用 [restic](https://restic.net/) 把「本專案有用到的軟體」的資料與設定檔加密
備份到 S3。目的地預設是本專案自建的 `docs/verification/seaweedfs-s3.md`
（SeaweedFS S3 gateway），也可以整個覆寫成外部/獨立 S3。備份範圍（路徑清單、
備份前置指令）逐主機可覆寫，比照 `wazuh-fim.md` 的 `wazuh_fim_directories`
設計——見 `docs/verification/restic-backup.md` §1.5。

本 runbook 涵蓋兩台 vm-target：一台跑 `seaweedfs-s3-apply.yml` 當備份目的地
（`s3-dest`），一台跑 `restic-backup-apply.yml` 當被備份的主機
（`restic-backup`）。

---

## 1. §0.5 事實快照（AGENTS.md §2）

```
$ go run ./cmd/pilot vm-target list
s3-dest         running  192.168.122.3  2  1536  15  2026-07-06
restic-backup   running  192.168.122.5  2  1536  15  2026-07-06
```

**規格對齊**：兩台都是單一 host key 的 vm-target inventory（沒有 group），
所以 apply 一律帶 `-e target_group=all`，不能沿用 `wazuh-manager.md`/
`log-server.md` 那種「host key 剛好等於 playbook 預設 group 名」的免 override
寫法——`restic-backup-apply.yml` 的 `hosts:` 預設是 `restic-backup` 這個
**group**，vm-target 的單機 inventory 裡沒有這個 group，只有同名的 **host**，
兩者在 ansible 的 pattern-matching 語意下不相等，必須顯式 `target_group=all`
才會命中。

機密（`restic_aws_access_key_id`/`restic_aws_secret_access_key`/
`restic_password`）本 runbook 用 `-e` 帶入方便重現；正式 inventory 應改用
`-e @<vault 檔>`，見 §1.5 的變數說明與 `AGENTS.md` 對機密的通則。

---

## 2. 部署（apply）

### 2.1 前置：備份目的地（SeaweedFS S3 gateway）

```bash
go run ./cmd/pilot vm-target up --name s3-dest \
    --ssh-user ubuntu --disk 15 --memory 1536 --vcpus 2 \
    --ssh-timeout 5m --boot-timeout 5m

go run ./cmd/pilot vm-target run --name s3-dest \
    playbooks/apply/core-infra-provider-apply.yml \
    -e target_group=all -e infra_role=docker
```

實際輸出：

```
PLAY RECAP *********************************************************************
s3-dest                    : ok=6    changed=2    unreachable=0    failed=0    skipped=13   rescued=0    ignored=0
```

```bash
go run ./cmd/pilot vm-target run --name s3-dest \
    playbooks/apply/seaweedfs-s3-apply.yml -e target_group=all
```

實際輸出：

```
PLAY RECAP *********************************************************************
s3-dest                    : ok=9    changed=6    unreachable=0    failed=0    skipped=2    rescued=0    ignored=0
```

> 到這一步 SeaweedFS S3 gateway 是**預設的匿名模式**（`seaweedfs-s3.md` 的
> C6-C8 已知偏差）——這對純 `curl` 的 smoke test 夠用，但 §5 會說明這對
> `restic` **不夠用**，需要額外一步。

### 2.2 首次 apply restic-backup（會先踩到一個真的 bug，見 §5）

```bash
go run ./cmd/pilot vm-target up --name restic-backup \
    --ssh-user ubuntu --disk 15 --memory 1536 --vcpus 2 \
    --ssh-timeout 5m --boot-timeout 5m

go run ./cmd/pilot vm-target run --name restic-backup \
    playbooks/apply/restic-backup-apply.yml \
    -e target_group=all \
    -e restic_s3_target_host=192.168.122.3 \
    -e restic_aws_access_key_id=sandbox-access-key \
    -e restic_aws_secret_access_key=sandbox-secret-key \
    -e restic_password=sandbox-repo-password-123
```

第一次跑，實際輸出（失敗，rescue 自動接手清掉機密檔+停用 timer）：

```
TASK [Step 11: Run one backup now if needed (spec C4, C5, C6)] *****************
[ERROR]: Task failed: Module failed: Unable to start service restic-backup.service: Job for restic-backup.service failed because the control process exited with error code.

TASK [ROLLBACK — stop and disable the timer] ***********************************
changed: [restic-backup]

TASK [ROLLBACK — remove the env file (contains secrets)] ***********************
changed: [restic-backup]

PLAY RECAP *********************************************************************
restic-backup              : ok=15   changed=10   unreachable=0    failed=1    skipped=0    rescued=1    ignored=0
```

`journalctl -u restic-backup.service` 的真正錯誤：

```
Fatal: create key in repository at s3:http://s3-backup-server:8333/pilot-restic-backup failed: client.PutObject: Signed request requires setting up SeaweedFS S3 authentication
```

根因與修法見 §5「Bug 1」。修好後（在 `s3-dest` 掛上 `-s3.config` identity
檔並讓 access/secret key 跟 restic 端一致）重跑同一條指令：

```
TASK [Step 11: Run one backup now if needed (spec C4, C5, C6)] *****************
changed: [restic-backup]

PLAY RECAP *********************************************************************
restic-backup              : ok=12   changed=1    unreachable=0    failed=0    skipped=1    rescued=0    ignored=0
```

---

## 3. Verify

```bash
go run ./cmd/pilot vm-target verify --name restic-backup \
    docs/verification/restic-backup.md
```

實際輸出：

```
verdict: **PASS**  (pass=10 fail=0 skip=0)
```

完整報告：

```
| ID | Status | Detail |
|----|--------|--------|
| C1 | pass | rc-from-stdout=0 matches expected 0 |
| C2 | pass | rc-from-stdout=0 matches expected 0 |
| C3 | pass | rc-from-stdout=600 matches expected 600 |
| C4 | pass | rc-from-stdout=0 matches expected 0 |
| C5 | pass | rc-from-stdout=0 matches expected 0 |
| C6 | pass | rc-from-stdout=0 matches expected 0 |
| C7 | pass | rc-from-stdout=0 matches expected 0 |
| C8 | pass | rc-from-stdout=0 matches expected 0 |
| C9 | pass | rc-from-stdout=0 matches expected 0 |
| C10 | pass | rc-from-stdout=0 matches expected 0 |
```

`rc-from-stdout=` 前綴代表這是真的跑出來的 rc（不是巧合的 fallback 值），
見 `docs/verification/wazuh-fim.md` §5 對這個 detail 欄位的說明。

---

## 4. 冪等性 + 逐主機自訂路徑（實測）

### 4.1 冪等檢查：同樣變數重跑，changed=0

```bash
go run ./cmd/pilot vm-target run --name restic-backup \
    playbooks/apply/restic-backup-apply.yml \
    -e target_group=all -e restic_s3_target_host=192.168.122.3 \
    -e restic_aws_access_key_id=sandbox-access-key \
    -e restic_aws_secret_access_key=sandbox-secret-key \
    -e restic_password=sandbox-repo-password-123
```

實際輸出：

```
TASK [Step 11: Run one backup now if needed (spec C4, C5, C6)] *****************
skipping: [restic-backup]

PLAY RECAP *********************************************************************
restic-backup              : ok=11   changed=0    unreachable=0    failed=0    skipped=2    rescued=0    ignored=0
```

`Step 11` 被跳過（已有快照、env/腳本都沒變），這是刻意設計的條件觸發（見 §5
「Bug 2」），不是意外的 no-op。

### 4.2 負向測試：沒填目的地，apply 必須在任何 mutation 前乾淨失敗

```bash
go run ./cmd/pilot vm-target run --name restic-backup \
    playbooks/apply/restic-backup-apply.yml \
    -e target_group=all \
    -e restic_aws_access_key_id=x -e restic_aws_secret_access_key=y -e restic_password=z
```

實際輸出：

```
TASK [Gate: backup destination must be resolvable] *****************************
fatal: [restic-backup]: FAILED! => {
    "assertion": "(restic_s3_target_host | length > 0) or (restic_s3_alias not in restic_repository)",
    "changed": false,
    "evaluated_to": false,
    "msg": "restic_s3_target_host is empty AND restic_repository still uses the default s3-backup-server alias — the backup would have no reachable destination. Either pass -e restic_s3_target_host=<S3 IP/FQDN> (default SeaweedFS S3 gateway target), or override -e restic_repository=... to a fully externally-resolvable S3 endpoint."
}

PLAY RECAP *********************************************************************
restic-backup              : ok=1    changed=0    unreachable=0    failed=1    skipped=0    rescued=0    ignored=0
```

`ok=1 changed=0` — 卡在 `pre_tasks` 的 assert，沒有任何檔案/服務被動到。

### 4.3 逐主機自訂備份路徑（host_vars 覆寫的實測）

```bash
go run ./cmd/pilot vm-target run --name restic-backup \
    playbooks/apply/restic-backup-apply.yml \
    -e target_group=all -e restic_s3_target_host=192.168.122.3 \
    -e restic_aws_access_key_id=sandbox-access-key \
    -e restic_aws_secret_access_key=sandbox-secret-key \
    -e restic_password=sandbox-repo-password-123 \
    -e '{"restic_backup_paths": ["/etc", "/var/log/apt"]}'
```

實際輸出：

```
TASK [Step 11: Run one backup now if needed (spec C4, C5, C6)] *****************
changed: [restic-backup]

PLAY RECAP *********************************************************************
restic-backup              : ok=12   changed=2    unreachable=0    failed=0    skipped=1    rescued=0    ignored=0
```

env 檔內容變了（新路徑清單）→ 觸發一次新備份。用
`restic snapshots --json` 確認新快照真的涵蓋新路徑：

```json
[
  {
    "paths": ["/etc"],
    "short_id": "76f40059"
  },
  {
    "paths": ["/etc", "/var/log/apt"],
    "short_id": "8d02e88e"
  }
]
```

第二筆快照正確多了 `/var/log/apt`，第一筆（只有 `/etc`）沒被覆蓋或刪除——
restic 的快照是累加的，不是覆寫的，這也是選它而非單純 `tar` 的原因之一。
重跑 verify 仍是 10/10 PASS（`restic check` 對多快照的 repository 一樣過）。

---

## 5. 已知偏差 / 實測踩過的坑

| 問題 | 原因 | 修法 |
|------|------|------|
| **Bug 1 — `restic init` 對預設匿名模式的 SeaweedFS S3 gateway 失敗**：`Fatal: create key in repository ... Signed request requires setting up SeaweedFS S3 authentication` | `seaweedfs-s3.md` 的「匿名模式」只接受**完全不帶簽章**的請求（見該 spec §5 已知偏差，及本次同步補充的 `docs/runbooks/seaweedfs-s3.md` §5 對應列）。但 `restic` 的 S3 後端（跟 `aws` CLI/boto3 一樣）**一律**送 AWS SigV4 簽章請求，即使 access/secret key 是隨便填的字串——SeaweedFS 收到「有簽章、但沒有任何 identity 可比對」的請求時直接拒絕，跟「完全不簽章」是不同的程式路徑。這在只用純 `curl` 驗證過 `seaweedfs-s3.md` 的情況下不會被發現——本 spec 是第一個用「真正的 S3 client」對接這個 gateway 的案例 | 在 `s3-dest` 掛 `-e seaweedfs_s3_config_path=<s3.json>`（`seaweedfs-s3-apply.yml` 既有的選填變數），內容是一組 `{accessKey, secretKey}`，並讓 `restic-backup-apply.yml` 的 `restic_aws_access_key_id`/`restic_aws_secret_access_key` 跟這組值一致。**要用 `restic`（或任何簽章 S3 client）接這個 gateway，identity 設定不是「可選的加固項」，是必要條件**——跟 `seaweedfs-s3.md` 自己 C6-C8 anonymous smoke test 的定位剛好相反 |
| **Bug 2（設計階段就避免，未落地成真的 bug）— oneshot service 的 `state: started` 天生不冪等** | `ansible.builtin.systemd: name=<oneshot>.service state=started` 每次執行都會觸發，因為 oneshot 服務執行完就變回 `inactive`，下次 apply 一樣判定「需要 start」而回報 changed——跟 `spec-driven-feature-workflow` skill 點名的 `state: restarted` 陷阱是同一類問題 | 先跑一個唯讀的 `restic snapshots --json`（`changed_when: false`）查現況，只在「完全沒有快照」或「env/腳本剛被這次 apply 改過」時才觸發 `restic-backup.service`；§4.1 的冪等重跑（`changed=0`）與 §4.3 的「改路徑就觸發新快照」都證明這個條件邏輯正確 |
| **Bug 3 — apply playbook 原本只支援 Debian（`apt`），對 EL 系（FreeIPA server 用的 AlmaLinux 9）100% 會 fail** | `docs/verification/restic-backup.md` C1 原本用 `dpkg -s restic`，EL 系沒有 `dpkg` 指令，會直接以 rc=127 誤判成「沒裝」；EL9 BaseOS/AppStream 也沒有 `restic` 套件本身，需要 EPEL。這是本次拿真實 FreeIPA server（EL9）當備份對象才第一次踩到的組合——先前所有實測都在 Ubuntu vm-target 上做 | `restic-backup-apply.yml` 新增 `ansible_os_family` 分流：`Debian`→`apt`；`RedHat`→先 `dnf install epel-release` 再 `dnf install restic`。checklist C1 改成套件管理器中立的 `command -v restic`（見 spec v1.1 變更紀錄）|
| **Bug 4 — systemd oneshot service 底下 `restic` 找不到 `$HOME`，備份直接失敗** | `Fatal: ... unable to open cache: unable to locate cache directory: neither $XDG_CACHE_HOME nor $HOME are defined`。systemd 啟動的 service（即使 `User=root` 隱含執行）預設不帶 `$HOME`，跟互動式 shell 不同；`restic` 需要 `$HOME` 定位本機 metadata cache 目錄 | 備份腳本（`pilot-restic-backup.sh`）開頭補 `export HOME=/root`；Step 10 的唯讀 precheck 也補上同一行，兩處呼叫 `restic` 的地方都要一致 |
| **Bug 5 — 目的地 bucket 若從未存在，`restic`（`restic snapshots`／`restic init`）不會快速失敗，而是用遞增 backoff 重試到看起來像卡死** | SeaweedFS S3 gateway **不會**在 `PutObject`/`CreateBucket` 時自動生出不存在的 bucket（跟部分「隱式建立 bucket」的 S3 相容實作行為不同）；`restic` 的 S3 後端把「bucket does not exist」歸類成可重試錯誤，backoff 從 1s 開始每次翻倍，真的等到失敗可能要數十分鐘，观察上跟「hang 住」幾乎沒有分別。本次 FreeIPA 演練第一次 apply 就撞到——因為 `restic_s3_bucket` 預設值 `pilot-restic-backup` 從未在 SeaweedFS 上建立過（`seaweedfs-s3-apply.yml` 只會建它自己的 smoke bucket `pilot-s3-smoke`）| **兩層修法**：(1) 操作面——走本專案 SeaweedFS 目的地時，首次套用 `restic-backup-apply.yml` 前，先在該 SeaweedFS host 用 `weed shell` 手動建好 `restic_s3_bucket`（預設 `pilot-restic-backup`）：`sudo docker exec pilot-seaweedfs sh -c "echo 's3.bucket.create -name pilot-restic-backup' \| weed shell"`（跟 `seaweedfs-s3-apply.yml` 建自己 smoke bucket 用的是同一招）；(2) 程式面防禦——`restic-backup-apply.yml` 的 Step 10 precheck 與腳本內的 `restic snapshots`/`restic init` 呼叫全部包一層 `timeout 60`，即使真的忘記先建 bucket，也會在 60 秒內乾淨失敗並留下清楚的 rc 而不是無限期看似卡住 |

---

## 6. FreeIPA server + client 災難復原演練（實測，2026-07-06）

> 目的：用本專案既有的 `freeipa-server`/`freeipa-client` 當「有實際資料/設定檔
> 的軟體」範例，驗證 `restic-backup` 真的能保護到這些資料——不只是「有跑
> `restic backup` 沒報錯」，而是**故意打斷 server、讓 client 登入失敗，再從
> 備份救回來、確認整條認證/授權鏈路恢復**。三台 vm-target：`freeipa-server`
> （AlmaLinux 9，192.168.122.2）、`freeipa-client`（Ubuntu 24.04，
> 192.168.122.6）、`s3-dest`（Ubuntu 24.04 上的 SeaweedFS S3 gateway，
> 192.168.122.7）。

### 6.1 基線：server + client 都健康，登入正常

依 `docs/verification/freeipa-server.md` §7.1、`docs/verification/freeipa-client.md`
§7 的 SOP 部署（server apply → `freeipa-client-fixtures.yml` 建 `pilotuser`/
`pilot-all` sudo 規則 → client enroll），兩份 spec 皆 PASS：

```
freeipa-server : verdict PASS (pass=16 fail=0 skip=0)
freeipa-client : verdict PASS (pass=10 fail=0 skip=0)
```

端到端登入基線（真實輸出）：

```
$ id pilotuser@ipa.pilot.internal
uid=552800003(pilotuser) gid=552800003(pilotuser) groups=552800003(pilotuser)

$ sudo runuser -u pilotuser -- sudo -l
User pilotuser may run the following commands on freeipa-client:
    (root) NOPASSWD: ALL
```

### 6.2 在 FreeIPA server 上套用 restic-backup（FreeIPA 專用範圍）

依 `group_vars/restic-backup.example.yml` 針對 FreeIPA server 的建議範例
（`restic_backup_paths: ["/etc", "/var/lib/ipa/backup"]`、
`restic_backup_pre_hook: "ipa-backup --data --logs"`），目的地指向本專案
`s3-dest` 上的 SeaweedFS：

```bash
go run ./cmd/pilot vm-target run --name freeipa-server \
    playbooks/apply/restic-backup-apply.yml \
    -e target_group=all \
    -e restic_s3_target_host=192.168.122.7 \
    -e restic_aws_access_key_id=sandbox-access-key \
    -e restic_aws_secret_access_key=sandbox-secret-key \
    -e restic_password=sandbox-repo-password-123 \
    -e '{"restic_backup_paths": ["/etc", "/var/lib/ipa/backup"]}' \
    -e restic_backup_pre_hook="ipa-backup --data --logs"
```

第一次套用依序踩到 §5 的 **Bug 3**（`dnf`/EPEL 支援缺失，已修 playbook）、
**Bug 5**（bucket 不存在的 retry storm，手動 `weed shell` 建 bucket 排除）、
**Bug 4**（`$HOME` 未設，已修腳本）——三個都是修 playbook/腳本本身、從頭重跑，
不是繞過或標記例外。修完後乾淨的 PLAY RECAP：

```
PLAY RECAP *********************************************************************
freeipa-server             : ok=14   changed=2    unreachable=0    failed=0    skipped=2    rescued=0    ignored=0
```

`pilot vm-target verify --name freeipa-server docs/verification/restic-backup.md`
→ **PASS pass=10 fail=0 skip=0**。快照內容確認涵蓋正確路徑：

```json
{"paths":["/etc","/var/lib/ipa/backup"],"hostname":"ipa1.ipa.pilot.internal",
 "summary":{"files_new":980,"data_added":32292780},"short_id":"977f31ae"}
```

（`ipa-backup --data --logs` 的輸出落在 `/var/lib/ipa/backup/ipa-full-<時間戳>`，
連同 `/etc` 一起被這份快照涵蓋——這正是 spec §1.5 設計「pre-hook 先把即時資料
轉成靜態檔案，再讓 restic 一起備份」的用意。）

冪等重跑 `changed=0`（Step 11 因「已有快照且 env/腳本沒變」被跳過）。

### 6.3 打斷 server：刪除 389-ds 設定檔

第一次嘗試只刪單一檔 `/etc/dirsrv/slapd-IPA-PILOT-INTERNAL/dse.ldif`
**不夠**——389-ds 自己在同一個目錄留了 `dse.ldif.bak`/`dse.ldif.startOK`，
`ipactl start` 時會自動從這兩份補檔案復原，服務照樣正常起來（389-ds 自帶的
自我修復機制）。改成刪掉**整個設定目錄**才是真正會讓 389-ds 起不來的破壞：

```bash
sudo ipactl stop
sudo rm -rf /etc/dirsrv/slapd-IPA-PILOT-INTERNAL
sudo ipactl start
```

真實輸出（服務啟動失敗）：

```
Starting Directory Service
Failed to start Directory Service: CalledProcessError(Command ['/bin/systemctl', 'start', 'dirsrv@IPA-PILOT-INTERNAL.service'] returned non-zero exit status 1)

$ sudo ipactl status
Directory Service: STOPPED
Directory Service must be running in order to obtain status of other services
```

LDAP（389）/ Kerberos（88）埠確認不再 listening。

### 6.4 確認 client 端登入真的失敗

清掉 client 的 SSSD 快取、重啟 SSSD，強制走「即時查 server」而非吃舊快取
（不清快取的話，短時間內 `id`/`sudo -l` 會因為快取命中而看起來「還是通的」，
掩蓋了 server 其實已經掛掉的事實——這是演練過程中第一次嘗試時真的踩到的
誤判，記錄在此避免下次重蹈覆轍）：

```bash
sudo rm -f /var/lib/sss/db/cache_ipa.pilot.internal.ldb \
           /var/lib/sss/db/timestamps_ipa.pilot.internal.ldb
sudo systemctl restart sssd
```

真實輸出（登入/授權都失敗）：

```
$ id pilotuser@ipa.pilot.internal
id: 'pilotuser@ipa.pilot.internal': no such user

$ sudo runuser -u pilotuser -- sudo -n -l
runuser: user pilotuser does not exist or the user entry does not contain all the required fields
```

**故障因果鏈完整成立**：server 設定檔遺失 → 389-ds 起不來 → LDAP/Kerberos 埠
關閉 → client 端 SSSD 查不到帳號 → 認證與 sudo 授權雙雙失效。

### 6.5 從 restic 備份還原、確認系統恢復正常

在 server 上用 restic 把 `/etc/dirsrv` 從最新快照救回來：

```bash
. /etc/pilot/restic-env && export HOME=/root
restic restore latest --target / --include /etc/dirsrv -v
```

真實輸出：

```
restoring snapshot 977f31ae of [/etc /var/lib/ipa/backup] at 2026-07-06 09:10:17... to /
Summary: Restored 44 / 43 files/dirs (992.147 KiB / 992.147 KiB) in 0:00, skipped 4 files/dirs 17.284 KiB
```

（還原回來的檔案 owner/權限跟原本一致——`dirsrv:dirsrv`，restic 以 root 執行
時預設保留原始 owner/mode，不需要額外修權限。）

重新啟動、確認服務健康：

```
$ sudo ipactl start
Starting Directory Service
Starting krb5kdc Service
Starting kadmin Service
Starting httpd Service
Starting ipa-custodia Service
Starting pki-tomcatd Service
Starting ipa-otpd Service
ipa: INFO: The ipactl command was successful

$ sudo ipactl status
Directory Service: RUNNING
krb5kdc Service: RUNNING
kadmin Service: RUNNING
httpd Service: RUNNING
ipa-custodia Service: RUNNING
pki-tomcatd Service: RUNNING
ipa-otpd Service: RUNNING
```

`pilot vm-target verify --name freeipa-server docs/verification/freeipa-server.md`
→ **PASS pass=16 fail=0 skip=0**（跟 §6.1 基線一致）。

清掉 client 快取、重啟 SSSD 後，登入/授權雙雙恢復：

```
$ id pilotuser@ipa.pilot.internal
uid=552800003(pilotuser) gid=552800003(pilotuser) groups=552800003(pilotuser)

$ sudo runuser -u pilotuser -- sudo -n -l
User pilotuser may run the following commands on freeipa-client:
    (root) NOPASSWD: ALL
```

`pilot vm-target verify --name freeipa-client docs/verification/freeipa-client.md`
→ **PASS pass=10 fail=0 skip=0**。`restic-backup` 本身的 spec 也重新
verify 一次確認未受影響 → **PASS pass=10 fail=0 skip=0**。

### 6.6 演練結論

- **restic-backup 對 FreeIPA server 的保護鏈路是真的**：從「刪設定檔 → 服務
  掛掉 → client 認證/授權失效」到「restic restore → 服務恢復 → client
  認證/授權恢復」，每一步都是真實指令、真實輸出，不是紙上談兵。
- 演練過程中發現並修好 3 個真事故（Bug 3–5，見 §5），全部是**先在其他
  Ubuntu vm-target 測 restic-backup 骨架時不會踩到、只有換成真實的
  FreeIPA server（EL9 + 有實際 ipa-backup 資料）才會踩到**的組合——印證了
  `spec-driven-feature-workflow` skill 強調的「用真實軟體當範例跑一輪，
  比單測骨架本身更容易挖出根因」。
- 演練也證實了 389-ds 自己的 `dse.ldif.bak`/`.startOK` 自我修復機制、以及
  SSSD 本機快取，都可能讓「看起來系統正常」掩蓋「其實 server 已經掛了」的
  事實——驗證故障/復原時要注意繞過這兩層快取，才是量測真實狀態。

---

## 7. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-06 | v1.0 | 初版：restic 備份到 S3（預設本專案自建 SeaweedFS S3 gateway），實測踩到「匿名 S3 gateway 對簽章 client 拒絕」的真事故，修法為掛 SeaweedFS identity 設定；驗證通過 10/10、冪等重跑 changed=0、逐主機自訂路徑正確累加快照、負向測試（無目的地）在任何 mutation 前乾淨失敗 | sre |
| 2026-07-06 | v1.1 | 新增 §6：用 FreeIPA server/client 做完整的備份/故障/還原演練，實測踩到並修好 3 個真事故（EL9 不支援、systemd oneshot 缺 `$HOME`、SeaweedFS bucket 不存在時的 retry storm，見 §5 Bug 3–5），演練最終 PASS：server/client/restic-backup 三份 spec 故障前後皆綠燈 | sre |
