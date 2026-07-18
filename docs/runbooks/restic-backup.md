# Runbook — restic-backup（跨主機通用 restic 備份到 S3）

> 撰寫日期：2026-07-06 (UTC)；v1.1 補 FreeIPA 災難復原演練（見 §6）
> 對齊：`docs/verification/restic-backup.md`（v1.1）、`playbooks/apply/restic-backup-apply.yml`
> 維護者：sre
>
> v1.2 (2026-07-17)：原本獨立的可重複步驟清單
> `docs/runbooks/restic-backup-dr-drill-test-plan.md` 已整併進本檔 §6（含
> VM 建立、S3 identity、bucket、teardown 與統一 gotcha 表），該檔已歸檔到
> `docs/runbooks/archived/`。§6 現在**同時是**帶真實輸出的紀錄**及**可直接
> 複製貼上重跑的步驟清單，不需要再對照兩份文件。

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
    playbooks/apply/docker-apply.yml \
    -e target_group=all
```

> 2026-07-17：docker preflight 改用獨立的 `playbooks/apply/docker-apply.yml`
> （原本是 `core-infra-provider-apply.yml -e infra_role=docker`），見
> `docs/runbooks/docker.md`。

實際輸出（`docker-apply.yml` 拆分後在 vm-target 上重測，見 `docs/runbooks/docker.md` §2）：

```
PLAY RECAP *********************************************************************
s3-dest                    : ok=5    changed=2    unreachable=0    failed=0    skipped=2    rescued=0    ignored=0
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

## 6. FreeIPA server + client 災難復原演練（實測；建置沿用 2026-07-06，
故障/復原重測於 2026-07-17）

> 目的：用本專案既有的 `freeipa-server`/`freeipa-client` 當「有實際資料/設定檔
> 的軟體」範例，驗證 `restic-backup` 真的能保護到這些資料——不只是「有跑
> `restic backup` 沒報錯」，而是**故意打斷 server、讓 client 登入失敗，再從
> 備份救回來、確認整條認證/授權鏈路恢復**。
>
> 本節原本分散在本檔與已歸檔的 `restic-backup-dr-drill-test-plan.md`
> 兩份文件；2026-07-17 整併時，§6.1–§6.2（VM 建立、S3 signed identity）
> 的指令沿用 2026-07-06 原始真實輸出（未重跑，因指令本身未變更）；
> §6.3 起（FreeIPA 部署、restic apply、故障注入、還原、三份 spec 重驗）
> 於 2026-07-17（Git SHA `b80ca43`）用本次整併驗證的環境**重新實跑**，
> 下方輸出為當次真實結果，取代舊有的 2026-07-06 DR 段輸出。

### 6.0 拓撲與角色

三台 vm-target，角色名稱可自訂（`--name` 只是 label，不影響 playbook 判斷）：

| 角色 | 本次重測使用的 target 名稱 | OS | IP（本次） |
|---|---|---|---|
| FreeIPA server（被破壞/被備份對象） | `freeipa-server` | AlmaLinux 9.8 | 192.168.122.3 |
| FreeIPA client（觀察登入/授權是否恢復） | `client-vm`（即 `freeipa-client` 角色） | Ubuntu 24.04 | 192.168.122.6 |
| S3 備份目的地（SeaweedFS S3 gateway） | `nexus`（即 `s3-dest` 角色） | Ubuntu 24.04 | 192.168.122.5 |

vault 至少需要 `ipa_admin_password`（`ipa_dm_password` 未設時自動沿用同一組密碼，
見 `freeipa-server-apply.yml` 的 `ipa_dm_password: "{{ ipa_admin_password }}"`
預設）；restic 側機密本節沿用 `-e` 直接帶入方便重現，正式環境建議改
`-e @<vault 檔>` 附加同名 key（`restic_password`/`restic_aws_access_key_id`/
`restic_aws_secret_access_key`，見 `vault.example.all.yaml`）。

### 6.1 起 3 台 VM（沿用 2026-07-06 原始真實輸出，指令未變更故未重跑）

```bash
go run ./cmd/pilot vm-target up --name freeipa-server --base-image almalinux-9 \
    --ssh-user ubuntu --vcpus 2 --memory 4096 --disk 30 \
    --ssh-timeout 8m --boot-timeout 8m

go run ./cmd/pilot vm-target up --name freeipa-client \
    --ssh-user ubuntu --vcpus 2 --memory 2048 --disk 20 \
    --ssh-timeout 8m --boot-timeout 8m

go run ./cmd/pilot vm-target up --name s3-dest \
    --ssh-user ubuntu --vcpus 2 --memory 1536 --disk 15 \
    --ssh-timeout 5m --boot-timeout 5m
```

**預期結果**：三台都印出 `✓ target <name> up`，各自拿到一個
`192.168.122.x` 靜態 IP。`virt-customize ... supermin exited` 警告是已知
無害訊息（見 `vm-target-spec-testing` skill），忽略即可。

> 本次（2026-07-17）整併驗證重用既有 vm-target pool 中已存在、角色相符的
> 三台 VM，改用 `go run ./cmd/pilot vm-target reset --name <target>`
> （revert 回 pristine post-boot state，跟全新 `up` 是同一份 base image
> 的乾淨起點，效果等價）取代重新 `up`，省下建置時間；`up` 指令本身仍是
> 未來從零建置時的正確做法，維持不變。

驗證就緒 + 互通：

```bash
go run ./cmd/pilot vm-target exec --name freeipa-server -- sudo -n id
go run ./cmd/pilot vm-target exec --name freeipa-client -- sudo -n id
go run ./cmd/pilot vm-target exec --name s3-dest -- sudo -n id
```

### 6.2 部署備份目的地（SeaweedFS S3，掛簽章 identity）

**必須先掛 identity 設定再啟動**——SeaweedFS 預設匿名模式會拒絕 `restic`
（簽章 client），見 §6.9 gotcha 表第 1 條、§5 Bug 1。

```bash
go run ./cmd/pilot vm-target run --name s3-dest \
    playbooks/apply/docker-apply.yml \
    -e target_group=all

go run ./cmd/pilot vm-target exec --name s3-dest -- sudo mkdir -p /etc/seaweedfs
go run ./cmd/pilot vm-target exec --name s3-dest -- sudo tee /etc/seaweedfs/s3.json <<'EOF'
{"identities":[{"name":"restic-backup","credentials":[{"accessKey":"sandbox-access-key","secretKey":"sandbox-secret-key"}],"actions":["Admin","Read","Write"]}]}
EOF

go run ./cmd/pilot vm-target run --name s3-dest \
    playbooks/apply/seaweedfs-s3-apply.yml \
    -e target_group=all -e seaweedfs_s3_config_path=/etc/seaweedfs/s3.json
```

**預期結果**：`PLAY RECAP ... failed=0`。

> **2026-07-17 重測發現：手動建 bucket 這步現在已經是防禦性動作，不再是
> 必要條件**——`seaweedfs-s3-apply.yml` 目前預設
> `seaweedfs_extra_buckets: ["pilot-restic-backup"]`，apply 本身就會
> 自動建好 restic 要用的 bucket（本次重測的真實 PLAY RECAP：
> `TASK [SeaweedFS — create extra S3 buckets (idempotent)] changed: [nexus] => (item=pilot-restic-backup)`）。
> §5 Bug 5 記載的手動 `weed shell` 建 bucket 步驟現在是**歷史包袱**，
> 保留下方指令純粹當作「萬一 `seaweedfs_extra_buckets` 被覆寫成不含這個
> bucket 名稱」時的手動備援：

```bash
go run ./cmd/pilot vm-target exec --name s3-dest -- \
    sudo docker exec pilot-seaweedfs sh -c "echo 's3.bucket.create -name pilot-restic-backup' | weed shell"
```

記下 `s3-dest` 的 IP（後面步驟要用）：

```bash
go run ./cmd/pilot vm-target list
```

### 6.3 部署 FreeIPA server + client，建立登入基線（2026-07-17 真實輸出）

```bash
go run ./cmd/pilot vm-target run --name freeipa-server \
    playbooks/apply/freeipa-server-apply.yml \
    -e target_group=all -e ipa_server_ip=192.168.122.3 \
    -e @~/.vault/main.yaml
```

真實 PLAY RECAP：

```
PLAY RECAP *********************************************************************
freeipa-server             : ok=30   changed=10   unreachable=0    failed=0    skipped=5    rescued=0    ignored=0
```

```bash
go run ./cmd/pilot vm-target verify --name freeipa-server docs/verification/freeipa-server.md --timeout 40
```

**第一次 verify 真實輸出**：`FAIL total=18 pass=17 fail=1`——`C16`（389-ds
稽核日誌檔已寫入）回 `rc=2`。這是 apply 最後一步「寫入 dummy 描述觸發稽核
寫入」跟 verify 之間的短暫 race（稽核檔剛觸發寫入、尚未真正落盤），不是稽核
功能沒開；**立即重跑 verify 兩次都乾淨 PASS**：

```
verdict: **PASS**  (pass=18 fail=0 skip=0)
```

（新 gotcha，見 §6.9 表最後一列。）

```bash
go run ./cmd/pilot vm-target run --name freeipa-server \
    playbooks/test/fixtures/freeipa-client-fixtures.yml \
    -e fixtures_target_group=all -e @~/.vault/main.yaml
```

真實 PLAY RECAP：`ok=7 changed=4 failed=0`（建立 `pilotuser` + sudo 規則
`pilot-all`）。

```bash
go run ./cmd/pilot vm-target run --name freeipa-client \
    playbooks/apply/freeipa-client-apply.yml \
    -e target_group=all -e ipa_server_ip=192.168.122.3 \
    -e ipa_verify_user=pilotuser -e @~/.vault/main.yaml

go run ./cmd/pilot vm-target verify --name freeipa-client docs/verification/freeipa-client.md --timeout 40
```

真實輸出：`ok=25 changed=13 failed=0`；verify **PASS pass=10 fail=0 skip=0**
（一次就過，未踩到 C8 sudo 快取冷啟動 gotcha）。

端到端登入基線（真實輸出）：

```
$ id pilotuser@ipa.pilot.internal
uid=275400003(pilotuser) gid=275400003(pilotuser) groups=275400003(pilotuser)

$ sudo runuser -u pilotuser -- sudo -n -l
User pilotuser may run the following commands on client-vm:
    (root) NOPASSWD: ALL
```

（uid 跟 2026-07-06 的 552800003 不同，是 IPA 幫每個 realm 生命週期分配的
uidNumber 範圍不同，非異常。）

### 6.4 在 FreeIPA server 上套用 restic-backup（FreeIPA 專用範圍）

```bash
go run ./cmd/pilot vm-target run --name freeipa-server \
    playbooks/apply/restic-backup-apply.yml \
    -e target_group=all \
    -e restic_s3_target_host=192.168.122.5 \
    -e restic_aws_access_key_id=sandbox-access-key \
    -e restic_aws_secret_access_key=sandbox-secret-key \
    -e restic_password=sandbox-repo-password-123 \
    -e '{"restic_backup_paths": ["/etc", "/var/lib/ipa/backup"]}' \
    -e restic_backup_pre_hook="ipa-backup --data --logs"
```

本次乾淨一次過（§5 Bug 3–5 對應的修法都已經在 playbook 裡，未再踩到）：

```
PLAY RECAP *********************************************************************
freeipa-server             : ok=18   changed=11   unreachable=0    failed=0    skipped=5    rescued=0    ignored=0
```

`pilot vm-target verify --name freeipa-server docs/verification/restic-backup.md`
→ **PASS pass=10 fail=0 skip=0**。快照內容確認涵蓋正確路徑：

```json
{"paths":["/etc","/var/lib/ipa/backup"],"hostname":"ipa1.ipa.pilot.internal",
 "summary":{"files_new":1006,"data_added":30335702},"short_id":"0927137b"}
```

冪等重跑（同樣變數）：`changed=0`（Step 11 因「已有快照且 env/腳本沒變」
被跳過）：

```
PLAY RECAP *********************************************************************
freeipa-server             : ok=16   changed=0    unreachable=0    failed=0    skipped=7    rescued=0    ignored=0
```

**建立可辨識測試資料，證明「最新快照真的包含它」**（2026-07-17 新增的重測
步驟，原 2026-07-06 演練沒做這步，直接沿用既有快照）：

```bash
go run ./cmd/pilot vm-target exec --name freeipa-server -- \
    sudo bash -c 'echo "dr-drill-marker-20260717-restic-consolidation" > /etc/dr-drill-marker.txt'
go run ./cmd/pilot vm-target exec --name freeipa-server -- sudo systemctl start restic-backup.service
go run ./cmd/pilot vm-target exec --name freeipa-server -- \
    sudo bash -c '. /etc/pilot/restic-env && export HOME=/root && restic ls latest /etc/dr-drill-marker.txt'
```

真實輸出（確認新快照 `e8123314` 真的收錄了這個檔案）：

```
snapshot e8123314 of [/etc /var/lib/ipa/backup] at 2026-07-17 06:34:03... by root@ipa1.ipa.pilot.internal filtered by [/etc/dr-drill-marker.txt]:
/etc/dr-drill-marker.txt
```

### 6.5 打斷 server：刪除 389-ds 設定檔

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

LDAP（389）/ Kerberos（88）埠確認不再 listening（`ss -tln` 對 `:389 `/`:88 `
均無命中）。

### 6.6 確認 client 端登入真的失敗

清掉 client 的 SSSD 快取、重啟 SSSD，強制走「即時查 server」而非吃舊快取
（不清快取的話，短時間內 `id`/`sudo -l` 會因為快取命中而看起來「還是通的」，
掩蓋了 server 其實已經掛掉的事實）：

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

### 6.7 從 restic 備份還原、確認系統恢復正常

在 server 上用 restic 把 `/etc/dirsrv` 從最新快照救回來：

```bash
. /etc/pilot/restic-env && export HOME=/root
restic restore latest --target / --include /etc/dirsrv -v
```

真實輸出：

```
restoring snapshot e8123314 of [/etc /var/lib/ipa/backup] at 2026-07-17 06:34:03... to /
Summary: Restored 44 / 43 files/dirs (992.978 KiB / 992.978 KiB) in 0:00, skipped 4 files/dirs 17.284 KiB
```

（還原回來的檔案 owner/權限跟原本一致——`dirsrv:dirsrv`，restic 以 root 執行
時預設保留原始 owner/mode，不需要額外修權限。）

重新啟動、確認服務健康：

```
$ sudo ipactl start
Starting Directory Service
Starting krb5kdc Service
Starting kadmin Service
Starting named Service
Starting httpd Service
Starting ipa-custodia Service
Starting pki-tomcatd Service
Starting ipa-otpd Service
Starting ipa-dnskeysyncd Service
ipa: INFO: The ipactl command was successful

$ sudo ipactl status
Directory Service: RUNNING
krb5kdc Service: RUNNING
kadmin Service: RUNNING
named Service: RUNNING
httpd Service: RUNNING
ipa-custodia Service: RUNNING
pki-tomcatd Service: RUNNING
ipa-otpd Service: RUNNING
ipa-dnskeysyncd Service: RUNNING
```

> 本次重測服務清單多了 `named`/`ipa-dnskeysyncd`（2026-07-06 演練只有 7 個
> 服務）——`freeipa-server-apply.yml` 的 `ipa_setup_dns` 實際預設是 `true`
> （`ipa_setup_dns: "{{ freeipa_setup_dns | default(true) }}"`）。這是本次
> 整併重測發現的真實文件/程式落差：`docs/verification/freeipa-server.md`
> §1 當時記載「預設 `false`」，已於同一次整併作業更正為 `true`（見該檔
> v1.3 變更紀錄）；不影響本次 DR 演練的通過條件（C17/C18 兩種狀態都設計
> 成能乾淨過）。

`pilot vm-target verify --name freeipa-server docs/verification/freeipa-server.md`
→ **PASS pass=18 fail=0 skip=0**（跟 §6.3 基線一致）。

清掉 client 快取、重啟 SSSD 後，登入/授權雙雙恢復：

```
$ id pilotuser@ipa.pilot.internal
uid=275400003(pilotuser) gid=275400003(pilotuser) groups=275400003(pilotuser)

$ sudo runuser -u pilotuser -- sudo -n -l
User pilotuser may run the following commands on client-vm:
    (root) NOPASSWD: ALL
```

`pilot vm-target verify --name freeipa-client docs/verification/freeipa-client.md`
→ **PASS pass=10 fail=0 skip=0**。`restic-backup` 本身的 spec 也重新
verify 一次確認未受影響 → **PASS pass=10 fail=0 skip=0**。

**這步過了，DR 演練就算成功。**

### 6.8 收尾：Teardown

```bash
go run ./cmd/pilot vm-target down --name freeipa-client
go run ./cmd/pilot vm-target down --name freeipa-server
go run ./cmd/pilot vm-target down --name s3-dest
go run ./cmd/pilot vm-target list   # 確認為空
```

> 本次整併重測選擇**保留**三台 VM（`vm-target snapshot --tag
> post-workstream-a`）供同一次整併作業後續 workstream 沿用，未執行上方
> `down`；下次要做乾淨的 DR 演練、且不需要保留環境給後續工作時，才需要跑
> 完整 teardown。

### 6.9 演練結論 + 統一 gotcha 表

- **restic-backup 對 FreeIPA server 的保護鏈路是真的**：從「刪設定檔 → 服務
  掛掉 → client 認證/授權失效」到「restic restore → 服務恢復 → client
  認證/授權恢復」，每一步都是真實指令、真實輸出，不是紙上談兵。
- 2026-07-06 首次演練發現並修好 3 個真事故（Bug 3–5，見 §5）；2026-07-17
  整併重測**未再踩到**這三個舊 bug（已在 playbook 修好），但發現了下方表格
  最後兩列的新事項。
- 389-ds 自己的 `dse.ldif.bak`/`.startOK` 自我修復機制、SSSD 本機快取，都
  可能讓「看起來系統正常」掩蓋「其實 server 已經掛了」的事實——驗證故障/
  復原時要注意繞過這兩層快取，才是量測真實狀態。

本表是 DR 演練專屬 gotcha（跟通用 restic-backup 的 §5 Bug 表不同層次，
兩份都要看）：

| 症狀 | 原因 | 解法 |
|---|---|---|
| 刪了 `dse.ldif`，`ipactl start` 卻還是正常起來 | 389-ds 自己在同目錄留了 `dse.ldif.bak`/`.startOK`，`ipactl start` 會自動從中復原 | 要模擬「真的救不回來」的故障，得刪整個 `/etc/dirsrv/slapd-<instance>` 目錄，不能只刪一個檔（見 §6.5） |
| server 明明已經掛了，client 的 `id`/`sudo -l` 卻還是成功 | SSSD 本機快取還沒過期，命中舊快取而非即時查 LDAP | 清 `/var/lib/sss/db/cache_*.ldb`/`timestamps_*.ldb` 並 `systemctl restart sssd` 再測（見 §6.6） |
| `freeipa-client-apply.yml` 的 C8 verify 第一次 fail：`sudo: a terminal is required to read the password` | 剛 enroll 完，SSSD 的 sudo 快取還沒刷新 | `sudo rm -f /var/lib/sss/db/*.ldb && sudo systemctl restart sssd` 後重跑 verify（2026-07-17 本次重測未踩到，一次就過，但仍是已知可能出現的偏差） |
| `pilot vm-target run --name <某台> ...` 顯示 `skipping: no hosts matched` | apply playbook 的 `hosts:` 預設是角色 group 名，vm-target 單機 inventory 只有同名的 **host**、沒有這個 **group** | 一律加 `-e target_group=all` |
| `pilot vm-target verify` 對 C16（389-ds 稽核日誌檔已寫入）第一次回 `rc=2`，緊接著重跑就 PASS | apply 最後一步「寫入 dummy 描述觸發稽核寫入」跟稽核檔實際落盤之間有短暫 race；verify 若緊接在 apply 完成後立刻執行可能撞到 | 重跑一次 verify（2026-07-17 本次重測實測：第一次 FAIL pass=17 fail=1，間隔數秒後連續兩次重跑皆 PASS pass=18 fail=0） |
| `ipactl start` 印出 `named`/`ipa-dnskeysyncd`（DNS 相關服務），比 2026-07-06 首次演練多兩個服務 | `playbooks/apply/freeipa-server-apply.yml` 的 `ipa_setup_dns`/`ipa_setup_ntp` 實際預設都是 `true`（由 FreeIPA 自己管理 DNS/NTP），2026-07-17 整併重測發現時 `docs/verification/freeipa-server.md` 文件記載跟程式碼不一致 | 已修：`docs/verification/freeipa-server.md` v1.3 更正文件描述以符合程式碼；要精確重現「DNS/NTP 由既有 role 管理、FreeIPA 不管」則顯式 `-e ipa_setup_dns=false -e ipa_setup_ntp=false` |

---

## 7. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-06 | v1.0 | 初版：restic 備份到 S3（預設本專案自建 SeaweedFS S3 gateway），實測踩到「匿名 S3 gateway 對簽章 client 拒絕」的真事故，修法為掛 SeaweedFS identity 設定；驗證通過 10/10、冪等重跑 changed=0、逐主機自訂路徑正確累加快照、負向測試（無目的地）在任何 mutation 前乾淨失敗 | sre |
| 2026-07-06 | v1.1 | 新增 §6：用 FreeIPA server/client 做完整的備份/故障/還原演練，實測踩到並修好 3 個真事故（EL9 不支援、systemd oneshot 缺 `$HOME`、SeaweedFS bucket 不存在時的 retry storm，見 §5 Bug 3–5），演練最終 PASS：server/client/restic-backup 三份 spec 故障前後皆綠燈 | sre |
| 2026-07-17 | v1.2 | 文件整併：`restic-backup-dr-drill-test-plan.md` 併入 §6（該檔已歸檔），§6 從「證據記錄」升級為「證據記錄+可重跑步驟清單」二合一。§6.3 起（FreeIPA 部署、restic apply、故障注入、還原、三份 spec 重驗）於本次整併時重新實跑，全部 PASS；發現並記錄 2 個新事項：(1) C16 verify 緊接 apply 之後有短暫 race，重跑即過；(2) `ipa_setup_dns`/`ipa_setup_ntp` 實際預設 `true`，跟 `freeipa-server.md` 文件記載的 `false` 不一致——已在同一次整併作業修好 `freeipa-server.md`（v1.3）。新增建立可辨識標記檔、確認其被最新快照收錄的步驟，加強 DR 證據力；新增 §6.9 統一 DR 專屬 gotcha 表 | sre |
