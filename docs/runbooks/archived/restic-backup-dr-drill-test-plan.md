# Runbook — restic-backup 災難復原(DR)測試計畫（以 FreeIPA server/client 為例）

> **Historical evidence — no longer maintained.**
> 整併日期：2026-07-17。本檔內容已併入唯一現行入口
> [`docs/runbooks/restic-backup.md`](../restic-backup.md) §6（含 VM 建立、
> S3 identity、bucket、FreeIPA 部署、故障注入、還原、teardown、統一 DR
> gotcha 表）。以下原始內容的實跑證據執行日期仍是 **2026-07-06**（未因
> 本次整併搬移而改期）。

> 撰寫日期：2026-07-06 (UTC)
> 對齊：`docs/verification/restic-backup.md`（v1.1）、`docs/verification/freeipa-server.md`、
> `docs/verification/freeipa-client.md`、`playbooks/apply/restic-backup-apply.yml`
> 對照文件：完整實測證據（含真實輸出）見 `docs/runbooks/restic-backup.md` §6——
> 本檔是**可重複執行的步驟清單**，抽掉逐字輸出，方便下次直接照抄重跑。
>
> 本檔每一步都已在真實 vm-target sandbox（`freeipa-server` AlmaLinux 9、
> `freeipa-client` Ubuntu 24.04、`s3-dest` Ubuntu 24.04）實跑過一輪
> （2026-07-06），全程只用 `go run ./cmd/pilot vm-target` 系列指令。

---

## 0. 目標

證明 `restic-backup` 真的能保護「本專案有實際資料/設定檔的軟體」——不只是
「有跑 `restic backup` 沒報錯」，而是完整走一次：

1. FreeIPA server 提供 client 登入/sudo 授權（正常基線）
2. 故意打斷 server（刪設定檔），確認 client 登入**真的失敗**
3. 用 restic 從備份還原，確認 server/client **恢復正常**

三台 vm-target 缺一不可：`freeipa-server`（EL9，被備份/被破壞的對象）、
`freeipa-client`（Ubuntu，用來證明「登入失敗/恢復」的觀察端）、`s3-dest`
（SeaweedFS S3 gateway，備份目的地）。

---

## 1. 前置確認

```bash
go run ./cmd/pilot vm-target list
```

**預期結果**：乾淨環境應該是空的（`no targets`）。若上次測試留了同名 VM，先
`vm-target down` 清掉再重來，避免 IP/狀態殘留。

確認 vault 密碼檔存在（從 `vault.example.all.yaml` 建立的一份）：

```bash
ls -la ~/.vault/main.yaml
```

沒有就建立（假密碼、repo 外）：

```bash
mkdir -p ~/.vault && chmod 700 ~/.vault
cp vault.example.all.yaml ~/.vault/main.yaml
# 編輯 ~/.vault/main.yaml，把 ipa_admin_password 改成你自己的密碼（>= 8 字元）
chmod 600 ~/.vault/main.yaml
```

> 不同名稱的 `vm-target up` 現在可平行執行：state 已改用跨程序鎖定的
> `Store.Mutate`，修正舊版 state-file race。以下維持依序命令，因為它們是本次
> DR 演練的原始實測證據；資源足夠時可平行建立三台 VM，但後續 FreeIPA、S3 與
> DR 步驟仍須依本計畫的相依順序執行。

---

## 2. 起 3 台 VM

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

驗證就緒 + 互通：

```bash
go run ./cmd/pilot vm-target exec --name freeipa-server -- sudo -n id
go run ./cmd/pilot vm-target exec --name freeipa-client -- sudo -n id
go run ./cmd/pilot vm-target exec --name s3-dest -- sudo -n id
```

---

## 3. 部署備份目的地（SeaweedFS S3，掛簽章 identity）

**必須先掛 identity 設定再啟動**——SeaweedFS 預設匿名模式會拒絕 `restic`
（簽章 client），見 §7 gotcha 表第 1 條。

```bash
go run ./cmd/pilot vm-target run --name s3-dest \
    playbooks/apply/core-infra-provider-apply.yml \
    -e target_group=all -e infra_role=docker

go run ./cmd/pilot vm-target exec --name s3-dest -- sudo mkdir -p /etc/seaweedfs
go run ./cmd/pilot vm-target exec --name s3-dest -- sudo tee /etc/seaweedfs/s3.json <<'EOF'
{"identities":[{"name":"restic-backup","credentials":[{"accessKey":"sandbox-access-key","secretKey":"sandbox-secret-key"}],"actions":["Admin","Read","Write"]}]}
EOF

go run ./cmd/pilot vm-target run --name s3-dest \
    playbooks/apply/seaweedfs-s3-apply.yml \
    -e target_group=all -e seaweedfs_s3_config_path=/etc/seaweedfs/s3.json
```

**預期結果**：`PLAY RECAP ... failed=0`。

**接著手動預先建好 restic 要用的 bucket**（SeaweedFS 不會在 `PutObject`/
`CreateBucket` 時自動生出不存在的 bucket；沒先建的話 `restic` 首次
init/backup 會因為「bucket does not exist」觸發長時間 retry backoff，看起來
像卡死，見 §7 gotcha 表第 4 條）：

```bash
go run ./cmd/pilot vm-target exec --name s3-dest -- \
    sudo docker exec pilot-seaweedfs sh -c "echo 's3.bucket.create -name pilot-restic-backup' | weed shell"
```

**預期結果**：`created bucket pilot-restic-backup`。

記下 `s3-dest` 的 IP（後面步驟要用）：

```bash
go run ./cmd/pilot vm-target list
```

---

## 4. 部署 FreeIPA server + client，建立登入基線

```bash
# server（首裝約 8-12 分鐘）
go run ./cmd/pilot vm-target run --name freeipa-server \
    playbooks/apply/freeipa-server-apply.yml \
    -e target_group=all -e ipa_server_ip=<freeipa-server IP> \
    -e @~/.vault/main.yaml

go run ./cmd/pilot vm-target verify --name freeipa-server \
    docs/verification/freeipa-server.md --timeout 40
```

**預期結果**：`PLAY RECAP ... failed=0`；verify **PASS pass=16 fail=0**。

```bash
# server 端建立測試帳號 pilotuser + sudo 規則 pilot-all（跨 host 前置 fixture）
go run ./cmd/pilot vm-target run --name freeipa-server \
    playbooks/test/fixtures/freeipa-client-fixtures.yml \
    -e fixtures_target_group=all -e @~/.vault/main.yaml
```

```bash
# client enroll（首次含 apt 下載，約 3-6 分鐘）
go run ./cmd/pilot vm-target run --name freeipa-client \
    playbooks/apply/freeipa-client-apply.yml \
    -e target_group=all -e ipa_server_ip=<freeipa-server IP> \
    -e ipa_verify_user=pilotuser -e @~/.vault/main.yaml

go run ./cmd/pilot vm-target exec --name freeipa-client -- true   # 暖 SSH 連線
go run ./cmd/pilot vm-target verify --name freeipa-client \
    docs/verification/freeipa-client.md --timeout 40
```

**預期結果**：verify **PASS pass=10 fail=0**。若 C8（sudo NOPASSWD）第一次
fail、`sudo: a terminal is required` 之類訊息，是 SSSD sudo 快取冷啟動，見
§7 gotcha 表第 5 條，清快取重跑即可。

確認登入基線（**這是後面用來對照「壞了」跟「救回來了」的黃金輸出**）：

```bash
go run ./cmd/pilot vm-target exec --name freeipa-client -- id pilotuser@ipa.pilot.internal
go run ./cmd/pilot vm-target exec --name freeipa-client -- sudo runuser -u pilotuser -- sudo -n -l
```

**預期結果**：
```
uid=552800003(pilotuser) gid=552800003(pilotuser) groups=552800003(pilotuser)
...
User pilotuser may run the following commands on freeipa-client:
    (root) NOPASSWD: ALL
```

---

## 5. 部署 restic-backup（FreeIPA 專用範圍）

```bash
go run ./cmd/pilot vm-target run --name freeipa-server \
    playbooks/apply/restic-backup-apply.yml \
    -e target_group=all \
    -e restic_s3_target_host=<s3-dest IP> \
    -e restic_aws_access_key_id=sandbox-access-key \
    -e restic_aws_secret_access_key=sandbox-secret-key \
    -e restic_password=sandbox-repo-password-123 \
    -e '{"restic_backup_paths": ["/etc", "/var/lib/ipa/backup"]}' \
    -e restic_backup_pre_hook="ipa-backup --data --logs"

go run ./cmd/pilot vm-target verify --name freeipa-server \
    docs/verification/restic-backup.md --timeout 40
```

**預期結果**：`PLAY RECAP ... failed=0`；verify **PASS pass=10 fail=0**。
確認快照涵蓋正確路徑：

```bash
go run ./cmd/pilot vm-target exec --name freeipa-server -- \
    sudo bash -c '. /etc/pilot/restic-env && export HOME=/root && restic snapshots --json'
```

**預期結果**：至少一筆快照，`"paths":["/etc","/var/lib/ipa/backup"]`。

冪等檢查（同樣變數再跑一次）：

```bash
go run ./cmd/pilot vm-target run --name freeipa-server \
    playbooks/apply/restic-backup-apply.yml \
    -e target_group=all -e restic_s3_target_host=<s3-dest IP> \
    -e restic_aws_access_key_id=sandbox-access-key \
    -e restic_aws_secret_access_key=sandbox-secret-key \
    -e restic_password=sandbox-repo-password-123 \
    -e '{"restic_backup_paths": ["/etc", "/var/lib/ipa/backup"]}' \
    -e restic_backup_pre_hook="ipa-backup --data --logs"
```

**預期結果**：`changed=0`（Step 11 因「已有快照且 env/腳本沒變」跳過）。

---

## 6. 打斷 server：刪除 389-ds 設定檔

```bash
go run ./cmd/pilot vm-target exec --name freeipa-server -- sudo ipactl stop
go run ./cmd/pilot vm-target exec --name freeipa-server -- \
    sudo rm -rf /etc/dirsrv/slapd-IPA-PILOT-INTERNAL
go run ./cmd/pilot vm-target exec --name freeipa-server -- sudo ipactl start
```

> ⚠️ **一定要刪整個 `slapd-<instance>` 目錄，不要只刪 `dse.ldif` 一個檔**。
> 389-ds 在同目錄留了 `dse.ldif.bak`/`dse.ldif.startOK`，只刪單一檔會被
> `ipactl start` 自動從備份復原、服務照樣正常起來——見 §7 gotcha 表第 2 條。

**預期結果**：`ipactl start` 印出
`Failed to start Directory Service: CalledProcessError(...)`；
`sudo ipactl status` 顯示 `Directory Service: STOPPED`。

```bash
go run ./cmd/pilot vm-target exec --name freeipa-server -- sudo ipactl status
```

---

## 7. 確認 client 端登入真的失敗

**必須清 SSSD 快取再重試**，否則短時間內會吃到舊快取、誤判「還是通的」，
見 §7 gotcha 表第 3 條：

```bash
go run ./cmd/pilot vm-target exec --name freeipa-client -- \
    sudo rm -f /var/lib/sss/db/cache_ipa.pilot.internal.ldb /var/lib/sss/db/timestamps_ipa.pilot.internal.ldb
go run ./cmd/pilot vm-target exec --name freeipa-client -- sudo systemctl restart sssd
```

```bash
go run ./cmd/pilot vm-target exec --name freeipa-client -- id pilotuser@ipa.pilot.internal
go run ./cmd/pilot vm-target exec --name freeipa-client -- sudo runuser -u pilotuser -- sudo -n -l
```

**預期結果**：
```
id: 'pilotuser@ipa.pilot.internal': no such user
...
runuser: user pilotuser does not exist or the user entry does not contain all the required fields
```

---

## 8. 從 restic 備份還原、確認恢復正常

```bash
go run ./cmd/pilot vm-target exec --name freeipa-server -- \
    sudo bash -c '. /etc/pilot/restic-env && export HOME=/root && restic restore latest --target / --include /etc/dirsrv -v'
```

**預期結果**：`Summary: Restored 44 / 43 files/dirs ...`（數字可能因版本微調而略有出入，重點是 `Restored` 非 0）。

```bash
go run ./cmd/pilot vm-target exec --name freeipa-server -- sudo ipactl start
go run ./cmd/pilot vm-target exec --name freeipa-server -- sudo ipactl status
go run ./cmd/pilot vm-target verify --name freeipa-server docs/verification/freeipa-server.md --timeout 40
```

**預期結果**：7 個服務全部 `RUNNING`；verify 回到 **PASS pass=16 fail=0**
（跟 §4 基線一致）。

清 client 快取，確認登入/授權恢復：

```bash
go run ./cmd/pilot vm-target exec --name freeipa-client -- \
    sudo rm -f /var/lib/sss/db/cache_ipa.pilot.internal.ldb /var/lib/sss/db/timestamps_ipa.pilot.internal.ldb
go run ./cmd/pilot vm-target exec --name freeipa-client -- sudo systemctl restart sssd
go run ./cmd/pilot vm-target exec --name freeipa-client -- id pilotuser@ipa.pilot.internal
go run ./cmd/pilot vm-target exec --name freeipa-client -- sudo runuser -u pilotuser -- sudo -n -l
go run ./cmd/pilot vm-target verify --name freeipa-client docs/verification/freeipa-client.md --timeout 40
go run ./cmd/pilot vm-target verify --name freeipa-server docs/verification/restic-backup.md --timeout 40
```

**預期結果**：`id`/`sudo -l` 都跟 §4 基線一樣成功；`freeipa-client` verify
**PASS pass=10 fail=0**；`restic-backup` verify 仍 **PASS pass=10 fail=0**
（本身沒被這場演練影響）。

**這步過了，DR 演練就算成功。**

---

## 9. 收尾：Teardown

```bash
go run ./cmd/pilot vm-target down --name freeipa-client
go run ./cmd/pilot vm-target down --name freeipa-server
go run ./cmd/pilot vm-target down --name s3-dest
go run ./cmd/pilot vm-target list   # 確認為空
```

---

## 10. 已知 gotcha 一覽（跑之前先知道，少走冤枉路）

| 症狀 | 原因 | 解法 |
|---|---|---|
| `restic init`/`backup` 失敗：`Fatal: ... Signed request requires setting up SeaweedFS S3 authentication` | SeaweedFS 匿名模式只接受完全不簽章的請求，`restic` 一律送簽章請求 | 見 §3，`seaweedfs-s3-apply.yml` 一定要帶 `-e seaweedfs_s3_config_path=<s3.json>`，identity 的 access/secret key 要跟 restic-backup 那邊一致 |
| 刪了 `dse.ldif`，`ipactl start` 卻還是正常起來 | 389-ds 自己在同目錄留了 `dse.ldif.bak`/`.startOK`，`ipactl start` 會自動從中復原 | 要模擬「真的救不回來」的故障，得刪整個 `/etc/dirsrv/slapd-<instance>` 目錄，不能只刪一個檔（見 §6） |
| server 明明已經掛了，client 的 `id`/`sudo -l` 卻還是成功 | SSSD 本機快取還沒過期，命中舊快取而非即時查 LDAP | 清 `/var/lib/sss/db/cache_*.ldb`/`timestamps_*.ldb` 並 `systemctl restart sssd` 再測（見 §7） |
| 首次 `restic snapshots`/`restic init` 卡住十幾分鐘、看起來像 hang | SeaweedFS 不會自動生出不存在的 bucket，`restic` 對「bucket 不存在」用遞增 backoff 重試，實際上不是真的卡死只是等很久 | 首次套用 `restic-backup-apply.yml` 前先手動 `weed shell` 建好 `restic_s3_bucket`（見 §3）。playbook 本身也已加 `timeout 60` 防禦，最慢 60 秒內會乾淨失敗 |
| `restic-backup-apply.yml` 在 FreeIPA server（EL9）上，Step 1 直接 fail 或 C1 verify fail | 舊版 playbook 只支援 Debian `apt`；EL 系沒有 `dpkg` 指令，spec C1 舊版用 `dpkg -s` 會誤判成「沒裝」 | 已修：playbook 依 `ansible_os_family` 分流（Debian→apt；RedHat→dnf+EPEL），spec C1 改用 `command -v restic`（v1.1 起不會再遇到，若遇到代表用了舊版檔案） |
| `restic-backup.service`（systemd oneshot）失敗：`unable to open cache: unable to locate cache directory: neither $XDG_CACHE_HOME nor $HOME are defined` | systemd 啟動的 service 不帶 `$HOME`，`restic` 需要它定位本機 metadata cache | 已修：備份腳本與 Step 10 precheck 開頭都補 `export HOME=/root`（v1.1 起不會再遇到） |
| `freeipa-client-apply.yml` 的 C8 verify 第一次 fail：`sudo: a terminal is required to read the password` | 剛 enroll 完，SSSD 的 sudo 快取還沒刷新 | `sudo rm -f /var/lib/sss/db/*.ldb && sudo systemctl restart sssd` 後重跑 verify |
| `pilot vm-target run --name <某台> ...` 顯示 `skipping: no hosts matched` | apply playbook 的 `hosts:` 預設是角色 group 名，vm-target 單機 inventory 只有同名的 **host**、沒有這個 **group** | 一律加 `-e target_group=all` |

更完整的逐字真實輸出（PLAY RECAP、journalctl、restic 快照 JSON 等）見
`docs/runbooks/restic-backup.md` §6。
