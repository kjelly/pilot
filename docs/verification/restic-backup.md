# Verification Spec — restic-backup（跨主機通用 restic 備份到 S3，涵蓋本專案各軟體的資料/設定檔）

> 版本：v1.2（v1.0 的通用骨架已於 vm-target 沙盒實測；v1.1 用真實的 FreeIPA
> server/client 做完整備份/故障/還原演練，修好 3 個真事故，見 §8 與
> `docs/runbooks/restic-backup.md` §5–§6；v1.2 讓多主機共用 repository 的並行驗證
> 以有界 lock 等待安全完成）
> 對齊規範：pilot 通用 config-only 服務規範；備份目的地預設指向本專案自建的
> `docs/verification/seaweedfs-s3.md`（SeaweedFS S3 gateway），亦可透過變數
> 切換到外部/獨立 S3（AWS S3、另一台 MinIO 等）。
> 維護者：sre

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Hostname / Inventory group | `restic-backup`（跨主機通用；掛在任何需要備份的既有主機上，例：`ipa-1`、`web-1`——比照 `wazuh-fim`/`audit-log-forwarding` 的「疊加型」group，不是獨立角色）|
| OS / version | Ubuntu 22.04 / 24.04 LTS |
| 角色 | 用 [restic](https://restic.net/) 把這台主機上「本專案有用到的軟體」的資料與設定檔加密備份到 S3（預設本專案自建的 SeaweedFS S3 gateway，可切換外部 S3），排程執行 + 保留策略（retention/prune） |
| 套用範圍 | `restic` 套件、`/etc/pilot/restic-env`（機密/設定，0600）、`/usr/local/bin/pilot-restic-backup.sh`、`restic-backup.service`/`.timer`、`/etc/hosts`（`s3-backup-server` 別名，選填） |
| 風險等級 | High（備份是最後一道資料遺失防線；備份目的地/密碼設定錯誤會導致「以為有備份、實際上救不回來」） |

> 為何用 restic 而非 `tar`+cron 或 `rsync`：restic 原生支援 S3 後端
> （`-r s3:http://host:port/bucket`）、加密（`RESTIC_PASSWORD`）、去重/增量儲存、
> 內建 `restic check` 完整性驗證與 `restic forget --prune` 保留策略，一套
> binary 涵蓋這份 spec需要的全部能力，不必手刻加密/去重/保留邏輯。
>
> 為何備份範圍設計成「通用角色 + 每台主機自訂路徑」而非「每個軟體各寫一份
> 備份 playbook」：本專案已有的資料型軟體（FreeIPA server 的 389-ds 目錄、
> Keycloak 的 PostgreSQL、log-server 的 rsyslog 落地檔、Wazuh manager 的
> 設定與索引）分布在不同角色的 group_vars 裡，各自的資料位置/備份手法（例如
> PostgreSQL 需要 `pg_dump` 而不是直接複製執行中的 data 目錄）差異很大。比照
> `wazuh-fim.md` 的 `wazuh_fim_directories` 設計：本 spec 提供一個通用、可在
> 任何主機套用的 restic 執行骨架（`restic_backup_paths` 可逐主機覆寫），另外
> 用選填的 `restic_backup_pre_hook`（逐主機覆寫的一行 shell 指令）讓需要「先
> dump 再備份」的軟體（如 Keycloak 的 PostgreSQL、FreeIPA 的 `ipa-backup`）
> 在 restic 執行前先把資料轉成靜態檔案，兩種需求共用同一套 apply/verify
> 骨架，不必每個軟體重複一份 restic 安裝/排程/驗證邏輯。見 §1.5 與
> `group_vars/restic-backup.example.yml` 的逐軟體 host_vars 範例。

## 1.5 依賴變數契約

在套用或驗證此主機時，Playbook 與變數參數必須嚴格遵守以下命名，禁止擅自縮寫或發明新變數：

| 變數名稱 | 說明/用途 | 是否必填 | 預設值 |
|---------|----------|---------|--------|
| `restic_s3_target_host` | S3 端點的 IP 或 FQDN；套用時會被 pin 進 `/etc/hosts` 的 `s3-backup-server` 別名，供預設的 `restic_repository` 使用。**兩種情境擇一必填**：填這個變數（走預設 repository，指向本專案自建的 SeaweedFS S3 gateway），或直接覆寫 `restic_repository` 指向已有真實 DNS 的外部 S3（見下）| 二擇一必填 | 空字串 |
| `restic_repository` | restic repository 完整位置字串（`restic -r` 的值）| 否 | `s3:http://s3-backup-server:{{ restic_s3_port }}/{{ restic_s3_bucket }}`（走 `s3-backup-server` 別名，指向 `restic_s3_target_host`）|
| `restic_s3_port` | 預設 repository 使用的 S3 埠 | 否 | `8333`（SeaweedFS S3 gateway 預設埠，見 `seaweedfs-s3.md`）|
| `restic_s3_bucket` | 預設 repository 使用的 bucket 名稱 | 否 | `pilot-restic-backup` |
| `restic_aws_access_key_id` | S3 後端認證用的 access key（來自 vault，不可硬編碼；SeaweedFS 預設匿名模式下任何非空字串皆可，仍要求明確帶入，見 `seaweedfs-s3.md` §5 已知偏差）| 是 | 無（`mandatory`）|
| `restic_aws_secret_access_key` | S3 後端認證用的 secret key（來自 vault，不可硬編碼，`no_log`）| 是 | 無（`mandatory`）|
| `restic_password` | restic repository 加密密碼（來自 vault，不可硬編碼，`no_log`；遺失此密碼等同遺失所有備份，不經過任何托管機制）| 是 | 無（`mandatory`）|
| `restic_backup_paths` | 這台主機要備份的路徑清單（list）——逐主機可覆寫，比照 `wazuh_fim_directories` 的 pattern | 否 | `["/etc"]` |
| `restic_backup_pre_hook` | 備份前執行的一行 shell 指令（例：先 `pg_dump` 到檔案、或跑 `ipa-backup`），執行完才跑 `restic backup`；逐主機可覆寫 | 否 | 空字串（不執行）|
| `restic_backup_schedule` | `systemd` timer 的 `OnCalendar=` 排程字串 | 否 | `*-*-* 02:00:00`（每日 02:00）|
| `restic_retention_daily` / `restic_retention_weekly` / `restic_retention_monthly` | `restic forget --prune` 的保留份數 | 否 | `7` / `4` / `6` |

> `restic_s3_target_host` 沿用 `siem_forward_host`/`wazuh_manager_host` 同一種
> 「別名 + 選填 IP」設計，但**語意不同、不能比照跳過**：`siem_forward_host`
> 沒填只是少了「轉送」這個加值層，本機仍有完整功能；`restic_s3_target_host`
> 沒填、且 `restic_repository` 也沒被覆寫成外部 S3 的話，備份**完全沒有目的
> 地**——這不是「先本機、之後補」的過渡態，是整個功能失效。因此 apply
> playbook 在 `pre_tasks` 明確擋下這個組合（見 §6），不會靜默裝好排程卻永遠
> 備份失敗。
>
> `restic_backup_paths` 與 `restic_backup_pre_hook` 都是**逐主機**變數，放進
> 該主機的 `host_vars/<主機短名>.yml`（不要放進共用的 `group_vars/
> restic-backup.yml`，否則同 group 所有主機會被覆寫成同一份清單）——見
> `group_vars/restic-backup.example.yml` 針對 FreeIPA server / Keycloak DB /
> log-server / Wazuh manager 的建議路徑與 pre_hook 範例。

## 2. Checklist

| ID  | Category | Check                                                        | Expected | Command |
|-----|----------|---------------------------------------------------------------|----------|---------|
| C1  | package  | `restic` 已安裝                                               | 0        | command -v restic >/dev/null 2>&1; echo $? |
| C2  | file     | 機密/設定檔 `/etc/pilot/restic-env` 存在                       | 0        | test -f /etc/pilot/restic-env; echo $? |
| C3  | file     | `/etc/pilot/restic-env` 權限為 `0600`（內含 S3 credentials 與 repository 密碼）| 600 | stat -c '%a' /etc/pilot/restic-env |
| C4  | config   | repository 可連線且已初始化（`restic snapshots` 執行成功）      | 0        | sh -c '. /etc/pilot/restic-env && restic snapshots >/dev/null 2>&1; echo $?' |
| C5  | data     | 至少已有一筆快照（首次 apply 已觸發一次備份）                    | 0        | sh -c '. /etc/pilot/restic-env && restic snapshots --json 2>/dev/null | grep -q "short_id" && echo 0 || echo 1' |
| C6  | data     | `restic check` 完整性驗證通過                                  | 0        | sh -c '. /etc/pilot/restic-env && restic check --retry-lock 120s >/dev/null 2>&1; echo $?' |
| C7  | config   | 備份腳本含保留策略旗標（`--keep-daily`）                        | 0        | grep -q -- '--keep-daily' /usr/local/bin/pilot-restic-backup.sh; echo $? |
| C8  | service  | `restic-backup.timer` 為 enabled                              | 0        | systemctl is-enabled restic-backup.timer >/dev/null 2>&1; echo $? |
| C9  | service  | `restic-backup.timer` 為 active                               | 0        | systemctl is-active restic-backup.timer >/dev/null 2>&1; echo $? |
| C10 | register | `/etc/hosts` 已 pin `s3-backup-server` 別名（僅當使用預設 repository、`restic_s3_target_host` 有填時適用，見 §5）| 0 | getent hosts s3-backup-server >/dev/null 2>&1; echo $? |

> C1–C10 全部用**正邏輯 rc**；C5/C7 用 `sh -c '... && echo 0 || echo 1'` 或
> `grep ...; echo $?` 讓外層指令恆回 0（見 `verification-spec-template.md`
> 陷阱 1）。C5 含字面 `|`（`grep -q "short_id" && echo 0 || echo 1` 前面還有
> 一個 `restic snapshots --json 2>/dev/null | grep`），依模板約定用多欄位讓
> parser 把 pipeline 接回同一個 Command，不用 `\|` 跳脫。
> C3 是**數字 expected**（`600`），不是字串 `~0600`——比照模板「涉及檔案權限
> 的 row 寫出數字」的規則；`stat -c '%a'` 本身輸出就是不帶前導 0 的十進位
> 字串（`600`，不是 `0600`）。
> C9 用 `systemctl is-active` 的**數字 rc**而非 `~active`（`active` 是
> `inactive` 的子字串，見模板陷阱 3）。對 `.timer` unit，`is-active` 在
> timer 被 `systemctl start` 後立刻回 `active (waiting)`，不需要等到下一次
> `OnCalendar` 觸發。
> C4–C6 依賴 apply 已經執行過至少一次 `restic-backup.service`（見 §6）—— 若
> 只裝好 timer、還沒真的跑過一次備份，C5/C6 會因為 repository 剛
> `restic init` 完、裡面真的沒有任何快照而合理 fail，這不是誤判。
> C1 用 `command -v restic`（查 `$PATH` 是否有這個執行檔）而不是
> `dpkg -s restic`——後者在 EL 系（AlmaLinux/RHEL/Rocky）上因為沒有 `dpkg`
> 指令會直接以 rc=127 misreport 成「沒裝」，即使套件（EPEL 的 `restic.rpm`）
> 其實已經裝好。apply playbook 同時支援 Debian（`apt`）與 EL（`dnf`+EPEL，
> 見 §6），checklist 用套件管理器中立的檢查法避免綁死單一發行版。
> C6 保留 restic repository lock 的安全性，但允許多台
> `restic-backup` host 的 per-host verifier 並行時有界等待 120 秒。因此對整個
> group 驗證時必須配 `--timeout 180`，避免 pilot 預設 15 秒先中止等待。

## 3. 證據收集

- 工具：`pilot verify docs/verification/restic-backup.md -i <inventory> -l restic-backup --timeout 180`
- 輸出格式：`.verification/restic-backup-<UTC>.{ndjson,md}`
- 預期 row 數：10（C1–C10）

## 4. PASS / FAIL 規則

- 全部 C1–C10 `status=pass` → **PASS**：備份鏈路完整（repository 已初始化、至少一份快照、完整性驗證通過、排程已啟用）
- 任一 `status=fail` → **FAIL**，常見修法：
  - C1 fail → 套件沒裝好，檢查 apt 來源/網路
  - C2/C3 fail → env 檔沒 render 或權限被改動；重跑 apply
  - C4 fail → S3 端點不可達（`restic_s3_target_host`/`restic_repository` 設錯，或目的地 S3 服務本身沒起來）、或 credentials 錯誤
  - C5 fail → C4 通過但備份從沒真的跑成功；看 `journalctl -u restic-backup.service`
  - C6 fail → repository 資料損毀（罕見；需要人工介入，`restic check --read-data` 進一步定位）
  - C7 fail → 備份腳本被手動改過，保留策略遺失
  - C8/C9 fail → timer 沒裝好或被停用；`systemctl status restic-backup.timer`
  - C10 fail → 見 §5，需先確認 `restic_s3_target_host` 是否有填

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C10 | 若套用時**沒有**填 `restic_s3_target_host`（即改用完全外部覆寫的 `restic_repository`，目的地本身有真實 DNS，不需要靠 `/etc/hosts` 別名），這條會合理 fail——此時應只看 C1–C9 是否全 pass，C10 視為不適用 | 使用外部 S3（真實 DNS）的部署 | 無（設計如此，非暫時偏差） |
| — | `restic_backup_paths` 預設只有 `/etc`；這是通用、對任何主機都安全的最小備份範圍（設定檔），**不是**針對本專案各軟體資料的完整備份。要備份 FreeIPA/Keycloak/log-server/Wazuh 的實際資料，必須在該主機的 `host_vars` 補上對應路徑與（需要的話）`restic_backup_pre_hook`，見 §1.5 與 `group_vars/restic-backup.example.yml` 的範例——這些範例路徑/指令**未在本 repo 的 vm-target 沙盒實測**（沙盒測的是通用骨架本身，見 `docs/runbooks/restic-backup.md` §2），套用到正式主機前建議先在 staging 跑過一次確認 | 所有環境 | 無（設計如此的範圍界定） |
| — | `restic check`（C6）只做 metadata/tree 完整性檢查，不加 `--read-data`（會把整個 repository 內容重新讀一次驗 checksum，資料量大時非常耗時），日常排程/verify 不適合每次都做 | 所有環境 | 建議另外排一個較低頻率（如每月）的 `--read-data` 全量檢查，不在本 spec 範圍 |

## 6. Playbook 對應

對應 apply playbook：`playbooks/apply/restic-backup-apply.yml`

| Spec ID | Apply task | 備註 |
|---------|------------|------|
| — | `pre_tasks: assert` 擋下「`restic_s3_target_host` 空字串且 `restic_repository` 仍是預設值」的組合 | 見 §1.5 說明；避免裝好排程卻永遠備份失敗 |
| — | `pre_tasks: assert` 擋下非 Debian/RedHat 的 OS family | C1 的安裝手法依 OS family 分流（見下） |
| C1 | `ansible_os_family == 'Debian'` → `apt install restic`；`== 'RedHat'` → 先 `dnf install epel-release` 再 `dnf install restic`（EL9 的 BaseOS/AppStream 沒有 restic，需 EPEL）| Ubuntu/Debian universe 套件庫已有，不需額外加 repo；EL 系（AlmaLinux/RHEL/Rocky）實測需要先裝 EPEL，見 `docs/runbooks/restic-backup.md` §5 對 FreeIPA server（EL9）實測踩到的坑 |
| C2, C3 | `template`/`copy` 產生 `/etc/pilot/restic-env`（`mode: '0600'`，`no_log: true`） | 內含 S3 credentials 與 repository 密碼 |
| C7 | `copy` 產生 `/usr/local/bin/pilot-restic-backup.sh`（`mode: '0700'`） | 內含 `restic init`（僅未初始化時）、`restic backup`、`restic forget --prune` |
| C8, C9 | `copy` 產生 `restic-backup.service`/`.timer`，`systemd: enabled+started` | timer 觸發 service；service 是 `Type=oneshot` |
| C4, C5, C6 | 先查現有快照（`restic snapshots --json`），只在「還沒有任何快照」或「env/腳本剛變更」時才 `systemd: name=restic-backup.service state=started` 觸發一次同步執行 | oneshot service 的 `systemctl start` 會等到執行完才回，不需額外 poll；有條件觸發是為了讓「同樣變數重跑」維持 changed=0（見 §7.1 冪等檢查）；備份腳本開頭 `export HOME=/root`——systemd 起的 oneshot service 預設不帶 `$HOME`，`restic` 找不到本機 metadata cache 目錄會直接失敗（實測踩過，見 `docs/runbooks/restic-backup.md` §5）|
| C10 | `lineinfile /etc/hosts` pin `s3-backup-server`（`when: restic_s3_target_host | length > 0`）| 必須在備份腳本第一次執行（觸發 restic init）之前 |

## 7. SOP

### 7.1 標準情境：走本專案自建的 SeaweedFS S3 gateway

```bash
S3_IP=$(go run ./cmd/pilot vm-target show-inventory --name seaweedfs-s3 \
    | awk '/ansible_host:/{print $2; exit}')

# 1. 起 VM
go run ./cmd/pilot vm-target up --name restic-backup \
    --ssh-user ubuntu --disk 20 --memory 2048 --vcpus 2 \
    --ssh-timeout 5m --boot-timeout 5m

# 2. apply（機密走 -e，正式環境請改用 vault 檔）
go run ./cmd/pilot vm-target run --name restic-backup \
    playbooks/apply/restic-backup-apply.yml \
    -e restic_s3_target_host=$S3_IP \
    -e restic_aws_access_key_id=sandbox-access-key \
    -e restic_aws_secret_access_key=sandbox-secret-key \
    -e restic_password=sandbox-repo-password-123

# 3. verify
go run ./cmd/pilot vm-target verify --name restic-backup \
    docs/verification/restic-backup.md

# 4. 冪等檢查（同樣的變數再跑一次，應 changed=0；restic-backup.service 只在
#    「還沒有任何快照」或「env/腳本剛變更」時才觸發，見 §6，避免
#    `systemd: state: started` 套在 oneshot service 上變成每次都 changed）
go run ./cmd/pilot vm-target run --name restic-backup \
    playbooks/apply/restic-backup-apply.yml \
    -e restic_s3_target_host=$S3_IP \
    -e restic_aws_access_key_id=sandbox-access-key \
    -e restic_aws_secret_access_key=sandbox-secret-key \
    -e restic_password=sandbox-repo-password-123
```

### 7.2 逐軟體自訂備份範圍（host_vars 覆寫）

```bash
# host_vars/ipa-1.yml（FreeIPA server：備份設定 + 用官方 ipa-backup 產生的資料快照）
# restic_backup_paths: ["/etc", "/var/lib/ipa/backup"]
# restic_backup_pre_hook: "ipa-backup --data --logs"

go run ./cmd/pilot vm-target run --name restic-backup \
    playbooks/apply/restic-backup-apply.yml \
    -e restic_s3_target_host=$S3_IP \
    -e restic_aws_access_key_id=sandbox-access-key \
    -e restic_aws_secret_access_key=sandbox-secret-key \
    -e restic_password=sandbox-repo-password-123 \
    -e '{"restic_backup_paths": ["/etc", "/var/lib/ipa/backup"]}' \
    -e restic_backup_pre_hook="ipa-backup --data --logs"
```

> 在真實 inventory 中，`restic_backup_paths`/`restic_backup_pre_hook` 應放進
> 該主機的 `host_vars/<hostname>.yml`，不要每次用 `-e` 帶——見
> `group_vars/restic-backup.example.yml`。

## 8. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-06 | v1.0 | 初版：跨主機通用 restic 備份到 S3（預設本專案自建 SeaweedFS S3 gateway，可切換外部 S3），逐主機可覆寫備份路徑與 pre-hook | sre |
| 2026-07-06 | v1.1 | 用真實的 FreeIPA server（EL9）跑一次完整備份/故障/還原演練，發現並修正三個真事故：(1) apply playbook 原本只支援 Debian `apt`，補上 EL 系 `dnf`+EPEL 分流，C1 checklist 從 `dpkg -s` 改成套件管理器中立的 `command -v restic`；(2) 備份腳本在 systemd oneshot service 底下缺 `$HOME`，補 `export HOME=/root`；(3) 目的地 SeaweedFS bucket 若從未存在，`restic snapshots` 對「bucket does not exist」的重試退避會拖非常久、看起來像卡死，非 playbook bug 但記錄於 runbook 供排查。演練成功：刪除 389-ds 設定檔造成 server 故障、client 登入失敗，restic restore 還原後系統恢復正常，見 `docs/runbooks/restic-backup.md` §7 | sre |
| 2026-07-22 | v1.2 | C6 加入 `--retry-lock 30s`，使多台 host 共用 repository 時的並行 verifier 保留 lock 保護並有界等待；group 驗證明確使用 `--timeout 60` | sre |
| 2026-07-22 | v1.3 | C6 的 lock 等待延長為 `--retry-lock 120s`，group verifier timeout 同步為 180 秒；三台 host 共用 signed S3 repository 的並行 probe 實測全數通過 | sre |
