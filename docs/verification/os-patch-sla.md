# Verification Spec — os-patch-sla (Ubuntu/Debian periodic OS patching)

> 版本：v1.4
> 對齊規範：pilot 通用 OS 套件定期更新規範（Critical 15 天、High 30 天、Medium 90 天修補週期；更新前非生產環境驗證；自動化推送更新）
> 維護者：sre

## 1. 目標系統

| Hostname | Group    | Address          | User   | Port | IdentityFile                |
|----------|----------|------------------|--------|------|------------------------------|
| sandbox  | sandbox  |                  |        |      |                              |
| staging  | staging  |                  |        |      |                              |
| prod     | prod     |                  |        |      |                              |

> 各 host 的 Address/User/IdentityFile 留空、靠 `--from-ssh-config` 從 `~/.ssh/config` 補；
> 實際位址在 deployment repo 的 inventory 維護，這份 spec 留在工具的通用 repo。

> **每一列是 inventory 的「環境 group」，不是 hostname**（issue #174）：`pilot verify` 把這張表
> 以 group pattern（`prod:sandbox:staging`）交給 `ansible --list-hosts`，對你用 `-i` 傳入的那份
> inventory 解析成實際 host。每個 stage 各有自己的 inventory，所以只有該 stage 的 group 會比對到 host。
> 這張表**不准**放 `all` group，也不准放某台測試機的字面 hostname（例如 `test-vm`）：只要有一列的 Group
> 是 `all`（或留空），`pilot verify` 就改成把整張表當字面 hostname 比對，在沒有那些名字的 inventory 上
> 直接報 `spec targets contains host "..." that is absent from inventory`。
>
> vm-target 測試做法：每個 stage 一台拋棄式 VM，**不要**讓同一台 VM 同時屬於 staging 與 prod
> （playbook 的 stage cross-check 會正確地擋下 sandbox 套用，見 AGENTS.md §4.3）：
>
> - sandbox：`pilot vm-target up --name <n> --hosts sandbox`，
>   然後 `pilot vm-target test --name <n> --playbook playbooks/apply/os-patch-sla-apply.yml --spec docs/verification/os-patch-sla.md -- <vars>`。
> - staging：`--hosts staging`，`--` 後帶 `-e patch_stage=staging -e confirm_staging=true`。
> - prod：`--hosts prod`，`--` 後帶 `-e patch_stage=prod -e confirm_prod=true -e staging_attested_within_hours=24`。
> - 不需要 `-e target_group=`：playbook 的 `hosts:` 是 `target_group | default(patch_stage)`，
>   所以 `patch_stage` 就決定要套用哪個環境 group（issue #177 之前 play vars 寫死
>   `target_group: sandbox`，staging/prod 因此選不到 host）。只有要刻意改選別的 group 時才帶
>   `-e target_group=`。

## 2. Checklist

| ID  | Category     | Check                                                       | Expected      | Command |
|-----|--------------|-------------------------------------------------------------|---------------|---------|
| C1 | pkg | 一般可升級套件數量（資訊；查詢成功即 PASS，不要求零） | 0 | /usr/bin/python3 -c 'import apt; c=apt.Cache(); print("general-updates=" + str(sum(p.is_upgradable for p in c)))' |
| C2 | security | 所有已安裝套件均無較新的 security 版本 | 0 | /usr/bin/python3 -c 'import apt, apt_pkg; c=apt.Cache(); n=sum(p.is_installed and any(apt_pkg.version_compare(v.version,p.installed.version)>0 and any(o.archive.endswith("-security") for o in v.origins) for v in p.versions) for p in c); print(n); raise SystemExit(n != 0)' |
| C3 | timestamps | apt history.log 檔案存在 | 0 | test -f /var/log/apt/history.log |
| C4 | timestamps | apt history.log 最後修改在 90 天內 | 0 | sh -c 'find /var/log/apt/history.log -mtime -90 > /tmp/m.tmp; test -s /tmp/m.tmp' |
| C5 | service | unattended-upgrades 服務在跑 | 0 | systemctl is-active unattended-upgrades |
| C6 | config | 原生有效設定只允許當前 distro 的可信 security origins，且無額外 Origins-Pattern | 0 | /usr/bin/python3 -c 'import apt, apt_pkg, platform; r=platform.freedesktop_os_release(); d=r["ID"].capitalize(); c=apt.Cache(); want={o.origin+":"+o.archive for p in c for v in p.versions for o in v.origins if o.trusted and o.origin==d and (o.archive==r["VERSION_CODENAME"]+"-security" if d=="Ubuntu" else o.codename==r["VERSION_CODENAME"]+"-security" and o.label=="Debian-Security")}; a=apt_pkg.config.value_list("Unattended-Upgrade::Allowed-Origins"); p=apt_pkg.config.value_list("Unattended-Upgrade::Origins-Pattern"); print(a,p,sorted(want)); raise SystemExit(not want or not a or not set(a).issubset(want) or bool(p))' |
| C7 | separation | prod 不應被 marker 標記為允許直接推送 | 0 | test ! -f /etc/no-prod-direct-push |
| C8 | pkg | unattended-upgrades 套件已安裝 | 0 | dpkg-query -W -f='${db:Status-Status}' unattended-upgrades | grep -qx installed |

C1 的輸出是實際一般可升級數量，不計入 apt 的 Listing header；Expected `0` 是查詢退出碼，
不是零個更新。安全更新可能留下非 security 更新；C2 才要求 security 更新數量為零，並檢查
所有較新版本，而非只看 apt candidate。查詢錯誤必須 FAIL，不能被管線末端的計數掩蓋。
C6 讀原生 apt 合併後的有效設定及可信套件來源：Ubuntu 以 release-security archive 辨識，
Debian 以 release-security codename 和 Debian-Security label 辨識，不假設兩者 archive 命名相同。
C8 精確要求 dpkg 狀態 installed，不接受 config-files。

## 3. 證據收集

- 工具：`pilot verify docs/verification/os-patch-sla.md --inventory <inv.yaml>`
- 輸出格式：NDJSON
- 預期 row 數：8

## 4. PASS / FAIL 規則

- 全部 C1–C8 `status=pass` → **PASS**：本次 security-only 套用與 checklist 通過；不代表 CVE severity SLA 或觀察期已由自動化證明
- 任一 row fail → **FAIL**，列出 fail id + actual + want
- C7 fail → 立即把 host 從 prod rollout 名單中隔離（手動或 auto-pause）

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C1 | 一般更新僅觀察；本 playbook 只套用 security 更新，不要求所有一般更新歸零 | 全部 | 固定政策 |
| C6 | RHEL/CentOS 用 dnf-automatic 而非 unattended-upgrades；spec 不適用 | RHEL 系列 | 暫停支援 |

目前有效的 candidate 實跑摘要與未涵蓋範圍見 [LATEST](../evidence/os-patch-sla/LATEST.md)。
Ubuntu 24.04 與 Debian 12 的原生 CLI/來源格式已探查；完整 VM apply/verify 證據以該 record 為準。

## 6. Playbook 對應與政策

對應 apply：`playbooks/apply/os-patch-sla-apply.yml`。驗收直接由 `pilot verify` 執行本 checklist；
舊 `playbooks/verify/` 產物已棄用。

- sandbox 自動允許；staging 要 `confirm_staging=true`；prod 要 `confirm_prod=true`。
  `patch_stage` 必須符合 inventory 環境 group，`target_group` 僅控制選取，不繞過 gate。
- prod 的 `staging_attested_within_hours <= 168` 是操作者提供的 staging 佐證時效。
  預設 age 為 168；playbook 不查外部 attestation，也不自動證明完成 24h 觀察；觀察與升版授權由操作者負責。
- 所有 stage 都只執行 security 更新。`unattended_origins` 預設取原生可信 security
  metadata 的 origin:archive；自訂值必須是該清單的非空子集，非 security 值直接拒絕。
- 寫入 late managed fragment 前備份既有內容，清除繼承的 Allowed-Origins 與 Origins-Pattern，
  再驗證有效設定，之後才以 `DEBIAN_FRONTEND=noninteractive` 執行原生 `unattended-upgrade --debug`。
  任何非零退出碼立即失敗；即使原生指令回零，C2 非零仍使 apply 失敗。
- changed 依 dpkg 套件/status/version 集合前後差異，不猜 debug 訊息。C1 是一般更新觀察；
  C2 是 security 收斂斷言；C3/C4 是套件歷史檔狀態，並非按 CVE severity 計算的 SLA。
- C5 啟用服務，C6 驗證有效來源政策，C7 由 verify 檢查 marker，C8 經 strict apt framework 安裝套件。
  check mode 不執行升級；缺套件時不啟停不存在的服務，實際安裝與收斂需 apply 驗證。
- 失敗時還原 managed policy 並保持 play 失敗；**不自動降版或還原已更新的套件**。
  原生工具失敗可能已套用部分套件；需要套件復原時使用事前 VM snapshot/外部備份。
  `reboot_if_needed` 預設 false；若明示 true，僅 sandbox/staging 會重開機，prod 另行協調。

## 7. 把 FAIL 變 PASS 的 SOP

1. **先在 sandbox 驗證**（vm-target 測試做法見 §1 的說明，每個 stage 一台 VM）：
   ```bash
   ansible-playbook -i inventory-sandbox.yaml \
       playbooks/apply/os-patch-sla-apply.yml \
       -e patch_stage=sandbox --check --diff
   ansible-playbook -i inventory-sandbox.yaml \
       playbooks/apply/os-patch-sla-apply.yml \
       -e patch_stage=sandbox
   ```
2. **推 staging**（仍可手動；`pilot spec --apply` 已於 2026-07-17 棄用，
   套用一律走手寫 apply playbook）：
   ```bash
   ansible-playbook -i inventory-staging.yaml \
       playbooks/apply/os-patch-sla-apply.yml \
       -e patch_stage=staging -e confirm_staging=true
   ```
3. **人工觀察與授權**：依部署流程完成 staging 觀察，再跑一次 `pilot verify` 確認 checklist；playbook 不自動計時。
4. **推 prod**（promote gate 在 playbook 本身：`confirm_prod` + staging 佐證時效）：
   ```bash
   ansible-playbook -i inventory-prod.yaml \
       playbooks/apply/os-patch-sla-apply.yml \
       -e patch_stage=prod -e confirm_prod=true \
       -e staging_attested_within_hours=24
   ```
   沒帶 `confirm_prod=true`、或 staging 佐證超過時效，playbook 的
   gate assert 會直接擋下（fail-closed），不會套用。
5. **事後回填 SQLite**：對 prod inventory 再跑一次 `pilot verify
   docs/verification/os-patch-sla.md -i inventory-prod.yaml`，
   `spec_checkpoints.status` 翻成 `verified-pass`。

## 8. Commit / 版控

- ✅ 進版控：`docs/verification/os-patch-sla.md`、`playbooks/apply/os-patch-sla-apply.yml`（`playbooks/verify/os-patch-sla.yml` 已於 2026-07-17 棄用，不再更新）
- ❌ 不進版控：`.verification/*.md`、`.verification/*.ndjson`、本地 inventory.yaml、`~/.local/share/pilot/history.db`

## 9. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-06-30 | v1.0 | 初版（C1–C7）| pilot |
| 2026-10-28 | v1.1 | 新增 C8（`unattended-upgrades` 套件已安裝）。起因 issue #167：apply playbook 從不安裝這個套件，Step 4（systemd start+enable）在沒裝的主機上失敗，`--check` 也一樣（套件只被模擬安裝，unit 不存在）；Step 3 的 `failed_when: false` 還把「指令不存在」當成成功。apply 現在以 strict 政策經共用 apt framework 安裝套件，並在安裝後斷言套件存在（C5、C6 原本隱含依賴它，但沒有任何 row 檢查套件本身）| pilot |
| 2026-10-29 | v1.2 | §1 目標系統表改為純環境 group（`sandbox`/`staging`/`prod`），移除 `test-vm`/`all` 那一列，並在表下說明每列是 inventory group、不准放 `all` 或字面測試 hostname、vm-target 每個 stage 一台 VM。起因 issue #174：`all` 列讓 `pilot verify` 把整張表當字面 hostname，單台 vm-target VM 上報 `spec targets contains host "test-vm" that is absent from inventory`。依 AGENTS.md §2.1 選 B（改 spec）；stage gate 不動。Checklist C1–C8 與所有 Expected 值不變。§7 SOP 的 staging/prod 指令補上 `-e target_group=<stage>`（play vars 的 `target_group: sandbox` 讓 `hosts:` 的 default 不生效，不帶會 0 host）；staging 指令一併補上 apply 本來就要求的 `confirm_staging=true` | pilot |
| 2026-10-29 | v1.3 | issue #177 已修正 `os-patch-sla-apply.yml`：play vars 不再宣告 `target_group: sandbox`，`hosts:` 的 `default(patch_stage)` 恢復生效。移除 v1.2 加進 §1 與 §7 SOP 的 `-e target_group=<stage>` 提醒與說明（staging/prod 只帶 `-e patch_stage=<stage>` 與對應 confirm 旗標即可）；Checklist C1–C8、Expected 值與 §1 目標系統表不變 | pilot |
| 2026-11-03 | v1.4 | issue #172：修正原生旗標與錯誤傳遞；明確 security-only 政策，C1 改為一般更新實數觀察、C2 維持 security 零；C6 驗證原生合併設定，區分 Debian/Ubuntu security metadata。移除未實作的自動 24h 觀察與套件回滾承諾 | pilot |
