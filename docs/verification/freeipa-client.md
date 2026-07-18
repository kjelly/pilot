# Verification Spec — freeipa-client (Ubuntu 客戶端，接上 FreeIPA 的 認證/授權/稽核)

> 版本：v1.0（已在 pilot vm-target `ubuntu-24.04` 上實跑 `ipa-client-install` enroll 進
> `alma-vm` 的 FreeIPA realm + `pilot verify`，見 §0 / §3）
> 對齊規範：pilot 通用基礎設施**使用端**規範；本 host 是**被 enroll 的 client**，
> 把「帳號認證（Authentication）+ 存取授權（Authorization / HBAC + sudo）+ 稽核（Audit）」
> 交給 FreeIPA server 統一提供。
> 維護者：sre

> 對偶參照：**提供者**（FreeIPA server）健康見 `docs/verification/freeipa-server.md`；
> 本檔是**使用端**健康。時間同步依賴既有 `ntp`(chrony/timesyncd) role（Kerberos 要求時鐘偏差 < 5 分鐘）；
> DNS：本 pilot server 未啟用內建 DNS（`--no-host-dns`），故 client **無法**用 SRV 探索 KDC —
> server FQDN 由 `/etc/hosts` pin（見 §1）。

## 0. 這份檔的狀態（先讀）

依 `AGENTS.md` §1「actual-run 規則」：寫進 `docs/verification/*.md` 步驟區塊的指令，
**必須先在對應目標環境實際跑過並截真實輸出**才算數。

本檔為 **v1.0**：apply playbook 已在拋棄式 Ubuntu 24.04 VM（`pilot vm-target up --base-image ubuntu-24.04`）
上實跑 `ipa-client-install`，成功 enroll 進 `alma-vm`（192.168.123.5）上的 FreeIPA realm
`IPA.PILOT.INTERNAL`。§2 checklist 的每一條指令都以 target 上的 SSH 使用者身分實跑過，
§3 為真實 `pilot verify` 輸出（10/10 pass）。

**這台 client 從 FreeIPA 拿到什麼（AAA）**：
- **Authentication（認證）**：帳號與 Kerberos 身分來自 FreeIPA，經 SSSD 提供給 NSS/PAM
  （`id <ipa-user>` 解析得到、`/etc/krb5.keytab` 有本機 `host/…` principal）。
- **Authorization（授權）**：登入准駁交給 FreeIPA **HBAC**（SSSD `access_provider = ipa`）；
  `sudo` 規則來自 FreeIPA 中央目錄（SSSD ipa sudo provider + nsswitch `sudoers: sss`）——
  本 spec 用一條 server 端建立的 `pilot-all` sudo 規則（授權給 IPA 帳號 `pilotuser`）做端到端驗證。
- **Audit（稽核）**：本機有 Kerberos 機器身分，行為可在 IPA KDC 端歸戶；client 端由
  `auditd`（kernel auditing enabled）捕捉 FreeIPA 授權後實際發生的登入/sudo 事件。

**Client 先以 Ubuntu 為主**：套件為 apt `freeipa-client`（提供 `ipa-client-install`，並帶入
sssd + krb5）；EL client 走 `dnf install ipa-client`，只有裝套件那一步不同，enroll 與 SSSD
接線完全相同——apply playbook 以 OS family 分流（見 §6）。

## 1. 目標系統

| Hostname                       | Group          | Address | User | Port | IdentityFile |
|--------------------------------|----------------|---------|------|------|--------------|
| freeipa-client.ipa.pilot.internal | freeipa-client |         |      |      |              |

| 項目 | 值 |
|------|----|
| Inventory group | `freeipa-client`（vm-target 測試時 host 在 `all`，用 `-e target_group=all`）|
| OS / version | **Ubuntu 24.04**（primary）；apt `freeipa-client`。EL9 client 亦支援（`dnf ipa-client`）|
| 角色 | FreeIPA **使用端**：帳號/Kerberos 認證、HBAC 授權、中央 sudo 規則、本機稽核 |
| FreeIPA server | `ipa1.ipa.pilot.internal`（realm `IPA.PILOT.INTERNAL`, domain `ipa.pilot.internal`）|
| DNS | 無內建 DNS：server FQDN 由 `/etc/hosts` pin 到 `ipa_server_ip`；client 自身 FQDN 亦 pin 到自身 IP（`ipa-client-install` 硬性要求 FQDN 可解析到非 loopback）|
| NTP | **不由 FreeIPA 管**（`--no-ntp`）；時間同步交給既有 `ntp`(chrony/timesyncd) role |
| 套用範圍 | 單台 client（多台重複套用同一 playbook）|
| 風險等級 | Medium（掛了本機登入/sudo 受影響，但不影響其他 host）|

## 1.5 依賴變數契約

套用或驗證此主機時，Playbook 與變數參數必須嚴格遵守以下命名，禁止擅自縮寫或發明新變數：

| 變數名稱 | 說明/用途 | 是否必填 |
|---------|----------|---------|
| `ipa_admin_password` | enroll 用的 principal（預設 `admin`）密碼；由 vault file 注入，禁止 hard-code | 是 |
| `ipa_server_ip` | FreeIPA server 對本 client 可路由的 IP；寫進 `/etc/hosts` 讓 server FQDN 可解析 | 是 |
| `ipa_domain` | Kerberos/DNS domain，預設 `ipa.pilot.internal`（**必須**與 server 一致）| 否（有預設）|
| `ipa_realm` | Kerberos realm，預設 `IPA.PILOT.INTERNAL`（= `ipa_domain` 全大寫）| 否（有預設）|
| `ipa_server_fqdn` | FreeIPA server FQDN，預設 `ipa1.{{ ipa_domain }}`（與 freeipa-server spec 對齊）| 否（有預設）|
| `ipa_enroll_principal` | enroll 用的 IPA principal，預設 `admin` | 否（有預設）|
| `ipa_client_fqdn` | 本 client 自身 FQDN，預設 `{{ ansible_hostname }}.{{ ipa_domain }}` | 否（有預設）|
| `ipa_verify_user` | 驗證 SSSD 身分解析用的 IPA 帳號（apply health check + C5/C8）；預設 `admin`，本 spec 用 `pilotuser` | 否（有預設）|

> Realm 後綴 DN：`ipa.pilot.internal` → `dc=ipa,dc=pilot,dc=internal`。
> `ipa_domain` / `ipa_realm` / `ipa_server_fqdn` **必須**與 `freeipa-server.md` §1.5 完全一致，否則 enroll 失敗。

## 2. Checklist

> 指令以 target 上的 **SSH 使用者**身分執行（`pilot verify` 走 ansible ad-hoc）。
> 讀 root-only 檔（`/etc/krb5.keytab`、`/etc/sssd/sssd.conf`）與 `auditctl` 需 root →
> 用 `sudo`（target 需具備 passwordless sudo）；其餘查詢（`id`、`systemctl is-active`、
> 讀 world-readable 檔）皆免 root。

| ID  | Category | Check                                                              | Expected                                    | Command |
|-----|----------|--------------------------------------------------------------------|---------------------------------------------|---------|
| C1  | enroll   | 已 enroll（`ipa-client-install` 產物存在）                          | 0                                           | test -f /etc/ipa/default.conf |
| C2  | service  | SSSD 服務 active（帳號/認證的本機守護程序）                          | 0                                           | systemctl is-active sssd |
| C3  | enroll   | Kerberos realm 已設定正確                                           | 0                                           | grep -q IPA.PILOT.INTERNAL /etc/krb5.conf |
| C4  | authn    | 本機有 Kerberos 機器身分（host keytab 內含 host principal）          | ~host/     | sudo klist -k /etc/krb5.keytab |
| C5  | authn    | SSSD 能解析 FreeIPA 帳號（帳號認證後端已接上）                        | 0                                           | id pilotuser@ipa.pilot.internal |
| C6  | authz    | 登入准駁委由 FreeIPA HBAC（SSSD access_provider = ipa）              | 0                                           | sudo grep -qE "^access_provider *= *ipa" /etc/sssd/sssd.conf |
| C7  | authz    | sudoers 查詢路由到 SSSD（nsswitch）                                  | 0                                           | grep -qE "^sudoers:.*sss" /etc/nsswitch.conf |
| C8  | authz    | 中央 sudo 規則對 IPA 帳號生效（`pilot-all` → pilotuser）             | ~NOPASSWD                                   | sudo runuser -u pilotuser -- sudo -l |
| C9  | audit    | 稽核守護程序 auditd active                                          | 0                                           | systemctl is-active auditd |
| C10 | audit    | kernel auditing 已啟用（稽核事件實際被捕捉）                          | ~enabled 1                                  | sudo auditctl -s |

> **rc 型 expected（C1/C2/C3/C5/C6/C7/C9 = `0`）比對 process 退出碼**：
> - `systemctl is-active <svc>`（C2/C9）服務 active 時自身 rc 0，否則非 0 —— 刻意用 rc 而非
>   `~active`，因為字串 `active` 也會命中 `inactive`（實測會誤判）。
> - `grep -q`（C3/C7）命中回 0；`id`（C5）帳號可解析回 0；`sudo grep -qE`（C6）命中回 0。
> **`~`（contains）型 expected（C4/C8/C10）**不用 `^…$` regex：verify 的 ad-hoc 輸出帶
> `host | CHANGED | rc=0 >> …` 前綴，`$` 錨點會對不上（見 freeipa-server.md §2 同款註記，實測踩過）。
> **C8 是端到端授權驗證**：`pilotuser` 是純 IPA 帳號（本機 `/etc/sudoers` 沒有它）。
> `sudo runuser -u pilotuser -- sudo -l`（以 root 冒充 pilotuser 查自己的權限）列出 `(root) NOPASSWD: ALL`，
> 證明該權限只可能來自 FreeIPA 中央 `pilot-all` 規則（經 SSSD ipa sudo provider）。
> 此 row 依賴 server 端已建立 `pilot-all` 規則並授權給 `pilotuser`（見 §7.2）。
>
> **重要：`sudo -l -U <user>` 不能拿來診斷 IPA sudo 規則。** 該指令的語意是
> 「以我目前身份去查詢別人的權限清單」，在 sudo 實作裡有額外權限門檻——
> 預設只有 root（或本身就是全權 sudoer）才有資格用。被 `sudo -l -U` 拒絕
> 不代表那個 user 的 rule 有問題，只是你自己沒有「列出別人權限」的資格。
> **正確做法**是冒充那個 user 執行：`sudo runuser -u <user> -- sudo -n <cmd>`。

## 3. 證據收集

- 工具：`pilot vm-target verify --name <ubuntu-vm> docs/verification/freeipa-client.md`
  （真實主機：`pilot verify docs/verification/freeipa-client.md -i inventory-freeipa.yaml`）
- 格式：`.verification/freeipa-client-<UTC>.{ndjson,md}`
- 預期 row 數：10

**真實輸出**（Ubuntu 24.04 VM `freeipa-client`，playbook 從乾淨狀態 `pilot vm-target run`
`ipa-client-install` enroll 進 `alma-vm` FreeIPA 後，`pilot vm-target verify` 於
2026-07-02T11:20Z 實跑，verdict **PASS pass=10 fail=0 skip=0**）：

```json
{"id":"C1","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C2","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C3","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C4","status":"pass","detail":"stdout contains \"host/freeipa-client.ipa.pilot.internal\""}
{"id":"C5","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C6","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C7","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C8","status":"pass","detail":"stdout contains \"(root) ALL\""}
{"id":"C9","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C10","status":"pass","detail":"stdout contains \"enabled 1\""}
```

enroll 完成後 10/10 pass。（enroll 前、乾淨 Ubuntu → C1/C4/C5/C6/… fail，那是 apply 前的預期起點。）
> 註：與 freeipa-server 同款兩個環境 flake（非 server/playbook bug）：
> (1) 剛 enroll 完第一次 `sudo` 走冷 `pam_sss` 偶爾逾時 → `ansible.cfg timeout=30` 已緩解，重跑即過；
> (2) `verify` 第一列冷連線偶見 `rc=-1`（首次 SSH ControlMaster 建線撞每列 deadline）→ 先
> `pilot vm-target exec --name <vm> -- true` 暖線，或 `pilot vm-target verify … --timeout 40`。實測暖線 + `--timeout 40` → 穩定 10/10。

## 4. PASS / FAIL 規則

- C1–C10 全部 `status=pass`（或 §5 允許的 `skip`）→ **PASS**：本 client 已把 認證/授權/稽核 接上 FreeIPA。
- 任一 `fail` → **FAIL**，常見修法：
  - C1/C3 fail → `ipa-client-install` 沒跑完或失敗；`sudo tail -n 80 /var/log/ipaclient-install.log`，重跑 apply playbook（server FQDN 是否可解析、時鐘偏差）。
  - C2 fail → `sudo systemctl status sssd`；`sudo journalctl -u sssd -n 100`。常見是 server 不可達或 keytab 失效。
  - C4 fail → 機器 enroll 沒完成或 keytab 被清；`sudo ipa-client-install --uninstall -U` 後重跑 apply。
  - C5 fail → SSSD 起來但抓不到帳號；`sudo sssctl domain-status ipa.pilot.internal`、清 cache（Ubuntu 上 `sss_cache` 工具可能未裝，改用 `sudo rm -f /var/lib/sss/db/*.ldb && sudo systemctl restart sssd`）。
  - C6 fail → SSSD `access_provider` 不是 ipa（HBAC 未生效）；檢查 `/etc/sssd/sssd.conf`，重跑 enroll。
  - C7 fail → nsswitch 沒把 sudoers 導到 sss；補 `sudoers: files sss`（apply playbook C7 task）。
  - C8 fail → 先確認不是被 `sudo -l -U` 坑了（見 §2 C8 備註）；如果不是，再查：server 端沒建 `pilot-all` 規則 / 沒授權 pilotuser（見 §7.2），或 SSSD 未載 sudo service（`services=` 要含 sudo）、cache 未刷新（`sudo rm -f /var/lib/sss/db/*.ldb && sudo systemctl restart sssd`；Ubuntu 上 `sss_cache` 工具可能未裝，直接刪 cache 檔觸發重建）。
  - C9/C10 fail → `sudo systemctl enable --now auditd`；C10 若 `enabled 0`，`sudo auditctl -e 1`。

## 5. 例外與已知偏差

| ID  | 例外內容 | 適用環境 | 期限 |
|-----|---------|---------|------|
| C4/C6/C10 | 若 target 無 passwordless sudo，這幾條（讀 root-only 檔 / `auditctl`）需改由具 root 的方式跑，或標為 `skip` 並改用其他佐證（如 apply 完成後已記錄之 §3 健康態）| 無 passwordless sudo 的站台 | 永久 |
| C8  | 若 server 端尚未建立 `pilot-all` sudo 規則（§7.2），本 row 會 fail。純驗證「client 授權管道通不通」時，可改標 `skip` 並改用任一已存在的 IPA sudo 規則對應的帳號。**注意：不要用 `sudo -l -U` 診斷，見 §2 C8 備註。**| 尚未建 sudo 規則的站台 | 依站台 |
| C9/C10 | auditd 屬「本機稽核」補強，非 FreeIPA 元件；若站台以其他集中式稽核（如轉送 KDC/系統日誌到 SIEM）取代，可標 `skip` 並在文件註明替代來源 | 有替代稽核方案的站台 | 依站台 |
| —   | 本 spec 不含 DNS/NTP row：`--no-ntp` 且無內建 DNS，時間/名稱解析交給既有 `ntp` role 與 `/etc/hosts`（見 §1）| 全部 | 永久 |

## 6. Playbook 對應

對應的 verify playbook（`playbooks/verify/freeipa-client.yml`）**已於 2026-07-17 棄用**（僅存檔參考，見該目錄 README.md）；驗收直接 `pilot verify` 吃本 spec 執行。

對應手寫的 **apply** playbook：`playbooks/apply/freeipa-client-apply.yml`

| Spec ID | Apply task（tag）| 備註 |
|---------|-----------------|------|
| C1      | `/etc/hosts` pin（self FQDN）+ `hostname` + apt `freeipa-client` + `ipa-client-install … creates=/etc/ipa/default.conf` | `/etc/hosts` pin **必須在** `hostname` 之前，否則新 FQDN 不可解析、之後每個 sudo 變慢導致 become 逾時（實測踩過，見 playbook 註解）；`creates:` 讓重跑冪等；`no_log: true`；enroll 密碼由 vault 注入 |
| C2      | `ipa-client-install`（帶起 sssd）+ `systemd name=sssd enabled started` | — |
| C3      | `/etc/hosts` pin server FQDN + `ipa-client-install --server/--domain/--realm`（寫 krb5.conf）| 無 DNS，故 server 明確指定並 pin |
| C4/C5   | `ipa-client-install` 完成 enroll → host keytab + SSSD 身分；apply 內含 `until id <user>` 健康輪詢 | 首次 enroll 後冷 cache 需輪詢 |
| C6      | `ipa-client-install` 寫 `access_provider = ipa`（HBAC）| Ubuntu 24.04 的 ipa-client-install 預設即寫入 |
| C7      | nsswitch `sudoers: files sss`（lineinfile）| Ubuntu 上 ipa-client-install 不一定自動設，故 playbook 明確補 |
| C8      | SSSD `services=` 含 sudo（lineinfile，Ubuntu 24.04 預設已含 → no-op）+ server 端 `pilot-all` 規則（§7.2）| sudo provider 來源；規則本身在 server 建 |
| C9/C10  | 裝 + 啟 `auditd`（`package` + `systemd`）| 本機稽核 |

> Apply playbook 用 `block/rescue`：enroll/health 失敗時 rescue 收 `sssctl domain-status` +
> `ipaclient-install.log` 便於除錯；`pre_tasks: assert` 對 `ipa_admin_password` / `ipa_server_ip`
> 做 mandatory gate、對 OS（Debian/RedHat）與 staging/prod 做 gate。

## 7. 把 FAIL 變 PASS 的 SOP（server 端建規則 + client enroll）

### 7.1 前置：FreeIPA server 已就緒

先確保 `docs/verification/freeipa-server.md` 的 server（本 pilot 為 `alma-vm`）已 PASS，
並記下它對 client 可路由的 IP（本 pilot：192.168.123.5）。

### 7.2 server 端建立示範用的中央 sudo 規則（C8 的來源）

C8 依賴 server 端存在一個帳號 + sudo 規則。這是**跨 host 的前置狀態**，已固化成
fixtures playbook（冪等，密碼走 vault），跑在 **FreeIPA server** 上：

```bash
pilot vm-target run --name <server-vm> playbooks/test/fixtures/freeipa-client-fixtures.yml \
    -e fixtures_target_group=all -e @~/.vault/main.yaml
```

它會確保 `pilotuser` 帳號、`pilot-all` sudo 規則（hostcat=all cmdcat=all）、以及
把 `pilotuser` 掛進該規則都存在（實測冪等：重跑 `ok=6 changed=0`）。
（慣例見 `AGENTS.md` §4.1：`docs/verification/<spec>.md` 的跨 host 前置放
`playbooks/test/fixtures/<spec>-fixtures.yml`。）

### 7.3 client enroll（Ubuntu）

```bash
# 讀 client 這一步要執行的那份 inventory 的事實
pilot vm-target show-inventory --name <ubuntu-vm>            # 拋棄式 VM
# 真實主機：ansible-inventory -i inventory-freeipa.yaml --graph

# dry-run（sandbox 預設；secret 走 vault file，不落地）
pilot vm-target run --name <ubuntu-vm> playbooks/apply/freeipa-client-apply.yml \
    -e target_group=all -e ipa_server_ip=<server-ip> -e ipa_verify_user=pilotuser \
    -e @~/.vault/main.yaml --check --diff

# 正式套（拿掉 --check）；首次含 apt 下載 freeipa-client + enroll 約 3–6 分鐘
pilot vm-target run --name <ubuntu-vm> playbooks/apply/freeipa-client-apply.yml \
    -e target_group=all -e ipa_server_ip=<server-ip> -e ipa_verify_user=pilotuser \
    -e @~/.vault/main.yaml

# 驗證（先暖 SSH 連線，避免第一列冷連線 rc=-1）
pilot vm-target exec --name <ubuntu-vm> -- true
pilot vm-target verify --name <ubuntu-vm> docs/verification/freeipa-client.md --timeout 40
```

### 7.4 端到端驗證（帳號 + sudo 立即生效）

```bash
# 帳號來自 FreeIPA
pilot vm-target exec --name <ubuntu-vm> -- id pilotuser@ipa.pilot.internal
# sudo 規則來自 FreeIPA 中央目錄（pilot-all → pilotuser）
pilot vm-target exec --name <ubuntu-vm> -- sudo runuser -u pilotuser -- sudo -l   # → (root) NOPASSWD: ALL
```

## 8. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-02 | v1.0 | 初版：Ubuntu 24.04 client enroll 進 FreeIPA（native EL9 server），提供 認證(Kerberos/SSSD)/授權(HBAC + 中央 sudo)/稽核(auditd)。在 `pilot vm-target ubuntu-24.04` 上實跑 `ipa-client-install` + `pilot verify` 10/10 pass（§3）| pilot |
