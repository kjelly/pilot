# Verification Spec — freeipa-client (Ubuntu 客戶端，接上 FreeIPA 的 認證/授權/稽核)

> 版本：v1.3（v1.0 已在 pilot vm-target `ubuntu-24.04` 上實跑 `ipa-client-install` enroll 進
> `alma-vm` 的 FreeIPA realm + `pilot verify`；v1.1 修正 canonical HBAC lockdown 下的 C8 false-negative，見 §0 / §3 / §8；
> v1.3 新增 C11 host DNS 自動註冊，見 §0 / §8）
> 對齊規範：pilot 通用基礎設施**使用端**規範；本 host 是**被 enroll 的 client**，
> 把「帳號認證（Authentication）+ 存取授權（Authorization / HBAC + sudo）+ 稽核（Audit）」
> 交給 FreeIPA server 統一提供。
> 維護者：sre

> 對偶參照：**提供者**（FreeIPA server）健康見 `docs/verification/freeipa-server.md`；
> 本檔是**使用端**健康。時間同步依賴既有 `ntp`(chrony/timesyncd) role（Kerberos 要求時鐘偏差 < 5 分鐘）；
> DNS：SRV-based KDC 探索**不使用**——server FQDN 一律由 `/etc/hosts` pin（見 §1）。這與
> selected FreeIPA server 是否啟用 native DNS（`freeipa_setup_dns`，預設 `true`）是兩回事：
> native DNS enabled 時，enrollment 會**額外**在 FreeIPA authoritative DNS 建立本 client 的
> A/AAAA record（C11，`freeipa-client-host-dns-registration` feature）；disabled 時安全 skip，
> 不影響 C1–C10 的 AAA 行為。`freeipa-dns-client`（把本機 resolver 指向 FreeIPA DNS）是完全
> 獨立的能力，不是 enrollment 的前提，見 `docs/verification/freeipa-dns-client.md`。

## 0. 這份檔的狀態（先讀）

依 `AGENTS.md` §1「actual-run 規則」：寫進 `docs/verification/*.md` 步驟區塊的指令，
**必須先在對應目標環境實際跑過並截真實輸出**才算數。

本檔 **v1.0** 的 apply playbook 已在拋棄式 Ubuntu 24.04 VM（`pilot vm-target up --base-image ubuntu-24.04`）
上實跑 `ipa-client-install`，成功 enroll 進 `alma-vm`（192.168.123.5）上的 FreeIPA realm
`IPA.PILOT.INTERNAL`。§2 checklist C1–C10 的每一條指令都以 target 上的 SSH 使用者身分實跑過，
§3 為真實 `pilot verify` 輸出（10/10 pass）。

**v1.3（C11 host DNS registration）— 已 live 驗證，2026-08-21**：新增 enrollment 自動在 FreeIPA
authoritative DNS 建立本 client A/AAAA record 的能力（`freeipa_client_register_dns`，effective
default 繼承 selected FreeIPA server 的 `freeipa_setup_dns`），以及既有已 enroll client 的
idempotent DNS backfill path（`playbooks/apply/tasks/freeipa-client-host-dns.yml`）。實作依 §1
non-negotiable rules：不寫入 `freeipa-dns.yaml`、不預設 dynamic DNS updates、不用
`--all-ip-addresses`、DNS conflict fail-closed、不因 DNS verify 失敗而 rollback 已成功的
enrollment。

Live vm-target 證據（3 台 VM：`freeipa-srv` almalinux-9 + `freeipa-cli-a`/`freeipa-cli-b`
ubuntu-24.04，`pilot vm-target run --group freeipa-server=freeipa-srv --group
freeipa-client=<client>` 讓 `groups['freeipa-server']` hostvars 偵測吃到真實跨主機 inventory，
不是單機 `target_group=all` 的簡化路徑）：
- clean enroll + DNS create + `pilot verify` C11 pass + 冪等重跑 `changed=0`（freeipa-cli-a）
- 先關閉 DNS registration enroll，再開啟重跑觸發 kinit+`dnsrecord-add` backfill（不重跑
  `ipa-client-install`）+ 冪等重跑 `changed=0`（freeipa-cli-b）
- DNS conflict fail-closed：手動塞一筆衝突 A record，rerun 在**任何 mutation 之前**（pre_tasks
  plan phase）就 fail，不 silent overwrite；清掉衝突後 rerun 恢復 `changed=0`
- `--check --diff` 對一台真正全新、從未 apply 過的 VM 跑：DNS plan 正確預覽、確認零 mutation
  （hostname 未變、`freeipa-client` 套件未裝、`/etc/ipa/default.conf` 不存在）

實測發現並修好 2 個真 bug（root cause 見 §8 v1.3 change log）：
1. spec.md §9.1 原設計要求 installer 帶 `--ip-address=`，但實測該旗標**不是**經 server 端
   host-add 靜態註冊 DNS，而是觸發 client 端一次性 `nsupdate` GSS-TSIG 動態更新，前提是 OS
   resolver 已指向 FreeIPA DNS——沒有這個前提時逾時（~37s）、`ipa host-show`/`dnsrecord-find`
   均確認未建立任何 record。修法：新 enroll 與既有 client 統一改走 admin-kinit +
   `dnsrecord-add`（不再傳 `--ip-address`）。
2. `select('trim')`（Jinja 沒有這個 test，只有同名 filter）在 dig 輸出非空時會直接炸掉
   `ansible.builtin.assert` 的 `fail_msg` 求值；`ipa dnsrecord-add` 重複值的真實錯誤訊息是
   `no modifications to be performed`，不是猜測的 `already contains`。兩處都已修正並補冪等
   實測。

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
| DNS | 無 SRV-based KDC 探索：server FQDN 由 `/etc/hosts` pin 到 `ipa_server_ip`；client 自身 FQDN 亦 pin 到自身 IP（`ipa-client-install` 硬性要求 FQDN 可解析到非 loopback）。若 selected server `freeipa_setup_dns=true`（預設），enrollment 另會在 FreeIPA authoritative DNS 建立本 client 的 A/AAAA record（C11）|
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
| `freeipa_client_register_dns` | 是否在 enrollment 時建立本 client 的 authoritative DNS A/AAAA record（C11）；未設時 effective 值繼承 selected FreeIPA server 的 `freeipa_setup_dns` | 否（有 effective default）|
| `freeipa_client_dns_addresses` | 明確指定要寫入 DNS 的 address list（IPv4/IPv6 皆可）；未設時 fallback 為 `ansible_default_ipv4.address` | 否（有 fallback）|

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
| C8  | authz    | 中央 sudo 規則對 IPA 帳號生效（`pilot-all` → pilotuser）             | ~NOPASSWD                                   | sudo -l -U pilotuser |
| C9  | audit    | 稽核守護程序 auditd active                                          | 0                                           | systemctl is-active auditd |
| C10 | audit    | kernel auditing 已啟用（稽核事件實際被捕捉）                          | ~enabled 1                                  | sudo auditctl -s |
| C11 | dns      | FreeIPA authoritative DNS 有本 client 的 A record（非 `/etc/hosts`）  | 0                                            | dig +short @ipa1.ipa.pilot.internal "$(hostname -f)" A | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' |

> **rc 型 expected（C1/C2/C3/C5/C6/C7/C9 = `0`）比對 process 退出碼**：
> - `systemctl is-active <svc>`（C2/C9）服務 active 時自身 rc 0，否則非 0 —— 刻意用 rc 而非
>   `~active`，因為字串 `active` 也會命中 `inactive`（實測會誤判）。
> - `grep -q`（C3/C7）命中回 0；`id`（C5）帳號可解析回 0；`sudo grep -qE`（C6）命中回 0。
> **`~`（contains）型 expected（C4/C8/C10）**不用 `^…$` regex：verify 的 ad-hoc 輸出帶
> `host | CHANGED | rc=0 >> …` 前綴，`$` 錨點會對不上（見 freeipa-server.md §2 同款註記，實測踩過）。
> **C8 是中央 sudo 授權驗證**：`pilotuser` 是純 IPA 帳號（本機 `/etc/sudoers` 沒有它）。
> verify 的 Ansible ad-hoc runner 以 root 執行 `sudo -l -U pilotuser`，列出 `(root) NOPASSWD: ALL`，
> 證明該權限只可能來自 FreeIPA 中央 `pilot-all` 規則（經 SSSD ipa sudo provider），同時不讓
> `runuser` 額外觸發 PAM/HBAC account gate。
> 此 row 依賴 server 端已建立 `pilot-all` 規則並授權給 `pilotuser`（見 §7.2）。
>
> **重要：`sudo -l -U <user>` 只允許 root（或本身有足夠 sudo 權限者）查詢。** C8 可使用它是因為
> verify 明確以 root 執行；一般非 root 操作者若被拒，不代表 IPA rule 有問題。反過來，使用
> `runuser -u <user> -- sudo -l` 會先經 PAM account/HBAC；站台關閉預設 `allow_all` 時，即使中央
> sudo rule 完全正確也可能被 HBAC 擋掉，不能拿它單獨判斷 sudo provider。
> **C11 直接查 authoritative DNS，不查 `/etc/hosts`**：故意不用 `getent hosts`/`ping`，因為
> C1/C3 的 apply task 已經把 client/server FQDN pin 進 `/etc/hosts`，那兩個工具會讀到 pin 而非
> 真正的 DNS 狀態，造成 false positive（spec.md §17）。`@ipa1.ipa.pilot.internal` 這個 nameserver
> 位址本身透過系統 resolver（含 `/etc/hosts`）解出並無妨——重點是**拿到答案之後的那一步**是對
> 該位址發出的一次真實 DNS query，答案來自 FreeIPA 自己的 named/bind9，不是本機檔案。Expected
> 只驗證「回傳了一個格式合法的 IPv4」（存在性 + 格式），不比對精確 IP：VM 的位址可能因
> DHCP/重建而變動，C1–C10 已經證明身分正確，C11 的職責純粹是「authoritative DNS 沒有
> NXDOMAIN/空答案」。

## 3. 證據收集

- 工具：`pilot vm-target verify --name <ubuntu-vm> docs/verification/freeipa-client.md`
  （真實主機：`pilot verify docs/verification/freeipa-client.md -i inventory-freeipa.yaml`）
- 格式：`.verification/freeipa-client-<UTC>.{ndjson,md}`
- 預期 row 數：11

> **C11 evidence 狀態：已於 2026-08-21 live 驗證**（下方 v1.3 區塊）。

**v1.0/v1.1 真實輸出**（Ubuntu 24.04 VM `freeipa-client`，playbook 從乾淨狀態 `pilot vm-target run`
`ipa-client-install` enroll 進 `alma-vm` FreeIPA 後，`pilot vm-target verify` 於
2026-07-02T11:20Z 實跑，verdict **PASS pass=10 fail=0 skip=0**，C1–C10）：

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

**v1.3 真實輸出（2026-08-21，含 C11）**：topology 為 `freeipa-srv`（almalinux-9,
`freeipa_setup_dns` 預設 `true`）+ `freeipa-cli-a`（ubuntu-24.04）+ `freeipa-cli-b`
（ubuntu-24.04），`pilot vm-target run --group freeipa-server=freeipa-srv --group
freeipa-client=freeipa-cli-a playbooks/apply/freeipa-client-apply.yml -e
target_group=freeipa-client -e ipa_verify_user=admin -e @<vault>` 乾淨 enroll 後，
`pilot vm-target verify --name freeipa-cli-a docs/verification/freeipa-client.md --timeout 40`：

```json
{"id":"C1","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C2","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C3","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C4","status":"pass","detail":"typed matcher matched"}
{"id":"C5","status":"fail","detail":"probe_status=module_error: id: 'pilotuser@ipa.pilot.internal': no such user"}
{"id":"C6","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C7","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C8","status":"fail","detail":"probe_status=module_error: sudo: unknown user pilotuser"}
{"id":"C9","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C10","status":"pass","detail":"typed matcher matched"}
{"id":"C11","status":"pass","detail":"rc=0 matches expected 0"}
```

verdict FAIL pass=9 fail=2（C5/C8）——**與 C11 無關**：本輪未先跑 §7.2 的
`freeipa-client-fixtures.yml`（`pilotuser` demo 帳號從未建立），這是既有 spec 前置條件，不是
本次 DNS feature 造成的回歸；C1–C4/C6/C7/C9/C10/**C11** 全部 pass，其中 C11 直接證明
`dig +short @ipa1.ipa.pilot.internal "$(hostname -f)" A` 對真實 authoritative FreeIPA DNS
回傳合法 IPv4。同一 client 冪等重跑 `playbooks/apply/freeipa-client-apply.yml`：
`PLAY RECAP ... ok=52 changed=0 failed=0`（DNS 相關 task 全數 `changed=0`）。

**backfill 情境**（`freeipa-cli-b`）：先以 `-e freeipa_client_register_dns=false` 乾淨 enroll
（`ok=38 changed=15 failed=0`，`dig` 確認 DNS 無記錄）；重跑同一 playbook、這次不覆寫
`freeipa_client_register_dns`（讓它從真實 inventory 偵測到的 `freeipa-server`
`freeipa_setup_dns` 繼承成 `true`）：`ipa-client-install` task 顯示 `ok`（`creates:` 擋下重新
enroll，未 re-run），DNS backfill 的 `dnsrecord-add` task 顯示 `changed`（僅此一個
`changed`，`PLAY RECAP ... ok=56 changed=1 failed=0`），`dig` 確認記錄已建立；再次重跑
`PLAY RECAP ... ok=52 changed=0 failed=0`（backfill 冪等）。

**conflict fail-closed**：對 `freeipa-cli-a` 的 authoritative DNS 手動塞一筆額外 A record
（`10.66.66.66`，desired 之外的值），重跑 apply：`fatal` 於 pre_tasks 的 plan-phase conflict
gate（`PLAY RECAP ... ok=22 changed=0 failed=1`——**在任何 mutation 之前**就 fail，不會動到
`/etc/hosts`/重新 enroll/DNS），錯誤訊息明確列出衝突位址；清掉衝突記錄後重跑，恢復
`changed=0`。

**check-mode（全新 VM）**：`pilot vm-target reset --name freeipa-cli-b` 回到 pristine 狀態後，
`... --check --diff`：DNS plan 正確印出（`current: [既有殘留記錄] desired: [此 VM IP] action:
NOOP`——因為 server 上仍留著同一 IP 的舊記錄，這是預期行為，不是 bug），事後確認
`hostname` 未變、`freeipa-client` 套件未裝、`/etc/ipa/default.conf` 不存在——零 mutation。
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
  - C8 fail → 先確認 probe 確實以 root 執行；再查 server 端沒建 `pilot-all` 規則 / 沒授權 pilotuser（見 §7.2），或 SSSD 未載 sudo service（`services=` 要含 sudo）、cache 未刷新（`sudo rm -f /var/lib/sss/db/*.ldb && sudo systemctl restart sssd`；Ubuntu 上 `sss_cache` 工具可能未裝，直接刪 cache 檔觸發重建）。
  - C9/C10 fail → `sudo systemctl enable --now auditd`；C10 若 `enabled 0`，`sudo auditctl -e 1`。

## 5. 例外與已知偏差

| ID  | 例外內容 | 適用環境 | 期限 |
|-----|---------|---------|------|
| C4/C6/C10 | 若 target 無 passwordless sudo，這幾條（讀 root-only 檔 / `auditctl`）需改由具 root 的方式跑，或標為 `skip` 並改用其他佐證（如 apply 完成後已記錄之 §3 健康態）| 無 passwordless sudo 的站台 | 永久 |
| C8  | 若 server 端尚未建立 `pilot-all` sudo 規則（§7.2），本 row 會 fail。純驗證「client 授權管道通不通」時，可改標 `skip` 並改用任一已存在的 IPA sudo 規則對應的帳號。`sudo -l -U` 必須以 root 執行，見 §2 C8 備註。| 尚未建 sudo 規則的站台 | 依站台 |
| C9/C10 | auditd 屬「本機稽核」補強，非 FreeIPA 元件；若站台以其他集中式稽核（如轉送 KDC/系統日誌到 SIEM）取代，可標 `skip` 並在文件註明替代來源 | 有替代稽核方案的站台 | 依站台 |
| C11 | 若 `freeipa_client_register_dns` effective 值為 `false`（selected FreeIPA server 未啟用 native DNS），本 row 預期 fail（authoritative DNS 本來就不會有這筆 record）；應改標 `skip`，佐證改用 apply 輸出的 `FreeIPA client DNS plan: registration: DISABLED`（spec.md §13.2）debug 訊息 | selected server `freeipa_setup_dns=false` 的站台 | 永久 |
| —   | 本 spec 的 NTP 部分不含獨立 row：`--no-ntp`，時間同步交給既有 `ntp` role（見 §1）| 全部 | 永久 |

## 6. Playbook 對應

對應的 verify playbook（`playbooks/verify/freeipa-client.yml`）**已於 2026-07-17 棄用**（僅存檔參考，見該目錄 README.md）；驗收直接 `pilot verify` 吃本 spec 執行。

對應手寫的 **apply** playbook：`playbooks/apply/freeipa-client-apply.yml`

| Spec ID | Apply task（tag）| 備註 |
|---------|-----------------|------|
| C1      | `tasks/cloud-init-etc-hosts-guard.yml` + `/etc/hosts` pin（self FQDN）+ `hostname` + apt `freeipa-client` + `ipa-client-install … creates=/etc/ipa/default.conf` | `/etc/hosts` pin **必須在** `hostname` 之前，否則新 FQDN 不可解析、之後每個 sudo 變慢導致 become 逾時（實測踩過，見 playbook 註解）；`creates:` 讓重跑冪等；`no_log: true`；enroll 密碼由 vault 注入；cloud-init 上的主機另需先跑 hosts-guard，否則此 pin 只撐到下次重開機（見 §8 2026-08-18） |
| C2      | `ipa-client-install`（帶起 sssd）+ `systemd name=sssd enabled started` | — |
| C3      | `tasks/cloud-init-etc-hosts-guard.yml` + `/etc/hosts` pin server FQDN + `ipa-client-install --server/--domain/--realm`（寫 krb5.conf）| 無 DNS，故 server 明確指定並 pin；`cloud-init-etc-hosts-guard.yml` 在此 pin 之前執行，寫 `/etc/cloud/cloud.cfg.d/99-pilot-disable-manage-etc-hosts.cfg`（`manage_etc_hosts: false`）讓 pin 撐過重開機（見 §8 2026-08-18） |
| C4/C5   | `ipa-client-install` 完成 enroll → host keytab + SSSD 身分；apply 內含 `until id <user>` 健康輪詢 | 首次 enroll 後冷 cache 需輪詢 |
| C6      | `ipa-client-install` 寫 `access_provider = ipa`（HBAC）| Ubuntu 24.04 的 ipa-client-install 預設即寫入 |
| C7      | nsswitch `sudoers: files sss`（lineinfile）| Ubuntu 上 ipa-client-install 不一定自動設，故 playbook 明確補 |
| C8      | SSSD `services=` 含 sudo（lineinfile，Ubuntu 24.04 預設已含 → no-op）+ server 端 `pilot-all` 規則（§7.2）| sudo provider 來源；規則本身在 server 建 |
| C9/C10  | 裝 + 啟 `auditd`（`package` + `systemd`）| 本機稽核 |
| C11     | `tasks/freeipa-client-host-dns.yml`（phase `plan`，pre_tasks，在 `/etc/hosts` pin **之前**：resolve + validate + dig 查 authoritative DNS + conflict gate；phase `apply`，enrollment/health 之後：kinit+`dnsrecord-add` 註冊/backfill missing address，新 enroll、既有 client 都走同一條路；兩邊都收尾於 dig-based post-apply verify）| effective `freeipa_client_register_dns` 未設時繼承 selected FreeIPA server 的 `freeipa_setup_dns`；conflict fail-closed（spec.md §8），不 silent takeover。**不使用 `ipa-client-install --ip-address=`**——2026-08-21 live vm-target 實測發現該旗標並非透過 server 端 host-add 靜態註冊，而是觸發 client 端一次性 `nsupdate` GSS-TSIG 動態更新，前提是 OS resolver 已指向 FreeIPA DNS（`freeipa-dns-client` 的職責，spec.md §18 明確要求兩者獨立），在未指向時會逾時失敗且不建立任何 record（`ipa host-show`/`ipa dnsrecord-find` 均確認無 IP）。因此新 enroll 與既有 client 統一改用 admin-kinit + `dnsrecord-add`，不依賴 installer 本身的 DNS 更新 |

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
pilot vm-target exec --name <ubuntu-vm> -- sudo -l -U pilotuser   # → (root) NOPASSWD: ALL
```

## 8. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-02 | v1.0 | 初版：Ubuntu 24.04 client enroll 進 FreeIPA（native EL9 server），提供 認證(Kerberos/SSSD)/授權(HBAC + 中央 sudo)/稽核(auditd)。在 `pilot vm-target ubuntu-24.04` 上實跑 `ipa-client-install` + `pilot verify` 10/10 pass（§3）| pilot |
| 2026-07-22 | v1.1 | canonical roster 關閉預設 `allow_all` HBAC 時，C8 的 `runuser` 會先被 PAM account gate 拒絕，造成中央 sudo rule 已生效卻 false-negative。改由 root runner 執行 `sudo -l -U pilotuser`，在 CAND20 的 client-vm 與 Nexus 實跑皆列出 `(root) NOPASSWD: ALL`；證據見 `.verification/minimal-poc-update/2026-07-22-round-12/formal-verify-cand20/freeipa-client-c8-root-query-probe.cast` | sre |
| 2026-08-18 | v1.2 | 修正真實事件（`cloud-init-freeipa-incident-report.md`）：`yk-pro6k-dev-01/02/03` 三台主機的 cloud-init `manage_etc_hosts: true` 在每次開機時依模板重建 `/etc/hosts`，把 C1/C3 的 FreeIPA server/client FQDN `lineinfile` pin 一併清掉，SSSD 因此解析不到 IPA server 而 offline，SSH 登入行為隨離線快取狀態不一致。手動改 `/etc/hosts` 不是永久修復——下次重開機會復發。新增共用 task `playbooks/apply/tasks/cloud-init-etc-hosts-guard.yml`，在 pin 之前寫入 pilot 專屬的 `/etc/cloud/cloud.cfg.d/99-pilot-disable-manage-etc-hosts.cfg`（`manage_etc_hosts: false`），讓 pin 永久生效；沒有 cloud-init 的主機（`/etc/cloud/cloud.cfg` 不存在）此 task 為 no-op。同一手法沿用 `tasks/freeipa-dns-client-resolver.yml` 的 netplan drop-in慣例（新增自己的高優先權檔案，不改別的層擁有的檔案）。已在 `pilot vm-target`（Ubuntu 24.04）上實測：base image 預設未設 `manage_etc_hosts`（即 cloud-init 預設 `false`），先手動加 `manage_etc_hosts: true` 的 00- 檔重現受影響主機的狀態，確認 `cloud-init clean --logs` + reboot 會照原樣清空自訂 `/etc/hosts` 項目；套用本 task 寫入 99- 檔後，同一 clean+reboot 循環下自訂項目撐過重開機，且第二次套用回報 `changed=0`（冪等）。已鎖進 `internal/spec/freeipa_client_regression_test.go` | pilot |
| 2026-08-21 | v1.3 | 新增 C11：enrollment/既有 client 自動在 FreeIPA authoritative DNS 註冊 A/AAAA record（`freeipa-client-host-dns-registration`，見 repo 根目錄 `spec.md`），新增 `playbooks/apply/tasks/freeipa-client-host-dns.yml`（plan phase 於 pre_tasks 做 resolve/validate/conflict-check，全在任何 mutation 之前；apply phase 於 enrollment 後做 kinit+`dnsrecord-add` 註冊/backfill + post-apply 驗證），`contracts/freeipa-client.yaml` 新增 `freeipa_client_register_dns`/`freeipa_client_dns_addresses`，`contracts/freeipa-server.yaml` 新增 `dnsTcp`/`dnsUdp` endpoints。**live vm-target 找到並修正 2 個真 bug**（不是「看起來對」就收工，見 §3 v1.3 證據）：(1) spec.md §9.1 原設計要 installer 帶 `--ip-address=`，但實測該旗標**不透過 server 端 host-add 靜態註冊**，而是觸發 client 端一次性 `nsupdate` GSS-TSIG 動態更新（需要 OS resolver 已指向 FreeIPA DNS，是 `freeipa-dns-client` 的職責，非本 feature 前提），沒有這個前提就逾時 ~37s 且不建立任何 record；修法：新 enroll 與既有 client 統一改走 admin-kinit + `dnsrecord-add`，installer 不再帶 `--ip-address`。(2) `select('trim')` 不是合法 Jinja test（`trim` 只有同名 filter），dig 輸出非空時會讓 `ansible.builtin.assert` 的 `fail_msg` 求值直接炸掉；改用 `map('trim') \| reject('equalto', '')`。順便修正 `ipa dnsrecord-add` 重複值的猜測錯誤字串（`already contains` → 實測真正的 `no modifications to be performed`）與對應 `changed_when`。3 台 vm-target（1 台 almalinux-9 `freeipa-server` + 2 台 ubuntu-24.04 `freeipa-client`，用 `--group` 建立真實跨 group inventory 讓 `freeipa_setup_dns` hostvars 偵測吃到真資料）驗證：clean enroll+DNS create+冪等、既有 client DNS-disabled→enable 觸發 backfill+冪等、DNS conflict fail-closed（衝突 record 存在時在任何 mutation 前就 fail，清掉後恢復冪等）、全新 VM `--check --diff` 零 mutation。regression test 新增 `TestRegression_FreeipaClientSpec_C11QueriesAuthoritativeDNS`/`TestRegression_FreeipaClientApplyPlaybook_HostDNSSafety`/`TestRegression_FreeipaClientHostDNSTask_NoLog`（`internal/spec/freeipa_client_regression_test.go`），`go test ./...`/`ansible-playbook --syntax-check`/`pilot spec --lint` 全過 | pilot |
| 2026-08-27 | v1.4 | v3.2 §16 持久性 SSSD client hardening（offline/cached authentication policy）：新增兩個選填 host_vars `freeipa_client_sssd_cache_credentials`/`freeipa_client_sssd_offline_credentials_expiration`（`contracts/freeipa-client.yaml`），沿用既有 `sudo_provider` task 的 `lineinfile` + `insertafter: '^ipa_domain\s*='` 手法寫入 `/etc/sssd/sssd.conf` 對應行，未設定則完全不動既有值。**明確的範圍決策，非隱藏缺口**：這次交付只驗證了設定值正確落地 sssd.conf 且 SSSD 重啟正常（`ansible-playbook --syntax-check`/`ansible-lint`/`go test`(contract schema + tag coverage) 全過），**沒有**驗證 spec.md §16.3 要求的「IdM 真的斷線時的行為」——這需要另一台獨立 client VM 加上刻意切斷網路/DNS 的多階段情境，屬於本次 v3.2 交付另一個已明確標記延後的項目（`docs/superpowers/specs/2026-08-27-pilot-roster-v3.2-identity-credential-hardening-spec.md` §16），與 v3.1 §17 當初延後的理由相同 | pilot |
