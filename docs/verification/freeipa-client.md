# Verification Spec — freeipa-client (Ubuntu 客戶端，接上 FreeIPA 的 認證/授權/稽核)

> 版本：v1.5（v1.0 已在 pilot vm-target `ubuntu-24.04` 上實跑 `ipa-client-install` enroll 進
> `alma-vm` 的 FreeIPA realm + `pilot verify`；v1.1 修正 canonical HBAC lockdown 下的 C8 false-negative，見 §0 / §3 / §8；
> v1.3 新增 C11 host DNS 自動註冊，見 §0 / §8；v1.5 新增 Day-2 IP 遷移/DNS replacement，
> live vm-target L1-L11 全數 PASS，見 §8 / §9 變更紀錄）
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
| `freeipa_client_dns_replace_from_address` | Day-2 IP 遷移的 expected-old CAS token（單次授權，非永久 allow-flag）；未設時任何 authoritative extra 依然 fail-closed（見 §0 v1.5 / §9）| 否（不設 = 無 replacement 授權）|

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
| C11     | `tasks/freeipa-client-host-dns.yml`（phase `plan`，pre_tasks，在 `/etc/hosts` pin **之前**：resolve + validate + dig 查 authoritative DNS + CAS/identity 狀態機；phase `apply`，enrollment/health 之後：`ADD` 走 kinit+`dnsrecord-add`，`REPLACE` 走 apply-time re-read + kinit + `dnsrecord-mod`/value-scoped `dnsrecord-del`；兩邊都收尾於 dig-based exact post-apply verify）| effective `freeipa_client_register_dns` 未設時繼承 selected FreeIPA server 的 `freeipa_setup_dns`；`extra` 非空且無 `freeipa_client_dns_replace_from_address` 授權時 fail-closed（spec.md §8），不 silent takeover；有授權時見 §9 Day-2 replacement 狀態機。**不使用 `ipa-client-install --ip-address=`**——2026-08-21 live vm-target 實測發現該旗標並非透過 server 端 host-add 靜態註冊，而是觸發 client 端一次性 `nsupdate` GSS-TSIG 動態更新，前提是 OS resolver 已指向 FreeIPA DNS（`freeipa-dns-client` 的職責，spec.md §18 明確要求兩者獨立），在未指向時會逾時失敗且不建立任何 record（`ipa host-show`/`ipa dnsrecord-find` 均確認無 IP）。因此新 enroll 與既有 client 統一改用 admin-kinit + `dnsrecord-add`，不依賴 installer 本身的 DNS 更新 |

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

## 8. Day-2 IP 遷移（Host DNS Replacement）

> 完整規格：`docs/superpowers/specs/2026-09-02-freeipa-client-host-dns-ip-replacement-spec.md`。

**這解決什麼問題**：已受 Pilot/FreeIPA 管理的 client 主機換 IP 時，C11 的 `extra != ∅`
fail-closed gate 會擋下部署，過去只能 operator 手動登入 FreeIPA `dnsrecord-mod`。這個
功能讓 Pilot 能在**明確授權 + 身分證明**下安全收斂 DNS，**不削弱**原本的 no-implicit-takeover
不變量——沒有授權時行為與之前完全相同（fail-closed）。

**SOP（`pilot edit` 路徑）**：

1. 先在主機本身把 IP 換好（OS 網路層），確保新 IP 可連線、且 `/etc/ipa/default.conf` /
   `/etc/krb5.keytab` 都還在（沒有重新 enroll、沒有清過 keytab）。
2. `pilot edit` 修改該 host 的 `ansible_host`：舊 IP → 新 IP。因為此 host 掛
   `freeipa-client` role，TUI 會跳出明確 confirmation；選 **Yes** 會同時寫入
   `ansible_host: 新IP` + `freeipa_client_dns_replace_from_address: 舊IP`；選 **No** 只改
   `ansible_host`，之後若 DNS 仍是舊 IP 會照原本 fail-closed 行為擋下。
3.（建議）先跑 `--check --diff` 預覽 `action: REPLACE`，確認零 mutation。
4. 執行 deploy：plan phase 算出 `extra`/`missing`，唯一 stale extra 需精確等於授權值，且
   target 需用既有 keytab `kinit -k -t` 證明身分，才會給出 `action: REPLACE`；apply phase
   會在 mutation 前重新查一次 authoritative DNS（TOCTOU CAS re-check），確認仍相符才寫入。
5. 重跑應 `changed=0`（`NOOP_STALE_ACK`）；殘留的 `freeipa_client_dns_replace_from_address`
   不會造成任何後續 mutation，直到下次 `pilot edit` 再次確認時被覆寫成新的舊 IP。

**手動路徑**（不透過 `pilot edit`）：直接在 host_vars 設定
`freeipa_client_dns_replace_from_address: <目前 authoritative DNS 上的舊 IP>`，語意與上面
第 4 步相同。

**安全不變量**（見 spec §14 S1-S10，鎖在 `internal/spec/freeipa_client_regression_test.go`）：
- 沒有授權時 `extra != ∅` 永遠 fail-closed（S1）；
- 授權只在 `extra == {該授權值}` 時生效，精確 CAS 比對，不是模糊比對（S2）；
- 一次只能授權**一個** stale address——`|extra| > 1` 永遠 fail（S3，V1 non-goal，見下）；
- 一台全新/未 enroll 的主機，即使拿到正確授權值，也無法通過 identity proof（既有
  `/etc/ipa/default.conf` host/realm 相符 + 既有 keytab 的 exact principal `kinit`
  成功）而 takeover 既有 DNS owner（S4）；
- apply phase 一律在 mutation 前重新讀一次 authoritative DNS，不信任 plan 階段的舊快照（S5）；
- 一律不做 owner-wide `dnsrecord-del`，刪除必限定 record type/value，同 owner 的 TXT 等
  foreign record 不受影響（S6/S7）；
- 成功後 authoritative A/AAAA 集合與 desired **完全相等**（S8，順便修正舊有「只檢查
  missing、沒檢查 extra」的 exact-match 缺口，見下方變更紀錄）。

**V1 non-goals（明確不做，見 spec §23）**：同時更換舊 IPv4 + 舊 IPv6（multiple stale
extras）、PTR/reverse DNS 遷移、GSS-TSIG dynamic DNS、fresh host 沿用既有 FQDN 的自動
takeover、自動判斷「看到舊 IP 就一定是同一 host」。

**Live VM 證據（2026-09-02，spec §19 L1-L11 全數 PASS）**：

Topology：`freeipa-srv`（almalinux-9，native DNS）+ `freeipa-cli-a`/`freeipa-cli-b`
（ubuntu-24.04），`pilot vm-target up` 建立、`vm-target wire` + 手動 sudo sed 補
`/etc/hosts`（`vm-target wire` 對 ubuntu ssh_user 缺 sudo 前綴是既有 CLI 限制，非本
feature bug，已在 evidence 記錄避開）。`freeipa-server-apply.yml`/`freeipa-client-apply.yml`
透過 host 端 `ansible-playbook`（`--sandbox` 容器內建映像缺 `openssh-client`，同樣是
既有環境限制，非本 feature 影響範圍）。IP 遷移用 `virsh net-update default` 改
DHCP static reservation（同一張網卡的 MAC）+ guest 端 `systemctl restart
systemd-networkd` 觸發真實 DHCP 換址（`dhclient` 在 Ubuntu 24.04 cloud image 上不存在，
現代 netplan/systemd-networkd 慣例）——這是**同一台 VM 磁碟/keytab**真正改變可路由 IP，
不是重建新機器。

- **L1 clean enrollment**：`freeipa-cli-a` 乾淨 enroll，`pilot verify` 11/11 pass（含
  C11），冪等重跑 `changed=0 failed=0`。ADD path 未被本次改動破壞。
- **L2 happy path（10.20.30.41 風格 IPv4 遷移，真實位址 192.168.122.3→.203）**：
  `pilot edit` SOP 的手動等價操作（`-e freeipa_client_dns_replace_from_address=192.168.122.3`）；
  plan 印出 `action: REPLACE identity_proof: PASS`，apply `dnsrecord-mod A -> ['192.168.122.203']`，
  `PLAY RECAP ... changed=3 failed=0`；`dig` 確認 authoritative A 只剩 `.203`；冪等重跑
  `action: NOOP_STALE_ACK changed=0 failed=0`（殘留的 CAS token 不再造成任何 mutation）。
- **L3 無授權**：IP 已換但未設 `freeipa_client_dns_replace_from_address`：在 pre_tasks
  plan phase 的 `CONFLICT_UNAUTHORIZED` gate fail（`ok=36 failed=1`，`/etc/hosts`/
  hostname/enrollment 全未觸碰），錯誤訊息直接給出正確的補救指令；`dig` 確認 DNS 完全未變。
- **L4 錯誤/過期授權**：`freeipa_client_dns_replace_from_address=192.168.122.99`（非
  live 上真正的 stale 值）：`CONFLICT_CAS_MISMATCH` fail，零 mutation，訊息明確列出
  expected old / live extra / desired。
- **L5 全新主機冒充既有 FQDN（最重要的負向測試）**：`freeipa-cli-b`（從未 enroll）帶
  `ipa_client_fqdn=freeipa-cli-a.ipa.pilot.internal` + 正確的
  `freeipa_client_dns_replace_from_address`：在 `CONFLICT_IDENTITY_UNPROVEN` gate fail
  （`ok=38 failed=1`），因為沒有 `/etc/ipa/default.conf`/host keytab 可以 `kinit`；
  DNS 完全未被 takeover，`freeipa-cli-b` 事後確認仍是全新狀態（`test -f
  /etc/ipa/default.conf` rc=0 代表**不存在**）。
- **L6 old+new 並存收斂**：手動在 DNS 塞回舊值使 current=`[.203, .3]`、desired=`[.203]`，
  `freeipa_client_dns_replace_from_address=192.168.122.3`：單一 `dnsrecord-mod` 把 A
  RRset 收斂到精確 `['192.168.122.203']`（`changed=1 failed=0`），沒有因為 `missing=[]`
  就跳過 stale removal。
- **L7 foreign TXT 存活**：同 owner 先加 `TXT=foreign-record-should-survive`，
  再把 client 遷移到第三個位址（`.203→.204`，`freeipa_client_dns_replace_from_address=192.168.122.203`）：
  REPLACE 後 `A=192.168.122.204`、`TXT=foreign-record-should-survive` 完全存活
  （`ipa dnsrecord-show` 實測輸出）。
- **L8 CNAME 衝突 regression**：對一個帶 CNAME 的 owner（`cname-test.ipa.pilot.internal`）
  以任意 `freeipa_client_dns_replace_from_address` 值嘗試 REPLACE：仍在既有
  `Gate: DNS owner must not already have a CNAME` fail，訊息明確加註「no replacement
  acknowledgement 可以繞過」，零 mutation。
- **L9 apply-time race / CAS invalidation**：用一支**disposable verification harness**
  （`tmp/`，直接 include 未修改過的 production `tasks/freeipa-client-host-dns.yml`
  plan+apply 兩個 phase，中間插一個 `pause: seconds: 12` 讓外部行程有機會介入——不是
  production path 加 sleep/debug backdoor）：plan 算出 `action: REPLACE`（extra=`['.203']`
  R=`'.203'`）後，在 pause 期間外部把 DNS 改成 `extra='.205'`；apply phase 重新 dig 後
  正確偵測到落差，在「Gate: apply-time CAS still exactly matches」fail：
  `FAIL CLOSED — authoritative state changed after planning ... apply-time extra
  ['192.168.122.205'] vs authorized 192.168.122.203`，`changed=0`，`.205` 完全未被覆寫成
  desired。這證明 apply-time re-query 是真的在防護 TOCTOU，不只是文件宣稱。
- **L10 `--check --diff` 預覽**：對 L6 的 old+new-coexist REPLACE 情境先跑
  `--check --diff`：正確印出 `action: REPLACE identity_proof: PASS`，`changed=0`，
  authoritative DNS 與 target 設定事後確認完全未變，再真正 apply 才產生上面 L6 的結果。
- **L11 IPv6 canonicalization（找到並修好 1 個真 bug）**：手動以**展開格式**
  `2001:0db8:0000:0000:0000:0000:0000:0061` 建立 stale AAAA record，`freeipa_client_dns_replace_from_address`
  同樣用展開格式傳入：plan 正確算出 `extra: ['2001:db8::61']`（`dig` 自己會正規化顯示）、
  `replace_from: 2001:db8::61`，CAS 比對正確判定相符、`action: REPLACE`。但第一次
  apply 在 `dnsrecord-del` 失敗：`ipa: ERROR: AAAA record does not contain
  '2001:db8::61'`——**真因**：FreeIPA/LDAP 儲存值時保留原始輸入格式（不像 `dig`
  顯示會正規化），`dnsrecord-del --aaaa-rec=<value>` 是精確字串比對，用我方正規化後的
  compressed 值去刪一個 LDAP 裡仍是展開格式的值會找不到。**修法**：cross-family 刪除前
  新增一個 read-only `ipa dnsrecord-show --all --raw` 查詢（沿用 `freeipa-dns-apply.yml`
  同款慣例），從中找出「正規化後等於 R」的**原始字串**再刪除，而非直接用正規化值。修好後
  重跑：`PRUNE_STALE freeipa-cli-a.ipa.pilot.internal 2001:db8::61`，`changed=1 failed=0`，
  `dig AAAA` 確認記錄消失、`A`/`TXT` 不受影響。此 bug 已鎖進
  `TestRegression_FreeipaClientHostDNSTask_DeleteUsesRawStoredValue`。

**過程中另找到並修好第二個真 bug（影響所有 action，不只 IPv6）**：這個 repo 的
`ansible.cfg` 全域啟用 `fact_caching = jsonfile`（1 小時 TTL）。`freeipa-client-apply.yml`
原本用隱式 `gather_facts: true`——同一 inventory hostname 在 cache TTL 內重跑會直接
沿用**換 IP 之前**快取的 `ansible_default_ipv4.address`，導致 desired 位址算成舊值，
完全偵測不到 IP 真的變了（實測：換 IP 後立刻重跑，desired 仍印出舊 IP，
`action: NOOP`——這正是本 feature 存在的理由被自己的 fact cache 悄悄繞過）。修法：
改成 `gather_facts: false` + pre_tasks 第一個 task 明確呼叫 `ansible.builtin.setup`
（explicit 呼叫一律真的執行，不像隱式 gather-facts 那樣會被快取跳過），只在這支
playbook 停用快取，不動全域 `ansible.cfg`。

**收尾**：最終真實狀態（`.204`，A only，TXT 存活）以正確 inventory 跑
`pilot verify docs/verification/freeipa-client.md` 得到 **PASS pass=11 fail=0
skip=0**；`ansible-playbook --syntax-check`、`ansible-lint`（production 門檻，0
violation）、`go build ./...`、`go vet ./...`、`go test ./...` 全過（僅剩 3 個與本
feature 無關的既有失敗：本 sandbox 無真 TTY 的 2 個 deploy 測試、1 個無關的
`TestRegression_LogShippingPlaybookAutoDetectsDashboardHost`、1 個 repair-MCP
subprocess timeout——均與 freeipa-client DNS 無關，非本次改動造成）。3 台 VM 事後
`vm-target down` 全部清除。

## 9. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-02 | v1.0 | 初版：Ubuntu 24.04 client enroll 進 FreeIPA（native EL9 server），提供 認證(Kerberos/SSSD)/授權(HBAC + 中央 sudo)/稽核(auditd)。在 `pilot vm-target ubuntu-24.04` 上實跑 `ipa-client-install` + `pilot verify` 10/10 pass（§3）| pilot |
| 2026-07-22 | v1.1 | canonical roster 關閉預設 `allow_all` HBAC 時，C8 的 `runuser` 會先被 PAM account gate 拒絕，造成中央 sudo rule 已生效卻 false-negative。改由 root runner 執行 `sudo -l -U pilotuser`，在 CAND20 的 client-vm 與 Nexus 實跑皆列出 `(root) NOPASSWD: ALL`；證據見 `.verification/minimal-poc-update/2026-07-22-round-12/formal-verify-cand20/freeipa-client-c8-root-query-probe.cast` | sre |
| 2026-08-18 | v1.2 | 修正真實事件（`cloud-init-freeipa-incident-report.md`）：`yk-pro6k-dev-01/02/03` 三台主機的 cloud-init `manage_etc_hosts: true` 在每次開機時依模板重建 `/etc/hosts`，把 C1/C3 的 FreeIPA server/client FQDN `lineinfile` pin 一併清掉，SSSD 因此解析不到 IPA server 而 offline，SSH 登入行為隨離線快取狀態不一致。手動改 `/etc/hosts` 不是永久修復——下次重開機會復發。新增共用 task `playbooks/apply/tasks/cloud-init-etc-hosts-guard.yml`，在 pin 之前寫入 pilot 專屬的 `/etc/cloud/cloud.cfg.d/99-pilot-disable-manage-etc-hosts.cfg`（`manage_etc_hosts: false`），讓 pin 永久生效；沒有 cloud-init 的主機（`/etc/cloud/cloud.cfg` 不存在）此 task 為 no-op。同一手法沿用 `tasks/freeipa-dns-client-resolver.yml` 的 netplan drop-in慣例（新增自己的高優先權檔案，不改別的層擁有的檔案）。已在 `pilot vm-target`（Ubuntu 24.04）上實測：base image 預設未設 `manage_etc_hosts`（即 cloud-init 預設 `false`），先手動加 `manage_etc_hosts: true` 的 00- 檔重現受影響主機的狀態，確認 `cloud-init clean --logs` + reboot 會照原樣清空自訂 `/etc/hosts` 項目；套用本 task 寫入 99- 檔後，同一 clean+reboot 循環下自訂項目撐過重開機，且第二次套用回報 `changed=0`（冪等）。已鎖進 `internal/spec/freeipa_client_regression_test.go` | pilot |
| 2026-08-21 | v1.3 | 新增 C11：enrollment/既有 client 自動在 FreeIPA authoritative DNS 註冊 A/AAAA record（`freeipa-client-host-dns-registration`，見 repo 根目錄 `spec.md`），新增 `playbooks/apply/tasks/freeipa-client-host-dns.yml`（plan phase 於 pre_tasks 做 resolve/validate/conflict-check，全在任何 mutation 之前；apply phase 於 enrollment 後做 kinit+`dnsrecord-add` 註冊/backfill + post-apply 驗證），`contracts/freeipa-client.yaml` 新增 `freeipa_client_register_dns`/`freeipa_client_dns_addresses`，`contracts/freeipa-server.yaml` 新增 `dnsTcp`/`dnsUdp` endpoints。**live vm-target 找到並修正 2 個真 bug**（不是「看起來對」就收工，見 §3 v1.3 證據）：(1) spec.md §9.1 原設計要 installer 帶 `--ip-address=`，但實測該旗標**不透過 server 端 host-add 靜態註冊**，而是觸發 client 端一次性 `nsupdate` GSS-TSIG 動態更新（需要 OS resolver 已指向 FreeIPA DNS，是 `freeipa-dns-client` 的職責，非本 feature 前提），沒有這個前提就逾時 ~37s 且不建立任何 record；修法：新 enroll 與既有 client 統一改走 admin-kinit + `dnsrecord-add`，installer 不再帶 `--ip-address`。(2) `select('trim')` 不是合法 Jinja test（`trim` 只有同名 filter），dig 輸出非空時會讓 `ansible.builtin.assert` 的 `fail_msg` 求值直接炸掉；改用 `map('trim') \| reject('equalto', '')`。順便修正 `ipa dnsrecord-add` 重複值的猜測錯誤字串（`already contains` → 實測真正的 `no modifications to be performed`）與對應 `changed_when`。3 台 vm-target（1 台 almalinux-9 `freeipa-server` + 2 台 ubuntu-24.04 `freeipa-client`，用 `--group` 建立真實跨 group inventory 讓 `freeipa_setup_dns` hostvars 偵測吃到真資料）驗證：clean enroll+DNS create+冪等、既有 client DNS-disabled→enable 觸發 backfill+冪等、DNS conflict fail-closed（衝突 record 存在時在任何 mutation 前就 fail，清掉後恢復冪等）、全新 VM `--check --diff` 零 mutation。regression test 新增 `TestRegression_FreeipaClientSpec_C11QueriesAuthoritativeDNS`/`TestRegression_FreeipaClientApplyPlaybook_HostDNSSafety`/`TestRegression_FreeipaClientHostDNSTask_NoLog`（`internal/spec/freeipa_client_regression_test.go`），`go test ./...`/`ansible-playbook --syntax-check`/`pilot spec --lint` 全過 | pilot |
| 2026-09-02 | v1.5 | 新增 Day-2 IP 遷移（`freeipa_client_dns_replace_from_address` CAS token + apply-time re-check + identity proof via `kinit -k -t`），見 §8。`playbooks/apply/tasks/freeipa-client-host-dns.yml` 新增 REPLACE 狀態機（`NOOP`/`ADD`/`REPLACE`/`NOOP_STALE_ACK`/4 種 `CONFLICT_*`）、IP 一律先用 `ipaddress.ip_address().compressed` 正規化再比較（修正 IPv6 expanded/compressed 誤判 false-conflict 的既有隱患）、`freeipa-client-apply.yml` 把 enrollment/keytab 的 `stat` 移到 pre_tasks（DNS plan include 之前，供 identity proof 與既有 installer gate 共用同一份 canonical 結果，不再各自探測）。**順便修正一個既有 bug**：post-apply「exact」驗證過去只檢查 `desired - post == ∅`（missing-only），沒檢查 `post - desired == ∅`（extra），與 task 名稱宣稱的「matches … exactly」不符；已修成雙向差集equality。`contracts/freeipa-client.yaml`/`group_vars/freeipa.example.yml` 新增/補文件該欄位。regression test 新增 8 支（contract 登錄、no owner-wide delete、state machine 形狀/優先序、identity proof AND 組合、enrollment probe 順序、apply-time CAS re-check、post-apply 雙向 exact 驗證、cross-family delete 用 as-stored raw value）於 `internal/spec/freeipa_client_regression_test.go`；另補一支 `TestRegression_FreeipaClientApplyPlaybook_FreshFactsNotCached` 鎖下方 fact-caching bug 的修法（`gather_facts: false` + 明確 `setup`）；`go build`/`go vet`/`go test ./...`/`ansible-playbook --syntax-check`/`ansible-lint`（production 門檻）全過。`pilot edit` UX（`ansible_host` 換 IP 在 freeipa-client host 上的 confirm 畫面 + `set_host_field` automation action 的 `confirm` 欄位對等）另見 `cmd/pilot/cmd/edit_tui_freeipa_client.go`/`edit_actions_registry.go`/`edit_automation.go`/`edit_automation_driver.go`。**live vm-target §19 L1-L11 全數 PASS（2026-09-02，見 §8 evidence 段落）**：3 台 VM（1×almalinux-9 server + 2×ubuntu-24.04 client）、同一 VM 真實改 IP（`virsh net-update` DHCP reservation + guest 端 `systemctl restart systemd-networkd`，非重建新機）驗證 happy path/無授權/錯誤授權/fresh-host 冒充/old+new並存/foreign TXT/CNAME衝突/apply-time race/`--check --diff`/IPv6 canonicalization。**實測額外找到並修好 2 個真 bug**（不在原始碼審查中發現，只有真的跑過 VM 才暴露）：(1) cross-family stale 刪除用了正規化後的 compressed 值去比對 FreeIPA/LDAP 裡可能仍是展開格式儲存的 IPv6 值，`dnsrecord-del` 精確字串比對失敗——已改成 delete 前先 `dnsrecord-show --all --raw` 找出「正規化後等於 R 的原始字串」；(2) 本 repo `ansible.cfg` 全域 `fact_caching`（1h TTL）讓這支 playbook 隱式 `gather_facts: true` 在 IP 剛換完重跑時吃到換 IP 前快取的 `ansible_default_ipv4.address`，導致完全偵測不到 IP 已變——已改成 `gather_facts: false` + pre_tasks 明確呼叫 `ansible.builtin.setup`（只在本 playbook 繞過快取，不動全域設定） | pilot |
| 2026-08-27 | v1.4 | v3.2 §16 持久性 SSSD client hardening（offline/cached authentication policy）：新增兩個選填 host_vars `freeipa_client_sssd_cache_credentials`/`freeipa_client_sssd_offline_credentials_expiration`（`contracts/freeipa-client.yaml`），沿用既有 `sudo_provider` task 的 `lineinfile` + `insertafter: '^ipa_domain\s*='` 手法寫入 `/etc/sssd/sssd.conf` 對應行，未設定則完全不動既有值。**明確的範圍決策，非隱藏缺口**：這次交付只驗證了設定值正確落地 sssd.conf 且 SSSD 重啟正常（`ansible-playbook --syntax-check`/`ansible-lint`/`go test`(contract schema + tag coverage) 全過），**沒有**驗證 spec.md §16.3 要求的「IdM 真的斷線時的行為」——這需要另一台獨立 client VM 加上刻意切斷網路/DNS 的多階段情境，屬於本次 v3.2 交付另一個已明確標記延後的項目（`docs/superpowers/specs/2026-08-27-pilot-roster-v3.2-identity-credential-hardening-spec.md` §16），與 v3.1 §17 當初延後的理由相同 | pilot |
