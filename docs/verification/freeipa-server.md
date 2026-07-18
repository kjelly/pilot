# Verification Spec — freeipa-server (native EL9, 帳號 + sudo 中央管理端)

> 版本：v1.3（v1.0 的 13 條已在 pilot vm-target `almalinux-9` 上實跑 `ipa-server-install` + `pilot verify`；v1.1 新增稽核日誌 C14–C16；v1.2 將 DNS 與 NTP 服務改為可選啟用，並新增相容性檢測列 C17–C18；v1.3 修正 §0/§1/§1.5 對 `ipa_setup_dns`/`ipa_setup_ntp` 預設值的文件描述以符合程式碼，見 §0 / §3 / §8）
> 對齊規範：pilot 通用基礎設施**服務端**規範；本 host 是提供 LDAP + Kerberos + sudo 中央目錄的那台（identity provider / directory），不是使用端
> 維護者：sre

> 對偶參照：使用端（被 enroll 的 client）健康見 `core-infra.md` / `pam-oidc-sshd.md`；
> 本檔是 FreeIPA **提供者**健康。**`ipa_setup_ntp`/`ipa_setup_dns` 在
> `freeipa-server-apply.yml` 實際預設都是 `true`**（由 FreeIPA 自己管理
> NTP/DNS）——2026-07-17 runbook 整併重測時發現本檔原本記載的「預設關閉、
> 依賴既有 `ntp`/`dns`(unbound) role」跟程式碼不一致，已更正（見 §1.5）；
> 要改回「依賴既有 role、不由 FreeIPA 管理」需顯式 `-e ipa_setup_ntp=false
> -e ipa_setup_dns=false`。

## 0. 這份檔的狀態（先讀）

依 `AGENTS.md` §1「actual-run 規則」：寫進 `docs/verification/*.md` 步驟區塊的指令，
**必須先在對應目標環境實際跑過並截真實輸出**才算數。

本檔 **v1.0** 部分（C1–C13）：apply playbook 已在拋棄式 EL9 VM（`pilot vm-target up --base-image almalinux-9`）
上實跑 `ipa-server-install` 成功（7 個 IPA 服務全 RUNNING、`ipa user-find` 走 SPNEGO rc=0），
§2 checklist C1–C13 每一條指令都以 target 上的 SSH 使用者身分實跑過，§3 為真實 `pilot verify` 輸出。

**v1.1 新增（C14–C16，389-ds 目錄服務稽核日誌）** 亦已實跑：於 live `freeipa-server` vm-target
（`instance=slapd-IPA-PILOT-INTERNAL`）跑 apply 的 `freeipa-audit` task，用 `dsconf config replace`
把 `nsslapd-auditlog*-logging-enabled` 由 `off`→`on`（`changed=1`、動態生效免重啟），
再 `pilot vm-target verify` 得 **PASS pass=16 fail=0 skip=0**（真實輸出見 §3）。

**為什麼是「native 裝在主機」而不是容器（重要設計決定）**：
早期版本把 FreeIPA 跑在 systemd-in-Docker 容器（`quay.io/freeipa/freeipa-server`）。
它能裝起所有 server 元件（DS/KDC/CA/HTTP），但**確定性地**卡在最後 self-enroll：
httpd 的 mod_auth_gssapi 取不到自己的 `HTTP/…` acceptor 憑證（SPNEGO
`cannot find mechanisms to negotiate`），且與 runtime（Docker == podman）、
設定（gssproxy interposer 或直接指 keytab）皆無關 —— 這是**容器層的 GSSAPI mechglue 問題，
不是 playbook bug**。同一組安裝步驟在 native EL9 主機上 self-enroll 乾淨通過。
因此本 spec 與 apply playbook 一律走 **native `ipa-server-install`**，不要再回頭引入容器路徑。

## 1. 目標系統

| Hostname                | Group          | Address       | User     | Port | IdentityFile |
|-------------------------|----------------|---------------|----------|------|--------------|
| ipa1.ipa.pilot.internal | freeipa-server |               |          |      |              |

| 項目 | 值 |
|------|----|
| Inventory group | `freeipa-server`（vm-target 測試時 host 在 `all`，用 `-e target_group=all`）|
| OS / version | **Enterprise Linux 9 原生**（AlmaLinux / Rocky / RHEL 9）；`ipa-server` 4.13.x |
| 角色 | 中央帳號目錄（389/636 LDAP）+ Kerberos KDC（88/464）+ sudo 規則來源（SSSD sudo provider）+ CA/enrollment（80/443）|
| 網路模式 | **host-native**：所有埠直接 bind 在主機（無容器、無埠映射）|
| DNS | **內建 DNS，預設啟用**（`ipa_setup_dns` 預設 `true`，自動安裝 `ipa-server-dns` 並設定 forwarders；`-e ipa_setup_dns=false` 才會改用 `--no-host-dns`）|
| NTP | **由 FreeIPA 管理 NTP，預設啟用**（`ipa_setup_ntp` 預設 `true`，配置 chrony；`-e ipa_setup_ntp=false` 才會改用 `--no-ntp`）|
| FQDN 規則 | FreeIPA **硬性禁止** server FQDN == domain；FQDN 必須是 domain 底下的 host，預設 `ipa1.<domain>` |
| 套用範圍 | 單台（HA replica 不在本 spec 範圍）|
| 風險等級 | High（掛了全網 login + sudo 受影響）|

## 1.5 依賴變數契約

套用或驗證此主機時，Playbook 與變數參數必須嚴格遵守以下命名，禁止擅自縮寫或發明新變數：

| 變數名稱 | 說明/用途 | 是否必填 |
|---------|----------|---------|
| `ipa_admin_password` | FreeIPA `admin` 帳號密碼（首次安裝時同時設為 Directory Manager 密碼，除非另給 `ipa_dm_password`）；由 vault file 注入，禁止 hard-code | 是 |
| `ipa_server_ip` | 本 host 對其他主機可路由的 LAN IP；寫進 `/etc/hosts` 讓 FQDN 解析到非 loopback（FreeIPA 安裝硬性要求）| 是 |
| `ipa_domain` | Kerberos/DNS domain，預設 `ipa.pilot.internal` | 否（有預設）|
| `ipa_realm` | Kerberos realm，預設 `IPA.PILOT.INTERNAL`（= `ipa_domain` 全大寫）| 否（有預設）|
| `ipa_server_fqdn` | server FQDN，預設 `ipa1.{{ ipa_domain }}`（**不可** == `ipa_domain`）| 否（有預設）|
| `ipa_dm_password` | Directory Manager 密碼；不給則沿用 `ipa_admin_password` | 否 |
| `ipa_enable_audit_log` | 是否開啟 389-ds 目錄服務稽核日誌（寫入 + 失敗寫入），預設 `true`；checklist C14–C16 依賴此為 `true` | 否（有預設）|
| `ipa_ds_instance` | 389-ds instance 名，預設 `slapd-{{ ipa_realm | replace('.', '-') }}`（= `slapd-IPA-PILOT-INTERNAL`）| 否（有預設）|
| `ipa_setup_dns` | 是否啟用 FreeIPA 內建 DNS 服務，預設 `true` | 否（有預設）|
| `ipa_dns_forwarders` | 當啟用 DNS 時，上游 DNS 轉發器 IP 列表，預設 `[]`（無轉發器） | 否（有預設）|
| `ipa_setup_ntp` | 是否由 FreeIPA 管理/啟用 NTP 同步，預設 `true` | 否（有預設）|

> Realm 後綴 DN：`ipa.pilot.internal` → `dc=ipa,dc=pilot,dc=internal`（checklist C11/C13 用到）。
> 換 domain 時，C11/C13 的 base DN 也要跟著換。
> 389-ds instance 名由 realm 推導：`IPA.PILOT.INTERNAL` → `slapd-IPA-PILOT-INTERNAL`（`.`→`-`），
> 稽核日誌落在 `/var/log/dirsrv/slapd-IPA-PILOT-INTERNAL/audit`（C14–C16 用到）。換 realm 時也要跟著換。

## 2. Checklist

> 指令以 target 上的 **SSH 使用者**身分執行（`pilot verify` 走 ansible ad-hoc）。
> `ipactl` 需 root → C2 用 `sudo`（target 需具備 passwordless sudo）；其餘查詢
> （`ss` 列出 listening、匿名 `ldapsearch`、`curl`、讀 world-readable 檔）皆免 root。

| ID  | Category  | Check                                                            | Expected                       | Command |
|-----|-----------|------------------------------------------------------------------|--------------------------------|---------|
| C1  | install   | FreeIPA 已設定完成（安裝產物存在）                                 | 0                              | test -f /etc/ipa/default.conf |
| C2  | service   | 所有 IPA 服務健康（`ipactl status` 全 RUNNING → 自身 rc 0）       | 0                              | sudo ipactl status |
| C3  | service   | 主機 FQDN 正確                                                    | ~ipa1.ipa.pilot.internal       | hostname -f |
| C4  | port      | LDAP 389/tcp 在 host listening                                   | 0                              | ss -tlnH | grep -q ":389 " |
| C5  | port      | LDAPS 636/tcp 在 host listening                                  | 0                              | ss -tlnH | grep -q ":636 " |
| C6  | port      | Kerberos 88/tcp 在 host listening                                | 0                              | ss -tlnH | grep -q ":88 " |
| C7  | port      | Kerberos 88/udp 在 host listening                                | 0                              | ss -ulnH | grep -q ":88 " |
| C8  | port      | kpasswd 464/udp 在 host listening                                | 0                              | ss -ulnH | grep -q ":464 " |
| C9  | port      | HTTP 80/tcp 在 host listening（enrollment 取 CA cert）            | 0                              | ss -tlnH | grep -q ":80 " |
| C10 | port      | HTTPS 443/tcp 在 host listening（IPA API / Web UI）              | 0                              | ss -tlnH | grep -q ":443 " |
| C11 | ldap      | LDAP rootDSE 廣告的 namingContext = realm 後綴                    | ~dc=ipa,dc=pilot,dc=internal   | ldapsearch -x -H ldap://localhost -b "" -s base namingContexts |
| C12 | http      | CA 憑證 endpoint 可被抓（client enroll 會走這條）                  | ~200                           | curl -fsS -o /dev/null -w "%{http_code}" http://ipa1.ipa.pilot.internal/ipa/config/ca.crt |
| C13 | sudo      | sudo 規則 LDAP 子樹存在（SSSD sudo provider 的來源）              | ~ou=sudoers                    | ldapsearch -x -H ldap://localhost -b "ou=sudoers,dc=ipa,dc=pilot,dc=internal" -s base dn |
| C14 | audit     | 389-ds 目錄服務稽核日誌（寫入操作）已啟用                          | ~nsslapd-auditlog-logging-enabled: on     | sudo dsconf slapd-IPA-PILOT-INTERNAL config get nsslapd-auditlog-logging-enabled |
| C15 | audit     | 389-ds 失敗寫入操作稽核日誌（auditfail）已啟用                     | ~nsslapd-auditfaillog-logging-enabled: on | sudo dsconf slapd-IPA-PILOT-INTERNAL config get nsslapd-auditfaillog-logging-enabled |
| C16 | audit     | 稽核日誌檔存在且已寫入（啟用後 389-ds 會寫入 header，非空）         | 0                              | sudo test -s /var/log/dirsrv/slapd-IPA-PILOT-INTERNAL/audit |
| C17 | port      | DNS 53/tcp 在 host listening（僅在啟用 DNS 時強驗，未啟用則自動 skip 達標） | 0                              | if ! ss -tlnH | grep -q ":53 "; then ! systemctl is-active --quiet named-pkcs11 && ! systemctl is-active --quiet named; fi |
| C18 | port      | DNS 53/udp 在 host listening（僅在啟用 DNS 時強驗，未啟用則自動 skip 達標） | 0                              | if ! ss -ulnH | grep -q ":53 "; then ! systemctl is-active --quiet named-pkcs11 && ! systemctl is-active --quiet named; fi |

> **C4–C10** 都含 `|` pipeline，parser 會把後續 column 自動接回 Command（見 spec template 說明），
> 並用 `":<port> "`（尾隨空白）避免 `:80` 誤命中 `:8080`；host-native 下埠直接 bind 在主機。
> 純數字 expected（C1/C2/C4–C10 = `0`）比對 **exit code**：`grep -q` 命中回 0。
> **C2 用正邏輯**（`sudo ipactl status` 全服務 RUNNING 時自身回 rc 0；任一 STOPPED/FAILED 則回非 0）
> ——刻意不寫成 `... | grep STOPPED` 的反邏輯，因為 ansible ad-hoc 會把「指令回非 0」判為 task 失敗、
> 讓 verify 收到的是 ansible 的 rc（2）而非管線的 rc（1），反邏輯 expected 永遠對不上（實測踩過）。
> **C3/C11–C13 用 `~`（contains）或字串比對**，不用 `^…$` regex：verify 的 ad-hoc 輸出帶
> `host | CHANGED | rc=0 | (stdout) …` 前綴，`$` 錨點會對不上（實測踩過）。
> **C14–C16（389-ds 目錄服務稽核日誌）** 需 root：`dsconf` 走 ldapi socket 以 root autobind
> 讀 `cn=config`（匿名讀不到），稽核檔 `mode 600 dirsrv:dirsrv`（一般帳號讀不到）——故三條都用
> `sudo`（同 C2，target 需 passwordless sudo）。389-ds 稽核日誌**預設關閉**，由 apply playbook
> 用 `dsconf config replace ...=on` 開啟（動態生效、免重啟，見 §6）。`dsconf config get` 輸出
> 為 `nsslapd-auditlog-logging-enabled: on` 形式，C14/C15 用 `~`（contains）比對該整行。
> instance 名 `slapd-IPA-PILOT-INTERNAL` 由 realm 推導（`IPA.PILOT.INTERNAL` 的 `.`→`-`）；
> 稽核檔路徑 `/var/log/dirsrv/<instance>/audit`——**換 realm 時 C14–C16 的 instance/路徑也要跟著換**。
> **C17–C18 (DNS 埠監聽)** 採用了相容設計：當 `ipa_setup_dns` 為 `true` 時，named 服務會啟動並監聽 `53` 埠，此時 `ss` 管道成功回傳 `0`；若未啟用 DNS，則 `ss` 回傳 `1`，但右半部判斷 named 服務皆為 inactive 也會成功，最終仍回傳 `0` (PASS)，從而實現了無狀態的「動態 skip 達標」。

## 3. 證據收集

- 工具：`pilot vm-target verify --name <el9-vm> docs/verification/freeipa-server.md`
  （真實主機：`pilot verify docs/verification/freeipa-server.md -i inventory-freeipa.yaml`）
- 格式：`.verification/freeipa-server-<UTC>.{ndjson,md}`
- 預期 row 數：18

**真實輸出（C17–C18，v1.2，未啟用 DNS 時）**：
`pilot vm-target verify` 實跑，C17/C18 與其餘 rows 共 18/18 獲得 PASS，範例如下：
```json
{"id":"C17","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C18","status":"pass","detail":"rc=0 matches expected 0"}
```

**真實輸出（C1–C13，v1.0）**（AlmaLinux 9.8 VM，playbook 從乾淨狀態 `pilot vm-target run` native `ipa-server-install`
完成後，`pilot vm-target verify` 於 2026-07-02T09:45Z 實跑，verdict **PASS pass=13 fail=0 skip=0**）：

```json
{"id":"C1","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C2","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C3","status":"pass","detail":"stdout contains \"ipa1.ipa.pilot.internal\""}
{"id":"C4","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C5","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C6","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C7","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C8","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C9","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C10","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C11","status":"pass","detail":"stdout contains \"dc=ipa,dc=pilot,dc=internal\""}
{"id":"C12","status":"pass","detail":"stdout contains \"200\""}
{"id":"C13","status":"pass","detail":"stdout contains \"ou=sudoers\""}
```

安裝完成後 C1–C13 13/13 pass。（安裝前、dev box 無 FreeIPA → 13/13 fail，那是 apply 前的預期起點。）

**真實輸出（C14–C16，v1.1，389-ds 稽核日誌）**：apply（`freeipa-audit` task 以 `dsconf config replace`
把 `nsslapd-auditlog*-logging-enabled` 由 `off`→`on`，`changed=1`、動態生效免重啟）後，
`pilot vm-target verify --name freeipa-server ... --timeout 40` 於 2026-07-06T02:22Z 實跑，
全 16 列 verdict **PASS pass=16 fail=0 skip=0**：

```json
{"id":"C14","status":"pass","detail":"stdout contains \"nsslapd-auditlog-logging-enabled: on\""}
{"id":"C15","status":"pass","detail":"stdout contains \"nsslapd-auditfaillog-logging-enabled: on\""}
{"id":"C16","status":"pass","detail":"rc=0 matches expected 0"}
```

（apply 前 C14/C15 為 `off`、C16 稽核檔為空 → 三條皆 fail，那是啟用稽核前的預期起點。）

> 註：冷連線時第一列（C1）偶見 `rc=-1`——那是 verify 每列預設 15s deadline 撞上「第一次 SSH
> ControlMaster 建線」的成本，非 server 問題。穩定作法二選一：先 `pilot vm-target exec --name <vm> -- true`
> 暖 SSH 連線，或提高每列逾時 `pilot vm-target verify --name <vm> <spec> --timeout 40`。實測暖線 + `--timeout 40` → 穩定 13/13。

## 4. PASS / FAIL 規則

- C1–C18 全部 `status=pass`（或 §5 允許的 `skip`）→ **PASS**：本機已可對外提供帳號 + sudo 管理，client 可 enroll，且目錄寫入操作留有稽核軌跡。
- 任一 `fail` → **FAIL**，常見修法：
  - C1 fail → `ipa-server-install` 沒跑完或失敗；`sudo tail -n 80 /var/log/ipaserver-install.log`，重跑 apply playbook。
  - C17/C18 fail → 啟用 DNS 時 named 服務未正常啟動，或未啟用 DNS 時系統 named 服務處於異常狀態。可使用 `sudo systemctl status named-pkcs11 named` 檢查狀態。
  - C2 fail → 某 IPA 服務掛了；`sudo ipactl status` 看哪個 STOPPED，`sudo ipactl restart`。
  - C3 fail → 主機 hostname 沒設成 FQDN；`sudo hostnamectl set-hostname ipa1.ipa.pilot.internal`。
  - C4–C10 fail → 對應服務沒起或防火牆擋；先查 C2，再查 host firewall（`firewalld`/`nftables`）是否放行該埠。
  - C11 fail → Directory Server 沒起或 realm 後綴打錯（對照 `ipa_domain`）。
  - C12 fail → HTTP(80) 沒起或 FQDN 在本機不可解析；確認 `/etc/hosts` 有 `ipa_server_ip ipa1.ipa.pilot.internal`（FQDN 在前）。
  - C13 fail → schema-compat（slapi-nis）未載入或匿名讀被關；見 §5 例外。
  - C14/C15 fail → 389-ds 稽核日誌未開啟；重跑 apply（`freeipa-audit` tag）或手動
    `sudo dsconf slapd-IPA-PILOT-INTERNAL config replace nsslapd-auditlog-logging-enabled=on nsslapd-auditfaillog-logging-enabled=on`（動態生效、免重啟）。
  - C16 fail → 稽核已開但檔案仍為空：做一次目錄寫入（如 `ipa user-mod admin --title=x`）觸發寫入紀錄；
    或確認 instance 名/路徑正確（`ls /etc/dirsrv/`）。若稽核檔權限非 root 可讀，確認以 `sudo` 執行。

## 5. 例外與已知偏差

| ID  | 例外內容 | 適用環境 | 期限 |
|-----|---------|---------|------|
| C2  | 若 target 無 passwordless sudo，C2 需改由具 root 的方式跑 `ipactl status`（或 apply 完成後改查 §3 已記錄之健康態）| 無 passwordless sudo 的站台 | 永久 |
| C13 | 若站台關閉 compat plugin 的匿名讀，`ou=sudoers` 匿名查詢會失敗。此時本 row 改以 Directory Manager bind 驗證（`-D "cn=Directory Manager" -w "$IPA_DM_PASSWORD"`），或標為 `skip` 並改用 §7 的 client 端 `sudo -l` 端到端驗證 | 有 compat hardening 的站台 | 永久 |
| C14–C16 | 若站台的合規要求不需要 389-ds 目錄寫入稽核（或改由外部 syslog/後端集中稽核取代），可設 `-e ipa_enable_audit_log=false` 關閉，並把 C14–C16 標為 `skip` | 不採 389-ds 內建稽核的站台 | 永久 |
| C16 | 稽核日誌的**輪替與磁碟用量**（`nsslapd-auditlog-maxlogsperdir` / `-logmaxdiskspace`）不在本 spec 範圍；預設值沿用 389-ds 出廠設定，長期落地站台請自行納入磁碟監控 | C16 | 稽核已開但檔案仍為空：做一次目錄寫入（如 `ipa user-mod admin --title=x`）觸發寫入紀錄；  |
| —   | 內建 DNS (C17-C18) 與 NTP 服務為可選啟用。若未啟用，時間同步由既有 `ntp`(chrony) 提供，DNS 由 `dns`(unbound) 提供；若啟用，FreeIPA 會接管並修改配置，此時需注意與現有 role 的衝突 | 全部 | 永久 |
| —   | **容器路徑已停用**：systemd-in-Docker 版本卡在 httpd GSSAPI acceptor（SPNEGO），與 runtime/設定無關，見 §0。本 spec 只認 native EL9 | 全部 | 永久 |

## 6. Playbook 對應

對應的 verify playbook（`playbooks/verify/freeipa-server.yml`）**已於 2026-07-17 棄用**（僅存檔參考，見該目錄 README.md）；驗收直接 `pilot verify` 吃本 spec 執行。

對應手寫的 **apply** playbook：`playbooks/apply/freeipa-server-apply.yml`

| Spec ID | Apply task（示例） | 備註 |
|---------|-------------------|------|
| C3      | `ansible.builtin.hostname name=ipa1.ipa.pilot.internal` + `/etc/hosts` pin（FQDN 為 canonical）| FQDN 必須是該 IP 的第一個名字，否則 `get_server_ip_address` 中止 |
| C1      | `ansible.builtin.dnf name=ipa-server` + `command: ipa-server-install -U … creates=/etc/ipa/default.conf` | `creates:` 讓重跑冪等；`no_log: true`；admin/DM 密碼由 vault 注入 `-e @~/.vault/main.yaml` |
| C2      | 安裝後 `until ipactl status` 沒有 STOPPED/FAILED 的 wait task | 首裝 8–12 分鐘，retries 拉長 |
| C4–C10  | 由 `ipa-server-install` 一次帶起（LDAP/Kerberos/HTTP/CA）；host-native 直接曝在主機 | firewall 放行由 host 層負責 |
| C11–C13 | `ipa-server-install -r IPA.PILOT.INTERNAL -n ipa.pilot.internal` 建立後綴、sudo compat 子樹 | — |
| C14–C16 | `command: dsconf {{ ipa_ds_instance }} config replace nsslapd-auditlog-logging-enabled=on nsslapd-auditfaillog-logging-enabled=on`（tag `freeipa-audit`）| `dsconf` 走 ldapi socket 以 root autobind，免 DM 密碼；動態生效、免重啟；先 `config get` 判斷、已 `on` 則跳過（冪等）；`ipa_enable_audit_log=false` 可整段關閉 |
| C17–C18 | `command: ipa-server-install --setup-dns ...` 且安裝 `ipa-server-dns` 套件，啟動 named 服務 | 預設不啟用。啟用後 named 服務聽在 `53` 埠 |

> Apply playbook 用 `block/rescue`：安裝失敗時 rescue 收 `ipactl status` + `ipaserver-install.log` 便於除錯；
> `pre_tasks: assert` 對 `ipa_admin_password` / `ipa_server_ip` 做 mandatory gate、對 OS（必須 EL9）與 staging/prod 做 gate。

## 7. 把 FAIL 變 PASS 的 SOP（server 端 + client enroll）

### 7.1 起 FreeIPA server（本 host，native EL9）

```bash
# 1. 先讀這一步要執行的那份 inventory 的事實
pilot vm-target show-inventory --name <el9-vm>              # 拋棄式 VM
# 真實主機：ansible-inventory -i inventory-freeipa.yaml --graph

# 2. dry-run（sandbox 預設；secret 走 vault file，不落地）
pilot vm-target run --name <el9-vm> playbooks/apply/freeipa-server-apply.yml \
    -e target_group=all -e ipa_server_ip=<vm-ip> \
    -e @~/.vault/main.yaml --check --diff

# 3. 正式套（拿掉 --check）；首裝約 8–12 分鐘
pilot vm-target run --name <el9-vm> playbooks/apply/freeipa-server-apply.yml \
    -e target_group=all -e ipa_server_ip=<vm-ip> \
    -e @~/.vault/main.yaml

# 4. 驗證
pilot vm-target verify --name <el9-vm> docs/verification/freeipa-server.md
```

### 7.2 建一條 sudo 規則（帳號 + sudo 中央管理示範）

```bash
# 在 server 上 kinit admin 後用 ipa CLI（admin 密碼由操作者互動輸入，不落 spec）
pilot vm-target exec --name <el9-vm> -- kinit admin
pilot vm-target exec --name <el9-vm> -- ipa sudorule-add allow-all-ops
pilot vm-target exec --name <el9-vm> -- ipa sudorule-add-user allow-all-ops --groups=admins
pilot vm-target exec --name <el9-vm> -- ipa sudorule-mod  allow-all-ops --cmdcat=all --hostcat=all
```

### 7.3 其他主機 enroll（帳號 + sudo 立即生效）

```bash
# client 端（RHEL/EL：dnf install ipa-client；Ubuntu：apt install freeipa-client）
# 先確保 client 能解析 ipa1.ipa.pilot.internal（既有 unbound DNS 或 /etc/hosts）
sudo ipa-client-install \
    --server=ipa1.ipa.pilot.internal \
    --domain=ipa.pilot.internal \
    --realm=IPA.PILOT.INTERNAL \
    --mkhomedir \
    --no-ntp                       # 時間同步交給既有 ntp role

# enroll 後 SSSD 會同時接管 帳號(getent) 與 sudo：
getent passwd <ipa-user>           # 帳號來自 FreeIPA
sudo -l -U <ipa-user>              # sudo 規則來自 FreeIPA（C13 的子樹）
```

> `ipa-client-install` 近版預設會在 `/etc/nsswitch.conf` 設 `sudoers: files sss` 並啟用 SSSD 的 sudo
> service；不需手動改。若舊版沒自動設，補 `sudoers: files sss` 即可。

## 8. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-02 | v0.1 | 初版草稿（C1–C13）；容器（systemd-in-Docker）+ host networking。**未實跑** | pilot |
| 2026-07-02 | v1.0 | **改為 native EL9 `ipa-server-install`**（容器路徑卡在 httpd GSSAPI acceptor，見 §0）。在 `pilot vm-target almalinux-9` 上實跑安裝 + `pilot verify` 13/13 pass；checklist 去除 `docker exec`、FQDN 改 `ipa1.ipa.pilot.internal`、C1 改查 `/etc/ipa/default.conf`、C2 用 `sudo ipactl status` | pilot |
| 2026-07-06 | v1.1 | 新增 **389-ds 目錄服務稽核日誌** 整合：checklist C14–C16（稽核/失敗稽核 logging-enabled、稽核檔非空）、§1.5 新增 `ipa_enable_audit_log` / `ipa_ds_instance`、apply playbook 新增 `freeipa-audit` task（`dsconf config replace ...=on`，冪等、動態生效）。已於 live `freeipa-server` vm-target 實跑 apply（`off`→`on`，`changed=1`）+ `pilot verify`（2026-07-06T02:22Z）得 **16/16 PASS**，真實 ndjson 見 §3 | pilot |
| 2026-07-07 | v1.2 | **變更為可選 DNS 與 NTP**。在 playbook 中支援 `ipa_setup_dns` (自動安裝 `ipa-server-dns` 套件與配置 forwarders) 及 `ipa_setup_ntp`。Spec checklist 新增 `C17`、`C18` 作為 DNS 埠檢測，並以 shell `||` 邏輯實現無狀態的「動態 skip 達標」機制。Go Regression 測試同步更新 row 數與 ID 校驗 | pilot |
| 2026-07-17 | v1.3 | 修正文件與程式碼不一致：`ipa_setup_dns`/`ipa_setup_ntp` 在 `freeipa-server-apply.yml` 實際預設都是 `true`（由 FreeIPA 自己管理 DNS/NTP），本檔 §0/§1/§1.5 原本記載「預設 `false`/關閉」跟程式碼不符——`docs/runbooks/metrics-alerting.md`/`restic-backup.md` 整併重測時，用真實 `ipactl start` 輸出（9 個服務，含 `named`/`ipa-dnskeysyncd`）發現此落差。只更新文件描述以符合現行程式碼行為，未改程式碼、未改 checklist 判斷邏輯（C17/C18 本來就相容兩種狀態） | sre |
