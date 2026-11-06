# Verification Spec — freeipa-client (Ubuntu 客戶端，接上 FreeIPA 的 認證/授權/稽核)

> 本次變數契約修改（issue #81）的 tested revision、測試範圍與結果，見
> [2026-10-20 evidence](../evidence/spec-inventory-inputs/2026-10-20-e11fb44.md)。

> 版本：v1.8（v1.0 已在 pilot vm-target `ubuntu-24.04` 上實跑 `ipa-client-install` enroll 進
> `alma-vm` 的 FreeIPA realm + `pilot verify`；v1.1 修正 canonical HBAC lockdown 下的 C8 false-negative，見 §0 / §3 / §8；
> v1.3 新增 C11 host DNS 自動註冊，見 §0 / §8；v1.5 新增 Day-2 IP 遷移/DNS replacement，
> live vm-target L1-L11 全數 PASS，見 §8 / §9 變更紀錄；v1.6 新增 host annotations（enrollment
> 後把 `pilot_annotations` 投影到 FreeIPA userClass/nshostlocation），驗證方式是 apply 本身內建
> 的 Phase F 讀回比對（非 checklist row——見 §1.5/§6/§9 v1.6 說明與 live L1-L13 證據）；
> v1.7 修正 C1/C8 的 apt install 不再對「無關第三方 APT repository 壞掉」fatal（改走共用
> `playbooks/apply/tasks/apt-package-install.yml`，見 `docs/verification/apt-repository-tolerance.md`
> 與 §9 v1.7 說明）；v1.8 新增 C12：SSH client 端預設對本 realm 網域開啟 GSSAPI ticket
> delegation，確保未來停用密碼登入後 pilot-access-gateway 跳板機仍可 relay 登入，見 §9 v1.8 說明；
> v1.14 新增 C13–C18：SSH key 等非密碼登入時對已過期 FreeIPA 密碼的政策（opt-in，
> `freeipa_client_sssd_password_expiry_policy`），row 指令與 apply／fixture playbook 已實跑，正式 evidence 尚未完成，見 §0 / §9 v1.14／v1.15；
> v1.16 新增 C19–C20：`renew` 時一併設定 `[pam] pam_initgroups_scheme = always`，讓改密碼後重新登入與管理員 reset 不被 SSSD 的 PAM 快取擋住（#262／#263），見 §0 / §9 v1.16
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

**v1.14／v1.15（C13–C18：SSH key 登入時對已過期密碼的政策）— apply 與 fixture playbook 已實作，Ubuntu 24.04 `renew` 的 `topology test` evidence 已產生，2026-11-05**：
新變數 `freeipa_client_sssd_password_expiry_policy`（`warn`／`renew`／`off`，未設定就不動）把 SSSD
domain 的 `ipa_access_order` 設成 `expire, pwd_expire_policy_<warn|renew>` 或 `expire`。`renew` 讓用
SSH key（或 GSSAPI）登入、但 FreeIPA 密碼已過期的人在拿到 shell 前先改密碼。roster 給的預設密碼是
管理員 reset，FreeIPA 一律標成立即過期，所以這也包含還沒改過預設密碼的人。

- C13–C18 依主機 sssd.conf **當下**的 `ipa_access_order` 判斷預期結果，未啟用的主機也會 PASS。
- 2026-11-05 在拋棄式 topology（AlmaLinux 9 FreeIPA server + Ubuntu 24.04 client，SSSD 2.9.4、
  OpenSSH 9.6p1）用 `pilot verify --probe`（與 `pilot verify` 相同的管線）實跑 C13–C18：未設定、
  `warn`、`renew`、`off` 四種狀態全部 PASS；另外製造每一列要擋的狀態，每一列都會 FAIL（§3 v1.14）。
  這一輪政策是手動改 sssd.conf + 重啟 SSSD 模擬的，所以是 row 指令的實測，**不是** evidence chain。
- v1.15：`playbooks/apply/freeipa-client-apply.yml` 實作 C13／C14（見 §6），
  `playbooks/test/fixtures/freeipa-client-pwexpiry-fixtures.yml` 建立 C15–C17 的 fixture 帳號
  （`pilot-pwexpired`／`pilot-pwvalid`／`pilot-pwnear`／`pilot-nopw`，直接用 `ipa user-mod --random`／
  `--password-expiration` 造出狀態，不經 roster）。2026-11-05 在同一組拋棄式 topology 用
  `ansible-playbook` 直接實跑（開發期探測，不是 `topology test`）：`renew`／`warn`／`off`／未設定四種狀態
  C13–C18 全部 PASS、重跑 `changed=0`；負向控制（非法值、非 24.04、`renew` 在 gateway 主機、
  `ipa_access_order` 重複或未知形式、`sssctl config-check` 失敗、SSSD 沒載入政策、`--check`）都在
  修改前拒絕或由 rescue 還原，sssd.conf 位元組不變；hand-edit 後不重啟再跑 `--tags C14` /
  `--tags sssd_hardening` 會重啟 SSSD。
- 目前有效 evidence（v1.16，`renew` 加 `pam_initgroups_scheme = always`；Ubuntu 24.04 client + AlmaLinux 9 server，全新 VM）：
  - **一般 client**：candidate `d1b9220beef77a7545e58cc2e5d8794b55fd1031`（tree `8d66316ce8ef29f7d2ebc4fd1535adbce54ea95f`）的
    `vm-target topology test` 全部通過——L3 `--check --diff`、L4 apply、L5 verify（`freeipa-server.md` 20/0/0、本 spec
    20/0/0、`login-probe.md` 14/0/0）、L6 `changed=0`；之後在同一組 VM 實跑 A01–A09、A11、A13、A14、A17、A18，負向對照組
    N1–N11 與 `always` 的代價量測，逐項結果與限制見
    [evidence LATEST](../evidence/freeipa-client-password-renewal/LATEST.md)。
  - **A12（FreeIPA primary／replica／全部不可達）**：candidate `49c289dbe9794621dad8f97bfa332c8f4ffceaec`（與上一個只差
    HA 測試 chain 一個檔案）的 HA 拓樸通過（verify 20/0/0、16/0/0、20/0/0，L6 `changed=0`），結果見
    [evidence LATEST](../evidence/freeipa-client-password-expiry-ha/LATEST.md)。
  - **A10（gateway／directory／target-policy 主機）**：同一個 candidate `49c289db` 的六節點拓樸通過（gateway 33/0/0、
    directory 9/0/0、target-policy 5/0/0，L6 `changed=0`），結果見
    [evidence LATEST](../evidence/freeipa-client-password-expiry-gateways/LATEST.md)。
- A04：過期、使用者知道舊密碼時，sshd 改跑 `passwd`、改完斷線、重新登入進 shell 且 sudo 正常，FreeIPA 到期日 +90 天。
  A18（v1.16）：改完密碼後即使只用 TTY 反覆重試，第二次嘗試（約 10 秒）就成功；非互動式約 4 秒；使用者有開著的 session 時管理員
  reset 在 0.4 秒內被發現。對照組（拿掉 `always` 行、重啟 SSSD）重現 #262／#263：TTY-only 重試 16 次都沒有成功，reset 要 99.1 秒
  才被發現。login-probe 的 canary 有 2099 到期的密碼時維持 `ok`，密碼被管理員 reset 成過期後 11 秒內轉成 `session`，恢復到期日後
  53 秒內回到 `ok`（受 probe 60 秒週期限制）。
- A06 的結果要知道：停用的帳號與 HBAC 拒絕的帳號在 `renew` 下沒有 `passwd` 提示、被直接拒絕；`krbPrincipalExpiration`
  已過期的帳號會走到 `passwd` 提示，但 FreeIPA 拒絕改密碼（即使舊密碼正確），所以沒有 shell、密碼不變。
  同一個帳號在 `off`（原本行為）下用 key 登入會拿到 shell，所以 `renew` 比原本嚴格，但不是在提示之前拒絕（#266）。
- A10 的結果：對 gateway、directory、target 三台套用 `renew` 後，密碼有效時 portal、Directory TUI 與 e2e 的 `disabled` 4/4、
  `recording` 3/3 通過（`strict` 見下）；密碼過期時 TTY 登入由 `passwd` 取代 ForceCommand（沒有 `pilot-session`／
  `pilot-directory-session` 行程），沒有 TTY 的登入、遠端命令與經 gateway 的 ssh／sftp 都失敗並帶 "Password change required
  but no TTY available"，沒有任何 gateway 事件、session store 紀錄或 target 登入產生，所以沒有繞過 recording 的 session；改完密碼
  後 gateway 約 4–6 秒、directory 約 16 秒重新登入。沒有密碼的 portal 帳號在 `renew` 下被拒絕（同 A17，對照主機可登入）。
  **這個 PR 沒有解除 preflight 對這三個群組的 `renew` 拒絕**：evidence 是用另一份不含這三個群組的 inventory 套用 `renew` 取得的，
  解除拒絕要改 execution-affecting 的 playbook，需要新的 candidate 並重做全部證據。e2e `strict` 階段沒有穩定的 20/20：
  TP07 轉發探針偶發失敗（有、無 `always` 都會，#272），`AG72-pilot-connect` 在使用者留有 Kerberos ticket 時失敗（#272）；
  已建立的 SSH 連線（ControlPersist）在密碼被 reset 後仍可用到結束（#270）。
- A12 的結果：兩台 server 都在、primary 停止（replica 提供服務）、replica 停止時，有效密碼的 key 登入分別為 0.45、1.23、1.43 秒；
  兩台都停止時，已快取的有效密碼使用者仍可用 key 登入（約 0.2–0.6 秒），已快取的過期使用者沒有 shell（有 TTY 時停在
  `Current Password:`，改密碼回 "System is offline, password change not possible"），沒看過的使用者被拒絕；server 恢復後
  同一個改密碼在 34.8 秒內成功，沒有任何清快取指令。`sssctl domain-status` 的 Online 欄位會落後實際狀態。
- `always` 的代價（一台 client 的 A-B-A 量測）：每個「距離使用者上一個 PAM 請求超過 5 秒、而使用者已有 session」的 PAM 請求
  多一次後端使用者查詢（約 4 個 LDAP 搜尋），每次多約 10 ms，登入時間沒有變長；高負載主機與 FreeIPA 伺服器端的負載沒有量。
- A16（sudo cache 與密碼過期交叉，#267）：PAM 的過期狀態與 sudo 規則是兩個獨立的更新機制。把使用者加進 sudo 規則後，PAM 在改密碼後
  約 2 秒就是 `Success`，但規則要等後端的 `SUDO Smart Refresh`（預設每 900 秒）才生效（實測 647 秒與 900 秒，`always` 與預設
  scheme 都一樣），與 `renew` 無關，沒有用任何清快取指令。新帳號加進規則後，最久約 15 分鐘沒有 sudo。
- SSH 公鑰在使用者被快取後才加入時要等一段時間才可用（#269）。這不屬於本功能的行為，但會影響測試與操作。

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
| OS / version | **Ubuntu 24.04**（primary）；apt `freeipa-client`。EL9 client 亦支援（`dnf ipa-client`）。C13–C18 的 `warn`／`renew` 只支援 Ubuntu 24.04：其他主機設定 `freeipa_client_sssd_password_expiry_policy` 時，apply 在修改前拒絕 |
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
| `freeipa_server_ip` | FreeIPA server 對本 client 可路由的 IP；寫進 `/etc/hosts` 讓 server FQDN 可解析 | 是 |
| `freeipa_domain` | Kerberos/DNS domain，預設 `ipa.pilot.internal`（**必須**與 server 一致）| 否（有預設）|
| `freeipa_realm` | Kerberos realm，預設 `IPA.PILOT.INTERNAL`（= `freeipa_domain` 全大寫）| 否（有預設）|
| `freeipa_server_fqdn` | FreeIPA server FQDN，預設 `ipa1.{{ ipa_domain }}`（與 freeipa-server spec 對齊）| 否（有預設）|
| `ipa_enroll_principal` | enroll 用的 IPA principal，預設 `admin` | 否（有預設）|
| `ipa_client_fqdn` | 本 client 自身 FQDN，預設 `{{ ansible_hostname }}.{{ ipa_domain }}` | 否（有預設）|
| `ipa_verify_user` | 驗證 SSSD 身分解析用的 IPA 帳號（apply health check + C5/C8）；預設 `admin`，本 spec 用 `pilotuser` | 否（有預設）|
| `freeipa_client_register_dns` | 是否在 enrollment 時建立本 client 的 authoritative DNS A/AAAA record（C11）；未設時 effective 值繼承 selected FreeIPA server 的 `freeipa_setup_dns` | 否（有 effective default）|
| `freeipa_client_dns_addresses` | 明確指定要寫入 DNS 的 address list（IPv4/IPv6 皆可）；未設時 fallback 為 `ansible_default_ipv4.address` | 否（有 fallback）|
| `freeipa_client_dns_replace_from_address` | Day-2 IP 遷移的 expected-old CAS token（單次授權，非永久 allow-flag）；未設時任何 authoritative extra 依然 fail-closed（見 §0 v1.5 / §9）| 否（不設 = 無 replacement 授權）|
| `freeipa_client_sssd_password_expiry_policy` | 非密碼登入（SSH key、GSSAPI）時對已過期 FreeIPA 密碼的處理，寫進 SSSD domain 的 `ipa_access_order`：`warn`（照常登入）、`renew`（登入前要求改密碼）、`off`（寫回 `expire`）；**未設定就不動** sssd.conf。`warn`／`renew` 下從沒設過密碼的帳號會被拒絕（C17）。只支援 Ubuntu 24.04（C13–C17）。`renew` 另在 `[pam]` 寫 `pam_initgroups_scheme = always`（C19／C20）；`warn`／`off` 會移除值剛好是 `always` 的那一行 | 否（未設 = 不動）|
| `freeipa_client_sssd_password_expiry_warning_days` | `warn`／`renew` 時寫入 SSSD domain 的 `pwd_expiration_warning`（天，1–30）；未設時 14 | 否（有預設）|

> Realm 後綴 DN：`ipa.pilot.internal` → `dc=ipa,dc=pilot,dc=internal`。
> `ipa_domain` / `ipa_realm` / `ipa_server_fqdn` **必須**與 `freeipa-server.md` §1.5 完全一致，否則 enroll 失敗。


Inventory 輸入由各元件 contract 的 `groupVars` 檢查。FreeIPA 的 `ipa_*` realm/server/DNS 別名由上述 `freeipa_*` 輸入推導；既有單次 `-e` 別名覆寫仍相容，不是 inventory 的設定介面。

## 1.6 衍生值與檔案資料（非 inventory 輸入）

| 欄位 | 說明 | 是否必填 |
|---|---|---|
| `pilot_annotations` | 描述性、非機密的 host metadata（`location`/`project`/`owner`/…），由 `hosts.yml` 的 `annotations:` 經 `pilot inventory generate` 投影而來；enrollment/health 成功後投影到 FreeIPA `userClass`（`pilot.annotation.<key>=<value>`）與（`location` 專用）`nshostlocation`；**沒有對應的 checklist row**——投影結果需要已認證的 `ipa` 查詢才能讀到，這份 spec 既有的 C1–C11 刻意全部只讀本機檔案/服務，不需要 Kerberos ticket，annotations 因此改由 apply 本身的 Phase F 內建讀回驗證取代（見 §6/§9 v1.6）| 否（未設 = 空 dict，等同不使用此功能）|

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
| C12 | authn    | SSH client 對本 realm 網域已開啟 GSSAPI ticket delegation（供跳板機停用密碼登入後仍可 relay） | 0 | sh -c 'ssh -G dummy.ipa.pilot.internal 2>&1 | grep -qi "^gssapidelegatecredentials yes$"' |
| C13 | pwexpiry | `ipa_access_order` 是 Pilot 寫的形式（沒有這行、`expire`、`expire, pwd_expire_policy_warn`、`expire, pwd_expire_policy_renew`），sssd.conf 恰好一個 domain section、這行最多一行 | 0 | sudo awk 'BEGIN{d=0;n=0} /^\[domain\//{d++} /^ipa_access_order[ \t]*=/{n++; v=$0; sub(/^[^=]*=[ \t]*/, "", v)} END{exit !(d == 1 && n <= 1 && (n == 0 || v ~ /^expire(, pwd_expire_policy_(warn|renew))?$/))}' /etc/sssd/sssd.conf |
| C14 | pwexpiry | 執行中的 SSSD 已載入檔案裡的 `ipa_access_order`（confdb 與 sssd.conf 一致；改了檔沒重啟會 FAIL） | 0 | sudo sh -c 'f=$(sed -n "s/^ipa_access_order *= *//p" /etc/sssd/sssd.conf); c=$(ldbsearch -H /var/lib/sss/db/config.ldb -b cn=domain,cn=config -s one ipa_access_order 2>/dev/null | sed -n "s/^ipa_access_order: //p"); [ "$f" = "$c" ]' |
| C15 | pwexpiry | 密碼已過期的 fixture 帳號 `pilot-pwexpired`：`renew` 時 PAM account 要求新密碼，其他設定照常通過 | 0 | sudo sh -c 'v=$(sed -n "s/^ipa_access_order *= *//p" /etc/sssd/sssd.conf); case "$v" in *pwd_expire_policy_renew*) w="new one required";; *) w="pam_acct_mgmt: Success";; esac; sssctl user-checks -a acct -s sshd pilot-pwexpired 2>&1 | grep -qF "$w"' |
| C16 | pwexpiry | 密碼有效（到期日在未來）的 fixture 帳號 `pilot-pwvalid`：任何設定下 PAM account 都通過 | 0 | sudo sh -c 'sssctl user-checks -a acct -s sshd pilot-pwvalid 2>&1 | grep -qF "pam_acct_mgmt: Success"' |
| C17 | pwexpiry | 從沒設過密碼的 fixture 帳號 `pilot-nopw`：設了 `pwd_expire_policy_*` 時被拒絕（System error），否則通過 | 0 | sudo sh -c 'v=$(sed -n "s/^ipa_access_order *= *//p" /etc/sssd/sssd.conf); case "$v" in *pwd_expire_policy_*) w="pam_acct_mgmt: System error";; *) w="pam_acct_mgmt: Success";; esac; sssctl user-checks -a acct -s sshd pilot-nopw 2>&1 | grep -qF "$w"' |
| C18 | pwexpiry | sshd 有效設定 `UsePAM yes`（密碼過期的處理靠 sshd 的 PAM account） | 0 | sh -c 'sudo sshd -T 2>/dev/null | grep -qi "^usepam yes$"' |
| C19 | pwexpiry | `pam_initgroups_scheme = always` 只在 `renew` 時出現：`ipa_access_order` 含 `pwd_expire_policy_renew` 時 sssd.conf 恰好有一行 `pam_initgroups_scheme`、而且值是 `always`；其他政策（未設定、`warn`、`expire`）下沒有值為 `always` 的那一行 | 0 | sudo sh -c 'v=$(sed -n "s/^ipa_access_order *= *//p" /etc/sssd/sssd.conf); a=$(grep -c "^pam_initgroups_scheme *= *always *$" /etc/sssd/sssd.conf); n=$(grep -c "^pam_initgroups_scheme" /etc/sssd/sssd.conf); case "$v" in *pwd_expire_policy_renew*) [ "$a" = 1 ] && [ "$n" = 1 ];; *) [ "$a" = 0 ];; esac' |
| C20 | pwexpiry | 執行中的 SSSD 已載入檔案裡的 `pam_initgroups_scheme`（confdb `cn=pam,cn=config` 與 sssd.conf 一致；改了檔沒重啟會 FAIL） | 0 | sudo sh -c 'f=$(sed -n "s/^pam_initgroups_scheme *= *//p" /etc/sssd/sssd.conf); c=$(ldbsearch -H /var/lib/sss/db/config.ldb -b cn=pam,cn=config -s base pam_initgroups_scheme 2>/dev/null | sed -n "s/^pam_initgroups_scheme: //p"); [ "$f" = "$c" ]' |

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
>
> **C13–C18（v1.14，密碼過期政策）**：
> - **跟著主機當下的設定判斷**：`freeipa_client_sssd_password_expiry_policy` 未設定時 Pilot 不動
>   sssd.conf，所以 C15／C17 先讀 `ipa_access_order` 再決定要比對哪個結果。未啟用的主機（`ipa_access_order`
>   不存在或是 `expire`）全部 PASS。C13 只接受 Pilot 會寫的形式；手動寫了 `pwd_expire_policy_reject`
>   或其他值的主機會 FAIL（2026-11-05 實測），因為 Pilot 不知道那台主機的政策是誰定的。
> - **C14 讀的是執行中的設定**：SSSD 啟動時把 sssd.conf 載入 `/var/lib/sss/db/config.ldb`。實測改了
>   sssd.conf 但沒重啟時，confdb 仍是舊值（C14、C15、C17 FAIL）；重啟後才變成
>   `ipa_access_order: expire, pwd_expire_policy_renew`。只讀檔案的檢查抓不到「寫了但沒生效」。
> - **`sssctl user-checks` 的結果在 stderr，結束碼永遠是 0**：`pam_acct_mgmt: …` 那一行印在 stderr，
>   被拒絕時 rc 也是 0（2026-11-05 實測），所以 C15–C17 一律 `2>&1 | grep -qF`，用 grep 的 rc 判斷。
>   實測的三種結果字串：`pam_acct_mgmt: Success`、`pam_acct_mgmt: Authentication token is no longer valid; new one required`、
>   `pam_acct_mgmt: System error`。`sssctl user-checks -s sshd` 走 `/etc/pam.d/sshd` 的 account stack
>   （Ubuntu 的 `common-account` 裡的 `pam_sss`），跟 sshd 走的是同一段。
> - **C17 鎖的是限制，不是功能**：SSSD 對 IPA 帳號固定用 MIT Kerberos 密碼政策，SSSD 快取裡沒有
>   `krbLastPwdChange`（帳號從沒設過密碼）時直接拒絕（SSSD 2.9.4 `ldap_auth.c` 的
>   `find_password_expiration_attributes()`；log：`No Kerberos password expiration attributes found, but
>   MIT Kerberos password policy was requested. Access will be denied.`）。實測 `warn` 與 `renew` 都一樣，
>   sshd 記 `Access denied for user pilot-nopw: 4 (System error)`。所以啟用前，主機上能登入的 FreeIPA
>   帳號都必須設過密碼（含 login canary）。`pilot spec --lint` 對 C17 的「reverse-logic grep」warning
>   是誤判：`System error` 在 `warn`／`renew` 下是**預期**結果，grep 命中回 0；健康路徑一律 rc 0
>   （§3 v1.14 四種狀態都 PASS），不是「健康時 grep 找不到」的反邏輯。
> - **C15–C17 依賴 fixture 帳號**：`pilot-pwexpired`（管理員 reset 過、還沒自己改：
>   `krbPasswordExpiration` = `krbLastPwdChange`）、`pilot-pwvalid`（有密碼，`--password-expiration`
>   設在遠未來）、`pilot-nopw`（沒有密碼），三者都要被 HBAC 允許登入本機。fixture playbook 待新增
>   （§5、§7）。實測 client 的 SSSD 快取讀得到 `krbLastPwdChange`／`krbPasswordExpiration`，這是整個
>   功能的前提。
> - **C18**：`renew` 要靠 sshd 呼叫 PAM account 才會觸發；`UsePAM no` 時 sshd 不走 PAM，政策完全
>   無效。用 `sshd -T` 讀合併 `sshd_config.d` 後的有效值，不讀單一檔案。

## 3. 證據收集

- 工具：`pilot vm-target verify --name <ubuntu-vm> docs/verification/freeipa-client.md`
  （真實主機：`pilot verify docs/verification/freeipa-client.md -i inventory-freeipa.yaml`）
- 格式：`.verification/freeipa-client-<UTC>.{ndjson,md}`
- 預期 row 數：18

> **C19–C20（v1.16，`pam_initgroups_scheme`）**：
> - **為什麼要寫它**：SSSD 2.9.4 的 PAM responder 只有在「沒有 5 秒的 initgr 快取項目、而且使用者沒有 session」時才
>   向後端重讀使用者（預設 `pam_initgroups_scheme = no_session`）。過期密碼的 TTY 登入在跑 `passwd` 前就開了 PAM
>   session，結束時的 `CLOSE_SESSION` 又重新啟動 5 秒窗口，所以反覆互動重試會一直讀到快取裡過期的到期時間
>   （改完密碼仍被擋，一般 client 實測 3 輪都超過 240 秒；#262）；使用者有任何開著的 session 時，管理員 reset 也要等
>   session 結束才被發現（實測 100.5 秒，gateway 52–59 秒；#263）。`always` 讓每個 PAM 請求（5 秒窗口之外）都重讀。
> - **只在 `renew` 寫**：`warn`／`off`／未設定都不需要強制改密碼，所以不改 PAM responder 的快取行為；從 `renew` 改回
>   `warn`／`off` 時只移除值剛好是 `always` 的那一行（其他值視為操作者自己的設定，不碰）。
> - **C19 判斷依 `ipa_access_order`**：沿用 C15／C17 的寫法，未啟用 `renew` 的主機若手動寫了 `always` 會 FAIL，因為
>   Pilot 不知道那是誰定的。
> - **C20 讀執行中的設定**：同 C14，檔案改了沒重啟 FAIL。

> **C11 evidence 狀態：已於 2026-08-21 live 驗證**（下方 v1.3 區塊）。
> **C13–C18 狀態：row 指令與 apply／fixture playbook 已實跑（下方 v1.14 區塊、§0），正式 evidence 尚未完成。**

**v1.14 row 指令實測（2026-11-05，不是 evidence chain）**：拋棄式 topology `pwx-ipa`（AlmaLinux 9，
`freeipa-server-apply.yml`）+ `pwx-cli`（Ubuntu 24.04.4，SSSD 2.9.4，OpenSSH 9.6p1，
`freeipa-client-apply.yml` enroll，`PLAY RECAP … failed=0`）。fixture 帳號手動建立（`ipa user-add`、
`ipa user-mod --random`、`--password-expiration=20991231000000Z`），政策以手動修改 sssd.conf + 重啟
SSSD 模擬。每一列以 `pilot verify --probe '<command>' --probe-expected 0 -i <inventory> -l pwx-cli`
執行：

| 狀態 | C13 | C14 | C15 | C16 | C17 | C18 |
|---|---|---|---|---|---|---|
| 未設定（enroll 後的原樣） | PASS | PASS | PASS | PASS | PASS | PASS |
| `expire, pwd_expire_policy_warn` | PASS | PASS | PASS | PASS | PASS | PASS |
| `expire, pwd_expire_policy_renew` | PASS | PASS | PASS | PASS | PASS | PASS |
| `expire`（`off`） | PASS | PASS | PASS | PASS | PASS | PASS |
| 檔案改成 `renew`、SSSD 沒重啟 | PASS | **FAIL** | **FAIL** | — | **FAIL** | — |
| `expire, pwd_expire_policy_reject`（不是 Pilot 寫的值） | **FAIL** | — | **FAIL** | — | — | — |
| `ipa_access_order` 出現兩行 | **FAIL** | — | — | — | — | — |
| `pilot-pwvalid` 的到期日改到過去（`renew`） | — | — | — | **FAIL** | — | — |
| `sshd_config.d` 加上 `UsePAM no`（只讀 `sshd -T`，sshd 未 reload） | — | — | — | — | — | **FAIL** |

**v1.16 C19／C20 row 指令實測（2026-11-05，用 `pilot verify --probe` 對真實 Ubuntu 24.04 client，SSSD 2.9.4）**：

| 狀態 | C19 | C20 |
|---|---|---|
| 未設定（沒有任何這兩行） | PASS | PASS |
| `off`（`expire`，沒有 `pam_initgroups_scheme`） | PASS | PASS |
| `warn`（沒有 `pam_initgroups_scheme`） | PASS | PASS |
| `renew` + `pam_initgroups_scheme = always`，已重啟 | PASS | PASS |
| `renew`，沒有 `pam_initgroups_scheme` | **FAIL** | PASS |
| `renew` + `no_session` | **FAIL** | PASS |
| `off` + `always`（殘留） | **FAIL** | PASS |
| `renew` + `always`，檔案改了但 SSSD 沒重啟 | PASS | **FAIL** |

C20 在重啟後約 3 秒內曾失敗兩次，之後同樣狀態的 12 次探測全部通過，所以 playbook 重啟後的比對最多重試 5 次、間隔 2 秒。

FAIL 都是 `rc=2, expected 0`（ad-hoc runner 對非 0 結束碼回報 rc=2）。同一次也確認了 sshd 的實際行為
（不是 checklist row，供 apply／runbook 使用）：`renew` 下密碼已過期的帳號用 key 登入時，
`BatchMode`／沒有 TTY 印 `WARNING: Your password has expired.` + `Password change required but no TTY
available.` 並以 rc=1 結束，遠端命令沒有執行；`ssh -tt` 時 sshd 改跑 `passwd`（`You must change your
password now and login again!` → `Current Password:` → `New password:` → `Retype new password:` →
`passwd: password updated successfully`），結束後斷線，FreeIPA 的 `krbPasswordExpiration` 變成 90 天後；
`sftp` rc=255；`warn` 下照常登入。

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
  - C13 fail → `ipa_access_order` 不是 Pilot 寫的值、出現多行，或 sssd.conf 有不只一個 domain section：
    查 `sudo grep -n "^\[domain/\|^ipa_access_order" /etc/sssd/sssd.conf`。不是 Pilot 寫的值要先決定
    這台主機的政策：設 `freeipa_client_sssd_password_expiry_policy` 讓 apply 接手，或手動移除那一行。
  - C14 fail → sssd.conf 改了但 SSSD 沒重啟：重跑 apply（帶 C13／C14 的 tag 時也會重啟），不要只靠手動
    `systemctl restart sssd` 收尾，那代表 apply 的重啟條件有 bug。
  - C19 fail → `renew` 的主機沒有 `pam_initgroups_scheme = always`（或值是別的），或沒啟用 `renew` 的主機卻有 `always`：
    查 `sudo grep -n "^\[pam\]\|^pam_initgroups_scheme" /etc/sssd/sssd.conf`；重跑 apply 讓政策接手。
  - C20 fail → 檔案與執行中的 SSSD 不一致：重跑 apply（帶 C19／C20 的 tag 時也會重啟），不要只靠手動 `systemctl restart`。
  - C15 fail → 先看 C14；C14 PASS 時，確認 `pilot-pwexpired` 仍是過期狀態（有人用它登入並改過密碼後
    就不再過期：重跑 fixture）與 HBAC 允許它登入本機。
  - C16 fail → `pilot-pwvalid` 的到期日過了或 HBAC 擋下：重跑 fixture。
  - C17 fail → 先看 C14；設了 `pwd_expire_policy_*` 卻回 `Success` 代表 `pilot-nopw` 其實有密碼（fixture
    被改過），沒設卻被拒絕代表 HBAC 擋下或帳號停用。
  - C18 fail → `sudo sshd -T | grep -i usepam`，找出設成 `no` 的 `sshd_config.d` 檔案。

## 5. 例外與已知偏差

| ID  | 例外內容 | 適用環境 | 期限 |
|-----|---------|---------|------|
| C4/C6/C10 | 若 target 無 passwordless sudo，這幾條（讀 root-only 檔 / `auditctl`）需改由具 root 的方式跑，或標為 `skip` 並改用其他佐證（如 apply 完成後已記錄之 §3 健康態）| 無 passwordless sudo 的站台 | 永久 |
| C8  | 若 server 端尚未建立 `pilot-all` sudo 規則（§7.2），本 row 會 fail。純驗證「client 授權管道通不通」時，可改標 `skip` 並改用任一已存在的 IPA sudo 規則對應的帳號。`sudo -l -U` 必須以 root 執行，見 §2 C8 備註。| 尚未建 sudo 規則的站台 | 依站台 |
| C9/C10 | auditd 屬「本機稽核」補強，非 FreeIPA 元件；若站台以其他集中式稽核（如轉送 KDC/系統日誌到 SIEM）取代，可標 `skip` 並在文件註明替代來源 | 有替代稽核方案的站台 | 依站台 |
| C11 | 若 `freeipa_client_register_dns` effective 值為 `false`（selected FreeIPA server 未啟用 native DNS），本 row 預期 fail（authoritative DNS 本來就不會有這筆 record）；應改標 `skip`，佐證改用 apply 輸出的 `FreeIPA client DNS plan: registration: DISABLED`（spec.md §13.2）debug 訊息 | selected server `freeipa_setup_dns=false` 的站台 | 永久 |
| —   | 本 spec 的 NTP 部分不含獨立 row：`--no-ntp`，時間同步交給既有 `ntp` role（見 §1）| 全部 | 永久 |
| C15–C17 | 依賴三個 fixture 帳號（`pilot-pwexpired`／`pilot-pwvalid`／`pilot-nopw`，§2 C13–C18 備註）。沒有跑過 fixture 的站台這三列會 FAIL（帳號不存在），可標 `skip`；正式環境不要建立這三個帳號以外的測試帳號來代替。| 沒有跑 fixture 的站台 | 依站台 |
| C19 | `renew` 下改完密碼後重新登入：非互動式重試約 3–4 秒就恢復；`pam_initgroups_scheme = always`（v1.16）之前，只用 TTY 重試的使用者可能被擋數分鐘（#262），有了它以後在實測中第二次嘗試（約 10 秒）就成功。管理員 reset 在使用者有開著的 session 時也會在 1.4 秒內被發現（#263）。代價（每個 PAM 請求多一次後端使用者與群組查詢）與 FreeIPA 不可達時的行為見 evidence；不要用清快取當修法（AGENTS.md §5.9）| `renew` 的主機 | 永久（SSSD 行為）|

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
| C12     | `/etc/ssh/ssh_config.d/05-freeipa-client-gssapi-delegate.conf`（`copy`，`Host *.{{ ipa_domain }}` 區塊開 `GSSAPIAuthentication`/`GSSAPIDelegateCredentials yes`）| 純 client-side 設定檔，無對應 service 需重啟；`ipa-client-install` 自己的 `04-ipa.conf` 從不動這兩個選項 |
| C13     | `freeipa-client-apply.yml` 的 block：快照 sssd.conf → preflight（恰好一個 `[domain/`、`access_provider = ipa`、`ipa_access_order` 最多一行且是已知形式、`pwd_expiration_warning` 最多一行）→ `lineinfile` 整行寫入 `ipa_access_order`（`warn`／`renew` 另寫 `pwd_expiration_warning`，`insertafter: '^ipa_domain\s*='`）→ `sssctl config-check`；失敗由 rescue（`always`）還原快照。輸入檢查（值、Ubuntu 24.04、`renew` 不在 gateway／directory／target-policy 主機、天數 1–30）是 `always` 的 pre_tasks，在任何修改之前 | 未設定時完全不碰 sssd.conf |
| C14     | 既有的「restart SSSD after wiring responders」task 加上 `C13`／`C14`／`sssd_hardening` 的 tag，`when:` 改讀 `(x \| default({})) is changed`，並在 confdb 與檔案不一致（drift 檢查 rc=1）時也重啟；重啟後的 block 再確認 SSSD active、`sssctl config-check`、confdb 與檔案一致，不一致就還原快照、重啟 SSSD 並讓 run 失敗 | 既有 bug 的修正：`sssd_hardening` 的 task 改了 sssd.conf，但 restart 原本只標 `C8`，`--tags sssd_hardening` 從不重啟 |
| C19     | `freeipa-client-apply.yml` 同一個 C13 block：preflight 另要求恰好一個 `[pam]` 區塊、`pam_initgroups_scheme` 最多一行且值是 `always` 或 `no_session`；`renew` 時用 `lineinfile` 整行寫入 `pam_initgroups_scheme = always`（`insertafter: '^\[pam\]\s*$'`），`warn`／`off` 時只移除值剛好是 `always` 的那一行；寫入失敗由同一個 rescue 還原快照 | 未設定時不碰；`renew` 之外的政策不寫入 |
| C20     | restart 的 `when:` 讀這個 register 的 `is changed`；confdb drift 檢查與重啟後的檢查同時比對 `cn=pam,cn=config` 的 `pam_initgroups_scheme`（重啟後最多重試 5 次，每次隔 2 秒，因為 SSSD 剛啟動時 confdb 可能還沒寫完）；不一致就還原快照、重啟並讓 run 失敗 | 與 C14 同一個 tag 機制 |
| C15–C17 | verify-only：fixture 帳號的 PAM account 結果，對應的 mutation 是 C13／C14 | `playbooks/test/fixtures/freeipa-client-pwexpiry-fixtures.yml`（經 `freeipa-client-fixtures.yml` 建帳號，再用 `ipa user-mod --random`／`--password-expiration` 造出狀態；只對還沒有密碼的帳號寫入，重跑 `changed=0`）|
| C18     | verify-only：`UsePAM yes` 是 Ubuntu 的 sshd 預設，本 playbook 不寫 | 只確認沒有被其他 drop-in 關掉 |
> Apply playbook 用 `block/rescue`：enroll/health 失敗時 rescue 收 `sssctl domain-status` +
> `ipaclient-install.log` 便於除錯；`pre_tasks: assert` 對 `ipa_admin_password` / `ipa_server_ip`
> 做 mandatory gate、對 OS（Debian/RedHat）與 staging/prod 做 gate。

**Host annotations（v1.6，不是 checklist row）**：enrollment/health 成功 + DNS apply/verify 之後，
`tasks/freeipa-host-annotations.yml` 被 include 一次。Phase A 用內嵌 python3 重驗
`pilot_annotations`（key/value contract、secret-name gate、256-byte userClass 序列化上限）；
Phase B admin-kinit + `ipa host-show --all --raw`（`check_mode: false`，未 OS-enrolled 時先做
`/etc/ipa/default.conf` stat gate，避免對未 enroll 的全新 host 嘗試 kinit）；Phase C/D 用另一支
內嵌 python3 解析 live `userClass`（case-insensitive `pilot.annotation.` prefix 判斷
Pilot-owned vs foreign，duplicate/malformed 直接 fail-closed）並算出 add/delete 與
`nshostlocation` ownership/adoption 決策；Phase E 依序 `--delattr=userclass=` →
`--addattr=userclass=` → native location `--setattr`/`--delattr=nshostlocation=`
（`not ansible_check_mode` 逐一 gate，`--check` 只讀不寫）；Phase F 只在本次真的有 mutation 時
re-read 並三向驗證（desired 全部落地 + foreign 全部存活 + native location 精確相符）。
沒有對應的 C-number checklist row——`pilot verify` 的 ad-hoc SSH 探針不帶 Kerberos ticket，
無法直接 `ipa host-show`（實測 `ipa: ERROR: did not receive Kerberos credentials`），這份 spec
既有 C1–C11 刻意全部只讀本機檔案/服務正是為了避開這個限制；Phase F 內建讀回驗證取代了
checklist row 的角色。真機證據見 §9 v1.6 變更紀錄（spec.md §26 L1-L13 全數 live 通過）。

**Host annotations / access policy 的名稱解析前置檢查（v1.13，不是 checklist row）**：上面兩個
reconcile 的 admin `kinit` 讀的是**主機當下的解析狀態**——MIT `kinit` 用 glibc `getaddrinfo` 解析
`/etc/krb5.conf` 的 KDC 名稱，解析不到時在送出任何封包前就失敗（stderr 與「KDC 連不上」完全相同，
KDC 日誌也看不到請求）。修復它的 `/etc/hosts` server-pool pin 是 mutation，`--check` 不會寫入，
所以 resolver 被改過的主機（例：DNS 清單含公共 DNS、FreeIPA DNS 沒回應）過去在 preview 就以
`no_log` 遮蔽的訊息失敗（issue #168）。現在兩個 task 檔在 kinit 之前、已 enroll 才 include 共用的
`tasks/freeipa-client-kdc-preflight.yml`（唯讀、`check_mode: false`、有 `timeout`）：

- 用主機自己的 resolver（`socket.getaddrinfo`，與 kinit/`ipa` 同一條 libc 路徑）解析 realm stanza
  （`/etc/krb5.conf` 與 `krb5.conf.d`，含 `includedir`）的 KDC 名稱、選定的 admin endpoint FQDN 與
  FreeIPA server pool FQDN。**必要名稱**有兩種：(a) admin endpoint FQDN（`ipa -e xmlrpc_uri=…` 要用；
  輸出 `admin_unresolved`）；(b) 「沒有任何 `kdc` 名稱解析得到」（`kdc_unusable`：有 kdc 名稱、
  沒有 IP literal 的 KDC、且全部解析不到）時的 KDC 名稱。kinit 只要**任一** KDC 名稱可解析就能運作
  （OR，不是 AND），所以多餘的舊 KDC 名稱只印提示、不失敗。`master_kdc` 不是初始 AS exchange 的
  KDC 清單，**不計入**（可解析的 `master_kdc` 不得遮住已死的 `kdc` 清單；不可解析的 `master_kdc`
  也不使可用的 `kdc` 變成必要），與 `admin_server`／`kpasswd_server` 一樣只回報、不要求。
- **KDC 值的解析契約**（對 MIT libkrb5 1.22.x 以 `profile_get_values` 與 kinit `KRB5_TRACE` 實測；
  EL9 的 1.21.1、Ubuntu 24.04 的 1.20.1 未逐一重跑）：先依 profile 層解碼——以 `"` 開頭的值會處理
  跳脫（`\n \t \b`，其他 `\x` 為 `x`）直到結尾引號、引號之後的文字丟棄、沒結尾的引號延伸到行尾；
  未加引號的值照原樣，值內的 `#`／`;` **不是**註解——再取**第一個空白分隔的 token** 當 host，然後
  拆 `host:port`、`[v6]` 或 `[v6]:port`、`https://host[:port]/path`；`tcp/`、`udp/` 前綴**不剝除**
  （libkrb5 照字面查）；逗號不分隔。libkrb5 會拒絕（kinit 以 `Invalid argument` 結束）的值——
  沒有方括號的兩個以上冒號、非數字或超過 65535 的 port、空 host、沒結尾的 `[`、`http://`——不會被
  當成名稱探測，改列在 `unparsable` 並印提示。`kdc = "localhost:88"` 因此與 `kdc = localhost:88`
  結果相同。區段與 include 也依 libkrb5 判讀（以真實 kinit 1.22.2 逐項實測，擷取在同一份 fixture 的
  `structure_rows`）：子區段只在值剛好是 `{`（`kdc = h1{` 是普通值）或單獨一行 `{` 時開啟，以 `}` 開頭的行
  （可接註解或其他文字）關閉；`Realm =` 的 `{` 可以在下一行；`includedir` 讀 `*.conf` 與無副檔名的檔案、
  跳過 dot-file；`include` 只有在第 0 欄才會被跟隨（縮排的 `include` 不跟隨）；`[realms]` 區段標頭在第 0 欄
  永遠有效，縮排的標頭只有在前面已經有某個區段開著時才被接受（檔案第一個區段就縮排、或只有註解在前，
  libkrb5 會忽略它）；檔案以 `errors='replace'` 讀取。libkrb5 在整個 profile 載入失敗（例如縮排 `include`
  之前已有區段時 kinit 報設定檔錯誤）的情況，probe 無法模擬，只會讀不到該檔。
  比對用小寫並去掉結尾的 `.`（探測的名稱本身也去掉結尾的點）。
- 狀態 `freeipa_client_kdc_preflight_state`：`ok`；`deferred`（**只**在 `--check`、pin 這個 task 本次
  會變更（`freeipa_client_hosts_pool_pin` is changed）、且 pin 讓 kinit 與 FreeIPA 讀取需要的名稱
  可解析時：`kdc_unusable` 的話至少**一個**解析不到的 KDC 名稱是 pool 成員（`kdc_names ∩ pool ≠ ∅`），
  且每個解析不到的 admin endpoint 都是 pool 成員）——呼叫端略過整段依賴 kinit 的讀取，印出
  「annotations/access policy 延後到 apply：`<host>` 解析不到 `<名稱>`（resolver: `<list>`）；pin 會讓
  `<KDC∩pool 名稱>`［與 admin endpoint `<fqdn>`］可解析，這就是 kinit 與 FreeIPA 讀取需要的；krb5.conf
  裡其他過時的 KDC 名稱留給 apply 的 server-list reconciliation」，apply 會先寫 pin 再 reconcile
  （pin 在 playbook 裡早於這兩個 include）；其餘解析不到的情況一律 `failed`：assert 明說 `<host>`
  解析不到哪些 FQDN、resolver 清單（`/etc/resolv.conf` 加 `resolvectl dns`）與可能原因（沒有待變更的
  pin／pin 只釘 pool 成員（列出 pool），而 krb5.conf 的 KDC 名稱沒有任何一個是 pool 成員、或 admin
  endpoint 不是 pool 成員／pin 已套用仍解析不到），**不遮蔽**（此檔沒有 secret，不用 `no_log`）。
  真實 run 永遠不會 deferred。
- **preview 不預測 failover reconciliation**：真實 apply 的 `freeipa-client-server-failover.yml` 會把
  realm 檔改寫成 active pool、並移除已退役的 KDC 名稱，但它在 `--check` 下被跳過，preview 也**不**預測
  這個移除。因此「krb5.conf 列出的每個 KDC 都在 pool 之外」（retired-only）的主機在 preview 仍會
  `failed`（`not_covered_by_pin`），訊息明說 preview 不預測該 reconciliation，而不是斷言 apply 無法
  修復；失敗訊息也不把「kinit 一定失敗」當成確定事實（SSSD 的 KDC locator 可能不經名稱查詢就提供 KDC
  位址）：寫成 kinit 可能失敗、preview 把它當成風險而 fail closed；要通過 preview 請修 resolver、`/etc/hosts` 或 krb5.conf 裡過時的名稱。這是已知限制，不嘗試預測。
- 限制：`--tags host-annotations`／`--tags host-access-policy` 不會執行 pin task（tag 是
  `freeipa-client`、`C3`），pin 的 register 不存在，視為「沒有待變更的 pin」，所以這種 `--check`
  在名稱解析不到時**明確失敗**而不是 deferred。
- admin `kinit` 本身改成 `command` + `stdin`（原本是 shell `printf %s "{{ ipa_enroll_password }}" | kinit`，
  密碼裡的 `$`、反引號會被 shell 展開；#118 清單移除這一項），不再讓 task 直接失敗：它 `register`
  結果，交給共用的 `tasks/freeipa-client-kinit-result.yml` 只用結束碼與 stderr 分類——
  `cannot_resolve`／`cannot_contact_kdc`／`preauth_failed`／`client_not_found`／`clock_skew`／`other`——
  再以固定文字失敗（類別、principal、主機、kinit rc；**絕不輸出原始 stderr**，分類 task 是
  `no_log`）。同一個 stderr（`Cannot contact any KDC for realm …`）同時代表「名稱解析不到」與「KDC
  port 沒人聽」（MIT krb5 1.22.2 實測），所以只在 preflight 有**必要**名稱解析不到（`required_unresolved`）時才歸 `cannot_resolve`；kinit 用不到的過時名稱（另一個 KDC 可解析）不算證據，port 不通仍是 `cannot_contact_kdc`。
  access policy 的 kinit 同樣修正（它原本已是 stdin，但失敗一樣被遮蔽）。
- 不在此次範圍：resolver 偏離偵測（`freeipa-dns-client`／`pilot doctor`／`~domain` routing）另開 issue；
  沒有新的 C-number row（理由同 annotations：`pilot verify` 探針沒有 Kerberos ticket）。
  驗證：`internal/spec/freeipa_client_kdc_preflight_regression_test.go`（以真 python3 跑探針、以真
  `ansible-playbook` 跑 `check × pin pending × pin 涵蓋` 狀態機與 kinit 分類、fixture 來自本機真實
  MIT kinit 1.22.2 擷取，無法在本機重現的 libkrb5 訊息有明確標示不是 live capture）。vm-target 實跑
  （AlmaLinux 9 FreeIPA server + Ubuntu 24.04 client，resolver 被改過、`/etc/hosts` pin 被移除；
  healthy baseline L3→L6、drift 的 `--check` deferred／`--tags` 明確失敗／real apply 自行修復、錯誤
  密碼與 KDC 不通的分類、stale+active KDC 延後與 retired-only 失敗、帶引號的 KDC 值、Ubuntu 1.20.1／EL9
  1.21.1 的 libkrb5 解析交叉檢查）見
  [`docs/evidence/freeipa-client/2026-10-29-9e9f2b3e.md`](../evidence/freeipa-client/2026-10-29-9e9f2b3e.md)；
  `Clock skew too great` 無法在 live 重現。OR 規則與 KDC 值解析契約（含 libkrb5 實測擷取
  `internal/spec/testdata/kdc-preflight/libkrb5-kdc-values.json`）由上面的 regression test 鎖住，
  live 驗證以 evidence 記錄的 tested revision 為準。

**Host access policy（v1.9，不是 checklist row）**：annotations 之後，
`tasks/freeipa-host-access-policy.yml` 被 include 一次（兩個 include 都以 `apply: tags` 把
tag 帶進被 include 的 task）。它把 `pilot_ssh_recording`（`hosts.yml` 的 `ssh_recording:`
經 `pilot inventory generate` 產生）投影成 FreeIPA host 上**恰好一個** userClass 值
`pilot.policy.ssh-recording=<off|terminal_output>`；未定義時代表沿用 gateway 預設，並移除既有的
managed 值。Phase A 在任何 live read 前驗證 `pilot_ssh_recording` 必須是字串 `off`/`terminal_output`
（手改 inventory.yml 的未加引號 `off` 會被 Ansible 解析成 boolean，直接 fail）；Phase B 以
`command` + `stdin` 做 admin kinit（`no_log`）後 `ipa host-show --all --raw`，失敗時區分
`HOST_ABSENT` 與 `FREEIPA_UNREACHABLE`；Phase C/D 以內嵌 python3 依 case-insensitive prefix 分出
managed/foreign，duplicate/malformed/unknown（含保留值 `terminal_io`）一律在 mutation 前
fail-closed，不自動刪除；Phase E 只用 `--delattr`/`--addattr`；Phase F 只在有 mutation 時讀回，
驗證 managed 值**完全等於** desired、foreign 值（含 annotations）完全不變。與 annotations 相同，
沒有 C-number row（`pilot verify` 探針沒有 Kerberos ticket）；取而代之的是 Phase F 內建讀回、
`internal/spec/freeipa_host_access_policy_regression_test.go`（靜態不變量 + 以 python3 實跑
plan script 的 reconcile matrix + Phase 0 真實擷取的 fixture），以及 live evidence
（per-host recording spec §35 的 L2、L6、L7、L9–L11、L17）。設計與決策見
`docs/superpowers/specs/2026-09-23-pilot-access-gateway-per-host-session-recording-spec.md` §7、§8。

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
| 2026-09-14 | v1.7 | 修正真實事件：host `x64-deliver-bbq` 上一個與 freeipa-client 無關的第三方（HashiCorp）APT repository 出現 `NO_PUBKEY FC9CA96ACA026560`，但 C1/C8 的 `ansible.builtin.apt` 安裝 task 當時綁死 `update_cache: true`（刷新*全部* configured APT source），導致該無關 repo 壞掉直接讓 `freeipa-client`（Ubuntu archive 本身健康、可正常安裝）整段 fatal。改成 C1/C8 都改走新建的共用 task `playbooks/apply/tasks/apt-package-install.yml`（cache-first：先查已裝/已有 candidate 才決定要不要 refresh；不足才 best-effort 全域 refresh；仍不足則只 scoped-refresh 宣告的 required source，即 Ubuntu 官方 archive，不碰使用者的第三方 repo 檔案），required source（Ubuntu archive）本身壞掉仍然 fatal，signature 驗證全程不降級（無 `trusted=yes`/`allow_unauthenticated`）。詳細 policy 語意、failure classification、scoped-refresh 機制、安全不變量見新增的 `docs/verification/apt-repository-tolerance.md`。Go 測試新增 `TestAptUpdateCacheAllowlist`（ratchet：偵測 `playbooks/apply/*.yml` 新增裸 `update_cache: true`）、`TestAptNoInsecureFlags`、`TestAptClassifyFailureScript*`（用本機真實 Ubuntu 24.04 `apt-get` 擷取的 output 當 fixture，不是手寫猜測——過程中就抓到 2 個真 bug：apt 實際 404 文字是 `File not found` 不是 `Not Found`，且該行本身沒有 `W:`/`E:`/`Err:` 前綴，原本逐行 prefix filter 會整行漏判成 unknown；非 root 下鎖檔錯誤實際文字是 `Could not open lock file`，不只有 `Could not get lock`——已修正 classifier 與對應的 bounded-retry pattern，見 `cmd/pilot/cmd/apt_policy_test.go`）。`ansible-playbook --syntax-check`/`ansible-lint`/`go build`/`go vet`/`go test ./...` 全過。**尚未**live vm-target 驗證（`docs/verification/apt-repository-tolerance.md` T1/T3/T7 仍標記 `NOT YET LIVE-VERIFIED`）——静態/單元測試已過但依 AGENTS.md §1.1 不得因此宣稱 live 驗證完成 | pilot |
| 2026-09-09 | v1.6 | 新增 host annotations（`docs/superpowers/specs/2026-09-09-host-annotations-freeipa-sync-spec.md`）：`hosts.yml` 的 `annotations:` map 經 `internal/inventory`（`Host.Annotations`、`ValidateAnnotation*`、`SerializeAnnotation`）驗證後投影成 `pilot_annotations` host var，`playbooks/apply/tasks/freeipa-host-annotations.yml`（enrollment/health 成功後 include 一次）把它 declarative 同步到 FreeIPA `userClass`（`pilot.annotation.<key>=<value>`，scoped `--addattr`/`--delattr`，絕不 full replace）與 `location` 專用 `nshostlocation`；foreign `userClass`/`nshostlocation` 一律保留，duplicate/malformed managed 值與 location ownership drift 一律 fail-closed。**沒有新增 checklist row**——`pilot verify` 的 ad-hoc SSH 探針不帶 Kerberos ticket，無法直接 `ipa host-show`，改由 apply 本身 Phase F 的內建讀回驗證取代（見 §1.5/§6 說明）。`pilot edit` 新增獨立 annotations CRUD 選單（`hosts.item.annotations`，不與既有「其他變數」共用）與 `add_annotation`/`edit_annotation`/`delete_annotation` 結構化 automation action（刻意不支援 `value_env`——annotations 不是 secret channel）。**live vm-target L1-L13 全數 PASS**（`annot-ipa1` almalinux-9 FreeIPA server + `annot-cli1` ubuntu-24.04 client，`pilot vm-target up`/`wire` + `pilot vm-target run playbooks/apply/freeipa-client-apply.yml -e target_group=all -e ipa_server_ip=<server-ip> -e '{"pilot_annotations": {...}}' -e @~/.vault/main.yaml`）：L1 clean enroll+annotations（`userclass`/`nshostlocation` 三筆全部落地）、L2 冪等重跑 `changed=0`、L3 update（`project=alpha→beta`，`changed=2`：precise delete+add）、L4 delete（`owner` 移除，`changed=1`）、L5 foreign userClass（手動塞 `external-provisioning`）重跑後完整存活、L6 foreign native location（`nshostlocation` 手動改成非 Pilot 管理值）在**任何 mutation 之前**於 `Gate: reconcile plan must have no conflicts` fail（`CONFLICT_FOREIGN_LOCATION`，`nshostlocation` 完全未被覆寫）、L7 location drift（marker 存在但 native 被人工改到第三個值）同樣 mutation 前 fail（`CONFLICT_LOCATION_DRIFT`）、L8 duplicate managed key（手動塞第二筆 `pilot.annotation.project=`）mutation 前 fail（`CONFLICT_DUPLICATE_MANAGED_KEY`）、L9 malformed managed value（手動塞 `pilot.annotation.BadKey=x`）mutation 前 fail（`CONFLICT_MALFORMED_MANAGED_VALUE`，不自動修好/刪除）、L10 `--check --diff` 對已有 pending 變更（`beta→delta`）正確印出 `delete: [...beta] add: [...delta]` 且零 mutation、L11 host absent（server 端 `ipa host-del` 移除 host object，本機 enrollment 狀態不動）在**真實**（非 check）run 於 `Gate: FreeIPA host object must exist` fail（`HOST_ABSENT`）、L12 value 含 Unicode/空白/等號（`note: "台北 DC owner=AI Platform"`）完整 round-trip 且冪等、L13 case-only value replace（`project: Beta→beta`）確認 `changed=2`（delete `Beta` + add `beta`，非被 LDAP case-insensitive equality 誤判成 NOOP），最終 live 只剩 `beta` 一筆，未同時殘留兩種大小寫。**live vm-target 找到並修正 2 個真 bug**：(1) check-mode 對「從未 enroll 過的全新 host」跑 `--check --diff` 時，annotations task 的 admin kinit 排在 FreeIPA host-object-exists 檢查**之前**執行——但 `ipa-client-install` 本身在 check mode 下被跳過（是真 mutation），該 client 的 `/etc/krb5.conf` 從未寫入真實 realm，kinit 因此必然失敗，把整個 check-mode 預覽炸掉而非優雅回報 BLOCKED；修法：kinit 前先加一個 OS-level `/etc/ipa/default.conf` stat gate（獨立於既有的 LDAP-level host-object-exists gate），只有本機真的已完成 enrollment 才嘗試 kinit，否則直接印出「尚未 enroll，無法驗證」的 debug 訊息並整段 skip（`playbooks/apply/tasks/freeipa-host-annotations.yml` 的巢狀 `block:`）。(2) Phase F 的 `re-read live state for verification` task 的 `when:` 折疊字串裡有一組左右括號不對稱（`((...) > 0 or (...) > 0 or (...) != 'NOOP')` 少了一個右括號），會讓 Jinja 求值直接炸掉；此 bug 是實跑前逐行覆查 diff 時發現，不是靠 VM 失敗訊息抓到的，一併記錄以求誠實——已補上缺的右括號。`ansible-playbook --syntax-check`、`ansible-lint`（production 門檻，0 violation，僅剩 3 個與本 feature 無關的既有 `freeipa-client-apply.yml` 違規：C-pre-condition 的 `systemctl` module 用法與 2 處既有 `/etc/hosts` pin task 的 `name[template]`）、`go build ./...`、`go vet ./...`、`go test ./...`（全過，0 fail）全過。Go regression test 新增 `TestRegression_FreeipaHostAnnotationsTask_StaticSafetyInvariants`/`TestRegression_FreeipaHostAnnotationsTask_KinitIsNoLog`/`TestRegression_FreeipaClientApplyPlaybook_AnnotationsRunAfterEnrollment`（`internal/spec/freeipa_host_annotations_regression_test.go`），鎖 spec.md §25 的 12 條靜態不變量（scoped add/delete、never full-replace、foreign preservation、conflict-before-mutation、check-mode 零 mutation、argv-only、不寫入 `description`…）。2 台 VM 事後 `vm-target down` 全部清除 | pilot |
| 2026-09-16 | v1.8 | 起因：`pilot-access-gateway` 的「Connect」功能實測發現，若使用者端機器沒有主動要求 GSSAPI ticket delegation，停用密碼登入會讓整條跳板機路徑斷掉（見 `docs/evidence/pilot-access-gateway/2026-09-16-gssapi-no-password-fallback.md`）——`ipa-client-install` 自己的 `04-ipa.conf` 從不設定 `GSSAPIAuthentication`/`GSSAPIDelegateCredentials`，一般 OpenSSH client 預設也沒開。新增 C12：`freeipa-client-apply.yml` 自己寫入 `/etc/ssh/ssh_config.d/05-freeipa-client-gssapi-delegate.conf`，對 `Host *.{{ ipa_domain }}` 開啟兩者——只限本 realm 網域（非 `Host *`），因為對非本 realm 的主機 GSSAPI 認證本來就不會協商成功，用網域範圍把「絕不對外洩漏 ticket」的邊界寫死在設定檔本身，而不是只靠巧合。**live vm-target 驗證**（`ag-gw02`，複用既有 Phase 7/8 vm-target）：首次 apply `changed`、`/etc/ssh/ssh_config.d/05-freeipa-client-gssapi-delegate.conf` 內容與預期逐字相符、`ssh -G dummy.ipa.pilot.internal` 確認 `gssapidelegatecredentials yes` 生效（C12 checklist 指令本身）；第二次 apply `changed=0`（冪等）。`ansible-playbook --syntax-check`、`pilot spec --lint`、`go build ./...`、`go test ./cmd/pilot/cmd/... -run TestSpecPlaybookTagAlignment` 全過。同一組實際 GSSAPI 端對端 negotiation（同樣的兩個選項：`GSSAPIAuthentication yes`/`GSSAPIDelegateCredentials yes`）已在同日稍早的 `pilot-access-gateway` 測試中對 `ag-gw01`→`ag-target01` 兩段連線全程驗證成功（密碼/pubkey/keyboard-interactive 全部關閉），本次只需驗證這兩個選項現在是**預設**自動寫入、不用使用者手動 `-o` 覆寫，未重複跑一次相同的端對端 negotiation | pilot |
| 2026-09-23 | v1.9 | 新增 host access policy projection（`docs/superpowers/specs/2026-09-23-pilot-access-gateway-per-host-session-recording-spec.md` §7/§8，Phase 2）：`tasks/freeipa-host-access-policy.yml` 把 `pilot_ssh_recording` 投影成 FreeIPA userClass `pilot.policy.ssh-recording=<off\|terminal_output>`，不新增 C-number row（理由同 annotations，見 §6）。同時修正既有 annotations include 沒有 `apply: tags` 的問題：`--tags host-annotations`／直接對本 playbook `--tags freeipa-client` 過去會靜默跳過 include 內所有 task。live vm-target（`ipa-server-4.13.1`、Ubuntu 24.04 client）：fresh host `--check --diff` BLOCKED 零 mutation；4 台 client 真實 enroll `failed=0`（inherit → NOOP）；L2 ADD、L6 off 取代、L7 inherit 刪除、L11 foreign/annotation 保留、L9 DUPLICATE / L10 MALFORMED / 保留值 `terminal_io` UNKNOWN 皆在 mutation 前 fail 且值不變、boolean `false` 在 Phase A 被擋、已 enroll 主機 `--check --diff` 只印 plan 零 mutation、完整 playbook 第二次 apply `changed=0`；`--tags host-access-policy` 的 tag-scoped 執行也證實 `apply: tags` 生效。證據見 `docs/evidence/pilot-access-gateway/2026-09-23-phase2-freeipa-host-access-policy.md` | pilot |
| 2026-09-24 | v1.10 | Checklist 不變。實作面：(1) 全新 AlmaLinux 9 client 沒有 `dig`，DNS 預檢 rc=127 被 fail-closed gate 擋下——現在先檢查、缺少就安裝（EL `bind-utils`、Debian 經 apt framework 的 `bind9-dnsutils`），check-mode preview 對沒有 dig 的主機印訊息後 `end_host`；(2) EL 的 ipa-client 4.13.1 把 realm 區塊寫在 `/etc/krb5.conf.d/freeipa-realm`，failover reconcile 改為先找出實際檔案；(3) EL 上 `sssd-sudo.socket` 預設停用、socket 啟動的 sudo responder 連不到 backend，C8 在 EL 永遠 "not allowed"——RedHat 改為在 `services=` 保留顯式 `sudo` responder（NFS client overlay 寫同一行）；(4) 各 include 補上 `apply` tags、`ipa_cfg`/keytab stat 補 C11、auditd 改走 apt framework。4 台 vm-target topology（含一般 EL client）L3→L6 PASS，見 `docs/evidence/include-apply-tags-apt-framework/2026-09-24-dfb58a5.md` | pilot |
| 2026-10-12 | v1.11 | Checklist 不變。password-auth drop-in（`/etc/ssh/sshd_config.d/05-freeipa-client-password-auth.conf`）原本不驗證就寫入並 restart sshd：`sshd_config.d` 裡有其他壞掉的檔案時，restart 失敗、sshd 停在 down，下一次 run 看到 drop-in 沒變也不會再試。現在寫入時先用 `sshd -t -f` 單獨驗證，再對整份設定跑 `sshd -t`，通過才 **reload**（不再 restart；reload 失敗時正在執行的 sshd 不受影響）。任何一步失敗，rescue 把 drop-in 放回這次 run 開始時的樣子並讓 run 失敗，下一次 run 會重試。`playbooks/decommission/freeipa-client-decommission.yml` 移除這個 drop-in 時也一樣（失敗時放回 drop-in，decommission 可 resume）。由 `internal/spec/sshd_config_write_regression_test.go::TestRegression_SshdConfigWritesAreValidatedAndReverted`（allowlist 清空）與 `sshd_config_write_behavior_test.go` 鎖住。另外，`ipa-client-install`（enroll）與 `ipa-client-install --uninstall`（decommission）自己會 restart sshd：設定壞掉時 restart 失敗、sshd 停在 down，uninstall 還會做到一半就停（SSSD 設定已移除、`/etc/ipa/default.conf` 還在；2026-10-12 在 AlmaLinux 9 實測）。兩者之前現在都先跑 `sshd -t`，失敗就不執行 installer、什麼都不改；`TestRegression_IpaInstallersRunAfterAnSshdCheck` 對全 repo 鎖住（freeipa-server、replica、realm-replacement 的 installer 列在 allowlist，各需自己的實跑）；實跑（含對照組）見 [`docs/evidence/sshd-config-writes/2026-10-12-aca4915.md`](../evidence/sshd-config-writes/2026-10-12-aca4915.md) | pilot |
| 2026-10-12 | v1.12 | Checklist 不變。enrollment 之前的 `sshd -t` 移到 pre_tasks、任何變更與套件安裝之前（`always`，唯讀，`--check` 也會執行；仍沿用 enrollment 的 `creates:`）：`dnf install` FreeIPA 套件本身也會讓 sshd 被 restart（2026-10-12 在全新 AlmaLinux 9 主機實測：systemd「Queuing reload/restart jobs for marked units」），v1.11 放在 `ipa-client-install` 正前方的檢查在全新主機上來不及；`internal/spec/sshd_config_write_regression_test.go::TestRegression_IpaInstallersRunAfterAnSshdCheck`（allowlist 清空）與 `sshd_config_write_behavior_test.go::TestRegression_IpaInstallersCheckSshdFirst` 鎖住，並檢查會跑 installer 的 play 不得在 `sshd -t` 之前安裝套件；實跑（含對照組）見 [`docs/evidence/sshd-config-writes/2026-10-12-2fe32c6.md`](../evidence/sshd-config-writes/2026-10-12-2fe32c6.md) | pilot |
| 2026-10-29 | v1.13 | Checklist 不變。issue #168：已 enroll 主機的 resolver 被改過、解析不到 `krb5.conf` 的 KDC 名稱時，`--check` preview 在 host annotations 的 admin `kinit` 失敗且被 `no_log` 遮蔽；修復它的 `/etc/hosts` server-pool pin 是 mutation，preview 不會寫入。新增 `tasks/freeipa-client-kdc-preflight.yml`（kinit 之前以主機自己的 resolver 解析 KDC 與 FreeIPA 名稱，`--check` 且 pin 待變更時 deferred、其餘解析不到一律不遮蔽地失敗並列出 host/FQDN/resolver）與 `tasks/freeipa-client-kinit-result.yml`（kinit 失敗分類，不輸出原始 stderr），接到 annotations 與 access policy 兩個 task 檔；annotations 的 kinit 由 shell `printf` pipe 改為 `command` + `stdin`。pool pin 加 `register: freeipa_client_hosts_pool_pin`。PR #180 review 後就地修正：preflight 的必要名稱改為 OR（任一 KDC 名稱可解析即可，pin 只需涵蓋其中一個＋每個解析不到的 admin endpoint；retired-only 在 preview 仍失敗、不預測 failover reconciliation），KDC 值依 libkrb5 解碼（引號、空白、`host:port`／`[v6]`／https），`master_kdc` 不計入，kinit 分類只在必要名稱解析不到時才歸 `cannot_resolve`。resolver 偏離偵測不在此次範圍（另開 issue）。見 §6；vm-target 實跑見 [`docs/evidence/freeipa-client/2026-10-29-9e9f2b3e.md`](../evidence/freeipa-client/2026-10-29-9e9f2b3e.md) | pilot |
| 2026-11-05 | v1.14 | 新增 C13–C18：SSH key 等非密碼登入時對已過期 FreeIPA 密碼的政策（`freeipa_client_sssd_password_expiry_policy`：`warn`／`renew`／`off`，未設定不動；`freeipa_client_sssd_password_expiry_warning_days`）。row 依主機當下的 `ipa_access_order` 判斷，未啟用的主機也會 PASS。2026-11-05 在拋棄式 AlmaLinux 9 server + Ubuntu 24.04 client 以 `pilot verify --probe` 實跑：四種政策狀態全部 PASS，每一列要擋的狀態都 FAIL（§3 v1.14）。實測發現：`sssctl user-checks` 的結果在 stderr 且 rc 永遠 0；confdb 只在 SSSD 重啟時更新；從沒設過密碼的帳號在 `warn`／`renew` 下被拒絕（SSSD 2.9.4 原始碼與實測一致，C17）；改完密碼後數秒內重新登入仍被要求修改（§5）。apply playbook、fixture playbook、正式 evidence 尚未完成，`tag_coverage_test` 對 C13／C14 會失敗直到 apply 實作 | pilot |
| 2026-11-05 | v1.15 | Checklist 不變（C1–C18）。實作 C13／C14 的 apply：`freeipa-client-apply.yml` 新增 `always` 的輸入 gate（值、Ubuntu 24.04、`renew` 不在 gateway／directory／target-policy 主機）、快照→preflight→整行寫入→`sssctl config-check` 的 block（rescue 還原）、confdb drift 檢查，並修正既有 bug：SSSD restart task 只標 `C8`，`--tags sssd_hardening` 改了 sssd.conf 卻不重啟（現在帶 `C13`／`C14`／`sssd_hardening`，讀其他 register 一律 `default({})`）。新增 `playbooks/test/fixtures/freeipa-client-pwexpiry-fixtures.yml`。在拋棄式 AlmaLinux 9 server + Ubuntu 24.04 client 以 `ansible-playbook` 實跑（開發期，不是 `topology test`）：四種政策狀態 C13–C18 全 PASS、重跑 `changed=0`；負向控制與 rescue（含 confdb 讀不到時還原快照並重啟 SSSD）都實際觸發。正式 evidence 尚未產生 | pilot |
| 2026-11-05 | v1.16 | 新增 C19–C20：`renew` 時一併在 `[pam]` 設 `pam_initgroups_scheme = always`（`warn`／`off` 時移除值剛好是 `always` 的那一行）。原因：SSSD 2.9.4 PAM responder 在「5 秒 initgr 窗口內或使用者有 session」時不向後端重讀使用者，造成改密碼後反覆 TTY 重試持續被拒（一般 client 3 輪都超過 240 秒，#262）與管理員 reset 在使用者有 session 時延遲發現（100.5 秒、gateway 52–59 秒，#263）；在測試 VM 上 `always` 讓前者約 10 秒恢復、後者 1.4 秒內發現。row 指令已在實機以 `pilot verify --probe` 對八種狀態各驗過 PASS／FAIL。playbook、regression test 與完整 evidence 隨同一個 PR。同時處理 A12（FreeIPA 不可達、replica）的實測與代價量測 |
