# Verification Spec — freeipa-server-replica (native EL9, HA 第二/後續台)

> 版本：v1.0（**已實跑**——三台 vm-target 全鏈路 apply + verify + HA failover 實測，見 §0/§3/§9）
> 對齊規範：pilot 通用基礎設施**服務端**規範；本 host 是加入既有 FreeIPA realm 的
> 第二台（或後續台）multi-master replica，不是全新 realm 的第一台
> 維護者：sre

> 對偶參照：第一台（既有 realm 的起點）健康見 `freeipa-server.md`；本檔只驗證
> 「加入既有 realm 之後，這台自己的健康 + 它跟既有主機的複寫拓樸是否同步」，
> 不重複第一台已驗證過的單機邏輯以外的東西。時間同步 / DNS 預設依賴既有
> `ntp`(chrony) / `dns`(unbound) role，語意與 `freeipa-server.md` §1 完全相同——
> 這兩個開關**不會**自動跟第一台同步，見 §5。

## 0. 這份檔的狀態（先讀）

依 `AGENTS.md` §1「actual-run 規則」：寫進 `docs/verification/*.md` 步驟區塊的指令，
**必須先在對應目標環境實際跑過並截真實輸出**才算數。

**v1.0（本版）已完整實跑**：三台 vm-target（`ipa-primary`/`ipa-replica`/
`ipa-ha-client`，AlmaLinux 9 × 2 + Ubuntu 24.04 × 1）跑過完整鏈路——
`freeipa-server-apply.yml`（primary）→ `freeipa-server-replica-apply.yml`
（replica）→ `pilot vm-target verify`（15/15 PASS,§3）→ `freeipa-client-apply.yml`
（client,enroll 向 primary）→ 手動模擬 primary/replica 輪流關閉,驗證 client 端
真的能 failover,以及兩台都關掉時真的無法登入（§9 的完整敘事與真實輸出）。

實跑過程中**發現並修好兩個真的會擋線的 bug**（都不是憑空猜的,是這次真跑撞出來的）：

1. **`ipa-replica-install` 在 promotion 模式下不接受任何 NTP 旗標**——本檔 apply
   playbook 原本沿用 primary 那支的邏輯,幫 `ipa-replica-install` 也帶了
   `--no-ntp`,結果直接炸掉,錯誤是 `NTP configuration cannot be updated during
   promotion`。修法：promotion 模式下完全不傳 NTP 旗標(NTP 已經在
   step 1/2 的 `ipa-client-install` 那裡決定過了)。已修進
   `playbooks/apply/freeipa-server-replica-apply.yml`。
2. **`ipa-client-install`/`freeipa-client-apply.yml` 把 `sudo` 塞進 SSSD 的
   `services=` 這一行,跟現代 SSSD(≥2.3,這次踩到的是 2.9.4)預設的
   socket-activated sudo responder衝突**,導致 `sssd-sudo.socket` 啟動失敗
   (`Misconfiguration found for the sudo responder`),`sudo -l` 對任何人永遠
   回「not allowed」,沒有任何錯誤訊息、看起來像是 sudo 規則沒生效,其實是
   responder 根本沒起來。這個 bug 跟本次 replica 工作無關(是既有
   `freeipa-client-apply.yml` 的既存缺陷),但擋住了本次 HA client 端測試,已
   在 `playbooks/apply/freeipa-client-apply.yml` 順手修掉(拿掉 `services=`
   裡的 `sudo`,交給 socket activation)。

另外實跑也發現一個**只做手動修補、沒有寫進任何 playbook 的必要步驟**：套用
`freeipa-server-replica-apply.yml` 前,**primary 必須先手動把新 replica 的
FQDN/IP pin 進自己的 `/etc/hosts`**（本 playbook 只會 pin 自己端）,否則
`ipa-replica-install` 的 remote conncheck 會失敗——完整說明與真實錯誤訊息見
§5 那一條例外。

在此之前（僅 lint/generate/syntax-check 過,尚未實跑）的 v0.1 草稿走的步驟,
供之後同類 spec 參考：

```bash
# 1. 先起既有 primary（若還沒有）
pilot vm-target up --name ipa-primary --base-image almalinux-9
pilot vm-target run --name ipa-primary playbooks/apply/freeipa-server-apply.yml \
    -e target_group=all -e ipa_server_ip=<primary-vm-ip> -e @~/.vault/main.yaml

# 2. 起第二台，跑本 spec 對應的 apply playbook
pilot vm-target up --name ipa-replica --base-image almalinux-9
pilot vm-target test --name ipa-replica \
    --playbook playbooks/apply/freeipa-server-replica-apply.yml \
    --spec docs/verification/freeipa-server-replica.md \
    --verify-timeout 40 \
    -- -e target_group=all -e ipa_server_ip=<primary-vm-ip> \
       -e ipa_replica_ip=<replica-vm-ip> -e @~/.vault/main.yaml
```

## 1. 目標系統

| Hostname                | Group                    | Address       | User     | Port | IdentityFile |
|--------------------------|---------------------------|---------------|----------|------|--------------|
| ipa2.ipa.pilot.internal | freeipa-server-replica    |               |          |      |              |

| 項目 | 值 |
|------|----|
| Inventory group | `freeipa-server-replica`（vm-target 測試時 host 在 `all`，用 `-e target_group=all`）|
| OS / version | **Enterprise Linux 9 原生**（AlmaLinux / Rocky / RHEL 9）；`ipa-server` 4.13.x（跟 primary 同版本，見 §5）|
| 角色 | 既有 FreeIPA realm 的**第二台（或後續台）multi-master replica**——非 primary/secondary，加入後兩台都可讀寫 |
| 網路模式 | **host-native**：所有埠直接 bind 在主機（無容器、無埠映射），與 `freeipa-server.md` 相同 |
| 前置條件 | 既有 primary（`freeipa-server.md` 涵蓋的那台）必須已裝好、健康、且此主機網路可達 |
| 加入方式 | `ipa-client-install`（先以一般 client 身分加入）→ `ipa-replica-install`（升級成 replica）；見 apply playbook 檔頭註解「WHY client-then-promote」|
| DNS / NTP | 語意與 `freeipa-server.md` 相同（可選啟用，預設關閉），但**不會**自動與 primary 同步，見 §5 |
| 套用範圍 | 單台加入既有 realm（同時加入第 3+ 台重複套用本 playbook，每次一台;見 §5 併發限制）|
| 風險等級 | High（此為 HA 的存在理由，但拓樸操作錯了會讓兩台一起壞——見 §5）|

## 1.5 依賴變數契約

套用或驗證此主機時，Playbook 與變數參數必須嚴格遵守以下命名，禁止擅自縮寫或發明新變數：

| 變數名稱 | 說明/用途 | 是否必填 |
|---------|----------|---------|
| `ipa_admin_password` | FreeIPA `admin` 帳號密碼；由 vault file 注入，禁止 hard-code | 是 |
| `ipa_server_ip` | **既有 primary** 的 LAN IP（沿用 `freeipa-client-apply.yml` 的同名同義，指「要對它 enroll 的既有伺服器」，不是這台自己）| 是 |
| `ipa_replica_ip` | **這台自己**對其他主機可路由的 LAN IP；寫進 `/etc/hosts` 讓自己的 FQDN 解析到非 loopback | 是 |
| `ipa_domain` | Kerberos/DNS domain，**必須跟 primary 完全一致**，預設 `ipa.pilot.internal` | 否（有預設）|
| `ipa_realm` | Kerberos realm，**必須跟 primary 完全一致**，預設 `IPA.PILOT.INTERNAL` | 否（有預設）|
| `ipa_server_fqdn` | **既有 primary** 的 FQDN，預設 `ipa1.{{ ipa_domain }}` | 否（有預設）|
| `ipa_replica_fqdn` | **這台自己**的 FQDN，預設 `ipa2.{{ ipa_domain }}`（**不可**與 `ipa_server_fqdn` 或既有其它 replica 相同）| 否（有預設）|
| `ipa_replica_setup_ca` | 這台是否同時擔任 CA replica，預設 `true`（HA 建議至少 2 台有 CA；但 CA **renewal master** 角色不會跟著轉移，見 §5）| 否（有預設）|
| `ipa_setup_dns` | 是否啟用 FreeIPA 內建 DNS 服務（語意同 `freeipa-server.md`，**不自動跟 primary 同步**），預設 `false` | 否（有預設）|
| `ipa_dns_forwarders` | 當啟用 DNS 時，上游 DNS 轉發器 IP 列表，預設 `[]` | 否（有預設）|
| `ipa_setup_ntp` | 是否由 FreeIPA 管理/啟用 NTP 同步（語意同 `freeipa-server.md`），預設 `false` | 否（有預設）|

> Realm 後綴 DN 與 389-ds instance 名的推導規則與 `freeipa-server.md` §1.5 相同（同一個 realm）。
> 換 domain/realm 時，本檔與 `freeipa-server.md` 要**一起換**——兩份 spec 描述的是同一個 realm 的不同節點。

## 2. Checklist

> 指令以 target 上的 **SSH 使用者**身分執行（`pilot verify` 走 ansible ad-hoc）。
> C2 需 root → 用 `sudo`（target 需具備 passwordless sudo）；其餘查詢免 root。
> C1–C13 的邏輯與 `freeipa-server.md` 的 C1–C13 完全對稱（同樣是「這台自己健康
> 嗎」），差異只在 hostname/FQDN 換成這台自己的；C14–C15 是本檔獨有、只有
> multi-master 拓樸才需要驗證的兩條。

| ID  | Category      | Check                                                            | Expected                       | Command |
|-----|---------------|--------------------------------------------------------------------|---------------------------------|---------|
| C1  | install       | FreeIPA 已設定完成（安裝產物存在）                                 | 0                               | test -f /etc/ipa/default.conf |
| C2  | service       | 所有 IPA 服務健康（`ipactl status` 全 RUNNING → 自身 rc 0）       | 0                               | sudo ipactl status |
| C3  | service       | 主機 FQDN 正確（這台自己的，不是 primary 的）                     | ~ipa2.ipa.pilot.internal        | hostname -f |
| C4  | port          | LDAP 389/tcp 在 host listening                                    | 0                               | ss -tlnH | grep -q ":389 " |
| C5  | port          | LDAPS 636/tcp 在 host listening                                   | 0                               | ss -tlnH | grep -q ":636 " |
| C6  | port          | Kerberos 88/tcp 在 host listening                                 | 0                               | ss -tlnH | grep -q ":88 " |
| C7  | port          | Kerberos 88/udp 在 host listening                                 | 0                               | ss -ulnH | grep -q ":88 " |
| C8  | port          | kpasswd 464/udp 在 host listening                                 | 0                               | ss -ulnH | grep -q ":464 " |
| C9  | port          | HTTP 80/tcp 在 host listening                                     | 0                               | ss -tlnH | grep -q ":80 " |
| C10 | port          | HTTPS 443/tcp 在 host listening                                   | 0                               | ss -tlnH | grep -q ":443 " |
| C11 | ldap          | LDAP rootDSE 廣告的 namingContext = realm 後綴（跟 primary 同一個後綴，證明是同一個 backend suffix，不是另開的獨立 realm）| ~dc=ipa,dc=pilot,dc=internal    | ldapsearch -x -H ldap://localhost -b "" -s base namingContexts |
| C12 | http          | CA 憑證 endpoint 可被抓（走這台自己的 FQDN，client 也可改指到這台做 failover）| ~200                            | curl -fsS -o /dev/null -w "%{http_code}" http://ipa2.ipa.pilot.internal/ipa/config/ca.crt |
| C13 | sudo          | sudo 規則 LDAP 子樹存在（跟 primary 複寫過來，不是本機獨立建的）    | ~ou=sudoers                     | ldapsearch -x -H ldap://localhost -b "ou=sudoers,dc=ipa,dc=pilot,dc=internal" -s base dn |
| C14 | replication   | 這台看得到 **primary** 在 `cn=masters` 拓樸清單裡（複寫已同步 primary 的存在）| ~cn=ipa1.ipa.pilot.internal     | sudo ldapsearch -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "cn=masters,cn=ipa,cn=etc,dc=ipa,dc=pilot,dc=internal" -s sub dn |
| C15 | replication   | 這台自己也出現在 `cn=masters` 拓樸清單裡（不是單純 enroll 成 client 就停在那，真的升級成 replica 了）| ~cn=ipa2.ipa.pilot.internal     | sudo ldapsearch -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "cn=masters,cn=ipa,cn=etc,dc=ipa,dc=pilot,dc=internal" -s sub dn |

> **C4–C10** 都含 `|` pipeline，parser 會把後續 column 自動接回 Command（同
> `freeipa-server.md` 的說明），並用 `":<port> "`（尾隨空白）避免 `:80` 誤命中
> `:8080`。
> **C2 用正邏輯**（原因與寫法完全同 `freeipa-server.md` 的 C2 註記——反邏輯 grep
> 在 ansible ad-hoc 下 expected 永遠對不上）。
> **C3/C11–C13/C14/C15 用 `~`（contains）**，不用 `^…$` regex（原因同上，ad-hoc
> 輸出帶 wrapper 前綴，錨點對不上）。
> **C14/C15 是本檔的核心驗證目的**：兩條都查同一個 `cn=masters,cn=ipa,cn=etc,<suffix>`
> 子樹，用「查到的清單裡是否包含某台的 `cn=<fqdn>`」而不是「數共有幾台」——
> 因為台數會隨拓樸成長變動，寫成固定數字 expected 會在加第三台後失效；查
> 「特定 fqdn 出現在清單裡」才是跟拓樸大小無關的固定 expected。C14 證明「這台
> 已經從 primary 複寫到拓樸資料」，C15 證明「這台自己真的完成升級成 replica
> （不是卡在 client enroll 那一步）」——兩者缺一都代表 join 沒有完全成功。
> **C14/C15 需要 root（`sudo` + ldapi SASL/EXTERNAL autobind）**：`cn=masters,cn=ipa,cn=etc`
> 是系統容器，**不像** `ou=sudoers`（C13）那樣有給匿名讀的 ACI——實測過匿名
> `ldapsearch -x` 對這個子樹回 `result: 0 Success` 但零筆資料（不是錯誤,是
> ACL 悄悄擋掉,第一次沒注意到差點誤判「複寫沒同步」）。改用
> `-Y EXTERNAL -H ldapi://%2Frun%2F<389-ds instance>.socket` 以 root autobind
> 才讀得到,同 `freeipa-server.md` C14–C16 的 `dsconf` 走 ldapi 的道理。389-ds
> instance 名由 realm 推導（`IPA.PILOT.INTERNAL` → `slapd-IPA-PILOT-INTERNAL`），
> 換 realm 時 C14/C15 的 socket 路徑也要跟著換。

## 3. 證據收集

- 工具：`pilot vm-target verify --name <el9-vm-2> docs/verification/freeipa-server-replica.md`
  （真實主機：`pilot verify docs/verification/freeipa-server-replica.md -i inventory-freeipa.yaml`）
- 格式：`.verification/freeipa-server-replica-<UTC>.{ndjson,md}`
- 預期 row 數：15

**真實輸出**（`ipa-replica` vm-target，primary=`ipa-primary`/192.168.122.2，
replica=`ipa-replica`/192.168.122.3，2026-07-09T09:28:29Z，暖 SSH 連線 +
`--timeout 40`）：verdict **PASS pass=15 fail=0 skip=0**：

```json
{"id":"C1","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C2","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C3","status":"pass","detail":"stdout contains \"ipa2.ipa.pilot.internal\""}
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
{"id":"C14","status":"pass","detail":"stdout contains \"cn=ipa1.ipa.pilot.internal\""}
{"id":"C15","status":"pass","detail":"stdout contains \"cn=ipa2.ipa.pilot.internal\""}
```

複測(整趟 HA failover 實測跑完、兩台服務都恢復之後,§9)重新對兩份 spec 各跑一次
`pilot vm-target verify`,確認沒有把任何東西跑壞：`freeipa-server.md` 對
`ipa-primary` **PASS pass=18 fail=0 skip=0**;本檔對 `ipa-replica` **PASS
pass=15 fail=0 skip=0**(2026-07-09T09:41Z)。

## 4. PASS / FAIL 規則

- C1–C15 全部 `status=pass`（或 §5 允許的 `skip`）→ **PASS**：此節點已完成加入既有
  realm 的 multi-master 拓樸，可獨立提供帳號 + sudo 服務，且雙向複寫確認同步。
- 任一 `fail` → **FAIL**，常見修法：
  - C1 fail → `ipa-client-install` 或 `ipa-replica-install` 沒跑完；`sudo tail -n 80 /var/log/ipareplica-install.log`（若連 client enroll 都沒過，看 `/var/log/ipaclient-install.log`），重跑 apply playbook。
  - C2 fail → 某 IPA 服務掛了；`sudo ipactl status` 看哪個 STOPPED，`sudo ipactl restart`。
  - C3 fail → 主機 hostname 沒設成這台自己的 FQDN；`sudo hostnamectl set-hostname ipa2.ipa.pilot.internal`。
  - C4–C10 fail → 對應服務沒起或防火牆擋；先查 C2，再查 host firewall 是否放行該埠。
  - C11 fail → Directory Server 沒起，或這台的 realm/domain 設定跟 primary 不一致（打錯 `-e ipa_domain=`）。
  - C12 fail → HTTP(80) 沒起或這台自己的 FQDN 在本機不可解析；確認 `/etc/hosts` 有 `ipa_replica_ip ipa2.ipa.pilot.internal`（FQDN 在前）。
  - C13 fail → 複寫還沒同步完（剛 join 完成，等 replicate 追上）,或 primary 端本來就沒有這個子樹(先確認 primary 端的 `freeipa-server.md` C13 有過)。
  - C14 fail → 這台完全沒跟 primary 複寫成功——檢查網路是否真的連得到 `ipa_server_ip`,以及 `ipa-replica-install` 是否真的跑完(看 rescue 區塊印出的 log)。
  - C15 fail → 這台卡在「已是 client、還沒升級成 replica」——多半是 `ipa-replica-install` 步驟本身失敗但 `ipa-client-install` 先成功了;檢查 `/var/log/ipareplica-install.log`,常見原因是 `--admin-password` 權限不足(admin 帳號需在 `admins` group)或 primary 端磁碟/服務異常擋掉了複寫協議。

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| — | **套用前必須手動把這台的 FQDN/IP pin 進 primary（以及其它既有節點）的 `/etc/hosts`**：`ipa-replica-install` 在 promotion 模式下會叫 primary 反過來對這台做一次 remote conncheck（primary 主動連回這台的 389/636/88/464/80/443），沒有內建 DNS 時 primary 端解析不到新節點的 FQDN 就會整個 install 失敗，錯誤訊息是 `ERROR: Port check failed! Unable to resolve host name 'ipa2.ipa.pilot.internal'`（實跑踩過，見 §0 的真實 log）。本 playbook 只會 pin 自己端（新 replica）的 `/etc/hosts`，**不會**（也做不到——vm-target 的 ansible inventory 一次只認得一台機器）幫你去改 primary 的 `/etc/hosts`。套用前先手動在 primary（以及任何已存在的其它 replica）上加一行 `<這台的 IP> <這台的 FQDN> <短名>`，或者從一開始就在整個 realm 啟用真正的 DNS（`ipa_setup_dns=true`，且所有節點一致，見下一條例外） | 全部 | 永久 |
| — | **CA renewal master 不會自動轉移**：`ipa_replica_setup_ca=true` 只讓這台成為 CA **replica**（能簽憑證),CA **renewal**(定期更新 CA 憑證本身)的角色仍留在原本那台,直到有人手動 `ipa config-mod --ca-renewal-master-server=<fqdn>` 轉移。原本那台(通常是 primary)下線前忘記轉移,會導致全網 CA 憑證到期後無人續期。本 playbook 刻意不自動做這件事——這是需要人判斷「該轉去哪台」的操作,不該被套用腳本悄悄做掉 | 全部 | 永久 |
| — | **DNS/NTP 選項不會跨節點同步**：`ipa_setup_dns`/`ipa_setup_ntp` 只控制「這台自己」,不會去讀 primary 或其它既有 replica 目前的設定。若站台混用(某些節點開 DNS、某些沒開),靠 DNS SRV record 做 client failover 的機制會不完整。操作者要自己保證同一個 realm 裡所有節點的這兩個開關一致 | 全部 | 永久 |
| — | **既有 client 的 failover 不會自動補上**:加入這台 replica 後,舊有的 `freeipa-client-apply.yml` 已 enroll 過的主機,`/etc/sssd/sssd.conf` 的 `ipa_server`/DNS 設定不會自動改成看得到新節點。要讓既有 client 真正 failover 到新節點,需要另外重跑 client 端設定(補 `ipa_server` 多值清單,或啟用 DNS SRV)——這在 client 端 spec(`freeipa-client.md`)的範圍,不在本檔 | 全部 | 永久 |
| — | **移除/退役一台 replica 不在本 playbook 範圍**:單純關機或刪除 VM 會留下孤兒的拓樸/複寫協議紀錄。正式退役要從**存活的**節點跑 `ipa server-del <fqdn>`(或舊版 `ipa-replica-manage del`)清理,本 playbook 只處理「加入」,不處理「移除」 | 全部 | 永久 |
| — | **389-ds 目錄服務稽核日誌尚未在此 playbook 對齊**:`freeipa-server-apply.yml` 有 `freeipa-audit` task(見該 spec C14–C16),本檔的 apply playbook 目前沒有等價任務,新節點預設不會開稽核日誌。若站台要求所有節點稽核政策一致,套用完本 playbook 後要自己補跑或等後續版本補上 | 需稽核一致性的站台 | 直到本 playbook 補上等價 task 為止 |
| — | **同時加入第 3+ 台不要併發**:對同一個 primary **同時**跑多個 `ipa-replica-install`(不同新主機並行)在 389-ds 複寫協議上有已知的競態風險(拓樸段建立衝突)。多台要加入,一律**循序**跑完一台、C14/C15 都 PASS,再開始下一台——跟本 repo 既有的 `pilot vm-target up` 併發 state race 是不同層的問題,但處理原則相同(序列化,不要並行對同一個共享狀態寫入)| 全部 | 永久 |
| — | **容器路徑不適用**:與 `freeipa-server.md` 相同的理由(httpd GSSAPI acceptor 在容器內卡死),本檔與 apply playbook 一律只認 native EL9,不接受任何容器化變體 | 全部 | 永久 |

## 6. Playbook 對應

對應產生的 **verify** playbook：`playbooks/verify/freeipa-server-replica.yml`（由 `pilot spec --generate` 產，**勿手寫**）

對應手寫的 **apply** playbook：`playbooks/apply/freeipa-server-replica-apply.yml`

| Spec ID | Apply task（示例） | 備註 |
|---------|-------------------|------|
| C3      | `ansible.builtin.hostname name=ipa2.ipa.pilot.internal` + `/etc/hosts` pin（自己與 primary 雙向 pin）| tag `R1` |
| C1      | `ipa-client-install`（tag `R1`，gate on `/var/log/ipaclient-install.log`）→ `ipa-replica-install`（tag `R2`，gate on `/var/log/ipareplica-install.log`）| 兩個獨立 marker，避免 `/etc/ipa/default.conf` 在兩步之間都存在造成的誤判,見 apply playbook 檔頭註解 |
| C2      | 安裝後 `until ipactl status` 沒有 STOPPED/FAILED 的 wait task(tag `R2`)| 首次 promote 8–12 分鐘,retries 拉長 |
| C4–C10  | 由 `ipa-replica-install` 一次帶起(LDAP/Kerberos/HTTP/CA);host-native 直接曝在主機 | firewall 放行由 host 層負責 |
| C11/C13 | 由複寫從 primary 同步過來,不是本機重新建立 | — |
| C12     | `--setup-ca`(`ipa_replica_setup_ca` 預設 true)| tag `R2` |
| C14/C15 | `block/rescue` 內的 `ldapsearch -Y EXTERNAL -H ldapi://%2Frun%2F<389-ds instance>.socket -b cn=masters,cn=ipa,cn=etc,<suffix>`(tag `freeipa-replica-verify`;root autobind,見上方 C14/C15 註記為何不能用匿名 `-x`)| 失敗會走 rescue,印 `ipactl status` + tail replica-install log |

> Apply playbook 用 `block/rescue`:promote 失敗時 rescue 收 `ipactl status` +
> `ipareplica-install.log` 便於除錯;`pre_tasks: assert` 對
> `ipa_admin_password`/`ipa_server_ip`/`ipa_replica_ip` 做 mandatory gate、對 OS
> (必須 EL9)、對「這台不能跟 primary 是同一台」、對 staging/prod 做 gate。

## 7. 把 FAIL 變 PASS 的 SOP（加入既有 realm）

### 7.1 前提：primary 已經健康

```bash
# primary 必須先跑過 freeipa-server.md 且 PASS,見該檔 §7.1
pilot vm-target verify --name <primary-vm> docs/verification/freeipa-server.md
```

### 7.2 起第二台、加入拓樸

```bash
# 1. 讀這一步要執行的那份 inventory 的事實
pilot vm-target show-inventory --name <replica-vm>              # 拋棄式 VM
# 真實主機：ansible-inventory -i inventory-freeipa.yaml --graph

# 2. dry-run(sandbox 預設;secret 走 vault file,不落地)
pilot vm-target run --name <replica-vm> playbooks/apply/freeipa-server-replica-apply.yml \
    -e target_group=all -e ipa_server_ip=<primary-vm-ip> \
    -e ipa_replica_ip=<replica-vm-ip> \
    -e @~/.vault/main.yaml --check --diff

# 3. 正式套(拿掉 --check);首次 promote 約 8–12 分鐘
pilot vm-target run --name <replica-vm> playbooks/apply/freeipa-server-replica-apply.yml \
    -e target_group=all -e ipa_server_ip=<primary-vm-ip> \
    -e ipa_replica_ip=<replica-vm-ip> \
    -e @~/.vault/main.yaml

# 4. 驗證(這台自己 + 拓樸複寫)
pilot vm-target verify --name <replica-vm> docs/verification/freeipa-server-replica.md
```

### 7.3 加第 3 台以上

重複 §7.2,一次只加一台、等前一台 C14/C15 都 PASS 才開始下一台(見 §5 併發限制)。

## 9. HA failover 實測(client 端,2026-07-09)

> **可重複執行的步驟清單見 `docs/runbooks/freeipa-server-replica-ha-drill.md`**——
> 本節是這次實測的敘事記錄與真實輸出片段,那份 runbook 是抽掉逐字輸出後、
> 下次直接照抄重跑用的命令清單(含所有 gotcha)。
>
> 目的:C1–C15 只證明「這台自己健康 + 拓樸資料同步」,不證明「真的有機器在用它、
> 而且真的能在一台掛掉時繼續服務」。這節補上第三台 client(`ipa-ha-client`,
> Ubuntu 24.04)實際 enroll + 輪流關閉兩台 server 的完整敘事與真實輸出——這是
> 使用者明確要求的驗證項目,不是本檔 checklist 的一部分(client 沒有自己的
> spec row,以下是敘事記錄,不是 pass/fail 表)。

### 9.1 前置

- `ipa-ha-client` 用 `freeipa-client-apply.yml` enroll 向 **primary**(`ipa1`)。
- 手動用 `playbooks/test/fixtures/freeipa-client-fixtures.yml` 在 primary 上建
  `pilotuser` + sudo 規則 `pilot-all`(hostcat=all cmdcat=all !authenticate)——
  這是本 repo canonical 的 demo 帳號建立方式(AGENTS.md §4.1),不是手刻
  `ipa user-add`。
- **手動**把 replica(`ipa2`)的 FQDN/IP 補進 client 的 `/etc/hosts`,以及把
  `/etc/krb5.conf`(`kdc=`/`admin_server=`/`kpasswd_server=`)與
  `/etc/sssd/sssd.conf` 的 `ipa_server=` 都補上 `ipa2`——**這兩步都是手動做的,
  沒有寫進任何 playbook**,是本次實測撞出來的真實需求,已記進 §5 的例外清單。

### 9.2 步驟與真實輸出

| 步驟 | 動作 | Kerberos 認證(`kinit admin`) | 身分查詢(`id pilotuser`) | sudo 授權(`sudo -l -U pilotuser`) | `sssctl domain-status` |
|---|---|---|---|---|---|
| 基準 | 兩台都上線 | **成功** | 成功 | 成功(NOPASSWD: ALL) | Online,Active=ipa1 |
| A | 只 pin `/etc/hosts`,關 **primary**,client krb5.conf/sssd.conf 仍只認 ipa1 | **失敗**:`kinit: Cannot contact any KDC` | 成功(SSSD offline cache) | — | Offline,Active=ipa1(卡住,沒真的切) |
| B | 補上 §9.1 的 client 端多伺服器設定,關 **primary**、replica 上線 | **成功**(走 ipa2) | 成功 | 成功 | **Online,Active=ipa2** |
| C | 恢復 primary、關 **replica** | **成功**(走 ipa1) | 成功 | 成功 | Online,Active=ipa1 |
| D | **兩台都關** | **失敗**:`kinit: Cannot contact any KDC`(rc=1) | 已快取的使用者仍成功(offline cache);**從未查過**的使用者失敗(`no such user`) | 已快取的規則仍顯示(offline cache) | **Offline** |
| 恢復 | 先恢復 primary | 立即成功 | — | — | — |

真實終端輸出(節錄,步驟 B,關 primary、replica 上線之後)：

```
=== id pilotuser (primary down, replica up, client now knows both) ===
uid=1462400003(pilotuser) gid=1462400003(pilotuser) groups=1462400003(pilotuser)
=== sudo -l -U pilotuser ===
User pilotuser may run the following commands on ipa-ha-client:
    (root) NOPASSWD: ALL
=== kinit admin ===
Password for admin@IPA.PILOT.INTERNAL:
KINIT_OK
=== sssctl domain-status ===
Online status: Online
Active servers:
IPA: ipa2.ipa.pilot.internal
Discovered IPA servers:
- ipa1.ipa.pilot.internal
- ipa2.ipa.pilot.internal
```

真實終端輸出(節錄,步驟 D,兩台都關掉之後——這是使用者明確要求的「確保無法
登入」驗證)：

```
=== kinit admin (BOTH servers down — this is the authoritative 'cannot login' proof) ===
kinit: Cannot contact any KDC for realm 'IPA.PILOT.INTERNAL' while getting initial credentials
kinit rc=1
=== id a NEVER-looked-up identity (neverseenuser@domain) ===
id: 'neverseenuser@ipa.pilot.internal': no such user
id rc=1
=== sssctl domain-status ===
Online status: Offline
```

### 9.3 結論與誠實的補充說明

1. **HA 本身確實有效**:任一台(primary 或 replica)掛掉,只要 client 端設定
   同時知道兩台,`kinit`/`id`/`sudo -l` 全部正常延續,不中斷。這是本檔存在的
   核心理由,已用真機驗證。
2. **「兩台都掛 → 無法登入」的權威證明是 `kinit`**:Kerberos 取票**沒有離線
   路徑**,兩台都下線時 100% 立即失敗(`Cannot contact any KDC`)——這就是
   使用者要求的「確保此時無法登入」。
3. **誠實的補充**:SSSD 對**已經查過**的身分/sudo 規則有本機快取,兩台都掛
   時舊快取仍會回應(`id`/`sudo -l` 對已快取使用者不會馬上報錯)。這是 SSSD
   設計上的離線韌性功能,不是 bug,但代表「兩台都掛 = 完全無法存取任何東西」
   這句話不完全精確——精確的講法是「兩台都掛 = 無法取得任何**新的**
   Kerberos 票證,且無法查到任何**先前沒查過**的身分」。已快取的既有 SSH
   session、已快取身分的本機查詢在快取有效期內仍會回應。
4. **步驟 A 揪出的真實限制**:光靠 `/etc/hosts` pin **不足以**做到 client 端
   failover——`/etc/krb5.conf` 的 `kdc=` 與 `sssd.conf` 的 `ipa_server=` 都是
   client enroll 時針對**單一** server 寫死的,沒有真正 DNS SRV 的話,兩份設定
   都要手動補上第二台才會真的 failover。這正是 §5 那條「既有 client 的
   failover 不會自動補上」例外的具體驗證,细节現在也補進本節。

## 10. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-09 | v0.1 | 初版草稿:multi-master replica 加入既有 realm(client-then-promote 流程)。checklist C1–C13 對稱既有 `freeipa-server.md`,新增 C14/C15 驗證雙向拓樸複寫。**未實跑**(見 §0)——lint/生成/syntax-check 已過,尚未在真實兩台 vm-target 上跑過 apply + verify | pilot |
| 2026-07-09 | v1.0 | **已實跑**:三台 vm-target(primary/replica/client)跑完整鏈路,`pilot vm-target verify` 15/15 PASS(§3)。修正 apply playbook 兩個實跑撞出的 bug——(1) `ipa-replica-install` promotion 模式不接受 NTP 旗標,(2) `freeipa-client-apply.yml` 的 `services=` 塞 `sudo` 跟 SSSD socket-activated sudo responder 衝突(既有 bug,順手修掉)。C14/C15 的查詢方式改為 root+ldapi(`-Y EXTERNAL`),因為 `cn=masters,cn=ipa,cn=etc` 匿名讀不到(實跑才發現)。新增 §9 完整記錄 client 端 HA failover 實測(kinit 作為「兩台都掛 = 無法登入」的權威證明,並誠實記錄 SSSD offline cache 的補充說明);§5 新增「primary 需手動 pin 新 replica /etc/hosts」的例外 | pilot |
