# Verification Spec — freeipa-identity（canonical identity primitives + legacy authorization reconciler）

> 版本：v1.6（2026-08-11 roster-schema-v2 migration：netgroups 與 hostgroup
> 巢狀 membership 交付，新增 C19–C24，已在 `freeipa-server` vm-target 上依序
> 套用 legacy/canonical v1/schema-v2 三份 fixture 後實跑 24/24 PASS，並實測
> netgroup authoritative pruning，見 §3、§7.1a）
> 前一版：v1.2（2026-07-22 delivery batch 1；已在獨立 AlmaLinux 9
> `freeipa-identity-v2` vm-target 上實跑 canonical apply、checklist 與冪等重跑）
> 相容基線：v1.1 已在 `pilot vm-target freeipa-server` 上實跑
> `playbooks/test/fixtures/freeipa-identity-fixtures.yml` 建立 fixture，
> §2 checklist 逐條實測，見 §3；v1.1 新增 §7.2a check-mode 安全性閘門）
> 對齊規範：本檔驗證的不是單一 host 的既定角色（如 freeipa-server/freeipa-client），
> 而是 `playbooks/apply/freeipa-identity-apply.yml` 這個**通用 reconciler**本身的正確性：
> 給它任何 roster（使用者/群組/HBAC/sudo 規則清單），套用後的即時狀態必須完全對應
> roster 宣告的內容——包含「roster 移除了什麼，live 狀態也要跟著移除」。
> 維護者：sre

> 對偶參照：**被授權的對象**（enrolled client 上的認證/授權接線）健康見
> `docs/verification/freeipa-client.md`；**目錄服務本身**健康見
> `docs/verification/freeipa-server.md`。本檔是**授權資料本身**（誰在哪個群組、
> 哪條 HBAC/sudo 規則授權了誰）是否確實反映 roster 的驗證。

## 0. 這份檔的狀態（先讀）

依 `AGENTS.md` §1「actual-run 規則」：寫進 `docs/verification/*.md` 步驟區塊的指令，
**必須先在對應目標環境實際跑過並截真實輸出**才算數。

本檔 **v1.6** 已交付 canonical `schema_version: 1` 與 `2` 的 users/groups/hosts/
hostgroups（含巢狀 membership）/HBAC/sudo/netgroups，以及 legacy `ipa_*`
compatibility。Canonical roster 必須透過 `freeipa_roster_file` namespaced
載入；直接 `-e @roster.yaml` 會讓 top-level `groups`/`hosts` 撞到 Ansible
magic variables，因此不受支援。一支 schema_version: 1 roster 不需要手動轉
版——`pilot edit`/MCP roster driver/`pilot deploy`/`pilot reconcile` 的
preflight 都會在打開 roster 時自動呼叫 `EnsureRosterCurrent` 升級到 v2
（已驗證、已備份、atomic），或用 `pilot roster migrate <file>` 明確觸發。
尚未交付的僅剩 `migration`（roster 內宣告式批次改名/刪除）這個獨立
fail-closed 工作流程——見 §5。

本檔 v1.0 的既有基線：`freeipa-identity-apply.yml` 在本次重新設計後（2026-07-16）新增了
三層能力——(1) 密碼自行變更保護（不覆蓋使用者已自行設定的密碼）、(2) 既有物件的
屬性 drift 修正（`*-mod` reconcile，取代原本 create-only 的 `*-add` no-op）、
(3) 成員/掛載關係的雙向 diff（roster 移除一筆，rerun 後 live 也真的移除）——
每一層都已對著本檔 §7 的 fixture 在活的 `freeipa-server` VM 上實測過。§2 的
checklist 驗證的是「套用 fixture 後的最終狀態」（單次快照，`pilot spec --generate`
的既定模型），§7 則是這幾層 reconciler 行為本身（roster 改了、rerun 之後會不會
真的生效）的可重現 SOP——這類「改 roster → rerun → 比較前後」的動態驗證天生不
適合塞進單指令一列的 checklist 格式，因此另立一節，不勉強塞進 §2。

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Inventory group | `freeipa-server`（fixture 與 checklist 皆對 FreeIPA server 本機跑，vm-target 測試用 `-e target_group=all`）|
| OS / version | 與 `freeipa-server.md` 相同（native AlmaLinux 9 `ipa-server-install`）|
| 角色 | `freeipa-identity-apply.yml` 本身不含任何使用者/群組/規則資料——它是純粹的 reconciler，資料一律由 `-e @<roster>.yaml` 注入 |
| 套用範圍 | 對 FreeIPA server 本機跑（`ansible.builtin.command` 直接呼叫本機 `ipa` CLI，非透過 SSH 到別台）|
| 風險等級 | High（本 playbook 直接增減真實使用者的登入/sudo 權限；§7.3 的移除語意已刻意做成「roster 移除一筆＝立即撤權」，誤刪 roster 一行等於誤撤真實權限）|

## 1.5 依賴變數契約

在套用或驗證此 playbook 時，roster 必須嚴格遵守以下命名（完整 schema 見
`playbooks/apply/freeipa-identity.roster.example.yaml`），禁止擅自縮寫或發明新變數：

| 變數名稱 | 說明/用途 | 是否必填 |
|---------|----------|---------|
| `freeipa_roster_file` | canonical roster 檔路徑；以 `include_vars: name=freeipa_roster` 載入，避免 `groups`/`hosts` magic-variable collision | canonical 必填 |
| `freeipa.admin.principal` / `freeipa.admin.password` | canonical kinit principal/密碼；密碼由 vault 保護，禁止 hard-code | canonical 必填 |
| `schema_version` / `users` / `groups` | canonical identity primitives，`1` 或 `2`；支援 attributes、state、authoritative direct/nested membership | canonical 必填 |
| `hostgroups[].membership.hostgroups` | 巢狀 hostgroup 成員（v1/v2 皆支援，authoritative，雙向 diff）；本檔 C19 驗證 | 否 |
| `netgroups` | schema-v2-only：可含 users/groups/hosts/hostgroups/nested netgroups，命名須符合 `^ng-[a-z0-9][a-z0-9_.-]*$`；`internal/inventory/roster_netgroup.go` 驗證 unique/collision/reference/cycle | 否（v1 roster 宣告此欄位會在 top-level-keys gate fail closed）|
| `ipa_admin_password` | kinit admin 用密碼；由 vault file 注入，禁止 hard-code | 是 |
| `ipa_domain` / `ipa_realm` | Kerberos/DNS domain/realm，預設 `ipa.pilot.internal` / `IPA.PILOT.INTERNAL` | 否（有預設）|
| `ipa_users` / `ipa_groups` / `ipa_hostgroups` / `ipa_hbac_rules` / `ipa_sudo_rules` | 五份資料清單，見 roster schema 檔 | 否（皆預設 `[]`，可只給其中幾份）|

> Checklist §2 查的是 fixture（`playbooks/test/fixtures/freeipa-identity-fixtures.yml`）
> 套用後的 LDAP 狀態，走 **root 透過 ldapi unix socket 的 SASL EXTERNAL autobind**——
> 跟 `freeipa-server.md` 的 `dsconf`（走 ldapi、免 Directory Manager 密碼）同一個機制，
> 而不是 `ipa` CLI（那需要一張 Kerberos ticket，checklist 指令不能內嵌管理密碼）。
> Socket 路徑固定為 `/run/slapd-IPA-PILOT-INTERNAL.socket`（與 realm 對應）。

## 2. Checklist

> 指令直接在 FreeIPA server 本機以 root 執行（`pilot verify` 走 ansible ad-hoc，
> `become: true`）。前置：先跑過 §7.1 的 legacy 與 canonical fixture。

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | membership | `fixture-user-a` 是 `fixture-group-a` 成員（roster 宣告的正向 membership）| 0 | ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "cn=fixture-group-a,cn=groups,cn=accounts,dc=ipa,dc=pilot,dc=internal" member 2>/dev/null | grep -q "uid=fixture-user-a," |
| C2 | membership | `fixture-user-b` **不是** `fixture-group-a` 成員（負向案例：沒宣告就沒有）| 0 | ! ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "cn=fixture-group-a,cn=groups,cn=accounts,dc=ipa,dc=pilot,dc=internal" member 2>/dev/null | grep -q "uid=fixture-user-b," |
| C3 | hbac | `fixture-hbac-a` 的 host category 正確套用 roster `hostcat: all` | ~hostCategory: all | ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "cn=hbac,dc=ipa,dc=pilot,dc=internal" "(cn=fixture-hbac-a)" hostCategory 2>/dev/null |
| C4 | hbac | `fixture-hbac-a` 掛載了 roster 宣告的 `groups: [fixture-group-a]` | ~memberuser: cn=fixture-group-a, | ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "cn=hbac,dc=ipa,dc=pilot,dc=internal" "(cn=fixture-hbac-a)" memberuser 2>/dev/null |
| C5 | sudo | `fixture-sudo-a` 沒有 `cmdCategory: all`（roster 給 `allow_commands`，證明「specific-list vs category 互斥」正確走 allow_commands 分支，沒被 cmdcat 蓋掉）| 0 | ! ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "cn=sudorules,cn=sudo,dc=ipa,dc=pilot,dc=internal" "(cn=fixture-sudo-a)" cmdCategory 2>/dev/null | grep -q "cmdCategory: all" |
| C6 | sudo | `fixture-sudo-a` 掛載了 roster 宣告的 `groups: [fixture-group-a]` | ~memberuser: cn=fixture-group-a, | ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "cn=sudorules,cn=sudo,dc=ipa,dc=pilot,dc=internal" "(cn=fixture-sudo-a)" memberuser 2>/dev/null |
| C7 | drift | `fixture-hostgroup-a` 的 `desc` 與 roster 完全一致（證明 `hostgroup-mod` 屬性 reconcile 有跑）| ~description: freeipa-identity spec fixture hostgroup | ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "cn=fixture-hostgroup-a,cn=hostgroups,cn=accounts,dc=ipa,dc=pilot,dc=internal" description 2>/dev/null |
| C8 | drift | `fixture-user-a` 的姓名（`sn`）與 roster 完全一致（證明 `user-mod` 屬性 reconcile 有跑）| ~sn: A | ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "uid=fixture-user-a,cn=users,cn=accounts,dc=ipa,dc=pilot,dc=internal" sn 2>/dev/null |
| C9 | canonical-user | canonical user 的 display name、email、shell 與 home 已收斂 | ~displayName: Canonical Alpha | ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "uid=fixture-canonical-user-a,cn=users,cn=accounts,dc=ipa,dc=pilot,dc=internal" displayName mail loginShell homeDirectory 2>/dev/null |
| C10 | canonical-state | `state: disabled` / `enabled: false` 真的鎖住帳號 | ~nsAccountLock: TRUE | ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "uid=fixture-canonical-user-b,cn=users,cn=accounts,dc=ipa,dc=pilot,dc=internal" nsAccountLock 2>/dev/null |
| C11 | canonical-membership | canonical team group 直接包含宣告的 user | ~member: uid=fixture-canonical-user-a, | ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "cn=team-fixture-canonical,cn=groups,cn=accounts,dc=ipa,dc=pilot,dc=internal" member 2>/dev/null |
| C12 | canonical-nesting | canonical filesystem group 直接包含宣告的 nested team group | ~member: cn=team-fixture-canonical, | ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "cn=data-fixture-canonical-rw,cn=groups,cn=accounts,dc=ipa,dc=pilot,dc=internal" member 2>/dev/null |
| C13 | canonical-hbac | canonical HBAC rule 掛載 access group 與 sshd service | ~memberUser: cn=access-fixture-canonical-ssh, | ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "cn=hbac,dc=ipa,dc=pilot,dc=internal" "(cn=fixture-canonical-hbac)" memberUser memberService 2>/dev/null |
| C14 | hbac-lockdown | break-glass enabled 且 `allow_all` disabled | ~ipaEnabledFlag: TRUE | ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "cn=hbac,dc=ipa,dc=pilot,dc=internal" "(cn=fixture-canonical-breakglass)" ipaEnabledFlag 2>/dev/null |
| C15 | canonical-sudo | canonical sudo command group 包含受限 command | ~member: ipaUniqueID= | ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "cn=fixture-service-read,cn=sudocmdgroups,cn=sudo,dc=ipa,dc=pilot,dc=internal" member 2>/dev/null |
| C16 | canonical-sudo | canonical sudo rule 掛載 role group 與 allow command group | ~memberUser: cn=role-fixture-canonical-ops, | ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "cn=sudorules,cn=sudo,dc=ipa,dc=pilot,dc=internal" "(cn=fixture-canonical-sudo)" memberUser memberAllowCmd 2>/dev/null |
| C17 | canonical-sudo | canonical sudo rule 含 specific run-as root 與 `!authenticate` | ~ipaSudoOpt: !authenticate | ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "cn=sudorules,cn=sudo,dc=ipa,dc=pilot,dc=internal" "(cn=fixture-canonical-sudo)" ipaSudoRunAsExtUser ipaSudoOpt 2>/dev/null |
| C18 | automount | FreeIPA indirect automount key 使用 FQDN 與 `sec=krb5i` | 0 | ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "cn=default,cn=automount,dc=ipa,dc=pilot,dc=internal" "(automountKey=fixture-alpha)" automountInformation 2>/dev/null | grep -Eq '^automountInformation: .*sec=krb5i.* [[:alnum:].-]+:/projects/fixture-alpha$' |
| C19 | hostgroup-nesting | `hostgroup-fixture-v2-parent` 直接包含宣告的巢狀 hostgroup（schema-v2 §8：`membership.hostgroups` 現在真的被 reconcile） | ~member: cn=hostgroup-fixture-v2-child, | ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "cn=hostgroup-fixture-v2-parent,cn=hostgroups,cn=accounts,dc=ipa,dc=pilot,dc=internal" member 2>/dev/null |
| C20 | netgroup | netgroup 直接包含宣告的 user（`memberUser`；netgroup 的 user 與 group 成員共用同一個 LDAP 屬性，不是分開的 `memberUser`/`memberGroup`——已對活體 server 查證，不是假設） | ~memberUser: uid=fixture-v2-user-a, | ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "cn=ng,cn=alt,dc=ipa,dc=pilot,dc=internal" "(cn=ng-fixture-v2-clients)" memberUser 2>/dev/null |
| C21 | netgroup | netgroup 直接包含宣告的 group（同一個 `memberUser` 屬性，見 C20 備註） | ~memberUser: cn=team-fixture-v2, | ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "cn=ng,cn=alt,dc=ipa,dc=pilot,dc=internal" "(cn=ng-fixture-v2-clients)" memberUser 2>/dev/null |
| C22 | netgroup | netgroup 直接包含宣告的 host（`memberHost`；host 與 hostgroup 成員也共用同一個屬性，同上已查證） | ~memberHost: fqdn=fixture-v2-host-a.ipa.pilot.internal, | ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "cn=ng,cn=alt,dc=ipa,dc=pilot,dc=internal" "(cn=ng-fixture-v2-clients)" memberHost 2>/dev/null |
| C23 | netgroup | netgroup 直接包含宣告的 hostgroup（同一個 `memberHost` 屬性，見 C22 備註） | ~memberHost: cn=hostgroup-fixture-v2-parent, | ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "cn=ng,cn=alt,dc=ipa,dc=pilot,dc=internal" "(cn=ng-fixture-v2-clients)" memberHost 2>/dev/null |
| C24 | netgroup-nesting | netgroup 直接包含宣告的巢狀 netgroup（`member`，一般 `member` 屬性，不是 `memberUser`/`memberHost`；netgroup-to-netgroup DN 一律是 `ipaUniqueID=<隨機值>`，不像其他型別有穩定的 `cn=` 形式，所以驗證存在性而非比對特定 UUID） | 0 | ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -b "cn=ng,cn=alt,dc=ipa,dc=pilot,dc=internal" "(cn=ng-fixture-v2-clients)" member 2>/dev/null | grep -q '^member: ipaUniqueID=' |

> **C19–C24 沿用同一套 SASL EXTERNAL/ldapi 唯讀查詢**，fixture 是
> `playbooks/test/fixtures/freeipa-identity-v2.roster.yaml`（schema_version: 2，
> 獨立於 v1 canonical fixture，不共用物件）。**C20–C23 的屬性名稱刻意對活體
> FreeIPA server 查證過**，不是照 `ipa netgroup-show` CLI 的人類可讀欄位名稱
> （`Member User:`/`Member Group:`/`Member Host:`/`Member Hostgroup:`/`Member
> netgroups:`）類推：底層 LDAP schema 把 user 和 group 成員合併進同一個
> `memberUser` 屬性、host 和 hostgroup 成員合併進同一個 `memberHost` 屬性，
> 只有巢狀 netgroup 走一般的 `member` 屬性——這五個標籤在 CLI 上看起來分開，
> 在 LDAP 上其實只有三種屬性。這類「CLI 顯示欄位 ≠ 底層儲存屬性」的落差，
> 正是 `freeipa-dns.md` changelog 記載過的同一類風險（規則格式假設一旦猜錯，
> 檢查會靜默失敗或永遠讀到空值），此處查證方式：先在活體 server 上用
> `ipa netgroup-add-member` 建好每種成員，再直接 `ldapsearch` 讀原始屬性，
> 而非假設 CLI 標籤與 LDAP 屬性同名。

> **rc 型 expected（C1/C2/C5 = `0`）比對 process 退出碼**：C1/C2 直接對 `grep -q` 的
> rc；C2/C5 用 shell `!` 反轉（`grep` 找不到才是我們要的「pass」），跟
> `freeipa-server.md` C17/C18 的無狀態動態 skip 用同一招。
> **`~`（contains）型 expected（C3/C4/C6/C7/C8）**：ldapsearch 輸出直接 grep 該行；
> 用 `-o ldif-wrap=no -LLL` 關掉 78 欄自動換行，否則長 DN 被截斷換行會讓 `grep -q`
> 因為字串被行斷點切開而漏判（實測踩過：預設換行下 `memberuser: cn=fixture-group-a,...`
> 這行剛好卡在斷點附近，穩定性不能只靠運氣）。
> **為什麼不用 `ipa` CLI**：`ipa sudorule-show`/`hbactest` 等指令都需要先
> `kinit admin`，而 admin 密碼不能寫進這份會進 git 的 spec 檔——改走
> root 對 ldapi unix socket 的 SASL EXTERNAL autobind（跟 `freeipa-server.md`
> 的 `dsconf` 同一個「本機 root 免密碼」機制），純唯讀查詢，不會意外碰到真實資料。

## 3. 證據收集

- 工具：`pilot vm-target verify --name <server-vm> docs/verification/freeipa-identity.md`
  （真實主機：`pilot verify docs/verification/freeipa-identity.md -i inventory-freeipa.yaml`）
- 前置：先套用 legacy 與 canonical v1 fixture（見 §7.1），C19–C24 另外需要
  §7.1a 的 schema-v2 fixture
- 格式：`.verification/freeipa-identity-<UTC>.{ndjson,md}`
- 預期 row 數：24

**目前真實輸出摘要**（`freeipa-identity-v2` AlmaLinux 9 VM，2026-07-22 同時套用
legacy 與 canonical fixture 後實跑；完整 stdout/row payload 留在 raw artifact，正式
candidate 的 immutable revision 與 evidence link 見 runbook §0.5）：

```
$ pilot vm-target verify --name freeipa-identity-v2 docs/verification/freeipa-identity.md
✔ NDJSON:   .verification/freeipa-identity-20260722-032722.ndjson
✔ Report:   .verification/freeipa-identity-20260722-032722.md

verdict: PASS  (pass=12 fail=0 skip=0)
```

**Schema-v2 / C19–C24 真實輸出**（`freeipa-server` vm-target，2026-08-11 依序套用
legacy、canonical v1、schema-v2 三份 fixture 後實跑；C19–C24 首次加入時單獨驗證
`pass=6 fail=0`，此處是三份 fixture 都套用後的完整 24-row 結果）：

```
$ pilot vm-target run --name freeipa-server playbooks/test/fixtures/freeipa-identity-v2-fixtures.yml \
    -e fixtures_target_group=all -e ipa_admin_password=NewPass123!
freeipa-server             : ok=53   changed=13   unreachable=0    failed=0    skipped=80

# 立刻重跑一次：
freeipa-server             : ok=52   changed=0    unreachable=0    failed=0    skipped=81

$ pilot vm-target verify --name freeipa-server docs/verification/freeipa-identity.md
✔ NDJSON:   .verification/freeipa-identity-20260811-061431.ndjson
✔ Report:   .verification/freeipa-identity-20260811-061431.md

verdict: PASS  (pass=24 fail=0 skip=0)
```

> C19–C24 一開始單獨跑（尚未套用 legacy/canonical v1 fixture）時，其餘既有 row
> 如預期 `fail`（fixture 物件在這次全新 VM 狀態下還不存在）——這不是本次交付
> 的 regression，純粹是同一顆 VM 上 legacy/canonical fixture 沒重新套用過；
> 套用 §7.1 兩份既有 fixture 後同一份 spec 立刻變成 24/24 PASS，證明 C19–C24
> 與既有 18 row 彼此獨立、互不干擾。

> 這個 PASS 也順帶驗證了一個更大的發現：`pilot spec --generate` 過去有個
> dedup 邏輯錯誤（見 v1.0 changelog、`internal/spec/generator.go`），凡是
> Command 沒對到 Pattern A-F（`test -f`/`grep`/`sysctl -n`/`systemctl
> is-active`/`dpkg -s`/`awk print`）而落到 raw fallback 分支的 row，全部
> 會被錯誤地當成同一個 dedup key，只留下第一條的指令，其餘 row 的 ID 被
> 錯貼在那一個 task 上——本檔最初套用舊版產生器時，8 條就是活生生的例子
> （8 rows → 7 deduped，只剩 1 個 task）。修好後才重新產生本檔的
> `playbooks/verify/freeipa-identity.yml`，也連帶重新產生了本 repo受影響的
> 其他既有 spec（`freeipa-server`/`freeipa-client`/`core-infra*`/`docker`/
> `keycloak`/`os-patch-sla`/`seaweedfs-s3`/`freeipa-server-replica`）。

## 4. PASS / FAIL 規則

- C1–C24 全部 `status=pass` → **PASS**：reconciler 套用 legacy、canonical v1
  與 schema-v2 三份 fixture 後，LDAP 裡的成員關係、規則屬性、物件屬性完全對應
  roster 宣告的內容（C19–C24 額外驗證巢狀 hostgroup 與 netgroup 五種 membership
  型別）。
- 任一 `fail` → **FAIL**，常見修法：
  - C1/C2 fail → 確認 §7.1 fixture 已套用過、fixture 的 group/user 名稱沒被改過；
    若 C2 fail（fixture-user-b 意外變成員），檢查是不是誤把兩個 fixture 使用者的
    `groups:` 寫反了。
  - C3/C4/C5/C6 fail → 檢查 `freeipa-identity-apply.yml` 的
    "Ensure sudo/HBAC rules exist"、"Reconcile sudo/HBAC rule category attributes"、
    "Attach hostgroups/groups to sudo/HBAC rules" 這幾個 task 有沒有跑過、有沒有
    因為 "Gate: sudo rule category vs specific-list fields are mutually exclusive"
    擋下（fixture roster 本身不該觸發這個 gate，若觸發表示 fixture 檔被改壞了）。
  - C7/C8 fail → 檢查 "Reconcile IPA hostgroup descriptions"/"Reconcile user
    first/last names" 這兩個 `*-mod` task 有沒有跑、`changed_when`/`failed_when`
    是否誤判成 no-op。
  - Socket 路徑找不到（`ldap_sasl_interactive_bind: Can't contact LDAP server`）→
    確認 389-ds instance 名稱是否仍是 `slapd-IPA-PILOT-INTERNAL`
    （`find /run -iname '*slapd*sock*'` 確認實際路徑）。
  - C19 fail → 檢查 "Ensure nested hostgroup membership"（`tags: [identity,
    hostgroups]`）有沒有跑過；C20–C23 fail → 檢查 "Ensure netgroup direct
    user/group/host/hostgroup membership"（`tags: [identity, netgroups]`）；
    C24 fail → 檢查 "Ensure nested netgroup membership"。四者皆需先套用
    §7.1a 的 schema-v2 fixture。

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C1–C12 | 本 checklist 只驗證「套用 fixture 後的單次快照」，不驗證 reconciler 的 ADD/REMOVE/drift-correction 動態行為本身（roster 改了、rerun 之後真的生效）——那部分見 §7 的 SOP，不強塞進 `pilot spec` 的單指令快照模型 | 全部 | 永久 |
| — | `migration`（roster 內宣告式批次改名/刪除）仍是獨立的 fail-closed 工作流程，尚未交付；playbook 對非空值 fail closed，不把忽略欄位偽裝成成功。Users/groups/hosts/hostgroups（含巢狀）/HBAC/sudo/netgroups 皆已交付 | canonical roster | 待定 |
| — | netgroup 巢狀 cycle 偵測（`ng-a → ng-b → ng-a` 這類）只在 Go 層（`internal/inventory/roster_netgroup.go`、`pilot roster lint`）擋，**沒有**在 `freeipa-identity-apply.yml` 重複實作同一個檢查——刻意的設計決策：Jinja 沒有安全的方式走任意深度 graph traversal，硬做風險（見 `freeipa-dns.md` changelog 記載過的規則格式假設猜錯、靜默失效案例）大於效益。前提：roster 必須先過 `pilot roster lint`（或走 `pilot edit`/`EnsureRosterCurrent` 的自動升級路徑）才套用——繞過 `pilot` 直接手改 roster 再 `ansible-playbook` 套用的人，本來就已經在其他既有 gate（Go validator 完全沒跑到）的保護範圍之外 | 直接 `ansible-playbook`（不經 `pilot`）套用 netgroups 的情境 | 永久 |
| — | 本 spec 不含密碼自行變更保護（§7.4）的 checklist row：該行為的證據（`krbLastPwdChange`/`krbPasswordExpiration` 前後比對）本質是「rerun 前後對比」，同樣不適合單指令快照——手動走 §7.4 的 SOP 驗證 | 全部 | 永久 |
| — | 本 spec 不含 netgroup authoritative pruning（roster 移除一個 netgroup 成員、rerun 後 live 真的移除）的 checklist row，理由同 C1–C12——這是「改 → rerun → 比較」動態行為，見 §7.1a 的 pruning 驗證記錄 | 全部 | 永久 |

## 6. Playbook 對應

對應的 verify playbook（`playbooks/verify/freeipa-identity.yml`）**已於 2026-07-17 棄用**
（僅存檔參考，見該目錄 README.md）；驗收直接 `pilot verify` 吃本 spec 執行。

對應手寫的 **apply** playbook：`playbooks/apply/freeipa-identity-apply.yml`

| Spec ID | Apply task（tag）| 備註 |
|---------|-----------------|------|
| C1/C2 | `Ensure user group membership` + `Remove stale group memberships`（`tags: [identity, users, groups]`）| 後者是本次新增的移除半邊 |
| C3/C5 | `Reconcile HBAC/sudo rule category attributes`（`tags: [identity, hbac]`/`[identity, sudo]`）| 本次新增：既有規則的 category 也會被 `-mod` 修正 |
| C4/C6 | `Attach groups to HBAC/sudo rules` + `Remove stale groups from HBAC/sudo rules` | 後者是本次新增的移除半邊 |
| C7 | `Reconcile IPA hostgroup descriptions`（`tags: [identity, hostgroups]`）| 本次新增 |
| C8 | `Reconcile user first/last names`（`tags: [identity, users]`）| 本次新增 |
| C9/C10 | `Ensure IPA users exist`、`Reconcile user first/last names`、`Reconcile canonical account enabled state`（`tags: [identity, users]`）| canonical attribute/state reconcile |
| C11/C12 | `Ensure/Remove stale canonical direct user/nested-group membership`（`tags: [identity, users, groups]`）| authoritative direct membership |
| C19 | `Ensure nested hostgroup membership` + `Remove stale nested hostgroup memberships`（`tags: [identity, hostgroups, C19]`）| roster-schema-v2 migration spec §8；`membership.hostgroups` 從完全未 reconcile 變成 authoritative |
| C20/C21 | `Ensure netgroup direct user membership`（`C20`）+ `Ensure netgroup direct group membership`（`C21`）+ 對應的 `Remove stale netgroup direct user/group membership` | netgroup 的 user/group 成員在 LDAP 層共用 `memberUser`，Ansible 層仍是各自獨立的 task/roster 欄位 |
| C22/C23 | `Ensure netgroup direct host membership`（`C22`）+ `Ensure netgroup direct hostgroup membership`（`C23`）+ 對應的 `Remove stale netgroup direct host/hostgroup membership` | 同上，LDAP 層共用 `memberHost` |
| C24 | `Ensure nested netgroup membership` + `Remove stale nested netgroup membership`（`tags: [identity, netgroups, C24]`）| 建立順序：所有 `state: present` netgroup 物件先建完，才開始接 nested membership，YAML 宣告順序不影響結果 |

## 7. 把 FAIL 變 PASS 的 SOP（fixture 套用 + reconciler 動態行為驗證）

### 7.1 套用 fixture

```bash
pilot vm-target run --name <server-vm> playbooks/test/fixtures/freeipa-identity-fixtures.yml \
    -e fixtures_target_group=all -e @~/.vault/main.yaml
pilot vm-target run --name <server-vm> playbooks/test/fixtures/freeipa-identity-canonical-fixtures.yml \
    -e fixtures_target_group=all -e @~/.vault/main.yaml
```

冪等：重跑應只剩 `Kinit admin`/`Release the Kerberos ticket` 之外全部 `ok`
（實測：首次套用 `changed=10`，第二次重跑除既有的「密碼相關」/「disable allow_all」
兩個已知的非冪等雜訊外，其餘全 `ok`）。

### 7.1a 套用 schema-v2 fixture（netgroups + 巢狀 hostgroup，C19–C24 前置）

```bash
pilot vm-target run --name <server-vm> playbooks/test/fixtures/freeipa-identity-v2-fixtures.yml \
    -e fixtures_target_group=all -e @~/.vault/main.yaml
```

真實輸出（`freeipa-server` vm-target，2026-08-11）：

```
首次套用：ok=53  changed=13  failed=0  skipped=80
立刻重跑：ok=52  changed=0   failed=0  skipped=81
```

**Netgroup authoritative pruning 驗證**（本節是 roster-schema-v2 migration
spec §25 的即時驗證，跟 §7.3 的既有 user/group 撤銷驗證是同一類「改 →
rerun → 比較」動態行為，理由同樣不適合塞進 §2 單指令快照）：

```bash
# 1. 手動在 live 端幫 ng-fixture-v2-clients 加一個 roster 沒宣告的 member：
pilot vm-target exec --name <server-vm> -- sudo ipa netgroup-add-member ng-fixture-v2-clients --users=admin
# 2. 重新套用 fixture（roster 沒變，membership.users 仍只有 fixture-v2-user-a）：
pilot vm-target run --name <server-vm> playbooks/test/fixtures/freeipa-identity-v2-fixtures.yml \
    -e fixtures_target_group=all -e @~/.vault/main.yaml
# → changed=1（只有 "Remove stale netgroup direct user membership" 顯示 changed）
# 3. 確認 live 狀態真的撤銷了：
pilot vm-target exec --name <server-vm> -- \
    ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket \
    -b "cn=ng,cn=alt,dc=ipa,dc=pilot,dc=internal" "(cn=ng-fixture-v2-clients)" memberUser
#    → 只剩 uid=fixture-v2-user-a 與 cn=team-fixture-v2；uid=admin 已消失
```

實測於 2026-08-11：步驟 2 的 `changed=1` 與步驟 3 的 LDAP 查詢結果都與上述描述
一致——手動加的 `admin` 成員在下一次 apply 就被移除，且移除後同一份 spec 立刻
重驗（`pilot vm-target verify`）仍是 24/24 PASS，證明 pruning 不會誤刪
roster 本來就宣告的成員。

### 7.2 執行 checklist

```bash
pilot vm-target exec --name <server-vm> -- true   # 暖連線
pilot vm-target verify --name <server-vm> docs/verification/freeipa-identity.md
```

### 7.2a Check-mode 安全性閘門（`pilot deploy`／`pilot reconcile` 的 preview 也要跑過，不能只信 `pilot vm-target verify`）

**2026-07-16（v4.9 全新環境重跑）發現並修好**：`pilot vm-target verify`（§7.2）
從不用 `--check` 模式跑 Ansible，所以 v4.8 reconciler 改版加的 5 個
`set_fact`「算出待移除項目」任務——只要它們前面那個 `command`/`shell`
lookup 任務在 check mode 下被 Ansible 自動跳過（`ansible.builtin.command`/
`shell` 本來就不支援 check mode），accumulator fact 就完全沒被設過，後面
任何無條件引用它的任務就會直接爆 `'<name>' is undefined`——**這個 spec
之前的驗證從來沒抓到過**，是靠這次真的把 `pilot deploy` 的 mandatory
preview 開起來對一個全新環境跑才第一次踩到。已在
`playbooks/apply/freeipa-identity-apply.yml`加上`\| default(...)`修好
（`ipa_pwd_needs_reset`/`ipa_group_membership_removals`/
`ipa_hostgroup_membership_removals`/`ipa_hbac_removals`/
`ipa_sudo_removals`，共 12 處呼叫點）。**往後任何修改這支 playbook 的人，
在只跑完 §7.2 的 `pilot vm-target verify` 之後，還必須額外跑一次這個**：

```bash
ansible-playbook playbooks/apply/freeipa-identity-apply.yml \
    -i <inventory.yml> -e stage=sandbox -e @<roster.yaml> \
    --check --diff
# 對一台「從沒真的 apply 過」的全新主機跑，PLAY RECAP 必須 failed=0——
# 只對已經真的套用過一次的主機跑，看起來會綠燈但其實沒測到這個 class 的問題
# （跟 minimal-poc-architecture.md §3.2a 的 v4.1→v4.2 教訓一模一樣）。
```

### 7.3 驗證「roster 移除一筆＝立即撤權」（Phase 2 動態行為）

```bash
# 1. 把 fixture-user-a 從 fixture-group-a 移除（改 fixtures playbook 的
#    ipa_users[0].groups，或直接對某個真實 roster 做一樣的事），重跑：
pilot vm-target run --name <server-vm> playbooks/test/fixtures/freeipa-identity-fixtures.yml \
    -e fixtures_target_group=all -e @~/.vault/main.yaml
# 2. 確認 live 狀態真的撤權了：
pilot vm-target exec --name <server-vm> -- \
    ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket \
    -b "cn=fixture-group-a,cn=groups,cn=accounts,dc=ipa,dc=pilot,dc=internal" member
#    → 不應再看到 fixture-user-a
# 3. 加回去、重跑，確認又出現——完整往返，實測於 2026-07-16（本 session 用
#    demo 環境的 alice/sysops 做過同款往返，含 hbactest 從 granted→denied→granted）。
```

### 7.4 驗證「使用者自行設定的密碼不被覆蓋」（Phase 0 動態行為）

```bash
# 1. 對某個 force_password: true 的使用者，模擬他自己完成改密碼（3 行：
#    舊密碼、新密碼、新密碼再一次）：
pilot vm-target exec --name <server-vm> -- kinit <user>   # 依提示輸入 3 行
# 2. 記錄此刻的 krbLastPwdChange：
pilot vm-target exec --name <server-vm> -- \
    ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket \
    -b "uid=<user>,cn=users,cn=accounts,dc=ipa,dc=pilot,dc=internal" krbLastPwdChange
# 3. 重跑 apply（roster 的 force_password: true 沒動）：
pilot vm-target run --name <server-vm> playbooks/apply/freeipa-identity-apply.yml \
    -e target_group=all -e @<roster>.yaml
# 4. 再查一次 krbLastPwdChange，應與步驟 2 完全相同（沒被重設）——實測於
#    2026-07-16（demo 環境 alice：兩次查詢皆為 20260716064701Z，密碼確實沒被動）。
```

## 8. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-16 | v1.0 | 初版：`freeipa-identity-apply.yml` 從 create-only 重設計為真正的 infra-as-code reconciler（密碼自行變更保護、屬性 drift reconcile、成員/掛載關係雙向 diff），新增 `playbooks/test/fixtures/freeipa-identity-fixtures.yml` fixture，checklist C1–C8 全數對著活的 `freeipa-server` VM 實測。§7 記錄了 reconciler 動態行為（roster 增減、密碼保護）的可重現驗證 SOP，因其「改 → rerun → 比較」的本質不適合塞進 §2 的單指令快照模型 | pilot |
| 2026-07-16 | v1.1 | 全新 3-VM 環境（`docs/runbooks/minimal-poc-architecture.md` v4.9）重新走一遍完整 delivery-test 流程時，發現 v1.0 從未驗證過的一個真實缺口：`pilot vm-target verify`（§7.2）不會用 `--check` 模式跑 Ansible，所以 reconciler 自己的 5 個 `set_fact` 「算待移除項目」任務在 check mode 下全部因為前面 lookup 任務被跳過而拿到未定義變數，讓 `pilot deploy` 自己的 mandatory preview 直接崩潰——這正是本 spec 從未在意的一種行為，現已修好（`\| default(...)` 共 12 處）並新增 §7.2a 這道 SOP 閘門，往後任何人改這支 playbook 都必須額外對一台全新主機跑一次 `--check --diff` 確認 `failed=0`，不能只信 §7.2 綠燈。同一次重跑也順便再驗證了一遍 §7.3/§7.4 的動態行為（移除/恢復/密碼保護），結果與 v1.0 一致 | pilot |
| 2026-07-22 | v1.2 | 依 implementation plan 完成 delivery batch 1：canonical v1 users/groups normalization、validation、attributes、disabled state、direct/nested authoritative membership 與 legacy compatibility；新增 C9–C12。實測發現 canonical top-level `groups`/`hosts` 與 Ansible magic variables 衝突，正式入口改為 `freeipa_roster_file` namespaced load | pilot |
| 2026-07-22 | v1.3 | C18 移除舊 fixture host `freeipa-nfs-v2.ipa.pilot.internal` 的硬編碼，改以 rc matcher 同時驗證 `sec=krb5i`、合法 FQDN 與固定 remote path；新 matcher 已透過 `pilot verify --probe` 對 Nexus 的真實 IPA automount entry 實跑 PASS，evidence：`.verification/minimal-poc-update/2026-07-22-round-12/dev-probe-identity-c18/probe.cast` | pilot |
| 2026-07-30 | v1.4 | 修復真實 bug（`freeipa-dns` Phase 5 minimal-poc round-18 重建時發現）：「`Gate: canonical top-level and FreeIPA keys are known`」（~行 156-161）的 `freeipa.*` 允許清單硬寫成 `['server', 'admin', 'defaults', 'safety']`，遺漏 `domain`/`realm` —— 但 `internal/inventory/roster_validate.go` 的 `knownFreeIPAKeys` 明確允許這兩個欄位（其註解本身就寫著「the apply playbook deliberately ignores them」，即這兩個欄位存在時 apply 應該容忍、非拒絕）。`pilot edit`'s NFS-role-add bootstrap（`WriteMinimalNFSServerRoster`）本身就會在 roster 寫入 `freeipa.domain`，代表**任何透過官方 sanctioned 工具鏈建立的 roster，只要曾走過 NFS bootstrap，套用 `freeipa-identity` reconcile 就必定在第一個 gate 就 fail**——`pilot roster lint` 完全不會抓到（Go validator 本來就允許），只有真的跑 `ansible-playbook` 才會顯現。修法：把這兩個欄位加進 assert 的允許清單，使其與 Go-side schema 一致。 | pilot |
| 2026-07-30 | v1.5 | 修復真實 bug（使用者回報「`pilot edit` 裡新增的 user，`enabled` 欄位顯示 `false`，但 reconcile 之後卻登得進去」，兩台獨立 AlmaLinux 9 vm-target 上對活的 FreeIPA server 實測重現）：`freeipa-identity-apply.yml` 本身的 enable/disable 邏輯是對的——顯式 `enabled: false` 套用後 `ipa user-show --all --raw` 確認 `nsaccountlock: TRUE`，且 `kinit` 直接被 KDC 拒絕（`Client's credentials have been revoked`）；真正的 bug 在 `pilot edit` 的 roster manager：`internal/inventory/roster.go`'s `AppendRosterUser`（`rosterUserStub{Name, State}`）新增 user 時完全不寫 `enabled` 欄位，而 `cmd/pilot/cmd/edit_tui_roster.go` 的欄位清單畫面卻用 `rosterBoolDisplay`（缺欄位一律顯示 `false`）顯示這個欄位——但 playbook 對缺欄位的實際預設是 `item.enabled \| default(true)`（第 910、357 行）。結果：編輯畫面告訴使用者「這個帳號是 disabled」，reconcile 卻把它當 enabled 套用，activate 之後真的能 `kinit`/登入，兩邊完全對不上。連帶發現 `password.preserve_existing` 欄位有同一類 bug（顯示預設 `false`，playbook 實際預設 `true`，第 360 行）。修法：`AppendRosterUser`/`SimulateAddRosterUser` 新增 user 時明確寫入 `enabled: true`（比照既有 HBAC/sudo rule stub 建立時就明寫 `enabled: true` 的慣例），`enabled`/`password.preserve_existing` 兩處顯示欄位改用 `rosterBoolDisplayDefault(..., true)`，讓沒有這兩個欄位的既有/手改 roster 也能顯示與 playbook 一致的有效值。`go test ./internal/inventory/... ./cmd/pilot/cmd/...` 全綠(4 個既有無關失敗維持不變)。 | pilot |
| 2026-08-11 | v1.6 | Roster-schema-v2 migration 交付（spec.md 11-phase 實作全數完成）：schema v2 版本判定/驗證（`internal/inventory/roster_version.go`/`roster_validate.go`）、v1→v2 純 in-memory migration + semantic-equivalence fingerprint（`roster_migrate.go`）、mutation lock/backup/atomic write/rollback（`roster_migrate_file.go`）、`pilot roster migrate`/`pilot roster lint --upgrade`、TUI/MCP/`pilot deploy`/`pilot reconcile` preflight 全面自動升級（`EnsureRosterCurrent`）、netgroups 首次成為 first-class schema 物件（`roster_netgroup.go` + `freeipa-identity-apply.yml` 的 create/reconcile-membership/authoritative-prune/delete-absent 五種成員型別）、hostgroup 巢狀 membership 從完全未 reconcile 變成 authoritative（`membership.hostgroups`，本檔新增 §8 §6/§8 前身 issue，見 C19）、NFS export selector 新增 hostgroup/netgroup 型別（`@value` 渲染，`freeipa-nfs-exports.j2`）、ansible-vault 加密 roster 的 migration 支援（真實 `ansible-vault` binary，never 落地 plaintext temp file）。本檔新增 C19–C24（netgroup 五種 membership 型別 + hostgroup 巢狀 membership），與既有 C1–C18 一起在 `freeipa-server` vm-target 上依序套用 legacy/canonical v1/schema-v2 三份 fixture 後實跑 24/24 PASS；另外實測 netgroup authoritative pruning（手動加一個 roster 未宣告的 member、重新 apply 後確認被移除，見 §7.1a）。**兩個非顯而易見的真實 gotcha，皆已對活體 FreeIPA server 查證、非假設**：(1) `ipa netgroup-show --all` 的成員欄位標籤是單數且不一致——`Member User:`/`Member Group:`/`Member Host:`/`Member Hostgroup:`（均單數）但 `Member netgroups:`（小寫、複數），跟其他物件類型的慣例（如 `group-show` 的 `Member users:`，複數）都不一樣；(2) 同一組成員在底層 LDAP 完全是另一套屬性名稱——netgroup 的 user 與 group 成員共用 `memberUser`、host 與 hostgroup 成員共用 `memberHost`、nested netgroup 走一般的 `member`（不是 `memberGroup`/`memberHostgroup`/`memberNetgroup`），且 netgroup-to-netgroup 的 DN 一律是不可預測的 `ipaUniqueID=<uuid>`（不像其他物件類型有穩定的 `cn=` 形式）。netgroup 巢狀 cycle 偵測刻意只留在 Go 層（`pilot roster lint`），未在 Ansible 重複實作，理由與已知限制見 §5。`go test ./...`（1626 tests）、`ansible-playbook --syntax-check`、`go vet`、`gofmt`、`-race` 全綠。 | pilot |
