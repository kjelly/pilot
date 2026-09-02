# Pilot FreeIPA Client Host DNS — Day-2 IP Replacement 實作規格

- **日期**：2026-09-02
- **狀態**：DRAFT — implementation-ready
- **目標 repository**：`kjelly/pilot`
- **設計基準**：`1f4f77d88d1930c523f83676e64324beb4ff6bc4`（原草稿基準 `c397390` 已核驗落後 17 commits，但全部為 deploy/inventory `sameHosts` cascade 與 monitoring 相關工作，未觸及本規格依賴的任何 freeipa-client/DNS 檔案，故直接更新為 current HEAD）
- **落版位置**：`docs/superpowers/specs/2026-09-02-freeipa-client-host-dns-ip-replacement-spec.md`（已落版）
- **主要影響元件**：`freeipa-client`、`pilot edit`、FreeIPA authoritative DNS registration
- **相容性要求**：不得削弱現有 fail-closed / no implicit takeover；既有初次 enrollment 與 DNS backfill 行為必須保持相容

---

## 1. 交付目標

目前 Pilot 的 `freeipa-client` host DNS lifecycle 能安全處理：

1. 新主機 enrollment 後建立 A/AAAA；
2. 已 enrollment、但 DNS 缺少 desired address 時補建；
3. DNS owner 已存在不屬於 desired set 的 address 時 fail-closed，拒絕 implicit takeover。

但正常的 Day-2 操作「**同一台已受 Pilot / FreeIPA 管理的主機變更 IP**」會被第三項安全閘門擋下：

```text
old authoritative DNS: host1.<domain> -> 10.20.30.41
new desired address:   host1.<domain> -> 10.20.30.61

current - desired = [10.20.30.41]
=> authoritative DNS must not conflict with desired addresses
=> fail-closed / no implicit takeover
```

本功能要讓 Pilot 能辨識「**已 enrollment 的同一 host，且 operator 明確授權從 expected-old IP 遷移**」的情況，安全地將 A/AAAA RRset 收斂到新的 desired address，而不要求 operator 先登入 FreeIPA 手動 `dnsrecord-mod`。

### 1.1 核心要求

本功能 MUST：

- 保留現有 `no implicit takeover` 原則；
- 預設仍是 add-only：沒有明確 replacement acknowledgement 時，任何 `current - desired != ∅` 都 MUST fail；
- replacement 僅可作用於**已成功 enrollment 且可證明持有既有 host keytab 的同一台 client**；
- 使用 expected-old compare-and-swap（CAS）語意，不得用永久性 `allow_replace: true`；
- mutation 前 MUST 再讀一次 authoritative DNS 並重新驗證 CAS，避免 TOCTOU；
- mutation 後 MUST 驗證 authoritative A/AAAA 集合與 desired **完全相等**；
- 不得刪除同 owner 下的 TXT、SSHFP 或其他不屬於本 feature 的 RR；
- `--check --diff` MUST 能顯示 replacement plan，且零 mutation；
- `pilot edit` 修改受管 `freeipa-client` 的 `ansible_host` IP 時，應提供安全的 expected-old acknowledgement UX。

---

## 2. 現況與問題根因

### 2.1 現行實作

主要檔案：

```text
playbooks/apply/tasks/freeipa-client-host-dns.yml
playbooks/apply/freeipa-client-apply.yml
contracts/freeipa-client.yaml
docs/verification/freeipa-client.md
internal/spec/freeipa_client_regression_test.go
```

現行 `freeipa-client-host-dns.yml`：

1. 在 `plan` phase 直接 query selected FreeIPA server 的 authoritative DNS；
2. 取得 A、AAAA、CNAME；
3. 計算：

```text
current = authoritative A/AAAA addresses
desired = freeipa_client_dns_addresses
          or ansible_default_ipv4.address

extra   = current - desired
missing = desired - current
```

4. 只要 `extra` 非空就 fail：

```text
Gate: authoritative DNS must not conflict with desired addresses
(spec.md §8.2/§8.3, fail-closed, no implicit takeover)
```

5. apply phase 目前只有 `dnsrecord-add` missing values，沒有 replacement path。

這個安全行為本身是正確的；問題是 Pilot 尚未建模「**受管 host 的合法 IP migration**」。

### 2.2 不可接受的修法

Coding agent MUST NOT 用以下方式解決：

- 移除或弱化 `ipa_client_dns_extra` gate；
- 遇到 extra 就直接 `dnsrecord-mod`；
- 新增永久性的 `freeipa_client_dns_allow_replace: true`；
- 把新舊 IP 同時塞進 desired 來繞過 conflict；
- 關閉 `freeipa_client_register_dns` 來繞過錯誤；
- 把每台 client hostname 移到 `freeipa-dns.yaml` service-DNS manifest 管理；
- 對 owner 執行無 value/type 範圍限制的 `ipa dnsrecord-del <zone> <owner>`；
- 使用 `--all-ip-addresses` 或預設啟用 dynamic DNS update；
- 依賴 `getent hosts` / `ping` 判斷 authoritative DNS 狀態。

---

## 3. 設計原則

### 3.1 Fail-closed 不變

原本：

```text
missing only -> ADD
extra exists -> FAIL
```

改成：

```text
missing only
    -> ADD

extra exists
    + explicit expected-old acknowledgement
    + same enrolled host identity proven
    + CAS still matches immediately before mutation
    -> REPLACE

extra exists
    + any prerequisite missing/mismatch
    -> FAIL CLOSED
```

### 3.2 不使用永久 allow flag

本版新增的是 expected-old CAS token：

```yaml
freeipa_client_dns_replace_from_address: 10.20.30.41
```

它的意思不是「這個 host 以後都允許 takeover」，而是：

> 本次 desired-state migration 僅授權移除 authoritative DNS 中精確等於 `10.20.30.41` 的 stale address；若 live DNS 已不是這個值，不得 mutation。

因此下次 IP 再改時，例如：

```text
10.20.30.61 -> 10.20.30.81
```

舊的 acknowledgement `10.20.30.41` 不會吻合 authoritative `extra=[10.20.30.61]`，部署 MUST 再次 fail-closed，直到 operator 明確更新 expected-old address。

### 3.3 V1 scope：一次授權一個 stale address

為避免擴大 `pilot edit` inventory scalar model 與 replacement blast radius，V1 的 acknowledgement 是**單一 IP literal**。

V1 MUST：

- `extra` 恰好只有一個 address 才可能進入 REPLACE；
- 該唯一 `extra` MUST 等於 `freeipa_client_dns_replace_from_address`；
- `extra` 有兩個以上時 MUST fail-closed；
- desired set 仍可包含多個 address；
- IPv4 與 IPv6 都要支援單一 stale address replacement。

同時更換舊 IPv4 + 舊 IPv6 等「multiple stale extras」列為 V2/non-goal，不得在 V1 用模糊規則自動判定。

---

## 4. 新增 contract / configuration

### 4.1 `contracts/freeipa-client.yaml`

新增 optional non-secret host/group var：

```yaml
- name: freeipa_client_dns_replace_from_address
  type: string
  required: false
  secret: false
```

若目前 contract schema 使用 inline form，應遵循現有檔案風格：

```yaml
- {name: freeipa_client_dns_replace_from_address, type: string, required: false, secret: false}
```

### 4.2 語意

`freeipa_client_dns_replace_from_address`：

- 未設定 / 空字串：沒有 replacement authorization；
- 設定：必須是合法 IPv4 或 IPv6 literal；
- 只授權 authoritative `extra` 中**精確一個** stale address；
- 不代表 desired address；desired 仍由既有 `freeipa_client_dns_addresses` 或 fallback 決定；
- 不得自動由 playbook 猜測；
- 不得由 DNS current state 自動回填；
- 可由 `pilot edit` 在 operator 明確確認後寫入；
- deploy 成功後 playbook MUST NOT 回寫/修改 source inventory；
- 若 authoritative 已完全等於 desired，殘留 acknowledgement MUST 被視為 harmless stale acknowledgement，不得造成 change 或 failure。

### 4.3 IP canonicalization

所有參與集合比較的 IP：

- desired addresses；
- authoritative A/AAAA；
- `freeipa_client_dns_replace_from_address`；

MUST 先用 Python stdlib `ipaddress.ip_address()` 正規化後比較。

IPv6 MUST 使用 `.compressed` canonical form，避免：

```text
2001:0db8:0000:0000::1
2001:db8::1
```

被錯誤判定為不同地址。

不得新增 Python 外部 dependency。

### 4.4 Reserved address policy

`freeipa_client_dns_replace_from_address` MUST 套用與 desired address 相同的 IP policy：

- reject loopback；
- reject unspecified；
- reject multicast；
- reject link-local；
- malformed literal -> fail before any mutation。

---

## 5. Desired / Current / CAS 狀態模型

定義：

```text
D = desired authoritative address set
C = current authoritative A/AAAA address set
E = C - D    # extra / stale / conflicting
M = D - C    # missing
R = normalized freeipa_client_dns_replace_from_address, optional
```

### 5.1 狀態轉移表

| 條件 | Plan action | 結果 |
|---|---|---|
| DNS registration disabled | `DISABLED` | no-op |
| owner 有 CNAME | `CONFLICT_CNAME` | fail-closed |
| `E=∅`, `M=∅` | `NOOP` | changed=0 |
| `E=∅`, `M!=∅` | `ADD` | 走既有 backfill path |
| `E!=∅`, `R` 未設定 | `CONFLICT_UNAUTHORIZED` | fail-closed |
| `E!=∅`, `|E|>1` | `CONFLICT_MULTI_EXTRA` | fail-closed |
| `E={x}`, `R!=x` | `CONFLICT_CAS_MISMATCH` | fail-closed |
| `E={R}`, host identity 無法證明 | `CONFLICT_IDENTITY_UNPROVEN` | fail-closed |
| `E={R}`, host identity proven | `REPLACE` | apply phase re-check 後 mutation |
| `E=∅`, `R` 有值 | `NOOP_STALE_ACK` | changed=0 + debug only |

### 5.2 `ADD` 與 `REPLACE` 不得混淆

`ADD`：

- authoritative current 沒有任何 undesired value；
- 只補 missing；
- 沿用現行行為。

`REPLACE`：

- authoritative current 至少有一個 undesired value；
- 只有 CAS + identity proof 都成立才可執行；
- mutation 後 authoritative address set 必須完全等於 D。

---

## 6. 同一台已 enrollment host 的 identity proof

Replacement 的安全核心不是「FQDN 一樣」；而是必須能證明現在由 inventory 新 IP 連上的 target 持有既有 FreeIPA host credential。

### 6.1 Fresh / unenrolled host 永遠不得 REPLACE

Plan phase 在 DNS replacement 判定前 MUST 讀取：

```text
/etc/ipa/default.conf
/etc/krb5.keytab
```

如果 replacement candidate 存在，但任一不存在：

```text
CONFLICT_IDENTITY_UNPROVEN
```

MUST fail before `/etc/hosts`、hostname、package installation、enrollment 等 mutation。

### 6.2 將 enrollment read-only probe 提前到 `pre_tasks`

現行 `freeipa-client-apply.yml` 對 `/etc/ipa/default.conf` 的 `stat` 位於 tasks 後段。

本功能 MUST：

1. 在 DNS plan include 之前加入 read-only `stat`；
2. 將結果保存成單一 canonical fact/register；
3. 後續 installer gate MUST reuse 同一結果；
4. 不得為本 feature 複製兩套「是否已 enrollment」判定。

目標順序：

```text
pre_tasks
  resolve selected FreeIPA server
  resolve desired client FQDN
  stat /etc/ipa/default.conf          # read-only
  stat /etc/krb5.keytab               # read-only when needed
  include DNS phase=plan              # zero mutation

tasks
  existing mutation path
  ipa-client-install only if not enrolled
  health checks
  include DNS phase=apply
```

### 6.3 Local FreeIPA config 必須一致

對 replacement candidate，MUST read-only 驗證 `/etc/ipa/default.conf` 至少能對應：

```text
host   == ipa_client_fqdn
realm  == ipa_realm
```

若檔案中有可可靠取得的 domain/server 欄位，也 MUST 與本次 selected deployment 一致。

不得因欄位缺失自行猜測另一套 realm/domain。

### 6.4 必須證明持有 exact host keytab principal

僅檢查檔案存在不夠。

Replacement candidate MUST 使用獨立 ccache 執行 read-only credential proof：

```text
kinit -k -t /etc/krb5.keytab host/<ipa_client_fqdn>@<ipa_realm>
```

要求：

- principal 必須是 exact FQDN + exact realm；
- 使用 dedicated temporary ccache；
- `changed_when: false`；
- ccache 最終必須清理；
- 不得輸出 credential/keytab material；
- `kinit` 失敗 -> fail-closed；
- 不接受僅以 hostname、`/etc/hosts`、DNS resolve 成功作為 ownership proof。

這能證明目前連到的 target 實際持有該 FreeIPA host principal 的 key material，而不只是使用相同 hostname。

### 6.5 Server-side host existence

若現有 helper/API 能在不新增第二套 auth flow 的前提下 read-only 驗證 `ipa host-show <fqdn>`，SHOULD 一併驗證。

但 V1 的 mandatory identity gate 是：

```text
existing enrollment config
+ exact host keytab principal
+ successful keytab kinit
```

不得以「server-side host-show 成功但 client 無有效 keytab」放行。

---

## 7. Plan phase 行為

### 7.1 Plan 必須在任何 mutation 前完成

保留目前架構：

```text
freeipa_client_dns_phase: plan
```

位於 `pre_tasks` 且在 `/etc/hosts` pin 之前。

所有以下操作均為 read-only：

- desired resolve；
- address validation/canonicalization；
- authoritative DNS query；
- CNAME conflict query；
- current/extra/missing 計算；
- enrollment/config/keytab probe；
- host-keytab `kinit` proof；
- action selection。

### 7.2 Plan debug output

現有 DNS plan debug MUST 擴充，至少顯示：

```text
registration: ENABLED
fqdn: host1.ipa.pilot.internal
current: [10.20.30.41]
desired: [10.20.30.61]
extra: [10.20.30.41]
missing: [10.20.30.61]
replace_from: 10.20.30.41
action: REPLACE
identity_proof: PASS
```

不得顯示：

- `ipa_admin_password`；
- keytab content；
- Kerberos ticket；
- ccache content。

### 7.3 Action MUST 被保存

Plan phase MUST 保存足以讓 apply phase驗證的 facts，例如：

```text
ipa_client_dns_plan_action
ipa_client_dns_plan_current_addresses
ipa_client_dns_plan_desired_addresses
ipa_client_dns_plan_extra
ipa_client_dns_plan_missing
ipa_client_dns_replace_from_effective
ipa_client_dns_identity_proven
```

命名可依現有風格調整，但不得讓 apply phase只依「plan 曾經 PASS」就直接 mutation；apply 必須 live re-query。

---

## 8. Apply phase：TOCTOU / CAS re-check

### 8.1 Mutation 前重新查 authoritative DNS

對 `REPLACE`，apply phase在取得 mutation credential 後、第一個 DNS write 之前 MUST：

1. 重新 query authoritative A；
2. 重新 query authoritative AAAA；
3. 重新 query CNAME；
4. 套用與 plan 完全相同的 response validity parsing；
5. canonicalize current values；
6. 重新計算 `E2`、`M2`；
7. 重新驗證：

```text
CNAME absent
|E2| == 1
E2 == {R}
identity_proven == true
```

任何一項改變：

```text
FAIL CLOSED — authoritative state changed after planning
```

不得 mutation。

### 8.2 不可把 plan snapshot 當作 apply truth

禁止：

```text
plan says REPLACE
=> apply directly dnsrecord-mod using old snapshot
```

必須是：

```text
plan says REPLACE
=> apply re-read
=> CAS matches NOW
=> mutate
```

這是防止另一個 operator / automation / replica propagation 在 plan 與 apply 中間改掉 DNS 後被 Pilot 覆寫。

---

## 9. DNS mutation 規則

### 9.1 不得 owner-wide delete

本功能 MUST NOT 執行：

```bash
ipa dnsrecord-del <zone> <owner>
```

因為同一 owner 可能還有 Pilot 不擁有的 TXT 等 RR。

所有 delete 必須限定 record type/value。

### 9.2 優先 reuse 現有 FreeIPA DNS reconciler pattern

`playbooks/apply/freeipa-dns-apply.yml` 已有 live-tested：

```text
dnsrecord-add
dnsrecord-mod
dnsrecord-del
```

以及 A/AAAA value reconcile pattern。

Coding agent SHOULD reuse相同的：

- CLI attribute naming；
- comma-joined multi-value semantics；
- changed/no-op interpretation；
- post-verify pattern；
- dedicated admin ccache / `no_log` convention。

不得建立另一套推測 FreeIPA CLI 行為的 implementation。

### 9.3 同一 RR family 的 replacement

例如：

```text
current A = [10.20.30.41]
desired A = [10.20.30.61]
```

應使用：

```text
dnsrecord-mod A RRset -> exact desired A values
```

使同 family replacement 盡量在單一 FreeIPA command 完成，避免先刪除造成空窗。

### 9.4 `old + new` 已同時存在

例如：

```text
current A = [10.20.30.41, 10.20.30.61]
desired A = [10.20.30.61]
extra     = [10.20.30.41]
missing   = []
R         = 10.20.30.41
```

這仍是合法 `REPLACE`/prune case。

必須將 A RRset 收斂到：

```text
[10.20.30.61]
```

不得因 `missing=[]` 就跳過 stale removal。

### 9.5 Cross-family replacement

若唯一 stale 是某 family，而 desired 改到另一 family，例如：

```text
current A    = [10.20.30.41]
desired AAAA = [2001:db8::61]
```

mutation 順序 MUST：

1. 先建立/收斂 desired family；
2. 再 value-scoped 刪除 authorized stale family/value；
3. exact post-verify。

不得先把唯一 owner address 刪掉再新增，避免不必要的 NXDOMAIN/empty window。

### 9.6 Multi-value desired family

如果 desired family 有多個合法值，而唯一 stale `E={R}` 已授權，`dnsrecord-mod` MUST 將該 family 收斂到完整 desired family set，而不是只加一個 missing value後留下其他 drift。

---

## 10. Post-apply authoritative verification

### 10.1 修正現有「exact」驗證缺口

目前 task 名稱/訊息表示：

```text
matches desired addresses exactly
```

但現行 assert 實際只檢查：

```text
desired - post == ∅
```

這只證明 missing 為空，不能證明沒有 extra。

本功能實作時 MUST 一併修正成真正 exact equality：

```text
(post - desired) == ∅
AND
(desired - post) == ∅
```

或等價的 canonical sorted-set equality。

### 10.2 Exact verification 套用所有 action

此強化 MUST 套用：

- `ADD`；
- `REPLACE`；
- 任一實際執行過 DNS write 的 path。

避免 race 導致 Pilot 在 apply 後仍留下未宣告 address 卻誤報成功。

### 10.3 CNAME 仍需驗證

Post-write SHOULD 再確認 owner 沒有 CNAME conflict；若 authoritative state 出現不可能的 CNAME/drift，fail，不得把 apply 當成功。

---

## 11. `pilot edit` UX

### 11.1 觸發條件

當 operator 在 `pilot edit` 修改某 host 的：

```text
ansible_host: OLD_IP -> NEW_IP
```

且：

- OLD/NEW 都是合法 IP literal；
- OLD != NEW；
- host roles 包含 `freeipa-client`；

TUI MUST 顯示明確 confirmation。

### 11.2 建議提示

語意至少要讓 operator 看見 host、old、new 與實際影響，例如：

```text
This host uses freeipa-client.
Authorize Pilot to replace its authoritative host DNS only when the
existing stale address is exactly 10.20.30.41?

Host: host1
Connection IP: 10.20.30.41 -> 10.20.30.61
Expected stale DNS: 10.20.30.41

[Yes] [No]
```

文案可符合 Pilot 現有 TUI 語言，但不得只顯示模糊的「Allow DNS update?」。

### 11.3 Operator 選 Yes

儲存：

```yaml
ansible_host: 10.20.30.61
freeipa_client_dns_replace_from_address: 10.20.30.41
```

目前 inventory host model 的 `Extra map[string]string` 可容納此 scalar；V1 不應為這個功能順便重構全部 host extras 成 typed list。

### 11.4 Operator 選 No

只修改：

```yaml
ansible_host: 10.20.30.61
```

不得寫入 replacement acknowledgement。

後續若 authoritative DNS 仍是 OLD_IP，deploy 應按照既有 fail-closed 行為停止，並給 actionable error。

### 11.5 第二次再改 IP

若 inventory 中已殘留：

```yaml
freeipa_client_dns_replace_from_address: 10.20.30.41
```

之後 operator 再改：

```text
10.20.30.61 -> 10.20.30.81
```

並再次選 Yes，TUI MUST overwrite 為：

```yaml
freeipa_client_dns_replace_from_address: 10.20.30.61
```

不得沿用第一次的 OLD_IP。

### 11.6 非 IP / 非 freeipa-client

以下情境 MUST 不自動產生 acknowledgement：

- `ansible_host` 是 hostname 而不是 IP literal；
- host 沒有 `freeipa-client` role；
- old/new 相同；
- old 值不存在。

operator 仍可進階手動設定 contract var，但 deploy safety gates 不變。

### 11.7 Automation semantics

已核驗 current HEAD 現況（`cmd/pilot/cmd/edit_tui.go`、`edit_actions_registry.go`、`edit_automation.go`、`edit_automation_driver_dns.go`）：

- `ansible_host` 欄位編輯目前走的是通用 `pushHostFieldEdit`（`edit_tui.go` 內的一般 host field editor），**沒有**專屬 automation driver；
- `edit_automation_driver_dns.go` 已存在，但範圍僅限 freeipa-dns zone/record manifest 畫面，不涵蓋 freeipa-client host IP 編輯這條路徑；
- 因此本功能在 Phase 4 實質上是**新建**這個欄位的 automation-driver 整合點，而非單純延伸一個已涵蓋此 flow 的既有 action。

Coding agent MUST：

- 沿用既有 `edit_actions_registry.go` / `edit_automation.go` 的 registry 慣例與 automation action 語意（不得另創一套平行機制）；
- 讓 interactive TUI 路徑與 automation/action-driven 路徑共用同一組 explicit acknowledgement semantics；
- 不得讓 automation path 繞過 human/explicit authorization requirement；
- 不得另外建立與 TUI 完全不同的 hidden mutation path；
- 開始實作前仍 MUST 重新讀一次 current HEAD 上述檔案，確認上述現況未被更新的 commit 改變。

---

## 12. Manual configuration UX

即使不透過 `pilot edit`，operator 也可以明確設定：

```yaml
freeipa_client_dns_replace_from_address: 10.20.30.41
```

### 12.1 Error message 必須可操作

當偵測：

```text
current = [10.20.30.41]
desired = [10.20.30.61]
extra   = [10.20.30.41]
```

但沒有 acknowledgement，fail message MUST 至少包含：

```text
host/FQDN
current authoritative address(es)
desired address(es)
stale/extra address(es)
```

並說明兩個安全選項：

1. 若這確實是同一已 enrollment host 的 IP migration，設定：

```yaml
freeipa_client_dns_replace_from_address: 10.20.30.41
```

2. 若不是同一 host，手動解決 DNS/ownership conflict；不要設定 acknowledgement。

不得把「直接關掉 fail-closed gate」列為建議。

### 12.2 CAS mismatch error

例如：

```text
expected old: 10.20.30.41
live extra:   10.20.30.51
```

MUST 明確報：

```text
replacement authorization is stale / does not match live authoritative DNS
```

且零 mutation。

---

## 13. Check mode

### 13.1 Existing fresh-topology exemption 不得擴大

目前 fresh clean-room `--check` 因 FreeIPA server 尚未真正 install，authoritative DNS response gate 有 check-mode exemption。

這個 exemption只適用「**真正 fresh topology、尚無可驗證 authority**」的 preview。

對：

```text
already-enrolled client
+ replacement acknowledgement present
```

`--check --diff` 若無法 query authoritative DNS，就**不能**宣稱 CAS 可安全 replacement。

因此 replacement intent 下 MUST fail-closed：

```text
cannot verify authoritative DNS for requested replacement
```

### 13.2 `--check --diff` REPLACE preview

當 authority 可達且 CAS/identity 都成立，preview MUST 顯示：

```text
action: REPLACE
remove: [old]
add: [new]       # 若有
final: [desired]
```

但 MUST：

- 不執行 `dnsrecord-mod`；
- 不執行 `dnsrecord-del`；
- 不執行 `dnsrecord-add`；
- 不修改 inventory；
- 不修改 `/etc/hosts`；
- 不修改 hostname；
- 不 install package / enroll。

Read-only `dig` / `stat` / keytab `kinit` proof 可執行，前提是符合目前 check-mode read-only convention。

---

## 14. Security / safety invariants

以下 invariant MUST 由 tests 鎖住：

### S1 — No implicit takeover

沒有 `freeipa_client_dns_replace_from_address` 時，`extra != ∅` 永遠 fail。

### S2 — Exact CAS

V1 只在：

```text
extra == {replace_from}
```

時允許 replacement。

### S3 — Single stale address only

`|extra| > 1` 永遠 fail。

### S4 — Existing host identity proof

Fresh / unenrolled / invalid-keytab target 永遠不能使用 replacement acknowledgement takeover 既有 owner。

### S5 — Apply-time re-read

任何 REPLACE write 之前都要重新 query authoritative DNS。

### S6 — No owner-wide deletion

不得刪除整個 DNS owner。

### S7 — Foreign RR preservation

同 owner 的 TXT/其他非 A/AAAA record 必須存活。

### S8 — Exact final state

成功後：

```text
authoritative A/AAAA set == desired set
```

### S9 — Secret hygiene

所有 admin kinit / credential path 繼續遵守 `no_log` / dedicated ccache；replacement 不新增 secret log。

### S10 — Existing address policy remains

現有：

```text
explicit first IPv4 == ansible_default_ipv4.address
```

與 multi-NIC fail-closed policy不得為本功能放寬。

---

## 15. Idempotency

### 15.1 Replacement 第一次成功

第一次：

```text
current=[old]
desired=[new]
R=old
=> REPLACE
=> changed > 0
```

### 15.2 第二次 rerun

成功後 source inventory 可仍保留：

```yaml
freeipa_client_dns_replace_from_address: old
```

第二次：

```text
current=[new]
desired=[new]
extra=[]
missing=[]
R=old
=> NOOP_STALE_ACK
=> changed=0
```

不得因 stale acknowledgement 強制再次 `dnsrecord-mod`。

### 15.3 不由 apply 自動清 acknowledgement

Ansible apply MUST NOT 修改 operator source inventory / host_vars 來移除 CAS field。

理由：

- deployment playbook 不應擁有 source-of-truth writer side effect；
- stale acknowledgement 本身沒有權限放寬，因下次 replacement live `extra` 必須再精確匹配；
- `pilot edit` 下次 IP change 會在再次確認後 overwrite expected-old。

---

## 16. 預期修改檔案

Coding agent MUST 先重新讀 current HEAD；下列為 baseline 預期，不得因檔名在後續 commit 有變更就硬套舊行號。

### 16.1 必改

```text
playbooks/apply/tasks/freeipa-client-host-dns.yml
playbooks/apply/freeipa-client-apply.yml
contracts/freeipa-client.yaml
group_vars/freeipa.example.yml
docs/verification/freeipa-client.md
internal/spec/freeipa_client_regression_test.go
cmd/pilot/cmd/edit_tui.go                    # 或 current HEAD 的 host edit implementation
```

### 16.2 依 current architecture 找到並更新

```text
cmd/pilot/cmd/edit_actions_registry.go       # action registry；本功能需在此登錄新 action
cmd/pilot/cmd/edit_automation.go             # automation action 執行語意
cmd/pilot/cmd/edit_automation_driver_dns.go  # 現有 driver 範例（僅涵蓋 freeipa-dns manifest，非本 flow，可參考其 pattern）
cmd/pilot/cmd/*edit*_test.go
cmd/pilot/cmd/*automation*_test.go
internal/inventory/*                         # 僅在現有 scalar Extra writer 真的需要調整時
```

### 16.3 不應修改責任邊界

本功能不應把 client host DNS 搬到：

```text
freeipa-dns.yaml
playbooks/apply/freeipa-dns-apply.yml
```

`freeipa-dns-apply.yml` 只作為已驗證 FreeIPA DNS mutation/reconcile pattern 的參考與可重用 helper 來源；若要抽 shared helper，必須維持兩個 feature 的 ownership semantics，不得把 lifecycle 合併成同一 manifest。

---

## 17. 建議 implementation decomposition

### Phase 1 — Spec / contract / regression guard

1. 新增 contract var；
2. 更新 example config；
3. 在 regression tests 先鎖：
   - no implicit takeover；
   - CAS field；
   - exact final-set assert；
   - no owner-wide delete；
   - plan-before-mutation sequencing。

### Phase 2 — Read-only plan model

1. canonicalize D/C/R；
2. 建立 action state machine；
3. 提前 enrollment stat；
4. 建立 keytab identity proof；
5. 新增 REPLACE plan output；
6. 尚不新增 mutation。

此 phase 結束時，可在真實 client 看到：

```text
action=REPLACE
```

但 apply 仍不得真正 replacement。

### Phase 3 — Apply re-check + mutation

1. dedicated credential setup；
2. live authoritative re-query；
3. CAS re-check；
4. same-family `dnsrecord-mod`；
5. 必要時 cross-family add-then-value-delete；
6. exact post-verify；
7. cleanup ccache。

### Phase 4 — `pilot edit` integration

1. hook old/new `ansible_host` change；
2. freeipa-client role detection；
3. explicit confirmation；
4. scalar Extra persistence；
5. 於 `edit_actions_registry.go` / `edit_automation.go` 新增本欄位的 automation action（現況沒有現成 driver 可延伸，見 §11.7）；
6. TUI unit/driver tests。

### Phase 5 — Live VM verification + evidence

依 §19 完整矩陣執行，不得只跑 syntax/unit tests 就宣告完成。

---

## 18. Automated test requirements

### 18.1 Contract / static regression

至少新增：

1. `freeipa_client_dns_replace_from_address` 已登錄、optional、string、non-secret；
2. replacement 不引入 `--all-ip-addresses`；
3. replacement 不引入 default `--enable-dns-updates`；
4. plan include 仍在任何 mutation前；
5. enrollment/keytab read-only probe 在 DNS replacement plan 可取得；
6. REPLACE apply path 有 authoritative re-query；
7. REPLACE 有 apply-time CAS gate；
8. 不存在 owner-wide `dnsrecord-del <zone> <owner>` path；
9. post-apply exact verification同時檢查 both differences；
10. credential command遵守 `no_log` / ccache hygiene。

### 18.2 State-machine tests

至少涵蓋：

| Case | Current | Desired | R | Identity | Expected |
|---|---|---|---|---|---|
| A | `[]` | `[new]` | unset | n/a | ADD |
| B | `[new]` | `[new]` | unset | n/a | NOOP |
| C | `[old]` | `[new]` | unset | pass | FAIL unauthorized |
| D | `[old]` | `[new]` | `old` | pass | REPLACE |
| E | `[old]` | `[new]` | `wrong` | pass | FAIL CAS mismatch |
| F | `[old1,old2]` | `[new]` | `old1` | pass | FAIL multi-extra |
| G | `[old]` | `[new]` | `old` | fail | FAIL identity |
| H | `[old,new]` | `[new]` | `old` | pass | REPLACE/prune |
| I | `[new]` | `[new]` | `old` | pass | NOOP_STALE_ACK |
| J | IPv6 expanded old | compressed desired | matching canonical R | pass | canonical comparison correct |

若 state machine 目前只能存在 Ansible/Jinja，仍 MUST 用 regression fixture 或 helper tests 覆蓋；若為了可測性抽成 Python stdlib helper，禁止加入外部 Python library。

### 18.3 `pilot edit` tests

至少涵蓋：

1. freeipa-client `old IP -> new IP`, confirm Yes：
   - `ansible_host=new`；
   - `freeipa_client_dns_replace_from_address=old`。
2. 同情境 confirm No：
   - 只改 `ansible_host`；
   - 不新增 CAS field。
3. 已有舊 CAS，第二次 IP change confirm Yes：overwrite 為 immediately previous IP。
4. non-freeipa-client host：不提示/不寫 CAS。
5. hostname -> IP / IP -> hostname：不自動寫 CAS。
6. automation driver 與 interactive path 語意一致。

### 18.4 Check-mode tests

至少涵蓋：

- fresh topology 既有 exemption 不 regression；
- already-enrolled replacement + reachable authority -> REPLACE preview / zero write；
- already-enrolled replacement + unreachable authority -> fail-closed；
- check mode不得因 skipped mutation誤報 completed replacement。

---

## 19. Mandatory live VM test matrix

依 Pilot 既有 infrastructure feature 規範，本功能 MUST 在 disposable VM 上做真實 FreeIPA 測試。

最低 topology：

```text
1 x AlmaLinux 9 FreeIPA server with native DNS
2 x Ubuntu 24.04 FreeIPA clients
```

實際 OS 版本若 current Pilot verification baseline 已更新，以 current baseline 為準，但必須是真實 FreeIPA + 真實 client，不接受 mock-only。

### L1 — Clean enrollment regression

1. clean client；
2. deploy freeipa-client；
3. A record建立；
4. authoritative dig 正確；
5. rerun `changed=0`。

目的：replacement 不能破壞原本 create/backfill path。

### L2 — Day-2 IPv4 migration happy path

起始：

```text
host1 -> OLD_IP
DNS   -> OLD_IP
```

讓同一 VM/host 實際改成 NEW_IP，並更新 inventory：

```yaml
ansible_host: NEW_IP
freeipa_client_dns_replace_from_address: OLD_IP
```

驗證：

1. plan = REPLACE；
2. keytab identity proof PASS；
3. apply 真實改 authoritative DNS；
4. final A/AAAA exact desired；
5. OLD_IP 不存在；
6. rerun `changed=0`。

### L3 — No acknowledgement

同一 migration，但不設 R：

- fail in plan；
- DNS 完全不變；
- `/etc/hosts` / hostname / enrollment config 在該失敗 run 不被 Pilot 先修改。

### L4 — Wrong/stale acknowledgement

```text
DNS extra = OLD_IP
R         = WRONG_IP
```

- fail CAS mismatch；
- zero DNS mutation。

### L5 — Fresh-host takeover attempt

建立新 VM，inventory 使用與既有 DNS owner相同的 FQDN/desired，並手動給正確 R。

因新 VM 沒有有效既有 host keytab：

- MUST fail identity proof；
- MUST NOT takeover DNS；
- MUST NOT先 enrollment 再藉此變成可 replacement。

這是本 feature 最重要的負向安全測試之一。

### L6 — Old + new coexist cleanup

先人工建立：

```text
A = [OLD_IP, NEW_IP]
D = [NEW_IP]
R = OLD_IP
```

驗證 Pilot 安全 prune OLD，final exact `[NEW_IP]`。

### L7 — Foreign TXT preservation

同 owner先加：

```text
TXT = foreign-record-should-survive
A   = OLD_IP
```

執行 replacement後：

```text
A   = NEW_IP
TXT = foreign-record-should-survive
```

TXT 必須完全存活。

### L8 — CNAME conflict regression

保留現有 CNAME-at-owner fail-closed 行為，replacement acknowledgement不得繞過。

### L9 — Apply-time race / CAS invalidation

必須證明 apply phase re-query 真的有效。

可用 test hook / controlled pause / 分階段 fixture，在 plan完成後、DNS write 前將 authoritative stale address從：

```text
OLD_IP -> OTHER_IP
```

期望：

- apply-time CAS re-check fail；
- Pilot 不把 OTHER_IP 覆寫成 desired；
- error明確指出 live authoritative state changed。

若 Ansible task無自然 pause，coding agent可用專用 disposable verification harness，不得為 production path 加 sleep/debug backdoor。

### L10 — `--check --diff`

對 L2 同一情境先跑 check mode：

- 顯示 REPLACE plan；
- authoritative DNS不變；
- target configuration不變；
- 再 real apply後成功。

### L11 — IPv6 canonicalization

至少有一個 live 或強等價 integration test確認 expanded/compressed IPv6不產生 false conflict。

---

## 20. Verification spec 更新

`docs/verification/freeipa-client.md` MUST：

1. 保留 C11 authoritative DNS 直接查詢原則；
2. 更新 C11/新增適當 row，涵蓋 Day-2 replacement；
3. 記錄 replacement 的 fail-closed prerequisite；
4. 記錄 exact post-state semantics；
5. changelog 新增本版日期/版本；
6. 指向 live VM evidence；
7. 明確說明 multiple stale extras 仍為 V1 non-goal；
8. 不再寫成「IP 改變只能人工清 DNS」的永久操作方式。

若 acceptance row numbering已被 current HEAD 更新，coding agent MUST 依 current 文件調整，不得為了符合本規格硬改既有 row ID。

---

## 21. Observability / operator diagnostics

### 21.1 Failure categories

建議 debug/error至少可清楚區分：

```text
DNS_AUTHORITY_UNVERIFIABLE
DNS_CNAME_CONFLICT
DNS_REPLACE_UNAUTHORIZED
DNS_REPLACE_MULTI_EXTRA
DNS_REPLACE_CAS_MISMATCH
DNS_REPLACE_IDENTITY_UNPROVEN
DNS_REPLACE_STATE_CHANGED
DNS_POST_VERIFY_MISMATCH
```

不要求一定建立 enum，但 human-visible message MUST 能分辨根因。

### 21.2 Error output 不得只印 generic assert

例如 unauthorized conflict 應能看到：

```text
FQDN
live current
live extra
desired
required acknowledgement value
```

identity failure 應說明是：

```text
replacement requires proof of an already-enrolled client with the exact host keytab principal
```

但不得輸出 keytab/ticket/secret material。

---

## 22. Backward compatibility

### 22.1 未設定新欄位

所有未設定：

```text
freeipa_client_dns_replace_from_address
```

的既有環境 MUST 保持原行為：

- missing-only -> add；
- exact match -> no-op；
- extra -> fail-closed。

### 22.2 DNS registration disabled

`freeipa_client_register_dns=false` 或 effective disabled：

- 新 replacement field不得觸發任何 DNS query/mutation side effect；
- plan output可指出 acknowledgement ignored because registration disabled；
- 不應因此 fail deployment。

### 22.3 Existing server capability detection

selected FreeIPA server沒有 native DNS 時，現有 gate 行為不變；replacement field不得強制開啟 DNS registration。

---

## 23. Non-goals

V1 明確不做：

1. generic DNS takeover；
2. replacement multiple stale extras；
3. multi-NIC divergent DNS vs `ansible_default_ipv4.address` policy；
4. PTR / reverse DNS migration；
5. service DNS manifest ownership改造；
6. GSS-TSIG dynamic DNS update；
7. FreeIPA replica topology ownership arbitration；
8. 自動判斷「看到舊 IP 就一定是同一 host」；
9. fresh host reuse existing FQDN 的自動 takeover；
10. 自動刪除 operator source inventory 中的 acknowledgement；
11. 以 DNS TTL propagation 等待機制取代 authoritative exact verify；
12. 對非 A/AAAA RR 做 reconciliation。

---

## 24. Definition of Done

Coding agent 只有在以下全部成立時可宣告完成。

### 24.1 Code / static quality

- [ ] current HEAD archaeology完成，沒有覆蓋較新的行為；
- [ ] contract lint pass；
- [ ] `gofmt` clean；
- [ ] `go vet ./...` pass；
- [ ] `go test ./...` pass；
- [ ] Ansible syntax check pass；
- [ ] Ansible lint符合 repo 現有門檻；
- [ ] `pilot spec --lint`（若 current HEAD仍提供此命令）pass。

### 24.2 Safety

- [ ] no implicit takeover invariant仍存在；
- [ ] CAS exact-match test存在；
- [ ] fresh host takeover負向測試存在；
- [ ] apply-time re-query / race test存在；
- [ ] no owner-wide DNS delete test存在；
- [ ] foreign TXT preservation live-tested；
- [ ] final authoritative set exact equality已修正。

### 24.3 UX

- [ ] `pilot edit` IP change可建立 expected-old acknowledgement；
- [ ] operator可拒絕 acknowledgement；
- [ ] 第二次 IP change會更新 expected-old；
- [ ] automation/non-interactive path不能隱式繞過 acknowledgement；
- [ ] error message提供可直接採取的下一步。

### 24.4 Live evidence

- [ ] §19 L1-L10 全部完成；
- [ ] IPv6 canonicalization至少 integration/live 有證據；
- [ ] first replacement changed > 0；
- [ ] immediate rerun `changed=0`；
- [ ] evidence path記錄於 `docs/verification/freeipa-client.md` changelog / evidence section。

---

## 25. Coding agent 實作約束

### 25.1 先重新讀 current HEAD

本規格以 baseline：

```text
c39739018a39961d421deb439db8cc8921619a5f
```

撰寫。

開始實作前 MUST：

1. fetch current `main`/default branch；
2. 重新讀本規格列出的實際檔案；
3. 檢查 baseline 後是否已有 DNS/IP lifecycle 改動；
4. 若 current HEAD 已有更好的安全機制，整合而不是退回 baseline；
5. 不可只按本文件舊行號 patch。

### 25.2 Spec-first / test-first

實作順序 MUST 優先：

```text
spec/verification expectation
-> regression tests
-> implementation
-> live VM validation
-> evidence update
```

不得先放寬 gate讓 happy path過，再補安全測試。

### 25.3 Reuse existing semantics

MUST 優先 reuse Pilot 既有：

- authoritative `dig` parser；
- FreeIPA DNS CLI mutation pattern；
- dedicated Kerberos ccache pattern；
- `no_log` secret handling；
- `pilot edit` host writer；
- automation action semantics；
- verification/evidence conventions。

不得建立第二套未驗證的平行 framework。

### 25.4 不得偷偷擴 scope

若 implementation 發現 V1 需要大改 typed inventory model、DNS ownership ledger、replica consensus 等，先保持本規格安全最小集；不得為了「順便做漂亮」擴成無關大改。

---

## 26. Acceptance examples

### 26.1 Happy path

Before：

```yaml
# host inventory
host1:
  ansible_host: 10.20.30.41
  roles:
    - freeipa-client
```

Authoritative：

```text
host1.ipa.pilot.internal. A 10.20.30.41
```

Operator 將同一 host 改為 `10.20.30.61`，`pilot edit` confirm replacement：

```yaml
host1:
  ansible_host: 10.20.30.61
  roles:
    - freeipa-client
  freeipa_client_dns_replace_from_address: 10.20.30.41
```

Target 實際 default IPv4：

```text
10.20.30.61
```

Plan：

```text
current:      [10.20.30.41]
desired:      [10.20.30.61]
extra:        [10.20.30.41]
missing:      [10.20.30.61]
replace_from: 10.20.30.41
identity:     PASS
action:       REPLACE
```

Apply final：

```text
host1.ipa.pilot.internal. A 10.20.30.61
```

Second rerun：

```text
current: [10.20.30.61]
desired: [10.20.30.61]
action: NOOP_STALE_ACK
changed=0
```

### 26.2 Unsafe takeover attempt

Existing DNS：

```text
host1.ipa.pilot.internal. A 10.20.30.41
```

Fresh machine宣稱：

```yaml
ansible_host: 10.20.30.61
freeipa_client_dns_replace_from_address: 10.20.30.41
```

但 fresh machine沒有 existing valid：

```text
host/host1.ipa.pilot.internal@IPA.PILOT.INTERNAL keytab credential
```

結果：

```text
action: CONFLICT_IDENTITY_UNPROVEN
FAIL before mutation
DNS remains 10.20.30.41
```

### 26.3 Stale CAS

```text
R:       10.20.30.41
current: 10.20.30.51
desired: 10.20.30.61
```

結果：

```text
CONFLICT_CAS_MISMATCH
zero mutation
```

---

## 27. 最終行為摘要

實作完成後，Pilot 對 client host DNS 的行為應是：

```text
                         ┌───────────────────────┐
                         │ authoritative current │
                         └───────────┬───────────┘
                                     │
                                     v
                           compare with desired
                                     │
                  ┌──────────────────┼──────────────────┐
                  │                  │                  │
                exact          missing only          extra
                  │                  │                  │
                  v                  v                  v
                NOOP               ADD         explicit CAS present?
                                                       │
                                           ┌───────────┴───────────┐
                                           │                       │
                                          no                      yes
                                           │                       │
                                           v                       v
                                    FAIL CLOSED          enrolled identity proven?
                                                                   │
                                                        ┌──────────┴─────────┐
                                                        │                    │
                                                       no                   yes
                                                        │                    │
                                                        v                    v
                                                 FAIL CLOSED       apply-time DNS re-read
                                                                             │
                                                                  CAS still exact match?
                                                                             │
                                                                  ┌──────────┴─────────┐
                                                                  │                    │
                                                                 no                   yes
                                                                  │                    │
                                                                  v                    v
                                                           FAIL CLOSED            REPLACE
                                                                                       │
                                                                                       v
                                                                           exact authoritative verify
```

這個設計的目的不是讓 Pilot「更容易覆寫 DNS」，而是把原本只能人工介入的合法 Day-2 host IP migration，提升成**有 ownership proof、有單次 expected-old authorization、有 apply-time CAS、有 exact postcondition 的受控 reconciliation**。

