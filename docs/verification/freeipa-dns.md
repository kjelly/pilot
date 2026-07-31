# Verification Spec — freeipa-dns（FreeIPA DNS service-domain declarative reconciler）

> 版本：v1.1（Phase 5 完成：2026-07-30 對活體 FreeIPA DNS 主機
> [freeipa-server-vm，AlmaLinux 9 `ipa-server-install --setup-dns`] 實跑
> C1-C12 全數 PASS，見 §3/§8；同日 minimal-poc round-18 全站重建
> 再次透過真正的 `pilot reconcile` 精靈驗證一次，額外找到並修復
> `freeipa_server_fqdn` 預設值計算錯誤，見 §8 v1.1）
> 對齊規範：`docs/specs/freeipa-dns.md`（設計文件，本檔對應該設計文件的 §13）
> 維護者：sre

> 對偶參照：本檔驗證的不是 `freeipa-server` 主機本身是否健康（見
> `docs/verification/freeipa-server.md`），而是 `freeipa-dns-apply.yml` 這個
> **通用 reconciler**本身的正確性：給它任何 manifest（zones/records 宣告），
> 套用後 FreeIPA 的 DNS 控制平面必須完全對應 manifest 宣告的內容。與
> `freeipa-identity.md`（授權資料 reconciler）同一種驗證模型。本檔管的是
> FreeIPA **自己**的 DNS 控制平面資料；讓**其他目標主機**的 OS resolver 真的
> 去用這個 DNS 服務是另一個獨立能力，見 `docs/verification/freeipa-dns-client.md`。

## 0. 這份檔的狀態（先讀）

依 `AGENTS.md` §1「actual-run 規則」：寫進 `docs/verification/*.md` 步驟區塊的指令，
必須先在對應目標環境實際跑過並截真實輸出才算數。**本檔已完成這件事**：2026-07-30，
`docs/specs/freeipa-dns.md` 全部 5 個 Phase 對一台真實的 vm-target
（AlmaLinux 9，`ipa-server-install --setup-dns` 原生安裝，非 fake shim）實跑，
C1-C12 全數 PASS，見 §3 的真實輸出摘要。本檔升版為 **v1.0**。

Phase 1-4（contract/schema/Go validator、完整 CRUD mutation、`pilot edit`
manifest CRUD 選單）在本機用 stateful fake `ipa` CLI shim 驗證過邏輯本身，
但那不等於活體驗證——Phase 5 才是唯一能確認下列假設的步驟，而 Phase 5
**確實找到兩個因為只測過 fake shim 而被隱藏的真實 bug**（見下方「Phase 5
發現並修復的真實 bug」），現已全部修復並重新驗證：

### Phase 5 發現並修復的真實 bug

1. **`ipa ... --all --raw` 每一行都有 2 個空白縮排**（例如
   `"  arecord: 192.168.122.3"`，不是 `"arecord: 192.168.122.3"`）——
   playbook 原本所有 `^attrname:`（無前導空白容忍）的 regex 因此永遠不會
   match。這不只是「不精確」，而是**完全失效**：authoritative-mode
   stale-record prune 的區塊切分（以 `idnsname:` 為錨點）從未真正插入過
   marker，`current_values_raw`/`current_ttl` 也永遠讀到空值。先前只用
   自己手寫、格式假設剛好一致的 fake shim 測試，才會看起來正確。修法：
   全部改成 `^[ \t]*attrname:`。修好後才第一次證實 authoritative prune
   對真實 unmanaged record 有效（§3 C8）。
2. **`ipa dnszone-add` 真實成功輸出裡沒有 `"Added DNS zone"` 這段文字**
   （原本的 `changed_when` 條件假設有）——修法：既然 `when:` 已經把這個
   迴圈篩到「bulk 探索確認不存在」的 zone 才會真的執行，直接
   `changed_when: true`。
3. **split-horizon 偵測閘門會對自己造的 zone 誤判為衝突**——`dig SOA
   <zone>` 查的是本機系統 resolver，而 FreeIPA `--setup-dns` 安裝後這台機
   器的 `/etc/resolv.conf` 就是指向自己（`127.0.0.1`）。zone 一旦建立成功，
   下一次重跑對「這個 zone 是否已存在別處」的檢查會查到自己剛建立的
   SOA，誤判成「upstream 已存在同名 zone」而擋下整個 apply——即使
   `acknowledge_split_horizon` 設對也一樣，因為問題出在誤判本身，不是
   確認流程。修法：把這個檢查改成只在「zone 尚未被 FreeIPA 管理」時才跑
   （比對 `ipa dnszone-find` 的 bulk 結果），語意對齊 spec §7.1 原本的定義
   （「upstream 已存在、且 FreeIPA 尚未管理」才算衝突）。
4. （防禦性加固，非真的 bug）比照 `freeipa-identity-apply.yml` 已有的
   慣例，`Reconcile A/AAAA/CNAME record value and TTL` 補上
   `failed_when` 容忍 FreeIPA 的 `"no modifications to be performed"`
   訊息；`Report zone creation`/`Report zone deletion` 補上
   `not (item.skipped | default(false))`，修正它們原本連「已存在、被
   跳過」的 zone 都一併印出 `CREATE_ZONE`/`DELETE_ZONE` 的誤報。

全部 4 項修復後，在同一台活體伺服器上重新完整驗證：zone 建立、3 筆
A/AAAA/CNAME record 建立、多值 drift 收斂（`SET_VALUE`）、明確刪除
（`state: absent`）、authoritative-mode 清除真實 unmanaged record、
merge-mode 保留 unmanaged record、zone 刪除、以及每一步之後的乾淨重跑
（`changed=0 failed=0`），皆通過。

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Inventory group | `freeipa-server`（與 `freeipa-identity.md` 相同：day-2 reconciler 對 FreeIPA server 本機跑）|
| OS / version | 與 `freeipa-server.md` 相同（native AlmaLinux 9 `ipa-server-install --setup-dns`）|
| 角色 | `freeipa-dns-apply.yml` 本身不含任何 zone/record 資料——純粹的 reconciler，資料一律由 `freeipa_dns_manifest_file` 指向的 manifest 檔提供（namespaced `include_vars`，非 `-e @`）|
| 套用範圍 | 對 designated primary FreeIPA server 本機跑（`hostCardinality: exactly-one`）；即使存在 replica 也不得平行套用 |
| 風險等級 | Medium-High（誤設 `records_mode: authoritative` 或 zone delete 會刪除既有 DNS 記錄；safety gate 見 `docs/specs/freeipa-dns.md` §6-§7）|

## 1.5 依賴變數契約

| 變數名稱 | 說明/用途 | 是否必填 |
|---------|----------|---------|
| `freeipa_dns_manifest_file` | manifest 檔絕對路徑；以 `include_vars: name=freeipa_dns_manifest` 載入 | 是 |
| `ipa_admin_password` | kinit admin 用密碼；由 vault file 注入，禁止 hard-code | 是 |
| `freeipa_domain` / `freeipa_realm` / `freeipa_server_fqdn` | 必須與 manifest 的 `freeipa.domain`/`freeipa.realm`/`freeipa.server` 完全一致，否則在 kinit 前 fail closed | 否（有預設，見 `contracts/freeipa-server.yaml`）|
| `freeipa_setup_dns` | 必須未被設為 `false`（`freeipa-server-apply.yml` 的 native DNS 安裝旗標）| 否（預設 `true`）|

## 2. Checklist

> 指令直接在 FreeIPA server 本機以 root 執行，走 root 對 ldapi unix socket 的
> SASL EXTERNAL autobind（與 `freeipa-identity.md` 同一機制，純唯讀查詢，不需
> Kerberos ticket，也不會把 admin 密碼寫進這份會進 git 的 spec 檔）。前置：
> 已套用 §7 描述的真實 fixture manifest（2026-07-30 對活體 server 實跑）。
> Socket 路徑對應本次實跑的 realm：`/run/slapd-IPA-PILOT-INTERNAL.socket`。

| ID | Category | Check | Expected | Command | 實測輸出 |
|----|----------|-------|----------|---------|---------|
| C1 | zone | fixture zone 存在且 active | idnsZoneActive: TRUE | `ldapsearch -o ldif-wrap=no -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket -s base -b "idnsname=svc.pilot.internal.,cn=dns,dc=ipa,dc=pilot,dc=internal" idnsZoneActive` | `idnsZoneActive: TRUE` |
| C2 | record | A record values 等於 manifest（解析自 nexus `ansible_host`）| aRecord: 192.168.122.3 | `ldapsearch ... -s base -b "idnsname=grafana,idnsname=svc.pilot.internal.,cn=dns,dc=ipa,dc=pilot,dc=internal" aRecord` | `aRecord: 192.168.122.3` |
| C3 | record | AAAA record values 等於 manifest（顯式 `values:`，非 inventory_host） | aAAARecord: 2001:db8::81 | `ldapsearch ... -s base -b "idnsname=wazuh-v6,idnsname=svc.pilot.internal.,cn=dns,dc=ipa,dc=pilot,dc=internal" aAAARecord` | `aAAARecord: 2001:db8::81` |
| C4 | record | CNAME target 等於 manifest | cNAMERecord: grafana.svc.pilot.internal. | `ldapsearch ... -s base -b "idnsname=grafana-alias,idnsname=svc.pilot.internal.,cn=dns,dc=ipa,dc=pilot,dc=internal" cNAMERecord` | `cNAMERecord: grafana.svc.pilot.internal.` |
| C5 | target | `inventory_host: nexus` 解析為目前 `ansible_host`，且改變 nexus 現有 A record 的值後重跑會收斂回宣告值（drift correction，本輪對 grafana 手動注入了第二筆 `arecord: 203.0.113.5`，重跑後只剩宣告值）| SET_VALUE，changed=1 | `ipa dnsrecord-mod svc.pilot.internal. grafana --a-rec=192.168.122.3 --a-rec=203.0.113.5`（注入）→ 重跑 playbook | `"msg": "SET_VALUE grafana.svc.pilot.internal. A ttl=300"`；重跑後 `dnsrecord-show` 只剩 `arecord: 192.168.122.3` |
| C6 | record | TTL drift 已被 reconciler 修正為 manifest 宣告值（`ttl: 120`，非 defaults 的 300）| dNSTTL: 120 | `ldapsearch ... -s base -b "idnsname=ttl-fixture,idnsname=svc.pilot.internal.,cn=dns,dc=ipa,dc=pilot,dc=internal" dNSTTL` | `dNSTTL: 120` |
| C7 | delete | `state: absent` 已刪除指定 RRset（record 不存在）| exit!=0（No such object 或 attribute 不存在）| `! ldapsearch ... -s base -b "idnsname=delete-fixture,idnsname=svc.pilot.internal.,cn=dns,dc=ipa,dc=pilot,dc=internal" aRecord 2>/dev/null \| grep -q aRecord` | `exit=0`（即反轉後的 `!` 成立，record 確認不存在）|
| C8 | prune | authoritative mode 已刪除 manifest 未宣告的 stale supported RRset（`authoritative-fixture.pilot.internal.` zone 下手動建立的 unmanaged A record `stale-fixture`，套用後消失，同時宣告的 `app-fixture` 被新增）| No such object (32) | `ldapsearch ... -s base -b "idnsname=stale-fixture,idnsname=authoritative-fixture.pilot.internal.,cn=dns,dc=ipa,dc=pilot,dc=internal" aRecord` | `SASL SSF: 0` / `No such object (32)`；playbook 輸出 `PRUNE_RRSET stale-fixture.authoritative-fixture.pilot.internal. A` 與 `ADD_VALUE app-fixture.authoritative-fixture.pilot.internal. A ttl=300`，同一次 apply |
| C9 | safety | FreeIPA identity domain zone 從未被本 reconciler 刪除或 authoritative-prune | idnsZoneActive: TRUE | `ldapsearch ... -s base -b "idnsname=ipa.pilot.internal.,cn=dns,dc=ipa,dc=pilot,dc=internal" idnsZoneActive` | `idnsZoneActive: TRUE` |
| C10 | safety | 已明確 `acknowledge_split_horizon: true` 的全新 zone 正常建立；未確認情境的拒絕行為與「zone 已被 FreeIPA 管理後不再誤判」見 §7 | changed=1，`CREATE_ZONE` | 套用含 `split-horizon-fixture.pilot.internal.`（`acknowledge_split_horizon: true`）的 manifest | `"msg": "CREATE_ZONE split-horizon-fixture.pilot.internal."`，`changed=1 failed=0`（測試後已 `ipa dnszone-del` 清理，非最終 fixture 狀態的一部分）|
| C11 | verify | `dig @FreeIPA server`（127.0.0.1，本機即 authoritative）的實際回覆等於 desired state（權威路徑，非 LDAP 內部視角）| 192.168.122.3 | `dig +short grafana.svc.pilot.internal. A @127.0.0.1` | `192.168.122.3` |
| C12 | idempotency | 無 drift 時重跑 reconcile 為 `changed=0 failed=0` | changed=0 failed=0 | 對已收斂的 fixture manifest 重跑 `playbooks/apply/freeipa-dns-apply.yml`（無任何 `-e` 變更）| `freeipa-dns-vm : ok=29 changed=0 unreachable=0 failed=0 skipped=13 rescued=0 ignored=0`（多次重跑皆一致，見 §3）|

> `pilot verify`/`pilot spec --generate` 尚未針對本檔重跑產生對應的
> ndjson row（`.verification/freeipa-dns-<UTC>.ndjson`）；上表的「實測輸出」
> 欄位是本輪 Phase 5 手動執行上述指令的真實輸出，逐字摘錄，非改寫。C10 的
> fixture zone 已在同一輪測試中刪除（其存在只是為了證明「首次建立、
> 尚未被 FreeIPA 管理」的 split-horizon 檢查路徑），最終保留的 fixture 狀態
> 見 §7。

> **為什麼用 ldapsearch 而非 `ipa` CLI**：跟 `freeipa-identity.md` 同理——`ipa
> dnszone-show`/`dnsrecord-show` 需要先 `kinit admin`，admin 密碼不能寫進這份
> 進 git 的 spec 檔。改走 root 對 ldapi unix socket 的 SASL EXTERNAL
> autobind，純唯讀查詢。Socket 路徑固定為
> `/run/slapd-IPA-PILOT-INTERNAL.socket`（與 realm 對應）。
> **C7/C8/C9 的 `!`/`grep` 反轉**：確認「不存在」比對 process 退出碼，跟
> `freeipa-identity.md` C2/C5 同一招。
> **C12 用 marker file 而非直接比對 `changed=0`**：`pilot verify` 的單指令
> checklist 模型無法直接讀「上一次 ansible-playbook 執行的 recap」；marker
> 由 fixture SOP 在確認 recap `changed=0 failed=0` 後寫入（時間戳），Phase 3/5
> 建立對應 fixture 時一併實作。

## 3. 證據收集

- 狀態：**v1.0 — 2026-07-30 對活體 server 實跑，C1-C12 全數 PASS**。
- 目標環境：`pilot vm-target` 建立的 disposable KVM VM（AlmaLinux 9），
  透過 `freeipa-server-apply.yml` 安裝（`--setup-dns`，realm
  `IPA.PILOT.INTERNAL`，domain `ipa.pilot.internal`），另一台 vm-target
  （Ubuntu 24.04，名稱 `nexus`）作為 `target.inventory_host` 解析對象。
- 實跑的 manifest 場景（依序，每個場景後都確認一次乾淨重跑 `changed=0
  failed=0`）：
  1. 建立 `svc.pilot.internal.`（merge mode）zone，宣告 3 筆 A record
     （grafana/wazuh/s3，皆透過 `target.inventory_host: nexus` 解析）→
     `dig` 確認三個名稱都解析到 nexus 的真實 IP。
  2. 手動對 `grafana` 注入第二筆 `arecord`（模擬 drift）→ 重跑 → 確認
     reconciler 偵測到「現有值 ≠ 宣告值」並發出恰好一次 `dnsrecord-mod`
     收斂回宣告值（`SET_VALUE`，`changed=1`）→ 再重跑 `changed=0`。
  3. 追加 AAAA（顯式 `values:`）、CNAME、自訂 TTL（120）、`state: absent`
     的 `delete-fixture` 記錄到同一個 zone，套用後逐一確認：AAAA/CNAME
     值正確、TTL 正確、`delete-fixture` 記錄已刪除且不會在下次重跑
     時被誤加回來。
  4. 新增 `authoritative-fixture.pilot.internal.`（`records_mode:
     authoritative`）zone：先手動用 `ipa dnszone-add`/`ipa dnsrecord-add`
     建立一筆 manifest 不知道的 unmanaged A record（`stale-fixture`），
     manifest 同時宣告一筆 `app-fixture` A record；套用後同一次 apply
     內確認 `stale-fixture` 被刪除、`app-fixture` 被新增。
  5. 新增 `split-horizon-fixture.pilot.internal.`
     （`acknowledge_split_horizon: true`）zone，確認全新 zone 在「尚未被
     FreeIPA 管理」的情況下可以正常建立（測試後刪除，不保留在最終
     fixture 狀態）。
  6. 用 `allow_zone_delete: true` + `-e confirm_dns_zone_delete=true`
     刪除一個測試用 throwaway zone，確認 `changed_when` 正確識別出
     `"Deleted DNS zone"` 字樣、`DELETE_ZONE` 只在真的刪除時才印出。
- 最終保留的 fixture 狀態（供未來重跑本檔 §2 checklist 直接使用，見 §7）：
  `svc.pilot.internal.`（merge，grafana/wazuh/s3/wazuh-v6/grafana-alias/
  ttl-fixture 皆 present，delete-fixture 為 absent）與
  `authoritative-fixture.pilot.internal.`（authoritative，僅
  app-fixture）。
- 每個場景都確認過至少一次 `changed=0 failed=0` 的乾淨重跑；C12 的最終
  idempotency rerun 的完整 PLAY RECAP：
  `freeipa-dns-vm : ok=29 changed=0 unreachable=0 failed=0 skipped=13 rescued=0 ignored=0`。
- `pilot vm-target verify`/`pilot spec --generate` 尚未針對本檔產生對應
  的 ndjson row（本輪驗證改用手動執行 §2 每一行 `ldapsearch`/`dig` 指令
  並逐字記錄輸出，未透過 `pilot spec` 自動產生的 verify playbook）；
  下一輪如需 `pilot verify` 產生的 ndjson 證據，重跑 §7 的 fixture 建立
  步驟後執行 `pilot vm-target verify --name <server-vm>
  docs/verification/freeipa-dns.md` 即可。
- Row 數：12

## 4. PASS / FAIL 規則

- C1–C12 全部 pass → reconciler 套用 fixture manifest 後，DNS 控制平面（LDAP
  內部狀態與外部 `dig` 回覆）完全對應 manifest 宣告的內容。2026-07-30 對
  活體 server 實跑，全數 PASS（見 §3）。
- 任一 fail → 常見待查方向：
  - C1-C6 fail → 確認 fixture manifest 是否已套用過、`freeipa_dns_manifest_file`
    是否指到正確路徑；若曾在別的 checkout 上套用過，優先確認
    `playbooks/apply/freeipa-dns-apply.yml` 的 regex 是否還是
    `^[ \t]*attrname:`（前導空白容忍）——2026-07-30 曾因為漏了這個容忍
    導致 current-state 一律讀成空值，見 §0「Phase 5 發現並修復的真實 bug」#1。
  - C7 fail → 檢查 `freeipa-dns-apply.yml` 的 `Delete explicit absent RRsets`
    task 是否有跑到，以及 `dnsrecord-show` 是否正確讀到了要刪除的 current values。
  - C8 fail → 檢查整區 `dnsrecord-find --all --raw` dump 的區塊解析是否正確
    （`Flatten authoritative-zone record dumps into per-owner blocks` /
    `Parse current authoritative-zone owner/type/value entries`）——同樣
    優先檢查 `^[ \t]*idnsname:` 的前導空白容忍是否還在。
  - C9 fail → **嚴重**：reconciler 刪除了受保護的 identity domain zone，立即
    停止套用並比對 `docs/specs/freeipa-dns.md` §5.3/§6.3 的 protected-zone gate。
  - C10 fail（在本應該建立的全新 zone 上誤判 split-horizon 衝突）→ 檢查
    split-horizon 偵測是否還正確跳過「已被 FreeIPA 管理」的 zone（見 §0
    的真實 bug #3）；一個常見誤判來源是這台主機的系統 resolver
    （`/etc/resolv.conf`）本身就指向這台 FreeIPA 伺服器自己。
  - C11 fail 但 C1-C6 pass → 檢查 named/bind-dyndb-ldap 是否已重新載入 zone
    資料（LDAP 寫入與實際 DNS 應答之間可能有短暫落差）。
  - C12 fail（重跑 `changed>0`）→ 這是最值得警覺的 fail 模式：代表
    current-vs-desired diff 邏輯把「相同」誤判成「不同」，很可能又是
    regex 前導空白的問題（見 #1）復發，或是新增的 record 類型/欄位沒有
    對齊 `current_values`/`desired_values` 的正規化規則。

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C9/C10 | 「未確認情境會被拒絕」（壞 manifest → 確認 apply 失敗 → 確認狀態未被破壞）是 reconciler 的動態拒絕行為，不適合塞進單指令 checklist snapshot；本輪 Phase 5 只驗證了「正確情境成功」的一半（C9 的「從未被刪除」、C10 的「acknowledge 後成功建立」），未逐一實跑「manifest 忘記 acknowledge_split_horizon 時真的被拒絕」「嘗試刪除 identity zone 時真的被拒絕」這兩條負向路徑 | 全部 | 永久（同 `freeipa-identity.md` 的既有慣例）——負向路徑留給下一輪按 §7 的 SOP 補測 |
| — | reverse zone（`in-addr.arpa.`/`ip6.arpa.`）、SRV/MX/CAA/NAPTR/SSHFP、DNSSEC、GSS-TSIG dynamic update 均不在本版範圍內（`docs/specs/freeipa-dns.md` §2 非目標）| 全部 | 永久 |
| — | 本輪只驗證了 A/AAAA/CNAME 三種 record type 與 merge/authoritative 兩種 records_mode；未測試同一 zone 內同時存在數十筆 record 時 authoritative-prune 區塊解析的效能與正確性上限 | 全部 | 無明確期限，留意大型 zone 場景 |

## 6. Playbook 對應

對應的 **apply** playbook：`playbooks/apply/freeipa-dns-apply.yml`

| Spec ID | Apply task（tag）| 備註 |
|---------|-----------------|------|
| C1 | `Ensure declared zones exist`（`tags: [C1]`）| Phase 2：真實 `ipa dnszone-add`，只在 bulk zone-find 顯示不存在時才跑 |
| C2 | `Reconcile A/AAAA/CNAME record value and TTL`（`tags: [C2, C3, C4, C6]`）| Phase 2：真實 `dnsrecord-add`/`dnsrecord-mod`，A record 部分 |
| C3 | 同上（`tags: [C2, C3, C4, C6]`）| AAAA record 部分 |
| C4 | 同上（`tags: [C2, C3, C4, C6]`）| CNAME record 部分 |
| C5 | `Gate: inventory target host exists and resolves to a non-empty ansible_host`（`tags: [C5]`）| pre_tasks 的 preflight gate，Phase 1 起即生效；解析本身在 `Compute record reconcile plan` 完成 |
| C6 | 同 C2（`tags: [C2, C3, C4, C6]`）| TTL 與 value 在同一次 `dnsrecord-add`/`-mod` 呼叫一併設定，而非分開的 SET_TTL 呼叫 |
| C7 | `Delete explicit absent RRsets`（`tags: [C7]`）| Phase 3：真實 `ipa dnsrecord-del`，用 `dnsrecord-show` 讀到的 current values 精確刪除該 RRset |
| C8 | `Prune stale authoritative RRsets`（`tags: [C8]`）| Phase 3：真實 `ipa dnsrecord-del`，先解析整區 `dnsrecord-find --all --raw` dump 找出 manifest 未宣告的 supported-type RRset |
| C9 | `Gate: protected zone cannot be deleted or pruned`（`tags: [C9]`）| 真正的 fail-closed preflight gate，Phase 1 即已生效 |
| C10 | `Gate: unacknowledged split-horizon zone creation`（`tags: [C10]`）| 同上；真的執行 live `dig SOA` 查詢上游 |
| C11 | `Post-apply verification: query the authoritative DNS answer` + `Gate: post-apply DNS answer matches desired state`（`tags: [C11]`）| Phase 2 新增：真實 apply 完成後才跑（`not ansible_check_mode`），比對 `dig` 回覆與 desired state |
| C12 | — | 冪等性是多次執行的性質，非單一 tagged task 可代表；見 §7 |

## 7. 動態行為 SOP（fixture 套用 + reconciler 拒絕行為驗證）

已於 2026-07-30 對活體 vm-target 實跑（見 §3）。重現步驟：

```bash
# 0. 前置：freeipa-server（AlmaLinux 9, --setup-dns）與 nexus（任一 host，
#    只需 ansible_host 可解析）皆已 up，freeipa-server 已跑過
#    freeipa-server-apply.yml。

# 1. 建立 merge-mode zone + 3 個 A record（透過 inventory host 解析）
cat > freeipa-dns.yaml <<'EOF'
schema_version: 1
freeipa:
  domain: ipa.pilot.internal
  realm: IPA.PILOT.INTERNAL
  server: ipa1.ipa.pilot.internal
dns:
  defaults: {ttl: 300, records_mode: merge}
  safety: {allow_shadow_existing_zone: false, allow_authoritative_prune: true, allow_zone_delete: false}
  zones:
    - name: svc.pilot.internal.
      state: present
      acknowledge_split_horizon: false
      records:
        - {name: grafana, type: A, state: present, target: {inventory_host: nexus}}
        - {name: wazuh,   type: A, state: present, target: {inventory_host: nexus}}
        - {name: s3,      type: A, state: present, target: {inventory_host: nexus}}
EOF

pilot vm-target run --name <freeipa-server-vm> playbooks/apply/freeipa-dns-apply.yml \
  -e target_group=<host-or-group> -e freeipa_dns_manifest_file=$PWD/freeipa-dns.yaml \
  -e freeipa_server_fqdn=ipa1.ipa.pilot.internal -e @<vault-with-ipa_admin_password>

# → CREATE_ZONE, 3x ADD_VALUE, changed>0. Rerun → changed=0.
# → dig +short grafana.svc.pilot.internal. A @127.0.0.1 資料一致。

# 2. drift correction：直接對 FreeIPA 注入一筆額外值，模擬「有人手動改過」
pilot vm-target exec --name <freeipa-server-vm> -- bash -c '
printf %s "<ipa_admin_password>" | kinit admin@IPA.PILOT.INTERNAL
ipa dnsrecord-mod svc.pilot.internal. grafana --a-rec=<原IP> --a-rec=203.0.113.5
kdestroy'
# 重跑同一個 manifest（不改任何檔案）→ SET_VALUE grafana.svc.pilot.internal. A，
# changed=1；dnsrecord-show 確認只剩宣告值。再重跑 → changed=0。

# 3. 明確刪除：追加一筆 state: absent 的 record（例如 delete-fixture），重跑
#    → DELETE_RRSET；再重跑 → changed=0（已經不存在）。

# 4. authoritative-mode prune：新 zone + 手動塞一筆 unmanaged record
pilot vm-target exec --name <freeipa-server-vm> -- bash -c '
printf %s "<ipa_admin_password>" | kinit admin@IPA.PILOT.INTERNAL
ipa dnszone-add authoritative-fixture.pilot.internal.
ipa dnsrecord-add authoritative-fixture.pilot.internal. stale-fixture --a-rec=192.168.122.250
kdestroy'
# manifest 加入 records_mode: authoritative 的 authoritative-fixture.pilot.internal.
# zone，宣告 app-fixture，重跑一次同時看到 PRUNE_RRSET stale-fixture... 與
# ADD_VALUE app-fixture...；再重跑 → changed=0。

# 5. merge-mode 保留 unmanaged record（核心保證，避免與 #4 混淆）
pilot vm-target exec --name <freeipa-server-vm> -- bash -c '
printf %s "<ipa_admin_password>" | kinit admin@IPA.PILOT.INTERNAL
ipa dnsrecord-add svc.pilot.internal. unmanaged-thing --a-rec=10.10.10.10
kdestroy'
# svc.pilot.internal. 是 merge mode，重跑同一個 manifest → changed=0，
# unmanaged-thing 仍然存在（未被清除）。

# 6. split-horizon（正向路徑）：全新 zone + acknowledge_split_horizon: true
#    → CREATE_ZONE 正常成功（因為此 zone 尚未被 FreeIPA 管理，dig SOA 查
#    不到任何東西，acknowledge 與否都不影響結果——這條路徑主要驗證的是
#    「zone 已被管理後不再誤判」，見 §0 bug #3）。

# 7. zone 刪除
pilot vm-target run --name <freeipa-server-vm> playbooks/apply/freeipa-dns-apply.yml \
  -e target_group=<host-or-group> -e freeipa_dns_manifest_file=<manifest含state:absent的zone> \
  -e confirm_dns_zone_delete=true -e @<vault>
# → DELETE_ZONE，changed=1；重跑 → changed=0（已經不存在）。
```

**尚未實跑的負向路徑**（見 §5 例外）：manifest 忘記
`acknowledge_split_horizon: true` 時的拒絕、對 identity zone 或
`allow_zone_delete: false` 的 zone 嘗試刪除時的拒絕。這兩條沿用
`freeipa-identity.md` §7 的既有慣例（給壞 manifest → 確認 apply 在任何
mutation 前就失敗 → 確認狀態未被破壞），留給下一輪補上。

## 8. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-30 | DRAFT v0.1 | 初版：`docs/specs/freeipa-dns.md` Phase 1（contract、schema、Go validator、read-only plan skeleton）落成後建立的 checklist 骨架；尚無任何活體 evidence | pilot |
| 2026-07-30 | DRAFT v0.2 | Phase 2 落成：zone 建立與 A/AAAA/CNAME present record 的 value/TTL reconcile 為真實 mutation（含 IP 變更後自動收斂、冪等重跑）；C11 從「尚無法驗證」改為有對應 apply task；§6 對照表更新為真實 task 名稱；本機用 stateful fake `ipa` CLI shim 反覆驗證過 add/mod/no-op 判斷邏輯與冪等性,但仍未對活體 FreeIPA server 驗證,狀態維持 DRAFT | pilot |
| 2026-07-30 | DRAFT v0.3 | Phase 3 落成：明確 RRset 刪除（C7）與 authoritative-mode stale-record prune（C8）為真實 mutation；zone 刪除（`ipa dnszone-del`）補上（先前只有 gate，沒有實際 mutation task）；authoritative prune 解析整區 `dnsrecord-find --all --raw` dump，明確標記為本檔信心最低、最需要 Phase 5 活體驗證的部分；本機 stateful fake `ipa` CLI shim 驗證過 delete/prune/merge-保留-unmanaged 三種情境,狀態維持 DRAFT | pilot |
| 2026-07-30 | DRAFT v0.4 | Phase 4 落成：`pilot edit` 新增獨立的 freeipa-dns manifest 選單（`cmd/pilot/cmd/edit_tui_dns.go`），涵蓋 zone/record CRUD、target.inventory_host picker（讀 hosts.yml）、normalized preview、Simulate-then-write 驗證閘門（同 `internal/inventory.ValidateDNSManifest`）；新增 yaml.Node surgery 寫入層（`internal/inventory/freeipa_dns_write.go`）；teatest 覆蓋建立 3 筆 service record（grafana/wazuh/s3，皆透過 inventory host 解析）不需手改 YAML 即通過同一個 Go validator | pilot |
| 2026-07-30 | v1.0 | **Phase 5 完成，升版出 DRAFT**：對活體 vm-target（AlmaLinux 9 `--setup-dns`）實跑 C1-C12 全數 PASS（見 §3）。過程中找到並修復 3 個真實 bug（見 §0）：(1) `ipa ... --all --raw` 每行有 2 空白縮排，導致所有 `^attrname:` regex 從未 match，authoritative prune 實際上從未真正運作過、current-state 一律讀空值——只是因為先前只測過格式假設剛好一致的 fake shim 才沒被抓到；(2) `ipa dnszone-add` 真實成功輸出沒有 `"Added DNS zone"`，`changed_when` 一律誤判成 `ok`；(3) split-horizon 偵測用系統 resolver 查詢，`--setup-dns` 安裝後主機自己就是 resolver，導致 zone 建立成功後的每一次重跑都對自己剛建立的 zone 誤判成「upstream 衝突」而擋下整個 apply——即使確認過 `acknowledge_split_horizon` 也一樣。三個 bug 修復後重新驗證：zone 建立、3 筆 A/AAAA/CNAME record、多值 drift 收斂、明確刪除、authoritative prune（含真實 unmanaged record）、merge-mode 保留 unmanaged record、zone 刪除、每一步後的乾淨重跑，全部通過。§2 checklist 換成本輪實跑的真實 fixture 名稱與逐字輸出；§7 補上可重現的完整 SOP | pilot |
| 2026-07-30 | v1.1 | minimal-poc round-18（`docs/runbooks/minimal-poc-architecture.md`）用真正的 3-VM 全站重建 + 真正的 `pilot reconcile` 精靈（非本檔 v1.0 用的手動 `-e` CLI 呼叫）再跑一次，額外找到並修復第 4 個真實 bug：`ipa_server_fqdn_expected: freeipa_server_fqdn \| default(inventory_hostname)`——當 `freeipa_server_fqdn` 依 `group_vars/freeipa.example.yml` 自己的說明「通常不用填，會自動從 freeipa_domain 推導」而留空時，這個 fallback 算出的是 inventory 裡的短別名（例如 `freeipa-server`），而不是 `freeipa-server-apply.yml` 自己真正用來安裝伺服器的 FQDN（`ipa1.<domain>`），導致 manifest 的 `freeipa.server` 欄位怎麼填都對不上，"Gate: manifest freeipa.{domain,realm,server} match this inventory" 必定失敗。v1.0 的驗證從未走到這個 gap，因為當時的手動指令一律明確帶了 `-e freeipa_server_fqdn=...`。修法：改成 `freeipa_server_fqdn \| default('ipa1.' ~ ipa_domain)`，對齊 `freeipa-server-apply.yml` 自己的預設值計算方式。修復後，透過 `pilot reconcile` 精靈（無任何手動 `-e`）完整跑過一次 grafana/wazuh/s3 三筆 A record 建立（`changed=2`）與乾淨重跑（`changed=0`），兩者皆真實通過 | pilot |
