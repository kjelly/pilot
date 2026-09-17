# Pilot FreeIPA Client HA + Single-Node Compatibility 改善計畫

> **狀態（2026-09-17）**：Phase 0-5、7 已實作並用真實 vm-target 驗證完成；Phase 6（contract
> provider pool）刻意延後，H7/H8 未活體驗證——完整範圍見 §20 各 Phase 小節與 §25 Definition
> of Done。實作證據：`docs/evidence/freeipa-client-ha/`。驗收結果：
> `docs/runbooks/freeipa-server-replica-ha-drill.md`（已全面改版，移除人工 sed 步驟）。

- Target repository: `kjelly/pilot`
- Baseline commit: `e91073738717e6b9e4f9ca6ef4da360433ea78c8`
- Scope: FreeIPA client runtime HA、DNS HA、既有 client Day-2 收斂、Pilot control-plane failover
- Primary goal: **同一套實作同時支援 1 台與 N 台 FreeIPA server，不允許 HA 與 single-node 形成兩套互相漂移的配置路徑。**
- Required outcome: `freeipa-server` 單機部署維持現有可用性；加入 `freeipa-server-replica` 後，client 不需人工 `sed` 即可承受任一台 FreeIPA server 單點故障。

---

## 1. 背景與目前缺口

目前 `playbooks/apply/freeipa-client-apply.yml` 明確採用單一 server：

```yaml
ipa-client-install
--server={{ ipa_server_fqdn }}
--domain={{ ipa_domain }}
--realm={{ ipa_realm }}
```

並且只將單一 `ipa_server_fqdn -> ipa_server_ip` pin 到 `/etc/hosts`。

目前程式碼註解也明確寫著：

```text
No SRV-based KDC discovery in this pilot
```

現有 HA drill（`docs/runbooks/freeipa-server-replica-ha-drill.md` §6）已經**實際跑過**且留有真實輸出：`vm-target topology up`/`wire` 自動處理 `/etc/hosts`，但 `/etc/krb5.conf`（`kdc`/`admin_server`/`kpasswd_server`）與 `/etc/sssd/sssd.conf`（`ipa_server`）仍是靠該 runbook §6 裡當場手打的 `sed -i` 補上多值、再 `systemctl restart sssd`，之後 §7-§11 的 failover 演練才會 PASS。§14 gotcha 表也明確記載「這一段 `vm-target topology` 目前沒有收進宣告式流程,因為它是 playbook/OS 設定檔層級的細節」。`docs/topologies/freeipa-ha-topology.yaml:35` 的註解與此一致：

```text
patched (manually — wire only pins /etc/hosts, see the runbook §6).
```

因此目前的 HA PASS 證明的是「FreeIPA 本身有 HA 能力，且靠一次性手動 sed 可以讓 client 也 failover」，不是「Pilot deploy 出來的 client 自動具有 HA」——手動 sed 這件事本身就是本計畫要消除的目標（見本文件開頭 Required outcome）。

另外還有四個結構性問題：

1. `freeipa-client-apply.yml` 使用 `creates: /etc/ipa/default.conf`，既有 client 不會重新跑 `ipa-client-install`，所以只修 fresh enrollment 不會修到既有 fleet。
2. `freeipa-server-replica-apply.yml` 在沒有顯式設定時，`ipa_setup_dns` 預設為 `false`；primary 預設則是 `true`，容易形成只有一台 DNS provider 的 SPOF。
3. `freeipa-client-host-dns.yml` authoritative DNS read 目前直接 query `@{{ ipa_server_ip }}`，control-plane 仍綁定單一 server。
4. `contracts/freeipa-client.yaml` 的 provider binding 是 `sourceSelection: exactlyOne`，語意仍是「client 依賴一個 primary endpoint」，無法完整表達 HA provider pool。

---

# 2. 設計原則

## 2.1 Single-node 必須是一級支援模式

不得要求使用者為了使用 FreeIPA client：

- 一定要建立 replica。
- 一定要部署 integrated DNS。
- 一定要建立 load balancer / VIP。
- 一定要提供 DNS SRV。

只有一台 `freeipa-server` 時，必須繼續支援目前的：

```text
client
  │
  ├── /etc/hosts → ipa1
  ├── Kerberos   → ipa1
  └── SSSD       → ipa1
```

單機不是 degraded/error state；只有在 operator 明確要求 `ha` 時，少於 2 個 server 才是 configuration error。

---

## 2.2 HA 與 single-node 必須共用相同 state machine

推薦新增：

```yaml
freeipa_client_topology_mode: auto
```

合法值：

| 值 | 語意 |
|---|---|
| `auto` | 1 個 provider → `single`；2 個以上 → `ha` |
| `single` | 強制只使用 primary；供 staged rollout / troubleshooting |
| `ha` | 至少需要 2 個可用 FreeIPA provider，否則 fail closed |

預設必須是：

```yaml
freeipa_client_topology_mode: auto
```

不要求現有單機 inventory 增加任何設定。

---

# 3. 核心架構：Server Pool

新增 shared task：

```text
playbooks/apply/tasks/freeipa-server-pool.yml
```

由 client、DNS client、replica verification、FreeIPA control-plane mutation 共用。

輸出至少包含：

```yaml
freeipa_server_pool:
  - inventory_host: ipa-1
    fqdn: ipa1.ipa.pilot.internal
    ip: 10.0.0.10
    kind: primary
    dns_provider: true

  - inventory_host: ipa-2
    fqdn: ipa2.ipa.pilot.internal
    ip: 10.0.0.11
    kind: replica
    dns_provider: true

freeipa_server_fqdns:
  - ipa1.ipa.pilot.internal
  - ipa2.ipa.pilot.internal

freeipa_server_ips:
  - 10.0.0.10
  - 10.0.0.11

freeipa_dns_server_ips:
  - 10.0.0.10
  - 10.0.0.11

freeipa_client_topology_mode_effective: ha
```

## 3.1 Pool source

順序固定：

1. `groups['freeipa-server']`
2. `groups['freeipa-server-replica']`

禁止：

- 從 DNS SRV 反推 Pilot desired state。
- 從目前 client 的 `sssd.conf` 反推 desired state。
- 用「目前哪台 reachable」決定 topology membership。

Reachability 只能決定 bootstrap ordering，不得改變 desired pool。

## 3.2 Pool invariants

必須 fail closed：

- FQDN 重複。
- IP 重複但對應不同 FreeIPA FQDN。
- primary 與 replica FQDN 相同。
- HA mode 下 provider 數 `< 2`。
- 多 replica 環境無法決定每台 replica 的 canonical FQDN。

### Replica FQDN backward compatibility

目前只有一台 replica 時可保留：

```yaml
freeipa_replica_fqdn: ipa2.<domain>
```

legacy default。

當 `freeipa-server-replica` 超過 1 台時：

- 每台必須有獨立 `freeipa_replica_fqdn` host var，或
- inventory generator 必須生成穩定且唯一的 canonical FQDN。

不得讓多台 replica 都 fallback 成 `ipa2.<domain>`。

---

# 4. Fresh Client Enrollment

## 4.1 不採純 SRV-only enrollment

Fresh client 改成由 `freeipa_server_pool` 建構 `ipa-client-install` argv。

FreeIPA `ipa-client-install --server` 本身可重複指定多次；多個 server 會被寫入 client 的 SSSD / Kerberos failover 設定。

因此推薦：

### Single-node

```bash
ipa-client-install \
  --server=ipa1.ipa.pilot.internal \
  --domain=ipa.pilot.internal \
  --realm=IPA.PILOT.INTERNAL \
  ...
```

等價於目前行為。

### HA

```bash
ipa-client-install \
  --server=ipa1.ipa.pilot.internal \
  --server=ipa2.ipa.pilot.internal \
  --domain=ipa.pilot.internal \
  --realm=IPA.PILOT.INTERNAL \
  ...
```

若有第三台：

```bash
--server=ipa1...
--server=ipa2...
--server=ipa3...
```

## 4.2 禁止使用 `--fixed-primary`

HA mode 不得帶：

```text
--fixed-primary
```

SSSD 應保留 `_srv_` discovery，加上 installer 寫入的 fixed server fallback。

預期 semantic state：

```ini
ipa_server = _srv_, ipa1.ipa.pilot.internal, ipa2.ipa.pilot.internal
```

這形成：

```text
              DNS SRV discovery
                    │
                    ▼
SSSD ────────> _srv_
  │
  ├──────────> ipa1
  └──────────> ipa2
                 ↑
           fixed fallback
```

即使 SRV/DNS discovery 暫時失效，只要 server FQDN 仍能 resolve，SSSD 還有 fixed list。

---

# 5. Bootstrap Reachability

server pool 的順序是 desired-state 順序；enrollment 時另外計算：

```yaml
freeipa_bootstrap_servers:
  - <reachable-first>
  - <other providers>
```

Probe 必須是 read-only。

至少 probe：

- TCP/443：FreeIPA HTTP API / enrollment。
- TCP/88：Kerberos。
- TCP/389 或 636：依目前 FreeIPA endpoint contract。
- DNS/FQDN resolution。

HA mode：

```text
>= 1 server reachable → 可以進 enrollment
0 server reachable    → fail
```

Single mode：

```text
唯一 server reachable → continue
唯一 server unreachable → fail
```

當 `ipa1` down、`ipa2` up 時：

```text
desired pool: [ipa1, ipa2]
bootstrap argv order: [ipa2, ipa1]
```

不能因 primary down 就把 `ipa1` 從 desired state 永久刪除。

**Phase 0 實測證據（2026-09-17，`docs/evidence/freeipa-client-ha/2026-09-17-installer-golden/fixture-c-primary-down-fresh-enroll/`）**：
在 ipa1 停機時執行 `ipa-client-install --server=ipa1 --server=ipa2 ...`（ipa1 排第一），installer
自己會 probe 每一台給定的 server，並把探測不到的那一台**直接從 krb5.conf/sssd.conf/default.conf
整個拿掉**，不是只調整順序或標記優先度——結果只剩 `ipa2`（`kdc=ipa2:88`、
`ipa_server = _srv_, ipa2...`、`server = ipa2...`），完全沒有 `ipa1` 的任何蹤跡。也就是說單靠
「Pilot 算好 reachable-first 順序再傳給 installer」**不足以**滿足 H5（"desired server pool 仍保留
`[ipa1, ipa2]`"）——argv 順序不是 installer 決定寫入哪些 server 的依據，它自己的連線探測才是。

**這使得 §7 的 server-failover reconciliation 從「錦上添花的 idempotent 安全網」變成「H5 能不能
PASS 的必要步驟」**：Phase 3/4 必須讓 reconciliation **無條件**接在每一次 fresh enrollment 之後
執行（不只是既有 client 才需要），並把 reconciliation 的比對基準設為 §3 的
`freeipa_server_pool`（完整 desired pool），而不是「這次 installer 實際寫入了什麼」——否則一台
在 primary 掛掉期間新增的 client，即使 primary 之後恢復，也永遠不會把它加回自己的 failover 清單。

---

# 6. `/etc/hosts` 改成 Pool-aware

目前：

```text
<ipa1-ip> ipa1.<domain> ipa1
```

改成 Pilot-managed block：

```text
# BEGIN PILOT FREEIPA SERVER POOL
10.0.0.10 ipa1.ipa.pilot.internal ipa1
10.0.0.11 ipa2.ipa.pilot.internal ipa2
# END PILOT FREEIPA SERVER POOL
```

目的：

- integrated DNS 短暫失效時，KDC/LDAP server FQDN 仍可解析。
- static multi-server Kerberos 不會重新引入 DNS SPOF。
- server add/remove 可 declarative reconcile。

必須保留目前 client 自己的：

```text
<client-ip> <client-fqdn> <shortname>
```

不要混入 server pool block。

## 6.1 Legacy migration

目前 Pilot 已寫入的 legacy primary line沒有 marker。

Migration 僅可刪除「完全等於 Pilot legacy format」且 FQDN/IP 都符合 current desired primary 的那一行，再改由 block 管理。

不得廣泛刪除使用者自訂 `/etc/hosts` entries。

---

# 7. Existing Client Day-2 HA Reconciliation

這是必要工作，不可只修 `ipa-client-install`。

新增：

```text
playbooks/apply/tasks/freeipa-client-server-failover.yml
```

執行時機：

```text
ipa-client-install fresh enrollment
        │
        ▼
server-failover reconciliation
        │
        ▼
SSSD restart / cache invalidate
        │
        ▼
HA health verification
```

對已 enrollment client，直接從 reconciliation 開始。

**這一步不是可選的 idempotent 保險，是必要步驟**（見 §5 Phase 0 實測證據）：installer 自己的
連線探測會把 enroll 當下不可達的 server 整個排除在 krb5.conf/sssd.conf 之外，所以即使是「剛
enroll 完的全新 client」，也必須無條件跑一次 reconciliation，把結果對齊 §3 的完整
`freeipa_server_pool`，才能保證 primary 掛掉期間新增的 client 之後也會擁有完整 failover 清單
（H5）。

## 7.1 先建立 golden fixtures

Coding 前先用 disposable VM 執行：

### Fixture A：單機

```bash
ipa-client-install --server=ipa1 ...
```

保存：

```text
/etc/krb5.conf
/etc/sssd/sssd.conf
/etc/ipa/default.conf
```

### Fixture B：兩台

```bash
ipa-client-install --server=ipa1 --server=ipa2 ...
```

保存相同三份檔案。

以 **真實 installer output** 決定 reconciler 應產生的 semantic state，禁止靠猜測 hard-code format。

Evidence 放：

```text
docs/evidence/freeipa-client-ha/<date>-installer-golden/
```

---

# 8. SSSD Reconciliation

Pilot 可以 declaratively 管理：

```ini
ipa_server = _srv_, ipa1.ipa.pilot.internal, ipa2.ipa.pilot.internal
```

Single：

```ini
ipa_server = _srv_, ipa1.ipa.pilot.internal
```

或 installer golden fixture 所實際產生的等價值。

規則：

1. 不使用 `--fixed-primary` semantic。
2. 不把 server pool 排序交給 nondeterministic map iteration。
3. 變更後 restart SSSD。
4. `sss_cache -E`。
5. 驗證：

```bash
sssctl domain-status <domain>
id <uncached-user>
```

---

# 9. Kerberos Reconciliation

必須讓直接使用 MIT Kerberos 的程式也能 HA：

```bash
kinit
kvno
kpasswd
```

不能只修 SSSD。

## 9.1 Required semantic state

HA 至少要有：

```ini
[realms]
IPA.PILOT.INTERNAL = {
    kdc = ipa1.ipa.pilot.internal:88
    kdc = ipa2.ipa.pilot.internal:88

    ...
}
```

`admin_server` / `kpasswd_server` 的實際 shape 應以 Phase 0 multi-server `ipa-client-install` golden fixture 為準。

## 9.2 不要用 blind `sed`

禁止沿用 runbook 現在：

```bash
sed -i 's/.../.../'
```

正式實作。

建立一個 deterministic reconciler：

```text
scripts/freeipa-client-krb5-reconcile.py
```

或等價 Ansible-safe helper。

要求：

1. 只修改目標 `ipa_realm` subsection。
2. 只修改 installer/Pilot 管理的：
   - `kdc`
   - `admin_server`
   - `kpasswd_server`
3. 保留：
   - 其他 realm。
   - `domain_realm`。
   - 使用者自訂非 server-list relation。
4. 先 backup。
5. atomic replace。
6. mutation 後立即驗證：
   - parser 可正常讀取。
   - `kinit -k -t /etc/krb5.keytab host/<client>@REALM` 成功。
7. validation fail → restore backup → fail play。

不得以「SSSD 還能登入」當 Kerberos config 成功證據。

---

# 10. Replica DNS 改善

目前 primary：

```yaml
ipa_setup_dns: "{{ freeipa_setup_dns | default(true) }}"
```

replica：

```yaml
ipa_setup_dns: "{{ freeipa_setup_dns | default(false) }}"
```

改成 **replica 繼承 realm 的 effective DNS policy**。

建議：

```text
primary effective DNS = true
    ↓
replica default DNS = true

primary effective DNS = false
    ↓
replica default DNS = false
```

因此：

- 單機：沒有 replica，不受影響。
- HA + integrated DNS：replica 預設同時成為 DNS provider。
- external DNS deployment：若 `freeipa_setup_dns=false`，所有 IPA node 都不強制跑 BIND。

## 10.1 Existing replica Day-2 DNS enablement

若：

```text
desired ipa_setup_dns = true
actual DNS server role = absent
```

不得因 `ipa-replica-install creates:` 已存在就 NOOP。

新增 idempotent reconciliation：

```text
check server-role DNS
        │
        ├─ enabled → NOOP
        │
        └─ absent
             │
             ├─ dnf ipa-server-dns
             └─ ipa-dns-install -U ...
```

forwarder/no-forwarder 必須沿用 primary/replica 現有 policy。

若：

```text
desired=false
actual DNS=enabled
```

**不要自動移除 DNS role**。

回報 drift/warning，要求明確 decommission workflow；避免 destructive downgrade。

---

# 11. DNS Client HA

`tasks/freeipa-dns-client-resolver.yml` 已經有 multi-nameserver 架構，保留並加強 gate。

## Single

允許：

```text
nameserver 10.0.0.10
```

## HA + integrated DNS

要求至少：

```text
nameserver 10.0.0.10
nameserver 10.0.0.11
```

且驗證：

```bash
dig @10.0.0.10 _ldap._tcp.<domain> SRV
dig @10.0.0.11 _ldap._tcp.<domain> SRV

dig @10.0.0.10 _kerberos._udp.<domain> SRV
dig @10.0.0.11 _kerberos._udp.<domain> SRV
```

兩台 authority 的 SRV RRset 必須都包含預期 server pool。

## External DNS mode

若 realm 明確：

```yaml
freeipa_setup_dns: false
```

則不要求 IPA replica 安裝 DNS。

但 HA verification 至少要確認 system resolver 能解析：

```text
_ldap._tcp.<domain>
_kerberos._udp.<domain>
所有 freeipa_server_fqdns
```

外部 resolver 本身是否具有 infrastructure HA 不由 Pilot v1 管理。

---

# 12. FreeIPA Client DNS Mutation 不得綁死 primary

目前 `freeipa-client-host-dns.yml` 使用：

```bash
dig @{{ ipa_server_ip }}
```

在 HA mode 下改成：

```text
freeipa_dns_authority_pool
```

read path：

```text
for server in pool:
    query authoritative data
    first valid authoritative response wins
```

但是 CAS / conflict detection 需要額外防 split-brain：

HA mode 必須至少比較兩個 authority：

```text
ipa1 RRset == ipa2 RRset
```

正常 multi-master replication 本身就有短暫收斂延遲；若 read-path 一發現 `ipa1 != ipa2` 就立即 fail closed，會把正常的 replication lag 誤判成 split-brain，導致 Day-2 DNS mutation 長期性 flaky。因此讀取前的一致性檢查必須是**有界重試**，不是單次比較：

```text
poll ipa1/ipa2 RRset, interval=<N>s, timeout=<T>s
  一致 → 用該值繼續
  timeout 仍不一致 → fail closed（此時才視為真正的 split-brain/複寫中斷）
```

**Phase 0 實測數據**（2026-09-17，vm-target `ipa-primary`/`ipa-replica`，同一 libvirt `default` 網路，近乎零延遲的 LAN 環境）：對一般 LDAP 物件（`ipa hostgroup-add`）做跨 server 收斂計時，`ipa1→ipa2` 與 `ipa2→ipa1` 兩個方向共 3 次試驗，全部在**第一次輪詢（1 秒間隔）就收斂**，量到的實際延遲介於 1.57s–2.33s。這是本環境的下限，不代表正式環境（跨機房/higher-latency 網路）的實際值,因此建議預設：

```text
interval = 2s
timeout  = 30s   (~15 次輪詢；本環境 3 次試驗最慢 2.33s 的 10 倍以上安全餘裕)
```

正式導入前，Phase 5 應在目標環境的真實網路拓樸下重跑同一組計時，若量到的延遲明顯高於本 LAN 環境，`<T>` 需相應調高，不得直接沿用這裡的 vm-target 數字。

不得選一台結果直接 mutation。

mutation 後也必須用同樣的 bounded-retry 邏輯等待所有 reachable DNS replica 收斂到 desired RRset，再 PASS；重試耗盡仍未收斂則回報 drift，不得靜默判定 PASS。

---

# 13. Pilot Control-plane Server Failover

即使 client runtime 已 HA，Pilot 自己執行 `ipa ...` CLI 若仍使用 `/etc/ipa/default.conf` 的單一 `xmlrpc_uri`，primary outage 時 Day-2 reconcile 還是會失敗。

新增 shared selector：

```text
playbooks/apply/tasks/freeipa-admin-endpoint-select.yml
```

輸入：

```yaml
freeipa_server_pool
```

輸出：

```yaml
freeipa_admin_server_fqdn
```

選擇規則：

1. desired pool 不變。
2. probe reachable HTTPS API。
3. deterministic first reachable。
4. 選擇結果的快取範圍是 **per play run，不是 per task**：同一次 `ansible-playbook` 執行只 select 一次並在整個 run 內重用，避免對每個 `ipa ...` task 都重新 probe 造成的延遲；同一次 run 內若 selected endpoint 中途變成不可達，允許重新 select 一次並記錄，但不得每個 task 都重探。
5. 如果所有 server unavailable → fail closed。

所有 client-side：

```text
ipa dnsrecord-*
ipa host-*
ipa group-*
```

等 operation 應明確使用 selected endpoint，做法是在每一個 `ipa` 呼叫加上：

```bash
ipa -e xmlrpc_uri=https://{{ freeipa_admin_server_fqdn }}/ipa/xml <command> ...
```

（見 §13.1 — 這是實測證實可行的 non-mutating per-invocation override，不需要改寫 `/etc/ipa/default.conf`。）

### 13.1 Concurrency safety — 已用實測解決，不需要序列化

**Phase 0 實測結論（2026-09-17）**：`ipa --help`/`man ipa` 證實 `-e KEY=VAL` 是官方支援的
per-invocation 覆寫（"This option overrides configuration files"），對 `xmlrpc_uri` 這個 key
同樣有效。實際驗證：client 的 `/etc/ipa/default.conf` 指向 `ipa2` 時，先停掉 `ipa1`，`ipa
host-find` 用預設設定（走 ipa2）成功，同一時間 `ipa -e
xmlrpc_uri=https://ipa1.ipa.pilot.internal/ipa/xml host-find` 準確回報
`[Errno 111] Connection refused`（連到真的關掉的那台，不是被 fallback 掩蓋掉的假成功）——證明
這個 override 真的改變了實際連線目標，不只是 `ipa env` 顯示的表面值。

因此原本擔心的「改寫共用 `default.conf` 造成 site-wide 併發 race」不成立，也不需要原先設想的
併發序列化：`freeipa-admin-endpoint-select.yml` 只需要把 `freeipa_admin_server_fqdn` 算出來、
餵給每個 `ipa` 呼叫的 `-e xmlrpc_uri=` 參數，全程不寫入任何共用檔案，天生對併發安全。

Phase 5 仍應補一條 regression/vm-target 證據，鎖住「`-e xmlrpc_uri=` 覆寫對一個真的被關掉的
server 會如實回報連線失敗，不會被自動 fallback 掩蓋」這個行為，避免未來 FreeIPA 版本升級後
`-e` 語意跟這裡假設的不一致卻沒人發現。

---

# 14. Contract / Delivery Provider Pool

Runtime HA 完成後，還要消除目前：

```yaml
sourceSelection: exactlyOne
```

對 control-plane 的單點語意。

## 14.0 現有機制盤點（先確認再動手）

`internal/delivery/dependency_availability.go` 目前對 ambiguous `exactlyOne`/`all` binding，`bindingProviderCandidates` 已經會 degrade 成「該 provider role 的所有候選 host」，再由 `anyReachable()` 判定「候選中任一台 reachable 即滿足依賴」——也就是說「N 個候選、reachable ≥ 1 即 satisfied」這個 availability 語意**已經存在**，不需要重新發明。

真正缺的能力只有一項：目前一個 binding 的候選 host 只能來自**單一** provider component/role（`from: {component: X}`）；`freeipa-client` 沒辦法讓同一個 binding 同時把 `freeipa-server` 和 `freeipa-server-replica` 兩個不同 component 的 host 合併成一份候選名單。因此 Phase 6 的範圍應限縮成：

1. 新增 `fromPool` 這種**跨 component 聚合**的 binding 型態（相對於現有的 `from`），只在 binding 使用 `fromPool` 時才進入新程式路徑。
2. `fromPool` 解析出的合併候選名單，直接餵給既有的 `anyReachable`/`ResolveExecutionScopeWithDependencies` 邏輯，不重寫這兩者。
3. `preflight.go` 的 `validateProviderBindings` 需要能驗證 `fromPool` 型態（目前只認 `from`），但不動 `exactlyOne`/`all`/`from` 既有分支。

全 repo 目前有 14 個 contract 使用 `sourceSelection: exactlyOne`（只有 FreeIPA 這組會改用 `fromPool`），只要新路徑嚴格用 `fromPool` 的有無來分支，其餘 13 個既有 `from`+`exactlyOne` 綁定在結構上不會被觸碰；仍必須新增 regression test 明確鎖住「既有非 FreeIPA 的 exactlyOne 綁定行為不變」（見 §17）。

## 14.1 需要的 contract abstraction

新增 generic `providerPool`（實作為上述 `fromPool` binding），不要在 FreeIPA 寫 hard-coded special case。

示意：

```yaml
providerPools:
  - id: freeipaServers
    members:
      - {component: freeipa-server, endpoint: https}
      - {component: freeipa-server-replica, endpoint: https}
    minAvailable: 1

bindings:
  - input: freeipa_server_pool
    fromPool: freeipaServers
    sourceSelection: all
```

`dependency_availability.go` 對 provider pool 的規則：

```text
pool member 2 台
reachable 1 台 → dependency satisfied
reachable 0 台 → dependency unavailable
```

這個 semantic 對 single-node 自然成立：

```text
pool member 1 台
reachable 1 台 → satisfied
reachable 0 台 → unavailable
```

## 14.2 禁止語意

不要把：

```text
primary down + replica up
```

判定成：

```text
freeipa-client dependency unavailable
```

只因 `freeipa-server` primary contract 的 exactlyOne host 不 reachable。

---

# 15. HA Verification 必須避免 SSSD Cache False Positive

目前 HA drill 已經證明：

```text
primary down
id user → 仍可能成功
```

不能據此判定 failover 正常，因為可能只是 offline cache。

每個 failover test 必須至少做：

```bash
kdestroy
sss_cache -E
```

並使用「從未在該 client lookup 過」的 principal。

至少驗證：

```text
kinit <uncached-user>
id <uncached-user>
sudo -l -U <uncached-user>
sssctl domain-status <domain>
```

其中：

```text
kinit
```

是必要的權威測試之一。

---

# 16. Acceptance Matrix

## S1 — Single server + integrated DNS

Topology：

```text
ipa1 + client
```

驗證：

- client deploy PASS。
- 不要求 replica。
- `kinit` PASS。
- `id` PASS。
- HBAC PASS。
- sudo PASS。
- DNS PASS。
- idempotent rerun `changed=0`（除預期 probe task）。
- reboot 後 PASS。

---

## S2 — Single server + no integrated DNS

Topology：

```text
ipa1(DNS disabled) + client
```

驗證：

- legacy `/etc/hosts` bootstrap capability 被保留。
- enrollment PASS。
- Kerberos PASS。
- SSSD PASS。
- 不因沒有 SRV record 強制報錯。
- `freeipa-dns-client` 若未選用，不應成為 required dependency。

這是 backward compatibility gate。

---

## H1 — Two server HA baseline

Topology：

```text
ipa1 + ipa2 + client
```

全部由 Pilot deploy，**禁止手動 sed**。

驗證：

```text
provider pool = [ipa1, ipa2]
KDC list      = ipa1 + ipa2
SSSD list     = _srv_ + ipa1 + ipa2
DNS resolver  = ipa1 + ipa2   # integrated DNS mode
```

---

## H2 — Primary failure

1. baseline 成功。
2. stop `ipa1`。
3. `kdestroy`。
4. `sss_cache -E`。
5. 使用 uncached user。

必須 PASS：

```text
kinit
id
sudo -l
DNS query
sssctl domain-status
```

Active server 最終必須是 `ipa2` 或其他 surviving replica。

---

## H3 — Replica failure

復原 `ipa1`、關閉 `ipa2`。

重複 H2。

必須 PASS。

---

## H4 — Total outage negative control

關閉所有 IPA server。

預期：

```text
fresh kinit → FAIL
```

不得把 cached `id` 成功解釋成 HA。

至少復原一台後：

```text
client 自動恢復
```

不得重跑 Pilot 才恢復。

---

## H5 — Fresh client while primary is down

Topology 已有：

```text
ipa1 down
ipa2 up
```

此時加入全新 client。

要求：

```text
pilot deploy freeipa-client → PASS
```

bootstrap selector 必須將 ipa2 排第一，但 desired server pool 仍保留 `[ipa1, ipa2]`。

---

## H6 — Existing single client migration

1. 使用舊版 single-server Pilot enroll client。
2. 加入 replica。
3. 更新 Pilot。
4. rerun `freeipa-client-apply.yml`。

禁止：

```text
ipa-client-install --uninstall
```

要求原地收斂為：

```text
single → HA
```

再執行 H2。

---

## H7 — Add third replica

```text
[ipa1, ipa2]
    ↓
[ipa1, ipa2, ipa3]
```

client rerun 後：

- SSSD pool 更新。
- Kerberos pool 更新。
- `/etc/hosts` pool 更新。
- 不重新 enroll host。
- ipa1 或 ipa2 任一台 down 仍 PASS。

---

## H8 — Replica removal

先完成正式 server decommission，再從 inventory 移除 ipa2。

client rerun：

- Pilot-managed SSSD entry 移除 ipa2。
- Pilot-managed Kerberos server list 移除 ipa2。
- Pilot-managed hosts block 移除 ipa2。
- 不動 foreign config。

---

# 17. Regression Tests

新增：

```text
internal/spec/freeipa_client_ha_regression_test.go
```

至少鎖：

1. `ipa-client-install` argv 由 list 產生，而不是單一 hard-code `--server={{ ipa_server_fqdn }}`。
2. single mode list length=1。
3. HA mode list length>=2。
4. 不存在 `--fixed-primary`。
5. server pool task 必須在 enrollment 前執行。
6. failover reconcile 必須在 fresh enrollment 後，也必須對 existing enrollment 執行。
7. `/etc/hosts` server pool 使用 managed block。
8. HA mode 不允許 `<2` provider。
9. single mode 不允許被 HA gate 誤擋。

擴充：

```text
internal/spec/freeipa_server_replica_regression_test.go
```

鎖：

- replica DNS effective policy 繼承 primary/realm policy。
- existing replica DNS role reconciliation 存在。
- `desired=false` 不自動移除 DNS。

擴充：

```text
internal/spec/freeipa_dns_client_regression_test.go
```

鎖：

- HA integrated-DNS mode 至少 2 nameserver。
- single mode允許 1 nameserver。
- explicit override 仍優先於 auto-detection。

Contract provider pool：

```text
internal/delivery/preflight_test.go
internal/delivery/dependency_availability_test.go
internal/contract/lint_test.go
```

至少測：

```text
pool=[ipa1] reachable=[ipa1]               PASS
pool=[ipa1] reachable=[]                   FAIL
pool=[ipa1,ipa2] reachable=[ipa1]          PASS
pool=[ipa1,ipa2] reachable=[ipa2]          PASS
pool=[ipa1,ipa2] reachable=[]              FAIL
```

**非回歸測試（必要）**：新增 `fromPool` binding 型態後，對其餘 13 個既有 `from`+`exactlyOne`/`all` 綁定的既有 test case 逐一重跑並保持全綠，額外鎖一條「一個沒有 `fromPool` 欄位的 binding，其解析結果與新增 `fromPool` 支援前完全相同」的 regression test，證明 §14.0 所述「新路徑只在 `fromPool` 存在時觸發」對既有 14 個 exactlyOne 綁定沒有副作用。

---

# 18. Disposable VM Topologies

保留目前：

```text
docs/topologies/freeipa-ha-topology.yaml
```

但必須移除 `docs/topologies/freeipa-ha-topology.yaml:35` 的註解：

```text
patched (manually — wire only pins /etc/hosts, see the runbook §6).
```

以及 `docs/runbooks/freeipa-server-replica-ha-drill.md` §6 現有的手動 `sed -i` 步驟本身（該 runbook 目前真的靠這幾行 sed 讓 client failover，見 §1 背景）——Phase 4/7 完成後，§6 改成直接引用 Server Pool + failover reconciliation 自動產生的結果，不再需要任何 `sed`；§14 gotcha 表對應那一列也一併移除或改記成「已修復」。

新增：

```text
docs/topologies/freeipa-single-topology.yaml
```

至少：

```text
ipa-primary
ipa-client
```

HA topology：

```text
ipa-primary
ipa-replica
ipa-ha-client
```

若 vm-target topology group 名稱和 production inventory role group 不一致，測試 inventory generation 必須映射到真正：

```text
freeipa-server
freeipa-server-replica
freeipa-client
freeipa-dns-client
```

避免測到一條 production 不會走的簡化 code path。

---

# 19. Verification Spec 更新

## `docs/verification/freeipa-client.md`

現況（撰寫本 spec 時）已用到 **C1–C12**（C12 為 SSH GSSAPI ticket delegation），因此新增 rows 必須從 **C13** 起接續，不得沿用下列示意編號：

```text
C13 server-pool
C14 sssd-failover
C15 kerberos-failover
C16 single-node-compatibility
C17 existing-client-ha-reconcile
```

實作前務必重新跑一次 `pilot spec docs/verification/freeipa-client.md --lint` 確認當下真實的最後一個 row 編號，不得憑本 spec 記錄的編號硬編。

## `docs/verification/freeipa-server-replica.md`

現況已用到 **C1–C15**（與 `contracts/freeipa-server-replica.yaml` 的 `traceability.rows` 一致），新增 rows 一律從 **C16** 起接續：

```text
C16 replica DNS role parity
C17 client no-manual-patch failover
```

同上，實作前重新 lint 確認真實最後編號。

## `docs/verification/freeipa-dns-client.md`

新增：

```text
HA resolver cardinality
SRV consistency across authorities
```

---

# 20. 實作階段

每個 Phase 除了自己的 exit gate 外，一律必須通過 AGENTS.md §3.0 既有的機器強制 gate：`cmd/pilot/cmd/tag_coverage_test.go::TestSpecPlaybookTagAlignment`（spec row 與 playbook tag 對齊）與 `TestRegression_SpecAndInventoryAgree`（spec 宣告的 group 與測試 inventory 對齊；本 spec 的 client/server-replica 屬於 AGENTS.md §3.0 例外，走 `-e target_group=` override 時比照 `freeipa_client_regression_test.go` 的既有作法處理）。不得只憑本 spec 自訂的 exit gate 就視為完成。

## Phase 0 — Golden behavior spike ✅ 完成（2026-09-17）

只調查，不改 production behavior。Evidence：
`docs/evidence/freeipa-client-ha/2026-09-17-installer-golden/`（`vm-target topology
docs/topologies/freeipa-ha-topology.yaml`：`ipa-primary`/`ipa-replica` AlmaLinux 9、
`ipa-ha-client` Ubuntu 24.04，`snapshot`/`rollback` 在同一台 client VM 上重複測試不同情境）。

工作與結果：

1. Fixture A（single `--server=ipa1`）：enroll 成功，`krb5.conf`/`sssd.conf`/`default.conf`
   都只含 ipa1，行為與現有 `freeipa-client-apply.yml` 一致。
2. Fixture B（HA `--server=ipa1 --server=ipa2`，兩台都上線）：enroll 成功，`sssd.conf` 產出
   `ipa_server = _srv_, ipa1.ipa.pilot.internal, ipa2.ipa.pilot.internal`，與 §4.2/§8 預期完全
   一致；`krb5.conf` 對 `kdc`/`master_kdc`/`admin_server`/`kpasswd_server` 都各自重複兩行
   （§9.1 只預期前三者，實際還多了 `master_kdc`，需相應調整 reconciler）；`default.conf` 的
   `server`/`xmlrpc_uri` 只認 ipa1（見 Phase 0 item 4）。
3. Fixture C（primary down 時 fresh HA enroll，見 §5 詳細記錄）：**重大發現**——installer 自己
   probe 每台給定的 server，把探測不到的整個從 krb5/sssd/default.conf 拿掉，不只是調整順序。
   單靠 argv 順序不足以保留完整 desired pool，§7 的 server-failover reconciliation 因此從
   「可選安全網」變成「H5 能不能 PASS 的必要步驟」（已回寫 §5/§7）。
4. `ipa` CLI server override：**確認為 non-mutating per-invocation**——`ipa -e
   xmlrpc_uri=https://<fqdn>/ipa/xml <command>` 真實變更連線目標（用「stop 該 server、確認
   override 指向它時如實回報連線失敗」驗證過，不是只改 `ipa env` 的顯示值），完全不需要碰
   `/etc/ipa/default.conf`。原本 §13.1 設想的併發序列化風險不存在（已回寫）。
5. Replication 收斂時間：LAN 環境（vm-target 同一 libvirt 網路）3 次試驗均在第一次 1 秒輪詢
   內收斂，實測 1.57s–2.33s；已回寫 §12 作為 `interval=2s / timeout=30s` 預設值的依據，並註明
   正式環境需重新量測。

Exit gate（全部通過）：

- [x] 確認 multi-server `ipa-client-install` 在 Ubuntu 24.04 client 符合預期（EL9 client 留給
      Phase 7 一併驗證，本階段未單獨測試 EL9 作為 client 角色）。
- [x] 確認 `ipa` CLI server override 機制——`-e xmlrpc_uri=`，non-mutating，不需序列化。
- [x] 記錄實測到的 replication 收斂時間區間（1.57s–2.33s，LAN 環境）。

---

## Phase 1 — Server Pool + topology mode ✅ 完成（2026-09-17）

修改（已完成，commit 待建立）：

```text
playbooks/apply/tasks/freeipa-server-pool.yml   (new)
contracts/freeipa-client.yaml                    (+freeipa_client_topology_mode groupVar)
group_vars/freeipa.example.yml                   (+文件)
internal/spec/freeipa_client_ha_regression_test.go (new, 7 tests)
```

先只產生 facts / debug，不改 enrollment——`freeipa-client-apply.yml` 本身完全沒動，新 task
尚未被任何 playbook include，Phase 3 才會真正接上 enrollment argv。

Evidence：`docs/evidence/freeipa-client-ha/2026-09-17-phase1-server-pool/ansible-run-output.log`
（本機 `ansible-core 2.19.2`，`ansible_connection: local` 的合成 inventory，非 vm-target——這個
task 100% 是 inventory/Jinja 計算，沒有任何遠端指令，不需要真實 VM 就能验证真實行為；`ipa`
CLI 相關行為已在 Phase 0 用 vm-target 驗證過）。

Exit gate（全部通過，見上述 evidence log）：

- [x] single inventory effective=`single`
- [x] HA inventory effective=`ha`
- [x] 強制 `ha` 但只有一台 → fail（`assertion evaluated_to: false`，訊息點名 spec §2.2/§3.2）
- [x] 強制 `single` 即使有 replica → pool active set 只使用 primary（`pool_full` 仍列兩台，
      `pool_active`/`freeipa_server_fqdns`/`freeipa_server_ips` 只有 primary）

額外驗證的 fail-closed invariant（超出原本 exit gate，但 §3.2 有要求，一併做掉）：

- [x] 2 台 replica 都沒設 `freeipa_replica_fqdn` → fail
- [x] 2 台 replica 都設了不同 `freeipa_replica_fqdn` → 成功，3 個相異 FQDN
- [x] 同一個 IP 綁到兩個不同 FQDN → fail
- [x] primary FQDN 與 replica FQDN 相同 → fail（duplicate-FQDN gate 一併涵蓋）

`go build ./...`、`go test ./internal/spec/... ./internal/contract/...`（290 pass）、
`ansible-lint playbooks/apply/tasks/freeipa-server-pool.yml`（0 failure/warning）、
`pilot contract lint`、`TestSpecPlaybookTagAlignment` 全部通過，無既有測試回歸。

---

## Phase 2 — Replica DNS parity ✅ 完成（2026-09-17）

修改（已完成）：

```text
playbooks/apply/freeipa-server-replica-apply.yml   (ipa_setup_dns default true; R3 Day-2 DNS reconciliation)
docs/verification/freeipa-server-replica.md          (+C16 row, ipa_setup_dns 變數說明更新)
contracts/freeipa-server-replica.yaml                (+C16 row mapping)
cmd/pilot/cmd/tag_coverage_test.go                    (+R3 stageTag)
internal/spec/freeipa_server_replica_regression_test.go (16 rows + 3 個新 DNS-parity 測試)
```

完成：

- DNS policy inheritance（`ipa_setup_dns` 預設從 `false` 改成 `true`，與 primary 一致）。
- fresh replica `--setup-dns`（既有邏輯，未變動語意，只是預設值跟著上面改變而觸發）。
- existing replica `ipa-dns-install` reconciliation（新增 R3 三個 task：ticket-free 的
  `systemctl is-active named.service` 偵測 → 缺就裝 `ipa-server-dns` + 跑
  `ipa-dns-install` → desired=false 但實際 active 只警告不移除）。
- role verification（新增 C16 row，`systemctl is-active named.service` rc-based）。

Evidence：`docs/evidence/freeipa-client-ha/2026-09-17-phase2-replica-dns-parity/`
（vm-target `ipa-primary`/`ipa-replica`/`ipa-ha-client`，4 個真實情境各自的完整
PLAY RECAP + 一次 `pilot vm-target verify` 16/16 PASS + 雙 DNS server SRV 查詢對照）。

Exit gate（全部通過）：

- [x] integrated DNS HA topology 兩台均可 authoritative answer（`dig @ipa1`/`dig @ipa2`
      對 `_kerberos._udp` 回傳相同 SRV RRset，見 evidence #6）。
- [x]（額外驗證，非原訂 exit gate 但 spec §10.1 要求）existing replica 從
      `ipa_setup_dns=false` 改回預設 `true` 後，Day-2 reconciliation 正確補裝 DNS。
- [x] idempotent rerun `changed=0`。
- [x] `desired=false` 但實際 DNS active 時只警告、不自動移除（drift 之後仍是 active）。

**實跑額外發現一個跟本 Phase 無關但擋住測試的真infra bug**：`vm-target reset` 後的 AlmaLinux 9
replica 系統時鐘一度落後 54 分鐘（`chronyd` 服務顯示 active 但 `chronyc tracking` 顯示從未真的
同步過），導致 `ipa-client-install`/`ipa-replica-install` 因 Kerberos clock skew 失敗兩次。手動
`hwclock -s` 修復後穩定重現。既有 precondition check 只查 `systemctl is-active`,查不到「服務在跑
但没真的同步」這種狀態——本次僅記錄、未修復(見 evidence README,不在本次 spec 範圍內)。

---

## Phase 3 — Fresh client multi-server enrollment ✅ 完成（2026-09-17）

修改（已完成）：

```text
playbooks/apply/freeipa-client-apply.yml    (server-pool wired in; dynamic --server argv;
                                              pool-aware /etc/hosts block; reachability gate)
docs/verification/freeipa-client.md          (C12 matcher 修復，見下方 real bug)
internal/spec/freeipa_client_regression_test.go (更新 1 個既有測試 + 新增 4 個)
```

完成：

- dynamic repeated `--server` argv（從 `freeipa_server_fqdns` 建構,single mode 自然收斂成單一
  `--server=` 旗標,語意跟修改前逐位元組相同）。
- all-server `/etc/hosts` block（`blockinfile`,依 §6 與 client 自己的 self-pin 分開;§6.1 legacy
  migration 已實作,但發現且修好一個實跑才會現形的自我衝突 bug,見下方）。
- **偏離 spec §5 的原始描述**：沒有實作「reachable-first argv 重排序」。Phase 0 實測已證實
  installer 自己會 probe 每個給定的 `--server` 並依連線狀況決定寫入哪些,不看 argv 順序;因此
  改成「probe + fail-closed gate」（0 台可達才擋,不重排序），已足夠滿足 spec §5 決策表(HA:
  `>=1 reachable` 可進 enrollment,`0 reachable` 才 fail)。
- single path byte-for-byte semantic compatibility（S1 實測與 Phase 0 Fixture A 的
  sssd.conf/krb5.conf 內容逐字相同）。

Evidence：`docs/evidence/freeipa-client-ha/2026-09-17-phase3-client-enrollment/`（vm-target
`ipa-primary`/`ipa-replica`/`ipa-ha-client`,用 `--group freeipa-server=ipa-primary --group
freeipa-server-replica=ipa-replica --group freeipa-client=ipa-ha-client` 組合出真正的
production role-group 名稱,讓 `freeipa-server-pool.yml` 的 inventory-driven 邏輯走真實路徑,不
是只靠 `-e ipa_server_ip=` override 繞過)。

Exit gate：

- [x] H1 PASS：`sssd.conf`/`krb5.conf` 含兩台,`/etc/hosts` pool block 含兩台,`kinit`/`id` 成功,
      idempotent rerun `changed=0`。
- [x] S1 PASS：與 Fixture A 內容相同,`pilot vm-target verify` 12/12 PASS,idempotent rerun
      `changed=0`。
- [ ] S2（single + 無 integrated DNS）尚未在本 phase 實跑——留給 Phase 7 完整 acceptance matrix
      補齊,不要誤植成已驗證。

**實跑找到並修好 3 個真 bug**（見 evidence README 完整說明）：

1. `vars: {freeipa_domain: "{{ ipa_domain }}"}` 直接放在 include_tasks 上會跟 `ipa_domain`
   自己的定義互相遞迴，Jinja 直接炸「Recursive loop detected in template」。改用中繼
   `set_fact` 打斷循環。
2. Legacy migration 的 anchored regex 跟 blockinfile 自己渲染出的 primary 那行文字完全相同
   （都是 `<ip> <fqdn> <shortname>`），沒有 gate 的話兩個 task 每次互相打架，永遠
   `changed`，永遠不會收斂到 idempotent。改成只在 block 還不存在時才跑 migration。
3. **與本 phase 無關但一起發現的既有 bug**：`docs/verification/freeipa-client.md` C12 用
   `grep -qi` 卻拿 `~yes` 比對 stdout——`-q` 本來就不印任何東西，這個 row 從一開始就不可能
   PASS，之前也沒人跑過所以沒被抓到。已修成 `sh -c '...'` 包住 pipe + rc-based `Expected: 0`。

---

## Phase 4 — Existing client Day-2 reconciliation ✅ 完成（2026-09-17）

新增（已完成）：

```text
playbooks/apply/tasks/freeipa-client-server-failover.yml
```

**未新增獨立 Python script**：改用 Ansible-native 實作（`set_fact`/`regex_search`/
`ansible.builtin.copy`），理由是這個 repo 完全沒有其他 playbook 邏輯走 Python script 這條路，
用純 Ansible 維持一致性；spec 原文本來就允許「等價 Ansible-safe helper」二選一。

完成：

- SSSD pool reconciliation（單行 `ipa_server=` lineinfile，從 `freeipa_server_fqdns` 算出）。
- Kerberos pool reconciliation（**非** blind sed：用兩個 `regex_search` 錨點把 krb5.conf
  切成 pre/post，中間换成從 `freeipa_server_pool_active` 全新算出的
  kdc/master_kdc/admin_server/kpasswd_server 區塊，用字串串接組回去,不是
  regex_replace 帶 replacement string——找到一個真的會爆的理由,見下方 bug 1）。
- backup/rollback（mutate 前 `copy` 備份,mutate 後 `kinit -k -t /etc/krb5.keytab` 真實驗證,
  失敗就還原備份 + fail play,不是「SSSD 還能查得到身分」就當作過）。
- idempotency（見 evidence,第二次 rerun `changed=0`）。
- 掛載時機：無條件接在 `ipa-client-install` 之後（不論這次是真的 fresh enroll 還是對已
  enrollment client 的 `creates:` no-op），對應 §7 的架構圖與 Phase 0 的實測發現。

Evidence：`docs/evidence/freeipa-client-ha/2026-09-17-phase4-existing-client-reconciliation/`
（H6 acceptance test：既有 single-mode client + inventory 加入 replica → rerun → 原地收斂成
HA,`kinit`/`sssctl domain-status` 都證實兩台 KDC 都被發現,rerun `changed=0`）。

Exit gate（全部通過）：

- [x] H6 PASS：single → HA 原地收斂,沒有 `--uninstall`,沒有手動編輯。
- [x] rerun `changed=0`。

**實跑找到並修好 1 個真 bug**（AGENTS.md §5.6 同類）：krb5 server-list block 原本用
`regex_replace('^(.*)$', '    kdc = \1:88\n    ...')` 在**單引號** YAML 字串裡塞 `\n`——
YAML 單引號完全不解析反斜線跳脫,結果 `\n` 真的變成字面上兩個字元寫進 `/etc/krb5.conf`,不是
換行 byte(實測看到 `kpasswd_server = ipa1...:464\n    kdc = ipa2...` 擠在同一行)。改用 Jinja
`{% for %}` template（跟 Phase 3 pool-aware `/etc/hosts` block 同一招）產生真正的多行內容。
**這個 bug 沒被驗證步驟本身抓到**（`kinit -k` 那次剛好還是驗證通過)——是靠人工檢視真實檔案內容
才發現,提醒「mutation 自己的驗證通過」不等於「輸出內容真的對」。

尚未做（留給 Phase 7 或之後）：rollback-on-validation-failure 路徑只靠程式碼結構自證（簡單的
布林 `when:` 條件），沒有刻意注入失敗來實測過。

---

## Phase 5 — DNS mutation/control-plane failover ✅ 完成（範圍比原文窄，2026-09-17）

修改（已完成）：

```text
playbooks/apply/tasks/freeipa-admin-endpoint-select.yml   (new)
playbooks/apply/tasks/freeipa-client-host-dns.yml           (8 處 dig 改用選中的 authority)
playbooks/apply/tasks/freeipa-host-annotations.yml          (6 處 ipa host-show/host-mod 加上 -e xmlrpc_uri=)
playbooks/apply/freeipa-client-apply.yml                    (wire selector + freeipa_dns_read_authority_ip)
```

完成：

- admin endpoint live selection（`-e xmlrpc_uri=` per-invocation override，Phase 0 已實測確認
  non-mutating,不需要序列化)。
- 把 `freeipa-client-host-dns.yml` 的 8 個 `dig @{{ ipa_server_ip }}`（永遠查 primary）改成
  `dig @{{ freeipa_dns_read_authority_ip }}`（查 live-selected endpoint)，以及
  `freeipa-host-annotations.yml` 6 個 `ipa host-show`/`ipa host-mod` 呼叫都加上同一個
  override——這兩個檔案都不是原本 Phase 5 修改清單裡列的,是實測 primary down 時連鎖失敗才發現
  需要一併修。

**沒有做（刻意縮小範圍,非遺漏)**：

- **replica consistency gate（§12 的「比較 >=2 authority,發現不一致就 fail closed」)**：沒做。
  `freeipa-client-host-dns.yml` 現有的 Day-2 IP replacement REPLACE 路徑（CAS 重驗證、identity
  proof、TOCTOU re-read）是一大塊已經很成熟、測過很多輪的 state machine（S1-S10）,要在這之上
  疊加「多權威一致性比對」需要重新驗證整條路徑,風險與工作量都遠超本輪其他 Phase。目前只是把
  單一 authority 從「永遠查 primary」換成「查 live-selected endpoint」——這解決了「primary 掛掉
  時連正常讀寫都失敗」這個實測遇到的真問題,但**沒有**偵測「兩個 authority 真的意見不一致
  (split-brain)」這件事,那個仍待補。
- 也沒有把 override 加到這兩個檔案以外「還在用 bare `ipa` CLI」的其他 task（例如
  freeipa-identity-apply.yml 等)——那是更大範圍的一次性 sweep,同樣留給之後。

Evidence：`docs/evidence/freeipa-client-ha/2026-09-17-phase5-admin-endpoint-select/`（5 個檔案
按時間序記錄:先發現 DNS read 沒修會擋、修完又發現 host-annotations 也會擋、修完兩個才真的
primary down 全綠,idempotent rerun 也綠)。

Exit gate（通過,但範圍如上收斂）：

- [x] primary down 時 DNS backfill（ADD 路徑）+ host annotations reconcile 仍 PASS
      (`ok=129 changed=0 failed=0`)。
- [x] primary 恢復後 idempotent rerun `changed=0`。
- [ ] REPLACE 路徑 + 多 authority 一致性 gate：未做,見上方說明。

---

## Phase 6 — Contract provider pool ⏸ 刻意延後（2026-09-17，非遺漏）

**沒有實作**。原因：

深入看過 `internal/delivery/dependency_availability.go`/`preflight.go` 之後（見 §14.0），發現
比原先估計的還要更動到核心：目前的 `Dependency`/`bindingProviderCandidates` 模型天生假設
「一個 dependency = 一個 provider component」，`firstUnmetDependency` 對
`component.Dependencies` 逐一獨立判斷 unmet——要讓「primary down 但 replica up」不被判定成
「freeipa-client dependency unavailable」，不能只加一個 binding 層的 `fromPool`,還得讓
**dependency 本身**能表示「這個需求可以由 pool 裡任一個 component 滿足」（OR 語意,不是現有的
per-component AND 獨立判斷）。這代表要新增 `Dependency.PoolID`（跟 `Component` 互斥的新欄位）、
在 `ResolveExecutionScopeWithDependencies`/`firstUnmetDependency`/`DependencySupportHosts` 三處
都加上 pool-aware 分支（把多個 component 的 role hosts union 起來再判斷 reachable),還要讓
`validateProviderBindings` 認得「provider 其實是一個虛擬 union,不是單一 component」。

這已經不是「加一個新 binding kind,行為對既有 14 個 exactlyOne 綁定零影響」這麼簡單──
`internal/delivery` 是被全部 37 個 component 共用的核心 layer,任何在這裡的改動都需要對整批
既有 contract 重新跑一次完整回歸,風險與工作量都遠超本輪其他 phase。相較之下,Phase 0-5 已經
用真實 vm-target 完整證明「client 端 HA 真的能 failover」這件事本身,Phase 6 影響的是
「Pilot 自己在 primary 掛掉時,site-wide 自動化部署會不會誤判 freeipa-client 缺依賴而跳過」──
這是真實但範圍更窄的問題（只影響全站自動化部署,不影響 client 本身的 HA 行為),留到之後單獨
一個 spec/session 處理比較負責任。

**Definition of Done 因此明確不含 Phase 6 這一項**——如果之後有人要撿起來做,設計方向已經在
上面（`Dependency.PoolID` + 三處 pool-aware 分支）想清楚了,不用重新調查一次。

修改（原訂,未執行）：

```text
internal/contract/*
internal/delivery/preflight.go
internal/delivery/dependency_availability.go
contracts/freeipa-client.yaml
```

Exit gate（未達成，留待後續)：

- [ ] primary down、replica up 不再被 dependency-availability layer 誤擋。
- [ ] single provider behavior 不退化。
- [ ] §17 的非回歸測試（13 個既有 exactlyOne 綁定 + 新增測試)。

---

## Phase 7 — Full destructive HA drill ✅ 完成（範圍如下,2026-09-17）

完整跑並全部 PASS：

```text
S1  ✅ (Phase 3 evidence 重用 + 本輪 §7 baseline 重新確認)
S2  ✅ (client 端 freeipa_client_register_dns=false，未另搭無 DNS 的 primary)
H1  ✅
H2  ✅ (uncached principal drilluser，符合 §15 嚴謹度要求)
H3  ✅ (對稱)
H4  ✅ (含負向對照組 neverseenuser + 復原後不重跑 Pilot 就自動恢復)
H5  ✅ (Phase 4 reconciliation 證實把 primary 補回 desired pool)
H6  ✅ (Phase 4 evidence，本輪不重跑)
H7  ⏸ 未做（需要第三台 VM，Phase 1 已用合成 inventory 驗證過底層邏輯）
H8  ⏸ 未做（需要完整 decommission 流程）
```

Evidence：

```text
docs/evidence/freeipa-client-ha/2026-09-17-phase7-full-drill/
```

（加上 Phase 0-5 各自的子目錄，合起來是完整證據鏈）

**結論**：

```text
client HA = supported（S1/S2/H1-H6 範圍內；H7/H8 拓樸變更未活體驗證，
            Phase 6 的 site-wide 自動化部署 dependency-availability 語意未做）
```

已寫入 `docs/runbooks/freeipa-server-replica-ha-drill.md`（全面改版，刪除舊版手動 sed 步驟）。

---

# 21. Rollout / Migration Policy

建議 rollout：

```text
release N
  topology_mode=auto
  server-pool discovery + report only

release N+1
  fresh client multi-server enrollment
  existing client reconciliation enabled in staging

release N+2a
  production existing-client reconciliation — canary
    僅對 staging 內一小撮（例如 1-2 台非關鍵）host 執行 Day-2
    krb5/sssd reconciliation，觀察至少一個完整業務週期無異常
    （這一步直接改寫正式 fleet 既有 /etc/krb5.conf、/etc/sssd/sssd.conf，
    禁止跳過直接對全 fleet 執行）

release N+2b
  production existing-client reconciliation — fleet-wide
  provider-pool control-plane semantics
```

因為 Phase 4 的 existing-client reconciliation 是對已在正式環境跑的 client 原地改寫 Kerberos/SSSD 設定，release N+2a 的 canary 步驟不可省略；canary 觀察期若出現任何 kinit/SSSD 異常，必須先回滾（依 §9.2 的 backup/restore）並回到 Phase 4 修正，才可重新排入 N+2b。

若需要在 production 漸進導入：

```yaml
freeipa_client_topology_mode: single
```

可暫時保持 legacy single behavior。

確認 replica / DNS / tests 完成後改回：

```yaml
freeipa_client_topology_mode: auto
```

不需要 uninstall/re-enroll。

---

# 22. Observability

每次 apply 至少輸出非敏感摘要：

```text
FreeIPA client topology:
  requested_mode: auto
  effective_mode: ha
  providers:
    - ipa1.ipa.pilot.internal (10.0.0.10)
    - ipa2.ipa.pilot.internal (10.0.0.11)
  dns_providers:
    - 10.0.0.10
    - 10.0.0.11
  bootstrap_server: ipa2.ipa.pilot.internal
  sssd_failover: PASS
  kerberos_failover_config: PASS
```

不得輸出：

- admin password。
- keytab。
- Kerberos ticket。
- secret vault path contents。

---

# 23. Failure Semantics

| 狀態 | single | HA |
|---|---|---|
| 1/1 provider reachable | PASS | N/A |
| 0/1 reachable | FAIL | N/A |
| 2/2 reachable | N/A | PASS |
| 1/2 reachable | N/A | PASS / degraded |
| 0/2 reachable | N/A | FAIL |
| HA requested but pool=1 | N/A | config FAIL |
| integrated DNS HA but只有 1 DNS provider | N/A | FAIL |
| DNS replicas RRset 不一致 | 可繼續 single authority | HA mutation fail closed |
| SSSD cached lookup成功但 `kinit` fail | FAIL | FAIL |

---

# 24. Non-goals

本計畫不導入：

- Keepalived / VIP。
- HAProxy/L4 LB 作為 FreeIPA client 前端。
- Pacemaker。
- shared filesystem。
- 自動轉移 CA renewal-master role。
- 同時容忍所有 FreeIPA node 故障。
- 自動管理外部企業 DNS resolver HA。
- multi-site / FreeIPA location latency routing。

FreeIPA 原生 multi-master + client failover 已足以解決本問題，不需要再疊一層 stateful LB。

---

# 25. Definition of Done

2026-09-17 現況（Phase 0-5、7 完成，Phase 6 刻意延後，H7/H8 未活體驗證）：

- [x] 只有 `freeipa-server` 一台時，不增加 replica 也能正常 deploy/client login（S1）。
- [x] single + no integrated DNS 仍可正常 enrollment/auth（S2，client 端 register_dns=false
      驗證過；沒有另搭一台真的關掉 DNS 的 primary）。
- [x] 有 replica 時 client 不需要任何人工 `/etc/krb5.conf` / `sssd.conf` patch（H1/H5/H6）。
- [x] fresh HA client 自動得到 multi-server Kerberos + SSSD（H1）。
- [x] existing single client rerun Pilot 後原地變成 HA（H6，Phase 4）。
- [x] primary 掛掉：fresh `kinit` PASS（H2）。
- [x] primary 掛掉：uncached `id` PASS（H2，`drilluser`）。
- [x] primary 掛掉：sudo/HBAC PASS（H2）。
- [x] replica 掛掉：對稱 PASS（H3）。
- [x] integrated DNS 模式任一 DNS server 掛掉仍可 resolve（H2/H3 的 `dig` 檢查）。
- [x] primary 掛掉時 Pilot Day-2 FreeIPA mutation 能使用 surviving replica（Phase 5：DNS
      backfill + host annotations，**不含** Day-2 IP-replacement REPLACE 路徑）。
- [x] 所有 FreeIPA server 掛掉時 fresh `kinit` 必須 FAIL（H4）。
- [x] 任一 server 恢復後 client 自動恢復，不要求重新 deploy（H4 recovery）。
- [x] HA drill 完全移除人工 `sed`（本次全面改版的 runbook）。
- [x] single/HA topology VM evidence 都 committed（`docs/evidence/freeipa-client-ha/`）。
- [x] regression tests 防止未來重新退化成單一 `--server`（`internal/spec/
      freeipa_client_ha_regression_test.go` 等）。

**明確不含**（見對應 Phase 的說明,不是遺漏)：
- Phase 6 contract provider pool（site-wide 自動化部署的 dependency-availability 語意）。
- H7（新增第三台 replica）/ H8（移除 replica）的活體 3-VM 驗證。
- DNS 多權威一致性 gate（spec §12 的 split-brain 偵測)與 Day-2 IP-replacement REPLACE 路徑
  的 admin-endpoint 整合。

---

# 26. 參考依據

Pilot baseline：

- `playbooks/apply/freeipa-client-apply.yml`
- `playbooks/apply/freeipa-server-replica-apply.yml`
- `playbooks/apply/tasks/freeipa-dns-client-resolver.yml`
- `playbooks/apply/tasks/freeipa-client-host-dns.yml`
- `contracts/freeipa-client.yaml`
- `contracts/freeipa-server-replica.yaml`
- `internal/delivery/preflight.go`
- `internal/delivery/dependency_availability.go`
- `docs/runbooks/freeipa-server-replica-ha-drill.md`
- `docs/verification/freeipa-server-replica.md`
- `docs/topologies/freeipa-ha-topology.yaml`

External behavior used by this design：

- FreeIPA `ipa-client-install`: `--server` may be specified multiple times; fixed list provides client failover.
- SSSD IPA provider: `_srv_` plus explicit primary server list supports automatic failover.
- IdM integrated DNS: replica may run integrated DNS via `ipa-replica-install --setup-dns`; DNS can also be added to an existing IdM server with `ipa-dns-install`.


