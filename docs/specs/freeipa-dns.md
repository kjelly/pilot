# SPEC：FreeIPA DNS Service Domain Declarative Reconciler

* **Component ID**：`freeipa-dns`
* **狀態**：Proposed
* **適用專案**：`kjelly/pilot`
* **目標架構**：Minimal PoC Architecture
* **主要入口**：`pilot reconcile`
* **主要管理對象**：FreeIPA DNS zones 與 DNS resource records
* **資料模型版本**：`schema_version: 1`

---

## 1. 目標

在現有 Pilot Minimal PoC 架構中，加入宣告式 FreeIPA DNS 管理能力，使操作者可以透過版本化 manifest 動態新增、更新及刪除服務 DNS 名稱。

第一個實際使用案例：

```text
grafana.example.com  → nexus
wazuh.example.com    → nexus
s3.example.com       → nexus
```

`nexus` 的 IP 不應硬編碼在 manifest；應由目前 inventory 中的：

```yaml
hostvars["nexus"].ansible_host
```

動態解析。

因此，即使每次使用 `pilot vm-target topology up` 重建 VM 後，libvirt DHCP 配發不同 IP，只需重新執行 `pilot reconcile`，DNS records 就會收斂到新的 `nexus` IP。

---

## 2. 非目標

第一版不處理：

1. Nginx、Caddy、Traefik 等反向代理設定。
2. Grafana、Wazuh、SeaweedFS 的 TLS 憑證簽發。
3. 公開 DNS provider API，例如 Cloudflare、Route 53。
4. Router 或 DHCP server 的 DNS server option。
5. DNSSEC key rollover。
6. GSS-TSIG dynamic DNS update。
7. Reverse DNS／PTR zone。
8. SRV、MX、CAA、NAPTR、SSHFP records。
9. 多個獨立 FreeIPA realm。
10. 自動將 public `example.com` 委派給 FreeIPA。

FreeIPA DNS reconciler 只管理 FreeIPA 內的 DNS control plane。

---

## 3. 架構決策

### 3.1 建立獨立 `freeipa-dns` component

新增：

```text
freeipa-server
└── freeipa-dns
```

`freeipa-dns` 是獨立的 day-2 reconciler，和 `freeipa-identity` 採用相同操作模式：

```bash
pilot reconcile -i <workspace>/inventory.yml
```

不由：

```bash
pilot deploy
```

自動執行。

理由：

* FreeIPA server 安裝與 DNS record lifecycle 是不同生命週期。
* 新增服務名稱不應觸發整個 FreeIPA server 重裝或 site-wide deploy。
* DNS records 不屬於 identity、HBAC、sudo 或 NFS roster。
* DNS manifest 不包含密碼，適合版本控制。
* DNS 變更需要獨立 preview、stage gate、刪除保護與 idempotency evidence。

> **為何不用現有 `contracts/dns.yaml`（`core-infra-provider` unbound + `dns_zones`）**：
> 那套機制對「內網自訂域名解析」已經夠用且複雜度低很多，但它是純轉發／靜態
> resolver，資料不進 LDAP、不會被 FreeIPA replica 複寫、也不是已加入 domain
> 的 client 拿 SRV record 做 Kerberos discovery 時查詢的來源。本 spec 選擇
> FreeIPA-integrated DNS，前提是這些服務名稱確實需要成為 FreeIPA 身分網域的
> 權威資料（單一 source of truth、隨 replica 複寫）。若只是要內網自訂域名
> 解析、不需要跟 FreeIPA identity 綁定，應優先用現有 `dns_zones`，不需要這支
> reconciler 額外的 Kerberos ccache／split-horizon／delegation 複雜度。

### 3.2 使用獨立 manifest

新增 manifest：

```text
<workspace>/freeipa-dns.yaml
```

對應 host variable：

```yaml
freeipa_dns_manifest_file: /absolute/path/to/workspace/freeipa-dns.yaml
```

該變數設定在 `freeipa-server` host。

FreeIPA admin 密碼仍由：

```text
<workspace>/.vault/main.yaml
```

提供：

```yaml
ipa_admin_password: ...
```

DNS manifest 本身禁止包含密碼。

### 3.3 單一 mutation target

`freeipa-dns` 的 `hostCardinality` 必須為：

```yaml
exactly-one
```

即使架構中存在 FreeIPA replica，也只在 designated primary 執行 DNS mutation。FreeIPA replication 負責將 DNS LDAP objects 複製到 replicas。

不得同時在 primary 與 replica 平行執行 reconciler。

---

## 4. Manifest schema

### 4.1 完整範例

```yaml
---
schema_version: 1

freeipa:
  domain: ipa.pilot.internal
  realm: IPA.PILOT.INTERNAL
  server: ipa1.ipa.pilot.internal

dns:
  defaults:
    ttl: 300
    records_mode: merge

  safety:
    allow_shadow_existing_zone: false
    allow_authoritative_prune: false
    allow_zone_delete: false

  zones:
    - name: example.com.
      state: present

      # merge:
      #   只管理 manifest 中明確出現的 RRset。
      # authoritative:
      #   manifest 是此 zone 支援 record types 的完整 desired state。
      records_mode: merge

      # 如果 example.com 已存在於外部 DNS，建立同名 FreeIPA zone
      # 會形成 split-horizon DNS。必須明確確認。
      acknowledge_split_horizon: true

      records:
        - name: grafana
          type: A
          state: present
          ttl: 300
          target:
            inventory_host: nexus

        - name: wazuh
          type: A
          state: present
          ttl: 300
          target:
            inventory_host: nexus

        - name: s3
          type: A
          state: present
          ttl: 300
          target:
            inventory_host: nexus
```

結果：

```text
grafana.example.com.  A  <目前 nexus ansible_host>
wazuh.example.com.    A  <目前 nexus ansible_host>
s3.example.com.       A  <目前 nexus ansible_host>
```

### 4.2 建議的 delegated service zone

正式環境較建議將專用子網域委派給 FreeIPA：

```yaml
dns:
  defaults:
    ttl: 300
    records_mode: authoritative

  safety:
    allow_shadow_existing_zone: false
    allow_authoritative_prune: true
    allow_zone_delete: false

  zones:
    - name: svc.example.com.
      state: present
      records_mode: authoritative

      delegation:
        verify: true
        expected_nameservers:
          - ipa1.ipa.pilot.internal.

      records:
        - name: grafana
          type: A
          state: present
          target: {inventory_host: nexus}

        - name: wazuh
          type: A
          state: present
          target: {inventory_host: nexus}

        - name: s3
          type: A
          state: present
          target: {inventory_host: nexus}
```

結果為：

```text
grafana.svc.example.com
wazuh.svc.example.com
s3.svc.example.com
```

上層 authoritative DNS 必須事先建立 NS delegation。Pilot 第一版只驗證 delegation，不修改上層 DNS。

---

## 5. Schema contract

### 5.1 Top-level keys

只接受：

```text
schema_version
freeipa
dns
```

未知 top-level key 必須 fail closed。

### 5.2 `freeipa` keys

```yaml
freeipa:
  domain: string
  realm: string
  server: FQDN
```

規則：

* `domain` 必須與 inventory 的 `freeipa_domain` 相同。
* `realm` 必須與 `freeipa_realm` 相同。
* `server` 必須與 `freeipa_server_fqdn` 相同。
* manifest 不得有 `admin.password`。
* manifest 所指定 server 必須等於實際執行 playbook 的 FreeIPA server。

任一不一致時，在 `kinit` 和任何 mutation 前失敗。

### 5.3 Zone fields

| 欄位                          | 必填 | 允許值                             |
| --------------------------- | -: | ------------------------------- |
| `name`                      |  是 | 絕對 DNS zone FQDN                |
| `state`                     |  否 | `present`、`absent`；預設 `present` |
| `records_mode`              |  否 | `merge`、`authoritative`         |
| `acknowledge_split_horizon` |  否 | boolean，預設 `false`              |
| `delegation`                |  否 | delegation verification object  |
| `records`                   |  否 | record list                     |

Zone name 正規化規則：

* 轉成小寫。
* 內部統一補上結尾 `.`。
* 禁止 root zone `.`。
* 第一版禁止 `in-addr.arpa.`。
* 第一版禁止 `ip6.arpa.`。
* 禁止刪除 FreeIPA identity domain。
* 禁止 authoritative prune FreeIPA identity domain。

### 5.4 Record fields

| 欄位                      |  必填 | 說明                               |
| ----------------------- | --: | -------------------------------- |
| `name`                  |   是 | zone-relative owner name，或 `@`   |
| `type`                  |   是 | `A`、`AAAA`、`CNAME`               |
| `state`                 |   否 | `present`、`absent`               |
| `ttl`                   |   否 | 60–86400，預設使用 `dns.defaults.ttl` |
| `values`                | 條件式 | 明確指定 record values               |
| `target.inventory_host` | 條件式 | 從 inventory 解析 IP                |

`values` 和 `target` 必須二選一，不能同時存在。

### 5.5 Inventory target resolution

以下宣告：

```yaml
target:
  inventory_host: nexus
```

解析為：

```yaml
hostvars["nexus"].ansible_host
```

要求：

* `nexus` 必須存在於 inventory。
* `ansible_host` 必須存在且非空。
* `A` record 只能解析成 IPv4。
* `AAAA` record 只能解析成 IPv6。
* 不接受 inventory hostname 的模糊比對。
* 不接受取 inventory group 第一台主機。
* 目標 host 不存在時必須在 mutation 前失敗。

### 5.6 CNAME 規則

CNAME value 必須：

* 是完整 FQDN。
* 以 `.` 結尾。
* 不可是 IP。
* 不可與自身 owner 相同。
* 不可建立於 zone apex `@`。
* 同一 owner 不可同時宣告 CNAME 與 A／AAAA。
* 如果目前 FreeIPA 中同一 owner 已有其他 RR type，reconciler 必須 fail closed，不得偷偷刪除其他 record type。

範例：

```yaml
- name: grafana
  type: CNAME
  state: present
  values:
    - nexus.ipa.pilot.internal.
```

---

## 6. Desired-state 語意

### 6.1 `merge` mode

`merge` 是預設且較安全的模式。

行為：

* 新增 manifest 中不存在的 records。
* 更新 manifest 中 values 或 TTL 不一致的 records。
* manifest 未提及的既有 records 保留。
* 從 manifest 移除一筆 record，不代表刪除 FreeIPA record。
* 刪除必須明確宣告 `state: absent`。

範例：

```yaml
- name: wazuh
  type: A
  state: absent
```

當 `state: absent` 沒有指定 `values` 時，刪除該 owner 的指定 RRset type，但不得刪除同 owner 的其他 RR type。

### 6.2 `authoritative` mode

`authoritative` 表示 manifest 是該 zone 下所有受支援 RR types 的完整 desired state。

行為：

* 新增缺少的 records。
* 更新不同的 records。
* 刪除 manifest 中已不存在的 A、AAAA、CNAME RRsets。
* 保留 SOA 與 NS。
* 第一版不處理或刪除不支援的 record types。
* 必須同時設定：

```yaml
dns:
  safety:
    allow_authoritative_prune: true
```

若未確認，preview 可顯示預計刪除內容，但 real apply 必須拒絕。

`authoritative` 只建議用於專門委派給 Pilot／FreeIPA 的 service zone，例如：

```text
svc.example.com.
```

不建議用於共用 public apex zone。

### 6.3 Zone deletion

宣告：

```yaml
- name: old-svc.example.com.
  state: absent
```

必須同時符合：

```yaml
dns:
  safety:
    allow_zone_delete: true
```

並在 reconcile real-apply prompt 額外確認：

```text
confirm_dns_zone_delete=true
```

缺少任一條件都必須拒絕。

以下 zones 永遠禁止刪除：

* FreeIPA identity domain。
* Root zone。
* Reverse zones。
* FreeIPA installer 建立且被標記為 protected 的 zones。

---

## 7. Split-horizon 與 delegation safety

### 7.1 偵測既有外部 zone

建立新 zone 前，reconciler 應使用 FreeIPA forwarder 或明確設定的 upstream resolver 查詢：

```bash
dig +short SOA example.com. @<upstream>
```

如果 upstream 已存在同名 zone，而 FreeIPA 尚未管理該 zone，代表即將建立 split-horizon zone。

除非 zone 明確宣告：

```yaml
acknowledge_split_horizon: true
```

否則 real apply 必須拒絕。

### 7.2 Delegation verification

若設定：

```yaml
delegation:
  verify: true
  expected_nameservers:
    - ipa1.ipa.pilot.internal.
```

reconciler 必須查詢 parent DNS 的 NS delegation。

結果不符合時：

* `--check`：顯示 warning 和預期差異。
* real apply：預設 fail closed。
* 不自動修改 parent DNS。

---

## 8. Reconcile 執行流程

`playbooks/apply/freeipa-dns-apply.yml` 必須依下列順序執行。

### 8.1 載入 manifest

使用 namespaced include：

```yaml
- ansible.builtin.include_vars:
    file: "{{ freeipa_dns_manifest_file }}"
    name: freeipa_dns_manifest
```

禁止使用：

```bash
-e @freeipa-dns.yaml
```

避免未來 top-level key 與 Ansible magic variables 衝突，也與其他 canonical roster 的載入模式一致。

### 8.2 Preflight gates

所有 gates 必須在 `kinit` 及 mutation 前執行：

1. manifest file 存在。
2. `schema_version == 1`。
3. 無未知 keys。
4. FreeIPA domain、realm、server 與 inventory 一致。
5. `freeipa_setup_dns` 未被設為 `false`。
6. FreeIPA DNS API 可用。
7. TCP/UDP 53 正常 listening。
8. inventory target references 全部可解析。
9. 所有 IP/FQDN/TTL 格式正確。
10. zone、record identity 不重複。
11. CNAME exclusivity 成立。
12. prune/delete safety conditions 成立。
13. stage 與 inventory environment group 一致。

### 8.3 Kerberos credential

使用獨立 credential cache：

```text
/tmp/pilot-freeipa-dns-<pid>.ccache
```

以 `ansible.builtin.command` 的 `stdin` 傳送密碼：

```yaml
argv:
  - kinit
  - admin@IPA.PILOT.INTERNAL
stdin: "{{ ipa_admin_password }}"
```

要求：

* `no_log: true`
* 不使用 command-line password argument。
* play 結束時一定執行 `kdestroy`。
* cache file 必須在 `always` block 中刪除。

### 8.4 讀取 current state

使用 FreeIPA CLI，不增加外部 Ansible collection dependency：

```bash
ipa dnszone-show
ipa dnszone-find
ipa dnsrecord-show
ipa dnsrecord-find
```

優先使用 `--all --raw`（未翻譯的 LDAP attribute 名稱，locale-independent）；禁止依賴翻譯後的人類可讀訊息做核心狀態判斷。

> 註：`ipa` CLI 讀取指令沒有真正的 JSON 輸出模式（真 JSON 只存在於 IPA 的
> JSON-RPC API，需要額外的 Kerberos-認證 HTTP client，超出本 spec §8 範圍）。
> 沿用 `freeipa-identity-apply.yml` 已驗證的做法：`--all --raw` 取得英文
> attribute 名稱後逐行 parse，而非期待可直接反序列化的 JSON。

Current state 正規化為：

```yaml
current_zones:
  example.com.:
    records:
      grafana:
        A:
          ttl: 300
          values: [10.0.0.20]
```

所有 values：

* 排序。
* 去除重複。
* DNS names 轉小寫並補 trailing dot。
* IP 使用 canonical textual representation。

### 8.5 產生 plan

Plan 必須區分：

```text
CREATE_ZONE
DELETE_ZONE
ADD_VALUE
DELETE_VALUE
DELETE_RRSET
SET_TTL
NOOP
```

Preview 範例：

```text
CREATE_ZONE example.com.
ADD_VALUE grafana.example.com. A 192.168.122.81
ADD_VALUE wazuh.example.com. A 192.168.122.81
ADD_VALUE s3.example.com. A 192.168.122.81
SET_TTL grafana.example.com. 300
```

刪除必須以醒目方式顯示：

```text
DELETE_RRSET old.example.com. A
DELETE_ZONE old-svc.example.com.
```

### 8.6 Check mode

`--check --diff` 必須：

* 執行完整 validation。
* 執行完整 current-state discovery。
* 產生完整 plan。
* 不執行任何 IPA mutation。
* 有差異時讓 recap 顯示 `changed > 0`。
* 無差異時顯示 `changed=0`。
* 不建立或刪除 Kerberos／DNS persistent state。

### 8.7 Apply order

Real apply 順序：

1. 建立 zones。
2. 更新 zone attributes。
3. 刪除明確 absent records。
4. authoritative prune stale records。
5. 新增／更新 desired records。
6. 更新 TTL。
7. 刪除 state absent zones。
8. Post-apply verification。
9. 清除 Kerberos credential。

Records 必須在 zone deletion 前處理，以便產生清楚 evidence。

### 8.8 Post-apply verification

每筆 `state: present` record 都必須驗證：

```bash
dig @127.0.0.1 +short <fqdn> <type>
```

回覆集合必須等於 desired values。

另從 FreeIPA server 的 LAN IP 驗證：

```bash
dig @<freeipa_server_ip> +short <fqdn> <type>
```

`state: absent` RRset 必須回覆空集合。

---

## 9. Stage policy

沿用 Pilot 現有 stage convention：

```yaml
stage: sandbox
confirm_staging: false
confirm_prod: false
staging_attested_within_hours: 168
```

規則：

* `sandbox`：一般 create/update 可直接套用。
* `staging`：需要 `confirm_staging=true`。
* `prod`：需要 `confirm_prod=true` 且 staging attestation 未超過 168 小時。
* authoritative prune：另外需要 manifest safety flag。
* zone delete：另外需要 manifest safety flag 和 runtime confirmation。

禁止用 manual extra `-e` 臨時覆寫 manifest 中的 zone 或 record。

---

## 10. Component contract

新增：

```text
contracts/freeipa-dns.yaml
```

建議內容：

```yaml
---
schemaVersion: 1
id: freeipa-dns
role: freeipa-server

specs:
  - path: docs/verification/freeipa-dns.md
    rows: {all: true}

playbooks:
  apply: playbooks/apply/freeipa-dns-apply.yml

regressionTests:
  - internal/spec/freeipa_dns_regression_test.go
  - cmd/pilot/cmd/tag_coverage_test.go

dependencies:
  - component: freeipa-server
    required: true
    relation: sameHosts

conflicts: []
bindings: []

hostCardinality: exactly-one

resources:
  minCPU: 1
  minRAMMiB: 512
  minDiskGiB: 1

groupVars:
  - name: ipa_admin_password
    type: string
    required: true
    secret: true
    validation: "^.{8,}$"

stagePolicy:
  variable: stage
  default: sandbox

evidenceRequirement:
  targetTest: topology
  idempotency: required

traceability:
  mode: mapped
  rows:
    "docs/verification/freeipa-dns.md#C1":
      {tags: [freeipa-dns-zone], reason: zone creation}
    "docs/verification/freeipa-dns.md#C2":
      {tags: [freeipa-dns-record], reason: A record reconcile}
    "docs/verification/freeipa-dns.md#C3":
      {tags: [freeipa-dns-record], reason: AAAA record reconcile}
    "docs/verification/freeipa-dns.md#C4":
      {tags: [freeipa-dns-record], reason: CNAME reconcile}
    "docs/verification/freeipa-dns.md#C5":
      {tags: [freeipa-dns-target], reason: inventory host resolution}
    "docs/verification/freeipa-dns.md#C6":
      {tags: [freeipa-dns-record], reason: TTL reconcile}
    "docs/verification/freeipa-dns.md#C7":
      {tags: [freeipa-dns-delete], reason: explicit RRset deletion}
    "docs/verification/freeipa-dns.md#C8":
      {tags: [freeipa-dns-prune], reason: authoritative stale-record pruning}
    "docs/verification/freeipa-dns.md#C9":
      {tags: [freeipa-dns-safety], reason: protected-zone safety}
    "docs/verification/freeipa-dns.md#C10":
      {tags: [freeipa-dns-safety], reason: split-horizon safety}
    "docs/verification/freeipa-dns.md#C11":
      {tags: [freeipa-dns-verify], reason: authoritative DNS answer}
    "docs/verification/freeipa-dns.md#C12":
      {tags: [freeipa-dns-idempotency], reason: clean rerun}

verification:
  autoDeploy: false

site:
  include: false
  order: 0
  vars: {}
  tags: []
  optIn: true
```

---

## 11. Pilot edit 整合

新增獨立選單，不放進 identity roster manager：

```text
pilot edit
├── Hosts
├── Group vars
├── Vault
├── FreeIPA identity roster
├── FreeIPA DNS manifest
└── ...
```

新增檔案：

```text
cmd/pilot/cmd/edit_tui_dns_manifest.go
internal/inventory/freeipa_dns_manifest.go
internal/inventory/freeipa_dns_validate.go
```

### 11.1 TUI 功能

第一版至少支援：

* 建立最小 manifest。
* 顯示 zones。
* 新增 zone。
* 編輯 zone state。
* 編輯 `records_mode`。
* 顯示 records。
* 新增 A／AAAA／CNAME record。
* 設定 explicit values。
* 設定 `target.inventory_host`。
* 修改 TTL。
* 將 record 設成 `state: absent`。
* 顯示完整 normalized preview。
* 顯示 validation violations。

### 11.2 寫入規則

所有寫入必須：

1. 先在記憶體中 simulate。
2. 執行與 playbook gates 對等的 Go validator。
3. 只有 validation 通過才寫檔。
4. 使用 `yaml.Node` 修改。
5. 不完整 remarshal 整份 YAML。
6. 保留未修改區段的 comments 與順序。

---

## 12. Minimal PoC 整合

### 12.1 Workspace

新增：

```text
<workspace>/
├── hosts.yml
├── inventory.yml
├── freeipa-dns.yaml
├── host_vars/
│   └── freeipa-server.yml
└── .vault/
    └── main.yaml
```

`host_vars/freeipa-server.yml`：

```yaml
freeipa_dns_manifest_file: /absolute/path/to/workspace/freeipa-dns.yaml
```

必須使用絕對路徑。

### 12.2 操作順序

```bash
./pilot vm-target topology up \
  --topology docs/topologies/minimal-poc-topology.yaml

./pilot edit --dir <workspace>
./pilot inventory generate --dir <workspace>
./pilot edit --dir <workspace>

./pilot deploy \
  -i <workspace>/inventory.yml \
  --timeout 90m

./pilot reconcile \
  -i <workspace>/inventory.yml \
  --timeout 90m
```

DNS reconciliation 時選擇：

```text
component: freeipa-dns
target: freeipa-server
stage: sandbox
secret vars file: <workspace>/.vault/main.yaml
manual extra -e: empty
```

### 12.3 解析器限制

目前 FreeIPA client deployment 不應被此 component 靜默修改。

第一版 acceptance 使用：

```bash
dig @<freeipa_server_ip> grafana.example.com
```

驗證。

若需要讓 `nexus`、`client-vm` 或 LAN 裝置直接執行：

```bash
curl https://grafana.example.com
```

則 DHCP、systemd-resolved 或 NetworkManager 必須另外把 FreeIPA 設成該 zone 的 resolver。這應做成後續獨立的 `freeipa-dns-client` component，不應偷偷塞入 `freeipa-dns` server reconciler。

---

## 13. Verification spec

新增：

```text
docs/verification/freeipa-dns.md
```

至少包含以下 rows：

| ID  | 驗證                                            |
| --- | --------------------------------------------- |
| C1  | Desired zone 存在且 active                       |
| C2  | A record values 等於 manifest                   |
| C3  | AAAA record values 等於 manifest                |
| C4  | CNAME target 等於 manifest                      |
| C5  | `inventory_host: nexus` 解析為目前 `ansible_host`  |
| C6  | TTL drift 可被修正                                |
| C7  | `state: absent` 可刪除指定 RRset                   |
| C8  | authoritative mode 可刪除 stale supported RRsets |
| C9  | identity/protected zone deletion 被拒絕          |
| C10 | 未確認的 split-horizon zone creation 被拒絕          |
| C11 | `dig @FreeIPA` 回覆符合 desired state             |
| C12 | 無 drift rerun 為 `changed=0 failed=0`          |

---

## 14. 測試需求

### 14.1 Go unit tests

新增：

```text
internal/inventory/freeipa_dns_validate_test.go
internal/inventory/freeipa_dns_manifest_test.go
```

覆蓋：

* 缺少 schema version。
* 未知 top-level key。
* 重複 zone。
* 重複 `(zone, name, type)`。
* 非法 zone FQDN。
* 非法 IPv4／IPv6。
* 非法 CNAME。
* CNAME 與 A 同 owner。
* apex CNAME。
* 不存在的 inventory host。
* A record 指到 IPv6。
* AAAA record 指到 IPv4。
* TTL 超出範圍。
* 未確認 authoritative prune。
* 未確認 zone delete。
* protected zone delete。
* split-horizon 未確認。
* manifest normalization deterministic。
* YAML comments preservation。

### 14.2 Regression tests

新增：

```text
internal/spec/freeipa_dns_regression_test.go
```

鎖定：

* C1–C12 全部存在。
* 每列有 command 和 expected。
* contract traceability 完整。
* apply playbook tags 覆蓋完整。
* component 為 day-2、`site.include: false`。
* dependency 為 `freeipa-server sameHosts`。
* cardinality 為 `exactly-one`。

### 14.3 Playbook integration tests

測試流程：

1. 建立 `example.com.`。
2. 建立三筆 A records 指向 nexus。
3. 變更 inventory 中 nexus IP。
4. check mode 顯示三筆 update。
5. real apply 更新三筆 records。
6. 外部手動修改 Grafana record 製造 drift。
7. reconcile 修正 drift。
8. 將 Wazuh 設為 `state: absent`。
9. reconcile 刪除 Wazuh A RRset。
10. 建立 unmanaged TXT record。
11. merge mode rerun保留 TXT。
12. authoritative mode 只 prune 支援且宣告可管理的 RR types。
13. clean rerun `changed=0 failed=0`。

---

## 15. 分階段實作

### Phase 1：Contract、schema 與 read-only plan

交付：

* `contracts/freeipa-dns.yaml`
* manifest example
* Go validator
* verification spec skeleton
* playbook manifest loading
* current-state discovery
* check-mode plan
* 所有 safety gates

限制：

* 不執行 DNS mutation。

完成標準：

* 合法 manifest 可產生 deterministic plan。
* 非法 manifest 全部在 `kinit` 前失敗。
* `go test ./...` 通過。

### Phase 2：Zone 與 present records

交付：

* zone create。
* A／AAAA／CNAME add。
* value reconcile。
* TTL reconcile。
* post-apply `dig` verification。

完成標準：

* 三個 service domains 可解析至目前 nexus IP。
* nexus IP 改變後可自動更新。
* rerun `changed=0`。

### Phase 3：Deletion 與 authoritative mode

交付：

* explicit RRset absence。
* stale RRset prune。
* protected-zone safety。
* zone deletion double confirmation。
* split-horizon detection。

完成標準：

* merge mode 不刪 unmanaged records。
* authoritative mode 可清除 stale managed record types。
* 所有 destructive operation 都有 fail-closed gate。

### Phase 4：`pilot edit` TUI

交付：

* DNS manifest top-level menu。
* zone／record CRUD。
* inventory host picker。
* simulate-before-write。
* comment-preserving YAML node edits。

完成標準：

* 不需手改 YAML 即可建立三筆 service records。
* TUI 產出的 manifest 通過相同 Go validator。
* scripted action／TREC 可重放。

### Phase 5：Minimal PoC evidence

交付：

* 更新 Minimal PoC configuration guide。
* 更新 Minimal PoC architecture runbook。
* 新增 reconcile DNS drive script。
* 新增完整 actual-run evidence。
* 更新 teaching guide。

完成標準：

* Fresh VM rebuild。
* Full site deploy。
* Identity reconcile。
* DNS reconcile。
* 三個 service names 從 FreeIPA DNS 正確解析。
* drift correction 通過。
* deletion cycle 通過。
* 最終 idempotency `changed=0 failed=0`。
* evidence 無 secret scan findings。

---

## 16. 建議檔案變更清單

```text
contracts/freeipa-dns.yaml

playbooks/apply/freeipa-dns-apply.yml
playbooks/apply/freeipa-dns.manifest.example.yaml

docs/verification/freeipa-dns.md
docs/runbooks/freeipa-dns.md
docs/runbooks/minimal-poc-architecture.md
docs/runbooks/minimal-poc-configuration.md

internal/inventory/freeipa_dns_manifest.go
internal/inventory/freeipa_dns_validate.go
internal/inventory/freeipa_dns_manifest_test.go
internal/inventory/freeipa_dns_validate_test.go

internal/spec/freeipa_dns_regression_test.go

cmd/pilot/cmd/edit_tui_dns_manifest.go
cmd/pilot/cmd/edit_tui_dns_manifest_test.go
cmd/pilot/cmd/tag_coverage_test.go
cmd/pilot/cmd/deploy_catalog.go   # register Reconcile:true catalog entry, per AGENTS.md §3.0
DELIVERY.md                       # playbook table row, same as freeipa-identity (line ~539)

playbooks/test/fixtures/freeipa-dns-canonical.yaml
playbooks/test/fixtures/freeipa-dns-invalid-cname.yaml
playbooks/test/fixtures/freeipa-dns-authoritative.yaml

scripts/minimal-poc/04a-edit-freeipa-dns.drive
scripts/minimal-poc/04b-reconcile-freeipa-dns.drive
scripts/minimal-poc/README.md
scripts/minimal-poc/TEACHING-GUIDE.md
```

---

## 17. 最終驗收情境

給定 inventory：

```yaml
all:
  hosts:
    freeipa-server:
      ansible_host: 192.168.122.50
    nexus:
      ansible_host: 192.168.122.81
```

以及 manifest：

```yaml
schema_version: 1

freeipa:
  domain: ipa.pilot.internal
  realm: IPA.PILOT.INTERNAL
  server: ipa1.ipa.pilot.internal

dns:
  defaults:
    ttl: 300
    records_mode: merge
  safety:
    allow_shadow_existing_zone: false
    allow_authoritative_prune: false
    allow_zone_delete: false
  zones:
    - name: example.com.
      state: present
      acknowledge_split_horizon: true
      records:
        - {name: grafana, type: A, state: present, target: {inventory_host: nexus}}
        - {name: wazuh, type: A, state: present, target: {inventory_host: nexus}}
        - {name: s3, type: A, state: present, target: {inventory_host: nexus}}
```

執行 reconcile 後：

```bash
dig @192.168.122.50 +short grafana.example.com A
dig @192.168.122.50 +short wazuh.example.com A
dig @192.168.122.50 +short s3.example.com A
```

三者都必須回覆：

```text
192.168.122.81
```

將 `nexus.ansible_host` 改為：

```text
192.168.122.99
```

重新執行 reconcile 後，三者都必須改為：

```text
192.168.122.99
```

再次執行 reconcile，最終 recap 必須為：

```text
changed=0
failed=0
```

這是第一版完成的核心 Definition of Done。

