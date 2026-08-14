# Pilot Internal Endpoint / FreeIPA PKI 功能實作規格

## 0. 文件狀態

**Target repository:** `kjelly/pilot`
**Implementation baseline:** `9488c456e8141d4131c4edcf64c446d07b0abadc`
**Pilot baseline version:** `0.2.0`
**Spec revision:** v1.1 — reverse-proxy HTTPS upstream (§12.4) integrated；見 §67 Revision Log
**Feature class:** Infrastructure / PKI / DNS / Internal Endpoint
**Primary lifecycle:** Day-2 declarative reconcile
**Target implementation language:** Go + Ansible
**Required evidence:** real `vm-target topology` run + idempotency

Coding agent 在開始修改前 **MUST** 再確認目前 HEAD；若 HEAD 已超過本文件基準，先比較與本功能相關的檔案。不得直接假定本文列出的 line number 或 contract count 仍未變。

目前 codebase 已有：

* FreeIPA server / client；
* FreeIPA native DNS；
* `freeipa-dns` declarative reconciler；
* `freeipa-dns-client`；
* ComponentContract v1；
* Verification Spec v2；
* `pilot edit` semantic action registry；
* MCP inspect / plan / apply；
* DNS manifest Go validator、normalizer、writer、TUI editor。

`freeipa-dns` 本身明確把 TLS certificate issuance 與 Nginx/Caddy/Traefik reverse proxy 排除在既有 component 範圍之外，因此本功能不得直接膨脹 `freeipa-dns` 的責任。

---

# 1. Problem Statement

Pilot 要提供公司的 internal endpoint control plane。

使用者應能宣告任意內部 FQDN，例如：

```text
yyy.linker.internal
aaa.xxx.linker.internal
api.dev.xxx.linker.internal
postgres.db.linker.internal
```

`linker.internal` **只是例子，不得 hard-code**。

每個 FQDN 可以：

1. DNS 直接指到目標主機；
2. DNS 指到 reverse proxy，再 proxy 到指定 backend IP + port；
3. 不啟用 TLS；
4. 使用 FreeIPA CA 簽發的 HTTPS certificate。

其中：

```text
DNS 不攜帶 TCP port。
```

例如：

```text
direct.example.internal
    DNS → app01 IP
    使用者 → https://direct.example.internal:8443

grafana.example.internal
    DNS → proxy01 IP
    proxy01:443 → grafana01:3000
    使用者 → https://grafana.example.internal
```

---

# 2. Primary User Experience

使用者最終只需維護一份：

```text
internal-endpoints.yaml
```

並執行：

```text
pilot reconcile
```

選擇：

```text
internal-endpoint
```

Pilot MUST 收斂：

```text
FQDN
  │
  ├─ DNS
  │   ├─ direct        → target host
  │   └─ reverse_proxy → proxy host
  │
  ├─ TLS
  │   ├─ disabled
  │   └─ FreeIPA CA
  │
  └─ routing
      ├─ direct
      └─ nginx reverse proxy
```

使用者不得需要手動：

* 建立 FreeIPA HTTP service principal；
* 設定 service `managedBy`；
* 執行 `ipa-getcert`；
* 追蹤 certificate renewal；
* 寫 Nginx vhost；
* 新增 endpoint A/AAAA RRset；
* 把 FreeIPA CA 手工 copy 到每台 managed host。

---

# 3. Locked Architecture Decisions

以下為 v1 **鎖定決策**。

## 3.1 Primary resource 名稱

核心 resource MUST 稱為：

```text
internal-endpoint
```

不得設計成：

```text
internal-ingress
internal-website
nginx-service
```

原因是 reverse proxy 不是必經路徑。

---

## 3.2 FQDN 是 resource primary key

Manifest 使用完整 FQDN：

```yaml
fqdn: aaa.xxx.linker.internal
```

不得設計：

```yaml
domain: linker.internal
name: aaa.xxx
```

作為唯一 data model。

程式內可自行計算 relative owner。

---

## 3.3 不 hard-code internal domain

Validator MUST 接受任意合法 DNS FQDN：

```text
example.internal
svc.company.internal
aaa.xxx.linker.internal
service.lab.example
```

但 wildcard：

```text
*.example.internal
```

v1 不支援。

---

## 3.4 Nested FQDN 必須支援

現行 DNS validator 已允許含多個 label 的 relative owner；例如 zone：

```text
linker.internal.
```

搭配：

```text
aaa.xxx
```

本身就是合法 record name。

因此：

```text
aaa.xxx.linker.internal
```

MUST 是 first-class supported case。

不得為每層 label 建立 DNS zone。

---

## 3.5 DNS zone 與 endpoint 是不同 resource

`internal-endpoint` **不建立或刪除 DNS zone**。

DNS zone lifecycle 繼續由：

```text
freeipa-dns
```

管理。

所以使用 endpoint 前：

```text
linker.internal.
```

或其他 parent zone 必須先由 `freeipa-dns` 建立。

---

## 3.6 Endpoint DNS v1 只管理 A / AAAA

Endpoint reconciler v1 只會產生：

```text
A
AAAA
```

不產生：

```text
CNAME
SRV
MX
TXT
CAA
```

CNAME 等 advanced DNS record 繼續由 `freeipa-dns` 管理。

---

## 3.7 Reverse proxy provider v1 固定 Nginx

資料模型要保留 provider abstraction，但 v1：

```yaml
provider: nginx
```

是唯一合法值。

未來可以加入：

```text
caddy
traefik
haproxy
```

但不得為未實作 provider 提供假選項。

---

# 4. Components

此功能新增三個 ComponentContract。

```text
freeipa-ca-trust
reverse-proxy
internal-endpoint
```

---

# 5. Component: `freeipa-ca-trust`

## 5.1 Responsibility

唯一責任：

> 將目前 FreeIPA integrated CA trust chain 安裝至 managed Linux host 的 OS system trust store。

這個 component 不：

* enroll FreeIPA client；
* 設定 SSSD；
* 設定 DNS；
* 發 service certificate；
* 管理 endpoint。

---

## 5.2 Scope

Default target：

```text
all
```

「managed hosts」定義為目前 Ansible inventory 的：

```text
all.hosts
```

而不是：

```text
freeipa-client
```

因為 TLS trust 與 FreeIPA AAA enrollment 是不同責任。

---

## 5.3 CA source

CA material MUST 從 designated primary：

```text
freeipa-server
```

透過現有 Ansible/SSH management channel 讀取。

Source：

```text
/etc/ipa/ca.crt
```

Bootstrap 階段不得使用：

```text
curl http://ipa.../ipa/config/ca.crt
```

作為 trust source。

原因是 SSH/Ansible 已是 Pilot 既有 trusted management path。

---

## 5.4 FreeIPA 必須真的是 root CA

本 feature 的 root-CA mode MUST 做 live preflight。

必須確認：

1. integrated IdM CA 存在；
2. IdM CA signing certificate 本身是 CA；
3. IdM CA signing certificate 是 self-signed；
4. issuer == subject；
5. certificate chain 與 `/etc/ipa/ca.crt` 一致。

Red Hat 的 IdM 架構定義指出，當 integrated CA 本身是 root CA 時，會使用 self-signed CA certificate。

目前 Pilot 的 `freeipa-server-apply.yml` 使用 native `ipa-server-install`，且 installer arguments 沒有走 external-CA flow，因此以該 playbook 新建的環境符合 integrated-root 的預期；但 coding agent **仍必須檢查 live state**，因為既有 deployment 可能曾被人工改成 external root。

若 live environment 是：

```text
External Root
   ↓
FreeIPA Intermediate CA
```

則此 feature MUST fail closed：

```text
FreeIPA CA is not the configured root trust anchor
```

不得偷偷接受成另一種 PKI topology。

---

## 5.5 OS trust installation

Debian / Ubuntu：

```text
/usr/local/share/ca-certificates/pilot-freeipa-ca.crt
update-ca-certificates
```

RedHat family：

```text
/etc/pki/ca-trust/source/anchors/pilot-freeipa-ca.crt
update-ca-trust
```

實作 MUST：

* copy full required CA chain；
* deterministic filename；
* compare content/fingerprint；
* CA 未改變時 changed=0；
* CA rotation 時 replace；
* 更新 system trust store；
* verify trust。

已 enroll 的 FreeIPA client 可另外執行：

```text
ipa-certupdate
```

但 **不得依賴它作為唯一實作**，因為 non-enrolled managed hosts 一樣必須信任 CA。Red Hat 文件確認 `ipa-certupdate` 會更新 system-wide CA database。

---

## 5.6 New files

```text
contracts/freeipa-ca-trust.yaml
docs/verification/freeipa-ca-trust.md
playbooks/apply/freeipa-ca-trust-apply.yml
playbooks/apply/tasks/freeipa-ca-trust.yml
internal/spec/freeipa_ca_trust_regression_test.go
```

其中：

```text
playbooks/apply/tasks/freeipa-ca-trust.yml
```

MUST 能同時被：

```text
freeipa-ca-trust-apply.yml
internal-endpoint-apply.yml
```

重用。

---

# 6. Component: `reverse-proxy`

## 6.1 Responsibility

只負責：

```text
install nginx
enable nginx
establish Pilot-owned nginx configuration boundary
```

不得在 base component 內管理 endpoint DNS 或 certificate。

---

## 6.2 Inventory role

新增合法 host role：

```text
reverse-proxy
```

需要更新：

```text
internal/inventory/contracts.go
internal/inventory/catalog.go
inventory examples / tests
```

目前 inventory role catalog 是固定 catalog，而不是可任意增加 YAML group，因此這一步不能省略。

**既有 gap（本 feature 順手修）**：目前 `freeipa-dns-client` 角色完全沒有被 wire 進 `internal/inventory/contracts.go` / `internal/inventory/catalog.go`（`inventory.Roles()` 直接讀 `roleContracts`，找不到就視為 unknown role），卻出現在 `inventory.example.yml` 裡——那段示範其實沒有走過 catalog 驗證，用「hosts.yml → `pilot inventory generate`」這條路徑目前**產生不出** `freeipa-dns-client` group。新增 `reverse-proxy` 時，coding agent MUST 同時把 `freeipa-dns-client` 也補進 `roleContracts` / `catalog.go`（`topLevelOrder`/aggregate），並修正 `inventory.example.yml` 讓它與 catalog 一致。這是 §27.1 要求「把 `freeipa-dns-client` 加進三個 built-in role preset」的前提——`validateRolePresets()` 會拿 `inventory.Roles()` 驗證 preset 裡的角色名稱，角色沒先進 catalog，preset 就存不進去。

**部署建議（Phase 10 全 topology 實測發現，2026-08-14）**：`reverse-proxy` role（以及任何擔任 internal-endpoint route owner 的 host——direct 的 `target.inventory_host` 或 reverse_proxy 的 `proxy.inventory_host`）SHOULD 額外套用 `freeipa-dns-client-apply.yml`。原因：`freeipa-client`（AAA/Kerberos enrollment）與 `freeipa-dns-client`（OS resolver 指向 FreeIPA DNS）是兩個完全獨立的元件——一台已完成 `ipa-client-install` 的 host，其 `/etc/resolv.conf`/`systemd-resolved` 預設仍然指向原本的 DHCP/libvirt resolver，不會自動變成 FreeIPA DNS，因此該 host 自己也無法用一般 DNS 查到其他 internal-endpoint FQDN（例如反向代理 host 想直接 `curl` 同一批 endpoint 的其他 FQDN 來自我檢查時會失敗）。這不是 bug，是兩個角色故意分離的設計；只是實際佈署 reverse-proxy/direct target 時，若沒有同時附加 `freeipa-dns-client`，容易誤以為 DNS 沒接上。

---

## 6.3 Nginx ownership

Endpoint-owned config 一律放：

```text
/etc/nginx/conf.d/pilot-internal-endpoint-<stable-id>.conf
```

`stable-id` MUST 由 canonical FQDN deterministic 產生。

不得覆寫 unmanaged：

```text
/etc/nginx/nginx.conf
/etc/nginx/conf.d/<foreign file>
```

除非 base role 為了建立 include contract 所必要。

---

## 6.4 Default distribution site

安裝後 MUST 關閉/remove distribution default site，避免：

```text
default_server
```

攔截 Pilot endpoint。

---

## 6.5 New files

```text
contracts/reverse-proxy.yaml
docs/verification/reverse-proxy.md
playbooks/apply/reverse-proxy-apply.yml
internal/spec/reverse_proxy_regression_test.go
```

另可新增：

```text
playbooks/apply/templates/internal-endpoint-nginx.conf.j2
```

但 endpoint-specific template 的 owner 邏輯屬於 `internal-endpoint`。

---

# 7. Component: `internal-endpoint`

此 component 是整個 feature 的主要 day-2 reconciler。

Contract：

```text
site.include = false
site.optIn = true
```

並加入：

```text
pilot reconcile
```

catalog：

```go
Reconcile: true
```

目前 reconcile 只接受明確標為 reconciler 的 catalog entry；不能只新增 playbook 而漏掉 catalog wiring。

---

# 8. Manifest Location

Default：

```text
<workspace>/internal-endpoints.yaml
```

Host/group variable：

```yaml
internal_endpoint_manifest_file: /absolute/path/to/internal-endpoints.yaml
```

Manifest：

* MUST NOT contain password；
* MAY be version controlled；
* MUST use strict schema；
* unknown keys fail closed。

ComponentContract 目前只支援 primitive group vars，因此整個 structured endpoint graph 必須留在 manifest，不能試圖塞進 contract `groupVars:`。

---

# 9. Manifest Schema v1

完整 schema example：

```yaml
---
schema_version: 1

defaults:
  dns:
    ttl: 300

safety:
  allow_endpoint_delete: false

endpoints:

  # ─────────────────────────────────────────────
  # 1. DNS direct + FreeIPA TLS
  # ─────────────────────────────────────────────
  - fqdn: yyy.linker.internal
    state: present

    dns:
      zone: linker.internal.
      ttl: 300

    route:
      mode: direct

      target:
        inventory_host: app01

    tls:
      mode: freeipa
      port: 443

      sink:
        cert_file: /etc/myapp/tls/server.crt
        key_file: /etc/myapp/tls/server.key

        key_owner: root
        key_group: myapp
        key_mode: "0640"

        reload:
          mode: systemd
          unit: myapp.service


  # ─────────────────────────────────────────────
  # 2. nested FQDN + direct + non-standard HTTPS port
  # ─────────────────────────────────────────────
  - fqdn: aaa.xxx.linker.internal
    state: present

    dns:
      zone: linker.internal.

    route:
      mode: direct

      target:
        inventory_host: app02

    tls:
      mode: freeipa
      port: 8443

      sink:
        cert_file: /etc/example/tls/server.crt
        key_file: /etc/example/tls/server.key
        key_group: example
        key_mode: "0640"

        reload:
          mode: systemd
          unit: example.service


  # ─────────────────────────────────────────────
  # 3. Nginx reverse proxy
  # ─────────────────────────────────────────────
  - fqdn: grafana.linker.internal
    state: present

    dns:
      zone: linker.internal.

    route:
      mode: reverse_proxy

      proxy:
        provider: nginx
        inventory_host: web01

      upstream:
        scheme: http
        inventory_host: grafana01
        port: 3000

    tls:
      mode: freeipa


  # ─────────────────────────────────────────────
  # 4. pure DNS
  # ─────────────────────────────────────────────
  - fqdn: postgres.db.linker.internal
    state: present

    dns:
      zone: linker.internal.

    route:
      mode: direct

      target:
        inventory_host: pg01

    tls:
      mode: disabled


  # ─────────────────────────────────────────────
  # 5. explicit literal IP
  # ─────────────────────────────────────────────
  - fqdn: appliance.linker.internal
    state: present

    dns:
      zone: linker.internal.

    route:
      mode: direct

      target:
        address: 10.20.30.40

    tls:
      mode: disabled
```

---

# 10. Schema Validation Rules

## 10.1 Top level

Only:

```text
schema_version
defaults
safety
endpoints
```

Unknown key → error.

---

## 10.2 `fqdn`

Rules:

* required；
* canonical lowercase；
* input trailing `.` MAY be accepted but normalized away；
* no wildcard；
* RFC-valid label lengths；
* no duplicate canonical FQDN；
* no IP literal；
* no URL；
* no port。

Invalid：

```text
https://foo.example.internal
foo.example.internal:8443
*.example.internal
```

Valid：

```text
foo.example.internal
aaa.xxx.example.internal
```

---

## 10.3 `dns.zone`

Required.

Canonical：

```text
lowercase + trailing dot
```

Endpoint FQDN MUST be:

```text
zone apex
```

or a strict descendant.

Example：

```text
fqdn: aaa.xxx.linker.internal
zone: linker.internal.
```

derived owner：

```text
aaa.xxx
```

Apex：

```text
fqdn: linker.internal
zone: linker.internal.
```

derived owner：

```text
@
```

---

# 11. DNS Ownership Rules

這部分 MUST fail closed，否則會產生兩個 reconciler 互相打架。

## 11.1 Parent zone 必須存在

`dns.zone` MUST 出現在：

```text
freeipa-dns.yaml
```

且：

```yaml
state: present
```

---

## 11.2 Parent zone MUST use merge mode

Endpoint-managed FQDN 所在 zone 的 effective：

```yaml
records_mode: merge
```

MUST 成立。

若 zone 為：

```yaml
records_mode: authoritative
```

endpoint validation MUST fail。

原因是現有 `freeipa-dns` authoritative mode 可能把 endpoint reconciler 建出的 RRset 當 stale record prune 掉。現行 DNS component 本來就區分 `merge` 與 `authoritative`。

---

## 11.3 Exact RRset collision

若 `freeipa-dns.yaml` 已明確管理相同：

```text
(zone, owner, record type)
```

則 `internal-endpoint` MUST fail：

```text
DNS ownership conflict
```

不得「後寫者覆蓋前寫者」。

---

## 11.4 DNS record destination

### direct

```text
route.target.inventory_host
    ↓
hostvars[target].ansible_host
    ↓
A / AAAA
```

或：

```text
route.target.address
    ↓
A / AAAA
```

### reverse_proxy

DNS MUST 指向：

```text
route.proxy.inventory_host
```

**不是 upstream。**

例如：

```text
grafana.linker.internal
    A → web01 IP
```

而不是：

```text
grafana01 IP
```

---

## 11.5 Port 不進 DNS

下面語意永遠不存在：

```text
grafana.linker.internal → 10.0.0.50:3000
```

DNS 只存：

```text
grafana.linker.internal → 10.0.0.10
```

port 只存在 route configuration。

---

# 12. Route Schema

## 12.1 `direct`

Exactly one：

```yaml
target:
  inventory_host: app01
```

或：

```yaml
target:
  address: 10.20.30.40
```

禁止兩者同時。

`address` v1 MUST 是 IP literal。

---

## 12.2 Direct + TLS

若：

```yaml
tls:
  mode: freeipa
```

則：

```yaml
route.target.inventory_host
```

MUST 存在。

下面組合非法：

```yaml
target:
  address: 10.20.30.40

tls:
  mode: freeipa
```

原因是 Pilot 無法推導 certificate private-key owner。

---

## 12.3 `reverse_proxy`

Required：

```yaml
proxy:
  provider: nginx
  inventory_host: web01

upstream:
  scheme: http
  inventory_host: app01
  port: 3000
```

或：

```yaml
upstream:
  scheme: http
  address: 10.20.30.40
  port: 3000
```

Backend port：

```text
1..65535
```

`upstream.scheme` MUST 明確指定，合法值：

```text
http
https
```

不得省略；省略 MUST fail：

```text
upstream.scheme is required (http|https)
```

---

## 12.4 Reverse Proxy Upstream Protocol：HTTP / HTTPS

v1 upstream 同時支援：

```text
http
https
```

範例：

```yaml
route:
  mode: reverse_proxy

  proxy:
    provider: nginx
    inventory_host: web01

  upstream:
    scheme: https
    inventory_host: backend01
    port: 8443

    tls:
      verify: false
```

結果：

```text
Client
  │
  │ HTTPS + FreeIPA trusted certificate
  ▼
web01 / nginx
  │
  │ HTTPS
  │ upstream certificate NOT verified
  ▼
backend01:8443
```

### 12.4.1 `tls.verify` 是必填（當 `scheme: https`）

當：

```yaml
upstream:
  scheme: https
```

必須有：

```yaml
tls:
  verify: true | false
```

若 `scheme: https` 但沒有設定 `tls.verify`，validator MUST fail：

```text
HTTPS upstream requires explicit tls.verify=true or tls.verify=false
```

原因是不能因漏填設定而靜默降低 upstream authentication。

### 12.4.2 Secure HTTPS upstream（`verify: true`）

```yaml
upstream:
  scheme: https
  inventory_host: backend01
  port: 8443

  tls:
    verify: true
```

Nginx MUST：

```nginx
proxy_pass https://<backend-ip>:8443;

proxy_ssl_verify on;
proxy_ssl_server_name on;
```

並使用 proxy host 的 OS CA trust bundle 驗證 upstream certificate。由於 `freeipa-ca-trust` 已將 FreeIPA CA 安裝到所有 managed host，因此 upstream 若使用 FreeIPA CA certificate，也應能使用此模式。

### 12.4.3 Insecure HTTPS upstream（`verify: false`）

以下 MUST 被正式支援為合法 v1 configuration，不得被 validator 拒絕：

```yaml
upstream:
  scheme: https
  inventory_host: backend01
  port: 8443

  tls:
    verify: false
```

代表：

> Nginx 與 upstream 之間仍使用 TLS 加密，但不驗證 upstream certificate 的 CA chain / identity。

生成設定：

```nginx
proxy_pass https://<backend-ip>:8443;

proxy_ssl_verify off;
proxy_ssl_server_name on;
```

**Security invariant**：`scheme=https` + `verify=false` 的語意是 *encrypted but unauthenticated upstream TLS*。它不等於 `http`，也不等於「trusted HTTPS」。normalized preview、TUI（§37）、MCP inspect（§40）都 MUST 明確顯示：

```text
upstream: https://10.20.30.40:8443
TLS verification: DISABLED
```

不得只顯示「HTTPS」，以免 operator 誤以為 upstream identity 有被驗證。

### 12.4.4 HTTP upstream 不得帶 `tls`

```yaml
upstream:
  scheme: http
  inventory_host: app01
  port: 3000
```

合法。以下非法：

```yaml
upstream:
  scheme: http
  inventory_host: app01
  port: 3000

  tls:
    verify: false
```

Validator MUST report：

```text
upstream.tls is only valid when upstream.scheme=https
```

### 12.4.5 SNI（`tls.server_name`）

HTTPS upstream MUST 支援 SNI：

```yaml
upstream:
  scheme: https
  inventory_host: backend01
  port: 8443

  tls:
    verify: false
    server_name: backend.service.internal
```

生成：

```nginx
proxy_ssl_server_name on;
proxy_ssl_name backend.service.internal;
```

用途：

1. TLS SNI；
2. `verify: true` 時的 certificate hostname validation identity。

不得自動把 `inventory_host` 當作 certificate DNS name，因為 inventory alias 可能只是 `backend01`，而實際 certificate 是 `backend.service.internal`。

### 12.4.6 Default SNI Derivation

如果 `tls.server_name` 未設定：

* upstream 使用 `address`：不得猜測 SNI。若 `verify: true`，MUST fail：`verified HTTPS upstream using an IP address requires tls.server_name`。
* upstream 使用 `inventory_host`：v1 MAY 使用該 inventory host 的 canonical hostname/FQDN，**只有當能從 inventory 明確解析出 canonical FQDN 時**。不能明確解析時：`verify: true` → fail；`verify: false` → 可繼續，SNI 可以省略或使用顯式 `server_name`。

最推薦 manifest 仍是顯式設定：

```yaml
tls:
  verify: false
  server_name: backend.internal
```

### 12.4.7 Complete Examples

HTTP：

```yaml
upstream:
  scheme: http
  inventory_host: grafana01
  port: 3000
```

HTTPS + valid certificate：

```yaml
upstream:
  scheme: https
  inventory_host: api01
  port: 8443

  tls:
    verify: true
    server_name: api.backend.internal
```

HTTPS + self-signed / invalid / untrusted certificate（v1 必須支援的正式 use case）：

```yaml
upstream:
  scheme: https
  inventory_host: legacy01
  port: 8443

  tls:
    verify: false
    server_name: legacy01.internal
```

---

# 13. Reverse Proxy Generated State

對：

```yaml
fqdn: grafana.linker.internal

route:
  mode: reverse_proxy
  proxy:
    inventory_host: web01
  upstream:
    scheme: http
    inventory_host: grafana01
    port: 3000

tls:
  mode: freeipa
```

logical result：

```nginx
server {
    listen 443 ssl;
    server_name grafana.linker.internal;

    ssl_certificate     <pilot-managed cert>;
    ssl_certificate_key <pilot-managed key>;

    location / {
        proxy_pass http://<grafana01-ip>:3000;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

如 TLS enabled，HTTP 80 SHOULD redirect 到 HTTPS。

套用前 MUST：

```text
nginx -t
```

成功後才 reload。

錯誤 config 不得取代 running config。

上面示範是 `upstream.scheme: http` 的情形。`https` upstream 的 nginx 生成規則與 readiness check 見 §13.1、§13.2。

---

## 13.1 HTTP / HTTPS Upstream Nginx Generation

### HTTP

```nginx
proxy_pass http://10.20.30.40:3000;
```

不得產生 `proxy_ssl_*`。

### Verified HTTPS（`tls.verify: true`）

```nginx
proxy_pass https://10.20.30.40:8443;

proxy_ssl_server_name on;
proxy_ssl_name api.backend.internal;

proxy_ssl_verify on;
proxy_ssl_verify_depth 5;

proxy_ssl_trusted_certificate <OS-system-CA-bundle>;
```

CA bundle path 必須依 proxy host OS 決定，不可硬編碼只支援 Ubuntu。

### Unverified HTTPS（`tls.verify: false`）

```nginx
proxy_pass https://10.20.30.40:8443;

proxy_ssl_server_name on;
proxy_ssl_name legacy.internal;

proxy_ssl_verify off;
```

若沒有 `server_name`，`proxy_ssl_verify off;` 即可；不得捏造 hostname。

---

## 13.2 Upstream Readiness Check（依 scheme/verify 分流）

「backend reachable」的 readiness check 必須依 upstream mode 驗證：

### HTTP

```text
TCP connect
HTTP transport
```

### HTTPS + `verify: true`

```text
TCP connect
TLS handshake
CA verification
hostname verification
HTTP transport
```

### HTTPS + `verify: false`

```text
TCP connect
TLS handshake
HTTP transport
```

**不得因 certificate self-signed、expired、hostname mismatch 或 untrusted CA 而 fail readiness**——`verify: false` 已明確宣告 operator 接受這些風險。

但下面仍要 fail readiness：

```text
connection refused
TLS protocol handshake failure
timeout
backend completely unreachable
```

---

# 14. TLS Data Model

合法：

```text
disabled
freeipa
```

此 `tls.mode` 只描述 **frontend**（endpoint 對外的 certificate）。`route.mode: reverse_proxy` 的 **upstream** TLS（nginx → backend）是獨立的 schema 分支，見 §12.4；兩者可以獨立設定，例如 frontend `tls.mode: freeipa` 搭配 upstream `scheme: https` + `tls.verify: false`。

---

# 15. Certificate Owner Derivation

使用者不得自己指定：

```yaml
certificate_owner:
```

Pilot MUST derive。

### direct

```text
certificate owner = route.target.inventory_host
```

### reverse_proxy

```text
certificate owner = route.proxy.inventory_host
```

---

# 16. Certificate Owner Preconditions

若：

```text
tls.mode = freeipa
```

certificate owner MUST：

1. 是 inventory host；
2. 已真正完成 FreeIPA enrollment；
3. `/etc/ipa/default.conf` 存在；
4. `/etc/krb5.keytab` 有 host principal；
5. certmonger/IPA certificate tooling 可用。

不得只因 `hosts.yml` 有：

```text
freeipa-client
```

role 就假定 enrollment 成功。

必須做 live preflight。

Red Hat 的 certmonger 流程本身也要求 certificate request 所在 web host 是已 enroll 的 IdM client；certmonger 會追蹤並自動續期 certificate。

---

# 17. FreeIPA Service Identity

每個 FreeIPA TLS endpoint logical principal：

```text
HTTP/<fqdn>
```

例如：

```text
HTTP/grafana.linker.internal
```

Certificate SAN MUST 包含：

```text
DNS:grafana.linker.internal
```

不得只依靠 CN。

Red Hat 的 `ipa-getcert` service certificate workflow 原生支援：

* `HTTP/<fqdn>` principal；
* DNS SAN；
* cert/key file；
* post-renew service restart/reload；
* certmonger renewal tracking。

---

# 18. FreeIPA managedBy Delegation

Endpoint FQDN 可能不是 certificate owner 的 canonical hostname。

例如：

```text
endpoint:
grafana.linker.internal

physical owner:
proxy01.ipa.example.internal
```

Pilot MUST 建立正確的 delegated management relationship。

Required logical state：

```text
HTTP/grafana.linker.internal
    managed by
proxy01.ipa.example.internal
```

Red Hat 明確說明 host/service 都有 `managedby`，且 host delegation **不會自動包含 service delegation**；service 要使用：

```text
ipa service-add-host
```

獨立授權。

因此 implementation MUST NOT 只做：

```text
host-add-managedby
```

然後假定 HTTP service 也被授權。

---

# 19. Virtual Host Object

若目前 FreeIPA release 對非實體 host FQDN 建 service principal 時要求 host object，implementation MAY 建立：

```text
virtual host object = endpoint FQDN
```

並使用：

```text
host-add-managedby
service-add-host
```

把實體 certificate owner 設為 manager。

Red Hat 對 DNS alias/不同 DNS domain 的 certificate case 也採用 virtual host object + managedBy 的做法。

Coding agent MUST 在 disposable live FreeIPA 測試目前版本的最小必要 object set。

不得只靠推測 CLI 行為。

---

# 20. Private-Key Boundary

**硬性 security invariant：**

```text
Private key MUST be generated and remain on certificate owner host.
```

不得：

1. 在 FreeIPA server 產生 private key；
2. 在 controller 產生 private key；
3. 將 private key經 Ansible distribute。

Red Hat 也建議 service private key 在 service node 產生，避免複製到 IdM server。

---

# 21. Certmonger

TLS certificate MUST 由 certmonger tracking。

Acceptance：

```text
status: MONITORING
stuck: no
CA: IPA
SAN contains exact endpoint FQDN
```

Renewal 後 MUST reload consumer。

---

# 22. Direct TLS Certificate Sink

因為 Pilot 不知道任意 application 如何讀 certificate，所以 direct TLS MUST 使用明確 sink contract。

Required：

```yaml
sink:
  cert_file: /absolute/path/server.crt
  key_file: /absolute/path/server.key

  reload:
    mode: systemd
    unit: myapp.service
```

Rules：

* absolute path only；
* cert/key path 不得相同；
* parent directory MUST already exist；
* parent directory 不得 world-writable；
* existing path 若為 symlink → fail；
* target systemd unit MUST exist；
* unit name strict validation；
* 不接受 raw shell command。

Key permissions：

```yaml
key_owner: root
key_group: myapp
key_mode: "0640"
```

optional。

Defaults：

```text
owner = root
group = root
mode  = 0600
```

Certificate default：

```text
0644
```

---

# 23. Direct TLS Scope v1

v1 只完整支援：

```text
systemd-managed TLS consumer
```

不支援 arbitrary：

```text
docker exec ...
kubectl ...
shell reload command
HTTP webhook
```

若 application 無法以 systemd + certificate files 整合：

```text
route.mode = reverse_proxy
```

是 v1 推薦路徑。

---

# 24. TLS Verification

所有 managed hosts 對 `tls.mode=freeipa` endpoint MUST 能在：

**不使用 `-k` / `--insecure`** 的情況下完成 TLS handshake。

HTTP response 可以是：

```text
200
301
302
401
403
404
```

只要 TLS hostname / chain verification 成功。

因此驗證不得使用：

```text
curl --fail
```

作為唯一條件，因為 401/404 不等於 TLS failure。

必須分別判斷：

```text
DNS resolution
TCP connect
TLS chain
hostname/SAN
HTTP transport
```

---

# 25. Meaning of "All Managed Hosts Trust CA"

此 requirement 精確定義為：

> 所有 Pilot inventory Linux hosts 的 **OS system trust store** 信任 FreeIPA CA。

保證：

```text
curl
OpenSSL
system-library based TLS clients
```

不保證：

```text
Java private cacerts
application-bundled CA store
container image private CA store
Firefox private trust store
embedded appliance trust store
```

這些屬於 future trust-provider extension。

---

# 26. DNS Resolver Coverage

建立 DNS record 不代表每台 host 一定查得到。

目前 `freeipa-dns-client-apply.yml` 已：

* 與 AAA enrollment 獨立；
* 支援 Debian/Ubuntu；
* 支援 RedHat；
* 能自動找 FreeIPA DNS provider；
* 能安全套到 FreeIPA server/replica 自己；
* 明確支援 `target_group=all`。

因此 coding agent MUST：

1. 把目前 resolver mutation implementation 抽成 shared task/include；
2. 保持原本 `freeipa-dns-client` standalone behavior backward compatible；
3. `internal-endpoint` reconcile 在 baseline phase 對 `all` hosts 套用相同 resolver state。

不得 copy/paste 形成第二套不同 DNS-client logic。

---

# 27. `freeipa-dns-client` Backward Compatibility

目前 contract 是 opt-in：

```yaml
site:
  include: false
  optIn: true
```

本 feature **不得直接把它改成全站 unconditional site role**，因為這會改變未使用 internal-endpoint 的既有 deployment。

Global DNS resolver management 只在：

```text
internal-endpoint reconcile
```

內成為 mandatory baseline。

---

## 27.1 Default Role Preset Coverage（鎖定決策）

除了「§27 contract 層保持 opt-in」之外，`freeipa-dns-client` MUST 被加進 `cmd/pilot/cmd/edit_tui_role_presets.go` 的 `defaultRolePresets()` 內建三組 minimal-PoC 角色範本：

```text
FreeIPA 身份伺服器(minimal PoC)
Nexus 中央服務節點(minimal PoC)
被監控的 Linux 主機(minimal PoC)
```

三組 `Roles` 清單 MUST 各自新增 `freeipa-dns-client`。目的：任何用這三個內建範本建出來的 minimal-PoC host，預設就有 FreeIPA DNS resolver baseline，不需要先啟用 `internal-endpoint` 才能查到 FreeIPA 管理的 DNS record。

這不牴觸 §27 的 opt-in 決策：

* Component contract 的 `site.include:false, optIn:true` 仍然成立——`freeipa-dns-client-apply.yml` 是不是被套用，仍取決於有沒有 host 被標了這個角色；
* 這裡改的是「哪些角色**預先幫你勾好**」這個 authoring-time 便利性，不是 site.yml 的 auto-include 邏輯；
* 已存在、已客製化 `role-presets.yml` 的環境不受影響——`loadRolePresets` 讀到既有檔案時完全取代內建清單（見 §6.2 落差說明），只有**尚未客製化**、還在用內建三組的環境會拿到新角色。

前提（見 §6.2 落差說明）：`freeipa-dns-client` MUST 先被補進 `internal/inventory/contracts.go`/`catalog.go` 成為合法角色，否則 `validateRolePresets()` 會以 `未知角色 "freeipa-dns-client"` 拒絕這三組 preset。

需要更新：

```text
cmd/pilot/cmd/edit_tui_role_presets.go   （defaultRolePresets 三組 Roles）
cmd/pilot/cmd/edit_tui_role_presets_test.go（或等價 test）
docs/runbooks/minimal-poc-architecture.md （若有列出三組角色清單）
```

---

# 28. Internal Endpoint Apply Sequence

**順序是 acceptance requirement。**

對 `state: present`：

```text
Phase 0
  manifest load
  strict validation
  ownership ledger load

Phase 1
  inventory / dependency / live preflight

Phase 2
  all hosts:
    FreeIPA CA trust baseline

Phase 3
  all hosts:
    FreeIPA DNS resolver baseline

Phase 4
  FreeIPA control plane:
    endpoint host/service identity
    managedBy delegation

Phase 5
  certificate owner:
    certmonger request / converge
    SAN validation
    renewal tracking
    consumer reload configuration

Phase 6
  reverse_proxy only:
    render nginx candidate
    nginx -t
    reload
    local proxy/backend check

Phase 7
  DNS:
    create/update A/AAAA
    DNS IS CHANGED LAST

Phase 8
  all managed hosts:
    DNS verification
    TLS verification where enabled

Phase 9
  atomically update ownership ledger
```

**DNS MUST be changed after the destination is ready.**

避免：

```text
DNS points to new destination
→ certificate / nginx still not ready
→ outage
```

---

# 29. Ownership Ledger

Declarative manifest 是 source of truth，但 Pilot 仍需要知道：

```text
哪些外部 resource 是 Pilot 建的
```

避免 delete foreign resource。

新增：

```text
/var/lib/pilot/internal-endpoint/state.json
```

位於 designated FreeIPA control host。

內容不得有 secret/private key。

最少：

```json
{
  "schema_version": 1,
  "endpoints": {
    "grafana.linker.internal": {
      "route_mode": "reverse_proxy",
      "route_owner": "web01",
      "dns_zone": "linker.internal.",
      "dns_owner": "grafana",
      "dns_type": "A",
      "service_principal": "HTTP/grafana.linker.internal",
      "service_created_by_pilot": true,
      "virtual_host_created_by_pilot": true,
      "certificate_owner": "web01",
      "certificate_file": "...",
      "key_file": "...",
      "nginx_file": "...",
      "certificate_serial": "..."
    }
  }
}
```

Ledger：

* MUST atomic-write temp + rename；
* MUST root-owned；
* SHOULD mode `0600`；
* failure before full reconcile MUST NOT overwrite last good ledger。

---

# 30. Route Ownership Changes

v1：

```text
direct → reverse_proxy
reverse_proxy → direct
target host A → target host B
proxy host A → proxy host B
```

視為 **route owner migration**。

v1 MUST fail closed：

```text
route owner change is not supported in-place
```

除非 future schema version 明確實作 migration protocol。

IP 因 DHCP / inventory `ansible_host` 改變 **不算** route-owner change：

```text
inventory_host 相同
IP 不同
```

應正常 reconcile DNS。

---

# 31. Endpoint Deletion

Manifest：

```yaml
state: absent
```

只是一個 declarative intent。

真實刪除還需：

```yaml
safety:
  allow_endpoint_delete: true
```

加 runtime：

```text
confirm_endpoint_delete=true
```

兩者都要。

---

# 32. Delete Sequence

對 Pilot ledger 中已知 endpoint：

```text
1. remove DNS RRset
2. remove nginx vhost if Pilot-owned
3. nginx -t + reload
4. stop certmonger tracking
5. revoke current certificate when identifiable
6. remove Pilot-owned local certificate/key
7. remove Pilot-created service principal if safe
8. remove Pilot-created virtual host only if safe/unreferenced
9. remove ledger entry
```

若 endpoint：

```text
state: absent
```

但 ledger 不存在：

```text
FAIL CLOSED
```

不得猜測哪些 live resource 可以刪。

---

# 33. FreeIPA Identity Delete Safety

即使 ledger 顯示 Pilot 建立，virtual host object 刪除前仍必須檢查：

* 是否還有其他 service principal；
* 是否有非 Pilot managedBy；
* 是否有其他 references。

有外部 reference：

```text
leave object
emit warning
```

不得 cascade delete。

---

# 34. DNS Delete Safety

`internal-endpoint`：

* 永不 delete zone；
* 只 delete 自己 ledger 記錄的 A/AAAA RRset；
* 不 delete 同 owner 的其他 RR type。

例如：

```text
foo A      ← Pilot endpoint
foo TXT    ← foreign
```

刪 endpoint 後：

```text
foo TXT
```

必須保留。

---

# 35. Manifest Go Package

新增建議：

```text
internal/inventory/internal_endpoint_manifest.go
internal/inventory/internal_endpoint_validate.go
internal/inventory/internal_endpoint_write.go
```

以及：

```text
*_test.go
```

Go side MUST 提供：

```go
LoadInternalEndpointManifest
ValidateInternalEndpointManifest
NormalizeInternalEndpointManifest
```

normalized model 至少包含：

```go
type NormalizedInternalEndpoint struct {
    FQDN              string
    State             string

    DNSZone           string
    DNSOwner          string
    DNSRecordType     string
    DNSValue          string
    TTL               int

    RouteMode         string
    RouteOwnerHost    string
    RouteOwnerIP      string

    UpstreamScheme        string // http|https
    UpstreamHost          string
    UpstreamIP            string
    UpstreamPort          int

    UpstreamTLSVerify     bool
    UpstreamTLSServerName string

    TLSMode           string
    TLSPort           int

    CertificateOwner  string
    ServicePrincipal  string

    CertFile          string
    KeyFile           string
    ReloadUnit        string
}
```

Raw/parsed schema（normalize 之前）的 `upstream.tls.verify` MUST 使用 pointer/optional representation，不得直接用 `bool`：

```go
type InternalEndpointUpstreamTLS struct {
    Verify     *bool  `yaml:"verify"`
    ServerName string `yaml:"server_name,omitempty"`
}
```

原因是 `bool` 無法區分「未設定」與「false」；`*bool` 才能讓 validator 抓到「`scheme: https` 但漏填 `tls.verify`」這個 fail-closed case（§12.4.1）。Normalize 完成後才收斂成 `NormalizedInternalEndpoint.UpstreamTLSVerify bool`。

Normalized result MUST：

* deterministic；
* sorted by FQDN；
* lowercase DNS names；
* inventory host references resolved；
* IPv4/IPv6 parsed；
* no secrets。

---

# 36. Validator Must Mirror Apply Gates

採用目前 FreeIPA DNS 的既有 pattern：

```text
Go validator
    ↕ same invariants
Ansible preflight
```

現行 DNS TUI 就是先透過 Go simulation/validator，再做 YAML node mutation。

Internal endpoint 也必須這樣。

不得：

```text
TUI 接受
reconcile 才突然說 schema invalid
```

---

# 37. `pilot edit` Integration

Top-level menu 新增：

```text
internal-endpoints manifest — internal DNS/TLS/routes
```

目前 top-level menu 已包含 roster 與 freeipa-dns manifest；新 manifest 應使用相同 UX pattern。

最低功能：

```text
Endpoints
  ├─ list
  ├─ create
  ├─ detail
  ├─ edit state
  ├─ edit DNS zone/TTL
  ├─ edit route
  ├─ edit TLS
  └─ normalized preview
```

---

# 38. TUI Safety

TUI 寫檔前 MUST：

```text
simulate desired mutation
→ ValidateInternalEndpointManifest
→ only then yaml.Node write
```

不得 full struct marshal，避免破壞：

```text
comments
future sections
manual ordering
```

沿用 DNS manifest editor 的 node-surgery pattern。

---

# 39. Semantic Actions

`editActionRegistry()` 至少新增：

```text
create_internal_endpoint_manifest

create_internal_endpoint

set_internal_endpoint_state

set_internal_endpoint_dns

set_internal_endpoint_route_direct

set_internal_endpoint_route_proxy

set_internal_endpoint_tls_disabled

set_internal_endpoint_tls_freeipa

set_internal_endpoint_tls_sink
```

實作可拆更多 action，但不得使用一個 unrestricted：

```text
set_arbitrary_yaml_path
```

semantic action schema 必須保持有限、可驗證。

現有 DNS actions 已由 single action registry 同時供：

* action schema；
* validation；
* TUI automation driver；
* MCP；

這個 single-source pattern MUST 延續。

---

# 40. MCP Integration

`pilot_edit_inspect` 新增：

```json
{
  "include_internal_endpoints": true
}
```

Output example：

```json
{
  "internal_endpoints": [
    {
      "fqdn": "grafana.linker.internal",
      "state": "present",
      "route_mode": "reverse_proxy",

      "dns_zone": "linker.internal.",
      "dns_record_type": "A",

      "route_owner_host": "web01",
      "route_owner_ip": "10.0.0.10",

      "upstream_host": "grafana01",
      "upstream_ip": "10.0.0.20",
      "upstream_port": 3000,

      "tls_mode": "freeipa",
      "certificate_owner": "web01"
    }
  ]
}
```

不得輸出：

```text
private key
password
vault value
```

新增 MCP resource：

```text
pilot://internal-endpoints
```

目前 MCP 已有 DNS resolved-IP view 與 plan/apply contract，因此 endpoint 不應做一套平行的 agent API。

---

# 41. Workspace Completeness

更新：

```text
cmd/pilot/cmd/workspace_completeness.go
```

當 workspace 已配置：

```text
internal_endpoint_manifest_file
```

時檢查：

* manifest exists；
* schema valid；
* referenced inventory hosts exist；
* DNS zones exist in FreeIPA DNS manifest；
* zone merge-mode compatible；
* reverse-proxy hosts 有 `reverse-proxy` role；
* direct TLS sink syntax valid。

只做 static check。

下面 live state 不在 completeness：

```text
FreeIPA enrollment
nginx active
certmonger
actual DNS
actual certificate
```

目前 completeness 已集中檢查 workspace source files，所以 endpoint config 不得另造獨立「只有 reconcile 才知道」的 readiness definition。

---

# 42. Reconcile Catalog

修改：

```text
cmd/pilot/cmd/deploy_catalog.go
```

新增：

```text
internal-endpoint
```

要求：

```go
Reconcile: true
```

Note 要明確告知：

```text
data-driven day-2 reconciler
requires internal_endpoint_manifest_file
manages DNS + FreeIPA service certificates + optional nginx
```

---

# 43. Component Contracts

## 43.1 `freeipa-ca-trust`

Suggested contract semantics：

```yaml
schemaVersion: 1
id: freeipa-ca-trust
role: all

specs:
  - path: docs/verification/freeipa-ca-trust.md
    rows: {all: true}

playbooks:
  apply: playbooks/apply/freeipa-ca-trust-apply.yml

dependencies:
  - component: freeipa-server
    required: true
    relation: planOnly
    reason: >
      CA source is selected from the designated freeipa-server inventory
      host and transferred through the existing Ansible management channel.

hostCardinality: one-or-more

stagePolicy:
  variable: stage
  default: sandbox

evidenceRequirement:
  targetTest: topology
  idempotency: required

verification:
  autoDeploy: false

site:
  include: false
  order: 0
  vars: {}
  tags: []
  optIn: true
```

`planOnly` 是因為 ComponentContract v1 目前只有：

```text
sameHosts
providerEndpoint
planOnly
```

沒有「read artifact from provider inventory host」relation。

不要為這一個 feature 擴 ComponentContract schema。

---

## 43.2 `reverse-proxy`

```yaml
schemaVersion: 1
id: reverse-proxy
role: reverse-proxy

specs:
  - path: docs/verification/reverse-proxy.md
    rows: {all: true}

playbooks:
  apply: playbooks/apply/reverse-proxy-apply.yml

dependencies: []

hostCardinality: one-or-more

stagePolicy:
  variable: stage
  default: sandbox

evidenceRequirement:
  targetTest: vm
  idempotency: required

verification:
  autoDeploy: false

site:
  include: true
  order: <after-freeipa-client>
  vars: {}
  tags: [reverse-proxy]
  optIn: false
```

---

## 43.3 `internal-endpoint`

```yaml
schemaVersion: 1
id: internal-endpoint
role: freeipa-server

specs:
  - path: docs/verification/internal-endpoint.md
    rows: {all: true}

playbooks:
  apply: playbooks/apply/internal-endpoint-apply.yml

dependencies:
  - component: freeipa-server
    required: true
    relation: sameHosts

  - component: freeipa-dns
    required: true
    relation: planOnly
    reason: >
      Endpoint records may only be reconciled inside a FreeIPA DNS
      zone already declared by the freeipa-dns manifest.

  - component: freeipa-ca-trust
    required: true
    relation: planOnly
    reason: >
      The endpoint reconciler applies the same CA-trust baseline to all
      managed hosts before endpoint verification.

  - component: reverse-proxy
    required: false
    relation: planOnly
    reason: >
      Required only for endpoints whose route.mode is reverse_proxy;
      the exact host is selected in the endpoint manifest.

hostCardinality: exactly-one

groupVars:
  - name: ipa_admin_password
    type: string
    required: true
    secret: true

  - name: internal_endpoint_manifest_file
    type: string
    required: true
    secret: false

stagePolicy:
  variable: stage
  default: sandbox

evidenceRequirement:
  targetTest: topology
  idempotency: required

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

# 44. Verification Specs MUST be Spec v2

新的：

```text
docs/verification/freeipa-ca-trust.md
docs/verification/reverse-proxy.md
docs/verification/internal-endpoint.md
```

全部 MUST 使用 Spec v2。

目前 parser 已正式支援：

* strict YAML front matter；
* typed expect；
* per-host / aggregate scope；
* applicability；
* readOnly / isolatedMutation action；
* verification tags；
* cleanup policy。

不得為新 component 再新增 legacy verification table spec。

---

# 45. `freeipa-ca-trust` Acceptance Rows

至少：

| ID | Requirement                                               |
| -- | --------------------------------------------------------- |
| C1 | designated IdM CA 是 integrated self-signed root CA        |
| C2 | managed host 安裝的 CA bundle fingerprint 與 server source 相同 |
| C3 | Debian/Ubuntu system trust 能驗證 CA-issued leaf             |
| C4 | RedHat system trust 能驗證 CA-issued leaf                    |
| C5 | 未 enroll FreeIPA 的 host 一樣能建立 trust                       |
| C6 | rerun unchanged → changed=0                               |

---

# 46. `reverse-proxy` Acceptance Rows

至少：

| ID | Requirement                                  |
| -- | -------------------------------------------- |
| C1 | nginx package installed                      |
| C2 | nginx enabled/active                         |
| C3 | `nginx -t` success                           |
| C4 | distro default site 不接管 arbitrary endpoint   |
| C5 | Pilot config namespace 存在且不覆蓋 foreign config |
| C6 | rerun unchanged → changed=0                  |

---

# 47. `internal-endpoint` Acceptance Rows

至少：

| ID  | Requirement                                         |
| --- | --------------------------------------------------- |
| C1  | strict schema，unknown field fail                    |
| C2  | nested FQDN 可 normalize                             |
| C3  | duplicate canonical FQDN fail                       |
| C4  | direct route DNS 指向 target                          |
| C5  | reverse_proxy DNS 指向 proxy，不是 upstream              |
| C6  | port 不進 DNS                                         |
| C7  | referenced FreeIPA zone 必須存在且為 merge mode           |
| C8  | DNS ownership collision fail closed                 |
| C9  | all managed hosts 使用 FreeIPA DNS resolver           |
| C10 | all managed hosts trust FreeIPA CA                  |
| C11 | TLS cert owner 正確推導                                 |
| C12 | TLS owner 未 enroll → fail before mutation           |
| C13 | HTTP service principal / managedBy 正確               |
| C14 | cert SAN 包含 exact FQDN                              |
| C15 | certmonger status MONITORING                        |
| C16 | private key 只存在 certificate owner                   |
| C17 | proxy endpoint HTTPS handshake success              |
| C18 | proxy forwards 到 declared backend port              |
| C19 | direct endpoint HTTPS handshake success             |
| C20 | non-443 direct TLS 正確使用 `fqdn:port`                 |
| C21 | `state: absent` 沒有 dual confirmation 時不 mutation（見下方 2026-08-14 註記） |
| C22 | delete 不碰 foreign DNS type/config                   |
| C23 | missing ownership ledger 的 destructive request fail（見下方 2026-08-14 註記） |
| C24 | route-owner migration v1 fail closed（見下方 2026-08-14 註記） |
| C25 | inventory host IP 改變可正常更新 DNS                       |
| C26 | rerun unchanged → changed=0                         |
| C27 | reverse proxy 支援 HTTPS upstream                       |
| C28 | HTTPS upstream `verify=true` 正常驗證 CA + hostname       |
| C29 | HTTPS upstream `verify=false` 可連線 self-signed/untrusted certificate |
| C30 | HTTPS upstream 未明確設定 `verify` 時 fail closed          |
| C31 | insecure HTTPS upstream 仍實際使用 TLS，不可退化成 HTTP        |
| C32 | explicit upstream TLS SNI/server_name 正確傳遞            |

**2026-08-14 註記（C21/C23/C24）**：這三項底層行為（dual confirmation 才能刪除、
destructive request 要有 ownership ledger 記錄才放行、route-owner migration v1 fail
closed）本身仍是真實需求，`playbooks/apply/internal-endpoint-apply.yml` 裡對應的
assert gate 完全沒動，而且早在 Phase 8 就已經用真實 negative-path VM 測試證明過會
fail closed（見 `docs/evidence/internal-endpoint/2026-08-14-phase8.md`）。改變的只是
`docs/verification/internal-endpoint.md` 不再用獨立編號的 row 追蹤它們——這三個 row
原本的探測方式依賴一支 `pilot reconcile internal-endpoint --manifest/--ledger` 非互動
CLI，這支 CLI 從 Phase 6 起每一輪都被列為「之後再做」，最終拍板不做（需要先解決
secret/vault 怎麼安全帶進去的設計問題，不是隨手包一層就好）。三個 row 已從該檔移除，
`internal-endpoint-apply.yml` 裡對應 task 的 `tags: [C21]`/`[C23]`/`[C24]` 也一併移除
（gate 本身保留），以符合 `tag_coverage_test.go` 的孤兒 tag 檢查。

---

# 48. Contract Traceability

所有新 rows 必須：

```text
apply task tag
```

或：

```text
explicit exemption + reason
```

現行 contract lint 會：

* 驗 spec path；
* 驗 regression tests；
* 驗 playbook tags；
* 驗 row ownership；
* 驗所有 `*-apply.yml` 都有 contract。

因此 coding agent 不得最後才補 contract。

應在 feature 第一階段就建立：

```text
spec
contract
playbook skeleton
regression skeleton
```

---

# 49. Existing Contract Fixture Count

目前：

```go
len(loaded) != 28
```

是 fixture test 的硬編碼。

本規格新增三份 production contracts 後，若期間沒有其他 contract 加入：

```text
28 → 31
```

coding agent MUST 更新相關 fixture expectations。

但開始 implementation 時必須重新 count，不得盲目寫死 31。

---

# 50. Regression Tests

新增：

```text
internal/inventory/internal_endpoint_manifest_test.go
internal/inventory/internal_endpoint_validate_test.go
internal/inventory/internal_endpoint_write_test.go

internal/spec/freeipa_ca_trust_regression_test.go
internal/spec/reverse_proxy_regression_test.go
internal/spec/internal_endpoint_regression_test.go
```

另外修改：

```text
cmd/pilot/cmd/tag_coverage_test.go
cmd/pilot/cmd/actions_test.go
cmd/pilot/cmd/edit_*_test.go
cmd/pilot/cmd/mcp*_test.go
internal/contract/*test.go
internal/inventory/*catalog*test.go
```

---

# 51. Validator Unit-Test Matrix

至少包含：

```text
valid direct IPv4
valid direct IPv6
valid explicit address
valid reverse proxy
valid nested FQDN
valid zone apex

duplicate fqdn
wildcard fqdn
fqdn with URL scheme
fqdn with port
fqdn outside zone
unknown inventory host
direct both address + inventory_host
direct neither
literal address + freeipa TLS
proxy host missing
proxy host without reverse-proxy role
upstream port 0
upstream port 65536
unknown route mode
unknown TLS mode
relative cert path
cert path == key path
invalid systemd unit
TLS owner not enrolled
authoritative DNS zone
DNS ownership collision
unknown manifest key
state absent without delete safety

reverse proxy upstream missing scheme
valid http upstream
valid https upstream verify=true
valid https upstream verify=false
https upstream missing tls.verify
http upstream with tls block
unknown upstream scheme
https upstream verify=true + explicit server_name
https upstream verify=false + server_name
https upstream verify=true + IP only + no SNI
https upstream verify=false + IP only
```

---

# 52. Disposable Topology Acceptance

MUST 使用至少三台 VM。

```text
freeipa-server
    EL9
    integrated DNS
    integrated self-signed root CA

proxy01
    Ubuntu 24.04
    FreeIPA client
    reverse-proxy

app01
    Ubuntu 24.04
    FreeIPA client
    disposable HTTP/TLS test service
```

---

# 53. Required Test Endpoints

建立 test zone，例如：

```text
apps.pilot.internal.
```

至少三個 endpoints：

### A. Direct TLS

```text
direct.apps.pilot.internal
    DNS → app01
    HTTPS → app01:<non-standard-port>
    FreeIPA certificate
```

---

### B. Nested direct DNS

```text
aaa.xxx.apps.pilot.internal
    DNS → app01
    tls.disabled
```

證明 nested owner。

---

### C. Reverse proxy

```text
proxy.apps.pilot.internal
    DNS → proxy01
    HTTPS :443
    nginx → app01:18080
```

---

### D. Reverse proxy + insecure HTTPS upstream

```text
legacy.apps.pilot.internal
    DNS → proxy01
    HTTPS :443（FreeIPA-signed frontend certificate）
    nginx → app01:18443（HTTPS, self-signed certificate, tls.verify: false）
```

證明 upstream 確實走 TLS，而不是把 backend 改成 HTTP 讓測試假通過；也證明 proxy 在 manifest 明確宣告 `tls.verify: false` 時，能接受 self-signed/untrusted upstream certificate。

---

# 54. Disposable Direct TLS Test Service

Test topology MAY 使用 Python stdlib 建立 disposable HTTPS service。

僅能放在：

```text
test fixture / disposable topology
```

不得把它變成 production component dependency。

測試目的：

* consume cert_file/key_file；
* systemd reload/restart；
* non-standard port；
* return deterministic body。

同一套 disposable HTTPS service fixture 應可重用於 endpoint D（§53，reverse proxy insecure HTTPS upstream）：在 `app01` 上另起一個 instance（例如 port 18443），憑證改為**未加入 FreeIPA CA trust chain 的 self-signed certificate**，用來證明 `proxy01` 的 nginx 在 `tls.verify: false` 時仍能完成 TLS handshake 並轉發，而不需要、也不應該把該憑證發成 FreeIPA-signed。

---

# 55. Actual-Run Evidence

Feature 不能只通過 unit test。

Coding agent MUST 執行：

```text
fresh topology
→ apply prerequisites
→ freeipa DNS zone
→ internal-endpoint reconcile
→ verify
→ second reconcile
```

第二次：

```text
changed=0
failed=0
```

並保留實際 evidence。

Repository 規則要求 verification/runbook 裡聲稱執行成功的命令必須先有 actual-run evidence；不可把預期輸出寫成已驗證事實。

新增：

```text
docs/evidence/freeipa-ca-trust/YYYY-MM-DD.md
docs/evidence/reverse-proxy/YYYY-MM-DD.md
docs/evidence/internal-endpoint/YYYY-MM-DD.md
```

---

# 56. Failure-Injection Tests

至少測：

### invalid Nginx candidate

預期：

```text
nginx -t fails
current running config remains active
DNS not changed
```

### certificate request failure

預期：

```text
DNS not changed
Nginx new vhost not activated
ledger not committed
```

### backend unreachable

reverse-proxy endpoint：

```text
pre-DNS readiness fails
DNS not switched
```

### DNS API failure

預期：

```text
certificate/nginx may have prepared state
but ledger not mark endpoint fully applied
subsequent reconcile safely resumes
```

### CA trust failure on one managed host

預期：

```text
endpoint publication stops before DNS exposure
```

---

# 57. Idempotency Requirements

下面全部 unchanged：

```text
CA bundle
DNS resolver
IPA host/service object
managedBy
certmonger tracking
certificate
nginx config
DNS record
ownership ledger
```

第二次 reconcile：

```text
changed=0
```

不得每次：

```text
renew cert
restart nginx
rewrite ledger
re-add managedBy
```

---

# 58. Certificate Renewal Test

至少一次測試要證明：

```text
certmonger tracks certificate
```

且 post-renew hook 可以 reload consumer。

不要求測試真的等到 certificate expiry。

可使用 safe resubmit/renewal test，但必須遵守 disposable target 規則。

---

# 59. No Secret Leakage

以下不得出現在：

```text
stdout
stderr
TREC recording
MCP output
audit JSON
normalized preview
git diff
```

內容：

```text
ipa_admin_password
private key
raw key material
```

Ansible secret operations MUST：

```yaml
no_log: true
```

但不要把整個 playbook 都 `no_log`，避免失去診斷能力。

---

# 60. Documentation Changes

完成實跑後更新：

```text
README.md
DELIVERY.md
docs/network-firewall-matrix.md
docs/runbooks/<new feature docs>
```

至少說清楚：

```text
direct vs reverse_proxy
DNS never stores ports
nested FQDN
FreeIPA CA root assumption
all-host trust behavior
all-host DNS behavior
direct TLS sink
certificate renewal
delete safety
```

---

# 61. CLI / UX Examples Required in Docs

至少提供：

### direct DNS only

```yaml
- fqdn: postgres.db.linker.internal
  state: present

  dns:
    zone: linker.internal.

  route:
    mode: direct
    target:
      inventory_host: pg01

  tls:
    mode: disabled
```

---

### direct HTTPS

```yaml
- fqdn: aaa.xxx.linker.internal
  state: present

  dns:
    zone: linker.internal.

  route:
    mode: direct
    target:
      inventory_host: app01

  tls:
    mode: freeipa
    port: 8443

    sink:
      cert_file: /etc/app/tls/server.crt
      key_file: /etc/app/tls/server.key
      key_group: app
      key_mode: "0640"

      reload:
        mode: systemd
        unit: app.service
```

Client：

```text
https://aaa.xxx.linker.internal:8443
```

---

### reverse proxy

```yaml
- fqdn: grafana.linker.internal
  state: present

  dns:
    zone: linker.internal.

  route:
    mode: reverse_proxy

    proxy:
      provider: nginx
      inventory_host: web01

    upstream:
      scheme: http
      inventory_host: grafana01
      port: 3000

  tls:
    mode: freeipa
```

Client：

```text
https://grafana.linker.internal
```

---

### reverse proxy with insecure HTTPS upstream

```yaml
- fqdn: legacy.linker.internal
  state: present

  dns:
    zone: linker.internal.

  route:
    mode: reverse_proxy

    proxy:
      provider: nginx
      inventory_host: web01

    upstream:
      scheme: https
      inventory_host: legacy01
      port: 8443

      tls:
        verify: false
        server_name: legacy01.internal

  tls:
    mode: freeipa
```

Client：

```text
https://legacy.linker.internal
```

Nginx ↔ upstream 之間仍是 TLS，只是不驗證 `legacy01` 的 certificate（見 §12.4.3）。

---

# 62. Explicit Non-Goals v1

v1 MUST NOT implement：

* wildcard certificates；
* wildcard DNS endpoint；
* ACME；
* public CA；
* Cloudflare / Route53；
* upstream mTLS client certificates；
* per-endpoint custom upstream CA bundle；
* certificate pinning；
* arbitrary upstream TLS cipher configuration；
* arbitrary upstream TLS protocol configuration；
* arbitrary TCP proxy；
* UDP proxy；
* SRV port discovery；
* Kubernetes Ingress；
* container-internal CA injection；
* Java cacerts；
* arbitrary shell reload hooks；
* multi-FreeIPA realm；
* multi-active reverse-proxy HA/VIP；
* automatic DNS zone creation；
* in-place route-owner migration；
* automatically reconfigure arbitrary application TLS settings。

---

# 63. Implementation Order

Coding agent MUST 依下列順序實作。

## Phase 1 — Specs / contracts

先建立：

```text
docs/verification/freeipa-ca-trust.md
docs/verification/reverse-proxy.md
docs/verification/internal-endpoint.md

contracts/freeipa-ca-trust.yaml
contracts/reverse-proxy.yaml
contracts/internal-endpoint.yaml
```

先讓：

```text
contract/spec lint
```

結構正確。

---

## Phase 2 — Pure Go endpoint model

完成：

```text
loader
validator
normalizer
unit tests
```

此階段不得碰 live host。

---

## Phase 3 — CA trust

完成：

```text
freeipa-ca-trust shared tasks
standalone apply
verification
```

先在 VM 實跑。

---

## Phase 4 — Reverse proxy base

完成：

```text
reverse-proxy role
inventory catalog
nginx base
verification
```

先在 VM 實跑。

---

## Phase 5 — FreeIPA certificate lifecycle

完成：

```text
service principal
managedBy
ipa-getcert
certmonger
SAN verification
renewal hook
```

必須在 real disposable FreeIPA topology 驗證，不能 mock FreeIPA CLI。

---

## Phase 6 — Endpoint direct mode

先做：

```text
direct + tls.disabled
direct + tls.freeipa
```

證明 nested FQDN。

---

## Phase 7 — Reverse proxy mode

加入：

```text
nginx vhost
upstream IP/port
TLS
DNS→proxy
```

---

## Phase 8 — Ownership / deletion

加入：

```text
ledger
state absent
dual confirmation
foreign-resource protection
```

---

## Phase 9 — TUI / actions / MCP

等 core reconcile 已有完整 unit/integration test 後再 expose agent-facing mutation surface。

---

## Phase 10 — Full topology evidence

最後：

```text
fresh topology
apply
reconcile
verify
idempotency
failure injection
docs evidence
```

**完成（2026-08-14）**：fresh 3-VM topology（`p10-ipa`/`p10-app`/`p10-proxy`）涵蓋
manifest schema 支援的每一種 route/TLS 組合（5 個真實 endpoint + 1 個刻意設計失敗
的 endpoint）；apply/reconcile 全部真跑；idempotency 第二輪 `changed=0 failed=0`；
failure injection（non-enrolled host 上 tls.mode=freeipa 必須在 enrollment
preflight 就 fail closed）已驗證。`docs/verification/internal-endpoint.md` 這輪達到
28/32（史上最佳，前次最佳是 Phase 7 的 21/32），剩下 4 項（C9、C21、C23、C24）都是
已明確定位、已記錄、刻意延後的缺口（DNS resolver baseline 尚未實作；`pilot
reconcile internal-endpoint` 非互動 CLI 尚未存在），不是未知問題。`freeipa-ca-trust.md`
／`reverse-proxy.md`（Phase 3/4 已是 v1.0）在這輪新 topology 上重新確認 100% 綠燈、
無 regression。完整 evidence：`docs/evidence/internal-endpoint/2026-08-14-phase10.md`。

**同日 follow-up（2026-08-14）**：C9 補上真邏輯（見 §47 表格前的 DoD 註記），
`internal-endpoint.md` 升級到 29/32 fixable。隨後拍板 **C21/C23/C24 直接 retire，
不實作** `pilot reconcile internal-endpoint` 非互動 CLI（見 §47 acceptance rows表格
後的 2026-08-14 註記——底層 gate 保留且 Phase 8 已驗證過，只是不再單獨編號驗證）。
`docs/verification/internal-endpoint.md` 現在是 29 rows，理論上已無任何 row 卡在
「等未來才會做的工作」——離 v1.0 promotion 只差一次把兩輪修正合併在同一個 topology
上重跑的完整驗證（尚未執行）。

---

# 64. Required Files Summary

預期新增/修改至少包含：

```text
contracts/
  freeipa-ca-trust.yaml
  reverse-proxy.yaml
  internal-endpoint.yaml

docs/verification/
  freeipa-ca-trust.md
  reverse-proxy.md
  internal-endpoint.md

docs/evidence/
  freeipa-ca-trust/...
  reverse-proxy/...
  internal-endpoint/...

playbooks/apply/
  freeipa-ca-trust-apply.yml
  reverse-proxy-apply.yml
  internal-endpoint-apply.yml
  internal-endpoints.manifest.example.yaml

playbooks/apply/tasks/
  freeipa-ca-trust.yml
  freeipa-dns-client-common.yml

playbooks/apply/templates/
  internal-endpoint-nginx.conf.j2

internal/inventory/
  internal_endpoint_manifest.go
  internal_endpoint_validate.go
  internal_endpoint_write.go
  *_test.go

internal/spec/
  freeipa_ca_trust_regression_test.go
  reverse_proxy_regression_test.go
  internal_endpoint_regression_test.go

cmd/pilot/cmd/
  deploy_catalog.go
  edit_tui.go
  edit_tui_internal_endpoints.go
  edit_actions_registry.go
  edit automation driver helpers
  mcp_edit_tools.go
  workspace_completeness.go
  associated tests

internal/inventory/
  catalog.go
  contracts.go
```

並依 contract count / traceability 調整：

```text
internal/contract/*test.go
cmd/pilot/cmd/tag_coverage_test.go
```

---

# 65. Definition of Done

Feature 只有在以下條件 **全部成立** 時才算完成。

* [ ] 任意非 wildcard FQDN 可建立
* [ ] `aaa.xxx.<zone>` nested FQDN 可建立
* [ ] direct DNS 可指 inventory host
* [ ] direct DNS 可指 explicit IP
* [ ] reverse proxy DNS 永遠指 proxy host
* [ ] backend port 不進 DNS
* [ ] FreeIPA 確認為 self-signed integrated root CA
* [ ] 所有 managed Linux host system trust 安裝 FreeIPA CA
* [x] 所有 managed host 使用 FreeIPA DNS resolver（2026-08-14 補上真邏輯，見
  `docs/evidence/internal-endpoint/2026-08-14-phase10.md` 的 follow-up round：
  `tasks/freeipa-dns-client-resolver.yml` 共用檔 + C9 自身探測改成 OS-portable，
  3 台 vm-target（AlmaLinux 自我指向 + AlmaLinux client + Ubuntu client）驗證，
  idempotent）
* [ ] direct FreeIPA TLS certificate owner 正確
* [ ] proxy FreeIPA TLS certificate owner 正確
* [ ] private key 不離開 certificate owner
* [ ] HTTP service managedBy/delegation 正確
* [ ] certificate SAN 正確
* [ ] certmonger MONITORING
* [ ] renewal hook 存在
* [ ] Nginx candidate config 先 `nginx -t`
* [ ] DNS 最後才 publish
* [ ] HTTPS 從所有 managed hosts 驗證成功且完全不用 insecure mode
* [ ] DNS ownership collision fail closed
* [ ] authoritative zone conflict fail closed
* [ ] deletion 需要 manifest safety + runtime confirm
* [ ] foreign resource 不被刪
* [ ] route-owner migration v1 fail closed
* [ ] ownership ledger atomic
* [ ] `pilot edit` 可管理 endpoint manifest
* [ ] semantic actions 可 plan/apply
* [ ] MCP 可 inspect endpoint normalized state
* [ ] MCP 不洩漏 secret/private key
* [ ] ComponentContract 全通過
* [ ] Spec v2 全通過
* [ ] Go regression tests 全通過
* [ ] fresh topology actual-run PASS
* [ ] second reconcile `changed=0 failed=0`
* [ ] evidence 已寫入 repo
* [ ] README / DELIVERY / firewall matrix 與真實實作一致

---

# 66. Final Architectural Invariant

整套功能的最終責任模型必須保持：

```text
FreeIPA
├── corporate root CA
├── HTTP/<fqdn> service identities
└── authoritative DNS

freeipa-ca-trust
└── managed-host OS trust

internal-endpoint
├── FQDN desired state
├── direct / reverse_proxy decision
├── certificate ownership
├── DNS endpoint RRset
└── lifecycle / safety / ownership

reverse-proxy
└── Nginx runtime provider
```

對任何 endpoint：

```text
route.mode = direct
    DNS → target

route.mode = reverse_proxy
    DNS → proxy
    proxy → backend:port
```

永遠不得把：

```text
DNS = reverse proxy
```

當成系統的固定前提。

這是本功能最重要的 long-term architecture constraint。


---

# 67. Revision Log

## v1.1 — Reverse Proxy HTTPS Upstream

以下修訂已整合進本文對應章節（§9、§12.3–§12.4、§13.1–§13.2、§14、§35、§47、§51、§53–§54、§61、§62），取代原 v1.0 對 reverse proxy upstream protocol 的限制，不再以獨立附錄保留：

* `route.upstream` 新增必填欄位 `scheme: http|https`；省略 MUST fail（§12.3）。
* HTTPS upstream 新增 `tls.verify: true|false`（必填，漏填 fail closed）與 `tls.server_name`（SNI）（§12.4.1、§12.4.5–§12.4.6）。
* `verify: false` 為正式支援的 v1 功能語意是 *encrypted but unauthenticated upstream TLS*，不是降級成 `http`，也不是「trusted HTTPS」；normalized preview/TUI/MCP inspect MUST 明確標示 `TLS verification: DISABLED`（§12.4.3）。
* HTTP upstream 不得帶 `tls` block（§12.4.4）。
* Nginx 生成規則按 http / verified-https / unverified-https 三分流（§13.1），readiness check 按 scheme/verify 三分流，`verify: false` 時不得因憑證不受信任而判定 readiness 失敗（§13.2）。
* `NormalizedInternalEndpoint` 擴充 `UpstreamScheme`、`UpstreamTLSVerify`、`UpstreamTLSServerName`；raw schema 的 `tls.verify` MUST 用 `*bool`，以區分「未設定」與「false」（§35）。
* Acceptance rows 新增 C27–C32，validator unit-test matrix 新增對應案例（§47、§51）。
* Disposable topology 新增 endpoint D（reverse proxy + insecure HTTPS upstream，backend 為 app01 上另一個 self-signed HTTPS instance）（§53–§54）。
* 移除原 non-goal「HTTPS upstream reverse proxy」；新增更精確的 non-goals：upstream mTLS client certificates、per-endpoint custom upstream CA bundle、certificate pinning、arbitrary upstream TLS cipher/protocol configuration（§62）。

此修訂沒有更動 §1–§11、§15–§34、§36–§46、§48–§50、§55–§60、§63–§66 的既有決策；`internal-endpoint` 仍是唯一 primary resource，DNS 仍只指向 route owner（direct target 或 proxy host，never upstream），port 仍不進 DNS。

## v1.2 — `freeipa-dns-client` Default Role Preset Coverage

新增鎖定決策（§6.2、§27.1）：

* 修掉既有 gap——`freeipa-dns-client` 目前未被 wire 進 `internal/inventory/contracts.go`/`catalog.go`，`inventory.example.yml` 裡的示範其實走不通 `pilot inventory generate`；新增 `reverse-proxy` 角色時 MUST 一併補上（§6.2）。
* `cmd/pilot/cmd/edit_tui_role_presets.go` 的三組內建 minimal-PoC role preset（FreeIPA 身份伺服器、Nexus 中央服務節點、被監控的 Linux 主機）MUST 各自把 `freeipa-dns-client` 加進 `Roles` 清單，讓新建 minimal-PoC host 預設具備 DNS resolver baseline（§27.1）。
* 此決策只影響 authoring-time 的角色範本便利性，不改變 §27 既定的 component-contract opt-in 語意；已存在 `role-presets.yml` 的環境不受影響。
