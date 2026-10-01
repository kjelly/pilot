---
schemaVersion: 2
compatibility: {minPilotVersion: "0.9"}
intent:
  summary: dns caching resolver tier with automatic FreeIPA split forwarding
  source: 2026-10-01 使用者需求 — 在 FreeIPA DNS 前加一層獨立的 DNS 主機，內部網域自動導向 FreeIPA，外部網域導向使用者設定的 upstream
  maintainer: sre
targets:
  roles: [dns]
  hostScope: per-host
  platforms:
    - {os: ubuntu, versions: ["22.04", "24.04"]}
inputs:
  - {name: dns_mode, required: true, validation: '^(freeipa-split|forward-only)$'}
  - {name: dns_upstream_servers, required: true, validation: '^[0-9A-Fa-f:.@]+( [0-9A-Fa-f:.@]+)*$'}
  - {name: dns_access_control, required: true, validation: '^[0-9A-Fa-f:./]+( [0-9A-Fa-f:./]+)*$'}
  - {name: dns_cache_max_ttl, required: true, validation: '^[0-9]+$'}
  - {name: dns_cache_max_negative_ttl, required: true, validation: '^[0-9]+$'}
  - {name: dns_dnssec_validation, required: true, validation: '^(true|false)$'}
  - {name: external_probe_name, required: true, validation: '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?\.?$'}
  - {name: freeipa_domain, required: true, validation: '^(none|[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?)$'}
  - {name: freeipa_dns_server_ips, required: true, validation: '^(none|[0-9A-Fa-f:.]+( [0-9A-Fa-f:.]+)*)$'}
  - {name: freeipa_probe_fqdn, required: true, validation: '^(none|[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?)$'}
  - {name: freeipa_extra_zone_probe_fqdn, required: true, validation: '^(none|[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?)$'}
  - {name: freeipa_reverse_probe_ip, required: true, validation: '^(none|[0-9A-Fa-f:.]+)$'}
  - {name: dns_zone_probe_fqdn, required: true, validation: '^(none|[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?)$'}
  - {name: pilot_inventory_path, required: true, validation: '^(none|/.*)$'}
  - {name: dns_consumer_pattern, required: true, validation: '^(none|[A-Za-z0-9_.:!&*-]+)$'}
traceability: {components: [dns]}
defaults:
  become: true
  timeout: 30s
  action: {mode: readOnly}
evidencePolicy: {captureStdout: true, retention: retain-all}
---

# Verification Spec — dns（FreeIPA 前的第一層快取 DNS，自動分流）

> 版本：**DRAFT v0.2（2026-10-01，尚未對 vm-target 實跑）**
> 對齊規範：pilot 通用基礎設施**服務端**規範；擴充既有 `dns` role
> （目前由 `core-infra-provider-apply.yml -e infra_role=dns` 實作）
> 維護者：sre

## 0. 這份檔的狀態（先讀）

這是 AGENTS.md §3.0 的 spec-first 產物：**先確定 acceptance，再寫 playbook**。
apply playbook、regression test 與 actual-run evidence 都還不存在，下面每一個
row 都是要達成的驗收條件，現在對任何主機跑都不會全綠。

完成後，本檔取代 `docs/verification/core-infra-provider.md` 的 DNS rows
（C1–C3、C7）；`core-infra-provider.md` 只保留 NTP（見 §7 配套變更）。

v0.2 把「所有設定都能用 `pilot edit` 完成」與三個既有 bug 的修正納入同一個
delivery（§3.5），並依實際讀到的 resolver 共用 task 調整 tier 主機自己的 resolver
設計（§2 B9）。

### 0.1 需求來源與使用者決定（2026-10-01）

需求原文：新增一個 dns role 當作第一層 DNS，降低 FreeIPA DNS 的壓力；新的 DNS
要自動分流，內部網域導向 FreeIPA，外部網域導向外部 DNS server。

使用者對評估的回覆：

| 問題 | 決定 |
|---|---|
| 新 role 還是擴充 | 擴充既有 `dns` role，先寫 spec |
| 有沒有量測到 FreeIPA DNS 壓力 | 沒有，是預防性的 |
| tier 放哪 | 獨立主機 |
| 外部 upstream | 使用者可設定 |
| 遷移後關掉 FreeIPA 的 open recursion | 不關（`freeipa_dns_allow_any_recursion` 維持現狀） |
| 除了 IPA domain 還有哪些內部 zone | 使用者可設定 |
| `pilot edit` 支援與既有 bug | 一起修；先更新 spec，再跑 vm-target |

### 0.2 寫 spec 前實測到、直接影響設計的事實

以下來自 2026-10-01 的探測，都不是本 spec 的 actual-run evidence，只是用來避免
猜 expected：
- 對一台既有的 FreeIPA vm-target 唯讀 `dig`。
- 一個只綁本機高 port 的拋棄式 unbound **1.24.2**（Homebrew 版，不是目標 Ubuntu
  的套件版本，§8 A1）。
- 在 scratchpad 用 ansible-core 2.19.2 與 `pilot inventory generate` 做的最小重現。

| 事實 | 影響 |
|---|---|
| unbound 開啟 DNSSEC 驗證時，stub 到 FreeIPA 的 `ipa.pilot.internal` 一律 SERVFAIL（`+cd` 則 NOERROR）；加 `domain-insecure` 後正常 | §2 B3；C12 會在漏設時直接 fail |
| unbound 內建 `168.192.in-addr.arpa.` 等 RFC1918 反解 zone 為 `static`：stub 一個 `122.168.192.in-addr.arpa.`，查詢仍由內建 zone 回 NXDOMAIN（SOA `localhost. nobody.invalid.`），根本不會送到 FreeIPA；加 `local-zone: "<zone>" transparent` 後才會送出 | §2 B3；C16 |
| FreeIPA zone 的 SOA minimum 是 3600、SRV TTL 是 86400、A TTL 是 1200 | §2 B5：沒有上限時，新建的紀錄可能被快取的 NXDOMAIN 擋 1 小時，SRV 變動要 1 天才生效 |
| `cache-max-negative-ttl: 60` 會直接反映在 NXDOMAIN authority SOA 的 TTL；`cache-max-ttl: 300` 把 86400 的 SRV TTL 壓到 300 | C13、C14 可以用實際回應驗證，不只讀設定 |
| 對 FreeIPA 送 RD=0 查詢一個它不是權威的名字（例如它沒有的反解 zone），回的是指向 root 的 upward referral，unbound 端結果是 SERVFAIL | §5 G5：每個導向 FreeIPA 的 zone，apply 前都要確認 FreeIPA 回 `aa` |
| stub 有兩個位址、其中一個不可達時，查詢仍會成功（最差約 1.1 秒） | HA 依賴多個 FreeIPA DNS server 時成立 |
| FreeIPA 的 named 對 `id.server CH TXT` 回空字串；unbound 設 `identity` 後回 `"pilot-dns:<name>"` | C18、C20 用它判斷「回答的是不是 tier」 |
| `unbound-control list_stubs` 的格式是 `ipa.pilot.internal. IN stub noprime +i 192.0.2.1 192.168.122.2`；`list_forwards` 是 `. IN forward 1.1.1.1 9.9.9.9`；`get_option access-control` 每行一筆 `<cidr> allow` | C5、C6、C11 的解析方式 |
| 沒套用 resolver baseline 的 Ubuntu 主機，`/etc/resolv.conf` 第一個 nameserver 是 systemd-resolved 的 `127.0.0.53`，它不轉送 `id.server` 的 CH 查詢 | C20 假設 consumer 的 resolver 由 baseline 管理（直接寫入真實 nameserver）；指向 `127.0.0.53` 的主機會被判定不在 tier 上 |
| **既有 bug 1**：`core-infra-provider-apply.yml` 在 play `vars:` 宣告 `dns_zones: []`，蓋掉 inventory 的 `dns_zones`（重現結果 `dns_zones=[]`） | §3.5 P5：inventory 提供的設定不准出現在 play `vars:`（AGENTS.md §4.5 第 3 點） |
| **既有 bug 2**：`group_vars/dns/` 目錄存在時，Ansible 只載入目錄，`group_vars/dns.yml` 整個被忽略；`pilot inventory generate` 對 `dns` 主機兩個都會建立，結果 `dns_listen_addr`、`dns_upstream` 都是 UNSET | §3.5 P1、P4 |
| **既有 bug 3**：scaffold 把 `zones.example.yaml` 原樣複製成生效中的設定，假的 `pilot.lan` 與指向 `10.0.1.2` 的 `corp.internal` stub 都會變成真設定 | §3.5 P6 |
| 同一個 group 目錄底下兩個檔案都定義 `dns_zones` 時不會合併，後載入的整個蓋掉前面的；`core-infra-provider-dns-zones.md` 說的「同 group 多檔自動合併」不成立 | §3.5 P1 改成單一檔案；runbook 要改正 |
| resolver 共用 task 的最後一步要求「FreeIPA server FQDN 解析得到」，forward-only 的 tier 主機無法使用它；原本的 role 為了綁 `0.0.0.0:53` 關掉 systemd-resolved stub，再整個改寫 `/etc/resolv.conf` | §2 B9：unbound 只綁 `127.0.0.1` 與服務位址，不動 stub，也不管理 tier 主機自己的 resolver |

probe 的寫法也用同一個拋棄式 unbound 先跑過一次：
- 正常設定下，C2–C8、C10–C14、C18 都得到預期值。
- 把 `domain-insecure`、cache 上限、`hide-identity`、ACL、forward 清單、stub 清單
  分別改壞後，C5、C6、C10–C14、C18 每一列都會 fail。其中 cache 上限有另外單獨
  移除測過，確認 C13、C14 是因為 TTL 超過上限而 fail，不是被別的錯誤連帶。
- C20 對一組沒有 tier 的既有 3 台 vm-target 唯讀執行，結果是 `got=1 want=3`：
  FreeIPA 自己 self-skip，另外兩台被判定不在 tier 上。

## 1. 目標系統與拓樸

| 項目 | 值 |
|---|---|
| Inventory group | `dns`（既有 role，名稱不變） |
| OS | Ubuntu 22.04 / 24.04（沿用既有 role；不支援 EL） |
| 軟體 | unbound（`dns_provider` 只接受 `unbound`） |
| 主機 | **獨立主機**：不可同時屬於 `freeipa-server`、`freeipa-server-replica`（兩者的 named 也要用 port 53，§5 G3） |
| 數量 | sandbox/staging 至少 1 台；**prod 至少 2 台**（§5 G9，§8 A3） |
| 風險等級 | High：tier 會成為 fleet DNS 的第一層 |

```
consumer ──► dns tier（unbound ×N，有 cache）
               ├─ stub-zone <freeipa_domain> + dns_freeipa_zones ──► FreeIPA DNS servers（named）
               ├─ stub-zone dns_stub_zones ──► 其他內部權威 DNS
               ├─ dns_zones（既有的 local-zone / stub_addr，手動編輯）
               └─ forward-zone "." ──► dns_upstream
FreeIPA server/replica：resolver 維持指向自己；forwarders 與 recursion 設定不變
```

## 2. 行為契約

**B1 自動分流。** inventory 裡有 FreeIPA DNS provider（`tasks/freeipa-server-pool.yml`
算出的 server pool 中 `dns_provider` 為真的成員）時，tier 自動進入 `freeipa-split`
模式：小寫正規化後的 `freeipa_domain`（取自 freeipa-server 主機的 hostvars，因為
tier 主機不在 `group_vars/freeipa.yml` 套用的 group 裡），以及 `dns_freeipa_zones`
裡的每個 zone，都以 `stub-zone` 送到**全部** DNS provider。清單用完整 pool，不受
`freeipa_client_topology_mode` 影響，與 resolver 共用 task 的 provider 偵測一致。
沒有 FreeIPA DNS provider 時是 `forward-only`，行為與現在的 role 相同。FreeIPA server
清單不另外發明來源，直接沿用 client HA 已經在用的 server pool（AGENTS.md §5.7 單一來源）。

**B2 用 stub-zone，不用 forward-zone。** stub 送的是 RD=0 查詢，FreeIPA 不需要替
tier 開 recursion，也不可能形成轉發迴圈。

**B3 內部 zone 的兩個 unbound 陷阱都要處理。** DNSSEC 驗證開啟時，每個 stub zone
（FreeIPA 的、`dns_stub_zones` 的、`dns_zones` 的 `stub_addr`）都加
`domain-insecure`。反解 zone 如果落在 unbound 內建的 local zone（RFC1918 反解、
AS112 等）之下，要加 `local-zone: "<zone>" transparent`（或對完全同名的內建 zone
用 `nodefault`），否則查詢不會送出去。

**B4 外部查詢。** `forward-zone "."` 送到 `dns_upstream`（依列出的順序），
不設 `forward-first`：upstream 全掛時回 SERVFAIL，不自己從 root 遞迴。FreeIPA 的
位址不得出現在 `.` 的 forward 清單（C6）。DoT 不在 v1 範圍（§8 A5）。

**B5 Cache 上限。** `cache-max-ttl` = `dns_cache_max_ttl`（預設 300），
`cache-max-negative-ttl` = `dns_cache_max_negative_ttl`（預設 60）。目的是讓
FreeIPA 紀錄新增、刪除、主機 decommission 之後，tier 最多 300 秒內反映，
不需要 reconciler 回頭 flush tier 的 cache。`serve-expired` 保持關閉：FreeIPA
不可達時，tier 不回過期的內部紀錄（AGENTS.md §5.9）。

**B6 DNSSEC。** `dns_dnssec_validation` 預設 `true`。只有 upstream 會剝掉 DNSSEC
紀錄時才設 `false`；開著的時候，apply 會先確認 upstream 有回 RRSIG（§5 G6）。

**B7 ACL。** `access-control` 只允許 `dns_access_control` 列出的 CIDR
（預設 `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`；localhost 是 unbound
預設允許）。`0.0.0.0/0` 與 `::/0` 一律拒絕（§5 G4）。

**B8 Identity。** `hide-identity: no`、`identity: "pilot-dns:<inventory_hostname>"`、
`hide-version: yes`。consumer 與 verify 用 `id.server CH TXT` 判斷回答的是不是 tier。

**B9 監聽位址與 tier 主機自己的 resolver。** unbound 只綁 `127.0.0.1` 與這台主機的
服務位址（B10 的推導），不綁 `0.0.0.0`，所以 systemd-resolved 的 stub
（`127.0.0.53`）可以照常運作。dns role **不管理** tier 主機自己的 resolver：
- resolver baseline（`freeipa-dns-client`、`internal-endpoint` 的全 fleet baseline）
  套到 tier 主機時，tier 主機就是一般 consumer，依 B10 取得 nameserver。只有一支
  playbook 寫 resolver 設定，所以不會互相改寫。
- 舊 role 套用過的主機（`/etc/systemd/resolved.conf` 被整份改寫成
  `DNSStubListener=no`、`/etc/resolv.conf` 指向監聽位址）不做遷移，那份設定在新的
  監聽方式下仍然可用。舊的 unbound 設定片段 `infra-pilot.conf` 由新 playbook 移除，
  否則會跟新設定重複定義 `forward-zone "."`。

**B10 Consumer 契約**（實作在 `tasks/freeipa-dns-client-resolver.yml`，見 §7）：

1. tier 節點的服務位址由一個 tier 與 consumer 共用的 task 檔推導：該主機的
   `dns_listen_addr`（只在 host_vars 覆寫時才有），否則是 `ansible_host`。
2. `freeipa_dns_client_servers` 有明確設定時，維持現行行為，完全以它為準。
3. `dns` group 有主機時，consumer 的 nameserver 依序是各 tier 節點的服務位址（inventory
   順序），不足 3 筆時再補 FreeIPA DNS provider 當最後的 fallback，總數最多 3 筆
   （glibc `MAXNS`）。
4. FreeIPA DNS provider 自己維持現行的 self-first，不改指 tier。
5. `dns` group 沒有主機時，行為與現在完全相同。

**B11 不動 FreeIPA。** FreeIPA 的 forwarders（`freeipa_dns_forwarders`）與
`allow-recursion`（`freeipa_dns_allow_any_recursion`）都不改（使用者決定）。
consumer 在 tier 全掛時 fallback 到 FreeIPA，仍然能解析外部網域。

**B12 非 FreeIPA 的內部 zone。** `dns_stub_zones` 每一筆寫成 `<zone>=<ip>[,<ip>...]`，
該 zone 以 `stub-zone` 送到列出的位址，B3 同樣適用。

## 3. Apply 變數契約

全部放在 `group_vars/dns.yml`（§3.5 P1）。表中標「範例註解」的，是在
`group_vars/dns.example.yml` 以註解形式列出預設值；不設定就用預設。

| 變數 | 型別 / 預設 | 說明 |
|---|---|---|
| `dns_provider` | string，`unbound` | 只接受 `unbound`；其他值 fail-closed。不再寫在 play `vars:` |
| `dns_upstream` | list of IP，`[1.1.1.1]`（範例註解） | 外部 upstream（既有變數，**型別擴充**）：為了相容，字串會以空白或逗號拆開；每一筆必須是 IP（可帶 `@port`），否則 fail-closed（含 `-e dns_upstream=[1.1.1.1]` 被當成字串的陷阱） |
| `dns_freeipa_zones` | list of zone，`[]`（範例註解） | **新增**：除了 `freeipa_domain` 以外，也要送到 FreeIPA 的 zone（反解 zone、freeipa-dns manifest 建的 zone 等） |
| `dns_stub_zones` | list of `zone=ip[,ip]`，`[]`（範例註解） | **新增**：送到其他內部權威 DNS 的 zone（B12） |
| `dns_access_control` | list of CIDR，三段 RFC1918（範例註解） | **新增**：取代寫死在 template 裡的兩行 ACL |
| `dns_cache_max_ttl` | int，`300`（範例註解） | **新增** |
| `dns_cache_max_negative_ttl` | int，`60`（範例註解） | **新增** |
| `dns_dnssec_validation` | bool，`true`（範例註解） | **新增** |
| `dns_listen_addr` | string，不設定 | 既有變數，**語意改變**：只用於單一主機的覆寫，寫在該主機的 host_vars；不設定時服務位址是 `ansible_host`。必須是該主機上的位址，不接受 `0.0.0.0`、`::`（§5 G10） |
| `dns_zones` | list，`[]` | 既有的 local zone / `stub_addr`，**手動編輯**（巢狀結構，§3.5 P2）；不再寫在 play `vars:` |
| `freeipa_domain`、`freeipa_setup_dns`、`freeipa_server_fqdn`、`freeipa_client_topology_mode` | 沿用 | 只讀；經 `tasks/freeipa-server-pool.yml` 推導 FreeIPA DNS provider |

## 3.5 設定介面契約（`pilot edit`）

**P1 單一檔案。** `dns` role 的設定全部放在 `group_vars/dns.yml`，從
`group_vars/dns.example.yml` 建立。pilot 不再建立 `group_vars/dns/` 目錄，
`group_vars/dns/zones.example.yaml` 併入 `dns.example.yml` 的註解範例。

**P2 可編輯。** §3 除了 `dns_zones` 與單機覆寫用的 `dns_listen_addr` 以外，每個
變數都是一行的值或一行的清單（`key: [a, b]`），可以在 `pilot edit` 的 group_vars
編輯器設定、修改、還原成預設。`dns_zones` 是巢狀結構，維持手動編輯；本地紀錄
建議改放 FreeIPA，用 `pilot edit` 既有的 freeipa-dns 畫面管理（§8 A8）。

**P3 舊 workspace 補新設定。** 既有的 `group_vars/dns.yml` 沒有新變數時，
`pilot edit` 開啟該檔要提供「從範例補上缺少的設定」，以註解（= 預設值）形式加入，
不改變既有行為。

**P4 遮蔽偵測。** 任何 group 或 host 同時有 `group_vars/<name>.yml` 與
`group_vars/<name>/`（`host_vars` 同理）時，`pilot inventory lint` 回報 error，
`pilot inventory generate` 與 `pilot edit` 顯示警告，說明 Ansible 只會載入目錄。

**P5 寫入的值就是生效的值。** inventory 提供的設定不准出現在 apply playbook 的 play
`vars:`（AGENTS.md §4.5 第 3 點）。要有一個測試從 `pilot edit` 的真實入口寫入設定，
再用 `ansible-inventory --host` 讀回 Ansible 實際看到的值（AGENTS.md §5.15）。

**P6 範例不會變成真設定。** 範例檔裡的 zone 與位址都是註解；scaffold 出來的
`dns.yml` 在使用者修改前，不會產生任何 local zone 或 stub zone。

verify inputs（§4）是驗收時才給的值，不屬於 `pilot edit` 的範圍。
## 4. Verify inputs

inputs 由 verifier 獨立宣告（`--input`、`--inputs-file`、`PILOT_INPUT_<NAME>`，或
inventory 的 `pilot_inputs`），不從 playbook 讀，避免 spec 跟實作有同一個盲點。
值跟 apply 變數不一致時，對應的 row 會 fail，不會靜默通過。

**所有 input 都是必填**。某個功能沒有使用時，明確填 `none`，不能留空：沒給 input
會讓 verify 在執行前就失敗，所以不會有 row 因為漏給值而被靜默跳過。

| Input | 對應 row | 說明 |
|---|---|---|
| `dns_mode` | C11–C16、C20 的 `appliesWhen` | `freeipa-split` 或 `forward-only` |
| `dns_upstream_servers` | C6 | 預期的 upstream，空白分隔，寫法與 `list_forwards` 印出的一致 |
| `dns_access_control` | C5 | 預期允許的 CIDR，空白分隔 |
| `dns_cache_max_ttl`、`dns_cache_max_negative_ttl` | C10、C13、C14 | |
| `dns_dnssec_validation` | C8、C9 的 `appliesWhen` | |
| `external_probe_name` | C7、C8、C19 | 外部名稱；DNSSEC 開啟時必須是有簽章的名稱（例如 `isc.org`） |
| `freeipa_domain`、`freeipa_dns_server_ips`（空白分隔）、`freeipa_probe_fqdn` | C11–C14、C20 | forward-only 模式填 `none`；split 模式填 `none` 時 probe 印 `missing-input` 並 fail |
| `freeipa_extra_zone_probe_fqdn` | C15 | `dns_freeipa_zones` 裡某個 zone 的 **A record**；沒有額外 zone 時填 `none`（C15 變成 not_applicable） |
| `freeipa_reverse_probe_ip` | C16 | FreeIPA 反解 zone 裡有 PTR 的 IP；沒有反解 zone 時填 `none` |
| `dns_zone_probe_fqdn` | C17 | `dns_zones` 或 `dns_stub_zones` 裡的名稱（取代舊 C7 的 `$DNS_PROBE_NAME`）；都沒有時填 `none` |
| `pilot_inventory_path`、`dns_consumer_pattern` | C20 | inventory 絕對路徑與 consumer 的 Ansible host pattern；forward-only 模式填 `none`，split 模式填 `none` 時 C20 fail |

## 5. Apply-time gates 與 rollback

這些不是 verify row，是 apply playbook 必須做到的失敗行為。每一條都要有 regression
test 的「應該觸發」案例，能在 vm-target 製造的也要實際觸發一次（AGENTS.md §5.12）。

| ID | Gate | 失敗時的行為 |
|---|---|---|
| G1 | stage gates（confirm 旗標、環境 group cross-check、prod attestation，AGENTS.md §4.3） | fail，所有 task 之前，標 `always` |
| G2 | `dns_provider == 'unbound'` | fail |
| G3 | 主機不可同時屬於 `freeipa-server`、`freeipa-server-replica` | fail |
| G4 | 輸入形狀：`dns_upstream` 每筆是 IP 且不為空；`dns_access_control` 每筆是 CIDR，且不含 `0.0.0.0/0`、`::/0`；cache 上限是非負整數；`dns_stub_zones` 每筆是 `zone=ip[,ip]`；zone 名稱合法、小寫正規化後在 auto／`dns_freeipa_zones`／`dns_stub_zones`／`dns_zones` 之間不重複 | fail，寫任何檔案之前 |
| G5 | split 模式：每個導向 FreeIPA 的 zone，對每個 FreeIPA DNS server 送 `+norec SOA` 都要拿到 NOERROR 且帶 `aa` | 真實 run：fail，不改設定。check mode 在 FreeIPA 尚未存在的全新 target 上：印出明確訊息後 `meta: end_host`（AGENTS.md §4.5 第 4 點） |
| G6 | 每個 upstream 回應 `. NS`；DNSSEC 開啟時，`+dnssec . DNSKEY` 要有 RRSIG | fail，訊息提示可設 `dns_dnssec_validation: false` |
| G7 | 新設定先跑 `unbound-checkconf`，通過才取代線上設定 | fail，線上設定與服務都不變 |
| G8 | 重啟後自我檢查：外部 `. NS`，split 模式再加 `SOA <freeipa_domain>`，都要從本機解析成功 | rescue 還原舊設定並重啟，再 fail；訊息如實說明還原有沒有成功（AGENTS.md §4.5 第 7 點） |
| G9 | `stage=prod` 時 `dns` group 至少 2 台 | fail |
| G10 | 服務位址（B10）是這台主機上的 IPv4 位址，且不是 `0.0.0.0` | fail，寫任何檔案之前；訊息說明要移除 group_vars 裡共用的 `dns_listen_addr` |

## Checks

```yaml
- id: C1
  category: package
  check: unbound and bind9-dnsutils (dig, used by the self-check and these probes) are installed
  probe: |
    out=""
    for p in unbound bind9-dnsutils; do
      if [ "$(dpkg-query -W -f='${Status}' "$p" 2>/dev/null)" = "install ok installed" ]; then out="$out $p=installed"; else out="$out $p=missing"; fi
    done
    echo $out
  expect: {stdout: {equals: unbound=installed bind9-dnsutils=installed}}
  tags: [dns-C1]
- id: C2
  category: service
  check: unbound.service is active and its control channel answers
  probe: |
    s=$(systemctl is-active unbound 2>&1)
    c=$(unbound-control status 2>&1 | grep -c 'is running')
    echo "service=$s control=$c"
  expect: {stdout: {equals: service=active control=1}}
  tags: [dns-C2]
- id: C3
  category: config
  check: the effective unbound configuration passes unbound-checkconf
  probe: |
    if out=$(unbound-checkconf 2>&1); then echo valid; else printf '%s\n' "$out" | sed -n 1p; fi
  expect: {stdout: {equals: valid}}
  tags: [dns-C3]
- id: C4
  category: listen
  check: unbound itself owns UDP and TCP port 53 on at least one non-loopback address
  probe: |
    cnt() { ss -H -ln"$1"p 'sport = :53' 2>/dev/null | awk '/"unbound"/ && $4 !~ /^(127\.|\[::1\]|::1)/ {n++} END {print n+0}'; }
    echo "udp=$(cnt u) tcp=$(cnt t)"
  expect: {stdout: {regex: '^udp=[1-9][0-9]* tcp=[1-9][0-9]*$'}}
  tags: [dns-C4]
- id: C5
  category: acl
  check: every dns_access_control CIDR is allowed and no allow-all entry exists
  probe: |
    [ -n "$PILOT_VAR_DNS_ACCESS_CONTROL" ] || { echo missing-input; exit 0; }
    acl=$(unbound-control get_option access-control 2>/dev/null)
    missing=""
    for c in $PILOT_VAR_DNS_ACCESS_CONTROL; do
      printf '%s\n' "$acl" | grep -qxF "$c allow" || missing="$missing $c"
    done
    open=$(printf '%s\n' "$acl" | grep -cE '^(0\.0\.0\.0/0|::/0) allow')
    if [ -z "$missing" ] && [ "$open" = 0 ]; then echo acl-ok; else echo "acl-bad missing=$missing open=$open"; fi
  expect: {stdout: {equals: acl-ok}}
  tags: [dns-C5]
- id: C6
  category: forward
  check: the root forward zone sends exactly dns_upstream_servers and never a FreeIPA DNS server
  probe: |
    [ -n "$PILOT_VAR_DNS_UPSTREAM_SERVERS" ] || { echo missing-input; exit 0; }
    got=$(unbound-control list_forwards 2>/dev/null | awk '$1=="." && $3=="forward" {for (i=4;i<=NF;i++) if ($i !~ /^\+/) print $i}' | sort -u)
    want=$(printf '%s\n' $PILOT_VAR_DNS_UPSTREAM_SERVERS | sort -u)
    leak=""
    for ip in $PILOT_VAR_FREEIPA_DNS_SERVER_IPS; do
      [ "$ip" = none ] && continue
      printf '%s\n' "$got" | grep -qxF "$ip" && leak="$leak $ip"
    done
    if [ -n "$got" ] && [ "$got" = "$want" ] && [ -z "$leak" ]; then echo forward-ok; else echo "forward-bad got=$(echo $got) want=$(echo $want) leak=$leak"; fi
  expect: {stdout: {equals: forward-ok}}
  tags: [dns-C6]
- id: C7
  category: external
  check: an external name resolves through the tier with NOERROR and at least one answer
  probe: |
    r=$(dig +time=3 +tries=2 +noall +comments +answer @127.0.0.1 "$PILOT_VAR_EXTERNAL_PROBE_NAME" A)
    st=$(printf '%s\n' "$r" | sed -n 's/.*status: \([A-Z]*\),.*/\1/p')
    n=$(printf '%s\n' "$r" | awk '$3=="IN" && ($4=="A" || $4=="CNAME") {n++} END {print n+0}')
    echo "status=$st answers=$n"
  expect: {stdout: {regex: '^status=NOERROR answers=[1-9][0-9]*$'}}
  verifyOnly: true
- id: C8
  category: dnssec
  check: with validation enabled, the validator module is loaded and a signed external answer carries the ad flag
  probe: |
    mc=$(unbound-control get_option module-config 2>/dev/null)
    fl=$(dig +time=3 +tries=2 +dnssec +noall +comments @127.0.0.1 "$PILOT_VAR_EXTERNAL_PROBE_NAME" SOA | sed -n 's/^;; flags: \([^;]*\);.*/\1/p')
    case " $mc " in *" validator "*) v=on ;; *) v=off ;; esac
    case " $fl " in *" ad "*) ad=yes ;; *) ad=no ;; esac
    echo "validator=$v ad=$ad"
  expect: {stdout: {equals: validator=on ad=yes}}
  appliesWhen:
    all:
      - input: {name: dns_dnssec_validation, operator: equals, value: "true"}
  tags: [dns-C8]
- id: C9
  category: dnssec
  check: with validation disabled, the validator module is not loaded
  probe: |
    mc=$(unbound-control get_option module-config 2>/dev/null)
    [ -n "$mc" ] || { echo control-error; exit 0; }
    case " $mc " in *" validator "*) echo validator=on ;; *) echo validator=off ;; esac
  expect: {stdout: {equals: validator=off}}
  appliesWhen:
    all:
      - input: {name: dns_dnssec_validation, operator: equals, value: "false"}
  tags: [dns-C9]
- id: C10
  category: cache
  check: the running cache-max-ttl and cache-max-negative-ttl equal the declared caps
  probe: |
    mx=$(unbound-control get_option cache-max-ttl 2>/dev/null)
    ng=$(unbound-control get_option cache-max-negative-ttl 2>/dev/null)
    if [ -n "$mx" ] && [ "$mx" = "$PILOT_VAR_DNS_CACHE_MAX_TTL" ] && [ "$ng" = "$PILOT_VAR_DNS_CACHE_MAX_NEGATIVE_TTL" ]; then echo caps-ok; else echo "caps-bad max=$mx neg=$ng"; fi
  expect: {stdout: {equals: caps-ok}}
  tags: [dns-C10]
- id: C11
  category: split
  check: the FreeIPA domain is a stub zone pointing at exactly the FreeIPA DNS servers
  probe: |
    case "$PILOT_VAR_FREEIPA_DOMAIN $PILOT_VAR_FREEIPA_DNS_SERVER_IPS" in *none*) echo missing-input; exit 0 ;; esac
    z=$(printf '%s.' "$PILOT_VAR_FREEIPA_DOMAIN" | tr 'A-Z' 'a-z')
    got=$(unbound-control list_stubs 2>/dev/null | awk -v z="$z" '$1==z && $3=="stub" {for (i=4;i<=NF;i++) if ($i!="prime" && $i!="noprime" && $i !~ /^\+/) print $i}' | sort -u)
    want=$(printf '%s\n' $PILOT_VAR_FREEIPA_DNS_SERVER_IPS | sort -u)
    if [ -n "$got" ] && [ "$got" = "$want" ]; then echo stub-ok; else echo "stub-bad got=$(echo $got) want=$(echo $want)"; fi
  expect: {stdout: {equals: stub-ok}}
  appliesWhen:
    all:
      - input: {name: dns_mode, operator: equals, value: freeipa-split}
  tags: [dns-C11]
- id: C12
  category: split
  check: an internal A record answered through the tier equals the FreeIPA authoritative answer
  probe: |
    case "$PILOT_VAR_FREEIPA_PROBE_FQDN $PILOT_VAR_FREEIPA_DNS_SERVER_IPS" in *none*) echo missing-input; exit 0 ;; esac
    ipa=$(printf '%s\n' $PILOT_VAR_FREEIPA_DNS_SERVER_IPS | sed -n 1p)
    t=$(dig +time=3 +tries=2 +noall +answer @127.0.0.1 "$PILOT_VAR_FREEIPA_PROBE_FQDN" A | awk '$4=="A" {print $5}' | sort)
    a=$(dig +time=3 +tries=2 +norec +noall +answer @"$ipa" "$PILOT_VAR_FREEIPA_PROBE_FQDN" A | awk '$4=="A" {print $5}' | sort)
    if [ -n "$t" ] && [ "$t" = "$a" ]; then echo match; else echo "mismatch tier=$(echo $t) freeipa=$(echo $a)"; fi
  expect: {stdout: {equals: match}}
  appliesWhen:
    all:
      - input: {name: dns_mode, operator: equals, value: freeipa-split}
  verifyOnly: true
- id: C13
  category: split
  check: FreeIPA Kerberos and LDAP SRV records resolve through the tier with TTL at or below dns_cache_max_ttl
  probe: |
    [ "$PILOT_VAR_FREEIPA_DOMAIN" != none ] || { echo missing-input; exit 0; }
    out=""
    for s in _kerberos._udp _ldap._tcp; do
      r=$(dig +time=3 +tries=2 +noall +answer @127.0.0.1 "$s.$PILOT_VAR_FREEIPA_DOMAIN" SRV | awk -v cap="$PILOT_VAR_DNS_CACHE_MAX_TTL" '$4=="SRV" {n++; if (cap+0 < $2+0) o++} END {print n+0 ":" o+0}')
      out="$out $s=$r"
    done
    echo $out
  expect: {stdout: {regex: '^_kerberos\._udp=[1-9][0-9]*:0 _ldap\._tcp=[1-9][0-9]*:0$'}}
  appliesWhen:
    all:
      - input: {name: dns_mode, operator: equals, value: freeipa-split}
  verifyOnly: true
- id: C14
  category: split
  check: a nonexistent internal name returns NXDOMAIN carrying the FreeIPA SOA with TTL at or below dns_cache_max_negative_ttl
  probe: |
    case "$PILOT_VAR_FREEIPA_DOMAIN $PILOT_VAR_FREEIPA_DNS_SERVER_IPS" in *none*) echo missing-input; exit 0 ;; esac
    ipa=$(printf '%s\n' $PILOT_VAR_FREEIPA_DNS_SERVER_IPS | sed -n 1p)
    n="pilot-dns-nx-$(date +%s)-$$.$PILOT_VAR_FREEIPA_DOMAIN"
    r=$(dig +time=3 +tries=2 +noall +comments +authority @127.0.0.1 "$n" A)
    st=$(printf '%s\n' "$r" | sed -n 's/.*status: \([A-Z]*\),.*/\1/p')
    ttl=$(printf '%s\n' "$r" | awk '$4=="SOA" {print $2; exit}')
    mname=$(printf '%s\n' "$r" | awk '$4=="SOA" {print tolower($5); exit}')
    want=$(dig +time=3 +tries=2 +norec +noall +answer @"$ipa" "$PILOT_VAR_FREEIPA_DOMAIN" SOA | awk '$4=="SOA" {print tolower($5); exit}')
    if [ "$st" = NXDOMAIN ] && [ -n "$want" ] && [ "$mname" = "$want" ] && [ -n "$ttl" ] && [ "$ttl" -le "$PILOT_VAR_DNS_CACHE_MAX_NEGATIVE_TTL" ]; then echo nxdomain-from-freeipa; else echo "bad status=$st mname=$mname want=$want ttl=$ttl"; fi
  expect: {stdout: {equals: nxdomain-from-freeipa}}
  appliesWhen:
    all:
      - input: {name: dns_mode, operator: equals, value: freeipa-split}
  verifyOnly: true
- id: C15
  category: split
  check: an A record in a dns_freeipa_zones zone answered through the tier equals the FreeIPA authoritative answer
  probe: |
    [ "$PILOT_VAR_FREEIPA_DNS_SERVER_IPS" != none ] || { echo missing-input; exit 0; }
    ipa=$(printf '%s\n' $PILOT_VAR_FREEIPA_DNS_SERVER_IPS | sed -n 1p)
    t=$(dig +time=3 +tries=2 +noall +answer @127.0.0.1 "$PILOT_VAR_FREEIPA_EXTRA_ZONE_PROBE_FQDN" A | awk '$4=="A" {print $5}' | sort)
    a=$(dig +time=3 +tries=2 +norec +noall +answer @"$ipa" "$PILOT_VAR_FREEIPA_EXTRA_ZONE_PROBE_FQDN" A | awk '$4=="A" {print $5}' | sort)
    if [ -n "$t" ] && [ "$t" = "$a" ]; then echo match; else echo "mismatch tier=$(echo $t) freeipa=$(echo $a)"; fi
  expect: {stdout: {equals: match}}
  appliesWhen:
    all:
      - input: {name: dns_mode, operator: equals, value: freeipa-split}
      - input: {name: freeipa_extra_zone_probe_fqdn, operator: notEquals, value: none}
  verifyOnly: true
- id: C16
  category: split
  check: a PTR record in a FreeIPA reverse zone answered through the tier equals the FreeIPA authoritative answer
  probe: |
    [ "$PILOT_VAR_FREEIPA_DNS_SERVER_IPS" != none ] || { echo missing-input; exit 0; }
    ipa=$(printf '%s\n' $PILOT_VAR_FREEIPA_DNS_SERVER_IPS | sed -n 1p)
    t=$(dig +time=3 +tries=2 +noall +answer @127.0.0.1 -x "$PILOT_VAR_FREEIPA_REVERSE_PROBE_IP" | awk '$4=="PTR" {print tolower($5)}' | sort)
    a=$(dig +time=3 +tries=2 +norec +noall +answer @"$ipa" -x "$PILOT_VAR_FREEIPA_REVERSE_PROBE_IP" | awk '$4=="PTR" {print tolower($5)}' | sort)
    if [ -n "$t" ] && [ "$t" = "$a" ]; then echo match; else echo "mismatch tier=$(echo $t) freeipa=$(echo $a)"; fi
  expect: {stdout: {equals: match}}
  appliesWhen:
    all:
      - input: {name: dns_mode, operator: equals, value: freeipa-split}
      - input: {name: freeipa_reverse_probe_ip, operator: notEquals, value: none}
  verifyOnly: true
- id: C17
  category: zones
  check: a name configured through dns_zones or dns_stub_zones resolves through the tier with NOERROR and at least one answer
  probe: |
    r=$(dig +time=3 +tries=2 +noall +comments +answer @127.0.0.1 "$PILOT_VAR_DNS_ZONE_PROBE_FQDN" A)
    st=$(printf '%s\n' "$r" | sed -n 's/.*status: \([A-Z]*\),.*/\1/p')
    n=$(printf '%s\n' "$r" | awk '$3=="IN" && ($4=="A" || $4=="CNAME") {n++} END {print n+0}')
    echo "status=$st answers=$n"
  expect: {stdout: {regex: '^status=NOERROR answers=[1-9][0-9]*$'}}
  appliesWhen:
    all:
      - input: {name: dns_zone_probe_fqdn, operator: notEquals, value: none}
  verifyOnly: true
- id: C18
  category: identity
  check: the tier answers id.server CH TXT with its pilot-dns identity
  probe: |
    dig +time=2 +tries=1 +short @127.0.0.1 id.server CH TXT 2>&1
  expect: {stdout: {regex: '^"pilot-dns:[^"]+"$'}}
  tags: [dns-C18]
- id: C19
  category: resolver
  check: the tier host's own name resolution still works after apply (the dns role leaves the systemd-resolved stub and the host resolver alone)
  probe: |
    if g=$(getent hosts "$PILOT_VAR_EXTERNAL_PROBE_NAME" 2>&1); then echo resolves; else echo "broken getent=$g"; fi
  expect: {stdout: {equals: resolves}}
  verifyOnly: true
- id: C20
  category: consumer
  check: every consumer host matching dns_consumer_pattern resolves through the tier first, via both /etc/resolv.conf and systemd-resolved (FreeIPA DNS providers self-skip)
  probe: |
    case "$PILOT_VAR_PILOT_INVENTORY_PATH $PILOT_VAR_DNS_CONSUMER_PATTERN $PILOT_VAR_FREEIPA_PROBE_FQDN" in *none*) echo missing-input; exit 0 ;; esac
    cmd=$(sed "s/@FQDN@/$PILOT_VAR_FREEIPA_PROBE_FQDN/" <<'EOF'
    if systemctl is-active -q named 2>/dev/null; then echo provider-skip; exit 0; fi
    ns=$(awk '$1=="nameserver" {print $2; exit}' /etc/resolv.conf)
    id=$(dig +time=2 +tries=1 +short @"$ns" id.server CH TXT 2>/dev/null)
    case "$id" in '"pilot-dns:'*) ;; *) echo "not-tier ns=$ns"; exit 3 ;; esac
    if systemctl is-active -q systemd-resolved 2>/dev/null; then
      rs=$(resolvectl dns 2>/dev/null | awk -F': ' '$1=="Global" {split($2, a, " "); print a[1]}')
      rid=$(dig +time=2 +tries=1 +short @"$rs" id.server CH TXT 2>/dev/null)
      case "$rid" in '"pilot-dns:'*) ;; *) echo "resolved-not-tier rs=$rs"; exit 5 ;; esac
    fi
    g=$(getent hosts @FQDN@) || { echo nss-fail; exit 4; }
    echo tier-ok
    EOF
    )
    got=$(ansible "$PILOT_VAR_DNS_CONSUMER_PATTERN" -i "$PILOT_VAR_PILOT_INVENTORY_PATH" -m shell -a "$cmd" 2>&1 | grep -c '| rc=0')
    want=$(ansible "$PILOT_VAR_DNS_CONSUMER_PATTERN" -i "$PILOT_VAR_PILOT_INVENTORY_PATH" --list-hosts 2>/dev/null | tail -n +2 | wc -l)
    if [ "$want" -gt 0 ] && [ "$got" = "$want" ]; then echo "all $want consumers on tier"; else echo "got=$got want=$want"; fi
  expect: {stdout: {regex: '^all [1-9][0-9]* consumers on tier$'}}
  scope: aggregate
  become: false
  timeout: 120s
  appliesWhen:
    all:
      - input: {name: dns_mode, operator: equals, value: freeipa-split}
  verifyOnly: true
```

## PASS / FAIL

所有適用的 row 都 pass 才算 PASS。`appliesWhen` 不成立的 row 是 `not_applicable`，
不影響結果。分流相關的 row 由 `dns_mode` 決定是否適用；C15–C17 只在對應 input
不是 `none` 時適用。input 一律必填，所以不會因為漏給值而靜默跳過；split 模式下
必要的 input 填了 `none`，probe 印 `missing-input` 並 fail。unresolved host、
runner error、timeout、matcher 不符都算 FAIL。

## Traceability

- 有 tag 的 row（`dns-C1`–`C6`、`C8`–`C11`、`C18`）各自對應 apply playbook 中產生
  該狀態的 task；task 的 tag 要能用 `--tags dns-Cn` 單獨重跑。
- `verifyOnly` 的 row（C7、C12–C17、C19）是 C6、C8、C10、C11 與 zone 設定組合出的
  端到端行為；`contracts/dns.yaml` 的 traceability exemptions 要逐一登記
  （`derived` 指向對應 tag，或 `verifyOnly` 附理由）。
- C20 驗的是 consumer 端，由 `tasks/freeipa-dns-client-resolver.yml` 實作（B10），
  不屬於 `dns` 的 apply playbook，所以是 `verifyOnly`；consumer 端自己的 row 仍在
  `freeipa-dns-client.md`。

## 6. 證據計畫（尚未執行）

完整輸出放 `.verification/` 或 pilot evidence store；提交的只有
`docs/evidence/dns/<date>-<tested-revision>.md` 的 sanitized 摘要（AGENTS.md §1.2）。
正式 run 依 §1.5 對 candidate commit 執行。

- **E1 全新拓樸**：`vm-target topology test --ephemeral`，至少包含 FreeIPA server
  （AlmaLinux 9，`--setup-dns`）、2 台 `dns`（Ubuntu 24.04）、1 台 Ubuntu
  `freeipa-dns-client`；能負擔的話再加 1 台 AlmaLinux consumer 涵蓋 NetworkManager
  路徑。L3 check mode → snapshot → apply → verify → L6 `changed=0`。
- **E2 反解 zone 前置**：freeipa-dns manifest 目前禁止 `in-addr.arpa.`，C16 需要的
  反解 zone 與 PTR 用 `playbooks/test/fixtures/dns-fixtures.yml`（AGENTS.md §4.1）
  在 FreeIPA server 上建立。
- **E3 tier 主機也是 consumer**：讓其中一台 tier 主機同時屬於 `freeipa-dns-client`，
  依序跑 `dns` apply → resolver baseline → `dns` apply，兩支都要 `changed=0`（B9）。
- **E4 gate 真的會觸發**：至少實際觸發 G5（`dns_freeipa_zones` 放一個 FreeIPA 沒有的
  zone）、G6（一個不可達的 upstream）、G8（讓重啟後的自我檢查失敗，確認 rescue
  還原且訊息如實）、G10（group_vars 裡留著共用的 `dns_listen_addr`）。
- **E5 cache 上限的實際效果**：先查一個不存在的內部名稱，接著在 FreeIPA 建立它，
  確認 `dns_cache_max_negative_ttl` 秒內可以從 tier 解析到。
- **E6 tier 容錯**：停掉其中一台 tier 的 unbound，consumer 仍能解析，並記錄延遲。
- **E7 `pilot edit` round-trip**（Go 測試，§3.5 P5）：從 `pilot edit` 的真實入口設定
  §3 每一個可編輯變數，再用 `ansible-inventory --host` 讀回生效值；另測 P3 補設定、
  P4 遮蔽偵測、P6 scaffold 不產生 zone。
- **E8 用 `pilot edit` 寫出的 workspace 實跑**：E1 的 `dns` 設定由 `pilot edit` 寫進
  workspace 的 `group_vars/dns.yml`，playbook 透過 inventory 旁的 group_vars 自動載入
  （不是用 `-e` 傳），證明 P1、P5 在真機上成立。
- inputs 的傳法：`vm-target topology test` 沒有 `--input`，verify 子行程會繼承
  `PILOT_INPUT_<NAME>` 環境變數。C20 需要的 `pilot_inventory_path` 是測試中途才寫出
  的暫存 inventory，由 `topology test` 在 verify 期間自動填入（操作者自己設定時以
  操作者為準）。
- `--ephemeral` 的限制：FreeIPA 的 IP、反解要查的 IP、`dns_stub_zones` 的位址都要等
  VM 拿到 DHCP 位址才知道，`--ephemeral` 無法事先提供這些 inputs 與設定。因此 E1 的
  做法是先 `topology up` 建立全新 VM，用 `pilot edit` 寫好 workspace，再對尚未套用過
  任何設定的 VM 跑 `topology test`（L3 check mode 仍然是在全新主機上執行，失敗時
  自動 rollback）。

## 7. 配套變更（同一個 delivery bundle）

1. `dns` 從 `core-infra-provider-apply.yml` 拆成 `playbooks/apply/dns-apply.yml`
   （比照 2026-07-17 拆 docker）；`core-infra-provider-apply.yml` 與
   `core-infra-provider.md` 只留 NTP，`core_infra_provider_regression_test.go` 同步改。
2. `contracts/dns.yaml`：spec 改指本檔、apply 改指 `dns-apply.yml`、`conflicts` 加
   `freeipa-server`／`freeipa-server-replica`、`groupVars` 依 §3 更新、traceability
   exemptions；`site.order` 移到 `freeipa-server`（40）之後，因為 G5 需要 FreeIPA 已經
   在服務。
3. `playbooks/site.yml` 的 import 位置、`cmd/pilot/cmd/deploy_catalog.go`、
   `internal/inventory/contracts.go` 的描述、`inventory.example.yml`。
4. 新增 tier 與 consumer 共用的服務位址推導 task 檔；`tasks/freeipa-dns-client-resolver.yml`
   依 B10 優先指向 tier。`freeipa-dns-client.md` §1.5 的自動偵測說明、
   `internal-endpoint.md` C9 的說明要同步改，兩者的 regression test 與 evidence 要重跑。
5. 設定介面（§3.5）：`group_vars/dns.example.yml` 改寫並併入 `zones.example.yaml`
   的內容；移除 `group_vars/dns/zones.example.yaml` 與 nested group_vars 範例的
   scaffold；`.gitignore` 相關規則；group_vars 編輯器的「從範例補上缺少的設定」；
   `group_vars`／`host_vars` 遮蔽偵測。
6. 新增 `internal/spec/dns_regression_test.go`（row 連號、inputs、tags、G2–G10 的
   「應該觸發」案例）、`cmd/pilot/cmd/tag_coverage_test.go` 的 `specTagMap`，以及
   E7 的 `pilot edit` round-trip 測試。
7. 新增 `docs/runbooks/dns.md`（含 AGENTS.md §2 的事實快照），並改正
   `docs/runbooks/core-infra-provider-dns-zones.md`（多檔合併的說法、目錄配置）。
8. AGENTS.md §4.3 的 apply playbook 清點加上 `dns-apply.yml`。
9. restic 備份範圍（AGENTS.md §4.2）不需要改：tier 只寫 `/etc`。

## 8. 假設、未知項與非目標

需要使用者確認的假設：

- **A1** Ubuntu 22.04/24.04 的 unbound 套件預設開啟 DNSSEC 驗證（root trust
  anchor）並可用 `unbound-control`。目前只在 unbound 1.24.2 上測過行為，目標版本要在
  E1 確認；預設沒有開的部分由 playbook 補上。
- **A2** cache 上限預設 300／60 秒。
- **A3** prod 至少 2 台 tier（G9）。
- **A4** consumer 的 nameserver 順序是「tier 在前，不足 3 筆再補 FreeIPA」（B10）。
- **A5** v1 不做 DNS-over-TLS upstream。
- **A6** playbook 拆成 `dns-apply.yml`，並把 site 順序移到 FreeIPA server 之後。
- **A7** dns role 不管理 tier 主機自己的 resolver（B9）。
- **A8** `dns_zones` 維持手動編輯；需要用 `pilot edit` 管理的本地紀錄放到 FreeIPA。

未知項：

- glibc 預設 `timeout:5`，第一台 tier 掛掉時，走 glibc resolver 的 consumer
  （主要是 EL）每次查詢會多等最多 5 秒。是否要在 resolver baseline 加
  `options timeout:1 attempts:2`，會改變所有 `freeipa-dns-client` 主機的輸出，
  留待決定。
- IPv6：ACL 與 upstream 允許填 IPv6，但 E1 只涵蓋 IPv4；G10 只接受 IPv4 服務位址。

非目標：FreeIPA 的 forwarders 與 recursion 設定（B11）、reconciler 主動 flush tier
cache、VIP／keepalived、EL tier 主機、DNS64、tier 的 metrics exporter（之後可接
`host-monitoring`）、`dns_zones` 的結構化編輯畫面。

破壞性邊界：apply 會改寫 tier 主機的 unbound 設定並重啟 unbound。設定錯誤時，
G7／G8 讓 tier 保持或還原到舊設定。consumer 端的變更會改寫每台 consumer 的
resolver，沿用 `freeipa-dns-client` 既有的 snapshot 與 rollback。

## 9. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|---|---|---|---|
| 2026-10-01 | DRAFT v0.1 | 初版 spec-first 草稿：擴充既有 `dns` role 成 FreeIPA 前的第一層快取 DNS（自動分流、cache 上限、DNSSEC、ACL、identity、consumer 契約）；尚未有 apply playbook 與實跑證據 | sre |
| 2026-10-01 | DRAFT v0.2 | 納入 `pilot edit` 設定介面契約（§3.5）與三個既有 bug；新增 `dns_stub_zones`、G10；B9 改成「只綁 `127.0.0.1` 與服務位址、不管理 tier 主機自己的 resolver」（原 v0.1 要求 tier 主機優先指向自己，但 resolver 共用 task 需要 FreeIPA，且兩支 playbook 會搶同一份設定），C19 隨之改成驗證 tier 主機自己的解析沒有被破壞；G3 不再排除 `freeipa-dns-client` | sre |
