# Runbook — DNS 架構診斷（`pilot_diagnose_dns_architecture`）

> 對應 issue：#62
> 程式：`cmd/pilot/cmd/mcp_diagnose_dns_architecture.go`、`internal/diagnose/dns_architecture*.go`
> 對照的 playbook 規則：`playbooks/apply/dns-apply.yml`、`playbooks/apply/tasks/freeipa-server-pool.yml`、
> `playbooks/apply/tasks/dns-tier-endpoints.yml`、`playbooks/apply/tasks/freeipa-dns-client-resolver.yml`、
> `playbooks/apply/freeipa-server-apply.yml`、`playbooks/apply/freeipa-server-replica-apply.yml`
> 維護者：sre

## 0. 一句話目標

用一次唯讀的 MCP 呼叫回答「這套環境的 DNS 怎麼接的」：dns tier、FreeIPA DNS
（primary/replica、FQDN、zone）、FreeIPA 的 forwarding，以及每台受管主機的 resolver
路徑；宣告值、推導值與實際狀態分開列，不一致的地方附證據。

## 0.5 目前有效的事實快照

最新驗證：2026-10-16，candidate `cdcd39b`（tree `422ca9ec8272a5e0a709991d7a5407eba117d3ff`，PR #92 修正 replica forwarder 的 kinit、與 `main` `f98327b` 合併後），
在新建的 6 台 topology 上，**PASS**；run ID、UTC 時段、target image digest、套件版本與 inventory 指紋都在執行當下記錄。摘要：
[`docs/evidence/freeipa-replica-dns-provider/2026-10-16-cdcd39b.md`](../evidence/freeipa-replica-dns-provider/2026-10-16-cdcd39b.md)。
#91 的情境（tier 拒絕 client、`freeipa_server_fqdn` 帶結尾的點、`K/M`／`k` principal、stub 與 FreeIPA BIND 當第一跳）也在這個 candidate 上重跑。
更早幾輪（不同 candidate，僅供歷史參考）：[`2026-10-15-46fbc58.md`](../evidence/dns-architecture-diagnose/2026-10-15-46fbc58.md)、
[`2026-10-14-46fbc58.md`](../evidence/dns-architecture-diagnose/2026-10-14-46fbc58.md)、
[`2026-10-14-8951d2e.md`](../evidence/dns-architecture-diagnose/2026-10-14-8951d2e.md)、
[`2026-10-14-e862f1d.md`](../evidence/dns-architecture-diagnose/2026-10-14-e862f1d.md)。

| 項目 | 事實 |
|---|---|
| 目標環境 | `pilot vm-target topology`，6 台由 `topology up` 新建的 VM：`pr92-ipa`、`pr92-r1`、`pr92-r2`、`pr92-r3`（AlmaLinux 9.8，與先前 record 相同的 base image digest；`pr92-ipa` 為 ipa-server 4.13.4-1.el9_8，其他節點的套件版本這次沒有記錄；`pr92-r3` 列在 inventory，最後才 promote）、`pr92-dns`（Ubuntu 24.04.4，unbound 1.19.2-1ubuntu3.10）、`pr92-client`（Ubuntu 24.04.4）；由 candidate 的 playbook 部署，測完已移除 |
| inventory host 集合 | `freeipa-server`: pr92-ipa；`freeipa-server-replica`: pr92-r1、pr92-r2、pr92-r3（都不設 `freeipa_setup_dns`）；`dns`: pr92-dns；`freeipa-dns-client`: pr92-client |
| 外部 state | `~/.vault/main.yaml` 的 `ipa_admin_password`（只給 FreeIPA 安裝、§2 的唯讀 principal 設定）；`pr92-ipa` 的 `/etc/pilot/dns-reader.keytab` |
| 結果 | 透過真實 `pilot mcp serve` 呼叫：健康時 `complete`、14 項比對全部 `match`，沒 promote 的 `pr92-r3` 只有 `freeipa_replica_not_dns_server`（同一 tree 拿掉「跳過被排除的 replica」這一行的對照 binary：`partial`，`pr92-r3` 被報成 `unknown`）；stub 或 FreeIPA BIND 當第一跳時沒有第一跳誤報；tier 拒絕 client 時回報 `dns_query_failed: … first_hop_identity (… REFUSED)`；`freeipa_server_fqdn` 帶結尾的點時 `complete`；`K/M` 在啟動時被拒、`k` 被接受（`auth_required`）；promote 之後 17/17 |
| 對齊決定 | 不需要：這個工具不對應 verification spec，也不寫 inventory |

## 1. 為什麼

- 回答「FreeIPA DNS 怎麼接、有沒有 forwarding、內部網域是不是送到 FreeIPA」原本要
  串 workspace inspect、好幾次 DNS/raw 指令，再讀 contract 與 playbook；宣告與實際
  很容易混在一起，沒有 Kerberos 時也說不清楚哪些是未知。
- 這個工具分四層回答：
  - `supported`：component contract 提供什麼（`dns`、`freeipa-server`、
    `freeipa-server-replica`、`freeipa-dns-client`、`internal-endpoint`、
    `freeipa-dns`），inventory 有沒有指派、最近一次 delivery 紀錄。
  - `declared`：inventory 實際寫了哪些相關變數（`inventory:hostvars[<host>].<var>`）。
  - `effective`：playbook 的規則把這些值算成什麼（tier 模式、stub/forward zone、
    FreeIPA server pool、forwarders、每台主機的 resolver 清單）。這份規則是 Go
    複本；`internal/diagnose/dns_architecture_playbook_test.go` 會用 ansible-playbook
    跑上面列的 playbook task 本身，結果不同就 fail，所以 playbook 仍是唯一來源。
  - `observed`：固定的唯讀 probe（每台 FreeIPA DNS provider 的權威 SOA/NS/SRV，
    每台 tier 的 unbound forward/stub zone、內外部解析與對 FreeIPA 的 G5 探測，
    指定的 `client_host` 的 resolver）。
- `differences` 逐項比對 effective 與 observed，`evidence` 指到 inventory 變數與
  這次呼叫的 step（`step:<step id>#<section>`，audit record 裡有原始指令與輸出）。
  `unknown`（看不到）與 `absent`（看到了，沒有）不合併。
- 經 tier 解析外部名稱成功（NOERROR 且有紀錄），只代表 tier 解析得到，不代表是某個
  forwarder 回答的；工具只回報「設定的 forward zone」與「解析結果」，並以 finding
  `external_resolution_forwarder_unproven` 標明。tier 有回應但回 SERVFAIL、REFUSED 或
  查無此名稱，是解析失敗（事實狀態 `error`／`absent`，finding
  `external_resolution_failed`）；沒有任何回應（連線被拒、逾時）是看不到（`unknown`，
  finding `external_resolution_unknown`，`status` 為 `partial`）。

## 2. 準備唯讀 principal（每個 realm 做一次）

FreeIPA 的 DNS 設定（global forwarders、forward policy、各 server 的 forwarders、
forward zone、zone 清單）要有 Kerberos ticket 才讀得到。工具只用操作者事先核准的
唯讀 principal：不收密碼、不使用主機預設 credential cache 裡現有的 ticket（部署後
root 的預設 cache 可能留著 `admin` 的 ticket，工具不會碰它）。`admin`、`administrator`、
`root`，以及 FreeIPA 自己的 service principal（`host/`、`HTTP/`、`ldap/`、`DNS/`、
`ipa-dnskeysyncd/`、`krbtgt/` 等，這些 keytab 能改目錄或 DNS 資料）在啟動時就被拒絕；
principal 的每一段都要以英數字開頭，不能被 `kinit` 當成選項（例如 `-c/tmp@REALM`
會變成指定 ccache）。讀取時 `--rights` 顯示這個 principal 對全域 DNS 設定（`cn=dns`，
`ipa dnsconfig-show`）有任何寫入權限（`w`、`o`）時，工具不採用它讀到的任何內容，Kerberos
狀態是 `refused_privileged`、status 是 `auth_required`，finding
`freeipa_principal_not_read_only`。工具只檢查這一個 entry 的權限：只能改 zone 或 record
（`idnsname=*`）、或能改 DNS 以外資料的 role 不會被這項檢查擋下，所以 reader 的 role
必須維持下面的唯讀設定。

在 FreeIPA server 上用管理員執行（`<fqdn>` 是這台 server 的 FQDN）：

```bash
kinit admin
ipa privilege-add "Pilot DNS Reader" --desc="Read-only DNS view for pilot_diagnose_dns_architecture"
ipa privilege-add-permission "Pilot DNS Reader" \
    --permissions="System: Read DNS Configuration" \
    --permissions="System: Read DNS Servers Configuration" \
    --permissions="System: Read DNS Entries"
ipa role-add "Pilot DNS Reader" --desc="Read-only DNS view for pilot_diagnose_dns_architecture"
ipa role-add-privilege "Pilot DNS Reader" --privileges="Pilot DNS Reader"
ipa service-add pilot-dns-reader/<fqdn>
ipa role-add-member "Pilot DNS Reader" --services=pilot-dns-reader/<fqdn>
mkdir -p /etc/pilot
ipa-getkeytab -p pilot-dns-reader/<fqdn> -k /etc/pilot/dns-reader.keytab
chmod 0600 /etc/pilot/dns-reader.keytab
kdestroy
```

- 三個 permission 都只有 read：`System: Read DNS Entries` 涵蓋 `idnsname=*` 底下的
  zone 與 forward zone，另外兩個分別是全域 DNS 設定與各 server 的 DNS 設定。
- 工具的 probe 不用 become：keytab 必須讓 inventory 的 `ansible_user` 讀得到。
  `ansible_user` 不是 root 時，把檔案 owner 改成那個帳號（權限維持 0600）。
- 工具優先在 primary 上讀；primary 連不到時改用第一台連得到的 DNS replica。要在
  primary 停機時也讀得到，把同一個 keytab 檔複製到每台 replica 的相同路徑。不要在
  replica 上再跑一次 `ipa-getkeytab`：它會產生新 key，前一份 keytab 立刻失效。

## 3. 啟動 MCP server

```bash
pilot mcp serve --dir <workspace> --enable-diagnose \
    --diagnose-inventory <inventory.yml> --audit-dir <audit dir> \
    --diagnose-freeipa-principal pilot-dns-reader/<fqdn>@<REALM> \
    --diagnose-freeipa-keytab /etc/pilot/dns-reader.keytab
```

- 兩個 `--diagnose-freeipa-*` 要一起給；principal 格式不對、任何一段以 `-` 開頭、是
  §2 列的管理員或 FreeIPA service principal、keytab 不是絕對路徑或含 `..` 時，server
  直接拒絕啟動。
- 不給時工具照常回答，只是 FreeIPA 設定那幾項是 `auth_required`，整體 status 是
  `auth_required`。

工具參數（全部選填）：

| 參數 | 意義 |
|---|---|
| `client_host` | 確切的 inventory 主機名稱；讀它實際的 resolver（`/etc/resolv.conf`、systemd-resolved、第一個 nameserver 回不回 `pilot-dns:` identity），跟 pilot 會替它寫的清單比對 |
| `internal_name` | 在每台 FreeIPA DNS provider 上權威查詢、也經每台 tier 查詢的內部名稱；預設是 primary 的 FQDN（轉小寫、去掉結尾的 `.`）。primary 的 FQDN 不是合法的 DNS 名稱又沒給這個參數時，內部名稱的比對不做，並以 `probe_skipped` 回報 |
| `external_name` | 經 tier 查詢的外部名稱（A）；預設查 root NS（`.`），跟 dns role 自己的 G6/G8 一樣 |

## 4. 讀結果

| 欄位 | 內容 |
|---|---|
| `status` | `complete`、`partial`（有看不到的 live 事實或比對，或有沒跑的 probe）、`auth_required`（FreeIPA 設定沒有核准的 credential 可讀、kinit 成功但 FreeIPA 不接受 ticket，或 principal 有寫入權限；其他事實照樣回報）。`complete` 只代表每項事實都看得到，不代表 DNS 正常：失敗本身列在 `findings` |
| `findings` | 代碼加主體。每個失敗或看不到的事實都會出現在某個 finding：`live_fact_unknown`（看不到的 live 事實，含 FreeIPA 設定）、`dns_query_failed`（DNS 查詢有回應但失敗：SERVFAIL/REFUSED 等錯誤碼、NXDOMAIN、沒有該型別的紀錄；`getent` 查無此名稱）、`comparison_unknown`（做不了的比對）、`probe_skipped`（超過上限或名稱不合法而沒跑的 probe）、`declared_value_unevaluated`（Jinja 樣板）、`freeipa_named_not_running`、`dns_tier_not_running`、`freeipa_dns_provider_unreachable`、`dns_tier_host_unreachable`、`client_unreachable`、`freeipa_dns_not_authoritative_from_tier`、`declared_live_mismatch`/`declared_live_absent`、`freeipa_read_permission_missing`、`auth_required`、`freeipa_principal_not_read_only`、`freeipa_forwarders_invalid`、`external_resolution_forwarder_unproven`、`external_resolution_failed`、`external_resolution_unknown`、`dns_tier_not_assigned`、`freeipa_replica_not_dns_server`（FreeIPA 沒有列為 DNS server、playbook 會排除的 replica；它的 probe 失敗是預期的） |
| `paths` | 精簡的路徑：tier 把哪些 zone 送到哪台 FreeIPA、`.` 送到哪個 upstream；每台 FreeIPA DNS 的 live SOA（`authoritative`，或實際的 status 與 `aa`）；FreeIPA 的 forwarders；每台主機的 resolver 順序 |
| `execution` | MCP server 的執行帳號、每台被 probe 主機上的遠端帳號、Kerberos 狀態（`not_configured`、`available`、`auth_required`、`refused_privileged`、`unreachable`、`not_applicable`） |
| `supported` / `declared` / `effective` / `observed` / `differences` | 見 §1 |
| `steps`、`audit_directory` | 每個 probe 的原始輸出（上限 64 KiB）與 audit record |

事實狀態：`observed`、`absent`、`unknown`、`auth_required`、`permission_denied`、
`unreachable`、`not_applicable`、`error`。DNS 查詢：NOERROR 且有該型別的紀錄是
`observed`；NXDOMAIN 或沒有該型別的紀錄是 `absent`；SERVFAIL、REFUSED 等錯誤碼是
`error`；沒有回應（逾時、連線被拒）是 `unknown`。服務狀態（`systemctl is-active`）：
rc 0 是在跑（含 `reloading`），rc 3 且 `inactive`/`failed` 是沒在跑，其他（例如
`Failed to connect to bus`）是 `unknown`。client 的 first hop 讀完整的 `id.server CH TXT`
回應：`pilot-dns:<name>` 是 tier；回應了但沒有 identity（含 NOTIMP，例如 libvirt 的
dnsmasq）不是 tier；REFUSED（例如 tier 的 access-control 不允許這台 client）是
`dns_query_failed`。

## 5. 已知限制與注意事項

- **還沒 promote 的 replica**：未設 `freeipa_setup_dns` 的 replica 要自己權威回答 FreeIPA 的
  zone，或 FreeIPA 的 NS 紀錄列出它，`dns-apply.yml` 與 resolver task 才會用它
  （`tasks/freeipa-dns-providers-live.yml`）。工具從各 provider 自己的 SOA／NS probe（`+norec`）
  與 NS 紀錄做同樣的判斷：沒列出的 replica 會有 finding
  `freeipa_replica_not_dns_server`，effective 的 tier stub 與 resolver 清單也跟 playbook 一樣
  不含它，它自己 probe 失敗不算 `partial`。

- **FreeIPA 不會說「沒權限」**：principal 缺少上面的 permission 時，`ipa
  dnsconfig-show` 回「Global DNS configuration is empty」、各 `-find` 回「Number of
  entries returned 0」（rc 1），跟真的沒有設定一模一樣（FreeIPA 4.13.4 實測）。工具
  用 `--rights` 確認全域設定讀得到，並以「FreeIPA 有列出 DNS server 時，自己的
  server 項目與網域 zone 一定存在」判斷 `-find` 的空結果是不是被隱藏；看不到就回
  `permission_denied`，不會回「沒有 forwarder」。
- **各 server 的 forwarders**：每台 DNS server 有自己的 forwarder 設定（`ipa dnsserver-*`），
  它的 named 優先用這個。安裝時的 `--forwarder` 會寫進去，2026-10-15 起每次 apply
  `freeipa-server-apply.yml`／`freeipa-server-replica-apply.yml` 也會用
  `ipa dnsserver-mod` 讓它等於 inventory 的值。不一致時 `differences` 會列出那台
  server，代表 inventory 改了之後還沒重新 apply。
- replica 是否算 DNS 提供者、replica 的 forwarders 怎麼解讀，跟安裝 playbook 一致：
  `freeipa_setup_dns` 預設 `true`（issue #67），`freeipa_dns_forwarders` 用與 primary
  相同的 `tasks/freeipa-dns-forwarders.yml` 正規化（issue #68）。`freeipa_dns_forwarders`
  不是清單也不是字串時，finding `freeipa_forwarders_invalid`。
- probe 不用 become：`unbound-control` 需要讀 unbound 的 control key，`ansible_user`
  不是 root 時 tier 的 forward/stub zone 會是 `unknown`。
- 有上限：最多 probe 5 台 FreeIPA DNS provider、5 台 tier 主機，其餘的列在
  `probe_skipped`，status 是 `partial`；resolver 清單最多 50 台。inventory 裡是 Jinja
  樣板（`ansible-inventory` 不會展開）的值，effective 回 `unknown` 並列出變數，不會猜
  （finding `declared_value_unevaluated`）。
- 內部名稱只查 A 紀錄：只有 IPv6 位址（AAAA）的 FreeIPA 主機，內部名稱會是
  `dns_query_failed`（沒有 A 紀錄），status 是 `partial`。pilot 的 FreeIPA 部署目前
  以 IPv4 為準。
- 每台 FreeIPA DNS provider 對內部名稱的權威回答都會跟第一台回答的比對
  （`FreeIPA <host> answer for <name> equals <first>'s`），資料沒同步的 replica 會是
  `mismatch`。

## 6. 變更紀錄

| 日期 | 變更 | 變更者 |
|---|---|---|
| 2026-10-13 | 初版（issue #62）；§0.5 填入 candidate `f63d490` 的實跑結果 | pilot |
| 2026-10-13 | replica 的 DNS 預設與 forwarders 改成跟安裝 playbook 一致（issue #67、#68），移除 `freeipa_replica_dns_unused` | pilot |
| 2026-10-14 | PR #66 review：外部解析要 NOERROR 且有紀錄才算成功，SERVFAIL/查無紀錄是 `external_resolution_failed`、沒有回應是 `external_resolution_unknown`；連得到的主機上任何 `unknown` 的 live 事實都讓 `status` 變成 `partial`（`live_fact_unknown`）；`paths` 標出每台 FreeIPA DNS 的 live SOA | pilot |
| 2026-10-14 | §0.5 改成 candidate `6522b94`（上兩列合併後）在全新 4 台 topology 上的實跑結果 | pilot |
| 2026-10-14 | PR #66 follow-up：每個失敗或未知的事實都有 finding（`auth_required`、`dns_query_failed`、`freeipa_named_not_running`、`live_fact_unknown`、`comparison_unknown`、`probe_skipped`），拒絕 FreeIPA 服務 principal 與有寫入權的 principal；§0.5 改指向 candidate `8951d2e` | pilot |
| 2026-10-14 | PR #91 review：第一跳只有在 tier 位址回錯誤 rcode 時才算查詢失敗；FQDN 在讀入時統一轉小寫、去掉結尾的點；寫入權限檢查只看全域 DNS 設定（`cn=dns`），說明照實寫；live fixture 換成同一次 pr91 擷取；§0.5 改指向 candidate `46fbc58` | pilot |
| 2026-10-15 | PR #91 review：§0.5 改指向同一 candidate `46fbc58` 在新建 topology 上的重跑，這次在執行當下記錄 run ID、UTC 時段、target image digest、inventory 與 reader role 指紋；結果與前一輪相同。前一輪的套件版本沒有在這次重新確認，表格不再列出 | pilot |
| 2026-10-15 | PR #92（#73 的 follow-up）：`freeipa_setup_dns` 未設、FreeIPA 的 NS 紀錄沒有列出、自己也不權威回答 zone 的 replica，比照 `dns-apply.yml` 與 resolver task 排除，只回報 `freeipa_replica_not_dns_server`；各 server 的 forwarders 由 FreeIPA playbook 管理，不一致時提示重新 apply。與 #91 合併時，provider 答案一致性比對改成跳過被排除的 replica；`paths` 不再把被排除的 replica 列成 authoritative，改列「left out of the DNS paths」 | pilot |
| 2026-10-15 | §0.5 改指向合併後的 candidate `287cf79` 在新建 6 台 topology 上的實跑；#91 的其他情境註明最後一次實跑在 `46fbc58` | pilot |
| 2026-10-15 | §0.5 改指向再次與 `main` 合併後的 candidate `b02b5cb`；#91 的情境也在它上面重跑，不再引用 `46fbc58` 當現行證據 | pilot |
| 2026-10-16 | §0.5 改指向 candidate `cdcd39b`（PR #92 的 replica forwarder kinit 改由 stdin 傳密碼，並與 `main` `f98327b` 合併）；#91 的情境也在它上面重跑 | pilot |
