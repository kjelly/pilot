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

最新驗證：尚未在 candidate 上實跑（evidence-only commit 會更新本節）。

| 項目 | 事實 |
|---|---|
| 目標環境 | — |
| inventory host 集合 | — |
| 外部 state | — |
| 結果 | — |
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
- 經 tier 解析外部名稱成功，只代表 tier 解析得到，不代表是某個 forwarder 回答的；
  工具只回報「設定的 forward zone」與「解析結果」，並以 finding
  `external_resolution_forwarder_unproven` 標明。

## 2. 準備唯讀 principal（每個 realm 做一次）

FreeIPA 的 DNS 設定（global forwarders、forward policy、各 server 的 forwarders、
forward zone、zone 清單）要有 Kerberos ticket 才讀得到。工具只用操作者事先核准的
唯讀 principal：不收密碼、不使用主機預設 credential cache 裡現有的 ticket（部署後
root 的預設 cache 可能留著 `admin` 的 ticket，工具不會碰它），`admin` 也會被拒絕。

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

- 兩個 `--diagnose-freeipa-*` 要一起給；principal 格式不對、是 `admin`/`root`、
  keytab 不是絕對路徑或含 `..` 時，server 直接拒絕啟動。
- 不給時工具照常回答，只是 FreeIPA 設定那幾項是 `auth_required`，整體 status 是
  `auth_required`。

工具參數（全部選填）：

| 參數 | 意義 |
|---|---|
| `client_host` | 確切的 inventory 主機名稱；讀它實際的 resolver（`/etc/resolv.conf`、systemd-resolved、第一個 nameserver 回不回 `pilot-dns:` identity），跟 pilot 會替它寫的清單比對 |
| `internal_name` | 在每台 FreeIPA DNS provider 上權威查詢、也經每台 tier 查詢的內部名稱；預設是 primary 的 FQDN |
| `external_name` | 經 tier 查詢的外部名稱（A）；預設查 root NS（`.`），跟 dns role 自己的 G6/G8 一樣 |

## 4. 讀結果

| 欄位 | 內容 |
|---|---|
| `status` | `complete`、`partial`（有看不到的 live 事實或比對）、`auth_required`（FreeIPA 設定沒有核准的 credential 可讀；其他事實照樣回報） |
| `findings` | 代碼加主體，例如 `dns_tier_not_assigned`、`dns_tier_not_running`、`freeipa_dns_provider_unreachable`、`declared_live_mismatch`、`freeipa_read_permission_missing`、`freeipa_replica_dns_unused`、`freeipa_forwarders_invalid`、`external_resolution_forwarder_unproven` |
| `paths` | 精簡的路徑：tier 把哪些 zone 送到哪台 FreeIPA、`.` 送到哪個 upstream；FreeIPA 的 forwarders；每台主機的 resolver 順序 |
| `execution` | MCP server 的執行帳號、每台被 probe 主機上的遠端帳號、Kerberos 狀態（`not_configured`、`available`、`auth_required`、`unreachable`、`not_applicable`） |
| `supported` / `declared` / `effective` / `observed` / `differences` | 見 §1 |
| `steps`、`audit_directory` | 每個 probe 的原始輸出（上限 64 KiB）與 audit record |

事實狀態：`observed`、`absent`、`unknown`、`auth_required`、`permission_denied`、
`unreachable`、`not_applicable`、`error`。

## 5. 已知限制與注意事項

- **FreeIPA 不會說「沒權限」**：principal 缺少上面的 permission 時，`ipa
  dnsconfig-show` 回「Global DNS configuration is empty」、各 `-find` 回「Number of
  entries returned 0」（rc 1），跟真的沒有設定一模一樣（FreeIPA 4.13.4 實測）。工具
  用 `--rights` 確認全域設定讀得到，並以「FreeIPA 有列出 DNS server 時，自己的
  server 項目與網域 zone 一定存在」判斷 `-find` 的空結果是不是被隱藏；看不到就回
  `permission_denied`，不會回「沒有 forwarder」。
- **各 server 的 forwarders**：每台 DNS server 安裝時的 `--forwarder` 會留成那台
  server 自己的設定（`ipa dnsserver-*`），之後改 `freeipa_dns_forwarders` 只會更新
  全域清單。兩者不一致時，`differences` 會列出那台 server 的項目。
- **replica 的 DNS 預設不一致**（現有 playbook 的行為，這個工具只回報、不修改）：
  `freeipa-server-replica-apply.yml` 在 `freeipa_setup_dns` 未設定時預設安裝 DNS，
  但 server pool 與 resolver task 只有在明確設成 true 時才把 replica 當成 DNS
  provider。這種 replica 跑著 named，卻沒有 tier stub 或 client 會問它；finding
  `freeipa_replica_dns_unused`。
- **replica 的 forwarders 寫成字串**：`freeipa_dns_forwarders: 8.8.8.8`（範例檔的
  寫法）在 primary 會被拆成清單，但 replica playbook 會對字串的每個字元產生一個
  `--forwarder`（ansible-core 2.19.2 實測），finding `freeipa_forwarders_invalid`。
  replica 一律用清單。
- probe 不用 become：`unbound-control` 需要讀 unbound 的 control key，`ansible_user`
  不是 root 時 tier 的 forward/stub zone 會是 `unknown`。
- 有上限：最多 probe 5 台 FreeIPA DNS provider、5 台 tier 主機；resolver 清單最多
  50 台。inventory 裡是 Jinja 樣板（`ansible-inventory` 不會展開）的值，effective
  回 `unknown` 並列出變數，不會猜。

## 6. 變更紀錄

| 日期 | 變更 | 變更者 |
|---|---|---|
| 2026-10-13 | 初版（issue #62） | pilot |
