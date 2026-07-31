# 原始問題

使用者在透過 `infra-deploy` 執行 `pilot reconcile` 時，遇到 `dt-port6000` 無法加入
FreeIPA，以及 restic repository 初始化失敗。診斷確認 `dt-port6000`
(`192.168.110.35`) 無法連線至 FreeIPA (`10.1.58.11`) 的必要服務埠，亦無法連線至
SeaweedFS S3 (`10.1.58.12:8333`)；使用者要求規劃一套在套用前即可偵測此類
「主機對主機服務不可達」的機制，並確認網路流向應由 playbook 或手動方式提供。

# 報告內文

## 1. 結論與目標

新增一個由 **Component Contract + inventory** 產生檢查矩陣的唯讀功能：

```bash
pilot network-check --inventory /pilot/config/inventory.yml
```

再讓 `pilot deploy` 與 `pilot reconcile` 在任何 preview 或 apply 前預設執行它。

此功能的 source of truth 是 `contracts/*.yaml`，不是解析 Ansible playbook，也不建立
另一份手工維護的 network matrix。playbook 只負責 mutation；contract 宣告元件提供的
endpoint 與消費端的必要連線，CLI 根據實際 inventory 展開成 source host → target host
的探測工作。

本次事故應在 apply 前被擋下，並以可操作的資訊顯示：

```text
FAIL tcp dt-port6000 (192.168.110.35)
  -> freeipa / ipa1.linker.internal (10.1.58.11):389 [FreeIPA LDAP]
  result: timeout
  hint: check routing/firewall from 192.168.110.0/24 to 10.1.58.0/24

FAIL tcp dt-port6000 (192.168.110.35)
  -> it-core (10.1.58.12):8333 [SeaweedFS S3]
  result: timeout
  hint: check routing/firewall and the S3 gateway listener
```

## 2. 已確認的現況與設計缺口

### 2.1 本次真實環境事實

透過 `infra-deploy` 的 Ansible SSH 唯讀檢查得到：

| Source | Target | 結果 | 意義 |
|---|---|---|---|
| `dt-port6000` | `10.1.58.11:80,88,389,464` | 無法連線 | `ipa-client-install` 找不到 LDAP/FreeIPA server |
| `dt-port6000` | `10.1.58.12:8333` | timeout | delegated restic init 無法到達 SeaweedFS |
| `freeipa` | FreeIPA services | 全部 RUNNING | 不是 FreeIPA server 故障 |
| `it-core` | SeaweedFS `:8333` | HTTP 403 | gateway 正常且需簽章，非服務未啟動 |

`playbooks/preflight.yml` 目前只驗證 controller → target 的 SSH；`pilot doctor` 只檢查
controller 本機工具。因此兩者都不可能找出 target → provider 的 east-west 網路阻斷。

### 2.2 既有可重用資料

contracts 已有下列結構化資訊：

- `dependencies`：元件之間的部署/拓樸關係。
- `bindings`：consumer input 對應哪個 provider endpoint。
- `endpoints`：provider 提供的 scheme 與 port。

例如 `contracts/restic-backup.yaml` 綁定 `seaweedfs-s3.s3`，而
`contracts/seaweedfs-s3.yaml` 宣告 `http:8333`。此 edge 可完全自動推導。

但 FreeIPA contract 尚未完整表達 client enrollment 的連線需求。現在 provider 只宣告
部分 endpoint；`ipa-client-install` 的必要 `80/88/389/464` 與 UDP Kerberos/kpasswd
需求散落於 playbook 註解與工具行為。直接掃描 playbook 會脆弱、難以涵蓋外部 endpoint、
也無法可靠判斷「連入」與「監聽」的語意。

## 3. Contract schema 設計

### 3.1 新增 consumer-side `networkRequirements`

在 `ComponentContract v1` 增加可選欄位，不改既有 `endpoints` 的 provider 宣告責任：

```yaml
networkRequirements:
  - name: ipa-enrollment
    to: {component: freeipa-server}
    probes:
      - {protocol: tcp, port: 80,  purpose: ipa-client discovery/bootstrap}
      - {protocol: tcp, port: 88,  purpose: Kerberos KDC}
      - {protocol: udp, port: 88,  purpose: Kerberos KDC}
      - {protocol: tcp, port: 389, purpose: LDAP}
      - {protocol: tcp, port: 464, purpose: kpasswd}
      - {protocol: udp, port: 464, purpose: kpasswd}
```

每個 requirement 必須包含：

- `name`：stable ID，作為輸出、測試與 evidence key。
- `to.component`：已存在的 provider component；必須對應既有 dependency。
- `probes[]`：`protocol` (`tcp` 或 `udp`)、`port` (1–65535)、可選 `purpose`。
- 可選 `endpoint`：如有指定，lint 必須確認 provider 有同名 `endpoints` entry，並由該
  entry supply scheme/port。consumer 特有的多埠需求則用 `probes` 明列。
- 可選 `whenInput`：只在某個已解析的 non-secret input 為某值時產生 edge；第一版不實作，
  先以不同 contract requirement 明確表達，避免 condition language 過早膨脹。

`endpoints` 仍表示「provider 對外提供什麼」；`networkRequirements` 表示「consumer 在
runtime 必須能從哪裡連到什麼」。兩者不可互相取代。

### 3.2 第一批 contract 更新

先覆蓋所有有明確 `providerEndpoint` dependency 的元件；每個變更需對照 apply playbook
真正使用的協定/port 與 verification spec，而不是憑常識補值。

| Consumer | Provider | 首批 requirement |
|---|---|---|
| `freeipa-client` | `freeipa-server` | TCP 80/88/389/464、UDP 88/464 |
| `restic-backup` | `seaweedfs-s3` | provider endpoint `s3` (`tcp:8333`) |
| `prometheus` | `seaweedfs-s3`、`alertmanager` | S3 endpoint、Alertmanager 實際 ingest port |
| `thanos-query` | `seaweedfs-s3` | S3 endpoint |
| `dashboard` | `thanos-query` | Thanos Query 實際 API port |
| `log-shipping` | `dashboard` | Loki ingest port |
| `wazuh-fim` | `wazuh-manager` | agent enrollment/runtime ports |
| `pam-oidc-sshd` | `keycloak` | OIDC discovery/token/JWKS HTTPS port |
| NFS client/server contracts | FreeIPA/NFS providers | 依實際 client operation 宣告 |

若某個 provider 沒有足夠的 `endpoints` 資料，先補 provider contract；不可在 CLI 寫一張
component-name → port 的 switch map。這是避免 drift 的核心規則。

### 3.3 外部 endpoint 與 alias

若 `restic_repository`、OIDC issuer 等被使用者覆寫成 inventory 外的 FQDN/IP，contract
無法從 provider group 推得目標 host。第一版採明確行為：

- 已知 inventory provider：展開每個 provider host，執行 source → target probe。
- 外部 endpoint：從已解析、非 secret 的 group/host var 取得 host:port；probe 顯示
  `target=external:<hostname>`，不要求它出現在 inventory。
- 無法安全解析（例如任意 shell command 或 secret 衍生 endpoint）：列 `SKIP`，輸出原因，
  不假裝 PASS；對 required requirement 則視為 preflight failure。

Alias（例如 `s3-backup-server`）需同時檢查：目標 IP port 與 `getent hosts <alias>` 是否解析到
預期 target。這能把「port 可達但 /etc/hosts 沒被寫入」和「網路阻斷」分開報告。

## 4. CLI、輸出與執行模型

### 4.1 新 command

```bash
pilot network-check --inventory inventory.yml
pilot network-check --inventory inventory.yml --component freeipa-client
pilot network-check --inventory inventory.yml --format text
pilot network-check --inventory inventory.yml --format json
```

旗標：

- `--component <id>`：只檢查選定 consumer component；可重複。
- `--limit <ansible pattern>`：只從被選中的 source host 出發，方便 day-2 診斷。
- `--timeout <duration>`：單一 TCP/UDP probe timeout，預設 3 秒。
- `--format text|json`：人用摘要或 automation/evidence 解析用資料。
- `--allow-skipped`：只供診斷使用；預設任何 required edge 的 `SKIP` 都非零結束。

exit code：

- `0`：所有 required probe PASS。
- `1`：至少一個 required probe FAIL 或無法安全建立 target。
- `2`：CLI/inventory/contract 無效。

### 4.2 由 target 發起探測

不能從 controller 探測後推論 target 可達；檢查必須透過 Ansible 在每個 source target 上執行。

探測命令第一版採最小依賴：

- TCP：Python stdlib socket connect（目標主機本來就必須能跑 Ansible Python）。
- UDP：送出 datagram 並報告「socket 可建立/無本機 route」；UDP 本質無法像 TCP 證明遠端
  service 正在接收，結果標為 `REACHABLE-UNCONFIRMED`，不把它誤報成 service health。
- DNS/alias：`getent ahostsv4 <name>`。
- HTTP health：僅在 contract 的 probe 明確宣告 `kind: http` 時執行，不以 HTTP 403 視為
  網路失敗；SeaweedFS root 的 403 正是「可達、認證不足」的有效訊號。

每筆 JSON result 至少含 `requirement`, `source`, `target`, `resolvedIP`, `protocol`, `port`,
`status`, `durationMs`, `detail`, `route`。

### 4.3 deploy / reconcile 整合

在既有靜態 completeness validation 後、Ansible `playbooks/preflight.yml` 的 SSH 檢查成功後、
preview/apply 前，執行與所選 components 相交的 network check。

流程：

```text
inventory/contract validation
  → controller → target SSH preflight
  → target → provider network-check
  → preview (--check --diff)
  → apply
```

互動式 deploy/reconcile 若 network check FAIL，預設停止，提供明確的「返回、不套用」選項。
非互動/automation 模式直接以 exit code 1 中止。可以提供顯式 `--skip-network-check` 作為
break-glass，但必須要求 `--confirm-skip-network-check`，並在輸出/evidence 明示此風險。

現有 `playbooks/preflight.yml` 保持只檢查 SSH/靜態 inventory；network graph 和 contract
解析留在 Go CLI，避免在 Ansible YAML 複製 contract 邏輯。

## 5. 實作步驟

1. **Contract model/lint**
   - 擴充 `internal/contract.Contract`、YAML schema/fixture 與 validation。
   - 驗證 component、dependency、endpoint、protocol、port、duplicate requirement/probe。
   - contract lint 必須拒絕缺 dependency 的跨 component requirement。

2. **Planning layer**
   - 新增純 Go planner：載入 contract catalog + rendered inventory，產生排序穩定的
     `NetworkProbePlan`。
   - 支援 provider endpoint binding、同 group 多 host 的笛卡兒展開、consumer/source limit、
     endpoint override/alias 的 explicit result。
   - planner 不跑 shell、也不接觸 secret。

3. **Ansible execution adapter**
   - 由 Go 產生暫時的唯讀 probe playbook，或以 `ansible` ad-hoc JSON callback 執行安全的
     Python socket probe；兩者都不可修改 target。
   - 實作 JSON parser、timeout、unreachable handling、stable result formatting。
   - probe 無法執行、source SSH 不通、遠端 Python 不可用，都要以 `ERROR` 匯入結果，不能
     靜默略過。

4. **Cobra command**
   - 實作 `cmd/pilot/cmd/network_check.go` 與旗標、text/JSON renderer、exit contract。
   - 將 command 加入 root command/help 與 semantic actions（若 automation 介面適用）。

5. **Deploy/reconcile gate**
   - 在取得 selected contract scope 後呼叫 planner/executor。
   - interactive TUI 顯示 source→target matrix 與最短修正提示；automation 維持結構化結果。
   - 確保只有 selected components 的 edges 執行，避免不相關 optional role 阻擋單一部署。

6. **第一批 contract migration**
   - 先完成 `freeipa-client` 與 `restic-backup`，以本事故為 regression case。
   - 再依 catalog 的 providerEndpoint components 分批補齊，不在第一個 PR 混入未驗證的 port。

7. **文件與 evidence**
   - 新增 verification spec、apply-free command behavior（此功能不需要 apply playbook）、
     regression tests 和 runbook。
   - 正式候選 revision 必須在 disposable topology 上做 PASS 與故意阻斷一條 edge 的 FAIL
     兩條路徑，保存 evidence；最後用 evidence-only commit 更新摘要。

## 6. Verification spec 與測試計畫

新增 `docs/verification/network-check.md`，至少含：

| Row | Acceptance criterion |
|---|---|
| C1 | contract lint 拒絕無效 network requirement |
| C2 | planner 從 `freeipa-client → freeipa-server` 展開正確 source/target/ports |
| C3 | planner 從 `restic-backup → seaweedfs-s3.s3` 取得 `tcp:8333` |
| C4 | target-side TCP probe 對可達 endpoint PASS |
| C5 | target-side TCP probe 對被阻斷 endpoint FAIL，含 source/target/port |
| C6 | alias 解析錯誤與 port 不通可區分 |
| C7 | `network-check --format json` schema 穩定且不洩漏 secret |
| C8 | deploy/reconcile 在 required edge FAIL 時 preview/apply 前停止 |
| C9 | `--skip-network-check --confirm-skip-network-check` 需要雙旗標並留下警示 |

測試分層：

- Go unit tests：contract lint、planner 展開、renderer、exit code、deploy/reconcile gate。
- Ansible adapter tests：解析 PASS/FAIL/UNREACHABLE/timeout JSON。
- Docker target：以可達 local listener 驗證 PASS；以不存在/隔離 port 驗證 FAIL。
- Multi-VM topology：一台 consumer、一台 provider，驗證真實 target-originated probe；再加入
  firewall/network namespace rule 製造單向阻斷，證明 controller 可 SSH 但 consumer 不可達 provider
  時仍會被抓到。
- 真實 staging：在不改動主機狀態下，對 `infra-deploy` inventory 執行一次，只保存 sanitized
  result（IP/host 是否可公開依既有 evidence policy 決定）。

## 7. 不納入第一版的項目

- 不掃描任意 Ansible task、template 或 shell command 推測網路流向。
- 不把 UDP probe 偽裝成遠端服務健康檢查。
- 不做 ICMP/ping 作為 required health gate；ICMP 常被刻意封鎖，且不等於應用 port 可達。
- 不自動修改 firewall、route、DNS、`/etc/hosts` 或 security group。
- 不檢查所有 host pair；只檢查 selected contracts 需要的 directed edges。
- 不解析或輸出 vault/credentials。

## 8. 風險與決策點

| 風險 | 控制方式 |
|---|---|
| contract port 漏寫造成 false PASS | contract lint + playbook/spec review + 真實 FAIL-path topology test |
| port 寫死於 CLI 再次漂移 | CLI 無 component-specific port switch；ports 僅由 contract 讀取 |
| 外部 endpoint 無法解析 | 明示 SKIP/FAIL，不視為 PASS；要求非 secret 連線參數 |
| UDP 無握手語意 | 以 `REACHABLE-UNCONFIRMED` 呈現；TCP/應用層 probe 才能通過 required health |
| probe 自己改變系統 | 僅使用 socket/DNS/HTTP GET；不寫檔、不開 service、不執行 credentialed operation |
| 大型 inventory 造成慢 | 去重 `(source,target,protocol,port)`、並行上限、短 timeout、只選取相關 components |

## 9. 建議交付切分

### PR 1 — Foundation + 本次事故覆蓋

- contract schema + lint。
- `pilot network-check` planner/executor/text+JSON output。
- `freeipa-client`、`restic-backup` 的 requirements。
- Docker/VM PASS+FAIL tests。
- 僅以 standalone command 交付，不改 deploy/reconcile default flow。

### PR 2 — 安全 gate

- 將 selected-component network check 納入 deploy/reconcile。
- TUI/automation bypass contract、evidence integration。
- 實際 staging read-only evidence。

### PR 3 — Catalog coverage

- 依 component 分批補齊其餘 providerEndpoint requirements。
- 每個 component 一併補 provider endpoints、regression test 和 verification evidence。

此切分讓使用者能先用新 command 檢查目前 `dt-port6000` 的網段問題，同時避免在未完成
所有 legacy contract 定義前，以廣泛的自動 gate 阻擋無關工作。

## 10. 完成定義

功能完成時，以下條件全數成立：

1. `pilot network-check` 可從 contract+inventory 產生並執行 directed network probes。
2. `freeipa-client` 與 `restic-backup` 的本次失敗會在 mutation 前以正確 source/target/port
   顯示為 FAIL。
3. controller SSH 成功但 target→provider 不通的 case 有自動化 regression test。
4. ports/protocol 不在 Go switch map 或第二份手工 matrix；契約是唯一宣告來源。
5. deploy/reconcile 預設 fail closed，break-glass 需明確雙重確認且可追溯。
6. 有 candidate-based 實測 evidence，包含 PASS 與故意 FAIL 的驗證結果。
