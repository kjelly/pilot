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

港口資訊的 source of truth 是「provider 自己宣告的 `endpoints:`」，不新增一份
consumer 側手工維護的網路需求清單。理由見 3.2。

### 3.1 重用並補齊既有 `dependencies` + `endpoints`，只加一個可選過濾欄位

現有 `Dependency`（`relation: providerEndpoint`）已經宣告「這個 consumer 需要連到哪個
provider」；現有 `Endpoint`（`name/scheme/port/path`）已經可以宣告 provider 開放的
tcp/udp/http port（`contracts/dns.yaml`、`contracts/ntp.yaml` 已經在用 `scheme: udp`，
不是新概念）。這兩者組合就足以推導多數 edge，不需要另一份 `networkRequirements` 頂層
schema、也不需要 `probes[] {protocol, port, purpose}` 這種平行結構。

唯一要補的是 `Dependency` 上一個可選欄位，用來處理「provider 開放多個 port，但這個
consumer 只用得到其中幾個」：

```yaml
dependencies:
  - component: freeipa-server
    required: true
    relation: providerEndpoint
    endpoints: [ldap, kerberosTcp, kerberosUdp, kpasswdUdp, httpBootstrap]
```

- 省略 `endpoints`＝檢查 provider 宣告的**全部** endpoint。多數元件只有 1–2 個
  endpoint（`seaweedfs-s3`、`wazuh-manager`、`keycloak`），省略即可，零額外撰寫。
- 填 `endpoints`＝只檢查列出的名字；每個名字必須存在於 provider 的 `endpoints[].name`，
  否則 lint 直接拒絕——沿用 `internal/contract/lint.go:234`
  `validateBindingEndpoints` 已有的「binding 引用不存在 endpoint 就報錯」模式，加一個
  對稱的 `validateDependencyEndpoints`。
- 這個欄位只在「provider 開放多個 port，但這個特定 consumer 用不到全部」時才填；填寫時
  必須對照 apply playbook 真正使用的 port 與 §3.3 的 verification spec 交叉核對，不可
  憑常識猜。

`scheme` 已經足以決定探測方式，不需要另外的 `probes[].kind`：`tcp`/`udp`/`unix` 走
socket-level connect；`http`/`https`/`ldap`/`ldaps`/`grpc` 走該 scheme 對應的 TCP
connect（`http`/`https` 額外送一次請求，但任何有效 HTTP 回應——含 403/401——都算
PASS，理由見 §4.2）。

### 3.2 為什麼不讓 consumer 自己宣告 probes

原案曾考慮讓每個 consumer 自行列一份 `probes[] {protocol, port, purpose}`。放棄的理由：

- 這等於把 provider 已經宣告過的 port，在 consumer 端重新打一次。兩份資料源一旦不
  同步，本身就是一種新的 drift——跟 §7 要避免的「CLI 寫 component→port switch map」
  是同一類風險，只是把它搬進了 contract 裡而已。
- 對照既有 `bindings`（1 個 input ↔ 1 個 provider endpoint）發現它已經覆蓋大多數單埠
  案例：`restic-backup`→`seaweedfs-s3.s3`、`wazuh-fim`→`wazuh-manager.agent`、
  `pam-oidc-sshd`→`keycloak.oidc`。真正需要「一個 consumer 要連 provider 多個 port」
  的案例，目前只有 FreeIPA enrollment 這一個；而它現有的 binding
  （`freeipa_server_ip` ← `freeipa-server.https`，port 443）根本沒有指到這次事故真正
  卡住的 port（80/88/389/464，見 §2.1）——binding 本來就不是為「多埠依賴」設計的。
  可見「一個可選 `endpoints` 過濾欄位＋把 provider 自己的 `endpoints:` 補齊」就足以
  精確表達這個唯一的多埠案例，不必為此新增一整套 probes schema。
- Port 的權威來源應該只有一份：provider 的 `endpoints:`。它現在不完整
  （`freeipa-server.yaml` 只宣告 4 個，但 `docs/verification/freeipa-server.md`
  C4–C10 已經用 `ss`/`curl` 驗證過 7 個真實 listening port），先把它補齊，比另開一份
  平行資料結構更省、也更符合「contract 是唯一宣告來源」（§7）。

### 3.3 第一批 contract 更新

| Provider 要補的 `endpoints:` | 依據 |
|---|---|
| `freeipa-server` | 補 `httpBootstrap`(tcp:80)、`kerberosUdp`(udp:88)、`kpasswdUdp`(udp:464)；`docs/verification/freeipa-server.md` C7–C9 已驗證這三個真的在 listen，既有 `ldap`/`ldaps`/`kerberosTcp`/`https` 不動 |
| 其餘有 `providerEndpoint` dependency 的 provider | 逐一核對對應 `docs/verification/<provider>.md` 的 `port`/`http` 分類 row 與 apply playbook 真正 bind 的 port，補齊 `endpoints:`；目前只確認 FreeIPA 缺項，其餘假設完整、實作時逐一驗證 |

| Consumer dependency 要窄化 `endpoints:` | 理由 |
|---|---|
| `freeipa-client → freeipa-server` | `ipa-client-install` 不會用到 443(https)；填 `endpoints: [ldap, kerberosTcp, kerberosUdp, kpasswdUdp, httpBootstrap]` |
| 其餘（`restic-backup`、`prometheus`、`thanos-query`、`dashboard`、`log-shipping`、`wazuh-fim`、`pam-oidc-sshd`、NFS client/server …）| 先省略 `endpoints`（＝檢查 provider 全部 endpoint），除非實測發現某 provider 有這個 consumer 用不到的 port |

若某個 provider 沒有足夠的 `endpoints` 資料，先補 provider contract；不可在 CLI 寫一張
component-name → port 的 switch map。這是避免 drift 的核心規則。

### 3.4 外部 endpoint 與 alias

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
   - 在 `internal/contract.Dependency` 加一個可選 `Endpoints []string` 過濾欄位（見
     §3.1）；不新增頂層 schema。
   - 新增 `validateDependencyEndpoints`（仿 `internal/contract/lint.go:234`
     `validateBindingEndpoints` 的模式）：`Dependency.Endpoints` 裡的每個名字都必須存在於
     對應 provider 的 `endpoints[].name`，否則 lint 拒絕。
   - 依 §3.3 補齊 `freeipa-server.yaml` 等 provider 的 `endpoints:`，並在
     `freeipa-client.yaml` 的 dependency 上填 `endpoints:` 窄化清單。
   - fixture/schema test 補上「`Endpoints` 引用不存在的名字」與「provider 補齊後 lint 仍
     PASS」兩個 case。

2. **Planning layer**
   - 新增純 Go planner：載入 contract catalog + rendered inventory，產生排序穩定的
     `NetworkProbePlan`。
   - Edge 來源＝每個被選中 component 的 `dependencies[relation=providerEndpoint]`；
     endpoint 集合＝該 dependency 的 `Endpoints`（若非空）否則 provider 的全部
     `endpoints`。
   - 支援同 group 多 host 的笛卡兒展開、consumer/source limit、endpoint override/alias 的
     explicit result（§3.4）。
   - planner 不跑 shell、也不接觸 secret。

3. **Ansible execution adapter**
   - 沿用 `internal/tools/verify_spec.go` 已有的 ansible ad-hoc 執行模式（該檔案已有
     「為什麼用 ad-hoc 而不直接跑指令」的說明），不另外產生暫時 playbook：對每個
     source host 以 ad-hoc 呼叫一個安全的 Python socket probe 模組/腳本，兩者都不可修改
     target。
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
   - **不是** `docs/verification/network-check.md`（見 §6 說明為什麼）；`pilot
     network-check` 的行為驗收改寫成 Go regression tests，evidence 走
     `docs/runbooks/network-check.md`（比照既有 `docs/runbooks/vm-target.md`——
     同樣是「CLI 工具本身」的 runbook，不對應任何 role/apply playbook）。
   - 正式候選 revision 必須在 disposable topology 上做 PASS 與故意阻斷一條 edge 的 FAIL
     兩條路徑，保存 evidence；最後用 evidence-only commit 更新摘要。

## 6. 驗收方式：為什麼不是 `docs/verification/network-check.md`

`docs/verification/*.md` 這套格式（`TESTING.md` §0 定義）綁定一個很具體的形狀：一個
`contracts/*.yaml` component、一支 `playbooks/apply/*.yml`、Command 欄位是**一條 ansible
ad-hoc（或 `--local`）shell 指令，對已經被那支 apply playbook converge 過的單一 target
host** 驗證 post-condition，執行方式是 `pilot verify docs/verification/<x>.md`。本 repo
現有 29 份 spec（`freeipa-server.md`、`restic-backup.md`……）全部是這個形狀，包含
`hello-localhost.md` 這種最小 smoke test 也一樣。

`pilot network-check` 不是這個形狀：它**沒有 apply playbook**，不 converge 任何 host，
`contracts/*.yaml` 也不會有它的條目（`internal/contract/lint.go:60` 目前假設每個
component 的 `Playbooks.Apply` 都是一個真實存在的檔案路徑，硬塞一個空 apply 只會讓 lint
邏輯打結）。它的驗收本質上分兩種，各自已有更適合的既有機制：

- **contract lint / planner 展開 / CLI 輸出格式 / exit code / deploy 閘門**——這些是
  Go 程式邏輯正確性，跟 `vm-target`、`doctor`、`deploy_completeness` 等既有 CLI 功能
  的驗收方式相同：直接寫 Go regression test（`internal/contract/*_test.go`、新的
  `internal/networkcheck/*_test.go`、`cmd/pilot/cmd/network_check_test.go`），跑
  `TESTING.md` L1 tier 的 `go test ./...`，不需要一份 markdown spec 去描述「go test 應該
  過」。
- **在真實/拋棄式 topology 上，probe 對可達/被阻斷的 port 是否真的回報對的結果**——這是
  L4 tier 的 actual-run evidence，跟其他工具功能（例如 `docs/runbooks/vm-target.md`）
  一樣寫進 **runbook**，不是 verification spec：因為這裡沒有「重跑 `pilot verify` 比對
  Expected」這個動作，有的是「跑一次 `pilot network-check`，看它自己回報的 PASS/FAIL 對
  不對」。

具體要驗收的項目（以 Go test 或 runbook 記錄，視性質分流，不建一份新 spec）：

| # | Acceptance criterion | 驗收方式 |
|---|---|---|
| 1 | contract lint 拒絕引用不存在 endpoint 名字的 `Dependency.Endpoints` | `internal/contract` unit test |
| 2 | planner 從 `freeipa-client → freeipa-server` 展開正確 source/target/ports | `internal/networkcheck` unit test |
| 3 | planner 從 `restic-backup → seaweedfs-s3.s3` 取得 `tcp:8333` | `internal/networkcheck` unit test |
| 4 | target-side TCP probe 對可達 endpoint PASS | Docker-target regression test |
| 5 | target-side TCP probe 對被阻斷 endpoint FAIL，含 source/target/port | Docker-target regression test |
| 6 | alias 解析錯誤與 port 不通可區分 | `internal/networkcheck` unit test |
| 7 | `network-check --format json` schema 穩定且不洩漏 secret | `cmd/pilot/cmd` regression test |
| 8 | deploy/reconcile 在 required edge FAIL 時 preview/apply 前停止 | `cmd/pilot/cmd` regression test（同 `deploy_exitcode_regression_test.go` 的模式）|
| 9 | `--skip-network-check --confirm-skip-network-check` 需要雙旗標並留下警示 | `cmd/pilot/cmd` regression test |
| 10 | Multi-VM topology：真實 target-originated probe，故意用 firewall/network namespace 規則製造單向阻斷，證明 controller SSH 通但 consumer 連不到 provider 時仍會被抓到 | `docs/runbooks/network-check.md` 實跑 evidence（PASS + 故意 FAIL 兩條路徑）|
| 11 | 真實 staging：對 `infra-deploy` inventory 唯讀執行一次 | `docs/runbooks/network-check.md`，只保存 sanitized result |

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

- `Dependency.Endpoints` 欄位 + lint。
- `pilot network-check` planner/executor/text+JSON output。
- 補齊 `freeipa-server` 的 `endpoints:`、窄化 `freeipa-client`/驗證 `restic-backup` 的
  dependency。
- Docker/VM PASS+FAIL tests。
- 僅以 standalone command 交付，不改 deploy/reconcile default flow。

### PR 2 — 安全 gate

- 將 selected-component network check 納入 deploy/reconcile。
- TUI/automation bypass contract、evidence integration。
- 實際 staging read-only evidence。

### PR 3 — Catalog coverage

- 依 component 分批補齊其餘 provider 的 `endpoints:`，並在需要窄化的 dependency 上補
  `Endpoints`。
- 每個 component 一併補 regression test 和 verification evidence。

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
