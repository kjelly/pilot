# Pilot Outbound State Webhook + State Projection 實作規格

- **日期**：2026-09-16
- **狀態**：PROPOSED / implementation-ready
- **目標 repository**：`kjelly/pilot`
- **設計基準**：`13ea9be6bf5aad800a64e31fdff423142a3825ad`（`main`，2026-09-16）
- **建議落版位置**：`docs/superpowers/specs/2026-09-15-outbound-state-webhook-spec.md`
- **主要影響元件**：`pilot deploy`、`pilot reconcile`、`pilot access reconcile`、`pilot access breakglass`、`pilot gateway-scope`、Component Contract、`internal/delivery`、`internal/store`、FreeIPA roster effective-access resolver
- **功能名稱**：**Pilot Outbound State Webhook**
- **風險等級**：High（會發布身分／權限 metadata，且接在既有 mutation workflow 的 terminal boundary）
- **相容性要求**：沒有 `integrations.yaml` 的既有 workspace 行為 MUST 完全不變；Webhook runtime failure MUST NOT 改寫原 operation 的成功／失敗 exit semantics。

---

# 1. 目標

Pilot 需要提供一個與特定 Portal、CMDB、網站或外部團隊實作無關的通用 outbound integration 機制。

當 Pilot 管理的 deploy 或 day-2 reconcile operation 到達 terminal outcome 時，Pilot MAY 依 workspace 的 declarative 設定向一個或多個 HTTP endpoint 發送 webhook。

V1 的 public operation type 仍只有：

```text
deploy
reconcile
```

以下 dedicated frontend MUST 投影成同一個 `reconcile` operation，而不是形成不相容的新 wire operation：

| CLI frontend | `operation.type` | Effects |
|---|---|---|
| `pilot reconcile` | `reconcile` | 所選 components 的 contract effects union |
| `pilot gateway-scope reconcile` | `reconcile` | `identity.hostgroups`, `access.hbac` |
| `pilot gateway-scope enable-auto` | `reconcile` | `identity.hostgroups`, `access.hbac` |
| `pilot gateway-scope disable-auto` | `reconcile` | `identity.hostgroups`, `access.hbac` |
| `pilot access reconcile <roster-file> --once` | `reconcile` | `access.hbac`, `access.sudo`, `access.grants` |
| `pilot access breakglass activate <roster-file> <name>` | `reconcile` | `access.hbac`, `access.grants` |
| `pilot access breakglass deactivate <roster-file> <name>` | `reconcile` | `access.hbac`, `access.grants` |

每個 dedicated frontend 仍產生自己的 `workflow_id`，每個 subscription 最多一個 terminal event。`delivery_runs` MAY 為空；這表示該 frontend 尚未經 `internal/delivery.Transaction`，不得虛構 run ID。

Read-only `pilot gateway-scope plan`、`pilot access status` 與 `pilot access breakglass status` 不形成 terminal mutation event。

使用者 MUST 可以獨立設定：

1. 哪一種 operation：
   - `deploy`
   - `reconcile`
2. 哪一種 terminal result：
   - `success`
   - `failure`
   - `cancelled`（V1 支援但非必要設定）
3. `reconcile`（包含 dedicated reconcile frontends）是否只針對特定 semantic effects 發送，例如：
   - `identity.*`
   - `access.*`
   - `dns.*`
4. payload 型態：
   - `snapshot`
   - `diff`
   - `both`
5. webhook endpoint、authentication、timeout、retry policy。

主要使用情境：

> 其他團隊維護一個程式，需要在 Pilot deploy 或 day-2 reconcile operation 後取得 Pilot 管理的主機、使用者與有效權限狀態，且不應依賴 `hosts.yml`、FreeIPA roster 或 Pilot 內部 schema。

本功能 MUST 將 Pilot 的內部資料模型轉成 versioned、sanitized、deterministic 的 external projection。

## 1.1 Projection truth model

`user_host_access_v1` 明確代表：

```text
Pilot canonical declarative sources 在 operation terminal 後的完整、可重現投影
```

它的 basis 固定為：

```text
pilot_declared
```

它不是所有遠端系統的 live observed state，也不宣稱未被本次 operation 觸及的 domain 已重新驗證。Wire 的：

```text
state.authoritative
```

只表示該 snapshot 可作為這個 webhook consumer 的下一個 **Pilot-declared publication baseline**，不表示所有遠端主機已被掃描或與 declaration 無 drift。

遠端套用結果由下列欄位獨立表達：

```text
operation.result
operation.delivery_runs
state.application_consistency
state.confirmed_effects
```

因此 Docker deploy 成功可以發布完整 declarative snapshot，但 `confirmed_effects` 不會憑空包含 identity/access；consumer 不得把 `authoritative=true` 解讀成 FreeIPA live state 已驗證。

---

# 2. 非目標

V1 MUST NOT：

1. 實作外部 Portal。
2. 提供 inbound webhook。
3. 讓外部系統修改 Pilot state。
4. 將 raw `hosts.yml`、raw roster、Vault 或 Ansible variables 原樣送出。
5. 將 password、initial password、private key、SSH public key body、token、Vault secret 送出。
6. 把 webhook runtime failure 當成 infrastructure operation failure。
7. 依 component 名稱做 user-facing subscription，例如要求使用者設定：
   ```yaml
   component: freeipa-identity
   ```
8. 用 playbook tag、label、檔名 substring 或 error string heuristic 判斷「這是不是 user roster reconcile」。
9. 把 `diff` 定義成 Ansible `--diff`。
10. 把 `diff` 定義成 operation 前後的本機 `hosts.yml` / roster 檔案差異。
11. 宣稱 snapshot 是所有遠端主機的完整 live runtime scan。
12. 為 webhook 建立背景 daemon。V1 是 durable outbox + bounded synchronous attempt + explicit/opportunistic flush。
13. 在 grant／breakglass 到期時間點自動喚醒 process 發送新 event。Consumer MUST 依 `valid_until`／`valid_not_after` 自行停止使用過期 access；下一次 reconcile terminal event 會再發布不含過期 grant 的 snapshot。

---

# 3. 現況與設計約束

## 3.1 Deploy / Reconcile 已共享 execution path

目前 `pilot reconcile` 最終使用與 deploy 共用的 catalog execution：

```text
runReconcileInteractive
    -> runCatalogPlaybookDeploy(..., reconcileOnly=true, ...)
```

`runCatalogPlaybookDeploy` 在普通 deploy 是單選；只有 `reconcileOnly=true` 時是 multi-select 並逐一執行。全站 multi-component deploy 另走：

```text
runDeployInteractive
    -> runSiteDeploy
    -> executeRecordedDeployment(playbooks/site.yml, ...)
```

因此 webhook MUST 掛在 **top-level workflow terminal boundary**，而不是：

- 每個 Ansible task；
- 每個 playbook；
- `executeRecordedDeployment()` 每次呼叫；
- 每個 component。

因此 terminal boundary MUST 同時包住 `runSiteDeploy`、單一 catalog deploy、multi-component reconcile，以及上表列出的 dedicated reconcile frontends。否則一次 multi-component deploy/reconcile 會送出多個錯誤粒度的 webhook，或 dedicated access mutation 完全沒有通知。

## 3.2 Component 已有 stable identity

`cmd/pilot/cmd/deploy_catalog.go` 的：

```go
type deployPlaybook struct {
    Key       string
    ...
    Reconcile bool
}
```

其中 `Key` 是 stable component ID，例如：

```text
freeipa-identity
freeipa-dns
internal-endpoint
```

但 `Reconcile bool` 只能回答：

> 這個 component 是否可以進入 day-2 reconcile flow？

它不能回答：

> 這個 component 會修改什麼 semantic state？

所以 V1 MUST 將 semantic effect 宣告放進 canonical **Component Contract**，不得新增另一份 webhook-specific component mapping。

## 3.3 Component Contract 目前是 strict schema

`internal/contract/contract.go` 目前：

```go
const SchemaVersion = 1

type Contract struct {
    SchemaVersion int `yaml:"schemaVersion"`
    ID            string `yaml:"id"`
    ...
}
```

Loader 使用 strict known-field decode，未知欄位會被拒絕。

因此 `effects` MUST 先成為正式 `Contract` field，再修改任何 `contracts/*.yaml`。

## 3.4 Delivery 已有 machine-readable outcome

`internal/delivery/transaction.go` 已定義：

```text
success
failed
partial_success
partial_failed
cancelled
rolled_back
rollback_failed
evidence_failed
authorization_required
```

Webhook MUST 保留這些原始 outcome，不得只從 Go `error != nil` 猜結果。

## 3.5 Delivery evidence 已有 run ID / component set

`internal/store/delivery_evidence.go` 的 `RunStarted` 已包含：

```go
RunID      string
Component  string
Components []string
Stage      string
Playbook   string
Inventory  string
```

Outbound integration MUST reuse既有 delivery identity/evidence，不得再發明一套互相無法 correlation 的 component/run identity。

但既有 `run_id` 是 transaction 級，不等同「一次 CLI deploy/reconcile」。

V1 MUST 新增 **workflow_id** 來表示一次 top-level deploy/reconcile semantic operation，包括 §1 列出的 dedicated reconcile frontends。

## 3.6 Pilot 已有 sanitized / effective access 基礎

Pilot 已經有：

- `EffectiveHBACAccessList`
- `EffectiveSudoAccessList`
- nested group 展開
- nested hostgroup 展開
- grant compiler
- breakglass runtime state
- MCP inspect 的 non-secret roster projection

Outbound webhook MUST reuse/refactor這些 semantics，不得在 webhook package 再寫一套 authorization resolver。

## 3.7 Store schema

設計基準 commit 的：

```text
internal/store/sqlite.go
SchemaVersion = 15
```

本功能需要 durable outbox/cursor。

Implementation MUST 使用「實作當下的 next actual schema version」；若 main 已超過 15，不得硬編碼假設為 16。

---

# 4. 核心 invariant

## INV-1 — 一次 workflow 最多一個 terminal event / webhook

一次：

```bash
pilot deploy
```

即使內部執行：

```text
docker
prometheus
alertmanager
```

對同一 webhook subscription 仍只能產生一個 terminal event。

同理：

```bash
pilot reconcile
```

選擇：

```text
freeipa-identity
freeipa-dns
internal-endpoint
```

不能因三個 component 各自完成而送三次 operation terminal webhook。

`pilot access reconcile`、單次 breakglass activate/deactivate、`pilot gateway-scope reconcile/enable-auto/disable-auto` 也各自是一個 workflow；不得因內部執行多個 Ansible task 或 managed rule 而送出多個 event。

## INV-2 — Webhook runtime failure 不改 infrastructure outcome

例如：

```text
Apply   PASS
Verify  PASS
Webhook HTTP 503
```

Pilot MUST：

```text
operation exit code = 原本成功 exit code
webhook = pending retry
```

MUST NOT：

```text
operation exit 1
```

此 invariant 也包含 post-mutation 的 local publication failure，例如 SQLite enqueue、projection 或 serialization 失敗。Pilot MUST 保留原 operation exit semantics、輸出明確的 bounded warning，並將 `publication_status=failed_local` 記入本地 diagnostic log（若 log/store 仍可用）。

「durable」保證從 outbox enqueue transaction 成功後開始；磁碟滿載或 SQLite 損壞使 enqueue 本身失敗時，不得宣稱事件已 durable。為降低此風險，任何 enabled integration MUST 在 mutation 前先完成 config parse、store open/migration 與一個 rollback-only write transaction readiness check。

## INV-3 — Invalid static integration config 在 mutation 前 fail

若 workspace 有 `integrations.yaml`，但 schema invalid，例如：

```yaml
payload: snapshots
```

Pilot MUST 在執行任何遠端 mutation 前拒絕 operation。

這與 runtime webhook failure 不同：

```text
invalid config before mutation -> fail closed
network/runtime failure after operation -> deployment result unchanged
```

Store schema migration/open failure、無法讀取指定 CA file、無效 endpoint/auth/delivery policy 都屬 static/pre-publication readiness failure，MUST 在 mutation 前 fail closed。Secret environment variable缺失屬 runtime delivery failure，依 INV-2 保留原 operation outcome 並留下 pending event。

## INV-4 — Raw secret 永不進入 webhook/outbox

以下 MUST NOT 出現在：

- HTTP body
- HTTP header log
- outbox DB JSON
- cursor snapshot JSON
- webhook status
- retry error
- CLI warning

包括：

```text
freeipa.admin.password
password.initial
ssh_keys.values
ipa_admin_password
Vault secret value
private key
bearer token
HMAC secret
```

## INV-5 — `diff` 是 publication-state diff

`diff` MUST 定義為：

```text
previous authoritative snapshot acknowledged by this logical webhook consumer
or an earlier FIFO authoritative event that MUST be ACKed first
                                  ↓
                         current snapshot
```

不是：

```text
operation start local file
        ↓
operation end local file
```

原因：

```text
1. operator 先修改 roster
2. roster 已包含 alice
3. pilot reconcile
4. local roster operation 前後內容相同
```

若使用 local-before/local-after：

```text
diff = empty
```

這會錯失真正需要通知外部系統的 Alice 狀態。

## INV-6 — Publication authority 與 remote application consistency 分離

成功：

```text
state.basis = pilot_declared
state.source_complete = true
state.application_consistency = confirmed_for_effects
state.confirmed_effects = operation.effects
state.authoritative = true
```

失敗：

```text
state.basis = pilot_declared
state.source_complete = true
state.application_consistency = partial_or_unknown
state.confirmed_effects = completed_components 的 effects union
state.authoritative = false
```

`authoritative=true` 只表示「可前進 publication cursor，並以這份完整 Pilot-declared snapshot 作為 consumer baseline」。它不是遠端 live scan 證明。外部 consumer MUST 同時看 `basis`、`source_complete`、`application_consistency` 與 `confirmed_effects`，不得由 `authoritative` 推導未列在 `confirmed_effects` 的 domain 已完成遠端驗證。

若 projection source unreadable：

```text
state.source_complete = false
state.application_consistency = WorkflowResult.ApplicationConsistency（不改寫）
state.confirmed_effects = WorkflowResult.ConfirmedEffects（不改寫）
state.authoritative = false
```

此時 snapshot/diff MUST omitted，cursor MUST NOT advance。Projection failure 只證明 publication source 無法完整 materialize，不得抹除已由 structured workflow result 得知的 remote application outcome。

## INV-7 — Effects 是 component contract metadata

User-facing config 不得依賴：

```text
freeipa-identity
```

而應訂閱：

```text
identity.*
access.*
```

未來 `freeipa-identity` 拆成：

```text
freeipa-users
freeipa-groups
freeipa-hbac
freeipa-sudo
```

只要新 contracts 持續宣告相同 effects，使用者的 `integrations.yaml` 不需修改。

---

# 5. 高階架構

```text
                        Component Contracts
                         effects: [...]
                               │
                               ▼
pilot deploy / reconcile
pilot gateway-scope reconcile / enable-auto / disable-auto
pilot access reconcile / breakglass activate / deactivate
        │
        │ workflow_id
        ▼
Prepare / Preflight / Apply / Verify / Idempotency / Rollback
        │
        ▼
Terminal Workflow Result
        │
        ├── requested components
        ├── executed components
        ├── completed components
        ├── delivery outcomes
        ├── effects
        └── success/failure/cancelled
        │
        ▼
Subscription Matcher
        │
        ├── operation
        ├── result
        └── effects_any
        │
        ▼
State Projection Builder
        │
        ├── hosts.yml
        ├── canonical roster
        ├── effective HBAC
        ├── effective sudo
        ├── temporary/sudo grants
        └── active breakglass
        │
        ▼
ManagedEnvironmentSnapshotV1
        │
        ├──────────────┬────────────────┐
        ▼              ▼                ▼
    snapshot          diff             both
                        │
                        ▼
                 Durable Outbox
                        │
                        ▼
                   HTTP Sender
                        │
                 2xx ───┴── error
                  │            │
                  ▼            ▼
           advance cursor   pending retry
```

---

# 6. Component Effects

## 6.1 Contract schema

在：

```text
internal/contract/contract.go
```

新增：

```go
type Effect string

type Contract struct {
    ...
    Effects []Effect `yaml:"effects"`
}
```

`effects` 為 additive optional field，因此 V1 建議維持：

```yaml
schemaVersion: 1
```

不要求一次升級所有 contract。

但：

> 所有 `deployCatalog` 中 `Reconcile: true` 的 component MUST 有至少一個 effect。

以 cross-layer regression test 強制。

## 6.2 Effect naming

合法格式：

```regex
^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$
```

合法：

```text
identity.users
identity.groups
access.hbac
access.sudo
dns.records
network.endpoints
```

非法：

```text
users
Identity.Users
identity/*
identity.*
freeipa-identity
```

Wildcard 只存在 user subscription，不存在 contract declaration。

## 6.3 Known effect registry

MUST 在 Go code 維護 typed registry，避免 typo silent routing：

```go
const (
    EffectIdentityUsers       Effect = "identity.users"
    EffectIdentityGroups      Effect = "identity.groups"
    EffectIdentityHostgroups  Effect = "identity.hostgroups"
    EffectIdentityNetgroups   Effect = "identity.netgroups"

    EffectAccessHBAC          Effect = "access.hbac"
    EffectAccessSudo          Effect = "access.sudo"
    EffectAccessGrants        Effect = "access.grants"

    EffectDNSZones            Effect = "dns.zones"
    EffectDNSRecords          Effect = "dns.records"

    EffectNetworkResolver     Effect = "network.resolver"
    EffectNetworkEndpoints    Effect = "network.endpoints"

    EffectTrustCA             Effect = "trust.ca"
    EffectTLSCertificates     Effect = "tls.certificates"
    EffectReverseProxyRoutes  Effect = "reverse_proxy.routes"

    EffectIdentityReplica     Effect = "identity.freeipa_replica"
    EffectIdentityRealm       Effect = "identity.realm_membership"

    EffectStorageNFSIdentity  Effect = "storage.nfs.identity"

    EffectMonitoringScrapeTargets Effect = "monitoring.scrape_targets"
)
```

未知 effect MUST 被 contract lint 拒絕。

Effect 宣告規則：

1. contract MUST 宣告它直接修改的 semantic domain；
2. 若該 mutation 會改變 `user_host_access_v1` 的 resolved access，MUST 另外宣告對應的 `access.hbac`／`access.sudo`；
3. 不得只因 dependency 可能執行就把 dependency effects 複製到 consumer contract；auto-executed dependency effects 由 workflow aggregation 加入；
4. 一個 effect 可以觸發 event，即使 V1 projection 沒有該 domain 的 entity。這時 event 仍提供 operation metadata，而 snapshot ID MAY 不變；不得假裝 diff 一定非空。

## 6.4 初始 contract mapping

至少將現有 reconcile component 補齊：

| Component | Effects |
|---|---|
| `freeipa-identity` | `identity.users`, `identity.groups`, `identity.hostgroups`, `identity.netgroups`, `access.hbac`, `access.sudo`, `access.grants`, `storage.nfs.identity` |
| `freeipa-dns` | `dns.zones`, `dns.records` |
| `freeipa-dns-client` | `network.resolver` |
| `freeipa-ca-trust` | `trust.ca` |
| `freeipa-server-replica` | `identity.freeipa_replica` |
| `freeipa-realm-replacement` | `identity.realm_membership` |
| `pilot-gateway-scope` | `identity.hostgroups`, `access.hbac` |
| `internal-endpoint` | `network.endpoints`, `dns.records`, `tls.certificates`, `reverse_proxy.routes` |
| `prometheus` | `monitoring.scrape_targets` |

這張表與設計基準 commit 的 `Reconcile: true` entries MUST 完全相等。若 implementation 時 `deployCatalog` 又新增其他 reconciler，實作 PR MUST 先擴充 known registry、在本表記錄設計決定，再補 contract effects；不得由實作者臨場猜一個字串只為讓 test PASS。

## 6.5 freeipa-identity 範例

```yaml
schemaVersion: 1
id: freeipa-identity
role: freeipa-server

effects:
  - identity.users
  - identity.groups
  - identity.hostgroups
  - identity.netgroups
  - access.hbac
  - access.sudo
  - access.grants
  - storage.nfs.identity

specs:
  ...
```

## 6.6 Cross-layer lint

新增 test：

```text
cmd/pilot/cmd/deploy_catalog_effects_test.go
```

規則：

```text
for entry in deployCatalog:
    if entry.Reconcile:
        contract(entry.Key) MUST exist
        contract(entry.Key).Effects MUST NOT be empty
```

test MUST 同時鎖：

```text
set(deployCatalog where Reconcile=true)
    == set(§6.4 expected mapping keys)
```

並逐 component 比對 exact effect set，避免只檢查 non-empty 而讓錯誤 domain 靜默 routing。

不得在 `deployPlaybook` 再新增一份：

```go
Effects []string
```

Contract 是唯一 source of truth。

---

# 7. 使用者設定：`integrations.yaml`

## 7.1 預設位置

Workspace：

```text
<workspace>/
├── hosts.yml
├── inventory.yml
├── integrations.yaml
├── group_vars/
└── .vault/
```

Default：

```text
<workspace>/integrations.yaml
```

檔案不存在：

```text
outbound webhook disabled
```

不得產生 warning，普通 deploy/reconcile/access/gateway command 也不得因本功能開啟／migrate webhook outbox 或建立 workflow publication state。這是「未啟用 integration 時舊行為不變」的明確 fast path。使用者明確呼叫 `pilot webhook status/lint/flush` 時可依該 subcommand 契約開啟 store；不屬於普通 operation fast path。

檔案存在但 invalid：

```text
fail before any remote mutation
```

## 7.2 完整範例

```yaml
schema_version: 1

# 一個 stable source identity。
# 同一套 external system 若接收多個 Pilot workspace，靠此欄位區分來源。
source_id: linker-infra-prod

webhooks:
  - name: external-user-host-directory
    enabled: true

    endpoint: https://other-team.example.com/api/v1/pilot/events

    projection: user_host_access_v1

    events:
      # 每次 deploy 成功，送完整最新 snapshot
      - operation: deploy
        result: success
        payload: snapshot

      # deploy 失敗也通知，但只送 publication-state diff。
      # failure state 會明確標記 authoritative=false。
      - operation: deploy
        result: failure
        payload: diff

      # reconcile 只有 identity/access semantics 才送。
      - operation: reconcile
        result: success
        effects_any:
          - identity.*
          - access.*
        payload: both

      - operation: reconcile
        result: failure
        effects_any:
          - identity.*
          - access.*
        payload: both

    auth:
      type: hmac_sha256
      secret_env: PILOT_EXTERNAL_DIRECTORY_WEBHOOK_SECRET

    tls:
      # 不設定時使用 OS trust store。
      # 私有 CA 可指定 PEM bundle。
      ca_file: /etc/pilot/ca/external-team.pem

    delivery:
      timeout: 5s
      max_attempts: 10
      initial_backoff: 30s
      max_backoff: 30m
```

這份設定的 semantics：

| Operation | Result | Effects | Action |
|---|---|---|---|
| deploy | success | 任意 | snapshot |
| deploy | failure | 任意 | diff |
| reconcile | success | identity/access | snapshot + diff |
| reconcile | failure | identity/access | snapshot + diff |
| reconcile | success | only `dns.*` | skip |
| reconcile | failure | only `dns.*` | skip |

## 7.3 Config model

```go
type Config struct {
    SchemaVersion int             `yaml:"schema_version"`
    SourceID      string          `yaml:"source_id"`
    Webhooks      []WebhookConfig `yaml:"webhooks"`
}

type WebhookConfig struct {
    Name       string            `yaml:"name"`
    Enabled    bool              `yaml:"enabled"`
    Endpoint   string            `yaml:"endpoint"`
    Projection string            `yaml:"projection"`
    Events     []EventRule       `yaml:"events"`
    Auth       AuthConfig        `yaml:"auth"`
    TLS        TLSConfig         `yaml:"tls"`
    Delivery   DeliveryConfig    `yaml:"delivery"`
}

type EventRule struct {
    Operation  OperationKind `yaml:"operation"`
    Result     ResultClass   `yaml:"result"`
    EffectsAny []string      `yaml:"effects_any"`
    Payload    PayloadMode   `yaml:"payload"`
}

type AuthConfig struct {
    Type      AuthType `yaml:"type"`
    SecretEnv string   `yaml:"secret_env"`
}

type TLSConfig struct {
    CAFile            string `yaml:"ca_file"`
    AllowInsecureHTTP bool   `yaml:"allow_insecure_http"`
}

type DeliveryConfig struct {
    Timeout        time.Duration `yaml:"timeout"`
    MaxAttempts    int           `yaml:"max_attempts"`
    InitialBackoff time.Duration `yaml:"initial_backoff"`
    MaxBackoff     time.Duration `yaml:"max_backoff"`
}

type PayloadMode string

const (
    PayloadSnapshot PayloadMode = "snapshot"
    PayloadDiff     PayloadMode = "diff"
    PayloadBoth     PayloadMode = "both"
)
```

Raw YAML decoding MUST retain field-presence information for `enabled` and every delivery field（例如 raw struct 使用 pointers），再 normalize 成 runtime config。V1 不允許因 Go zero value 而默默把「漏寫」解讀為另一種安全策略。

Defaults：

| Field | Default |
|---|---|
| `enabled` | 無；MUST explicit `true` 或 `false` |
| `tls.ca_file` | empty，使用 OS trust store |
| `tls.allow_insecure_http` | `false` |
| `delivery.timeout` | `5s` |
| `delivery.max_attempts` | `10` |
| `delivery.initial_backoff` | `30s` |
| `delivery.max_backoff` | `30m` |

## 7.4 Validation

MUST：

- `schema_version == 1`
- `source_id` 符合 `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`，不允許 whitespace/control character
- `webhooks` 必須有 `1..16` entries；要完全關閉可移除檔案或將每個 entry 明確設 `enabled: false`
- webhook `name` unique
- webhook `name` non-empty，且符合 `^[a-z][a-z0-9_-]{0,62}$`
- `enabled` 必須明確出現
- endpoint 是 absolute URL，host non-empty，不得含 URL userinfo、query 或 fragment；憑證必須使用 `auth`，不得塞在 URL
- endpoint scheme 只能是 `https`；只有 `tls.allow_insecure_http: true` 時可用 `http`，並顯示 warning
- `projection == user_host_access_v1`（V1）
- 每個 webhook 至少一個 event rule
- 同一 webhook 的 `(operation, result)` MUST unique
- operation 只能：
  - `deploy`
  - `reconcile`
- result 只能：
  - `success`
  - `failure`
  - `cancelled`
- payload 只能：
  - `snapshot`
  - `diff`
  - `both`
- `effects_any`：
  - empty = 不做 effect filter
  - 只能用在 `operation: reconcile`；`deploy` rule 必須 empty，因為 V1 不保證每個普通 deploy component 都有 effects
  - exact effect 必須是 known effect
  - wildcard 只能是 trailing namespace wildcard，例如：
    ```text
    identity.*
    access.*
    ```
  - 不支援 regex / arbitrary glob
- auth secret 只能存 env var **名稱**
- `auth` 必填
- `auth.type` 只能是 `hmac_sha256` 或 `bearer`；V1 不支援 unauthenticated mode
- `auth.secret_env` 必填且符合 `^[A-Z_][A-Z0-9_]*$`
- `tls.ca_file` 若非空，MUST 是 execution controller 上的絕對路徑、regular file、可讀 PEM bundle；在 mutation 前檢查
- `delivery.timeout` 必須在 `100ms..30s`
- `delivery.max_attempts` 必須在 `1..100`
- `delivery.initial_backoff` 必須在 `1s..24h`
- `delivery.max_backoff` 必須在 `initial_backoff..24h`
- YAML unknown fields MUST fail。

整份 YAML 的 schema、required fields、enum、URL shape 與 duplicate identity 檢查會套用到 enabled 與 disabled entries；但 CA file readability、secret env 與 HTTP client 建立這類 runtime readiness 只對 `enabled: true` entries 執行。所有 entries 都 disabled 時不產生新 event、不讀 secret env、不建立 network client；若 DB 已有同 identity pending rows，status/flush 視為 `paused_config`。

HTTP client MUST 使用自有 `http.Client` 並設定：

```text
CheckRedirect => always return http.ErrUseLastResponse
```

V1 不跟隨任何 3xx redirect，避免把 body、Bearer header 或 HMAC headers 轉送到 config 未授權的 host。3xx 分類為 non-retryable `http_redirect`，進 dead-letter。

### 7.4.1 Config identity 與 pending event

Pending event dispatch MUST 用 exact key：

```text
(source_id, webhook_name)
```

上述是 wire/logical consumer identity。因預設 `--data-dir` 可被多個 workspace 共用，local store query MUST 再加上不出 wire 的 `workspace_key`：

```text
workspace_key = sha256(canonical absolute --dir workspace path)
store key    = (workspace_key, source_id, webhook_name)
```

Canonical path 必須 clean/absolute，且在可解析時先 resolve symlinks。`pilot webhook status/flush` 只能查詢當前 workspace key。

- `source_id` 改變代表新的 publication source；舊 source 的 pending event 變成 `orphaned_config`，不得送到新 source。
- webhook `name` 改名代表新 logical consumer；舊名稱同樣 `orphaned_config`。
- 同名 webhook 的 endpoint、CA、auth env 名稱、secret value 或 delivery policy rotation MAY 改變；pending immutable body 使用 current config 的 transport/retry policy。
- `enabled: false` 時既有 pending event 進 `paused_config`，不增加 attempt；重新 enable 後恢復 `pending`。
- event rules 或 payload mode 的後續變更只影響新 event，不得重寫已 enqueue 的 body。

Config 成功 parse 且 store open 後，MUST 先在一個 transaction 內 reconcile 這些 config states，再開始 operation/flush。`paused_config -> pending` 保留 `attempt_count` 與原 `next_attempt_at`；若已過期則立即 due。轉為 `orphaned_config` 時同步套用 terminal payload compaction，刪除該舊 logical identity 的 cursor snapshot（重新加入時必須 bootstrap），且不可因未來同名 config 回來而自動復活。

Store MUST 保留 workspace 與 current `source_id` 的 binding，才能在 source change 時只 orphan 該 workspace 的舊 rows。同一 data-dir 內一個 `source_id` 不得同時 bind 到兩個 workspace key，否則 sequence/cursor identity 會衝突，readiness MUST fail。Workspace 移動後若仍使用同一 data-dir/source ID，V1 fail closed 並要求用原 `--dir` 先 flush／清理，或改用新 data-dir/source ID；V1 不自動推測 workspace rename。

## 7.5 Effect matching

```yaml
effects_any:
  - identity.*
  - access.sudo
```

若 operation effects：

```text
dns.records
identity.users
```

=> match。

若：

```text
dns.records
dns.zones
```

=> no match。

Prefix wildcard：

```text
identity.*
```

matches：

```text
identity.users
identity.groups
identity.hostgroups
```

不 matches：

```text
identity
access.identity
```

---

# 8. Operation Workflow Model

## 8.1 為什麼需要 workflow_id

既有 delivery `run_id` 是一個 transaction 的 evidence ID。

一次 top-level deploy 可能執行：

```text
workflow_id = W1

run_id = R1 docker
run_id = R2 prometheus
run_id = R3 alertmanager
```

Webhook 要表達：

```text
一次使用者操作
```

因此 MUST 建立：

```go
type WorkflowID string
```

在 static integration readiness 通過、component／grant selection 已確定、任何 remote mutation 開始前生成一次 lowercase RFC 4122 UUIDv4。

Cancellation boundary：

- 在 `workflow_id` 生成前取消：沒有 workflow，也不發 event；
- 在 `workflow_id` 生成後但 mutation 前取消：`result=cancelled`、`application_consistency=unchanged`；
- mutation 開始後收到 cancel/context interruption：`result=cancelled`、`application_consistency=unchanged_or_partial`；
- 若 config 沒訂閱 `cancelled`，只完成本地 workflow/evidence，不 enqueue webhook。

## 8.2 Workflow result

```go
type WorkflowResult struct {
    WorkflowID string

    Operation OperationKind

    StartedAt  time.Time
    FinishedAt time.Time

    RequestedComponents []string
    ExecutedComponents  []string
    CompletedComponents []string

    FailedComponent string

    Effects []contract.Effect

    DeliveryRuns []DeliveryRunResult

    Result ResultClass

    ApplicationConsistency StateConsistency
    ConfirmedEffects       []contract.Effect
}

type DeliveryRunResult struct {
    RunID      string
    Components []string
    Outcome    delivery.Outcome
    FailedStep string
}
```

## 8.3 Component sets

`requested_components`：

> 使用者/automation 在 top-level flow 選的 component。

`executed_components`：

> 實際開始執行的 component，包括 Pilot 自動加入的 required `sameHosts` dependency。

`completed_components`：

> 完整 transaction 成功的 component。

`failed_component`：

> terminal failure 發生時的 component；若無法精確歸屬則空值。

Webhook routing 的 `effects` MUST 至少包含：

```text
requested_components 的 effects union
```

並 SHOULD 加入實際 auto-executed dependency effects。

如此：

```text
使用者選 freeipa-identity
preflight 就失敗
```

仍可 routing 到：

```text
identity.*
access.*
```

而不會因 playbook 尚未開始就漏掉 failure notification。

`confirmed_effects`：

> 已成功完成 transaction 的 components effect union。整個 workflow 成功時通常等於 executed effects；failure/cancelled 時 MAY 為子集。它只描述本次 operation 證明過的 domain，不描述 snapshot 內其他 declarative domain。

Wire normalization：`requested_components`、`executed_components`、`completed_components`、`effects`、`confirmed_effects` 全部 lexical sort + dedupe；`delivery_runs` 保留真實 execution order，同一 run 的 `components` 也 sort + dedupe。不得依 Go map iteration 產生 wire order。這些 non-omitempty arrays 與 `delivery_runs` 無元素時必須 encode 為 `[]`，不得為 `null`。

Dedicated frontends 的 component/result mapping：

- `pilot gateway-scope reconcile/enable-auto/disable-auto`：requested/executed component 都是 `pilot-gateway-scope`；若它未使用 `internal/delivery.Transaction`，`delivery_runs=[]`。
- `pilot access reconcile <roster-file> --once`：requested/executed component 是 `freeipa-identity`，但 routing effects 僅使用 §1 表列的 access subset，不能錯稱整份 identity roster 都已完成。
- breakglass activate/deactivate：component sets 為空、`delivery_runs=[]`、effects 使用 §1 表列值；event MUST 另外帶 bounded `operation.subject={"kind":"breakglass","name":"<grant>"}`，不得帶 reason、ticket、actor 或其他可能敏感的 activation detail。

Direct frontend success/failure 必須由 structured result 建立，禁止解析 CLI/error string。若既有 helper 尚未回傳 structured result，必須先加 backward-compatible result API，再接 publication。

Dedicated frontend 不得因 `delivery_runs=[]` 而推導成 unknown；其 structured result MUST 直接給出：

| Frontend terminal state | Public result | Application consistency | Confirmed effects | Authoritative candidate |
|---|---|---|---|---:|
| 全部預期 mutation/verification 完成 | `success` | `confirmed_for_effects` | 該 frontend routing effects | true |
| mutation 前拒絕／失敗 | `failure` | `unchanged` | empty | false |
| mutation 後失敗但有 structured completed phases | `failure` | `partial` | 只列已證明 effects | false |
| mutation 後無法證明邊界 | `failure` | `partial_or_unknown` | 只列已證明 effects；可為 empty | false |

`authoritative candidate=true` 仍必須同時通過 projection `available/source_complete` 條件才能寫成 wire `authoritative=true`。

---

# 9. Internal Outcome → Public Result Mapping

Wire contract 透過每個 `delivery_runs[].outcome` 保留：

```text
internal delivery.Outcome value
```

同時提供簡單的：

```text
result = success | failure | cancelled
```

固定 mapping（`authoritative` 仍須同時滿足 projection `source_complete=true`）：

| `delivery.Outcome` | Public result | Application consistency | Authoritative |
|---|---|---|---:|
| `success` | `success` | `confirmed_for_effects` | true |
| `partial_success` | `success` | `partial` | false |
| `failed` | `failure` | `partial_or_unknown` | false |
| `partial_failed` | `failure` | `partial_or_unknown` | false |
| `rolled_back` | `failure` | `rolled_back` | false |
| `rollback_failed` | `failure` | `unknown` | false |
| `evidence_failed` | `failure` | `unknown` | false |
| `authorization_required` | `failure` | `unchanged_or_unknown` | false |
| `cancelled` | `cancelled` | `unchanged_or_partial` | false |

多 component workflow：

```text
任一 required transaction failure
    -> workflow result = failure

全部 terminal transaction success
    -> workflow result = success
```

多 transaction 的聚合規則 MUST deterministic：

1. `confirmed_effects` = 所有 structured completed/success transactions 的 effects union，sort + dedupe。
2. Public result precedence：任一 failure-class outcome → `failure`；否則任一 `cancelled` → `cancelled`；否則為 `success`。
3. 全部 outcome 都是 `success` 才是 `confirmed_for_effects`。
4. 含 `rollback_failed` 或 `evidence_failed` → `unknown`。
5. 含 `failed` 或 `partial_failed` → `partial_or_unknown`。
6. 含 `cancelled` → 依是否已開始 mutation 為 `unchanged` 或 `unchanged_or_partial`。
7. 含 `rolled_back` 只有在「所有已開始的 mutation 都有 structured rollback success，且沒有其他 completed mutation」時可為 `rolled_back`；否則為 `partial_or_unknown`。
8. 只含 `authorization_required` 且證明 mutation 未開始時為 `unchanged`；無法證明時為 `unchanged_or_unknown`。
9. 剩餘含 `partial_success` 的 success workflow 為 `partial`。

上述 4→9 依列出的 precedence 先後套用；實作不得依 component 執行順序得到不同結果。

`partial_success` 的 CLI 可能仍是 exit 0，但 webhook MUST 保留：

```json
{
  "result": "success",
  "delivery_runs": [{"outcome":"partial_success"}],
  "state": {
    "basis": "pilot_declared",
    "source_complete": true,
    "application_consistency": "partial",
    "confirmed_effects": [],
    "authoritative": false
  }
}
```

外部 consumer 不得被簡化的 `result=success` 誤導。

---

# 10. Structured Delivery Result

目前 `delivery.Transaction.Run()` 回傳：

```go
(outcome Outcome, err error)
```

為避免 webhook 從 error string parse：

```text
"apply failed:"
"verify failed:"
```

新增 backward-compatible structured method：

```go
type Result struct {
    Outcome    Outcome
    FailedStep string
}

func (t Transaction) RunResult(ctx context.Context) (Result, error)
```

既有 API 保留：

```go
func (t Transaction) Run(ctx context.Context) (Outcome, error) {
    result, err := t.RunResult(ctx)
    return result.Outcome, err
}
```

不得為 webhook 破壞其他 transaction callers。

---

# 11. State Projection：`user_host_access_v1`

## 11.1 定義

V1 只提供一個 external projection：

```text
user_host_access_v1
```

它不是：

```text
hosts.yml JSON
roster JSON
```

而是：

```text
Pilot canonical declarative sources 的 sanitized state（basis=pilot_declared）
```

V1 projection涵蓋 hosts.yml hosts、roster users、identity groups、FreeIPA hostgroups，以及 resolved login/sudo access。Roster hosts 只用來把 identity/access 參照解析到 hosts.yml host。Netgroups、NFS shares/automount、DNS/TLS/monitoring entities尚未進 projection；相關 effect 仍可觸發 operation event，但 snapshot ID MAY 不變。Consumer 不得把「event有該 effect」解讀成 payload一定含該 domain entity。

## 11.2 Snapshot shape

```go
type UserHostAccessSnapshotV1 struct {
    Hosts      []ProjectedHost      `json:"hosts"`
    Users      []ProjectedUser      `json:"users"`
    Groups     []ProjectedGroup     `json:"groups"`
    Hostgroups []ProjectedHostgroup `json:"hostgroups"`

    Access ProjectedAccess `json:"access"`
}

type ProjectedHost struct {
    ID                     string            `json:"id"`
    Name                   string            `json:"name"`
    Source                 string            `json:"source"`
    FQDN                   string            `json:"fqdn,omitempty"`
    Address                string            `json:"address,omitempty"`
    Env                    string            `json:"env,omitempty"`
    Roles                  []string          `json:"roles"`
    DeploymentAvailability string            `json:"deployment_availability,omitempty"`
    Annotations            map[string]string `json:"annotations,omitempty"`
}

type ProjectedUser struct {
    Name            string   `json:"name"`
    DisplayName     string   `json:"display_name,omitempty"`
    Email           string   `json:"email,omitempty"`
    Enabled         bool     `json:"enabled"`
    UID             *int     `json:"uid,omitempty"`
    GID             *int     `json:"gid,omitempty"`
    EffectiveGroups []string `json:"effective_groups"`
}

type ProjectedGroup struct {
    Name        string   `json:"name"`
    Category    string   `json:"category,omitempty"`
    Type        string   `json:"type,omitempty"`
    Description string   `json:"description,omitempty"`
    Users       []string `json:"users"`
    Groups      []string `json:"groups"`
}

type ProjectedHostgroup struct {
    Name             string   `json:"name"`
    Description      string   `json:"description,omitempty"`
    HostIDs          []string `json:"host_ids"`
    Hostgroups       []string `json:"hostgroups"`
    EffectiveHostIDs []string `json:"effective_host_ids"`
}

type ProjectedAccess struct {
    Login []ProjectedLoginAccess `json:"login"`
    Sudo  []ProjectedSudoAccess  `json:"sudo"`
}
```

## 11.3 Host source

Host entity 只來自 `hosts.yml`；canonical roster 的 hosts 只提供
FreeIPA identity/access 參照，不另外產生 host entity：

```text
<workspace>/hosts.yml              -> source=inventory
canonical roster hosts[]           -> roster FQDN/address mapping only
```

Inventory side 使用：

```text
internal/inventory.Parse
```

MUST include：

```text
name
ansible_host -> address
env
roles
deployment_availability
annotations
```

Stable IDs：

```text
inventory host: inventory:<hosts.yml name>
```

Roster `hosts[]` MUST include a real FQDN and IPv4 address, but its entries
are not emitted as `snapshot.hosts[]` entities. Each present roster host MUST
match exactly one `hosts.yml` host by `ip_address == ansible_host`; the
projection maps its FQDN references to that inventory host ID. Missing or
ambiguous matches make the projection unavailable. `state: absent` roster
hosts are omitted from the mapping.

MUST NOT include：

```text
ssh_key_file
arbitrary Extra vars
secret-like host vars
controller filesystem paths
```

`annotations` 已被 Pilot 定義為 descriptive non-secret metadata，因此可以進 projection。

## 11.4 Inventory host mapping

MUST NOT invent a host mapping from a short name or reverse DNS：

```text
short inventory hostname + domain 猜 FQDN
IP reverse DNS 猜 FQDN
```

The current single-source projection uses an exact, unique
`ansible_host == roster.ip_address` mapping to resolve roster access
references to `inventory:<hosts.yml name>`. It never emits a second roster
host entity and fails closed if the address match is missing or ambiguous.

Access target MUST 使用 inventory host ID：

```text
inventory:<hosts.yml name>
```

因此每個 `ProjectedLoginAccess.HostIDs`／`ProjectedSudoAccess.HostIDs` 都能 join 到 `snapshot.hosts[].id`。Projection builder MUST 驗證 referential integrity；任何 explicit access host 無法映射到 present inventory host 時，projection unavailable，不得輸出 dangling reference。`all_hosts=true` 的 universe 是 snapshot 中的 inventory hosts。

## 11.5 Roster source

Roster path MUST 透過 deploy/reconcile 已解析的 inventory/host-vars semantics 找到：

```text
freeipa_roster_file
```

MUST 抽出並 reuse `ensureFreeIPARostersCurrentSnapshot` 的 target/path resolution 原則；不能直接呼叫目前會 warning-and-continue 的 migration helper來當 authoritative reader。Outbound resolver 必須回傳 typed result：`absent`、`one(path)` 或 `multiple(paths)`。

MUST NOT 用：

```text
掃 workspace 找第一個有 users: key 的 YAML
```

作 authoritative webhook source。

若同一 workspace 的 effective FreeIPA targets 指向不同 canonical roster path：

```text
projection build MUST fail closed
```

error class：

```text
multiple_roster_sources
```

不得偷偷 merge。

## 11.6 Encrypted roster

Pilot 已有 encrypted roster 的 in-memory `ansible-vault view` pattern。

新增 shared read-only helper，例如：

```go
type RosterReadOptions struct {
    VaultPasswordFile string
}

func BuildExternalRosterProjection(
    path string,
    opts RosterReadOptions,
    now time.Time,
    stateDir string,
) (ExternalRosterProjection, error)
```

要求：

1. encrypted roster decrypt in memory。
2. 不建立 plaintext persistent temp file。
3. secret fields 不可進 return type。
4. plaintext 不可進 error。
5. plaintext 不可 log。

Vault password file resolve order：

```text
1. 本次 deploy/reconcile 已使用的 vaultInput.VaultPasswordFile
2. PILOT_VAULT_PASSWORD_FILE（若 implementation 採用此 fallback）
3. roster plaintext -> 不需 password file
4. encrypted + 無 reusable password file -> projection unavailable
```

`--ask-vault-pass` 但沒有 reusable password file 時，V1 不得試圖把使用者輸入的 password 存進 DB 或 env。

## 11.7 Projection unavailable

若 operation webhook 本身可發送，但 projection 因 roster decrypt/source error 無法建立：

仍 SHOULD 發送 terminal event，但 projection fields 不可用。下例假設 operation 本身已成功並證明 `access.hbac`：

```json
{
  "state": {
    "available": false,
    "basis": "pilot_declared",
    "source_complete": false,
    "authoritative": false,
    "application_consistency": "confirmed_for_effects",
    "confirmed_effects": ["access.hbac"],
    "error_class": "projection_unavailable"
  }
}
```

`application_consistency` 與 `confirmed_effects` MUST 原樣複製 `WorkflowResult`；不得因 projection error、serialization error 或 payload size error 改寫。

MUST NOT：

```text
把 users/access 當空陣列送出，讓 consumer 誤判全部使用者已刪除。
```

cursor MUST NOT advance。

`snapshot` 與 `diff` fields MUST omitted；不得送 `null`、空 object 或空 entity arrays。Metadata-only unavailable event MUST 小於 64 KiB。

## 11.8 Entity inclusion rules

Roster projection MUST 使用同一個 injected `now`，不得在 users、grants、breakglass 各自呼叫 `time.Now()`。

- users `state: absent`：omit。
- users present/disabled：保留 entity；`ProjectedUser.Enabled` 必須同時滿足 roster enabled flag 與 account-policy lifecycle active。
- groups/hosts `state: absent`：omit。
- hostgroups `state: absent`：omit；direct membership 與 nested hostgroups保留，並輸出 transitive `EffectiveHostIDs`。
- group membership 引用 absent user/group：projection unavailable（正常 roster validation應更早拒絕）。
- `EffectiveGroups` 是 present group graph 的 transitive membership，sort/dedupe 後輸出；disabled user仍可顯示 membership，但不得出現在 effective access users。
- unknown optional roster sections不會自動進 projection；只有明列在 typed projection struct 的 allowlist fields 可發布。

---

# 12. Effective Access Projection

## 12.1 原則

External consumer 不應重新實作：

```text
nested group expansion
nested hostgroup expansion
HBAC semantics
sudo semantics
temporary grant lifecycle
breakglass activation
```

Pilot MUST 輸出 resolved access。

## 12.2 Login access

```go
type ProjectedLoginAccess struct {
    ID         string     `json:"id"`
    Source     string     `json:"source"`
    Rule       string     `json:"rule"`
    Users      []string   `json:"users"`
    AllHosts   bool       `json:"all_hosts"`
    HostIDs    []string   `json:"host_ids,omitempty"`
    Services   []string   `json:"services"`
    ValidUntil *time.Time `json:"valid_until,omitempty"`
}
```

`Source`：

```text
static_hbac
temporary_grant
breakglass
```

Stable ID：

```text
static_hbac:<rule>
temporary_grant:<grant>
breakglass:<grant>
```

## 12.3 Sudo access

```go
type ProjectedSudoAccess struct {
    ID             string     `json:"id"`
    Source         string     `json:"source"`
    Rule           string     `json:"rule"`
    Users          []string   `json:"users"`
    AllHosts       bool       `json:"all_hosts"`
    HostIDs        []string   `json:"host_ids,omitempty"`
    AllCommands    bool       `json:"all_commands"`
    Commands       []string   `json:"commands,omitempty"`
    DeniedCommands []string   `json:"denied_commands,omitempty"`
    RunAsUsers     []string   `json:"run_as_users"`
    RunAsGroups    []string   `json:"run_as_groups"`
    Options        []string   `json:"options"`
    ValidNotBefore *time.Time `json:"valid_not_before,omitempty"`
    ValidNotAfter  *time.Time `json:"valid_not_after,omitempty"`
}
```

Source：

```text
static_sudo
sudo_grant
```

Stable ID：

```text
static_sudo:<rule>
sudo_grant:<grant>
```

## 12.4 Reuse existing semantics

Static rules：

```text
EffectiveHBACAccessList
EffectiveSudoAccessList
```

Temporary/sudo grants：

```text
CompileGrants
EvaluateGrantLifecycle
```

Active breakglass：

```text
internal/accessgrants runtime activation state
```

Reuse 不代表直接複製現有 return value。特別是現有 `EffectiveSudoAccess` 沒有完整展開 direct deny commands、deny command groups、run-as 與 options；outbound builder MUST 擴充 shared resolver，不得以不完整欄位冒充 effective sudo。Builder MUST 套用以下 effective filter：

1. static HBAC `state: absent` 或 `enabled: false`：omit；現有 `EffectiveHBACAccessList` 會回傳 `Enabled`，不能在 wire projection 丟掉該欄後仍保留 rule。
2. static sudo absent：omit。
3. temporary grant 只有 `EvaluateGrantLifecycle(...) == active` 才輸出；`ValidUntil` 必須等於有效窗口終點。
4. sudo grant 只有 `EvaluateGrantLifecycle(...) == active` 才輸出；未到 `valid_not_before` 或已過 `valid_not_after` 都 omit。仍保留 not-before/not-after，讓 consumer 在長時間沒有新 event 時也能強制終點時間。
5. breakglass 只有 `Activation.IsActive(now)` 且 roster definition仍 present 時輸出；`ValidUntil=activation.ExpiresAt`。
6. 每條 access 的 users 必須與「present 且 Enabled=true」user set 取交集；結果為空的 rule omit。
7. explicit hosts/hostgroups 展開後全部轉成對應的 `inventory:<hosts.yml name>` IDs；任何 dangling、missing 或 ambiguous address mapping 使整個 projection unavailable。
8. `all_hosts=true` 時 `host_ids` 必須 omitted；consumer 以 snapshot 中的 inventory hosts 作 universe。

Static sudo 的 `commands` 必須是 direct allow commands 與 allow command groups 的 resolved union；`denied_commands` 必須是 direct deny commands 與 deny command groups 的 resolved union。`run_as_users`、`run_as_groups`、`options` 必須原樣語意化、sort/dedupe 後輸出。任一 referenced user/group/host/hostgroup/command-group 不存在或 absent，必須使 projection unavailable，不得像現有 read-only helper 一樣 silent skip。

任一 entity type 內出現 duplicate stable key（host `id`、user/group/hostgroup `name`、access `id`）也必須 projection unavailable，否則 diff upsert/delete 無法定義。

若 roster 有兩筆同名 active breakglass activation，builder MUST collapse 成單一 `breakglass:<grant>` entity，`ValidUntil` 取目前 active records 的最大 expiry；不得因 activation history 產生 duplicate diff keys。

Implementation SHOULD 把目前分散在 `cmd/pilot/cmd/mcp_edit_resources.go` 的 sanitized roster reading，逐步抽成 reusable internal package；MUST NOT 讓 outbound integration import `cmd/pilot/cmd`。

---

# 13. Deterministic Snapshot

## 13.1 Snapshot ID

Snapshot ID：

```text
sha256:<hex>
```

hash input 只包含 semantic state：

```text
hosts
users
groups
hostgroups
access
```

MUST NOT 包含：

```text
generated_at
event_id
workflow_id
delivery outcome
webhook name
```

否則相同狀態每次 deploy 都會得到不同 snapshot ID。

## 13.2 Canonicalization

Hash 前 MUST：

- hosts sort by `id`
- users sort by `name`
- groups sort by `name`
- hostgroups sort by `name`
- access sort by `id`
- roles sort
- effective groups sort
- users/host_ids/services/commands/denied_commands/run_as_users/run_as_groups/options sort
- 所有非-omitempty collection 的 nil/empty normalize 成 JSON `[]`；`annotations` 空值 omit；禁止同一語意有時 hash 成 `null`、有時 hash 成 `[]`
- map 使用 deterministic JSON key order
- timestamps UTC RFC3339Nano

API：

```go
func CanonicalizeSnapshot(in UserHostAccessSnapshotV1) UserHostAccessSnapshotV1
func SnapshotID(in UserHostAccessSnapshotV1) string
```

## 13.3 Same state still sends event

使用者若設定：

```yaml
- operation: deploy
  result: success
  payload: snapshot
```

即使：

```text
previous snapshot_id == current snapshot_id
```

MUST 仍發 terminal event。

原因：

```text
使用者要求的是每次 deploy 成功通知
```

snapshot dedupe 不得吞掉 operation event。

---

# 14. Diff Semantics

## 14.1 定義

Diff 是：

```text
base authoritative publication snapshot
        ↓
current projection snapshot
```

稱為：

```text
state projection diff
```

不得稱：

```text
Ansible diff
operation mutation diff
live runtime diff
```

## 14.2 Cursor scope

Cursor key：

```text
wire lineage: (source_id, webhook_name, projection)
local store:  (workspace_key, source_id, webhook_name, projection)
```

`webhook_name` 是 logical consumer identity。

因此 endpoint failover：

```yaml
name: external-directory
endpoint: https://new-endpoint.example.com/...
```

可以保留同一條 diff lineage。

若這其實是新 consumer，使用者 MUST 改 `name`。

## 14.3 Diff shape

```go
type StateDiffV1 struct {
    BaseSnapshotID   string `json:"base_snapshot_id,omitempty"`
    TargetSnapshotID string `json:"target_snapshot_id"`
    Bootstrap        bool   `json:"bootstrap"`

    Hosts       EntityDiff[ProjectedHost]        `json:"hosts"`
    Users       EntityDiff[ProjectedUser]        `json:"users"`
    Groups      EntityDiff[ProjectedGroup]       `json:"groups"`
    Hostgroups  EntityDiff[ProjectedHostgroup]   `json:"hostgroups"`
    LoginAccess EntityDiff[ProjectedLoginAccess] `json:"login_access"`
    SudoAccess  EntityDiff[ProjectedSudoAccess]  `json:"sudo_access"`
}

type EntityDiff[T any] struct {
    Upsert []T      `json:"upsert"`
    Delete []string `json:"delete"`
}
```

`Upsert` 一律送完整 entity，不送 JSON Patch。

好處：

- consumer implementation 簡單；
- forward compatibility 較高；
- retry idempotent；
- 不需理解 field-level patch ordering。

## 14.4 Stable keys

| Entity | Diff key |
|---|---|
| Host | `id` |
| User | `name` |
| Group | `name` |
| Hostgroup | `name` |
| LoginAccess | `id` |
| SudoAccess | `id` |

## 14.5 First delivery

如果沒有 cursor：

```text
BaseSnapshotID = ""
Bootstrap = true
```

Diff：

```text
all current entities -> upsert
delete -> []
```

所以 `payload: diff` 也能 bootstrap 新 consumer。

## 14.6 Cursor advancement

只有同時滿足：

```text
HTTP delivery 2xx
AND state.authoritative == true
AND state.available == true
AND state.source_complete == true
```

才 advance cursor。

Failure event：

```text
authoritative=false
```

即使外部回 200，也不得改 authoritative cursor。

## 14.7 Pending event chain

同一 webhook MUST FIFO delivery。

如果 authoritative diff A 尚未 ACK，而新的 authoritative diff B 產生：

```text
B base MUST chain from A target
```

Event enqueue 時的 effective base 依序取：

```text
同 webhook 最後一筆尚未 ACK、authoritative=true 的 target snapshot
否則 current cursor snapshot
否則 empty bootstrap base
```

Outbox 必須保存 target snapshot content，使後續成功 ACK 時可以正確更新 cursor。Non-authoritative failure/cancel event 可以使用同一 effective base算顯示用 diff，但不會成為後續 authoritative chain 的 predecessor。

不得平行送同一 webhook 的兩個 state-mutating events。

## 14.8 Dead-letter / base mismatch

若前一個 authoritative diff 進入 dead-letter：

- 後續 `diff` event 若 base 無法對上 current cursor：
  ```text
  state = blocked_base_mismatch
  ```
- 後續 `snapshot` / `both` 可作為新的 self-contained convergence point，成功後重新建立 cursor。

Recovery event 發送前，dispatcher MUST 將 dead-letter 後、recovery sequence 前的 `diff`-only events 標成 `blocked_base_mismatch`。`both` event 遇到 base mismatch時，consumer MUST 以 snapshot atomic replace，忽略該 event 的 diff，再把 cursor 設為 target snapshot ID。

V1 不得默默重寫已嘗試發送過的 event body。唯一例外是 §22.3 已定義、進入 terminal state 後不再可送的 payload compaction；它不得復活或重送該 row。

---

# 15. Webhook Wire Contract V1

## 15.1 Envelope

每個 matched logical webhook 產生一個獨立 lowercase RFC 4122 UUIDv4 `event_id`；同 workflow 的不同 webhook 共用 `workflow_id`、但 `event_id` 不同。Retry 永遠使用原 `event_id`。

```json
{
  "schema_version": 1,
  "event_id": "f2db8d8c-...",
  "event_type": "pilot.operation.terminal",
  "created_at": "2026-09-15T06:30:00Z",

  "source": {
    "id": "linker-infra-prod",
    "pilot_version": "..."
  },

  "subscription": {
    "name": "external-user-host-directory",
    "sequence": 42
  },

  "operation": {
    "workflow_id": "3ad2...",
    "type": "reconcile",
    "result": "success",

    "requested_components": ["freeipa-identity"],
    "executed_components": ["freeipa-identity"],
    "completed_components": ["freeipa-identity"],

    "effects": [
      "identity.users",
      "identity.groups",
      "identity.hostgroups",
      "identity.netgroups",
      "access.hbac",
      "access.sudo",
      "access.grants",
      "storage.nfs.identity"
    ],

    "delivery_runs": [
      {
        "run_id": "...",
        "outcome": "success"
      }
    ],

    "started_at": "2026-09-15T06:28:11Z",
    "finished_at": "2026-09-15T06:29:58Z"
  },

  "state": {
    "projection": "user_host_access_v1",
    "projection_version": 1,
    "requested_payload": "both",

    "available": true,
    "basis": "pilot_declared",
    "source_complete": true,
    "application_consistency": "confirmed_for_effects",
    "confirmed_effects": ["identity.users", "identity.groups", "identity.hostgroups", "identity.netgroups", "access.hbac", "access.sudo", "access.grants", "storage.nfs.identity"],
    "authoritative": true,

    "snapshot_id": "sha256:...",
    "base_snapshot_id": "sha256:..."
  },

  "snapshot": {},
  "diff": {}
}
```

### 15.1.1 State field contract

| Field | Meaning |
|---|---|
| `basis` | V1 固定 `pilot_declared` |
| `available` | 本 event 是否包含完整 requested snapshot/diff payload |
| `source_complete` | canonical sources 是否完整解析；payload-too-large 可為 true但 available=false |
| `application_consistency` | 只描述本次 operation 對其 effects 的 structured apply/verify結果；不受 projection/delivery failure 改寫 |
| `confirmed_effects` | 本次已完成 components/frontends 證明的 effects；sorted unique |
| `authoritative` | 此 event ACK 後是否可前進 declared-state publication cursor |
| `error_class` | unavailable 時的 bounded allowlisted class；available 時 omit |

V1 `state.error_class` allowlist：

```text
projection_unavailable
multiple_roster_sources
serialization_failed
payload_too_large
```

這是 payload availability class，不是 `failure.class` 或 outbox delivery error；三者使用不同 typed enum，不得共用一個 free-form string。

`application_consistency` allowed values：

```text
confirmed_for_effects
partial
partial_or_unknown
rolled_back
unknown
unchanged
unchanged_or_unknown
unchanged_or_partial
```

`authoritative=true` MUST imply：

```text
available=true
source_complete=true
operation.result=success
application_consistency=confirmed_for_effects
```

反向不必成立，例如 `partial_success` 保持 non-authoritative。`confirmed_effects` MAY 為空（例如 Docker deploy），不得以空值推導 projection unavailable。

`operation.subject` 是 optional bounded object，目前只允許：

```json
{"kind":"breakglass","name":"<validated-grant-name>"}
```

所有其他 operation omit；不得把 arbitrary user input、reason、ticket 或 actor map 原樣放入。

## 15.2 `snapshot` mode

如果 config：

```yaml
payload: snapshot
```

Body：

```text
snapshot present
diff omitted
```

## 15.3 `diff` mode

```yaml
payload: diff
```

Body：

```text
diff present
snapshot omitted
```

Pilot outbox 內部仍 MUST 保存 target snapshot state，以便成功 ACK 後更新 cursor。

## 15.4 `both` mode

```yaml
payload: both
```

Body：

```text
snapshot present
diff present
```

兩者 MUST 指向相同：

```text
state.snapshot_id
diff.target_snapshot_id
```

---

# 16. Success Snapshot 範例

```json
{
  "schema_version": 1,
  "event_id": "94c0568d-6f66-4d26-bbd2-c2b207f7a183",
  "event_type": "pilot.operation.terminal",
  "created_at": "2026-09-15T06:30:00Z",

  "source": {
    "id": "linker-infra-prod",
    "pilot_version": "0.x"
  },

  "subscription": {
    "name": "external-user-host-directory",
    "sequence": 42
  },

  "operation": {
    "workflow_id": "d94cd98b-...",
    "type": "deploy",
    "result": "success",
    "requested_components": ["docker"],
    "executed_components": ["docker"],
    "completed_components": ["docker"],
    "effects": [],
    "delivery_runs": [
      {
        "run_id": "5a777...",
        "outcome": "success"
      }
    ],
    "started_at": "2026-09-15T06:28:11Z",
    "finished_at": "2026-09-15T06:29:58Z"
  },

  "state": {
    "projection": "user_host_access_v1",
    "projection_version": 1,
    "requested_payload": "snapshot",
    "available": true,
    "basis": "pilot_declared",
    "source_complete": true,
    "application_consistency": "confirmed_for_effects",
    "confirmed_effects": [],
    "authoritative": true,
    "snapshot_id": "sha256:10af..."
  },

  "snapshot": {
    "hosts": [
      {
        "id": "inventory:gpu-a01",
        "name": "gpu-a01",
        "source": "inventory",
        "address": "10.20.30.41",
        "env": "prod",
        "roles": [
          "docker",
          "freeipa-client"
        ],
        "deployment_availability": "required",
        "annotations": {
          "location": "DC1/Rack-A03/U18",
          "project": "llm-training",
          "owner": "ai-platform"
        }
      }
    ],

    "users": [
      {
        "name": "alice",
        "display_name": "Alice Wang",
        "email": "alice@example.internal",
        "enabled": true,
        "effective_groups": [
          "team-developers"
        ]
      }
    ],

    "groups": [
      {
        "name": "team-developers",
        "category": "team",
        "type": "posix",
        "users": ["alice"],
        "groups": []
      }
    ],

    "hostgroups": [
      {
        "name": "gpu-hosts",
        "host_ids": ["freeipa:gpu-a01.ipa.pilot.internal"],
        "hostgroups": [],
        "effective_host_ids": ["freeipa:gpu-a01.ipa.pilot.internal"]
      }
    ],

    "access": {
      "login": [
        {
          "id": "static_hbac:developer-ssh",
          "source": "static_hbac",
          "rule": "developer-ssh",
          "users": ["alice"],
          "all_hosts": false,
          "host_ids": [
            "freeipa:gpu-a01.ipa.pilot.internal"
          ],
          "services": ["sshd"]
        }
      ],
      "sudo": []
    }
  }
}
```

---

# 17. Success Diff 範例

假設 external consumer 上一次 ACK 的 state：

```text
snapshot_id = sha256:AAA
```

之後 roster 新增 Alice，再成功：

```bash
pilot reconcile
```

選：

```text
freeipa-identity
```

Webhook：

```json
{
  "schema_version": 1,
  "event_type": "pilot.operation.terminal",

  "operation": {
    "type": "reconcile",
    "result": "success",
    "requested_components": ["freeipa-identity"],
    "effects": [
      "identity.users",
      "identity.groups",
      "access.hbac"
    ]
  },

  "state": {
    "projection": "user_host_access_v1",
    "projection_version": 1,
    "requested_payload": "diff",
    "available": true,
    "basis": "pilot_declared",
    "source_complete": true,
    "application_consistency": "confirmed_for_effects",
    "confirmed_effects": ["identity.users", "identity.groups", "access.hbac"],
    "authoritative": true,
    "base_snapshot_id": "sha256:AAA",
    "snapshot_id": "sha256:BBB"
  },

  "diff": {
    "base_snapshot_id": "sha256:AAA",
    "target_snapshot_id": "sha256:BBB",
    "bootstrap": false,

    "hosts": {
      "upsert": [],
      "delete": []
    },

    "users": {
      "upsert": [
        {
          "name": "alice",
          "display_name": "Alice Wang",
          "enabled": true,
          "effective_groups": ["team-developers"]
        }
      ],
      "delete": []
    },

    "groups": {
      "upsert": [
        {
          "name": "team-developers",
          "category": "team",
          "type": "posix",
          "users": ["alice"],
          "groups": []
        }
      ],
      "delete": []
    },

    "hostgroups": {
      "upsert": [],
      "delete": []
    },

    "login_access": {
      "upsert": [
        {
          "id": "static_hbac:developer-ssh",
          "source": "static_hbac",
          "rule": "developer-ssh",
          "users": ["alice"],
          "all_hosts": false,
          "host_ids": ["freeipa:gpu-a01.ipa.pilot.internal"],
          "services": ["sshd"]
        }
      ],
      "delete": []
    },

    "sudo_access": {
      "upsert": [],
      "delete": []
    }
  }
}
```

這個 diff 即使：

```text
reconcile 前 roster 已經有 alice
reconcile 後 roster 仍然有 alice
```

仍正確，因為 base 是：

```text
last ACKed external publication state
```

不是 local file pre-state。

---

# 18. Failure Event 範例

假設：

```text
freeipa-identity
  users  applied
  groups applied
  hbac   applied
  sudo   failed
```

Webhook：

```json
{
  "schema_version": 1,
  "event_type": "pilot.operation.terminal",

  "operation": {
    "type": "reconcile",
    "result": "failure",
    "requested_components": ["freeipa-identity"],
    "executed_components": ["freeipa-identity"],
    "completed_components": [],
    "failed_component": "freeipa-identity",

    "effects": [
      "identity.users",
      "identity.groups",
      "access.hbac",
      "access.sudo",
      "access.grants"
    ],

    "delivery_runs": [
      {
        "run_id": "...",
        "outcome": "failed",
        "failed_step": "apply"
      }
    ]
  },

  "failure": {
    "class": "apply_failed",
    "phase": "apply",
    "component": "freeipa-identity"
  },

  "state": {
    "projection": "user_host_access_v1",
    "projection_version": 1,
    "requested_payload": "both",

    "available": true,
    "basis": "pilot_declared",
    "source_complete": true,
    "application_consistency": "partial_or_unknown",
    "confirmed_effects": [],
    "authoritative": false,

    "base_snapshot_id": "sha256:AAA",
    "snapshot_id": "sha256:BBB"
  },

  "snapshot": {
    "...": "post-failure Pilot projection"
  },

  "diff": {
    "base_snapshot_id": "sha256:AAA",
    "target_snapshot_id": "sha256:BBB",
    "bootstrap": false,
    "...": "non-authoritative projection delta"
  }
}
```

重要：

```text
failure event HTTP 200
```

仍：

```text
authoritative cursor 不 advance
```

所以後續完整成功仍會從上一個 authoritative state 收斂。

---

# 19. Failure Error Redaction

Wire MUST NOT 直接使用：

```go
err.Error()
```

因為 Ansible / shell / external command error 可能包含：

- argument values；
- remote stderr；
- credentials；
- paths；
- implementation details。

Wire 只提供 bounded structured class：

```go
type FailureInfo struct {
    Class     string `json:"class"`
    Phase     string `json:"phase,omitempty"`
    Component string `json:"component,omitempty"`
}
```

Allowed class：

```text
preflight_failed
preview_failed
apply_failed
verify_failed
idempotency_failed
rollback_failed
evidence_failed
authorization_required
```

`Class` 必須來自這個 typed allowlist，不是任意擴充的 free-form value。`Phase` 只能是 `prepare|preflight|preview|apply|verify|idempotency|rollback|evidence|authorization`；`Component` 只能來自已驗證的 contract/catalog stable ID，否則 omit。

完整本地 error 仍照現有 CLI / evidence path 處理，但不得放 external body。

Publication/outbox `last_error_class` 使用另一組 fixed enum，例如：

```text
missing_auth_secret
network_error
timeout
http_redirect
http_4xx
http_5xx
projection_unavailable
multiple_roster_sources
payload_too_large
local_persistence_error
```

`last_error_text` 只能由本 enum與 bounded status metadata組成；MUST NOT 保存 response body、request headers、full endpoint URL、raw `error.Error()` 或 TLS peer detail。HTTP status可保存數字。

---

# 20. Authentication

## 20.1 Supported V1 auth

```text
hmac_sha256
bearer
```

推薦：

```text
hmac_sha256
```

因為 Pilot 是 sender，可以對自己的 raw body 計算 signature。

## 20.2 HMAC config

```yaml
auth:
  type: hmac_sha256
  secret_env: PILOT_EXTERNAL_DIRECTORY_WEBHOOK_SECRET
```

Secret value：

```text
只能 runtime 從 environment 讀取
不得寫 integrations.yaml
不得寫 outbox
不得寫 delivery evidence
```

## 20.3 HMAC headers

```text
Content-Type: application/json
User-Agent: pilot/<version>

X-Pilot-Event-ID: <event_id>
X-Pilot-Event-Timestamp: <unix-seconds>
X-Pilot-Delivery-Attempt: <n>
Idempotency-Key: <event_id>

X-Pilot-Signature-256: sha256=<hex>
```

Signature input：

```text
<timestamp> "." <event_id> "." <raw-body>
```

Pseudo：

```go
mac := hmac.New(sha256.New, secret)
mac.Write([]byte(timestamp))
mac.Write([]byte("."))
mac.Write([]byte(eventID))
mac.Write([]byte("."))
mac.Write(rawBody)
```

Receiver SHOULD：

- timestamp freshness check；
- HMAC constant-time compare；
- event ID dedupe。

## 20.4 Bearer

```yaml
auth:
  type: bearer
  secret_env: PILOT_EXTERNAL_DIRECTORY_TOKEN
```

HTTP：

```text
Authorization: Bearer <secret>
```

不得 log。

## 20.5 Missing secret

如果 config schema 正確，但 runtime env 缺 secret：

```text
deploy/reconcile result 不變
outbox event 保留 pending
last_error_class = missing_auth_secret
```

後續環境補齊 secret 後可：

```bash
pilot webhook flush
```

---

# 21. TLS

預設 MUST：

```text
https
```

並使用 OS trust store。

Private CA：

```yaml
tls:
  ca_file: /etc/pilot/ca/external-team.pem
```

V1 SHOULD NOT 提供：

```yaml
insecure_skip_verify: true
```

避免正式 integration 輕易關閉 server identity verification。

若真的需要測試 plain HTTP，可提供 explicit：

```yaml
tls:
  allow_insecure_http: true
```

預設：

```text
false
```

且 CLI MUST 顯示 warning。

HTTPS client MUST 設 `tls.Config.MinVersion=tls.VersionTLS12`。`ca_file` 的 certificates 是 append 到 OS/system root pool，不是靜默取代；PEM 沒有任何可 parse certificate 時 readiness fail。Server name verification 使用 endpoint hostname，不提供 override 或 `insecure_skip_verify`。

---

# 22. Durable Outbox

## 22.1 為什麼一定要 outbox

Webhook 不可只有：

```go
http.Post(...)
```

否則：

```text
deploy success
network 2 秒斷線
process exit
event 永久消失
```

V1 MUST 先 durable enqueue，再嘗試 HTTP。

## 22.2 Store schema

`internal/store/sqlite.go` 新增 next actual schema version。

Migration boundary：只新增 tables/indexes，不修改或刪除既有 delivery evidence/decommission data。Base schema 與 `migrateSteps` MUST 同步；測試必須從真實 v15 fixture（或 implementation 時的 previous version fixture）upgrade、close、reopen，再與 fresh DB schema objects比對。

預期 table：

```sql
CREATE TABLE webhook_outbox (
    event_id             TEXT PRIMARY KEY,
    workspace_key        TEXT NOT NULL,
    source_id            TEXT NOT NULL,
    webhook_name         TEXT NOT NULL,
    sequence             INTEGER NOT NULL,

    workflow_id          TEXT NOT NULL,
    operation            TEXT NOT NULL,
    result               TEXT NOT NULL,

    projection           TEXT NOT NULL,
    payload_mode         TEXT NOT NULL,

    authoritative        INTEGER NOT NULL,
    state_available      INTEGER NOT NULL,
    source_complete      INTEGER NOT NULL,

    base_snapshot_id     TEXT NOT NULL DEFAULT '',
    target_snapshot_id   TEXT NOT NULL DEFAULT '',

    body_json            TEXT NOT NULL,
    body_sha256          TEXT NOT NULL,

    -- Internal only. Needed to advance/rebuild cursor after diff-only delivery.
    target_snapshot_json TEXT NOT NULL DEFAULT '',

    state                TEXT NOT NULL,
    attempt_count        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at      TEXT,

    claim_owner          TEXT NOT NULL DEFAULT '',
    claim_until          TEXT,

    last_error_class     TEXT NOT NULL DEFAULT '',
    last_error_text      TEXT NOT NULL DEFAULT '',

    created_at           TEXT NOT NULL,
    delivered_at         TEXT,

    UNIQUE(workspace_key, source_id, webhook_name, sequence),
    UNIQUE(workspace_key, source_id, webhook_name, workflow_id)
);

CREATE TABLE webhook_workspace_binding (
    workspace_key     TEXT PRIMARY KEY,
    current_source_id TEXT NOT NULL UNIQUE,
    updated_at        TEXT NOT NULL
);
```

`state`：

```text
pending
delivering
delivered
dead_letter
blocked_base_mismatch
orphaned_config
paused_config
```

`last_error_text` MUST sanitized + bounded，例如 512 bytes。

MUST 同時建立查詢 index，至少覆蓋：

```sql
(workspace_key, source_id, webhook_name, sequence)
(workspace_key, state, next_attempt_at)
(workspace_key, state, claim_until)
```

所有 SQLite time text 使用 UTC RFC3339Nano，寫入前 normalize；query 不得混用 local timezone string。Clock-dependent store/dispatcher tests MUST 注入 `now`，不用 wall-clock sleep。

Projection/diff 與其他大型 payload fragments MUST 在 transaction 外建好。Sequence allocation、將 sequence 填入 bounded envelope、最後 deterministic JSON marshal/hash 與 outbox insert MUST 在同一個 `BEGIN IMMEDIATE` transaction：讀該 `(workspace_key, source_id, webhook_name)` 的 `MAX(sequence)`、加一、finalize、insert；禁止先在 Go process 內猜 sequence 再寫入。這是 transaction 內唯一允許的 JSON finalize，不得在 lock 內重做 source read/projection/diff。

Final body 使用 deterministic struct-based JSON、UTF-8、無額外 trailing newline；`body_sha256` 是這組 exact bytes 的 lowercase hex SHA-256（無 `sha256:` prefix）。每次 retry 必須原樣送出 `body_json` bytes，不得重新 materialize timestamp、projection 或 JSON。HMAC delivery timestamp/header MAY 每次 attempt 不同，但 signed body 不變。

## 22.3 Cursor table

```sql
CREATE TABLE webhook_state_cursor (
    workspace_key   TEXT NOT NULL,
    source_id       TEXT NOT NULL,
    webhook_name    TEXT NOT NULL,
    projection      TEXT NOT NULL,

    snapshot_id     TEXT NOT NULL,
    snapshot_json   TEXT NOT NULL,

    last_event_id   TEXT NOT NULL,
    updated_at      TEXT NOT NULL,

    PRIMARY KEY (workspace_key, source_id, webhook_name, projection)
);
```

`cursor.snapshot_json` 是 sanitized projection，不含 secret。

`body_json`、`target_snapshot_json` 只是 active delivery/retry 所需。Row 進入 `delivered`、`dead_letter`、`blocked_base_mismatch` 或 `orphaned_config` 這些 terminal state 時，同一 state-transition transaction MUST 將兩欄清為 empty string，保留 `body_sha256`、event/operation metadata 與 error class 作 audit。`paused_config` 不是 terminal，必須保留 immutable body 以便重新 enable 後送出。Cursor 只保留下次 diff 所需的最後 authoritative snapshot。

## 22.4 Stable webhook name

Outbox identity 持有：

```text
workspace_key (local only)
source_id
webhook_name
```

dispatch 時從 current config resolve：

```text
endpoint
auth mode
secret_env
TLS
timeout
```

好處：

> 同一 logical consumer 換 endpoint / rotate secret 後，pending events 可以送到新的 endpoint，不需要複製 secret/config snapshot。

若 config 已不存在：

```text
orphaned_config
```

不得猜 endpoint。

---

# 23. Delivery Ordering

同一：

```text
(workspace_key, source_id, webhook_name) locally
(source_id, webhook_name) on wire
```

MUST serial FIFO。

不得：

```text
event 42 / event 43 parallel HTTP POST
```

避免：

```text
new snapshot 先到
old snapshot 後到
consumer state regression
```

`sequence` MUST monotonic per logical webhook。

External consumer SHOULD：

```text
persist latest sequence
ignore/reject lower sequence
```

作為第二層防護。

## 23.1 Cross-process claim lease

`dispatcher concurrency=1` 只限制單一 process 不夠；`pilot deploy`、`pilot reconcile` 與 cron `pilot webhook flush` 可能同時執行。

Claim MUST 在 `BEGIN IMMEDIATE` transaction 內原子完成：

1. 找到該 logical webhook 最低 sequence、可送且未被更早 blocking event擋住的 row；
2. row 必須是 `pending`，或是 `delivering` 且 `claim_until <= now`；
3. conditional update 成 `delivering`，寫入每次 claim 新生的 UUIDv4 `claim_owner` 與 `claim_until=now+lease`；
4. commit 後才可做 HTTP；
5. `MarkDelivered`／`MarkAttemptFailed` MUST 同時比對 `event_id + claim_owner`，stale worker不得覆寫新 claim；
6. process crash 後 lease 到期可重領同一 event ID。

Default lease：

```text
max(2 * delivery.timeout, 30s)
```

HTTP attempt 不得超過 lease；context timeout必須早於 lease expiry。

不同 logical webhooks MAY parallel；同一 `(workspace_key, source_id, webhook_name)` 永遠最多一個 live claim。

FIFO blocking 規則：

- `pending`、未過期 `delivering`、`paused_config` 是 blocking state；後續 sequence 不得超車。
- `delivered`、`dead_letter`、`blocked_base_mismatch`、`orphaned_config` 是 terminal state，不阻擋後續 sequence；但 §14.8 的 diff base safety 仍優先，不得因 terminal state 而送出無法收旂的 diff-only event。
- `delivering` lease 過期後不跳過，而是 reclaim 同一 event ID。
- 重新出現同一 `(workspace_key, source_id, webhook_name)` config 不會自動復活既有 `orphaned_config` rows；若需重送必須未來另定 explicit operator workflow，V1 不提供。

---

# 24. Retry Policy

## 24.1 Retryable

Retry：

```text
network error
context deadline
HTTP 408
HTTP 425
HTTP 429
HTTP 5xx
```

`429` / `503` 若有合法 `Retry-After` SHOULD honor。

`Retry-After` 只接受 non-negative decimal delay-seconds 或 RFC 7231 HTTP-date，使用 injected clock 計算；超過 `delivery.max_backoff` 時 MUST cap，無效或過去時間視為沒有 header。

## 24.2 Non-retryable

一般：

```text
HTTP 4xx
```

除上列 retryable code 外，直接：

```text
dead_letter
```

External receiver 如果收到重複 `event_id`，SHOULD idempotently 回 2xx，而不是依賴 409。

## 24.3 Backoff

Default：

```text
initial = 30s
factor = 2
max = 30m
max_attempts = 10
```

`attempt_count` 只在已獲得 claim、即將發出一次 signed HTTP request 時於 transaction 內加一；claim crash/reclaim 不可重複預增。Missing secret env 沒有發出 HTTP，保持 `pending`、記錄 `missing_auth_secret` 並排下次 retry，但不消耗 `max_attempts`。

第 `n` 次 HTTP 失敗後的基礎 delay：

```text
min(max_backoff, initial_backoff * 2^(n-1))
```

再套用可注入 RNG 的 ±20% bounded jitter（不得小於 1s、不得超過 `max_backoff`）。合法 `Retry-After` 取代 exponential delay，只做 `max_backoff` cap，不再加 jitter。

當失敗後 `attempt_count >= max_attempts`，同一 claim completion transaction MUST 將 row 轉為 `dead_letter`、清空 claim fields 且 `next_attempt_at=NULL`。Non-retryable response 在第一次就做相同 transition。

若 config rotation 將 `max_attempts` 降到 `attempt_count` 以下，下次 claim 必須不發 HTTP，直接依 current policy 轉 `dead_letter`；不得多送一次。

## 24.4 V1 沒有 background daemon

Pilot CLI process 結束後不會自行醒來 retry。

Retry 來源：

1. terminal event enqueue 後立刻 bounded attempt；
2. 後續所有 covered operation 結尾 opportunistic flush due events；
3. operator：
   ```bash
   pilot webhook flush
   ```
4. 環境若要求時間型 delivery SLO，可自行用 systemd timer/cron 呼叫：
   ```bash
   pilot webhook flush
   ```

V1 不得宣稱 process exit 後還在 background retry。

## 24.5 Synchronous publication budget

Terminal workflow MUST 先 enqueue 所有 matched subscriptions，再開始 HTTP，避免前一個慢 endpoint 阻止後面的 event durable 化。

每次 operation terminal publication：

- 每個本次新 enqueue 的 webhook最多立即 attempt 一次；
- 不同 webhooks MAY parallel，但全 process最多 4 個 HTTP attempts；
- detached context 必須使用 `context.WithTimeout(context.WithoutCancel(ctx), 30s)`；
- 30 秒總 budget 或各 webhook timeout任一先到即停止，其餘保持 pending；
- opportunistic old-event flush最多另外 claim 20 筆，且共享同一 30 秒總 budget。

不得只用 `context.WithoutCancel` 而沒有 deadline。

---

# 25. HTTP Success Semantics

HTTP：

```text
200-299
```

視為 ACK。

Dispatcher 不得將 response body 寫入 log/store/error。為了 connection reuse 可讀取並丟棄最多 64 KiB，超過就 close；分類只使用 status code 與經驗證的 `Retry-After`。

ACK 後 transaction：

```text
mark outbox delivered
+
if authoritative && state_available && source_complete:
    advance cursor
+
compact terminal outbox payload fields
```

兩者 MUST 在同一 SQLite transaction 完成，並清空 claim fields。

若 uncertain commit：

- retry same event_id；
- receiver 必須可 idempotent；
- local unique keys防止 duplicated outbox row。

---

# 26. Publication 與 Operation Exit Code

| Operation result | Webhook result | Pilot exit |
|---|---|---|
| success | 2xx | 原 success |
| success | timeout | 原 success |
| success | 503 | 原 success |
| success | missing webhook auth env | 原 success |
| success | projection unavailable | 原 success |
| success | local enqueue/store failure after mutation | 原 success（明確 critical warning；不得稱為 pending） |
| failure | 2xx | 原 failure |
| failure | timeout | 原 failure |
| failure | 503 | 原 failure |

唯一例外：

```text
integrations.yaml / store readiness failure BEFORE mutation
```

這時直接拒絕 operation。

---

# 27. Publication Timing

## 27.1 Success

MUST 在以下全部完成後 build snapshot：

```text
apply
verify
required idempotency
accepted auto-host-var persistence
reconcile batch completion
dedicated reconcile frontend terminal result
```

不得沿用 wizard 進入時的：

```go
deployInventorySnapshot
```

當作 webhook current state。

應：

```text
operation terminal
     ↓
重新讀 hosts.yml / resolved sources
     ↓
重新 materialize projection
```

## 27.2 Failure

Failure terminal 後同樣重新 build Pilot projection。

但 wire MUST：

```text
authoritative=false
```

External system可拿來：

- 顯示；
- audit；
- debug；
- 人工 review；

預設不應直接覆寫 authoritative database。

## 27.3 Cancelled

如果 config 有：

```yaml
result: cancelled
```

可送 terminal event。

若沒有：

```text
skip
```

---

# 28. Integration 進入點

## 28.1 不要掛在 `executeRecordedDeployment()`

錯誤：

```go
func executeRecordedDeployment(...) error {
    ...
    sendWebhook()
}
```

原因：

- sameHosts dependency 也會呼叫；
- multi-component deploy 會呼叫多次；
- reconcile batch 會有多 request；
- 一次 user operation 變成 N 個 webhook。

## 28.2 正確 boundary

建立共用 top-level workflow coordinator；它必須包住而不是藏在下列 helper 內部：

```text
runDeployInteractive -> site OR catalog
runReconcileInteractive -> catalog batch
runGatewayScope(..., planOnly=false)
runGatewayScopeAutomember(..., enable=true|false)
runAccessReconcileCmd
runAccessBreakglassActivateCmd
runAccessBreakglassDeactivateCmd
```

概念 API：

```go
type PreparedWorkflow struct {
    ID        string
    Operation OperationKind
    Effects   []contract.Effect
    // selected components / bounded subject metadata / projection inputs
}

func executeAndPublishWorkflow(
    ctx context.Context,
    prepared PreparedWorkflow,
    execute func(context.Context) (WorkflowResult, error),
) error
```

`PreparedWorkflow` 只能在 config/store readiness 與 selection 完成後建立，且必須在第一個 remote mutation 前建立。Coordinator 必須以共同 finalizer 保證 success、failure、cancelled 都走同一個 terminal aggregation；panic 不得轉成 webhook success，原有 panic/recovery policy保持不變。

在真正 terminal 後：

```go
result, err := executeWorkflow(...)

publishCtx, cancel := context.WithTimeout(
    context.WithoutCancel(ctx),
    30*time.Second,
)
defer cancel()

publishErr := outbound.PublishTerminal(publishCtx, result)

reportPublicationStatus(publishErr)

// MUST return original workflow error
return err
```

Site deploy 必須由 site transaction resolved components 建立 requested/executed/completed sets；不得因它不是 catalog multi-select 就漏掉 publication。Catalog reconcile batch則聚合每個 request 與 dependency transaction，只在 batch terminal 發一次。

Dedicated frontends MUST 呼叫同一 coordinator 或一個共享、行為等價且由同一 regression suite覆蓋的 adapter；禁止各自 copy/paste config load、projection、enqueue 或 exit-code handling。

## 28.3 保留既有 helper API

大量 tests / callers 已使用：

```go
executeRecordedDeployment(...) error
```

建議新增：

```go
func executeRecordedDeploymentResult(...) (DeploymentExecutionResult, error)

func executeRecordedDeployment(...) error {
    _, err := executeRecordedDeploymentResult(...)
    return err
}
```

避免為 webhook 大範圍破壞現有 test/caller。

---

# 29. Suggested Go Packages

新增：

```text
internal/outbound/
├── config.go
├── effect_match.go
├── model.go
├── projection.go
├── projection_roster.go
├── canonical.go
├── diff.go
├── event.go
├── outbox.go
├── dispatcher.go
├── auth.go
└── retry.go
```

理由：

```text
outbound
```

比：

```text
portal
webhookportal
externaldirectory
```

更符合 generic integration。

V1 只有 HTTP webhook，但 domain 名稱不要綁死某個 consumer。

---

# 30. Suggested Interfaces

```go
type ProjectionBuilder interface {
    Build(
        context.Context,
        ProjectionRequest,
    ) (ProjectionResult, error)
}

type DiffEngine interface {
    Diff(
        base UserHostAccessSnapshotV1,
        target UserHostAccessSnapshotV1,
    ) StateDiffV1
}

type Outbox interface {
    EnqueueBatch(context.Context, []EventDraft) ([]EnqueuedEvent, error)
    ClaimNextDue(context.Context, ClaimRequest) (*ClaimedEvent, error)
    MarkDelivered(context.Context, DeliveryACK) error       // includes claim owner
    MarkAttemptFailed(context.Context, DeliveryFailure) error // includes claim owner
    ReleaseExpiredClaims(context.Context, time.Time) error
}

type Dispatcher interface {
    Deliver(context.Context, PendingEvent, WebhookConfig) error
}
```

---

# 31. Event Matching Algorithm

Pseudo：

```go
var drafts []EventDraft
for _, webhook := range config.Webhooks {
    if !webhook.Enabled {
        continue
    }

    rule, ok := matchRule(
        webhook.Events,
        workflow.Operation,
        workflow.Result,
        workflow.Effects,
    )
    if !ok {
        continue
    }

    projection := buildProjectionOncePerWorkflow(...)

    draft := buildEventDraft(
        sourceID,
        webhook,
        rule,
        workflow,
        projection,
        cursorOrPendingChainBase,
    )

    drafts = append(drafts, draft)
}

outbox.EnqueueBatch(drafts) // one SQLite tx allocates sequence + finalizes/inserts all bodies; no HTTP before commit
outbox.FlushDueBounded(...)
```

Projection MUST cache by：

```text
(workflow_id, projection name/version)
```

如果三個 webhook 都訂閱 `user_host_access_v1`：

```text
只 build 一次 state
```

再各自依各自 cursor 算 diff。

`EventDraft` 已含 transaction 外建好的 canonical snapshot/diff `json.RawMessage`，但還沒有 `subscription.sequence`或 final body/hash。`EnqueueBatch` MUST be idempotent for the exact same `(workspace_key, source_id, webhook_name, workflow_id, body_sha256)`；若 unique key已存在但以該 row 的既有 sequence finalize 後 hash不同，回傳 conflict，不得覆寫 immutable event。

---

# 32. Event Rule Uniqueness

同一 webhook：

```yaml
events:
  - operation: deploy
    result: success
    payload: snapshot

  - operation: deploy
    result: success
    payload: diff
```

MUST lint fail：

```text
duplicate event rule for (deploy, success)
```

避免「同一 workflow 同一 webhook 到底送一個還是兩個 event」的歧義。

若需要兩種 consumer behavior，建立兩個 webhook entries。

---

# 33. Source / Projection Error Handling

## 33.1 hosts.yml parse failure

如果 operation 本身已 terminal，但 post-operation `hosts.yml` 無法 parse：

```text
state.available=false
state.source_complete=false
error_class=projection_unavailable
```

不得把 hosts 當空。

## 33.2 roster absent

若 workspace 根本沒有任何 configured canonical roster source：

這對「沒有 FreeIPA identity 的 workspace」可以是合法：

```text
users=[]
groups=[]
access=[]
```

但 builder MUST 能區別：

```text
source absent
```

與：

```text
source configured but unreadable
```

後者不可轉空。

## 33.3 roster encrypted but password unavailable

```text
state.available=false
state.source_complete=false
error_class=projection_unavailable
```

CLI 顯示：

```text
⚠ outbound webhook <name>: state projection unavailable; terminal metadata queued/sent without state
```

不得顯示 vault path secret content。

所有 unavailable cases 共用 §11.7 的 metadata-only envelope rules；不得每個 error path 自行決定空 snapshot shape。

---

# 34. Webhook CLI

## 34.1 Lint

```bash
pilot webhook lint
pilot webhook lint --dir /path/to/workspace
```

輸出：

```text
✓ integrations.yaml valid
✓ webhook external-user-host-directory
  events: 4
  projection: user_host_access_v1
```

不測 network。

`lint` MUST 做 strict schema、URL/auth/delivery bounds 與 store open/migration readiness；只對 enabled entries 做 CA file readability。Secret env缺失只顯示 secret name對應的 runtime warning，不印值、不讓 lint schema verdict失敗。

所有 `pilot webhook` subcommands MUST 支援同一個 `--dir` workspace resolution，並沿用 root `--data-dir` 決定 `history.db`；不得讓 `lint`、`status`、`flush` 各自推導不同路徑。

## 34.2 Status

```bash
pilot webhook status
```

顯示：

```text
NAME                         PENDING  DELIVERING  PAUSED  DEAD  BLOCKED  ORPHANED  LAST-ACK
external-user-host-directory 2        0           0       0     0        0         sha256:...
```

MUST NOT 顯示：

```text
secret value
Authorization header
HMAC
```

## 34.3 Flush

```bash
pilot webhook flush
pilot webhook flush --name external-user-host-directory
pilot webhook flush --force
```

`--force`：

> 忽略 `next_attempt_at`，但仍遵守 FIFO / base safety。

`--force` 不得竊取尚未到期的 live claim；只能 claim pending row或已過期 delivering lease。

## 34.4 Test

可新增：

```bash
pilot webhook test external-user-host-directory
```

只送 synthetic connectivity event：

```text
pilot.webhook.test
```

MUST NOT：

- advance state cursor；
- 模擬 deploy success；
- 包含 production snapshot。

若 implementation scope 需要縮小，`test` 可延後；`lint/status/flush` 為 V1 REQUIRED。

---

# 35. CLI Output

成功 delivery：

```text
✓ deploy completed
✓ webhook external-user-host-directory delivered (event=..., snapshot=sha256:...)
```

pending：

```text
✓ deploy completed
⚠ webhook external-user-host-directory pending retry (event=..., reason=http_503)
```

projection unavailable：

```text
✓ deploy completed
⚠ webhook external-user-host-directory sent without state projection (projection_unavailable)
```

failure operation：

```text
✗ reconcile failed: ...
✓ webhook external-user-host-directory delivered failure event (event=...)
```

Webhook log不得把原 operation error 重新 render 成外部 payload。

---

# 36. External Consumer Contract

Consumer SHOULD：

1. verify TLS；
2. verify HMAC/Bearer；
3. dedupe `event_id`；
4. persist `subscription.sequence`；
5. only advance authoritative local state if：
   ```text
   state.available=true
   AND state.source_complete=true
   AND state.authoritative=true
   ```
6. snapshot：
   ```text
   atomic replace
   ```
7. diff：
   ```text
   assert local snapshot_id == diff.base_snapshot_id
   apply upserts/deletes atomically
   set snapshot_id = diff.target_snapshot_id
   ```
8. only after durable commit return HTTP 2xx。
9. 對 login/sudo access 的 `valid_until`／`valid_not_before`／`valid_not_after` 執行本地時間 gate；V1 不保證到期瞬間另送 event。
10. 將 `basis=pilot_declared` 顯示／儲存為 declared state，不得標示成 remote live scan。

Failure event：

```text
authoritative=false
```

consumer可存 operation audit，但 SHOULD NOT 直接覆寫 authoritative state。

---

# 37. Security Boundary

Webhook projection MUST use allowlist，不使用 blocklist。

Outbox/cursor 含主機、email 與權限 metadata，視為 sensitive local state。當至少一個 webhook enabled 時，readiness MUST 在 Unix-like 平台：

1. 新 `history.db` 在 SQLite open 前以 `0600` 建立；
2. 既有 `history.db` 自動收窄為 `0600`，失敗則在 remote mutation 前 fail closed；
3. open/migration 後驗證 DB 與已存在的 `-wal`/`-shm` 沒有 group/world bits；若 driver 產生過寬 sidecar，收窄失敗即 fail closed；
4. `pilot webhook status` 不得印 body/cursor JSON。

無 `integrations.yaml` 的普通 operation fast path 不改 mode、不 open DB，維持相容性。不支援 Unix permission bits 的平台必須在 implementation 中有明確 platform-specific secure storage policy；不得靜默宣稱已驗證 `0600`。

允許：

```text
namespaced host id
host name/FQDN/source
host address
env
roles
deployment_availability
annotations

user name
display name
email
enabled
uid/gid
group names
hostgroup names/direct membership/effective host IDs

effective login access
effective sudo access
time validity
```

禁止：

```text
Ansible Extra vars
Vault vars
freeipa admin password
initial password
SSH key material
private key path
secret env value
raw Ansible stdout/stderr
raw arbitrary command error
```

即使新增 roster field，除非 projection struct 明確新增欄位，否則不會自動外洩。

---

# 38. Payload Size

Default maximum serialized body：

```text
8 MiB
```

Config MAY future expose，但 V1 可先固定。

超過：

```text
state.available=false
state.source_complete=true
state.authoritative=false
error_class=payload_too_large
```

Pilot MUST 改 enqueue 一個小於 64 KiB 的 metadata-only terminal event，omit snapshot/diff，且 cursor不前進。`application_consistency` 與 `confirmed_effects` 仍保留 structured workflow result，不得改寫為 unknown/empty。不得自動 truncate entity arrays，因為 truncation 會破壞 snapshot/diff correctness。

---

# 39. Observability

最少提供 local metrics/status counters（若現有 Pilot CLI 沒有常駐 metrics exporter，先以 DB/status 為準）：

```text
queued_total
delivered_total
delivery_failures_total
dead_letter_total
projection_failures_total
```

`pilot webhook status` 可從 SQLite aggregate。

如果未來接 Prometheus，再投影，不要求 V1 為此新增 daemon。

---

# 40. Store / Outbox Concurrency

MUST 使用 SQLite transaction 保證：

```text
sequence allocation
outbox insert
cursor update
delivery state transition
cross-process claim / lease recovery
```

不發生 lost update。

同一 webhook dispatcher concurrency：

```text
1
```

不同 webhook：

```text
MAY parallel
```

V1 MAY 將不同 webhook也全部 serial，但仍 MUST 實作 §23.1 的 cross-process claim；process-local mutex不算完成。

SQLite connection MUST 啟用 WAL、foreign keys 與 `busy_timeout=5s`（或等價 bounded retry）。`BEGIN IMMEDIATE` transaction 內只可做 DB 讀寫/轉移與 §22.2 為了填入 sequence 所必需的 final bounded-envelope marshal/hash；不得做 source read、projection、diff、DNS 或 HTTP，避免長時間佔用 writer lock。Busy timeout 後仍失敗時，套用 INV-2 的 pre-mutation readiness 或 post-mutation `failed_local` 邊界；不得把未 commit enqueue 報成 pending。

---

# 41. Automation Compatibility

以下都 MUST 走相同 webhook semantics：

```text
pilot deploy interactive
pilot deploy --force
pilot deploy --actions ...
pilot reconcile interactive
pilot reconcile --actions ...
pilot gateway-scope reconcile
pilot gateway-scope enable-auto
pilot gateway-scope disable-auto
pilot access reconcile <roster-file> --once
pilot access breakglass activate <roster-file> <name>
pilot access breakglass deactivate <roster-file> <name>
```

因為 automation 最終仍使用相同 execution workflow。

不得只在 Cobra `RunE` 最外層 patch 一種模式，而漏掉 automation driver。

---

# 42. Direct Ansible Compatibility

以下：

```bash
ansible-playbook ...
```

不會觸發 Pilot outbound webhook。

這是預期行為。

如果外部團隊要求 guaranteed notifications，操作 MUST 經：

```text
pilot deploy
pilot reconcile
```

本功能不攔截 arbitrary Ansible execution。

---

# 43. Config Examples

## 43.1 只要 deploy success snapshot

```yaml
schema_version: 1
source_id: linker-infra-prod

webhooks:
  - name: asset-service
    enabled: true
    endpoint: https://asset.example.com/pilot

    projection: user_host_access_v1

    events:
      - operation: deploy
        result: success
        payload: snapshot

    auth:
      type: bearer
      secret_env: ASSET_SERVICE_TOKEN
```

## 43.2 成功和失敗都通知

```yaml
events:
  - operation: deploy
    result: success
    payload: snapshot

  - operation: deploy
    result: failure
    payload: both
```

## 43.3 Reconcile 只有 user/access

```yaml
events:
  - operation: reconcile
    result: success
    effects_any:
      - identity.*
      - access.*
    payload: diff

  - operation: reconcile
    result: failure
    effects_any:
      - identity.*
      - access.*
    payload: both
```

## 43.4 所有 deploy / reconcile terminal state

```yaml
events:
  - {operation: deploy, result: success, payload: snapshot}
  - {operation: deploy, result: failure, payload: both}

  - {operation: reconcile, result: success, payload: snapshot}
  - {operation: reconcile, result: failure, payload: both}
```

---

# 44. 實際情境

## Scenario A — Docker deploy

設定：

```yaml
- operation: deploy
  result: success
  payload: snapshot
```

執行：

```bash
pilot deploy
```

選：

```text
docker
```

結果：

```text
docker PASS
workflow success
snapshot build
webhook POST
```

即使 user roster 沒變，仍會送最新完整 snapshot。

## Scenario B — User roster reconcile

設定：

```yaml
effects_any:
  - identity.*
  - access.*
```

執行：

```text
pilot reconcile
 -> freeipa-identity
```

Contract effects match：

```text
identity.users
identity.groups
access.hbac
access.sudo
```

=> webhook。

## Scenario C — DNS reconcile

```text
pilot reconcile
 -> freeipa-dns
```

Effects：

```text
dns.zones
dns.records
```

Subscription only：

```text
identity.*
access.*
```

=> skip，完全不送 HTTP。

## Scenario D — Reconcile partial failure

```text
users PASS
groups PASS
hbac PASS
sudo FAIL
```

=> failure webhook：

```text
authoritative=false
consistency=partial_or_unknown
```

原 `pilot reconcile` 仍依原 failure exit code 結束。

## Scenario E — External endpoint down

```text
deploy PASS
webhook 503
```

=>：

```text
outbox pending
deploy exit success
```

之後：

```bash
pilot webhook flush
```

重送同一 `event_id`。

---

# 45. Required Code Changes

## 45.1 `internal/contract/contract.go`

新增：

```text
Effect type
Contract.Effects
validation
known effect registry / helper
```

## 45.2 `contracts/*.yaml`

所有現有：

```text
Reconcile: true
```

對應 contract 加 `effects:`。

至少包含 §6.4 mapping。

## 45.3 `cmd/pilot/cmd/deploy_catalog_effects_test.go`

新增：

```text
every reconciler has effects
every catalog key resolves to contract
exact §6.4 component/effect mapping
```

## 45.4 `internal/delivery/transaction.go`

新增 backward-compatible：

```text
Result
RunResult
FailedStep
```

保持既有 `Run()`。

## 45.5 `cmd/pilot/cmd/deploy.go`

重構：

```text
deployment execution result
catalog workflow aggregation
workflow_id
requested/executed/completed components
delivery run IDs/outcomes
terminal publication
site.yml workflow aggregation
static config/store readiness before mutation
```

不要把 webhook 放進每個 component runner。

## 45.6 `cmd/pilot/cmd/reconcile.go`

使用與 deploy 相同的 terminal publication path。

不得 copy/paste 一份 reconcile webhook code。

同時修改：

```text
cmd/pilot/cmd/gateway_scope.go
cmd/pilot/cmd/access_cli.go
cmd/pilot/cmd/access_breakglass_cli.go
```

使 §1 的 dedicated frontends 走同一 terminal workflow publication adapter。

## 45.7 `internal/outbound/*`

新增：

```text
config
matcher
projection
diff
event
outbox
dispatcher
auth
retry
```

## 45.8 `internal/inventory/*`

必要時抽出：

```text
safe sanitized roster projection
effective grant access resolver
encrypted roster in-memory read helper
typed roster source resolver (absent / one / multiple)
namespaced inventory/freeipa host projection
account-policy-aware active user resolver
```

不得 outbound package import cmd package。

## 45.9 `internal/store/sqlite.go`

next schema：

```text
webhook_outbox
webhook_state_cursor
atomic sequence allocation
cross-process claim lease
```

base schema + migration MUST 同步更新。

## 45.10 `cmd/pilot/cmd/webhook.go`

新增：

```text
pilot webhook lint
pilot webhook status
pilot webhook flush
```

## 45.11 Docs

新增：

```text
docs/runbooks/outbound-webhook.md
docs/verification/outbound-webhook.md
```

README / DELIVERY 若有 command surface table，補上相關入口。

---

# 46. Tests

## 46.1 Config unit tests

至少：

| ID | Check |
|---|---|
| CFG1 | missing `integrations.yaml` => disabled/no error |
| CFG2 | unknown field rejected |
| CFG3 | invalid payload rejected |
| CFG4 | duplicate `(operation,result)` rejected |
| CFG5 | invalid effect wildcard rejected |
| CFG6 | unknown exact effect rejected |
| CFG7 | duplicate webhook name rejected |
| CFG8 | HTTP without explicit opt-in rejected |
| CFG9 | secret value cannot be configured directly |
| CFG10 | auth block/type/secret_env required and strict |
| CFG11 | URL userinfo/query/fragment 與無效 source ID rejected |
| CFG12 | delivery defaults and bounds exact |
| CFG13 | unreadable/non-absolute CA file fails readiness |
| CFG14 | source/name change or disabled config yields orphaned/paused semantics |
| CFG15 | deploy rule with `effects_any` is rejected; reconcile rule accepts it |
| CFG16 | webhook count/source ID bounds and explicit all-disabled behavior exact |

## 46.2 Contract tests

| ID | Check |
|---|---|
| E1 | valid effects load |
| E2 | duplicate effect rejected |
| E3 | unknown effect rejected |
| E4 | every `Reconcile:true` entry has effects |
| E5 | freeipa-identity declares identity/access effects |
| E6 | freeipa-dns does not accidentally declare identity/access effects |
| E7 | exact mapping includes prometheus and pilot-gateway-scope |

## 46.3 Projection tests

| ID | Check |
|---|---|
| P1 | hosts include annotations |
| P2 | host `Extra` excluded |
| P3 | passwords excluded |
| P4 | ssh key values excluded |
| P5 | nested groups expand |
| P6 | nested hostgroups expand |
| P7 | effective HBAC correct |
| P8 | effective sudo correct |
| P9 | active temporary grant included |
| P10 | inactive temporary grant excluded from effective login |
| P11 | active sudo grant represented with validity |
| P12 | active breakglass included |
| P13 | inactive breakglass excluded |
| P14 | deterministic sort/hash |
| P15 | encrypted roster decrypts in memory with password file |
| P16 | encrypted roster without reusable password -> projection unavailable |
| P17 | configured unreadable roster never becomes empty authoritative users |
| P18 | disabled HBAC rule omitted from effective login |
| P19 | disabled/account-expired user omitted from access users but retained as user entity |
| P20 | snapshot hosts come only from hosts.yml; roster host references map to inventory IDs by one exact address match |
| P21 | every explicit access host_id resolves to a projected inventory host |
| P22 | absent roster entities omitted; invalid dangling membership fails closed |
| P23 | duplicate active breakglass records collapse to one stable entity |
| P24 | unavailable/oversize event omits snapshot and diff rather than sending empty state |
| P25 | hostgroup direct/nested membership projects valid namespaced host IDs and effective closure |
| P26 | sudo allow/deny command groups, direct commands, run-as and options resolve completely |
| P27 | future/expired sudo grants and dangling/duplicate stable-key entities fail the specified inclusion rules |

## 46.4 Diff tests

| ID | Check |
|---|---|
| D1 | no cursor => bootstrap |
| D2 | user add => upsert |
| D3 | user delete => delete key |
| D4 | role/annotation change => host upsert |
| D5 | HBAC change => login access upsert |
| D6 | identical state => empty diff but event still exists |
| D7 | hash ignores generated timestamp |
| D8 | failure event does not advance cursor |
| D9 | success ACK advances cursor |
| D10 | pending authoritative event preserves FIFO chain |
| D11 | base mismatch blocks unsafe diff |
| D12 | later snapshot can re-establish cursor |
| D13 | pending authoritative target, not stale cursor, becomes next event base |
| D14 | non-authoritative event never becomes chain predecessor |
| D15 | host diff key is namespaced `id`, not display name |

## 46.5 Dispatcher tests

使用 `httptest.Server`：

| ID | Check |
|---|---|
| H1 | HMAC signature exact |
| H2 | bearer not logged |
| H3 | 204 => delivered |
| H4 | 500 => retry |
| H5 | 429 => retry |
| H6 | 400 => dead-letter |
| H7 | timeout => retry |
| H8 | same event retry keeps event ID |
| H9 | sequence ordered |
| H10 | missing auth env remains pending |
| H11 | webhook error never changes caller-provided operation result |
| H12 | redirects are not followed and become `http_redirect` dead-letter |
| H13 | two stores/processes cannot claim the same webhook sequence concurrently |
| H14 | expired lease can be reclaimed; stale claim owner cannot mark delivered |
| H15 | event N+1 cannot deliver while N has a live claim |
| H16 | dead-letter diff blocks dependent diffs; later snapshot/both safely re-establishes cursor |
| H17 | enqueue batch is atomic and hash-conflict fail-closed |
| H18 | synchronous publication respects 30s total budget |
| H19 | max attempts/non-retryable response atomically become dead-letter and clear claim |
| H20 | exponential jitter/Retry-After bounds exact; missing secret consumes no HTTP attempt |
| H21 | terminal payload compaction is atomic; paused rows retain immutable retry body |
| H22 | SQLite writer contention obeys bounded busy timeout and never performs HTTP inside transaction |
| H23 | TLS minimum version, system+custom roots, hostname verification and invalid PEM behavior exact |
| H24 | shared data-dir isolates workspace keys; source rebinding cannot orphan/deliver another workspace's rows |

## 46.6 Workflow regression tests

| ID | Check |
|---|---|
| W1 | one-component deploy => exactly one terminal event |
| W2 | multi-component deploy => exactly one event |
| W3 | sameHosts dependency => still one event |
| W4 | multi-component reconcile => one event |
| W5 | freeipa-identity matches identity subscription |
| W6 | freeipa-dns does not match identity-only subscription |
| W7 | apply failure emits failure event |
| W8 | verify failure emits failure event |
| W9 | webhook 503 after deploy success => deploy remains success |
| W10 | webhook 204 after deploy failure => deploy remains failure |
| W11 | `--actions` follows identical semantics |
| W12 | `--force` follows identical semantics |
| W13 | invalid integrations config blocks before mutation |
| W14 | site.yml deploy emits exactly one event with resolved component sets |
| W15 | pre-workflow cancellation emits no event; post-workflow-ID cancellation follows subscription |
| W16 | gateway-scope reconcile/enable-auto/disable-auto each emit one reconcile event |
| W17 | access reconcile emits one reconcile event with access-only effects |
| W18 | breakglass activate/deactivate each emit one bounded reconcile event |
| W19 | success snapshot declares `basis=pilot_declared` and does not claim unrelated confirmed effects |
| W20 | local enqueue failure after mutation preserves operation exit and never reports pending |

## 46.7 Secret regression

建立 fixture secret values，例如：

```text
PILOT-SECRET-NEVER-LEAK-123
ssh-ed25519 AAAA-SECRET-KEY-FIXTURE
```

assert 它們不存在於：

```text
serialized webhook body
outbox body_json
cursor snapshot_json
status output
retry error
test logs
```

另外 assert enabled integration 的 DB/WAL/SHM permission policy，以及 terminal row payload 已清除、cursor 不會被 `status` 印出。

---

# 47. Verification Spec

新增：

```text
docs/verification/outbound-webhook.md
```

建議 rows：

```text
C1  config strict parse
C2  effect routing
C3  deploy success snapshot
C4  deploy failure event
C5  reconcile identity success
C6  reconcile DNS subscription skip
C7  snapshot deterministic hash
C8  diff baseline semantics
C9  bootstrap diff
C10 cursor only advances on authoritative ACK
C11 HTTP retry/outbox
C12 FIFO ordering
C13 HMAC
C14 secret non-disclosure
C15 multi-component one-event semantics
C16 automation parity
C17 failure does not alter deploy exit status
C18 encrypted roster safe projection
C19 projection unavailable does not emit destructive empty state
C20 store migration / reopen persistence
C21 disabled/account-inactive access is excluded
C22 namespaced host identity and access referential integrity
C23 cross-process claim lease preserves FIFO
C24 redirect/auth/TLS fail-closed behavior
C25 site.yml and dedicated reconcile frontend parity
C26 declarative-state basis and confirmed-effects semantics
C27 bounded synchronous publication and local enqueue-failure semantics
C28 complete sudo allow/deny/run-as/options and validity semantics
C29 terminal payload compaction and DB/WAL/SHM permission boundary
C30 shared-data-dir workspace isolation and source binding
```

在 production implementation 開始前，先建立這 30 個 row 的 acceptance contract、inputs、target matrix、failure/rollback semantics 與 scenario ownership。任何要寫進 `docs/verification/outbound-webhook.md` 的 executable command 必須先在對應環境實際跑過；尚未有 binary/test harness 的 command 不得預寫。可先保留不含未驗證 command block 的 DRAFT contract，待 Phase 5 actual-run 後補入已證明的命令與最新 evidence link。

---

# 48. Implementation Phases

## Phase 0 — Acceptance contract 與 evidence harness plan

Deliver：

- `docs/verification/outbound-webhook.md` DRAFT acceptance rows C1-C30（不含任何尚未執行的命令）
- `internal/spec/outbound_webhook_regression_test.go`，鎖 row IDs、effect mapping、required scenarios 與 secret sentinels
- clean-room actual-run topology、HTTPS receiver、candidate/evidence artifact路徑
- human review：確認 projection basis、published PII fields、endpoint trust boundary、destructive boundary

Exit criteria：

```text
acceptance semantics frozen
unknowns = 0
destructive remote changes = only the already-selected deploy/reconcile operation
webhook subsystem itself performs no infrastructure mutation
```

## Phase 1 — Contract effects + config

Deliver：

- `Contract.Effects`
- typed known effects
- reconciler effects mapping
- cross-layer lint
- `integrations.yaml` parser/validator
- config tests

Exit criteria：

```text
go test ./internal/contract/... ./cmd/pilot/cmd/...
```

effects/config tests PASS。

## Phase 2 — Projection + diff

Deliver：

- `user_host_access_v1`
- sanitized hosts/users/groups/access
- encrypted roster read path
- deterministic canonicalization
- snapshot hash
- diff engine
- tests

Exit criteria：

```text
no secret leakage
deterministic hash
nested access resolution PASS
```

## Phase 3 — Store + outbox + HTTP

Deliver：

- DB migration
- outbox
- cursor
- HMAC/bearer
- retry classification
- FIFO dispatcher
- atomic claim lease / crash recovery
- `webhook status/flush/lint`

Exit criteria：

```text
restart persists pending event
same event retry idempotent
cursor ACK semantics PASS
two-process claim/FIFO tests PASS
```

## Phase 4 — Workflow wiring

Deliver：

- workflow ID
- structured transaction result
- workflow result aggregation
- effect routing
- exactly one terminal publication
- interactive/force/actions parity
- site.yml aggregation
- gateway-scope/access/breakglass dedicated frontend parity

Exit criteria：

```text
success/failure/cancel integration tests PASS
existing deploy/reconcile/access/gateway-scope tests unchanged
```

## Phase 5 — Immutable candidate actual-run / verification / docs

Deliver：

- freeze local candidate commit；記錄 commit ID、tree ID、execution-affecting file hashes
- 從 clean isolated checkout 執行 §48.1 evidence plan
- 將實際跑過的 commands 與 sanitized latest evidence link 寫入 verification spec
- runbook
- README/DELIVERY updates
- full regression

Exit criteria：

```bash
clean candidate actual-run PASS
go build ./...
go test ./...
```

PASS。

Candidate 成功後不得再修改 execution-affecting code/config/spec fixture；evidence 與 docs使用後續 evidence-only commit。任何修正形成新 candidate，舊 evidence失效。

## 48.1 Actual-run evidence plan

正式 evidence run MUST 至少包含：

| Lane | Target | 必證明內容 |
|---|---|---|
| L1 | clean local checkout | build、full Go tests、contract/config lint、fresh DB migration + reopen |
| L2 | local real HTTPS receiver（test CA） | HMAC、Bearer、204、429/Retry-After、503、400、redirect拒絕、timeout、body hash、secret sentinel absence |
| L3 | 兩個獨立 Pilot processes/兩個 workspace 共用同一 temporary `--data-dir` | claim lease、同 webhook FIFO、crash後 lease reclaim、sequence monotonic、workspace isolation/source-binding fail-closed |
| L4 | fresh disposable vm-target | 一次實際 `pilot deploy` success，證明 mutation outcome不受 receiver 503影響、event durable pending、後續 flush用同 event ID成功 |
| L5 | fresh disposable vm-target / topology（依 FreeIPA spec需要） | `pilot reconcile` identity success/failure、effective projection、encrypted roster in-memory、disabled HBAC/account-inactive user exclusion |
| L6 | disposable FreeIPA target | access reconcile、breakglass activate/deactivate、gateway-scope reconcile/enable-auto/disable-auto 各一個 terminal event，並證明每次最多一個 |
| L7 | failure injection | projection unavailable、payload too large、local enqueue failure、cancel-before/after-workflow-ID、dead-letter後 snapshot recovery |

規則：

1. 所有 target commands 必須使用 Pilot sanctioned CLI；不得用 direct `ansible-playbook` 取代被測 workflow。
2. Receiver 保存 raw request、headers、timestamp、event ID與接收順序到 `.verification/`；提交版 evidence只放 sanitized summary。
3. Secret sentinel掃描涵蓋 receiver capture、history DB、CLI stdout/stderr、automation trace、Ansible log與 evidence artifact。
4. L4-L6 必須保存原 operation exit code、PLAY RECAP／verify verdict、webhook status/outbox row摘要與 receiver ACK。
5. Runbook/verification 只保留最新測試日期、tested revision/tree、target/inventory、PASS/FAIL數字與 evidence link，不嵌完整 transcript。

---

# 49. Acceptance Criteria

功能完成必須同時滿足：

1. `integrations.yaml` 可設定 deploy success 發 snapshot。
2. 可設定 deploy failure 發 diff。
3. 可設定 reconcile success/failure 各自 payload mode。
4. 可用 `identity.*` / `access.*` 判斷 roster-related reconcile，不依賴 component 名稱。
5. `freeipa-dns` 不會誤觸 identity-only subscription。
6. 每個 covered top-level operation 每 webhook 最多一個 terminal event。
7. multi-component / dependency execution 不重複發送。
8. success snapshot 是 operation terminal 後重新 materialize，且明確標記 `basis=pilot_declared`。
9. failure snapshot 明確 `authoritative=false`。
10. diff 基準是 publication cursor，不是 local pre/post files。
11. first diff 可以 bootstrap。
12. ACK 前不 advance cursor。
13. failure event ACK 不 advance authoritative cursor。
14. HTTP failure 有 durable outbox。
15. retry 使用同一 event ID。
16. 同一 webhook 跨 process claim/lease仍保持 FIFO。
17. webhook、projection、post-mutation local enqueue failure不修改原 operation exit code。
18. invalid integration config／store readiness 在 remote mutation 前 fail。
19. raw roster/vault/credentials 不會進 webhook。
20. encrypted roster plaintext 不落 disk。
21. 沒有 integrations config 時既有 Pilot 行為不變。
22. disabled HBAC、disabled/account-expired user、inactive/expired grant不會出現在 effective access。
23. inventory/FreeIPA hosts使用 namespaced stable ID，explicit access target沒有 dangling reference。
24. `pilot gateway-scope reconcile/enable-auto/disable-auto`、`pilot access reconcile`、breakglass activate/deactivate走相同 terminal publication semantics。
25. auth必填、redirect不跟隨、HTTP需 explicit opt-in、CA/delivery bounds fail closed。
26. unavailable/oversize projection只發 metadata event，絕不發 destructive empty snapshot/diff。
27. site.yml、catalog、sameHosts、reconcile batch與 automation paths都有 exactly-one event regression。
28. immutable candidate 依 §48.1 actual-run 全部 PASS 且 evidence 可追溯。
29. `go build ./...` 與 `go test ./...` PASS。
30. 共用 data-dir 時 status/flush/orphan reconciliation 不會跨 workspace，source ID 衝突在 mutation 前 fail closed。

---

# 50. 最終設計決策

本功能正式採用以下模型：

```text
Component Contract
      │
      └── effects
             │
             ▼
Deploy / Reconcile Workflow
(including access / gateway-scope dedicated frontends)
             │
             └── terminal result
                    │
                    ▼
              Subscription
                    │
        ┌───────────┼────────────┐
        ▼           ▼            ▼
     snapshot      diff          both
        │           │            │
        └───────────┴────────────┘
                    │
                    ▼
               Durable Outbox
                    │
                    ▼
            External Team Program
```

其中：

```text
snapshot
```

代表：

> operation terminal 後重新建立、`basis=pilot_declared` 的 versioned Pilot-managed declarative state projection；不是未受本次 operation 影響之 remote domain 的 live-scan 證明。

```text
diff
```

代表：

> 該 logical webhook consumer 上一個 authoritative ACK snapshot 到目前 projection 的 semantic entity diff。

```text
failure snapshot/diff
```

代表：

> operation failure 後可觀察的完整 Pilot-declared projection；MUST 標記 non-authoritative、`application_consistency=partial_or_unknown`，不得冒充完整成功後的 remote runtime state。

這個 boundary 讓 Pilot 保有：

- component semantics；
- authorization resolution；
- secret filtering；
- state versioning；
- diff semantics；

而外部團隊只需要實作穩定的 webhook consumer，不需要理解 Pilot 的 `hosts.yml`、roster、Ansible 或 FreeIPA 內部結構。
