# RFC：ComponentContract v1

> 狀態：Final — accepted for production implementation
> 日期：2026-07-18
> 範圍：M1.1 production loader/API contract + 六份 schema fixtures
> 接受依據：2026-07-18 使用者要求關閉 review findings 並全面開始 production
> implementation；本版已固定 role cardinality、dependency placement、
> provider selection 與 auto-deploy eligibility。
>
> **實作標示：production loader baseline 已實作；runtime integration 尚未實作。**
> `internal/contract/contract.go` 現在提供 strict YAML decode、local schema validation
> 與 stable directory loading；`fixture_schema_test.go` 保留 spec/tag/ownership 的
> repository lint gate。contract 尚未接 deploy catalog view、site lint 或 TUI。

## 1. 決策摘要

1. 每個 component 恰有一個 primary target role；同一 role 可以承載多個
   component（例如 `log-server` 與 `log-shipping`），不是雙向 1—1。
2. 一支 playbook 可以被多個 component 引用；dns、ntp 共用
   `core-infra-provider-apply.yml`。
3. `specs` 使用結構化 entry，可選 row selector；因此 dns、ntp 可共用
   `core-infra-provider.md`，分別選 category `dns`／`ntp`。
4. 不保留語意不足的 `tagMode: noRowTags`。無 row tag 的 playbook 必須提供
   machine-readable row → feature/stage tag mapping，或逐 row 宣告 verify-only。
5. `site.yml` 維持手寫；contract 的 `site` projection 只用來 lint order、
   coverage、vars、tags 與 opt-in，不自動生成 site。
6. `groupVars.secret: true` 是 vault key 的唯一結構化宣告，不另設 vault key 清單。
7. `playbooks.rollback: null` 時 rollback policy 只能是 `none`。
8. 新 component 的完整 bundle 包含 spec、apply playbook、regression test、
   contract，並依需要同步 group_vars、backup scope 與 actual-run evidence。
9. dependency 必須宣告 placement relation；跨 host endpoint binding 必須宣告
   provider selection，禁止默取 group 第一台。
10. deploy transaction 只自動執行 `verification.autoDeploy: true` 的 contract；
    這類 contract 引用的 spec 必須全部是 Spec v2，row applicability 只由 spec
    定義。`verification.autoDeploy` 必須顯式提供，不能因欄位省略而猜測。

## 2. Schema

```yaml
schemaVersion: 1
id: docker
role: docker
specs:
  - path: docs/verification/docker.md
    rows: {all: true}
playbooks:
  apply: playbooks/apply/docker-apply.yml
  rollback: null
  upgrade: null
  decommission: null
regressionTests:
  - internal/spec/docker_regression_test.go
dependencies: []
conflicts: []
bindings: []
os: []
hostCardinality: one-or-more
resources: {}
groupVars: []
inputRules: []
endpoints: []
stagePolicy: {}
experimental: false
evidenceRequirement: {}
lifecycle: {}
traceability: {}
verification:
  autoDeploy: false
site: {}
```

Strict YAML decode；unknown schema version／unknown field 是 error。

### 2.1 Test-only executable schema gate

`internal/contract/fixture_schema_test.go` 以 private Go types 固定本輪已 review 的
nested shape；不匯出 symbol、不讓 runtime 載入 fixture。已固定的結構包括：

| 區塊 | nested shape |
|---|---|
| `specs[].rows` | `all`、`ids`、`categories` 三者恰選一 |
| `playbooks` | `apply` 必填；`rollback`／`upgrade`／`decommission` nullable |
| `dependencies` | `{component, required, relation}`；relation =
  `sameHosts|providerEndpoint|planOnly` |
| `bindings` | `{input, requiredWhenDependencySelected, sourceSelection,
  from: {component, endpoint}}` |
| `os` | `{distro, versions[]}` |
| `resources` | `{minCPU, minRAMMiB, minDiskGiB}` |
| `groupVars` | `{name, type, required, default, secret, validation}`；type =
  `string|stringList|integer|boolean|duration` |
| `inputRules` | strict `all`／`any` union；condition =
  `{input, operator, value?}`；operator =
  `nonEmpty|equals|notEquals|contains|notContains` |
| `endpoints` | `{name, scheme, port, path}`；unix 用 path，network endpoint 用 port |
| `stagePolicy` | `{variable, default}` |
| `evidenceRequirement` | `{targetTest, idempotency}` |
| `lifecycle.backup` | nullable `{provider, preHook, paths[]}` |
| `traceability` | `rowTags` strategy 或逐 qualified row ref `mapped`；exemption 為 `verifyOnly`／`derived` |
| `verification` | 必填 `{autoDeploy}`；true 時所有 selected specs 必須是 v2 |
| `site` | `{include, order, vars, tags, optIn, targetGroupExpression}` |

schema gate 已驗證：

- unknown top-level／nested field 與 unknown version 會被拒絕；
- `groupVars.default` 必須符合宣告 type；duration 使用 Go duration syntax；
- fixture 引用的 spec、apply playbook、regression test 確實存在；
- selector 選到的 row/category 存在且非空；
- rowTags／mapped／derived 引用的 apply tag 確實存在；
- binding input 必須存在於 `groupVars`，source component 必須是 dependency；
- input rule 必須有 reason、引用已宣告 group var，且 `all`／`any` 恰選一；
- `verification.autoDeploy` 必須顯式提供；
- 六份 fixture 不得重複擁有同一個 spec row。

這是 production loader 的 executable schema baseline，不是 runtime loader 本身。

## 3. Spec mapping

`specs` entry：

```yaml
- path: docs/verification/core-infra-provider.md
  rows:
    categories: [dns]
```

`rows` 只能選一種：

- `all: true`
- `ids: [C1, C2]`
- `categories: [dns]`

Contract lint 必須證明：

- selector 至少選到一列；
- 同一 spec row 不會在同一 deploy plan 被兩個 component 重複擁有；
- selector 引用的 ID／category 存在；
- 未被任何 component 接管的 row 有明確 finding。

Spec v2 的 traceability 引用改為 plural：

```yaml
traceability:
  components: [dns, ntp]
```

真正的 row ownership 仍由 contract selector 決定；spec 只保存可引用的 component
集合，避免 shared spec 被迫謊稱只有一個 owner。

Row applicability 不放 contract。Spec v2 的 `appliesWhen` 是唯一 source of truth；
contract 只能選 ownership rows，不能覆寫或放寬 applicability。v1 spec 可以由
contract loader／lint 管理，但 `verification.autoDeploy` 必須是 false。

Contract 內的 row identity 一律是 `<spec-path>#<row-id>`，例如
`docs/verification/docker.md#C3`。原因是 component 可擁有 1–N 份 spec，而每份
spec 都可能有 `C1`；只用裸 row ID 會碰撞。`rowTags` 仍以 row ID 推導實際
Ansible tag，但所有 `mapped`／`exemptions` map key 與 evidence scope 都使用
qualified row ref。

## 4. Traceability

### 4.1 Row tags

```yaml
traceability:
  mode: rowTags
  tag:
    kind: rolePrefixed
    prefix: docker
```

`kind`：

- `bare`：row C3 → tag C3。
- `rolePrefixed`：row C3 → `<prefix>-C3`。

### 4.2 Mapped tags

Installer／reconciler／stage pipeline 沒有 1:1 row task 時：

```yaml
traceability:
  mode: mapped
  rows:
    "docs/verification/freeipa-server.md#C1": {tags: [freeipa-install], reason: "..."}
    "docs/verification/freeipa-server.md#C2": {tags: [freeipa-service], reason: "..."}
```

每個 selected row 都必須出現在 mapping；不允許只有 component-level
`noRowTags` reason。

### 4.3 Verify-only／derived rows

```yaml
traceability:
  exemptions:
    "docs/verification/docker.md#C5":
      kind: verifyOnly
      reason: whole-chain functional probe
    "docs/verification/docker.md#C3":
      kind: derived
      tags: [docker-C1]
      reason: CLI is delivered by the package task
```

`derived` 必須引用實際存在的 apply tag。這讓 P1「每 row 可追到 apply 或
verify-only」與現行豁免相容。

### 4.4 Partial deploy

- `rowTags`：requested apply tags 解析成 rows。
- `mapped`：feature/stage tag 反查 rows。
- `verifyOnly` row 不因 partial apply 自動加入，除非它依賴的 tags 全在本次 scope
  或使用者明確指定 `--verify-rows`。
- 無法唯一解析 → fail closed，要求 `--verify-rows`。

## 5. Dependencies 與 bindings

```yaml
dependencies:
  - component: seaweedfs-s3
    required: false
    relation: providerEndpoint
bindings:
  - input: restic_s3_target_host
    requiredWhenDependencySelected: true
    sourceSelection: exactlyOne
    from:
      component: seaweedfs-s3
      endpoint: s3
```

optional dependency 允許外部服務替代。跨欄位 preflight 不能塞進單欄
`groupVars.validation`，必須用 `inputRules`：

```yaml
inputRules:
  - any:
      - {input: restic_s3_target_host, operator: nonEmpty}
      - {input: restic_repository, operator: notContains, value: s3-backup-server}
    reason: self-hosted S3 needs a target; external S3 must override the default
```

`inputRules` 在 dependency binding、使用者 input 與 defaults resolve 後、apply
前評估；false 使 plan fail closed。`equals`／`notEquals`／`contains`／
`notContains` 必須有 value；`contains`／`notContains` 僅接受 string input/value；
`nonEmpty` 禁止 value。
這讓 restic 的「提供 self-hosted target 或覆寫成 external repository」二擇一
成為 machine-readable contract，不依賴 playbook 跑到 pre_tasks 才發現。

### 5.1 Placement relation

- `sameHosts`：本 component deployment scope 的每台 host 都必須同時具備 dependency
  role/capability；只在 inventory 其他機器找到 dependency 不算通過。
- `providerEndpoint`：dependency 在別的 provider scope，必須至少有一個 binding
  引用其 endpoint。
- `planOnly`：只要求 dependency 出現在同一 resolved plan，不要求 co-location；
  僅用於純排序/授權依賴，lint 要求 reason。

### 5.2 Provider selection

`sourceSelection`：

- `exactlyOne`：provider scope 恰一台時自動綁定；多台時要求使用者明確指定
  provider host，零台 fail。
- `all`：input 必須是 list type，綁定全部 provider endpoints。
- `explicit`：不論 cardinality 都要求 CLI/TUI 明確選擇。

`resolveGroupHost` 的「取第一台」行為不得進 contract-driven planner。selection、
provider host 與 resolved endpoint 都寫入 evidence。

## 6. Host cardinality

允許：

- `exactly-one`
- `one-or-more`
- `zero-or-more`

cardinality 套用在本次 stage／limit／host pattern 解出的 component deployment
scope，不是整份 inventory。

`role` 欄位的精確 cardinality是 component → one role、role → zero-or-more
components。loader 提供 `ComponentsForRole(role) []ComponentContract`，不提供會
假設唯一的 `ComponentForRole(role)`。

## 7. Site projection

`site` 只做 lint：

```yaml
site:
  include: true
  order: 30
  vars: {infra_role: dns}
  tags: [infra, dns]
  optIn: false
  targetGroupExpression: null
```

lint 固定驗證不可由 component 覆寫的 prelude：

1. localhost `target_group is not defined` safety gate；
2. `tags: [always]`；
3. `preflight.yml` 在所有 apply imports 之前。

並驗證 dns／ntp 雙 import、site tags、log-shipping 動態 target group 與 opt-in
排除。M1.3 前不生成或重寫 `site.yml`。

## 8. Lifecycle

```yaml
playbooks:
  rollback: null
lifecycle:
  backup: null
  upgrade: null
  decommission: null
```

- playbooks 保存 executable path。
- lifecycle 保存 policy／data handling contract，不重複保存 path。
- `playbooks.rollback: null` → rollback policy 只能 `none`。
- lifecycle null 先 warning；decommission action 遇 null 必須 fail closed。

## 9. 六份試點

| fixture | 驗證重點 |
|---|---|
| docker | role-prefixed row tags、derived/verify-only exemptions |
| freeipa-server | exactly-one、secret、mapped feature tags |
| restic-backup | optional dependency、binding、secret、overlay role |
| dns | shared playbook/spec、category selector、site vars |
| ntp | shared playbook/spec、category selector、site vars |
| log-shipping | dependency binding、dynamic target group、bare row tags |

六份 canonical contract 位於 `contracts/`；`docs/tmp/future/contracts/` 是 review
mirror，loader 解碼後的 semantic-equality regression test 會阻止兩者漂移。它們尚未
接入 deploy runtime。

## 10. Loader 開工 gate

以下全數完成才開始 production `internal/contract` loader/API：

| Gate | 狀態 |
|---|---|
| 六份 fixtures 可被 strict YAML decoder 解析 | **完成（test-only）** |
| selector／traceability 正負案例 | **完成本輪核心案例** |
| shared spec plural traceability 同步回 Spec v2 RFC | **完成** |
| site lint-only 決策 | **完成：維持手寫 + lint** |
| regression test 留在 Delivery Bundle DoD | **完成** |
| group vars／vault key／endpoint 欄位命名 review | **完成** |
| role cardinality／dependency placement／provider selection | **完成** |
| auto-deploy v2-only 與 applicability ownership | **完成** |

production loader/API baseline 已實作：canonical `contracts/` 由 strict loader 載入，
並提供 component／role lookup 與唯讀 `pilot contract lint`。M1.2 仍需收斂全量
lint；deploy catalog view、site lint 與 TUI integration 也尚未實作。

## 11. 非目標

- M1.1 不搬完 22 個 component。
- 不生成 `site.yml`。
- 不改 deploy catalog／role contracts。
- 不把 contract做成 LLM tool schema。
- 不在 fixture review 前固化 Go loader API。
