# RFC：ComponentContract v1

> 狀態：Proposed
> 日期：2026-07-18
> 範圍：M1.1 RFC + 六份 fixtures；本 RFC 尚不授權 loader／API 實作
>
> **實作標示：六份 fixture 已建立並通過 YAML parse；正式功能尚未實作。**
> `internal/contract`、strict loader、contract lint、deploy catalog view、
> site lint 與 TUI integration 目前都不存在。

## 1. 決策摘要

1. component ↔ primary inventory role 是 1—1。
2. 一支 playbook可以被多個 component 引用；dns、ntp 共用
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
endpoints: []
stagePolicy: {}
experimental: false
evidenceRequirement: {}
lifecycle: {}
traceability: {}
site: {}
```

Strict YAML decode；unknown schema version／unknown field 是 error。

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
- 未被任何 component接管的 row 有明確 finding。

Spec v2 的 traceability 引用改為 plural：

```yaml
traceability:
  components: [dns, ntp]
```

真正的 row ownership 仍由 contract selector 決定；spec 只保存可引用的 component
集合，避免 shared spec 被迫謊稱只有一個 owner。

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
    C1: {tags: [freeipa-install], reason: "..."}
    C2: {tags: [freeipa-service], reason: "..."}
```

每個 selected row 都必須出現在 mapping；不允許只有 component-level
`noRowTags` reason。

### 4.3 Verify-only／derived rows

```yaml
traceability:
  exemptions:
    C5:
      kind: verifyOnly
      reason: whole-chain functional probe
    C3:
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
bindings:
  - input: restic_s3_target_host
    requiredWhenDependencySelected: true
    from:
      component: seaweedfs-s3
      endpoint: s3
```

optional dependency 允許外部服務替代；此時 required group var 可用 validation 的
`oneOfRequired` 表達。

## 6. Host cardinality

允許：

- `exactly-one`
- `one-or-more`
- `zero-or-more`

cardinality 套用在本次 stage／limit／host pattern 解出的 component deployment
scope，不是整份 inventory。

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
- `playbooks.rollback: null` → rollback policy只能 `none`。
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

Fixtures 位於 `docs/tmp/future/contracts/`，不是 production loader input。

## 10. Loader 開工 gate

以下全數完成才開始 `internal/contract`：

- 六份 fixtures 可被 strict YAML decoder 解析。
- selector／traceability 的正負案例定稿。
- shared spec plural traceability 同步回 Spec v2 RFC。
- site lint-only 決策被接受。
- regression test 明確留在 Delivery Bundle DoD。
- group vars／vault key／endpoint 欄位完成命名 review。

## 11. 非目標

- M1.1 不搬完 22 個 component。
- 不生成 `site.yml`。
- 不改 deploy catalog／role contracts。
- 不把 contract做成 LLM tool schema。
- 不在 fixture review 前固化 Go loader API。
