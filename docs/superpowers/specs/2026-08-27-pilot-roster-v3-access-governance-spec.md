# Pilot Roster v3.0 — Core Access Governance 實作規格

Status: DRAFT implementation specification
Target repository: kjelly/pilot
Baseline: main at bda6717ec887de7b1a329a8610785abeaca779a1
Date: 2026-08-26
Audience: Coding agent / maintainer implementing the change

## 1. Goal

v3.0 在已完成的 HBAC simplification 上，加入 lifecycle-aware authorization。

`grants: []` 已於 v2→v3 migration（baseline 已合入）以空陣列存在，`kind` 詞彙目前只有
`temporary_grant | breakglass`（見 §2、§5a）。本 spec **擴充** `grants[]` 的元素形狀與
其餘 v3 top-level 區塊，而不是重新定義 `grants[]` 本身。

MUST 實作：

1. unified time-bound grants（`temporary_grant` / `sudo_grant`）
2. temporary_grant → managed HBAC compilation
3. sudo_grant → native timed sudo compilation
4. authentication policies / Kerberos authentication indicators
5. grant security policies
6. Separation of Duties
7. break-glass lifecycle（作為 `grants[].kind == breakglass` 的定義 + 啟用生命週期）
8. account lifecycle
9. effective access explain / provenance
10. lifecycle status / next transition

Approval / approval receipt OUT OF SCOPE。

本 spec 維持單一文件，但實作 MUST 依 §21 的三個 phase 循序交付，每個 phase 各自
可獨立驗收與 vm-target 驗證；不得跳過前一 phase 的 exit criteria 直接開工下一 phase。

## 2. Mandatory dependency

先完成：

```text
v2-hbac-authorization-simplification.md
v2-to-v3-migration.md
```

v3.0 MUST assume：

```text
static login authorization = HBAC
access-* = deprecated compatibility only
grants[] top-level list already exists (schema_version=3), currently empty
grants[].kind 詞彙目前只有 temporary_grant | breakglass（無 login/sudo，無獨立
  breakglass 頂層區塊）——這是已合入 internal/inventory/roster_grants.go 的既定事實，
  不是本 spec 可重新選擇的設計空間
```

v3.0 MUST NOT create a new access group for any grant。

v3.0 MUST NOT rename or remove the already-shipped `grants[].kind` values
(`temporary_grant`、`breakglass`)。本 spec 只能對它們做 **additive** 擴充
（新增 `sudo_grant`、新增可選欄位），細節見 §5a。

## 3. Baseline files to inspect

```text
internal/inventory/roster_version.go
internal/inventory/roster_validate.go
internal/inventory/roster_grants.go
internal/inventory/roster_effective.go
internal/inventory/roster_migrate.go
internal/inventory/roster_migrate_file.go
cmd/pilot/cmd/edit_actions_registry.go
cmd/pilot/cmd/edit_tui_roster_access.go
cmd/pilot/cmd/edit_automation_driver_roster_access.go
cmd/pilot/cmd/mcp_edit_resources.go
playbooks/apply/freeipa-identity-apply.yml
playbooks/apply/freeipa-identity.roster.example.yaml
docs/runbooks/freeipa-identity.md
docs/verification/freeipa-identity.md
```

`internal/inventory/roster_grants.go` 是目前唯一實作 `grants[]` 驗證的檔案（v2→v3
migration 的產出）。本 spec 對 grants schema 的每一項擴充都必須先讀這個檔案，確認
是 additive 而非破壞既有 `knownGrantKinds`/`knownGrantKeys`。

## 4. Static authorization model inherited from v2

Modern static HBAC：

```yaml
hbac:
  rules:
    - name: production-ssh
      subjects:
        users: [vendor01]
        groups: [team-sre, role-production-operator]
      targets:
        hosts: [db-special.ipa.pilot.internal]
        hostgroups: [production]
      services: [sshd]
```

Rules：

```text
HBAC group subject:
  team        allowed
  role        allowed
  access      allowed, legacy/deprecated
  filesystem forbidden

sudo group subject:
  role only
```

v3.0 validation MUST reuse centralized category policy from HBAC simplification。

## 5. Schema v3 additions

```yaml
schema_version: 3

grants: []           # already shipped (v2->v3 migration); this spec only extends
                      # the element shape — see §5a / §6. The top-level list itself
                      # is not new.

auth_policies: []     # new in this spec (Phase 2)

security:
  grant_policies: []  # new in this spec (Phase 2)
  conflicts: []       # new in this spec (Phase 2)

account_policies: []  # new in this spec (Phase 3)
```

Existing static `hbac` and `sudo` remain first-class and are not replaced。

**沒有獨立的 `breakglass: []` 頂層區塊。** Break-glass 是 `grants[].kind == breakglass`
的一種定義（§6.3），不重新開一個新的頂層 section——這是為了不與已合入的
`grants[]` 詞彙表衝突（§2）而做的明確設計決定，見 §14 的完整說明。

## 5a. Baseline delta — `internal/inventory/roster_grants.go` 需要的 additive 修改

已合入版本：

```go
knownGrantKeys  = []string{"name", "kind", "subjects", "targets"}
knownGrantKinds = []string{"temporary_grant", "breakglass"}
```

本 spec 要求的擴充（全部是新增，不刪除、不重新命名既有值）：

```go
knownGrantKinds = []string{"temporary_grant", "sudo_grant", "breakglass"}

// knownGrantKeys 依 kind 而不同，改用 kind-conditional 檢查取代單一 flat 允許清單：
//   全部 kind 共用: name, kind, state, subjects, targets, services
//   temporary_grant / sudo_grant 額外必須: validity, justification
//   sudo_grant 額外允許: privilege, run_as, options
//   breakglass 額外允許: activation, auth_policy（且 MUST NOT 允許 validity/justification —— 見 §6.3/§7）
```

MUST NOT 改變的既有語意：

- `subjects`/`targets` 既有的 team/role/access/filesystem 分類規則（§4、§7）不變。
- 任何在本 baseline 之前就存在、只填了 `name`/`kind`/`subjects`/`targets` 的
  `grants[]` 元素（若存在）在升級後仍必須驗證通過或給出明確、可行動的錯誤訊息，
  不得被靜默誤判成別的 kind 或別的欄位語意（§19 回歸測試要求）。

## 6. Unified grants

Grant relationship shape intentionally mirrors HBAC/sudo。三個 `kind` 值：
`temporary_grant`、`sudo_grant`、`breakglass`（沿用 §2/§5a 已上線詞彙，`sudo_grant`
為本 spec 新增）。

### 6.1 `kind: temporary_grant`（時效性 login 授權）

```yaml
grants:
  - name: vendor-project-x
    state: present
    kind: temporary_grant

    subjects:
      users:
        - vendor01
      groups:
        - team-sre

    targets:
      hosts:
        - db-special.ipa.pilot.internal
      hostgroups:
        - production-db

    services:
      - sshd

    validity:
      not_before: 2026-08-21T09:00:00+08:00
      not_after: 2026-08-31T18:00:00+08:00

    justification:
      reason: Project X maintenance
      ticket: INC-1234
      requested_by: alice
```

### 6.2 `kind: sudo_grant`（時效性 sudo 授權）

```yaml
  - name: alice-prod-nginx
    state: present
    kind: sudo_grant

    subjects:
      users:
        - alice
      groups:
        - role-production-operator

    targets:
      hosts: []
      hostgroups:
        - prod-web

    privilege:
      command_groups:
        - web-service-manage
      commands: []
      command_category: ""

    run_as:
      users: [root]
      groups: []

    options: []

    validity:
      not_before: 2026-08-21T15:00:00+08:00
      not_after: 2026-08-21T19:00:00+08:00

    justification:
      reason: Incident response
      ticket: INC-4421
      requested_by: alice
```

### 6.3 `kind: breakglass`（緊急存取定義，非直接生效的時間窗）

```yaml
  - name: infrastructure-emergency
    state: present
    kind: breakglass

    subjects:
      users:
        - emergency-admin
      groups: []

    targets:
      hosts: []
      hostgroups:
        - production-linux

    services: [sshd]

    activation:
      max_duration: 1h
      require_reason: true
      require_ticket: true

    auth_policy: production-strong-auth
```

`breakglass` 定義**沒有** `validity`、也**沒有** `justification`——它是一個待啟用的
樣板，不是已生效的時間窗。啟用時才產生 runtime activation state 與當次
reason/ticket（§14 的 `pilot access breakglass activate` CLI），不寫回這個定義本身。

## 7. Grant validation

Common（全部 kind）：

- name unique
- state `present|absent`
- kind `temporary_grant|sudo_grant|breakglass`
- `len(subjects.users)+len(subjects.groups) > 0`
- `len(targets.hosts)+len(targets.hostgroups) > 0`
- direct users resolve to roster user; `admin` only where explicitly supported by grant type/policy
- direct hosts are non-empty FQDN-shaped enrolled host names; do not require top-level `hosts:` declaration
- target hostgroups resolve
- no implicit `hostcat: all` in generic grant
- reason REQUIRED（僅適用於帶 `justification` 的 kind，即 `temporary_grant`/`sudo_grant`；`breakglass` 沒有 `justification` 欄位，見下）
- unknown fields fail closed，依 kind 而不同的允許清單見 §5a
- `approval` is unknown/invalid in v3.0

Kind-specific：

```text
temporary_grant / sudo_grant:
  validity.not_after REQUIRED
  not_before OPTIONAL
  RFC3339 with offset/Z
  not_after > not_before
  justification.reason REQUIRED

breakglass:
  validity  MUST be absent (fail closed if present)
  justification MUST be absent (fail closed if present)
  subjects.groups MUST be empty（只接受具名 direct user，不接受 group——避免
    「誰有緊急權限」隨 group membership 漂移）
  activation.max_duration REQUIRED，語法見 §12 duration grammar
  activation.require_reason / require_ticket 為 boolean，預設 true
  auth_policy OPTIONAL，若存在必須參照一個 auth_policies 條目（Phase 2 之後才可解析，
    Phase 1 完成時允許此欄位驗證為「格式正確但暫不解析引用」）
```

Login group subjects（`temporary_grant`）：

```text
team        PASS
role        PASS
access      PASS, legacy warning if surfaced
filesystem FAIL
```

Sudo group subjects（`sudo_grant`）：

```text
role PASS
all others FAIL
```

Mixed direct + grouped subjects/targets are valid for `temporary_grant`/`sudo_grant`。
`breakglass` 的 `subjects.groups` 恆為空（見上），故不適用 mixed-group 規則。

## 8. Lifecycle evaluator

```go
type GrantLifecycleState string

const (
    GrantPending GrantLifecycleState = "pending"
    GrantActive  GrantLifecycleState = "active"
    GrantExpired GrantLifecycleState = "expired"
    GrantAbsent  GrantLifecycleState = "absent"
)
```

```text
state=absent                  -> absent
now < not_before              -> pending
not_before <= now < not_after -> active
now >= not_after              -> expired
```

MUST use injected clock and UTC comparison。

此 evaluator 只適用於帶 `validity` 的 kind（`temporary_grant`/`sudo_grant`）。
`breakglass` 定義沒有 `validity`，不參與 pending/active/expired 判定；它的「是否目前
生效」完全由 runtime activation state 決定（§14），兩者 MUST NOT 被混用同一套狀態機。

## 9. temporary_grant（login）compiler

Each `kind: temporary_grant` grant compiles directly to a deterministic
Pilot-managed HBAC rule：

```text
pilot-grant-login-<sanitized-name>-<short-hash>
```

（規則命名沿用 `login` 字樣純粹是 HBAC rule 的人類可讀慣例，與 schema 的
`kind: temporary_grant` 值無關，兩者故意不同步。）

Compiled rule copies：

```text
subjects.users
subjects.groups
targets.hosts
targets.hostgroups
services
```

**No access wrapper group is created.**

State：

```text
pending -> disabled or absent managed HBAC
active  -> present + enabled
expired -> disabled, retained in v3.0
absent  -> absent
```

HBAC lacks native per-rule expiry, therefore v3.0 MUST expose：

```bash
pilot access reconcile --once
pilot access status
```

and report `next_transition_at`。

Do not claim second-precision expiry without an external/controller reconcile。

## 10. sudo_grant compiler

Each `kind: sudo_grant` grant compiles directly to deterministic Pilot-managed
sudo rule：

```text
pilot-grant-sudo-<stable-id>
```

Copy：

- direct users
- role groups
- direct hosts
- hostgroups
- commands/command groups
- run-as
- options

Set native FreeIPA/LDAP：

```text
sudoNotBefore
sudoNotAfter
```

RFC3339 → generalized time：

```text
YYYYMMDDHHMMSSZ
```

Exact CLI/backend behavior MUST be verified on the supported FreeIPA target。

Existing sudo command denylist and safety validation MUST be reused。

## 11. Authentication policies（Phase 2）

```yaml
auth_policies:
  - name: production-strong-auth
    state: present

    targets:
      hosts: []
      hostgroups:
        - production-linux

    require_any:
      - otp
      - pkinit
```

Initial indicators：

```text
otp
radius
pkinit
hardened
```

MUST use FreeIPA/Kerberos native authentication indicator enforcement——
`ipa host-mod <fqdn> --auth-ind=...`（`krbPrincipalAuthInd`），一個 host-mod
call、每個 indicator 一個重複 flag，additive union（`require_any` 的多筆
policy 涵蓋同一台 host 時直接取聯集，語意等同 OR，不需要額外 Go 端邏輯）。

**Guardrail（活體驗證，見下）**：FreeIPA 的 `validate_auth_indicator`
（`ipaserver/plugins/service.py`）用 `server_find()` 判斷 target 是否為 IPA
server/replica——是的話 `host`/`cifs`/`ldap`/`HTTP` 這幾個 service prefix
一律禁止帶 auth indicator（保護 keytab-based 的基礎設施信任鏈，例如
SSSD 自己、cross-service 認證）；一般 enrolled client 只有 `cifs` 被禁止,
`host/*` 完全可以設定。因此套用前 MUST 先查 `ipa server-find --raw`,若
`auth_policies[].targets` 解析出的任一 host 落在 server/replica 集合裡就
fail closed,不可等到 `ipa host-mod` 本身報錯才發現。

**Prune**：`krbPrincipalAuthInd` 是一般屬性,不像 HBAC/sudo rule 有
pilot-owned 命名可以拿來 diff、判斷「這是不是 Pilot 設的」。所以拿掉一個
`auth_policies` 條目後,舊 indicator 不會自動消失——必須靠 Pilot 自己本地
記錄的「上次設過哪些 host」狀態（見 `internal/accessgrants` 的
auth-policy-hosts.json,同一套 `internal/statefile` 機制、breakglass
activation state 已經用過)做前後 diff,對「先前是 Pilot 設的、現在從
roster 移除了」的 host 明確送一個空值的 `--auth-ind=`（清空,而不是不帶
這個 flag——不帶 flag 對已存在的屬性完全沒有作用）。

Do not attach interactive auth indicators blindly to internal IdM services。

## 12. Grant security policies（Phase 2）

```yaml
security:
  grant_policies:
    - name: production-login
      state: present

      match:
        kinds: [temporary_grant]
        hostgroups: [production-linux]

      require:
        max_duration: 8h
        reason: true
        ticket: true
        auth_policy: production-strong-auth
```

`match.kinds` 的合法值即 §6 的三個 grant kind（`temporary_grant`/`sudo_grant`/
`breakglass`）。

Match MUST evaluate **resolved targets**：

- direct hosts
- hostgroups
- nested hostgroups where applicable

Do not introduce arbitrary expression language in v3.0。

Supported duration grammar：

```text
30m
1h
8h
24h
7d
```

## 13. Separation of Duties（Phase 2）

```yaml
security:
  conflicts:
    - name: payment-create-vs-approve
      state: present
      mutually_exclusive:
        - role-payment-create
        - role-payment-approve
```

MUST evaluate effective nested group membership。

`team-*` can feed `role-*`; therefore SoD resolver cannot only inspect direct role members。

At minimum v3.0 guarantees role-group SoD。Command-level temporary sudo SoD MAY require a later explicit privilege-label layer; do not overclaim it。

## 14. Break-glass（Phase 3）

Break-glass 分兩層，且明確分開：

1. **定義**：一個 `grants[].kind == breakglass` 條目（§6.3），存在 roster 裡，
   宣告誰（單一具名使用者）、對哪些 host/hostgroup、哪些 service，以及啟用時的
   政策上限（`activation.max_duration`、`require_reason`、`require_ticket`、
   `auth_policy`）。定義本身不是已生效的存取。
2. **啟用**：CLI 觸發的 runtime 動作，在定義的政策上限內建立一個有時效的
   managed authorization（實作方式與 §9 的 temporary_grant compiler 相同機制，
   compiled rule 命名可沿用 `pilot-grant-login-<name>-<hash>` 慣例），並記錄
   當次 reason/ticket/操作者/到期時間。

啟用 **MUST NOT** 改寫這個定義本身（不改 `subjects`/`targets`/`services`/
`activation`/`auth_policy`），也 **MUST NOT** 建立 `access-*`。啟用狀態存放在獨立的
runtime store（例如既有的 `pilot access reconcile`/`status` 所用的狀態儲存），
不寫回 roster YAML。

CLI：

```bash
pilot access breakglass activate <name>   --duration 45m   --reason "database outage"   --ticket INC-9921

pilot access breakglass deactivate <name>
pilot access breakglass status
```

`--duration` MUST NOT 超過對應定義的 `activation.max_duration`；`--reason`/
`--ticket` 依 `require_reason`/`require_ticket` 決定是否必填。

Existing `hbac.disable_allow_all` admin break-glass invariant from v2 MUST remain valid。

## 15. Account lifecycle（Phase 3）

```yaml
account_policies:
  - name: vendor01-contract
    state: present
    user: vendor01
    type: contractor

    validity:
      not_before: 2026-08-01T00:00:00+08:00
      not_after: 2026-10-31T23:59:59+08:00

    sponsor: alice
    ticket: HR-2231
```

Account expiration dominates grant：

```text
account expired -> no grant may restore access
```

Prefer FreeIPA native account/principal expiration。

## 16. Effective access explain（Phase 3）

Read-only API MUST preserve the simplified HBAC provenance rather than collapsing everything into an `access-*` concept。

Example：

```bash
pilot access explain   --user vendor01   --host db-special.ipa.pilot.internal   --service sshd   --format json
```

Source kinds：

```text
static_hbac
temporary_grant
sudo_grant
breakglass
```

三個非 `static_hbac` 的 source kind 直接等於 §6 的 `grants[].kind` 值——不需要另外的
名稱轉換表（沿用已上線詞彙的直接好處）。

Static HBAC detail SHOULD include：

```text
rule name
direct user hit
group path: user -> team/role/legacy access
direct host hit
hostgroup path
service
```

Temporary source（`temporary_grant`/`sudo_grant`）includes validity and next transition。
`breakglass` source includes current activation state（active/inactive）與到期時間，
而非 `validity`（因為定義本身沒有 validity，見 §6.3/§8）。

## 17. TUI / structured actions / MCP（Phase 3）

HBAC authoring changes from the simplification spec remain canonical。

v3 adds an `Access governance` area：

```text
Access governance
├── Static HBAC
├── Grants
├── Authentication policies
├── Security policies
├── Break-glass
├── Account lifecycle
└── Explain access
```

Do not duplicate a second static-HBAC editor。

Grant actions at minimum：

```text
create_grant                 (kind required: temporary_grant | sudo_grant | breakglass)
set_grant_subjects
set_grant_targets
set_grant_validity            (temporary_grant / sudo_grant only)
set_grant_privilege           (sudo_grant only)
set_grant_justification       (temporary_grant / sudo_grant only)
set_grant_activation          (breakglass only)
delete_grant
inspect_access
activate_breakglass
deactivate_breakglass
```

Grant fields must support both direct and grouped subject/target collections
（`breakglass` 除外，見 §7：`subjects.groups` 恆為空）。

Existing HBAC actions remain：

```text
create_hbac_rule(users, groups, hosts, hostgroups, services)
set_hbac_users
set_hbac_groups
set_hbac_targets
set_hbac_services
```

## 18. Apply ordering

```text
1 schema validation
2 reference resolution
3 effective user/group/hostgroup expansion
4 SoD evaluation
5 grant policy evaluation
6 reconcile identities/groups/hosts
7 reconcile auth policies
8 reconcile static HBAC/sudo
9 compile/reconcile grants (temporary_grant, sudo_grant)
10 reconcile breakglass activation state (independent of step 9's validity-driven reconcile)
11 reconcile account lifecycle
12 refresh SSSD where required
13 verify
```

Steps 1–5 fail before mutation。

## 19. Tests

### Static HBAC integration
- team direct HBAC survives under v3
- role direct HBAC survives
- legacy access survives + warning
- filesystem still rejected
- users+groups mixed
- hosts+hostgroups mixed
- sibling preservation remains

### Grant schema
- temporary_grant users only
- temporary_grant team group
- temporary_grant role group
- temporary_grant legacy access group
- temporary_grant filesystem rejected
- mixed users+groups
- mixed hosts+hostgroups
- sudo_grant role group
- sudo_grant team group rejected
- breakglass subjects.groups rejected (must be empty)
- breakglass with validity present rejected
- breakglass with justification present rejected
- invalid FQDN
- invalid time interval
- approval field rejected
- pre-Phase-1 shaped grant (name/kind/subjects/targets only, kind in
  {temporary_grant, breakglass}) still validates or fails with an explicit,
  actionable message — never silently reclassified (baseline-compat, §5a)

### Compiler
- temporary_grant creates HBAC with no wrapper group
- lifecycle state maps correctly
- repeated reconcile idempotent
- sudo_grant validity native attributes verified
- breakglass activation creates managed authorization without mutating the
  grant definition
- breakglass activation duration capped by `activation.max_duration`

### Explain
- static direct user
- static team path
- static role path
- legacy access path
- temporary_grant
- sudo_grant
- breakglass (active and inactive)
- multiple simultaneous sources

### Integration
- real FreeIPA modern static fixture
- real FreeIPA legacy compatibility fixture
- timed login activation/expiry via reconcile
- timed sudo
- breakglass activate/deactivate end-to-end on FreeIPA target
- auth indicator enforcement where fixture supports it

## 20. Acceptance criteria

v3.0 is complete only if：

```text
new access-* group creation = impossible through sanctioned tooling
static team/role/direct HBAC = first-class
grants[].kind = temporary_grant | sudo_grant | breakglass, additive to the
  already-shipped temporary_grant/breakglass values (no rename, no new
  top-level breakglass section)
temporary_grant / sudo_grant = direct compiled policy, no wrapper group
breakglass = grants-kind definition + separate runtime activation, never a
  standing wrapper group
filesystem group cannot become login subject
legacy access remains valid but deprecated
explain preserves real provenance
all three phases in §21 have independently passed their exit criteria with
  vm-target evidence
```

Approval is not required for any v3.0 capability。

## 21. Implementation phases

單一 spec，三個循序 phase；每個 phase MUST 在前一個 phase 的 exit criteria 有
vm-target evidence 之後才開工，依 `vm-target-spec-testing` skill 驗證，符合
AGENTS.md §1 的 actual-run 規則。

### Phase 1 — Grants core + lifecycle + compilers

Scope：§5、§5a、§6、§7、§8、§9、§10；CLI `pilot access reconcile --once`、
`pilot access status`。

Exit criteria：

- `roster_grants.go` 依 §5a additive 擴充，既有 grants 測試全部維持通過
- lifecycle evaluator 用 injected clock 單元測試 pending/active/expired/absent
- `temporary_grant` → managed HBAC compiler，無 wrapper group，reconcile 冪等
- `sudo_grant` → native `sudoNotBefore`/`sudoNotAfter` compiler，在真實 FreeIPA
  vm-target 上驗證過
- §19「Static HBAC integration」「Grant schema」「Compiler」測試群組在
  vm-target 上通過

### Phase 2 — Policy layer

Scope：§11 auth_policies、§12 security.grant_policies、§13 security.conflicts
(SoD)。

Depends on：Phase 1（grant_policies 需要對已編譯的 grants 做 match）。

Exit criteria：

- auth indicator enforcement 在支援的 FreeIPA target 上驗證過
- duration grammar parser（30m/1h/8h/24h/7d）單元測試覆蓋
- SoD 能解析 nested team→role membership（沿用既有 nested-HBAC 測試模式）
- §19 auth-indicator / grant-policy / SoD 測試通過

### Phase 3 — Break-glass + account lifecycle + explain + surfaces

Scope：§6.3/§14 breakglass 定義與啟用 CLI、§15 account_policies、§16 explain、
§17 TUI/actions/MCP。

Depends on：Phase 1（grants/compiler 基礎設施）、Phase 2（breakglass 的
`auth_policy` 引用需要 auth_policies 存在）。

Exit criteria：

- breakglass 啟用建立 runtime state，不改動 roster 裡的 grant 定義
- account expiration dominates grant（有測試：帳號過期 + grant 仍 active = 無法存取）
- explain 能區分全部 4 個 source kind 並保留真實 provenance path
- TUI「Access governance」區域 + MCP tools + structured actions 落地，既有
  static-HBAC editor 未被重複
- §20 全部 acceptance criteria 滿足
