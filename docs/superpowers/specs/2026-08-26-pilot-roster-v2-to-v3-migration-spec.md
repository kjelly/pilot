# Pilot Roster v2 → v3 Migration 實作規格

## 1. Goal

實作安全、可重複、fail-closed 的 roster schema v2 → v3 migration。

本 migration 的唯一目的，是讓 `grants[]` 成為 first-class v3 schema —— 也就是 HBAC simplification spec §27（Integration contract with the Pilot v3 specification set）定義的 temporary/breakglass login 與 sudo 授權容器。除 `grants[]` 之外，v3.0 不預先建立任何其他頂層 section；`auth_policies`、`security.*`、`account_policies` 等欄位目前沒有任何 spec 定義其形狀，留給各自的 v3.1/v3.2 spec 定案後再各自以 additive migration 加入（見 §5）。

**HBAC authorization simplification 是獨立的 v2-compatible prerequisite，並不需要 schema migration。**

本 spec 受下列文件 §27 全部規則約束（見 §3）：

```text
docs/superpowers/specs/2026-08-26-pilot-hbac-authorization-simplification-spec.md
```

基線：

```text
521366e899561f7e38edc012fc88339742382468
```

## 2. Required prerequisite

coding agent MUST 先完成並通過：

```text
docs/superpowers/specs/2026-08-26-pilot-hbac-authorization-simplification-spec.md
```

因此 migration engine 面對的合法 v2 roster 可能包含：

```text
modern:
  HBAC subjects.groups = team-* / role-*
  HBAC subjects.users  = direct users
  HBAC targets.hosts   = direct enrolled FQDNs

legacy:
  HBAC subjects.groups = access-*
```

兩者都必須可遷移。

## 3. Architecture to preserve

先讀：

```text
internal/inventory/roster_version.go
internal/inventory/roster_validate.go
internal/inventory/roster_migrate.go
internal/inventory/roster_migrate_file.go
internal/inventory/roster_effective.go
cmd/pilot/cmd/roster_lint.go
playbooks/apply/freeipa-identity-apply.yml
playbooks/apply/freeipa-identity.roster.example.yaml
docs/verification/freeipa-identity.md
docs/superpowers/specs/2026-08-26-pilot-hbac-authorization-simplification-spec.md   # 尤其 §27
```

沿用既有 transaction：

```text
lock
 -> read
 -> detect schema
 -> validate source
 -> transform in memory
 -> validate candidate
 -> semantic fingerprint
 -> backup
 -> atomic replace
 -> reopen + validate
 -> rollback on failure
```

## 4. Version constants

新增：

```go
const (
    RosterSchemaV1 RosterSchemaVersion = 1
    RosterSchemaV2 RosterSchemaVersion = 2
    RosterSchemaV3 RosterSchemaVersion = 3

    CurrentRosterSchemaVersion = RosterSchemaV3
)
```

HBAC simplification phase本身不得提前修改這些 constants。

## 5. v3 top-level additions

合法 v2 → v3 candidate 在缺少時 append，且僅 append 這一個 section：

```yaml
grants: []
```

`grants[]` 每個元素的形狀由 HBAC spec §27.3 定義，MUST 遵守：

```yaml
grants:
  - kind: temporary_grant | breakglass   # §27.5 explain 分類之一
    subjects:
      users: []
      groups: []
    targets:
      hosts: []
      hostgroups: []
```

規則（HBAC spec §27.3 / §27.5）：

- login grant 的 `subjects.groups` 接受 team / role / legacy access；filesystem group 禁止。
- sudo grant 的 `subjects.groups` 僅接受 role。
- 兩者的 `subjects.users` 與 `targets.hosts` 都是 first-class（不強制透過 group/hostgroup 才能授權）。
- `grants[]` MUST NOT 重建已移除的 wrapper 抽象（不得再發明一個等價於舊 `access-*` 的東西）。
- breakglass 不是獨立 top-level section；它是 `grants[]` 裡 `kind: breakglass` 的一筆資料，與 §27.5 的 explain 分類（static_hbac / temporary_grant / breakglass / sudo_grant）對齊。
- schema migration 本身不合成任何 `grants[]` 項目 —— v2 沒有 grants 概念可轉換，這裡新增的只是空陣列骨架，供之後 authoring 使用。

**實作備註（結構驗證 vs. login/sudo 語意驗證）**：`§27` 從未替 login grant 和 sudo grant 命名一個判別欄位（`kind` 只分 temporary_grant/breakglass，不分 login/sudo）。本 migration 附帶的 `checkGrants` 結構驗證器因此只強制執行兩種 flavor 共通、無條件成立的那條規則——filesystem group 永遠不能當 grant subject——不去猜一個 §27 沒定義的判別欄位名稱來強制執行 login-only-team/role/access 與 sudo-only-role 的差異化限制。這條差異化限制留給日後定義 grants authoring 的 v3.x spec 補齊；理由與 §5 對 auth_policies/security.\*/account_policies 的態度一致：schema 已定的部分（filesystem 永遠禁止）現在就強制執行，schema 沒定的部分（判別欄位）不猜。

**Out of scope for this migration**（不建立，留給各自尚未定案的 v3.x spec 自行以 additive migration 加入自己的頂層 key）：

```text
auth_policies
security.grant_policies
security.conflicts
account_policies
password_policies    # 若 v3.2 最終採用 top-level
credential_policies  # 同上
```

這些欄位在 HBAC spec §27 或現有 codebase 中都沒有形狀定義。schema version 是穩定契約，不應該在形狀未定案前就先佔用欄位名稱 —— v3.1（security operations）、v3.2（identity hardening）各自定案後，各自跑一次小型 additive migration（例如 v3.0 → v3.1 只新增 `security:`，不動 `grants[]`），比在 v3.0 就先猜測形狀更安全，也避免日後因形狀猜錯而需要二次 rename migration。

## 6. Explicit no-transform rules

對齊 HBAC spec §27.4，並加上本 migration 額外的 fail-closed 邊界。Migration MUST NOT：

- 建立 `access-*`
- 刪除 `access-*`
- 把 `access-*` 改成 `role-*`
- flatten access group membership
- 把 team/role HBAC 改寫成 grants
- 把 static direct-user/direct-host HBAC 改寫成 grants
- 自動加 expiry
- 自動加 MFA
- 自動建立 SoD rule
- 自動改 account lifecycle

Schema migration 必須保持 static authorization 完全一致。

## 7. Pure transformer

新增：

```go
func MigrateRosterV2ToV3(root *yaml.Node) (*yaml.Node, error)
```

要求：

- preserve comments
- preserve anchors/aliases
- preserve scalar style
- preserve section/list order
- change only schema version and append safe empty v3 sections
- fail rather than overwrite conflicting nodes

## 8. Chained migration

`pilot roster migrate`：

```text
v1 -> v2 -> v3
v2 -> v3
v3 -> no-op
```

推薦：

```go
type rosterMigrationStep struct {
    From      RosterSchemaVersion
    To        RosterSchemaVersion
    Transform func(*yaml.Node) (*yaml.Node, error)
}
```

每一步都 validate。

**必須同步修改的既有硬編碼閘門**：`internal/inventory/roster_migrate_file.go` 的 `MigrateRosterFile` 目前寫死：

```go
if targetVersion != int(RosterSchemaV2) {
    return RosterMigrationResult{}, fmt.Errorf(
        "migrate roster %s: unsupported target schema version %d (only %d is supported)",
        path, targetVersion, RosterSchemaV2)
}
```

這段檢查必須改成從 `rosterMigrationStep` chain 動態推導支援範圍（例如檢查 chain 裡是否存在一條 `From <= current <= To == targetVersion` 的路徑），否則即使新增了 `MigrateRosterV2ToV3`，任何 `TargetVersion: 3` 的呼叫仍會在這一行被直接拒絕，`EnsureRosterCurrent`（見 §12）也會跟著失敗。

## 9. Semantic fingerprint

v2→v3 before/after MUST preserve：

- users
- groups including legacy access groups
- hosts
- hostgroups
- netgroups
- FreeIPA metadata
- NFS / NFS clients
- policy_exceptions
- effective HBAC
- effective sudo
- rendered NFS selectors

Effective HBAC fingerprint MUST cover the simplified geometry：

```text
direct subjects.users
UNION recursively expanded subjects.groups

direct targets.hosts
UNION recursively expanded targets.hostgroups
```

No category-specific special casing in fingerprint resolver。

## 10. Encrypted roster

繼續支援：

```bash
pilot roster migrate ~/.vault/ipa-identity.yaml   --vault-password-file ~/.vault/vault-pass
```

要求：

- plaintext never written to temp
- backup remains encrypted
- no decrypted YAML in logs
- wrong password fails before write

## 11. CLI

v2 lint after simplification may be：

```text
ok: schema v2; no issues found
warning: group "access-old" uses deprecated category "access" ...
notice: current schema is v3; run pilot roster migrate ...
```

deprecation warning 與 schema-upgrade notice 是不同概念。

`pilot roster migrate --dry-run` SHOULD output：

```json
{
  "from_version": 2,
  "to_version": 3,
  "steps": ["v2->v3"],
  "changed": true,
  "semantic_equivalent": true
}
```

## 12. EnsureRosterCurrent

`internal/inventory.EnsureRosterCurrent`（`roster_migrate_file.go`）已經是唯一的自動升級 chokepoint，且已經接在：

```text
cmd/pilot/cmd/deploy_completeness.go
cmd/pilot/cmd/edit_tui_roster.go
cmd/pilot/cmd/edit_tui.go
cmd/pilot/cmd/inventory.go
```

這 4 處都呼叫 `EnsureRosterCurrent(path, RosterMigrationOptions{})`，`TargetVersion` 留空即預設吃 `CurrentRosterSchemaVersion`。因此完成 §4（把常數改成 V3）與 §8（chain 支援 v2→v3、拆掉硬編碼閘門）後，這 4 個入口**不需要任何額外改動**就會自動把 roster 升到 v3 —— 這是既有設計已經正確集中的地方，本 migration 不需要、也不應該重新分別接線。

驗收方式：`grep -rn "EnsureRosterCurrent" cmd/pilot/cmd/*.go`，確認呼叫點清單與上面一致，沒有遺漏也沒有需要新增的入口。

Migration failure MUST stop later mutation（`EnsureRosterCurrent` 回傳 error 時，呼叫方必須中止而非略過繼續寫入）。

## 13. Required tests

1. modern v2 team HBAC → v3, effective access identical
2. modern v2 role HBAC → v3, effective access identical
3. mixed direct user + group HBAC → identical
4. mixed direct host + hostgroup HBAC → identical
5. legacy access HBAC → identical and group preserved
6. migration never creates access groups
7. migration never rewrites static HBAC as grants
8. plain v2→v3
9. encrypted v2→v3
10. chained v1→v3
11. v3 no-op
12. future version fail closed
13. invalid v2 fails before backup
14. v2 roster 已存在衝突節點（例如手動加了格式不對的 `grants:`）→ fail before backup，不覆寫（§7 fail rather than overwrite conflicting nodes）
15. comments/anchors preserved
16. semantic mismatch fail
17. atomic rollback
18. concurrent lock
19. wrong vault password no-write

## 14. Acceptance criteria

```text
CurrentRosterSchemaVersion == 3
```

且：

- HBAC simplification remains backward compatible
- legacy access groups survive migration unchanged
- modern team/role/direct HBAC survives unchanged
- migration changes zero authorization semantics
- v1→v2 safety guarantees remain intact
- `grants[]` 的形狀（kind/subjects/targets）符合 HBAC spec §27.3 / §27.5
- v3.0 除 `grants[]` 外不新增任何未經 spec 定義形狀的頂層 section（見 §5 out of scope）
- `EnsureRosterCurrent` 既有 4 個呼叫點（§12）在不改動呼叫端程式碼的情況下自動生效

