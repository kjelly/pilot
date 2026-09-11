# Pilot Host Annotations + FreeIPA Metadata Projection 實作規格

- **日期**：2026-09-09
- **狀態**：VERIFIED / implemented — Phase 1-5 全部完成，live vm-target L1-L13 全數 PASS（見 `docs/verification/freeipa-client.md` §9 v1.6 變更紀錄）
- **目標 repository**：`kjelly/pilot`
- **設計基準**：`6ff866cd92961650e279dfb1b1967f1ef01fb104`（`main`，2026-09-07）
- **建議落版位置**：`docs/superpowers/specs/2026-09-09-host-annotations-freeipa-sync-spec.md`
- **主要影響元件**：`hosts.yml` / inventory parser-render-generator、`pilot edit`、`freeipa-client`、FreeIPA host metadata
- **功能名稱**：**Pilot Host Annotations**
- **風險等級**：Medium
- **相容性要求**：不得改變既有 role、env、deployment availability、Ansible extra host vars、FreeIPA enrollment、HBAC/sudo 或 DNS semantics

---

## 1. 目標

Pilot 需要允許 operator 在 `hosts.yml` 對任意 host 記錄供人員查閱的 key/value metadata，例如：

- 實體位置；
- 所屬專案；
- 使用單位 / owner；
- asset tag；
- cost center；
- 用途 / note。

範例：

```yaml
hosts:
  gpu-a01:
    ansible_host: "10.20.30.41"
    roles:
      - freeipa-client
      - linux-servers
      - host-monitoring
    env: prod

    annotations:
      location: "DC1/Rack-A03/U18"
      project: "llm-training"
      owner: "ai-platform"
      asset_tag: "IT-2026-00128"
      note: "H100 training node"
```

本功能 MUST 同時做到：

1. `annotations` 在 `hosts.yml` 有獨立 schema，不與 Ansible deployment vars 混用。
2. `pilot inventory lint` 能驗證 annotation。
3. `pilot inventory generate` 將 annotations 投影成 namespaced Ansible host var `pilot_annotations`。
4. `pilot edit` 提供 annotations CRUD。
5. 對已由 `freeipa-client` 管理並成功 enrollment 的 host，將 annotations 同步到 FreeIPA host object。
6. FreeIPA projection MUST declarative、idempotent，並只管理 Pilot 自己擁有的 values。
7. 不得覆寫其他系統或人工寫入的 FreeIPA `userClass`。
8. `location` SHOULD 同時安全投影到 FreeIPA 原生 `nshostlocation`，讓 Web UI / `ipa host-show` 更容易閱讀。
9. annotation 永遠是 descriptive metadata；Pilot 本身不得用它控制 role、host selection、deploy、HBAC、sudo、automember 或 repair authorization。
10. annotation 禁止儲存 secret。

---

## 2. 現況

### 2.1 `hosts.yml` 已有 open-ended Extra，但不適合直接拿來做 metadata

目前：

```go
type Host struct {
    Name                   string
    AnsibleHost            string
    AnsibleUser            string
    SSHKeyFile             string
    Roles                  []string
    Env                    string
    DeploymentAvailability DeploymentAvailability
    Extra                  map[string]string
}
```

`internal/inventory/inventory.go` 對未知 host key 會放進：

```go
Extra map[string]string
```

並在 generated inventory 中直接輸出成 host vars。

因此今天 technically 可以：

```yaml
hosts:
  gpu-a01:
    location: "DC1/Rack-A03/U18"
    project: "llm-training"
```

但這兩個 key 會和真正影響 automation 的 Ansible vars 共用相同 namespace。

這不是本功能可接受的正式資料模型。

### 2.2 `pilot edit` 已有 Extra CRUD

現有 TUI host menu 有：

```text
其他變數(共 N 個)
```

且已有：

- add extra var
- edit extra var
- delete extra var
- structured automation driver
- flow tests

Host Annotations MUST 沿用這套 UX pattern，但 MUST 使用不同資料欄位與不同 semantic action ID。

### 2.3 FreeIPA `userClass` 適合做 namespaced provisioning metadata

FreeIPA host object 支援 `userClass`：

- LDAP attribute：`userClass`
- CLI display：`Class`
- multi-valued
- `host_add` / `host_mod` / `host_find` 支援
- 原始設計就是讓 provisioning systems 放 custom tags
- 可供 local interpretation / automember 使用

因此 Pilot V1 不新增自訂 LDAP schema。

FreeIPA 官方參考：

- https://www.freeipa.org/page/HowTo/Add_a_new_attribute
- https://www.freeipa.org/page/V3/Integration_with_provisioning_systems
- https://freeipa.readthedocs.io/en/ipa-4-9/api/host_mod.html
- https://freeipa.readthedocs.io/en/ipa-4-11/api/host_add.html

### 2.4 重要限制

`userClass`：

- 是 case-insensitive matching；
- schema 單一 value 上限為 256；
- 可被 FreeIPA automember / namespace 類機制解讀。

因此本規格 MUST 使用 `pilot.annotation.` namespace，且 Pilot MUST NOT 建立依賴 annotation 的 automember/access policy。

---

## 3. 核心設計原則

### 3.1 Canonical source of truth

對使用簡化 inventory 流程的 workspace：

```text
hosts.yml
  annotations
      |
      +--> generated inventory.yml
      |      pilot_annotations
      |
      +--> freeipa-client reconcile
             |
             +--> userClass: pilot.annotation.*
             +--> nshostlocation (location only)
```

`hosts.yml` 是 canonical source。

FreeIPA 是 projection，不是第二份可反向編輯的 source of truth。

MUST NOT：

```text
FreeIPA -> 自動回寫 hosts.yml
```

### 3.2 Descriptive metadata 與 operational config 分離

以下是 operational config：

```yaml
roles:
env:
deployment_availability:
ansible_host:
freeipa_client_dns_replace_from_address:
```

以下才是 descriptive metadata：

```yaml
annotations:
  location:
  project:
  owner:
```

Pilot MUST NOT 因 annotation value 改變：

- role membership；
- env group；
- deployment target；
- access permission；
- sudo；
- HBAC；
- hostgroup；
- FreeIPA automember；
- agent repair authority；
- monitoring selection；
- decommission retention decision。

若未來真的需要 policy label，必須另建有明確 semantics 的 schema，不得偷用 `annotations`。

### 3.3 不新增 FreeIPA LDAP schema

V1 MUST NOT：

- 修改 389-DS schema；
- 增加 custom objectClass；
- 直接操作 LDAP DN；
- fork FreeIPA schema。

統一使用既有：

```text
userClass
nshostlocation
```

### 3.4 Pilot ownership 必須可辨識

所有 Pilot 管理的 `userClass` MUST 使用：

```text
pilot.annotation.<key>=<value>
```

例如：

```text
pilot.annotation.location=DC1/Rack-A03/U18
pilot.annotation.project=llm-training
pilot.annotation.owner=ai-platform
pilot.annotation.asset_tag=IT-2026-00128
```

Pilot 只能新增、修改、刪除符合 `pilot.annotation.` prefix 的 values。

---

## 4. `hosts.yml` schema

### 4.1 新欄位

在每一個 host entry 新增：

```yaml
annotations:
  <key>: "<value>"
```

完整範例：

```yaml
hosts:
  gpu-a01:
    ansible_host: "10.20.30.41"
    roles: [freeipa-client, linux-servers, host-monitoring]
    env: prod
    deployment_availability: required

    annotations:
      location: "DC1/Rack-A03/U18"
      project: "llm-training"
      owner: "ai-platform"
      asset_tag: "IT-2026-00128"
```

### 4.2 Go model

修改：

```go
type Host struct {
    Name                   string
    AnsibleHost            string
    AnsibleUser            string
    SSHKeyFile             string
    Roles                  []string
    Env                    string
    DeploymentAvailability DeploymentAvailability

    // Descriptive, non-secret metadata. No deployment semantics.
    Annotations map[string]string

    // Existing open-ended Ansible host vars. Operational namespace.
    Extra map[string]string
}
```

`Annotations` 與 `Extra` MUST 是完全不同的 map。

### 4.3 YAML type

`annotations` MUST 是：

```text
map[string]string
```

以下 MUST fail lint：

```yaml
annotations:
  project: 123
```

```yaml
annotations:
  enabled: true
```

```yaml
annotations:
  projects:
    - alpha
    - beta
```

```yaml
annotations:
  owner:
    team: ai
```

不得用 `fmt.Sprint()` 將非 string 自動轉成字串。

理由：human metadata 必須有 deterministic round-trip，不允許 YAML implicit typing 造成：

```text
true -> "true"
0012 -> "12"
2026-09-09 -> timestamp/string ambiguity
```

### 4.4 Key contract

Key MUST：

```regex
^[a-z][a-z0-9_.-]{0,62}$
```

因此：

```text
location
project
project.phase
asset_tag
cost-center
owner.team
```

合法。

以下不合法：

```text
Location
PROJECT
_foo
foo/bar
foo bar
```

理由：

- FreeIPA `userClass` equality 是 case-insensitive；
- key 全 lowercase 可消除 `Project` / `project` alias；
- 限制 ASCII key 讓 parser / Portal / CLI 穩定。

### 4.5 Value contract

Value MUST：

- 是 YAML string；
- UTF-8；
- 非空；
- `value == strings.TrimSpace(value)`；
- 不得含 `\r`、`\n`、NUL；
- SHOULD 避免其他控制字元；
- 可以包含一般空白、`/`、`.`、`-`、`_`、`:`、`=`、Unicode。

例如：

```yaml
annotations:
  project: "LLM Project A"
  location: "台北機房/DC1/Rack-A03/U18"
  note: "owner=AI Platform"
```

均合法。

### 4.6 FreeIPA serialized length gate

對每筆：

```text
serialized = "pilot.annotation." + key + "=" + value
```

UTF-8 encoded serialized value MUST：

```text
len([]byte(serialized)) <= 256
```

超過 MUST 在 `pilot inventory lint` 階段 fail。

不得等到 `ipa host-mod` 才發現。

### 4.7 每 host annotation 數量

V1：

```text
max annotations per host = 32
```

超過 MUST lint error。

這是 abuse / accidental data dump 防線，不代表 FreeIPA 本身只能放 32 個 `userClass`。

### 4.8 Secret prohibition

Annotation MUST NOT 用來存：

```text
password
token
api key
private key
credential
secret
cookie
session
```

實作 SHOULD 抽出或重用 `internal/decommission/store.go` 既有的
`secretLikeKeyPattern` 正規式（目前用於 decommission evidence 的
encode gate，尚未被 `pilot edit` / automation driver 的 extra-var 路徑
引用）。MUST NOT 假設 `pilot edit` 已有等價拒絕邏輯——目前該路徑只有
`TestValidateAddVaultKeyAllowsSecretLikeKeyName` 這種「允許 vault key
使用 secret 樣式命名」的相反邏輯。建議抽成 `internal/inventory`（或共用
package）的匯出函式，供 lint、TUI、automation driver 三處共用同一份
regex，避免三套判斷各自 drift。

至少以下 key MUST reject：

```text
password
passwd
secret
token
api_key
apikey
private_key
credential
credentials
```

且 nested/dotted 形式也要判斷最後 token，例如：

```text
service.api_key
project.secret
```

MUST reject。

錯誤訊息需明確：

```text
annotation "api_key" looks secret-bearing; annotations are projected to FreeIPA and must contain non-secret descriptive metadata only
```

---

## 5. Parser / Render

### 5.1 Parse

目前 parser 對 unknown field：

```go
default:
    h.Extra[k] = fmt.Sprint(v)
```

新增：

```go
case "annotations":
    annotations, err := parseAnnotations(v)
    if err != nil {
        return nil, fmt.Errorf("inventory: host %q: annotations: %w", name, err)
    }
    h.Annotations = annotations
```

`annotations` MUST NOT 落入 `Extra`。

### 5.2 Render

`internal/inventory/render.go` 必須 deterministic。

輸出順序：

```text
ansible_host
ansible_user
ansible_ssh_private_key_file
deployment_availability
Extra (sorted)
annotations (sorted)
roles
env
```

或將 `annotations` 放在 `Extra` 前亦可；但測試必須鎖定唯一順序。

建議：

```yaml
  gpu-a01:
    ansible_host: "10.20.30.41"
    annotations:
      asset_tag: "IT-2026-00128"
      location: "DC1/Rack-A03/U18"
      owner: "ai-platform"
      project: "llm-training"
    roles: [freeipa-client, linux-servers]
    env: "prod"
```

Annotations key MUST lexicographically sorted。

### 5.3 Comment preservation

現有 `Render` 本來就不 preservation comments。

本功能不處理 comment round-trip。

---

## 6. Generated Ansible inventory

### 6.1 不直接展開 annotation key

MUST NOT：

```yaml
all:
  hosts:
    gpu-a01:
      location: "..."
      project: "..."
```

因為會污染 Ansible host-var namespace。

MUST：

```yaml
all:
  hosts:
    gpu-a01:
      ansible_host: "10.20.30.41"
      pilot_annotations:
        location: "DC1/Rack-A03/U18"
        project: "llm-training"
        owner: "ai-platform"
```

### 6.2 Name

固定：

```text
pilot_annotations
```

不得同時支援：

```text
annotations
host_annotations
metadata
labels
```

等 alias。

### 6.3 Empty annotations

沒有 annotation 時 SHOULD 不產生：

```yaml
pilot_annotations: {}
```

而是省略欄位。

### 6.4 Manual `inventory.yml`

直接維護完整 `inventory.yml` 的 operator MAY 直接使用：

```yaml
pilot_annotations:
  project: "alpha"
```

但 `freeipa-client` apply MUST 對這條 bypass `hosts.yml` 的路徑再次做 runtime validation。

原因：`pilot inventory lint` 只保護 simplified `hosts.yml` path。

---

## 7. FreeIPA projection contract

### 7.1 userClass serialization

每筆 desired annotation：

```text
key = project
value = llm-training
```

轉成：

```text
pilot.annotation.project=llm-training
```

不做 base64、JSON、URL encoding。

原因：FreeIPA UI / CLI 需要讓人可以直接閱讀。

### 7.2 Parsing

對 live `userClass`：

1. case-insensitive 判斷 prefix `pilot.annotation.`；
2. 去掉 prefix；
3. 以第一個 `=` 分割 key/value；
4. value 其餘 `=` 全部保留。

例如：

```text
pilot.annotation.note=owner=AI Platform
```

解析成：

```text
key   = note
value = owner=AI Platform
```

### 7.3 Foreign values

例如 live FreeIPA：

```text
userClass:
  XYZ
  provisioning-linux
  external.cmdb=1234
  pilot.annotation.project=alpha
```

Pilot-owned：

```text
pilot.annotation.project=alpha
```

Foreign：

```text
XYZ
provisioning-linux
external.cmdb=1234
```

所有 foreign values MUST preserve。

### 7.4 禁止 full replace

MUST NOT：

```bash
ipa host-mod host1 --setattr=userclass=...
```

把整個 `userClass` 重建。

因為會覆寫 foreign values，且有 race。

只能對 Pilot-owned individual values 使用：

```bash
ipa host-mod <fqdn> --delattr=userclass=<exact-old-value>
ipa host-mod <fqdn> --addattr=userclass=<desired-value>
```

命令 MUST 用 Ansible `argv`，不得拼 shell command string。

### 7.5 Duplicate Pilot key

若 live FreeIPA 出現：

```text
pilot.annotation.project=alpha
pilot.annotation.project=beta
```

同一個 key 有多個 Pilot-owned value：

```text
CONFLICT_DUPLICATE_MANAGED_KEY
```

MUST fail before mutation。

不得猜：

- 第一筆；
- 最後一筆；
- lexicographically smallest；
- 自動刪除全部再重建。

### 7.6 Malformed Pilot-owned entry

例如：

```text
pilot.annotation.foo
pilot.annotation.=bar
pilot.annotation.BadKey=x
```

MUST：

```text
CONFLICT_MALFORMED_MANAGED_VALUE
```

fail closed。

原因：prefix 已宣告像是 Pilot-owned，但 live state 不符合 Pilot contract，需人工確認，不可自動破壞。

### 7.7 Case behavior

因 LDAP equality case-insensitive：

```text
pilot.annotation.project=Alpha
pilot.annotation.project=alpha
```

不可視為兩個合法 concurrent values。

若 desired 只是大小寫修改，reconcile MUST 使用：

```text
DELETE old spelling
ADD desired spelling
```

不得只靠 case-insensitive set comparison判定 NOOP。

---

## 8. `location` 原生 FreeIPA projection

### 8.1 Dual projection

若：

```yaml
annotations:
  location: "DC1/Rack-A03/U18"
```

FreeIPA desired：

```text
userClass:
  pilot.annotation.location=DC1/Rack-A03/U18

nshostlocation:
  DC1/Rack-A03/U18
```

`userClass` 仍保留 location，因為：

- 所有 annotation 有一致 round-trip；
- `nshostlocation` 是方便人類看 FreeIPA UI 的 projection；
- `pilot.annotation.location` 同時扮演 ownership marker。

### 8.2 Ownership/adoption gate

以下表格同時涵蓋「該 host 第一次被 Pilot 設定 location」與「已由 Pilot
管理、後續每次 reconcile」兩種情形——`X` 一律代表**當次 reconcile 的
desired location**，不限定是該 host 的第一次 apply：

| Current Pilot location marker | Current `nshostlocation` | 行為 |
|---|---|---|
| none | empty | set marker + set native location |
| none | `X` | adopt：add marker，native unchanged |
| none | non-empty `Y != X` | FAIL `CONFLICT_FOREIGN_LOCATION` |
| old=`Y` | native=`Y` | Pilot owns；可改為 `X` |
| old=`Y` | native=`X` | acceptable converged native; replace marker |
| old=`Y` | native=other `Z` | FAIL `CONFLICT_LOCATION_DRIFT` |

Pilot MUST NOT 在沒有 ownership marker 的情況下覆蓋非空 `nshostlocation`。

### 8.3 Removal

若 source 刪除：

```yaml
annotations:
  # location removed
```

而 live：

```text
pilot.annotation.location=DC1/Rack-A03/U18
nshostlocation=DC1/Rack-A03/U18
```

MUST：

1. remove Pilot location userClass marker；
2. clear `nshostlocation`。

若 marker=`X`，但 native location 已人工改成 `Y`：

```text
CONFLICT_LOCATION_DRIFT
```

MUST fail，不得清除 `Y`。

### 8.4 Native mutation

設定：

```bash
ipa host-mod <fqdn> --setattr=nshostlocation=<value>
```

清除時 SHOULD 使用 exact current value：

```bash
ipa host-mod <fqdn> --delattr=nshostlocation=<current>
```

不得對 host object 做整體 setattr replacement。

---

## 9. Reconcile execution model

### 9.1 V1 掛在 `freeipa-client` lifecycle

V1 MUST 使用現有 client lifecycle 的 canonical FQDN：

```yaml
ipa_client_fqdn
```

而不是在 controller 端自行猜：

```text
inventory_hostname + domain
ansible_host reverse DNS
FreeIPA host-find by IP
```

目前 `freeipa-client-apply.yml` 的 default：

```text
ipa_client_fqdn = ansible_hostname + "." + ipa_domain
```

因此最安全的 V1 是在 client 已成功 enrollment 後執行 annotation reconcile。

新增：

```text
playbooks/apply/tasks/freeipa-client-host-annotations.yml
```

或更通用：

```text
playbooks/apply/tasks/freeipa-host-annotations.yml
```

由：

```text
playbooks/apply/freeipa-client-apply.yml
```

include。

### 9.2 執行位置

可沿用 freeipa-client 現有 admin-kinit / `ipa` CLI auth flow。

MUST NOT 為 annotations 再建立第二套：

- LDAP bind password；
- JSON-RPC credential；
- service account；
- direct 389-DS bind。

### 9.3 Host must exist

Annotation reconcile 前：

```bash
ipa host-show <ipa_client_fqdn> --all --raw
```

MUST 成功。

如果 host object 不存在：

```text
HOST_ABSENT
```

MUST fail。

Annotations feature MUST NOT 自行：

```bash
ipa host-add ...
```

Host object creation/enrollment 仍由既有 FreeIPA client lifecycle 擁有。

### 9.4 V1 eventual consistency

因 V1 故意重用 client runtime FQDN：

> 若 operator 在 host 離線期間只修改 `hosts.yml.annotations`，FreeIPA copy 會維持 last-applied state，直到該 host 下一次成功執行 `freeipa-client` reconcile。

這是 V1 明確限制，不得偷偷用 inventory key / IP 猜 host FQDN 來繞過。

Future V2 若要求「host 離線也能立即更新 FreeIPA metadata」，必須先正式加入 canonical FreeIPA host identity field，例如：

```yaml
freeipa_fqdn:
```

並讓 client enrollment 與 central metadata reconciler 共用同一欄位。

V1 不在此 scope 內。

---

## 10. Reconcile phases

對每台 host：

### Phase A — Validate desired

驗證：

- `pilot_annotations` 是 map；
- key contract；
- value contract；
- secret prohibition；
- count；
- serialized length。

任何錯誤：

```text
FAIL BEFORE LIVE MUTATION
```

### Phase B — Read live

執行：

```bash
ipa host-show <fqdn> --all --raw
```

取得：

- `userClass`
- `nshostlocation`

read task 即使 `--check` 也 MUST 執行：

```yaml
check_mode: false
changed_when: false
```

### Phase C — Parse / ownership gate

計算：

```text
C_managed = current pilot.annotation.* entries
C_foreign = all other userClass values
D_managed = serialized desired annotations
```

驗證：

- malformed managed;
- duplicate managed key;
- location ownership/drift。

任何 conflict MUST 在 mutation 前 fail。

### Phase D — Plan

```text
delete = C_managed - D_managed
add    = D_managed - C_managed
```

但 key/value comparison 要能處理 case-only replace。

輸出可讀 plan：

```text
Host annotations plan for gpu-a01.ipa.pilot.internal
  delete:
    pilot.annotation.project=alpha
  add:
    pilot.annotation.project=beta
  preserve foreign userClass:
    provisioning-linux
  native location:
    NOOP
```

不得在一般 stdout 印出 secret；annotations 本來禁止 secret，但 log 仍應避免額外 dump 全部 inventory vars。

### Phase E — Apply

順序：

1. delete stale Pilot-owned `userClass`;
2. add missing desired Pilot-owned `userClass`;
3. apply safe `nshostlocation` mutation;
4. re-read live state;
5. verify。

### Phase F — Verify

MUST re-run：

```bash
ipa host-show <fqdn> --all --raw
```

assert：

```text
live pilot.annotation.* == desired serialized set
```

並 assert：

```text
all originally observed foreign userClass values still exist
```

如果 desired location：

```text
nshostlocation == desired location
```

如果 location 已被 Pilot-owned remove：

```text
nshostlocation absent
```

除非 location drift gate earlier 已 fail。

---

## 11. Idempotency

完全 converged：

```text
delete = []
add = []
location action = NOOP
```

第二次 apply MUST：

```text
changed=0
failed=0
```

Annotations task 不得因為每次都跑 `host-mod` 而產生 changed。

只有實際 add/delete/set/clear 才 changed。

---

## 12. Check mode

`--check --diff` MUST：

- 執行 desired validation；
- 執行 `ipa host-show --all --raw` read；
- 計算 plan；
- 顯示 would-add / would-delete / native-location action；
- 不執行任何 `host-mod`；
- 不改 `hosts.yml`；
- 不改 FreeIPA；
- 不建立 host object。

對尚未 enrollment 的 host：

```text
HOST_ABSENT
```

可報 blocked/check-plan，而不是假裝 apply 後會成功。

---

## 13. TUI — `pilot edit`

### 13.1 Host menu

現有：

```text
角色(roles)：...
其他變數(共 N 個)
```

新增獨立項：

```text
註解 / 資產資訊(共 N 個)
```

ID 建議：

```text
hosts.item.annotations
```

不得併入：

```text
hosts.item.extra_vars
```

### 13.2 CRUD

新增：

```go
pushAnnotationsMenu(...)
pushAnnotationAdd(...)
pushAnnotationEdit(...)
pushAnnotationDeleteConfirm(...)
```

可重用 Extra CRUD 的 UI helper，但 domain state 必須指向：

```go
Host.Annotations
```

### 13.3 UX copy

Annotations menu SHOULD 顯示：

```text
這些欄位只供人員 / Portal / FreeIPA 查閱，不影響部署角色或權限。
禁止存放 password、token、key 等秘密資料。
```

### 13.4 Validation

TUI 在 save 前 MUST 與 `inventory.Lint` 使用同一 validation function。

不可 TUI 有一套 regex、lint 再有另一套。

建議抽出：

```go
func ValidateAnnotations(map[string]string) []AnnotationIssue
func ValidateAnnotation(key, value string) error
func SerializeAnnotation(key, value string) (string, error)
```

---

## 14. Structured edit automation

現有 automation 已有：

```text
add_extra_var
edit_extra_var
delete_extra_var
```

新增：

```text
add_annotation
edit_annotation
delete_annotation
```

### 14.1 Action examples

```yaml
version: 1
steps:
  - action: add_annotation
    host: gpu-a01
    key: project
    value: llm-training
```

```yaml
version: 1
steps:
  - action: edit_annotation
    host: gpu-a01
    key: project
    value: llm-inference
```

```yaml
version: 1
steps:
  - action: delete_annotation
    host: gpu-a01
    key: project
```

### 14.2 No `value_env`

Annotations MUST NOT 支援：

```text
value_env
```

因為 annotations 不是 secret/config injection channel。

所有 values 必須直接明文存在 source YAML。

### 14.3 Determinism

Automation driver 與人工 TUI 必須呼叫相同 domain mutation helper。

不得：

```text
TUI -> one code path
structured action -> direct map mutation
```

形成 semantics drift。

---

## 15. `hosts.example.yml`

新增範例：

```yaml
  web-1:
    ansible_host: "<FILL-ME>"
    roles: [freeipa-client, freeipa-dns-client, linux-servers]
    env: prod
    annotations:
      location: "DC1/Rack-A03/U18"
      project: "example-project"
      owner: "platform-team"
```

旁邊 comment MUST 說明：

```text
annotations 只供人/Portal/FreeIPA 查閱，不控制 Ansible 行為；
禁止存秘密。freeipa-client apply 成功後會將它們投影到 host userClass。
```

---

## 16. FreeIPA `userClass` 與 policy 的安全界線

FreeIPA 設計允許 automember 使用 `userClass`。

因此 Pilot MUST：

- 不建立 matching `pilot.annotation.*` 的 automember rule；
- 不根據 annotation 自動加入 hostgroup；
- 不把 annotation 當 HBAC/sudo selector；
- 不把 project/location 自動轉成 access group；
- 不使用 annotation 決定 namespace delegation。

如果部署現場管理員自己建立：

```text
userClass ~= pilot.annotation.project=...
```

的 automember / custom policy，這屬 deployment-specific 外部行為，不屬 Pilot annotation contract。

Runbook MUST 明確記錄此 caveat。

---

## 17. FreeIPA namespace 相容性

FreeIPA 新版設計可能用 host `userClass` 作 namespace。

Pilot MUST：

- preserve non-Pilot `userClass`；
- 不假設 host 只有 Pilot values；
- 不清空整個 attribute；
- 不把 foreign `XYZ` / namespace value 當 annotation；
- prefix matching 必須限定 `pilot.annotation.`。

例如：

```text
XYZ
pilot.annotation.project=alpha
```

reconcile 後 foreign `XYZ` MUST 仍存在。

---

## 18. 錯誤模型

建議 error codes / reason strings：

```text
ANNOTATION_INVALID_TYPE
ANNOTATION_INVALID_KEY
ANNOTATION_EMPTY_VALUE
ANNOTATION_SECRET_KEY
ANNOTATION_VALUE_TOO_LONG
ANNOTATION_TOO_MANY
HOST_ABSENT
CONFLICT_DUPLICATE_MANAGED_KEY
CONFLICT_MALFORMED_MANAGED_VALUE
CONFLICT_FOREIGN_LOCATION
CONFLICT_LOCATION_DRIFT
FREEIPA_READ_FAILED
FREEIPA_MUTATION_FAILED
FREEIPA_VERIFY_FAILED
```

至少錯誤訊息 MUST 帶：

```text
inventory host name
FreeIPA FQDN (若已解析)
annotation key (若適用)
reason
```

不得帶 vault password / Kerberos credential。

---

## 19. 不可接受的實作

Coding agent MUST NOT：

1. 直接讓未知 top-level host key 代表 annotations。
2. 把 annotations 放進 `Host.Extra`。
3. generated inventory 直接輸出 `project:` / `location:`。
4. 用 JSON blob 覆寫 FreeIPA `description`。
5. 為此功能擴充 LDAP schema。
6. 用 `ipa host-mod --setattr=userclass=...` 覆寫整個 `userClass`。
7. 刪除 foreign `userClass`。
8. host 不存在時自動 `ipa host-add`。
9. 由 `ansible_host` IP 猜 FreeIPA FQDN。
10. 由 `inventory_hostname` 無條件猜 FreeIPA FQDN。
11. 在 client 尚未 enrollment 前 mutation metadata。
12. 讓 annotations 能存 `value_env` / vault reference。
13. 讓 annotations 影響 roles / access / deploy targeting。
14. 在 check mode 執行 `host-mod`。
15. location 有 foreign value 時直接 takeover。
16. 用 shell string 插值執行 FreeIPA command。
17. 吞掉 malformed / duplicate Pilot values 並自動「修好」。
18. 將 `pilot.annotation.*` foreign-looking case variant 當作 unmanaged；prefix ownership 必須 case-insensitive。

---

## 20. 預期檔案修改

至少：

```text
internal/inventory/inventory.go
internal/inventory/render.go
internal/inventory/inventory_test.go
internal/inventory/render_test.go

cmd/pilot/cmd/edit_tui.go
cmd/pilot/cmd/edit_tui_flows_test.go
cmd/pilot/cmd/edit_automation*.go
cmd/pilot/cmd/edit_automation*_test.go

hosts.example.yml

playbooks/apply/freeipa-client-apply.yml
playbooks/apply/tasks/freeipa-host-annotations.yml   # 建議
internal/spec/freeipa_client_regression_test.go

docs/verification/freeipa-client.md
docs/runbooks/freeipa-identity.md 或 docs/runbooks/freeipa-client.md
```

若目前測試分檔模式比較適合，可新增：

```text
internal/inventory/annotations.go
internal/inventory/annotations_test.go

cmd/pilot/cmd/edit_tui_annotations.go
cmd/pilot/cmd/edit_automation_driver_annotations.go
```

SHOULD 優先分檔，避免讓既有大型 TUI / inventory 檔案繼續膨脹。

---

## 21. 建議 domain helper

### 21.1 Inventory side

```go
const (
    AnnotationUserClassPrefix = "pilot.annotation."
    MaxAnnotationsPerHost     = 32
    MaxUserClassValueBytes     = 256
)

func ValidateAnnotationKey(key string) error
func ValidateAnnotationValue(value string) error
func ValidateAnnotations(values map[string]string) error
func SerializeAnnotation(key, value string) (string, error)
```

`SerializeAnnotation` 必須做最後長度驗證。

### 21.2 Live parsing model

若使用 Go 做 plan/parser，可定義：

```go
type FreeIPAHostAnnotationState struct {
    Managed  map[string]string
    Foreign  []string
    Location string
}

type AnnotationPlan struct {
    FQDN           string
    Add            []string
    Delete         []string
    Preserve       []string
    LocationAction string
    LocationFrom   string
    LocationTo     string
}
```

若 V1 全在 Ansible task/Jinja 完成，也應維持同一 conceptual model，並以 regression tests 鎖住。

### 21.3 優先建議

**Go 負責 pure validation / serialization；Ansible 負責 live FreeIPA read/mutate。**

這與 Pilot 現有：

```text
Go computes/decides
Ansible mutates
```

方向一致。

但 V1 不應為了 purity 額外建立新的常駐服務。

---

## 22. FreeIPA task pseudo flow

```yaml
- validate pilot_annotations

- ipa host-show <fqdn> --all --raw
  changed_when: false
  check_mode: false

- parse:
    current_pilot_userclass
    foreign_userclass
    current_nshostlocation

- fail if:
    malformed pilot entry
    duplicate pilot key
    location foreign takeover
    location drift

- calculate:
    userclass_delete
    userclass_add
    native_location_action

- debug plan

- when not ansible_check_mode:
    delete stale managed values one by one

- when not ansible_check_mode:
    add desired managed values one by one

- when not ansible_check_mode:
    apply native location action if required

- when not ansible_check_mode:
    re-read host-show --all --raw

- assert:
    pilot managed set == desired
    pre-existing foreign values preserved
    native location correct
```

All `ipa` commands MUST use：

```yaml
ansible.builtin.command:
  argv:
    - ipa
    - host-mod
    - "{{ ipa_client_fqdn }}"
    - "--addattr=userclass={{ item }}"
```

不得：

```yaml
shell: ipa host-mod {{ fqdn }} ...
```

---

## 23. Unit tests

### 23.1 Parser

MUST test：

- no annotations；
- one annotation；
- multiple annotations；
- Unicode value；
- value with `=`；
- non-string int reject；
- bool reject；
- list reject；
- map reject；
- annotations not copied into Extra；
- existing Extra unchanged。

### 23.2 Validation

MUST test：

- lowercase key accepted；
- dotted/dash/underscore accepted；
- uppercase reject；
- space reject；
- empty key reject；
- empty value reject；
- leading/trailing whitespace reject；
- newline reject；
- secret key reject；
- serialized exactly 256 bytes accepted；
- 257 bytes rejected；
- 32 entries accepted；
- 33 entries rejected。

### 23.3 Render

MUST test：

- sorted annotations；
- deterministic output；
- Parse -> Render -> Parse preserves annotations；
- old hosts file without annotations renders same semantics；
- Extra + annotations coexist。

### 23.4 Generate

MUST test：

```text
hosts.yml annotations
    ->
inventory.yml pilot_annotations
```

並 assert：

```text
location/project never appear as top-level host vars
```

---

## 24. TUI / automation tests

MUST test：

- host menu count；
- add annotation；
- edit value；
- delete annotation；
- duplicate add error；
- invalid key error；
- secret key error；
- save + reload round-trip；
- `add_annotation` structured action；
- `edit_annotation`；
- `delete_annotation`；
- annotation action 不改 `Extra`；
- extra-var action 不改 `Annotations`。

---

## 25. Static / regression tests for FreeIPA playbook

`internal/spec/freeipa_client_regression_test.go` 或新 regression file MUST 至少鎖定：

1. annotation task include 在 successful enrollment path 後。
2. read 使用 `ipa host-show --all --raw`。
3. mutation 只有 `addattr=userclass` / `delattr=userclass` scoped operations。
4. 不存在 full `--setattr=userclass=...`。
5. foreign preservation logic 存在。
6. duplicate/malformed managed state gate 在 mutation 前。
7. check mode 不 mutation。
8. post-mutation re-read + verify。
9. native location 有 ownership gate。
10. 不存在 `ipa host-add` annotation fallback。
11. command 使用 argv。
12. annotations 不被寫入 FreeIPA `description`。

---

## 26. Real FreeIPA verification — mandatory

依 Pilot infrastructure feature 慣例，本功能 MUST 在 disposable VM 做真實 FreeIPA 測試。

至少：

```text
1 x FreeIPA server (EL9)
1 x client (Ubuntu 24.04)
```

### L1 — initial apply

Source：

```yaml
annotations:
  location: "DC1/Rack-A03/U18"
  project: "alpha"
  owner: "platform"
```

驗證：

```bash
ipa host-show <client-fqdn> --all --raw
```

必須看到：

```text
userclass: pilot.annotation.location=DC1/Rack-A03/U18
userclass: pilot.annotation.project=alpha
userclass: pilot.annotation.owner=platform
nshostlocation: DC1/Rack-A03/U18
```

### L2 — idempotent rerun

同一 config 重跑：

```text
changed=0
failed=0
```

annotation tasks 不可 reported changed。

### L3 — update

Source：

```yaml
project: beta
```

驗證：

```text
pilot.annotation.project=alpha absent
pilot.annotation.project=beta present
```

### L4 — delete

刪掉：

```yaml
owner:
```

驗證：

```text
pilot.annotation.owner=platform absent
```

### L5 — foreign userClass preservation

人工先加：

```bash
ipa host-mod <fqdn> --addattr=userclass=external-provisioning
```

再跑 Pilot。

驗證：

```text
external-provisioning still present
```

### L6 — foreign native location conflict

先移除 Pilot location marker並人工設：

```text
nshostlocation = Manual/DC2
```

source desired：

```text
location = DC1/Rack-A03/U18
```

Pilot MUST：

```text
fail before mutation
```

且：

```text
Manual/DC2 unchanged
```

### L7 — location drift

先讓 Pilot 管 location `X`，再人工把 native 改成 `Y`，但保留 Pilot marker `X`。

rerun MUST：

```text
CONFLICT_LOCATION_DRIFT
```

且不得 overwrite `Y`。

### L8 — duplicate managed key

人工加入第二個：

```text
pilot.annotation.project=gamma
```

在已有 `project=beta` 時。

Pilot MUST fail before mutation。

### L9 — malformed managed value

人工建立可被 FreeIPA接受、但 Pilot parser 視為 malformed 的 `pilot.annotation.*` value。

Pilot MUST fail closed，不得自動刪。

### L10 — check mode

變更 source project：

```text
beta -> delta
```

執行：

```bash
ansible-playbook ... --check --diff
```

驗證 plan 顯示：

```text
delete beta
add delta
```

但 live FreeIPA 仍是 beta。

### L11 — host absent

對沒有 FreeIPA host object 的 target 執行 annotation path。

MUST：

```text
HOST_ABSENT
```

且：

```bash
ipa host-show <fqdn>
```

仍 not found。

### L12 — value with spaces / Unicode / equals

例如：

```yaml
annotations:
  note: "台北 DC owner=AI Platform"
```

必須成功 round-trip 且 rerun idempotent。

### L13 — case-only value replace（驗證 §7.7 假設）

先 apply：

```yaml
annotations:
  project: "Alpha"
```

確認 live：

```text
userclass: pilot.annotation.project=Alpha
```

再把 source 改成僅大小寫不同：

```yaml
annotations:
  project: "alpha"
```

rerun 並驗證：

1. 因 LDAP `userClass` equality 為 case-insensitive，reconcile MUST 走
   `DELETE pilot.annotation.project=Alpha` + `ADD
   pilot.annotation.project=alpha`，而非被 case-insensitive set 比對誤判
   為 NOOP。
2. rerun 後 `ipa host-show <fqdn> --all --raw` 只出現：

   ```text
   userclass: pilot.annotation.project=alpha
   ```

   不得同時保留 `Alpha` 與 `alpha` 兩筆。
3. 若 FreeIPA server 實際拒絕新增與既有值僅大小寫不同的 `userClass`
   （即先前 `DELETE` 尚未落地就 `ADD` 會撞 case-insensitive uniqueness
   衝突），MUST 記錄成 §7.7 的已知限制並改為 delete-then-verify-then-add
   的兩階段 apply，不得略過此驗證直接假設可行。

此 case 在 §7.7 僅為書面推論，未經真機驗證前不得視為既定行為；本 row
是 Phase 5 補齊前 §7.7 唯一沒有 live evidence 佐證的規則。

---

## 27. Verification spec

更新：

```text
docs/verification/freeipa-client.md
```

新增 annotation 相關 checklist rows。

實際 ID MUST 先檢查當時 `freeipa-client.md` 的最新 C-number，不得硬撞既有 ID。

建議 rows：

```text
host metadata managed userClass matches desired
foreign userClass preserved
nshostlocation matches desired location
annotation rerun idempotent
```

所有 row command 必須先 live actual-run 後才能標成正式 PASS evidence。

---

## 28. Evidence

新增：

```text
docs/evidence/freeipa-client/<YYYY-MM-DD>-host-annotations.md
```

記錄至少：

- Pilot commit SHA；
- FreeIPA server OS/version；
- client OS/version；
- topology；
- source annotations；
- first apply output；
- host-show raw evidence；
- idempotent rerun；
- update/delete；
- foreign preservation；
- location conflict；
- duplicate/malformed fail-closed；
- check mode zero mutation。

禁止在 evidence 放：

```text
ipa_admin_password
vault content
Kerberos credential
```

---

## 29. Migration / backward compatibility

### 29.1 Existing files

舊：

```yaml
hosts:
  web-1:
    ansible_host: "10.0.0.10"
    foo: "bar"
```

`foo` MUST 仍為 `Extra`。

本功能不得把舊 unknown keys 自動移到 `annotations`。

### 29.2 No heuristic migration

MUST NOT 自動把：

```text
location
project
owner
department
```

從 Extra 搬成 annotations。

因為既有 workspace 可能真的有 Ansible roles 使用這些變數。

### 29.3 Reserved `annotations`

從本版起：

```text
annotations
```

成為 reserved structured host field。

如果現有 workspace 有：

```yaml
annotations: "some scalar"
```

lint MUST 清楚報錯，要求手動改名或轉成 map。

### 29.4 FreeIPA pre-existing values

Pilot 第一次上線時：

- foreign `userClass` 全 preserve；
- matching well-formed `pilot.annotation.*` 視為現有 Pilot-managed state並正常 reconcile；
- malformed Pilot prefix fail closed；
- non-empty foreign `nshostlocation` 不自動 takeover。

---

## 30. Documentation

至少更新：

### `hosts.example.yml`

加入 annotations example。

### `DELIVERY.md`

在 simplified hosts source 說明：

```text
annotations = descriptive metadata
Extra = operational Ansible vars
```

### FreeIPA runbook

說明：

```text
userClass
pilot.annotation.*
location -> nshostlocation
foreign value preservation
eventual consistency V1
secret prohibition
```

### `pilot edit`

如有 user-facing docs，加入 annotations menu。

---

## 31. Acceptance Criteria

以下全部完成才算 feature done。

### AC1 — schema

`hosts.yml` 支援：

```yaml
annotations:
  key: "value"
```

並有 strict validation。

### AC2 — semantic separation

Annotations 不進 `Extra`，不成為 top-level Ansible vars。

### AC3 — generated inventory

只輸出：

```yaml
pilot_annotations:
```

### AC4 — deterministic round-trip

Parse/Render deterministic，key sorted。

### AC5 — TUI

`pilot edit` 有獨立 annotations CRUD。

### AC6 — structured actions

支援：

```text
add_annotation
edit_annotation
delete_annotation
```

### AC7 — FreeIPA projection

已 enrollment freeipa-client 能得到：

```text
pilot.annotation.<key>=<value>
```

### AC8 — foreign preservation

非 `pilot.annotation.*` 的 `userClass` 永不被 Pilot 刪除。

### AC9 — declarative prune

從 source 刪除 Pilot annotation 後，對應 Pilot userClass 被移除。

### AC10 — location

`annotations.location` 安全投影 `nshostlocation`，且不 implicit takeover foreign value。

### AC11 — no implicit host creation

Metadata feature 不 `host-add`。

### AC12 — check mode

可 plan、零 mutation。

### AC13 — idempotency

第二次 apply：

```text
changed=0 failed=0
```

### AC14 — secret safety

secret-like annotation key 在 lint/TUI/automation path 均被拒絕。

### AC15 — live evidence

Real FreeIPA L1-L13 至少完成，evidence 落版。

### AC16 — no regression

至少：

```bash
go test ./internal/inventory/...
go test ./cmd/pilot/cmd/...
go test ./internal/spec/...
go test ./...
```

依 repository 當下實際 testing convention 執行；不能只跑新 tests。

### AC17 — current inventory behavior preserved

Existing：

```text
roles
env
deployment_availability
Extra
inventory generate
pilot edit extra vars
```

全部相容。

---

## 32. Implementation phases

### Phase 1 — Local schema

完成：

- `Host.Annotations`
- parser
- validation
- serializer
- render
- generate
- unit tests
- `hosts.example.yml`

此 phase 不碰 FreeIPA。

### Phase 2 — TUI / structured actions

完成：

- annotations menu
- CRUD
- automation actions
- round-trip tests

### Phase 3 — FreeIPA read/plan

完成：

- shared annotation task
- runtime validation
- `host-show --all --raw`
- current parser
- conflict gates
- check-mode plan
- no mutation

### Phase 4 — FreeIPA mutation

完成：

- scoped add/delete
- native location
- post-write verify
- idempotency
- regression tests

### Phase 5 — live verification

完成 L1-L13。

只有此 phase 完成後：

```text
DRAFT implementation-ready
```

才能升為：

```text
VERIFIED / implemented
```

---

## 33. Future work / non-goals

V1 non-goals：

1. Offline host 的 immediate central metadata update。
2. Portal database。
3. FreeIPA -> hosts.yml reverse sync。
4. Arbitrary nested metadata。
5. List/object annotation values。
6. Annotation history/audit ledger。
7. CMDB integration。
8. Annotation-based HBAC/sudo。
9. Annotation-based deploy targeting。
10. FreeIPA custom LDAP schema。
11. Secret metadata。
12. Multiple source-of-truth。

Future Portal / `pilot-link` 可直接讀 FreeIPA：

```text
userClass: pilot.annotation.*
nshostlocation
```

並解析成 read-only host metadata。

若未來要求 host offline 時也能立即同步 metadata，應新增 explicit canonical FreeIPA identity field，並建立 controller-side reconciler；不得用 IP 或 inventory alias 猜測。

---

## 34. Coding agent completion checklist

Coding agent 完成前逐項確認：

```text
[ ] current HEAD 重新確認，沒有用過期 line number 硬 patch
[ ] Host.Annotations 與 Extra 分離
[ ] strict string-only parser
[ ] annotation validators 共用
[ ] userClass 256-byte serialized gate
[ ] secret-like key gate
[ ] generated inventory 使用 pilot_annotations
[ ] annotations 不污染 top-level Ansible vars
[ ] TUI annotations CRUD
[ ] structured annotation actions
[ ] no value_env for annotations
[ ] FreeIPA read before mutation
[ ] host absent fail closed
[ ] malformed/duplicate managed state fail closed
[ ] only pilot.annotation.* is owned
[ ] foreign userClass preserved
[ ] no full userClass replacement
[ ] location ownership gate
[ ] check mode zero mutation
[ ] post-write verification
[ ] second apply changed=0
[ ] unit / TUI / regression tests pass
[ ] disposable real FreeIPA L1-L13 complete
[ ] verification spec updated
[ ] evidence recorded without secrets
[ ] docs updated
```

---

## 35. 最終 desired state example

### `hosts.yml`

```yaml
hosts:
  gpu-a01:
    ansible_host: "10.20.30.41"
    roles:
      - freeipa-client
      - linux-servers
      - host-monitoring
    env: prod

    annotations:
      location: "DC1/Rack-A03/U18"
      project: "llm-training"
      owner: "ai-platform"
      asset_tag: "IT-2026-00128"
```

### Generated `inventory.yml`

```yaml
all:
  hosts:
    gpu-a01:
      ansible_host: "10.20.30.41"
      pilot_annotations:
        asset_tag: "IT-2026-00128"
        location: "DC1/Rack-A03/U18"
        owner: "ai-platform"
        project: "llm-training"
```

### FreeIPA

```text
$ ipa host-show gpu-a01.ipa.pilot.internal --all --raw

fqdn: gpu-a01.ipa.pilot.internal
nshostlocation: DC1/Rack-A03/U18
userclass: pilot.annotation.asset_tag=IT-2026-00128
userclass: pilot.annotation.location=DC1/Rack-A03/U18
userclass: pilot.annotation.owner=ai-platform
userclass: pilot.annotation.project=llm-training
```

如果原本另有：

```text
userclass: XYZ
userclass: external-provisioning
```

apply 後仍 MUST 存在。

---

## 36. 設計摘要

V1 的正式 contract：

```text
hosts.yml
  annotations: map[string]string
          |
          v
Host.Annotations
          |
          +--> inventory.yml / pilot_annotations
          |
          +--> freeipa-client post-enrollment reconcile
                    |
                    +--> userClass: pilot.annotation.<key>=<value>
                    |
                    +--> nshostlocation for annotation "location"
```

最重要 invariants：

```text
annotations != Ansible Extra
hosts.yml = source of truth
FreeIPA = projection
Pilot only owns pilot.annotation.*
foreign userClass is immutable to Pilot
location takeover is fail-closed
no secrets
no access/deployment semantics
no schema extension
no host auto-creation
idempotent + verify-after-write
```

