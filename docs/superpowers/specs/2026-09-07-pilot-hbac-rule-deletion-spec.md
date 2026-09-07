# Pilot HBAC Rule 刪除功能實作規格

**文件狀態：** `IMPLEMENTATION_READY`（Phase 1-3 全數完成，含 Case C 真實重現驗證，見 v1.6 變更記錄）
**規格版本：** v1.6
**日期：** 2026-09-07
**目標 Repository：** `kjelly/pilot`
**事實快照基準：** `main@01e85ee48e6e9c2cca882783b276299c461832f5`
**主要語言：** Go、Ansible
**目標讀者：** Coding agent / maintainer

- **目的**: 為 Pilot 的靜態 `hbac.rules[]` 補齊 declarative deletion lifecycle
- **優先級**: High

> v1.1 變更：補上 check-mode 處理、`ipa hbacrule-show` not-found 與真實錯誤的判斷邏輯、
> 明確要求複用既有 grant-HBAC prune task 的實作 pattern、MCP 併發安全要求、
> 以及 tag coverage lint 的相容性要求。原始內容(v1.0)已對照 `main@01e85ee4` 逐項核實無誤診。
>
> v1.2 變更：Phase 1 實作階段對照 `freeipa-identity-apply.yml` 現有程式碼後，發現 v1.1 §6.2/§6.4
> 假設的「獨立 pre-delete lookup + post-delete verify」設計並非本檔案對這類物件刪除的實際慣例；
> 已改為與既有 `netgroup-del`／`Prune v3.0 grant HBAC rules` 一致的單一 task 設計（§6.2 記錄了改版理由），
> §6.3 的 check-mode 假設也一併修正為「純 skip 即安全，只補可觀測性 debug 訊息」。
>
> v1.3 變更：Phase 1（Ansible 刪除邏輯 + Go validator `allow_all` 防護 + 單元測試）完成真實
> vm-target 驗證，證據見 `docs/verification/freeipa-identity.md` §7.5（候選 checklist row C30 見
> 該檔 §9.4）：Case A（roster absent + live 存在 → 真的刪除，事後 `ipa hbacrule-show` 確認
> `HBAC rule not found`）、Case B（roster absent + live 已不存在 → 冪等 no-op，`changed=0`）、
> Case D（`--check` → 不執行、印出 preview 訊息、live 狀態不變）、`allow_all` 保護（繞過 Go
> validator 直接對 hand-edited roster 跑 Ansible，gate 於任何 delete task 前就 fail closed）皆
> PASS。Case C（FreeIPA 因被引用而拒絕刪除）查證後認為 FreeIPA 對一般 HBAC login rule 沒有內建
> referential-integrity 阻擋，找不到可重現的真實觸發條件，未執行——`failed_when` 的 not-found
> 判斷邏輯已由 Case A 的真實 stderr 佐證。過程中順手修好兩個與本功能無關的既有 pilot 缺陷：
> `vm-target run --sandbox` 對 `-e @~/...` 形式的 vault 檔案路徑未展開 `~`
> （`cmd/pilot/cmd/vm_target.go` 新增 `expandHomeDir`，`TestExpandHomeDir` 鎖回歸）、
> `freeipa-identity-canonical.roster.yaml` 的 fixture host 硬編碼 IP 撞上新建 vm-target 的 DHCP
> 分配。`go test ./...`、`go vet`、`make playbook-lint` 全綠。
>
> v1.4 變更：Phase 2（TUI Delete/Restore、absent 顯示、`delete_hbac_rule`/`restore_hbac_rule`
> structured actions）完成實作。`edit_tui_roster_access.go`：detail 畫面新增條件式 lifecycle
> 選項（present rule 顯示「Delete login rule」，`allow_all` 例外不提供；absent rule 顯示
> 「Restore login rule」），Delete 走新的 `pushRosterHBACDeleteConfirm` 確認畫面（§9.2 的 impact
> summary），Confirm/Cancel 都只可能改動 `state` 欄位，其餘 subjects/targets/services 不變；
> list 畫面（`pushRosterHBACMenu`）為 absent rule 加 `[absent]` 後綴（§9.3）。
> `edit_automation_driver_roster_access.go` 新增 `deleteHBACRule`/`restoreHBACRule`；兩者透過
> `editActionRegistry()`（`edit_actions_registry.go`）註冊為 `delete_hbac_rule`/`restore_hbac_rule`
> structured actions —— 這是 spec/scenario 驗證/driver 執行三者的唯一真相來源，新增後自動被
> 既有 generic `pilot edit plan`/`apply` MCP tool（已走 `addRecoveredTool`，見 §11.1）曝光，
> 不需要另外註冊 MCP tool；MCP `inspect` 的 `inspectHBACRule.State` 欄位本來就沒有過濾 absent
> rule，§11 的「不得隱藏 absent rule」要求已自動滿足，未改動。`allow_all` 保護對 TUI 與
> structured action 走同一份程式碼路徑（detail 畫面本來就不建這個選項），故意不做第二層
> 獨立檢查，兩個介面永遠不會分岔。新增/更新 16 個 Go 測試（TUI 層 5 個、driver/結構化
> action 層 2 個，另外同步更新 `actions_test.go` 兩個 catalog-stability golden 測試的 action
> 計數 102→104）。`go build`、`go vet`、`CI=1 go test ./...`（含 race）全綠。Phase 2 純
> Go/TUI 變更，未動 Ansible/FreeIPA 行為，因此不需要額外的 vm-target 實跑證據——真實
> `ipa hbacrule-del` 行為仍由 Phase 1 的 vm-target 證據涵蓋。
>
> v1.5 變更：Phase 3（drift 偵測 + access explain 訊息整合）完成。
> `internal/accessgrants/drift.go`：`ComputeDrift` 新增 `desiredAbsentStaticHBAC []string`
> 參數與 `hbac_should_be_absent` drift category（§14）——roster 明確宣告 `state: absent`
> 的靜態 HBAC rule，若 probe 回報 live 仍存在就標記；只檢查呼叫端明確列出的名稱，
> 不會把「roster 從未管過」的其他 live rule 一併掃進來（§4.2 的 never-prune 原則）。
> `DriftOnce` 新增 `staticAbsentHBACRuleNames` 直接讀 roster 的 `hbac.rules[]`（`BuildPlan`/
> `CompileGrantsFile` 只編譯 grant 衍生規則，從不知道這些手寫靜態規則的存在），把名稱併入
> 既有的 `pilot_drift_hbac_names` probe 清單——沿用同一支 `freeipa-access-drift-probe.yml`，
> 沒有新增 playbook 或新的 probe 邏輯。7 個新測試（3 個 `ComputeDrift` 純函式層級對應
> §16.6 的三個案例、2 個 `DriftOnce` 端對端含 fake runner、加上既有 14 個呼叫點機械式補
> 新參數）。`pilot access explain`（`internal/inventory/explain.go`）本來就在
> `ExplainStaticHBAC` 過濾掉 `state: absent` 的規則——刪除一條規則後它會自動從「目前授予
> 存取」的來源清單消失，其他規則的說明不受影響，§13/驗收準則 #12 的核心語意（不誤報單一
> 規則授予了絕對存取、其他規則仍要能正確列出）在讀碼確認後屬於既有行為，本輪未新增獨立的
> 「before/after 差異」工具——§17 原文的 before/after 是這個 phase 唯一沒有具體規格細節的
> 一句話（§13 只寫了下方那句完成訊息文字，沒有再定義 diff 輸出格式），刻意不做未經明確
> 規格的臆測性功能。TUI 側（`edit_tui_roster_access.go`）：`pushRosterHBACEdit` 新增
> `banner string` 參數（原本寫死 `"✅ 已更新"`），刪除確認成功後改顯示 §13 建議的完成訊息
> （提示其他規則可能仍授予相同存取，引導跑 `pilot access explain`），Restore 顯示
> 「✅ 已還原登入規則」；其餘 5 個既有欄位編輯呼叫點維持原本的 `"✅ 已更新"`。新增 1 個
> TUI 斷言（刪除完成訊息含 `pilot access explain`）。`go build`、`go vet`、
> `CI=1 go test ./...`（含 `internal/accessgrants`、`cmd/pilot/cmd` 兩個套件的 `-race`）全綠。
>
> v1.6 變更：對真實 FreeIPA vm-target（新建拋棄式 `hbac-delete-verify`，AlmaLinux 9，
> 與 v1.3/文件頂端記錄的那次是不同 VM）完整重跑一次 Phase 1 的 Case A/B/D/`allow_all`，
> 數字與 v1.3 記錄完全一致（無回歸）。**更正 v1.3 對 Case C 的誤診**：v1.3 記錄「FreeIPA
> 對一般 HBAC login rule 沒有內建的 referential-integrity 阻擋，找不到可重現的真實
> 觸發條件」——這個結論是錯的。真實建構方式：`ipa selinuxusermap-add
> --hbacrule=<rule> --selinuxuser=<ctx> <name>` 建立一個引用該 HBAC rule 的
> SELinux User Map 後，`ipa hbacrule-del <rule>` 會真的失敗：`rc=1`，
> `stderr="ipa: ERROR: <rule> cannot be deleted because SELinux User Map <name>
> requires it"`。透過 roster `state: absent` 觸發完整的 `freeipa-identity-apply.yml`
> apply（未改動任何程式碼）：`PLAY RECAP ok=77 changed=0 failed=1`，失敗於
> 「Delete static HBAC rules explicitly marked absent」，`failed_when_result: true`
> （stderr 不含 "not found"，正確歸類為真實錯誤），play fail closed，事後確認 rule
> 仍存在、無其他物件被動到——§4.3/§15.2/§15.3 的要求**零程式碼改動**即滿足。
> §16.5 Case C、§18 驗收準則 #4 已同步更新；`docs/verification/freeipa-identity.md`
> 同步更新至 v1.11。教訓：「沒找到重現方式」不等於「不可重現」，尤其涉及 FreeIPA 這種
> 有大量物件間隱性依賴的系統，下次類似的「查證後認為不可重現」結論應該更保守地標記
> 為「本次未找到，不代表窮盡」而非直接下「不會發生」的結論。

## 1. Executive Summary

Pilot 應導入 HBAC rule 的刪除功能，但刪除語義不得是直接從 roster 移除 YAML entry。

本規格要求採用：

```text
Delete HBAC rule
    =
set hbac.rules[].state = absent
```

並由 FreeIPA reconciler 在 apply/deploy 時執行：

```text
ipa hbacrule-del <rule-name>
```

最後驗證 rule 已不存在，並刷新 SSSD cache。

此設計與 Pilot 既有 `delete_grant` / declarative lifecycle 一致。

---

## 2. 問題背景

目前 Pilot 已經允許 static HBAC rule 宣告：

```yaml
hbac:
  rules:
    - name: production-ssh
      state: absent
```

Go validator 也接受：

```text
state: present
state: absent
```

但是目前 `freeipa-identity-apply.yml` 在 normalize static HBAC rule 時，只處理：

```yaml
when:
  - item.state | default('present') == 'present'
```

也就是 `state: absent` 的 static HBAC rule 會被忽略，而不是被刪除。

目前真正執行：

```text
ipa hbacrule-del
```

的邏輯，只存在於 v3 grant compile / prune 流程。

因此目前存在以下不一致：

```text
Roster intent:
state: absent

FreeIPA live state:
rule 仍然存在
```

這是一個 authorization safety gap，因為使用者可能認為權限已撤銷，但實際 FreeIPA HBAC rule 仍有效。

---

## 3. Current State

| Layer | Current behavior | Status |
|---|---|---|
| Roster schema | `hbac.rules[].state` 接受 `present / absent` | 已具備 |
| Go validator | static HBAC `state: absent` 合法 | 已具備 |
| Static HBAC reconciler | 只 normalize `state: present` | 缺失 |
| Grant HBAC reconciler | 已支援 `Present=false -> hbacrule-del` | 可參考 |
| TUI | HBAC 可新增、修改，無刪除 | 缺失 |
| Structured Actions | 無 `delete_hbac_rule` | 缺失 |
| Drift | compiled grant HBAC 有 orphan detection | 部分具備 |
| SSSD refresh | identity apply 後已有 `sss_cache -E` | 已具備 |

---

## 4. Design Principles

### 4.1 Delete MUST mean declarative absent

不得將 HBAC rule 從 roster 直接移除作為正式 deprovision 流程。

正確做法：

```yaml
hbac:
  rules:
    - name: production-ssh
      state: absent
      subjects:
        users: []
        groups: [team-sre]
      targets:
        hosts: []
        hostgroups: [production]
      services: [sshd]
```

這保留：

- lifecycle intent
- audit history
- restore capability
- drift detection context
- Pilot managed ownership information

---

### 4.2 Never prune unknown FreeIPA HBAC rules

禁止實作：

```text
live HBAC rules - roster HBAC rules = delete all
```

因為 Pilot 無法證明 FreeIPA 裡面的其他 HBAC rule 是否由：

- administrator 手動建立
- 其他 automation 建立
- 其他系統管理
- FreeIPA built-in 提供

Pilot 只能刪除 roster 明確宣告：

```yaml
state: absent
```

的 static HBAC rule。

---

### 4.3 Fail closed

刪除失敗不得被忽略。

禁止：

```yaml
failed_when: false
```

HBAC rule 可能仍被其他 FreeIPA object reference，例如 SELinux user mapping。

若 FreeIPA 拒絕刪除，Pilot 應停止並回報原因。

---

## 5. Required Architecture

目標 lifecycle：

```text
Roster
  |
  | state: absent
  v
Normalize absent HBAC rules
  |
  v
Pre-delete live check
  |
  +-- not found --> no-op
  |
  +-- exists
         |
         v
ipa hbacrule-del
         |
         v
Verify absence
         |
         v
Refresh SSSD cache
         |
         v
Drift = clean
```

---

## 6. Ansible Reconciler Changes

Primary file:

```text
playbooks/apply/freeipa-identity-apply.yml
```

### 6.1 Add absent HBAC collection

新增 fact：

```yaml
ipa_hbac_rules_absent: []
```

現有 `ipa_hbac_rules` 保持只包含 present rules。

Normalize 分流：

```text
hbac.rules[state=present]
        -> ipa_hbac_rules

hbac.rules[state=absent]
        -> ipa_hbac_rules_absent
```

---

### 6.2 Delete static HBAC rules — single-task idiom（不需要獨立的 pre-delete lookup / verify）

> **v1.2 修訂**：實作階段核對 `freeipa-identity-apply.yml` 現有程式碼後發現，
> 「pre-delete lookup → delete → post-delete verify」三步驟設計並非本檔案對這一類物件的實際慣例。
> 本檔案已有兩個直接可比的既有先例，兩者都只用**單一 command task**、
> 靠 `failed_when` 對 stderr 做字串比對來同時處理 idempotent-delete 與 fail-closed，
> 不需要額外的 show-before/show-after：
>
> ```text
> "Delete netgroups explicitly marked absent"（freeipa-identity-apply.yml，Netgroups 區塊）
> "Prune v3.0 grant HBAC rules whose grant is now absent (spec.md §9)"（同檔，line ~1972）
> ```
>
> 兩者結構完全一致：
>
> ```text
> ansible.builtin.command:
>   argv: [ipa, <verb>-del, "{{ item }}"]
> register: <result>
> changed_when: "'Deleted ...' in (<result>.stdout | default(''))"
> failed_when:
>   - <result>.rc != 0
>   - "'not found' not in (<result>.stderr | default(''))"
> ```
>
> 這已經同時滿足原本 §6.2（pre-delete lookup）與 §6.4（verify absence）想達成的語義：
> `rc == 0`（成功刪除）或 stderr 含 `not found`（本來就不存在）都視為「這個名字現在不存在」= 成功；
> 其他非零 rc 一律 fail closed。額外加一次 `hbacrule-show` 查詢只是重複同一個 API 呼叫，
> 不會讓判斷更正確，只會多一次網路往返。**因此本規格改為採用單一 task 設計**，
> 與 netgroup／grant-HBAC 兩個既有 delete 路徑保持一致，方便三者未來合併重構。

要求：

- idempotent
- 不得刪除非 roster 明確 `state: absent` 的 rule
- deletion failure 必須 fail closed
- **實作者 MUST 複用**上述既有 task 的 module／`changed_when`／`failed_when` 寫法，loop 來源改成
  `ipa_hbac_rules_absent`（見 6.1），任務命名可比照
  `"Delete static HBAC rules explicitly marked absent"`

若日後 FreeIPA CLI 行為變化導致「not found」字串比對失準，才需要重新引入獨立的
pre-delete lookup；在此之前不要為了假設的健壯性多加一層查詢。

---

### 6.3 Check-mode 正確性

`ansible.builtin.command` 對 check-mode 沒有真正的 diff 支援 —— 在 `--check` 下，
delete task 會被 Ansible 直接跳過（不執行、不合成 rc），這正是 netgroup-del／grant-HBAC-prune
既有兩條 delete 路徑目前的行為，**是安全的預設值，不是坑**：不會真的刪除任何 FreeIPA 物件。

> 舊版本（v1.1）曾假設 command/shell 在 check-mode 下會「合成假 rc=0/stdout=''」而非單純 skip
> —— 那是 `dcgm-exporter`/`host-monitoring` 案例中**有 `when` 依賴上一個 registered 變數**時才會
> 出現的現象（被 skip 的 task 其 registered 變數確實預設帶出 `rc: 0`／空字串，若後續 task 沒有先
> 檢查「上一步是否真的執行」就直接讀取，才會誤判）。本功能的 delete task 本身沒有這種級聯依賴，
> 純粹被 skip 即安全終止，不需要 `check_mode: false`。

唯一要補的是可觀測性：check-mode 下這個刪除是完全靜默的，操作者看不到「原本會刪掉什麼」。
新增一個 `ansible.builtin.debug` task，`when: ansible_check_mode`，對 `ipa_hbac_rules_absent`
逐一印出：

```text
would delete HBAC rule <name> (check mode, not executed)
```

不需要、也不得讓這個 debug task 影響 `changed_when`/drift 判斷 —— 它純粹是人類可讀的提示。

---

### 6.4 `ipa hbacrule-del` not-found 與真實錯誤的判斷

延續 6.2 採用的單一 task 設計，`failed_when` 直接對 `hbacrule-del` 自己的 rc/stderr 做判斷，
不需要額外一次 `hbacrule-show` 查詢：

```text
rc == 0                                    -> deleted（stdout 含 "Deleted HBAC rule" 時視為 changed）
rc != 0 且 stderr 含 "not found"            -> 已經不存在（no-op，成功）
rc != 0 且 stderr 不含 "not found"          -> 其他錯誤（fail closed，例如仍被其他物件參照）
```

MUST 針對 stderr 內容做明確字串比對（例如 `'not found' not in (result.stderr | default(''))`），
不得用「非 0 就當作 not found」這種寬鬆判斷，否則會把權限不足、連線失敗、reference 未清空等真實
錯誤誤判成 no-op，違反 §4.3 fail closed 原則 —— 這與既有 netgroup-del／grant-HBAC-prune 的
`failed_when` 邏輯逐字一致。

---

### 6.5 Tag coverage 相容性

新增的 task（normalize 分流、allow_all gate、delete、check-mode debug）MUST 遵循既有 always-tag prerequisite 慣例：
若這些 task 產出的 fact（`ipa_hbac_rules_absent` 等）會被其後帶 tag 的 task 使用，
normalize task 本身要嘛帶 `always`,要嘛顯式帶上所有可能用到它的 tag，
避免 site-wide 帶 `--tags` 執行時，因為只剩 `always` task 而讓 absent 分流被跳過。
提交前 MUST 跑 `tag_coverage_test`（孤兒 tag / 漏 tag 雙向鎖），確認新 task 不破壞既有 ratchet。

---

## 7. `allow_all` Protection

FreeIPA built-in：

```text
allow_all
```

不得透過普通 HBAC deletion lifecycle 刪除。

以下 roster 必須被拒絕：

```yaml
hbac:
  rules:
    - name: allow_all
      state: absent
```

Pilot 已經有專門控制：

```yaml
hbac:
  disable_allow_all: true
```

因此：

```text
delete_hbac_rule allow_all
```

應回報：

```text
allow_all is a FreeIPA built-in safety rule.
Use hbac.disable_allow_all instead.
```

建議在 Go validator 與 sanctioned authoring surfaces 都加入此 protection。

---

## 8. Go Inventory / Validator Changes

Primary files：

```text
internal/inventory/roster_validate.go
internal/inventory/roster.go
```

### 8.1 Preserve existing state semantics

保持：

```text
present
absent
```

不得新增 schema version。

---

### 8.2 Reject deleting `allow_all`

建議 validator rule：

```text
if hbac rule name == "allow_all" && state == "absent"
    violation
```

---

### 8.3 Add helper for soft deletion

建議 API：

```go
func SimulateDeleteRosterHBACRule(path, name string) ([]RosterViolation, bool, error)
func DeleteRosterHBACRule(path, name string) error
```

實際語義不是 physical delete，而是：

```text
state = absent
```

命名如果怕誤導，可改成：

```go
MarkRosterHBACRuleAbsent
RestoreRosterHBACRule
```

但 sanctioned actions 對使用者仍可稱：

```text
delete_hbac_rule
```

---

## 9. TUI Changes

Primary file：

```text
cmd/pilot/cmd/edit_tui_roster_access.go
```

目前 HBAC detail 應新增 lifecycle actions。

### 9.1 Present rule

建議畫面：

```text
HBAC rule production-ssh

 subjects.groups       [team-sre]
 subjects.users        []
 targets.hostgroups    [production]
 targets.hosts         []
 services              [sshd]

 --------------------------------
 Delete login rule
 Back
```

---

### 9.2 Delete confirmation

確認畫面需顯示 impact summary：

```text
Delete HBAC rule?

production-ssh

Subjects:
  groups:
    - team-sre

Targets:
  hostgroups:
    - production

Services:
  - sshd

This removes the authorization granted by this rule.
Other HBAC rules may still grant equivalent access.

[Confirm delete]
[Cancel]
```

確認後只改：

```yaml
state: absent
```

不得直接從 YAML array 移除。

---

### 9.3 Display absent rules

HBAC list 應繼續顯示 absent rule：

```text
production-admin
production-ssh [absent]
```

這樣使用者可以理解 rule 的 lifecycle 狀態。

---

### 9.4 Restore

建議支援：

```text
Restore HBAC rule
```

效果：

```yaml
state: present
```

Restore 可以與 delete 同批實作，也可以列為 Phase 2。

---

## 10. Structured Actions

Primary files：

```text
cmd/pilot/cmd/edit_actions_registry.go
cmd/pilot/cmd/edit_automation_driver_roster_access.go
```

新增：

```yaml
action: delete_hbac_rule
name: production-ssh
```

語義：

```text
delete_hbac_rule
    -> locate hbac.rules[name]
    -> set state = absent
    -> validate candidate
    -> write roster
```

不得讓 agent 自己組合任意 `set state` 操作。

明確 action intent 對：

- Hufu
- MCP
- structured automation
- coding agents

都更安全。

---

### 10.1 Optional restore action

可新增：

```yaml
action: restore_hbac_rule
name: production-ssh
```

效果：

```text
state = present
```

---

## 11. MCP / Agent Surface

若 MCP edit tools 暴露 HBAC mutation，必須同步增加：

```text
delete_hbac_rule
restore_hbac_rule
```

Inspect output 應顯示：

```json
{
  "name": "production-ssh",
  "state": "absent"
}
```

不得將 absent rule 完全從 inspect graph 隱藏。

---

### 11.1 併發安全：MUST 使用 `addRecoveredTool`

Pilot MCP server 對每個 tool call 都是真併發跑 goroutine；任一 handler panic 過去曾導致整個 transport process 死掉
（已於既有 11 個 tool 上修復，統一改走 `addRecoveredTool` wrapper）。

`delete_hbac_rule` / `restore_hbac_rule` 若在此 Phase 暴露為 MCP tool，MUST 透過 `addRecoveredTool` 註冊，
禁止裸用 `mcp.AddTool` 直接掛新 handler，否則會重新引入已修復過的 process-level crash 風險。

---

## 12. SSSD Cache Refresh

Pilot 目前 identity apply 已有：

```text
sss_cache -E
```

因此 static HBAC deletion 成功後應沿用既有 refresh 流程。

不需要建立新的 cache invalidation architecture。

---

## 13. Access Explain Integration

刪除 HBAC rule 不代表某 user 一定失去 login permission。

例如：

```text
alice -> production01 / sshd

production-ssh   grants access
sre-global-ssh   also grants access
```

刪除 `production-ssh` 後：

```text
alice -> production01 / sshd

production-ssh   removed
sre-global-ssh   still grants access
```

因此 UI / CLI 不應顯示：

```text
user access revoked
```

除非 effective access resolver 已證明沒有其他 HBAC path。

建議在 deletion completion message 使用：

```text
HBAC rule marked absent.
Effective access may still be granted by other rules.
Use `pilot access explain` to inspect the final authorization path.
```

---

## 14. Drift Detection

目前 static HBAC full drift 尚未完整支援。

此次最低要求新增：

```text
desired:
  static HBAC state = absent

live:
  rule exists

=> drift category:
   hbac_should_be_absent
```

建議 DriftItem：

```text
Category: hbac_should_be_absent
Name: production-ssh
Detail: static roster HBAC rule is declared absent but still exists in FreeIPA
```

不要將所有 live static HBAC rule 都當成 orphan。

只有 roster 明確掌握 lifecycle 的 static rule 才能做 managed absence 判斷。

---

## 15. Error Handling

### 15.1 Rule not found

應視為成功 / no-op：

```text
state: absent
FreeIPA: not found
=> clean
```

---

### 15.2 Referenced rule cannot be deleted

如果 FreeIPA 回傳 dependency/reference error：

Pilot 必須：

- fail apply
- 保持 roster `state: absent`
- 不回退為 present
- 顯示 FreeIPA 原始錯誤的安全摘要
- 不繼續假裝 reconcile clean

例如：

```text
HBAC rule deletion blocked

rule:
  production-ssh

FreeIPA rejected deletion because the rule is still referenced.
No other HBAC rules were modified.
```

---

### 15.3 Partial failure

若一次 apply 有多條 HBAC deletion：

```text
rule-a deleted
rule-b failed
```

整個 play 必須 fail。

不得把 deployment 標示為成功。

---

## 16. Tests

### 16.1 Go validator

必測：

```text
state: present        PASS
state: absent         PASS
state: disabled       FAIL
allow_all + absent    FAIL
```

---

### 16.2 Inventory mutation

必測：

```text
delete_hbac_rule
-> state changes present -> absent
```

以及：

```text
already absent
-> idempotent
```

---

### 16.3 TUI

必測：

- present rule 有 Delete
- absent rule 顯示 `[absent]`
- delete confirmation 可 cancel
- confirm 後只改 state
- sibling fields 不得被改動
- `allow_all` 不得提供 Delete

---

### 16.4 Structured actions

必測：

```yaml
action: delete_hbac_rule
name: production-ssh
```

結果：

```yaml
state: absent
```

並驗證其他欄位完全保留。

---

### 16.5 Ansible integration

Case A：live rule exists

```text
roster state: absent
live: exists

expected:
hbacrule-del
verify not found
```

Case B：live rule already absent

```text
roster state: absent
live: not found

expected:
no mutation
success
```

Case C：FreeIPA blocks delete

```text
expected:
play fails
rule remains absent in roster
error surfaced
```

Case D：`--check`（check-mode）執行

```text
roster state: absent
live: exists
apply mode: --check

expected:
hbacrule-show 仍真的執行（不受 --check 影響）
hbacrule-del 不得真的執行
report: "would delete HBAC rule <name> (check mode, not executed)"
不得回報 drift = clean
```

---

### 16.6 Drift

必測：

```text
roster absent + live exists
=> hbac_should_be_absent
```

```text
roster absent + live missing
=> no drift
```

```text
unmanaged live rule
=> not automatically orphaned
```

---

## 17. Recommended Delivery Phases

### Phase 1 — Backend correctness（已完成，v1.6 起含 Case C 真實重現）

實作：

- static HBAC absent normalize（6.1）
- `hbacrule-del`（單一 task 設計 + 6.4 的 not-found vs. 其他錯誤判斷；複用既有 netgroup-del／grant-HBAC-prune pattern，見 6.2）
- check-mode 可觀測性（6.3）
- `allow_all` protection
- dependency error fail-closed ✅ v1.6：SELinux User Map 引用觸發的真實 FreeIPA 拒絕，對 vm-target 重現並確認 zero-code-change 即 fail closed
- tag coverage 相容性（6.5）
- tests（含 16.5 Case D check-mode）

Phase 1 是最重要部分，因為這直接修正 authorization lifecycle gap。

---

### Phase 2 — Authoring surfaces（已完成，v1.4）

實作：

- TUI Delete ✅
- absent display ✅
- Restore ✅
- `delete_hbac_rule` ✅
- `restore_hbac_rule` ✅
- MCP surface ✅（沒有新增 MCP tool——既有 generic `plan`/`apply` tool 已走 `addRecoveredTool`，
  透過 `editActionRegistry()` 自動曝光新 action，見文件頂端 v1.4 變更記錄）

---

### Phase 3 — Observability（已完成，v1.5）

實作：

- `hbac_should_be_absent` drift ✅
- improved access explain output ✅（`ExplainStaticHBAC` 本來就過濾 `state: absent`，
  刪除後自動不再列為授權來源，其他規則不受影響；讀碼確認，未改動程式）
- before/after effective authorization reporting ⬜ 刻意不做——spec.md 全文只在 §13 給了
  完成訊息文字，從未定義這個「diff 報告」的輸出格式/觸發點，屬於臆測性功能，見文件頂端
  v1.5 變更記錄

---

## 18. Acceptance Criteria

功能完成需同時滿足：

1. Static `hbac.rules[].state: absent` 會真正刪除 FreeIPA HBAC rule。✅ Phase 1（vm-target Case A）
2. Repeated apply 完全 idempotent。✅ Phase 1（vm-target Case B）
3. FreeIPA rule 已不存在時不報錯。✅ Phase 1（vm-target Case B）
4. FreeIPA 拒絕 deletion 時 apply 必須 fail。✅ Phase 1，Case C 已於 v1.6 對真實 vm-target
   重現並驗證通過（SELinux User Map 引用觸發真實拒絕，`failed_when` 零改動即正確
   fail closed，見文件頂端 v1.6 記錄）
5. 不會刪除 roster 未管理的 HBAC rule。✅ Phase 1（§4.2 設計原則，未實作 live-vs-roster 反向 prune）
6. 不可透過普通 delete lifecycle 刪除 `allow_all`。✅ Phase 1 Go validator + Ansible gate；Phase 2 TUI/
   structured action 也同路徑擋下（見 v1.4 記錄）
7. TUI delete 只會把 `state` 改成 `absent`。✅ Phase 2
8. Structured action 提供 `delete_hbac_rule`。✅ Phase 2（連同 `restore_hbac_rule`）
9. Absent rule 仍保留在 roster。✅ Phase 2
10. SSSD cache 在 reconcile 後被刷新。✅ Phase 1（沿用既有 `sss_cache -E`）
11. Drift 能辨識 `state: absent` 但 live rule 仍存在。✅ Phase 3（`hbac_should_be_absent`）
12. `pilot access explain` 仍能正確說明其他可能授權來源。✅ Phase 3（`ExplainStaticHBAC`
    既有行為即滿足；未新增 before/after diff 工具，見 §17 Phase 3 記錄）

---

## 19. Final Decision

Pilot 應導入 HBAC rule deletion。

但正確實作不是：

```text
remove YAML entry
```

而是：

```text
Roster state: absent
        ↓
Explicit managed deletion
        ↓
FreeIPA hbacrule-del
        ↓
Absence verification
        ↓
SSSD cache refresh
        ↓
Drift = clean
```

這能與 Pilot 既有 declarative configuration、grant lifecycle、drift model 與安全設計保持一致，同時避免誤刪 unmanaged FreeIPA authorization objects。


