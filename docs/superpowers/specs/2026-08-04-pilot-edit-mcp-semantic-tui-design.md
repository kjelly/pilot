# Pilot Edit MCP Semantic TUI Agent Design

## Status

* 狀態：Draft（實作中 — Phase 1）
* 文件路徑：`docs/superpowers/specs/2026-08-04-pilot-edit-mcp-semantic-tui-design.md`
* 目標元件：`pilot edit`
* 第一版傳輸：MCP stdio
* 主要使用者：Codex、OpenCode、Crush、Goose 及其他支援 MCP 的 coding agent

## Goal

新增 Pilot-owned MCP Server，讓外部 coding agent 可以：

1. 查詢 `pilot edit` 支援的 semantic actions。
2. 讀取目前 workspace 的非秘密設定摘要。
3. 產生版本化 semantic action scenario。
4. 要求 Pilot 預演該 scenario。
5. 在使用者批准 MCP 寫入工具後，由 Pilot 對真實 workspace 執行完全相同的 scenario。
6. 由 Pilot 自己透過既有 Bubble Tea router 與 `tea.KeyMsg` 操作真正的 `pilot edit` 畫面。
7. 保存 TUI 錄影、semantic trace、scenario、diff、validation 與結果摘要，供人工稽核與機器驗證。

本功能不得讓 Agent 直接寫入 `hosts.yml`、`group_vars`、role preset 或 vault 檔案，也不得讓 Agent 自行猜測終端機畫面並發送任意 raw keys。

## Product Boundary

Pilot runtime 不呼叫 LLM。

外部 coding agent 負責：

* 理解使用者自然語言要求。
* 查詢 Pilot MCP capabilities。
* 產生 semantic actions。
* 解釋預計變更。
* 發出 plan 或 apply tool call。

Pilot 負責：

* 驗證 semantic action schema。
* 確認 workspace 與 action target。
* 將 semantic actions 轉成標準 Bubble Tea key messages。
* 經由既有 TUI router、screen callback、validation 與 save path 執行修改。
* 產生可重播、可追蹤的稽核資料。
* 在錯誤、衝突或安全規則不成立時停止。

MCP Server 只是另一個 Pilot input adapter，不是另一套設定編輯器。

## Core Invariants

### 1. TUI 是正式 mutation path

所有 MCP 觸發的設定變更都必須經過：

```text
MCP semantic action
    ↓
Pilot action validation
    ↓
automationDriver
    ↓
tea.KeyMsg
    ↓
editRouterModel.Update
    ↓
既有 Bubble Tea screen callback
    ↓
既有 save path
```

禁止：

```text
MCP handler
    ↓
直接修改 YAML、inventory struct 或檔案
```

MCP 執行路徑不得新增第二套 YAML mutation implementation。

### 2. Semantic action registry 是唯一契約來源

MCP tools、`pilot actions schema`、scenario validation 與 automation execution 必須使用同一個 `editActionRegistry()`。

現況：`editActionRegistry()`（`edit_actions_registry.go`）目前已有 24 個 action（MVP 列出的 19 個，加上後續階段列的 5 個 vault action 其實都已存在於 registry 中），但 `editActionDef` 目前只有 `Spec`、`Validate`、`Run` 三個欄位，沒有結構化的 audit metadata 欄位。

新增 action 時，必須同時具有：

* 對外 schema。
* 輸入驗證。
* TUI 執行函式。
* audit metadata。
* 測試。

`audit metadata` 是本規格新增的第四個必要欄位，需要擴充 `editActionDef` struct 並回填全部既有 24 個 action 的定義，屬於一次性 breaking change，不是單純疊加新欄位。

不得在 MCP handler 中另外維護 action name、required fields 或 allowed values 清單。

### 3. Agent 不操作 raw terminal

Agent 只能提交 semantic actions，例如：

```json
{
  "action": "set_host_field",
  "host": "web-01",
  "field": "ansible_host",
  "value": "10.20.0.15"
}
```

Agent 不可提交：

```json
{
  "keys": ["DOWN", "DOWN", "ENTER", "CTRL-U", "TEXT ..."]
}
```

實際 key sequence 必須由 Pilot 根據 live TUI state 決定。

### 4. 錄影內容來自 live TUI model

稽核錄影必須擷取執行中的 `editRouterModel.View()`，而不是另外製作一套模擬畫面。

每個 semantic action 至少記錄：

* action 開始 marker。
* action name。
* action 前 screen ID。
* Pilot 發送的非敏感 key 摘要。
* action 後 TUI frame。
* action result。
* error 或 rollback marker。

### 5. MCP stdout 不得包含 TUI 輸出

stdio MCP Server 的 stdout 僅供 MCP JSON-RPC。

以下內容不得寫入 stdout：

* TUI frame。
* banner。
* log。
* debug menu。
* recorder output。
* progress text。
* Go logger output。

診斷 log 寫入 stderr。TUI frame、錄影與 trace 寫入 audit artifact。

## Scope

### MVP 必須支援

* `create_host`
* `set_host_field`
* `enable_role`
* `disable_role`
* `delete_host`
* `add_extra_var`
* `edit_extra_var`
* `delete_extra_var`
* `apply_role_preset`
* `copy_roles_from_host`
* `create_role_preset`
* `rename_role_preset`
* `delete_role_preset`
* `restore_role_presets`
* `set_group_var`
* `restore_group_var_default`
* `save_hosts`
* `discard_hosts`
* `save_group_vars`
* `discard_group_vars`

### MVP 可讀但不可修改

* workspace completeness 結果。
* role catalog。
* action schema。
* host 與 role membership。
* group_vars 的非秘密 scalar value。
* vault filename、是否加密及 key name metadata。

### MVP 不包含

* `deploy`
* `reconcile`
* 任意 shell command execution
* 任意 Ansible invocation
* Streamable HTTP transport
* 遠端 MCP Server
* Agent 自行控制 raw PTY
* nested YAML editor
* roster mutation
* FreeIPA DNS manifest mutation
* 未遮蔽的 vault secret input

### 後續階段

`add_vault_key`、`set_vault_value`、`delete_vault_key`、`save_vault`、`discard_vault` 這 5 個 action **已經存在於** `editActionRegistry()` 並可透過 `pilot edit --actions` 執行。`tui_textinput.go` 的 `EchoPassword` 遮罩渲染、`edit_automation_driver.go` 的 trace redaction（`sendRedacted`／`typeSecretOrPlain`）與 `value_env`-only 讀取（`resolveValueOrEnv`）也都已實作並有測試覆蓋（`edit_automation_driver_vault_test.go`）。換句話說，secret-safe 機制本身並非空白。

MCP 第一版刻意仍將這 5 個 action 排除在 capabilities 之外，原因不是機制不存在，而是：

* 現有 redaction 測試只驗證到 trace 層，尚未證明 masking 在 `session.cast` 錄影 frame 層級同樣生效。
* MCP 是新的 attack surface，需要獨立的 secret sentinel 測試才能開放。

完成 session.cast 層級的 masking 驗證與對應測試後，才可將這 5 個 action 加入 MCP capabilities：

* `add_vault_key`
* `set_vault_value`
* `delete_vault_key`
* `save_vault`
* `discard_vault`

Roster 與 FreeIPA DNS 必須先各自建立 semantic action contract，才可透過 MCP 暴露。

## CLI Interface

新增：

```bash
pilot mcp serve \
  --dir <workspace> \
  --transport stdio \
  --audit-dir <path> \
  [--allow-write]
```

### Flags

| Flag            | Default                         | Contract                            |
| --------------- | ------------------------------- | ----------------------------------- |
| `--dir`         | `.`                             | MCP Server 唯一允許存取的 workspace root。  |
| `--transport`   | `stdio`                         | 第一版只接受 `stdio`。                     |
| `--audit-dir`   | `<workspace>/.pilot/audit/edit` | plan、apply、trace、cast 與 diff 的保存位置。 |
| `--allow-write` | `false`                         | 未開啟時不得註冊或執行 apply mutation。         |
| `--log-level`   | 沿用全域設定                          | 所有 log 僅寫入 stderr。                  |

Workspace root 必須在 Server 啟動時 canonicalize。MCP tool argument 不得任意切換 workspace root。

### Read-only default

以下指令只提供 inspect 與 plan：

```bash
pilot mcp serve --dir envs/prod
```

要允許 apply：

```bash
pilot mcp serve \
  --dir envs/prod \
  --allow-write
```

即使啟用 `--allow-write`，MCP Client／Host 仍應將 apply tool 視為 mutation tool，並在呼叫前向使用者取得核准。

## MCP Tools

## `pilot_edit_capabilities`

性質：read-only。

回傳目前 Server 真正允許的 action contract，不得只回傳全域 registry 後讓 Agent自行猜測哪些 action 被 policy 禁止。

### Output

```json
{
  "schema_version": 1,
  "workspace": "/absolute/path/envs/prod",
  "write_enabled": true,
  "actions": [
    {
      "name": "create_host",
      "description": "create a host through the hosts TUI",
      "required": ["host"]
    }
  ],
  "unsupported": {
    "deploy": "not part of pilot edit MCP",
    "set_vault_value": "secret-safe recording is not enabled"
  }
}
```

## `pilot_edit_inspect`

性質：read-only。

讀取 workspace 並回傳 Agent 規劃 semantic actions 所需的最小資訊。

### Input

```json
{
  "include_group_vars": true,
  "include_vault_metadata": false
}
```

### Output

```json
{
  "workspace_revision": "sha256:...",
  "hosts": [
    {
      "name": "web-01",
      "ansible_host": "10.20.0.15",
      "ansible_user": "admin",
      "env": "prod",
      "roles": ["web-server"]
    }
  ],
  "role_presets": [],
  "group_vars": {
    "freeipa.yml": {
      "freeipa_realm": "EXAMPLE.INTERNAL"
    }
  },
  "completeness": {
    "blocking": [],
    "warnings": []
  }
}
```

禁止回傳：

* vault value。
* resolved `value_env`。
* private key 內容。
* password、token 或 secret value。
* 未經 allowlist 的任意檔案內容。

## `pilot_edit_plan`

性質：read-only，但會在隔離的 temporary workspace 中執行 TUI scenario。

用途：

* 驗證 Agent 產生的 semantic actions。
* 透過真正 TUI 預演。
* 產生 diff。
* 產生 plan recording。
* 不修改使用者 workspace。

### Input

```json
{
  "base_revision": "sha256:...",
  "scenario": {
    "version": 1,
    "title": "Add web-02",
    "steps": [
      {
        "action": "create_host",
        "host": "web-02"
      },
      {
        "action": "set_host_field",
        "host": "web-02",
        "field": "ansible_host",
        "value": "10.20.0.16"
      },
      {
        "action": "apply_role_preset",
        "host": "web-02",
        "preset": "web-server"
      },
      {
        "action": "save_hosts"
      }
    ]
  }
}
```

### Behaviour

1. 驗證 `base_revision`。
2. 驗證 scenario version 與 unknown fields。
3. 依 MCP policy 過濾 actions。
4. 建立 workspace temporary copy。
5. 對 temporary copy 建立 `editRouterModel`。
6. 由 `automationDriver` 發送 `tea.KeyMsg`。
7. 擷取 action markers、TUI frames 與 trace。
8. 執行 inventory lint 與 workspace completeness。
9. 產生 temporary workspace 相對原 workspace 的 unified diff。
10. 保存 immutable plan artifact。
11. 回傳 `plan_id`。

### Output

```json
{
  "plan_id": "01K1...",
  "base_revision": "sha256:...",
  "scenario_hash": "sha256:...",
  "valid": true,
  "affected_files": [
    "hosts.yml"
  ],
  "diff": "...",
  "validation": {
    "blocking": [],
    "warnings": []
  },
  "audit": {
    "directory": ".pilot/audit/edit/01K1...-plan",
    "recording": "session.cast",
    "trace": "trace.jsonl",
    "diff": "diff.patch"
  }
}
```

Plan 不得修改真實 workspace，即使 scenario 內含 `save_hosts` 或其他 save action。

## `pilot_edit_apply`

性質：mutation。

只接受先前成功產生的 `plan_id`，不得接受一份新的任意 scenario。

### Input

```json
{
  "plan_id": "01K1...",
  "expected_revision": "sha256:..."
}
```

### Behaviour

1. 確認 Server 以 `--allow-write` 啟動。
2. 取得 workspace mutation lock。
3. 重新計算 workspace revision。
4. 確認 revision 等於：

   * plan 的 `base_revision`
   * request 的 `expected_revision`
5. 讀取 plan 保存的 immutable scenario。
6. 建立 apply 前 workspace backup journal。
7. 對真實 workspace 建立 `editRouterModel`。
8. 由 `automationDriver` 重跑完全相同的 semantic actions。
9. 所有設定變更必須由既有 TUI save path 寫入。
10. 執行 lint 與 completeness。
11. 產生 apply diff、trace、recording 與 result。
12. 計算新 workspace revision。
13. 釋放 lock。

若任何步驟失敗，必須使用 backup journal 回復本次 apply 已修改的 managed files，並在 audit result 中記錄 rollback。

### Output

```json
{
  "session_id": "01K2...",
  "plan_id": "01K1...",
  "result": "applied",
  "revision_before": "sha256:...",
  "revision_after": "sha256:...",
  "affected_files": [
    "hosts.yml"
  ],
  "validation": {
    "blocking": [],
    "warnings": []
  },
  "rolled_back": false,
  "audit": {
    "directory": ".pilot/audit/edit/01K2...-apply",
    "recording": "session.cast",
    "trace": "trace.jsonl",
    "diff": "diff.patch",
    "result": "result.json"
  }
}
```

## Stable Automation Identity

目前人類可見 label 不得成為 MCP contract。

每個 MCP 可操作的 TUI screen 與 menu item 必須具有 stable automation ID。

範例：

```go
type SelectItem struct {
    AutomationID string
    Label        string
}
```

```text
AutomationID: hosts.create
Label:         ➕ 新增主機

AutomationID: hosts.save
Label:         💾 存檔並離開
```

規則：

* TUI 繼續顯示 `Label`。
* automation driver 優先用 `AutomationID` 尋找項目。
* 中文文案、emoji 或排序調整不得改變 automation ID。
* 同一個 screen 中 automation ID 必須唯一。
* MCP mode 遇到沒有 stable ID 的必要操作時必須 fail closed。
* 為相容既有測試，非 MCP legacy automation 可暫時保留 label fallback。
* 新增 MCP action 不得依賴 fixed menu index。

Screen ID 也必須穩定，例如：

```text
edit.top
hosts.path
hosts.list
hosts.item
hosts.roles
group_vars.files
group_vars.entries
vault.files
vault.entries
confirm.discard
confirm.save
```

## Audited TUI Session

新增共用的 audited session runner：

```go
type AuditedEditSession struct {
    ID          string
    Workspace   string
    Scenario    editScenario
    Router      *editRouterModel
    Driver      *automationDriver
    Recorder    AuditRecorder
    Trace       TraceSink
}
```

核心介面：

```go
type AuditRecorder interface {
    Start(SessionMetadata) error
    RecordActionStart(ActionEvent) error
    RecordKeys(KeyEvent) error
    RecordFrame(FrameEvent) error
    RecordActionResult(ActionResultEvent) error
    Close(SessionResult) error
}
```

`automationDriver.send` 或其共用邊界必須通知 recorder：

```go
type FrameEvent struct {
    Sequence int
    Time     time.Time
    Action   string
    ScreenID string
    View     string
}
```

Recorder 不得改變 router state，也不得自行發送按鍵。

## Definition of “Real TUI”

本規格所稱「真正的 TUI」必須同時符合：

* 使用正式 `editRouterModel`。
* 使用正式 screen implementations。
* action 經 `editRouterModel.Update`。
* navigation 經正式 callback。
* input 經 `tea.KeyMsg`。
* validation 與 save 經既有 screen path。
* recording frame 取自正式 `View()`。
* interactive `pilot edit` 與 MCP 使用相同 screen code。

僅產生看起來相似的文字 transcript，不算真正的 TUI。

不要求 MCP Server 將畫面直接顯示在 MCP Client 的 terminal；錄影與 audit artifact 即為 TUI session 的外部表示。

## Audit Artifacts

每個 plan 與 apply session 建立獨立目錄：

```text
.pilot/audit/edit/<timestamp>-<session-id>-<kind>/
├── metadata.json
├── scenario.redacted.json
├── trace.jsonl
├── session.cast
├── diff.patch
├── validation.json
├── managed-files-before.json
├── managed-files-after.json
└── result.json
```

### `metadata.json`

至少包含：

* session ID
* kind：`plan` 或 `apply`
* Pilot version
* git revision，若目前位於 Git repository
* MCP client info，若 protocol 提供
* workspace canonical path
* start／finish timestamps
* scenario hash
* workspace revision
* terminal width／height
* recorder implementation

### `scenario.redacted.json`

保存原始 semantic actions，但：

* 不保存 resolved environment value。
* secret value 固定寫成 `«redacted»`。
* 不保存任意 vault plaintext。
* 不保存私鑰內容。

### `trace.jsonl`

每行一個事件：

```json
{
  "sequence": 5,
  "step": 2,
  "action": "set_host_field",
  "screen_id": "hosts.item",
  "item_id": "host.field.ansible_host",
  "keys": ["CTRL-U", "TEXT<10 chars>", "ENTER"],
  "result": "ok"
}
```

`TEXT` trace 可記錄字元數，但敏感內容不得記錄。

### `session.cast`

必須可被標準 asciicast player 或 Pilot 文件指定的 recorder reader 播放。

錄影至少包含：

* Session 標題。
* workspace。
* plan 或 apply。
* 每個 semantic action marker。
* action 前後 TUI frame。
* save frame。
* validation result。
* success、failure 或 rollback marker。

Pilot 可選擇整合 TREC，但 TREC 不得成為 MCP Server 的硬 runtime dependency。若存在 `TREC_MARKER_FD`，應沿用現有 marker integration。

### `diff.patch`

* Plan：temporary workspace 相對 real workspace。
* Apply：apply 後相對 apply 前。
* 不得包含被 policy 定義為 secret 的內容。
* 若受管理檔案可能含秘密，該檔案的 diff 必須省略 value，並在結果中標記 `redacted_diff=true`。

### `result.json`

至少包含：

```json
{
  "result": "applied",
  "failed_step": null,
  "rolled_back": false,
  "revision_before": "sha256:...",
  "revision_after": "sha256:...",
  "validation_passed": true
}
```

## Secret Safety

### MCP arguments

MCP 不得接受 literal vault secret：

```json
{
  "action": "set_vault_value",
  "value": "real-password"
}
```

Secret action 必須使用：

```json
{
  "action": "set_vault_value",
  "value_env": "PILOT_SECRET_FREEIPA_ADMIN_PASSWORD"
}
```

### Server policy

* Secret environment variable 只在 action 執行時讀取。
* resolved value 不得進入 tool result。
* resolved value 不得進入 error。
* resolved value 不得進入 trace。
* resolved value 不得進入 scenario artifact。
* resolved value 不得進入 diff。
* resolved value 不得進入 TUI recording。
* secret key 名稱可以記錄，但 value 必須遮蔽。

### TUI masking

`tui_textinput.go` 的 `newSecretTextInputModel` 已使用 `EchoMode = textinput.EchoPassword` 做到 password-style masked rendering；`edit_automation_driver.go` 的 driver 已做到「將實際字元送入 model，但 trace 只記 `TEXT<redacted>`」。這些機制已存在於既有 `pilot edit --actions` 路徑並有測試覆蓋，MCP 不需要重新發明：

* `View()` 已只顯示固定遮蔽符號。
* recorder／trace 收到的 key event 已只有 `TEXT<redacted>`。

啟用 MCP vault mutation 前，仍必須額外驗證並補測試：

* recorder 產生的 `session.cast` frame 本身（不只是 trace）不得包含 resolved value——現有測試只驗證到 trace 層，未驗證到 cast frame 層。
* presentation frame 不得包含 resolved value。
* 新增 session.cast 層級的 secret sentinel 測試，證明錄影檔案本身也遮蔽成功。

在上述 session.cast 層級驗證完成以前，MCP capabilities 必須排除 vault mutation actions。

## Workspace Security

### Path confinement

Server 啟動時 canonicalize `--dir` 與 `--audit-dir`。

所有檔案操作必須確認：

* 路徑位於 workspace root 或 audit root。
* 拒絕絕對 action file path。
* 拒絕 `..`。
* 拒絕 path separator 出現在只允許 basename 的欄位。
* 拒絕 symlink parent escape。
* 拒絕 symlink target escape。
* group_vars 與 vault filename 必須符合允許的 extension。
* temporary workspace 不得落在受追蹤 workspace 內。

### Managed files

Workspace revision 與 backup journal只處理 Pilot-owned files：

* `hosts.yml`
* `role-presets.yml`
* `group_vars/*.yml`
* `group_vars/*.yaml`
* `host_vars/*.yml`
* `host_vars/*.yaml`
* 後續啟用時的 `.vault/*.yml`
* 後續啟用時的 `.vault/*.yaml`

不得遞迴 hash 或備份 workspace 內任意大型檔案。

### Workspace revision

Revision 必須由：

```text
relative path
file mode
content hash
symlink status
```

以排序後的 canonical encoding 計算。

Plan 與 apply 間任何 managed file 改變，都必須回傳 `workspace_changed`，不得自動覆蓋。

## Mutation Lock and Rollback

同一 workspace 同時間只允許一個 apply session。

Lock 必須：

* 具備 process ID。
* 具備開始時間。
* 具備 session ID。
* 在正常完成與失敗時釋放。
* 不因單純存在舊 lock file 就永久阻擋；須檢查 owner process 或採 OS file lock。

Apply 前建立 backup journal。

如果 scenario 已成功儲存 `hosts.yml`，但後續 group_vars action 失敗：

1. 停止執行後續 action。
2. 記錄失敗畫面與 trace。
3. 從 journal 還原本 session 已修改的 managed files。
4. 驗證還原後 revision 等於 apply 前 revision。
5. 將 `rolled_back=true` 寫入 result。
6. Tool result 必須明確說明 apply 未成立。

Rollback 是失敗復原機制，不得被當作新的設定 mutation API。

## Scenario Rules

MCP scenario 沿用既有 version 1 envelope：

```go
type editScenario struct {
    Version int          `json:"version"`
    Title   string       `json:"title"`
    Steps   []editAction `json:"steps"`
}
```

額外規則：

* unknown JSON fields 必須拒絕。
* scenario 不可為空。
* step 數量須有合理上限，預設 200。
* scenario serialized size 須有合理上限，預設 1 MiB。
* 每個修改中的 editor 必須有對應 save 或 discard action。
* scenario 結束時不得留在 dirty editor。
* apply scenario 不得包含 `deploy` 或 `reconcile`。
* action target 必須由 live TUI state 唯一解析。
* 找不到 target 或 target 不唯一時 fail closed。
* apply 必須使用 plan 保存的 scenario，不接受 tool request 內替換 scenario。

## Structured Errors

MCP tool error result 應包含：

```json
{
  "code": "unexpected_screen",
  "message": "expected hosts list screen",
  "step": 3,
  "action": "enable_role",
  "screen_id": "hosts.path",
  "rolled_back": false,
  "audit_directory": ".pilot/audit/edit/..."
}
```

標準 error codes：

* `invalid_scenario`
* `unsupported_action`
* `write_disabled`
* `workspace_changed`
* `workspace_locked`
* `path_outside_workspace`
* `secret_policy_violation`
* `unexpected_screen`
* `target_not_found`
* `ambiguous_target`
* `save_failed`
* `validation_failed`
* `recording_failed`
* `apply_failed`
* `rollback_failed`

Error message 不得包含 secret value。

## Proposed Code Changes

### New files

```text
cmd/pilot/cmd/mcp.go
cmd/pilot/cmd/mcp_server.go
cmd/pilot/cmd/mcp_edit_tools.go
cmd/pilot/cmd/mcp_edit_tools_test.go
cmd/pilot/cmd/edit_agent_session.go
cmd/pilot/cmd/edit_agent_session_test.go
cmd/pilot/cmd/edit_audit.go
cmd/pilot/cmd/edit_audit_test.go
cmd/pilot/cmd/edit_workspace_revision.go
cmd/pilot/cmd/edit_workspace_revision_test.go
cmd/pilot/cmd/edit_workspace_lock.go
cmd/pilot/cmd/edit_workspace_lock_test.go
cmd/pilot/cmd/edit_workspace_backup.go
cmd/pilot/cmd/edit_workspace_backup_test.go
```

第一版允許 MCP adapter 與 audited session 暫時留在 `cmd` package，以直接重用目前未 export 的 TUI router 與 driver。不得為了本功能同時進行大規模 package migration。

後續若抽離 package，必須保持：

```text
interactive CLI ─┐
JSON scenario ───┼── same audited edit session
MCP tools ───────┘
```

### Modified files

```text
cmd/pilot/cmd/root.go
cmd/pilot/cmd/actions.go
cmd/pilot/cmd/edit_actions_registry.go
cmd/pilot/cmd/edit_automation.go
cmd/pilot/cmd/edit_automation_driver.go
cmd/pilot/cmd/edit_tui.go
cmd/pilot/cmd/edit_tui_dns.go
cmd/pilot/cmd/edit_tui_roster.go
cmd/pilot/cmd/edit_tui_vault.go
cmd/pilot/cmd/tui_select.go
cmd/pilot/cmd/tui_multiselect.go
cmd/pilot/cmd/tui_textinput.go
go.mod
README.md
TESTING.md
```

Stable Automation ID 不是只動 `tui_select.go`／`tui_multiselect.go`／`tui_textinput.go` 三個共用元件檔就能落地。`newSelectModel`／`newMultiSelectModel` 目前在全 repo 約有 70 個呼叫點（`edit_tui_dns.go` 14 處、`edit_tui_roster.go` 15 處、`edit_tui.go` 13 處等），每一處都需要補上對應的 `AutomationID`。上表已補列主要的 `edit_tui_*.go` 進入點，但實際 diff 範圍會涵蓋所有建構 select／multiselect 畫面的檔案；Phase 1 的工時估算必須以「約 70 處呼叫點」為準，而非以「兩三個檔案」為準。

### SDK

使用官方 Go MCP SDK：

```text
github.com/modelcontextprotocol/go-sdk/mcp
```

依實作時最新穩定 release 鎖定版本，不得使用未固定版本或無意間升級到 pre-release。

## Compatibility

* 不帶 MCP 參數的 `pilot edit` 行為必須完全不變。
* 現有畫面 label 與 navigation 不得因新增 automation ID 而改變。
* `pilot edit --actions` 必須繼續可用。
* `pilot actions list` 與 `pilot actions schema` 必須繼續由相同 registry 產生。
* 現有 presentation 與 trace 格式可增加欄位，但不得移除既有欄位。
* TREC marker integration 必須繼續可用。
* MCP Server 不得成為 `pilot edit` 的必要 runtime dependency。
* 不使用 MCP 的使用者不需要安裝或設定任何 Agent。

## Testing Requirements

## Unit Tests

必須涵蓋：

* MCP capabilities 與 action registry 一致。
* MCP policy 正確排除 deploy、reconcile 與未安全化的 vault actions。
* stable screen IDs 唯一。
* stable item IDs 在同一 screen 唯一。
* driver 在 MCP mode 不使用 menu index。
* label 改變後 automation ID 仍可操作。
* unknown action 被拒絕。
* unknown JSON field 被拒絕。
* dirty editor 未 save／discard 被拒絕。
* revision hash deterministic。
* managed file 變更造成 revision 改變。
* plan 不修改真實 workspace。
* apply revision conflict。
* concurrent apply lock。
* apply 中途失敗後 rollback。
* rollback 後 revision 恢復。
* path traversal。
* symlink parent escape。
* symlink target escape。
* secret 不出現在 result、trace、cast、diff 或 error。
* recorder failure 的處理符合 policy。

## TUI Regression Tests

使用真實 router 測試：

```text
create_host
set_host_field
apply_role_preset
save_hosts
```

驗證：

* 每一步都經正式 screen。
* driver 發出 `tea.KeyMsg`。
* 最終檔案由既有 save path 建立。
* recording frame 與 live `View()` 一致。
* trace action 數量與 scenario 相同。
* interactive `pilot edit` 既有測試全部通過。

## MCP Integration Tests

啟動真實 stdio Server，使用官方 MCP client：

1. 建立 connection。
2. 列出 tools。
3. 呼叫 capabilities。
4. 呼叫 inspect。
5. 呼叫 plan。
6. 確認 workspace 未改變。
7. 呼叫 apply。
8. 確認 workspace 改變。
9. 檢查 audit artifacts。
10. 關閉 connection。

測試必須驗證：

* MCP stdout 每一筆輸出都是合法 protocol message。
* stderr log 不污染 stdout。
* TUI frame 不出現在 stdout。
* client cancel 能停止尚未進入 save 的 plan。
* client disconnect 不留下 workspace lock。
* apply 已開始寫入後發生 cancellation 時會 rollback。

## Recording Tests

* `session.cast` 可解析。
* 每個 action 都有 start 與 result marker。
* failed action 有 failure marker。
* rollback 有 rollback marker。
* cast 內存在真實 TUI screen title。
* cast 不含測試 secret sentinel。
* trace 不含測試 secret sentinel。
* diff 不含測試 secret sentinel。
* scenario artifact 不含測試 secret sentinel。

若測試環境有 TREC：

* 執行一個完整 plan recording。
* 執行一個完整 apply recording。
* 執行 `trec verify`。
* 保存 fresh evidence。

TREC 缺少時，核心測試仍須通過。

## Race and Failure Tests

至少執行：

```bash
go test ./cmd/pilot/cmd -run 'TestMCP|TestAuditedEdit|TestWorkspaceRevision' -count=1
go test -race ./cmd/pilot/cmd -run 'TestMCP|TestAuditedEdit|TestWorkspaceLock' -count=1
go test ./... -count=1
go test -race ./... -count=1
go build ./...
```

上述指令是實作完成後必須執行的驗證要求；實際成功結果須另存 evidence，不得在未執行前宣稱通過。

## Acceptance Criteria

### AC1 — Agent can discover the contract

MCP client 能取得目前允許的 semantic actions，且內容與 Pilot registry 一致。

### AC2 — Agent cannot submit raw keys

任何包含 raw terminal key sequence 的 tool input 都不在 schema 內，且無法驅動 TUI。

### AC3 — Plan uses the real TUI

`pilot_edit_plan` 對 temporary workspace 執行 scenario 時，所有 action 都經正式 Bubble Tea router、screen callback 與 `tea.KeyMsg`。

### AC4 — Plan does not mutate the workspace

成功或失敗的 plan 都不得改變真實 workspace revision。

### AC5 — Apply reuses the approved plan

`pilot_edit_apply` 只能執行既有 plan 保存的 scenario。不能在 apply request 中替換 action 或 value。

### AC6 — Apply detects stale workspaces

Plan 後只要 managed file 被人工或其他 Agent 修改，apply 就回傳 `workspace_changed`，且不寫入任何檔案。

### AC7 — Apply is auditable

成功 apply 至少產生：

* TUI recording
* semantic trace
* redacted scenario
* before／after revision
* diff
* validation result
* final result

### AC8 — Partial writes are recovered

若 scenario 在一個檔案已 save 後失敗，Pilot 會回復本次 apply 所做的變更，且 result 顯示 `rolled_back=true`。

### AC9 — Secrets never appear in evidence

使用固定 sentinel secret 執行測試時，該字串不得出現在：

* MCP response
* stdout
* stderr
* trace
* cast
* scenario artifact
* diff
* error
* result

### AC10 — Human interactive behaviour is unchanged

既有 `pilot edit` label、navigation、save、discard 與 cancel semantics 保持相容。

### AC11 — MCP protocol output is clean

在 stdio transport 下，Server stdout 不包含任何非 MCP protocol data。

### AC12 — Recording proves TUI execution

稽核者能從 recording 與 trace 看出：

* 執行了哪個 semantic action。
* Pilot 當時位於哪個 screen。
* Pilot 執行了哪些非敏感 key 類型。
* action 是否成功。
* 哪些檔案最後改變。
* 是否發生 rollback。

## Delivery Evidence

完成實作後建立：

```text
docs/evidence/pilot-edit-mcp/<date>-<tested-revision>.md
```

Evidence 至少包含：

* tested commit revision。
* build command 與結果。
* focused unit test 結果。
* full test 結果。
* race test 結果。
* 使用實際 MCP client 的 plan call。
* 使用實際 MCP client 的 apply call。
* plan 前後 workspace hash。
* apply 前後 workspace hash。
* audit artifact 路徑。
* recording 檢查結果。
* secret sentinel 掃描結果。
* interactive `pilot edit` regression 結果。

不得只使用 mock MCP handler 作為交付證據。

## Recommended Implementation Order

### Phase 1 — Stable identity and session boundary

* 為 edit screens 與 items 加入 stable automation ID（範圍涵蓋全 repo 約 70 處 `newSelectModel`／`newMultiSelectModel` 呼叫點，見「Proposed Code Changes」說明，非單一共用元件檔可完成）。
* 將 audited session runner 從 CLI globals 中隔離。
* 保持原本 interactive flow 不變。
* 增加 frame observer 與 recorder interface。

### Phase 2 — Workspace planning

* workspace revision。
* temporary copy。
* plan execution。
* diff。
* validation。
* plan audit artifacts。

### Phase 3 — MCP read-only server

* `pilot mcp serve`。
* capabilities。
* inspect。
* plan。
* stdio protocol cleanliness tests。

### Phase 4 — Guarded apply

* `--allow-write`。
* plan persistence。
* workspace lock。
* revision conflict。
* backup journal。
* rollback。
* apply artifacts。

### Phase 5 — Secret-safe vault

* masked TUI input。
* `value_env`-only MCP policy。
* recorder redaction。
* secret sentinel tests。
* vault actions 加入 capabilities。

### Phase 6 — Additional editors

在各自 semantic contract 完成後，依序評估：

* roster。
* FreeIPA DNS manifest。
  -其他 `pilot edit` screen。

## Definition of Done

只有同時滿足以下條件才算完成：

* Coding agent 能透過 MCP 取得 action contract。
* Coding agent 能建立 plan。
* Plan 使用正式 TUI 且不修改真實 workspace。
* 使用者批准 apply tool 後，Pilot 透過正式 TUI 修改 workspace。
* Agent 從未直接寫入 Pilot-managed YAML。
* Apply 有 revision conflict protection。
* Apply 失敗可 rollback。
* Audit artifacts 完整且可解析。
* Secret sentinel 沒有出現在任何 evidence。
* MCP stdout 沒有 protocol 外資料。
* 現有 interactive 與 automation tests 全部通過。
* 完整 actual-run evidence 已保存並連結。

