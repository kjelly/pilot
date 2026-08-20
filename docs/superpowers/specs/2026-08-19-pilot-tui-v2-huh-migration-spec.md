Pilot TUI v2 + Huh Migration Specification

Status

狀態：Draft — coding-agent implementation contract

建議 repo 路徑：docs/superpowers/specs/2026-08-19-pilot-tui-v2-huh-migration-spec.md

主要目標：將 Pilot TUI 遷移到 Bubble Tea v2 + Huh v2 + Bubbles v2

必須保留：Pilot router、semantic automation、MCP/--actions mutation path、audit/recording semantics

主要實作範圍：cmd/pilot/cmd TUI、automation driver、TUI tests、Charm dependencies

Implementation Baseline（供 coding agent 對照的具體起點；仍必須依 Coding Agent Start Checklist 重新核實，main 可能已演進）：

commit 5c28336da817fb3568f5c940fe7177be21344377（main，本節撰寫時的 HEAD）。

go.mod：go 1.26.4、github.com/charmbracelet/bubbletea v1.3.10、github.com/charmbracelet/bubbles v1.0.0、github.com/charmbracelet/lipgloss v1.1.0（indirect）。

Upstream v2 三件套已核實為 stable release，不是 unreleased pseudo-version：charm.land/bubbletea/v2 v2.0.8、charm.land/bubbles/v2 v2.0.0、charm.land/huh/v2 v2.0.3（皆為 2026 年 2–3 月起發布）。

基準狀態：go build ./... 乾淨；CI=1 go test ./... -count=1 全過（1813 tests / 22 packages）。這是一個適合分階段 bisect 的乾淨起點。

Goal

將目前 Pilot 自行維護的表單型 TUI primitives：

select

multi-select

text input

secret input

confirm

list filtering / scrolling / key help

替換為以 Huh v2 為主要 widget provider、Bubbles v2 為補充 primitive 的薄 Pilot UI Adapter，同時將整個 TUI runtime 遷移到 Bubble Tea v2。

最終架構：

Pilot business workflows
        │
        ▼
Pilot routers
(editRouterModel；deploy 側是 deploy_tui.go 的 per-prompt standaloneScreen wrappers，
 目前沒有等價的常駐 router type，見下方「Current State to Preserve」)
        │
        ▼
Pilot-owned UI contract
(Screen / Factory / AutomationState)
        │
        ▼
Thin Pilot UI Adapter
        │
        ├── Huh v2       form-oriented controls
        └── Bubbles v2   primitive/fallback controls
        │
        ▼
Bubble Tea v2

本改版的成功條件不是「畫面看起來比較漂亮」，而是：

Pilot 不再自行維護一般 Select/MultiSelect/Input/Confirm 的 cursor/filter/viewport/render loop。

Router 仍是 workflow navigation 的唯一 owner。

semantic automation 不依賴 Huh concrete types 或 Huh private state。

MCP/pilot edit --actions 仍驅動真正的 live TUI model，而不是新增第二套 mutation path。

所有既有 screen IDs、action schema、secret-redaction 與主要 cancel/back semantics 保持相容。

最終程式碼完全移除 Bubble Tea v1 / Bubbles v1 imports。

Why This Change

目前 Pilot 已使用 Bubble Tea，但表單 primitive 大量由 Pilot 自行維護。

現況代表 Pilot 必須自己處理：

cursor movement / wrap

list viewport 與 terminal resize

fuzzy filtering

search mode

help rendering

checkbox state

text input integration

confirm behavior

v1 key normalization

這些屬於通用 TUI widget responsibility，不應由 Pilot business code 長期持有。

另一方面，Pilot 的 router 與 automation semantics 是產品邏輯，不可交給 Huh 決定：

editRouterModel 決定 pilot edit 的 screen transition；pilot deploy 側目前沒有等價的常駐 router type（見下方「Current State to Preserve」），而是 deploy_tui.go 逐個 standalone screen 各自決定 confirm/cancel。

Esc/back behavior 反映 Pilot workflow hierarchy。

automationScreenID() 與 stable item IDs 是 machine-facing contract。

automationDriver 將 semantic action 展開成 live TUI input。

audit recorder 擷取 live TUI frame 與 safe key trace。

因此本改版的 boundary 是「換掉 widget implementation，不換掉 Pilot workflow ownership」。

Current State to Preserve

Coding agent 開始實作前必須重新讀取當下 main branch；不得只依本文件假設檔案仍與 2026-08-19 完全相同。

本規格建立時（commit 5c28336，2026-08-19）的重要現況如下——以下已用 grep/go test 核實，不是猜測，但 coding agent 開工前仍必須依 Start Checklist 重新核實一次（main 可能已演進）：

go.mod 使用 Go 1.26.4；Bubble Tea 為 github.com/charmbracelet/bubbletea v1.3.10；Bubbles 為 github.com/charmbracelet/bubbles v1.0.0；lipgloss v1.1.0 為 indirect 依賴。

cmd/pilot/cmd/tui_screen.go 已定義 router-embedded screen contract（`screen` interface：`Finished() bool` / `Canceled() bool` / `automationScreenID() string`），且已有 standaloneScreen wrapper、listClampWindow/listMoveCursor/listFilterIndices 等共用 list 邏輯，以及 updateListSearch 實作「search 中 Esc 先清除 query、非 search 中 Esc 才真正 cancel」的兩階段語意。這些正是本 spec Phase 1 要建的 Screen contract 的雛形——Phase 1 是「把已經在運作的邏輯抽到 interface 後面」，不是從零設計。

tui_select.go / tui_multiselect.go 自行處理 filtering、scrolling、cursor 與 rendering；selectItem{ID, Label} 與 multiSelectItem{ID, Label, Description, Checked} 兩個 struct 都已存在 ID 欄位，設計目的就是本 spec 要的 stable automation identity（selectItem 的檔案內註解明確引用 docs/superpowers/specs/2026-08-04-pilot-edit-mcp-semantic-tui-design.md 的「Stable Automation Identity」章節）。

但目前這個 ID 欄位在生產程式碼幾乎沒有被填入：newSelectModelWithScreenID(screenID, title, items []string)（77 個生產呼叫點）一律把每個 item 包成 selectItem{Label: s}，ID 永遠是空字串；真正能帶入 per-item ID 的 newSelectModelWithIDs(screenID, title, []selectItem) 建構子在生產程式碼裡零個外部呼叫點（只有它自己的定義行）。multiSelectItem{} 的情況好一點但仍是少數：生產程式碼 6 個 literal 建構點只有 2 個設了 ID。反過來，screen 層級的 screenID（例如 "hosts.list"、"roster.top"）已經相當普及——edit_tui*.go 裡已有約 154 個不同的 screenID 字面值在用。也就是說「哪個畫面」這一層 stable ID 已經做得不錯，「畫面裡哪一項」這一層 stable ID 幾乎是空的，Core Invariant 5 真正要補的是後者。

edit_automation_driver.go 已經有 chooseByID(r *editRouterModel, wantScreenID, itemID string) error（約第 746 行）與依 item.ID 比對的邏輯，但目前只有它自己的單元測試（edit_automation_driver_screenid_test.go）在呼叫它——所有真正驅動 semantic action 的生產路徑一律經由 choose(label string)（label/title 字串比對）：光是 edit_automation_driver*.go 這個檔案家族（driver 本身 + dns/extravars/groupvars/internal_endpoint/presets/roster/roster_access/roster_groups/roster_sudo/vault，共約 5,955 行）裡 .choose( 呼叫就有 190+ 處，且大量是 list.title == "..." 或 strings.Contains(list.title, ...) 這種對 render 出的中文/emoji 標籤做字串比對，而不是 chooseByID。chooseByID 是「已存在但完全沒接上生產流程」的半成品，不是「需要新增」的東西——真正的工作量是把這 190+ 個 choose(label) 呼叫點換成 chooseByID，並在對應的 77+6 個 item 建構點把 ID 填上。

editRouterModel（cmd/pilot/cmd/edit_tui.go，1074 行）是 pilot edit 的長生命週期 router，但它每一個 transitionTo(...) callback 目前都寫成 `func(r *editRouterModel, s screen) tea.Cmd { m := s.(selectModel); ... }` 這種對 concrete type 的斷言——這個模式不只出現在 automation driver，也遍布 edit_tui_dns.go / edit_tui_groupvars.go / edit_tui_hostvars.go / edit_tui_internal_endpoints.go / edit_tui_minimal.go / edit_tui_role_presets.go / edit_tui_roster.go / edit_tui_roster_access.go / edit_tui_roster_sudo.go / edit_tui_vault.go 這些 workflow 檔案本身，以及 deploy_tui.go、prompt_automation.go。全 repo 對 .(selectModel)/.(multiSelectModel)/.(textInputModel)/.(confirmModel) 的斷言實測 206 處、散在 32 個檔案（23 個是生產程式碼、9 個是測試檔案——測試檔案斷言 concrete type 屬於合理的 characterization test 寫法，不是要清除的對象；生產程式碼裡的 23 個檔案才是 Core Invariant 2「router callback 不得依賴 concrete widget implementation」真正要處理的範圍）。這代表 Automation Driver Refactor 與 Router Refactor 兩節的工作量遠大於只改 automation driver 系列檔案。

pilot deploy 側沒有與 editRouterModel 對等的常駐 router：repo 裡不存在任何 deployWizardModel 型別。deploy_tui.go 只有 111 行，其中 runSelectProgram/runTextProgram/runConfirmProgram 各自對 selectModel/textInputModel/confirmModel 包一個短生命週期、standaloneScreen 包裝的獨立 tea.Program（每個 prompt 各跑各的 Program），而不是像 pilot edit 一樣共用一個常駐 Program——deploy_tui.go 檔案開頭註解明確說明過這是刻意設計（deploy.go 的控制流是線性、不可回頭的一條路，不像 edit.go 有可回頭的選單樹，共用 router 的好處對它不成立）。本文件後面所有寫到「deployWizardModel」的地方，都應理解成這個 per-prompt standaloneScreen 模式；coding agent 不應嘗試尋找或保留一個叫 deployWizardModel 的真實型別。

confirmModel 目前的 Esc/Ctrl-C 語意，與本文件後面 Huh Adapter Requirements / Error and Cancel Semantics 兩節原本的敘述不一致，已在對應段落訂正，以「現況」為準：confirmModel.Canceled() 永遠回傳 false（硬編碼），Esc/Ctrl-C 目前的效果是直接判定成「選 No」（value=false, answered=true）——這是刻意設計（tui_confirm.go 檔案註解：一個 yes/no 問題沒答，預設走最安全的選項，不應該讓它 abort 整個 wizard）。Confirm 目前根本沒有一個獨立於「選 No」的 cancel 結果。Select/MultiSelect/Input 的 Canceled() 則確實是真正獨立的狀態（esc/ctrl+c 時設 canceled=true），跟 Confirm 不同，不受這條訂正影響。

semantic TUI/MCP design（docs/superpowers/specs/2026-08-04-pilot-edit-mcp-semantic-tui-design.md，1226 行，已核實存在於 repo）明確要求 mutation 必須經由 live TUI router path。

上述「automation driver 與眾多 workflow 檔案都直接 type-assert 具體 screen 型別」是本 migration 的最高風險：若直接將 selectModel 換成 *huh.Form，automation 與 router callback 會同時失去可觀測狀態並立即大量破壞——而且破壞面是 23 個生產檔案，不是 1–2 個 automation driver 檔案。

Upstream Baseline

本規格建立時，Charm 主線已使用下列 module paths：

charm.land/bubbletea/v2
charm.land/bubbles/v2
charm.land/huh/v2
charm.land/lipgloss/v2

2026-08-19 查核 upstream main 時：

Huh v2 依賴 Bubble Tea v2 與 Bubbles v2。

Bubble Tea v2 View() 回傳 tea.View，不再是 string。

Bubble Tea v2 主要 keyboard press event 是 tea.KeyPressMsg。

v1 tea.KeyMsg{Type: ...}、Runes 等寫法不可直接搬到 v2。

Huh Select 原生支援 / filtering、viewport、j/k 與方向鍵 navigation。

Huh Form 可作為 Bubble Tea model 嵌入其他 Bubble Tea application。

Dependency policy：

實作時選擇當下最新 stable v2 release set，不得依賴 unreleased main pseudo-version，除非 coding agent 明確證明 stable release 有 blocking defect，並在 PR 說明原因。

go.mod 最終只保留 v2 Charm module families；不得同時保留 Bubble Tea v1 + v2 作為長期 compatibility layer。

Huh/Bubbles/Lipgloss 的 transitive versions 由 Go MVS 解決，但不得留下兩套不同 major import path。

Non-Goals

本 migration 不包含：

重寫 pilot edit workflow。

重寫 deploy/reconcile business logic。

改變 semantic action JSON schema。

改變 MCP tool names 或 authorization model。

將 Agent 改成 raw terminal / raw PTY automation。

將 YAML mutation 從 TUI callback 搬到 MCP handler。

建立 k9s 類型的全螢幕 infrastructure dashboard。

一次把多個既有單欄位 wizard screen 合併成大型 multi-field form。

因為 Huh 支援 accessible mode 就直接改變現有 non-TTY behavior；accessible CLI 是後續獨立產品需求。

重新設計所有中文 wording、emoji 或 workflow menu hierarchy。

UI migration 可以改善 spacing、filter presentation、validation/error presentation，但不得藉機改變 workflow semantics。

Core Invariants

1. Pilot Router Remains Authoritative

Router 必須繼續負責：

current screen ownership

screen transition

back/cancel routing

banner composition

shell-out suspend/resume

workflow completion / quit

Huh Form 不得成為整個 pilot edit 或 pilot deploy 的 global router。

允許：

editRouterModel
  -> one Pilot SelectScreen adapter
      -> one Huh field/form

禁止：

one giant Huh form
  -> internally owns hosts -> roles -> group_vars -> vault workflow

2. Pilot Owns the UI Contract

Business/router/automation code 不得依賴：

*huh.Select[...]

*huh.MultiSelect[...]

*huh.Input

Huh internal selector state

Bubbles viewport internals

這些 concrete types 只允許存在於 UI adapter package。

3. Automation Contract Is Semantic, Not Widget-Specific

Automation 必須能在不知道 widget provider 是 Huh 或自製 implementation 的情況下：

得知目前 screen ID。

得知 screen kind。

查詢 selectable item stable ID / label / checked state。

查詢目前是否為 secret input。

發送 canonical Pilot key action。

觀察結果與 live rendered frame。

不得以 Huh concrete type assertion 取代目前的 Pilot concrete type assertion。

4. Live TUI Remains the Mutation Path

必須繼續符合：

semantic action
  -> action registry
  -> automation driver
  -> canonical Pilot input
  -> Bubble Tea v2 message
  -> live Pilot router
  -> live Pilot UI adapter
  -> existing callback/save path

禁止 automation 直接呼叫 Huh accessor 或直接寫結果值來跳過 keyboard/update path。

若 automation 要勾選 checkbox，必須讓 live UI model 接收到與人類操作等價的 input event。

5. Stable IDs Outlive Labels

Select/MultiSelect option 的 machine identity 必須使用 stable ID。

Human label 可包含：

中文

emoji

動態 count

狀態文字

Automation 不得把這些內容視為首選 identity。

既有尚未有 ID 的 menu 可以暫時使用 exact/legacy label fallback，但 migration 完成時所有被 semantic automation 主動定位的固定 menu action 應具有 stable ID。

6. Secrets Never Enter Automation Snapshots

任何 AutomationState / trace / recorder metadata：

不得包含 secret input 真值。

不得包含 Huh field accessor 的 secret value。

不得包含 clipboard/paste secret content。

Secret screen 可暴露：

kind = input
secret = true
has_value = true/false   # 若真的需要

但不可暴露 value。

7. Preserve Workflow Semantics, Not Pixel Output

Migration acceptance 應比較：

selected result

checked result

entered value

validation outcome

screen transition

screen ID

cancel/back behavior

semantic trace

secret masking

不要求 Huh rendering 與舊版逐字元相同。

Golden tests 不得因 ANSI style、padding 或 help wording 小改就大量失敗。

Target Package Design

建立 Pilot-owned UI package，建議位置：

internal/tui/
  screen.go
  state.go
  spec.go
  factory.go
  keys.go
  view.go
  theme.go
  huh_select.go
  huh_multiselect.go
  huh_input.go
  huh_confirm.go

若 coding agent 有更符合當下 repo package boundary 的位置可以調整，但必須維持同一 dependency direction：

cmd workflow/router
    -> internal/tui contract
        -> Huh/Bubbles/Bubble Tea

不得變成：

internal/tui
    -> cmd/pilot/cmd business workflow

Required Pilot UI Interfaces

實際名稱可調整，但 contract 必須具備等價能力。

Base Screen

Conceptual contract：

type Screen interface {
    tea.Model
    Finished() bool
    Canceled() bool
    AutomationState() AutomationState
}

Bubble Tea v2 tea.Model 的 View signature 必須由 v2 API 決定；不要為了保留 v1 interface 再做另一套假的 View() string model。

Typed Result Interfaces

Router callback 不得再依賴 concrete widget implementation。

需要等價於：

type SelectScreen interface {
    Screen
    SelectedID() string
    SelectedIndex() int
}

type MultiSelectScreen interface {
    Screen
    CheckedIDs() []string
    CheckedLabels() []string
}

type InputScreen interface {
    Screen
    Value() string
}

type ConfirmScreen interface {
    Screen
    Value() bool
}

SelectedIndex() / CheckedLabels() 是 migration compatibility helper；新 workflow 應優先使用 stable ID。

不得讓 router callback 使用：

s.(*huh.Form)
s.(*huh.Select[string])

Automation State

建立 immutable snapshot struct，至少包含：

type ScreenKind string

const (
    ScreenSelect      ScreenKind = "select"
    ScreenMultiSelect ScreenKind = "multi-select"
    ScreenInput       ScreenKind = "input"
    ScreenConfirm     ScreenKind = "confirm"
)

type AutomationItem struct {
    ID          string
    Label       string
    Description string
    Checked     bool
}

type AutomationState struct {
    ScreenID string
    Kind     ScreenKind
    Title    string
    Items    []AutomationItem
    Secret   bool
}

可增加 focused item ID、filter-active 等 machine-useful metadata，但必須遵守 secret boundary。

AutomationState() 只回傳 Pilot-owned immutable data，不得暴露 Huh pointer。

Screen Specs and Factory

Router 應描述「需要什麼 control」，不是「如何建 Huh field」。

Conceptual types：

type Choice struct {
    ID          string
    Label       string
    Description string
}

type SelectSpec struct {
    ScreenID string
    Title    string
    Choices  []Choice
    InitialID string
}

type MultiSelectChoice struct {
    Choice
    Checked bool
}

type InputSpec struct {
    ScreenID string
    Title    string
    Default  string
    Secret   bool
    Validate func(string) error
}

type ConfirmSpec struct {
    ScreenID string
    Title    string
    Default  bool
}

Factory：

type Factory interface {
    Select(SelectSpec) SelectScreen
    MultiSelect(MultiSelectSpec) MultiSelectScreen
    Input(InputSpec) InputScreen
    Confirm(ConfirmSpec) ConfirmScreen
}

Router 建構時注入 factory，production 使用 Huh factory；tests 可使用 production factory 或 deterministic test double，依測試目的選擇。

不得在每個 workflow function 到處直接 huh.NewSelect()。

Huh Adapter Requirements

Select

使用 Huh v2 Select 作為主要 implementation。

必須符合：

option value 使用 stable Pilot ID，不使用 human label。

label/description 只用於 presentation。

/ 可進入 filter。

navigation 至少支援方向鍵與 j/k。

list 超出可視高度時可 scroll。

resize 後可正常操作。

empty source list 時 Enter 不得偽造成功 selection。

filter zero-result 時 Enter 不得偽造 selection。

selected result 可 mapping 回 original choice index，以支援 transitional caller。

filter 不得改變 machine-facing item ID。

舊版 Pilot 的 filter 行為中，搜尋狀態按 Esc 先清除搜尋，再次 Esc 才 cancel screen。若 Huh default 不完全相同，adapter 必須攔截/調整 keymap，使 Pilot workflow 的既有 cancel expectation 保持成立，或以 characterization test 證明對既有 flow 無 observable regression。

MultiSelect

使用 Huh v2 MultiSelect 作為主要 implementation。

必須符合：

option value 為 stable ID。

label/description 供人類閱讀。

initial checked state 可帶入。

zero selected 是合法值。

empty source list 對 optional checklist 必須可完成，保持目前 Pilot semantics。

filtered view 不得破壞原始 checked state。

automation snapshot 必須能得知每一項 checked state，而不讀 Huh private fields。

若 Huh public API 無法在不破壞 encapsulation 的前提提供 automation 所需 checked snapshot，adapter 必須由 Pilot 自己持有 canonical checked-ID set，並讓 Huh accessor 綁定這個 set；不得反射或讀 Huh unexported state。

Input

Huh v2 Input 優先。

必須符合：

default value。

cursor/focus 正常。

trim semantics 與現況一致：router 取得 Value() 時不保存不必要的 leading/trailing whitespace。

validator failure 留在同一 screen，顯示 error，不完成 screen。

Esc/Ctrl-C cancel。

automation 的 replace-text 操作仍可透過 canonical clear/type/submit input 完成。

若某些 Huh Input 行為無法滿足 Pilot secret 或 automation contract，可在 adapter 內使用 Bubbles v2 textinput 作為 fallback。這是允許的，因為目標是 Huh-first + Bubbles fallback，而不是 Huh-only。

Secret Input

必須保留 password masking。

Acceptance：

human interactive view 不出現 plaintext。

router.View() frame 不出現 plaintext。

presentation recording 不出現 plaintext。

session.cast 不出現 plaintext。

automation trace 的 typed content 維持 «redacted» 或既有等價安全表示。

AutomationState() 不出現 plaintext。

Confirm

使用 Huh Confirm 或 adapter-owned equivalent。

必須保留現況語意（見「Current State to Preserve」對 confirmModel 的訂正——這裡是刻意保留現有行為，不是要「修好」一個缺陷）：

default true/false。

keyboard selection（y/n 直接生效，Enter 採用 default）。

Enter confirm。

Esc/Ctrl-C 解析為「選 No」（value=false），不得產生一個新的、以前不存在的獨立 Canceled()==true 結果——Huh Confirm 若原生把 Esc 視為表單 abort/StateAborted，adapter 必須攔截並把它映射回「No」，不得讓這個 abort state 洩漏成 ConfirmScreen 的 Canceled()。

若某個具體呼叫點確實需要「Esc 應該真的取消，不是選 No」這種新語意，屬於 Requires Explicit Approval / Separate Spec 的範圍，不得在本 migration 裡順手改掉。

Bubble Tea v2 Migration Requirements

Bubble Tea v2 migration 必須視為獨立 workstream，而不是單純 import rename。

View Migration

v2 View() 回傳 tea.View。

需要更新：

generic Screen interface

standalone screen wrapper

edit router

deploy router

test harness

audit/presentation frame extraction

所有直接呼叫 .View() 並期待 string 的 code

建立一個 Pilot-owned helper 將 tea.View 安全轉成 audit 用的 rendered content，例如：

viewContent(view tea.View) string

Audit recorder 只需要 content 時可以使用這個 helper，但 runtime router 不得因此丟棄 child view 的 cursor/terminal metadata。

View Composition

editRouterModel 現在會把 banner string prepend 到 child screen output。

v2 後必須建立 composeView(prefix, child tea.View) tea.View 或等價 helper，要求：

保留 child view 的所有 terminal metadata。

保留 cursor metadata。

prefix 增加行數時，若 cursor coordinates 是 absolute view coordinates，必須正確調整。

不得用 tea.NewView(prefix + child.Content) 無條件覆蓋 child view，導致 Huh/Bubbles cursor 或其他 metadata 消失。

此 helper 必須有 unit test。

Keyboard Migration

v2 主要使用 tea.KeyPressMsg。

禁止在 business/automation code 大量散落 Bubble Tea v2 key struct literal。

建立 Pilot canonical key layer，例如：

type KeyAction string

const (
    KeyUp      KeyAction = "up"
    KeyDown    KeyAction = "down"
    KeyEnter   KeyAction = "enter"
    KeyEscape  KeyAction = "esc"
    KeySpace   KeyAction = "space"
    KeyClear   KeyAction = "ctrl+u"
)

並集中實作：

KeyAction -> Bubble Tea v2 KeyPressMsg
Bubble Tea v2 KeyPressMsg -> canonical key name

Automation trace 必須繼續輸出 stable canonical names：

up
down
enter
space
ctrl+u
«redacted»

不得讓 trace 因 Bubble Tea v2 String() 改成 space 等 upstream representation 而產生不必要 schema drift。

Return / Ctrl-J Compatibility

現有 Pilot 特別處理某些 PTY/tmux 將 Return 送成 LF/Ctrl-J 的情況。

v2 migration 必須保留等價 compatibility，並有 regression test。

不得假設 v2 upgrade 自動解決所有 terminal normalization。

Automation Driver Refactor

這是 migration 的 mandatory prerequisite。

Remove Concrete Screen Assertions

最終 automation driver 不得出現：

r.current.(selectModel)
r.current.(multiSelectModel)
r.current.(textInputModel)
r.current.(*huh.Form)
r.current.(*huh.Select[string])

改由：

r.current.AutomationState()

與 typed Screen result interface 完成 introspection。

Choosing Items

chooseByID(screenID, itemID) 已存在（cmd/pilot/cmd/edit_automation_driver.go，約第 746 行），也已有專屬單元測試（edit_automation_driver_screenid_test.go），但目前零個生產呼叫點——所有真正驅動 semantic action 的路徑都還在用 choose(label)（title/label 字串比對，散布在 edit_automation_driver*.go 全家族，190+ 呼叫點）。這裡不是「新增」，是：

把 190+ 個既有 choose(label) 呼叫點逐步換成 chooseByID(screenID, itemID)——可以按 workflow 域（roster/dns/vault/groupvars/...）逐檔進行，每換完一個檔案讓相關 automation test 全過再換下一個。

在對應的 item 建構點補上 stable ID（現況：newSelectModelWithScreenID 77 個生產呼叫點一律不帶 ID、multiSelectItem{} 6 個 literal 只有 2 個帶 ID）；把純 []string 呼叫升級成帶 ID 的 selectItem/multiSelectItem 版本。

chooseByLabel(...)（即現有 choose(label)）保留作 legacy fallback，用於尚未升級或本質是 dynamic label 的呼叫點。

固定 workflow menu item 優先 stable ID。

Dynamic entity（例如 hostname、user name）可以使用 deterministic entity-derived ID，或明確 documented exact-label identity；不得使用 ambiguous substring 作為唯一 machine contract。

Checked State

Role checklist / roster checklist 等 automation 必須從 AutomationState.Items[].Checked 讀取目前狀態。

Driver 再決定是否需要送 Space。

不得直接改 adapter 的 checked set。

Text Entry

Driver 仍以 input event 操作：

clear -> type -> enter

Secret input：

clear -> type secret through live model -> enter

但 trace/recording 必須 redacted。

Screen IDs

所有既有 explicit screen IDs 必須保持不變，除非有獨立 migration table 與 compatibility handling。

至少涵蓋（已用當下 main 核實約有 154 個不同 screenID 字面值在用，下面類別是覆蓋範圍檢查用，不是精確清點）：

edit top menu（例如 "edit.top"）

hosts screens（例如 "hosts.list"、"hosts.item"、"hosts.roles"、"hosts.extra_vars"、"hosts.extra_var_action"、"hosts.role_preset_apply"、"hosts.role_copy_from_host"）

role preset screens

group_vars screens

vault screens

roster screens（含 roster access/groups/sudo 子畫面，例如 "roster.top"、"roster.users.list"、"roster.user.detail"）

DNS/internal-endpoint screens

host_vars screens

minimal workspace wizard screens

不得將 Huh field key 當成 screen ID source of truth。

Router Refactor

Edit Router

editRouterModel 保留原本 responsibility。

需要變更：

current 改為 Pilot UI Screen interface。

router 持有/inject tui.Factory。

transition helper 使用 factory 建立 screen。

callback 使用 typed screen interfaces，而非 concrete implementation。

v2 tea.View composition。

v2 key/message handling。

不得重寫 hosts/group_vars/vault/roster/DNS workflow 為另一套 state machine。

Deploy Wizard

deploy 側現有的 standalone prompts（deploy_tui.go 的 runSelectProgram/runTextProgram/runConfirmProgram，各自包一個短生命週期 tea.Program）也必須遷移到同一 Pilot UI contract；migration 不得因此把 deploy 目前多個獨立 one-shot prompt 硬併成一個常駐 router——deploy_tui.go 檔案開頭註解已明確說明過為何不這麼做（deploy.go 是線性、不可回頭的流程，不像 edit.go 有可回頭的選單樹），這個設計選擇不是本 migration 的範圍。

禁止 edit 使用 Huh、deploy 仍保留另一套 duplicate custom primitive。

若 deploy 有特殊 primitive，先證明其 contract 無法由 generic adapter 表達，再新增 Pilot-owned adapter type。

Standalone Prompts

現有 one-shot screen wrapper 必須保留等價 behavior：

primitive 本身不 tea.Quit。

standalone owner 在 Screen Finished() 後才 quit。

router-embedded screen 不得因 Enter 直接終止整個 wizard。

這是核心 invariant，必須有 test。

Error and Cancel Semantics

Migration 必須建立 characterization tests 鎖住：

Select Enter = submit selected item。

Select Esc = cancel/back。

Search/filter active 時 Esc semantics 與現況一致。

MultiSelect Enter = commit whole checked set。

MultiSelect Esc = discard current checklist edits / back，依 caller contract。

Input validation error = 留在 screen。

Input Esc/Ctrl-C = cancel。

Confirm 沒有獨立的 cancel 結果：Esc/Ctrl-C 現況等同選擇「No」，Canceled() 恆為 false；migration 必須原樣保留這個 collapse，不得讓 Huh 的 abort state 變成一個新的、以前不存在的 Confirm cancel 結果。

Top-level edit Esc = quit wizard。

Nested edit Esc = 回上一層，而不是 quit whole wizard。

Shell-out return 後 router 恢復正確 screen。

不得只以 Huh Form StateAborted 一個 state 取代 Pilot 所有 cancel/back policy。

Search and Filtering Contract

Huh 的 filtering 可以取代目前 Pilot hand-written fuzzy filter，但 human-visible behavior 必須保持合理相容。

Required observable behavior：

/ 啟動 search/filter。

query 可編輯。

no matches 有明確 feedback。

filter 不改變原始 option stable ID。

清除 filter 後完整 item set 恢復。

長列表仍可 scroll。

filter 後選取結果 mapping 回正確 original entity。

不要求 Huh fuzzy algorithm 與舊 listFuzzyMatches() 完全同演算法。

但既有 automation 不得依賴 fuzzy search 才能定位 machine target；automation 應依 stable ID/state 計算 navigation。

Theme and Rendering Boundary

建立單一 Pilot theme construction point。

目的：

Huh fields 使用一致 theme。

未來若要支援 mono/light/dark 可在一處完成。

business workflow 不 import Lipgloss。

本 migration 不要求新增 theme CLI flag。

不得在每個 screen 建立各自不同 Huh theme。

Accessibility Boundary

Huh v2 有 accessible mode，但本 migration 不直接啟用成 product feature。

原因：Pilot router、automation recorder、non-TTY guard 與 Huh accessible prompting 的 ownership 尚未定義。

本階段只要求 adapter 不做阻礙未來 accessible mode 的設計，例如不要把 ANSI rendering 當成 semantic state。

File-Level Migration Plan

以下是預期 touch points；coding agent 必須以實作當下 main branch 重新搜尋補齊。

New

建議：

internal/tui/screen.go
internal/tui/state.go
internal/tui/spec.go
internal/tui/factory.go
internal/tui/keys.go
internal/tui/view.go
internal/tui/theme.go
internal/tui/huh_select.go
internal/tui/huh_multiselect.go
internal/tui/huh_input.go
internal/tui/huh_confirm.go

Modify

至少（已用當下 main 實測 grep 補齊——這份清單比只列 automation driver 大一個量級，因為每個 workflow 檔案自己的 router callback 也 concrete-type-assert，不只 automation driver 這樣做）：

go.mod
go.sum
cmd/pilot/cmd/edit_tui.go（router 本身，1074 行）
cmd/pilot/cmd/deploy_tui.go（deploy 的 per-prompt standaloneScreen wrappers，111 行，不是常駐 router）
cmd/pilot/cmd/prompt_automation.go
cmd/pilot/cmd/edit_automation_driver.go
cmd/pilot/cmd/edit_automation_driver_dns.go
cmd/pilot/cmd/edit_automation_driver_extravars.go
cmd/pilot/cmd/edit_automation_driver_groupvars.go
cmd/pilot/cmd/edit_automation_driver_internal_endpoint.go
cmd/pilot/cmd/edit_automation_driver_presets.go
cmd/pilot/cmd/edit_automation_driver_roster.go
cmd/pilot/cmd/edit_automation_driver_roster_access.go
cmd/pilot/cmd/edit_automation_driver_roster_groups.go
cmd/pilot/cmd/edit_automation_driver_roster_sudo.go
cmd/pilot/cmd/edit_automation_driver_vault.go
cmd/pilot/cmd/edit_tui_dns.go
cmd/pilot/cmd/edit_tui_groupvars.go
cmd/pilot/cmd/edit_tui_hostvars.go
cmd/pilot/cmd/edit_tui_internal_endpoints.go
cmd/pilot/cmd/edit_tui_minimal.go
cmd/pilot/cmd/edit_tui_role_presets.go
cmd/pilot/cmd/edit_tui_roster.go
cmd/pilot/cmd/edit_tui_roster_access.go
cmd/pilot/cmd/edit_tui_roster_sudo.go
cmd/pilot/cmd/edit_tui_vault.go
cmd/pilot/cmd/edit_audit*.go
cmd/pilot/cmd/tui_testharness_test.go
cmd/pilot/cmd/tui_standalone_test.go
TUI primitive tests（tui_select_test.go / tui_multiselect_test.go / tui_textinput_test.go / tui_confirm_test.go / tui_screen_test.go / tui_keyboard_contract_test.go）
edit/deploy flow tests（edit_tui_test.go、edit_tui_roster_checklist_test.go 等）
automation driver tests（edit_automation_driver_test.go、edit_automation_driver_roster_access_test.go、edit_automation_driver_screenid_test.go）
MCP semantic TUI tests（mcp_edit_tools_test.go、mcp_edit_errors_test.go 等）

以及所有 import Bubble Tea v1/Bubbles v1 的檔案——上述清單合計（cmd/pilot/cmd/{tui_,edit_,deploy_}*.go）約 27,000+ 行，占該 package 全部程式碼約 55%；coding agent 必須把這個範圍當成排程依據，不能假設只動 automation driver 系列就夠。

Delete or Reduce to Compatibility Shim

最終不應再存在 hand-written generic widget loops：

cmd/pilot/cmd/tui_select.go
cmd/pilot/cmd/tui_multiselect.go
cmd/pilot/cmd/tui_textinput.go
cmd/pilot/cmd/tui_confirm.go

允許 migration 過程短暫保留同名 constructor shim，但 final state 若保留檔案，內容只能是薄 adapter glue，不得繼續自行處理 generic cursor/filter/viewport/render logic。

tui_screen.go 的 shared router semantics 可被搬入 internal/tui，不可只是刪除後讓 Huh own router policy。

Implementation Phases

Coding agent 必須依 phase 實作；每個 phase 結束時 build/tests 應可獨立通過。不要做一個無法 bisect 的巨型 commit。

Phase 0 — Characterize Existing Contract

在改 dependency 前補齊 regression tests。

至少鎖住：

select result / cancel / empty / filter。

multi-select checked semantics。

input validation / secret masking。

confirm 現況（Esc/Ctrl-C 等同選 No，Canceled() 恆為 false，沒有獨立 cancel 結果）。

nested Esc back behavior。

top-level Esc quit behavior。

router resize forwarding。

standalone vs embedded quit ownership。

automation screen IDs。

automation stable item IDs。

secret trace/cast sentinel。

representative pilot edit --actions end-to-end scenario。

representative MCP plan/apply scenario。

Phase 0 不改 UI behavior。

Phase 1 — Introduce Pilot-Owned UI Contract

建立：

Screen

typed result interfaces

Screen specs

Factory

AutomationState

stable Choice type

先用現有 custom implementation 包裝這些 interfaces。

同時把 automation driver 與每個 workflow 檔案（edit_tui_*.go／deploy_tui.go／prompt_automation.go）裡的 concrete type assertions 移除，改讀 AutomationState()／typed result interface。這是全 migration 工作量最大的單一 phase：現況 206 處 .(selectModel)/.(multiSelectModel)/.(textInputModel)/.(confirmModel) 斷言分佈在 32 個檔案（23 個生產檔案需要真正改寫，9 個測試檔案的斷言屬於合理 characterization 寫法，可視情況保留或改寫成透過 AutomationState 斷言），不是「加個 interface 包一下」量級的工作，coding agent 排時程與拆 commit 時必須反映這點。

此 phase 完成後，即使尚未導入 Huh，automation 與 router callback 都已經與 widget concrete implementation 解耦。

Gate：

semantic action schema 不變。

existing TUI tests 通過。

automation/MCP tests 通過。

Phase 2 — Bubble Tea v2 + Bubbles v2 Foundation

先升 runtime major version，暫時保留 Pilot-owned custom adapter behavior。

處理：

import paths。

tea.View。

tea.KeyPressMsg。

key normalization。

test harness。

standalone wrapper。

router view composition。

recorder frame extraction。

Bubbles v2 textinput。

Gate：

no Bubble Tea v1 import。

no Bubbles v1 import。

existing behavior characterization tests 通過。

automation traces 使用原 canonical key names。

這個 phase 的目的，是把 framework major migration 與 Huh behavior migration 分離，方便定位 regression。

Phase 3 — Add Huh v2 Adapter

將 generic primitive implementation 逐個替換：

Confirm

Input

Select

MultiSelect

每替換一個 primitive就先讓相關 tests 全通過，再換下一個。

Huh integration 只發生在 internal/tui adapter package。

Gate：

business/router code 無 Huh imports。

automation driver 無 Huh imports。

Huh option values 使用 stable IDs。

secret input sentinel tests 通過。

Phase 4 — Router Call-Site Cleanup

將所有 workflow screen construction 收斂到 factory/spec。

完成：

edit flows

deploy flows

roster

DNS

internal endpoints

vault

host_vars

role presets

minimal workspace wizard

逐步將 fixed menu navigation 從 label identity 升級為 stable item ID——現況約 77 個 selectItem 生產建構點、6 個 multiSelectItem 生產建構點缺 ID，且 190+ 個 choose(label) 呼叫點要換成 chooseByID；這是第二大工作量的 phase，僅次於 Phase 1。

Gate：

all existing explicit screen IDs preserved。

automation external scenario schema unchanged。

nested back behavior unchanged。

Phase 5 — Remove Legacy Widget Code

刪除：

hand-written list scrolling logic。

hand-written fuzzy filter logic。

old v1 key compatibility code。

obsolete legacy widget tests that只測 private implementation details。

保留/重寫為 adapter-level behavior tests。

Gate：

repo 搜尋不到 github.com/charmbracelet/bubbletea v1 import。

repo 搜尋不到 github.com/charmbracelet/bubbles v1 import。

repo business packages 搜尋不到 charm.land/huh/v2 import；只允許 UI adapter package。

generic UI behavior 不再由 cmd/pilot/cmd 手寫。

Phase 6 — Full Regression and Evidence

執行完整 regression。

至少：

go test ./...

go vet ./...

go test -race -count=1 ./...（若 CI/環境支援）

interactive PTY smoke for pilot edit

pilot edit --actions representative scenario

MCP plan/apply representative scenario

secret masking sentinel across rendered frame/trace/cast

若 repo 當下 AGENTS.md / TESTING.md 有更嚴格要求，以當下文件為準。

Testing Requirements

Adapter Unit Tests

Select

choose first/middle/last。

up/down wrap。

j/k navigation。

filter query。

no result。

clear filter。

filter + select maps correct stable ID/index。

empty list Enter does not finish。

Esc cancel。

resize long list。

Chinese + emoji labels。

MultiSelect

initial checked state。

toggle on/off。

multiple values。

zero values。

empty list commit when caller marks checklist optional/compatible。

filter preserves checked state。

description rendering does not affect ID。

Input

default value。

replace value。

trim behavior。

validation success/failure。

Esc cancel。

Ctrl-C cancel。

Return/Ctrl-J compatibility。

Secret Input

Use a unique sentinel such as a test-generated random marker，不要使用真實 secret。

Assert sentinel absent from：

screen rendered content

router rendered content

automation trace

audit metadata

cast/presentation frame

但 final returned value 必須仍正確交給既有 callback/save path。

Confirm

default true。

default false。

choose yes。

choose no。

Esc/Ctrl-C 解析為 no，且不產生獨立於「no」的 cancel 結果（沿用現況，不是新行為）。

Router Tests

至少涵蓋：

transition to next screen。

callback reads typed result interface。

nested Esc returns one level。

top-level Esc exits。

WindowSize forwarded after transition。

banner + child view composition。

child view cursor metadata preserved。

standalone Screen finishing causes wrapper quit, embedded screen finishing does not directly quit Program。

Automation Tests

既有 scenario tests 優先原封不動保留。

新增 assertions：

driver 不依賴 concrete adapter type。

AutomationState carries stable IDs。

choose fixed item by ID。

label wording/emoji change 不破壞 ID-based automation test。

checked state is observable through snapshot。

semantic trace key names stable across v2。

MCP Regression

至少證明：

MCP semantic action
 -> automation driver
 -> Bubble Tea v2 router
 -> Huh-backed adapter
 -> existing save callback
 -> expected workspace diff

不得 mock 掉 Huh-backed screen 後宣稱 migration end-to-end 成功。

Compatibility Requirements

Must Remain Compatible

pilot edit user workflow structure。

pilot deploy interactive prompt semantics。

pilot edit --actions scenario schema。

semantic action registry names/required fields。

MCP edit tool behavior。

screen IDs。

audit trace schema unless explicitly versioned。

vault/secret redaction guarantee。

non-TTY guard behavior。

existing save/discard confirmation semantics。

Allowed UI Differences

colors。

padding。

cursor glyph。

help layout。

filter visual presentation。

scroll indicator presentation。

validation message styling。

Requires Explicit Approval / Separate Spec

renaming semantic actions。

changing screen IDs。

changing scenario JSON schema。

changing Esc/back hierarchy。

combining multiple workflow screens into one multi-field form。

removing TUI-as-mutation-path invariant。

exposing secret values to agent state。

Performance and Resource Requirements

Migration 不追求 microbenchmark，但應避免明顯 regression：

opening a menu 不得執行 network IO。

static Select/MultiSelect 不得在每個 Update 重新建大型 business dataset。

AutomationState() 不得做 filesystem IO。

View rendering 不得做 YAML parsing 或 inventory scan。

Huh dynamic options 只有真正 dynamic data 才使用；一般 menu 用 static options。

Logging and Debugging

PILOT_DEBUG_MENU 若仍為既有測試/工具依賴，必須保留等價 capability，或將 debug output 改由 Pilot adapter/factory 統一產生。

不得從 Huh private state dump debug data。

Debug output：

不得污染 MCP stdout。

secret item/value 必須 redacted。

Prohibited Shortcuts

Coding agent 不得：

直接把 screen alias 成 *huh.Form。

讓 automation type-assert Huh types。

為了讓 tests 通過而讓 automation 直接改 bound value。

保留 v1 與 v2 Bubble Tea 兩套 runtime 長期共存。

以反射讀取 Huh unexported fields。

把 fixed menu automation identity 繼續建立在 emoji/substring label 上。

刪除 secret masking tests。

因 Huh default Esc 行為不同就靜默改變 Pilot router back semantics。

用大量 exact ANSI golden snapshots 取代 semantic behavior tests。

在 migration 同時重寫 unrelated workflow/business logic。

為了簡化 Huh integration，讓一個 screen 自行 tea.Quit 並破壞 router ownership。

讓 audit recorder 只錄 mock/synthetic view，而不是 live router view。

Acceptance Criteria

本 migration 完成時，以下全部成立：

Architecture

Runtime 使用 Bubble Tea v2。

Widget layer 使用 Huh v2；需要 primitive fallback 時使用 Bubbles v2。

Router 只依賴 Pilot-owned UI interfaces。

Business workflow code 不 import Huh。

Automation driver 不 import Huh。

Automation driver 不 type-assert legacy concrete screen models。

Huh/Bubbles concrete types 被限制在 thin UI adapter boundary。

Behavior

pilot edit interactive flow 可正常完成。

pilot deploy interactive prompts 可正常完成。

nested Esc/back semantics preserved。

filter/search works for long Select/MultiSelect lists。

resize does not break list/input interaction。

validation behavior preserved。

Confirm 的 Esc/Ctrl-C 與現況一致：解析為 No，且不衍生出一個新的獨立 Canceled() 結果（除非另有核准的 separate spec）。

Automation

all existing semantic action names unchanged。

all existing explicit screen IDs unchanged。

stable item ID is available to automation。

representative pilot edit --actions scenario passes through live Huh-backed TUI。

representative MCP plan/apply passes through live Huh-backed TUI。

trace key names remain canonical/stable。

Security

secret plaintext absent from rendered frames。

secret plaintext absent from automation snapshot。

secret plaintext absent from trace/cast/presentation audit artifacts。

secret value still reaches intended save callback when authorized。

Cleanup

no Bubble Tea v1 imports。

no Bubbles v1 imports。

no duplicate hand-written generic select/multiselect filtering/viewport implementation。

obsolete compatibility code removed。

go mod tidy leaves no unused v1 dependency tree。

Quality Gates

go test ./... passes。

go vet ./... passes。

race test passes where supported。

PTY smoke test passes。

secret sentinel regression passes。

current repository CI passes。

Recommended Commit Structure

Coding agent 應盡量產生可 review / bisect 的 commits：

test: characterize current TUI and automation contracts

refactor: introduce pilot-owned TUI interfaces and automation state

refactor: decouple automation driver from concrete TUI models

chore: migrate Bubble Tea and Bubbles to v2

feat: add Huh v2 Pilot UI adapters

refactor: migrate edit and deploy routers to UI factory

refactor: switch automated menu targeting to stable IDs

test: add Huh-backed router MCP and secret regressions

cleanup: remove legacy custom widget implementations

若某一步實際需要拆得更細可以拆，但不得把全部 migration 壓成單一無法 review 的 commit。

Coding Agent Start Checklist

開始修改前必須：

讀根目錄 AGENTS.md。

讀 TESTING.md。

讀本 spec。

讀 docs/superpowers/specs/2026-08-04-pilot-edit-mcp-semantic-tui-design.md。

重新搜尋所有 Bubble Tea/Bubbles v1 imports。

重新搜尋所有 selectModel / multiSelectModel / textInputModel / confirmModel assertions。

重新搜尋所有 automationScreenID / stable item ID 使用點。

重新搜尋所有 .View() 直接當 string 使用的地方。

重新讀當下 upstream Bubble Tea v2/Huh v2 upgrade notes；本 spec 不取代 upstream API documentation。

若 main branch 已在本 spec 之後演進，coding agent 必須以「Core Invariants + Acceptance Criteria」為 source of truth，調整 file-level plan；不得硬套已過期檔名。

Definition of Done

本工作只有在「Huh-backed human path」與「semantic automation path」實際匯合到同一個 Bubble Tea v2 router model 時才算完成。

最終必須是：

Human keyboard ───────────────┐
                              ▼
                     Pilot UI Adapter
                              │
                              ▼
                       Pilot Router
                              │
                              ▼
                  Existing mutation callback

Semantic action
    │
    ▼
automationDriver
    │ canonical Pilot keys
    └─────────────────────────► same Pilot UI Adapter

若 human path 使用 Huh，但 automation path 改成直接 mutation/accessor assignment，則視為 migration 失敗，即使所有 YAML 最終結果看似正確。
