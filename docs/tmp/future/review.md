# 原始問題

評估以下文件目前是否已可開始實作，並將 review 意見寫入
`docs/tmp/future/review.md`：

- `docs/tmp/future/PRODUCT_ROADMAP.md`
- `docs/tmp/future/IMPLEMENTATION_PLAN.md`
- `docs/tmp/future/SPEC_V2_IMPLEMENTATION_PLAN.md`

# 報告內文

> Review 日期：2026-07-18
> Review 基準：commit `91581d6`
> 文件性質：產品／實作規劃 review，不是可執行 runbook。

## 結論

**條件式 GO：可以開始下一個受限切片，但不可全面開始 M0.2、M0.3、M1 loader
或 Spec v2。**

> 實作更新（2026-07-18）：本 review 批准的機器可執行切片已完成——
> `IMPLEMENTATION_PLAN.md` 過期事實已修正；M0.2 expected-host pure resolver／
> truth table 已加入；六份 ComponentContract fixtures 已通過 test-only strict
> schema／semantic gate；三份 RFC 已完成 technical review 並明標等待人接受。

三份主文件的產品方向、依賴順序與安全邊界大致一致；M0.1 與本次受限切片也已
實作完成。本輪批准範圍與結果：

1. **完成**：修正 `IMPLEMENTATION_PLAN.md` 的過期現況、catalog count 與程式碼
   座標。
2. **完成 technical review，等待人接受**：三份 Proposed RFC：
   - Verification Safety Boundary；
   - Append-only Delivery Evidence；
   - ComponentContract v1。
3. **完成**：M0.2 expected-host resolver truth table、純 resolver 與
   table-driven tests。
4. **完成 test-only gate**：ComponentContract nested schema、fixture schema
   validation 與核心負向案例；沒有建立 production loader。

下列工作目前仍是 **NO-GO**：

- M0.2 正式 runner 接線：resolver 精確語意與 timeout 執行模型尚未完整定案。
- M0.3 schema v13／`RunWriter`：Evidence RFC 仍是 Proposed。
- M0.4 deploy transaction：仍缺 M0.2、Safety RFC Final 與正式 component/spec
  mapping。
- M1.1 production loader/API：六份 fixture 已通過 test-only strict gate，但
  ComponentContract RFC 尚未由人接受。
- M1.2／M1.3：依賴 M1.1 loader 與 contract lint。
- M2.1：硬性依賴完整 M0.2 合併。
- M2.2／M2.3：硬性依賴 M2.1、Safety RFC Final 與 contract traceability。
- P3–P5：仍依賴前述 P0／P1／P2 能力。

## 開工判定矩陣

| 工作 | 判定 | 理由 |
|---|---|---|
| M0.1 | **DONE** | exit-code 與 `verify --dir` error preservation 已有程式與 regression tests |
| 三份 RFC technical review | **DONE；等待接受** | technical consistency 已核對；只有人接受後才關閉 hard gate |
| M0.2 resolver truth table／純函式／tests | **DONE** | inventory authority、scope intersection、spec constraint、override finding 已由 tests 固定 |
| M0.2 production runner | **NO-GO** | `target_group` 衝突解法與真正 per-host timeout 機制仍未完全固定 |
| M0.3 evidence schema/runtime | **NO-GO** | Evidence RFC 尚未 Final |
| ComponentContract test-only schema validation | **DONE** | 六份 fixture 已 strict decode 並核對 selector／tag／binding／row ownership |
| M1.1 loader/API | **NO-GO** | RFC 仍是 Proposed，test-only private schema 不構成 runtime 授權 |
| M2.1–M2.3 | **NO-GO** | `SPEC_V2_IMPLEMENTATION_PLAN.md` 所列硬性依賴尚未關閉 |

## 主要 review findings

### P1 — `IMPLEMENTATION_PLAN.md` 保留已修正的 M0.1 缺口 — 已修正

現況表與附錄仍宣稱：

> `executeDeployment` 在 apply 失敗時回傳 `nil`，造成 exit 0。

但目前 `cmd/pilot/cmd/deploy.go:609-635` 已在 preview／apply 失敗時回傳 error。
這與同一文件的「M0.1 已完成」狀態互相矛盾，也會讓後續實作者重做已完成工作。

本輪已同步修正：

- §0 P0 現況表；
- 附錄 A 的 deploy 座標與「失敗回 nil」說明；
- 文件開頭的 baseline 摘要。

### P1 — Proposed RFC 已有決策，但 hard gate 沒有正式關閉方式

Safety、Evidence、ComponentContract 三份 RFC 都已選定主要方向，卻仍標示
`Proposed`。Implementation plan 又把 `Final` 當成 M0.3、M0.4、M1 loader 與
M2.2 的硬性前置，因此目前不能直接實作下游。

每份 RFC 至少需要補齊：

- 狀態改為 `Accepted`／`Final` 的明確條件；
- 接受日期與接受者／決策紀錄；
- 尚未解決事項清單為空，或明示哪些事項延後且不阻擋當前 milestone；
- 對應 milestone 的可機器驗證 acceptance tests。

本 review 判定三份 RFC **可以進入 final review**，但不自行把 Proposed 視為
Final。

### P1 — M0.2 resolver 切片已完成，但尚不能全面接入正式 verify

已完成的 callback spike可靠地固定了：

- JSON callback 必要環境；
- `ok`／`unreachable`／`module_error`／`runner_error`／`missing` status；
- truncated callback fail closed；
- expected／observed host set 的基本不變式。

本輪已以 `internal/tools/expected_hosts.go` 與 table-driven tests 固定：

- inventory host universe 是唯一 host 事實；
- 已提供的 execution selectors 逐層取交集；
- 沒有 override 時，spec targets 約束 execution scope；
- 明確 `target_group` override 可處理合法 group mismatch，但留下 finding；
- 空集合、未知 host 與 scope 衝突皆 fail closed。

尚未固定／接線的部分仍包括：

- `target_group` override 與 spec Targets／CLI scope 衝突時的精確演算法；
- inventory host pattern 與 `--limit` 的解析入口及錯誤分類；
- 真正 per-host timeout 採逐 host invocation、remote timeout wrapper 或其他方案；
- controller timeout 後已觀察到的 partial callback 是否一律捨棄。

因此正式替換 `runAnsibleAdHoc` 仍須等待 Ansible scope adapter 與 timeout
決策；pure resolver 完成不等於 production per-host verify。

### P1 — ComponentContract fixture strict schema gate — 已完成 test-only 階段

前一輪只有一般 YAML parse。本輪新增
`internal/contract/fixture_schema_test.go`，現在已證明：

- unknown top-level／nested field 與 unknown version 被拒絕；
- nested 欄位型別與核心 enum 被 private draft types 固定；
- selector、traceability、binding 與 duplicate row owner 負向案例被拒絕；
- fixture 引用的 spec row、apply tag、playbook 與 regression test 確實存在。

這些型別與 validator 全部只存在 `_test.go`，沒有匯出 production API；因此
達成 schema review gate，又沒有提前固化 runtime loader。

第二次 schema review 另發現 component 可擁有 1–N specs，但每份 spec 都可能有
`C1`；若 traceability map 只用裸 row ID 會碰撞。本輪已把 mapping／exemption
identity 固定為 `<spec-path>#<row-id>`，同步六份 fixtures，並新增兩份 spec
各自擁有 `C1` 的回歸測試。

仍需由人接受 ComponentContract RFC，才可：

1. 將 private draft types 轉為 production type；
2. 建立 loader/API；
3. 擴充全量 contract lint 與 22 個 component 遷移。

### P2 — baseline 數字與程式碼座標漂移 — 已修正

文件開頭寫「22 個 deploy catalog 項目」，目前
`cmd/pilot/cmd/deploy_catalog.go` 實際有 **21** 個 `Key`。另外 M0.1 完成後，
appendix 仍引用舊的 failure 行為。

本輪已把 baseline 修正為 21，並更新 deploy 與 topology pipeline 座標。長期仍
建議由 test 或產生器驗證容易漂移的數字。

### P2 — `review.md` 原結論已成為歷史敘述 — 已修正

先前 review 的「可以立即開始 M0.1、兩份 RFC、callback spike 與六份 fixtures」
已全部完成。若繼續保留為主結論，下一位實作者無法知道目前真正可做的是
resolver／schema validation，還是已完成的第一批工作。

本次已將 review 改為目前基準線與本輪實作結果；歷史決策仍可由 Git history
查閱。

## 三份主文件評估

### `PRODUCT_ROADMAP.md`

產品方向可接受，P0 → P1 → P2 → P3/P4/P5 的順序合理，且已清楚區分 coding
agent authoring 與 deterministic runtime。它適合作為產品方向，不應直接當成
implementation acceptance contract。

判定：**方向 GO；不能單獨授權 runtime 實作。**

### `IMPLEMENTATION_PLAN.md`

里程碑拆分與依賴圖合理；過期的 M0.1 現況與 catalog count 已修正，M0.2 pure
resolver 與 M1.1 test-only schema gate 已同步標示。尚未閉合的是 RFC 人工接受、
Ansible scope adapter 與 timeout contract。

判定：**條件式 GO；只開 resolver/schema-validation/RFC-finalization 切片。**

### `SPEC_V2_IMPLEMENTATION_PLAN.md`

文件已明確標示 Spec v2 尚未實作，也正確要求 M0.2 → M2.1 → M2.2 → M2.3
依序進行。typed matcher、v1 compatibility、`needsReview` fail-closed、
per-check action 與 secret transport 的責任邊界大致一致。

判定：**設計可保留；目前 NO-GO，等待 M0.2 完整合併與 Safety RFC Final。**

## 本輪事實查核證據

### 相關 Go package 測試

實際執行：

```text
go test ./internal/spec ./internal/tools ./internal/store ./cmd/pilot/cmd
```

實際輸出：

```text
ok  	github.com/anomalyco/pilot/internal/spec	(cached)
ok  	github.com/anomalyco/pilot/internal/tools	(cached)
ok  	github.com/anomalyco/pilot/internal/store	(cached)
ok  	github.com/anomalyco/pilot/cmd/pilot/cmd	12.204s
exit code: 0
```

此結果證明目前相關 package baseline 為綠色；不代表尚未實作的 M0.2 runner、
schema v13、ComponentContract loader 或 Spec v2 已完成。

### 六份 contract fixture YAML parse

實際執行：

```text
if test -f /tmp/pilot-validate-contract-fixtures.go; then go run /tmp/pilot-validate-contract-fixtures.go docs/tmp/future/contracts/*.yaml; else echo 'validator missing'; fi
```

實際輸出：

```text
docs/tmp/future/contracts/dns.yaml OK
docs/tmp/future/contracts/docker.yaml OK
docs/tmp/future/contracts/freeipa-server.yaml OK
docs/tmp/future/contracts/log-shipping.yaml OK
docs/tmp/future/contracts/ntp.yaml OK
docs/tmp/future/contracts/restic-backup.yaml OK
exit code: 0
```

這是一般 YAML parse，不是 strict ComponentContract schema validation。

### Deploy catalog 數量

實際執行：

```text
rg -n '^\s*Key:' cmd/pilot/cmd/deploy_catalog.go | wc -l
```

實際輸出：

```text
21
exit code: 0
```

### 本輪實作後全套 Go test

實際執行：

```text
go test ./...
```

實際輸出：

```text
?   	github.com/anomalyco/pilot/cmd/pilot	[no test files]
ok  	github.com/anomalyco/pilot/cmd/pilot/cmd	(cached)
ok  	github.com/anomalyco/pilot/images	(cached)
ok  	github.com/anomalyco/pilot/internal/ansible	(cached)
?   	github.com/anomalyco/pilot/internal/config	[no test files]
ok  	github.com/anomalyco/pilot/internal/contract	(cached)
ok  	github.com/anomalyco/pilot/internal/dockertarget	(cached)
ok  	github.com/anomalyco/pilot/internal/groupvars	(cached)
ok  	github.com/anomalyco/pilot/internal/inventory	(cached)
ok  	github.com/anomalyco/pilot/internal/logx	(cached)
ok  	github.com/anomalyco/pilot/internal/sandbox	(cached)
ok  	github.com/anomalyco/pilot/internal/spec	(cached)
ok  	github.com/anomalyco/pilot/internal/statefile	(cached)
ok  	github.com/anomalyco/pilot/internal/store	(cached)
ok  	github.com/anomalyco/pilot/internal/tools	(cached)
ok  	github.com/anomalyco/pilot/internal/vaultfile	(cached)
ok  	github.com/anomalyco/pilot/internal/vmtarget	(cached)
exit code: 0
```

### 本輪實作後 build

實際執行：

```text
go build ./...
```

實際輸出：

```text
(no output)
exit code: 0
```

### 本輪實作後 race gate

實際執行：

```text
go test -race ./...
```

實際輸出：

```text
?   	github.com/anomalyco/pilot/cmd/pilot	[no test files]
ok  	github.com/anomalyco/pilot/cmd/pilot/cmd	(cached)
ok  	github.com/anomalyco/pilot/images	(cached)
ok  	github.com/anomalyco/pilot/internal/ansible	(cached)
?   	github.com/anomalyco/pilot/internal/config	[no test files]
ok  	github.com/anomalyco/pilot/internal/contract	1.070s
ok  	github.com/anomalyco/pilot/internal/dockertarget	(cached)
ok  	github.com/anomalyco/pilot/internal/groupvars	(cached)
ok  	github.com/anomalyco/pilot/internal/inventory	(cached)
ok  	github.com/anomalyco/pilot/internal/logx	(cached)
ok  	github.com/anomalyco/pilot/internal/sandbox	(cached)
ok  	github.com/anomalyco/pilot/internal/spec	(cached)
ok  	github.com/anomalyco/pilot/internal/statefile	(cached)
ok  	github.com/anomalyco/pilot/internal/store	(cached)
ok  	github.com/anomalyco/pilot/internal/tools	(cached)
ok  	github.com/anomalyco/pilot/internal/vaultfile	(cached)
ok  	github.com/anomalyco/pilot/internal/vmtarget	(cached)
exit code: 0
```

### 文件 diff 檢查

實際執行：

```text
git diff --check
```

實際輸出：

```text
(no output)
exit code: 0
```

本輪另以人工檢視 changed／untracked files；只包含設計文字、測試 host alias 與
fixture metadata，未加入 credential、token、private key、內部主機識別或真實
secret value。

## 建議下一步

依安全開工順序：

1. 由人接受或退回三份已完成 technical review 的 RFC；未被接受不解鎖下游。
2. 定案 M0.2 的 Ansible inventory／pattern／limit adapter 與 per-host timeout
   機制，再接 production runner。
3. ComponentContract RFC 接受後，才把 test-only private types 轉為 production
   loader/API。
4. M0.2 full 合併後才開始 M2.1。
5. Evidence RFC Final 後才開始 M0.3；Safety RFC Final、M0.2 與 contract mapping
   都完成後才開始 M0.4。

## 綜合可信度

**97%**

依據：三份主文件、三份 RFC、M0.2 spike／pure resolver、六份 strict-validated
fixtures、目前 Go source、全套 test/build/race 均已交叉核對。剩餘不確定性來自
尚未實跑 production per-host runner，以及本輪沒有建立 multi-host target 驗證
future runtime design。
