# 原始問題

評估以下文件是否已可開始實作，並將 review 意見寫入
`docs/tmp/future/review.md`：

- `docs/tmp/future/PRODUCT_ROADMAP.md`
- `docs/tmp/future/IMPLEMENTATION_PLAN.md`
- `docs/tmp/future/SPEC_V2_IMPLEMENTATION_PLAN.md`

# 報告內文

## 結論

**條件式 GO：第一批工作可以開始，但整份計畫仍不能全面開工。**

可以立即開始：

1. M0.1 exit-code 修正與回歸測試。
2. Verification safety boundary RFC。
3. Append-only delivery evidence data model RFC。
4. M0.2 JSON callback／timeout attribution／expected-host resolver spike。
5. M1.1 ComponentContract RFC 與六份試點 fixtures。

仍須暫緩：

- M0.2 全面重寫：等待 spike 固化 timeout、callback 與 host resolver 契約。
- M0.3 schema v13：等待 evidence RFC 定稿。
- M0.4 deploy transaction：等待 safety RFC、M0.2 與 component/spec mapping。
- M1.1 loader、M1.2、M1.3：等待六份試點與 row traceability 契約定稿。
- M2.1：等待 M0.2 合併。
- M2.2、M2.3：等待 M2.1、safety RFC 與 ComponentContract traceability。

修訂 5 已修正上一輪唯一的直接文案矛盾：試點 contract 現在一致定為
docker、freeipa-server、restic-backup、dns、ntp、log-shipping 六份。

整體準備度評估為 **93%**。目前文件足以安全啟動第一批切片；剩餘問題集中在
尚未定稿的 RFC，以及三個會影響 M0.3／M1.1 loader／M1.2 的下游契約細節。

> 實作更新（2026-07-18）：第一批工作已開始。M0.1 已完成；兩份 hard-gate RFC
> 已建立為 Proposed；M0.2 callback spike 與 decoder tests 已完成；M1.1 RFC
> 與六份 fixtures 已建立。下列「剩餘問題」保留開工前的查核脈絡，處理結果以
> 各小節標示與最新 RFC／IMPLEMENTATION_PLAN 為準。

## 事實查核總結

### 修訂 5 查核

`IMPLEMENTATION_PLAN.md` 已在所有相關位置統一：

- component ↔ role 維持 1—1；
- dns 與 ntp 是兩份 component contract，共用
  `core-infra-provider-apply.yml`；
- M1.1 試點清單是六份；
- M1.2 前置是六份試點通過 contract lint；
- §9 開工順序與「可開始 vs 暫緩」也引用同一組六份試點。

沒有再找到把目前 gate 寫成三份或五份的殘留文字。

### Codebase 事實

計畫引用的主要現況仍與程式碼一致：

- `internal/store/sqlite.go` 的 schema version 是 12。
- `spec_checkpoints` 使用 `UNIQUE(spec_path, row_id)` 與 upsert，保存的是最新狀態，
  不是 append-only delivery history。
- `cmd/pilot/cmd/deploy.go` 的 preview／apply 失敗回傳 `nil` 缺口已由 M0.1 修正。
- `internal/tools/verify_spec.go` 尚未產生可靠的 per-host result；現行 verify 也仍會
 透過 `stageVerifyEnv` 寫入遠端 `/etc/pilot-verify.env`。
- `playbooks/site.yml` 確實有安全 prelude、preflight、dns／ntp 雙 import、
  site-level tags、動態 `target_group` 與 opt-in 排除等特殊 execution semantics。
- `tag_coverage_test.go` 目前確實存在 `noRowTags` 類型的 playbook-level 豁免，
  不只 row tag 與 verify-only 兩種狀態。

### 本輪測試

實際執行：

```text
go test ./internal/spec ./internal/tools ./internal/store ./cmd/pilot/cmd
```

結果：

```text
ok   github.com/anomalyco/pilot/internal/spec        (cached)
ok   github.com/anomalyco/pilot/internal/tools       (cached)
ok   github.com/anomalyco/pilot/internal/store       (cached)
ok   github.com/anomalyco/pilot/cmd/pilot/cmd        (cached)
```

這只證明目前相關套件的基準線仍為綠色，不代表 RFC、per-host callback、schema v13
或 Spec v2 已完成。

## 上一輪意見處理狀態

### 已關閉

1. M0.2 已把 `runner_error`／`missing` 納入 `ProbeStatus`，並把 timeout 歸因列為
   spike 必答契約。
2. Expected-host resolver 已指定 inventory 與 CLI scope 是執行 host set 的權威，
   並保留 AGENTS.md 的單 host `target_group` override 例外。
3. M0.3 已要求原子 seq allocation、heartbeat join-before-terminal 與
   terminal-after-append 禁止規則。
4. Append-only 已要求 store API／SQLite enforcement 與直接 UPDATE／DELETE 負向測試。
5. `site.yml` 生成範圍已改為 RFC 二選一，並傾向先維持手寫、contract lint-only。
6. Spec v2 的 front-matter、fenced checks、`needsReview` list 與 destructive action
   粒度文字已一致。
7. M1.1 試點 contract 數量已統一為六份。

### 仍是既有 hard gate

`docs/tmp/future/` 已建立：

- `VERIFICATION_SAFETY_BOUNDARY_RFC.md`（Proposed）；
- `APPEND_ONLY_DELIVERY_EVIDENCE_RFC.md`（Proposed）。

RFC 尚未 review/final，因此仍不能宣稱 M0.3、M0.4 或 M2.2 已取得開工條件。

## 開工前問題與處理狀態

### 1. P1 row-level traceability 與 `noRowTags` — 已由 ComponentContract RFC 處理

`PRODUCT_ROADMAP.md` 的 P1 完成定義要求：

> 每份 spec row 都能追到負責實作它的 apply tag，或明確標示為 verify-only。

但 `IMPLEMENTATION_PLAN.md` 與 Spec v2 計畫允許 component-level
`tagMode: noRowTags`；現行 `tag_coverage_test.go` 也有 freeipa identity、
freeipa server、replica、os-patch 等整支 playbook 的 `noRowTags` 豁免。

這代表目前實際存在第三種狀態：

- 有 row tag；
- verify-only；
- 沒有 row tag，但以 feature tag、stage tag或資料驅動 reconciler 的理由豁免。

若只把第三種狀態寫成 `noRowTags` 加一段理由，P1 的「每一 row 可追溯」並未真的
達成；M0.4 的 partial deploy tag → row resolver 也無法從 component-level 豁免
推導選中的 rows。

M1.1 RFC 必須二選一：

1. 強化 contract，為 `noRowTags` 元件提供機器可辨識的 row → feature/stage tag
   mapping；或
2. 修改 P1 完成定義，明確允許具理由的 component-level exemption，並規定
   partial deploy 對這類元件必須要求 `--verify-rows` 或 fail closed。

這不阻擋六份 fixtures 開始撰寫，但會阻擋 M1.1 loader、M1.2 tag map 退役與
M0.4 partial scope 完整接線。

處理結果：ComponentContract RFC 採方案 1，以 `traceability.mode: mapped`
逐 row 對應 feature/stage tags；新 schema 不保留 component-level `noRowTags`。

### 2. M1.2「新增元件只需」漏列 regression test — 已修正文案

M1.1 schema 已有 `regressionTests`，產品 roadmap 的 Delivery Bundle 也包含
regression test；AGENTS.md §3 更明確要求新增 spec 必須同步新增 regression test。

但 M1.2 驗收目前寫成：

> spec + playbook + contract 一檔 + group_vars example

這會讓完成定義與 repo 硬規則不一致。建議至少改為：

> spec + apply playbook + regression test + contract；需要變數／備份範例時同步
> 更新 group_vars 與 restic backup scope。

「tag map、deploy 選單、DELIVERY 表由 contract 自動衍生」可以保留，但不能把
regression test 從新 component 的交付檔案清單中省略。

處理結果：IMPLEMENTATION_PLAN 的 M1.2 DoD 已補回 regression test，並保留
AGENTS.md §4.2 的條件式 backup scope 更新。

### 3. Append-only DELETE enforcement 與 `pilot runs prune` — 已由 evidence RFC 處理

M0.3 提議以 SQLite trigger 直接拒絕 delivery events／evidence 的 UPDATE／DELETE，
同一節又把 `pilot runs prune --before <t>` 排入 P5。

若採無條件拒絕 DELETE 的 trigger，P5 prune 將無法實作；若 prune 可以繞過 trigger，
append-only 的資料庫層保證又需要定義受信任邊界。

Evidence RFC 應明確選擇：

- 永不從主資料庫刪除，只做 archive／database rotation；
- 受 policy 控制的 prune transaction，先寫 tombstone／audit event 再刪除；
- 或只用封裝 store API 保護一般寫入，不採無條件 DELETE trigger。

同時應定義 prune 對 `delivery_runs` view、`verify_evidence`、孤兒 run 與稽核查詢的
一致性。此問題不阻擋 evidence RFC 開始，但阻擋 schema v13 定稿。

處理結果：evidence RFC 採 database generation rotation；active DB 不做 row
DELETE，`runs prune` 只處理已封存 archive file 並先留下 audit event。

### 4. ComponentContract rollback 欄位名稱殘留 — 已統一

M1.1 schema 已定義 `playbooks: {apply, rollback, upgrade, decommission}`，後文卻寫
`rollbackPlaybook: null`。應統一為 `playbooks.rollback: null`，避免 RFC fixture
與 loader struct 各自採用不同欄位。

這是小型文案問題，不影響第一批 GO 判定。

處理結果：IMPLEMENTATION_PLAN 與 fixtures 已統一使用 `playbooks.rollback`。

## 邏輯與推理評估

整體依賴順序仍然合理：

```text
M0.1
  ├─ safety RFC
  ├─ evidence RFC
  └─ M0.2 spike → M0.2 implementation → M2.1

M1.1 RFC + 6 fixtures → loader → M1.2 → M1.3

M0.2 + evidence RFC → M0.3
M0.2 + safety RFC + component/spec mapping → M0.4
M2.1 + safety RFC + contract traceability → M2.2 → M2.3
```

特別正確的決策包括：

- 先修 false-success exit code，再擴大 deploy transaction。
- M0.2 與 M2.1 串行，避免同時改 verifier execution core。
- 不以有損的 Ansible one-line parsing 寫正式 evidence。
- 在 safety RFC 前不把現行寫入型 verify 自動接入 production deploy。
- 在 site execution projection 未被證明可無損重建前，維持手寫 site 並先做 lint。
- Spec v2 不提前固化 secret transport 與 destructive-action schema。

目前沒有需要推翻 roadmap、ComponentContract 或 Spec v2 整體方向的問題；上述
剩餘事項都可以在已規劃的 RFC／試點階段內閉合。

## 建議開工順序

1. M0.1 exit-code 修正。
2. 並行撰寫 safety RFC 與 evidence RFC；evidence RFC 納入 prune／trigger 決策。
3. M0.2 spike，產出 timeout/status matrix 與 host resolver truth table。
4. M1.1 RFC 與六份 fixtures，先定案 `noRowTags` 的 row traceability／partial-scope
   行為，再寫 loader。
5. 修正 M1.2 DoD，補回 regression test 與 AGENTS.md §4.2 的條件式 backup 更新。
6. 依各 gate 關閉狀態逐項解鎖 M0.2 full、M0.3、M0.4、M1 loader 與 M2。

## 綜合結論與修正建議

**第一批實作已開始並完成原批准切片：M0.1、兩份 Proposed RFC、M0.2 callback
spike，以及 M1.1 RFC／六份 fixtures。**

修訂 5 已讓試點範圍足夠明確。下一步不需要再延後第一批工作；但在進入
ComponentContract loader／M1.2 前必須閉合 `noRowTags` traceability 與 regression
test DoD，在 schema v13 前必須由 evidence RFC 閉合 prune 與 DELETE enforcement。

## 可信度

**98%**

依據：三份文件的最新修訂、相關程式碼座標、現行 tag 豁免與 future 目錄內容均已
核對；M0.2 callback shape 已實跑，Go test/build/race gate 亦已通過。剩餘不確定性
來自 RFC 尚未 review/final，以及 expected-host resolver 尚未接入正式 verify。
