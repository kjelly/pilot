# pilot 產品路線圖實作計畫

> 依據:`docs/tmp/future/PRODUCT_ROADMAP.md`(2026-07-18)
> 基準線:codebase 現況調查(見附錄 A),schema v12、21 個 deploy catalog 項目、24 份 verification spec。
> 修訂:2026-07-18 依 `docs/tmp/future/review.md` 審查修正——exit-code 契約表、verify 唯讀邊界前置 RFC、evidence 改 immutable event stream、M0.4 mapping 前置、contract 邊界決策、開工順序。review 的事實宣稱已逐一對 code 核實(runner 為具體 struct、`stageVerifyEnv` 確實寫遠端 env 檔、`runVerifyMulti` 失敗確實非零退出)。
> 修訂 2:2026-07-18 依 review 第二輪(條件式 GO)修正——json callback 需 `ANSIBLE_LOAD_CALLBACK_PLUGINS=1` + `ansible.posix.json`(已實測重現)、expected host set 對帳、全 sink 共用 redaction pipeline(`--ask-vault-pass` 下 pilot 不知 plaintext)、active-run/唯一性語意、partial deploy verify scope、contract 複數 schema + bindings。
> 修訂 3:2026-07-18 依 review 第三輪(準備度 82%)修正——`--one-line` 降級僅限 diagnostic(正式 evidence fail closed)、event stream 增 `run_heartbeat`、partial deploy 的 tag→row scope resolver 與完整 outcome enum、清理摘要殘留的舊 schema 名稱。**各里程碑的詳細 schema 章節(M0.3、M1.1、SPEC_V2 §3)為唯一 source of truth,其他章節摘要與之出入時以詳細章節為準。**
> 修訂 4:2026-07-18 依 review 第四輪(準備度 88%)修正——M0.2 spike 增 timeout 歸因契約與 `ProbeStatus` `runner_error`/`missing`、expected-host resolver 補來源優先序/集合語意(含 AGENTS.md `target_group` 例外)、M0.3 補 append 併發契約與 append-only enforcement、M1.1 補 site execution projection 決策(傾向 site.yml 先維持手寫 + lint)與試點 fixtures 3→5、M2.2 摘要「front-matter 或 fenced YAML」改為兩者皆需。
> 修訂 5:2026-07-18 依 review 第五輪(準備度 92%)修正——M1.1 試點 contract 清單統一為**六份**:component↔role 1—1 下 core-infra-provider 不是一份 contract,而是 dns、ntp 兩份(共用同一支 apply playbook),清單定為 docker、freeipa-server、restic-backup、dns、ntp、log-shipping;M1.2 前置與 §9 的「三試點」同步修正。其餘三項(兩份 RFC 尚未撰寫、M0.2 全面實作待 spike、M0.3 writer/enforcement 選項交 evidence RFC 定案)為既有 gate 狀態,無需改文。
> 實作進度 1:2026-07-18——M0.1 exit-code 修正與 regression tests 已完成；兩份 hard-gate RFC 已建立為 Proposed；M0.2 callback spike 已以 ansible-core 2.19.2 實跑並加入 decoder fixtures/tests；M1.1 ComponentContract RFC 與六份 YAML fixtures 已建立。Proposed RFC 尚待 review/final，因此 M0.3/M0.4/M2.2 仍未解鎖；M0.2 decoder 也尚未接入正式 verify。
> 實作進度 2:2026-07-18——M0.2 expected-host pure resolver 與 table-driven
> truth table 已加入 `internal/tools/expected_hosts*`；六份 ComponentContract
> fixtures 已由 test-only strict decoder 與 selector／traceability／binding／
> duplicate-owner 負向測試驗證。正式 Ansible scope adapter、per-host runner、
> production contract loader 與 RFC Final 仍未完成。
> 修訂 6:2026-07-18 關閉 production-readiness review——三份 RFC 已 Final；
> M0.2 固定 single-host isolated invocation + bounded workers 與 standalone scope；
> Spec v2 新增 `appliesWhen`/`not_applicable`、canonical action 與 secretRef；
> ComponentContract 固定 role 1:N、dependency placement/provider selection；
> Evidence 固定 idempotency/finalization 並把 rotation 移至 P5。
> 實作進度 3:2026-07-18——M2.2 已完成 strict v2 parser、typed runtime、
> applicability/not_applicable evidence、aggregate scope、CLI/file/env/inventory
> `pilot_inputs` precedence，以及 secretRef/isolatedMutation fail-closed gate。local
> CLI fixture 已實跑 PASS；M2.3 migration CLI 也已可產出 review-gated draft +
> JSON sidecar。同一份 read-only v2 fixture 已在 local、docker-target、
> vm-target 與一般 inventory backend 實跑，四者均為 1/1 PASS；一般 inventory
> 使用 localhost connection fixture，未宣稱已在 staging／真實主機驗證。
> 實作進度 4:2026-07-18——canonical ComponentContract 已補齊 22 個
> component；`pilot contract lint` 會驗證 bundle path、row/tag traceability
> 與 exemption ratchet、dependency DAG/endpoint、apply/deploy catalog coverage。
> `internal/delivery` contract preflight 已實作 cardinality、required input、
> inputRules、sameHosts、provider selection、OS/resource 與 facts-unavailable
> warning；接入 deploy/TUI 仍屬 M0.4/P3 wiring。
>
> 上述修訂 1–5／實作進度 1–2 是決策歷史，包含當時的 Proposed／NO-GO
> 狀態與已被更正的 1—1 假設；目前 gate 只看修訂 6、下方狀態快照與各
> Final RFC。

> **文件狀態：IMPLEMENTATION PLAN — NOT AN EXECUTABLE RUNBOOK**
>
> 本文件中的未來命令、schema 與 API 是設計內容，不是已驗證操作程序。狀態以
> 下表與各里程碑開頭的 status block 為準。
>
> **Production implementation 判定：GO（2026-07-18）**。表示所有架構決策
> blocker 已關閉，可依依賴圖開始實作；不表示所有 milestone 可忽略前置而平行，
> 也不表示尚未寫出的 runtime 已驗證。

### 狀態圖例

- **✅ 已實作並驗證**：正式 code path 已修改，test/build/race gate 通過。
- **🟡 部分已實作**：已有可呼叫的正式 code path，但尚未完成 runtime wiring 或
  該 milestone 的所有 acceptance criteria。
- **🟢 Final design／可開工**：implementation contract 已接受，runtime 仍須實作
  與 actual-run 驗證。
- **🧪 Spike 已驗證**：實驗 code／fixture 有測試，但未接入正式 runtime。
- **📄 Proposed**：設計文件已建立；即使 technical review 完成，仍須由人接受／
  final，且不代表已有完整 runtime。
- **⏸ 尚未實作**：不得從計畫文字推論產品已支援。

### 實作狀態快照（2026-07-18）

| 里程碑／產物 | 狀態 | 實作內容 | 明確未實作 |
|---|---|---|---|
| M0.1 | **✅ 已實作並驗證** | deploy exit-code、preflight rejection、`verify --dir` 原始錯誤、regression tests | deploy 後自動 verify/evidence |
| Safety RFC | **🟡 部分已實作** | v2 action gate、secretRef fail-closed、v2-only autoDeploy schema gate | secret-aware module、deploy authorization wiring |
| Evidence RFC | **✅ 已實作並驗證** | schema v13、RunWriter、heartbeat/finalization、standalone verify evidence；rotation 移 P5 | deploy transaction usage（M0.4） |
| M0.2 | **✅ 已實作並驗證** | JSON decoder、status、expected-host resolver、Ansible scope adapter、single-host bounded runner | deploy transaction wiring（M0.4） |
| M1.1/M1.2 | **✅ 已實作並驗證** | strict loader/Catalog、22 份 canonical contracts、bundle/traceability/dependency/endpoint/apply/deploy catalog lint | DELIVERY table 改為生成 view |
| M0.3 | **✅ 已實作並驗證** | schema v13、append-only event/evidence stream、serialized RunWriter、heartbeat/finalization、standalone verify evidence | deploy transaction 對 writer 的使用（M0.4） |
| M0.4 | **⏸ 尚未實作** | 無 | deploy transaction、rollback/idempotency policy |
| M1.3 | **🟡 preflight engine 已實作** | cardinality、required inputs、inputRules、sameHosts、provider selection、OS/resource/facts warning | 接入 deploy/TUI inventory resolver |
| M2.1 | **✅ 已實作並驗證** | typed `Expect`、v1 Expected compiler、legacy output compatibility evaluator | migration |
| M2.2 | **✅ 已實作並驗證** | strict v2 parser、typed execution、applicability/action/secretRef boundary、input precedence；local/docker/vm/general-inventory backend 同一 fixture 均 PASS | staging／真實主機 acceptance、migration |
| M2.3 | **🟡 部分已實作** | `pilot spec migrate`、v1 prose preservation、needsReview/sidecar/非零 fail-closed | template/document migration、正式 spec target-test |
| P3/P4/P5 | **⏸ 尚未實作** | 無 | TUI/eval/query |

## 0. 現況與差距總覽

| 支柱 | 現況 | 關鍵差距 |
|---|---|---|
| P0 交付交易 | 交易鏈(syntax→snapshot→apply→verify→idempotency→rollback)**已存在但只在 `vm-target test` / `topology test`**(`vm_target.go:1488`、`vm_target_topology.go:677`);`pilot deploy` 只有 preflight+preview+stage gate+apply，M0.1 已使 preview/apply/preflight failure 正確回傳非零 | deploy 後不跑 verify；無 run ID；不寫 evidence；無 rollback policy |
| P1 ComponentContract | 元件事實分散在 `deployCatalog`(deploy_catalog.go:39)、`roleContracts`(inventory/contracts.go:17)、`specTagMap`(tag_coverage_test.go:50)、group_vars example、DELIVERY.md 五處 | 無單一可 lint 資料模型;cardinality、依賴、必要 vault key、stage policy 都不是結構化資料 |
| P2 Spec v2 | matcher 是魔法前綴(verify_spec.go:321:`^`=regex、`~`=substring、整數=rc、`present`);parser 單版本,`版本:` 欄位只是資訊 | 無 typed matcher、無版本化 parser、無 v1→v2 遷移工具 |
| P3 Contract TUI | deploy 選單來自 `deployCatalog` label;host 靠自由輸入 `target_group`/`--limit` | 選單、依賴提示、host 選擇未由 contract 驅動 |
| P4 authoring eval | 無 | 需先有 P1 lint 與 P0 deterministic gate 才有可量測的東西 |
| P5 evidence | 只有一張 **upsert**(非 append-only)的 `spec_checkpoints` 表(sqlite.go:29,`UNIQUE(spec_path,row_id)`);verify 輸出 NDJSON 檔在 `.verification/` | 無 deployment run 紀錄、無 host×row evidence 表、無查詢面 |

另一個橫切差距(P0 與 P2 都踩到):**verify 結果不是 per-host**。`runAnsibleAdHoc`(verify_spec.go:192)對 `all` 跑 ad-hoc 後把整個 process 的輸出壓成單一 `VerifyRow`;`VerifyRow.Host` 欄位存在但從未填。這必須最先修,否則 P0 的「host × row 判定」與 P5 的 evidence 粒度都是空談。

## 1. 執行順序與里程碑

原則:每個里程碑都可獨立合併、有回歸測試、不破壞現有 CLI 行為(必要時以 flag 過渡)。P0 拆四個里程碑,P1 拆三個,P2 拆三個;P3/P4/P5 各為一~二個。

```text
M0.1 exit-code 修正 ──► M0.2 per-host verify ──► M0.3 run ID + evidence 寫入 ──► M0.4 deploy 交易閉環
                                                        │
M1.1 contract schema ──► M1.2 lint 收斂五處事實 ──► M1.3 deploy/DAG 接上 contract
                                                        │
M2.1 typed matcher(v1 內部重構)──► M2.2 v2 parser 並存 ──► M2.3 遷移工具 + lint
                                                        │
M3.1 contract-driven TUI          M5.1 evidence query    M4.1 brief corpus + eval gate
```

依賴關係:M0.3 需要 M0.2 的 per-host 結果;M0.4 需要 M0.2、M0.3、
M1.1 production mapping 與 **M2.2 v2 applicability/action runtime**；M1.3 需要
M1.1/M1.2；M2.1 必須排在 M0.2 之後；M2.2 引用 M1.1 component ID；M3.1 需要
M1.3；M5.1 需要 M0.3；M4.1 需要 M1.2 與 M0.4。

三份 RFC 均已 Final，architecture gate 已關閉。里程碑間的 code dependency 仍
照圖執行；「可全面開始」是整份計畫可進入 production implementation，不是把
相依的 verifier/store/parser 改動同時寫進同一 branch。

---

## 2. P0:可信任的交付交易

### M0.1 — 失敗必須非零退出(最小、最急)

**狀態：已完成（2026-07-18）**。preview/apply 非零、外部 binary 啟動失敗與
preflight failure 後拒絕繼續都回傳 error；乾淨取消維持 exit 0；`verify --dir`
保留造成 no-report 的原始 per-spec error。回歸測試見
`deploy_exitcode_regression_test.go`、`verify_dir_rollup_regression_test.go`。

**exit-code 契約(先定案再動手,消除「取消 vs 失敗」的語意矛盾)**

| 情境 | exit code |
|---|---|
| 使用者在任何提問主動取消(尚無失敗發生) | 0 |
| preflight 失敗、使用者選擇不繼續 | 非零(這是「拒絕在失敗後繼續」,不是取消) |
| preflight 失敗、使用者明確選擇繼續、後續全過 | 0(人已接受風險,此授權記入 evidence) |
| preview(`--check`)或 apply 非零 | 非零 |
| verify 任一 host×row 失敗(M0.4 起) | 非零 |
| 外部程式無法啟動(ansible-playbook 缺失等) | 非零,fail closed |

**改動**
- `cmd/pilot/cmd/deploy.go`:`executeDeployment`(:572)在 preview 或 apply 非零時回傳 error(保留現有「❌ 套用失敗」訊息);依上表盤點 `abortOrErr`(:133)所有呼叫點。
- `verify --dir`(`runVerifyMulti`,verify.go:332)**現況更正**(review 指正):它已依報告重建的失敗列回傳非零,不是「失敗卻 exit 0」。實際缺口是 `_ = runVerifyOne(...)` 丟棄 per-spec 即時 error(parse 失敗、ansible 起不來),之後只剩「no report produced」看不出原因——修正為保留並回報每份 spec 的原始失敗原因,不重做已正確的 aggregate exit code。

**測試 seam(現況更正:`internal/ansible.Runner` 是具體 struct,不是可注入 interface)**
- 二選一,不做大重構:deploy 側定義最小 interface(`*ansible.Runner` 自然滿足)注入假 runner;或用假 ansible binary fixture(PATH 注入)實跑。

**驗收 / 測試**
- 新增 `deploy_exitcode_regression_test.go`:對契約表每一列一個案例(模擬 apply rc=2、binary 缺失、user-cancel、preflight-拒絕繼續)。
- `verify --dir` 對「spec parse 失敗」「ansible 無法啟動」各一案例:原始錯誤出現在輸出、exit 非零。

**規模**:小(1-2 天)。這是 roadmap「最先三件事」#1 的前半。

### M0.2 — per-host verify

**Spike 已驗證／production design Final（2026-07-18）**。實跑與資料契約見
`docs/tmp/future/M0_2_PER_HOST_VERIFY_SPIKE.md`；decoder、fixtures 與測試位於
`internal/tools/ansible_callback_spike*`；expected-host 的純集合 resolver 與
table-driven truth table 位於 `internal/tools/expected_hosts*`。Ansible
inventory／pattern／limit adapter、bounded per-host runner 尚未接入正式 verify，
但 design gate 已關閉，可開始 production implementation。

**前置 spike(review 建議 #3:先驗證資料契約,不直接全面重寫)**
- **callback 環境變數已實測定案**(2026-07-18,ansible-core 2.19.2):ad-hoc CLI 只設 `ANSIBLE_STDOUT_CALLBACK=json` **不生效**(輸出仍是 one-line);必須同時 `ANSIBLE_LOAD_CALLBACK_PLUGINS=1` + `ANSIBLE_STDOUT_CALLBACK=ansible.posix.json` 才有含 `hosts.<name>.stdout/stderr/rc` 的 JSON。`ansible.posix` collection 列為 per-host verify 的**必要 preflight,缺席即 fail closed**——不做 `--one-line` fallback 寫正式 evidence(review 第三輪 #1:one-line 逐行解析是有損的——多行 stdout/stderr、probe 輸出撞 marker、timeout/unreachable 欄位形態不穩定,無法證明 host×row evidence 與原始執行結果等價)。`--one-line` 僅保留為 **diagnostic degraded mode**:報告明標降級、不寫入 delivery evidence、不得讓 deploy transaction 判定成功。若 preflight 依賴負擔過高,備案是在 repo 內提供受測且版本化的 callback plugin(spike 一併評估兩案)。
- 以兩台主機實測:一台正常、一台故意 fail,再各補 unreachable 與 timeout 一輪,確認 per-host 欄位形態與邊角(msg-only 失敗、module_stderr 等)。
- **timeout 執行模型已定案**：每個 host × row 是獨立 single-host Ansible
  invocation，以最多 8 個 bounded workers 平行。該 invocation 的 controller
  timeout 可歸因唯一 host，記 `timeout`；啟動失敗／callback 不完整記
  `runner_error`；完整 callback 缺 host 記 `missing`。outer cancel 才取消整列，
  未完成 host 記 `runner_error: parent_cancelled`，不把其他 host 誤標 timeout。
- spike 產出:鎖定 `ProbeResult{Stdout, Stderr string; ExitCode int; Status: ok|timeout|unreachable|module_error|runner_error|missing}`(後兩者依 #1 增補:`runner_error` = invocation 層失敗/callback 不完整,`missing` = host 未出現於 callback 且原因未明)與正規化規則——這也是 Spec v2 typed matcher 的輸入契約(見 SPEC_V2 計畫 §3.3)。

**改動**
- `internal/tools/verify_spec.go`:`runAnsibleAdHoc`(:192)改用 json callback 的結構化 per-host 結果,不再解析壓扁的 combined output。
- 每個 spec row 產生 N 筆 `VerifyRow`(每 host 一筆),填入既有的 `Host` 欄位,外加 `Stdout`、`Stderr`、`ExitCode`、`MatcherVerdict`、`StartedAt/FinishedAt`。
- matcher(`matchExpected` :321)逐 host 判定;row verdict = 所有 host 皆 pass。
- **expected host set 對帳**(review 第二輪 #2:callback 只回報「有回應的 host」,證明不了沒漏):跑 probe 前由**單一權威函式**解出 expected host set——輸入為實際 inventory + spec Targets 表 + CLI `--host`/host pattern + `--limit` + stage/target selection(這幾個來源今天並不一致,此函式即統一點)。
  - **來源優先序與集合語意**(review 第四輪 #2:只列來源不定關係,resolver 實作時會亂選):**實際 inventory + CLI host pattern/`--limit` 是執行 host set 的權威來源**;spec Targets 表是 acceptance scope constraint 與 lint 對齊來源——不得憑文字加入 inventory 不存在的 host,也**不與權威來源直接取交集**。AGENTS.md 明列的例外是關鍵反例:單一 host + `target_group` 型 spec 的宣告 group 可以刻意 ≠ vm-target inventory group(靠 `-e target_group=all`/CLI scope 對齊),交集語意會解出空集合、把合法測試誤判 FAIL。`target_group` override 如何替代或驗證 spec 宣告 group 由 resolver 契約明定;每一種衝突輸出具體 finding,不靜默取其中一邊。
  - **pure resolver 已完成**：inventory host universe 為權威；已明確提供的
    execution selectors 依序取交集；spec target 在沒有 override 時約束 execution
    scope；明確 `target_group` override 可替代不相等／不存在的 spec group，但
    必須留下 finding；任何 selector 空集合、未知 host 或 scope 衝突皆 fail closed。
    尚待 adapter 把 Ansible inventory、host pattern、`--limit` 與 stage/component
    selection 解析成此 pure input。
  - **standalone default 已定案**：有 spec Targets 且沒有 selector時直接以
    resolved spec target hosts 為 scope；無 Targets 的 remote verify 必須明確
    `--host`／`--limit`，或使用 `--local`，不再隱式遠端 `all`。deploy mode 永遠
    由 component plan 提供 scope。
  - 再與 callback observed set 做集合比對:
  - expected 為空 → 整份 spec FAIL(不是 skip)。
  - expected − observed 非空 → 每個遺漏 host 各產生一筆 FAIL evidence。
  - observed − expected 非空 → runner/inventory contract error(fail closed,不靜默收下)。
  - `unreachable` → 該 host FAIL 並保留 ansible 錯誤原文。
- 報告(`renderVerifyReport` :257)與 NDJSON 升級為 host×row 粒度;`.md` 報告 row 層彙總、host 明細展開。

**驗收 / 測試**
- docker-target 起 2 容器同 group,spec 一列在 A 過 B 掛,斷言:整體 FAIL、報告含兩台各自的 stdout/rc、exit code 非零。
- 既有 24 份 spec 在單 host 情境輸出不回歸(golden 檔更新一次)。

**規模**:中(4-6 天，含 adapter、bounded runner、deterministic ordering 與
regression tests)。roadmap P0 必要能力第 4 點。

### M0.3 — deployment run ID 與 append-only evidence

**RFC 狀態：Final／production implementation GO**，見
`docs/tmp/future/APPEND_ONLY_DELIVERY_EVIDENCE_RFC.md`。RFC 已選定 serialized
RunWriter + SQLite transaction、operation idempotency、trigger enforcement 與
bounded cancel finalization。M0.3 retain-all；generation rotation 移至 P5。

**資料模型定案:immutable event stream**(review 阻塞項 3 要求二選一——原稿「開頭取 ID + 表上有 finished_at/outcome + 不可 UPDATE」自相矛盾,已選定事件流)

**改動**
- `internal/store/sqlite.go`:schema v13(依 v12 教訓,**base schema 與 migration 同步改**):
  - `delivery_events`(唯一可寫的交易表,只 INSERT):event_id、run_id(uuid)、seq、
    operation_id、type、step、payload(json)、exit_code、created_at；
    `UNIQUE(run_id,operation_id)` 讓 uncertain-commit retry 可安全去重。
  - `verify_evidence`(只 INSERT):run_id、spec_path、row_id、host、attempt、
    operation_id、content_hash、command、expected、stdout、stderr、exit_code、
    probe_status、verdict、started_at/finished_at；同 key 重試 hash 相同視為成功，
    hash 不同 fail closed。
  - `delivery_runs` 改為 **SQL VIEW**(由 events 聚合 started/finished/outcome),不是可寫表——**無任何 UPDATE**。
  - **active-run 語意已定案**：heartbeat interval 10s、lease 45s、grace 15s；
    最新 heartbeat 未過期為 running，逾期且無 terminal 為 abandoned。terminal
    前 stop-and-join heartbeat。
  - **唯一性約束**:`UNIQUE(run_id, seq)`;每個 run 至多一筆 terminal event(`type='run_finished'` 的 partial unique index)。
  - **append 併發契約**(review 第四輪 #3:`UNIQUE(run_id, seq)` 只會**偵測**衝突,不會安全**分配**下一個 seq——heartbeat goroutine、主交易 step writer 與 defer 中的 `run_finished` 會並行 append,兩個 writer 可能讀到同一個 `MAX(seq)+1`,或 terminal 後仍有晚到 heartbeat):evidence RFC 定義**單一 append API**——每 run 一個 serialized writer,或 SQLite transaction 內原子配置 seq 並寫入。invariant 一併鎖定:`run_started` 必為 seq 1;terminal event 唯一且必為最後一筆;terminal 後任何 append 拒絕;**heartbeat goroutine 停止並 join 之後才寫 terminal event**(建立 happens-before);heartbeat append 失敗時交易是否繼續與 evidence health 標記。以並行 heartbeat+step+finish 的 `go test -race` regression 鎖住。
  - **append-only enforcement**(review 第四輪 #4:「只 INSERT」若只是 coding convention,不構成資料模型保證;`verify_evidence.run_id` 也無法對 SQL VIEW `delivery_runs` 建一般 FK):RFC 選定**可測**的 enforcement——store 層不暴露任何 update/delete API、所有寫入只走 append transaction,及/或 SQLite trigger 直接拒絕 UPDATE/DELETE;evidence append 前檢查 run 已存在且尚未 terminal(替代 FK);測試直接嘗試 UPDATE/DELETE 舊 event/evidence,必須失敗。
  - **terminal event 保證**:交易主流程以 defer/recover 確保每條 return/cancel/panic 路徑都 INSERT `run_finished`；context cancel 後使用
    `context.WithoutCancel` + 5s timeout 的 finalization context。terminal persist
    失敗則 CLI 非零 evidence_failed；SIGKILL/斷電由 lease 投影 abandoned。
  - **standalone `pilot verify` 同樣寫 `run_started`/`run_finished`**(step 只有 verify)——否則 `verify_evidence.run_id` 在 `delivery_runs` view 查不到。
- **run ID 規則**:deploy 於 `runDeploy` 開頭產生 uuid;standalone `pilot verify` 改用 `verify-<uuid>`(現行秒級 timestamp 可碰撞,棄用);run_id 即去重 key,rerun 一律開新 run,不存在覆寫路徑。
- **redaction / 大小 / retention**（以 Final Safety RFC 為唯一邊界）：
  - matcher 一律在**記憶體中的原始結果**上評估;**所有持久化 sink(SQLite、NDJSON、`.md` 報告、event payload)共用同一個 redaction pipeline**,不存在「DB 有刷、檔案沒刷」的旁路。
  - pilot **永遠不解析或取得 secret plaintext**；只轉交 vault file／password
    mechanism 與 `ansibleVar` reference。secret-aware module 在 Ansible vars
    pipeline 內取得值、以 child stdin 傳遞並在回傳前 redaction。
  - secret-bearing probe 的 stdout/stderr 預設不持久化；evidence 只記
    status、verdict、`redacted` 標記與 secret reference 名稱。安全 module、
    callback leakage 與 fake-recorder 驗收未完成前直接拒跑，不提供弱化旁路。
  - evidence 的 `command` 欄保存原始 probe 與變數 reference,**不保存**展開 secret 後的 materialized shell command。
  - 保留 raw evidence 檔時:改 `0600`(現行 `0644`),授權、加密與 retention 由 evidence RFC 定——不沿用公開可讀的一般 report。
  - stdout/stderr 落庫各截斷至 64 KB 並帶 truncated flag(順序:記憶體判定 → redaction → 截斷 → persist)。
  - M0.3 retention 固定全留；generation rotation／archive/prune 與獨立
    `evidence_admin_events` 排入 P5。
  - transformed secret（base64、截斷、hash）不能靠 exact-string masking 保證；
    以「不持久化 secret-bearing output」與 lint 禁止 secret×stdout-match 作主要
    防線，redaction 只作縱深防禦。
- `spec_checkpoints` 保留為「最新狀態」快取,事實來源改為 evidence 表。

**驗收 / 測試**
- store 層測試:同 run 重複 INSERT 不覆蓋;migration v12→v13 replay 測試(比照 v12 replay-drop 測試模式)。
- 跑兩次 verify,`verify_evidence` 有兩批紀錄、`spec_checkpoints` 只反映最新——斷言前次不被改寫。

**規模**:中偏大(5-8 天，不含 P5 rotation/prune)。roadmap「最先三件事」#2。

### M0.4 — deploy 交易閉環(verify 進 deploy、policy 化 rollback/idempotency)

**前置(implementation dependency；design 均已 Final)**
1. M0.2 per-host runner 與 M0.3 evidence store 已合併。
2. M1.1 production contract mapping 已合併：每 component 恰有一個 target role，
   role 可有多個 components；dependency placement/provider selection 已解析。
3. M2.2 v2 parser/action/applicability 已合併。`verification.autoDeploy: true`
   contract 只可引用 v2；v1 不存在 auto-run fallback。
4. **partial deploy 的 verify scope 契約**:
   - apply scope → verify scope 的 mapping:`--limit`/host pattern 直接餵 M0.2 的 expected host set;`--tags` 部分套用時只驗證 selected rows。
   - **tag→row scope resolver**(review 第三輪 #5:Ansible tag 不只 row tag——單 spec 裸 `C3`、多 role 粗 tag `db` 與細 tag `db-C3`、一 task 多 tag、`always`/`never` 特殊 tag):requested tags + contract `traceability`(rowTags bare/rolePrefixed、mapped;ComponentContract RFC 已以此取代早前的 `tagMode`)+ playbook tag coverage → selected spec rows。**無法無歧義解析時 fail closed**,或要求使用者明確給 `--verify-rows`——不猜測。
   - 先以 tag→row 選 ownership rows，再逐 host 評估 v2 `appliesWhen`；false
     產生 `not_applicable` evidence，不執行 probe且不算 PASS。condition error
     fail closed。
   - outcome enum 完整定義:`success`/`failed`/`partial_success`/
     `partial_failed`/`cancelled`/`rolled_back`/`rollback_failed`/
     `evidence_failed`/`authorization_required`；partial outcome 明示只對 selected
     applicable rows×hosts 成立。
   - idempotency rerun 使用與 apply **完全相同**的 tags/limit/extra-vars。
   - 此契約定案後才抽取 `internal/delivery.Transaction`。

**改動**
- `cmd/pilot/cmd/deploy.go`:apply 成功後自動接 per-host verify；spec 集合來自
  `verification.autoDeploy: true` contract mapping；full-site deploy 對每個非空
  component scope 跑 selected v2 specs 的 applicable rows。
- **apply 成功 + verify 失敗 = 交易失敗**(non-zero),outcome=`verify_failed`。
- 交易步驟機:把 `runVtTest` 的 5 步機(vm_target.go:1488)抽成 `internal/delivery` 套件的 `Transaction`(steps: preflight→preview→apply→verify→idempotency→rollback-on-failure),`deploy`、`vm-target test`、`topology test` 三處共用,行為差異用 policy 表達:
  - `idempotency: always|stage>=staging|never`(第二次 check-mode 或 apply 斷言 changed=0)
  - `rollback: none|snapshot|playbook`——真實主機沒有 VM snapshot,先支援 `none`(預設,只標記 outcome)與 `playbook`(component 宣告 rollback playbook 才可用;無宣告時明說「無自動 rollback」而非假裝有)。
  - verify 邊界依 Final Safety RFC 執行；scalar/缺 action 拒絕，
    isolatedMutation 走 authorization+cleanup；secretRef 走受控 playbook/module。
- 每步 INSERT `delivery_events`;結束 INSERT `run_finished` event(outcome、final_exit_code)。

**驗收 / 測試(P0 完成定義)**
- vm-target 三節點 topology 實跑:故意讓一台 verify 失敗 → deploy 非零、run 查得到那台那列的 stdout/rc。
- 從 run ID 能回答「哪個版本、什麼輸入、哪些主機、哪列成敗」——寫成一個 store 查詢測試。
- `vm-target test` / `topology test` 改用 `internal/delivery` 後既有行為不回歸(既有 topology test 已實跑過 site.yml smoke,重跑一次當驗收)。

**規模**:大(1-2 週)。完成後 P0 收斂。

---

## 3. P1:DeliveryBundle / ComponentContract

### M1.1 — schema 與載入器

**RFC／fixtures 狀態：Final／production loader implementation GO**，見
`docs/tmp/future/COMPONENT_CONTRACT_RFC.md`、canonical `contracts/*.yaml` 與
`docs/tmp/future/contracts/*.yaml` review mirrors。六份 contracts 已通過 test-only strict decode、
selector、traceability、binding、實際 tag 與 duplicate-owner 驗證；測試位於
`internal/contract/fixture_schema_test.go`。`internal/contract/contract.go` 已提供
strict YAML decode、local schema validation、stable directory loading 與 root-path
containment、`LoadDefaultCatalog` 與 role/component lookup；canonical contracts 已在
`contracts/`，並由唯讀 `pilot contract lint` 顯示載入結果。22 個 component
已全量遷移，bundle path、row/tag traceability、dependency endpoint 與
apply/deploy catalog drift 已由 lint 阻擋；尚未接入 deploy/TUI。

**改動**
- 新套件 `internal/contract`:`ComponentContract` Go struct + YAML 檔 `contracts/<component>.yaml`(一元件一檔,可 review、可版本化;**不是 LLM tool schema**)。欄位對齊 roadmap P1 清單:
  - `id`、`role`、`specs: [{path, rows}]`(1—N；rows 可為 all/ids/categories，支援 dns/ntp 共用 spec 的 row ownership)、`playbooks: {apply, rollback, upgrade, decommission}`(依用途各至多一支;**欄位形狀直接對齊已定的 cardinality,不再用單數 `spec`/`playbook`**,review 第二輪 #6)、`regressionTests`
  - `dependencies` 每項加 `relation: sameHosts|providerEndpoint|planOnly`；
    `bindings` 加 `sourceSelection: exactlyOne|all|explicit`，宣告 provider endpoint
    如何綁 input。多台 provider 不得默取第一台
  - `os`(distro+version 支援矩陣)、`hostCardinality`(`exactly-one|one-or-more|zero-or-more`;**套用在本次 stage/limit/host-pattern 解出的 deployment scope**,不是整份 inventory 的全域 host 數)、`resources`(minCPU/minRAM/minDisk)
  - `groupVars`(每項 `{name,type,required,default,secret,validation}`；type =
    string/stringList/integer/boolean/duration；secret 是 vault key 唯一宣告處)、
    `inputRules`（strict all/any + typed condition，表達跨欄位 preflight）、
    `endpoints`
  - `stagePolicy`、`experimental`、`evidenceRequirement`(**宣告離開 experimental 需要哪種 actual-run evidence,不保存「目前是否已有」這種會過期的靜態事實**——實際狀態由 append-only run 查詢得出)
  - `lifecycle`:`backup`、`upgrade`、`decommission` 契約(rollback 已在 `playbooks.rollback`;先允許 `null` 並 lint 警示,不假造)
  - `traceability.mode`:`rowTags` | `mapped`；rowTags 再選 `bare`／`rolePrefixed(<prefix>)`，mapped 必須逐 qualified row ref (`<spec-path>#<row-id>`) 對應 feature/stage tag。`noRowTags` 不進新 schema；verify-only／derived row 也以 qualified row ref 逐列宣告 exemption，避免 1—N specs 的 `C1` 碰撞。細節見 ComponentContract RFC。
  - `verification.autoDeploy`：true 時 selected specs 必須全為 v2；applicability
    由 spec 的 `appliesWhen` 唯一定義，contract 不得覆寫。
- Loader + 嚴格解析(未知欄位報錯,呼應「不提前加入 parser 不認識的欄位」);contract 檔自帶 `schemaVersion: 1`,未知版本拒絕(與 Spec v2 同紀律)。

**邊界決策(review 阻塞項 5;M1.2 全量遷移的前提,先在 RFC 定稿)**
- role cardinality：component → exactly one primary target role；role →
  zero-or-more components。`log-server`/`log-shipping` overlay 是合法案例。
  一個 component 可宣告 1—N specs 與各用途 playbook。
- 既有例外先明處理(review 第二輪 #6):`core-infra-provider` 一支 playbook 涵蓋 dns/ntp 兩個 role(specTagMap `prefixes: ["dns","ntp"]`)——遷移方案定為**拆成兩個 component 共用同一支 apply playbook**(playbook 可被多個 contract 引用,tag namespace 天然分開);試點期若發現不可行再調整模型,不默默留例外。
- `groupVars` 每項 = `{name,type,required,default,secret,validation}`；`required`
  且無 default 且未提供 ⇒ deploy 前擋下。
- 跨欄位要求只用 `inputRules`；rule 的 `all`／`any` 恰選一，condition operator
  固定為 `nonEmpty|equals|notEquals|contains|notContains`。dependency binding、
  使用者 input 與 defaults resolve 後、apply 前評估；false fail closed。
- 資源檢查:facts 可取得且低於 minimum ⇒ **fail**;facts 不可取得 ⇒ **warning + evidence 註記**(不假裝檢查過)。
- lifecycle null 規則:`backup`/`upgrade`/`decommission` 可為 null(lint warning);`playbooks.rollback: null` ⇒ 該 component 的 rollback policy 只能是 `none`。
- **site.yml 決策已定案**：維持手寫；contract 只 lint order/coverage/vars/tags/
  opt-in 與不可覆寫的 safety prelude，M1 不生成 site.yml。

六份試點為 **docker、freeipa-server、restic-backup、dns、ntp、log-shipping**。
Final schema 已定稿；六份 canonical contracts 已走正式 loader，並由 review mirror
semantic-equality test 鎖住。M1.2 可開始擴充全量 lint。

### M1.2 — lint 收斂五處事實來源

**狀態（2026-07-18）：✅ 22 個 component 與 production lint 已完成；DELIVERY
表格改為生成 view 留待文件投影收尾。**

**前置**:M1.1 production loader/API 合併，六份試點改走正式 loader 並通過
contract lint。這是 code dependency，不是未決 schema blocker。

**改動**
- `pilot contract lint`(或併入 `make playbook-lint` 的 Go 檢查):
  - contract 的 `specs: [...]` / `playbooks: {...}` / `regressionTests` 所列檔案存在
  - spec 每列 row ID 可追到 playbook tag 或標記 `verifyOnly`——把 `tag_coverage_test.go` 的 `specTagMap`(手工維護)**改由 contract 生成**,exemptRows ratchet 語意保留
  - `dependencies` 無環;`groupVars`(含 `secret: true` 項——即 vault key 的唯一宣告處,無獨立 `vaultKeys` 清單)與 `group_vars/*.example.yml`、`roleContracts.VaultSections` 一致
  - DELIVERY.md 對照表改為由 contract 生成(或 lint 比對 drift)
- 逐步遷移:`deployCatalog` 欄位(Playbook/DefaultGroup/StageVar/AutoHostVars/VaultHint)改為從 contract 衍生,`deploy_catalog.go` 縮成 contract 的 view;`roleContracts` 同理。遷移完成前 lint 比對兩邊一致,防 drift。
- 22 個元件全數補齊 contract(機械工作,可平行)。

**驗收(P1 完成定義)**
- 新增一個元件的必要 bundle:spec + apply playbook + regression test + contract；需要變數／備份範例時同步 group_vars 與 AGENTS.md §4.2 backup scope。tag map、deploy 選單、DELIVERY 表由 contract 自動衍生。
- 故意做壞每類 lint(缺依賴、cardinality 錯、少 vault key)各有一個負向測試。

### M1.3 — deploy 前置檢查與 DAG

**狀態（2026-07-18）：🟡 deterministic preflight engine 已完成；deploy/TUI
inventory facts 與 input resolver wiring 待 M0.4/P3。**

**改動**
- `internal/delivery` preflight 步驟擴充:依 contract 檢查 host cardinality、必要
  vars/vault key、inputRules、dependency relation、sameHosts coverage、provider
  endpoint selection 與 host 資源；多台 provider 若不是 `all` 必須明確選擇，
  不取第一台。
- site.yml:依 M1.1 RFC 的生成範圍決策執行(傾向 lint-only)——contract 依賴拓撲先只用來 **lint** 現有手寫 site.yml 的順序與 coverage;僅當 site execution projection 定稿並涵蓋全部特殊匯入語意(安全閥、preflight、infra_role 雙匯入、動態 target_group、opt-in 排除)後才切換自動生成。core-infra-provider 與 log-shipping 的 contract fixture 是 M1.3 開工前的必要 contract test。

**規模**:M1.1 中、M1.2 大(22 元件的資料搬遷)、M1.3 中。合計 2-3 週。

---

## 4. P2:Spec v2 schema

> 細部設計、schema 定義、遷移規則見 `docs/tmp/future/SPEC_V2_IMPLEMENTATION_PLAN.md`。

### M2.1 — typed matcher(先做內部重構,不動檔案格式)

- `internal/spec` 新增 `Matcher` 型別(`exitCode`、`stdout.equals/contains/regex`、`timeout`),`matchExpected` 的五種魔法前綴各自對應到一個 typed matcher —— v1 字串在 parse 時**轉譯**成 typed matcher,執行層(verify_spec.go)只認 typed matcher。
- 好處:v2 來臨前,執行語意已單一化;v1/v2 只是兩個前端。
- 測試:魔法前綴→typed matcher 的轉譯表逐案測試；v1 保留 legacy TrimSpace、
  v2 使用 one-trailing-newline normalization；24 份 spec verdict 零回歸。

### M2.2 — v2 parser 並存

**狀態（2026-07-18）：✅ 已實作並驗證（unit + local/docker/vm/general-inventory backend）；尚未宣稱 staging／真實主機 acceptance。**

- v2 spec 用 front-matter + fenced YAML checks；包含 typed matcher、
  `appliesWhen`、`scope`、canonical object action 與
  `secretRef:{provider:ansibleVar,name}`。applicability false 記
  `not_applicable`，不執行 probe、不算 PASS。
- `spec.Parse` 依 `schemaVersion` 分派;**未知版本、未知欄位明確拒絕**。
- v1 manual verify 照常運作；production deploy auto-verify 只接受 v2。

### M2.3 — 遷移工具與 lint

**狀態（2026-07-18）：🟡 migration CLI 已實作；正式 spec 的逐份 target-test 遷移待 feature 變更時進行。**

- `pilot spec migrate <v1.md>`:輸出 v2 草稿；matcher、action 或 applicability
  無法安全推導時寫 `needsReview`，尤其 known-deviation/optional prose 一律
  `applicability-unknown`，不猜條件。
- `spec.Lint` 擴充 v2 規則;`spec --generate` 維持診斷定位(繼續擋 `--generate` 到 playbooks/verify,不恢復 heuristic→apply)。
- 驗收(P2 完成定義):同一份 v2 spec 在 local、docker-target、vm-target、真實 inventory 判定一致——用一份 fixture spec 在三種 target 實跑斷言。

**規模**:合計約 3.5-4.5 週。v1 長期可 manual 使用；要設
`verification.autoDeploy: true` 的 component 必須先遷移其 specs。

---

## 5. P3:contract-driven TUI(依賴 M1.3)

- `pilot deploy` 選單:從「選 playbook」升級為「選 capability → 解析依賴 → 顯示部署 DAG(順序、目標主機、跨主機連線)」;資料全部來自 contract + M1.3 validation engine,**TUI 與非互動 CLI 共用同一份 plan/validation**(把 plan 產生器放 `internal/delivery`,TUI 只是前端)。
- apply 前的缺漏畫面:缺 host、缺 vars、缺 vault key、資源不足、backup policy 未定,一頁列清。
- 多 host component:cardinality=exactly-one 時強制明確選擇,不再默默取 group 第一台(現行 `resolveGroupHost` 行為)。
- `experimental: true` 或尚未滿足 `evidenceRequirement`(實際狀態由 append-only run 查詢得出,contract 不存靜態 evidence 事實)的元件預設隱藏,`--show-experimental` 顯示並加警示。
- day-2:`pilot deploy --action upgrade|decommission`,依 contract lifecycle 欄位走對應 playbook;decommission 需明確處理資料保留(contract 未宣告 → 擋下並說明,不是只從 inventory 刪 role)。
- 測試:沿用 teatest/PTY 模式(`deploy_tui_pty_test.go`),CI=1、SELECT 唯一子字串、按鍵間隔送出(既有 trec 經驗)。

**規模**:2 週。

## 6. P4:coding-agent authoring eval(依賴 M0.4 + M1.2)

- `eval/briefs/*.md`:版本化 Requirement Brief corpus(先 5 篇,涵蓋單機服務、exactly-one、跨主機依賴、含 secret、含 decommission)。
- `eval/run.sh` + Go harness:對一份 agent 產出的 bundle 跑 deterministic gate——contract lint、spec lint、tag coverage、docker/vm-target 首次通過率、第二次 apply changed=0、secret 洩漏掃描(grep vault 值/硬編 IP)。
- 產出機器可讀 scorecard(json),model-independent;不評「看起來不錯」。
- 明確不做:不把 eval 跑在 pilot runtime 內,eval 是 repo 工具。

**規模**:1-2 週(corpus 撰寫佔大半)。

## 7. P5:evidence 查詢與供應鏈追溯(依賴 M0.3/M0.4)

- 擴充 event payload 與 `delivery_runs` view projection(`delivery_runs` 是 VIEW 不是可寫表,「補欄位」= 加 payload 欄與投影):artifact/image digest(從 apply recap 或 contract endpoints 收集)、操作者授權事件(stage gate 的確認輸入與時間,M0.4 已有落點)。
- `pilot runs` 子命令:
  - `pilot runs list [--host H] [--component C]`
  - `pilot runs show <run-id>`(版本、輸入摘要、host×row 明細)
  - `pilot runs last-success --host H`(某主機最後一次成功交付版本)
  - `pilot runs pending-spec <spec>`(哪些主機尚未通過新版 spec)
  - `pilot runs diff <run-a> <run-b>`(evidence diff)
- CVE/元件影響面:`pilot runs affected --component C`(靠 contract 的 component↔run 關聯)。
- 全部唯讀查詢,append-only 不變式由 store 層測試鎖住。
- 實作 generation rotation、archive/prune 與獨立
  `evidence_admin_events`；requested/finished/failed 三態不混入 delivery run。

**規模**:1-2 週。

---

## 8. 橫切守則(對應 roadmap「明確不做」)

1. 不加回 LLM provider/agent loop——所有新套件(`internal/contract`、`internal/delivery`)零 model 依賴。
2. 不把 probe heuristic 編成 mutation——`spec --generate` 維持診斷,M2.3 遷移工具只轉格式不轉語意。
3. v2 parser 落地(M2.2)前,任何文件不得宣稱支援 Spec v2 檔案格式;M1.1 contract 檔案在 loader 合併前同理。
4. 不以總體 PASS 掩蓋局部失敗——所有 applicable host×row 中任一 FAIL ⇒
   整體 FAIL；`not_applicable` 有明細與理由但不算 PASS。
5. destructive boundary 仍由人確認——stage gate(`promptStageDecision`)保留,M0.4 只是把「人已授權」記進 evidence。

## 9. 開工順序(依 review 修訂)

1. M0.2 production slice：Ansible scope adapter → single-host bounded runner →
   decoder/report integration。timeout/scope design 已 Final。
2. M1.1 production loader/API 可與 M0.2 平行；先讓六 fixtures 改走正式 loader。
3. M0.2 合併後依序做 M2.1 → M2.2 → M2.3；M2.2 可使用已 Final 的 Safety 與
   ComponentContract schema。
4. M0.3 store 可與 M2 branch 平行；Final Evidence RFC 已關閉 schema blocker。
5. M1.2/M1.3 在 loader 合併後開始。
6. M0.4 最後整合 M0.2 + M0.3 + M1 mapping + M2.2 applicability/action；
   先遷移要自動驗證的 component specs，再設 `verification.autoDeploy: true`。

目前狀態：**Production implementation GO**。可立即並行啟動三條互不踩檔的
production workstream：M0.2 runner、M0.3 store、M1.1 loader；M2.1 等 M0.2
合併後開始。這些是實作依賴，不是等待額外產品決策。

設計文件對應:ADR-authoring 邊界(隨 M1.1)、RFC-ComponentContract(M1.1)、RFC-Spec v2(M2.2 前)、ADR-evidence data model(M0.3 前)、**RFC-Verification safety boundary(M0.4/M2.2 前)**、Test Strategy-eval(M4.1)。

---

## 附錄 A:現況調查關鍵座標

- deploy 流程:`cmd/pilot/cmd/deploy.go`(runDeploy :56、runPreflight :220、promptStageDecision :262、executeDeployment :576；preview/apply failure 已在 :609-635 fail closed)
- verify:`cmd/pilot/cmd/verify.go`、`internal/tools/verify_spec.go`(matchExpected :321 魔法前綴;runAnsibleAdHoc :192 壓扁 per-host)
- M0.2 expected-host pure resolver：`internal/tools/expected_hosts.go` +
  `expected_hosts_test.go`；尚未接 Ansible scope adapter。
- spec parser:`internal/spec/parser.go`(5 欄 checklist 表;Version 欄位僅資訊)
- store:`internal/store/sqlite.go`(SchemaVersion=12;唯一活表 `spec_checkpoints`,upsert 非 append-only)
- 元件事實五處:`deploy_catalog.go:39`、`inventory/contracts.go:17`、`tag_coverage_test.go:50`、`group_vars/*.example.yml`、DELIVERY.md
- P0 參考實作:`vm_target.go:1488`(runVtTest 5 步機)、`vm_target_topology.go:677`(cluster pipeline,含 snapshot/rollback/rewire)
- TUI:`deploy_tui.go` + `tui_*.go` 原語 + teatest/PTY 測試
- CI:`.github/workflows/ci.yml`(go test -race、playbook-lint、golangci-lint)
