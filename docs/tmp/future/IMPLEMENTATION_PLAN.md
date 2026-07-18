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

> **文件狀態：IMPLEMENTATION PLAN — NOT AN EXECUTABLE RUNBOOK**
>
> 本文件中的未來命令、schema 與 API 是設計內容，不是已驗證操作程序。狀態以
> 下表與各里程碑開頭的 status block 為準。

### 狀態圖例

- **✅ 已實作並驗證**：正式 code path 已修改，test/build/race gate 通過。
- **🧪 Spike 已驗證**：實驗 code／fixture 有測試，但未接入正式 runtime。
- **📄 Proposed**：設計文件已建立；即使 technical review 完成，仍須由人接受／
  final，且不代表已有完整 runtime。
- **⏸ 尚未實作**：不得從計畫文字推論產品已支援。

### 實作狀態快照（2026-07-18）

| 里程碑／產物 | 狀態 | 實作內容 | 明確未實作 |
|---|---|---|---|
| M0.1 | **✅ 已實作並驗證** | deploy exit-code、preflight rejection、`verify --dir` 原始錯誤、regression tests | deploy 後自動 verify/evidence |
| Safety RFC | **📄 Proposed，等待接受** | technical review 完成；per-check action、secret-aware runner contract | action runtime、secret-aware module |
| Evidence RFC | **📄 Proposed，等待接受** | technical review 完成；event schema、RunWriter、heartbeat、retention 決策 | schema v13、store API、runs CLI |
| M0.2 | **🧪 Spike + pure resolver 已驗證** | ansible JSON callback decoder、status normalization、expected-host truth table／pure resolver | Ansible inventory/scope adapter、per-host timeout、正式 `runAnsibleAdHoc` 接線 |
| M1.1 | **📄 RFC + fixtures + schema gate** | 六份 fixtures、test-only strict decode 與語意／負向測試 | production loader/API、全量 contract lint、catalog/site integration |
| M0.3/M0.4 | **⏸ 尚未實作** | 無 | delivery events、transaction、rollback/idempotency policy |
| M1.2/M1.3 | **⏸ 尚未實作** | 無 | 全量 contracts、DAG/preflight |
| M2.1–M2.3 | **⏸ 尚未實作** | 文件已同步設計決策 | typed matcher、v2 parser、migration |
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

依賴關係:M0.3 需要 M0.2 的 per-host 結果;**M0.4 需要 Verification safety boundary RFC 定稿 + M1.1 的 component↔spec mapping**;M1.3 需要 M1.1/M1.2;**M2.1 必須排在 M0.2 之後依序進行**(同動 verifier 執行層,不可平行);M2.2 的 `traceability` 欄位引用 M1.1 的 component ID;M3.1 需要 M1.3;M5.1 需要 M0.3 的表;M4.1 需要 M1.2 的 lint 與 M0.4 的 gate。

兩份短 RFC 是硬性門檻:**Verification safety boundary**(M0.4 與 M2.2 的前置)與 **Append-only delivery evidence data model**(M0.3 的前置;本計畫已選 immutable event stream,RFC 定稿確認)。

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

**Spike／pure resolver 狀態：已完成（2026-07-18）**。實跑與資料契約見
`docs/tmp/future/M0_2_PER_HOST_VERIFY_SPIKE.md`；decoder、fixtures 與測試位於
`internal/tools/ansible_callback_spike*`；expected-host 的純集合 resolver 與
table-driven truth table 位於 `internal/tools/expected_hosts*`。Ansible
inventory／pattern／limit adapter、per-host timeout 與完整 runner 尚未接入正式
verify，仍維持暫緩。

**前置 spike(review 建議 #3:先驗證資料契約,不直接全面重寫)**
- **callback 環境變數已實測定案**(2026-07-18,ansible-core 2.19.2):ad-hoc CLI 只設 `ANSIBLE_STDOUT_CALLBACK=json` **不生效**(輸出仍是 one-line);必須同時 `ANSIBLE_LOAD_CALLBACK_PLUGINS=1` + `ANSIBLE_STDOUT_CALLBACK=ansible.posix.json` 才有含 `hosts.<name>.stdout/stderr/rc` 的 JSON。`ansible.posix` collection 列為 per-host verify 的**必要 preflight,缺席即 fail closed**——不做 `--one-line` fallback 寫正式 evidence(review 第三輪 #1:one-line 逐行解析是有損的——多行 stdout/stderr、probe 輸出撞 marker、timeout/unreachable 欄位形態不穩定,無法證明 host×row evidence 與原始執行結果等價)。`--one-line` 僅保留為 **diagnostic degraded mode**:報告明標降級、不寫入 delivery evidence、不得讓 deploy transaction 判定成功。若 preflight 依賴負擔過高,備案是在 repo 內提供受測且版本化的 callback plugin(spike 一併評估兩案)。
- 以兩台主機實測:一台正常、一台故意 fail,再各補 unreachable 與 timeout 一輪,確認 per-host 欄位形態與邊角(msg-only 失敗、module_stderr 等)。
- **timeout 歸因契約**(review 第四輪 #1:現行一列一個 ansible ad-hoc process,controller 端 `exec.CommandContext`(verify_spec.go:277)逾時殺掉**整個 process**——callback JSON 可能不完整、已完成與未完成 host 混在同一 invocation、expected−observed 只能證明 host 未出現不能證明原因):spike 必須定案 (1) timeout 是 invocation-level 還是 host-level;(2) JSON 不完整時已觀察 host 的結果是否可信;(3) 未觀察 host 記 `timeout`、`missing` 還是 `runner_error`;(4) 若要真 per-host timeout,走每 host 分開執行、remote `timeout` wrapper,還是可回報 task timeout 的 playbook/callback 路徑。**不把所有非 observed 情況壓成 timeout。**
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
  - 再與 callback observed set 做集合比對:
  - expected 為空 → 整份 spec FAIL(不是 skip)。
  - expected − observed 非空 → 每個遺漏 host 各產生一筆 FAIL evidence。
  - observed − expected 非空 → runner/inventory contract error(fail closed,不靜默收下)。
  - `unreachable` → 該 host FAIL 並保留 ansible 錯誤原文。
- 報告(`renderVerifyReport` :257)與 NDJSON 升級為 host×row 粒度;`.md` 報告 row 層彙總、host 明細展開。

**驗收 / 測試**
- docker-target 起 2 容器同 group,spec 一列在 A 過 B 掛,斷言:整體 FAIL、報告含兩台各自的 stdout/rc、exit code 非零。
- 既有 24 份 spec 在單 host 情境輸出不回歸(golden 檔更新一次)。

**規模**:中(3-5 天)。roadmap P0 必要能力第 4 點。

### M0.3 — deployment run ID 與 append-only evidence

**RFC 狀態：Proposed**，見
`docs/tmp/future/APPEND_ONLY_DELIVERY_EVIDENCE_RFC.md`。RFC 已選定 serialized
RunWriter + SQLite transaction、trigger enforcement 與 generation rotation；
review/final 前不開始 schema v13。

**資料模型定案:immutable event stream**(review 阻塞項 3 要求二選一——原稿「開頭取 ID + 表上有 finished_at/outcome + 不可 UPDATE」自相矛盾,已選定事件流)

**改動**
- `internal/store/sqlite.go`:schema v13(依 v12 教訓,**base schema 與 migration 同步改**):
  - `delivery_events`(唯一可寫的交易表,只 INSERT):event_id、run_id(uuid)、seq、type(`run_started`/`run_heartbeat`/`step_finished`/`run_finished`)、step(preflight/preview/apply/verify/idempotency/rollback)、payload(json)、exit_code、created_at。`run_started` 的 payload 含 pilot_version、git_commit、inventory_path/hash、playbook、stage、host_set、extra_vars_summary(非敏感;secret 只存 reference 名)、operator;`run_finished` 含 outcome 與 final_exit_code。
  - `verify_evidence`(只 INSERT):run_id、spec_path、row_id、host、command、expected、stdout、stderr、exit_code、probe_status、verdict、started_at/finished_at。
  - `delivery_runs` 改為 **SQL VIEW**(由 events 聚合 started/finished/outcome),不是可寫表——**無任何 UPDATE**。
  - **active-run 語意**(review 第二輪 #4 + 第三輪 #2:event stream 不可 UPDATE,單靠 `run_started` 帶一次性 lease 會把超過最初 lease 的長時間執行誤判成 `abandoned`):交易執行中定期 INSERT `run_heartbeat` event(payload 含 pid、`expires_at`);view 以**最新一筆 heartbeat 的 `expires_at`** 判定 open run——未逾期 `running`、逾期 `abandoned`。heartbeat 間隔、lease 長度、grace period、heartbeat 寫入失敗時交易是否繼續與 evidence 健康標記,以及 SIGTERM/SIGINT、panic、正常 return、SIGKILL/斷電各自的 terminal 行為矩陣,由 evidence RFC 定稿——**此模型定案前不開始 schema v13 migration**。
  - **唯一性約束**:`UNIQUE(run_id, seq)`;每個 run 至多一筆 terminal event(`type='run_finished'` 的 partial unique index)。
  - **append 併發契約**(review 第四輪 #3:`UNIQUE(run_id, seq)` 只會**偵測**衝突,不會安全**分配**下一個 seq——heartbeat goroutine、主交易 step writer 與 defer 中的 `run_finished` 會並行 append,兩個 writer 可能讀到同一個 `MAX(seq)+1`,或 terminal 後仍有晚到 heartbeat):evidence RFC 定義**單一 append API**——每 run 一個 serialized writer,或 SQLite transaction 內原子配置 seq 並寫入。invariant 一併鎖定:`run_started` 必為 seq 1;terminal event 唯一且必為最後一筆;terminal 後任何 append 拒絕;**heartbeat goroutine 停止並 join 之後才寫 terminal event**(建立 happens-before);heartbeat append 失敗時交易是否繼續與 evidence health 標記。以並行 heartbeat+step+finish 的 `go test -race` regression 鎖住。
  - **append-only enforcement**(review 第四輪 #4:「只 INSERT」若只是 coding convention,不構成資料模型保證;`verify_evidence.run_id` 也無法對 SQL VIEW `delivery_runs` 建一般 FK):RFC 選定**可測**的 enforcement——store 層不暴露任何 update/delete API、所有寫入只走 append transaction,及/或 SQLite trigger 直接拒絕 UPDATE/DELETE;evidence append 前檢查 run 已存在且尚未 terminal(替代 FK);測試直接嘗試 UPDATE/DELETE 舊 event/evidence,必須失敗。
  - **terminal event 保證**:交易主流程以 defer/recover 確保每條 return/cancel/panic 路徑都 INSERT `run_finished`(panic 記 outcome=`panic`);真正的 SIGKILL/斷電留下 open run,由 lease 規則辨識,不需要修復性寫入。
  - **standalone `pilot verify` 同樣寫 `run_started`/`run_finished`**(step 只有 verify)——否則 `verify_evidence.run_id` 在 `delivery_runs` view 查不到。
- **run ID 規則**:deploy 於 `runDeploy` 開頭產生 uuid;standalone `pilot verify` 改用 `verify-<uuid>`(現行秒級 timestamp 可碰撞,棄用);run_id 即去重 key,rerun 一律開新 run,不存在覆寫路徑。
- **redaction / 大小 / retention**(review 第二輪 #3 重寫:原稿「以 vault 解出的值刷除」在 `--ask-vault-pass` 路徑不成立——`vaultInput` 只轉交 vars 檔/password file/密碼提示給 ansible,pilot 從不知道解密後的 plaintext;且 `.verification/` NDJSON/報告是另一個未遮罩的持久化 sink,現行以 `0644` 建立):
  - matcher 一律在**記憶體中的原始結果**上評估;**所有持久化 sink(SQLite、NDJSON、`.md` 報告、event payload)共用同一個 redaction pipeline**,不存在「DB 有刷、檔案沒刷」的旁路。
  - pilot 可取得 secret plaintext 時(vars 檔/password file 路徑)做 exact-string 刷除;**無法取得時(`--ask-vault-pass` 等)**,secret-bearing probe 的 stdout/stderr **預設不持久化**(evidence 只記 verdict + `redacted` 標記),或依 RFC 引入受控 secret resolver——不得宣稱已完成 exact-value redaction。
  - evidence 的 `command` 欄保存原始 probe 與變數 reference,**不保存**展開 secret 後的 materialized shell command。
  - 保留 raw evidence 檔時:改 `0600`(現行 `0644`),授權、加密與 retention 由 evidence RFC 定——不沿用公開可讀的一般 report。
  - stdout/stderr 落庫各截斷至 64 KB 並帶 truncated flag(順序:記憶體判定 → redaction → 截斷 → persist)。
  - retention 預設全留;`pilot runs prune --before <t>` 排入 P5。
  - 轉換過的 secret(base64、截斷、hash)任何 exact-string 刷除都抓不到——殘餘風險記入 safety RFC,並以 lint 警告 secret×stdout-match 組合。
- `spec_checkpoints` 保留為「最新狀態」快取,事實來源改為 evidence 表。

**驗收 / 測試**
- store 層測試:同 run 重複 INSERT 不覆蓋;migration v12→v13 replay 測試(比照 v12 replay-drop 測試模式)。
- 跑兩次 verify,`verify_evidence` 有兩批紀錄、`spec_checkpoints` 只反映最新——斷言前次不被改寫。

**規模**:中(3-5 天)。roadmap「最先三件事」#2。

### M0.4 — deploy 交易閉環(verify 進 deploy、policy 化 rollback/idempotency)

**前置(缺一不可,review 阻塞項 2、4)**
1. **Verification safety boundary RFC 定稿**:verify 現況並非唯讀——`stageVerifyEnv`(verify_spec.go:88)在 `KEYCLOAK_ISSUER` 存在時對所有可達 host 寫 `/etc/pilot-verify.env`,部分既有 check 亦有 POST/PUT/DELETE 型 self-test。RFC 二選一:嚴格唯讀(寫入型 self-test 移至 apply/fixture)或明確隔離、可清理、需人授權的 verification-action 類型。**定案前 verify 不自動接入 production deploy 交易**。
2. **component↔role↔playbook↔spec mapping 先於 `internal/delivery` 抽取**:由 M1.1 contract 定義(component 1—1 primary role、1—N spec、playbook 依用途各至多一支)。原稿「`deployCatalog.SpecPath` 一對一暫接」**取消**——一對一表達不了多 spec、site deploy 與 day-2,只是把手工關聯搬進新套件、固化 drift。
3. **partial deploy 的 verify scope 契約**(review 第二輪 #5:`pilot deploy` 允許 `--tags`/`--limit`/`target_group`,不定義 scope mapping 會兩頭錯——無條件全 spec 驗證讓 scope 外的 row/host 弄失敗交易,只驗 selected tags 又會把 component 整體健康誤報成功):
   - apply scope → verify scope 的 mapping:`--limit`/host pattern 直接餵 M0.2 的 expected host set;`--tags` 部分套用時只驗證 selected rows。
   - **tag→row scope resolver**(review 第三輪 #5:Ansible tag 不只 row tag——單 spec 裸 `C3`、多 role 粗 tag `db` 與細 tag `db-C3`、一 task 多 tag、`always`/`never` 特殊 tag):requested tags + contract `traceability`(rowTags bare/rolePrefixed、mapped;ComponentContract RFC 已以此取代早前的 `tagMode`)+ playbook tag coverage → selected spec rows。**無法無歧義解析時 fail closed**,或要求使用者明確給 `--verify-rows`——不猜測。
   - outcome enum 完整定義,不只定成功態:`partial_success` / `partial_failed` / `cancelled` / rollback 後狀態(如 `rolled_back`);partial outcome 明示只對 selected rows×hosts 成立,不冒充 component 整體健康。
   - idempotency rerun 使用與 apply **完全相同**的 tags/limit/extra-vars。
   - 此契約定案後才抽取 `internal/delivery.Transaction`。

**改動**
- `cmd/pilot/cmd/deploy.go`:apply 成功後自動接 per-host verify;spec 集合來自 contract mapping;full-site deploy 對每個非空 group 跑該 component 宣告的全部 spec(等同 `topology test --verify spec=<limit>` 的邏輯搬進 deploy)。
- **apply 成功 + verify 失敗 = 交易失敗**(non-zero),outcome=`verify_failed`。
- 交易步驟機:把 `runVtTest` 的 5 步機(vm_target.go:1488)抽成 `internal/delivery` 套件的 `Transaction`(steps: preflight→preview→apply→verify→idempotency→rollback-on-failure),`deploy`、`vm-target test`、`topology test` 三處共用,行為差異用 policy 表達:
  - `idempotency: always|stage>=staging|never`(第二次 check-mode 或 apply 斷言 changed=0)
  - `rollback: none|snapshot|playbook`——真實主機沒有 VM snapshot,先支援 `none`(預設,只標記 outcome)與 `playbook`(component 宣告 rollback playbook 才可用;無宣告時明說「無自動 rollback」而非假裝有)。
  - verify 邊界依 safety RFC 執行。module allowlist 只是縱深防禦,**不構成唯讀保證**(review 指正:`command`/`shell` probe 本身就能寫入)——唯讀保證來自 RFC 定案的規範 + lint + review,寫入型檢查一律走 RFC 定義的去向。
- 每步 INSERT `delivery_events`;結束 INSERT `run_finished` event(outcome、final_exit_code)。

**驗收 / 測試(P0 完成定義)**
- vm-target 三節點 topology 實跑:故意讓一台 verify 失敗 → deploy 非零、run 查得到那台那列的 stdout/rc。
- 從 run ID 能回答「哪個版本、什麼輸入、哪些主機、哪列成敗」——寫成一個 store 查詢測試。
- `vm-target test` / `topology test` 改用 `internal/delivery` 後既有行為不回歸(既有 topology test 已實跑過 site.yml smoke,重跑一次當驗收)。

**規模**:大(1-2 週)。完成後 P0 收斂。

---

## 3. P1:DeliveryBundle / ComponentContract

### M1.1 — schema 與載入器

**RFC／fixtures 狀態：已建立、待接受**，見
`docs/tmp/future/COMPONENT_CONTRACT_RFC.md` 與
`docs/tmp/future/contracts/*.yaml`。六份 fixtures 已通過 test-only strict decode、
selector、traceability、binding、實際 tag 與 duplicate-owner 驗證；測試位於
`internal/contract/fixture_schema_test.go`。這不是 production loader/API，正式
runtime 仍依本節 gate 暫緩。

**改動**
- 新套件 `internal/contract`:`ComponentContract` Go struct + YAML 檔 `contracts/<component>.yaml`(一元件一檔,可 review、可版本化;**不是 LLM tool schema**)。欄位對齊 roadmap P1 清單:
  - `id`、`role`、`specs: [{path, rows}]`(1—N；rows 可為 all/ids/categories，支援 dns/ntp 共用 spec 的 row ownership)、`playbooks: {apply, rollback, upgrade, decommission}`(依用途各至多一支;**欄位形狀直接對齊已定的 cardinality,不再用單數 `spec`/`playbook`**,review 第二輪 #6)、`regressionTests`
  - `dependencies` / `conflicts`,加上結構化 **`bindings`**——宣告「依賴元件的哪個 endpoint 綁到本元件哪個 input/group var」,如 `{input: restic_s3_target_host, from: {component: seaweedfs-s3, endpoint: s3}}`。沒有 binding,TUI 推導不出 `restic_s3_target_host`/`wazuh_manager_host`,`autoHostVar` 就退役不掉
  - `os`(distro+version 支援矩陣)、`hostCardinality`(`exactly-one|one-or-more|zero-or-more`;**套用在本次 stage/limit/host-pattern 解出的 deployment scope**,不是整份 inventory 的全域 host 數)、`resources`(minCPU/minRAM/minDisk)
  - `groupVars`(每項 `{name, required, default, secret, validation}`;`secret: true` 的項**即為** vault key 的單一宣告處,不另設獨立 `vaultKeys` 清單——同一事實不兩處宣告)、`endpoints`(輸出 endpoint 名與 port,`bindings.from` 的引用對象)
  - `stagePolicy`、`experimental`、`evidenceRequirement`(**宣告離開 experimental 需要哪種 actual-run evidence,不保存「目前是否已有」這種會過期的靜態事實**——實際狀態由 append-only run 查詢得出)
  - `lifecycle`:`backup`、`upgrade`、`decommission` 契約(rollback 已在 `playbooks.rollback`;先允許 `null` 並 lint 警示,不假造)
  - `traceability.mode`:`rowTags` | `mapped`；rowTags 再選 `bare`／`rolePrefixed(<prefix>)`，mapped 必須逐 qualified row ref (`<spec-path>#<row-id>`) 對應 feature/stage tag。`noRowTags` 不進新 schema；verify-only／derived row 也以 qualified row ref 逐列宣告 exemption，避免 1—N specs 的 `C1` 碰撞。細節見 ComponentContract RFC。
- Loader + 嚴格解析(未知欄位報錯,呼應「不提前加入 parser 不認識的欄位」);contract 檔自帶 `schemaVersion: 1`,未知版本拒絕(與 Spec v2 同紀律)。

**邊界決策(review 阻塞項 5;M1.2 全量遷移的前提,先在 RFC 定稿)**
- component↔role:**1—1**(component 恰對應一個 primary role);一個 component 可宣告 **1—N 份 spec**、多支 playbook(依用途 apply/rollback/upgrade/decommission 各至多一支)。這份 mapping 同時是 M0.4 `internal/delivery` 的 spec 來源。
- 既有例外先明處理(review 第二輪 #6):`core-infra-provider` 一支 playbook 涵蓋 dns/ntp 兩個 role(specTagMap `prefixes: ["dns","ntp"]`)——遷移方案定為**拆成兩個 component 共用同一支 apply playbook**(playbook 可被多個 contract 引用,tag namespace 天然分開);試點期若發現不可行再調整模型,不默默留例外。
- `groupVars` 每項 = `{name, required, default, secret, validation}`;`required` 且無 default 且未提供 ⇒ deploy 前擋下。
- 資源檢查:facts 可取得且低於 minimum ⇒ **fail**;facts 不可取得 ⇒ **warning + evidence 註記**(不假裝檢查過)。
- lifecycle null 規則:`backup`/`upgrade`/`decommission` 可為 null(lint warning);`playbooks.rollback: null` ⇒ 該 component 的 rollback policy 只能是 `none`。
- **site.yml 生成範圍決策**(review 第四輪 #5:現行 site.yml 含 contract schema 表達不了的特殊執行語意——`target_group is not defined` + `tags: [always]` 安全閥、`preflight.yml` 固定先跑、`core-infra-provider-apply.yml` 以 `infra_role: dns/ntp` 匯入兩次、每個 import 的 site-level 粗 tags、log-shipping 的動態 `target_group` fallback 運算式、freeipa-identity/replica 等 day-2/opt-in 元件刻意不進 site——僅靠 `playbooks.apply` + dependency DAG 無法無損重建):M1.1 RFC 二選一——(1) 新增 **site execution projection**(`site.include`、`site.vars`、`site.tags`、`site.optIn`,安全 prelude 定為不可由 component 覆寫的模板)後才宣稱生成;(2) **site.yml 維持手寫,contract 只 lint 順序與 coverage**。**傾向先採 (2)**——在 projection 被證明能無損重建上述全部行為之前,不切換自動生成。

**先寫 6 份試點 contract**(review 第四輪 #5 + 第五輪 #1:原 3 份——docker、freeipa-server、restic-backup,涵蓋無依賴/exactly-one/有依賴(binding)三型——涵蓋不了共用 playbook 與動態 target_group;且 component↔role 1—1 下 core-infra-provider 不是一份 contract,而是 **dns、ntp 兩份**(共用同一支 apply playbook,見上);試點清單定為 **docker、freeipa-server、restic-backup、dns、ntp、log-shipping**,後三份是最難的例外,不留到 M1.2 全量遷移才爆),以 RFC + YAML fixtures 形式 review;**loader 與 API 在試點 schema/lint 定稿後才動工**(review 第二輪:schema 未定前不固化 loader),通過後才啟動 M1.2;不要一次搬 22 個。

### M1.2 — lint 收斂五處事實來源

**前置**:M1.1 邊界決策定稿且六份試點(docker、freeipa-server、restic-backup、dns、ntp、log-shipping)通過 contract lint;在此之前全量遷移暫緩(review 阻塞項 5)。

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

**改動**
- `internal/delivery` preflight 步驟擴充:依 contract 檢查目標 inventory 的 host cardinality、必要 group vars/vault key 是否已填、依賴元件是否在 site 部署範圍內、(可取得時)host 資源;任一不符 → deploy 前擋下,清楚列出缺什麼。
- site.yml:依 M1.1 RFC 的生成範圍決策執行(傾向 lint-only)——contract 依賴拓撲先只用來 **lint** 現有手寫 site.yml 的順序與 coverage;僅當 site execution projection 定稿並涵蓋全部特殊匯入語意(安全閥、preflight、infra_role 雙匯入、動態 target_group、opt-in 排除)後才切換自動生成。core-infra-provider 與 log-shipping 的 contract fixture 是 M1.3 開工前的必要 contract test。

**規模**:M1.1 中、M1.2 大(22 元件的資料搬遷)、M1.3 中。合計 2-3 週。

---

## 4. P2:Spec v2 schema

> 細部設計、schema 定義、遷移規則見 `docs/tmp/future/SPEC_V2_IMPLEMENTATION_PLAN.md`。

### M2.1 — typed matcher(先做內部重構,不動檔案格式)

- `internal/spec` 新增 `Matcher` 型別(`exitCode`、`stdout.equals/contains/regex`、`timeout`),`matchExpected` 的五種魔法前綴各自對應到一個 typed matcher —— v1 字串在 parse 時**轉譯**成 typed matcher,執行層(verify_spec.go)只認 typed matcher。
- 好處:v2 來臨前,執行語意已單一化;v1/v2 只是兩個前端。
- 測試:魔法前綴→typed matcher 的轉譯表逐案測試;24 份 spec 判定結果零回歸。

### M2.2 — v2 parser 並存

- v2 spec 用 markdown front-matter(metadata)**加** `## Checks` 下的 fenced YAML 區塊(checks)承載結構化欄位——兩者皆需,見 SPEC_V2 D1(維持人可讀的 markdown 主體):`schemaVersion: 2`、`intent`、`targets`(含 hostScope/平台)、`inputs`(必填+validation+secret ref)、`checks`(穩定 row ID、probe、typed matcher、timeout、`scope: per-host|aggregate`)、`traceability`(`components` 引用 1—N 個 M1.1 contract ID,resolved tag/row mapping 由 contract traceability 推導、regression invariant)、per-check `action`、`evidencePolicy`、`compatibility`(最低 pilot 版本)。
- `spec.Parse` 依 `schemaVersion` 分派;**未知版本、未知欄位明確拒絕**。
- v1 照常運作;`pilot verify` 對兩版行為一致(同一 typed matcher 執行層)。

### M2.3 — 遷移工具與 lint

- `pilot spec migrate <v1.md>`:輸出 v2 草稿;無法安全轉換的 matcher(如語意模糊的 `~` 子字串)標 `needsReview: [<finding>]`(機器可辨識的 `[]string` 欄位,非空 ⇒ verify 整份拒跑),不做靜默轉換。
- `spec.Lint` 擴充 v2 規則;`spec --generate` 維持診斷定位(繼續擋 `--generate` 到 playbooks/verify,不恢復 heuristic→apply)。
- 驗收(P2 完成定義):同一份 v2 spec 在 local、docker-target、vm-target、真實 inventory 判定一致——用一份 fixture spec 在三種 target 實跑斷言。

**規模**:M2.1 中、M2.2 大、M2.3 中。合計 2-3 週。遷移 24 份既有 spec 不搶進度,v1 長期可用,逐份隨修改順手遷。

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

**規模**:1-2 週。

---

## 8. 橫切守則(對應 roadmap「明確不做」)

1. 不加回 LLM provider/agent loop——所有新套件(`internal/contract`、`internal/delivery`)零 model 依賴。
2. 不把 probe heuristic 編成 mutation——`spec --generate` 維持診斷,M2.3 遷移工具只轉格式不轉語意。
3. v2 parser 落地(M2.2)前,任何文件不得宣稱支援 Spec v2 檔案格式;M1.1 contract 檔案在 loader 合併前同理。
4. 不以總體 PASS 掩蓋局部失敗——M0.2 起所有 rollup 皆由 host×row 明細聚合,聚合層測試鎖住「任一 FAIL ⇒ 整體 FAIL」。
5. destructive boundary 仍由人確認——stage gate(`promptStageDecision`)保留,M0.4 只是把「人已授權」記進 evidence。

## 9. 開工順序(依 review 修訂)

1. **M0.1(修訂版)**:preview/apply 非零退出 + exit-code 契約表 + runner 測試 seam;`verify --dir` 只補「保留 per-spec 原始錯誤」。
2. **兩份短 RFC（已建立為 Proposed，待 review/final）**：Verification safety boundary（涵蓋 per-check verification action、secret transport、所有 sink）、Append-only delivery evidence data model（event stream、heartbeat、lease、terminal matrix、prune/DELETE）。
3. **M0.2 JSON callback spike + pure resolver（已完成）**：已實跑
   success/module-error/unreachable/controller-timeout，並固化 decoder fixtures、
   expected-host truth table 與 pure resolver；下一切片是 Ansible scope adapter
   與 per-host timeout 決策，仍不得使用有損 `--one-line` evidence。
4. **M1.1 六份試點 contract（RFC + YAML fixtures + test-only schema gate 已建立，
   不含 production loader）**：fixtures 已 strict decode 並對實際 spec rows／
   playbook tags 做語意驗證；loader/API 與全量遷移(M1.2)仍待 RFC 接受。
5. M0.2 完成後依序 → M2.1(不可平行);M0.3/M0.4、M1.2+、M2.2 待各自前置關閉後開工。

目前狀態：**已完成／已產出**——M0.1、兩份 Proposed hard-gate RFC、M0.2
callback spike + pure resolver、M1.1 RFC/fixtures + test-only schema gate；
**下一個可做**——review/accept 三份 RFC、M0.2 Ansible scope adapter 與 timeout
決策；**暫緩**——M0.2 正式 runner 接線(待 adapter/timeout contract)、M1.1
production loader 與 M1.2/M1.3(待 ComponentContract RFC 接受)、M0.3/M0.4
(待 RFC final + M0.2 + contract mapping)、M2.1(待 M0.2 合併)、
M2.2/M2.3(待 M2.1 + safety RFC final)。

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
