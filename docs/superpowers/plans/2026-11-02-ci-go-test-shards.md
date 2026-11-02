# kjelly/pilot — Go CI 測試分片實作計畫

- **版本**：2026-11-02，依目前程式現況修訂。
- **Repository**：https://github.com/kjelly/pilot
- **狀態**：可開始實作；新增工具與 CI 行為均待實作、待實測，不代表功能已通過驗收。
- **交付範圍**：coding agent 在 repository 內完成耗時量測、Go top-level test 分片、執行結果核對、CI 發布閘門與回歸測試。
- **預期效益**：縮短大型 Go package 的測試等待時間，保留完整測試涵蓋及既有發布條件；同時量測新增 runner 成本，避免只改善單一 test step。

## 1. 已確認的起點

本計畫以本地 revision `eabddff4` 為查核起點。實作開始時，coding agent 應重新確認目前分支的相關檔案；若已有部分實作，沿用並補足驗收。

| 項目 | 已確認現況 | 本次處理方式 |
|---|---|---|
| Go suite | `test` matrix 為 `spec / cmd / rest`；前兩組各只有一個 package | 將前兩組改為 top-level test 分片；保留 rest 的完整 package 範圍 |
| Ansible suites | `playbook-integration` 已有五個平行 targets，且為 image 的 dependency | 維持現有行為，移除重做平行化的工作 |
| Race suite | `Makefile` 的 `test-race` 使用 `-race -count=1 -timeout 45m` | 保留旗標及不帶分片參數的完整測試行為 |
| 重複準備成本 | 每個 Go job 都執行全 repo 的 vet/build；PTY harness 另有每個 process 共用的 CLI build | 分開量測，納入分片數選擇；本次不改動 vet/build 架構或 PTY harness |
| Candidate reuse | `changes` 與 `ci-validation-reuse.py` 已依 frozen merge、tree、parents、成功 receipt 判斷沿用 | 保留 receipt 與 evidence-only 的安全條件 |
| GitHub 設定 | 2026-11-02 唯讀查詢：main 的 branch protection 回覆 Branch not protected，套用中的 branch rules 為空 | 本計畫不需要新增 required checks 或修改管理設定 |

同日列出的 top-level tests 為 `internal/spec` 539 個、`cmd/pilot/cmd` 1,369 個。這是當時的數量，實作不得將數字寫死成驗收條件。

[CI #556](https://github.com/kjelly/pilot/actions/runs/41410664990) 的 Ansible suites 還在單一 job 內循序執行，因此其約 35 分鐘整體耗時只作歷史背景，不能當成現行架構的 baseline。本次由 coding agent 收集現行架構的新基準。

開始實作前已確認 `eabddff48ebe0f619053f168a60f050437d97e57` 的 main push CI [run 41442066295](https://github.com/kjelly/pilot/actions/runs/41442066295) 為 completed/success（2026-11-02，12:07:01–12:46:55 UTC）。這證明實作前的完整 CI 為綠燈；逐測試 JSON 與權重仍由階段 A 補齊，不能從 package 總時間反推。

## 2. 範圍與必要契約

本次只改 CI orchestration 與其測試工具，不新增 runner、不改帳號額度或 repository 管理設定，也不導入需要額外秘密或私人 VM 的驗收工作。

1. **測試完整性**：每個可執行的 top-level Test、Example、Fuzz seed target 都必須被分派；subtests 跟隨 parent。Benchmark 不屬於一般 race suite，TestMain 不作為分派項目。
2. **執行完整性**：除了分派清單，還必須核對實際 Go JSON events；清單完整但 selector 沒有真正選到測試，仍須失敗。
3. **保持既有強制測試**：五個 Ansible targets、mandatory-container flags、root-only、Thanos、MCP、Python、skill tests、duplicate-key checks 與 lint 均保留；不修改既有測試的 skip 條件。
4. **保持發布條件**：任何必要 shard 或結果核對失敗、取消、缺失，都不得讓 image 或 promote 執行；不增加 continue-on-error 或繞過 dependencies 的成功路徑。
5. **可重現**：同一 tested tree、平台、Go toolchain、分片設定、權重與測試清單，產生相同分派；權重不得在各 runner 臨時自行更新。
6. **不宣稱 race 語意完全等價**：保留 race detector，並在導入時比較完整與分片執行，檢查 process 內共享狀態、背景 goroutine、TestMain、fixture 與 cleanup 的依賴。不能只憑旗標相同判定等價。
7. **維持事件語意**：PR、main push、release tag、workflow_dispatch、fork、evidence-only reuse、ci-receipt 及 promote lock 都須有契約測試；本次不為驗收建立 release tag 或移動 latest。

## 3. 實作設計

### 3.1 工具與檔案責任

以下新檔案及介面均為待實作契約，並非已驗證的操作指令。

| 檔案 | 責任 |
|---|---|
| `scripts/ci-go-test-shards.py`（新增） | Python 標準函式庫工具；提供 matrix、discover、plan、run、verify、summarize、weights 功能，使用 subprocess 呼叫 Go 並保留退出碼 |
| `scripts/ci-go-test-shards.json`（新增） | 唯一的 package/group/shard 數設定；spec、cmd 固定對應現有兩個 package，rest 由現有 package selector 推導 |
| `scripts/ci-go-test-weights.json`（新增） | 從成功的完整 race run 產生的逐 package/test 耗時權重、來源 candidate/run 及版本；由明確工具操作更新後提交 |
| `scripts/tests/test_ci_go_test_shards.py`（新增） | 不需要 Go 的分派、事件核對、耗時彙整及錯誤處理單元測試 |
| `scripts/tests/test_ci_go_test_shards_runtime.py`（新增） | 真正啟動 Go 的小型 fixture 測試，與快速單元測試分開收集 |
| `.github/workflows/ci.yml` | 收集 JSON、執行 matrix、上傳 artifacts、核對完整結果及保持 image/receipt dependencies |
| `Makefile` | 保留 test-race 預設行為；增加可選 `GO_TEST_RUN_REGEX` / `GO_TEST_JSON` 及新工具測試入口，使用安全的參數傳遞 |
| `cmd/pilot/cmd/ci_shards_test.go` 等既有 CI 合約測試 | 更新舊三組 matrix 假設，鎖住設定來源、Go 旗標、所有額外測試步驟與發布依賴 |
| `TESTING.md` | 記載設定、權重更新、結果判讀及回滾；完成真跑後才寫操作命令 |

工具不需要新的 Python 套件或 API credential。讀取 GitHub Actions 量測資料沿用既有 GitHub 存取；API/metadata 讀不到時標記缺資料，不將零秒當成量測值。

### 3.2 發現與分派

1. Discovery 必須使用與執行相同的平台、Go toolchain、build tags、race build 與相關環境，避免一般 build 清單遺漏 race build 才會編入的測試。
2. 以 Go 的 list 功能取得 top-level Test、Example、Fuzz 名稱；只解析測試清單及已辨識的 Go 控制輸出，不將 build error、package summary 或 Benchmark 誤當測試。保留原始清單與退出碼。
3. spec、cmd 各自生成完整 partition，再選取本 shard。名稱保留原值、排序固定；空清單、重複名稱、非法 index/total、discovery 失敗或測試數少於 shard 數時直接失敗。
4. 使用 LPT：先依權重降序、同權重按名稱排序，再放入累積權重最小的 shard；累積權重相同時選最小 index。權重使用正整數毫秒，零耗時提升為 1 ms；未知測試使用固定 1,000 ms，並列入 summary。
5. 權重由成功 baseline 的 top-level terminal events 產生；多筆可比樣本取每項中位數。平行測試的 elapsed 不等於 job 的可加總 wall time，最終仍以真實 shard 耗時驗收。
6. baseline 與 shard 數為 1 的完整模式不依賴權重檔，避免尚未量測就無法啟動。shard 數大於 1 時，權重檔缺失、格式錯誤、非有限值或非正權重須失敗；過期測試的權重不參與分派並列出。新測試不得因為沒有權重而遺漏。
7. 驗證所有 shard 的聯集等於 discovery、交集為空、每項恰好一次，且沒有空 shard。從整份 partition 算出共同 digest；revision/run 與實際耗時另行記錄，不讓 timestamp 影響分派 digest。
8. Selector 為完整名稱的 anchored alternation，正確處理 regex escape；不包含 subtest 路徑。執行工具拒絕衝突的 run/skip/short 等選項，避免繞過選取契約。
9. rest 沿用 `ci-go-test-packages.sh` 的完整集合，不傳 top-level selector。每次驗證 spec、cmd、rest packages 聯集等於當下完整 module 的 package 清單，且互不重疊。

### 3.3 實際執行與結果核對

執行路徑保留 `make test-race` 的 race/count/timeout 契約。可選 selector 未設定時仍執行完整 suite；已設定卻為空或非法時須拒絕，不可退回全跑。rest 必須明確不帶 selector。

Go 執行以 JSON 模式記錄 stdout，stderr 另存；Make recipe echo 等非 Go 輸出必須與 JSON 串流隔離。wrapper 保留 Go 原始退出碼，避免 pipe 或 artifact 上傳把失敗變成成功。Go 失敗時仍嘗試保存診斷報告；報告產生失敗不能覆蓋原始失敗。

每個 spec/cmd shard 的核對至少包含：

- 實際 top-level run events 與預定清單相等，每項只有一次 terminal pass/skip；任何 fail 或缺少 terminal event 都失敗。
- 未預定的 top-level test、未執行的預定 test、重複事件、錯誤 package、破損或截斷 JSON 都失敗；subtest events 不另算 top-level 次數。
- 保留 parent/subtest 的 skip 名稱及原因。既有合法 skip 可存在；強制 Ansible/root 測試依原有入口 fail-closed，不能把整份 log 出現任何 SKIP 當成錯誤。
- 例如 `TestRegression_IdentitySSHCacheLiveSSH` 缺少私人 topology 設定時本來就會 skip；本次不要求提供該 topology，也不改變這個條件。
- rest 報告須涵蓋預定 packages；無 test files 的 package 可用 Go 明確的 package 結果表示，不得把缺失報告當作無測試。

每個 shard artifact 包含原始 discovery/JSON/stderr、完整 partition、selector、退出碼及核對摘要。摘要記錄 tested revision/tree、run ID/attempt、Go/platform、相關非秘密旗標、設定/權重 hash、測試數、共同 partition digest 與實際耗時。baseline、完整對照與正式 shards 使用不同 artifact 前綴，不把對照執行誤算成分片重跑。

CI artifacts 設定保留 7 天，agent 在到期前取回驗收資料；到期或遺失時重新驗證，不手填成功結果。需要長期保留的原始證據依 repo 的 evidence 政策歸檔，Git 只提交 sanitized 摘要與可追溯位置。上傳前沿用 repo 的敏感資訊檢查；不保存 credential、完整環境變數或含秘密的 fixture 值，必要遮罩須保留判定所需的事件、退出碼及識別資訊。

### 3.4 CI 編排與發布閘門

1. 沿用 `changes` job，在既有 reuse 檢查之外讀取分片設定並輸出 matrix；此步只需 Python，不在 changes 編譯或跑大型 Go suite。每個 entry 帶唯一 id、group、index、total。拒絕未知 group/package、重複 id、不連續 index、不一致 total 或多個 rest entries；matrix 產生失敗時直接阻擋測試，不回退到空清單。
2. 初始候選設定採 **spec 2 + cmd 2 + rest 1**。所有 Go entries 採 fail-fast false，初始 max-parallel 為 5；不更動現有 Ansible matrix。此上限只管理 Go matrix，不代表整個帳號的併發上限。
3. 每個 shard 從同一 frozen checkout 與已提交的權重生成 partition；保留既有 setup、vet/build。Python callback、skill、duplicate-key steps 仍只在唯一 rest entry 執行。
4. 每個 entry 上傳名稱含 run attempt 與 shard id 的唯一 artifact；成功 job 必須有完整報告，缺檔不能僅 warning。失敗/取消時的 artifacts 盡力保留。
5. 新增 blocking `go-test-results` job，needs 包含 changes 與整個 test matrix。沒有額外的 always/成功放行條件；test 失敗、取消或被跳過時，此 job 依 dependencies 被阻擋。
6. 結果 job 從同一分片設定推導必要 entries，核對 artifact 精確集合、candidate/run/attempt、同 group 的 partition digest、設定/權重 hash，再重新核對實際執行集合。缺檔、重複、不一致或跨 candidate 混用均失敗。
7. image 同時等待既有 validation jobs 與 go-test-results；ci-receipt 仍只在完整成功 image 之後產生。不得以 artifact 已上傳代替成功執行證據。
8. evidence-only 被合法 reuse 時，test、go-test-results、image 保持既有鏈的 skipped 行為，不為缺少本次 shard artifacts 製造假成功。首次驗證、程式/workflow 改動及 main/tag 仍走完整驗證。
9. 新工具快速單元測試納入既有 `ci-workflow-test` 入口，既有 reuse tests 不得被取代。真實 Go fixture 測試只在 Go test 階段的 rest entry 執行，不讓 changes 收集到需要 Go 的測試。

## 4. Coding agent 的實作順序

每階段都由 coding agent 撰寫程式、跑測試、讀結果與修正；不要求使用者手動蒐集 log、計算權重或填寫測試名稱表。

| 階段 | 工作 | 完成條件 |
|---|---|---|
| A：現行基準 | 原有三組 package matrix 加入 JSON/artifact 與彙整工具，不改分派；收集成功 CI 的逐測試與 job/step 耗時 | 能從實際結果重建測試清單、skip 摘要與權重；來源 revision/tree/toolchain 可追溯 |
| B：分片與核對 | 實作 deterministic partition、selector、事件核對、matrix、結果 job 及負向測試；以 2+2+1 起跑 | 測試清單和實際執行完整，發布閘門完整，CI 真正跑完 |
| C：對照與調校 | 候選分支暫時加入 spec/cmd 完整 race 對照 jobs，與 shards 使用同一 candidate、工具鏈及環境，只有 selector 不同；兩者都 blocking | 對照 top-level/subtest verdict、skip 及共享狀態；差異有解釋或已修正，不能直接忽略 |
| D：正式收斂 | 移除暫時對照 jobs，形成新 candidate，再跑正式完整 CI；依量測決定保留 2 shards 或各增為 3 | 最終 candidate 的全部正式 shards、結果核對及既有 validations 成功；附前後量測 |

階段可分為量測與分片導入兩個變更，不要求為每項量測另開 PR。暫時對照 jobs 的新增/移除須同步 image dependencies 與契約測試；不可為了對照在本機重跑兩個大型 package 全套。階段 D 若調整設定/權重，須重跑受影響 CI，不能沿用前一份 partition 的成功結果。

導入對照只能證明所測 candidate 的涵蓋、觀察結果與隔離情形；不保證所有可能測試順序下的 race 行為都一致。有跨測試依賴時先修正隔離並補回歸；無法在本次修妥就保留原 package 執行方式，不以放寬 skip 或刪除測試交付。

## 5. 必須自動化的測試

| 測試面向 | 必須覆蓋的行為 |
|---|---|
| Discovery | 同一 race/build 環境、Test/Example/Fuzz、Benchmark 與 summary 過濾、失敗/空清單/重複名稱 |
| Partition | 聯集完整、互斥、無空 shard、未知/刪除測試、輸入順序不影響 digest、LPT tie-break、非法參數及權重 |
| 真實 selector | 小型 Go fixture 驗證相似前綴、subtests、Example、Fuzz seeds、race-only build-tag 測試；核對實際事件 |
| 執行核對 | 故意漏掉 selector 項目、加進非預定項目、錯誤 regex、重複/缺失 terminal、失敗/合法 skip、破損 JSON、錯誤 package |
| Wrapper/Makefile | Go 失敗仍回傳失敗；無 selector 的完整模式不變；空 selector 拒絕；rest 不受 selector 污染；race/count/timeout 保留 |
| Artifacts | 缺檔/多檔、混用 tree/run/attempt、權重/設定/digest 不同、空報告均拒絕；失敗 run 不產生成功摘要 |
| Packages/額外測試 | 新 package 自動進 rest、互不重疊；callback/skill/duplicate-key 與新工具 runtime steps 恰好保留在 rest |
| CI graph | 新結果 job、Ansible、root、Thanos、MCP、lint 都是 image 前置；錯誤 dependency、continue-on-error、繞過 failure 的條件必須被攔截 |
| 事件與 reuse | PR/main/tag/dispatch/fork/evidence-only 的判斷 fixture；workflow 變更不得沿用舊 receipt，frozen checkout 維持一致 |
| 效能彙整 | 區分 queue/setup/build/test/post-job；不將缺資料視為零，不將平行測試 elapsed 加總當 wall time；失敗及取消另列 |

契約測試必須包含故意放回錯誤的案例，證明漏 shard、漏 dependency、遺漏 artifact 或錯誤 selector 會導致失敗。真實 GitHub 驗證在不發布 image 的 PR 上，暫時令單一 shard 非零退出，觀察 image/ci-receipt 被阻擋；修復後以新 candidate 跑成功鏈。cancel/missing 等分支以自動化負向 fixture 驗證，不要求取消他人的工作或建立真實 release。

## 6. 量測與接受條件

### 6.1 正確性：全部必達

- [ ] spec/cmd 的 discovery、預定 partition 與實際 events 一致；rest packages 完整保留，新增測試/package 自動收錄。
- [ ] 共同 manifest 與 artifacts 綁定同一 candidate/run/attempt；漏跑、重跑、報告缺失或 selector 錯誤均 fail-closed。
- [ ] 原有 race/count/timeout、完整 Makefile 模式及額外 validations 不變；合法 skip 原因保留，mandatory 入口仍拒絕依賴缺失。
- [ ] 完成同 candidate 的完整/分片對照；沒有未解釋的 verdict/skip 差異或已知跨測試狀態依賴。
- [ ] image、promote、ci-receipt、evidence-only reuse 與 frozen checkout 契約測試成功；真實 PR 的失敗 shard 確實阻擋發布鏈。
- [ ] 最終 candidate 的正式 CI 成功，含必需報告與結果核對；修改權重、設定或執行工具後重新驗證。
- [ ] 新工具單元與真實 Go fixture 測試、相關 Go CI 合約測試、workflow YAML 檢查成功。actionlint 對既有 promote.queue 語法的工具版本限制應精確列出，不整體忽略其他錯誤。

### 6.2 效能：由 agent 量測後決定

每次結果至少記錄來源 revision/tree、run/attempt、event、toolchain、cache 情況、samples 數、Go 各 group 最慢 job、queue/setup/test 時間、整體 workflow wall time 與總 runner 執行分鐘。PR/main 分開，reuse、失敗及取消不混進成功耗時比較，另列其結果與重試成本。

- 優先使用來源測試相同、工具鏈相同且環境可比的完整/分片對照；比較完整 package 與該 group 最慢 shard 的實際 job 時間，不只比較權重預估值。
- 導入至少有一組真實可比對照及最終正式 CI；有更多可比樣本再報 median 並附樣本數。單組樣本只作初步效能結論，不宣稱穩定 P90 或 flaky rate。
- 先通過全部正確性條件，再以實測最慢 Go job 較短的設定為候選；多樣本用中位數，只有一組則標為初步結果。差異落在已觀察樣本波動內時選較少 shards；單一樣本也不足以支持繼續增加 shards。
- 若沒有觀察到最慢 Go job 縮短，維持原 package 路徑並保留量測工具，不宣告效能改善。總 runner 分鐘與 queue time 如實列出；本計畫不要求使用者另外核准抽象的成本門檻，也不以增加帳號額度解決量測問題。
- 若有多組資料顯示 2 shards 仍不平衡，可由 agent 以同一工具測試 3 shards，依前述規則選擇；調整為 3+3+1 時將 Go matrix 上限同步為 7，並重測 graph/設定契約，不讓第七個 entry 因固定上限而被迫等下一波。
- 包含完整對照 jobs 的 workflow wall time 會被對照拖長，必須標成對照 run；整體效益以階段 A 與 D 的可比正式 runs 判斷。若樣本不足或其他 jobs 波動，明列尚不能確認整體加速，不從 group 加速直接推算整個 workflow 的改善。
- 移除固定 20 分鐘內及快三倍的交付要求。最慢單一 top-level test、冷編譯、PTY build 與排隊限制列成量測結論；本次不擴張成 runner 採購或另一項 fixture 最佳化專案。

## 7. 回滾與交付

coding agent 必須測試可將設定中的 spec/cmd shard 數改回 1，使兩個 package 以完整模式執行；rest 範圍與額外 validations 不變，結果核對及 image gate 仍啟用。設定值 1 的完整模式須有真實 Go fixture 與 CI 契約測試，不依賴人工重寫 YAML；交付摘要應說明回滾測試的實際範圍，不將 fixture 驗證宣稱為完整 CI 回滾實測。

若問題來自新執行/核對工具，退回導入前的 package matrix 與 Makefile，連同 image dependencies、changes matrix output 及相關 assertions 一起還原；不得只刪結果 job 而留下可漏測的半套分片。

交付需包含程式、回歸測試、CI graph 差異、可追溯的完整/分片對照及最終 CI artifact 連結、量測摘要、設定與權重維護方式、回滾方式及其驗證範圍。保留失敗嘗試及限制，完整 logs 不塞回本文件。

正式結果綁定乾淨 candidate 的 revision/tree；任何執行相關修正形成新 candidate。測試輸出不得套用到不同 tree，亦不得為製造 evidence-only reuse 而移動程式/設定到 evidence 目錄。

本文件只定義可由 coding agent 完成的 repository 與 CI 工作。若實作時既有 GitHub 存取失效、Actions 需管理員核准，或 repository 新增 required-check 規則而必須調整管理設定，agent 應先完成不受影響的程式與測試，再列出具體受阻操作、所需權限與建議最小處理方式向使用者詢問；不自行新增 credential、提高額度或修改保護規則。

## 8. 參考

- [目前 CI workflow](../../../.github/workflows/ci.yml)
- [目前 package selector](../../../scripts/ci-go-test-packages.sh)
- [Makefile](../../../Makefile)
- [CI matrix/執行契約測試](../../../cmd/pilot/cmd/ci_shards_test.go)
- [Image dependency 契約測試](../../../cmd/pilot/cmd/ci_needs_test.go)
- [Candidate reuse](../../../scripts/ci-validation-reuse.py)
- [Go testing flags](https://pkg.go.dev/cmd/go#hdr-Testing_flags)
- [GitHub matrix 與 max-parallel](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/run-job-variations)
