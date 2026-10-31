# Pilot 歷史缺陷與 target 驗證

`issue-to-pr`、`pr-ready`、`pr-review-merge` 與 `pilot-code-review` 共用此檔。修復或審查 pilot 時先讀，再選與 diff 有關的列；
不把所有歷史案例都變成每次必跑的測試。現行 `AGENTS.md`、
`docs/actual-run-evidence.md` 與需求是規則來源，歷史留言只是選題線索。
案例記錄截至 2026-10-30，**不代表各 PR 目前仍有同一缺陷**。

## 先建立能驗證的問題

1. 固定 repo、base/head SHA、操作入口、預期 target 與 acceptance invariant。
   用變更路徑的 Git log、修正 commit、PR 留言與未解決 threads 找過去的失敗，
   檢查相鄰 caller、共用 include 與平行 backend；不只讀最後一則「已修正」。
2. 保存 finding ledger：`id, class, origin, trigger, invariant, fix_sha,
   regression, counterexample, status`。再次出現同 class 就先讓 SA 盤點受影響
   路徑與測試矩陣，再實作 class 層級修復；不要依每則新留言追加一個字串特例。
3. 把 regression 的 oracle 寫成外部行為。適用時在唯讀 scratch 複本
   （例如 `git archive`，不是 item 的 worktree）撤回修復或做單點 mutation，確認測試會因**指定 invariant**失敗；編譯失敗、
   缺工具、權限錯誤或另一道 gate 先拒絕，都不是該 regression 的負向證明。
4. 分開記錄「結構檢查」「真實工具 harness」「完整產品入口」「VM 原生服務」。
   harness 使用抽出的 task、fake executable、合成輸入或 fault shim 時明列邊界。
   CI 綠燈不能證明 `LookPath`/環境 gate 後的測試未被 skip；查實際執行數與版本。

## 依變更選檢查

| 變更 / 失敗類別 | 要證明的 invariant 與反例 | 歷史依據 |
|---|---|---|
| tags、跨 playbook prerequisite、check mode | **本次被選取的 tasks**確實會建立前提；group membership 不等於 install plan。比較 standalone、site import、component/row tags、dependency 合成 tags、相關 `--skip-tags` 與 full run；確認 marker 的 tags/OS 條件一致、不被 fact cache 或前一次 include 污染。preview 不建立服務時不能假裝已驗證依賴；real apply 仍須 fail closed。 | [#184 group→task selection](https://github.com/kjelly/pilot/pull/184#issuecomment-6500691661)，修復 `8cc5b2af` |
| 狀態 snapshot、upgrade、backup、rescue | 在 mutation **之前**取得有效舊狀態；「unit 不存在」與「query 失敗」不同。對必要 probe 的失敗不能吞錯後繼續。測 probe 失敗、mutation 前/後失敗、tag 排除備份來源；以 active/enabled、舊 binary hash、DB integrity、有效設定及可用性驗證回復。早期拒絕本身不能進 rescue 把原本健康服務停掉。`rc!=0` 且資料還原不等於可用性已恢復。 | [#190 skip-C1](https://github.com/kjelly/pilot/pull/190#issuecomment-6501029037)、[query-error](https://github.com/kjelly/pilot/pull/190#issuecomment-6511529237) |
| 原生設定 parser / rewrite / validator | 先讓原生工具接受輸入，再證明輸出只有預期語意差異。涵蓋 header 與 script/heredoc context、註解/終止符、quoted token/backslash、等價格式。驗證 **distro 原 policy + managed fragment 的合成配置**與 effective path set；單檔 rc0、awk rc0、changed=0 都無法排除 duplicate 或檔名被改壞。需要支援多 awk 時驗證對應實作。 | [#188 endscript](https://github.com/kjelly/pilot/pull/188#issuecomment-6494546364)、[semicolon](https://github.com/kjelly/pilot/pull/188#issuecomment-6500696399)、[heredoc/quoted path](https://github.com/kjelly/pilot/pull/188#issuecomment-6511462614) |
| vault、target_group、stage、診斷 | 追查最後實際 argv 與 Ansible precedence；測省略/明示旗標、衝突 `-e @file`、play vars 與多 host group，驗證實際 hosts/recap，不接受 no-hosts exit0。秘密安全用合成 sentinel 測 stdout、stderr、health JSON、callback/verbosity；未知工具訊息不能當作安全原文，key=value regex 不會遮蔽 prose 裡的秘密。 | [#187 scope](https://github.com/kjelly/pilot/pull/187#issuecomment-6496877966)、[diagnostic leak](https://github.com/kjelly/pilot/pull/187#issuecomment-6503233619)，stage 修復 `2d706709` |
| lock、journal、cleanup、交易 | 鎖住實體資源 identity 與完整 probe→mutate→rollback 期間；測 symlink/hardlink、另一 writer 建檔、程序結束與 namespace。PID、路徑字串與 Go race PASS 不能取代 flock/transaction 的 invariant；cleanup 不得刪除其他 live owner 的資料。 | #146：`58847c24`、`a64e33c7`、`5f814f13`、`b07fd542` |
| 主機探索、啟動時限、遠端服務 | 用實際 enrollment server / 可觀察 readiness，而非設計上應該可用的 DNS 或任意 timeout。需要時測 fresh boot、慢啟動、永不就緒的有界失敗、multi-node 真實連線；不能把增加 timeout 當作已證明原始自然故障。 | #191 `9b81c591`、#192 `f8d85c08` |
| gate / 回歸測試 / evidence | 每道拒絕測試確認拒絕原因；錯誤碼與輸出內容一起約束，確認 counterexample 能觸發測試。區分 repo-wide lint 的掃描邊界、exception 與真實 task selection；測試要讀新路徑。 | #155 `9ab3d55e`、#146 `4b97aded`、`22cad092` |

更細的 pilot 檢查依變更選讀
[pilot-code-review](../SKILL.md) 及其 references；不要複製一份
AGENTS 規則到每個角色。每個新 candidate 仍須確認當前 API、工具與 inventory。

## 何時用 vm-target

SA/Root 在派 Coder **之前**，Reviewer 在給結論**之前**，都要明列
`target_validation = required | not-needed | blocked`、理由與待證明 invariant。
此欄記在 checkpoint / review artifact；它是人工判讀契約，並非既有 Python gate
新增且已機器驗證的 JSON 欄位。`blocked` 不能當成 `not-needed`。

- **required**：repo 規則或使用者要求 actual run；或變更承諾取決於真實
  systemd/service availability、fresh 安裝/check mode、upgrade/migration、
  rollback、容器 mount/reload、FreeIPA enrollment/automount/跨 host 授權、
  deploy/reconcile 的 target selection，而現有 candidate evidence 未覆蓋。
  用符合支援 OS/拓樸的 vm-target 驗證有疑慮的路徑；多 playbook/host 依賴用 topology。
- **not-needed**：例如文字/skill 配置，或 parser/純 Go 變更能以真實原生工具、
  CLI/integration test 證明相關 invariant，且無 repo 強制 target run。
  記錄工具版本、實跑範圍與未涵蓋內容；不要為「有跑 VM」而開無關環境。
- **blocked**：KVM、映像、必要硬體/服務、權限或時間預算使所需驗證無法完成。
  保存已取得的證據，列明缺口；修復流程保持 Draft。單純 review 回報
  `Needs Discussion / 未完成驗證`，不憑疑慮宣稱 confirmed defect 或完整 Approve。
  容器/本機 harness 可補證據，但不可冒稱 VM/systemd/GPU/真實上游驗證。

### Target run 的必要邊界

1. 用專用且唯一命名的 disposable target，先列現有 VMs，讀實際 inventory
   確認 hosts/groups/stage。只對自己建立的 VM/snapshot 注入故障與清理；
   使用者既有環境與真實主機不因 skill 自動取得 mutation 授權。延用已有授權，
   只有目標、風險或副作用超出範圍時才請使用者決定。
2. 從該 candidate SHA 的乾淨、唯讀 `git archive` scratch 複本執行（滿足 AGENTS.md §1.5；
   不是 item 的 worktree，也不是目前 checkout），記 commit/tree、執行檔案 hashes、
   image digest、工具版本與 inventory facts。對外部合成 vars/fixtures/fault
   shim 也記錄內容 fingerprint 與用途，不能用修改 production source 的 overlay
   聲稱測過原始 HEAD。開發快測允許 dirty；正式證據不允許。
3. 優先用 `pilot vm-target test`，或多機的 `pilot vm-target topology test`
   對真正全新 target 跑 syntax → check/diff → apply → committed spec verify →
   第二次 apply `changed=0`。跨 playbook 排序用 fresh/ephemeral topology。
   依當前 CLI `--help`、repo 規則與 target skill 組命令，不從歷史複製旗標/主機名；
   只有合法不支援 check mode 的情況才明說理由跳過，不能為了綠燈規避。
4. 再跑與缺陷相關的失敗路徑。HEAD/BASE 對照要從相同 healthy snapshot、
   相同 selector/vars/故障點起跑；不在 HEAD 改過的主機上直接跑 BASE。記錄
   預期失敗 rc 與回復後 invariant。一次性 fault injection 不是觀察到自然故障；
   同 source 不同版本標籤的 binaries 不是跨版本 DB migration 證明。
5. 正常全鏈成功與故障回復分開給結果；fixture/fake upstream 與原生 daemon
   各自說清楚。保存原始輸出到 repo 允許的暫存位置，sanitized 摘要依
   `docs/actual-run-evidence.md` 紀錄；spec/runbook 更新 latest 摘要與連結，
   不累加 transcript、不因失敗放寬 Expected。不得先寫未跑過的 SOP。
6. 執行相關內容有變就形成新 candidate，重跑受影響驗證；舊 PASS 不沿用。
   結束清理自己的 target，確認遠端 PR HEAD/base 未移動再給 Ready/審查結論。

完整 target 操作可選讀
[vm-target-spec-testing](../../vm-target-spec-testing/SKILL.md)，以現行 AGENTS
與 actual-run evidence 規則為準；舊教學中的預期輸出、逐步手跑或 transcript
貼法不能凌駕目前的 candidate/test-chain/evidence 規則。

## 可直接放進 task envelope 的提示詞

### SA / Coder

> 先讀目前 AGENTS、actual-run evidence 規則與 pilot-history-checks，再回看這些
> 變更路徑的 Git 修復和 PR review。列 trigger → violated invariant → root cause，
> 並盤點同 class 的 caller/include/backend。先定 acceptance/oracle，再修實作；
> 不放寬 spec。決定 target_validation（required/not-needed/blocked）及理由。
> 如需 vm-target，用專用 target 與乾淨 candidate，依實際 inventory 跑 fresh
> check/apply/verify/idempotency，另測本次 tags、probe-error 與 rollback 邊界。
> 需要 BASE 對照時還原相同 snapshot。回報 candidate/tree、命令、工具版本、
> 真實執行/skip 數、counterexample、回復後 effective state、artifact 與限制。
> 只使用 Root 指派且已驗證的 checkout（不建立 worktree、不切換 branch）；你不是唯一工作者，不回退別人的改動。只有 Root 操作
> push/PR lifecycle；未授權 review 不自行啟動 target mutation。

### Independent Reviewer

> 不信任 Coder 的 PASS 摘要。讀 exact base/head 的 diff、舊 finding ledger 與
> 關聯修復歷史，確認修正前反例能被現有 regression 擋住。特別查本次 task
> selection 而非 group 意圖、有效 probe snapshot、早拒絕/rescue 是否保留
> 服務可用性、原生 parser 合成配置與秘密輸出邊界。分開 bug 與 evidence gap；
> origin 以 PR base 判斷，前一輪漏看不是 pre-existing。對原生服務仍有疑慮時
> 提出並在已授權範圍執行 vm-target 計畫，否則交 Root 處理；不要把必要而未跑
> 的情境列為 PASS。回報完整 coverage、file:line/trigger/impact、BASE/HEAD
> 對照、typed findings、target_validation 理由、驗證層級及明確未測限制。
