# FreeIPA Go reconcile — Phase 2 使用者與群組寫入 MVP 規格

日期：2026-11-06。對應計畫：`docs/superpowers/plans/2026-10-15-freeipa-go-ssh-reconcile.md` Phase 2。前一階段：`docs/superpowers/specs/2026-10-30-freeipa-go-reconcile-phase1-spec.md`（下稱 P1 spec；目前驗收紀錄見 [LATEST](../../evidence/freeipa-go-reconcile/LATEST.md)）與 `docs/superpowers/specs/2026-10-16-freeipa-go-reconcile-phase0-contract.md`（P0）。

狀態：草稿（P2-0，只有文件）。沒有任何 Phase 2 的程式碼，也沒有任何實跑。規格由 2026-11-06 對 main `402ca398`（含 Phase 1，PR #255）的設計審查整理而成，文中的檔案與行號都是那個 commit 的樣子；行號會漂移，實作與 lint 以符號與 task 名稱為準，不寫死行號。

**讀法：每一項都標明它是什麼。**

- **決定 Dn**：這份規格已定下，實作照做；§3 是總表，細節在各節。
- **補充**：設計審查沒有寫、這份規格為了讓行為完整而補上的決定，review 時請特別看（§14 列出全部）。
- **待使用者確認 Un**（§12）：附有設計審查的預設值與它的後果，**不是已確認的決定**。未確認前實作不得假設它們已成立；U1 擋住 P2-2 的合併。
- **未決 Qn**（§13）與**未知 Xn**（§1）：還沒有答案，各自寫明由什麼擷取、量測或誰的回答解決。

本文件不提供操作 SOP。文中的指令、旗標、檔名與 JSON 欄位是要實作的介面（欄位名稱為擬議），不是已實跑的步驟。AGENTS.md §4.0 的資料夾表**不在這個 PR 修改**（入口 playbook 還不存在），P2-3 新增該列（§5.1）。

## 0 範圍

Phase 2 交付 users／groups 範圍的**寫入**，以及讓它安全的前置條件：

- **取鎖閘門**：所有會執行 `freeipa-identity-apply.yml` 的非測試程式碼路徑，在漏斗處取得 FreeIPA server 的 `/etc/ipa` 遠端鎖（§4）。這是 Phase 2 對既有使用者最明顯的行為變更（`pilot deploy`、`pilot reconcile`、`pilot access`、`pilot host decommission` 的 identity 路徑都會取鎖，並對不支援的 inventory 形態拒絕執行），不只影響 opt-in 的 Go engine；其餘變更在變數未設、或沒有未列出的 outcome 時行為不變。
- **#138 授權快取入口與探測**：由 Ansible 在 Go 寫入前把義務寫進 FreeIPA 主機的 journal，或唯讀探測既有義務（§5）。
- **未結清結果**：義務沒有結清的 run 一律不是成功（§6）。
- **Go writer**：寫入前重讀、stage 與 batch、逐項分類、驗證、journal、密碼、lifecycle 與刪除保護（§7）。
- **入口**：`pilot reconcile --component freeipa-identity --engine golang --scope users-groups|full --force`；`users-groups` 不執行 playbook，`full` 是混合執行（§8）。
- **驗收與效能**：live driver、`TestLiveGoApplyDriver` 的各個 arm、計畫 §6 的數字（§10）。

不在 Phase 2：

- SSH key 的變更與 client 快取收斂：Go 只讀、只在 plan 報告，留在 #138 的區塊（計畫 Phase 1「與 PR #138 的關係」，決定不變）。
- users／groups 以外的 section（hosts、hostgroups、netgroups、HBAC、sudo、NFS、grants、auth／account／password policy）：仍由 Ansible 處理（Phase 3）。
- P1 spec §7.3 的 `blocked` 原因沒有一個改為「支援」：uid／gid 變更（需要明確確認的設計）、external 群組（K2 已擷取形態，但寫入 external 成員屬於 trust 範圍）、live type 不符、preserved 同名、marker 衝突、大小寫衝突、引用 absent 物件，全部維持 `blocked`（§7.9）。legacy roster（沒有 `schema_version`）仍交舊 engine。
- 互動 wizard、`--actions`、MCP、`--ask-vault-pass`（Phase 4）；預設 engine 的切換（Phase 4）。
- 上線授權與對正式環境的任何套用：這份規格涵蓋的所有寫入測試只在拋棄式 FreeIPA 測試 VM 上執行。

## 1 假設、未知、風險與 destructive 邊界

AGENTS.md §0.2 要求明列；沒有列出的項目不是「沒有」，是尚未發現。

### 1.1 假設

| # | 假設 | 依據 |
|---|---|---|
| A1 | 只支援 FreeIPA 4.13.4／API 2.257 | P0、P1 實測；`freeiparpc.DefaultSupportedAPIVersions`（`internal/freeiparpc/client.go:35`） |
| A2 | pilot 所有入口使用的 SSH 身分都能對 `/etc/ipa` 取 `flock`（唯讀開啟即可，不建立檔案） | P0 決定與實測（`internal/sshdial/lock.go:15-19`）；只在 FreeIPA 4.13.4 的 EL 主機實測過 |
| A3 | 一輪綁定同一台寫入 server，不在中途切到 replica | 計畫 §3 |
| A4 | 控制主機上 pilot 與它啟動的 ansible-playbook 是同一個使用者，入口的結果檔是該使用者的 `0600` 檔 | 入口設計（§5.4） |
| A5 | roster 與 vault 的讀法、stage gate 與 P1 spec §2–§3 相同 | P1 spec |
| A6 | live 寫入測試只在拋棄式 VM 上做，每個 candidate 用全新 VM、失敗修正後形成新 candidate | AGENTS.md §1.5 |

### 1.2 未知

| # | 未知 | 怎麼解決 |
|---|---|---|
| X1 | 正式環境的 inventory 形態：freeipa-server 主機是否用 ProxyCommand、密碼 SSH、docker／local connection 或不在 allowlist 的 `-o` | **操作者檢查正式 inventory**；U1 的前提，P2-2 合併前必須完成 |
| X2 | 正式環境的 SSH RTT 與 FreeIPA 版本 | P2-8 量測，接入前確認（計畫 Phase 0 已列） |
| X3 | 寫入回應的真實形態（`passwd`、刪除、`group_mod`、marker、重複、batch 部分失敗…） | §9 的 K6–K15 擷取；擷取前不寫 fixture、不寫判讀 |
| X4 | 入口在 `no hosts matched`、task 被 `when` 跳過、多台主機時 ansible-playbook 的真實輸出；controller 端 `copy` 結果檔的行為 | §9 的 K16、K17 |
| X5 | pilot 被 SIGKILL 或當機時，legacy 路徑啟動的 ansible-playbook 子行程是否仍在執行（預期會：它們沒有隨 pilot 結束的機制；未實測）。若會，鎖已隨 ssh 結束而放掉，另一輪可以在它結束前取鎖 | P2-2 的 live arm L7 只**記錄**行為，不判定通過；殘餘風險（R3） |
| X6 | client 上舊授權在 SSSD 快取下實際延續多久 | 計畫已列為未實測；不影響 Phase 2 的正確性規則（未結清就回報，不依賴這個數字） |

### 1.3 風險

| # | 風險 | 處理 |
|---|---|---|
| R1 | 混合執行改 `cmd/pilot/cmd/deploy.go`，AGENTS.md §5.5 列為最高風險檔案 | hook 只對 identity 元件生效；新增行為測試；全量路徑 live 跑（H1–H5） |
| R2 | legacy 漏斗掉鎖時只殺 ansible-playbook（`exec.CommandContext`），孫行程握著 pipe 時返回會被拖延（#261 第 2 項） | 不在本階段修；P2-2 記錄 |
| R3 | 鎖只約束 pilot 的程式碼路徑：手動 `ansible-playbook`、dev 路徑（`vm-target run`／`vm-target test`／`topology test`）、不經 pilot 的 IPA 管理工具、X5 的情形 | 計畫的殘餘風險；`pilot` 輸出與文件要寫明這個前提（§8.6） |
| R4 | `users-groups` scope 在 `inventory.yml` 落後 `hosts.yml` 時拒絕（唯讀，P1 spec §2.2 步驟 2），混合路徑則照 Ansible engine 現況重新產生（可能 migrate roster）；「inventory.yml 是否最新」有三份實作（#277） | 不在本階段統一；兩種行為都寫進輸出 |
| R5 | 入口之後的 Plan₂ 可能比 Plan₁ 多出操作（外部 writer） | 執行 Plan₂ 是安全的（入口已執行）；差異回報為 `conflict`（§7.2） |
| R6 | 入口的單一 JSON 結果檔靠 controller 端 `copy`（`delegate_to: localhost`）；`become` 與連線形態可能影響 | K17 擷取，P2-3 實跑 |
| R7 | `partial_failed` 的 webhook 沒有 `confirmed_effects`（`completedComponentIDs` 只算 `success`，`cmd/pilot/cmd/outbound_workflow.go:121-127`），訂閱者看不到已提交的 users／groups 變更；`application_consistency` 是 `partial_or_unknown` | 接受並記錄（Q4） |
| R8 | server 端先放掉鎖、client 還沒注意到（sshd 的 ClientAlive 設定）：`Lost()` 看不到 | 文件記錄；lock 的 ssh 帶 `ServerAliveInterval=15`、`ServerAliveCountMax=3`（§4.2）縮短反方向的偵測時間 |

### 1.4 destructive 邊界

Go 在 Phase 2 才第一次送出寫入 RPC。每一項都有對應的保護，細節在 §7：

| # | 操作 | 邊界 |
|---|---|---|
| B1 | `user_del`（永久刪除，不帶 `preserve`，與 playbook 相同） | 只刪 roster 宣告 `state: absent` 的使用者；刪除前即時重讀；blocked 或保護物件一律不刪（§7.9、§7.10） |
| B2 | `group_del` | 只刪 roster 宣告 `state: absent` 的群組；marker 必須先存在且描述正確（§7.3 S8） |
| B3 | `group_remove_member`（authoritative 撤銷，包含 roster 以外的使用者；沒有 `membership` 區塊的群組等於空集合，P1 spec §5.2） | plan 已用 `implicit_membership_prune` 報告；與 playbook 語意相同 |
| B4 | `passwd`（重設不可逆，也無法讀回比對） | 每位使用者一次呼叫、不進 batch、不重送；結果不明就 unknown（§7.5、§7.8） |
| B5 | `user_disable` | 與 playbook 相同；自鎖保護見 U3 |
| B6 | 入口把 FreeIPA 主機上的 `auth_pending` 設為 true | 這是義務，刻意持久化；沒有寫入就不執行入口（§7.2） |
| B7 | 取鎖閘門讓既有入口對不支援的 inventory 形態拒絕執行 | 行為變更，待使用者確認（U1） |
| B8 | 沒有自動 rollback | Go 的寫入是 reconciler 效果，失敗後以「重讀、重算」重跑收斂；不 fallback 到舊 playbook（計畫 §4） |

## 2 不變量

每個 PR 都要讓下面七條保持成立；測試與 lint 針對它們設計。

- **I1 序列化**：每條會執行 `freeipa-identity-apply.yml` 或新入口的非測試程式碼路徑，從「確認之後」到該次執行（含冪等性再套用、verify、rollback）結束，持有該 FreeIPA server 的 `/etc/ipa` 遠端鎖。一輪只取一次；混合 run 沿用已持有的鎖，不重新取。dev 路徑（`vm-target run`／`vm-target test`／`topology test`）不在範圍，lint 的註解寫明理由（計畫 §4 步驟 2）。
- **I2 執行器**：沒有任何寫入 RPC 離開 pilot，除非 (a) 這一輪的鎖已持有且沒有掉，(b) 這一輪對**已上鎖主機**的入口結果已被觀察到。由 `freeiparpc` 的 WriteGate 結構性保證，不靠呼叫端的紀律（§7.1）。
- **I3 入口觸發**：入口只會接在「非空且沒有 blocked 的 Plan₁」之後；空的 Plan₁ 不執行入口（改做唯讀探測）。入口之後才寫入，寫入集合取自 Plan₂（它是權威）。入口執行後 Plan₂ 為空是允許的（多刷新一次，無害），在 `users-groups` scope 它算義務未結清。（補充：設計審查原本寫「入口執行若且唯若最終寫入集合非空」，與它自己的流程——入口在 Read₂ 之前——不一致，這裡改為與流程一致的寫法；§7.2。）
- **I4 永不成功**：Go 有寫入（或入口已執行）、但沒有觀察到該主機的 `acked=true` 的 run，以及探測讀到 `pending=true` 的 run，**不是成功**：結束碼非 0、outcome 是失敗類（義務未結清是 `partial_failed`，§6）、webhook 的 `result` 為 `failure`、不被 `store.LastSuccess` 當成成功。
- **I5 混合略過**：引擎變數為 `go` 時，任何 `--tags` 下都沒有 users／groups 的 mutation task 執行；SSH key 區塊與授權快取 task 照常執行；變數未設時行為與今天逐位元組相同（§8.4）。
- **I6 秘密**：密碼、cookie、vault 內容不進 argv、環境、plan、結果檔、delivery 事件、log。
- **I7 fail closed**：任何 `blocked` 項目或不支援的輸入，都是零寫入、沒有入口；混合 run 在這種情況下也不執行 playbook。

## 3 決定總表

| # | 主題 | 決定 | 詳見 |
|---|---|---|---|
| D1 | 取鎖位置 | 在漏斗處、確認之後、第一次執行之前；一輪一把鎖；混合 run 沿用已持有的鎖 | §4.5 |
| D2 | 取鎖包裝 | 新套件 `internal/identitylock`；`Acquirer` 由 `cmd` 建好注入，各漏斗的 options 必填，nil 即錯誤 | §4.1 |
| D3 | target 推導 | host 取 inventory 名稱、剛好一台；推導函式下沉到 `internal/sshdial/hostvars.go`；不支援的 inventory 形態拒絕執行，不退回無鎖（U1） | §4.2 |
| D4 | 等待策略 | CLI 漏斗最多等 30 分鐘並每 30 秒印一行；`pilot reconcile --lock-wait`；TUI breakglass 等待 0；Phase 2 不提供略過（U2） | §4.3 |
| D5 | 掉鎖 | 舊漏斗取消 ansible-playbook 並回報；Go writer 每批前檢查；`Held.Lost()` 只在沒有 Release 的結束時關閉 | §4.4 |
| D6 | 全 repo lint | 引用 allowlist、具名漏斗 AST 檢查、contract 守衛，附變異驗證 | §4.6 |
| D7 | 交錯測試 | 用真實 helper 重現清除交錯與覆蓋交錯；先於任何 live Go 寫入通過 | §4.7 |
| D8 | 入口名稱 | `playbooks/apply/freeipa-identity-auth-cache.yml`，單檔兩模式 `prepare`／`probe`；AGENTS.md §4.0 的列由 P2-3 新增 | §5.1 |
| D9 | 探測 | helper 新增唯讀動作 `auth_inspect`（計畫選項 (a)） | §5.3 |
| D10 | 入口結果 | controller 端 JSON 結果檔，取代計畫擬議的 stdout `AUTH_CACHE[…]` 標記 | §5.4 |
| D11 | 觀察 | identity playbook 為 ack task 加 `register`，結尾加一個 `always` 的觀察 task | §5.5 |
| D12 | 共用輸入 | journal 路徑、`ipa_domain`、helper 原始碼同檔、同表達式，靜態與 runtime 一致性測試 | §5.6 |
| D13 | 未結清結果 | 使用既有 `delivery.OutcomePartialFailed`，新增 sentinel `delivery.ErrPartiallyApplied`，不新增 outcome | §6.1 |
| D14 | 結束碼 | 0 成功、1 失敗（含 unknown、partial）、3 blocked（P1）、4 只剩義務未結清 | §6.3 |
| D15 | outcome 讀取者 | 每個 outcome 明列，未列的不再被發布成 success | §6.4 |
| D16 | WriteGate | `freeiparpc.Config.WriteGate`，非唯讀客戶端沒有它就拒絕建立 | §7.1 |
| D17 | 流程 | Read₁→Plan₁→（入口）→Read₂→Plan₂→stages→Read₃→Plan₃ | §7.2 |
| D18 | stage 與 batch | 八個 stage，每個 batch 只放互相獨立的操作，上限 25 個 | §7.3 |
| D19 | 分類與重試 | 五類結果；寫入不重送；unknown 不重送、靠重讀分類 | §7.4、§7.5 |
| D20 | 驗證 | 重讀整份、Plan₃ 不得再有已嘗試物件的操作 | §7.6 |
| D21 | journal | 存在 delivery store 的 run 事件，不含秘密；不從 journal 續跑 | §7.7 |
| D22 | 密碼 | 值只在執行時由記憶體中的 roster 取出；值的形態由 yaml.Node 判斷 | §7.8 |
| D23 | lifecycle 與保護 | absent 為永久刪除；blocked 原因不變；Go 只碰 roster 物件、marker 與 roster 群組的直接成員；不支援的內容在寫入前拒絕 | §7.9 |
| D24 | 自鎖保護 | 新 blocked 原因 `protected_object`（U3） | §7.10 |
| D25 | #273 | 先修：adapter 對型別錯誤的 `membership`／`password`／`ssh_keys` fail closed | §7.9 |
| D26 | CLI | `--scope users-groups\|full`、`--lock-wait`、`--result-out` | §8.1 |
| D27 | users-groups scope | 自己的 delivery run，不執行 playbook，結果義務未結清時結束碼 4 | §8.2 |
| D28 | 混合 | 重用 Ansible reconcile 路徑，hook 只對 identity 元件生效 | §8.3 |
| D29 | skip 變數 | `pilot_identity_users_groups_engine`（不用計畫擬議的 `identity_users_groups_engine`） | §8.4 |
| D30 | 輸出與秘密 | stdout 摘要、`--result-out`（`pilot.identity-apply/v1`）、`--plan-out` 與它同一個 #274 修正 | §8.6 |

## 4 取鎖閘門

### 4.1 套件與 `Held`

**決定 D2。** 新增 `internal/identitylock`：

- `type Acquirer func(ctx context.Context) (*Held, error)`。
- `Held`：`Host`（inventory 名稱）、`Lost() <-chan struct{}`、`Release() error`、`Bind(ctx) (context.Context, context.CancelFunc)`；`HeldFrom(ctx)` 取出 ctx 上的 token。
- `Bind` 產生的 ctx 在鎖掉了時以 cause `ErrLockLost` 取消，並帶著 token（Go 的 WriteGate 用它，§7.1）。ctx 在取鎖之前就已交給下游的漏斗（deploy 的 `RunResult`，§4.5）改在取鎖後以同樣的語意對它的 `CancelCauseFunc` 通知；實作形狀由 P2-2 決定，行為由 §4.4 的測試鎖住。

**`Held.Lost()` 只在「沒有 Release 的結束」關閉。** `sshdial.Lock.Lost()` 回傳 `p.done`（`internal/sshdial/lock.go:110`），它在 ssh session 因任何原因結束時關閉，包括 `Release`；而它的 doc comment（`:108-109`）寫「without Release」。**不改 `sshdial`**：`internal/sshdial/sshdial_test.go:276-278` 斷言 `Release` 之後 `Lost` 是關閉的（失敗訊息 `Lost is not closed after Release`），改它會打破 P0 的測試與已實跑的行為。`Held` 在呼叫 `Release` 前先記下「已釋放」，只在未釋放時才把 `Lost` 轉成自己的訊號；P2-2 順手把 `lock.go:108-109` 的 doc comment 改成與實作相符。

`accessgrants.{Reconcile,Activate,Deactivate}Options.Lock` 與 `FreeIPAClientProviderConfig.IdentityLock` 是**必填**：nil 在任何執行之前回傳錯誤，新的呼叫者不可能漏掉。

### 4.2 target 推導

**決定 D3。** 取鎖要 `sshdial.Target`。三個漏斗各自解析主機與 hostvars，由 `cmd` 建好 `Acquirer` 後注入（`resolvePatternHosts` 與 snapshot helper 都在 `cmd`，`internal/accessgrants` 與 `internal/decommission` 不依賴它們）：

| 漏斗 | 主機解析 | hostvars |
|---|---|---|
| deploy runner（identity 元件） | `deploymentAppliedHosts(applied, scope, execScope.Included)`（`cmd/pilot/cmd/deploy_dependency_plan.go:119`；`scope` 由 `resolveDeploymentScope` 產生，已含 `target_group` 覆寫與 `--limit`，`deploy.go:2358`、`:2417`；`execScope.Included` 帶 availability） | `loadDeployInventorySnapshot`（`deploy.go:2539`） |
| `accessgrants.applyPlan`（`internal/accessgrants/reconcile.go:459`） | `ansible freeipa-server -i <inv> --list-hosts`（`resolvePatternHosts`，`cmd/pilot/cmd/deploy.go:2640`）；`applyPlan` 傳給 ansible-playbook 的只有 playbook、`-i`、`-e @file` 與選用的 vault 密碼檔，沒有 limit、沒有 `target_group`（`:489-493`） | `ansible-inventory --list` |
| decommission converge（`freeipaIdentityConvergeStep.Execute`，`internal/decommission/providers/freeipa_client.go:456`） | 同上，對 `ServerInventory`（`cmd/pilot/cmd/host_decommission.go:594`）；額外參數只有 roster 與 vault 的 `-e`（`:710-722`），沒有 limit 或 `target_group` | 同上 |

規則：

- **host 是 inventory 名稱，剛好一台**（AGENTS.md §5.13：`ansible_host` 是連線位址，不是身分）；不是剛好一台，在任何 ansible-playbook 之前拒絕。
- 把 `sshTargetFromHostVars`、`sshOptionArgs`、`splitShellWords`（連同 `unsupportedSSHHostVars`、`multiplexOptions`，`cmd/pilot/cmd/reconcile_golang.go:402-550`）搬到 `internal/sshdial/hostvars.go`，公開為 `TargetFromHostVars`。`// gate:` 註解隨函式搬走；ledger 的持有者清單（`cmd/pilot/cmd/reconcile_golang_ledger_test.go:49-56`）與每個 row 一起搬到 `internal/sshdial` 的對應測試，`TestReconcileGolangEveryGateHasARow` 的函式清單同步更新。規則與 P1 spec §4 完全相同：只接受 allowlist 內的 `-o`（`internal/sshdial/sshdial.go:48-55`）；`ansible_connection` 未設或 `ssh`；`ansible_ssh_args` 只准 `ControlMaster`／`ControlPath`／`ControlPersist`（忽略）；密碼 SSH、`ansible_ssh_executable`、舊名稱一律拒絕。
- 取鎖用的 ssh 另外帶 `ServerAliveInterval=15`、`ServerAliveCountMax=3`，除非 target 自己設了。
- **不支援的形態（`ansible_connection: docker`／`local`、ProxyCommand、密碼 SSH、不在 allowlist 的 `-o`）：拒絕執行，訊息指出是哪個 hostvar；永不「無鎖執行」。** repo 內的 topology 檔（`docs/topologies/*`）是 `vm-target topology` 的輸入（docker-target 沒有 topology 指令），vm-target 的 inventory 是 `ansible_connection: ssh` 加 `ControlMaster` 與兩個 allowlist 內的 `-o`（`internal/vmtarget/vmtarget.go:1488-1494`）；docker-target 的 inventory 是 `ansible_connection: docker`（`internal/dockertarget/dockertarget.go:618`），repo 內沒有 FreeIPA 角色跑在它上面。**這是行為變更：見 U1。**
- 已知缺口（與 P1 同類）：透過 `-e @file` 提供的連線變數，推導時看不到。

### 4.3 等待與失敗策略

**決定 D4。**

- 每個 CLI 漏斗最多等 **30 分鐘**（受 ctx 約束），每 30 秒在 stderr 印一行進度（哪台 server、已等多久、上限）。一輪完整 identity 約 26–27 分鐘（計畫 §1），所以 30 分鐘夠等一輪完整的 legacy 執行。
- `pilot reconcile --lock-wait <時間>`（兩個 engine 都有；`0` 立即失敗，driver 的忙碌測試用它）。`pilot deploy`、`pilot access …`、`pilot host decommission` 沒有旗標，用預設值。
- `pilot edit` 的 TUI breakglass（`cmd/pilot/cmd/edit_tui_roster_breakglass.go:164`、`:193`）是同步呼叫、`context.Background()`、沒有進度畫面，等待 **0**；錯誤訊息指向會等待的 `pilot access breakglass activate`。
- 忙碌：`ErrLockBusy`，訊息指名 server 與路徑。ssh 失敗：整輪失敗，**永不在沒有鎖的情況下繼續**。
- **不提供略過（bypass）**：略過會重新引入清除交錯與覆蓋交錯。安全的替代方案是計畫的選項 (iv)（`auth_pending` 加世代）。見 U2。
- **補充（`--timeout` 與等待）**：`pilot reconcile --engine golang --force` 的 `--timeout` 分段計算：取鎖之前的 preflight 在自己的期限內（沿用 P1 的 `--timeout` 語意）、取鎖等待由 `--lock-wait` 界定、取鎖之後的讀取、入口、寫入與驗證整段**重新**以 `--timeout` 計時。否則預設 30 分鐘的等待會吃掉整個 30 分鐘的執行期限。SIGINT／SIGTERM／SIGHUP 在任何階段都取消。
- **補充（`--lock-wait` 的適用）**：`--lock-wait` 只對會取鎖的執行（`--force`）有意義；與 `--preview-only` 同時使用即拒絕（預覽不持鎖），與 `--plan-out` 對 Ansible engine 的處理一致。

### 4.4 `Lost()` 處理

**決定 D5。**

- **會包 ansible-playbook 的漏斗**在 `held.Bind(ctx)` 之下執行 ansible-playbook：掉鎖就取消 run（ansible-playbook 被殺；#138 的 journal 設計為 crash-safe），然後回傳 `lock lost; FreeIPA may be partially reconciled; rerun`——即使 ansible-playbook 已經以 0 結束（交錯的另一輪可能已經動過）。
- **Go writer**：WriteGate 在每次寫入呼叫或每個 batch 之前檢查 `Lost`；已送出的 batch 的答案照實記錄；之後不再送任何寫入；驗證讀取（Read₃）照常執行（讀取不需要鎖）；結果是失敗，若已有 `success` 或 `unknown` 的操作則為 `partial_failed`（§6.1）。
- 驗證讀取用 `context.WithoutCancel` 加上有界的期限（**補充**，常數 `golangVerifyTimeout`，初值 60 秒；比照 P1 登出用的 10 秒），所以掉鎖、`--timeout` 與第一次 Ctrl-C 之後仍會嘗試讀一次；第二次 Ctrl-C 立即結束 pilot（P1 spec §2.5 已知限制 3）。讀取失敗就保留 unknown。
- 殘餘（R8）：server 端先放掉鎖、client 還沒發現的情形看不到；文件記錄。

### 4.5 時機

**決定 D1。** 鎖取在「確認之後、第一個會改動的執行之前」；預覽、唯讀查詢與互動確認的等待都不持鎖。

- **deploy runner**：在 `executeDeploymentTransaction` 的 `apply` closure 裡，確認分支之後（`cmd/pilot/cmd/deploy.go:1446-1460`）、`PrepareApply`（`:1461-1465`）之前取鎖；`txn.RunResult` 回傳後才釋放（涵蓋 verify、冪等性再套用、rollback）。傳給 `RunResult` 的 ctx 是 `WithCancelCause` 的子 ctx，掉鎖時後續步驟一併取消。`PrepareApply`（`deploy.go:1330`）目前沒有非測試的設定者，混合執行是它的第一個使用者（§8.3）。
- **`accessgrants.applyPlan`**：extra-vars 檔寫好之後（`internal/accessgrants/reconcile.go:481-487`）、`runner.Run` 之前（`:493`）。
- **decommission converge**：`Execute` 內、`e.provider.exec` 之前（`internal/decommission/providers/freeipa_client.go:477`）。
- **從不取鎖**：`--check` 預覽、唯讀 inspect 查詢（`--tags freeipa_host_absent_inspect`，`internal/decommission/providers/freeipa_client.go` 的 `query`，約 `:875-901`）、drift probe、Go `--preview-only`。
- **混合 run**：在 `apply` closure 取一次，`PrepareApply`（Go 的入口與寫入）與 playbook 都在這把鎖之下，不經過取鎖包裝重新取（同一把鎖不可重入，會死鎖）。

### 4.6 全 repo lint（AGENTS.md §5.10）

**決定 D6。** `cmd/pilot/cmd/identity_lock_funnel_test.go`，四部分：

1. **引用 allowlist**：對 `cmd/`、`internal/` 的非測試 `.go` 做 AST 走訪；凡是不含空白、且包含 `freeipa-identity-apply.yml` 或 `freeipa-identity-auth-cache.yml` 的字串 `BasicLit`，以及每個對 `accessgrants.DefaultPlaybook`（含 package 內的裸識別字）的引用，都必須在 allowlist 項目 `{檔案, 角色: 漏斗或資料, 理由}` 內。目前的項目：`internal/accessgrants/reconcile.go:30`（常數與 `applyPlan` 所在，漏斗）、`internal/accessgrants/breakglass.go:123`／`:187`（把它交給 `applyPlan`，漏斗輸入）、`cmd/pilot/cmd/host_decommission.go:596`（資料，接進 decommission 的漏斗）、`cmd/pilot/cmd/deploy_catalog.go:74`（catalog 資料）、`cmd/pilot/cmd/access_cli.go:86`、`cmd/pilot/cmd/access_breakglass_cli.go:88`、`:92`（旗標預設值，資料）。含空白的說明文字（例如 `cmd/pilot/cmd/roster_lint.go:27-28`、`cmd/pilot/cmd/edit_actions_registry.go:906`）依構造排除。
2. **具名漏斗 AST 檢查**（以函式與方法名稱比對，不比 receiver，因為漏斗經介面呼叫）：`applyPlan`、`(*freeipaIdentityConvergeStep).Execute`、`executeDeploymentTransaction` 的 apply closure、`executeRecordedDeploymentCore`（在 options 的字面值設 `IdentityLock`），以及 Go 的入口路徑。要求取鎖呼叫先於第一個執行呼叫（`runner.Run`、`e.provider.exec`、`runOnce(false…`）；執行 auth-cache 入口的函式必須接收 `*identitylock.Held`。注意 `--playbook` 可以覆寫（`cmd/pilot/cmd/access_cli.go:86`、`cmd/pilot/cmd/access_breakglass_cli.go:88`、`:92`），所以 `applyPlan` 裡的取鎖是無條件的。
3. **contract 守衛**：沒有元件的 `dependencies` 指向 `freeipa-identity`（目前確實沒有）；`freeipa-identity` 沒有 `canonical_apply` 的 remediation（目前只有 `contracts/alertmanager.yaml:35`）；`freeipa-identity` 維持 `site.include: false`（`contracts/freeipa-identity.yaml:65`）。之後任何一項被改變，測試失敗，直到那條路徑也取鎖。
4. 註解寫明 dev 路徑的排除與理由（I1）。

**負向對照**：lint 自己的表格測試餵合成原始碼（缺取鎖呼叫、取鎖在執行之後、新的未列入引用），比照 `internal/sshdial/start_lint_test.go`（`TestRegression_SSHStartsOnlyThroughStart`）；PR 附變異驗證的紀錄（拿掉任一漏斗的取鎖，lint 與 §4.7 的序列化測試都要 fail）。

### 4.7 交錯與順序測試

**決定 D7。** 下面的單元測試必須在任何 live Go 寫入之前通過（計畫 Phase 2 取鎖閘門）：

- `TestAuthCacheClearInterleavingWithoutLockLosesObligation`、`…OverwriteInterleavingWithoutLockLosesObligation`：驅動**真實**的 helper（`python3`、暫存 journal），照計畫「清除交錯」「覆蓋交錯」的精確順序，斷言混合 playbook 的 settle 時 `dirty=false`——這個危害是真的，它就是區別性對照：沒有鎖，義務確實被丟掉。
- `TestFunnelsSerializeAuthCacheObligation`：同樣兩種順序經兩個漏斗呼叫驅動，ansible-playbook 換成呼叫真實 helper 的假腳本，`sshdial` 的假 ssh 走 `local` 模式，鎖路徑用暫存目錄（`LockOptions.Path`）：第二個漏斗等待或失敗，義務存活到混合 run 自己的 settle 與 ack。拿掉任一漏斗的取鎖呼叫，它就 fail。
- 每個漏斗的順序測試（假 acquirer＋假 runner 記錄 `lock, run(--check), run(apply), idempotency, release`）；非 identity 的 deploy 元件從不取鎖；`--preview-only` 從不取鎖。
- 掉鎖測試（§4.4）：每個漏斗的 ansible-playbook 在掉鎖時被取消、結果仍是失敗（即使 ansible-playbook 以 0 結束）。

## 5 授權快取入口與探測

### 5.1 名稱與資料夾

**決定 D8。** `playbooks/apply/freeipa-identity-auth-cache.yml`。

- 與 identity playbook 同一個資料夾，所以 `lookup('file', playbook_dir ~ '/files/freeipa-ssh-key-cache.py')`（identity playbook 的 `ipa_ssh_cache_program`，`playbooks/apply/freeipa-identity-apply.yml:232`）讀的是**同一個檔案**：helper 原始碼共用是由構造保證的，不是靠比對兩份副本。
- 名稱不是 `*-apply.yml`：`validateApplyCoverage`（`internal/contract/lint.go:222-238`）與 `TestSpecPlaybookTagAlignment`（`cmd/pilot/cmd/tag_coverage_test.go:345`）都只看 `*-apply.yml`，所以不需要為它另建 contract、catalog 項目或 `site.yml` 條目（它不是 component，只由 pilot 的 Go 程式碼呼叫）。但 `playbooks/apply/*.yml` 的全 repo lint（stage gate、always 前置、收斂性、tagged 前置…，`internal/spec` 的各個測試以 `playbooks/` 或 `playbooks/apply/*.yml` 走訪）照樣適用，所以它必須帶完整的 AGENTS.md §4.3 gate。
- 為何不放 `playbooks/check/`：那個資料夾依慣例是唯讀（目前 4 支由 Go 呼叫的探測，`internal/freeipa/probe.go:5`），而入口要寫 journal。為何不放 `playbooks/decommission/`：它是 decommission 專用。AGENTS.md §4.0 的表目前**沒有** `playbooks/check/` 這一列，也沒有「內部入口」這一列。
- **AGENTS.md §4.0 新增一列由 P2-3 做**（入口那時才存在）：「`playbooks/apply/<component>-<purpose>.yml`（不是 `-apply.yml`）：只由 pilot 的 Go 程式碼呼叫的內部入口；沒有 contract；完整的 §4.3 gate」。`playbooks/check/` 缺列的問題不在這個階段處理。

### 5.2 一個檔案、兩個模式

**決定 D8（續）。** 必填變數 `pilot_identity_auth_cache_action`，值為 `prepare` 或 `probe`，**沒有預設值**。`pre_tasks` 的 gate 全部標 `tags: [always]`：

- AGENTS.md §4.3 的 stage／confirm／cross-check／prod attestation。
- `not ansible_check_mode`（入口不做預覽；與 identity playbook 的 `auth_prepare` 一樣要求非 check mode，`freeipa-identity-apply.yml:937-939`）。
- `(ansible_run_tags | list) == ['all']` 且沒有 skip tags（ansible-core 2.19 的 `ansible_run_tags` 是 tuple，AGENTS.md §4.3 第 7 點；入口不接受 `--tags`）。
- `ansible_play_hosts_all | length == 1`。
- `pilot_identity_auth_cache_action` 合法、`pilot_identity_auth_cache_output` 已設。

task：取 `hostname -f`；`prepare` 執行 helper 的 `auth_prepare`；`probe` 執行 helper 的 `auth_inspect`；最後把結果寫到 controller（`ansible.builtin.copy`，`delegate_to: localhost`，`become: false`，`0600`，`changed_when: false`）。

### 5.3 探測：helper 的唯讀動作

**決定 D9（計畫選項 (a)）。** 自 `4e774a95`（2026-11-03）起，helper 的 `journal()` 對 `inspect`／`plan`／`retirement_status` 已有不取鎖、不建立 sidecar lock、不寫檔的唯讀路徑（`playbooks/apply/files/freeipa-ssh-key-cache.py:269-296`），內容沒變的寫入也不重寫 journal（`:310`）。所以探測只需要：

- 把 `"auth_inspect"` 加進 `:269` 的唯讀動作元組；
- 在 `update`（`:125`）加 `if action == "auth_inspect": return {"auth_pending": state.get("auth_pending", True)}`。

語意：journal 不存在或沒有 `auth_pending` 欄位視為 `true`，與 `auth_prepare` 的 `previous` 預設相同（`:192-198`：從未記錄的 journal 無法證明先前的執行都刷新過）；domain 不符時 `update` 本來就會丟 `journal domain mismatch`（`:127-128`），探測因此 fail closed。唯讀路徑不建立任何檔案。P2-3 重跑 #138 helper 的既有測試；寫入路徑沒有動，不需要重做 #138 的 live 矩陣。計畫選項 (b)（直接讀 journal 檔）不採用：兩份判讀要靠一致性測試鎖住，而唯讀動作只有四行。

唯讀路徑讀的是 `0700` 目錄裡的 journal，所以探測與入口一樣要 `become`。

### 5.4 入口結果：controller 端 JSON 結果檔

**決定 D10。** Go 在每次執行前建立一個空的暫存檔（`secretpath.PrivateTempDir` 底下、`0600`；先例：`internal/freeipa/probe.go` 的暫存 extra-vars 與 output 檔，以及它「缺少、格式錯誤、自相矛盾一律 fail closed」的處理），路徑以 `-e pilot_identity_auth_cache_output=<路徑>` 傳入。task 把下面的物件寫進去（欄位名稱為擬議）：

```json
{
  "schema": "pilot.identity-auth-cache/v1",
  "action": "prepare",
  "host": "<inventory_hostname>",
  "fqdn": "<hostname -f>",
  "previous": true
}
```

`probe` 帶 `pending`（布林）而不是 `previous`；`observe`（§5.5，identity playbook 寫的）帶 `prepared`、`dirty`、`refreshed`、`acked`。Go 只在**全部**成立時接受：ansible-playbook 結束碼 0；檔案非空且只有一個 JSON 物件（後面沒有多餘資料）；`schema` 正確；`action` 與要求的相同；該 action 必要的欄位存在且型別正確；`host` 等於已上鎖的 inventory 主機；`fqdn` 與 `Dialer.FQDN()` 相同（不分大小寫）。檔案是空的（`no hosts matched` 以 0 結束時就是這樣）、來自別台主機、`action` 不符、解析失敗、多台主機的結果，一律是入口失敗：Go 不寫入。

**為什麼不用計畫擬議的 stdout `AUTH_CACHE[<host>]: …` 標記**：roster 控制的文字可以進到 loop label 與輸出，標記可被偽造；解析依賴 stdout callback 與格式；而且 #108 的「解析到另一台主機的區塊」這一類錯誤在單一結果檔下不存在。這是對計畫擬議的刻意偏離，記錄於此與 §14。

### 5.5 identity playbook 的觀察

**決定 D11。** 為了讓混合 run 判斷「這一輪有沒有結清」，identity playbook 增加兩處：

- 「Acknowledge legacy authorization cache recovery」（`freeipa-identity-apply.yml:4177-4198`）目前沒有 `register`；加上 `register: ipa_auth_cache_ack`。
- 在 block 內、`always:` 之前（最後一個 task 之後，約 `:4218-4219`）新增一個標 `always` 的 task，`when: not ansible_check_mode` 且 `pilot_identity_auth_cache_output is defined`，寫 `action: observe` 的結果檔。它讀的每個值都用 `is defined`／`default`（AGENTS.md §4.4）：`acked` 為 `ipa_auth_cache_ack is defined and not skipped and rc == 0`；`prepared` 看 `ipa_auth_cache_prepare`（`:925-940`）；`dirty` 看 `ipa_auth_cache_settle`（`:4028-4048`）；`refreshed` 看 `ipa_sudo_refresh_results`（`:4114-4147`）。legacy run 從不定義 `pilot_identity_auth_cache_output`，所以這個 task 被跳過，行為不變。

block 內較前面的 task 失敗時沒有觀察結果：那一輪本來就是失敗，混合 run 把它記為 playbook 失敗（§6.2）。

### 5.6 三個共用輸入

**決定 D12。** 入口與 identity playbook 共用：

1. journal 路徑：`ipa_identity_ssh_cache_state_file | default('/var/lib/pilot-identity/ssh-cache.json')`（contract 的 groupVar，`contracts/freeipa-identity.yaml:31`；identity playbook 內多處逐字重複，例如 `:932`、`:1477`、`:4184`，以及 `playbooks/apply/tasks/freeipa-ssh-cache-preflight.yml:25`）。
2. `ipa_domain`：`freeipa_domain | default('ipa.pilot.internal')`（`freeipa-identity-apply.yml:70`）。
3. helper 原始碼：`ipa_ssh_cache_program`（`:232`），同資料夾同一個檔案。

入口不在 play `vars:` 宣告 inventory 輸入（`ipa_identity_ssh_cache_state_file`、`freeipa_domain`，AGENTS.md §4.5 第 3 點）；`ipa_domain` 與 `ipa_ssh_cache_program` 以與 identity playbook 逐字相同的別名表達式宣告。

一致性測試（AGENTS.md §5.7）：(i) 靜態：入口與 identity playbook（含它 include 的 task 檔，至少 `freeipa-ssh-cache-preflight.yml`）中，journal 表達式、`ipa_domain` 表達式與 helper 表達式的每一處出現都逐字相同，且入口檔位於 `playbooks/apply/`；(ii) runtime：在 localhost 用真實 Ansible，對 {`freeipa_domain` 設／未設} × {`ipa_identity_ssh_cache_state_file` 設／未設} 求出兩邊的值並比對。負向對照：在 fixture 副本裡改掉一處預設值，兩個測試都要 fail。

### 5.7 入口的 Ansible 參數

入口的參數由 deploy 用的同一批 helper 建立（`ansibleExtraVarArgs`，`cmd/pilot/cmd/deploy_dependency_plan.go:51`；`vault.becomeArgs()`，`cmd/pilot/cmd/deploy.go:1294`），同一份 inventory、同一個 `target_group`（有的話），再加 `--limit <已上鎖的主機>`。`stage`、`confirm_staging`、`confirm_prod`、`staging_attested_within_hours` 在 Go-only 路徑由 `--stage` 與 `--staging-attested-within-hours` 經與 Ansible engine 相同的函式產生（`stageDecisionFromFlag`，`deploy.go` 內，不另寫一套）。Go-only 路徑用 `deployAnsibleCommand` 加 `withIsolatedChildren` 執行，享有 P1 spec §2.5 的子行程保證。

## 6 未結清結果

### 6.1 outcome

**決定 D13。** 使用既有的 `delivery.OutcomePartialFailed`，不新增 outcome。讀取者已逐一核對（main `402ca398`）：

- `outcomeExitCode` 回傳 1（`internal/delivery/transaction.go:228-233`）。
- `aggregateWorkflowResult` 發布為 `failure`、`application_consistency` 為 `partial_or_unknown`（`cmd/pilot/cmd/outbound_workflow.go:232`、`:246`）；`docs/superpowers/specs/2026-09-15-outbound-state-webhook-spec.md:1188-1198` 的對照表已列這一列。
- `completedComponentIDs` 不算它（沒有已確認的效果，`cmd/pilot/cmd/outbound_workflow.go:121-127`）；`store.LastSuccess`（`internal/store/runs.go:153`）與 snmp-exporter 診斷（`cmd/pilot/cmd/mcp_delivery_tools.go:399`）也不把它當成功；evidence 的 redact allowlist 已含它（`internal/evidence/redact.go:509`）。

**為什麼不新增 enum**：`aggregateWorkflowResult` 的 `default` 把任何沒列出的 outcome 發布成 `success`（`cmd/pilot/cmd/outbound_workflow.go:237-238`），新 outcome 會直接變成對外的成功，並且改變 webhook 的 outcome 對照表。這是設計審查發現、計畫沒有寫到的危害。

**新 sentinel `delivery.ErrPartiallyApplied`**：`Transaction.RunResult` 中，apply、verify、idempotency 任一步的錯誤包著它，結果就是 `OutcomePartialFailed`、`FailedStep` 是那一步、**不 rollback**（reconciler 的效果已提交）。目前非測試程式碼沒有任何路徑會產生 `partial_failed`（只有讀取者，grep 確認），這是它的第一個 producer。使用處：

- Go 已有至少一個操作的結果是 `success` 或 `unknown`，之後失敗或結果不明（`FailedStep: apply`）。（補充：設計審查寫「寫了 ≥1 個操作」；全部嘗試的操作都是確定未套用的失敗——`failed`／`conflict-failed`——時沒有東西被改動，記為一般失敗 `failed`，不是 partial。）
- 混合 run：Go 已提交之後 playbook 失敗（`apply`）、`pilot verify` 失敗（`verify`）、冪等性失敗（`idempotency`）。
- 義務未結清（見下一點，`FailedStep: verify`）：webhook 的 `failure.class` 是 `verify_failed`、phase 是 `verify`（`failureClassFor`，`cmd/pilot/cmd/outbound_workflow.go:178-197`），都在 webhook 的 allowlist 內。

### 6.2 義務未結清

義務未結清是 `ErrPartiallyApplied` 的一種，另用 `identityreconcile.ErrUnsettled`（**補充**，型別包著 `delivery.ErrPartiallyApplied`）標示「Go 的每個操作都已完成並驗證、（混合）playbook 也成功、只剩授權快取義務」，CLI 以它決定結束碼 4（§6.3）。

| 情形 | scope | 結果 |
|---|---|---|
| Go 有寫入，入口已執行（所以 journal 的 `auth_pending` 為 true） | `users-groups` | 一律未結清：沒有 playbook 去 settle 與 ack |
| Plan₁ 為空，探測 `pending=true` | `users-groups` | 未結清（來自先前的執行） |
| Plan₁ 為空，探測 `pending=false` | `users-groups` | **成功**；不執行入口、不改 journal |
| 探測沒有結果、結果來自別台主機、`fqdn` 不符 | 兩者 | 失敗（不是「沒有義務」） |
| 觀察到 `acked=true` | `full` | 已結清 |
| 沒有觀察結果、缺欄位、別台主機、`acked=false`（`ipa_identity_refresh_sssd_cache` 為 false、`pilot_deferred_hosts` 與 `freeipa-client` 有交集、tag 漏掉、`no hosts matched`） | `full` | 未結清（U4 討論這條嚴格規則） |
| Go 失敗，沒有任何操作是 `success`／`unknown`，但入口已執行 | 兩者 | 一般失敗（`failed`，結束碼 1），訊息附上「入口已執行，義務已記錄」；一次多餘的刷新無害 |

未結清時的訊息（計畫 §(ii)）：「授權快取義務未結清，client 在 SSSD 快取過期前可能仍沿用舊授權；下一次選到 `identity` 或 `client-cache` 的 apply 或完整 apply 會刷新所有 enrolled client（`ipa_identity_refresh_sssd_cache` 為 false 時則要先改回 true）」。pilot 不自己執行 settle、刷新或 ack。

本機證據：delivery 事件 `identity.auth_cache`，payload `{source: this_run|previous_run, entry_ran, probe_pending, observed_acked}`（無秘密）。

### 6.3 結束碼

**決定 D14。** `pilot reconcile --engine golang`：

| 碼 | 條件 |
|---|---|
| 0 | 成功：所有操作完成並驗證；義務已結清，或不需要（探測 `pending=false` 的零寫入 run） |
| 1 | 失敗，包括 unknown 與 partial |
| 3 | blocked：plan 有 `blocked` 項目，零寫入、沒有入口（P1 已定；`--force` 同樣） |
| 4 | 只剩義務未結清：每個 Go 操作都已完成並驗證，沒有別的失敗（driver 用它斷言「零 mutation 且義務如實回報」） |

子行程的結束碼仍不傳遞（P1 spec §2.3）。history 記的 `run_finished.exit_code` 是 `outcomeExitCode` 的 0／1，CLI 的 3／4 是 CLI 自己的語意；兩者刻意不同。

### 6.4 outcome 讀取者強化

**決定 D15。** 同一個 PR（P2-6）：`aggregateWorkflowResult` 明列每個 `delivery.Outcome` 常數（`success` 與 `partial_success` 為 `success`），`default` 改為 `failure`，未知 outcome 永不被發布成成功。測試：每個 `delivery.Outcome` 常數都被明確分類；一個合成的未知 outcome 得到 `failure`。

## 7 Go writer

### 7.1 WriteGate

**決定 D16。** `freeiparpc.Config` 新增 `WriteGate func(ctx context.Context, method string) error`。

- `New` 對 `!ReadOnly && WriteGate == nil` 拒絕建立。
- 在 `Call`（`internal/freeiparpc/client.go:315`）與 `Batch`（`internal/freeiparpc/commands.go:154`）的 `ReadOnly` 檢查旁，任何東西被序列化或送出之前呼叫；拒絕等於「沒有送出」（`Stats.Writes` 不增加）。
- 不擴大 allowlist：11 個寫入方法已在清單內（`internal/freeiparpc/commands.go:20-37`：`user_add`、`user_mod`、`user_del`、`user_enable`、`user_disable`、`passwd`、`group_add`、`group_mod`、`group_del`、`group_add_member`、`group_remove_member`）。
- 引擎的 gate：`HeldFrom(ctx)` 存在 ∧ 沒有掉 ∧ 這一輪的入口結果已被觀察到。
- 測試：gate 關閉時每個寫入方法與每個含寫入的 batch 都回錯誤，fake server 收到**零**個請求；唯讀客戶端不受影響；「永遠開著的 gate」會讓零請求測試 fail。

P1 的預覽繼續以 `ReadOnly: true` 建立，不帶 WriteGate。

### 7.2 流程

**決定 D17。** `identityreconcile.Execute`，在已持有的鎖之下：

1. **Read₁**（`Observe`）→ **Plan₁**。
2. Plan₁ 有 `blocked`：停止（結束碼 3），沒有入口、零寫入（I7）。
3. Plan₁ 的寫入數為 0：不執行入口。`users-groups` scope 做唯讀探測；混合 run 交給 playbook。
4. Plan₁ 的寫入數大於 0：執行入口（`prepare`），並驗證結果（§5.4）。失敗就停止，零寫入。
5. **Read₂ → Plan₂**：入口與第一批寫入之間隔著一次 ansible-playbook 啟動，Read₂ 就是計畫 §4 步驟 4 的「寫入前重讀」與「入口空窗的前置條件」；入口已執行，所以 Plan₂ 是權威。與 Plan₁ 的差異回報為 `conflict`（R5）。Plan₂ 有 `blocked`：停止、回報義務。Plan₂ 為空：Go 結束（入口執行過、Go 沒有寫入；混合 run 繼續交給 playbook）。
6. 依 §7.3 的 stage 執行 Plan₂。
7. **Read₃ → Plan₃**（§7.6）。

**與計畫字面的差異**（§14）：計畫要入口接在「寫入前重讀與重新規劃之後」，並要求測「第一次 plan 沒有寫入、重讀後才產生寫入」。這裡的入口接在 Plan₁ 之後、Read₂ 之前：Read₂ 同時是「寫入前重讀」與「入口空窗的覆蓋」，不需要在入口前多讀一次再於入口後補讀；Plan₁ 為空時沒有任何重讀，也就沒有「重讀後才出現寫入」的情形。對應的測試改為：Plan₁ 非空→入口→Plan₂ 多出 Plan₁ 沒有的操作→入口仍先於第一個寫入；Plan₁ 為空→沒有入口、沒有重讀。

**寫入前的前置條件**（計畫 §4 步驟 5）：除刪除外，不在每批之前另外讀取；前置條件由伺服器的逐項回應判斷（add 的 `DuplicateEntry`、mod／enable 的 `NotFound` 都是 `conflict-failed`，§7.4）。刪除是例外，見 S8。

### 7.3 stage 與 batch

**決定 D18。** 依計畫 §7.2 的順序（P1 spec §7.2），每個 stage 的操作互相獨立；跨 stage 就是依賴。每個 batch 最多 **25** 個命令（初值，常數；P2-8 量測後可調，語意不變；Q2）。

| stage | 操作 | 備註 |
|---|---|---|
| S1 | `group_add` | |
| S2 | `group_mod`、marker 的 `group_add`（nonposix） | marker 名稱由 `HistoryMarkerName` 決定（`internal/identityreconcile/marker.go:11`） |
| S3 | `user_add`、`user_mod` | `user_mod` 只帶不同的欄位 |
| S4 | `passwd` | **一位使用者一次呼叫，不進 batch**（B4） |
| S5 | `group_remove_member` | 每個群組每種成員一筆，含所有成員 |
| S6 | `group_add_member` | 同上 |
| S7 | `user_enable`／`user_disable` | |
| S8 | 刪除 | 先一個 batch 的 `user_show`／`group_show` 加 marker 重讀，立即再 `user_del`，最後 `group_del`；marker 必須驗證描述正確才送 `group_del` |

### 7.4 逐項分類

**決定 D19。**

| 結果 | 意義 | 例 |
|---|---|---|
| `success` | 已套用 | RPC 成功且有 result |
| `noop` | 不需要變更 | `EmptyModlist`、`AlreadyActive`／`AlreadyInactive`、刪除時的 `NotFound`、成員「already a member」／「not a member」 |
| `conflict-failed` | 前置條件已不成立 | add 的 `DuplicateEntry`、mod／enable／disable 的 `NotFound`、成員「no such entry」 |
| `failed` | 被拒絕 | 其他 `RPCError`（含密碼政策）、`ACIError` |
| `unknown` | 可能已套用 | `OutcomeUnknownError` |

`DecodeMemberResult`（`internal/freeiparpc/commands.go:253`）必須讓每個成員都有去處。第一個 `conflict-failed`、`failed` 或 `unknown` 之後停止排程後面的操作與 stage；目前這個 batch 已送出，記錄完它的所有逐項答案；然後執行驗證。分類所依據的真實回應形態來自 §9 的擷取（X3）。

### 7.5 重試與 unknown

- **寫入不重送**，唯一的例外是 client 已證明「401 發生在指令執行之前」的重新登入（P0）。讀取：client 內建的一次 transport 重試與一次重新登入；executor 不另加。
- **unknown 不重送**，由 Read₃ 把它分類為 `converged`、`not-applied` 或 `still-unknown`。密碼的值無法比對：時間戳只能當提示（`initialize`：`krblastpwdchange` 出現；`reset`：`krbpasswordexpiration` ≤ `krblastpwdchange`），操作維持 unknown、run 失敗。重跑是安全的，因為決定是依狀態做的（已有 key 就不再初始化；仍在重設的密碼上就不再重設）；**不宣稱 exactly-once**（計畫 §4）。
- 取消、逾時與掉鎖時的行為見 §4.4。

### 7.6 驗證

**決定 D20。** Read₃ 重讀整份 managed 狀態並重新規劃：Plan₃ 不得含任何**已嘗試**物件的操作，否則 `verify_failed`。這同時是行程內的「第二輪零寫入」檢查。驗證讀取用 §4.4 的有界 ctx。

### 7.7 journal

**決定 D21。** delivery store 的 run（`history.db`，`0600`，由 `openSpecStore` 建立，`cmd/pilot/cmd/spec.go:253-268`）就是 run journal：

- 每個 batch 或單一呼叫**之前**（`sending`）與**之後**（狀態、RPC 錯誤名稱與代碼）各寫一筆 `identity.op` 事件，payload 是 plan 的 `Operation`（不含密碼、cookie、key 本體）；另有 `identity.verify` 與 `identity.auth_cache`。
- store 對同一個 `operation_id` 但 payload 不同的事件回 `ErrEvidenceConflict`（`internal/store/delivery_evidence.go:176-182`），所以「之前」與「之後」兩筆用不同的 `operation_id`（**補充**）。
- **補充**：寫入 `sending` 事件失敗，該批**不送出**（fail closed；AGENTS.md §5.8，紀錄只能根據實際執行結果產生）。
- 不從 journal 續跑：重啟＝重讀、重算（計畫 §4 失敗與恢復）。journal 是稽核紀錄，不是恢復輸入。
- 測試：哨兵密碼與哨兵 cookie 不出現在 pilot data 目錄任何檔案。

### 7.8 密碼

**決定 D22。**

- 值只在執行時、只為「有密碼操作」的使用者，從記憶體中的 roster 取出（`PasswordSource`）；`Desired` 只增加值的**形態**，不帶值。plan、事件、結果檔都沒有值（I6）。
- **補充（值的形態怎麼判斷）**：P1 的 adapter 收到的是解成 `map[string]any` 的 roster（`cmd/pilot/cmd/reconcile_golang.go:205-209`、`internal/identityreconcile/desired.go:84`），`!vault`、`!unsafe` 與引號等 tag／style 在那裡已經遺失，所以不能在 adapter 判斷形態。`internal/inventory` 的 `ansibleScalarKind`（`internal/inventory/roster_admin_password.go:472`）是未匯出的、吃 `*yaml.Node` 的唯一判斷（AGENTS.md §5.7）。P2-5 新增一個匯出函式，輸入 roster 位元組、輸出每位使用者 `password.initial` 的形態，內部呼叫它，不另寫一套。
- 範本、inline `!vault`、非字串的 `password.initial`，**在有計畫的密碼操作時**一律新的 blocked 原因 `password_value_unsupported`（roster 可以用範本寫 `password.initial`，`playbooks/apply/tasks/freeipa-identity-normalize-users-groups.yml` 的開頭註解 `:5-10` 與 `:55`）；沒有計畫的密碼操作時不擋（no-op 的 run 不該因為它被擋）。
- 語意與 playbook 相同：`preserve_existing` 預設 true；`force_change: false` 沒有作用（已知缺口，計畫 Phase −1）；決定規則在 `playbooks/apply/freeipa-identity-apply.yml:1233-1257`，roster 的預設在 normalize 檔 `:55-57`。
- RPC 形態：`passwd [principal] {password}`（P0 的 `internal/freeiparpc/live_test.go:303` 用法）；成功與政策拒絕的真實回應列入 K6。

### 7.9 lifecycle、managed ownership 與先拒絕

**決定 D23、D25。**

- `absent`：永久 `user_del`（不帶 `preserve`，與 playbook 相同，`playbooks/apply/freeipa-identity-apply.yml:1718-1730`）；群組刪除前必須即時重讀並驗證 marker（`:1734-1782`）。
- Go 只碰：roster 宣告的使用者與群組、它們的 marker、roster 群組的直接成員（authoritative 撤銷＝playbook 語意）；刪除只針對 `state: absent`。其他物件永不出現在操作中。
- **history marker**：每個套用中的群組在 S2 確保 marker 存在（`group.marker.create`；名稱 `HistoryMarkerName`，描述 `HistoryMarkerDescription` 即 `pilot.group-history/v1 name=<name>`，`internal/identityreconcile/marker.go:11-19`）；刪除群組前（S8）重讀並驗證 marker 存在且描述正確才送 `group_del`，marker 衝突維持 `blocked`（`marker_collision`）。**使用者 lifecycle**：`absent` 是永久刪除；與 preserved 使用者同名維持 `blocked`（`preserved_user`），Go 不做 preserve／undelete。
- `blocked` 原因與 P1 spec §7.3 相同，**沒有一個變成支援**；新增 `password_value_unsupported`（§7.8）與 `protected_object`（§7.10）。
- **#273 先修（P2-1，在任何寫入路徑之前）**：`internal/identityreconcile/desired.go:199`、`:208`、`:242` 對型別錯誤的 `password`、`ssh_keys`、`membership` 用 `x, ok := …(map[string]any)` 靜默當成未宣告；有寫入時，錯型別的 `membership` 會被讀成「authoritative、沒有成員」，撤銷所有直接成員。adapter 對非 mapping 的 `membership`／`password`／`ssh_keys` 改為 fail closed（P1 spec §5.1 嚴格檢查的同一風格，在建立 tunnel 之前失敗）。`ValidateRoster` 本身在 Phase 2 不變：改它會改變 Ansible engine 的行為，需要先擷取 playbook 對這些輸入的真實反應（§5.6；Q1）。
- **寫入前先拒絕**：adapter 拒絕與 `blocked` 一律零寫入、沒有入口；混合 run 在這種情況下不執行 playbook（I7）。`users-groups` scope 的 `not_in_scope`（P1 spec §5.3）只報告，不阻擋，因為 scope 的定義就是不宣稱整份 identity。

### 7.10 自鎖保護

**決定 D24（待使用者確認 U3）。** 新增 blocked 原因 `protected_object`：刪除或停用登入的 principal、把它移出 `admins`、刪除 `admins`／`ipausers`／`editors`／`trust admins`。這比 playbook 嚴格（P1 spec D9 的同類取向）；沒有它，roster 可以在 run 中途移除 engine 自己的讀取權限，之後的驗證讀取失敗，而寫入已經套用。

## 8 入口、scope 與混合執行

### 8.1 CLI

**決定 D26。** `pilot reconcile --component freeipa-identity --engine golang --scope users-groups|full (--preview-only|--force) [--stage …] [--staging-attested-within-hours …] [--limit …] [--timeout …] [--lock-wait …] [--plan-out …] [--result-out …]`。

| 組合 | 結果 |
|---|---|
| `--engine golang` 沒有 `--preview-only` 也沒有 `--force` | 拒絕（互動不支援，P1 D2） |
| `--engine golang` 帶 `--actions`、或 `--component` 不是剛好一個 `freeipa-identity` | 拒絕（P1 §2.1，不變；其他元件是 Phase 4） |
| `--engine golang --preview-only` 沒有 `--scope` | `users-groups`（P1 行為不變，不取鎖） |
| `--engine golang --preview-only --scope full` | 混合預覽：Ansible `--check --diff`（帶 skip 變數）加 Go 的唯讀 plan；不取鎖（§8.3） |
| `--engine golang --force` 沒有 `--scope` | 拒絕：`--scope` 必填 |
| `--scope` 不是 `users-groups` 或 `full` | 拒絕 |
| `--scope` 或 `--result-out` 搭配 `--engine ansible` | 拒絕（旗標無效，比照 `--plan-out`） |
| `--result-out` 沒有 `--force` | 拒絕 |
| `--lock-wait` 搭配 `--preview-only` | 拒絕（§4.3） |
| `--force` 與 `--preview-only` 同時 | 拒絕（現有規則） |

`--force` 就是確認；staging／prod 要 `--stage`（prod 另要 attestation），規則與 P1 的 `golangPreviewStage` 完全相同。這些拒絕都在讀 inventory、vault 或建立連線之前，以 `// gate:` 與 test row 鎖住（P1 §10.1 的結構）。

### 8.2 users-groups scope

**決定 D27。** 擴充 `reconcile_golang.go`：P1 的 preflight（P1 spec §2.2 步驟 1–6）→ 建 Dialer → **取鎖**（§4.5）→ FQDN、CA、client、登入、`CheckServer` → `Execute`（§7.2）→ 零寫入時做探測 → 結果。

- 自己的 delivery run（`store.StartRun`，metadata 記 engine 與 scope），經 `delivery.Transaction`（Apply＝Go，Verify＝驗證加義務）與 `publishTerminalWorkflow`，effects 為 `identity.users`、`identity.groups`（`PublishTerminalWorkflowInput.Effects` 容許專用 frontend 指定固定子集，`cmd/pilot/cmd/outbound_workflow.go:314-319`；contract 的 effects 列表在 `contracts/freeipa-identity.yaml:4-12`）。
- **從不執行 identity playbook**；入口執行過或探測 `pending=true` 就是義務未結清（§6.2）。
- 一個全新主機的 journal 不存在，探測視為 `pending=true`，直到第一次完整 playbook run 觀察到 `acked=true`。

### 8.3 full scope（混合）

**決定 D28。** 重用 Ansible reconcile 路徑（`runReconcileInteractive` 的預設值 driver → `runCatalogPlaybookDeploy` → 依賴鏈 → `executeRecordedDeploymentCore`），以 ctx 上的標記啟用，所以 availability／deferred、預覽、stage、history、webhook、冪等性與 runtime-race 的邏輯都不重複（AGENTS.md §5.7）。只對 identity 的那個 transaction：

- 額外參數 `-e pilot_identity_users_groups_engine=go -e pilot_identity_auth_cache_output=<暫存檔>`。
- Preview：加上 Go 的唯讀 plan；有 `blocked` 就預覽失敗，不取鎖。
- Apply：取鎖（I1）→ `PrepareApply`＝`Execute`（以 `HeldFrom(ctx)` 取得 token）→ playbook。Go 失敗，playbook 不執行（I7、計畫「混合執行模型」）。
- Verify：先既有的 `pilot verify`，再解析觀察結果：該主機的 `acked`；否則 `ErrUnsettled`（§6.2）。
- Idempotency（≥ staging）：playbook 再套用一次，再加上 Go 的唯讀 plan 必須 0 個操作。
- 在 Go 已提交至少一個操作之後，任何後續步驟的失敗都以 `ErrPartiallyApplied` 包起來（§6.1）。

R1：改 `deploy.go` 是最高風險；hook 只對 identity 元件生效，並有行為測試與 H1–H5 的 live 驗證。

### 8.4 skip 變數與受保護範圍

**決定 D29。** 變數 `pilot_identity_users_groups_engine`（`ansible` 預設或 `go`）。用 `pilot_` 前綴而不是計畫擬議的 `identity_users_groups_engine`：group_vars 裡的一個 `identity_users_groups_engine: go` 會在每一輪 legacy run 中靜默關掉 users／groups，`pilot_` 前綴降低誤設的機率；並由 lint 鎖住它不出現在任何 contract `groupVars`、`group_vars/*.example.yml`。

- **guard**：標 `always` 的 assert：值必須是 `ansible` 或 `go`，且 `go` 一定伴隨非空的 `pilot_identity_auth_cache_output`。
- **在這些 task 加上** `when: pilot_identity_users_groups_engine | default('ansible') != 'go'`：users／groups 區段中除了 SSH key 區塊以外的每一個 task。以 task 名稱為錨：第一段從「List existing IPA groups」（`playbooks/apply/freeipa-identity-apply.yml:969`）到「Gate: every password this run set was accepted」（`:1318`）；SSH key 區塊（「Resolve enrolled SSH key cache targets」`:1341` 到「Acknowledge verified SSH key cache pairs」`:1470`）**不加**；第二段從「Ensure user group membership」（`:1489`）到「Delete canonical groups explicitly marked absent」（`:1770-1782`）。（約 969–1328、1489–1782 行。）
- **fact 讀取者地圖（對主要名稱已核對，P2-7 的 runtime 測試是窮舉的證明）**：區段內設定的 fact（`ipa_existing_*`、`ipa_pwd_*`、`canonical_group_*` 等）只在區段內被讀；`ipa_active_users`／`ipa_active_groups` 來自 pre_tasks（`:773-788`，`always`）。區段外唯一的讀取者是 `auth_settle` 的 `changed` 計算：它讀 `ipa_identity_cache_mutation_registers`（`:104` 起）列出的 register，只看 `changed`（`:4036-4041`），被跳過的 register 是 `changed: false`，不是未定義。這正是 Go 的寫入需要入口先把 `auth_pending` 設為 true 的原因：settle 看不到 Go 的變更。
- **測試**：(i) 靜態 lint：區段以 task 名稱錨定，每個 task 都有 guard，SSH key 區塊與其他區段沒有；(ii) runtime，沿用既有的假 `ipa` harness（`internal/spec` 的 identity-noop／ssh-cache runtime 風格）：變數為 `go` × tags {無、`users`、`groups`、`identity`、`passwords`、`C11`、`sshkeys`} ⇒ 假 `ipa` 的呼叫紀錄沒有任何 users／groups 的 mutation，且有 SSH key 的 `user-mod --sshpubkey`；變數未設 ⇒ 呼叫紀錄與今天相同。負向對照：拿掉任一個 guard，兩個測試都 fail。

### 8.5 結束碼

見 §6.3。取鎖忙碌、入口失敗、Go 失敗都是 1。

### 8.6 輸出與秘密

**決定 D30。**

- stdout：engine、scope、目標、版本、每類操作的數量與每個結果類別的數量、驗證結果、授權快取狀態（§6.2 的訊息）、`freeiparpc.Stats`。stderr：取鎖等待的進度行。輸出與 `pilot` 文件寫明鎖只約束 pilot 的程式碼路徑（R3）。
- `--result-out`：`pilot.identity-apply/v1`（plan、逐項狀態、驗證、`auth_cache`、stats；欄位為擬議）。檔案以 `0600` 與 `O_EXCL` 建立，**在任何寫入之前**就建立（路徑已存在就在寫入之前拒絕，與 P1 的 `--plan-out` 一樣不整輪做完才發現）；寫入或關閉失敗就移除檔案（#274）。**補充**：只要這一輪已通過 Read₁（有 plan）就寫出，成功或失敗都寫，因為部分套用後逐項狀態正是操作者需要的；沒有進到 Read₁ 的失敗不寫。
- #274（`--plan-out` 寫入或關閉失敗留下截斷的 plan 檔，`writeGolangPlan`，`cmd/pilot/cmd/reconcile_golang.go:616`）與 `--result-out` 共用同一個「獨占建立、失敗時移除」的修正，不另寫兩份。
- 密碼、cookie、vault 內容不出現在任何輸出、錯誤、log、plan、結果檔、事件（I6）。
- `pilot.identity-apply/v1` 與 `pilot.identity-auth-cache/v1` 都有 Parse → Render → Parse 的 round-trip 測試（AGENTS.md §5.15）。

## 9 實作前必須先擷取

依 AGENTS.md §5.6，判讀規則只能來自真實擷取。K6–K15 在拋棄式 FreeIPA 測試 VM 上經 P0 的 tunnel 以 `freeiparpc` 擷取，fixture 放 `internal/freeiparpc/testdata/`，以測試鎖住（每個擷取附竄改探測），擷取後刪除測試物件。已有的擷取不重做：`user_add`／`user_mod`／`user_enable`／`user_disable` 成功與常見失敗、`group_add`、`group_add_member`（成功、已是成員、成員不存在）、`group_remove_member` 的 not-member、`batch` 的混合（讀取成功、`NotFound`、`EmptyModlist`），見 `internal/freeiparpc/testdata/`。

| # | 擷取 | 決定什麼 |
|---|---|---|
| K6 | `passwd` 成功；密碼政策拒絕（錯誤名稱、代碼、訊息）；各 `maxlife` 下的時間戳 | §7.8 的 RPC 形態、`failed` 的分類、unknown 的時間戳提示 |
| K7 | `user_del` 成功與 `NotFound` | 刪除的 `noop` 判讀 |
| K8 | `group_del` 成功與 `NotFound` | 同上 |
| K9 | `group_mod`（description）成功與 `EmptyModlist` | S2 的分類 |
| K10 | marker 的 `group_add`（nonposix，帶 description）成功，以及 `group_find` 讀回的 `objectclass`／description | S2 與 S8 的 marker 驗證 |
| K11 | `group_add` 的 `DuplicateEntry` | `conflict-failed` |
| K12 | `group_remove_member` 成功（使用者與群組成員） | S5 的分類 |
| K13 | `group_add_member` 以 `group` 成員（成功、已是成員、不存在） | S6 的分類 |
| K14 | `user_add`／`user_mod` 各選項的名稱：`givenname`、`sn`、`displayname`、`mail`（含多值的取代語意）、`loginshell`、`homedirectory` | S3 的欄位對映；email 宣告時「整組 `mail` 剛好等於 `{email}`」要怎麼達成 |
| K15 | 含一個 `DuplicateEntry` 項目、其餘成功的寫入 batch | §7.4 的 batch 部分失敗處理 |
| K16 | 入口的真實 ansible-playbook 輸出與結束碼：`no hosts matched`（預期 0）、task 被 `when` 跳過、多台主機；以及 funnel 用的 `ansible <pattern> --list-hosts` 在空比對與多台時的輸出 | §5.4 的解析器，「入口結束碼為 0 不能證明義務已寫入」 |
| K17 | controller 端 `copy`（`delegate_to: localhost`）結果檔：成功、目的目錄不可寫、`become` 的影響 | R6 |

## 10 測試與驗收

### 10.1 單元測試證明什麼

**單元測試只證明邏輯與 fixture 的對應；它們不證明 sshd 的 flock、真實 inventory、playbook 的行為與真實的寫入回應。** 那些由 §10.2 的 live 測試證明。

- 取鎖：§4.6 lint 與變異驗證、§4.7 的交錯與順序測試、`Held.Lost()` 在 `Release` 之後不關閉、掉鎖取消 ansible-playbook、`TargetFromHostVars` 的每一列（含 `ansible_connection: docker`）。
- 入口：結果解析器的「應該通過」與「應該觸發」兩種案例（真實輸出，K16）、`auth_inspect`（journal 不存在→`true`、domain 不符→錯誤、不建立任何檔案）、§5.6 的一致性測試、結果檔的 round-trip。
- outcome：§6.4 的測試、結束碼矩陣、`partial_failed` 不被 `LastSuccess` 當成成功、webhook 的 `result` 與 `failure.class`。
- writer：WriteGate 對每個寫入方法與 batch（零請求）；stage 與 batch 的邊界；逐項分類矩陣（K6–K15 的 fixture）；unknown 的分類矩陣；journal 與秘密不外洩（每條錯誤路徑）；`password_value_unsupported`、`protected_object`、#273 的每個欄位各有「應該觸發」的 row 與負向對照。
- 混合：§8.4 的靜態與 runtime 測試；hook 只對 identity 元件生效；Go 失敗時 playbook 不執行；`ErrPartiallyApplied` 的包裝。
- gate ledger：新增的 `// gate:` 與 row（P1 §10.1 的結構），變異驗證。

計畫對測試的要求與本規格的對應：

| 計畫的要求 | 對應 |
|---|---|
| Go 移出成員、停用、刪除而其餘 section 沒有變更時 client 仍被刷新；寫入後、playbook 前中斷，下一輪即使 Go 沒有寫入也會刷新 | §4.7 的交錯測試；H1、H3 |
| 入口的觸發條件 | §7.2 的順序測試（取代方式見該節）；A2、A3 |
| 執行器不變量，入口失敗案例用真實輸出 | §7.1 的零請求測試；K16 |
| 序列化 | §4.7、§4.6 |
| 三個共用輸入 | §5.6 |
| users／groups-only 的兩輪 | A2–A4 |
| 刷新標記的兩種案例 | §5.4 的解析器測試；H1、H4 |

### 10.2 live 測試計畫（driver 的 arm）

`TestLiveGoApplyDriver` 擴充 P1 的 `TestLiveGoPreviewDriver`（`internal/identityreconcile/live_test.go:37`）：建置 `pilot` binary、只驅動 CLI。每個 candidate 用全新的拋棄式拓樸（一台 FreeIPA server 加一台已 enroll 的 client，以 sanctioned 的 `pilot vm-target topology up` 建立），先 snapshot，失敗時 rollback，每個 arm 記錄 server `error_log` 的寫入計數。evidence 記錄 candidate／tree、server 與 API 版本、每個 arm 的 PASS／FAIL、**skip 數（必須為 0；有 skip 要列原因）**，以及生效的 `--lock-wait`、batch 上限與 `--timeout`。

| arm | 做什麼 | 通過條件 |
|---|---|---|
| A1 | legacy `--force` 建立基準 → Go 預覽 | 寫入操作 0（P1 D12） |
| A2 | 新增一位使用者（含 `password.initial`）、一個群組與成員關係，`--scope users-groups --force` | 結束碼 4；操作恰為 `group.create`、`group.marker.create`、`user.create`、`user.password.initialize`、`group.member_user.add`；server `error_log` 的寫入與操作一一對應；Read₃ 零差異 |
| A3 | A2 之後重跑 | 零 mutation、沒有入口；探測 `pending=true`；結束碼 4（這算通過） |
| A4 | 一次完整的 legacy run（觀察到 acked）→ 重跑 `users-groups` | 結束碼 0、沒有入口、journal 位元組不變 |
| A5 | 修改一個屬性 | 恰一個 `user_mod`，只帶該欄位 |
| A6 | 撤銷：移除成員、停用、刪除使用者、刪除群組（marker 驗證） | 操作與預期相同；之後 H1 證明 client 端真實 deny |
| A7 | 外部 drift：用 `freeiparpc` 寫入 `givenname`、多餘成員、停用 | 恰 3 個修復；重跑 0 |
| A8 | 失敗與重跑：(i) 密碼政策拒絕；(ii) 在 batch 中途殺掉 tunnel 的 `ssh -W` | (i) 結束碼 1、後面的 stage 沒有執行，修正後收斂；(ii) unknown、結束碼 1、重跑收斂且沒有重複 |
| A9 | 忙碌的鎖：legacy `pilot reconcile --force` 執行中，Go `--lock-wait 0` 與 `--lock-wait 30m` | `0` 在 tunnel 與登入之前失敗（`error_log` 沒有 session）；`30m` 等待後成功；journal 狀態符合預期 |
| A10 | 掉鎖：S3 期間殺掉鎖的 ssh | 之後沒有寫入、結束碼 1 |
| A11 | docker-connection 的 workspace | 在 ssh 之前被拒 |
| A12 | uid 變更 | 結束碼 3、零寫入、沒有入口 |
| A13 | journal 的 domain 不符 | 入口失敗、零寫入 |
| H1 | 混合 `--scope full --force`，只有 users／groups 變更 | 觀察到 acked、client 已刷新（client 上真實 deny）、結束碼 0 |
| H2 | H1 之後 legacy 完整重跑 | users／groups 區段的 task `changed=0`（json callback，逐 task） |
| H3 | `users-groups` run（Go 有寫入、沒有 playbook）→ 之後混合且 Go 零寫入 | 刷新發生（等同「中斷後下一輪」） |
| H4 | `ipa_identity_refresh_sssd_cache: false` | 結束碼 4、history 為 `partial_failed`、webhook 為 failure |
| H5 | Go 寫入之後 playbook 失敗 | `partial_failed`、結束碼 1 |
| L1–L6（P2-2） | 每個漏斗（deploy／reconcile、`access reconcile --once`、breakglass、decommission）持有鎖（同時另一個連線對 `/etc/ipa` 以 `flock --nonblock --conflict-exit-code 75` 取鎖得到 75）；第二個同時的漏斗等待或失敗；掉鎖殺掉 playbook；不支援的 inventory 被拒絕 | 各自通過 |
| L7（P2-2） | legacy 執行中 `kill -9` pilot，觀察 ansible-playbook 是否繼續、鎖何時釋放 | **只記錄（X5）**，不判定通過 |
| P（P2-8） | 計畫 §6 的目標：120／40 無差異 p95 ≤ 30 秒（20 次樣本）、單一屬性 ≤ 30 秒、100 次新增 ≤ 120 秒加重跑 0、1,000／200 的完整性、入口耗時（與整輪分開呈現）、混合整輪 wall time、SSH RTT 與版本 | 記錄實際數字；未達要說明原因，不放寬門檻 |

### 10.3 退出條件

計畫的 Phase 2 退出條件對應到上面的 arm：

- 取鎖閘門已通過：lint 與兩種交錯的 regression test（§4.6、§4.7）加 L1–L6。
- 新增、修改、撤銷、外部 drift 修復、第二輪零 mutation、失敗重跑在 live target 通過：A2–A8。`users-groups` scope 的第二輪通過條件是「零 mutation 且義務如實回報」（A3），不是「結果為成功」；成功要求兩輪之間有一次觀察到 `acked=true` 的完整 playbook run（A4）；全新主機的 journal 不存在，同樣是未結清。
- 效能目標：P。
- 混合全量 run 在 live target 通過，其後以 legacy 全量重跑時 users／groups 相關 task `changed=0`：H1、H2。
- 完整的 `go test -race ./...` 由 CI 的 `Go test` job 執行（AGENTS.md §5）。

## 11 PR 序列

每個 PR 都可以獨立合併。target_validation 依 AGENTS.md §1.4：`required` 表示需要拋棄式 VM 上的實跑；`not-needed` 附理由；目前沒有 `blocked`（需要的是一台由 Root 管理的拋棄式 FreeIPA 測試 VM）。

| PR | 範圍 | 主要檔案 | 驗收 | target_validation | 相依 |
|---|---|---|---|---|---|
| P2-0 | 這份規格與計畫的狀態、過期敘述更正 | 本檔、計畫 | 決定與擷取表；沒有可執行的 SOP | not-needed：只有文件 | — |
| P2-1 | #273：adapter 對型別錯誤 fail closed | `internal/identityreconcile/desired.go` 與測試、gate row | 每個欄位一個「應該觸發」的 row 與負向對照 | not-needed：純輸入驗證，無入口 | — |
| P2-2 | **取鎖閘門** | `internal/identitylock`、`internal/sshdial/hostvars.go`、`accessgrants` options、decommission config、deploy 的 transaction option、CLI 接線、lint | §4.6 lint、§4.7 測試；`go test` 涵蓋 `cmd/pilot/cmd`、`internal/spec`、`internal/accessgrants`、`internal/decommission`、`internal/sshdial` | **required**：真實 sshd 的 flock、真實 inventory 形態（L1–L7）；**U1 確認且正式 inventory 檢查完成前不可合併** | U1 |
| P2-3 | 入口 playbook、`auth_inspect`、identity 的觀察與 ack register、AGENTS.md §4.0 的一列、Go 的結果解析器 | `playbooks/apply/freeipa-identity-auth-cache.yml`、`files/freeipa-ssh-key-cache.py`、`freeipa-identity-apply.yml`（兩處）、`internal/identityreconcile/authcache.go` | §5 的測試；解析器可先於 playbook 完成 | **required**：`pilot vm-target test` 對入口（全新 VM：journal 不存在／true／false、domain 不符、check mode 拒絕）與 identity playbook 的觀察（acked true；refresh 關閉時 false），AGENTS.md §1.4 | P2-2（`Held` 型別出現在簽章；解析器可先做） |
| P2-4 | 擷取 K6–K15 與 fixture 測試 | `internal/freeiparpc/testdata`、find／write 的 fixture 測試 | 每個擷取有斷言與竄改探測 | **required**：在拋棄式 VM 上擷取 | P2-2（U6） |
| P2-5 | executor（沒有入口） | `freeiparpc` 的 WriteGate、`identityreconcile/execute.go`、journal sink 介面、`inventory` 的值形態匯出函式、新的 blocked 原因 | §7 的單元矩陣；WriteGate 零請求測試 | not-needed：沒有進入點，fixture 驅動；它的 live 證明由 P2-6 提供 | P2-1、P2-4 |
| P2-6 | users-groups scope 的套用 | `reconcile.go`、`reconcile_golang.go`、`delivery.ErrPartiallyApplied`、outcome 讀取者強化、`--result-out` 與 #274、gate ledger | 結束碼矩陣、history 與 webhook 測試、秘密；driver A1–A13 | **required** | P2-2、P2-3、P2-5 |
| P2-7 | 混合 | identity playbook 的 guard、`deploy.go` 的 identity hook、`--scope full` | §8.4 靜態與 runtime；driver H1–H5 | **required** | P2-6 |
| P2-8 | 效能、evidence 與計畫退出條件更新 | `docs/evidence/freeipa-go-reconcile/*`、計畫 | 最終 candidate 上的 §10.2 的 P | **required**：量測 | P2-7 |

順序規則：取鎖閘門（P2-2）先於 P2-4、P2-6、P2-7；在 P2-7 之前不啟用混合。P2-1 可與 P2-2 並行。

## 12 待使用者確認

**下面六項是設計審查的預設值與它的後果，不是已確認的決定。** 每項都需要使用者回答；沒有回答前，實作只能依預設值寫程式碼、不得把它當成已同意。

- **U1　不支援的 SSH 形態讓 legacy 漏斗拒絕執行**
  預設（待使用者確認）：拒絕。`pilot deploy`、`pilot reconcile`、`pilot access`、breakglass 與 `pilot host decommission` 的 identity 路徑，遇到 freeipa-server 主機使用 ProxyCommand、密碼 SSH、docker／local connection，或不在 allowlist（`ConnectTimeout`、`ProxyJump`、`ServerAliveCountMax`、`ServerAliveInterval`、`StrictHostKeyChecking`、`UserKnownHostsFile`）的 `-o` 選項時，改為錯誤並指出那個 hostvar。
  後果：現在能跑的這類 inventory 在 P2-2 之後會失敗。**P2-2 在操作者檢查過正式 inventory 之前不能合併**（檢查方式：以 AGENTS.md §0.1 的方法讀真實 inventory 的事實，即 `ansible-inventory -i <inventory> --graph`／`--list`，看 freeipa-server 主機的連線 hostvar；X1。這份規格沒有執行它）。不同意時的替代：提供有稽核紀錄的略過旗標，但會重新引入交錯的危害（U2 同一個理由）。

- **U2　長時間執行期間的 breakglass**
  預設（待使用者確認）：CLI 最多等 30 分鐘，TUI 立即失敗；不提供略過。
  後果：一輪完整 identity（legacy 約 26–27 分鐘）進行中，事故中的 breakglass activate 會等到那一輪結束，或在 TUI 被立即拒絕並指向 `pilot access breakglass activate`。替代：略過會重新引入清除交錯；安全的替代是計畫的選項 (iv)（`auth_pending` 加世代，改 #138 的 helper 與 journal 格式，重跑 #138 的 live 矩陣）。

- **U3　自鎖保護**
  預設（待使用者確認）：啟用 `protected_object`（§7.10）。
  後果：roster 若刪除或停用登入 principal、把它移出 `admins`、刪除 `admins`／`ipausers`／`editors`／`trust admins`，Go engine 回報 `blocked`（結束碼 3）而不套用；這比 playbook 嚴格（Ansible engine 照樣會套用這種 roster）。不啟用的後果：roster 可以在 run 中途移除 engine 自己的讀取權限，之後的驗證讀取失敗，而寫入已套用。

- **U4　延後的 optional client 讓混合 run 永不成功**
  預設（待使用者確認）：保留計畫的語意並寫進文件：只要有 `freeipa-client` 被延後（`pilot_deferred_hosts`），ack 被略過，`acked=false`，混合 run 的結果是結束碼 4。
  後果：只要有 optional client 關機，混合 run 就不是成功。同一條嚴格規則也使 `ipa_identity_refresh_sssd_cache: false` 的 run 一律是結束碼 4——即使 journal 本來就是乾淨的（零寫入、沒有義務），那是一個誤報。替代：把「`dirty` 明確為 false」也算已結清（`settled = acked 或 dirty==false`）：能消除乾淨 journal 的誤報，但偏離計畫的「沒有觀察到刷新完成標記就不聲稱已結清」，且延後 client 的情形仍是未結清。

- **U5　撤銷、刪除、密碼的 checklist row**
  預設（待使用者確認）：延後。新增 row 要在兩個 engine 都有 tag，並依 AGENTS.md §1 實跑 `pilot verify`；Phase 2 的 driver 直接斷言它們（A2、A5–A8），`KindsWithoutSpecRow`（`internal/identityreconcile/spec_rows.go:25-27`）維持原狀。
  後果：撤銷、刪除與密碼在 `docs/verification/freeipa-identity.md` 仍只有手動程序，沒有 `pilot verify` 的自動驗收。

- **U6　擷取（P2-4）的時機**
  預設（待使用者確認）：P2-2 合併之後。依字面讀計畫「閘門通過之前，不執行任何 live Go 寫入測試」，經 `freeiparpc` 對拋棄式 VM 的擷取也是 live Go 寫入。
  後果：關鍵路徑是 P2-2 → P2-4 → P2-5 → P2-6 → P2-7 → P2-8，P2-2（最大的一個 PR）擋住所有後面的工作。若使用者裁定「拋棄式 VM 上的 client 擷取不算 live Go 寫入測試」（單一操作者的拋棄式 VM 沒有與 legacy 漏斗交錯的問題），P2-4 可以提前與 P2-2 並行。

## 13 未決問題

| # | 問題 | 由什麼解決 |
|---|---|---|
| Q1 | `ValidateRoster` 要不要也拒絕型別錯誤的 `membership`／`password`／`ssh_keys`（會改變 Ansible engine 的行為）？Phase 2 只讓 Go adapter 拒絕（P2-1） | 先擷取 playbook 對這些輸入的真實反應（AGENTS.md §5.6），再另案決定 |
| Q2 | batch 上限 25 是否合適 | P2-8 的量測；語意不變，只調常數 |
| Q3 | 使用者決定 U1–U6 | 使用者 |
| Q4 | `partial_failed` 的 webhook 沒有 `confirmed_effects`，訂閱者看不到已提交的 users／groups 變更（R7） | 需要時另案修改 webhook 規格；不在 Phase 2 |
| Q5 | 正式環境的 SSH RTT 與 FreeIPA 版本（X2）；SIGKILL 後的 legacy 子行程（X5）；#261 的孫行程拖延（R2）；#277 的三份實作（R4） | 各自的量測或另案，不在本階段修 |

## 14 與設計審查和計畫的差異、補充

**對計畫字面的偏離**（刻意）：

1. **入口結果用 controller 端 JSON 結果檔**，不用計畫擬議的 stdout `AUTH_CACHE[<host>]: …` 標記（§5.4，原因同該節）。
2. **混合 skip 變數名**用 `pilot_identity_users_groups_engine`，不是擬議的 `identity_users_groups_engine`（§8.4）。
3. **入口位置**在 Plan₁ 之後、Read₂ 之前，不是在「寫入前重讀與重新規劃之後」；計畫列出的一個測試案例（第一次 plan 沒有寫入、重讀後才產生寫入）因此改成等價的案例（§7.2）。
4. 計畫說「helper 的每個動作都寫 journal，沒有唯讀動作」，已不符 main：自 `4e774a95` 起有唯讀路徑（計畫在這個 PR 更正）；探測因此只需四行（§5.3）。
5. 計畫列出三個讀取 outcome 的地方，漏了 `aggregateWorkflowResult` 的 `default` 會把未列出的 outcome 發布成 `success`（§6.1、§6.4）。
6. 計畫 §(ii) 引用的密碼判斷 task 行號已過期（計畫在這個 PR 更正）。

**補充**（設計審查沒有寫、這份規格補上的決定；請特別 review）：

| # | 補充 | 位置 |
|---|---|---|
| E1 | I3 的措辭改為與流程一致（入口接在非空 Plan₁ 之後；Plan₂ 為空允許） | §2、§7.2 |
| E2 | `--timeout` 分段（preflight、取鎖等待、取鎖之後重新計時）；`--lock-wait` 與 `--preview-only` 同用即拒絕 | §4.3、§8.1 |
| E3 | 驗證讀取用 `WithoutCancel` 加有界期限（60 秒）；取消、逾時與掉鎖後仍嘗試一次 | §4.4 |
| E4 | `ErrPartiallyApplied` 只在有操作是 `success` 或 `unknown` 時使用；其餘失敗是一般 `failed`；`ErrUnsettled` 型別 | §6.1、§6.2 |
| E5 | 密碼值的形態由 `yaml.Node` 經 `inventory` 的匯出函式判斷（`map[string]any` 已遺失 tag） | §7.8 |
| E6 | `sending` 與結果事件用不同的 `operation_id`；`sending` 寫入失敗就不送出 | §7.7 |
| E7 | `--result-out` 的寫出條件（通過 Read₁ 後成功或失敗都寫）與在寫入之前獨占建立 | §8.6 |
| E8 | skip 變數的值必須是 `ansible` 或 `go`（assert）；混合 run 對已提交 Go 操作之後的任何步驟失敗一律包 `ErrPartiallyApplied` | §8.3、§8.4 |
| E9 | 入口的共用輸入一致性測試也掃 `freeipa-ssh-cache-preflight.yml`（同一個 journal 表達式的第三處） | §5.6 |
| E10 | L7：SIGKILL 後 legacy 子行程的行為只記錄（X5） | §1.2、§10.2 |

## 15 交給後續階段

P1 spec §11 交給 Phase 2 的四件事在這裡的處理：取鎖閘門、#138 入口、`users-groups` scope 的探測與未結清結果（§4–§6）；`blocked` 中哪些要支援——沒有一個（§0、§7.9）；撤銷、刪除與密碼的 checklist row——延後（U5）；batch 邊界與寫入前重讀（§7.2、§7.3）。

仍然留給後續階段的：

- Phase 3：其餘 section 的搬移、client fan-out、host／hostgroup／netgroup／HBAC／sudo；是否需要它由 P2-8 的量測決定（計畫「規模與 go/no-go」）。
- Phase 4：互動入口、`--ask-vault-pass`、預設 engine 切換、舊 engine 的手動回退流程。
- uid／gid 變更的明確確認設計；external 群組的寫入；撤銷、刪除與密碼的 checklist row（U5）。
