# FreeIPA Go reconcile — Phase 2 使用者與群組寫入 MVP 規格

日期：2026-11-06。對應計畫：`docs/superpowers/plans/2026-10-15-freeipa-go-ssh-reconcile.md` Phase 2。前一階段：`docs/superpowers/specs/2026-10-30-freeipa-go-reconcile-phase1-spec.md`（下稱 P1 spec；目前驗收紀錄見 [LATEST](../../evidence/freeipa-go-reconcile/LATEST.md)）與 `docs/superpowers/specs/2026-10-16-freeipa-go-reconcile-phase0-contract.md`（P0）。

狀態：草稿（P2-0，文件）。P2-1（#273 的 adapter 拒絕，§7.9）與 P2-2（取鎖閘門，§4）已在 Phase 2 分支實作；P2-2 的 live arm L1–L11 已在 candidate `91f82abb` 對拋棄式 FreeIPA 實跑（[pr-284](../../evidence/freeipa-go-reconcile/pr-284.md)），U1 已由維護者在 2026-11-06 確認（§12）。其餘 Phase 2 沒有程式碼，也沒有任何實跑。規格由 2026-11-06 對 main `402ca398`（含 Phase 1，PR #255）的設計審查整理而成，文中的檔案與行號都是那個 commit 的樣子；行號會漂移，實作與 lint 以符號與 task 名稱為準，不寫死行號。

**讀法：每一項都標明它是什麼。**

- **決定 Dn**：這份規格已定下，實作照做；§3 是總表，細節在各節。
- **補充**：設計審查沒有寫、這份規格為了讓行為完整而補上的決定，review 時請特別看（§14 列出全部）。
- **待使用者確認 Un**（§12）：附有設計審查的預設值與它的後果，**不是已確認的決定**，除非該項寫明已確認。未確認前實作不得假設它們已成立；U1 已於 2026-11-06 確認，其餘 U2–U6 仍待確認。
- **未決 Qn**（§13）與**未知 Xn**（§1）：還沒有答案，各自寫明由什麼擷取、量測或誰的回答解決。

修訂：第二、三輪 review（F1–F4、R2-N1 到 R2-N4 與 P3／P4）與 #273 的 adapter 實作已併入，§14 的 E11–E41 列出（E38 是 P2-2 實作時的差異，E39 是 P2-2 review 之後的取鎖前檢查與已知限制，E40 是 breakglass 自動化步驟失敗被回報成功的修正與措辭收斂，E41 是 decommission 的鎖取得太晚〔違反 D1〕的 live 發現與修正）。

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
| X1 | 正式環境的 inventory 形態：freeipa-server 主機是否用 ProxyCommand、密碼 SSH、docker／local connection 或不在 allowlist 的 `-o` | **已解決（2026-11-06）**：維護者確認正式 inventory 不使用 ProxyCommand、密碼 SSH、docker／local connection（U1）。這是維護者的陳述；這份規格沒有執行 `ansible-inventory` 讀過正式 inventory |
| X2 | 正式環境的 SSH RTT 與 FreeIPA 版本 | P2-8 量測，接入前確認（計畫 Phase 0 已列） |
| X3 | 寫入回應的真實形態（`passwd`、刪除、`group_mod`、marker、重複、batch 部分失敗…） | §9 的 K6–K15 擷取；擷取前不寫 fixture、不寫判讀 |
| X4 | 入口在 `no hosts matched`、task 被 `when` 跳過、多台主機時 ansible-playbook 的真實輸出；controller 端 `copy` 結果檔的行為 | §9 的 K16、K17 |
| X5 | pilot 被 SIGKILL 或當機時，legacy 路徑啟動的 ansible-playbook 子行程是否仍在執行（預期會：它們沒有隨 pilot 結束的機制；未實測）。若會，鎖已隨 ssh 結束而放掉，另一輪可以在它結束前取鎖 | P2-2 的 live arm L7 只**記錄**行為，不判定通過；殘餘風險（R3） |
| X6 | client 上舊授權在 SSSD 快取下實際延續多久 | 計畫已列為未實測；不影響 Phase 2 的正確性規則（未結清就回報，不依賴這個數字） |

### 1.3 風險

| # | 風險 | 處理 |
|---|---|---|
| R1 | 混合執行改 `cmd/pilot/cmd/deploy.go`，AGENTS.md §5.5 列為最高風險檔案 | hook 只對 identity 元件生效；新增行為測試；全量路徑 live 跑（H1–H5） |
| R2 | legacy 漏斗掉鎖時只殺 ansible-playbook 主行程（`exec.CommandContext`），不殺它的 process group：孫行程握著 pipe 時返回會被拖延（#261 第 2 項），而 fork 出的 worker 可能在掉鎖**之後**把進行中的 task 做完（那一個 task 沒有鎖的保護；之後不會再有新的 task，因為 ansible-playbook 主行程已死） | 不在本階段修；P2-2 記錄（runbook §4.3 寫給操作者） |
| R3 | 鎖只約束 pilot 的程式碼路徑：手動 `ansible-playbook`、dev 路徑（`vm-target run`／`vm-target test`／`topology test`）、不經 pilot 的 IPA 管理工具、X5 的情形 | 計畫的殘餘風險；`pilot` 輸出與文件要寫明這個前提（§8.6） |
| R4 | `users-groups` scope 在 `inventory.yml` 落後 `hosts.yml` 時拒絕（唯讀，P1 spec §2.2 步驟 2），混合路徑則照 Ansible engine 現況重新產生（可能 migrate roster）；「inventory.yml 是否最新」有三份實作（#277） | 不在本階段統一；兩種行為都寫進輸出 |
| R5 | 入口之後的 Plan₂ 可能比 Plan₁ 多出操作（外部 writer） | 執行 Plan₂ 是安全的（入口已執行）；差異回報為 `conflict`（§7.2） |
| R6 | 入口的單一 JSON 結果檔靠 controller 端 `copy`（`delegate_to: localhost`）；`become` 與連線形態可能影響 | K17 擷取，P2-3 實跑 |
| R7 | `partial_failed` 的 webhook 沒有 `confirmed_effects`（`completedComponentIDs` 只算 `success`，`cmd/pilot/cmd/outbound_workflow.go:121-127`），訂閱者看不到已提交的 users／groups 變更；`application_consistency` 是 `partial_or_unknown` | 接受並記錄（Q4） |
| R8 | server 端先放掉鎖、client 還沒注意到（sshd 的 ClientAlive 設定）：`Lost()` 看不到 | 文件記錄；lock 的 ssh 帶 `ServerAliveInterval=15`、`ServerAliveCountMax=3`（§4.2）縮短反方向的偵測時間 |
| R9 | 取鎖等待期間（最長 30 分鐘）按 Ctrl-C：本機 ssh 被殺，但遠端 `flock --wait N` 行程在 sshd 關閉連線後仍等到它自己的期限 `N`（flock 自己保證在 `N` 秒結束，`internal/sshdial/lock.go:56-59`）；它取得鎖時會因 stdin EOF 立刻結束並放鎖，不會長期占鎖，但這段時間它是一個幽靈等待者，會讓另一個合法等待者的那一次嘗試多等一輪 | **不加 `timeout` 包裝**：`flock --wait N` 已經在 `N` 秒結束；而把整條遠端指令包在 `timeout` 之下，會在 `N` 加寬限之後連**持有中**的鎖一起殺掉（等於掉鎖），flock 的等待與持有又在同一個行程裡，包裝沒辦法只套在等待階段。處理：接受 `--wait N` 界定的上限；live arm L8 記錄 Ctrl-C 之後遠端行程多久消失，L9 證明持有中的鎖不會被計時器殺掉（§10.2） |
| R10 | 取鎖 ssh 的 `ServerAliveInterval=15`、`ServerAliveCountMax=3` 讓網路中斷約 45 秒就被視為掉鎖，legacy 漏斗因此取消 ansible-playbook；今天同樣的中斷不會殺掉一輪長時間的 run。這是行為變更，也是「偵測反方向掉鎖要多快」與「容忍短暫中斷」的取捨 | 寫進 U1、U2 的後果；數值是常數，P2-2 的 live arm 量測後可調（調大＝R8 的偵測更慢） |
| R11 | `users-groups` 的寫入 run 在觀察到 `acked` 的完整 run 之前，webhook 一律是 `failure`（義務未結清，§6.2）；`store.LastSuccess`（`pilot runs last-success`）會把零寫入、`pending=false` 的 `users-groups` 成功 run 當成該主機最近一次成功交付，而它沒有執行完整 playbook | 文件寫明給 webhook 訂閱者；`LastSuccess` 是否依 scope 過濾見 Q6 |
| R12 | 取鎖的 target 只來自 `ansible-inventory --list` 的 hostvars，下列連線設定它看不到（§4.2 已知缺口）：`-e @file`（與 JSON 物件形式的 `-e`）提供的 `ansible_host`、`ansible_user`、`ansible_port`、`target_group`，`ansible.cfg` 的 `ssh_args`／`host_key_checking`，環境變數 `ANSIBLE_SSH_ARGS`。`target_group` 或 `ansible_host` 只由 `-e @file` 提供時，鎖可能鎖 A 機而 playbook 的目標是 B 機 | 接受並記錄：連線設定寫在 inventory（host_vars／group_vars）而不是 `-e @file` 或 ansible.cfg；`-e target_group=<g>`（key=value 形式）在 deploy 路徑有被解析，access 與 decommission 不傳 `target_group`；runbook §4.3 寫給操作者；L1–L6 的 live arm 對真實 inventory 驗證，不涵蓋 `-e @file` 提供的連線變數 |
| R13 | `--ask-vault-pass`／`--ask-become-pass`（deploy／reconcile 精靈的答案）的密碼提示發生在 ansible-playbook 裡，也就是**取鎖之後**：操作者輸入密碼的時間算在持鎖時間裡，與 D1「互動確認的等待不持鎖」不同 | **接受並記錄，不拒絕這兩個旗標**：拒絕會讓今天可用的 ansible engine 流程失效，而且沒有辦法在取鎖前先問（提示在 ansible-playbook 內）；後果只是持鎖變長（別的 run 要多等，互斥本身不受影響）。要避免就用 `--vault-password-file`。runbook §4.3 寫給操作者 |
| R14 | breakglass `Activate` 在掉鎖時回傳 `ErrLockLost`，而那在它記錄 activation **之前**：即使 playbook 已以 0 結束、規則已在 FreeIPA 啟用，`breakglass-activations.json` 沒有這筆紀錄，直到重跑；`Deactivate` 同理，掉鎖時不標記 `deactivated`（規則可能已被收掉，紀錄仍是 active） | 接受並記錄：錯誤訊息已說 FreeIPA 可能已被部分調和、要重跑；`activate` 重跑是冪等的 apply，`deactivate` 重跑把規則收掉；runbook §4.3 寫給操作者 |
| R15 | 一個含 `activate_breakglass`（或 `deactivate_breakglass`）的 scenario 在它**之後**的步驟失敗時，apply 的 rollback 只還原 workspace 的檔案：啟用已在 FreeIPA 生效、`breakglass-activations.json` 已有紀錄，rollback 不會把它收掉。這一輪之前同樣如此（那時失敗的啟用甚至被當成成功）；MCP 的 `apply_failed` 訊息指名失敗的步驟，但沒有說前面的啟用還在 | 接受並記錄，**沒有改**：把 breakglass 步驟放在 scenario 的最後，或失敗後用 `pilot access breakglass status` 檢查並 `deactivate`；要讓 rollback 反向執行需要 apply 的步驟模型有補償動作，不是一行的修正 |
| R16 | decommission 的一輪在 `freeipa_client_uninstall`（或 converge 之前的任何步驟）進行中掉鎖：`Bind` 取消的 ctx 殺掉執行中的 ansible-playbook（只殺主行程，R2），這一輪以包著 `ErrLockLost` 的錯誤結束，converge 不啟動。client 可能已部分或全部解除 enrollment，roster 尚未 tombstone，FreeIPA 的 host 紀錄還在，plan 沒有完成。掉鎖若發生在 converge 之後（驗證、finalize），這一輪仍以 `ErrLockLost` 結束（它沒有持有鎖到結束，這正是鎖要保證的），即使 finalize 已完成；重跑 `apply` 會重播 receipt（`already_completed`，不取鎖）。**finalize 已完成（receipt 已記錄）時，訊息說的是這一輪已完成**，並說明為什麼它仍是失敗（掉鎖之後的部分沒有受保護，重疊的 identity 執行可能讓 client 的授權快取沒被刷新），不說「FreeIPA 可能被部分調和」或「請重跑」（對一個已完成的下架那是假的）；結果與錯誤一起回傳，TUI 據此把主機從記憶中的 hosts 拿掉（`lockLostAfterCompletionError`、`decommissionRunEnd`）。沒有完成的一輪，文字不變這不比 converge 進行中掉鎖或 converge 因其他原因失敗更糟：掉鎖需要鎖的 ssh 連線自己中斷，pilot 無法避免；而掉鎖之後的 plan 能不能 `resume`，取決於 workspace 是否有效（例如選用的 `ipa_client_fqdn` 有沒有設，issue #303，既有缺口，不在這個 PR） | 接受並記錄：取鎖移到第一個步驟之前（E41）讓**取鎖失敗**（忙碌、逾時、取消、拒絕）不再留下半套狀態（等待中的 Ctrl-C／SIGTERM 在 CLI 是**行程直接結束**，不是 context 取消：`apply`／`resume` 沒有安裝訊號處理，所以沒有任何訊息、也不會印 `was not started`，狀態卻同樣沒有改變（approval 保留、plan 可 resume；live 觀察，L4、L11A）；`was not started` 的訊息只在鎖忙碌、等待逾時、被拒絕，以及 context 被取消（程式內部，例如測試；CLI 本身沒有這條路徑）時出現），但一輪已開始之後的掉鎖本來就無法避免；錯誤訊息已寫明 FreeIPA 可能已被部分調和、要重跑；runbook §4.3 寫給操作者；測試 `TestDecommissionApplyWithTheLockLostDuringTheUninstallStopsBeforeTheConverge` |

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
| B7 | 取鎖閘門讓既有入口對不支援的 inventory 形態拒絕執行，而且是在任何 ansible-playbook、ssh 與任何步驟**之前**（取鎖前檢查，§4.2），不是取鎖時才拒絕 | 行為變更；U1 已於 2026-11-06 確認 |
| B8 | 沒有自動 rollback | Go 的寫入是 reconciler 效果，失敗後以「重讀、重算」重跑收斂；不 fallback 到舊 playbook（計畫 §4） |

## 2 不變量

每個 PR 都要讓下面七條保持成立；測試與 lint 針對它們設計。

- **I1 序列化**：每條會執行 `freeipa-identity-apply.yml` 或新入口的非測試程式碼路徑，從「確認之後」到該次執行（含冪等性再套用、verify、rollback）結束，持有該 FreeIPA server 的 `/etc/ipa` 遠端鎖。一輪只取一次；混合 run 沿用已持有的鎖，不重新取。dev 路徑（`vm-target run`／`vm-target test`／`topology test`）不在範圍，lint 的註解寫明理由（計畫 §4 步驟 2）。
- **I2 執行器**：沒有任何寫入 RPC 離開 pilot，除非 (a) 這一輪的鎖仍然 `Active()`（已持有、沒有 `Release`、沒有掉，§4.1），(b) 這一輪對**已上鎖主機**的入口結果已被觀察到。由 `freeiparpc` 的 WriteGate 結構性保證，不靠呼叫端的紀律（§7.1）。
- **I3 入口觸發**：入口只會接在「非空且沒有 blocked 的 Plan₁」之後；空的 Plan₁ 不執行入口（改做唯讀探測）。入口之後才寫入，寫入集合取自 Plan₂（它是權威）。入口執行後 Plan₂ 為空是允許的（多刷新一次，無害），在 `users-groups` scope 它算義務未結清。（補充：設計審查原本寫「入口執行若且唯若最終寫入集合非空」，與它自己的流程——入口在 Read₂ 之前——不一致，這裡改為與流程一致的寫法；§7.2。）
- **I4 永不成功**：Go 有寫入（或入口已執行）、但沒有觀察到該主機的 `acked=true` 的 run，以及探測讀到 `pending=true` 的 run，**不是成功**：結束碼非 0、outcome 是失敗類（義務未結清是 `partial_failed`，§6）、webhook 的 `result` 為 `failure`、不被 `store.LastSuccess` 當成成功。
- **I5 混合略過**：引擎變數為 `go` 時，任何 `--tags` 下都沒有 users／groups 的 mutation task 執行；SSH key 區塊與授權快取 task 照常執行；變數未設時行為與今天逐位元組相同（§8.4）。
- **I6 秘密**：密碼、cookie、vault 內容不進 argv、環境、plan、結果檔、delivery 事件、log。
- **I7 fail closed**：任何 `blocked` 項目或不支援的輸入，都是零寫入，混合 run 在這種情況下也不執行 playbook。Plan₁ 就 `blocked` 時沒有入口；Plan₂ 才出現的 `blocked`（以及 §7.3 的破壞性差異衝突）發生在入口之後，入口已執行、零寫入（§7.2）。

## 3 決定總表

| # | 主題 | 決定 | 詳見 |
|---|---|---|---|
| D1 | 取鎖位置 | 在漏斗處、確認之後、第一次執行之前；一輪一把鎖；混合 run 沿用已持有的鎖 | §4.5 |
| D2 | 取鎖包裝 | 新套件 `internal/identitylock`；`Acquirer` 由 `cmd` 建好注入，各漏斗的 options 必填，nil 即錯誤 | §4.1 |
| D3 | target 推導 | host 取 inventory 名稱、剛好一台；推導函式下沉到 `internal/sshdial/hostvars.go`；不支援的 inventory 形態拒絕執行，不退回無鎖（U1）；**每個漏斗在任何 ansible-playbook、ssh、approval 紀錄與它自己的步驟之前，先用同一個推導做無 ssh 的取鎖前檢查**（只整理 workspace 的事仍在它之前：精靈的問題、`inventory.yml` 的重新產生、roster 的 schema 升級，見 §4.2），取鎖時的檢查保留當縱深防禦 | §4.2 |
| D4 | 等待策略 | CLI 漏斗最多等 30 分鐘並每 30 秒印一行；`pilot reconcile --lock-wait`；TUI breakglass 等待 0；Phase 2 不提供略過（U2） | §4.3 |
| D5 | 掉鎖與取消 | 只取消 ansible-playbook 的指令 ctx（`Bind`），`RunResult`、證據與 Go RPC 的 ctx 不取消；Go writer 用 `Held.Active()` 在每批前檢查，進行中的 batch 回真實答案；`Held.Lost()` 只在沒有 Release 的結束時關閉；**一條類別規則：記錄 run 結果的每一個寫入（journal、step 證據、終端寫入、`--result-out`、外送 projection、outbox、webhook 送出）在取消之後用 `WithoutCancel` 加有界期限**，sink 清單與負責 PR 在 §4.4 | §4.1、§4.4 |
| D6 | 全 repo lint | 引用 allowlist、具名漏斗 AST 檢查、contract 守衛，附變異驗證；`executeDeploymentTransaction` 對 identity playbook 沒有 `IdentityLock` 時執行期拒絕 | §4.6 |
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
| D17 | 流程 | Read₁→Plan₁→（入口）→Read₂→Plan₂→stages→Read₃→Plan₃；Plan₂ 比 Plan₁ 多出破壞性操作就停止 | §7.2、§7.3 |
| D18 | stage、batch 與前置條件 | 八個 stage，每個 batch 只放互相獨立的操作，上限 25 個；`passwd`、成員撤銷、刪除在送出前各有批次重讀與謂詞 | §7.3 |
| D19 | 分類與重試 | 五類結果；寫入不重送；unknown 不重送、靠重讀分類 | §7.4、§7.5 |
| D20 | 驗證 | 重讀整份、Plan₃ 不得再有已嘗試物件的操作 | §7.6 |
| D21 | journal | 存在 delivery store 的 run 事件，不含秘密；不從 journal 續跑 | §7.7 |
| D22 | 密碼 | 值只在執行時由記憶體中的 roster 取出；值的形態由 yaml.Node 判斷 | §7.8 |
| D23 | lifecycle 與保護 | absent 為永久刪除；blocked 原因不變；Go 只碰 roster 物件、marker 與 roster 群組的直接成員；不支援的內容在寫入前拒絕 | §7.9 |
| D24 | 自鎖保護 | 新 blocked 原因 `protected_object`，在 plan 的每個 stage 邊界（不只最終狀態）檢查登入 principal 存在、enabled、對 `admins` 遞移可達，並擋它自己的密碼重設；選擇「擋下」而不是調換新增與撤銷的順序（U3） | §7.10 |
| D25 | #273 | 已在分支實作：adapter 在任何讀取或寫入之前拒絕型別錯誤與明確的 `null`（Go 有自己預設值的鍵、頂層清單、`freeipa.admin.principal`、nested 鍵、`absent` 項目的形狀）；Go 不管理的鍵（`uid`、`gid`、`display_name`、`email`、群組 `gid`）的 `null` 是「不管理」，接受；`""` 是值（Q8） | §7.9 |
| D26 | CLI | `--scope users-groups\|full`、`--lock-wait`、`--result-out` | §8.1 |
| D27 | users-groups scope | 自己的 delivery run，不執行 playbook，結果義務未結清時結束碼 4 | §8.2 |
| D28 | 混合 | 重用 Ansible reconcile 路徑，hook 只對 identity 元件生效 | §8.3 |
| D29 | skip 變數 | `pilot_identity_users_groups_engine`（不用計畫擬議的 `identity_users_groups_engine`） | §8.4 |
| D30 | 輸出與秘密 | stdout 摘要、`--result-out`（`pilot.identity-apply/v1`）、`--plan-out` 與它同一個 #274 修正 | §8.6 |
| D31 | live 注入點 | driver 用 build tag `identity_live_hooks` 建置的 pilot，提供 `after_entry`、`before_stage`、`before_batch`、`after_send`（請求已送出、答案未讀）暫停點，讓 driver 殺程序、送訊號或寫入外部變更；A8(ii)、A10、A17–A21 用它；預設與發佈的 binary 不含，CI 編譯帶 tag 的版本 | §10.2 |

## 4 取鎖閘門

### 4.1 套件與 `Held`

**決定 D2。** 新增 `internal/identitylock`：

- `type Acquirer func(ctx context.Context) (*Held, error)`。
- `Held`：`Host`（inventory 名稱）、`Active() bool`（沒有 `Release`、也沒有掉鎖）、`Lost() <-chan struct{}`、`Release() error`，以及兩個把 token 放進 ctx 的方法：`Attach(ctx) context.Context` 只帶 token，**永不因掉鎖而取消**；`Bind(ctx) (context.Context, context.CancelFunc)` 帶 token，並在掉鎖時以 cause `ErrLockLost` 取消。`HeldFrom(ctx)` 取出 token。實作形狀由 P2-2 決定，行為由 §4.4 與 §4.7 的測試鎖住。
- **`Bind` 只用在指令的 ctx**：ansible-playbook 的執行（apply、冪等性再套用、rollback playbook、入口）。它的結果**不得**交給 `delivery.Transaction.RunResult`、store 或 journal 的寫入、`freeiparpc` 的呼叫與驗證讀取；那些用 `Attach` 或原本的 ctx。原因見 §4.4：取消那些 ctx 會讓證據寫入失敗而遮住真正的結果，也會讓進行中的 RPC 變成 unknown。
- WriteGate 與所有「現在還能不能寫」的判斷用 `Active()`，不直接看 `Lost()`：`Held.Lost()` 只在沒有 Release 的結束時關閉，`Release` 之後不會關閉，只看 `Lost()` 的 gate 會在 `Release` 之後放行寫入。

**`Held.Lost()` 只在「沒有 Release 的結束」關閉。** `sshdial.Lock.Lost()` 回傳 `p.done`（`internal/sshdial/lock.go:110`），它在 ssh session 因任何原因結束時關閉，包括 `Release`；而它的 doc comment（`:108-109`）寫「without Release」。**不改 `sshdial`**：`internal/sshdial/sshdial_test.go:276-278` 斷言 `Release` 之後 `Lost` 是關閉的（失敗訊息 `Lost is not closed after Release`），改它會打破 P0 的測試與已實跑的行為。`Held` 在呼叫 `Release` 前先記下「已釋放」，只在未釋放時才把 `Lost` 轉成自己的訊號；P2-2 順手把 `lock.go:108-109` 的 doc comment 改成與實作相符。

`accessgrants.{Reconcile,Activate,Deactivate}Options.Lock` 是**必填**：nil 在任何執行之前回傳錯誤，新的呼叫者不可能漏掉。decommission 不同（E41）：它的鎖屬於**整輪**而不是 converge 步驟，所以 `FreeIPAClientProviderConfig` **沒有** `IdentityLock`；一輪的擁有者（`runHostDecommissionApply`）在第一個步驟之前取鎖、把它放進 `decommission.Apply` 的 ctx，converge 步驟用 `identitylock.Require(ctx)` 讀取（沒有鎖就以 `ErrNoLock` 拒絕、鎖已掉或已放也拒絕），自己從不取鎖也不放鎖。

### 4.2 target 推導

**決定 D3。** 取鎖要 `sshdial.Target`。三個漏斗各自解析主機與 hostvars，由 `cmd` 建好 `Acquirer` 後注入（`resolvePatternHosts` 與 snapshot helper 都在 `cmd`，`internal/accessgrants` 與 `internal/decommission` 不依賴它們）：

| 漏斗 | 主機解析 | hostvars |
|---|---|---|
| deploy runner（identity 元件） | `deploymentAppliedHosts(applied, scope, execScope.Included)`（`cmd/pilot/cmd/deploy_dependency_plan.go:119`；`scope` 由 `resolveDeploymentScope` 產生，已含 `target_group` 覆寫與 `--limit`，`deploy.go:2358`、`:2417`；`execScope.Included` 帶 availability） | `loadDeployInventorySnapshot`（`deploy.go:2539`） |
| `accessgrants.applyPlan`（`internal/accessgrants/reconcile.go:459`） | `ansible freeipa-server -i <inv> --list-hosts`（`resolvePatternHosts`，`cmd/pilot/cmd/deploy.go:2640`）；`applyPlan` 傳給 ansible-playbook 的只有 playbook、`-i`、`-e @file` 與選用的 vault 密碼檔，沒有 limit、沒有 `target_group`（`:489-493`） | `ansible-inventory --list` |
| decommission（整輪的鎖，由 `runHostDecommissionApply` 取；converge 步驟 `freeipaIdentityConvergeStep.Execute` 只讀它，E41） | 同上，對 workspace 產生的 `inventory.yml`（`hostDecommissionLockRequest`）；converge 的額外參數只有 roster 與 vault 的 `-e`，沒有 limit 或 `target_group` | 同上 |

規則：

- **host 是 inventory 名稱，剛好一台**（AGENTS.md §5.13：`ansible_host` 是連線位址，不是身分）；不是剛好一台，在任何 ansible-playbook 之前拒絕。
- 把 `sshTargetFromHostVars`、`sshOptionArgs`、`splitShellWords`（連同 `unsupportedSSHHostVars`、`multiplexOptions`，`cmd/pilot/cmd/reconcile_golang.go:402-550`）搬到 `internal/sshdial/hostvars.go`，公開為 `TargetFromHostVars`。`// gate:` 註解隨函式搬走；ledger 的持有者清單（`cmd/pilot/cmd/reconcile_golang_ledger_test.go:49-56`）與每個 row 一起搬到 `internal/sshdial` 的對應測試，`TestReconcileGolangEveryGateHasARow` 的函式清單同步更新。規則與 P1 spec §4 完全相同：只接受 allowlist 內的 `-o`（`internal/sshdial/sshdial.go:48-55`）；`ansible_connection` 未設、`ssh` 或 `ansible.builtin.ssh`（ansible-core 把兩個名字解析成同一個外掛，所以長名字的 inventory 與短名字連線方式相同；P2-2 review 之後補上，Go engine 的 tunnel 同一個函式因此也接受；`paramiko`、`smart`、`docker`、`local`、帶 collection 的其他名字與非字串的值維持拒絕）；`ansible_ssh_args` 只准 `ControlMaster`／`ControlPath`／`ControlPersist`（忽略）；密碼 SSH、`ansible_ssh_executable`、舊名稱一律拒絕。
- 取鎖用的 ssh 另外帶 `ServerAliveInterval=15`、`ServerAliveCountMax=3`，除非 target 自己設了（約 45 秒的網路中斷就會被視為掉鎖，行為變更與取捨見 R10、U1、U2），以及 `ConnectTimeout=30`，除非 target 自己設了：TUI breakglass 同步取鎖、等待 0、沒有 ctx 可以取消，對不回應的 server 原本要等作業系統的 TCP connect 逾時（數分鐘）。它只限制連線階段，不限制忙碌時的等待（那是 `flock --wait`）或持鎖的時間；tunnel 的 ssh 沒有這些選項。
- **不支援的形態（`ansible_connection: docker`／`local`、ProxyCommand、密碼 SSH、不在 allowlist 的 `-o`）：拒絕執行，訊息指出是哪個 hostvar；永不「無鎖執行」。** repo 內的 topology 檔（`docs/topologies/*`）是 `vm-target topology` 的輸入（docker-target 沒有 topology 指令），vm-target 的 inventory 是 `ansible_connection: ssh` 加 `ControlMaster` 與兩個 allowlist 內的 `-o`（`internal/vmtarget/vmtarget.go:1488-1494`）；docker-target 的 inventory 是 `ansible_connection: docker`（`internal/dockertarget/dockertarget.go:618`），repo 內沒有 FreeIPA 角色跑在它上面。**這是行為變更：見 U1。**
- **取鎖前檢查（P2-2 review 之後補上；「在任何 ansible-playbook 之前拒絕」的實作）。** 取鎖是漏斗在送出 playbook 之前做的**最後**一件事，而多數漏斗在那之前已經做了別的事：decommission 的 converge 步驟排在 `freeipa_client_uninstall` 與 `freeipa_roster_host_absent` 之後（取鎖移到整輪之前以前，拒絕時 client 已解除安裝、roster 已 tombstone；E41 把取鎖本身也移到第一個步驟之前，所以現在連拒絕以外的取鎖失敗也不會留下這種半套狀態）；deploy 與 reconcile 在 preflight、freeipa-server 依賴的 apply 與 `--check` 之後，而且 `--preview-only` 通過並不預告 `--force` 會被拒絕；access、breakglass、drift 修復在能力探測或唯讀探測之後。所以每個漏斗在做任何事之前，先用**取鎖用的同一個推導**檢查：`identityLockTarget`（剛好一台 freeipa-server 主機，加上對 inventory snapshot 的 `sshdial.TargetFromHostVars`）。取鎖（`productionIdentityLock`）與預檢查（`checkIdentityLockTarget`）都呼叫它，是同一個決定而不是第二份複本（AGENTS.md §5.7；測試對真實 inventory 斷言兩者同意，且理由相同）。預檢查只問 `ansible` 與 `ansible-inventory`，**不啟動 ssh、不啟動 ansible-playbook**；不支援就拒絕並指出是哪個 hostvar；取鎖時的檢查保留當縱深防禦。位置：

  | 漏斗 | 預檢查的位置 |
  |---|---|
  | deploy、reconcile（ansible engine） | `executeRecordedDeploymentWithAuthorizationResult` 的一開頭（`precheckIdentityDeploy`），在顯示計畫、要求授權、freeipa-server 依賴的 apply、preflight 與任何預覽之前，`--preview-only` 也一樣；批次執行（`executeCatalogBatch`，`pilot reconcile`／多元件 deploy）另在顯示計畫與要求授權**之前**（`precheckIdentityBatch`）。主機是解析後 scope（含 `--limit`、`target_group`）裡**尚未被 availability 排除**的候選主機；apply 步驟鎖的主機是它的子集，而 contract 的 exactly-one 在候選主機多於一台時本來就會在自己的 preflight 失敗，只是更晚 |
  | `pilot access reconcile`、`access breakglass activate`／`deactivate`、`access drift --repair-managed`、`identity drift --repair-managed` | 指令一開頭（`identityLockFor`），在能力探測、唯讀探測與 playbook 之前。`--repair-managed` 即使沒有 drift 也會被拒絕：檢查在探測之前，探測結果出來前不知道要不要鎖 |
  | `pilot edit` 的 TUI breakglass | 畫面動作一開頭（`tuiIdentityLockFor`），訊息顯示在 banner，**同時記錄成這一步的失敗**（`editRouterModel.failedAction`）：`pilot edit --actions`、scenario 與 MCP apply 的步驟因此以同一個原因失敗，不是回報成功（§4.3、E40） |
  | `pilot host decommission apply`、`resume`（與 TUI 的 decommission 流程，同一個函式） | `runHostDecommissionApply`：舞台確認與 provider 的建立（它會重新產生 `inventory.yml`）之後、記錄 approval 與第一個步驟**之前**，而且只對有 `freeipa_identity_apply_converge` 步驟的 plan（`needsLock`）；已完成的 plan 重播 receipt、不檢查、不取鎖。預檢查與 `Acquirer` 的建立由 `identityLockFor` 一次完成；**鎖本身在 approval 之後、`decommission.Apply` 之前取**（§4.5，E41）。`resume` 即使 converge 步驟已經做完，只要 inventory 後來變成不支援也會被拒絕（fail closed，訊息寫明） |
  | `pilot host decommission plan` | **不拒絕**，改在 stderr 印警告（stdout 的 JSON 不受影響，plan 照存、結束碼 0）。理由：blocker 會進 plan hash 與 freshness 的重新推導（`PlanInputForFreshness` 會對同一組 provider 重跑 `PlanHost`），而這個條件取決於 inventory 的連線 hostvar，那些不在 plan 記錄的外部狀態裡，做成 blocker 會讓連線 hostvar 的改動變成 `plan_stale`，讓一份沒有人能 apply 的 plan 看起來只是過期；apply／resume 自己會在第一個步驟之前拒絕 |

  **「之前」指的是什麼，以及拒絕之後 webhook 聽到什麼（P2-2 第二輪 review 之後逐漏斗核對，E40）。** 預檢查在漏斗自己的任何 ansible-playbook、ssh、approval 紀錄與步驟（依賴 apply、預覽、探測、解除安裝、tombstone）之前；它**不是**在所有事情之前：精靈的問題（`pilot deploy`／`pilot reconcile` 的 component、stage、limit、tags、vault、extra vars 提問）、`autoRegenerateInventoryFromHosts`（從 `hosts.yml` 重新產生 `inventory.yml`）與 `ensureFreeIPARostersCurrentSnapshot`（roster 的 schema 自動升級，會留備份）在 deploy／reconcile 的預檢查之前就做了，decommission 的 stage 確認與 provider 的建立（它會重新產生 `inventory.yml`）也在之前。這些只整理 workspace，不碰 FreeIPA；文件與 `--help` 只准說「在任何 ansible-playbook、ssh、approval 紀錄與漏斗自己的步驟之前」，不准說「在做任何事之前」。
  拒絕也**不是**一律不發 outbound 事件，要看漏斗在哪裡發布，逐一如下（`TestPrecheckRefusalOutboundEventsByFunnel` 各附對照組，證明「沒有事件」是拒絕造成的，不是訂閱從不符合）：

  | 漏斗 | 預檢查拒絕時的 outbound 事件 |
  |---|---|
  | 互動式單一元件 `pilot deploy`（沒有 `--component`；`runCatalogPlaybookDeployEntry`，`cmd/pilot/cmd/deploy.go` 在 `executeRecordedDeploymentResult` 回傳後**無條件**呼叫 `publishTerminalWorkflow`） | **發一個** `operation.result: failure`、`failure.class: apply_failed` 的事件，訂閱了 deploy 失敗的 webhook 會收到。沒有任何元件被執行，事件的 `completed_components` 是空的；沒有鎖被取、沒有 playbook 啟動 |
  | 批次：`pilot reconcile`、`pilot deploy --component …`（`executeCatalogBatch`，預檢查在顯示計畫之前，早於 `publishTerminalWorkflow`） | 不發 |
  | `pilot access reconcile --once`、`access breakglass activate`／`deactivate`（`identityLockFor` 在 workflow id 與發布之前回傳錯誤） | 不發 |
  | `access drift --repair-managed`、`identity drift --repair-managed`、`pilot host decommission`、TUI 的 breakglass | 這些漏斗沒有 outbound 發布的路徑，不發 |

  上面每個漏斗都不留 approval（decommission 的預檢查先於 `RecordApproval`，其餘沒有 approval）。互動式單一元件 deploy 發事件是它的既有行為：它不看 `executeRecordedDeploymentResult` 的錯誤發生在哪個階段，回傳錯誤就發，所以預檢查的拒絕與在它之後才失敗的 run 同樣會發；這一輪**沒有改程式**；是否要讓它在執行前的拒絕不發事件，是另一個決定，不在 P2-2。`TestEveryCLIFunnelRefusesAnUnlockableInventoryBeforeRunningAnything` 等測試對每個漏斗、每種拒絕原因（ProxyCommand、docker connection、密碼、不在 allowlist 的 `-o`、`ansible_ssh_executable`）用真實的 `ansible`／`ansible-inventory` 與 `ansible-playbook`、`ssh` 的記錄器斷言「什麼都沒執行」，並對同一批漏斗斷言可鎖的 inventory 不被預檢查擋下；lint（§4.6 第 6 點）鎖住每個進入點的預檢查先於它的第一個執行呼叫，以及沒有從清單外的函式呼叫漏斗。
- **三個漏斗的 hostvars 都是 `loadDeployInventorySnapshot`（行為變更，P2-2 review 之後補記）。** 它先跑 `validateInventorySecretStorage`，再跑**不帶 vault 密碼**的 `ansible-inventory --list`。所以 `pilot access`、breakglass、drift 修復與 `pilot host decommission` 對下列 workspace 現在會在取鎖前拒絕：group_vars／host_vars 裡有 contract 宣告為 `secret: true` 的明文輸入（secret 該放 `.vault/main.yaml`）；整份 group_vars 被 ansible-vault 加密（`ansible-inventory` 沒有密碼讀不了：`Attempting to decrypt but no vault secrets found.`，2026-11-06 以本機 ansible-core 2.19.2 實測）。這些指令原本不經過這兩道檢查，同一個 workspace 在 P2-2 之前能跑；runbook §4.3 與各指令的 `--help` 寫給操作者。
- **已知缺口（P2-2 review 之後補記，風險 R12）。** 取鎖的 target 只來自 `ansible-inventory --list` 的 hostvars，所以下列對 playbook 有效、對鎖與預檢查**看不見**：`-e @file`（與 JSON 物件形式的 `-e`）提供的 `ansible_host`、`ansible_user`、`ansible_port` 等連線變數與 `target_group`；`ansible.cfg` 的 `ssh_args`、`host_key_checking`；環境變數 `ANSIBLE_SSH_ARGS`（pilot 自己的 ssh 固定 `BatchMode=yes`、`ControlPath=none`，不讀這些）。後果最重的是：`target_group` 或 `ansible_host` 只由 `-e @file` 提供時，鎖可能鎖 A 機而 playbook 的目標是 B 機。這不是這個 PR 修的：連線設定要寫在 inventory，不要寫在 `-e @file` 或 ansible.cfg；`-e target_group=<g>`（key=value 形式）在 deploy 路徑有被解析（`resolveDeploymentScope` 的 `extraVarValue`），access 與 decommission 不傳 `target_group`。已知缺口與 P1 同類，live arm 以真實 inventory 驗證，不涵蓋 `-e @file` 提供的連線變數。

### 4.3 等待與失敗策略

**決定 D4。**

- 每個 CLI 漏斗最多等 **30 分鐘**（受 ctx 約束），每 30 秒在 stderr 印一行進度（哪台 server、已等多久、上限）。一輪完整 identity 約 26–27 分鐘（計畫 §1），所以 30 分鐘夠等一輪完整的 legacy 執行。
- `pilot reconcile --lock-wait <時間>`（兩個 engine 都有；`0` 立即失敗，driver 的忙碌測試用它）。`pilot deploy`、`pilot access …`、`pilot host decommission` 沒有旗標，用預設值。
- `pilot edit` 的 TUI breakglass（`cmd/pilot/cmd/edit_tui_roster_breakglass.go:164`、`:193`）是同步呼叫、`context.Background()`、沒有進度畫面，等待 **0**；錯誤訊息指向會等待的 `pilot access breakglass activate`。**TUI 的 host decommission 同樣等待 0**（P2-2 review 之後；`pushDecommissionExecute`，與 CLI 是同一個 `runHostDecommissionApply`）：它也是在 Bubble Tea 的 update loop 裡同步呼叫、沒有 context 可取消、沒有畫面可顯示進度，預設的 30 分鐘等待會讓終端機凍結，Ctrl-C 也到不了它。鎖忙碌時在任何步驟之前立即失敗，畫面寫明沒有步驟執行、approval 保留、用 `pilot host decommission resume --id <id>`（會等鎖）或重新進入這個畫面繼續；CLI 的 `apply`／`resume` 仍等 30 分鐘。等待時間與進度的寫入對象由 ctx 帶進（`withIdentityLockWait`／`withIdentityLockProgress`，與 `pilot reconcile --lock-wait` 同一個機制），TUI 把進度丟棄（寫到 stderr 會弄花畫面）。測試：`edit_tui_decommission_lock_test.go`（假鎖：請求的 `Wait` 是 0、進度不是 stderr、畫面內容、什麼都沒改、approval 保留、同一份 plan 之後由 `resume` 完成；CLI 的等待不受影響；真實 flock：持有者在時 TUI 立即返回）。
- **自動化步驟（`pilot edit --actions`、scenario、MCP apply）的 breakglass 失敗就是步驟失敗（E40；AGENTS.md §5.8，found live）。** 畫面把啟用或停用的結果顯示成 `❌` banner，driver 原本只導覽、按 Enter 就回傳，所以被拒絕（預檢查、鎖忙碌、掉鎖）或失敗（playbook）的 `activate_breakglass`／`deactivate_breakglass` 都**回報成功**：`--actions` 結束碼 0、沒有輸出，MCP apply 說 "applied"，而什麼都沒有執行、沒有任何緊急存取生效。現在畫面用 `editRouterModel.failedAction` 建 banner，同一處把失敗（含「啟用／停用哪個 grant 沒做成」與原因）記在 router 上，driver 每按一個鍵與每個步驟結束時取走（`takeStepFailure`，與名冊寫入被拒絕的 `writeRefused` 同一條路）：步驟以 `step N (activate_breakglass): break-glass <name>: activation failed: <原因>`（停用是 `deactivation failed`）失敗，`--actions` 停在那一步（之前的步驟保留），apply 整個 rollback 並回傳 `apply_failed`（MCP 的 `rolled_back: true`）。**措辭只說操作失敗，不說啟用的狀態**（P2-2 review 之後從 `was not activated`／`was not deactivated` 改成這樣）：失敗可以發生在 FreeIPA 已被改動**之後**——playbook 已套用規則而紀錄寫不進去（原因訊息是 `activation applied to FreeIPA but recording state failed`，停用則是 `deactivation applied to FreeIPA but recording state failed`）、或 playbook 以 0 結束之後掉鎖（R14）——那時「沒有啟用」是假的，緊急存取其實已生效。FreeIPA 還沒被改動之前就失敗的啟用（預檢查拒絕、鎖忙碌、playbook 失敗）不留紀錄，失敗的停用不改紀錄；之後才失敗的，原因訊息會說 FreeIPA 已改動，要用 `pilot access breakglass status` 檢查並重跑或 `deactivate`。MCP 看到的 registry Description 寫明失敗就是步驟失敗、apply 的 rollback 不收回已生效的啟用（R15）、plan 不執行這兩個步驟而以 warning 略過。不是比對 banner 的字串：全 repo lint `TestRegression_FailureBannersAreRecordedForTheDriver` 要求 `edit_*.go` 裡每個 `❌` 開頭的字面值只出現在 `failedAction`。**plan 不執行這兩個步驟**（它們對 FreeIPA 跑 playbook 並寫本機狀態，plan 的暫存副本預覽不了；暫存副本也沒有 `inventory.yml`）：plan 以 warning 回報「沒有執行 `<action> <name>`」，**不是失敗**（失敗的 plan 永遠不能被 apply；MCP 的 apply 一定要先有 plan），apply 才會執行並可能失敗。已知限制見 R15。
- 取鎖等待由遠端的 `flock --wait N`（`N`＝`--lock-wait`）界定，**不另外包 `timeout`**（`internal/sshdial/lock.go:56-59`）：Ctrl-C 之後留在遠端的等待者最多活到 `N` 秒（R9）；包 `timeout` 會在 `N` 加寬限之後把持有中的鎖一起殺掉，而 flock 的等待與持有在同一個行程裡，無法只包等待階段。
- 忙碌：`ErrLockBusy`，訊息指名 server 與路徑。ssh 失敗：整輪失敗，**永不在沒有鎖的情況下繼續**。
- **不提供略過（bypass）**：略過會重新引入清除交錯與覆蓋交錯。安全的替代方案是計畫的選項 (iv)（`auth_pending` 加世代）。見 U2。
- **補充（`--timeout` 與等待）**：`pilot reconcile --engine golang --force` 的 `--timeout` 分段計算：取鎖之前的 preflight 在自己的期限內（沿用 P1 的 `--timeout` 語意）、取鎖等待由 `--lock-wait` 界定、取鎖之後的讀取、入口、寫入與驗證整段**重新**以 `--timeout` 計時。否則預設 30 分鐘的等待會吃掉整個 30 分鐘的執行期限。SIGINT／SIGTERM／SIGHUP 在任何階段都取消。
- **補充（`--lock-wait` 的適用）**：`--lock-wait` 只對會取鎖的執行（`--force`）有意義；與 `--preview-only` 同時使用即拒絕（預覽不持鎖），與 `--plan-out` 對 Ansible engine 的處理一致。
- **已知限制（P2-2 review 之後補記，風險 R13）：`--ask-vault-pass`／`--ask-become-pass`。** deploy／reconcile 精靈選了這兩個之一時，密碼提示發生在 ansible-playbook 裡，也就是取鎖**之後**：操作者輸入密碼的時間算在持鎖時間裡，與 D1「預覽、唯讀查詢與互動確認的等待都不持鎖」不同（`--check` 預覽同樣會問，但它不持鎖）。**選擇記錄為已知限制，不拒絕這兩個旗標**：拒絕會讓今天可用的 ansible engine 流程失效，而且沒有辦法在取鎖前先問（提示在 ansible-playbook 內，要先問就得由 pilot 自己問密碼再傳進去，那是 Phase 4 的 `--ask-vault-pass` 範圍）；後果只是持鎖變長（別的 run 要多等，互斥本身不受影響，I1 不被破壞）。要避免就用 `--vault-password-file`。decommission、access、breakglass、drift 沒有這兩個旗標。

### 4.4 `Lost()` 處理

**決定 D5。**

- **會包 ansible-playbook 的漏斗**：只有 ansible-playbook 的指令 ctx 用 `held.Bind(ctx)`。掉鎖就取消這個指令（ansible-playbook 被殺；#138 的 journal 設計為 crash-safe），該步驟以包著 `ErrLockLost` 的錯誤失敗，訊息 `lock lost; FreeIPA may be partially reconciled; rerun`——即使 ansible-playbook 已經以 0 結束（交錯的另一輪可能已經動過）。`Transaction.RunResult` 的 ctx 與步驟證據用的 ctx **不被取消**，所以 outcome 是 `failed`（`FailedStep` 是掉鎖時正在執行的步驟，原因是 `ErrLockLost`），不是 `evidence_failed`。每個步驟結束後檢查 `Held.Active()`：已掉就把該步驟的結果改為失敗（唯讀的驗證步驟不被取消，但結果作廢）。
- **Go writer**：WriteGate 用 `Active()` 在每次寫入呼叫或每個 batch 之前檢查，掉鎖後拒絕**新的**寫入。Go 的 RPC ctx **不因掉鎖取消**，所以進行中的 batch 回傳它真正的答案並照實記錄（成功就是 `success`，不是 `unknown`）；之後不再送任何寫入；驗證讀取（Read₃）照常執行（讀取不需要鎖）；結果是失敗，若已有 `success` 或 `unknown` 的操作則為 `partial_failed`（§6.1）。取消 RPC 的只有操作者的訊號與 `--timeout`，那種取消下進行中的寫入是 `unknown`（P0 的語意）。
- 驗證讀取用 `context.WithoutCancel` 加上有界的期限（**補充**，常數 `golangVerifyTimeout`，初值 60 秒；比照 P1 登出用的 10 秒），所以掉鎖、`--timeout` 與第一次 Ctrl-C 之後仍會嘗試讀一次；第二次 Ctrl-C 立即結束 pilot（P1 spec §2.5 已知限制 3）。讀取失敗就保留 unknown。
- 殘餘（R8）：server 端先放掉鎖、client 還沒發現的情形看不到；文件記錄。
- 殘餘（R2，P2-2 review 之後補記）：掉鎖時 `Bind` 取消的指令 ctx 只殺 ansible-playbook **主行程**（`exec.CommandContext`），不殺它的 process group。ansible 的 fork worker 可能在掉鎖**之後**把正在執行的那一個 task 做完，那個 task 沒有鎖的保護；不會有新的 task（主行程已死）。與 R2 的孫行程拖延同一個原因，一併留給 #261；runbook §4.3 寫給操作者。
- 殘餘（R14，P2-2 review 之後補記）：breakglass `Activate` 在掉鎖時回傳 `ErrLockLost`，而那在它記錄 activation **之前**（`applyPlan` 先回傳）：即使 playbook 已以 0 結束、規則已在 FreeIPA 啟用，`breakglass-activations.json` 沒有這筆紀錄，直到重跑 `activate`（apply 是冪等的）或 `deactivate`（把規則收掉）；`Deactivate` 同理，掉鎖時不標記 `deactivated`，規則可能已被收掉而紀錄仍是 active。不改順序：先記錄再 apply 會在 apply 失敗時留下一筆不存在的啟用；錯誤訊息已寫明 FreeIPA 可能已被部分調和、要重跑；runbook §4.3 寫給操作者。
- 殘餘（R16，E41）：decommission 的 `Bind` 套在整個 `decommission.Apply` 的 ctx：它只用於指令（freshness 的唯讀查詢、各步驟的 ansible-playbook），沒有 journal、step 證據或 `delivery` 的寫入會吃這個 ctx（`Store.SavePlan`、`RecordApproval` 等不帶 ctx），所以 §4.1「Bind 只用在指令的 ctx」成立。掉鎖時 `Executor.Run` 在下一步之前看到 ctx 已取消而停止，執行中的 playbook 被殺，converge 步驟自己也用 `Require` 拒絕已掉的鎖；`Apply` 之後的 `held.Check()` 把「context canceled」換成包著 `ErrLockLost` 的錯誤。一輪已開始之後的掉鎖留下什麼，見 R16。

**類別規則：記錄 run 結果的寫入不隨取消失敗。** 同一類錯誤出現過兩次：一個可能已被取消的 run ctx 傳進了「記錄這個 run 結果」的寫入，寫入因 ctx 已取消而失敗，把真正的結果遮掉。第一次是 step 證據，第二次是外送的 webhook。所以這裡只定**一條**規則，不逐點修補：

> **任何在 run 的 ctx 可能已被取消（掉鎖、`--timeout`、Ctrl-C）之後，還要記錄這個 run 結果的寫入，都在 `context.WithoutCancel(ctx)` 加有界期限之下執行。**

已對 main `402ca398` 核對的兩個既有案例：

- `Transaction.runStep`（`internal/delivery/transaction.go:208-216`）用步驟的 ctx 寫 `step_finished` 事件，寫入失敗時回傳 `errEvidencePersistence`，**丟掉步驟自己的錯誤**；`RunWriter.appendEvent` 經 `withImmediateTx` 以 `db.Conn(ctx)` 取連線（`internal/store/delivery_evidence.go:353-359`），ctx 已取消就失敗。所以取消 `RunResult` 的 ctx 會把 `failed`／`partial_failed` 變成 `evidence_failed`，並失去 `ErrPartiallyApplied`。`RunWriter.Finish` 已經避開這件事：它用 `context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)`（`delivery_evidence.go:302`）。
- `publishTerminalWorkflow(ctx, …)`（`cmd/pilot/cmd/outbound_workflow.go:379`）把 command ctx 交給 `CheckWorkspaceBinding`（`internal/outbound/outbox.go:546-547` 的 `BeginTx(ctx)`）、`ReconcileWebhookConfig`、`EffectiveBase`、`EnqueueBatch`、`FlushWebhooks`，以及 `buildOutboundProjection` 內的 `resolveInventoryVariables(ctx, …)`（執行 `ansible-inventory --list`，`cmd/pilot/cmd/deploy.go:2988-2996`）；六個呼叫者（`deploy.go:3379`、`:3907`、`:4000`，`access_cli.go:264`，`access_breakglass_cli.go:184`，`gateway_scope.go:469`）都傳 command ctx。P1／混合路徑的 ctx 是 signal ctx，SIGINT 或 `--timeout` 會讓 enqueue 失敗（訊息「event NOT durable」），一個有已提交寫入的 `partial_failed` run 因此不發布任何事件。

**sink 清單**（這張表就是規則的登記表，新的 sink 要加進來，見下面的測試）：

| # | sink | 位置 | 負責 PR | 期限（脫離取消的路徑上） |
|---|---|---|---|---|
| T1 | journal 事件（`identity.op`、`identity.verify`、`identity.auth_cache`） | `identityreconcile.Execute` 對 sink 的每個呼叫（含 Read₃） | P2-5（executor 保證，不靠 sink 的實作） | `evidenceAppendTimeout`，初值 5 秒 |
| T2 | step 證據（`step_finished`） | `Transaction.runStep` | P2-6 | 同上 |
| T3 | 終端 run 寫入（`run_finished`） | `RunWriter.Finish` | 已有（`delivery_evidence.go:302`） | 5 秒 |
| T4 | `--result-out` 檔 | users-groups 與混合的收尾 | P2-6 | 本機檔案寫入，不吃 ctx；列在表裡是因為它不能被「ctx 已取消」的錯誤路徑跳過 |
| T5 | 外送的 projection 與 snapshot（`buildOutboundProjection` → `resolveInventoryVariables`） | `publishTerminalWorkflow` | P2-6 | `outboundPublishTimeout`，初值 30 秒（整個 publish 共用） |
| T6 | outbox 寫入（`CheckWorkspaceBinding`、`ReconcileWebhookConfig`、`EffectiveBase`、`EnqueueBatch`） | `publishTerminalWorkflow` | P2-6 | 同 T5 |
| T7 | webhook 送出（`FlushWebhooks`） | `publishTerminalWorkflow` | P2-6 | `webhookFlushTimeout`，初值 10 秒；盡力而為：送不出的事件留在 outbox，之後由 `pilot webhook flush`（`cmd/pilot/cmd/webhook.go:276`，用 `context.Background()`）送出 |
| T8 | `pilot verify` 的 evidence（`AppendEvent` 與 `AppendEvidence`，`internal/tools/verify_spec.go:500`、`:526`） | Verify 步驟裡既有的 `pilot verify`（`autoDeployVerify`） | **有理由的豁免** | 不適用：它記錄的是一次本身會被取消打斷的驗證——取消時 Verify 步驟不執行或中止，不存在「取消之後還要記錄的結果」，run 的結果由 T2、T3 記錄。登記表仍要有這一列，否則掃描會把它當成未登記的 sink |

- **改在哪裡，以及何時脫離**：T1–T3 一律在脫離取消的 ctx 下寫，並加 5 秒上限（短的本機 SQLite 寫入；`Finish` 今天就是這樣）。T5–T7 由 P2-6 在 `publishTerminalWorkflow` 的開頭判斷一次：**只有 `ctx.Err() != nil`**（進入時 run 的 ctx 已被取消）才以 `context.WithTimeout(context.WithoutCancel(ctx), outboundPublishTimeout)` 衍生 ctx 並用於整個函式，flush 另外限 `webhookFlushTimeout`；`ctx.Err() == nil` 的正常路徑**維持今天的行為**：flush 預算是 30 秒（`DefaultFlushOptions`，`internal/outbound/dispatcher.go:238`），projection 的 `ansible-inventory` 不加期限。不一律加期限的原因：一律加會把今天的 30 秒 flush 預算與沒有上限的 projection 改成別的上限，正常路徑的 publish 不該因為這個修正而變；另一個做法是把期限設得不小於 flush 預算加 projection 的耗時，但 projection 今天沒有上限，找不到有意義的數字。進入之後才收到的訊號（發布到一半被中斷）仍是操作者的決定，行為同今天。六個呼叫者（包括非 identity 的元件）在同一個地方被涵蓋。T2 同樣改在 `runStep`，P2-2 不需要改它：掉鎖不取消 `RunResult` 的 ctx。
- **行為變更（所有元件）**：只發生在取消路徑——取消之後，step 證據不再變成 `evidence_failed`，publish 在期限內完成而不是靜默失敗；代價是取消後的行程退出最多延後 `outboundPublishTimeout`（其中 flush 最多 `webhookFlushTimeout`），第二次訊號仍立即結束 pilot。**正常路徑的 publish 沒有行為變更**（flush 預算 30 秒、projection 不加期限）；唯一的正常路徑差異是 T1、T2 的 5 秒上限（`Finish` 今天已是）。列入 P2-6 的測試與 §14。
- 不改 `runStep` 對真實 store 失敗的處理：脫離取消之後 append 仍失敗，才是 `evidence_failed`。
- **測試**：一個表格驅動的單元測試 `TestTerminalSinksSurviveCancel`，案例至少有：users-groups 有已提交的操作、混合的 Go 階段、混合的 playbook 階段、掉鎖；每個案例在失敗點（以 fake 在 D31 的同樣位置）取消 run 的 ctx，然後逐個 sink 斷言已持久化：outbox 有 `failure` 的事件（`failure.class` 依 `FailedStep`）、`--result-out` 檔已寫出且可解析、journal 事件在（`identity.op` 的送出與結果、`identity.verify`）、step 證據在、run 的列是終態（`run_finished` 為 `partial_failed`）。另一個登記表測試 `TestTerminalSinksAreRegistered`：走訪 `cmd/pilot/cmd`、`internal/identityreconcile`、`internal/delivery`、`internal/outbound`、`internal/tools` 的非測試程式碼中對 `AppendEvent`、`AppendEvidence`、`Finish`、`EnqueueBatch`、`CheckWorkspaceBinding`、`ReconcileWebhookConfig`、`FlushWebhooks` 與結果檔建立的呼叫（`internal/tools/verify_spec.go:500`、`:526` 登記為 T8 的有理由的豁免），要求所在的函式出現在上表對應的測試登記表（附負責 PR 與脫離取消的位置），新的終端 sink 沒有一列就失敗（AGENTS.md §5.7、§5.10）；負向對照：加一個合成的 sink 呼叫，測試必須 fail。

### 4.5 時機

**決定 D1。** 鎖取在「確認之後、第一個會改動的執行之前」；預覽、唯讀查詢與互動確認的等待都不持鎖。

- **取鎖前的檢查不是取鎖：** 在下面每個位置之前，每個漏斗已經用同一個推導做過無 ssh 的取鎖前檢查（§4.2），所以不支援的 inventory 在任何步驟之前就被拒絕；取鎖時的檢查保留當縱深防禦。

- **deploy runner**：在 `executeDeploymentTransaction` 的 `apply` closure 裡，確認分支之後（`cmd/pilot/cmd/deploy.go:1446-1460`）、`PrepareApply`（`:1461-1465`）之前取鎖；`txn.RunResult` 回傳後才釋放（涵蓋 verify、冪等性再套用、rollback）。`RunResult` 的 ctx **不**被掉鎖取消；每個會執行 ansible-playbook 的步驟閉包（apply、冪等性、rollback）把自己的指令 ctx 以 `held.Bind` 衍生（§4.1、§4.4）。取到的 `Held` 由 `executeDeploymentTransaction` 的區域變數持有，供各步驟閉包與最後的 `defer Release` 使用。`PrepareApply`（`deploy.go:1330`）目前沒有非測試的設定者，混合執行是它的第一個使用者（§8.3）。
- **`accessgrants.applyPlan`**：extra-vars 檔寫好之後（`internal/accessgrants/reconcile.go:481-487`）、`runner.Run` 之前（`:493`）。
- **decommission**（E41 之後；之前取在 converge 步驟的 `Execute` 內，違反本節第一句）：`runHostDecommissionApply`，**approval 之後、`decommission.Apply` 之前**，一輪只取一次，持有到 `Apply` 結束（含 freshness 的重新推導、所有步驟、驗證與 finalize）。理由：decommission 第一個會改動的執行是 `freeipa_client_uninstall`，converge 是最後一步，鎖取在 converge 就是取在第一個改動之後。`Apply` 的 ctx 以 `held.Bind` 衍生（掉鎖時不啟動下一步並殺掉執行中的 playbook；decommission 的 ctx 沒有證據寫入，見 §4.4），`Apply` 之後 `held.Check()`，最後 `Release`。converge 步驟從 ctx 讀鎖（`identitylock.Require`），不再取第二次。只有「尚未完成且有 converge 步驟」的 plan 取鎖（`needsLock`）；已完成的 plan 重播 receipt，沒有 converge 步驟的 plan 從不跑 identity playbook，兩者都不取、也不預檢查。freshness 的唯讀重新推導也在鎖之下：它讀的狀態在這一輪結束前沒有別的 pilot 執行能改，代價是 plan 過期時要等鎖（最多 30 分鐘）之後才被告知。**取鎖失敗**（鎖忙碌、`Wait` 逾時、等待中取消、拒絕）發生在任何步驟之前：client、roster、server 都沒有改，approval 保留，同一份 plan 之後用 `resume`（需要先前記錄的 approval）或再跑一次 `apply --confirm-host` 都能繼續，不必重新 plan。（等待中的 Ctrl-C／SIGTERM 不屬於「context 被取消」：`apply`／`resume` 沒有安裝訊號處理，行程直接結束，**沒有訊息**，狀態卻同樣沒有改變；`was not started` 的訊息只在鎖忙碌、逾時、被拒絕與 context 被取消時出現）
- **從不取鎖**：`--check` 預覽、唯讀 inspect 查詢（`--tags freeipa_host_absent_inspect`，`internal/decommission/providers/freeipa_client.go` 的 `query`，約 `:875-901`）、drift probe、Go `--preview-only`。
- **混合 run**：在 `apply` closure 取一次，`PrepareApply`（Go 的入口與寫入）與 playbook 都在這把鎖之下，不經過取鎖包裝重新取（同一把鎖不可重入，會死鎖）。

### 4.6 全 repo lint（AGENTS.md §5.10）

**決定 D6。** `cmd/pilot/cmd/identity_lock_funnel_test.go`，六部分（第 6 點是 P2-2 review 之後補上的取鎖前檢查）：

1. **引用 allowlist**：對 `cmd/`、`internal/` 的非測試 `.go` 做 AST 走訪；凡是不含空白、且包含 `freeipa-identity-apply.yml` 或 `freeipa-identity-auth-cache.yml` 的字串 `BasicLit`，以及每個對 `accessgrants.DefaultPlaybook`（含 package 內的裸識別字）的引用，都必須在 allowlist 項目 `{檔案, 角色: 漏斗或資料, 理由}` 內。目前的項目：`internal/accessgrants/reconcile.go:30`（常數與 `applyPlan` 所在，漏斗）、`internal/accessgrants/breakglass.go:123`／`:187`（把它交給 `applyPlan`，漏斗輸入）、`cmd/pilot/cmd/host_decommission.go:596`（資料，接進 decommission 的漏斗）、`cmd/pilot/cmd/deploy_catalog.go:74`（catalog 資料）、`cmd/pilot/cmd/access_cli.go:86`、`cmd/pilot/cmd/access_breakglass_cli.go:88`、`:92`（旗標預設值，資料）。含空白的說明文字（例如 `cmd/pilot/cmd/roster_lint.go:27-28`、`cmd/pilot/cmd/edit_actions_registry.go:906`）依構造排除。
2. **具名漏斗 AST 檢查**（以函式與方法名稱比對，不比 receiver，因為漏斗經介面呼叫）：`applyPlan`、`(*freeipaIdentityConvergeStep).Execute`（讀 ctx 裡這一輪的鎖：`identitylock.Require` 先於 `e.provider.exec`，E41）、`runHostDecommissionApply`（取鎖在 `ds.RecordApproval` 之後、`decommission.Apply` 之前，條件只有 `needsLock`；`lockFunnel.Confirm` 要求確認呼叫存在、而且沒有任何一個在取鎖之後，E41）、`executeDeploymentTransaction` 的 apply closure、`executeRecordedDeploymentCore`（在 options 的字面值設 `IdentityLock`），以及 Go 的入口路徑。要求取鎖呼叫先於第一個執行呼叫（`runner.Run`、`e.provider.exec`、`decommission.Apply`、`runOnce(false…`）；執行 auth-cache 入口的函式必須接收 `*identitylock.Held`。注意 `--playbook` 可以覆寫（`cmd/pilot/cmd/access_cli.go:86`、`cmd/pilot/cmd/access_breakglass_cli.go:88`、`:92`），所以 `applyPlan` 裡的取鎖是無條件的。
3. **contract 守衛**：沒有元件的 `dependencies` 指向 `freeipa-identity`（目前確實沒有）；`freeipa-identity` 沒有 `canonical_apply` 的 remediation（目前只有 `contracts/alertmanager.yaml:35`）；`freeipa-identity` 維持 `site.include: false`（`contracts/freeipa-identity.yaml:65`）。之後任何一項被改變，測試失敗，直到那條路徑也取鎖。
4. 註解寫明 dev 路徑的排除與理由（I1）。
5. **執行期拒絕**（lint 第 1 點看不到的呼叫者）：`executeDeploymentTransaction`（`cmd/pilot/cmd/deploy.go:1381`）在任何 ansible-playbook 之前檢查，playbook 是 identity apply（以與第 1 點相同的檔名常數判斷）而 `options.IdentityLock == nil` 就回傳錯誤。預覽也要求設定它（它只是 acquirer，預覽不呼叫）。`executeDeployment`（`deploy.go:1323`）傳空的 options，目前沒有非測試的呼叫者，卻是最容易被新程式碼拿去用的入口；這道檢查把它與其他直接建構 options 的呼叫者一併擋下。測試：`executeDeployment` 與空 options 的呼叫對 identity playbook 失敗，對其他 playbook 不受影響。
6. **取鎖前檢查**（§4.2）：每個進入點（`identityPrecheckFunnels`：deploy 與 reconcile 的 `executeRecordedDeploymentWithAuthorizationResult` 與 `executeCatalogBatch`、五個 CLI 指令、兩個 TUI 畫面動作、`runHostDecommissionApply`、`identityLockFor`）要在它的第一個執行呼叫之前呼叫預檢查，並先於它之後才能做的事（顯示計畫、要求授權、記錄 approval）；無條件（decommission 的條件是 `needsLock`：plan 尚未完成且有 converge 步驟；TUI 的呼叫在畫面的 closure 裡，只檢查順序）。呼叫漏斗的函式（`executeRecordedDeploymentCore`、`accessgrants.{ReconcileOnce,RepairManaged,Activate,Deactivate}`、`decommission.Apply`）只能從清單上的函式呼叫（`identityProtectedCalls`），清單上的項目必須仍然真的呼叫它（過期項目失敗）；直接呼叫 `newIdentityLock` 的地方（`identityLockBuilders`，目前是 `identityLockFor` 與 deploy 的 Core；decommission 經 `identityLockFor`，provider 的註冊表不再建鎖，所以 `plan` 不建鎖）逐檔計數，清單外的呼叫失敗；`identityLockPrecheck` 與其他測試接縫一樣不准非測試程式碼賦值。

**負向對照**：lint 自己的表格測試餵合成原始碼（缺取鎖呼叫、取鎖在執行之後、新的未列入引用），比照 `internal/sshdial/start_lint_test.go`（`TestRegression_SSHStartsOnlyThroughStart`）；PR 附變異驗證的紀錄（拿掉任一漏斗的取鎖，lint 與 §4.7 的序列化測試都要 fail）。

### 4.7 交錯與順序測試

**決定 D7。** 下面的單元測試必須在任何 live Go 寫入之前通過（計畫 Phase 2 取鎖閘門）：

- `TestAuthCacheClearInterleavingWithoutLockLosesObligation`、`…OverwriteInterleavingWithoutLockLosesObligation`：驅動**真實**的 helper（`python3`、暫存 journal），照計畫「清除交錯」「覆蓋交錯」的精確順序，斷言混合 playbook 的 settle 時 `dirty=false`——這個危害是真的，它就是區別性對照：沒有鎖，義務確實被丟掉。
- `TestFunnelsSerializeAuthCacheObligation`：同樣兩種順序經兩個漏斗呼叫驅動，ansible-playbook 換成呼叫真實 helper 的假腳本，`sshdial` 的假 ssh 走 `local` 模式，鎖路徑用暫存目錄（`LockOptions.Path`）：第二個漏斗等待或失敗，義務存活到混合 run 自己的 settle 與 ack。拿掉任一漏斗的取鎖呼叫，它就 fail。
- 每個漏斗的順序測試（假 acquirer＋假 runner 記錄 `lock, run(--check), run(apply), idempotency, release`）；非 identity 的 deploy 元件從不取鎖；`--preview-only` 從不取鎖。
- 掉鎖測試（§4.4）：每個漏斗的 ansible-playbook 在掉鎖時被取消、結果仍是失敗（即使 ansible-playbook 以 0 結束）；**deploy 漏斗掉鎖後的 outcome 是 `failed`、原因是 `ErrLockLost`，不是 `evidence_failed`，`step_finished` 事件存在**；`Held.Lost()` 在 `Release` 之後不關閉、`Active()` 在 `Release` 與掉鎖之後都是 false。
- 證據與外送不隨取消失敗（P2-5、P2-6，§4.4 的類別規則）：`TestTerminalSinksSurviveCancel` 與登記表測試 `TestTerminalSinksAreRegistered`；取消的 ctx 下，journal sink、`Transaction.runStep` 與 `publishTerminalWorkflow` 仍寫入；`users-groups` run 在已有 `success` 或 `unknown` 的操作後掉鎖、逾時或收到訊號，結果是 `partial_failed`（`FailedStep` 為當時的步驟），不是 `evidence_failed`；進行中 batch 的真實答案被 journaled。

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

**決定 D10。** Go 在每次執行前建立一個空的暫存檔（`secretpath.PrivateTempDir` 底下、`0600`；先例：`internal/freeipa/probe.go` 的暫存 extra-vars 與 output 檔，以及它「缺少、格式錯誤、自相矛盾一律 fail closed」的處理），路徑以 `-e '{"pilot_identity_auth_cache_output": "<路徑>"}'`（JSON 物件形式：值含空白時 `-e k=v` 會被 Ansible 靜默截斷，`internal/accessgrants/reconcile.go:472-474` 的註解是同一個原因） 傳入。task 把下面的物件寫進去（欄位名稱為擬議）：

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

**結果檔的生命週期。** 入口（`prepare`／`probe`）每次呼叫各用自己新建的空暫存檔。混合 run 的 identity playbook 觀察（`observe`）在整個 transaction 內共用一個路徑，但**每次 ansible-playbook 呼叫之前**都重新建立成空檔：apply 之前由 `PrepareApply` 做，冪等性再套用之前由包住 `Idempotency` 步驟的包裝做。Verify 在冪等性之前執行（`Transaction` 的順序是 apply、verify、idempotency，`internal/delivery/transaction.go:138-178`），讀的是 apply 階段的內容；冪等性再套用寫它自己的內容，其觀察只作參考，義務以 apply 階段為準（冪等性的判準仍是 `changed=0` 與 Go 的零操作 plan）。所以不論先後，都不會把上一階段的結果當成這一階段的，也不會讀到空檔以外的殘留內容。測試：先放上一階段的內容再執行下一階段，解析器讀到的只有這一階段的結果；冪等性階段沒有輸出時 Verify 不受影響。

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

**stage 規則的單一來源（P2-6）**：Go-only 的 `--force` 同時用到兩個各自實作 stage 規則的函式——`golangPreviewStage`（P1 的 stage gate，與 playbook 的三道 assert 等價，`cmd/pilot/cmd/reconcile_golang.go:349`）負責「拒絕或接受」，`stageDecisionFromFlag`（Ansible engine 的 stage 與 confirm 變數，`cmd/pilot/cmd/deploy.go` 內）負責入口的 extra vars。AGENTS.md §5.7：P2-6 要不是合併成單一來源，就加一致性測試——同一組（`--stage`、attestation、主機的環境 group）輸入，兩者對「拒絕或接受」與「產生的 stage 與 confirm 變數」一致；負向對照：改動其中一個的規則，測試必須 fail。

## 6 未結清結果

### 6.1 outcome

**決定 D13。** 使用既有的 `delivery.OutcomePartialFailed`，不新增 outcome。讀取者已逐一核對（main `402ca398`）：

- `outcomeExitCode` 回傳 1（`internal/delivery/transaction.go:228-233`）。
- `aggregateWorkflowResult` 發布為 `failure`、`application_consistency` 為 `partial_or_unknown`（`cmd/pilot/cmd/outbound_workflow.go:232`、`:246`）；`docs/superpowers/specs/2026-09-15-outbound-state-webhook-spec.md:1188-1198` 的對照表已列這一列。
- `completedComponentIDs` 不算它（沒有已確認的效果，`cmd/pilot/cmd/outbound_workflow.go:121-127`）；`store.LastSuccess`（`internal/store/runs.go:153`）與 snmp-exporter 診斷（`cmd/pilot/cmd/mcp_delivery_tools.go:399`）也不把它當成功；evidence 的 redact allowlist 已含它（`internal/evidence/redact.go:509`）。

**為什麼不新增 enum**：`aggregateWorkflowResult` 的 `default` 把任何沒列出的 outcome 發布成 `success`（`cmd/pilot/cmd/outbound_workflow.go:237-238`），新 outcome 會直接變成對外的成功，並且改變 webhook 的 outcome 對照表。這是設計審查發現、計畫沒有寫到的危害。

**新 sentinel `delivery.ErrPartiallyApplied`**：`Transaction.RunResult` 中，apply、verify、idempotency 任一步的錯誤包著它，結果就是 `OutcomePartialFailed`、`FailedStep` 是那一步、**不 rollback**（reconciler 的效果已提交）。目前非測試程式碼沒有任何路徑會產生 `partial_failed`（只有讀取者，grep 確認），這是它的第一個 producer。使用處：

- Go 已有至少一個操作的結果是 `success` 或 `unknown`，之後失敗或結果不明（`FailedStep: apply`）。（補充：設計審查寫「寫了 ≥1 個操作」；全部嘗試的操作都是確定未套用的失敗——`failed`／`conflict-failed`——時沒有東西被改動，記為一般失敗 `failed`，不是 partial。）
- Read₃／Plan₃ 驗證失敗（`verify_failed`，§7.6）而 Go 已有 `success` 或 `unknown` 的操作：`partial_failed`；`FailedStep` 在 `users-groups` 是 `verify`，在混合 run 是 `apply`（Apply 在執行 playbook 之前就拒絕繼續）；沒有已提交的操作則是一般 `failed`。
- 混合 run：Go 已提交之後 playbook 失敗（`apply`）、`pilot verify` 失敗（`verify`）、冪等性失敗（`idempotency`）。
- 掉鎖、取消或逾時發生在 Go 已有 `success` 或 `unknown` 的操作之後（§4.4）。
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
| Plan₂ 有 `blocked`（入口已執行，零寫入） | 兩者 | 結束碼 3、outcome `failed`、`FailedStep: apply`；訊息附上「入口已執行，`auth_pending` 已記錄（多一次刷新，無害）」，`identity.auth_cache` 記 `entry_ran=true`；混合 run 不執行 playbook（I7） |
| Plan₂ 比 Plan₁ 多出破壞性操作（§7.3），零寫入 | 兩者 | 結束碼 1、outcome `failed`、`FailedStep: apply`，訊息指出是哪些操作，要求重新預覽；入口已執行，同上 |

未結清時的訊息（計畫 §(ii)）：「授權快取義務未結清，client 在 SSSD 快取過期前可能仍沿用舊授權；下一次選到 `identity` 或 `client-cache` 的 apply 或完整 apply 會刷新所有 enrolled client（`ipa_identity_refresh_sssd_cache` 為 false 時則要先改回 true）」。pilot 不自己執行 settle、刷新或 ack。

本機證據：delivery 事件 `identity.auth_cache`，payload `{source: this_run|previous_run, entry_ran, probe_pending, observed_acked}`（無秘密）。

**給 webhook 訂閱者與 `runs` 讀取者的注意**（寫進 `pilot` 的 `--help` 與使用說明）：`users-groups` scope 有寫入的 run，在觀察到 `acked` 的完整 run 之前，對外的 `operation.result` 一律是 `failure`（`failure.class` 是 `verify_failed`，`application_consistency` 是 `partial_or_unknown`，`confirmed_effects` 為空，R7、R11）；這不是 Go 的寫入失敗，而是授權快取義務未結清。訂閱者要以 run 的 metadata（engine、scope）與 `identity.auth_cache` 事件解讀，不能把它當成「identity 同步失敗」。零寫入且 `pending=false` 的 `users-groups` run 才是 `success`；`store.LastSuccess` 是否把它當成該主機最近一次成功交付，見 Q6。

### 6.3 結束碼

**決定 D14。** `pilot reconcile --engine golang`：

| 碼 | 條件 |
|---|---|
| 0 | 成功：所有操作完成並驗證；義務已結清，或不需要（探測 `pending=false` 的零寫入 run） |
| 1 | 失敗，包括 unknown 與 partial |
| 3 | blocked：plan 有 `blocked` 項目，零寫入（P1 已定；`--force` 同樣）；Plan₁ 就 blocked 時沒有入口，Plan₂ 才出現時入口已執行（§6.2） |
| 4 | 只剩義務未結清：每個 Go 操作都已完成並驗證，沒有別的失敗（driver 用它斷言「零 mutation 且義務如實回報」） |

子行程的結束碼仍不傳遞（P1 spec §2.3）：**混合路徑也一樣**。`--scope full --force` 目前會走 `runReconcileInteractive`（`cmd/pilot/cmd/reconcile.go:90`），不經 `runReconcileGolangPreview`；那條路徑回傳的錯誤若包著 ansible-playbook 的 `*exec.ExitError`，會讓 pilot 以 ansible 的結束碼（3 或 4）結束，被誤讀成 blocked 或義務未結清（P1 spec §2.3 的同一個問題）。所以混合路徑的分派也要套 `runReconcileGolangPreview`（`reconcile_golang.go:111-118`）的 exit-code 保護：非 `golangPreviewError` 的失敗一律包成結束碼 1，只有 blocked 與義務未結清這兩種有名字的結果是 3 與 4。測試：混合 run 的 playbook 以 ansible 的結束碼 3、4 失敗時，pilot 結束碼是 1。history 記的 `run_finished.exit_code` 是 `outcomeExitCode` 的 0／1，CLI 的 3／4 是 CLI 自己的語意；兩者刻意不同。

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
5. **Read₂ → Plan₂**：入口與第一批寫入之間隔著一次 ansible-playbook 啟動，Read₂ 就是計畫 §4 步驟 4 的「寫入前重讀」與「入口空窗的前置條件」；入口已執行，所以 Plan₂ 是權威。與 Plan₁ 的差異回報為 `plan_changed`（R5）：Plan₁ 沒有、Plan₂ 有的**非破壞性**操作照常執行並回報；Plan₂ 比 Plan₁ 多出**破壞性**操作（§7.3 的集合）則**停止、零寫入、不執行**——結束碼 1，要求操作者重新預覽（`--force` 下不替操作者確認一份他沒看過的破壞性計畫）。Plan₂ 有 `blocked`：停止、零寫入、結束碼 3、outcome `failed`，訊息附上入口已執行（§6.2）；混合 run 不執行 playbook（I7）。Plan₂ 為空：Go 結束（入口執行過、Go 沒有寫入；混合 run 繼續交給 playbook）。
6. 依 §7.3 的 stage 執行 Plan₂。
7. **Read₃ → Plan₃**（在 Apply 步驟內執行，判定由 Verify 步驟消費，§7.6）。

**與計畫字面的差異**（§14）：計畫要入口接在「寫入前重讀與重新規劃之後」，並要求測「第一次 plan 沒有寫入、重讀後才產生寫入」。這裡的入口接在 Plan₁ 之後、Read₂ 之前：Read₂ 同時是「寫入前重讀」與「入口空窗的覆蓋」，不需要在入口前多讀一次再於入口後補讀；Plan₁ 為空時沒有任何重讀，也就沒有「重讀後才出現寫入」的情形。對應的測試改為：Plan₁ 非空→入口→Plan₂ 多出 Plan₁ 沒有的操作→入口仍先於第一個寫入；Plan₁ 為空→沒有入口、沒有重讀。

### 7.3 stage、batch 與寫入前的前置條件

**決定 D18。** 依計畫 §7.2 的順序（P1 spec §7.2），每個 stage 的操作互相獨立；跨 stage 就是依賴。每個 batch 最多 **25** 個命令（初值，常數；P2-8 量測後可調，語意不變；Q2）。

| stage | 操作 | 備註 |
|---|---|---|
| S1 | `group_add` | |
| S2 | `group_mod`、marker 的 `group_add`（nonposix） | marker 名稱由 `HistoryMarkerName` 決定（`internal/identityreconcile/marker.go:11`） |
| S3 | `user_add`、`user_mod` | `user_mod` 只帶不同的欄位 |
| S4 | `passwd` | **一位使用者一次呼叫，不進 batch**（B4） |
| S5 | `group_remove_member` | 每個群組每種成員一筆，含所有成員 |
| S6 | `group_add_member` | 同上 |
| S7 | `user_enable`／`user_disable` | `user_disable` 之前有批次重讀（下）；兩者之間沒有依賴 |
| S8 | 刪除 | 先一個 batch 的 `user_show`／`group_show` 加 marker 重讀並判斷下面的謂詞，立即再 `user_del`，最後 `group_del`；marker 必須驗證描述正確才送 `group_del` |

**寫入前的前置條件**（計畫 §4 步驟 5：「每批寫入前檢查所需 live preconditions」；(ii) 也要求入口空窗的外部變更由它涵蓋）。除了入口之後的 Read₂，下列四處（S4、S5、S7 的停用、S8）在送出前再做一次批次重讀（`user_show`／`group_show`，`all: true`，每批至多 25 個）：

- **破壞性集合**（本節各處用它）：plan 的 `destructive` 為 true 的種類（`user.password.reset`、`user.delete`、`group.delete`），加上權限收斂的種類（`group.member_user.remove`、`group.member_group.remove`、`user.disable`；後者是 §14 的補充，依計畫 §4「刪除與權限收斂前即時重讀」）。**Plan₂ 比較 Plan₁ 的規則**：Plan₂ 裡這個集合的操作，以「種類、物件、成員」為粒度（成員撤銷細到每個成員），只要不在 Plan₁ 就是 conflict：停止、零寫入、結束碼 1（§7.2）。
- **S4 之前（`passwd`）**：對所有有計畫 `passwd` 的使用者做一次批次 `user_show`，以與 plan 相同的規則重新判斷：`initialize` 要求沒有 `krblastpwdchange`；`reset` 要求 `preserve_existing: false` 且使用者仍在上次重設的密碼上（`krbpasswordexpiration` 存在且 ≤ `krblastpwdchange`）。不符的使用者 `conflict-failed`、**不送 `passwd`**，並**停止後面的 stage（S5–S8）**；通過的其他使用者照常送出（每位各自一次呼叫）。本輪 S3 新建的使用者也在這次讀取內（讀得到、且沒有 `krblastpwdchange` 才通過）。
- **S5 之前（成員撤銷）**：對有計畫撤銷的群組批次 `group_show`，以 roster 宣告的集合重算 live 直接成員該撤銷的集合：重算結果含 Plan₂ 撤銷清單**沒有**的成員 ⇒ conflict，不撤銷、**停止後面的 stage**；Plan₂ 清單中已不在群組的成員 ⇒ `noop`。
- **S7 之前（`user_disable`）**：停用屬於權限收斂，與其他收窄的操作一樣先做批次 `user_show`，謂詞分兩種使用者：
  - **本輪 S3 新建的使用者**（宣告為 `enabled: false` 或 `state: disabled` 而 live 沒有它：plan 對它產生 `user.create` 加依賴它的 `user.disable`，`internal/identityreconcile/plan.go:466-468`）：Plan₂ 沒有它的觀察，所以**不做 Plan₂ 的比較**；謂詞只有「讀回存在、不是登入的 principal」。
  - **既有的使用者**：存在、`ipauniqueid` 與 Plan₂ 的觀察相同、不是登入的 principal。
  - **已經停用 ⇒ `noop`**，不是 conflict；`nsaccountlock` 不是謂詞（外部先停用只是少做一件事）。只有出乎意料的改變才是 `conflict-failed`：既有使用者不存在、或 `ipauniqueid` 不同（刪除後重建）、或是登入 principal；conflict 不送 `user_disable`，**停止後面的 stage（S8）**。
  - `user_enable`（放寬）不另做重讀，靠伺服器的逐項回應。
- **S8 之前（刪除）**：對要刪除的使用者批次 `user_show`，所有謂詞**在任何 `user_del` 送出之前**判斷完：存在；`ipauniqueid` 與 `uidnumber` 與 Plan₂ 的觀察相同（沒有被刪除後重建）；不是 preserved；不是登入的 principal。（「roster 仍把它列為 absent」不是謂詞：run 綁定開始時載入的 `desired_revision`，Go 不在 run 中途重讀 roster 檔，這個條件恆真。）不存在 ⇒ 該使用者 `noop`；**任何一個使用者的其他謂詞不成立 ⇒ S8 整個停止**：同一批的其他使用者也不刪（`not_executed`），後面的 `group_del` 也不送。`group_del` 的謂詞在它自己的批次重讀之後同樣判斷：存在、`ipauniqueid` 與 `gidnumber` 與 Plan₂ 相同、marker 驗證通過；任何一個不成立，其餘 `group_del` 都不送。
- `LiveUser` 與 `LiveGroup` 因此增加 `ipauniqueid`（`user_find --all` 已帶，`internal/freeiparpc/find_state_fixtures_test.go:261-270`；群組與 `user_show`／`group_show` 的形態列入 K19，擷取前不寫判讀）。

**其餘（S1–S3、S6、`user_enable`）不另做批次重讀**：它們的前置條件由伺服器的逐項回應判斷（add 的 `DuplicateEntry`、mod／enable 的 `NotFound` 都是 `conflict-failed`，§7.4）。這是對計畫 §4 步驟 5 的**刻意放寬**，列入 §14：這些操作冪等或只放寬、失敗時沒有效果、前一個讀取（Read₂）才剛完成；不可逆或收斂權限的操作才各自有上面的重讀。

### 7.4 逐項分類

**決定 D19。**

| 結果 | 意義 | 例 |
|---|---|---|
| `success` | 已套用 | RPC 成功且有 result |
| `noop` | 不需要變更 | `EmptyModlist`、`AlreadyActive`／`AlreadyInactive`、刪除時的 `NotFound`、成員「already a member」／「not a member」 |
| `conflict-failed` | 前置條件已不成立 | add 的 `DuplicateEntry`、mod／enable／disable 的 `NotFound`、成員「no such entry」 |
| `failed` | 被拒絕 | 其他 `RPCError`（含密碼政策）、`ACIError` |
| `unknown` | 可能已套用 | `OutcomeUnknownError` |
| `not_executed` | 因為前面的停止而沒有送出（計畫 §4 步驟 6 要求記錄的「未執行項目」） | 第一個 `conflict-failed`／`failed`／`unknown` 之後排程的操作；S8 因任何一個謂詞不成立而停止時，同批與後面的刪除；前置條件重讀不成立而被跳過的使用者之後的 stage |

`DecodeMemberResult`（`internal/freeiparpc/commands.go:253`）必須讓每個成員都有去處。第一個 `conflict-failed`、`failed` 或 `unknown` 之後停止排程後面的操作與 stage，這些操作記為 `not_executed`；目前這個 batch 已送出，記錄完它的所有逐項答案；然後執行驗證。`--result-out` 與 `identity.op` 事件列出每個操作的結果類別，所以操作者看得到一次停止跳過了什麼。前置條件重讀（§7.3）不成立而沒有送出的操作是 `conflict-failed`（沒有送出），它之後被跳過的才是 `not_executed`。分類所依據的真實回應形態來自 §9 的擷取（X3）。

### 7.5 重試與 unknown

- **寫入不重送**，唯一的例外是 client 已證明「401 發生在指令執行之前」的重新登入（P0）。讀取：client 內建的一次 transport 重試與一次重新登入；executor 不另加。
- **unknown 不重送**，由 Read₃ 把它分類為 `converged`、`not-applied` 或 `still-unknown`。密碼的值無法比對：時間戳只能當提示（`initialize`：`krblastpwdchange` 出現；`reset`：`krbpasswordexpiration` ≤ `krblastpwdchange`），操作維持 unknown、run 失敗。重跑是安全的，因為決定是依狀態做的（已有 key 就不再初始化；仍在重設的密碼上就不再重設）；**不宣稱 exactly-once**（計畫 §4）。
- 取消、逾時與掉鎖時的行為見 §4.4。

### 7.6 驗證

**決定 D20。** Read₃ 重讀整份 managed 狀態並重新規劃：Plan₃ 不得含任何**已嘗試**物件的操作，否則 `verify_failed`；Go 已有 `success` 或 `unknown` 的操作時，這個失敗是 `partial_failed`，否則是一般 `failed`；`FailedStep` 在 `users-groups` 是 `verify`，在混合 run 是 `apply`（Apply 在執行 playbook 之前就拒絕繼續，§6.1 與下面的步驟說明）。「Plan₃ 不空」在整份規格裡都是這一句的定義：**在這一輪嘗試過的物件上仍有操作**。這同時是行程內的「第二輪零寫入」檢查。驗證讀取用 §4.4 的有界 ctx。

**Read₃／Plan₃ 在哪一個 transaction 步驟執行（補充）。** Read₃ 在 **Apply 步驟內**執行：寫入失敗或 unknown 時也要讀，才能分類 unknown（§7.5），而 Apply 失敗之後 `Transaction` 不會執行 Verify。Apply 步驟的 Go 階段回報**寫入階段**的結果（`failed`、`conflict-failed`、`unknown` 的操作，有 `success`／`unknown` 的操作就包 `ErrPartiallyApplied`）；Plan₃ 的判定（在嘗試過的物件上是否仍有操作、`unknown` 的分類、Read₃ 本身是否成功）存起來。之後：

- **`users-groups` scope**（沒有 playbook）：由 **Verify 步驟**消費判定。**Read₃ 失敗讓 Verify 失敗**（讀不到就沒有驗證，結果是 unknown 而不是通過）；Plan₃ 在嘗試過的物件上仍有操作（D20 的定義）也讓 Verify 失敗（`FailedStep: verify`）。
- **混合 run**：**Go 階段失敗、Read₃ 失敗、或 Plan₃ 在這一輪嘗試過的物件上仍有操作（D20 的定義）時，Apply 步驟在執行 playbook 之前就失敗，不執行舊 playbook**（計畫「混合執行模型」：失敗或 unknown 的 Go 階段之後不跑舊 playbook）。這種失敗記為 `FailedStep: apply`（Apply 步驟拒絕繼續），錯誤的原因是 Go 階段的失敗或 `verify_failed`，`identity.verify` 事件記載原因；有 `success`／`unknown` 的操作就包 `ErrPartiallyApplied`。Go 階段與 Read₃ 都成功、嘗試過的物件上沒有殘留操作，才執行 playbook。**沒有嘗試過的物件上的 drift**（外部在這一輪中改了無關的物件）**不擋 playbook**，只在 Plan₃ 與 `--result-out` 報告：它不是這一輪寫入的結果，比 D20 更嚴格的規則會讓一個無關物件的外部變更擋住整個混合 run。混合的 Verify＝既有的 `pilot verify`、義務（§8.3）。
- Apply 失敗時 Read₃ 的結果照樣寫進 `identity.verify` 事件與 `--result-out`，`FailedStep` 仍是 `apply`。

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
- `password.initial` 的處理分三層：(1) **非字串**（數字、布林、list、mapping）：P2-1 的 adapter 在建立 tunnel 之前就拒絕，不論有沒有密碼操作（訊息提醒加引號讓它保持字串，§7.9）；(2) **`null`**（`password.initial: ~`）：等於沒有 initial password，不產生密碼操作，兩個 engine 一致；(3) **範本與 inline `!vault`**：decode 之後只剩一個字串，adapter 的型別檢查看不出它們與一般字串的差別，只有上面的 Node 判斷看得出——**在有計畫的密碼操作時**一律新的 blocked 原因 `password_value_unsupported`（roster 可以用範本寫 `password.initial`，`playbooks/apply/tasks/freeipa-identity-normalize-users-groups.yml` 的開頭註解 `:5-10` 與 `:55`）；沒有計畫的密碼操作時不擋（no-op 的 run 不該因為它被擋）。
- 語意與 playbook 相同：`preserve_existing` 預設 true；`force_change: false` 沒有作用（已知缺口，計畫 Phase −1）；決定規則在 `playbooks/apply/freeipa-identity-apply.yml:1233-1257`，roster 的預設在 normalize 檔 `:55-57`。
- RPC 形態：`passwd [principal] {password}`（P0 的 `internal/freeiparpc/live_test.go:303` 用法）；成功與政策拒絕的真實回應列入 K6。

### 7.9 lifecycle、managed ownership 與先拒絕

**決定 D23、D25。**

- `absent`：永久 `user_del`（不帶 `preserve`，與 playbook 相同，`playbooks/apply/freeipa-identity-apply.yml:1718-1730`）；群組刪除前必須即時重讀並驗證 marker（`:1734-1782`）。
- Go 只碰：roster 宣告的使用者與群組、它們的 marker、roster 群組的直接成員（authoritative 撤銷＝playbook 語意）；刪除只針對 `state: absent`。其他物件永不出現在操作中。
- **history marker**：每個套用中的群組在 S2 確保 marker 存在（`group.marker.create`；名稱 `HistoryMarkerName`，描述 `HistoryMarkerDescription` 即 `pilot.group-history/v1 name=<name>`，`internal/identityreconcile/marker.go:11-19`）；刪除群組前（S8）重讀並驗證 marker 存在且描述正確才送 `group_del`，marker 衝突維持 `blocked`（`marker_collision`）。**使用者 lifecycle**：`absent` 是永久刪除；與 preserved 使用者同名維持 `blocked`（`preserved_user`），Go 不做 preserve／undelete。
- `blocked` 原因與 P1 spec §7.3 相同，**沒有一個變成支援**；新增 `password_value_unsupported`（§7.8）與 `protected_object`（§7.10）。
- **#273（P2-1，已在 Phase 2 分支實作；規格以該實作為準）**：P1 的 adapter 把型別錯誤與明確的 `null` 當成未宣告，或當成 Go 自己的預設值。預覽時只是顯示不對的計畫，有寫入時是錯的寫入：錯型別的 `membership` 讀成「authoritative、沒有成員」會撤銷所有直接成員；`enabled: ~` 在 playbook 是 `ipa user-disable`（`freeipa-identity-apply.yml:1697` 的 `item.enabled | default(true) | bool`，`default()` 不取代 `null`），Go 卻讀成 enabled。adapter 在**任何讀取或寫入之前**拒絕（沿用既有的 roster-adapter gate：結束碼 1、沒有 tunnel、沒有請求、沒有 plan，不新增 `// gate:` id；訊息指出欄位與 roster 物件，只寫型別、不寫值）。判斷準則：Go 套用自己的預設值的鍵，playbook 對 `null` 的讀法若不同就拒絕；Go 不管理的鍵，`null` 就是不管理。兩組 helper 分開，新增的鍵必須選一邊：
  - **`null` 拒絕**：使用者的 `state`、`enabled`、`first`、`last`、`login_shell`、`home_directory`；群組的 `state`、`type`、`description`；頂層 `users`、`groups`（不寫與 `[]` 才是空）；`freeipa.admin.principal`（playbook 的 `principal | default('admin')` 保留 `None`，kinit 會要 `None@REALM`，Go 卻會以 `admin` 登入）；nested 的七個鍵 `membership.users`、`membership.groups`、`membership.authoritative`、`ssh_keys.values`、`ssh_keys.authoritative`、`password.preserve_existing`、`password.force_change`。
  - **`null` 接受，等於「不管理」**：使用者的 `uid`、`gid`、`display_name`、`email`，群組的 `gid`（playbook 以 `is none` 略過參數，與不寫相同；`pilot edit` 的 roster 精靈對空白的整數欄位寫 `null`，隨 repo 出貨的範例 roster `playbooks/apply/freeipa-identity.roster.example.yaml` 也寫 `uid: null`，拒絕它會拒絕 pilot 自己產生與提供的 roster）；`password.initial: ~`（等於沒有 initial password，§7.8）；`freeipa` 與 `freeipa.admin` 本身的 `null`（等於未設定，P1 spec §4 的 N3 規則）。
  - `users`、`groups` 若存在必須是 list（其他型別拒絕）；每個元素必須是 mapping（非 mapping 的元素拒絕），而且它的 `name` 必須是字串（非字串的 `name` 拒絕）。
  - `password`、`ssh_keys`（使用者）與 `membership`（群組）若存在必須是 mapping：`null` 與其他型別都拒絕，`{}` 與不寫視為未宣告；`password.initial` 若存在且不是 `null` 必須是字串（只檢查型別，值不載入）。
  - `state: absent` 的項目不被 reconcile，但仍檢查 `password`、`ssh_keys`、`membership` 三個鍵的形狀（不讀裡面的內容）：playbook 的 gate 對每個項目都呼叫 `.keys()`，一份只在 absent 項目上錯型別的 roster，Ansible engine 本來就拒絕。
  - **空字串 `""` 是一個值，不是 `null`**：`pilot edit` 對空白的文字欄位（`first`、`last`、`login_shell`、`home_directory`、`display_name`、`email`、群組的 `description`）寫 `""`，兩個 engine 都把 `""` 當成值接受並送出（playbook 的 `is none` 對 `""` 不成立）。FreeIPA 對空值的真實回答尚未擷取，所以 Phase 2 寫入前有一個明確的決定點（Q8；擷取是 K21，P2-4）。
  - 完整清單與 playbook 對每個 `null` 的實際讀法，記在 P1 spec §5.1 的對應條目（已隨 P2-1 更新）。比 playbook 嚴格是允許的（P1 spec §5.1）。`ValidateRoster` 本身不變：它是 Ansible engine 的入口（Q1）。
- **寫入前先拒絕**：adapter 拒絕與 Plan₁ 的 `blocked` 一律零寫入、沒有入口；Plan₂ 才出現的 `blocked` 也是零寫入，但入口已執行（§6.2）；混合 run 在這些情況下都不執行 playbook（I7）。`users-groups` scope 的 `not_in_scope`（P1 spec §5.3）只報告，不阻擋，因為 scope 的定義就是不宣稱整份 identity。

### 7.10 自鎖保護

**決定 D24（待使用者確認 U3）。** 新增 blocked 原因 `protected_object`。判斷的對象是 **plan 在每個 stage 邊界的模擬狀態**，不只是最終狀態：S5 的成員撤銷先於 S6 的成員新增，所以「把登入 principal 從 `admins` 直接成員改成經過 `ops` 這個本身屬於 `admins` 的群組」在最終狀態下成立，但 S5 之後、S6 之前它沒有任何通往 `admins` 的路徑，S6 的 `group_add_member` 會以 `ACIError` 失敗，engine 在 run 中途鎖死自己（而寫入已部分套用）。

- **規則**：以 live 的群組直接成員圖為起點，依 stage 順序累積套用 plan 的操作（S1–S3 的建立、S4 的密碼、S5 的撤銷、S6 的新增、S7 的啟用或停用、S8 的刪除），在**每個 stage 之後**的圖檢查登入 principal：存在、`enabled`、並且對 `admins` **遞移可達**（`user_find` 的 `memberof_group` 是遞移的，見 P1 spec §6.3 與擷取）。任何一個邊界不成立就 blocked，訊息指出是哪個邊界（例如「S5 之後」）與缺了什麼。實際需要檢查的邊界是 S5 之後（撤銷之後、新增之前：live＋S1–S3 的建立－S5 的撤銷，**還沒有 S6 的新增**）、S7 之後與最後（S8 之後）；其餘 stage 不會讓可達性變差，但規則對每個邊界一視同仁，不寫死哪些邊界。
- **為什麼擋，而不是把會影響 principal 的新增排到撤銷之前**：兩者擇一，這裡選前者。調換順序會偏離 playbook 的「先撤銷、再新增」（P1 spec §7.2），改變 H2 要求的 legacy 收斂比對基準，並且讓權限在收窄之前先放寬一段時間；擋下來的代價是操作者得把這種變更拆成兩次 roster 編輯（先建立新路徑，再移除舊路徑）——對一個在 run 中途鎖死自己的 engine 是可以接受的代價，而且訊息會說明該怎麼拆。
- 也擋：
  - 刪除或停用登入的 principal（上面的「存在、enabled」在 S7、S8 之後的邊界涵蓋它）。
  - 對登入 principal 自己的 `user.password.reset`：run 中途換掉登入密碼會讓之後的 session 與 relogin 失敗，而且 `passwd` 沒有讀回比對（§7.5）。（`initialize` 不會發生在登入帳號上：它已經有密碼。）
  - 刪除 `admins`、`ipausers`、`editors`、`trust admins`。
- 因此「直接從 `admins` 撤銷，但路徑（principal ∈ `ops` ∈ `admins`）在 live 就已存在」不擋；「撤銷巢狀群組唯一的路徑」會擋；「同一個 plan 才建立新路徑」（路徑在 S5 之後還不存在）會擋。
- 測試：逐 stage 邊界的表格測試（每個邊界各一個「應該觸發」與「應該通過」的 row；其中「同一個 plan 建立路徑」與「路徑已存在」是一對區別性對照）；live 見 A14、A21。

這比 playbook 嚴格（P1 spec D9 的同類取向）；沒有它，roster 可以在 run 中途移除 engine 自己的讀取權限，之後的驗證讀取失敗，而寫入已經套用。

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

- 自己的 delivery run（`store.StartRun`，metadata 記 engine 與 scope），經 `delivery.Transaction`（Apply＝Go 的 `Execute`，含 Read₃；Verify＝Plan₃ 的判定加義務，§7.6）與 `publishTerminalWorkflow`，effects 為 `identity.users`、`identity.groups`（`PublishTerminalWorkflowInput.Effects` 容許專用 frontend 指定固定子集，`cmd/pilot/cmd/outbound_workflow.go:314-319`；contract 的 effects 列表在 `contracts/freeipa-identity.yaml:4-12`）。
- **從不執行 identity playbook**；入口執行過或探測 `pending=true` 就是義務未結清（§6.2）。
- **收尾的寫入遵守 §4.4 的類別規則**：journal、step 證據、終端寫入、`--result-out`、外送 projection、outbox 與 webhook 送出（T1–T7）在 SIGINT、`--timeout` 或掉鎖之後都用脫離取消的 ctx 加有界期限；一個有已提交操作的 `partial_failed` run 一定留下 outbox 的 `failure` 事件。這個 scope 的 ctx 是 P1 的 signal ctx，所以不遵守這條規則就會在取消時發布不出事件。
- 一個全新主機的 journal 不存在，探測視為 `pending=true`，直到第一次完整 playbook run 觀察到 `acked=true`。

### 8.3 full scope（混合）

**決定 D28。** 重用 Ansible reconcile 路徑（`runReconcileInteractive` 的預設值 driver → `runCatalogPlaybookDeploy` → 依賴鏈 → `executeRecordedDeploymentCore`），以 ctx 上的標記啟用，所以 availability／deferred、預覽、stage、history、webhook、冪等性與 runtime-race 的邏輯都不重複（AGENTS.md §5.7）。只對 identity 的那個 transaction：

- 額外參數 `-e pilot_identity_users_groups_engine=go -e '{"pilot_identity_auth_cache_output": "<暫存檔>"}'`（路徑一律用 JSON 物件形式傳，不用 `-e k=v`）。**`extra_var_keys` 的 metadata 不能被它弄壞**：`deploymentMetadata` 以第一個 `=` 切每個 extra var 來記 `extra_var_keys`（`cmd/pilot/cmd/deploy.go:3058-3065`），一個 JSON 物件形式的元素切不出正確的 key（會把 `{"pilot_…": "/路徑` 之類的片段當成 key，或整個丟掉）。P2-7 讓它辨認 JSON 物件：元素以 `{` 開頭就解析並**只記錄頂層 key**（`pilot_identity_auth_cache_output`），**永不記錄值**；其他 `k=v` 照舊。讀 extra vars 的其他函式（`extraVarValue` 等，`cmd/pilot/cmd/deploy_dependency_plan.go`）只認 `k=v`，它們不需要讀這兩個變數。測試：以混合 run 實際使用的 extra vars（路徑含 `=` 與空白）呼叫 `deploymentMetadata`，`extra_var_keys` 恰是預期的 key、不含路徑片段。
- Preview：加上 Go 的唯讀 plan；有 `blocked` 就預覽失敗，不取鎖。
- Apply：取鎖（I1）→ `PrepareApply`＝`Execute`（ctx 以 `Attach` 帶 token，`HeldFrom` 取得，不被掉鎖取消，§4.1）→ playbook（指令 ctx 以 `Bind` 衍生）。Go 階段失敗、Read₃ 失敗或 Plan₃ 不空（D20 的定義：嘗試過的物件上仍有操作），playbook 都不執行（I7、計畫「混合執行模型」，§7.6）。`PrepareApply` 之前先把觀察結果檔重建為空檔（§5.4 的生命週期）。
- Verify：先既有的 `pilot verify`，再解析 apply 階段的觀察結果：該主機的 `acked`；否則 `ErrUnsettled`（§6.2）。
- Idempotency（≥ staging）：觀察結果檔重建為空檔後，playbook 再套用一次，再加上 Go 的唯讀 plan 必須 0 個操作；它的觀察只作參考（§5.4）。
- 在 Go 已提交至少一個操作之後，任何後續步驟的失敗都以 `ErrPartiallyApplied` 包起來（§6.1）。
- **收尾的寫入同樣遵守 §4.4 的類別規則**（T1–T7）：混合 run 的 ctx 是這裡的 signal ctx，取消之後 `publishTerminalWorkflow` 與 step 證據仍在脫離取消的有界 ctx 下完成。
- 這條路徑的錯誤也要經 `runReconcileGolangPreview` 那一層的 exit-code 保護，包成結束碼 1、3、4（§6.3；`runReconcileInteractive` 本身不做這件事）。
- **訊號處理（補充）**：互動式 reconcile 路徑沒有 `signal.NotifyContext`（`runReconcileInteractive` 只用 `withDeployAnsibleRuntime(cmd.Context(), runtime)`，`cmd/pilot/cmd/reconcile.go:113`；P1 spec §3 說明根 context 沒有接訊號），今天在那條路徑上 Ctrl-C 會讓 pilot 以預設動作立刻結束，沒有 Read₃、沒有 journal 的「之後」事件。混合 run 有 Go 寫入，不能這樣。所以 **`--engine golang --scope full` 的整個 run** 套用與 P1 預覽相同的 `signal.NotifyContext(SIGINT, SIGTERM, SIGHUP)`（SIGHUP 在啟動時已被忽略就不接）；這是 opt-in 的 engine，不改變 `--engine ansible` 的行為。第一次訊號：**Go 階段**取消 Go 的 RPC ctx（不再送新的寫入，進行中的寫入是 `unknown`），Read₃ 在脫離取消的有界 ctx 下仍然嘗試（§4.4），playbook 不執行，最後釋放鎖；**playbook 階段**取消 ansible-playbook 的指令 ctx（它也會收到終端機送給同一個 process group 的訊號），該步驟失敗，鎖在 `RunResult` 之後釋放；兩種情況的 outcome 都依 §6.1（有 `success`／`unknown` 的操作就是 `partial_failed`），證據用脫離取消的 ctx 寫入。第二次訊號立即結束 pilot（預設動作恢復，P1 spec §2.5 已知限制 3）。測試：混合 run 在 Go 階段與 playbook 階段各收到一次 SIGINT（單元層級以 fake，live 見 A17(iii)(iv)）。

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

依 AGENTS.md §5.6，判讀規則只能來自真實擷取。擷取有三種，各有負責的 PR：

- **RPC 擷取（K6–K15、K19、K21，P2-4 負責）**：在拋棄式 FreeIPA 測試 VM 上經 P0 的 tunnel 以 `freeiparpc` 擷取，fixture 放 `internal/freeiparpc/testdata/`，以測試鎖住（每個擷取附竄改探測），擷取後刪除測試物件。`passwd` 的 fixture 不得含密碼：擷取用一次性的隨機密碼，request 不存進 fixture（response 本來就不含密碼），並有測試掃描 fixture 目錄，確認該密碼字串不在任何檔案裡（比照 P0 的 live 測試）。
- **Ansible 擷取（K16–K18，P2-3 負責）**：對全新 VM 跑真實的 `ansible-playbook`（入口與 identity playbook），輸出存成 fixture（放 `internal/identityreconcile/testdata/`，檔名由 P2-3 決定）；不手寫格式。
- **client 觀察（K20，P2-6 負責）**：在 acked 基準上以一位真實使用者做一次等價的人工觀察，結果定義 §10.2 各 arm 的 allow／deny 判準，在 arm 之前完成。

已有的擷取不重做：`user_add`／`user_mod`／`user_enable`／`user_disable` 成功與常見失敗（含 `user-mod-acierror.json` 的 `ACIError`）、`group_add`、`group_add_member`（成功、已是成員、成員不存在）、`group_remove_member` 的 not-member、`batch` 的混合（讀取成功、`NotFound`、`EmptyModlist`），見 `internal/freeiparpc/testdata/`。

| # | 擷取 | 決定什麼 | 負責 |
|---|---|---|---|
| K6 | `passwd` 成功；密碼政策拒絕（錯誤名稱、代碼、訊息）；各 `maxlife` 下 `passwd` 之後 `user_show` 的時間戳 | §7.8 的 RPC 形態、`failed` 的分類、unknown 的時間戳提示 | P2-4 |
| K7 | `user_del` 成功與 `NotFound` | 刪除的 `noop` 判讀 | P2-4 |
| K8 | `group_del` 成功與 `NotFound` | 同上 | P2-4 |
| K9 | `group_mod`（description）成功與 `EmptyModlist` | S2 的分類 | P2-4 |
| K10 | marker 的 `group_add`（nonposix，帶 description）成功，以及 `group_find` 讀回的 `objectclass`／description | S2 與 S8 的 marker 驗證 | P2-4 |
| K11 | `group_add` 的 `DuplicateEntry` | `conflict-failed` | P2-4 |
| K12 | `group_remove_member` 成功（使用者與群組成員） | S5 的分類 | P2-4 |
| K13 | `group_add_member` 以 `group` 成員（成功、已是成員、不存在） | S6 的分類 | P2-4 |
| K14 | `user_add`／`user_mod` 各選項的名稱：`givenname`、`sn`、`displayname`、`mail`（含多值的取代語意）、`loginshell`、`homedirectory` | S3 的欄位對映；email 宣告時「整組 `mail` 剛好等於 `{email}`」要怎麼達成 | P2-4 |
| K15 | 含一個 `DuplicateEntry` 項目、其餘成功的寫入 batch | §7.4 的 batch 部分失敗處理 | P2-4 |
| K16 | 入口的真實 ansible-playbook 輸出與結束碼：`no hosts matched`（預期 0）、task 被 `when` 跳過、多台主機；以及 funnel 用的 `ansible <pattern> --list-hosts` 在空比對與多台時的輸出 | §5.4 的解析器，「入口結束碼為 0 不能證明義務已寫入」 | P2-3 |
| K17 | controller 端 `copy`（`delegate_to: localhost`）結果檔：成功、目的目錄不可寫、`become` 的影響 | R6 | P2-3 |
| K18 | identity playbook 的 `observe` 結果檔（§5.5）的真實輸出：`acked` 為 true；`acked` 為 false 的三種原因（`ipa_identity_refresh_sssd_cache` 為 false、`pilot_deferred_hosts` 與 `freeipa-client` 有交集、settle 沒有執行所以 `dirty` 缺值）；block 內較前面的 task 失敗而沒有觀察檔；`--limit` 之下 | §5.4 的 `observe` 解析器（「應該通過」與「應該觸發」兩種案例）、§5.5 對 `is defined`／`default` 的讀法 | P2-3 |
| K19 | S4、S5、S7（`user_disable`）、S8 之前的批次重讀（§7.3）：`user_show`／`group_show` 的 `all: true` 回應欄位——`ipauniqueid`、`uidnumber`／`gidnumber`、`krblastpwdchange`、`krbpasswordexpiration`、`nsaccountlock`、`preserved`、群組的直接成員；preserved 使用者的 `user_show`；batch 中一項 `NotFound` 時其餘項目的答案 | 前置條件謂詞（§7.3）的判讀；`LiveUser`／`LiveGroup` 增加 `ipauniqueid` | P2-4 |
| K20 | client 上「allow／deny」的判準：哪個使用者、哪個動作、哪個可觀察的結果。預期的形態：roster 使用者（有 HBAC 與 sudo 授權、有 `password.initial`）在 client 上以密碼登入（`ssh` 結束碼 0＝allow，認證或存取被拒＝deny）與 `sudo -n` 的結果；撤銷之後立即（SSSD 快取內，X6）與經 refresh 之後各觀察一次，記錄各自需要多久、用什麼有界的等待判斷（不用 sleep 當證明）；登入用的密碼來自 vault，不進 argv 或輸出 | A6、H1、H3、H4 的 allow／deny 斷言、X6 的量測 | P2-6 |
| K21 | FreeIPA 對**空值**的真實回答：`user_add`／`user_mod` 對 `givenname`、`sn`、`loginshell`、`homedirectory`、`displayname`、`mail` 給 `""`，`group_add`／`group_mod` 對 `description` 給 `""`（成功、清除，或錯誤；錯誤名稱、代碼與訊息） | Q8：`""` 是否對必填的鍵拒絕、對 `display_name`／`email` 代表什麼 | P2-4 |

## 10 測試與驗收

### 10.1 單元測試證明什麼

**單元測試只證明邏輯與 fixture 的對應；它們不證明 sshd 的 flock、真實 inventory、playbook 的行為與真實的寫入回應。** 那些由 §10.2 的 live 測試證明。

- 取鎖：§4.6 lint 與變異驗證、§4.7 的交錯與順序測試、`Held.Lost()` 在 `Release` 之後不關閉、掉鎖取消 ansible-playbook、`TargetFromHostVars` 的每一列（含 `ansible_connection: docker`）。
- 入口：結果解析器的「應該通過」與「應該觸發」兩種案例（真實輸出，K16）、`auth_inspect`（journal 不存在→`true`、domain 不符→錯誤、不建立任何檔案）、§5.6 的一致性測試、結果檔的 round-trip。
- outcome：§6.4 的測試、結束碼矩陣（含混合路徑的 playbook 以 ansible 的結束碼 3、4 失敗時 pilot 結束碼是 1，§6.3）、`partial_failed` 不被 `LastSuccess` 當成成功、webhook 的 `result` 與 `failure.class`、`Plan₂ blocked` 與 Plan₂ 破壞性差異的結果（§6.2）、Plan₃ 驗證失敗有已提交操作時是 `partial_failed`。
- writer：WriteGate 對每個寫入方法與 batch（零請求；`Active()` 在 `Release` 與掉鎖後都擋）；stage 與 batch 的邊界；逐項分類矩陣（K6–K15 的 fixture）；unknown 的分類矩陣；**前置條件（§7.3）**：S4 的 `passwd` 在使用者已被外部設過密碼時不送出且後面的 stage 不執行、S5 的撤銷在群組多出 Plan₂ 沒有的成員時不執行、S8 的 `user_del` 在 `ipauniqueid` 改變（刪除後重建）／preserved／登入 principal 時不送出且後面的刪除停止，每一條都有「應該觸發」與「應該通過」的 row（K19 的 fixture）；S7 的 `user_disable` 各有 row：**本輪新建且宣告為停用的使用者通過**（沒有 Plan₂ 比較）、既有使用者已被外部停用（`noop`，不是 conflict）、被刪除後重建（conflict）、是登入 principal（conflict），S8 在同一批有兩位使用者而其中一位謂詞不成立時**兩位都不刪**、`group_del` 不送；Read₃ 在 Apply 步驟內執行：寫入失敗時 `FailedStep` 是 `apply`、Read₃ 的結果仍寫進 `identity.verify` 與結果檔；`users-groups` 在 Plan₃ 不空（D20 的定義）或 Read₃ 失敗時 Verify 失敗（`FailedStep: verify`）；混合 run 在 Go 階段失敗、Read₃ 失敗或 Plan₃ 不空時 **playbook 沒有執行**（`FailedStep: apply`，§7.6），而外部只改了一個**沒有嘗試過的**無關物件時 playbook 照常執行（對照）；`not_executed` 類別出現在 `--result-out` 與 `identity.op` 事件（§7.4）；Plan₂ 多出破壞性操作（`user.delete`、`user.password.reset`、成員撤銷、`user.disable`）時零寫入，多出非破壞性操作時照常執行；journal 與秘密不外洩（每條錯誤路徑）；`password_value_unsupported`（範本與 inline `!vault`，對照：一般字串）、`protected_object`（**逐 stage 邊界**的表格測試：登入 principal 被停用、刪除、移出 `admins`、遞移路徑被切斷、自己的密碼被重設；以及「同一個 plan 才建立通往 `admins` 的新路徑」＝S5 之後不可達而最終可達，必須 blocked，對照「路徑在 live 就已存在」通過，和「非登入的 admin 被改」、「仍經巢狀群組屬於 `admins`」通過）、#273 的每個拒絕的欄位（`null`、錯型別、`absent` 項目的形狀、`freeipa.admin.principal: ~`）各有「應該觸發」的 row，接受的形狀（`uid`／`gid`／`display_name`／`email`／群組 `gid` 的 `null`、`password.initial: ~`、`freeipa` 的 `null`、`{}`、不寫）各有「應該通過」的 row，`""` 依 Q8 的決定各有 row（決定之前不寫）；`passwd` 的 fixture 目錄掃描不含擷取時用的密碼。
- 混合：§8.4 的靜態與 runtime 測試；hook 只對 identity 元件生效；Go 失敗時 playbook 不執行；`ErrPartiallyApplied` 的包裝；Go 階段與 playbook 階段各收到一次 SIGINT 的行為（§8.3）；JSON 物件形式的 `-e` 在路徑含空白時不被截斷。
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

**acked 基準（補充）。** **每個斷言探測或 journal 狀態的 arm 都從 acked 基準開始**，不從全新拓樸開始：journal 不存在時 helper 的 `auth_prepare` 回傳 `previous=True`（`playbooks/apply/files/freeipa-ssh-key-cache.py:196`），所以在全新拓樸上「入口之後 `pending=true`」的斷言沒有入口也成立（空洞），第一次混合 run 也一定會刷新，與入口有沒有運作無關，起點就不區別 (ii) 的機制。基準做法：一次完整的 legacy `pilot reconcile --component freeipa-identity --force`（觀察到 acked）→ 以零差異的 `users-groups --force` 斷言探測讀到 `pending=false`（結束碼 0）→ snapshot；除了 A1（建立基準）與 A11（在 ssh 之前被拒）之外，**每個 arm 都從這個 snapshot 開始（rollback 回來），開始前先斷言 `pending=false`**，下面列出的接續 arm 除外。driver 以自己的 SSH 身分唯讀地讀 journal 的位元組（driver 可以有 sudo，pilot 本身沒有，計畫 §3），在需要時斷言 journal 的值與 server `error_log` 的寫入計數。要驗證 client 行為的 arm，在撤銷**之前**先在 client 上以被撤銷的使用者做一次真實的登入或 `sudo`（K20 定義的 allow 判準），讓 SSSD 快取它的授權。

**接續的 arm**（不 rollback，起點是上一個 arm 的結束狀態；每個的起點斷言不同，driver 逐一斷言，不是「全部 `pending=false`」）：

| 接續的 arm | 接在 | 起點斷言 |
|---|---|---|
| A3 | A2 | journal `pending=true`（A2 的入口寫的），Plan₁ 為空 |
| A4 | A3 | journal `pending=true`；A4 自己的完整 legacy run 讓它變成 acked，之後探測 `pending=false` |
| H2 | H1 | H1 結束時探測 `pending=false`，client 已 deny |
| H3 | A6 | journal `pending=true`，client 仍 allow（A6 的結束狀態），Plan₁ 為空 |
| A18 的 (i)、(ii) | 殺掉 pilot 之後立刻做的 snapshot（每個各自從它開始） | journal `pending=true`、server `error_log` 的寫入計數為 0；(i) roster 已還原成零差異，(ii) 是原 roster |
| H4 的第二次混合 run | H4 的第一次 | journal `pending=true`，client 仍 allow，Plan₁ 為空 |

A9 的兩個子案例（`--lock-wait 0` 與 `30m`）各自 rollback 到基準，起點 `pending=false`。

**每次 rollback 之後（補充）**：`vm-target rollback` 本身會還原 guest 的時鐘（`internal/vmtarget/vmtarget.go:1306-1318` 呼叫 `restoreGuestClock`，失敗會回傳錯誤，`clock.go` 的 `restoredClockMaxSkew` 是 5 秒）；driver 在每次 rollback 之後、做任何 arm 步驟之前，斷言 guest 與 host 的時鐘差在 `restoredClockMaxSkew` 之內，並對該 target 的 ssh 控制連線做 `ssh -O exit`（預防 driver 與 ansible 的 ssh 卡在 rollback 前留下的 ControlMaster），以及清掉該 target 的 Ansible fact cache（`.agents/skills/pilot-trec-verification/references/known-gotchas.md` 記錄 rollback 之後仍需手動清）。時鐘差過大會讓 Kerberos 與 `ipa-client-install` 失敗，那是環境問題，不是 arm 的結果，arm 重跑。

**決定 D31（補充）：決定性的注入點。** 有些 arm 需要在 run 的特定位置做事（入口之後殺 pilot、stage 之間寫入外部變更、讓一個寫入真正「已送出、未回答」）。靠 sleep 競爭無法重現，所以 driver 用 build tag `identity_live_hooks` 建置 pilot（driver 本來就自己建置 binary）：帶這個 tag 的檔案提供暫停點 `after_entry`、`before_stage:<S>`、`before_batch:<S>:<n>`，以及 `after_send:<S>:<n>`——第 n 個 batch 的請求已寫入 tunnel 之後、讀取回應之前暫停（由 tag 版的連線包裝在請求寫出後停止讀取，server 照常處理；實作形狀由 P2-6 決定），這是產生真正進行中的寫入的唯一方式。每個暫停點通知 driver 並等它對一個 FIFO 寫入後才繼續；driver 在暫停時殺掉 pilot、送訊號、殺掉 tunnel 或鎖的 ssh，或用 `freeiparpc` 寫入外部變更。**用到的 arm：A8(ii)、A10（`after_send:S3:1`）、A17（`after_send:S3:1`）、A18、A19、A20、A21。** 預設 build 與發佈的 binary 不含這些檔案；測試鎖住「沒有 tag 就沒有暫停點」，CI 另外編譯帶 tag 的版本（`go build -tags identity_live_hooks ./...`），確保暫停點不會因為沒人編譯而壞掉（Q7）。單元層級以 fake 在同樣的位置重現。

| arm | 做什麼 | 通過條件 |
|---|---|---|
| A1 | legacy `--force` 建立基準 → Go 預覽 | 寫入操作 0（P1 D12） |
| A2 | 新增一位使用者（含 `password.initial`）、一個群組與成員關係，`--scope users-groups --force` | 結束碼 4；操作恰為 `group.create`、`group.marker.create`、`user.create`、`user.password.initialize`、`group.member_user.add`；server `error_log` 的寫入與操作一一對應；Read₃ 零差異；探測讀到 `pending=true`（起點是 `pending=false`，所以這個 true 是入口寫的） |
| A3 | A2 之後重跑 | 零 mutation、沒有入口；探測 `pending=true`；結束碼 4（這算通過） |
| A4 | 一次完整的 legacy run（觀察到 acked）→ 重跑 `users-groups` | 結束碼 0、沒有入口、journal 位元組不變 |
| A5 | 修改一個屬性 | 恰一個 `user_mod`，只帶該欄位 |
| A6 | 從 acked 基準、暖過 client 快取開始：撤銷（移除成員、停用、刪除使用者、刪除群組並驗證 marker），`users-groups --force` | 操作與預期相同、結束碼 4；FreeIPA 上已撤銷，但 **client 仍 allow**（`users-groups` 從不刷新，這是 H1、H3 的對照，不是 bug）；探測 `pending=true`。client 端的 deny 由 H1、H3 證明 |
| A7 | 外部 drift：用 `freeiparpc` 寫入 `givenname`、多餘成員、停用 | 恰 3 個修復；重跑 0 |
| A8 | 失敗與重跑：(i) 密碼政策拒絕；(ii) `after_send:S3:1` 殺掉 tunnel 的 `ssh -W`（請求已送出、答案未讀） | (i) 結束碼 1、後面的 stage 沒有執行、後面的操作是 `not_executed`，修正後收斂；(ii) 該 batch 的寫入是 `unknown`、結束碼 1、Read₃ 分類，重跑收斂且沒有重複 |
| A9 | 忙碌的鎖：legacy `pilot reconcile --force` 執行中，Go `--lock-wait 0` 與 `--lock-wait 30m` | `0` 在 tunnel 與登入之前失敗（`error_log` 沒有 session）；`30m` 等待後成功；journal 狀態符合預期 |
| A10 | 掉鎖：`after_send:S3:1` 殺掉鎖的 ssh（S3 的 batch 已送出、答案未讀） | 進行中的 batch 回傳它**真正的答案**並照實記錄（不是 `unknown`，因為掉鎖不取消 RPC，§4.4）；之後沒有新的寫入；Read₃ 被嘗試；有 `success` 的操作時 outcome 是 `partial_failed`（不是 `evidence_failed`），結束碼 1；**outbox 有 `failure` 的事件**（`failure.class` 為 `apply_failed`） |
| A11 | docker-connection 的 workspace | 在 ssh 之前被拒 |
| A12 | uid 變更 | 結束碼 3、零寫入、沒有入口 |
| A13 | journal 的 domain 不符 | 入口失敗、零寫入 |
| A14 | 登入 principal 的自鎖：(a) 被停用、(b) 被刪除、(c) 直接移出 `admins`、(d) 移出巢狀群組而切斷它唯一到 `admins` 的路徑、(e) 自己的密碼被重設（`preserve_existing: false`）、(f) **同一個 plan 才建立通往 `admins` 的新路徑**：principal 本來直接屬於 `admins`，roster 把它改成只屬於 `ops`（`ops` 在 live 就屬於 `admins`，principal 還不在 `ops`）——最終狀態可達，但 S5 之後、S6 之前不可達 | 每一個：結束碼 3、零寫入、沒有入口，(f) 的訊息指出是「S5 之後」。對照：另一個非登入的 admin 被停用、移出 `admins` 都通過；principal 被直接移出 `admins` 但仍經巢狀群組屬於 `admins` 通過；(f) 的對照是路徑在 live 就已存在（principal 已在 `ops`）時，同樣的撤銷通過，每個邊界都可達 |
| A15 | 需要 `passwd`，但 `password.initial` 是範本，或是 inline `!vault` | 結束碼 3（`password_value_unsupported`）、零寫入、沒有入口。對照：同一個使用者用一般字串通過；未加引號的數字 `password.initial` 在 adapter 以結束碼 1 被拒，沒有 tunnel（§7.9） |
| A16 | 混合 `--scope full --force`，plan 有 `blocked`（例如 uid 變更） | 結束碼 3、零寫入；**playbook 沒有執行**（server 上沒有任何 identity playbook 的 task：沒有 helper 呼叫、沒有 SSH key 區塊） |
| A17 | (i) `after_send:S3:1` 之後收到 SIGINT；(ii) 同一位置 `--timeout` 到期；(iii) 混合 `--scope full`，Go 階段中 `after_send:S3:1` 之後收到 SIGINT（要有真正進行中的寫入才會是 `unknown`）；(iv) 混合，playbook 階段收到 SIGINT | 各自：不再送新的寫入；(i)(ii)(iii) 進行中的寫入被取消，分類為 `unknown`；Read₃ 仍被嘗試；outcome 是 `partial_failed`（有 `success`／`unknown` 的操作），step 證據與 `identity.op` 事件照寫（不是 `evidence_failed`）；(iii) playbook 不執行；(iv) ansible-playbook 被殺、outcome 是 `partial_failed`；第二次 Ctrl-C 立即結束；每種都釋放鎖；**每種的 outbox 都有 `failure` 的事件**（見下面的接收端說明） |
| A18 | `after_entry` 殺掉 pilot（SIGKILL） | 在 acked 基準上：入口之前 `pending=false`；暫停在 `after_entry` 時 journal 為 `pending=true`、server `error_log` 的寫入計數為 0（這才是入口的證明）；殺掉之後零寫入。(i) 把 roster 還原成與 live 一致（零差異）後 `users-groups --force`：結束碼 4、`source=previous_run`；(ii) 原 roster 重跑：再次執行入口、結束碼 4、`source=this_run` |
| A19 | 外部 writer 在 Plan₂ 之後、寫入之前改物件：(a) `before_stage:S4`：被計畫 `passwd` 的使用者已被外部設過密碼；(b) `before_stage:S5`：權威群組被外部加入一個 roster 沒有的直接成員；(c) `before_stage:S7`：要停用的使用者已被外部停用，或被刪除後重建；(d) `before_stage:S8`：要刪除的使用者被外部刪除後重建（`ipauniqueid` 改變），且同一批還有另一位使用者；(e) `after_entry`：外部 writer 讓 Plan₂ 比 Plan₁ 多出一個成員撤銷 | (a) 該使用者不送 `passwd`、S5–S8 不執行；(b) 新成員沒有被撤銷、後面的 stage 不執行；(c) 重建的不送 `user_disable`、後面的 stage 不執行，已經停用的是 `noop`；(d) 整個 S8 停止：兩位使用者都不刪、`group_del` 不送，皆為 `not_executed`；(e) 零寫入、結束碼 1、入口已執行（探測讀到 `pending=true`，起點是 `pending=false`）。每個都有不注入的對照：照常完成 |
| A20 | session 在 run 中途失效（`before_batch:S3:2`）。誘發方式由 P2-4 找（P0 已擷取失效 session 的 401 回應，`user-mod-after-session-logout.body`；活的 server 上怎麼讓 pilot 自己的 session 失效尚未確定） | 讀取：client 重新登入一次後重送；寫入：401 是在指令執行之前才重送（P0 已證明），否則 `unknown`；各自不重複寫入、journal 照寫。若 P2-4 找不到可行的誘發方式，這個 arm 在單元層級以捕捉的 401 回應重放，原因記為有理由的豁免（skip 數仍要列出原因） |
| A21 | 權限在 run 中途被外部收回：`before_stage:S3` 用 `freeiparpc` 把登入 principal 移出 `admins`（模擬 K 擷取的 `ACIError`，`user-mod-acierror.json`）；另一次是以非 admin 的 principal 啟動 | 前者：後面的寫入得到 `ACIError`、分類 `failed`、後面的 stage 是 `not_executed`、Read₃ 嘗試、有 `success` 時 `partial_failed`、結束碼 1；後者：P1 D7 在建立任何讀取之前拒絕（結束碼 1，沒有 plan） |
| A22 | 新增一位宣告為停用的使用者（`enabled: false`；plan 是 `user.create` 加 `user.disable`），`users-groups --force` | 從 acked 基準開始：結束碼 4（義務未結清）；操作恰為 `user.create` 與 `user.disable`、**沒有 conflict**；server 上該使用者存在且 `nsaccountlock` 為真；Read₃ 零差異。對照：同一位使用者在 live 已存在而被停用，走既有使用者的謂詞（`ipauniqueid` 相同）通過 |
| H1 | 從 acked 基準、暖過快取開始：混合 `--scope full --force` 套用與 A6 相同的撤銷（只有 users／groups 變更） | 結束碼 0；server 上 `auth_prepare`（入口）先於第一個寫入 RPC；client 的授權**已 deny**；之後零差異的 `users-groups --force` 結束碼 0（探測 `pending=false`，即 ack 之後 journal 是 false） |
| H2 | H1 之後 legacy 完整重跑 | users／groups 區段的 task `changed=0`（json callback，逐 task） |
| H3 | 緊接 A6（不 rollback，journal 為 `pending=true`、client 仍 allow）：混合 `--scope full --force`，Go 零寫入 | 結束碼 0；playbook 自己的 prepare 讀到 `previous=true`，refresh 與 ack 發生；client **已 deny**；之後探測 `pending=false`（等同「中斷後下一輪」） |
| H4 | 從 acked 基準、暖過快取開始：混合套用同一個撤銷，`ipa_identity_refresh_sssd_cache: false` | 結束碼 4、history 為 `partial_failed`、webhook 為 failure；**client 仍 allow**；探測 `pending=true`。之後打開刷新、混合再跑一次（Go 零寫入）：結束碼 0、client 已 deny |
| H5 | Go 寫入之後 playbook 失敗 | `partial_failed`、結束碼 1 |
| L1–L6（P2-2） | 每個漏斗（deploy／reconcile、`access reconcile --once`、breakglass、decommission）持有鎖（同時另一個連線對 `/etc/ipa` 以 `flock --nonblock --conflict-exit-code 75` 取鎖得到 75）；第二個同時的漏斗等待或失敗；掉鎖殺掉 playbook 且 outcome 是 `failed`（不是 `evidence_failed`）；不支援的 inventory 被拒絕（L10 專測拒絕發生的時機：在任何步驟之前） | 各自通過 |
| L10（P2-2，取鎖前檢查） | 對**真實 inventory**（不是假的 `ansible-inventory`）的 freeipa-server 主機設定 ProxyCommand（另可各測 docker connection、`ansible_ssh_pass`、不在 allowlist 的 `-o`），在 ssh 與 ansible-playbook 的記錄器之下依序跑：(a) `pilot host decommission apply`（plan 含 freeipa-client 的 converge 步驟）與 `resume`；(b) `pilot reconcile --component freeipa-identity --preview-only` 與 `--force`；(c) `pilot access reconcile --once`、`access breakglass activate`／`deactivate`、`access drift --repair-managed`、`identity drift --repair-managed`；(d) `pilot edit --actions` 的 `activate_breakglass` 與 `deactivate_breakglass`（各一個 scenario；E40：這一項是 P2-2 第二輪 review 時在 live 抓到「拒絕卻結束碼 0」的那條路徑）；(e) `decommission plan` | (a) 拒絕且訊息指出 ProxyCommand；client 沒有被解除安裝（`ipa-client` 仍在）、roster 沒有 tombstone、沒有留下 approval；沒有任何 ansible-playbook 或 ssh 啟動；(b) 兩者**同樣被拒絕**，沒有依賴 apply、沒有預覽；(c) 拒絕、沒有探測、沒有 playbook；(d) **結束碼非 0**、步驟錯誤是 `step N (activate_breakglass): break-glass <name>: activation failed: 取鎖前檢查沒有通過…ProxyCommand`（stderr，沒有 ssh 與 playbook），沒有 breakglass 狀態檔的新紀錄，前面的步驟保留；(e) plan 成功、結束碼 0、stderr 有警告。拿掉 ProxyCommand 後同一批指令不被預檢查擋下 |
| L11（P2-2，decommission 的取鎖時機，E41） | 對**真實**的 FreeIPA server 與一台已 enroll 的 client（拋棄式），`pilot host decommission plan` 之後：(a) 另一個持有者（pilot 自己的 `AcquireLock`，不是外部 `flock`）持有 `/etc/ipa` 鎖，`apply --confirm-host` 在等待中收到 SIGTERM（另測 Ctrl-C，以及持有者讓等待逾時的情形；前兩者是行程直接結束，沒有訊息）；(b) 持有者放鎖後 `resume`（另一輪：再跑一次 `apply --confirm-host`）；(c) apply 進行中（uninstall 之前）由另一條連線把持鎖的 ssh session 殺掉（掉鎖） | (a) 沒有任何步驟執行：client 仍 enrolled（`ipa-client` 仍在，`ipa host-show` 仍有 host 紀錄）、roster 沒有 tombstone、`hosts.yml` 不變、approval 保留——**對 SIGTERM 與 Ctrl-C 斷言的只有這些狀態，不斷言訊息**（行程直接結束，沒有訊息，沒有安裝訊號處理）；等待逾時與忙碌鎖的情形才有錯誤訊息，寫明 `was not started` 與 no step ran；(b) 同一份 plan（同一個 plan id、同一個 hash）完成，鎖在 uninstall 之前取、converge 之後放；(c) 這一輪以 `ErrLockLost` 結束、converge 沒有啟動（可能已部分 uninstall，見 R16）。E41 的 live 發現來自 Root 在 candidate `1751a83e` 的實跑；修正後的 candidate `91f82abb` 已重跑 (a)–(c)（SIGTERM 與 Ctrl-C 兩種，掉鎖；[pr-284](../../evidence/freeipa-go-reconcile/pr-284.md)，沒有測持有者讓等待逾時的情形，那只有單元與真實 flock 的整合測試） |
| L7（P2-2） | legacy 執行中 `kill -9` pilot，觀察 ansible-playbook 是否繼續、鎖何時釋放 | **只記錄（X5）**，不判定通過 |
| L8（P2-2） | 取鎖等待期間（另一個持有者執行中）按 Ctrl-C | 本機沒有殘留 ssh；遠端的 `flock --wait` 行程不會超過 `--lock-wait`（它本來就在 `N` 秒結束，`internal/sshdial/lock.go:56-59`，R9）；**記錄**它實際多久消失 |
| L9（P2-2） | **持有者是 pilot 自己的 `AcquireLock`**（測試 harness 以 `sshdial` 取鎖並持有，不是外部的 `flock`；要證明的是 pilot 自己的取鎖指令沒有被計時器限制），持有的時間遠超過另一個等待者的 `--lock-wait` 加寬限（例如等待 10 秒、持有 60 秒） | 等待者在 `N` 秒後以 `ErrLockBusy` 結束；**持有者的鎖沒有被任何計時器殺掉**（60 秒後另一個連線對 `/etc/ipa` 以 `flock --nonblock --conflict-exit-code 75` 仍得到 75）——這證明取鎖的遠端指令沒有被 `timeout` 之類的包裝限制住持有階段（R9） |
| P（P2-8） | 計畫 §6 的目標：120／40 無差異 p95 ≤ 30 秒（20 次樣本）、單一屬性 ≤ 30 秒、100 次新增 ≤ 120 秒加重跑 0、1,000／200 的完整性、入口耗時（與整輪分開呈現）、混合整輪 wall time、SSH RTT 與版本 | 記錄實際數字；未達要說明原因，不放寬門檻 |

H1 與 H3 各有對照（A6 與 H4 的 client 仍 allow），兩者都從 acked 基準開始、暖過快取、做同一個撤銷；只有走過入口（H1）或由下一次零寫入混合 run 補上刷新（H3）的 run 讓 client deny。「入口寫下義務」由 A18 證明：在 acked 基準上，入口之前 `pending=false`，`after_entry` 暫停時 `pending=true` 且寫入計數為 0——在全新拓樸上這個斷言會空洞地成立（缺 journal 就是 true），所以不用它。A2 的 `pending=true` 同樣來自基準；「ack 之後 `pending=false`」由 H1、H3 的最後一步證明。

**outbox 的斷言（A10、A17 的每個子案例）**：driver 在 workspace 放一份 integrations 設定，指向 driver 自己的本機 HTTP 接收端。通過條件：接收端收到 `operation.result` 為 `failure` 的事件，或（flush 因 `webhookFlushTimeout` 沒送出時）outbox 有 pending 的 `failure` 事件，之後 `pilot webhook flush` 送達；`failure.class` 與 `FailedStep` 對得上（§6.1）。這是 §4.4 類別規則的 live 證明：沒有這條規則時，取消會讓 enqueue 失敗而什麼都不發布。

### 10.3 退出條件

計畫的 Phase 2 退出條件對應到上面的 arm：

- 取鎖閘門已通過：lint 與兩種交錯的 regression test（§4.6、§4.7）加 L1–L6。
- 新增、修改、撤銷、外部 drift 修復、第二輪零 mutation、失敗重跑在 live target 通過：A2–A8；新 gate 與新路徑的觸發證明（AGENTS.md §5.12 第 2 點）：A10、A14–A22。`users-groups` scope 的第二輪通過條件是「零 mutation 且義務如實回報」（A3），不是「結果為成功」；成功要求兩輪之間有一次觀察到 `acked=true` 的完整 playbook run（A4）；全新主機的 journal 不存在，同樣是未結清。
- 效能目標：P。
- 混合全量 run 在 live target 通過，其後以 legacy 全量重跑時 users／groups 相關 task `changed=0`：H1、H2；授權快取刷新由 acked 基準上的對照證明（H1、H3、H4 對 A6）。
- 完整的 `go test -race ./...` 由 CI 的 `Go test` job 執行（AGENTS.md §5）。

## 11 PR 序列

每個 PR 都可以獨立合併。target_validation 依 AGENTS.md §1.4：`required` 表示需要拋棄式 VM 上的實跑；`not-needed` 附理由；目前沒有 `blocked`（需要的是一台由 Root 管理的拋棄式 FreeIPA 測試 VM）。

| PR | 範圍 | 主要檔案 | 驗收 | target_validation | 相依 |
|---|---|---|---|---|---|
| P2-0 | 這份規格與計畫的狀態、過期敘述更正 | 本檔、計畫 | 決定與擷取表；沒有可執行的 SOP | not-needed：只有文件 | — |
| P2-1 | #273：adapter 在任何讀取或寫入之前拒絕型別錯誤與明確的 `null`（§7.9 的清單，含 `absent` 項目的形狀與 `freeipa.admin.principal`；Go 不管理的鍵的 `null` 接受）。**已在 Phase 2 分支實作**；P1 spec §5.1 的對應條目已更新 | `internal/identityreconcile/desired.go` 與測試（沿用既有的 roster-adapter gate，不新增 `// gate:` id）、P1 spec §5.1 | 每個拒絕的鍵（`null` 與錯型別）與每種形狀錯誤（`users`／`groups` 不是 list、元素不是 mapping、`name` 不是字串）一個「應該觸發」的 row；接受的形狀（`uid`／`gid`／`display_name`／`email`／群組 `gid` 的 `null`、`password.initial: ~`、`freeipa` 的 `null`、`{}`、不寫）各一個「應該通過」的 row；隨 repo 出貨的範例 roster 與 `pilot edit` 寫出的 roster 通過 | not-needed：拒絕發生在建立 tunnel 之前，沒有連線可驗證（預覽會走到 adapter，由 cobra 層測試涵蓋） | — |
| P2-2 | **取鎖閘門** | `internal/identitylock`（`Held` 的 `Active`／`Attach`／`Bind`）、`internal/sshdial/hostvars.go`、`accessgrants` options、decommission config、deploy 的 transaction option 與執行期拒絕、取鎖 ssh 的 ServerAlive、CLI 接線、lint | §4.6 lint（含第 5 點的執行期拒絕）、§4.7 測試（含掉鎖後 outcome 是 `failed`）；`go test` 涵蓋 `cmd/pilot/cmd`、`internal/spec`、`internal/accessgrants`、`internal/decommission`、`internal/sshdial` | **required**：真實 sshd 的 flock、真實 inventory 形態（L1–L11）；U1 已於 2026-11-06 確認（維護者陳述正式 inventory 不使用被拒絕的形態） | —（U1 已確認） |
| P2-3 | 入口 playbook、`auth_inspect`、identity 的觀察與 ack register、AGENTS.md §4.0 的一列、Go 的結果解析器；**擷取 K16–K18**（真實 `ansible-playbook` 輸出，§9） | `playbooks/apply/freeipa-identity-auth-cache.yml`、`files/freeipa-ssh-key-cache.py`、`freeipa-identity-apply.yml`（兩處）、`internal/identityreconcile/authcache.go`、`internal/identityreconcile/testdata/`（K16–K18 的 fixture） | §5 的測試；解析器可先於 playbook 完成 | **required**，程序如下（AGENTS.md §1.4）。(1) identity playbook 的新觀察 task：`pilot vm-target test --playbook playbooks/apply/freeipa-identity-apply.yml --spec docs/verification/freeipa-identity.md`，L3 的 `--check --diff` 照跑（觀察 task 在 check mode 被跳過）。(2) 入口：它依 §5.2 拒絕 check mode，L3 會在它自己的 gate 失敗，所以用 `pilot vm-target test --playbook playbooks/apply/freeipa-identity-auth-cache.yml --spec docs/verification/freeipa-identity.md --skip-checkmode`，在已套用 identity roster 的全新 VM 上；`--skip-checkmode` 的理由、以及「`--spec` 用 identity 的 spec 是因為入口不是 component、沒有自己的 spec（§5.1），L5 驗證的是入口沒有弄壞 identity 狀態、L6 要求入口 `changed=0`」寫進 evidence 的「未涵蓋」段。(3) 入口的拒絕路徑（check mode、`--tags`、多台主機、錯的 action、domain 不符）與 K16、K17 的擷取用 `pilot vm-target run`，不是 test 鏈：它們不是一條會成功的鏈，這是對 AGENTS.md §1.4「首選鏈」的有文件的偏離。journal 不存在／true／false 各一次，AGENTS.md §1.4 | P2-2（`Held` 型別出現在簽章；解析器可先做） |
| P2-4 | **擷取 K6–K15、K19、K21**（RPC，§9）與 fixture 測試 | `internal/freeiparpc/testdata`、find／write 的 fixture 測試 | 每個擷取有斷言與竄改探測；`passwd` 的 fixture 不含密碼，由掃描 fixture 目錄的測試鎖住 | **required**：在拋棄式 VM 上擷取 | P2-2（U6） |
| P2-5 | executor（沒有入口） | `freeiparpc` 的 WriteGate（用 `Held.Active()`）、`identityreconcile/execute.go`（journal sink 與 Read₃ 用脫離取消的 ctx、§7.3 的前置條件重讀與破壞性差異規則、§7.10 的逐 stage 自鎖檢查）、journal sink 介面、`inventory` 的值形態匯出函式、新的 blocked 原因（`password_value_unsupported`、`protected_object`）、`LiveUser`／`LiveGroup` 的 `ipauniqueid`；Q8 決定之後才寫送出 `""` 的程式碼 | §7 的單元矩陣；WriteGate 零請求測試 | **required（重跑 P1 的 driver）**：這個 PR 改了 `user_find` 的解析（`LiveUser` 增加 `ipauniqueid`）與 `freeiparpc.New`（`!ReadOnly && WriteGate == nil` 拒絕），所以在全新 VM 上對不可變 candidate 重跑 `TestLiveGoPreviewDriver`，確認預覽仍是 0 寫入；executor 本身沒有進入點，它的 live 證明由 P2-6 提供 | P2-1（已實作）、P2-4；Q8 |
| P2-6 | users-groups scope 的套用；**K20**（client allow／deny 的判準，§9） | `reconcile.go`、`reconcile_golang.go`、`delivery.ErrPartiallyApplied`、`Transaction.runStep` 的證據寫入改用脫離取消的 ctx（影響所有 deploy 元件，§4.4）、outcome 讀取者強化、`--result-out` 與 #274、gate ledger、`identity_live_hooks` 的暫停點（D31，CI 編譯帶 tag 的版本）、`publishTerminalWorkflow` 與其他終端 sink 的脫離取消 ctx 及 `TestTerminalSinksSurviveCancel`／`TestTerminalSinksAreRegistered`（§4.4）、`golangPreviewStage` 與 `stageDecisionFromFlag` 的單一來源或一致性測試（§5.7） | 結束碼矩陣、history 與 webhook 測試、秘密；`runStep` 與 `publishTerminalWorkflow` 在取消的 ctx 下仍寫入（所有元件）；driver A1–A15、A17(i)(ii)、A18–A22（A8(ii)、A10、A17(i)(ii)、A18–A21 需要 D31 的暫停點；A14、A15、A22 是 plan 階段或一般執行，不需要）；**混合的 arm（A16、A17(iii)(iv)）不在這個 PR**：混合在 P2-7 之前不啟用 | **required** | P2-2、P2-3、P2-5 |
| P2-7 | 混合 | identity playbook 的 guard、`deploy.go` 的 identity hook、`--scope full`、混合路徑的訊號處理、`deploymentMetadata` 辨認 JSON 物件形式的 extra var（只記 key，§8.3） | §8.4 靜態與 runtime；混合路徑的 exit-code 保護、結果檔生命週期與訊號處理（§5.4、§6.3、§8.3）；driver H1–H5（在 acked 基準上，§10.2）與混合的 arm A16（plan 階段，不需要暫停點）、A17(iii)(iv)（需要 D31 的 `after_send` 暫停點，由 P2-6 的 tag 檔案提供） | **required** | P2-6 |
| P2-8 | 效能、evidence 與計畫退出條件更新 | `docs/evidence/freeipa-go-reconcile/*`、計畫 | 最終 candidate 上的 §10.2 的 P | **required**：量測 | P2-7 |

順序規則：取鎖閘門（P2-2）先於 P2-4、P2-6、P2-7；在 P2-7 之前不啟用混合。P2-1 已在分支實作，可與 P2-2 並行。P2-5 開始寫會送出 `""` 的程式碼之前，Q8 要先決定（K21 在 P2-4 擷取）。

**每個 `required` 的 PR 各有一份 evidence record**（AGENTS.md §1.2）：`docs/evidence/freeipa-go-reconcile/pr-<PR 編號>.md`（先例：`pr-255.md`），一個變更一份、每個 candidate 就地覆寫，機器部分由 `pilot vm-target test --evidence-record` 產生，live driver 的 arm 由 driver 的摘要補上；原始輸出只放在 AGENTS.md §1.2 規定的 gitignored 位置，不進 Git。每份在提交前跑 redaction／secret 掃描（密碼、cookie、vault 內容、journal 內容的哨兵值為 0 筆），掃描結果寫進該份 record；`LATEST.md` 由 P2-8 在最終 candidate 上改寫。

## 12 待使用者確認

**下面六項是設計審查的預設值與它的後果，不是已確認的決定，除非該項寫明已確認（目前只有 U1）。** 每項都需要使用者回答；沒有回答前，實作只能依預設值寫程式碼、不得把它當成已同意。

- **U1　不支援的 SSH 形態讓 legacy 漏斗拒絕執行**
  **已確認（2026-11-06）**：維護者確認正式 inventory 不使用 ProxyCommand、密碼 SSH，也不使用 docker／local connection，所以下面的預設（拒絕）成立，P2-2 不再因它被擋住。這是維護者的陳述：這份規格沒有執行 `ansible-inventory` 讀過正式 inventory（X1 的檢查方式仍是下面括號內的那一個，之後接入正式環境時照做）。
  預設：拒絕。`pilot deploy`、`pilot reconcile`、`pilot access`、breakglass 與 `pilot host decommission` 的 identity 路徑，遇到 freeipa-server 主機使用 ProxyCommand、密碼 SSH、docker／local connection，或不在 allowlist（`ConnectTimeout`、`ProxyJump`、`ServerAliveCountMax`、`ServerAliveInterval`、`StrictHostKeyChecking`、`UserKnownHostsFile`）的 `-o` 選項時，改為錯誤並指出那個 hostvar。
  後果：現在能跑的這類 inventory 在 P2-2 之後會失敗。另一個行為變更（R10）：取鎖 ssh 帶 `ServerAliveInterval=15`、`ServerAliveCountMax=3`，網路中斷約 45 秒就被視為掉鎖，legacy 漏斗因此取消 ansible-playbook；今天同樣的中斷不會殺掉一輪長時間的 run。**（已確認前：P2-2 在操作者檢查過正式 inventory 之前不能合併；現已確認，見上）**（檢查方式：以 AGENTS.md §0.1 的方法讀真實 inventory 的事實，即 `ansible-inventory -i <inventory> --graph`／`--list`，看 freeipa-server 主機的連線 hostvar；X1。這份規格沒有執行它）。不同意時的替代：提供有稽核紀錄的略過旗標，但會重新引入交錯的危害（U2 同一個理由）。

- **U2　長時間執行期間的 breakglass**
  預設（待使用者確認）：CLI 最多等 30 分鐘，TUI 立即失敗；不提供略過。
  後果：一輪完整 identity（legacy 約 26–27 分鐘）進行中，事故中的 breakglass activate 會等到那一輪結束，或在 TUI 被立即拒絕並指向 `pilot access breakglass activate`。同一組數值的取捨（R10）：ServerAlive 15 秒×3 次讓「反方向掉鎖」約 45 秒內被偵測到，代價是短暫的網路中斷就會殺掉長時間的 legacy run；調大（例如 15 秒×12 次）容忍較久的中斷，但 server 先放鎖、client 還沒發現的視窗（R8）也隨之變長。替代：略過會重新引入清除交錯；安全的替代是計畫的選項 (iv)（`auth_pending` 加世代，改 #138 的 helper 與 journal 格式，重跑 #138 的 live 矩陣）。

- **U3　自鎖保護**
  預設（待使用者確認）：啟用 `protected_object`（§7.10）。
  後果：roster 若刪除或停用登入 principal、重設它自己的密碼、讓它對 `admins` 的遞移成員資格在 plan 的**任何一個 stage 邊界**消失（直接移出而仍經巢狀群組屬於 `admins` 不算；「同一個 plan 才建立通往 `admins` 的新路徑」算，因為 S5 的撤銷先於 S6 的新增，S5 之後 S6 之前它暫時不可達，S6 會以 `ACIError` 失敗，這種變更要拆成兩次 roster 編輯）、刪除 `admins`／`ipausers`／`editors`／`trust admins`，Go engine 回報 `blocked`（結束碼 3）而不套用；這比 playbook 嚴格（Ansible engine 照樣會套用這種 roster）。不啟用的後果：roster 可以在 run 中途移除 engine 自己的讀取權限，之後的驗證讀取失敗，而寫入已套用。

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
| Q1 | `ValidateRoster`（與 `pilot roster lint`）要不要也拒絕同一批型別錯誤與明確的 `null`，讓兩個 engine 在同一個早的點拒絕？Phase 2 只讓 Go adapter 拒絕（P2-1，涵蓋 #273 的範圍）；`ValidateRoster` 本身不變，因為它是 Ansible engine 的入口（改它會改變 Ansible engine 對這些輸入的行為）。P2-1 已在分支實作 | 產品決定，另案。「先擷取 playbook 對這些輸入的真實反應」這一半已由 P2-1 完成（ansible-core 2.19.2 對同一批運算式的重播，記在 P1 spec §5.1），不再阻擋這個決定 |
| Q2 | batch 上限 25 是否合適 | P2-8 的量測；語意不變，只調常數 |
| Q3 | 使用者決定 U2–U6（U1 已於 2026-11-06 確認） | 使用者 |
| Q4 | `partial_failed` 的 webhook 沒有 `confirmed_effects`，訂閱者看不到已提交的 users／groups 變更（R7） | 需要時另案修改 webhook 規格；不在 Phase 2 |
| Q5 | 正式環境的 SSH RTT 與 FreeIPA 版本（X2）；SIGKILL 後的 legacy 子行程（X5）；#261 的孫行程拖延（R2）；#277 的三份實作（R4） | 各自的量測或另案，不在本階段修 |
| Q6 | `store.LastSuccess`（`pilot runs last-success`，`cmd/pilot/cmd/runs.go:141-150`）要不要依 scope 過濾：零寫入、`pending=false` 的 `users-groups` 成功 run 目前會被它當成該主機最近一次成功交付（R11）。建議預設：排除 `scope=users-groups` 的 run，另提供旗標納入 | 使用者；P2-6 前決定（run 的 metadata 已記 scope，§8.2） |
| Q7 | D31 的 build tag 暫停點（`after_entry`、`before_stage`、`before_batch`、`after_send`）是否可接受？替代：driver 以 PATH 前置的 ansible-playbook 包裝腳本只做 `after_entry` 一種注入。**這個替代會失去 `after_send`，所以 A8(ii)、A10、A17(i)(ii)(iii) 的「真正進行中的寫入」以及 A19 的 stage 之間的外部寫入都退回單元層級**（只剩 A18 與 A19(e) 的 `after_entry` 可 live） | 使用者或 Root；P2-6 前決定 |
| Q8 | **`""`（空字串）的處理**：`pilot edit` 對空白的文字欄位寫 `""`（`first`、`last`、`login_shell`、`home_directory`、`display_name`、`email`、群組 `description`），兩個 engine 都把它當值接受並送出（§7.9）。必填的鍵（`first`、`last`、`login_shell`、`home_directory`、群組 `description`）送 `""` 會怎樣、`display_name`／`email` 的 `""` 是「清除」還是錯誤，都要看 FreeIPA 的真實回答。**P2-5 開始寫會送出這些值的程式碼之前必須決定**：選項 (a) adapter 對必填鍵的 `""` 拒絕（比照 `null`，讓操作者省略該鍵或給值），`display_name`／`email` 的 `""` 依擷取結果當成「清除」或拒絕；(b) 照 playbook 送出（兩個 engine 同行為，風險是 FreeIPA 的錯誤在 stage 中途才出現）。**暫定傾向 (a)**，但不是決定 | K21 的擷取（P2-4）之後，使用者；在 P2-5 開始前 |

## 14 與設計審查和計畫的差異、補充

**對計畫字面的偏離**（刻意）：

1. **入口結果用 controller 端 JSON 結果檔**，不用計畫擬議的 stdout `AUTH_CACHE[<host>]: …` 標記（§5.4，原因同該節）。
2. **混合 skip 變數名**用 `pilot_identity_users_groups_engine`，不是擬議的 `identity_users_groups_engine`（§8.4）。
3. **入口位置**在 Plan₁ 之後、Read₂ 之前，不是在「寫入前重讀與重新規劃之後」；計畫列出的一個測試案例（第一次 plan 沒有寫入、重讀後才產生寫入）因此改成等價的案例（§7.2）。
4. 計畫說「helper 的每個動作都寫 journal，沒有唯讀動作」，已不符 main：自 `4e774a95` 起有唯讀路徑（計畫在這個 PR 更正）；探測因此只需四行（§5.3）。
5. 計畫列出三個讀取 outcome 的地方，漏了 `aggregateWorkflowResult` 的 `default` 會把未列出的 outcome 發布成 `success`（§6.1、§6.4）。
6. 計畫 §(ii) 引用的密碼判斷 task 行號已過期（計畫在這個 PR 更正）。
7. **寫入前的前置條件放寬了一部分**：計畫 §4 步驟 5 與 (ii) 要求「每批寫入前檢查所需 live preconditions」。規格只對 S4（`passwd`）、S5（成員撤銷）、S7 的 `user_disable`、S8（刪除）在送出前做批次重讀，並對 Plan₂ 多出的破壞性操作停止（§7.3）；S1–S3、S6、`user_enable` 靠伺服器的逐項回應（`DuplicateEntry`、`NotFound` 為 `conflict-failed`）判斷，不另做批次重讀。理由在 §7.3：這些操作冪等、失敗時沒有效果、Read₂ 才剛完成。

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
| E11 | `Held` 拆成 `Active`／`Attach`／`Bind`：掉鎖只取消 ansible-playbook 的指令 ctx；`RunResult`、證據、Go 的 RPC 與驗證讀取的 ctx 不取消，進行中的 batch 回真實答案；WriteGate 用 `Active()`（`Release` 之後也擋） | §4.1、§4.4 |
| E12 | 類別規則（§4.4）：記錄 run 結果的每個寫入（T1–T7：journal、step 證據、終端寫入、`--result-out`、外送 projection、outbox 寫入、webhook 送出）在取消之後用 `WithoutCancel` 加有界期限；P2-5 負責 T1，P2-6 負責 T2、T4–T7；改 `runStep` 與 `publishTerminalWorkflow` 影響所有 deploy／access／gateway-scope 的元件（取消後不再 `evidence_failed`、publish 在期限內完成；`publishTerminalWorkflow` 只在進入時 `ctx.Err() != nil` 才脫離取消，正常路徑不變）；單一表格驅動測試與登記表測試 | §4.4、§11 |
| E13 | 前置條件：S4、S5、S8 的批次重讀與謂詞；破壞性集合（含 `user.disable`，比 plan 的 `destructive` 旗標多）與「Plan₂ 比 Plan₁ 多出破壞性操作就停止」；`LiveUser`／`LiveGroup` 增加 `ipauniqueid` | §7.3 |
| E14 | live 驗證改從 acked 基準開始、暖 client 快取，並加對照（A6、H4 的 client 仍 allow）；H1／H3 才讓 client deny；A6 不再宣稱 client deny | §10.2 |
| E15 | 新 gate 與新路徑的觸發證明：A14–A19、L8；決定性注入點 D31（build tag，Q7）；後續輪次再增加 A20、A21、L9（E27–E31） | §10.2 |
| E16 | `protected_object` 依 plan 執行後的遞移成員資格判斷，並擋登入 principal 自己的密碼重設 | §7.10 |
| E17 | 混合 run 的結果檔生命週期（每次 ansible-playbook 前重建為空檔、Verify 先於冪等性）；identity playbook 的 `observe` 輸出列入 K18 | §5.4、§9 |
| E18 | `executeDeploymentTransaction` 對 identity playbook 沒有 `IdentityLock` 時執行期拒絕（涵蓋 `executeDeployment` 與直接建構 options 的呼叫者） | §4.6 |
| E19 | Plan₃ 驗證失敗而 Go 已有 `success`／`unknown` 操作 ⇒ `partial_failed`，`FailedStep` 在 `users-groups` 是 `verify`、在混合 run 是 `apply`；Plan₂ `blocked`（入口已執行）⇒ 結束碼 3、`failed`；混合路徑也套 exit-code 保護 | §6.1、§6.2、§6.3 |
| E20 | 風險 R9（取鎖等待時 Ctrl-C 的遠端等待者；不加 `timeout` 包裝，L9 證明持有中的鎖不被殺）、R10（ServerAlive 45 秒掉鎖，記入 U1、U2）、R11（`users-groups` 寫入 run 的 webhook 一律 `failure`，文件寫明給訂閱者）；Q6（`LastSuccess` 依 scope 過濾） | §1.3、§6.2、§12、§13 |
| E21 | #273 的範圍與分支上已實作的 adapter 一致（P2-1，§7.9）：Go 有自己預設值的鍵、頂層清單、`freeipa.admin.principal`、nested 鍵的明確 `null` 與錯型別、`absent` 項目的形狀，都在任何讀取或寫入之前拒絕；Go 不管理的 `uid`／`gid`／`display_name`／`email`／群組 `gid` 的 `null` 接受為「不管理」（`pilot edit` 與出貨的範例 roster 都寫它們）；`password.initial` 分三層處理（非字串＝adapter、`~`＝沒有密碼、範本與 `!vault`＝blocked）；`""` 是值，Q8 是 P2-5 之前的決定點，K21 是它的擷取；Q1 縮小為「要不要搬進 `ValidateRoster`」 | §7.8、§7.9、§9、§13 |
| E22 | 自鎖保護在 plan 的每個 stage 邊界檢查（principal 存在、enabled、對 `admins` 遞移可達），不只最終狀態；選擇擋下，而不是把會影響 principal 的新增排到撤銷之前（理由在 §7.10）；A14(f) 與「路徑已存在」的對照 | §7.10、§10.2 |
| E23 | **每個**斷言探測或 journal 狀態的 arm 都從 acked 基準開始並先斷言 `pending=false`；A18 在 `after_entry` 斷言 `pending=true` 且寫入計數為 0；說明全新拓樸上該斷言空洞（缺 journal 就是 true） | §10.2 |
| E24 | 擷取的負責 PR：K6–K15、K19、K21 屬 P2-4（RPC），K16–K18 屬 P2-3（真實 ansible-playbook 輸出），K20 屬 P2-6（client allow／deny 的判準與 X6 的量測）；§9 標題只對 RPC 擷取寫 `freeiparpc`；`""` 的處理是 P2-5 之前的決定點 Q8 | §9、§13 |
| E25 | S7 的 `user_disable` 與其他收窄的操作一樣先批次重讀；S8 任何一位使用者的謂詞不成立就整個停止（同批的其他使用者也不刪）；刪掉恆真的「roster 仍是 absent」謂詞；新的 `not_executed` 結果類別 | §7.3、§7.4 |
| E26 | Read₃／Plan₃ 在 Apply 步驟內執行，判定由 Verify 步驟消費；Apply 失敗時 `FailedStep` 是 `apply`，Read₃ 的結果仍寫進事件與結果檔；混合 run 在 Go 階段失敗、Read₃ 失敗或 Plan₃ 不空（D20 的定義）時不執行 playbook（Apply 在 playbook 之前失敗），`users-groups` 的 Read₃ 失敗讓 Verify 失敗 | §7.6 |
| E27 | **更正上一輪的 R9 處理**：遠端指令不包 `timeout`（會連持有中的鎖一起殺掉，`flock --wait N` 本來就在 `N` 秒結束）；新增 L9 證明持有中的鎖不被計時器殺掉 | §1.3、§4.3、§10.2 |
| E28 | D31 增加 `after_send:<S>:<n>`（請求已送出、答案未讀），A8(ii)、A10、A17 用它製造真正進行中的寫入；CI 編譯帶 tag 的版本 | §10.2 |
| E29 | 混合路徑的訊號處理：`--engine golang --scope full` 的整個 run 套用與 P1 預覽相同的 `signal.NotifyContext`，Go 階段與 playbook 階段各自的行為與 outcome | §8.3 |
| E30 | P2-3 的 target 程序（`--skip-checkmode` 與理由、`--spec` 用 identity 的 spec、拒絕路徑用 `vm-target run`，對 AGENTS.md §1.4 的有文件的偏離）；P2-5 重跑 `TestLiveGoPreviewDriver`；P2-1 的 target_validation 理由更正；每個 required PR 一份 evidence record 與 redaction 掃描 | §11 |
| E31 | 傳給 Ansible 的路徑一律用 JSON 物件形式的 `-e`；`passwd` fixture 不含密碼；新增 A20（session 在 run 中途失效）與 A21（權限在 run 中途被收回、非 admin 啟動）；§4.6 的「四部分」更正為五部分 | §5.4、§8.3、§9、§10.2、§4.6 |
| E32 | 同一類錯誤第二次出現（取消的 run ctx 傳進記錄結果的寫入）後改成**類別規則**：T1–T7 的 sink 清單與負責 PR（§4.4）；`publishTerminalWorkflow` 的 outbox 與 projection 也在 ctx 已取消時脫離取消（取消時 `partial_failed` 的 run 仍留下 `failure` 事件）；一個表格驅動測試加一個登記表測試；A10、A17 的 live 斷言 outbox | §4.4、§8.2、§8.3、§10.2 |
| E33 | S7 的 `user_disable` 謂詞分本輪新建的使用者（只要讀回存在、不是登入 principal，沒有 Plan₂ 可比）與既有的使用者（`ipauniqueid` 相同）；已經停用是 `noop`，`nsaccountlock` 不是謂詞；新增 A22 與「新建且停用」的單元 row | §7.3、§10.2 |
| E34 | acked 基準的條款點名接續的 arm 與各自的起點斷言（A3 接 A2、A4 接 A3、H2 接 H1、H3 接 A6、A18 的 (i)(ii)、H4 的第二次 run）；每次 rollback 之後斷言時鐘（`Rollback` 已呼叫 `restoreGuestClock`）、`ssh -O exit`、清 fact cache | §10.2 |
| E35 | 混合 run 在 Go 階段失敗、Read₃ 失敗或 Plan₃ 不空（D20 的定義，無關物件的 drift 不算）時，Apply 在 playbook 之前失敗、不執行舊 playbook（`FailedStep: apply`）；`users-groups` 的 Read₃ 失敗讓 Verify 失敗 | §7.6、§6.1 |
| E36 | 其餘小項：§7.9 補上 `users`／`groups` 不是 list、元素不是 mapping、`name` 不是字串的拒絕；A17(iii) 用 `after_send`；Q7 說明退回 `after_entry` 的代價；L9 的持有者是 pilot 自己的 `AcquireLock`；`deploymentMetadata` 辨認 JSON 物件形式的 `-e` 只記 key；`golangPreviewStage` 與 `stageDecisionFromFlag` 的單一來源或一致性測試；P2-6 列的需要暫停點的 arm 更正 | §7.9、§10.2、§13、§8.3、§5.7、§11 |
| E37 | 最後的措辭修正：`publishTerminalWorkflow` 只在 `ctx.Err() != nil` 時脫離取消並套用期限，正常路徑保留今天的 30 秒 flush 預算與無期限的 projection；混合的 playbook 閘門用 D20 的「嘗試過的物件上仍有操作」，無關物件的 drift 不擋；A16 與 A17(iii)(iv) 移到 P2-7；`FailedStep` 在 `users-groups` 是 `verify`、混合是 `apply`；`internal/tools` 的 verify evidence 加入登記表掃描（T8，有理由的豁免） | §4.4、§7.6、§11 |
| E38 | P2-2（取鎖閘門）實作時與本規格字面不同或補上的地方（理由在各項）：(1) `executeDeploymentTransaction` 的 apply closure 在 `PrepareApply` 之前還有第二個確認（`runOnce(false, dryRunFirst)` 內的「確定要執行正式套用指令嗎？」），所以 `runOnce` 拆成 `announce`（印指令與確認）與 `execute`，鎖取在最後一個確認之後、`PrepareApply` 之前，`PrepareApply`（目前沒有非測試的設定者）因此移到 announce 之後；(2) §4.6 第 3 點的 contract 守衛另外要求 `freeipa-identity` 不宣告 rollback／upgrade／decommission playbook（那些是別的檔名，`executeDeploymentTransaction` 的檔名判斷看不到）；(3) lint 另有一部分：非測試程式碼中每個 `accessgrants.{Reconcile,Activate,Deactivate}Options` 與 `providers.FreeIPAClientProviderConfig` 的 literal 都要設定它的鎖欄位（E41：decommission 的 config 之後沒有鎖欄位，不在此列），`identitylocktest`（測試用的假鎖）只准測試 import，`newIdentityLock`／`newIdentityLockDialer`（測試接縫）非測試程式碼不得賦值；(4) ServerAlive 實作在 `sshdial.AcquireLock` 內（`Target.lockTarget`），不是在 cmd 組 Target 時，所以每個取鎖者都有，tunnel 的 ssh 沒有；(5) 三個漏斗的 hostvars 都用 `loadDeployInventorySnapshot`（含它的 `validateInventorySecretStorage` 檢查），所以 `pilot access`、breakglass、drift repair、`pilot host decommission` 對 group_vars 有明文 secret 的 workspace 現在會在取鎖時拒絕（行為變更）；(6) `pilot access drift --repair-managed` 也是漏斗（經 `RepairManaged` → `ReconcileOnce` → `applyPlan`），§4.2 的表與 §10.2 的 L1–L6 沒有點名它，`RepairManaged` 在探測之前就拒絕 nil 的鎖；(7) `--lock-wait` 只接受 0 或至少 1s 的 Go duration（遠端 `flock --wait` 是整數秒），未設為 30 分鐘，與 `--preview-only` 同用即拒絕；(8) 取鎖等待的進度行走 stderr：`pilot reconcile` 經 context 帶 `cmd.ErrOrStderr()`，其他路徑預設 `os.Stderr` | §4.2、§4.3、§4.5、§4.6 |
| E39 | P2-2 review 之後的修正（一輪，只動 P2-2 的範圍）：(1) 取鎖前檢查：每個漏斗在任何 ansible-playbook、ssh 與步驟之前，用取鎖用的同一個推導（`identityLockTarget`）拒絕不支援的 inventory，取鎖時的檢查保留當縱深防禦；deploy 與 reconcile 的 `--preview-only` 與 `--force` 一致；decommission apply／resume 在記錄 approval 與第一個步驟之前拒絕，`decommission plan` 選擇印警告而不是 blocker（理由在 §4.2）；lint 第 6 部分；(2) access、breakglass、drift 修復與 decommission 讀 hostvars 的行為變更（明文 secret、整份 vault 加密的 group_vars 在取鎖前拒絕）補進 §4.2、runbook §4.3 與各指令的 `--help`；(3) `-e @file`、ansible.cfg 的 `ssh_args`、`ANSIBLE_SSH_ARGS`、`host_key_checking` 的已知缺口（R12）；`ansible_connection: ansible.builtin.ssh` 接受為 ssh（同一個外掛；其他外掛維持拒絕，測試各有 row）；(4) `--ask-vault-pass`／`--ask-become-pass` 選擇記錄為已知限制、不拒絕（R13，理由在 §4.3）；(5) 掉鎖只殺 ansible-playbook 主行程，fork worker 可能做完進行中的 task（R2、§4.4）；(6) breakglass 掉鎖在記錄 activation 之前回傳（R14、§4.4）；(7) 等待進度行不再在 ssh 還在連線時說「另一輪持有中」，取鎖 ssh 預設 `ConnectTimeout=30`（TUI `Wait: 0` 路徑原本沒有）。**沒有改**：deploy 取鎖被拒絕或忙碌時 `FailedStep` 是 `apply`（取鎖在 apply 步驟的 closure 裡，拆成獨立步驟要動 delivery 的步驟模型，不是一行的修正）。這一輪同樣**沒有 live arm 的實跑**；live arm 要加：decommission 對被拒絕的 inventory 的 apply 與 resume（client 沒有被解除安裝、approval 沒有留下）、deploy／reconcile 的 `--preview-only` 對被拒絕的 inventory（與 `--force` 同樣的拒絕）、drift 修復對被拒絕的 inventory（沒有探測就拒絕） | §1.3、§4.2、§4.3、§4.4、§4.6 |
| E40 | P2-2 第二輪 review 之後的修正（只動 P2-2 的範圍）：(1) **breakglass 的自動化步驟失敗被回報成功**（§4.3；`editRouterModel.failedAction`／`takeStepFailure`、plan 的 `planSkipped`、lint `TestRegression_FailureBannersAreRecordedForTheDriver`，測試涵蓋終端機 router、`--actions`、apply、MCP apply，失敗原因為預檢查拒絕、鎖忙碌、掉鎖、playbook 失敗，以及成功的對照組）；原有的 `TestEditAutomationDriverRosterGrantsFlow_ActivateDeactivateBreakglass` 與 `TestTUIBreakglassIsRefusedBeforeAnythingRuns` 以「banner 是 ❌ 而 driver 錯誤是 nil」為期望，把這個洞寫成了契約，期望改為 banner 與步驟錯誤同時成立；(2) 預檢查拒絕時 outbound 事件逐漏斗寫實（§4.2；互動式單一元件 `pilot deploy` 會發一個 `failure`／`apply_failed` 事件，其餘不發），原來的「與其他執行前的驗證錯誤一樣不發事件」不成立；(3) 「在做任何事之前」改成「在任何 ansible-playbook、ssh、approval 紀錄與漏斗自己的步驟之前」（D3、§4.2、runbook §4.3、`--help`），並寫明哪些只整理 workspace 的事在它之前；deploy 與 reconcile 的 `Long` 與其餘指令各自抄了一份段落，改成單一來源（`identityLockHelp`、`identityLockDeployHelp`，`TestLockHelpIsASingleSource` 鎖住引用、並擋下別處的複本）；(4) `executeCatalogBatch` 的 `precheckIdentityBatch` 對**每個** request 檢查：第一個 request 不是 identity playbook 時不可停下（新增兩個 request 的案例，變異「遇到第一個非 identity 的 request 就 return」現在被抓到）；(5) availability 的 optional 主機探測與取鎖的 target 推導共用 `sshdial.IsSSHConnection`：`ansible.builtin.ssh` 的 optional 主機原本被當成「v1 沒有 prober 的連線」而失敗（偏保守的方向，現在與 `ssh` 相同），`TestClassifyConnectionSupport_AgreesWithTheSSHTargetDerivation` 兩邊逐值核對。**同一個改動也影響 required 的主機**（P2-2 後續 review 補記）：`ansible.builtin.ssh` 的 required 主機原本被當成「不是 ssh、由 Ansible 自己處理」而不探測，現在與 `ssh` 一樣是 Probable，所以它連不上時是 Blocking（在鎖的 ssh 失敗之前就擋下），不再被放行；其他連線外掛的 required 主機維持不探測、不擋；`TestClassifyConnectionSupport_RequiredHostAgreesWithTheSSHTargetDerivation` 對 {`ssh`、`ansible.builtin.ssh`、未設} × {未設、`required`} 鎖住 Probable、不 Fatal、與 `TargetFromHostVars` 一致，並對 `delivery.ResolveExecutionScope` 斷言不可連線的 required ssh 主機是 Blocking（不是 Deferred）。**同類掃描（`--actions` 步驟的畫面動作是否把失敗只放在 banner）**：會對 workspace 檔案以外的東西動作的只有 breakglass 兩個畫面（`accessgrants.Activate`／`Deactivate`，已修）；`deploy`／`reconcile` 步驟走 `runAutomatedDeploymentStep`，回傳執行的錯誤；`save_hosts` 失敗進 `r.err`；名冊寫入被拒絕走 `writeRefused`（PR #148）；`accessgrants.EvaluateIdentityHygiene`、Status、Explain 是唯讀，失敗進 `r.err`。**沒有改**：monitoring、SNMP catalog 與 credentials、DNS 與 internal-endpoint manifest 的畫面對「驗證沒過，尚未寫入」與「存檔失敗」也只設 `⚠️` banner（約四十處），它們只寫 workspace 自己的檔案，apply 的 diff 與 `affected_files` 看得出沒有寫入，而且 DNS 的測試把「閘門擋下的步驟導覽後不報錯」寫成契約（`TestEditAutomationDriverDNSFlow_SwitchRecordValueSourceAndZoneState`）；要不要改成步驟失敗是另一個決定（會改變既有 manifest 步驟的契約），不在這一輪。本輪的 live 實跑：沒有（沒有動 VM）；N1 在本機以 `pilot edit --actions` 加 ProxyCommand 的 inventory 重現（結束碼 0、沒有輸出、沒有紀錄），修正後同一個 scenario 結束碼非 0 並指名原因 | §4.2、§4.3、R15、§10.2 L10 |
| E41 | P2-2 第三輪 review 之後的修正（只動 P2-2 的範圍）：**decommission 的鎖取得太晚，違反 D1**。(1) **live 發現**（一台拋棄式 FreeIPA server 加一台已 enroll 的 client，candidate `1751a83e`）：`pilot host decommission apply` 先執行 `freeipa_client_uninstall` 與 roster tombstone，最後的 `freeipa_identity_apply_converge` 步驟才取鎖（`freeipaIdentityConvergeStep.Execute` 內，預設等 30 分鐘）。另一輪持有鎖時，apply 已把 client 解除 enrollment，才在 converge 等鎖，操作者中斷（SIGTERM）之後 client 已解除 enrollment、FreeIPA 的 host 紀錄還在。D1 要求鎖取在「確認之後、第一個會改動的執行之前」，decommission 第一個會改動的執行是 uninstall，不是 converge；第二輪 review 只把「inventory 不可鎖」的預檢查移到前面（E39），取鎖本身沒有動。同一個位置問題也出現在鎖忙碌（`Wait: 0`）、等待逾時、等待中 Ctrl-C。(2) 修正（root cause）：`runHostDecommissionApply`（apply、resume 與 TUI 同一個函式）對「尚未完成且有 converge 步驟」的 plan，approval 之後、`decommission.Apply` 之前取鎖，持有到 `Apply` 結束，`Apply` 的 ctx 以 `held.Bind` 衍生，`Apply` 之後 `held.Check()`，最後 `Release`；預檢查與 `Acquirer` 的建立由 `identityLockFor` 一次完成，仍在 approval 之前。converge 步驟從 ctx 讀鎖（新的 `identitylock.Require`：沒有鎖 `ErrNoLock`、鎖已掉或已放也拒絕），不再取鎖也不放鎖，所以一輪只有一個鎖 session；`FreeIPAClientProviderConfig.IdentityLock` 移除，provider 的註冊表不再建鎖（`plan` 也建註冊表，從不鎖）。取鎖失敗發生在任何步驟之前：client、roster、server 都沒有改，approval 保留，`resume` 或再跑一次 `apply` 都能用同一份 plan 繼續（測試兩條路徑都走）。（等待中的 Ctrl-C／SIGTERM 不屬於「context 被取消」：`apply`／`resume` 沒有安裝訊號處理，行程直接結束，**沒有訊息**，狀態卻同樣沒有改變；`was not started` 的訊息只在鎖忙碌、逾時、被拒絕與 context 被取消時出現）(3) **事實（教正）**：那次 live 之後 `resume` 報 `stale_resume: plan_stale`、重新 plan 被 `cleanup_failed_terminal` 擋下，**原因是 workspace 沒有設選用的 `ipa_client_fqdn`**（converge 的 SSH 快取退役檢查在 uninstall 之後報 `retirement inventory identity/stage mismatch`），那是既有缺口（issue #303），與鎖的時機無關：Root 在 base `d5c10e7a` 把 `ipa_client_fqdn` 設好之後，uninstall 之後 SIGKILL 的 apply 可用 `resume` 完成，也就是 workspace 有效時，舊的「等鎖時被中斷」本來就能 resume。**所以這個修正改的是鎖何時取（D1），不是讓半套 decommission 變得可 resume**：它沒有碰 freshness 或 planner 的語意，也沒有移除任何 dead end；#303 的 workspace 在修正前後都一樣走不完。(4) 掉鎖（R16）：uninstall 進行中掉鎖，這一輪以 `ErrLockLost` 結束、converge 不啟動；`Apply` 之後 `held.Check()` 失敗時一律回報 `ErrLockLost`（包住原本的錯誤），即使 finalize 已完成（結束碼仍非 0；finalize 已完成而 receipt 已記錄時，訊息說「已完成」而不說「可能部分調和／請重跑」，見 R16）。(5) lint：`lockFunnel` 新增 `Confirm`（確認呼叫存在且沒有任何一個在取鎖之後），converge 步驟的漏斗改為 `identitylock.Require` 先於 playbook，`runHostDecommissionApply` 的取鎖漏斗與預檢查漏斗都以 `needsLock` 為條件，`identityLockBuilders` 與 `lockedOptionTypes` 不再有 decommission 的項目；每個項目都附對真實原始碼的變異。(6) 測試以真實 workspace、planner、freshness、executor 與 FreeIPA client provider 驅動 `runHostDecommissionApply`，只有外界是假的（模擬 client 與 server 狀態的 `ansible-playbook`、記憶體裡的鎖；一個測試用 production 的 acquirer 加真實 flock）。**本輪沒有 live 實跑**（沒有動 VM；L11 要在修正後的 candidate 上重跑） | §4.2、§4.5、§4.6、R16、§10.2 L11 |

## 15 交給後續階段

P1 spec §11 交給 Phase 2 的四件事在這裡的處理：取鎖閘門、#138 入口、`users-groups` scope 的探測與未結清結果（§4–§6）；`blocked` 中哪些要支援——沒有一個（§0、§7.9）；撤銷、刪除與密碼的 checklist row——延後（U5）；batch 邊界與寫入前重讀（§7.2、§7.3）。

仍然留給後續階段的：

- Phase 3：其餘 section 的搬移、client fan-out、host／hostgroup／netgroup／HBAC／sudo；是否需要它由 P2-8 的量測決定（計畫「規模與 go/no-go」）。
- Phase 4：互動入口、`--ask-vault-pass`、預設 engine 切換、舊 engine 的手動回退流程。
- uid／gid 變更的明確確認設計；external 群組的寫入；撤銷、刪除與密碼的 checklist row（U5）。
