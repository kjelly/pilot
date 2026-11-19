# FreeIPA Go reconcile — Phase 3a HBAC 規格

日期：2026-11-19。前一階段：`docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md`（下稱 P2）、Phase 1：`2026-10-30-freeipa-go-reconcile-phase1-spec.md`（下稱 P1）。

狀態：**草案；P3-0（K1–K8 的擷取）已在拋棄式 lab 完成（§1.3），其餘尚未實作、沒有實跑**。本文件是 acceptance contract：它定義完成後外部可觀察到什麼，不是實作的逐行翻譯。文中的指令、旗標、變數是要實作的介面，不是已實跑的步驟。凡是寫成「K-」開頭的項目都是**要擷取的事實**，不可由本文件推測（AGENTS.md §5.6）；已擷取的列在 §1.3，K9、K10 仍未做。

## 0 範圍

Phase 3a 把 **roster 的 HBAC** 從 identity playbook 搬到 Go engine，只在 `--engine golang --scope full` 的混合 run 生效：

- `hbac.services`：HBAC service 物件的建立。
- `hbac.rules[]`：rule 的建立、分類（hostcat／servicecat）、`hosts`／`hostgroups`／`services`／`users`／`groups` 的附加與**逐 rule 限定的移除**、`enabled` 的收斂、`state: absent` 的刪除。
- `hbac.disable_allow_all`：`allow_all` 的 lockdown，含 `hbactest` 前後證明與失敗回滾（維護者 2026-11-19 決定連 lockdown 一起搬）。
- Go 的唯讀 plan 與 `--preview-only` 要把這些列進 plan；idempotency 步驟的「Go plan 不得有操作」要涵蓋 HBAC。

不在 Phase 3a：

- **`pilot access` 編譯出的 grant HBAC rule**（`pilot_compiled_grant_hbac_rules`、`pilot_compiled_grant_hbac_prune`）：它們只經 `-e` 交給 playbook，Go 看不到，仍留在 playbook（§3.3）。
- hosts、hostgroups、netgroups、sudo、NFS、auth／account／password policy：仍由 Ansible 處理（維持 P2 §0；順序見 P2 §15 的 Phase 3 建議）。
- `--scope users-groups` 與預設 engine：不變。`--scope users-groups` 不碰 HBAC。
- 互動 wizard、`--actions`、MCP、預設 engine 的切換（Phase 4）。
- 對正式環境的任何套用：本規格的所有寫入測試只在拋棄式 FreeIPA 測試 VM 上執行。

## 1 假設、未知、風險與 destructive 邊界

### 1.1 假設

- A1：P2 的取鎖閘門、授權快取入口（`prepare`）、journal、Gate 與 batch 機制可以原樣重用；HBAC 階段在**同一把鎖之內**執行，不另取鎖。
- A2：playbook 是 HBAC 語意的 source of truth（P1 D8）。Go 對 desired state 的解讀與 playbook 不一致時，以 playbook 為準，差異寫進 §9。
- A3：`hbacrule-*`、`hbacsvc-*`、`hbactest` 都能經 JSON-RPC 呼叫（K1 確認方法名稱與引數形態）。
- A4：HBAC 的寫入屬於授權快取的 mutation（playbook 的 `ipa_identity_cache_mutation_registers` 含全部 HBAC register），所以 HBAC 寫入同樣產生 P2 §5 的義務，要由 settle 結清。

### 1.2 未知（要擷取，不可猜）

| # | 未知 | 擷取方式 | 被什麼擋住 |
|---|---|---|---|
| K1 | `hbacrule_find`／`hbacrule_show`／`hbacsvc_find` 的 JSON 形態：成員欄位名稱（`memberuser_user`、`memberuser_group`、`memberhost_host`、`memberhost_hostgroup`、`memberservice_hbacsvc`）、`usercategory`／`hostcategory`／`servicecategory`、`ipaenabledflag` 的型別（`["TRUE"]` 或布林）、外部成員欄位是否出現 | lab 上 `--all` 的 JSON-RPC 回應 | 讀取層、plan |
| K2 | 寫入指令的 JSON 形態與錯誤：`hbacrule_add`（含 `hostcategory`／`servicecategory`）、`hbacrule_mod`（空字串清除分類）、`hbacrule_add_host`／`_remove_host`／`_add_user`／`_remove_user`／`_add_service`／`_remove_service` 的 `failed` 結構、`hbacrule_enable`／`_disable`、`hbacrule_del`、`hbacsvc_add`；重複（already exists）、不存在（not found）、已是成員（already a member）、no modifications 的錯誤名稱與 code | lab，逐項擷取（P2-4 的做法） | writer、分類 |
| K3 | 分類與成員互斥：`hostcategory=all` 時附加 host、有成員時設 `hostcategory=all` 的錯誤（playbook 註解引用的 "host category cannot be set to 'all' while there are allowed hosts"） | lab | stage 順序（§5.2） |
| K4 | `hbacrule_add_host` 對短名稱與 FQDN 的處理，以及 `hbacrule_show` 回傳的 host 是否一律是 FQDN | lab | host 比對（§3.2） |
| K5 | `hbactest` 的 JSON 形態（`value`、`matched`、`notmatched`）與 `--user=admin --host=<server> --service=sshd` 的結果欄位 | lab | lockdown（§6） |
| K6 | `hbacrule_disable allow_all` 與 `hbacrule_show allow_all` 的 `ipaenabledflag`；`allow_all` 在新裝 server 的預設內容 | lab | lockdown、plan |
| K7 | rule 名稱大小寫：FreeIPA 對 rule 名稱是否大小寫敏感（user／group／host 是不敏感的） | lab | 名稱比對、碰撞偵測 |
| K8 | 一個 rule 引用了 `state: absent` 的 user 或 group 時，Go 階段與 playbook 的行為（E47 的失敗形狀） | lab | blocked 規則（§4） |
| K9 | 正式規模的 rule 數量與讀取成本（`hbacrule_find` 的 `sizelimit`；P2 的 K3 經驗） | lab + 正式環境唯讀 | 讀取層（X2 仍未解） |

### 1.3 已擷取的事實（P3-0）

在拋棄式 lab（FreeIPA 4.13.4、API 2.257，AlmaLinux 9 單台 server）以 `internal/freeiparpc/capture_p3a_live_test.go` 擷取，97 個 fixture 在 `internal/freeiparpc/testdata/`（`hbac*`、`batch-hbac-*`、`env-domain`），事實與負向對照在 `capture_p3a_facts_test.go`（每個事實都用「換掉一個它讀的 fixture」證明會失敗）。這些結論**推翻或定案**了本文件原本的幾處假設：

| K | 擷取到的事實 | 對設計的影響 |
|---|---|---|
| K1 | `ipaenabledflag` 是一個元素的布林 list（`[true]`）；沒有分類時 `hostcategory`／`servicecategory`／`usercategory` **整個 key 不存在**，有分類是 `["all"]`；成員欄位 `memberuser_user`、`memberuser_group`、`memberhost_host`（小寫 FQDN）、`memberhost_hostgroup`、`memberservice_hbacsvc`；`hbacrule_find` 帶 `all`、無條件即回傳全部，附 `count`、`truncated`；新裝 server 有兩條內建 rule：`allow_all`、`allow_systemd-user` | 讀取層以 key 不存在表示「沒有分類」；`allow_systemd-user` 不能被當成未管理的使用者 rule 報告（§4.3） |
| K2 | 成員指令（add／remove）一律 HTTP 200，結果有 `completed` 與每種成員的 `failed` list：新增成功 `completed 1`；已是成員 `completed 0` 加 `This entry is already a member`；物件不存在 `no such entry`；**移除**不是成員、或物件根本不存在，都是 `This entry is not a member`；一次兩個成員其中一個已存在，只改另一個並列出前者。rule 不存在是 `NotFound 4001`。`hbacrule_add`／`hbacsvc_add` 重複是 `DuplicateEntry 4002`；沒有變更的 `hbacrule_mod` 是 `EmptyModlist 4202`（要視為 converged）。**`hbacrule_enable`／`_disable` 對已經是該狀態的 rule 也回成功**（`result: true`，summary 與真的變更相同），所以 Go 一定要靠讀回判斷有沒有變更，不能靠回應；`hbacrule_del` 的結果是 `{"failed": []}`，value 是名稱 list | 分類沿用 P2 K13 的逐成員分類；「已是成員」與「不是成員」是 converged；enable／disable 只在 live 狀態不符時送；verify 靠重讀 |
| K3 | 分類與成員互斥是 `MutuallyExclusiveError 4303`，兩個方向各有固定訊息（`hosts cannot be added when host category='all'`、`host category cannot be set to 'all' while there are allowed hosts`）；`hbacrule_mod` 帶空字串清除分類（之後 key 消失），再清一次是 `EmptyModlist`；`servicecategory` 同形 | stage 順序（§5.2）成立：先移除成員、再改分類、最後附加 |
| K4 | **短名稱會被 FreeIPA 補上 server 的 domain**，存成小寫 FQDN；大寫 FQDN 與小寫是同一個成員（`already a member`）；`env` 回 `domain`、`realm`、`host` | **Q3 定案**：host 比對用小寫 FQDN，roster 的短名稱以 `env` 的 `domain` 補全。與 playbook 的「去掉網域後比較」不同（§9） |
| K5 | `hbactest` 回 `value`（布林）、`summary`（`Access granted: True／False`）、`matched`（沒有符合時是 null）、`notmatched`、`warning`、`error`；`allow_all` 停用時，沒有 break-glass rule 的 `admin` 是 `False`，有 enabled 的 break-glass 是 `True`，停用它就回 `False`；對不存在的主機與服務不報錯（rule 的分類是 all 時仍符合） | lockdown 以 `value` 判斷（不比對文字） |
| K6 | `allow_all` 停用後 `ipaenabledflag` 是 `[false]`；重複停用、重複啟用都成功 | 回滾與冪等成立 |
| K7 | **rule 名稱不分大小寫**，保留第一次建立的拼法：以小寫再建一次是 `DuplicateEntry`，以任一種大小寫 show 都回原拼法；`hbacrule_find` 的條件也不分大小寫 | **Q4 定案**：比對一律小寫；roster 內兩個只差大小寫的 rule 是 `case_collision`；送指令時保留 roster 的拼法 |
| K8 | **刪除使用者會自動把他從引用它的 rule 移掉**；對不存在的使用者附加是 `no such entry` 的逐成員失敗 | 「roster 把已刪使用者仍列在 rule」的行為：Go 階段的 user 刪除之後 rule 已經沒有他，HBAC 階段再附加會逐成員失敗，所以要在 plan 階段分類（§4.2 Q1） |

K9（正式規模的 rule 數與 `hbacrule_find` 成本）與 K10（run 2 的固定成本）仍未量測。

### 1.4 風險

- R1（**鎖死登入**）：HBAC 寫錯會讓使用者無法登入。lockdown 把 `allow_all` 關掉，若沒有可用的 break-glass rule，所有人（含 admin）被擋。緩解：沿用 playbook 的前置檢查與 `hbactest` 前後證明、失敗回滾（§6），且 lockdown 在所有 rule 收斂**之後**、最後一步執行。
- R2（**順序**）：HBAC 引用的 host／hostgroup 由 playbook 建立。Go 階段放在 playbook 之後（§2 D1）。第二個階段若在 playbook 失敗後仍執行，會對不完整的 FreeIPA 寫入：因此 playbook 失敗時 HBAC 階段**不執行**（§7.3）。
- R3（**分類與成員互斥**）：FreeIPA 不接受「hostcat=all 而且有成員」。stage 順序錯會讓 rule 在中間狀態失敗或短暫放寬（先清成員、後設 hostcat=all 才安全；反向要先清分類、才能附加成員）。§5.2 固定順序。
- R4（**移除是逐 rule 限定的**）：只移除「這條 rule 上目前存在、而這條 rule 自己的 roster 清單沒有」的成員，不掃其他 rule，也不刪 roster 沒提到的 rule 或 service（§4.3）。
- R5（**quota／規模**）：`hbacrule_find` 的預設回傳上限；沿用 P2 K3 的 `sizelimit=0` 做法，且讀到的筆數與 server 的 `count` 不符就失敗（K9）。
- R6（**混合 run 變長**）：多一次 playbook 啟動（§7.2 的 run 2），固定成本約是 always 標記的 task（K10 量測）。取代的是正式環境約 280 秒的重複 SSSD 刷新。

### 1.5 destructive 邊界

- HBAC 的移除（成員）與刪除（rule）都標 `destructive: true`；沿用 P2 §1.4 的規則：Plan₁ 沒有、Plan₂ 才出現的 destructive 操作不送出（`ErrDestructiveDiff`）。
- `allow_all` 永不刪除（validator 已擋，Go 再擋一次，§4.2）。
- Go 不刪 roster 沒提到的 rule、service；列在 plan 的 report（`unmanaged_hbac`），不動它們。
- 所有寫入測試只在拋棄式 lab。

## 2 決定總表

| # | 決定 | 理由 |
|---|---|---|
| D1 | **HBAC 是 playbook 之後的第二個 Go 階段**（2026-11-19 維護者決定）：Go(users/groups) → playbook run 1 → Go(HBAC) → playbook run 2（只做授權快取 settle）。 | HBAC 引用 playbook 建立的 hosts／hostgroups；放在前面會讓「同一輪新建 hostgroup 並引用它」blocked。 |
| D2 | **lockdown 一起搬到 Go**（2026-11-19 維護者決定）。 | HBAC 階段在 playbook 之後，lockdown 若留在 playbook 會在 rule 建好之前執行，break-glass 前置檢查必掛。 |
| D3 | grant 編譯出的 rule 留在 playbook。 | 輸入只經 `-e`，Go 看不到；兩邊各管自己的 rule 集合，名稱空間分開（`CompiledLoginRuleName`）。 |
| D4 | playbook 新增 `pilot_identity_hbac_engine`（`ansible` 預設或 `go`），`go` 時跳過**roster** 來源的 HBAC task，仍處理 grant 編譯的 rule（§3.3）。 | 與 P2 的 `pilot_identity_users_groups_engine` 同一種 guard，且同樣由 gate 拒絕沒有 Go 階段的 `go`。 |
| D5 | 第二個階段**重用** P2 的 Gate、Journal、批次、Outcome、結果與驗證的型別，但有自己的 plan 與 stage；不改 users/groups 的 plan 結構。 | 避免把 HBAC 塞進一個以 users/groups 為核心的 `Plan`；§5.7 一致性。 |
| D6 | 授權快取 settle 由 **run 2**（`--tags client-cache` 的同一支 identity playbook）完成，不另寫刷新邏輯。run 1 以變數跳過刷新與確認。 | 刷新邏輯（客戶端清單、deferred、timeout、gate）已在 playbook；複製一份會 drift（AGENTS.md §5.7）。 |
| D7 | playbook 失敗（run 1 非 0）時，HBAC 階段與 run 2 都不執行；義務仍欠著，結束碼沿用 P2 §6（4）。 | R2。 |
| D8 | preview：HBAC 的唯讀 plan 把「roster 宣告了、但 live 還沒有」的 host／hostgroup 視為將由 playbook 建立（不 blocked），兩邊都沒有才 blocked。apply 時第二階段在 playbook 之後重讀，不存在就 blocked。 | preview 看不到 playbook 的結果；apply 以真實狀態為準。 |
| D9 | 不新增旗標。`--scope full` 自動帶 HBAC；`--scope users-groups` 不碰。 | 範圍不放進旗標（P1 D1）。 |

## 3 desired state

### 3.1 來源與正規化

來自 roster 的 `hbac`：`services`、`rules`、`disable_allow_all`。與 playbook 的 "Normalize canonical HBAC rules"（`freeipa-identity-apply.yml` 約 672–692 行）逐欄相同：

| roster | desired |
|---|---|
| `name` | rule 名稱（小寫比對，送出時保留拼法，K7） |
| `subjects.users`／`subjects.groups` | `users`／`groups`（預設 `[]`） |
| `services` | `services`（validator 要求至少一個，所以 roster 的 rule 不會用 `servicecat`） |
| `enabled` | 預設 `true` |
| `targets.hosts`／`targets.hostgroups` | 有任一個非空：`hosts`、`hostgroups`，且 `hostcat` 為空字串（清除）；否則 `hostcat = targets.hostcat`（預設 `all`） |
| `state` | `present`（預設）進 rules；`absent` 進 absent 清單，只需名稱 |
| `hbac.services[].name` | HBAC service 物件 |
| `hbac.disable_allow_all` | 預設 `false` |

### 3.2 比對規則（與 playbook 相同，不是新設計）

- user、group、hostgroup、service：比對前轉小寫；送指令時保留 roster 的原拼法。
- host：**小寫 FQDN**（K4 定案）。roster 的短名稱以 `env` 的 `domain` 補全（FreeIPA 自己也這樣做），讀回的 `memberhost_host` 本來就是小寫 FQDN。playbook 比對時是**去掉網域、轉小寫**（`regex_replace('\\..*$', '')`），所以它會把 `web1.a.example` 與 `web1.b.example` 當成同一台；Go 不會。兩者在 roster 一律寫同一個 domain 的 FQDN 或短名稱時等價，差異記在 §9。
- rule 名稱：小寫比對（K7），送指令時保留 roster 的拼法；兩個只差大小寫的 rule 是 `case_collision`。

### 3.3 playbook 與 Go 的分工

`ipa_hbac_rules` 在 playbook 是 roster rule 與 grant 編譯 rule 的合併清單。`pilot_identity_hbac_engine=go` 時：

- roster 來源的 rule 不進 `ipa_hbac_rules`、不進 `ipa_hbac_rules_absent`、`ipa_hbac_services` 為空；
- grant 編譯的 rule 照舊進（附加／移除／enabled 的 task 照舊）；`pilot_compiled_grant_hbac_prune` 照舊；
- lockdown block 整段不執行（`ipa_hbac_disable_allow_all` 在 `go` 時視為 `false`）。

兩邊的集合互斥：Go 只管 roster 的名稱，playbook 只管 grant 的名稱。名稱同時出現在兩邊是 roster 與 grant 的碰撞，Go 的 preflight 以 blocked（`name_collision_with_grant`）拒絕。K11：Go 要怎麼知道 grant 編譯的名稱？它們由 `pilot access` 寫進 `-e` 檔；Phase 3a 的做法是名稱空間前綴（`CompiledLoginRuleName` 的前綴）——roster 的 rule 名稱若在該前綴下就 blocked。

## 4 live 讀取與 plan

### 4.1 讀取

唯讀，沿用 P1 的 `Finder` 與 `sizelimit=0`：`hbacrule_find --all`、`hbacsvc_find`、`host_find --pkey-only`、`hostgroup_find --pkey-only`，以及 P1 已讀的 users／groups。讀取數不依 rule 數成長（不逐 rule `show`）。

### 4.2 blocked 原因（不送任何寫入）

| 原因 | 條件 |
|---|---|
| `allow_all_delete` | roster 有 `allow_all` 且 `state: absent`（validator 已擋，Go 再擋） |
| `reference_unresolved` | rule 引用的 host／hostgroup 在 live 與 roster 宣告兩邊都沒有；user／group 在 live 與 users／groups 的 desired 兩邊都沒有（D8） |
| `reference_to_absent` | 引用的 user／group 是 `state: absent`（與 P1 同名原因；E49：Go **不**因此擋 preflight，維持 P2 的決定——是否改變是 Q1） |
| `lockdown_no_break_glass` | `disable_allow_all: true` 而沒有 enabled、subjects 含 `admin`、`hostcat: all` 的 rule |
| `name_collision_with_grant` | §3.3 |
| `case_collision` | 兩個 rule 名稱只差大小寫（K7：FreeIPA 的 rule 名稱不分大小寫，第二個會是 `DuplicateEntry`） |

`reference_to_absent` 的處理要與 P2 E49(1) 一致；**Q1 未決**：沿用「不擋」（playbook 會 `partial_failed`，E47(10)(a)）或改成擋。預設沿用，因為兩個 engine 同形。

### 4.3 operation 與順序

kind，順序照 playbook（約 2368–2650 行）：

1. `hbacsvc.create`
2. `hbacrule.create`（新 rule：只帶 `hostcategory`／`servicecategory`，與 playbook 的 "Ensure HBAC rules exist" 同）
3. `hbacrule.member.remove`（host、hostgroup、service、user、group 五種；**逐 rule 限定**：只移除這條 rule 目前有、而它自己的 desired 沒有的成員）
4. `hbacrule.category.update`（`hostcategory`／`servicecategory`，一律明確送值，空字串是清除）
5. `hbacrule.member.add`（hostgroup、host、service、user、group）
6. `hbacrule.enable`／`hbacrule.disable`
7. `hbacrule.delete`（`state: absent`；刪不存在的是 converged，不是錯誤）
8. `hbac.allow_all.disable`（lockdown，§6）

不刪 roster 沒列出的 rule、不移除 service。這與 playbook 一致（playbook 沒有這類 task），列在 `reports.unmanaged_hbac`。

## 5 writer

### 5.1 入口

與 P2 §7 同形：寫入前重讀並重算（Plan₁→Plan₂）、Plan₂ 與 Plan₁ 比較 destructive、Entry.Prepare 在第一個寫入之前記下義務（義務已存在則 `previous=true`，Prepare 不重複造成問題；K12 確認 prepare 對已 dirty 的 journal 是冪等）、Gate 開啟、逐 stage 送出、寫入後重讀驗證、journal 全程記錄。

### 5.2 stage

| stage | 內容 | 必須在 … 之後 | 原因 |
|---|---|---|---|
| H1 | `hbacsvc.create` | 無 | 後續附加 service 需要它存在 |
| H2 | `hbacrule.create` | H1 | 同上 |
| H3 | `member.remove` | H2 | R3：先清成員，才能把分類設成 `all` |
| H4 | `category.update` | H3 | R3、K3 |
| H5 | `member.add` | H4 | 分類清掉之後才能附加成員（K3） |
| H6 | `enable`／`disable` | H5 | 收斂完才啟用，避免半成品 rule 生效 |
| H7 | `rule.delete` | H6 | 與 netgroup 的刪除排在最後同理 |
| H8 | lockdown | H7 | R1：所有 rule 收斂之後 |

每個 stage 用 P2 的批次（`MaxBatch` 25）。member 指令的部分成功（`failed` 結構）逐成員分類，沿用 P2 K13。unknown outcome 的解析沿用 P2 §7.5（寫入後讀回判斷 converged／not-applied）。

### 5.3 失敗政策

- 任何 stage 失敗：之後的 stage 不送；已送的記為 partial；義務維持欠著；結束碼 1（有寫入）。與 P2 §6 同。
- lockdown 失敗：依 §6 回滾；回滾本身失敗要明說，不可寫成已還原。

## 6 lockdown（`hbac.allow_all.disable`）

與 playbook 的 "Transactional HBAC allow_all lockdown"（約 2717–2780 行）同一個 contract，用 RPC 重現：

1. 前置：roster 有 enabled、`admin` 為 subject、`hostcat: all` 的 rule（blocked 原因 `lockdown_no_break_glass` 在 plan 階段就檢查）。
2. `hbactest --user=admin --host=<FreeIPA server FQDN> --service=sshd` 必須 `Access granted: True`（K5：以 `value`／`matched` 判斷，不用文字比對）。
3. 若 `allow_all` 目前 enabled：`hbacrule_disable allow_all`；已 disabled 是 converged。
4. 再次 `hbactest`，仍須 granted。
5. 任一步失敗：`hbacrule_enable allow_all`（回滾），並報告回滾是否成功（回滾失敗時錯誤指名要人工檢查 HBAC）。
6. `--preview-only`（或 `--check`）不執行任何 hbactest 寫入以外的動作：hbactest 本身是唯讀，preview 可以跑步驟 1–2 並報告「lockdown 將執行」；不執行 3–5。

測試 host 是 `freeipa.server`（roster）或 inventory 解出的 server FQDN，與 playbook 的 `identity_hbac_test_host` 相同。

## 7 混合 run 的整合

### 7.1 playbook 變更

- 新增 `pilot_identity_hbac_engine`（預設 `ansible`），與 `pilot_identity_users_groups_engine` 同一種 gate：只在 `go` 且 pilot 給了授權快取觀察檔路徑時接受；其他組合拒絕（P2 §8.5 的 guard 形狀）。
- `go` 時：§3.3 的跳過；另外**不刷新、不確認**（新增 `pilot_identity_cache_settle: defer`，run 1 帶它，refresh 與 ack task 以它跳過，觀察記 `acked=false`）。
- run 2：`ansible-playbook … --tags client-cache`，不帶 `defer`，帶觀察檔路徑；它是現有「tagged run」的路徑（playbook 既有的 "Report deferred authorization cache refresh" 就是針對 tag 選擇）。K10：量測 run 2 的固定成本。
- 新增的 `when:` 全部走 AGENTS.md §4.4／§4.5 的規則（always 的前置要 always、`is defined` 讀法），並有 regression test（P2 §8.5 的測試是範本）。

### 7.2 transaction

```
preview:  Go(users/groups 唯讀 plan) → Go(HBAC 唯讀 plan，D8) → playbook --check
apply:    [lock] Go(users/groups) → playbook run 1 (hbac=go, settle=defer)
          → Go(HBAC) → playbook run 2 (--tags client-cache) → verify → [unlock]
idempotency: Go(users/groups) plan 與 Go(HBAC) plan 都必須沒有操作
```

結果檔 `pilot.identity-apply/v1` 的 `scope` 仍是 `full`；新增選用物件 `hbac`（`ran`、`writes`、`stages`、`lockdown`、`error`）。義務判定由 **run 2** 的觀察決定；沒有 run 2 或 run 2 失敗就欠著（結束碼 4）。

### 7.3 失敗路徑

| 情況 | 行為 |
|---|---|
| Go(users/groups) blocked／失敗 | 不啟動 playbook，沿用 P2 |
| run 1 非 0 | **不跑** HBAC 階段與 run 2；義務欠著；`partial_failed`，結束碼 1（Go 已寫入）或沿用 P2 |
| HBAC 階段 blocked（apply 時重讀發現 host 不存在等） | 零寫入、不跑 run 2，義務欠著、結束碼 3 若整輪沒有任何寫入，否則 1 |
| HBAC 階段部分失敗 | 不跑 run 2？**Q2：** 預設仍跑 run 2 結清已發生的變更的快取（失敗的 rule 保持原狀），結束碼 1 |
| run 2 失敗或沒觀察到 ack | 結束碼 4（未結清） |

Q2 的預設需要維護者確認（見 §10）。

## 8 驗收

規格 row 對應 `docs/verification/freeipa-identity.md` 的 C13、C14（HBAC 相關），新增的 row 在實作時補，並經 `pilot spec --lint` 與 `TestSpecPlaybookTagAlignment`。

### 8.1 單元／整合

- desired 解析：每個 §3.1 的欄位組合、預設值、`hostcat` 與 hosts 的互斥、`state: absent`、大小寫。
- plan：每種 blocked、每個 operation kind 的新增／移除／分類切換（hosts→all、all→hosts）、`unmanaged_hbac` report、順序。
- writer：fake IPA（P2 的 `fakeipa_test.go` 擴充）涵蓋每個 stage 的成功、already-exists、not-found、already-a-member、部分失敗、unknown outcome、Gate 關閉時拒絕、destructive diff 拒絕。
- lockdown：每一步失敗的回滾、回滾失敗的訊息、preview 不寫入。
- **每個 gate 要有「通過」與「觸發」兩種案例，都用真實擷取的輸出**（AGENTS.md §5.12）。

### 8.2 live（拋棄式 lab：FreeIPA server + 一台 enrolled client）

- K1–K9 的擷取（fixture 只來自這裡）。
- Go(HBAC) 收斂之後：舊 engine（Ansible）對同一份 roster 全量重跑，HBAC 相關 task `changed=0`（P1 D12 的對照，雙向）。
- 反向：Ansible 先收斂，Go plan 的寫入數為 0。
- 登入 oracle（P2 K20）：被授權的使用者在 client 上 ssh 登入成功；移出 rule 之後被拒；rule 設 disabled 被拒；刪 rule 被拒。
- 撤銷路徑：從 roster 移除 rule／成員 → 被清掉（AGENTS.md §5.14）；`state: absent` 刪除；刪不存在的 rule 冪等。
- lockdown：成功、break-glass 缺失被擋、`hbactest` 後驗失敗時回滾（以破壞 break-glass 的 live 狀態製造）。
- 混合 run：新建 hostgroup + 引用它的 rule，同一輪收斂（D1 的核心理由）。
- 失敗路徑：run 1 失敗時 HBAC 階段不執行；HBAC 階段 blocked；run 2 失敗結束碼 4。
- 每個新 gate 對 live 狀態真的觸發一次。

### 8.3 evidence

`docs/evidence/freeipa-go-reconcile/pr-<n>.md`（機器部分由 pilot 產生）與 `LATEST.md` 新增 Phase 3a 一節；candidate 凍結與隔離 checkout 依 AGENTS.md §1.5。

## 9 與 playbook 的已知差異（實作時填，目前為空）

已知的：(1) host 比對：Go 用小寫 FQDN，playbook 去掉網域後比（§3.2，K4）；(2) `reference_to_absent`（§4.2，K8：刪使用者已自動移出 rule）；(3) rule 名稱 `case_collision`：playbook 沒有這個檢查，同名只差大小寫時 playbook 會在 `hbacrule-add` 之後把第二個當成「已存在」而靜默合併，Go 擋下。每一項要寫出理由與 live 證據。

## 10 待確認

| # | 問題 | 預設 |
|---|---|---|
| Q1 | HBAC 引用 `state: absent` 的 user／group，Go 是否在 preflight 擋 | 不擋（與 P2 E49(1)、Ansible 同形） |
| Q2 | HBAC 階段部分失敗時，是否仍跑 run 2 結清快取 | 跑，結束碼 1 |
| Q3 | host 比對採 FQDN 或短名稱 | **已定案（K4）**：小寫 FQDN，短名稱以 `env` 的 domain 補全 |
| Q4 | rule 名稱是否大小寫敏感 | **已定案（K7）**：不分大小寫，保留第一次的拼法 |
| Q5 | run 2 的固定成本可接受嗎（等 K10；對照：省下約 280 秒的重複刷新） | 等量測 |

## 11 實作切片

| 切片 | 內容 | 需要 lab |
|---|---|---|
| P3-0 | K1–K8 擷取、fixture、事實測試（**已完成**，§1.3；K9 仍待量測） | 是 |
| P3-1 | desired 解析、live 讀取、plan（含 blocked、順序）（**已完成**：`hbac_desired.go`、`hbac_live.go`、`hbac_plan.go`、`hbac_test.go`；allowlist 加入 HBAC 的讀寫方法，寫入方法由 11 個變 23 個）；唯讀 preview 納入（入口）留給 P3-5 | 否（fixture 來自 P3-0） |
| P3-2 | writer：stage、批次、分類、驗證、journal、fake IPA 矩陣 | 否 |
| P3-3 | lockdown | 是（K5、K6） |
| P3-4 | playbook：`pilot_identity_hbac_engine`、settle defer、run 2 的 tag 路徑、regression test | 是（K10） |
| P3-5 | transaction 整合：第二階段、run 2、結果檔、結束碼、idempotency | 是 |
| P3-6 | live driver、evidence、文件 | 是 |

## 12 變更紀錄

| 日期 | 變更 |
|---|---|
| 2026-11-19 | 初版草案。維護者決定：D1（playbook 之後的第二個 Go 階段）、D2（lockdown 一起搬）。 |
| 2026-11-19 | P3-1：desired、live 讀取、plan 完成；`freeiparpc` 的 allowlist 加入 HBAC 方法（security boundary 的測試計數 11→23）。 |
| 2026-11-19 | P3-0：K1–K8 擷取完成（§1.3），Q3、Q4 定案，§3.2、§4.2、§9 對應更新。 |
