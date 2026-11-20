# FreeIPA Go reconcile 最新驗收

## Phase 3a：HBAC 組件的 playbook 變更（PR #396）

目前狀態：**PASS（playbook 的部分）**。驗收日期 2026-11-20，candidate `5882eabaa996468ffa7a68c2e41ad368026c0046`，tree `f3522e1387bf8d145c6480d222b2e5f50f99b739`（已合併 main `f9cbd198`）。機器產生的 record 由 pilot 寫出，指標如下：

| Record | Tested commit | Outcome | Finished (UTC) | Verify |
|---|---|---|---|---|
| [pr-396.md](pr-396.md) | `5882eabaa996468ffa7a68c2e41ad368026c0046` | success | 2026-11-20 08:32 | PASS 24/0/0 |

- **範圍**：`freeipa-identity-apply.yml` 新增選用的 `-e pilot_identity_hbac_engine=go`、`-e pilot_identity_cache_settle=defer` 與對應 gate，並與 main 的憑證拆分（#142／#216）合併。Go 的 HBAC writer、lockdown 與 `ExecuteHBAC` 在這個 candidate **沒有接到任何入口**，不能在 VM 上證明，沒有造假的 driver。
- **Target**：兩台拋棄式 `vm-target` VM：FreeIPA 4.13.4 server（AlmaLinux 9.8）與一台 enrolled client（Ubuntu 24.04.4）；沒有任何正式環境。
- **結果**：預設模式的正式鏈 L1–L6 全部通過（L3 `changed=0`、L4 `changed=70`、`freeipa-identity.md` 24/0/0、L6 `changed=0`），並在 `-v` 下建立帶 `password.initial` 的使用者、輸出 0 筆秘密；手動的 go 模式：run 1（`defer`）不建立也不改名冊的 HBAC 物件、`allow_all` 仍啟用、grant rule 照建、不刷新 SSSD（`acked=false refreshed=false`），run 2（`--tags client-cache`）刷新並 acknowledge（`acked=true`，義務結清），再跑 run 1 為 `changed=0`；8 個 gate 負向案例與 4 個帶 tag 的負向案例都在變更之前以 rc 2 失敗、FreeIPA 狀態不變；`--tags hbac`／`C13`／`C14`／`--skip-tags client-cache` 在 go 模式不動名冊 HBAC，預設模式的同一個 tag 會改回漂移。
- **已知限制**：Go 的 HBAC 階段、H1–H8 stage、lockdown 證明與回滾、K9／K10、混合 run 的 transaction 與結束碼、登入 oracle 都不在這份 record（P3-5、P3-6）；手動執行不是正式鏈；只驗證 ansible-core 2.19.2 與單一 server。

候選、手動執行的逐項結果、失敗路徑與限制見 [PR #396 驗收紀錄](pr-396.md)。

## Issue #394：Go engine 送出單一 `{{ name }}` 形式的 `password.initial`

目前狀態：**PASS**。驗收日期 2026-11-20，candidate `c58edf7e4c027e37ccd363b56b5d80eeafd62bfa`，tree `c2306ed5384e4207cfd707451295c82b3e72b1ce`（已合併 main `f9937741`）。

- **範圍**：`pilot reconcile --component freeipa-identity --engine golang` 對 `password.initial` 恰好是一個 `{{ name }}` 的使用者，以這次執行的變數（帶 `-e @.vault/main.yaml` 的 `ansible-inventory --list`）解析並送出；其他寫法與無法證明的值維持 `password_value_unsupported`。
- **Target**：拋棄式 `vm-target` VM：一台 FreeIPA 4.13.4 server（AlmaLinux 9.8）與一台 enrolled client（Ubuntu 24.04）；只在這裡實跑，沒有任何正式環境。
- **結果**：`TestLiveGoApplyDriver` 的 A1、A15、A23 共 19／19 arm 通過、0 skip：Go engine 以加密 vault 的值建立使用者並以 kinit 證明（錯誤的值失敗）；Ansible engine 以 main 的 identity playbook 從同一個範本設出同一個密碼（A23(f)）；之後的 Ansible engine 完整 run 在 users／groups 區段沒有變更；8 個觸發（含 vars 端字面的 `{__ansible_unsafe: ...}` mapping 與 `!unsafe` 字串，原因 `unsafe-marker`）都是 exit 3、0 寫入；混合 run 通過。同一個 candidate 前兩次執行因 harness 環境（另一個 session 的 driver 共用寫死的 `/tmp/p26cp`；`bwrap` 裡 ssh 設定的擁有者）在 A1 失敗，與更早 candidate 的較廣 arm 一起寫在 record 的失敗路徑。
- **已知限制**：只驗證 ansible-core 2.19.2；driver 在私有 `/tmp` 與 ssh client 設定的複本裡執行；#165 的 `ServerDeclared`、`AdminPasswordProvided` 讀 marker 的行為沒有改（#358）；其他 roster 欄位與 run 輸入見 #397、#398。

候選、各 arm 的事實、失敗路徑與限制見 [Issue #394 驗收紀錄](issue-394.md)。

## Phase 2：使用者與群組的寫入 MVP（PR #284，P2-2 到 P2-8）

目前狀態：**PASS，附已記錄的未達項**（完整 identity 的 180 秒目標，見下）。驗收日期 2026-11-07。最後一個 code candidate：`7ed9f4a2dc6f9eb0d7fde55cb8e5d2a2fdbfeebd`，tree `f441d624415e4935ce339602cbceeac971da41e6`（P2-8 的測試 candidate；它之後只有一個只動測試的 CI 修正與文件）。Go engine 與 identity playbook 的**執行閉包的正式檔案**與 P2-7 的 candidate `0e364254273b917865cbe2002ac5300e1e5fdb83`（tree `b015f2326f2fcf8381577a3251f424b7b1a7e62f`）逐位元組相同（`git diff` 為空），所以 P2-6、P2-7 的 live arm 沒有重跑；P2-8 在合併 main 之後的 tree 上又跑了 users-groups 的新增、修改、刪除、重跑、預覽與混合 run。

- **範圍**：`pilot reconcile --component freeipa-identity --engine golang --scope users-groups|full --force`：取鎖閘門、授權快取入口與探測、Go writer（寫入前重讀、stage 與 batch、密碼、刪除保護、journal）、users-groups scope 的套用、混合 scope 與 playbook 的 guard，以及效能量測。
- **Target**：拋棄式 `vm-target` VM：一台 FreeIPA 4.13.4 server（2 vCPU、6 GiB）與一台 enrolled client（Ubuntu 24.04）；只在這裡實跑，沒有任何正式環境。
- **各項結果**（candidate 與細節在 [PR #284 驗收紀錄](pr-284.md) 對應的一節）：
  - **P2-2 取鎖閘門**：candidate `91f82abb`（tree `dfb5135d`）；34 筆 arm 紀錄（33 PASS，L7 依規格只記錄），L11 A、B PASS，秘密 0 筆。
  - **P2-3 入口 playbook、helper 探測、identity 的觀察與結果解析器**：candidate `dac5efcf`（tree `33e6848c`）；`vm-target test` 鏈 L1–L6 通過、verify 24/0/0；25 次入口與 8 次 identity 的拒絕與結果路徑都如規格。
  - **P2-4 寫入 RPC 的擷取（K6–K15、K19、K21）**：candidate `0afb30b8`（tree `411b64d1`）；114 筆擷取、56 個 fact 與 255 個竄改探測，109／109 個移除斷言的 mutant 與 22／22 個其他 negative control 都被抓到。
  - **P2-5 Go writer（沒有入口）**：candidate `2fc4d798`（tree `0207df1a`）；P1 的預覽 driver 在全新 VM 上重跑 8／8、寫入 0；executor 本身的證明是單元矩陣與 mutation sweep。
  - **P2-6 users-groups 的套用、K20、D31 暫停點、結果檔**：candidate `8aafd05b`（tree `183ac1f8`）；driver 48／48 arm。
  - **P2-7 混合 scope、identity playbook 的 guard**：candidate `0e364254`（tree `b015f232`）；`vm-target test` 鏈 6／6 步、driver 58／58 arm（含混合的 A16、H1–H6、A17(iii)(iv)）。
  - **P2-8 效能量測**：candidate `7ed9f4a2`（tree `f441d624`）；**PASS**：四個 launch 共 246 個樣本，沒有任何樣本未通過所屬情境的正確性 gate；7 個 control 在真實 run 上都觸發；gate 的 38 個 mutation 全被抓到。
- **效能（拋棄式 lab，不是正式環境；數字、樣本數與限制在 pr-284.md 的 P2-8 一節）**：120／40 無差異 p95 9.7 秒（n=20，目標 30）、單一屬性 p95 16.9 秒（n=20，目標 30）、100 次新增 p95 35.0 秒（n=20，目標 120）且重跑零寫入、1,000／200 讀取完整（1139 位使用者、488 個群組）；入口 playbook 約 2.1 秒，與整輪分開呈現；批次上限 10／25／50／100 的比較後 `MaxBatch` 維持 25。**未達**：完整 identity 的混合 run 在寬 roster（21 台 host、22 條 HBAC、26 條 sudo）544.0 秒（目標 180；窄 roster 120 位使用者 108.3 秒達成）；原因在 identity playbook 的 sudo 與 HBAC task 與逐使用者的 normalization，不在 Go；Phase 3 的 go／no-go 輸入與建議在 pr-284.md 與計畫的「規模與 go/no-go」（建議，不是決定）。舊 engine 的基準在寬 roster 上另列，不比倍數。
- **已知限制**：只有拋棄式 lab（一個 FreeIPA 4.13.4 server、沒有 replica、一台 Ubuntu client；X2 的正式環境 RTT 與版本未解）；效能樣本中混合、批次比較、舊 engine 的 n 小於 20，不稱 p95；入口耗時在 218 個有入口或探測的 run 中有 4 個沒有被觀察到；`ansible-playbook` 被 SIGKILL 的 pilot 留下的子行程（X5）與 `-e @file` 提供的連線設定（R12）等規格 §1.3 列出的風險仍在。
- **維護者已確認的預設**（2026-11-07，spec E49）：Q6（`pilot runs last-success` 預設排除 `scope=users-groups`，`--include-users-groups` 納入）、Q8（空字串：`first`、`last`、`home_directory` 的 `""` 被拒，其餘四個鍵的 `""` 是「沒有值」）、U3（自鎖保護 `protected_object` 啟用），以及 U2、U4–U6、Q7；U1 已於 2026-11-06 確認。
- **CI**：開始 P2-8 時 `364e2051` 的 pull_request run 有兩個 `internal/spec` 測試失敗（`ANSIBLE_HOME` 的覆寫把 collection 路徑一起移走，CI 的 ansible-core 2.19.15 的 `json` callback 在 `ansible.posix`；本機以 ansible-core 2.19.15 重現，修正 `d1ef9d4b` 只動測試）。

候選、實測數據、失敗路徑與限制見 [PR #284 驗收紀錄](pr-284.md)。

## Phase 1：唯讀預覽（PR #255）

目前狀態：**PASS**。驗收日期 2026-11-05，candidate `4f469406e578228b3d132270f7852dae9a6f8f7d`，tree `1e096225fbe631a96d9792c4d60ef5aebdb0f27c`。

- **範圍**：Phase 1 唯讀預覽 `pilot reconcile --component freeipa-identity --preview-only --engine golang`。
- **Target**：拋棄式 `vm-target` VM（FreeIPA 4.13.4，API 2.257），單一 `freeipa-server` 主機。
- **結果**：
  - §10.3 driver 8/8 PASS，每次預覽 0 個寫入。
  - 28 個失敗路徑 arm、共 30 次執行，全部依規格結束；L3 依已知限制 3 結束。涵蓋 vault 密碼來源卡住時的 `--timeout`、Ctrl-C、SIGTERM、終端機斷線、ProxyJump、伺服器凍結時的登出與登入、blocked plan、非 admins 讀取者、登入被拒。
  - 秘密 0 筆。

候選、實測數據、失敗路徑與限制見 [PR #255 驗收紀錄](pr-255.md)。
