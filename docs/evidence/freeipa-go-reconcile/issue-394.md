# Issue #394：Go engine 送出單一 `{{ name }}` 形式的 `password.initial`

Spec：`docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md` §7.8、D22、A15、A23、E51。程式碼：`internal/inventory`（`RosterRunVars.UserInitialPassword`、`RosterUserPasswords`、`passwordCaptureNames`）、`internal/identityreconcile`（`desired.go`、`plan.go`、`passwords.go`）、`cmd/pilot/cmd/reconcile_golang*.go`（`golangRunVars`）。

這是 #394 唯一的一份 record；新的 candidate 就地覆寫，被取代的版本留在 Git history（`docs/actual-run-evidence.md` §1）。

**狀態：PASS**，candidate `9c0e2772`：17 個 live arm 全部通過。這個變更沒有改任何 playbook 或 contract；arm 以 pilot 的 Go engine 與 Ansible engine 對真實 FreeIPA server 執行。

## 目前的 candidate

| 項目 | 內容 |
|---|---|
| 測試的 candidate | `9c0e2772898eff00ae98777dc3c877f7d5609ff6`，tree `a2c7a898d91bced18828712f23088940d1613d2f`，branch `issue/394-go-engine-password-template`（base `main` `90a2249b`）。從該 commit 的全新本機 clone 執行（`git status` 為空） |
| Target | 兩台拋棄式 `vm-target` VM：FreeIPA 4.13.4（`ipa-server-4.13.4-1.el9_9`、krb5 1.21.1）on AlmaLinux 9.8（角色 `freeipa-server`），與 enroll 進它的 Ubuntu 24.04.4 client（`freeipa-client` 4.11.1、sssd 2.9.4，角色 `freeipa-client`）；兩台都以 VM 自己的 key 用 root ssh 連線。每個 arm 開始前，兩台都回到同一組 enrolled 基準 snapshot，再由 A1 建立 acked 基準 |
| Workspace 與輸入 | repo 以外的拋棄式 workspace：`hosts.yml`（server 名稱為 `ipa1`、client 以 FQDN 命名並設 `ipa_client_fqdn`、絕對路徑的 `freeipa_roster_file`）經 `pilot inventory generate` 產生 `inventory.yml`；`.vault/main.yaml` 以 `ansible-vault` 加密，vault 密碼由 Ansible 從 `ANSIBLE_VAULT_PASSWORD_FILE` 讀取（環境模式）。lab 的 admin 密碼是隨機產生、存在 repo 以外的 0600 檔案。每個 arm 的 roster 與 vault 變數由 driver 寫入該 arm 的 workspace 複本；A23 的密碼值在執行時隨機產生，含空白、`0123`、反引號、`$HOME`、`%s`、CJK、單雙引號 |
| Controller 工具 | Go 1.26.8、ansible-core 2.19.2 |
| Harness | `TestLiveGoApplyDriver`（`internal/identityreconcile/live_apply_test.go` 與 `live_apply_lab_test.go`、`live_apply_arms_test.go`、`live_apply_arms3_test.go`），由 driver 從 candidate 自行 build 的 pilot binary 執行；arm 篩選 `A1 baseline,A15,A23` |
| 判定 | **PASS**：17／17 arm，1112 秒 |
| 執行 | 2026-11-19 10:46–11:05 UTC；操作者：維護者工作站上的 coding agent |

影響執行的檔案（Git blob id、SHA-256 前綴）；其餘檔案由上面的 tree id 涵蓋：

| 檔案 | Blob | SHA-256 |
|---|---|---|
| `cmd/pilot/cmd/reconcile_golang.go` | `4822cc70ab8c` | `d20024672e6ada0a` |
| `cmd/pilot/cmd/reconcile_golang_apply.go` | `dc19799c6c3a` | `9aa3c0a1f8bc486b` |
| `cmd/pilot/cmd/reconcile_golang_mixed.go` | `44b97cd4f4e8` | `9507d9f8bb63380e` |
| `internal/identityreconcile/desired.go` | `11ab64a6c0d2` | `82347d4728e5def5` |
| `internal/identityreconcile/passwords.go` | `dc3a089307c0` | `02b00d12bafb6f60` |
| `internal/identityreconcile/plan.go` | `9c91c0ceafd5` | `69c5167fd046fca6` |
| `internal/inventory/roster_playbook_names.go` | `cdc0d43cc0bf` | `76d09a9b64f5d5b6` |
| `internal/inventory/roster_run_facts.go` | `734e35d4b0d5` | `0c31f4774319f4d4` |
| `internal/inventory/roster_user_passwords.go` | `84b5cd076ed4` | `0f7c049d92b4d063` |
| `playbooks/apply/freeipa-identity-apply.yml`（未變更） | `42196c440731` | `e6c3b08f46becea0` |
| `playbooks/apply/tasks/freeipa-identity-normalize-users-groups.yml`（未變更） | `c7787803979c` | `e34525e8ba2c0ed2` |
| `internal/identityreconcile/live_apply_arms3_test.go` | `9253d4125f14` | `55e81b113ced029f` |
| `internal/identityreconcile/live_apply_arms_test.go` | `8448a069a08a` | `de6d4700cb027f29` |
| `internal/identityreconcile/live_apply_test.go` | `d4a06dea4ddd` | `e7fb7ce99f1bd9fa` |
| `internal/identityreconcile/live_apply_lab_test.go` | `479f7824732a` | `5da2d3440f490a67` |

## 各 arm 的結果

一筆 run 寫成「結束碼、結果檔的 verdict、server 記到的寫入」。kinit oracle 只看結束碼：admin 設的初始密碼是已過期狀態，kinit 從 stdin 讀「初始密碼、新密碼、新密碼」，只有初始密碼正確才成功；每個用到它的 arm 都在同一次 run 裡先確認錯誤的值會失敗。

| Arm | 結果 | 秒 | 觀察到的事實 |
|---|---|---|---|
| A1 基準 | PASS | 248 | exit 0，`ok`，0 寫入；journal acked |
| A15 範本（`lookup` filter） | PASS | 20 | exit 3，`blocked`，0 寫入，沒有入口 |
| A15 inline `!vault` | PASS | 20 | exit 3，`blocked`，0 寫入，沒有入口 |
| A15 一般字串（對照） | PASS | 25 | exit 4，`unsettled`，`user_add` 1、`passwd` 1 |
| A15 未加引號的數字 | PASS | 18 | adapter 拒絕，沒有結果檔、沒有寫入 |
| A23(a) 單一 `{{ name }}`，值在加密的 vault | PASS | 24 | exit 4，`unsettled`；plan 只有 `user.create`、`user.password.initialize`；`user_add` 1、`passwd` 1；驗證乾淨；輸出、結果檔與 pilot data 目錄都沒有該值；錯誤的值 kinit 失敗、vault 的值 kinit 成功 |
| A23(c) 接著跑 Ansible engine 的完整 run | PASS | 147 | exit 0；輸出中有 70 個 users／groups 區段的 task，沒有一個 changed；server 沒有 `passwd`、`user_add`（只證明沒有重設：`preserve_existing` 預設為 true，這一步不比較密碼值） |
| A23(b) 對照：同一個值直接寫在 roster | PASS | 23 | exit 4，`user_add` 1、`passwd` 1；錯誤的值 kinit 失敗、正確的值 kinit 成功（oracle 會說「是」） |
| A23(d) 混合 run（`--scope full --force`） | PASS | 268 | exit 0，`ok`；`user_add` 1、`passwd` 1（另有 2 筆不屬於 Go plan 的 `user_mod`，arm 不斷言它們）；kinit 以 vault 的值成功、錯誤的值失敗；之後 Ansible engine 的完整 run 在 users／groups 區段沒有 changed、沒有 `passwd` |
| A23(f) Ansible engine 以同一個範本建立第二位使用者 | PASS | 162 | Ansible engine 的完整 run 建立 `p26-tpl2`，server 記到 1 筆 `passwd`；錯誤的值 kinit 失敗、vault 的值 kinit 成功。與 A23(a) 合起來，表示兩個 engine 從同一個範本設出同一個密碼 |
| A23(e) 觸發：變數未定義 | PASS | 19 | exit 3，`blocked`，0 寫入，沒有入口 |
| A23(e) 觸發：空字串 | PASS | 18 | exit 3，`blocked`，0 寫入 |
| A23(e) 觸發：未加引號的數字 | PASS | 26 | exit 3，`blocked`，0 寫入 |
| A23(e) 觸發：inline `!vault` 的變數值 | PASS | 28 | exit 3，`blocked`，0 寫入 |
| A23(e) 觸發：filter | PASS | 19 | exit 3，`blocked`，0 寫入 |
| A23(e) 觸發：identity playbook 自己設定的名稱（`identity_admin_password`） | PASS | 19 | exit 3，`blocked`，0 寫入 |
| A23(e) 對照：沒有密碼操作的既有使用者引用未定義的變數 | PASS | 20 | exit 0，`ok`，0 寫入（沒有被擋） |

被擋下的 run 的訊息指名使用者、`password.initial`、原因與變數名稱，不含值（arm 斷言，並掃描輸出、結果檔與 data 目錄）。

## 失敗路徑

- **前一個 candidate `a741c7d7`（tree `db8918e0`）的 run，2026-11-19 09:54–10:28 UTC**：53 個 arm 中 52 個通過。arm 篩選 `A1,A2,A15,A23` 以前綴比對，所以 A2、A2b、A10–A22、A16、A17(iii)(iv) 也一起跑了，全部通過。唯一的失敗是 A23(b)：「the roster's literal is not the user's initial password」。原因在 arm 本身：它把 `yamlText(value)`（JSON 加引號的 YAML scalar，只適合 `vaultWith` 寫入的 vault）傳給 roster，而 roster 是由 Go 字串 `yaml.Marshal` 出來的，引號與跳脫字元因此成了密碼的一部分；pilot 照 roster 的字面值送出，行為正確。修正在 `e44b5a71`（改傳 `value`），同一個 commit 新增 A23(f)。
- 兩個 candidate 之間影響執行的程式碼差異只在 `9c4045fd`：被 Ansible 保留的名稱（`ansible_*`、`role_*`、magic variable、Jinja global）改用新的拒絕原因 `reserved` 與它自己的訊息。兩種寫法都是拒絕，送出的值不變。上面那一輪較廣的 arm 只跑在 `a741c7d7` 上。
- `ansible-inventory` 讀不到 run 的變數（例如 stderr 帶出 vault 內容的失敗）只有本機測試（假的 `ansible-inventory` 以執行時產生的 sentinel 寫 stderr，sentinel 沒有出現在任何輸出）；沒有在 VM 上製造。
- 沒有 `.vault/main.yaml` 的 workspace 會先被 inventory 完整性檢查拒絕（`vault: .vault/main.yaml: 不存在`），所以 `no-run-vars` 只在單元測試觸發。

## 本機（非 live）的證明

- Oracle `TestRosterUserPasswordValuesMatchAnsible`（`make identity-secret-test`）：真實 ansible-playbook 執行 identity playbook 的 pre_tasks 到 normalize include，dump `passwd` stdin 讀的值；Go 端用真實 `ansible-inventory --list -e @vault --playbook-dir` 解析。53 列 × 明文與加密 vault 兩種模式，Go 送出的值與 Ansible 逐位元組相同；Go 拒絕的列記錄 Ansible 實際做了什麼（包括 `identity_admin_password` 在 inventory 時 Ansible 送的是 vault 的 admin 密碼）。
- Candidate `9c0e2772` 的 SHA 綁定 receipts：build、gofmt 與 `go vet`、golangci-lint（新程式碼 0 issues）、10 個套件的 `go test`、`cmd/pilot/cmd` 的 reconcile／identity lock／CI 一致性 selectors、`make identity-secret-test`。

## 未涵蓋

- 只在一個 FreeIPA 4.13.4 server、沒有 replica、一台 Ubuntu client 的拋棄式 lab 實跑；沒有任何正式環境。
- 只驗證 ansible-core 2.19.2（pilot-cli image 釘 `2.19.*`）；其他版本的 controller 沒有驗證。
- vars 檔裡字面上寫成單一 key 的 mapping `{__ansible_unsafe: x}`，在 `ansible-inventory --list` 裡與 `!unsafe x` 無法分辨，Go 會送 `x`，Ansible 送的是 JSON 物件（刻意模仿 Ansible 內部標記；與 #358 第 5 點同類）。沒有實跑。
- 範本以外的 roster 欄位與 run 的其他輸入（#397、#398）不在這個變更。
- kinit oracle 依賴 kinit 從非 terminal 的 stdin 讀密碼變更的回答；這一輪每個 arm 都以「錯誤的值失敗、正確的值成功」確認了它在這台 server 上成立。

## 秘密

- 所有密碼值（lab admin、vault 密碼、A23 的隨機值）都在執行時產生，只存在 repo 以外的 0600 檔案與 driver 的記憶體；這份 record 只寫名稱，不寫值。
- driver 的 `noValue` 掃描每個 A23 run 的輸出、結果檔與 pilot data 目錄（含 `ansible.log`），沒有找到值。
- 提交前以 `.agents/skills/_shared/scripts/secret_scan.py` 掃描 `90a2249b..HEAD` 每個 commit，並以 lab admin 與 vault 密碼作為已知秘密逐字比對：0 筆。
