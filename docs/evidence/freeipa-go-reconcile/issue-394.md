# Issue #394：Go engine 送出單一 `{{ name }}` 形式的 `password.initial`

Spec：`docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md` §7.8、D22、A15、A23、E51。程式碼：`internal/inventory`（`RosterRunVars.UserInitialPassword`、`RosterUserPasswords`、`passwordCaptureNames`）、`internal/identityreconcile`（`desired.go`、`plan.go`、`passwords.go`）、`cmd/pilot/cmd/reconcile_golang*.go`（`golangRunVars`）。

這是 #394 唯一的一份 record；新的 candidate 就地覆寫，被取代的版本留在 Git history（`docs/actual-run-evidence.md` §1）。

**狀態：PASS**，candidate `c58edf7e`：19 個 live arm 全部通過，0 skip。這個變更沒有改任何 playbook 或 contract（`git diff f9937741..c58edf7e -- playbooks contracts` 為空）；candidate 已合併 main `f9937741`，所以 arm 執行的是 main 的 identity playbook（PR #382 把使用者的憑證分到 `ipa_active_user_credentials`）。arm 以 pilot 的 Go engine 與 Ansible engine 對真實 FreeIPA server 執行。

## 目前的 candidate

| 項目 | 內容 |
|---|---|
| 測試的 candidate | `c58edf7e4c027e37ccd363b56b5d80eeafd62bfa`，tree `c2306ed5384e4207cfd707451295c82b3e72b1ce`，branch `issue/394-go-engine-password-template`（合併了 main `f9937741`）。從該 commit 的全新本機 clone 執行（`git status` 為空） |
| Target | 兩台拋棄式 `vm-target` VM：FreeIPA 4.13.4（`ipa-server-4.13.4-1.el9_9`，API 2.257，krb5 1.21.1-10.el9_9.2，389-ds-base 2.9.0-5.el9_9）on AlmaLinux 9.8（角色 `freeipa-server`），與 enroll 進它的 Ubuntu 24.04.4 client（`freeipa-client` 4.11.1-2、sssd 2.9.4-1.1ubuntu6.9、krb5 1.20.1，角色 `freeipa-client`）。lab 從 main `f9937741` 的 `git archive` 以 `pilot vm-target topology up` 建立，再以 `pilot deploy --component freeipa-server`、`--component freeipa-client` 部署（兩次都是 `failed=0`）；版本由操作者在 build 之後以 ssh 在 VM 上讀取（套件管理器與發行版的 release 檔），driver 的輸出裡沒有這些資訊；兩台都以 VM 自己的 key 用 root ssh 連線。每個 arm 開始前，兩台都回到同一組 enrolled 基準 snapshot，再由 A1 建立 acked 基準 |
| Workspace 與輸入 | repo 以外的拋棄式 workspace：`hosts.yml`（server 名稱為 `ipa1`、client 以 FQDN 命名並設 `ipa_client_fqdn`、絕對路徑的 `freeipa_roster_file`）經 `pilot inventory generate` 產生 `inventory.yml`；`.vault/main.yaml` 以 `ansible-vault` 加密，vault 密碼由 Ansible 從 `ANSIBLE_VAULT_PASSWORD_FILE` 讀取（環境模式）。lab 的 admin 密碼是隨機產生、存在 repo 以外的 0600 檔案。每個 arm 的 roster 與 vault 變數由 driver 寫入該 arm 的 workspace 複本；A23 的密碼值在執行時隨機產生，含空白、`0123`、反引號、`$HOME`、`%s`、CJK、單雙引號 |
| Controller 工具 | Go 1.26.8、ansible-core 2.19.2 |
| Harness | `TestLiveGoApplyDriver`（`internal/identityreconcile/live_apply_test.go` 與 `live_apply_lab_test.go`、`live_apply_arms_test.go`、`live_apply_arms3_test.go`），由 driver 從 candidate 自行 build 的 pilot binary 執行；arm 篩選 `A1 baseline,A15,A23`。driver 在 `bwrap --dev-bind / / --tmpfs /tmp --bind <lab 目錄> <lab 目錄> --ro-bind <ssh client 設定的複本> /etc/ssh` 裡執行：私有的 `/tmp`，以及內容與主機的 `/etc/ssh/ssh_config`、`ssh_config.d/*.conf` 相同（`diff` 為空）、但由執行者擁有的複本（原因見「失敗路徑」）；candidate 的原始碼沒有改 |
| 判定 | **PASS**：19／19 arm，0 skip，1064 秒 |
| 執行 | 2026-11-20 02:59:57–03:17:42 UTC；操作者：維護者工作站上的 coding agent |

影響執行的檔案（Git blob id、SHA-256 前綴）；其餘檔案由上面的 tree id 涵蓋。「與 `9c0e2772` 相同」指與前一個 candidate 的 blob 相同：

| 檔案 | Blob | SHA-256 | 與前一個 candidate |
|---|---|---|---|
| `cmd/pilot/cmd/reconcile_golang.go` | `4822cc70ab8c` | `d20024672e6ada0a` | 相同 |
| `cmd/pilot/cmd/reconcile_golang_apply.go` | `dc19799c6c3a` | `9aa3c0a1f8bc486b` | 相同 |
| `cmd/pilot/cmd/reconcile_golang_mixed.go` | `44b97cd4f4e8` | `9507d9f8bb63380e` | 相同 |
| `internal/identityreconcile/desired.go` | `11ab64a6c0d2` | `82347d4728e5def5` | 相同 |
| `internal/identityreconcile/passwords.go` | `dc3a089307c0` | `02b00d12bafb6f60` | 相同 |
| `internal/identityreconcile/plan.go` | `28a2b62ab18b` | `34bd008cb2d8b0d7` | 只有註解不同 |
| `internal/inventory/roster_playbook_names.go` | `cdc0d43cc0bf` | `76d09a9b64f5d5b6` | 相同 |
| `internal/inventory/roster_run_facts.go` | `4b93b0808b5d` | `047994612366dc4d` | 不同（`unsafe-marker` 拒絕） |
| `internal/inventory/roster_user_passwords.go` | `90973fbdcbba` | `eaabbbc43980d4cd` | 不同（`unsafe-marker` 原因碼與訊息） |
| `playbooks/apply/freeipa-identity-apply.yml`（main `f9937741` 的版本，本變更沒有改） | `548cb1a7ce8d` | `acba1de4d0ab9042` | 不同（PR #382） |
| `playbooks/apply/tasks/freeipa-identity-normalize-users-groups.yml`（未變更） | `c7787803979c` | `e34525e8ba2c0ed2` | 相同 |
| `internal/identityreconcile/live_apply_arms3_test.go` | `921ce7233e26` | `402370745475cf8d` | 不同（兩個新的 A23(e) 觸發） |
| `internal/identityreconcile/live_apply_arms_test.go` | `8448a069a08a` | `de6d4700cb027f29` | 相同 |
| `internal/identityreconcile/live_apply_test.go` | `d4a06dea4ddd` | `e7fb7ce99f1bd9fa` | 相同 |
| `internal/identityreconcile/live_apply_lab_test.go` | `479f7824732a` | `5da2d3440f490a67` | 相同 |

## 各 arm 的結果

一筆 run 寫成「結束碼、結果檔的 verdict、server 記到的寫入」。kinit oracle 只看結束碼：admin 設的初始密碼是已過期狀態，kinit 從 stdin 讀「初始密碼、新密碼、新密碼」，只有初始密碼正確才成功；每個用到它的 arm 都在同一次 run 裡先確認錯誤的值會失敗。

| Arm | 結果 | 秒 | 觀察到的事實 |
|---|---|---|---|
| A1 基準 | PASS | 222 | exit 0，`ok`，0 寫入；journal acked |
| A15 範本（`lookup` filter） | PASS | 19 | exit 3，`blocked`，0 寫入，沒有入口 |
| A15 inline `!vault` | PASS | 20 | exit 3，`blocked`，0 寫入，沒有入口 |
| A15 一般字串（對照） | PASS | 24 | exit 4，`unsettled`，`user_add` 1、`passwd` 1 |
| A15 未加引號的數字 | PASS | 19 | arm 斷言：exit 1，adapter 要求把密碼加上引號，沒有建立 tunnel 或登入（driver 的 summary 沒有這一筆 run 的結果檔與寫入數）；之後 journal 仍是 acked |
| A23(a) 單一 `{{ name }}`，值在加密的 vault | PASS | 23 | exit 4，`unsettled`；操作 2 個（`user.create`、`user.password.initialize`）；`user_add` 1、`passwd` 1；輸出、結果檔與 pilot data 目錄都沒有該值；錯誤的值 kinit 失敗、vault 的值 kinit 成功 |
| A23(c) 接著跑 Ansible engine 的完整 run | PASS | 135 | arm 斷言：exit 0；輸出中有 70 個 users／groups 區段的 task，沒有一個 changed；server 沒有 `passwd`、`user_add`（只證明沒有重設：`preserve_existing` 預設為 true，這一步不比較密碼值）；之後 journal acked |
| A23(b) 對照：同一個值直接寫在 roster | PASS | 23 | exit 4，`unsettled`，`user_add` 1、`passwd` 1；錯誤的值 kinit 失敗、正確的值 kinit 成功 |
| A23(d) 混合 run（`--scope full --force`） | PASS | 246 | exit 0，`ok`；`user_add` 1、`passwd` 1（另有 2 筆不屬於 Go plan 的 `user_mod`，arm 不斷言它們）；kinit 以 vault 的值成功、錯誤的值失敗；之後 Ansible engine 的完整 run 在 users／groups 區段沒有 changed、沒有 `passwd`；journal acked |
| A23(f) Ansible engine 以同一個範本建立第二位使用者 | PASS | 159 | arm 斷言：Ansible engine 的完整 run 建立 `p26-tpl2`，server 記到 1 筆 `passwd`；錯誤的值 kinit 失敗、vault 的值 kinit 成功。與 A23(a) 合起來，表示兩個 engine 從同一個範本設出同一個密碼；這一輪執行的是 main `f9937741` 的 playbook（`passwd` 迴圈走訪 `ipa_active_user_credentials`） |
| A23(e) 觸發：變數未定義 | PASS | 21 | exit 3，`blocked`，0 寫入，沒有入口 |
| A23(e) 觸發：空字串 | PASS | 19 | exit 3，`blocked`，0 寫入 |
| A23(e) 觸發：未加引號的數字 | PASS | 20 | exit 3，`blocked`，0 寫入 |
| A23(e) 觸發：inline `!vault` 的變數值 | PASS | 19 | exit 3，`blocked`，0 寫入 |
| A23(e) 觸發：filter | PASS | 18 | exit 3，`blocked`，0 寫入 |
| A23(e) 觸發：identity playbook 自己設定的名稱（`identity_admin_password`） | PASS | 19 | exit 3，`blocked`，0 寫入 |
| A23(e) 觸發：變數是字面的 `{__ansible_unsafe: ...}` mapping（加密的 vault） | PASS | 20 | exit 3，`blocked`，0 寫入，沒有入口 |
| A23(e) 觸發：變數是 `!unsafe` 字串（加密的 vault） | PASS | 19 | exit 3，`blocked`，0 寫入，沒有入口 |
| A23(e) 對照：沒有密碼操作的既有使用者引用未定義的變數 | PASS | 19 | exit 0，`ok`，0 寫入（沒有被擋） |

被擋下的 run 的訊息指名使用者、`password.initial`、原因與變數名稱，不含值（arm 斷言，並掃描輸出、結果檔與 data 目錄）；兩個 `__ansible_unsafe` 觸發另外斷言訊息含 `__ansible_unsafe` 與變數名稱 `ipa_default_initial_password`。

## 失敗路徑

- **這個 candidate 的前兩次執行（2026-11-20 02:53–02:58 UTC）都在 A1 失敗，原因在 harness 的環境，不在 pilot**：
  - 第一次直接在主機上執行：同一台主機上另一個 session 的 live driver 使用同一個寫死的 `PILOT_SSH_CONTROL_BASE`（`/tmp/p26cp`，`live_apply_test.go` 的 `cp` 欄位），而 `labEnv.rollback` 每次 rollback 都 `os.RemoveAll` 這個目錄，所以 A1 的 legacy apply 執行到一半時 ssh ControlPath 的目錄被刪（`unix_listener: cannot bind to path /tmp/p26cp/pilot-ssh-…: No such file or directory`），在 task `List existing IPA groups` 變成 unreachable，exit 1。反方向也成立：這次執行的 rollback 也可能刪掉另一個 driver 的目錄。
  - 第二次在 `bwrap` 的私有 `/tmp` 裡執行：user namespace 裡 root 擁有的 `/etc/ssh/ssh_config.d/*.conf` 顯示成 overflow uid，ssh 以 `Bad owner or permissions` 拒絕讀取，`vm-target rollback` 等待 SSH 失敗。
  - 第三次（上面的 PASS）在同樣的私有 `/tmp` 裡，把內容相同、由執行者擁有的 ssh client 設定複本以唯讀方式掛到 `/etc/ssh`。寫死的 control base 是 driver 的 test-hermeticity 問題，這個變更沒有修。
- **前一個 candidate `9c0e2772`（tree `a2c7a898`），2026-11-19 10:46–11:05 UTC**：A1、A15、A23 共 17／17 通過（那時 A23(e) 只有 6 個觸發）。它之後的 Go 差異是 merge gate 的修正（vars 端的 `__ansible_unsafe` marker 以 `unsafe-marker` 擋下）；這一輪的兩個新觸發與 A1、A15、A23(a)–(f) 在新的 candidate 上重跑。
- **更早的 candidate `a741c7d7`（tree `db8918e0`），2026-11-19 09:54–10:28 UTC**：54 個 arm 中 53 個通過。arm 篩選 `A1,A2,A15,A23` 以前綴比對，所以 A2、A2b、A10–A22、A16、A17(iii)(iv) 也一起跑了，全部通過。唯一的失敗是 A23(b)：arm 本身把 `yamlText(value)` 傳給 roster，引號與跳脫字元因此成了密碼的一部分；pilot 照 roster 的字面值送出，行為正確。修正在 `e44b5a71`，同一個 commit 新增 A23(f)。較廣的那批 arm 只跑在 `a741c7d7` 上。
- `ansible-inventory` 讀不到 run 的變數（例如 stderr 帶出 vault 內容的失敗）只有本機測試（假的 `ansible-inventory` 以執行時產生的 sentinel 寫 stderr，sentinel 沒有出現在任何輸出）；沒有在 VM 上製造。
- 沒有 `.vault/main.yaml` 的 workspace 會先被 inventory 完整性檢查拒絕（`vault: .vault/main.yaml: 不存在`），所以 `no-run-vars` 只在單元測試觸發。

## 本機（非 live）的證明

- Oracle `TestRosterUserPasswordValuesMatchAnsible`（`make identity-secret-test`）：真實 ansible-playbook 執行 identity playbook 的 pre_tasks 到 normalize include，dump `passwd` stdin 讀的值；Go 端用真實 `ansible-inventory --list -e @vault --playbook-dir` 解析。在 candidate `c58edf7e` 上，共用 run 有 64 列 × 明文與加密 vault 兩種模式（128 個子測試），另有 `TestRosterUserPasswordValuesInIsolatedRuns` 的 10 個子測試，全部通過、0 skip；Go 送出的列與 Ansible 逐位元組相同；Go 拒絕的列記錄 Ansible 實際做了什麼（字面的 `{__ansible_unsafe: x}` mapping 時 Ansible 送的是那個 dict 的 JSON，真正的 `!unsafe` 字串時送文字，Go 兩者都以 `unsafe-marker` 拒絕）。
- 真實 CLI 入口 `TestRosterPasswordReferenceThroughTheUnsafeMarkerBlocksTheRun`（真實 `ansible-inventory`／`ansible-vault`、假的 FreeIPA，明文與加密 vault）：exit 3、零寫入、零 playbook 呼叫、`password_value_unsupported`、輸出沒有值。
- 負向控制（`88c8e567` 與 `0a667597` 的 `git archive` 暫存複本，合併 main 之前；之後這些檔案的非測試程式碼沒有再改）：拿掉 `UserInitialPassword` 裡的 `unsafe-marker` 拒絕，oracle 的 marker 列與 CLI 測試都失敗（Go 送出、exit 4 且 server 收到 `user_add` 與 `passwd`）；把拒絕改放進共用的 `lookup`，`ServerDeclared`／`AdminPasswordProvided` 的測試失敗。
- Candidate `c58edf7e` 的本機 receipts：build、gofmt 與 `go vet`、golangci-lint（`--new-from-rev` main，0 issues）、`internal/inventory`、`internal/identityreconcile`、`internal/rosteroracletest` 的 `go test`、main 帶進來的 `internal/spec` 測試、`cmd/pilot/cmd` 的 reconcile／password-ref selectors、`make identity-secret-test`（0 skip）。

## 未涵蓋

- 只在一個 FreeIPA 4.13.4 server、沒有 replica、一台 Ubuntu client 的拋棄式 lab 實跑；沒有任何正式環境。
- 只驗證 ansible-core 2.19.2（pilot-cli image 釘 `2.19.*`）；其他版本的 controller 沒有驗證。
- driver 在私有 `/tmp` 與 ssh client 設定的複本裡執行（內容相同、擁有者不同）；主機上的 `/tmp` 沒有被這一輪使用。
- `ServerDeclared` 與 `AdminPasswordProvided`（#165 的事實）讀 marker 的行為沒有改：內層字串為空（`AdminPasswordProvided`）或空白（`ServerDeclared`）時與 Ansible 的判斷不同，記在 #358。
- 範本以外的 roster 欄位與 run 的其他輸入（#397、#398）不在這個變更。
- kinit oracle 依賴 kinit 從非 terminal 的 stdin 讀密碼變更的回答；這一輪每個 arm 都以「錯誤的值失敗、正確的值成功」確認了它在這台 server 上成立。

## 秘密

- 所有密碼值（lab admin、vault 密碼、A23 的隨機值）都在執行時產生，只存在 repo 以外的 0600 檔案與 driver 的記憶體；這份 record 只寫名稱，不寫值。
- driver 的 `noValue` 掃描 A23(a)、(d)、(f) 與 A23(e) 觸發的輸出、結果檔與 pilot data 目錄（含 `ansible.log`），沒有找到值；A23(c) 只檢查輸出沒有該值；A23(b) 的對照組不做掃描。
- 提交前以 `.agents/skills/_shared/scripts/secret_scan.py` 掃描 `f9937741..HEAD` 每個 commit，並以 lab admin 與 vault 密碼作為已知秘密逐字比對：0 筆。
