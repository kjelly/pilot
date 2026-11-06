# FreeIPA Go reconcile — Phase 1 唯讀 observer 與 planner 規格

日期：2026-10-30。對應計畫：`docs/superpowers/plans/2026-10-15-freeipa-go-ssh-reconcile.md` Phase 1。前一階段：`docs/superpowers/specs/2026-10-16-freeipa-go-reconcile-phase0-contract.md`（下稱 P0）。

狀態：已實作並實跑。入口與旗標、vault 與憑證、SSH 目標推導、stage gate、adapter、observer、planner、plan JSON、spec row 對應檢查都已實作；§9 的 K1–K5 已擷取並以 fixture 鎖住，沒有推翻本文件的決定；§10.3 driver 已對拋棄式 vm-target 實跑，目前有效的 candidate、tree、目標與各步驟結果見 [目前驗收紀錄](../../evidence/freeipa-go-reconcile/LATEST.md)。§10.4 剩 CI 的 `go test -race ./...`。

本文件不提供操作 SOP。文中的指令與旗標是要實作的介面，不是已實跑的步驟。

## 0 範圍

Phase 1 交付 users／groups 範圍的**唯讀預覽**：

- 本機 pilot 讀取 roster 與 inventory，經 Phase 0 的 SSH tunnel 與 JSON-RPC session 讀取 FreeIPA 現況，產生 plan，然後結束。
- 不送出任何 FreeIPA 寫入；不寫任何本機檔案（plan 輸出檔除外，見 §2.4）；不取 `/etc/ipa` 遠端鎖（計畫 §4 步驟 2「預覽不持鎖」）。
- 不改 `playbooks/apply/freeipa-identity-apply.yml`；不接 delivery history 與 webhook（計畫 Phase 4）。

不在 Phase 1：任何寫入、journal 與恢復、混合執行、#138 授權快取入口、取鎖閘門（計畫 Phase 2）。

## 1 決定總表

| # | 主題 | 決定 | 理由 |
|---|---|---|---|
| D1 | 入口 | `pilot reconcile --component freeipa-identity --preview-only --engine golang`（§2；2026-10-30 使用者決定名稱） | 計畫 Phase 4 要在既有 reconcile 入口加 engine 選擇。Go engine 處理的範圍會隨階段擴大，所以範圍不放進 engine 名稱，而是記在輸出與 plan 的 `scope`（Phase 1 為 `users-groups`） |
| D2 | 只有非互動入口 | `--engine` 不是預設值時，必須同時帶 `--preview-only`、剛好一個 `--component freeipa-identity`，不可帶 `--actions` | 互動 wizard 與 automation schema 不變（AGENTS.md §5.15 的 prompt 同步留給 Phase 4） |
| D3 | Ansible 預覽不執行 | 選 Go engine 時不跑 `--check --diff`；輸出標明 engine 與範圍 | 計畫要求 `--preview-only` 不能在不經 Go engine 的情況下被當成 Go 預覽通過 |
| D4 | roster 版本 | 接受 schema 1、2、3（與 playbook 相同）；沒有 `schema_version` 的 legacy roster 拒絕 | users／groups 的驗證三版相同（`validateRosterCommon`）；P0 矩陣已定 legacy 交舊 engine |
| D5 | 不 migrate roster | Go 預覽不呼叫 `ensureFreeIPARostersCurrent` | 它會改寫 roster 檔；D4 已接受舊版本，不需要升級 |
| D6 | vault | 四種模式見 §3；`--ask-vault-pass` 在 Phase 1 不可達 | 非互動預設值模式永遠不選 ask（§3） |
| D7 | 讀取者 | 登入帳號必須遞移屬於 `admins` 群組，否則在產生 plan 前失敗 | 非 admin 讀取者看到的欄位尚未擷取（計畫 Phase 1 find 讀取契約「尚未擷取」） |
| D8 | 相容語意 | 以 playbook 的實際行為為準，不以 P0 矩陣的措辭為準；差異見 §8 | Phase 2 退出條件要求混合 run 後舊 engine 全量重跑 users/groups 為 changed=0 |
| D9 | 比舊 engine 嚴格之處 | 列為 `blocked`，不靜默跟隨（§7.3） | 預覽階段誤擋的代價是操作者看到訊息；跟隨的代價是 Phase 2 寫錯 |
| D10 | 寫入在程式上不可能 | 預覽使用的 `freeiparpc.Client` 以唯讀模式建立，寫入方法在送出前於本機拒絕（§6.1） | 「讀取無 mutation」要由結構保證，不只由測試抽樣 |
| D11 | plan 不授權 mutation | plan 帶 desired revision、目標與 observation fingerprint；Phase 2 套用時一律重讀重算（計畫 §4 步驟 4） | 舊快照只能用於預覽 |
| D12 | 「已套用」對照 | 舊 engine 套用後，Go plan 的寫入操作數必須為 0（§10.3） | 在沒有 Go 寫入之前，用舊 engine 驗證 Go 對 desired state 的解讀 |

## 2 入口

### 2.1 旗標

- `--engine`：`ansible`（預設，現有行為）或 `golang`。
- `--plan-out <path>`：只在 `--engine golang` 時有效；把 plan JSON（§7.5）寫到這個路徑。路徑在入口處正規化一次（AGENTS.md §5.11）；檔案以 `0600` 建立，已存在時拒絕覆寫；上層目錄必須已存在（pilot 不建立目錄），入口處就檢查，不是整輪讀完才在寫檔時發現（只檢查存在，不檢查可寫；檔案另以 `O_EXCL` 建立，檢查之後才出現的檔案不會被取代）。

拒絕的組合（在讀 inventory、vault 或建立任何連線之前）：

| 組合 | 錯誤 |
|---|---|
| `--engine golang` 沒有 `--preview-only` | Phase 1 只提供預覽 |
| 同時有 `--force` | 同上 |
| `--component` 不是剛好一個 `freeipa-identity` | Go engine 只處理 identity 的 users／groups |
| 有 `--actions` | D2 |
| `--plan-out` 但 engine 不是 `golang` | 旗標無效 |

`--stage`、`--staging-attested-within-hours`、`--limit`、`--timeout`、`--dir`、`-i` 沿用現有語意。`--timeout` 是 Go 預覽整輪的期限（`ansible-inventory`、`ansible --list-hosts`、`ansible-vault`、SSH 與 FreeIPA 讀取合計）；Ansible engine 的 `--timeout` 則是每次 `ansible-playbook` 呼叫各自的上限，`--help` 兩種都寫明。子行程在期限或訊號時如何結束見 §2.5。

### 2.2 執行順序

每一步失敗都結束，不往下做。步驟 1–6 不建立任何 SSH 連線。

1. 旗標檢查（§2.1）。
2. 解析 inventory：沿用 reconcile 的 inventory 解析與 `--limit`，以 `ansible-inventory --list` 取得 hostvars（`resolveInventoryVariables`），用 `freeipa-server` 角色解析出主機；contract `hostCardinality: exactly-one`，不是剛好一台就失敗。沿用 `validateDeploymentCompleteness`（不寫檔）。同目錄的 `hosts.yml` 產生出的 inventory 與 `inventory.yml` 不同時失敗：Ansible engine 在這裡會重新產生 inventory，唯讀預覽不寫檔，請操作者先執行 `pilot inventory generate`。
3. stage gate：與 playbook 的三道 assert 等價（AGENTS.md §4.3）。主機在 `prod` group 但 stage 不是 prod、在 `staging` group 但 stage 不是 staging、stage 是 staging/prod 但主機不在該 group，都拒絕；staging／prod 需要確認（沿用 `--stage` 的現有語意：在指令列指定即視為確認）；prod 另需 attestation ≤ 168 小時。以一致性測試鎖住 Go 判斷與 playbook assert 的條件集合相同（AGENTS.md §5.7）；若可行，重用 `internal/decommission` 的 `StageScope` 依主機 group 推導 stage 的邏輯。
4. 載入 roster：路徑取自該主機 hostvars 的 `freeipa_roster_file`，相對路徑相對於 workspace（與 `deploy_completeness.go` 相同）；未設定即失敗（playbook 在這種情況也以「roster 沒有任何資料」gate 失敗）。加密 roster 依 §3 解密，只在記憶體。以 `inventory.ValidateRoster` 驗證，再做 §5 的 adapter 檢查。
5. admin 憑證：§3。
6. SSH 目標推導：§4。
7. 建立 tunnel、讀 FQDN 與 CA、登入、`CheckServer`（Phase 0 的 API 版本檢查）。
8. 讀取現況（§6），完整性與讀取者檢查。
9. 規劃（§7），輸出結果，`session_logout`，關閉 tunnel。

### 2.3 結束碼與結果

| 結果 | 結束碼 | 條件 |
|---|---|---|
| `ok` | 0 | 讀取完整、plan 已產生、沒有 `blocked` 項目；寫入操作可為任意數量（這是預覽） |
| `blocked` | 非 0 | plan 已產生，但有 `blocked` 項目（§7.3） |
| `failed` | 非 0 | 步驟 1–8 任一失敗；不產生 plan |

`blocked` 的結束碼是 3，`failed` 是 1（`reconcile_golang.go` 的 `golangPreviewBlockedExitCode`，以測試鎖住）。除了產生出的 blocked plan，每個失敗都以 1 結束：子行程（`ansible-inventory`、`ansible --list-hosts`、`ansible-vault`）的結束碼不傳遞。包著子行程 `*exec.ExitError` 的錯誤本身滿足 `ExitCoder`，原樣回傳會讓 pilot 以 ansible 的 3 或 4 結束，3 會被誤讀成「blocked」卻沒有 plan；所以 `--engine golang` 的非 blocked 失敗一律包成結束碼 1 的錯誤，`errors.Is` 仍可經 `Unwrap` 到達內層 sentinel（`ErrNoVaultSecret`、`context.DeadlineExceeded` 等）。其他指令的結束碼不在這份規格的範圍。

### 2.4 輸出

- 終端機：engine、範圍、目標、FreeIPA 版本、每類操作的數量、`blocked` 與報告項目、讀取統計（`freeiparpc.Stats`）。不印屬性值以外的 diff 細節（細節在 plan JSON）。
- `--plan-out`：§7.5 的 JSON，只在 `ok` 或 `blocked` 時寫出。失敗的預覽不印預覽、不寫 plan；包含預覽送出了任何寫入（`stats.writes` 不為 0，內部錯誤）的情形：這個檢查在印出與寫檔之前。
- 密碼、session cookie、vault 密碼不出現在任何輸出、錯誤訊息、log 或 plan（P0 §4「秘密不外洩」）。

### 2.5 子行程

Go 預覽只啟動 `ansible-inventory --list`、`ansible <pattern> --list-hosts`、`ansible-vault view`（每個加密檔一次）、`ssh … hostname -f`、`ssh … cat /etc/ipa/ca.crt`、每條連線一個 `ssh -W 127.0.0.1:443`（登入後的 session_logout 在取消後也會用一條新的）。它們都由 `internal/childproc.Isolate` 在新的 session（沒有 controlling terminal，stdin 是 `/dev/null`）執行。`exec.CommandContext` 只殺直接的子行程，`Wait` 再讀輸出管線直到 EOF：子行程啟動的行程只要繼承了管線，就能讓 `Wait` 等到它自己結束為止；下面的規則就是為了不讓這件事發生。

- 子行程啟動的行程留在同一個 process group：`ANSIBLE_VAULT_PASSWORD_FILE` 的 vault password client script（`ansible-inventory`、`ansible`、`ansible-vault` 三種指令啟動時都會執行它，並讓它繼承 stderr）、ProxyJump 的跳板 ssh、ssh_config 的 ProxyCommand。
- `--timeout` 到期，或收到 SIGINT／SIGTERM／SIGHUP（SIGHUP 在啟動時已被忽略，例如 nohup，就不接）時：對每個執行中子行程的 process group 送 SIGKILL，輸出管線最多再等 2 秒（`childproc.WaitDelay`）。錯誤包著 `context.DeadlineExceeded`／`context.Canceled`（並保留子行程的 `*exec.ExitError`），結束碼 1，不產生 plan，不建立任何連線（步驟 7 之前）。`ansible --list-hosts` 被取消時不會被當成「沒有主機」：context 結束先於 §2.2 步驟 2 對「leaves us with no hosts to target」的正規化。
- 子行程以 0 結束，但它啟動的行程握著輸出管線超過 2 秒：該步驟失敗（`childproc.ErrHelperKeptOutput`、`exec.ErrWaitDelay`），不使用已讀到的輸出，那可能只是一部分。例外：tunnel 的資料走直接的 fd，只有 stderr 被握著，`ssh -W` 以 0 結束時視為連線結束（server 關閉連線）。
- 離開 process group 的行程（`setsid`、daemon）殺不到；它握著管線時，等待由 2 秒的 `WaitDelay` 界定，行程本身留下。
- 每條 tunnel 的 `ssh -W`（以及讀 FQDN、CA 的 ssh）由 `sshdial.Dialer` 記錄到被回收為止。預覽回傳前（最後執行的 defer，排在登出與 `client.CloseIdleConnections()` 之後）呼叫 `Dialer.Close()`：對還沒被回收的每個 ssh 的 process group 送 SIGKILL，等到每個都被回收才回傳（離開 group 的行程握著 stderr 時最多再 2 秒），之後 dialer 不再啟動 ssh（`sshdial.ErrDialerClosed`）。所以預覽回傳時它啟動的 ssh 都已結束並被回收，包括 server 不回應、net/http 還在自己的 goroutine 裡做 TLS handshake 的連線（登入被取消時、登出放棄後）。`CloseIdleConnections` 只讓 idle 連線以 TLS close_notify 正常關閉；它對進行中的 dial 只取消 context、不等待，不是這個保證的來源。
- 範圍：只有 Go 預覽這樣執行。`deployAnsibleCommand` 只在 context 帶有 Go 預覽設的標記（`withIsolatedChildren`，與 SIGINT／SIGTERM／SIGHUP 的處理放在同一個 `signal.NotifyContext`）時才套用 `childproc.Isolate`；Ansible engine、`pilot deploy` 與其他指令的命令不變，仍留在 pilot 的 process group，終端機的訊號照樣送到它們的子行程。這些路徑有同類的風險（子行程啟動的行程握著管線時 `Wait` 不返回），不在這份規格的範圍，另案處理。

已知限制：

1. 上面第三點的行程不會被殺：子行程已被回收，對它的 process group 送訊號可能打到重用同一個 id 的無關行程（`kill()` 對已回收的 ssh 也不送訊號）。
2. 子行程收不到終端機送給 pilot 的訊號，由 pilot 殺掉它們。SIGKILL、SIGQUIT（Ctrl-\）或殺掉 pilot 的 process group 時 pilot 來不及殺，它們留到自己結束：`ansible` 到它的 vault script 結束，`ssh` 到 stdin 關閉且 server 回應。
3. 第二次 Ctrl-C 立即結束 pilot（第一次訊號後預設處理已恢復），這時還在進行的登出用的 `ssh -W` 等伺服器回應或關閉才結束（`Dialer.Close` 不會執行）。
4. 需要 terminal 輸入的 vault password client script，以及需要輸入密碼或確認 host key 的 ProxyJump 跳板（OpenSSH 不把 BatchMode 傳給跳板），在沒有 terminal 的 session 裡 fail closed：在 `ansible-inventory` 或 `ssh` 這一步失敗，不提示。

## 3 憑證與 vault

admin 帳號與密碼的來源與 playbook 的「Normalize canonical FreeIPA settings」相同：

- principal：roster `freeipa.admin.principal`，預設 `admin`。
- 密碼：vault vars 檔的 `ipa_admin_password`；未定義或空字串時改用 roster 的 `freeipa.admin.password`；結果長度至少 8（playbook 的「Gate: admin credential present」）。

vars 檔沿用 `promptVault` 在預設值模式下的選擇：`<inventory 目錄>/.vault/main.yaml` 存在就用它，否則沒有 vars 檔。四種模式：

| 模式 | 如何進入 | Go 的讀法 |
|---|---|---|
| 明文 vars 檔 | `.vault/main.yaml` 未加密 | 直接解析 YAML |
| 指定密碼檔 | Phase 1 不可達（預設值模式不會填密碼檔路徑），保留給 Phase 4 | `inventory.ViewEncryptedRoster`，只在記憶體 |
| 環境密碼來源 | `.vault/main.yaml` 已加密；預設值模式選「密碼檔」但路徑為空，現有入口因此不傳 `--vault-password-file` | 執行 `ansible-vault view` 且**不帶** `--vault-password-file`，讓 Ansible 自己讀 `ANSIBLE_VAULT_PASSWORD_FILE` 或 ansible.cfg；env 與工作目錄要和同一次 reconcile 執行 ansible-playbook 時相同（`prepareDeployAnsibleRuntime` 的 env），密碼來源的解析才一致。新增明確的 ambient 模式函式 `inventory.ViewVaultFileAmbient`，不改 `ViewEncryptedRoster` 對既有呼叫者的語意。沒有任何密碼來源時 `ansible-vault view` 會**提示輸入密碼**（K5 擷取），與 ansible-playbook 直接失敗不同。提示走 Python getpass：有 controlling terminal 時它直接開 `/dev/tty` 提示並等人輸入，沒有 terminal 才讀 stdin，所以只關閉 stdin 不夠（在終端機上執行會卡在提示）。`ViewVaultFileAmbient` 因此在**新的 session**（`Setsid`，沒有 controlling terminal）執行 `ansible-vault`，stdin 是 `/dev/null`：提示讀到 EOF，以 EOFError 結束，分類為「沒有設定 vault 密碼來源」。`ansible-vault` 與其他子行程一樣依 §2.5 執行與結束。需要 terminal 才能取得密碼的 vault password client script 在 Go preview 不支援，同樣 fail closed（`ansible-inventory`、`ansible` 執行它時也一樣，§2.5）。pilot 的 root context（`rootCmd.Execute()` 用 `context.Background()`）沒有接 SIGINT／SIGTERM，Go preview 在執行期間自己接：`signal.NotifyContext(SIGINT, SIGTERM, SIGHUP)`（SIGHUP 在啟動時已被忽略就不接），只在 `--engine golang`（Ansible engine 與其他指令不變，因為它們的 handler 不全部看 context，見 `withServiceCommandSignals`）。第一次訊號與 `--timeout` 一樣取消 context：執行中的子行程連同它們啟動的行程被殺掉（§2.5）、不再建立連線，已登入的 session 以不被取消、最多 10 秒的 context 送出 `session_logout`；取消後立即恢復預設處理，所以第二次 Ctrl-C 直接結束 pilot，不等 logout（§2.5 已知限制 3）。每個子行程都在自己的 session，收不到終端機對 pilot 的訊號（Ctrl-C、終端機關閉），由 pilot 殺掉；所以 Go preview 也接 SIGHUP |
| `--ask-vault-pass` | Phase 1 不可達 | Phase 4 加互動入口時再定；要求不變：在建立 tunnel 前完成，vault 密碼不進 argv、環境或暫存檔 |

加密的 roster 用同一個模式解密。

值的形態：`ipa_admin_password` 與 `freeipa.admin.password` 只接受一般字串 scalar。Jinja 模板、inline `!vault`、非字串一律在建立 tunnel 前失敗，訊息說明 Go engine 不展開 Ansible 模板。判斷重用 `internal/inventory` 的 `ansibleScalarKind`，不另寫一套（AGENTS.md §5.7）。

密碼只存在 pilot process 記憶體與 TLS 內的 POST body；不進 argv、環境、plan、log 或暫存檔（計畫 §3）。

## 4 SSH 目標推導

由步驟 2 的那一台主機的 hostvars 推導 `sshdial.Target`：

| hostvar | Target 欄位 | 規則 |
|---|---|---|
| `ansible_host`（未設定時用 inventory 名稱） | `Host` | `ansible_host` 是連線位址，不是身分（AGENTS.md §5.13） |
| `ansible_port` | `Port` | 整數 |
| `ansible_user` | `User` | — |
| `ansible_ssh_private_key_file` | `IdentityFile` | — |
| `ansible_ssh_common_args`、`ansible_ssh_extra_args` | `Options` | 只接受 `-o Key=Value`，且 key 在 `sshdial` 的 `allowedOptions` 內；其他任何內容拒絕 |
| `ansible_connection` | — | 只接受未設定或 `ssh`；`docker`、`local` 等拒絕 |
| `ansible_ssh_args` | — | 只接受 `ControlMaster`、`ControlPath`、`ControlPersist`（vm-target 的 inventory 帶這三項），不採用：tunnel 自己管理連線重用（計畫 §3）；其他選項拒絕 |
| `ansible_ssh_host`、`ansible_ssh_port`、`ansible_ssh_user`、`ansible_private_key_file`、`ansible_ssh_executable`、`ansible_ssh_password` | — | 舊名稱或改變 ssh 程式的設定，有設定就拒絕 |
| `ansible_ssh_pipelining` 等其他變數 | — | 不影響 SSH 連線本身，忽略 |
| `ansible_password`、`ansible_ssh_pass` | — | 有設定就拒絕（Go 不做密碼 SSH） |

拒絕在建立任何連線前發生，訊息指出是哪個 hostvar；不默默忽略（計畫 §3）。`ansible_host`、`ansible_user`、`ansible_ssh_private_key_file` 存在時必須是字串，其他型別（整數、布林、清單）一律拒絕，不轉成字串也不忽略：被忽略的 `ansible_user: 1000` 會以本機使用者連線，`ansible_host` 被忽略會連到 inventory 名稱。未設定與 `null` 視為未設定，空字串的 `ansible_host` 沿用 inventory 名稱；`ansible_port` 可為整數或十進位字串。FreeIPA server 的 FQDN 由 `sshdial.Dialer.FQDN`（遠端 `hostname -f`，與 playbook 補 `freeipa.server` 的方式相同）讀取；roster 有 `freeipa.server` 時兩者必須相同（大小寫不敏感），否則失敗；`freeipa.server` 存在時必須是字串，`freeipa` 與 `freeipa.admin` 存在時必須是 mapping（未設定與 `null` 視為未設定）：roster validator 不檢查這些型別，被忽略的 `freeipa.server: 123` 會略過這道比對，被忽略的 `admin: bob` 會以預設的 `admin` 登入。這些在建立 tunnel 之前拒絕。

## 5 desired state（roster adapter）

新增 `internal/identityreconcile`。adapter 把通過 `ValidateRoster` 的 roster 轉成型別明確的 desired state。

### 5.1 使用者

只處理 `state` 不是 `absent` 的使用者（playbook 的「Select active identity objects」）；`absent` 的使用者進入刪除（§7.1）。

| roster | FreeIPA 屬性 | desired 值（與 playbook「Normalize canonical users」相同） | 比較 |
|---|---|---|---|
| `first` | `givenname` | 預設為 `name` | 一律比較 |
| `last` | `sn` | 預設為 `name` | 一律比較 |
| `display_name` | `displayname` | 未宣告不管理 | 宣告時比較；不清除 |
| `email` | `mail` | 未宣告不管理 | 宣告時：live 的整組 `mail` 必須剛好等於 `{email}`（FreeIPA 自動產生 `<uid>@<domain>`，且可有多個值，2026-10-27 擷取） |
| `uid` | `uidnumber` | 未宣告不管理 | 宣告時比較十進位字串；不同即 `blocked`（§7.3） |
| `gid` | `gidnumber` | 未宣告不管理 | 同上 |
| `login_shell` | `loginshell` | 預設 `/bin/bash` | 一律比較 |
| `home_directory` | `homedirectory` | 預設 `/home/<name>` | 一律比較 |
| `enabled`／`state` | `nsaccountlock` | `enabled` 預設為 `state != disabled` | live 的 `nsaccountlock` 為布林（擷取） |
| `password.initial` | — | desired state 只保留「有沒有宣告」，**不載入密碼值** | 決定密碼動作（§7.1） |
| `password.preserve_existing` | — | 預設 true（`force_change` 不影響動作，與 Phase −1 決定相同） | 同上 |
| `ssh_keys.values` | `ipasshpubkey` | 未宣告不管理；空清單代表清除 | 只報告（§7.4） |

FreeIPA 以小寫儲存名稱；比較使用者與群組名稱一律轉小寫（AGENTS.md §5.13）。

Go 比 playbook 嚴格的輸入檢查（在建立 tunnel 前失敗）：

- `enabled`、`password.*`、`membership.authoritative` 若存在必須是 YAML 布林。playbook 以 `| bool` 接受 `"yes"` 等字串，Go 的 validator 則忽略非布林值（`boolFieldDefault`），兩者不一致；Go engine 不重做 Ansible 的轉換規則。
- `uid`、`gid` 若存在必須是非負整數。
- `first`、`last`、`display_name`、`email`、`login_shell`、`home_directory` 若存在必須是字串。
- `password`、`ssh_keys`（使用者）與 `membership`（群組）若存在必須是 mapping，`null`（包括只寫了鍵名、後面留空的 `membership:`）也拒絕；不寫與 `{}` 視為未宣告。原因：playbook 的 gate `(item.X | default({})).keys()` 對 `null` 與其他非 mapping 值同樣失敗（`default()` 取代未定義的值，不取代 `null`；ansible-core 2.19.2 實測），Go 若把 `null` 當成未宣告，空的 `membership:` 會變成 authoritative 且沒有成員的群組，Ansible engine 卻拒絕同一份 roster；`freeipa`、`freeipa.admin` 不在此列，`null` 仍視為未設定。這些 mapping 裡的 `membership.users`、`membership.groups`、`membership.authoritative`、`ssh_keys.values`、`ssh_keys.authoritative`、`password.preserve_existing`、`password.force_change` 若存在也不可為 `null`（Go 否則會套用自己的預設值）；訊息指出欄位與物件，並說「not null」，請省略該鍵或給值。playbook 對這些 `null` 的讀法不一致（ansible-core 2.19.2，同一批運算式實測）：`membership.authoritative: ~` 在 `apply.yml:1600` 的 `| default(true) | bool` 變成 false，不撤銷成員，Go 卻會撤銷；`membership.users: ~` 的移除集合與不寫相同、之後在 `:1662` 的 `subelements` 失敗（「先在 `:1635` 撤銷成員、再失敗」是從 task 順序推得，沒有實際執行移除 task，只重播了運算式）；`membership.groups: ~` 在 `:427` 的 gate 失敗；`ssh_keys.authoritative: ~` 與兩個 password 旗標在 `:391`/`:386`/`:387` 的 gate 失敗；`ssh_keys.values: ~` 與不寫相同（不管理金鑰），但與 `values: []`（清除全部）容易混淆，所以也拒絕。`password.initial: ~` 仍接受，等於沒有 initial password（`:1214` 的 `rejectattr('password', 'none')` 把它排除，兩個 engine 一致）。比 playbook 更嚴格是允許的（本節開頭）。`password.initial` 若存在且不是 `null` 必須是字串（只檢查型別，值不載入）；`ssh_keys.authoritative` 若存在必須是布林，且必須是 true；`users`、`groups` 若存在必須是 list（`null` 也拒絕：playbook 的 `loop` 會以「must resolve to a 'list', not 'NoneType'」失敗；不寫或 `[]` 才是空），每個元素必須是 `name` 為字串的 mapping。使用者的 `state`、`enabled`、`first`、`last`、`login_shell`、`home_directory` 與群組的 `state`、`type`、`description` 若存在也不可為 `null`（不寫才是預設）：playbook 讀 `null` 的方式與 Go 的預設值不同（`enabled: ~` 在 `:1697` 的 `| default(true) | bool` 是 false，playbook 會 `ipa user-disable`，Go 讀成 enabled；`first`/`last`/`description` 變成 `--first=None` 等；`state`、`type` 在 `:374`/`:412`/`:414` 的 gate 失敗；`login_shell`、`home_directory` 不送參數）。`freeipa.admin.principal: ~` 同樣拒絕（playbook 的 `principal | default('admin')` 保留 None，kinit 會用 `None@REALM`；不寫才是 `admin`）。使用者的 `uid`、`gid`、`display_name`、`email` 與群組的 `gid` 是 Go 不管理的欄位：`null` 與不寫相同，都是不管理，所以接受（playbook 在 `:1006`、`:1128`–`:1134` 以 `is none` 略過兩者的參數；`pilot edit` 的 roster 精靈對空白的整數欄位寫 `null`；`freeipa-identity.roster.example.yaml` 也寫 `uid: null`，拒絕它會拒絕 pilot 自己產生與提供的 roster）。判斷準則：Go 套用自己的預設值的鍵，playbook 對 `null` 的讀法若不同就拒絕；Go 不管理的鍵，`null` 就是不管理。程式裡以兩組 helper 分開（`stringOr`/`boolOr` 拒絕 `null`，`unmanagedString`/`unmanagedID` 接受），新增的鍵必須選一邊。`state: absent` 的項目不被 reconcile，但 playbook 的 gate 對每個項目（包括 absent）都對 `password`、`ssh_keys`、`membership` 呼叫 `.keys()`，所以 Go 也檢查 absent 項目這三個鍵的型別（只檢查型別，裡面的內容不讀）。roster validator 不檢查這些型別（`mapField` 對型別不符回傳 nil，`boolFieldDefault` 對非布林回傳預設值），以前型別錯誤的值被當成「未宣告」：`membership: [alice]` 變成 authoritative 且沒有成員的群組（§5.2），預覽把撤銷所有直接成員當成計畫。錯誤訊息指出欄位與 roster 物件（`users[1] (bob): password must be a mapping, not string`），只寫型別、不寫值（issue #273）。`ValidateRoster` 本身未改：它是 Ansible engine 的入口，改它之前要先對 playbook 的同一個輸入實跑擷取（AGENTS.md §5.6）。

### 5.2 群組

只處理 `state` 不是 `absent` 的群組；`absent` 進入刪除。

| roster | FreeIPA | desired 值 | 比較 |
|---|---|---|---|
| `description` | `description` | 預設為 `name`（playbook 的 `desc`） | 一律比較 |
| `gid` | `gidnumber` | 未宣告不管理 | 宣告時比較；不同即 `blocked` |
| `type` | `objectclass`（§6.3） | 預設 `posix` | 不同即 `blocked`；`external` 一律 `blocked`（§7.3） |
| `membership.authoritative` | — | 預設 true | 決定是否撤銷 |
| `membership.users` | `member_user` | 未宣告視為空集合 | 直接成員 |
| `membership.groups` | `member_group` | 未宣告視為空集合 | 直接成員 |
| `category` | — | 不送到 FreeIPA | 不比較 |

**注意（playbook 現行語意，Go 必須相同）**：`authoritative` 預設 true，且未宣告的 `membership.users`／`groups` 等於空集合，所以 roster 裡沒有 `membership` 區塊的群組，其所有直接成員都會被撤銷，包含不在 roster 裡的使用者（「Compute stale canonical group membership」以 `membership.users | default([])` 計算）。這與計畫 §4「欄位未宣告與宣告空集合分開處理」的一般原則不同；改變它是 roster 語意變更，不在本計畫範圍。plan 對這種群組另列一筆報告，讓操作者看得到。

### 5.3 不在範圍的 roster 內容

`hosts`、`hostgroups`、`netgroups`、HBAC、sudo、NFS、grants、`auth_policies`、`account_policies`、`password_policies`、privileged identity、credential policies，以及使用者的 `authentication`：plan 在 `not_in_scope` 列出 roster 中出現的項目，不阻擋預覽。它們由舊 engine 處理（P0 §3「不在 Phase 2 範圍」）。

## 6 observer

### 6.1 唯讀客戶端

`freeiparpc` 新增唯讀模式（例如 `Config.ReadOnly`）：allowlist 中標為 write 的方法，以及含任何寫入的 batch，在送出前於本機以 `ErrMethodNotAllowed` 拒絕。Go 預覽一律以唯讀模式建立客戶端。測試：

- 唯讀模式下呼叫每一個寫入方法都被拒絕，fake server 沒有收到任何請求。
- 整條預覽路徑（cobra 指令到 observer）結束後 `Stats.Writes == 0`。

### 6.2 讀取

| 讀取 | 用途 |
|---|---|
| `user_find`，`all: true` | 使用者屬性、`nsaccountlock`、密碼狀態、SSH key、讀取者檢查（`memberof_group`） |
| `user_find`，`all: true`、`preserved: true` | 找出與 roster 同名的 preserved 使用者。K1：預設讀取不列 preserved 使用者，這次讀取只列 preserved 使用者，每筆 `preserved: true`、`nsaccountlock: true`、沒有 `memberof_group` |
| `group_find`，`all: true` | 群組屬性、type、直接成員、history marker |

`Find` 已帶 `sizelimit=0`、`timelimit=0`，`truncated` 或 count 不符即失敗（P0 §2）。K3：`sizelimit=0` 不受 FreeIPA 的 `ipasearchrecordslimit` 限制；389-ds 的 `nsslapd-sizelimit` 或 `nsslapd-lookthroughlimit` 低於資料量時，`user_find` 回 `truncated: true`，`group_find` 回 `SizeLimitExceeded`／`AdminLimitExceeded` 錯誤，都不會靜默少回，所以不需要分段讀取。observer 一律帶 `all: true`；測試的 fake server 要斷言收到的選項，不只依 method 回 fixture（計畫 Phase 1 find 讀取契約）。

### 6.3 判讀規則

- 直接成員只讀 `group_find` 的 `member_user`、`member_group`；不讀 `user_find` 的 `memberof_group`（遞移，2026-10-27 擷取）。
- 缺少成員屬性代表空集合，前提是讀取完整且讀取者已通過 D7；否則失敗（計畫 §4「未知欄位不可當成空值」）。
- 群組 type：`objectclass` 含 `posixgroup` 為 posix；與擷取到的 nonposix 集合（`top`、`groupofnames`、`nestedgroup`、`ipausergroup`、`ipaobject`）相同為 nonposix；其他組合為「未辨識」。roster 宣告的群組 live type 未辨識時 `blocked`。external 群組（K2：nonposix 集合加 `ipaexternalgroup`）在 Phase 1 也落在「未辨識」。
- 讀取者（D7）：以登入帳號名稱在 `user_find` 結果中找到該使用者，`memberof_group` 必須含 `admins`；找不到或不含即失敗。K4：不加篩選的讀取中 admin 的 `memberof_group` 含 `admins`（admin 沒有 `givenname`）。
- history marker：`group_find` 的結果中，名稱為 `pilot-internal-history-g-<sha256>` 的群組。名稱的 hash 輸入與 `tasks/freeipa-group-history-marker.yml` 相同（roster 中的 `name` 原字串，不轉小寫），以 Jinja `hash('sha256')` 的實際輸出鎖住大小寫混合名稱的案例。
- 只有 roster 列出的使用者與群組是 managed 物件；其他物件不出現在操作中（membership 撤銷除外，見 §5.2）。

### 6.4 SSH key 正規化

與 #138 helper（`playbooks/apply/files/freeipa-ssh-key-cache.py` 的 `keyset`）相同：取「類型 + base64 本體」，忽略註解，檢查 wire format 的演算法字串與類型一致。以一致性測試對同一組輸入比對 Go 與 helper 的輸出（AGENTS.md §5.7）。

## 7 planner

### 7.1 操作種類

| 種類 | RPC（Phase 2） | 條件 | destructive |
|---|---|---|---|
| `group.create` | `group_add` | roster 群組不存在 | 否 |
| `group.update` | `group_mod` | `description` 不同 | 否 |
| `group.marker.create` | `group_add`（nonposix） | 套用中或要刪除的群組沒有 marker | 否 |
| `user.create` | `user_add` | roster 使用者不存在 | 否 |
| `user.update` | `user_mod` | §5.1「比較」欄任一欄位不同；只帶不同的欄位 | 否 |
| `user.password.initialize` | `passwd` | 有 `password.initial`，且沒有 `krblastpwdchange`（含本輪新建者） | 否 |
| `user.password.reset` | `passwd` | 有 `password.initial`、`preserve_existing: false`，且使用者不在上次重設的密碼上（`krbpasswordexpiration` 存在且 `<= krblastpwdchange` 才算仍在重設的密碼上） | 是 |
| `group.member_user.remove`、`group.member_group.remove` | `group_remove_member` | authoritative 且 live 直接成員不在宣告集合中；每個群組每種成員一筆，合併所有成員 | 否 |
| `group.member_user.add`、`group.member_group.add` | `group_add_member` | 宣告的直接成員不在 live；同上合併 | 否 |
| `user.enable`／`user.disable` | `user_enable`／`user_disable` | `nsaccountlock` 與宣告不同 | 否 |
| `user.delete` | `user_del`（不帶 preserve） | `state: absent` 且 live 存在 | 是 |
| `group.delete` | `group_del` | `state: absent` 且 live 存在；marker 必須存在且描述正確 | 是 |

密碼條件與 Phase −1 的決定、playbook 的「Decide the password action for each user」相同；時間戳為 `YYYYMMDDHHMMSSZ`，字串比較即可（擷取）。plan 不含密碼值。

### 7.2 順序與依賴

依 playbook 的順序產生，同種類內依小寫名稱排序，結果穩定：

1. `group.create`、`group.update`、`group.marker.create`
2. `user.create`、`user.update`
3. `user.password.*`
4. 成員撤銷（使用者、群組），再成員新增（使用者、群組）
5. `user.enable`／`user.disable`
6. `user.delete`，再 `group.delete`（刪除群組前先確保 marker）

每個操作列出它依賴的操作 ID（例如加成員依賴該使用者與群組的 create）。Phase 1 不決定 batch 邊界；依賴是給 Phase 2 executor 的輸入。

### 7.3 blocked

下列情形不產生操作，改列為 `blocked`，預覽結果為 `blocked`（§2.3）：

| 原因 | 說明 |
|---|---|
| `uid_or_gid_change` | 使用者 `uidnumber`／`gidnumber`、群組 `gidnumber` 與宣告不同。會改變檔案擁有者；playbook 會直接送出，Go 先擋（P0 已定 Phase 2 先拒絕） |
| `group_type_mismatch` | live type 與宣告不同。FreeIPA 不能就地轉換；playbook 不比較 type，會靜默保留 |
| `group_type_unrecognized` | live `objectclass` 未辨識（§6.3） |
| `external_group` | roster 宣告 `type: external`（live 形態見 §9 K2） |
| `preserved_user` | roster 使用者與 preserved 使用者同名（§9 K1） |
| `marker_collision` | marker 存在但描述不是 `pilot.group-history/v1 name=<name>`（與 playbook 的 marker 檢查相同，playbook 在此失敗） |
| `case_collision` | 兩個 roster 群組或使用者名稱只差大小寫（validator 以原字串判斷唯一，FreeIPA 以小寫儲存） |
| `reference_to_absent` | 群組成員引用了 `state: absent` 的使用者或群組。validator 允許，但 playbook 在使用者已刪除後的重跑會因 `group-add-member` 找不到成員而失敗 |

### 7.4 報告（不是操作，不影響結果）

- `ssh_keys`：IPA 的 key 集合與 roster 宣告不同的使用者，列出兩邊的指紋（`sshpubkeyfp` 或由正規化 key 計算），不列 key 本體。Go 不接管 key（計畫 Phase 1「SSH key 範圍的決定」）。
- `implicit_membership_prune`：沒有 `membership` 區塊、或沒有宣告 `users`／`groups` 而 authoritative 的群組（§5.2）。
- `not_in_scope`：§5.3。

### 7.5 plan JSON

```json
{
  "schema": "pilot.identity-plan/v1",
  "engine": {"name": "golang", "pilot_revision": "…"},
  "scope": "users-groups",
  "result": "ok | blocked",
  "target": {"inventory_host": "…", "fqdn": "…", "ssh": {"host": "…", "port": 22, "user": "…"}, "destination": "127.0.0.1:443"},
  "server": {"version": "4.13.4", "api_version": "2.257"},
  "desired_revision": "sha256:…",
  "observation": {"observed_at": "…Z", "fingerprint": "sha256:…", "users": 0, "groups": 0},
  "operations": [{"id": "…", "kind": "user.update", "object": "alice", "fields": {"loginshell": {"from": "…", "to": "…"}}, "destructive": false, "depends_on": []}],
  "blocked": [{"reason": "uid_or_gid_change", "object": "…", "detail": "…"}],
  "reports": {"ssh_keys": [], "implicit_membership_prune": [], "not_in_scope": []},
  "stats": {"http_requests": 0, "reads": 0, "writes": 0, "relogins": 0, "read_retries": 0}
}
```

欄位名稱為擬議；語意如下：

- `desired_revision`：正規化 desired state 的 canonical JSON 的 SHA-256。密碼值不在 desired state 中（§5.1），所以不是可離線猜密碼的摘要。
- `observation.fingerprint`：observer 正規化後的 managed live state 的 SHA-256。
- 操作 ID 由種類、物件與參數決定，同一份輸入兩次預覽得到相同 ID。
- 值可以出現使用者與群組名稱、屬性值；不可以出現密碼、cookie、vault 內容、SSH key 本體。提交到 repo 的 evidence 只放數量，不放 plan 內容。

plan 不授權任何 mutation（D11）。

## 8 對 P0 矩陣的修正

P0 §3 有三處與 playbook 不符，本文件以 playbook 為準（D8），並同步修正 P0：

1. 「roster 載入與結構 gate」一列的 spec 欄寫 C1–C3；C1–C3 是成員與 HBAC 檢查，不是 roster gate。
2. 「屬性收斂」一列寫「未宣告的欄位不碰」；playbook 對 first、last、shell、home 一律送出預設值，只有 display name、email、uid、gid 未宣告時不碰（§5.1）。
3. 「建立群組」一列寫「type 不同時拒絕」；這是 Go 的新要求，playbook 不比較 type（§7.3 `group_type_mismatch`）。

## 9 實作前的擷取

依 AGENTS.md §5.6，判讀規則只能來自真實擷取。在拋棄式 vm-target（目前有 `pwfix-ipa`，FreeIPA 4.13.4／API 2.257）經 Phase 0 的 tunnel 擷取，fixture 放 `internal/freeiparpc/testdata/`，以測試鎖住，擷取後刪除測試物件。

| # | 擷取 | 決定什麼 | 何時 |
|---|---|---|---|
| K1 | 一位 preserved 使用者：預設 `user_find --all` 是否列出；`preserved: true` 的結果與 `preserved` 欄位 | §6.2 第二次讀取的選項與 `preserved_user` 的判斷 | **已擷取（2026-11-05）**：預設讀取不列；`preserved: true` 只列 preserved 使用者（不含 active），每筆 `preserved: true`。`TestPreservedUsersNeedTheirOwnRead` |
| K2 | 一個 external 群組的 `group_find --all` | 是否能從「未辨識」改為明確的 external | **已擷取（2026-11-05）**：objectclass 為 nonposix 集合加 `ipaexternalgroup`，沒有 `gidnumber`。Phase 1 仍視為未辨識（`TestExternalGroupClasses`、`TestCapturedExternalGroupIsBlocked`）；Phase 2 可據此辨識 |
| K3 | 在拋棄式 VM 上把 FreeIPA 的 `ipasearchrecordslimit` 與 389-ds 的 size／lookthrough limit 調低到資料量以下，`sizelimit=0` 的 `user_find`／`group_find` 回什麼 | 完整性規則：server 端限制是否一定反映成 `truncated: true` 或錯誤；若會靜默少回，observer 要改成分段讀取 | **已擷取（2026-11-05）**：151 users、101 groups 下，`ipasearchrecordslimit=10`（FreeIPA 最低值）不影響 `sizelimit=0`；`nsslapd-sizelimit=3` 與 `nsslapd-lookthroughlimit=3` 各自讓 `user_find` 回 `truncated: true`、`group_find` 回錯誤。不會靜默少回（`TestServerLimitsNeverShortenAReadSilently`）。三個限制都已還原並讀回確認 |
| K4 | 不加篩選的 `user_find --all`，包含 admin 帳號 | D7 的 `admins` 判斷，以及完整讀取時出現的系統帳號形態 | **已擷取（2026-11-05）**：138 users，admin 的 `memberof_group` 為 `admins`、`trust admins`，沒有 `givenname`；所有 entry 都能解析（`TestUnfilteredReadShowsTheAdminsMember`、`TestObserveReadsEverythingWithAllAndChecksTheReader`） |
| K5 | 本機 `ansible-vault view` 在環境密碼來源模式下：有 `ANSIBLE_VAULT_PASSWORD_FILE`、只有 ansible.cfg、兩者都沒有時的結束碼與 stderr | §3 的錯誤分類 | **已擷取（2026-10-30，ansible-core 2.19.2）**：前兩者解密成功；兩者都沒有時提示輸入密碼，stdin 關閉時 rc 1、stderr 含 `EOFError`；密碼錯誤時 rc 1、stderr 含 `Decryption failed`。stderr 存在 `internal/inventory/testdata/ansible-vault-view-*.stderr` |

非 admin 讀取者的欄位不在 Phase 1 擷取：D7 直接不支援。

## 10 測試與驗收

### 10.1 單元測試

- 入口：§2.1 拒絕矩陣每一列；從 cobra 指令走到 observer（AGENTS.md §5.15），以假的 `ssh` 與 `httptest` TLS server 回放 fixture。
- 每個拒絕（§2.2 步驟 1–8、§6.3、D7、D10）各有一個會觸發它的 test row，行為以同一組不變量檢查：該 gate 自己的訊息或 sentinel；結束碼 1（只有 blocked plan 是 3，§2.3）；送出的請求不超過該步驟允許的（§2.1 的拒絕之前不執行 `ansible-inventory`、`ansible`、`ansible-vault`；步驟 7 之前沒有 tunnel；登入被拒之後沒有 JSON-RPC；登入之後的任何失敗都有 `session_logout`；讀取失敗之後不再讀）；沒有 plan 檔；密碼、cookie 與 vault 內容不在錯誤、輸出、plan 與 pilot data 目錄任何檔案中。伺服器端的答案取自真實擷取（§9，登入被拒、無 session、`truncated`、`SizeLimitExceeded`）。
- 這個清單由結構鎖住（AGENTS.md §5.10、§5.12）：預覽入口各函式（`runReconcile`、`validateReconcileEngineFlags`、`runReconcileGolangPreview`、`golangPreview`、`inventoryCurrentWithHosts`、`golangPreviewStage`、`rosterServer`、`writeGolangPlan`；`sshTargetFromHostVars`、`sshOptionArgs`、`splitShellWords` 在 Phase 2 的 P2-2 搬到 `internal/sshdial/hostvars.go`（`TargetFromHostVars`），它們的 gate 與 row 隨之搬到 `internal/sshdial/hostvars_test.go` 的 `TestTargetFromHostVarsEveryGateHasARow`）與 `identityreconcile.Observe` 中每個不是 `nil` 的 return 都以 `// gate: <id>` 命名；每個 id 唯一，且有 test row（row 的 `gate` 欄位）或附理由的豁免，豁免被 row 取代、row 指向不存在的 gate、有 return 沒有名字，都會讓測試失敗（`TestReconcileGolangEveryGateHasARow`、`TestObserveEveryGateHasARow`；掃描器是 `internal/gateledger`，它自己的測試證明每一種漂移都會被報告）。新增 gate 沒有 row 時 CI 失敗。row 是否真的讓該 gate 觸發，由變異驗證確認（刪掉該 gate，對應 row 必須失敗），不由掃描器推定。
- 子行程（§2.5）：每種子行程（`ansible-inventory`、`ansible --list-hosts`、`ansible-vault`、`ssh` 讀 FQDN、讀 CA、tunnel）各有 row：卡住且它啟動的行程握著管線時，`--timeout`、SIGINT、SIGHUP 都在期限後結束，結束碼 1，錯誤包著 context 錯誤，子行程與 helper 都不在（查 pid，不靠 sleep）；0 結束但 helper 握著管線時以 `ErrHelperKeptOutput` 失敗；離開 group 的 helper 不讓等待超過 2 秒；SIGHUP 在啟動時已被忽略時不被接走；成功的預覽之後沒有 `ssh -W` 留下；每個子行程是 session leader，Ansible engine 共用的 builder 對沒有標記的 context 不是。每個 row 在預覽回傳的當下（不給寬限）檢查直接子行程（ansible 工具、ssh、tunnel）已被回收，不是之後才消失：回傳之後 pilot 立刻結束，非同步的收尾來不及執行；TLS handshake 永不完成的 tunnel 有 row（登入時；`--timeout` 之後的登出；Ctrl-C 之後的登出）；登出被回答時 tunnel 也在回傳前被回收；SIGINT、SIGTERM、SIGHUP 各有 row；`Dialer.Close` 有 row（沒人關閉的 tunnel 被殺掉並回收、等到 `Wait` 返回、之後不再啟動 ssh；遠端指令與持有的 lock 一併結束；與 `DialContext` 競爭時啟動的 ssh 無一漏掉）。變異驗證：每個機制各拿掉一次，對應的 row 必須失敗：拿掉 `defer dialer.Close()`（C13、C13b、C14）；把它排在登出之後才註冊（先執行，登出被拒：C11、C13、C13b、C15；登入失敗的返回沒有 `Close`：C14）；`Close` 不等待回收、`start` 不登記、`Close` 不拒絕之後的啟動、`Wait` 返回後不註銷、`start` 在登記前放開鎖（`Dialer.Close` 的 row，其中 `start` 不登記時 C13、C13b、C14 也失敗）；不接 SIGTERM（C2b）。這些 row 的 tunnel 經一層讓連線延遲關閉的包裝（`lateClose`），net/http 留給自己的 goroutine 去結束的連線就一定晚於預覽的回傳，沒有它，這幾個 row 在沒有 `Dialer.Close` 的程式碼上有時會通過（goroutine 與回傳競爭；實測八次執行中 C13 兩次、C14 一次）。`internal/sshdial` 只有 `start` 啟動 ssh、且先 `childproc.Isolate`，由 AST lint 鎖住；`internal/childproc` 自己的測試涵蓋 session、group kill、`WaitDelay`、pty 下沒有 controlling terminal、`Cause`。
- 憑證：§3 每種模式；模板、inline `!vault`、非字串、長度不足各自在建立 tunnel 前失敗；錯誤訊息不含密碼。
- 目標推導：§4 每一列，含 `ansible_connection: docker` 與不支援的 ssh 參數。
- stage gate：與 playbook assert 的一致性測試。
- adapter：預設值與 playbook normalize 相同（一致性測試，做法由實作決定，例如在 localhost 以真實 Ansible 計算同一段 Jinja）；§5.1 的嚴格檢查。
- observer：唯讀客戶端（§6.1）；fake server 斷言 `all: true` 等選項；不完整讀取、截斷、缺欄位一律失敗。
- planner（計畫 Phase 1 工作項）：no-op、單人單欄位變更、外部 drift、巢狀成員、空集合與未宣告集合（§5.2 的隱含撤銷）、保留外部資料（不在 roster 的物件不出現）、大小寫、`absent`、每一種 `blocked`、依賴與排序穩定、同輸入兩次 plan 相同、live 變更後 fingerprint 與操作改變。
- 秘密：每種錯誤路徑的輸出與 plan 都不含測試用密碼與 cookie。

計畫 Phase 1 工作項中的「逾期 grants」：grants 只編譯成 HBAC／sudo 規則，不改變群組成員（`grant_compile.go`），所以對 users／groups plan 沒有影響；測試鎖住「含逾期 grant 的 roster 與不含時 users／groups plan 相同」。

### 10.2 spec row 對應檢查

新增測試鎖住 `docs/verification/freeipa-identity.md` 的 users／groups row 與 planner 的操作種類，雙向檢查，比照 `TestSpecPlaybookTagAlignment`：

- users／groups row 的集合**由 contract 推導**：`contracts/freeipa-identity.yaml` traceability 中 tags 含 `users` 或 `groups` 的 row（目前 C1、C2、C8–C12）。新 row 帶這兩個 tag 就自動進入檢查。
- 對應表：

| row | 操作種類 | 驗證讀取 |
|---|---|---|
| C9 | `user.create`、`user.update` | `displayname`、`mail`、`loginshell`、`homedirectory` |
| C10 | `user.enable`、`user.disable` | `nsaccountlock` |
| C11 | `group.create`、`group.member_user.add` | `member_user` |
| C12 | `group.member_group.add` | `member_group` |

- 豁免（附理由）：C1、C2、C8 是 legacy roster 的 row，Go engine 拒絕 legacy roster（D4）。
- 沒有 row 的操作種類（附理由，有 row 之後豁免變成過期而 fail）：`user.password.*`（`freeipa-identity.md` 以 §7.4 手動程序驗證）、`group.member_user.remove`、`group.member_group.remove`（撤銷沒有 checklist row，`freeipa-identity.md` §7.3 為手動程序）、`user.delete`、`group.delete`、`group.marker.create`（候選 row C25、C26 不在 §2 checklist，parser 不讀）、`group.update`。
- 檢查失敗的條件：row 沒有對應也沒有豁免；程式宣告的對應指向不存在的 row；豁免的 row 已有對應；planner 的操作種類不在對應表也不在豁免表。
- 先放回一個 regression（刪掉一筆對應），確認測試會 fail（AGENTS.md §5.7）。相容期內 `TestSpecPlaybookTagAlignment` 照常要通過。

Phase 2 開始寫入前要決定：撤銷、刪除與密碼是否要新增 checklist row（新增 row 要依 AGENTS.md §1 實跑）。

### 10.3 Go reconcile test driver（Phase 1 部分）

`internal/identityreconcile/live_test.go` 的 `TestLiveGoPreviewDriver`，設定 `PILOT_IDENTITY_ENGINE_LIVE_VM` 才執行（其他環境變數見該測試的註解；SSH 與 admin 密碼沿用 `internal/freeiparpc/live_test.go` 的變數，只用於 drift 的前置寫入與讀 server log），輸入為 vm-target 名稱與一個以 sanctioned pilot 流程建立的 workspace。driver 執行建置出的 `pilot` binary，不呼叫 engine 內部函式：

1. `pilot vm-target snapshot`（測試前狀態，測試結束時 rollback 回這裡）。
2. 以舊 engine 套用（`pilot reconcile --component freeipa-identity --force`），建立基準，再 snapshot 一次（基準）。
3. Go 預覽：結果 `ok`，寫入操作 0（D12）。測試 roster 不含會觸發 `blocked` 的內容。
4. 以 fixture 寫入製造外部 drift（一個屬性、一個多出的直接成員、一個停用狀態）。這些寫入用 Phase 0 的 `freeiparpc` 客戶端，屬於測試前置，不是受測 engine。
5. Go 預覽：操作剛好是預期的三筆，種類與物件正確。
6. 讀取無 mutation 的證明（每次預覽都做）：預覽期間 server `error_log` 新增的部分沒有任何寫入方法；plan 的 `stats.writes` 為 0。原本列的「`pilot verify` 前後相同」不採用：server log 直接記錄每個 API 呼叫，是更強的證明，且不依賴 verify 輸出格式。
7. `pilot vm-target rollback` 到步驟 2 的基準 snapshot，再預覽一次，結果與步驟 3 相同（2026-11-05 修正：原本寫 rollback 到步驟 1，那是套用前的狀態，預覽不可能與步驟 3 相同）。
8. 輸出 evidence 摘要：tested revision／tree、vm、FreeIPA 版本、每一步 PASS／FAIL、`stats`、耗時。

apply 與第二輪零 mutation 在 Phase 2 接上。

目前有效的實跑摘要：見 [LATEST](../../evidence/freeipa-go-reconcile/LATEST.md)（candidate、tree、目標、各步驟的結果與每次預覽的寫入數）；重新驗證只改 evidence 目錄，不改這份規格。

### 10.4 退出條件

- §9 的 K1、K3、K4、K5 已擷取並以 fixture 鎖住（2026-11-05 完成）。
- §10.1、§10.2 通過；`go test -race ./...` 綠。
- §10.3 在全新 vm-target 上從不可變 candidate 實跑通過，證據依 AGENTS.md §1.5 記錄。
- 計畫的 Phase 1 退出條件：讀取無 mutation（§6.1、§10.3 步驟 6）；plan 能解釋每個操作（§7.5 的欄位與依賴）；不支援的內容明確阻擋（§7.3）或列為不在範圍（§5.3）。

## 11 交給 Phase 2 的事

- 取鎖閘門、#138 授權快取入口、users/groups-only scope 的探測與未結清結果（計畫 Phase 2）。
- `blocked` 中哪些要在 Phase 2 支援（uid/gid 變更需要明確確認的設計；external 群組需要 K2）。
- 撤銷、刪除與密碼的 checklist row（§10.2）。
- batch 邊界與寫入前重讀（計畫 §4 步驟 4–5）。
