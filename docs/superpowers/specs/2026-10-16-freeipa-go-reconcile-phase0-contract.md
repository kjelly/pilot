# FreeIPA Go reconcile — Phase 0 契約與傳輸決定

日期：2026-10-16。對應計畫：`docs/superpowers/plans/2026-10-15-freeipa-go-ssh-reconcile.md` Phase 0。

狀態：Phase 0 的傳輸與 API 決定已依真實擷取定案（§2）。users／groups 範圍的驗收契約（§3、§4）是 Phase 1–2 的實作依據，尚未實作。

本文件不提供操作 SOP。新套件 `internal/sshdial`、`internal/freeiparpc` 目前只供 Phase 1 以後的 engine 使用，沒有接到任何 pilot 入口。

## 1 範圍

Phase 0 交付：
- `internal/sshdial`：以系統 OpenSSH `-W` 提供 `net.Conn`；讀取寫入 server 的 FQDN 與 CA；遠端排他鎖。
- `internal/freeiparpc`：
  - `login_password` session，含 Referer 與 cookie；
  - TLS 只信任 pin 的 CA，並驗證 server FQDN；
  - JSON-RPC 呼叫與 batch；
  - method allowlist；
  - 錯誤分類：登入、session、RPC、傳輸、結果未知；
  - API 版本檢查；
  - membership 結果解析。
- 真實擷取的 fixture。單元測試以 fixture 回放，live 測試對拋棄式 VM 實跑（§5）。

不在 Phase 0：roster 轉 desired state、planner、journal、CLI 入口、與舊 playbook 的混合執行。

## 2 依真實擷取定案的傳輸與 API 行為

所有結論取自 FreeIPA 4.13.4（API 2.257、AlmaLinux 9.8）實際回應。fixture 在 `internal/freeiparpc/testdata/`。

| 主題 | 實測結果 | 決定 |
|---|---|---|
| 轉送目的地 | `ssh -W 127.0.0.1:443` 搭配 TLS ServerName 為 server FQDN，httpd 接受 | 預設目的地 `127.0.0.1:443` |
| 登入 | `POST /ipa/session/login_password`（form `user`、`password`，Referer `https://<fqdn>/ipa`）回 200，`Set-Cookie: ipa_session=…` | 採用；cookie 只在記憶體 |
| 密碼錯誤 | 401，`X-IPA-Rejection-Reason: invalid-password` | `LoginError{Reason}`，不重試 |
| 密碼過期 | 401，`X-IPA-Rejection-Reason: password-expired` | 同上，訊息要求輪替密碼 |
| 沒有 session | `/ipa/session/json` 回 401（HTML 頁面，`WWW-Authenticate: Negotiate`） | 視為 session 失效 |
| 登出 | `/ipa/session/logout` 回 **404**；登出要呼叫 `session_logout` 命令 | 以 `session_logout` 結束 session |
| session 失效後的寫入 | `session_logout` 之後送 `user_mod`，回 401，重新登入讀回，**屬性未改變** | 401 發生在命令執行前：讀取與寫入都可重新登入一次後重送；第二次 401 即失敗 |
| API 版本 | `version: 2.999` 與 `2.100` 都被接受，不回錯誤；不帶 `version` 只回 `VersionMissing` warning | server 不會擋不相容的 client，**由 client 檢查**：登入後 `ping`，解析 `API version`，不在支援清單時在任何寫入前失敗。支援清單目前只有實測過的 `2.257` |
| 應用層錯誤 | HTTP 200，`error` 物件帶 `name` 與 `code`，例如 `NotFound` 4001、`DuplicateEntry` 4002、`EmptyModlist` 4202、`AlreadyActive` 4009、`AlreadyInactive` 4010、`ACIError` 2100、`CommandError` 905 | `RPCError{Name, Code}`；呼叫端以 name 判斷 |
| membership | 已是成員、找不到成員時仍為 HTTP 200、`error: null`；`result.completed` 為 0，`result.failed.member.<type>` 列出 `[名稱, 原因]` | `MemberResult` 逐成員解析；`completed` 與 `failed` 必須和要求的成員數一致 |
| batch | `batch` 回 `count` 與 `results[]`；單項失敗不影響其他項。失敗項的格式與最外層不同：`error` 是訊息字串，另有 `error_name`、`error_code`、`error_kw` | 逐項按命令判讀；每項必須有 `error`，`ping` 的成功項只有合法的 `summary`，其他命令必須有非 null 的 `result`；兩種錯誤格式分別解析；batch 不是交易 |
| 截斷 | `*_find` 結果帶 `truncated: true`（`sizelimit` 不足時） | 呼叫端一律帶 `sizelimit=0`、`timelimit=0`，`truncated` 為 true 即失敗 |
| 回應的必要欄位 | 每個回應都有 `error`（成功時為 null）與 `result` 物件；除 `ping`（只有 `summary`）外，每個允許的命令在 `result` 內都有非 null 的 `result`；`*_find` 一定有 `count`、`truncated`、`result`，沒有命中時是 `count: 0`、`truncated: false`、`result: []`；membership 結果一定有 `completed` 與 `failed.member` | 缺欄位、欄位為 null 或型別不對的回應**不算成功**，是 `ErrIncompleteResponse`：寫入（含有寫入的 batch）視為結果未知，讀取直接失敗；只有真實的空結果才是空集合（PR #120 review 後修正） |
| keep-alive | 一條連線約 100 個請求後被 httpd 關閉，Transport 會重新 dial（每次一個新的 `ssh -W`，約 0.8 秒） | 接受；大量讀取用 `*_find --all` 或 `batch` 降低請求數 |
| 延遲（拋棄式 VM，同機） | ping p50 52 ms；6 次 `*_find --all` 讀完 users、groups、hosts、hostgroups、HBAC、sudo 約 3.7 秒；120 次 `user_show --all` 逐一 33.7 秒、一次 batch 5.7 秒 | 讀取以 `*_find --all` 為主；每次 `ipa` CLI 呼叫約 800 ms，這是改用 JSON-RPC 的主要收益 |

遠端鎖：
- 寫入 server 上以 `flock --wait <秒> --conflict-exit-code 75 /etc/ipa sh -c 'echo locked; exec cat'` 持有，鎖到 stdin 關閉或 SSH 中斷為止。
- 選 `/etc/ipa`，因為它在每台 FreeIPA server 上都存在，且任何 SSH 身分都能以唯讀開啟；不需要建立檔案。共用 `/tmp` 的檔案會受 `fs.protected_regular` 限制。
- 舊 engine 的入口要在 Phase 2 取得同一把鎖。

## 3 users／groups 功能對照矩陣

Phase 2 的 Go engine 要逐列保持現有行為（`playbooks/apply/freeipa-identity-apply.yml`）。

「spec」欄是 `docs/verification/freeipa-identity.md` 的 row 或章節。Phase 1 的 spec row 對應檢查會鎖住這張表。

| 行為 | 現有 task | spec | engine 要求 |
|---|---|---|---|
| roster 載入與結構 gate（版本、未知 key、使用者與群組結構、category 前綴、名稱唯一且可解析） | pre_tasks 的 `Gate: canonical …` | §4、C1–C3 | 重用 `internal/inventory` 的載入與 validator；不在 engine 另寫一套。失敗時不建立 tunnel |
| 只支援 canonical roster（`schema_version`） | legacy `ipa_users[].groups` 路徑 | — | legacy roster 由 engine 拒絕，交舊 engine 處理 |
| 使用者預設值：first/last 預設為名稱、shell `/bin/bash`、home `/home/<name>`、`enabled` 預設依 `state != disabled` | `Normalize canonical users…` | — | 同一套預設；以表格測試對照 playbook 的 normalize |
| 建立使用者 | `Ensure IPA users exist` | C9 | 只對不存在者 `user_add` |
| 屬性收斂：first、last、display name、email、uid、gid、shell、home | `Reconcile user first/last names` | C8、C9 | `user_mod` 只帶不同的欄位；未宣告的欄位不碰。uid/gid 變更屬 destructive（影響檔案擁有者），Phase 2 先拒絕並要求明確確認 |
| 密碼：沒有 Kerberos key 時初始化；`preserve_existing: false` 要求重設，使用者仍在上次重設的密碼時不重複；查不到狀態時 fail closed | `Look up password state…`、`Decide the password action…`、兩道 gate | §7.4 | 判斷依 `krbLastPwdChange`、`krbPasswordExpiration`（`maxlife=0` 時沒有後者）。`passwd` 送出後逾時或中斷記為 unknown，不自動重送 |
| SSH key：`ssh_keys.values` 是 authoritative 清單；空清單清除全部；未宣告不管理 | `Set SSH public keys…` | §5.1（runbook） | 以 key 本體比較集合；清除時送空值 |
| 啟用／停用 | `Reconcile canonical account enabled state` | C10 | 只在 `nsaccountlock` 與宣告不同時呼叫 |
| 建立群組；description、gid 收斂；posix／nonposix／external | `Ensure IPA groups exist`、`Reconcile IPA group descriptions` | C11、C12 | 只對不存在者 `group_add`；`group_mod` 只帶不同的欄位；type 不同時拒絕（FreeIPA 不能就地轉換） |
| 每個套用過的群組有 history marker（`pilot-internal-history-g-<sha256>`，description `pilot.group-history/v1 name=<name>`）；刪除群組前 marker 必須存在 | `Ensure durable history marker…`（`tasks/freeipa-group-history-marker.yml`） | §9 | 相同命名與描述；marker 查詢失敗或碰撞時 fail closed |
| 直接成員：`membership.authoritative`（預設 true）時撤銷名冊外的直接成員；false 時只新增 | `Look up canonical group direct membership`、`Remove stale…`、`Ensure canonical direct …` | C11、C12 | 直接與間接成員分開；新增與撤銷依集合差合併呼叫，逐成員檢查 `MemberResult`；成員查詢失敗不能當成空集合 |
| 刪除 `state: absent` 的使用者與群組 | `Delete canonical users…`、`Look up actual FreeIPA group…`、`Delete canonical groups…` | §9 | 刪除前即時重讀；not found 視為已完成；其他錯誤停止 |
| 不完整讀取時不得撤銷 | #102、#119 的 gate | v1.13、v1.15 | `*_find` 帶 `sizelimit=0`；`truncated` 或缺欄位時禁止 authoritative 撤銷 |

不在 Phase 2 範圍：
- host、hostgroup、netgroup、HBAC、sudo；
- password policy、per-user authentication types、NFS。

混合執行時，這些項目仍由舊 playbook 處理（計畫 §5 混合執行模型）。per-user authentication types 雖然是使用者屬性，仍留在舊 playbook，直到 Phase 3 搬移該 section。

## 4 engine 專屬驗收條件

Phase 1 起轉成可執行的檢查：
- **只做必要的寫入。** 第二輪對同一份 roster 送出 0 個寫入命令。單一屬性變更只產生該物件的一個 `user_mod`，且只帶該欄位。
  - 由 client 端計數器與 server `error_log` 兩邊核對。
- **秘密不外洩。** 密碼與 session cookie 不出現在：
  - argv、環境變數、錯誤訊息、log、plan、journal；
  - `ssh` 的 remote command。
  - 單元測試對每種錯誤路徑檢查；live 測試對整個輸出比對。
- **不跟隨 HTTP redirect。** 登入、RPC 與登出均拒絕 redirect（含同 origin）；請求只可送至 pin 的 HTTPS origin，沒有 HTTP 直連 fallback。307/308 不得重送密碼或 cookie。此邊界以故障注入驗證，不宣稱真實 FreeIPA 曾回 redirect。
- **TLS 與 API 版本 fail closed。** CA 或 hostname 不符時，在送出任何 HTTP 請求（含密碼）之前失敗。API 版本不在支援清單時，在任何寫入前失敗。
- **401 只重登一次。** 401 重新登入一次後重送（§2 已證明 401 發生於執行前）；連續兩次 401 即失敗。
- **結果未知要明說。** 寫入在送出後遇到傳輸中斷、逾時或取消時回報 unknown，不自動重送；讀取可重試一次。
- **不完整的回應不算成功。** 缺欄位、null 或型別不對的回應：
  - 單次寫入，或含有寫入的 batch：回報 unknown，並計入 `Stats.Unknown`；
  - 讀取：直接失敗。
  - 只有回應明確說「零筆、未截斷」時，才可當成空集合（§2「回應的必要欄位」）。
- **sshd 拒絕轉送時說明原因。** `AllowTcpForwarding no`、`DisableForwarding yes`、`PermitOpen` 不含目的地時，preflight 在 mutation 前失敗並指出原因。
- **遠端鎖。** 同時兩個 writer 時，第二個在等待時限後失敗；持有者的 SSH 中斷後鎖釋放。
- **效能**：計畫 §6。

## 5 Phase 0 驗證

- 單元測試：
  - `internal/sshdial`：在 PATH 放假的 `ssh`，鎖定 argv 與錯誤分類；鎖以本機 `flock` 實測。
  - `internal/freeiparpc`：以 `httptest` TLS server 回放 §2 的真實擷取。
- live 測試：`internal/freeiparpc/live_test.go`，只在設定 `PILOT_FREEIPA_LIVE_SSH` 時執行，對拋棄式 vm-target：
  - 建立 tunnel、登入、檢查 API 版本；
  - 對單一測試帳號建立、改一個欄位、重跑零寫入；
  - batch 逐項錯誤；
  - session 失效後重登；
  - 非 admin 帳號的權限不足；
  - CA 與 hostname 不符；
  - 讀寫途中切斷 tunnel、逾時；
  - 遠端鎖的互斥與中斷釋放；
  - sshd 關閉轉送時的錯誤（由 evidence 腳本暫時改 sshd 設定）。
- 結果記錄在 `docs/evidence/freeipa-go-reconcile/<date>-<rev>.md`。
