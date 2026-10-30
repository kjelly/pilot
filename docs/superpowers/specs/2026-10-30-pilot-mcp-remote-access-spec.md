# Pilot MCP 遠端存取（GitHub 設定來源）— 實作規格

> **文件狀態：可開始實作（2026-10-30 修訂）**
> **設計基準：** `main@584e1b75`（本檔引用的 pilot 程式碼位置都在這個 commit 核對過）
> **本檔位置：** `docs/superpowers/specs/2026-10-30-pilot-mcp-remote-access-spec.md`（2026-10-30 自 `docs/tmp/` 移入）。
> **範圍：** 使用者端 Linux/macOS；deploy node 為 Linux + Docker。Windows 不在範圍內。
> **工作項目：** §14 只列 coding agent 能獨立完成的工作。需要操作者在真實環境做的事，
> 列在 §4.1 前置條件與 §16 上線後事項，不是本規格的工作項目。
> **路徑與名稱：** 本檔所有 deploy node 路徑、主機名稱、repo 名稱都是佔位符（`<env-root>`、
> `<ssh-alias>`、`<org>/<config-repo>`）。依本規格新增、會進 Git 的任何檔案（runbook、evidence、
> 範例設定、測試 fixture）也只能用佔位符或測試用的假路徑，不得寫入真實環境的路徑、主機名稱、IP
> 或 repo 名稱。使用者本機的 profile 不進 Git，可以寫真實值。

## 0. 決策摘要

| ID | 決策 | 來源 |
|---|---|---|
| D1 | 設定檔的來源是 GitHub private repo。使用者電腦用本機 Git 憑證取得，經 SSH 傳到 deploy node。deploy node 不持有 GitHub 憑證，也不執行 `git clone`。 | 使用者，2026-10-30 |
| D2 | Secret（`.vault/`）留在 deploy node，不放進 GitHub 傳來的設定。未來可能改從 Azure Key Vault 讀取；本規格只固定「secret 來自 deploy node 端的目錄」這個邊界，Azure Key Vault 另寫規格。 | 使用者，2026-10-30 |
| D3 | 只提供 `observe` 與 `edit` 兩種權限。`--enable-diagnose-raw`、`--enable-repair`、`--enable-diagnose-active` 不開放。 | 使用者，2026-10-30 |
| D4 | 執行環境是既有的 pilot-cli Docker image，以 **tag** 指定；tag 可以在 coding agent 的 MCP 設定（`pilot-mcp connect --image <repo>:<tag>`）或 profile 中指定。 | 使用者，2026-10-30 |
| D5 | **deploy node 上只啟動一個 docker container**：`pilot-mcp` 經 SSH 執行一次 `docker run`，一個 MCP session 就是一條 SSH 連線、一個 container。deploy node 只需要 pilot-cli image 與一個能用 docker 的 SSH 帳號；不放啟動器、不用 forced command、不建新目錄。 | 使用者，2026-10-30 |
| D6 | 同一條連線的 stdin 先送設定 snapshot，再送 MCP 串流；stdout 先回一行 ready，再回 MCP 串流（§7.2）。 | 本規格 |
| D7 | 容器內的路徑配置與現行 Deploy workflow 相同（§2.2）：workspace 在 `/pilot/config`、`.vault` 在 `/pilot/config/.vault`、該環境的 pilot data dir 共用。設定檔裡 `/pilot/config/...` 的絕對路徑不必修改。 | 本規格，依現行 runner 做法 |
| D8 | 每個 container 只掛載一個環境的 `.vault`（唯讀）與 `.pilot-data`。edit mode 只改非秘密設定；vault 與 secret 由操作者在 deploy node 上維護。 | 本規格 |

不變式：

1. deploy node 不接收 GitHub 憑證；使用者端不需要、也不得開 SSH agent forwarding。
2. GitHub 傳來的 snapshot 只含非秘密設定。secret 只來自 deploy node 上該環境的 `.vault`，且唯讀。
3. `docker run` 不傳任何環境變數。container 內只有 image 內建的環境變數與 docker 自動設定的
   `HOSTNAME`、`HOME`，都不是 secret。
4. 一個 container 只看得到一個環境的 `.vault` 與 data dir。
5. `pilot-mcp connect` 輸出給 agent 的 stdout 只有 MCP JSON-RPC bytes；所有狀態與錯誤都寫 stderr。
6. 每個 session 固定一個環境、一個 commit SHA、一個內容 digest。branch 或 tag 之後的更新不影響進行中的 session。
7. 驗證失敗一律 fail closed：不回退舊 snapshot，也不改用其他設定。
8. edit 只走既有 `pilot_edit_*` 路徑。非秘密的變更要回到 GitHub，一律由人審核後 commit/PR；
   本工具不 commit、不 push。

**權限的限制由使用者端決定（D5 的代價）**：SSH 帳號能用 docker，持有 key 的人等同 deploy node 的 root，
能讀所有環境的 `.vault`。observe/edit、環境與 image 的限制來自使用者端 profile，用來防止誤用與限制
coding agent 能呼叫的工具，不是對持有 key 的人的強制控制。這和舊做法（直接 `ssh … docker run`）相同。

## 1. 目標與非目標

### 1.1 目標

- Codex、Claude Code、Crush 等 coding agent 只要設定一行本機指令
  `pilot-mcp connect --profile <name> [--image <repo>:<tag>]`，就能使用 deploy node 上的 pilot MCP。
- deploy node 上每個 session 只啟動一個 container，除了 image 與 SSH 帳號之外不需要任何設定。
- agent 設定裡沒有 GitHub、SSH 或 vault 的憑證。
- 設定來自 GitHub，每個 session 可以追溯到環境、commit SHA 與 pilot binary。
- 取代已經無法使用的舊做法（pilot repo 內 `.codex/config.toml`、`crush.json`：把 deploy node 上的單一
  設定目錄掛進 container，並預設開啟 raw 指令與寫入權限）。
- edit session 中對非秘密設定的修改，可以帶回使用者本機的 Git 工作目錄，由人審核後送 PR。

### 1.2 非目標

- 不在 pilot runtime 加入 LLM。
- 不讓 deploy node 存取 GitHub；不在 deploy node 執行 commit、push 或開 PR。
- 不經遠端修改 `.vault` 或任何 secret；不經遠端修改位於 `.vault/` 以外的 roster（§2.1）。
- 不對持有 SSH key 的人做 deploy node 端的權限強制（D5）。
- 不提供 agent 設定安裝器（各 agent 已有官方 `mcp add` 指令，見 §10）。
- 不改變 `pilot mcp serve` 既有的 flag、預設值與工具行為。
- 不取代 GitHub Actions 的 Deploy workflow；MCP 不執行部署。
- 其他自原規格移除的項目見 §15。

## 2. 現況

### 2.1 pilot（已核對，`main@584e1b75`）

| 事實 | 位置 | 對本規格的影響 |
|---|---|---|
| `pilot mcp serve` 只支援 stdio，使用 `mcp.StdioTransport`，它固定讀 `os.Stdin`；go-sdk 另有 `mcp.IOTransport{Reader, Writer}` 可接任意 reader/writer；`mcp.CommandTransport` 會自己啟動子程序 | `cmd/pilot/cmd/mcp.go:76-78`、`:158-162`；go-sdk v1.8.0 `mcp/transport.go:128-161`、`mcp/cmd.go:20-45` | `serveMCP` 改成接受 transport；remote 以 `IOTransport` 接在讀完 snapshot 的同一個 reader 上（§7.2）；doctor 也用 `IOTransport`（§5.5） |
| flag：`--dir`、`--allow-write`、`--enable-diagnose`、`--enable-diagnose-active`、`--enable-diagnose-raw`、`--enable-repair`、`--audit-dir`、`--diagnose-inventory` 等 | `mcp.go:58-69` | 遠端只用 `--dir`、`--allow-write`、`--enable-diagnose`、`--audit-dir`、`--diagnose-inventory`（§8） |
| `capabilities`/`inspect`/`plan`、workspace integrity、diagnose session 工具一定註冊；`pilot_edit_apply` 只在 `--allow-write` 時註冊 | `mcp_edit_tools.go:120-138`、`mcp_workspace_tools.go:25-68` | observe 也有這些工具（§8） |
| `--enable-diagnose` 註冊 sudo/dns/logs/metrics/login 等，以及 composite 與 delivery 工具 | `mcp_diagnose_tools.go:138-174`、`mcp_delivery_tools.go:64-68` | 工具名單放在 `internal/mcpwire`，以一致性測試對齊（§13.1） |
| raw 指令工具 `pilot_diagnose_run`；repair 5 個工具；SNMP active probe | `mcp_diagnose_tools.go:1659`、`mcp_repair_tools.go:63-79`、`mcp_diagnose_active_tools.go:42` | remote 沒有任何 flag 能開啟它們（D3） |
| secret action（`add_vault_key`、`set_vault_value`、`delete_vault_key`、`save_vault`、`discard_vault`、`set_user_password`、`configure_alertmanager_receiver`）只接受 `value_env`，值在 server process 內以 `os.Getenv` 讀取 | `mcp_edit_tools.go:41-57`、`edit_automation_driver.go:631-639` | container 內沒有 secret 環境變數（不變式 3）；寫入 `.vault` 會因唯讀掛載失敗（D8） |
| plan 與 MCP apply 不寫 `.vault/` 以外的 roster（`errRosterOutsideEditScope`） | `edit_tui_roster.go:661`、`:723` | roster 放在 workspace 根目錄的設定（§2.2），遠端無法改 roster（§1.2） |
| 舊診斷工具經 `resolveDiagnoseInventory` → `autoRegenerateInventoryFromHosts` 重寫 `inventory.yml`；delivery/monitoring 工具用不會重寫的 `resolveDiagnoseInventoryReadOnly`，`inventory.yml` 不存在就失敗 | `mcp_diagnose_tools.go:99-136`、`mcp_delivery_tools.go:73` | session 開始時必須先產生 `inventory.yml`（§7.2） |
| `autoRegenerateInventoryFromHosts` 除了寫 `inventory.yml`，還會從目前目錄的 `group_vars/` 補缺少的 group_vars（`copyMissingGroupVars` 用相對路徑），並補 host_vars skeleton、NFS roster 條目與 vault skeleton | `cmd/pilot/cmd/inventory.go:465-505`、`:206-208` | 這些補寫不能被當成 edit 的變更匯出（§7.2 baseline）；vault skeleton 在唯讀 `.vault` 上只印 `vault: skip` 警告（`inventory.go:291-294`） |
| NFS roster 補寫以 host 變數裡的 roster 路徑為準，沒有範圍限制 | `inventory.go:372-386`、`edit_tui_roster.go:718` | 設定裡指向 `/pilot/vault`、`/pilot/data`、`/tmp/pilot-mcp` 的路徑在 session 開始時拒絕（§6.2） |
| 解析不可信 YAML 前要先擋 alias 環與過度展開：`parseYAMLDocument`/`checkAliasGraph`（未匯出） | `internal/inventory/yaml_alias_graph.go:23`、`:45`、`AGENTS.md` §5.11 第 6 點 | 新增匯出的包裝函式給 remote 的路徑檢查使用（§6.2） |
| delivery 工具從 `<--dir>/contracts` 載入 contract catalog | `mcp_delivery_tools.go:80-85`、`mcp_diagnose_tools.go:66-78` | session 開始時把 image 內的 `contracts/` 複製進 workspace（§7.2） |
| contract root 由 flag、`PILOT_ROOT` 或目前目錄決定 | `cmd/pilot/cmd/contract.go:123-133` | container 內目前目錄是 `/pilot`；測試以 `--pilot-root` 指定 |
| audit 預設寫在 workspace 內 `<dir>/.pilot/audit/edit`；`pilot_diagnose_recent_changes` 從這裡讀變更歷史；所有工具都遵守 `--audit-dir` | `mcp.go:86-89`、`mcp_diagnose_composite_tools.go:598`、`mcp_diagnose_evidence.go:81-86` | 遠端一律指定 data dir 內的 `--audit-dir`，跨 session 保留 |
| edit 的 workspace lock 在 `<dir>/.pilot` | `cmd/pilot/cmd/edit_workspace_lock.go:43` | 每個 session 各自一份 |
| data dir 來源依序：`--data-dir`（package 變數 `dataDir`）、`PILOT_DATA_DIR`、設定檔的 `data_dir`、預設 `~/.local/share/pilot`；工具在每次呼叫時讀取 | `cmd/pilot/cmd/root.go:95-106`、`internal/config/config.go:35`、`cmd/pilot/cmd/spec.go:271-273` | remote 設定 package 變數 `dataDir`（§7.2） |
| secret 政策檢查 `configpolicy.Policy.Workspace(dir)` 檢查 `group_vars/`、`host_vars/` | `internal/configpolicy/secrets.go:283` | session 開始時重用，不另寫掃描器 |
| 主機 `env` 只接受 `prod`、`staging`、`sandbox`；`inventory.Parse` 對沒寫的 env 回空字串 | `internal/inventory/catalog.go:62`、`inventory.go:238` | 空字串視為 `sandbox`；環境名稱限這三個 |
| `.vault` 目錄是 symlink 時可通過 `secretpath` 與 managed vault 檢查（靜態閱讀，未實跑） | `internal/secretpath/`、`docs/config-secret-storage.md` | `.vault` 以 symlink 疊進 workspace；由 I15 實跑確認（§13.3） |
| pilot-cli image 執行階段以 root 執行，`WORKDIR /pilot`，沒有 ENTRYPOINT；pilot 在 `/usr/local/bin/pilot`；`/pilot` 內有 `ansible.cfg`、playbooks、group_vars、contracts 等，沒有 `/pilot/config` | `images/Dockerfile.pilot-cli:244,259,262` | 以 `--entrypoint /usr/local/bin/pilot` 執行；可建立 `/pilot/config` symlink |
| `cmd/pilot` 無法編譯成 darwin（`internal/peercred/peercred.go:30`、`internal/sessionrecording/redaction.go:54`、`internal/inventory/roster_write.go:49`、`roster_lock.go:563`；2026-10-30 以 `GOOS=darwin go build ./cmd/pilot` 實測）；`go-sdk/mcp`、`configpolicy`、`secretpath`、`contract`、`statefile` 可以 | — | 使用者端必須是獨立的 `cmd/pilot-mcp`（§5.1） |
| Go panic 以結束碼 2 結束；`cmd/pilot/main.go` 只處理回傳的 error | `cmd/pilot/main.go` | remote 的錯誤結束碼避開 1、2（§7.5） |
| session/state 持久化一律用 `internal/statefile.Store[T]` | `AGENTS.md` §5.1 | edit session 的 `session.json` 用 `statefile.Store` |
| go-sdk 版本有 `CommandTransport` | `go.mod`（`modelcontextprotocol/go-sdk` v1.8.0） | doctor 以它當 MCP client |
| `kjelly/pilot` 是 public repo，目前沒有 release tag | `gh repo view`、`git ls-remote --tags` | 使用者端以 `go install …@<commit>` 安裝 |

### 2.2 設定 repo 與 Deploy workflow 的現行做法（2026-10-30 讀取使用者提供的設定 repo）

- 一個設定 repo 內有多個環境（`sandbox`／`staging`／`prod`），每個環境是一個獨立的 pilot workspace
  目錄（`hosts.yml`、`group_vars/`、`host_vars/`、`monitoring/`、`integrations.yaml`，部分環境有
  roster 檔）。`inventory.yml` 由 `hosts.yml` 產生，不進 Git。
- 環境名稱、目錄名稱、pilot stage 是同一個值；每台主機的 `env` 必須等於環境名稱（沒寫視為 `sandbox`）。
- roster 檔放在 workspace 根目錄、進 Git，只有結構；密碼欄位寫成 vault 變數引用，值在 `.vault/main.yaml`。
- 不進 Git 的資料放在 deploy node 上，依環境分目錄：`<env-root>/<env>/.vault/`（`main.yaml`、
  Ansible 用的 SSH key 等）與 `<env-root>/<env>/.pilot-data/`（pilot data dir，含執行紀錄）。
- 設定檔以 `/pilot/config/...` 絕對路徑引用檔案，例如 `ansible_ssh_private_key_file` 指向
  `/pilot/config/.vault/<key>`、`freeipa_roster_file` 指向 `/pilot/config/<roster 檔>`。
- Deploy 由 deploy node 上的 self-hosted GitHub Actions runner 執行，透過 host 的 docker socket 啟動
  pilot-cli container。每次執行的掛載方式：

  ```text
  -v <checkout>/<env 目錄>:/pilot/config
  -v <env-root>/<env>/.vault:/pilot/config/.vault          # Deploy 為可寫：pilot 會補 vault skeleton
  -v <env-root>/<env>/.pilot-data:/root/.local/share/pilot
  ```

- workflow 先把 image tag 解析成 image ID，整次執行都用這個 ID；同一個環境同時只跑一個 Deploy。
- 改到設定的 PR 必須通過設定 repo 既有的 lint 與 preview 檢查才能合併。
- 舊的 MCP 做法把 deploy node 上一個固定的設定目錄掛成 `/pilot/config`。設定改成「依環境分目錄、
  workspace 只在 GitHub、`.vault` 與 `.pilot-data` 另外存放」之後，那個目錄已不存在，舊指令無法使用。

## 3. 架構

```text
使用者電腦                                    deploy node
┌──────────────────────────┐                ┌─────────────────────────────────────────────┐
│ coding agent             │                │ sshd：能用 docker 的帳號                     │
│   │ stdio (MCP)          │                │                                             │
│   ▼                      │  一條 SSH 連線  │ docker run --rm -i <repo>:<tag>             │
│ pilot-mcp connect ─────────────────────────▶   pilot mcp remote session --env prod …     │
│   │ git fetch（本機憑證）│ stdin：         │   1. 讀 snapshot → 驗證 → 建 workspace       │
│   │ 產生 snapshot        │  snapshot＋MCP  │   2. stdout 回一行 ready                    │
│   │ 組 docker run 參數   │ stdout：        │   3. in-process MCP server（stdio）          │
│   └─ 轉送 MCP ◀──────────── ready＋MCP     │   /pilot/config → session work 目錄          │
└──────────────────────────┘                │   work/.vault → /pilot/vault（ro）           │
        ▲ git（使用者憑證）                 │   data dir = /pilot/data                     │
   GitHub private repo                      │        │ Ansible / SSH → managed hosts       │
                                            └─────────────────────────────────────────────┘
```

信任邊界：

1. **使用者電腦**持有 GitHub 憑證與 SSH key，決定要用的環境、mode 與 image tag（D5）。
2. **GitHub 設定**是資料，不是程式。remote 不執行其中的任何檔案；snapshot 不能提供 `.vault`、
   `contracts` 等保留路徑，也不能引用 `/pilot/config/` 以外的 `/pilot/...` 路徑（§6.2）。這些檢查防止
   設定錯誤或被汙染的 repo 內容造成傷害。
3. **source 宣告是使用者端的聲明**：deploy node 沒有 GitHub 憑證，無法驗證「這份內容真的來自該
   commit」。remote 只驗證內容 digest、檔案規則與環境一致性，並把 commit SHA 記錄下來，供稽核用。

## 4. Deploy node

### 4.1 前置條件（操作者提供；不是本規格的工作項目）

- deploy node 上的 pilot-cli image 必須由**包含 WP2 的 commit** build 並載入（與 Deploy workflow 用同一個
  repository 與 tag 慣例）。舊 image 沒有 `pilot mcp remote`，連線會以 `REMOTE_RUNTIME` 失敗，`doctor`
  第 4 步會指出這一點。
- 一個能執行 docker 的 SSH 帳號（屬於 `docker` group）。建議為 MCP 另建帳號，方便單獨撤銷；
  把使用者的公鑰加進它的 `authorized_keys`，每行前面加 `restrict`（關掉 port/agent/X11 forwarding 與
  PTY，仍可執行指令）。
- 這個帳號的 login shell 必須相容 POSIX sh（bash、sh、dash、zsh 皆可）：遠端指令以單引號包住每個
  token 後交給它執行。shell 啟動檔不得輸出到 stdout，也不得讀取 stdin（會吃掉 snapshot）。
- 既有的 `<env-root>/<env>/.vault/` 與 `<env-root>/<env>/.pilot-data/`（§2.2），不需要搬動。
- 不需要建立其他目錄：edit session 與 audit 由 container 自動建立在 `<env-root>/<env>/.pilot-data/mcp/` 下。

### 4.2 每次 `docker run` 的掛載

由 `pilot-mcp` 依 profile 組出（§5.4），只掛被要求的那一個環境：

| host 路徑 | container 路徑 | 掛載 | 內容 |
|---|---|---|---|
| `<env-root>/<env>/.vault` | `/pilot/vault` | **ro** | 該環境的 secret 與 SSH key |
| `<env-root>/<env>/.pilot-data` | `/pilot/data` | rw | 該環境的 pilot data dir，與 Deploy workflow 共用（delivery 工具看得到部署紀錄）；MCP 自己的資料放在 `/pilot/data/mcp/` |

`/pilot/data/mcp/` 的內容：

| 路徑 | 內容 |
|---|---|
| `/pilot/data/mcp/audit/` | `--audit-dir`，跨 session 保留 |
| `/pilot/data/mcp/sessions/<id>/` | edit session 的 source、work 與 `session.json`；保留給 `changes` 使用（§7.3、§7.4） |

observe session 的 workspace 放在 container 內的 `/tmp/pilot-mcp/<id>/`，container 結束（`--rm`）就消失，
不在 host 留下任何東西。container 路徑定義為 `internal/mcpwire` 的常數，使用者端與 remote 共用。

## 5. 使用者端 `pilot-mcp`

### 5.1 獨立 binary

使用者端是新的 `cmd/pilot-mcp`，只匯入可移植的 package（§12）。原因是 `cmd/pilot` 無法編譯成
darwin（§2.1）。CI 必須對 `./cmd/pilot-mcp` 做 `linux/amd64`、`linux/arm64`、`darwin/amd64`、
`darwin/arm64` 的 cross-compile 檢查。安裝方式：`go install github.com/kjelly/pilot/cmd/pilot-mcp@<commit>`。

### 5.2 指令

```text
pilot-mcp connect  --profile <name> [--image <repo>:<tag>]
pilot-mcp doctor   --profile <name> [--image <repo>:<tag>] [--json]
pilot-mcp changes  --profile <name> [--session <id>] --into <git-worktree>
pilot-mcp sessions [--profile <name>]
pilot-mcp version
```

`connect` 給 agent 的 stdout 只有 MCP bytes；其他指令的人類可讀輸出寫 stdout。image 的優先順序：
`--image` → profile 的 `target.image`；兩者都沒有時報 `PROFILE_INVALID`。

### 5.3 Profile

路徑 `$XDG_CONFIG_HOME/pilot-mcp/profiles.yaml`（沒有 XDG 時 `~/.config/pilot-mcp/profiles.yaml`）。
檔案不含憑證，但不得 group/world 可寫，避免被他人改掉連線目標或 mode。使用者手動編輯，不提供
`profile add` 這類指令。每個「環境 × mode」一個 profile。

```yaml
version: 1
profiles:
  prod-observe:
    source:
      url: git@github.com:<org>/<config-repo>.git
      ref: main
      subdir: <env 目錄>               # 該環境 workspace 在 repo 內的路徑
    target:
      ssh_host: <ssh-alias>            # ssh config 的 alias
      ssh_config: ~/.ssh/config        # 選填；有填時以 ssh -F 傳入
      env: prod
      env_root: <env-root>             # deploy node 上放 <env>/.vault、<env>/.pilot-data 的目錄
      image: pilot-cli:latest          # 選填；會被 --image 覆蓋
      docker: docker                   # 選填；deploy node 上的 docker 指令，預設 docker
      network_host: false              # 選填；true 時加 --network host
    mode: observe                      # observe | edit
    timeouts:
      git_seconds: 60
      ssh_seconds: 15
      startup_seconds: 60              # 選填；送出 snapshot 後等 ready 的上限，預設 60
```

驗證規則（strict decode，未知欄位、重複 key、空值一律拒絕）：

- profile 名稱 `^[a-z][a-z0-9_-]{0,47}$`。
- `source.url` 只接受 `git@<host>:<owner>/<repo>[.git]`、`ssh://git@<host>[:port]/<owner>/<repo>[.git]`、
  `https://<host>/<owner>/<repo>[.git]`。拒絕 userinfo（`user:pass@`）、`file://`、`ext::`、本機路徑與
  以 `-` 開頭的值。測試用本機 bare repo 只能經 package 層級的測試接縫開放，不提供使用者可設定的開關。
- `source.ref` 是 branch/tag 名稱（`git check-ref-format --branch` 合法）或完整 40/64 位 hex SHA；
  縮寫 SHA 拒絕。
- `source.subdir` 是乾淨的相對路徑，不含 `..`；可以是 `.`。
- `target.ssh_host` 符合 `^[A-Za-z0-9][A-Za-z0-9._-]*$`；`target.ssh_config` 展開 `~` 後必須是存在的一般檔案。
- `target.env` 只接受 `sandbox`、`staging`、`prod`。
- `target.env_root`、`target.docker`：`env_root` 必須是絕對路徑；兩者字元都限 `[A-Za-z0-9._/-]`，
  不含 `..`、不以 `-` 開頭。這讓組出的遠端指令不需要跳脫，也不含逗號（可以安全放進 `--mount`）。
- `target.image` 與 `--image`：`<repo>:<tag>`，`<repo>` 符合 `^[a-z0-9]+([._/-][a-z0-9]+)*$`，
  `<tag>` 符合 `^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`；不接受 digest。
- `mode` 只接受 `observe`、`edit`。

### 5.4 `connect` 流程

1. 讀 profile 並驗證。
2. **Git**：以系統 `git` 操作 bare cache `$XDG_CACHE_HOME/pilot-mcp/git/<sha256(正規化 url)>`
   （`0700`）。git 子程序以新的 session 執行（`Setsid`，沒有 controlling terminal），並設
   `GIT_TERMINAL_PROMPT=0`、`SSH_ASKPASS_REQUIRE=never`：不能互動輸入就直接失敗，同時保留使用者的
   `core.sshCommand` 與 credential helper。
   - branch/tag：fetch `refs/heads/<ref>` 與 `refs/tags/<ref>`；兩者都存在時報錯（不猜）。
   - SHA：`git fetch origin <sha>`；失敗時 fetch 所有 heads/tags 後再檢查該 SHA 是否存在。
   - 以 `git rev-parse --verify <x>^{commit}` 取得完整 SHA。
3. **Snapshot**：依 §6.1 產生 tar。
4. **組遠端指令**（每個 token 都符合 §5.3 的字元規則，再逐一加單引號後以空白串接）：

   ```text
   <docker> run --rm -i --init --pull never --log-driver none
     --cap-drop ALL [--cap-add <§13.3 實測證明必要的最小集合>]
     --security-opt no-new-privileges [--network host]
     --mount type=bind,source=<env_root>/<env>/.vault,target=/pilot/vault,readonly
     --mount type=bind,source=<env_root>/<env>/.pilot-data,target=/pilot/data
     --entrypoint /usr/local/bin/pilot <repo>:<tag>
     mcp remote session --protocol v1 --mode <mode> --env <env>
   ```

   - 不傳任何 `-e`/`--env`（不變式 3）。
   - `--log-driver none`：MCP 流量（包含工具輸出）不得留在 docker 的 log。
   - `--pull never`：只用 deploy node 上已有的 image。
   - `--mount type=bind`：host 路徑不存在時 docker 直接失敗，不會自動建立空目錄。
5. **SSH**：`ssh <固定選項> <ssh_host> '<遠端指令>'`。固定選項：`-T -e none -o BatchMode=yes
   -o ForwardAgent=no -o ClearAllForwardings=yes -o StrictHostKeyChecking=yes -o RemoteCommand=none
   -o RequestTTY=no -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o ConnectTimeout=<ssh_seconds>`，
   有 `ssh_config` 時加 `-F <path>`。`RemoteCommand=none`、`RequestTTY=no` 讓使用者 ssh config 裡的同名設定
   不會影響連線。不接受其他使用者提供的 ssh 參數。
6. **送出 snapshot**：先寫 header 行 `PILOT-MCP-SNAPSHOT <位元組數>\n`，再寫 tar（§7.2）。寫入期間同時讀
   ssh 的 stdout 與 stderr，避免雙方互等；寫入遇到 EPIPE 就停止寫，改讀 remote 的錯誤行（§11）。
7. **等 ready**：讀 ssh 的 stdout 直到出現以 `PILOT-MCP-READY ` 開頭的一行，上限 `startup_seconds`。在它
   之前的位元組（例如遠端 shell 啟動檔印出的內容）不轉給 agent，改印到 stderr 當警告；超過 64 KiB 或超過
   時間仍沒有 ready 就報 `REMOTE_RUNTIME`。ready 行的 JSON 中 `mode`、`env`、`protocol` 必須與 profile
   相符，否則報 `REMOTE_REJECTED`。讀 ready 行用的 buffered reader 若已多讀了 ready 之後的位元組，
   這些位元組屬於 MCP 串流，必須先轉給 agent。
8. 把 session 紀錄附加到 `$XDG_STATE_HOME/pilot-mcp/sessions.jsonl`（`0600`）：時間、profile、env、
   image、mode、session_id、commit_sha、content_digest。也在 stderr 印一行 session ID。
9. **轉送 MCP**：之後才開始把 agent 的 stdin 寫進 ssh，並把 ssh 的 stdout 原樣寫給 agent；ssh 的
   stderr 原樣轉到自己的 stderr。

串流規則：

- ready 之前，給 agent 的 stdout 不寫任何 byte。
- 串流不解析、不緩衝整份 JSON-RPC；處理短寫、雙向 EOF 與子程序結束。
- SIGINT/SIGTERM：關閉 ssh 的 stdin，最多等 5 秒後 kill ssh；結束碼 130/143。
- 不自動重試。失敗由 agent 重新啟動 MCP server 處理。
- 錯誤判讀見 §11。

### 5.5 `doctor`

依序檢查，每一步輸出 `pass|fail|skip` 與原因；`--json` 時輸出
`[{check_id,status,reason_code,elapsed_ms}]` 加上 `profile`、`env`、`image`、`mode`、`commit_sha`、
`content_digest`、`pilot_binary_sha256`。

1. profile 合法。
2. git 可非互動取得 ref，解析出完整 SHA。
3. snapshot 可產生且在限制內。
4. `ssh <ssh_host> '<docker> run --rm --pull never --log-driver none --entrypoint /usr/local/bin/pilot <repo>:<tag> mcp remote version'`
   回傳 protocol 與 pilot binary SHA-256（確認 image 存在且支援 `mcp remote`）。
5. 依 §5.4 建立 session，收到 ready。
6. 以 MCP client（`github.com/modelcontextprotocol/go-sdk/mcp` 的 client）完成 `initialize` 與 `tools/list`。
   transport 用 `mcp.IOTransport`，Reader 是讀 ready 行的同一個 buffered reader（保留已多讀的位元組），
   Writer 是 ssh 的 stdin。不用 `CommandTransport`：它會自己啟動子程序，無法接在已經在跑的 ssh 上。
7. 工具集斷言（名單定義在 `internal/mcpwire`，與 server 的一致性由 §13.1 的測試鎖住）：
   - 兩種 mode 都必須有 `pilot_edit_inspect` 與 `pilot_diagnose_sudo`；都不得有
     `pilot_diagnose_run`、`pilot_diagnose_snmp_probe` 或任何 `pilot_repair_*`。
   - observe 不得有 `pilot_edit_apply`；edit 必須有。
8. 結束 session。doctor 不呼叫任何工具，所以 edit session 也不會被保留（§7.2 第 7 步）。

### 5.6 `changes`

把 edit session 對非秘密設定的修改帶回本機 Git 工作目錄：

1. 決定 session：`--session`，或 `sessions.jsonl` 裡該 profile 最近一次 edit session。
2. 以 §5.4 相同的方式 SSH 執行 `docker run`（不加 `-i`，只掛 `/pilot/data`，不掛 `.vault`），container 指令為
   `mcp remote changes --protocol v1 --env <env> <session-id>`，stdout 收到 tar（§7.3）。
3. 驗證 tar：第一個 entry 是 manifest；其餘 entry 只能是 regular file，路徑規則同 §6.2，必須正好是
   manifest 列出的 add/modify 路徑，SHA-256 必須等於 manifest 的 `new_sha256`。任何不符都報
   `CHANGESET_INVALID`，一個檔案都不寫。
4. 檢查 `--into`：等於 `git rev-parse --show-toplevel`（是 repo 的最上層）、`origin` 的 URL 與 profile 的
   `source.url` 指向同一個 repo、`git status --porcelain` 為空，且 base commit（session 的 commit_sha）
   在本機存在（不存在就從 `origin` fetch）。「同一個 repo」的判斷：把兩個 URL 都解析成 host、owner、
   repo（三種 URL 寫法視為相同），去掉結尾的 `.git`，不分大小寫比較。
5. tar 內的路徑相對於 profile 的 `subdir`，寫入時加上這個前綴。
6. `git check-ignore` 判定為忽略的路徑一律跳過，並在 stderr 列出。
7. 對其餘每個變更的路徑，確認 `HEAD` 上的內容等於 base commit 上的內容
   （`git diff --quiet <base> HEAD -- <path>`）。任何一個不符就報 `CHANGESET_CONFLICT`，一個檔案都不寫。
8. 寫入前對每個目標路徑的每一層既有元件做 `Lstat`，任何一層是 symlink 就報 `CHANGESET_CONFLICT`
   （`os.Root` 只防止寫出根目錄，仍會跟隨根目錄內的 symlink）。之後經 `os.Root`（以 `--into` 為根）
   以「同目錄暫存檔 + rename」寫入新增/修改的檔案、刪除被刪的檔案。
9. stdout 列出變更清單，並提示：用 `git diff` 審核，自行 commit 並開 PR；PR 會經過設定 repo
   既有的 lint 與 preview 檢查。

`changes` 不 commit、不 push、不呼叫 GitHub API。

## 6. Snapshot 規則

### 6.1 使用者端產生

1. 以 `git ls-tree -r -z --full-tree <sha>:<subdir>`（subdir 是 `.` 時用 `<sha>`）列出檔案，以
   `git cat-file --batch` 讀取內容。不用 `git archive`，避免 `export-ignore`／`export-subst` 改變內容。
   - mode `120000`（symlink）、`160000`（submodule）或其他非 `100644`/`100755` 的 entry：報
     `SNAPSHOT_INVALID`。
   - 內容以 `version https://git-lfs.github.com/spec/v1` 開頭（LFS pointer）：報 `SNAPSHOT_INVALID`。
   - `.vault/`、`.pilot/`、`.pilot-data/`、`contracts/` 下的路徑：移除，並在 stderr 逐一列出（正常情況下
     設定 repo 不會有這些路徑）。
   - 上限：檔案總量 ≤ 64 MiB、檔案數 ≤ 10,000、單檔 ≤ 8 MiB；超過報 `SNAPSHOT_TOO_LARGE`。
2. 寫出正規化的 tar：mode 一律 `0644`，mtime/uid/gid 歸零，依路徑 byte 排序，不含 directory entry。
3. tar 的第一個 entry 是 `.pilot-mcp-manifest.json`（≤ 1 MiB）。manifest 本身不在 `files` 清單內，
   也不計入 digest：

```json
{
  "protocol": "pilot-mcp-remote/v1",
  "source": {"url": "git@github.com:<org>/<config-repo>.git", "ref": "main",
             "commit_sha": "<40/64 hex>", "subdir": "<env 目錄>"},
  "env": "prod",
  "client_version": "<pilot-mcp 版本>",
  "client_user": "<本機使用者名稱，只供稽核>",
  "files": [{"path": "hosts.yml", "size": 1234, "sha256": "<hex>"}],
  "content_digest": "<hex>"
}
```

`content_digest` 的定義（使用者端與 remote 必須用同一份實作，放在 `internal/mcpwire`）：
依 path 的 byte 順序，對每個檔案依序寫入 `uint32 BE len(path)`、path bytes、
`uint64 BE size`、32 bytes 的 raw SHA-256，對整個串流取 SHA-256。檔案順序、mtime 改變不影響
digest；內容、路徑或大小改變一定改變 digest。

### 6.2 Remote 驗證

- header 行必須完全符合 `^PILOT-MCP-SNAPSHOT [0-9]{1,9}\n$`，長度上限 64 bytes，位元組數 ≤ 80 MiB
  （檔案上限加 tar header 與 manifest 的餘裕）；否則 `SNAPSHOT_INVALID` 或 `SNAPSHOT_TOO_LARGE`。
- 第一個 entry 必須是 manifest；manifest 的 `env` 必須等於 `--env`，否則 `ENV_MISMATCH`。
- 每個 entry 只接受 regular file（directory entry 忽略）。路徑必須：
  - 是相對路徑，且 `path.Clean(p) == p`；
  - 不含 `..`、`\`、NUL 或控制字元；
  - 不重複，轉成小寫後也不重複；
  - 不在 `.vault/`、`.pilot/`、`.pilot-data/`、`contracts/`、`.git/` 之下。違反時回 `SNAPSHOT_INVALID`；
    `.vault/` 的訊息寫明「secret 由 deploy node 提供」。
- 寫入 session 目錄的 `source/`：目錄由 remote 自己建立（`0700`），檔案以
  `O_CREAT|O_EXCL|O_NOFOLLOW` 建立（`0600`）。
- 解開後：
  - 重新計算 digest，必須等於 manifest 的 `content_digest`；檔案清單必須與 manifest 完全相同；
  - snapshot 根目錄必須有 `hosts.yml`；
  - 用 `inventory.Parse` 讀出每台主機的 `env`（空字串視為 `sandbox`），全部必須等於 `--env`；
    否則 `ENV_MISMATCH`。這可以防止把一個環境的設定配上另一個環境的 `.vault`；
  - **路徑引用範圍**：以 alias 防護過的 parser（`internal/inventory` 新增匯出的
    `parseYAMLDocument` 包裝函式，§2.1）解析 snapshot 內每個 `.yml`/`.yaml` 檔；解析失敗或 alias 有環、
    過度展開，回 `SNAPSHOT_INVALID`。逐一檢查所有 scalar 字串：以 `/` 開頭、`path.Clean` 後等於或位於
    `/pilot/vault`、`/pilot/data`、`/tmp/pilot-mcp` 之下的，回 `PATH_OUT_OF_SCOPE`（`/pilot/config/../data`
    清理後是 `/pilot/data`，一樣拒絕）。image 內其他唯讀路徑（例：`/pilot/dist/…`）與受管主機上的路徑
    不受影響。以 Jinja 模板組出的路徑檢查不到（§16）；
  - 從 `/pilot/contracts` 嚴格載入 contract catalog（載入失敗回 `RUNTIME_ERROR`，不得退回空 catalog），
    `configpolicy.New(catalog).Workspace(source)` 必須沒有 violation，否則回
    `SECRET_POLICY_VIOLATION`。violation 只回報檔案、欄位與行號，不回報值（沿用既有格式）。

## 7. `pilot mcp remote`

### 7.1 子指令與 flag

只在 container 內執行，由 `pilot-mcp` 組出的 `docker run` 呼叫：

```text
pilot mcp remote version
pilot mcp remote session --protocol v1 --mode <observe|edit> --env <env>
pilot mcp remote changes --protocol v1 --env <env> <session-id>
```

- `--protocol` 只接受 `v1`，否則 `PROTOCOL_UNSUPPORTED`；`--env` 只接受 `sandbox`、`staging`、`prod`；
  `--mode` 只接受 `observe`、`edit`；`<session-id>` 是 32 個小寫 hex。不符：`COMMAND_INVALID`。
- 沒有任何 flag 能開啟 raw、repair 或 active 工具。
- 容器內路徑有固定預設值（`internal/mcpwire` 的常數）。只為測試保留 `--vault-dir`、`--tmp-dir`、
  `--pilot-root`、`--config-link`，以及 root 的 `--data-dir`：
  - `--pilot-root` 會切換目前目錄並設定 `PILOT_ROOT`（container 內不需要，目前目錄本來就是 `/pilot`）；
  - `--config-link ""` 代表不建立 `/pilot/config` symlink、直接以 work 目錄當 `--dir`。

`version` 在 stdout 輸出一行 JSON：`{"protocol":"pilot-mcp-remote/v1","pilot_binary_sha256":…}`。

### 7.2 `session`

1. 產生 session ID（32 個小寫 hex，128-bit CSPRNG）。session 目錄：observe 是 `/tmp/pilot-mcp/<id>/`；
   edit 是 `/pilot/data/mcp/sessions/<id>/`（建立後立刻取得它的 `.lock`，§7.4）。edit mode 開始前先做
   一次回收（§7.4）。
2. 以一個 buffered reader 包住 `os.Stdin`：讀 header 行，再以 `io.LimitReader(reader, n)` 讀 tar，並讀完
   全部 n bytes。之後同一個 reader 正好停在 MCP 串流的開頭；MCP server 用
   `mcp.IOTransport{Reader: reader, Writer: stdout}`，不用固定讀 `os.Stdin` 的 `StdioTransport`（§2.1）。
3. 依 §6.2 驗證，寫入 `source/`。
4. 建立 workspace：
   1. 把 `source/` 複製成 `work/`。
   2. 建立 symlink `work/.vault → /pilot/vault`。
   3. 把 `/pilot/contracts` 複製成 `work/contracts`（delivery 工具從 workspace 載入 catalog，§2.1）。
   4. 建立 symlink `/pilot/config → <session>/work`（`--config-link` 預設值），讓設定檔裡的
      `/pilot/config/...` 絕對路徑照常可用（D7）。`/pilot/config` 若已存在且不是 symlink，回
      `RUNTIME_ERROR`（代表 image 改了，不可覆蓋）。
   5. 以目前目錄 `/pilot`（與 Deploy workflow 的 container 相同，`copyMissingGroupVars` 從這裡讀
      `group_vars/`）呼叫既有的 `autoRegenerateInventoryFromHosts`（由 `cmd/pilot/cmd` 注入，§12），
      產生 `work/inventory.yml` 並完成它的補寫（§2.1）。失敗回 `WORKSPACE_INVALID`。唯讀 `.vault`
      造成的 `vault: skip` 警告寫 stderr，不算失敗。
   6. edit mode 記錄 **baseline**：`work/` 內所有 regular file（不跟隨 symlink，排除 `.pilot/`、`contracts/`）
      的路徑與 SHA-256，並以 `statefile.Store` 寫入 `session.json`：`id`、`mode`、`env`、`created_at`、
      source 聲明、`client_user`、`content_digest`、baseline、`pilot_binary_sha256`、`state: serving`。
5. stdout 輸出一行 ready（之後才有 MCP bytes）：

   ```text
   PILOT-MCP-READY {"protocol":"pilot-mcp-remote/v1","session_id":"<32 hex>","mode":"observe","env":"prod","commit_sha":"<hex>","content_digest":"<hex>","files":42,"pilot_binary_sha256":"<hex>"}
   ```

6. root 的 `--data-dir` 沒有指定時，設定 package 變數 `dataDir = /pilot/data`（等同 `pilot --data-dir`；
   工具在呼叫時讀它，§2.1；測試以 `--data-dir` 指定時保留測試值）。然後在同一個 process 內啟動 MCP
   server（由 `cmd/pilot/cmd` 注入的 `serveMCP`，傳入第 2 步的 `IOTransport`，§12），等同：
   `pilot mcp serve --dir /pilot/config --audit-dir /pilot/data/mcp/audit
   --diagnose-inventory /pilot/config/inventory.yml --enable-diagnose [--allow-write]`。
   `--allow-write` 只在 edit mode。stdout 只有 MCP bytes；診斷寫 stderr（`slog`）。
7. 結束條件：stdin EOF、SIGTERM/SIGHUP，或執行超過 `--max-session-duration`（預設 12h）。結束時：
   - observe：不需處理（container 結束後 `/tmp` 一起消失）。
   - edit：跟 baseline 比沒有變更（§7.3 的清單為空）就刪除 session 目錄；否則寫入 `state: ended`、
     `ended_at`，保留給 `changes` 使用。
8. 任何一步在送出 ready 之前失敗：刪除 session 目錄，依 §7.5 輸出錯誤，stdout 不輸出任何內容。

### 7.3 `changes <session-id>`

- `/pilot/data/mcp/sessions/<id>/session.json` 不存在：`SESSION_NOT_FOUND`。`env` 必須等於 `--env`、
  `mode` 必須是 edit、`state` 必須是 `ended`，否則 `SESSION_NOT_FOUND`（訊息說明原因）。
- 變更清單：`work/` 內（不跟隨 symlink，排除 `.pilot/`、`contracts/`、`.vault`，以及 source 裡沒有的
  `inventory.yml`，那是產生出來的）與 baseline 相比新增、修改或刪除的 regular file。每個路徑的 `op` 依
  source 決定：
  - source 沒有、work 有：`add`；
  - source 有、work 沒有：`delete`；
  - 兩者都有：`modify`；
  - 兩者都沒有（只存在於 baseline 的產生檔被刪掉）：不匯出。
  `base_sha256` 是 source 的 SHA-256（`add` 為空）。
- 任何匯出的檔案內容含有 session 目錄的內部路徑（`/pilot/data/mcp/` 或 `/tmp/pilot-mcp/`）時回
  `CHANGESET_INVALID`。
- stdout 輸出 tar：第一個 entry 是 manifest
  `{"protocol","session_id","env","base_commit_sha","changes":[{"path","op","base_sha256","new_sha256"}]}`，
  之後是 `add`/`modify` 的檔案，依路徑排序。
- 不刪除 session（可重複執行）；由 §7.4 的保留期限回收。

### 7.4 edit session 的鎖與回收

- 每個 edit session 目錄有一個 `.lock`，session 期間持有 `flock(LOCK_EX)`，process 結束時由 kernel 釋放
  （照 `internal/secretpath/private_temp_dir.go` 的寫法）。
- 每次執行 edit 的 `session` 與 `changes` 時，處理之前先對 `/pilot/data/mcp/sessions/` 做一次有時間上限
  （2 秒）的回收。只處理非阻塞拿得到 `.lock` 的目錄（拿得到代表沒有 process 在用），處理期間一直持有鎖：
  - 沒有 `session.json`、且目錄建立超過 10 分鐘（session 在寫入 `session.json` 之前就中斷）：刪除；
  - `state: serving`（container 被殺掉，沒走到結束步驟）：視為已中斷，照 §7.2 第 7 步處理：沒有變更就刪除，
    有變更就改成 `ended`（`ended_at` 用目前時間）保留；
  - `ended` 且 `ended_at` 超過 7 天、或建立超過 30 天：刪除。
  這是 AGENTS.md §5.14 第 5 點的要求：不能只靠正常結束清理。回收失敗只記 `slog.Warn`，不影響請求。
- observe session 不在 host 留下任何東西，不需要回收。

### 7.5 錯誤輸出

所有錯誤都在 stderr 輸出一行：

```text
pilot-mcp-remote: <CODE>: <訊息>
```

並以下列結束碼結束。結束碼避開 1（一般錯誤）、2（Go panic）、125–127（docker 與 shell）與 255（ssh）：

| exit | code |
|---|---|
| 0 | 成功 |
| 64 | `COMMAND_INVALID`、`PROTOCOL_UNSUPPORTED` |
| 65 | `SNAPSHOT_INVALID`、`SNAPSHOT_TOO_LARGE`、`ENV_MISMATCH`、`PATH_OUT_OF_SCOPE`、`SECRET_POLICY_VIOLATION`、`WORKSPACE_INVALID`、`SESSION_NOT_FOUND`、`CHANGESET_INVALID` |
| 66 | `RUNTIME_ERROR` |

成功時的 stdout：`version` 是一行 JSON；`session` 是 ready 行加 MCP bytes；`changes` 是 tar。
失敗時 stdout 不輸出任何內容。

## 8. 權限模型

| mode | 註冊的工具 | `.vault` | 說明 |
|---|---|---|---|
| `observe` | `pilot_edit_capabilities/inspect/plan`、workspace integrity 與 diagnose session 工具，加上 `--enable-diagnose` 的全部工具 | ro | 沒有 apply；plan 在暫存複本上執行，不改 work |
| `edit` | 上述全部，加上 `pilot_edit_apply` | ro | 只能改非秘密設定；寫 `.vault` 的 action 因唯讀掛載失敗並 rollback，`.vault/` 以外的 roster 由既有的 `errRosterOutsideEditScope` 拒絕（§2.1）。變更只在 session 內，用 `changes` 帶回 |

不開放：`pilot_diagnose_run`（`--enable-diagnose-raw`）、`pilot_repair_*`（`--enable-repair`）、
`pilot_diagnose_snmp_probe`（`--enable-diagnose-active`）。需要時由操作者在 deploy node 上自己執行。

mode 由 profile 決定（D5）。coding agent 只能呼叫這次 session 註冊的工具，無法在 session 中提高 mode。

`--enable-diagnose` 的工具會以該環境 `.vault` 內的 Ansible SSH key，對受管主機執行固定的唯讀指令。

## 9. Edit 變更流程

```text
GitHub commit（base）
  → session（edit）：source/ → work/（產生 inventory.yml，記錄 baseline）
  → agent 用 pilot_edit_plan / pilot_edit_apply 修改 work/ 的非秘密設定
  → session 結束（有變更才保留，7 天）
  → pilot-mcp changes --into <本機 clone>：驗證、檢查衝突後寫入工作目錄
  → 人用 git diff 審核，自行 commit 並開 PR（經設定 repo 的 lint 與 preview 檢查）
  → 合併後由既有的 Deploy workflow 部署
```

vault 與 roster 密碼的修改不經本工具，由操作者在 deploy node 上維護 `.vault`。

## 10. Agent 設定範例（只寫文件，不做安裝器）

image tag 寫在 agent 的 MCP 設定裡（`--image`）；不寫時用 profile 的 `target.image`。

Claude Code：

```bash
claude mcp add --transport stdio --scope user pilot-prod -- \
  /absolute/path/to/pilot-mcp connect --profile prod-observe --image pilot-cli:latest
```

Codex：

```bash
codex mcp add pilot-prod -- \
  /absolute/path/to/pilot-mcp connect --profile prod-observe --image pilot-cli:latest
```

並在 `~/.codex/config.toml` 的 `[mcp_servers.pilot-prod]` 加 `startup_timeout_sec = 90`，涵蓋首次
git fetch、上傳與 container 啟動的時間。

Crush（`crush.json`，格式同 pilot repo 內現有檔案）：

```json
{
  "mcp": {
    "pilot-prod": {
      "type": "stdio",
      "command": "/absolute/path/to/pilot-mcp",
      "args": ["connect", "--profile", "prod-observe", "--image", "pilot-cli:latest"]
    }
  }
}
```

其他 agent：依其官方文件，把同樣的 command 與 args 設成 local stdio MCP server。本規格不列
未查證的設定格式。runbook 只能寫實際執行過的指令（AGENTS.md §1）；agent CLI 在測試環境無法
執行時，該段標示為「未實跑的設定範例」。

## 11. 使用者端錯誤與結束碼

`pilot-mcp` 在 stderr 輸出一行 `pilot-mcp: <CODE>: <訊息>`，訊息不含 URL userinfo 或 secret。
remote 錯誤時保留 remote 的 code（例：`pilot-mcp: REMOTE_REJECTED: ENV_MISMATCH: …`）。

判讀順序：

1. ssh 結束碼 255：`SSH_FAILED`（exit 5）。
2. stderr 最後一行符合 `^pilot-mcp-remote: ([A-Z_]+): ` 時，**以 code 為準**（不看結束碼）：
   `CHANGESET_INVALID` → exit 8；`RUNTIME_ERROR` → exit 7；其餘 → `REMOTE_REJECTED`（exit 6）。
3. 沒有 code 行：結束碼 125 → `DOCKER_FAILED`（訊息提示「image 不存在，或 docker 無法啟動 container」）；
   126/127 → `DOCKER_FAILED`（訊息提示「deploy node 上找不到 docker 或沒有權限」）；其他非 0（例：panic 的 2、
   舊 image 不認得 `mcp remote` 的 1）→ `REMOTE_RUNTIME`，訊息提示「可能是 image 版本太舊，請跑
   `pilot-mcp doctor`」。兩者都是 exit 7。

| exit | code | 意義 |
|---|---|---|
| 0 | — | 成功 |
| 2 | `PROFILE_INVALID` | profile 或參數錯誤 |
| 3 | `GIT_AUTH_REQUIRED`、`GIT_REF_NOT_FOUND`、`GIT_FAILED` | Git 認證、ref 或指令失敗 |
| 4 | `SNAPSHOT_INVALID`、`SNAPSHOT_TOO_LARGE` | 使用者端 snapshot 檢查失敗 |
| 5 | `SSH_FAILED` | 連線、host key 或認證失敗 |
| 6 | `REMOTE_REJECTED` | remote 驗證失敗，或 ready 行的 mode/env/protocol 不符 |
| 7 | `REMOTE_RUNTIME`、`DOCKER_FAILED` | remote 執行期錯誤、docker 失敗、無法解析的回應 |
| 8 | `CHANGESET_CONFLICT`、`CHANGESET_INVALID` | `changes` 的檢查失敗（使用者端或 remote） |
| 130/143 | — | SIGINT/SIGTERM |

## 12. 檔案配置

```text
cmd/pilot-mcp/main.go                 # 使用者端 binary（可移植）
internal/mcpwire/                     # 兩端共用：container 路徑常數、manifest、header/ready 行、digest、錯誤行、工具名單（可移植）
internal/mcpclient/
  profile.go  git.go  snapshot.go  dockercmd.go  transport.go  bridge.go
  doctor.go   changes.go  records.go
internal/mcpremote/
  command.go  archive.go  pathscope.go  session.go  gc.go
  workspace.go  export.go
cmd/pilot/cmd/mcp_remote.go           # pilot mcp remote；注入 callback
cmd/pilot/cmd/mcp.go                  # 抽出 serveMCP(ctx, mcpServeOptions, mcp.Transport)，pilot mcp serve 傳 StdioTransport，行為不變
internal/inventory/yaml_alias_graph.go  # 新增匯出的 parseYAMLDocument 包裝函式（給 remote 的路徑檢查）
```

- `internal/mcpwire`、`internal/mcpclient` 不得匯入 Linux 專用的 package（`cmd/pilot/cmd`、
  `internal/inventory`、`internal/peercred` 等）；以 CI 的 darwin cross-compile 檢查鎖住。
- `internal/mcpremote` 不能匯入 `cmd/pilot/cmd`（會造成 import cycle）。它定義兩個 callback：
  `GenerateInventory(workDir string, stderr io.Writer) error` 與
  `Serve(ctx context.Context, opts ServeOptions) error`，由 `cmd/pilot/cmd/mcp_remote.go` 以
  `autoRegenerateInventoryFromHosts` 與 `serveMCP` 注入。`internal/mcpremote` 可以直接匯入
  `internal/configpolicy`、`internal/contract`、`internal/inventory`（`Parse`）與 `internal/statefile`。
- `internal/mcpremote` 不匯入 Git 相關程式，也不讀任何 GitHub 憑證。
- secret 檢查只用 `internal/configpolicy`；`hosts.yml` 只用 `inventory.Parse`；inventory 產生只呼叫既有的
  `autoRegenerateInventoryFromHosts`，不另寫 parser 或產生器。
- docker 參數只在 `internal/mcpclient/dockercmd.go` 組出，container 路徑只用 `internal/mcpwire` 的常數。

## 13. 測試與驗收

所有測試 fixture 只用假路徑、假主機名稱與假 repo（例：`example.invalid`、`t.TempDir()`）。

### 13.1 單元測試

- `TestProfile_*`：合法、缺欄位、未知欄位、重複 key、URL 含 userinfo、`file://`、`ext::`、`..`、
  縮寫 SHA、ssh_host 以 `-` 開頭、非法 env、非法 env_root/docker、非法 image、沒有 image、檔案 group 可寫。
- `TestGitResolve_*`（本機 bare repo，經測試接縫）：branch → 完整 SHA、tag、完整 SHA、
  branch 與 tag 同名、force-push 後重新解析、非互動認證失敗、subdir。
- `TestSnapshot_*`：正規化、保留路徑移除、symlink/submodule/LFS 拒絕、`export-ignore` 不影響內容、
  上限、digest 對順序與 mtime 不變、對內容/路徑/大小敏感（兩端用同一份 `mcpwire` 實作）。
- `TestDockerCmd_*`：組出的遠端指令 golden（沒有 `-e`、有 `--log-driver none` 與 `--pull never`、用
  `--mount type=bind`、只掛一個環境、`.vault` 一定是 `readonly`、`changes` 不掛 `.vault`、每個 token 都加
  單引號）。
- `TestRemoteArchive_*`：header 格式與上限、絕對路徑、`..`、`\`、控制字元、重複與大小寫衝突、
  symlink/hardlink/device/FIFO、PAX 路徑、manifest 不符、保留路徑、主機 `env` 與 `--env` 不符、
  `PATH_OUT_OF_SCOPE`（`/pilot/vault/x`、`/pilot/data/x`、`/tmp/pilot-mcp/x`、`/pilot/config/../data`；
  `/pilot/dist/x` 與 `/opt/pilot/x` 不受影響）、YAML alias 有環與過度展開、configpolicy violation、catalog
  載入失敗；另加 `FuzzRemoteArchive`（語料包含 alias bomb）。失敗時不留 session 目錄。
- `TestRemoteStdin_*`：讀完 header 與 tar 之後，同一個 reader 的下一個 byte 正好是 MCP 串流的第一個 byte；
  `IOTransport` 從這裡開始讀（以 `io.Pipe` 測試，tar 後緊接著 JSON-RPC，不必替換 `os.Stdin`）。
- `TestRemoteCommand_*`：flag 驗證、`PROTOCOL_UNSUPPORTED`。
- `TestSession_*`：observe 不在 data dir 留東西、edit 有變更才保留、`session.json` 經 `statefile.Store`
  讀寫、回收規則（含沒有 `session.json` 的目錄與停在 `serving` 的 session）、持有鎖的 session 不被刪、
  測試指定的 `--data-dir` 不被覆蓋。
- `TestPrepareWorkspace_*`：產生 `inventory.yml`、baseline 不含產生器補寫的變更、`contracts` 複製、
  `.vault` symlink。因為 `copyMissingGroupVars` 讀相對路徑，這些測試用 `t.Chdir` 且不得平行執行。
- `TestBridge_*`：ready 之前給 agent 的 stdout 為零 byte、ready 之前的雜訊印到 stderr、超過 64 KiB 或
  `startup_seconds` 沒有 ready 時失敗、ready 行之後已被多讀的位元組會轉給 agent、寫 snapshot 時遇到 EPIPE
  改讀錯誤行、短寫、雙向 EOF、訊號、子程序提早結束。
- `TestRepoMatch_*`：`git@`、`ssh://`、`https://` 三種寫法、有無 `.git`、大小寫不同時視為同一個 repo；
  不同 host、owner 或 repo 時不同。
- `TestErrorMapping_*`：ssh 255、有 code 行（各 code 對應的 exit，含 `CHANGESET_INVALID` → 8）、沒有 code
  行的 125、126、127、2 與其他值。
- `TestChanges_*`：add/modify/delete、只存在 baseline 的檔案不匯出、subdir 前綴、`git check-ignore`
  跳過、tar 驗證（多餘檔案、SHA 不符、symlink entry）、`--into` 不是最上層或 origin 不符、工作目錄內
  任一層是 symlink 時拒絕、衝突時一個檔案都不寫、含 session 內部路徑的內容被拒絕。
- **一致性測試（AGENTS.md §5.7）**：以 observe 與 edit 的選項建立 server，列出實際註冊的工具，必須
  滿足 `internal/mcpwire` 的名單（必須有、不得有）；故意加一個 repair 工具時測試要失敗。
- `pilot mcp serve` 回歸：抽出 `serveMCP` 後，既有 `mcp_test.go` 全部通過，flag 與預設值不變。

### 13.2 整合測試（真實 process，不用 Docker）

- 測試在 `127.0.0.1` 的隨機 port 以目前使用者身分啟動 `sshd`（自產 host key、`UsePAM no`、自訂
  `AuthorizedKeysFile`，key 行前加 `restrict`），使用者端以 profile 的 `target.ssh_config` 指向測試產生的
  ssh config。
- profile 的 `target.docker` 指向 shim（假的 docker，例：測試 binary 以 `TestMain` 重新執行自己）：
  - `run` 時解析 `pilot-mcp` 給的 argv，把每個 `--mount` 的 source 對應到 remote 的測試 flag
    （`/pilot/vault` → `--vault-dir`、`/pilot/data` → `--data-dir`），加上 `--tmp-dir`、`--config-link ""`
    與 `--pilot-root <repo 根目錄>`，然後執行 image 後面的 `pilot mcp remote …`；
  - 另一種模式先在 stdout 印幾行雜訊再執行，模擬遠端 shell 啟動檔的輸出；
  - 記錄收到的 argv，供斷言「只掛一個環境」。
- `readonly` 由測試把 `.vault` 測試目錄設成不可寫（目錄 `0555`、檔案 `0444`）來模擬。以 root 執行時這個
  模擬無效，相關 case skip；設了 `PILOT_REQUIRE_SSHD_TESTS=1` 時改為失敗。
- 本機沒有 `sshd` 時 skip；CI 安裝 `openssh-server` 並設 `PILOT_REQUIRE_SSHD_TESTS=1`，讓 skip 變成失敗。
  新增 `make mcp-remote-test`；它的 CI job 必須加進 `image` job 的 `needs`
  （`cmd/pilot/cmd/ci_needs_test.go`），`timeout-minutes` 必須通過
  `cmd/pilot/cmd/ci_timeout_consistency_test.go`。

| Case | 操作 | 驗收 |
|---|---|---|
| I01 | `pilot-mcp connect`（本機 bare repo，含兩個環境目錄）→ MCP `initialize` + `tools/list` | 成功；給 agent 的 stdout 第一個 byte 就是 JSON-RPC |
| I02 | observe profile | 沒有 `pilot_edit_apply`、`pilot_diagnose_run`、`pilot_repair_*`；data dir 內沒有留下 session |
| I03 | edit profile | 有 `pilot_edit_apply`；對 `hosts.yml` 做一次 apply 後 `changes` 帶回正確檔案（含 subdir 前綴），不含產生器的補寫 |
| I04 | shim 在 ready 前印雜訊 | 連線成功；雜訊出現在 stderr，不在給 agent 的 stdout |
| I05 | 兩個 session 用不同 SHA 同時執行 | 讀到的設定各自對應自己的 SHA |
| I06 | 舊診斷工具重寫 `inventory.yml` | 只寫在 `work/`；`source/` 不變；`changes` 不帶出 |
| I08 | SIGKILL `pilot-mcp`、強制斷 SSH | remote process 在 30 秒內結束 |
| I09 | snapshot 含 `.vault/x` 或 `contracts/x` | `SNAPSHOT_INVALID` |
| I10 | snapshot 的 `group_vars` 有明文密碼 | `SECRET_POLICY_VIOLATION`，訊息不含密碼 |
| I11 | 帶假 GitHub token 的 credential helper | remote 的檔案、process args、env、audit 都找不到該 token |
| I12 | edit session 呼叫 `set_vault_value`（`value_env=HOME`） | apply 失敗並 rollback；`.vault` 內容不變 |
| I13 | profile 的 env 是 staging，但 subdir 指向 `env: prod` 的設定 | `ENV_MISMATCH` |
| I14 | 任何連線 | shim 記錄的 argv 只掛 profile 指定環境的 `.vault` 與 `.pilot-data` |
| I16 | `pilot_diagnose_delivery` 呼叫 | 能載入 catalog 並讀到 data dir 的紀錄（以測試資料建立） |
| I17 | snapshot 的 `freeipa_roster_file` 指向 `/pilot/data/x` | `PATH_OUT_OF_SCOPE`，data dir 沒有被寫入 |

### 13.3 vm-target 端對端

- 新增 `playbooks/test/fixtures/mcp-remote-access-setup.yml`（AGENTS.md §4.0 的測試前置；不對應
  `docs/verification/` spec）：在 VM 上安裝 docker（沿用 `docker-apply.yml`）、載入本機 build 的
  pilot-cli image（兩個不同 tag）、建立能用 docker 的帳號並登記測試公鑰（`restrict`），以及至少兩個環境的
  `<env-root>/<env>/.vault`、`.pilot-data`（用 VM 上的測試路徑）。fixture 必須冪等。
- 情境：
  - observe handshake 加一次對 VM 本身的 `pilot_diagnose_dns` 呼叫；
  - **I15**：設定檔以 `/pilot/config/.vault/<key>` 與 `/pilot/config/<roster>` 引用檔案時，診斷、roster
    讀取與 `.vault` symlink 都正常運作；
  - delivery 工具讀到 `.pilot-data` 內的紀錄；同一環境同時有 MCP session 與另一個寫 data dir 的 pilot
    指令時，兩邊都正常；
  - edit apply 加 `changes`；
  - `--image` 選兩個不同 tag 都能連線；不存在的 tag 回 `DOCKER_FAILED`；
  - container 內 `env` 只有 image 內建值與 `HOSTNAME`、`HOME`；`docker logs` 沒有留下 MCP 內容；
  - 強制中斷、edit session 回收；
  - 決定 `--cap-add` 的最小集合，並更新 `TestDockerCmd_*` 的 golden。
- 證據放在 `docs/evidence/mcp-remote-access/<date>-<tested-sha>.md`；完整輸出只放 `.verification/`。
  evidence 只寫 VM 的測試路徑或佔位符，不寫真實 deploy node 的資訊。
- 新增 `docs/runbooks/mcp-remote-access.md`，含 AGENTS.md §2 要求的事實快照段。裡面的每一條設定指令，
  都必須先在 vm-target 上實際跑過；路徑與名稱一律用佔位符。
- 自動化測試不使用真實 GitHub repo（沒有憑證）；以本機 bare repo 代替，並在 evidence 寫明這個限制。

## 14. 工作包（coding agent，依序，每包一個 PR）

| WP | 內容 | 完成條件 |
|---|---|---|
| WP1 | 把 `runMCPServe` 抽成 `serveMCP(ctx, mcpServeOptions, mcp.Transport)`，`pilot mcp serve` 傳 `StdioTransport`，行為不變 | 既有 MCP 測試全綠；`go test -race ./...` 綠 |
| WP2 | `internal/mcpwire`、`internal/mcpremote`、`pilot mcp remote`、`internal/inventory` 匯出的 YAML 解析包裝；工具名單一致性測試 | §13.1 中 remote、session、workspace、stdin、一致性測試全綠；fuzz 跑過 |
| WP3 | `internal/mcpclient`、`cmd/pilot-mcp`（connect/doctor/changes/sessions/version）；CI 加 darwin/linux cross-compile job，加進 `image.needs` 並通過 timeout 一致性測試 | §13.1 中 client 的測試全綠；四種 GOOS/GOARCH 都能 build；`ci_needs_test`、`ci_timeout_consistency_test` 綠 |
| WP4 | §13.2 整合測試（含 shim）、`make mcp-remote-test`、CI job（安裝 `openssh-server`、`PILOT_REQUIRE_SSHD_TESTS=1`、加進 `image.needs`） | §13.2 全部 case 通過；CI 綠，含 `ci_needs_test`、`ci_timeout_consistency_test` |
| WP5 | §13.3 fixture、vm-target 實跑、`docs/runbooks/mcp-remote-access.md`、evidence | evidence 記錄 tested revision/tree 與實際結果；runbook 指令都實跑過；本 WP 新增的檔案只含佔位符與測試路徑 |
| WP6 | README 加入 `pilot-mcp` 說明與 §10 的設定範例 | README 範例只用佔位符；`go test ./...` 綠 |

每個 WP 都要遵守 AGENTS.md：`go build ./...`、`go vet ./...`、`go test ./...`、`go test -race ./...`
全綠；正式 evidence 依 §1.5 對不可變 candidate commit 執行。

## 15. 自原規格移除的項目

| 原規格內容 | 處置 | 原因 |
|---|---|---|
| 自訂分幀傳輸協定、`client_nonce` 冪等、prepare/serve 兩段連線 | 改成一條連線：header＋tar＋MCP | 使用者要求 deploy node 每個 session 只啟動一個 container（D5） |
| Remote policy YAML、forced command、host 上的啟動器、`authorized_keys` 產生器 | 移除 | 使用者要求 deploy node 只啟動 docker，不放其他東西（D5）；權限由使用者端 profile 決定 |
| `repair`、`raw-debug` mode 與伺服器端核准機制 | 移除 | 使用者決定只開 observe 與 edit（D3） |
| edit mode 修改 vault、secret 與 roster | 移除 | `.vault` 唯讀掛載（D8）；secret action 的值只能來自 server process 的環境變數；roster 在 `.vault/` 以外時 MCP 拒絕寫入 |
| Session 狀態機、lease/heartbeat、remote systemd 服務 | 移除 | observe 的狀態只在 container 內；edit 用 flock 加 TTL 回收 |
| Agent 安裝器、`pilot mcp init` TUI、`profile add/remove` | 移除 | 各 agent 已有官方 `mcp add`；四種設定格式變動快，維護成本高、效益低 |
| changeset 自動開 PR（`gh` 整合）、三方合併 | 改成 `changes --into` 寫入本機工作目錄 | 開 PR 留給人；遇到衝突就停止；PR 走設定 repo 既有的檢查 |
| commit 簽章、provenance 驗證 | 移除 | deploy node 沒有 GitHub 憑證，本來就無法獨立驗證；改為明確記錄為使用者端聲明 |
| 強制 image digest | 改成 tag（使用者決定，D4） | 與 Deploy workflow 追 tag 的做法一致；tag 可在 agent 設定中選擇 |
| Prometheus metrics、observability counter | 移除 | 使用量小，`audit` 與 `sessions.jsonl` 就夠 |
| 本機/遠端 cache 預熱（`prefetch`）、SLO | 移除 | 沒有實測數據前不設計 |
| `--insecure-legacy-ssh`、GitHub Enterprise allowlist | 移除 | 沒有需求 |
| 把 MCP 工具改成依 session 區分 inventory 輸出 | 移除 | `work/` 本來就是每個 session 一份的私有複本，既有程式碼不用改 |
| Windows、OpenCode V1/V2、Crush `crushrc` 的格式細節 | 移除 | 不在範圍；未查證的格式不寫進規格 |

## 16. 已知風險、限制與上線後事項

1. **持有 SSH key 的人等同 deploy node root**：帳號能用 docker，可以讀所有環境的 `.vault`。observe/edit、
   環境與 image 的限制只來自使用者端 profile（D5），和舊做法相同。要撤銷某人的存取，刪掉他在
   `authorized_keys` 的那一行。
2. **coding agent 可能改 profile**：agent 若有寫入使用者家目錄的權限，可以改 profile 的 mode，在下次啟動
   時變成 edit。agent 無法在進行中的 session 提高權限。必要時只為 agent 建立 observe 的 profile。
3. **遠端 shell 啟動檔**：SSH 會透過帳號的 login shell 執行指令，shell 啟動檔印出的內容會在 ready 之前
   出現；`pilot-mcp` 會跳過並警告（§5.4 第 7 步）。啟動檔若讀取 stdin，會吃掉 snapshot，連線以
   `SNAPSHOT_INVALID` 失敗。MCP 專用帳號不要有會輸出內容或讀 stdin 的啟動檔（§4.1）。
4. **連線斷掉的偵測**：`docker run -i` 在 stdin 結束時關閉 container 的 stdin，pilot 收到 EOF 後結束（I08）。
   網路直接斷掉、沒有送出 FIN 時，使用者端由 `ServerAliveInterval` 發現並結束；deploy node 端要等 sshd
   發現連線中斷（依 sshd 的 keepalive 設定）或 `--max-session-duration` 到期，container 才會結束。
5. **source 是使用者端聲明**：deploy node 無法驗證 commit SHA 的真偽，只能記錄。
6. **路徑引用檢查只擋字面路徑**：以 Jinja 模板組出的路徑仍可能碰到同一環境的 data dir；不同環境的資料
   不會被掛進 container（不變式 4）。
7. **symlink 相容性**：`/pilot/config` 與 `.vault` 都是 symlink。I15（§13.3）必須證明 roster 解析、
   `configpolicy`、Ansible 的 SSH key 路徑都能透過 symlink 正常運作。若某個既有檢查拒絕這種配置，
   停下來回報，不得放寬既有檢查。
8. **data dir 與 Deploy 共用**：MCP 會讀寫 `<env-root>/<env>/.pilot-data`（run store、Ansible runtime、
   `mcp/` 子目錄），與同環境的 Deploy 並行時由 SQLite 與既有檔案鎖處理；§13.3 在 vm-target 上驗證並行。
9. **MCP 看到的設定不一定是最後部署的版本**：session 用 profile 的 ref（通常是 `main`），而 deploy node
   最後一次部署的可能是另一個 commit。delivery 工具讀得到部署紀錄，可用來比對。
10. **Azure Key Vault**：未來改用時，邊界仍是 container 內的 `/pilot/vault`（或替代它的 secret 來源）；
   需另寫規格，不影響使用者端與傳輸方式。
11. **上線後事項（使用者決定時機；不是本規格的工作包）**：以包含 WP2 的 commit build pilot-cli image 並
    載入 deploy node、在 deploy node 建立 SSH 帳號並登記公鑰、用真實 GitHub repo 跑 `pilot-mcp doctor`、
    確認後再把 pilot repo 內 `.codex/config.toml` 與 `crush.json` 改成 `pilot-mcp connect`。
