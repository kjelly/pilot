# Runbook：pilot-mcp 遠端存取

## 0. 目標

讓 Codex、Claude Code 等 coding agent 以一行 `pilot-mcp connect` 使用 deploy node 上的 pilot MCP：設定由
使用者電腦從 GitHub 取得，經 SSH 在 deploy node 上啟動一個 pilot-cli container 執行。設計見
[規格](../superpowers/specs/2026-10-30-pilot-mcp-remote-access-spec.md)。

## 0.5 目前有效的事實快照

| 項目 | 狀態 |
|---|---|
| 最新驗證 | 2026-10-30，tested commit `4ff4fc7`（tree `994e2354`），[evidence](../evidence/mcp-remote-access/2026-10-30-4ff4fc7.md) |
| 驗證 target | 拋棄式 vm-target（Ubuntu 24.04 golden），已刪除；inventory 只有 `all` 一台 host |
| 結果 | fixture `--check --diff` 對全新 VM 通過；fixture 冪等（第二次 `changed=0`）；E2E 4/4 PASS；`pilot-mcp doctor` 全部 pass；Claude Code `claude mcp get` 為 `✔ Connected` |
| 真實 deploy node | 尚未依本 runbook 設定（由操作者決定時機，規格 §16） |
| 外部 state | 每個環境的 `<env-root>/<env>/.vault/`：Ansible 用的 SSH key 與 `main.yaml` 等；MCP 以唯讀掛載，不讀寫 secret 值 |
| 對齊決定 | 不適用：本功能不是 Ansible 元件，沒有 spec §1 Targets table |

## 1. 為什麼

舊做法（直接 `ssh … docker run …`，把 deploy node 上一個設定目錄掛進 container）在設定改成「依環境分目錄、
workspace 只在 GitHub、`.vault` 與 `.pilot-data` 另外存放」後已無法使用，而且預設開啟 raw 指令與寫入權限。
新做法：
- 設定的版本來自 GitHub，每個 session 固定一個 commit。
- secret 留在 deploy node，以唯讀掛載提供。
- 只開放 observe 與 edit。
- deploy node 上每個 session 只啟動一個 container。

## 2. Deploy node 設定（操作者）

持有這個帳號 SSH key 的人等同 deploy node 的 root（帳號在 `docker` group）。observe/edit 與環境的限制只來自
使用者端 profile（規格 §0 D5）。

1. 以包含 `pilot mcp remote` 的 commit build pilot-cli image，送到 deploy node：

   ```bash
   make pilot-cli-image PILOT_CLI_IMAGE=<repo>:<tag>
   docker save <repo>:<tag> -o <image-file>
   # 在 deploy node 上（root）：
   docker load -i <image-file>
   ```

   確認 image 支援遠端協定：

   ```bash
   docker run --rm --pull never --log-driver none --entrypoint /usr/local/bin/pilot <repo>:<tag> mcp remote version
   ```

   輸出應為 `{"protocol":"pilot-mcp-remote/v1",…}`。

2. 建立專用帳號，登記使用者的公鑰（每行前面加 `restrict`）。在 deploy node 上以 root 執行：

   ```bash
   useradd -m -s /bin/bash -G docker <mcp-account>
   install -d -m 0700 -o <mcp-account> -g <mcp-account> /home/<mcp-account>/.ssh
   printf 'restrict %s\n' '<public-key>' > /home/<mcp-account>/.ssh/authorized_keys
   chown <mcp-account>:<mcp-account> /home/<mcp-account>/.ssh/authorized_keys
   chmod 600 /home/<mcp-account>/.ssh/authorized_keys
   ```

   帳號的 login shell 必須相容 POSIX sh；shell 啟動檔不得輸出到 stdout，也不得讀取 stdin。

3. 既有的 `<env-root>/<env>/.vault/` 與 `<env-root>/<env>/.pilot-data/` 不需要搬動；不需要建立其他目錄。

撤銷某人的存取：刪掉他在 `authorized_keys` 的那一行。

## 3. 使用者端設定

1. 從 pilot repo build `pilot-mcp`（Linux 與 macOS 都可以）：

   ```bash
   go build -o <bin-dir>/pilot-mcp ./cmd/pilot-mcp
   ```

2. 在 `~/.ssh/config` 為 deploy node 設一個 alias（`User <mcp-account>`、`IdentityFile <key>`），並先 `ssh` 一次
   把 host key 存進 `known_hosts`。確認非互動 ssh 沒有輸出：

   ```bash
   ssh -T <ssh-alias> true | wc -c
   ```

   應為 `0`。

3. 寫 `~/.config/pilot-mcp/profiles.yaml`（權限 `600`），每個「環境 × mode」一個 profile：

   ```yaml
   version: 1
   profiles:
     <profile>:
       source:
         url: https://github.com/<org>/<config-repo>
         ref: main
         subdir: <env 目錄>
       target:
         ssh_host: <ssh-alias>
         env: <env>
         env_root: <env-root>
         image: <repo>:<tag>
       mode: observe
       timeouts:
         git_seconds: 60
         ssh_seconds: 15
   ```

   本機 git 必須能非互動讀取設定 repo（SSH key 已載入 ssh-agent，或 HTTPS 有 credential helper，例如 `gh`）。

4. 檢查：

   ```bash
   <bin-dir>/pilot-mcp doctor --profile <profile>
   ```

   六項（profile、git、snapshot、remote-version、session、mcp-tools）都應為 `pass`。

5. 加到 coding agent：

   ```bash
   claude mcp add --transport stdio --scope user <name> -- <bin-dir>/pilot-mcp connect --profile <profile> --image <repo>:<tag>
   claude mcp get <name>
   codex mcp add <name> -- <bin-dir>/pilot-mcp connect --profile <profile> --image <repo>:<tag>
   ```

   `claude mcp get` 應顯示 `✔ Connected`。Codex 要在 `~/.codex/config.toml` 的 `[mcp_servers.<name>]` 加
   `startup_timeout_sec = 90`。Crush 的設定格式見規格 §10（未實跑）。

## 4. Edit 變更送回 GitHub

edit profile（`mode: edit`）的 session 結束後，把變更寫進設定 repo 的乾淨 clone，自行審核、commit、開 PR：

```bash
<bin-dir>/pilot-mcp changes --profile <edit-profile> --into <clone>
```

（2026-10-30 的驗證以 E2E 測試呼叫同一個函式實跑；CLI 子指令本身沒有對 VM 實跑。）

vault、roster 密碼與 roster 本身都不能經 edit session 修改（規格 §8）：vault 由操作者在 deploy node 上維護，
roster 直接在設定 repo 送 PR。

## 5. 疑難排解

`pilot-mcp` 在 stderr 印一行 `pilot-mcp: <CODE>: <訊息>`，結束碼見規格 §11。

| code | 常見原因 |
|---|---|
| `GIT_AUTH_REQUIRED` | 本機 git 無法非互動取得設定 repo：ssh-agent 沒載入 key、HTTPS 沒有 credential helper（`gh` 找不到自己的設定目錄時也會如此） |
| `SSH_FAILED` | host key 不在 `known_hosts`、key 不對、連不到 deploy node |
| `DOCKER_FAILED` | deploy node 上沒有該 image tag，或帳號不在 `docker` group |
| `REMOTE_RUNTIME`（提示 image 太舊） | image 的 pilot 沒有 `mcp remote`；重新 build 並載入 image |
| `REMOTE_REJECTED: ENV_MISMATCH` | profile 的 `env` 與設定裡主機的 `env` 不同 |
| `REMOTE_REJECTED: SECRET_POLICY_VIOLATION` | 設定的 `group_vars`/`host_vars` 有明文 secret（訊息只列檔案、欄位與行號） |
| `REMOTE_REJECTED: PATH_OUT_OF_SCOPE` | 設定裡有字面路徑指向 `/pilot/vault`、`/pilot/data` 或 `/tmp/pilot-mcp`；改用 `/pilot/config/...` |
| `CHANGESET_CONFLICT` | `--into` 不是乾淨的最上層 clone、origin 不同、HEAD 在 base 之後改過同一個檔案，或新增的路徑在 clone 裡已經存在（目錄，或 macOS 上大小寫／Unicode 拼法不同的同名檔） |
| `CHANGESET_INVALID`（`changes`） | 修改後的設定會被下一個 session 拒絕（訊息列出 import 的 code 與檔案，包含沒被修改、但 image 升級後才被拒絕的檔案），或修改含只改大小寫的改名、目錄與檔案互換。這類修改帶不回：在設定 repo 修正或直接做，再用新的 edit session 重做 |

## 6. 測試

不用 Docker 的整合測試（本機 sshd）：

```bash
make mcp-remote-test
```

端對端（拋棄式 vm-target、真實 Docker 與 image）：

```bash
pilot vm-target up --name <vm> --memory 4096
pilot vm-target run --name <vm> playbooks/apply/docker-apply.yml -e target_group=all
pilot vm-target run --name <vm> playbooks/test/fixtures/mcp-remote-access-setup.yml -e @<fixture-vars.json>
PILOT_MCP_E2E=1 PILOT_MCP_E2E_SSH_CONFIG=<ssh-config> PILOT_MCP_E2E_SSH_HOST=<alias> \
  PILOT_MCP_E2E_ADMIN_HOST=<root-alias> PILOT_MCP_E2E_TARGET_IP=<vm-ip> \
  PILOT_MCP_E2E_ENV_ROOT=/srv/pilot-mcp-e2e/env PILOT_MCP_E2E_IMAGE=<repo>:<tag> \
  PILOT_MCP_E2E_IMAGE_ALIAS=<repo>:<tag2> PILOT_MCP_E2E_MANAGED_USER=mcp-managed \
  go test -count=1 -timeout 20m -run TestE2E ./internal/mcpclient
pilot vm-target down --name <vm>
```

`<fixture-vars.json>` 的欄位見 fixture 檔頭（image tarball、image tag、client 與 managed-host 的公鑰、managed-host
私鑰路徑），全部用測試值。
