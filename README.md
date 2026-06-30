# pilot

> **你的 Ansible AI 副駕駛 — 由本機 LLM 驅動、每一次寫入都經過人類審批**

`pilot` 是一個以 Go 撰寫的 CLI 工具，把本地或雲端的 Ollama 模型接到 Ansible 工作流上。LLM 負責推理失敗原因、提出修復、產生 playbook，但**任何會動到系統的動作都會先變成一個「提議」(proposal) 等你按 y/N 確認**。

```
┌─────────────────┐
│      pilot      │  ← Go 編譯出的單一二進位（這個 repo）
│  (ReAct agent)  │
└──────┬──────────┘
       │ HTTP /api/chat（function calling）
       ▼
┌─────────────────┐
│     Ollama      │  ← 本機或 :cloud 模式
│  qwen3.5:cloud  │
└─────────────────┘
       ▲
       │ 提議：每一次寫入都需要人類 y/N
       │
┌──────┴──────────┐
│  人類（你）     │
└─────────────────┘
```

---

## 目錄

- [pilot 是什麼、能做什麼、不能做什麼](#pilot-是什麼能做什麼不能做什麼)
- [環境需求](#環境需求)
- [安裝](#安裝)
- [5 分鐘快速上手](#5-分鐘快速上手)
- [指定 Playbook 的三種方式](#指定-playbook-的三種方式)
- [📋 Spec-driven 工作流（寫需求 → 套用 → 驗證）](#-spec-driven-工作流寫需求--套用--驗證)
- [核心概念](#核心概念)
- [完整指令參考](#完整指令參考)
- [設定檔 `config.yaml`](#設定檔-configyaml)
- [安全防護](#安全防護)
- [進階主題](#進階主題)
- [常見問題 FAQ](#常見問題-faq)
- [延伸閱讀](#延伸閱讀)
- [Sandbox 模式（Docker 容器）](#sandbox-模式docker-容器)
- [測試指南 TESTING.md](./TESTING.md) — 開發 / CI / AI agent 跑測試的完整流程

---

## pilot 是什麼、能做什麼、不能做什麼

### 它能做什麼

- 讀取 Ansible playbook、日誌、InSpec 報告
- 請 LLM 診斷失敗原因並提出具體修復
- 直接生成符合 CIS Benchmark 的 Ansible task YAML
- **每個寫入操作都先變成「提議」**：你按 `y` 通過、`n` 拒絕、還能看詳情或整批放棄
- 把所有提議 + 決策同時存進 SQLite 與可進 Git 的 YAML，方便稽核
- 把 Ansible 官方文件做成**離線全文索引**（bleve BM25，無需 embedding model），不用再連 devdocs.io

### ⚠️ 它**不會**做的事

- **不會繞過審批。** `--auto-approve=medium` 只是選項，且即使開了，`run_ansible` 在 apply 模式下會被自動升級為 `high` 風險，仍然需要你按 `y`。不確定時請保持 `never`。
- **不會亂開 shell。** `run_command` 採白名單制（見 [安全防護](#安全防護)）。
- **不會讀敏感檔。** `/etc/shadow`、私密金鑰、`/proc`、`/sys` 一律拒絕。
- **執行期不需要連網。** RAG 索引建好後，整套 agent 流程都能離線跑。

---

## 環境需求

| 元件 | 最低版本 | 為什麼需要 | 怎麼裝 |
|------|----------|------------|--------|
| **Go** | 1.22+ | 編譯 `pilot` 二進位 | https://go.dev/dl/ |
| **Ollama** | 0.5+ | 提供 LLM 推理；embedding 僅 playbook 索引需要 | https://ollama.com/download |
| **Ansible** | ansible-core 2.14+ | 執行 playbook 與 `ansible-doc` | `pip install ansible-core` 或 `apt install ansible` |
| **磁碟空間** | ~2 GB | 存放 RAG 索引（~80 MB）+ 模型 | — |
| **記憶體** | 8 GB+（跑本機 LLM 時）| 本機模型推薦 16 GB | — |

> 不想跑本機 LLM？把 `model` 設成 `qwen3.5:cloud` 走 Ollama 的雲端模型，就不需要 GPU。

---

## 安裝

### 1. 啟動 Ollama 並拉模型

```bash
# 啟動 Ollama 服務（背景執行）
ollama serve &

# LLM：選一個，推薦其中之一
ollama pull qwen3.5:cloud    # 雲端模型，不吃顯存
# 或
ollama pull qwen2.5:7b      # 本機 7B 模型（需 ~5 GB RAM）

# Embedding 模型（**只有**要索引自家 playbook 才需要；Ansible 文件
# 索引已改用 bleve BM25，不再需要 embedding）
# ollama pull nomic-embed-text
```

### 2. 編譯 pilot

```bash
git clone <repo-url> pilot
cd pilot
make build          # 產出 ./pilot 二進位
```

### 3. 確認環境健康

```bash
./pilot doctor
```

成功時會看到所有 7 項檢查都 `OK`：

```
🏥 Starting pilot self-diagnosis...
======================================
[1] Checking Ollama server connection at http://localhost:11434... OK
[2] Checking LLM model "qwen3.5:cloud"... OK
[3] Checking Embedding model "nomic-embed-text" (for playbook index)... OK
[4] Checking Ansible installation... OK (ansible [core 2.18.5])
[5] Checking 'ansible-playbook' executable... OK
[6] Checking SQLite database at ~/.local/share/pilot... OK
[7] Checking RAG docs index at .../docs.bleve... WARNING (not built yet)
======================================
✓ All critical checks passed! pilot is ready to fly. 🚀
```

第 7 項 WARNING 是正常的 — 還沒建過 RAG 索引。

### 4. （建議）建 RAG 索引

第一次跑需要 5–15 分鐘（CPU）或 1–3 分鐘（GPU），之後就會走快取：

```bash
./pilot index-docs
```

---

## 5 分鐘快速上手

```bash
# ① 純分析，不會改系統 — 拿一條失敗日誌讓 LLM 給建議
./pilot diagnose examples/fake-ansible-failure.log

# ② 互動式聊天 — 想做什麼直接用中文講
./pilot chat
> 幫我檢查這台機器是否符合 CIS 5.2.1（停用 root SSH 登入）
> exit

# ③ 對單一 playbook 跑 agent — 提議 → 你審批 → 真的套用
./pilot run examples/disable-root-ssh.yml
```

第一次跑 `pilot run` 時，你會看到類似這樣的畫面（這就是 **Proposal 審批**）：

```
[proposal] run_ansible (risk: medium)
  Playbook: examples/disable-root-ssh.yml
  Mode:    --check --diff（先預演，不直接套用）
  Reason:  Disable PermitRootLogin 以符合 CIS 5.2.1
  Diff:    + PermitRootLogin no
           - PermitRootLogin yes

  Approve? [y/N/d(etails)/a(bort)]
> y
✓ Approved. Executing…
```

---

## 指定 Playbook 的三種方式

`pilot run` 接受**三種互斥的指定方式**：

### ① 位置參數（最直觀）

```bash
pilot run playbooks/ssh.yml
```

### Inventory / Limit 的優先順序

`pilot run` 解析 inventory 的順序（高優先到低）：

1. CLI 旗標 `-i` / `--inventory` 或 `--limit`
2. `ANSIBLE_INVENTORY` 環境變數（**僅** inventory；limit 沒有 env fallback，因為它是 per-run 概念）
3. JSONL stdin 內每行的 `inventory` / `limit` 欄位
4. 都不設時 → 用 playbook 自己的 `hosts:` clause

```bash
# 環境變數（CI 常用）
ANSIBLE_INVENTORY=/etc/ansible/prod.ini pilot run --discover playbooks/

# 明確旗標蓋過 env
pilot run -i /etc/ansible/staging.ini --limit web01 site.yml

# JSONL 行內 inventory 蓋過 env
echo '{"playbook":"/p1.yml","inventory":"/override.ini"}' | ANSIBLE_INVENTORY=/from-env.ini pilot run --from-stdin
```

### ② 從 stdin 讀（適合 CI / 動態生成）

```bash
# 純路徑，每行一個
ls playbooks/*.yml | pilot run --from-stdin

# JSONL：可指定每本的 inventory / limit
pilot run --from-stdin <<'EOF'
{"playbook":"/p1.yml","inventory":"/inv/prod","limit":"web01"}
{"playbook":"/p2.yml","limit":"db"}
EOF
```

### ③ 用 glob 或目錄自動探索

```bash
pilot run --discover 'playbooks/cis-*.yml'   # glob
pilot run --discover playbooks/               # 整個目錄
```

當指定多本時，pilot 會以**批次**執行：

```
▶ Batch adaf8e41 — 2 playbooks
  [1/2] ✓ ssh.yml
  [2/2] ✗ sudo.yml  (1 proposal rejected)
✓ Batch complete: 1/2 succeeded
```

加上 `--fail-fast` 會在第一本失敗時立刻中止。

### JSONL 完整欄位

JSONL stdin 的每行可帶 11 個 ansible-playbook 旗標（除了 `playbook` 是必填，其他都選填）：

| 欄位 | 對應旗標 | 型別 |
|------|----------|------|
| `playbook` | （位置參數） | string, **必填** |
| `inventory` | `-i` | string |
| `limit` | `--limit` | string |
| `tags` | `--tags` | string[] |
| `skip_tags` | `--skip-tags` | string[] |
| `extra_vars` | `-e @<tmpfile>` | object（巢狀 JSON 會序列化到暫存檔） |
| `extra_vars_raw` | `-e` | string（與 `extra_vars` 互斥） |
| `become` | `--become` | bool |
| `forks` | `--forks` | int |
| `user` | `--user` | string |
| `connection` | `--connection` | string，enum: `local / ssh / paramiko / docker` |
| `vault_password_file` | `--vault-password-file` | string（必須在 allowed_roots 內） |
| `diff` | `--diff` | bool |
| `timeout` | （per-run timeout，秒） | int |
| `flush_cache` | `--flush-cache` | bool |

**範例：**

```bash
pilot run --from-stdin <<'EOF'
{"playbook":"/hardening/ssh.yml","inventory":"/inv/prod.ini","limit":"webservers","tags":["cis"],"become":true,"forks":10}
{"playbook":"/hardening/sudo.yml","extra_vars":{"env":"prod","audit_level":2},"timeout":300}
EOF
```

> 所有選填欄位都使用 `*T` 指標或 `omitempty` 標籤 — 沒帶的欄位會是零值，**對應旗標不會進入 argv**。這讓舊版 JSONL（只有 `playbook`）繼續可用。

---

## 核心概念

| 名詞 | 意義 |
|------|------|
| **Proposal（提議）** | LLM 想呼叫某個工具時，會先建立一個 proposal，等你按 `y/N` 決定。**這是 pilot 最核心的安全機制。** |
| **Risk level（風險分級）** | `low`（純資訊）、`medium`（改設定）、`high`（停服務 / 重啟）。`--auto-approve` 用這個分級決定是否自動放行。 |
| **Plan（計畫）** | 一組有序操作的批次提議。適合「我想一次做完這五件事」的情境。 |
| **Dry-run（預演）** | `--dry-run-all` 走完整個 agent 流程但**不動系統**，所有 mutation 工具會被攔截並標記為 `[DRY-RUN] would call X`。 |
| **RAG（檢索增強生成）** | pilot 會把 Ansible 模組文件 + 你的 playbook 切成 chunk，建成本地索引（Ansible 文件用 bleve BM25，playbook 用 embedding），LLM 要查語法時就從本地撈。 |
| **Sanitizer（脫敏器）** | 在每次 LLM 來回前自動把密碼、token、私鑰、`/etc/shadow` 行、email 等敏感字串遮蔽掉。 |

---

## 完整指令參考

### 全域旗標（每個子命令都能用）

| 旗標 | 預設值 | 說明 |
|------|--------|------|
| `--config <path>` | `~/.config/pilot/config.yaml` | 指定設定檔 |
| `--ollama <url>` | `http://localhost:11434` | Ollama server URL |
| `--model <name>` | `qwen3.5:cloud` | LLM 模型名稱（要本機就跑 `qwen2.5:7b`） |
| `--stream` | `true` | 把 LLM token 即時串流到 stderr |
| `--auto-approve <lvl>` | `never` | `low` / `medium` / `never`。⚠️ `medium` 會自動通過所有 low/medium 提議，**包含寫入類工具**。Apply-mode 的 playbook 一律升級為 `high`，仍需手動審批。 |
| `--data-dir <path>` | `~/.local/share/pilot` | 提議、SQLite、生成 playbook 的存放位置 |
| `--tui` | `false` | **Opt-in**：啟動互動式 Bubbletea TUI（須有 TTY；無 TTY 時退回 promptui）。**預設為 off**，CI / agent / SSH 用者更乾淨 |
| `--no-tui` | `false` | `DEPRECATED` 別名，等同「不傳 `--tui`」。留一個版本給舊腳本用 |

### `pilot run` — 對 playbook 跑 agent

```bash
pilot run [<playbook>] [goal]
```

第二個位置參數 `goal` 是選填的自然語言目標，會作為額外 context 餵給 LLM。

| 旗標 | 預設值 | 說明 |
|------|--------|------|
| `-i, --inventory` | — | Ansible inventory 檔案 |
| `--limit` | — | 限定 host pattern |
| `--from-stdin` | `false` | 從 stdin 讀 playbook 路徑（自動偵測 JSONL） |
| `--discover` | — | glob pattern 或目錄 |
| `--dry-run-all` | `false` | 走完整流程但不動系統 |
| `--skip-syntax-check` | `false` | 跳過 `ansible-playbook --syntax-check` 前置檢查 |
| `--fail-fast` | `false` | 搭配 `--from-stdin` / `--discover` 使用，第一本失敗就停 |
| `--execution-mode` | `serial` | `serial` / `parallel`（parallel 為實驗性，採 `MaxConc` 信號量） |
| `--no-index` | `false` | 跳過文件索引新鮮度檢查（不要自動重建） |
| `--no-index-on-start` | `false` | 索引過期時警告但不重建 |
| `--strict-index` | `false` | 索引過期時直接報錯退出（不重建） |

**範例**

```bash
# 基本
pilot run site.yml

# 限定主機
pilot run -i inventory/prod site.yml --limit web01

# 預演模式
pilot run site.yml --dry-run-all

# 批次
pilot run --discover 'playbooks/cis-*.yml' --fail-fast
```

### `pilot chat` — 互動式 REPL

```bash
pilot chat
pilot chat --inventory /etc/ansible/prod.ini --limit webservers
```

進入多輪對話。輸入 `exit` 或按 `Ctrl-D` 離開。

```
💬 pilot chat (type 'exit' to quit)

> 這台主機的 SSH 設定符合 CIS 嗎？
> 幫我列舉所有 Permit* 開頭的設定
> exit
```

**Session 預設值（`--inventory` / `--limit`）**

`pilot chat` 可帶兩個 session-level 預設值，會以**雙管齊下**方式套用：

1. **System prompt 注入**：LLM 會在 system prompt 看到「Default inventory: ...」提示，主動在 `run_ansible` / `apply_patch` 工具呼叫裡帶上
2. **工具層 deterministic 補上**：如果 LLM 漏帶 `inventory` 或 `limit` 參數，工具會在執行前自動補上預設值

```bash
# 預設所有 run_ansible 都用 prod inventory、只跑 webservers group
pilot chat --inventory /etc/ansible/prod.ini --limit webservers
> 把 PermitRootLogin 關掉  # LLM 不會主動問 inventory，因為預設已經有了
```

> 預設值必須落在 `allowed_playbook_roots` 內，否則 LLM 端 `run_ansible` 仍會拒絕（fail-closed）。

### `pilot diagnose` — 一鍵分析失敗日誌

```bash
pilot diagnose <log-file>             # 純文字日誌
pilot diagnose --stdin                # 從 stdin 讀 JSON（給 Ansible callback plugin 用）
```

| 旗標 | 說明 |
|------|------|
| `--stdin` | 從 stdin 讀 JSON 格式的 failure context |
| `-q, --quiet` | 只輸出診斷結果，不要 header |
| `--output` | `stdout`（預設）/ `stderr` |

**範例**

```bash
# 拿到一份失敗日誌時
pilot diagnose /var/log/ansible-fail.log
```

### `pilot doctor` — 自我診斷

```bash
pilot doctor
```

依序檢查 Ollama 連線、LLM 模型、playbook 用的 embedding 模型（若需要）、`ansible` / `ansible-playbook` 執行檔、SQLite、RAG 索引。出問題先跑這個。

### `pilot index-docs` — 建/重建 Ansible 文件 RAG 索引

```bash
pilot index-docs
```

第一次跑約 30–90 秒（bleve BM25 索引，無需 embedding），之後若 ansible-core 沒改版會直接跳過。

| 旗標 | 說明 |
|------|------|
| `--refresh` | 強制重建 |
| `--no-save` | 不寫到磁碟（測試用） |
| `--quiet` | 不輸出進度 |
| `--embedding-model` | **已停用**（保留向後相容；docs 索引不再需要 embedding）|

### `pilot index-playbooks` — 索引你自己的 playbook

```bash
pilot index-playbooks [dir...]            # 預設掃 ./playbooks 與 ~/.local/share/pilot/playbooks
pilot index-playbooks ~/my-playbooks/ --recursive --refresh
```

| 旗標 | 說明 |
|------|------|
| `--recursive` | 遞迴掃子目錄 |
| `--refresh` | 丟掉舊索引從頭建 |
| `--quiet` | 靜默模式 |

### `pilot search-docs` — 查 RAG 索引

```bash
pilot search-docs "disable root ssh login"
pilot search-docs "auditd rule syntax" --k 3 --source modules
```

| 旗標 | 預設值 | 說明 |
|------|--------|------|
| `--k` | `5` | 回傳幾筆結果 |
| `--source` | `all` | `modules` / `playbooks` / `all` |

### `pilot list-runs` — 看歷史 run

```bash
pilot list-runs                            # 最近 20 筆
pilot list-runs --limit 100                # 多看一點
pilot list-runs --batch adaf8e41           # 只看某個批次
```

### `pilot show-plan <plan-id>` — 看批次計畫

```bash
pilot show-plan <plan-id>
```

顯示計畫的標題、摘要、底下所有操作的風險分級與理由。

### `pilot models` — 看 Ollama 裡有哪些模型

```bash
pilot models
```

### `pilot version` — 印版本

```bash
pilot version
# pilot 0.2.0
```

---

## 設定檔 `config.yaml`

預設讀取 `~/.config/pilot/config.yaml`（可用 `--config` 改位置）。完整範例：

```yaml
# pilot config example
# Copy to ~/.config/pilot/config.yaml

ollama_url: http://localhost:11434
model: qwen3.5:cloud
max_iterations: 20            # 單次 agent loop 最多幾輪
max_concurrent: 5             # 平行模式下的併發上限
auto_approve: never           # never | low | medium

data_dir: ~/.local/share/pilot

# === 工具白/黑名單（縱深防禦） ===

# Block specific tools from being callable (defense in depth)
# blocked_tools:
#   - run_command

# Allow only these tools (overrides the default set)
# allowed_tools:
#   - read_file
#   - ask_user
#   - generate_playbook

# === 客製系統提示詞（可選） ===
# system_prompt: |
#   You are pilot, an AI co-pilot for Ansible automation.
```

> **更進階的白名單設定**（`AllowedCommands` / `AllowedReadPaths` / `AllowedPlaybookRoots` / `CustomRedactRules`）放在結構化 `config` 區段，詳見 [DEVELOPER.md](./DEVELOPER.md)（開發者導向）。

### 主要欄位速查

| 欄位 | 型別 | 預設 | 說明 |
|------|------|------|------|
| `ollama_url` | string | `http://localhost:11434` | Ollama 服務位址 |
| `model` | string | `qwen3.5:cloud` | LLM 模型名 |
| `max_iterations` | int | `20` | 單一任務最多推理幾輪 |
| `max_concurrent` | int | `5` | `--execution-mode parallel` 下的 goroutine 上限 |
| `auto_approve` | string | `never` | `never` / `low` / `medium` |
| `data_dir` | path | `~/.local/share/pilot` | 提議、SQLite、playbook 存放處 |
| `system_prompt` | string | 內建 | 覆蓋 LLM 的 system prompt |
| `allowed_tools` | []string | （全開）| 白名單，設定後**只剩**這些能用 |
| `blocked_tools` | []string | （無） | 黑名單，**永遠**不能用 |

---

## 安全防護

pilot 的安全是**多層防禦**，不依賴 LLM 自我約束：

### 1. Proposal 審批（最高層）

任何工具呼叫都先變成 Proposal，你必須在 TUI/CLI 上按 `y/N`。`--auto-approve` 只是把這層**部分自動化**，並未移除。

### 2. `run_command` — 結構化 argv 白名單

pilot **不是**用 `bash -c` 跑命令。輸入會被解析成 argv，只要含有 `;` `&&` `\|\|` `\|` `` ` `` `$()` `>` `<` `&` `\n` 這類 metacharacter 就**直接拒絕**。即使解析成功，argv 還要對上一個型別化的 `CmdSpec` 白名單：

| 指令 | 允許的參數 |
|------|------------|
| `uname` | `-a` |
| `systemctl` | `status` / `is-active` / `is-enabled` |
| `sysctl` | 單一 `net.` / `kernel.` / `vm.` / `fs.` 開頭的 key（拒絕 `-w` 等 flag）|
| `ip` | `addr show` / `route show` |
| `ufw` | `status` |
| `dpkg` | `-l` |
| `apt` | `list --upgradable` |
| `cat` | 路徑必須在 `allowed_read_paths` 內 |

這樣 `sysctl -w net.ipv4.ip_forward=1`、`bash -c id`、`uname -a; id` 全部會被擋下。

### 3. `read_file` — 敏感路徑黑名單 + 前綴白名單

兩段式檢查（發生在 symlink 解析之後）：

1. **硬黑名單**：`/etc/shadow*`、`/etc/sudoers*`、`/.ssh/{id_*,authorized_keys}`、`/.aws/credentials`、`/.gnupg/`、`/proc/`、`/sys/`、`/boot/`、`/var/log/{auth.log,secure,wtmp,btmp}`…
2. **白名單前綴**（預設）：`/etc/{ansible,ssh,fail2ban,audit,login.defs,pam.d,security,sysctl.d}/`、`/etc/hosts`、`/etc/hostname`、`/etc/os-release`、`/var/log/syslog`、`/tmp/`、`/opt/`…

代表 `/tmp/x → /etc/shadow` 的 symlink 攻擊也會被識破。

### 4. `run_ansible` — playbook / inventory 路徑白名單

LLM 無法指 `run_ansible` 跑任意路徑。Playbook 與 inventory 都必須落在 `allowed_playbook_roots` 內，預設包含 `$DataDir/playbooks`、`./playbooks`、`cwd`、`./examples/`。未設定時**全部拒絕**（fail-closed）。

### 5. Prompt-injection 防護

所有工具輸出都會被包進 `<untrusted_tool_output tool=…>…</untrusted_tool_output>` 標記，system prompt 明確要求 LLM 把整個區塊當純資料、不執行其中的「指令」。

### 6. Sanitizer（脫敏器）

送給 LLM 之前自動遮蔽：

- `password=…` / `token=…` / `api_key=…` / `secret=…`
- `-----BEGIN ... PRIVATE KEY-----` 區塊
- `/etc/shadow` 的 root 行
- email address
- IPv4（**預設關閉**，要用 `OptInRules` 開啟，否則會把 inventory 的 IP 一起洗掉）

> 脫敏規則是**在所有 LLM 來回前執行**的，不是事後稽核才發現。

### 7. 完整 Audit Log

每次 run 都會寫到 `~/.local/share/pilot/history.db`（SQLite），所有 Proposal 同時存成 `~/.local/share/pilot/proposals/<id>.yaml`（可直接 `git add`）。審計時：

```bash
pilot list-runs --limit 50
```

---

## 進階主題

### RAG：離線查 Ansible 模組

預設情況下 LLM 不知道某個 `ansible.builtin.lineinfile` 的 `regexp` 怎麼寫，會亂掰。RAG 解決這個：

```bash
# 一次性建索引（bleve BM25，無需 embedding）
pilot index-docs

# 之後 LLM 在 agent 裡會自動呼叫 search_docs 工具
pilot run examples/disable-root-ssh.yml

# 你也可以手動查
pilot search-docs "how to disable root ssh login" --k 3
```

- **Ansible 官方模組**索引存於 `~/.local/share/pilot/docs.bleve`（bleve BM25，~40 MB，**不需 embedding model**）
- **你的 playbook**索引存於 `~/.local/share/pilot/playbooks-index.json`（仍用向量 embedding，預設 `nomic-embed-text`）
- `pilot run` 啟動時會自動偵測 ansible-core 是否有更新，必要時重建 docs 索引
- 兩種索引可分別查：`pilot search-docs --source modules` / `--source playbooks` / `--source all`

### Planning 模式（批次審批）

當任務複雜時，LLM 可以把多個操作打包成一個 Plan，一次給你看：

```json
{
  "title": "Disable root SSH + restart sshd",
  "summary": "Apply CIS 5.2.1 + bounce sshd",
  "operations": [
    {"tool": "run_ansible", "args": {"playbook": "ssh.yml"},
     "rationale": "Disable PermitRootLogin", "risk_level": "medium"},
    {"tool": "run_ansible", "args": {"playbook": "restart.yml"},
     "rationale": "Restart sshd", "risk_level": "high"}
  ]
}
```

審批後內部每個 operation 會被當成個別 Proposal 跑（apply-mode 仍升級為 high）。

### Dry-run 模式

兩種用途：

- `--dry-run-all`：走完整 agent 流程，但任何會動系統的工具呼叫都會被攔截成 `[DRY-RUN] would call X`。
- 內建的 `ansible-playbook --check --diff`：**即使 LLM 要求 apply**，`run_ansible` 也會被強制加上 `--check --diff`，先給你看 diff 才放行。

想真的套用，要 LLM 明確呼叫 `apply_playbook`，這個會被升級為 high 風險提議。

### 平行化（實驗性）

```bash
pilot run --execution-mode parallel --discover 'playbooks/*.yml'
```

會用 goroutine 跑多個 playbook，併發上限由 `max_concurrent` 控制（Channel 信號量）。互動式 TUI 內部有 mutex 防止輸出混亂。

### Auto-Rollback

當 `run_ansible` 失敗時，pilot 會問你要不要一鍵 rollback：

```
[proposal] run_ansible (risk: high) — FAILED
  ssh.yml  failed on host web01

Rollback? [Y/n]
> y
[proposal] generate_rollback (risk: low)
  Generating reverse playbook from last successful snapshot…
✓ Rollback applied.
```

### 索引管理

| 旗標 | 行為 |
|------|------|
| `--no-index` | 跳過文件索引新鮮度檢查 |
| `--no-index-on-start` | 過期時警告但不重建 |
| `--strict-index` | 過期時直接報錯退出 |

CI / 正式環境建議搭配 `--strict-index`，避免模型用舊文件給出過時語法。

---

## 常見問題 FAQ

<details>
<summary><b>Q：跑 <code>pilot run</code> 一直卡在「連不到 Ollama」</b></summary>

依序檢查：

1. `ollama serve` 還在跑嗎？
   ```bash
   curl http://localhost:11434/api/tags   # 應該回 JSON
   ```
2. 跑一次 `pilot doctor` 看完整狀態。
3. Ollama 跑在別台？用 `--ollama http://192.168.x.x:11434` 或寫進 `config.yaml` 的 `ollama_url`。
</details>

<details>
<summary><b>Q：<code>pilot index-docs</code> 跑到一半失敗 / 跑超久</b></summary>

- **首次跑約 30–90 秒**（bleve BM25，不再需要 embedding 推論）。如果超過幾分鐘才奇怪。
- 中斷了就重跑，pilot 會接續（或加 `--refresh` 從頭）。
- 不再需要 `qwen3-embedding` 模型；只有索引自家 playbook 才需要 embedding。
</details>

<details>
<summary><b>Q：<code>read_file</code> 被拒絕「path is blocked」</b></summary>

pilot 預設只允許讀保守白名單。要讀其他路徑，編輯 `config.yaml` 加上 `allowed_read_paths`（在結構化 config 區段，見 [DEVELOPER.md](./DEVELOPER.md)）。

但**敏感路徑（`/etc/shadow`、私鑰、`/proc`、`/sys`）永遠不能加**。
</details>

<details>
<summary><b>Q：<code>run_ansible</code> 拒絕執行我的 playbook</b></summary>

路徑不在 `allowed_playbook_roots` 內。預設白名單只有：

- `$DataDir/playbooks`（`~/.local/share/pilot/playbooks`）
- `./playbooks`
- `cwd`
- `./examples/`

把 playbook 放到這些目錄，或在 `config.yaml` 自訂 `allowed_playbook_roots`。
</details>

<details>
<summary><b>Q：為什麼 LLM 提的 apply 動作還是要我按 y？明明已經 `--auto-approve=medium`</b></summary>

這是**故意的安全機制**。`run_ansible` / `apply_playbook` 在 apply-mode 下會被自動升級為 `high` 風險，**不受** `auto-approve=medium` 影響。要完全無人值守（極度不推薦）就…目前沒有，這層保護是寫死的。
</details>

<details>
<summary><b>Q：我誤刪了一個服務，pilot 可以還原嗎？</b></summary>

看情境：

- **同一個 run 內失敗**：pilot 會主動問你要不要 rollback（見 [Auto-Rollback](#auto-rollback)）。
- **跨 run / 跨手動操作**：pilot 沒辦法。**強烈建議**正式環境在套用前先做 snapshot（LVM、ZFS、雲端 snapshot 都行），pilot 不是備份工具。
</details>

<details>
<summary><b>Q：怎麼看 LLM 上一輪做了什麼決策？</b></summary>

```bash
# 看所有 run 的清單
pilot list-runs

# 進 SQLite 直接撈
sqlite3 ~/.local/share/pilot/history.db "SELECT id, mode, status FROM runs ORDER BY started_at DESC LIMIT 10;"
```

每個 Proposal 同時存成 YAML：

```
~/.local/share/pilot/proposals/<id>.yaml
```

可以直接 `git init` 這個目錄做版本控管。
</details>

<details>
<summary><b>Q：可以離線用嗎？</b></summary>

可以，但要先**一次性**做兩件事（之後都能離線）：

1. `ollama pull` 你要的模型（雲端模型仍需網路）。
2. `pilot index-docs` 建本地 RAG 索引。

之後整個 agent loop 都不會主動連外網。
</details>

<details>
<summary><b>Q：怎麼換 LLM？想用 Llama 3、Qwen 2.5、Gemma…</b></summary>

```bash
ollama pull llama3.1:8b
```

然後：

```bash
pilot --model llama3.1:8b run examples/disable-root-ssh.yml
```

或寫進 `config.yaml` 的 `model` 欄位。

注意：不是所有模型都支援 function calling。**推薦**：`qwen2.5:7b` 以上、`llama3.1:8b` 以上、`qwen3.5:cloud`。
</details>

<details>
<summary><b>Q：怎麼升級 pilot？</b></summary>

```bash
cd pilot
git pull
make build
./pilot version
```

舊的 `~/.local/share/pilot` 資料會自動沿用（SQLite migration 用 `PRAGMA user_version` 追蹤，**如果新版的 schema 比你的資料新太多，會 fail-closed 提示要升級**，不會偷偷洗掉資料）。
</details>

---

## 延伸閱讀

- 開發者導向的技術文件（架構、API、貢獻流程、安全模型原始碼層級說明）：[DEVELOPER.md](./DEVELOPER.md)
- 實作細節與功能變更紀錄：[implementation_report.md](./implementation_report.md)

---

## 📋 Spec-driven 工作流（寫需求 → 套用 → 驗證）

> 寫 ansible playbook 最痛苦的事不是寫，是**事後才知道 spec 跟實際系統不一致**。
> pilot 把這條鏈接起來：

```
┌───────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  docs/verification│    │ playbooks/      │    │  .verification/ │
│  <feature>.md     │ --→│ verify/         │ --→│ <spec>-<UTC>.  │
│  (人寫：spec)     │    │ <spec>.yml      │    │   {.ndjson,.md}│
└───────────────────┘    └─────────────────┘    └─────────────────┘
                              ↑                       ↑
                              │  generator 1-to-1      │  結構化 verdict
                              └───────────────────────┘
                              pilot spec --generate
                              pilot verify

┌───────────────────────────┐    ┌───────────────────────────┐
│  playbooks/apply/          │    │  ~/.local/share/pilot/    │
│  <spec>-apply.yml          │ --→│  history.db                │
│  (人寫：mutations + block/ │    │  spec_checkpoints table    │
│  rescue with -e params)    │    │  (spec → proposal 追溯)   │
└───────────────────────────┘    └───────────────────────────┘
         ↑                                ↑
         ansible-playbook -i inv.yaml …   SQLite 寫下每次 verdict
```

### 三個產物的分工（必讀）

| 產物 | 誰寫 | 是不是 mutate | 用什麼跑 |
|------|------|--------------|---------|
| `docs/verification/<feature>.md` | **你** | 不 mutate，只是 checklist | `pilot spec --lint` 把關 |
| `playbooks/verify/<feature>.yml` | **generator** (`pilot spec --generate`) | ❌ 純 inspect | `ansible-playbook … verify.yml` 或 `pilot verify` |
| `playbooks/apply/<feature>-apply.yml` | **你**（手寫，但有結構） | ✅ 會改系統 | `ansible-playbook … apply.yml -e patch_stage=…` |

**原則**：inspect 跟 mutate 分開。你看到 `playbooks/apply/*-apply.yml` 就是在動 host；看到 `playbooks/verify/*-yml` 純 read。

> 範例：`docs/runbooks/pam-oidc-sshd.md` 是一份完整的 spec-driven runbook，
> 從寫 spec、generate inspect playbook、手寫 apply playbook、套用到 test-vm、
> 看 SQLite 追蹤 verdict 的 SOP 全在裡面。

### 四個核心命令

#### `pilot spec <spec.md> --lint`
只 parse + lint。不動檔案。修完所有 error 才進下一步。

```bash
pilot spec docs/verification/pam-oidc-sshd.md --lint
# spec Verification Spec — pam-oidc-sshd: 7 rows, 0 findings (0 errors)
```

Lint 規則：
- `ID` 非空 + 唯一 + 符合 `^[A-Za-z][A-Za-z0-9._-]*$`
- `Expected` 必填、**不可**是 vague 詞（`OK` / `合理` / `maybe` 之類）
- `Command` 必填且非空白

#### `pilot spec <spec.md> --generate <out.yml>`
機械化生成 **inspect-only** playbook。直接跑這個最常踩到的坑：

```bash
pilot spec docs/verification/pam-oidc-sshd.md \
    --generate playbooks/verify/pam-oidc-sshd.yml
ansible-playbook -i inventory.yaml \
    playbooks/verify/pam-oidc-sshd.yml    # inspection only，changed=0
```

#### `pilot verify <spec.md> --inventory <yaml> --limit <host>`
對 inventory 跑 spec 7 個 row，比對 expected，回寫 SQLite + 落 `.verification/`。

```bash
pilot verify docs/verification/pam-oidc-sshd.md \
    -i inventory.yaml -l test-vm \
    --report-dir .verification
# verdict: **FAIL**  (pass=2 fail=5 skip=0)
```

Verify 對 Expected 的判斷支援：
- `0`、`1` 等純數字：比對 exit code（會從 stdout 抓 `echo $?`）
- `present`：`exit code = 0`
- `~active`：stdout 包含 `active`（substring match，前面加 `~`）
- `^OK provider=…`：anchored regex
- 其他：字串完全相等

#### `pilot spec <spec.md> --to-inventory <out.yaml>`
從 spec `## 1. 目標系統` 表格產 ansible inventory，`--from-ssh-config` 還能從 `~/.ssh/config` 補欄位：

```bash
pilot spec docs/verification/os-patch-sla.md \
    --to-inventory inventory.yaml --from-ssh-config
# ✔ inventory written: inventory.yaml (3 hosts from spec + ~/.ssh/config augmented)
```

### 5 分鐘走完整個閉環（範例）

```bash
# 0. 寫 spec.md → docs/verification/hello-localhost.md
#    (用法見 docs/verification-spec-template.md)

# 1. Lint
pilot spec docs/verification/hello-localhost.md --lint

# 2. 抽出 inventory（從 spec 表格）
pilot spec docs/verification/hello-localhost.md \
    --to-inventory inventory.yaml

# 3. 跑 inspect
pilot verify docs/verification/hello-localhost.md -i inventory.yaml -l myhost

# 4. 寫一份 apply playbook（如果會動系統）
#    範本見 playbooks/apply/pam-oidc-sshd-apply.yml：
#      - 先 snapshot / 備份
#      - block/rescue 寫進 lockout safety net
#      - 用 -e key=value 帶 host-specific 參數

# 5. 真套用：dry run 先
ansible-playbook -i inventory.yaml playbooks/apply/pam-oidc-sshd-apply.yml \
    -e kc_ssh_pam_deb=/abs/path.deb -e keycloak_issuer=https://… \
    --check --diff

# 6. 真套用
ansible-playbook -i inventory.yaml playbooks/apply/pam-oidc-sshd-apply.yml \
    -e kc_ssh_pam_deb=/abs/path.deb -e keycloak_issuer=https://…

# 7. 再 verify 一次：apply → verify 閉環
pilot verify docs/verification/hello-localhost.md -i inventory.yaml -l myhost

# 8. 看 SQLite 覆蓋率
pilot spec status docs/verification/hello-localhost.md
# spec=…/hello-localhost.md total=3 verified=3 (pass=3) coverage=100.0%
```

### Spec-driven 對純 `ansible-playbook` 多了什麼好處

| | 純 ansible-playbook | pilot spec-driven |
|---|---|---|
| Spec 寫完到能跑要多久 | 自己寫 playbook（一條 row → 一個 task） | `pilot spec --generate` 1 秒 |
| 跑結果怎麼看 | stdout 紅綠字 | `.verification/<spec>-<UTC>.md` 表格 + SQLite |
| 改 row 的時候 spec 跟 playbook 會不會漂 | 很容易漂（沒人檢查） | generator 重產時漂移會立刻被 lint 抓到 |
| 跨 sandbox/staging/prod 同一份 playbook | 要 fork 三份 | 一份 + `-e patch_stage=…` gate |
| rollback | 自己寫或靠記憶 | apply playbook 用 `block/rescue` 強制送你 |
| DRY-run | `--check --diff` 一條指令 | 同一條（apply playbook 須支援 `--check`） |
| **什麼時候「我適合 spec 寫好就行、跑 ansible 就夠了」** | 你已寫好 apply playbook、CI 環境、要可重現 | spec 還在變、要 explore、發現新東西 |

詳細的 ansible-playbook 開發 workflow 看 [`docs/ansible-playbook-development.md`](./docs/ansible-playbook-development.md)。
完整閉環的範例（從 spec → apply → verify → 失敗 → 修 spec）看 [`docs/runbooks/pam-oidc-sshd.md`](./docs/runbooks/pam-oidc-sshd.md)。

---

## Sandbox 模式（Docker 容器）

### 為什麼需要 Sandbox？

開發與測試 Ansible playbook 時，你不想直接打到正式主機。Sandbox 模式讓 `pilot run` / `pilot chat` 啟動一個 **Docker 容器** 作為執行環境，所有 `run_ansible` / `run_command` / `read_file` 都路由到容器內：

- **Loop engineering**：反覆修改 playbook → 重跑 → 修東西，container 還在，可以保留狀態觀察 `idempotency`
- **OS 對齊**：用 `ubuntu:22.04` image 模擬正式主機的 OS，比「在 macOS 上跑 ubuntu playbook」可靠
- **安全隔離**：壞掉的 playbook 不會動到 pilot 所在的主機
- **可重現**：image tag 鎖定 OS 版本，今天跑跟一個月後跑一致

### 快速上手

```bash
# 1) 啟動 sandbox，image 自動從現有 container 'web01' 推導
pilot run --sandbox --sandbox-hostname web01 site.yml

# 2) 或明確指定 image
pilot run --sandbox --sandbox-image ubuntu:22.04 site.yml

# 3) chat session 也可用，整段對話共用同一 container
pilot chat --sandbox --sandbox-image rockylinux:9
> 把 PermitRootLogin 關掉並 reload sshd
```

啟動時會看到：

```
📦 sandbox active: docker:ubuntu:22.04
💡 TUI requested but no TTY available; using promptui   ← 只有在 `--tui` 但無 TTY 時才印
▶ Starting run ...
```

`pilot run` 結束時 container 會被 `docker rm -f` 自動拆掉。

### 運作原理

```
┌─────────────────┐
│      pilot      │  ← 還是你跑的那個 Go binary
│  (Agent Loop)   │
└──────┬──────────┘
       │ 工具呼叫
       ▼
┌─────────────────┐
│  Environment    │  ← LocalEnv 預設；--sandbox 時換成 DockerEnv
│  abstraction    │
└──────┬──────────┘
       │ 沒開 sandbox：exec.CommandContext(...)  ← 直接在本機跑
       │ 開了 sandbox：docker exec <container> ...
       ▼
┌─────────────────┐
│  Docker         │
│  Container      │  ← ubuntu:22.04, rockylinux:9, alpine:3.20, ...
│  (sleep ∞)      │
└─────────────────┘
```

關鍵設計：

1. **`run_ansible` 自動生成 docker inventory** — 不需要 wrap `ansible-playbook` 在 `docker exec` 裡。pilot 動態寫一個 inventory：
   ```yaml
   all:
     hosts:
       sandbox:
         ansible_connection: docker
         ansible_host: <container_id>
         ansible_user: root
   ```
   然後 `ansible-playbook -i <這個 inventory> site.yml` 透過 ansible 內建的 docker connection plugin 跟容器溝通。

2. **`run_command` / `read_file` 包成 `docker exec`** — 白名單、path allow-list、Sanitizer 全部保留，sandbox 只是 transport layer。

3. **`--dry-run-all` 完全跳過 docker 啟動** — dry-run 的目的是「看 LLM 想做什麼」，不需要隔離環境。

4. **每次 `pilot run` 一個新 container**（`--rm`） — 乾淨，不留狀態。loop engineering 在同一個 run 內反覆執行 OK，跨 run 就是乾淨起始。

### CLI 旗標

| 旗標 | 預設 | 說明 |
|------|------|------|
| `--sandbox` | `false` | 啟用 sandbox 模式 |
| `--sandbox-image <image>` | `""` | 明確指定 docker image（蓋過 auto-detect）|
| `--sandbox-hostname <host>` | `""` | 從 `docker inspect <host>` 推導 image 的 hostname |
| `--sandbox-network <mode>` | `host` | docker `--network` 模式（`host` / `bridge` / `none`）|
| `--sandbox-mode <mode>` | `docker` | sandbox 執行模式：`docker`（host ansible + docker connection plugin）vs `docker-exec`（`docker exec` 進容器跑 ansible）|

### Config 區塊（`~/.config/pilot/config.yaml`）

```yaml
sandbox:
  enabled: true                   # 預設不啟用
  image: ubuntu:22.04              # 留空時用 auto-detect
  mode: docker                     # docker (預設) | docker-exec
  container_name: ""               # 留空自動生成（pilot-sandbox-<host>-<unix>）
  network: host
  pull: missing                    # always | missing | never
  auto_detect: docker-inspect      # docker-inspect | none
```

### Auto-detect 流程

```bash
# 場景：你有個名為 web01 的 container（`docker run --name web01 ubuntu:22.04`）
# pilot 會用 `docker inspect web01` 抓到 image = ubuntu:22.04
# 然後 `docker run --rm --network host --name pilot-sandbox-<rand> ubuntu:22.04 sleep infinity`
pilot run --sandbox --sandbox-hostname web01 site.yml
```

auto-detect 失敗時的錯誤訊息明確指引：

```
sandbox enabled but no image specified and no hostname for auto-detect;
set sandbox.image in config or pass --sandbox-image / --sandbox-hostname
```

### 兩種 sandbox 執行模式：`docker` vs `docker-exec`

`--sandbox-mode` 旗標選擇 `run_ansible` 如何觸碰容器：

| Mode | host 上跑什麼 | 容器內需要什麼 | host 端 Python 依賴 |
|------|--------------|----------------|-------------------|
| `docker`（預設，舊） | host 的 `ansible-playbook` 透過 `connection: docker` plugin 跟容器對接 | 任何有 `python3` 的 image | `docker-py` + `community.docker` collection |
| `docker-exec`（新） | host 透過 `docker cp` + `docker exec` 在容器內跑 `ansible-playbook` | 必須有 `ansible-playbook` 在 `$PATH` | 只要 `docker` CLI |

#### 什麼時候用哪個？

- **用 `docker`（預設）**：你想用 host 自己的 ansible 版本，container 是任意 Linux 發行版（含 `alpine` / `distroless`），且 host 已經裝好 `docker-py` + `community.docker`
- **用 `docker-exec`**：你不希望在 host 裝 Python 套件、想要用跟 image 內建相同版本的 ansible（更貼近正式環境）、或是要在 CI runner 跑 pilot 而 CI 環境沒預裝 ansible collection

#### `docker-exec` 範例

```bash
# 1) 確認 image 內有 ansible
docker run --rm geerlingguy/docker-ubuntu2204-ansible:latest which ansible-playbook
# /usr/bin/ansible-playbook

# 2) 跑 pilot，整個 playbook 執行鏈都在容器內
pilot run --sandbox \
  --sandbox-image geerlingguy/docker-ubuntu2204-ansible:latest \
  --sandbox-mode docker-exec \
  site.yml
```

#### 底層差異

`docker` 模式：
```
HOST                                       CONTAINER
─────                                      ─────────
ansible-playbook site.yml
   │
   │ (connection: docker via community.docker + docker-py)
   ▼
docker exec <id> python3 -m ...              ← 每個 task 一次 docker exec
                                             ← 容器要有 python3
```

`docker-exec` 模式：
```
HOST                                       CONTAINER
─────                                      ─────────
docker cp site.yml     <id>:/tmp/pb.yml
docker cp inv.yml      <id>:/tmp/inv.yml
docker exec <id> ansible-playbook \
   -i /tmp/inv.yml /tmp/pb.yml              ← 整個 playbook 在容器內跑
                                             ← 容器要有 ansible-playbook
docker exec <id> rm -f /tmp/pb.yml
docker exec <id> rm -f /tmp/inv.yml          ← 自動清理
```

#### 常見錯誤

```
ERROR: docker exec ... ansible-playbook: command not found
```

→ 你挑的 image 沒有 ansible。換成 `geerlingguy/docker-ubuntu2204-ansible:latest`、`mcr.microsoft.com/oss/ansible/ansible-runner:latest` 這類預裝 image，或 `Dockerfile` 內 `RUN apt-get install -y ansible` 自己打包。

---

### 限制與注意事項

- **`docker` 模式：container 內需有 `/usr/bin/python3`** — ansible 的 docker connection plugin 透過 SSH-over-Python 跟 container 對接。`ubuntu:22.04` / `rockylinux:9` / `alpine:3.20` 都有；某些 minimal image 沒有要先 `docker run ... apk add python3`
- **`docker-exec` 模式：container 內需有 `ansible-playbook`** — 用 `geerlingguy/docker-ubuntu2204-ansible:latest` 這類預裝 image，或自己 `RUN apt-get install -y ansible` 進 image
- **`--network host` 看得到 host 全部 port** — 在你本機開發沒差，正式環境請改 `--sandbox-network none` 或 `bridge`
- **Binary 檔不能用 `read_file`** — `docker exec cat` 對 binary 會壞。文件、設定檔沒問題；二進位請用 `ansible.builtin.slurp` 模組
- **多 host inventory 全部 collapse 到同一 container** — 設計上如此。loop engineering 不需要多 OS 場景；若要 multi-host 多 OS，請用 `pilot run` 多次並指定不同 image
- **每個 run 一個新 container** — 跨 run 不保留狀態。loop engineering 請在同一個 `pilot run` 內反覆試
- **Audit**：sandbox image 會寫進 SQLite（`runs.sandbox_image` 欄位，schema v7），`pilot list-runs` 看得到
- **想跑完整 sandbox 測試**：`make test-sandbox`（涵蓋 unit + 真實 container 整合測試 + 三種 mode smoke test），詳見 [TESTING.md](./TESTING.md)

### FAQ

<details>
<summary><b>Q：sandbox 跟 --auto-approve 能同時用嗎？</b></summary>

可以，但 `run_ansible` 在 apply 模式仍會升級為 high 風險，**不會**被 `--auto-approve=medium` 自動放行。Sandbox 不改變人類審批這層保護。
</details>

<details>
<summary><b>Q：sandbox 對效能影響？</b></summary>

`docker exec` 每次約 +5~20ms 開銷；ansible-playbook 任務本身（apt install、systemctl reload）通常數秒起跳，sandbox 開銷可忽略。
</details>

<details>
<summary><b>Q：怎麼看 container 還在不在？</b></summary>

```bash
docker ps | grep pilot-sandbox
# 或跑 pilot 時加 --sandbox-network bridge，container 不會被 --rm 自動刪
# （pilot 結束時仍會 docker rm -f）
```
</details>

<details>
<summary><b>Q：能跑 systemd-based 服務測試嗎？</b></summary>

受限。`--network host` 模式下 container 預設**沒有** systemd（除非 image 是 `ubuntu:systemd-*` 之類特化版）。通常做法：playbook 用 `command:` / `service:` 模組搭配 `ansible.builtin.shell` 啟動 daemon，而不是靠 systemd 自動啟動。
</details>

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).

© 2026 pilot Contributors.
