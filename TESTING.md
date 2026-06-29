# Pilot 測試指南

> 目的：把 sandbox/docker-exec 等功能的測試流程記錄成**可重現**的步驟。
> 給未來的自己、CI runner、AI agent 直接照著跑。

---

## 0. Repository layout & version control policy

pilot is a generic tool repo. The split between "code in git" and "state on disk" matters:

| Path                          | In git? | Why                                        |
|-------------------------------|---------|--------------------------------------------|
| `docs/verification/*.md`      | yes     | Spec is the source of truth — must review  |
| `playbooks/*.yaml` / `.yml`   | yes     | Hand-written, peer-reviewed                |
| `playbooks/generated/*.yml`   | **no**  | Derived from `pilot spec --generate`; reproducible |
| `.verification/*.md`         | **no**  | One file per `pilot verify` run; local evidence only |
| `~/.local/share/pilot/history.db` | **no** | SQLite: runs / proposals / spec_checkpoints / agent_messages |
| `*.ndjson`                    | **no**  | Raw verifier output (also covered by `.verification/`) |

The pattern: **specs and playbooks in git, execution state in SQLite, evidence on local disk.**
SQLite only stores *paths and IDs* (e.g. `spec_checkpoints.spec_path = "docs/verification/X.md"`),
never spec content. This way `git clone` + a DB restore is enough to bootstrap any machine.

To wipe all local state without touching git:

```bash
rm -rf .verification/ ~/.local/share/pilot/history.db
```

## TL;DR — 一行驗證所有東西

```bash
make test-sandbox
```

等價於：unit tests + 整合測試 + 真實 container 跑 sample playbook（涵蓋 localhost / sandbox / docker-exec 三種 mode）。

預期結果：所有步驟 exit 0，最後一行印 `ALL CHECKS PASSED`。

---

## 1. 測試分層

| 層 | 範圍 | 速度 | 需要 |
|----|------|------|------|
| **L1 Unit** | 純函式邏輯 | < 5s | go |
| **L2 Integration** | 真實 docker container 跑 ansible | ~30s | go + docker + ansible image |
| **L3 Smoke (pilot binary)** | pilot run 三種 mode | ~5-60s | L2 + ollama + 至少一個 model |

對應的指令：

```bash
# L1 — 純單元測試
go test -count=1 -run "^Test" -short ./...

# L2 — 整合測試（需要 docker daemon + geerlingguy/...-ansible image）
go test -count=1 -run "TestDockerExecRunner_RealContainer" ./internal/tools/...

# L3 — Pilot binary smoke test
./scripts/test-sandbox.sh
```

---

## 2. Pre-requisites

### 2.1 必備

```bash
# 工具鏈
go version          # 1.22+
docker --version    # 24+
ansible-playbook --version  # 2.16+

# 預先拉好測試用 image
docker pull geerlingguy/docker-ubuntu2204-ansible:latest

# 確認有 ollama + 一個能跑 tool calling 的 model
ollama list
# 至少要有其中一個: qwen2.5:3b / qwen2.5:7b / qwen3.5:cloud
```

### 2.2 環境驗證（一鍵）

```bash
make test-prereq
```

或手動：

```bash
# 1) go modules
go mod download

# 2) docker daemon
docker ps > /dev/null && echo "docker OK" || echo "docker FAIL"

# 3) ansible
ansible-playbook --version | head -1

# 4) ollama
curl -sf http://localhost:11434/api/tags > /dev/null && echo "ollama OK" || echo "ollama FAIL"

# 5) image cached
docker images -q geerlingguy/docker-ubuntu2204-ansible:latest | grep -q . \
  && echo "ansible image OK" || echo "ansible image MISSING"
```

### 2.3 設定檔（自動 approve medium 避免 LLM 卡在 prompt）

寫到 `/tmp/pilot-cfg.yaml`：

```yaml
ollama_url: http://localhost:11434
model: qwen2.5:3b
max_iterations: 10
auto_approve: medium       # 自動放行 read_file + run_ansible(check)
data_dir: ~/.local/share/pilot
```

---

## 3. Sample Playbook

`playbooks/hello-localhost.yml` 是測試用的最小 playbook：

- **純 read-only**（不動任何檔案 / 服務）
- `hosts: localhost` + `connection: local`（不依賴 SSH）
- 展示 `gather_facts` / `command` + `register` / `slurp` + `b64decode` / `block` + `rescue` / `assert`
- load average threshold = 20.0（避免被開發機的高 load 觸發 assert 失敗）

可直接用 raw ansible-playbook 驗證：

```bash
ansible-playbook playbooks/hello-localhost.yml
```

預期：10 個 task 全 ok，0 changed，PLAY RECAP 顯示 `ok=10`。

---

## 4. 跑 Pilot：四種場景

### 4.1 場景 A：Localhost（本機直連，最快）

不開 sandbox、不掛 container，pilot 在你的 Ubuntu 上跑。

```bash
echo '{"playbook":"'$(pwd)'/playbooks/hello-localhost.yml","connection":"local","check":true}' \
  | ./pilot --config /tmp/pilot-cfg.yaml run --from-stdin --skip-syntax-check --no-tui
```

**預期輸出片段：**

```
💡 TUI not available (no TTY), using promptui
▶ Starting run <UUID>
[auto-approve medium] run_ansible on 
▶ 執行中: run_ansible ...
PLAY [Pilot smoke test - system info probe] *********
TASK [1) Greeting] *********
ok: [localhost]
  ✓ /workspace/pilot/playbooks/hello-localhost.yml
```

**成功指標**：
- 沒有 `📦 sandbox active` banner
- 出現 `[auto-approve medium] run_ansible` → 代表 LLM 提議被接受
- 結尾有 `✓ <playbook path>`

### 4.2 場景 B：Sandbox 模式（傳統，`connection: docker`）

`--sandbox` 啟動 docker container，但 ansible-playbook **仍在 host 上** 跑，用 `connection: docker` plugin 透過 docker API 進容器。

**前置**（host 需裝）：

```bash
pip install docker
ansible-galaxy collection install community.docker
```

**指令**：

```bash
echo '{"playbook":"'$(pwd)'/playbooks/hello-localhost.yml","connection":"local","check":true}' \
  | ./pilot --config /tmp/pilot-cfg.yaml run --from-stdin \
      --sandbox --sandbox-image geerlingguy/docker-ubuntu2204-ansible:latest \
      --skip-syntax-check --no-tui
```

**預期開頭**：

```
📦 sandbox active: docker:geerlingguy/docker-ubuntu2204-ansible:latest
```

**常見錯誤**：

```
ModuleNotFoundError: No module named 'docker'
```

→ `pip install docker`（缺 docker-py）

```
ERROR! couldn't resolve module/action 'community.docker.docker_connection'
```

→ `ansible-galaxy collection install community.docker`（缺 collection）

### 4.3 場景 C：Sandbox 模式 + `docker-exec`（新，**無 host 依賴**）

`--sandbox-mode=docker-exec` 把 ansible-playbook **跑在容器內**。host 不需要 docker-py、不需要 community.docker。

**前置**：容器 image 必須含 `ansible-playbook`。`geerlingguy/docker-ubuntu2204-ansible:latest` 已內建。

**指令**：

```bash
echo '{"playbook":"'$(pwd)'/playbooks/hello-localhost.yml","connection":"local","check":true}' \
  | ./pilot --config /tmp/pilot-cfg.yaml run --from-stdin \
      --sandbox --sandbox-image geerlingguy/docker-ubuntu2204-ansible:latest \
      --sandbox-mode docker-exec \
      --skip-syntax-check --no-tui
```

**底層差異**：

```
Sandbox (mode=docker):
  HOST  ansible-playbook site.yml
        └─ connection: docker → docker-py → docker exec per task

Sandbox (mode=docker-exec):
  HOST  docker cp site.yml     <id>:/tmp/pilot-pb-*.yml
  HOST  docker cp inventory    <id>:/tmp/pilot-inv-*.yml
  HOST  docker exec <id> ansible-playbook -i /tmp/inv /tmp/pb
  HOST  docker exec <id> rm /tmp/pilot-*  (cleanup)
```

**常見錯誤**：

```
ERROR: docker exec ... ansible-playbook: not found
```

→ 換 image：`geerlingguy/docker-ubuntu2204-ansible:latest` / `mcr.microsoft.com/oss/ansible/ansible-runner:latest` / `quay.io/ansible/awx-ee:latest`

### 4.4 場景 D：純 Docker（繞過 pilot，最穩定）

如果你只想確認 playbook 在容器內能跑，不要 pilot 的 LLM：

```bash
# 啟動容器
docker run -d --rm --name pilot-test \
  --mount type=bind,source="$(pwd)/playbooks",target="$(pwd)/playbooks",readonly \
  geerlingguy/docker-ubuntu2204-ansible:latest sleep infinity

# 跑 playbook
docker exec pilot-test bash -c "cd $(pwd) && ansible-playbook -i /dev/stdin playbooks/hello-localhost.yml" \
  <<'EOF'
all:
  hosts:
    localhost:
      ansible_connection: local
EOF

# 清理
docker rm -f pilot-test
```

**預期**：`PLAY RECAP` 顯示 `ok=10 changed=0 failed=0`。

---

## 5. 完整測試套件

### 5.1 Unit + Integration 一次跑

```bash
go test -count=1 ./...
```

預期：`~394 passed in 16 packages`（test 數會隨新增而增加）。

### 5.2 跑多次（檢測 flaky）

```bash
go test -count=3 ./...
```

預期：`~1182 passed`（394 × 3 = 1182）。

### 5.3 Race detector

```bash
make test-race
# 等價於: go test -race -count=1 ./...
```

### 5.4 單跑 docker-exec 整合測試

```bash
go test -count=1 -v -run "TestDockerExecRunner_RealContainer" ./internal/tools/...
```

預期：

```
=== RUN   TestDockerExecRunner_RealContainer
--- PASS: TestDockerExecRunner_RealContainer (12.34s)
PASS
```

如果 image 沒拉：

```
SKIP: image "geerlingguy/docker-ubuntu2204-ansible:latest" not pulled locally
```

→ `docker pull geerlingguy/docker-ubuntu2204-ansible:latest` 後重跑。

---

## 6. 驗證腳本：`scripts/test-sandbox.sh`

一鍵跑 L1 + L2 + L3，適合 CI / AI agent 呼叫。

```bash
./scripts/test-sandbox.sh
```

完整 flow：

1. **L1 unit** — `go test -count=1 ./...`（無 docker 也能跑，會 skip docker 整合測試）
2. **L2 integration** — `go test -count=1 -run TestDockerExecRunner_RealContainer`（需要 docker + image）
3. **L3 smoke** — 編譯 pilot binary、跑三個場景的 smoke test，驗證預期 banner 與 exit code
4. **Cleanup** — 拆掉所有 `pilot-sandbox-*` 與 `pilot-dexec-*` 容器

退出碼：

| 退出碼 | 意義 |
|--------|------|
| 0 | 全部通過 |
| 1 | 任何 L1/L2/L3 步驟失敗 |
| 2 | pre-req 缺工具（go / docker / ollama / image） |

---

## 7. 常見問題與排查

### 7.1 `pilot run` 卡在 prompt 不動

**症狀**：印 `▶ Starting run <UUID>` 後等幾分鐘沒回應

**原因**：LTM 提議的 tool call 進入人工審批（promptui 需要 TTY）

**修法**：

```bash
# 用 config 自動 approve
auto_approve: medium   # 放行 read_file (low) + run_ansible check (medium)

# 或單次指令指定
./pilot run --auto-approve medium ...
```

注意：`run_ansible` 在 apply 模式（`check=false`）**永遠升級為 high**，不會被 medium auto-approve。

### 7.2 `playbook path "/xxx" is outside the allowed roots`

**症狀**：LLM 給的 playbook 路徑被 `run_ansible` 拒絕

**原因**：預設 allow-list 只認 `./playbooks/`、`./examples/`、`cwd`、`<DataDir>/playbooks/`

**修法**（二選一）：

```bash
# 1) 把 playbook 搬進 ./playbooks/
cp my-pb.yml playbooks/

# 2) config 開白名單
cat >> ~/.config/pilot/config.yaml <<EOF
allowed_playbook_roots:
  - /tmp/my-playbooks
EOF
```

### 7.3 Sandbox 容器沒拆乾淨

**症狀**：`docker ps` 看到一堆 `pilot-sandbox-*`

**修法**：

```bash
docker rm -f $(docker ps -aq --filter name=pilot-sandbox)
docker rm -f $(docker ps -aq --filter name=pilot-dexec)
```

或用 script（會在步驟 4 自動跑）：

```bash
./scripts/test-sandbox.sh --cleanup-only
```

### 7.4 `ollama not reachable at http://localhost:11434`

**修法**：

```bash
# 啟動 ollama
ollama serve &

# 或指定別的位置
./pilot --ollama http://gpu-host.lan:11434 run ...
```

### 7.5 `TestLocalEnvironment_Exec_Timeout` flaky

這個測試在 load 高的機器可能誤判（process 還沒到 timeout 就被排程器提前送 SIGKILL）。已修：實作有 100ms grace period 容忍抖動。如果還在 flaky，請把開發機 load 降下來（`uptime` 看 < 5）。

### 7.6 `TestDockerExecRunner_RealContainer` 失敗，exit code 2

**症狀**：

```
exit code 2, want 0
stdout: usage: ansible-playbook
ansible-playbook: error: unrecognized arguments: <some host path>
```

**原因**：你手動改了 docker_exec_runner.go，把 playbook 位置搬離了 `args[0]`。`BuildArgs` 的契約是「playbook 是第一個位置參數（index 0）」，dockerExecRunner 預期這個 layout。

**修法**：在 `runInContainer` 找 playbook 位置時不要假設是 index 0，改用 `args[0]` 讀取第一個非 flag 參數。

---

## 8. 新增功能的測試 checklist

當你新增 / 修改任何 sandbox 相關功能，請依序跑這 5 個：

```bash
# 1) 編譯
go build ./...

# 2) 靜態分析
go vet ./...

# 3) 單元測試
go test -count=1 ./internal/tools/...

# 4) 整合測試（真實 container）
go test -count=1 -run "TestDockerExecRunner_RealContainer" ./internal/tools/...

# 5) Smoke test（pilot binary）
./scripts/test-sandbox.sh
```

5 個都過才能 commit。

---

## 9. CI 友善的最小指令集

不依賴 ollama、不跑 LLM、純離線：

```bash
# Pre-req: go, docker, geerlingguy/...-ansible image
go mod download
go build ./...
go vet ./...
go test -count=1 -short ./...                                  # L1
go test -count=1 -run "TestDockerExecRunner_RealContainer" \
  ./internal/tools/...                                          # L2
ansible-playbook playbooks/hello-localhost.yml                 # raw sanity
docker rm -f $(docker ps -aq --filter name=pilot-)
echo "ALL CHECKS PASSED"
```

複製到 CI YAML 的 `script:` 區段即可。

---

## 10. 相關檔案

| 檔案 | 用途 |
|------|------|
| `playbooks/hello-localhost.yml` | 測試用 sample playbook（純 read-only）|
| `internal/tools/docker_exec_runner.go` | `docker-exec` 模式的執行邏輯 |
| `internal/tools/docker_exec_runner_test.go` | resolveSandboxMode / findFlagValue 等 unit test |
| `internal/tools/docker_exec_runner_integration_test.go` | 真實 container 跑 ansible 的整合測試 |
| `internal/sandbox/sandbox.go` | `Environment` 介面定義 |
| `internal/sandbox/docker.go` | `DockerEnvironment` 實作 |
| `scripts/test-sandbox.sh` | 自動化 L1+L2+L3 smoke test |
| `Makefile` | `make test-sandbox` / `make test-prereq` 目標 |
| `README.md` | 使用者面向文件 |
| `implementation_report.md` | 變更歷史 |
