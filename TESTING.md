# Pilot 測試指南

> 目的：把 pilot 的測試流程記錄成**可重現**的步驟，
> 給未來的自己、CI runner、AI agent 直接照著跑。
>
> （2026-07-17 起退役的是 pilot **runtime 內建**的 LLM agent 面；目前仍以
> Codex/Claude 這類外部 coding agent 依需求撰寫 spec、apply playbook 與測試，
> 再由本文件的確定性流程驗證。舊的 sandbox/docker-exec smoke 流程見 git
> history。）

---

## 0. Repository layout & version control policy

pilot is a generic tool repo. The split between "code in git" and "state on disk" matters:

| Path                          | In git? | Why                                        |
|-------------------------------|---------|--------------------------------------------|
| `docs/verification/*.md`      | yes     | Coding agent 起草、reviewer 確認的 acceptance contract |
| `playbooks/apply/*-apply.yml` | yes     | Coding agent 依已確認 spec 直接撰寫並 peer-review；不是 generator 產物（lockout safety net lives here） |
| `playbooks/verify/*.yml`      | yes     | **Deprecated 2026-07-17** (see its README.md): kept for reference only; do not regenerate or run — acceptance is `pilot verify <spec.md>` |
| `playbooks/generated/*.yml`   | **no**  | Ad-hoc `pilot spec --generate` output (the no-path default); local only |
| `.verification/*.md`         | **no**  | One file per `pilot verify` run; local evidence only |
| `~/.local/share/pilot/history.db` | **no** | SQLite: spec_checkpoints (verify verdicts per spec row) |
| `inventory*.yaml`             | **no**  | Local exec artifact; regenerate via `pilot inventory generate` |
| `*.ndjson`                    | **no**  | Raw verifier output (also covered by `.verification/`) |

The pattern: **specs and playbooks in git, execution state in SQLite, evidence on local disk.**
SQLite only stores *paths and IDs* (e.g. `spec_checkpoints.spec_path = "docs/verification/X.md"`),
never spec content. This way `git clone` + a DB restore is enough to bootstrap any machine.

To wipe all local state without touching git:

```bash
rm -rf .verification/ ~/.local/share/pilot/history.db
```

---

## 1. 測試分層

```bash
# L1 — Go 單元/整合測試（TUI 的 PTY 測試必須帶 CI=1）
CI=1 go test ./...

# L2 — 靜態分析
go vet ./...

# L3 — playbook 語法 + lint + 重複 YAML key 檢查（不需要 VM）
make playbook-lint

# L4 — 真實環境端到端：拋棄式 KVM VM 上跑 apply → verify → 冪等
go run ./cmd/pilot vm-target test --name <vm> \
    --playbook playbooks/apply/<x>-apply.yml \
    --spec docs/verification/<x>.md \
    -- -e target_group=all
```

- **TUI 測試**：`edit`/`deploy` 的 Bubble Tea 流程有三層——model 單元測試、
  teatest 整合測試、真實 binary PTY E2E。PTY 測試在互動 shell 下會誤判,
  一律 `CI=1 go test ./cmd/pilot/cmd/`。
- **race detector**：`make test-race`（= `go test -race -count=1 ./...`）。
- **Python callback**：`make test-callback`。
- **MCP server**（`pilot mcp serve`）：`cmd/pilot/cmd/mcp_edit_tools_test.go` /
  `mcp_test.go` 用真的 MCP client（非 mock handler）對編譯出的 `pilot` binary
  跑 capabilities/inspect/plan/apply 全流程,含 workspace revision 前後比對、
  audit artifact（asciicast + scenario/diff metadata）驗證、secret sentinel
  掃描（確認 vault 值從不外洩到 plan/apply 回傳或 audit 紀錄）。手動驗證：
  `go run ./cmd/pilot mcp serve --dir <workspace> --allow-write` 起一個
  stdio server,再用任一 MCP client 送 tool call。

## 2. Pre-requisites

```bash
make test-prereq     # go / docker / ansible 一鍵檢查
./pilot doctor       # ansible 工具鏈 + vm-target（KVM/virt-customize）前置
```

## 3. 交付前 SOP checklist（新增/修改功能一律照跑）

```bash
go build ./...                      # 1) 編譯
go vet ./...                        # 2) 靜態分析
CI=1 go test ./... -count=1         # 3) 全部測試
make test-race                      # 3b) race detector（碰共用/並行 state 的改動必跑）
make playbook-lint                  # 4) playbook 有動的話
# 5) spec/playbook 有動的話：vm-target test 真跑一輪（見 AGENTS.md §1.4）
```

以上 5 項是底線，一定要過。踩到下表任一種情境時**額外**做對應那一項——
這張表是 2026-09 兩週 22 個 fix commit 回顧後整理的高風險清單，細節見
AGENTS.md 對應章節。「自動化程度」欄老實標出哪些是一個指令就能查、哪些
仍要人判斷：

| 你動到的東西 | 指令 | 自動化程度 |
|---|---|---|
| `playbooks/apply/*.yml` 裡任何 `tags: [always]` 的 task | `go test ./internal/spec/ -run TestRegression_AlwaysTaggedTasksHaveAllPrerequisitesAlways -v`（全 repo 靜態掃描，`CI=1 go test ./...` 已經跑得到，不用另外加） | **多數情況全自動**。它只做靜態 data-flow 分析，看不穿 `include_tasks`/role 邊界（跨檔案讀變數）——這種情況要手動對「空 `--tags`」與「單一元件 tag」各跑一次 `ansible-playbook --check --diff`（AGENTS.md §4.4） |
| `cmd/pilot/cmd/deploy.go` 的 `--limit`/依賴展開/`effectiveDeploymentTags` | 1) `go test ./cmd/pilot/cmd/ -run TestResolveDeploymentScope -v` 先確認既有場景沒回歸；2) 針對這次改動手寫一個新的跨兩跳依賴 regression test；3) `go run ./cmd/pilot vm-target topology test --topology <多跳依賴topology.yaml> --ephemeral -- -e target_group=all --limit <部分host>` | **半自動**。第 1 步是指令；第 2、3 步要自己準備案例與 topology，無法一鍵生成（AGENTS.md §5.5） |
| 解析 `ipa`/`dig`/`docker` 等外部 CLI 輸出的程式碼或 task | 沒有指令能自動判斷「fixture 是不是真的擷取的」；手動 SSH 進 vm-target 跑一次真實指令，把 stdout **和** stderr 存下來，再對照程式裡的 fixture/regex | **純手動判斷**。檢查重點：訊息在哪個串流、換行是否為字面 `\n`、單位是否一致（AGENTS.md §5.6） |
| 新增/改一個 gate/探測 task | `make poc-checkmode-test VAULT=<path>`（預設跑 minimal-poc topology + `site.yml`；用 `TOPOLOGY=`/`PLAYBOOK=` 覆寫成你要測的那支） | **全自動**，一鍵指令（AGENTS.md §4.0 round-13） |
| 改到測試共用的 package-level 變數（如 `dataDir`） | `go test ./cmd/pilot/cmd/ -run <你的新測試> -v` 單獨跑一次，再 `CI=1 go test ./cmd/pilot/cmd/... -v` 整包跑一次——兩次結果不一致就是有殘留 state | **指令現成，但要記得手動跑兩次比對**；CI 預設只跑整包，不會主動幫你做這個對照 |

## 4. 相關檔案

- 硬規則（actual-run、spec↔inventory 對齊）：[AGENTS.md](./AGENTS.md)
- Playbook 開發心法（L1–L8 測試金字塔）：[docs/ansible-playbook-development.md](./docs/ansible-playbook-development.md)
- vm-target / docker-target 用法：`docs/runbooks/vm-target.md`、`docs/runbooks/docker-target.md`
