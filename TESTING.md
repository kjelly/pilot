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

## 2. Pre-requisites

```bash
make test-prereq     # go / docker / ansible 一鍵檢查
./pilot doctor       # ansible 工具鏈 + vm-target（KVM/virt-customize）前置
```

## 3. 新增功能的測試 checklist

```bash
go build ./...                      # 1) 編譯
go vet ./...                        # 2) 靜態分析
CI=1 go test ./... -count=1         # 3) 全部測試
make playbook-lint                  # 4) playbook 有動的話
# 5) spec/playbook 有動的話：vm-target test 真跑一輪（見 AGENTS.md §1.4）
```

## 4. 相關檔案

- 硬規則（actual-run、spec↔inventory 對齊）：[AGENTS.md](./AGENTS.md)
- Playbook 開發心法（L1–L8 測試金字塔）：[docs/ansible-playbook-development.md](./docs/ansible-playbook-development.md)
- vm-target / docker-target 用法：`docs/runbooks/vm-target.md`、`docs/runbooks/docker-target.md`
