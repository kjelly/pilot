# pilot

> **Coding-agent-assisted、spec-driven 的 Ansible 佈署工具 — 寫需求、真套用、可驗證**

`pilot` 是一個以 Go 撰寫的**確定性** CLI 工具，通常與 Codex、Claude 這類
coding agent 搭配使用：使用者先寫自然語言需求，coding agent 直接在 repo 裡
撰寫對應的 verification spec、apply playbook 與 regression test；pilot 再用
lint、拋棄式測試環境（`vm-target`/`docker-target`）、verify 與 TUI
（`deploy`/`edit`）證明並交付這些產物。它專注在三件事：

1. **如何把需求變成可追溯、可證明的 spec + playbook** —— coding agent 先把
   需求落成 `docs/verification/*.md` 驗收合約，再直接撰寫 `playbooks/apply/*.yml`
   實作；row ID tag 與 regression test 鎖住 spec ↔ playbook ↔ inventory 的
   對應，pilot 再負責 lint 與逐列 verify，而不是靠 LLM heuristic 產生正式 apply。
2. **如何利用 docker/VM 技術，快速驗證 playbook 符合規格** ——
   `vm-target`（KVM VM）/ `docker-target`（容器）一鍵起落拋棄式環境；
   `vm-target test` 一口氣跑完 syntax → snapshot → apply → verify → 冪等，
   playbook 沒在乾淨環境過關就不進版控。
3. **使用者如何快速方便將軟體佈署成想要的架構** —— inventory、group_vars、
   vault 全部經由互動式 TUI wizard（`pilot edit` / `pilot inventory generate`）
   產生與維護（不手寫 YAML）；`pilot deploy` 問答式帶你選元件、選 stage、
   預覽、確認後套用，stage/confirm gate 擋住打錯環境。

```
自然語言需求
    └─ Codex / Claude（讀 repo + AGENTS.md，分兩階段 authoring）
         ├─ docs/verification/<x>.md           驗收合約
         ├─ playbooks/apply/<x>-apply.yml      mutation 實作
         └─ internal/spec/*_regression_test.go 對應與 invariant
                │
                ├─ pilot spec --lint
                ├─ vm-target test：apply → verify → 冪等
                └─ pilot deploy / pilot verify：交付與驗收
                     → .verification/ 報告 + SQLite spec_checkpoints
```

> 2026-07-17 起，早期的 LLM agent 面（`chat`/`run`/`diagnose`/RAG/ollama 整合）
> 已全數退役。這代表 **pilot runtime 不再內建或呼叫 LLM**，不是禁止使用
> Codex/Claude 開發本 repo；外部 coding agent 正是目前撰寫 spec、apply
> playbook 與 regression test 的主要 authoring 介面。

### Spec v2 方向：Requirement Brief → Delivery Bundle

這裡的 **Spec v2** 先指產品與 authoring contract，不代表目前 parser 已經支援
新的檔案格式或 `version: 2` 欄位。它把工作的起點從「人手寫完整 spec」改成
「人提供自然語言需求與限制，coding agent 產出可審核、可執行、可證明的 bundle」。

Spec v2 的責任分工是：

- **輸入**：Requirement Brief，包含目標、拓撲、限制、風險與不可違反事項。
- **輸出**：Delivery Bundle，至少包含 verification spec、apply playbook、
  regression test，以及要在哪個 target 取得 actual-run evidence 的計畫。
- **審核**：人確認需求理解、acceptance criteria、風險與 destructive boundary；
  不必從空白頁手刻 spec/playbook，但仍保有最後意圖與上線授權。
- **執行**：pilot 不推理需求，也不呼叫 model；只對 bundle 做確定性的
  lint、target test、deploy、verify、idempotency 與 evidence recording。

在 parser/schema 真正版本化之前，不要在 spec 檔加入尚未支援的 v2 語法；
先以這套 authoring contract 演進產品，再用獨立變更遷移格式與相容性。

---

## 環境需求

| 需求 | 用途 | 必要性 |
|------|------|--------|
| Go 1.22+ | 編譯 | 必要 |
| ansible / ansible-playbook | 套用與驗證 | 必要 |
| ansible-lint | L2 lint | 建議 |
| libvirt + libguestfs-tools | `pilot vm-target`（拋棄式 KVM VM） | 用到才要 |
| docker 或 podman | `pilot docker-target`（拋棄式容器） | 用到才要 |

```bash
go build -o pilot ./cmd/pilot
./pilot doctor        # 自我診斷：ansible 工具鏈 + vm-target 前置
```

### 環境變數

| 變數 | 作用 | 對應旗標/預設 |
|------|------|--------------|
| `PILOT_LOG_LEVEL` | 診斷日誌分級（debug/info/warn/error） | `--log-level`；預設 warn |
| `PILOT_LOG_FORMAT` | `json` 時診斷日誌輸出 JSON | 預設純文字 |
| `PILOT_ROOT` | spec / playbook layout 的專案根目錄 | `--root`；預設目前目錄 |
| `PILOT_DATA_DIR` | history.db 與 target state 的資料目錄 | `--data-dir`；預設 `~/.local/share/pilot` |
| `PILOT_SSH_BIN` / `PILOT_VIRSH_BIN` | vm-target 用的 ssh / virsh 執行檔覆寫 | 測試/特殊環境用 |
| `PILOT_DOCKER_BIN` / `PILOT_PODMAN_BIN` | docker-target 的 container 引擎執行檔覆寫 | 預設 PATH 上的 docker/podman |
| `PILOT_DEBUG_MENU` | TUI 選單除錯輸出（會破壞 PTY 自動化，勿在腳本裡開） | 預設關 |

---

## 命令總覽

| 命令 | 做什麼 |
|------|--------|
| `pilot edit` | TUI wizard：建立/編輯 inventory、group_vars、vault |
| `pilot inventory generate` | 互動式產生 inventory（含 group_vars/vault skeleton） |
| `pilot deploy` | 依 deploy catalog 選 component 佈署（TUI；套用前 [y/N] 確認） |
| `pilot spec <x.md> --lint` | 檢查 spec 格式與 Expected 文法 |
| `pilot verify <x.md> -i <inv>` | 逐列執行 spec、比對 Expected、落報告；`--dir` 一次驗全部、`--probe` 單列調參 |
| `pilot vm-target up/run/verify/test/down` | 拋棄式 KVM 測試 VM；`test` 一次跑完 syntax→apply→verify→冪等 |
| `pilot docker-target up/run/verify/down` | 輕量容器版測試環境 |
| `pilot doctor` | 環境自我診斷 |

各命令細節：`pilot <cmd> --help`；硬規則與工作流紀律見 [AGENTS.md](./AGENTS.md)，
文件索引見 [docs/README.md](./docs/README.md)。

---

## 📋 Spec-driven 工作流（寫需求 → 套用 → 驗證）

> 寫 ansible playbook 最痛苦的事不是寫，是**事後才知道 spec 跟實際系統不一致**。
> pilot 把這條鏈接起來：

```
┌───────────────────┐                         ┌─────────────────┐
│  docs/verification│      pilot verify       │  .verification/ │
│  <feature>.md     │ ──────────────────────→ │ <spec>-<UTC>.   │
│  (agent 起草+review)│  逐列執行+比對 Expected │   {.ndjson,.md} │
└───────────────────┘                         └─────────────────┘

┌───────────────────────────┐    ┌───────────────────────────┐
│  playbooks/apply/          │    │  ~/.local/share/pilot/    │
│  <spec>-apply.yml          │ --→│  history.db                │
│  (agent 直接撰寫 + review；│    │  spec_checkpoints table    │
│  mutations + block/rescue) │    │  (spec row → verdict 追溯)│
└───────────────────────────┘    └───────────────────────────┘
         ↑                                ↑
         ansible-playbook -i inv.yaml …   SQLite 寫下每次 verdict
```

### 三個產物的分工（必讀）

| 產物 | 誰寫 | 是不是 mutate | 用什麼跑 |
|------|------|--------------|---------|
| `docs/verification/<feature>.md` | **Coding agent 起草、reviewer 確認** | 不 mutate，只是 acceptance checklist | `pilot spec --lint` 把關 |
| `playbooks/apply/<feature>-apply.yml` | **Coding agent 依已確認 spec 直接撰寫**（不是 pilot generator 產物） | ✅ 會改系統 | `ansible-playbook … apply.yml -e patch_stage=…` |

**原則**：inspect 跟 mutate 分開。mutate 走 `playbooks/apply/*-apply.yml`；
inspect 不再有獨立 playbook——`pilot verify` 直接吃 spec 逐列執行並比對 Expected。
（`playbooks/verify/*.yml` 已於 2026-07-17 棄用，見該目錄 README.md：generator
產物其實不比對 Expected、部分 pattern 還會 mutate，配不上 verify 這個名字。）

> 範例：`docs/runbooks/pam-oidc-sshd.md` 是一份完整的 spec-driven runbook，
> 從確定 spec、直接撰寫 apply playbook、套用到 test-vm、
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
這是保留給 parser/generator 開發與人工檢視的**診斷工具**，不是目前的 feature
authoring 主線，也不是正式 apply playbook 的來源。coding agent 應直接依需求與
已確認的 spec 編輯 `playbooks/apply/*.yml`；`--apply` 已於 2026-07-17 棄用。
**驗收也不要走這個**——generator 產物不比對 Expected，驗收一律用下面的
`pilot verify`。輸出請放
gitignored 的 `playbooks/generated/`（不帶路徑時的預設）；輸出到已棄用的
`playbooks/verify/` 會直接報錯：

```bash
pilot spec docs/verification/pam-oidc-sshd.md \
    --generate playbooks/generated/pam-oidc-sshd.yml
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

#### `pilot inventory generate` — 產 inventory
（`pilot spec --to-inventory` 已於 2026-07-17 棄用；inventory 一律用互動式的
`pilot inventory generate` / `pilot edit` 產生與維護。）

### 5 分鐘走完整個閉環（範例）

```bash
# 0. 把需求交給 Codex/Claude，先產出並確認 spec.md
#    → docs/verification/hello-localhost.md
#    (格式見 docs/verification-spec-template.md)

# 1. Lint
pilot spec docs/verification/hello-localhost.md --lint

# 2. 產 inventory（互動式 wizard；hello-localhost 也可直接 --local 免 inventory）
pilot inventory generate

# 3. 跑 inspect
pilot verify docs/verification/hello-localhost.md -i inventory.yaml -l myhost

# 4. 再請 coding agent 依已確認的 spec 寫 apply playbook（如果會動系統）
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
| Spec 寫完到能跑要多久 | 自己寫驗證腳本 | `pilot verify` 直接吃 spec，0 秒 |
| 跑結果怎麼看 | stdout 紅綠字 | `.verification/<spec>-<UTC>.md` 表格 + SQLite |
| 改 row 的時候 spec 跟 playbook 會不會漂 | 很容易漂（沒人檢查） | row ID tags + regression test + actual-run evidence 抓漂移 |
| 跨 sandbox/staging/prod 同一份 playbook | 要 fork 三份 | 一份 + `-e patch_stage=…` gate |
| rollback | 自己寫或靠記憶 | apply playbook 用 `block/rescue` 強制送你 |
| DRY-run | `--check --diff` 一條指令 | 同一條（apply playbook 須支援 `--check`） |
| **什麼時候「我適合 spec 寫好就行、跑 ansible 就夠了」** | 你已寫好 apply playbook、CI 環境、要可重現 | spec 還在變、要 explore、發現新東西 |

詳細的 ansible-playbook 開發 workflow 看 [`docs/ansible-playbook-development.md`](./docs/ansible-playbook-development.md)。
完整閉環的範例（從 spec → apply → verify → 失敗 → 修 spec）看 [`docs/runbooks/pam-oidc-sshd.md`](./docs/runbooks/pam-oidc-sshd.md)。

---

## 延伸閱讀

- 產品後續方向（Spec v2、Delivery Bundle、交付交易與 evidence）：[PRODUCT_ROADMAP.md](./PRODUCT_ROADMAP.md)
- 硬規則（actual-run、spec↔inventory 對齊、gate 慣例）：[AGENTS.md](./AGENTS.md)
- 文件索引 / 命名與 layout 約定：[docs/README.md](./docs/README.md)
- 什麼進版控、什麼不進：[TESTING.md](./TESTING.md)
- 交付驗證：[DELIVERY.md](./DELIVERY.md)
- Playbook 開發心法（測試金字塔 L1–L8）：[docs/ansible-playbook-development.md](./docs/ansible-playbook-development.md)
