# AGENTS.md — pilot 工具 repo 對 AI agent 的硬規則

> **TL;DR** — 寫進 `docs/runbooks/*.md` 或 `docs/verification/*.md` 的每一條
> `bash` / `go run` / `ansible-playbook` 指令，**寫進文件前**必須在
> 對應的 vm-target / docker-target / 本地環境實際跑過一次並截到真實輸出。
> 沒跑過的 SOP 是負債，不是文檔。

---

## 0. 為什麼有這份檔

2026-07-01 這個 repo 出了一次 spec-vs-inventory 不一致的事故：

- `docs/verification/core-infra-provider-db.md` §1 目標系統表寫了 `keycloak-db` group
- 但當下 `pilot vm-target up` 帶的是 `--hosts core,dns,ntp,keycloak,db`，**沒有** `keycloak-db`
- runbook 步驟寫 `-e infra_role=db -l core`，照跑就 `skipping: no hosts matched`
- AI agent 寫 SOP 時沒實際執行、沒看 `show-inventory` 真實輸出，憑 spec 設計意圖腦補

修法見 §1 / §2 / §3。所有後續 PR 都要符合這三條。

---

## 1. 寫「可執行的步驟」之前 — actual-run 規則

> **硬規則**：任何要寫進 `docs/runbooks/*.md` 或 `docs/verification/*.md` 步驟區塊
> 的指令，寫進文件前必須符合下面三件事，缺一不可。

### 1.1 自己跑過一次

不是「照經驗寫下來」或「照 README 抄」，是**在當下這個 repo 的環境跑出來**。
具體動作：

```bash
# 1. 跑前先看 inventory / 服務狀態
go run ./cmd/pilot vm-target list
go run ./cmd/pilot vm-target show-inventory --name core

# 2. 跑指令
go run ./cmd/pilot vm-target run --name core \
    playbooks/apply/...yml -e ... --check --diff

# 3. 截真實輸出（PLAY RECAP / 退出碼 / PASS FAIL 數字）
```

### 1.2 把真實輸出貼進文件

不是「預期 PLAY RECAP: changed=8..12」，是**這次跑出來**的截錄：

```markdown
# 預期這次跑會看到：
PLAY RECAP *********************************************************************
core                       : ok=12  changed=8    unreachable=0    failed=0
```

如果跑了但失敗，把失敗也寫進去；下一個讀文件的人需要知道哪一步會壞。

### 1.3 spec / playbook / inventory 寫的 host alias 要對得起

寫 `-e target_group=keycloak-db` 之前先 `show-inventory` 確認 `keycloak-db` 真的在
inventory 裡。寫 `-l <group>` 之前也一樣。

**對應 regression test**：`internal/spec/core_infra_provider_db_regression_test.go::TestRegression_SpecAndInventoryAgree`
會跑 `go run ./cmd/pilot vm-target show-inventory --name core`，比對 spec §1 聲稱的
group set 跟 inventory 實際的 host set。任何不一致 CI 會 fail。

新增 spec 時也照這個 pattern 寫 regression test — 見 §3 範本。

---

## 2. 「事實快照」段是 runbook 的一部分

每份 `docs/runbooks/*.md` 在 §0 一句話目標之後、§1 為什麼之前，**必須有**
「事實快照」段（推薦編號 §0.5 或 §0.b），內容至少含：

| 必含項 | 範例指令 |
|--------|---------|
| vm-target list 當下輸出 | `go run ./cmd/pilot vm-target list` |
| inventory 當下 host 集合 | `go run ./cmd/pilot vm-target show-inventory --name core \| grep '^    [a-z]'` |
| vault / spec 依賴的外部 state | `~/.vault/keycloak-sandbox.yaml` 的 key 列表（不印密碼） |
| 對齊決定 | spec 跟 inventory 不一致時走 A 還是 B（見下） |

### 2.1 對齊決定 A vs B

當 spec §1 目標系統表裡的 group 在當下 inventory 找不到時，**必須**明確二選一：

| 選項 | 動作 | 適用 |
|------|------|------|
| **A. 改 inventory** | `vm-target down` + `vm-target up --hosts <包括 spec 提到的全部 alias>` | 願意 reprovision（會丟現有服務，spec 對齊的代價） |
| **B. 改 spec** | 把 spec §1 目標系統表對齊 inventory 當下 host 集合 | 不想 reprovision，spec 跟現實妥協 |

> **不準**「假裝對齊」 — 兩邊都寫一點、看起來一致但其實沒跑過。regression test
> `TestRegression_SpecAndInventoryAgree` 會 fail。

---

## 3. 寫新 spec 時 — 範本

每份 `docs/verification/<feature>.md` 寫完**至少**要附：

1. **lint clean**：`go run ./cmd/pilot spec docs/verification/<feature>.md --lint` 0 errors
2. **bash -n 過**：`go test -count=1 -run TestShellSyntax ./internal/spec/` PASS
3. **regression test**：`internal/spec/<feature>_regression_test.go` 至少鎖：
   - row ID 連號、無 vague expected
   - cross-row invariant（哪個 row 必含 `$KEYCLOAK_ISSUER` 之類）
   - **若 spec §1 有 Targets table：spec 跟 vm-target inventory 對齊**（抄 `TestRegression_SpecAndInventoryAgree`）

範本已存在：`core-infra-provider-db_regression_test.go`（含 `TestRegression_SpecAndInventoryAgree`）。
新 spec 照抄這個結構。

---

## 4. 寫 playbook 時

- `playbooks/apply/*.yml` 動 `/etc/xxx` 之前**先 snapshot** 為 `.pre-<role>.bak`
- 用 `block/rescue` 把 snapshot → mutate → verify 包成一個區塊；任何 mutate
  task fail → rescue 自動還原
- 任何 host-specific 值走 `-e key=value`，**不準 hard-code** 套到哪個 host
- **變數命名一致性**：變數名稱必須與 Spec 中定義的命名一字不差（例如使用 `keycloak_db_password`），禁止擅自發明新變數、縮寫（如將 `password` 改成 `passwd`）或拼寫錯誤。
- `infra_role=...` 之類的多合一 playbook，pre_tasks 用 `ansible.builtin.assert`
  fail-closed 守住 stage gate
- **每個對應到 spec check 的 task 必須帶 `tags:`**（讓開發時能 `--tags C3` 只重跑
  一條，不必整本 playbook 重跑）。命名慣例：
  - **單一 spec 的 playbook**（如 `pam-oidc-sshd-apply.yml`）：裸 `tags: [C3]`，
    tag 名 = spec row ID，一字不差。
  - **多 spec / 多 role 的 playbook**（如 `core-infra-provider-apply.yml`，一個檔涵蓋
    docker / db / dns / ntp / keycloak 各自的 spec）：裸 `Cx` 會跨 spec 撞號
    （docker 的 C1 ≠ db 的 C1），**必須**用 role 粗標籤 + `<role>-Cx` 命名空間細標籤，
    例如 `tags: [db, db-C3]`、`tags: [dns, dns-C2]`。
  - 對應關係要對得起 spec 的 command 欄（例如 `ports 127.0.0.1:5432:5432` → `db-C3`），
    **不準憑 task 名稱腦補**；對不上就先讀 spec checklist。
  - `pilot spec --generate` 產的 verify playbook 已自動帶 tag，不用手補；手補的是
    `playbooks/apply/*.yml`。
- 改完後 `ansible-playbook --syntax-check` + `ansible-playbook --list-tags <file>`
  （確認 tag 齊全無撞號）+ 對 vm-target 跑一次 `--check --diff` 才能 commit

---

## 5. 寫 / 改 Go code 時

- `go build ./...` 跟 `go test ./...` 都過才能 commit
- **`go test -race ./...` 也必須綠**（CI 就是跑這個）。不要在測試裡對共用
  slice / map 做「goroutine 寫 + 主 goroutine 讀」而沒有同步——用 channel
  關閉或 `sync` 建立 happens-before。race gate 紅掉，等於後面每個 agent 都
  失去「測試綠 = 安全」這個判準。
- 新增 public symbol 寫一行 doc comment
- 任何改 spec parser / generator / verifier 行為的 PR，必須把對應的 regression
  test 一起改（不要在 regression 失敗時 revert parser；先想 spec 為什麼這樣寫）
- 改完跑 `gofmt -w`（或 `make lint`）；不要留下手縮排。

### 5.1 target backend（docker / vm）是「兩份平行實作」——一起改

`internal/dockertarget` 與 `internal/vmtarget` 是刻意平行的兩個 backend，
**沒有**共用 interface（`Target`/`Options`/`Exec` 回傳型別各自不同，硬抽
interface 是 speculative generality）。因此：

- 動到 target 生命週期（`Up`/`Down`/staging inventory/旗標）時，**先問這個行為
  是不是兩個 backend 都該有**。是的話兩邊一起改，或把共用部分下沉到共用層，
  **不要只改一邊**（`--ssh-timeout` 失效、docker 有 `--check` 而 vm 沒有，都是
  只改一邊造成的漂移）。
- 狀態持久化**一律**走 `internal/statefile.Store[T]`（版本化 + 原子寫入，已測）。
  不要再手寫 temp-file+rename。
- CLI 端把 inventory 寫到暫存檔一律用 `writeTempInventory`（`cmd/pilot/cmd`）。

### 5.2 長生命週期物件不要把 per-call option 寫回自身欄位

`Manager` 這種跨多次呼叫重用的物件，per-call 的選項（timeout、旗標）要用
**區域變數**傳進去，不可寫回 `m.xxx` 欄位——否則一次呼叫的 override 會外洩到
之後每一次操作（vmtarget 的 `m.sshTimeout` 就中過這個雷）。

### 5.3 加一個 LLM tool 的步驟

1. `internal/tools/<tool>.go`：定義 struct + `Spec()` + `Execute(ctx, args)`。
2. `internal/tools/schemas.go`：加參數的 JSON schema（手寫字串）。
3. `internal/tools/defaults.go`：在 `DefaultRegistryWithConfig()` 註冊
   （`spec := t.Spec(); spec.Execute = t.Execute; r.MustRegister(spec)`）。
4. `internal/tools/<tool>_test.go`：input 驗證 + 行為 + 安全性測試。

注意事項：

- schema 的 property 名稱與 `Execute` 裡 `json:"..."` unpack struct 的欄位是
  **手動同步**的，沒有 codegen。改一邊就要改另一邊，否則 LLM 那個欄位會靜默
  傳不進來。`TestToolSchemasAreStructurallyValid` 會擋住 `required` 名稱打錯，
  但**擋不了**「struct 少了一個 schema 有的欄位」——自己對齊。
- **Interceptor 在 agent loop 與 MCP server 兩條路徑都會跑**。MCP 那條路徑
  **沒有**人工核准 / dry-run 保護（見 `internal/tools/registry.go` 的
  `Interceptor` doc）。任何會 mutate 的 tool，若靠 interceptor 做防護，要確保
  該防護不依賴 dry-run context，否則經 MCP 呼叫會直接執行。

### 5.4 agent loop 的 `handleToolCall`

它是一條 pipeline：`size-cap → buildProposal → approve → applyInterceptor →
dry-run skip → preExecSnapshot → Execute → persist → loop-guards →
recoverFromFailedApply → per-host dedup`。每個階段是獨立的具名 method。加新階段
時延續這個切法，不要把邏輯塞回主函式變回 god function。

---

## 6. 不要做的事

- ❌ 不要從「spec 設計意圖」推「inventory 應該有的 host」 — 從 `show-inventory` 讀事實
- ❌ 不要在 runbook 寫「預期 PASS 11/11」沒實際跑過 — 寫「這次跑 PASS 11/11，截錄如下」
- ❌ 不要把硬規則繞過（「這次特例」是滑坡的開始）
- ❌ 不要把密碼 / token 寫進 spec、playbook、runbook — 走 `-e @~/.vault/...yaml`
- ❌ 不要擅自縮寫、拼錯或發明新變數名稱（例如把 `keycloak_db_password` 寫成 `keyclack_db_passwd`），必須完全依據 Spec 與既有變數命名。


---

## 7. 變更紀錄

| 日期       | 版本 | 變更 | 變更者 |
|------------|------|------|--------|
| 2026-07-01 | v1.0 | 初版（spec-vs-inventory 事故後寫的硬規則）| sre |
| 2026-07-01 | v1.1 | §4 加 apply playbook `tags:` 硬規則（對齊 spec ID / 多 role 命名空間 / `--list-tags` 驗證）| sre |
| 2026-07-02 | v1.2 | §5 大幅擴充 Go 架構約定（`-race` gate、target 兩份平行實作、`statefile`/`writeTempInventory` 共用層、per-call option 不寫回欄位、加 tool 步驟 + schema/struct 同步、Interceptor 雙路徑、`handleToolCall` pipeline）| sre |
