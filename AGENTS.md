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
- 新增 public symbol 寫一行 doc comment
- 任何改 spec parser / generator / verifier 行為的 PR，必須把對應的 regression
  test 一起改（不要在 regression 失敗時 revert parser；先想 spec 為什麼這樣寫）

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
