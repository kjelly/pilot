# AGENTS.md — pilot 工具 repo 對 AI agent 的硬規則

> **TL;DR** — 寫進 `docs/runbooks/*.md` 或 `docs/verification/*.md` 的每一條
> `bash` / `go run` / `ansible-playbook` 指令，**寫進文件前**必須在
> **對應的目標環境**（vm-target / docker-target / 本地 / 真實主機）實際跑過一次
> 並把真實輸出保存成可追溯的 evidence artifact。runbook/spec 只保留目前有效的
> 操作契約、短摘要與 evidence 連結，不累積完整 transcript。沒跑過的 SOP 是負債，
> 不是文檔。
>
> 本檔的規則以「host / inventory」為核心，一律指**你這一步實際要執行的那份
> inventory**——不管它來自拋棄式測試 VM 還是真實主機。讀它的事實，不要照
> spec 設計意圖腦補（見 §0.1 的讀法對照）。
>
> **本 repo 的實際 authoring model**：使用者提供自然語言需求，Codex/Claude
> 這類外部 coding agent 直接撰寫 spec、apply playbook 與 regression test；
> pilot runtime 不呼叫 LLM，只負責確定性的 lint、target test、deploy、verify
> 與證據。`pilot spec --generate` 不是正式 apply playbook 的來源。

---

## 0. 為什麼有這份檔

2026-07-01 這個 repo 出了一次 spec-vs-inventory 不一致的事故：

- `docs/verification/core-infra-provider-db.md` §1 目標系統表寫了 `keycloak-db` group
- 但當下 `pilot vm-target up` 帶的是 `--hosts core,dns,ntp,keycloak,db`，**沒有** `keycloak-db`
- runbook 步驟寫 `-e infra_role=db -l core`，照跑就 `skipping: no hosts matched`
- AI agent 寫 SOP 時沒實際執行、沒看 `show-inventory` 真實輸出，憑 spec 設計意圖腦補

修法見 §1 / §2 / §3。所有後續 PR 都要符合這三條。

### 0.1 名詞：「目標 inventory」與怎麼讀它的事實

本檔說的「inventory」「host」「group」，一律指**你這一步實際要執行的那份
inventory**。事故的教訓與所有規則都與它的來源無關——同一條紀律適用於拋棄式
測試 VM，也適用於真實主機。讀它的**事實**（不是 spec 說「應該」有什麼）：

| 目標環境 | 讀 group→host 事實的指令 |
|----------|--------------------------|
| vm-target（拋棄式 KVM VM） | `go run ./cmd/pilot vm-target show-inventory --name <n>` |
| docker-target（拋棄式容器） | `go run ./cmd/pilot docker-target show-inventory --name <n>` |
| 真實主機 / 任意 inventory 檔 | `ansible-inventory -i <inventory> --graph`（或 `--list`） |

下文出現 `show-inventory` 之處，若你的目標是真實主機，一律換成
`ansible-inventory -i <inventory> --graph`——規則不變，只是讀事實的工具不同。

### 0.2 Authoring model：需求由 coding agent 落成，pilot 做確定性證明

本 repo 不把 LLM 放在 pilot runtime 裡。正常功能開發是：

1. 使用者以自然語言描述需求、限制與想要的架構。
2. Codex/Claude 先把需求整理成 `docs/verification/<feature>.md` acceptance
   contract；spec 定義「完成後外部可觀察到什麼」，不是 playbook 實作的逐行翻譯。
3. spec 經 lint、review、驗收方法確認後，coding agent 才直接撰寫
   `playbooks/apply/<feature>-apply.yml` 與 regression test。
4. pilot 用 docker/vm target 真跑 apply → verify → idempotency；完整結果與失敗
   寫入獨立 evidence artifact，spec/runbook 只保留目前有效摘要與連結。

**Spec v2 定義**（目前是產品 / authoring contract，不是 parser schema version）：

- 流程是 `Requirement Brief → Delivery Bundle`。bundle 至少含 verification
  spec、apply playbook、regression test 與 actual-run evidence 計畫。
- coding agent 必須把需求中的假設、未知項、風險與 destructive boundary 明列；
  不准在 spec/playbook 中自行填空後假裝是使用者已確認的需求。
- 人負責確認 intent、acceptance criteria、風險與上線授權；不要求人從空白頁
  手寫完整 spec 或 playbook。
- 在 parser 與相容性測試真正加入版本支援前，不准自行新增 `version: 2` 或其他
  尚未實作的 spec 語法。authoring model 與檔案格式版本必須分開演進。

**責任邊界**：

- 自然語言需求是工作的起點；spec 是 acceptance 的 source of truth；apply
  playbook 是 mutation 實作。三者不可混成同一份「看起來一致」的文字。
- 同一個 coding agent 可以同時產出 spec 與 playbook，但必須分兩階段：
  **先確定 spec，再實作 playbook**。不准為了讓已寫好的 playbook PASS 而靜默
  放寬 Expected；若需求或驗收方法確實錯了，必須明說原因並同步更新變更紀錄。
- spec 優先驗證**外部行為 / effective state**，不要只重讀 playbook 剛寫入的
  檔案。例如服務要測有效設定或真實連線，權限要測 allow/deny，reconciler 要測
  新增與撤銷；避免 spec 與實作由同一個 agent 寫出相同盲點。
- `pilot spec --generate` 只供 parser/generator 開發與診斷性人工檢視；不得拿來
  取代 `playbooks/apply/*.yml`，也不得把「generator 有產出」當作功能已交付。
- 除非使用者另開明確需求，不要把 model/provider、prompt orchestration 或
  agent loop 重新塞回 pilot runtime；pilot 保持 provider-independent、deterministic。

---

## 1. 寫「可執行的步驟」之前 — actual-run 規則

> **硬規則**：任何要寫進 `docs/runbooks/*.md` 或 `docs/verification/*.md` 步驟區塊
> 的指令，寫進文件前必須符合下面三件事，缺一不可。完整 evidence 的保存與
> candidate revision 規則見 [`docs/actual-run-evidence.md`](docs/actual-run-evidence.md)。

### 1.1 自己跑過一次

不是「照經驗寫下來」或「照 README 抄」，是**在當下這個 repo 的環境跑出來**。
具體動作：

```bash
# 1. 跑前先讀「你這一步要執行的那份 inventory」的事實（見 §0.1）
#    拋棄式測試 VM：
go run ./cmd/pilot vm-target list
go run ./cmd/pilot vm-target show-inventory --name core
#    真實主機 / 任意 inventory 檔：
ansible-inventory -i <inventory> --graph

# 2. 對「同一個」環境跑指令
go run ./cmd/pilot vm-target run --name core \
    playbooks/apply/...yml -e ... --check --diff
#    真實主機等價（playbook 的 hosts 是變數，inventory 是外部參數）：
ansible-playbook -i <inventory> playbooks/apply/...yml \
    -e target_group=<group> --check --diff

# 3. 截真實輸出（PLAY RECAP / 退出碼 / PASS FAIL 數字）
```

### 1.2 真實輸出與操作文件分開保存

不是「預期 PLAY RECAP: changed=8..12」，而是保存**這次真的跑出來**的完整輸出。
原始 stdout/stderr、逐 row 結果與失敗紀錄放在 `.verification/` 或 pilot append-only
evidence store；需要提交的 sanitized 摘要放在
`docs/evidence/<feature>/<date>-<tested-revision>.md`。

runbook/spec 只保留一份「目前有效」摘要：測試日期、tested revision、tested tree、
target/inventory、PASS/FAIL 數字，以及 evidence record 連結。重新驗證時**取代**摘要與
latest link，不把新一輪 transcript 追加到原文件。歷史過程由獨立 evidence record 與
Git history 保存。

如果跑了但失敗，完整失敗輸出也要進 artifact；只有仍會影響目前操作的症狀、原因與
修法，才濃縮成 runbook 的 gotcha。不得把失敗隱藏成成功摘要。

### 1.3 spec / playbook / inventory 寫的 host alias 要對得起

寫 `-e target_group=keycloak-db` 或 `-l <group>` 之前，先讀**你要執行的那份
inventory**（§0.1）確認該 group / host 真的存在——vm-target 用 `show-inventory`，
真實主機用 `ansible-inventory -i <inv> --graph`。對不上就是 `skipping: no hosts
matched`（或更糟，打錯機器）。**不要**從 spec 設計意圖推斷它「應該」在。

**對應 regression test**：`internal/spec/core_infra_provider_db_regression_test.go::TestRegression_SpecAndInventoryAgree`
以 vm-target 作為參考環境，跑 `go run ./cmd/pilot vm-target show-inventory --name core`，
比對 spec §1 聲稱的 group set 跟 inventory 實際的 host set。任何不一致 CI 會 fail。
（這條 CI 檢查的是 repo 內 spec 文件對測試環境的一致性；上真實主機時，同樣的
「對齊」責任落在你執行前的 `ansible-inventory` 確認,不受此 test 影響。）

新增 spec 時也照這個 pattern 寫 regression test — 見 §3 範本。

### 1.4 首選：用 `vm-target test` 一次跑完 fresh → verify → idempotency

不要再手動一步一步跑「apply → verify → 再 apply 檢查 changed=0」。
`pilot vm-target test` 就是為了產出 §1.2 要的證據而存在的——它一口氣做：

1. `ansible-playbook --syntax-check`（L1）
2. **`ansible-playbook --check --diff`（L3 dry-run，對 target 當下狀態；2026-07-23 新增）**
   ——在任何 mutation 之前跑，抓 check-mode/全新主機的排序 bug（見 §4.0 的
   round-13 教訓）。合法無法 check-mode 的 playbook 用 `--skip-checkmode` 跳過。
3. 自動 snapshot（失敗會 auto-rollback 回 pre-test）
4. apply playbook（L4）
5. `pilot verify`（L5）
6. **再 apply 一次並斷言 `changed=0`**（L6 冪等）

playbook 需要的變數放在 `--` 之後，會**原封不動**轉給 apply 與冪等兩次 run
（`-e target_group=<g>` 時比照 `run`，自動放掉 `-l <name>` 限制）：

```bash
pilot vm-target test --name <vm> \
    --playbook playbooks/apply/<role>-apply.yml \
    --spec docs/verification/<role>.md \
    --verify-timeout 40 \
    -- -e target_group=all -e <var>=<val> -e @~/.vault/<secrets>.yaml
```

把它印出的 PLAY RECAP（兩次）+ verify verdict 保存進 evidence artifact，並在
spec/runbook 更新短摘要與連結，就滿足 §1.2。

多機情境（site.yml、FreeIPA primary+replica+client 這類跨 host playbook）用
**`vm-target topology test`**（2026-07-18 新增，同日以 site.yml + 2-node smoke
拓樸實跑通過、並實測 auto-rollback，證據見 `docs/runbooks/vm-target.md` §3.7）
——對整個 topology spec 做同一條鏈：**對 rendered inventory 當下狀態跑 `--check --diff`（2026-07-23
新增，任何 mutation 之前）** → 全 cluster 一鍵 snapshot → 用 render 出的 grouped inventory apply →
逐份 `--verify <spec.md>=<group>` 驗收 → 再 apply 斷言 `changed=0` → 失敗時
**每個 node** 自動 rollback + re-wire。**多 playbook 交互的排序 bug（例如 site.yml 裡
一支 playbook 的 check-mode-gated 真實動作，是另一支 playbook 稍後斷言的前提）只有在
`--ephemeral` 對全新 VM 跑過這條鏈才會現形**——對已經 apply 過的既有 topology 跑
`--check --diff` 不會抓到，見 §4.0 的 round-13 教訓：

```bash
pilot vm-target topology test --topology docs/topologies/freeipa-ha-topology.yaml \
    --playbook playbooks/site.yml \
    --verify docs/verification/freeipa-server.md=ipa_masters \
    --verify docs/verification/freeipa-client.md=ipa_clients \
    -- -e stage=sandbox
```

> 拿不準某條 checklist 的 expected 怎麼寫？先用 `pilot verify --probe '<cmd>'
> [--probe-expected '<v>'] -i <inv> -l <host>` 把候選指令丟進**與 verify 完全相同**的
> 管線，看它實際回的 rc / stdout / clean / verdict，再決定 expected 的寫法——不要用猜的。
> 三個 matcher 陷阱（反邏輯 grep、`^` 錨點、`~active`）見 `docs/verification-spec-template.md`，
> `pilot spec --lint` 也會對它們 warn。

### 1.5 正式 evidence run 使用不可變 candidate，不要求日常 worktree 永遠乾淨

- 開發期間可以在 dirty worktree 跑快速測試；「乾淨」不是日常迭代的前置條件。
- 完整 target test 前，先把本次功能內容凍結成**本地 candidate commit**。正式測試
  必須從該 revision 的乾淨、隔離 checkout 執行，並記錄 commit ID 與 tree ID。
- candidate 測試失敗後的任何修正都形成新 candidate，舊 evidence 立即失效；不得把
  舊結果套到新 tree。
- candidate 測試成功後，不得再修改會影響執行結果的 spec、playbook、fixture、Go code、
  inventory contract 或依賴鎖檔。完整 evidence 與 sanitized 摘要用後續
  **evidence-only commit** 引用 tested revision/tree。
- 若 PR 最後 squash/rebase，evidence record 仍須保存 tested tree 與 execution-affecting
  file hashes；CI/ reviewer 必須能證明最終功能內容與被測 candidate 相同。

---

## 2. 「事實快照」段是 runbook 的一部分

每份 `docs/runbooks/*.md` 在 §0 一句話目標之後、§1 為什麼之前，**必須有**
「目前有效的事實快照」段（推薦編號 §0.5 或 §0.b）。這一段只保留最新摘要與
evidence link，不累積歷次輸出；完整 snapshot 留在對應 evidence artifact。內容至少含：

| 必含項 | 範例指令 |
|--------|---------|
| 目標環境當下狀態 | `go run ./cmd/pilot vm-target list`（真實主機：你的 inventory 檔路徑 + 來源） |
| inventory 當下 host 集合 | vm-target：`… show-inventory --name core \| grep '^    [a-z]'`；真實主機：`ansible-inventory -i <inv> --graph` |
| vault / spec 依賴的外部 state | `~/.vault/keycloak-sandbox.yaml` 的 key 列表（不印密碼） |
| 對齊決定 | spec 跟 inventory 不一致時走 A 還是 B（見下） |

### 2.1 對齊決定 A vs B

當 spec §1 目標系統表裡的 group 在當下 inventory 找不到時，**必須**明確二選一：

| 選項 | 動作 | 適用 |
|------|------|------|
| **A. 改 inventory** | vm-target：`down` + `up --hosts <包括 spec 提到的全部 alias>`；真實主機：編輯你的 inventory 檔，把該 group / host 補上（或加到既有 group） | 願意動環境讓它符合 spec（測試 VM 是 reprovision，真實主機是改 inventory 定義） |
| **B. 改 spec** | 把 spec §1 目標系統表對齊 inventory 當下 host 集合 | 不想動環境，spec 跟現實妥協 |

> **不準**「假裝對齊」 — 兩邊都寫一點、看起來一致但其實沒跑過。regression test
> `TestRegression_SpecAndInventoryAgree` 會 fail。

---

## 3. 寫新 spec 時 — 範本

### 3.0 Coding agent 的 spec-first 順序

收到新功能需求時，coding agent 必須依下列順序工作：

1. 先列出可觀察的 acceptance criteria、目標 inventory、支援平台、必要變數與
   failure/rollback 行為，再寫 spec。
2. lint spec 並確認 matcher 在真實 verify pipeline 的語意；拿不準就用既有的
   `pilot verify --probe` 流程，不可猜 Expected。
3. spec 確定後才寫 apply playbook；task tag 必須回指 spec row。
4. 同步寫 regression test，鎖 row、變數契約、tag coverage 與 cross-row
   invariant。新增 component 時也要同步既有 inventory role contract、
   deploy catalog、`site.yml`/`DELIVERY.md`（若適用）及 §4.2 備份範圍。
5. 最後依 §1.4 真跑 target test；只有 spec + playbook「看起來互相對得上」
   不算完成。

每份 `docs/verification/<feature>.md` 寫完**至少**要附：

1. **lint clean**：`go run ./cmd/pilot spec docs/verification/<feature>.md --lint` 0 errors
2. **bash -n 過**：`go test -count=1 -run TestShellSyntax ./internal/spec/` PASS
3. **regression test**：`internal/spec/<feature>_regression_test.go` 至少鎖：
   - row ID 連號、無 vague expected
   - cross-row invariant（哪個 row 必含 `$KEYCLOAK_ISSUER` 之類）
   - **若 spec §1 有 Targets table：spec 跟目標 inventory 對齊**（抄 `TestRegression_SpecAndInventoryAgree`；該範本以 vm-target 作參考環境，真實主機部署時對齊責任在執行前的 `ansible-inventory` 確認）

> **例外（單一 host + `target_group` 型 spec）**：若這份 spec 的 §1 宣告的 group（如
> `freeipa-server` / `freeipa-client`）刻意**不等於** vm-target 參考環境的 group（測試時 host
> 落在 `all`，靠 `-e target_group=all` override），就**不要**套 `TestRegression_SpecAndInventoryAgree`
> ——那個範本假設「spec 宣告的 group == inventory 的 group」，在這種 spec 會恆假。改在 regression
> test 註解寫清楚「對齊責任在 `-e target_group=` override」，並把其餘結構鎖好（row 連號、lint、
> apply playbook 的 row-ID tags 覆蓋每個 row、AAA/cross-row invariant）。範本見
> `freeipa_client_regression_test.go`。

範本已存在：`core-infra-provider-db_regression_test.go`（含 `TestRegression_SpecAndInventoryAgree`，
group == inventory 的一般情形）與 `freeipa_client_regression_test.go`（單一 host + `target_group`
的例外情形）。新 spec 照對應的結構抄。

---

## 4. 寫 playbook 時

### 4.0 資料夾配置：測試 playbook 與真實 playbook 分開放

`playbooks/` 底下依「用途」分資料夾，新增 playbook 一律放對位置，不准散在 `playbooks/` 根目錄：

| 路徑 | 放什麼 | 性質 |
|---|---|---|
| `playbooks/apply/*.yml` | coding agent 依已確認 spec 直接撰寫、經 review 的真實安裝/設定 playbook（含 snapshot→rollback 安全網；不是 pilot generator 產物） | **真實** |
| `playbooks/decommission/*.yml` | 單一元件的 host decommission 清理 playbook（例：`freeipa-client-decommission.yml`）——one host at a time、idempotent、decommission 專用的 mutation playbook，只由 `internal/decommission/providers` 呼叫，不准 operator 直接跑；不准把每個元件的 product-specific 行為塞進單一 monolithic `host-decommission.yml`（docs/superpowers/specs/2026-09-02-host-decommission-spec.md §15） | **真實** |
| `playbooks/verify/*.yml` | **已棄用（2026-07-17，見該目錄 README.md）**：舊 generator 產物，僅存檔參考。**不要新增、更新或執行**；驗收一律 `pilot verify docs/verification/<x>.md`，`--generate` 也已拒絕輸出到這裡 | **棄用** |
| `playbooks/site.yml`、`playbooks/preflight.yml` | 全站入口與前置檢查 | **真實** |
| `playbooks/test/fixtures/*.yml` | 跨 host 前置狀態、demo / sim / user-setup 等測試前置（見 §4.1） | **測試** |
| `playbooks/test/*.yml` | smoke test / 範例 playbook（如 `hello-localhost.yml`） | **測試** |

- 判準是**用途**不是機制：fixtures 雖然會對 FreeIPA 下真實設定指令，但建的是 demo/測試帳號
  （`pilotuser`/`audituser`/`hz_*`），所以歸測試側。真正的營運身分/權限走
  `playbooks/apply/freeipa-identity-apply.yml`（資料驅動、吃真實 vault roster）。
- 同資料夾內的 `import_playbook` 用**裸檔名相對路徑**（如 `import_playbook: freeipa-client-fixtures.yml`），
  搬動整個資料夾時才不會斷；跨資料夾引用才寫完整 `playbooks/<dir>/<file>.yml`。
- 搬動或改路徑時，全庫（Go、scripts、docs/runbooks、`TESTING.md`、`AGENTS.md`）的引用要一起更新，
  改完 `git grep 'playbooks/<舊路徑>'` 必須為空。

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
  - **機器強制（2026-07-18 起）**：`cmd/pilot/cmd/tag_coverage_test.go::TestSpecPlaybookTagAlignment`
    鎖兩個方向——playbook 有 spec 沒有的 row-shaped tag（孤兒 tag）、spec row 沒有
    對應 tag 的 task 又不在豁免表。新增 spec/playbook 必須進該測試的 `specTagMap`
    （或豁免表附理由）；刻意不用 row tag 的 playbook 用 `noRowTags` 寫明原因。
  - `pilot spec --generate` 的診斷產物即使自動帶 tag，也**不算**正式 apply
    traceability；`playbooks/apply/*.yml` 的 tag 必須由 coding agent 對照 spec
    實際補齊並由 regression test 鎖住。
- **repo 級設計決策要一次系統性套用到所有相關指令，不要遇到一個修一個**：例如
  「這個 topology 不管理 DNS」這個決策，`ipa host-add` 早就用 `--ip-address`
  處理過，但 `ipa service-add` 沒有對應的 `--force`，直到 round 13 才在 apply 時
  才發現。做這類決策時，先 `grep -rn "ipa .*-add\|ipa .*-mod"` 過全部
  `playbooks/apply/*.yml`，把每一支隱含依賴 DNS（或該決策影響的其他前提）的
  指令列成清單、逐一確認，而不是等某個元件真的跑到才發現漏掉。
- **task 的 `vars:` 蓋不掉同名的 `set_fact`/`register` 變數**：Ansible 變數
  precedence 裡 `set_fact`/registered 變數的順位高於 task-level `vars:`，所以想用
  `vars: some_fact: "{{ some_fact | combine(...) }}"` 動態縮小或覆寫一個「早就被
  `set_fact` 設過」的同名變數的視圖，這個覆蓋會被靜默忽略（不報錯，值也不變）。
  2026-07-23 在 item-3（NFS share group-ownership 自我修復）的第一版修法上踩過：
  `freeipa-nfs-server-apply.yml` 的「Render the isolated managed exports
  fragment」task 想用 task-level `vars: nfs_selected_server: {{ ... | combine({'shares':
  nfs_shares_ready}) }}` 把已延後（roster 群組尚不存在）的 share 從匯出清單排除，
  但 `nfs_selected_server` 早被前面的 `set_fact` 設過，覆蓋沒生效，範本仍然把該
  share 的路徑寫進 exports fragment，`exportfs -rav` 在那個目錄根本沒建立時直接
  炸掉——check-mode 測不出來（command 模組在 check mode 下整段被跳過，`nfs_shares_ready`
  變成空清單，兩邊剛好都是空的所以測不出差異），只有對一台全新 host 真的跑一次
  apply（`pilot vm-target test`，帶一個群組故意不存在的測試 roster）才抓到。
  正確作法：要覆寫的話對該變數本身**再下一次 `set_fact`**（而不是用 task `vars:`
  蓋同名字），讓新值成為之後所有 task 看到的事實。
- candidate 凍結前先跑 `ansible-playbook --syntax-check` + `ansible-playbook --list-tags <file>`
  （確認 tag 齊全無撞號）+ 對目標環境（vm-target / docker-target；上真實主機前
  至少對一台 staging）跑一次 `--check --diff`；完整 evidence run 則依 §1.5 對本地
  candidate commit 執行。真實主機沒有
  snapshot→rollback 安全網，`--check --diff` 與 §4 開頭的 `block/rescue` 備份更不能省。
  **這個 `--check --diff` 必須對一台真正全新、從未 apply 過的 target 跑**，不是重複
  用一台早就 apply 過的 dev VM——2026-07-23 的教訓（`docs/runbooks/minimal-poc-architecture.md`
  round 13）：`freeipa-nfs-server-apply.yml`/`freeipa-nfs-client-apply.yml` 的多個 gate
  在全新主機上必掛（因為它們斷言的真實狀態，是另一支 playbook 裡正確地被
  `when: not ansible_check_mode` 擋掉的動作才會產生的），但因為之前只在已經
  apply 過的主機上測過 `--check --diff`，這個 class 的 bug 睡了很久才被抓到——跟
  docker_container/-image 之前修過的同類 bug 一模一樣。`pilot vm-target test` /
  `pilot vm-target topology test`（含 `--ephemeral`）自 2026-07-23 起**內建**這一步
  （L3，snapshot 之前、任何 mutation 之前），對一支多 playbook 交互（例如
  site.yml 裡 freeipa-client 影響 freeipa-nfs-server 那種跨 playbook 依賴）**必須**
  用 `--ephemeral` 對全新 VM 跑過，不能只測單一 playbook。合法無法 check-mode
  的 playbook 才用 `--skip-checkmode` 跳過，並在 spec/runbook 寫明原因。
  便利入口：`make poc-checkmode-test VAULT=<path>`（見 `scripts/topology-checkmode-test.sh`）。

### 4.1 跨 host 前置狀態走 `playbooks/test/fixtures/<spec>-fixtures.yml`

有些 spec 的 check 依賴**別台 host** 上的狀態（例：`freeipa-client` 的 C8「中央 sudo 規則對
IPA 帳號生效」需要 FreeIPA **server** 上先有帳號 + sudo 規則）。這種前置**不要**用手打的
`exec` 指令當口耳相傳的知識——固化成 fixtures playbook：

- 路徑慣例：`playbooks/test/fixtures/<spec-stem>-fixtures.yml`（對應 `docs/verification/<spec-stem>.md`）。
- 跑在提供前置狀態的那台 host 上（通常是 server，不是被測的 client）。
- 必須**冪等**（重跑 `changed=0`）；密碼一律走 vault，敏感 task 加 `no_log: true`。
- 在 spec §7 SOP 明確寫出「先跑 fixtures，再 apply + verify」。

範本：`playbooks/test/fixtures/freeipa-client-fixtures.yml`（kinit 走 vault、`ipa user-add` /
`sudorule-add` 用「rc≠0 且 stderr 沒有 already exists 才算失敗」做冪等）。

**FreeIPA 的 demo / 測試建立使用者只准走這一支**——其他 fixtures 不准自己手刻
`ipa user-add`，一律在檔案開頭用 `import_playbook` 引入並參數化：

```yaml
- name: Ensure the demo IPA user exists (canonical user fixtures)
  ansible.builtin.import_playbook: freeipa-client-fixtures.yml
  vars:
    ipa_fixture_user: "{{ audit_demo_user | default('audituser') }}"
    ipa_fixture_user_first: Audit
    ipa_fixture_user_last: Demo
    ipa_fixture_manage_sudorule: false   # 只建 user；demo 自帶（更嚴格的）sudo 規則
```

- `ipa_fixture_manage_sudorule: false` 很重要：預設的 `pilot-all` 規則是
  hostcat=all + cmdcat=all + `!authenticate`，把 demo 帳號掛上去會讓「預期 sudo
  被拒」的斷言直接破功。
- vm-target 的 inventory 一次只有一台 VM：import 進來的 play 目標是
  `freeipa-server` 群組，對 client VM 跑時該 play 會因比對不到 host 自動 skip
  （反之亦然），所以同一支 wrapper 對 server、client 各跑一次即可，不用拆檔。
  現成範例：`freeipa-audit-user-setup.yml`、`freeipa-hostauthz-user-setup.yml`、
  `freeipa-audit-demo.yml`。

### 4.2 新增或移除「會產生資料/設定檔的軟體角色」時 — 同步 restic-backup 備份範圍

新增一支 apply playbook（`playbooks/apply/<role>-apply.yml`）如果那個角色會
在目標主機上留下**值得復原的資料或設定**（資料庫、目錄服務資料、收到的日誌、
規則檔、憑證…），或是**移除**一個既有角色，**必須**同步檢查/更新下列位置——
不要只顧著讓新角色自己的 spec/playbook 過關就收工：

1. **`group_vars/restic-backup.example.yml`** — 這份檔案底部列了「本專案既有
   角色」的建議 `restic_backup_paths`/`restic_backup_pre_hook` host_vars 範例
   （目前有 FreeIPA server、Keycloak DB、log-server、Wazuh manager 四組）。
   新增角色時補一段對應範例；移除角色時刪掉對應範例，不要留下指向已不存在
   的 playbook/spec 的殘留說明。
   判斷「值得備份」的粗略標準：這個角色的 apply playbook 有沒有寫入 `/etc`
   以外、重開機/重裝會遺失的資料（資料庫 data 目錄、收到的日誌、簽出的憑證
   …）——只裝套件、只改 `/etc` 設定檔的角色通常已被 `restic-backup` 預設的
   `["/etc"]` 涵蓋，不必特別加範例。
2. 需要「先 dump 再備份」的軟體（尤其是資料庫類：直接複製執行中的 data 目錄
   不安全）要在範例裡示範對應的 `restic_backup_pre_hook`（例：`pg_dumpall`、
   `ipa-backup`），不要只給路徑清單、漏掉這一步。
3. 若新角色的主機通常也會需要備份，評估是否要把它加進
   `inventory.example.yml` 的 `restic-backup:` group（比照現有的
   `wazuh-fim`/`audit-log-forwarding` 疊加型 group 慣例——同一台主機同時屬於
   多個角色 group 是常態，不衝突）。
4. `docs/verification/restic-backup.md` 本身**不需要**因為新增/移除軟體而
   改動——它的 checklist（C1–C10）刻意設計成跟具體備份路徑無關（見該 spec
   §1.5 的設計說明：路徑是逐主機變數，spec 只驗證「有沒有快照、完整性過不
   過」這類通用條件）。上面 1–3 點的「範例/文件」才需要同步，**不要**誤以為
   要改 spec 本身的 row 或 regression test。

範本：`group_vars/restic-backup.example.yml` 現有的四個範例區塊
（`host_vars/ipa-1.yml`、`host_vars/keycloak-db-1.yml`、
`host_vars/log-server-1.yml`、`host_vars/wazuh-manager-1.yml`）；設計脈絡見
`docs/verification/restic-backup.md` §1、`docs/runbooks/restic-backup.md`。

### 4.3 stage gate 必須跟 inventory 的環境 group 對齊(cross-check assert)

`playbooks/apply/*.yml` 現在**全部 41 支**都有 `stage`/`confirm_staging`/
`confirm_prod` gate,規則一致、沒有例外(`core-infra-provider`、`dns`、`docker`、
`freeipa-server`、`freeipa-client`、`freeipa-identity`、`freeipa-dns`、
`freeipa-dns-client`、`freeipa-ca-trust`、`freeipa-nfs-server`、
`freeipa-nfs-client`、`freeipa-server-replica`、`freeipa-realm-replacement`、
`keycloak`、`keycloak-db`、`seaweedfs-s3`、`pam-oidc-sshd`、`log-server`、
`audit-log-forwarding`、`wazuh-manager`、`wazuh-fim`、`restic-backup`、
`os-patch-sla`(用 `patch_stage`)、`host-monitoring`、`dcgm-exporter`、`prometheus`、`thanos-query`、
`detection-engine`、`alertmanager`、`snmp-exporter`、`dashboard`、`log-shipping`、`reverse-proxy`、`internal-endpoint`、
`agent-controller`、`gateway-scope`、`pilot-access-gateway`、`pilot-access-directory`、`pilot-session-store`、`pilot-access-target-policy`、`login-probe`)。
`freeipa-server-replica`、
`freeipa-realm-replacement`、
`freeipa-dns`、`freeipa-dns-client`、`freeipa-ca-trust`、`internal-endpoint`、`agent-controller` 與後五支可觀測性堆疊一樣是**還沒接進
`site.yml`**(前三者是刻意的:day-2、opt-in 操作,不是每個部署都要的穩態
角色,比照 `freeipa-identity` 的待遇;`agent-controller` 是 experimental
Phase 1(見 `docs/architecture/agent-monitoring.md`);後五支則是一開始清點時漏掉,
2026-07-09 一併補齊;`snmp-exporter` 也是 opt-in、`site.include: false`——
同 `prometheus`/`alertmanager`/`thanos-query`/`detection-engine`/`dashboard`,
且 Phase 0 階段連 task 都還沒有,見
`docs/superpowers/specs/2026-09-01-snmp-monitoring-integration-spec.md`;`pilot-access-target-policy`
同樣是 day-2/opt-in、`site.include: false`——收緊 transport target 的 sshd 設定是刻意的操作,
不是每次全站部署都該發生的事,見
`docs/superpowers/specs/2026-09-23-pilot-access-gateway-captive-ssh-transport-spec.md` §13)——
**不要因為一支 playbook「還沒接進 site.yml」或
「角色感覺不重要」就假設它可以不用 gate**,新增任何 apply playbook 一律要帶。

寫或改任何一支 apply playbook,`pre_tasks` 除了既有的「staging/prod 需要
confirm 旗標」assert,**必須**同時帶這一道 cross-check(新增同類 playbook 照抄,
變數名依 playbook 自身命名替換):

```yaml
- name: "Gate: stage must match this host's inventory environment group"
  ansible.builtin.assert:
    that:
      - not ('prod' in group_names and stage != 'prod')
      - not ('staging' in group_names and stage != 'staging')
      - not (stage in ['staging', 'prod'] and stage not in group_names)
    fail_msg: >-
      stage={{ stage }} 與 {{ inventory_hostname }} 的 inventory 環境 group 不一致
      (group_names: {{ group_names }})。
```

背景:2026-07-09 發現 `-e stage=` 跟 inventory 的 `staging`/`prod` 環境 group
(純粹給 `target_group` 篩選用的標籤)完全沒有連動——整個 repo 沒有任何
playbook 讀 `group_names` 去反推 `stage`,導致「機器已經歸進 `staging` group,
但指令沒帶 `-e stage=staging`」會靜默用 `sandbox` 的寬鬆門檻套用,沒有任何
警告(等同繞過 confirm gate)。

**寫 runbook / spec / 對外文件描述 stage 行為時,一律照下面這個講,不要簡化成
「要套用就要指定 stage」——那是錯的**:

1. 服務角色 group 有填這台機器,是永遠必要的條件,跟 stage 無關。
2. 這台機器**沒**被歸進 `staging`/`prod` 環境 group → 不用帶 `-e stage=`,
   預設 `sandbox` 直接套用。
3. 這台機器被歸進 `staging`/`prod` → 必須帶對應的 `-e stage=` + confirm 旗標,
   帶錯或漏帶都被上面的 assert 擋下來,不會套用。
4. 新增一支全新的 apply playbook 時,**一律要帶這套 gate,沒有預設豁免**
   (vars 區塊加 `stage: sandbox` / `confirm_staging: false` /
   `confirm_prod: false` / `staging_attested_within_hours: 168`,pre_tasks
   加上面三道 assert,放在該 playbook 既有的其他 gate/pre-flight 檢查**之
   前**)。2026-07-09 之前先漏了 6 支、又漏了另外 5 支尚未接進 `site.yml`
   的可觀測性角色,兩輪才補齊——教訓是「規則要對所有 `playbooks/apply/*.yml`
   一致套用,不要因為某支還沒接進 site.yml、或角色看起來次要,就假設它可以
   例外」。真的有理由不需要 gate 的 playbook(純唯讀、不 mutate 任何東西的
   inspect playbook),在檔頭註解寫清楚原因,不要沉默省略。
5. prod attestation gate 一律寫成
   `that: [(staging_attested_within_hours | int) <= 168]` + `when: stage == 'prod'`。
   **不要**在 `that:` 裡再放 `stage != 'prod'`:`that:` 的每一項都要成立,
   而 `when:` 已經限定只在 prod 執行,多這一項會讓 stage=prod 永遠失敗
   (2026-09-24 修正 9 支 playbook 共 10 道 gate;最早的 core-infra-provider
   `2c25c9d` 一開始就這樣寫,之後被照抄,包括 `pilot deploy` 選 prod 並填了
   有效時數的情況也一樣失敗)。
   `internal/spec/assert_negates_when_regression_test.go::TestRegression_AssertNeverNegatesItsOwnWhen`
   對全部 `playbooks/**` 檢查「assert 的 `that:` 不准是自己 `when:` 的反面」。
6. stage gate(confirm、上面的 cross-check、prod attestation,以及其他只在
   prod 才檢查的 assert)**一律標 `tags: [always]`**。沒標的話,帶 `--tags <row>`
   時 gate 被跳過、帶 tag 的變更照跑。`pilot deploy` 單一元件精靈會把「要只跑
   某幾個檢查項目嗎？」的答案原樣傳給 `--tags`,所以一台已經歸進 `prod` group
   的主機、用預設 stage(sandbox)加上 row tag 部署時,cross-check 不會執行,
   主機就在沒有任何確認下照 sandbox 規則被改(2026-09-25 修正 core-infra-provider、
   docker、keycloak、keycloak-db、reverse-proxy、seaweedfs-s3;同時補上
   freeipa-ca-trust、internal-endpoint 兩個 play、reverse-proxy 缺少的 cross-check——
   在那之前本節「全部都有」的說法並不成立)。唯讀查詢若刻意用 action tag 避開
   gate(`wazuh-manager-agent-deregister.yml`),或像 internal-endpoint 只在
   decommission 唯讀查詢時跳過 cross-check,要在 gate 旁註明原因並登記 allowlist。
   `internal/spec/tagged_run_gates_regression_test.go` 的
   `TestRegression_StageGatesAlwaysRunInTaggedPlays` 與
   `TestRegression_ApplyPlaysWithConfirmGateHaveCrossCheck` 對全 repo 鎖住這兩件事。
7. pilot 自己呼叫 playbook 的地方也要帶 stage:`-e stage=` 必須等於那次 run 的
   目標主機在 inventory 裡的環境 group,staging/prod 還要帶操作者給的確認。
   `pilot host decommission` 原本完全不帶,staging/prod 主機一律卡在
   cross-check(2026-09-25 重現);現在由 `internal/decommission/stage.go` 的
   `StageScope` 依「每次 run 的目標主機」決定 stage——退役主機用它自己的,
   FreeIPA identity reconcile 用 freeipa-server 主機的,Wazuh deregistration
   用 wazuh-manager 主機的——`apply`/`resume` 收 `--confirm-staging`、
   `--confirm-prod`、`--staging-attested-within-hours`(TUI 問同樣的問題),
   缺確認時在任何步驟前拒絕。一次 run 的目標主機跨不同 stage 時直接報錯。
   唯讀查詢(`freeipa_host_absent_inspect`,`plan` 階段就會跑;
   `iep_decommission_verify`)不帶 stage,對應 playbook 只在「這個 tag 是唯一
   的 tag」時跳過 cross-check(`(ansible_run_tags | list) != [...]`——
   ansible-core 2.19 的 `ansible_run_tags` 是 tuple,直接跟 list 比永遠不相等),
   由 `TestRegression_DecommissionQueryCrossCheckExemptions` 鎖住。
   新增會呼叫 playbook 的 pilot 功能時照這個模式做,不要只帶 sandbox。

另外,`playbooks/site.yml` 開頭有一道獨立的安全閥(`hosts: localhost` 的
`assert target_group is not defined`),擋下「全站入口誤帶 `-e target_group=`
同時覆寫全部子 playbook 目標,讓『空 group 自動跳過』的保護失效」的事故——
這道閥**不要**移除或繞過。新增 import 進 `site.yml` 的 playbook,若它的
`hosts:` 也走 `target_group` 覆寫慣例,要確保它只在「單獨執行」時被 override,
不依賴 site.yml 幫忙擋。

### 4.4 `always` tag 的前置探測/set_fact task 要跟著標 `always`

Site-wide deploy 在 operator 沒帶 `--tags` 時,`effectiveDeploymentTags` 仍會
合成內部依賴 tags 餵給 Ansible;即使如此,一支 playbook 裡 `tags: [always]`
的 task **永遠會跑**,但它讀取的前置 fact/探測 task 如果沒有同樣標 `always`,
在 tag-scoped apply 下會被跳過——結果是 `always` task 在讀一個從沒被設過的
變數,要嘛 undefined-variable 崩潰,要嘛靜默吃到預設值、漏資料。

2026-09-03 這個模式在同一天連續咬了三支 playbook:`prometheus-apply.yml`
(外部 scrape target 編譯任務,commit `2abb6fd`)、`dcgm-exporter-apply.yml`/
`host-monitoring-apply.yml`(GPU/port 探測 pre_tasks,commit `dada083`)。
`af239e3` 已加入 repo 全域 regression lint 鎖住這個不變量,但第一版**只掃了
`tasks:` 區塊,漏掃 `pre_tasks:`**,導致同一天又多抓到 2 個真 bug 才補齊。

新增或修改任何一支 `playbooks/apply/*.yml`:

- 只要某個 task 標了 `tags: [always]`,**回頭檢查它讀的每一個變數**是從哪個
  task 的 `set_fact`/`register` 來的,那個來源 task 也必須標 `always`(跨
  `tasks:` 與 `pre_tasks:` 都要檢查)。
- 對「`--tags` 留空」與「只給該元件自己的單一 tag」兩種情境各跑一次該
  playbook(見 §4.0 的 `--check --diff` 要求),不要只驗證「有帶完整 tags」
  的那條路徑。
- 跑 `internal/spec` 裡名稱含 `AlwaysTagPrerequisite` 的 regression lint,
  確認新 task 沒有漏掛。
- 檢查(assert/fail)本身也一樣:放在 `pre_tasks` 的輸入檢查,或跟帶 row tag
  的步驟放在同一個 task 清單裡的檢查,沒有 tag 就會在任何 `--tags` run 被跳過,
  而它要擋的步驟照跑。輸入檢查一律標 `always`(它讀的 fact 也要 `always`,
  見上一點);流程中間驗證某一步結果的 assert 標那一步的 row tag。2026-10-01
  修正 10 支 playbook 共 20 個沒有 tag 的檢查(必填變數、secrets、S3 位址、
  alertmanager 設定、detection-engine feature profile,以及 detection-engine/
  agent-controller 複製 binary 後的 SHA256 與 status 檢查),
  `internal/spec/tagged_run_gates_regression_test.go::TestRegression_NoUntaggedChecksInTaggedPlays`
  對全 repo 鎖住。跟沒有 tag 的步驟放在一起的檢查不受影響(decommission
  playbook 的移除與驗證都只在完整 run 執行)。
- rescue 也一樣會被 `--tags` 篩選:帶 tag 的 run 失敗時,只有 `--tags` 也選得到
  的 rescue task 會執行(ansible-core 2.19.2 實測)。rescue task 沒有 tag,
  `--tags <row>` 失敗就不會回滾;rescue 只剩一部分 task 有 `always`、最後的
  `fail` 卻沒有,rescue 會「成功」,整個 run 反而回報成功。規則:block 裡有帶
  tag 的 task,rescue 每個 task 都標 `always`;rescue 讀的 snapshot/fact(備份檔、
  `*_is_upgrade` 這類升級判斷、備份目錄)也要標 `always`(上面第一點,
  `AlwaysTagPrerequisite` lint 會抓)。只還原「這次 run 改過的東西」的 rescue
  可以改用 `x is defined` 檢查 setter 有沒有跑(audit-log-forwarding 的
  audit.rules 還原),lint 接受這種寫法,但不接受單純的 `| default`。
  block 的 `always:` 區段同理。
  `internal/spec/rescue_tags_regression_test.go::TestRegression_RescueRunsWheneverItsBlockDoes`
  對全 repo 鎖住;2026-10-01 修正 8 支(agent-controller、alertmanager、
  dashboard、detection-engine、pam-oidc-sshd、prometheus、restic-backup、
  thanos-query),同日再修正其餘 12 支,`rescueTagGapAllowlist` 清空。
- 不只 `always` task:帶 row tag 的 task 讀的 `register`/`set_fact`,setter 也
  要在同樣的 `--tags` 下執行(setter 標 `always`,或帶 reader 的每個 tag),
  不然就用 `| default(...)`/`is defined` 讀。最常見的是 container task 的
  `restart: "{{ x_result is changed }}"`:render task 是別的 row tag,
  `--tags <container row>` 每次都在 container task 報 undefined。rescue 會在
  `--tags` 下回滾之後,這種必然失敗會連帶刪掉設定檔或停掉服務,所以要一起修。
  `restart:` 這類「這次有沒有改」的判斷用 `(x_result | default({})) is changed`
  (render 沒跑就是沒改,不重啟)。`include_tasks` 檔案裡設的 fact 也算:
  wazuh-manager C10、wazuh-fim C7 的 `/etc/hosts` pin 讀
  `tasks/resolve-hosts-alias-target.yml` 設的 `hosts_alias_resolved_ip`,但那個
  include 沒有 tag,這兩列每次都失敗,rescue 會在 `--tags` 下跑之後就把部署好的
  設定刪掉(2026-10-01 實跑抓到;audit-log-forwarding C15、log-shipping C5、
  restic-backup C10 同樣)。只讀的共用 include 用
  `tags: [always]` + `apply: {tags: [always]}`;lint 會展開 include 檔案檢查。
  `internal/spec/tagged_prerequisite_regression_test.go::TestRegression_TaggedTasksReadOnlyWhatTheirTagsSet`
  對全部 `playbooks/apply/*.yml` 檢查;2026-10-01 修了上面 8 支裡的 6 支,
  同日再修 rescue 那 12 支裡的 8 支,最後修其餘 7 支(freeipa-client、
  freeipa-identity、gateway-scope、pilot-access-directory、pilot-access-gateway、
  pilot-session-store、seaweedfs-s3),`taggedPrerequisiteAllowlist` 清空。
  Kerberos ticket 也是前置:跑 `ipa` 指令的 task,同一個 play 裡前面的 kinit
  要標 `always` 或帶它的 row tag——playbook 在完整 run 結尾會 `kdestroy`,
  沒有快取的 ticket 可以撐。freeipa-identity 的 admin kinit 原本只有群組 tag
  (每個 C<n> row 都報 `did not receive Kerberos credentials`),
  pilot-access-directory AD_service、pilot-session-store SS_service 也一樣;
  `internal/spec/ipa_kinit_regression_test.go::TestRegression_IpaCommandsHaveAKinitForTheirTags`
  對全部 `playbooks/apply/*.yml` 檢查(對應的 kdestroy 也要帶同樣的 tag)。
- 反方向也一樣:mutation **之前**必須先跑的 task,即使 mutation 不讀它的結果,
  也要帶齊 mutation 的每一個 tag——例如把 mutation 會毀掉的資訊先記下來的
  task、擋降級的 assert。反過來,只該在 restart/health 之後才做的清理,在
  `--tags` run 裡要自己確認前提成立(沒有待生效的重啟、health 此刻通過),不能
  假設完整 run 裡排在前面的步驟這次也跑過。2026-10-02 PR #19 review:
  pilot-access-gateway 的 Step 11 帶 AG01/AG41/AG42/AG94,記下舊 token 路徑的
  AG82 task 只帶 `AG_config`/`AG82`,`--tags AG01` 換掉唯一記錄自訂 token 路徑的
  config,之後的完整 apply 再也找不到那個 token;`--tags AG_config`/`AG82` 則在
  舊 gateway 還在跑時就刪掉它;錄影政策的降級檢查也少了 AG94、AG81。這種前後
  關係無法從 YAML 推導,逐一用測試鎖住
  (`internal/spec/pilot_access_gateway_ag82_regression_test.go::TestRegression_GatewayWritesFollowTheirChecks`,
  另有對每個 tag 實際跑一次的行為測試)。

### 4.5 Ansible 語意陷阱:語法合法、執行不報錯,結果卻是錯的

§4.0 已經記過一個(task `vars:` 蓋不掉同名的 `set_fact`)。2026-08-24~09-24
的 fix 又踩到同一類的另外幾個;其中第 2、3、7 點都是修過之後又在別處重犯
(見 §5.10)。它們全部通過 `--syntax-check`、執行時也不報錯,只有在真機上看
結果才會發現:

1. **block 的 `when:` 會在 block 內每個 task 各自重新判斷**,不是進 block 時
   判斷一次。如果 block 的條件是一個會被 block 內 task 改掉的 fact,條件一翻,
   block 後半段的 task 就被靜默跳過。`5b735ee`:apt refresh block 以
   `not _pilot_apt_has_candidate` 當條件,block 內的 re-check 一成功,後面的
   task 就全被跳過。**規則**:block 的條件只能用進 block 前就固定、block 內
   不會再被改動的 fact;需要時先 `set_fact` 一個專用的 gate fact。
2. **同一支 task 檔被 include 多次時,前一次 include 設的 `set_fact` 仍然有效**。
   `6a32a00`(08-28)先在 `tasks/resolve-hosts-alias-target.yml` 修過一次:
   第二次 include 沿用第一次留下的 `hosts_alias_resolved_ip`,detection-engine
   的 Alertmanager alias 被釘成 Thanos 節點的 IP。`5b735ee`(09-23)又在
   09-14 新增的 apt framework 修一次:`freeipa-client` 把它 include 兩次,
   第二次安裝 `sssd-tools` 時讀到第一次留下的 `stale_metadata=True`。
   **規則**:會被重複 include 的 task 檔(`playbooks/apply/tasks/*.yml`),
   開頭必須重置自己的 per-include 狀態 fact。
3. **play 層級的 `vars:` 優先順序高於 inventory 的 `group_vars`/`host_vars`**。
   `360c6f2`(09-11)先修過 `internal-endpoint-apply.yml` 與
   `detection-engine-apply.yml`(空字串預設值蓋掉 operator 在 inventory 設好的值);
   4 天後 `81f7090` 又在 09-14 新增的 `pilot-access-gateway-apply.yml` 修一次:
   它在 play `vars:` 把 `gateway_id`/`freeipa_servers`/`ipa_realm` 等寫成
   字面值,contract-driven inventory 提供的值全部被蓋掉,不報錯。
   **規則**:應該由 inventory 提供的
   變數,不准在 play `vars:` 宣告;必填的讓既有 assert 擋,選填的用
   `_effective_` 別名加 `default()`。(§4.3 的 `stage`/`confirm_*` 預設值不在
   此限:它們由 `-e` 提供,而 `-e` 的優先順序高於 play vars。)
   2026-10-13 第三次:15 支 playbook 在 play `vars:` 宣告了 60 個 contract
   `groupVars` 或 `group_vars/<role>.example.yml` 記載的變數(snmp-exporter
   的 group_vars 範本整份沒有效果),`pilot deploy` 的 preflight 讀到 inventory
   的值,Ansible 實際用的卻是 play 預設值。現在改在 stage gate 之後用一個標
   `always` 的 `set_fact`(`x: "{{ x | default(...) }}"`)補預設值,並由全 repo
   lint `internal/spec/play_vars_inventory_precedence_regression_test.go::TestRegression_ApplyPlayVarsDoNotShadowInventoryInputs`
   鎖住:任何一份 contract 的 `groupVars` 與 example 的 key,都不准出現在任何
   apply playbook 的 play `vars:`,不只是它自己 contract 的那支——同一台主機上
   一個變數只有一個值,兩支 playbook 必須讀到同一個值(只修 log-shipping 時,
   log-server 仍用 play vars 的 `siem_log_root`,Promtail 會 tail 一個 rsyslog
   沒寫入的目錄)。刻意由其他變數推導的(FreeIPA playbook 的 `ipa_realm`)列在
   該測試的 `playVarsInputAllowlist` 並寫明理由。spec 變數契約表(標題含「變數契約」
   的 `##` 段落,例如 §1.5 依賴變數契約、dns.md §3 Apply 變數契約)第一欄列出的變數
   也必須宣告在 contract `groupVars`:只寫在 group_vars example 不算,因為 preflight
   只讀 `groupVars`(`TestRegression_SpecInputsAreDeclaredContractInputs`;issue #81
   的待處理清單已清空,不再接受 allowlist)。衍生別名、單次 `-e` 授權與 roster 欄位
   另列非 inventory 的段落,不得冒充 inventory 輸入。log-server 的
   `siem_receiver_tcp_port` 只寫在 spec,play vars 一直蓋掉 inventory,client 改送
   2514 時 rsyslog 仍聽 514。宣告成 `integer` 的 input,preflight 與 repair 都接受
   整數、整數值的 float(`ansible-inventory --list` JSON 的數字)與十進位字串
   (`contract.ValueMatchesType`),port 一律宣告成 `integer`。
   新增 groupVars 或 example key 時,預設值寫在這個 `set_fact`。
4. **check mode 下被跳過的 task,register 出來的結果沒有 `stdout`**。直接對它做
   `from_json` 或取 `.stdout`/`.json`,在 `--check --diff` 會崩潰(`81f7090`
   Step 17/18)。依賴同一次 run 裡只被「模擬」的前置動作(建使用者、enroll)
   的 task 也一樣(`4675b6b`)。**規則**:讀取「check mode 下可能被跳過的 task」
   結果的 task,要加 `when: not ansible_check_mode` 或先判斷 `is skipped`。
   全新主機的 preview 需要提早結束時,印明確訊息再 `meta: end_host`;真實 run
   仍然 fail closed。
5. **只為安裝器準備的 task 沒加條件,每次 apply 都把狀態重設回去**。
   `875066d`:`freeipa-server-apply.yml` 預建 installer 目錄時強制
   `root:root 0755`,但 installer 跑完後就接手了這些路徑的 owner(例如
   `/var/lib/ipa/pki-ca/publish`)。全新安裝後的第一次重跑就 `changed=1`,還
   改掉了 installer 設的權限;之後幾次看起來冪等,只是因為破壞已經發生過了。
   **規則**:只為 installer 或一次性流程準備的 task,必須用「安裝已完成」的
   marker(例如 `ipa_cfg`)擋住。驗證冪等要看「全新安裝**之後的第一次**重跑」,
   不是對一台已經重跑過很多次的主機再跑一次。
6. **同一個 task 裡重複的 YAML key(例如兩個 `register:`)只有最後一個生效**
   (`c0890f6`)。`make playbook-lint` 會跑 `scripts/check-yaml-duplicate-keys.py`
   抓這類錯誤,凍結 candidate 前要跑過。
7. **`shell` 模組預設用 `/bin/sh`;在 Debian/Ubuntu 上那是 dash,不認得
   `set -o pipefail`**:它會印出 `Illegal option -o pipefail` 並以 rc=2 結束,
   後面的指令完全不會執行(2026-09-24 在本機 dash 0.5.12 + ansible 實測)。
   `869f164` 修過 decommission 的一處;2026-09-24 全 repo 掃描又找到 5 處,
   最嚴重的是 `tasks/freeipa-dns-client-resolver.yml` 的 rescue ROLLBACK:它設了
   `failed_when: false`,所以在 Debian/Ubuntu 上 `/etc/resolv.conf` 從來沒被
   還原,下一個 task 卻印出「was restored」。**規則**:用到 bash 語法
   (`pipefail`、`[[`、`<<<`、陣列)的 shell task 必須加
   `args: {executable: /bin/bash}`。`internal/spec/shell_pipefail_regression_test.go`
   對全部 `playbooks/**` 檢查 `pipefail` 這一項。rescue 裡的 rollback 如果用
   `failed_when: false`,要 register 結果,並在後續訊息如實說明有沒有還原,
   不准寫死「已還原」。
   設了 `pipefail` 之後,也不准 pipe 進會提早結束的 reader(`head`、
   `grep -q`/`-m`、`sed …q`、`awk …exit`):reader 先結束時 writer 收到
   SIGPIPE,整條 pipeline 以 rc=141 結束,搭配 `set -e` 就直接中止,即使
   reader 已經拿到要的資料。2026-09-24 `tasks/freeipa-dns-client-resolver.yml`
   的 snapshot 用了 `nmcli … | head -n1`,讓
   `TestFreeipaDNSClientRollback_ELRestoresNetworkManagerSettings` 約 1% 機率
   失敗,main CI 因此兩度變紅。改成讀完整個輸出(`sed -n 1p`、`grep -c`)或在
   bash 裡取第一行(`${out%%$'\n'*}`);
   `TestRegression_PipefailShellTasksHaveNoEarlyExitReader` 對全部
   `playbooks/**` 檢查。
8. **`include_tasks` 的 `tags:` 只作用在 include 那一行,不會傳給被 include
   進來的 task**。`374780b`:帶 `--tags C1` 時 apt framework 什麼都沒裝,也
   不報錯。要讓 `--tags` 篩選生效,寫成
   `include_tasks: {file: ..., apply: {tags: [...]}}`。2026-09-24 已用
   ansible-core 2.19.2 實測確認。全 repo 由
   `internal/spec/include_tasks_apply_tags_regression_test.go::TestRegression_TaggedIncludeTasksUseApply`
   鎖住（2026-09-24 已全部遷移，allowlist 為空）。加上 `apply` 之後，被
   include 的 task 可能讀到同一次 `--tags` run 沒設過的 fact（§4.4），也可能
   繞過沒帶 tag 的安全 gate：前置 fact 要跟著帶對應 tag，只讀的載入/正規化
   pre_tasks 標 `always`，mutation 安全 gate 標它保護的 row tag（範例：
   `internal-endpoint-apply.yml`）。遷移要對該 playbook 跑 tag-scoped 的
   vm-target 測試。被多個 caller 共用的 task 檔裡再 include 別的檔案時，無法寫出
   caller 的 row tag，用 `apply: {tags: [always]}`（代表「這個 include 有跑就跑」，
   例：`tasks/freeipa-dns-client-resolver.yml` 的 dig 安裝）。
   安全 gate 的 tag 要涵蓋它保護的**每一個** mutation 的 row tag，不只是 gate
   自己那一列：PR #10 的 review 抓到遷移後的兩個繞過——`freeipa-ca-trust` 的
   stage gate 沒帶 tag，`--tags C2 -e stage=prod` 沒帶 `confirm_prod` 也照樣
   裝 CA；`internal-endpoint` 的 C7/C8 DNS gate 只標 `[C7]`/`[C8]`，`--tags C4`
   就能在不檢查 zone/collision 的情況下改 DNS record。有 `apply` include 的
   play，pre_tasks 裡的 assert/fail 一律標 `always`（或帶齊該 play 所有 include
   apply 的 tag），由
   `internal/spec/tagged_run_gates_regression_test.go::TestRegression_PreTaskGatesRunUnderApplyTags`
   鎖住（allowlist 只剩 core-infra-provider 的 `infra_role` 與 restic-backup
   的兩道輸入檢查，留給後續修正；stage gate 已全部是 `always`，見 §4.3 第 6 點）；`tasks:` 裡的 gate 對 mutation 的對應無法從 YAML
   推導，要像 `TestRegression_InternalEndpointGatesCoverTaggedMutations` 那樣
   逐一鎖住。
9. **`ansible.builtin.apt`/`package` 直接裝套件、不走 apt framework，會吃當下
   主機上的 apt index**：index 過期時下載 404，apply 在真正要做的事之前就失敗
   （2026-09-24，`tasks/freeipa-dns-client-resolver.yml` 在 vm-target golden
   image 上）。Debian 路徑一律用 `tasks/apt-package-install.yml`；
   `cmd/pilot/cmd/apt_policy_test.go::TestAptDirectInstallAllowlist` 鎖住
   （2026-09-24 已全部遷移，allowlist 為空）。
10. **free-form `shell:`/`command:` 字串會先經過 Ansible 的 `split_args`,
   連 shell 註解裡的引號也算**:註解寫了一個 apostrophe(`test's`),整支 task
   檔載入失敗(`failed at splitting arguments, either an unbalanced jinja2
   block or quotes`)。bash 看不到註解,所以直接跑腳本的 unit test 會過;
   `--syntax-check` 不載入 `include_tasks` 的檔案,也抓不到,只有真的跑才會
   現形(2026-09-24,`tasks/freeipa-dns-client-resolver.yml`)。free-form
   字串裡(含註解)的引號與 Jinja `{{ }}`/`{% %}`/`{# #}` 都要成對;
   `internal/spec/freeform_args_regression_test.go::TestRegression_FreeFormCommandsSplitInAnsible`
   用與 `split_args` 相同的規則檢查全部 `playbooks/**`。
11. **在 loop 裡累加的 fact,loop 沒有任何 item 時就不會被設定**:
   `x: "{{ (x | default([])) + [item] }}"` 這種寫法,清單是空的時候 `x` 仍然
   undefined,之後任何不帶 default 的讀取都會失敗。2026-09-25
   `internal-endpoint-apply.yml` 的 `internal_endpoint_normalized` 在
   `endpoints: []` 時讓 decommission verify 查詢直接報
   `'internal_endpoint_normalized' is undefined`。累加前先用 `set_fact` 設成
   空值(`[]`/`{}`);或確保每個不帶 default 的讀取都被檢查過它的 `when:` 擋住,
   或跟累加的 task 用同一個 loop。
   `internal/spec/loop_accumulator_regression_test.go::TestRegression_LoopAccumulatorsAreInitializedOrGuarded`
   對全部 `playbooks/**` 檢查。
12. **`{{ }}` 模板裡字串字面值的 `\\` 不會被還原成 `\`**(ansible-core 2.19.2,
   2026-10-02 實測):YAML 不是雙引號字串時,`regex_replace('/\\.', '')` 找的是
   「反斜線 + 任意字元」,永遠比對不到,也不報錯。裸的 `when:`/`that:` 運算式
   兩種寫法都會還原,所以同一個 regex 在 `that:` 裡有效、在同一個 task 的
   `fail_msg` 裡卻失效:AG82 的 `..` 檢查會擋下路徑,訊息卻列出空清單;路徑
   正規化的 `/./` 也從來沒有生效,測試只是靠另一道 inode 比對過關(PR #19)。
   模板裡一律寫單一個反斜線(`'/\.(?=/|$)'`、`'\1'`),兩種情境都正確;或改用
   雙引號 YAML 字串,讓 YAML 先吃掉一層。
   `internal/spec/template_backslash_regression_test.go::TestRegression_JinjaTemplatesUseSingleBackslashes`
   對全部 `playbooks/**` 檢查(`freeipa-dns-apply.yml` 的 `[ \\t]` 列在 allowlist:
   `ipa` 輸出只用空白縮排,結果正確,修正要另外對 freeipa-dns 實跑),
   `TestJinjaTemplateBackslashSemantics` 對本機 ansible-core 鎖住這個前提。
13. **被 `when:` 跳過的 task 仍然會 register,值是 `{changed: false, skipped: true}`**:
   用 `combine()` 合併兩個互斥 task 的 register 結果,最後合併的那個決定
   `changed`。`prometheus-apply.yml` 這樣合併兩個 prometheus.yml render,
   有 Alertmanager 時被跳過的「無 alerting」版本蓋掉 `changed: true`,設定
   變更從未重啟 container(2026-10-12 正式環境:新的 dcgm-exporter target
   寫進主機檔案好幾週,Prometheus 都沒 scrape)。**規則**:每個 register
   結果各自用 `(x | default({})) is changed` 檢查再 `or`,不准合併;
   `internal/spec/registered_result_combine_regression_test.go::TestRegression_RegisteredResultsAreNeverCombined`
   對全部 `playbooks/**` 檢查。
   同一次事故的另一半:**單檔 bind mount 在 `copy` 換掉檔案後仍指向舊 inode**。
   `copy` 用 rename 寫檔,主機路徑換成新 inode,沒重啟的 container 繼續讀
   舊檔,reload(Prometheus `/-/reload`、SIGHUP)也只重讀舊檔。只靠「這次
   render 有沒有 changed」決定重啟,一旦某次 run render 了檔案卻沒走到重啟
   (失敗、`--tags`、條件寫錯),之後每次 run 都看到檔案沒變,container 永遠
   讀舊檔。container task 前 include `tasks/container-file-mount-drift.yml`
   (比對 container 實際看到的檔案與主機檔案,不同就重啟),include 標
   `always`、`when:` 跟 container task 相同,`restart:` 加上
   `or container_mount_drift_stale | default(false) | bool`。目前 8 支
   playbook 的 11 個 container 都已接上(prometheus、thanos-sidecar、
   alertmanager、teams-proxy、loki、dcgm-exporter、promtail、seaweedfs、
   snmp-exporter、thanos-store、thanos-compact);
   `internal/spec/container_file_mount_regression_test.go::TestRegression_FileMountedContainersRestartOnStaleMounts`
   對全部 `playbooks/**` 檢查:掛單一檔案的 docker_container 前面必須有
   同一個 container 的檢查,`when:` 要相同,且 `restart:` 要讀它的結果。
   這個檢查讀的 inspect 結果含 container 的 `Config.Env`,單獨掛載的密碼檔
   hash 出來就是密碼的 SHA-256,所以它的 task 都是 `no_log`
   (`TestRegression_ContainerFileMountDriftHidesWhatItReads`)。

14. **`kinit` 沒帶 `KRB5CCNAME` 就寫進執行帳號的預設 credential cache**,playbook
   結束後 ticket 一直留在主機上,之後任何用預設 cache 的程式(其他自動化、操作者
   手動的 `ipa`、診斷工具)都在不知情下以那個身分執行。2026-10-13(issue #69)全新
   部署的 FreeIPA server 上 root 的 `KCM:0` 就留著 `admin@REALM`。只在成功路徑最後
   `kdestroy` 不夠:失敗、`--tags`、以及 `KCM:`/`KEYRING:` collection(之後另一個
   principal 的 kinit 會切換 primary cache,裸 `kdestroy` 只刪掉那一個)都會留下 ticket;
   pilot-access-gateway 甚至從來不 `kdestroy`(PR #72 review)。**規則**:
   - 把用到 ticket 的 task 包進一個 block,block 的 `environment:` 設
     `KRB5CCNAME: "{{ pilot_krb5ccname | default('FILE:/nonexistent/pilot-krb5cc-not-open') }}"`,
     第一個 task include `tasks/freeipa-private-ccache-open.yml`、`always:` include
     `tasks/freeipa-private-ccache-close.yml`,兩者都標 `always` 並帶
     `apply: {tags: [always]}`。block 裡(含 include 進來的檔案)的 kinit/ipa 都用這個
     私有 cache,成功、失敗、`--tags` 都會清掉。kinit 以 `become` 執行時,block 也要
     `become`,cache 才會屬於同一個帳號。
   - close 會把 `pilot_krb5ccname` 設回不存在的路徑:fact 會活過 block 與 play,不重設的話,
     之後的 kinit 會寫進已刪除的路徑,重新建出沒人清的 cache。被 SIGKILL 留下的 cache 由
     同一個執行帳號下次執行時清除,而且只清自己的:共用 sticky `/tmp` 裡別的帳號的 cache
     刪不掉,刪了會讓整個 run 在 kinit 之前 EPERM 失敗。`--check` 時只回報、不刪。
   - 會被別處 include 的 task 檔裡的 kinit 自己寫 `environment: {KRB5CCNAME:
     "{{ pilot_krb5ccname }}"}`,在 block 外被 include 時直接失敗,不會退回預設 cache。
   - 也接受:`ansible.builtin.tempfile` 註冊的 cache,且外層 block 的 `always:` 對它
     `kdestroy`,tag 涵蓋 kinit 的每一個 tag(`freeipa-dns-apply.yml` 的寫法);只需要
     kinit 結果碼時用 `-c MEMORY:<name>`。字面值(`KCM:`、`""`、固定的 `/tmp` 路徑)不算私有。
   - 不要用 play 層級的 `environment:`:它也會套到 `ipa-server-install`/`ipa-client-install`
     這類安裝程式。
   - `ipa` 指令要跟 kinit 用同一個 cache:放在同一個 block 裡;放在 block 後面就沒有 ticket。
   - spec 的 checklist row 不能依賴 playbook 留下的 ticket:`pilot-gateway-scope.md`、
     `internal-endpoint.md` 原本直接跑 `ipa`,能通過只是因為 #69 的 ticket 一直留著。
     需要讀 FreeIPA 的 row 用 root 經 ldapi 的 SASL EXTERNAL(`freeipa-identity.md` 的寫法)。
     這類 row 一定要以 root 執行:`spec.NeedsBecome` 看到 `ldapi://` 或 `-Y EXTERNAL` 就會 become
     (非 root 的 SASL EXTERNAL 只會以該 uid 或匿名綁定,讀到的比較少,verdict 取決於誰連線),
     `internal/spec/needs_become_ldapi_regression_test.go` 對全部 spec 鎖住。
     server 的 host keytab 不能代替:FreeIPA 對 host principal 靜默隱藏部分屬性
     (例如 `txtrecord`)。
   - `vm-target run --sandbox` 會把整個 `playbooks/` 複製進 container,跨目錄的 include
     (`playbooks/check/*` include `../apply/tasks/...`)才找得到。
   - lint:`internal/spec/kinit_private_ccache_regression_test.go::TestRegression_KinitUsesAPrivateCredentialCache`
     對全部 `playbooks/**`(`.yml` 與 `.yaml`)檢查每一個 kinit,沒有 allowlist;
     `internal/spec/ipa_kinit_regression_test.go::TestRegression_IpaCommandsHaveAKinitForTheirTags`
     檢查 `ipa` 跟 kinit 用同一個 cache;
     `internal/spec/spec_probe_split_args_regression_test.go::TestRegression_SpecProbesSplitInAnsible`
     檢查 spec row 能通過 Ansible 的 `split_args`(row 的註解裡有 `'` 會讓 `pilot verify`
     在 shell 執行前就失敗)。
15. **密碼插進 shell 或 free-form `command:` 字串,會被 shell 展開或斷詞改寫**:
   Ansible 先把值代入指令字串,shell 才解析,所以密碼裡的 `$`、反引號、`$(...)`
   會被展開,甚至被執行;引號則會讓整行解析失敗。free-form `command:` 會先斷詞,
   空白和引號一樣會改變內容。`no_log: true` 只隱藏輸出,擋不住這些。
   2026-10-16 PR #92 review:replica forwarder 的
   `printf %s "{{ ipa_admin_password }}" | kinit` 在既有 DNS replica 上重跑時,
   `demo$x` 讓 kinit 收到 `demo`;實跑時密碼裡的 `$(touch …)` 在 replica 上以 root
   執行。同一支 playbook 的 self-register kinit 與 primary 的 dnsconfig-mod kinit
   也是同樣寫法。**規則**:密碼用 `ansible.builtin.command` 的 `stdin` 傳入
   (`argv: [kinit, …]` 加 `stdin:`)。argv 元素雖然不會被改寫,但任何本機使用者都能從
   `/proc/<pid>/cmdline` 讀到,只能用在沒有其他輸入方式的程式(FreeIPA installer)。
   `internal/spec/secret_command_text_regression_test.go::TestRegression_NoSecretInCommandText`
   對全部 `playbooks/**` 檢查。main 上原本就有的 33 處列在 allowlist,記錄每個
   `<檔案>::<task 名稱>` 的 task 數:同名 task 被複製一份也會失敗,遷移後不調低數字
   也會失敗;遷移由 #118 追蹤。`TestRegression_FreeIPAKinitTasksPassPasswordUnchanged`
   用真實 `ansible-playbook` 與 fake kinit 確認密碼原樣送達。

16. **`ipa` 的長選項接受唯一前綴**:`ipa` CLI 用 Python optparse,一個不存在的選項只要是
   另一個選項的唯一前綴,就被靜默當成那個選項。`hbacrule-find`/`sudorule-find` 沒有 host 篩選,
   host decommission 查詢用的 `--host=<fqdn>` 一直被當成 `--hostcat`,永遠查到 0 筆,HBAC/sudo
   直接引用的檢查因此永遠 pass(issue #104,2026-10-15)。**規則**:playbook 裡每個
   `ipa <子指令> --選項` 都要是該子指令 `--help` 列出的完整選項名稱;
   `internal/spec/ipa_cli_options_regression_test.go::TestRegression_PlaybookIPAOptionsExistInIPAHelp`
   對全部 `playbooks/**` 檢查,選項清單在 `internal/spec/testdata/freeipa-cli-options.txt`
   (FreeIPA 4.13.4 擷取)。新增子指令時,在 FreeIPA server 跑 `ipa <cmd> --help` 補進清單。

驗證方式:改完依 §4.0 對**全新** target 跑 `--check --diff`,再依 §1.4 用
`vm-target test`/`topology test --ephemeral` 確認 L6 冪等檢查是接在一次
from-scratch install 之後。

---

## 5. 寫 / 改 Go code 時

- 凍結 candidate 前先跑 `go build ./...` 跟 `go test ./...`；正式 evidence run
  依 §1.5 對不可變 candidate 執行
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
- 狀態持久化**一律**走 `internal/statefile.Store[T]`（版本化 + 原子寫入 +
  跨行程 flock，已測）。不要再手寫 temp-file+rename。
- **任何 state 的 read-modify-write 一律走 `Store.Mutate(fn)`**，不准
  `Load()` → 改 → `Save()` 分開做——那正是 2026-07-06 兩個 `vm-target up`
  並行時 last-writer-wins、一台 VM 的 state 條目消失變孤兒 domain 的事故
  根因（`Save` 只保證「單次寫入原子」，不保證「讀改寫整段原子」）。長時間
  操作（建 VM、teardown）放鎖外，只有比對/改 slice 的那一小段放進 Mutate
  的 fn。回歸測試：`statefile_test.go::TestStore_ConcurrentMutateLosesNoEntries`、
  `vmtarget_test.go::TestUp_ConcurrentDifferentNames_BothPersist`。
- CLI 端把 inventory 寫到暫存檔一律用 `writeTempInventory`（`cmd/pilot/cmd`）。

### 5.2 長生命週期物件不要把 per-call option 寫回自身欄位

`Manager` 這種跨多次呼叫重用的物件，per-call 的選項（timeout、旗標）要用
**區域變數**傳進去，不可寫回 `m.xxx` 欄位——否則一次呼叫的 override 會外洩到
之後每一次操作（vmtarget 的 `m.sshTimeout` 就中過這個雷）。

### 5.3 Coding agent 是開發介面，不是 pilot runtime dependency

- Codex/Claude 可以讀 repo、改檔、跑測試並依本檔產出 feature bundle；這是
  repo 開發流程，不是 pilot binary 的一部分。
- 新功能若需要可重用的確定性能力，優先做成一般 Go package / CLI subcommand，
  由 spec 與 test 鎖行為；不要為了讓 coding agent 能呼叫，就先發明 LLM tool
  registry、prompt schema 或 agent loop。
- `internal/tools` 目前留下的確定性 helper 依一般 Go code 規則維護；目錄名稱
  不代表要恢復已退役的 LLM runtime。

### 5.4 三種輸出管道分清楚（error / 診斷 / 使用者 UX）

pilot 有三種輸出，**不要混用**：

1. **回傳的 error** — 主要控制流。用 `%w` 包裝往上回傳。**不要對同一個 error
   又 log 又 return**（log XOR return）；由最上層決定怎麼呈現。
2. **診斷（diagnostics）** — 「復原型」警告（"index 找不到，繼續"）、內部
   debug trace。一律走 **`log/slog`**（`slog.Warn/Debug/Error(msg, "key", val)`）。
   由 `internal/logx` 設定：分級（預設 WARN）、結構化 k/v、可被 `--log-level`
   /`$PILOT_LOG_LEVEL` 調整、TUI 啟動時自動改寫到 `pilot.log` 不污染畫面。
   **新的內部診斷寫 `slog`，不要再 `fmt.Fprintf(os.Stderr, "warning: …")`。**
3. **使用者 UX** — TUI wizard、預覽、確認、進度與結果（含 emoji 狀態行）。
   走 CLI writer（`cmd.OutOrStdout()`/`ErrOrStderr()`）或 TUI。這是產品介面，
   **不是 log**，不要塞進 slog（會被分級藏掉、破壞 UX）。

判斷：**使用者為了完成任務需要看到的 → UX；操作者 debug 時才需要的 → slog。**

### 5.5 site-wide `--limit` / 依賴展開 / tags 篩選是目前最高風險的核心邏輯

`cmd/pilot/cmd/deploy.go` 裡「`--limit` 如何展開 `sameHosts`/`providerEndpoint`
依賴主機、opt-in component 要不要自動納入、apply 用的 tags 跟 verification
用的 tags 該不該共用」這一整塊,2026-09-02~09-04 三天內連續修了 6 次
(`4920694`、`2d5cedb`、`e22907c`、`394fa77`、`e75c321`,加上多跳 provider
chain 那個真因見 [[pilot-deploy-limit-sameHosts-dependency-not-autocascaded]]
的 `1f4f77d`)。每一次都是「單元測試綠燈」之後才在更複雜的真實 topology
(多跳依賴、opt-in component、`--limit` 只框一部分主機)上現形——其中一次
甚至是使用者在正式 infra-deploy 環境自己撞到、自己修的。

已經沉澱成規則的具體不變量:

- `sameHosts` 依賴的 host 解析要跟著 **consumer 自己解析出來的 host** 走,
  不能沿用最外層原始的 `--limit` 字串重查一次(多跳 provider chain 會失真)。
- opt-in(`Site.Include: false`)component **只要有 inventory host 落在
  `--limit` 的解析範圍內就要納入**,不能因為它是 opt-in 就整批排除;
  `'all'` 這個 pseudo-role 本身不算「有指定 opt-in component」,不能觸發
  納入。
- apply 用的 tags(給 Ansible 篩選任務)跟 verification 用的 tags(給
  `pilot verify` 篩選驗收行)是**兩件事**,依賴帶進來的 provider 可能有
  apply tag 但不該被拉進 verification 篩選範圍。

改動這塊邏輯(`resolveDeploymentScope`/`addDependencies`/
`effectiveDeploymentTags`/`effectiveDeploymentLimit`/`componentsForPlaybook`
任一個)**不能只跑 `deploy_test.go` 既有的 mock 案例**:至少要新增一個涵蓋
「跨兩跳依賴 + `--limit` 只框其中一段」的 regression test(範本見
`TestResolveDeploymentScope_LimitFollowsProviderSameHostsDependency`),且
合併前對一個真的有多跳依賴的 topology(`vm-target`/`docker-target` 皆可)
跑一次真實 `--limit` 部署,不能只憑 mock 通過就當作驗證完成。

### 5.6 解析外部 CLI(`ipa`/`dig`/`docker` 等)輸出的 fixture 必須來自真實擷取

2026-08-27~09-03 這一週,FreeIPA/identity/decommission 相關程式碼在真實
vm-target 上跑出至少 11 個之前所有單元測試都是綠燈的真 bug(`0bb39cc`、
`f05bb01`、`783a6cd`、`3b4ef4d`、`3f29243`、`b2425e0`)。commit message 原話:
「單元測試裡手寫的 expected string 是 self-consistent 但錯的,剛好跟 bug
本身互相印證」。具體踩過的坑:

- `ipa host-show` 對已刪除主機印 "not found" 在 **stderr**,程式只掃了
  stdout,永遠比對不到。
- `ansible.builtin.debug` 印出字面兩個字元 `\n`,不是真正的換行 byte;用
  `^`/`(?m)$` 錨定的 regex 對這種文字永遠比對不到,卻不會報錯,靜默變成
  假陽性 PASS。
- `dig +short` 在 UDP timeout/communication error 時仍以 rc=0 印一段診斷
  字串到 stdout,跟「查無紀錄」的空字串無法用 rc 區分——必須改用
  `+noall +comments +answer` 並顯式解析 `;; Got answer:`/NOERROR 狀態。
- `changed_when` 用字串比對 `ipa pwpolicy-add`/`-mod`/`-del` 的輸出,但那些
  字串在真實輸出裡根本不存在(add/mod 只印欄位 dump,del 什麼都不印),
  永遠回報 `ok` 而非 `changed`。
- FreeIPA 的 `krbmaxpwdlife`/`krbminpwdlife` 在 LDAP 裡存的單位是秒,
  `ipa pwpolicy-add --maxlife`/`--minlife` 的 CLI 輸入單位是天/小時——drift
  probe 兩邊沒換算直接比較,永遠誤判成 drift。

**新規則**:任何 Go 程式碼或 Ansible task 需要解析外部 CLI 的輸出(比對
字串、用 regex 抓欄位、判斷 changed/failed)時:

1. 先在一台真實 vm-target(或等效環境)上實際跑一次那個外部指令,把
   **真實的 stdout 和 stderr 都存下來**,fixture/expected string 只能從
   這份真實擷取轉錄,不准手寫猜測格式。
2. 特別檢查:訊息是印在 stdout 還是 stderr?印出來的換行是不是字面
   `\n`?單位是什麼(秒/天/相對值)?「沒有變化」跟「操作失敗」的輸出
   是否可以用 rc 以外的東西區分?
3. 這類程式碼的驗收不能只靠 unit test 過就算數,必須有一次對應的
   `pilot vm-target test`/`topology test` 真實執行證據(見 §1.4),理由是
   這批 bug 全部是「unit test 早就綠燈」但真機執行才現形。

**測試共用狀態的附帶教訓**:同一時期有 3 個獨立 commit 專門修測試間互相
污染的 package-level 變數(如 `dataDir` 沒有在測試間重置,見
[[pilot-cobra-pflag-changed-state-persists-test-hazard]])。任何會被
`t.Setenv`/命令列旗標覆寫的 package-level 變數,新測試都要直接設該
package 變數本身並掛 `t.Cleanup` 復原,不能只 `t.Setenv` 就假設下個測試
看不到殘留。

> §5.7~§5.15 是回顧 fix commit 歸納出的重複模式:§5.7~§5.9 來自 2026-09-23
> 回顧的最近 20 個(`9550b38`~`5b735ee`,09-15~09-23),§5.10~§5.15 來自
> 2026-09-24 再往前回顧的 50 個(`27ec586`~`81f7090`,08-24~09-15)。它們不只
> 適用於 Go:playbook、測試、Dockerfile、contract 都適用。

### 5.7 同一件事記在兩個以上的地方時,必須有一致性測試或改成單一來源

這是那 20 個 fix 裡最常見的一類(8 個)。新增一個元件要改 N 個地方,漏改的那一處
要嘛靜默失效,要嘛之後才在正式環境爆開。其中 `9550b38`(contract
`site.include` 與 `site.yml` 的 import 清單不同步,deploy 記錄「成功」,其實
什麼都沒套用)與 `c58d63a`(teatest 的固定終端高度被新 role 擠爆)都是
**同一類問題第二次發生**。

目前已有的一致性測試(新增同類配對時照抄):

| 配對 | 測試 |
|---|---|
| contract `site.include`/`site.tags` ↔ `playbooks/site.yml` 的 `import_playbook` | `cmd/pilot/cmd/site_yml_consistency_test.go::TestSiteYMLImportsEveryReachableComponent` |
| `group_vars/*.example.yml` 期待的 `dist/` artifact ↔ `images/Dockerfile.pilot-cli` | `cmd/pilot/cmd/dockerfile_artifact_consistency_test.go::TestDockerfileBakesEveryDistArtifactGroupVarsExpects` |
| Go 常數 `pilotSSHConfig` ↔ `pilot-access-gateway-apply.yml` Step 12 的 ssh_config | `cmd/pilot/cmd/portal_ssh_config_sync_test.go::TestPilotSSHConfigMatchesApplyPlaybook` |
| `docs/verification/*.md` 的 row ↔ apply playbook 的 tag | `cmd/pilot/cmd/tag_coverage_test.go::TestSpecPlaybookTagAlignment`(見 §4.0) |
| 任何 contract 的 `groupVars` 與 `group_vars/<role>.example.yml` 的 key ↔ 每一支 apply playbook 的 play `vars:`(不准宣告,見 §4.5 第 3 點) | `internal/spec/play_vars_inventory_precedence_regression_test.go::TestRegression_ApplyPlayVarsDoNotShadowInventoryInputs` |
| spec 變數契約表列出的變數 ↔ contract `groupVars` | `internal/spec/play_vars_inventory_precedence_regression_test.go::TestRegression_SpecInputsAreDeclaredContractInputs` |
| log-server 的 `siem_log_root`/`siem_receiver_tcp_port` ↔ log-shipping 的 `siem_log_root`、audit-log-forwarding/wazuh-manager 的 `siem_forward_port` | `internal/spec/siem_shared_inputs_regression_test.go::TestRegression_SIEMSharedInputsResolveTheSameOnEverySide` |
| audit-log-forwarding client 的 `siem_forward_port` ↔ inventory log-server 的 `siem_receiver_tcp_port`(apply 時的 gate) | `internal/spec/siem_shared_inputs_regression_test.go::TestRegression_AuditForwardPortMatchesTheLogServerReceiver` |
| `pilot deploy` preflight ↔ `pilot repair` 對 contract input 型別的判斷(單一來源 `contract.ValueMatchesType`) | `internal/repair/reapply_plan_test.go::TestBuildReapplyPlan_IntegerInputFormsMatchPreflight`、`cmd/pilot/cmd/deploy_input_types_test.go::TestDeployPreflightAcceptsInventoryNumbers` |
| canonical roster 的 `freeipa.admin.password` ↔ vault 的 `ipa_admin_password`(操作者資料;只載入名冊的 `pilot access`/`identity drift`/`roster remove-*` 需要前者,所以不能改成參照) | `pilot edit` 改後者時同步前者:`cmd/pilot/cmd/edit_tui_vault_roster_sync_test.go::TestEditAutomationDriverVaultAdminPasswordSyncsRosters`(只認 `.vault/main.yaml`:`::TestEditAutomationDriverSecondaryVaultLeavesRostersAlone`);preflight warning:`::TestWarnFreeIPARosterAdminDrift`;apply gate:`internal/spec/freeipa_nfs_admin_password_regression_test.go::TestRegression_FreeIPANFSServerAdminPasswordDriftGate`;已不一致時的修正(手動改名冊):`cmd/pilot/cmd/edit_tui_vault_roster_guidance_test.go::TestFreeIPARosterDriftRecoveryIsAHandEdit`;名冊要跟著改卻被鎖住時整次存檔拒絕,終端機、`--actions`、plan、apply 的結果與 warnings 一致:`cmd/pilot/cmd/edit_vault_save_parity_test.go::TestVaultSaveRosterSyncParity`;兩邊對密碼值的判斷(單一來源 `inventory.ansibleScalarKind`,含 `!unsafe`、`!vault`、模板、沒加引號的非字串):`internal/inventory/roster_admin_password_test.go::TestAdminPasswordFormsAreJudgedAlikeOnBothSides`,對真實 Ansible loader 驗證:`internal/inventory/roster_yaml_types_test.go::TestAnsibleTagsMatchTheClassifier`(`make identity-secret-test`) |

規則:

1. 新增一組「A 改了、B 就要跟著改」的配對時(Go 常數對 template、contract 對
   `site.yml`、`deployCatalog` 對 MCP prompt schema(`a520bdc`)、config struct
   對產生的設定檔……),同一個 PR 必須二選一:由單一來源產生另一邊,或加一個
   一致性測試。一致性測試要**故意把 regression 放回去,確認它真的會 fail**
   (`9550b38` 就用 reverse-proxy 的案例這樣驗過);沒驗過的測試只是另一份會
   drift 的清單。
2. 能從既有事實推導的值,不要要求操作者手抄到第二個地方。`b1e4349`:replica
   的 `freeipa_roster_file` 改從同一份 `hosts.yml` 裡的 primary 推導;
   `00cc3b3`:`ipa_realm`/`freeipa_servers` 改從 `freeipa_domain` 推導。明確
   覆寫永遠優先,推導不出來時 fail closed。`*.example.yml` 不准帶「生效中的空值
   覆寫」(例如 `freeipa_servers: []`),它會靜默蓋掉推導;要示範就寫成註解。
3. 如果測試 fixture 的大小取決於一個會成長的 registry(role contract 數、
   catalog 項目數),要依 registry 長度計算,不要寫死。已知欠債:
   `cmd/pilot/cmd/edit_tui_role_presets_test.go` 的 teatest 終端高度仍寫死
   52 列;下次新增 role 又被擠出畫面時,改成依 role 數量計算,不要再手動加大。
4. 新增 component、spec 或 role 後,凍結 candidate 前一定要跑**完整的**
   `go test ./...`,不能只跑自己的 package。`e238964`(新 spec 沒登記進
   `tagCheckExemptSpecs`)與 `c58d63a` 都只在全量測試時才現形。
5. 元件的 `site.include` 從 `false` 改成 `true` 時,要對 vm-target/docker-target
   跑一次真實的全站 deploy。`a52e32a`:`pilot-access-gateway` 改成
   `site.include: true` 當天,第一次全站 deploy 就在正式環境中斷,因為
   Dockerfile 從沒 bake 它需要的 binary——這條路徑之前從來沒被走到過。

### 5.8 沒有 error 不等於成功

失敗被回報成成功,是最貴的一類 bug:操作者和下游 webhook 訂閱者都會以為事情做完了。

1. `internal/ansible.Runner` 的 `Run`/`RunWithTimeout`/`RunWithExtraEnv` 在
   playbook 失敗(結束碼非 0)時,回傳的 `err` 是 **`nil`**,失敗只記在
   `Result.ExitCode`。每個呼叫點都必須檢查 `ExitCode`,不准用 `_` 丟掉
   `*Result`。`df31248`:`runGatewayScope` 只看 `err`,真實的
   `ipa hostgroup-add-member` 失敗被當成成功,還發出了
   `operation.result:"success"` webhook。新增呼叫點時,照
   `cmd/pilot/cmd/gateway_scope_test.go::TestRunGatewayScopeSurfacesAnsiblePlaybookFailure`
   寫 regression test:在 `PATH` 放一個 `exit 1` 的假 `ansible-playbook`,確認
   指令回傳 error。(2026-09-23 盤點過,當下所有呼叫點都有檢查。)
2. delivery record、webhook 等「成功」紀錄只能根據實際執行結果產生,不能根據
   執行計畫產生。`9550b38`:元件被排進全站 deploy 的 `--tags` 就被記成成功,
   但它的 playbook 根本不在 `site.yml` 裡,從來沒執行過。
3. 會碰網路的外部指令(`apt-get update`、下載探測等)一定要有時間上限。
   `5b735ee`:`apt-get update` 卡在 caching proxy 的半關閉(CLOSE-WAIT)連線上,
   整個 play 無限期卡住。現在一律包 coreutils `timeout`(先 TERM,30 秒後 KILL),
   rc 124 或 -9 都視為失敗。
4. 修復步驟失敗後,不准拿修復前的舊資料繼續往下做。`5b735ee`:refresh 失敗了,
   舊 index 仍列著舊 candidate,re-check 因此通過,install 又撞上同樣的 404。
   修復失敗要明確 fail(例如 `FATAL(stale_metadata_unrecovered)`)。
5. 工具的設定或過濾也可能靜默失效。`c0890f6`:`.golangci.yml` 的
   `exclude-functions` 還寫著舊的 module 路徑,排除規則全部失效,卻沒有任何
   警告。golangci-lint 預設每個 linter 最多顯示 50 筆、相同訊息最多 3 筆,
   畫面顯示 87 筆,實際有 276 筆。盤點 lint 問題數量時要加
   `--max-issues-per-linter=0 --max-same-issues=0`;更改 module 路徑後,
   `git grep` 舊路徑必須為空,`.golangci.yml` 這類設定檔也要算在內。

### 5.9 決策要讀權威來源,不要讀快取或快照

授權、信任與 mutation 的判斷,要讀「此刻真正生效的狀態」。快取和快照只能拿來
顯示,不能拿來下決定。

1. 授權判斷要讀 kernel 實際使用的憑證,不讀目錄服務快取的成員列表。`f1d1552`:
   舊的 `internal/identity.IsMemberOfGroup` 掃 `getent group` 的成員列表,而
   SSSD 會對整個 group 快取(`entry_cache_timeout` 預設 5400 秒)。結果新加入的
   使用者最多被拒絕 90 分鐘,被移除的使用者也能繼續通過。現在改用
   `identity.PeerInGroup`:從 `SO_PEERCRED` 取 pid/uid,讀 `/proc/<pid>/status`
   的 GID,並確認該 `/proc` 條目仍屬於 peer uid(防止 pid 重用)。新增的
   group-gated API 一律用它。
2. 會隨時間變動的信任資料,不要在 apply 當下抓一次就存成快照。`c084b71`:
   gateway 的 ssh_config 原本在 apply 時用 `ssh-keyscan` 產生
   `GlobalKnownHostsFile`,apply 之後才加入 scope 的主機一律被
   `StrictHostKeyChecking` 拒絕,而且 `ssh-keyscan` 是不經驗證就信任的 TOFU。
   現在改成用 `sss_ssh_knownhostsproxy`,每次連線時向 SSSD/FreeIPA 查主機在
   enrollment 時登記的 host key。
3. 快取裡「看起來有」不等於「現在真的能用」。`ad6d552`:apt index 仍列著
   Candidate,但它指向的 .deb 在 mirror 上已經被取代,下載會 404。現在 cache
   hit 時會先用 `apt-get install --download-only` 探測一次。
4. 長時間運作的服務要以自己的持久狀態為準,不以「這一輪外部查詢剛好回傳了
   什麼」為準。`30d6b92`:detection engine 的 refresh 原本只處理當輪 Prometheus
   還有回傳的 subject,短暫的資料缺口就讓 Alertmanager alert 自然過期;重啟後
   也沒把 SQLite 裡的 active episode 載回記憶體。現在 refresh 掃描 SQLite 中
   全部的 active episode,啟動時也會 hydrate。
5. 在 evidence 或排錯過程中,如果要「清快取、重啟、手動同步」才能讓結果正確
   (例如跑 `sss_cache`),那是 bug 的症狀。要開成 bug 追根本原因,不准只把
   workaround 寫進 evidence 就收工。`f1d1552` 的根本原因,在 2026-09-18 的
   session-store evidence 裡就已經出現過(空的 member list),當時用
   `sss_cache` 繞過去,直到 2026-09-23 新使用者在全新 topology 上被拒絕才修掉。

### 5.10 修 bug 時先掃同類;會在新程式碼重犯的,做成全 repo 檢查

回顧 70 個 fix 時最重要的發現:好幾類 bug 修過之後,又在**新寫的程式碼**裡重犯,
原因都是當初只修了發現的那一處。

| 同類 bug | 第一次修 | 第二次修 | 為什麼重犯 |
|---|---|---|---|
| play `vars:` 蓋掉 inventory 的值(§4.5 第 3 點) | `360c6f2`(09-11,2 支 playbook) | `81f7090`(09-15) | 只有鎖住單一 playbook 的測試;09-14 新增的 `pilot-access-gateway-apply.yml` 照舊寫法 |
| 同一支 task 檔 include 兩次,fact 殘留(§4.5 第 2 點) | `6a32a00`(08-28) | `5b735ee`(09-23) | 沒有規則;09-14 新增的 apt framework 又踩到 |
| `dig` 的錯誤診斷被當成 DNS 紀錄 | `131ae5a`(08-25,依猜測加 rc 檢查) | `0bb39cc`(08-31,同一個檔案) | 第一次修沒有先擷取真實輸出:`dig` 出錯時 rc 也是 0 |
| validator 要求目標已在 roster 的 `hosts:` 裡 | grants 的版本 | `687205f` | 新增 auth_policies validator 時照抄舊寫法 |
| `/bin/sh` 下的 `pipefail`(§4.5 第 7 點) | `869f164`(09-13) | 2026-09-24 全 repo 掃描再修 5 處 | 只修了發現的那一個 task |

對照組:`always` tag 這類 bug 在 09-07 寫進 §4.4、並有全 repo lint 之後,最近
20 個 fix 裡就沒有再出現。

規則:

1. 修一個 bug 時,先用 `git grep` 找出同樣寫法在全 repo 的其他出現處並一起修;
   commit message 寫出搜尋範圍與結果(例如「掃過 `playbooks/**`,另有 N 處,
   一併修正」)。
2. 如果這類 bug 會在**新寫的**程式碼裡再犯(某種 Ansible 寫法、共用 helper 的
   誤用、某種 validator 形狀),就加一個**全 repo** 的 lint/regression test,
   不要只加鎖住單一檔案的測試。範本:
   `internal/spec/always_tag_prerequisite_regression_test.go`、
   `internal/spec/shell_pipefail_regression_test.go`。新 lint 要先對修正前的程式碼
   跑一次,確認它真的抓得到(§5.7 第 1 點)。
3. 第一次修如果是依據「猜測的輸出格式」,就等於還沒修;依 §5.6 先擷取真實輸出。

### 5.11 路徑在入口處轉成絕對路徑一次,不要讓不同執行環境各自解析

7 個 fix 都是「在開發機上正常,到 pilot-cli 容器、全新 runtime 或換個工作目錄
就壞」:

- 路徑被接兩次:`a0a8375`(`--dir` 的預設值已經接過 dir,validator 和實際載入
  又各接一次,變成 `dir/dir/inventory.yml`)、`db36b85`
  (`.vault/.vault/main.yaml`)。
- 相對路徑的基準不同:`0174f81`(Ansible 的 `lookup('file', ...)` 相對的是
  playbook 所在目錄,不是 repo root 或 cwd)、`eaab7bd`(`--sandbox` 只複製
  playbook 本身,同目錄的 `include_tasks`/template 全部找不到)。
- `~` 沒被展開:`6eff4bf`(參數沒經過 shell,`@~/.vault/main.yaml` 的 `~` 在
  容器裡變成 `/root`)。
- 以為目錄存在、路徑夠短:`b7b2ecb`(全新容器裡沒有 ControlPath 目錄,
  UNREACHABLE 又被 `no_log` 藏成看不懂的訊息)、`f469407`(ControlPath 超過
  Unix socket 的 108 bytes 上限)、`374780b`(`ansible.builtin.tempfile` 不會
  建立上層目錄)。

規則:

1. 使用者或設定檔給的路徑,在 CLI 入口處**只正規化一次**(展開 `~`、轉成絕對
   路徑、canonicalize),之後一律傳絕對路徑。預設值、validator、實際載入不准
   各自再 join 一次。
2. 傳給 Ansible 的檔案路徑一律用絕對路徑。playbook 不准用 repo-relative 的預設值
   去 `lookup('file')`;沒有值就明確跳過(`0174f81` 的作法)。
3. 會在 pilot-cli image 或 `docker run --rm` 這類全新 runtime 執行的指令,要在
   那個環境實際跑過一次,不能只在開發機驗證。需要的目錄(ControlPath、
   tempfile 的上層目錄)由程式自己建立。
4. 用路徑組 Unix socket 時要算 108 bytes 上限(`f469407` 改成
   `/tmp/pilot-<scope>-%C`)。
5. 檔案鎖要鎖「實際會被改的那個檔案」,不是呼叫者給的路徑寫法。名冊寫入一律先
   `lockRosterFile(path)`(`internal/inventory/roster_lock.go`):它用
   `secretpath.Canonical` 解析 symlink 鏈,在真實檔案旁取 migrate 與 remove 兩組
   sidecar lock,之後只讀、只判斷、只寫 `lk.target`(symlink 保留為 link)。名冊另有 hard link
   (`Nlink>1`)時,sidecar 之後還要以 `openRosterForWrite` 開啟名冊本身並對那個 inode
   `flock(LOCK_EX)`(`rosterLock.identity`,`release` 時關閉):sidecar 以路徑命名,同一個 inode 的兩個
   hard link 名稱各有自己的 sidecar,只有 inode 上的鎖能讓兩邊互斥;被持有回傳 `ErrMutationLocked`,
   其他失敗回傳 `ErrRosterLockFile`(fail closed)。只有一個名字的名冊不取 inode 鎖(名字就是它的身分,
   rename 會換 inode;名冊本身不能 flock 的檔案系統也照常靠 sidecar 運作);取鎖時只有一個名字、
   之後才多出 hard link 的名冊,寫入時以 `ErrMutationLocked` 拒絕(重試即可)。
   `inventory.RosterFileKey` 是「哪個檔案」的唯一判斷:一個名字的檔案是它的 canonical path,有 hard link
   的一般檔案是 `inode:<dev>:<ino>`;鎖、`RosterJournal`(記錄與 `ErrRosterJournalBusy`)、apply rollback
   的分組與 `rosterCandidates` 的去重都用它,不准各自再算一套(§5.7)。這個鎖
   不可重入:已持有 lock 的函式要把 `*rosterLock` 傳給 `*Locked` helper,不准再呼叫
   另一個會取鎖的 writer。PR #148 review:同步經 symlink 寫入真實檔案,鎖卻取在
   symlink 的路徑上,`pilot roster remove-*` 以真實路徑持有的鎖擋不住它;同一類問題
   遍及所有名冊 writer(各自鎖自己拿到的路徑、migrate 與 remove 互不排斥、十幾個
   writer 完全沒鎖)。
   - 建立任何 lock 檔之前,`lockRosterFile` 先用 writer 自己的判斷(`checkRosterWritable`,即
     `openRosterForWrite`)確認這個使用者能寫名冊:不能寫的回傳 `ErrRosterNotWritable`,不建立 lock 檔,
     所以只有能寫名冊的人會留下 lock 檔。PR #148 review(P2-1):lock 檔原本一律 `0600`、而且在檢查名冊
     之前就建立,同 group 第一個寫入 `0660` 名冊的人會把其他成員鎖在外面,只能讀名冊的人失敗後留下的
     lock 檔也會把擁有者鎖在外面。取鎖順序與取鎖後重新 resolve 不變,`writeLockedRoster` 在鎖內仍會再判斷
     一次;失敗後**不刪** lock 檔(刪掉別人正 flock 的檔案會讓第三者鎖到同名的新檔案,互斥失效)。
     `ProbeRosterWrite` 照同樣順序檢查(先名冊、再 lock 檔,名冊有其他 hard link 時最後對它的 inode 短暫取
     shared flock)。dry-run 的 `MigrateRosterFile` 不取鎖
     (`planRosterMigration` 只算結果),只能讀的名冊也能預覽。
   - lock 檔的權限:以 `O_EXCL` 建立,才知道是不是這次建的;`keepOwner` 之後,這次建的設成 `0600`,
     名冊的 group 能讀或寫時加 group 讀,other 能讀或寫、名冊帶 access ACL,或 lock 檔擁有者不是名冊擁有者
     時加 other 讀(名冊還不存在時看誰能在目錄裡建立它:目錄的 w 位元);這個使用者擁有(root 則任何)的
     既有 lock 檔只補上缺的讀取位元,舊版留下的 `0600` 因此會被修好。lock 檔只記錄 pid,flock 只需要讀取權
     (唯讀開啟的 fallback 早就存在)
     (`internal/inventory/roster_lock_mode_test.go::TestRosterLockFilesLetTheRostersWritersIn`、
     `roster_root_users_test.go::TestRosterWritersSharingAGroupDoNotLockEachOtherOut` 以兩個同 group 的
     使用者實際驗證)。
   - lock 檔本身不跟隨 symlink:以 `O_NOFOLLOW|O_NONBLOCK` 開啟(FIFO 不會卡住
     open),必須是只有一個名字的一般檔案,chown 一律對 fd 做(以 root 執行時,跟隨
     symlink 會截斷並 chown 別的檔案);只能讀的既有 lock 檔照樣可以 flock(例如舊版
     root 留下的,或在唯讀檔案系統上:`EROFS` 跟 `EACCES` 一樣改以唯讀開啟),完全打不開時回傳 `ErrRosterLockFile`
     並說明要修什麼,跟「被持有」(`ErrMutationLocked`)分開。lock 檔的 open/fstat/flock 失敗只要不是「被持有」
     (EWOULDBLOCK),不論原因(symlink、目錄、FIFO、`EROFS`、`EIO`、`ENOSPC`、`ENOLCK`…)一律回傳包著原因的
     `ErrRosterLockFile`,writer 與 probe 一致,`pilot edit` 的 vault 存檔因此會拒絕,而不是存了 vault、名冊留在舊密碼
     (`roster_lock_mode_test.go::TestRosterLockFileFailuresAreErrRosterLockFile`)。罕見的檔案系統錯誤以
     `inventory.InjectFileFault`(`fileFault`,只給測試用;lock 檔與名冊的 open、flock、路徑解析的故障注入點,
     package 內外的測試共用)模擬。它不是 package 唯一的測試接縫:其他只給測試用的 package 變數各管一件事
     (`createRosterTemp`、`fchownRosterTemp`、`renameRosterTemp`、`fallocateRoster`、`writeRosterAt`、
     `lockContentionWait`、`afterRosterLockHook`、`afterRosterAdminLookHook`)。不需要寫入的情況(schema 已是最新、沒有缺的 host)不取鎖。
     lock 被持有時 `flockMutationLock` 以短暫 backoff 重試最多 `lockContentionWait`(250ms)才回傳
     `ErrMutationLocked`,讓 plan 探測時一瞬間的 shared flock 不會害 writer 失敗
     (`internal/inventory/roster_lock_file_test.go::TestRosterLockContentionIsBriefAndBounded`)。
   - 持有鎖之後一律用 `writeLockedRoster`(`internal/inventory/roster_write.go`,名冊寫入
     primitive 的唯一位置)寫,寫法只有一套:先以不截斷的方式開啟名冊寫入(`openRosterForWrite`,
     「哪些名冊拒寫」只在這裡決定,拒絕一律包 `ErrRosterNotWritable`:workspace 不准用的路徑、這個使用者
     不能寫(`0400`,root 除外)、symlink、不是一般檔案);通常以同目錄暫存檔(`.<名冊>.pilot-tmp-*`)
     設好原本的權限與擁有者後 rename 取代,不取鎖的讀者(同步的預查、唯讀指令、playbook)不會讀到
     寫到一半的檔案;暫存檔依序 fchown → fchmod → 比對延伸屬性,之後才寫入內容並 sync。名冊另有 hard link、
     帶 POSIX ACL、這個使用者不能在目錄建暫存檔(EACCES/EPERM)、暫存檔給不了原本的擁有者(非 root 寫別人的
     名冊),或暫存檔與名冊的延伸屬性(經 fd 的 `Flistxattr`/`Fgetxattr` 比對完整 name→value,在 chmod 之後
     才比,ACL mask 已定;略過 `security.ima`/`security.evm`;沒有 xattr 支援的檔案系統兩邊都視為沒有)不同時
     (`errRosterAttrsDiffer`:目錄的 default ACL 被暫存檔繼承會讓更多人讀得到名冊,換名也會丟掉名冊的
     SELinux label 或 `user.*` 屬性,PR #148 review P2-3)改為原地覆寫,inode、擁有者、link、ACL 與延伸屬性
     都不變。換名(`renameRosterTemp`)回傳 `EBUSY`(單一檔案的 bind mount,pilot-cli 的 `docker run -v`)、
     `EXDEV`、`EPERM`、`EACCES` 時也改為經已開啟的 fd 原地覆寫(PR #148 review P2-2:main 原本就原地覆寫,
     #148 一度讓每個 writer 在 bind mount 上失敗);其他換名錯誤寫入失敗、名冊不變。原地覆寫會變大時先
     `fallocate(FALLOC_FL_KEEP_SIZE)` 預留空間(不用 mode 0:那會先把檔案補上 NUL、讀者看得到,pilot 中途死掉
     還會留著),`ENOSPC`/`EDQUOT` 在改動任何 byte 之前失敗,`EOPNOTSUPP`/`ENOSYS` 直接寫;之後才失敗的錯誤
     會說名冊可能只寫了一部分,不准再說「original untouched」。
     暫存檔因其他原因建不出來(ENOSPC、EDQUOT、EMFILE)時寫入失敗、名冊不變,不改走原地覆寫
     (`internal/inventory/roster_lock_test.go::TestWriteLockedRosterFallsBackInPlaceOnlyOnPermission`、
     `roster_write_test.go::TestWriteLockedRosterWritesInPlaceWhenTheRenameIsRefused`、
     `::TestWriteLockedRosterKeepsTheRostersExtendedAttributes`、`::TestWriteRosterInPlaceReservesRoomFirst`、
     root 才能跑的 `roster_root_mount_test.go::TestRosterSyncThroughASingleFileBindMount` 實際 bind mount)。
     所有名冊 byte 的寫入(換名、原地覆寫、新建)都只在 `writeLockedRoster` 裡發生。寫入失敗時只有原地覆寫
     寫到一半可能改到名冊,錯誤包 `errRosterPartlyWritten`——這是「可能寫到一半」唯一的訊號,journal 據此記成
     `Failed`(§5.14 第 7 點);其他失敗名冊不變。schema 升級在建立備份之前以 `checkLockedRosterWritable` 在鎖內
     再確認一次能寫(`lockRosterFile` 取鎖前已擋過:不留 lock 檔、不留備份、不回報 rollback),寫入失敗時只在
     `errRosterPartlyWritten` 時經 `writeLockedRoster` 寫回原內容(journal 一樣記下這次 rollback),其他失敗回報
     「left unchanged」(`internal/inventory/roster_migrate_file_test.go::TestMigrateRosterFileRollsBackOnlyAWriteThatChangedTheRoster`、
     `roster_journal_test.go::TestRosterJournalRecordsAMigrationsPartWayRollback`)。新名冊 `0600`,root 執行時
     擁有者跟目錄相同,migration 的備份給名冊的擁有者;取得鎖之後清掉超過兩分鐘的殘留暫存檔。加密名冊解密後的
     明文放在 `secretpath.PrivateTempDir` 建的 `0700` 私有目錄(`pilot-roster-decrypt-<pid>-*`),清理時整個目錄
     刪掉,pilot 在清理前被殺掉留下的目錄由下一次建立時清掉(§5.14 第 5 點);writer 的暫存檔清理只掃那個目錄、
     不掃整個 `$TMPDIR`。`PrivateTempDir` 涵蓋 plan 的暫存 workspace、試做名冊寫入的副本、加密名冊解密後的明文;
     schema migration 的明文候選檔不在其中,仍是名冊旁的 `0600` 暫存檔(`.<名冊>.pilot-tmp-*`),被殺掉留下的
     由 `sweepRosterTemps` 在下一次取得該名冊的鎖時清掉(只清超過兩分鐘的)。admin 密碼同步只改「整個值都在那一行」的 scalar(`scalarOnItsLine`:把那行剩下的
     文字單獨 parse 必須得到同值同 tag),跨行的加引號或 plain 密碼一律拒絕,否則舊密碼的下半段會以註解留在檔案裡。
     有 hard link 的名冊一律原地覆寫,所有名字都看到新內容,且所有名字共用同一把 inode 鎖
     (`internal/inventory/roster_lock_hardlink_test.go::TestHardLinkedRosterNamesShareOneLock`、
     `::TestPreparedAdminSyncHoldsEveryNameOfAHardLinkedRoster`、`::TestRosterInodeLockOnlyWhenTheRosterHasAnotherName`;
     PR #148 review:鎖只以路徑命名時,經另一個 hard link 名稱的 writer 能在 Prepare 與 Commit 之間寫入而被蓋掉)。
     已知限制:名冊以單一檔案 bind mount 進容器時,lock 檔建在容器裡那個
     目錄,容器內與主機上的 pilot 不互斥(要共用鎖就 mount 整個目錄)。
     預查讀到空檔時改在鎖內重讀(空不空依預查讀到的內容判斷,不再讀第二次)。
     `TestRosterWritersRefuseALockedRoster` 對每個 writer 驗證這套寫法(唯讀時回傳 `ErrRosterNotWritable`、
     不建立 lock 檔、旁邊不留任何檔案、錯誤不提 rollback,root 則寫入並保留 `0400`;hard link、殘留暫存檔、
     root 時保留擁有者)。
   - 要跟其他檔案一起改的名冊寫入分成兩步:`inventory.PrepareRosterAdminSync` 在鎖內決定要寫的
     內容並**持有鎖**,`Commit` 寫入後放鎖、`Release` 只放鎖(`SyncRosterAdminPassword` 就是
     Prepare + Commit)。Prepare 在鎖內呼叫 `checkLockedRosterWritable`(同一個 `checkRosterWritable`/`openRosterForWrite`
     判斷,另外要求名冊仍在),`writeLockedRoster` 會拒絕的名冊在這裡就拒絕;只有執行時才會發生的 I/O 錯誤(寫暫存檔時磁碟滿、rename 失敗)留到 Commit。
     `pilot edit` 存 `.vault/main.yaml` 時先 Prepare 每一份要跟著改的名冊,任何一份被持有、lock 檔
     不能用或名冊不能寫就全部 Release、整次存檔拒絕(vault 也不寫),否則寫 vault 再 Commit:先存
     vault 會讓名冊留在舊密碼,而之後再存不會補同步。plan 在暫存複本(永遠可寫、沒人鎖)上執行,另以
     `inventory.ProbeRosterWrite`(跟 `lockRosterFile` 同順序:先 `checkRosterWritable`、再檢查 lock 檔,不建立 lock 檔)檢查真實名冊,
     apply 會被拒絕時 plan 也失敗(`cmd/pilot/cmd/edit_vault_save_parity_test.go::TestVaultSaveRosterSyncParity`)。
     Prepare 讀取與判斷時的錯誤(加密檔或 inline `!vault`、讀不到或不是合法 YAML、alias、flow mapping、
     多行 scalar、改寫後自我檢查失敗)都包 `ErrRosterNeedsHandEdit`,只有這些讓存檔照常進行並列為「未同步」;
     其他任何錯誤(已分類或沒分類)都經 `rosterRefusal` 拒絕存檔(fail closed),plan 的探測解析不到真實名冊
     也一樣(`internal/inventory/roster_refusal_matrix_test.go::TestRosterRefusalsAgreeAcrossPrepareProbeAndWriter`、
     `cmd/pilot/cmd/edit_vault_save_refusal_matrix_test.go::TestVaultSaveRefusesEveryRosterWriteRefusal`,
     每個拒絕原因 × 四個入口)。每一行提示依它談的那個值判斷:「請加引號」看新存的值,「pilot 不知道舊密碼」
     看舊值(inline `!vault`、模板、沒加引號、list/mapping)(`edit_vault_value_kinds_test.go::TestVaultSaveLineForEveryValueKindPair`),
     deploy preflight 對 inline `!vault` 也列出無法比對的名冊。
     暫存複本只有 `group_vars/`、`host_vars/` 最上層的檔案,plan 從真實 workspace 讀子目錄裡 vars 檔的
     `freeipa_roster_file`,跟 apply 看到同一組名冊
     (`cmd/pilot/cmd/edit_tui_vault_roster_scope_test.go::TestEditPlanAndApplyAgreeOnNestedVarsRosterReferences`)。
   - package 以外寫名冊的地方也要經過這個鎖:`pilot edit` apply 失敗的 rollback 用
     `inventory.RestoreRosterFile`/`RemoveRosterFile`,只還原這個 session 自己的寫入蓋掉的內容
     (`inventory.RosterJournal` 在 `writeLockedRoster` 記下的紀錄,見 §5.14 第 7 點),且只在名冊仍是
     這個 session 最後寫入的內容時才還原,否則留下並在錯誤裡列出路徑與原因(`cmd/pilot/cmd/edit_tui_vault_roster_scope_test.go::TestEditApplyRollbackLeavesARosterAnotherProcessTouched`);
     `pilot edit` 對 workspace 名冊(`rosterCandidates`:預設 `.vault/ipa-identity.yaml` 與每個
     `freeipa_roster_file` 指到的檔案)執行 `ansible-vault edit` 時以 `inventory.HoldRosterLock` 持有鎖
     (`edit_tui_vault_roster_lock_test.go::TestAnsibleVaultEditHoldsTheRosterLock`);不是名冊的加密檔
     (`keycloak.yaml` 等)不取鎖、不留 lock 檔(`edit_tui_vault_lock_scope_test.go::TestAnsibleVaultEditLocksOnlyRosters`)。
     `ansible-vault edit` 的鎖只在 editor 執行期間持有(`rosterEditCommand.Run`),
     自動化丟掉這個指令時不會留下鎖(`::TestEditApplyLeavesNoRosterLockAfterAnEncryptedFileStep`)。
     rollback 對同一個檔案的多個名字(symlink 或 hard link,以 `inventory.RosterFileKey` 分組)只還原一次,
     已回到原內容的算完成,這個 session
     沒寫過、被別人改過的名冊不算失敗(`edit_tui_vault_roster_scope_test.go::TestEditApplyRollbackRestoresARosterWithTwoNames`、
     `::TestEditApplyRollbackRestoresARosterWithTwoHardLinkedNames`、
     `::TestEditApplyRollbackKeepsARosterTheSessionNeverWrote`)。plan 的暫存複本保留 `.vault/` 名字之間的別名
     結構(指向同一個檔案的 symlink、鏈、指向 workspace 外的 link、hard link 在複本裡是指向同一個一般檔案的
     相對 symlink,不離開複本),所以 plan 與 apply 的 `AffectedFiles`、diff、warnings 一致
     (`cmd/pilot/cmd/edit_plan_alias_parity_test.go::TestEditPlanMatchesApplyForAliasedVaultFiles`)。
   - 名冊被持有、lock 檔不能用或名冊不能寫(`ErrRosterNotWritable`)時,`pilot edit` 在終端機顯示 banner、不結束 session;
     自動化則讓那一步失敗(錯誤列出名冊路徑與原因):MCP apply 整個 rollback 並回傳錯誤而不是
     "applied",`--actions` 停在那一步、保留之前的步驟(不 rollback)——banner 只是給人看的,
     不能讓自動化把沒寫入當成功(§5.8)。`editAgentSession.Run` 回傳
     `(editRunResult{Warnings}, error)`,失敗時也帶 warnings,呼叫端不能漏掉:`--actions`
     印到 stderr(`warning: …`),plan/apply 放進結果。
   - plan 與 MCP apply 只寫 session 自己的 `.vault/` 檔案(`editWriteScope`):plan 的複本沒有、
     apply 的 rollback 也還原不了其他檔案。`mutateRosterSource` 在 plan/apply 下對 `.vault/` 以外的
     名冊先在暫存目錄的副本上執行那次寫入(`simulateRosterWrite`,真實檔案只讀、不留 lock 檔):副本會
     被改動才回傳 `errRosterOutsideEditScope`(經 `rosterBusyBanner` 讓那一步失敗),不需要寫入就照常
     通過、回傳模擬的結果(`cmd/pilot/cmd/edit_write_scope_test.go::TestEditPlanAndApplyAcceptAnExternalRosterThatNeedsNoWrite`)。
     為此每個寫入 closure 都以參數接收要寫的路徑,且參數名必須遮蔽被檢查的路徑變數,寫入不會碰到外層
     的真實路徑(`TestConfigSecretPaths_AllRosterSourceWritesCarryWorkspace` 檢查)。終端機與 `--actions` 不受限。
     「session 自己的 `.vault/` 檔案」以 `vaultSpelling` 判斷:名稱在 `.vault/` 裡,或是從別處指進 `.vault/` 的
     symlink。plan 裡的 `freeipa_roster_file` 不論相對或絕對,都相對於真實 workspace 解讀(`rosterWritePath`),
     `.vault/` 檔案對應到複本、其他檔案用真實檔案(只讀或在副本上試做);plan 的錯誤、warnings 與檢查結果
     的路徑對應回真實 workspace(`cmd/pilot/cmd/edit_roster_ref_matrix_test.go::TestEnableNFSRosterRefMatrix`、
     `::TestVaultRotationRosterRefMatrix`,寫法 × 名冊狀態 × 四個入口)。plan 的暫存 workspace 與試做用的副本
     含 secret,跟加密名冊解密後的明文一樣以 `secretpath.PrivateTempDir`(cmd 裡的 `privateTempDir`;`<prefix>-<pid>-*`、`0700`)
     建立,下次建立時清掉這個使用者已結束 pilot 留下的(§5.14 第 5 點,「已結束」以持有的 flock 判斷、不看 pid;`cmd/pilot/cmd/private_temp_dir_test.go`、
     `internal/inventory/roster_lock_test.go::TestDecryptedScratchFileSweepsWhatADeadPilotLeft`)。`hosts.yml` 裡指到真實 workspace `.vault/` 的絕對路徑,在 plan 的複本上
     由 `r.rosterWritePath` 對應到複本,寫進 `hosts.yml` 的路徑由 `r.recordedPath` 決定(plan 記錄
     真實路徑);`edit_tui*.go` 不准直接 `resolveRosterPath(`/`filepath.Abs(filepath.Join(dir`
     (`cmd/pilot/cmd/edit_write_scope_test.go::TestEditorResolvesRosterReferencesThroughItsScope`、
     `::TestEditPlanAndApplyRefuseAnExternalRosterWrite`、`::TestEditPlanEnablingNFSLeavesRealRostersAlone`)。
     兩者都經過 `rosterBusyBanner`,它把拒絕記在 router 上,driver 每一步檢查
     (`edit_tui_vault_roster_lock_test.go::TestEditApplyFailsOnABusyRoster`、
     `::TestApplyHandler_BusyRosterIsAnErrorNotApplied`、`::TestEditTUIBusyRosterKeepsTheSessionOpen`);
     `edit_tui_roster_busy_guard_test.go::TestRegression_EditRosterWritesReportABusyRoster`
     對 `cmd/pilot/cmd` 每一個 `mutateRosterSource(Value)` 找出它綁定的 error(if-init、
     `x, err :=`、`err =`),要求同一個函式在下一個名冊寫入綁定同名變數之前把它傳給
     `rosterBusyBanner`,否則要在 `busyReportExemptions` 以「函式|inventory API」(或 deploy、
     inventory generate 的檔名)登記理由;丟掉、`_` 或直接 return 結果一律失敗。
     `::TestRegression_BusyRosterErrorsGoThroughRosterBusyBanner` 禁止其他函式自行處理這兩個
     錯誤(只豁免 rollback)。
   `internal/inventory/roster_lock_guard_test.go::TestRegression_RosterWritersLockCanonicalTarget`
   對 `internal/inventory` 鎖住:`acquireMutationLock` 只能出現在 `roster_lock.go`;`rosterLock` 只能在
   `roster_lock.go` 建立;會寫檔或刪檔(含 `os.OpenFile`/`openLockFile` 寫入／建立、`os.Create`、
   `os.Rename`/`renameRosterTemp`、`os.Remove`/`os.RemoveAll`)的函式與 method 必須呼叫
   `lockRosterFile` 或接收 `*rosterLock`,並寫該 lock 的 target 或由它衍生的路徑(`a, err := f(<衍生>)`
   的第一個結果也算;只豁免寫入 primitive、lock 檔本身、vault 檔與 freeipa-dns/internal-endpoints manifest,
   以及只刪自己檔案的 `sweepRosterTemps`、`decryptedScratchFile`);`RemoveRosterFile` 因此刪 `lk.target`
   而不是 `lk.path`(經 symlink 時原本刪掉的是 link);`renameRosterTemp` 跟 `os.Rename` 一樣只能出現在
   `roster_write.go`;持有
   lock 的函式不准再走到另一個 `lockRosterFile`;接收者持有 `*rosterLock` 的 method(例如
   `PreparedRosterAdminSync.Commit`)視同持有鎖。`TestRosterWritersRefuseALockedRoster`
   對每一個 exported 名冊 writer 實際驗證(新增 writer 沒有對應 case 就 fail)。
   需要 root 的擁有者測試以 `requireRoot` 標記:一般使用者執行時 skip,
   `make root-test` 以使用者身分編譯、經 `sudo -n` 以 root 執行並設
   `PILOT_REQUIRE_ROOT_TESTS=1`(skip 變 fail),CI 的 "Root-only ownership tests" job 跑這個
   target;`cmd/pilot/cmd/root_test_consistency_test.go::TestRootOnlyTestsRunInCI` 鎖住
   Makefile 的 `ROOT_TESTS` 等於所有會走到 `requireRoot` 的測試、CI 確實執行它。

### 5.12 每個 gate、matcher、`changed_when` 都要證明它會觸發

8 個 fix 是「檢查從一開始就比對不到任何東西」,等於沒有檢查,結果永遠 PASS 或
永遠 `ok`:

- `3b4ef4d`:比對的 FreeIPA 屬性名稱(`managedby_service:` 等)在真實的
  `ipa host-show --all --raw` 輸出裡根本不存在,HD11/HD12 gate 永遠關閉;用
  `^`/`(?m)$` 錨定的 regex 碰上 `debug` 印出的字面 `\n`,永遠比對不到。
- `3f29243`:Verify 送出 `host_dns`/`hbac_references`/`sudo_references` 查詢,
  playbook 卻從沒處理,HD10/HD11 永遠 pass。
- `b2425e0`:`changed_when` 比對的 "Added policy" 等字串不存在,真的變更永遠
  回報 `ok`。
- `6a32a00`:`failed_when` 比對不含空白的 `"resultType":"vector"`,真實的
  `json.dumps` 輸出從不這樣印。
- `869f164`:`/bin/sh` 下 `pipefail` 沒有生效(§4.5 第 7 點)。
- `374780b`:`include_tasks` 的 `tags:` 沒傳下去,`--tags C1` 時什麼都沒裝也
  不報錯(§4.5 第 8 點);`apt-cache policy pkg1 pkg2` 對完全不認識的套件直接
  略過不印,聯合查詢時誤判「有 candidate」。
- `131ae5a`/`0bb39cc`:`dig` 的錯誤診斷被當成 DNS 紀錄。

§5.6 規定 fixture 要來自真實擷取;這裡再加三條:

1. 新增或修改任何 gate、matcher、`failed_when`、`changed_when`、verify regex 時,
   regression test 要**同時**有「應該通過」和「應該觸發」兩種案例,兩者都用
   真實擷取的輸出。只有一種案例的測試證明不了什麼。
2. 對 vm-target 實跑時,只要能製造出 gate 要擋的狀態,就讓每個新 gate 真的
   觸發一次,確認它會 fail,不是只看到它 PASS。
3. 送出去的查詢或參數,要確認接收端真的有處理(`3f29243`)。接收端沒有對應
   分支時要 fail,不能回傳空結果。

### 5.13 主機身分統一用小寫 FQDN,在邊界轉換一次

- `33f0b94`:`hosts.yml` 的 key 是短名稱(`client-vm`),跟 FreeIPA 回傳的 FQDN
  永遠比對不到:每台主機都被誤判成有未知的 service principal,roster 條目也不會
  收斂成 absent。
- `3b4ef4d`:`firstNonEmpty(host.AnsibleHost, host.Name)` 優先用 SSH 連線位址
  (通常是 IP)當主機身分,FreeIPA 操作全部打到 IP。
- `0bb39cc`:HBAC 成員比對分大小寫,造成先移除再加回的來回變動。
- `2a97765`:roster 自動補上的 FQDN 保留了大寫,產生重複條目。

規則:

1. `ansible_host`/`AnsibleHost` 是**連線位址**,永遠不是主機身分。主機身分用
   inventory 名稱,或 FreeIPA 解析出的 FQDN(`internal/decommission/planner.go`
   的 `providerFQDN`)。
2. 跟 FreeIPA 互動前,先用權威來源(例如 `ipa host-show` 的結果)解析出完整
   FQDN,後續所有比對與 roster 操作都用這個值
   (`internal/decommission/providers/freeipa_client.go` 的
   `resolveAuthoritativeFQDN`)。
3. FQDN,以及 FreeIPA 的 user/group/host/hostgroup 名稱,比對前一律先轉小寫;
   送給指令時可以保留原始拼法。
4. 測試要涵蓋「inventory key 是短名稱」「大小寫混用」「`ansible_host` 是 IP」
   三種輸入。

### 5.14 移除、撤銷、清理的路徑要跟新增路徑一樣測

§0.2 已經要求「reconciler 要測新增與撤銷」,但這 50 個 fix 裡仍有 5 個出在這一側
(再加上最近 20 個裡的 `f1d1552`:被移除的使用者還能通過授權):

- `5306f53`:indicator 清單為空時省略了參數,而不是送出清除參數,舊值留著;
  主機從 `auth_policies` 移除後,永遠不會被清掉(後來加了本地 statefile,
  記錄 Pilot 設定過哪些主機)。
- `fde40f7`:`Down` 對已經刪除的 target 報錯,重試迴圈因此失敗。
- `34a43ce`:process 被 SIGKILL 時 `defer` 不會執行,留下孤兒暫存檔。
- `3b4ef4d`:cleanup 步驟本來就會改 live state,Finalize 卻拿清理前的 hash
  比對,永遠回報 `plan_stale`。
- `b7b2ecb`:只從 decommission 目標自己的變數找 roster 路徑,一般 client 永遠
  找不到,`apply` 永遠卡在 `active_residue`。

規則:

1. reconciler 要有「從 desired state 移除 → live state 被清掉」的 regression test
   與實跑證據;只測新增的 reconciler 不算完成。
2. 「空清單」必須明確代表「清除」,不能等同「不處理」;兩種語意都需要時,用
   不同欄位表示。
3. 要清掉「Pilot 曾經設定、現在已從 desired state 消失」的東西,必須記錄 Pilot
   設定過什麼;沒有記錄就無法 prune(`5306f53` 用 statefile 追蹤)。
4. teardown、`Down`、cleanup 必須冪等:目標已經不存在就視為成功。要偵測打錯的
   名字,放在 CLI 層處理(`fde40f7` 的作法)。
5. 可能被 timeout 或 SIGKILL 中斷的程式,不能只靠 `defer` 清理;暫存檔要能在
   下次執行時被辨識並清掉(`34a43ce` 用 PID 命名,`sweepStaleLogTemp` 只清
   已結束 PID 的檔案)。plan 的暫存 workspace、試做名冊寫入的副本與加密名冊解密後的明文放在
   `secretpath.PrivateTempDir` 建的目錄(`<prefix>-<pid>-*`、`0700`);建立時清掉這個使用者已結束的 pilot
   留下的同 prefix 目錄。「已結束」**不能**用 pid 判斷:另一個 PID namespace 的 pilot(bwrap 沙箱的 agent、
   掛載同一個 `/tmp` 的容器)看不到這個 pid,會把還在用的目錄刪掉(plan 的 `hosts.yml` 憑空消失,
   `label "nexus" not found`)。每個目錄裡有 `.pilot-alive` 標記檔,建立者在整個生命週期持有它的獨佔 flock
   (kernel 在 process 結束時放掉,不論怎麼結束);清理者只有拿得到這把鎖才刪,`EWOULDBLOCK` 或任何其他錯誤
   一律視為仍在使用(寧可留下也不刪)。沒有標記檔的目錄(舊版 pilot 留下的,或 mkdir 與建標記之間)只有在
   mtime 超過 10 分鐘且名稱的 pid 在清理者自己的 namespace 也不存在時才刪,所以舊版 pilot 在別的 namespace
   超過 10 分鐘的目錄仍然擋不住。已知限制:被殺掉的 pilot 的鎖由 kernel 釋放,它的目錄在下一次建立時才清掉;
   不支援 flock 的 `$TMPDIR` 只留下沒有標記的目錄(記一筆 slog warning),退回上述 age + pid 規則。呼叫端自己
   `os.RemoveAll` 目錄,持有鎖的 fd 在下一次 `PrivateTempDir` 時才放掉
   (`internal/secretpath/private_temp_dir_test.go::TestAPilotInAnotherPIDNamespaceDoesNotSweepALiveDirectory`
   用真正的 bwrap PID namespace 鎖住這件事,沒有 bwrap 時 skip)。
6. 自己會改 live state 的步驟之後,後續的 freshness/drift 檢查要以改完之後的
   狀態為基準。
7. rollback 只還原「這個 session 自己的寫入」蓋掉的內容,而且這份紀錄要在**寫入的地方**
   產生,不准事後比對檔案在步驟前後的差異去推斷是誰寫的:有別的 writer 不受同一把鎖管的
   檔案(名冊),別人在快照之後、session 寫入之前存的修改會被當成 session 的而被還原掉,
   rollback 還回報成功(PR #148 review P2:`pilot edit` apply 的 rollback 原本這樣推斷)。
   `inventory.JournalRosterWrites` 開啟後,`writeLockedRoster`(唯一寫名冊 byte 的地方)在鎖內
   記下每次寫入前與寫入後的內容,原地覆寫中途失敗(錯誤包 `errRosterPartlyWritten`,同一個訊號也決定
   schema 升級要不要 rollback;那次 rollback 也經 `writeLockedRoster`,一樣被記下)記為 `Failed`;
   apply 在 rollback 前 `Stop` 它(不再記錄,rollback 自己的還原寫入不算 session 的,但仍保有對名冊的
   claim,別的 apply 在這段期間註冊不進來,否則會把這次的還原寫入記成它自己的),rollback 做完才由
   `defer` 的 `Close` 放掉 claim
   (`cmd/pilot/cmd/edit_workspace_rollback_journal_test.go::TestEditApplyKeepsItsRosterClaimThroughTheRollback`);
   rollback 依紀錄:沒寫過且不是在某一步執行期間被改的名冊保留,沒寫過卻在某一步執行期間被改的
   名冊無法歸屬、留給人工檢查且不還原,寫入不成鏈(前一次寫入後的內容 ≠ 下一次寫入前的內容)
   或有 `Failed` 也留給人工檢查,否則在名冊仍是最後一次寫入的內容時還原成第一次寫入前的內容
   (`cmd/pilot/cmd/edit_workspace_rollback_attribution_test.go`)。哪些 `.vault/` 檔案算名冊同樣只看
   **執行前**的狀態與 journal,不看 session 留下的內容(PR #148 review:一個 plain 的 `main.yaml` 被 session
   加上 `groups`/`users`/`freeipa` 等 key 就被當成名冊,rollback 回報「留給人工檢查」,與 runbook 說非名冊檔一律還原
   相矛盾):執行前就存在,且是 ansible-vault 加密、或名冊專屬的頂層 key 是 mapping/list(vault editor
   只寫 scalar)、或是 workspace 指定的名冊(預設 `.vault/ipa-identity.yaml` 與 `freeipa_roster_file`,
   可能只有 scalar),或 journal 記錄過對它的寫入。執行前不存在、journal 也沒有紀錄的 `.vault/` 檔案
   (`pilot roster add-user`、`pilot access`、decommission 等另一個 process 在 apply 期間建立的名冊也是這種)
   改看**現在**的內容:加密、名冊專屬 key 是 mapping/list、或是 workspace 現在指定的名冊(含預設
   `.vault/ipa-identity.yaml`),就是別人的名冊,保留並列入 warnings(在某一步執行期間出現的留給人工檢查),
   絕不移除(PR #148 review of 374a7ca:新建的名冊曾被靜默刪除,與「rollback 不還原不是自己寫的名冊」相矛盾);
   只有 scalar-only、非指定名冊、未加密的新檔案(vault editor 唯一能建立的)才是一般檔案,直接移除。保守的邊界:
   vault editor 以預設名稱 `ipa-identity.yaml` 建立只有 scalar 的檔案,與別人建立的名冊無法區分,一律保留
   (`rosterNamesBeforeApply`、`foreignNewRosters`、`edit_workspace_rollback_classification_test.go`、
   `edit_workspace_rollback_foreign_new_test.go`)。加密的非名冊檔
   (`keycloak.yaml`)走同樣的保留/留給人工路徑,但只有留下明文名冊時才印 `freeipa.admin.password` 的提示。
   journal 與 rollback 以 `inventory.RosterFileKey` 辨識檔案,同一個檔案經不同 hard link 名稱的寫入記在
   同一個 key 下。沒有寫入紀錄就無法 rollback
   的寫入一律拒絕(讀不到寫入前內容的名冊不寫);同一 process 裡兩個 journal 不能看同一份名冊
   (名字不同但是同一個檔案也算,例如 hard link;`ErrRosterJournalBusy`,MCP 回 `workspace_locked`)。
   `inventory.RemoveRosterFile`(rollback 移除 session 新建的名冊)是對鎖住的檔案直接 `os.Remove`,不經
   `writeLockedRoster`,**不寫進任何 journal**;前提是呼叫端已經 `Stop`/`Close` 所有看著這個檔案的 journal,
   否則 journal 看到檔案消失卻沒有紀錄(`pilot edit` 的 rollback 在 `Stop` 之後才呼叫它;新的呼叫端照做)。新的寫入路徑若繞過 `writeLockedRoster`,
   `internal/inventory/roster_journal_guard_test.go::TestRegression_RosterBytesAreWrittenOnlyByWriteLockedRoster`
   會失敗。

### 5.15 功能要從真實入口一路測到,不是只測函式

6 個 fix 是「程式碼寫好了,卻沒有任何路徑會走到它」:

- `06131ff`:SNMP catalog/credentials 畫面從 Monitoring 選單進不去;畫面每次
  切換都從磁碟重讀 vault,之前加的內容被丟掉。
- `a01e094`:`baseline_samples` 表從沒被寫入。預設部署下 baseline 永遠暖不起來
  (`Observe` 要等 `Valid`,`Valid` 又需要 `Observe` 累積的歷史),之前所有的
  告警其實都是 log hard-trigger 觸發的。
- `3f29243`:Phase 3a 的註解寫著「Phase 3b contract」,playbook 卻從沒實作。
- `4443269`:prompt-id 只串到一半,completeness 檢查卻無條件啟用,讓既有的
  自動化情境全部失敗。
- `bbaa4ba`:`Render()` 少了 `DeploymentAvailability` 欄位,TUI 存檔後值就
  消失;Parse → Render → Parse 沒有 round-trip 測試。
- `cd407d5`:git stash 失誤,commit 只包含新檔案,單獨 build 不過。

規則:

1. 新增 TUI 畫面、CLI 參數或設定欄位時,至少要有一個測試從真實入口(router、
   cobra 指令、磁碟上的檔案)一路走到新功能,再把結果讀回來。範本:
   `cmd/pilot/cmd/edit_automation_driver_test.go::TestEditAutomationDriver_HostSettingsRoundTrip`
   (驅動真實 router,再從磁碟重新 parse `hosts.yml`)。
2. 會序列化的 struct 新增欄位時,要有 Parse → Render → Parse 的 round-trip 測試。
3. 程式碼註解裡「之後的 Phase 會補」的 contract,要寫進 spec 或 runbook 的已知
   缺口;實作之前,對應的檢查要 fail 或標示「未實作」,不能回傳 pass。
4. 每個 commit 都要能單獨 build。用過 `git stash` 或部分 staging 之後,commit 前
   要在乾淨 checkout 對 staged 內容跑一次 `go build ./...`。
5. 有「暖機」或啟動條件的狀態機,要有一個從冷啟動開始、不依賴其他觸發來源的
   測試(`internal/detection/engine_test.go::TestEngine_RunCycle_BaselineWarmsUpWithoutCohortOrLog`)。

---

## 6. 不要做的事

- ❌ 不要把中間產物、原始測試輸出、臨時檔或 scratch data 放到 repo 其他路徑；
  原始輸出只准進 gitignored `.verification/`、pilot evidence store、`./tmp`、`/tmp`
  或系統暫存目錄。唯一可提交的例外是刻意產出的 sanitized
  `docs/evidence/<feature>/<date>-<tested-revision>.md` 短摘要。
- ❌ 不要從「spec 設計意圖」推「inventory 應該有的 host」 — 從**你實際要執行的那份 inventory** 讀事實（vm-target：`show-inventory`；真實主機：`ansible-inventory -i <inv> --graph`，見 §0.1）
- ❌ 不要在 runbook 寫「預期 PASS 11/11」沒實際跑過；只可寫真實 verdict 摘要與
  evidence link，完整 transcript 不得持續追加到 runbook/spec
- ❌ 不要把硬規則繞過（「這次特例」是滑坡的開始）
- ❌ 不要把密碼 / token 寫進 spec、playbook、runbook — 走 `-e @~/.vault/...yaml`
- ❌ 不要擅自縮寫、拼錯或發明新變數名稱（例如把 `keycloak_db_password` 寫成 `keyclack_db_passwd`），必須完全依據 Spec 與既有變數命名。
- ❌ 不要讓 coding agent 先寫完 playbook，再反過來放寬 spec Expected 讓它 PASS；需求或驗收方法真的要改時，必須明說並記錄原因
- ❌ 不要把 `pilot spec --generate` 的 heuristic output 當正式 apply playbook、actual-run evidence 或交付完成證明
- ❌ 不要因為 Codex/Claude 是主要 authoring 介面，就把 LLM provider / prompt orchestration / agent loop 重新加回 pilot runtime
- ❌ 新增或移除會產生資料/設定檔的軟體角色時，不要漏改 `group_vars/restic-backup.example.yml` 的對應備份範例（見 §4.2）
- ❌ 新增/改 stage gate 時，不要只做「confirm 旗標」檢查而漏掉「host 的環境 group 是否與 stage 一致」的 cross-check（見 §4.3）——否則機器已歸類進 `staging`/`prod`，但指令忘了帶 `-e stage=`，會靜默用 `sandbox` 門檻套用
- ❌ 不要移除或繞過 `playbooks/site.yml` 開頭的 `target_group` 安全閥（見 §4.3）——它擋的是「全站入口誤帶 `-e target_group=` 同時覆寫全部子 playbook 目標」的事故
- ❌ 新增/改 `playbooks/apply/*.yml` 的 task 標 `tags: [always]` 時，不要漏查它依賴的前置 fact/探測 task 是否也標了 `always`（見 §4.4）——`pre_tasks:` 跟 `tasks:` 都要檢查
- ❌ 改動 `deploy.go` 的 `--limit`/依賴展開/tags 篩選邏輯時，不要只憑既有 mock 測試綠燈就合併；至少要有一個跨兩跳依賴的 regression test + 一次真實 topology 部署證據（見 §5.5）
- ❌ 撰寫解析外部 CLI 輸出的程式碼或 task 時，不要手寫猜測的 expected string 當 fixture——必須來自真實 vm-target 擷取的 stdout/stderr（見 §5.6）
- ❌ 不要在 play 層級 `vars:` 宣告應由 inventory 提供的變數，也不要讓 block 的 `when:` 依賴 block 內會被改動的 fact（見 §4.5）
- ❌ 新增「A 改了 B 就要跟著改」的配對時，不要既沒有一致性測試、也沒有改成單一來源（見 §5.7）——這類 drift 已經兩度造成「deploy 記錄成功，其實什麼都沒套用」
- ❌ 呼叫 `internal/ansible.Runner` 時不要只檢查 `err`；playbook 失敗記在 `Result.ExitCode`（見 §5.8）
- ❌ 授權、信任、mutation 的判斷不要讀快取或 apply 當下抓的快照（見 §5.9）；要清快取才會正確的結果是 bug，不是可以寫進 evidence 的 workaround
- ❌ shell task 用了 `pipefail` 或其他 bash 語法時，不要漏掉 `args: {executable: /bin/bash}`（見 §4.5 第 7 點）——Debian/Ubuntu 的 `/bin/sh` 是 dash，會以 rc=2 直接結束
- ❌ 不要把密碼、token 這類秘密值插進 shell 或 free-form `command:` 字串（見 §4.5 第 15 點）——用 `stdin` 傳入；`no_log` 只隱藏輸出，擋不住 shell 展開
- ❌ 修 bug 時不要只修發現的那一處；先 `git grep` 同類寫法，會在新程式碼重犯的要做成全 repo lint（見 §5.10）
- ❌ 不要讓預設值、validator、實際載入各自 join 同一個路徑，也不要把 repo-relative 路徑交給 Ansible `lookup('file')`（見 §5.11）
- ❌ 新增 gate、matcher、`changed_when` 時，不要只寫「應該通過」的測試；也要有用真實輸出證明它會觸發的案例（見 §5.12）
- ❌ 不要把 `ansible_host` 當成主機身分，也不要分大小寫比對 FQDN 或 FreeIPA 名稱（見 §5.13）
- ❌ reconciler 不要只測新增；「從 desired state 移除 → live state 被清掉」與冪等 teardown 都要有測試（見 §5.14）
- ❌ 新增畫面、參數、欄位時，不要只測函式本身；至少要有一個從真實入口走到底、再讀回結果的測試（見 §5.15）
- ❌ `kinit` 不要寫進預設 credential cache；用 `tasks/freeipa-private-ccache-open.yml`/`-close.yml` 的私有 cache（見 §4.5 第 14 點）

---

## 7. Patch and workspace rules

在套用任何 patch 前，先確認 shell 所在 workspace 與 Git root 一致：

```bash
pwd
pwd -P
git rev-parse --show-toplevel
git status --short
```

後續檔案路徑一律相對於 `git rev-parse --show-toplevel` 的 repo root。

若 `apply_patch` 回報檔案不存在：

1. 先以 repo-root 相對路徑重試一次。
2. 再執行下列唯讀確認，不能只靠猜測路徑：

   ```bash
   git ls-files | rg -i '<basename>'
   ls -la <parent-directory>
   pwd -P
   git rev-parse --show-toplevel
   ```

3. 若 shell 能讀到精確檔案、`apply_patch` 仍回報不存在，視為 patch backend 與
   workspace 的檔案系統 namespace 不一致；要明確回報此限制。

只有在上述確認完成後，才可用直接內容替換作 fallback。替換必須：

- 只針對一個明確檔案；
- 使用一個精確錨點，且在錨點出現零次或多次時失敗；
- 禁止 broad replacement、`cat` 或未驗證的 base64 覆寫；
- 立即執行：

  ```bash
  git diff --check
  git diff -- <path>
  ```

---

### Evidence recordings are disposable

- `trec` recordings and cast files are disposable evidence artifacts and are not
  committed to Git. Do not put cast filenames, cast paths, or recording-file
  inventories in committed runbooks. Runbooks may describe that a command was
  executed and include its real sanitized output, but the evidence file itself
  must remain outside the document.
- Keep raw `trec`/Ansible stdout and stderr only while the one-time acceptance
  run or its diagnosis is active. Once a truthful sanitized candidate summary
  has been committed, successful raw artifacts may be deleted. A failed run may
  be deleted after its fix has been verified by a newer candidate; do not turn
  disposable recordings into a permanent archive by default.
- **Summary-first reading rule:** agents must first read the command result or
  compact summary (exit code, duration, `PLAY RECAP`, verify verdict counts,
  candidate/tree). A zero-exit run with `failed=0` and passing verdicts does not
  justify opening the full transcript. On failure, search raw output for
  `FAILED!`, `fatal:`, `unreachable`, and `PLAY RECAP`, then read only the
  affected task and its bounded context. Read an entire recording only for an
  audit, baseline comparison, TUI replay, or an explicit user request.
- A committed sanitized evidence record must stand on its own after
  `.verification/` cleanup: it contains truthful candidate/tree, target
  summary, real verdicts, and redaction facts, but never a raw artifact path,
  filename, inventory, or required archive ID.
- **Committed-document link rule:** every repository-relative Markdown link in
  a tracked document must resolve to a tracked repository file at commit time.
  Do not link to `.verification/`, `tmp`/`/tmp`, vaults, generated local-only
  files, an ignored path, or a file that does not exist in Git. If the target
  is one-time operational evidence, replace the link with its sanitized
  candidate/tree, target summary, and real verdict; never leave a dead local
  evidence link behind.

### Per-run wizard drivers and path removal

- A `trec drive` script or other wizard driver is derived from the current
  inventory, environment, and live UI. Unless the user explicitly asks to
  maintain one as a product fixture, create it per run under `tmp/`, `/tmp`,
  `.verification/`, or the evidence store; do not commit it or describe it as
  a reusable operational contract.
- Runbooks and evidence records may state that a wizard was driven, but must
  not link to, require, or preserve a per-run driver. Record the tested
  candidate/tree, target facts, and actual verdict instead.
- Before deleting or moving a tracked path, run
  `git grep -nF '<old-path>' -- .` and resolve every match. After the change,
  the same search must have no matches, and `git diff --check` must pass.

### Trec-related issues never go in runbooks

- Any issue discovered while driving a wizard via `trec` — `EXPECT`/`SELECT`/
  `TOGGLE`/`CHOOSE`/`CHECKLIST_DOWN`/`DOWN` opcodes misbehaving, the `Bubble
  Tea`/promptui prompt pre-fill surprising a text input, MCP-vs-CLI recording
  fallbacks diverging, `PILOT_DEBUG_MENU` interacting badly with `SELECT`,
  `EXPECT_QUIET` being misused as a child-exit signal, the `vault`/`extra -e`/
  `vars 檔路徑` prompt chain for `freeipa-identity`'s roster turning out to
  require `vars 檔路徑` and not `extra -e`, host-key churn during `ssh`
  recording, the `BACKSPACE <n>` then `TEXT` pre-fill rule, etc. — is a
  **trec / wizard-driving** issue, not an operational / playbook issue.
  The canonical home for such issues is `.agents/skills/pilot-trec-verification/SKILL.md`
  (plus `~/.agents/skills/trec-mcp/SKILL.md` and `~/.agents/skills/trec-tui-drive/SKILL.md`
  for the tool layer itself). Operational runbooks (`docs/runbooks/*.md`)
  may describe **what** the operator did (which `trec drive --script` was
  used, what `Y` was pressed, what the output was), but never the
  *operational finding* that came from a `trec` recording session —
  not in the §0.5a fact snapshot, not in the changelog, not in a "Real
  bugs #N" row. The §0.5a timestamp + the changelog are for *what this
  pass actually deployed / verified*, not for *how the recording driver
  behaved*. If a `trec`-discovered finding also turns out to be a real
  bug in `pilot` or a playbook (not just in the driver), record the bug
  in the appropriate place (Go source / playbook / spec) — but
  categorize the entry as *bug* not *trec issue*.

## 8. 變更紀錄

| 日期       | 版本 | 變更 | 變更者 |
|------------|------|------|--------|
| 2026-07-01 | v1.0 | 初版（spec-vs-inventory 事故後寫的硬規則）| sre |
| 2026-07-01 | v1.1 | §4 加 apply playbook `tags:` 硬規則（對齊 spec ID / 多 role 命名空間 / `--list-tags` 驗證）| sre |
| 2026-07-02 | v1.2 | §5 大幅擴充 Go 架構約定（`-race` gate、target 兩份平行實作、`statefile`/`writeTempInventory` 共用層、per-call option 不寫回欄位、加 tool 步驟 + schema/struct 同步、Interceptor 雙路徑、`handleToolCall` pipeline）| sre |
| 2026-07-02 | v1.3 | §5.5 三種輸出管道約定（error / `slog` 診斷 / 使用者 UX）；導入 `internal/logx` 結構化 logging，`--log-level`/`$PILOT_LOG_LEVEL`| sre |
| 2026-07-02 | v1.4 | inventory 規則改為**來源中立**：新增 §0.1「目標 inventory」名詞與讀法對照（vm-target `show-inventory` / 真實主機 `ansible-inventory --graph`）；§1.1/§1.3/§2/§2.1/§3/§4/§6 一併泛化，同一套紀律適用測試 VM 與真實主機 | sre |
| 2026-07-06 | v1.5 | 新增 §4.2：新增/移除會產生資料的軟體角色時，必須同步更新 `group_vars/restic-backup.example.yml` 的備份範圍範例（起因：`restic-backup` 上線後，既有角色清單容易在新增/移除軟體時漏改）；§6 補一條對應的 ❌ 提醒 | sre |
| 2026-07-06 | v1.6 | §5.1 新增「state RMW 一律走 `Store.Mutate`」硬規則（起因：兩個 `vm-target up` 並行時 Load→改→Save 的 last-writer-wins 讓一台 VM 的 state 條目消失變孤兒 domain；`statefile` 已加跨行程 flock + `Mutate`，vmtarget `Up` 改名額預約制，dockertarget 同步） | sre |
| 2026-07-09 | v1.7 | 新增 §4.3:stage gate 必須跟 inventory 的環境 group 對齊(起因:`-e stage=` 跟 `staging`/`prod` 環境 group 完全沒有連動,機器已歸類進 `staging` 卻沒帶 `-e stage=staging` 會靜默用 sandbox 門檻套用;8 支 apply playbook 已補上 `group_names` cross-check assert,`site.yml` 也加了 `target_group` 安全閥擋全站入口誤用);§6 補兩條對應的 ❌ 提醒 | sre |
| 2026-07-09 | v1.8 | 補齊 v1.7 遺留的 6 支缺 gate playbook(`pam-oidc-sshd`、`log-server`、`audit-log-forwarding`、`wazuh-manager`、`wazuh-fim`、`restic-backup`);同時發現另有 5 支尚未接進 `site.yml` 的可觀測性 playbook(`prometheus`/`thanos-query`/`alertmanager`/`dashboard`/`log-shipping`)也沒有 gate,記錄在 §4.3 留待下一輪 | sre |
| 2026-07-09 | v1.9 | 補齊 v1.8 記錄的 5 支可觀測性 playbook——`playbooks/apply/*.yml` 現在**全部 19 支**都有 stage/confirm/cross-check gate,規則一致無例外;§4.3 第 4 點改寫為「新增 playbook 一律要帶,沒有預設豁免」 | sre |
| 2026-07-09 | v1.10 | 新增第 20 支 apply playbook `freeipa-server-replica-apply.yml`(FreeIPA multi-master HA replica,對應 spec `docs/verification/freeipa-server-replica.md` v0.1 草稿、尚未實跑);§4.3 playbook 清點更新為 20 支,並記錄它刻意不接進 `site.yml`(day-2/opt-in,比照 `freeipa-identity`) | pilot |
| 2026-07-17 | v1.11 | 把 `docker` 角色從 `core-infra-provider-apply.yml`(`-e infra_role=docker`)拆成獨立的第 21 支 apply playbook `playbooks/apply/docker-apply.yml`,理由與 2026-07-01 拆 `keycloak-db` 相同(見 `docs/runbooks/docker.md`);`core-infra-provider-apply.yml` 現在只剩 `dns`/`ntp` 兩個 `infra_role`;`site.yml`、`deployCatalog`、`inventory` role contract、`DELIVERY.md` playbook 對照表一併更新;§4.3 playbook 清點更新為 21 支 | pilot |
| 2026-07-18 | v1.12 | 對齊實際 authoring model：使用者寫自然語言需求，外部 Codex/Claude 先確定 spec、再直接撰寫 apply playbook/regression test，pilot runtime 專注確定性 lint/test/deploy/verify/evidence；明定 generator 非正式 apply 來源，移除已退役 LLM tool/agent loop 規則 | pilot |
| 2026-07-18 | v1.13 | 新增 §7 patch/workspace 規則：套用 patch 前確認 Git root；patch backend 找不到檔案時先重試相對路徑並驗證追蹤檔與父目錄，fallback 必須採精確錨點與 diff 驗證 | pilot |
| 2026-07-20 | v1.14 | 明定 trec cast 為不可提交的暫存證據；committed runbook 不得記錄 cast 檔名、路徑或錄影檔清單，只保留實際執行輸出 | pilot |
| 2026-07-22 | v1.15 | 新增「Trec-related issues never go in runbooks」：任何 trec 驅動 wizard 過程中發現的 issue（opcodes 行為、MCP/CLI 差異、wizard prompt chain、host-key churn、預填行為等）一律記錄在 `.agents/skills/pilot-trec-verification/SKILL.md` 及其同層 tool-driver skills；operational runbook 只記錄「這次 pass 做了什麼/驗證了什麼」，不記錄「trec 驅動時踩了什麼坑」。原因：v11.0 重新驗證時把 wizard banner 的 UI 落差誤列為「Real bugs #27」，實際是 trec 驅動時的 prompting 路徑問題，應該留在 trec skill 的 §7 gotcha list 而非 runbook 的 bug table | pilot |
| 2026-07-22 | v1.16 | actual-run evidence 與操作文件分離：runbook/spec 只留目前有效摘要與連結，完整輸出進獨立 artifact；正式完整測試改為先凍結本地 candidate commit，再從乾淨隔離 checkout 驗證，後續 evidence-only commit 引用 tested revision/tree。日常 dirty worktree 仍可跑快速測試 | pilot |
| 2026-07-23 | v1.17 | 新增 committed-document link rule：tracked 文件的 repository-relative Markdown link 必須指向 Git 追蹤檔；不得連到 `.verification/`、暫存、vault、generated local-only、ignored 或不存在的檔案。一次性驗收改以 sanitized candidate/tree、target 與 verdict 摘要表達 | pilot |
| 2026-08-03 | v1.19 | 新增 per-run wizard driver 與路徑刪除規則：agent 依當前環境產生暫存 driver，不提交、不當作 runbook 契約；刪除／搬移 tracked path 前後必須盤點並清除引用 | pilot |
| 2026-07-31 | v1.18 | 新增第 25 支 apply playbook `freeipa-dns-client-apply.yml`(目標主機把 DNS resolver 指向已經在跑 DNS 的 FreeIPA server/replica;與 `freeipa-client` AAA 納管互不相依,day-2/opt-in,不接進 `site.yml`,比照 `freeipa-server-replica`/`freeipa-dns`);§4.3 playbook 清點更新為 25 支,補上先前清點漏掉的 `freeipa-dns` | pilot |
| 2026-08-24 | v1.20 | 新增 `dcgm-exporter` apply playbook(GPU 主機的 NVIDIA dcgm-exporter 監控 agent,獨立於 `host-monitoring` 之外的 component,依賴 `docker`;已接進 `site.yml`);§4.3 playbook 清點更新為 31 支 | sre |
| 2026-08-28 | v1.21 | Stage A-2:新增 `detection-engine` apply playbook(中央 Detection Engine,從 Thanos metrics 建立 adaptive SignalEvent,依賴 host-monitoring/thanos-query/alertmanager,已接進 `site.yml`,見 `docs/superpowers/specs/2026-08-28-detection-engine-spec.md`);§4.3 playbook 清點更新為 32 支 | sre |
| 2026-09-01 | v1.22 | Agent Monitoring Phase 1:新增 `agent-controller` apply playbook(observe-only incident controller,接收 Alertmanager webhook、正規化成 incident、派送唯讀診斷請求給外部 Agent Runtime,零 mutation 權限,不依賴其他 component,experimental/day-2 opt-in,不接進 `site.yml`,見 `docs/superpowers/specs/2026-09-01-agent-monitoring-phase-1-observe-only-controller-spec.md`、`docs/architecture/agent-monitoring.md`);§4.3 playbook 清點更新為 33 支 | pilot |
| 2026-09-01 | v1.23 | SNMP Monitoring Integration Phase 0:新增 `snmp-exporter` contract/verification skeleton 與 apply playbook(只有 stage/confirm/inventory-group gate,`tasks: []`,尚無任何部署邏輯;day-2/opt-in,不接進 `site.yml`,見 `docs/superpowers/specs/2026-09-01-snmp-monitoring-integration-spec.md`、`docs/architecture/snmp-monitoring.md`);§4.3 playbook 清點更新為 34 支 | pilot |
| 2026-09-07 | v1.24 | 兩週 22 個 fix commit 回顧後新增三條硬規則:§4.4(`always` tag 前置任務要跟著標,起因 `2abb6fd`/`dada083` 連續咬 3 支 playbook,`af239e3` lint 第一版還漏掃 `pre_tasks`)、§5.5(`deploy.go` 的 `--limit`/依賴展開/tags 篩選是高風險核心邏輯,3 天內修 6 次)、§5.6(解析外部 CLI 輸出的 fixture 必須來自真實擷取,起因 FreeIPA/decommission 一週內抓到 11 個「unit test 早就綠燈但真機才現形」的真 bug,附帶 package-level 測試狀態污染的教訓);§6 補三條對應 ❌ 提醒 | pilot |
| 2026-09-14 | v1.25 | pilot-access-gateway Phase 6:新增 `gateway-scope` apply playbook(`pilot gateway-scope plan/reconcile` CLI 的後端,把一個 scope 的目標主機清單發布成 FreeIPA hostgroup `pilot-target-<scope>`,day-2/opt-in、not per-host role,見 `docs/superpowers/specs/2026-09-14-pilot-access-gateway-stateless-freeipa-portal-spec.md` §9.6/§57、`docs/verification/pilot-gateway-scope.md`);§4.3 playbook 清點更新為 35 支;活體 vm-target 測試發現 `-e gateway_scope_hosts=[...]` 這種寫法會被 Ansible 當純字串(逐字元跑 diff),必須用 `-e '{"gateway_scope_hosts": [...]}'` 的 JSON 物件形式 | pilot |
| 2026-09-14 | v1.26 | pilot-access-gateway Phase 7:新增 `pilot-access-gateway` apply playbook(裝 stateless FreeIPA-backed SSH/sudo 存取閘道到單一 gateway 主機,含 reader service principal/keytab、systemd socket-activated API、`pilot portal` 前端;ForceCommand 步驟預設關閉,留給 Phase 8,見 `docs/superpowers/specs/2026-09-14-pilot-access-gateway-stateless-freeipa-portal-spec.md` §55/§0 G4、`docs/verification/pilot-access-gateway.md`);§4.3 playbook 清點更新為 36 支,登記為一般 per-host 角色(`internal/inventory` topLevelOrder/roleContracts,比照 `agent-controller`/`freeipa-server-replica`,而非像 `gateway-scope` 那樣豁免);活體 vm-target 測試抓到並修正 4 個真 bug:`ipa service-add` 要求正向 DNS record 先存在、`/usr/local/libexec` 在 Ubuntu 上不存在、local fallback group 會被 nsswitch `files` 來源永久遮蔽同名 FreeIPA 群組(已改成 fail-closed 檢查,不再建 local 群組)、`RuntimeDirectory=` declare 在錯的 systemd unit(`.service`)上會讓重啟 service 把 `.socket` 建立的 socket 檔一併刪掉(已搬到 `.socket` unit);另外在定位這組 bug 過程中先誤判成「systemd 無法可靠解析 SSSD 群組」,實際重跑驗證後已回頭修正相關文件註解為正確成因(local group shadowing) | pilot |
| 2026-09-14 | v1.27 | pilot-access-gateway Phase 8(收尾):在人員明確核准後(啟用 ForceCommand、模擬 FreeIPA 斷線皆被 auto-mode classifier 攔下要求人工確認)對 disposable vm-target 完整跑過 §55.1 三步鎖定回歸測試(AG20/21/25)+ 新增第二台 gateway 對 AG26/27 同/異 scope 隔離做強驗證(含同一使用者對兩個 scope 都有真實 HBAC 權限但互不外溢的案例)+ FreeIPA 斷線 fail-closed 活體驗證(AG16);過程中意外發現並修正一個真的 process-crash 可用性 bug:`internal/freeipaaccess.NewClient` 原本同步載入 keytab,缺檔會讓整個 process exit,因為服務是 socket-activated 很快撞上 systemd start-rate-limit 讓**整個 socket 單元**卡死、修好 keytab 也不會自動恢復——已改成跟既有 session 建立一樣 lazy + per-call retry(`internal/freeipaaccess/kerberos_test.go` 新增兩個回歸測試);也補上 playbook 原本只能開、不能透過旗標關閉 ForceCommand 的對稱性 gap。至此 8 個 Phase(§60)全數完成 | pilot |
| 2026-09-18 | v1.28 | Pilot Access Directory/Gateway Handoff/Session Recording delivery(`docs/superpowers/specs/2026-09-16-pilot-access-directory-session-routing-recording-spec.md`)Phase 8(收尾):新增 `pilot-session-store` apply playbook(terminal recording 的獨立 stateful persistence,加密 index + TLS ingest API + 獨立 Unix socket read/replay API;從不是 SSH portal ingress,無 ForceCommand/HBAC;依賴 freeipa-client 取得機器 keytab 走 `ipa-getcert` 核發 ingest TLS 憑證,不需要 admin 密碼;已接進 `site.yml`,見 `docs/verification/pilot-session-store.md`);§4.3 playbook 清點更新為 38 支;順手補上 `internal/sessionstore.LoadMasterKeyFile` 原本完全沒有單元測試涵蓋的缺口(`internal/sessionstore/encryption_test.go`);read socket 權限設計刻意不沿用 Gateway/Directory 共用的 `/run/pilot`(該目錄的決定性權限來自 systemd `.socket` unit 的 `SocketUser`/`SocketGroup`/`SocketMode`,而這個元件的 read API 是 process 自己 `net.Listen`,沒有 socket activation),改用專屬 `RuntimeDirectory=pilot-session-store` + `UMask=0007` + `Group=role-pilot-session-auditor` 三者搭配才能讓 auditor group 成員真的連得上 | pilot |
| 2026-09-23 | v1.29 | Captive SSH transport(`docs/superpowers/specs/2026-09-23-pilot-access-gateway-captive-ssh-transport-spec.md`)Phase 4:新增第 39 支 apply playbook `pilot-access-target-policy-apply.yml`(transport target 端的 sshd 政策:以 `Match Address <gateway 位址>` 對 Gateway 來的每個 session 拒絕 sshd forwarding——刻意不用 `Match Group`,因為 opaque transport 無法強制 inner username;驗證通過後才加入 FreeIPA hostgroup `pilot-transport-ready`,gateway 只對這個 hostgroup 開 `pilot-transport-v1`;`absent` 先移出 hostgroup 再移除 drop-in;day-2/opt-in,不接進 `site.yml`,與 `pilot-access-gateway`/`pilot-access-directory` 互斥);§4.3 清點更新為 39 支;§4.2 不需新增 restic 範例(只寫 `/etc`,已被預設 `["/etc"]` 涵蓋) | pilot |
| 2026-09-23 | v1.30 | 回顧最近 20 個 fix commit(`9550b38`~`5b735ee`,2026-09-15~09-23)後新增四條規則:§4.5(Ansible 語意陷阱:block `when:` 在每個 task 各自重新判斷、重複 include 的狀態外洩、play `vars:` 蓋掉 inventory、check mode 被跳過的 register、installer 準備 task 每次重設 owner、重複 YAML key)、§5.7(同一件事記在兩處時必須有一致性測試或單一來源,列出現有的四個一致性測試;起因:20 個 fix 裡 8 個屬於這類,`9550b38`/`c58d63a` 是同類第二次)、§5.8(沒有 error 不等於成功:`ansible.Runner` 失敗只記在 `Result.ExitCode`、網路步驟要有 timeout、修復失敗不准沿用舊資料、lint 設定/輸出上限會靜默失效)、§5.9(決策讀權威來源不讀快取/快照:SSSD member list、apply 時的 `ssh-keyscan`、過期 apt index、detection refresh;需要清快取才正確的結果要當 bug 處理);§6 補四條對應 ❌ 提醒 | pilot |
| 2026-09-24 | v1.31 | 再往前回顧 50 個 fix commit(`27ec586`~`81f7090`,2026-08-24~09-15)後新增 §5.10~§5.15:§5.10(修 bug 先掃同類,會在新程式碼重犯的做成全 repo lint;起因:play `vars:` 覆蓋、include 兩次 fact 殘留、`dig` 診斷、validator 形狀、`pipefail` 都是修一處後在別處重犯)、§5.11(路徑在入口正規化一次,7 個 fix 是容器/全新 runtime/不同 cwd 下路徑解析不同)、§5.12(gate/matcher/`changed_when` 要有證明會觸發的測試,8 個 fix 是永遠比對不到的檢查)、§5.13(主機身分統一用小寫 FQDN,`ansible_host` 不是身分)、§5.14(移除/撤銷/清理路徑與冪等 teardown)、§5.15(從真實入口測到底、round-trip、每個 commit 單獨可 build);§4.5 補第 7 點(`shell` 預設 `/bin/sh`=dash 不認得 `pipefail`,新增全 repo lint `internal/spec/shell_pipefail_regression_test.go`,同時修正它抓到的 5 個 task,含 `tasks/freeipa-dns-client-resolver.yml` 在 Debian/Ubuntu 上從未生效的 rescue ROLLBACK)與第 8 點(`include_tasks` 的 `tags:` 不會傳給被 include 的 task),並在第 2、3 點補上第一次修的 commit;§6 補七條對應 ❌ 提醒 | pilot |
| 2026-09-24 | v1.32 | §4.5 第 8 點改寫：`include_tasks` 帶 tags 卻沒有 `apply` 的寫法改由全 repo lint `TestRegression_TaggedIncludeTasksUseApply` 鎖住（17 處尚未遷移的列入 ratchet allowlist），並補上共用 task 檔巢狀 include 用 `apply: {tags: [always]}` 的寫法；新增第 9 點（直接用 `ansible.builtin.apt`/`package` 裝套件會吃過期的 apt index，`TestAptDirectInstallAllowlist` 鎖住，4 處列入 allowlist）。起因：`freeipa-dns-client` 的 vm-target 實跑（`docs/evidence/freeipa-dns-client/2026-09-24-583df40.md`） | pilot |
| 2026-09-24 | v1.33 | §4.5 第 8、9 點：帶 tags 沒 `apply` 的 17 組 `include_tasks` 與 4 個繞過 apt framework 的套件安裝全部遷移，兩個 ratchet allowlist 清空；補上遷移時的規則（前置 fact 帶對應 tag、只讀 pre_tasks 標 `always`、mutation 安全 gate 標它保護的 row tag） | pilot |
| 2026-09-24 | v1.34 | §4.5 第 8 點：安全 gate 的 tag 要涵蓋它保護的每一個 mutation。修正 PR #10 review 抓到的兩個 `--tags` 繞過（`freeipa-ca-trust` stage gate 改 `always`；`internal-endpoint` C7/C8 gate 補 C4–C6、C12 preflight 補 C13/C15，fleet-wide baseline play 補上 stage gate），新增全 repo lint `TestRegression_PreTaskGatesRunUnderApplyTags`（allowlist 列 4 支既有、留給後續 repo-wide stage gate 修正的 playbook） | pilot |
| 2026-09-24 | v1.35 | §4.5 第 7 點：`pipefail` 下不准 pipe 進 `head`/`grep -q` 這類提早結束的 reader（SIGPIPE → rc=141）。修正 `tasks/freeipa-dns-client-resolver.yml` snapshot 的 `nmcli … \| head -n1`（讓 main CI 偶發紅燈），新增全 repo lint `TestRegression_PipefailShellTasksHaveNoEarlyExitReader`；新增第 10 點：free-form shell 字串（含註解）的引號要成對，否則 `split_args` 讓整支 task 檔載入失敗，新增 `TestRegression_FreeFormCommandsSplitInAnsible` | pilot |
| 2026-09-24 | v1.36 | §4.3 新增第 5 點：prod attestation gate 的 `that:` 不准放 `stage != 'prod'`（搭配 `when: stage == 'prod'` 會讓 prod 永遠失敗）。修正 9 支 playbook 共 10 道 gate，新增全 repo lint `TestRegression_AssertNeverNegatesItsOwnWhen` | pilot |
| 2026-09-25 | v1.37 | §4.3 新增第 6 點：stage gate 一律標 `always`，否則 `--tags`（包括 `pilot deploy` 單一元件精靈的 tags 欄位）會跳過 cross-check，讓 prod group 主機以 sandbox 規則被改。6 支 playbook 的 18 道 gate 改標 `always`，freeipa-ca-trust、internal-endpoint（兩個 play）、reverse-proxy 補上 cross-check；新增 lint `TestRegression_StageGatesAlwaysRunInTaggedPlays`、`TestRegression_ApplyPlaysWithConfirmGateHaveCrossCheck` | pilot |
| 2026-10-01 | v1.38 | §4.3 新增第 7 點：pilot 呼叫 playbook 時，stage 要依每次 run 的目標主機的環境 group 決定，staging/prod 要帶操作者的確認。修正 `pilot host decommission` 完全不帶 stage、staging/prod 主機無法下架的問題（`StageScope`、`apply`/`resume` 的 `--confirm-staging`/`--confirm-prod`/`--staging-attested-within-hours`、TUI 確認畫面） | pilot |
| 2026-10-01 | v1.39 | §4.5 新增第 11 點：loop 累加的 fact 在空 loop 時不會被設定。修正 `internal-endpoint-apply.yml` 的 `internal_endpoint_normalized`（`endpoints: []` 時 decommission verify 查詢報 undefined），新增全 repo lint `TestRegression_LoopAccumulatorsAreInitializedOrGuarded` | pilot |
| 2026-10-01 | v1.40 | §4.4 補一點：assert/fail 檢查本身也要能在 `--tags` run 執行——輸入檢查標 `always`，流程中間的驗證標所屬步驟的 row tag。修正 10 支 playbook 共 20 個沒有 tag 的檢查，新增全 repo lint `TestRegression_NoUntaggedChecksInTaggedPlays`；`preTaskGateNotAlwaysAllowlist` 清空 | pilot |
| 2026-10-01 | v1.41 | §4.4 補兩點：(1) rescue 與 block `always:` 區段在 `--tags` 下一樣會被篩選，帶 tag 的 run 失敗時不會回滾。8 支 playbook 的 rescue 改標 `always`，連同它們讀的 snapshot/升級判斷（pam-oidc-sshd Step 1、agent-controller/detection-engine Step 3–5 與新增的 Step 3d 備份目錄）；新增全 repo lint `TestRegression_RescueRunsWheneverItsBlockDoes`，其餘 12 支列入 ratchet allowlist。(2) 帶 row tag 的 task 讀的 register/set_fact，setter 也要在同樣的 `--tags` 下執行，否則用 default 讀；修正其中 6 支的 17 處（container `restart:` 判斷、pam-oidc-sshd Step 4、agent-controller listen address），新增 lint `TestRegression_TaggedTasksReadOnlyWhatTheirTagsSet`，其餘 15 支列入 allowlist | pilot |
| 2026-10-01 | v1.42 | §4.4：其餘 12 支 playbook 的 rescue 改標 `always`，連同 rescue 讀的 snapshot/inspect（freeipa-nfs-server 的 exports 快照、freeipa-realm-replacement 的 tar 快照、pilot-access-target-policy 讀現有 drop-in），`rescueTagGapAllowlist` 清空；其中 8 支的 32 處 row-tag 前置讀取一起修（`restart:`/`when:` 的 `is changed` 改讀 default、只讀的偵測 task 標 `always` 或 reader 的 tag），`taggedPrerequisiteAllowlist` 剩 7 支；`AlwaysTagPrerequisite` lint 接受 `x is defined` 檢查；兩支前置 lint 都會展開 `include_tasks`/`import_tasks` 檔案裡設的 fact，抓到並修正 5 支 playbook 的 `/etc/hosts` pin 讀未標 tag 的 resolver include（wazuh-manager C10、wazuh-fim C7、audit-log-forwarding C15、log-shipping C5、restic-backup C10） | pilot |
| 2026-10-01 | v1.43 | §4.4：修正其餘 7 支 playbook 的 17 處 row-tag 前置讀取（`is changed`/`.changed` 改讀 default；freeipa-identity 的 HBAC/sudo lookup 補 C14/C17；gateway-scope 的計算與 kinit 標 `always`；pilot-access-gateway 的 Step 13 與 admin kinit 補 AG12/AG_service），`taggedPrerequisiteAllowlist` 清空；freeipa-identity 的 admin kinit/kdestroy 改 `always`、pilot-access-directory/pilot-session-store 的 kinit/kdestroy 補 AD_service/SS_service，新增 lint `TestRegression_IpaCommandsHaveAKinitForTheirTags` | pilot |
| 2026-10-01 | v1.44 | 新增第 40 支 apply playbook `dns-apply.yml`:`dns` role 從 `core-infra-provider-apply.yml -e infra_role=dns` 拆出,改成 FreeIPA 前的第一層 unbound 快取 DNS(inventory 有 FreeIPA DNS 時內部網域自動送到 FreeIPA,其餘送到使用者設定的 upstream;spec `docs/verification/dns.md`);`site.yml` 順序移到 freeipa-server 之後;`core-infra-provider` 只剩 NTP(row 重新編號 C1–C3)。同時修掉三個既有 bug:play `vars:` 的 `dns_zones: []` 蓋掉 group_vars、`group_vars/dns/` 目錄讓 `group_vars/dns.yml` 整個失效、scaffold 把範例的假 zone 複製成真設定;`pilot inventory lint`/`generate`/`pilot edit` 加上 group_vars/host_vars 遮蔽偵測;§4.3 清點更新為 40 支;§4.2 不需新增 restic 範例(只寫 `/etc`) | pilot |
| 2026-10-02 | v1.45 | §4.5 新增第 12 點：`{{ }}` 模板裡的 `\\` 不會被還原成 `\`，regex 靜默失效。修正 pilot-access-gateway AG82 的 `..` 拒絕訊息與路徑正規化，新增全 repo lint `TestRegression_JinjaTemplatesUseSingleBackslashes`（allowlist 一處：`freeipa-dns-apply.yml` 的 `[ \\t]`）與語意測試 `TestJinjaTemplateBackslashSemantics` | pilot |
| 2026-10-02 | v1.46 | §4.4 補一點：mutation 之前必須先跑的記錄/檢查 task 要帶齊 mutation 的每一個 tag，只該在 restart/health 之後做的清理在 `--tags` run 要自己確認前提。修正 pilot-access-gateway：AG82 的舊 token 路徑記錄補上 Step 11 的 AG01/AG41/AG42/AG94，刪除改成等沒有待生效重啟、config 不再指向 token、health 通過；錄影政策降級檢查補 AG94、AG81（PR #19 review）| pilot |
| 2026-10-12 | v1.47 | §4.5 新增第 13 點:互斥 task 的 register 結果不准用 `combine()` 合併(被跳過的 task 帶 `changed: false`),單檔 bind mount 在檔案被換掉後要比對 container 實際看到的內容再決定重啟。修正 `prometheus-apply.yml`(有 Alertmanager 時設定變更從未重啟 container),新增共用 `tasks/container-file-mount-drift.yml`、全 repo lint `TestRegression_RegisteredResultsAreNeverCombined`、`prometheus.md` C20;同一個檢查接上其餘 7 支 playbook 的 9 個掛單檔的 container,新增 lint `TestRegression_FileMountedContainersRestartOnStaleMounts`(也檢查 include 與 container 的 `when:` 相同);檢查的 task 一律 `no_log`(inspect 含 env、密碼檔的 hash),由 `TestRegression_ContainerFileMountDriftHidesWhatItReads` 鎖住 | pilot |
| 2026-10-13 | v1.48 | §4.5 第 3 點、§5.7:15 支 apply playbook 把 60 個 contract `groupVars` 或 `group_vars/<role>.example.yml` 記載的變數宣告在 play `vars:`,蓋掉 inventory 的值(agent-controller、dashboard、dcgm-exporter、detection-engine、freeipa-client、gateway-scope、host-monitoring、log-shipping、pilot-session-store、prometheus、restic-backup、snmp-exporter、thanos-query、wazuh-fim、wazuh-manager);改用 stage gate 之後的 `always` `set_fact` 補預設值(必填 secret 與已在讀取處 `default()` 的變數只移除),預設值不變。新增全 repo lint `TestRegression_ApplyPlayVarsDoNotShadowInventoryInputs` 與在 localhost 實際跑 Ansible 的 `TestRegression_InventoryInputsReachThePlay` | pilot |
| 2026-10-14 | v1.49 | §4.5 新增第 14 點：`kinit` 一律寫進私有 credential cache（`tasks/freeipa-private-ccache-open.yml`/`-close.yml`），不准寫進預設 cache 後留著。修正 issue #69 列出的 10 個檔案（freeipa-server、gateway-scope、internal-endpoint、4 支 `playbooks/check/*`、NFS server decommission、dns fixture），新增全 repo lint `TestRegression_KinitUsesAPrivateCredentialCache`（已會 `kdestroy` 的 13 個檔案列入 ratchet allowlist）；被中斷的 run 留下的 cache 只由同一個執行帳號清除，別的帳號的 cache 不碰（`TestRegression_PrivateCcacheOpenLeavesOtherUsersCaches`） | pilot |
| 2026-10-14 | v1.50 | §4.5 第 3 點、§5.7:play-vars lint 改成對每支 apply playbook 檢查所有 contract 的 input(log-server 的 `siem_log_root` 是 log-shipping 的 input,log-server 卻仍用 play vars,Promtail 找不到可 tail 的檔案、apply 失敗);新增 `TestRegression_SpecInputsAreDeclaredContractInputs`:spec 變數契約表列出的變數必須宣告在 contract `groupVars`(尚未處理的 15 個元件列在 `undeclaredSpecInputsAllowlist`,見 issue #81)。log-server、audit-log-forwarding、log-shipping 的變數契約表變數從 play vars 移到 `always` `set_fact`,並宣告進各自 contract;共用的 `siem_log_root`、SIEM 埠與 logrotate 次數的空值/null 一律回到預設,由 `TestRegression_SIEMSharedInputsResolveTheSameOnEverySide` 鎖住兩邊一致;audit-log-forwarding 在 client 的 `siem_forward_port` 與 inventory log-server 的 `siem_receiver_tcp_port` 不一致時 fail;log-server 拒絕系統或共用目錄當 `siem_log_root`(寫出的路徑與 `realpath` 解析後的真實路徑都檢查),既有目錄必須已是本角色建立的狀態(只有 `lost+found` 的新掛載檔案系統根目錄例外);SIEM port 與 `loki_port` 必須是 1–65535 的十進位整數;logrotate 設定檔的 `validate` 只在 `logrotate -d` 回報這個檔案本身的錯誤時失敗,並先安裝 logrotate;SELinux 主機上 rsyslogd(`syslogd_t`)只能用 `syslogd_port_t`/`rsh_port_t` 的 TCP port,非預設的 SIEM port 由 `tasks/rsyslog-selinux-tcp-port.yml` 標成 `syslogd_port_t`(被其他服務占用的 port 直接 fail),audit-log-forwarding spec 新增 C22 檢查 rsyslogd 對轉送埠的連線真的建立。preflight 與 repair 共用 `contract.ValueMatchesType`:`integer` 接受 `ansible-inventory` JSON 的 float 與十進位字串,修正既有 integer input(例如 `dns_cache_max_ttl`)寫在 group_vars 時 preflight 一律失敗的問題;port 一律宣告成 `integer` | pilot |
| 2026-10-14 | v1.51 | §4.5 第 14 點改寫（#72 合併後的 follow-up）：原本列在 allowlist、宣稱「已會 `kdestroy`」的 13 個檔案其實在失敗、`--tags`、`KCM:`/`KEYRING:` collection 時留下 ticket，pilot-access-gateway 根本沒有 `kdestroy`——全部改用私有 cache，lint 不再有 allowlist，並且也接受 tempfile/`MEMORY:` cache；close 重設 `pilot_krb5ccname`、`--check` 不刪過期 cache；`ipa` lint 檢查 cache 一致；`pilot-gateway-scope.md` C1–C3 與 `internal-endpoint.md` 六列改用 ldapi 讀 LDAP（原本靠洩漏的 ticket 才通過）；新增 `TestRegression_SpecProbesSplitInAnsible`；`vm-target run --sandbox` 複製整個 `playbooks/`; `spec.NeedsBecome` 把 `ldapi://`、`-Y EXTERNAL` 視為需要 root:`pilot-gateway-scope.md` C1–C3、`freeipa-identity.md` C1–C24、`freeipa-server-replica.md` C14/C15、`freeipa-dns.md` C1 原本以 SSH 使用者身分執行,只因 vm-target 的 SSH 使用者是 root 才通過(`TestRegression_LdapiExternalRowsRunAsRoot`);`freeipa-identity.md` netgroup 撤銷 SOP 的手動加成員改用 ldapi `ldapmodify`。#79 也新增 v1.50,後合併者重新編號 | pilot |
| 2026-10-14 | v1.52 | 新增 `login-probe-apply.yml`（GitHub issue #11：每站外部 SSH/PAM 登入探測；以 FreeIPA canary 帳號經系統 OpenSSH 真實登入，並經 node_exporter textfile collector 發布狀態）；同時新增 host-health / login-probe 告警與 Alertmanager inhibit 規則、topology fixtures、decommission target reconciliation 與 regression coverage。Prometheus spec 保留主線 C20–C22，login-probe 驗收項目編為 C23–C24 | pilot |
| 2026-10-16 | v1.53 | §4.5 新增第 15 點：密碼不得插進 shell 或 free-form `command:` 字串。PR #92 的 3 個 FreeIPA kinit task（replica forwarder、replica self-register、primary dnsconfig-mod）改用 `argv` + `stdin`；新增全 repo lint `TestRegression_NoSecretInCommandText`（既有 33 處列入以 task 數計算的 ratchet allowlist，#118 追蹤）與行為測試 `TestRegression_FreeIPAKinitTasksPassPasswordUnchanged`。#79（v1.50）、#80（v1.52）也新增列，後合併者重新編號 | pilot |
| 2026-10-15 | v1.54 | §4.5 新增第 16 點:`ipa` 的長選項接受唯一前綴,不存在的選項會被靜默當成另一個選項。修正 host decommission 的 HBAC/sudo 直接引用查詢(`--host=` 被當成 `--hostcat`,永遠 0 筆,issue #104),新增全 repo lint `TestRegression_PlaybookIPAOptionsExistInIPAHelp` | pilot |
| 2026-10-27 | v1.55 | §5.7 一致性表新增「名冊 `freeipa.admin.password` ↔ vault `ipa_admin_password`」(issue #146):只改 vault 會讓 freeipa-nfs-server 的 no_log gate 失敗且看不出原因。`pilot edit` 改 `.vault/main.yaml` 的 `ipa_admin_password` 時同步 workspace 名冊(只認 deploy 預設載入的這份、只寫這個 workspace `.vault/` 目錄裡的名冊,plan 不碰真實檔且與 apply 預覽相同的寫入、失敗的 apply 會一併 rollback、原子寫入)、未同步的名冊列在 banner 與 plan/apply 的 warnings、deploy/reconcile preflight 對不一致發 warning、nfs-server 的密碼一致性拆成不加 no_log、排在 stage gate 之後的獨立 gate;三者都指向唯一有效的修正:手動改名冊(pilot edit 只在密碼改變的那次存檔同步,再存不會補)。名冊不能改成 `{{ ipa_admin_password }}`:`pilot access`/`identity drift`/`roster remove-*` 只載入名冊。同一 PR 的 review 修正:§5.11 新增第 5 點,所有名冊 writer 改用 `lockRosterFile` 鎖 canonical 檔案(`secretpath.Canonical`),修掉 symlink 繞過鎖、migrate/remove 互不排斥、migrate 把 symlink 換成一般檔案、十幾個 writer 沒鎖的問題,新增全 package lint `TestRegression_RosterWritersLockCanonicalTarget`。Re-review 第二輪:lock 檔以 `O_NOFOLLOW` 開啟並對 fd chown(root 執行時不會截斷或 chown symlink 指向的檔案)、只能讀的 lock 檔照樣上鎖、打不開時回傳說明修法的 `ErrRosterLockFile`、不需寫入時不取鎖,`pilot edit` 對被持有的名冊顯示 banner 而不結束 session;名冊密碼只認 YAML 字串(沒加引號的數字跟 Ansible 一樣視為不一致);plan 透過被複製的 workspace 辨識名冊;apply rollback 只還原仍是本 session 寫入內容的名冊;guard 涵蓋 `os.OpenFile`/`os.Create` 寫入、method 與真正的 lock target,`ansible-vault edit` 執行期間持有名冊鎖。第三輪:自動化／MCP 遇到被持有或 lock 檔不能用的名冊時該步失敗並 rollback(MCP 回傳錯誤),終端機仍只顯示 banner;`ansible-vault edit` 的鎖只在 editor 執行期間持有;名冊寫入改為原子替換;lock 檔以 `O_NONBLOCK` 開啟;rollback 對同一檔案只還原一次、不把別人改過的名冊算成失敗;沒加引號、YAML 1.1 或 1.2 可能讀成非字串的密碼(名冊與 vault 兩邊)一律提示加引號,YAML 1.1 的判斷以 `make identity-secret-test` 對真實 Ansible loader 驗證。第四輪:名冊寫入只剩一套寫法 `writeLockedRoster`(拒寫不可寫的名冊;hard link、ACL、給不了擁有者時原地覆寫,否則同目錄暫存檔 rename;root 執行時新名冊與 migration 備份的擁有者正確;取鎖後清殘留暫存檔);密碼值的判斷收斂成 `ansibleScalarKind`(`!unsafe` 視為字串並在同步時保留,`vaultfile.Set` 寫入時改成字串 tag,沿用 vault 密碼建立名冊時不沿用模板、`!vault` 或非字串);vault 存檔改為 Prepare → 寫 vault → Commit,要跟著改的名冊被鎖住時整次存檔拒絕(每個入口一致,plan 以 `ProbeRosterWrite` 檢查真實名冊),`Run` 回傳 warnings、`--actions` 印到 stderr;plan/MCP apply 不寫 `.vault/` 以外的名冊(`errRosterOutsideEditScope`),plan 啟用 freeipa-nfs-server 時改寫複本並記錄真實路徑;busy lint 涵蓋所有綁定形式與 `cmd/pilot/cmd` 全部檔案;gateway 測試 harness 一併掃 stderr;新增 `make root-test` 與 CI job "Root-only ownership tests"。第五輪:plan/MCP apply 對 `.vault/` 以外的名冊先在副本上試做,只在真的要改時拒絕(啟用 freeipa-nfs-server 而外部名冊已有 `nfs.servers` 時不再失敗,與 main 相同);Prepare 與 plan 的探測(`ProbeRosterWrite`)檢查 `writeLockedRoster` 會拒絕的名冊(`openRosterForWrite`/`ErrRosterNotWritable`:不能寫、不是一般檔案、symlink),不能寫的名冊也讓存檔拒絕、plan 失敗;writer 碰到被持有的 lock 重試最多 250ms,plan 的探測不會害它失敗;暫存檔只在權限錯誤時改走原地覆寫;vault 舊值或新值是 inline `!vault`、舊值是模板時提示手動確認,preflight 一致。第六輪(獨立 review 對照 main 的回歸;兩條平行修正合併成同一套機制):`lockRosterFile` 在建立 lock 檔之前先確認能寫名冊(不能寫的不留 lock 檔),lock 檔以 `O_EXCL` 建立並依名冊的 group/other/ACL/擁有者給讀取權(既有的 `0600` 會補上);lock 檔任何非「被持有」的開啟/fstat/flock 失敗都是 `ErrRosterLockFile`(`EROFS` 跟 `EACCES` 一樣改以唯讀開啟既有 lock 檔),罕見的 open/flock/路徑解析錯誤以測試用的 `InjectFileFault` 注入(其他測試接縫見 §5.11 第 5 點);probe 與 writer 同順序(先名冊、再 lock 檔),dry-run migration 不取鎖;Prepare 只把讀取/判斷的錯誤(`ErrRosterNeedsHandEdit`)列為「未同步」,其他錯誤一律拒絕存檔(四個入口一致,以每個拒絕原因 × 入口的矩陣測試鎖住);換名遇 `EBUSY`/`EXDEV`/`EPERM`/`EACCES`(單一檔案 bind mount)改原地覆寫,原地變大前先 `fallocate`;暫存檔先 fchown、fchmod、比對延伸屬性才寫入內容,屬性不同(目錄 default ACL、SELinux label、`user.*`)改原地覆寫;跨行的 admin 密碼拒絕同步;plan 對相對路徑的 `freeipa_roster_file` 依真實 workspace 解讀,指進 `.vault/` 的 symlink 算 session 的檔案(寫法 × 名冊狀態 × 入口的矩陣測試),plan 的錯誤與 warnings 用真實路徑;含 secret 的暫存副本(plan 的暫存 workspace、試做副本、加密名冊解密後的明文)都放在 `secretpath.PrivateTempDir` 建的 pid 命名 `0700` 目錄(migration 的明文候選檔不在其中,仍是名冊旁的暫存檔),下次建立時清掉已結束 pilot 留下的;「請加引號」只看新存的值;`RemoveRosterFile` 刪 `lk.target`,guard 涵蓋刪檔、`renameRosterTemp`、`rosterLock` 字面值;已知限制:hard link 各自有 lock 檔、單一檔案 bind mount 的容器內外不互斥。第七輪:apply 的 rollback 不再以步驟前後的檔案差異推斷誰寫了名冊(別人在快照之後、session 寫入之前存的修改會被還原掉並回報成功),改由 `inventory.RosterJournal` 在 `writeLockedRoster` 記錄每次寫入前後的內容,rollback 只還原 session 自己的寫入蓋掉的內容,無法歸屬、寫入不成鏈或中途失敗的名冊留給人工檢查(§5.14 第 7 點),新增全 package lint `TestRegression_RosterBytesAreWrittenOnlyByWriteLockedRoster`;rollback 結果的 `After` 改為 rollback 後的實際狀態;寫入失敗時只有原地覆寫寫到一半可能改到名冊,錯誤包 `errRosterPartlyWritten`(journal 的 `Failed` 也以它判斷);schema 升級在建立備份之前拒絕不能寫的名冊(原本留下 `.bak` 並回報「rollback failed」),只在原地覆寫寫到一半時經 `writeLockedRoster` rollback(journal 一併記下);預查以讀到的內容判斷空檔;plan 讀子目錄裡 vars 檔的 `freeipa_roster_file`;plan 拒絕存 vault 時的錯誤與 banner 不再列出暫存複本的路徑;`freeipa_roster_file: ~/…` 展開 `~`(§5.11 第 1 點);`ansible-vault edit` 只對名冊取鎖;freeipa-nfs-server 的 no_log gate 訊息列出檢查條件,並註明 Ansible 無法展開的密碼值會在錯誤的 Origin 段落印出。第八輪(review of 3a4d4a3,兩個 P2、兩個 P3):(1) hard link 不再繞過鎖:`lockRosterFile` 在兩組 sidecar 之後,名冊有其他 hard link 時再 flock 名冊自己的 inode(`rosterLock.identity`;被持有 `ErrMutationLocked`、其他失敗 `ErrRosterLockFile`,`ProbeRosterWrite` 取 shared;只有一個名字的名冊不取;取鎖後才多出 hard link 的寫入被拒絕),新增 `inventory.RosterFileKey`(canonical path 或 `inode:<dev>:<ino>`)作為鎖、journal(記錄與 `ErrRosterJournalBusy`)、apply rollback 分組與 `rosterCandidates` 去重共用的唯一檔案身分,§5.11 第 5 點「已知限制」只剩 bind mount;(2) plan 的暫存複本保留 `.vault/` 名字之間的別名結構(複本內的相對 symlink),`.vault/ipa-identity.yaml` 與 `.vault/group-roster.yaml` 都連到 `.vault/actual.yaml` 時 plan 與 apply 的 `AffectedFiles`/diff/warnings 一致;(3) rollback 判斷哪些 `.vault/` 檔案是名冊只看執行前狀態與 journal,不看 session 留下的內容,plain 的 `main.yaml` 被加上 `groups` 等 key 不再被當成名冊(runbook §4.5「非名冊 `.vault/` 檔一律還原」因此成立),加密的非名冊檔留給人工但不印密碼提示;(4) apply 的 journal 在 rollback 前 `Stop`(不再記錄、保留 claim)、rollback 後才 `Close`,另一個 workspace 的 apply 在 rollback 期間註冊不進來(`workspace_locked`),不會把還原寫入記成自己的;第九輪(review of bb3d18e,P3):`PrivateTempDir` 清掃「已結束」的 pilot 時不再以 pid 判斷(別的 PID namespace 共用 `/tmp` 的 pilot 看不到 pid,刪掉還在用的 plan 暫存目錄,`label "nexus" not found` 的 flake):每個目錄有 `.pilot-alive` 標記檔,建立者持有它的 flock 直到結束,清理者只在拿得到鎖時刪(§5.14 第 5 點);沒有標記檔的舊目錄要超過 10 分鐘且 pid 不在自己的 namespace 才刪;`InjectFileFault` 與 `PrivateTempDir` 的涵蓋範圍改寫成實際範圍(§5.11 第 5 點);`RemoveRosterFile` 不經 journal,呼叫端要先 `Stop`/`Close` journal(§5.14 第 7 點)。實跑狀況:candidate `3b4bdb1` 曾對兩台全新 VM 實跑(`docs/evidence/freeipa-nfs-server/2026-10-28-3b4bdb1.md`),但之後併入的 Go 程式碼與 `freeipa-nfs-server-apply.yml` 的 gate 訊息文字都變了,合併後的樹沒有實機驗證過,只有本機單元與整合測試;依 §1.5 要對新的 candidate 重跑。第十輪(review of 374a7ca):(1) rollback 不再移除別的 process 在 apply 期間建立的名冊:快照沒有、journal 也沒記錄的 `.vault/` 檔案依現在的內容分類(加密、名冊 key 是 mapping/list、或 workspace 指定的名冊就保留並列入 warnings;在某一步執行期間出現的留給人工),只有 scalar-only 的新檔案才移除(§5.14 第 7 點);(2) `PrivateTempDir` 測試的 held-marker 計數不再依賴測試順序,sweep 測試涵蓋 marker 是 symlink/目錄/mode 0000/他人擁有的情況;(3) `ProbeRosterWrite` 的 inode 鎖不再用 write-only fd。以上只有本機單元與整合測試,沒有實機驗證 | pilot |
