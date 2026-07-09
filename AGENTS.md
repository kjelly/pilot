# AGENTS.md — pilot 工具 repo 對 AI agent 的硬規則

> **TL;DR** — 寫進 `docs/runbooks/*.md` 或 `docs/verification/*.md` 的每一條
> `bash` / `go run` / `ansible-playbook` 指令，**寫進文件前**必須在
> **對應的目標環境**（vm-target / docker-target / 本地 / 真實主機）實際跑過一次
> 並截到真實輸出。沒跑過的 SOP 是負債，不是文檔。
>
> 本檔的規則以「host / inventory」為核心，一律指**你這一步實際要執行的那份
> inventory**——不管它來自拋棄式測試 VM 還是真實主機。讀它的事實，不要照
> spec 設計意圖腦補（見 §0.1 的讀法對照）。

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

---

## 1. 寫「可執行的步驟」之前 — actual-run 規則

> **硬規則**：任何要寫進 `docs/runbooks/*.md` 或 `docs/verification/*.md` 步驟區塊
> 的指令，寫進文件前必須符合下面三件事，缺一不可。

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

### 1.2 把真實輸出貼進文件

不是「預期 PLAY RECAP: changed=8..12」，是**這次跑出來**的截錄：

```markdown
# 預期這次跑會看到：
PLAY RECAP *********************************************************************
core                       : ok=12  changed=8    unreachable=0    failed=0
```

如果跑了但失敗，把失敗也寫進去；下一個讀文件的人需要知道哪一步會壞。

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
2. 自動 snapshot（失敗會 auto-rollback 回 pre-test）
3. apply playbook（L4）
4. `pilot verify`（L5）
5. **再 apply 一次並斷言 `changed=0`**（L6 冪等）

playbook 需要的變數放在 `--` 之後，會**原封不動**轉給 apply 與冪等兩次 run
（`-e target_group=<g>` 時比照 `run`，自動放掉 `-l <name>` 限制）：

```bash
pilot vm-target test --name <vm> \
    --playbook playbooks/apply/<role>-apply.yml \
    --spec docs/verification/<role>.md \
    --verify-timeout 40 \
    -- -e target_group=all -e <var>=<val> -e @~/.vault/<secrets>.yaml
```

把它印出的 PLAY RECAP（兩次）+ verify verdict 貼進 spec §3 / runbook，就滿足 §1.2。

> 拿不準某條 checklist 的 expected 怎麼寫？先用 `pilot verify --probe '<cmd>'
> [--probe-expected '<v>'] -i <inv> -l <host>` 把候選指令丟進**與 verify 完全相同**的
> 管線，看它實際回的 rc / stdout / clean / verdict，再決定 expected 的寫法——不要用猜的。
> 三個 matcher 陷阱（反邏輯 grep、`^` 錨點、`~active`）見 `docs/verification-spec-template.md`，
> `pilot spec --lint` 也會對它們 warn。

---

## 2. 「事實快照」段是 runbook 的一部分

每份 `docs/runbooks/*.md` 在 §0 一句話目標之後、§1 為什麼之前，**必須有**
「事實快照」段（推薦編號 §0.5 或 §0.b），內容至少含：

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
> generated playbook 覆蓋每個 row、AAA/cross-row invariant）。範本見
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
| `playbooks/apply/*.yml` | 手寫的真實安裝/設定 playbook（含 snapshot→rollback 安全網） | **真實** |
| `playbooks/verify/*.yml` | `pilot spec --generate` 產的驗證 playbook（**勿手寫**） | **真實**（交付流程的驗收） |
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
  - `pilot spec --generate` 產的 verify playbook 已自動帶 tag，不用手補；手補的是
    `playbooks/apply/*.yml`。
- 改完後 `ansible-playbook --syntax-check` + `ansible-playbook --list-tags <file>`
  （確認 tag 齊全無撞號）+ 對目標環境（vm-target / docker-target；上真實主機前
  至少對一台 staging）跑一次 `--check --diff` 才能 commit。真實主機沒有
  snapshot→rollback 安全網，`--check --diff` 與 §4 開頭的 `block/rescue` 備份更不能省。

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

`playbooks/apply/*.yml` 現在**全部 20 支**都有 `stage`/`confirm_staging`/
`confirm_prod` gate,規則一致、沒有例外(`core-infra-provider`、
`freeipa-server`、`freeipa-client`、`freeipa-identity`、`freeipa-server-replica`、
`keycloak`、`keycloak-db`、`seaweedfs-s3`、`pam-oidc-sshd`、`log-server`、
`audit-log-forwarding`、`wazuh-manager`、`wazuh-fim`、`restic-backup`、
`os-patch-sla`(用 `patch_stage`)、`prometheus`、`thanos-query`、
`alertmanager`、`dashboard`、`log-shipping`)。`freeipa-server-replica` 與後五支
可觀測性堆疊一樣是**還沒接進 `site.yml`**(前者是刻意的:加 HA replica 是
day-2、opt-in 操作,不是每個部署都要的穩態角色,比照 `freeipa-identity` 的
待遇;後五支則是一開始清點時漏掉,2026-07-09 一併補齊)——**不要因為一支
playbook「還沒接進 site.yml」或「角色感覺不重要」就假設它可以不用 gate**,
新增任何 apply playbook 一律要帶。

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
   例外」。真的有理由不需要 gate 的 playbook(例如 `playbooks/verify/*.yml`
   這種純驗證、不 mutate 任何東西的),在檔頭註解寫清楚原因,不要沉默省略。

另外,`playbooks/site.yml` 開頭有一道獨立的安全閥(`hosts: localhost` 的
`assert target_group is not defined`),擋下「全站入口誤帶 `-e target_group=`
同時覆寫全部子 playbook 目標,讓『空 group 自動跳過』的保護失效」的事故——
這道閥**不要**移除或繞過。新增 import 進 `site.yml` 的 playbook,若它的
`hosts:` 也走 `target_group` 覆寫慣例,要確保它只在「單獨執行」時被 override,
不依賴 site.yml 幫忙擋。

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

### 5.5 三種輸出管道分清楚（error / 診斷 / 使用者 UX）

pilot 有三種輸出，**不要混用**：

1. **回傳的 error** — 主要控制流。用 `%w` 包裝往上回傳。**不要對同一個 error
   又 log 又 return**（log XOR return）；由最上層決定怎麼呈現。
2. **診斷（diagnostics）** — 「復原型」警告（"index 找不到，繼續"）、內部
   debug trace。一律走 **`log/slog`**（`slog.Warn/Debug/Error(msg, "key", val)`）。
   由 `internal/logx` 設定：分級（預設 WARN）、結構化 k/v、可被 `--log-level`
   /`$PILOT_LOG_LEVEL` 調整、TUI 啟動時自動改寫到 `pilot.log` 不污染畫面。
   **新的內部診斷寫 `slog`，不要再 `fmt.Fprintf(os.Stderr, "warning: …")`。**
3. **使用者 UX** — agent 的 LLM stream、提案、進度、結果（含 emoji 狀態行）。
   走 CLI writer（`cmd.OutOrStdout()`/`ErrOrStderr()`、`cfg.StreamWriter`）或
   TUI。這是產品介面,**不是 log**,不要塞進 slog（會被分級藏掉、破壞 UX）。

判斷：**使用者為了完成任務需要看到的 → UX；操作者 debug 時才需要的 → slog。**

---

## 6. 不要做的事

- ❌ 不要從「spec 設計意圖」推「inventory 應該有的 host」 — 從**你實際要執行的那份 inventory** 讀事實（vm-target：`show-inventory`；真實主機：`ansible-inventory -i <inv> --graph`，見 §0.1）
- ❌ 不要在 runbook 寫「預期 PASS 11/11」沒實際跑過 — 寫「這次跑 PASS 11/11，截錄如下」
- ❌ 不要把硬規則繞過（「這次特例」是滑坡的開始）
- ❌ 不要把密碼 / token 寫進 spec、playbook、runbook — 走 `-e @~/.vault/...yaml`
- ❌ 不要擅自縮寫、拼錯或發明新變數名稱（例如把 `keycloak_db_password` 寫成 `keyclack_db_passwd`），必須完全依據 Spec 與既有變數命名。
- ❌ 新增或移除會產生資料/設定檔的軟體角色時，不要漏改 `group_vars/restic-backup.example.yml` 的對應備份範例（見 §4.2）
- ❌ 新增/改 stage gate 時，不要只做「confirm 旗標」檢查而漏掉「host 的環境 group 是否與 stage 一致」的 cross-check（見 §4.3）——否則機器已歸類進 `staging`/`prod`，但指令忘了帶 `-e stage=`，會靜默用 `sandbox` 門檻套用
- ❌ 不要移除或繞過 `playbooks/site.yml` 開頭的 `target_group` 安全閥（見 §4.3）——它擋的是「全站入口誤帶 `-e target_group=` 同時覆寫全部子 playbook 目標」的事故


---

## 7. 變更紀錄

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
