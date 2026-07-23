# Verification Spec Template

> 給「把模糊需求落地成可驗證狀態」的標準格式。
> 每一個 row 對應 verify 的一個 check、apply playbook 的一個 step。

---

## 怎麼用這個檔案

1. 複製整份 → `docs/verification/<host-role>.md`
2. 把 `<...>` 佔位符替換成實際內容
3. 每一個 row 至少要明確寫出 **expected value**（不能寫「合理」「正常」這類模糊詞）
4. Command 欄位要可在目標主機一行 shell 跑完

---

## 模板

```markdown
# Verification Spec — <host role>

> 版本：<vX.Y>
> 對齊規範：<CIS Ubuntu 22.04 §X / STIG V-XXXX / 公司內規 / 客戶要求>
> 維護者：<owner>

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Hostname / Inventory group | |
| OS / version | |
| 角色 | |
| 套用範圍 | |
| 風險等級 | Low / Medium / High |


## 1.5 依賴變數契約

在套用或驗證此主機時，Playbook 與變數參數必須嚴格遵守以下命名，禁止擅自縮寫（如 password 改為 passwd）或發明新變數：

| 變數名稱 | 說明/用途 | 是否必填 |
|---------|----------|---------|
| `keycloak_db_password` | Keycloak 資料庫的密碼 | 是 |
| `keycloak_db_user` | Keycloak 資料庫連線使用者 | 是 |

## 2. Checklist

| ID  | Category | Check                          | Expected        | Command |
|-----|----------|--------------------------------|-----------------|---------|
| C1  | file     | /etc/ssh/sshd_config           | present         | test -f /etc/ssh/sshd_config |
| C2  | file     | PermitRootLogin no             | ^PermitRootLogin\s+no$ | grep -qE '^PermitRootLogin\s+no$' /etc/ssh/sshd_config |
| C3  | sysctl   | net.ipv4.ip_forward            | 0               | sysctl -n net.ipv4.ip_forward |
| C4  | service  | sshd.service                   | ~active         | systemctl is-active sshd |
| C5  | package  | fail2ban installed             | present         | dpkg -s fail2ban |
| ... |          |                                |                 | |

## 3. 證據收集

- 工具：`pilot verify docs/verification/<name>.md -i inv.yaml`
- 原始輸出：gitignored `.verification/<name>-<UTC>.{ndjson,md}` 或 pilot evidence store
- Sanitized 摘要：`docs/evidence/<name>/<date>-<tested-revision>.md`
- 本節只保留最新 tested revision/tree、真實 verdict 與摘要連結，不貼完整 transcript
- Row 數：N（等於 checklist row 數）

## 4. PASS / FAIL 規則

- 全部 row `status=pass` 或 `status=skip`（且 skip 有正當理由）→ **PASS**
- 任一 row `status=fail` → **FAIL**，列出 fail id + actual + want

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C2 | dev 環境允許 PermitRootLogin yes | dev | 無 |

## 6. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-06-30 | v1.0 | 初版 | alice |
```

---

## Expected 值的語法（必讀！）

`pilot verify` 用 `matchExpected` 比對，這是 v1 grammar：

| Expected 寫法 | 怎麼比對 | 範例 |
|---------------|---------|------|
| `0` / `1` 等純數字 | 比對 exit code；runner 會自動從 `echo $?` 抓 rc | `0`（exit code = 0）|
| `present` | 退出碼 0 即通過 | 檔案存在檢查 |
| `~running` | stdout **包含** substring（前面加 `~`） | `~running`、`~host/` |
| `^OK provider=...` | anchored regex（從 `^` 開頭） | `^OK provider=kc-ssh-pam` |
| 其他字串 | stdout 與 expected **完全相等**（去除 `(rc=N) ` 前綴） | `OK` / 任意固定字串 |

> **不要寫** `OK` / `正常` / `合理` / `足夠` — 這些詞會被 lint 攔下。

### 三個實測踩過的陷阱（`pilot spec --lint` 會 warn）

`pilot verify` 對 inventory 是走 **ansible ad-hoc**（`ansible <host> -m command/shell -a "<cmd>"`），
輸出長這樣：`host | CHANGED | rc=0 >> <stdout>`。這個 wrapper + ad-hoc 的退出碼語意，
造成三個「lint 過、但 verify 行為不如預期」的坑：

1. **反邏輯 grep + 數字 expected**（例 `... | grep -q STOPPED` expected `1`）：健康時 grep 找不到
   → 管線 rc=1 → ansible 把整個 task 判為 **FAILED**、回自己的 **rc=2**（不是管線的 1），expected `1`
   永遠對不上。**改用正邏輯**：直接斷言健康字串，或讓指令健康時自身回 0（expected `0`）。

2. **`^…$` anchored regex**：比對對象 `clean` 只有去掉 `(rc=N)` 前綴，**仍保留** `host | CHANGED | rc=0 >>`
   這段 wrapper，所以 `^` 錨點會對到 wrapper 而不是 stdout —— 只有 `--local`（無 ansible）時才有效。
   對 inventory 驗證請改用 **`~<substring>`**。

3. **`~active` 會誤命中 `inactive`**：`active` 是 `inactive` 的子字串，服務停掉也會 PASS。
   **服務健康檢查改用數字 rc**：`systemctl is-active <svc>` expected `0`（active 才回 0）。

### 第四個陷阱：長時間 probe 的 timeout 沒寫進規格

`pilot verify` 的 per-row command timeout **預設只有 15 秒**（`--timeout` 旗標，
見 `cmd/pilot/cmd/verify.go`）。任何 checklist row 的 command 本身就需要等待
（lock 重試、完整性掃描、跨主機共用 repository 的並行 probe……），只要
「command 自己的等待上限」大於這 15 秒，第一次 `pilot verify` 幾乎必定在真正
探測完成前就被中止、回報無意義的 timeout fail，逼作者重跑一次才抓到真正的
結果——白白浪費一輪。

**寫規格時要做的事，不要等踩到才補**：

1. 如果 command 本身有重試/等待旗標（例如 `restic check --retry-lock 120s`），
   在 Check 說明或表格下方的備註寫清楚這個內建等待上限是多少。
2. 在 §3 證據收集直接把對應的 `pilot verify --timeout <N>` 寫進工具指令裡，
   `N` 要包含 command 自身等待上限 + 合理緩衝（不要抓剛好；剛好等於 command
   等待上限，會在 ansible wrapper 本身的往返延遲上再度踩線）。
3. 不要留給操作者「跑失敗了再自己加 `--timeout`」——那正是失敗一輪才發現
   的重跑成本，規格寫清楚就能一次過。

範例見 `docs/verification/restic-backup.md` C6（`restic check --retry-lock
120s`）與 §3（`pilot verify … --timeout 180`）：120 秒的 lock 等待上限 + 一段
緩衝，取整為 180 秒的 verify timeout。

### 拿不準 expected 怎麼寫？用 `--probe` 先探

不要靠猜。把候選指令丟進**與 verify 完全相同**的管線，看它實際回什麼：

```bash
# 對 vm-target（先取 inventory）：
pilot vm-target show-inventory --name <vm> > /tmp/inv.yaml
pilot verify --probe 'sudo -l -U pilotuser' --probe-expected '~(root) ALL' \
    -i /tmp/inv.yaml -l <vm>
# 會印出 module/become、rc、raw stdout、clean（matcher 實際比對的字串）、以及 verdict
```

`--probe` 不寫任何 report / store，純粹讓你「看到 verify 看到的」再決定 expected 的寫法。

Command 欄位的注意事項：

- 含 `|`、`&&`、`||`、`;`、`>`、`<` 的 shell pipeline，verify 工具會自動改用 `ansible.builtin.shell`，不必改用 `command` module
- 含 `|` 的 command 因為 markdown 表格 cell 分隔，需要 **多寫幾個 column**：

  | 寫法 | 視覺上像 |
  |------|---------|
  | 不要這樣 | `\| C1 \| pkg \| check \| 0 \| apt list \| grep security \|` |
  | 不要這樣 | `\| C1 \| pkg \| check \| 0 \| apt list --upgradable \| grep security \|` |
  | 對 | `\| C1 \| pkg \| check \| 0 \| apt list --upgradable \| grep security \| wc -l \|` |

  parser 會自動把 `\| wc -l` 接回 Command，所以 `apt list ... | grep security | wc -l` 會被當成一個完整 pipeline 傳給 ansible。

---

## 撰寫 Checklist（給 spec 作者）

- [ ] 每個 row 的 **expected** 都是可判定值
- [ ] 每個 row 的 **command** 在目標主機上可單獨跑出結果
- [ ] ID 連號 `C1` / `C2` / `C3` ... 不跳號
- [ ] 涉及檔案權限的 row 寫出數字（`0644`）而非文字（`644` 或 `0o644`）
- [ ] 涉及 service 的 row 用 `systemctl is-active <svc>` + expected `0`（**不要**用 `~active`，會誤命中 `inactive`）
- [ ] 涉及 sysctl 的 row 寫出字串型 expected（`sysctl -n` 永遠回字串）
- [ ] 任一 row 的 command 本身等待上限超過 15 秒（`pilot verify` 預設 timeout），
      §3 證據收集的工具指令要帶對應的 `pilot verify --timeout <N>`（見「第四個
      陷阱：長時間 probe 的 timeout 沒寫進規格」）
- [ ] 例外有寫清楚「適用環境」跟「為什麼」
- [ ] 有版本號跟變更紀錄

---

## 對應的 apply playbook 約定

Spec-driven 工作流把 **inspect 跟 mutate 分開**：

| 檔 | 誰寫 | 用什麼跑 |
|----|------|---------|
| `docs/verification/<name>.md`（這份） | 你 | `pilot spec --lint` 把關；驗收直接 `pilot verify <本檔> -i <inventory>` |
| `playbooks/apply/<name>-apply.yml` | **你手寫**，但有結構 | `ansible-playbook … apply.yml -e key=value` |

> **不要**再為 spec 產生 `playbooks/verify/<name>.yml`——該目錄已於
> 2026-07-17 棄用（generator 產物不比對 Expected、部分 pattern 會 mutate，
> 見 `playbooks/verify/README.md`）。inspect 由 `pilot verify` 直接吃這份
> spec 執行，單列調參用 `pilot verify --probe`。

**Apply playbook 必須做的 3 件事**：

1. **可參數化**：所有 host-specific 值走 `-e kc_ssh_pam_deb=… -e keycloak_issuer=…`，
   不要 hard-code 套用到哪個 host
2. **`block/rescue` 包起來**：把 snapshot → mutate → verify 包成一個區塊；
   任何 mutate 失敗 rescue 自動還原 `/etc/pam.d/sshd` 或類似關鍵檔案
3. **`pre_tasks: assert:` 寫 gate**：例如套用到 prod 必須先確認 staging 通過過、
   帶 explicit confirm flag，不能靠「跑的人自己記得」

完整示範見 [`playbooks/apply/pam-oidc-sshd-apply.yml`](./playbooks/apply/pam-oidc-sshd-apply.yml)
與 [`playbooks/apply/os-patch-sla-apply.yml`](./playbooks/apply/os-patch-sla-apply.yml)。

範例 spec：

- [`docs/verification/hello-localhost.md`](./docs/verification/hello-localhost.md)：最簡單，
  3 rows；用來熟悉 generator / verify 流程
- [`docs/verification/pam-oidc-sshd.md`](./docs/verification/pam-oidc-sshd.md)：7 rows，
  PAM OIDC / Keycloak Device Flow；lockout-safety 範例
- [`docs/verification/os-patch-sla.md`](./docs/verification/os-patch-sla.md)：7 rows，
  OS 套件 SLA；stage-gating 範例

---

## 範例：完整 spec（bastion 主機）

```markdown
# Verification Spec — bastion-host (CIS-aligned)

> 版本：v1.0
> 對齊規範：CIS Ubuntu 22.04 Level 1 §5.2.x
> 維護者：infra-team

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Inventory group | bastion |
| OS | Ubuntu 22.04 LTS |
| 角色 | SSH jump host |
| 套用範圍 | 所有 bastion 主機 |
| 風險等級 | High |

## 2. Checklist

| ID  | Category | Check                                | Expected        | Command |
|-----|----------|--------------------------------------|-----------------|---------|
| C1  | file     | /etc/ssh/sshd_config                 | present         | test -f /etc/ssh/sshd_config |
| C2  | file     | PermitRootLogin no                   | ^PermitRootLogin\s+no$   | grep -qE '^PermitRootLogin\s+no$' /etc/ssh/sshd_config |
| C3  | file     | PasswordAuthentication no            | ^PasswordAuthentication\s+no$ | grep -qE '^PasswordAuthentication\s+no$' /etc/ssh/sshd_config |
| C4  | sysctl   | net.ipv4.ip_forward                  | 0               | sysctl -n net.ipv4.ip_forward |
| C5  | sysctl   | kernel.randomize_va_space            | 2               | sysctl -n kernel.randomize_va_space |
| C6  | service  | sshd.service state                   | ~active         | systemctl is-active sshd |
| C7  | service  | fail2ban.service state               | ~active         | systemctl is-active fail2ban |
| C8  | port     | 22/tcp listening                     | present         | ss -tln 'sport = :22' |
| C9  | user     | UID 0 帳號只允許 root                | 1               | getent passwd 0 | wc -l |
| C10 | file     | /etc/passwd 權限                     | 0               | stat -c '%a' /etc/passwd | tr -d ' ' |
| C11 | file     | /etc/shadow 權限                     | 0               | stat -c '%a' /etc/shadow | tr -d ' ' |
| C12 | package  | unattended-upgrades installed        | present         | dpkg -s unattended-upgrades |

## 3. 證據收集

- 工具：`pilot verify docs/verification/bastion-host.md -i inv.yaml`
- 原始輸出：gitignored `.verification/bastion-host-<UTC>.{ndjson,md}`
- Sanitized 摘要：`docs/evidence/bastion-host/<date>-<tested-revision>.md`
- Spec 只保留最新 revision/tree、真實 verdict 與摘要連結，不累積完整 transcript
- Row 數：12

## 4. PASS / FAIL 規則

- 全部 pass 或 skip（skip 須有理由）→ PASS
- 任一 fail → FAIL，輸出 fail rows 表格

## 5. 例外

| ID | 例外 | 環境 | 期限 |
|----|------|------|------|
| C2 | dev 環境允許 PermitRootLogin yes | dev | 無 |

## 6. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-06-30 | v1.0 | 初版 | infra-team |
```
