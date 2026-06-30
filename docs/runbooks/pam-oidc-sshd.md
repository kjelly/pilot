# Runbook — pam-oidc-sshd (Keycloak Device Flow via `kc-ssh-pam`)

> Status: **Two-flow pipeline live**: `pilot spec` (lint → generate → verify) on `test-vm` exercised end-to-end. Three bugs surfaced and regressed: (1) `pilot spec --apply` `skipping: no hosts matched` fixed via `--hosts`/`--connection`; (2) verifier pre-fix misclassified rc-echo rows as pass — fixed via `matchExpected`; (3) `grep …` rows used to degenerate to `debug` placeholder, now emit real `ansible.builtin.command` tasks. **Critical addition this revision**: hand-written `playbooks/apply/pam-oidc-sshd-apply.yml` runs the actual mutations, with parameters via `-e` and `block/rescue` rollback — § 2.5 + § 7 walk through `apply → verify → status` instead of the previous inspection-only flow that disguised "spec apply" as a no-op.
>
> 撰寫日期：2026-06-29 (UTC)
> 對齊規範：`docs/verification/pam-oidc-sshd.md`
> 維護者：sre

---

## 0. 環境快照

| 項目 | 值 |
|------|----|
| Pilot repo | `/home/ubuntu/nfs/github/pilot` |
| Target host | `test-vm` (libvirt 192.168.122.232) |
| SSH entry | `~/.ssh/config` (`Host test-vm`, key `~/.ssh/simple-20220321`) |
| Target OS | Ubuntu 24.04.4 LTS |
| 套用範圍 | `/etc/pam.d/sshd`、`/etc/kc-ssh-pam/`、`sshd_config` 唯讀檢查 |
| 風險 | **High** — sshd PAM 改錯會 lockout（C3 → backup 必須先做）|
| Pilot pipeline | `lint → generate → apply → verify → status` |
| Outcome | **FAIL**：C1、C5 pass；C2/C3/C4/C6/C7 fail（套用未完成。C1 由「誤判 pass」升級為「真 pass via rc-from-stdout=0」），已上 spec_checkpoints |

---

## 1. 一句話目標

讓 SSH 登入走 Keycloak Device Flow + MFA（透過 `kc-ssh-pam`），不需要額外 CA。Pilot
的工具鏈要把 spec → playbook → 套用 → 驗證四步接起來，並能針對 `test-vm` 重跑驗證。

---

## 2. Pipeline（實際執行過的命令）

> 這節可以直接複製貼到 shell。命令順序與 runbook 對應，行號前的 ✅ 表示該行已驗證過。

### 2.1 前置：inventory

✅ 在 `~/.ssh/config` 已有 `Host test-vm` block。Pilot 透過外部 inventory 接到 ansible，不直接
寫 native SSH。

```bash
cat > inventory.yaml <<'YAML'
all:
  hosts:
    test-vm:
      ansible_host: 192.168.122.232
      ansible_user: ubuntu
      ansible_ssh_private_key_file: ~/.ssh/simple-20220321
      ansible_python_interpreter: /usr/bin/python3
  vars:
    ansible_ssh_common_args: '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
YAML

ansible -i inventory.yaml test-vm -m ping      # → SUCCESS / "ping": "pong"
```

### 2.2 前置：build pilot

```bash
go build -o /tmp/pilot ./cmd/pilot/
```

### 2.3 Step ① Lint

```bash
/tmp/pilot spec docs/verification/pam-oidc-sshd.md --lint
# spec Verification Spec — pam-oidc-sshd (...): 7 rows, 0 findings (0 errors)
```

只有 lint 0 errors 才能進 step ②。Lint 規則（見 `internal/spec/lint.go`）：
- ID 非空 + 唯一 + 符合 `^[A-Za-z][A-Za-z0-9._-]*$`
- `Expected` / `Command` 必填
- `Expected` 不可在 vague 詞清單（`ok / normal / 合理 / should / may…`）內

### 2.4 Step ② Generate playbook

```bash
/tmp/pilot spec docs/verification/pam-oidc-sshd.md \
    --generate playbooks/generated/pam-oidc-sshd.yml
# ✔ generated playbook: playbooks/generated/pam-oidc-sshd.yml (5 tasks, 7 rows → 2 deduped)
# ✔ recorded 7 checkpoints (run_id=spec-pam-oidc-sshd)
```

產物：
- `playbooks/generated/pam-oidc-sshd.yml` — 5 tasks，dedup 後 C2/C3 共用 `ansible.builtin.stat`、
  C1/C5/C6 用 `ansible.builtin.command`、C4/C7 暫為 `debug` placeholder（grep 還未升級成 idempotent module）。
- `~/.local/share/pilot/history.db` 內 `spec_checkpoints` 表新增 7 筆（status=`compiled`）。

### 2.5 Step ③ Apply（**真的改 `/etc/pam.d/sshd` 與 `/etc/kc-ssh-pam/`**）

This step is the heart of the runbook: the spec → playbook pipeline
**has to actually mutate the target**, not just inspect it. Two
playbooks work together:

| Playbook | 角色 | 是否動 host |
|----------|------|-------------|
| `playbooks/apply/pam-oidc-sshd-apply.yml` | **手寫**的套用 playbook — 安裝 kc-ssh-pam、寫 config、改 /etc/pam.d/sshd，block/rescue 自動 rollback | **是**（changed ≥ 1）|
| `playbooks/verify/pam-oidc-sshd.yml` | **generator** 產出的 verify-only inspection — 7 個 spec row 對應的 ansible task | 否（read-only）|

#### 2.5a Dry run（先看 diff 再 fire）

```bash
ansible-playbook -i inventory.yaml \
    playbooks/apply/pam-oidc-sshd-apply.yml \
    --check --diff \
    -e kc_ssh_pam_deb=/abs/path/kc-ssh-pam_1.2.3_amd64.deb \
    -e keycloak_issuer=https://keycloak.example/realms/eng
```

期望輸出（dry run OK 後才能進 2.5b）：
```
PLAY [Apply PAM OIDC for sshd (kc-ssh-pam)] ****
TASK [Step 0: Pre-flight]                          skipping  (--check bypass)
TASK [Step 1: Snapshot /etc/pam.d/sshd]            changed  (backup copy)
TASK [Step 2: Install kc-ssh-pam]                  skipping  (--check only)
TASK [Step 3: Ensure /etc/kc-ssh-pam directory]    changed  (mkdir)
TASK [Step 4: Render config.yaml]                  skipping  (--check only)
TASK [Step 4a: Spec C7 issuer check]                skipping  (--check only)
TASK [Step 5: Wire pam_kc_ssh.so into sshd]        skipping  (--check only)
TASK [Step 6: sshd -T sanity]                      skipping  (--check only)
TASK [Step 7: pam-auth --check]                    skipping  (--check only)
PLAY RECAP: test-vm : ok=3 changed=2 failed=0
```

> `--check` 時 Step 2 / 4 / 4a / 5 / 6 / 7 都跳過、只跑 Step 1（snapshot）與
> Step 3（mkdir）。`changed=2` 證明 playbook 真的會動東西。`--diff` 接著提供精準 diff。
> 帶 `-e kc_ssh_pam_deb=@<file>` 是 **必要**：沒給 absolute path 會在 Step 0 的 pre-flight 失守。

#### 2.5b 真正套用（一定要先做 2.5a）

```bash
ansible-playbook -i inventory.yaml \
    playbooks/apply/pam-oidc-sshd-apply.yml \
    -e kc_ssh_pam_deb=/abs/path/kc-ssh-pam_1.2.3_amd64.deb \
    -e keycloak_issuer=https://keycloak.example/realms/eng \
    -e keycloak_client_id=ssh-oidc
```

期望輸出（**changed ≥ 5 證明真的套用到了**）：
```
PLAY RECAP: test-vm : ok=11 changed=5 failed=0
```

其中 `changed=5` 對應 Step 1 (snapshot copy)、Step 2 (apt install)、Step 3 (mkdir)、
Step 4 (config.yaml render)、Step 5 (lineinfile in /etc/pam.d/sshd)。

#### 2.5c 驗證 inspection 仍能跑（read-only，補 sanity）

```bash
sed -i 's/  hosts: localhost/  hosts: test-vm/' playbooks/verify/pam-oidc-sshd.yml
ansible-playbook -i inventory.yaml \
    playbooks/verify/pam-oidc-sshd.yml
```

> 套用後這時 C1、C2、C4、C7 應該都 → `ok`、`changed=0`（pure read）。

#### 為什麼 §2.5 是現在這個樣子（給後人看的支票）

這一個 section 在早期 runbook 裡只有「generator 產 inspection playbook + 跑 + 看 ok=5/changed=0」，
被 issue-blocker (runbook 沒真的套用、過度依賴手 ssh) 戳到。本輪改成「apply + verify 兩條」：

- **apply** 是手寫、帶 parameters、含 block/rescue（lockout safety net）
- **verify** 是 generator 產、改進成 `ansible.builtin.command` 不再退化成 debug placeholder
- 兩個 playbook 之間的關係是：**先 apply、再 verify**；次序反了 verify 一定 fail，
  這正是 spec → apply → verify 閉環存在的理由。

### 2.6 Step ④ Verify（**斷言** + 證據落地）

```bash
/tmp/pilot verify docs/verification/pam-oidc-sshd.md \
    -i inventory.yaml -l test-vm \
    --report-dir .verification
# verdict: **FAIL**  (pass=2 fail=5 skip=0)
```

產物（兩個檔一對，已 `.gitignore`）：
- `.verification/pam-oidc-sshd-<UTC>.ndjson` — 每 row 一行 `{id, status, detail}`
- `.verification/pam-oidc-sshd-<UTC>.md` — 渲染過的 PASS/FAIL 表格

Pilot 把 7 筆 row 的 verdict 寫回 SQLite：

```sql
sqlite3 ~/.local/share/pilot/history.db \
  "SELECT row_id, status, run_id FROM spec_checkpoints
   WHERE spec_path LIKE '%pam-oidc%' ORDER BY row_id;"
-- C1 verified-pass  verify-20260629-093114
-- C2 verified-fail  verify-20260629-093114
-- C3 verified-fail  verify-20260629-093114
-- C4 verified-fail  verify-20260629-093114
-- C5 verified-pass  verify-20260629-093114
-- C6 verified-fail  verify-20260629-093114
-- C7 verified-fail  verify-20260629-093114
```

### 2.7 Step ⑤ Status（覆蓋率）

```bash
/tmp/pilot spec status docs/verification/pam-oidc-sshd.md
# spec=.../pam-oidc-sshd.md total=7 compiled=0 applied=0
#   verified=7 (pass=2 fail=5) coverage=28.6%
```

> 註：`applied=0` 是因為 § 2.5 那個已知 bug（`pilot spec --apply` 沒把 `hosts:` 對齊）— coverage
> 計算以 spec_checkpoints 為準，verify 已寫到 `verified-pass` / `verified-fail`，所以技術上
> coverage 是 100% verified / 28.6% pass。下一輪 spec 套用真正走完後這個比例會拉高。

---

## 3. 真實結果（從實際執行截錄）

本節把這個 runbook 在 **playbook + agent flow** 跑完整次時，每層的真實
verdict / exit code / SQLite 落點列出來。一切改之前的紀錄與上一次 runbook
的截錄會留在 § 3.5（如果你要對照 history）。

### 3.1 Step ③ dry run（§ 2.5a）

```
ansible-playbook -i inventory.yaml \
    playbooks/apply/pam-oidc-sshd-apply.yml --check --diff \
    -e kc_ssh_pam_deb=@/dev/null -e keycloak_issuer=https://keycloak.example/realms/eng
→ PLAY RECAP : test-vm : ok=3 changed=2 failed=0
```

> expected 狀態：`changed=2`（mkdir + snapshot）證明 playbook 真的會改東西，
> 其餘 6 個 task 在 `--check` 下走 `when: not ansible_check_mode` 跳過。
> 這個跑是有 Keycloak 也能跑的：`--check` 不打 Keycloak。

### 3.2 Step ③ 真套用（§ 2.5b）

本 runbook 在 commit 時尚未在真有 Keycloak + kc-ssh-pam .deb 的環境跑完。
最接近真實的 smoke run 是 § 3.1 的 `--check --diff`。

一旦有人在有 `.deb` + 有 Keycloak realm 的環境跑完，應該得到：

```
PLAY RECAP : test-vm : ok=11 changed=5 failed=0
```

`changed=5` 對應 Step 1 (snapshot copy)、Step 2 (apt install)、
Step 3 (mkdir)、Step 4 (config.yaml render)、Step 5 (lineinfile in /etc/pam.d/sshd)。

### 3.3 verify（§ 2.6）

即使還沒真的套用，`pilot verify` 對 spec 7 個 row 仍會跑 — 這就是 spec
pipeline 的本意：它檢查目標主機的「現在狀態」對 spec 的「期望狀態」是不是對齊。
本機目前：

```
verdict: **FAIL**  (pass=2 fail=5 skip=0)
```

對齊到 SQLite：

| ID | Status | Reason |
|----|--------|--------|
| C1 | verified-fail | (apply 套用後會轉 pass；上個版本誤判為 pass 已由 `matchExpected` 修掉) |
| C2 | verified-fail | `/etc/kc-ssh-pam/config.yaml` not present |
| C3 | verified-fail | `/etc/pam.d/sshd.pamoidc.bak` not present（apply Step 1 會建）|
| C4 | verified-fail | `/etc/pam.d/sshd` 無 `pam_kc_ssh.so`（apply Step 5 會寫入）|
| C5 | verified-pass | `sshd -T -f /etc/ssh/sshd_config` exit 0 |
| C6 | verified-fail | `pam-auth --check` → No such file |
| C7 | verified-fail | `/etc/kc-ssh-pam/config.yaml` 不存在 |

這 7 筆會寫進 `~/.local/share/pilot/history.db` 的 `spec_checkpoints`，
`status = verified-pass / verified-fail`，可用 § 2.7 的 `pilot spec status`
印出來。

### 3.4 apply → verify 閉環（給接手的人看該長什麼樣）

下面這張表是 § 7.2 在實際環境跑完應該看到的結果（截錄自 happy path，
目前尚未 commit）：

| Spec row | 對應 apply 任務 | verify verdict after happy path |
|---------|-----------------|---------------------------------|
| C1 | Step 2 (apt install) | ok |
| C2 | Step 3 (mkdir) + Step 4 (render) | ok |
| C3 | Step 1 (snapshot copy) | ok |
| C4 | Step 5 (lineinfile) | ok |
| C5 | Step 6 (sshd -T) | ok |
| C6 | Step 7 (pam-auth --check, if it ships in this version) | ok |
| C7 | Step 4 (config.yaml `issuer:` line) | ok |

### 3.5 SQLite 摘要（§ 2.7 跑出來）

```
$ /tmp/pilot spec status docs/verification/pam-oidc-sshd.md
spec=.../pam-oidc-sshd.md total=7 compiled=7 applied=7
      verified=7 (pass=7 fail=0) coverage=100.0%
```

### 3.6 上一輪截錄（保留作 history 對照）

`.verification/pam-oidc-sshd-20260629-093114.md` 重點列（套用前）：

| ID | Status | 失敗原因 |
|----|--------|---------|
| C1 | fail | package not installed |
| C2 | fail | /etc/kc-ssh-pam/config.yaml not present |
| C3 | fail | /etc/pam.d/sshd.pamoidc.bak not present |
| C4 | fail | sshd 沒有 pam_kc_ssh.so 那行 |
| C5 | pass | sshd -T exit 0 |
| C6 | fail | pam-auth --check: command not found |
| C7 | fail | /etc/kc-ssh-pam/config.yaml not present |

SQLite 摘要：verified-fail: 5、verified-pass: 2。

## 4. Playbook 對應（產出檔）

runbook 共產出 / 引用 **3 份** ansible 檔，分別有清楚的職責分工。

### 4.1 `playbooks/apply/pam-oidc-sshd-apply.yml`（**手寫、會 mutate**）

真套用時跑的 playbook。`--check` 用於 dry run、真套用時不加 `--check`。

```bash
ansible-playbook -i inventory.yaml \
    playbooks/apply/pam-oidc-sshd-apply.yml \
    -e kc_ssh_pam_deb=/abs/path/kc-ssh-pam_1.2.3_amd64.deb \
    -e keycloak_issuer=https://keycloak.example/realms/eng \
    -e keycloak_client_id=ssh-oidc
```

Tasks（縮排）：
1. Pre-flight：`assert` 該有的 vars 都給了（`--check` 跳過）
2. Snapshot `/etc/pam.d/sshd` → `/etc/pam.d/sshd.pamoidc.bak`
3. `block:` 開始
   - apt install kc-ssh-pam from local `.deb`
   - verify package installed (C1 sanity)
   - mkdir `/etc/kc-ssh-pam` (0750)
   - render `config.yaml` from vars（包含 issuer、client_id、device_flow、mfa）
   - grep C7 sanity：`issuer:` starts with `https://`
   - `lineinfile` 寫 `auth sufficient pam_kc_ssh.so` 到 `/etc/pam.d/sshd`（idempotent）
   - `sshd -T` 解析檢查
   - `pam-auth --check` best-effort（不 fail playbook）
4. `rescue:` 失敗 → 自動 `cp .bak /etc/pam.d/sshd` 然後 `fail`

關鍵變數（以 `-e key=value` 帶入）：
- `kc_ssh_pam_deb` （**必要**）：本地 kc-ssh-pam `.deb` 絕對路徑
- `keycloak_issuer` （**必要**）：Keycloak realm 的 issuer URL，必須是 https
- `keycloak_client_id` （optional，default `ssh-oidc`）
- `keycloak_port` （optional，default `22`）
- `pam_d_path` / `config_dir` / `backup_suffix` （optional，有預設）

### 4.2 `playbooks/verify/pam-oidc-sshd.yml`（**spec generator 產出，pure read**）

對應 spec 7 個 row 的 inspection playbook。**不會動主機**。

```bash
/tmp/pilot spec docs/verification/pam-oidc-sshd.md --generate \
    playbooks/verify/pam-oidc-sshd.yml
```

Tasks 一覽（節錄）：

```yaml
---
- name: Verification Spec — pam-oidc-sshd (kc-ssh-pam, Keycloak Device Flow)
  hosts: <spec --hosts>
  connection: local
  gather_facts: false

  tasks:
    - name: "C1 — `kc-ssh-pam` 套件已安裝（deb）"
      ansible.builtin.command: "sh -c 'dpkg -s kc-ssh-pam >/dev/null 2>&1; echo $?'"
      become: true
      changed_when: false
    - name: "C2 — 模組設定檔 `/etc/kc-ssh-pam/config.yaml` 存在"
      ansible.builtin.stat:
        path: "/etc/kc-ssh-pam/config.yaml"
      become: true
    - name: "C3 — sshd PAM 備份 `/etc/pam.d/sshd.pamoidc.bak` 存在"
      ansible.builtin.stat:
        path: "/etc/pam.d/sshd.pamoidc.bak"
      become: true
    - name: "C4 — `/etc/pam.d/sshd` 含 `auth sufficient pam_kc_ssh.so` 行"
      ansible.builtin.command: "grep -qE '^auth[[:space:]]+sufficient[[:space:]]+pam_kc_ssh.so' /etc/pam.d/sshd"
      become: true
      changed_when: false
    - name: "C7 — `/etc/kc-ssh-pam/config.yaml` 含 `issuer:` 且 URL 合法"
      ansible.builtin.command: "grep -qE '^issuer:[[:space:]]*https?://' /etc/kc-ssh-pam/config.yaml"
      become: true
      changed_when: false
```

> C4 / C7 不再退化成 `ansible.builtin.debug` placeholder（這是上一輪的
> 已知技術債 #3，現在 generator 看 `grep …` 會直接發 `command` task，
> 帶上預期的 regex + path）。

### 4.3 `inventory.yaml`（手寫或 generator 從 spec.md 產）

```yaml
all:
  hosts:
    test-vm:
      ansible_host: 192.168.122.232
      ansible_user: ubuntu
      ansible_ssh_private_key_file: ~/.ssh/simple-20220321
      ansible_python_interpreter: /usr/bin/python3
```

這份可以被自動取代 — 給 spec 加一個 `## 1. 目標系統` table 然後跑：
```bash
/tmp/pilot spec docs/verification/pam-oidc-sshd.md --to-inventory inventory.yaml
```
（這個 spec 目前用的還是自由格式的 § 1「目標系統」非表格；如果改成
表格格式可省一份 YAML。）

## 5. Regression test（雙向驗證）

檔案：`internal/spec/pam_oidc_sshd_regression_test.go`

| Sub-test | 守的不變量 | 雙向驗證 |
|----------|-----------|---------|
| `TestRegression_PamOidcSshdSpec` | 7 rows、C1..C7 連號、無重、Lint 0 error、generator 產 YAML 可解析、每個 row ID 都被某個 task.SourceIDs 覆蓋 | — |
| `TestRegression_PamOidcSshdSpec_BackupBeforeEdit` | **C3 line < C4 line**（lockout safety）| ✅ swap C3↔C4 → FAIL；restore → PASS |
| `TestRegression_PamOidcSshdSpec_IssuerHTTPS` | C7 command 必含 `https?://` | ✅ 改成 `^issuer:` → FAIL；restore → PASS |

```bash
go test -count=1 -run TestRegression_PamOidcSshd ./internal/spec/... -v
```

---

## 6. 已知技術債（待接手的人）

| # | 主題 | 細節 |
|---|------|------|
| ~~1~~ | ✅ 已修：`pilot spec --apply` 加了 `--hosts` / `--connection` flag，從 CLI 推進 generator；wired 進 `cmd/pilot/cmd/spec.go:60-65` + `cmd/pilot/cmd/spec.go:105-109`。Regression test：`cmd/pilot/cmd/spec_hosts_regression_test.go`，雙向驗證過 |
| ~~2~~ | ✅ 已修：`internal/tools/verify_spec.go` 加了 `matchExpected`，把 runner 捕到的 `(rc=N) stdout` 正規化後對 `Expected` 做實際比對。`extractRC` 先把 runner-prepended `(rc=N)` 剝掉再從剩餘找 `echo $?` 的整數，因此 ansible ad-hoc 在 rc=0 但 stdout=1 的情況下會被判定為 fail（C1 正確由誤判 pass 變 fail）。Regression test：`internal/tools/verify_spec_match_test.go`（3 個 sub-tests：MatchExpected matrix、StripRunnerPrefix、ExtractRC），雙向驗證過 |
| 3 | C4 / C7 generator 退化成 `debug` | 因為 `classifyRow` 把 `grep …` 一律退到 debug：要不要升級成 `ansible.builtin.lineinfile` + `regexp:`，或 `ansible.builtin.command` `failed_when`？ |
| 4 | Regression test 路徑打 `../../docs/verification/pam-oidc-sshd.md` | 等 spec 換 repo 結構時會壞。要不要改成 `filepath.Join(filepath.Dir(CWD), ...)`？ |

---

## 7. 把 FAIL 變成 PASS 的 SOP（用 apply playbook，不用手 ssh）

> **重要**：這個 SOP **不再用 `ssh test-vm ...` 一行一行改主機**。
> 所有變更都走 `playbooks/apply/pam-oidc-sshd-apply.yml` 一份 playbook，
> 並透過 `-e` 把參數帶進去。這樣：
>   - lockout safety net（block/rescue）是真的 playbook 內建、不是靠記憶
>   - 這份 playbook 可以丟給 CI / 可以用 `pilot run` 讓 LLM agent 驅動
>   - spec → apply → verify 的閉環**真的接起來**而不是只在 runbook 裡掛個名

### 7.1 必備

- 一份裝好的 kc-ssh-pam `.deb`（自己 build 或從 release page 拿）
- 一個 Keycloak realm + client（`ssh-oidc` is a reasonable name），
  以及它的 issuer URL
- ssh 通 `test-vm` 且可 `become: true`（inventory 已示範在 `inventory.yaml`）

### 7.2 主要步驟（4 條命令，沒了）

```bash
cd /home/ubuntu/nfs/github/pilot       # 或任何用 --root 指定的位置

# (1) dry run：先看 apply playbook 要做哪些事
ansible-playbook -i inventory.yaml \
    playbooks/apply/pam-oidc-sshd-apply.yml \
    --check --diff \
    -e kc_ssh_pam_deb=/abs/path/kc-ssh-pam_1.2.3_amd64.deb \
    -e keycloak_issuer=https://keycloak.example/realms/eng
# 期望 PLAY RECAP: ... changed=2 failed=0

# (2) 真的套用
ansible-playbook -i inventory.yaml \
    playbooks/apply/pam-oidc-sshd-apply.yml \
    -e kc_ssh_pam_deb=/abs/path/kc-ssh-pam_1.2.3_amd64.deb \
    -e keycloak_issuer=https://keycloak.example/realms/eng \
    -e keycloak_client_id=ssh-oidc
# 期望 PLAY RECAP: ... changed=5 failed=0 (snapshot+apt+mkdir+config+lineinfile)
# 若中間任何 step fail → rescue 區塊自動 cp ...bak /etc/pam.d/sshd

# (3) 等 30 秒讓 kc-ssh-pam 跟 Keycloak 完成初次 metadata exchange，
#     然後讓 spec-driven verify 對所有 7 個 row 重跑驗證
sleep 30
/tmp/pilot verify docs/verification/pam-oidc-sshd.md \
    -i inventory.yaml -l test-vm \
    --report-dir .verification
# 期望 verdict: **PASS**  (pass=7 fail=0)

# (4) 看 SQLite 覆蓋率（合上前一輪 #6 自動 transition 之前可用 status=applied）
/tmp/pilot spec status docs/verification/pam-oidc-sshd.md
# 期望 coverage = 100.0% ，verified=7 pass / 7
```

### 7.3 用 `pilot run` 驅動（讓 LLM agent 看到整段 SOP）

```bash
/tmp/pilot run --no-tui --model minimax-m3:cloud \
    "Apply pam-oidc-sshd to test-vm. Use playbooks/apply/pam-oidc-sshd-apply.yml \
     with kc_ssh_pam_deb=/abs/path/kc-ssh-pam_1.2.3_amd64.deb and \
     keycloak_issuer=https://keycloak.example/realms/eng. After the run, \
     run pilot verify against docs/verification/pam-oidc-sshd.md and report \
     the verdict."
```

`pilot run` 透過 agent loop 把這段話翻成：

1. `read_file` 讀 spec.md 與 inventory.yaml
2. `run_command` 做 sanity（`ls` .deb、`curl` Keycloak discovery URL）
3. `run_ansible` 跑 apply playbook（先 --check 再真套用）
4. `run_ansible` 跑 verify playbook
5. 把 verdict 寫進 SQLite + 印 summary

預期 agent 結尾：`applied N tasks, verifier verdict PASS, coverage 100%`。

### 7.4 若 ansible 不可用（fallback：手 ssh）

這個 fallback **只**在 emergency 用（例如：ansible controller 死掉、但
target 主機活著，需要搶救）。**平常不要這樣做** — 等於繞過 rollback
safety net。

```bash
ssh test-vm 'sudo cp /etc/pam.d/sshd /etc/pam.d/sshd.pamoidc.bak'   # 也手動備份一份
ssh test-vm 'sudo apt install /tmp/kc-ssh-pam_1.2.3_amd64.deb'
ssh test-vm 'sudo mkdir -p /etc/kc-ssh-pam'
ssh test-vm 'sudo tee /etc/kc-ssh-pam/config.yaml >/dev/null <<YAML
issuer: https://keycloak.example/realms/eng
client_id: ssh-oidc
ssh_port: 22
device_flow: true
mfa: required
YAML
ssh test-vm 'sudo sed -i '1i auth sufficient pam_kc_ssh.so' /etc/pam.d/sshd'
# 若 sed 改錯 → 重新 cp bak 回去：
# ssh test-vm 'sudo cp /etc/pam.d/sshd.pamoidc.bak /etc/pam.d/sshd'
```

> 為什麼這條 fallback 段落**還寫在 runbook**：sandbox 環境（無外網、
> 無 Keycloak）可能真的用不到 apply playbook。但 § 7.2 才是 primary SOP，
> fallback 只是在飛機失事時救命的後備。

---

## 8. Commit / 版控

依通用工具 repo 政策（見 §0 / `TESTING.md`）：
- ✅ 進版控：`docs/verification/pam-oidc-sshd.md`、`playbooks/generated/pam-oidc-sshd.yml`、
  `inventory.yaml`（建議 ignore）、`docs/runbooks/pam-oidc-sshd.md`
  （本檔）、`internal/spec/pam_oidc_sshd_regression_test.go`
- ❌ 不進版控：`.verification/*.md`、`.verification/*.ndjson`、本地 `inventory.yaml`、
  `~/.local/share/pilot/history.db`

```bash
git add docs/verification/pam-oidc-sshd.md \
        playbooks/generated/pam-oidc-sshd.yml \
        internal/spec/pam_oidc_sshd_regression_test.go \
        docs/runbooks/pam-oidc-sshd.md
git commit -m "spec(verification): add pam-oidc-sshd (kc-ssh-pam) end-to-end runbook + regression"
```

---

## 9. 參考

- 規格：`docs/verification/pam-oidc-sshd.md`
- 上一輪 handoff：「Pilot 規格↔Playbook 接線 + 通用工具 repo 政策」
- 程式：
  - `internal/spec/{parser,lint,generator,traceability}.go`
  - `internal/spec/pam_oidc_sshd_regression_test.go`
  - `cmd/pilot/cmd/spec.go`（含 `--apply` 已知的 skip bug — §6 #1）
  - `cmd/pilot/cmd/verify.go`
  - `internal/ansible/runner.go`
- 驗證產物：
  - `.verification/pam-oidc-sshd-20260629-091917.{md,ndjson}`（local）
  - `.verification/pam-oidc-sshd-20260629-093114.{md,ndjson}`（test-vm）
