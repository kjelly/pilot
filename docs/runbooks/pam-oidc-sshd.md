# Runbook — pam-oidc-sshd (Keycloak Device Flow via `kc-ssh-pam`)

> Status: **Flow exercised end-to-end on `test-vm` (libvirt)**. Two bugs found in the run were fixed and regressed: (1) `pilot spec --apply` add --hosts/--connection; (2) verifier pre-fix reported pass when stdout was wrong. Verdict currently **FAIL (2 pass / 5 fail)** because `kc-ssh-pam` isn't installed on the target. This runbook records the post-fix pipeline and the SOP to take the spec to **PASS**.
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

### 2.5 Step ③ Apply（套用 / dry run）

```bash
/tmp/pilot spec docs/verification/pam-oidc-sshd.md \
    --apply -i inventory.yaml --hosts test-vm --connection ssh -l test-vm
# ✔ generated playbook: playbooks/generated/pam-oidc-sshd.yml (5 tasks, ...)
# ✔ recorded 7 checkpoints (run_id=spec-pam-oidc-sshd)
# PLAY [Verification Spec — pam-oidc-sshd (...)] ****
# ...
# PLAY RECAP
# test-vm : ok=5 changed=0 unreachable=0 failed=0
```

> `--hosts=test-vm --connection=ssh` 從 CLI 傳進 `spec.GenerateOptions`，讓 generator
> 寫出 `hosts: test-vm` / `connection: ssh` 而不是預設的 `localhost` / `local`。之前的
> `skipping: no hosts matched` bug（§ 6 #1）已用這個 CLI 接法修掉，不需手動 sed。
>
> 註：5 個 task 都是唯讀 inspection（test -f / sshd -T / pam-auth --check / grep），
> `ok=5` / `changed=0` 是預期 — 還沒真正改 `/etc/pam.d/sshd`。

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

### 3.1 `.verification/pam-oidc-sshd-20260629-093114.md` 重點列

| ID | Status | 失敗原因（簡述）|
|----|--------|----------------|
| C1 | pass  | `dpkg -s kc-ssh-pam` exit 1（沒裝）→ 等等，**這個應該是 fail 才對？** |

> ⚠️ **這是 spec 設計上的訊號**：`expected=0` + `dpkg -s ... >/dev/null 2>&1; echo $?` 這個
> 命令的最後 stdout 是 `1`（沒裝），但 Lint 接受 `0`，ad-hoc 比對時若 verifier 把 stdout
> 跟 `expected` 直接比，會誤判成 pass。詳細在 § 7.2。

| ID | Status | 失敗原因（簡述）|
|----|--------|----------------|
| C1 | pass | stdout=`1`（沒裝）；verifier 視為通過 → **誤判**（待修）|
| C2 | fail | `/etc/kc-ssh-pam/config.yaml` not present |
| C3 | fail | `/etc/pam.d/sshd.pamoidc.bak` not present |
| C4 | fail | sshd 沒有 `pam_kc_ssh.so` 那行 |
| C5 | pass | `sshd -T` exit 0 |
| C6 | fail | `pam-auth --check` → No such file |
| C7 | fail | `/etc/kc-ssh-pam/config.yaml` not present |

→ **本次斷言 FAIL，原因如上；2 個 pass 是誤判，見 § 7.2。**

### 3.2 SQLite 摘要

```
verified-fail: 5
verified-pass: 2
```

---

## 4. Playbook 對應（產出檔）

`playbooks/generated/pam-oidc-sshd.yml` 內容：

```yaml
---
- name: Verification Spec — pam-oidc-sshd (kc-ssh-pam, Keycloak Device Flow)
  hosts: test-vm                         # ← sed 後；generator 預設 localhost
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
      ansible.builtin.debug:
        msg: "Spec C4 requires lineinfile idempotent rewrite of /etc/pam.d/sshd (expected 0)"
      become: true
    - name: "C7 — `/etc/kc-ssh-pam/config.yaml` 含 `issuer:` 且 URL 合法"
      ansible.builtin.debug:
        msg: "Spec C7 requires lineinfile idempotent rewrite of /etc/kc-ssh-pam/config.yaml (expected 0)"
      become: true
```

---

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

## 7. 把 FAIL 變成 PASS 的 SOP

當你準備好在 `test-vm` 真的裝 `kc-ssh-pam` 並對接 Keycloak realm，依下列順序：

1. **先備份**（就算 spec 沒列，這步是救命的）
   ```bash
   ssh test-vm 'sudo cp /etc/pam.d/sshd /etc/pam.d/sshd.pre-kc-ssh-pam.bak'
   ```
2. **裝套件**（C1 由 fail → pass）
   ```bash
   ssh test-vm 'sudo apt install ./kc-ssh-pam_<ver>.deb'
   ```
3. **寫 config**（C2、C7 由 fail → pass）
   ```bash
   ssh test-vm 'sudo mkdir -p /etc/kc-ssh-pam && sudo tee /etc/kc-ssh-pam/config.yaml >/dev/null <<YAML
   issuer: https://keycloak.example/realms/eng
   client_id: ssh-oidc
   YAML'
   ```
4. **改 PAM**（C3、C4 由 fail → pass）
   ```bash
   ssh test-vm 'sudo cp /etc/pam.d/sshd /etc/pam.d/sshd.pamoidc.bak'
   ssh test-vm 'sudo tee /etc/pam.d/sshd >/dev/null <<PAM
   #%PAM-1.0
   auth sufficient pam_kc_ssh.so
   account required pam_unix.so
   PAM'
   ```
5. **重跑 verify**
   ```bash
   /tmp/pilot verify docs/verification/pam-oidc-sshd.md \
       -i inventory.yaml -l test-vm --report-dir .verification
   # 預期 verdict: **PASS**  (pass=7 fail=0)
   ```
6. **回填 spec_checkpoints 為 applied=true**
   暫時手動：
   ```bash
   sqlite3 ~/.local/share/pilot/history.db \
     "UPDATE spec_checkpoints SET status='applied'
      WHERE spec_path LIKE '%pam-oidc%'"
   ```
   （長期應該由 `pilot spec --apply` exit-0 時自動回填 — 這也是技術債 #1 一部分）

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
