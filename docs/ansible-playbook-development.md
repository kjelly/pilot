# Ansible Playbook 開發流程

> 適用場景：把模糊的合規 / 資安 / 維運需求落地成可重現、可驗證、可回歸的 Ansible Playbook。
> 核心精神：**先寫 spec → 再寫 playbook → 用證據驗證 → 用 baseline 回歸**。

> **2026-06 更新**：文件內的目錄結構、`pilot run` vs `ansible-playbook` 抉擇、
> apply playbook 樣板結構請見 [`README.md` 的「Spec-driven 工作流」章節](../README.md#-spec-driven-工作流寫需求--套用--驗證)。
> 本檔是「為何這樣做」的心法，README 是「今天怎麼跑」的 SOP。

---

## 0. 心法（讀後當 cheatsheet）

| 不要 | 要 |
|------|----|
| 直接寫 playbook | 先寫 verification spec |
| 用眼睛看 `ok=... changed=...` 判定成功 | 跑驗證腳本產出結構化證據 |
| 相信「跑過沒失敗」=系統正確 | 對齊 spec 期望值才算通過 |
| 改了 A 就 commit | 對 baseline report 做 diff 才 commit |
| 把 playbook 套到 prod 才第一次驗證 | sandbox / VM 迭代驗證收斂後才碰 prod |
| sandbox 跑完相信結果「還在」 | 產物寫到 writable root 才留得下 |

---

## 1. 整體流程

```
模糊需求
   │ (拆解 / 對齊法規 / 詢問利害關係人)
   ▼
Verification Spec (docs/verification/<host>.md)
   │ (契約：給 LLM + 給人 + 給 playbook 作者)
   ▼
Playbook skeleton (task 名稱 = spec ID)
   │ (L1 syntax → L2 lint → L3 dry-run)
   ▼
迭代迴圈（每次都在同一個 sandbox 內完成）：
   L4 apply  ──┐
   L5 verify  ──┤  對齊 spec → 改 playbook → 再 L4
   L6 idem    ──┘
   ▼
L7 baseline diff（vs 上次 report）
   ▼
commit: spec + playbook + verify script + report
```

每一層的細節在後面章節。

---

## 2. Step 1 — 拆需求成 Verification Spec

### 為什麼先寫 spec

- **Playbook 是手段，spec 是目的。** 手段換掉（例如改用 Puppet、Chef、shell）目的不變。
- Spec 是給 LLM 驗證用的契約：寫清楚 expected value + 收集方式，LLM 就能自動跑、自動判 PASS/FAIL。
- Spec 進版控 → spec 變更要走 PR review，playbook 才能跟著改。

### Spec 結構

完整 template 見 `docs/verification-spec-template.md`。摘要：

```markdown
# Verification Spec — <host role>

## 1. 目標系統
- host / inventory / role / OS
- 對齊的法規或規範（CIS / STIG / 公司內規 / 客戶要求）

## 2. Checklist
| ID  | Category | Check               | Expected       | Command |
|-----|----------|---------------------|----------------|---------|
| C1  | file     | /etc/ssh/sshd_config | present        | test -f ... |
| C2  | file     | PermitRootLogin      | ^PermitRootLogin no$ | grep -E ... |
| C3  | sysctl   | net.ipv4.ip_forward  | "0"            | sysctl -n ... |

## 3. 證據收集腳本
- 路徑：scripts/verify-<host>.sh
- 格式：每行一個 JSON object（NDJSON），含 id / status / detail

## 4. PASS / FAIL 規則
- 全部 C1..CN pass → PASS
- 任一 fail → FAIL，附實際值

## 5. 例外與已知偏差
```

### 拆需求的實際動作

1. **拿原始來源**：CIS Benchmark PDF、STIG .xml、公司 Wiki、客戶信件
2. **逐條轉成 checklist row**：每個 requirement 一個 row
3. **補 expected value**：原文若寫「should」，要明確化成「must contain X」或「must equal Y」
4. **補 command**：怎麼用一行指令讀到實際值
5. **標註例外**：測試環境可以放寬的項目

---

## 3. Step 2 — Playbook 結構

### 檔案布局（**2026-06 版**）

```
docs/verification/
  <name>.md                   # spec（人寫；pilot spec --lint 把關）

playbooks/
  verify/
    <name>.yml                # inspect-only（不要手寫；pilot spec --generate 產）
  apply/
    <name>-apply.yml          # mutations（人寫；含 -e vars + block/rescue）

inventory/
  <env>.yaml                  # sandbox / staging / prod 三份

.verification/                # baseline reports（gitignored）
  <name>-<UTC>.{ndjson,md}

~/.local/share/pilot/history.db
  spec_checkpoints row per (spec, row_id) per run
```

**原則**：

- `verify/<name>.yml` 用 `pilot spec --generate` 產出；手寫會跟 spec 漂移
- `apply/<name>-apply.yml` 永遠手寫（這就是 mutate playbook）；必須含 `-e` 參數、
  `block/rescue`、stage gate
- **不要**把兩種產物放在同個檔

### Task 命名對齊 spec

```yaml
# 範例：playbooks/bastion-hardening.yml
- name: Bastion hardening
  hosts: bastion
  become: true

  tasks:
    # === C2 ===
    - name: C2 — sshd PermitRootLogin no
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^PermitRootLogin\s+'
        line: 'PermitRootLogin no'
      notify: reload sshd

    # === C3 ===
    - name: C3 — sshd PasswordAuthentication no
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^PasswordAuthentication\s+'
        line: 'PasswordAuthentication no'
      notify: reload sshd

    # === C4 ===
    - name: C4 — sysctl net.ipv4.ip_forward = 0
      ansible.builtin.sysctl:
        name: net.ipv4.ip_forward
        value: '0'
        sysctl_set: true
        reload: true
```

優點：grep `C2` 可以從 spec 一路追到 playbook 任一行。

### Idempotency 三原則

1. **永遠用 stateful module**（`lineinfile` / `template` / `copy` / `package` / `service` / `sysctl`），
   不要用 `command` / `shell` 直接改檔，除非真的沒有 module。
2. **避免 `creates` / `removes` 判斷**：那是 workaround，正解是用 idempotent module。
3. **連跑 N 次結果應該一致**：第二次以後 `changed=0`。

---

## 4. Step 3 — 迭代迴圈（單次 sandbox 內完成）

每次改 playbook 都跑這一串，**全部塞在一個 `exec_command` 內**（sandbox 銷毀就拿不到 `/etc` 狀態了）：

```bash
# L1: 語法檢查（秒回）
ansible-playbook --syntax-check playbooks/<host>.yml

# L2: lint（若已裝 ansible-lint）
ansible-lint playbooks/<host>.yml

# L3: dry-run + diff（看「打算改什麼」，不真的改）
ansible-playbook -i inventory/dev playbooks/<host>.yml --check --diff

# L4: 真的套用
ansible-playbook -i inventory/dev playbooks/<host>.yml

# L5: 驗證（產出 NDJSON）
bash scripts/verify-<host>.sh > /tmp/verify-raw.ndjson

# L6: 渲染成 markdown report 並寫到 writable root
python3 scripts/render-report.py /tmp/verify-raw.ndjson \
  > "$HOME/nfs/github/pilot/.verification/<host>-$(date +%Y%m%d-%H%M%S).md"

# L7: 跟 baseline diff（取最新一份舊 report）
PREV=$(ls -1t /workspace/pilot/.verification/<host>-*.md | sed -n '2p')
LATEST=$(ls -1t /workspace/pilot/.verification/<host>-*.md | head -1)
if [ -n "$PREV" ]; then
  echo "=== diff $PREV -> $LATEST ==="
  diff -u "$PREV" "$LATEST" || true
fi

# L8: idempotency check — 再跑一次，期望 changed=0
ansible-playbook -i inventory/dev playbooks/<host>.yml | tail -20
```

**為什麼要塞同一個指令**：sandbox 銷毀後 `/etc/ssh/sshd_config` 不存在，
你無法在下一個指令驗證剛才改了什麼。

---

## 5. Step 4 — 驗證腳本要寫成 machine-readable

### NDJSON 格式

LLM 拿到 NDJSON 就能直接判定，不用 regex 抓字串：

```json
{"id":"C2","status":"pass","detail":"PermitRootLogin no"}
{"id":"C3","status":"pass","detail":"PasswordAuthentication no"}
{"id":"C4","status":"fail","detail":"got=1 want=0"}
```

每行一個 check object，至少含：
- `id`：對齊 spec
- `status`：`pass` / `fail` / `skip`
- `detail`：實際值或錯誤訊息（給人讀）

### Shell template

完整通用版見 `scripts/verify.sh`。最小骨架：

```bash
#!/bin/bash
set -u

emit() {
  local id=$1 status=$2 detail=$3
  # 用 python 做 JSON escape，避免 detail 含雙引號爆炸
  local esc
  esc=$(printf '%s' "$detail" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')
  printf '{"id":"%s","status":"%s","detail":%s}\n' "$id" "$status" "$esc"
}

# === 範例 checks ===

# C1: 檔案存在
test -f /etc/ssh/sshd_config \
  && emit C1 pass "exists" \
  || emit C1 fail "missing"

# C2: sshd_config 含 PermitRootLogin no
if grep -qE '^PermitRootLogin\s+no$' /etc/ssh/sshd_config; then
  emit C2 pass "PermitRootLogin no"
else
  actual=$(grep '^PermitRootLogin' /etc/ssh/sshd_config || echo not-set)
  emit C2 fail "actual=$actual"
fi

# C4: sysctl 值
actual=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
[ "$actual" = "0" ] && emit C4 pass "ip_forward=0" || emit C4 fail "ip_forward=$actual"

# C6: service 狀態
state=$(systemctl is-active sshd 2>/dev/null || echo unknown)
[ "$state" = "active" ] && emit C6 pass "active" || emit C6 fail "$state"
```

### Python render-report

```python
#!/usr/bin/env python3
# scripts/render-report.py — NDJSON → markdown
import json, sys, datetime

rows = [json.loads(line) for line in sys.stdin if line.strip()]
total = len(rows)
passed = sum(1 for r in rows if r["status"] == "pass")
failed = sum(1 for r in rows if r["status"] == "fail")
skipped = sum(1 for r in rows if r["status"] == "skip")

print(f"# Verification Report")
print(f"- generated: {datetime.datetime.utcnow().isoformat()}Z")
print(f"- total: {total}  pass: {passed}  fail: {failed}  skip: {skipped}")
print(f"- verdict: {'PASS' if failed == 0 else 'FAIL'}")
print()
print("| ID | Status | Detail |")
print("|----|--------|--------|")
for r in rows:
    print(f"| {r['id']} | {r['status']} | {r['detail']} |")
```

---

## 6. Step 5 — Baseline 與回歸

### Baseline 規則

- `.verification/<host>-*.md` 進版控（或進 git LFS）
- 最新一份 = **當前期望狀態**
- 任何 playbook 變更 → 重跑 → diff 新舊 report
- diff 出現**未預期的變化**（playbook 沒動但 report 變了）→ 環境漂移，需調查

### 用法

```bash
# 看兩次 report 的差別
diff -u .verification/bastion-20260101.md .verification/bastion-20260115.md

# 或只看 fail 列的變化
diff <(grep '^|.*fail' .verification/old.md) \
     <(grep '^|.*fail' .verification/new.md)
```

---

## 7. 測試金字塔速查

| Level | 名稱 | 工具 | 指令 | 失敗處理 |
|-------|------|------|------|----------|
| L1 | syntax | ansible-playbook | `--syntax-check` | 修 YAML |
| L2 | lint | ansible-lint | `ansible-lint <file>` | 改寫法 |
| L3 | intent | ansible-playbook | `--check --diff` | 確認 playbook 意圖 |
| L4 | apply | ansible-playbook | （無 flag） | 看 stderr |
| L5 | verify | scripts/verify.sh | （bash） | 對 spec |
| L6 | idempotency | ansible-playbook × N | `grep changed` | 用 idempotent module |
| L7 | regression | diff | `diff old new` | 查環境漂移 |

---

## 8. Sandbox / VM 環境策略

### 不要在 prod 第一次跑

| 環境 | 用途 | 重置方式 |
|------|------|----------|
| 本機 sandbox（Codex） | syntax + dry-run + 短 task | 自動銷毀 |
| kvmforge VM | 完整 apply + verify | snapshot / 重建 |
| staging | 接近 prod 的整合測試 | terraform / ansible |
| prod | 部署 | 跑過 staging 才進 |

### 用 kvmforge 開 VM 當 fixture

```bash
# 開一台 ubuntu 22.04
# 跑 playbook
# 跑 verify
# 不滿意就 destroy 重建，不要在壞掉的 VM 上疊修改
```

VM 比 docker 好的地方：systemd / sysctl / network 行為與真機一致。

---

## 9. 常見地雷

### 「跑過沒失敗」不等於 PASS
Ansible `failed=0` 只代表 task 沒拋例外。設定寫錯（少一個 `=`、多空格）task 還是 ok，但系統狀態不對。
→ **一定要 L5 verify 對 spec**。

### Idempotency 沒測
`command: echo X >> /etc/file` 每次跑都 append，最後檔案爆。
→ **L8 連跑 3 次，第二次以後 `changed=0`**。

### Handler 沒觸發
`notify: reload sshd` 但 handler 寫錯 module → service 沒 reload，新 config 沒生效。
→ L5 verify 確認實際行為（`sshd -T` / 連線測試）。

### 變數順序
group_vars 蓋 host_vars 不一定直覺。
→ L3 dry-run + `--diff` 看出實際值。

### 環境漂移
Playbook 沒動，但 verify 從 PASS 變 FAIL → 有人手動改過 host。
→ L7 baseline diff 抓出來。

### Sandbox 寫到錯誤位置
Sandbox 銷毀後檔案不見。
→ 產物寫到 `/workspace/pilot/`（writable root）或 `/tmp`。

---

## 10. 完成定義（DoD）

Playbook 可以 merge / ship 的條件：

- [ ] spec 文件 commit，ID 編號連續
- [ ] verify script 產出 NDJSON，每個 check 有 id/status/detail
- [ ] L1..L6 全部通過
- [ ] L7 baseline diff 對上一次 report 沒有未預期變化
- [ ] L8 idempotency：連跑 3 次 changed=0
- [ ] 在 staging 跑過一次完整 apply + verify
- [ ] PR 描述含：spec 連結、verify 報告連結、idempotency 證據

---

## 11. 參考與模板

- Spec template：`docs/verification-spec-template.md`
- Verify shell template：`scripts/verify.sh`
- 範例 playbook：`playbooks/hello-localhost.yml`（smoke test 起點）
- Sandbox 行為：見 `docs/sandbox-notes.md`（若需要可另外建立）

---

## 12. `ansible-playbook` vs `pilot run`：開發期間怎麼選

這兩個**不是替代關係** — `pilot run` 底下就是 `ansible-playbook`。
差別在誰負責「產生 playbook」這件事：

| 場景 | 選誰 | 理由 |
|------|------|-----|
| CI、production、可重現執行 | `ansible-playbook` | 你已寫好 playbook、不需 LLM |
| 第一次寫 playbook、要 iterate | `pilot run "<goal>"` | LLM 幫你看 spec、自己生出 playbook + 自動 root-cause 失敗 |
| 失敗後 debug | `pilot run "<我懷疑 X>"` | LLM 讀 stderr、自己 trace |
| Spec 還在變、要 explore | `pilot run` | 不用先把全部 playbook 寫對 |
| 改 apply playbook | **`ansible-playbook --check --diff`** + 然後 `ansible-playbook` 真套用 | 你已知道答案，只需要驗證 + 真套用 |

**判斷訣竅**：如果你問得出「該跑哪一條 ansible-playbook、帶什麼 flag、衝到哪個 host」，
**用 `ansible-playbook`**（省 token / 省錢 / 可 audit）。

如果你只講得出「我想要 Y 結果」但不知道 playbook 該怎麼寫，
**用 `pilot run`**（LLM 幫你 derive，你給意圖就好）。

### 開發期間用 `pilot run` 的 4 個 best practices

1. **`pilot run --no-tui --model minimax-m3:cloud`** 起手：non-interactive、方便抓 CI 跑的 log
2. **prompt 要包含意圖 + 環境**：「Apply pam-oidc-sshd 到 test-vm（libvirt 192.168.122.232），
   帶 .deb path X 跟 keycloak issuer Y」 — 別只給意圖不給環境，LLM 會猜錯
3. **第一次跑 agent 一定先 `--check --diff`**：spec → apply 失敗的鎖定 ssh 行為風險高，
   一定要看 dry-run diff 才放行
4. **一旦 playbook 收斂，把成果 commit 下來**：`pilot run` 適合 prototype，**不適合作為
   production 執行路徑**。 Prototype 完成後轉成 `playbooks/apply/<name>-apply.yml` +
   `ansible-playbook` 配上 inventory，三層分工：spec (人) / verify playbook (generator) / apply
   playbook (人)

詳細比較見 [README 的 Spec-driven 工作流章節](../README.md#-spec-driven-工作流寫需求--套用--驗證)。
