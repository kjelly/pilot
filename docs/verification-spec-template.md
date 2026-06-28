# Verification Spec Template

> 給「把模糊需求落地成可驗證狀態」的標準格式。
> 每一個 row 對應 playbook 一個 task、verify script 一個 check。

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
| 風險等級 | |

## 2. Checklist

| ID  | Category | Check                          | Expected                      | Command |
|-----|----------|--------------------------------|-------------------------------|---------|
| C1  | file     | /etc/ssh/sshd_config           | present                       | test -f /etc/ssh/sshd_config |
| C2  | file     | /etc/ssh/sshd_config PermitRootLogin | `^PermitRootLogin\s+no$` | grep -E '^PermitRootLogin\s+no$' /etc/ssh/sshd_config |
| C3  | sysctl   | net.ipv4.ip_forward            | "0"                           | sysctl -n net.ipv4.ip_forward |
| C4  | service  | sshd.service state             | active                        | systemctl is-active sshd |
| C5  | port     | 22/tcp listening               | yes                           | ss -tlnH 'sport = :22' |
| C6  | user     | /etc/passwd 權限               | 0644                          | stat -c '%a' /etc/passwd |
| C7  | package  | fail2ban installed             | present                       | dpkg -s fail2ban |
| ... |          |                                |                               | |

## 3. 證據收集

- 腳本路徑：`scripts/verify-<host>.sh`
- 輸出格式：NDJSON（每行一個 `{id, status, detail}` object）
- 預期 row 數：N（等於 checklist row 數）

範例輸出：

```json
{"id":"C1","status":"pass","detail":"exists"}
{"id":"C2","status":"pass","detail":"PermitRootLogin no"}
{"id":"C3","status":"fail","detail":"got=1 want=0"}
```

## 4. PASS / FAIL 規則

- 全部 row `status=pass` 或 `status=skip`（且 skip 有正當理由）→ **PASS**
- 任一 row `status=fail` → **FAIL**，報告列出 fail 的 id + actual + want

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C2 | 測試環境允許 PermitRootLogin yes | dev / ci | 無 |
| C5 | 22 port 在 staging 改 2222 | staging | 至 2026-Q3 |

## 6. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-06-28 | v1.0 | 初版 | alice |
```

---

## 撰寫 Checklist（給 spec 作者）

寫的時候自我檢查：

- [ ] 每個 row 的 **expected** 都是單一可判定值（避免「合理」「足夠」這類）
- [ ] 每個 row 的 **command** 在目標主機上可單獨跑出結果
- [ ] 涉及檔案權限的 row 寫出數字（`0644`）而非文字（`644` 或 `0o644`）
- [ ] 涉及 service 的 row 寫出 `active` / `inactive` / `enabled` / `disabled`
- [ ] 涉及 sysctl 的 row 寫出字串型 expected（`sysctl -n` 永遠回字串）
- [ ] 例外有寫清楚「適用環境」跟「為什麼」
- [ ] 有版本號跟變更紀錄

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

| ID  | Category | Check                                | Expected                   | Command |
|-----|----------|--------------------------------------|----------------------------|---------|
| C1  | file     | /etc/ssh/sshd_config                 | present                    | test -f /etc/ssh/sshd_config |
| C2  | file     | PermitRootLogin                       | `^PermitRootLogin\s+no$`   | grep -E '^PermitRootLogin\s+no$' /etc/ssh/sshd_config |
| C3  | file     | PasswordAuthentication                | `^PasswordAuthentication\s+no$` | grep -E '^PasswordAuthentication\s+no$' /etc/ssh/sshd_config |
| C4  | sysctl   | net.ipv4.ip_forward                  | "0"                        | sysctl -n net.ipv4.ip_forward |
| C5  | sysctl   | kernel.randomize_va_space            | "2"                        | sysctl -n kernel.randomize_va_space |
| C6  | service  | sshd.service state                   | active                     | systemctl is-active sshd |
| C7  | service  | fail2ban.service state               | active                     | systemctl is-active fail2ban |
| C8  | port     | 22/tcp listening                     | yes                        | ss -tlnH 'sport = :22' |
| C9  | user     | UID 0 帳號只允許 root                | exactly 1                  | getent passwd 0 \| wc -l |
| C10 | file     | /etc/passwd 權限                     | 0644                       | stat -c '%a' /etc/passwd |
| C11 | file     | /etc/shadow 權限                     | 0000 or 0640              | stat -c '%a' /etc/shadow |
| C12 | package  | unattended-upgrades installed        | present                    | dpkg -s unattended-upgrades |

## 3. 證據收集

- 腳本：scripts/verify-bastion.sh
- 格式：NDJSON
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
| 2026-06-28 | v1.0 | 初版 | infra-team |
```
