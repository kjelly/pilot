# Verification Spec — pam-oidc-sshd (kc-ssh-pam, Keycloak Device Flow)

> 版本：v1.0
> 對齊規範：pilot 通用 PAM OIDC 規範（Keycloak Device Flow 最小可驗證集）
> 維護者：sre

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Hostname / Inventory group | linux-servers (預設；本機 smoke 可用 localhost) |
| OS | Ubuntu 22.04+ / Debian 12+（kc-ssh-pam 以 .deb 發佈）|
| 角色 | 工程師 SSH 登入認證後端 → Keycloak（Device Flow + MFA）|
| 套用範圍 | `/etc/pam.d/sshd`、`/etc/kc-ssh-pam/`、`sshd_config` 唯讀檢查 |
| 風險等級 | High（sshd PAM 修改錯誤 → lockout；C3 + C4 必須在同 task 內處理 backup/restore）|

## 2. Checklist

| ID  | Category   | Check                                                     | Expected         | Command |
|-----|------------|-----------------------------------------------------------|------------------|---------|
| C1  | pkg        | `kc-ssh-pam` 套件已安裝（deb）                              | 0                | sh -c 'dpkg -s kc-ssh-pam >/dev/null 2>&1; echo $?' |
| C2  | file       | 模組設定檔 `/etc/kc-ssh-pam/config.yaml` 存在              | present          | test -f /etc/kc-ssh-pam/config.yaml |
| C3  | file       | sshd PAM 備份 `/etc/pam.d/sshd.pamoidc.bak` 存在           | present          | test -f /etc/pam.d/sshd.pamoidc.bak |
| C4  | pam        | `/etc/pam.d/sshd` 含 `auth sufficient pam_kc_ssh.so` 行    | 0                | grep -qE '^auth[[:space:]]+sufficient[[:space:]]+pam_kc_ssh.so' /etc/pam.d/sshd |
| C5  | sshd       | `sshd -T` 仍可解析 PAM 設定（未改到壞掉）                  | 0                | sh -c 'sshd -T -f /etc/ssh/sshd_config >/dev/null 2>&1; echo $?' |
| C6  | pam-auth   | `pam-auth --check` 報告 `kc-ssh-pam` 為有效 provider        | ^OK provider=kc-ssh-pam | pam-auth --check 2>/dev/null \| head -n1 |
| C7  | config     | `/etc/kc-ssh-pam/config.yaml` 含 `issuer:` 且 URL 合法      | 0                | grep -qE '^issuer:[[:space:]]*https?://' /etc/kc-ssh-pam/config.yaml |

> C1 / C4 / C5 / C7 的 expected 為 `0`：明確數值（命令最後 echo exit code）。
> C6 用固定字串字首 `^OK provider=kc-ssh-pam` 當 expected：固定字串比對，不是 vague word。
> C3 必須由 playbook 在改 `/etc/pam.d/sshd` **之前**產出；備份缺則視為 C3 fail → rollback。
> C7 的 issuer 必須是 `https?://`；缺 issuer 或空字串視為 fail。
> 已對 hello-localhost spec 也進行相同修正：把 `awk` 那行的 expected 由 `OK` 改成具體字串。

## 3. 證據收集

- 工具：`pilot verify docs/verification/pam-oidc-sshd.md --local` (smoke) 或 `--inventory` (fleet)
- 輸出格式：NDJSON
- 預期 row 數：7（C1–C7）
- 範例輸出（dev box 未套用 → 大部分 fail，這本身就是 regression signal）：

```json
{"id":"C1","status":"fail","detail":"exit=1: dpkg -s kc-ssh-pam not installed"}
{"id":"C6","status":"fail","detail":"pam-auth --check: command not found"}
```

## 4. PASS / FAIL 規則

- 全部 C1–C7 `status=pass` → **PASS**（僅當 target 已完整套用時才會發生）
- 任一 row fail → **FAIL**，列出 fail id + actual + want
- Smoke run（`--local` 在 dev box 上）預期為 **FAIL**，這是 spec 對環境的正向檢查：
  - kc-ssh-pam 不應在 dev box 自動安裝
  - 任何 `status=pass` 在沒有套用 playbook 的情況下出現 → 視為 spec 漂移、立即 review

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C2 | kc-ssh-pam ≥ 0.4 把 config 改成 `/etc/kc-ssh-pam/config.toml`；此時 C2 / C7 的 path 需更新 | kc-ssh-pam 0.4+ | 待上游穩定 |
| C6 | `pam-auth` 是 kc-ssh-pam 內附 CLI；套用未完成或版本過舊可能不存在 | 任何 | fail → 視為套用未完成 |

## 6. Playbook 對應

對應產生的 playbook：`playbooks/generated/pam-oidc-sshd.yml`

| Spec ID | Playbook task | 備註 |
|---------|---------------|------|
| C1      | `C1 — kc-ssh-pam apt install` | apt + become |
| C2      | `C2 — /etc/kc-ssh-pam/config.yaml present` | stat |
| C3      | `C3 — /etc/pam.d/sshd.pamoidc.bak present` | stat；同 block 必須在 C4 之前 |
| C4      | `C4 — lineinfile pam_kc_ssh.so in /etc/pam.d/sshd` | idempotent |
| C5      | `C5 — sshd -T parse smoke` | command |
| C6      | `C6 — pam-auth --check` | command |
| C7      | `C7 — config.yaml has issuer URL` | command |

> Block 順序：`backup → install → ensure_config → modify_pamd → sanity → check_tool → validate_config`。
> 非 C3 task fail → rescue block 自動跑 `cp ...bak /etc/pam.d/sshd`，確保 lockout 救援單一 command。

## 7. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-06-29 | v1.0 | 初版（dev box smoke fail 為預期，驗證 spec / lint / pipeline 可正常運作）| pilot |
