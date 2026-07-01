# Verification Spec — pam-oidc-sshd (kha7iq/kc-ssh-pam, Keycloak Device Flow)

> 版本：v2.0  
> 上游：https://github.com/kha7iq/kc-ssh-pam (`omidiyanto/keycloak-ssh-pam-module` fork)  
> 對齊規範：pilot 通用 PAM OIDC 規範（Keycloak Device Flow 最小可驗證集）  
> 維護者：sre

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Hostname / Inventory group | linux-servers (預設；本機 smoke 可用 localhost) |
| OS | Ubuntu 22.04+ / Debian 12+（kc-ssh-pam 以 .deb 發佈，或 `make install` 原始部署）|
| 角色 | 工程師 SSH 登入認證後端 → Keycloak（Device Flow + MFA）|
| 套用範圍 | `/etc/pam.d/sshd`、`/etc/keycloak-ssh/`、`/lib/security/pam_keycloak_device.so` |
| 風險等級 | High（sshd PAM 修改錯誤 → lockout；C3 + C4 必須在同 task 內處理 backup/restore）|

### 關鍵差異（v1→v2）

| 項目 | v1（錯誤） | v2（正確，上游 `kha7iq/kc-ssh-pam`） |
|------|-----------|--------------------------------------|
| PAM 模組名 | `pam_kc_ssh.so` | `pam_keycloak_device.so` |
| Config 目錄 | `/etc/kc-ssh-pam/` | `/etc/keycloak-ssh/` |
| Config 檔 | `config.yaml`（YAML key `issuer:`）| `config.yaml`（YAML key `keycloak.server_url:`）|
| 監控 daemon | `pam-auth` CLI | `keycloak-ssh-monitor`（systemd） |
| systemd unit | — | `keycloak-ssh-monitor.service` |
| 安裝方式 | `apt install kc-ssh-pam`（無此 deb） | `make install` 或 `scripts/install.sh` |

## 2. Checklist

| ID  | Category   | Check | Expected | Command |
|-----|------------|-------|----------|---------|
| C1  | pkg/deps   | Go + `libpam0g-dev` + `build-essential` 已安裝 | ~1 | sh -c 'dpkg-query -W -f="${Status}" golang-go libpam0g-dev build-essential 2>/dev/null | awk "/^ii/{c++} END{print c}"' |
| C2  | file       | PAM 模組 `/lib/security/pam_keycloak_device.so` 存在 | present | test -f /lib/security/pam_keycloak_device.so -o -f /lib/x86_64-linux-gnu/security/pam_keycloak_device.so |
| C3  | file       | sshd PAM 備份 `/etc/pam.d/sshd.kcsssh.bak` 存在 | present | test -f /etc/pam.d/sshd.kcsssh.bak |
| C4  | pam        | `/etc/pam.d/sshd` 含 `auth sufficient pam_keycloak_device.so` 行 | 0 | grep -qE '^auth[[:space:]]+sufficient[[:space:]]+pam_keycloak_device\.so' /etc/pam.d/sshd; echo $? |
| C5  | sshd       | `sshd -T` 仍可解析 PAM 設定（未改到壞掉） | 0 | sh -c 'sshd -T -f /etc/ssh/sshd_config >/dev/null 2>&1; echo $?' |
| C6  | monitor    | `keycloak-ssh-monitor` 二進位存在 | present | test -f /usr/local/bin/keycloak-ssh-monitor |
| C7  | systemd    | `keycloak-ssh-monitor.service` systemd unit 存在 | present | test -f /etc/systemd/system/keycloak-ssh-monitor.service |
| C8  | config     | `/etc/keycloak-ssh/config.yaml` 含 `keycloak.server_url:` 且 URL 合法 | 0 | grep -qE '^[[:space:]]*server_url:[[:space:]]*https?://' /etc/keycloak-ssh/config.yaml; echo $? |
| C9  | config     | `/etc/keycloak-ssh/config.yaml` 含 `keycloak.realm:` 非空 | present | grep -qE '^[[:space:]]*realm:[[:space:]]+[^[:space:]]' /etc/keycloak-ssh/config.yaml |

> C1/C4/C5/C8 的 expected 為 `0`：明確 exit code。  
> C2/C3/C6/C7/C9 的 expected 為 `present`：檔案/目錄存在（`test -f` → `0`）。  
> C7 systemd unit 可存在但 daemon 未啟動；start 失敗不影響 spec PASS（取決於 apply 範圍）。

## 3. 證據收集

- 工具：`go run ./cmd/pilot vm-target verify --name <target> docs/verification/pam-oidc-sshd.md`
- 輸出格式：NDJSON + markdown
- 預期 row 數：9（C1–C9）
- 範例輸出（dev box 未套用 → 大部分 fail）：

```json
{"id":"C1","status":"fail","detail":"dpkg-query: package golang-go not found"}
{"id":"C2","status":"fail","detail":"pam_keycloak_device.so not found"}
{"id":"C4","status":"fail","detail":"pam_keycloak_device.so not in /etc/pam.d/sshd"}
```

## 4. PASS / FAIL 規則

- 全部 C1–C9 `status=pass` → **PASS**
- 任一 fail → **FAIL**
- Smoke run（`--local` 在 dev box 上）預期為 **FAIL** — 這是 spec 對環境的正向檢查

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C7 | systemd unit 存在但 daemon 未 enable/run — apply 範圍可能只到安裝不包含 start | 任何 | 視 apply 範圍 |
| C2 | Debian/Ubuntu 的 PAM security 路徑可能是 `/lib/x86_64-linux-gnu/security/` 而非 `/lib/security/` | Debian 12+ | 永久 |

## 6. Playbook 對應

對應 apply playbook：`playbooks/apply/pam-oidc-sshd-apply.yml`

| Spec ID | Apply task | 備註 |
|---------|------------|------|
| C1 | `install build deps` | apt: golang, libpam0g-dev, build-essential |
| C2 | `install pam_keycloak_device.so` | make install 或直接 copy build/ |
| C3 | `backup /etc/pam.d/sshd` | 同一 block 必須在 C4 之前 |
| C4 | `lineinfile pam_keycloak_device.so in /etc/pam.d/sshd` | idempotent |
| C5 | `sshd -T parse smoke` | command |
| C6 | `install keycloak-ssh-monitor` | make install 或 copy build/ |
| C7 | `install systemd unit` | make install 或 copy configs/systemd/ |
| C8 | `render config.yaml — server_url` | keycloak.server_url |
| C9 | `render config.yaml — realm` | keycloak.realm |

## 7. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-06-29 | v1.0 | 初版（錯誤假設無上游 kc-ssh-pam deb） | pilot |
| 2026-07-01 | v2.0 | 重寫對齊真實上游 `kha7iq/kc-ssh-pam`：pam_keycloak_device.so、/etc/keycloak-ssh/、keycloak.server_url YAML key、keycloak-ssh-monitor daemon | pilot |
