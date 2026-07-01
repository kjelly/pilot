# Runbook — pam-oidc-sshd end-to-end on `bastion`

> 目標：在 `bastion` VM 上安裝 `kha7iq/kc-ssh-pam`，讓工程師可用 Keycloak Device Flow（瀏覽器登入 + MFA）透過 SSH 認證，認證端為 `core` 主機的 Keycloak。

---

## §0 事實快照

### 0.1 VM 狀態
```bash
go run ./cmd/pilot vm-target list
```
```
NAME     STATUS   IP               VCPU  MEM(MiB)  CREATED
core     running  192.168.123.234  2     2048      2026-07-01T08:13:12
bastion  running  192.168.124.143  2     2048      2026-07-01T10:09:42
```

### 0.2 Inventory aliases
```bash
go run ./cmd/pilot vm-target show-inventory --name bastion | grep -E "^    [a-z]"
```
```
    bastion:
    linux-servers:     ← 這是 pam-oidc-sshd spec 的預設 group
```

### 0.3 Network routing（重要！）
`bastion` 在 `pilot-bastion` isolated network，`core` 在 `default` network，
兩者隔離。以下 route 必須存在（host 上執行一次，VM 重啟後可能需要重加）：
```bash
# 在 host 上執行（需要 sudo）
sudo iptables -I LIBVIRT_FWI -s 192.168.124.0/24 -j ACCEPT
```

在 bastion VM 內執行：
```bash
ssh -i /var/lib/libvirt/images/pilot/bastion/id_ed25519 \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  root@192.168.124.143 \
  'ip route add 192.168.123.0/24 via 192.168.124.1 dev enp1s0 2>/dev/null || true'
```

在 bastion VM 內執行（讓 Keycloak URL 可解析）：
```bash
ssh -i /var/lib/libvirt/images/pilot/bastion/id_ed25519 \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  root@192.168.124.143 \
  'grep -q "192.168.123.234.*idp.infra.internal" /etc/hosts \
   || echo "192.168.123.234 idp.infra.internal" >> /etc/hosts'
```

### 0.4 依賴的 vault/環境變數
```
KEYCLOAK_ISSUER = https://idp.infra.internal:8080/realms/master
```
（從 `core` 上已正常運作的 Keycloak）

---

## §1 Keycloak Client 設定（在 `core` 主機的 Keycloak 上操作）

> **這些步驟在 Keycloak Admin Console 操作**，URL：`http://192.168.123.234:8080/admin/`

### 1.1 建立 Client
1. 登入 Keycloak Admin Console
2. 選擇 realm `master`
3. 進入 **Clients** → **Create client**
4. 填入：
   - **Client type**: `OpenID Connect`
   - **Client ID**: `ssh-pam-client`
5. 點 **Next**，啟用：
   - **OAuth 2.0 Device Authorization Grant**: ✅ ON
6. 點 **Save**

### 1.2 設定 Backchannel Logout
在 client 設定頁面：
1. **Backchannel logout URL**: `http://192.168.124.143:7291/backchannel-logout`
2. **Backchannel logout session required**: ✅ ON
3. **Front channel logout**: OFF
4. **Save**

### 1.3 建立測試 user
1. 進入 **Users** → **Add user**
2. **Username**: `testuser`（必須與 bastion VM 上的 Linux username 完全一致）
3. **Create**
4. 進入 **Credentials** → **Set password** → 設定密碼（此密碼在 Device Flow 中仍需用於 Keycloak 登入）

---

## §2 Apply — 在 `bastion` 上安裝 kc-ssh-pam

### 2.1 Dry run / preview（先做這個）
```bash
cd /home/ubuntu/nfs/github/pilot

go run ./cmd/pilot vm-target run --name bastion \
  playbooks/apply/pam-oidc-sshd-apply.yml \
  -e keycloak_server_url=https://idp.infra.internal:8080 \
  -e keycloak_realm=master \
  -e keycloak_client_id=ssh-pam-client \
  --check --diff 2>&1 | head -100
```

**預期**：PLAY RECAP 全部 `ok=N  changed=0  failed=0`（check mode 無實際變更）

### 2.2 Real apply
```bash
cd /home/ubuntu/nfs/github/pilot

go run ./cmd/pilot vm-target run --name bastion \
  playbooks/apply/pam-oidc-sshd-apply.yml \
  -e keycloak_server_url=https://idp.infra.internal:8080 \
  -e keycloak_realm=master \
  -e keycloak_client_id=ssh-pam-client \
  2>&1 | tail -50
```

**預期 PLAY RECAP**：
```
bastion  : ok=18  changed=12   unreachable=0    failed=0
```

### 2.3 確認 SSH 仍可正常登入（套用後不應 lockout）
```bash
ssh -i /var/lib/libvirt/images/pilot/bastion/id_ed25519 \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  root@192.168.124.143 \
  'echo "SSH OK after apply: $(hostname)"'
```

---

## §3 Verify — 確認所有 spec rows pass

### 3.1 Run verify
```bash
cd /home/ubuntu/nfs/github/pilot

go run ./cmd/pilot vm-target verify --name bastion \
  docs/verification/pam-oidc-sshd.md 2>&1
```

### 3.2 預期輸出
```
PASS 9/9

C1  pass  — build deps installed
C2  pass  — pam_keycloak_device.so exists
C3  pass  — /etc/pam.d/sshd.kcsssh.bak backup exists
C4  pass  — pam_keycloak_device.so wired in /etc/pam.d/sshd
C5  pass  — sshd -T parseable
C6  pass  — keycloak-ssh-monitor binary exists
C7  pass  — keycloak-ssh-monitor.service exists
C8  pass  — server_url uses https in config
C9  pass  — realm non-empty in config
```

---

## §4 測試 SSH + Keycloak Device Flow（功能性測試）

### 4.1 從本機嘗試 SSH（會觸發 Device Flow）

> ⚠️ 此測試需要瀏覽器可存取 Keycloak URL。`core` 的 Keycloak 監聽在 192.168.123.234:8080，
> bastion 的 route 已設定好。如果從 host 直接測試，需要 host 可路由到 192.168.123.234。

```bash
# 在 bastion 本機測試（不走 SSH key，直接觸發 pam_keycloak_device.so 的互動式流程）
# 這需要從另一個 terminal SSH 進去：
ssh -o PreferredAuthentications=keyboard-interactive \
  -o StrictHostKeyChecking=no \
  testuser@192.168.124.143
```

預期終端機輸出：
```
  ╔══════════════════════════════════════════════════════╗
  ║         🔐 Keycloak SSH Authentication              ║
  ╚══════════════════════════════════════════════════════╝

  Complete your login in the browser:
  👉 https://idp.infra.internal:8080/realms/master/device?user_code=XXXX-YYYY

  Press ENTER after completing browser login:
```

### 4.2 驗證 /etc/keycloak-ssh/config.yaml 內容
```bash
ssh -i /var/lib/libvirt/images/pilot/bastion/id_ed25519 \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  root@192.168.124.143 \
  'cat /etc/keycloak-ssh/config.yaml'
```

確認包含正確的 `server_url`、`realm`、`client_id`。

---

## §5 如果套用失敗 / Lockout 救援

### 5.1 自動 Rollback
Apply playbook 使用 `block/rescue` 架構。任何修改 `/etc/pam.d/sshd` 的 task 失敗時，
rescue block 會自動執行：
```bash
cp /etc/pam.d/sshd.kcsssh.bak /etc/pam.d/sshd
```
SSH 應該在 rollback 後恢復正常。

### 5.2 手動救援（如果 playbook 完全失敗）
```bash
ssh -i /var/lib/libvirt/images/pilot/bastion/id_ed25519 \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  root@192.168.124.143 \
  'cp /etc/pam.d/sshd.kcsssh.bak /etc/pam.d/sshd 2>/dev/null; echo "Restored"'
```

---

## §6 上游參考

| 資源 | URL |
|------|-----|
| kha7iq/kc-ssh-pam GitHub | https://github.com/kha7iq/kc-ssh-pam |
| 使用的 fork | https://github.com/omidiyanto/keycloak-ssh-pam-module |
| PAM 模組 | `pam_keycloak_device.so` |
| Config 路徑 | `/etc/keycloak-ssh/config.yaml` |
| Monitor daemon | `keycloak-ssh-monitor` (systemd) |
| 預設監聽 port | 7291 |

---

## §7 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-01 | v1.0 | 初版（spec v2.0 重寫後的 end-to-end runbook）| pilot |
