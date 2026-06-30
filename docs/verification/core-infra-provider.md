# Verification Spec — core-infra-provider (Internal DNS + NTP + Keycloak server)

> 版本：v1.0
> 對齊規範：pilot 通用基礎設施**服務端**規範（這份 host 是要提供 internal DNS、NTP、Keycloak 的那台，而不是使用端）
> 維護者：sre

> 對偶參照：使用端健康見 `core-infra.md`；本檔是提供者健康。

## 1. 目標系統

| Hostname     | Group          | Address          | User   | Port | IdentityFile  |
|--------------|----------------|------------------|--------|------|---------------|
| infra-1      | infra-provider |                  |        |      |               |

> 同一台 host 可同時跑 DNS / NTP / Keycloak。`infra-provider` group 是本檔預設目標。

## 2. Checklist

| ID | Category  | Check                                                                              | Expected    | Command |
|----|-----------|------------------------------------------------------------------------------------|-------------|---------|
| C1 | dns       | DNS 服務 daemon 已安裝（unbound / bind9 / dnsmasq 三擇一；至少一個）                       | 1           | sh -c 'dpkg-query -W -f=%{Package} bind9 bind9-dnsutils bind9-host bind9-libs unbound dnsmasq 2>/dev/null | grep -xE "(unbound|bind9|dnsmasq)" | head -n1 | wc -l' |
| C2 | dns       | DNS 服務在本機 listening，且不是 systemd-resolved stub (`127.0.0.53`)                  | present     | sh -c 'ss -tulnH \| grep ":53 " \| grep -v "127.0.0.53" \| head -n1' |
| C3 | dns       | 本機是 authoritive（本機 resolv.conf 第一個 nameserver 不是 127.0.0.1）                     | 0           | awk 'NR==1{print $2}' /etc/resolv.conf \| grep -qE '^(127\.[0-9]+\.[0-9]+\.[0-9]+|::1)$' |
| C4 | ntp       | NTP daemon 已安裝（chrony / ntp / ntpsec 三擇一；至少一個）                              | 1           | sh -c 'dpkg-query -W -f=%{Package} chrony ntp ntpsec 2>/dev/null | grep -xE "(chrony|ntp|ntpsec)" | head -n1 | wc -l' |
| C5 | ntp       | chronyd 或 ntpd active                                                            | ~active     | systemctl is-active chronyd ntpd 2>&1 \| head -n1 |
| C6 | ntp       | Stratum ≤ 5（本機沒被上上游設成 leaf-of-leaf）                                          | ~Stratum    | timedatectl show-timesync 2>&1 \| grep -oE 'Stratum=[0-5]' |
| C7 | keycloak  | keycloak process 可見（容器或 binary；容忍任何啟動方式）                                    | present     | pidof keycloak 2>/dev/null |
| C8 | keycloak  | HTTP listener 8080 / 8443 至少一個在 LISTEN                                              | 1           | sh -c 'ss -tulnH | grep -E ":(8080|8443)\b" | head -n1 | wc -l' |
| C9 | keycloak  | OIDC discovery endpoint 回 200                                                       | 200         | sh -c 'curl -fsS -o /dev/null -w "%{http_code}" $KEYCLOAK_ISSUER/.well-known/openid-configuration' |

### 補上 env 變數（跑 spec 前先 `export`）

```bash
export KEYCLOAK_ISSUER=https://idp.infra.internal/realms/master
```

> Secret / token 不進版控：`$KEYCLOAK_ISSUER` 是 URL，安全；admin token
>   跟 password 由 vault file (`-e @keycloak-vault.yaml`) 在 apply playbook 階段帶入，
>   不污染 spec。

## 3. 證據收集

- 工具：`pilot verify docs/verification/core-infra-provider.md -i infra.yaml`
- 格式：`.verification/core-infra-provider-<UTC>.{ndjson,md}`
- Row 數：9

範例輸出（dev box 沒裝任何 DNS / NTP / Keycloak → 9/9 fail，這正是預期）：

```json
{"id":"C1","status":"fail","detail":"rc=1 — no dns package installed"}
{"id":"C4","status":"fail","detail":"rc=1 — no ntp package installed"}
{"id":"C7","status":"fail","detail":"rc=1 — pgrep returned 0"}
{"id":"C9","status":"fail","detail":"rc=2 — discovery endpoint unreachable"}
```

## 4. PASS / FAIL 規則

- C1–C9 全部 `status=pass` → **PASS**：本機已準備好提供 internal DNS / NTP / Keycloak 三項服務
- 任一 fail → **FAIL**，常見修法：
  - C1 fail → `apt install unbound`（推薦）或 `bind9` / `dnsmasq`
  - C4 fail → `apt install chrony`（推薦，NTS 支援）
  - C6 fail → NTP 上游設定錯誤，重檢 `pool.ntp.org` / `ntp.ubuntu.com`
  - C7 / C8 fail → Keycloak container 没起；先 `podman logs keycloak`
  - C9 fail → discovery 路徑或 issuer 拼錯；檢查 `$KEYCLOAK_ISSUER`

## 5. 例外與已知偏差

| ID | 例外內容                                              | 適用環境   | 期限      |
|----|------------------------------------------------------|-----------|----------|
| C2 | 在 docker-desktop / kind node 內跑時會誤抓到 host DNS service  | laptop/VM | 排除 local DNS |
| C5 | RHEL 套件名為 `chronyd`，systemd unit 為 `chronyd.service` 不是 `chrony`；spec 用 `chronyd ntpd` 兩個名字涵蓋      | RHEL    | 永久     |

## 6. Playbook 對應

對應產生的 **verify** playbook：`playbooks/verify/core-infra-provider.yml`（spec generator）

對應手寫的 **apply** playbook：`playbooks/apply/core-infra-provider-apply.yml`

| Spec ID | Apply task (示例)                              | 備註 |
|---------|-----------------------------------------------|------|
| C1-C3   | `apt` install unbound + `block/rescue` 切 dns | stage=sandbox 跑一次 dry-run；backup `/etc/systemd/resolved.conf` 防 lockout |
| C4-C6   | `apt` install chrony + NTP pool 上游          | chrony 預設接 ubuntu pool + NTS |
| C7-C9   | `podman` / `k8s` 起 keycloak                   | template-driven、admin token 由 vault 注入 |

> Apply playbook 必須 `block/rescue` 保護：例如關閉 systemd-resolved stub 改 server 模式失敗，
> 自動還原 `/etc/systemd/resolved.conf` 的 backup，避免 DNS 黑洞把 host 連線全斷。

## 7. 把 FAIL 變 PASS 的 SOP

```bash
# 1. 套前先看這台 host 是哪一個 group
ansible infra-1 -i inventory.yaml -m shell -a "id; hostname"

# 2. 套 dns provider（以 unbound 為例）
ansible-playbook -i inventory.yaml \
    playbooks/apply/core-infra-provider-apply.yml \
    -e provider_stage=sandbox \
    -e dns_provider=unbound \
    -e dns_upstream='1.1.1.1#cloudflare-dns.com 9.9.9.9#quad9.net'

# 3. 套 ntp provider
ansible-playbook -i inventory.yaml \
    playbooks/apply/core-infra-provider-apply.yml \
    -e provider_stage=sandbox \
    -e ntp_provider=chrony \
    -e ntp_pool='ntp.ubuntu.com pool.ntp.org'

# 4. 套 keycloak provider（要塞 env-vars from vault）
ansible-playbook -i inventory.yaml \
    playbooks/apply/core-infra-provider-apply.yml \
    -e provider_stage=sandbox \
    -e keycloak_realm=master \
    -e @~/.vault/keycloak-sandbox.yaml   # contains KEYCLOAK_ADMIN_USER / PASS
```

> 設 `provider_stage=prod` 額外需要 `-e confirm_prod=true` 確認 gate。
> 第一次 dry-run 一律 `--check --diff`。

## 8. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-06-30 | v1.0 | 初版（C1–C9）| pilot |
