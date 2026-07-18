# Verification Spec — core-infra (Internal DNS + Time Sync + Identity Provider)

> 版本：v1.0
> 對齊規範：pilot 通用基礎設施驗證規範（任何部署 staging / prod 的主機都需要滿足這份 spec）
> 維護者：sre

## 1. 目標系統

| Hostname   | Group     | Address          | User   | Port | IdentityFile                |
|------------|-----------|------------------|--------|------|------------------------------|
| test-vm    | all       |                  |        |      |                              |
| infra-1    | infra     |                  |        |      |                              |
| edge-*     | edge      |                  |        |      |                              |

> 所有 Address/User/IdentityFile 留空、用 `--from-ssh-config` 從 `~/.ssh/config` 補。

## 2. Checklist

| ID  | Category    | Check                                                                          | Expected | Command |
|-----|-------------|--------------------------------------------------------------------------------|----------|---------|
| C1  | dns         | 本機 `/etc/resolv.conf` 第一個 nameserver 為 `127.0.0.1` (本地 resolver)  | present  | awk 'NR==1{print $2}' /etc/resolv.conf |
| C2  | dns         | `systemd-resolved` 服務在跑                                                 | ~active  | systemctl is-active systemd-resolved |
| C3  | dns         | 本機至少能解析 `infra.internal` 與 `keycloak.infra.internal` 兩條 host 紀錄 | 0        | sh -c 'getent hosts infra.internal; getent hosts keycloak.infra.internal' |
| C4  | time        | `systemd-timesyncd` 服務在跑                                                | ~active  | systemctl is-active systemd-timesyncd |
| C5  | time        | NTP 同步有 source server 且 offset ≤ 100ms                                  | ~Offset  | sh -c 'timedatectl timesync-status 2>&1 \| grep -E "Server:|Offset:"' |
| C6  | identity    | Keycloak OIDC discovery endpoint 可達，回 200 OK                             | 200      | sh -c 'curl -fsS -o /dev/null -w "%{http_code}" $KEYCLOAK_ISSUER/.well-known/openid-configuration' |
| C7  | identity    | Keycloak discovery JSON 含 `issuer` 欄位且值跟 `$KEYCLOAK_ISSUER` 完全一致   | 0        | sh -c 'curl -fsS $KEYCLOAK_ISSUER/.well-known/openid-configuration \| grep -q "\"issuer\": \"$KEYCLOAK_ISSUER\""' |
| C8  | identity    | realm `master` 為 `enabled=true`、`accessTokenLifespan` ≤ 24h              | enabled  | sh -c 'curl -fsS -H "Authorization: Bearer $KEYCLOAK_TOKEN" $KEYCLOAK_ISSUER/realms/master \| grep -E "\"enabled\": true"' |

> 每個 row 都是 policy-as-code — 任何 C*N fail 就擋掉 prod/staging 准入。
> C6 / C7 / C8 透過 `$KEYCLOAK_ISSUER` + `$KEYCLOAK_TOKEN` 環境變數帶入，
>   spec 不可寫死 URL / token，符合通用工具 repo 政策。
> C5 用 `~Offset` 作為 substring 哨兵 — 不同 systemd 版本對 `timedatectl timesync-status` 欄位順序略不同，但只要有 sync source 就一定有 `Offset:` 行。

### 補上 X-Env 變數（跑 spec 前先 `export`）

```bash
export KEYCLOAK_ISSUER=https://keycloak.infra.internal/realms/master
export KEYCLOAK_TOKEN=$(kubectl get secret keycloak-admin -o jsonpath='{.data.password}' | base64 -d)
```

## 3. 證據收集

- 工具：`pilot verify docs/verification/core-infra.md --inventory infra.yaml`
- 格式：`.verification/core-infra-<UTC>.{ndjson,md}`
- Row 數：8

範例輸出（dev box 沒裝內部 DNS / Keycloak；C1, C3, C6, C7, C8 預期 fail）：

```json
{"id":"C1","status":"pass","detail":"127.0.0.1"}
{"id":"C3","status":"fail","detail":"getent: can't resolve 'infra.internal'"}
{"id":"C6","status":"fail","detail":"000 (keycloak_unreachable)"}
```

## 4. PASS / FAIL 規則

- C1–C8 全部 `status=pass` → **PASS**：本機內部 DNS / NTP / Keycloak 三者皆綠
- 任一 fail → **FAIL**；常見解法：
  - C1 fail → 重啟 systemd-resolved 或檢查 `/etc/systemd/resolved.conf`
  - C3 fail → 內部 DNS zone 未送達此 host；檢查 `unbound`/`dnsmasq` 服務與 zone 檔
  - C5 fail → NTP offset 超標；先檢查 `/var/log/syslog | grep -i ntp`
  - C6-C8 fail → Keycloak 不可達 / 設定不符

## 5. 例外與已知偏差

| ID | 例外內容                                         | 適用環境   | 期限      |
|----|-------------------------------------------------|-----------|----------|
| C3 | RHEL 預設無 systemd-resolved，改用 `nsswitch.conf`| RHEL 系列  | 永不      |
| C6 | 開發 / CI 無法連 staging Keycloak；用 mock endpoint | dev box    | 至 prod 上線 |
| C5 | VM suspend 之後 offset 重置，sync 需 ≥ 30s 才回到 ≤ 100ms | laptop / VM | 無       |

## 6. Playbook 對應

對應的 verify playbook（`playbooks/verify/core-infra.yml`）**已於 2026-07-17 棄用**（僅存檔參考，見該目錄 README.md）；驗收直接 `pilot verify` 吃本 spec 執行。

對應手寫的 **apply** playbook：`playbooks/apply/core-infra-apply.yml`

| Spec ID | Apply task | 備註 |
|---------|-----------|------|
| C1      | 寫 `/etc/systemd/resolved.conf` + 設 stub listener | via `copy` |
| C2      | 啟用並 `systemctl enable --now systemd-resolved` | `service` module |
| C3      | 寫內部 `hosts` 紀錄 或 unbound zone stub | `copy` or `template` |
| C4      | 啟用 timesyncd、`/etc/systemd/timesyncd.conf` 配 NTP | `service` + `lineinfile` |
| C5      | 自動驗證；apply 後只 `timedatectl` 觸發一次 sync | `command` |
| C6-C8   | Keycloak client setup (Token exchange、verify)、DNS record 注入 | `lineinfile` + curl |

> Apply playbook 必須 stage-gated (`-e infra_stage=sandbox|staging|prod`)，
>   而且 Keycloak token 必須從 vault / `-e @vault.yaml` 拿，絕不放進 CLI argv。
> Block/rescue：DNS 改壞 (e.g. 失去 `/etc/resolv.conf`) 自動還原 backup。

## 7. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-06-30 | v1.0 | 初版（C1–C8）| pilot |
