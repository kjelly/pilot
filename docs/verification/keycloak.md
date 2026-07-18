# Verification Spec — keycloak (Keycloak server, identity provider)

> 版本：v1.0
> 對齊規範：pilot 通用基礎設施**服務端**規範（Keycloak 子集 —
> 為 `core-infra` 的 consumer spec / `pam-oidc-sshd` 的 client 提供 OIDC IdP）
> 維護者：sre

> 對偶參照：使用端健康見 `core-infra.md`（C6–C8：discovery 200、issuer
> 對應、realm enabled）；本檔是 **Keycloak provider 健康**。
> 從 `core-infra-provider.md`（v1.x）拆出 — 原本 Keycloak C7–C9
> 跟 DNS / NTP 擠在同一份，拆出後 DNS / NTP 走 `core-infra-provider.md`、
> Keycloak 走本檔、Keycloak 的 DB backing store 走 `core-infra-provider-db.md`
> （已獨立）。

## 1. 目標系統

| Hostname | Group     | Address | User | Port | IdentityFile |
|----------|-----------|---------|------|------|--------------|
| core     | keycloak  |         |      |      |              |
| idp-1    | keycloak  |         |      |      |              |

> `keycloak` group 是本檔預設目標。`idp-1` 是 spec 設計的標準命名（與
> `core-infra-provider-db.md` § 1 對偶；該檔 § 1 用 `keycloak-db` group，
> 本檔用 `keycloak` group 對應 Keycloak server）。`core` 是當下 vm-target
> sibling-of-vm-target 情境下與 `idp-1` 對應的 host alias。

## 2. Checklist

| ID | Category   | Check                                                                              | Expected | Command |
|----|------------|------------------------------------------------------------------------------------|----------|---------|
| C7 | keycloak   | keycloak process 可見（容器或 binary；容忍任何啟動方式）                                    | present  | sh -c 'pidof java >/dev/null 2>&1 || pidof kc.sh >/dev/null 2>&1; echo $?' |
| C8 | keycloak   | HTTP listener 8080 / 8443 至少一個在 LISTEN                                              | ~1       | sh -c 'ss -tulnH | awk "/:8080/ \|\| /:8443/ {f=1} END{print f+0}" ' |
| C9 | keycloak   | OIDC discovery endpoint 回 200                                                       | ~200     | sh -c 'curl -fsS -o /dev/null -w "%{http_code}" "${KEYCLOAK_ISSUER:-http://idp.infra.internal:8080/realms/master}/.well-known/openid-configuration"' |

### 補上 env 變數（跑 spec 前先 `export`）

```bash
export KEYCLOAK_ISSUER=https://idp.infra.internal/realms/master
```

> Secret / token 不進版控：`$KEYCLOAK_ISSUER` 是 URL，安全；admin token
> 跟 password 由 vault file (`-e @~/.vault/keycloak-sandbox.yaml`) 在 apply
> playbook 階段帶入，變數名：`kc_admin_user` / `kc_admin_password`、
> `kc_db_user` / `kc_db_password`、
> `pg_keycloak_db_password`（db provider 用的 PG password），
> 不污染 spec。

## 3. 證據收集

- 工具：`pilot verify docs/verification/keycloak.md -i inventory-core-infra.yaml -l keycloak`
- 格式：`.verification/keycloak-<UTC>.{ndjson,md}`
- Row 數：3（C7–C9；不沿用 C1–C6 — Keycloak spec 只看自己三條檢查）

範例輸出（dev box 沒裝 Keycloak → 3/3 fail，這正是預期）：

```json
{"id":"C7","status":"fail","detail":"rc=1 — pgrep returned 0"}
{"id":"C8","status":"fail","detail":"rc=1 — no 8080/8443 listener"}
{"id":"C9","status":"fail","detail":"rc=2 — discovery endpoint unreachable"}
```

## 4. PASS / FAIL 規則

- C7–C9 全部 `status=pass` → **PASS**：本機已準備好提供 Keycloak IdP
- 任一 fail → **FAIL**，常見修法：
  - C7 fail → Keycloak container / process 沒起；`docker ps -a` / `pidof java`
  - C8 fail → Keycloak 8080 沒 LISTEN；`docker logs pilot-keycloak` /
    `journalctl -u keycloak`
  - C9 fail → discovery 路徑或 issuer 拼錯；檢查 `$KEYCLOAK_ISSUER`、
    確認 `idp.infra.internal` 在 `/etc/hosts` 或 DNS 有解

## 5. 例外與已知偏差

| ID | 例外內容                                                       | 適用環境 | 期限 |
|----|--------------------------------------------------------------|---------|------|
| C8 | container 剛起時 8080 還沒 LISTEN；先 poll 60×5s retry           | 任何     | retry 60 次後穩定 |
| C9 | `KC_HOSTNAME=idp.infra.internal` 未在外部 DNS 註冊時，spec 跑前需 `echo 127.0.0.1 idp.infra.internal >> /etc/hosts`（apply 段已加）| sandbox | 永久 |

## 6. Playbook 對應

對應的 verify playbook（`playbooks/verify/keycloak.yml`）**已於 2026-07-17 棄用**（僅存檔參考，見該目錄 README.md）；驗收直接 `pilot verify` 吃本 spec 執行。

對應手寫的 **apply** playbook：`playbooks/apply/keycloak-apply.yml`

| Spec ID | Apply task (示例)                                                | 備註 |
|---------|------------------------------------------------------------------|------|
| C7      | `community.docker.docker_container: name=pilot-keycloak, state=started` | 容器內 `pidof java` 對到 row 通過 |
| C8      | `docker run … -p 8080:8080`（或 `start --http-enabled=true`）        | row 透過 `ss -tulnH` 驗 LISTEN |
| C9      | `lineinfile /etc/hosts: 127.0.0.1 idp.infra.internal` + 起 KC      | `KC_HOSTNAME=idp.infra.internal` 對到 row 通過 |

> Apply playbook 用 `community.docker.docker_container` 起 Keycloak
> container，data dir bind-mount 到 host `/var/lib/pilot/keycloak`。
> 容器以 uid=0 跑（Keycloak 的 narayana JTA object store 需要寫
> transaction-logs 到 bind-mount 的 `/opt/keycloak/data`）。
> DB backing 走 `playbooks/apply/keycloak-db-apply.yml`（同 vm-target
> 上跑）；Keycloak 容器透過 docker network `pilot-infra` 找
> `postgres` hostname（`KC_DB_URL=jdbc:postgresql://postgres:5432/keycloak`）。

## 7. 把 FAIL 變 PASS 的 SOP

```bash
# 0. Lint
go run ./cmd/pilot spec docs/verification/keycloak.md --lint
# spec Verification Spec — keycloak (Keycloak server, identity provider): 3 rows, 0 findings (0 errors)

# 1. （此步驟已棄用 2026-07-17）不再產生 playbooks/verify/keycloak.yml——
#    驗收由後面的 `pilot verify`/`vm-target verify` 直接吃本 spec 執行

# 2. 套前先看 keycloak-db 已經 PASS（Keycloak 啟動需要 DB）
go run ./cmd/pilot vm-target verify --name core \
    docs/verification/core-infra-provider-db.md
# 預期 11/11 PASS

# 3. 套 keycloak role
go run ./cmd/pilot vm-target run --name core \
    playbooks/apply/keycloak-apply.yml \
    -e target_group=keycloak \
    -e kc_admin_password=sandbox-admin-password-123 \
    -e kc_db_password=sandbox-db-password-123
# PLAY RECAP: ok=N changed=M failed=0
#   - mkdir /var/lib/pilot/keycloak
#   - lineinfile /etc/hosts (idp.infra.internal → 127.0.0.1)  ← spec C9 needs this
#   - docker pull quay.io/keycloak/keycloak:25.0
#   - docker run pilot-keycloak
#   - poll /realms/master 8080 for ready (60 retries × 5s)

# 4. 同步驗證
go run ./cmd/pilot vm-target verify --name core \
    docs/verification/keycloak.md
# verdict: **PASS**  (pass=3 fail=0 skip=0)
```

> 順序：docker → db → keycloak。**`core-infra-provider-db.md`** 11/11 PASS
> 是 `keycloak.md` PASS 的前提；**`keycloak.md`** PASS 又是
> **`core-infra.md`** C6–C8 從 FAIL 變 PASS 的前提。詳見對應 runbook。

## 8. 變更紀錄

| 日期       | 版本 | 變更                                                                                                  | 變更者 |
|------------|------|------------------------------------------------------------------------------------------------------|--------|
| 2026-07-02 | v1.0 | 從 `core-infra-provider.md` v1.0 拆出 C7–C9；spec §1 對齊 inventory `keycloak` / `core` / `idp-1` group | sre    |
