# Verification Spec — core-infra-provider-db (PostgreSQL backing store for Keycloak — Docker)

> 版本：v2.0
> 對齊規範：pilot 通用基礎設施**服務端**規範（PostgreSQL 子集 — 為 `core-infra-provider` 的 Keycloak role 提供 backing DB；PG 跑在 Docker container 內，data dir bind-mount 到 host）
> 維護者：sre

> 對偶參照：使用端健康見 `core-infra.md`；Keycloak provider 健康見 `core-infra-provider.md`；
> 本檔是 **DB provider 健康**（PostgreSQL container + 為 Keycloak 開好的 `keycloak` database + role）。
>
> v2.0：把 PG 從 host 換成 docker container（apply 段 `infra_role=db` 用
> `community.docker.docker_container` 起 `pilot-postgres` image `postgres:16`，
> data dir bind-mount 到 `/var/lib/pilot/postgres`）。spec 改為「對 docker
> 物件 + PG state」雙重檢查。

## 1. 目標系統

| Hostname     | Group          | Address          | User   | Port | IdentityFile  |
|--------------|----------------|------------------|--------|------|---------------|
| keycloak-db  | keycloak-db    |                  |        |      |               |
| db           | db             |                  |        |      |               |
| docker       | docker         |                  |        |      |               |
| core         | core           |                  |        |      |               |

> 同一台 host 可同時是 4 個 group（sibling-of-vm-target）。`keycloak-db` group
> 是 spec 設計的標準命名；`db` 是當下 inventory 裡實際有的 alias。`docker` 是
> PG container 跑起來的 engine；`core` 是 primary host name。

## 2. Checklist

| ID  | Category    | Check                                                                                | Expected | Command |
|-----|-------------|--------------------------------------------------------------------------------------|----------|---------|
| C1  | docker      | `pilot-postgres` container 存在且 running                                              | ~pilot-postgres | /usr/bin/docker ps --no-trunc 2>/dev/null | grep -m1 -oE 'pilot-postgres' | head -n1 |
| C2  | docker      | postgres container image 是 `postgres:16`（或 `pg_version` 變數）                          | ~postgres: | /usr/bin/docker ps --no-trunc 2>/dev/null | grep -m1 -oE 'postgres:[0-9]+' | head -n1 |
| C3  | port        | 5432/tcp 在 host 上 LISTEN（container port mapping `127.0.0.1:5432:5432`）                   | present  | ss -tulnH | grep ":5432 " | grep -vE "127\.0\.0\.(1|53|54)" | head -n1 |
| C4  | db          | `keycloak` database 已建立（在 container 內 query）                                       | ~1       | /usr/bin/docker exec pilot-postgres psql -U keycloak -d keycloak -tAc "SELECT 1 FROM pg_database WHERE datname='keycloak'" 2>/dev/null | head -n1 |
| C5  | role        | `keycloak` role 已建立（具備 LOGIN）                                                   | ~1       | /usr/bin/docker exec pilot-postgres psql -U keycloak -tAc "SELECT 1 FROM pg_roles WHERE rolname='keycloak' AND rolcanlogin" 2>/dev/null | head -n1 |
| C6  | ownership   | `keycloak` database 的 owner 是 `keycloak` role                                       | ~keycloak | /usr/bin/docker exec pilot-postgres psql -U keycloak -tAc "SELECT pg_catalog.pg_get_userbyid(datdba) FROM pg_database WHERE datname='keycloak'" 2>/dev/null | head -n1 |
| C7  | connectivity| 用 `keycloak` role 從 host 透過 TCP 連 DB，能 SELECT 1                                     | 0        | PGPASSWORD=${KEYCLOAK_DB_PASSWORD} psql -h 127.0.0.1 -U keycloak -d keycloak -tAc "SELECT 1" 2>/dev/null; echo "rc=$?" |
| C8  | volume      | host 的 `/var/lib/pilot/postgres` 有 bind-mount 到 container 的 `/var/lib/postgresql/data` | ~pilot  | /usr/bin/docker inspect pilot-postgres 2>/dev/null | grep -m1 -oE '/var/lib/pilot/postgres' | head -n1 |
| C9  | healthcheck | postgres container healthcheck 為 `healthy`                                            | ~healthy | /usr/bin/docker ps --no-trunc 2>/dev/null | grep -m1 -oE '\(healthy\)' | head -n1 |
| C10 | discover    | `pg_isready` 回 `accepting connections`（host 上透過 `docker exec`）                       | ~accepting | /usr/bin/docker exec pilot-postgres pg_isready -h 127.0.0.1 -p 5432 2>&1 | head -n1 |
| C11 | capacity    | DB size `< 10 GiB`（防 Keycloak 寫爆磁碟沒人發現）                                          | 0        | /usr/bin/docker exec pilot-postgres psql -U keycloak -tAc "SELECT CASE WHEN pg_database_size(datname) < 10737418240::bigint THEN 0 ELSE 1 END FROM pg_database WHERE datname='keycloak'" 2>/dev/null |

> C7 透過 `$KEYCLOAK_DB_PASSWORD` 環境變數帶入；`pilot verify` 跑前先 `export`。
> Secret / token 不進版控；`$KEYCLOAK_DB_PASSWORD` 由 vault file 在 apply 階段帶入。
> C4/C5/C6/C11 內 `'keycloak'` 用 chr() 拼字串，避開 markdown cell 拆欄位時的 `|` 衝突。

### 補上 env 變數（跑 spec 前先 `export`）

```bash
export KEYCLOAK_DB_PASSWORD=...    # 從 vault / 申請 / k8s secret 來；不走 spec
```

## 3. 證據收集

- 工具：`pilot verify docs/verification/core-infra-provider-db.md -i inventory-core-infra.yaml -l keycloak-db`
- 格式：`.verification/core-infra-provider-db-<UTC>.{ndjson,md}`
- Row 數：11（C1–C11）

範例輸出（dev box 沒裝 docker / 沒起 PG container → 11/11 fail，預期）：

```json
{"id":"C1","status":"fail","detail":"(rc=1) ... Error: No such object: pilot-postgres"}
{"id":"C3","status":"fail","detail":"(rc=0) ... empty stdout"}
```

## 4. PASS / FAIL 規則

- C1–C11 全部 `status=pass` → **PASS**：本機已準備好做為 Keycloak 的 PostgreSQL backing store
- 任一 fail → **FAIL**；常見修法：
  - C1 / C2 fail → container 沒起 / image 拉錯；先 `docker ps -a`、`docker logs pilot-postgres`
  - C3 fail → port 沒 map；檢查 `docker inspect` 的 PortBindings
  - C4 / C5 / C6 fail → apply 沒建好 db/role/owner；`docker exec -u postgres pilot-postgres psql` 進去手動補
  - C7 fail → 密碼不對或 pg_hba 拒絕；先 `docker logs pilot-postgres` 看
  - C8 fail → bind-mount 沒接上；`docker inspect` 查 Mounts
  - C9 fail → healthcheck 失敗（pg_isready 沒回 0）；先 `docker exec pilot-postgres pg_isready`
  - C10 fail → pg_isready 在 container 內也 fail；`docker logs`
  - C11 fail → DB 超過 10 GiB；先 `docker exec -u postgres pilot-postgres psql -c "SELECT pg_size_pretty(pg_database_size('keycloak'))"`

## 5. 例外與已知偏差

| ID  | 例外內容                                                                       | 適用環境       | 期限     |
|-----|------------------------------------------------------------------------------|---------------|----------|
| C2  | `pg_version` 預設 16；可由 `-e pg_version=15` 改                              | 任何          | 永久     |
| C9  | container 剛起時 healthcheck 是 `starting`（約 10s）；立刻 verify 會 fail | 任何          | retry 6次後穩定 |

## 6. Playbook 對應

對應的 verify playbook（`playbooks/verify/core-infra-provider-db.yml`）**已於 2026-07-17 棄用**（僅存檔參考，見該目錄 README.md）；驗收直接 `pilot verify` 吃本 spec 執行。

對應手寫的 **apply** playbook：`playbooks/apply/core-infra-provider-apply.yml`
（`infra_role=db` 段：`docker run postgres` + bind-mount + healthcheck）

| Spec ID | Apply task (示例)                                            | 備註 |
|---------|-------------------------------------------------------------|------|
| C1-C2   | `community.docker.docker_image` + `docker_container`        | idempotent |
| C3      | `ports: 127.0.0.1:5432:5432`                                 | host 上 LISTEN 5432 |
| C4-C6   | `POSTGRES_DB=keycloak` + `POSTGRES_USER=keycloak` env       | image 自動建 db + role；apply 段 `postgresql_db.owner=keycloak` 不需（image 自動 owner = user） |
| C7      | container env `POSTGRES_PASSWORD=...`                        | 從 vault 帶 |
| C8      | `volumes: /var/lib/pilot/postgres:/var/lib/postgresql/data` | host bind-mount |
| C9      | `healthcheck: pg_isready -U keycloak -d keycloak`            | container 內每 10s 檢 |
| C10-C11 | 不 mutate                                                    | 純讀 |

> Apply playbook 用 `community.docker.docker_container` 起 container，data dir 在
> host 上可備份 / 還原（`vm-target snapshot`）。要搬移就把整個目錄 tar 走。

## 7. 把 FAIL 變 PASS 的 SOP

```bash
# 1. 套前先看 docker 是否已就緒（spec docs/verification/docker.md）
go run ./cmd/pilot vm-target verify --name core docs/verification/docker.md
# 預期 8/8 PASS

# 2. 套 db role
go run ./cmd/pilot vm-target run --name core \
    playbooks/apply/core-infra-provider-apply.yml \
    -e target_group=keycloak-db -e infra_role=db \
    -e pg_keycloak_db_password=sandbox-db-password-123
# PLAY RECAP: ok=8 changed=4 failed=0
#   - mkdir /var/lib/pilot/postgres
#   - docker pull postgres:16
#   - docker network create pilot-infra
#   - docker run pilot-postgres

# 3. 同步驗證
go run ./cmd/pilot vm-target verify --name core \
    docs/verification/core-infra-provider-db.md
# verdict: **PASS**  (pass=11 fail=0 skip=0)

# 4. 讓 Keycloak provider 真的接（已經是同一 host；同 IP）：
go run ./cmd/pilot vm-target run --name core \
    playbooks/apply/core-infra-provider-apply.yml \
    -e target_group=keycloak -e infra_role=keycloak \
    -e kc_admin_password=sandbox-admin-password-123 \
    -e kc_db_password=sandbox-db-password-123
# Keycloak container 透過 docker network `pilot-infra` 找 `postgres` hostname
# → jdbc:postgresql://postgres:5432/keycloak
```

> 順序：docker → db → keycloak。同一台 host 跑同一個 playbook 三次，target_group
> 換三次就好。

## 8. 變更紀錄

| 日期       | 版本 | 變更                                                                 | 變更者 |
|------------|------|--------------------------------------------------------------------|--------|
| 2026-07-01 | v1.0 | 初版（host postgresql + 11 條 spec）                                  | sre    |
| 2026-07-01 | v2.0 | 改 docker postgres container；C1/C2/C8/C9 改查 docker 物件；其餘保留邏輯 | sre    |
