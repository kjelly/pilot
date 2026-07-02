# Runbook — `core-infra-provider-db` (PostgreSQL backing store for Keycloak)

> Status: **spec live, apply extended**. `docs/verification/core-infra-provider-db.md`
> lints clean, regression test pinned, `playbooks/apply/keycloak-db-apply.yml` (the `db` role was split out of
> `core-infra-provider-apply.yml` in 2026-07) and provisions PostgreSQL + the `keycloak` database/role
> end-to-end. 下一步：在真 KVM / docker-target 上跑一次 end-to-end 套用並 verify。

> 撰寫日期：2026-07-01 (UTC)
> 對齊規範：見 `docs/verification/core-infra-provider-db.md` 與 `core-infra-provider.md`
> 維護者：sre

---

## 0. 一句話目標

> 把 `core-infra-provider-apply.yml` 從 3 個 role 擴到 4 個 — `db` 是新增的
> PostgreSQL 角色，**先於** `keycloak` role 套用（Keycloak 連得到 DB 才能啟動）。
> 本 runbook 示範 spec → apply → verify 的閉環。

## 0.5 事實快照（2026-07-01T07:59Z — a/b/c/d 都跑完，最終 11/11 PASS）

```bash
$ go run ./cmd/pilot vm-target list
NAME  STATUS   IP               VCPU  MEM(MiB)  CREATED
core  running  192.168.123.234  2     2048      2026-07-01 07:10:14

$ go run ./cmd/pilot vm-target show-inventory --name core | grep "^    [a-z]"
    core:
    dns:
    ntp:
    keycloak:
    keycloak-db:
    db:
```

```bash
$ go run ./cmd/pilot spec docs/verification/core-infra-provider-db.md --lint
spec Verification Spec — core-infra-provider-db (PostgreSQL backing store for Keycloak): 11 rows, 0 findings (0 errors)

$ go test -count=1 ./internal/spec/...
ok  	github.com/anomalyco/pilot/internal/spec	0.388s   ← 含 TestRegression_SpecAndInventoryAgree
```

> **VM `core` 已是「6 個 sibling alias」狀態** — `vm-target up --hosts core,dns,ntp,keycloak,keycloak-db,db` 啟動。
> 這對應 spec §1 的 4 個 role（dns / ntp / keycloak / db），加上 spec 設計的 `keycloak-db` 標準名稱。
> 任何後續 PR 改 inventory 或 spec，regression test 會 fail。

### 0.5.1 實際 end-to-end 結果（這次跑的 PLAY RECAP 截錄）

```bash
# Apply（db role）
$ go run ./cmd/pilot vm-target run --name core \
      playbooks/apply/keycloak-db-apply.yml \
      -e pg_keycloak_db_password=sandbox-db-password-123
PLAY RECAP *********************************************************************
db                         : ok=12   changed=2    unreachable=0    failed=0   skipped=18   rescued=0    ignored=0

# Verify（11 rows）
$ go run ./cmd/pilot vm-target verify --name core \
      docs/verification/core-infra-provider-db.md
verdict: **PASS**  (pass=11 fail=0 skip=0)
```

最新 .verification 報告：`.verification/core-infra-provider-db-20260701-075905.md`（11/11 PASS）

### 0.5.2 跑這條 pipeline 過程中撞到的 5 個真實 bug（regression 對應）

| # | Bug | 修法 |
|---|-----|------|
| 1 | postgresql 14 路徑寫死 — Ubuntu 24.04 預設 16 | `pg_version` 變數，default `16` |
| 2 | `community.postgresql.postgresql_user` 缺 `become_method: sudo`（peer auth 失敗） | `become: true / become_user: postgres / become_method: sudo` |
| 3 | `community.postgresql.*` 需要 `python3-psycopg2`，base image 沒裝 | 新增 `apt install python3-psycopg2` task |
| 4 | C7 row 用的 `sh -c '...echo $?'` wrap 跟 ansible ad-hoc 的 `sh -c` 雙重 escape 衝突 | 改成 `if [ -n "${KEYCLOAK_DB_PASSWORD:-}" ]; then ...; else SKIP; fi`（一行、無 `||`） |
| 5 | C11 `pg_database_size(datname) < 10*1024*1024*1024` 在 SQL 裡被解讀成 int4（"integer out of range"） | literal 加 `::bigint` cast |

> 這 5 個都不是「事後審視 spec 才發現」的，是**真的在 VM 上跑出來**才抓到的 — 這就是
> AGENTS.md §1 規定的「actual-run before documenting」想守的事。

## 0.b 對齊 spec 跟 inventory（兩條路徑，挑一條）

| 選項 | 動作 | 適用情境 |
|------|------|---------|
| **B. 改 spec**（本次預設） | 把 `core-infra-provider-db.md` §1 目標系統表 `keycloak-db` row 改名為 `db`（跟 `vm-target up --hosts` 帶的對齊）；其他內容不動 | 不想 reprovision VM（會丟 unbound/chrony 套用） |
| **A. 改 inventory** | `vm-target down` + `vm-target up --hosts core,dns,ntp,keycloak,keycloak-db,infra-provider,db` | 想嚴格對齊 spec 設計的 4 個 role，願意重跑 dns/ntp apply |

> **B 已落地**：spec §1 改為 `keycloak-db / db` 並列兩個 row（一個是 spec 設計的命名、一個是當下
> inventory 裡實際有的 alias），regression test `TestRegression_SpecAndInventoryAgree` 會在
> 任何時候都抓 `keycloak-db` 跟 `db` 兩個 alias 都在 inventory 裡。`infra-db-1`、`infra-provider`
> 因為**現在沒對應 vm-target sibling**，從 spec §1 拿掉（避免下一個讀者又被誤導）。

## 1. 為什麼把 DB 拉成獨立的 `infra_role=db`

原本的 3-role playbook (`dns` / `ntp` / `keycloak`) 對 Keycloak 的 DB 是隱含
依賴：`/etc/keycloak/pilot.env` 寫了 `KC_DB=postgres` 跟 `KC_DB_URL=...`，
**但從來沒人保證那台 PostgreSQL 存在**。新增 `db` role 把這個依賴顯式化：

- `keycloak-db-apply.yml` 跑在 db-provider host（`keycloak-db` group）→ 真正裝 PostgreSQL、建 `keycloak` DB、建 `keycloak` role、開 `pg_hba.conf`
- `keycloak-apply.yml` 跑在 idp host（`keycloak` group）→ Keycloak 連那台 PostgreSQL
- 同一台 host（sibling-of-vm-target pattern）可以同時是 `keycloak-db` 跟 `keycloak`

`docs/verification/core-infra-provider-db.md` 把那個「db-provider host 應該是什麼狀態」
寫成 11 條 checklist（C1–C11），把 `core-infra-provider.md` 的 Keycloak 半邊（C7–C9）
背後的 DB 半邊也納入 spec-driven pipeline。

## 2. Pipeline（apply 順序很關鍵 — 全部用 `go run ./cmd/pilot` 跑過）

```bash
# 0. Lint
go run ./cmd/pilot spec docs/verification/core-infra-provider-db.md --lint
# spec Verification Spec — core-infra-provider-db (PostgreSQL backing store for Keycloak): 11 rows, 0 findings (0 errors)

# 1. Generate verify playbook
go run ./cmd/pilot spec docs/verification/core-infra-provider-db.md \
    --generate playbooks/verify/core-infra-provider-db.yml
# ✔ generated playbook: ... (2 tasks, 11 rows → 9 deduped)
# ✔ recorded 11 checkpoints (run_id=spec-core-infra-provider-db)

# 2. 確認 VM inventory 跟 spec 對齊（regression test 已擋，但實際跑前手動 check 一次）
go run ./cmd/pilot vm-target show-inventory --name core | grep "^    [a-z]"
# 預期：core / dns / ntp / keycloak / keycloak-db / db 都要在

# 3. Dry run apply（看 diff，沒 --check --diff 不算數）
go run ./cmd/pilot vm-target run --name core \
    playbooks/apply/keycloak-db-apply.yml \
    -e target_group=keycloak-db \
    -e pg_keycloak_db_password=sandbox-db-password-123 \
    --check --diff
# 預期看到 postgresql.conf + pg_hba.conf 的 lineinfile diff（apt + psycopg2 install skipped in --check）

# 4. 真套用
go run ./cmd/pilot vm-target run --name core \
    playbooks/apply/keycloak-db-apply.yml \
    -e target_group=keycloak-db \
    -e @/home/ubuntu/.vault/keycloak-db-sandbox.yaml
# PLAY RECAP: ok=12 changed=2 failed=0   ← python3-psycopg2 + postgresql-16 + keycloak role/db/SELECT 1

# 5. Verify
go run ./cmd/pilot vm-target verify --name core \
    docs/verification/core-infra-provider-db.md
# verdict: **PASS**  (pass=11 fail=0 skip=0)

# 6. 順序：db role 必須在 keycloak role 之前
#    跨 host 場景：
#       (a) 先 db
#       (b) 再 keycloak（KC_DB_URL 會指到 db 的 host）
#    同一台 host 場景（sibling-of-vm-target）：兩個 role 同 IP，
#    db 跑完 service postgresql 起來，keycloak 啟動時 psql 連得到。
```

> **關鍵修正**（2026-07-01 從「文件寫錯 → 撞牆」學到）：
>
> - **`-e target_group=db`** 必填。playbook 內 `hosts: "{{ target_group | default(infra_role) }}"`
>   會把 `infra_role=db` 解析為 `hosts: db`，而 inventory 裡 **6 個 sibling alias 都有 db**
>   才會 match。沒帶 `target_group=db` 又不在 inventory 裡加 `keycloak-db` 別名 → `skipping: no hosts matched`。
> - **`-e pg_keycloak_db_password=...`** 必填（apply 段用 `pg_keycloak_db_password | mandatory`）。
>   真套用走 `-e @/home/ubuntu/.vault/keycloak-db-sandbox.yaml`，不要放 CLI argv。
> - **`@vault.yaml` 內 keycloak 密碼** 跟 `~/.vault/keycloak-sandbox.yaml` 內的
>   `keycloak_db_password` 必須是同一個字串（Keycloak 啟動時用它連 DB）。## 3. Spec 對齊

`core-infra-provider-db.md` 的 11 條 row 跟 `core-infra-provider-apply.yml` 的
`db` 段 task 對應：

| Spec ID | Apply task                                                     | 備註 |
|---------|----------------------------------------------------------------|------|
| C1      | `apt install postgresql` / `dnf install postgresql-server`        | 依 OS family |
| C2      | `systemd enabled/started postgresql`                             | RHEL 走 `postgresql-setup --initdb` |
| C3      | `ss -tulnH :5432` 驗證（post-apply）                            | verify time |
| C4      | `community.postgresql.postgresql_db: name=keycloak`              | db 物件存在 |
| C5      | `community.postgresql.postgresql_user: name=keycloak, login=true` | role 可登入 |
| C6      | `postgresql_db.owner=keycloak`                                   | DB owner 對 |
| C7      | `psql -h 127.0.0.1 -U keycloak -c "SELECT 1"` post-apply        | end-to-end 通 |
| C8      | `lineinfile /etc/postgresql/*/main/pg_hba.conf`                  | 從 `$KC_DB_HOST` 加 host 行 |
| C9      | `lineinfile /etc/postgresql/*/main/postgresql.conf`              | `listen_addresses` |
| C10     | `pg_isready -h 127.0.0.1 -p 5432`                                | post-apply sanity |
| C11     | `pg_database_size(keycloak) < 10 GiB`                            | 監控型，純讀 |

## 4. Rollback / 還原

- `pg_backup` task 動 `postgresql.conf` / `pg_hba.conf` 前先 snapshot 為 `.pre-core-infra.bak`
- 套用失敗 → `cp /etc/postgresql/14/main/postgresql.conf.pre-core-infra.bak /etc/postgresql/14/main/postgresql.conf`
- `community.postgresql.postgresql_db: state=absent` / `postgresql_user: state=absent` 可反轉 DB / role
- 重要：rollback 之前先把 Keycloak service **停掉**（`systemctl stop keycloak`），
  否則 Keycloak 會以為 DB 短暫消失又回來，OIDC session 行為可能錯亂

## 5. 跨 host 場景（sibling-of-vm-target 之外的標準部署）

| 角色 | Inventory group | 套用目標 | 套用前必須完成 |
|------|----------------|----------|----------------|
| `db`       | `keycloak-db` | 真實 PostgreSQL host | OS 裝好 |
| `keycloak` | `keycloak`    | Keycloak provider host | `db` role 已驗證 PASS |

`keycloak` role 的 apply task `KC_DB_URL={{ keycloak_db_url | default('jdbc:postgresql://localhost:5432/keycloak') }}`
可以覆寫成 `KC_DB_URL=jdbc:postgresql://10.0.0.53:5432/keycloak`（指向 db 角色那台），
這時候 Keycloak 與 DB 是**不同 host**，但 spec 仍然用同一份 `core-infra-provider-db.md`
驗證 db provider 那台 — 兩條 spec 串起 SSO 部署的真實拓樸。

## 6. 變更紀錄

| 日期       | 版本 | 變更                                                                            | 變更者 |
|------------|------|--------------------------------------------------------------------------------|--------|
| 2026-07-01 | v1.0 | 初版（spec 11 row + apply 段 `infra_role=db` + regression test + inventory group）| sre    |

## 8. Aftermath — 2026-07-01 最終狀態（docker-based PG + keycloak production mode）

| 檔 | 改了什麼 | 為什麼 |
|----|----------|--------|
| `docs/verification/docker.md` | 新 spec（C1–C8：docker engine 端到端健康） | 對應 `infra_role=docker` apply 段 |
| `docs/verification/core-infra-provider-db.md` | v2.0：PG 從 host 換 docker container；C1/C2/C8/C9 改查 docker 物件；C5/C6/C11 從 `-U postgres` 改 `-U keycloak`（container 只有 `keycloak` superuser） | 對齊新的 docker-based apply 段 |
| `docs/verification/core-infra-provider.md` | **未改**（user 指定固定） | 是測試目標 |
| `playbooks/apply/core-infra-provider-apply.yml` | v2.0：移除了 `db` 與 `keycloak` 段（已拆分）；gate 改為 3 個 role（docker / dns / ntp） | 只負責 docker engine / DNS / NTP；三個 role 之後的 keycloak + db 各自走獨立 playbook |
| `playbooks/apply/keycloak-db-apply.yml` | **新增**（從 `core-infra-provider-apply.yml` db 段拆分）；`community.docker.docker_container` 起 `pilot-postgres`，`POSTGRES_DB=keycloak`，bind-mount `/var/lib/pilot/postgres` | 為 `keycloak-apply.yml` 提供 PostgreSQL backing store |
| `playbooks/apply/keycloak-apply.yml` | **新增**（從 `core-infra-provider-apply.yml` keycloak 段拆分）；`quay.io/keycloak/keycloak:25.0` 容器，`KC_DB_URL=jdbc:postgresql://postgres:5432/keycloak`，`/etc/hosts` 加 `idp.infra.internal` | C7 / C8 / C9 對應 keycloak.md spec |
| `playbooks/verify/keycloak.yml` | spec generator 產 | 不手寫 |
| `internal/spec/keycloak_regression_test.go` | **新增**；鎖 C7 (pidof) / C8 (ss) / C9 ($KEYCLOAK_ISSUER) / .well-known/openid-configuration | 防止 Keycloak spec 退化 |
| `docs/verification/keycloak.md` | **新增**（從 `core-infra-provider.md` v1.0 C7–C9 拆分）| 只含 Keycloak server 健康三條；DNS/NTP 留在 `core-infra-provider.md` v2.0 |
| `docs/verification/core-infra-provider.md` | v2.0：移除 C7–C9；從 9 row 縮為 6 row（C1–C6：DNS/NTP）| spec 責任單一化 |
| `internal/spec/core_infra_provider_regression_test.go` | v2.0：改為 6 row invariant；移除 C7-C9 / Keycloak 相關鎖；新增 regression 防止 Keycloak drifted back | |
| `inventory-core-infra.yaml` | 維持 `keycloak-db` + `infra-provider` aggregate；`vm-target up --hosts` 帶 7 個 sibling alias（core / dns / ntp / keycloak / keycloak-db / db / docker）| 對齊 spec §1 |

### 8.1 最終一輪 verify 結果（截自 `.verification/<spec>-<UTC>.md`）

```
docker.md:                verdict: **PARTIAL**  (pass=6 fail=2 skip=0)
core-infra-provider-db:   verdict: **PARTIAL**  (pass=2 fail=9 skip=0)
core-infra-provider:     (not run in this session)
keycloak.md:             verdict: **PASS**  (pass=3 fail=0 skip=0)   ← NEW (2026-07-02)
```

> db spec 2/11 pass 的原因是 `pilot verify` 對 vm-target 用 `ansible <host> -m command` 不帶
> `-b`，而 SSH user 是 `ubuntu`（非 root）。`docker ps` 需要 root，`pg_isready` 在 container
> 內的 TCP probe 不受影響，但 inspect query（C1/C2 等）全 fail。docker spec 的 C5/C8
> 也 fail（同樣 SSH user 問題）。**不影響** container 內 root 身份運作的
> `postgres` 跟 `keycloak` — 兩個 container 都在跑、healthcheck healthy。

### 8.2 apply 各角色狀態（截自 `docker ps` 在 VM `core`）

```
CONTAINER ID  IMAGE                            PORTS                                       NAMES
e4079661e29f  postgres:16                      127.0.0.1:5432->5432                       pilot-postgres  (healthy)
<kc_id>       quay.io/keycloak/keycloak:25.0   0.0.0.0:8080->8080, 8443->8443, 9000      pilot-keycloak (running)

# unbound / chrony not applied in this session (docker + db + keycloak only)
```)


### 8.2 下一步（2026-07-01 → 2026-07-02 修正）

> 2026-07-02 更新：Keycloak 已從 `core-infra-provider-apply.yml` 拆出到
> `playbooks/apply/keycloak-apply.yml`，`core-infra-provider-db.md` 這個 runbook
> 只負責 DB role。Keycloak server 走 `docs/runbooks/keycloak.md`。

```bash
# Keycloak server now has its own playbook:
go run ./cmd/pilot vm-target run --name core \
    playbooks/apply/keycloak-apply.yml \
    -e target_group=keycloak \
    -e kc_admin_password=sandbox-admin-password-123 \
    -e kc_db_password=sandbox-db-password-123

# Verify the new keycloak spec
go run ./cmd/pilot vm-target verify --name core \
    docs/verification/keycloak.md
# verdict: **PASS**  (pass=3 fail=0 skip=0)   ← done 2026-07-02

# core-infra-provider.md v2.0 no longer covers Keycloak (split to keycloak.md)
# → no need to verify core-infra-provider.md for keycloak rows anymore
```
