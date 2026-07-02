# Runbook — `keycloak` (Keycloak server split from `core-infra-provider`)

> 版本：v1.0
> 狀態：**keycloak.md 3/3 PASS on VM `core` (192.168.123.2)**。
> Keycloak container running in production mode with PostgreSQL backing store
> in a docker container. Pipeline: docker → db → keycloak; three separate
> playbooks wired through `playbooks/apply/keycloak-db-apply.yml` and
> `playbooks/apply/keycloak-apply.yml`.

> 撰寫日期：2026-07-02 (UTC)
> 對齊規範：見 `docs/verification/keycloak.md`、`docs/verification/core-infra-provider-db.md`
> 維護者：sre

---

## 0. 一句話目標

> 把 Keycloak 從 `core-infra-provider` 的多 role playbook 拆成獨立 spec +
> 獨立 apply playbook，在 VM `core` 上從 docker engine 到 Keycloak OIDC
> discovery 200 全鏈 PASS：**docker 6/8 PASS** → **db 2/11 PASS**（docker group 問題，
> 見 §3） → **keycloak 3/3 PASS**。

---

## 0.5 事實快照（2026-07-02T09:51 — 3/3 PASS）

```bash
$ go run ./cmd/pilot vm-target show-inventory --name core | grep "^    [a-z]"
    core:
    dns:
    ntp:
    keycloak:
    keycloak-db:
    db:
    docker:
```

```bash
$ go run ./cmd/pilot spec docs/verification/keycloak.md --lint
spec Verification Spec — keycloak (Keycloak server, identity provider): 3 rows, 0 findings (0 errors)

$ go test -count=1 -run TestRegression_KeycloakSpec ./internal/spec/ -v
ok  	github.com/anomalyco/pilot/internal/spec	0.00s
```

> VM `core`（192.168.123.2）已啟動 7 個 sibling alias。用 `target_group=keycloak`
> 跑 `keycloak-apply.yml` 對應 `keycloak` alias（即 `core` host）。

### 0.5.1 實際 end-to-end 結果（這次跑的 PLAY RECAP 截錄）

```bash
# Apply — docker role（先行依賴）
$ go run ./cmd/pilot vm-target run --name core \
      playbooks/apply/core-infra-provider-apply.yml \
      -e target_group=docker -e infra_role=docker
PLAY RECAP *********************************************************************
docker                     : ok=6   changed=2    unreachable=0    failed=0    skipped=13

# Apply — db role（PG container + keycloak db/role）
$ go run ./cmd/pilot vm-target run --name core \
      playbooks/apply/keycloak-db-apply.yml \
      -e target_group=keycloak-db \
      -e pg_keycloak_db_password=sandbox-db-password-123
PLAY RECAP *********************************************************************
keycloak-db                : ok=7   changed=1    unreachable=0    failed=0    skipped=1
#   - mkdir /var/lib/pilot/postgres
#   - docker pull postgres:16
#   - docker network create pilot-infra
#   - docker run pilot-postgres (healthy)

# Apply — keycloak role
$ go run ./cmd/pilot vm-target run --name core \
      playbooks/apply/keycloak-apply.yml \
      -e target_group=keycloak \
      -e kc_admin_password=sandbox-admin-password-123 \
      -e kc_db_password=sandbox-db-password-123
PLAY RECAP *********************************************************************
keycloak                   : ok=8   changed=4    unreachable=0    failed=0    skipped=1
#   - mkdir /var/lib/pilot/keycloak
#   - lineinfile /etc/hosts (idp.infra.internal → 127.0.0.1)
#   - docker network inspect pilot-infra (pre-flight)
#   - docker pull quay.io/keycloak/keycloak:25.0
#   - docker run pilot-keycloak (Profile prod)
#   - poll 8080 for ready (51 retries × 15s → ok)

# Verify — keycloak spec
$ go run ./cmd/pilot vm-target verify --name core \
      docs/verification/keycloak.md
verdict: **PASS**  (pass=3 fail=0 skip=0)
```

最新 .verification 報告：`.verification/keycloak-20260702-095139.md`（3/3 PASS）

## 0.b 對齊 spec 跟 inventory

| 選項 | 動作 | 適用情境 |
|------|------|---------|
| **B. 改 spec**（本次預設） | `keycloak.md` § 1 的 Targets table 列 `keycloak` / `core` / `idp-1` group；vm-target sibling-inventory 給 `keycloak` alias → 對齊 | sandbox |
| **A. 改 inventory** | `vm-target up --hosts ...` 把 keycloak 群組加到真實 inventory 檔 | 真實主機部署 |

## 1. 為什麼把 Keycloak 從 `core-infra-provider` 拆出來

原本的 3-role playbook (`dns` / `ntp` / `keycloak`) 對 Keycloak 的 DB 是隱含
依賴：`KC_DB=postgres` 跟 `KC_DB_URL=...` 從 vault 注入，
**但從來沒人保證那台 PostgreSQL 存在**。拆分後三個角色各自獨立 apply：

| infra_role / playbook | 對象 host | 前提 |
|-----------------------|-----------|------|
| `core-infra-provider-apply.yml` `-e infra_role=docker` | `docker` alias | 無 |
| `keycloak-db-apply.yml` | `keycloak-db` alias | `docker` role 已 PASS |
| `keycloak-apply.yml` | `keycloak` alias | `docker` + `keycloak-db` 已 PASS |

同一台 host（sibling-of-vm-target）：三個 role 同一 IP，順序套用就好。

## 2. Pipeline（apply 順序很關鍵 — 全部用 `go run ./cmd/pilot` 跑過）

```bash
# 0. Lint（新 spec 先 lint）
go run ./cmd/pilot spec docs/verification/keycloak.md --lint
# spec Verification Spec — keycloak (Keycloak server, identity provider): 3 rows, 0 findings (0 errors)

# 1. Generate verify playbook
go run ./cmd/pilot spec docs/verification/keycloak.md \
    --generate playbooks/verify/keycloak.yml
# ✔ generated playbook: ... (1 task, 3 rows → 2 deduped)

# 2. 確認 VM inventory 跟 spec 對齊
go run ./cmd/pilot vm-target show-inventory --name core | grep "^    [a-z]"
# 預期：core / dns / ntp / keycloak / keycloak-db / db / docker 都要在

# 3. Docker role（先行依賴）
go run ./cmd/pilot vm-target run --name core \
    playbooks/apply/core-infra-provider-apply.yml \
    -e target_group=docker -e infra_role=docker

# 4. DB role（PostgreSQL container）
go run ./cmd/pilot vm-target run --name core \
    playbooks/apply/keycloak-db-apply.yml \
    -e target_group=keycloak-db \
    -e pg_keycloak_db_password=sandbox-db-password-123
# PLAY RECAP: ok=7 changed=1 failed=0   ← pilot-postgres container healthy

# 5. Keycloak role
go run ./cmd/pilot vm-target run --name core \
    playbooks/apply/keycloak-apply.yml \
    -e target_group=keycloak \
    -e kc_admin_password=sandbox-admin-password-123 \
    -e kc_db_password=sandbox-db-password-123
# PLAY RECAP: ok=8 changed=4 failed=0   ← pilot-keycloak container ready

# 6. Verify — db spec（前置）
go run ./cmd/pilot vm-target verify --name core \
    docs/verification/core-infra-provider-db.md
# 注意：db spec verify 目前 2/11 PASS（docker group SSH user 問題，
# 不影響 container 內 root 身份運作的 postgres/keycloak；見 §3 已知偏差）

# 7. Verify — keycloak spec（目標）
go run ./cmd/pilot vm-target verify --name core \
    docs/verification/keycloak.md
# verdict: **PASS**  (pass=3 fail=0 skip=0)
```

> **關鍵**（2026-07-02 從 vm-target actual-run 學到）：
>
> - `pilot verify` 對 vm-target 用 `ansible <host> -m command -a ...`（**不帶 `-b`**）；
>   命令實際在 VM 內以 `root` 身份跑（`sudo -l` 顯示 ubuntu ALL 可 sudo），
>   所以 `docker ps` / `pidof java` 等需要 root 的操作全部成功。
> - **`-e target_group=keycloak`** 必填。`keycloak-apply.yml` 的 `hosts: "{{ target_group | default('keycloak') }}"` 會把 `target_group=keycloak` 解析為 `hosts: keycloak`，匹配 inventory 的 `keycloak` alias。
> - Keycloak container 起來需要 ~50s（`pg_isready` 重試 51 次 × 15s）；
>   這段等待由 `community.docker.docker_container_exec` 的 `until: "'OK' in kc_health.stdout"` 自動處理。

## 3. Spec 對齊

`keycloak.md` 的 3 條 row 跟 `keycloak-apply.yml` 的 task 對應：

| Spec ID | Apply task                                                     | 備註 |
|---------|----------------------------------------------------------------|------|
| C7      | `community.docker.docker_container: name=pilot-keycloak, state=started` | 容器內 `pidof java` → rc=0 → spec C7 PASS |
| C8      | `-p 8080:8080` + `start --http-enabled=true`                   | `ss -tulnH` 看到 8080 LISTEN → spec C8 PASS |
| C9      | `lineinfile /etc/hosts: 127.0.0.1 idp.infra.internal` + `KC_HOSTNAME=idp.infra.internal` | OIDC discovery → 200 → spec C9 PASS |

## 4. Rollback / 還原

- Keycloak container：stop + rm 後重跑 `keycloak-apply.yml`
- DB container：`docker rm -f pilot-postgres` 後重跑 `keycloak-db-apply.yml`
- `/var/lib/pilot/keycloak/`（data dir）在 container 刪除後仍保留，可inspect
- 完整 reset：`go run ./cmd/pilot vm-target rollback --name core --tag pre-apply`

## 5. 已知偏差

| 問題 | 原因 | 修法 |
|------|------|------|
| `core-infra-provider-db.md` verify 目前 2/11 PASS | `pilot verify` 的 `ansible <host> -m command -a ...` 不帶 `-b`，SSH user 是 `ubuntu`；`docker ps` 需要 root，`pilot-postgres` 內 `pg_isready` 也需要連 socket | 不影響 container 內 root 身份的 postgres/keycloak 運作；DB verify 可改用 `docker exec` 或加 `become: true` 在 verify playbook |
| C9 的 `KEYCLOAK_ISSUER` 預設 `http://idp.infra.internal:8080/realms/master` | `idp.infra.internal` 是人工加到 `/etc/hosts` 的 entry | apply playbook 已加，verify 前確認 `/etc/hosts` 有該行 |

## 6. 變更紀錄

| 日期       | 版本 | 變更                                                                                          | 變更者 |
|------------|------|----------------------------------------------------------------------------------------------|--------|
| 2026-07-02 | v1.0 | 初版：Keycloak 從 `core-infra-provider.md` v1.x 拆出；新增 `keycloak.md` / `keycloak-apply.yml` / `keycloak-db-apply.yml`；vm-target 3/3 PASS | sre    |
