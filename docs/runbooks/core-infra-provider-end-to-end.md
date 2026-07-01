# Runbook — `core-infra-provider` (DNS + NTP + DB + Keycloak) end-to-end on real KVM

> Status: **end-to-end 9/9 PASS on VM `core` (192.168.123.234)**.
> Keycloak running in **production mode** (`Profile prod activated`) with
> PostgreSQL backing store in a docker container. All four `infra_role`s
> wired through `playbooks/apply/core-infra-provider-apply.yml`; the
> verifier only uses `go run ./cmd/pilot vm-target …` — no manual steps.

> 撰寫日期：2026-07-01 (UTC)
> 對齊規範：見 `docs/verification/{core-infra-provider,core-infra-provider-db,docker}.md`
> 維護者：sre

---

## 0. 一句話目標

> 從一台**完全乾淨的 noble-base.qcow2** 開始，**只**用
> `go run ./cmd/pilot vm-target …` 跑完下面五個 `infra_role`，**4 條 spec
> 全綠**（docker 8/8 + db 11/11 + provider 9/9）：

| infra_role   | 套用什麼                                                | spec                    | 結果      |
|--------------|--------------------------------------------------------|-------------------------|-----------|
| `docker`     | apt install docker.io + docker-compose-v2              | `docker.md`              | 8/8 PASS |
| `db`         | docker run postgres:16 + 建 keycloak role/db + bind-mount  | `core-infra-provider-db.md` | 11/11 PASS |
| `dns`        | apt install unbound + 切 system-resolved stub off       | `core-infra-provider.md`   | C1-C3 PASS |
| `ntp`        | apt install chrony + 接上游 pool                       | `core-infra-provider.md`   | C4-C6 PASS |
| `keycloak`   | docker run quay.io/keycloak/keycloak:25.0 (prod mode)  | `core-infra-provider.md`   | C7-C9 PASS |

---

## 1. 一行終結指令（給懂的人）

```bash
go run ./cmd/pilot vm-target up \
    --base-image /var/lib/libvirt/images/pilot/noble-base.qcow2 \
    --name core --ssh-user root \
    --hosts core,dns,ntp,keycloak,keycloak-db,db,docker \
    --vcpus 2 --memory 2048

for role in docker db dns ntp keycloak; do
    go run ./cmd/pilot vm-target run --name core \
        playbooks/apply/core-infra-provider-apply.yml \
        -e target_group=core -e infra_role=$role \
        -e pg_keycloak_db_password=sandbox-db-password-123 \
        -e kc_admin_password=sandbox-admin-password-123 \
        -e kc_db_password=sandbox-db-password-123
done

# 3 個 spec 全部 verify
for spec in docker.md core-infra-provider-db.md core-infra-provider.md; do
    go run ./cmd/pilot vm-target verify --name core docs/verification/$spec
done
```

跑完預期：3 個 spec 全綠，VM 上有 `pilot-postgres` + `pilot-keycloak` 兩個 docker container
在跑，Keycloak 已 listen 在 :8080 且 OIDC discovery 回 200。

---

## 2. 完整步驟（給第一次跑的人）

### 2.0 環境檢查（一次性）

```bash
go run ./cmd/pilot vm-target list
# 應為空（or 顯示之前的 target）

# 確認 base image 存在
ls -lh /var/lib/libvirt/images/pilot/noble-base.qcow2
# -rw-r--r-- 1 libvirt-qemu kvm 276M Jul  1 03:45 ...

# 確認 ansible collection 裝好
ansible-galaxy collection list | grep -E "community\.(postgresql|general|docker)"
# community.docker                         4.5.2
# community.general                        10.6.0
# community.postgresql                     3.14.0
```

### 2.1 起 VM

```bash
go run ./cmd/pilot vm-target up \
    --base-image /var/lib/libvirt/images/pilot/noble-base.qcow2 \
    --name core --ssh-user root \
    --hosts core,dns,ntp,keycloak,keycloak-db,db,docker \
    --vcpus 2 --memory 2048
# ✓ target core up
#   ip: 192.168.123.234
```

> `--hosts` 七個 alias 對應 7 個 group，**同一個 IP**。後面 apply
> 只要用 `-e target_group=core`（或其他任一 alias）都會 match 同一台。

### 2.2 套 docker role（**必須第一個**）

```bash
go run ./cmd/pilot vm-target run --name core \
    playbooks/apply/core-infra-provider-apply.yml \
    -e target_group=core -e infra_role=docker
# PLAY RECAP: ok=6 changed=2 failed=0
#   - apt install docker.io docker-compose-v2
#   - systemd enable --now docker
```

Verify：
```bash
go run ./cmd/pilot vm-target verify --name core \
    docs/verification/docker.md
# verdict: **PASS**  (pass=8 fail=0 skip=0)
```

### 2.3 套 db role（PostgreSQL container）

```bash
go run ./cmd/pilot vm-target run --name core \
    playbooks/apply/core-infra-provider-apply.yml \
    -e target_group=core -e infra_role=db \
    -e pg_keycloak_db_password=sandbox-db-password-123
# PLAY RECAP: ok=8 changed=4 failed=0
#   - mkdir /var/lib/pilot/postgres
#   - docker pull postgres:16
#   - docker network create pilot-infra
#   - docker run pilot-postgres
```

Verify：
```bash
go run ./cmd/pilot vm-target verify --name core \
    docs/verification/core-infra-provider-db.md
# verdict: **PASS**  (pass=11 fail=0 skip=0)
```

> DB 用 docker container、bind-mount 到 host 的 `/var/lib/pilot/postgres`。
> 密碼從 `-e pg_keycloak_db_password=...` 帶入（不要放 CLI argv，用
> `-e @/path/to/vault.yaml` 也行）。

### 2.4 套 dns role

```bash
go run ./cmd/pilot vm-target run --name core \
    playbooks/apply/core-infra-provider-apply.yml \
    -e target_group=core -e infra_role=dns
# PLAY RECAP: ok=12 changed=7 failed=0
#   - apt install unbound
#   - lineinfile postgresql.conf /etc/unbound/unbound.conf.d/infra-pilot.conf
#   - lineinfile /etc/systemd/resolved.conf (DNSStubListener=no)
#   - swap /etc/resolv.conf to 127.0.0.1
#   - systemd enable --now unbound
```

### 2.5 套 ntp role

```bash
go run ./cmd/pilot vm-target run --name core \
    playbooks/apply/core-infra-provider-apply.yml \
    -e target_group=core -e infra_role=ntp
# PLAY RECAP: ok=8 changed=3 failed=0
#   - apt install chrony
#   - lineinfile /etc/chrony/chrony.conf
#   - systemd enable --now chronyd
```

### 2.6 套 keycloak role（**production mode**）

```bash
go run ./cmd/pilot vm-target run --name core \
    playbooks/apply/core-infra-provider-apply.yml \
    -e target_group=core -e infra_role=keycloak \
    -e kc_admin_password=sandbox-admin-password-123 \
    -e kc_db_password=sandbox-db-password-123
# PLAY RECAP: ok=8 changed=3 failed=0
#   - mkdir /var/lib/pilot/keycloak (chown 0:0 — keycloak runs as root in container)
#   - lineinfile /etc/hosts (idp.infra.internal → 127.0.0.1)  ← spec C9 needs this
#   - docker pull quay.io/keycloak/keycloak:25.0
#   - docker run pilot-keycloak (Profile prod activated)
#   - poll /realms/master 8080 for ready
```

> Keycloak 用 `start --http-enabled=true` 跑在 production mode。容器以
> root (uid=0) 身份跑（narayana JTA object store 需要寫 transaction-logs
> 到 bind-mount 的 `/opt/keycloak/data`）。資料持久化在 host 的
> `/var/lib/pilot/keycloak`。
>
> **為什麼要在 /etc/hosts 加 `idp.infra.internal`**：Keycloak 的 OIDC
> discovery 在 spec 裡用 `${KEYCLOAK_ISSUER:-http://idp.infra.internal:8080/realms/master}/...`
> — `idp.infra.internal` 是容器對外發行的 hostname，沒在 DNS 註冊，要在
> host 端手動加 entries（apply 已經會加）。

### 2.7 驗證整個 pipeline

```bash
go run ./cmd/pilot vm-target verify --name core \
    docs/verification/core-infra-provider.md
# verdict: **PASS**  (pass=9 fail=0 skip=0)
```

C1–C3 是 DNS、C4–C6 是 NTP、C7–C9 是 Keycloak。**全部 9 條綠** = end-to-end PASS。

---

## 3. 驗證最終狀態

```bash
# Container 列表
go run ./cmd/pilot vm-target exec --name core -- docker ps
# pilot-keycloak  quay.io/keycloak/keycloak:25.0   Up X minutes (healthy)
# pilot-postgres  postgres:16                      Up X minutes (healthy)

# OIDC discovery 端到端
go run ./cmd/pilot vm-target exec --name core -- \
    curl -fsS -o /dev/null -w "code=%{http_code}\n" \
    http://idp.infra.internal:8080/realms/master/.well-known/openid-configuration
# code=200

# PostgreSQL 從 host 用 keycloak role 登入
go run ./cmd/pilot vm-target exec --name core -- \
    PGPASSWORD=sandbox-db-password-123 psql -h 127.0.0.1 -U keycloak -d keycloak -c "SELECT 1"
# ?column?
# ----------
#         1

# Keycloak admin login
go run ./cmd/pilot vm-target exec --name core -- \
    curl -fsS -X POST -d "username=admin&password=sandbox-admin-password-123&grant_type=password" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    http://idp.infra.internal:8080/realms/master/protocol/openid-connect/token
# {"access_token":"...","token_type":"Bearer","refresh_token":"...","expires_in":300,...}
```

---

## 4. Snapshot / Rollback

```bash
# Snapshot 整套狀態（keycloak + postgres containers + unbound + chrony + /etc configs）
go run ./cmd/pilot vm-target snapshot --name core --tag post-keycloak-prod-install
# ✓ snapshotted core as post-keycloak-prod-install

# 跑壞了？
go run ./cmd/pilot vm-target rollback --name core --tag post-keycloak-prod-install
# ✓ rolled back core to post-keycloak-prod-install
```

---

## 5. Vault 文件範本

```bash
# ~/.vault/keycloak-db-sandbox.yaml (chmod 600)
pg_keycloak_db_password: sandbox-db-password-123
keycloak_admin_password: sandbox-admin-password-123
keycloak_db_user: keycloak
keycloak_db_password: sandbox-db-password-123
```

Production 時換成 vault 來源（`-e @~/.vault/keycloak-prod.yaml`），
**絕不**把密碼塞 CLI argv。

---

## 6. 變更紀錄

| 日期       | 版本 | 變更                                                                          | 變更者 |
|------------|------|------------------------------------------------------------------------------|--------|
| 2026-07-01 | v1.0 | 初版（5 role end-to-end PASS；Keycloak production mode；PG docker container）   | sre    |
