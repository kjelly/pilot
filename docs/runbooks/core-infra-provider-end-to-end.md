# Runbook — `core-infra-provider` (DNS + NTP + DB + Keycloak) end-to-end on real KVM

> Status: **end-to-end re-verified 2026-07-17 on VM `dockersplit` (192.168.122.2)**,
> after `docker` was split out of `core-infra-provider-apply.yml` into its own
> standalone playbook (`playbooks/apply/docker-apply.yml`, see
> `docs/runbooks/docker.md`). Keycloak running in **production mode**
> (`Profile prod activated`) with PostgreSQL backing store in a docker
> container. All five roles now live in **five separate playbooks**
> (`docker-apply.yml` / `keycloak-db-apply.yml` /
> `core-infra-provider-apply.yml -e infra_role=dns` /
> `core-infra-provider-apply.yml -e infra_role=ntp` / `keycloak-apply.yml`) —
> no single playbook covers all five roles anymore, unlike the 2026-07-01
> original version of this runbook.

> 撰寫日期：2026-07-01 (UTC)；改版日期：2026-07-17 (UTC)
> 對齊規範：見 `docs/verification/{docker,core-infra-provider-db,core-infra-provider,keycloak}.md`
> 維護者：sre

---

## 0. 一句話目標

> 從一台**完全乾淨的 ubuntu-24.04-golden.qcow2** 開始，**只**用
> `go run ./cmd/pilot vm-target …` 跑完下面五個角色，**4 條 spec 全綠**
> （docker 8/8 + db 11/11 + provider(dns/ntp) 7/7 + keycloak 3/3 = 29/29）：

| 角色 / playbook                                                    | 套用什麼                                               | spec                          | 結果      |
|---------------------------------------------------------------------|---------------------------------------------------------|--------------------------------|-----------|
| `docker-apply.yml`                                                   | apt install docker.io + docker-compose-v2               | `docker.md`                    | 8/8 PASS  |
| `keycloak-db-apply.yml`                                              | docker run postgres:16 + 建 keycloak role/db + bind-mount| `core-infra-provider-db.md`    | 11/11 PASS|
| `core-infra-provider-apply.yml -e infra_role=dns`                    | apt install unbound + 切 system-resolved stub off        | `core-infra-provider.md`       | C1-C3 PASS|
| `core-infra-provider-apply.yml -e infra_role=ntp`                    | apt install chrony + 接上游 pool                         | `core-infra-provider.md`       | C4-C6 PASS|
| `keycloak-apply.yml`                                                 | docker run quay.io/keycloak/keycloak:25.0 (prod mode)    | `keycloak.md`                  | C7-C9 PASS|

## 0.5 事實快照（2026-07-17 重新驗證時）

```bash
go run ./cmd/pilot vm-target list
# NAME         STATUS   IP             VCPU  MEM(MiB)  DISK(GiB)  CREATED
# dockersplit  running  192.168.122.2  2     2048      20         2026-07-17 16:12:18

go run ./cmd/pilot vm-target show-inventory --name dockersplit | grep -E '^    [a-z]'
# dockersplit: / core: / docker: / dns: / ntp:
```

- 目標：本次重測只帶 `--hosts core,docker,dns,ntp` 四個 sibling alias
  （沒有另外帶 `keycloak`/`keycloak-db`/`db`）。`keycloak-db-apply.yml` /
  `keycloak-apply.yml` 兩支 playbook 各自的 hosts pattern 預設是
  `keycloak-db`/`keycloak`，本次改用 `-e target_group=core`（既有 alias）
  覆寫，一樣命中同一台機器。
- **對齊決定：B（改跑法，不改 inventory）**——沒有重新用 7 個 alias 建 VM，
  是因為驗證重點是「docker 拆分後，其餘 4 個角色還能不能正確串起來」，不需要
  額外的 alias 名稱來證明這件事；用既有 alias + `target_group=` override 一樣
  能命中同一台機器並跑出正確結果。
- vault 依賴：`pg_keycloak_db_password` / `kc_admin_password` / `kc_db_password`
  ——本次用 sandbox 佔位密碼透過 `-e` 帶入（**只在 disposable vm-target 上這樣
  做**；staging/prod 一律走 `-e @~/.vault/keycloak-*.yaml`，見 §5）。

> ⚠️ **`-e target_group=all` 陷阱**：本次重測第一次嘗試 `keycloak-db-apply.yml`
> 時誤用了 `-e target_group=all`。因為這台 vm-target 有 5 個 sibling alias
> （`dockersplit`/`core`/`docker`/`dns`/`ntp`，全部指向同一個 IP），
> `target_group=all` 讓 ansible 對「同一台機器」平行跑了 5 次同一個 play，
> 造成 `docker network create pilot-infra` 409 Conflict（5 個 goroutine 同時
> 建同一個 docker network）。**sibling-of-vm-target 場景一律用單一 alias**
> （如 `-e target_group=core`），不要用 `all`——`all` 是給「inventory 裡真的
> 有多台不同機器」的場景設計的。容器本身其實成功建立（見下方 §2 的乾淨重跑
> 輸出），只是第一次的 PLAY RECAP 很吵，故此處不列入證據。

---

## 1. 一行終結指令（給懂的人，2026-07-17 更新版）

```bash
go run ./cmd/pilot vm-target up \
    --base-image /var/lib/libvirt/images/pilot/images/ubuntu-24.04-golden.qcow2 \
    --name dockersplit --ssh-user root \
    --hosts core,docker,dns,ntp \
    --vcpus 2 --memory 2048 --disk 20 --ssh-timeout 8m --boot-timeout 8m

go run ./cmd/pilot vm-target run --name dockersplit playbooks/apply/docker-apply.yml \
    -e target_group=docker

go run ./cmd/pilot vm-target run --name dockersplit playbooks/apply/keycloak-db-apply.yml \
    -e target_group=core -e pg_keycloak_db_password=sandbox-db-password-123

for role in dns ntp; do
    go run ./cmd/pilot vm-target run --name dockersplit \
        playbooks/apply/core-infra-provider-apply.yml \
        -e target_group=core -e infra_role=$role
done

go run ./cmd/pilot vm-target run --name dockersplit playbooks/apply/keycloak-apply.yml \
    -e target_group=core \
    -e kc_admin_password=sandbox-admin-password-123 \
    -e kc_db_password=sandbox-db-password-123

# 4 個 spec 全部 verify
go run ./cmd/pilot vm-target verify --name dockersplit docs/verification/docker.md
go run ./cmd/pilot vm-target verify --name dockersplit docs/verification/core-infra-provider-db.md
go run ./cmd/pilot vm-target verify --name dockersplit docs/verification/core-infra-provider.md
go run ./cmd/pilot vm-target verify --name dockersplit docs/verification/keycloak.md
```

跑完預期：4 個 spec 全綠（8+11+7+3=29 rows），VM 上有 `pilot-postgres` +
`pilot-keycloak` 兩個 docker container 在跑，Keycloak 已 listen 在 :8080
且 OIDC discovery 回 200。

---

## 2. 完整步驟 + 這次跑的真實截錄

### 2.1 起 VM

```bash
go run ./cmd/pilot vm-target up \
    --base-image /var/lib/libvirt/images/pilot/images/ubuntu-24.04-golden.qcow2 \
    --name dockersplit --ssh-user root \
    --hosts core,docker,dns,ntp \
    --vcpus 2 --memory 2048 --disk 20 --ssh-timeout 8m --boot-timeout 8m
# ✓ target dockersplit up
#   ip: 192.168.122.2
```

### 2.2 套 docker role（**必須第一個**；現為獨立 playbook）

```bash
go run ./cmd/pilot vm-target run --name dockersplit \
    playbooks/apply/docker-apply.yml \
    -e target_group=docker
# PLAY RECAP: docker  ok=5  changed=2  unreachable=0  failed=0  skipped=2
#   - apt install docker.io docker-compose-v2
#   - user group add (root → docker)
```

Verify：
```bash
go run ./cmd/pilot vm-target verify --name dockersplit docs/verification/docker.md
# verdict: **PASS**  (pass=8 fail=0 skip=0)
```

### 2.3 套 db role（PostgreSQL container）

```bash
go run ./cmd/pilot vm-target run --name dockersplit \
    playbooks/apply/keycloak-db-apply.yml \
    -e target_group=core \
    -e pg_keycloak_db_password=sandbox-db-password-123
# PLAY RECAP: core  ok=8  changed=0  unreachable=0  failed=0  skipped=1
#   (changed=0 因為第一次跑撞到 §0.5 記錄的 target_group=all 競態時容器就已建好；
#    乾淨環境從頭跑一次預期 changed=1，見 docker_container 那個 task)
```

Verify：
```bash
go run ./cmd/pilot vm-target verify --name dockersplit docs/verification/core-infra-provider-db.md
# verdict: **PASS**  (pass=11 fail=0 skip=0)
```

> DB 用 docker container、bind-mount 到 host 的 `/var/lib/pilot/postgres`。
> 密碼只從 `-e` 或 `-e @~/.vault/keycloak-sandbox.yaml` 帶入，絕不放 CLI
> argv 以外的地方持久化（staging/prod 一律走 vault 檔，見 §5）。

### 2.4 套 dns role

```bash
go run ./cmd/pilot vm-target run --name dockersplit \
    playbooks/apply/core-infra-provider-apply.yml \
    -e target_group=core -e infra_role=dns
# PLAY RECAP: core  ok=13  changed=7  unreachable=0  failed=0  skipped=5
#   - apt install unbound
#   - write /etc/unbound/unbound.conf.d/infra-pilot.conf
#   - write /etc/systemd/resolved.conf (DNSStubListener=no)
#   - swap /etc/resolv.conf to 127.0.0.1
#   - systemd enable --now unbound
```

### 2.5 套 ntp role

```bash
go run ./cmd/pilot vm-target run --name dockersplit \
    playbooks/apply/core-infra-provider-apply.yml \
    -e target_group=core -e infra_role=ntp
# PLAY RECAP: core  ok=8  changed=3  unreachable=0  failed=0  skipped=8
#   - apt install chrony
#   - write /etc/chrony/chrony.conf
#   - systemd enable --now chronyd
```

Verify（dns + ntp 合在同一份 spec）：
```bash
go run ./cmd/pilot vm-target verify --name dockersplit docs/verification/core-infra-provider.md
# verdict: **PASS**  (pass=7 fail=0 skip=0)
```

> 2026-07-17 重測時發現並修正了這份 spec 的一個既有 bug：C6（NTP stratum
> 檢查）原本只用 `timedatectl show-timesync`，但這支 apply playbook 的
> `ntp_provider` 預設是 chrony，chrony 啟用時 `systemd-timesyncd` 是
> inactive，`show-timesync` 回 `Failed to parse bus message: No route to
> host`，C6 在任何一台照預設值跑過 apply 的全新主機上必 fail——這個 bug
> 跟本次 docker 拆分無關，是全面 re-verify 時意外發現的。已改成
> `chronyc tracking` 優先、`timedatectl show-timesync` 作 ntpd/ntpsec 主機
> 的 fallback，見 `docs/verification/core-infra-provider.md` v2.2 變更紀錄。

### 2.6 套 keycloak role（**production mode**）

```bash
go run ./cmd/pilot vm-target run --name dockersplit \
    playbooks/apply/keycloak-apply.yml \
    -e target_group=core \
    -e kc_admin_password=sandbox-admin-password-123 \
    -e kc_db_password=sandbox-db-password-123
# PLAY RECAP: core  ok=8  changed=4  unreachable=0  failed=0  skipped=1
#   - mkdir /var/lib/pilot/keycloak (chown 0:0 — keycloak runs as root in container)
#   - lineinfile /etc/hosts (idp.infra.internal → 127.0.0.1)  ← spec C9 needs this
#   - docker pull quay.io/keycloak/keycloak:25.0
#   - docker run pilot-keycloak (Profile prod activated；wait-for-HTTP 重試了 3 次才 ok，屬正常暖機)
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
go run ./cmd/pilot vm-target verify --name dockersplit docs/verification/keycloak.md
# verdict: **PASS**  (pass=3 fail=0 skip=0)
```

**4 個 spec 全部綠**（docker 8/8 + db 11/11 + provider 7/7 + keycloak 3/3
= 29/29）= end-to-end PASS。

---

## 3. 驗證最終狀態（2026-07-17 實跑截錄）

```bash
# Container 列表
go run ./cmd/pilot vm-target exec --name dockersplit -- docker ps
# CONTAINER ID   IMAGE                            STATUS                        NAMES
# 6f6004ddd47e   quay.io/keycloak/keycloak:25.0  Up 38 seconds (healthy)       pilot-keycloak
# 8f689aa54b7f   postgres:16                     Up About a minute (healthy)   pilot-postgres

# OIDC discovery 端到端
go run ./cmd/pilot vm-target exec --name dockersplit -- \
    curl -fsS -o /dev/null -w "code=%{http_code}\n" \
    http://idp.infra.internal:8080/realms/master/.well-known/openid-configuration
# code=200
```

> PostgreSQL 與管理員登入的密碼驗證需在受控終端以 vault 值執行；不要把
> 密碼以環境變數、CLI 參數或文件內容傳遞。上面的 container health check 與
> OIDC discovery 已涵蓋本 runbook 的非敏感端到端可用性確認。

---

## 4. Snapshot / Rollback

```bash
# Snapshot 整套狀態（keycloak + postgres containers + docker + unbound + chrony + /etc configs）
go run ./cmd/pilot vm-target snapshot --name dockersplit --tag post-keycloak-prod-install
# ✓ snapshotted dockersplit as post-keycloak-prod-install

# 跑壞了？
go run ./cmd/pilot vm-target rollback --name dockersplit --tag post-keycloak-prod-install
# ✓ rolled back dockersplit to post-keycloak-prod-install
```

---

## 5. Vault 文件範本

```yaml
# ~/.vault/keycloak-sandbox.yaml (chmod 600)
# 將下列 placeholder 換成唯一的實際值；此檔案不得提交到 git。
pg_keycloak_db_password: <postgres-password>
kc_admin_password: <keycloak-admin-password>
keycloak_db_user: keycloak
kc_db_password: <postgres-password>
```

Production 時改用對應的 vault 檔（`-e @~/.vault/keycloak-prod.yaml`），
**絕不**把密碼塞 CLI argv、環境變數或文件內容。

---

## 6. 變更紀錄

| 日期       | 版本 | 變更                                                                          | 變更者 |
|------------|------|--------------------------------------------------------------------------------|--------|
| 2026-07-01 | v1.0 | 初版（5 role end-to-end PASS；Keycloak production mode；PG docker container）   | sre    |
| 2026-07-14 | v1.1 | 移除文件與命令中的明文 Keycloak/PostgreSQL 密碼，統一改由 vault 檔注入 | Codex |
| 2026-07-17 | v2.0 | `docker` 角色從 `core-infra-provider-apply.yml -e infra_role=docker` 拆成獨立的 `playbooks/apply/docker-apply.yml`；全篇指令與 5 個角色的 playbook 對應表更新；在全新 vm-target（`dockersplit`）上重新跑完全部 5 個角色，4 條 spec（docker/db/core-infra-provider/keycloak）29/29 row PASS；順帶發現並修正 `core-infra-provider.md` C6 的既有 NTP stratum 檢查 bug（見 §2.5 說明）；記錄 `-e target_group=all` 在 sibling-of-vm-target 場景下的平行競態陷阱（見 §0.5） | pilot |