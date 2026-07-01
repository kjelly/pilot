# Runbook — `docker` (container engine for `db` + `keycloak`)

> Status: **spec live, apply wired**. `docs/verification/docker.md` 8/8 PASS;
> `core-infra-provider-apply.yml` 的 `infra_role=docker` 段會自動 `apt install
> docker.io docker-compose-v2` + `systemd enable --now docker`。Docker 是
> `db` 跟 `keycloak` 兩個 infra role 的 prerequisite，必須先套。

> 撰寫日期：2026-07-01 (UTC)
> 對齊規範：見 `docs/verification/docker.md`
> 維護者：sre

---

## 0. 一句話目標

> 跑 `go run ./cmd/pilot vm-target run … -e infra_role=docker` 一次，
> 這台 VM 上就有 docker engine + compose plugin。後續 `db` 跟 `keycloak`
> 兩個 role 才能起 container。

## 1. 為什麼這個 role 獨立

原本 `db` 跟 `keycloak` 兩個 apply 段都要起 container，但它們**沒**包
「裝 docker 引擎」這一步。原因是裝 docker 是「machine 級」改動，跟裝
postgresql 套件、起 Keycloak config 是「application 級」改動不同 — 後者
可以重跑，前者重跑太多次會把 base image 弄髒。

把 `docker` 拉成獨立 role 的好處：
- 一台 host 跑一次就夠；後續 `db` / `keycloak` 跑都靠這個 docker
- CI / staging / prod 三個 stage 都跑一次 `docker`，後面 4 個 role 各自 idem
- rollback 簡單：`vm-target rollback` 還原到「docker 裝好但沒起任何 container」

## 2. Pipeline（全部用 `go run ./cmd/pilot vm-target` 跑過）

```bash
# 0. Lint
go run ./cmd/pilot spec docs/verification/docker.md --lint
# spec Verification Spec — docker (container engine): 8 rows, 0 findings (0 errors)

# 1. Generate verify playbook
go run ./cmd/pilot spec docs/verification/docker.md \
    --generate playbooks/verify/docker.yml
# ✔ generated playbook: ... (2 tasks, 8 rows → 6 deduped)
# ✔ recorded 8 checkpoints (run_id=spec-docker)

# 2. Apply
go run ./cmd/pilot vm-target run --name core \
    playbooks/apply/core-infra-provider-apply.yml \
    -e target_group=core -e infra_role=docker
# PLAY RECAP: ok=6 changed=2 failed=0
#   - apt install docker.io docker-compose-v2
#   - systemd enable --now docker

# 3. Verify
go run ./cmd/pilot vm-target verify --name core \
    docs/verification/docker.md
# verdict: **PASS**  (pass=8 fail=0 skip=0)
```

> **路徑**：`pilot vm-target run` 會自動塞 `-i inv -l core`；你只需要指定
> `-e target_group=core`（或任何 sibling alias：dns/ntp/keycloak/keycloak-db/db/docker）
> 跟 `-e infra_role=docker`。
>
> 同台 VM 想換 `infra_role` 不用改 inventory，只要把 `infra_role` 換掉、target
> 指向同個 sibling alias 即可。

## 3. 順序

```
docker  →  db  →  keycloak
  │        │       │
  │        │       └── pilot-keycloak (docker) 連 pilot-postgres (docker)
  │        └── pilot-postgres (docker) 5432/tcp
  └── docker engine
```

跑同一台 VM 場景（sibling-of-vm-target）：同一個 playbook 三次，換
`infra_role` 三次就好。**先 docker、再 db、最後 keycloak**（keycloak 連 db）。

## 4. 變更紀錄

| 日期       | 版本 | 變更                                                    | 變更者 |
|------------|------|--------------------------------------------------------|--------|
| 2026-07-01 | v1.0 | 初版（spec 8 row + apply 段 + regression test）        | sre    |
