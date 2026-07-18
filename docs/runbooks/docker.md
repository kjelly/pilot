# Runbook — `docker` (container engine, standalone playbook)

> Status: **spec live, apply now fully independent**. `docs/verification/docker.md`
> 8/8 PASS on a genuinely fresh vm-target (see §2 below for real captured
> output). Apply playbook: `playbooks/apply/docker-apply.yml` — a standalone
> playbook, no longer a `-e infra_role=docker` branch inside
> `core-infra-provider-apply.yml`. Docker is still the prerequisite for `db`
> (`keycloak-db-apply.yml`) and `keycloak` (`keycloak-apply.yml`), plus
> `seaweedfs-s3`、`wazuh-manager`、`prometheus`/`thanos-query`/`alertmanager`.

> 撰寫日期：2026-07-01 (UTC)；改版日期：2026-07-17 (UTC)
> 對齊規範：見 `docs/verification/docker.md`
> 維護者：sre

---

## 0. 一句話目標

> 跑 `go run ./cmd/pilot vm-target run … playbooks/apply/docker-apply.yml` 一次，
> 這台 VM 上就有 docker engine + compose plugin。後續 `db` 跟 `keycloak`
> 兩個 role 才能起 container。

## 0.5 事實快照（2026-07-17 跑這次重新驗證時）

```bash
go run ./cmd/pilot vm-target list
# NAME         STATUS   IP             VCPU  MEM(MiB)  DISK(GiB)  CREATED
# dockersplit  running  192.168.122.2  2     2048      20         2026-07-17 16:12:18

go run ./cmd/pilot vm-target show-inventory --name dockersplit | grep -E '^    [a-z]'
# dockersplit:
# core:
# docker:
# ntp:
# dns:
```

- 目標 group：`docker`（本 spec 的預設目標；vm-target 情境下 sibling alias
  還有 `core`/`dns`/`ntp`，同一個 IP）。
- vault 依賴：無——`docker-apply.yml` 不吃任何密碼變數。
- 對齊決定：spec §1 宣告的 `docker`/`core` 兩個 group，跟這次 `vm-target up
  --hosts core,docker,dns,ntp` 建出的 inventory 完全對齊，走 **A（inventory
  已經對齊，不用改 spec）**。

## 1. 為什麼這個 role 獨立成自己的 playbook

原本 `docker` 是 `core-infra-provider-apply.yml` 裡用 `-e infra_role=docker`
選的一個分支，跟 `dns`/`ntp` 共用同一支檔案、同一個 stage gate。2026-07-17
把它拆成獨立的 `playbooks/apply/docker-apply.yml`，理由跟同一天更早拆出
`keycloak-db-apply.yml`（PostgreSQL）一致：

- **machine 級 vs 應用/服務 級改動分開**：裝 docker 引擎是一次性的機器層級
  改動（後續 `db`/`keycloak`/`seaweedfs-s3`/`wazuh-manager` 等角色都要靠它），
  跟 `dns`/`ntp` 這種「這台機器本身要提供 DNS/NTP 服務」的 provider 設定，
  責任邊界不同，不該共用同一支 playbook、同一個 stage/confirm 生命週期。
- **`pilot deploy` 選單更誠實**：獨立成 catalog entry 後，使用者選「Container
  引擎(Docker)」時看到的就是它自己的 playbook，不用先選「核心基礎服務」
  再從 `infra_role` 三選一，且不會把 docker 的 note（"是 keycloak-db/keycloak
  等角色的前置"）跟 dns/ntp 的 note 混在一起。
- **拆分後仍相容既有 5-role pipeline**：`docs/runbooks/core-infra-provider-end-to-end.md`
  描述的 `docker → db → dns → ntp → keycloak` 順序不變，只是第一步的指令換了
  一個 playbook 路徑。

拆分本身不改變 `docs/verification/docker.md` 的 checklist（C1–C8 不變）——
純粹是「哪支 playbook 負責套用」的變動。

## 2. Pipeline（全部用 `go run ./cmd/pilot vm-target` 跑過，2026-07-17 重新驗證）

```bash
# 0. Lint
go run ./cmd/pilot spec docs/verification/docker.md --lint
# spec Verification Spec — docker (container engine): 8 rows, 1 findings (0 errors)
#   (findings 是既有的 C2 ~active/inactive substring 警告，非本次拆分引入)

# 1. （此步驟已棄用 2026-07-17）不再產生 playbooks/verify/docker.yml——
#    驗收由後面的 `pilot vm-target verify`/`test` 直接吃 spec 執行，
#    見 playbooks/verify/README.md

# 2. 起一台全新 vm-target（沒有裝過任何東西的 ubuntu-24.04-golden 基底）
go run ./cmd/pilot vm-target up \
    --base-image /var/lib/libvirt/images/pilot/images/ubuntu-24.04-golden.qcow2 \
    --name dockersplit --ssh-user root \
    --hosts core,docker,dns,ntp \
    --vcpus 2 --memory 2048 --disk 20 \
    --ssh-timeout 8m --boot-timeout 8m

# 3. Dry-run（--check --diff；所有 mutate task 應全部 skipping）
go run ./cmd/pilot vm-target run --name dockersplit \
    playbooks/apply/docker-apply.yml \
    -e target_group=docker \
    --check --diff
# PLAY RECAP: docker  ok=3  changed=0  unreachable=0  failed=0  skipped=5

# 4. 真套用
go run ./cmd/pilot vm-target run --name dockersplit \
    playbooks/apply/docker-apply.yml \
    -e target_group=docker
# PLAY RECAP: docker  ok=5  changed=2  unreachable=0  failed=0  skipped=2
#   - Docker — install docker.io (Debian family)   changed
#   - Docker — enable + start docker.service        ok (already started by apt hook)
#   - Docker — ensure docker CLI usable (group add) changed

# 5. Verify
go run ./cmd/pilot vm-target verify --name dockersplit \
    docs/verification/docker.md
# verdict: **PASS**  (pass=8 fail=0 skip=0)

# 6. 冪等性檢查：原樣重跑一次，PLAY RECAP 必須 changed=0
go run ./cmd/pilot vm-target run --name dockersplit \
    playbooks/apply/docker-apply.yml \
    -e target_group=docker
# PLAY RECAP: docker  ok=5  changed=0  unreachable=0  failed=0  skipped=2
```

實跑截錄（`docker --version` / `docker compose version` / group membership）：

```
Docker version 29.1.3, build 29.1.3-0ubuntu3~24.04.2
Docker Compose version 2.40.3+ds1-0ubuntu1~24.04.1
active
uid=0(root) gid=0(root) groups=0(root),112(docker)
```

> **路徑**：`pilot vm-target run` 會自動塞 `-i inv -l dockersplit`；你只需要
> 指定 `-e target_group=docker`（或任何 sibling alias：core/dns/ntp/keycloak/
> keycloak-db/db）。`docker-apply.yml` 不再需要 `-e infra_role=docker`——它本身
> 就是單一角色的 playbook。

## 3. 順序

```
docker  →  db  →  keycloak
  │        │       │
  │        │       └── pilot-keycloak (docker) 連 pilot-postgres (docker)
  │        └── pilot-postgres (docker) 5432/tcp
  └── docker engine (playbooks/apply/docker-apply.yml)
```

跑同一台 VM 場景（sibling-of-vm-target）：同一個 IP 換 3 支「各自獨立」的
playbook（`docker-apply.yml` → `keycloak-db-apply.yml` → `keycloak-apply.yml`）
即可。**先 docker、再 db、最後 keycloak**（keycloak 連 db）。

## 4. 已知限制（記錄，暫無修復需求）

- **RHEL family（AlmaLinux/Rocky/RHEL 9）套用 `docker-apply.yml` 會失敗**：
  `Docker — install docker (RHEL family)` task 直接嘗試 `dnf install docker
  docker-compose`，但 AlmaLinux 9 預設倉庫（BaseOS/AppStream）沒有
  `docker-compose` 這個套件，需要額外的 EPEL 或 Docker 官方 `docker-ce` repo
  才能裝——目前 playbook 沒有處理這個 repo 依賴，真實錯誤是 `Failed to install
  some of the specified packages: No package docker-compose available`
  （2026-07-17 runbook 整併重測時，嘗試在既有 AlmaLinux 9 vm-target 上套
  docker 給 `metrics-alerting.md` 當 S3 目的地用而踩到；playbook 拆分後此
  限制原封不動延續）。
- **目前無此需求，只記錄不修**：本專案所有需要 docker 的角色（`db`、
  `keycloak`、`seaweedfs-s3`、`prometheus`/`thanos-query`/`alertmanager`
  等）在既有 runbook 裡都是用 Ubuntu vm-target 驗證過，沒有 RHEL family
  的實際部署需求。若未來真的要在 EL 系主機上跑 docker，需要先在
  `docker-apply.yml` 補上 EPEL/docker-ce repo 的安裝步驟，再重新驗證這條路徑。

## 5. 變更紀錄

| 日期       | 版本 | 變更                                                    | 變更者 |
|------------|------|--------------------------------------------------------|--------|
| 2026-07-01 | v1.0 | 初版（spec 8 row + apply 段 + regression test）        | sre    |
| 2026-07-17 | v1.1 | 新增 §4：記錄 RHEL family（AlmaLinux 9）`infra_role=docker` 因缺 `docker-compose` 套件來源（無 EPEL/docker-ce repo）而失敗的已知限制。純文件註記，不修程式碼——目前所有需要 docker 的角色都只在 Ubuntu vm-target 上驗證，沒有 EL 系的實際需求 | sre |
| 2026-07-17 | v2.0 | Apply 段從 `core-infra-provider-apply.yml` 的 `infra_role=docker` 分支拆成獨立的 `playbooks/apply/docker-apply.yml`（自己的 stage/confirm gate，理由同日拆 `keycloak-db` 一致）；全篇指令改用新 playbook 路徑；在全新 vm-target（`dockersplit`）上重新跑過 apply → verify → 冪等 rerun，8/8 PASS，`changed=0` 收斂；§0.5 補上本次事實快照 | pilot |