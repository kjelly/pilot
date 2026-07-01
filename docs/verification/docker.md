# Verification Spec — docker (container engine)

> 版本：v1.0
> 對齊規範：pilot 通用 container engine 規範（`docker.io` 提供 container runtime；`db` 跟 `keycloak` 兩個 infra role 都跑在它上面）
> 維護者：sre

## 1. 目標系統

| Hostname     | Group          | Address          | User   | Port | IdentityFile  |
|--------------|----------------|------------------|--------|------|---------------|
| docker-host  | docker         |                  |        |      |               |
| core         | core           |                  |        |      |               |

> 同一台 host 可同時是 `docker` + `core`（sibling-of-vm-target pattern）。`docker`
> group 是本檔預設目標。

## 2. Checklist

| ID  | Category    | Check                                                                                | Expected | Command |
|-----|-------------|--------------------------------------------------------------------------------------|----------|---------|
| C1  | pkg         | docker server 已安裝（`docker.io` 套件；dev box 沒裝會 fail）                            | ~1       | dpkg-query -W -f='${Package}\n' docker.io 2>/dev/null | awk "/^docker\\.io$/ {f=1} END{print f+0}" |
| C2  | service     | docker 服務 active（systemd unit 為 `docker.service`）                                  | ~active  | systemctl is-active docker 2>&1 | head -n1 |
| C3  | cli         | `docker --version` 印出 `Docker version ...` 字串                                    | ~Docker | docker --version 2>&1 | head -n1 |
| C4  | socket      | `/var/run/docker.sock` 存在且 group=docker                                             | ~docker  | stat -c '%a %U %G %n' /var/run/docker.sock 2>/dev/null | head -n1 |
| C5  | hello-world | `docker run --rm hello-world` 至少能跑完一次（證明 pull + run + cleanup 全鏈通）           | ~Hello   | docker run --rm hello-world 2>&1 | grep -m1 -oE 'Hello from Docker' | head -n1 |
| C6  | network     | `docker network ls` 至少包含預設三個（bridge / host / none）                              | ~bridge  | docker network ls --format '{{.Name}}' 2>/dev/null | grep -m1 -oE '^bridge$' | head -n1 |
| C7  | compose     | `docker compose version` 有印出來（v2 plugin；apt 裝 `docker-compose-v2` 給）             | ~Docker  | docker compose version 2>&1 | head -n1 |
| C8  | cgroup      | docker info 顯示 cgroup driver 為 systemd 或 cgroupfs（host 跟 container driver 一致）   | ~Cgroup  | docker info 2>/dev/null | grep -m1 -E 'Cgroup (Driver|Version)' | head -n1 |

> C5 hello-world 第一次跑會 pull image（~10s）；後續跑 < 1s。
> C4 `~docker` 是 substring 比對，捕到 `/var/run/docker.sock` 那一行（含 group 名 `docker`）。
> C7 預期 `Docker Compose version v2.x.x` 之類 — substring `Docker` 即可。
> C8 預期 `Cgroup Driver: systemd` 或 `Cgroup Version: 2` — substring `Cgroup` 即可。

## 3. 證據收集

- 工具：`pilot verify docs/verification/docker.md -i inventory-core-infra.yaml -l docker`
- 格式：`.verification/docker-<UTC>.{ndjson,md}`
- Row 數：8

範例輸出（dev box 沒裝 docker → 大部分 fail）：

```json
{"id":"C1","status":"fail","detail":"rc=0, expected 1 (stdout 0)"}
{"id":"C2","status":"fail","detail":"inactive"}
{"id":"C5","status":"fail","detail":"docker not found"}
```

## 4. PASS / FAIL 規則

- C1–C8 全部 `status=pass` → **PASS**：本機已準備好跑 `db` 跟 `keycloak` 兩個 Docker-backed role
- 任一 fail → **FAIL**；常見修法：
  - C1 fail → `apt install docker.io docker-compose-v2`（Debian）；`dnf install docker docker-compose`（RHEL）
  - C2 fail → `systemctl enable --now docker`
  - C3 fail → docker CLI 不在 `$PATH`；檢查 `/usr/bin/docker` 是否被 strip 掉（v29 的 `docker --version` 是 `Docker version X.Y.Z, build ...`，沒 Server/Client 分行）
  - C4 fail → `/var/run/docker.sock` 不在；dockerd 沒啟動（先解決 C2）
  - C5 fail → hello-world pull 失敗（網路 / DNS）；先試 `docker pull hello-world` 看錯誤
  - C6 fail → dockerd 沒建預設 network（罕見；多半是 dockerd crash → 看 `journalctl -u docker`）
  - C7 fail → 沒裝 `docker-compose-v2` plugin；apt 補
  - C8 fail → cgroup driver 不一致（混 systemd + cgroupfs）；看 kernel 是不是 cgroup v2（Ubuntu 22.04+ 預設 v2）

## 5. 例外與已知偏差

| ID  | 例外內容                                                              | 適用環境       | 期限     |
|-----|----------------------------------------------------------------------|---------------|----------|
| C5  | 在 air-gapped / 嚴格 firewall 環境下 pull 失敗                            | 任何          | 至 network 修好 |
| C8  | 某些 cloud image 預設 cgroupfs；`docker info` 顯示 `Cgroup Version: 1` | 舊版 image    | 無       |

## 6. Playbook 對應

對應產生的 **verify** playbook：`playbooks/verify/docker.yml`（spec generator）

對應手寫的 **apply** playbook：`playbooks/apply/core-infra-provider-apply.yml`（`infra_role=docker` 段）

| Spec ID | Apply task (示例)                              | 備註 |
|---------|-----------------------------------------------|------|
| C1      | `apt install docker.io docker-compose-v2`       | apt + become |
| C2      | `systemd enable --now docker`                   | idempotent |
| C3-C8   | （無對應 task；`docker` 套件裝好後自動能用）         | 驗證端檢查 |

> Apply playbook 必須 `block/rescue` 保護：apt 失敗（網路問題）不要 lockout host。

## 7. 把 FAIL 變 PASS 的 SOP

```bash
# 1. 套前先看這台 host 是哪一個 group
ansible docker-host -i inventory-core-infra.yaml -m shell -a "id; hostname"

# 2. 跑 dry-run
go run ./cmd/pilot vm-target run --name core \
    playbooks/apply/core-infra-provider-apply.yml \
    -e target_group=docker -e infra_role=docker \
    --check --diff

# 3. 真套用
go run ./cmd/pilot vm-target run --name core \
    playbooks/apply/core-infra-provider-apply.yml \
    -e target_group=docker -e infra_role=docker
# PLAY RECAP: changed=4..6 failed=0
#   - apt install docker.io docker-compose-v2
#   - apt cache update
#   - systemd docker enable/start
#   - user group add (root → docker)

# 4. 立即 verify
go run ./cmd/pilot vm-target verify --name core \
    docs/verification/docker.md
# verdict: **PASS**  (pass=8 fail=0 skip=0)
```

> **順序很重要**：`docker` 必須在 `db` 跟 `keycloak` 之前（後兩者用 docker）。
> 跑同一台 VM 場景（sibling-of-vm-target）：同一 IP 跑 3 個 role 就好。

## 8. 變更紀錄

| 日期       | 版本 | 變更                                       | 變更者 |
|------------|------|-------------------------------------------|--------|
| 2026-07-01 | v1.0 | 初版（C1–C8：docker engine 端到端健康）     | sre    |
