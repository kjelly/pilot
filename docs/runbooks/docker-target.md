# Runbook — `pilot docker-target` (Docker as a disposable target host)

> 撰寫日期：2026-06-30 (UTC)
> 對齊規範：見 `internal/dockertarget/dockertarget.go` 與 `cmd/pilot/cmd/docker_target.go`
> 維護者：sre

---

## 0. 一句話目標

> **「把 docker container 當 VM 用」**：起一台 disposable 容器、跑 playbook / spec、
> 驗證結果、拆掉。**和 `--sandbox` 完全不同**——`--sandbox` 是「pilot agent 的工具
> 執行環境」；`docker-target` 是「playbook / verify 的目標 host」。

兩者正交，可疊加也可以分開用。

---

## 1. 為什麼要這個機制

之前的痛點（你經歷過兩次）：

```bash
# 痛點 1：每次都得自己 docker run + 自己寫 inventory + 自己 rm
docker run -d --name infra-test ...
cat > /tmp/inv-docker.yaml ...
ansible-playbook -i /tmp/inv-docker.yaml ...
docker rm -f infra-test

# 痛點 2：`pilot run --sandbox` 跟「對 docker 套 playbook」是兩件事
# 你按 Tab 補完 `--sandbox` 跑下去，會以為能直接驗證，結果是「agent 工具跑容器」
# 而不是「playbook 操作容器」
```

新機制把這條鏈包成一個子命令群，每一步都自動：
1. `up` → docker run + 寫 state
2. `run` / `verify` → 自動帶 inventory + limit
3. `down` → docker rm -f + 刪 state

---

## 2. 一次完整操作流程

### 2.1 起一台 docker target

```bash
/tmp/pilot docker-target up --image ubuntu:24.04 --name infra-test
# ✓ target infra-test up
#   container_id : e9e926fc72c5
#   image        : ubuntu:24.04
#   hostname     : infra-test
#   network      : host
#   privileged   : true
#   inventory    : `pilot docker-target show-inventory --name infra-test`
```

預設值（`Options{}` zero value → 安全 default）：

| 設定 | 預設 | 為什麼 |
|------|------|--------|
| `--network` | `host` | 不開 bridge，省 DNS / port mapping 麻煩 |
| `--privileged` | `true` | 讓 container 內能 `apt install` / 跑 systemd 服務 |
| `--hostname` | = `--name` | ansible inventory key 跟 docker container name 一致 |
| entrypoint | `sleep infinity` | 容器常駐，playbook 跑完也不會自己退出 |

### 2.2 列出現有 targets

```bash
/tmp/pilot docker-target list
# NAME        IMAGE         STATUS   CONTAINER_ID  CREATED
# infra-test  ubuntu:24.04  running  e9e926fc      2026-06-30 09:18:09
```

`--json` 給 scripts 用。

### 2.3 在 container 裡 exec 一條命令

```bash
/tmp/pilot docker-target exec --name infra-test -- uname -a
# Linux infra-test 6.17.0-35-generic #35~24.04.1-Ubuntu SMP ...

/tmp/pilot docker-target exec --name infra-test -- bash -c 'cat /etc/os-release | head -3'
# PRETTY_NAME="Ubuntu 24.04.4 LTS"
# NAME="Ubuntu"
# VERSION_ID="24.04"
```

> 注意：argv 是**逐字**丟給 `docker exec`，沒有 host shell。
> 要用 pipe / redirect 就在 container 裡 `sh -c` 或 `bash -c`。

### 2.4 跑 playbook（自動帶 inventory + limit）

```bash
/tmp/pilot docker-target run --name infra-test -- \
    playbooks/apply/core-infra-provider-apply.yml \
    -e infra_role=dns \
    -e target_group=infra-test \
    -e dns_listen_addr=127.0.0.1 \
    --check --diff
```

`--` 後面的所有參數原封不動丟給 `ansible-playbook`，
外加 `-i <tmpfile> -l <target>` 由 pilot 自動注入。

### 2.5 跑 spec 驗證

```bash
/tmp/pilot docker-target verify --name infra-test -- \
    docs/verification/core-infra-provider.md
```

這等價於：

```bash
/tmp/pilot verify docs/verification/core-infra-provider.md \
    -i <generated-inventory> -l infra-test
```

### 2.6 拆掉

```bash
/tmp/pilot docker-target down --name infra-test
# ✓ target infra-test down
```

冪等：container 已經不在了也會成功清掉 state record
（避免之前的 bug：「docker rm: No such container」會冒上來誤導 user）。

---

## 3. 跟 `pilot sandbox` 的差別

| 軸 | `pilot sandbox` (--sandbox) | `pilot docker-target` (新) |
|----|----------------------------|----------------------------|
| 影響什麼 | pilot **agent** 的 tool exec 環境 | ansible playbook / verify 的 **target host** |
| 容器生命週期 | 跟 `pilot run` 同進退 | user 控制（up/down 明確指令） |
| 用途 | loop-engineer 同個 playbook 不用每次裝 | 對一台「準 production」的 container 套東西 |
| LLM / Ollama | 需要 | **不需要** |
| inventory 產生 | agent 內部自動 | CLI 自動 + 寫到 tmpfile |
| 跟 inventory.yaml 互動 | 不互動（容器是透明的） | 完全取代 — 你不需要寫 inventory-*.yaml |

**可以疊加**：

```bash
# 在 docker target 跑 playbook，同時 pilot agent 本身跑在另一台 sandbox container
/tmp/pilot run --sandbox --sandbox-image rockylinux:9 \
    playbooks/apply/core-infra-provider-apply.yml \
    -i /tmp/inv-from-docker-target.yaml
```

但 99% 情境下你只會用 `docker-target`，因為它**更直接**。

---

## 4. State 檔在哪

`$HOME/.local/share/pilot/docker-targets.json`（可用 `--data-dir` 改）

```json
{
  "version": 1,
  "targets": [
    {
      "name": "infra-test",
      "image": "ubuntu:24.04",
      "container_id": "e9e926fc72c5...",
      "status": "running",
      "hostname": "infra-test",
      "network": "host",
      "privileged": true,
      "created_at": "2026-06-30T09:18:09Z",
      "started_at": "2026-06-30T09:18:09Z"
    }
  ]
}
```

- **Versioned**（`"version": 1`）：未來 schema 改時會 fail-closed 而不是悄悄壞掉
- **Atomic save**：寫到 `<dir>/.docker-targets-*.json.tmp` 再 `rename`，避免 crash 中途
  留半截檔
- **gitignored**：`inventory*.yaml` 規則之外，但這份 state 內部有 container_id / 路徑
  等 metadata，不該進版控（進了也沒意義，別台機器的 container id 不一樣）

---

## 5. 雙回歸測試覆蓋

`internal/dockertarget/dockertarget_test.go` 17 個 case；`cmd/pilot/cmd/docker_target_test.go` 7 個。

| 測試 | 守的 bug |
|------|----------|
| `TestUp_RefusesDuplicate` | 第二次同名 Up 會「默默覆蓋」舊 record |
| `TestUp_RefusesHijack` | 撿到不屬於 pilot state 的同名 container 會「自動接管」 |
| `TestDown_IdempotentWhenContainerAlreadyGone` | 容器已被手動刪了還報 `No such container` |
| `TestExec_PassesArgvVerbatim` | `Exec` 偷偷加 `sh -c` 包 argv |
| `TestSave_AtomicOnDiskVerify` | crash mid-save 留半截 state 檔 |
| `TestList_StableOrder` | 容器順序隨 json map 迭代浮動 |
| `TestRunDtUp_RequiresName` | `--name` 缺了自動用 `pilot-target` 預設，污染 inventory key |
| `TestGet_RefreshStatus_Running/Missing` | docker 報 running/false/壞掉時的狀態機 |

---

## 6. 已知限制 / 後續可做

| 限制 | 影響 | 解法 |
|------|------|------|
| container 必須先裝 `python3`（ubuntu:24.04 minimal 沒預設） | ansible 跑不動 | run 前先 `pilot docker-target exec -- bash -c 'apt install -y python3'`；或預先 `docker commit` 一個帶 python 的 image |
| `playbooks/apply/core-infra-provider-apply.yml` 假設 `/etc/systemd/resolved.conf` 存在 | 全新 ubuntu container 沒裝 systemd-resolved | playbook 改成 `creates: ...` 條件；或 `apt install -y systemd-resolved` |
| `show-inventory` 不支援多 host | 一個 target = 一台 host | 多 host 用 `--sandbox-topology` 走 sandbox 那條 |
| `--privileged` 是 default | 在多租戶環境不適用 | `--no-privileged` + 自己手動 `--cap-add=...` |
| inventory 寫到 tmpfile | 失敗時可能留垃圾 | `defer os.Remove(invPath)` 已處理 |

### 6.1 建議的下一步

1. **pre-bake image**：寫一個 `Dockerfile.pilot-target-ubuntu` 把 `python3` + `systemd-resolved` 預裝好
2. **multi-host 支援**：把 `Target` struct 加 `[]string peers` 欄位，RenderInventory 出 group 形式
3. **`pilot docker-target snapshot <name> --tag <image>`** 跟 `pilot sandbox snapshot` 對齊
4. **整合進 run loop**：`pilot run --target <docker-target-name> <playbook>` 跟 LLM agent loop 接軌

---

## 7. 變更紀錄

| 日期 | 版本 | 變更 |
|------|------|------|
| 2026-06-30 | v1.0 | 初版：up/down/list/run/verify/exec/show-inventory 7 個子命令 |

---

## 8. 進階功能（v1.1 增量）

### 8.1 Pre-baked image（`--image-pilot`）

stock `ubuntu:24.04` 沒帶 `python3` / `systemd-resolved`，每次起 target 都要手動裝。
我們提供一份預裝好的 image：

```bash
# 1. 一次性 build
./images/build.sh
# pilot-target:ubuntu-24.04    211MB

# 2. 用 --image-pilot 走捷徑（展開為 pilot-target:ubuntu-24.04）
pilot docker-target up --image-pilot ubuntu-24.04 --name infra-test
# 或顯式：
pilot docker-target up --image pilot-target:ubuntu-24.04 --name infra-test
```

預裝的東西：`python3` / `systemd-resolved` / `iproute2` / `procps` / `dnsutils` /
`curl` / `sudo` / `ca-certificates` / `openssh-client` / `gnupg`。
跑 ansible playbooks 不會再「fatal: python3 not found」。

`--image` 跟 `--image-pilot` 互斥，避免 typo。

### 8.2 Multi-host targets（`--hosts`）

一台 docker container 可以有多個 ansible inventory alias，**全部指向同一台**。
給「一個 role 一個 group 名」的 playbook 用：

```bash
pilot docker-target up --image-pilot ubuntu-24.04 \
    --name core --hosts dns,ntp,keycloak
# inventory 同時有 core: dns: ntp: keycloak: 四個 host entry，
# 全部 ansible_host: core（同一台 container）
```

驗證：

```bash
pilot docker-target show-inventory --name core
# all:
#   hosts:
#     core:        { ansible_host: core, ... }
#     dns:         { ansible_host: core, ... }
#     ntp:         { ansible_host: core, ... }
#     keycloak:    { ansible_host: core, ... }
```

`--hosts` 接受 comma-separated 跟 repeated flag 兩種形式。Aliases 會被
去重（同一個名稱給兩次只出現一次）；無效字元（空白、slash）會被拒絕。

### 8.3 Snapshot / Rollback（`snapshot` / `rollback`）

跟 `pilot sandbox snapshot` 對齊：

```bash
# 1. 套完 DNS role 後存盤
pilot docker-target snapshot --name core --tag my-baseline
# ✓ snapshotted core as my-baseline (image id: sha256:23df9)

# 2. ... 跑其他 playbook 玩壞了 ...
pilot docker-target rollback --name core --image my-baseline
# ✓ rolled back core to image my-baseline (new container: 736f5160)

# rollback 會 preserve Hostname / Hosts / Network / Privileged，
# 換 image + 換 container_id，其他設定不動
```

### 8.4 整合進 `pilot run`（`--target`）

新 flag：`pilot run --target <docker-target-name> <playbook>...`。
LLM agent loop 的 `run_ansible` tool 會自動拿該 target 的 generated
inventory + limit 當 default，使用者不用手動帶 `-i /tmp/... -l core`：

```bash
pilot docker-target up --image-pilot ubuntu-24.04 --name core
pilot run --target core playbooks/apply/core-infra-provider-apply.yml \
    -e infra_role=dns
# agent loop 看到 playbook 給 LLM 時，run_ansible 預設就會用
# /tmp/pilot-run-target-XXX.yaml + --limit core
```

跟 `--sandbox` 是正交：
- `--target core` → LLM 的 `run_ansible` 跑在 host，把 inventory 指到 container
- `--sandbox`     → LLM 自己整套跑在一個 disposable container

兩個可以疊：`pilot run --sandbox --sandbox-image ubuntu:24.04 --target core`
讓 LLM 跑在 sandbox container A，但 `run_ansible` 對 sandbox container B 操作。
實務上 99% 不會這樣搞。

---

## 9. 變更紀錄（v1.1 增量）

| 日期 | 版本 | 變更 |
|------|------|------|
| 2026-06-30 | v1.1 | ＋pre-bake image (`--image-pilot`) / ＋multi-host (`--hosts`) / ＋snapshot+rollback / ＋`pilot run --target` |
| 2026-06-30 | v1.0 | 初版：up/down/list/run/verify/exec/show-inventory |
