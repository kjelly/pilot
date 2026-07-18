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

# 痛點 2（歷史）：舊 LLM agent 的 `pilot run --sandbox`（agent 工具跑容器）
# 常被誤當成「對 docker 套 playbook」；該 agent 面已於 2026-07-17 退役
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
| `--privileged` | `true` | 讓 container 內能 `apt install`、掛 cgroup |
| `--systemd` | `false` | 預設不開機 systemd（見下方說明） |
| `--hostname` | = `--name` | ansible inventory key 跟 docker container name 一致 |
| entrypoint | `sleep infinity` | 容器常駐，playbook 跑完也不會自己退出 |

> **⚠️ systemd 服務管理要加 `--systemd`**：預設 entrypoint 是 `sleep infinity`，
> 容器內 **PID 1 不是 systemd**，所以 `ansible.builtin.systemd` / `service` module、
> 或任何 `systemctl start/restart`（含啟動 `systemd-resolved`）都會回
> `System has not been booted with systemd as init system (PID 1)`。
> 要跑這類 playbook（例如 core-infra 的 DNS role），起 target 時加 `--systemd`：
>
> ```bash
> pilot docker-target up --image-pilot ubuntu-24.04 --systemd --name infra-test
> #   systemd      : true
> ```
>
> `--systemd` 會把 entrypoint 換成 `/sbin/init`，並掛上 `--tmpfs /run`
> `--tmpfs /run/lock`，讓 systemd 能在容器內當 PID 1 開機。它**需要 privileged**
> （和 `--no-privileged` 互斥，會直接報錯）以及一個**真的裝了 systemd 的 image**——
> stock `ubuntu:24.04` 沒有 `/sbin/init` 會起不來，請用 `--image-pilot ubuntu-24.04`
> （或自己 build 帶 systemd 的 image）。

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

（舊 LLM agent 的 `pilot run --sandbox` 疊加用法已隨 agent 面於 2026-07-17 退役；
對 docker 套 playbook 一律走 `docker-target`。）

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
| container 必須先裝 `python3`（ubuntu:24.04 minimal 沒預設） | ansible 跑不動 | 用 `--image-pilot ubuntu-24.04`（已預裝）；或 run 前 `apt install -y python3`；或自己 `docker commit` |
| 預設 entrypoint 是 `sleep infinity`，PID 1 不是 systemd | `systemctl` / `service` / `systemd-resolved` 任務全炸 | 起 target 時加 `--systemd`（見 §2.1 / §8.5），用 `/sbin/init` 開機 |
| `show-inventory` 不支援多 host | 一個 target = 一台 host | 多 host 用 `--sandbox-topology` 走 sandbox 那條 |
| `--privileged` 是 default | 在多租戶環境不適用 | `--no-privileged` + 自己手動 `--cap-add=...`；或改用 `--engine podman`（見 §8.6）— rootless 消掉「使用者在 docker group = host root」這條路 |
| inventory 寫到 tmpfile | 失敗時可能留垃圾 | `defer os.Remove(invPath)` 已處理 |

### 6.1 建議的下一步

1. **pre-bake image**：寫一個 `Dockerfile.pilot-target-ubuntu` 把 `python3` + `systemd-resolved` 預裝好
2. **multi-host 支援**：把 `Target` struct 加 `[]string peers` 欄位，RenderInventory 出 group 形式
3. **`pilot docker-target snapshot <name> --tag <image>`**
（原第 4 點「整合進 LLM agent run loop」已隨 agent 面於 2026-07-17 退役）

---

## 7. 變更紀錄

| 日期 | 版本 | 變更 |
|------|------|------|
| 2026-06-30 | v1.0 | 初版：up/down/list/run/verify/exec/show-inventory 7 個子命令 |

---

## 8. 進階功能（v1.1 增量）

### 8.1 Pre-baked image（`--image-pilot`）

stock `ubuntu:24.04` 沒帶 `python3` / `systemd` / `systemd-resolved`，每次起 target
都要手動裝。我們提供一份預裝好的 image，而且**第一次 `up` 會自動 build，不用先手動跑**：

```bash
# 直接 up；image 不在本機時會自動從內建 Dockerfile build（一次性，幾分鐘）
pilot docker-target up --image-pilot ubuntu-24.04 --name infra-test
# ▶ image pilot-target:ubuntu-24.04 not found locally; building from built-in Dockerfile (one-time, takes a few minutes)…
# ✓ built pilot-target:ubuntu-24.04
# ✓ target infra-test up

# 顯式 --image pilot-target:... 也會觸發同樣的自動 build：
pilot docker-target up --image pilot-target:ubuntu-24.04 --name infra-test
```

> 自動 build 只對 `pilot-target:*` tag 生效（內建 Dockerfile 已 embed 進 binary，
> 不依賴 CWD）。一般 `--image ubuntu:24.04` 之類仍交給 docker 自己 pull。
> 想預先 build（例如 CI、離線）仍可顯式跑 `./images/build.sh`。

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

### 8.4 整合進 `pilot run`（`--target`）——已退役

`pilot run --target` 是舊 LLM agent loop 的整合點，已隨 agent 面於
2026-07-17 退役。對 docker target 跑 playbook 直接用
`pilot docker-target run --name <n> <playbook> …`。

### 8.5 systemd target（`--systemd`）

讓 docker container 真正當 VM 用：以 systemd 開機，`systemctl` / `service` /
`systemd-resolved` 都能動。完整可還原、可測試的流程：

```bash
# 1. 以 systemd 開機起一台 target（image 不在本機會自動 build，含 systemd +
#    systemd-sysv + systemd-resolved，不用先手動 ./images/build.sh）
pilot docker-target up --image-pilot ubuntu-24.04 --systemd --name infra-test
#   privileged   : true
#   systemd      : true

# 2. 確認 PID 1 真的是 systemd（而不是 sleep）
pilot docker-target exec --name infra-test -- ps -p 1 -o comm=
# systemd
pilot docker-target exec --name infra-test -- systemctl is-system-running
# running   (或 degraded — 容器內部分 unit 起不來屬正常，systemctl 仍可用)

# 3. 跑需要 systemd 的 apply playbook（DNS role 會 restart systemd-resolved）
pilot docker-target run --name infra-test -- \
    playbooks/apply/core-infra-provider-apply.yml -e infra_role=dns

# 4. 驗證
pilot docker-target verify --name infra-test -- docs/verification/core-infra-provider.md
```

**還原（snapshot / rollback）對 systemd target 一樣適用**，且 rollback 會
preserve `--systemd` 設定（換 image / container 但 init 模式不變）：

```bash
pilot docker-target snapshot --name infra-test --tag dns-baseline
# ... 玩壞了 ...
pilot docker-target rollback --name infra-test --image dns-baseline
#   新 container 仍以 systemd 開機（Systemd 欄位隨 state 一起 round-trip）

# 徹底拆掉（systemd 收到 SIGRTMIN+3 會 graceful shutdown，不會卡 10s timeout）
pilot docker-target down --name infra-test
```

注意事項：
- `--systemd` **必須 privileged**（與 `--no-privileged` 互斥，會直接報錯）。
- image 必須有 `/sbin/init`；stock `ubuntu:24.04` 沒有，請用 `--image-pilot`。
- 不需要 systemd 的 playbook 就別開 `--systemd`，`sleep infinity` 更輕量、
  也能用任何沒裝 systemd 的 image（含 alpine / distroless）。

### 8.6 Podman engine（`--engine podman`，opt-in）

> Status: **opt-in，docker 仍是預設**。兩邊並存一段時間再決定要不要切預設值。

動機：拿掉「使用者要在 `docker group` 才能跑 docker-target」這個 root-equivalence
洞（`docker group` 成員等同 host root，`docker run -v /:/host` 就能提權）。
podman rootless + daemonless，天生不需要這個 group。

```bash
pilot docker-target up --image-pilot ubuntu-24.04 --name infra-test \
    --engine podman
#   engine       : podman

# --systemd 一樣可以疊：rootless podman 對「容器內 systemd」的支援本來就比
# docker 成熟，這是 podman 的招牌功能之一，不是靠 --privileged 硬撐。
pilot docker-target up --image-pilot ubuntu-24.04 --engine podman \
    --systemd --name infra-test
```

- `--engine` 只在 `up` 指定；`down` / `exec` / `run` / `verify` / `snapshot` /
  `rollback` 都從 state 讀回該 target 建立時的 engine，不用每次重複帶。
- 底層走 `containers.podman.podman` ansible connection plugin（`containers.podman`
  collection 是前置條件，不是 `community.docker` 那個 `docker` plugin）。
- Binary 覆寫：`PILOT_PODMAN_BIN`（對稱於既有的 `PILOT_DOCKER_BIN`）。
- **rootless 前置條件**（機器層級，不是這個 repo 能保證的）：
  - cgroup v2 + systemd user session delegation（Ubuntu 24.04 預設有，但要在
    實際跑 docker-target 的機器上確認，CI service account 常常沒有）
  - `/etc/subuid` / `/etc/subgid` 有給該使用者帳號配 range（一般互動式帳號
    `adduser` 時會自動配，service account 常常沒有，要另外設定）
- 已知限制：rootless `--privileged` 不是 docker 那種「真 host root」（被 user
  namespace 關住），但目前 `--systemd` 路徑仍然要求 privileged；拿掉它、改用
  `--cap-add` 白名單是下一步，不在這次範圍內。

**已在真機 podman 4.9.3（rootless，Ubuntu）跑過 end-to-end**：
`up`（含 `--image-pilot` 自動 `podman build`）→ `show-inventory` → `ansible -m ping`
（透過 `containers.podman.podman`）→ `docker-target run`（完整 playbook，
含 `copy` module）→ `snapshot` → `rollback`（`engine` 欄位正確保留）→ `down`。
`--systemd` 也驗證過：容器內 `ps -p 1 -o comm=` 回 `systemd`，且即使
`--privileged`，host 端的 `conmon`/container process owner 仍是一般使用者
（非 root）——證實 rootless `--privileged` 跟 docker 的 `--privileged` 不是
同一個風險等級。

過程中順手修了一個**跟這次改動無關的既有 bug**：`docker-target run` 和
`show-inventory` 兩個子命令一直在檢查 `dtSnapshotTag`（一個屬於 `snapshot`
子命令的 package-level flag 變數,`run`/`show-inventory` 根本沒有 `--tag`
flag）,導致這兩個指令在乾淨的 CLI 呼叫下永遠因為空字串驗證失敗而報錯。
已移除這兩處誤植的檢查（`runDtShowInventory` / `runDtRun`）。

---

## 9. 變更紀錄（v1.1+ 增量）

| 日期 | 版本 | 變更 |
|------|------|------|
| 2026-07-03 | v1.3 | ＋`--engine podman`（opt-in，docker 仍是預設）：rootless/daemonless，消掉 docker-group root-equivalence；`Target`/`Options` 加 `Engine` 欄位、per-engine binary override（`PILOT_PODMAN_BIN`）、inventory 依 engine 切 `containers.podman.podman` connection plugin；真機 rootless podman 4.9.3 跑過 up/show-inventory/ping/run/snapshot/rollback/down + `--systemd` 全套驗證；順手修 `run`/`show-inventory` 誤檢查 `dtSnapshotTag` 的既有 bug |
| 2026-06-30 | v1.2 | ＋`--systemd`（以 /sbin/init 開機，systemctl/service/systemd-resolved 可用，rollback 保留設定）；image 補 systemd+systemd-sysv+STOPSIGNAL；`up` 對 `pilot-target:*` image 缺漏時自動 build（Dockerfile embed 進 binary，免先跑 build.sh）；修 `pilot run --target` 的 inventory tmpfile 外洩 |
| 2026-06-30 | v1.1 | ＋pre-bake image (`--image-pilot`) / ＋multi-host (`--hosts`) / ＋snapshot+rollback / ＋`pilot run --target` |
| 2026-06-30 | v1.0 | 初版：up/down/list/run/verify/exec/show-inventory |
