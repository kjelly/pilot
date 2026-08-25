# Verification Spec — dcgm-exporter（被監控主機的 GPU 監控 agent：NVIDIA DCGM Exporter）

> 版本：v1.0
> 對齊規範：pilot 通用「每台受管主機都裝一份」agent 規範，跟
> `host-monitoring.md`/`wazuh-fim.md`/`audit-log-forwarding.md` 同一類 Shape
> （cross-cutting agent role，可疊加到任何既有主機上，不擁有專屬 role 之外
> 的意義）。獨立成自己的 component，理由見 `host-monitoring.md` 開頭的說明：
> 一個軟體一個 component，不要塞進 `host-monitoring` 那份 spec/playbook。
> 維護者：sre

> 這份 spec 只負責 GPU 硬體層 metrics（利用率、記憶體、溫度、功耗……），來源
> 是 NVIDIA 官方的 `dcgm-exporter`。**這份 playbook 不安裝、不管理 NVIDIA
> GPU 驅動本身**——驅動被視為主機硬體佈建階段就該裝好的前提（跟
> `host-monitoring.md` 不管理 Kubernetes 本身、只偵測它是同一種責任邊界切
> 法）；這裡只負責「驅動已經裝好」之後的容器化 exporter 部署。
>
> **GPU 自動偵測**：套用前用 `nvidia-smi -L` 探測目標主機是否真的有 GPU
> 且驅動可用——沒有的話整段原生安裝直接跳過（不 fail、不要求密碼），這樣
> `dcgm-exporter` inventory group 可以跟其他監控 agent 一樣統一管理一批候選
> 主機，即使其中混了非 GPU 主機也不會出錯。
>
> **Kubernetes GPU Operator 自動偵測**：某些 GPU 主機可能已經透過 Kubernetes
> 的 NVIDIA GPU Operator（該 Operator 預設就會部署自己的 `dcgm-exporter`
> DaemonSet）在管 `:9400`，不是靠這支 playbook。套用前會先檢查
> `dcgm_exporter_port` 是否已經被監聽、且不是這支 playbook 自己管理的容器
> ——如果是，整段原生安裝直接跳過（不搶 port），跟 `host-monitoring.md`
> §0 對 Kubernetes DaemonSet 的處理方式一致。

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Hostname / Inventory group | `dcgm-exporter`（vm-target/真實主機測試時用單一 host，見 §7） |
| OS / version | Ubuntu 22.04/24.04 LTS（apt；NVIDIA Container Toolkit 官方 repo 目前只驗證過這個 distro 家族，見 §1.5） |
| 角色 | GPU 主機：以官方 Docker image 執行 `dcgm-exporter`，透過 NVIDIA Container Toolkit 把 GPU 裝置傳進容器，對外提供 `:9400/metrics` |
| 套用範圍 | `nvidia-container-toolkit` 套件、`/etc/docker/daemon.json` 的 `nvidia` runtime、`pilot-dcgm-exporter` 容器、`/etc/dcgm-exporter/web-config.yml` |
| 風險等級 | Low（純唯讀 metrics exporter，不接受任何寫入型 API；主要風險是暴露 GPU 硬體使用細節，故跟 `host-monitoring.md` 一樣強制 Basic Auth） |

## 1.5 依賴變數契約

在套用或驗證此主機時，Playbook 與變數參數必須嚴格遵守以下命名，禁止擅自縮寫或發明新變數：

| 變數名稱 | 說明/用途 | 是否必填 | 預設值 |
|---------|----------|---------|--------|
| `dcgm_exporter_version` | 固定安裝的官方 Docker image tag（`nvidia/dcgm-exporter` on Docker Hub） | 否 | `3.3.9-3.6.1-ubuntu22.04` |
| `dcgm_exporter_port` | exporter 監聽的 port（容器內外一致，`-p` 直通） | 否 | `9400` |
| `dcgm_exporter_basic_auth_user` | HTTP Basic Auth 使用者名稱（非機密） | 否 | `prometheus` |
| `dcgm_exporter_basic_auth_password` | HTTP Basic Auth 密碼；日後接上 `prometheus.md` 的 GPU scrape 設定時，兩邊必須用同一個值，否則 Prometheus 端會被 401 擋下（見本檔 §5 已知留白） | 是 | 無（空值會被 gate 擋下） |

> **為何用官方 Docker image，不像 `host-monitoring.md` 那樣走 pinned
> release binary**：`dcgm-exporter` 本身要連結 DCGM 共用函式庫（`libdcgm.so`）
> 才能跟驅動溝通，NVIDIA 沒有提供一個可以像 `node_exporter` 那樣單一靜態
> binary + 官方 checksum 直接下載驗證的發佈形式——官方唯一穩定支援的發佈
> 管道就是 Docker/OCI image（`nvidia/dcgm-exporter`），版本標籤本身已經
> 固定了 DCGM/driver toolkit 組合，等同於 `node_exporter_checksums` 那種
> 版本鎖定的角色。它需要目標主機已有可用的 Docker Engine，但**不**依賴
> pilot 的 `docker` component，也不要求該主機被放進 `docker` inventory group：
> 已由既有環境管理的 Docker 可以直接使用。這是本 repo 少數 docker-based
> 而非 binary-based 的 per-host agent。
>
> **NVIDIA Container Toolkit**：讓 `docker run --runtime nvidia` 能把 GPU
> 裝置節點/驅動函式庫正確 bind 進容器，是 GPU 監控容器化的必要中介層，屬於
> 這個 playbook 的套用範圍（類比 `host-monitoring.md` 為了 Basic Auth 安裝
> `htpasswd` 這個小依賴，而不是它要管理的核心對象）。套件來自 NVIDIA 官方
> `libnvidia-container` apt repo（`nvidia.github.io/libnvidia-container`），
> 目前只驗證過 Ubuntu/Debian 家族；GPU 驅動本身（`nvidia-driver-*`）不在
> 這支 playbook 的套用範圍內，必須由主機佈建階段先裝好——`nvidia-smi -L`
> 探測失敗就代表這個前提不成立，整段原生安裝優雅跳過（見 §0/§5）。
>
> **為何 Basic Auth 是強制而非選填**：跟 `host-monitoring.md` v1.1 的
> node_exporter 一樣，`dcgm-exporter` 預設把 GPU 使用率/記憶體/溫度/功耗等
> 硬體細節用純文字攤在 `:9400/metrics` 上，任何連得到這個 port 的人都能讀
> ——同一種主機偵查資訊洩漏風險。實測確認 `dcgm-exporter` 3.x 也是用跟
> `node_exporter` 相同的 `exporter-toolkit` web config 機制（`--web-config-file`
> flag，`docker run --entrypoint dcgm-exporter nvidia/dcgm-exporter:<tag>
> --help` 可看到），所以套用方式完全比照 `host-monitoring.md` §1.5：
> `htpasswd -nbBC 10` 在目標主機就地產生 bcrypt hash，明文密碼不落地、不進
> Ansible log（`no_log: true`），用密碼明文的 sha256 fingerprint 判斷憑證是
> 否真的變了，只有真的變了才重新雜湊、重寫檔案、重啟容器。

## 2. Checklist

| ID  | Category | Check                                             | Expected  | Command |
|-----|----------|----------------------------------------------------|-----------|---------|
| C1  | pkg      | `nvidia-container-toolkit`（`nvidia-ctk` CLI）已安裝  | present   | nvidia-ctk --version |
| C2  | config   | **運行中的** Docker daemon 已註冊 `nvidia` runtime（不是只檢查 `daemon.json` 文字） | 0 | sh -c 'docker info | sed -n "/^ Runtimes:/p" | grep -qw nvidia; echo $?' |
| C3  | container| `pilot-dcgm-exporter` 容器為 running                 | 1         | docker ps --filter name=pilot-dcgm-exporter --filter status=running -q | wc -l |
| C4  | version  | 容器 image 符合固定版本標籤                            | ~nvidia/dcgm-exporter:3.3.9-3.6.1-ubuntu22.04 | docker ps --filter name=pilot-dcgm-exporter --no-trunc | grep -m1 -oE 'nvidia/dcgm-exporter:[^ ]+' |
| C5  | config   | 容器實際掛載 `nvidia` runtime（GPU 裝置真的有傳進去）    | ~nvidia   | docker inspect pilot-dcgm-exporter | grep -m1 -oE '"Runtime": *"[^"]+"' |
| C6  | gpu      | 容器內可透過 GPU 裝置實際查到 GPU（不只是設定，是行為證明） | 0         | docker exec pilot-dcgm-exporter nvidia-smi -L > /dev/null 2>&1; echo $? |
| C7  | port     | `9400/tcp` 有在監聽                                  | present   | ss -tln 'sport = :9400' |
| C8  | http     | 未帶認證的 `/metrics`（9400）請求被拒絕（驗證確實有生效，不是設定了但沒生效） | ~401 | curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:9400/metrics |
| C9  | config   | `web-config.yml` 已宣告 `basic_auth_users` 且含指定的使用者名稱 | 0 | grep -qE '^\s*prometheus:' /etc/dcgm-exporter/web-config.yml; echo $? |

> **C1/C4/C5 刻意不用 `docker inspect -f '{{...}}'` / `docker ... --format
> '{{...}}'` 這種 Docker 自己的 Go template 語法**，即使看起來像既有慣例
> ——實測（`pilot verify --probe`）證實 ansible ad-hoc 的 `-m command`/
> `-m shell` 會對整個 Command 字串跑 Jinja finalization，任何 `{{ ... }}`
> 都會被當成 Jinja 表達式解析，`{{.Config.Image}}`/`{{.HostConfig.Runtime}}`
> 這種開頭是 `.` 的寫法對 Jinja 是語法錯誤（"unexpected '.'"），導致整個
> row 直接 `module_error`——跟 `dashboard.md` C14 那段說明記載的是同一個
> Jinja finalization 陷阱。C1 改用 `nvidia-ctk --version`（`command -v` 是
> shell builtin，`ansible.builtin.command` 模組不啟動 shell 也會直接
> `rc=2`，一併避開）；C4 改用 `docker ps`（不加 `--format`）的純文字表格
> 輸出——這裡另外發現 `docker inspect` 的 `.Config.Image` 欄位在這個
> repo 的測試環境裡會被 Docker 解析成 `sha256:...` digest 而不是原本下的
> tag 字串，用 `docker ps` 才抓得到人類可讀的版本標籤；C5 改用
> `docker inspect` 印出完整 JSON 再 `grep` 擷取 `Runtime` 欄位。全程不出現
> 任何 `{{`/`}}` 字元。
> C4 只驗證「這個版本標籤的 image 確實被跑起來」，不重複驗證 image 內容的
> 完整性——那是 Docker 自己 pull 時的 digest/manifest 驗證負責的事，跟
> `host-monitoring.md` C2 不重複驗 checksum 是同一種分工。
> C6 驗證的是「GPU 裝置真的傳進容器了」這個**行為**，不只是「runtime 設定
> 成 nvidia」（C5 驗證那個）——只驗證設定存在，抓不到「toolkit 裝了但
> `nvidia-ctk runtime configure` 沒真的生效」這種真實會發生的 gap，跟
> `host-monitoring.md` C9/C10 的分工邏輯一致。
> **含認證資料的內容驗證（「認證後真的能抓到 `DCGM_FI_DEV_GPU_UTIL`」）刻意
> 不放進這份 spec**：跟 `host-monitoring.md` 同樣理由——spec 的
> Command/Expected 是所有部署共用的固定字串，沒有地方能安全內插每個站台不同
> 的密碼（AGENTS.md 禁止 spec 出現密碼）。這條端到端證明改由未來
> `prometheus.md` 對應的 GPU scrape job 檢查完成（見 §5 已知留白）。

## 3. 證據收集

- 工具：`pilot verify docs/verification/dcgm-exporter.md -i <inventory> -l dcgm-exporter`
- 輸出格式：`.verification/dcgm-exporter-<UTC>.{ndjson,md}`
- 預期 row 數：9

## 4. PASS / FAIL 規則

- C1–C9 全部 `status=pass` → **PASS**
- 任一 `status=fail` → **FAIL**，常見修法：
  - C1 fail → NVIDIA Container Toolkit 沒裝上；檢查 apt repo 是否加成功
    （`apt-cache policy nvidia-container-toolkit`）
  - C2 fail → `nvidia-ctk runtime configure --runtime=docker` 沒跑、docker
    沒重啟套用設定，或 daemon 實際使用的設定來源不是 `/etc/docker/daemon.json`；
    以 `docker info` 的 `Runtimes:` 為準，不要只 grep 設定檔
  - C3 fail → 容器沒啟動；`docker logs pilot-dcgm-exporter`，常見原因是
    GPU 未偵測到或 `nvidia_exporter_gpu_present` 判斷成 false
  - C4 fail → image tag 跑掉；檢查 `dcgm_exporter_version`
  - C5/C6 fail → runtime 沒吃到 `nvidia`，或 toolkit 裝了但 GPU 裝置沒真的
    傳進容器；先確認主機本身 `nvidia-smi -L` 正常
  - C7 fail → port 沒監聽；檢查 C3 是否先 pass
  - C8 fail（回 200 而不是 401）→ 認證形同虛設；檢查容器啟動指令是否真的
    帶了 `--web-config-file`，以及 C9 是否 pass
  - C9 fail → `web-config.yml` 沒渲染成功或找不到指定使用者；檢查
    `dcgm_exporter_basic_auth_password` 是否有帶、`htpasswd`
    （`apache2-utils`）是否安裝成功

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C1–C9 | 目標主機沒有 GPU（`nvidia-smi -L` 探測失敗）時，apply 會整段跳過原生安裝，本檔全部 row 都不適用於這台主機而必定 fail——這是**預期行為，不是 bug**，讓 `dcgm-exporter` inventory group 可以跟其他候選 GPU 主機混編而不必逐台先篩選 | 沒有 GPU 或 GPU 驅動未安裝的主機 | 不會解除——這種主機不屬於本 spec 範圍 |
| C1, C3–C6, C8, C9 | 當 `dcgm_exporter_port` 已被非本 playbook 管理的程式佔用（常見於 Kubernetes NVIDIA GPU Operator 已部署自己的 `dcgm-exporter` DaemonSet），apply 會整段跳過原生安裝；C7（port 監聽）通常仍會 pass（有別的東西在 serve），C8 視現有 exporter 是否有自己的認證機制而定 | 由 Kubernetes GPU Operator（或任何其他機制）自行管理 dcgm-exporter 的主機 | 不會解除——這種主機的健康狀態改由該機制自己的健康檢查負責 |
| — | 只驗證過 `x86_64`；`arm64`（如 NVIDIA Jetson）需要不同的 image tag 後綴，目前 pre_tasks gate 直接 fail 非 x86_64 架構 | 非 x86_64 主機 | 需要時在 apply playbook 補上 arm64 對應的 image tag 與架構分支 |
| — | 預設不給 `SYS_ADMIN` 且維持 Docker 預設 seccomp，以最小權限執行；但 `nvidia-smi -L` 偵測到**已建立的 MIG instance** 時，DCGM 3.6.1 的 CacheManager 否則會以 `Error: -17` 退出，playbook 因此只對該情境加入 `SYS_ADMIN` 與 `seccomp=unconfined`。這是 MIG 初始化相容性例外，不是為了開啟 DCP profiling。 | 有 active MIG instance 的 GPU 主機 | 未來 DCGM/NVIDIA 修正此相容性問題時，重新實測後再評估移除例外；非 MIG 主機始終維持最小權限。 |
| — | 這份 spec 只驗證 exporter 本身；把 `dcgm-exporter` group 接進 `prometheus.md` 的 scrape 設定（比照 `host-monitoring.md` 的 `node_exporter_targets` 自動展開）尚未實作，屬已知留白 | 全部部署 | 待實作：`prometheus.md` 新增對應的 GPU scrape job |

## 6. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-08-25 | v1.0 | C2 改驗證 running dockerd 的 `docker info` runtime list；dt-dev 證實 `daemon.json` 有 `nvidia`、但 service 尚未載入而建立容器失敗。apply 會在設定變更**或**有效 runtime 缺少時重啟 Docker，並於重啟後 assert。 | pilot |
| 2026-08-25 | v1.0 | MIG 相容性修正：真實 RTX PRO 6000 Blackwell MIG host 實測，原本最小權限容器以 `CacheManager Init Failed. Error: -17` 退出、9400 connection refused；僅在 `nvidia-smi -L` 回報 MIG instance 時加入 `SYS_ADMIN` + `seccomp=unconfined` 後 DCGM 初始化成功且未認證 `/metrics` 回 401。 | pilot |
| 2026-08-24 | v1.0 | 初版：`dcgm-exporter` 官方 Docker image + NVIDIA Container Toolkit + 強制 HTTP Basic Auth；GPU 自動偵測（無 GPU 優雅跳過）；Kubernetes GPU Operator 自動偵測（DaemonSet 已管理時跳過原生安裝）。真實 GPU 主機（Ubuntu 24.04 + NVIDIA RTX PRO 6000 Blackwell）`pilot verify` 實測跑過；C1/C4/C5 因 Docker Go template `{{...}}` 撞上 ansible ad-hoc 的 Jinja finalization（跟 `dashboard.md` C14 同一個坑）改用純文字輸出寫法 | sre |
