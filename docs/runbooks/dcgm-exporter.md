# Runbook — dcgm-exporter（GPU 主機的監控 agent：NVIDIA DCGM Exporter）

> 撰寫日期：2026-08-24 (UTC)
> 對齊規範：`docs/verification/dcgm-exporter.md`（v1.0）
> 維護者：sre

---

## 0. 目標與範圍

替有 GPU 的受管主機安裝 NVIDIA 官方的 `dcgm-exporter`（GPU 利用率/記憶體/
溫度/功耗等硬體層 metrics），跟 `host-monitoring`（node_exporter）同一類
Shape 但獨立成自己的 component——理由見 `docs/verification/host-monitoring.md`
開頭的說明：一個軟體一個 component，不要塞進 `host-monitoring` 那份
spec/playbook。

兩個設計決策，寫在這裡是因為它們不是顯而易見的預設選擇：

1. **官方 Docker image，不像 `host-monitoring` 走 pinned release binary**：
   `dcgm-exporter` 要連結 DCGM 共用函式庫（`libdcgm.so`）才能跟驅動溝通，
   NVIDIA 沒有提供可以像 `node_exporter` 那樣單一靜態 binary + 官方
   checksum 直接驗證的發佈形式，官方唯一穩定支援的發佈管道就是 Docker/OCI
   image。這是本 repo少數 docker-based 而非 binary-based 的 per-host agent，
   依賴 `docker` component（見 contract `dependencies`）。
2. **強制 HTTP Basic Auth，沒有選填 escape hatch**：跟 `host-monitoring`
   v1.1 的 node_exporter 一樣，GPU 使用細節用純文字攤在網路上是主機偵查
   資訊洩漏。實測確認 `dcgm-exporter` 3.x 也支援跟 `node_exporter` 相同的
   `exporter-toolkit` `--web-config-file` 機制（`docker run --entrypoint
   dcgm-exporter nvidia/dcgm-exporter:<tag> --help` 可看到這個 flag），套用
   方式完全比照 `host-monitoring`。

不安裝 NVIDIA GPU 驅動本身——驅動是主機佈建階段的前提，`nvidia-smi -L`
探測失敗就代表這個前提不成立，整段原生安裝優雅跳過（見 spec §0/§5）。

## 1. §0.5 事實快照（AGENTS.md §2）

這個元件**沒有用 `pilot vm-target`**（disposable KVM VM）測試——這批 VM
沒有 GPU passthrough，無法真的跑 `dcgm-exporter`。改用使用者提供的一台真實
GPU 主機，走 AGENTS.md §0.1「真實主機」測試路徑（`ansible-inventory -i <inv>
--graph` 讀事實，`ansible-playbook -i <inv>` 直接跑，跟 vm-target 是同一套
紀律）：

```
$ ssh <host> hostnamectl
 Static hostname: test
 Operating System: Ubuntu 24.04.4 LTS
 Kernel: Linux 6.8.0-138-generic
 Architecture: x86-64
 Virtualization: kvm
 Hardware Vendor: QEMU

$ ssh <host> nvidia-smi -L
GPU 0: NVIDIA RTX PRO 6000 Blackwell Server Edition (UUID: GPU-e009dde2-bf13-e6f8-b84b-ce972e854349)
```

測試前該主機**沒有安裝 Docker**、也沒有 NVIDIA Container Toolkit repo；GPU
驅動（`nvidia-driver-580-server-open` 系列）已由主機佈建階段裝好（不屬於本
playbook 套用範圍）。

Tested revision：本檔對應的 spec/playbook 首次落地時的工作樹（新增
`docs/verification/dcgm-exporter.md`、`playbooks/apply/
dcgm-exporter-apply.yml`、`contracts/dcgm-exporter.yaml`）。

## 2. 部署（apply）

依賴鏈：先套用 `docker`（見 contract `dependencies: [{component: docker,
relation: sameHosts}]`），再套用 `dcgm-exporter`。

```bash
ansible-playbook -i <inv.yaml> playbooks/apply/docker-apply.yml
ansible-playbook -i <inv.yaml> playbooks/apply/dcgm-exporter-apply.yml \
    -e dcgm_exporter_basic_auth_password=<password>
```

真實輸出（docker）：

```
PLAY RECAP *********************************************************************
gpu-1                       : ok=5    changed=2    unreachable=0    failed=0    skipped=2    rescued=0    ignored=0
```

真實輸出（dcgm-exporter，首次 apply，ドライラン修好兩個 check-mode bug
之後——見 §7）：

```
PLAY RECAP *********************************************************************
gpu-1                       : ok=25   changed=7    unreachable=0    failed=0    skipped=4    rescued=0    ignored=0
```

手動雙重確認認證行為（不只是相信 spec 的 grep）：

```bash
$ curl -sS -o /dev/null -w 'unauth=%{http_code}\n' http://127.0.0.1:9400/metrics
unauth=401
$ curl -sS -u prometheus:<password> -o /dev/null -w 'auth=%{http_code}\n' http://127.0.0.1:9400/metrics
auth=200
$ curl -sS -u prometheus:<password> http://127.0.0.1:9400/metrics | grep DCGM_FI_DEV_GPU_UTIL
DCGM_FI_DEV_GPU_UTIL{gpu="0",UUID="GPU-e009dde2-...",modelName="NVIDIA RTX PRO 6000 Blackwell Server Edition",...} 0
```

真實 GPU 型號、UUID 都出現在回傳的 metrics 裡——確認這不只是容器啟動成功，
是真的透過 NVIDIA Container Toolkit 的 `nvidia` runtime 把 GPU 裝置傳進了
容器，DCGM 也真的連上驅動讀到資料。

## 3. 驗證（spec C1–C9）

```bash
go run ./cmd/pilot verify docs/verification/dcgm-exporter.md -i <inv.yaml> -l dcgm-exporter
```

```
verdict: **PASS**  (pass=9 fail=0 skip=0)
```

## 4. 冪等重跑（idempotency）

```bash
ansible-playbook -i <inv.yaml> playbooks/apply/dcgm-exporter-apply.yml \
    -e dcgm_exporter_basic_auth_password=<同一個password>
```

```
PLAY RECAP *********************************************************************
gpu-1                       : ok=21   changed=0    unreachable=0    failed=0    skipped=8    rescued=0    ignored=0
```

`changed=0`——確認 bcrypt hash 的 fingerprint 機制真的擋住了「密碼沒變也
重新雜湊、重寫檔案、重啟容器」這個陷阱，跟 `host-monitoring` 的 node_exporter
同一種設計。

## 4a. 「port 已被其他程式佔用」自動偵測（NVIDIA GPU Operator 情境模擬）

在跑 apply 前，先用一個假的容器佔住 9400 port，模擬「這台 GPU 主機已經有
Kubernetes NVIDIA GPU Operator 部署自己的 dcgm-exporter DaemonSet」：

```bash
$ docker rm -f pilot-dcgm-exporter
$ docker run -d --name fake-foreign-exporter -p 9400:8080 nginx:alpine
$ ss -ltn '( sport = :9400 )'
LISTEN 0 4096 0.0.0.0:9400 0.0.0.0:*
```

重跑 apply（**不需要**先移除假容器）：

```
TASK [Report: skipping native install (port already served by something else)] ***
    "msg": "9400/tcp 已經被監聽,且不是本 playbook 管理的 pilot-dcgm-exporter 容器
    ——跳過原生安裝以避免搶 port。這台主機很可能已經透過 Kubernetes NVIDIA GPU
    Operator 的 DaemonSet 部署了自己的 dcgm-exporter(見 spec §5)。"
}
PLAY RECAP *********************************************************************
gpu-1                       : ok=8    changed=0    unreachable=0    failed=0    skipped=21   rescued=0    ignored=0
```

`changed=0`，OS/架構/密碼 gate 全部正確跳過，沒有搶 port——確認偵測邏輯
有效。移除假容器、重跑 apply 恢復正常安裝，`pilot verify` 再度
`PASS (pass=9 fail=0 skip=0)`，確認偵測邏輯只在真的被別人佔用時才跳過，
不會誤判自己剛裝好的容器。

## 5. 已知留白

- 這份 spec 只驗證 exporter 本身；把 `dcgm-exporter` group 接進
  `prometheus.md` 的 scrape 設定（比照 `host-monitoring.md` 的
  `node_exporter_targets` 自動展開）尚未實作。
- 只驗證過 x86_64 + Ubuntu 24.04；`arm64`（Jetson）與其他 distro 家族未測試
  （見 spec §5）。
- 非 MIG GPU 主機維持不帶 `SYS_ADMIN`、Docker 預設 seccomp 的最小權限設定。
  但偵測到 active MIG instance 時，playbook 會自動加入 `SYS_ADMIN` 與
  `seccomp=unconfined`；否則 DCGM 3.6.1 的 CacheManager 會以 `Error: -17`
  退出，9400 不會監聽。這是已在 RTX PRO 6000 Blackwell MIG host 實測的相容性
  例外，不是為了啟用 profiling metrics。

## 6. Teardown

這是使用者提供的真實主機，不是拋棄式 vm-target，測試結束後**保留**
`pilot-dcgm-exporter` 容器 + NVIDIA Container Toolkit 在跑（等同一次真實
部署），未執行 teardown。如需移除：

```bash
docker rm -f pilot-dcgm-exporter
rm -rf /etc/dcgm-exporter
apt-get remove -y nvidia-container-toolkit
rm -f /etc/apt/sources.list.d/nvidia-container-toolkit.list
```

## 7. 踩過的雷（真實 GPU 主機實測時發現）

寫 spec/playbook 時憑經驗設計的部分，在真的 GPU 主機上跑時踩到三個真 bug：

| 症狀 | 根因 | 修法 |
|------|------|------|
| `--check --diff` 對一台**乾淨、沒有 GPU** 的主機模擬跑，也會回報「GPU 偵測到、port 被其他程式佔用」而整段跳過原生安裝——跟真實狀態完全相反 | `command`/`shell` 模組沒有 check-mode 模擬能力，ansible-core 在 `--check` 下會直接跳過這些 task，但**合成一個假的 `rc=0`/`stdout=""` 結果**（不是留 undefined）。`nvidia-smi -L`、`ss -ltn` 的 port 檢查、`docker ps` 的自身容器檢查三個探測 task 都沒有強制真的執行，導致 `rc==0` 的判斷永遠成立，`--check` dry-run 完全不可信 | 三個讀取型探測 task 都加 `check_mode: false`，強制在 `--check` 下也真的執行（同一份 SSH session 上真的跑 `nvidia-smi -L`/`ss`/`docker ps`），確保 dry-run 反映真實主機狀態；跟 `audit-log-forwarding-apply.yml` 既有的讀取型 probe 慣例一致 |
| 加上前一項修法後，`--check` 對一台**有 GPU 但從零開始**的主機跑，會在「Render web-config.yml」直接 crash：`Error while resolving value for 'content': object of type 'list' has no attribute 1` | `htpasswd` 這個 CLI 是**這支 playbook 自己**在同一次 apply 用 `apt` 裝的；`--check` 下這個安裝步驟只被模擬，binary 根本不存在，`htpasswd -nbBC 10 ...` 這個 task 本身在 check mode 下被跳過、合成 `stdout=""`，後面 `.split(':', 1)[1]` 對空字串 split 出的單一元素 list 取索引 1 就爆炸——跟 `host-monitoring-apply.yml` runbook §7 記載的第二個坑是同一個成因，只是這裡表現成 crash 而不是靜默錯誤 | 產生 bcrypt hash（Step 6）與依賴它的 render web-config.yml / 寫 fingerprint（Step 7）三個 task 都加 `and not ansible_check_mode`，延後到真正 apply，**不**對這些 task 用 `check_mode: false`（那招只適合前提條件來自「前一次已完成的 apply」的情境，這裡的前提條件恰好是同一次 check-mode run 才會建立的東西） |
| `pilot verify` 對 C1/C4/C5 三個 row 全部回報 `module_error`：C1 是 `rc=2: Error executing command`，C4/C5 是 `Syntax error in template: unexpected '.'` | C1 用了 `command -v nvidia-ctk`——`command` 是 shell builtin，`ansible.builtin.command` 模組不啟動 shell，直接找不到叫 `command` 的執行檔。C4/C5 用了 Docker 自己的 Go template 語法 `docker inspect -f '{{.Config.Image}}'`/`'{{.HostConfig.Runtime}}'`——ansible ad-hoc 的 `-m command`/`-m shell` 會對整個 Command 字串跑 Jinja finalization，任何 `{{ ... }}` 都被當成 Jinja 表達式解析，開頭是 `.` 的寫法對 Jinja 是語法錯誤，直接 `module_error`。跟 `docs/verification/dashboard.md` C14 那段記載的是同一個 Jinja finalization 陷阱（那邊也點名 `docker.md` C6 本身也踩在這個坑上，屬既存缺陷）。另外實測發現 `docker inspect` 的 `.Config.Image` 欄位在這個環境裡被 Docker 解析成 `sha256:...` digest，不是原本下的 tag 字串，即使繞開 Jinja 問題這個欄位本身也驗不到想驗的東西 | C1 改用 `nvidia-ctk --version`（純執行檔呼叫）；C4 改用 `docker ps --filter name=... --no-trunc`（純文字表格輸出，人類可讀的 tag 字串仍在）+ `grep -oE`；C5 改用 `docker inspect ... \| grep -oE '"Runtime": *"[^"]+"'`（印出完整 JSON 再 grep，不觸發 `-f`/`--format`）。全程不出現任何 `{{`/`}}` 字元 |

三者都在真實 GPU 主機的 `--check --diff` 與 `pilot verify` 階段抓到，修完後
真正 apply（§2）、冪等重跑（§4）、port-occupied 情境（§4a）都乾淨通過，
沒有殘留問題。

## 8. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-08-24 | v1.0 | 初版：`dcgm-exporter` 元件落地，真實 GPU 主機（Ubuntu 24.04 + NVIDIA RTX PRO 6000 Blackwell）實跑 apply/verify/idempotency/port-occupied 情境全 PASS；修好 2 個 check-mode 真 bug + 1 個 spec 層 Jinja finalization/digest-vs-tag 真 bug | sre |
