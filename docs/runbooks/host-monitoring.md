# Runbook — host-monitoring（被監控主機的監控 agent：node_exporter）

> 撰寫日期：2026-08-10 (UTC)
> 對齊規範：`docs/verification/host-monitoring.md`（v1.1）
> 消費端整合證據見 `docs/runbooks/metrics-alerting.md` §7a（`prometheus`
> 自動探索 + 端到端 `up{job="node"}==1` 證明）
> 維護者：sre

---

## 0. 目標與範圍

替被監控主機安裝 `node_exporter`（OS/硬體層 metrics：CPU、記憶體、磁碟、
網路），這是新增的獨立元件——起因是調查 Grafana 的 `Node Exporter Full`
dashboard 為何完全沒資料，追到根因是這個 repo 從來沒有部署 node_exporter
的能力（`prometheus` 只 scrape 自己）。

角色名稱取通用的 `host-monitoring` 而非 `node-exporter`，理由見
`docs/verification/host-monitoring.md` 開頭的說明：目前只實作
node_exporter，之後若要在同一批主機上加裝其他監控 agent（例如
blackbox_exporter、process-exporter），比照本 repo「一個軟體一個
component」的慣例新增獨立的 spec + playbook，不要塞進這裡。

兩個設計決策，寫在這裡是因為它們不是顯而易見的預設選擇：

1. **兩種 distro 統一走固定版本的官方 release binary，不用套件管理器**：
   Ubuntu 22.04/24.04 的 `prometheus-node-exporter` apt 套件版本停在
   1.7.0（實測）；AlmaLinux 9（含 EPEL）完全沒有 node_exporter 套件（實測
   `dnf search node_exporter` 零結果）。
2. **強制 HTTP Basic Auth，沒有選填 escape hatch**：node_exporter 預設會把
   硬體/OS/process 細節用純文字攤在網路上，任何連得到 port 的人都能讀，是
   實質的主機偵查資訊洩漏。用 `--web.config.file`（exporter-toolkit）+
   `htpasswd` 產生的 bcrypt hash 擋下匿名讀取。

## 1. §0.5 事實快照（AGENTS.md §2）

```bash
$ go run ./cmd/pilot vm-target list   # 測試前
NAME            STATUS   IP             VCPU  MEM(MiB)  DISK(GiB)  CREATED
client-vm       running  192.168.122.3  2     2048      20         2026-08-06 18:29:21
freeipa-server  running  192.168.122.2  2     4608      30         2026-08-06 18:29:21
nexus           running  192.168.122.4  6     12288     80         2026-08-06 18:29:21
```

上面三台是別的 workstream（`docs/runbooks/metrics-alerting.md`）保留中的
VM，本次測試全程未動它們，新建三台獨立命名的 VM：

| VM | base image | 用途 |
|----|------------|------|
| `hm-ubuntu` | ubuntu-24.04（預設） | 單機測試：apt-based distro |
| `hm-el9` | `--base-image almalinux-9` | 單機測試：dnf-based distro，無 node_exporter 套件 |
| `prom-test` | ubuntu-24.04（預設） | 多 VM cross-check：跑 `prometheus`，見 §7a 的 metrics-alerting.md |

Tested revision：本檔對應的 spec/playbook 首次落地時的工作樹（新增
`docs/verification/host-monitoring.md`、`playbooks/apply/
host-monitoring-apply.yml`、`contracts/host-monitoring.yaml`）。

`pilot services status`：`running=true profile=dev-lite`（沿用既有的
host-local cache stack，`--services local`）。

## 2. 部署（apply）

```bash
go run ./cmd/pilot vm-target up --name hm-ubuntu --ssh-user ubuntu \
    --disk 20 --memory 2048 --vcpus 2 \
    --ssh-timeout 8m --boot-timeout 8m --services local

go run ./cmd/pilot vm-target run --name hm-ubuntu --skip-lint \
    playbooks/apply/host-monitoring-apply.yml \
    -e target_group=hm-ubuntu \
    -e node_exporter_basic_auth_password=<password>
```

> `-e target_group=hm-ubuntu`：vm-target 單機 inventory 的 host key 就是
> VM 名稱本身，跟 playbook 預設的 `host-monitoring` group 名稱不同，所以
> 一定要帶這個 override（跟 `docs/verification/wazuh-fim.md` §7 提到的
> 「把 VM 取跟 group 同名就不用 override」是同一個機制，這裡選擇不同名，
> 所以要帶）。
>
> `node_exporter_basic_auth_password` 是硬性必填（見 §0 的設計決策 2），
> 拋棄式沙盒測試才用 `-e` 帶明文，真實 inventory 一律用 vault 檔。

真實輸出（Ubuntu 24.04，首次 apply）：

```
PLAY RECAP *********************************************************************
hm-ubuntu                  : ok=24   changed=11   unreachable=0    failed=0    skipped=2    rescued=0    ignored=0
```

AlmaLinux 9（`hm-el9`，同一套 playbook、同一個密碼）：

```
PLAY RECAP *********************************************************************
hm-el9                     : ok=24   changed=11   unreachable=0    failed=0    skipped=2    rescued=0    ignored=0
```

兩邊 `changed` 數字完全一致——確認「兩種 distro 裝出一致行為」這個設計目標
真的達成，不是理論上應該一致。

## 3. 驗證（spec C1–C10）

```bash
go run ./cmd/pilot vm-target verify --name hm-ubuntu docs/verification/host-monitoring.md
```

```
verdict: **PASS**  (pass=10 fail=0 skip=0)
```

AlmaLinux 9 同樣 `PASS (pass=10 fail=0 skip=0)`。

手動雙重確認 C9/C10 背後的真實行為（不只是相信 spec 的 grep）：

```bash
$ curl -sS -o /dev/null -w 'unauth=%{http_code}\n' http://127.0.0.1:9100/metrics
unauth=401
$ curl -sS -u prometheus:<password> -o /dev/null -w 'auth=%{http_code}\n' http://127.0.0.1:9100/metrics
auth=200
```

## 4. 冪等重跑（idempotency）

```bash
go run ./cmd/pilot vm-target run --name hm-ubuntu --skip-lint \
    playbooks/apply/host-monitoring-apply.yml \
    -e target_group=hm-ubuntu \
    -e node_exporter_basic_auth_password=<同一個password>
```

```
PLAY RECAP *********************************************************************
hm-ubuntu                  : ok=16   changed=0    unreachable=0    failed=0    skipped=10   rescued=0    ignored=0
```

`changed=0`——確認 bcrypt hash 的 fingerprint 機制真的擋住了「密碼沒變也
重新雜湊、重寫檔案、重啟服務」這個陷阱（bcrypt 本身每次呼叫的 salt 都不
同，若不做這層 fingerprint 比對，每次 apply 都會被判定成 changed）。
AlmaLinux 9 同樣 `changed=0`。

## 4a. Kubernetes 自動偵測（v1.2）

新建一台 VM（`hm-k8s-sim`），在跑 apply **之前**先用一個假的 listener 佔住
9100 port，模擬「這台主機已經有 Kubernetes DaemonSet 部署 node_exporter」
的情境（另外也建了 `/var/lib/kubelet` 觸發訊息裡的 kubelet 偵測）：

```bash
$ python3 -m http.server 9100 --bind 0.0.0.0 &   # 模擬 DaemonSet 已佔用 port
$ sudo mkdir -p /var/lib/kubelet                  # 模擬這是一台 k8s node
```

**不帶密碼**直接跑 apply（故意測試「這種主機不該被要求密碼」）：

```bash
go run ./cmd/pilot vm-target run --name hm-k8s-sim --skip-lint \
    playbooks/apply/host-monitoring-apply.yml -e target_group=hm-k8s-sim
```

實際輸出：

```
TASK [Report: skipping native install (port already served by something else)] ***
ok: [hm-k8s-sim] => {
    "msg": "9100/tcp is already listening and is not our own pinned node_exporter binary —
    skipping native install on this host to avoid a port conflict. 偵測到 /var/lib/kubelet 存在,
    這台主機很可能是 Kubernetes node, node_exporter 大概是透過叢集的 DaemonSet(例如
    kube-prometheus-stack)部署的。 Prometheus 仍會透過 inventory 的 host-monitoring group
    成員資格照常 把這台主機當 scrape target;..."
}

TASK [Gate: supported OS ...] ***************************************
skipping: [hm-k8s-sim]
TASK [Gate: supported CPU architecture] *****************************
skipping: [hm-k8s-sim]
TASK [Gate: required basic-auth password present (fail early, before any mutation)] ***
skipping: [hm-k8s-sim]

PLAY RECAP *********************************************************************
hm-k8s-sim                 : ok=9    changed=0    unreachable=0    failed=0    skipped=22   rescued=0    ignored=0
```

`failed=0`、`changed=0`，且完全沒有要求密碼——確認「port 已被佔用時整段
優雅跳過」真的有效，OS/架構/密碼 gate 都正確被跳過，不會因為「這台機器碰
巧不是我們支援的 distro」或「沒帶密碼」而 fail。

殺掉假的 listener、拿掉偽裝，重跑一次確認「port 空出來之後恢復正常安裝」：

```
PLAY RECAP *********************************************************************
hm-k8s-sim                 : ok=27   changed=11   unreachable=0    failed=0    skipped=3    rescued=0    ignored=0
```

再跑一次（idempotency，同時驗證「偵測邏輯不會誤判自己剛裝好的 binary」）：

```
PLAY RECAP *********************************************************************
hm-k8s-sim                 : ok=19   changed=0    unreachable=0    failed=0    skipped=11   rescued=0    ignored=0
```

`changed=0`，且 `pilot verify docs/verification/host-monitoring.md` 仍
`PASS (pass=10 fail=0 skip=0)`——確認偵測邏輯只在「port 被別人佔用」時
才會跳過，不會對我們自己上一輪裝好的 node_exporter 誤判成「外部佔用」。

## 5. 跨主機整合證明（`prometheus` 自動探索 + 認證通過的 scrape）

完整證據在 `docs/runbooks/metrics-alerting.md` §7a（含實際渲染的
`prometheus.yml` 內容、`up{job="node"}==1` 的查詢結果）。摘要：

- `prometheus-apply.yml` 自動從 inventory 的 `host-monitoring` group 展開
  scrape target，不需要手動填 IP 清單。
- 用跟這裡相同的 `node_exporter_basic_auth_password` 認證，成功抓到資料
  （`up{job="node"}==1`）。
- 這條鏈路本身就是 §3 C9/C10 沒有覆蓋到的「認證後真的能抓到有效資料」的
  端到端證明——這份 spec 刻意不驗證這件事，因為驗證需要密碼，而 spec 的
  Command 欄位不能安全內插每站不同的密碼（見 spec §1.5 的說明）。

## 6. Teardown

```bash
go run ./cmd/pilot vm-target down --name hm-k8s-sim
go run ./cmd/pilot vm-target down --name hm-el9
go run ./cmd/pilot vm-target down --name hm-ubuntu
# prom-test 的 teardown 見 metrics-alerting.md §7a
```

## 7. 踩過的雷（實測 vm-target 時發現）

寫 spec/playbook 時憑經驗設計的 check-mode 處理，在真的 vm-target 上跑
`--check --diff` 時踩到兩個真 bug，兩個都是同一類「check-mode 下，前提條件
只被模擬、沒真的存在」的陷阱，但成因略有不同：

| 症狀 | 根因 | 修法 |
|------|------|------|
| `--check` 對從零開始的主機跑，`unarchive` 直接 crash：`Source '/tmp/node_exporter-....tar.gz' does not exist` | 上一步的 `get_url` 在 check mode 下只模擬下載（回報 changed=true，但沒真的寫檔），`unarchive` 不像 `copy`/`file` 能優雅處理「來源不存在」，會直接嘗試讀檔失敗 | 在 `unarchive` 與後續依賴解壓結果的 `copy` 的 `when` 都加 `and not ansible_check_mode`，延後到真正 apply，跟本 repo既有的 check-mode-fresh-bootstrap 慣例一致（見 `docs/runbooks/minimal-poc-architecture.md` 的同類記錄） |
| 產生 bcrypt hash 的 task 原本用 `check_mode: false` 強制在 `--check` 下真的執行（想避免下一步 `copy` 讀到未定義的 `.stdout`），結果失敗：`Error executing command: No such file or directory: 'htpasswd'` | `htpasswd` 這個 CLI 工具是**這支 playbook 自己**在同一次 apply 裡用 `apt`/`dnf` 裝的；在 `--check` 下這個安裝步驟也只被模擬，binary 根本不存在。`check_mode: false` 這招只適合「前提條件來自前一次已完成的 apply」的情境（例如探測一個已經在跑的 docker 容器），這裡的前提條件恰好是**同一次** check-mode run 才會建立的東西，用法不對 | 拿掉 `check_mode: false`，改成跟 `unarchive` 一樣加 `and not ansible_check_mode`，整段「產生 hash → 渲染 web-config.yml → 寫 fingerprint」延後到真正 apply |
| （v1.2，Kubernetes 偵測加進來後）Step 2 的 task name 裡有 `{{ node_exporter_arch }}`，這個變數只在「沒被佔用」分支才會算出來——當該分支因為 `node_exporter_port_occupied_by_other` 被跳過時，Ansible 仍會嘗試 render 這個被跳過 task 的 name 字串，噴 `error 1 - 'node_exporter_arch' is undefined` 警告（不是 fatal，但輸出很醜，recap 裡 task 名稱變成一段錯誤訊息） | Ansible 對 task 的 `name:` 欄位做 Jinja render 這件事，跟這個 task 最後會不會被 `when` 跳過是分開的兩件事——即使確定會跳過，name 字串仍然會被 render 一次 | task name 裡的 `{{ node_exporter_arch }}` 改成 `{{ node_exporter_arch | default('unknown') }}` |

三者都在 `--check --diff`／實際跑 k8s 偵測情境（§4a）階段抓到，修完後真正
apply（§2）與冪等重跑（§4）都乾淨通過，沒有殘留問題。

跟 `prometheus` 整合時另外發現 2 個真 bug（Jinja `\n` 逃逸失敗、
`to_nice_yaml` key 排序讓 spec C13 的錨點抓錯），記在
`docs/runbooks/metrics-alerting.md` §7a/§9，不重複列在這裡。

## 8. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-08-10 | v1.0 | 初版：node_exporter 元件落地，Ubuntu 24.04 + AlmaLinux 9 vm-target 實跑 apply/verify/idempotency 全 PASS，修好 2 個 check-mode 真 bug，跟 `prometheus` 的整合證明見 metrics-alerting.md §7a | sre |
| 2026-08-10 | v1.1 | 新增 Kubernetes 自動偵測：port 已被非本 playbook 管理的程式佔用時整段跳過原生安裝（不搶 port、不要求密碼、不因為不支援的 OS fail）；vm-target 實測「模擬 DaemonSet 佔用 port」→ 優雅跳過、「port 空出來」→ 恢復正常安裝、冪等重跑不誤判自己剛裝好的 binary 三種情境；修好 1 個 task-name Jinja render 警告 | sre |
