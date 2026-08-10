# Runbook — Metrics / Thanos / Alertmanager（跨機房指標彙總 + 中央告警）

> 撰寫日期：2026-07-06 (UTC)（`prometheus`/`thanos-query` 部分）；
> 2026-07-07（`alertmanager` 部分，原獨立文件 `docs/runbooks/alertmanager.md`）；
> v2.0（2026-07-17）文件整併：兩者合併成本檔，共用一次四主機環境重新實跑，
> 原 `alertmanager.md` 已歸檔。
> v2.1（2026-08-10）新增 §7a：`prometheus` 自動從 inventory 的
> `host-monitoring` group 展開 node_exporter scrape target（強制 HTTP
> Basic Auth），對應新元件 `docs/runbooks/host-monitoring.md`。
> 對齊規範：`docs/verification/prometheus.md`（v1.2）、
> `docs/verification/thanos-query.md`（v1.1）、
> `docs/verification/alertmanager.md`（v1.0）、
> `docs/verification/host-monitoring.md`（v1.1）
> 維護者：sre

---

## 0. 目標與資料流

每個機房/站台各跑一份 Prometheus + Thanos Sidecar（`prometheus` 角色），把
2 小時一個的 TSDB block 上傳到共用的 S3-compatible object storage（本專案
自建的 SeaweedFS）；中央跑一份 Thanos Query + Store Gateway + Compactor
（`thanos-query` 角色），**自動讀 Ansible inventory 的 `prometheus` group**
組出各站 Sidecar 的 StoreAPI 位址，不需要手動維護站台 IP 清單。全局查詢
（`/api/v1/query`）打中央的 Thanos Query 就能查到所有站台的資料，且每筆
結果帶有 `site` label 分辨來源站。

每個站台的 Prometheus 也各自 eval 自己的 alert rules（`Watchdog` +
`PrometheusDown` + `HostDown` 等 seed rules），推送到中央的 Alertmanager
（`alertmanager` 角色）：`prometheus-apply.yml` 套用時透過
`alertmanager_target_host` 變數把 `alertmanager-backend` 這個別名 pin 進
`/etc/hosts`，`prometheus.yml` 的 `alerting.alertmanagers` 區塊據此指向
中央。三者合起來就是「站台收集 → 中央彙總查詢 → 中央統一告警路由」完整
一條鏈路。

跟本專案其他 central+agent 角色對子（`wazuh-manager`/`wazuh-fim`、
`log-server`/`audit-log-forwarding`）方向相反：那些是「agent 端填一個
`-e central_host` 變數」，Thanos Query 這裡是「**中央主動探索站台**」——
`thanos-query` 角色完全不需要知道中央在哪裡，只需要 inventory 的
`prometheus` group 存在。Alertmanager 則跟既有慣例一致（站台填中央 IP）。
見三份 spec 開頭的架構說明。

`thanos-query` 與 `alertmanager` 典型部署是同一台主機同時屬於兩個
inventory group（共用 `pilot-metrics` docker network）；本次重測刻意拆成
兩台獨立主機（見 §1），驗證兩者互不依賴、可以分開伸縮。

`dashboard.md`（Grafana + Loki）**不併入本檔**，只更新連結——dashboard 同時
涵蓋 log-shipping，不只是純 metrics consumer，保留獨立角色文件。

---

## 1. §0.5 事實快照（2026-07-17T07:20–07:45 UTC，整併重測）

```
$ go run ./cmd/pilot vm-target list
NAME       STATUS   IP             VCPU  MEM(MiB)  DISK(GiB)
client-vm  running  192.168.122.6  2     2048      20
nexus      running  192.168.122.5  6     12288     80
pt-alert   running  192.168.122.2  2     2048      20
pt-s3      running  192.168.122.4  2     2048      20

$ go run ./cmd/pilot spec docs/verification/prometheus.md --lint
spec Verification Spec — prometheus (per-site Prometheus + Thanos Sidecar): 12 rows, 0 findings (0 errors)

$ go run ./cmd/pilot spec docs/verification/thanos-query.md --lint
spec Verification Spec — thanos-query (central Thanos Query + Store Gateway + Compactor): 10 rows, 0 findings (0 errors)

$ go run ./cmd/pilot spec docs/verification/alertmanager.md --lint
spec Verification Spec — alertmanager (central Alertmanager for all sites): 7 rows, 0 findings (0 errors)
```

四台 vm-target，各自角色（本次重測沿用既有 pool 中已存在、先 `vm-target
reset` 回 pristine 狀態的三台，另加一台新建；角色名稱由 `--name` 決定，跟
底層 target 名稱無直接綁定關係，任何名稱都可以）：

| 角色 | 本次重測 target 名稱 | Ubuntu 版本 | IP |
|---|---|---|---|
| `s3`（SeaweedFS S3 目的地） | `pt-s3` | 24.04 | 192.168.122.4 |
| `site-a`（Prometheus + Thanos Sidecar） | `client-vm` | 24.04 | 192.168.122.6 |
| `central`（Thanos Query/Store/Compactor） | `nexus` | 24.04 | 192.168.122.5 |
| `alert`（Alertmanager） | `pt-alert` | 24.04 | 192.168.122.2 |

**對齊決策**：四台都是 vm-target 單機 inventory（沒有 inventory
`children:` group），`prometheus`/`thanos-query` 這類讀 group 探索站台的
task 靠 `pilot vm-target run` 的 `--group <group>=<target1>,<target2>`
旗標動態組出 group（見 §5），不需要手寫合併過的 inventory YAML、也不需要
繞到 raw `ansible-playbook -i <file>` 這層——這是本次整併重測發現的重要
改進，取代了兩份來源文件原本各自「手動合併 inventory + 直接跑
`ansible-playbook`」的做法（見 §9 gotcha 表）。

**一個真實環境限制（跟本檔內容無關，記錄避免下次重踩）**：原本想讓
`s3` 角色沿用同一批既有 vm-target 池中恰好是 AlmaLinux 9 的一台，套用
`core-infra-provider-apply.yml -e infra_role=docker` 時在 `Docker —
install docker (RHEL family)` 這個 task 上真的失敗：
`No package docker-compose available`（AlmaLinux 9 預設倉庫沒有這個
套件，需要額外的 EPEL/docker-ce repo，playbook 目前沒處理這個依賴）。
繞過方式：`s3` 角色改用全新的 Ubuntu vm-target（本檔其餘三個角色也全部
用 Ubuntu，這是四份 spec 本來就假設的組合）。這是 `core-infra-provider-apply.yml`
本身的一個真實缺口，跟 metrics/alerting 無關，這裡不修；已在
`docs/runbooks/docker.md` §4 記錄成已知限制（目前無 EL 系實際需求，暫不
修復）。

---

## 2. 部署 SeaweedFS S3 目的地（簽章模式）

Thanos 一律送 AWS SigV4 簽章請求（跟 `restic-backup.md` 一樣），SeaweedFS
預設匿名模式不接受，需要 `-s3.config` identity 檔：

```bash
go run ./cmd/pilot vm-target run --name pt-s3 \
    playbooks/apply/docker-apply.yml \
    -e target_group=all
```

> 2026-07-17：docker preflight 改用獨立的 `playbooks/apply/docker-apply.yml`
> （原本是 `core-infra-provider-apply.yml -e infra_role=docker`），見
> `docs/runbooks/docker.md`；任務內容不變，下方 PLAY RECAP 的 skipped 數字
> 是舊 playbook（dns/ntp/docker 三選一）的截錄，改用新 playbook 後會變小
> （少了 dns/ntp 恆為 false 的 `when:` 分支），不影響部署結果本身。

```
PLAY RECAP *********************************************************************
pt-s3                      : ok=7    changed=2    unreachable=0    failed=0    skipped=13   rescued=0    ignored=0
```

```bash
go run ./cmd/pilot vm-target exec --name pt-s3 -- sudo mkdir -p /etc/pilot-s3
go run ./cmd/pilot vm-target exec --name pt-s3 -- sudo tee /etc/pilot-s3/s3.json <<'EOF'
{"identities":[{"name":"thanos","credentials":[{"accessKey":"thanos-sandbox-key","secretKey":"thanos-sandbox-secret-123"}],"actions":["Admin","Read","Write"]}]}
EOF

go run ./cmd/pilot vm-target run --name pt-s3 \
    playbooks/apply/seaweedfs-s3-apply.yml \
    -e target_group=all -e seaweedfs_s3_config_path=/etc/pilot-s3/s3.json \
    -e '{"seaweedfs_extra_buckets": ["pilot-thanos-metrics"]}'
```

真實輸出：

```
PLAY RECAP *********************************************************************
pt-s3                      : ok=12   changed=7    unreachable=0    failed=0    skipped=3    rescued=0    ignored=0
```

`seaweedfs-s3-apply.yml` 的 `seaweedfs_extra_buckets` 這次直接帶
`pilot-thanos-metrics`，apply 本身就自動建好 bucket（真實 recap：
`TASK [SeaweedFS — create extra S3 buckets (idempotent)] changed: [pt-s3] => (item=pilot-thanos-metrics)`）——
不需要再手動 `weed shell` 建 bucket；兩份來源文件原本各自記載的手動建
bucket 步驟現在是**歷史包袱**（SeaweedFS 仍然不會自動生出 bucket，只是
現在 apply 本身就會做這件事，不需要操作者另外一步）。

---

## 3. 部署 `alertmanager` 角色（中央）

```bash
go run ./cmd/pilot vm-target run --name pt-alert \
    playbooks/apply/alertmanager-apply.yml -e target_group=all
```

真實輸出：

```
PLAY RECAP *********************************************************************
pt-alert                   : ok=8    changed=4    unreachable=0    failed=0    skipped=1    rescued=0    ignored=0
```

驗證：

```bash
go run ./cmd/pilot vm-target verify --name pt-alert docs/verification/alertmanager.md --timeout 40
```

```
verdict: **PASS**  (pass=7 fail=0 skip=0)
```

冪等重跑：

```
PLAY RECAP *********************************************************************
pt-alert                   : ok=8    changed=0    unreachable=0    failed=0    skipped=1    rescued=0    ignored=0
```

---

## 4. 部署 `prometheus` 角色（站台 `site-a`，同時接上 S3 與 Alertmanager）

```bash
go run ./cmd/pilot vm-target run --name client-vm playbooks/apply/prometheus-apply.yml \
    -e target_group=all \
    -e prometheus_site_label=site-a \
    -e thanos_s3_target_host=192.168.122.4 \
    -e thanos_aws_access_key_id=thanos-sandbox-key \
    -e thanos_aws_secret_access_key=thanos-sandbox-secret-123 \
    -e alertmanager_target_host=192.168.122.2
```

真實輸出（沒有任何一個 task fail；官方 Prometheus image 跑 `nobody`
uid 65534，host data dir chown 成 65534:65534 這個防禦性設計一次到位）：

```
PLAY RECAP *********************************************************************
client-vm                  : ok=19   changed=10   unreachable=0    failed=0    skipped=5    rescued=0    ignored=0
```

驗證：

```bash
go run ./cmd/pilot vm-target verify --name client-vm docs/verification/prometheus.md --timeout 40
```

```
verdict: **PASS**  (pass=12 fail=0 skip=0)
```

冪等重跑：`changed=0`（`ok=18 skipped=5 failed=0`）。

---

## 5. 部署 `thanos-query` 角色（中央 `central`）—— 用 `--group` 動態組 inventory

**測試基礎設施的限制，不是 playbook 的限制**：`pilot vm-target run` 每次
只餵一個 VM 自己的單主機 inventory（`RenderInventory()` 只寫
`all.hosts.<name>`，沒有 `children:` group）。但 `thanos-query-apply.yml`
的核心設計就是**讀 inventory 的 `prometheus` group** 組出站台清單。

**2026-07-17 整併重測起改用 `vm-target run --group`**（`prometheus-thanos.md`
舊版是手動組一份合併 inventory 檔 + 直接 `ansible-playbook -i <file>` 跑，
違反「不直接執行 raw `ansible-playbook`」的通則——`--group` 旗標現在是
`vm-target run` 自己的功能，同一條指令內就能組出多台已存在 vm-target 的
inventory group，不需要跳出 `vm-target` 這層 CLI）：

```bash
go run ./cmd/pilot vm-target run --name nexus playbooks/apply/thanos-query-apply.yml \
    --group prometheus=client-vm --group thanos-query=nexus \
    -e target_group=thanos-query \
    -e thanos_s3_target_host=192.168.122.4 \
    -e thanos_aws_access_key_id=thanos-sandbox-key \
    -e thanos_aws_secret_access_key=thanos-sandbox-secret-123
```

真實輸出（`Announce discovered sites` 證明真的讀到 inventory 的
`prometheus` group，不是空清單）：

```
TASK [Announce discovered sites (debug)] ***************************************
ok: [nexus] => {
    "msg": "thanos_query_store_group=prometheus; discovered 1 site(s): ['client-vm']"
}

PLAY RECAP *********************************************************************
nexus                      : ok=14   changed=8    unreachable=0    failed=0    skipped=3    rescued=0    ignored=0
```

**驗證第一次真的 FAIL**（本次整併重測發現的真事故，非本檔操作失誤）：

```bash
go run ./cmd/pilot vm-target verify --name nexus docs/verification/thanos-query.md --timeout 40
```

```
- generated: 2026-07-17T07:37:37Z
- total:     10  pass: 6  fail: 4  skip: 0
- verdict:   **FAIL**

| C4 | fail | stdout="000", expected substring ~"200" |
| C5 | fail | stdout="000", expected substring ~"200" |
| C9 | fail | rc=2, ... |
| C10 | fail | rc=2, ... |
```

**根因**：`thanos-query-apply.yml` 的 `thanos_query_http_port` 早就預設
改成 `10912`（見 playbook 本身的註解：刻意避開跟站台 Thanos Sidecar 的
host port 10902 collide，讓「central 跟某個站台的 Prometheus 剛好同機」
這種常見情境不需要額外 override），但 `docs/verification/thanos-query.md`
的 C4/C5/C9/C10 從沒跟著改，一直寫死 10902——這是**規格落後於程式碼**的
真事故，不是這次部署本身的問題。

**修法**：把 `docs/verification/thanos-query.md` 的 C4/C5/C9/C10 全部改成
`http://127.0.0.1:10912/...`（規格已修，見該檔 v1.1 變更紀錄），修好後
乾淨重跑：

```
verdict: **PASS**  (pass=10 fail=0 skip=0)
```

冪等重跑：`changed=0`（`ok=14 skipped=3 failed=0`）。

---

## 6. 端到端證明：全局查詢真的彙總了跨站資料

```bash
go run ./cmd/pilot vm-target exec --name nexus -- curl -fsS 'http://127.0.0.1:10912/api/v1/query?query=up'
```

```json
{"status":"success","data":{"resultType":"vector","result":[
  {"metric":{"__name__":"up","instance":"localhost:9090","job":"prometheus","site":"site-a"},
   "value":[1784274022.105,"1"]}
],"analysis":{}}}
```

```bash
go run ./cmd/pilot vm-target exec --name nexus -- curl -fsS 'http://127.0.0.1:10912/api/v1/stores'
```

```json
{"status":"success","data":{
  "sidecar":[{"name":"192.168.122.6:10901","lastError":null,"labelSets":[{"site":"site-a"}],...}],
  "store":[{"name":"pilot-thanos-store:10903","lastError":null,"labelSets":[],...}]
}}
```

從中央的 Thanos Query 打 `/api/v1/query`，回傳的 series 帶
`site="site-a"` label，`/api/v1/stores` 顯示真的發現了 `client-vm`
（192.168.122.6）這個站台的 Sidecar——這就是「異地機房資料匯總、全局查詢」
的真實證明，不是靠猜或只是 HTTP 200 空結果。

---

## 7. 端到端證明：Prometheus → Alertmanager 告警推送

**持續性 Watchdog（seed rule，永遠 firing）**：

```bash
go run ./cmd/pilot vm-target exec --name pt-alert -- \
    sudo curl -fsS http://127.0.0.1:9093/api/v2/alerts
```

```json
[{"labels":{"alertname":"Watchdog","severity":"info","site":"site-a"},
  "status":{"state":"active"}, ...}]
```

**`site=site-a` 標籤從 Prometheus `external_labels` 成功傳到
Alertmanager**，證明 Prometheus 正確評估 seed rules、推送至
`alertmanager-backend:9093`、Alertmanager 接收並 group。

**有界測試告警（firing → resolved 的完整生命週期，本次整併重測新增的
證據）**：

```bash
NOW=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
END=$(date -u -d "+20 seconds" +%Y-%m-%dT%H:%M:%S.000Z)
go run ./cmd/pilot vm-target exec --name pt-alert -- sudo curl -fsS -X POST \
    http://127.0.0.1:9093/api/v2/alerts -H "Content-Type: application/json" \
    -d "[{\"labels\":{\"alertname\":\"pilot-consolidation-test-alert\",\"severity\":\"info\"},
         \"annotations\":{\"msg\":\"metrics-alerting consolidation firing/resolved evidence\"},
         \"startsAt\":\"$NOW\",\"endsAt\":\"$END\"}]"
```

立刻查詢（firing 中）：

```
Watchdog active
pilot-consolidation-test-alert active
```

TTL（20 秒）過後重查（含 `active=true&silenced=true&inhibited=true&
unprocessed=true` 全狀態一起查）：

```
Watchdog active
```

`pilot-consolidation-test-alert` 已完全從所有狀態（active/silenced/
inhibited/unprocessed）消失——確認它真的 resolved 並被清掉，不是卡在某個
中間狀態，也沒有殘留。

---

## 7a. 新增：`host-monitoring`（node_exporter）自動探索 + Basic Auth（2026-08-10）

### 背景

調查 Grafana 的 `Node Exporter Full` dashboard 為何沒資料，追到根因是這個
repo 從來沒有部署 node_exporter 的能力——`prometheus` 只 scrape 自己。新增
獨立元件 `host-monitoring`（`docs/verification/host-monitoring.md` +
`playbooks/apply/host-monitoring-apply.yml`），裝在被監控主機上；`prometheus`
這邊新增自動從 inventory 的 `host-monitoring` group 展開 scrape target 的
邏輯（`node_exporter_targets`，留空時自動探索），並要求強制 HTTP Basic
Auth（`node_exporter_basic_auth_user`/`password`，兩邊必須帶同一個值）。

### 事實快照（2026-08-10T07:40–07:55 UTC）

- `pilot vm-target list`（測試前）：既有 `client-vm`/`freeipa-server`/`nexus`
  三台（別的 workstream 保留中，未動）。
- 本次新建 3 台：`hm-ubuntu`（Ubuntu 24.04）、`hm-el9`（AlmaLinux 9，跨
  distro 驗證）、`prom-test`（Ubuntu 24.04，跑 `prometheus`）。
- Tested revision：本次 host-monitoring 相關變更的工作樹（`git status`
  當時為 host-monitoring 系列新檔 + prometheus 系列修改，未 commit）。

### 單機測試：`host-monitoring` on Ubuntu 24.04（`hm-ubuntu`）

```bash
go run ./cmd/pilot vm-target up --name hm-ubuntu --ssh-user ubuntu \
    --disk 20 --memory 2048 --vcpus 2 --ssh-timeout 8m --boot-timeout 8m --services local

go run ./cmd/pilot vm-target run --name hm-ubuntu --skip-lint \
    playbooks/apply/host-monitoring-apply.yml -e target_group=hm-ubuntu \
    -e node_exporter_basic_auth_password=<password>
# PLAY RECAP: ok=24 changed=11 failed=0 skipped=2

go run ./cmd/pilot vm-target verify --name hm-ubuntu docs/verification/host-monitoring.md
# verdict: PASS (pass=10 fail=0 skip=0)

# 冪等重跑（同一組密碼)
go run ./cmd/pilot vm-target run --name hm-ubuntu --skip-lint \
    playbooks/apply/host-monitoring-apply.yml -e target_group=hm-ubuntu \
    -e node_exporter_basic_auth_password=<password>
# PLAY RECAP: ok=16 changed=0 failed=0 skipped=10
```

### 單機測試：`host-monitoring` on AlmaLinux 9（`hm-el9`，跨 distro）

同一套 playbook、同一個密碼，對 `hm-el9`（`--base-image almalinux-9`）重跑
一次完整流程：apply（`ok=24 changed=11 failed=0`）→ verify
（`PASS pass=10 fail=0 skip=0`）→ 冪等重跑（`changed=0`）。EL9 走
`httpd-tools`（非 Debian 的 `apache2-utils`）取得 `htpasswd`，bcrypt hash
產生流程與 Ubuntu 完全一致，兩邊行為/版本一致（符合設計目標）。

### 多 VM cross-check：`prometheus` 自動探索 `host-monitoring`

```bash
go run ./cmd/pilot vm-target up --name prom-test --ssh-user ubuntu \
    --disk 20 --memory 3072 --vcpus 2 --ssh-timeout 8m --boot-timeout 8m --services local
go run ./cmd/pilot vm-target run --name prom-test --skip-lint \
    playbooks/apply/docker-apply.yml -e target_group=prom-test

# 用 --group 把 hm-ubuntu 標成 host-monitoring group、prom-test 標成
# prometheus group,組成同一份 inventory（沒有真的 seaweedfs-s3/alertmanager,
# 用假 S3 endpoint 只為了通過 gate,不影響 node-exporter 整合本身要驗證的東西)
go run ./cmd/pilot vm-target run \
    --group host-monitoring=hm-ubuntu --group prometheus=prom-test --skip-lint \
    playbooks/apply/prometheus-apply.yml -e target_group=prometheus \
    -e prometheus_site_label=test-site -e thanos_s3_endpoint=203.0.113.1:9000 \
    -e thanos_aws_access_key_id=fakekey -e thanos_aws_secret_access_key=fakesecret \
    -e node_exporter_basic_auth_password=<同一組password>
# PLAY RECAP: ok=21 changed=9 failed=0 skipped=8
```

實際渲染出來的 `/etc/pilot/prometheus/prometheus.yml`（節錄）：

```yaml
scrape_configs:
- job_name: prometheus
  static_configs:
    - targets: ["localhost:9090"]

- basic_auth:
    password_file: /etc/prometheus/node-exporter-basic-auth-password
    username: prometheus
  job_name: node
  static_configs:
  - targets:
    - 192.168.122.5:9100
```

端到端證明（直接對 Prometheus API 查詢，percent-encode `{`/`}` 避開 curl
自己的 URL globbing）：

```bash
$ curl -fsS 'http://127.0.0.1:9090/api/v1/query?query=up%7Bjob%3D%22node%22%7D'
{"status":"success","data":{"resultType":"vector","result":[{"metric":
{"__name__":"up","instance":"192.168.122.5:9100","job":"node"},
"value":[1786348255.670,"1"]}]}}
```

`up{job="node"}==1`——認證通過、真的抓到資料。同時在 `hm-ubuntu` 上直接
確認「未認證會被擋」與「認證後放行」兩條路徑都對：

```bash
$ curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9100/metrics
401
$ curl -sS -u prometheus:<password> -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9100/metrics
200
```

`docs/verification/prometheus.md -i <combined-inv> -l prometheus` 全 14
rows：`pass=12 fail=2`——fail 的只有 C9（假 S3 endpoint 連不到，timeout，
跟本次改動無關）跟 C11（沒接 alertmanager，§5 已知例外），本次改動直接
相關的 C13/C14 皆 pass。冪等重跑 `changed=0`。

### 完成後：teardown

```bash
go run ./cmd/pilot vm-target down --name prom-test
go run ./cmd/pilot vm-target down --name hm-el9
go run ./cmd/pilot vm-target down --name hm-ubuntu
```

---

## 8. 各角色 Verify / Idempotency 總表

| 角色 | target | verify | 冪等重跑 |
|---|---|---|---|
| `alertmanager` | pt-alert | PASS pass=7 fail=0 skip=0 | changed=0 |
| `prometheus` | client-vm | PASS pass=12 fail=0 skip=0 | changed=0 |
| `thanos-query` | nexus | PASS pass=10 fail=0 skip=0（修正 port 後） | changed=0 |
| `host-monitoring`（Ubuntu 24.04） | hm-ubuntu | PASS pass=10 fail=0 skip=0 | changed=0 |
| `host-monitoring`（AlmaLinux 9） | hm-el9 | PASS pass=10 fail=0 skip=0 | changed=0 |
| `prometheus`（+ node-exporter 自動探索，§7a） | prom-test + hm-ubuntu | pass=12 fail=2（C9/C11，跟本次改動無關，見 §7a） | changed=0 |

三份原始 spec 全數 PASS；`host-monitoring` 兩種 distro 皆 PASS；`prometheus`
的 node-exporter 整合相關 rows（C13/C14）皆 PASS。所有 apply 的第二次
執行皆 `changed=0`。

---

## 9. 已知坑 / 實測發現

| 坑 | 說明 | 解法 |
|----|------|------|
| Thanos 官方 image (`thanosio/thanos:v0.36.1`) 跑 uid 1001，Store/Compactor 對 root-owned host 目錄寫入被拒絕、無限重啟 | `mkdir /var/lib/thanos-store/meta-syncer: permission denied` | `thanos-query-apply.yml` 已內建把 data dir chown 成 `1001:1001`（本次重測未再踩到，playbook 已修好） |
| `docker_container` 模組修好 ownership 後不會自動重建卡在無限重啟迴圈的舊 container | 模組只比對自己宣告的參數 diff，host 目錄外部狀態變化不影響判斷 | 需要手動 `docker rm -f` 卡住的舊 container，下次 apply 才會用乾淨環境重建（本次全新環境未踩到） |
| `docs/verification/thanos-query.md` C4/C5/C9/C10 對 port 10902 curl 拿到 `000`/rc=2 | `thanos_query_http_port` 早就預設改成 `10912`（避免跟站台 Sidecar 的 10902 collide），spec 沒跟著更新——2026-07-17 整併重測發現的真事故 | 已修：spec 改用 10912（見 `docs/verification/thanos-query.md` v1.1）；若套用時有覆寫 `-e thanos_query_http_port=<值>`，checklist 也要跟著改 |
| `/api/v1/stores` 回應沒有 `"status"` 欄位 | v0.36.1 的欄位只有 `name`/`lastCheck`/`lastError`/`labelSets`，不是憑經驗猜的欄位 | spec 改成數 `"lastError":null` 出現次數 |
| 零站台時 `/api/v1/stores` 的判斷邏輯恆真 | 中央自己的 Store Gateway 永遠是一個 StoreAPI endpoint，跟「有沒有站台接上」是兩件事 | spec 改成專門檢查 `"sidecar":[` 這個 JSON key，只有真的有站台 Sidecar 連上才會出現 |
| `pilot vm-target run --name <某台> ... -e target_group=<角色 group 名>` 顯示 `skipping: no hosts matched` | apply playbook 的 `hosts:` 預設是角色 group 名，單機 vm-target inventory 沒有這個 group，只有同名 host | 對單一 VM 測試時用 `-e target_group=all` |
| Jinja vs Prometheus template：`prometheus_alert_rules` 是 inline YAML 字串時 `{{ $labels.X }}` 被 Ansible Jinja 二次解析失敗 | `"Syntax error: unexpected char '$'"` | 改用 `prometheus_alert_rules_file` 檔案路徑 + `copy: src:`，避開 Jinja 處理 |
| 舊版文件用「手動合併 inventory + raw `ansible-playbook -i <file>`」測 `thanos-query-apply.yml` 的站台探索 | 當時 `pilot vm-target run` 還沒有能組合多台 vm-target inventory 的旗標 | 現在改用 `vm-target run --group <group>=<target1,target2,...>`（見 §5），不再需要繞出 `vm-target` 這層 CLI、也不用手寫合併 inventory |
| AlmaLinux 9（RHEL family）套 `core-infra-provider-apply.yml -e infra_role=docker` 失敗：`No package docker-compose available` | RHEL family 的 docker 安裝沒處理 EPEL/docker-ce repo 依賴（本檔範圍外，未修，已記錄在 `docs/runbooks/docker.md` §4） | 本檔四個角色一律用 Ubuntu vm-target；若要在 EL 系上跑，需先手動解決 docker-compose 套件來源 |
| （2026-08-10，§7a）`host-monitoring-apply.yml` 在 `--check` 對從零開始的主機跑：`unarchive` 對一個只被 `get_url` 模擬下載（check mode 下沒真的下載）的來源檔案，直接 crash（不像 `copy`/`file` 能優雅模擬） | `Source '/tmp/node_exporter-....tar.gz' does not exist` | 在 `unarchive`/後續 `copy` 的 `when` 加 `and not ansible_check_mode`，延後到真正 apply 才做，跟本 repo既有的 check-mode-fresh-bootstrap 慣例一致 |
| （2026-08-10，§7a）同一類 check-mode 坑：`htpasswd` 這個 CLI 工具本身是**這支 playbook 自己**在同一次 apply 裡用 `apt`/`dnf` 裝的，在 `--check` 下只被模擬安裝，強制 `check_mode: false` 讓產生 bcrypt hash 的 task 真的執行,反而因為 binary 真的不存在而失敗 | `Error executing command: No such file or directory: 'htpasswd'` | 拿掉 `check_mode: false`，改成跟 `unarchive` 一樣加 `and not ansible_check_mode` 整段延後——`check_mode: false` 只適合「前提條件來自前一次 apply」的情境（例如既有 docker_container_exec 探測已存在的容器），不適合前提條件就是**同一次** check-mode run 裡才會建立的東西 |
| （2026-08-10，§7a）`prometheus-apply.yml` 新增的 node-exporter scrape job 用 Jinja `~ "\n"` 手動拼字串塞進 `>-` YAML folded scalar，結果 `\n` 沒被展開成真正換行,渲染出無效 YAML | 本機模擬測試就抓到，未上真機（見下一條真機才抓到的坑） | 改用原生 list/dict 資料結構 + `to_nice_yaml(indent=2)` 序列化，徹底避開手動處理換行字元 |
| （2026-08-10，§7a）改用 `to_nice_yaml` 後，spec C13 原本錨定 `^-\s*job_name:\s*node$`（假設 `job_name` 是這個 list item 的第一個 key），實測在真的 `prom-test` vm-target 上失敗 | `to_nice_yaml` 預設把 dict key 依字母序排列，真實輸出是 `- basic_auth:` 打頭，`job_name: node` 變成第二行 | C13 改成只錨 `^\s*job_name:\s*node$`（不管前面有沒有 `-`），對 key 順序無感 |

---

## 10. Teardown

```bash
go run ./cmd/pilot vm-target down --name nexus
go run ./cmd/pilot vm-target down --name client-vm
go run ./cmd/pilot vm-target down --name pt-alert
go run ./cmd/pilot vm-target down --name pt-s3
go run ./cmd/pilot vm-target list   # 確認為空
```

> 本次整併重測選擇**保留** `client-vm`/`nexus` 供同一次整併作業的其他
> workstream 沿用，未執行上方 teardown 的前兩行；`pt-alert`/`pt-s3` 是本
> workstream 專用建立的 VM，验收完成後應正常 teardown。

---

## 11. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-06 | v1.0 | 初版：`prometheus`/`thanos-query` 設計、apply playbook、spec、regression test、vm-target 三台 VM 實測（3 個真事故修好），全局跨站查詢驗證成功 | sre |
| 2026-07-14 | v1.1 | 更正舊版 `vm-target up` state-file race 說明：不同名稱 VM 現可平行建立 | Codex |
| 2026-07-17 | v2.0 | 文件整併：`docs/runbooks/alertmanager.md` 併入本檔（該檔已歸檔），檔名由 `prometheus-thanos.md` 改為 `metrics-alerting.md`。用同一次四主機環境（`prometheus`/`thanos-query`/`alertmanager`/S3 目的地）重新實跑三個角色的 apply/verify/idempotency，新增 Prometheus→Alertmanager 端到端證明（含有界測試告警 firing→resolved 的完整生命週期）。改用 `vm-target run --group` 取代舊版手動合併 inventory + raw `ansible-playbook` 的探索測試方式。發現並修好 `docs/verification/thanos-query.md` 的 port 10902→10912 真事故（規格落後於 playbook 早先的預設值變更）。發現一個範圍外的真實環境限制：`core-infra-provider-apply.yml` 的 RHEL family docker 安裝缺 `docker-compose` 套件來源（AlmaLinux 9），未修 | sre |
| 2026-08-10 | v2.1 | 新增 §7a：`prometheus` 自動從 inventory 的 `host-monitoring` group 展開 node_exporter scrape target（新元件，見 `docs/runbooks/host-monitoring.md`），強制 HTTP Basic Auth。3 台新 vm-target（Ubuntu + AlmaLinux 9 + prometheus）實跑：`host-monitoring` 兩種 distro 各自 apply/verify（10/10 PASS）/冪等重跑（changed=0）；`prometheus` 用 `--group` 跟 `host-monitoring` 組合 inventory，端到端證明 `up{job="node"}==1`（認證通過）與未認證 401/認證後 200 兩條路徑。實跑中發現並修好 4 個真 bug：`unarchive`/`htpasswd` 在 check-mode 對「同一次 apply 裡才會建立的前提條件」處理不當（兩處）、`prometheus_scrape_configs` 手動拼 `\n` 在 `>-` YAML scalar 下沒被展開成真換行（改用 `to_nice_yaml`）、改用 `to_nice_yaml` 後 spec C13 原本錨定的 `^-\s*job_name:` 因為 key 依字母序排列而抓不到（改成不錨 `^-`）——後兩個是本機模擬/真機分別抓到的，見 §9 表格 | sre |
