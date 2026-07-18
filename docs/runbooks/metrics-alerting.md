# Runbook — Metrics / Thanos / Alertmanager（跨機房指標彙總 + 中央告警）

> 撰寫日期：2026-07-06 (UTC)（`prometheus`/`thanos-query` 部分）；
> 2026-07-07（`alertmanager` 部分，原獨立文件 `docs/runbooks/alertmanager.md`）；
> v2.0（2026-07-17）文件整併：兩者合併成本檔，共用一次四主機環境重新實跑，
> 原 `alertmanager.md` 已歸檔。
> 對齊規範：`docs/verification/prometheus.md`（v1.1）、
> `docs/verification/thanos-query.md`（v1.1）、
> `docs/verification/alertmanager.md`（v1.0）
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

## 8. 三角色 Verify / Idempotency 總表

| 角色 | target | verify | 冪等重跑 |
|---|---|---|---|
| `alertmanager` | pt-alert | PASS pass=7 fail=0 skip=0 | changed=0 |
| `prometheus` | client-vm | PASS pass=12 fail=0 skip=0 | changed=0 |
| `thanos-query` | nexus | PASS pass=10 fail=0 skip=0（修正 port 後） | changed=0 |

三份 spec 全數 PASS，三個 apply 的第二次執行皆 `changed=0`。

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
