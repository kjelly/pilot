# Runbook — `dashboard` + `log-shipping`（Grafana + Loki 觀測畫面）

> Status: **`dashboard.md` v1.1 14/14 PASS**、**`log-shipping.md` 7/7
> PASS**，idempotency 已驗證（re-apply changed=0），正負向路徑都真實測
> 過，Grafana 自己的 datasource proxy 真的能查到 Thanos 跟 Loki 的資料，
> 兩份內建 dashboard 也在真實瀏覽器（Playwright）裡確認過會用真實資料
> 正常運作。

> 撰寫日期：2026-07-06 (UTC)
> 對齊規範：`docs/verification/dashboard.md`（v1.1）、
> `docs/verification/log-shipping.md`（v1.0）
> 維護者：sre

---

## 0. 一句話目標

`prometheus.md` + `thanos-query.md`（跨站 metrics）跟 `log-server.md`
（中央日誌落地）都只有 CLI/HTTP API,沒有一個給人看的畫面。`dashboard`
角色補上這塊:Grafana 對 `thanos-query` 的 Prometheus-compatible API 開一
個 datasource、對本機 Loki 開另一個,兩個 datasource 的 uid 都寫死成固定
值(`pilot-thanos-query`、`pilot-loki`),讓 spec 可以用固定字串驗證
provisioning 檔案內容。`log-shipping` 角色疊在 `log-server.md` 之上(同一
台主機、不改 log-server 本體),用 Promtail 把 rsyslog 已經落地的檔案轉送
進 dashboard 那台的 Loki。

架構決策(使用者已確認):日誌轉送機制選 **Promtail agent**,不是改用
rsyslog 內建的 `omhttp` 直推——Promtail 是專門做這件事的工具,設定簡單、
社群文件齊全,跟現有 `audit-log-forwarding`「client 端跑 agent、填一個
central IP 變數」的既有慣例完全一致;`omhttp` 雖然不用多裝一個 process,
但要手刻 Loki 的 JSON push 格式進 RainerScript,較冷門、出錯不易排查,而
且會改到已經是 v1.0 的 `log-server-apply.yml` 本體。

---

## 0.5 事實快照（2026-07-06T11:5X–12:1X UTC，本機 docker smoke test + vm-target 之間）

套用前先用本機 docker(非 vm-target)驗證三個關鍵假設,省下 vm-target 除錯
輪次:

```bash
$ docker run --rm --entrypoint id grafana/grafana:11.1.0
uid=472(grafana) gid=0(root)
$ docker run --rm --entrypoint id grafana/loki:2.9.8
uid=10001(loki) gid=10001(loki)
$ docker run --rm --entrypoint id grafana/promtail:2.9.8
uid=0(root) gid=0(root)
```

confirmed:Grafana/Loki 官方 image 都不是 root,host data dir 需要
chown;Promtail 是 root,不需要（讀 log-server 的 rsyslog-owned 檔案、寫
自己的 positions 目錄都沒有權限問題）。

本機也先跑通 Loki push/query API、Grafana datasource provisioning(固定
uid)、Promtail tail→push→query 全鏈路,才動手寫 playbook——細節見 §6
Bug 1、Bug 2（都是在寫 spec 當下就避免掉的坑，不是 vm-target 才發現）。

```bash
$ go run ./cmd/pilot vm-target list
(no targets — 起 VM 前)

$ go run ./cmd/pilot spec docs/verification/dashboard.md --lint
spec Verification Spec — dashboard (Grafana + Loki，跨機房 Metrics/Log 觀測入口): 10 rows, 0 findings (0 errors)

$ go run ./cmd/pilot spec docs/verification/log-shipping.md --lint
spec Verification Spec — log-shipping (Promtail：log-server → dashboard Loki): 7 rows, 0 findings (0 errors)

$ go test ./internal/spec/ -run 'TestRegression_DashboardSpec|TestRegression_LogShippingSpec' -v
--- PASS: TestRegression_DashboardSpec (0.00s)
--- PASS: TestRegression_LogShippingSpec (0.00s)
```

四台 vm-target:`ds-s3`（SeaweedFS S3,thanos-query 的 object storage）、
`ds-tq`（`thanos-query` 角色,零站台,只為了給 dashboard 一個真實可查詢的
Prometheus-compatible 上游）、`ds-dash`（`dashboard` 角色）、`ds-log`
（`log-server` + `log-shipping` 角色疊加）。全部 ubuntu-24.04、
2 vCPU/2GB/20GB,`--ssh-user ubuntu`。

**對齊決策**:沒有另外部署一個 `prometheus` 站台——`thanos-query.md` 本身
已經在上一輪 vm-target 測試證明「零站台也能正常運作」,這裡的重點是驗證
`dashboard`/`log-shipping` 自己的邏輯,不需要重複證明 thanos-query 沒問
題;用一個真實、零站台的 thanos-query 當上游,比自架假的健康檢查 endpoint
更有證據力,成本也不高(複用上一輪已經跑通的 playbook)。

---

## 1. 起 4 台 VM + 裝 Docker（本次證據為依序建立）

不同名稱的 `vm-target up` 可平行執行；state 的跨程序 `Store.Mutate` 已修正舊版
state-file race。以下維持依序命令與原始輸出，作為本次實測證據；資源足夠時可改為
平行建立這四台不同名稱的 VM。Docker apply 仍依各角色的後續依賴順序執行。

```bash
$ go run ./cmd/pilot vm-target up --name ds-s3   --ssh-user ubuntu --disk 20 --memory 2048 --vcpus 2 --ssh-timeout 8m --boot-timeout 8m
  ip: 192.168.122.2
$ go run ./cmd/pilot vm-target up --name ds-tq   --ssh-user ubuntu --disk 20 --memory 2048 --vcpus 2 --ssh-timeout 8m --boot-timeout 8m
  ip: 192.168.122.3
$ go run ./cmd/pilot vm-target up --name ds-dash --ssh-user ubuntu --disk 20 --memory 2048 --vcpus 2 --ssh-timeout 8m --boot-timeout 8m
  ip: 192.168.122.4
$ go run ./cmd/pilot vm-target up --name ds-log  --ssh-user ubuntu --disk 20 --memory 2048 --vcpus 2 --ssh-timeout 8m --boot-timeout 8m
  ip: 192.168.122.8
```

`virt-customize ... supermin exited with error status 1` 出現在全部四台,
已知無害警告（fallback 用 uncustomized image）。

```bash
$ for n in ds-s3 ds-tq ds-dash ds-log; do
    go run ./cmd/pilot vm-target run --name $n \
      playbooks/apply/core-infra-provider-apply.yml \
      -e target_group=all -e infra_role=docker
  done
# 四台皆 PLAY RECAP: ok=6 changed=2 failed=0 skipped=13
```

---

## 2. `ds-s3` + `ds-tq`：給 dashboard 一個真實的 Prometheus 上游

跟 `docs/runbooks/prometheus-thanos.md` §2 完全同一套 SeaweedFS 簽章模式
setup（只是換一個 bucket 名避免跟舊資料混用）:

```bash
$ cat s3.json
{"identities":[{"name":"thanos","credentials":[
  {"accessKey":"dash-sandbox-key","secretKey":"dash-sandbox-secret-123"}
],"actions":["Admin","Read","Write"]}]}
# 寫進 ds-s3:/etc/pilot-s3/s3.json

$ go run ./cmd/pilot vm-target run --name ds-s3 \
    playbooks/apply/seaweedfs-s3-apply.yml \
    -e target_group=all -e seaweedfs_s3_config_path=/etc/pilot-s3/s3.json
PLAY RECAP: ds-s3  ok=9 changed=6 failed=0

$ go run ./cmd/pilot vm-target exec --name ds-s3 -- \
    sudo docker exec pilot-seaweedfs sh -c "echo 's3.bucket.create -name pilot-dashboard-metrics' | weed shell"
create bucket under /buckets
created bucket pilot-dashboard-metrics
```

套用 `thanos-query`（零站台,只當健康的查詢上游）:

```bash
$ go run ./cmd/pilot vm-target run --name ds-tq playbooks/apply/thanos-query-apply.yml \
    -e target_group=all \
    -e thanos_s3_target_host=192.168.122.2 \
    -e thanos_s3_bucket=pilot-dashboard-metrics \
    -e thanos_aws_access_key_id=dash-sandbox-key \
    -e thanos_aws_secret_access_key=dash-sandbox-secret-123
PLAY RECAP: ds-tq  ok=12 changed=8 failed=0
```

第一次套用就成功,沒有 fail 任何一個 task(uid 1001 chown 防禦性設計已經
在上一輪 `thanos-query-apply.yml` 修好,這裡直接吃到)。

---

## 3. `ds-dash`：套用 `dashboard`（Grafana + Loki）

```bash
$ go run ./cmd/pilot vm-target run --name ds-dash playbooks/apply/dashboard-apply.yml \
    -e target_group=all \
    -e thanos_query_target_host=192.168.122.3 \
    -e grafana_admin_password=dash-sandbox-pass
...
TASK [Wait for Loki to become ready] ***
FAILED - RETRYING (x12, ~24s)
ok: [ds-dash]
...
PLAY RECAP: ds-dash  ok=12 changed=9 failed=0
```

Loki 需要約 24 秒完成 ring/compactor join 才 ready,重試迴圈吃住了、不是
bug（跟本機 smoke test 觀察到的 10–15 秒暖機一致，vm 上稍慢屬正常）。

驗證(**第一次跑,發現真 bug,見 §6 Bug 3**):

```bash
$ go run ./cmd/pilot vm-target verify --name ds-dash docs/verification/dashboard.md
verdict: FAIL (pass=6 fail=4)
C5 fail | rc=2 ...   C6 fail | rc=2 ...   C9 fail | ...   C10 fail | ...
```

修完 spec（見 §6 Bug 3）後重新驗證:

```bash
$ go run ./cmd/pilot vm-target verify --name ds-dash docs/verification/dashboard.md
verdict: **PASS**  (pass=10 fail=0 skip=0)
```

Idempotency(原樣重跑一次):

```bash
$ go run ./cmd/pilot vm-target run --name ds-dash playbooks/apply/dashboard-apply.yml -e ...(同上)
PLAY RECAP: ds-dash  ok=12 changed=0 failed=0
```

---

## 4. `ds-log`：套用 `log-server` + `log-shipping`（疊加）

```bash
$ go run ./cmd/pilot vm-target run --name ds-log playbooks/apply/log-server-apply.yml -e target_group=all
PLAY RECAP: ds-log  ok=8 changed=4 failed=0

$ go run ./cmd/pilot vm-target run --name ds-log playbooks/apply/log-shipping-apply.yml \
    -e target_group=all -e loki_target_host=192.168.122.4
PLAY RECAP: ds-log  ok=6 changed=5 failed=0
```

驗證(**發現真 bug,見 §6 Bug 4**):

```bash
$ go run ./cmd/pilot vm-target verify --name ds-log docs/verification/log-shipping.md
verdict: FAIL (pass=6 fail=1)
C4 fail | rc-from-stdout=1, expected 0
```

修完 spec 後:

```bash
$ go run ./cmd/pilot vm-target verify --name ds-log docs/verification/log-server.md
verdict: **PASS**  (pass=12 fail=0 skip=0)   # log-server.md 本體完全沒被動到

$ go run ./cmd/pilot vm-target verify --name ds-log docs/verification/log-shipping.md
verdict: **PASS**  (pass=7 fail=0 skip=0)
```

Idempotency:

```bash
$ go run ./cmd/pilot vm-target run --name ds-log playbooks/apply/log-shipping-apply.yml -e ...(同上)
PLAY RECAP: ds-log  ok=6 changed=0 failed=0
```

---

## 5. 負向路徑測試（deliberately exercise the "not connected yet" state）

spec §1.5/§5 都寫明「上游還沒接上」是合法狀態,不是 bug——照
`spec-driven-feature-workflow` skill 的要求實際測過,不只是紙上寫寫:

**`log-shipping.md`**(拔掉 `/etc/hosts` 的 `pilot-loki-backend` pin,不帶
`loki_target_host` 重新套用):

```bash
$ go run ./cmd/pilot vm-target exec --name ds-log -- sudo sed -i '/pilot-loki-backend/d' /etc/hosts
$ go run ./cmd/pilot vm-target run --name ds-log playbooks/apply/log-shipping-apply.yml -e target_group=all
PLAY RECAP: ds-log  ok=5 changed=0 failed=0 skipped=1   # /etc/hosts pin task 正確跳過

$ go run ./cmd/pilot vm-target verify --name ds-log docs/verification/log-shipping.md
verdict: FAIL (pass=5 fail=2)
C5 fail | rc-from-stdout=1, expected 0
C6 fail | stdout="(stderr) curl: (6) Could not resolve host: pilot-loki-backend", expected ~"PILOT-LOGSHIP-SELFTEST"
```

正確地**只有** C5(alias pin)、C6(跨主機功能性)fail,C1–C4、C7 全部照常
pass——證明 Promtail 本身健康跟「有沒有接上中央」是兩件獨立的事。

**`dashboard.md`**(拔掉 `thanos-query-backend` pin,不帶
`thanos_query_target_host` 重新套用):

```bash
$ go run ./cmd/pilot vm-target exec --name ds-dash -- sudo sed -i '/thanos-query-backend/d' /etc/hosts
$ go run ./cmd/pilot vm-target run --name ds-dash playbooks/apply/dashboard-apply.yml \
    -e target_group=all -e grafana_admin_password=dash-sandbox-pass
PLAY RECAP: ds-dash  ok=11 changed=0 failed=0 skipped=1

$ go run ./cmd/pilot vm-target verify --name ds-dash docs/verification/dashboard.md
verdict: FAIL (pass=9 fail=1)
C8 fail | stdout="000", expected ~"200"
```

正確地**只有** C8 fail,其餘 9 行照常 pass。兩邊都補回變數重新套用,
最終恢復成全綠(見 §3、§4 的 idempotency 區塊之後)。

---

## 5.5 真實端到端證據：透過 Grafana 自己的 datasource proxy 查詢

不只驗證 Loki/Thanos 自己的 API,連 Grafana 對外的查詢介面也真的打通:

```bash
$ go run ./cmd/pilot vm-target exec --name ds-dash -- \
    curl -fsS -u admin:dash-sandbox-pass \
    "http://127.0.0.1:3000/api/datasources/proxy/uid/pilot-thanos-query/api/v1/query?query=up"
{"status":"success","data":{"resultType":"vector","result":[],"analysis":{}}}
# result 是空陣列——預期行為,ds-tq 是零站台的 thanos-query,沒有東西在
# scrape;重點是 Grafana 透過固定 uid 的 datasource 成功把查詢轉發到
# Thanos Query 並拿回合法回應,不是連線失敗。

$ go run ./cmd/pilot vm-target exec --name ds-dash -- \
    curl -fsS -u admin:dash-sandbox-pass -G \
    "http://127.0.0.1:3000/api/datasources/proxy/uid/pilot-loki/loki/api/v1/query" \
    --data-urlencode 'query={job="pilot-dashboard-selftest"}'
{"status":"success","data":{"resultType":"streams","result":[{"stream":{"job":"pilot-dashboard-selftest"},
  "values":[["1783340192108490627","PILOT-DASHBOARD-SELFTEST"]]}], ...}}
```

Loki 那筆確實查到 spec C7 自己寫進去的 selftest 標記——證明 Grafana→Loki
這條路徑完整可用。

---

## 6. 踩過的雷

### Bug 1（本機 smoke test 階段，寫 playbook 之前就抓到）：容器 uid 不是 root

`docker run --rm --entrypoint id grafana/grafana:11.1.0` → uid 472；
`grafana/loki:2.9.8` → uid 10001。兩者都不是 root，host-mounted 資料目錄
沒有先 chown 的話會啟動失敗（跟 `prometheus.md`/`thanos-query.md` 遇過的
同一類坑）。**修法**：`dashboard-apply.yml` 在起 container 前先用
`ansible.builtin.file` 把 `grafana_host_data_dir`／`loki_host_data_dir`
分別 chown 成 `472:472`／`10001:10001`。因為是本機 smoke test 就先抓到，
vm-target 上第一次套用就沒有再踩到這個坑。

### Bug 2（本機 smoke test 階段）：Grafana provisioning 需要固定 uid 才能讓 spec 用靜態字串驗證

一開始沒想清楚 Grafana provisioning 的 datasource uid 預設是隨機產生
（要先呼叫 API 查出來才能組第二個驗證指令）。本機測試時發現 Grafana 的
provisioning YAML 支援直接指定 `uid:` 欄位，於是把
`pilot-loki`／`pilot-thanos-query` 寫死進 apply playbook 的
`datasources.yml` 模板，讓 spec 的 C5/C6 可以直接 `grep` 固定字串，不用
先打 API。這個設計決策省掉了「spec 需要先做一次 API 呼叫才能驗證」的
額外複雜度。

### Bug 3（vm-target 實測才發現）：`dashboard.md` 的 C5/C6/C9/C10 留了沒替換掉的 `{{ var }}`

寫 spec 時修好了 C8（原本誤寫 `http://{{ thanos_query_target_host }}...`
——Command/Expected 欄位不能內插部署期變數，跟 `thanos-query.md` C10 的
既有規則一樣），但**同一個錯誤在 C5、C6、C9、C10 又各自犯了一次**
（`{{ dashboard_config_dir }}`、`{{ grafana_host_data_dir }}`、
`{{ loki_host_data_dir }}`），沒有一次性抓乾淨。

**症狀**：`pilot vm-target verify` 回報 C5/C6 `rc=2` 且 detail 是一段
看起來不相關的 deprecation warning 訊息，C9/C10 直接回「expected: present
(rc=0)」的 fail——完全看不出跟「Command 裡有沒有替換掉的 `{{ }}`」有任何
關聍,只能靠讀 ansible ad-hoc 的完整輸出(`ansible <host> -m command -a
"..."` 對一個含 `{{ dashboard_config_dir }}` 字面文字的路徑執行
`test -d`,自然找不到這個字面路徑的目錄)才看出真正原因。

**根本原因**:ansible ad-hoc 的 `-a` 參數仍然會過 Jinja 模板引擎,但沒有
定義同名變數時,不是丟一個好懂的「undefined variable」錯誤,而是把它當
成字面文字繼續往下跑,對一個「路徑字面上真的叫
`{{ dashboard_config_dir }}`」的目錄做 `test -d`,自然找不到,回傳一個
看似無關的失敗。

**修法**:把 C5、C6、C9、C10 的 Command 全部換成 `dashboard_config_dir`／
`grafana_host_data_dir`／`loki_host_data_dir` 的**預設值**字面路徑
（`/etc/pilot/dashboard/...`、`/var/lib/pilot/grafana`、
`/var/lib/pilot/loki`），並在 §5 已知偏差補一條「覆寫成非預設路徑的環境
這四行會如預期 fail」的說明（跟 `log-shipping.md` C3/C4 同一種處理方
式）。同時在 `dashboard_regression_test.go` 加一條「**任何一行 Command
都不准出現 `{{`**」的斷言，鎖死這整類錯誤，不會再犯第二次。

### Bug 4（vm-target 實測才發現）：`log-shipping.md` C4 的 grep pattern 沒算到 render 出來的值是加引號的

`log-shipping-apply.yml` 把 Promtail 的 push URL 用
`url: "http://{{ loki_endpoint }}/loki/api/v1/push"` 樣板 render（外層
包了一組雙引號，跟 `prometheus.md`/`thanos-query.md` 其他 URL 欄位不加
引號的寫法不一致，純粹是我寫模板時的隨手選擇），而 spec C4 原本的 grep
pattern 是 `url:\s*http://pilot-loki-backend:...`——沒有把中間那個
`"` 字元算進去，導致 pattern 永遠比對不到真正 render 出來的內容,C4 100%
必 fail。

**修法**:直接讀 `ds-log:/etc/pilot/promtail/promtail-config.yml` 的真實
內容確認引號存在，把 C4 的 pattern 改成
`url:\s*"http://pilot-loki-backend:3100/loki/api/v1/push"`，並在
`log_shipping_regression_test.go` 加一條鎖死「C4 必須比對加引號版本」的
斷言。**這個 bug 剛好證明了 verification-spec-template.md 反覆強調的
「拿不準 expected/command 怎麼寫，先用 `--probe` 或直接讀真實 render 出
來的檔案，不要用猜的」——C6（同一份 spec 裡的跨主機功能性驗證）當時反而
一次就 pass，因為它是直接查詢實際內容而不是 grep 特定格式，這個對比很
說明問題。**

---

## 7. 拆除（v1.0 這一輪）

```bash
$ for n in ds-s3 ds-tq ds-dash ds-log; do go run ./cmd/pilot vm-target down --name $n; done
✓ target ds-s3 down
✓ target ds-tq down
✓ target ds-dash down
✓ target ds-log down
$ go run ./cmd/pilot vm-target list
(no targets)
```

---

## 9. v1.1：內建兩份 dashboard（Grafana 原生 template variable，依環境自動更新）

### 9.0 架構決策

使用者要求「加一個 spec 與 playbook,能夠依據環境自動化設定 dashboard」。
給了兩個候選:

- **Grafana 原生 template variable**(選定):dashboard JSON 內容固定,
  用 `label_values()` 查詢即時列出目前有哪些 site/job,新站台/主機不需要
  重新套用 playbook。
- Ansible 依 inventory 動態產生每站/每主機面板:一進畫面就並排看到全部,
  但新增站台後要重新套用才會反映,且要維護一份會產生 Grafana JSON 的
  Jinja 樣板。

使用者選擇前者。

### 9.1 動手前:本機 smoke test 定案 JSON schema

Grafana 的 Loki 變數查詢格式（`type: 1`）跟 Prometheus 的
`label_values()` 字串格式不一樣,版本敏感、容易寫錯又無法只靠讀 JSON
schema 文件確認。套用到 vm-target 之前,先在本機用真實 Prometheus（兩個
`site` label 的 static_configs）+ Loki（兩筆不同 `job` 的測試訊息）+
Grafana,並用 **Playwright 開真實瀏覽器**確認兩份 dashboard 都能正常
運作:

```
$ curl http://127.0.0.1:19090/api/v1/query --data-urlencode 'query=up'
{"status":"success","data":{"resultType":"vector","result":[
  {"metric":{"job":"prometheus","site":"site-b"},"value":[...,"1"]},
  {"metric":{"job":"prometheus","site":"site-a"},"value":[...,"1"]}
]}}
```

Playwright 開 `Pilot - Sites Overview`:`site` 變數的下拉選單正確顯示
`site-a`/`site-b`,"Sites Up" stat 面板顯示 `2`,"up by site" 時序圖的
圖例正確顯示 `site-a`/`site-b` 兩條線。開 `Pilot - Logs Explorer`:
`job` 變數列出真實 job 值,Logs 面板顯示两筆真實日誌內容
（"hello from dashboard"、"hello from log-server"）。兩份都是真的能用,
不只是 JSON 語法正確。

### 9.2 vm-target 實測(4 台:ds-s3、ds-tq、ds-dash 重新起,沿用 v1.0 的 SOP)

```bash
$ go run ./cmd/pilot vm-target run --name ds-dash playbooks/apply/dashboard-apply.yml \
    -e target_group=all \
    -e thanos_query_target_host=192.168.122.3 \
    -e grafana_admin_password=dash-sandbox-pass
PLAY RECAP: ds-dash  ok=15 changed=12 failed=0   # 第一次套用,沒有 fail 任何一個 task

$ go run ./cmd/pilot vm-target verify --name ds-dash docs/verification/dashboard.md
verdict: **PASS**  (pass=14 fail=0 skip=0)   # 14/14,含新增的 C11-C14

$ go run ./cmd/pilot vm-target run --name ds-dash playbooks/apply/dashboard-apply.yml -e ...(同上)
PLAY RECAP: ds-dash  ok=15 changed=0 failed=0   # idempotent
```

### 9.3 負向路徑測試:故意弄壞一份 dashboard JSON

`spec-driven-feature-workflow` skill 要求「有 on/off 維度就兩邊都要測」。
C14（沒有 provisioning 錯誤）天生就有這個維度——手動塞一份語法錯誤的
JSON 進 dashboards-json 目錄、重啟 Grafana:

```bash
$ go run ./cmd/pilot vm-target exec --name ds-dash -- sudo sh -c 'echo "{not valid json" > .../dashboards-json/broken-test2.json'
$ go run ./cmd/pilot vm-target exec --name ds-dash -- sudo docker restart pilot-grafana
$ go run ./cmd/pilot vm-target verify --name ds-dash docs/verification/dashboard.md
verdict: FAIL (pass=13 fail=1)
C14 fail | rc=2, expected 0
```

正確地**只有** C14 fail。移除壞檔、重啟、重新驗證 → 恢復 14/14 PASS。
這個負向路徑測試的過程中,連續發現並修好三個真 bug——見 §9.4。

### 9.4 這一輪踩過的雷（延續 §6 編號）

#### Bug 5:C14 的 grep pattern 假設了錯誤的欄位順序

第一版 C14 寫 `grep -q "level=error.*provisioning.dashboard"`，但
Grafana 真實的結構化 log 是 `logger=provisioning.dashboard ... level=
error ...`——`logger=` 欄位在前、`level=` 在後,跟我猜的順序相反,導致
pattern 永遠比對不到真正的錯誤行,C14 對著一個真的有錯誤的環境仍然
PASS。**修法**:改成 `logger=provisioning.dashboard.*level=error`，
用故意弄壞 JSON 的方式重新驗證,確認 FAIL 正確觸發。

#### Bug 6:`docker logs`(不加 `--since`)是整個 container 生命週期的累積歷史

修好 Bug 5 後,移除壞掉的 JSON 檔、`docker restart`,結果 C14 **還是**
FAIL——原因是 `docker logs` 預設回傳從 container 第一次建立以來累積的
**全部**輸出,單純 `docker restart` 不會清掉這份歷史,所以舊的(已經修好
的)錯誤訊息永遠留在裡面,C14 會一路 FAIL 到 container 被整個
rm+recreate 為止。**修法**:改用 `docker logs --since <這次啟動時間>`,
把檢查範圍限定在「這一次啟動之後」。

#### Bug 7:抓「這次啟動時間」不能用 `docker inspect -f '{{ ... }}'`

想抓啟動時間,直覺寫法是 `docker inspect -f '{{.State.StartedAt}}'`
(docker 自己的 Go template 語法,跟 `docker.md` C6 的
`docker network ls --format '{{.Name}}'` 長得一樣)。**用
`pilot verify --probe` 直接測發現整個 task FAILED**:

```
$ go run ./cmd/pilot verify --probe 'sh -c '"'"'! docker logs --since "$(docker inspect -f "{{.State.StartedAt}}" pilot-grafana)" ...'"'"'' ...
msg: "Task failed: Finalization of task args for 'ansible.builtin.shell' failed:
      Error while resolving value for '_raw_params': Syntax error in template: unexpected '.'"
```

**根本原因**:先前(§6 Bug 3)以為「ansible ad-hoc 的 `-m command`/`-a`
不會對 Command 字串跑 Jinja 模板替換」——這個推論是錯的。真正的機制是:
**ad-hoc 確實會跑 Jinja finalization**,`{{ dashboard_config_dir }}`
（v1.0 Bug 3）沒有拋出「undefined variable」是因為那次剛好也是一個
Jinja 語法/求值錯誤,兩種 bug 的症狀（rc=2 + 不相關的 deprecation
warning）長得一模一樣,容易誤判成同一種機制。用同一支 `--probe` 指令
去測 `docker.md` 現有的 C6（`docker network ls --format '{{.Name}}'`）
也重現一樣的 FAILED——**證實 `docker.md` C6 是本 repo 既有 spec 裡一個
尚未被發現的真實缺陷**,超出本次 `dashboard.md` 改動範圍,不在這裡修,
留給日後另案處理。

**修法**:C14 改成不含任何 `{{`/`}}` 字元的寫法,用 `docker inspect`
印出完整 JSON、`sed` 擷取 `StartedAt` 欄位值:

```
docker inspect pilot-grafana | sed -n 's/.*"StartedAt": "\([^"]*\)".*/\1/p' | head -1
```

用 `pilot verify --probe` 確認這個寫法 rc=0、真正在 ansible ad-hoc 下
可用,再放回 spec,最後用 vm-target 重跑正負向路徑各一次,兩邊都正確。

### 9.5 拆除（v1.1 這一輪）

```bash
$ for n in ds-s3 ds-tq ds-dash; do go run ./cmd/pilot vm-target down --name $n; done
✓ target ds-s3 down
✓ target ds-tq down
✓ target ds-dash down
$ go run ./cmd/pilot vm-target list
(no targets)
```

---

## 10. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-14 | v1.2 | 補充不同名稱 VM 現可平行建立；保留循序命令作為原始實測證據 | Codex |
| 2026-07-06 | v1.0 | 初版:`dashboard`（Grafana+Loki）+ `log-shipping`（Promtail）,4 台 vm-target 實測含正負向路徑,發現並修好 4 個真 bug | sre |
| 2026-07-06 | v1.1 | `dashboard.md` 新增 C11-C14:內建兩份 dashboard(Sites Overview、Logs Explorer),用 Grafana 原生 template variable 依環境自動列出 site/job；本機瀏覽器（Playwright）+ vm-target 正負向路徑實測,發現並修好 3 個真 bug（含一個波及 `docker.md` 既有 spec 的 ansible ad-hoc Jinja finalization 陷阱） | sre |
