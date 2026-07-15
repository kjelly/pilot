# Runbook — `prometheus` + `thanos-query`（跨機房指標彙總）

> Status: **`prometheus.md` 9/9 PASS**、**`thanos-query.md` 10/10 PASS**，
> idempotency 已驗證（re-apply changed=0），全局查詢真實回傳跨站資料
> （`up{job="prometheus",site="site-a"}==1`）。

> 撰寫日期：2026-07-06 (UTC)
> 對齊規範：`docs/verification/prometheus.md`（v1.0）、
> `docs/verification/thanos-query.md`（v1.0）
> 維護者：sre

---

## 0. 一句話目標

每個機房/站台各跑一份 Prometheus + Thanos Sidecar（`prometheus` 角色），把
2 小時一個的 TSDB block 上傳到共用的 S3-compatible object storage
（本專案自建的 SeaweedFS）；中央跑一份 Thanos Query + Store Gateway +
Compactor（`thanos-query` 角色），**自動讀 Ansible inventory 的
`prometheus` group**組出各站 Sidecar 的 StoreAPI 位址，不需要手動維護站台
IP 清單。全局查詢（`/api/v1/query`）打中央的 Thanos Query 就能查到所有站台
的資料，且每筆結果帶有 `site` label 分辨來源站。

跟本專案其他 central+agent 角色對子（`wazuh-manager`/`wazuh-fim`、
`log-server`/`audit-log-forwarding`）方向相反：那些是「agent 端填一個
`-e central_host` 變數」，這裡是「**中央主動探索站台**」——`prometheus`
角色完全不需要知道中央在哪裡。見兩份 spec 開頭的架構說明。

---

## 0.5 事實快照（2026-07-06T10:53–11:07 UTC）

```bash
$ go run ./cmd/pilot vm-target list
(no targets — 起 VM 前)

$ go run ./cmd/pilot spec docs/verification/prometheus.md --lint
spec Verification Spec — prometheus (per-site Prometheus + Thanos Sidecar): 9 rows, 0 findings (0 errors)

$ go run ./cmd/pilot spec docs/verification/thanos-query.md --lint
spec Verification Spec — thanos-query (central Thanos Query + Store Gateway + Compactor): 10 rows, 0 findings (0 errors)

$ go test ./internal/spec/ -run 'TestRegression_PrometheusSpec|TestRegression_ThanosQuerySpec' -v
--- PASS: TestRegression_PrometheusSpec (0.00s)
--- PASS: TestRegression_ThanosQuerySpec (0.00s)
```

三台 vm-target：`pt-s3`（SeaweedFS S3 目的地）、`pt-site-a`（`prometheus`
角色，模擬一個機房站台）、`pt-central`（`thanos-query` 角色，模擬中央
彙總查詢）。全部 ubuntu-24.04、2 vCPU/2GB/20GB，`--ssh-user ubuntu`。

**對齊決策**：三台都是全新 vm-target，inventory 跟 spec targets 天生一致
（不需要 A/B 選擇）。

---

## 1. 起 3 台 VM（本次證據為依序建立）

不同名稱的 `vm-target up` 現在可平行執行：state 已改用跨程序鎖定的
`Store.Mutate`，避免舊版的 last-writer-wins state-file race。以下保留依序命令與
原始輸出，作為本次實測的歷史證據；在資源充足且 VM 名稱互異時，可自行平行建立。

```bash
$ go run ./cmd/pilot vm-target up --name pt-s3 --ssh-user ubuntu \
    --disk 20 --memory 2048 --vcpus 2 --ssh-timeout 8m --boot-timeout 8m
✓ target pt-s3 up
  ip        : 192.168.122.2

$ go run ./cmd/pilot vm-target up --name pt-site-a --ssh-user ubuntu \
    --disk 20 --memory 2048 --vcpus 2 --ssh-timeout 8m --boot-timeout 8m
✓ target pt-site-a up
  ip        : 192.168.122.3

$ go run ./cmd/pilot vm-target up --name pt-central --ssh-user ubuntu \
    --disk 20 --memory 2048 --vcpus 2 --ssh-timeout 8m --boot-timeout 8m
✓ target pt-central up
  ip        : 192.168.122.4
```

`virt-customize ... supermin exited with error status 1` 出現在全部三台，
已知無害警告（fallback 用 uncustomized image，照樣開機正常）。

Docker engine（docs/verification/docker.md 前置）三台都套：

```bash
$ for n in pt-s3 pt-site-a pt-central; do
    go run ./cmd/pilot vm-target run --name $n \
      playbooks/apply/core-infra-provider-apply.yml \
      -e target_group=all -e infra_role=docker
  done
# 三台皆 PLAY RECAP: ok=6 changed=2 failed=0 skipped=13
```

---

## 2. 部署 SeaweedFS S3 目的地（簽章模式）

Thanos 一律送簽章請求（跟 restic 一樣），SeaweedFS 預設匿名模式不接受，
需要 `-s3.config` identity 檔：

```bash
$ cat s3.json
{
  "identities": [
    {"name": "thanos", "credentials": [
      {"accessKey": "thanos-sandbox-key", "secretKey": "thanos-sandbox-secret-123"}
    ], "actions": ["Admin", "Read", "Write"]}
  ]
}
# 寫進 pt-s3:/etc/pilot-s3/s3.json（經 base64 + vm-target exec 傳檔）

$ go run ./cmd/pilot vm-target run --name pt-s3 \
    playbooks/apply/seaweedfs-s3-apply.yml \
    -e target_group=all -e seaweedfs_s3_config_path=/etc/pilot-s3/s3.json
PLAY RECAP *********************************************************************
pt-s3                      : ok=9    changed=6    unreachable=0    failed=0    skipped=2
```

**預先建好 `pilot-thanos-metrics` bucket**（SeaweedFS 不會自動生出不存在的
bucket，跟 `docs/runbooks/restic-backup.md` §5 Bug 5 同一個坑）：

```bash
$ go run ./cmd/pilot vm-target exec --name pt-s3 -- \
    sudo docker exec pilot-seaweedfs sh -c "echo 's3.bucket.create -name pilot-thanos-metrics' | weed shell"
create bucket under /buckets
created bucket pilot-thanos-metrics
```

---

## 3. 套用 `prometheus` 角色（站台 `site-a`）

```bash
$ go run ./cmd/pilot vm-target run --name pt-site-a playbooks/apply/prometheus-apply.yml \
    -e target_group=all \
    -e prometheus_site_label=site-a \
    -e thanos_s3_target_host=192.168.122.2 \
    -e thanos_aws_access_key_id=thanos-sandbox-key \
    -e thanos_aws_secret_access_key=thanos-sandbox-secret-123
PLAY RECAP *********************************************************************
pt-site-a                  : ok=13   changed=8    unreachable=0    failed=0    skipped=0
```

第一次套用**沒有 fail 任何一個 task**（Prometheus 官方 image 跑 `nobody`
uid 65534、預先把 host data dir chown 成 65534:65534 這個防禦性設計一次到位）。

驗證：

```bash
$ go run ./cmd/pilot vm-target verify --name pt-site-a docs/verification/prometheus.md
verdict: **PASS**  (pass=9 fail=0 skip=0)
```

Idempotency（原樣重跑一次）：

```bash
$ go run ./cmd/pilot vm-target run --name pt-site-a playbooks/apply/prometheus-apply.yml -e ... （同上）
PLAY RECAP *********************************************************************
pt-site-a                  : ok=13   changed=0    unreachable=0    failed=0    skipped=0
```

---

## 4. 套用 `thanos-query` 角色（中央）—— 需要組合 inventory

**測試基礎設施的限制，不是 playbook 的限制**：`pilot vm-target run` 每次
只餵一個 VM 自己的單主機 inventory（`RenderInventory()` 只寫
`all.hosts.<name>`，沒有 `children:` group）。但 `thanos-query-apply.yml`
的核心設計就是**讀 inventory 的 `prometheus` group** 組出站台清單——單
VM inventory 天生沒有這個 group，直接 `vm-target run` 測不出真實的探索
行為。

做法：手動組一份包含兩台 VM（各自的 `show-inventory` 輸出）+
`children.prometheus.hosts.pt-site-a` 的暫存 inventory，直接用
`ansible-playbook -i <合併後的檔案>` 跑（不透過 `vm-target run` 這層
wrapper）——仍然是對兩台真實 VM 的真實 ansible-playbook 執行，只是繞過
只支援單一 VM 的 CLI 包裝。真實 production inventory（見
`inventory.example.yml`）本來就是這個「一份檔案、多個 group」的形狀，這裡
只是手動重建了那個形狀來測試。

```bash
$ go run ./cmd/pilot vm-target show-inventory --name pt-site-a   # 取得 ansible_host、私鑰路徑等
$ go run ./cmd/pilot vm-target show-inventory --name pt-central
# 手動合併成 pt-combined-inv.yaml：
#   all.hosts: { pt-site-a: {...}, pt-central: {...} }
#   all.children.prometheus.hosts: { pt-site-a: {} }
#   all.children.thanos-query.hosts: { pt-central: {} }

$ ansible-playbook -i pt-combined-inv.yaml playbooks/apply/thanos-query-apply.yml \
    -e target_group=thanos-query \
    -e thanos_s3_target_host=192.168.122.2 \
    -e thanos_aws_access_key_id=thanos-sandbox-key \
    -e thanos_aws_secret_access_key=thanos-sandbox-secret-123
```

第一次套用**失敗**——見 §5 Bug 1。修好後的乾淨結果：

```bash
PLAY RECAP *********************************************************************
pt-central                 : ok=12   changed=2    unreachable=0    failed=0    skipped=0

TASK [Announce discovered sites (debug)] ***************************************
ok: [pt-central] => {
    "msg": "thanos_query_store_group=prometheus; discovered 1 site(s): ['pt-site-a']"
}
```

驗證：

```bash
$ go run ./cmd/pilot vm-target verify --name pt-central docs/verification/thanos-query.md
verdict: **PASS**  (pass=10 fail=0 skip=0)
```

Idempotency（原樣重跑一次）：

```bash
PLAY RECAP *********************************************************************
pt-central                 : ok=12   changed=0    unreachable=0    failed=0    skipped=0
```

---

## 5. 端到端證明：全局查詢真的彙總了跨站資料

```bash
$ go run ./cmd/pilot vm-target exec --name pt-central -- \
    curl -fsS 'http://127.0.0.1:10902/api/v1/query?query=up'
{"status":"success","data":{"resultType":"vector","result":[
  {"metric":{"__name__":"up","instance":"localhost:9090","job":"prometheus","site":"site-a"},
   "value":[1783335846.718,"1"]}
],"analysis":{}}}

$ go run ./cmd/pilot vm-target exec --name pt-central -- \
    curl -fsS 'http://127.0.0.1:10902/api/v1/stores'
{"status":"success","data":{
  "sidecar":[{"name":"192.168.122.3:10901","lastError":null,"labelSets":[{"site":"site-a"}],...}],
  "store":[{"name":"pilot-thanos-store:10903","lastError":null,"labelSets":[],...}]
}}
```

從中央的 Thanos Query 打 `/api/v1/query`，回傳的 series 帶 `site="site-a"`
label——這就是「異地機房資料匯總、全局查詢」的真實證明，不是靠猜。

---

## 6. 踩過的雷（vm-target 實測發現、已在原始碼修好，非「已知偏差」）

### Bug 1 — Thanos 官方 image 跑 uid 1001，不是 root；Store/Compactor 對 root-owned 目錄寫入被拒絕、無限重啟

**症狀**：`thanos-query-apply.yml` 第一次套用時 `pilot-thanos-store` /
`pilot-thanos-compact` 兩個 container 都進入 `Restarting (1)` 無限重啟迴圈。

```
$ docker logs pilot-thanos-store
level=error err="mkdir /var/lib/thanos-store/meta-syncer: permission denied..."
```

**根因**：`docker run --rm --entrypoint id thanosio/thanos:v0.36.1` 確認
image 跑 `uid=1001(thanos) gid=1001(thanos)`；bind-mount 的 host data dir
（`/var/lib/pilot/thanos-store`、`/var/lib/pilot/thanos-compact`）原本是
`root:root 0755`，容器內非 root 使用者對它的子目錄 `mkdir` 被拒絕。
Prometheus（`prom/prometheus`，`nobody` uid 65534）跟 Thanos Sidecar
（無自己的可寫 `--data-dir`）都不受影響——這是 Store Gateway/Compactor
特有的坑。

**修法**：`playbooks/apply/thanos-query-apply.yml` 新增一個 task，把這兩個
data dir 明確 chown 成 `1001:1001`。

**額外的坑**：光是修好 ownership、重跑 playbook，`docker_container` 模組
本身並不會自動重建已經在無限重啟迴圈中的舊 container（它比對的是自己宣告
的參數(`command`/`image`/...)有沒有變,host 目錄的外部狀態變化不在它的
diff 範圍內，所以維持 `ok`、不觸發 restart/recreate）。必須手動
`docker rm -f pilot-thanos-store pilot-thanos-compact` 把卡住的舊
container 清掉,下一次 `ansible-playbook` 重跑才會用（已修好權限的)
乾淨環境重新建立 container。

### Bug 2 — C9 一開始查詢了一個不存在的 JSON 欄位

**症狀**：spec 第一版 C9 檢查 `curl .../api/v1/stores | grep "status":"up"`，
但 v0.36.1 的 `/api/v1/stores` 回應裡每個 store 物件根本沒有 `"status"`
這個 key（只有 `name`/`lastCheck`/`lastError`/`labelSets`）。

**根因**：寫 spec 時憑經驗猜的欄位名稱，沒有先用 `--probe` 或直接
`curl` 實際打過這個 API 確認真實 shape。

**修法**：改成數 `"lastError":null` 的出現次數（`lastError` 是 null 代表
這個 endpoint 健康）。

### Bug 3 — C9 修好欄位名稱後，在「站台都還沒接上」的情境下仍然錯誤地 PASS

**症狀**：故意把 `thanos_query_store_group` 指向一個不存在的 group（模擬
「一站都還沒部署」的狀態）重新套用，`pilot-thanos-store`（中央自己的
Store Gateway，永遠存在、不受站台數量影響）本身也會出現在
`/api/v1/stores` 的 `store` 分組裡、`lastError:null`——導致「至少一個
endpoint 健康」這個判斷邏輯,不管有沒有站台接上都恆真。

**根因**：C9 原本的檢查邏輯是「至少一個 StoreAPI 健康」，但沒有意識到
「中央自己的 Store Gateway」本身就是一個永遠存在的 StoreAPI endpoint,跟
「有沒有站台接上」是兩件事——這正是 `spec-driven-feature-workflow` skill
提醒的「只在 true-positive 狀態測過的檢查,不能證明它是真的檢查」。

**修法**：C9 改成專門檢查 `/api/v1/stores` 回應裡有沒有 `"sidecar":[`
這個 key——Thanos 把不同角色的 endpoint 分組在不同的 JSON key
（`sidecar`/`store`/`query`），只有真的有站台 Sidecar 連上時才會出現
`"sidecar"` 這個分組。修好後重測：零站台時 C9/C10 正確 fail（`pass=8
fail=2`），恢復站台後 C9/C10 正確變回 pass（`pass=10 fail=0`）。

### 測試基礎設施筆記（非 bug，見 §4）

`pilot vm-target run` 只餵單一 VM 自己的單主機 inventory，測
`thanos-query-apply.yml` 這種「讀 inventory group 做探索」的角色時，需要
手動組一份含多台 VM + `children` group 的暫存 inventory，直接用
`ansible-playbook -i <file>` 跑（見 §4）。

---

## 7. 收尾 Teardown

```bash
$ go run ./cmd/pilot vm-target down --name pt-central
$ go run ./cmd/pilot vm-target down --name pt-site-a
$ go run ./cmd/pilot vm-target down --name pt-s3
$ sudo rm -rf /var/lib/libvirt/images/pilot/pt-central \
              /var/lib/libvirt/images/pilot/pt-site-a \
              /var/lib/libvirt/images/pilot/pt-s3
```

---

## 8. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-14 | v1.1 | 更正舊版 `vm-target up` state-file race 說明：不同名稱 VM 現可平行建立；保留循序命令作為原始實測證據 | Codex |
| 2026-07-06 | v1.0 | 初版：`prometheus`/`thanos-query` 設計、apply playbook、spec、regression test、vm-target 三台 VM 實測（3 個真事故修好，見 §6），全局跨站查詢驗證成功 | sre |
