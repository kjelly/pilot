# Verification Spec — prometheus (per-site Prometheus + Thanos Sidecar)

> 版本：v1.0
> 對齊規範：pilot 通用 container-backed 服務規範（比照 `seaweedfs-s3.md`/
> `keycloak.md` 的 docker container 模式）
> 維護者：sre

> 跟 `thanos-query.md` 是一對「站台 / 中央」關係——本檔是**每個機房/站台**
> 各自跑一份的角色（`prometheus` group，類比 `wazuh-fim`），`thanos-query.md`
> 是**中央**彙總查詢角色（類比 `wazuh-manager`/`log-server`）。跟既有的
> 「agent 端填一個 central_host 變數」模式不同：這裡是**反向關係**——本角色
> 完全不需要知道中央在哪裡（Thanos Sidecar 只被動等中央的 Thanos Query 來
> 連），站台可以在中央還沒部署前就先獨立運作、獨立寫入/查詢本機資料。

## 1. 目標系統

| Hostname   | Group        | Address | User | Port | IdentityFile |
|------------|--------------|---------|------|------|--------------|
| site-a     | prometheus   |         |      |      |              |
| site-b     | prometheus   |         |      |      |              |

> `prometheus` group 是本檔預設目標。同一個 group 底下可以有多台主機，各自
> 代表不同機房/站台——`prometheus_site_label`（見 §1.5）就是用來讓
> `thanos-query.md` 的全局查詢分得出資料來自哪一站。

## 1.5 依賴變數契約

在套用或驗證此主機時，Playbook 與變數參數必須嚴格遵守以下命名，禁止擅自縮寫或發明新變數：

| 變數名稱 | 說明/用途 | 是否必填 | 預設值 |
|---------|----------|---------|--------|
| `prometheus_site_label` | 這個站台的識別名稱，寫進 Prometheus `external_labels.site`；`thanos-query.md` 的全局查詢靠這個欄位分辨資料來源站台 | 是 | 無（空字串會被 gate 擋下） |
| `thanos_s3_target_host` | 備份目的地 SeaweedFS S3 gateway（或其他 S3 endpoint）的 IP/FQDN；套用時 pin 進 `/etc/hosts` 的 `thanos_s3_alias` 別名 | 否（見下方 escape hatch） | 空字串 |
| `thanos_s3_alias` | 上面那個 IP 對應的 `/etc/hosts` 別名，Thanos objstore 設定一律指向這個別名 | 否 | `thanos-s3-backend` |
| `thanos_s3_port` | S3 gateway port | 否 | `8333` |
| `thanos_s3_bucket` | 存放 metrics TSDB blocks 的 bucket 名稱；**必須跟 `thanos-query.md` 那台用同一個值**，否則中央讀不到這一站上傳的資料 | 否 | `pilot-thanos-metrics` |
| `thanos_s3_endpoint` | 完整覆寫 S3 endpoint（`host:port`），跳過 `thanos_s3_alias` 的 `/etc/hosts` pin，改指向外部/獨立 S3 | 否 | `"{{ thanos_s3_alias }}:{{ thanos_s3_port }}"` |
| `thanos_aws_access_key_id` | S3 access key；一律用 vault 帶入，不進版控（拋棄式沙盒測試除外） | 是 | 無 |
| `thanos_aws_secret_access_key` | S3 secret key | 是 | 無 |
| `prometheus_scrape_interval` | 全域 scrape 間隔 | 否 | `15s` |
| `prometheus_retention_time` | 本機 TSDB 保留時間（上傳到 S3 之後，本機這份可以被裁掉；保留時間只是給 Thanos Sidecar 上傳留緩衝） | 否 | `6h` |
| `prometheus_scrape_configs` | 完整覆寫 `scrape_configs:` 區塊內容（多行字串，可依主機覆寫成不同的 scrape job） | 否 | 只 scrape 自己（`localhost:9090`） |

> **為何 `prometheus_site_label` 是必填、跟 `wazuh_manager_host` 不一樣**：
> `wazuh_manager_host`/`siem_forward_host` 空著時還有「純本機」意義（本機
> FIM/稽核規則照常生效，只是不轉送）；`prometheus_site_label` 空著卻沒有
> 合理預設——外部標籤本來就是「每一站不同」的值，寫死一個預設（例如
> `"default"`）會讓多站真的部署下去時，第二站忘記覆寫就悄悄跟第一站標籤
> 撞名、Thanos Query 端會把兩站資料錯誤地當成同一個 replica 去重疊，而不是
> 顯式失敗。所以直接 gate 擋下，強迫每次套用都要想清楚這一站的名字。
>
> **為何 `thanos_s3_bucket` 沒有 gate 檢查兩邊是否一致**：spec 的驗證範圍
> 只到「這台主機自己能不能讀寫這個 bucket」（C9）；「central 是否真的用
> 同一個 bucket」屬於部署時的人工契約（跟兩份 group_vars 檔案要填同一個
> 值一樣），會在 `thanos-query.md` C9/C10（發現 StoreAPI + 全局查詢帶
> site label）間接曝露出來——如果兩邊 bucket 不同，中央的 Store Gateway
> 永遠讀不到這一站上傳的歷史資料。

## 2. Checklist

| ID  | Category      | Check                                                     | Expected | Command |
|-----|---------------|------------------------------------------------------------|----------|---------|
| C1  | docker        | `pilot-prometheus` container 存在且 running                  | ~pilot-prometheus | docker ps --no-trunc 2>/dev/null | grep -m1 -oE 'pilot-prometheus' | head -n1 |
| C2  | docker        | `pilot-thanos-sidecar` container 存在且 running               | ~pilot-thanos-sidecar | docker ps --no-trunc 2>/dev/null | grep -m1 -oE 'pilot-thanos-sidecar' | head -n1 |
| C3  | http          | Prometheus `/-/healthy`（9090）回 200                        | ~200 | curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:9090/-/healthy |
| C4  | http          | Prometheus `/-/ready`（9090）回 200                          | ~200 | curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:9090/-/ready |
| C5  | http          | Thanos Sidecar `/-/healthy`（10902）回 200                   | ~200 | curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:10902/-/healthy |
| C6  | http          | Thanos Sidecar `/-/ready`（10902）回 200                     | ~200 | curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:10902/-/ready |
| C7  | metrics       | Prometheus 自我 scrape 成功（`up{job="prometheus"}==1`）       | ~"1"] | curl -fsS 'http://127.0.0.1:9090/api/v1/query?query=up' | grep -o '"value":\[[0-9.]*,"1"\]' |
| C8  | config        | `prometheus.yml` 已設定 `external_labels.site`               | 0 | sh -c 'grep -qE "^\s*site:" /etc/pilot/prometheus/prometheus.yml' |
| C9  | object-storage | Thanos Sidecar 可讀取 object storage bucket（`thanos tools bucket ls`） | 0 | sh -c 'docker exec pilot-thanos-sidecar thanos tools bucket ls --objstore.config-file=/etc/thanos/objstore.yml >/dev/null 2>&1' |

> C7 只驗證「Prometheus 有沒有成功 scrape 到至少一個 target」，不綁定
> 特定 job 名稱字面值以外的東西——`up` 查詢不加 label matcher，因為
> `prometheus_scrape_configs` 允許逐站覆寫成不同 job，這條 row 要對任何
> 覆寫都成立。
> C9 直接呼叫 sidecar container 內建的 `thanos` binary 做一次 bucket
> list，不靠等 2 小時 TSDB block 真的上傳（Thanos 預設 `--tsdb.path` 的
> block 上傳週期跟 `--storage.tsdb.min-block-duration` 掛鉤，等一個真實
> block 週期才能驗證「有沒有真的上傳過東西」不切實際）——這條只驗證
> 「object storage 這一段的連線/認證是通的」，「有沒有真的搬過資料」交給
> `thanos-query.md` C10（全局查詢帶 site label）間接證明。

## 3. 證據收集

- 工具：`pilot verify docs/verification/prometheus.md -i <inventory> -l prometheus`
- 輸出格式：`.verification/prometheus-<UTC>.{ndjson,md}`
- 預期 row 數：9

## 4. PASS / FAIL 規則

- C1–C9 全部 `status=pass` → **PASS**：這一站的 Prometheus + Thanos Sidecar 已就緒，本機監控 + 上傳鏈路都通
- 任一 fail → **FAIL**，常見修法：
  - C1/C2 fail → container 沒起；`docker ps -a` / `docker logs pilot-prometheus` / `docker logs pilot-thanos-sidecar`
  - C3/C4 fail → Prometheus 還沒 ready 或設定檔有誤；`docker logs pilot-prometheus`
  - C5/C6 fail → Sidecar 連不到 Prometheus（`--prometheus.url` 錯）或連不到 object storage；`docker logs pilot-thanos-sidecar`
  - C7 fail → scrape 設定有誤或 target 打不到；檢查 `prometheus_scrape_configs`
  - C8 fail → `prometheus_site_label` 沒有正確渲染進設定檔
  - C9 fail → S3 憑證/bucket 有誤，或 bucket 尚未預先建立（見 §5）

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C9 | SeaweedFS 不會自動生出不存在的 bucket，套用前需手動 `weed shell` 建好 `thanos_s3_bucket`（跟 `restic-backup.md` §5 Bug 5 同一個坑），否則本行 fail 且 sidecar log 會顯示 retry | SeaweedFS 目的地 | 無（預建 bucket 是常態操作） |

## 6. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-06 | v1.0 | 初版 | sre |
