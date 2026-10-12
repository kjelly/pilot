# Verification Spec — thanos-query (central Thanos Query + Store Gateway + Compactor)

> 版本：v1.3（2026-10-12：Compactor 分層保留 raw 30d / 5m 90d / 1h 90d，Query 啟用 auto-downsampling，見 §1.5、§6）
> 對齊規範：pilot 通用 container-backed 服務規範（比照 `seaweedfs-s3.md`/
> `keycloak.md` 的 docker container 模式）
> 維護者：sre

> 跟 `prometheus.md` 是一對「站台 / 中央」關係——本檔是**中央**彙總查詢
> 角色（`thanos-query` group，類比 `wazuh-manager`/`log-server`），
> `prometheus.md` 是**每個機房/站台**各自跑一份的角色（類比 `wazuh-fim`）。
> 跟既有的「central 是固定單一目標，agent 端填一個 `-e central_host` 變數」
> 模式方向相反：這裡是**中央主動找站台**——`thanos-query-apply.yml` 套用時
> 直接讀 Ansible inventory 的 `prometheus` group，自動組出每一站 Thanos
> Sidecar 的 StoreAPI 位址（`--store=<host>:10901`），不需要手動維護一份
> IP 清單變數。這是本專案目前唯一「中央自動探索多個站台」的角色；其餘
> central+agent 對子仍是「agent 端填中央 IP」的既有慣例。

## 1. 目標系統

| Hostname | Group         | Address | User | Port | IdentityFile |
|----------|---------------|---------|------|------|--------------|
| central  | thanos-query  |         |      |      |              |

> `thanos-query` group 是本檔預設目標。設計上只需要一台（跟 `wazuh-manager`/
> `log-server` 一樣是單一中央角色）。

## 1.5 依賴變數契約

在套用或驗證此主機時，Playbook 與變數參數必須嚴格遵守以下命名，禁止擅自縮寫或發明新變數：

| 變數名稱 | 說明/用途 | 是否必填 | 預設值 |
|---------|----------|---------|--------|
| `thanos_s3_target_host` | SeaweedFS S3 gateway（或其他 S3 endpoint）的 IP/FQDN；**必須跟 `prometheus.md` 那幾站指到同一個 S3 服務、同一個 bucket**，否則 Store Gateway 讀不到站台上傳的資料 | 否（見下方 escape hatch） | 空字串 |
| `thanos_s3_alias` | 上面那個 IP 對應的 `/etc/hosts` 別名 | 否 | `thanos-s3-backend` |
| `thanos_s3_port` | S3 gateway port | 否 | `8333` |
| `thanos_s3_bucket` | 存放 metrics TSDB blocks 的 bucket 名稱；**必須跟 `prometheus.md` 各站用同一個值** | 否 | `pilot-thanos-metrics` |
| `thanos_s3_endpoint` | 完整覆寫 S3 endpoint（`host:port`），跳過 `thanos_s3_alias` 的 `/etc/hosts` pin | 否 | `"{{ thanos_s3_alias }}:{{ thanos_s3_port }}"` |
| `thanos_aws_access_key_id` | S3 access key；必須跟各站 `prometheus.md` 用同一組憑證（同一個 SeaweedFS `s3.json` identity） | 是 | 無 |
| `thanos_aws_secret_access_key` | S3 secret key | 是 | 無 |
| `thanos_query_store_group` | 要自動探索的 Ansible inventory group 名稱（每個 host 視為一個站台，套用時讀 `hostvars[h].ansible_host` 組出 `--store=<ip>:10901`） | 否 | `prometheus` |
| `thanos_query_sidecar_grpc_port` | 各站 Thanos Sidecar 的 gRPC（StoreAPI）port | 否 | `10901` |
| `thanos_compact_retention_raw` | Compactor 保留 raw（原始 scrape 解析度）資料的期限（`--retention.resolution-raw`）；必須大於 40h，否則 Compactor 拒絕啟動 | 否 | `30d` |
| `thanos_compact_retention_5m` | Compactor 保留 5 分鐘降採樣資料的期限（`--retention.resolution-5m`）；必須大於 10d | 否 | `90d` |
| `thanos_compact_retention_1h` | Compactor 保留 1 小時降採樣資料的期限（`--retention.resolution-1h`） | 否 | `90d` |

> **`thanos_s3_target_host`/`thanos_s3_bucket` 跟 `prometheus.md` 共用同一組
> 變數名稱、同一個值**：這是刻意設計成一份 group_vars 契約可以同時套用給
> 兩邊角色（複製一份改 `-e`/host_vars 覆寫掉站台專屬的部份即可），而不是
> 各自發明一套命名，避免「central 填的 bucket 名跟站台不一致」這種只有跑到
> 全局查詢那一刻才會發現的隱性錯誤——見 §5 已知偏差。
>
> **分層保留與 `--query.auto-downsampling` 必須一起用**：Compactor 把超過
> 40 小時的 raw block 降採樣成 5m、超過 10 天的 5m block 降採樣成 1h，再依
> 三個 `thanos_compact_retention_*` 各自刪除過期的 block。預設 raw 30 天、
> 5m 與 1h 90 天：最近 30 天保留原始解析度，30–90 天只剩低解析度。
> 但 Store Gateway 只挑「解析度不粗於查詢的 `max_source_resolution`」的
> block，空缺只往**更細**的解析度補，不會退回更粗的；查詢沒帶這個參數時
> 只讀 raw（Thanos v0.36.1 `pkg/store/bucket.go` `getFor`、
> `pkg/api/query/v1.go` `parseDownsamplingParamMillis`）。所以 Thanos Query
> 一律帶 `--query.auto-downsampling`：range query 沒帶參數時以 `step / 5`
> 當作 `max_source_resolution`，Grafana 這類不帶參數的用戶端才查得到 raw
> 刪除後的資料。2026-10-12 在本機用 45 天的合成資料、同一版 image 實測：
> - 不帶參數時，raw 刪除後的時段（25 天前、40 天前）查詢結果是 0 點；
> - 開啟 auto-downsampling 後，25 天前、step 2h 的查詢由 5m block 回應；
> - instant query 不受影響，仍只讀 raw（`/api/v1/query` 看不到 30 天前的資料）。
>
> 限制：30–90 天前的資料只在 step 夠大（`step / 5 ≥ 5m`，即 step ≥ 25 分鐘；
> Grafana 約 1000 點寬的圖表對應時間範圍約 17 天以上）時查得到，把這段時間
> 放大到幾小時會是空白；`rate(x[5m])` 這種視窗小於兩個降採樣間隔的運算在
> 降採樣資料上也會是空的。需要放大檢視更舊的資料時，把
> `thanos_compact_retention_raw` 調長（三者相等就沒有這個限制，代價是
> object storage 用量增加）。
>
> **`thanos_query_store_group` 預設抓 `prometheus` group、不是寫死的 IP
> 清單**：套用時如果這個 group 是空的（`prometheus` 角色都還沒部署），
> playbook 仍會正常起 Thanos Query（只是 `--store` 清單只剩 Store
> Gateway 自己），C9（發現 StoreAPI up）跟 C10（全局查詢帶 site label）
> 在這個情境下预期 fail——不是 bug，是「站台還沒接上」的正常狀態，等
> 至少一個 `prometheus` 角色套用完、重新套用本 playbook 即可補上。

## 2. Checklist

| ID  | Category      | Check                                                            | Expected | Command |
|-----|---------------|-------------------------------------------------------------------|----------|---------|
| C1  | docker        | `pilot-thanos-query` container 存在且 running                      | ~pilot-thanos-query | docker ps --no-trunc 2>/dev/null | grep -m1 -oE 'pilot-thanos-query' | head -n1 |
| C2  | docker        | `pilot-thanos-store` container 存在且 running                      | ~pilot-thanos-store | docker ps --no-trunc 2>/dev/null | grep -m1 -oE 'pilot-thanos-store' | head -n1 |
| C3  | docker        | `pilot-thanos-compact` container 存在且 running                    | ~pilot-thanos-compact | docker ps --no-trunc 2>/dev/null | grep -m1 -oE 'pilot-thanos-compact' | head -n1 |
| C4  | http          | Thanos Query `/-/healthy`（10912）回 200                          | ~200 | curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:10912/-/healthy |
| C5  | http          | Thanos Query `/-/ready`（10912）回 200                            | ~200 | curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:10912/-/ready |
| C6  | http          | Thanos Store Gateway `/-/healthy`（10904）回 200                  | ~200 | curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:10904/-/healthy |
| C7  | http          | Thanos Compactor `/-/healthy`（10905）回 200                      | ~200 | curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:10905/-/healthy |
| C8  | object-storage | Thanos Store Gateway 可讀取 object storage bucket（`thanos tools bucket ls`） | 0 | sh -c 'docker exec pilot-thanos-store thanos tools bucket ls --objstore.config-file=/etc/thanos/objstore.yml >/dev/null 2>&1' |
| C9  | discovery     | Thanos Query 至少發現一個站台的 Thanos Sidecar（`sidecar` StoreAPI group）| 0 | sh -c 'curl -fsS http://127.0.0.1:10912/api/v1/stores | grep -q "\"sidecar\":\["' |
| C10 | query         | 全局查詢結果帶有 `site` label（證明跨站資料真的被彙總，不是只查中心自己） | 0 | sh -c 'curl -fsS "http://127.0.0.1:10912/api/v1/query?query=up" | grep -q "\"site\""' |
| C11 | config        | 執行中的 `pilot-thanos-compact` 對 raw、5m、1h 三種解析度都設了非零的保留期限（`--retention.resolution-*`） | 0 | sh -c 'a=$(docker inspect pilot-thanos-compact) || exit 1; for r in raw 5m 1h; do printf "%s\n" "$a" | grep -qE "\"--retention\.resolution-$r=[1-9][0-9a-z]*\"" || exit 1; done' |
| C12 | config        | 執行中的 `pilot-thanos-query` 帶 `--query.auto-downsampling`（不帶參數的 range query 才查得到 raw 刪除後的降採樣資料） | 0 | sh -c 'docker inspect pilot-thanos-query | grep -qF "\"--query.auto-downsampling\""' |
| C13 | object-storage | Thanos Store Gateway 已從 object storage 載入至少一個 block（`thanos_bucket_store_blocks_loaded` > 0） | 0 | sh -c 'm=$(curl -fsS http://127.0.0.1:10904/metrics) && printf "%s\n" "$m" | grep -qE "^thanos_bucket_store_blocks_loaded [1-9]"' |

> C9/C10 需要至少一個 `prometheus` 角色已經套用完成才會 pass；純中央
> 單獨套用時這兩行預期 fail，屬正常狀態（見 §1.5、§5）。
> C10 不檢查 site label 的**值**（值是部署時才知道的站名，spec 的
> Command/Expected 欄位是固定字串、不能內插），只檢查全局查詢結果**帶有
> 這個 label key**——證明「這筆資料是透過 Thanos 的跨站 label 機制查出來
> 的」，而不是 Thanos Query 自己開一個沒有意義的空查詢。

## 3. 證據收集

- 工具：`pilot verify docs/verification/thanos-query.md -i <inventory> -l thanos-query`
- 輸出格式：`.verification/thanos-query-<UTC>.{ndjson,md}`
- 預期 row 數：13

## 4. PASS / FAIL 規則

- C1–C13 全部 `status=pass` → **PASS**：中央 Thanos Query 已就緒，至少一個站台的資料已經可以被全局查詢查到，Store Gateway 已載入站台上傳的歷史 block，保留期限與降採樣查詢都已生效
- C1–C8、C11、C12 pass 但 C9/C10/C13 fail → 中央本身健康，只是還沒有任何站台接上或上傳過 block（見 §1.5、§5）——不算全局查詢功能損壞，但也不能算「全局查詢已驗證」
- 任一 C1–C8、C11、C12 fail → **FAIL**，常見修法：
  - C1–C3 fail → container 沒起；`docker ps -a` / `docker logs pilot-thanos-query` / `pilot-thanos-store` / `pilot-thanos-compact`
  - C4/C5 fail → Query 啟動參數有誤（例如 `--store` 清單語法錯）；`docker logs pilot-thanos-query`
  - C6/C7 fail → Store/Compact 連不到 object storage；檢查 objstore 設定與憑證
  - C8 fail → S3 憑證/bucket 有誤，或 bucket 尚未預先建立
  - C9 fail → 檢查 inventory 的 `prometheus` group 是否為空、各站 Thanos Sidecar 的 10901 是否對中央開放（防火牆/security group）
  - C10 fail → C9 若已 pass，通常是站台的 `prometheus_site_label` 沒設好（見 `prometheus.md` C8），或兩邊 `thanos_s3_bucket` 不一致
  - C11 fail → Compactor 沒帶保留期限，或某個 `thanos_compact_retention_*` 被設成 `0d`（永久保存）；`docker inspect pilot-thanos-compact` 看實際參數。Compactor 拒絕啟動時（raw ≤ 40h 或 5m ≤ 10d）C3/C7 也會 fail，`docker logs pilot-thanos-compact` 會說明
  - C12 fail → Query 沒帶 `--query.auto-downsampling`；Grafana 查不到 raw 保留期限之前的資料
  - C13 fail → 先看各站 `prometheus.md` C21/C22（Sidecar 有沒有真的上傳）；站台已有 block 時，檢查兩邊 `thanos_s3_bucket` 是否一致、`docker logs pilot-thanos-store`

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C9, C10 | `prometheus` group 尚無任何主機套用完成時，這兩行預期 fail | 站台尚未部署的環境 | 直到至少一站 `prometheus.md` PASS 為止 |
| C13 | 站台的第一個 block 要在 Prometheus 啟動後大約 3 小時才會上傳（見 `prometheus.md` §5 C22），Store Gateway 預設每 15 分鐘同步一次 bucket（`--sync-block-duration=15m`）；全新環境在這之前本行預期 fail | 剛部署、站台尚未上傳任何 block 的環境 | 直到至少一站 `prometheus.md` C22 PASS 為止 |
| C8 | SeaweedFS 不會自動生出不存在的 bucket，套用前需手動 `weed shell` 建好 `thanos_s3_bucket`（跟 `restic-backup.md` §5 Bug 5 同一個坑） | SeaweedFS 目的地 | 無（預建 bucket 是常態操作） |

## 6. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-06 | v1.0 | 初版 | sre |
| 2026-07-17 | v1.1 | 修正 C4/C5/C9/C10：`thanos-query-apply.yml` 的 `thanos_query_http_port` 早已預設改成 `10912`（避開跟站台 Thanos Sidecar 的 10902 collide），本規格的 checklist command 沒跟著更新，導致這 4 條在真實環境上必定 fail（`curl` 打 10902 拿到 000/connection refused）。`docs/runbooks/metrics-alerting.md` 整併重測時發現。若套用時有覆寫 `-e thanos_query_http_port=<其他值>`，這 4 條也要跟著改 | sre |
| 2026-08-28 | v1.2 | Detection Engine Stage A-0（見 `docs/superpowers/specs/2026-08-28-detection-engine-spec.md` §9/§57）：`contracts/thanos-query.yaml` 的 `query` endpoint 一直沒跟著 v1.1 這次修正同步，仍宣告 port `10902`（跟本檔實際驗證的 `10912` 不一致，一個下游 consumer contract 若照著 `contracts/thanos-query.yaml` 綁定會連錯 port）；已修正成 `10912` 並補上 `internal/spec/thanos_query_regression_test.go` 的 `TestRegression_ThanosQueryContractQueryEndpointIs10912` 鎖住。本檔 checklist 本身不變 | sre |
| 2026-10-12 | v1.3 | 新增 C11–C13 與 `thanos_compact_retention_raw`/`_5m`/`_1h`（預設 30d/90d/90d），Query 啟用 `--query.auto-downsampling`。需求是保存 90 天的資料、越舊的解析度可以越低。原本 Compactor 沒有保留期限（永久保存），而且各站 Sidecar 從未上傳成功（見 `prometheus.md` v1.6），Store Gateway 載入 0 個 block，C8 只檢查讀得到 bucket 所以沒抓到；C13 改為檢查 Store 真的載入了 block。分層保留只靠 Compactor 不夠：查詢沒帶 `max_source_resolution` 時只讀 raw，raw 刪除後的時段會是空的（本機實測，見 §1.5），所以 Query 必須開 auto-downsampling | pilot |
