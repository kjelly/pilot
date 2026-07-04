# Verification Spec — seaweedfs-s3 (SeaweedFS S3-compatible object storage gateway)

> 版本：v1.1
> 對齊規範：pilot 通用 container-backed 服務規範（比照 `keycloak.md` 的單一
> docker container 模式；SeaweedFS `weed server -s3` 一個 process 同時起
> master + volume + filer + S3 gateway）
> 維護者：sre

## 1. 目標系統

| Hostname | Group         | Address | User | Port | IdentityFile |
|----------|---------------|---------|------|------|--------------|
| s3       | seaweedfs-s3  |         |      |      |              |

> `seaweedfs-s3` group 是本檔預設目標。單一 docker container
> `pilot-seaweedfs` 對外開 4 個 port：master 9333 / volume 8080 /
> filer 8888 / S3 API 8333（皆為 SeaweedFS 官方預設值）。

## 2. Checklist

| ID | Category | Check                                                              | Expected | Command |
|----|----------|---------------------------------------------------------------------|----------|---------|
| C1 | process  | `weed server` process 可見                                          | 0        | sh -c 'pidof weed >/dev/null 2>&1; echo $?' |
| C2 | http     | Master HTTP `/healthz`（9333）回 200                                 | ~200     | curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:9333/healthz |
| C3 | http     | Volume HTTP `/healthz`（8080）回 200                                 | ~200     | curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/healthz |
| C4 | http     | Filer HTTP `/healthz`（8888）回 200                                  | ~200     | curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:8888/healthz |
| C5 | http     | S3 gateway HTTP `/healthz`（8333）回 200                             | ~200     | curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:8333/healthz |
| C6 | s3       | S3 API 可匿名 PUT object 到預建 bucket（path-style `PUT /bucket/key`） | ~200     | curl -fsS -X PUT --data-binary @/etc/pilot/seaweedfs-s3-check.txt -o /dev/null -w '%{http_code}' http://127.0.0.1:8333/pilot-s3-smoke/healthcheck.txt |
| C7 | s3       | S3 API 可匿名 GET 回同一個 object，內容吻合                            | ~pilot-s3-smoke-check | curl -fsS http://127.0.0.1:8333/pilot-s3-smoke/healthcheck.txt |
| C8 | s3       | S3 API 可匿名 DELETE object，刪後 GET 回 404                         | ~404     | sh -c 'curl -fsS -X DELETE -o /dev/null -w "%{http_code}" http://127.0.0.1:8333/pilot-s3-smoke/healthcheck.txt && curl -fsS -o /dev/null -w "%{http_code}" http://127.0.0.1:8333/pilot-s3-smoke/healthcheck.txt' |

> C1 用 `pidof weed`（不是 `pgrep`）：`weed server` 單一 binary 同時扮演
> master/volume/filer/s3 四個角色，`pgrep -f` 容易誤中 ansible 自己的
> shell 命令列。
> C2–C5 四個 `/healthz` 是 SeaweedFS 內建、四個子服務都有的統一 endpoint
> （`weed/server/master_server.go` / `filer_server.go` / `volume_server_handlers.go`
> / `weed/s3api/s3api_server.go` 都註冊了 `/healthz`），比猜測性的
> `/cluster/status`（SeaweedFS master 其實沒有這個 route）更可靠。
> C6–C8 直接用**沒有簽章**的 path-style `curl PUT`/`GET`/`DELETE`：apply
> playbook **預設不啟用** `-s3.config` identity 檔（見 §5 已知偏差），SeaweedFS
> 官方文件定義「沒有 config file、沒有 identities」時是 allow-all 匿名模式——
> 連 Authorization header 都不必帶，所以不需要在 spec 裡放 access key /
> secret key（AGENTS.md 禁止 spec 內夾帶密碼/token），也不必依賴 `aws`
> CLI（target host 不用額外裝套件）。
> C8 同一個 shell 行內串接 DELETE + GET：DELETE 預期 ~204、GET 在刪除後預期
> ~404；兩個都成功才算整 row pass。

## 3. 證據收集

- 工具：`pilot verify docs/verification/seaweedfs-s3.md -i <inventory> -l seaweedfs-s3`
- 輸出格式：`.verification/seaweedfs-s3-<UTC>.{ndjson,md}`
- 預期 row 數：8

## 4. PASS / FAIL 規則

- C1–C8 全部 `status=pass` → **PASS**：S3 server 已就緒，完整 CRUD 可用（寫入/讀取/刪除）
- 任一 fail → **FAIL**，常見修法：
  - C1 fail → container 沒起；`docker ps -a` / `docker logs pilot-seaweedfs`
  - C2–C5 fail → 對應子服務還沒 ready（`weed server` 啟動需數秒 volume
    先向 master 註冊完才會全綠）；先看 C1 是否 pass，再等幾秒重試
  - C6 fail → bucket `pilot-s3-smoke` 沒建好（apply 的 `weed shell
    s3.bucket.create` 沒跑成功）
  - C7 fail → C6 沒先 PASS（bucket 裡沒有這個 key），或 filer 資料層異常
  - C8 fail → DELETE 回的不是 204，或 DELETE 後 GET 不是 404（可能 object
    根本没被 C6 寫入、或 DELETE 後 filer metadata 沒即時更新）

## 5. 例外與已知偏差

| ID      | 例外內容                                                                                       | 適用環境 | 期限 |
|---------|------------------------------------------------------------------------------------------------|---------|------|
| C6–C8   | 預設不掛 `-s3.config` identity 檔，S3 API 對任何 access key（甚至完全不簽章）全部視為匿名 admin  | sandbox | 上 staging/prod 前必須改掛 `seaweedfs_s3_config_path`（vault 提供的 s3.json），屆時 C6–C8 這三條 anonymous smoke-test row 會因 403 fail——預期行為，需另外用帶簽章的探測或調整 bucket policy |
| C2–C5   | container 剛起時 volume/filer 可能還沒向 master 完成註冊，`/healthz` 短暫非 200                  | 任何    | apply 已加 30×2s 的 S3 gateway readiness poll，仍建議 verify 前等 5–10s |

## 6. 變更紀錄

| 日期       | 版本 | 變更 | 變更者 |
|------------|------|------|--------|
| 2026-07-04 | v1.0 | 初版：SeaweedFS S3 gateway spec，單一 `weed server -s3` container，7 rows | sre |
| 2026-07-04 | v1.1 | C8 DELETE：驗證 S3 API 可匿名刪除 object，補上 CRUD 最後一環；同步更新 §3 row count、§4 PASS 規則、§5 例外 ID、changelog | sre |
