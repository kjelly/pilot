# Runbook — `seaweedfs-s3` (SeaweedFS S3-compatible object storage gateway)

> Status: **seaweedfs-s3.md 7/7 PASS on VM `s3` (192.168.123.2)**, idempotency
> confirmed (`pilot vm-target test` — apply → verify → re-apply changed=0).
> Single `chrislusf/seaweedfs:4.37` docker container running `weed server -s3`
> (master + volume + filer + S3 gateway in one process).

> 撰寫日期：2026-07-04 (UTC)
> 對齊規範：見 `docs/verification/seaweedfs-s3.md`
> 維護者：sre

---

## 0. 一句話目標

> 起一個 `weed server -s3` docker container，四個子服務（master 9333 /
> volume 8080 / filer 8888 / S3 API 8333）全部 `/healthz` 200，並用**沒有簽章**
> 的 path-style `curl PUT`/`GET` 證明 S3 API 真的可以寫入/讀回檔案——不需要
> `aws` CLI、不需要在 spec 裡放任何 access key / secret key。

---

## 0.5 事實快照（2026-07-04T12:06 — 7/7 PASS，idempotency 已驗證）

```bash
$ go run ./cmd/pilot vm-target list
NAME              STATUS   IP             VCPU  MEM(MiB)  DISK(GiB)  CREATED
s3                running  192.168.123.2  2     2048      30         2026-07-04

$ go run ./cmd/pilot vm-target show-inventory --name s3 | grep "^    [a-z]"
    s3:
    seaweedfs-s3:

$ go run ./cmd/pilot spec docs/verification/seaweedfs-s3.md --lint
spec Verification Spec — seaweedfs-s3 (SeaweedFS S3-compatible object storage gateway): 7 rows, 0 findings (0 errors)

$ go test -count=1 -run TestRegression_SeaweedfsS3Spec ./internal/spec/ -v
--- PASS: TestRegression_SeaweedfsS3Spec (0.01s)
ok  	github.com/anomalyco/pilot/internal/spec	0.080s
```

VM `s3` 只有兩個 host alias（`s3` 本體 + `seaweedfs-s3` sibling），跟
`docs/verification/seaweedfs-s3.md` §1 的 Targets table 一致 — 用
`-e target_group=seaweedfs-s3` 對到這台。

### 0.5.1 實際 end-to-end 結果（`pilot vm-target test` 一次跑完 apply → verify → idempotency）

```bash
# 前置：docker engine role（沒有的話 community.docker.docker_container 會直接失敗）
$ go run ./cmd/pilot vm-target run --name s3 \
      playbooks/apply/core-infra-provider-apply.yml \
      -e target_group=seaweedfs-s3 -e infra_role=docker
PLAY RECAP *********************************************************************
seaweedfs-s3               : ok=6   changed=2   unreachable=0   failed=0   skipped=13
#   - apt install docker.io
#   - docker service enable+start

# 一次跑完：L1 語法檢查 → snapshot → apply → verify → 再 apply 驗 idempotency
$ go run ./cmd/pilot vm-target test --name s3 \
      --playbook playbooks/apply/seaweedfs-s3-apply.yml \
      --spec docs/verification/seaweedfs-s3.md \
      --verify-timeout 40 \
      -- -e target_group=seaweedfs-s3

=== [Step 3/5] L4 Apply Playbook ===
PLAY RECAP *********************************************************************
seaweedfs-s3               : ok=9   changed=4   unreachable=0   failed=0   skipped=2
#   - mkdir /var/lib/pilot/seaweedfs (owner 1000:1000 — see §5)
#   - write /etc/pilot/seaweedfs-s3-check.txt
#   - docker run pilot-seaweedfs (server -s3 mode)
#   - weed shell: s3.bucket.create -name pilot-s3-smoke

=== [Step 4/5] L5 Verification Spec ===
✔ NDJSON:   .verification/seaweedfs-s3-20260704-120607.ndjson
✔ Report:   .verification/seaweedfs-s3-20260704-120607.md
verdict: **PASS**  (pass=7 fail=0 skip=0)

=== [Step 5/5] L6 Idempotency Check ===
PLAY RECAP *********************************************************************
seaweedfs-s3               : ok=8   changed=0   unreachable=0   failed=0   skipped=3
✓ Idempotency check passed (changed=0)
🎉 ALL TESTS PASSED SUCCESSFULLY!
```

最新 .verification 報告全文：

```
| ID | Status | Detail |
|----|--------|--------|
| C1 | pass | rc=0 matches expected 0 |
| C2 | pass | stdout contains "200" |
| C3 | pass | stdout contains "200" |
| C4 | pass | stdout contains "200" |
| C5 | pass | stdout contains "200" |
| C6 | pass | stdout contains "200" |
| C7 | pass | stdout contains "pilot-s3-smoke-check" |
```

---

## 1. 為什麼選這個設計（單一 container、匿名 S3）

### 1.1 單一 `weed server -s3` container，而不是 4 個獨立 container

SeaweedFS 官方支援 master / volume / filer / s3 各自獨立起（見
`docker/seaweedfs-compose.yml`），但那是給多機 cluster 用的拓樸。單機
sandbox 用 `weed server -s3` 一個 process 全包，跟 `keycloak-apply.yml`
單一 `pilot-keycloak` container 的簡化哲學一致——複雜度留給要真的 scale-out
的人。

### 1.2 預設匿名 S3（不掛 `-s3.config`）

實測 SeaweedFS 原始碼（`weed/s3api/auth_credentials.go`）：沒有 `-s3.config`
時「沒有 config file、沒有 identities」是官方定義的 **allow-all 匿名模式**
——連 `Authorization` header 都不用帶。這讓 spec C6/C7 可以用純 `curl`
做真正的 S3 讀寫驗證，不必在 spec 裡放 access key / secret key
（AGENTS.md 禁止密碼/token 進 spec），也不需要額外裝 `aws` CLI
（Ubuntu 24.04 `noble` 的 universe repo 其實**沒有** `awscli` 這個 apt
套件了——這是實測過程中撞到的第一個坑，見 §5）。

生產環境要開 identity 認證，走 `-e seaweedfs_s3_config_path=<s3.json>`；
apply playbook 對 `stage=prod` 有 `assert` 擋著，沒帶這個變數不給跑（見
`seaweedfs-s3-apply.yml` 的 `Gate: prod must not run with anonymous S3 access`）。
一旦掛上 identity 檔，C6/C7 這兩條匿名 smoke-test row 會因 403 fail——
這是**預期**行為，不是 regression（見 spec §5 已知偏差）。

---

## 2. Pipeline（apply 順序）

```bash
# 0. Lint
go run ./cmd/pilot spec docs/verification/seaweedfs-s3.md --lint

# 1. Generate verify playbook
go run ./cmd/pilot spec docs/verification/seaweedfs-s3.md \
    --generate playbooks/verify/seaweedfs-s3.yml

# 2. 確認 VM inventory 跟 spec 對齊
go run ./cmd/pilot vm-target show-inventory --name s3 | grep "^    [a-z]"
# 預期：s3 / seaweedfs-s3 都要在

# 3. Docker role（先行依賴）
go run ./cmd/pilot vm-target run --name s3 \
    playbooks/apply/core-infra-provider-apply.yml \
    -e target_group=seaweedfs-s3 -e infra_role=docker

# 4. SeaweedFS S3 role
go run ./cmd/pilot vm-target run --name s3 \
    playbooks/apply/seaweedfs-s3-apply.yml \
    -e target_group=seaweedfs-s3

# 5. Verify
go run ./cmd/pilot vm-target verify --name s3 \
    docs/verification/seaweedfs-s3.md
# verdict: **PASS**  (pass=7 fail=0 skip=0)
```

或直接用 `pilot vm-target test` 一次跑完 3 段（見 §0.5.1）。

---

## 3. Spec 對齊

| Spec ID | Apply task                                                              | 備註 |
|---------|--------------------------------------------------------------------------|------|
| C1      | `community.docker.docker_container: name=pilot-seaweedfs, state=started` | 容器內 `weed server` process → host `pidof weed` rc=0 |
| C2      | `-p 9333:9333`（master HTTP，`weed server` 預設值）                        | `curl :9333/healthz` → 200 |
| C3      | `-p 8080:8080`（volume HTTP，預設值）                                      | `curl :8080/healthz` → 200 |
| C4      | `-p 8888:8888`（filer HTTP；`-s3` 隱含開 filer）                            | `curl :8888/healthz` → 200 |
| C5      | `-p 8333:8333`（S3 API，預設值）+ apply 內建 30×2s readiness poll           | `curl :8333/healthz` → 200 |
| C6      | `weed shell: s3.bucket.create -name pilot-s3-smoke`                       | 匿名 `curl -X PUT` 寫入 `/pilot-s3-smoke/healthcheck.txt` → 200 |
| C7      | 同上（讀取同一個 bucket/key）                                              | 匿名 `curl GET` 內容吻合 `/etc/pilot/seaweedfs-s3-check.txt` |

四個 `/healthz` 是 SeaweedFS 原始碼裡四個子服務都各自註冊的**同名** route
（`weed/server/master_server.go` L172-173、`filer_server.go` L253-254、
`volume_server_handlers.go` L143、`weed/s3api/s3api_server.go` L738-739）——
比一開始猜測性想用的 `/cluster/status`（master 實際上**沒有**這個 route）
更可靠，寫 spec 前已用 `vm-target exec` 逐一 curl 確認過（見 §0.5.1）。

---

## 4. Rollback / 還原

- Container：`docker rm -f pilot-seaweedfs` 後重跑 `seaweedfs-s3-apply.yml`
- Data dir：`/var/lib/pilot/seaweedfs/`（bind mount）在 container 刪除後仍保留
- 完整 reset：`go run ./cmd/pilot vm-target rollback --name s3 --tag pre-apply`
  （或 `pilot vm-target test` 失敗時的 auto-rollback tag，例如
  `pre-test-<unix-ts>`）

---

## 5. 已知偏差 / 實測踩過的坑

| 問題 | 原因 | 修法 |
|------|------|------|
| Ubuntu 24.04 `noble` 沒有 `awscli` apt 套件 | AWS 把 CLI 打包方式改成官方 zip installer，`noble` universe 只剩零散的 `python3-aws*` 依賴套件，不含完整 CLI | 改用**不需要簽章的純 `curl`** 做 S3 PUT/GET（SeaweedFS 匿名模式下不驗證 Authorization header），完全不裝 `aws` CLI |
| container 內 `sh` 不支援 `/dev/tcp`（bash-ism） | `chrislusf/seaweedfs` image 的 `/bin/sh` 是 busybox ash，不是 bash | apply 的 S3 gateway readiness poll 跟 docker healthcheck 都改用 `curl -fsS http://127.0.0.1:8333/healthz`（container 內建 `curl`，本來就是 S3 gateway 自己會用的工具） |
| `ansible.builtin.file` 把 data dir 設 `owner=0` 導致**每次 apply 都 changed=1**（idempotency 測試 fail） | image 的 entrypoint 會把執行 `weed` 的使用者降權到 `seaweed`（uid=1000/gid=1000），啟動時把 bind-mount 目錄 chown 回 1000:1000，跟 apply 設的 `owner=0` 互相打架 | 把 `seaweedfs_host_data_dir` 的 owner/group 改成 **1000:1000**（跟 image 裡的 `seaweed` 使用者一致），不要跟 container 搶所有權 |
| `weed shell s3.bucket.create` 對已存在的 bucket 一樣印 `created bucket`、rc=0（不是 create-exclusive 語意） | filer 端把 bucket 當一般目錄用 `mkdir`-like 語意處理，沒有「已存在就報錯」這條路 | apply 先 `s3.bucket.list` 查一次，只有真的沒有才跑 `s3.bucket.create`，`changed_when` 才會在第二次 apply 正確回報 `false` |
| C6/C7 若 apply 換成掛 `-s3.config` identity 檔（prod 用）就會全部 fail | 兩條 row 走匿名、無簽章請求，一旦伺服器要求驗證身份，匿名請求直接 403 | 這是**設計上的預期行為**，不是 regression；上 prod 前把這兩條 row 視為「僅適用 sandbox」的已知例外（spec §5 已註記） |
| **任何會送簽章請求的 S3 client（`restic`、`aws` CLI、boto3…）對預設匿名模式一律失敗**，錯誤是 `Signed request requires setting up SeaweedFS S3 authentication`，跟上一列「匿名 client 對已加身份驗證的伺服器」剛好相反方向 | 匿名模式只接受**完全不帶簽章**的請求；一旦請求帶了 `Authorization: AWS4-HMAC-SHA256...` 表頭，SeaweedFS 會嘗試驗證卻找不到任何 identity 可比對，直接拒絕——跟「允許匿名」和「允許任何簽章」是兩件不同的事，本文件先前只驗證過純 `curl`（真正不簽章）這一種 client | 要接真正的 S3 SDK/CLI（包括 `restic`），必須掛 `-e seaweedfs_s3_config_path=<s3.json>`，且該 identity 的 access/secret key 要跟 client 端設定的一致。完整實測見 `docs/runbooks/restic-backup.md` §5（`restic` 對接這個 S3 gateway 的案例）|

---

## 6. 變更紀錄

| 日期       | 版本 | 變更 | 變更者 |
|------------|------|------|--------|
| 2026-07-04 | v1.0 | 初版：SeaweedFS S3 gateway spec + apply playbook，單一 `weed server -s3` container；vm-target `s3` 7/7 PASS，`pilot vm-target test` 全套（apply/verify/idempotency）跑過 | sre |
