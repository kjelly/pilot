# Runbook — Detection Engine（中央 adaptive anomaly detection plane）

> 完整規格：`docs/superpowers/specs/2026-08-28-detection-engine-spec.md`
> 架構概覽：`docs/architecture/detection-plane.md`
> 驗證 spec：`docs/verification/detection-engine.md`（C1-C12）

## 0. 目標與資料流

Detection Engine（`pilot-detection-engine`）從中央 Thanos Query 讀取 Prometheus
metrics，用 robust-baseline-v1 + cohort-outlier-v1 兩個統計偵測器算出每台受管
主機的 adaptive anomaly score，達到門檻時建立 SignalEvent 並透過 SQLite outbox
送到中央 Alertmanager。Stage A（本輪落地範圍）Model Provider 永遠 disabled。

依賴鏈：`host-monitoring`（sameHosts，只借用 textfile collector 發布自己的
健康指標）、`thanos-query`（providerEndpoint，`:10912`，永不 `:10902`）、
`alertmanager`（providerEndpoint，`:9093`）。

## 1. §0.5 事實快照（2026-08-28T03:49–04:05 UTC，Stage A-2 實跑）

```
$ go run ./cmd/pilot vm-target list（測試前）
(no targets)
```

三台新建 vm-target，全部 Ubuntu 24.04：

| 角色 | target 名稱 | IP | 套用內容 |
|---|---|---|---|
| 被監控主機 | `monitored-subject-1` | 192.168.122.2 | `host-monitoring` |
| 站台 Prometheus | `prom-site` | 192.168.122.3 | `docker` + `prometheus`（auto-discover `monitored-subject-1`） |
| 中央 | `detect-central` | 192.168.122.4 | `host-monitoring` + `docker` + `alertmanager` + `thanos-query` + `detection-engine` |

Tested revision：Stage A-2 工作樹（本次改動涵蓋
`playbooks/apply/{detection-engine,host-monitoring}-apply.yml`、
`internal/detection/episode.go`、`cmd/pilot-detection-engine/main.go`、
contract/inventory/catalog/deploy_catalog/MCP diagnose 全套，詳見對應 commit）。

**對齊決策**：`detection_metrics_source_host`/`detection_alertmanager_target_host`
皆設為 `127.0.0.1`——thanos-query/alertmanager 與 detection-engine 同機
（`detect-central`），這是本次驗證刻意選擇的拓樸簡化（單一中央節點扮演三個
角色），不影響 §51 要驗證的身分鏈路本身。S3 全程使用假位址
（`203.0.113.1:9000`）——本輪目的是驗證 `pilot_host`/`site` 身分鏈路與
Detection Engine 自身的部署/生命週期，不是 Thanos object storage 上傳鏈路
（那條路徑由 `docs/runbooks/metrics-alerting.md` 用真實 SeaweedFS 涵蓋）。

## 2. 部署鏈（實際指令 + 真實輸出）

```bash
go run ./cmd/pilot vm-target up --name monitored-subject-1 --ssh-user ubuntu \
    --disk 20 --memory 2048 --vcpus 2 --ssh-timeout 8m --boot-timeout 8m --services local
go run ./cmd/pilot vm-target run --name monitored-subject-1 --skip-lint \
    playbooks/apply/host-monitoring-apply.yml -e target_group=monitored-subject-1 \
    -e node_exporter_basic_auth_password=<password>
# PLAY RECAP: ok=28 changed=11 failed=0

go run ./cmd/pilot vm-target up --name prom-site ... (同上規格)
go run ./cmd/pilot vm-target run --name prom-site --skip-lint playbooks/apply/docker-apply.yml -e target_group=prom-site
go run ./cmd/pilot vm-target run \
    --group host-monitoring=monitored-subject-1 --group prometheus=prom-site --skip-lint \
    playbooks/apply/prometheus-apply.yml -e target_group=prometheus \
    -e prometheus_site_label=real-lane-site -e thanos_s3_endpoint=203.0.113.1:9000 \
    -e thanos_aws_access_key_id=fakekey -e thanos_aws_secret_access_key=fakesecret \
    -e alertmanager_target_host=192.168.122.4 \
    -e node_exporter_basic_auth_password=<同一組password>
# PLAY RECAP: ok=38 changed=10 failed=0

go run ./cmd/pilot vm-target up --name detect-central ... (4096 MiB, 30 GiB)
go run ./cmd/pilot vm-target run --name detect-central --skip-lint playbooks/apply/host-monitoring-apply.yml -e target_group=detect-central -e node_exporter_basic_auth_password=<同一組password>
go run ./cmd/pilot vm-target run --name detect-central --skip-lint playbooks/apply/docker-apply.yml -e target_group=detect-central
go run ./cmd/pilot vm-target run --name detect-central --skip-lint playbooks/apply/alertmanager-apply.yml -e target_group=detect-central
go run ./cmd/pilot vm-target run --name detect-central \
    --group prometheus=prom-site --group thanos-query=detect-central --skip-lint \
    playbooks/apply/thanos-query-apply.yml -e target_group=thanos-query \
    -e thanos_s3_target_host=203.0.113.1 -e thanos_s3_endpoint=203.0.113.1:9000 \
    -e thanos_aws_access_key_id=fakekey -e thanos_aws_secret_access_key=fakesecret
# 全部 PLAY RECAP failed=0
```

**§51 real metrics-chain 中間查核**（部署 detection-engine 前）：

```bash
$ go run ./cmd/pilot vm-target exec --name detect-central -- curl -fsS 'http://127.0.0.1:10912/api/v1/query?query=up'
{"status":"success","data":{"resultType":"vector","result":[
{"metric":{"__name__":"up","instance":"192.168.122.2:9100","job":"node","pilot_host":"monitored-subject-1","site":"real-lane-site"},...},
{"metric":{"__name__":"up","instance":"localhost:9090","job":"prometheus","site":"real-lane-site"},...}
]}}
```

`pilot_host=monitored-subject-1`（真實 inventory hostname）與
`site=real-lane-site` 同時出現在**中央** Thanos Query——鏈路成立，才繼續佈署
Detection Engine 本身。

## 3. 部署 Detection Engine

```bash
go run ./cmd/pilot scripts/build-detection-engine.sh   # 產生 dist/ + sha256
go run ./cmd/pilot vm-target run --name detect-central \
    --group host-monitoring=detect-central --group thanos-query=detect-central \
    --group alertmanager=detect-central --group detection-engine=detect-central \
    --skip-lint playbooks/apply/detection-engine-apply.yml -e target_group=detection-engine \
    -e detection_engine_artifact_path=dist/pilot-detection-engine-linux-amd64 \
    -e detection_engine_artifact_sha256=<sha256> \
    -e detection_metrics_source_host=127.0.0.1 -e detection_alertmanager_target_host=127.0.0.1
```

### 3.1 實跑中發現並修好的真 bug（4 個）

| # | 現象 | 根因 | 修法 |
|---|---|---|---|
| 1 | `detection-engine-apply.yml` 的「host-monitoring textfile 目錄存在」preflight gate 直接 fail，即使 `host-monitoring-apply.yml` 剛套用成功 | `host-monitoring-apply.yml` 從來沒真的啟用 textfile collector——`ExecStart` 沒有 `--collector.textfile.directory`，`/var/lib/node_exporter` 根本不存在。spec 假設它已經存在，但實際程式碼沒有 | `host-monitoring-apply.yml` 新增 `node_exporter_textfile_dir`（預設 `/var/lib/node_exporter/textfile`，mode `1777` sticky bit）+ 對應 `ExecStart` flag；新增 `docs/verification/host-monitoring.md` C11（v1.3） |
| 2 | `status.json`/textfile metrics 的 `subjects.active`/`pilot_detection_subjects_total` 永遠是 0，即使真的偵測到 1 個 subject | `cmd/pilot-detection-engine/main.go` 的 `runServe` 從來沒有把 `engine.RunCycle()` 回傳的 `outcomes` 灌回 `Status.Subjects`/`MetricsSnapshot.SubjectsTotal`——欄位存在但沒人賦值 | 補上賦值邏輯（`len(outcomes)`），並從 `store.ListActiveEpisodes()` 灌 `Signals.Active` |
| 3 | 第二次以上的 upgrade（binary 內容真的改變）觸發 rollback：`db backup` 失敗 `SQL logic error: output file already exists` | SQLite 的 `VACUUM INTO` 拒絕覆寫已存在的檔案，但 spec §26 的 `pre-upgrade.db` 是固定檔名、每次 upgrade 都要用同一個路徑 | `db backup` 子指令在 `VACUUM INTO` 前先 `os.Remove` 舊檔（存在才刪，`os.IsNotExist` 視為正常）。**正確驗證了 rollback 機制本身**：這次失敗時 playbook 自己的 rescue 區塊正確地把 binary/DB 復原、重啟舊版本、服務恢復 healthy，才 fail 出來保留證據——rollback 設計本身沒有問題，問題只在被回滾的那個新 binary 的 backup 指令上 |
| 4 | `pilot-detection-engine signals list --db ...` 在沒有任何 episode 時輸出 `null`，不是 `[]` | Go 的 `var out []EpisodeRecord` 在 `append` 從未被呼叫時是 nil slice，`json.Marshal(nil)` 產生 `null` | `ListActiveEpisodes` 改成 `out := []EpisodeRecord{}`，新增 `TestStore_ListActiveEpisodesJSONMarshalsEmptyAsArray` 鎖住 |

### 3.2 真實輸出：完整 apply（第一次，含 upgrade rollback 插曲）

```
PLAY RECAP: detect-central : ok=46 changed=10 failed=0   # subjects.active 修好前
```

修好 bug #2 後 rebuild+redeploy（binary sha256 從
`905c353e...` 變成 `659345ac...`，觸發真正的 upgrade path）：

```
PLAY RECAP: detect-central : ok=47 changed=4 failed=0
```

（這次 upgrade 也是第一次撞到 bug #3——`db backup` 因為第一次 upgrade
留下的 `pre-upgrade.db` 而失敗；rollback 正確復原到修 bug #2 前的舊 binary，
`journalctl`/`systemctl is-active` 確認服務仍 healthy，只是行為退回舊版；
修好 bug #3 後乾淨重跑一次成功。）

最終乾淨 apply（bug #4 也修好後，binary sha256 `65de8b70...`）：

```
PLAY RECAP: detect-central : ok=47 changed=4 failed=0
```

### 3.3 冪等重跑

```
PLAY RECAP: detect-central : ok=44 changed=0 failed=0
```

## 4. §51 real metrics-chain 最終證據

```bash
$ go run ./cmd/pilot vm-target exec --name detect-central -- sudo /usr/local/bin/pilot-detection-engine status --json
{
  "schema_version": 1,
  "state": "healthy",
  "source": {"healthy": true},
  "subjects": {"active": 1},
  "model_provider": {"enabled": false, "healthy": false, "protocol": "", "circuit": "closed"},
  "signals": {"active": 0},
  "last_cycle": {"success": true}
}

$ go run ./cmd/pilot vm-target exec --name detect-central -- sudo cat /var/lib/node_exporter/textfile/pilot_detection_engine.prom
pilot_detection_engine_up 1
pilot_detection_cycle_duration_seconds 0.068254743
pilot_detection_cycle_overrun_total 0
pilot_detection_last_success_timestamp_seconds 1787889660
pilot_detection_subjects_total 1
pilot_detection_model_provider_up 0
pilot_detection_model_candidates_total 0
pilot_detection_model_circuit_open 0
pilot_detection_outbox_pending 0
```

`subjects.active=1` — Detection Engine 自己也確認了 `monitored-subject-1`
這一個 subject，跟 §51 要求的鏈路（inventory hostname → Prometheus
`pilot_host` label → 真實 Thanos `:10912` → Detection Engine）完全吻合。
`signals.active=0` 是預期的：baseline 需要 120 分鐘歷史才脫離 learning、
cohort 需要至少 3 個同 cohort peer，這個拓樸只有 1 個 subject 且測試時間
遠不到 120 分鐘，所以不會（也不應該）產生任何 SignalEvent——這條拓樸只
用來證明**身分鏈路**，不是拿來逼出真正的異常告警。

## 5. Spec v2 驗收結果（`pilot verify`）

```bash
$ go run ./cmd/pilot verify docs/verification/detection-engine.md -i <combined-inv> -l detection-engine --timeout 40
verdict: PASS  (pass=12 fail=0 skip=0)

$ go run ./cmd/pilot verify docs/verification/prometheus.md -i <combined-inv> -l prometheus --timeout 40
verdict: FAIL  (pass=14 fail=1 skip=0)   # C9 fail：假 S3 endpoint 連不到，§5 已知例外，與本次改動無關

$ go run ./cmd/pilot verify docs/verification/thanos-query.md -i <combined-inv> -l thanos-query --timeout 40
verdict: FAIL  (pass=9 fail=1 skip=0)    # C8 fail：同一個假 S3 endpoint 原因，§5 已知例外
```

`detection-engine.md` 全 12 rows PASS；`prometheus.md`/`thanos-query.md`
唯一的 fail 都是刻意使用假 S3 目的地造成，跟 Detection Engine 改動本身
無關，屬於各自 spec §5 已記錄的已知例外。

`vm-target verify --name <單一target>` 對這種需要 group 成員資格的 spec
無法直接解析（既有的 `pilot-verify-single-vm-targetgroup-gap`），繞法跟
`docs/runbooks/metrics-alerting.md` §7b 一致：手動組一份把該 target 標進
對應 group 的 inventory 檔，再用 `pilot verify -i <file> -l <group>` 跑。

## 6. 已知限制 / 尚未完成

- **Fake-protocol topology lane（spec §49 C11）尚未實跑**——
  `playbooks/test/detection-engine-fixtures.yml` 已經寫好（fake Thanos
  Query stub :10912 + fake Alertmanager stub :9093，皆為 stdlib-only
  Python + systemd），但尚未真的跑過 `vm-target topology test` 驗證整條
  lifecycle/escalation/resolution/outbox-ordering 情境。這條鏈路目前的
  證據是 `internal/detection` 的 Go 單元測試（`lifecycle_test.go`/
  `outbox_test.go`/`store_test.go`），已經逐一鎖住每個轉移規則，但沒有
  對應的活體 VM 執行記錄。
- 沒有逼出真正的 SignalEvent firing（見 §4 說明，這個拓樸的設計目的
  就不是拿來測這個）。
- Provider（Stage B）完全沒有涉及，`provider probe` 只確認回報
  disabled，沒有真的接過 OpenAI/Ollama。

## 7. Teardown

```bash
go run ./cmd/pilot vm-target down --name detect-central
go run ./cmd/pilot vm-target down --name prom-site
go run ./cmd/pilot vm-target down --name monitored-subject-1
```

## 8. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-08-28 | v1.0 | Stage A-2 首次實跑：3-VM 真實拓樸（monitored-subject-1 + prom-site + detect-central），完整部署鏈 + §51 real metrics-chain 證據 + Spec v2 12/12 PASS + 冪等重跑 changed=0；找到並修好 4 個真 bug（host-monitoring 缺 textfile collector、subjects/signals 計數從未寫回、SQLite VACUUM INTO 檔案已存在導致 upgrade rollback、`signals list` 空陣列序列化成 null） | sre |
