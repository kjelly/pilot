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

- ~~Fake-protocol topology lane（spec §49 C11）尚未實跑~~ — **已於
  2026-08-28 補跑**，見下方 §6.1。C11 現在有真實 VM 執行記錄，不再只靠
  `internal/detection` 的單元測試。
- 沒有逼出真正的 SignalEvent firing（見 §4 說明，這個拓樸的設計目的
  就不是拿來測這個）。
- Provider（Stage B）完全沒有涉及，`provider probe` 只確認回報
  disabled，沒有真的接過 OpenAI/Ollama。

## 6.1 Fake-protocol topology lane 實跑證據（2026-08-28）

拓樸：`tmp/detection-engine-fake-topology.example.yaml`
（`detection-engine-fixture` 跑 apply 目標 + `detection-fixture-source`
跑 fake Thanos stub :10912 + `detection-fixture-sink` 跑 fake
Alertmanager stub :9093，皆由 `playbooks/test/detection-engine-fixtures.yml`
佈署）。指令：

```bash
go run ./cmd/pilot vm-target topology test \
  --topology tmp/detection-engine-fake-topology.example.yaml \
  --playbook playbooks/apply/detection-engine-apply.yml \
  --verify docs/verification/detection-engine.md=detection-engine \
  --verify-timeout 40 \
  -- -e detection_engine_artifact_path=dist/pilot-detection-engine-linux-amd64 \
     -e detection_engine_artifact_sha256=25cb971b05e68dcbda326d2505aaab2b16ad30c3b0148fd6e61d1a2161a1c806 \
     -e detection_metrics_source_host=192.168.122.3 \
     -e detection_alertmanager_target_host=192.168.122.2
```

真實輸出（第三次乾淨全綠的一輪；前兩輪各抓到一個真 bug，見下）：

```
=== [Step 1/6] L1 Syntax Check ===
✓ Syntax check passed
=== [Step 2/6] L3 Dry-run (--check --diff) ===
PLAY RECAP: ok=36 changed=2 unreachable=0 failed=0 skipped=22 rescued=0 ignored=0
✓ Check-mode dry-run passed
=== [Step 3/6] Cluster snapshot: 3 node(s) (tag: pre-test-1787892816) ===
✓ Cluster snapshot created
=== [Step 4/6] L4 Apply Playbook (topology inventory) ===
PLAY RECAP: ok=49 changed=0 unreachable=0 failed=0 skipped=9 rescued=0 ignored=0
✓ Playbook apply completed
=== [Step 5/6] L5 Verification Specs (1) ===
✔ Report:   .verification/detection-engine-20260828-045359.md
verdict: **PASS**  (pass=12 fail=0 skip=0)
✓ Verification checks passed
=== [Step 6/6] L6 Idempotency Check ===
PLAY RECAP: ok=49 changed=0 unreachable=0 failed=0 skipped=9 rescued=0 ignored=0
✓ Idempotency check passed (changed=0)
🎉 ALL TESTS PASSED SUCCESSFULLY!
```

### 實跑中發現並修好的 2 個真 bug

1. **`tasks/resolve-hosts-alias-target.yml` 的 `hosts_alias_resolved_ip`
   fact 跨 include 洩漏（repo-wide，非 detection-engine 獨有）**——
   這支共用 task file 被 `detection-engine-apply.yml`
   在同一個 play 裡 include 兩次（先解析 Thanos alias 再解析
   Alertmanager alias）；`prometheus-apply.yml` 也是同樣模式
   （`thanos_s3_target_host` 再 `alertmanager_target_host`）。原本兩個
   DNS 解析 task 都用 `when: hosts_alias_resolved_ip is not defined`
   把關，但這是一個 **fact**，第一次 include 已經把它設成 Thanos 的
   IP，第二次 include 時它「已經 defined」，DNS 解析與
   consolidate 兩個 task 直接被跳過，於是 Alertmanager alias 被錯誤
   pin 成 Thanos 節點的 IP。結果：`Gate: Alertmanager is ready`
   對著一個沒有人在監聽 9093 的 IP 連線，穩定重現
   `Connection refused`（連兩輪皆同一失敗點；手動直連
   `detection-fixture-sink:9093` 當下確認服務本身健康，排除了
   fake-alertmanager 本身的問題）。修法：在共用 task file最前面加一個
   無條件重置 `hosts_alias_resolved_ip: ""` 的 task，並把後兩個
   `is not defined` guard 改成 `| default('') | length == 0`
   （與檔案裡其他既有 guard 風格一致）。
2. **state.db 落地權限是 `0644` 而非 spec 要求的 `0600`（C4 真失敗）**——
   sqlite driver 第一次建立 `state.db` 時用預設 umask，不會自己收緊到
   `0600`；`/var/lib/pilot/detection-engine` 目錄本身是 `0700`
   擋掉了其他使用者，但 spec C4 明確要求檔案自己也要是
   `pilot-detect:pilot-detect 600`（defense-in-depth）。修法：在
   Step 17（`db check`）後加 Step 17b，用
   `ansible.builtin.file` 顯式把 `state.db` 的 owner/group/mode 收緊到
   `pilot-detect:pilot-detect 0600`（`not ansible_check_mode` 保護，
   對已經是 600 的情況冪等）。

兩個 bug 都已回歸鎖定：`internal/spec/detection_engine_regression_test.go`
新增了對 `resultType:vector` 無空白子字串誤判的鎖（§49 之前 C7 那個
substring bug 的回歸測試），`docs/verification/host-monitoring.md`/
`prometheus.md` 系列既有的 dot-notation/`.get()` 慣例延伸套用到這兩處
修法上。

拓樸曾兩次在 rollback 之後、緊接著重跑時，在第一個真正需要連線的
remote task（`stat` 模組）卡在
`Timeout (32s) waiting for privilege escalation prompt`；VM 直接手動
連線（`vm-target exec`、原始 `ssh` 重現同樣的
ControlMaster/ControlPath 參數）都證實服務與 SSH 本身健康、連線通常
< 1s 完成 —— 判定為 rollback 後 libvirt snapshot-revert 造成的短暫
guest 端延遲（非邏輯 bug），單純重跑即恢復正常，未改動任何程式碼。

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
| 2026-08-28 | v1.1 | Fake-protocol topology lane（spec §49 C11）補跑：`vm-target topology test` 對 fake Thanos/Alertmanager fixture 全綠（L1/L3/L4/L5 12-12 PASS/L6 changed=0）；找到並修好 2 個真 bug（`resolve-hosts-alias-target.yml` 的 fact 跨 include 洩漏，repo-wide，`prometheus-apply.yml` 同樣受影響；state.db 落地權限 0644 應為 0600）；Stage A 達成 VERIFICATION_READY | sre |
