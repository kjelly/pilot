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

## 6.2 Stage B Model Provider 實跑證據（2026-08-28）

拓樸：`tmp/detection-engine-fake-topology.example.yaml`（4 節點：新增
`detection-fixture-provider` 跑 fake native Ollama Chat API :11434，回應
一個 schema/語意皆合法的 ModelDetectionBatchResponse——`status:ok`、每個
candidate_id 各回一筆、`contributors:[]`）。指令：

```bash
go run ./cmd/pilot vm-target topology test \
  --topology tmp/detection-engine-fake-topology.example.yaml \
  --playbook playbooks/apply/detection-engine-apply.yml \
  --verify docs/verification/detection-engine.md=detection-engine \
  --verify docs/verification/detection-engine-model-provider.md=detection-engine \
  --verify-timeout 40 \
  -- -e detection_engine_artifact_path=dist/pilot-detection-engine-linux-amd64 \
     -e detection_engine_artifact_sha256=<sha256> \
     -e detection_metrics_source_host=<source IP> \
     -e detection_alertmanager_target_host=<sink IP> \
     -e detection_model_provider_enabled=true \
     -e detection_model_provider_protocol=ollama-chat \
     -e detection_model_provider_model=fake-model \
     -e detection_model_provider_auth=none \
     -e detection_model_provider_base_url=http://<provider IP>:11434
```

（跑之前先對 `detection-engine-fixture` 套用一次
`host-monitoring-apply.yml -e target_group=all -e node_exporter_basic_auth_password=...`——
全新拓樸沒有 textfile collector 目錄，detection-engine 的既有 preflight
gate 會擋下。）

真實輸出（**第一次就全綠**，不像 C11 fake-lane 補跑時踩過 3 個真 bug）：

```
=== [Step 2/6] L3 Dry-run (--check --diff) ===
PLAY RECAP: ok=39 changed=8 unreachable=0 failed=0 skipped=22
✓ Check-mode dry-run passed
=== [Step 3/6] Cluster snapshot: 4 node(s) ===
✓ Cluster snapshot created
=== [Step 4/6] L4 Apply Playbook ===
PLAY RECAP: ok=53 changed=11 unreachable=0 failed=0 skipped=8
✓ Playbook apply completed
=== [Step 5/6] L5 Verification Specs (2) ===
verdict: **PASS**  (pass=12 fail=0 skip=0)   # detection-engine.md
verdict: **PASS**  (pass=5  fail=0 skip=0)   # detection-engine-model-provider.md — M1-M5
=== [Step 6/6] L6 Idempotency Check ===
PLAY RECAP: ok=51 changed=0 unreachable=0 failed=0 skipped=10
✓ Idempotency check passed (changed=0)
```

目標主機上直接確認：

```
$ pilot-detection-engine provider probe --config /etc/pilot/detection-engine/config.yaml
provider probe ok: protocol=ollama-chat status=ok elapsed=2ms

$ sudo pilot-detection-engine status --json
{
  "model_provider": {"enabled": true, "healthy": true, "protocol": "ollama-chat", "circuit": "closed"},
  "subjects": {"active": 1}, "signals": {"active": 0}, "last_cycle": {"success": true}
}
```

Stage B-1（engine core + contract/inventory/playbook delivery +
provider-verification lane）至此全部有真實證據。

## 6.3 Stage B-2 real-provider evidence（Ollama native，2026-08-28）

同一套拓樸，把 `detection_model_provider_base_url` 從 fake fixture
（`detection-fixture-provider:11434`）換成一台真實 Ollama server
（`http://10.1.80.71:11434`，`model: gemma4:e4b`），其餘完全比照 §6.2：

```bash
go run ./cmd/pilot vm-target topology test \
  --topology tmp/detection-engine-fake-topology.example.yaml \
  --playbook playbooks/apply/detection-engine-apply.yml \
  --verify docs/verification/detection-engine.md=detection-engine \
  --verify docs/verification/detection-engine-model-provider.md=detection-engine \
  --verify-timeout 40 \
  -- -e detection_engine_artifact_path=dist/pilot-detection-engine-linux-amd64 \
     -e detection_engine_artifact_sha256=<sha256> \
     -e detection_metrics_source_host=<source IP> \
     -e detection_alertmanager_target_host=<sink IP> \
     -e detection_model_provider_enabled=true \
     -e detection_model_provider_protocol=ollama-chat \
     -e detection_model_provider_model=gemma4:e4b \
     -e detection_model_provider_auth=none \
     -e detection_model_provider_base_url=http://10.1.80.71:11434
```

真實輸出（第一次就全綠）：

```
=== [Step 4/6] L4 Apply Playbook ===
PLAY RECAP: ok=53 changed=11 unreachable=0 failed=0 skipped=8
✓ Playbook apply completed
=== [Step 5/6] L5 Verification Specs (2) ===
verdict: **PASS**  (pass=12 fail=0 skip=0)   # detection-engine.md
verdict: **PASS**  (pass=5  fail=0 skip=0)   # detection-engine-model-provider.md — M1-M5
=== [Step 6/6] L6 Idempotency Check ===
PLAY RECAP: ok=51 changed=0 unreachable=0 failed=0 skipped=10
✓ Idempotency check passed (changed=0)
```

目標主機上直接確認（真實模型，非 fixture）：

```
$ pilot-detection-engine provider probe --config /etc/pilot/detection-engine/config.yaml
provider probe ok: protocol=ollama-chat status=insufficient_data elapsed=9.161s

$ sudo pilot-detection-engine status --json
{
  "model_provider": {"enabled": true, "healthy": true, "protocol": "ollama-chat", "circuit": "closed"},
  "last_cycle": {"success": true}
}
```

背景踏查（跟這次實跑本身無關，但值得記錄）：同一顆 `gemma4:e4b` tag
在**不同 Ollama host** 上結果不一致——`10.1.80.43:11434` 那台會回傳缺
envelope 的扁平 JSON（client-side validation 正確擋下，fallback
local）；`10.1.80.71:11434` 這台（本次實跑所用）用同一份 v1 prompt 就
正確回完整 envelope。根因已隔離到 prompt 內容本身（拿掉 format schema
的 `$schema` 欄位單獨測試無效，加一句明確要求「回完整 envelope」才有
用）而非 client 端序列化問題；因為 spec §36 的 prompt 是
version-locked（prompt_version=1），且問題本身是 host/build-specific
而非 v1 prompt 通用缺陷，暫不修改 prompt。另外實測
`qwen3.5-2b-FLM`（Lemonade Server, `10.1.80.71:13305`）：連線正常，但
同一份請求重跑多次回傳格式不穩定（有時缺 envelope、有時根本不是合法
JSON），client-side validation 同樣正確全部擋下；判斷為該 2B 模型
/FLM runtime 本身的可靠度限制，非 pilot 這邊的 bug。

Stage B-2 的「至少一個：Ollama native」要求至此有真實證據滿足。

## 6.4 Stage C-1 — flm protocol（2026-08-28）

背景：`docs/superpowers/specs/2026-08-28-npu-detect-engine-spec.md`（NPU
Detect Engine 新 spec，非本文件主 spec）驅動了這個追加工作。實測發現
`gemma4:e4b`（`10.1.80.43:11434`）跟 `qwen3.5-2b-FLM`（Lemonade Server,
`10.1.80.71:13305`）都對 Ollama 的 `format` JSON Schema 提示不理不睬
——直接打底層 NPU backend（`127.0.0.1:8001`，繞過 Lemonade 的 Ollama-API
轉譯層）送一個 `required` schema 給它，它完全無視、直接用自然語言回答
"OK"，證實 FastFlowLM 這條推論引擎本身不支援 grammar-constrained
decoding。

拍板決議：不建立平行的 `internal/detect` package，而是在既有
`ModelProvider` interface 上新增第三種 protocol `flm`——沿用既有
`ManagedProvider`（retry/circuit breaker）與 batch envelope，只新增
pipe-delimited text 契約（`VERDICT|SEVERITY|CATEGORY|CONFIDENCE`）取代
JSON。過程中還抓到一個真的 prompt bug：沒給具體範例時，
`qwen3.5-2b-FLM` 會把「VERDICT」這個**欄位名稱**字面輸出當成答案；補上
「不要照抄欄位名稱」的明確提示後穩定修好。

實測（透過 `provider probe`，`protocol: flm`）：
- `qwen3.5-2b-FLM`（原本經 ollama-chat/JSON 完全不能用）→ 3/3 連續成功。
- 真的送一批 3 個 candidate：正確分辨 CPU 過熱（score=0.75,
  category=cpu_utilization）、正常主機（score=0，不升級）、記憶體壓力
  （score=0.75, category=memory_pressure），3.5 秒跑完整批。

## 6.5 Stage C-1 追加 — NPU-primary-with-fallback（2026-08-28）

使用者需求：NPU（flm）優先，失敗時可 fallback 到 ollama-chat 或
openai-responses。實作為通用、protocol-agnostic 的
`FallbackProvider{Primary, Fallback *ManagedProvider}`（兩個各自獨立的
retry/circuit breaker），`config.yaml` 新增 `modelProvider.fallback.*`
巢狀區塊，`Engine.Provider` 型別從 `*ManagedProvider` 改成 `ModelProvider`
interface 以容納兩種形狀。

實測（`detection_model_provider_protocol=flm` 指向刻意錯誤的 port
19999，`fallback.protocol=ollama-chat` 指向真實 `10.1.80.71:11434`
`gemma4:e4b`）：

```bash
go run ./cmd/pilot vm-target run --name detection-engine-fixture \
  playbooks/apply/detection-engine-apply.yml -e target_group=all \
  ... \
  -e detection_model_provider_enabled=true \
  -e detection_model_provider_protocol=flm \
  -e detection_model_provider_model=qwen3.5-2b-FLM \
  -e detection_model_provider_base_url=http://10.1.80.71:19999 \
  -e detection_model_provider_fallback_enabled=true \
  -e detection_model_provider_fallback_protocol=ollama-chat \
  -e detection_model_provider_fallback_model=gemma4:e4b \
  -e detection_model_provider_fallback_base_url=http://10.1.80.71:11434
```

真實輸出（第一次因 dist/ binary 忘記重 build 而失敗——`config validate`
正確拋出 `field fallback not found`，自動 rollback 正確運作、把之前的
binary/service 復原；重 build 後第二次全綠）：

```
PLAY RECAP: ok=57 changed=6 unreachable=0 failed=0 skipped=7    # 首次 apply
PLAY RECAP: ok=54 changed=0 unreachable=0 failed=0 skipped=10   # 冪等重跑
```

目標主機上直接確認（真的透過完整 primary-fail→fallback-succeed 路徑）：

```
$ sudo pilot-detection-engine status --json
{"model_provider": {"enabled": true, "healthy": true, "protocol": "flm", "circuit": "closed"}, ...}

$ pilot-detection-engine provider probe --config /etc/pilot/detection-engine/config.yaml
provider probe ok: protocol=flm status=insufficient_data elapsed=12.192s
```

`elapsed=12.192s` 與 `status=insufficient_data` 跟先前單獨測 gemma4:e4b
via ollama-chat 的結果完全吻合（primary 失敗重試 1s+2s 退避＋fallback
真實呼叫約 9s），證實 fallback 真的接手，不是巧合。已知簡化：
`status.json`/metrics 的 `protocol` 欄位固定回報 primary 的 protocol
名稱，即使實際由 fallback 服務也一樣——這是 v1 的可接受簡化，不影響
正確性。

## 6.6 Stage C-2/C-3/C-4 — Log pipeline 實跑證據（2026-08-28）

docs/superpowers/specs/2026-08-28-npu-detect-engine-spec.md §14-18 的
Log/Loki pipeline，reconcile 成既有 `internal/detection` 的第三個對等
detector（baseline/cohort/log 三選一 max，非另立 schema）。Hard trigger
（known-critical-pattern，如 OOM/kernel panic/segfault）採**選項
B**：偵測器該 cycle 直接回報 `Score=1.0`，不繞過既有 lifecycle
hysteresis（3-of-4 warning / 2-consecutive critical）——`ComputeLocalScore`
的 max() 自然讓 1.0 主導，`HostLifecycle.Advance` 完全不用改。

拓樸新增第 5 個節點 `detection-fixture-logs`（fake Loki `query_range`
API，`/opt/pilot-fixtures/fake-loki.py`，固定回傳一行
`pilot_host=fixture-host-1` 的 OOM 訊息，不理會 query 的時間窗）：

```bash
go run ./cmd/pilot vm-target run --name detection-engine-fixture \
  playbooks/apply/detection-engine-apply.yml -e target_group=all \
  -e detection_engine_artifact_path=dist/pilot-detection-engine-linux-amd64 \
  -e detection_engine_artifact_sha256=6d148270b36b018ff9cffc812a524fe8f060f722504f991a2974fa5ab6299f8a \
  -e detection_metrics_source_host=192.168.122.4 \
  -e detection_alertmanager_target_host=192.168.122.7 \
  -e detection_log_source_enabled=true \
  -e detection_log_source_base_url=http://192.168.122.6:3100 \
  -e 'detection_log_source_query={job=~".+"}'
```

### 實跑中發現並修好的真 bug：fake Thanos fixture 忽略 `time=`/`end=` 參數

第一次全綠 apply（`ok=57 changed=11`）後，等了超過 8 分鐘（cycle_interval
15s，約 32 個 cycle），`status --json` 的 `signals.active` 始終是 0，
`state.db` 的 `signal_episodes`/`baseline_samples` 全空。追查發現：
`fake-thanos-query.py` 無論 request 帶的 `time=`/`end=` 參數是什麼，一律
回傳 `time.time()`（真實牆鐘時間）當樣本時間戳。真正的 engine 是用
`evaluationTime = wall_clock - detection_evaluation_delay`（contract
預設 20s）去查詢，而 `source.go` 的 `ClassifySample` 對超前
`evaluationTime` 5 秒以上的樣本一律判成 `future_sample`——所以每個
required feature 每個 cycle 都被判無效，`HostCycleValid` 永遠 false，
根本沒機會跑到 baseline/cohort/log 三選一那一段。這是既存的 fixture bug
（無關本次 Stage C-2/3/4 的邏輯，之前的 fake-lane 用法都沒有等到真的靠
`serve` 常駐 loop 產生一個持久 episode，只有透過 Go unit test 才驗證過
lifecycle），修法：讓 fixture 改讀 request 的 `time=`（vector）/`end=`
（matrix）參數當回傳時間戳，不理會就 fallback 真實時間。修完重跑
`detection-engine-fixtures.yml` 重啟 fixture 後，等待 90 秒即拿到：

```
$ sudo sqlite3 state.db "SELECT signal_id,state,severity,category_hint,last_score,critical_streak FROM signal_episodes;"
01M13QDC5E308NGDKD6G9ND93Q|firing|critical|known_critical_pattern|1.0|0

$ sudo sqlite3 state.db "SELECT * FROM outbox;"
...|fire|{"labels":{"alertname":"PilotAdaptiveAnomaly","pilot_host":"fixture-host-1","severity":"critical","site":"fixture-site",...},
   "annotations":{"category_hint":"known_critical_pattern","confidence":"1","score":"1",
   "top_contributors":"[\"log:0d5293c46997\"]"},...}|pending|0|...
```

`top_contributors` 的 `log:0d5293c46997` 證實真的是 log detector（不是
baseline/cohort）驅動這個 episode；`category_hint=known_critical_pattern`
+ `last_score=1.0` 精確對上選項 B 的預期行為，且 revision=1 就直接是
`firing`/`critical`（episode 只在真正跨過閾值時才第一次落地寫入 DB，
不代表繞過了 hysteresis）。

**發現當時的已知限制（已於 §6.7 修復，此處保留原始踏查記錄）**：outbox
row 當時停在 `status=pending, attempts=0` 沒有被送到 fake
Alertmanager（`received-alerts.ndjson` 全空，即使雙向 `curl /-/ready`
都回 200）。查證後確認 `cmd/pilot-detection-engine/main.go` 的
`runServe` scheduler callback 從來沒有呼叫 `ClaimOutboxItem`/對
`alertmanagerBaseUrl` 發 HTTP POST——整個 `serve` daemon 當時沒有接上
outbox 遞送 worker，這是既存於 Stage A 的落差，並非本次 log pipeline
造成。

冪等重跑（同一組 `-e`，含 log source）：

```
PLAY RECAP: detection-engine-fixture ok=55 changed=0 failed=0 unreachable=0 skipped=10
```

## 6.7 Outbox 遞送 worker 接上 serve daemon（2026-08-28）

補上 §6.6 發現的 gap：新增 `internal/detection/outbox_deliver.go`
的 `AlertmanagerSender`，`runServe` 的 scheduler callback 每個 cycle
在 `RunCycle` 之後（同一 goroutine，非另開 worker）呼叫
`DrainOutbox`，迴圈 `ClaimOutboxItem` → `POST {baseUrl}/api/v2/alerts`
（body 包成 JSON array，符合 Alertmanager 真實 API v2 契約，`payload_json`
本身只存單一物件）→ `CompleteOutboxItem`，直到沒有可 claim 的 row 為止
（上限 `maxOutboxDrainPerCycle=100` 防止病態 backlog 卡住 cycle
scheduler）。retry/dead 分類完全沿用既有 `ClassifyDeliveryOutcome`/
backoff ladder，沒有新發明語義。`AlertmanagerSendFailureTotal`
（reason→count）比照 `ModelRequestTotal` 現有慣例，走「這個 cycle 的
snapshot」而非跨 process 累加。新增 5 個 Go 單元測試
（`outbox_deliver_test.go`：200 送達、network error 進 retry、4xx 進
dead、同一 pass 送多筆、沒東西可送時完全不撥網路），第一次跑就全綠。

實測：重跑同一個 5-VM fake-topology + log hard-trigger 場景（重 build
binary，sha256 `055b542b7...`），90 秒後：

```
$ sudo sqlite3 state.db "SELECT id,status,attempts,last_error_code FROM outbox;"
01M13T0CKENPEP51M28GYSAA4J|delivered|0|

$ sudo cat /var/lib/node_exporter/textfile/pilot_detection_engine.prom | grep outbox
pilot_detection_outbox_pending 0

$ ssh detection-fixture-sink sudo cat /opt/pilot-fixtures/received-alerts.ndjson
[{"labels": {"alertname": "PilotAdaptiveAnomaly", "pilot_host": "fixture-host-1", "severity": "critical",
  "site": "fixture-site", "source": "detection-engine"}, "annotations": {"category_hint": "known_critical_pattern",
  "confidence": "1", "profile": "linux-host-v1", "score": "1", "signal_id": "01M13T0CKE2K94S1S80FQH3N6M",
  "top_contributors": "[\"log:0d5293c46997\"]"}, "startsAt": "2026-08-28T09:07:30Z", "endsAt": "2026-08-28T09:10:30Z"}]
```

這是第一次真的看到 alert body 落到 fake Alertmanager 的 `received-alerts.ndjson`
（body 是 JSON array，證實走了真實 `/api/v2/alerts` 契約，不是原本存的單一物件）。
`outbox.status=delivered` + `pilot_detection_outbox_pending=0` 雙重確認。
冪等重跑 `changed=0`。C11 exemption 的措辭（「outbox 機制只驗結構完整，
scenario 證據來自 fake-protocol topology lane」）現在完全站得住腳——
這次的 fake-protocol topology lane 實跑本身就是那個 scenario 證據。

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
| 2026-08-28 | v1.2 | Stage B-1 全部落地：engine core（OpenAI/Ollama adapter、batch、fusion、retry/circuit）+ contract/inventory/playbook delivery（provider group vars、`detection-model-provider` Vault section、apply-time gates、provider.env/systemd EnvironmentFile）+ provider-verification lane（新增 `detection-fixture-provider` fake Ollama Chat fixture，`docs/verification/detection-engine-model-provider.md` M1-M5 全 PASS、冪等 changed=0，第一次跑就全綠，未發現新 bug） | sre |
| 2026-08-28 | v1.3 | Stage B-2 real-provider evidence（Ollama native）：同拓樸把 provider base_url 換成真實 `10.1.80.71:11434`/`gemma4:e4b`，M1-M5 全 PASS、冪等 changed=0；順手記錄 gemma4:e4b 跨 host 不一致（host/build-specific，非 v1 prompt 通用缺陷）與 qwen3.5-2b-FLM（Lemonade）回傳格式不穩定的踏查結果 | sre |
| 2026-08-28 | v1.4 | Stage C-1：新增 `flm` protocol（pipe-delimited text 契約，取代 FastFlowLM 不支援的 JSON schema 強制）+ NPU-primary-with-fallback（`FallbackProvider`，任一 protocol 組合皆可當 primary/fallback）。實測 `qwen3.5-2b-FLM` 從完全不能用變 3/3 成功；實測 fallback 真的透過 primary-fail→fallback-succeed 全路徑（含一次因忘記重 build binary 觸發的自動 rollback，正確運作），apply/冪等皆 PASS | sre |
| 2026-08-28 | v1.5 | Stage C-2/C-3/C-4：Log/Loki pipeline（npu-detect-engine spec §14-18），reconcile 成 baseline/cohort 的第三個對等 detector；known-critical-pattern hard trigger 用選項 B（該 cycle 直接 Score=1.0，仍走既有 lifecycle hysteresis，非繞過）。新增 `detection-fixture-logs` fake Loki fixture 節點，5-VM 拓樸實跑：找到並修好 1 個真 fixture bug（fake Thanos 忽略 `time=`/`end=` 參數固定回傳當下牆鐘時間，配合預設 20s evaluation_delay 讓每個 cycle 的樣本都被判 `future_sample`，導致整條 metrics 鏈永遠無效，log pipeline 沒機會被跑到）；修完後拿到真實持久化的 `signal_episodes` row（`state=firing, severity=critical, category_hint=known_critical_pattern, last_score=1.0`）與對應 outbox `fire` 事件（`top_contributors` 含 `log:` 前綴證實由 log detector 驅動），冪等重跑 changed=0。已知既存限制：outbox 遞送 worker 本來就沒接上 `serve` daemon（Stage A 就有的 gap，非本次造成）——已於 v1.6 補上 | sre |
| 2026-08-28 | v1.6 | 把 outbox 遞送 worker 接上 `serve` daemon：新增 `AlertmanagerSender.DrainOutbox`，`runServe` 每個 cycle 在 `RunCycle` 後 claim+POST+complete 直到沒有可送的 row（`maxOutboxDrainPerCycle=100` 防病態 backlog），沿用既有 retry/dead/backoff 語義，5 個新 Go 單元測試第一次全綠。重跑同一個 5-VM fake-topology + log hard-trigger 場景，第一次真的在 fake Alertmanager 的 `received-alerts.ndjson` 看到送達的 alert body（JSON array，符合真實 `/api/v2/alerts` 契約），`outbox.status=delivered`、`pilot_detection_outbox_pending=0`，冪等重跑 changed=0 | sre |
