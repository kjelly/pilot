# Runbook — `alertmanager` (中央 Alertmanager,收各站 Prometheus 推送的告警)

> 撰寫日期:2026-07-07 (UTC)
> 對齊規範:`docs/verification/alertmanager.md`(v1.0)、
> `docs/verification/prometheus.md`(v1.1)
> 維護者:sre

---

## 0. 一句話目標

中央跑一份 `pilot-alertmanager`(`prom/alertmanager:v0.27.0` 容器,9093),收每個
站台 Prometheus 自己 eval 出來的告警,統一路由給 receivers(slack/email/webhook
等,預設 stub 是 `null` receiver,正式環境用 vault 帶入完整 `alertmanager.yml`)。
各站 Prometheus 在 `prometheus-apply.yml` 套用時透過 `alertmanager_target_host`
變數 pin 進各機的 `/etc/hosts` 成 `alertmanager-backend` 別名;Prometheus 端
`prometheus.yml` 的 `alerting.alertmanagers` 區塊跟 seed alert rules
(`Watchdog` + `PrometheusDown` + `HostDown`)一併套用上去,整條告警推送管道
就接起來了。

跟 `thanos-query` / `dashboard` 一樣是本專案的中央單例角色,典型部署是
同一台主機同時屬於 `thanos-query` + `alertmanager` 兩個 inventory group
(共用 `pilot-metrics` docker network)。

---

## 0.5 事實快照 (2026-07-07T02:07 UTC)

```bash
$ go run ./cmd/pilot vm-target list
NAME     STATE    IP           BASE IMAGE
pt-alert running  192.168.122.2 ubuntu-24.04
pt-s3   running  192.168.122.3 ubuntu-24.04
pt-site-a running 192.168.122.4 ubuntu-24.04

$ go run ./cmd/pilot vm-target show-inventory --name pt-alert
(all: hosts: pt-alert: ansible_host=192.168.122.2)

$ go run ./cmd/pilot spec docs/verification/alertmanager.md --lint
spec Verification Spec — alertmanager (central Alertmanager for all sites): 7 rows, 0 findings (0 errors)

$ go run ./cmd/pilot spec docs/verification/prometheus.md --lint
spec Verification Spec — prometheus (per-site Prometheus + Thanos Sidecar): 12 rows, 0 findings (0 errors)

$ go test ./internal/spec/ -run 'TestRegression_AlertmanagerSpec|TestRegression_PrometheusSpec' -v
--- PASS: TestRegression_AlertmanagerSpec (0.00s)
--- PASS: TestRegression_PrometheusSpec (0.00s)
```

**對齊決策**: 三台都是全新 vm-target，inventory 跟 spec targets 天生一致（不需要 A/B 選擇）。

---

## 1. 起 VM（本次證據為依序建立）

不同名稱的 `vm-target up` 可平行執行；state 的跨程序 `Store.Mutate` 已修正舊版
state-file race。以下維持依序命令與原始輸出，作為本次實測證據；資源足夠時可改為
平行建立這三台不同名稱的 VM。

```bash
# pt-alert: Alertmanager 主機（跟 thanos-query 可同機，這裡獨立）
$ go run ./cmd/pilot vm-target up --name pt-alert --ssh-user ubuntu --disk 20 --memory 2048 --vcpus 2 --ssh-timeout 8m --boot-timeout 8m
✓ target pt-alert up (192.168.122.2)

# pt-s3: SeaweedFS S3 目的地（給 Prometheus 上傳 TSDB blocks 用）
$ go run ./cmd/pilot vm-target up --name pt-s3 --ssh-user ubuntu --disk 20 --memory 2048 --vcpus 2 --ssh-timeout 8m --boot-timeout 8m
✓ target pt-s3 up (192.168.122.3)

# pt-site-a: 站台 Prometheus
$ go run ./cmd/pilot vm-target up --name pt-site-a --ssh-user ubuntu --disk 30 --memory 2048 --vcpus 2 --ssh-timeout 8m --boot-timeout 8m
✓ target pt-site-a up (192.168.122.4)
```

---

## 2. 套用軟體

### 2a. Docker（各 VM 皆需）

```bash
# pt-alert, pt-s3, pt-site-a 各自裝 docker
$ for vm in pt-alert pt-s3 pt-site-a; do
  go run ./cmd/pilot vm-target run --name $vm \
    playbooks/apply/core-infra-provider-apply.yml \
    -e target_group=$vm -e infra_role=docker
done
# PLAY RECAP: 各 VM ok=6 changed=2 skipped=13 failed=0
```

### 2b. SeaweedFS S3（pt-s3）

```bash
# 放 s3.json 進 VM（signing mode，restic/prometheus 都需 SigV4）
$ go run ./cmd/pilot vm-target exec --name pt-s3 -- bash -c \
  'sudo mkdir -p /etc/pilot-s3 && echo "{\"identities\":[{\"name\":\"pilot\",\"credentials\":[{\"accessKey\":\"pilot-access-key\",\"secretKey\":\"pilot-secret-key\"}],\"actions\":[\"Admin\",\"Read\",\"Write\"]}]}" | sudo tee /etc/pilot-s3/s3.json'

$ go run ./cmd/pilot vm-target run --name pt-s3 \
    playbooks/apply/seaweedfs-s3-apply.yml \
    -e target_group=all -e seaweedfs_s3_config_path=/etc/pilot-s3/s3.json
# PLAY RECAP: pt-s3 ok=9 changed=2 failed=0

# 預建 thanos bucket
$ go run ./cmd/pilot vm-target exec --name pt-s3 -- sudo docker exec pilot-seaweedfs sh -c \
  "echo 's3.bucket.create -name pilot-thanos-metrics' | weed shell"
# created bucket pilot-thanos-metrics
```

### 2c. Alertmanager（pt-alert）

```bash
$ go run ./cmd/pilot vm-target test --name pt-alert \
    --playbook playbooks/apply/alertmanager-apply.yml \
    --spec docs/verification/alertmanager.md \
    -- -e target_group=all
# L1: ✓ Syntax check passed
# L4 Apply: pt-alert ok=6 changed=4 failed=0
# L5 Verify: verdict: PASS (pass=7 fail=0 skip=0)
# L6 Idempotent: pt-alert ok=6 changed=0 failed=0
# 🎉 ALL TESTS PASSED SUCCESSFULLY!
```

### 2d. Prometheus（pt-site-a，整合 Alertmanager）

```bash
$ go run ./cmd/pilot vm-target test --name pt-site-a \
    --playbook playbooks/apply/prometheus-apply.yml \
    --spec docs/verification/prometheus.md \
    -- -e target_group=all \
       -e prometheus_site_label=site-a \
       -e thanos_s3_target_host=192.168.122.3 \
       -e thanos_aws_access_key_id=pilot-access-key \
       -e thanos_aws_secret_access_key=pilot-secret-key \
       -e alertmanager_target_host=192.168.122.2
# L1: ✓ Syntax check passed
# L4 Apply: pt-site-a ok=16 changed=9 skipped=1 failed=0
# L5 Verify: verdict: PASS (pass=12 fail=0 skip=0)
# L6 Idempotent: pt-site-a ok=16 changed=0 skipped=1 failed=0
# 🎉 ALL TESTS PASSED SUCCESSFULLY!
```

---

## 3. 整鍊測試

### 3a. Prometheus 端：C1–C12 verify（12/12 PASS）

```bash
$ go run ./cmd/pilot vm-target verify --name pt-site-a docs/verification/prometheus.md
verdict: **PASS** (pass=12 fail=0 skip=0)
```

| ID | Status | Detail |
|----|--------|--------|
| C1 | pass | stdout contains "pilot-prometheus" |
| C2 | pass | stdout contains "pilot-thanos-sidecar" |
| C3 | pass | stdout contains "200" |
| C4 | pass | stdout contains "200" |
| C5 | pass | stdout contains "200" |
| C6 | pass | stdout contains "200" |
| C7 | pass | stdout contains "\"1\"]" |
| C8 | pass | rc=0 matches expected 0 |
| C9 | pass | rc=0 matches expected 0 |
| C10 | pass | rc=0 matches expected 0 |
| C11 | pass | rc=0 matches expected 0 |
| C12 | pass | rc=0 matches expected 0 |

### 3b. Alertmanager 端：C1–C7 verify（7/7 PASS）

```bash
$ go run ./cmd/pilot vm-target verify --name pt-alert docs/verification/alertmanager.md
verdict: **PASS** (pass=7 fail=0 skip=0)
```

| ID | Status | Detail |
|----|--------|--------|
| C1 | pass | stdout contains "pilot-alertmanager" |
| C2 | pass | stdout contains "200" |
| C3 | pass | stdout contains "200" |
| C4 | pass | rc=0 matches expected 0 |
| C5 | pass | rc=0 matches expected 0 |
| C6 | pass | stdout contains "200" |
| C7 | pass | rc=0 matches expected 0 |

### 3c. 端對端告警推送驗證

等 ~30 秒讓 Prometheus 評估並推送 Watchdog：

```bash
$ go run ./cmd/pilot vm-target exec --name pt-alert -- \
    sudo curl -fsS http://127.0.0.1:9093/api/v2/alerts | \
    python3 -c "import json,sys; [print(f'  - {a[\"labels\"][\"alertname\"]} site={a[\"labels\"].get(\"site\",\"\")} state={a[\"status\"][\"state\"]} receiver={a[\"receivers\"][0][\"name\"]}') for a in json.load(sys.stdin)]"

Active alerts: 2
  - pilot-alertmanager-selftest site= state=active receiver=null
  - Watchdog site=site-a state=active receiver=null
```

**`site=site-a` 標籤從 Prometheus external_labels 成功傳到 Alertmanager**，證明：
1. Prometheus 正確評估 seed rules（Watchdog firing）
2. 推送至 Alertmanager（`alertmanager_backend:9093`）
3. Alertmanager 接收並 group
4. `null` receiver（stub）正確收到但 drop（預設行為）
5. C7 self-test alert 也還在（沒被 GC）

---

## 4. 已知坑 / 實測發現

| 坑 | 說明 | 解法 |
|----|------|------|
| Jinja vs Prometheus template | `prometheus_alert_rules` 是 inline YAML 字串時，`{{ $labels.X }}` 會被 Ansible Jinja 二次解析失敗（"Syntax error: unexpected char '$'"） | 改用 `prometheus_alert_rules_file` 檔案路徑 + `copy: src:`，避開 Jinja 處理 |
| `target_group=` 與 vm-target | `pilot vm-target test -- -e target_group=alertmanager` 時，若 inventory 無 `alertmanager` group，play 會 `skipping: no hosts matched` | 對單一 VM 測試時用 `-e target_group=all`（讓 vm-target 的隱式 `-l <name>` 生效），或確保 inventory 有對應 group |
| Docker 非 root | cloud-init VM 預設 SSH user 是 ubuntu（非 root），docker 命令需 `sudo` | apply playbook 已用 `become: true`，vm-target exec 需手動加 `sudo` |

---

## 5.  Tear down

```bash
go run ./cmd/pilot vm-target down --name pt-site-a
go run ./cmd/pilot vm-target down --name pt-s3
go run ./cmd/pilot vm-target down --name pt-alert
```

---

## 6. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-14 | v1.1 | 補充不同名稱 VM 現可平行建立；保留循序命令作為原始實測證據 | Codex |
| 2026-07-07 | v0.1 | 初版骨架 | sre |
| 2026-07-07 | v1.0 | 實跑補完：7/7 PASS alertmanager、12/12 PASS prometheus、端對端 Watchdog 確認推送成功 | sre |
