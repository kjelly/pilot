# Verification Spec — alertmanager (central Alertmanager for all sites)

> 版本：v1.12
> 對齊規範：pilot 通用 container-backed 服務規範（比照 `prometheus.md` / `thanos-query.md` 的 docker container 模式）
> 維護者：sre

## 1. 目標系統

| Hostname | Group |
|----------|-------|
| central  | alertmanager |

> `alertmanager` group 只能有 **單一** 主機（與 `thanos-query` 可同機）。

## 1.5 依賴變數契約

| 變數名稱 | 說明/用途 | 是否必填 | 預設值 |
|----------|-----------|----------|--------|
| `alertmanager_version` | Alertmanager Docker image 版本 | 否 | `v0.27.0` |
| `alertmanager_receiver_mode` | `null`、`teams` 或 `custom`；未設定但已有 `alertmanager_config` 時為 legacy `custom` | 否 | `null` |
| `alertmanager_teams_webhook_url` | 單一 Teams / Power Automate HTTPS webhook URL（vault）；由 `pilot-alertmanager-teams-proxy` 消費，不再直接寫進 alertmanager.yml | 僅 `teams` 模式 | 無 |
| `alertmanager_teams_proxy_port` | Adaptive Card 轉換 proxy 對外（僅 loopback）監聽埠 | 否 | `8095` |
| `alertmanager_teams_proxy_image` | proxy 執行用的 Docker image | 否 | `python:3.12-alpine` |
| `alertmanager_config` | 完整 `alertmanager.yml` 內容（vault）；僅 `custom` 模式使用 | 僅 `custom` 模式 | 無 |
| `alertmanager_host_data_dir` | Alertmanager 持久化目錄 (silences, notifications) | 否 | `/var/lib/pilot/alertmanager` |
| `alertmanager_config_dir` | Alertmanager 設定檔目錄 | 否 | `/etc/pilot/alertmanager` |
| `docker_network_name` | Docker network 名稱 (與 thanos-query 共用) | 否 | `pilot-metrics` |

## 1.6 Teams routing contract

內建 `teams` 模式以 `alertname + pilot_subject + signal_id` 分組，`repeat_interval`
為 12 小時。只有 `severity=critical` 或明確帶 `action_required=true` 的 alert
進 Teams；一般 warning 留在 Detection Engine dashboard/digest。Adaptive Card 必須
顯示 reason、recommended action、runbook 與持續時間，讓收到通知的人能直接判斷
下一步。

## 1.7 Inhibit contract（GitHub issue #11）

host-health 規則（`playbooks/apply/templates/pilot-host-health-alert-rules.yml.j2`）
與 seed 的 `HostDown`（`up != 1`，`for: 10m`）加上下面兩條 inhibit 規則，保證三件事：

1. **整台主機掛掉只產生 `HostDown`。** `PilotLoginProbeTransportFailed` 的規則本身
   排除 `up{job="node"} == 0` 的主機，跟兩個 `for:` 的長短無關。`HostMetricsMissing`
   只採信這台主機在 `host_metrics_missing_success_window`（預設 140s）內真的登入成功過一次：
   probe 為這個 target 記錄的 last-success 時間戳要有變化（`changes()`，不依賴探測主機時鐘）。
   主機掛掉後不會再有新的成功登入；最後一次成功最多晚一次 textfile 寫出（15s）才被看見，所以
   條件在主機掛掉後最多還成立 時間窗 + 15s。只要這段時間不超過 `host_metrics_missing_for`（預設
   140s + 15s ≤ 3m，playbook 會擋），掛掉的主機就不會觸發 `HostMetricsMissing`——不論 probe 同時
   停擺、晚一輪才停擺，或因為大量主機同時掛掉、一輪要跑很久才輪到它——`HostDown` 照自己的時程送出。
   promtool 案例鎖住這些情況，也鎖住邊界（3m 的 `for` 配 165s 的時間窗不觸發，170s 會觸發）。
2. **監控資料缺口（node_exporter 停了或 9100 被擋，SSH 正常）只產生
   `HostMetricsMissing`。** 它在 `host_metrics_missing_for`（預設 3m）就觸發，抑制
   同一台主機 `job="node"` 的 `HostDown`（10m 才觸發，從一開始就被抑制）。
   `prometheus-apply.yml` 拒絕 `host_metrics_missing_for` ≥ 10m。它帶
   `keep_firing_for`（`login_probe_alert_keep_firing_for`，預設 5m），probe 單輪失敗或重啟
   （重啟後第一次寫出的 textfile 是 `success=0`）不會讓它中斷、讓 `HostDown` 漏出來。
   代價是延遲（預設值，Prometheus 未設 `evaluation_interval`，即 1m）：
   - node_exporter 恢復後，`HostMetricsMissing` 要等下一次 scrape（≤15s）與規則評估
     （≤1m）才不再成立；`keep_firing_for` 從那次評估開始算，剛好 5m 後 resolve，
     所以最多約 6m15s（實測 5m40s，`docs/evidence/login-probe/2026-10-15-243987b.md`）。
   - 資料缺口期間主機真的掛掉時，probe 要到下一輪失敗才會寫出 `success=0`
     （`login_probe_interval` 60s + `login_probe_total_timeout` 30s + textfile 寫出 ≤15s），
     再經 scrape（≤15s）與評估（≤1m）才不再成立，加上 `keep_firing_for` 5m，`HostDown`
     最多約 8m 後才不再被抑制，之後 Alertmanager 依 `group_interval`（5m）送出。
   - 資料缺口期間 probe 必須在每個時間窗內為這台主機記到一次成功登入。probe 正常時這由 playbook
     的 gate 保證（見下面前提）；probe 慢到同一台主機兩次成功的間隔超過時間窗（例如大量主機同時
     掛掉、一輪跑很久，`pilot_login_probe_round_overruns_total` 會增加）時，`HostMetricsMissing`
     會中斷或不觸發，`HostDown` 照常送出——寧可多送「Target down」，不會漏送（fail-safe）。它帶
   `action_required="true"`，`teams` 模式也會送出，不會因為 `HostDown` 被抑制而沒有
   任何通知。其他 job（例如 `dcgm`）的 `HostDown` 不受影響。
3. **一台 login probe 停擺（`PilotLoginProbeStale`）只抑制它自己的告警。** 每個
   `PilotLoginProbe*` 告警都帶 `probe_host`（看到它的 probe 主機），抑制只比對
   `probe_host`；另一台 probe 回報的 `AccountDenied` 照常送出。`PilotLoginProbeStale`
   帶 `action_required="true"`，`teams` 模式也會送出。

這個 Alertmanager 是所有站台共用的，兩條規則的 `equal` 都帶 `site`（每台 Prometheus 的
external label），兩個站台用了相同主機名稱時不會互相抑制。

`null` 與 `teams` 模式內建這兩條規則（`playbooks/apply/alertmanager-apply.yml` 的
`alertmanager_default_config`/`alertmanager_teams_config`）。`custom` 模式由 operator
自帶整份 `alertmanager_config`，**必須自行加入同樣的兩條**（C10 會檢查）：

```yaml
inhibit_rules:
  - source_matchers: ['alertname="HostMetricsMissing"']
    target_matchers: ['alertname="HostDown"', 'job="node"']
    equal: ['pilot_host', 'site']
  - source_matchers: ['alertname="PilotLoginProbeStale"']
    target_matchers: ['alertname=~"PilotLoginProbe(AccountDenied|AuthFailed|LoginStalled|HostKeyMismatch|SessionFailed|TransportFailed|NoTargets)"']
    equal: ['probe_host', 'site']
```

C10 讀的是執行中 Alertmanager 載入的設定（`amtool config show`），要求這兩條規則逐字相符；
舊版規則（`HostDown` 當來源、Stale 以 `site` 比對）或少了 `site` 的版本都會 FAIL。

上述保證有這些前提：

- 主機的 `pilot_host` 要等於 login probe 的 `probe_target`。自動展開的 target 一定成立；
  明確設定 `login_probe_targets` 時，名稱要用 inventory 名稱，否則上面的對應會靜默失效
  （見 `docs/runbooks/login-probe.md` §6）。
- 用 `prometheus_alert_rules_file` 換掉 seed 規則時，必須保留同樣的 `HostDown`
  （`up != 1`，`for: 10m`）。
- node scrape target 由 inventory 的 `host-monitoring` group 自動展開（帶 `pilot_host`）。
  改用 `node_exporter_targets` 明確列出 target 時，node series 沒有 `pilot_host`：
  `HostMetricsMissing` 不會觸發，主機掛掉時也不會排除 `PilotLoginProbeTransportFailed`。
- `PilotLoginProbeStale` 看的是 `login_probe_stale_seconds` 內 probe 寫入時間戳的 `changes()`，這段
  時間至少要有三次 scrape：`prometheus-apply.yml` 拒絕 `login_probe_stale_seconds` < 3 ×
  `prometheus_scrape_interval`（否則健康的 probe 會被當成停擺，`PilotLoginProbeStale` 會抑制它所有告警）。
- `prometheus-apply.yml` 對 `host_metrics_missing_success_window` 有兩道 gate：時間窗 + 15s（probe 的
  textfile 寫出間隔）不得超過 `host_metrics_missing_for`，否則掛掉的主機可能觸發 `HostMetricsMissing`
  並抑制它的 `HostDown`；而每台 login-probe 主機的 `login_probe_interval` + `login_probe_total_timeout`
  + 15s + 一次 scrape 不得超過時間窗，否則資料缺口期間 `HostMetricsMissing` 會中斷。後者讀
  `login-probe` group 每台主機的 hostvars（預設 60s / 30s，與 `login-probe-apply.yml` 相同）；預設
  140s 兩邊各留 15–20s 餘裕（60 + 30 + 15 + 15 = 120 ≤ 140，140 + 15 = 155 ≤ 180）。

`internal/spec/alertmanager_inhibit_regression_test.go::TestRegression_AlertmanagerInhibitBehaviour`
用 pinned 的 Alertmanager 實際跑兩種內建設定，確認哪些告警被抑制；
`internal/spec/testdata/host-health-alert-rules.promtest.yml` 用 promtool 鎖住時序。
CI 的 `Playbook lint` job 會跑 `make alert-rules-test`：pull image，並且不允許 skip。

`group_by` 仍是 `alertname + pilot_subject + signal_id`：login probe 告警沒有後兩者，
所以同一個 alertname 的所有主機會併成一則通知（整站 HBAC 失效時不會每台主機各一則）。

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | docker | `pilot-alertmanager` container 存在且 running | ~pilot-alertmanager | docker ps --no-trunc 2>/dev/null | grep -m1 -oE 'pilot-alertmanager' | head -n1 |
| C2 | http | Alertmanager `/-/healthy`（9093）回 200 | ~200 | curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:9093/-/healthy |
| C3 | http | Alertmanager `/-/ready`（9093）回 200 | ~200 | curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:9093/-/ready |
| C4 | config | `alertmanager.yml` 語法有效 (`amtool check-config`) | 0 | sh -c 'docker exec pilot-alertmanager amtool check-config /etc/alertmanager/alertmanager.yml >/dev/null 2>&1' |
| C5 | config | `alertmanager.yml` 含 route 區塊（YAML 或 JSON） | 0 | sh -c 'grep -qE "(^[[:space:]]*route:|\"route\"[[:space:]]*:)" /etc/pilot/alertmanager/alertmanager.yml' |
| C6 | http | API `/api/v2/status` 回 200 | ~200 | curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:9093/api/v2/status |
| C7 | functional | 推一筆測試告警至 Alertmanager，`/api/v2/alerts` 可查得 | 0 | sh -c 'curl -fsS -X POST http://127.0.0.1:9093/api/v2/alerts -H "Content-Type: application/json" -d "[{\"labels\":{\"alertname\":\"pilot-alertmanager-selftest\",\"severity\":\"info\"},\"annotations\":{\"msg\":\"PILOT-ALERTMANAGER-SELFTEST\"}}]" >/dev/null 2>&1; sleep 1; curl -fsS http://127.0.0.1:9093/api/v2/alerts | grep -q pilot-alertmanager-selftest' |
| C8 | docker | `pilot-alertmanager-teams-proxy`（teams 模式才存在）若存在則必須為 running 且 `/healthz` 回 200；non-teams 模式下容器不存在也算通過 | 0 | sh -c 'if docker ps -a --no-trunc 2>/dev/null | grep -q pilot-alertmanager-teams-proxy; then docker ps --no-trunc 2>/dev/null | grep -q pilot-alertmanager-teams-proxy && curl -fsS -o /dev/null -w "%{http_code}" http://127.0.0.1:8095/healthz 2>/dev/null | grep -q "^200$"; else true; fi' |
| C9 | functional | proxy 的 Alertmanager→Adaptive Card 轉換正確（`/render` 自我測試，不真的送 Teams）；容器不存在（non-teams 模式）也算通過 | 0 | sh -c 'if docker ps -a --no-trunc 2>/dev/null | grep -q pilot-alertmanager-teams-proxy; then curl -fsS -X POST http://127.0.0.1:8095/render -H "Content-Type: application/json" -d "{\"status\":\"firing\",\"groupLabels\":{\"alertname\":\"pilot-teams-proxy-selftest\"},\"alerts\":[{\"status\":\"firing\",\"labels\":{\"alertname\":\"pilot-teams-proxy-selftest\",\"severity\":\"info\"},\"annotations\":{}}]}" 2>/dev/null | grep -q "\"type\": \"AdaptiveCard\""; else true; fi' |
| C10 | config | 執行中的 Alertmanager 載入的設定（`amtool config show`，不是磁碟上的檔案）帶 GitHub issue #11 的兩條 inhibit 規則，內容逐字相符：`HostMetricsMissing` 抑制同 `pilot_host`、同 `site` 的 `HostDown{job="node"}`；`PilotLoginProbeStale` 抑制同 `probe_host`、同 `site` 的其他 `PilotLoginProbe*`。舊版（`HostDown` 當來源、`equal: site`）或少了 `site` 的規則都會 FAIL（`custom` 模式的設定也必須帶，見 §1.7） | 0 | sh -c 'r=$(docker exec pilot-alertmanager amtool config show --alertmanager.url=http://127.0.0.1:9093 2>/dev/null | awk "/^inhibit_rules:/{f=1;next} f&&/^[^ -]/{f=0} f&&/^- /{if(r!=\"\")print r;r=\"\"} f{sub(/^[ -]+/,\"\");r=r\" \"\$0} END{if(r!=\"\")print r}"); printf "%s\n" "$r" | grep -qxF " source_matchers: alertname=\"HostMetricsMissing\" target_matchers: alertname=\"HostDown\" job=\"node\" equal: pilot_host site" && printf "%s\n" "$r" | grep -qxF " source_matchers: alertname=\"PilotLoginProbeStale\" target_matchers: alertname=~\"PilotLoginProbe(AccountDenied|AuthFailed|LoginStalled|HostKeyMismatch|SessionFailed|TransportFailed|NoTargets)\" equal: probe_host site"' |

## 3. 證據收集

- 工具：`pilot verify docs/verification/alertmanager.md -i <inventory> -l alertmanager`
- 輸出格式：`.verification/alertmanager-<UTC>.{ndjson,md}`
- 預期 row 數：10
- 最新 actual-run evidence：`docs/evidence/login-probe/2026-10-15-243987b.md`
  （2026-10-15，candidate `243987b`，tree `f51ec98b`；全新 4 台 vm-target，`null` mode；L1-L6 PASS，
  本 spec 10/10 PASS（run `058add65-c90f-4aa4-934f-7031796c5f19`）；C10 經真實 verify pipeline 對已部署的
  Alertmanager PASS、對載入 `a742ad9` 舊規則的 Alertmanager FAIL；同一輪在真實 Alertmanager 上實測資料缺口
  （含 probe 單輪失敗）、整台主機停擺、兩台 probe 其中一台停擺的抑制行為）。
- 歷史：Teams mode 的 `/render` 與通知實測見 `docs/evidence/alertmanager/2026-09-17-30d6b92.md`
  （當時 9 個 row，早於 C10 與 issue #11 的 inhibit 規則）。

## 4. PASS / FAIL 規則

- C1–C7 全部 `status=pass` → **PASS**：Alertmanager 已就緒、可接收告警。
- 任一 `fail` → **FAIL**，見 §5 常見修法。

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|----------|----------|------|
| C5 | `null` receiver mode 僅含 stub route 仍屬正常；Teams webhook 的實際送達需由經授權的通知測試確認 | 所有環境 | 永久 |
| C8/C9 | `pilot-alertmanager-teams-proxy` 只在 `alertmanager_receiver_mode=teams` 時部署；null/custom 模式下容器不存在，兩個 row 皆設計成視為通過（見 Command 欄的 `if docker ps -a ... ; else true; fi` 分支） | 所有環境 | 永久 |

## 6. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-10-16 | v1.12 | PR #80 第七輪 review：第 1 點寫明餘裕（時間窗 + 15s textfile 寫出 ≤ `host_metrics_missing_for`）；第 2 點補上 probe 太慢時的 fail-safe 行為；`host_metrics_missing_success_window` 預設改為 140s，`prometheus-apply.yml` 新增兩道 gate（時間窗 + 15s ≤ `for`；probe 主機的 interval + total_timeout + 15s + 一次 scrape ≤ 時間窗），promtool 鎖住邊界 | sre |
| 2026-10-15 | v1.11 | PR #80 第六輪 review：`HostMetricsMissing` 改看 target 自己的 last-success 時間戳在 `host_metrics_missing_success_window`（預設 2m，必須短於 `host_metrics_missing_for`）內有沒有變化，不再看 probe 的 textfile 心跳；掛掉的主機因此永遠不會觸發它（probe 停擺、晚一輪停擺、或大量主機同時掛掉讓一輪跑很久都一樣），第 1 點的例外刪除，promtool 鎖住三種情況 | sre |
| 2026-10-15 | v1.10 | PR #80 第五輪 review：§1.7 第 1 點補上例外（probe 在 target 掛掉後一輪內才停擺時，`HostMetricsMissing` 會誤報幾分鐘，`HostDown` 照常送出），promtool 案例鎖住；延遲上限收緊為約 6m15s 與約 8m（`keep_firing_for` 從第一次不成立的評估開始算） | sre |
| 2026-10-15 | v1.9 | PR #80 第四輪 review：§1.7 的延遲改寫成推導出的上限（node_exporter 恢復後約 7m15s，實測 5m41s；資料缺口期間主機掛掉時 `HostDown` 約 9m 後才解除抑制）；補上 probe 新鮮度的 scrape 間隔前提與 `host_metrics_missing_for` ≥ `login_probe_stale_seconds`（`prometheus-apply.yml` 新增的兩道 gate） | sre |
| 2026-10-15 | v1.8 | PR #80 第三輪 review：C10 改讀執行中 Alertmanager 載入的設定（`amtool config show`），要求兩條 inhibit 規則逐字相符，舊規則與少了 `site` 的規則都會 FAIL（`TestRegression_AlertmanagerC10DistinguishesInhibitRules` 對真的 Alertmanager 跑 C10）；兩條規則的 `equal` 加上 `site`；`HostMetricsMissing` 加 `keep_firing_for`，probe 新鮮度改用 `changes()`；§1.7 補前提（`node_exporter_targets`、probe 間隔）；標頭版本對齊變更紀錄 | sre |
| 2026-10-15 | v1.7 | GitHub issue #11 / PR #80 review：改寫兩條 inhibit（§1.7、C10）。舊規則讓 `HostDown`（10m）抑制先觸發的 `HostMetricsMissing`，資料缺口反而只剩「Target down」；`PilotLoginProbeStale` 以 `site` 比對，一台 probe 停擺會抑制整站其他 probe 的告警。改為 `HostMetricsMissing` 抑制同主機的 `HostDown{job="node"}`，`PilotLoginProbeStale` 只比對 `probe_host`。「整台主機掛掉只產生 `HostDown`」改由規則本身保證。新增實際啟動 Alertmanager 的行為測試，CI 也會跑 | sre |
| 2026-10-13 | v1.6 | GitHub issue #11：`null`/`teams` 模式內建 HostDown 與 PilotLoginProbeStale 兩條 inhibit 規則（§1.7），新增 C10；`custom` 模式需自行加入 | sre |
| 2026-09-17 | v1.5 | Teams 僅接收 critical／明確 actionable warning；以 subject + signal 分組、12h repeat，卡片顯示行動資訊；candidate `30d6b92` L1-L6 target evidence PASS | sre |
| 2026-09-08 | v1.4 | 新增 `pilot-alertmanager-teams-proxy`：Alertmanager 原生 webhook_configs 無法直接餵給要求 Adaptive Card 的 Teams flowbot（Power Automate「當收到 Teams webhook 要求」觸發器），改成 webhook 先打內部 proxy 做格式轉換再轉發；新增 C8/C9 | sre |
| 2026-09-08 | v1.3 | 新增 null/custom/teams receiver mode 與單一 Teams webhook vault 契約 | sre |
| 2026-07-22 | v1.2 | C5 同時支援 Alertmanager 接受的 YAML 與 JSON config，避免合法 compact JSON 被誤判 | sre |
| 2026-07-22 | v1.1 | 修正 Targets table 欄位，讓 verifier 以 `alertmanager` inventory group 解析實際主機 | sre |
| 2026-07-07 | v1.0 | 初版 | sre |
