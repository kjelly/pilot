# Verification Spec — alertmanager (central Alertmanager for all sites)

> 版本：v1.4
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

## 3. 證據收集

- 工具：`pilot verify docs/verification/alertmanager.md -i <inventory> -l alertmanager`
- 輸出格式：`.verification/alertmanager-<UTC>.{ndjson,md}`
- 預期 row 數：9

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
| 2026-09-08 | v1.4 | 新增 `pilot-alertmanager-teams-proxy`：Alertmanager 原生 webhook_configs 無法直接餵給要求 Adaptive Card 的 Teams flowbot（Power Automate「當收到 Teams webhook 要求」觸發器），改成 webhook 先打內部 proxy 做格式轉換再轉發；新增 C8/C9 | sre |
| 2026-09-08 | v1.3 | 新增 null/custom/teams receiver mode 與單一 Teams webhook vault 契約 | sre |
| 2026-07-22 | v1.2 | C5 同時支援 Alertmanager 接受的 YAML 與 JSON config，避免合法 compact JSON 被誤判 | sre |
| 2026-07-22 | v1.1 | 修正 Targets table 欄位，讓 verifier 以 `alertmanager` inventory group 解析實際主機 | sre |
| 2026-07-07 | v1.0 | 初版 | sre |
