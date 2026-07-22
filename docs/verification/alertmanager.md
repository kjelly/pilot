# Verification Spec — alertmanager (central Alertmanager for all sites)

> 版本：v1.2
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
| `alertmanager_config` | 完整 `alertmanager.yml` 內容 (vault 建議) | 否 | (seed stub,只含 null receiver) |
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

## 3. 證據收集

- 工具：`pilot verify docs/verification/alertmanager.md -i <inventory> -l alertmanager`
- 輸出格式：`.verification/alertmanager-<UTC>.{ndjson,md}`
- 預期 row 數：7

## 4. PASS / FAIL 規則

- C1–C7 全部 `status=pass` → **PASS**：Alertmanager 已就緒、可接收告警。
- 任一 `fail` → **FAIL**，見 §5 常見修法。

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|----------|----------|------|
| C5 | `alertmanager_config` 尚未覆寫,僅有 stub `null` receiver，仍屬正常（只要 YAML `route:` 或 JSON `"route"` 存在） | 所有環境 | 永久 |

## 6. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-22 | v1.2 | C5 同時支援 Alertmanager 接受的 YAML 與 JSON config，避免合法 compact JSON 被誤判 | sre |
| 2026-07-22 | v1.1 | 修正 Targets table 欄位，讓 verifier 以 `alertmanager` inventory group 解析實際主機 | sre |
| 2026-07-07 | v1.0 | 初版 | sre |
