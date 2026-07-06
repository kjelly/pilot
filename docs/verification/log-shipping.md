# Verification Spec — log-shipping (Promtail：log-server → dashboard Loki)

> 版本：v1.0
> 對齊規範：pilot 通用 container-backed 服務規範（比照 `audit-log-forwarding.md`
> 的「client 端疊一個轉送 agent、central 端固定變數」模式）
> 維護者：sre

> 這是疊在 `log-server.md`**之上**、不修改它本體的一個角色（見
> `log-server.md` 該檔自己留的伏筆："查詢/dashboard 需求可日後在此之上
> 疊 Promtail→Loki，不影響本 spec"）。目標 group 跟 `log-server.md` 相同
> （同一台主機、兩個角色疊加），把 `{{ siem_log_root }}`（預設
> `/var/log/siem`）底下已經落地的檔案 tail 起來，轉送進
> `dashboard.md` 那台主機的 Loki，讓 Grafana 可以查。跟既有的
> `audit-log-forwarding.md`（client 填 `-e central_host`）是同一種
> 「agent 端知道中央位址」慣例——跟 `thanos-query.md` 那組「中央自動探索
> 站台」的反向模式不同，這裡沒有反過來的理由：Promtail 本來就需要主動
> push，沒有「中央自動發現 log-server 有哪些」的對應機制。

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Hostname / Inventory group | log-server（跟 `log-server.md` 同一台，角色疊加） |
| OS / version | Ubuntu 24.04 LTS / EL9 |
| 角色 | Promtail docker container，tail 本機 `siem_log_root` 下的檔案並 push 到中央 Loki |
| 套用範圍 | `/etc/pilot/promtail/`、`/etc/hosts`（一行 alias pin） |
| 風險等級 | Low（唯讀 tail 既有日誌檔，不寫入來源系統；對外只有出站 HTTP push） |

## 1.5 依賴變數契約

在套用或驗證此主機時，Playbook 與變數參數必須嚴格遵守以下命名，禁止擅自縮寫或發明新變數：

| 變數名稱 | 說明/用途 | 是否必填 | 預設值 |
|---------|----------|---------|--------|
| `loki_target_host` | `dashboard.md` 中央主機的 IP/FQDN（Loki 所在地） | 否（見下方 escape hatch） | 空字串 |
| `loki_alias` | 上面那個 IP 對應的 `/etc/hosts` 別名 | 否 | `pilot-loki-backend` |
| `loki_port` | Loki push API port | 否 | `3100` |
| `loki_endpoint` | 完整覆寫 Loki push endpoint（`host:port`），跳過 `loki_alias` 的 `/etc/hosts` pin | 否 | `"{{ loki_alias }}:{{ loki_port }}"` |
| `siem_log_root` | 要 tail 的根目錄；**必須跟 `log-server.md` 用同一個值**，否則 tail 不到東西 | 否 | `/var/log/siem` |
| `promtail_job_label` | Promtail 幫這批日誌打的 `job` label 值，Loki 查詢用來篩選 | 否 | `pilot-siem` |

> `loki_target_host` 留空時套用不會 fail（跟 `dashboard.md` 的
> `thanos_query_target_host` 同一種「上游還沒接上」正常狀態），Promtail
> 會照樣起來、只是 push 目標打不通，C6（跨主機功能性驗證）會如預期
> fail——見 §5。
>
> `siem_log_root` 跟 `log-server.md` 共用同一組變數名稱、同一個值，
> 是刻意設計（比照 `thanos_s3_bucket` 同時給 `prometheus.md` 跟
> `thanos-query.md` 共用的理由）：避免兩邊各自維護一份路徑、只在跑到
> C6 那一刻才發現對不上。

## 2. Checklist

| ID  | Category | Check                                                              | Expected | Command |
|-----|----------|----------------------------------------------------------------------|----------|---------|
| C1  | docker   | `pilot-promtail` container 存在且 running                             | ~pilot-promtail | docker ps --no-trunc 2>/dev/null | grep -m1 -oE 'pilot-promtail' | head -n1 |
| C2  | http     | Promtail `/ready`（9080）回 200                                       | ~200 | curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:9080/ready |
| C3  | config   | Promtail 設定檔含 `siem_log_root` 的 scrape glob                       | 0 | grep -qE '__path__:\s*/var/log/siem/\*\*/\*\.log' /etc/pilot/promtail/promtail-config.yml; echo $? |
| C4  | config   | Promtail 設定檔的 push 目標指向 `pilot-loki-backend` 別名                | 0 | grep -qE 'url:\s*"http://pilot-loki-backend:3100/loki/api/v1/push"' /etc/pilot/promtail/promtail-config.yml; echo $? |
| C5  | network  | `/etc/hosts` 已 pin `pilot-loki-backend` 別名                          | 0 | grep -qE '\spilot-loki-backend$' /etc/hosts; echo $? |
| C6  | functional | 本機注入唯一測試訊息，透過 Promtail 轉送後，向中央 Loki 查詢確實查到    | ~PILOT-LOGSHIP-SELFTEST | sh -c 'logger -p local6.info "PILOT-LOGSHIP-SELFTEST-$$"; sleep 6; curl -fsS -G http://pilot-loki-backend:3100/loki/api/v1/query --data-urlencode "query={job=\"pilot-siem\"}" | grep -o "PILOT-LOGSHIP-SELFTEST-[0-9]*"; true' |
| C7  | dir      | Promtail positions 檔目錄存在（記錄 tail 進度，重啟不重複轉送）          | present | test -d /var/lib/pilot/promtail |

> C3/C4 的路徑/別名是固定字串，不是變數內插——`siem_log_root`/`loki_alias`
> 若被覆寫成非預設值，這兩行在該環境下屬已知偏差（見 §5），不是本 spec
> 的責任範圍（比照 `prometheus.md` C8 只驗預設情境的既有慣例）。
> C6 用 `~contains` 而非 `^` 錨點，且用 `; true` 吸收 grep 找不到時的
> non-zero rc，避免 wrapper 把「還沒轉送到」的合法 FAIL 結果變成不可
> 判讀的 ansible FAILED 輸出（`verification-spec-template.md` 陷阱 2）。
> 測試訊息帶 `$$`（shell PID）是為了讓每次驗證的字串都不同，避免查到
> 上一輪驗證留下的舊資料造成偽陽性；`grep -o` 只驗證有匹配到這個模式
> （不驗證精確 PID 值），因為 Command/Expected 欄位不能因每次執行而變。

## 3. 證據收集

- 工具：`pilot verify docs/verification/log-shipping.md -i <inventory> -l log-server`
- 輸出格式：`.verification/log-shipping-<UTC>.{ndjson,md}`
- 預期 row 數：7

## 4. PASS / FAIL 規則

- C1–C5, C7 全部 pass 且 C6 pass → **PASS**：日誌確實從這台轉送到中央 Loki
- C1–C5, C7 pass 但 C6 fail → Promtail 本身健康，只是還沒接到中央 Loki（見 §1.5、§5）
- 任一 C1–C5, C7 fail → **FAIL**，常見修法：
  - C1 fail → container 沒起；`docker logs pilot-promtail`
  - C2 fail → 設定檔語法錯或掛載路徑錯
  - C3/C4 fail → apply playbook 的 template task 沒 render 成功
  - C5 fail → `loki_target_host` 沒填或 `/etc/hosts` pin task 沒跑到
  - C6 fail → 先確認 C1–C5 都 pass；再檢查中央 `dashboard.md` 的 Loki 是否真的在跑（`dashboard.md` C1/C3）、網路是否可達（`pilot-loki-backend` 別名解析、防火牆）
  - C7 fail → 目錄沒建立（volume 掛載會自動建，除非 apply 漏了 file task）

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C6 | `loki_target_host` 未填或 `dashboard.md` 尚未部署時，這行預期 fail | dashboard 尚未上線的環境 | 直到 `dashboard.md` PASS 為止 |
| C3, C4 | `siem_log_root`/`loki_alias` 被覆寫成非預設值時，這兩行的固定字串比對會 fail（功能本身仍正常，只是驗證用的字串跟著變了） | 覆寫了預設路徑/別名的環境 | 視站台設定 |

## 6. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-06 | v1.0 | 初版 | sre |
