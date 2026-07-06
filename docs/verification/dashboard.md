# Verification Spec — dashboard (Grafana + Loki，跨機房 Metrics/Log 觀測入口)

> 版本：v1.1
> 對齊規範：pilot 通用 container-backed 服務規範（比照 `thanos-query.md`/
> `seaweedfs-s3.md` 的 docker container 模式）
> 維護者：sre

> 這是「觀測三角」的最後一塊：`prometheus.md`（各站 metrics）+
> `thanos-query.md`（跨站 metrics 全局查詢）+ `log-server.md`（中央日誌
> 落地）已經分別把資料生出來、集中起來，但都只有各自的 CLI/HTTP API，
> 沒有一個給人看的畫面。本角色是**純消費端**：Grafana 對 `thanos-query`
> 的 Prometheus-compatible API（10902）跟本機 Loki 開兩個唯讀
> datasource，Loki 則負責接 `log-shipping.md`（跑在 `log-server` 主機上
> 的 Promtail agent）轉送過來的日誌。跟 `thanos-query` 一樣是本專案的
> 中央單例角色（比照 `wazuh-manager`/`log-server`）。
>
> **v1.1**:在 v1.0 的 datasource provisioning 之上,加兩份預先寫好的
> Grafana dashboard(見 §1.6)。**環境自動化設定的機制是 Grafana 原生
> template variable**(`label_values()` 查詢),不是 Ansible 在套用時讀
> inventory 動態產生 dashboard JSON——兩份 dashboard 的 JSON 內容在所有
> 環境都完全一樣(固定字串,不隨站台/主機數量改變),畫面上的下拉選單在
> **瀏覽器端**即時查詢 Thanos/Loki 現有哪些 `site`/`job` label 值。這代表
> 新增一個 `prometheus` 站台或 `log-server` 主機後,dashboard 會自動出現
> 新選項,**完全不需要重新套用這份 playbook**——跟 `thanos-query-apply.yml`
> 的 `--store` 清單「inventory 變動就必須重新套用」是刻意不同的設計:
> Grafana dashboard 在瀏覽器執行期本來就可以做到即時反應,沒有理由選擇
> 「重新套用才會反應」這種更笨重的做法。(使用者已確認採用此方案，見
> 對話紀錄——另一個選項是 Ansible 讀 inventory 動態產生每站/每主機各自
> 面板，優點是一進畫面就並排看到全部，缺點是環境變動必須重新套用。)

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Hostname / Inventory group | dashboard |
| OS / version | Ubuntu 24.04 LTS / EL9（docker container 為主，OS 版本差異小） |
| 角色 | Grafana（畫面）+ Loki（日誌儲存與查詢），皆為 docker container |
| 套用範圍 | `/etc/pilot/grafana/`、`/etc/pilot/loki/`、`/var/lib/pilot/grafana/`、`/var/lib/pilot/loki/` |
| 風險等級 | Low（純觀測用途，不寫入任何來源系統；Grafana admin 密碼外洩才有風險） |

> 設計上只需要一台（跟 `thanos-query`/`log-server` 一樣是單一中央角色）。

## 1.5 依賴變數契約

在套用或驗證此主機時，Playbook 與變數參數必須嚴格遵守以下命名，禁止擅自縮寫或發明新變數：

| 變數名稱 | 說明/用途 | 是否必填 | 預設值 |
|---------|----------|---------|--------|
| `thanos_query_target_host` | `thanos-query.md` 中央主機的 IP/FQDN，套用時會被 pin 進 `/etc/hosts`（比照 `thanos_s3_target_host`/`restic_s3_target_host` 的既有慣例） | 否（見下方 escape hatch） | 空字串 |
| `thanos_query_alias` | 上面那個 IP 對應的 `/etc/hosts` 別名；Grafana 的 Prometheus datasource URL 與 C8 都指向這個固定別名，不是變數內插的 IP | 否 | `thanos-query-backend` |
| `thanos_query_port` | Thanos Query 的 Prometheus-compatible API port | 否 | `10902` |
| `grafana_admin_password` | Grafana admin 密碼（`GF_SECURITY_ADMIN_PASSWORD`） | 是 | 無 |
| `grafana_host_data_dir` | Grafana 資料目錄（dashboards/session 等） | 否 | `/var/lib/pilot/grafana` |
| `loki_host_data_dir` | Loki 資料目錄（chunks/index） | 否 | `/var/lib/pilot/loki` |
| `dashboard_config_dir` | Grafana/Loki 設定檔根目錄 | 否 | `/etc/pilot/dashboard` |

> `thanos_query_target_host` 留空且套用時不會 fail（跟 `thanos-query.md`
> 的 `prometheus` group 可為空是同一種「上游還沒接上」正常狀態），但
> Grafana 的 Prometheus datasource 會指向一個打不通的位址，C8（連通性）
> 會如預期 fail——不是 bug，見 §5。**跟 S3 目的地那組 gate 不同**：這裡
> 不做「必須可解析」的啟動前 assert，因為 dashboard 通常會比
> `thanos-query` 早或晚上線，先把 Grafana/Loki 立起來、之後再補
> `thanos_query_target_host` 重新套用是合理的操作順序。
>
> Grafana 的兩個 datasource UID 是 apply playbook **寫死**的固定值
> （`pilot-loki`、`pilot-thanos-query`），不是 Grafana 自動產生的隨機
> UID——這樣 spec 的 Command/Expected 才能寫死字串去檢查 provisioning
> 檔案內容，不用先呼叫 API 查 UID 再組第二個指令。

## 1.6 內建 dashboard 內容

| Dashboard | uid（固定） | Datasource | Template variable | 用途 |
|-----------|------------|------------|--------------------|------|
| Pilot - Sites Overview | `pilot-sites-overview` | `pilot-thanos-query` | `site`(查詢 `label_values(up, site)`) | 看每一站 Prometheus 是否 up,`up{site=~"$site"}` |
| Pilot - Logs Explorer | `pilot-logs-explorer` | `pilot-loki` | `job`(查詢 Loki label values,label=`job`) | 瀏覽 `log-shipping.md` 轉送進來的日誌,`{job=~"$job"}` |

兩份都用實際起 Grafana + 真實 Prometheus/Loki 資料,在瀏覽器（Playwright）
裡開啟確認過:`site` 變數正確列出 `site-a`/`site-b`、面板顯示正確的
`up` 計數;`job` 變數正確列出真實 job 值、Logs 面板顯示真實日誌內容——
不是只驗證 JSON 語法正確,是真的能用。

## 2. Checklist

| ID  | Category | Check                                                                 | Expected | Command |
|-----|----------|------------------------------------------------------------------------|----------|---------|
| C1  | docker   | `pilot-loki` container 存在且 running                                  | ~pilot-loki | docker ps --no-trunc 2>/dev/null | grep -m1 -oE 'pilot-loki' | head -n1 |
| C2  | docker   | `pilot-grafana` container 存在且 running                                | ~pilot-grafana | docker ps --no-trunc 2>/dev/null | grep -m1 -oE 'pilot-grafana' | head -n1 |
| C3  | http     | Loki `/ready`（3100）回 200                                             | ~200 | curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:3100/ready |
| C4  | http     | Grafana `/api/health`（3000）回 200                                     | ~200 | curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:3000/api/health |
| C5  | config   | Grafana provisioning 檔含 Loki datasource（固定 uid `pilot-loki`）       | 0 | grep -qE 'uid:\s*pilot-loki' /etc/pilot/dashboard/grafana/provisioning/datasources/datasources.yml; echo $? |
| C6  | config   | Grafana provisioning 檔含 Prometheus datasource（固定 uid `pilot-thanos-query`） | 0 | grep -qE 'uid:\s*pilot-thanos-query' /etc/pilot/dashboard/grafana/provisioning/datasources/datasources.yml; echo $? |
| C7  | functional | Loki 本機注入一筆帶唯一 job label 的測試日誌，query 回同一筆              | ~PILOT-DASHBOARD-SELFTEST | sh -c 'curl -fsS -X POST http://127.0.0.1:3100/loki/api/v1/push -H "Content-Type: application/json" -d "{\"streams\":[{\"stream\":{\"job\":\"pilot-dashboard-selftest\"},\"values\":[[\"$(date +%s%N)\",\"PILOT-DASHBOARD-SELFTEST\"]]}]}"; sleep 2; curl -fsS -G http://127.0.0.1:3100/loki/api/v1/query --data-urlencode "query={job=\"pilot-dashboard-selftest\"}"' |
| C8  | network  | `thanos-query-backend`別名（Prometheus datasource 上游）連通性           | ~200 | curl -fsS -o /dev/null -w '%{http_code}' --max-time 5 http://thanos-query-backend:10902/-/healthy |
| C9  | dir      | Grafana 資料目錄存在（dashboards/session 持久化）                        | present | test -d /var/lib/pilot/grafana |
| C10 | dir      | Loki 資料目錄存在（chunks/index 持久化）                                 | present | test -d /var/lib/pilot/loki |
| C11 | file     | Grafana dashboard provisioning provider 設定檔存在                     | present | test -f /etc/pilot/dashboard/grafana/provisioning/dashboards/dashboards.yml |
| C12 | config   | `Pilot - Sites Overview` dashboard 檔存在且固定 uid 正確                 | 0 | grep -qE '"uid":\s*"pilot-sites-overview"' /etc/pilot/dashboard/grafana/dashboards-json/sites-overview.json; echo $? |
| C13 | config   | `Pilot - Logs Explorer` dashboard 檔存在且固定 uid 正確                  | 0 | grep -qE '"uid":\s*"pilot-logs-explorer"' /etc/pilot/dashboard/grafana/dashboards-json/logs-explorer.json; echo $? |
| C14 | functional | Grafana dashboard provisioning 沒有載入錯誤（僅看本次啟動之後）        | 0 | sh -c '! docker logs --since "$(docker inspect pilot-grafana | sed -n "s/.*\"StartedAt\": \"\([^\"]*\)\".*/\1/p" | head -1)" pilot-grafana 2>&1 | grep -q "logger=provisioning.dashboard.*level=error"' |

> C14 會觸發 `pilot spec --lint` 的「reverse-logic grep for a failure
> token」warning(誤判):linter 只用 regex 判斷「pipe 進 grep + 比對字串
> 含 `error` + expected 是數字」,沒有能力判斷指令開頭已經有 `!` 把整條
> pipeline 的結果反過來——健康路徑(沒有 error)下 `grep -q` 回 1,`!`
> negate 成 0,跟 expected `0` 是同一個正邏輯方向,不是 linter 想攔的
> 反邏輯陷阱(`... | grep -q STOPPED` expected `1` 那種)。已經用
> vm-target 實測驗證這個 `!` 寫法在 ansible ad-hoc 下行為正確(見
> `docs/runbooks/dashboard.md`)。
>
> C14 用 `docker logs --since "$(docker inspect pilot-grafana | sed -n '...' | head -1)"`
> 把檢查範圍限定在「這個 container 這一次啟動之後」,不是整個 container
> 生命週期的完整歷史——`docker logs`(不加 `--since`)預設會回傳從
> container 第一次建立以來累積的**全部**輸出,單純 `docker restart`
> 也不會清掉這份歷史。曾經修過的舊錯誤(例如手動誤放過一份壞掉的
> dashboard JSON,後來已經移除)如果不限定時間範圍,會讓 C14 永遠 fail
> 下去,直到 container 被整個 rm+recreate——這是實測 negative path 時
> 發現的真問題,不是憑空假設。
>
> 抓 container 啟動時間**不能**用 `docker inspect -f '{{ .State.StartedAt }}'`
> 這種 docker 自己的 Go template 語法(即使跟 `docker.md` C6 的
> `docker network ls --format '{{.Name}}'` 長得像、看似既有慣例）——
> 實測（`pilot verify --probe`）證實 **ansible ad-hoc 的 `-m shell`/
> `-a "..."` 確實會對整個 Command 字串跑 Jinja finalization**，任何
> `{{ ... }}` 都會被當成 Jinja 表達式解析，`{{.Name}}`/`{{.State.
> StartedAt}}` 這種開頭是 `.` 的寫法對 Jinja 是語法錯誤（"unexpected
> '.'"），導致整個 task 直接 FAILED（rc=2 + 一段看起來無關的
> deprecation warning，跟 v1.0 `{{ dashboard_config_dir }}` 那個 bug
> 的症狀一模一樣）——**`docker.md` C6 本身其實也踩在這個坑上**（已用
> `--probe` 證實會 FAIL，屬於本 repo既有 spec 的既存缺陷，不在本次
> `dashboard.md` 改動範圍內，另案處理）。C14 改用 `docker inspect`
> 印出完整 JSON 再用 `sed` 擷取 `StartedAt` 欄位值，全程不出現任何
> `{{`/`}}` 字元，避開這個 Jinja finalization 陷阱。

> C7 不檢查真正跨主機轉送（那是 `log-shipping.md` 的 C6 cross-host
> functional check），只證明 Loki 自己「收得進去、查得出來」正常運作，
> 隔離 Grafana/Loki 本身的問題跟 Promtail 轉送鏈路的問題，方便先定位是
> 哪一段壞掉。
> C8 跟 Grafana 的 Prometheus datasource URL 都指向 `thanos-query-backend`
> 這個固定別名，不是內插變數——比照 `thanos_s3_alias`/`restic_s3_target_host`
> 的既有慣例，把部署期才知道的 IP 藏進 apply playbook 寫入的 `/etc/hosts`，
> 讓 spec 的 Command/Expected 欄位維持固定字串（見 `verification-spec-template.md`
> 「Command/Expected 是靜態文字，不能內插」的規則）。

## 3. 證據收集

- 工具：`pilot verify docs/verification/dashboard.md -i <inventory> -l dashboard`
- 輸出格式：`.verification/dashboard-<UTC>.{ndjson,md}`
- 預期 row 數：14

## 4. PASS / FAIL 規則

- C1–C7, C9–C14 全部 pass 且 C8 pass → **PASS**：Grafana/Loki 就緒、內建 dashboard 都正確載入，且能連到 `thanos-query`
- C1–C7, C9–C14 pass 但 C8 fail → 觀測面板本身健康，只是 Prometheus 上游還沒接上（見 §1.5、§5），不算 dashboard 損壞
- 任一 C1–C7, C9–C14 fail → **FAIL**，常見修法：
  - C1/C2 fail → container 沒起；`docker logs pilot-loki` / `pilot-grafana`
  - C3 fail → Loki 啟動中（實測需要約 10–15 秒完成 ring join 才會 ready，非 bug，見 §5）或設定檔語法錯
  - C4 fail → Grafana 啟動失敗；常見原因是 `grafana_admin_password` 未設定
  - C5/C6 fail → provisioning 檔沒 render 成功或路徑不對；檢查 apply playbook 的 template task
  - C7 fail → Loki push/query API 本身有問題，跟轉送鏈路無關
  - C8 fail → `thanos_query_target_host` 沒填、填錯，或該主機的 `thanos-query.md` 尚未套用/防火牆擋住 10902
  - C9/C10 fail → 目錄沒建立或權限有誤導致 container 啟動失敗（見 §5 uid 備註）
  - C11 fail → dashboard provisioning provider 設定檔沒 render 成功；檢查 apply playbook 的 template task
  - C12/C13 fail → 對應的 dashboard JSON 檔沒 render 成功，或 uid 被意外改掉
  - C14 fail → `docker logs pilot-grafana` 找 `provisioning.dashboard` 開頭的 `level=error` 那幾行，通常是 dashboard JSON 語法錯（改壞了某份 dashboard 檔）

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C3 | Loki 啟動後約需 10–15 秒完成 ring/compactor join 才會回 200（`/ready` 在此之前回 503）；apply playbook 的 wait 迴圈已內建重試，純手動 curl 驗證時遇到 503 屬正常暖機期 | 所有環境 | 永久（Loki 設計如此） |
| C8 | `thanos_query_target_host` 未填或該中央尚未部署時，這行預期 fail | dashboard 早於 thanos-query 上線的環境 | 直到 `thanos-query.md` PASS 為止 |
| C5, C6, C9, C10, C11, C12, C13 | 這幾行的固定路徑（`/etc/pilot/dashboard/...`、`/var/lib/pilot/grafana`、`/var/lib/pilot/loki`）是 `dashboard_config_dir`/`grafana_host_data_dir`/`loki_host_data_dir` 的**預設值**；覆寫成非預設路徑的環境，這幾行會如預期 fail（功能本身仍正常） | 覆寫了預設路徑的環境 | 視站台設定 |
| C12, C13 | `prometheus`/`log-server` 尚未部署時,兩份 dashboard 的 template variable 下拉選單會是空的(沒有 site/job 可選),但 dashboard 本身仍正確載入,C12/C13 仍應 pass——這兩行只驗證 dashboard 檔本身,不驗證裡面查得到多少資料 | 站台/log-server 尚未部署的環境 | 直到至少一站上線為止(不影響 C12/C13 本身) |

## 6. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-06 | v1.0 | 初版 | sre |
| 2026-07-06 | v1.1 | 新增 C11–C14:內建兩份 dashboard(Sites Overview、Logs Explorer),用 Grafana 原生 template variable 依環境自動列出 site/job,不需要重新套用 playbook | sre |
