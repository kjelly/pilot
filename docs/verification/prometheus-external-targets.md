# Verification Spec — prometheus-external-targets (file_sd-based external exporter registry)

> 版本：v1.0
> 對齊規範：`spec.md`（Prometheus External Prometheus Exporter Target 實作規格）
> 維護者：sre
> 2026-08-24 已在真實 vm-target 上完整驗證（off/on/GC/三個負向 gate/冪等重跑），
> 證據見 `docs/evidence/prometheus-external-targets/2026-08-24-fbd214f.md`；
> 過程中發現並修好兩個真實 bug（見該檔 §6）。

> 這份 spec 是 `prometheus.md` 的**附加**能力，不是獨立角色：目標主機仍然是
> `prometheus` group（同一台機器），套用同一支
> `playbooks/apply/prometheus-apply.yml`。`prometheus.md` 的 C1-C14 驗證
> Prometheus + Thanos Sidecar 本身；本檔只驗證「額外的 external monitoring
> target（不受 Ansible 管理的第三方 exporter）能不能被同一個 Prometheus
> 正確 scrape」這一段，兩份 spec 對同一台主機各自獨立跑
> `pilot verify`。
>
> **只實作 Ansible/Jinja 層**：`spec.md` 描述的 `internal/monitoring/` Go
> domain model、`pilot monitoring` CLI、`pilot edit` TUI 尚未實作（見
> `spec.md` §77 的分期交付）。本檔跟對應的 playbook 改動，把
> `monitoring/targets.yml` + `monitoring/scrape-profiles.yml` 當成兩份純
> YAML 檔案，由 Ansible 直接讀取（`lookup('file', ...) | from_yaml`）、驗證、
> 編譯成 file_sd JSON + scrape job，不經過任何 Go 編譯器——這是刻意的範圍
> 縮減，不是遺漏。

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Inventory group | `prometheus`（與 `prometheus.md` 相同主機） |
| OS / version | 與 `prometheus.md` 相同 |
| 角色 | Prometheus external monitoring target 編譯（附加於既有 Prometheus） |
| 套用範圍 | 有設定 `monitoring_targets_file`/`monitoring_profiles_file` 的 `prometheus` 主機 |
| 風險等級 | Low（純新增檔案，不改動既有 `prometheus.md` 行為；見 §5 AC12 對應例外） |

## 1.5 依賴變數契約

在套用或驗證此主機時，Playbook 與變數參數必須嚴格遵守以下命名，禁止擅自縮寫或發明新變數：

| 變數名稱 | 說明/用途 | 是否必填 | 預設值 |
|---------|----------|---------|--------|
| `monitoring_targets_file` | `monitoring/targets.yml` 的路徑（相對於本 playbook 所在目錄，與 `prometheus_alert_rules_file` 同一種相對路徑慣例；也可傳絕對路徑） | 否 | 空字串（= 沒有 external target，等同 `schemaVersion: 1, targets: []`，spec.md §64） |
| `monitoring_profiles_file` | `monitoring/scrape-profiles.yml` 的路徑，同上慣例 | 否 | 空字串（= 沒有任何 profile） |
| `monitoring_auth` | `authRef -> {type, username, password}` 的 secret 字典；**必須**用 vault 帶入，不進版控（拋棄式沙盒測試除外） | 僅在有 profile 帶 `authRef` 時必填 | 無（未宣告，同 `thanos_aws_secret_access_key` 的 undeclared-secret 慣例） |
| `prometheus_targets_host_dir` | file_sd JSON 的 host 端目錄 | 否 | `{{ prometheus_config_dir }}/targets` |
| `prometheus_targets_container_dir` | file_sd JSON 的 container 端掛載路徑（`file_sd_configs` 裡引用的路徑） | 否 | `/etc/prometheus/targets` |
| `monitoring_secrets_host_dir` | basic-auth 密碼檔的 host 端目錄 | 否 | `{{ prometheus_config_dir }}/monitoring-secrets` |
| `monitoring_secrets_container_dir` | basic-auth 密碼檔的 container 端掛載路徑（`password_file` 引用） | 否 | `/etc/prometheus/monitoring-secrets` |

> **為何 secret 檔權限是 `0644` 而非 spec.md §47 原本建議的 `0600`**：
> `prom/prometheus` 官方 image 以固定 uid `65534`（`nobody`）執行，這個
> uid 不受本 playbook 控制；`0600` 只有檔案 owner 能讀，容器內的 `nobody`
> 讀不到自己不擁有的 `0600` 檔案。跟既有 `node_exporter_basic_auth_password`
> /Thanos `objstore.yml`（`secret_key`）完全同一種既有 trade-off，見
> `prometheus-apply.yml` 該兩處的既有註解——本功能沿用，不另外發明更嚴格
> 但實際上讀不到的權限。
>
> **為何沒有 `pilot monitoring validate` 這一列 gate check**：那是
> `internal/monitoring/` Go CLI 的驗收範圍（尚未實作，見上方 DRAFT 說明）；
> 本 playbook 用等效的 `ansible.builtin.assert`（profile 存在、jobName
> 唯一/非保留字、authRef 對應完整的 basic-auth 憑證）在套用前擋下同一類
> 錯誤，語意對齊 spec.md §22/§32，只是目前用 Ansible gate 實作而非獨立 CLI
> 子命令。

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | file     | file_sd 目錄存在（`{{ prometheus_targets_host_dir }}`，預設 `/etc/pilot/prometheus/targets`） | present | test -d /etc/pilot/prometheus/targets |
| C2 | config   | 目錄下所有已產生的 file_sd JSON 都是合法 JSON | 0 | sh -c 'for f in /etc/pilot/prometheus/targets/*.json; do [ -e "$f" ] || continue; python3 -m json.tool "$f" >/dev/null 2>&1 || exit 1; done; exit 0' |
| C3 | config   | `prometheus.yml` 含至少一個 external monitoring scrape job（`file_sd_configs`） | 0 | sh -c 'grep -qE "^[[:space:]]*-?[[:space:]]*file_sd_configs:" /etc/pilot/prometheus/prometheus.yml' |
| C4 | http     | Prometheus targets API 找得到 `pilot_source="external"` 的 target | 0 | sh -c 'curl -fsS http://127.0.0.1:9090/api/v1/targets | grep -q "\"pilot_source\":\"external\""' |
| C5 | metrics  | 至少一個 enabled external target 被成功 scrape（`up{pilot_source="external"}==1`） | ~"1"] | curl -fsS 'http://127.0.0.1:9090/api/v1/query?query=up%7Bpilot_source%3D%22external%22%7D' | grep -o '"value":\[[0-9.]*,"1"\]' |
| C6 | config   | `prometheus.yml` 語法有效（`promtool check config`；套用後、唯讀，姿勢比照 `prometheus.md` C10） | 0 | sh -c 'docker exec pilot-prometheus promtool check config /etc/prometheus/prometheus.yml >/dev/null 2>&1' |
| C7 | file     | file_sd 目錄權限非 world-writable | 0 | sh -c 'case "$(stat -c "%a" /etc/pilot/prometheus/targets)" in *[2367]) exit 1;; *) exit 0;; esac' |
| C8 | security | `prometheus.yml` 不含明碼 `password:`（basic_auth 一律走 `password_file`） | 0 | sh -c '! grep -qE "^[[:space:]]*password:[[:space:]]*[^[:space:]]" /etc/pilot/prometheus/prometheus.yml' |

> C4/C5 的 label matcher 只用 `pilot_source="external"`，不綁定特定
> `job`/`jobName` 字面值——`jobName` 是使用者在 `scrape-profiles.yml` 自訂
> 的值，spec 本身不該假設任何特定名稱（跟 `prometheus.md` C13 刻意不錨定
> key 順序是同一種「不綁死使用者可自訂的部分」精神）。`pilot_source`/
> `pilot_target` 才是 target compiler 保證一定會自動加上的固定 label
> （spec.md §8.6），所以拿它們當通用 marker。
> C2 對「目前沒有任何 file_sd JSON」（`monitoring_targets_file`/
> `monitoring_profiles_file` 都留空的既有部署）也會直接 PASS（glob 不展開時
> for 迴圈整段被跳過、exit 0）——這是刻意設計，讓這一行在「完全沒有
> external target」的環境下不會誤判為 fail，見 §5。
> C6 沿用 `prometheus.md` C10 的姿勢：`promtool` 只在套用後、以唯讀方式對
> 已經在跑的 container 執行，playbook 本身不把它當成 apply-time 的前置
> gate（見 `spec.md` §22/§55 的修正說明）。
> C7 用 `case` 而非 `grep -qE '[2367]$'`：後者對純數字字串一樣有效，但
> `case` 版本不需要额外的 shell pipeline、退出碼語意更直接（避免踩
> `docs/verification-spec-template.md` 提到的「反邏輯 grep + 數字 expected」
> 陷阱）。
> C3 的 regex 一開始寫成 `^[[:space:]]*file_sd_configs:`，在真的 vm-target
> 上實測直接 FAIL——原因跟 `prometheus.md` C13 那則備註是同一類坑：
> playbook 用 `to_nice_yaml` 序列化 scrape job dict 時會把 key 依字母序
> 排列，`file_sd_configs` 剛好排到最前面，變成 YAML list item 的第一個
> key，實際渲染出來是 `- file_sd_configs:`（開頭多一個 `-` 加空白的
> list marker），不是 `^[[:space:]]*file_sd_configs:` 預期的「行首只有
> 空白」。已修成 `^[[:space:]]*-?[[:space:]]*file_sd_configs:`，同時容許
> 有/沒有 list marker 兩種排列順序，並已在真實 VM 上重新驗證通過。

## 3. 證據收集

- 工具：`pilot verify docs/verification/prometheus-external-targets.md -i <inventory> -l prometheus`
- 輸出格式：`.verification/prometheus-external-targets-<UTC>.{ndjson,md}`
- 預期 row 數：8
- Sanitized 摘要：`docs/evidence/prometheus-external-targets/2026-08-24-fbd214f.md`（真實 vm-target 跑過 off/on/GC/負向 gate/冪等重跑全套）

## 4. PASS / FAIL 規則

- C1-C8 全部 `status=pass`（或 §5 允許的 skip/預期 fail）→ **PASS**：這台
  Prometheus 已經能正確 scrape 至少一個未受 Ansible 管理的 external
  exporter，且沒有把密碼洩漏進明碼設定檔
- 任一 fail → **FAIL**，常見修法：
  - C1 fail → `monitoring_profiles_file` 沒有任何 profile 但仍預期有目錄；
    確認至少一個 profile 已定義，或這是 §5 的預期例外
  - C2 fail → 某個 file_sd JSON 內容不是合法 JSON；檢查 apply playbook
    render 該檔的 task（`docker exec pilot-prometheus cat
    /etc/prometheus/targets/<jobName>.json`）
  - C3 fail → `monitoring_profiles_file` 沒有任何 profile（預期 fail，見
    §5），或 render 任務沒有把 `prometheus_external_scrape_block` 併入
    `scrape_configs`
  - C4/C5 fail → target 位址打不到，或 `monitoring_targets_file` 裡的
    target 全部 `enabled: false`；`docker logs pilot-prometheus | grep -i
    <jobName>`
  - C6 fail → `prometheus.yml` 語法有誤（通常是 §2 提到的 profile/target
    compile 出的 YAML 有縮排或型別問題）；`docker exec pilot-prometheus cat
    /etc/prometheus/prometheus.yml`
  - C7 fail → 目錄權限被外部工具改過；重新套用 playbook 會修正回 `0755`
  - C8 fail → 有 profile 誤用明碼 `password:` 而非 `password_file:`——這是
    playbook bug，不是使用者可調整的設定，需要回頭檢查 scrape-job 編譯
    task

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C1, C3, C4, C5 | `monitoring_targets_file`/`monitoring_profiles_file` 都未設定（或設定但沒有任何 profile/enabled target）時，這四行預期 fail（apply playbook 不會建立 file_sd 目錄、不會 render external scrape job） | 尚未設定 external monitoring target 的環境（`prometheus.md` 本身仍可獨立 PASS，見該檔） | 無（這是本功能「不影響既有部署」的設計，spec.md AC12/AC13/AC14） |
| C6 | 目前僅在真的有安裝 `promtool`（`prom/prometheus` 官方 image 內建）的 container 上驗證過；若未來允許自訂 Prometheus image 且該 image 不含 `promtool`，本行需要重新評估 | 使用非官方 Prometheus image 的環境 | 待自訂 image 支援排入 roadmap 時 |

## 6. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-08-24 | v1.0 DRAFT | 初版，對應 `spec.md` §7-24（Monitoring Target Registry + Scrape Profile，純 Ansible/Jinja 實作，`internal/monitoring/` Go CLI 尚未實作） | sre |
| 2026-08-24 | v1.0 | 真實 vm-target 驗證通過，修正 C3 regex（`to_nice_yaml` key 排序坑，同 `prometheus.md` C13 的坑）；playbook 端另修好 `selectattr('enabled','default',true)` 不是合法 Jinja 的 bug（見 evidence §6） | sre |
