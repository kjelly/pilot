# Verification Spec — prometheus-host-metadata (hosts.yml annotations → managed-host target labels)

> 版本：v0.1 DRAFT
> 對齊規範：`docs/superpowers/specs/2026-09-23-host-annotations-prometheus-labels-spec.md`
> 維護者：sre
> 尚未在真實 vm-target 上驗證；驗證通過後本段改為測試日期、tested revision 與
> evidence 連結。

> 這份 spec 是 `prometheus.md` 的**附加 opt-in** 能力，不是獨立角色：目標主機
> 仍是 `prometheus` group，套用同一支 `playbooks/apply/prometheus-apply.yml`。
> 刻意**不**把這些檢查塞進 `prometheus.md`——沒有設定
> `prometheus_host_annotation_labels` 的合法部署不應被判 FAIL（設計 spec §18）。
>
> 本檔只放「在**一次**啟用 mapping 的部署上，於 Prometheus 主機即可觀察」的
> row。invalid/secret/reserved/duplicate mapping 的 fail-closed、mapping 未設時
> 的 no-op、explicit override 不猜 metadata、冪等等需要**另一種部署狀態**或
> 「apply 應失敗」的案例，`pilot verify` 做不到，由下列層涵蓋：
>
> | 案例 | 涵蓋處 |
> |---|---|
> | invalid / secret-like / reserved / duplicate mapping fail before mutation | `internal/spec/prometheus_host_metadata_render_test.go`（真 ansible-playbook）+ 設計 spec §21 L10 live run |
> | mapping 未設 / `{}` 只有 `pilot_host` | 同上 render test + `prometheus.md` C15/C18（設計 spec §21 L11） |
> | explicit `node_exporter_targets` override 不帶 metadata | 同上 render test |
> | 冪等 `changed=0` | `pilot vm-target test` 內建 L6 |

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Inventory group | `prometheus`（與 `prometheus.md` 相同主機） |
| OS / version | 與 `prometheus.md` 相同 |
| 角色 | node/DCGM auto-discovery target labels 附加 hosts.yml annotation 維度 |
| 套用範圍 | 有設定 `prometheus_host_annotation_labels` 的 `prometheus` 主機 |
| 風險等級 | Low（預設 no-op；啟用後只改 series label set，見 §5） |

### 1.1 驗證拓樸（fixture 契約）

本檔 row 的 Expected 綁定下列 fixture 值；驗證用 inventory MUST 照這份建立：

| 主機 | Inventory groups | `pilot_annotations` |
|------|------------------|---------------------|
| Prometheus 主機（`prometheus` group） | `prometheus`、`host-monitoring` | `project: llm-training`（刻意缺 `location`/`owner`，供 C5） |
| 另一台 managed host | `host-monitoring`、`dcgm-exporter`（C9 用；可不真的部署 dcgm-exporter，見 §5） | `location: DC1/Rack-A03/U18`、`project: llm-training`、`owner: ai-platform`、`note: must-not-be-promoted` |

mapping：

```yaml
prometheus_host_annotation_labels:
  location: pilot_location
  project: pilot_project
  owner: pilot_owner
```

## 1.5 依賴變數契約

在套用或驗證此主機時，Playbook 與變數參數必須嚴格遵守以下命名，禁止擅自縮寫或發明新變數：

| 變數名稱 | 說明/用途 | 是否必填 | 預設值 |
|---------|----------|---------|--------|
| `prometheus_host_annotation_labels` | `<annotation key>: <pilot_* label>` 的 allowlist mapping；只作用在 node/DCGM auto-discovery target。放 `group_vars/prometheus.yml`（**不可**寫進 playbook play vars，會蓋掉 group_vars） | 否 | 未定義（= `{}`，完全維持舊行為） |

> 其餘變數（`node_exporter_basic_auth_*`、`dcgm_exporter_basic_auth_*`、
> `prometheus_site_label` 等）沿用 `prometheus.md` §1.5，本功能不新增。
> annotation 本身來自 generated inventory 的 `pilot_annotations`
> （`hosts.yml` 的 `annotations`），不在此處設定。

## 2. Checklist

| ID  | Category | Check | Expected | Command |
|-----|----------|-------|----------|---------|
| C1  | config   | `prometheus.yml` 的 node job 帶 `pilot_host` label（metadata 啟用後 canonical identity 仍在） | 0 | awk '/^- /{if (sec ~ /job_name: node/ && sec ~ /pilot_host:/) f=1; sec=$0 ORS; next} {sec=sec $0 ORS} END{if (sec ~ /job_name: node/ && sec ~ /pilot_host:/) f=1; print (f?0:1)}' /etc/pilot/prometheus/prometheus.yml |
| C2  | config   | node job 帶 promoted `pilot_project: llm-training` | 0 | awk '/^- /{if (sec ~ /job_name: node/ && sec ~ /pilot_project: llm-training/) f=1; sec=$0 ORS; next} {sec=sec $0 ORS} END{if (sec ~ /job_name: node/ && sec ~ /pilot_project: llm-training/) f=1; print (f?0:1)}' /etc/pilot/prometheus/prometheus.yml |
| C3  | config   | node job 帶 promoted `pilot_location: DC1/Rack-A03/U18`（值原樣，不 slugify） | 0 | awk '/^- /{if (sec ~ /job_name: node/ && sec ~ /pilot_location: DC1\/Rack-A03\/U18/) f=1; sec=$0 ORS; next} {sec=sec $0 ORS} END{if (sec ~ /job_name: node/ && sec ~ /pilot_location: DC1\/Rack-A03\/U18/) f=1; print (f?0:1)}' /etc/pilot/prometheus/prometheus.yml |
| C4  | config   | 未 allowlist 的 `note` 值不在 `prometheus.yml` | 0 | sh -c '! grep -q "must-not-be-promoted" /etc/pilot/prometheus/prometheus.yml' |
| C5  | config   | 缺 annotation 的主機不 render 空值 label（沒有 `pilot_*:` 後面是空字串的行） | 0 | awk '/^[[:space:]]*-?[[:space:]]*pilot_[a-z0-9_]+:/{v=$0; sub(/^[^:]*:[[:space:]]*/, "", v); if (v == "" || v == "\"\"" || v == "\047\047") b=1} END{print (b?1:0)}' /etc/pilot/prometheus/prometheus.yml |
| C6  | metrics  | `up{job="node",pilot_project="llm-training"}` 有 `1` 的 sample（label 已進 TSDB 且認證 scrape 成功） | ~"1"] | curl -fsS 'http://127.0.0.1:9090/api/v1/query?query=up%7Bjob%3D%22node%22%2Cpilot_project%3D%22llm-training%22%7D' | grep -o '"value":\[[0-9.]*,"1"\]' |
| C7  | metrics  | 真 node exporter metric（`node_uname_info`）帶 `pilot_project` + `pilot_location` | present | curl -fsS 'http://127.0.0.1:9090/api/v1/query?query=node_uname_info%7Bjob%3D%22node%22%2Cpilot_project%3D%22llm-training%22%2Cpilot_location%3D%22DC1%2FRack-A03%2FU18%22%7D' | grep -o '"metric"' |
| C8  | metrics  | 沒有任何 node series 帶 `pilot_note`（未 allowlist 的 annotation 沒進 TSDB） | ~"result":[] | curl -fsS 'http://127.0.0.1:9090/api/v1/query?query=node_uname_info%7Bpilot_note%21%3D%22%22%7D' | grep -o '"result":\[\]' |
| C9  | config   | DCGM job 帶與 node job 相同的 promoted `pilot_project: llm-training`（node/DCGM 共用同一 label builder） | 0 | awk '/^- /{if (sec ~ /job_name: dcgm/ && sec ~ /pilot_project: llm-training/) f=1; sec=$0 ORS; next} {sec=sec $0 ORS} END{if (sec ~ /job_name: dcgm/ && sec ~ /pilot_project: llm-training/) f=1; print (f?0:1)}' /etc/pilot/prometheus/prometheus.yml |
| C10 | config   | 加了 metadata labels 的 `prometheus.yml` 仍通過 `promtool check config` | 0 | sh -c 'docker exec pilot-prometheus promtool check config /etc/prometheus/prometheus.yml >/dev/null 2>&1' |

> C1–C3、C9 用 `prometheus.md` C15 同款 awk：以 `^- ` 切出每個 scrape job，
> 只在 `job_name: node`/`dcgm` 那一段內比對，避免 external target 或另一個 job
> 的同名 label 造成假陽性。`to_nice_yaml` 會把 labels key 依字母排序，所以不假設
> `pilot_host` 之後緊接哪個 key。

## 3. 證據收集

- 工具：`pilot verify docs/verification/prometheus-host-metadata.md -i <inventory> -l prometheus`
- 輸出格式：`.verification/prometheus-host-metadata-<UTC>.{ndjson,md}`
- 預期 row 數：10

## 4. PASS / FAIL 規則

- C1–C10 全部 `status=pass`（或 §5 允許的例外）→ **PASS**：selected annotations
  已作為 target labels 進到 Prometheus TSDB，未 allowlist 的沒有進去
- 任一 fail → **FAIL**，常見修法：
  - C2/C3/C9 fail → `prometheus_host_annotation_labels` 沒生效（放錯檔、被 play
    vars 蓋掉）或 generated inventory 沒有 `pilot_annotations`；
    `ansible-inventory -i <inv> --host <managed-host>` 看 `pilot_annotations`
  - C4/C8 fail → mapping 誤把 `note` 列進 allowlist
  - C5 fail → label builder 沒把空值當 missing（playbook bug）
  - C6/C7 fail → config 有 label 但 scrape 失敗（401：Basic Auth 密碼兩邊不一致）
    或還沒到第一次 scrape；等一個 `prometheus_scrape_interval` 再查
  - C10 fail → rendered YAML 有型別/縮排問題；`docker exec pilot-prometheus cat /etc/prometheus/prometheus.yml`

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C1–C10 | 未設定 `prometheus_host_annotation_labels` 時 C2/C3/C6/C7/C9 預期 fail（本功能 opt-in）；`prometheus.md` 仍可獨立 PASS | 未啟用本功能的環境 | 無（opt-in 設計） |
| C9 | 需要 inventory 有 `dcgm-exporter` group 主機。vm-target 沒有 GPU：可只把 managed host 列進 Prometheus inventory 的 `dcgm-exporter` group 驗 config 渲染（該 target `up{job="dcgm"}` 會是 0，`prometheus.md` C17 同時會 fail，屬預期）；無 `dcgm-exporter` 主機的環境此 row 預期 fail | 無 GPU / 無 dcgm-exporter 主機 | 無 |
| C6–C8 | promoted label 值改變會讓該 host 所有 series 換 label set，舊值 series 在 retention 內與新值並存；C8 只檢查 `pilot_note` 不存在，不檢查舊 label 值已消失 | 修改過 mapping 或 annotation 值的環境 | 無（Prometheus time-series 語意） |

## 6. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-09-23 | v0.1 DRAFT | 初版，對應設計 spec v1.1 §18（row ID 由設計 spec 的 M1–M9 改用 repo 慣例 C1–C10，並加 C10 promtool） | pilot |
