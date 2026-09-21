# 原始問題

幫我建立改善計畫，讓 Prometheus 可以自動偵測有安裝 dcgm-exporter 的主機，自動納入 Prometheus 抓資料的 endpoint，寫入到檔案 `./review.md`。

# 報告內文

## 1. 結論與建議方案

建議比照現有 node exporter 的整合方式，讓 `prometheus` component 將 inventory 的 `dcgm-exporter` group 視為 GPU metrics endpoint 的 canonical source，自動產生固定名稱為 `dcgm` 的 scrape job：

```text
inventory: dcgm-exporter group
        ↓ 依 inventory_hostname 排序、解析 ansible_host
Prometheus static_configs
        ↓ 每台主機保留 pilot_host label
http://<ansible_host>:9400/metrics
        ↓ 使用獨立的 dcgm-exporter Basic Auth
up{job="dcgm"} / DCGM_FI_* metrics
```

此處的「自動偵測」應採 declarative desired-state 語意：被指派 `dcgm-exporter` role 的主機就是應被 scrape 的主機，而不是在 Prometheus 部署時臨時掃 port、只加入當下有回應的主機。若 exporter 故障或網路中斷，target 必須保留並呈現 `up=0`，否則真正需要告警的主機反而會從監控中消失。

第一版應保持與 `node_exporter_targets` 相同的操作模型：

- `dcgm_exporter_targets` 未設定或為空時，自動展開 `dcgm-exporter` group。
- 明確提供非空 `dcgm_exporter_targets` 時，以 override 清單為準。
- 自動展開時，每台主機各自建立一個 `static_configs` entry，並帶 `pilot_host=<inventory_hostname>`。
- 預設 endpoint 為 `<ansible_host>:9400`，job 名稱固定為 `dcgm`。
- 只有 target 非空時才要求 DCGM Basic Auth credential、寫入 password file、掛載 secret volume。
- 不將密碼直接寫入 `prometheus.yml`、Ansible output、diff 或 evidence。

## 2. 現況與缺口

目前 repo 已具備 exporter 端，但尚未具備 consumer 端：

- `dcgm-exporter-apply.yml` 已能部署 `pilot-dcgm-exporter` container、使用 NVIDIA runtime、監聽 `:9400` 並強制 Basic Auth。
- `contracts/dcgm-exporter.yaml` 已宣告 `metrics` endpoint，預設 port 為 `9400`。
- `prometheus-apply.yml` 目前只會從 `host-monitoring` group 自動展開 node exporter targets。
- `contracts/prometheus.yaml` 只綁定 `host-monitoring` endpoint，沒有 `dcgm-exporter` dependency/binding。
- `docs/verification/dcgm-exporter.md` §5 已明確把 Prometheus GPU scrape job 列為尚未實作的已知留白。
- Prometheus vault contract 目前只包含 node exporter auth，尚未宣告它也會消費 `dcgm_exporter_basic_auth_password`。

先前對 `dev-p6k-ok` 的唯讀調查也證明，單純產生 scrape job 還不等於資料會成功進來：該主機的 `pilot-dcgm-exporter` 正在運行且 `0.0.0.0:9400` 有 listener，但 `it-core` 到 `192.168.60.164:9400` TCP connect timeout。因此本功能的真實環境驗收還需要網路 ACL 允許 Prometheus 主機連到 GPU 主機的 `9400/tcp`。

> **範圍註記**：`dev-p6k-ok`/`it-core` 是 production 站台，本次實作的 coding agent 沒有存取權限、不會也不能對它下任何指令；上面這個 ACL timeout 是既有調查交付的既定事實，本次不重新驗證。本文件的實作與驗收範圍到 disposable vm-target（§8.1/§8.2）為止；真實 GPU host 上線是後續由具 production 存取權限者執行的獨立步驟，見 §8.3 的範圍調整。

## 3. 目標與非目標

### 3.1 目標

1. Prometheus 自動從 inventory 找到所有宣告為 `dcgm-exporter` 的主機。
2. 自動生成具 Basic Auth 的 `dcgm` scrape job，不要求操作者逐台手寫 IP。
3. 每個 target 帶穩定的 `pilot_host` label，供 Thanos、Detection Engine、Grafana 與告警規則使用。
4. 支援 explicit override、零 target、credential rotation、設定移除與冪等重跑。
5. 用 spec、regression tests 與 disposable vm-target evidence 證明完整鏈路（真實 GPU host/production 上線驗證是後續獨立步驟，見 §8.3/§11.2，不在本次實作範圍）。

### 3.2 非目標

- 不由 Prometheus playbook 安裝 NVIDIA driver、Docker、NVIDIA Container Toolkit 或 dcgm-exporter。
- 不在 render 時以 port scan 決定 target；runtime health 應由 `up` metric 表達。
- 不改變 node exporter、external monitoring registry 或 SNMP job 的既有輸出。
- 不把 DCGM 密碼併入 node exporter 密碼；兩者維持獨立 credential。
- 不在本階段自動修改防火牆或跨網段 ACL；網路開通是部署前置條件。

## 4. Spec-first acceptance contract

先修改 `docs/verification/prometheus.md`，確認 acceptance contract 後才實作 playbook。建議新增下列變數契約：

| 變數 | 語意 | 必填條件 | 預設 |
|---|---|---|---|
| `dcgm_exporter_targets` | explicit override 的 `host:port` 字串清單 | 否 | 空清單，改走 group auto-discovery |
| `dcgm_exporter_basic_auth_user` | Prometheus scrape 使用者名稱 | 有 DCGM target 時 | `prometheus` |
| `dcgm_exporter_basic_auth_password` | 必須與 exporter 端使用相同值 | 有 DCGM target 時 | 無 |

建議在既有 C1–C15 後追加，不重新編號既有 rows：

| Row | 驗收目的 | 建議觀察結果 |
|---|---|---|
| C16 | `prometheus.yml` 已包含 `job_name: dcgm` | config 中精確存在該 job |
| C17 | 至少一個 DCGM target 完成認證並成功 scrape | `up{job="dcgm"}` 至少一筆為 `1` |
| C18 | auto-discovery target 帶 canonical identity | config/target 含 `pilot_host` label |
| C19 | 收到真正的 GPU 指標，而不只是 exporter 自身 metrics | `DCGM_FI_DEV_GPU_UTIL{job="dcgm"}` 至少一筆 sample |

Spec 還需明列以下 escape hatch：

- inventory 沒有 `dcgm-exporter` 主機且未指定 override：不 render `dcgm` job，也不要求 credential。
- explicit override：沿用 node exporter 現況，無法安全反推 inventory hostname，因此不自行捏造 `pilot_host`。
- `dcgm-exporter` group 可包含無 GPU 候選主機；這些主機若保留在 group，Prometheus target 會呈現 `up=0`。若不希望 scrape 候選主機，應使用 explicit target override，或另案新增可持久化的 scrape eligibility source；不可用瞬時 port probe 靜默排除。
- 由 Kubernetes GPU Operator 或其他機制提供的 `:9400` endpoint，只有在它遵守相同 Basic Auth contract 時才能使用自動 job；否則應走 external monitoring profile/target，避免錯用 credential。

同步更新 `docs/verification/dcgm-exporter.md`：移除「Prometheus 尚未整合」的已知留白，改成指向 Prometheus C16–C19，並維持 exporter 本身 C1–C9 與 consumer 端 E2E 驗收的責任分離。

## 5. Contract 與 inventory model 變更

### 5.1 `contracts/prometheus.yaml`

新增 optional provider dependency：

```yaml
dependencies:
  - component: dcgm-exporter
    required: false
    relation: providerEndpoint
```

新增 binding：

```yaml
bindings:
  - input: dcgm_exporter_targets
    requiredWhenDependencySelected: false
    sourceSelection: all
    from: {component: dcgm-exporter, endpoint: metrics}
```

新增三個 groupVars contract：`dcgm_exporter_targets`、`dcgm_exporter_basic_auth_user`、`dcgm_exporter_basic_auth_password`。不得新增尚未實作的 schema version。

### 5.2 Vault 與 inventory catalog

需同步處理：

- `internal/inventory/contracts.go`：Prometheus 描述改為同時自動展開 node/DCGM targets，並讓 Prometheus vault skeleton 包含 `dcgm-exporter-auth`。
- `internal/inventory/vault.go`：更新 `dcgm-exporter-auth` 說明，明確表示 exporter 與 Prometheus consumer 必須共用同一值，但仍與 node exporter 密碼分離。
- `group_vars/prometheus.example.yml`：加入自動 discovery、override 與 credential 說明。
- `cmd/pilot/cmd/deploy_completeness_test.go`、`internal/inventory/vault_test.go`：更新 fixture 與預期 key，避免新增 credential 後既有 completeness tests 產生假失敗。

若希望「沒有任何 DCGM target 時，vault completeness 也完全不要求 DCGM key」，需要另行擴充目前以 role 為單位的靜態 `VaultSections` 模型，使它能表達 conditional secret。第一版可比照現有 node exporter auth：vault skeleton/completeness 預先要求 key，但 playbook 的 mutation gate 仍只在 target 非空時生效。

## 6. `prometheus-apply.yml` 實作計畫

### 6.1 Target resolution

新增與 node exporter 平行、但變數名稱完全隔離的 facts：

- `prometheus_dcgm_exporter_targets`
- `prometheus_dcgm_exporter_auto_hosts`
- `prometheus_dcgm_exporter_auto_static_configs`
- `prometheus_dcgm_exporter_static_configs`
- `prometheus_dcgm_exporter_scrape_block`

解析規則：

1. `dcgm_exporter_targets` 非空時直接採用 override。
2. 否則讀取 `groups.get('dcgm-exporter', []) | sort`。
3. 每台 auto-discovered host 使用 `hostvars[item].ansible_host | default(item, true)`。
4. 接上 contract default port `:9400`。
5. 每台 host 個別建立 `static_configs` entry，附加 `labels.pilot_host = item`。
6. 使用 native list/dict 搭配 `to_nice_yaml`；不得手刻多行 YAML 或依賴 dict key 順序。

預期 render 形狀：

```yaml
- job_name: dcgm
  basic_auth:
    username: prometheus
    password_file: /etc/prometheus/dcgm-exporter-basic-auth-password
  static_configs:
    - targets:
        - 192.168.60.164:9400
      labels:
        pilot_host: dev-p6k-ok
```

### 6.2 Secret handling

新增獨立檔案：

- host path：`/etc/pilot/prometheus/dcgm-exporter-basic-auth-password`
- container path：`/etc/prometheus/dcgm-exporter-basic-auth-password`

必要約束：

- password file render task 必須 `no_log: true`。
- `prometheus.yml` 只能出現 `password_file`，不得出現明文密碼。
- 只有 DCGM target 非空時才建立及 bind mount password file。
- target 由非空變成空時，要移除 stale password file，避免秘密無限期殘留。
- credential 旋轉造成 password file changed 時，Prometheus container 必須 restart/reload。

### 6.3 Config composition

兩個 `Render prometheus.yml` 分支都要按照固定順序組合：

```text
prometheus_scrape_configs
→ prometheus_node_exporter_scrape_block
→ prometheus_dcgm_exporter_scrape_block
→ prometheus_external_scrape_block
```

同時更新：

- external profile reserved job names：加入 `dcgm`，避免同名 job collision。
- external endpoint overlap warning：同時檢查 node `:9100` 與 DCGM `:9400` managed endpoints。
- container volumes：條件式掛載 DCGM password file。
- container restart expression：納入 `dcgm_exporter_password_file_result is changed` 與 stale-file removal result。
- task tags：C16/C18 對應 render task；C17/C19 屬 verify-only，應在 contract/tag coverage exemption 中寫清楚理由。
- **`always` tag（AGENTS.md §4.4 硬規則）**：`prometheus_dcgm_exporter_targets`/`prometheus_dcgm_exporter_auto_hosts`/`prometheus_dcgm_exporter_auto_static_configs`/`prometheus_dcgm_exporter_static_configs`/`prometheus_dcgm_exporter_scrape_block` 這五個 set_fact task，全部要跟既有 node-exporter 對應區塊（`prometheus-apply.yml:235-296`）一樣標 `tags: [always]`——否則 site-wide 部署在 `--tags` 為空但實際只跑部分 tag 的情境下，`always` 的 config-render task 會讀到從未被設過的變數。改完要跑一次名稱含 `AlwaysTagPrerequisite` 的 regression lint 確認沒漏。

## 7. Regression tests

### 7.1 `internal/spec/prometheus_regression_test.go`

追加並鎖定：

- row IDs 連續為 C1–C19，無 vague expected。
- C16 精確檢查 `job_name: dcgm`，且不依賴 `to_nice_yaml` key 順序。
- C17 使用 percent-encoded PromQL 查詢 `up{job="dcgm"}`。
- C18 驗證 auto-discovery 產生 `pilot_host`，explicit override 不偽造 label。
- C19 查詢 `DCGM_FI_DEV_GPU_UTIL`，證明收到 GPU 指標。
- DCGM job 使用 `basic_auth.password_file`，不得 inline password。
- DCGM password render task 必須 `no_log: true`。
- password volume、credential gate、stale cleanup 與 restart 條件都只在適當狀態生效。
- `groups.get('dcgm-exporter', []) | sort` 與 `ansible_host` fallback 存在。
- node exporter 與 external target 的既有 render 不變。

### 7.2 其他 regression tests

- `cmd/pilot/cmd/tag_coverage_test.go`：更新 Prometheus C16–C19 coverage/exemption。
- contract loader/planner tests：證明 optional `dcgm-exporter → prometheus` provider binding 能產生所有 endpoint，零 provider 時不阻塞 Prometheus。
- vault skeleton/completeness tests：證明 DCGM secret key 正確生成、placeholder 被拒、值不會出現在輸出。
- **修正（實作階段查證後更新）**：讀 `cmd/pilot/cmd/deploy.go:2164-2168` 的 `addDependencies` 實作後發現，`resolveDeploymentScope`/`addDependencies` 只展開 `Required: true` 的依賴（`if !dependency.Required { continue }`）——`dcgm-exporter → prometheus` 跟既有 `host-monitoring → prometheus` 一樣是 `Required: false`，**本來就不會**被這條 Go 層的依賴展開/`--limit` 邏輯納入 scope。原先版本要求在這裡新增「`dcgm-exporter` 會被正確納入 `prometheus` 的部署順序與 `--limit` 展開」的 regression test 是錯的，會鎖一個不成立的行為。
  真正保證「reconcile 時自動帶入有 dcgm-exporter 的主機端點」的機制，跟 host-monitoring 完全一樣，是 **Ansible runtime 層**的 `groups.get('dcgm-exporter', [])`（§6.1）：pilot 產生的 rendered inventory 一律包含全部宣告的 group/host，不受 `--limit` 篩選——`--limit`/依賴展開只決定 Go 層要不要把 `dcgm-exporter`的 host 拉進 preflight/`selected` 清單，跟 Ansible 那邊 Jinja 讀到的 `groups` 內容是兩件事。所以本次要新增的 Go 層 regression test，範圍改成鎖「optional（`Required: false`）providerEndpoint 依賴**不會**被 `resolveDeploymentScope` 自動納入 `selected`/hosts」這個既有但目前沒有測試覆蓋的不變量（用合成 component 名稱、比照 `TestResolveDeploymentScope_LimitAutoIncludesRequiredProviderEndpointHost` 的寫法，只是把 `Required` 改成 `false` 並斷言相反結果）——防的是日後有人把這個關係誤改成 `Required: true` 或反過來，而不是假裝 Go 層會做它其實不做的展開。
  「reconcile 時自動帶入」這個使用者真正在意的行為，驗收責任落在 §8.2 的 disposable vm-target topology test（跟 host-monitoring 的 C13–C15 用同一套已驗證機制），不是靠新的 deploy.go 依賴展開測試。
- negative fixture：零 DCGM host、explicit override、credential 缺失、job name collision、target unreachable、credential mismatch。

## 8. 實際驗證與 evidence 計畫

依 AGENTS.md，正式驗證必須從不可變 candidate commit 的乾淨隔離 checkout 執行，修正後要產生新 candidate，舊 evidence 不可沿用。

### 8.1 L1–L3：靜態與 dry-run

在 candidate freeze 前完成：

1. Prometheus spec lint clean。
2. `TestShellSyntax` PASS。
3. Prometheus/DCGM regression、contract、vault、tag coverage tests PASS。
4. `prometheus-apply.yml` syntax check 與 list-tags PASS。
5. 對全新 target 執行 `--check --diff`，確認零 DCGM target、auto-discovery 與 secret mount path 不會在 check mode 產生錯誤。

### 8.2 無 GPU 的 disposable topology

一般 KVM VM 沒有 NVIDIA GPU，因此應新增一支只供測試的 fixture，在第二台 VM 提供：

- `:9400/metrics`
- Basic Auth
- 至少一筆格式正確的 `DCGM_FI_DEV_GPU_UTIL` 指標

fixture 必須位於 `playbooks/test/fixtures/`、可重跑 `changed=0`、密碼走測試 vault，不能混入正式 apply playbook。用 topology test 證明：

- Prometheus 自動產生 target。
- 認證成功。
- `pilot_host` label 正確。
- C16–C19 PASS。
- 第二次 apply `changed=0`。
- 失敗會觸發 topology rollback。

### 8.3 真實 GPU host（production，不在本次實作範圍內）

`dev-p6k-ok`/`it-core` 是 production 站台，本次實作的 coding agent 沒有存取權限，**不對它下任何指令，也不把它當本次的 acceptance evidence 來源**。本次實作以 §8.1（L1–L3 靜態/dry-run）與 §8.2（disposable topology + 假 DCGM fixture）為完整 acceptance 上限；只要這兩節 PASS，此功能即視為可合併交付。

真實 GPU host 上線是後續、由具 production 存取權限的人（例如 sre）在下列前提滿足後另行執行的獨立步驟，不算入本次交付的完成定義（見 §11）：

- `it-core (10.1.58.12) → dev-p6k-ok (192.168.60.164):9400/tcp` ACL 已開通（現況：TCP connect timeout，見 §2 範圍註記——本次實作不負責、也無法驗證這條 ACL）。
- inventory 事實確認 `dev-p6k-ok` 同時屬於 `dcgm-exporter` group。
- vault metadata 確認有 `dcgm_exporter_basic_auth_password` key，不輸出值。
- exporter 本地驗證已 PASS，再 apply Prometheus candidate（使用本次交付、已通過 §8.1/§8.2 的 candidate revision）。

執行者屆時至少保存：

- tested commit ID 與 tree ID（沿用本次交付通過 vm-target 驗收的同一份 candidate）。
- inventory group/host snapshot。
- Prometheus rendered target 摘要，不含 credential。
- `up{job="dcgm",pilot_host="dev-p6k-ok"} == 1`。
- `DCGM_FI_DEV_GPU_UTIL{job="dcgm",pilot_host="dev-p6k-ok"}` 有 sample。
- Prometheus apply 第二次 `changed=0`。
- sanitized evidence record 路徑；完整 stdout/stderr 留在 append-only evidence store。

## 9. Rollout 與 rollback

### 9.1 Rollout

本次交付（coding agent 實作範圍）：

1. 先在 disposable topology（vm-target + 假 DCGM fixture）驗證 config/auth/label 行為，這是本次交付的 acceptance evidence 上限（§8.2）。
2. spec/regression/tag coverage 全綠、candidate commit 凍結後即可合併。

後續 production rollout（由具存取權限者在合併後另行執行，不算本次交付）：

3. 在單一 sandbox Prometheus 站台 canary（`dev-p6k-ok`/`it-core` 之前先確認 ACL 已開通，見 §8.3）。
4. 確認所有新增 targets 的 `up` 狀態與 scrape error。
5. 再擴到其他站台；每站獨立驗證網路 ACL 與 credential 一致性。
6. 成功後才更新目前有效的 spec/runbook 摘要與 latest evidence link，不把完整 transcript 塞進操作文件。

### 9.2 Rollback

Rollback 必須能由同一支 playbook deterministic 完成：

- 移除 `dcgm-exporter` provider/清空 explicit target 後，重新 render 不含 `dcgm` job 的 config。
- 刪除不再使用的 DCGM password file與 container bind mount。
- Prometheus restart/reload 後 `/-/ready` 回 200、既有 node/external jobs 不受影響。
- 若新 config 導致 Prometheus 無法啟動，沿用 playbook block/rescue 還原 pre-Prometheus snapshot，並保存失敗 evidence。

## 10. 風險與控制

| 風險 | 影響 | 控制方式 |
|---|---|---|
| group 中混入無 GPU 主機 | target 長期 `up=0` | 文件明示 desired-state 語意；必要時使用 explicit override；不要用瞬時 probe 隱藏失敗 |
| exporter 與 Prometheus 密碼不同 | HTTP 401、無 GPU metrics | 共用 vault key；C17/C19 做端到端驗證 |
| 跨網段 9400 被 ACL 擋住 | connect timeout | rollout 前做 Prometheus-source network check；只允許 Prometheus source IP |
| external profile 使用 `dcgm` job 名稱 | series 混淆 | 將 `dcgm` 加入 reserved names gate |
| secret 被寫進 config/diff | credential 洩漏 | password_file、`no_log`、evidence secret scan |
| target 暫時故障時被自動排除 | 失去告警能力 | 不做 runtime port-scan filtering，保留 target 並讓 `up=0` 呈現 |
| 修改破壞 node/external jobs | 既有監控中斷 | byte/structure regression、canary、rollback snapshot |

## 11. 完成定義

### 11.1 本次交付（coding agent 實作範圍，用 vm-target 驗收）

只有同時符合以下條件，本次實作才算完成、可合併：

- Prometheus spec C1–C19 lint clean，regression 與 tag coverage PASS（含 §6.3 補的 `always` tag 檢查）。
- Contract/planner 能從 `dcgm-exporter` providers 解析所有 metrics endpoints；§7.2 的依賴展開/`--limit` regression test 通過。
- 零 target、auto-discovery、explicit override、credential rotation 與 target removal 均有測試。
- Disposable topology（vm-target，§8.2 的假 DCGM fixture）完成 fresh check-mode、apply、verify、idempotency。
- evidence 綁定 immutable tested revision/tree（vm-target candidate）；後續若修改 execution-affecting files，重新產生 candidate 與 evidence。
- 操作文件只保留最新摘要與 evidence link，沒有明文 credential 或累積 transcript。

### 11.2 Production 上線（後續獨立步驟，不算本次交付範圍）

以下條件由具 `dev-p6k-ok`/`it-core` 存取權限者在 §11.1 合併之後另行驗證，coding agent 不執行、也不對此負責：

- `it-core → dev-p6k-ok` 的 9400 ACL 已實際開通並驗證，不以「預期可通」代替證據。
- 真實 GPU host 上 `up{job="dcgm"}=1` 且至少一個 `DCGM_FI_*` series 可由 Prometheus/Thanos 查到。
- production evidence 沿用 §11.1 通過驗收的同一份 candidate revision/tree。
