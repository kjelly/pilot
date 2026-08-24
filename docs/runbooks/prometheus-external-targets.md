# Runbook — prometheus-external-targets（Prometheus 外部 exporter 監控目標）

> 撰寫日期：2026-08-24 (UTC)
> 對齊規範：`docs/verification/prometheus-external-targets.md`（v1.0）、`spec.md`（設計文件）
> 前置：`docs/runbooks/metrics-alerting.md`（`prometheus` 角色本身要先能部署）
> 真實測試證據：`docs/evidence/prometheus-external-targets/2026-08-24-fbd214f.md`
> 維護者：sre

---

## 0. 目標與範圍

讓既有的 `prometheus` 角色能 scrape **Pilot 不透過 Ansible/SSH 管理**的第三方
exporter（NAS、UPS、switch、外部資料庫……）——`spec.md` 定義的 Monitoring
Target Registry。核心不變量：

> Pilot inventory 描述「Pilot 管理什麼主機」；Monitoring Target Registry
> 描述「Prometheus 要監控什麼 endpoint」，兩者不得互相依賴。

**本次交付範圍（`spec.md` §78 Phase 1-6 全部）**：

1. `internal/monitoring`（Go domain model：schema、validate、compile、
   connectivity test）
2. `playbooks/apply/prometheus-apply.yml` 擴充（file_sd JSON 產生、scrape
   job 渲染、GC、Docker volume mount）
3. `pilot monitoring target/profile/validate` CLI
4. `pilot edit` 的 Monitoring TUI（新增/編輯/刪除 target 與 profile）
5. `--actions`/MCP 結構化操作（17 個 semantic action + `pilot_edit_inspect`
   擴充 + `pilot://monitoring/*` resources）
6. 本檔 + `internal/spec` regression test + golden test

**刻意不做**（`spec.md` 非目標，或本次判斷不需要）：不安裝/不 SSH 到
external target；不做 Kubernetes/Consul/FreeIPA DNS SRV service discovery；
不實作 `caRef`（CA registry）解析；不自動建立 alert rules。

## 1. §0.5 事實快照（AGENTS.md §2）

```
$ go run ./cmd/pilot vm-target list   # 測試前
(no targets — `pilot vm-target up` to start one)
```

測試前沒有任何殘留 VM。本次新建一台獨立命名的拋棄式 VM，測試完已 teardown：

| VM | base image | 用途 |
|----|------------|------|
| `ext-target-test` | ubuntu-24.04（預設，`--services local`） | 單機測試：`prometheus` 角色 + external monitoring target 機制 |

Tested revision：commit `fbd214f`（FreeIPA WSGI socket-timeout，與本功能無關）
之上的工作樹，對應 `playbooks/apply/prometheus-apply.yml` 擴充 +
`docs/verification/prometheus-external-targets.md` 首次落地時的內容。

`pilot services status`：未使用（`--services local` 僅代表輕量 host-local
cache，本次測試不依賴它）。

## 2. 部署（apply）

Thanos/S3 後端**刻意用假值**通過 gate（`docs/runbooks/metrics-alerting.md`
「多 VM cross-check」章節已驗證過的做法）——本次驗證的是 external target
機制本身，不是 Thanos 上傳鏈路：

```bash
go run ./cmd/pilot vm-target up --name ext-target-test --ssh-user ubuntu \
    --disk 20 --memory 3072 --vcpus 2 --ssh-timeout 8m --boot-timeout 8m --services local

go run ./cmd/pilot vm-target run --name ext-target-test --skip-lint \
    playbooks/apply/docker-apply.yml -e target_group=ext-target-test
# PLAY RECAP: ok=6 changed=2 failed=0 skipped=2

go run ./cmd/pilot vm-target run --name ext-target-test --skip-lint \
    playbooks/apply/prometheus-apply.yml -e target_group=ext-target-test \
    -e prometheus_site_label=test-site \
    -e thanos_s3_endpoint=203.0.113.1:9000 \
    -e thanos_aws_access_key_id=fakekey -e thanos_aws_secret_access_key=fakesecret \
    -e monitoring_targets_file=<workspace>/monitoring/targets.yml \
    -e monitoring_profiles_file=<workspace>/monitoring/scrape-profiles.yml \
    -e '{"monitoring_auth": {"demo-auth": {"type": "basic", "username": "demo", "password": "demo-secret-123"}}}'
# PLAY RECAP: ok=38 changed=6 failed=0 skipped=12
```

測試用 `monitoring/targets.yml`：一個未認證的 self-scrape target
（`127.0.0.1:9090`，即 Prometheus 自己的 `/metrics`，作為真實可達的「外部」
exporter，不需要額外基礎設施）、一個同 profile 但 `enabled: false` 的
target、一個帶 `authRef` 指向不可達位址（`203.0.113.5:9999`，TEST-NET-3）
的 target，用來驗證 basic-auth 密碼渲染路徑不需要真的有認證後端。

實機驗證（`docker exec` 直接看）：

- `/etc/pilot/prometheus/targets/external-selfscrape.json` 只有一筆（`enabled:
  false` 的那個正確被排除）
- `/etc/pilot/prometheus/targets/external-authed-demo.json` 一筆，含 `site`
  label
- `prometheus.yml` 的 `external-authed-demo` job：`basic_auth: {username: demo,
  password_file: /etc/prometheus/monitoring-secrets/demo-auth.password}`——
  全檔找不到明碼 `password:`
- `up{pilot_source="external"}`：`external-selfscrape` job `up=1`（真的
  scrape 成功），`external-authed-demo` job `up=0`（位址故意不可達，符合預期）

## 3. 驗證（spec C1–C8）

```bash
go run ./cmd/pilot vm-target verify --name ext-target-test \
    docs/verification/prometheus-external-targets.md --timeout 40
```

```
verdict: **PASS**  (pass=8 fail=0 skip=0)
```

同一台主機的既有 `prometheus.md` 也重新跑過一次，確認**沒有 regression**：

```
verdict: **FAIL**  (pass=10 fail=4 skip=0)
```

C9（假 S3 bucket）、C11（沒有 Alertmanager）、C13/C14（沒有
`host-monitoring` group）——四個都是 `prometheus.md` §5 本來就記載的預期
例外，跟本次改動前完全一致的失敗集合。

## 4. 冪等重跑（idempotency）

同一組 `-e` 參數原封不動重跑：

```
PLAY RECAP: ok=38 changed=0 failed=0 skipped=12
```

`changed=0`（含 file_sd JSON render、GC、container restart 判斷全部維持
不變）——證明 file_sd JSON 的 YAML/Ansible 序列化是決定性的（`spec.md` §72
要求），沒有因為 map 迭代順序不穩定而每次改變。

另外驗證了 GC 路徑：拿掉一個 profile 後重新 apply，`Remove stale file_sd
JSON for profiles no longer declared` 正確刪除對應舊 JSON、保留仍在用的
JSON，`pilot verify` 重新跑仍 PASS。

## 5. 負向路徑（deliberately triggered，非只讀程式碼推斷）

依照「只測過真陽性的 check 沒有證明力」的原則，三個驗證 gate 都實際觸發過
一次，確認真的會 FAIL 而不是想像中會 FAIL：

| 情境 | 觸發的 gate | 結果 |
|------|------------|------|
| target 指到不存在的 profile | "every enabled monitoring target references an existing scrape profile" | `failed: ... references unknown scrape profile "does-not-exist"` |
| profile `jobName: node` | "profile jobName must not use a reserved name" | `failed: ... uses a reserved jobName ("prometheus" or "node")` |
| 有 `authRef` 但沒帶 `monitoring_auth` | "every profile authRef resolves to a complete basic-auth credential" | `failed:` (no_log 遮蔽細節) |

三者都在 `pre_tasks` 階段失敗，任何檔案都還沒寫入——確認下一次帶正確參數
重新 apply，`changed=0`（沒有殘留的半套狀態）。

## 6. Teardown

```bash
go run ./cmd/pilot vm-target down --name ext-target-test
```

## 7. 踩過的雷（實測 vm-target 時發現）

| 症狀 | 根因 | 修法 |
|------|------|------|
| `[ERROR]: The filter plugin 'ansible.builtin.selectattr' failed: No test named 'default'.` | `selectattr('enabled', 'default', true)` 不是合法 Jinja——`'default'` 是 filter 不是 selectattr 的 test 名稱，這個寫法從一開始就不會動，只是在真的有 target 資料時才會真的觸發到那一行 | 改成先用 `loop:`（逐項 `{'enabled': true} \| combine(item)`，base-then-override，不是反過來）把每個 target 的 `enabled` 正規化成真的布林值，之後全部改用單純的 `selectattr('enabled')` |
| C3（`prometheus.yml` 含 `file_sd_configs`）在只剩一個 profile 時突然 FAIL，即使 `docker exec ... cat prometheus.yml` 看得到 `file_sd_configs:` 字樣 | 跟 `prometheus.md` C13 同一類坑：apply playbook 用 `to_nice_yaml` 序列化 scrape job dict 時會把 key 依字母序排列，`file_sd_configs`（字母排在最前）變成該 job 的第一個 key，實際輸出是 `- file_sd_configs:`（YAML list item 的 `-` 開頭），不是原本 regex `^[[:space:]]*file_sd_configs:` 預期的「行首只有空白」 | regex 改成 `^[[:space:]]*-?[[:space:]]*file_sd_configs:`，同時容許有/沒有 list marker 兩種排列，已在真實 vm-target 上重新驗證通過 |
| `pilot verify docs/verification/prometheus.md` 在單一 vm-target（inventory 只有 `all.hosts.<name>`，沒有 `prometheus` group）上跑會直接報錯：`spec targets matched zero inventory hosts and no target_group override was provided` | `prometheus.md` §1 的 Targets 表宣告 inventory group 為 `prometheus`；`internal/tools/expected_hosts.go` 的 expected-host resolver 要求這個宣告的 group 在 inventory 裡真的存在，否則需要一個 `TargetGroupOverride: true` 逃生門——但這個欄位**全 repo 只有測試在設，沒有任何一支正式程式碼路徑會把它設成 true**，`pilot verify`/`pilot vm-target verify` 都沒有對應 CLI flag 能觸發它 | 本次繞過：手動在 `pilot vm-target show-inventory` 產生的 inventory 加一段 `children: {prometheus: {hosts: {<name>: null}}}`，直接對這份修改過的 inventory 呼叫 `pilot verify -i <patched> -l <name>`。**這是全 repo 層級、跟本功能無關的既有缺口，本次未修**，留給後續處理——影響範圍是任何想在單一 ad-hoc vm-target 上驗證一份宣告了 v1 Targets group 的 spec 的場景 |
| 插入 `pilot edit` top menu 新選項後，7 個既有 teatest/PTY 測試從 PASS 變 FAIL | 這正是 `edit_tui.go` 檔頭註解自己警告過的「top-menu insertion regression」：既有測試用 `for i := 0; i < N { KeyDown }` 這種寫死的按鍵次數導航選單，插入第 10 個項目後，原本瞄準「離開」（index 8）或「快速建立最小 workspace」（index 7）的迴圈全部多按了一次，改選到隔壁的項目 | 逐一比對每個受影響迴圈原本瞄準哪個選單項目，把次數 +1（並更新過期的選單列舉註解），修完在乾淨 checkout 上重跑確認這 7 個測試在改動前後的差異確實是本次變更造成，不是既有 flaky 測試 |

## 8. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-08-24 | v1.0 | 初版：Phase 1-6 全部落地並在真實 vm-target 驗證通過 | sre |
