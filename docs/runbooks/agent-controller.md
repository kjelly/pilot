# Runbook — Agent Controller（Agent Monitoring Phase 1，observe-only incident controller）

## 0. 目標與資料流

見 `docs/architecture/agent-monitoring.md` 的完整資料流圖與設計決策；完整規格
`docs/superpowers/specs/2026-09-01-agent-monitoring-phase-1-observe-only-controller-spec.md`。

一句話：`pilot-agent-controller` 接收 Alertmanager webhook、正規化成
incident、派送唯讀診斷請求給外部 Agent Runtime(Phase 1 尚未接任何真實
Runtime,只有 fake/HTTP 兩個 dispatcher adapter)。零 mutation 權限,不吃
SSH 憑證。

## 1. 事實快照(2026-09-01,vm-target 拋棄式單機實跑)

- Tested tree:此 runbook 與 Phase 1 全部程式碼/文件同一個 commit(見本檔
  §8 變更紀錄的 commit hash——依 AGENTS.md v1.16「先凍結候選 commit,再用
  該 commit 的內容驗證,evidence-only commit 引用 tested revision」的慣例,
  這份 evidence 是對「即將成為該 commit 的 dirty worktree」實跑,不是另開
  乾淨 checkout——屬於 AGENTS.md 允許的日常驗證級別)。
- Target:單一 disposable `pilot vm-target`(`ubuntu-24.04`,2 vCPU/2GiB/15GiB),
  疊 `host-monitoring` → `docker` → `alertmanager` → `agent-controller` 四層。
- `pilot verify docs/verification/agent-controller.md`:**13/13 PASS**(見 §5)。
- 冪等重跑:`changed=0`(見 §3.2)。
- 真實 Alertmanager v0.27 → agent-controller 的 webhook 全鏈路成功遞送(見 §4)。

## 2. 部署鏈(實際指令 + 真實輸出摘要)

```bash
pilot vm-target up --name agentctl --base-image ubuntu-24.04 --vcpus 2 --memory 2048 --disk 15

pilot vm-target run --name agentctl playbooks/apply/host-monitoring-apply.yml \
    -e target_group=agentctl -e node_exporter_basic_auth_password=<vault>
# PLAY RECAP: ok=28 changed=12 failed=0

pilot vm-target run --name agentctl playbooks/apply/docker-apply.yml -e target_group=agentctl
# PLAY RECAP: ok=5 changed=2 failed=0

pilot vm-target run --name agentctl playbooks/apply/alertmanager-apply.yml -e target_group=agentctl
# PLAY RECAP: ok=9 changed=3 failed=0   (先用預設 null receiver 佔位,§4 再換真的 webhook route)

pilot vm-target run --name agentctl playbooks/apply/agent-controller-apply.yml \
    -e target_group=agentctl \
    -e agent_controller_artifact_path=dist/pilot-agent-controller-linux-amd64 \
    -e agent_controller_artifact_sha256=<sha256> \
    -e agent_controller_webhook_secret=<vault>
# PLAY RECAP: ok=36 changed=10 failed=0
```

`host-monitoring` 第一次沒帶 `node_exporter_basic_auth_password` 直接被
`pre_tasks` 的 assert 擋下(spec §1.5 硬規則,非 bug)——帶了密碼後乾淨過。
`alertmanager` 第一次因為這台 VM 還沒裝 docker 而失敗(`docker-apply.yml`
是獨立元件,不是 `alertmanager-apply.yml` 的依賴,得自己先套用)——裝完
docker 後乾淨過。

## 3. 實跑中發現並修好的 3 個真 bug

### 3.1 HMAC 簽章跟真實 Alertmanager 的 webhook_configs 不相容(最關鍵)

Phase 1 設計文件寫「Authenticate with mTLS or an HMAC/shared-secret
mechanism」,`internal/agentcontroller/http.go` 第一版真的實作成
HMAC-SHA256(對整個 request body 算簽章,`X-Pilot-Agent-Signature-256`
header)。部署到真實 Alertmanager v0.27 才發現:**Alertmanager 自己的
webhook_configs sender 完全沒有「對 outgoing body 算 HMAC」這個功能**——
它只能透過 `http_config.authorization`(Bearer)或 `http_config.basic_auth`
附一個固定憑證。HMAC-of-body 只有「送信方是自己可控的程式」才能用(例如
未來自製的 forwarder),對 stock Alertmanager 這個假設從一開始就不成立。

修法:`http.go` 改成 bearer token 常數時間比對(`verifyBearerToken`),
`docs/verification/agent-controller.md`、`docs/architecture/agent-monitoring.md`、
`group_vars/agent-controller.example.yml`、`contracts/agent-controller.yaml`
同步改用語言一致的「bearer token」而非「HMAC」。真實 Alertmanager
webhook_configs 設定範例已寫進 `group_vars/agent-controller.example.yml`
的註解區塊(§4 就是照那份設定跑出來的)。

### 3.2 C3 驗證探針打錯位址

`docs/verification/agent-controller.md` C3 第一版探針打
`http://127.0.0.1:${port}`,但 agent-controller 的 listener 依 spec
§5.2「private/network-scoped」硬性規定綁在
`{{ ansible_default_ipv4.address }}`(這台 VM 是 `192.168.122.3`),**不是**
`0.0.0.0`,所以 loopback 連不到——`pilot verify` 對這行回 `rc=7`
(curl「無法連線」)。修法:探針改成從 `/etc/pilot/agent-controller/config.yaml`
的 `listenAddr` 欄位動態抓真正綁定的位址。

### 3.3 C8 驗證探針檢查了錯誤的主機/錯誤的期望值

C8 第一版探針檢查 `/usr/local/bin/pilot`(control-plane 用的主 pilot
二進位)是否存在,expect `present`——但這支 agent-controller apply
playbook 從來沒有、也不應該把主 `pilot` 二進位裝到自己的目標主機上
(觀測用 MCP session 是跑在 operator 的 control plane,不是這台主機)。
修法:改成驗證這台主機**沒有**主 `pilot` 二進位(expect `absent`)——
這才是這台主機上唯一能真實驗證、也真正有意義的斷言:agent-controller
自己的主機連「能開出 raw/write MCP session 的工具」都沒裝,足跡最小。

三個 bug 都在寫進這份 runbook 前修好、重新實跑驗證過(見 §5)。

## 4. 真實 Alertmanager 遞送鏈證據

把 alertmanager 重新套用成真實 webhook route(不是預設 null receiver):

```yaml
route:
  receiver: 'agent-controller'
  group_by: ['alertname']
  group_wait: 5s
  group_interval: 30s
receivers:
  - name: 'agent-controller'
    webhook_configs:
      - url: "http://192.168.122.3:8090/webhooks/alertmanager"
        send_resolved: true
        http_config:
          authorization: {type: Bearer, credentials: "<webhook secret>"}
```

```bash
# 對 Alertmanager 自己的 API v2 直接開一個真的 alert(不是直接打 agent-controller)
curl -X POST http://127.0.0.1:9093/api/v2/alerts --data '[{"labels":{"alertname":"EvidenceRunTestAlert","severity":"critical","pilot_host":"agentctl"}, ...}]'
# → 200

# group_wait 過後檢查 agent-controller 自己的 status
pilot-agent-controller status --json
# ingress.ingested_events: 1, ingress.auth_failures: 0, ingress.ingest_errors: 0
```

`ingested_events` 從 0 變 1 且沒有任何 auth/ingest 錯誤——證實真實
Alertmanager 確實能用 bearer token 認證,把 webhook 送到 agent-controller,
且 payload 被正確接受、正規化、派送給(fake)Agent Runtime。

### 4.1 直接對已部署 binary 的補充場景(繞過 Alertmanager 的 group_interval 等待)

- **Replay(C7)**:對同一個 fingerprint/status/severity 連續直接送 3 次
  簽好的 webhook,`ingress.ingested_events` 正常累加(每次都被接受並處理)
  且沒有 `ingest_errors`——重複判斷(不重複建立 incident/run)的邏輯本身由
  `internal/agentcontroller` 46 個 Go 單元測試逐項覆蓋
  (`TestIngestEvent_ReplayIsNoOp` 等),這裡只確認真實部署上的 HTTP 層行為
  跟單元測試一致、沒有整合面的落差。
- **Resolved(C7)**:直接送一個 `status:"resolved"` 的同 fingerprint webhook,
  `200` + `ingested_events` 正常累加,無錯誤。
- **Restart(C11)**:`systemctl restart pilot-agent-controller.service` 後
  `systemctl is-active` → `active`,`db check` → `ok`,`status --json` 正常——
  服務重啟後 SQLite state 完整、程序正常重新開始接受流量。

## 5. Spec v2 驗收結果(`pilot verify`)

第一輪(§3 兩個探針 bug 修好前):**FAIL**(11 pass / 2 fail,C3+C8)。

修好後重跑:

```
$ pilot verify docs/verification/agent-controller.md -i <vm-target inventory>
verdict: **PASS**  (pass=13 fail=0 skip=0)
```

| ID | Status |
|----|--------|
| C1-C13 | 全部 pass |

C3、C7-C11、C13 是 `verifyOnly`(contract 的 exemption 表有列原因)——§4.1
的場景證據補足它們的真實行為面,C1/C2/C4/C5/C6/C12 由 `pilot verify` 的
探針直接判定。

冪等重跑(§3.2 用同樣的 `-e` 值再跑一次):`PLAY RECAP: ok=34 changed=0
failed=0`。升級路徑(重建 binary 後帶新 sha256 重跑)也真的跑過一次——
`agent_controller_is_upgrade` 判斷正確觸發、backup/rollback 素材有寫入。

## 6. 已知限制 / 尚未完成

- 沒有接任何真實外部 Agent Runtime——只驗證了 `FakeDispatcher`
  (`dispatcher.kind: fake`,這次實跑用的設定)。`HTTPDispatcher` 有 Go
  單元測試(`httptest` 起假伺服器覆蓋成功/逾時/畸形回應),但沒有對一個
  真實 Runtime 產品實跑過。
- Alertmanager 端的 `webhook_configs` route 完全靠操作者手動設定(見
  `group_vars/agent-controller.example.yml` 的範例區塊),contract 沒有
  `bindings`/`AutoHostVars` 自動接線(資料流方向跟 detection-engine 相反,
  見 `docs/architecture/agent-monitoring.md` §5)。
- 沒有測「postmortem mode」(spec §13 提到的選配、Phase 1 未實作)。
- Phase 2-5(結構化診斷 MCP 工具、人工核准 R1 remediation、政策閘門自主
  remediation、受控 R2 reapply)都還沒實作。

## 7. Teardown

```bash
pilot vm-target down --name agentctl
```

已執行,VM 與其 qcow2 overlay/狀態已清除。

## 8. 變更紀錄

| 日期 | 版本 | 變更 |
|---|---|---|
| 2026-09-01 | v1.0 | Phase 1 初次實跑:vm-target 四層部署鏈全綠、13/13 Spec v2 PASS、冪等 changed=0、真實 Alertmanager v0.27 webhook 遞送鏈驗證通過;實跑中發現並修好 3 個真 bug(HMAC→bearer token、C3 探針位址、C8 探針期望值反了)。tested revision: 見本次 commit(`git log` 對照)。 |
