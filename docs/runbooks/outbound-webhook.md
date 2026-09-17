# Runbook — Outbound state webhook (`pilot webhook`, `integrations.yaml`)

> 撰寫日期：2026-09-17
> 對齊規範：`docs/tmp/now/spec.md`（即將移至 `docs/superpowers/specs/`）、`internal/outbound/`、`cmd/pilot/cmd/outbound_workflow.go`
> 最新測試：2026-09-17，於 df31248（Phase 4 candidate f3cb905 + gateway-scope 修復），見 `docs/evidence/outbound-webhook/2026-09-17-phase5-actual-run.md`
> 維護者：sre

---

## 0. 一句話目標

`pilot deploy`/`pilot reconcile`（含 `pilot access reconcile`、`pilot access
breakglass activate/deactivate`、`pilot gateway-scope
reconcile/enable-auto/disable-auto`）每次跑完，如果 workspace 有
`integrations.yaml`，就把一份 sanitized 的 `user_host_access_v1` 宣告狀態
（誰能存取哪些主機、host/group/hostgroup 資產資訊）POST 給外部服務——不影響
原本操作的 exit code，也不需要外部服務隨時在線。

## 1. 啟用（operator 視角）

1. 在你的 workspace（`inventory.yml`/`hosts.yml` 同一層）建立
   `integrations.yaml`：

   ```yaml
   schema_version: 1
   source_id: pilot          # 這個 workspace 的穩定識別；換掉視同換一條 delivery lineage
   webhooks:
     - name: asset-portal
       enabled: true
       endpoint: https://your-receiver.example/webhooks/pilot
       projection: user_host_access_v1
       events:
         - {operation: deploy, result: success, payload: snapshot}
         - {operation: reconcile, result: success, payload: snapshot}
       auth:
         type: bearer            # 或 hmac_sha256
         secret_env: PILOT_WEBHOOK_ASSET_PORTAL_TOKEN
       tls: {}                    # ca_file: 自簽憑證才需要
   ```

2. `export PILOT_WEBHOOK_ASSET_PORTAL_TOKEN=...`（Pilot 只在送出當下讀這個
   環境變數，密鑰本身從不寫進任何檔案）。
3. `pilot webhook lint --dir <workspace>` 驗證 schema/URL/auth/CA，並提醒
   secret env 是否已設定（不連網路）。
4. 正常跑 `pilot deploy`/`pilot reconcile`；沒有 `integrations.yaml` 時，
   行為與這個功能存在之前完全一致（不會開 outbox store）。

## 2. 日常操作

```bash
pilot webhook status --dir <workspace>     # 每個 webhook 的 pending/delivering/paused/dead/blocked/orphaned 計數
pilot webhook flush  --dir <workspace>     # 立刻嘗試投遞到期事件（--name 限定單一 webhook、--force 忽略排程但絕不搶佔 live claim）
```

`status` 顯示 `DEAD > 0` 時，代表某事件用盡重試次數或收到不可重試的
4xx/3xx，需要人工排查外部服務端問題；`ORPHANED`/`BLOCKED` 代表
`integrations.yaml` 曾經改過名字/停用，或 diff chain 因為 base 不一致被
安全擋下。

## 3. 已知限制（2026-09-17 evidence run）

- ~~`pilot gateway-scope reconcile/enable-auto/disable-auto` 無法正確偵測
  底層 ansible 失敗~~ — 2026-09-17 於 Phase 5 evidence run 發現、已於
  `df31248` 修復（`runGatewayScope`/`runGatewayScopeAutomember` 改成跟
  `deploy.go` 一樣檢查 `res.ExitCode`，不能只看 `error`）。詳見 evidence
  doc 的 "Bug found and fixed" 一節。
- 加密（`ansible-vault`）roster 的「只在記憶體解密、不落地」路徑本輪只在
  unit test 層驗證過（`internal/outbound` Phase 2），這次 disposable VM
  跑的是明文 roster。
- `payload_too_large`、`projection_unavailable`、互動式
  cancel-before/after-workflow-ID 三個情境本輪沒有用真實 VM 觸發，維持
  unit/integration test 層的驗證（`internal/outbound/event_test.go`、
  `TestOutboundWorkflow_W15`）。

## 4. 除錯

- 一律先 `pilot webhook lint`：能抓到 schema 錯誤、CA 檔案讀不到、secret
  env 沒設。
- 事件送不出去卻查不到原因：`pilot webhook status` 看 `LAST-ACK`
  是否卡在舊的 snapshot id；`sqlite3 <data-dir>/history.db "select
  event_id,state,attempt_count,next_attempt_at from webhook_outbox"`
  直接看 outbox 原始列（本機除錯用，不要把這個查詢結果外流——`body_json`
  欄位可能含完整 snapshot）。
- 懷疑某次操作漏發或多發事件：先查 `docs/verification/outbound-webhook.md`
  對應的 `TestOutboundWorkflow_W<N>` 是否還綠燈，這些測試鎖住「每個
  operation 最多一個 terminal event」這條不變量。
