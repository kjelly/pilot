# RFC：Verification Safety Boundary

> 狀態：Proposed — technical review complete，等待接受
> 日期：2026-07-18
> 前置：`docs/tmp/future/IMPLEMENTATION_PLAN.md` M0.4、M2.2
>
> **實作標示：設計已完成，runtime 尚未實作。**
> 目前不存在 per-check action executor 或 secret-aware Ansible module；
> `stageVerifyEnv` 也尚未退役。本 RFC final 前不得宣稱 verify 已符合此邊界。
>
> Technical review 已確認 per-check action、production authorization、cleanup、
> secret transport 與 evidence sink 邊界彼此一致；狀態仍由人接受後才可改為
> Final，本標示不解鎖 M0.4／M2.2。

## 1. 決策摘要

1. Verification 的安全分類採 **per-check**，不是整份 spec 一個
   `safety.destructive` boolean。
2. 自動接入 deploy transaction 的 check 預設且只允許 `readOnly`。
3. 需要寫入 target／外部系統的 self-test 必須宣告為 `isolatedMutation`，具備
   額外授權、cleanup 與 evidence contract；未宣告一律視為違規。
4. v1 既有寫入型 check 在完成盤點與遷移前，不會自動接入 production deploy。
5. `secretRef` 不得進 CLI、process argv、一般環境變數或未遮罩的 Ansible module
   args。安全 runner 未完成前，含 `secretRef` 的 spec 可以 parse/lint，但 verify
   必須 fail closed。
6. 現行 `stageVerifyEnv` 寫 `/etc/pilot-verify.env` 的機制退役，不是 v2 input
   transport。

## 2. 問題

目前 verify 不是嚴格唯讀：

- `internal/tools/verify_spec.go::stageVerifyEnv` 會在 target 寫入
  `/etc/pilot-verify.env`。
- 部分既有 probe 使用 POST／PUT／DELETE 做 self-test。
- `command`／`shell` module 本身可執行任意 mutation；module allowlist 不能證明
  probe 唯讀。
- `--ask-vault-pass` 時 pilot 不知道 vault 解密後的 plaintext，無法宣稱能以
  exact-string 完整遮罩。

因此「verify 自動接入 deploy」之前，必須先定義哪些 mutation 合法、誰授權、
如何 cleanup，以及 evidence 可以保存什麼。

## 3. Check safety schema

Spec v2 每個 check 使用：

```yaml
action:
  mode: readOnly
```

或：

```yaml
action:
  mode: isolatedMutation
  authorization: explicit
  cleanup:
    required: true
    probe: ...
    expect:
      exitCode: 0
  residualRisk: "建立後刪除一筆 sandbox 測試物件"
```

規則：

- `action.mode` 預設 `readOnly`。
- `isolatedMutation` 必須有 `authorization`、`cleanup.required: true` 與
  `residualRisk`。
- parser 負責 enum、必填欄位與結構有效性。
- lint 負責偵測明顯 mutation pattern，包含 redirect、package/service mutation、
  HTTP mutation verb 與已知寫入型 CLI。lint 是防線，不是形式證明。
- coding review 與 actual-run evidence 仍是 read-only claim 的必要條件。

原計畫中的 spec-level `safety.destructive` 不進最終 schema；spec metadata 可以有
彙總風險說明，但執行授權以 check-level action 為準。

## 4. `readOnly` 執行規則

`readOnly` check：

- 可讀取檔案、service state、socket、API、DNS、metrics 與 effective state。
- 不得建立持久檔案、改 package/service/user/config、寫入 API resource 或修改
  inventory。
- controller 與 target 都適用同一規則。
- probe 暫存資料只允許在 runner 管理的 private temp scope，且不得成為被測系統
  的持久狀態。
- runner crash 後可辨識的 temp artifact 必須由下一次啟動 cleanup。

自動 deploy transaction 只執行 `readOnly` checks。遇到
`isolatedMutation` 時，預設 outcome 是 `authorization_required`，不是 skip 或
PASS。

## 5. `isolatedMutation` 執行規則

允許場景是外部行為只能靠建立／撤銷測試資源證明，例如：

- 建立一筆具唯一 run ID 的暫時物件，再讀回並刪除。
- 驗證 reconciler 的 revoke 行為。
- API 的 allow／deny self-test。

限制：

1. sandbox／staging 必須由操作者在當次 run 明確授權。
2. production 預設拒絕；只有 component contract 明確允許、check 宣告 cleanup，
   且操作者同時通過 production stage gate 與 action gate 才能執行。
3. 測試資源名稱必須包含 run ID，避免碰觸既有資源。
4. cleanup 以 `defer`／always block 執行；cleanup 失敗使整個 transaction FAIL。
5. evidence 保存 authorization、mutation scope、cleanup verdict 與 residual state。
6. rollback 不等於 cleanup。rollback 處理 deployment mutation；cleanup 處理
   verification 自己建立的暫時狀態。

## 6. Secret input transport

### 6.1 禁止路徑

Secret plaintext 不得出現在：

- pilot／ansible CLI argv；
- `-e name=value`；
- 一般 process environment；
- shell command materialization；
- report、NDJSON、SQLite event payload；
- 未受 `no_log`／redaction 保護的 Ansible callback。

### 6.2 選定方向

Remote secret probe 使用 repo 內版本化的 **secret-aware Ansible module**：

1. pilot 在 controller 記憶體解析 secret reference。
2. plaintext 透過 subprocess stdin 交給 Ansible runner，不進 argv。
3. module 的 secret 欄位標記 `no_log`，透過 Ansible transport 傳送。
4. module 啟動 probe child 時，以 stdin JSON 提供 secret，不放 argv／environment。
5. module 在回傳前先做 exact-string redaction；pilot persist pipeline 再做第二次
   redaction。
6. callback 只接受 module 定義的 structured result。

Local／controller probe 同樣只以 stdin JSON 接收 secret。

安全 module、crash cleanup、callback redaction 與 recorder leakage 測試未完成前：

- parser 接受 `secretRef`；
- lint 顯示 runner 尚未支援；
- verify 直接拒絕整份 spec；
- deploy transaction 不得繞過。

## 7. Evidence 規則

- matcher 在記憶體中的原始結果評估。
- persist 順序固定：evaluate → redact → truncate → persist。
- 所有 sink 共用同一 redaction pipeline：SQLite、NDJSON、Markdown report、
  diagnostic artifact。
- secret-bearing probe 預設不保存 stdout／stderr；只保存 status、verdict、
  redacted marker 與 secret reference 名稱。
- raw evidence 檔權限為 `0600`。
- command evidence 保存原始 probe 與 input reference，不保存 materialized secret。

## 8. v1 遷移

在 M0.4 前建立既有 24 份 spec 的 action inventory：

- 明確唯讀 → `readOnly`。
- 寫入型 self-test 可移至 apply／fixture → 移出 verify。
- 必須保留的建立／撤銷測試 → `isolatedMutation`。
- 無法判定 → `needsReview`，自動 deploy verify 拒跑。

`stageVerifyEnv` 使用者改為明確 non-secret input；secret input 等安全 module。

## 9. 驗收

- read-only spec 可自動接入 sandbox／staging／production deploy。
- mutation pattern 未宣告 action 時 lint error。
- `isolatedMutation` 未授權、cleanup 缺失或 production contract 未允許時 fail
  closed。
- cleanup failure 使 run 非零，evidence 可查到 residual state。
- secret plaintext 不出現在 argv、environment、stdout/stderr persistence、
  process recorder 與 SQLite。
- 安全 module 未完成前，含 `secretRef` spec 的 verify 必須拒跑。

## 10. 非目標

- 不宣稱能形式證明任意 shell command 唯讀。
- 不以 module allowlist 取代 review。
- 不讓 verify 隱式修復 target。
- 不把 verification-action 當成 apply playbook 的替代品。
