# Runbook — Model Provider generic subject wire (Phase 6)

> 撰寫日期：2026-09-02 (UTC)
> 對齊規範：`docs/superpowers/specs/2026-09-01-snmp-monitoring-integration-spec.md`
> §9.11、§15 Phase 6；`docs/verification/snmp-monitoring-integration.md` C14
> 維護者：sre

---

## 0. 目標與範圍

把 Stage B（Model Provider / NPU / FLM）的 candidate 輸入從
Linux-host-only 的 `{Host, Site}` 換成 spec §9.11 的
`{Subject SubjectKey}`,讓 SNMP subject 也能送進既有的
ManagedProvider/FallbackProvider/retry/circuit breaker/rate limiter,
不新增任何平行機制。

Exit gate：
```
model sees only aggregate features
malformed FLM reply preserves local anomaly
fallback lane PASS
no secret/raw OID in captured prompts
```

## 1. 實作內容

- `internal/detection/model_batch.go`：`Candidate` 從
  `{Host, Site, LocalScore, Current}` 改成
  `{Subject SubjectKey, LocalScore, Current}`,`SelectCandidates` 的排序
  tie-break 改用 `Subject.ID`。
- `internal/detection/model_schema.go`：`ModelCandidateRequest` 新增
  `SubjectID`/`SubjectKind`,`PilotHost` 降級成 `omitempty` 的相容鏡像欄位
  （managed_host 才填,其他 kind 省略)。這是一個**真的 wire schema
  version bump**：新增
  `schemas/model-detection-batch-request-v2.json`
  （`schema_version: const 2`,`subject_id`/`subject_kind`/`site` 必要,
  `pilot_host` 選填),`monitoring/detection/schemas/` 同步鏡像一份（維持
  既有 `TestModelSchema_EmbeddedCopyMatchesMonitoringTarget` 的
  byte-identical 規則)。舊的
  `model-detection-batch-request-v1.json` 兩份都保留在磁碟上——原始
  `docs/superpowers/specs/2026-08-28-detection-engine-spec.md` 仍把它當
  既存事實引用,不是這次 SNMP spec 可以回頭改的東西。Response schema
  完全沒動——`candidate_id` 本來就是不透明字串,形狀沒變。
- `internal/detection/model_engine.go`：`scoreOneBatch` 建 request 時
  `SubjectID`/`SubjectKind` 一定填,`PilotHost` 只在
  `Subject.IsManagedHost()` 時填,`SchemaVersion` 從 1 改成 2。
- `internal/detection/model_flm.go`：`formatFLMEvidence`（FLM 協定的
  純文字 evidence,不是 JSON)把 `pilot_host=` 那行換成
  `subject_id=`/`subject_kind=` 兩行,完全對齊 spec §9.11 給的 FLM
  evidence 範例格式。
- `internal/detection/engine.go`：`RunCycle` 建 candidate 時改用
  `Candidate{Subject: SubjectKey{ID: ..., Kind: identity.Kind, Site: ...}}`。
- Ollama/OpenAI 兩個協定完全不用改——它們都是直接
  `json.Marshal(ModelBatchRequest)` 當 request body,新欄位透過既有的
  `ModelBatchRequest`/`ModelCandidateRequest` 型別自動帶到位,這正是「一個
  wire schema、三種傳輸協定」的設計初衷。

## 2. 測試證據

```
$ go test ./internal/detection/... ./cmd/pilot-detection-engine/... -v
... 161 個 PASS ...
--- PASS: TestEngine_SNMPProfile_ModelFailurePreservesLocalAnomalyAndSeesOnlyAggregates
--- PASS: TestValidateBatchRequest_SNMPSubjectOmitsPilotHost
--- PASS: TestValidateBatchRequest_RejectsOldSchemaVersion
--- PASS: TestValidateBatchRequest_AdditionalPropertiesRejected
ok  	github.com/kjelly/pilot/internal/detection	...
ok  	github.com/kjelly/pilot/cmd/pilot-detection-engine	...
```

`go test ./...`：只剩既有 baseline 的 4 個失敗（與本次改動無關)。

## 3. Exit gate 對照

| Exit gate 項目 | 狀態 | 證據 |
|---|---|---|
| model sees only aggregate features | ✅ | `TestEngine_SNMPProfile_ModelFailurePreservesLocalAnomalyAndSeesOnlyAggregates`——遍歷真的捕捉到的 request,逐一確認 `current` 裡每個 key 都真的是 profile 宣告過的 feature name |
| malformed FLM reply preserves local anomaly | ✅ | 同一支測試:provider 每次都回錯,episode 仍然照常建立,`SubjectKind=network_device` |
| fallback lane PASS | ✅ | 既有 `TestFallbackProvider_*`（Phase 6 前就有,邏輯沒動,遷移後照樣全綠) |
| no secret/raw OID in captured prompts | ✅ | 同一支測試,對捕捉到的 request JSON 跑 `secretLikePattern`（community/credential/username/password/`1.3.6.1`)確認完全不含 |

## 4. 已知留白

- 沒有針對「真的接一個活的 Ollama/OpenAI/FLM endpoint,餵一個真的
  SNMP subject」跑端到端真機測試——Ollama/OpenAI 兩個協定原本就沒有
  disposable-VM 層級的真機驗證(這是既有 detection-engine spec 的既有
  留白,不是這次新增的),Phase 6 只是延續同樣的驗證深度（單元/fixture
  測試),沒有加大也沒有縮小既有的驗證範圍。
- `model-detection-batch-request-v1.json` 兩份檔案（`internal/detection/
  schemas/`與`monitoring/detection/schemas/`)留在磁碟上但已經沒有任何
  程式碼真的讀它——純粹因為舊 spec 文件仍引用它的檔名。如果未來確定舊
  spec 文件也要一併汰換,這兩個檔案可以安全刪除。
