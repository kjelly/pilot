# Runbook — Detection Engine subject/persistence generalization (Phase 4)

> 撰寫日期：2026-09-02 (UTC)
> 對齊規範：`docs/superpowers/specs/2026-09-01-snmp-monitoring-integration-spec.md`
> §9、§15 Phase 4；`docs/verification/snmp-monitoring-integration.md` C7-C9
> 維護者：sre

---

## 0. 目標與範圍

Phase 4 只做「機制」：把 `internal/detection` 從硬編碼 `pilot_host` 全面
改成 spec §9 定義的 generic `SubjectKey`/identity metadata/sampling
profile/多 profile 設定/持久化 schema。**不含**真的 SNMP feature
profile（`network-device-ifmib-v1`,屬於 Phase 5 的「實作」清單）——這裡
只是把管線改成「任何 profile 都能插進來」,不新增任何會真的產生 SNMP
訊號的程式碼。

Exit gate：
```
existing linux-host fixtures unchanged
DB migration/backfill PASS
managed host alert retains pilot_host
SNMP subject never gets pilot_host
rollback backup procedure proven
```

## 1. 實作內容

- `internal/detection/featureprofile.go`：`FeatureProfile` 新增
  `Identity IdentityProfile`（`label`/`kind`/`siteLabel`/`cohortLabel`）與
  `Sampling SamplingProfile`（`maxSampleAge`/`futureSkewTolerance`）；
  `EffectiveIdentity()`/`EffectiveSampling()`/`MaxSampleAge()`/
  `FutureSkewTolerance()` 在欄位空白時套用 spec §9.3 的
  managed-host/45s/5s 預設值,讓沒有寫 `identity:`/`sampling:` 的既有
  profile（含所有既有測試直接用 struct literal 建構的 FeatureProfile）行為
  完全不變。
- `internal/detection/source.go`：`ClassifySample` 的 45s/5s 改成參數
  （來自 profile 的 `MaxSampleAge()`/`FutureSkewTolerance()`）；
  `GroupSamplesByKey` 改吃 `IdentityProfile`,依 `identity.Label`/
  `identity.SiteLabel` 動態取值（不再寫死 `pilot_host`/`site`）,並實作
  spec §9.4 規則 1（identity label 空值整筆丟棄）、規則 2（非
  managed_host 的 site 空值也丟棄,managed_host 仍容忍空 site）;同時回傳
  每個 key 的 cohort 值（來自 `identity.CohortLabel`,§9.6：cohort 只能
  來自 compiler-controlled label,不能用查表猜）。
- `internal/detection/engine.go`：`RunCycle` 用 profile 的
  identity/sampling 取代硬編碼常數；`buildAlertPayload` 新增
  `pilot_subject`/`pilot_subject_kind`,並依 kind 決定要不要加
  `pilot_host`（managed_host）或 `pilot_target`（其他 kind,§9.8 把
  spec 原文只講 SNMP 的規則推廣成「任何非 managed_host」）；
  `persistTransition`/`Fingerprint` 呼叫都補上 subject kind/site。
- `internal/detection/fingerprint.go`：`Fingerprint` 簽名新增
  `subjectKind`/`site`（spec §9.8）,避免不同 kind 但 ID 字串剛好相同的
  兩個 subject 撞 fingerprint。
- `internal/detection/episode.go`/`baseline_store.go`：`EpisodeRecord`/
  `BaselineSampleRecord` 新增 `SubjectID`/`SubjectKind`,`PilotHost` 降級
  為「CLI/MCP 相容鏡像欄位」——managed_host 時等於 SubjectID,其他 kind
  時為空字串（見 §2 已知偏離）。
- `internal/detection/store.go`：新增 schemaV2 migration（見 §2）,以及
  `migration` struct 新增 `verify`/`postVerifySQL`/`requiresBackup` 三個
  欄位,支援「rename→create→copy→驗證 row count→drop」這種需要在真的丟棄
  舊表前先驗證的 migration,和「已有既存資料的 DB 才需要備份」的判斷。
- `internal/detection/config.go`：新增 `FeatureProfiles
  []FeatureProfileEntry`（多 profile 模式）,與既有
  `FeatureProfilePath`（單 profile 模式）互斥驗證；
  `ResolveFeatureProfilePaths()` 回傳要跑的 profile 路徑清單。
- `cmd/pilot-detection-engine/main.go`：`runServe` 改成對
  `cfg.ResolveFeatureProfilePaths()` 逐一 `buildEngine`,每個 profile 各自
  獨立的 `Engine`（各自的 baseline/lifecycle/fingerprint/episode 狀態,
  spec §9.5）,每個 cycle 依序跑完全部 engine 再彙總 outcomes/metrics 寫進
  同一份 `status.json`/textfile-metrics。`pilot_detection_subject_anomaly_score`
  新 metric 對每個 kind 都填,舊的 `pilot_detection_anomaly_score` 只對
  managed_host 填（§9.9）。
- `cmd/pilot-detection-engine/replay.go`：`pilot_host`/`site` 硬編碼字串
  改用 `profile.EffectiveIdentity().Label/SiteLabel`。

## 2. schemaV2 migration 設計 + 一個真的驗證過的 SQLite 限制

`baseline_samples` 沒有任何表對它下外鍵,所以用「rename→create→copy→驗證
row count→drop」安全地把 PK 從 `(pilot_host, feature, bucket_ts)` 換成
`(subject_id, subject_kind, feature, bucket_ts)`——舊 PK 底下兩個不同
kind 但都沒填 pilot_host 的 subject 會因為 SQL 的 NULL/空字串在 UNIQUE
約束下彼此不算相等,永遠不會被 `ON CONFLICT` 去重,history bucket 會無限
累積。這點已用一支獨立腳本針對 modernc.org/sqlite 實測驗證,不是憑空
假設。

`signal_episodes` 則不能用同一招:它被 `signal_history`/`outbox` 兩個表
下外鍵參照。用一支獨立、跟本 repo 無關的最小重現腳本
（`database/sql` + `modernc.org/sqlite`,建 parent/child 兩表、child 對
parent 下 FK,再對 parent 做 rename→create→copy→drop)實測發現：
`ALTER TABLE ... RENAME TO` 會把 child 表的 FK 定義**自動改指到被搬走的
暫存表名**,就算整個 rename→recreate→drop 包在 `PRAGMA foreign_keys=OFF`
裡也一樣——drop 舊表時仍然報 FK constraint failed,即使先 OFF 再 BEGIN
（因為 rename 造成的 schema 文字重寫跟 pragma 開關是兩回事,重現腳本三種
排列組合都測過)。所以
`signal_episodes` 只做**加欄位**（`ALTER TABLE ADD COLUMN subject_id`/
`subject_kind`,回填後即可),既有 `pilot_host` 欄位維持原本
`NOT NULL`（SQLite 無法用 ALTER TABLE 放寬既有欄位約束)。

**已知、刻意的 spec 偏離**：spec §9.7 point 4 說非 managed 的 subject
應該把 `pilot_host` 寫成 NULL；因為上述限制,這個套件裡非
managed_host 的 episode 之後一律寫 `pilot_host = ""`（空字串)而非真的
NULL。這是被上面驗證過的 driver/schema 限制逼出來的,不是疏漏。

備份機制：`OpenStore` 在跑任何 `requiresBackup` 的 migration 之前,若這個
DB 之前已經至少跑過一次 migration（不是全新安裝),就用
`VACUUM INTO` 對舊檔案做一次一致性快照（`<path>.pre-migration-<unix>.bak`)
——這是 spec §9.7 point 6/8 要求的、operator 要 rollback 回舊 binary 時
唯一可用的東西（舊 binary 沒辦法直接讀新 schema)。

## 3. 測試證據

```
$ go test ./internal/detection/... ./cmd/pilot-detection-engine/... -v
... 152 個 PASS,含全部既有測試(byte-identical 行為,無需修改斷言) ...
--- PASS: TestFeatureProfile_EffectiveIdentity_DefaultsToManagedHost
--- PASS: TestFeatureProfile_EffectiveIdentity_ExplicitProfileOverrides
--- PASS: TestFeatureProfile_MaxSampleAge_DefaultsTo45Seconds
--- PASS: TestFeatureProfile_MaxSampleAge_ExplicitOverride
--- PASS: TestFeatureProfile_Validate_RejectsUnparsableSamplingDuration
--- PASS: TestParseFeatureProfile_SNMPIdentityRoundTrips
--- PASS: TestGroupSamplesByKey_MissingIdentityLabelIsDropped
--- PASS: TestGroupSamplesByKey_NonManagedHostRequiresSiteLabel
--- PASS: TestGroupSamplesByKey_CohortComesFromCompilerControlledLabel
--- PASS: TestGroupSamplesByKey_SNMPSubjectKeyNeverAssignsPilotHost
--- PASS: TestBuildAlertPayload_ManagedHostRetainsPilotHost
--- PASS: TestBuildAlertPayload_NonManagedSubjectNeverGetsPilotHost
--- PASS: TestFingerprint_DifferentKindsNeverCollide
--- PASS: TestSchemaV2_BackfillsSignalEpisodesSubjectIdentity
--- PASS: TestSchemaV2_RecreatesBaselineSamplesWithNewPrimaryKey
--- PASS: TestSchemaV2_RequiresBackupBeforeApplying
--- PASS: TestSchemaV2Migration_BackfillsAndPassesIntegrityCheck
--- PASS: TestConfig_FeatureProfilePathAndFeatureProfilesAreMutuallyExclusive
--- PASS: TestConfig_NeitherFeatureProfilePathNorFeatureProfilesIsRejected
--- PASS: TestConfig_ResolveFeatureProfilePaths_SingleModeReturnsThePath
--- PASS: TestConfig_ResolveFeatureProfilePaths_MultiModeSkipsDisabled
ok  	github.com/kjelly/pilot/internal/detection	1.0s
ok  	github.com/kjelly/pilot/cmd/pilot-detection-engine	0.0s
```

`go test ./...`：只剩既有 baseline 4 個失敗（sandbox 無 tty 的
bubbletea 測試 x3、log-shipping 既有 bug、以及
`TestRepairClient_CapabilitiesAndPlan_RealSubprocess` 併發負載下的既有
flake,皆與本次改動無關）。

## 4. Exit gate 對照

| Exit gate 項目 | 狀態 | 證據 |
|---|---|---|
| existing linux-host fixtures unchanged | ✅ | 全部既有測試零修改斷言,只做函式簽名的機械調整（新增參數),全綠 |
| DB migration/backfill PASS | ✅ | `TestSchemaV2_*`、`TestSchemaV2Migration_BackfillsAndPassesIntegrityCheck` |
| managed host alert retains pilot_host | ✅ | `TestBuildAlertPayload_ManagedHostRetainsPilotHost` |
| SNMP subject never gets pilot_host | ✅ | `TestBuildAlertPayload_NonManagedSubjectNeverGetsPilotHost`、`TestGroupSamplesByKey_SNMPSubjectKeyNeverAssignsPilotHost` |
| rollback backup procedure proven | ✅ | `TestSchemaV2_RequiresBackupBeforeApplying`(真的呼叫 `VACUUM INTO` 並確認產出檔案) |

## 5. 已知留白

- 多 profile 模式（`cfg.ResolveFeatureProfilePaths()` 回傳多個路徑、
  `runServe` 對每個都建一個獨立 Engine）只有 config 解析/驗證層有完整單元
  測試,**沒有**用 disposable VM 實跑「linux-host-v1 + 一個假的第二
  profile 同時跑一整個 scheduler cycle」——因為 Phase 4 本身不新增任何真
  的第二個 profile,Phase 5 導入 `network-device-ifmib-v1` 時才會是第一個
  真正的多 profile 使用場景,屆時應該補上這個端到端證據。
- Model-provider 狀態/統計在多 engine 模式下,目前是「取第一個有設定
  Provider 的 engine」而非跨 engine 加總——因為目前設定檔的
  `modelProvider` 是全域唯一一份,並非 per-profile,所以在唯一支援的用法
  下這個簡化是精確的,但如果未來允許 per-profile 的 model provider,這裡
  要重新設計成真的跨 engine 彙總。
- `pilot_detection_subject_anomaly_score`/`pilot_detection_anomaly_score`
  兩個 metric 目前在 `main.go` 才有填值邏輯,`internal/detection`
  package 本身沒有針對這兩個 metric 寫渲染層級的專屬單元測試（只驗證了
  `metrics.go` 的 `Render()` 格式邏輯本身能正確處理新欄位,沒有對
  `main.go` 的填值分支寫整合測試)——這個分支邏輯不複雜,但誠實記錄尚未
  覆蓋。
