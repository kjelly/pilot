# 原始問題

評估以下文件目前是否已可開始實作，並將 review 意見寫入
`docs/tmp/future/review.md`：

- `docs/tmp/future/PRODUCT_ROADMAP.md`
- `docs/tmp/future/IMPLEMENTATION_PLAN.md`
- `docs/tmp/future/SPEC_V2_IMPLEMENTATION_PLAN.md`

# 報告內文

> Review 日期：2026-07-18（第六輪，獨立複核「修訂 6」關閉結果）
> Review 基準：commit `faa2d9c` 加上本工作樹修訂
> 文件性質：產品／實作規劃 review，不是可執行 runbook。

## 第六輪複核範圍與方法

前一輪（工作樹上已寫好的「修訂 6」）宣稱三份 RFC 已 Final、設計準備度
100%，可全面開始 production implementation。本輪不採信既有結論本身，
獨立重跑下列查核，逐項對照文件宣稱與實際 repo 狀態：

- 直接讀三份 Final RFC 全文（Safety、Evidence、ComponentContract）與
  `SPEC_V2_IMPLEMENTATION_PLAN.md`、`M0_2_PER_HOST_VERIFY_SPIKE.md` 全文，
  檢查交叉引用是否一致、是否有殘留的自相矛盾或未閉合的技術問題。
- 核對程式碼事實：`deploy_catalog.go` Key 數量、`executeDeployment` 錯誤
  路徑、`runVerifyMulti` 是否保留 per-spec 原始 error、
  `internal/tools/expected_hosts.go`／`expected_hosts_test.go`／
  `internal/contract/fixture_schema_test.go` 是否存在且內容與文件宣稱相符。
- 實際重跑 `go build ./...`、`go test ./internal/contract ./internal/tools`、
  完整 `go test ./...`、`go test -race ./...`、`git diff --check`（皆在本
  工作樹以 `GOCACHE=/tmp/pilot-go-build` 等 sandbox-safe 暫存路徑執行）。
- 抽查 `internal/contract/fixture_schema_test.go` 的 diff，確認新增的
  `inputRules`／`groupVars.type`／`dependencies.relation`／
  `bindings.sourceSelection`／`verification.autoDeploy` 欄位不只是 YAML
  文字修改，而是有對應的正負案例真正鎖住語意。
- 抽查六份 contract fixture 的變數命名（`restic_repository`、
  `restic_s3_port`、`loki_target_host` 等）是否真的對應
  `group_vars/*.example.yml` 與既有 playbook 變數，不是杜撰欄位。
- 核對先前已修正過的 bug 是否仍保持修正狀態（log-shipping fixture 的
  `targetGroupExpression` 應為 `wazuh-manager` fallback，對照
  `playbooks/site.yml:184` 附近的實際邏輯）。

**結論：本輪未發現與「修訂 6」結論矛盾的事實錯誤。** 三份 RFC 的 Final
狀態是有實質內容支撐的技術收斂（每份都有具體 schema、驗收條款與
非目標），不是單純因為使用者要求關門就蓋章；程式碼引用座標、規模數字、
測試存在性與六份 fixture 的欄位命名逐一核實皆為真。以下沿用並確認前一輪
判定，同時記錄本輪查核證據，供下一次修訂時比對。

## 最終判定

**GO：可以全面開始 production implementation。**

這個 GO 的精確意思是：原 review 中會改變 schema、runner、transaction 或
compatibility contract 的設計阻擋項已全部關閉，團隊可以依 dependency graph
開始 production code。它不表示尚未實作的 runtime 已完成，也不表示所有 milestone
可忽略前置而同時合併。

設計準備度為 **100%**；runtime 完成度仍依各 milestone 的狀態計算。

## 原阻擋項關閉結果

| 原 finding | 最終決策 | 可驗證的落點 |
|---|---|---|
| conditional row 無法區分合法不適用與失敗 | Spec v2 新增 strict declarative `appliesWhen`；false 記 `not_applicable`、不執行 probe、不算 PASS；解析錯誤 fail closed。production auto-verify 只接受 v2 | `SPEC_V2_IMPLEMENTATION_PLAN.md` §3.2–§3.3、§4 M2.2 |
| component ↔ role 1—1 假設錯誤，dependency 無 placement | 固定 component → one role、role → zero-or-more components；dependency relation 為 `sameHosts`、`providerEndpoint`、`planOnly`；provider selection 為 `exactlyOne`、`all`、`explicit` | `COMPONENT_CONTRACT_RFC.md` §1、§5–§6；六份 Final schema fixtures |
| `action` shape 不一致、secretRef/transport 未閉合 | canonical action 只接受 object，且 v2 必須顯式宣告；`secretRef` 為 `{provider: ansibleVar, name}`；secret check 走 `ansible-playbook` + `no_log` secret-aware module + child stdin，pilot 不取得 plaintext | `VERIFICATION_SAFETY_BOUNDARY_RFC.md` §3、§6、§9；Spec v2 §3 |
| evidence retry、cancel finalization、maintenance identity 未定 | event/evidence 都有 operation idempotency；evidence 有 attempt/content hash；cancel 使用 bounded independent finalization context；M0.3 retain-all，rotation 移 P5 並使用獨立 admin stream | `APPEND_ONLY_DELIVERY_EVIDENCE_RFC.md` §2–§7、§10 |
| M0.2 standalone scope 與 timeout model 未定 | 每個 host × row 使用 single-host isolated Ansible invocation，最多 8 workers；timeout 可唯一歸因。無 selector 時，Targets 成為 standalone default scope；無 Targets 的 remote verify 要求明確 selector 或 `--local` | `M0_2_PER_HOST_VERIFY_SPIKE.md`、`IMPLEMENTATION_PLAN.md` M0.2；`expected_hosts` regression test |
| v1 zero-regression 與 v2 normalization 衝突 | v1 保留 legacy `strings.TrimSpace` 與 rc-echo evaluator；v2 才使用 CRLF normalization + 移除一個 trailing newline；由 `ResolvedRow.Normalization` 明確分派 | `SPEC_V2_IMPLEMENTATION_PLAN.md` §3.3、M2.1 |

## Schema gate 結果

ComponentContract 六份 fixture 已同步為 Final schema fixture，並加入：

- typed `groupVars`；
- strict `inputRules`，可在 apply 前表達跨欄位 all/any preflight；
- dependency placement relation；
- provider `sourceSelection`；
- 必填的 `verification.autoDeploy`；
- v1 spec fixture 一律 `autoDeploy: false`。

production loader baseline 現在已提供 strict decode、local schema validation、stable
directory loading、root-path containment 與 canonical `contracts/` Catalog；review
mirrors 與 canonical contracts 的 semantic equality 由 regression test 鎖住。它尚未
接 deploy catalog、site lint 或 TUI；目前可用唯讀 `pilot contract lint` 檢查載入。

M0.2 pure resolver 也已補上「spec Targets 在無 explicit selector 時成為 default
scope」的 regression test，讓文件決策與現有 executable contract 一致。

## 可開工順序

以下三條 production workstream 可以立即平行開始：

1. **M0.2**：Ansible inventory/pattern adapter、bounded per-host runner、
   deterministic results。
2. **M0.3**：schema v13、RunWriter、append-only enforcement、heartbeat 與
   finalization。
3. **M1.1**：production ComponentContract loader/API，將 test-only schema 與
   validator 搬入正式 package。

後續依賴固定如下：

- M2.1 在 M0.2 合併後開始，避免同時重寫 verifier core。
- M2.2 在 M2.1 後實作 v2 parser、applicability、action 與 secretRef runtime。
- M1.2/M1.3 在 M1.1 production loader 後收斂全量 contracts 並接 planner。
- M0.4 在 M0.2、M0.3、M1.1 production mapping 與 M2.2 完成後接 deploy
  transaction。
- P3/P4/P5 依主計畫 dependency graph 展開，不再需要新的 architecture RFC
  才能排程。

## 仍須在實作階段完成的驗收

以下是 milestone DoD，不是新的 design blocker：

- secret-aware module 必須通過 fake process recorder 與 localhost Ansible Vault
  leakage test；完成前含 secretRef 的 spec fail closed。
- per-host runner 必須以 multi-host target 驗證 timeout、unreachable、missing、
  observed/expected host mismatch 與 deterministic ordering。
- schema v13 必須通過 v12 migration replay、concurrent append race、
  uncertain-commit retry 與 UPDATE/DELETE rejection。
- Spec v2 必須通過 local、docker-target、vm-target 與一般 inventory backend
  一致性驗收；無真實 staging evidence 時不得宣稱已在真實主機驗證。
- v1 parser/manual verify 長期保留；任何要自動接入 production deploy 的 spec
  必須先遷移到 v2 並關閉所有 `needsReview`。

## 本輪實際驗證

以下命令已於本工作樹實際執行。因完整測試需要 localhost listener、Docker socket
與 Ansible temp，完整 gate 使用 sandbox 外執行，暫存位置固定在 `/tmp`。

```text
GOCACHE=/tmp/pilot-go-build go test ./internal/contract ./internal/tools
```

結果：PASS，exit code 0。

```text
env GOCACHE=/tmp/pilot-go-build ANSIBLE_LOCAL_TEMP=/tmp/pilot-ansible-local \
ANSIBLE_REMOTE_TEMP=/tmp/pilot-ansible-remote go test ./...
```

結果：全部 PASS，exit code 0。

```text
env GOCACHE=/tmp/pilot-go-build go build ./...
```

結果：PASS，無輸出，exit code 0。

```text
env GOCACHE=/tmp/pilot-go-build ANSIBLE_LOCAL_TEMP=/tmp/pilot-ansible-local \
ANSIBLE_REMOTE_TEMP=/tmp/pilot-ansible-remote go test -race ./...
```

結果：全部 PASS，exit code 0。

```text
git diff --check
```

結果：PASS，無輸出，exit code 0。

這些結果證明本次文件支撐用的 schema fixture、scope resolver 與現有 code baseline
健康；它們不冒充尚未存在的 schema v13、production loader、per-host runner 或
Spec v2 runtime evidence。

## 第六輪複核證據（獨立重跑，非沿用上一輪輸出）

以下命令與檢查為本輪獨立重新執行，未直接採信前一輪記錄的結果：

```text
rg -n '^\s*Key:' cmd/pilot/cmd/deploy_catalog.go | wc -l   # 21
GOCACHE=/tmp/pilot-go-build go build ./...                  # exit 0，無輸出
GOCACHE=/tmp/pilot-go-build go test ./internal/contract ./internal/tools  # ok
env GOCACHE=/tmp/pilot-go-build ANSIBLE_LOCAL_TEMP=/tmp/pilot-ansible-local \
  ANSIBLE_REMOTE_TEMP=/tmp/pilot-ansible-remote go test ./...             # 全部 ok
env GOCACHE=/tmp/pilot-go-build ANSIBLE_LOCAL_TEMP=/tmp/pilot-ansible-local \
  ANSIBLE_REMOTE_TEMP=/tmp/pilot-ansible-remote go test -race ./...       # 全部 ok
git diff --check                                            # 無輸出
```

另以人工讀碼／讀檔核對（非跑指令）：

- `cmd/pilot/cmd/deploy.go` 的 `executeDeployment`：preview／apply 非零時確實
  回傳 `error`（`❌ 預覽失敗`／`❌ 套用失敗`），使用者取消維持 `nil`——與 M0.1
  exit-code 契約表一致。
- `cmd/pilot/cmd/verify.go:364-370`（`runVerifyMulti`）確實保留
  `runVerifyOne` 的原始 error 並印出，不是丟棄成「no report produced」看不出
  原因。
- `internal/tools/expected_hosts.go` 的 diff：新增
  `executionSelectorProvided` 旗標，未提供 execution selector 時
  `resolved = specHosts`（standalone default scope），對應
  `expected_hosts_test.go` 新增的
  `"spec targets become default scope without explicit selector"` 案例——
  文件宣稱與程式碼行為一致。
- `internal/contract/fixture_schema_test.go` 的 diff 新增
  `fixtureInputRule`／`fixtureVerification`／`groupVar.Type` 檢查與至少 7 個
  對應負向案例（如 `"input rule is a strict union"`、
  `"group var default must match declared type"`、
  `"v1 fixture cannot enable auto deploy"`），證明六份 fixture 的欄位擴充不是
  純文字編輯，而是有測試鎖住的語意。
- 六份 fixture 新增變數（`restic_repository`、`restic_s3_port`、
  `restic_s3_bucket`、`restic_backup_schedule`、`restic_retention_*`）逐一比對
  `group_vars/restic-backup.example.yml`，命名與預設值相符，非杜撰欄位。
- `log-shipping.yaml` 的 `targetGroupExpression` 仍是
  `"log-server if present, otherwise wazuh-manager"`，與
  `playbooks/site.yml:184` 附近的實際 fallback 邏輯一致——先前輪次抓到的
  「誤寫 dashboard」問題沒有復發。

**本輪未發現新的事實錯誤或設計缺口。** 與前一輪（「修訂 6」）給出的 98%
可信度、GO 判定一致，予以維持。

## 綜合結論

三份主文件現在使用同一組 canonical contract：

- roadmap 定義產品方向與完成條件；
- implementation plan 定義依賴與開工順序；
- Spec v2 plan 定義 parser/runtime/migration 語意；
- 三份 Final RFC 分別鎖 safety、evidence 與 component contract。

原 review 的六類阻擋項已閉合，沒有剩餘 schema 或 transaction 決策需要在寫
production code 前再次選案。可依本報告的三條平行 workstream 立即開工。

## 可信度

**98%**

依據：三份主文件、三份 Final RFC、M0.2 spike/resolver、六份 contract fixtures、
現行 verifier/store/deploy code，以及 full test/build/race gate 已交叉核對；
第六輪獨立重跑同一組驗證且額外抽查測試語意與變數命名真實性，未發現偏差。
剩餘 2% 是實作階段才可能暴露的 Ansible/runtime integration 問題，已被列為
fail-closed DoD，不會再造成設計歧義。
