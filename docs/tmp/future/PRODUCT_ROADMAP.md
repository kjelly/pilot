# 原始問題

如何讓 pilot 更完整地解決「正確交付軟體」：從自然語言需求出發，由
Codex/Claude 直接產生 verification spec、apply playbook 與 regression test，
再由 pilot 透過 docker/VM、TUI deploy/edit、verify 與 evidence 完成可信任的
交付。Spec v2 與後續產品應往哪個方向演進？

# 報告內文

> **文件狀態：產品規劃，不是可執行 runbook**
>
> 本文件描述目標與里程碑；只有下表標成「已實作並驗證」的項目可視為目前產品
> 行為。Final design 代表 production implementation 可開工，不代表 runtime 已
> 支援；spike 與 fixture 也不等於正式功能。
>
> **Production implementation：GO（2026-07-18）**。三份 blocking RFC 已
> Final，conditional acceptance、component placement、secret transport、
> evidence idempotency 與 M0.2 timeout/scope 均已有 canonical contract。

## 目前實作狀態（2026-07-18）

| 項目 | 狀態 | 已完成邊界 |
|---|---|---|
| M0.1 deploy exit-code | **已實作並驗證** | preview/apply 非零、binary 啟動失敗、preflight failure 後停止皆回 error；乾淨取消維持 exit 0 |
| `verify --dir` 原始錯誤 | **已實作並驗證** | no-report 時保留 per-spec parse/runner error |
| M0.2 per-host verify | **已實作並驗證** | single-host invocation、bounded workers、Ansible scope adapter、callback runner 已接正式 verify |
| Verification safety | **部分已實作** | v2 readOnly/isolatedMutation 與 secretRef fail-closed；secret-aware transport/deploy wiring 待 M0.4 |
| Append-only evidence | **已實作並驗證** | schema v13、operation/evidence idempotency、heartbeat/finalization；rotation 移 P5 |
| ComponentContract | **loader baseline 已實作／runtime wiring 待完成** | strict loader、role 1:N、dependency placement、provider selection、autoDeploy eligibility；尚未接 deploy/TUI |
| M0.3/M0.4 | **M0.3 已實作；M0.4 尚未實作** | append-only evidence 已接 standalone verify；deploy transaction 尚待整合 |
| Spec v2（M2.1–M2.3） | **M2.1/M2.2 已實作；M2.3 尚未實作** | strict v2 parser/runtime 已有 local CLI evidence；migration 與跨 target acceptance 待完成 |
| P3/P4/P5 | **尚未實作** | 仍是 roadmap |

## 產品北極星

pilot 的目標流程應是：

```text
Requirement Brief
  → Delivery Bundle
  → Deterministic Delivery Transaction
  → Verifiable Evidence
```

- **Requirement Brief**：使用者描述目標架構、限制、風險與不可違反事項。
- **Delivery Bundle**：coding agent 產生並經 review 的 spec、apply playbook、
  regression test 與 actual-run evidence 計畫。
- **Deterministic Delivery Transaction**：pilot 執行 preflight、preview、apply、
  per-host verify、idempotency 與必要的 rollback。
- **Verifiable Evidence**：保存這次交付使用的版本、inventory、host、輸入摘要與
  每個 host × spec row 的結果。

產品定位應維持 **agent-native、但不在 runtime 內嵌 agent**：

- Codex/Claude 是 repo 的主要 authoring 介面。
- pilot runtime 不負責理解自然語言、不綁定 model/provider，也不維護 agent loop。
- pilot 負責把 agent 產物變成可 lint、可執行、可驗證、可追溯的交付交易。

## 設計原則

1. **Spec-first，不是 generator-first**：先固定「何謂完成」，再實作 mutation。
2. **驗證外部行為**：優先測 effective state、真實連線、allow/deny、建立與撤銷，
   不只重讀 playbook 寫入的檔案。
3. **Fail closed**：啟動外部程式失敗、host 缺漏、matcher 不明確、依賴不完整，
   都不能被當成成功或自動跳過。
4. **Per-host 判定**：多主機部署的最小結果單位是 `(deployment, host, spec row)`。
5. **Applicability 先於 verdict**：條件不成立的 row 記
   `not_applicable` + 原因，不執行 probe、不冒充 PASS；條件解析失敗 fail closed。
6. **Evidence append-only**：後一次執行不能覆蓋前一次交付事實。
7. **人保留授權**：agent 可以產生 bundle，但 destructive boundary、風險接受與
   staging/prod 上線授權仍由人確認。
8. **格式與 authoring model 分開演進**：Spec v2 在 schema 尚未實作前，只代表
   authoring contract；不提前加入 parser 不認識的欄位。

## P0：先完成可信任的交付交易

最高優先不是增加更多角色，而是讓一般 deploy 具備完整且不可誤判的交易語意：

1. preflight
2. preview / check / diff
3. apply
4. 對應 spec 的 per-host verify
5. evidence persist
6. idempotency（依 stage/policy 決定是否必跑）
7. 失敗時依 policy rollback

必要能力：

- preview、apply、verify、evidence 任一步失敗，整體必須回傳非零結果。
- 外部程式無法啟動不得留下成功的 exit code。
- verify 必須維持唯讀；需要傳入 probe 變數時，不得先改 target 主機狀態。
  注意：現況並非唯讀（存在寫入遠端 env 檔與 POST/PUT/DELETE 型 self-test
  check）；Final Safety RFC 已定案 readOnly/isolatedMutation、授權/cleanup 與
  secret-aware playbook/module transport。runtime 必須照 RFC 實作後才可自動執行。
- 多台主機不得共用一個被壓扁的 row verdict；必須保存每台主機的 stdout、stderr、
  exit code、matcher verdict 與時間。
- production deploy auto-verify 只執行 Spec v2；v1 保留 manual verify。optional
  row 必須以 declarative applicability 表達，不能靠 prose 說「預期 fail」。
- apply 成功但 verify 失敗，部署仍然是失敗；是否 rollback 由明確 policy 決定。

P0 完成定義：

- 每次 deploy 都有唯一 run ID。
- 任一 applicable host × row 失敗都能讓整次交易失敗；not_applicable 不算 PASS。
- 使用者能從 run ID 回答「哪個版本，以什麼輸入，部署到哪些主機，哪一列驗證
  成功或失敗」。

## P1：把 Delivery Bundle 變成 repo 的正式契約

目前 spec、apply playbook、regression test、inventory role contract、deploy
catalog、site 順序與交付文件容易靠人工同步。建議建立可 lint 的
`DeliveryBundle` / `ComponentContract`，至少描述：

- component / role ID
- verification spec
- apply playbook
- regression tests 與 spec row tag coverage
- dependencies / conflicts
- 支援的 OS 與版本
- host cardinality，例如 exactly-one、one-or-more
- 最低 CPU / RAM / disk
- 必要 group vars、vault key 名稱與輸出 endpoint
- stage policy、experimental 狀態
- backup、rollback、upgrade 與 decommission contract

這個 contract 應成為下列功能的共同來源：

- TUI component 選單與相依性提示
- inventory lint 與 host cardinality 檢查
- deploy DAG 與執行順序
- bundle completeness / traceability lint
- DELIVERY 與元件對照表

不要一開始就設計成 LLM tool schema；它首先是一般、可測試、可版本化的產品資料
模型，coding agent 只是它的作者之一。

P1 完成定義：

- 新增 component 時，不必手動在多處重複宣告相同事實。
- deploy 前即可擋下缺少依賴、主機數量錯誤、資源不足與未提供必要變數。
- 跨欄位必要條件使用 machine-readable input rules，不依賴 apply playbook
  執行到 pre_tasks 才發現。
- 每份 spec row 都能追到負責實作它的 apply tag 或明確標示為 verify-only。
- 每個 dependency 都能回答是 same-host、provider endpoint 或純 plan ordering；
  provider 多台時必須明確選擇，不取 group 第一台。

## P2：Spec v2 成為明確、可遷移的驗收 schema

Spec v2 不應嘗試把 probe command 猜成 mutation。verification spec 與 apply
playbook 維持不同責任：spec 定義可觀察結果，apply 由 coding agent 直接實作。

建議的 v2 資訊：

- `intent`：需求目標、來源與決策背景
- `targets`：role、拓撲、host scope、支援平台
- `inputs`：一般變數、secret reference、必填與 validation
- `checks`：穩定 row ID、probe、typed matcher、timeout、per-host / aggregate
  scope、declarative `appliesWhen` 與 canonical action object；false 產生
  `not_applicable` evidence
- `traceability`：對應 apply tags、regression invariant
- `safety`：destructive boundary、stage gate、rollback requirement
- `evidencePolicy`：需要保存的輸出、idempotency 與 retention
- `compatibility`：schema version 與最低 pilot 版本

typed matcher 應取代難以閱讀的魔法字串，例如明確表達：

```yaml
expect:
  exitCode: 0
  stdout:
    equals: active
```

遷移原則：

- v1 與 v2 parser 在過渡期並存。
- 提供 lint finding 與明確的轉換工具，不做靜默語意轉換。
- 無法安全轉換的 matcher 標成需要人工確認。
- `pilot spec --generate` 保持診斷用途，不恢復「從 probe heuristic 產生正式
  apply」的產品暗示。

P2 完成定義：

- matcher 不再依賴隱晦 prefix 才能理解。
- parser 能明確拒絕未知版本與未支援欄位。
- 同一份 v2 spec 在 local、docker-target、vm-target 與真實 inventory 上具有一致
  的判定語意。
- v1 legacy whitespace/matcher verdict 零回歸；v2 使用明確的新 normalization。

## P3：讓 TUI 從「填 YAML」提升成「組合架構」

`pilot edit` / `pilot deploy` 的下一步應由 ComponentContract 驅動：

- 先選想要的 capability，再解析必要 component 與依賴。
- 以部署 DAG 呈現順序、目標主機與跨主機連線。
- 在 apply 前顯示缺少的 host、vars、vault keys、resource 與 backup policy。
- 對多 host component 要求明確選擇或符合 cardinality，不直接取 group 第一台。
- experimental 或未取得 actual-run evidence 的 component 預設隱藏或明確警示。
- 支援 day-2 的 upgrade、scale、decommission，不只處理首次安裝。

P3 完成定義：

- 使用者能在 apply 前看懂「會在哪些主機建立哪些 component，以及為什麼」。
- TUI 與非互動 CLI 使用同一份 plan 與 validation engine。
- 移除 component 時會明確處理資料保留、備份與相依元件，而不是只從 inventory
  刪除角色。

## P4：建立 coding-agent authoring eval

既然 Codex/Claude 是主要 authoring 介面，就應測量產出的 Delivery Bundle，而不是
把 model 放回 pilot runtime。

建立一組版本化 Requirement Brief corpus，評估：

- spec lint 是否一次通過
- 是否主動列出假設、未知項與風險
- spec row 是否驗證 effective state
- apply tag coverage 與變數命名是否對齊
- 是否洩漏 secret 或硬編 host-specific 值
- regression test 是否鎖住關鍵 invariant
- vm/docker target 第一次通過率與修復迭代次數
- 第二次 apply 是否 `changed=0`

eval 應該 model-independent，讓不同 Codex/Claude 版本都能用相同 deterministic
gate 比較，而不是依靠主觀閱讀判斷產物「看起來不錯」。

## P5：證據、查詢與供應鏈追溯

建議把 deployment run 保存成 append-only record：

- pilot、Git、spec、playbook 與 inventory 版本
- artifact / image digest
- 實際 host set 與 stage
- 非敏感輸入摘要與 secret reference 名稱
- preview / apply recap
- 每個 host × row 的 verification evidence
- idempotency、rollback 與最終狀態
- 操作者授權事件與時間

後續才能可靠提供：

- 某台主機目前最後一次成功交付的是哪個版本
- 哪些主機尚未通過新版 spec
- 某個 CVE / component / spec row 影響哪些 deployment
- 上次成功版本與這次失敗版本的 evidence diff

## 建議執行順序

| 階段 | 主題 | 為什麼先做 |
|---|---|---|
| P0 | 交付交易閉環 | 先消除「實際失敗但工具看起來成功」 |
| P1 | Delivery Bundle / ComponentContract | 建立後續 TUI、lint、DAG 的單一事實來源 |
| P2 | Spec v2 schema | contract 穩定後再版本化格式，避免 speculative schema |
| P3 | 架構組合 TUI | 用已驗證的 contract 提升部署 UX |
| P4 | Coding-agent eval | 量化 bundle 品質與不同模型版本的回歸 |
| P5 | Evidence query / supply-chain traceability | 在可靠 run model 上建立稽核與營運能力 |

最先應完成的三件事：

1. deploy 後必做 per-host verify，任一步失敗必須非零退出。
2. 建立 append-only deployment run 與 host × row evidence。
3. 定義 DeliveryBundle / ComponentContract，讓 spec、apply、inventory 與 TUI
   不再靠人工同步。

完成這三項後，pilot 才會從「依靠開發紀律維持正確」進一步成為「工具本身能證明
這次交付是否正確」的產品。

## 明確不做

- 不把 LLM provider、prompt orchestration 或 agent loop 加回 pilot runtime。
- 不把 verification command heuristic 編譯成正式 mutation playbook。
- 不要求使用者重新從空白頁手寫完整 spec。
- 不在 parser 尚未支援前宣稱已提供 Spec v2 檔案格式。
- 不以單一總體 PASS 掩蓋部分主機或部分 spec row 的失敗。

## 建議接續產出的設計文件

1. ADR：coding-agent authoring 與 deterministic runtime 的責任邊界。
2. RFC：DeliveryBundle / ComponentContract schema。
3. RFC：Spec v2 schema、matcher 與 v1 migration。
4. ADR：Deployment Run / Evidence append-only data model（須明確選擇
   immutable event stream 或「run header + 一次受限 finalization」其中一種
   模型，並涵蓋 redaction、大小上限與 retention）。
5. RFC：Verification safety boundary（唯讀邊界的定義，與既有寫入型檢查的
   去向）。
6. Test Strategy：Requirement Brief corpus 與 coding-agent eval 指標。
