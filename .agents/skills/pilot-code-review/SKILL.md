---
name: pilot-code-review
description: Review pilot repository PRs, branches, or local changes for deployment correctness, Ansible execution semantics, effective state, recovery, verification accuracy, and Go lifecycle invariants. Use for requested pilot code reviews or bug-fix reviews; ordinary implementation and deployment requests do not activate this review workflow by themselves.
---

# Pilot Code Review

找出有具體觸發條件、會改變實際行為的缺陷。追查 pilot 的執行契約：
需求 → spec/contract → CLI 計畫 → 實際目標與參數 → mutation → effective state → verify。

## 範圍與工作方式

- 以 skill 所在 repo 的 Git root 為基準解析下文的 repo 路徑，不寫死工作站路徑。
- 先讀目前的 `AGENTS.md`；它與 `docs/actual-run-evidence.md` 是 repo 規則的來源。
  歷史案例用來選檢查方向，不能取代目前規則或外部工具的實際語意。
- 修復或審查前也讀 [references/pilot-history-checks.md](references/pilot-history-checks.md)：
  近期 PR 的缺陷類別、要證明的 invariant、`target_validation` 的決定方式，以及可直接放進
  task envelope 的提示詞；`issue-to-pr`、`pr-ready` 與 `pr-review-merge` 引用的是同一份。
- 使用者指定 PR、branch、commit 或 local changes 時，以該範圍為準。
  未指定範圍時先看 working tree 與 staged diff；若兩者皆空且沒有可推定的目標，
  詢問要 review 哪個 revision，不自行擴大成全 repo audit。
- review 預設讀取 diff、相鄰程式、測試與現有 evidence。修改程式、建立 candidate、
  執行測試或部署依使用者已授權的任務範圍進行；不因本 skill 自行啟動 target
  mutation、切換使用者 branch 或發送 GitHub review/comment。
- 先看結果摘要；有失敗或矛盾時才讀相關 transcript 的局部內容。

## Review 流程

### 1. 確認被審查內容

記錄 base/head（local changes 包含 staged/unstaged 狀態）、變更檔案與操作 intent。
檢查相關 spec、`contracts/`、inventory contract、apply playbook 與 regression，
分清 acceptance 的要求與實作的假設；不為了實作會 PASS 而放寬 acceptance。
區分此次變更新增或放大的問題、與無關的既有 base 缺陷。

### 2. 追到實際執行與觀察

從變更所在入口追查必要的 caller/callee、shared include、provider 與 verifier。
依變更類型讀 [references/review-checks.md](references/review-checks.md) 對應段落：

- CLI / inventory / deploy orchestration：A。
- Ansible tasks / tags / template / check mode：B。
- service config / container / migration / rollback：C。
- spec / parser / validator / authorization gate：D。
- Go store / lifecycle / scheduler / goroutine：E。
- regression / actual-run evidence / CI：F。

從程式與目標 inventory 的事實判斷，不從命名或 spec 設計意圖猜 host、group、
FQDN、vars precedence、工具 exit code 或 rollback 能力。

### 3. 用相關情境挑戰契約

選會受此次變更影響的情境，從 code、既有 tests 與 evidence 確認行為。
未執行的情境標為未驗證，不能把思考推演寫成重現結果。

| 變更會影響 | 要追查的情境 |
|---|---|
| 安裝或相依角色 | fresh host 的 check mode、真正 apply、既有 host 的 upgrade |
| tags / includes / gates | full run、單一 row/component tag、pilot 合成的 dependency tags |
| mutation / reload / cleanup | mutation 前拒絕、寫入後失敗、reload 後失敗、修正後重跑 |
| 多 host / stage / vars | 分離的 provider/consumer、limit、vars file 衝突、各 run 的 stage |
| 授權 / parser | allowed 與 denied、等價的不同拼法、空值、typed YAML、非法輸入 |
| 時間 / lifecycle / concurrency | 邊界前後、重啟恢復、長時間存活、並行交錯、cleanup 早退 |

穩態 apply 的重跑應依契約收斂且 `changed=0`；一次性 migration 的重跑可能應明確
拒絕。依操作契約判斷，不要求所有操作都能無條件重複執行。

### 4. 查驗測試與 evidence 的辨識力

確認測試能分辨錯誤與正確狀態，而不是只鎖 YAML 文字或函式呼叫。檢查 regression
在修正前是否會失敗，以及 fake 是否省略了導致 bug 的真實語意。
需要部署證明的變更，核對 candidate/tree、execution-affecting hashes、target/inventory、
verdict 與未覆蓋情境；新 head 有執行相關修改時，舊 evidence 不證明新 head 正確。
缺證據是 validation gap；只有能指出觸發條件與錯誤行為時才列為已確認 bug。

## Finding 與結論

先列實際缺陷，依影響排序。每個 finding 包含：

- 檔案與精確行號；對 PR 優先錨定 changed line，再解釋相關 call path。
- 具體輸入／初始狀態／操作，以及 expected 與 actual 的差異。
- 使用者或營運影響、依據（code 推演／既有測試／實跑 evidence），以及修正方向。

不把 checklist 每一項都當成 finding，不把風格建議升級成可靠性缺陷。
同類問題先搜尋共用 helper 與其他 caller，合併報告範圍並指出適合鎖住的 repo-wide
invariant；只有收到修復任務時才修改，且遵守 `AGENTS.md` §5.10。

結尾給 review 範圍、已確認 findings、驗證方式及仍缺少的證據。沒有 findings 時寫
「未發現具體缺陷」，說明驗證限制，不宣稱已證明不存在 bug。
