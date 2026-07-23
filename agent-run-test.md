# 任務：依 runbook 從零重建、部署並驗證 Minimal PoC

請重新驗證 `docs/runbooks/minimal-poc-architecture.md`。這是一項實作與驗證任務：你必須依該 runbook 從零建立環境、完成部署，並執行其部署後驗證；不要只做靜態閱讀、lint 或提供建議。

`docs/runbooks/minimal-poc-architecture.md` 是拓樸、設定、部署順序與驗收項目的唯一業務來源。若本提示詞與 runbook 的角色、變數、驗證項目或預期行為衝突，先停止並回報衝突，不得自行選一邊或改寫 runbook。

## 成功定義

只有同時符合以下條件才能宣告完成：

1. 依 runbook 宣告的 VM 拓樸，從乾淨環境重建全部 VM 與暫存工作目錄。
2. `hosts.yml`、`group_vars/`、`.vault/` 與 inventory 都由 `pilot edit` 和 `pilot inventory generate` 產生；不得手寫或以 `sed`、`yq`、redirect 等方式修改 YAML。
3. 所有實際套用都經由 `pilot deploy` wizard 完成：一次全站 `site.yml` 部署，以及 runbook 指定、未納入 `site.yml` 的獨立元件（目前為 `freeipa-identity`）。agent 可以用 `pilot deploy --actions` 自動回答 wizard，但仍不得直接呼叫 `ansible-playbook` 套用。
4. runbook §4 的每一項部署後驗證都實際執行並通過，包括 FreeIPA allow/deny 與 `ipa hbactest`、Grafana/Thanos/Prometheus、Loki/Promtail、restic、Wazuh FIM，以及 FreeIPA identity reconciler 的移除／復原／drift／冪等性驗證。
5. 每個互動 wizard 與每個唯讀驗證步驟都有可驗證的 `trec` 錄影；正式 evidence cast 的 result、exit code、完整性與 secret scan 都通過 `trec verify`。semantic automation 的 runtime 不依賴 `trec verify`，但要交付影片時仍執行它。
6. 最終回報能連到各項錄影、實際輸出與驗證結果；不可用「應可通過」、「看起來成功」或只引用舊紀錄代替本次證據。

## 開始前必讀

開始任何動作前，完整閱讀並遵守：

- `AGENTS.md`
- `docs/runbooks/minimal-poc-architecture.md`
- `.agents/skills/pilot-trec-verification/SKILL.md`
- `~/.agents/skills/trec-tui-drive/SKILL.md`
- `~/.agents/skills/trec-mcp/SKILL.md`（若 shell 無法維持 `trec drive --interactive` 的 stdin session）

先以目前工作樹的原始碼重新計算 deploy catalog、角色 checklist 與 deploy 自動偵測變數鏈；不得從舊 cast、舊腳本、舊文件或記憶沿用 index、角色順序、VM IP、選單位置或 vault key 順序。

先執行 `go build -o ./pilot ./cmd/pilot`，之後所有 wizard 都只使用這個最新建置的 `./pilot`。

## 執行邊界

- 全部暫存 inventory、drive script、cast 與驗證腳本只放在 repo 的 `./tmp/`。
- 從零開始：先依 runbook 拆除其列出的 VM，再刪除整個本次 scratch workspace；不得重用任何舊的 `hosts.yml`、`inventory.yml`、`group_vars/`、`.vault/` 或 cast。
- 設定只能走 `pilot edit` 與 `pilot inventory generate`。若 wizard 無法產生某項必要設定，立刻停止並回報，禁止手動編輯 YAML 繞過。
- 部署只能走 `pilot deploy`。若 wizard 卡住、預覽失敗、套用未真正發生，或行為與 runbook 不一致，立刻停止並回報；禁止改用直接 Ansible 或其他部署途徑。
- 唯讀檢查可依 runbook 執行；涉及密碼、token、私鑰或遠端狀態變更的動作，先遵循環境的授權要求。秘密只能透過 vault、環境變數或 `trec` 的 secret-redaction 機制傳入，絕不可寫入 script、cast、transcript 或回報。
- 不得修改 tracked runbook、playbook、inventory example 或產品程式碼來讓本次流程通過；發現問題時保留證據並停止回報。

## Wizard 與錄影規則

### Agent semantic action discovery

開始寫 scenario 前，先從**目前建置的同一個 `pilot` binary** 讀 action
契約，不要從舊文件或記憶猜 action 名稱、欄位或可用值：

```bash
./pilot actions list
./pilot actions schema
```

`actions schema` 是 version 1 的 machine-readable JSON；它列出每個 action
的 required fields、field values、是否可 standalone，以及 deploy/reconcile
的 prompt answer contract。scenario validator 與這份輸出共用 action catalog。
`pilot edit --actions` 可包含 edit 後的 deploy/reconcile steps；獨立執行時，
`pilot deploy --actions` 只能含一個 `deploy` action，`pilot reconcile --actions`
只能含一個 `reconcile` action。

- 所有 `pilot edit`、`pilot deploy`、`pilot reconcile` 都設 `CI=1`。可用 semantic scenario 直接驅動真實 TUI，或用 `trec drive` 驅動互動按鍵並錄製；先探勘實際畫面，再決定哪種路徑適合該段影片。
- 每支 `.drive` 腳本執行前都要通過 `trec drive lint --strict`，並執行 `.agents/skills/pilot-trec-verification/references/lint_drive.py`。
- `SELECT` 只用畫面上唯一的完整 label 子字串，且每個 `SELECT` 後都要各自 `ENTER`；每次轉場後，在下一個動作前以 `EXPECT` 驗證新畫面。
- 角色 checklist 是例外：依當前 `roleContracts` 順序，以 `DOWN <n>` + `SPACE` 操作；index 0 不可寫 `DOWN 0`。
- 覆寫預填欄位必須先清空；vault 值用 `TEXT_ENV`／`TEXT_FILE` 或相對應的 replace 指令，不能以明文輸入。
- 儲存、提交或套用後立刻 `ASSERT` 成功訊息。長時間部署以 `WAIT_CHILD_EXIT@<足夠時限>` 再 `ASSERT_EXIT 0` 收尾，不能用安靜輸出判定完成。
- 每次 `pilot edit` 存檔後，立即唯讀核對落盤設定；特別確認每一 host 的 `ansible_user` 是帳號名稱，SSH key 欄位才是金鑰路徑。發現欄位污染時，視為 drive script 問題，修正後從乾淨 workspace 重跑。
- `pilot deploy` 的預覽成功不等於部署成功。必須明確通過 preview 後的「套用真正變更」確認，並在 cast 中確認 `✅ 套用完成` 與成功 exit code。
- agent 需要自動回答 deploy prompt 時，建立只含一個 `deploy` action 的 version 1 JSON scenario，然後執行：

  ```bash
  ./pilot deploy --actions ./tmp/deploy-scenario.json \
      --presentation --trace-out ./tmp/deploy.jsonl
  ```

  scenario 的 `answers` 以 prompt 的可見文字定位 select/text/confirm 答案；不要用固定 menu index，也不要把密碼、token、私鑰或 vault secret 放進 scenario。`--presentation` 會輸出適合教學影片的步驟畫面，`--trace-out` 是 machine-readable sidecar。這條路徑仍會執行原有 preflight、inventory preview、stage gate、preview、apply confirmation、transaction 與 evidence。
- day-2 調和同樣使用只含一個 `reconcile` action 的 scenario：

  ```bash
  ./pilot reconcile --actions ./tmp/reconcile-scenario.json \
      --presentation --trace-out ./tmp/reconcile.jsonl
  ```

  `pilot reconcile` 只會接受 contract catalog 宣告的 reconciler；不要把 `reconcile` action 混進 standalone `deploy` scenario。需要 edit→deploy→reconcile 連續影片時，才使用 `pilot edit --actions` 的 workflow scenario。
- 每個 cast 完成後執行 `trec verify`；結果不完整、仍為 `in_progress`、exit code 非 0、digest 不符或 secret scan 有 finding，均不可當作證據。

## 部署與驗證流程

1. 讀完 runbook，列出本次使用的 VM、角色、vault／roster 需求、部署入口與 §4 驗證清單。
2. 建置最新 `./pilot`，清理 VM 與 scratch workspace，重建 VM；錄製並保存環境清單與實際 IP。
3. 透過 `pilot edit` 建立 hosts 與角色，透過 `pilot inventory generate` 生成 inventory，再以 `pilot edit` 完成 group vars 與 vault。每次存檔都核對實際檔案內容和 inventory graph。
4. 依 runbook 的部署策略先執行全站 `site.yml`，再執行 `freeipa-identity` 的獨立部署。部署前完成 wizard preview；確認 real apply 成功，並保存兩次部署的各自 cast。
5. 依 runbook §4 的順序執行全部部署後驗證。每個唯讀驗證命令都以 plain `trec` 錄製；對 allow/deny、資料鏈路與 reconciler 等行為，保留命令、exit code 與實際 stdout/stderr。
6. 驗證 identity reconciler 的變更後，依 runbook 恢復所需狀態，並完成其冪等性檢查；不可因驗證而留下未恢復的 demo drift。
7. 對所有 casts 執行 `trec verify`，確認沒有尚開啟的 MCP terminal session，最後整理證據。

## 停止並回報的情況

遇到任一情況不要繞過：runbook 互相矛盾、wizard 不能產生必要設定、wizard 卡住／未套用、script 落到錯欄位、inventory 與 runbook 不一致、preview 或 apply 失敗、驗證失敗、cast 驗證失敗、需要未授權的遠端寫入，或需要手動改 YAML／直接 Ansible 才能繼續。

回報 bug 前，必須依序完成：檢查 `trec transcript` 中實際按鍵落點、唯讀核對落盤檔案、閱讀相關程式碼或註解確認是否為設計行為，並在除錯時一次只變更一個因素。

## 最終回報格式

請以以下格式交付：

1. **結論**：完成／未完成，以及未完成的第一個阻斷點。
2. **環境**：本次 VM 名稱、實際 IP、scratch 路徑（不得包含秘密）。
3. **部署證據**：site-wide 與 `freeipa-identity` 各自的 cast 路徑、`trec verify` 結果、實際 apply 結果摘要。
4. **驗證矩陣**：逐項列出 runbook §4 的驗證名稱、PASS/FAIL、證據 cast／transcript 路徑與關鍵實際輸出。
5. **偏差或問題**：若有，附 transcript、落盤檔案核對與程式碼查核結果；清楚區分 script 操作失誤、環境問題與產品缺陷。
6. **清理狀態**：保留或已移除哪些 disposable VM／scratch artifacts，以及原因。
