# Pilot 專案功能實作報告

我們已經成功在 `pilot` 專案中完整實作了所有優化提案！以下是各功能的實作詳情與程式碼連結：

---

## 1. 安全防護與動態白名單
* **實作內容**：
  * 修改了 [Config 結構體](internal/config/config.go) (line 20)，新增 `AllowedCommands` (L30)、`CustomRedactRules` (L31-35)、`AllowedReadPaths` (L36)、`AllowedPlaybookRoots` (L37) 欄位，支援從 `config.yaml` 載入設定。
  * 在 [RunCommandTool](internal/tools/run_command.go) (line 157) 新增 [isWhitelisted](internal/tools/run_command.go) (line 194) 方法判斷（結構上為方法 `func (t *RunCommandTool) isWhitelisted(...)`），可將設定檔載入的自訂命令與系統內建命令做聯集（Union）比對。
  * 支援在 [app.go](internal/app/app.go) (line 80) 載入自定義的機敏資訊 Regex 遮蔽規則，動態傳遞給 `sanitizer.NewWith` (L93)。

---

## 2. RAG 混合檢索與 Playbook 增量更新
* **實作內容**：
  * 在 [index.go](internal/docs/index.go) (line 234) 的 `Search` (函式起始 L234，詞彙匹配實際計算位於 L274-299) 引入詞彙匹配分數（Lexical overlap score），對精確匹配 `Ref` 給予最高 `+2.0` (L280) 的權重提升，與向量相似度（Cosine Similarity）相加，達成 **混合檢索 (Hybrid Search)**。
  * 新增了 [BuildIncremental](internal/docs/index.go) (line 160) 方法（定義起始 L158，函式宣告 L160），支援更新/新增指定 Ref 的 Chunks 並重新建置向量。
  * 實作了 [ensurePlaybooksIndex](cmd/pilot/cmd/index_manager.go) (line 115) 用於增量式更新 Playbooks RAG 索引（函式本體 L115-211），每次 `pilot run` 啟動時會比對檔案 size 和 `mtime` (metadata 解析 L137-147)，僅對新增或修改的 Playbook 呼叫 Embedding 模型，大幅縮減了每次重整的耗時。

---

## 3. 平行化批次執行與一鍵還原 (Auto-Rollback)
* **實作內容**：
  * 在 [run.go](cmd/pilot/cmd/run.go) (line 123) 中，若傳入 `--execution-mode parallel` (旗標 L50，平行分支 L124)，將透過 goroutine 平行化執行多個 Playbooks，並使用帶有容量限制（`res.Cfg.MaxConc`）的 Channel 作為信號量（Semaphore，`sem := make(chan struct{}, maxConc)` 在 L129）進行併發控制。
  * 為了防範平行化執行時多個 goroutine 同時存取終端機導致 promptui/TUI 介面混亂，我們在 [ConsoleApprover](internal/ui/prompt.go) (line 23) 引入了 `sync.Mutex` (L27) 進行資源鎖定。
  * 實作了 [AskRollback](internal/ui/prompt.go) (line 218)，當 `run_ansible` / `apply_playbook` 執行失敗時（呼叫端：[internal/agent/loop.go#L383](internal/agent/loop.go) (line 383)），會詢問使用者是否要一鍵還原。若點選 Yes，程式將自動調用 `generate_rollback` (工具位於 [internal/tools/generate_rollback.go#L27](internal/tools/generate_rollback.go) (line 27)) 產生還原 Playbook 並即時套用執行。

---

## 4. ANSI 顏色 Diff 與自我診斷命令
* **實作內容**：
  * 實作了 [colorizeLine](internal/ui/prompt.go) (line 129) 著色工具，在輸出預演變動時，為 `+` 開頭行著色為綠色（ANSI 32）、`-` 著色為紅色（ANSI 31）、`@@` 著色為青色（ANSI 36），提升了 Diff 輸出在終端機下的可讀性。
  * 建立了全新子命令 [doctorCmd](cmd/pilot/cmd/doctor.go) (line 16)（指令本體 `runDoctor` L22-147），用於檢查 Ollama 連線 (L31-39)、LLM (L42-61) / Embedding (L64-77) 模型是否就緒、Ansible (L80-93) / Ansible-playbook (L96-104) 執行檔路徑、SQLite 資料庫狀態 (L107-124) 及 Docs RAG 索引狀態 (L127-139)。

---

### 驗證與編譯
你可以直接運行 `make build` 進行編譯，並執行 `./pilot doctor` 查看診斷成果：
```bash
./pilot doctor
```

#### 驗證紀錄（2026-06-27）
* `go build ./...` 通過；`go test ./... -count=1` 全部套件皆 `ok`。
* `pilot doctor` 連線至 `http://localhost:11434` 的 Ollama，確認 `qwen3.5:cloud` LLM、`qwen3-embedding:4b` Embedding、`ansible [core 2.18.5]` 與 `ansible-playbook` 皆就緒；目前僅提示 RAG 文件索引尚未建立（需執行 `pilot index-docs`）。
