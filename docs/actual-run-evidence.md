# Actual-run evidence 與 candidate revision 規則

本文件定義 pilot repo 如何同時做到「每條操作都真的跑過」與「runbook/spec 不隨每次
重測無限膨脹」。它是 `AGENTS.md` §1 的細節規範。

## 1. 四種內容必須分開

| 內容 | Canonical location | 更新方式 |
|---|---|---|
| Acceptance contract | `docs/verification/<feature>.md` | 只在需求或驗收語意改變時更新 |
| 目前操作流程 | `docs/runbooks/<feature>.md` | 只保留現在可執行的步驟、rollback 與有效 gotcha |
| Sanitized evidence 摘要 | `docs/evidence/<feature>/<change>.md`（一個變更一份，例如 `issue-214.md`）與 `docs/evidence/<feature>/LATEST.md` | 同一變更的每個 candidate **就地覆寫**同一份 record；被取代的 candidate 由 Git history 保存。`LATEST.md` 由 pilot 在鏈成功時改寫，指向目前有效的 record；spec/runbook 只連到 `LATEST.md`，重新驗證就不必再改 spec/runbook。既有的 `<date>-<tested-revision>.md` 不必改名 |
| 完整原始輸出 | Gitignored `.verification/` 或暫時的受控驗收儲存 | 不提交 Git；只在一次性驗收與診斷期間保存 |

Runbook 與 spec 不得當成 chronological test journal。兩者只放靜態的
`../evidence/<feature>/LATEST.md` 連結；重測只改 evidence 目錄，日期、revision、數字
由 LATEST 與 record 提供。變更紀錄採不編號的 `## 變更紀錄`，欄位為「日期、PR、
驗收語意變更」；只記 contract 變更，不記重測，既有歷史保留。

## 2. Candidate-first 工作流

1. 在一般 worktree 開發並跑快速測試。此時 worktree 可以是 dirty。
2. 完成本輪 spec、playbook、fixture、code、inventory contract 與依賴鎖檔後，凍結成
   本地 candidate commit。
3. 從 candidate revision 建立乾淨、隔離的 checkout，確認沒有 tracked modification、
   會參與測試的 untracked file 或外部 overlay。
4. 在該 checkout 對實際 target 讀 inventory facts，再跑 dry-run、apply、verify、
   idempotency 與必要的 rollback/failure path。
5. inventory/spec 不一致時，無論選 A 改環境或 B 改 spec，都要重讀 facts 並從正式鏈
   起點重跑。失敗就修改原工作樹並產生新 candidate；舊 candidate 的 evidence 不得沿用。
6. 跑鏈時帶 `--evidence-record docs/evidence/<feature>/<change>.md`（`vm-target test` 與
   `vm-target topology test` 都支援），pilot 在鏈結束時寫出 record 的機器產生部分（§3.1），
   操作者只補兩段手寫內容，再以後續 evidence-only commit 提交；成功時 pilot 同步改寫
   `LATEST.md`。record 引用的 tested commit、tested tree 與執行閉包的檔案 hash 由 pilot
   算出，不手抄。
7. 若 rebase/squash 改寫 commit ID，必須重新證明 execution-affecting file hashes 未變；
   任何內容差異都需要新 candidate 與新 evidence run。

「完整測試前不得有 commit」不是本 repo 的規則。本地 candidate commit 是凍結測試輸入，
不代表發布、merge 或部署授權。

## 3. Evidence record 最小欄位

每份 sanitized evidence record 至少包含：

- feature/spec 與 apply playbook；
- run ID、UTC 時間與操作者；
- tested commit ID、tree ID、execution-affecting file hashes；
- target 類型、inventory 來源與實際 host/group 摘要；
- dry-run、apply、verify、idempotency 的真實 verdict、exit code 與摘要數字；
- target image digest，以及會影響結果之外部 state fingerprint（若適用）；
- redaction 類別；
- 失敗時的真實結論，不得改寫成 PASS。

完整 stdout/stderr、逐 row payload、秘密值與內部 operational identifiers 不放入
committed evidence summary。

### 3.1 機器產生與手寫的分界

`pilot vm-target test --evidence-record <file>`（topology test 同）寫出的 record 以
`<!-- pilot-evidence-record v1 … -->` 標記開頭，接一個 ```json 區塊（schema
`pilot-evidence-record/v1`），之後的表格只是同一份資料的人類可讀版。pilot 填的欄位：

- `candidate`：tested commit、tree 與來源（`git`：從執行所在的 checkout 讀，checkout
  有修改或未追蹤檔案時標 `dirty`；`flag`：從 `git archive` 複本執行時用
  `--evidence-candidate`/`--evidence-tree` 提供；`unknown` 的 record 沒有 gate 會接受）；
- `pilot_binary` 的 SHA-256 與版本、`tooling` 的 ansible-playbook 版本；
- `targets`（節點、group、IP、base image 路徑與 SHA-256）與 `inventory`（pilot 這次
  render 出的 host/group 名稱，不含連線變數）；
- `steps`：L1/L3/L4/L5/L6 與 rollback 各自的狀態、時間與每台主機的 PLAY RECAP 計數，
  沒跑到的步驟標 `not-run`；`verify`：每份 spec 的 verdict 與 pass/fail/skip；
- `closure`：執行閉包——playbook、`import_playbook`、`include_tasks`/`import_tasks`、
  `template`/`copy`/`script` 的來源、`vars_files`/`include_vars`、`lookup('file'|
  'template'|'fileglob')`、spec、對應的 contract、repo 內的 `-e @file`、`ansible.cfg`／
  `requirements.yml`，每個檔案附 mode、Git blob id 與 SHA-256。`patterns` 同時記錄檔案搜尋路徑
  （含未命中的優先路徑）、glob 與目錄範圍，gate 比較 candidate/HEAD 的匹配集合，
  防止新增輸入漏出原本的檔案清單。含模板的路徑展開成 glob
  並標 `dynamic`；整個 basename 都是變數的引用（例如 `{{ freeipa_roster_file }}`）
  列在 `unresolved`，repo 外的檔案（vault）只列路徑在 `external`，不讀也不 hash。
  resolver 也掃描 play vars、載入的 vars/template 內的 `lookup`/`query`，並納入 topology
  YAML 及自動載入的 `group_vars`/`host_vars`。無法靜態證明的 expression、動態路徑、
  Jinja include/import、自訂或 ambient Ansible configuration 與 symlink 都列為 unresolved；
  inline extra-vars 裡的 Jinja/lookup/query/q 也以不含 payload 的固定標籤列為 unresolved。
  task dispatch 的 positive subset 刻意只保留 direct copy 的已知 literal argument mapping，
  以及 debug mapping 的 literal scalar msg（可選 literal integer verbosity）。debug.var、
  scalar/free-form args 與未知 key 一律 unresolved；template 不論 delimiter/header 一律
  opaque，但仍記 source hash。assert/set_fact/fail/meta 與其他 actions 同樣拒絕自動 reuse。
  task metadata 必須有明確 semantic type：boolean flag 是 YAML bool、condition 是 bool/
  bool-list、numeric control 是 number，不能把字串當成已證明安全的 implicit expression。
  其他 dispatch/layout、custom configuration/plugin/module、controller context、CLI options、
  task/playbook import/include 與 script executable 都保留固定 unresolved label；已知來源
  仍可記 hash 供診斷，但不從程式碼或 runtime context 猜測完整依賴。
  unsupported 的 task 仍正常執行，exact-candidate evidence 不因此失效。
  任何 Jinja interpolation 與非 literal boolean 的 when/until/changed_when/failed_when/
  assert expression 都以 `unsupported expression` 拒絕自動 reuse；不假設任意 filter/test
  沒有 filesystem input。明示的 ansible_* dispatch context variables 同樣列為 unresolved。
  inline key=value 只接受 ASCII identifier key、緊接等號、ASCII space 分隔，以及無 quote 的
  value 或完整單一 quote pair 的 value（保留相反 quote）。embedded/concatenated quote、
  quoted key/whole assignment、等號旁空白、backslash 與 TAB/CR/LF 等 whitespace 一律 unresolved；
  JSON/YAML mapping 仍由正式 parser 處理。
  repository 的所有 native plugin directory（含 connection/become/strategy/module_utils 等）
  都記 membership pattern，present code hash 後仍 unresolved。外部 default plugin roots、
  collection/Python discovery paths 預設沒有受控 fingerprint，因此預設 record 標固定
  `ambient Ansible plugin discovery` unresolved；literal copy/debug 本身不代表可沿用。
  opt-in `--evidence-controller=pinned` 由 committed digest-pinned OCI recipe 建置並解析
  immutable image ID，L1/L3/L4/L6 及整個 L5 pilot child 都在相同 image 內執行。
  每個 subprocess 使用新的 private HOME/tmp、read-only candidate/binary/inventory/key、
  固定 Ansible config 與清除 host ANSIBLE/PYTHON environment 的 launcher。
  這個 profile 需要 matching repository source checkout、Docker daemon 及已存在且可驗證的
  Go module cache；只含 bundled playbooks/docs 的 runtime image 不支援完整 source closure。
  native pre/post probe 證明 Python/Ansible origin、effective config、所有 plugin loader、
  role/collection/sys.path 與 pinned Go toolchain 一致，才可清除 ambient refusal。
  `controller` 保存 typed proof、image/config/profile/binary/inventory hashes、native probe
  與實際 routed stage counts；selection flag 或 supplied boolean 不構成證明。
  inventory-aware group_vars/host_vars 依實際 rendered host/group/ancestor 集合記候選 membership，
  無關 example 檔案不會成為輸入。V1 spec、已證明的 pilot SSH inventory 與 literal task subset
  才支援這個初始 profile；不支援的 context 仍正常執行並明示 unresolved。
  不嘗試執行 Jinja。`resolution_version: 7` 區分這個解析與 controller 證明邊界。
  closure 在任何測試步驟前凍結，結束後重新比較；一致才標 `frozen: true`。
  中途改動輸入保留原 hash，outcome 改為 `invalid-inputs`，不更新 LATEST。
  pinned profile 另讀取實際執行 binary 的 BuildInfo，要求固定 Go1.26.8/linux/amd64/v1、
  CGO=0、workspace off 與無自訂 tags/compiler flags。由相同 image 的 Go toolchain 以
  offline readonly mode 驗證 module cache，確認 listed module version/sum 與 binary 一致，
  再記錄 cmd/pilot 的 transitive repository packages、Go/assembly/syso source、每個 package
  的新增檔案 membership、embed package subtree 及 go.mod/go.sum。workspace/vendor/replace、
  cgo/未知 build setting 或 partial/error listing 一律 unresolved；無 import 的新 package
  不在執行圖內。BuildInfo/settings/module identity 以 typed 欄位與 hash 保存。
  這份清單就是 reviewer 做 `target_reuse` 盤點時的 `execution_paths`，不必再手列；
- `redaction`：掃描每個步驟擷取的輸出，找 `-e @file`（明文 YAML）裡 secret 命名的
  key 與 inline extra-vars（含多個 key=value、JSON 與 compact `-e`）的 secret 值；
  command 隱藏整個 inline payload，`@file` reference 保留。已知 secret 也從 persisted
  metadata/error note 中遮蔽。經驗證的 schema/outcome/step status 等 typed protocol identity、
  以及實際對應 candidate bytes/mode/blob/SHA 的 execution file path 保持完整；相同字串若在
  operator/note/dynamic map 仍遮蔽，沒有 global secret-value 白名單。stdout/stderr 都擷取掃描，並維持原有輸出 channel；
  secret container 下的 scalar（含 numeric/bool）保留原始及 canonical spelling，
  plain YAML 1.1 yes/no/on/off 另掃描 Ansible 的 boolean spelling，quoted/explicit string 保持原值；未證明的 float/timestamp/null/tag 與 sexagesimal
  scalar 明示 payload-free skipped，僅保留已知候選值的部分偵測，
  並掃描標準 JSON 對 quote、backslash、換行等字元的 escaping（不推測任意編碼）。
  secret 的 `/`、`~` 等前綴不作為豁免，只有明示 `*_file` key 視為檔案 reference。
  YAML secret traversal 有 node/depth budget 與 cycle guard；超限時丟棄該 input 的
  部分掃描結果，僅留下不含 payload 的 skipped marker，普通 alias 仍支援。
  不能解析的 inline syntax、templated secret 的 runtime 結果與加密的 vault 檔列在
  `skipped`。inline grammar 外的 payload 全部標 skipped，不套用 shell quote/escape 規則；
  三個 Jinja opener `{{`、`{%`、`{#` 都標 runtime result not scanned，含 decoded JSON/YAML。
  人類摘要在有未掃描 input 時明示 INCOMPLETE，不把零 hit 說成完整 clean。
  命中時 record 仍會寫出，但 pilot 在 stderr 警告，原始輸出不得提交。

record 與 `LATEST.md` 由同一個 directory process lock 序列化發布。覆寫目前被
`LATEST.md` 指向的 record 前先移除並同步 pointer，再以同目錄 temporary file、fsync 與
atomic rename 替換 record；只有成功且 record 已 durable 時，才原子發布新的 pointer。
同路徑失敗會留下失敗 record 而沒有 LATEST；不同路徑失敗保留原本成功 pointer。
中斷或寫入失敗可以留下沒有 pointer 的狀態，不能留下指向已被覆寫失敗 record 的舊成功宣告。

操作者只寫兩段：`## Failure paths and arms (fill in)`（鏈外另外跑的失敗路徑／對照
arm：注入的故障、預期 rc、復原後狀態、artifact）與 `## Not covered / limits (fill in)`。
同一變更的下一個 candidate 覆寫 record 時，這兩段會帶著「carried over from <舊
candidate>」註記保留下來，重新檢查後改寫即可。`pilot evidence closure --playbook …
--spec … -- -e @…` 可以單獨印出閉包，給 reviewer 或 gate 對照。

`.verification/` 是一次性驗收與診斷的 staging location，不是 durable archive。接受
candidate 的前提是提交一份可獨立判讀的 sanitized evidence summary，不是封存 raw
artifact。成功候選的 raw stdout/stderr/cast 在摘要提交後可以清除；失敗候選的 raw
evidence 保留到修正已由新 candidate 驗證即可。命令若讀取秘密，只記 secret-file
reference 或 stable command ID，不記展開後的秘密值。

Agent 判讀先讀 command result 或 compact summary：candidate/tree、exit code、duration、
`PLAY RECAP` 與 verify verdict counts。只有 audit、baseline comparison、使用者明確要求，
或失敗診斷才讀 raw artifact；失敗時先以 `FAILED!`、`fatal:`、`unreachable`、`PLAY RECAP`
定位，再開啟受影響 task 的有限上下文。只有 audit 要求、被接受的 known deviation，或仍會
影響目前操作的失敗才提交 sanitized failure record；已被後續 candidate 取代的一般失敗
不得塞回 runbook。

## 4. 何時 evidence 失效

下列任一內容在正式測試後改變，既有 evidence 立即失效：

- verification spec 的 command、Expected、target 或變數契約；
- apply/site/preflight/fixture playbook；
- 執行路徑上的 Go code、script、template 或 dependency lock；
- inventory role/group contract 或 target image；
- 會改變結果的 vault key、外部服務或環境設定。

只修改拼字、說明文字、latest link 或 evidence metadata，且 execution-affecting file hash
沒有改變時，可以只補 evidence-only commit，不必重跑。

合入較新的 base 不會自動讓既有 actual-run 有效或失效。只有 base manifest 明確
標為 `kind: target-run`、獨立 reviewer 對最新 HEAD/base 完成執行依賴盤點、
且 gate 證明盤點範圍的 Git blob/mode 未變，並驗證其他差異是純 upstream 匯入
或逐項確認不影響執行的變更，才可沿用原 candidate 的 target evidence。
新增或改動執行依賴、無法建立完整依賴範圍時仍需重跑；不改寫 tested revision，
也不沿用舊 review/CI。欄位與機器判定見
[共用 target evidence 規則](../.agents/skills/_shared/target-evidence-reuse.md)。

## 5. 文件內容預算

- runbook 保留 current procedure，不保留逐版完整測試輸出。
- verification spec 保留 acceptance contract，不放大型演練敘事。
- 只有仍影響目前操作的事故，才濃縮成 gotcha；開發過程由 issue、commit 與 evidence
  record 保存。
- Coding agent 預設只讀 command result、compact summary 與 sanitized evidence，不讀 raw
  artifact；只有 audit、failure diagnosis、baseline comparison 或使用者明確要求時才載入。

機器 record 的 target reuse 由 gate 直接讀取已提交 artifact 的 JSON，驗證 candidate/tree、
成功狀態、乾淨 checkout、閉包 blob/mode 與搜尋範圍；不需手寫 `execution_paths`。
未解析引用、外部執行檔案、缺少 `resolution_version: 6`/`frozen: true`，或舊版沒有搜尋範圍的機器 record 不接受自動沿用。
既有手寫 record 仍走完整人工依賴盤點；review/CI receipt 仍須符合目前 HEAD/base。
