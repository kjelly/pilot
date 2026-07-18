# Spec v2 實作計畫

> 依據:`docs/tmp/future/PRODUCT_ROADMAP.md` P2、`docs/tmp/future/IMPLEMENTATION_PLAN.md` §4(本文件是該節的細化)
> 修訂:2026-07-18 依 `docs/tmp/future/review.md` 修正——become 全宣告化、aggregate/inputs/ProbeResult 語意閉合、parser/lint 責任邊界、needsReview 改機器可辨識、migration 不再有靜默語意轉換路徑。
> 修訂 2:2026-07-18 依 review 第二輪修正——tag 改依 contract `tagMode` 推導(前版「tag coverage 同時接受兩型」的宣稱經對 `tag_coverage_test.go` 與 AGENTS.md 查證**不正確**,已更正)、移除 `traceability.applyPlaybook`、inputs 補值來源優先序、`needsReview` 改 `[]string`、「真實 inventory」驗收明確化。
> 修訂 3:2026-07-18 依 review 第三輪修正——`secretRef` input 不得 materialize 進 CLI/module argv(受控 transport 由 safety RFC 選定,定稿前 verify 對含 secretRef 的 spec 拒跑)、M2.1 v1 相容層拆成 compile / compatibility evaluator / replay adapter 三塊、DoD 清除殘留的「預設 tag `<component>-<id>`」舊規則。
> 修訂 4:2026-07-18 依 review 第四輪修正——`probeStatus` 增 `runner_error`/`missing`(timeout 歸因由 M0.2 spike 定案,不把未觀察 host 壓成 timeout)、M2.3 migration 表的 `needsReview` 範例改 YAML list 語法(欄位型別本就是 `[]string`)、`safety.destructive` 的粒度(spec 層 vs per-check)交 safety RFC 定案。
> 前置依賴(硬性):**M0.2 先合併,M2.1 才開工**(同動 verifier 執行層,不可平行);**Verification safety boundary RFC 定稿是 M2.2 的門檻**(目前已建立 Proposed，尚未 final；inputs 的 secret transport 與 safety 語意依 RFC)。M1.1 ComponentContract RFC 已建立六份 fixtures；shared spec 的 `traceability` 引用需由單數 `component` 改為複數 `components`，M2.2 前同步 schema。

## 1. v1 現況精確描述(遷移的地基)

### 1.1 檔案格式

- 純 markdown(`docs/verification/*.md`,現有 24 份),parser 在 `internal/spec/parser.go`。
- Metadata 靠 blockquote 前綴字串:`> 版本:`、`> 對齊規範:`、`> 維護者:`(parser.go:78-83)——`Version` **只是資訊,不影響解析**。
- Checklist = `## 2. Checklist` 下的 5 欄表:`| ID | Category | Check | Expected | Command |`(parser.go:117-156)。
- Targets = 任意 H2 下含 `Hostname` 表頭的表(parser.go:241-253),餵 `GenerateInventory`。

### 1.2 v1 格式的結構性債(v2 要一併解掉的)

1. **Command 塞在表格 cell 裡**:命令含 `|` 得靠 quote-aware `splitRow`(parser.go:191)+「多餘欄位 re-join 回 Command」(parser.go:144-147)兩層 hack;已有專門回歸測試 `parser_pipe_in_cell_regression_test.go`。多行命令不可能。
2. **`{{ }}` 禁令**:ad-hoc 走 Jinja,docker Go template 語法會炸(docker.md C6 註記,2026-07-06 實踩)——這是執行通道的限制,v2 schema 要把它變成 lint 規則而不是口頭約定。
3. **rc-echo trick**:因為壓扁的 ad-hoc 輸出拿不到可靠 rc,v1 慣用 `cmd; echo $?` 把 rc 印進 stdout,配 `Expected: <int>`。
4. **become 靠 heuristic**:`spec.NeedsBecome`(generator.go:322)猜命令要不要 sudo,不是宣告式。
5. **verify 並非唯讀**:`stageVerifyEnv`(verify_spec.go:88)在 `KEYCLOAK_ISSUER` 存在時對所有可達 host 寫 `/etc/pilot-verify.env`;部分既有 check 有 POST/PUT/DELETE 型 self-test。v2 的 `inputs` 與 `safety` 設計以 Verification safety boundary RFC 定案為準,且 `inputs` 注入機制(§3.3)明確取代寫 env 檔的做法。

### 1.3 matcher 實際語意(verify_spec.go:321 `matchExpected`)

| v1 Expected | 實際語意 | 陷阱 |
|---|---|---|
| `""`(空) | process rc == 0 | |
| `present` | process rc == 0(同上,別名) | |
| `^…` | anchored regex,比對 **stripRunnerPrefix 後**的 stdout | 先剝 `(rc=N)` 前綴與 ad-hoc one-line 包裝 |
| 純整數 | **優先**比 `extractRC(stdout)`(rc-echo),沒有才比 process rc(:339-350) | 同一寫法有兩種來源,遷移不能機械對映 |
| `~…` | stdout(cleaned)substring contains | 語意最弱,`isVagueExpected`(lint.go:188)已會警告 |
| 其他字串 | stdout(cleaned)全等 | |

執行面:`runLocal`(sh -c)與 `runAnsibleAdHoc`(ansible ad-hoc,module 由 `adHocModule` 決定 command/shell)。M0.2 之後 ad-hoc 改 json callback,**每 host 有真實 rc**——這是 v2 `exitCode` matcher 能誠實存在的前提,也讓 rc-echo trick 可以退役。

## 2. 設計決策

### D1:v2 = YAML front-matter + fenced YAML checks 的 markdown

維持「spec 是人可讀的 markdown 文件」,結構化資料集中兩處:

- 檔頭 YAML front-matter(`---` 包夾):schemaVersion 與所有 metadata 區塊。
- `## Checks` 段落下**一個 fenced yaml block**:checks 清單。

不選純 YAML 檔的原因:現有 spec 的價值一半在 prose(陷阱註記、修法、evidence 範例),front-matter 方案讓這些自然留在 markdown 主體;也和現有 docs/verification/ 目錄、`pilot verify <path.md>` 的 UX 連續。

不沿用 markdown 表格的原因:typed matcher 是巢狀結構,塞表格 cell 等於發明第三種 escape hack;fenced YAML 一次解決多行命令、`|`、`{{ }}`(YAML 裡是字面值,lint 另擋)。

### D2:版本分派靠檔案開頭

檔案第一行是 `---` → v2 parser(front-matter 必含 `schemaVersion: 2`,缺了就報錯);否則 → v1 parser(現行 `ParseReader` 原封不動)。`spec.Parse` 變成 dispatcher。**未知 schemaVersion、未知欄位一律硬錯**(yaml decoder 開 `KnownFields(true)`),對應 roadmap「parser 能明確拒絕未知版本與未支援欄位」。

**parser 與 lint 的責任邊界**(一次定清楚,消除本文件先前的自相矛盾):**結構有效性 = parser error**——schemaVersion 缺失/未知、未知欄位、check id 重複或不合 `IDPattern`、`probe` 缺失、`expect` 全空、`StringMatcher` 非恰好一個欄位、`scope` 值非法;**品質與慣例 = lint**——vague `contains`、tag 對齊、`inputs` 宣告未使用、probe 含 `{{`(error 級 lint)。parser 通過代表「結構合法」,lint 才判斷「夠不夠好」。

### D3:執行層單一化——typed matcher 是唯一執行語意

v1 的五種魔法前綴在 **parse 時轉譯**成 typed matcher(M2.1);`matchExpected` 退役,執行層(verify_spec.go)只認 `Expect` 型別。v1/v2 從此只是兩個前端,「同一份 spec 在 local / docker-target / vm-target / 真實 inventory 判定一致」由單一執行層保證。

### D4:v2 不做的事

- 不把 probe 猜成 mutation(`spec --generate` 維持診斷,對 v2 也一樣)。
- 不強迫既有 24 份 v1 遷移;v1 parser 長期並存,逐份隨修改順手遷。
- front-matter 不放 ComponentContract 該管的事(依賴、cardinality、資源)——spec 只透過 `traceability.components` 引用 1—N 個 contract ID；shared spec 的 row ownership 由 contract selector 決定，避免兩處宣告同一事實。

## 3. v2 schema 定義

### 3.1 檔案範例(docker.md 節錄遷移後)

```markdown
---
schemaVersion: 2
compatibility:
  minPilotVersion: "0.9"        # 首個支援 v2 的版本,實作時定
intent:
  summary: container engine 驗收(docker.io;db 與 keycloak 跑在其上)
  source: AGENTS.md §2
  maintainer: sre
targets:
  roles: [docker]
  hostScope: per-host            # 預設所有 check 逐 host 判定
  platforms:
    - {os: ubuntu, versions: ["22.04", "24.04"]}
inputs: []                       # 本 spec 無 probe 變數;有的話:
  # - name: s3_endpoint
  #   required: true
  #   secretRef: false
  #   validation: "^https?://"
traceability:
  components: [docker]           # M1.1 ComponentContract IDs——mapping 唯一來源(D4);
                                 # playbook/row mapping 都從 contract 查,spec 不重複宣告
defaults:
  become: false                  # 必填:v2 全宣告式,無 NeedsBecome heuristic;check 可逐列覆寫
  timeout: 30s
  action: readOnly               # check 可覆寫為 isolatedMutation；需額外授權/cleanup
evidencePolicy:
  captureStdout: true
  retention: default
---

# Verification Spec — docker (container engine)

(prose、陷阱註記照舊放 markdown 主體…)

## Checks

```yaml
- id: C1
  category: pkg
  check: docker server 已安裝(docker.io 套件)
  probe: |
    dpkg-query -W -f='${Package}\n' docker.io 2>/dev/null | awk "/^docker\.io$/ {f=1} END{print f+0}"
  expect:
    stdout: {equals: "1"}
- id: C2
  category: service
  check: docker 服務 active
  probe: systemctl is-active docker
  expect:
    exitCode: 0
    stdout: {equals: active}
  timeout: 10s
- id: C5
  category: hello-world
  check: docker run --rm hello-world 全鏈通
  probe: docker run --rm hello-world 2>&1
  expect:
    stdout: {contains: "Hello from Docker"}
  timeout: 60s
```
```

注意 C1 的遷移:v1 是 rc-echo(`Expected: ~1` 比 awk 印出的 `1`),v2 直接寫 `stdout equals "1"`,語意不變但明確;若原意其實是「exit code 1」則寫 `exitCode: 1`——這正是純整數 Expected 需要人工確認的原因。

**tag 推導**(review 第二輪 #7 更正:前版「tag coverage 同時接受 bare 與 prefixed 兩型」**不正確**——`tag_coverage_test.go` 每個 mapping 由 `prefixes` 決定唯一形式(`empty = bare row IDs`),AGENTS.md 規則是 single-spec playbook 用裸 `C3`、multi-spec/multi-role 才用 `<role>-C3`):

- check 未寫 `tags` 時**不做全域預設**；resolved tag 由 ComponentContract traceability 推導——rowTags/bare → `C3`，rowTags/rolePrefixed → `<prefix>-C3`，mapped → contract 的 row→feature/stage tags，verifyOnly → 不產生 apply tag。新 schema 不接受只有 component-level reason 的 `noRowTags`。
- 無 contract 的 standalone spec:必須逐 check 顯式 `tags:` 或標 `verifyOnly`,parser 不猜。
- 此例 docker 的 contract 是 `rolePrefixed(docker)`(現行 specTagMap 即 `prefixes: ["docker"]`),resolved 為 `docker-C1`…`docker-C5`;顯式 `tags:` 保留給一列多 tag 的少數情況。

### 3.2 Go 型別(`internal/spec/v2.go` + `internal/spec/expect.go`)

```go
// expect.go — M2.1 就引入,v1/v2 共用
type Expect struct {
    ExitCode *int           `yaml:"exitCode,omitempty"`
    Stdout   *StringMatcher `yaml:"stdout,omitempty"`
    Stderr   *StringMatcher `yaml:"stderr,omitempty"` // v2 才可寫;v1 轉譯不會產生
}
type StringMatcher struct {
    Equals      *string `yaml:"equals,omitempty"`
    Contains    *string `yaml:"contains,omitempty"`
    NotContains *string `yaml:"notContains,omitempty"`
    Regex       *string `yaml:"regex,omitempty"`     // RE2,anchored 與否由作者寫
}
// 語意:Expect 內所有非 nil 條件 AND;StringMatcher 內恰好一個欄位非 nil(parser error,見 D2 邊界)。
// Expect 全空 = parser error(v1 的「空 Expected ⇒ rc==0」在轉譯時明確產生 ExitCode: &0)。

func (e Expect) Eval(res ProbeResult) Verdict // ProbeResult 定義見 §3.3(含 probeStatus 與正規化規則)
```

```go
// v2.go
type CheckV2 struct {
    ID       string        `yaml:"id"`
    Category string        `yaml:"category"`
    Check    string        `yaml:"check"`
    Probe    string        `yaml:"probe"`
    Expect   Expect        `yaml:"expect"`
    Timeout  time.Duration `yaml:"timeout,omitempty"`  // 預設沿用全域
    Scope    string        `yaml:"scope,omitempty"`    // per-host(預設)| aggregate
    Become   *bool         `yaml:"become,omitempty"`   // nil ⇒ 繼承 defaults.become;v2 全宣告式,無 NeedsBecome heuristic
    Action   Action        `yaml:"action,omitempty"`   // readOnly(預設)|isolatedMutation
    Tags     []string      `yaml:"tags,omitempty"`     // 未寫時依 contract traceability 推導(§3.1);standalone spec 必須顯式
    VerifyOnly bool        `yaml:"verifyOnly,omitempty"` // 無對應 apply tag 時必須明寫
    NeedsReview []string   `yaml:"needsReview,omitempty"` // migrate 未決標記,可累積多個 finding(如 v1-int-ambiguous + jinja-template-risk);非空 ⇒ verify 拒跑整份 spec
}
type SpecV2 struct {
    SchemaVersion int
    Defaults      Defaults // become 必填、timeout 選填——v2 無任何 heuristic 回退
    Compatibility, Intent, Targets, Inputs, Traceability, Safety, EvidencePolicy …(如 §3.1)
    Checks []CheckV2
}
```

**內部統一表示**:`SpecV2` 與 v1 `Spec` 都降到共同的 `ResolvedSpec`(rows 帶 `Expect`、probe、become、timeout、scope、tags),`verify_spec.go`、報告、store 只認 `ResolvedSpec`。v1 的 `Row.Expected` 字串保留在 `ResolvedRow.RawExpected` 供報告顯示原文。

### 3.3 v2 專屬語意(review 阻塞項 6 逐項閉合)

**ProbeResult 正規化(typed matcher 的輸入契約;細節由 M0.2 spike 定案)**

- 來源:remote probe 取 json callback 的 per-host stdout/stderr/rc 欄位(需 `ANSIBLE_LOAD_CALLBACK_PLUGINS=1` + `ANSIBLE_STDOUT_CALLBACK=ansible.posix.json`,已實測;availability preflight 與 fallback 見總計畫 M0.2);local probe 直接取程序輸出。
- 正規化:`\r\n` → `\n`;剝除**恰一個** trailing newline;非法 UTF-8 byte 以 U+FFFD 取代。matcher 對正規化後全文評估;evidence 落庫時才截斷(64 KB + truncated flag),截斷不影響判定。
- `probeStatus: ok | timeout | unreachable | module_error | runner_error | missing`(review 第四輪 #1 增補後兩者:現行一列一個 ansible process、controller 逾時殺整個 process,callback JSON 可能不完整——`runner_error` = invocation 層失敗/JSON 不完整,`missing` = host 未出現於 callback 且原因未明;**不把所有非 observed 情況壓成 timeout**,歸因規則與是否採 host-level timeout 由 M0.2 spike 定案):matcher **只在 `ok` 時評估**;其餘一律 FAIL 並記 status 與 ansible 原始錯誤——非 `ok` 不可能被 matcher 誤判成 pass(fail closed)。

**`scope: aggregate`**

- 定義:該 check 每次 verify 只執行**一次,在 controller(執行 pilot 的機器)本地執行**,不 delegate 到任何 target host。需要叢集視角的 check 本質是「從外部觀察」(query API、數 DNS record),controller 就是外部觀察點——因此**不存在 delegate 挑選問題**,也不會退化成「取 group 第一台」。
- evidence:host 欄記字面值 `controller`,語意獨立於 inventory;與 M0.2 的 host×row 表相容。
- 「在某台成員主機上跑一次」的檢查**不是** aggregate——那是 per-host check 搭配 contract 層把該 role 的 cardinality 設為 exactly-one。

**`inputs`**

- 宣告:`{name, required, secretRef, validation(RE2)}`;verify 開始前先 validate,`required` 未提供或 validation 不過 ⇒ 整份 spec 拒跑(fail closed)。
- **值來源與優先序**(review 第二輪 #8;高 → 低,隨 safety/evidence RFC 定稿):(1) CLI `--input name=value`(可重複);(2) `--inputs-file <yaml>`;(3) inventory/group var `pilot_inputs.<name>`;(4) 程序環境 `PILOT_INPUT_<NAME>`。同名以高優先者為準,報告註明每個 input 的實際來源。`secretRef: true` 的值**不接受** (1)/(4) 明文(會進 shell history/環境),只接受 vault reference 經 resolver 解出;resolver 拿不到 plaintext 時依 evidence RFC 的「不持久化 stdout/stderr」規則處理。
- 注入(**取代現行 `stageVerifyEnv` 寫 `/etc/pilot-verify.env` 的機制**,該機制隨 safety RFC 退役):
  - local / aggregate(controller)probe:直接以程序環境變數 `PILOT_VAR_<name>` 注入。
  - remote per-host probe(**僅限非 secret input**):pilot 在 module args 前綴 `PILOT_VAR_<name>='<value>' `,value 以 POSIX 單引號安全編碼(`'` → `'\''`;編碼函式獨立單元測試,涵蓋引號、空白、newline、UTF-8);僅支援 `shell` module(`command` module 無環境變數展開,lint 擋)。
  - **`secretRef: true` 的值不得 materialize 進 CLI/module argv**(review 第三輪 #3:即使 quoting 正確,plaintext 仍出現在 pilot 啟動的 `ansible` process argv、`ps`、診斷輸出與 subprocess recorder;persist 前刷 stdout/stderr 修補不了 transport 階段已發生的洩漏)。secret 的受控 transport 由 safety RFC 選定,候選:controller 端 `0600` 暫存資料配合受控 playbook/module;stdin/file-descriptor 傳遞、不進使用者可見 command;Ansible task 層 `no_log` + temp artifact 的明確清除與 crash recovery。**該契約定稿前:M2.2 的 parser 照常收下 `secretRef` 宣告,但 `pilot verify` 對含 secretRef input 的 spec 拒絕執行——不實作、不宣稱 secret input 可安全執行。**
  - probe 落地前不經任何模板引擎——禁止以 Jinja `{{ var }}` 引用 input。
- secret masking(persist 層的第二道防線;transport 層防護見上):`secretRef: true` 的值 (a) 不寫入 evidence 的 inputs 摘要(只記 reference 名);(b) persist 前對 stdout/stderr 做 exact-string 刷除。誠實限制:probe 若輸出轉換過的 secret(base64、截斷、hash)刷不到——殘餘風險記入 safety RFC,並以 lint 警告「probe 引用 secret input 且 expect 比對 stdout」的組合。

**`action`／verification safety**

- Proposed safety RFC 已選 per-check `action.mode: readOnly|isolatedMutation`，不是 spec-level `safety.destructive` boolean。
- 自動 deploy verify 只執行 `readOnly`；`isolatedMutation` 必須有額外授權、cleanup 與 residual-risk evidence，production 預設拒絕。
- 既有寫入型 self-test 要移至 apply/fixture，或明確遷移成 isolatedMutation；無法判定時 `needsReview`、fail closed。
- secret-aware runner 未完成前，含 `secretRef` 的 spec 仍拒跑。最終 schema 以 `VERIFICATION_SAFETY_BOUNDARY_RFC.md` review/final 為 M2.2 gate。

## 4. 里程碑

### M2.1 — typed matcher 內部重構(不動任何檔案格式)

**改動**
1. 新增 `internal/spec/expect.go`(§3.2)+ `Expect.Eval`。
2. 新增 `CompileV1Expected(expected string) (Expect, error)`:五種前綴 → Expect 的轉譯器。對映(依 §1.3 實際語意,不是理想語意):
   - `""` / `present` → `{ExitCode: 0}`
   - `^re` → `{Stdout: {Regex: "^re"}}`
   - `~sub` → `{Stdout: {Contains: "sub"}}`
   - 其他字串 → `{Stdout: {Equals: s}}`
   - 純整數 → **保留 v1 專屬的 `legacyRC` matcher**(`Expect` 加一個不對 v2 開放的 `legacyRCEcho *int` 欄位):語意 = extractRC(stdout) 優先、process rc 次之,完整復刻 :339-350。不要在 M2.1 就試圖「修正」它,零回歸優先。
3. v1 相容層拆三塊,位置各自明確(review 第三輪 #6 指正:`CompileV1Expected` 只接收 Expected 字串,而 `stripRunnerPrefix`/`extractRC`/`unwrapAdhocOneline` 處理的是**執行輸出**,籠統說「移進 v1 轉譯路徑」會把舊 callback 格式重新帶進 typed execution core):
   - **parse/compile**:`CompileV1Expected` 只負責把 v1 Expected 字串編成 matcher,不碰執行輸出。
   - **v1 compatibility evaluator**:在 structured stdout/rc(`ProbeResult`)上重現舊判定——`legacyRC` 的 extractRC rc-echo 優先邏輯住在這裡。
   - **historical replay adapter**:`stripRunnerPrefix`/`unwrapAdhocOneline` 只在重放舊 NDJSON detail 的對照測試中使用;M0.2 之後的新執行路徑**不再製造也不再解析** one-line 包裝。
4. `matchExpected` 改為薄殼:`CompileV1Expected` + `Eval`,跑穩一版後刪除。

**測試**
- 轉譯表逐案 unit test(含 rc-echo、`(rc=N)` 前綴、ad-hoc one-line 包裝三種 detail 形態 × 六種 Expected)。
- **零回歸關卡**:24 份 spec 的既有 regression test 全綠;另寫一個 fuzz-ish 對照測試——對歷史 NDJSON 報告裡的 (expected, detail, rc) 三元組重放,新舊實作 verdict 必須全等。

**規模**:3-4 天。**必須排在 M0.2 合併之後依序進行**——兩者都改 verifier 執行層,平行實作必然互踩(review 建議開工順序 #4;本文件先前「可並行」的說法與自己的風險表矛盾,以此為準)。

### M2.2 — v2 parser 並存

**改動**
1. `internal/spec/v2.go`:front-matter 偵測 + `yaml.v3` 嚴格解碼(`KnownFields(true)`);`## Checks` 下抓第一個 ```yaml fenced block 解 checks。schemaVersion ≠ 2、缺 front-matter 必填欄位、未知欄位、StringMatcher 多欄位/零欄位 → 具體行號的錯誤。
2. `spec.Parse` 分派(D2);`ResolvedSpec` 統一層,下游全部改吃它:
   - `internal/tools/verify_spec.go`(執行;v2 的 timeout/scope/become 生效)
   - `cmd/pilot/cmd/verify.go`(報告照舊;報告 header 註明 schema 版本)
   - `internal/spec/lint.go`(v2 規則見下)
   - `internal/spec/traceability.go` + `tag_coverage_test.go`(v2 的 resolved tags 由 contract traceability 推導或 check 顯式宣告；bare ↔ 空 prefixes、rolePrefixed ↔ 有 prefixes、mapped ↔ 逐 row feature/stage mapping、verifyOnly/derived ↔ 逐 row exemption；`specTagMap` 對 v2 檔改為自動)
   - `GenerateInventory`:v2 的 `targets.roles` + 現行 Hosts 表並存期——v2 front-matter 加選配 `targets.hosts`(同 v1 Hosts 表欄位)
   - `spec --generate`:對 v2 維持可用但輸出加「diagnostic only」註記,行為與 v1 相同
3. v2 lint 規則(結構有效性歸 parser,見 D2 邊界;`expect` 全空、StringMatcher 非恰一欄位是 parser error 不在此列):probe 含 `{{`(Jinja/Go template 風險)→ error;`contains` 值長度 < 3 或落在 `isVagueExpected` 清單 → warning;check 無 tag 對應且未標 `verifyOnly` → error(接 M1.2 的 contract lint);`inputs` 宣告了但 probe 未引用 → warning;probe 引用 `secretRef` input 且 expect 比對 stdout → warning(masking 殘餘風險);input 用於 remote probe 但 module 非 `shell` → error;含 `needsReview` → finding,且 `pilot verify` 對整份 spec 拒跑。
4. 寫**一份真的 v2 spec 進 repo**(建議新元件或最簡單的 docker.md 複本 `docker-v2.md` 放 fixtures,不是正式目錄),避免「宣稱支援 v2 但 repo 裡零實例」。

**測試**
- v2 parser 正反向:合法檔、未知欄位、未知版本、壞 fenced block、front-matter 缺 schemaVersion。
- **跨 target 一致性驗收(P2 完成定義)**:同一份 v2 fixture spec 在 (a) local、(b) docker-target、(c) vm-target、(d) **使用者提供的一般 inventory 檔**(非 spec 生成、非 vm-target 管理)各跑一次 `pilot verify`,斷言 host×row verdict 一致。(a)(b) 進 CI;(c) 進 `vm-target topology test`;(d) 是 M2.2 驗收的人工步驟——實務上用 delivery-test 環境的 staging 主機實跑並留 evidence(走 `pilot-trec-verification` 流程);若驗收時無 staging 主機可用,DoD 措辭降級為「一般 inventory backend 一致」,**不宣稱已在真實主機驗證**(review 第二輪 #9)。
- teatest/PTY 不受影響(verify 非互動),但 `verify --dir` rollup 混合 v1/v2 目錄要有測試。

**規模**:1.5-2 週。

### M2.3 — 遷移工具與收尾

**改動**
1. `pilot spec migrate <v1.md> [-o out.md]`:
   - metadata:`> 版本:` → 起始 `schemaVersion: 2` + 原版本進 `intent.source` 註記;維護者/對齊規範 → intent。
   - Hosts 表 → `targets.hosts`;prose 全數原樣搬進主體。
   - Expected 轉換規則(對映 M2.1 轉譯表),**needsReview 標記**:
     | v1 | v2 | 標記 |
     |---|---|---|
     | `""` / `present` | `exitCode: 0` | 自動 |
     | `^re` | `stdout: {regex}` | 自動 |
     | 字串全等 | `stdout: {equals}` | 自動 |
     | `~sub` | `stdout: {contains}` | 自動;命中 vague 清單時寫入 `needsReview: [weak-matcher]` |
     | 純整數 | 草稿 `exitCode: N` + `needsReview: [v1-int-ambiguous]` | **必人工**:v1 語意是「stdout rc-echo 優先、process rc 次之」,任何單一 v2 形式在部分情境都會改變 verdict(review 阻塞項 7 的實例:stdout 未印 rc 但 process rc 相符時,`stdout.equals` 會翻盤);因 needsReview 使 verify 整份拒跑,草稿值不構成靜默語意轉換 |
   - **`needsReview` 是機器可辨識的 schema 欄位(§3.2),不是 comment**:parser 接受、lint 列 finding、`pilot verify` 對含任何 needsReview 的 spec 整份拒跑——未確認的檔案**不可能**被當作可驗證的 v2 spec 使用,「不做靜默語意轉換」由機器保證。migrate 另輸出 sidecar report `<out>.migration.json`(逐列 finding、原 v1 語意、建議選項)。
   - become:v2 全宣告式(defaults.become + 逐 check 覆寫)。migrate 以 `NeedsBecome` heuristic 結果顯式寫入,並在 sidecar report 列出「值來自 heuristic」的列供人確認;此項確認不擋 verify——become 給錯只會權限失敗 → FAIL(fail closed),不會誤 pass。
   - probe 含 `{{` → 輸出並寫入 `needsReview: [jinja-template-risk]`(v1 靠口頭禁令,v2 逼人處理;欄位是 `[]string`,與既有 finding 並存時累加,如 `[v1-int-ambiguous, jinja-template-risk]`——golden test 依 list 語法固化,review 第四輪 #6)。
   - 任何 finding → migrate exit code 非零 + sidecar report(CI 可擋「假裝遷移完成」)。
2. 文件:`verification-spec-template.md` 出 v2 版(v1 模板保留、標 legacy);AGENTS.md §1/§2 增補 v2 authoring 規範;`vm-target-spec-testing` skill 的 references 更新。
3. 24 份既有 spec **不批次遷移**;訂規則:任何 spec 下次實質修改時順手 `spec migrate` + vm-target 重驗(走既有 `pilot-trec-verification` 流程留 evidence)。

**測試**
- migrate 的 golden 測試:docker.md → 預期 v2 輸出全文比對;每條 needsReview 規則一個負向案例。
- 無 finding 的遷移檔:`spec.Lint` 零 error、verify verdict 與 v1 原檔一致(docker-target 實測一輪)。含 finding 的遷移檔:斷言 verify 整份拒跑、migrate exit 非零、sidecar report 內容正確(「lint 零 error」不適用於含 needsReview 的檔案,兩者不衝突)。

**規模**:1 週。

## 5. 風險與緩解

| 風險 | 緩解 |
|---|---|
| M2.1 轉譯器沒復刻到 v1 邊角(rc-echo、`(rc=N)` 前綴、one-line 包裝) | 歷史 NDJSON 重放對照測試;`legacyRC` matcher 完整保留舊路徑,不趁機「修正」 |
| 與 M0.2 都重寫 verify_spec.go 執行層,合併衝突 | 順序固定:M0.2 → M2.1 → M2.2;M2.1 只動 matcher 不動 runner |
| v2 檔案在 parser 落地前流出 | M2.2 合併前,v2 fixture 只放 testdata,docs/verification/ 目錄 lint 擋 front-matter 檔(roadmap「不提前宣稱」) |
| fenced YAML 讓非工程 reviewer 更難讀 | check 的 `check:` 欄維持一句人話;報告 `.md` 渲染不變,閱讀面主要在報告不在 spec 原檔 |
| aggregate scope 與 per-host evidence 表(M0.3)粒度衝突 | aggregate 在 controller 執行、記 host=`controller` 單列,store schema 不需改 |
| `inputs` remote 注入的 shell quoting 出錯(值含引號、空白、newline) | 單引號編碼函式獨立單元測試;僅允許 `shell` module(lint 擋);不經任何模板引擎 |
| secret masking 刷不到轉換過的 secret(base64/截斷/hash) | 誠實記為殘餘風險:lint 警告 secret×stdout-match 組合 + 文件警語;長期解法歸 safety RFC |
| secret input plaintext 經 process argv/`ps`/診斷輸出洩漏(transport 階段,persist 刷除救不回) | `secretRef` 值不進 CLI/module argv;受控 transport(0600 暫存/stdin-fd/`no_log`)由 safety RFC 定;定稿前 verify 對含 secretRef 的 spec 拒跑 |
| verify 唯讀邊界未定就把 v2 接進 deploy 交易 | M2.2 開工門檻 = Verification safety boundary RFC 定稿;v2 schema 只承載宣告,不自行發明豁免 |

## 6. 完成定義(對照 roadmap P2)

- [ ] matcher 不再依賴隱晦 prefix 才能理解 —— `matchExpected` 刪除,執行層只有 `Expect.Eval`;v2 檔內 expect 全為 typed。
- [ ] parser 明確拒絕未知版本與未支援欄位 —— 負向測試鎖住。
- [ ] 同一份 v2 spec 在 local / docker-target / vm-target / 使用者提供的一般 inventory(staging 主機實跑留 evidence;無則明示未在真實主機驗證)判定一致 —— 跨 target 一致性測試 + topology test 實跑。
- [ ] v1 全部 24 份 spec 在整個過程零判定回歸 —— regression suite + NDJSON 重放。
- [ ] `pilot spec migrate` 可用:needsReview 為機器可辨識 schema 欄位 + sidecar report,含未決標記的檔案 verify 一律拒跑,無靜默語意轉換路徑。
- [ ] v2 全宣告式:become/timeout 無任何 heuristic 回退；resolved tag 依 contract traceability 推導(rowTags bare/prefixed 或 mapped row tags；verifyOnly/derived 逐 row exemption；standalone spec 逐 check 顯式宣告——見 §3.1)，tag coverage 對 v1/v2 混合 repo 全綠。
- [ ] RFC 文件(roadmap 建議產出 #3)隨 M2.2 合併定稿;Verification safety boundary RFC 先於 M2.2 定稿。

## 7. 時程總覽

| 里程碑 | 內容 | 規模 | 前置 |
|---|---|---|---|
| M2.1 | typed matcher 內部重構 | 3-4 天 | M0.2 合併(硬性,不可平行) |
| M2.2 | v2 parser 並存 + lint + 跨 target 驗收 | 1.5-2 週 | M2.1 + Verification safety boundary RFC 定稿 |
| M2.3 | migrate 工具 + 模板/文件 + 遷移規則 | 1 週 | M2.2 |

合計約 3-4 週,與總計畫 §4 的估計一致;M2.1 排在 M0.2 之後依序進行,不與 P0 的 verifier 改動平行。
