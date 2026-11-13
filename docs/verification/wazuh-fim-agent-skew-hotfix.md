# Verification Spec — wazuh-fim-agent-skew-hotfix（`pilot hotfix wazuh-agent-skew`）

> 版本：v0.1（實跑日期、tested revision 與 verdict 只記在 evidence；操作流程與踩過的雷見 [runbook](../runbooks/hotfix-wazuh-agent-skew.md)）
> 對齊規範：`docs/verification/wazuh-fim.md` §「共用 manager 相容性 gate」（agent 版本 V 高於
> manager 版本 M 一律 typed 拒絕、沒有降級路徑）與 `docs/verification/wazuh-manager.md` C12
> （已註冊 agent 不得高於 manager）。本 spec 是這兩份 fail-closed 的**出口**：把「agent 比 manager
> 新」的主機整理回「沒有 agent」，讓之後的 `pilot deploy` 能依 M 重新安裝正確版本。
> 維護者：sre

## Acceptance contract

### 需求（Requirement Brief）

使用者原話：「wazuh agent 部分主機版本比 wazuh manager 版本新。對於那些 agent 比 manager 版本還要新的主機，
需要移除那些主機的 agent。讓我未來可以用 pilot deploy 重新安裝正確版本。」

使用者確認的設計決定（2026-11-13）：

| 決定 | 內容 |
|------|------|
| 移除深度 | **完整移除**：停服務、解除 pilot 自己加的 hold／versionlock、卸載 `wazuh-agent` 套件、移除 `client.keys`，並在 manager 端 deregister |
| 版本來源 | **agent 主機實際安裝版本**（dpkg／rpm）對照 **manager 原生版本 M**（`wazuh-transaction.py manager-version`），與 `wazuh-fim-apply.yml` 的 gate 同一來源；不以 manager 登記表的 `Client version` 為判斷依據 |
| 失敗處理 | **整次 fail closed**：M 讀不到、版本無法解析、writer 未閒置、hold 屬外來等，在**任何**變更之前拒絕並指名原因，不做部分移除 |

### 指令

`pilot hotfix <子指令>`：`hotfix` 本身只是容器，每個「修正環境問題」的情境是一個子指令。第一個子指令是
`pilot hotfix wazuh-agent-skew`。

旗標與 `pilot deploy` 相同語意：`--dir`、`-i/--inventory`、`--timeout`、`--limit`、`--stage`、
`--staging-attested-within-hours`、`--force`、`--preview-only`。inventory 解析（含從 `hosts.yml` 自動重新
產生）、stage／confirm gate 與 `--limit` 都重用 deploy 的同一份實作，不另寫一套。

**v1 刻意不支援**（寫明，不是遺漏）：`--actions`／`--presentation`／`--trace-out`（它們綁在 edit scenario
schema 的 `deploy`／`reconcile` action 上，新增 `hotfix` action 需要另開需求）、`--component`、`--action`
（hotfix 子指令自己決定要動什麼，沒有 contract lifecycle）。

### 流程

1. **偵測（唯讀，不需 stage 確認）**：對 inventory 的 `wazuh-fim` 主機（受 `--limit` 限縮）逐台判斷。
   - M：inventory 的 `wazuh-manager` group 必須**恰好一台**（0 台或多台都拒絕），在那台執行
     `wazuh-transaction.py manager-version`。
   - 每台 agent：`wazuh-agent-hotfix.py inspect` 讀已安裝版本 V（Debian `dpkg-query`、EL `rpm -q`，
     只認 amd64／x86_64）、pilot 自己的 hold／versionlock 狀態、`client.keys` 的 agent ID 與 name
     （**只讀前兩欄，第三欄的 key 永不輸出**），並**自己讀** `/var/backups/pilot/wazuh` 底下的 writer
     marker（`writer-active.json`、`agent-active.json`、`central-active.json`，不取 lock，只看檔案是否存在）
     來確認沒有進行中的 Wazuh writer 或未完成 journal：比 `wazuh-transaction.py writer-inspect`
     更嚴（任何 marker 都拒絕，不接受 `writer-inspect` 會接受的狀態），而且不呼叫 coordinator。
   - **skewed 的判定只有一處**：`wazuh-agent-hotfix.py inspect --manager <M>` 的 `skewed` 欄位，Go 只讀不算。
     V 的 `X.Y.Z` 數字元組嚴格大於 M 才是 skewed；V ≤ M、或沒有安裝 agent，一律原樣不動。`skewed` 只在套件已安裝時
     才可能為真。
   - **residue（上一次移除卸載之後才失敗的主機）**：`inspect` 的 `residue` 欄位，定義**只有一個**：沒有安裝 agent 套件
     **且** audit plugin 孤立（`/etc/audit/plugins.d/af_wazuh.conf` 不存在、但 `ss -xl` 仍列出 who-data endpoint 的 listener）。
     residue 與 skewed 互斥；單純「沒有套件」的主機（連同殘留的 `client.keys` 或 pilot policy 檔）**不是** residue，不會被動。
     `skewed` 或 `residue` 的主機都是 **actionable**（會被這次 run 變更、需要確認）。
   - **偵測就拒絕「之後做不完」的主機**：skewed 的 EL 主機若沒有 auditd 自己的 legacy restart action，或 `ss -xl` 不能用，
     在**套件還裝著時**就拒絕（卸載後才發現會讓主機沒有套件、重跑選不到）。
2. **Plan**：印出 `主機 / 已安裝版本 / M / 動作` 表（residue 主機的動作是「清除遺留的 audit plugin（套件已不在）」，
   不會被稱為 skewed）。沒有任何 actionable 主機時印明確訊息並以 0 結束，不問任何確認。
3. **確認**：互動模式預設 No 的確認；`--force` 略過確認；`--preview-only` 只做 1–2 就結束（結束碼 0）。
   staging／prod 的 stage 確認沿用 deploy 的 `promptStageDecision`／`--stage`。
4. **套用（一次 `ansible-playbook`，兩個 play）**：
   - Play A（全部目標主機，`any_errors_fatal`，**唯讀**）：重新偵測，並在**任何變更之前**做完所有拒絕判斷，任何一台失敗，整次在
     Play B 開始前結束。這是「整次 fail closed」的實作點。套用模式下（`pilot_hotfix_mode` 不是 `observe`）、只對 actionable
     主機：staging／prod 確認、該主機的環境 group cross-check、manager 的環境 group cross-check（只要有 actionable 主機且會
     deregister）、prod attestation，以及（`pilot hotfix` 有帶時）確認過的主機清單（`pilot_hotfix_confirmed_hosts`：actionable
     主機不在清單裡就拒絕，要求重新 plan）。**manager 登記表比對**（唯讀）對有 enrollment 的 actionable 主機在偵測與套用模式都做：
     記錄的 ID 下若有登記，name 必須與 `client.keys` 一致（不分大小寫）；記錄的 name 若以**另一個 ID** 登記也拒絕（不猜）；ID 已不在
     manager 上視為已完成。Play B 的 `pre_tasks` 重複同樣的 stage gate 當作縱深防禦，**不可能是第一個失敗的**
     （Play B 是 `serial: 1`，`pre_tasks` 每台各跑一次，放在那裡的 gate 對第二台會在第一台已被變更之後才執行）。
   - Play B（只有 Play A 判定 actionable 的主機，`serial: 1`，每台依序，每步冪等）：
     ① 取得 host-wide Wazuh writer（`writer-claim`；之後的每個變更動作都以 `--owner` 驗證 writer marker 恰好屬於這次 run，別人的 marker、journal 或沒有 marker 一律拒絕）；② 停止並 disable `wazuh-agent`；
     ③ 在 manager 上依**已記錄的 ID 與 name 交叉比對**deregister（Play A 的登記表比對在這裡**再做一次**，因為兩者之間登記表可能變；ID 與 name 不吻合就拒絕，不猜）；
     ④ 一個 helper 動作 `remove`，**依序**：解除 pilot 自己的 hold／versionlock／apt preference（只動 pilot 擁有、內容完全符合的；外來內容在
     Play A 就已拒絕）→ 移除 `client.keys` → **卸載 `wazuh-agent` 套件**（Debian 用 `purge`）→ 讓 auditd 放掉套件移除後被遺留的 audit plugin（只在偵測到遺留 listener 時重啟 auditd：EL 用 auditd 套件自己的 legacy restart〔`systemctl restart` 被 RefuseManualStop 擋〕，Debian 用 `systemctl restart auditd`；等 who-data endpoint 的 listener 消失。auditd 約停一秒，期間 kernel audit 事件排隊）。
     較輕的做法都試過、都不行：對 auditd 送 `SIGHUP` 會讓 dispatcher 退出，之後 pilot 自己的那一次 `SIGHUP` 只印出 `initialized with 1 active plugins` 卻不啟動 plugin；殺掉 plugin 行程則會被 auditd 重生到 `exceeded max_restarts`；
     ⑤ 事後 assert 並在 `always` 區段釋放 writer（只要這個 play 取得過）。
   - **可接續（沒有 rollback，順序就是保證）**：卸載是唯一讓 `skewed` 變成 false 的步驟，所以它前面的每一步（停服務、deregister、解除 policy、移除
     `client.keys`）被中斷後，套件仍在、主機仍是 skewed，重跑會選到它並接續；卸載之後唯一可能還殘留的是孤立的 audit plugin，那正是 `residue`，重跑同樣會選到。
     兩個**不在保證內**的情況：(a) 卸載動作本身被殺掉，dpkg／rpm 可能留下半移除的套件狀態，`inspect` 以「unknown agent package state」按名拒絕，要手動修復後重跑；
     (b) controller 被殺或逾時時 `always` 區段不會執行，writer marker 會留著（`inspect` 看到會拒絕），要依 runbook 確認沒有 run 在進行後手動移除。
5. **結果**：逐台印 `已移除 / 已清除遺留的 audit plugin（residue）/ 略過（版本相容）/ 略過（未安裝）`，再提示「之後用 `pilot deploy` 重新安裝」。
   結果取自**套用當下**重新偵測的 marker，不是偵測階段的快照（偵測與套用之間狀態可能變）；計畫裡的 actionable 主機沒有被回報完成就是失敗。

### Fail-closed 清單（全部在任何變更之前拒絕，並指名原因）

- `wazuh-manager` group 不是恰好一台；M 讀不到或不是 `4.14.x`；
- 任一目標主機：套件狀態或架構未知、版本無法解析成 `X.Y.Z`、writer 未閒置（有 `writer-active.json` 或未完成
  journal，例如被中斷的 `wazuh-fim` 升級——該先走既有 recovery，不是 hotfix）、
  `/etc/apt/preferences.d/pilot-wazuh-agent` 內容不是 pilot 寫的格式、`versionlock.list` 的 pilot 區塊不是
  `wazuh-agent-0:4.14.N-R.x86_64`、`client.keys` 存在但無法解析出恰好一個 ID／name；
- stage 與目標主機（含被 deregister 的那台 manager）的環境 group 不一致，或缺少 staging／prod 確認；
- manager 登記表與主機的 `client.keys` 矛盾（記錄的 ID 下是另一個 name，或記錄的 name 以另一個 ID 登記）；
- 計畫確認之後才變成 actionable 的主機（不在確認清單裡）；
- skewed 的 EL 主機沒有 auditd 的 legacy restart action，或任何 skewed 主機的 `ss -xl` 不能用（`ss` 與 EL 的 legacy restart action 是新增的硬性依賴）。

### 與既有元件的邊界

- **不是 decommission**：`wazuh-agent-decommission.yml` 只刪 `client.keys`、保留套件與 hold（讓 FIM 設定留著給
  未來重新註冊），所以 `wazuh-fim-apply.yml` 對 V > M 仍會拒絕；hotfix 才把套件與 hold 一起清掉。兩者互不呼叫。
- **不修改 `wazuh-transaction.py`**：它是 328 KB 的 durable transaction；hotfix 只以既有、唯讀或 claim／release
  的 action（`manager-version`、`writer-claim`、`writer-release`）呼叫它，並在自己的
  `wazuh-agent-hotfix.py` 重做兩段小探測（已安裝版本、pilot 擁有的 hold artifact），以及**自己讀 writer marker 檔**
  （不呼叫 `writer-inspect`）。重複的常數
  （preference 路徑與格式、versionlock 區塊標記、writer state 根目錄，以及 audit endpoint／plugin 設定／`client.keys` 路徑，
  後三者與 `audit-whodata.py`、`wazuh-fim-apply.yml` 重複）由 regression test 鎖與
  對應檔案一致（AGENTS.md §5.7）。
- 順帶效果：被 deregister 的 skewed agent 一旦不在 manager 登記表，`wazuh-manager.md` C12 與 manager 的
  `check_agents` 不再因它而拒絕。

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Hostname / Inventory group | 偵測／套用：`wazuh-fim`（agent，受 `--limit` 限縮）與恰好一台 `wazuh-manager`；驗收見下方注意事項 |
| OS / version | Debian family（Ubuntu 22.04／24.04）與 RedHat family（AlmaLinux 9）；x86_64 |
| 角色 | 一次性、day-2、opt-in 的環境修正；沒有 contract、不進 `site.yml`、不是 component |
| 套用範圍 | agent：`wazuh-agent` 套件與服務、auditd 遺留的 audit plugin、`/var/ossec/etc/client.keys`、`/etc/apt/preferences.d/pilot-wazuh-agent`、`/etc/dnf/plugins/versionlock.list` 的 pilot 區塊、`/var/backups/pilot/wazuh` writer 狀態；manager：agent 登記（`manage_agents -r`） |
| 風險等級 | High（刪除套件與 manager 登記；錯刪合法 agent 等於該主機的 FIM 告警中斷到重新 deploy） |

> **驗收對象**：C1–C5、C7、C8 驗的是「**被 hotfix 移除**的那幾台（含 residue 主機）」的結束狀態，跑 `pilot verify` 時要用
> `-l <被移除的主機>`。對版本相容、原樣保留的 agent 主機，C1 本來就不該成立。這是 AGENTS.md §0.1
> 的「讀你實際執行的那份 inventory 的事實」：被移除的主機清單來自 hotfix 的結果 marker，不是 spec 猜的。
> C6 驗 manager，要用 `-l <wazuh-manager 主機>` 跑；在 agent 主機上它回 0（沒有 manager stack，無事可查），所以對 agent 跑 C6 不證明任何事。

## 1.5 依賴變數契約

| 變數名稱 | 說明/用途 | 是否必填 | 預設值 |
|---------|----------|---------|--------|
| `target_group` | playbook 的 `hosts:` 覆寫（`vm-target test` 與直接 `ansible-playbook` 用） | 否 | `wazuh-fim` |
| `stage` | `sandbox`／`staging`／`prod` | 否 | `sandbox` |
| `confirm_staging`、`confirm_prod`、`staging_attested_within_hours` | 同 §4.3 的 stage gate | 視 stage | `false`／`false`／`168` |
| `pilot_hotfix_deregister` | 是否在 manager 端 deregister（`pilot hotfix` 不帶它，用 playbook 預設 `true`；`false` 只供診斷，會留下 manager 上的登記） | 否 | `true` |
| `pilot_hotfix_mode` | `apply`（預設）或 `observe`（只跑 Play A 的唯讀偵測，不評估 apply 的 gate；`pilot hotfix` 用它產生計畫）；其他值被拒絕 | 否 | `apply` |
| `pilot_hotfix_confirmed_hosts` | 操作者確認過的主機清單，以 JSON object 值傳入（`-e '{"pilot_hotfix_confirmed_hosts": [...]}'`，不是 `key=[...]`）；有定義時，actionable 主機不在清單裡就在任何變更之前拒絕；未定義（vm-target 直接跑）不限制 | 否 | 未定義 |

本 playbook **不**新增任何 inventory 輸入變數：版本、manager 位址、registration 都從目標主機與 manager 的實際
狀態讀取（§5.9），所以沒有 contract `groupVars`，也沒有 `group_vars/*.example.yml`。

## 2. Checklist

| ID  | Category | Check | Expected | Command |
|-----|----------|-------|----------|---------|
| C1 | package | 被移除的主機上 `wazuh-agent` 套件不在已安裝狀態（Debian 的 `deinstall ok config-files` 不算已安裝） | 0 | sh -c 'if command -v rpm >/dev/null 2>&1; then rpm -q wazuh-agent >/dev/null 2>&1 && echo 1 || echo 0; else dpkg-query -W -f="\${Status}\n" wazuh-agent 2>/dev/null | grep -qxE "(install|hold) ok installed" && echo 1 || echo 0; fi' |
| C2 | service | `wazuh-agent.service` 既不 active 也不 enabled | 0 | sh -c 'systemctl is-active --quiet wazuh-agent || systemctl is-enabled --quiet wazuh-agent && echo 1 || echo 0' |
| C3 | policy | 沒有任何 native hold／versionlock 還指著 `wazuh-agent`（Debian `apt-mark showhold`、EL `versionlock.list`） | 0 | sh -c 'if command -v rpm >/dev/null 2>&1; then grep -qs "wazuh-agent" /etc/dnf/plugins/versionlock.list && echo 1 || echo 0; else apt-mark showhold 2>/dev/null | grep -qxE "wazuh-agent(:amd64)?" && echo 1 || echo 0; fi' |
| C4 | policy | pilot 擁有的 policy artifact 都已移除（Debian preference 檔；EL versionlock 區塊標記）——殘留的 `Pin: version * / Pin-Priority: -1` 會讓之後 `pilot deploy` 無法安裝任何其他版本 | 0 | sh -c 'if test -e /etc/apt/preferences.d/pilot-wazuh-agent || grep -qs "PILOT WAZUH VERSIONLOCK" /etc/dnf/plugins/versionlock.list; then echo 1; else echo 0; fi' |
| C5 | enrollment | `client.keys` 不存在或為空（舊 enrollment key 不會被重新安裝的 agent 沿用） | 0 | sh -c 'test -s /var/ossec/etc/client.keys && echo 1 || echo 0' |
| C6 | functional | 這台主機若跑著 Wazuh manager stack：所有已註冊 agent 版本都不高於 manager，且沒有未完成交易；沒有 manager stack 的主機沒有東西可查，回 0（`pilot verify` 對一個 group 一律跑全部列，無法只對 manager 指定這一列；所以要用 `-l <wazuh-manager 主機>` 驗它，見 §1 注意事項）。檢查本身與 `wazuh-manager.md` C12 相同，但命令多了 `test -x` 與 `2>&1`：原命令在 binary 不存在時，shell 的 `not found` 訊息讓 stdout 不是單獨一個整數，`pilot verify --local` 退回程序 rc=0 而**誤判 PASS**；inventory 路徑實測不受影響，見 #332） | 0 | sh -c 'if test -n "$(docker ps -aq --filter name=single-node-wazuh.manager-1 2>/dev/null)"; then test -x /usr/local/sbin/pilot-wazuh-transaction && /usr/local/sbin/pilot-wazuh-transaction central-verify >/dev/null 2>&1 && echo 0 || echo 1; else echo 0; fi' |
| C7 | transaction | hotfix 取得的 host-wide Wazuh writer 已釋放，沒有留下 writer marker | 0 | sh -c 'test -e /var/backups/pilot/wazuh/writer-active.json && echo 1 || echo 0' |
| C8 | audit | 沒有任何 unix socket 還在 listen Wazuh 的 who-data endpoint（套件移除〔Debian purge、EL RPM〕刪掉設定與 `/var/ossec`，但 auditd 仍留著它啟動的 `audisp-af_unix`，listener 綁在已被刪除的路徑上；之後重新安裝的 agent 連不上，EL 的 `pilot deploy` 在 who-data 步驟失敗，Debian 則靜默退回 real-time）。`ss -xl` 不論該路徑是否還存在都列出 listener。**沒有 `ss`、或 `ss -xl` 本身失敗時回 1（FAIL）**：看不到 listener 就不能說沒有，缺工具不能讓這一列通過 | 0 | sh -c 'command -v ss >/dev/null 2>&1 || { echo 1; exit 0; }; out=$(ss -xl 2>/dev/null) || { echo 1; exit 0; }; n=$(printf "%s\n" "$out" | grep -c "ossec/queue/sockets/audit"); test "$n" = 0 && echo 0 || echo 1' |

> C1–C5、C7 的 command 在 `-l` 限縮後只對被移除的主機有意義；它們刻意用「正邏輯 + `echo 0/1`」，避免反邏輯 grep
> 在 ansible ad-hoc 下被判為 FAILED（`docs/verification-spec-template.md` 陷阱 1）。

## 3. 證據收集

- 工具：`pilot verify docs/verification/wazuh-fim-agent-skew-hotfix.md -i <inventory> -l <被移除的主機>`
  （C1–C5、C7），以及 `-l <wazuh-manager 主機>` 取 C6。
- 實跑：`pilot vm-target topology test`（`--ephemeral`）對 `docs/topologies/wazuh-agent-skew-topology.yaml`
  執行，內含製造 skew 的 fixture（`playbooks/test/fixtures/wazuh-agent-skew-fixtures.yml`）。
- 原始輸出：gitignored `.verification/` 或 pilot evidence store；不貼完整 transcript。
- Sanitized 摘要：`docs/evidence/wazuh-fim-agent-skew-hotfix/<change>.md`；runbook §0.5 連到最新的一份。
- Row 數：8（等於 checklist row 數）。

## 4. PASS / FAIL 規則

- C1–C8 全部 `pass` → hotfix 結束狀態 **PASS**。
- 另需 target 實跑證明的負向案例（不是 checklist row，但屬驗收）：
  1. **相容 agent 不被碰**：同一次 run 中 V ≤ M 的主機，套件、hold、`client.keys`、manager 登記全部原樣。
  2. **fail closed**：把任一台主機製造成「writer marker 存在」，整次 run 在 Play B 之前結束，其他 skewed 主機
     也**沒有**被動到。
  3. **冪等**：第二次執行偵測到沒有 skewed 主機，`changed=0`、不問確認。
  4. **重新安裝**：hotfix 之後 `pilot deploy` 單一元件 `wazuh-fim` 對同一台主機成功，安裝的版本 = M。

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C6 | `pilot-wazuh-transaction` 由 `wazuh-manager-apply.yml` 安裝；手動安裝的 manager 沒有它，C6 會 fail——這種 manager 不在 pilot 的管理範圍，應先走 `wazuh-manager` 的 apply | 所有環境 | 永久（設計如此） |
| — | 偵測不到「從未連線過、`Client version: (null)`」的登記（它沒有版本可比）；這類登記由 `wazuh-manager.md` 既有的 `manage_agents -r` 說明處理 | 所有環境 | 永久 |
| — | v1 只支援單一 `wazuh-manager` 主機 | 所有環境 | 待有多 manager 需求再開 |
| — | 卸載動作本身被殺掉時，dpkg／rpm 可能留下半移除的套件狀態，`inspect` 以 unknown agent package state 拒絕（要手動修復）；controller 被殺或逾時時 writer marker 不會自動釋放（見 runbook §2） | 所有環境 | 永久（沒有 rollback，順序只保證卸載之前與之後的失敗） |

## 變更紀錄

| 日期 | PR | 驗收語意變更 |
|------|----|--------------|
| 2026-11-13 | — | 初版草稿：`pilot hotfix wazuh-agent-skew` 的 acceptance contract（尚未實跑） |
| 2026-11-13 | — | 新增 C8（audit plugin 遺留 listener）。起因：第一次實跑 hotfix 之後用真正的 `pilot deploy` 重裝，EL 主機在 who-data 步驟以 `external audit endpoint did not appear after reloading the audit daemon` 失敗；Debian 上 verify 抓到同樣的遺留 listener。hotfix 補上清理，重跑後 deploy 才成功 |
| 2026-11-13 | #331 | **C8 的 Command 改了（驗收方法變更）**：原命令在 `ss` 不存在時 `ss -xl 2>/dev/null` 失敗、`grep -c` 對空輸入印 0，於是缺 `ss` 的主機**誤判 PASS**；現在沒有 `ss` 或 `ss -xl` 失敗都印 1（FAIL），仍是單獨一個整數，Expected 不變。新增的 Go test 以 PATH 沒有 `ss`、`ss` 失敗、`ss` 沒有 listener、`ss` 列出 listener 四種真實形狀各鎖一次。同次 review 修正的其他語意（不改 row）：移除順序改為「解除 policy → 移除 `client.keys` → 卸載 → 清 audit plugin」，卸載最後；新增 `residue` 狀態（沒有套件且 audit plugin 孤立）讓卸載之後才失敗的主機重跑會被選到；所有拒絕（stage／環境 group／確認清單／manager 登記比對）移到 Play A、在任何變更之前；偵測就拒絕做不完的 skewed 主機（EL 沒有 legacy restart action、`ss` 不能用）；更正 §「與既有元件的邊界」對 `writer-inspect` 的描述（helper 自己讀 marker 檔） |
