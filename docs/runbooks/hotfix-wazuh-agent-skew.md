# Runbook — `pilot hotfix wazuh-agent-skew`：移除版本比 manager 新的 Wazuh agent

## 0. 一句話目標

部分主機的 Wazuh agent 版本比 Wazuh manager 新時，`pilot deploy` 無法重新安裝那些主機
（`wazuh-fim-apply.yml` 對 agent 版本 > manager 版本一律拒絕，沒有降級路徑）。這個指令把那些主機整理回
「沒有 agent」，之後用 `pilot deploy` 重新安裝即可，版本取 `wazuh_version`，未設定時為 manager 的版本。
驗收契約：[wazuh-fim-agent-skew-hotfix.md](../verification/wazuh-fim-agent-skew-hotfix.md)。

> 驗收證據：[最新 evidence](../evidence/wazuh-fim-agent-skew-hotfix/LATEST.md)（tested revision、tree、verdict、失敗路徑與未涵蓋範圍都在那裡）。

## 0.5 目前有效的事實快照

| 項目 | 內容 |
|------|------|
| 目標環境 | `pilot vm-target topology`，[wazuh-agent-skew-topology.yaml](../topologies/wazuh-agent-skew-topology.yaml)：4 台拋棄式 KVM VM（manager、相容 agent、Ubuntu 24.04 skewed agent、AlmaLinux 9.8 skewed agent） |
| inventory 事實 | `ansible-inventory --graph` 讀到：`wazuh-manager`＝`wsk-manager`；`wazuh-fim`＝`wsk-ok`、`wsk-deb`、`wsk-el`；`wazuh-skewed`＝`wsk-deb`、`wsk-el`。對齊決定 **A**：provision 這份宣告的拓樸，不從 spec 推測 |
| 製造 skew | [wazuh-agent-skew-fixtures.yml](../../playbooks/test/fixtures/wazuh-agent-skew-fixtures.yml)：用 pilot 自己的 playbook 部署 manager（4.14.1）與三台 agent，再 [wazuh-agent-skew-make-skew.yml](../../playbooks/test/fixtures/wazuh-agent-skew-make-skew.yml) 把 `wazuh-skewed` 兩台升到 4.14.9（套件在 pilot 之外被換掉，pilot 的 hold 改指向它） |
| 偵測到的狀態（真實輸出） | manager 4.14.1；`wsk-deb` 4.14.9-1、`wsk-el` 4.14.9-1（都是 skewed，都已向 manager 註冊）；`wsk-ok` 4.14.1-1（相容） |
| 對齊 | 用到的 vault／外部 state：無（只需要 `-e stage=sandbox`） |

正式實跑（candidate 綁定的 `vm-target topology test`，結果見上面連結的 evidence）：L1 syntax、L3 `--check --diff`、snapshot、L4 套用、
L5 驗收（skewed 兩台與 manager 各一份，全部 PASS）、L6 冪等 `changed=0`。鏈外另跑的 arm：

- `--preview-only`：只印計畫，什麼都沒變。
- 某台有進行中的 Wazuh writer：在偵測階段整次拒絕、結束碼 1，其他主機與 manager 登記完全沒動。
- 真正的 `--force`：兩台 skewed 被移除，版本相容的主機完全沒動；重跑一次什麼都不做。
- hotfix 之後 `pilot deploy --component wazuh-fim --limit <被移除的主機> --force`：成功，兩台裝回與 manager 相同的版本，
  hold／versionlock 重建，向 manager 重新註冊為 Active。

## 1. 為什麼不是 `host decommission`

`wazuh-agent-decommission.yml` 只停服務並刪 `client.keys`，**保留套件與 hold**（讓 FIM 設定留著給未來重新註冊）。
所以 `wazuh-fim-apply.yml` 對那台主機仍然看到 V > M 而拒絕。hotfix 把套件、hold／versionlock、manager 登記與
遺留的 audit plugin 一起清掉，兩者互不呼叫。

## 2. 用法

```bash
# 只看計畫（唯讀，不會問 stage，不變更任何東西）
pilot hotfix wazuh-agent-skew --dir <workspace> -i inventory.yml --preview-only

# 互動：印出計畫 → 選 stage → 確認（預設 No）→ 套用
pilot hotfix wazuh-agent-skew --dir <workspace> -i inventory.yml

# 非互動：採用預設值並略過確認；staging／prod 必須明示
pilot hotfix wazuh-agent-skew --dir <workspace> -i inventory.yml --force [--stage staging|prod ...]
```

旗標與 `pilot deploy` 同語意：`--dir`、`-i/--inventory`、`--timeout`、`--limit`、`--stage`、
`--staging-attested-within-hours`、`--force`、`--preview-only`。`--limit` 只限縮要偵測與處理的 agent 主機，
manager 一律會被讀取。完成後：

```bash
pilot deploy --dir <workspace> -i inventory.yml --component wazuh-fim --limit <被移除的主機>
```

### 它會做什麼、不會做什麼

1. **唯讀偵測**：`wazuh-manager` group 必須恰好一台；讀它的原生版本 M，與每台 `wazuh-fim` 主機實際安裝的 agent
   版本比。版本比較**只在** `playbooks/apply/files/wazuh-agent-hotfix.py inspect` 做一次，嚴格大於 M 才算 skewed；
   Go 只讀 playbook 印出的 marker。版本相容或沒裝 agent 的主機一律不動。
2. **整次 fail closed**：M 讀不到、版本無法解析、套件狀態未知、有進行中的 Wazuh writer 或未完成 journal、
   pilot 的 hold 檔內容不是 pilot 自己寫的格式……任何一台無法判定，整次在變更任何主機之前拒絕並指名原因。
3. **逐台變更**（`serial: 1`，第一個失敗就停）：取得 Wazuh writer → 停 agent → 在 manager 依**記錄的 ID 與名稱**
   取消登記（名稱對不上就拒絕，不猜）→ 解除 pilot 的 hold／versionlock → 卸載套件 → 移除 `client.keys` →
   讓 auditd 放掉遺留的 audit plugin → 事後驗證 → 釋放 writer。
4. **沒有 rollback**（套件卸載無法放回原位），但每一步冪等、順序保證任何中斷都留在重跑能完成的狀態：
   停了但完整的 agent（取消登記之前），或已取消登記但還裝著的 agent（卸載之前）。**重跑同一個指令即可接續。**
5. 在 manager 上刪除登記、卸載套件**不可復原**；確認提示明說這點。

### 範圍與限制

- 只支援單一 `wazuh-manager` 主機。
- 不支援 `--actions`／`--presentation`／`--trace-out`（它們綁在 edit scenario schema 的 `deploy`／`reconcile` action 上）。
- 互動的確認提示（預設 No）：「拒絕就什麼都不做」由單元測試以預設值驅動器涵蓋；真正的終端機 widget 與互動式選 stage 沒有實機驗證，實機只跑過 `--preview-only` 與 `--force`。
- 只處理 `wazuh-fim` group 的主機；agent 被安裝在 group 之外的主機不在偵測範圍。

## 3. 為什麼 spec 有 8 個 row、為什麼 C6 長那樣

- `pilot verify` 對一個 group 一律跑**全部** row，無法只對 manager 指定某一列。所以 C6（manager 的
  `central-verify`）在沒有 manager stack 的主機上回 0（無事可查），要用 `-l <wazuh-manager 主機>` 驗。
- C1–C5、C7、C8 驗的是「被移除的主機」的結束狀態，要用 `-l <被移除的主機>`（本次是 group `wazuh-skewed`）；對版本相容
  而保留 agent 的主機，C1 本來就不該成立。

## 4. 重跑這份驗證

```bash
pilot vm-target topology up --fresh --topology docs/topologies/wazuh-agent-skew-topology.yaml
pilot vm-target topology inventory --topology docs/topologies/wazuh-agent-skew-topology.yaml --out tmp/wsk.inv.yaml
ansible-playbook -i tmp/wsk.inv.yaml playbooks/test/fixtures/wazuh-agent-skew-fixtures.yml -e stage=sandbox
pilot vm-target topology test --topology docs/topologies/wazuh-agent-skew-topology.yaml \
    --playbook playbooks/apply/wazuh-fim-agent-skew-hotfix.yml \
    --verify docs/verification/wazuh-fim-agent-skew-hotfix.md=wazuh-skewed \
    --verify docs/verification/wazuh-fim-agent-skew-hotfix.md=wazuh-manager \
    --verify-timeout 40 -- -e stage=sandbox
pilot vm-target topology down --topology docs/topologies/wazuh-agent-skew-topology.yaml
```

fixture 的前三步（docker、manager、agent）只能跑一次：一旦有主機比 manager 新，`wazuh-manager-apply.yml` 與
`wazuh-fim-apply.yml` 都會拒絕（這正是 hotfix 要解的狀況，也是這個情境的自然驗證）；之後要重做 skew 只跑
`wazuh-agent-skew-make-skew.yml`，或 `topology rollback` 回 `topology test` 建立的 `pre-test-*` snapshot。

## 5. 踩過的雷

每一條都是實跑才現形，而且在當時所有單元測試都綠燈。

1. **helper 被自己的 writer claim 擋住。** 第一版的 `inspect` 把「Wazuh writer 閒置」當前置條件，但變更動作是在 playbook
   自己取得 writer 之後才執行，所以第一次實跑就在 quiesce 失敗（`writer-active.json`）。
   修法：變更動作帶 `--owner`，只接受恰好屬於這次 run 的 writer marker（別人的、central 的、journal、沒有 marker 都拒絕）；
   唯讀的 `inspect` 仍拒絕任何 marker。
2. **`pilot verify --local` 的 matcher 陷阱：缺 binary 也 PASS。** `sh -c '<不存在的指令> … && echo 0 || echo 1'` 在
   `--local` 下，shell 自己印的 `not found` 併在 `echo` 前面，輸出不是單獨一個整數，`rc-from-stdout` 抽不出來，退回程序 rc
   （永遠 0），於是缺少 coordinator 的 manager 也 PASS。`pilot verify --local --probe` 可以重現。**範圍要說窄**：inventory 路徑
   （`ansible --one-line`，ansible-core 2.20.1，輸出 `(stdout) 1 (stderr) …`）實測不受影響，`extractRC` 讀得到 `1`；
   `wazuh-manager.md` C11/C12、`wazuh-fim.md` C10、`wazuh-alert-delivery.md` C1 是同形寫法（#332，**本變更沒有修**）。
   本 spec 的 C6 加 `test -x` 與 `2>&1`，並由 regression test 對每個 row 鎖「輸出只有單獨的 0 或 1」，C6 另外對「有 manager stack 但沒有
   coordinator」鎖必須 FAIL。
3. **套件移除會遺留 audit plugin 的 listener（Debian 與 EL 都是）。** 移除套件刪掉 `/etc/audit/plugins.d/af_wazuh.conf` 與
   `/var/ossec`，但 auditd 仍留著它啟動的 `audisp-af_unix`，listener 綁在已被刪除的路徑（`ss -xl` 仍列出，`ls` 看不到檔案）。
   重新安裝後 EL 的 `pilot deploy` 在 who-data 步驟以 `external audit endpoint did not appear after reloading the audit
   daemon` 失敗；Debian 的 apply 沒有那一步，所以會靜默退回 real-time。**較輕的做法都試過、都不行**：對 auditd 送 `SIGHUP` 讓
   dispatcher 退出（`After reconfigure, there are no active plugins, exiting`），之後 pilot 自己的那次 `SIGHUP` 只印出
   `initialized with 1 active plugins` 卻不啟動 plugin；殺掉 plugin 行程則被 auditd 重生到 `exceeded max_restarts`。
   有效的是重啟 auditd（EL 用 auditd 套件自己的 `legacy-actions/auditd/restart`，因為 `systemctl restart` 被 `RefuseManualStop`
   擋；Debian 用 `systemctl restart auditd`），之後的 `pilot deploy` 才成功。代價：auditd 約停一秒，期間 kernel audit 事件排隊。
   只在偵測到遺留 listener 時才做。
4. **`pilot verify` 對一個 group 跑全部 row。** 第一版 C6 在 agent 主機上也跑（而且正確地 FAIL）。見 §3。
5. **Debian 用 purge，不用 remove。** `wazuh-transaction.py` 的 `Agent.installed()` 把 `deinstall ok config-files` 當成
   `unknown agent package state` 拒絕，`remove` 會讓之後的 `pilot deploy` 被擋。這一點是讀程式碼得出，**沒有單獨在實機重現**；
   實機上 purge 之後 `dpkg-query` 回「no packages found」，之後的 deploy 成功。
6. **fixture：Debian 升級會停在 conffile 提示。** 非互動 stdin 下 dpkg 在 `wazuh-agent.service` 的提示卡住、套件半設定；
   fixture 改用 `--force-confold`。這只影響測試 fixture，不影響 hotfix。
7. **共用主機的 SQLite 鎖。** 別的 session 同時使用 pilot 的歷史資料庫時，`topology test` 的 verify 步驟會因
   `database is locked (SQLITE_BUSY)` 失敗並 rollback；與本變更無關，重跑即可。
8. **失敗訊息看不到原因。** ansible 的失敗摘要只有 `non-zero return code`，真正的 typed 拒絕原因在 helper 的 stdout 裡；
   現在 CLI 會從失敗輸出撈出來印成「原因：…」（`internal/hotfix.Refusals`，用真實擷取當 fixture）。
9. **EL 的 who-data 步驟有既有的重啟 race（不是這個變更造成，但會影響「hotfix 之後重裝」）。** Wazuh 自己的 `restart.sh`
   （註冊後重啟 agent）可能和 pilot 的 `systemctl restart wazuh-agent` 重疊，留下一個在 audit endpoint 出現**之前**就啟動的
   `wazuh-syscheckd`（journal：`remains running after unit stopped`、`already running`），於是
   `native Wazuh audit stream or watches did not appear after restarting the agent`，約 60 秒後 apply 失敗。
   在 pilot 自己的一般 `wazuh-fim-apply.yml`（還沒有 hotfix 參與）也發生過一次，同一台主機重跑即通過。若 hotfix 之後的重裝在 EL
   卡在這一步，**直接重跑 `pilot deploy` 即可**；它需要另外追根本原因，不是在 hotfix 裡加 workaround。
