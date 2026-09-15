# Verification Spec — Pilot Gateway Scope Publication

> 版本：DRAFT v0.2（vm-target 已實測；尚未正式站台驗收）
> 對齊規範：docs/superpowers/specs/2026-09-14-pilot-access-gateway-stateless-freeipa-portal-spec.md §9.6/§57（Phase 6 — Gateway scope publication）
> 維護者：sre
>
> 最新 `--hosts all` actual-run evidence：[`2026-09-15-all-keyword.md`](../evidence/pilot-gateway-scope/2026-09-15-all-keyword.md)

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Inventory group | `freeipa-server`（或明確 `target_group`） |
| 角色 | 把一個 pilot-access-gateway scope 的目標主機清單發布成 FreeIPA hostgroup `pilot-target-<scope>` |
| 套用範圍 | 單一 scope 的 hostgroup 存在性與成員關係；不建立/管理 gateway 主機本身 |
| 前置需求 | FreeIPA server 已就緒；`gateway_scope_hosts` 列出的主機物件已存在於 FreeIPA（`ipa host-add`） |
| 風險等級 | Low — 只動一個獨立 hostgroup 的成員清單，不碰 HBAC/sudo/使用者 |

## 1.5 依賴變數契約

| 變數名稱 | 說明/用途 | 是否必填 |
|---------|----------|---------|
| `gateway_scope` | scope 名稱，例如 `gpu`（決定 hostgroup 名 `pilot-target-<scope>`） | 是 |
| `gateway_scope_hosts` | 該 scope 目標主機 FQDN 清單，需以 `-e '{"gateway_scope_hosts": [...]}'` 的 JSON 物件形式傳入（`-e gateway_scope_hosts=[...]` 這種寫法會被 Ansible 當成純字串，不會被解析成 list）；透過 `pilot gateway-scope plan/reconcile` 時也可指定字面值 `all`，由 controller 展開成指定 inventory 的 `freeipa-client` group | 是 |
| `ipa_admin_password` | kinit admin 用；只能來自 vault (`-e @~/.vault/main.yaml`) | 是 |
| `gateway_scope_plan_only` | `true` 時只讀 diff、不寫入（對應 `pilot gateway-scope plan`）；預設 `false`（對應 `reconcile`） | 否 |

此驗收文件記錄的具體情境：`gateway_scope=gpu`，`gateway_scope_hosts=["gpu-a.ipa.pilot.internal","gpu-b.ipa.pilot.internal"]`（與 pilot-access-gateway Phase 0-5 evidence 使用的同一組真實 FreeIPA fixture 一致）。

## 1.6 `all` 關鍵字契約

- `pilot gateway-scope plan/reconcile --hosts all` 是明確的 controller-side keyword；它只解析指定 `--inventory` 的 `freeipa-client` group，並將解析後的主機清單傳給 playbook。
- `all` 不代表 Ansible 的 `all` group，也不查詢所有 FreeIPA host object；未納入 `freeipa-client` 的 inventory host 不會被加入。
- **`all` 會排除所有 `pilot-access-gateway` 主機**（2026-09-15 修復）：`contracts/pilot-access-gateway.yaml` 宣告 `freeipa-client` 是必要的 `sameHosts` 依賴，代表每一台 gateway 主機結構上永遠也是 `freeipa-client`——沒有這條排除，`all` 會把 gateway 自己（以及環境裡其他 gateway）也發布成自己的 SSH target，且之後掛在 `pilot-target-<scope>` 上的 sudo/HBAC rule（`pilot-grant-sudo-<scope>`/`pilot-grant-login-<scope>` 慣例）會連帶套用到 gateway 主機本身，違反 gateway 登入授權應該走獨立 `pilot-access-gateways` hostgroup 的既有設計。已在活體 demo 實測重現並確認修復（`docs/evidence/pilot-gateway-scope/2026-09-15-all-keyword.md`）。若展開後一台都不剩（環境裡所有 `freeipa-client` 主機都是 gateway），會 fail closed 而非發布空清單。
- **`pilot-access-gateway-apply.yml` 自己也有一道防線（Step 3b）**：每次套用這個元件時，會主動偵測並移除該主機在任何 `pilot-target-<scope>` hostgroup 裡的殘留成員資格（絕不動 `pilot-access-gateways` 自己）。這是獨立於上面 CLI 修復的第二層防護——涵蓋「主機先被 `all` 之類的機制加進某個 target scope，之後才升級成 gateway」這種時序情境，冪等、每次重跑都會自我校正。
- `--hosts all,<host>`、空字串、空清單都必須 fail closed；不能把未填值解讀成全主機授權。
- `gateway_scope: all` 只是將 scope hostgroup 命名為 `pilot-target-all`；要發布成員仍須執行 `--hosts all` 的 plan/reconcile。
- 新增 `freeipa-client` 主機後，必須再次 reconcile；本功能不提供自動持續同步（若要免手動重跑，見下方「讓 all 自動涵蓋新主機」）。

### 讓 `all` 自動涵蓋新主機：`pilot gateway-scope enable-auto`/`disable-auto`（2026-09-15）

單純的 `--hosts all` 是**一次性快照**：controller 呼叫當下查詢 inventory，之後新加入的 `freeipa-client` 主機不會自動出現，要手動再跑一次 `pilot gateway-scope reconcile --hosts all`。`enable-auto`/`disable-auto` 這兩個正式子指令解決了這個問題,做法是 **FreeIPA 原生的 automember**,而不是讓 `pilot-access-gateway` 執行期或 controller 去做持續輪詢——兩者都會違反 spec.md AG17/AG18「gateway 執行期完全不依賴 inventory/roster」的既有設計（`go list -deps` 可驗證零依賴）：

```bash
# 立刻用「all」(排除 gateway 主機) 回填一次,並設定 automember rule
# --dir 用法跟 `pilot deploy --dir`/`pilot edit --dir` 一致：--inventory 預設
# "inventory.yml"(相對 --dir),--vault-file 沒給時會自動找 <dir>/.vault/main.yaml
pilot gateway-scope enable-auto --scope gpu --dir <workspace>

# 之後移除 automember rule(不會動現有成員資格)
pilot gateway-scope disable-auto --scope gpu --dir <workspace>
```

`plan`/`reconcile` 也支援同一個 `--dir` 捷徑（`--target-group` 預設已經是 `freeipa-server`，通常不用另外指定）：

```bash
pilot gateway-scope plan      --scope gpu --hosts all --dir <workspace>
pilot gateway-scope reconcile --scope gpu --hosts all --dir <workspace>
```

四個子指令都還是接受明確的 `-i/--inventory`、`--vault-file`、`--target-group`——`--dir` 只是設定合理預設值，不是唯一用法；混用時明確指定的旗標優先。

`enable-auto` 做兩件事：(1) 用跟 `reconcile --hosts all` 完全一樣、已排除 gateway 主機的展開邏輯,立刻把 `pilot-target-<scope>` 回填成目前狀態；(2) 在 FreeIPA 設一條 automember rule（`ipa automember-add --type=hostgroup` + `ipa automember-add-condition --key=fqdn --inclusive-regex='.*'`),讓**之後**每一台新 enroll 的 `freeipa-client` 主機在 `ipa-client-install` 建立 host 物件的當下就自動被加入該 hostgroup，不需要再手動 reconcile。兩者皆已對 `ag-spike-ipa` 活體驗證：新建一個測試用 host 物件（模擬新 enroll）後,沒呼叫任何 reconcile,它立刻出現在 hostgroup 成員清單裡。

**限制與已知互動（活體驗證時發現）**：
- automember 的條件只在物件「建立當下」評估一次；對已存在的主機不會回溯生效，而且無法在 enroll 當下就知道「這台主機未來會不會變成 gateway」（gateway 元件通常是之後才另外套用的）。所以 automember 本身**無法**單靠 exclusive 條件排除 gateway 主機——這正是 `pilot-access-gateway-apply.yml` Step 3b 防線存在的原因：即使 automember 一時把即將成為 gateway 的主機也掃進去，只要對它套用過一次 pilot-access-gateway，Step 3b 就會把它清出來，兩個機制互補。
- `enable-auto` 的回填部分是以 **pilot inventory** 的 `freeipa-client` group 為準（跟 `reconcile --hosts all` 同一份邏輯），不是查 FreeIPA 當下的即時物件清單。如果之後有主機是繞過 pilot 正常流程、直接用 `ipa host-add`／手動 `ipa-client-install` 建立的（不在 pilot 的 `hosts.yml` 裡），automember 會立刻把它加進 hostgroup，但**下次再跑一次 `enable-auto`** 時，reconcile 部分會因為 inventory 裡找不到這台主機而把它判定為 stale 並移除——已活體重現過這個行為。正常透過 `pilot deploy` 流程 enroll 的主機不會有這個問題（enroll 前主機就已經在 `hosts.yml` 裡）。實務上啟用 `enable-auto` 後，日常新增主機應該不需要再重跑它；真的要重跑（例如手動調整過 scope 的期望清單）前，先確認所有該留著的主機都已經在 inventory 裡。
- `disable-auto` 冪等；`ipa automember-del` 對已經不存在的 rule 回傳 exit code 2（`not found`），已在 `failed_when` 正確處理，不會誤判成失敗。

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | hostgroup | `pilot-target-gpu` hostgroup 存在 | 0 | ipa hostgroup-show pilot-target-gpu |
| C2 | membership | `gpu-a.ipa.pilot.internal` 是 hostgroup 成員 | ~gpu-a.ipa.pilot.internal | ipa hostgroup-show pilot-target-gpu --all |
| C3 | membership | `gpu-b.ipa.pilot.internal` 是 hostgroup 成員 | ~gpu-b.ipa.pilot.internal | ipa hostgroup-show pilot-target-gpu --all |

## 3. 已知限制

- Checklist 目前只驗證「hostgroup 存在 + 兩台真實 fixture 主機在裡面」——不驗證 add/remove 對稱性本身；add/remove/keep 三種路徑的正確性已在
  `docs/evidence/pilot-access-gateway/2026-09-14-phase6-gateway-scope.md` 用一個獨立的、之後會清掉的 `test1` scope 全部實測過，不重複佔用這份長期驗收文件的位置。
- idempotency（第二次 apply `changed=0`）由 `evidenceRequirement.idempotency: required`（contract）+ `pilot vm-target test` 通用驗證，不是這份 checklist 自己的一行。

## 4. Controller-side acceptance

- `all` 只展開 `freeipa-client` group，不受 inventory `all` group 的額外主機影響。
- 展開結果排序穩定，且傳給 playbook 的 `gateway_scope_hosts` 是非空 JSON list。
- 空值與 `all` 混用均拒絕；未解析的 `all` 不得抵達 `gateway-scope-apply.yml`。
- 覆蓋測試：`cmd/pilot/cmd/gateway_scope_test.go`。
