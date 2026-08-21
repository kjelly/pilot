# Runbook — Optional-Host Deployment Availability

> Status: **live-verified**。功能已依 `spec.md`（"Pilot Optional-Host Deployment
> Availability Specification"）Phase 1–7 全部實作並通過 `go test -race ./...`
> （1967 tests, 25 packages）與 Python callback 測試（`make test-callback`,
> 36/36）。在真實 `pilot vm-target` KVM VM 上驗證過兩次（commit 前、commit
> 後各一次），行為一致，見 §2。

> 撰寫日期：2026-08-21 (UTC+8)
> 對齊規範：repo root `spec.md`（Pilot Optional-Host Deployment Availability
> Specification）
> Tested revision：`dfab036`（feat: defer optional-host unavailability
> instead of failing deployment）
> 維護者：pilot

---

## 0. 一句話目標

機器標成 `deployment_availability: optional` 之後，外部人員隨時把它關機都
不會讓 `pilot deploy`／`pilot reconcile` 失敗——它會被排除在這次實際執行的
Ansible 範圍外並回報成「deferred」，其他機器照常套用；`required`（預設值，
沒填就是這個）機器若離線，仍會在套用任何變更**之前**中止並回傳非零結束碼。

## 0.5 事實快照（2026-08-21 這次重新驗證）

```bash
git log --oneline -1
# dfab036 feat: defer optional-host unavailability instead of failing deployment

pilot vm-target list
# avail-req   running  192.168.122.2  1 vcpu  2048 MiB  15 GiB
# avail-opt   running  192.168.122.3  1 vcpu  2048 MiB  15 GiB
```

- 目標：兩台一次性 `pilot vm-target` KVM VM（`ubuntu-24.04` base image），跑
  完即 `pilot vm-target down` 銷毀，不留存。
- inventory（簡表 `hosts.yml` → `pilot inventory generate`）：兩台都掛
  `roles: [docker]`；`avail-opt` 帶 `deployment_availability: optional`，
  `avail-req` 沒填（預設 `required`）。
- vault 依賴：無——`docker-apply.yml` 不吃任何密碼變數，選它純粹是為了讓驗證
  聚焦在「部署可用性」這一層，不被其他角色的前置條件干擾。
- 對齊決定：這是這個功能專屬的最小示範 topology，不掛在既有 runbook 的
  topology 上（走 A：另起一份乾淨、聚焦的 inventory）。
- 驗證跑了兩次，結果一致：一次在 commit `dfab036` 之前（uncommitted 工作
  樹），一次在 commit 之後（乾淨 checkout，`git status --short` 為空）。下面
  §2 的截錄是 commit 後那次的真實輸出。

## 1. 概念

`deployment_availability` 是**部署可用性政策**，不是 VM 電源政策——pilot 不
會、也不負責開機/關機任何機器。它只回答一個問題：「這台機器現在連不上時，
這次部署該不該因此失敗？」

```yaml
hosts:
  ipa-1:
    ansible_host: 10.10.0.10
    roles: [freeipa-server]
    # 沒填 deployment_availability = required（預設，向下相容）

  dev-vm-01:
    ansible_host: 10.10.10.21
    roles: [freeipa-client]
    deployment_availability: optional   # 外部人員隨時開關這台
```

決策表（`internal/delivery.ResolveExecutionScope`，pure、可離線單測）：

| 政策 | 連線探測 | 結果 |
|------|----------|------|
| required（含未填） | 連得到 | 納入執行範圍 |
| required（含未填） | 連不到 | **在套用前中止**，非零結束碼 |
| optional | 連得到 | 納入執行範圍 |
| optional | 連不到 | 排除、回報 deferred，其他機器照常套用，結束碼 0 |
| 無效值（非 required/optional） | 任何 | 在套用前中止，即使那台機器連得到 |

佈署途中才斷線的 `optional` 機器（探測時活著、apply 進行中才斷）只有在 Ansible
透過 `ansible_callback/pilot_result.py` 結構化事件證明「純連線層失敗、零 task
失敗」時才會被視為同一種 deferred；任何真正的 task/驗證/認證失敗，不論該機器
是不是 `optional`，一律還是視為失敗（fail-closed，見 `internal/ansible.
ClassifyDeploymentOutcome`）。

這一層只影響 pilot 管理的部署路徑（`pilot deploy`／`pilot reconcile`，經由
共用的 `executeRecordedDeployment` 漏斗）；直接手動 `ansible-playbook`（不經
pilot）不會自動套用，見 `DELIVERY.md` §1.6。

## 2. 實跑截錄（2026-08-21，commit `dfab036` 之後，全新 VM）

### 情境 A — optional 機器離線，佈署不受影響

```bash
pilot vm-target up --name avail-req --base-image ubuntu-24.04 --memory 2048 --vcpus 1 --disk 15
pilot vm-target up --name avail-opt --base-image ubuntu-24.04 --memory 2048 --vcpus 1 --disk 15
pilot inventory generate --in hosts.yml --out inventory.yml
virsh -c qemu:///system destroy avail-opt   # 模擬外部人員關機
pilot deploy --actions scenario-full.json …   # 單一元件 docker，stage=sandbox
```

真實輸出：

```
═══ Deployment availability ═══
Effective deployment scope: 1 台主機
Deferred:
  ○ avail-opt — deferred（unavailable）
⚠️  component "docker" host "avail-opt" facts unavailable; OS/resource minimums not verified
▶ 套用：ansible-playbook playbooks/apply/docker-apply.yml -i .../inventory.yml --limit avail-req -e stage=sandbox
...
PLAY RECAP
avail-req : ok=5 changed=2 unreachable=0 failed=0 skipped=2 rescued=0 ignored=0
✅ 套用完成。
```

結束碼 `0`。`avail-opt` 完全沒有出現在實際的 ansible 呼叫裡（`--limit` 已排除）。
即時驗證 `avail-req` 真的套用成功：

```bash
pilot vm-target exec --name avail-req -- docker --version
# Docker version 29.1.3
```

### 情境 B — required 機器離線，套用前中止

```bash
virsh -c qemu:///system destroy avail-req   # 現在兩台都離線
pilot deploy --actions scenario-full.json …  # 同一條指令，不變
```

真實輸出：

```
❌ 部署在套用前中止 — 以下必要主機目前無法連線：
  - avail-req
Error: 部署在套用前中止：必要主機無法連線：avail-req
```

結束碼 `1`。整份輸出裡沒有 `▶ 套用` 這一行、沒有 `PLAY RECAP`——apply
playbook 從未被呼叫，也沒有任何評估紀錄（evidence run）被啟動。

清理：`pilot vm-target down --name avail-req` / `avail-opt`；
`pilot vm-target list` 與 `virsh -c qemu:///system list --all` 皆確認為空。

## 3. 已知限制（記錄，暫無修復需求）

- **獨立的「完整前置檢查」提示（`runPreflight`）本身不吃 effective limit**：
  `pilot deploy`/`pilot reconcile` 一開始問的「要先跑前置檢查嗎？」若選
  「完整前置檢查」，它跑的是 `playbooks/preflight.yml` 全機連線 ping，這一步
  發生在使用者還沒選定要部署的範圍/tags/limit 之前，所以無法套用 effective
  limit——一台 optional 且目前離線的機器仍會讓這一步的 ping 失敗，但這一步
  本身是既有的、可跳過的軟性提示（失敗只會問「仍要繼續嗎？」），真正的
  required/optional 強制規則落在後面實際套用的路徑（本 runbook §2 驗證的就是
  這條路徑），不受這個提示影響。
- **冪等性重跑（第二次 apply 斷言 `changed=0`）尚未套用中途斷線的語意重分類**：
  只有主要的 apply 步驟會經過 `ClassifyDeploymentOutcome` 重新分類；冪等性
  檢查若恰好在這次重跑期間遇到 optional 機器離線，目前仍會被視為失敗。
- **evidence run 的 metadata 不會回填「執行途中才被判定 deferred」的主機**：
  §2 情境 A 這種佈署前就已知的 deferred 主機會寫進 evidence metadata；佈署
  「途中」才斷線、被語意重分類為 deferred 的主機目前只透過標準輸出回報，
  不會回頭補寫進同一筆 evidence 紀錄（spec 本身允許這個 v1 範圍取捨）。
- **相鄰但非本功能引入的潛在 bug（未修）**：`probeHostFacts`
  （`cmd/pilot/cmd/deploy_facts.go`）探測一台實際已離線的主機時，曾在一次
  驗證中留下一個孤兒 `ssh`/`ansible` 子行程（`exec.CommandContext` 的逾時只
  會殺掉直接的 `ansible` 子行程，不會殺到它 fork 出來的 `ssh` 孫行程），導致
  外層 wrapper 看起來卡住數分鐘，但 `pilot deploy` 自身早已印出
  `✅ 套用完成` 並正確退出。只重現過一次（疑似跟網路逾時時機有關），不影響
  `pilot deploy` 本身的正確性或結束碼，但這個功能讓「探測一台預期離線的
  optional 機器」變成常態操作而非例外，值得日後找時間修（讓
  `probeHostFacts` 在 context 取消時砍整個 process group）。

## 4. 變更紀錄

| 日期       | 版本 | 變更                                                                          | 變更者 |
|------------|------|-------------------------------------------------------------------------------|--------|
| 2026-08-21 | v1.0 | 初版；Phase 1–7 全部實作完成並在真實 vm-target 上驗證兩次（commit 前/後），行為一致；記錄 3 個已知限制 + 1 個相鄰但未修的 bug | pilot |
