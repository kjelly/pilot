# Verification Spec — Pilot Gateway Scope Publication

> 版本：DRAFT v0.1（vm-target 已實測；尚未正式站台驗收）
> 對齊規範：docs/tmp/now/spec.md §9.6/§57（Phase 6 — Gateway scope publication）
> 維護者：sre

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
| `gateway_scope_hosts` | 該 scope 目標主機 FQDN 清單，需以 `-e '{"gateway_scope_hosts": [...]}'` 的 JSON 物件形式傳入（`-e gateway_scope_hosts=[...]` 這種寫法會被 Ansible 當成純字串，不會被解析成 list） | 是 |
| `ipa_admin_password` | kinit admin 用；只能來自 vault (`-e @~/.vault/main.yaml`) | 是 |
| `gateway_scope_plan_only` | `true` 時只讀 diff、不寫入（對應 `pilot gateway-scope plan`）；預設 `false`（對應 `reconcile`） | 否 |

此驗收文件記錄的具體情境：`gateway_scope=gpu`，`gateway_scope_hosts=["gpu-a.ipa.pilot.internal","gpu-b.ipa.pilot.internal"]`（與 pilot-access-gateway Phase 0-5 evidence 使用的同一組真實 FreeIPA fixture 一致）。

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | hostgroup | `pilot-target-gpu` hostgroup 存在 | 0 | ipa hostgroup-show pilot-target-gpu |
| C2 | membership | `gpu-a.ipa.pilot.internal` 是 hostgroup 成員 | 0 | ipa hostgroup-show pilot-target-gpu --all \| grep -q gpu-a.ipa.pilot.internal |
| C3 | membership | `gpu-b.ipa.pilot.internal` 是 hostgroup 成員 | 0 | ipa hostgroup-show pilot-target-gpu --all \| grep -q gpu-b.ipa.pilot.internal |

## 3. 已知限制

- Checklist 目前只驗證「hostgroup 存在 + 兩台真實 fixture 主機在裡面」——不驗證 add/remove 對稱性本身；add/remove/keep 三種路徑的正確性已在
  `docs/evidence/pilot-access-gateway/2026-09-14-phase6-gateway-scope.md` 用一個獨立的、之後會清掉的 `test1` scope 全部實測過，不重複佔用這份長期驗收文件的位置。
- idempotency（第二次 apply `changed=0`）由 `evidenceRequirement.idempotency: required`（contract）+ `pilot vm-target test` 通用驗證，不是這份 checklist 自己的一行。
