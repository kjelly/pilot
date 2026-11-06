# FreeIPA Go reconcile 最新驗收

## Phase 2 P2-2：freeipa-identity 取鎖閘門（PR #284）

目前狀態：**PASS**。驗收日期 2026-11-06，candidate `91f82abbc5dacd1a746aabde7f5000bd0094607c`，tree `dfb5135d421fcc92e2a35014573baa701c55cc6b`。

- **範圍**：所有會執行 `playbooks/apply/freeipa-identity-apply.yml` 的入口都要先取得 FreeIPA server 的 `/etc/ipa` 鎖，並在執行任何 ansible-playbook 之前，拒絕鎖取不到的 inventory。入口包括：
  - deploy 與 reconcile
  - `pilot access reconcile`
  - break-glass（CLI、TUI、`pilot edit --actions`）
  - drift 修復
  - `pilot host decommission`
- **Target**：兩台拋棄式 `vm-target` VM：一台 FreeIPA 4.13.4 server，一台 enrolled client。
- **結果**：34 筆 arm 紀錄（33 PASS；L7 依規格只做記錄），L11 A、B 兩段 PASS，秘密 0 筆。逐項如下：
  - **持鎖執行**：L1–L3d，含 staging、`--limit`、vm-target 形態的 hostvars、drift 修復。
  - **等待與忙碌**：L5a–L5c、L9、L9l。
  - **掉鎖與中斷**：L6、L6k、L7、L8。
  - **取鎖前拒絕**：L10，涵蓋 6 種 inventory 形態與每個入口。
  - **decommission 先取鎖再動作**：L4、L11，含等鎖時中斷、掉鎖後 resume。

候選、實測數據、失敗路徑與限制見 [PR #284 驗收紀錄](pr-284.md)。

## Phase 1：唯讀預覽（PR #255）

目前狀態：**PASS**。驗收日期 2026-11-05，candidate `4f469406e578228b3d132270f7852dae9a6f8f7d`，tree `1e096225fbe631a96d9792c4d60ef5aebdb0f27c`。

- **範圍**：Phase 1 唯讀預覽 `pilot reconcile --component freeipa-identity --preview-only --engine golang`。
- **Target**：拋棄式 `vm-target` VM（FreeIPA 4.13.4，API 2.257），單一 `freeipa-server` 主機。
- **結果**：
  - §10.3 driver 8/8 PASS，每次預覽 0 個寫入。
  - 28 個失敗路徑 arm、共 30 次執行，全部依規格結束；L3 依已知限制 3 結束。涵蓋 vault 密碼來源卡住時的 `--timeout`、Ctrl-C、SIGTERM、終端機斷線、ProxyJump、伺服器凍結時的登出與登入、blocked plan、非 admins 讀取者、登入被拒。
  - 秘密 0 筆。

候選、實測數據、失敗路徑與限制見 [PR #255 驗收紀錄](pr-255.md)。
