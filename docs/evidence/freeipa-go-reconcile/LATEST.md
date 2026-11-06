# FreeIPA Go reconcile 最新驗收

目前狀態：**PASS**（2026-11-05，candidate `4f469406e578228b3d132270f7852dae9a6f8f7d`，tree `1e096225fbe631a96d9792c4d60ef5aebdb0f27c`）。

- 範圍：Phase 1 唯讀預覽 `pilot reconcile --component freeipa-identity --preview-only --engine golang`。
- Target：拋棄式 `vm-target` VM `pwfix-ipa`（FreeIPA 4.13.4，API 2.257），單一 `freeipa-server` 主機。
- 結果：§10.3 driver 8/8 PASS，每次預覽 0 個寫入；28 個失敗路徑 arm、30 次執行（vault 密碼來源卡住時的 `--timeout`、Ctrl-C、SIGTERM、終端機斷線、ProxyJump、伺服器凍結時的登出與登入、blocked plan、非 admins 讀取者、登入被拒）全部依規格結束，L3 依已知限制 3 結束；秘密 0 筆。

候選、實測數據、失敗路徑與限制見 [PR #255 驗收紀錄](pr-255.md)。
