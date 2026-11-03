# Go CI 分片最新驗收

目前狀態：**驗收通過**（2026-11-03 UTC）。正式配置 spec 2 + cmd 2 + rest 1；
完整/分片對照、實際失敗閘門，以及 filter alias 修補後的完整 CI 均完成。

最新 candidate：`d57f88511ea01e82bfd670cbe6dd7d19b879077c`；tested merge：
`6b577382fafcdda1c801b74d8be988633c4130e6`；tree：
`5f56db50063fbe2a1f9608f24b9bc4aa0edc3413`。
五個 Go shards 共 11,153 pass、77 合法 skip、0 fail（含 subtests），
所有 validations、image build 與完整 candidate receipt 成功。

原始導入的單次 workflow 比較為 39:40 → 25:10（36.55%），runner 分鐘增加
6.15%；這是歷史量測，不是新候選的效能結論。

候選、實測數據與限制見 [PR #231 驗收紀錄](pr-231.md)。
