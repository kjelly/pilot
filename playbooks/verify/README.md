# ⚠️ 已棄用（2026-07-17）— 不要再產生、更新或執行本目錄的 playbook

本目錄的 `*.yml` 是舊工作流用 `pilot spec --generate` 從
`docs/verification/*.md` 產出的「驗證 playbook」。**2026-07-17 起整個目錄棄用**，
檔案僅保留供歷史參考。驗收一律直接跑真正的驗證引擎：

```bash
go run ./cmd/pilot verify docs/verification/<name>.md -i <inventory> -l <host>
# 或包在 vm-target 裡：
go run ./cmd/pilot vm-target verify --name <vm> docs/verification/<name>.md
```

單列迭代調參用 `pilot verify --probe '<command>' --probe-expected '<expected>'`，
不再需要 `--tags Cx` 跑 generated playbook。

## 為什麼棄用

這批 generator 產物名為 verify、實際上做不到「驗證佈署是否成功」：

1. **不比對 Expected**：raw-fallback task 只看 rc，`~contains` / `^regex` /
   字串相等的期望值全被丟掉——沒佈署成功也可能全綠（假 PASS）。
2. **部分 pattern 是 mutate 語意**：`sysctl` 會寫值、`systemd` 會
   start+enable、`apt` 會裝套件——「驗證」跑下去會順手改掉被驗證的狀態。
3. **複合命令解析會壞**：`systemctl is-active docker 2>&1 | head -n1`
   之類的列會被翻成壞掉的 unit 名，佈署成功也報紅（假 FAIL）。
4. **committed 產物是 drift 溫床**：2026-07-16 曾發現 dedup bug 讓 9 份
   committed 檔案長期只剩 1–2 個真 task 而無人察覺。

`pilot verify` 沒有以上任何問題：直接讀 spec、逐列以 ansible ad-hoc 執行、
完整比對 Expected、純唯讀、落 `.verification/` 報告與 SQLite checkpoint。

## 防護

`pilot spec --generate` 已拒絕輸出到 `playbooks/verify/`（見
`cmd/pilot/cmd/spec.go`）。臨時需要 generated playbook（例如給
`pilot spec --apply` 用）時，輸出到 gitignored 的 `playbooks/generated/`
（`--generate` 不帶路徑時的預設位置）。
