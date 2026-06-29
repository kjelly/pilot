# Verification Spec — hello-localhost (smoke test)

> 版本：v1.0
> 對齊規範：pilot 內部 smoke test 規範（localhost 環境健康探針）
> 維護者：pilot

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Hostname / Inventory group | localhost |
| OS | Ubuntu 24.04 LTS |
| 角色 | pilot agent 端對端 smoke test |
| 套用範圍 | pilot 開發機 / 任何用 `pilot run` 驗證的環境 |
| 風險等級 | Low |

## 2. Checklist

| ID  | Category | Check                                       | Expected                          | Command |
|-----|----------|---------------------------------------------|-----------------------------------|---------|
| C1  | file     | `/etc/os-release` present                   | present                           | test -f /etc/os-release |
| C2  | sysload  | 1-minute load average < 20.0                | `OK`                              | awk '{if ($1+0 < 20.0) print "OK"; else print "FAIL:" $1}' /proc/loadavg |
| C3  | kernel   | kernel version probeable via `uname -r`     | `^\d+\.\d+`                     | uname -r |

> C2 的 expected value 為 `OK`：command 已內含 `< 20.0` 判斷；stdout 印 `OK` 或 `FAIL:<val>`。
> 嚴格數值比較見 `scripts/verify-hello-localhost.sh`（用 `bc -l` 與 `20.0` 比較）。
>
> C2 的 expected value 為 `OK`：command 已內含 `< 20.0` 判斷；stdout 印 `OK` 或 `FAIL:<val>`。
>
> C3 的 expected value 為正則 `^\d+\.\d+`：kernel 版本若**不匹配**此 pattern 就 fail。

## 3. 證據收集

- 腳本：`scripts/verify-hello-localhost.sh`
- 輸出格式：NDJSON（每行一個 `{id, status, detail}` object）
- 預期 row 數：3（C1, C2, C3）
- 範例輸出：

```json
{"id":"C1","status":"pass","detail":"/etc/os-release is present and readable"}
{"id":"C2","status":"pass","detail":"Load average OK: 0.42 (threshold 20.0)"}
{"id":"C3","status":"pass","detail":"Kernel version probed: 6.8.0-..."}
```

## 4. PASS / FAIL 規則

- 全部 `C1` `C2` `C3` `status=pass` 或 `status=skip`（且 skip 有正當理由）→ **PASS**
- 任一 row `status=fail` → **FAIL**，報告列出 fail 的 id + actual + want

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C2 | CI runner 瞬間尖峰可能讓 loadavg > 20 | CI shared runner | 無（建議直接 fail → 警示環境問題）|

## 6. Playbook 對齊

對應的 playbook：`playbooks/hello-localhost.yaml`

| Spec ID | Playbook task |
|---------|---------------|
| C0      | `1) Greeting` — greeting / smoke intro（不列入 verify）|
| C3-pre  | `2) Show kernel` — 收集 `kernel_out.stdout` |
| C2-pre  | `2b) Show load average` — 收集 `load.stdout` |
| C3-print| `2c) Print kernel and load` |
| C1-pre  | `3) Read probe files` — slurp `/etc/os-release` 內容（印證 C1 讀得到）|
| C1      | `4a) Assert /etc/os-release is readable` |
| C2      | `4b) Assert load average < 20.0` |

## 7. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-06-29 | v1.0 | 初版（從 `scripts/verify-hello-localhost.sh` 反向建立 spec + 對齊 playbook task name）| pilot |
