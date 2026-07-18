# M0.2 Per-host Verify Spike

> 狀態：production runner contract finalized；callback data contract + expected-host
> pure resolver 已驗證，正式 runner 待實作
> 日期：2026-07-18
> 環境：ansible-core 2.19.2、ansible package 12.0.0
>
> **實作標示：這是可測試的 spike，不是 production per-host verify。**
> 已實作 decoder／fixtures／tests 與 expected-host pure resolver／truth table；
> 尚未實作 Ansible inventory/scope adapter、正式 runner 接線與 delivery
> evidence persistence；本版已定案 per-host isolated invocation timeout。

## 1. 結論

正式 per-host evidence 使用：

```text
ANSIBLE_LOAD_CALLBACK_PLUGINS=1
ANSIBLE_STDOUT_CALLBACK=ansible.posix.json
```

不使用 Ansible one-line output 作正式 evidence。JSON callback 必須是完整、可解析的
document；truncated／沒有 JSON 的 invocation 視為 `runner_error`。

Status contract：

| status | 判定 |
|---|---|
| `ok` | 完整 callback 有 host，沒有 failed/unreachable，rc=0 |
| `timeout` | callback 或未來 per-host runner 明確回報該 host task timeout |
| `unreachable` | host payload `unreachable: true` |
| `module_error` | `failed: true` 或 rc 非零 |
| `runner_error` | invocation 啟動失敗、controller timeout、JSON 缺失／truncated |
| `missing` | callback 完整，但 expected host 沒出現在 document |

Production runner 不再讓多台 host 共用同一個 timeout process。每個
host × row 使用獨立 Ansible invocation，並以 bounded worker pool 執行；因此
該 process 的 `CommandContext` timeout 可歸因到唯一 host，記 `timeout`。啟動失敗、
callback 缺失／truncated 仍記該 host 的 `runner_error`。

## 2. Actual-run evidence

### 2.1 Callback preflight

```text
ansible [core 2.19.2]
ansible python module location = .../ansible/12.0.0/...
```

### 2.2 多行 stdout／stderr 成功

執行 localhost shell probe 後，真實 callback host payload：

```json
{
  "localhost": {
    "changed": true,
    "rc": 0,
    "stderr": "warn",
    "stdout": "line1\nline2"
  }
}
```

確認 JSON 保留 stdout 多行內容，stdout／stderr／rc 可分開取得。

### 2.3 Module error

probe `exit 7` 的真實 payload：

```json
{
  "localhost": {
    "failed": true,
    "msg": "non-zero return code",
    "rc": 7,
    "stderr": "bad-err",
    "stdout": "bad-out"
  }
}
```

Ansible process exit code為 2，但 host 的 module rc 是 7；per-host evidence 必須保存
host rc，不得只保存 controller process exit code。

### 2.4 Unreachable

對 TEST-NET `192.0.2.1` 的真實 payload：

```json
{
  "missing": {
    "changed": false,
    "msg": "Task failed: Failed to connect to the host via ssh: ... Connection timed out",
    "unreachable": true
  }
}
```

此形態沒有 rc/stdout/stderr；status 必須由 `unreachable: true` 判定，exit code
保存為 unknown sentinel。

### 2.5 Controller timeout

以 1 秒 controller timeout 中斷 `sleep 5`：

```text
[ERROR]: A worker was found in a dead state
```

process exit code是 124，沒有 JSON document。因此不能從 observed payload證明任何
host-level timeout，歸類為 invocation `runner_error`。

## 3. Decoder spike

已加入：

- `internal/tools/ansible_callback_spike.go`
- `internal/tools/ansible_callback_spike_test.go`
- `internal/tools/testdata/ansible-callback/*.json`

鎖定：

- 成功／module error／unreachable 欄位形狀；
- 完整 callback 中缺 host → `missing`；
- observed − expected → fail closed；
- truncated JSON → decoder error，再轉 `runner_error`；
- CRLF normalization 與只移除一個 trailing newline。

這份 decoder 刻意尚未接到 `runAnsibleAdHoc`。expected-host 的純集合 resolver
與 truth table 已完成；正式接線前仍需把 Ansible inventory、host pattern、
`--limit`、stage/component selection 解析成 resolver input。

## 4. Expected-host resolver contract

權威順序：

1. 實際 inventory 定義可存在的 host universe。
2. CLI host pattern、`--limit`、stage/component selection 定義本次 execution scope。
3. spec Targets 是 acceptance constraint／lint source，不得創造 inventory 中沒有
   的 host，也不直接與 execution scope 做會破壞 override 的機械交集。
4. 單 host + `target_group` 型 spec 明確允許 CLI override 把 spec role 對齊到
   inventory 的 `all`／其他實際 group。

Standalone default：

- 有 spec Targets 且未提供 execution selector → 以解析後的 spec target hosts
  作 expected scope，不先展開成整份 inventory。
- 沒有 spec Targets → 必須明確提供 `--host`／`--limit`，或使用 `--local`；
  不再默認遠端 `all`。
- deploy transaction → component planner 必須提供 resolved component scope，
  不使用 standalone default。

集合結果：

- expected 空集合 → FAIL；
- expected − observed → 每台一筆 `missing`；
- observed − expected → runner contract error；
- inventory 不存在 spec role，但有合法 `target_group` override → 使用 override
  scope 並產生 trace finding；
- inventory 不存在 spec role且無 override → FAIL；
- pattern／limit 指向零 host → FAIL。

已加入：

- `internal/tools/expected_hosts.go`
- `internal/tools/expected_hosts_test.go`

table-driven tests 鎖定：

- inventory universe 去重、排序且為唯一 host 事實；
- host pattern／`--limit`／stage/component selection 逐層取交集；
- selector 空集合、未知 inventory host、交集為空皆 fail closed；
- 沒有 override 時，execution scope 不得超出 spec target；
- 明確 `target_group` override 可處理 AGENTS.md 的單 host 例外，但必須產生
  trace finding，且仍不得選到零 host。

pure resolver 不自行執行或解析 `ansible-inventory`；正式接線前要由 adapter
提供已對實際 inventory 解析完成的各個 host set。

Adapter 的權威來源固定為 Ansible 自己的 inventory/pattern resolver，支援 static
inventory、dynamic inventory 與 inventory plugin；Go adapter 不自行重寫 Ansible
pattern grammar。adapter 回傳 canonical sorted host names、來源與 finding，再交
pure resolver。

## 5. Production runner 決策

1. 每個 row 先解析一次 expected hosts。
2. 以最多 8 個 worker（可設定但有上限）逐 host 執行單-host Ansible invocation。
3. 每個 invocation 啟用 `ansible.posix.json` callback；callback observed set
   必須恰為該 host。
4. per-host timeout 只終止該 host invocation，不取消其他已完成 host。
5. outer context cancel 才取消整列所有 workers；已完成結果保留，未完成 host
   記 `runner_error` + `parent_cancelled`，整列 FAIL。
6. 結果依 canonical host name 排序後才聚合與 persist，避免 concurrency 造成
   report/evidence 非 deterministic。
7. 一台 FAIL 不 short-circuit 其他 host；必須收齊可取得 evidence。

## 6. Production implementation 開工狀態

- scope adapter、single-host runner、bounded worker pool 與正式 decoder 接線可
  立即開始 production implementation。
- delivery evidence 依 Final Evidence RFC 接續實作。
- M2.1 仍在 M0.2 runner 合併後開始，避免同時重寫 verifier core。

本文件的 design gate 已關閉；未實作項是 implementation backlog，不再是
architecture blocker。
