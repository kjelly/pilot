# M0.2 Per-host Verify Spike

> 狀態：callback data contract 已驗證；尚未接入正式 verify
> 日期：2026-07-18
> 環境：ansible-core 2.19.2、ansible package 12.0.0

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

Controller `CommandContext` timeout 殺掉整個 Ansible process，不等於每台 host 都
timeout。若 callback 不完整，所有 expected hosts 記 `runner_error`，message 保存
`invocation_timeout`；`timeout` 保留給可證明的 host-level timeout。

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

這份 decoder 刻意尚未接到 `runAnsibleAdHoc`。正式接線前仍需完成 expected-host
resolver truth table。

## 4. Expected-host resolver contract

權威順序：

1. 實際 inventory 定義可存在的 host universe。
2. CLI host pattern、`--limit`、stage/component selection 定義本次 execution scope。
3. spec Targets 是 acceptance constraint／lint source，不得創造 inventory 中沒有
   的 host，也不直接與 execution scope 做會破壞 override 的機械交集。
4. 單 host + `target_group` 型 spec 明確允許 CLI override 把 spec role 對齊到
   inventory 的 `all`／其他實際 group。

集合結果：

- expected 空集合 → FAIL；
- expected − observed → 每台一筆 `missing`；
- observed − expected → runner contract error；
- inventory 不存在 spec role，但有合法 `target_group` override → 使用 override
  scope並產生 trace finding；
- inventory 不存在 spec role且無 override → FAIL；
- pattern／limit 指向零 host → FAIL。

正式實作應把上述案例寫成 table-driven resolver tests，再替換現行
`runAnsibleAdHoc`。

## 5. 尚未解鎖

- 尚未把 decoder 接入正式 verify。
- 尚未選擇真正 per-host timeout 的執行機制。
- 尚未寫 delivery evidence。
- 尚未讓 M2.1 typed matcher 開工。

上述工作等待 resolver tests 與 M0.2 完整實作切片，不在本 spike 偷跑。
