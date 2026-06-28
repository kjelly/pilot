# Ansible Callback: pilot

Sends Ansible task failures to `pilot` (a Go binary that calls Ollama) for AI-powered root-cause analysis. The diagnosis is printed inline in the playbook output.

## What it does

When a task fails during an `ansible-playbook` run:

1. The callback collects context: host, task name, module, error output, task YAML, play name.
2. It calls `pilot diagnose --stdin` with that context as JSON on stdin.
3. `pilot` sanitises the input (redacts passwords, keys, IPs, etc.), forwards it to Ollama, and prints the LLM's diagnosis.
4. The callback displays the diagnosis inline under a "🤖 pilot 診斷" banner.

## What it does NOT do

- It does **not** change playbook behaviour. Failures still fail; this just adds analysis.
- It does **not** retry failed tasks.
- It does **not** run any shell commands of its own (besides the pilot binary).
- It does **not** send data to the cloud unless your Ollama model is a `:cloud` model. Local models keep everything on your network.
- It is **no-op** if the `pilot` binary cannot be found (prints one warning, then continues).

## Install

### Per user (recommended for personal use)

```bash
cd /path/to/pilot
make install-callback-user
```

This installs to `~/.ansible/plugins/callback/pilot_diagnose.py`.

### System-wide

```bash
sudo make install-callback-system
```

This installs to `/etc/ansible/plugins/callback/pilot_diagnose.py`.

### Manual

```bash
mkdir -p ~/.ansible/plugins/callback
cp ansible_callback/pilot_diagnose.py ~/.ansible/plugins/callback/
```

## Enable

### In `ansible.cfg`

```ini
[defaults]
callbacks_enabled = pilot
```

### Per-run via env

```bash
ANSIBLE_CALLBACKS_ENABLED=pilot ansible-playbook site.yml
```

## Configuration

Precedence: **environment variable > `ansible.cfg` > default**.

| Option | Env var | Default | Description |
|--------|---------|---------|-------------|
| `binary` | `PILOT_BIN` | `/usr/local/bin/pilot` | Path to pilot binary |
| `model` | `PILOT_MODEL` | `qwen3.5:cloud` | Ollama model name |
| `timeout` | `PILOT_TIMEOUT` | `60` | Subprocess timeout (seconds) |
| `diagnose_unreachable` | — | `false` | Also diagnose `unreachable` hosts |
| `disable` | `PILOT_DISABLE` | `false` | Disable the plugin (no-op) |
| `extra_context` | — | `{}` | Dict of extra fields to include in the prompt |

### Examples

```ini
# ansible.cfg
[defaults]
callbacks_enabled = pilot

[callback_pilot]
model = qwen2.5:7b
timeout = 90
extra_context = { env: staging, owner: "@sre-team" }
```

```bash
# Override via env
PILOT_MODEL=qwen2.5:3b PILOT_TIMEOUT=120 ansible-playbook site.yml

# Disable for one run
PILOT_DISABLE=1 ansible-playbook site.yml
```

## Example output

```
TASK [CIS 5.2.1 : Disable SSH root login] ***************************
fatal: [web03]: FAILED! => {"changed": false, "msg": "Failed to ..."}

══════════════════════════════════════════════════════════════════════
🤖 pilot 診斷 (web03 / failed)
──────────────────────────────────────────────────────────────────────
1. 失敗的根本原因：web03 上的 sudoers 配置缺少 audit plugin 目錄...

2. 建議的修復步驟：
   - 在 web03 上建立 /var/db/sudo 目錄
   - ...

3. 對應 CIS Benchmark：5.2.1
══════════════════════════════════════════════════════════════════════

PLAY RECAP *************************************************************
web01                       : ok=2    changed=1    failed=0
web02                       : ok=2    changed=1    failed=0
web03                       : ok=1    changed=0    failed=1
```

## Per-host deduplication

The plugin only diagnoses the **first failure per host per playbook run**. After web03 fails once, subsequent web03 failures in the same run are not sent to the LLM. This avoids the AI being spammed when one root cause cascades into many tasks.

The dedup state resets at the start of each new `ansible-playbook` invocation via the `v2_playbook_on_stats` hook.

## Security

- `pilot` sanitises every JSON field before sending to the LLM: passwords, API keys, private keys, `/etc/shadow` entries, IPv4 addresses, and email addresses are redacted by default.
- The plugin itself does not read arbitrary host files; it only uses fields that Ansible already has in its `result._result` dict.
- The 60-second default timeout prevents a hung Ollama from stalling the playbook indefinitely.
- If `pilot` is missing or returns non-zero, the plugin logs a warning and continues — it never blocks the playbook.

## Testing

```bash
# From the pilot repo root
make test-callback
```

This runs the pure-Python unit tests (no Ansible or Ollama required). They cover binary resolution, option coercion, per-host dedup, subprocess argument shape, and graceful degradation on errors.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| No diagnosis in output | Callback not enabled | Check `callbacks_enabled` or `ANSIBLE_CALLBACKS_ENABLED` |
| `[pilot] binary not found` | pilot not on PATH | `which pilot`; set `PILOT_BIN` |
| `[pilot] timed out` | Ollama is slow or unreachable | Increase `PILOT_TIMEOUT`; check ollama server |
| `[pilot] exited 1: ...ollama returned 429...` | Cloud model rate-limited | Use a local model (`qwen2.5:7b`) or wait |
| Same diagnosis repeated for many tasks | Per-host dedup not kicking in (different hosts) | Expected; this is a per-host dedup |

## Uninstall

```bash
make uninstall-callback
```
