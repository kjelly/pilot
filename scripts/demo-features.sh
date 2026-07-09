#!/usr/bin/env bash
# pilot end-to-end demo for new features:
#  --from-stdin, --discover, --dry-run-all, --skip-syntax-check
#
# Run from the repo root after `make build`.
set -euo pipefail

cd "$(dirname "$0")/.."

BIN=./pilot
DEMO_MODEL="${DEMO_MODEL:-qwen2.5:3b}"

mkdir -p /tmp/harden-demo
cat > /tmp/harden-demo/ssh.yml <<'EOF'
- hosts: localhost
  tasks:
    - name: Ensure root SSH login is disabled
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^PermitRootLogin'
        line: 'PermitRootLogin no'
EOF
cat > /tmp/harden-demo/sudo.yml <<'EOF'
- hosts: localhost
  tasks:
    - name: Ensure auditd is running
      ansible.builtin.service:
        name: auditd
        state: started
        enabled: true
EOF

echo "=== 1. Single playbook (existing) ==="
$BIN run /tmp/harden-demo/ssh.yml --skip-syntax-check --dry-run-all --model "$DEMO_MODEL" 2>&1 | head -3

echo ""
echo "=== 2. --discover directory ==="
$BIN run --discover /tmp/harden-demo --skip-syntax-check --dry-run-all --model "$DEMO_MODEL" 2>&1 | head -5

echo ""
echo "=== 3. --from-stdin (plain paths) ==="
ls /tmp/harden-demo/*.yml | $BIN run --from-stdin --skip-syntax-check --dry-run-all --model "$DEMO_MODEL" 2>&1 | head -5

echo ""
echo "=== 4. --from-stdin (JSON Lines) ==="
( echo '{"playbook":"/tmp/harden-demo/ssh.yml","limit":"webservers"}'
  echo '{"playbook":"/tmp/harden-demo/sudo.yml"}'
) | $BIN run --from-stdin --skip-syntax-check --dry-run-all --model "$DEMO_MODEL" 2>&1 | head -5

echo ""
echo "=== 5. --discover glob pattern ==="
$BIN run --discover '/tmp/harden-demo/*.yml' --skip-syntax-check --dry-run-all --model "$DEMO_MODEL" 2>&1 | head -3

echo ""
echo "=== 6. Mutual exclusion: positional + --from-stdin (should error) ==="
$BIN run /tmp/harden-demo/ssh.yml --from-stdin 2>&1 | head -3 || true

echo ""
echo "=== 7. Syntax-check pre-flight (broken playbook) ==="
echo 'this is not: [valid' > /tmp/harden-demo/bad.yml
$BIN run --discover /tmp/harden-demo --dry-run-all --model "$DEMO_MODEL" 2>&1 | head -8

echo ""
echo "=== 8. --skip-syntax-check + broken playbook (LLM sees the error) ==="
$BIN run /tmp/harden-demo/bad.yml --skip-syntax-check --dry-run-all --model "$DEMO_MODEL" 2>&1 | head -3

rm -rf /tmp/harden-demo
echo ""
echo "Demo complete."
