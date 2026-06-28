#!/usr/bin/env bash
# Demo the RAG (search-docs) workflow.
# Requires: ollama running, ansible-core installed, an embedding model pulled.
set -euo pipefail

cd "$(dirname "$0")/.."

BIN=./pilot
DEMO_MODEL="${DEMO_MODEL:-qwen2.5:3b}"
EMBED_MODEL="${EMBED_MODEL:-qwen3-embedding:4b}"
DATA_DIR="${DATA_DIR:-$HOME/.local/share/pilot}"

echo "=== 1. Index Ansible module documentation ==="
echo "    (uses 'ansible-doc --metadata-dump' + Ollama embeddings)"
echo "    First run: 5-15 min on CPU. Subsequent runs: skip if version unchanged."
echo
$BIN index-docs --embedding-model "$EMBED_MODEL" --quiet 2>&1 || {
  echo "(index-docs may have failed if no network; using a mock index for the demo)"
}
echo

echo "=== 2. Show the saved index ==="
ls -la "$DATA_DIR"/docs-index.* 2>&1
echo

echo "=== 3. Query from the command line ==="
$BIN search-docs "disable root SSH login" --k 3 --source modules 2>&1 | head -30
echo

echo "=== 4. Index a directory of playbooks ==="
mkdir -p /tmp/harden-playbooks
cat > /tmp/harden-playbooks/ssh.yml <<'EOF'
- name: Harden SSH
  hosts: all
  become: true
  tasks:
    - name: Disable root SSH login
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^PermitRootLogin'
        line: 'PermitRootLogin no'
EOF
$BIN index-playbooks /tmp/harden-playbooks --quiet 2>&1
echo

echo "=== 5. Search across modules + playbooks ==="
$BIN search-docs "ssh root login" --k 3 --source all 2>&1 | head -30
echo

echo "=== 6. Run agent; the LLM can call search_docs automatically ==="
$BIN run /tmp/harden-playbooks/ssh.yml --skip-syntax-check --dry-run-all \
    --no-tui --model "$DEMO_MODEL" --no-index 2>&1 | head -20
echo

rm -rf /tmp/harden-playbooks
echo "Demo complete."
