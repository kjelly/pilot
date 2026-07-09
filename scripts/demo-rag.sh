#!/usr/bin/env bash
# Demo the RAG (search-docs) workflow.
# Requires: ollama running, ansible-core installed. No embedding model
# needed — the docs index is bleve (BM25) only.
set -euo pipefail

cd "$(dirname "$0")/.."

BIN=./pilot
DEMO_MODEL="${DEMO_MODEL:-qwen2.5:3b}"
DATA_DIR="${DATA_DIR:-$HOME/.local/share/pilot}"

echo "=== 1. Index Ansible module documentation ==="
echo "    (uses 'ansible-doc --metadata-dump'; bleve BM25, no embeddings)"
echo "    First run: 30-90 sec. Subsequent runs: skip if version unchanged."
echo
$BIN index-docs --quiet 2>&1 || {
  echo "(index-docs may have failed if no network; using a mock index for the demo)"
}
echo

echo "=== 2. Show the saved index ==="
ls -la "$DATA_DIR"/docs.bleve "$DATA_DIR"/docs-index.meta 2>&1
echo

echo "=== 3. Query from the command line ==="
$BIN search-docs "disable root SSH login" --k 3 2>&1 | head -30
echo

echo "=== 4. Run agent; the LLM can call search_docs automatically ==="
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
$BIN run /tmp/harden-playbooks/ssh.yml --skip-syntax-check --dry-run-all \
    --model "$DEMO_MODEL" --no-index 2>&1 | head -20
echo

rm -rf /tmp/harden-playbooks
echo "Demo complete."
