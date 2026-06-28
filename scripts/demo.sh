#!/usr/bin/env bash
# pilot demo — exercises every code path with no side effects on real hosts.
# Requires: ollama running locally with at least one model pulled.
set -euo pipefail

cd "$(dirname "$0")/.."

# Pick a model. Override with: DEMO_MODEL=qwen2.5:7b ./scripts/demo.sh
DEMO_MODEL="${DEMO_MODEL:-qwen2.5:3b}"
echo "Using model: $DEMO_MODEL"
echo

echo "=== 1. List available models ==="
./pilot models
echo

echo "=== 2. Run sanitizer unit tests ==="
go test ./internal/sanitizer/...
echo

echo "=== 3. Run tool registry unit tests ==="
go test ./internal/tools/...
echo

echo "=== 4. Diagnose a fake Ansible failure log ==="
./pilot diagnose examples/fake-ansible-failure.log --model "$DEMO_MODEL" --stream=false
echo

echo "=== 5. Show generated proposal directory structure (after a real run) ==="
ls -la ~/.local/share/pilot/ 2>/dev/null || echo "(no data yet — run 'pilot run' first)"
echo

echo "Demo complete. To do a real run:"
echo "  ./pilot run examples/disable-root-ssh.yml"
echo "  ./pilot chat"
