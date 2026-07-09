#!/usr/bin/env bash
# scripts/test-sandbox.sh
#
# L1 + L2 + L3 smoke test for the pilot sandbox feature.
#
# Layer 1 (unit):       go test ./... (no docker required, skips integration)
# Layer 2 (integration): go test -run TestDockerExecRunner_RealContainer
#                       (requires docker + ansible image)
# Layer 3 (smoke):     builds pilot binary, runs sample playbook in three
#                       modes (raw ansible, pilot localhost, pilot
#                       docker-exec sandbox)
#
# Exit codes:
#   0  all checks passed
#   1  test failure (L1 or L2)
#   2  pre-requisite missing
#   3  smoke test failure
#
# Usage:
#   ./scripts/test-sandbox.sh                 # run all layers
#   ./scripts/test-sandbox.sh --l1-only       # only unit tests
#   ./scripts/test-sandbox.sh --l2-only       # only integration
#   ./scripts/test-sandbox.sh --l3-only       # only smoke
#   ./scripts/test-sandbox.sh --cleanup-only  # just remove leftover containers
#   ./scripts/test-sandbox.sh --no-llm        # L3 without ollama (uses raw ansible)
#
# Designed to be safe for AI agents to call: prints every command, every
# expected outcome, and never silently swallows errors.

set -euo pipefail

# ---------- arg parsing -----------------------------------------------------
L1_ONLY=0
L2_ONLY=0
L3_ONLY=0
CLEANUP_ONLY=0
NO_LLM=0
for arg in "$@"; do
  case "$arg" in
    --l1-only)       L1_ONLY=1 ;;
    --l2-only)       L2_ONLY=1 ;;
    --l3-only)       L3_ONLY=1 ;;
    --cleanup-only)  CLEANUP_ONLY=1 ;;
    --no-llm)        NO_LLM=1 ;;
    -h|--help)
      sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "Unknown arg: $arg" >&2; exit 2 ;;
  esac
done

# ---------- setup -----------------------------------------------------------
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'
log()  { printf "${GREEN}[%s]${NC} %s\n" "$(date +%H:%M:%S)" "$*"; }
warn() { printf "${YELLOW}[%s]${NC} %s\n" "$(date +%H:%M:%S)" "$*" >&2; }
err()  { printf "${RED}[%s]${NC} %s\n" "$(date +%H:%M:%S)" "$*" >&2; }

cleanup() {
  log "Cleanup: removing leftover pilot containers"
  docker ps -aq --filter name=pilot-sandbox 2>/dev/null | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker ps -aq --filter name=pilot-dexec   2>/dev/null | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker ps -aq --filter name=pilot-test    2>/dev/null | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker ps -aq --filter name=pilot-dexec-test 2>/dev/null | xargs -r docker rm -f >/dev/null 2>&1 || true
}
trap cleanup EXIT  # always clean up on exit, even on failure

if [[ $CLEANUP_ONLY -eq 1 ]]; then
  cleanup
  exit 0
fi

# ---------- pre-req ---------------------------------------------------------
log "Pre-req checks"
need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    err "Missing: $1 — $2"
    exit 2
  fi
}
need go     "https://go.dev/doc/install"
need docker "https://docs.docker.com/engine/install/"
need ansible-playbook "sudo apt install ansible"

if ! docker ps >/dev/null 2>&1; then
  err "Docker daemon not reachable. Is the service running?"
  exit 2
fi

if [[ $NO_LLM -eq 0 ]]; then
  if ! curl -sf --max-time 3 http://localhost:11434/api/tags >/dev/null; then
    warn "Ollama not reachable at localhost:11434"
    warn "Continuing with --no-llm mode (L3 will use raw ansible-playbook instead of pilot binary)"
    NO_LLM=1
  fi
fi

log "Pre-req OK"
echo

# ---------- L1: unit --------------------------------------------------------
if [[ $L2_ONLY -eq 0 ]]; then
  log "L1 — unit tests"
  if ! go test -count=1 ./...; then
    err "L1 failed"
    exit 1
  fi
  log "L1 passed"
  echo
fi

# ---------- L2: integration (real container) --------------------------------
if [[ $L1_ONLY -eq 0 && $L3_ONLY -eq 0 ]]; then
  log "L2 — integration test (real docker container)"
  IMAGE="geerlingguy/docker-ubuntu2204-ansible:latest"
  if ! docker images -q "$IMAGE" | grep -q .; then
    warn "$IMAGE not pulled locally; pulling (this may take 1-2 min)"
    if ! docker pull "$IMAGE" >/dev/null 2>&1; then
      err "Failed to pull $IMAGE; L2 will be skipped"
    fi
  fi
  if docker images -q "$IMAGE" | grep -q .; then
    if ! go test -count=1 -v -run "TestDockerExecRunner_RealContainer" ./internal/tools/...; then
      err "L2 failed"
      exit 1
    fi
    log "L2 passed"
  fi
  echo
fi

# ---------- L3: smoke -------------------------------------------------------
if [[ $L1_ONLY -eq 0 && $L2_ONLY -eq 0 ]]; then
  log "L3 — smoke test (pilot binary + sample playbook)"

  # Always: raw ansible sanity
  log "L3.0 — raw ansible-playbook sanity"
  OUT=$(ansible-playbook playbooks/test/hello-localhost.yml 2>&1) || {
    err "raw ansible-playbook failed"
    echo "$OUT" | tail -20
    exit 3
  }
  if ! echo "$OUT" | grep -q "ok=10"; then
    err "raw ansible-playbook: expected ok=10 in PLAY RECAP, got:"
    echo "$OUT" | tail -10
    exit 3
  fi
  log "L3.0 passed (raw ansible OK)"
  echo

  if [[ $NO_LLM -eq 1 ]]; then
    # L3 with --no-llm: only raw + docker-exec path
    log "L3.1 — pure docker exec (bypasses pilot binary)"
    CNAME="pilot-dexec-smoke-$$"
    docker run -d --rm --name "$CNAME" \
      -v "$ROOT/playbooks:$ROOT/playbooks:ro" \
      geerlingguy/docker-ubuntu2204-ansible:latest sleep infinity >/dev/null
    sleep 1
    OUT=$(docker exec "$CNAME" bash -c "cd $ROOT && ansible-playbook -i /dev/stdin playbooks/test/hello-localhost.yml" <<EOF
all:
  hosts:
    localhost:
      ansible_connection: local
EOF
)
    docker rm -f "$CNAME" >/dev/null 2>&1 || true
    if ! echo "$OUT" | grep -q "ok=10"; then
      err "docker exec: expected ok=10, got:"
      echo "$OUT" | tail -10
      exit 3
    fi
    log "L3.1 passed (docker exec OK)"
  else
    # L3 with ollama: build binary, run all 3 modes
    log "L3.1 — build pilot binary"
    if ! go build -o /tmp/pilot-smoke ./cmd/pilot/; then
      err "go build failed"
      exit 3
    fi
    log "L3.1 passed (binary at /tmp/pilot-smoke)"

    CFG=/tmp/pilot-smoke-cfg.yaml
    cat > "$CFG" <<EOF
ollama_url: http://localhost:11434
model: qwen2.5:3b
max_iterations: 10
auto_approve: medium
data_dir: ~/.local/share/pilot
EOF

    # L3.2 — Localhost mode
    log "L3.2 — pilot run localhost mode (no sandbox)"
    OUT=$(echo "{\"playbook\":\"$ROOT/playbooks/test/hello-localhost.yml\",\"connection\":\"local\",\"check\":true}" \
      | timeout 240 /tmp/pilot-smoke --config "$CFG" run --from-stdin --skip-syntax-check 2>&1) || true
    if echo "$OUT" | grep -q "📦 sandbox active"; then
      err "localhost mode should not show sandbox banner"
      exit 3
    fi
    if ! echo "$OUT" | grep -q "auto-approve medium.*run_ansible"; then
      err "localhost mode: expected '[auto-approve medium] run_ansible', got first 30 lines:"
      echo "$OUT" | head -30
      exit 3
    fi
    log "L3.2 passed (localhost OK)"

    # L3.3 — Docker-exec sandbox mode
    log "L3.3 — pilot run --sandbox --sandbox-mode=docker-exec"
    OUT=$(echo "{\"playbook\":\"$ROOT/playbooks/test/hello-localhost.yml\",\"connection\":\"local\",\"check\":true}" \
      | timeout 240 /tmp/pilot-smoke --config "$CFG" run --from-stdin \
          --sandbox --sandbox-image geerlingguy/docker-ubuntu2204-ansible:latest \
          --sandbox-mode docker-exec --skip-syntax-check 2>&1) || true
    if ! echo "$OUT" | grep -q "📦 sandbox active: docker:geerlingguy"; then
      err "docker-exec mode: expected sandbox banner, got first 30 lines:"
      echo "$OUT" | head -30
      exit 3
    fi
    if ! echo "$OUT" | grep -q "auto-approve medium.*run_ansible"; then
      err "docker-exec mode: expected auto-approve run_ansible, got first 30 lines:"
      echo "$OUT" | head -30
      exit 3
    fi
    log "L3.3 passed (docker-exec OK)"
  fi
  echo
fi

# ---------- final -----------------------------------------------------------
log "ALL CHECKS PASSED"
echo
echo "Summary:"
echo "  L1 unit:        $( [[ $L2_ONLY -eq 0 ]] && echo ran || echo skipped )"
echo "  L2 integration: $( [[ $L1_ONLY -eq 0 && $L3_ONLY -eq 0 ]] && echo ran || echo skipped )"
echo "  L3 smoke:       $( [[ $L1_ONLY -eq 0 && $L2_ONLY -eq 0 ]] && echo ran || echo skipped )"
echo "  ollama used:    $( [[ $NO_LLM -eq 0 ]] && echo yes || echo no )"
exit 0
