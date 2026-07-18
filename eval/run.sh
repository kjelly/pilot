#!/usr/bin/env bash
# Deterministic, model-independent gates for a candidate delivery bundle.
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$root"

# Some constrained CI/agent sandboxes mount the default Go cache read-only.
# Keep evaluation artefacts outside the repository and allow callers to
# override the location.
export GOCACHE="${GOCACHE:-/tmp/pilot-eval-go-build}"

go run ./cmd/pilot contract lint
go test -count=1 -run TestSpecPlaybookTagAlignment ./cmd/pilot/cmd
go test -count=1 -run TestShellSyntax ./internal/spec

# Catch the two high-value authoring regressions deterministically.  This is a
# guardrail, not a substitute for secret-aware evidence transport: values must
# still be supplied through vault references and never printed by verification.
if rg -n --glob '*.yml' --glob '*.yaml' --glob '!*.example.yaml' \
	'^[[:space:]]*[^#[:space:]].*(?i:(password|token|secret|api[_-]?key))\s*[:=]\s*[^${{][^[:space:]]{7,}' \
	contracts playbooks/apply; then
  echo "authoring eval: possible inline secret material found" >&2
  exit 1
fi
if rg -n --glob '*.yml' --glob '*.yaml' \
  "^[[:space:]]*[^#[:space:]].*(?:ansible_host|[a-z_]+_host)\\s*:\\s*[\\\"']?(?:[0-9]{1,3}\\.){3}[0-9]{1,3}" \
  contracts playbooks/apply; then
  echo "authoring eval: host-specific IPv4 literal found; declare an input or inventory binding" >&2
  exit 1
fi

if [[ -n "${PILOT_EVAL_TARGET_TEST:-}" ]]; then
  echo "authoring eval: running caller-supplied disposable target test"
  bash -lc "$PILOT_EVAL_TARGET_TEST"
else
  echo "authoring eval: static gates passed; target test intentionally not run (set PILOT_EVAL_TARGET_TEST)."
fi
