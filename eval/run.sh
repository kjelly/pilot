#!/usr/bin/env bash
# Deterministic, model-independent gates for a candidate delivery bundle.
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$root"

# Some constrained CI/agent sandboxes mount the default Go cache read-only.
# Keep evaluation artefacts outside the repository and allow callers to
# override the location.
export GOCACHE="${GOCACHE:-/tmp/pilot-eval-go-build}"

args=(--root "$root" --output "${PILOT_EVAL_SCORECARD:-tmp/eval-scorecard.json}")
if [[ -n "${PILOT_EVAL_REQUIRE_TARGET:-}" ]]; then
  args+=(--require-target)
fi
go run ./cmd/eval "${args[@]}"
