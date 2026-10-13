#!/usr/bin/env bash
# scripts/build-login-probe.sh — builds the static pilot-login-probe
# release binary plus its .sha256 sidecar, the same delivery shape as
# scripts/build-detection-engine.sh (login-probe-apply.yml verifies the
# checksum before and after copying it to the probe host).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

VERSION="${LOGIN_PROBE_VERSION:-0.0.0-dev}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
OUT_DIR="dist"
OUT_BIN="${OUT_DIR}/pilot-login-probe-linux-amd64"

mkdir -p "${OUT_DIR}"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath \
  -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
  -o "${OUT_BIN}" \
  ./cmd/pilot-login-probe

sha256sum "${OUT_BIN}" > "${OUT_BIN}.sha256"

echo "built: ${OUT_BIN}"
echo "sha256: $(cut -d' ' -f1 "${OUT_BIN}.sha256")"
