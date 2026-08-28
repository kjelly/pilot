#!/usr/bin/env bash
# scripts/build-detection-engine.sh — builds the pinned, static
# pilot-detection-engine release binary (detection-engine spec §6.2).
#
# CGO_ENABLED=0 + a pure-Go SQLite driver (modernc.org/sqlite) is what
# makes a fully static linux/amd64 binary possible here; do not add a CGO
# dependency to internal/detection without updating this script and the
# spec first.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

VERSION="${DETECTION_ENGINE_VERSION:-0.0.0-dev}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
OUT_DIR="dist"
OUT_BIN="${OUT_DIR}/pilot-detection-engine-linux-amd64"

mkdir -p "${OUT_DIR}"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath \
  -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
  -o "${OUT_BIN}" \
  ./cmd/pilot-detection-engine

sha256sum "${OUT_BIN}" > "${OUT_BIN}.sha256"

echo "built: ${OUT_BIN}"
echo "sha256: $(cut -d' ' -f1 "${OUT_BIN}.sha256")"
