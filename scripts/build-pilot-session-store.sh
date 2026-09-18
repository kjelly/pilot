#!/usr/bin/env bash
# scripts/build-pilot-session-store.sh — builds the pinned, static
# pilot-session-store release binary (docs/tmp/now/spec.md §35/§36).
#
# CGO_ENABLED=0: internal/sessionstore uses modernc.org/sqlite (pure Go,
# no cgo sqlite3 driver needed), same as every other pilot-* binary in
# this repo.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

VERSION="${PILOT_SESSION_STORE_VERSION:-0.0.0-dev}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
OUT_DIR="dist"
OUT_BIN="${OUT_DIR}/pilot-session-store-linux-amd64"

mkdir -p "${OUT_DIR}"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath \
  -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
  -o "${OUT_BIN}" \
  ./cmd/pilot-session-store

sha256sum "${OUT_BIN}" > "${OUT_BIN}.sha256"

echo "built: ${OUT_BIN}"
echo "sha256: $(cut -d' ' -f1 "${OUT_BIN}.sha256")"
