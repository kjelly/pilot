#!/usr/bin/env bash
# scripts/build-pilot-access-directory.sh — builds the pinned, static
# pilot-access-directory release binary (docs/tmp/now/spec.md §36).
#
# CGO_ENABLED=0 for the same reason as scripts/build-pilot-access-gateway.sh:
# this binary reuses the same internal/freeipaaccess Kerberos/SPNEGO client
# (github.com/jcmturner/gokrb5/v8), which needs no cgo.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

VERSION="${PILOT_ACCESS_DIRECTORY_VERSION:-0.0.0-dev}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
OUT_DIR="dist"
OUT_BIN="${OUT_DIR}/pilot-access-directory-linux-amd64"

mkdir -p "${OUT_DIR}"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath \
  -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
  -o "${OUT_BIN}" \
  ./cmd/pilot-access-directory

sha256sum "${OUT_BIN}" > "${OUT_BIN}.sha256"

echo "built: ${OUT_BIN}"
echo "sha256: $(cut -d' ' -f1 "${OUT_BIN}.sha256")"
