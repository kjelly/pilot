#!/usr/bin/env bash
# scripts/build-pilot-access-gateway.sh — builds the pinned, static
# pilot-access-gateway release binary (docs/tmp/now/spec.md §54).
#
# CGO_ENABLED=0 is mandatory here specifically because this binary's
# Kerberos/SPNEGO client (github.com/jcmturner/gokrb5/v8) was chosen in
# Phase 0 BECAUSE it needs no cgo (see
# docs/evidence/pilot-access-gateway/2026-09-14-phase0-transport-spike.md).
# Do not add a CGO dependency to internal/freeipaaccess without redoing
# that spike and updating this script + spec.md §54 first.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

VERSION="${PILOT_ACCESS_GATEWAY_VERSION:-0.0.0-dev}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
OUT_DIR="dist"
OUT_BIN="${OUT_DIR}/pilot-access-gateway-linux-amd64"

mkdir -p "${OUT_DIR}"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath \
  -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
  -o "${OUT_BIN}" \
  ./cmd/pilot-access-gateway

sha256sum "${OUT_BIN}" > "${OUT_BIN}.sha256"

echo "built: ${OUT_BIN}"
echo "sha256: $(cut -d' ' -f1 "${OUT_BIN}.sha256")"
