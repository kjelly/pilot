#!/usr/bin/env bash
# scripts/per-host-recording-topology-test.sh — ephemeral fresh-host
# topology test of per-host SSH session recording (L1 syntax, L3 check-mode
# dry-run, L4 apply, L5 verify, L6 idempotency; AGENTS.md §1.4, §4.0).
#
# Builds the four binaries from this checkout, then runs
# `pilot vm-target topology test --ephemeral` on
# docs/topologies/per-host-recording-topology.yaml with
# playbooks/test/per-host-recording-topology.yml. For a formal evidence run,
# run it from a clean checkout of the candidate commit (AGENTS.md §1.5).
#
# Usage:
#   VAULT=~/.vault/per-host-recording-sandbox.yaml ./scripts/per-host-recording-topology-test.sh
#   make recording-topology-test VAULT=<path>
#
# Required env:
#   VAULT  — vars file (keep it outside the repo) with ipa_admin_password,
#            pilot_session_store_master_key and
#            pilot_session_store_ingest_signing_key (64 hex characters each
#            for the two store keys).
# Optional env:
#   DIST            — where the binaries are built (default dist/per-host-recording)
#   KEEP_ON_FAILURE — 1 keeps the VMs of a failed run for diagnosis; tear
#                     them down afterwards with `pilot vm-target topology down`
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

TOPOLOGY="docs/topologies/per-host-recording-topology.yaml"
PLAYBOOK="playbooks/test/per-host-recording-topology.yml"
VAULT="${VAULT:-}"
DIST="${DIST:-dist/per-host-recording}"
KEEP_ON_FAILURE="${KEEP_ON_FAILURE:-0}"
GATEWAY_ID="rec-gw1"
GATEWAY_SCOPE="rec"

if [ -z "$VAULT" ]; then
  echo "ERROR: VAULT=<path> is required (ipa_admin_password, pilot_session_store_master_key, pilot_session_store_ingest_signing_key)." >&2
  exit 2
fi
if [ ! -f "$VAULT" ]; then
  echo "ERROR: vault file not found: $VAULT" >&2
  exit 2
fi
VAULT_ABS="$(cd "$(dirname "$VAULT")" && pwd)/$(basename "$VAULT")"

mkdir -p "$DIST"
for c in pilot pilot-access-gateway pilot-access-directory pilot-session-store; do
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "$DIST/$c" "./cmd/$c"
done
DIST_ABS="$(cd "$DIST" && pwd)"

KEEP_ARGS=()
if [ "$KEEP_ON_FAILURE" = 1 ]; then
  KEEP_ARGS=(--keep-on-failure)
fi

# docs/verification/pilot-access-gateway.md AG01 compares the deployed
# config against these Spec v2 inputs; topology test's verify inherits them.
export PILOT_INPUT_GATEWAY_ID="$GATEWAY_ID"
export PILOT_INPUT_GATEWAY_SCOPE="$GATEWAY_SCOPE"

"$DIST_ABS/pilot" vm-target topology test \
  --topology "$TOPOLOGY" \
  --ephemeral "${KEEP_ARGS[@]}" \
  --playbook "$PLAYBOOK" \
  --verify docs/verification/freeipa-client.md=freeipa-client \
  --verify docs/verification/pilot-session-store.md=pilot-session-store \
  --verify docs/verification/pilot-access-gateway.md=pilot-access-gateway \
  --verify docs/verification/pilot-access-directory.md=pilot-access-directory \
  -- \
  -e "gateway_id=$GATEWAY_ID" \
  -e "gateway_scope=$GATEWAY_SCOPE" \
  -e '{"gateway_scope_hosts": ["rec-ta.ipa.pilot.internal", "rec-tb.ipa.pilot.internal"]}' \
  -e "pilot_binary_path=$DIST_ABS/pilot" \
  -e "pilot_access_gateway_binary_path=$DIST_ABS/pilot-access-gateway" \
  -e "pilot_session_store_binary_path=$DIST_ABS/pilot-session-store" \
  -e "pilot_access_directory_binary_path=$DIST_ABS/pilot-access-directory" \
  -e "directory_id=rec-dir1" \
  -e "pilot_access_gateway_recording_session_store_url=https://rec-store.ipa.pilot.internal:8443" \
  -e "pilot_session_store_retention_days=30" \
  -e "pilot_session_store_key_id=rec-1" \
  -e "@$VAULT_ABS"
