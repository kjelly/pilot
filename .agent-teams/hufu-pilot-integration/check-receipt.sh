#!/usr/bin/env bash
set -euo pipefail

: "${HUFU_CHECKPOINT_WORKSPACE:?launcher must export HUFU_CHECKPOINT_WORKSPACE}"
[[ $# -eq 1 ]] || { echo "usage: $0 <receipt-stem>" >&2; exit 2; }
receipt="$HUFU_CHECKPOINT_WORKSPACE/receipts/$1.json"
[[ -s $receipt ]] || { echo "missing receipt: $receipt" >&2; exit 1; }
jq -e '.version == 1 and .status == "passed"' "$receipt" >/dev/null
