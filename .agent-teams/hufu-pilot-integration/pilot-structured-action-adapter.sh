#!/usr/bin/env bash
set -euo pipefail

# Hufu's generic command action provider passes one static Action JSON object
# on stdin. This adapter is the Pilot-specific boundary: it validates the
# immutable EXECUTE contract, runs the audited bundle, and returns a small JSON
# result for Hufu's typed action receipt.
action=$(cat)
if ! jq -e '
  .capability == "pilot-structured-actions" and
  .type == "execute_bundle" and
  .payload == "{\"operation\":\"minimal-poc-structured-run\",\"version\":1}"
' <<<"$action" >/dev/null; then
  jq -n --argjson action "$action" \
    '{status:"failed",failure_class:"INVALID_TASK",message:"unexpected Pilot structured-action contract",action:$action}' >&2
  exit 1
fi

# All topology, dynamic-scenario, and Pilot state changes are deliberately
# behind this EXECUTE-only provider boundary. PREPARE/AUDIT workers never get
# a shell, and the audit script below runs before the first Pilot edit/deploy.
python3 .agent-teams/hufu-pilot-integration/resource_guard.py -- bash .agent-teams/hufu-pilot-integration/execute-structured-workflow.sh

: "${HUFU_CHECKPOINT_WORKSPACE:?launcher must export HUFU_CHECKPOINT_WORKSPACE}"
jq -e '.version == 1 and .status == "passed"' \
  "$HUFU_CHECKPOINT_WORKSPACE/receipts/execution.json" >/dev/null
jq -n --arg receipt "$HUFU_CHECKPOINT_WORKSPACE/receipts/execution.json" \
  '{outputs:{status:"passed",phase:"execute",receipt:$receipt}}'
