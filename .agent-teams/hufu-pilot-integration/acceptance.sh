#!/usr/bin/env bash
set -euo pipefail

: "${HUFU_CHECKPOINT_WORKSPACE:?launcher must export HUFU_CHECKPOINT_WORKSPACE}"
root=$HUFU_CHECKPOINT_WORKSPACE
receipts=$root/receipts
export PYTHONDONTWRITEBYTECODE=1
bash .agent-teams/hufu-pilot-integration/test-memory-contract.sh
python3 .agent-teams/hufu-pilot-integration/verify-evidence.py
for file in topology-preparation scenario-audit execution verification; do
  [[ -s $receipts/$file.json ]] || { echo "missing acceptance receipt: $file" >&2; exit 1; }
  jq -e '.version == 1 and .status == "passed"' "$receipts/$file.json" >/dev/null
done
jq -e '.topology_targets == 3' "$receipts/topology-preparation.json" >/dev/null
audit_hash=$(jq -r '.bundle_sha256' "$receipts/scenario-audit.json")
execution_hash=$(jq -r '.bundle_sha256' "$receipts/execution.json")
verification_hash=$(jq -r '.bundle_sha256' "$receipts/verification.json")
[[ $audit_hash == "$execution_hash" && $execution_hash == "$verification_hash" ]] || {
  echo "structured-action bundle changed between audit, execution, and verification" >&2
  exit 1
}
jq -e '.topology_rebuilt and .edit_passed and .inventory_passed and .deploy_passes == 2 and .reconcile_passes == 2 and .idempotent' "$receipts/execution.json" >/dev/null
jq -e '.topology_targets == 3 and .inventory_lint and .section4_checks > 0 and .full_runbook_scope' "$receipts/verification.json" >/dev/null
echo "Minimal PoC structured-action acceptance passed: $audit_hash"
