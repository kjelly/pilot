#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
: "${HUFU_CHECKPOINT_WORKSPACE:?launcher must export HUFU_CHECKPOINT_WORKSPACE}"
root=$HUFU_CHECKPOINT_WORKSPACE
python3 .agent-teams/hufu-pilot-integration/verify-evidence.py
./pilot vm-target topology status --topology docs/topologies/minimal-poc-topology.yaml >"$root/logs/topology-verification.log"
for target in freeipa-server nexus client-vm; do
  awk -v target="$target" '$1 == target && $2 == "running" {found=1} END {exit !found}' "$root/logs/topology-verification.log"
done
./pilot inventory lint --in "$root/hosts.yml" >"$root/logs/inventory-verification.log" 2>&1
# Final phase checks remain read-only; active backup/FIM/roster-cycle probes
# have already run behind the EXECUTE boundary and were sealed as evidence.
python3 - "$root" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, '.agent-teams/hufu-pilot-integration')
from workflow_contract import write_json, bundle_hash, HOSTS
import importlib.util
spec = importlib.util.spec_from_file_location('evidence', '.agent-teams/hufu-pilot-integration/verify-evidence.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
root = Path(sys.argv[1])
checks = module.verify()
# A fresh final HTTPS probe does not mutate the deployed state or the sealed logs.
from workflow_contract import remote
import json
health = remote('final-endpoint-health', 'client-vm', 'curl --fail --max-time 20 -sS https://grafana.it.pilot.internal/api/health')
if json.loads(health).get('database') != 'ok':
    raise SystemExit('final endpoint health failed')
write_json(root / 'receipts/verification.json', {
    'version': 1, 'status': 'passed', 'bundle_sha256': bundle_hash(root),
    'topology_targets': len(HOSTS), 'inventory_lint': True, 'section4_checks': checks,
    'full_runbook_scope': True})
print('complete structured run verification passed')
PY
