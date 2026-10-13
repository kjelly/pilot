#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

# Hufu invokes this objective verifier during AUDIT, after the worker's
# non-mutating attestation. It checks only static prerequisites: dynamic
# scenarios cannot be authored until EXECUTE has rebuilt the topology.
for script in \
  prepare-topology.sh \
  discover-pilot-capabilities.sh \
  capture-topology-inventory-facts.sh \
  author-structured-actions.sh \
  validate-structured-actions.sh \
  run-structured-actions.sh \
  execute-structured-workflow.sh \
  pilot-structured-action-adapter.sh; do
  bash -n ".agent-teams/hufu-pilot-integration/$script"
done

bash .agent-teams/hufu-pilot-integration/discover-pilot-capabilities.sh
jq -e '.version == 1 and .kind == "pilot-action-capabilities" and .source.read_only and (.action_schema.actions | length > 0)' \
  "$HUFU_CHECKPOINT_WORKSPACE/discovery/pilot-capabilities.json" >/dev/null

python3 .agent-teams/hufu-pilot-integration/check-capabilities.py
python3 - <<'PYTHON'
import ast
from pathlib import Path
for path in Path('.agent-teams/hufu-pilot-integration').glob('*.py'):
    ast.parse(path.read_text(), filename=str(path))
PYTHON
echo "static Execute contract audit passed"
