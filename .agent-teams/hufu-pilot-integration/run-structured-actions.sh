#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
# Nexus runs the Wazuh stack; allow Ansible SSH handshakes time to recover under load.
export ANSIBLE_TIMEOUT="${ANSIBLE_TIMEOUT:-60}"
: "${HUFU_CHECKPOINT_WORKSPACE:?launcher must export HUFU_CHECKPOINT_WORKSPACE}"
jq -e '.version == 1 and .status == "passed"' "$HUFU_CHECKPOINT_WORKSPACE/receipts/topology-preparation.json" >/dev/null
python3 .agent-teams/hufu-pilot-integration/run-workflow.py
