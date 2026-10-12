#!/usr/bin/env bash
set -euo pipefail

# PREPARE has two data-dependent deterministic steps. Keeping them in one
# static contract prevents Hufu's phase scheduler from dispatching action
# authoring before the topology has returned its current connection facts.
bash .agent-teams/hufu-pilot-integration/prepare-topology.sh
bash .agent-teams/hufu-pilot-integration/author-structured-actions.sh
echo "topology and structured-action bundle preparation passed"
