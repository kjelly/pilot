#!/usr/bin/env bash
set -euo pipefail

# This whole sequence runs only through Hufu's EXECUTE action provider. The
# topology must exist before dynamic scenarios can use its rendered addresses;
# their deterministic validation must pass before any Pilot edit/deploy action.
bash .agent-teams/hufu-pilot-integration/prepare-topology.sh
bash .agent-teams/hufu-pilot-integration/capture-topology-inventory-facts.sh
bash .agent-teams/hufu-pilot-integration/author-structured-actions.sh
bash .agent-teams/hufu-pilot-integration/validate-structured-actions.sh
bash .agent-teams/hufu-pilot-integration/run-structured-actions.sh
