#!/usr/bin/env bash
set -euo pipefail

# This whole sequence runs only through Hufu's EXECUTE action provider. The
# topology must exist before dynamic scenarios can use its rendered addresses;
# their deterministic validation must pass before any Pilot edit/deploy action.
python3 .agent-teams/hufu-pilot-integration/campaign_evidence.py prepare-topology -- bash .agent-teams/hufu-pilot-integration/prepare-topology.sh
python3 .agent-teams/hufu-pilot-integration/campaign_evidence.py capture-topology-inventory-facts -- bash .agent-teams/hufu-pilot-integration/capture-topology-inventory-facts.sh
python3 .agent-teams/hufu-pilot-integration/campaign_evidence.py author-structured-actions -- bash .agent-teams/hufu-pilot-integration/author-structured-actions.sh
python3 .agent-teams/hufu-pilot-integration/campaign_evidence.py validate-structured-actions -- bash .agent-teams/hufu-pilot-integration/validate-structured-actions.sh
python3 .agent-teams/hufu-pilot-integration/campaign_evidence.py run-structured-actions -- bash .agent-teams/hufu-pilot-integration/run-structured-actions.sh
