#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
workspace=$(mktemp -d /tmp/pilot-prompt-answer-contract.XXXXXX)
trap 'rm -rf -- "$workspace"' EXIT

HUFU_CHECKPOINT_WORKSPACE=$workspace \
  bash "$project_root/.agent-teams/hufu-pilot-integration/discover-pilot-capabilities.sh" >/dev/null
mkdir -p "$workspace/facts"
jq -n '{version:1,kind:"topology-inventory-facts",source:{read_only:true},hosts:{"freeipa-server":{ansible_host:"10.0.0.1",ansible_user:"root",ansible_ssh_private_key_file:"/tmp/ipa"},nexus:{ansible_host:"10.0.0.2",ansible_user:"root",ansible_ssh_private_key_file:"/tmp/nexus"},"client-vm":{ansible_host:"10.0.0.3",ansible_user:"root",ansible_ssh_private_key_file:"/tmp/client"}}}' \
  >"$workspace/facts/topology-inventory.json"
HUFU_CHECKPOINT_WORKSPACE=$workspace PILOT_PROMETHEUS_SITE_LABEL=test \
  bash "$project_root/.agent-teams/hufu-pilot-integration/author-structured-actions.sh" >/dev/null
HUFU_CHECKPOINT_WORKSPACE=$workspace \
  bash "$project_root/.agent-teams/hufu-pilot-integration/validate-structured-actions.sh" >/dev/null

for scenario in "$workspace/actions/deploy.json" "$workspace/actions/reconcile"/*.json; do
  jq -e --arg inventory "$workspace/inventory.yml" '
    .steps | length == 1 and .[0].inventory == $inventory and
    (. [0].answers | map(.prompt_id)) as $ids |
    (($ids | length) == ($ids | unique | length)) and
    ([. [0].answers[] | select(.prompt_id == "execution.preview") | .confirm] == [true]) and
    ([. [0].answers[] | select(.prompt_id == "execution.confirm_apply") | .confirm] == [true]) and
    all(. [0].answers[]; has("prompt") | not)
  ' "$scenario" >/dev/null
done

echo 'prompt-answer scenario contract passed'
