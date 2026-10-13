#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
workspace=$(mktemp -d /tmp/pilot-planner-schema-mismatch.XXXXXX)
trap 'rm -rf -- "$workspace"' EXIT

HUFU_CHECKPOINT_WORKSPACE=$workspace \
  bash "$project_root/.agent-teams/hufu-pilot-integration/discover-pilot-capabilities.sh" >/dev/null
jq 'del(.action_schema.actions[] | select(.name == "edit_extra_var")) | del(.menu_capabilities[] | select(.name == "edit_extra_var"))' \
  "$workspace/discovery/pilot-capabilities.json" >"$workspace/discovery/tampered.json"
mv "$workspace/discovery/tampered.json" "$workspace/discovery/pilot-capabilities.json"
mkdir -p "$workspace/facts"
jq -n '{version:1,kind:"topology-inventory-facts",source:{read_only:true},hosts:{"freeipa-server":{ansible_host:"10.0.0.1",ansible_user:"root",ansible_ssh_private_key_file:"/tmp/ipa"},nexus:{ansible_host:"10.0.0.2",ansible_user:"root",ansible_ssh_private_key_file:"/tmp/nexus"},"client-vm":{ansible_host:"10.0.0.3",ansible_user:"root",ansible_ssh_private_key_file:"/tmp/client"}}}' \
  >"$workspace/facts/topology-inventory.json"

set +e
HUFU_CHECKPOINT_WORKSPACE=$workspace PILOT_PROMETHEUS_SITE_LABEL=test \
  bash "$project_root/.agent-teams/hufu-pilot-integration/author-structured-actions.sh" >"$workspace/out" 2>&1
status=$?
set -e
[[ $status -ne 0 ]]
[[ ! -e $workspace/actions/edit.json ]]
echo 'planner rejects discovered-schema mismatch'
