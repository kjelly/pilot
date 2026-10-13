#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
workspace=$(mktemp -d /tmp/pilot-capability-discovery.XXXXXX)
trap 'rm -rf -- "$workspace"' EXIT

HUFU_CHECKPOINT_WORKSPACE=$workspace \
  bash "$project_root/.agent-teams/hufu-pilot-integration/discover-pilot-capabilities.sh" >/dev/null

artifact=$workspace/discovery/pilot-capabilities.json
jq -e '
  .version == 1 and .kind == "pilot-action-capabilities" and .source.read_only and
  .source.command == "./pilot actions schema" and
  (.action_schema.actions | any(.name == "edit_extra_var")) and
  (.menu_capabilities | any(.name == "save_hosts"))
' "$artifact" >/dev/null
[[ $(find "$workspace" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort) == discovery ]]
echo 'read-only Pilot capability discovery passed'
