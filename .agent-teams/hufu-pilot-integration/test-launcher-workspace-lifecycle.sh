#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
source "$project_root/scripts/hufu-workspace-lifecycle.sh"

test_root=$(mktemp -d /tmp/hufu-workspace-lifecycle.XXXXXX)
trap 'rm -rf -- "$test_root"' EXIT
team=hufu-pilot-integration

unset HUFU_WORKSPACE
select_hufu_workspace "$test_root" "$team"
initial=$HUFU_LAUNCHER_WORKSPACE
[[ $initial == "$test_root/current" ]]
[[ $(<"$test_root/active-workspace") == "$initial" ]]

mkdir -p "$initial/$team"
printf '%s\n' '{"workflow_state":"PREPARE"}' >"$initial/$team/session.json"
select_hufu_workspace "$test_root" "$team"
[[ $HUFU_LAUNCHER_WORKSPACE == "$initial" ]]

printf '%s\n' '{"workflow_state":"FAILED"}' >"$initial/$team/session.json"
select_hufu_workspace "$test_root" "$team"
replacement=$HUFU_LAUNCHER_WORKSPACE
[[ $replacement != "$initial" ]]
[[ -d $replacement ]]
[[ $(<"$test_root/active-workspace") == "$replacement" ]]

mkdir -p "$test_root/explicit/$team"
printf '%s\n' '{"workflow_state":"FAILED"}' >"$test_root/explicit/$team/session.json"
HUFU_WORKSPACE="$test_root/explicit"
select_hufu_workspace "$test_root" "$team"
[[ $HUFU_LAUNCHER_WORKSPACE == "$HUFU_WORKSPACE" ]]

echo 'Hufu launcher workspace lifecycle passed'
