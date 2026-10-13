#!/usr/bin/env bash
set -euo pipefail

# Exercise the exact host-editor transition used by the integration scenario:
# freeipa-nfs-server creates Nexus's roster extra, then edit_extra_var updates
# it before save_hosts closes the host editor. No topology or deploy runs.
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
workspace=$(mktemp -d /tmp/pilot-nfs-extra-var.XXXXXX)
trap 'rm -rf -- "$workspace"' EXIT

scenario="$workspace/edit.json"
jq -n '
  {version: 1, steps: [
    {action:"create_host",host:"nexus"},
    {action:"enable_role",host:"nexus",role:"freeipa-nfs-server",value_env:"PILOT_TEST_IPA_ADMIN_PASSWORD"},
    {action:"edit_extra_var",host:"nexus",key:"freeipa_roster_file",value_env:"PILOT_TEST_ROSTER_FILE"},
    {action:"save_hosts"}
  ]}
' >"$scenario"

export PILOT_TEST_IPA_ADMIN_PASSWORD=integration-test-password
export PILOT_TEST_ROSTER_FILE="$workspace/.vault/ipa-identity.yaml"
"$project_root/pilot" edit --dir "$workspace" --actions "$scenario" >/dev/null
grep -Fq "freeipa_roster_file: \"$PILOT_TEST_ROSTER_FILE\"" "$workspace/hosts.yml"
echo 'NFS roster extra-var transition passed'
