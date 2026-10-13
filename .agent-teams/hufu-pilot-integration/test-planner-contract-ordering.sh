#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
launcher=$project_root/run.sh
runner=$project_root/.agent-teams/hufu-pilot-integration/structured-action-runner.md
workspace=$(mktemp -d /tmp/pilot-planner-contract.XXXXXX)
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

for reconcile in freeipa-dns freeipa-identity; do
  jq -e '
    ([.steps[] | select(.action == "reconcile") | .answers[] |
      select(.prompt_id == "target_group" and .text == "")] | length) == 1 and
    ([.steps[] | .answers[] | select(.key? == "alertmanager_config")] | length) == 0
  ' "$workspace/actions/reconcile/$reconcile.json" >/dev/null
done

edit=$workspace/actions/edit.json
save=$(jq '[.steps | to_entries[] | select(.value.action == "save_hosts") | .key] | first' "$edit")
jq -e --argjson save "$save" '
  [.steps | to_entries[] | select(.value.action == "add_extra_var" or .value.action == "edit_extra_var") | .key] | all(. < $save)
' "$edit" >/dev/null
jq -e --argjson save "$save" '
  [.steps | to_entries[] | select(.value.action == "set_group_var" or .value.action == "set_vault_value") | .key] | all(. > $save)
' "$edit" >/dev/null
jq -e 'any(.steps[]; .action == "edit_extra_var" and .host == "nexus" and .key == "freeipa_roster_file")' "$edit" >/dev/null
jq -e '
  [
    {key:"ipa_admin_password", value_env:"PILOT_IPA_ADMIN_PASSWORD"},
    {key:"grafana_admin_password", value_env:"PILOT_GRAFANA_ADMIN_PASSWORD"},
    {key:"restic_aws_access_key_id", value_env:"PILOT_RESTIC_AWS_ACCESS_KEY_ID"},
    {key:"restic_aws_secret_access_key", value_env:"PILOT_RESTIC_AWS_SECRET_ACCESS_KEY"},
    {key:"restic_password", value_env:"PILOT_RESTIC_PASSWORD"},
    {key:"thanos_aws_access_key_id", value_env:"PILOT_THANOS_AWS_ACCESS_KEY_ID"},
    {key:"thanos_aws_secret_access_key", value_env:"PILOT_THANOS_AWS_SECRET_ACCESS_KEY"},
    {key:"node_exporter_basic_auth_password", value_env:"PILOT_NODE_EXPORTER_BASIC_AUTH_PASSWORD"},
    {key:"dcgm_exporter_basic_auth_password", value_env:"PILOT_DCGM_EXPORTER_BASIC_AUTH_PASSWORD"}
  ] as $required |
  ([.steps[] | select(.action == "set_vault_value") | {key, value_env}] | sort_by(.key)) ==
    ($required | sort_by(.key))
' "$edit" >/dev/null
export PILOT_IPA_ADMIN_PASSWORD=integration-test-ipa-password
export PILOT_GRAFANA_ADMIN_PASSWORD=integration-test-grafana-password
export PILOT_RESTIC_AWS_ACCESS_KEY_ID=integration-test-restic-access-key
export PILOT_RESTIC_AWS_SECRET_ACCESS_KEY=integration-test-restic-secret-key
export PILOT_RESTIC_PASSWORD=integration-test-restic-password
export PILOT_THANOS_AWS_ACCESS_KEY_ID=integration-test-thanos-access-key
export PILOT_THANOS_AWS_SECRET_ACCESS_KEY=integration-test-thanos-secret-key
export PILOT_NODE_EXPORTER_BASIC_AUTH_PASSWORD=integration-test-node-exporter-password
export PILOT_DCGM_EXPORTER_BASIC_AUTH_PASSWORD=integration-test-dcgm-exporter-password
export PILOT_FREEIPA_ROSTER_FILE="$workspace/.vault/ipa-identity.yaml"
export PILOT_FREEIPA_DNS_MANIFEST_FILE="$workspace/freeipa-dns.yaml"
export PILOT_INTERNAL_ENDPOINT_MANIFEST_FILE="$workspace/internal-endpoints.yaml"
"$project_root/pilot" edit --dir "$workspace" --actions "$edit" >/dev/null
python3 - "$workspace/.vault/main.yaml" <<'PY'
import sys
import yaml

expected = {
    "ipa_admin_password": "integration-test-ipa-password",
    "grafana_admin_password": "integration-test-grafana-password",
    "restic_aws_access_key_id": "integration-test-restic-access-key",
    "restic_aws_secret_access_key": "integration-test-restic-secret-key",
    "restic_password": "integration-test-restic-password",
    "thanos_aws_access_key_id": "integration-test-thanos-access-key",
    "thanos_aws_secret_access_key": "integration-test-thanos-secret-key",
    "node_exporter_basic_auth_password": "integration-test-node-exporter-password",
    "dcgm_exporter_basic_auth_password": "integration-test-dcgm-exporter-password",
}
with open(sys.argv[1], encoding="utf-8") as stream:
    vault = yaml.safe_load(stream)
if not isinstance(vault, dict):
    raise SystemExit("generated vault must be a mapping")
if {key: vault.get(key) for key in expected} != expected:
    raise SystemExit("generated vault did not resolve every required integration secret")
if any(value.startswith("CHANGE-ME-") for key, value in vault.items() if key in expected and isinstance(value, str)):
    raise SystemExit("generated vault retained a CHANGE-ME placeholder")
PY
grep -Fqx '    - PILOT_NODE_EXPORTER_BASIC_AUTH_PASSWORD' "$runner"
if jq -e 'any(.steps[]; .key? == "alertmanager_config")' "$edit" >/dev/null; then
  echo 'planner must leave the optional Alertmanager config at its built-in default' >&2
  exit 1
fi
jq -e '.version == 1 and .status == "passed"' "$workspace/receipts/scenario-audit.json" >/dev/null
for prompt_id in inventory topology_preview preflight component target_group stage limit tags become_password extra_vars execution.preview execution.confirm_apply; do
  jq -e --arg prompt_id "$prompt_id" '
    any(.prompt_schemas[]; .name == "reconcile" and any(.prompt_schema.prompts[]; .id == $prompt_id))
  ' "$workspace/discovery/pilot-capabilities.json" >/dev/null
done
grep -Fq 'schema_sha256' "$workspace/discovery/pilot-capabilities.json"
echo 'planner ordering, required vault, and discovery contract passed'
