#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

# This deterministic planner consumes only the versioned read-only discovery
# artifact and current topology inventory facts. It emits semantic Pilot action
# scenarios; it never drives Pilot or resolves a secret environment value.
: "${HUFU_CHECKPOINT_WORKSPACE:?launcher must export HUFU_CHECKPOINT_WORKSPACE}"
root=$HUFU_CHECKPOINT_WORKSPACE
actions=$root/actions
discovery=$root/discovery/pilot-capabilities.json
facts=$root/facts/topology-inventory.json
mkdir -p "$actions/reconcile"

[[ -s $discovery ]] || { echo "missing Pilot capability discovery: $discovery" >&2; exit 1; }
[[ -s $facts ]] || { echo "missing topology inventory facts: $facts" >&2; exit 1; }
jq -e '.version == 1 and .kind == "pilot-action-capabilities" and .source.read_only and (.action_schema.actions | type == "array")' "$discovery" >/dev/null
jq -e '.version == 1 and .kind == "topology-inventory-facts" and .source.read_only and (.hosts | type == "object")' "$facts" >/dev/null
schema=$(jq -c '.action_schema' "$discovery")
[[ $(printf '%s' "$schema" | sha256sum | awk '{print $1}') == "$(jq -r '.schema_sha256' "$discovery")" ]] || {
  echo "Pilot capability discovery schema hash mismatch" >&2
  exit 1
}
for action in create_host set_host_field enable_role add_extra_var add_vault_key \
  edit_extra_var save_vault set_group_var save_group_vars save_hosts deploy reconcile; do
  jq -e --arg action "$action" '.actions | any(.name == $action)' <<<"$schema" >/dev/null
done
jq -e '
  .actions | map(select(.name == "deploy" or .name == "reconcile")) |
  length == 2 and all(.[]; .prompt_schema.version == 1 and
    (.prompt_schema.prompts | type == "array" and length > 0))
' <<<"$schema" >/dev/null

fact() { jq -er --arg host "$1" --arg field "$2" '.hosts[$host][$field] | select(type == "string" and length > 0)' "$facts"; }
ipa_ip=$(fact freeipa-server ansible_host)
nexus_ip=$(fact nexus ansible_host)
client_ip=$(fact client-vm ansible_host)
ipa_user=$(fact freeipa-server ansible_user)
nexus_user=$(fact nexus ansible_user)
client_user=$(fact client-vm ansible_user)
ipa_key=$(fact freeipa-server ansible_ssh_private_key_file)
nexus_key=$(fact nexus ansible_ssh_private_key_file)
client_key=$(fact client-vm ansible_ssh_private_key_file)
site_label=${PILOT_PROMETHEUS_SITE_LABEL:?launcher must export PILOT_PROMETHEUS_SITE_LABEL}
for value in "$ipa_ip" "$nexus_ip" "$client_ip" "$ipa_user" "$nexus_user" "$client_user" "$ipa_key" "$nexus_key" "$client_key"; do
  [[ -n $value ]] || { echo 'topology inventory is missing a required host connection field' >&2; exit 1; }
done

# Host-scoped actions must finish before save_hosts closes the host editor.
# The NFS bootstrap has already created Nexus's freeipa_roster_file, so the
# plan updates it rather than adding a duplicate. Vault/group-vars screens
# cannot navigate back into the host editor.

jq -n \
  --arg ipa_ip "$ipa_ip" --arg nexus_ip "$nexus_ip" --arg client_ip "$client_ip" \
  --arg ipa_user "$ipa_user" --arg nexus_user "$nexus_user" --arg client_user "$client_user" \
  --arg ipa_key "$ipa_key" --arg nexus_key "$nexus_key" --arg client_key "$client_key" \
  --arg site_label "$site_label" '
  def host_fields($host; $ip; $user; $key): [
    {action:"set_host_field",host:$host,field:"ansible_host",value:$ip},
    {action:"set_host_field",host:$host,field:"ansible_user",value:$user},
    {action:"set_host_field",host:$host,field:"ssh_key_file",value:$key}
  ];
  def roles($host; $items): [$items[] | {action:"enable_role",host:$host,role:.}];
  {
    version: 1,
    steps: (
      ["freeipa-server", "nexus", "client-vm"] | map({action:"create_host",host:.})
      + host_fields("freeipa-server"; $ipa_ip; $ipa_user; $ipa_key)
      + host_fields("nexus"; $nexus_ip; $nexus_user; $nexus_key)
      + host_fields("client-vm"; $client_ip; $client_user; $client_key)
      + roles("freeipa-server"; ["freeipa-server", "freeipa-dns-client", "host-monitoring", "audit-log-forwarding", "wazuh-fim", "restic-backup"])
      + roles("nexus"; ["freeipa-client", "freeipa-dns-client", "host-monitoring", "docker", "audit-log-forwarding", "log-server", "wazuh-manager", "wazuh-fim", "seaweedfs-s3", "restic-backup"])
      + [{action:"enable_role",host:"nexus",role:"prometheus",host_vars:{prometheus_site_label:$site_label}}]
      + roles("nexus"; ["thanos-query", "alertmanager", "dashboard", "reverse-proxy"])
      + [{action:"enable_role",host:"nexus",role:"freeipa-nfs-server",value_env:"PILOT_IPA_ADMIN_PASSWORD"}]
      + roles("client-vm"; ["freeipa-client", "freeipa-dns-client", "host-monitoring", "docker", "audit-log-forwarding", "wazuh-fim", "restic-backup", "freeipa-nfs-client"])
      + [
        {action:"add_extra_var",host:"freeipa-server",key:"freeipa_roster_file",value_env:"PILOT_FREEIPA_ROSTER_FILE"},
        {action:"add_extra_var",host:"freeipa-server",key:"freeipa_dns_manifest_file",value_env:"PILOT_FREEIPA_DNS_MANIFEST_FILE"},
        {action:"edit_extra_var",host:"nexus",key:"freeipa_roster_file",value_env:"PILOT_FREEIPA_ROSTER_FILE"},
        {action:"add_extra_var",host:"client-vm",key:"freeipa_roster_file",value_env:"PILOT_FREEIPA_ROSTER_FILE"},
        {action:"add_extra_var",host:"freeipa-server",key:"internal_endpoint_manifest_file",value_env:"PILOT_INTERNAL_ENDPOINT_MANIFEST_FILE"},
        {action:"save_hosts"},
        {action:"set_vault_value",file:".vault/main.yaml",key:"ipa_admin_password",value_env:"PILOT_IPA_ADMIN_PASSWORD"},
        {action:"set_vault_value",file:".vault/main.yaml",key:"grafana_admin_password",value_env:"PILOT_GRAFANA_ADMIN_PASSWORD"},
        {action:"set_vault_value",file:".vault/main.yaml",key:"restic_aws_access_key_id",value_env:"PILOT_RESTIC_AWS_ACCESS_KEY_ID"},
        {action:"set_vault_value",file:".vault/main.yaml",key:"restic_aws_secret_access_key",value_env:"PILOT_RESTIC_AWS_SECRET_ACCESS_KEY"},
        {action:"set_vault_value",file:".vault/main.yaml",key:"restic_password",value_env:"PILOT_RESTIC_PASSWORD"},
        {action:"set_vault_value",file:".vault/main.yaml",key:"thanos_aws_access_key_id",value_env:"PILOT_THANOS_AWS_ACCESS_KEY_ID"},
        {action:"set_vault_value",file:".vault/main.yaml",key:"thanos_aws_secret_access_key",value_env:"PILOT_THANOS_AWS_SECRET_ACCESS_KEY"},
        {action:"set_vault_value",file:".vault/main.yaml",key:"node_exporter_basic_auth_password",value_env:"PILOT_NODE_EXPORTER_BASIC_AUTH_PASSWORD"},
        {action:"set_vault_value",file:".vault/main.yaml",key:"dcgm_exporter_basic_auth_password",value_env:"PILOT_DCGM_EXPORTER_BASIC_AUTH_PASSWORD"},
        {action:"save_vault",file:".vault/main.yaml"},
        {action:"set_group_var",file:"group_vars/freeipa.yml",key:"freeipa_server_ip",value:$ipa_ip},
        {action:"save_group_vars",file:"group_vars/freeipa.yml"},
        {action:"set_group_var",file:"group_vars/prometheus.yml",key:"thanos_s3_target_host",value:$nexus_ip},
        {action:"save_group_vars",file:"group_vars/prometheus.yml"},
        {action:"set_group_var",file:"group_vars/thanos-query.yml",key:"thanos_s3_target_host",value:$nexus_ip},
        {action:"save_group_vars",file:"group_vars/thanos-query.yml"},
        {action:"set_group_var",file:"group_vars/dashboard.yml",key:"thanos_query_target_host",value:$nexus_ip},
        {action:"save_group_vars",file:"group_vars/dashboard.yml"},
        {action:"set_group_var",file:"group_vars/wazuh-fim.yml",key:"wazuh_manager_host",value:$nexus_ip},
        {action:"save_group_vars",file:"group_vars/wazuh-fim.yml"},
        {action:"set_group_var",file:"group_vars/restic-backup.yml",key:"restic_s3_target_host",value:$nexus_ip},
        {action:"save_group_vars",file:"group_vars/restic-backup.yml"}
      ]
    )
  }' >"$actions/edit.json"

# Prompt IDs and semantic select values come exclusively from Pilot's discovered
# schema. Display text is deliberately absent, so localization cannot change an
# agent's scenario. The no-preview branch has one final apply confirmation.
answers_deploy=$(jq -n --arg inventory "$root/inventory.yml" --arg vault "$root/.vault/main.yaml" '
  [
    {prompt_id:"inventory",text:$inventory},
    {prompt_id:"topology_preview",confirm:false},
    {prompt_id:"preflight",select:"full"},
    {prompt_id:"scope",select:"site"},
    {prompt_id:"stage",select:"sandbox"},
    {prompt_id:"limit",text:""},
    {prompt_id:"tags",text:""},
    {prompt_id:"vault.use_default",confirm:true},
    {prompt_id:"become_password",confirm:false},
    {prompt_id:"auto_host_var.siem_forward_host.use_detected",confirm:true},
    {prompt_id:"auto_host_var.wazuh_manager_host.use_detected",confirm:true},
    {prompt_id:"auto_host_var.restic_s3_target_host.use_detected",confirm:true},
    {prompt_id:"auto_host_var.loki_target_host.use_detected",confirm:true},
    {prompt_id:"auto_host_var.thanos_s3_target_host.use_detected",confirm:true},
    {prompt_id:"auto_host_var.alertmanager_target_host.use_detected",confirm:true},
    {prompt_id:"auto_host_var.thanos_query_target_host.use_detected",confirm:true},
    {prompt_id:"extra_vars",text:""},
    {prompt_id:"execution.preview",confirm:true},
    {prompt_id:"execution.confirm_preview",confirm:true},
    {prompt_id:"execution.apply_after_preview",confirm:true},
    {prompt_id:"execution.confirm_apply",confirm:true}
  ]')
jq -n --arg inventory "$root/inventory.yml" --argjson answers "$answers_deploy" '{version:1,steps:[{action:"deploy",inventory:$inventory,answers:$answers}]}' >"$actions/deploy.json"

for role in freeipa-dns freeipa-identity; do
  jq -n --arg role "$role" --arg inventory "$root/inventory.yml" --arg vault "$root/.vault/main.yaml" '
    {version:1,steps:[{action:"reconcile",inventory:$inventory,answers:[
      {prompt_id:"inventory",text:$inventory},
      {prompt_id:"topology_preview",confirm:false},
      {prompt_id:"preflight",select:"full"},
      {prompt_id:"component",select:$role},
      {prompt_id:"target_group",text:""},
      {prompt_id:"stage",select:"sandbox"},
      {prompt_id:"limit",text:""},
      {prompt_id:"tags",text:""},
      {prompt_id:"vault.use_default",confirm:true},
      {prompt_id:"become_password",confirm:false},
      {prompt_id:"extra_vars",text:""},
      {prompt_id:"execution.preview",confirm:true},
    {prompt_id:"execution.confirm_preview",confirm:true},
    {prompt_id:"execution.apply_after_preview",confirm:true},
      {prompt_id:"execution.confirm_apply",confirm:true}
    ]}]}' >"$actions/reconcile/$role.json"
done

discovery_sha256=$(sha256sum "$discovery" | awk '{print $1}')
facts_sha256=$(sha256sum "$facts" | awk '{print $1}')
jq -n --arg discovery "$discovery_sha256" --arg facts "$facts_sha256" \
  '{version:1,kind:"semantic-action-plan-inputs",capability_discovery_sha256:$discovery,inventory_facts_sha256:$facts}' \
  >"$actions/planner-inputs.json"

python3 .agent-teams/hufu-pilot-integration/complete-plan.py
echo "structured-action bundle authored"
