#!/usr/bin/env bash
set -euo pipefail

# This Execute-owned read-only probe runs after topology rebuild, so planning
# uses facts for the targets it will actually manage.
: "${HUFU_CHECKPOINT_WORKSPACE:?launcher must export HUFU_CHECKPOINT_WORKSPACE}"
root=$HUFU_CHECKPOINT_WORKSPACE
facts_dir=$root/facts
raw_inventory=$facts_dir/topology-inventory.yml
mkdir -p "$facts_dir"

./pilot vm-target topology inventory --topology docs/topologies/minimal-poc-topology.yaml >"$raw_inventory"

host_field() {
  local host=$1 field=$2
  awk -v host="$host:" -v field="$field:" '
    $1 == host { inside=1; next }
    inside && $1 == field { print $2; exit }
    inside && /^[[:space:]]{4}[[:alnum:]][[:alnum:]_-]*:$/ { exit }
  ' "$raw_inventory"
}

for host in freeipa-server nexus client-vm; do
  for field in ansible_host ansible_user ansible_ssh_private_key_file; do
    value=$(host_field "$host" "$field")
    [[ -n $value ]] || { echo "topology inventory is missing $field for $host" >&2; exit 1; }
    printf -v "${host//-/_}_${field}" '%s' "$value"
  done
done

inventory_sha256=$(sha256sum "$raw_inventory" | awk '{print $1}')
tmp=$(mktemp "$facts_dir/.topology-inventory.XXXXXX")
jq -n \
  --arg hash "$inventory_sha256" \
  --arg ipa_ip "$freeipa_server_ansible_host" --arg ipa_user "$freeipa_server_ansible_user" --arg ipa_key "$freeipa_server_ansible_ssh_private_key_file" \
  --arg nexus_ip "$nexus_ansible_host" --arg nexus_user "$nexus_ansible_user" --arg nexus_key "$nexus_ansible_ssh_private_key_file" \
  --arg client_ip "$client_vm_ansible_host" --arg client_user "$client_vm_ansible_user" --arg client_key "$client_vm_ansible_ssh_private_key_file" '
  {version: 1, kind: "topology-inventory-facts",
   source: {command: "./pilot vm-target topology inventory --topology docs/topologies/minimal-poc-topology.yaml", read_only: true},
   inventory_sha256: $hash,
   hosts: {"freeipa-server": {ansible_host: $ipa_ip, ansible_user: $ipa_user, ansible_ssh_private_key_file: $ipa_key},
           nexus: {ansible_host: $nexus_ip, ansible_user: $nexus_user, ansible_ssh_private_key_file: $nexus_key},
           "client-vm": {ansible_host: $client_ip, ansible_user: $client_user, ansible_ssh_private_key_file: $client_key}}}
' >"$tmp"
mv "$tmp" "$facts_dir/topology-inventory.json"
echo "topology inventory facts captured"
