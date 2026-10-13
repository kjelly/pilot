#!/usr/bin/env bash
set -euo pipefail

: "${HUFU_CHECKPOINT_WORKSPACE:?launcher must export HUFU_CHECKPOINT_WORKSPACE}"
root=$HUFU_CHECKPOINT_WORKSPACE
logs=$root/logs
receipts=$root/receipts
topology=docs/topologies/minimal-poc-topology.yaml
mkdir -p "$logs" "$receipts"

run_logged() {
  local name=$1
  shift
  "$@" >"$logs/$name.log" 2>&1 || {
    echo "phase failed: $name (see $logs/$name.log)" >&2
    return 1
  }
}

probe_services() {
  local name=$1 status status_rc
  if status=$(./pilot services status --check --json 2>"$logs/$name.log"); then
    printf '%s\n' "$status" >"$logs/$name.json"
    jq -e '.configured == true and .running == true and .profile == "dev-lite"' <<<"$status" >/dev/null
  else
    status_rc=$?
    echo "live host service probe exited $status_rc (see $logs/$name.log)" >&2
    return 1
  fi
}

ensure_services() {
  # Persisted running=true is only informational. --check invokes the same
  # endpoint probes that vm-target consumes, before any topology teardown.
  if probe_services services-status; then
    echo "host service endpoints ready: profile=dev-lite"
    return 0
  fi
  # Reconcile the existing cache only when its live readiness check failed.
  # Never purge its data, drop services:local, or restart a healthy bundle.
  run_logged services-up ./pilot services up --profile dev-lite || return 1
  probe_services services-after-up-status || {
    echo "host services remain unavailable after startup; topology untouched" >&2
    return 1
  }
}

# A fresh campaign may contain AUDIT logs/discovery, but no generated state.
for path in hosts.yml inventory.yml .vault group_vars host_vars actions reports; do
  [[ ! -e $root/$path ]] || { echo "refusing stale checkpoint state: $path" >&2; exit 1; }
done
./pilot vm-target topology status --topology "$topology" >"$logs/topology-before.log"
ensure_services
run_logged topology-down ./pilot vm-target topology down --topology "$topology"
run_logged topology-up ./pilot vm-target topology up --topology "$topology"
./pilot vm-target topology status --topology "$topology" >"$logs/topology-preparation.log"
for target in freeipa-server nexus client-vm; do
  awk -v target="$target" '$1 == target && $2 == "running" {found=1} END {exit !found}' "$logs/topology-preparation.log"
done

tmp=$(mktemp "$receipts/.topology-preparation.XXXXXX")
jq -n '{version:1,status:"passed",topology_targets:3}' >"$tmp"
mv "$tmp" "$receipts/topology-preparation.json"
echo "topology preparation passed"
