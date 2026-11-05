#!/usr/bin/env bash
# Run only against dedicated disposable targets. Logs stay outside the source
# checkout; the caller owns provisioning, snapshots, candidate receipts/cleanup.
set -euo pipefail
if (( $# != 5 )); then
  echo "usage: $0 host-monitoring|topology PILOT_BINARY INVENTORY ARTIFACT_DIR CONSUMER_HOST" >&2
  exit 2
fi
mode=$1
pilot_bin=$(realpath "$2")
inventory_path=$(realpath "$3")
mkdir -p "$4"
artifacts=$(realpath "$4")
consumer_host=$5
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
workspace=$(dirname "$inventory_path")
export PILOT_DATA_DIR="$artifacts/data"
export ANSIBLE_LOCAL_TEMP="$artifacts/ansible-tmp"
mkdir -p "$ANSIBLE_LOCAL_TEMP"
chmod 700 "$artifacts" "$ANSIBLE_LOCAL_TEMP"
export ANSIBLE_NOCOLOR=1
export ANSIBLE_STDOUT_CALLBACK=default
unset ANSIBLE_CALLBACKS_ENABLED

run() {
  local log_name=$1
  shift
  if "$@" </dev/null >"$artifacts/$log_name.log" 2>&1; then
    echo "PASS $log_name"
  else
    local status=$?
    echo "FAIL $log_name rc=$status (see $artifacts/$log_name.log)" >&2
    return "$status"
  fi
}

assert_idempotent() {
  # Every native recap must have changed=0; accepting an empty recap would
  # mask no-host execution. Logs are emitted by real ansible-playbook.
  local log_file=$1
  if ! rg -q 'ok=[0-9]+[[:space:]]+changed=0[[:space:]]+unreachable=0[[:space:]]+failed=0' "$log_file" ||
     rg -q 'changed=[1-9][0-9]*' "$log_file"; then
    echo "FAIL idempotency (see $log_file)" >&2
    return 1
  fi
  echo "PASS idempotency"
}

case "$mode" in
  host-monitoring)
    cd "$repo_root"
    export PILOT_ROOT="$repo_root"
    vault_file="$workspace/.vault/main.yaml"
    if [[ ! -f "$vault_file" ]]; then
      echo "workspace requires .vault/main.yaml with the synthetic node_exporter_basic_auth_password" >&2
      exit 2
    fi
    # Noninteractive deploy discovers this vars file through the same workspace
    # convention used by the TUI. Use a plaintext synthetic test secret in a
    # private disposable workspace, not an operator's real credentials.
    probe=(ansible-playbook -i "$inventory_path" --limit "$consumer_host"
      playbooks/test/fixtures/deploy-components-host-monitoring.yml -e "@$vault_file")
    deploy=("$pilot_bin" deploy --dir "$workspace" --inventory "$inventory_path"
      --component host-monitoring --limit "$consumer_host" --stage sandbox)
    run inventory ansible-inventory -i "$inventory_path" --graph
    run fresh-preview "${deploy[@]}" --preview-only
    run fresh-apply "${deploy[@]}" --force
    run fresh-effective "${probe[@]}" -e issue251_probe_state=healthy
    ;;
  topology)
    cd "$repo_root/playbooks/test/fixtures/deploy-components"
    export PILOT_ROOT="$PWD"
    probe=(ansible-playbook -i "$inventory_path" playbooks/probe.yml)
    deploy=("$pilot_bin" deploy --dir "$workspace" --inventory "$inventory_path"
      --component dns --limit "$consumer_host" --stage sandbox)
    run inventory ansible-inventory -i "$inventory_path" --graph
    run initial-empty "${probe[@]}" -e issue251_probe_state=empty
    run preview "${deploy[@]}" --preview-only
    run after-preview-empty "${probe[@]}" -e issue251_probe_state=empty
    run apply "${deploy[@]}" --force
    run effective-placement "${probe[@]}" -e issue251_probe_state=applied
    run repeat-apply "${deploy[@]}" --force
    assert_idempotent "$artifacts/repeat-apply.log"
    run repeat-effective "${probe[@]}" -e issue251_probe_state=applied
    ;;
  *) echo "unknown mode: $mode" >&2; exit 2 ;;
esac

if [[ "$mode" == host-monitoring ]]; then
  # Explicit full-spec verification is required: this production contract has
  # autoDeploy=false, so the deployment transaction does not run its 12 rows.
  verify=("$pilot_bin" verify docs/verification/host-monitoring.md -i "$inventory_path"
    -l "$consumer_host" --timeout 40 --report-dir "$artifacts/verify")
  run initial-verify "${verify[@]}"
  run remove-tool "${probe[@]}" -e issue251_probe_state=remove
  run repair-preview "${deploy[@]}" --preview-only
  run preview-preserves-absence "${probe[@]}" -e issue251_probe_state=absent
  run repair-apply "${deploy[@]}" --force
  run repair-effective "${probe[@]}" -e issue251_probe_state=healthy
  run repair-verify "${verify[@]}"
  run repeat-apply "${deploy[@]}" --force
  assert_idempotent "$artifacts/repeat-apply.log"
  run repeat-effective "${probe[@]}" -e issue251_probe_state=healthy
  run repeat-verify "${verify[@]}"
fi
