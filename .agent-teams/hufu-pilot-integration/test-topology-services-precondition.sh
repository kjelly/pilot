#!/usr/bin/env bash
set -euo pipefail
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
script=$project_root/.agent-teams/hufu-pilot-integration/prepare-topology.sh
test_root=$(mktemp -d /tmp/hufu-topology-services.XXXXXX)
trap 'rm -rf -- "$test_root"' EXIT

make_fake_pilot() {
  local work=$1
  cat >"$work/pilot" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_PILOT_CALLS"
case "$1 $2 ${3-}" in
  'services status --check')
    [[ ${4-} == --json ]] || exit 97
    if [[ -f $FAKE_PILOT_CALLS.started && ${FAKE_POST_START_FAILURE:-false} == false ]]; then
      printf '%s\n' '{"configured":true,"running":true,"profile":"dev-lite"}'
      exit 0
    fi
    case "$FAKE_STATUS" in
      healthy) printf '%s\n' '{"configured":true,"running":true,"profile":"dev-lite"}' ;;
      stopped) echo 'service stack is not running' >&2; exit 17 ;;
      stale|unavailable)
        # A caller must not mistake this stale JSON for endpoint readiness.
        printf '%s\n' '{"configured":true,"running":true,"profile":"dev-lite"}'
        echo 'services: Harbor is unreachable: connection refused' >&2
        exit 19 ;;
      *) exit 98 ;;
    esac ;;
  'services up --profile')
    [[ ${4-} == dev-lite ]] || exit 97
    [[ ${FAKE_UP_RESULT:-success} == success ]] || { echo 'startup failed' >&2; exit 71; }
    touch "$FAKE_PILOT_CALLS.started" ;;
  'vm-target topology down'|'vm-target topology up') ;;
  'vm-target topology status') printf '%s\n' 'freeipa-server running' 'nexus running' 'client-vm running' ;;
  *) echo "unexpected pilot invocation: $*" >&2; exit 96 ;;
esac
FAKE
  chmod +x "$work/pilot"
}

run_case() {
  local name=$1 status=$2 up_result=${3:-success} post_failure=${4:-false}
  local work=$test_root/$name
  mkdir -p "$work/checkpoint"
  make_fake_pilot "$work"
  FAKE_PILOT_CALLS=$work/calls FAKE_STATUS=$status FAKE_UP_RESULT=$up_result \
    FAKE_POST_START_FAILURE=$post_failure HUFU_CHECKPOINT_WORKSPACE=$work/checkpoint \
    bash -c 'cd "$1" && bash "$2"' -- "$work" "$script" >"$work/output" 2>&1
}

run_case healthy healthy
if grep -Fq 'services up --profile dev-lite' "$test_root/healthy/calls"; then
  echo 'healthy endpoints must not be restarted' >&2; exit 1
fi
mapfile -t healthy_sequence <"$test_root/healthy/calls"
[[ ${healthy_sequence[1]} == 'services status --check --json' &&
   ${healthy_sequence[2]} == 'vm-target topology down --topology docs/topologies/minimal-poc-topology.yaml' ]]

for status in stopped unavailable stale; do
  run_case "$status" "$status"
  mapfile -t sequence <"$test_root/$status/calls"
  [[ ${sequence[1]} == 'services status --check --json' &&
     ${sequence[2]} == 'services up --profile dev-lite' &&
     ${sequence[3]} == 'services status --check --json' &&
     ${sequence[4]} == 'vm-target topology down --topology docs/topologies/minimal-poc-topology.yaml' ]] || {
    echo 'endpoint readiness must be rechecked before topology teardown' >&2; exit 1
  }
done
grep -Fq 'Harbor is unreachable' "$test_root/stale/checkpoint/logs/services-status.log"
jq -e '.status == "passed"' "$test_root/stale/checkpoint/receipts/topology-preparation.json" >/dev/null

for failure in startup-failure readiness-failure; do
  set +e
  if [[ $failure == startup-failure ]]; then
    run_case "$failure" stale failure
  else
    run_case "$failure" stale success true
  fi
  status=$?
  set -e
  [[ $status != 0 ]] || { echo "$failure unexpectedly succeeded" >&2; exit 1; }
  if grep -Fq 'vm-target topology down' "$test_root/$failure/calls"; then
    echo 'failed readiness must prevent topology teardown' >&2; exit 1
  fi
  [[ ! -e $test_root/$failure/checkpoint/receipts/topology-preparation.json ]]
done
[[ $(grep -Fc 'services up --profile dev-lite' "$test_root/readiness-failure/calls") == 1 ]]
grep -Fq 'host services remain unavailable after startup' "$test_root/readiness-failure/output"
echo 'live topology services precondition contract passed'
