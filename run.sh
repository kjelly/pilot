#!/usr/bin/env bash
set -euo pipefail
# This launcher scopes one disposable Minimal PoC campaign. --check never runs
# the team; execution uses its runtime-owned Prepare/Audit/Execute/Verify gates.
umask 077
export PYTHONDONTWRITEBYTECODE=1
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
cd "$project_root"
team=hufu-pilot-integration
team_dir=$project_root/.agent-teams/$team
mode=new
case "${1:-}" in
  ''|--new-session) ;;
  --check) mode=check ;;
  --resume) mode=resume ;;
  --help|-h)
    printf '%s\n' 'Usage: bash run.sh [--check|--new-session|--resume]' \
      'Default: fresh campaign; EXECUTE deletes/rebuilds freeipa-server, nexus, client-vm.' \
      '--check: build and check contracts/provider only; no VM or service changes.' \
      '--resume: requires HUFU_WORKSPACE; restores its bound checkpoint and secrets.' \
      'HUFU_BIN or HUFU_ROOT selects Hufu. HUFU_WORKSPACE is an exact team workspace.'
    exit 0 ;;
  *) echo "unknown option: $1" >&2; exit 2 ;;
esac
(( $# <= 1 )) || { echo 'unexpected arguments; the team owns its fixed task' >&2; exit 2; }
for tool in go jq python3 flock realpath; do
  command -v "$tool" >/dev/null || { echo "missing prerequisite: $tool" >&2; exit 1; }
done
python3 -c 'import yaml' || { echo 'python3 requires PyYAML' >&2; exit 1; }
# Validate typed resource limits before creating state or starting a campaign.
python3 "$team_dir/resource_guard.py" --check

# Serialize campaigns because all of them own the same three VM names and binary.
mkdir -p "$project_root/tmp"
exec 9>"$project_root/tmp/hufu-pilot-integration.lock"
flock -n 9 || { echo 'another Minimal PoC campaign is active' >&2; exit 1; }
cleanup() {
  [[ -z ${pilot_tmp:-} ]] || rm -f -- "$pilot_tmp"
  cleanup_hufu_command
  if [[ $mode == check && -n ${hufu_workspace:-} ]]; then
    rm -rf -- "$hufu_workspace" "$hufu_checkpoint_workspace"
  fi
}
source "$project_root/scripts/resolve-hufu.sh"
trap cleanup EXIT
pilot_tmp=$(mktemp "$project_root/.pilot-build.XXXXXX")
go build -trimpath -o "$pilot_tmp" ./cmd/pilot
chmod 755 "$pilot_tmp"
mv -f -- "$pilot_tmp" "$project_root/pilot"
pilot_tmp=''
if [[ -z ${HUFU_ROOT:-} && -z ${HUFU_BIN:-} ]]; then
  sibling=$(cd -- "$project_root/.." && pwd -P)/agent-team-cli
  [[ ! -f $sibling/go.mod ]] || export HUFU_ROOT=$sibling
fi
resolve_hufu_command
"${HUFU_COMMAND[@]}" team validate "$team_dir"
./pilot actions schema | python3 "$team_dir/check-capabilities.py" --stdin

# Online model-list checks are read-only and can time out transiently. Retry
# before allocating a campaign workspace/checkpoint; persistent failure remains
# fail-closed and leaves no orphan campaign state.
online_check_passed=0
for attempt in 1 2 3; do
  if "${HUFU_COMMAND[@]}" team check "$team" --agent-team-search-path "$project_root/.agent-teams" --online; then
    online_check_passed=1
    break
  fi
  if (( attempt < 3 )); then
    printf 'Online readiness attempt %d/3 failed; retrying in 10 seconds.\n' "$attempt" >&2
    sleep 10
  fi
done
if (( online_check_passed == 0 )); then
  echo 'Team online readiness failed after 3 checks; no campaign workspace was created.' >&2
  exit 1
fi

control_root=${TMPDIR:-/tmp}/pilot-hufu-workspaces
mkdir -p "$control_root"
if [[ $mode == resume ]]; then
  : "${HUFU_WORKSPACE:?--resume requires the exact HUFU_WORKSPACE printed by the original launch}"
  hufu_workspace=$(realpath -e -- "$HUFU_WORKSPACE")
  bound_checkpoint=$(python3 - "$hufu_workspace/pilot-launch.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['checkpoint'])
PY
)
  hufu_checkpoint_workspace=${HUFU_CHECKPOINT_WORKSPACE:-$bound_checkpoint}
  session=$hufu_workspace/session.json
  [[ -f $session ]] || { echo 'resume requires an existing session.json' >&2; exit 1; }
  state=$(jq -r '.workflow_state // empty' "$session")
  [[ $state != FAILED && $state != DONE ]] || {
    echo 'terminal campaign cannot resume; inspect its evidence, then use --new-session' >&2; exit 1;
  }
else
  if [[ $mode == check ]]; then
    hufu_workspace=$(mktemp -d "$control_root/check.XXXXXX")
    # Reserve a unique name but leave the directory absent for binding validation.
    hufu_checkpoint_workspace=$(mktemp -d "$project_root/tmp/hufu-check.XXXXXX")
    rmdir "$hufu_checkpoint_workspace"
  else
    if [[ -n ${HUFU_WORKSPACE:-} ]]; then
      hufu_workspace=$(realpath -m -- "$HUFU_WORKSPACE")
      mkdir -p "$hufu_workspace"
    else
      hufu_workspace=$(mktemp -d "$control_root/campaign.XXXXXX")
    fi
    if [[ -n ${HUFU_CHECKPOINT_WORKSPACE:-} ]]; then
      hufu_checkpoint_workspace=$HUFU_CHECKPOINT_WORKSPACE
    else
      hufu_checkpoint_workspace=$(mktemp -d "$project_root/tmp/hufu-checkpoint.XXXXXX")
      rmdir "$hufu_checkpoint_workspace"
    fi
  fi
fi
[[ $hufu_checkpoint_workspace == /* ]] || { echo 'checkpoint must be absolute' >&2; exit 2; }
hufu_checkpoint_workspace=$(realpath -m -- "$hufu_checkpoint_workspace")
case "$hufu_checkpoint_workspace/" in
  "$project_root/tmp/"*) ;;
  *) echo "checkpoint must remain under $project_root/tmp" >&2; exit 2 ;;
esac
case "$hufu_workspace/" in
  "$project_root/"*) echo 'Hufu control workspace must be outside the Pilot project' >&2; exit 2 ;;
esac
# Validate path containment before launch-state creates anything. realpath follows
# existing symlinks, so tmp/../outside and tmp/symlink/outside cannot escape.
state_mode=new
[[ $mode != resume ]] || state_mode=resume
# Capture the exports without echoing them. No set -x, argv secrets or transcripts.
exports=$(python3 "$team_dir/launch-state.py" "$hufu_workspace" "$hufu_checkpoint_workspace" "$state_mode")
eval "$exports"
unset exports
if [[ $mode == check ]]; then
  # Check is read-only: report unavailable caches without restarting them.
  # A real campaign may reconcile the cache inside its EXECUTE boundary.
  ./pilot services status --check --json >"$hufu_workspace/services-readiness.json" || {
    echo 'Host cache is unavailable; run ./pilot services up --profile dev-lite, then repeat --check.' >&2
    exit 1
  }
  "${HUFU_COMMAND[@]}" run --team "$team" \
    --agent-team-search-path "$project_root/.agent-teams" \
    --workspace "$hufu_workspace" --allow-path "$hufu_workspace" \
    --execution-profile strict-verification --goal-mode outcome --route team --unattended \
    --dry-run -- '依照 docs/runbooks/minimal-poc-architecture.md，使用 Pilot structured actions 從零重建並驗證 Minimal PoC。遵循 team 定義的完整 pipeline。'
  echo 'Preflight passed; no VM rebuild or Pilot deployment was executed.'
  exit 0
fi
for tool in virsh qemu-img cloud-localds ansible ansible-playbook sshpass script; do
  command -v "$tool" >/dev/null || { echo "missing execution prerequisite: $tool" >&2; exit 1; }
done
[[ -r /dev/kvm && -w /dev/kvm ]] || { echo '/dev/kvm is not accessible' >&2; exit 1; }
virsh -c qemu:///system net-info default >"$hufu_workspace/libvirt-network.log"
[[ $(virsh -c qemu:///system net-info default | awk '$1 == "Active:" {print $2}') == yes ]] || {
  echo 'libvirt default network is not active' >&2; exit 1;
}
# Fail on local inventory shadows instead of moving or deleting unrelated files.
python3 "$team_dir/check-local-state.py"
printf 'Hufu workspace: %s\nPilot checkpoint: %s\n' "$hufu_workspace" "$HUFU_CHECKPOINT_WORKSPACE"
printf '%s\n' 'EXECUTE will rebuild freeipa-server, nexus, client-vm; failures retain evidence.'
prompt='依照 docs/runbooks/minimal-poc-architecture.md，使用 Pilot structured actions 從零重建並驗證 Minimal PoC。遵循 team 定義的完整 pipeline。'
"${HUFU_COMMAND[@]}" run \
  --team "$team" \
  --agent-team-search-path "$project_root/.agent-teams" \
  --workspace "$hufu_workspace" \
  --allow-path "$hufu_workspace" \
  --execution-profile strict-verification \
  --goal-mode outcome --route team --unattended --report \
  -- "$prompt"
