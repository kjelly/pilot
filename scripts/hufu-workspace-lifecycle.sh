#!/usr/bin/env bash

# Source this helper from a launcher after it has created the workspace root.
# It tracks the active Hufu control-plane workspace without deleting terminal
# campaigns, whose receipts and transcripts remain useful failure evidence.

hufu_workspace_is_terminal() {
  local workspace=$1 team_name=$2
  local session="$workspace/$team_name/session.json"
  local state
  [[ -r $session ]] || return 1
  state=$(jq -r '.workflow_state // empty' "$session" 2>/dev/null) || return 1
  [[ $state == FAILED || $state == DONE ]]
}

hufu_workspace_path_is_within_root() {
  local root=$1 candidate=$2
  local canonical_root canonical_candidate
  canonical_root=$(realpath -m -- "$root")
  canonical_candidate=$(realpath -m -- "$candidate")
  case "$canonical_candidate/" in
    "$canonical_root/"*) return 0 ;;
    *) return 1 ;;
  esac
}

hufu_write_active_workspace() {
  local root=$1 workspace=$2
  local pointer="$root/active-workspace"
  local temporary
  temporary=$(mktemp "$root/.active-workspace.XXXXXX")
  printf '%s\n' "$workspace" >"$temporary"
  mv -f -- "$temporary" "$pointer"
}

# select_hufu_workspace sets HUFU_LAUNCHER_WORKSPACE. An explicit
# HUFU_WORKSPACE always wins, including a terminal one, so callers can inspect
# or intentionally resume a specific campaign. Default launches preserve a
# nonterminal campaign and create a new campaign only after Hufu has sealed
# the previous workflow as FAILED or DONE.
select_hufu_workspace() {
  local root=$1 team_name=$2
  local pointer="$root/active-workspace"
  local workspace="$root/current"

  if [[ -n ${HUFU_WORKSPACE:-} ]]; then
    mkdir -p -- "$HUFU_WORKSPACE"
    HUFU_LAUNCHER_WORKSPACE=$HUFU_WORKSPACE
    return 0
  fi

  if [[ -s $pointer ]]; then
    workspace=$(<"$pointer")
    if ! hufu_workspace_path_is_within_root "$root" "$workspace"; then
      printf 'Ignoring invalid Hufu active-workspace pointer outside %s\n' "$root" >&2
      workspace="$root/current"
    fi
  fi

  if hufu_workspace_is_terminal "$workspace" "$team_name"; then
    workspace=$(mktemp -d "$root/campaign.XXXXXX")
    hufu_write_active_workspace "$root" "$workspace"
  else
    mkdir -p -- "$workspace"
    hufu_write_active_workspace "$root" "$workspace"
  fi
  HUFU_LAUNCHER_WORKSPACE=$workspace
}
