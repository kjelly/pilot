#!/usr/bin/env bash
set -euo pipefail

# The team may opt out of Hufu's RAG vector search by omitting --memory, but
# it must never suppress the other memory mechanisms exposed by Hufu.
team_file=.agent-teams/hufu-pilot-integration/team.yaml
[[ -f $team_file ]] || { echo "missing team configuration: $team_file" >&2; exit 1; }

profile=$(awk -F: '/^execution-profile:[[:space:]]*/ { gsub(/[[:space:]]/, "", $2); print $2; exit }' "$team_file")
[[ $profile == strict-verification ]] || {
  echo "memory contract violation: execution-profile must be strict-verification, got ${profile:-missing}" >&2
  exit 1
}

denied=$(awk '
  /^tools:/ { in_tools=1; next }
  in_tools && /^[^[:space:]]/ { in_tools=0 }
  in_tools && /^[[:space:]]*denied:/ { print; exit }
' "$team_file")
[[ -n $denied ]] || { echo "team configuration has no tools.denied policy" >&2; exit 1; }

for memory_tool in stm_write ltm_update memory_save memory_query; do
  if [[ ,${denied//[[:space:]]/}, == *",$memory_tool,"* || ,${denied//[[:space:]]/}, == *",$memory_tool]"* ]]; then
    echo "memory contract violation: tools.denied disables $memory_tool" >&2
    exit 1
  fi
done

echo "Memory contract passed: strict verification retains non-RAG memory tools"
