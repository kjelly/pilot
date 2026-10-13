#!/usr/bin/env bash
set -euo pipefail

team=.agent-teams/hufu-pilot-integration/team.yaml

task_block() {
  local id=$1
  awk -v id="$id" '
    $0 == "  - id: " id { found=1 }
    found { print }
    found && $0 ~ /^  - id: / && $0 != "  - id: " id { exit }
    END { if (!found) exit 1 }
  ' "$team"
}

assert_attestation_phase() {
  local id=$1 phase=$2
  local block
  block=$(task_block "$id") || { echo "missing task: $id" >&2; exit 1; }
  grep -Fqx "    phase: $phase" <<<"$block"
  grep -Fqx '      tool-sequence: [submit_result]' <<<"$block"
  if grep -Eq 'tool-sequence:.*bash|command:.*bash' <<<"$block"; then
    echo "$id grants a shell command outside EXECUTE" >&2
    exit 1
  fi
}

assert_attestation_phase topology-preparer-boundary-v2 prepare
assert_attestation_phase structured-action-auditor-boundary-v2 audit
assert_attestation_phase acceptance-verifier-objective-v2 verify

execute=$(task_block structured-action-runner-execute-v2) || { echo 'missing Execute action task' >&2; exit 1; }
grep -Fqx '    phase: execute' <<<"$execute"
grep -Fq 'capability: pilot-structured-actions' <<<"$execute"
if grep -Fq 'tool-sequence:' <<<"$execute"; then
  echo 'Execute action must not expose a worker shell sequence' >&2
  exit 1
fi

mapfile -t stages < <(grep -nE 'prepare-topology|capture-topology-inventory-facts|author-structured-actions|validate-structured-actions|run-structured-actions' .agent-teams/hufu-pilot-integration/execute-structured-workflow.sh | cut -d: -f1)
(( ${#stages[@]} == 5 )) || { echo 'Execute workflow must contain all five ordered stages' >&2; exit 1; }
(( stages[0] < stages[1] && stages[1] < stages[2] && stages[2] < stages[3] && stages[3] < stages[4] )) || {
  echo 'Execute workflow stages are not ordered topology -> facts -> plan -> validate -> run' >&2
  exit 1
}

# Scenario authoring must finish all host-editor actions before save_hosts,
# and Nexus's NFS-generated roster extra is updated rather than added.
author=.agent-teams/hufu-pilot-integration/author-structured-actions.sh
first_save=$(grep -n '{action:"save_hosts"}' "$author" | head -n 1 | cut -d: -f1)
last_host_extra=$(grep -nE '\{action:"(add_extra_var|edit_extra_var)"' "$author" | tail -n 1 | cut -d: -f1)
[[ -n $first_save && -n $last_host_extra && $last_host_extra -lt $first_save ]] || {
  echo 'host extra-var actions must precede the first save_hosts' >&2
  exit 1
}
grep -Fq '{action:"edit_extra_var",host:"nexus",key:"freeipa_roster_file",value_env:"PILOT_FREEIPA_ROSTER_FILE"}' "$author"
if grep -Fq '{action:"add_extra_var",host:"nexus",key:"freeipa_roster_file"' "$author"; then
  echo 'Nexus NFS roster extra must be updated, not added' >&2
  exit 1
fi

echo 'Hufu Pilot phase-boundary contract passed'
