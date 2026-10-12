#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

: "${HUFU_CHECKPOINT_WORKSPACE:?launcher must export HUFU_CHECKPOINT_WORKSPACE}"
root=$HUFU_CHECKPOINT_WORKSPACE
actions=$root/actions
receipts=$root/receipts
discovery=$root/discovery/pilot-capabilities.json
facts=$root/facts/topology-inventory.json
planner_inputs=$actions/planner-inputs.json
mkdir -p "$receipts"

fail_audit() {
  local code=$1
  local file=$2
  local message=$3
  local tmp
  printf '%s\n' "$message" >&2
  tmp=$(mktemp "$receipts/.scenario-audit.XXXXXX")
  jq -n \
    --arg code "$code" \
    --arg file "$file" \
    --arg message "$message" \
    '{version:1,status:"failed",error:{code:$code,file:$file,message:$message}}' >"$tmp"
  mv "$tmp" "$receipts/scenario-audit.json"
  exit 1
}

edit=$actions/edit.json
deploy=$actions/deploy.json
[[ -s $discovery ]] || fail_audit "discovery_missing" "$discovery" "missing versioned Pilot capability discovery"
[[ -s $facts ]] || fail_audit "inventory_facts_missing" "$facts" "missing versioned topology inventory facts"
[[ -s $planner_inputs ]] || fail_audit "planner_inputs_missing" "$planner_inputs" "missing planner input manifest"
if ! jq -e '.version == 1 and .kind == "pilot-action-capabilities" and .source.read_only and (.action_schema.actions | type == "array")' "$discovery" >/dev/null; then
  fail_audit "invalid_discovery" "$discovery" "Pilot capability discovery is malformed or not read-only"
fi
discovered_schema=$(jq -c '.action_schema' "$discovery")
if [[ $(printf '%s' "$discovered_schema" | sha256sum | awk '{print $1}') != "$(jq -r '.schema_sha256' "$discovery")" ]]; then
  fail_audit "discovery_schema_hash_mismatch" "$discovery" "Pilot capability discovery schema hash does not match its declared schema"
fi
if ! jq -e '.version == 1 and .kind == "topology-inventory-facts" and .source.read_only and (.hosts | type == "object")' "$facts" >/dev/null; then
  fail_audit "invalid_inventory_facts" "$facts" "topology inventory facts are malformed or not read-only"
fi
discovery_sha256=$(sha256sum "$discovery" | awk '{print $1}')
facts_sha256=$(sha256sum "$facts" | awk '{print $1}')
if ! jq -e --arg discovery "$discovery_sha256" --arg facts "$facts_sha256" '
  .version == 1 and .kind == "semantic-action-plan-inputs" and
  .capability_discovery_sha256 == $discovery and .inventory_facts_sha256 == $facts
' "$planner_inputs" >/dev/null; then
  fail_audit "planner_input_mismatch" "$planner_inputs" "planner inputs do not match the discovered schema and current inventory facts"
fi
[[ -s $edit ]] || fail_audit "scenario_missing" "$edit" "missing structured edit scenario: $edit"
[[ -s $deploy ]] || fail_audit "scenario_missing" "$deploy" "missing structured deploy scenario: $deploy"
mapfile -t reconciles < <(find "$actions/reconcile" -maxdepth 1 -type f -name '*.json' -print 2>/dev/null | sort)
(( ${#reconciles[@]} > 0 )) || fail_audit "scenario_missing" "$actions/reconcile" "at least one reconcile scenario is required"

schema=$discovered_schema
validate_common() {
  local file=$1
  if ! jq -e '
    type == "object" and
    (.version == 1) and
    ((keys - ["version", "title", "steps"]) | length == 0) and
    (.steps | type == "array" and length > 0)
  ' "$file" >/dev/null; then
    fail_audit "invalid_scenario_envelope" "$file" "$file: expected Pilot scenario object {version:1,steps:[...]} (not a top-level array or single action object)"
  fi
  while IFS= read -r action; do
    jq -e --arg action "$action" '.actions | any(.name == $action)' <<<"$schema" >/dev/null || {
      fail_audit "unsupported_action" "$file" "$file uses unsupported action: $action"
    }
  done < <(jq -r '.steps[].action' "$file")
  if ! jq -e --argjson schema "$schema" '
    .steps | all(.[];
      . as $step |
      ($schema.actions[] | select(.name == $step.action)) as $contract |
      (((($contract.required // []) - ($step | keys)) | length) == 0) and
      (if $contract.answer? then
        (($step.answers? | type) == "array" and ($step.answers | length) > 0) and
        ($step.answers | all(.[];
          . as $answer |
          (((($contract.answer.required // []) - ($answer | keys)) | length) == 0) and
          (($contract.answer.exactly_one_of // []) as $choices |
            ([$choices[] as $choice | select($answer | has($choice))] | length) == 1)))
       else true end)
    )
  ' "$file" >/dev/null; then
    bad_step=$(jq -c --argjson schema "$schema" '
      .steps | to_entries[] |
      .value as $step |
      ($schema.actions[] | select(.name == $step.action)) as $contract |
      (($contract.required // []) | map(. as $required | select($step | has($required) | not))) as $missing |
      select(($missing | length) > 0) |
      {index:.key,action:$step.action,missing_required:$missing}
    ' "$file" | head -n 1)
    [[ -n $bad_step ]] || bad_step='{"error":"invalid prompt-answer contract"}'
    fail_audit "action_schema_contract" "$file" "$file: action schema contract failed at $bad_step"
  fi
  if ! jq -e --argjson schema "$schema" '
    .steps | all(.[];
      . as $step |
      ($schema.actions[] | select(.name == $step.action) | .secret_handling) as $policy |
      if ($policy == "value_env_required" or
          ($step.action == "add_vault_key") or
          ($step.action == "set_vault_value"))
      then (($step.value_env? | type) == "string" and
            ($step.value_env | length) > 0 and
            ($step | has("value") | not))
      else true end)
  ' "$file" >/dev/null; then
    bad_step=$(jq -c --argjson schema "$schema" '
      .steps | to_entries[] |
      .value as $step |
      ($schema.actions[] | select(.name == $step.action) | .secret_handling) as $policy |
      select(($policy == "value_env_required" or ($step.action == "add_vault_key") or ($step.action == "set_vault_value")) and
        ((($step.value_env|type) != "string") or (($step.value_env|length)==0) or ($step|has("value")))) |
      {index:.key,action:$step.action,key:($step.key // null),policy:$policy}
    ' "$file" | head -n 1)
    fail_audit "secret_handling_contract" "$file" "$file: schema secret-handling contract failed at $bad_step (use value_env and omit value whenever the action policy requires it)"
  fi
}

validate_common "$edit"
if ! jq -e '
  def host_scope:
    ["create_host", "set_host_field", "enable_role", "disable_role",
     "delete_host", "add_extra_var", "edit_extra_var", "delete_extra_var",
     "apply_role_preset", "copy_roles_from_host"];
  ([.steps | to_entries[] | select(.value.action == "save_hosts") | .key] | first) as $save_hosts |
  ($save_hosts != null) and
  ([.steps | to_entries[] | select(.value.action as $action | host_scope | index($action)) | .key] | all(. < $save_hosts)) and
  all(.steps[]; .action != "deploy" and .action != "reconcile")
' "$edit" >/dev/null; then
  fail_audit "invalid_edit_scenario_order" "$edit" "$edit: every host-scoped action must precede save_hosts; vault/group_vars actions may follow after the host editor is closed"
fi
if ! jq -e '
  any(.steps[]; .action == "add_extra_var" and .host == "freeipa-server" and .key == "freeipa_roster_file" and .value_env == "PILOT_FREEIPA_ROSTER_FILE") and
  any(.steps[]; .action == "add_extra_var" and .host == "freeipa-server" and .key == "freeipa_dns_manifest_file" and .value_env == "PILOT_FREEIPA_DNS_MANIFEST_FILE") and
  any(.steps[]; .action == "edit_extra_var" and .host == "nexus" and .key == "freeipa_roster_file" and .value_env == "PILOT_FREEIPA_ROSTER_FILE") and
  all(.steps[]; (.action != "add_extra_var") or (.host != "nexus") or (.key != "freeipa_roster_file"))
' "$edit" >/dev/null; then
  fail_audit "nfs_roster_extra_var_contract" "$edit" "$edit: FreeIPA server roster and DNS extras must be added before save_hosts; Nexus roster extra is created by freeipa-nfs-server and must be updated with edit_extra_var"
fi
validate_common "$deploy"
if ! jq -e '.steps | length == 1 and .[0].action == "deploy"' "$deploy" >/dev/null; then
  fail_audit "invalid_deploy_scenario" "$deploy" "$deploy: must contain exactly one deploy step"
fi
for file in "${reconciles[@]}"; do
  validate_common "$file"
  if ! jq -e '.steps | length == 1 and .[0].action == "reconcile"' "$file" >/dev/null; then
    fail_audit "invalid_reconcile_scenario" "$file" "$file: must contain exactly one reconcile step and no preparation actions; put required extra vars in edit.json before save_hosts"
  fi
done

# Prompt automation uses Pilot's stable prompt IDs. Validate every generated
# answer against the discovered ID/kind/value contract and require each schema
# entry marked always before execute can reach a mutation.
for file in "$deploy" "${reconciles[@]}"; do
  if ! jq -e --argjson schema "$schema" '
    .steps[0] as $step |
    ($schema.actions[] | select(.name == $step.action) | .prompt_schema) as $prompt_schema |
    ($step.answers | map(.prompt_id)) as $ids |
    (($ids | length) == ($ids | unique | length)) and
    all($step.answers[];
      . as $answer |
      ($prompt_schema.prompts[] | select(.id == $answer.prompt_id or
        (.id_pattern == "auto_host_var.*.use_detected" and ($answer.prompt_id | test("^auto_host_var\\..+\\.use_detected$"))) or
        (.id_pattern == "auto_host_var.*.value" and ($answer.prompt_id | test("^auto_host_var\\..+\\.value$"))))) as $definition |
      (($answer | keys | map(select(. == "select" or . == "text" or . == "confirm")) | length) == 1) and
      (if $definition.kind == "select" then $answer.select? != null
       elif $definition.kind == "text" then $answer.text? != null
       else $answer.confirm? != null end) and
      (($definition.accepted_values // []) as $accepted |
       if ($accepted | length) == 0 then true else ($accepted | index($answer.select)) != null end)) and
    all($prompt_schema.prompts[] | select(.requirement == "always"); .id as $id | ($ids | index($id)) != null) and
    ([ $step.answers[] | select(.prompt_id == "preflight") | .select ] == ["full"]) and
    ([ $step.answers[] | select(.prompt_id == "execution.preview") | .confirm ] == [true]) and
    ([ $step.answers[] | select(.prompt_id == "execution.confirm_preview") | .confirm ] == [true]) and
    ([ $step.answers[] | select(.prompt_id == "execution.apply_after_preview") | .confirm ] == [true]) and
    ([ $step.answers[] | select(.prompt_id == "execution.confirm_apply") | .confirm ] == [true]) and
    all($step.answers[]; has("prompt") | not)
  ' "$file" >/dev/null; then
    fail_audit "prompt_id_answer_contract" "$file" "$file: prompt answers must use unique discovered prompt_id values and the full-preflight preview/apply branch"
  fi
done

python3 .agent-teams/hufu-pilot-integration/validate-policy.py
