#!/usr/bin/env bash
set -euo pipefail

# AUDIT's runtime-owned verifier invokes this read-only discovery step. It
# records Pilot's exported semantic action/menu capabilities; neither a worker
# nor the planner guesses a menu or action name.
: "${HUFU_CHECKPOINT_WORKSPACE:?launcher must export HUFU_CHECKPOINT_WORKSPACE}"
root=$HUFU_CHECKPOINT_WORKSPACE
discovery_dir=$root/discovery
mkdir -p "$discovery_dir"

schema=$(./pilot actions schema)
jq -e 'type == "object" and (.actions | type == "array" and length > 0) and all(.actions[]; (.name | type == "string" and length > 0))' <<<"$schema" >/dev/null

schema_canonical=$(jq -c . <<<"$schema")
schema_sha256=$(printf '%s' "$schema_canonical" | sha256sum | awk '{print $1}')
tmp=$(mktemp "$discovery_dir/.pilot-capabilities.XXXXXX")
jq -n --argjson schema "$schema" --arg schema_sha256 "$schema_sha256" '
  {version: 1, kind: "pilot-action-capabilities",
   source: {command: "./pilot actions schema", read_only: true},
   schema_sha256: $schema_sha256, action_schema: $schema,
   menu_capabilities: ($schema.actions | map({name, execution_mode, required, optional, secret_handling})),
   prompt_schemas: ($schema.actions | map(select(.execution_mode == "prompt_answers") | {name, prompt_schema}))}
' >"$tmp"
mv "$tmp" "$discovery_dir/pilot-capabilities.json"
echo "Pilot capability discovery passed"
