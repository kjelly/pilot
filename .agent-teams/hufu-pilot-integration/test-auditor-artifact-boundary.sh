#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
coordinator=$project_root/.agent-teams/hufu-pilot-integration/coordinator.md
auditor=$project_root/.agent-teams/hufu-pilot-integration/structured-action-auditor.md
team=$project_root/.agent-teams/hufu-pilot-integration/team.yaml
verifier=$project_root/.agent-teams/hufu-pilot-integration/audit-execute-contract.sh

task_block() {
  awk '
    $0 == "  - id: structured-action-auditor-boundary-v2" { found=1 }
    found { print }
    found && /^  - id: / && $0 != "  - id: structured-action-auditor-boundary-v2" { exit }
    END { if (!found) exit 1 }
  ' "$team"
}

audit_task=$(task_block)
grep -Fqx '    phase: audit' <<<"$audit_task"
grep -Fqx '      forbid-artifacts: true' <<<"$audit_task"
grep -Fqx '      tool-sequence: [submit_result]' <<<"$audit_task"

for file in "$coordinator" "$auditor"; do
  grep -Fq 'submit_result` exactly once' "$file" || {
    echo "$file does not require exactly one auditor attestation" >&2
    exit 1
  }
  grep -Fq 'no `artifacts`, `receipt_ids`, or' "$file" || {
    echo "$file does not require an artifact-free auditor attestation" >&2
    exit 1
  }
  grep -Eqi '(must not|do not) create, write, produce, or claim the' "$file" || {
    echo "$file does not forbid worker ownership of discovery" >&2
    exit 1
  }
done
if rg -n -i 'submit_result.{0,80}to (produce|write|create).{0,80}(artifact|discovery)' "$coordinator" "$auditor"; then
  echo 'auditor instructions imply submit_result produces an artifact' >&2
  exit 1
fi
grep -Fq 'bash .agent-teams/hufu-pilot-integration/discover-pilot-capabilities.sh' "$verifier"

workspace=$(mktemp -d /tmp/pilot-auditor-boundary.XXXXXX)
trap 'rm -rf -- "$workspace"' EXIT
(
  cd "$project_root"
  HUFU_CHECKPOINT_WORKSPACE=$workspace bash .agent-teams/hufu-pilot-integration/audit-execute-contract.sh >/dev/null
)
jq -e '.version == 1 and .kind == "pilot-action-capabilities" and .source.read_only' \
  "$workspace/discovery/pilot-capabilities.json" >/dev/null

echo 'auditor artifact boundary contract passed'
