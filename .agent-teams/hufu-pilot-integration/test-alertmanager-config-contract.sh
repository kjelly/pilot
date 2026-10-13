#!/usr/bin/env bash
set -euo pipefail

author=.agent-teams/hufu-pilot-integration/author-structured-actions.sh
runner=.agent-teams/hufu-pilot-integration/structured-action-runner.md
playbook=playbooks/apply/alertmanager-apply.yml
runbook=docs/runbooks/minimal-poc-configuration.md
spec=docs/verification/alertmanager.md

python3 - "$playbook" <<'PY'
import sys
import yaml

with open(sys.argv[1], encoding="utf-8") as stream:
    variables = yaml.safe_load(stream)[0]["vars"]
    if "alertmanager_config" in variables:
        raise SystemExit("play vars must not shadow the operator config")
    config = variables["alertmanager_default_config"]
doc = yaml.safe_load(config)
if not isinstance(doc, dict):
    raise SystemExit("Alertmanager config must be a mapping")
if doc.get("global", {}).get("resolve_timeout") != "5m":
    raise SystemExit("missing global.resolve_timeout")
if doc.get("route", {}).get("receiver") != "null":
    raise SystemExit("missing null route")
if doc.get("receivers") != [{"name": "null"}]:
    raise SystemExit("receivers must contain the null receiver")
PY


if grep -Fq 'key:"alertmanager_config"' "$author"; then
  echo 'structured action planner must not override the optional Alertmanager config' >&2
  exit 1
fi
if grep -Fq 'PILOT_ALERTMANAGER_CONFIG' "$runner"; then
  echo 'structured action runner must not require an optional Alertmanager config' >&2
  exit 1
fi

echo 'Alertmanager config contract passed'
