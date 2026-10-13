#!/usr/bin/env bash
set -euo pipefail

wrapper=.agent-teams/hufu-pilot-integration/run-in-pty.sh
runner=.agent-teams/hufu-pilot-integration/run-structured-actions.sh
verifier=.agent-teams/hufu-pilot-integration/verify-structured-run.sh

[[ -x $wrapper ]] || { echo "$wrapper must be executable" >&2; exit 1; }

output=$(mktemp /tmp/pilot-pty-wrapper-output.XXXXXX)
trap 'rm -f -- "$output"' EXIT
set +e
"$wrapper" bash -c 'test -t 0 && test -t 1 && test -t 2; printf "pty-present\\n"; exit 23' >"$output" 2>&1
status=$?
set -e
[[ $status == 23 ]] || { echo "PTY wrapper exit status = $status, want 23" >&2; exit 1; }
tr -d '\r' <"$output" | grep -Fqx 'pty-present' || { echo 'PTY wrapper did not preserve child output' >&2; exit 1; }

PYTHONDONTWRITEBYTECODE=1 python3 - <<'PYTEST'
import sys
from unittest.mock import patch
from pathlib import Path
sys.path.insert(0, '.agent-teams/hufu-pilot-integration')
import workflow_contract as c
with patch.object(c, 'checkpoint', return_value=Path('/tmp/mock-checkpoint')), patch.object(c, 'run') as run:
    c.scenario('deploy.json', 'deploy')
    args = run.call_args.args[1]
    assert args[:2] == ['bash', str(c.TEAM / 'run-in-pty.sh')]
    assert args[3] == 'deploy' and args[args.index('--timeout') + 1] == '2h'
PYTEST

if rg -n '^[[:space:]]*\./pilot (deploy|reconcile)' "$runner" "$verifier"; then
  echo 'deploy/reconcile must not be invoked directly by execution or verification' >&2
  exit 1
fi

echo 'PTY prompt-action wrapper contract passed'
