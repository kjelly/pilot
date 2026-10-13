#!/usr/bin/env bash
set -euo pipefail

runner=.agent-teams/hufu-pilot-integration/run-structured-actions.sh
verifier=.agent-teams/hufu-pilot-integration/verify-structured-run.sh

for script in "$verifier"; do
  grep -Fq 'inventory lint --in "$root/hosts.yml"' "$script" || {
    echo "$script must lint the simple hosts source explicitly" >&2
    exit 1
  }
  if grep -Fq 'inventory lint --dir' "$script"; then
    echo "$script passes unsupported --dir to inventory lint" >&2
    exit 1
  fi
done

grep -Fq '"lint", "--in", str(root / "hosts.yml")' .agent-teams/hufu-pilot-integration/run-workflow.py
help=$(./pilot inventory lint --help)
grep -Fq -- '--in string' <<<"$help" || {
  echo 'pilot inventory lint must expose --in' >&2
  exit 1
}
if grep -Fq -- '--dir ' <<<"$help"; then
  echo 'pilot inventory lint unexpectedly exposes --dir' >&2
  exit 1
fi

echo 'inventory lint command contract passed'
